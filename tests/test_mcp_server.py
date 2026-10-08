"""MCP server testleri — PurpleLoop araçlarını agent'lara sunar (TDD: önce testler).

Kapsam:
  * sunucu oluşturma + 5 araç (status/scope_check/scan/killswitch/audit)
  * scope_check: kapsam içi izin / kapsam dışı RET + SCOPE_DENY audit kaydı
  * scan: FakeTransport ile uçtan uca, tuzak host'a paket gitmez
  * kill-switch aktifken scan reddedilir (fail-closed)
  * gerçek MCP el sıkışması (stdio, alt süreç)
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.mcp_server import build_server, TOOL_SPECS  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {
    "targets": ["127.0.0.1", "127.0.0.2"],
    "ports": [8081, 9010],
    "methods": ["GET", "HEAD"],
}


class FakeTransport:
    """Port-farklılaştırılmış sahte lab (tek haritalı transport FP üretir)."""

    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls.append(("tcp", host, port))
        return (host, port) in {("127.0.0.1", 8081), ("127.0.0.1", 9010),
                                ("127.0.0.2", 8081), ("127.0.0.2", 9010)}

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(("http", host, port, path))
        if port == 8081:
            if path == "/backup/secrets-old.txt":
                return (200, "db_password=PurpleL00p!Lab-2026\n", {"Server": "nginx"})
            if path == "/backup/":
                body = "<html><body><h1>Index of /backup/</h1></body></html>"
                return (200, body, {"Server": "nginx"})
            return (404, "not found", {})
        if port == 9010 and path == "/public/":
            body = ('<?xml version="1.0"?><ListBucketResult>'
                    "<Contents><Key>credentials-leaked.txt</Key></Contents>"
                    "</ListBucketResult>")
            return (200, body, {"Server": "MinIO"})
        if port == 9010:
            return (403, "AccessDenied", {})
        return (0, "", {})


def _make_ctx(tmp_path, active_ks=False):
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    if active_ks:
        (tmp_path / "KS").write_text("STOP", encoding="utf-8")
    return scope, audit, ks


def _audit_events(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


@pytest.mark.anyio
async def test_build_server_registers_five_tools(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    tools = await srv.list_tools()
    names = [t.name for t in tools]
    # v1.9: campaign + gate eklendi; ilk 5 aracın adı ve SIRASI değişmez
    assert names[:5] == ["status", "scope_check", "scan", "killswitch", "audit"]
    assert "campaign" in names and "gate" in names


def test_tool_specs_documented():
    for spec in TOOL_SPECS:
        assert spec["name"]
        assert spec["description"]
        assert spec["inputSchema"].get("type") == "object"


# ---------------------------------------------------------------------------
# 2) scope_check aracı
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_scope_check_allows_in_scope(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    res = await srv.call_tool("scope_check", {"host": "127.0.0.1", "port": 8081})
    data = json.loads(res.content[0].text)
    assert data["izinli"] is True
    assert data["sebep"] == ""


@pytest.mark.anyio
async def test_scope_check_denies_out_of_scope_and_audits(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    res = await srv.call_tool("scope_check", {"host": "203.0.113.99", "port": 80})
    data = json.loads(res.content[0].text)
    assert data["izinli"] is False
    assert data["sebep"]
    denies = [e for e in _audit_events(audit.path) if e["event"] == "SCOPE_DENY"]
    assert denies, "kapsam dışı istek audit'e SCOPE_DENY olarak yazılmalı"
    assert denies[-1]["host"] == "203.0.113.99"
    assert denies[-1]["port"] == 80


# ---------------------------------------------------------------------------
# 3) scan aracı — FakeTransport ile uçtan uca
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_scan_tool_returns_findings_and_summary(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path),
                       transport_factory=lambda: FakeTransport())
    res = await srv.call_tool("scan", {
        "hosts": ["127.0.0.1"],
        "endpoints": ["127.0.0.1:8081", "127.0.0.1:9010"],
    })
    data = json.loads(res.content[0].text)
    tips = {f["tip"] for f in data["findings"]}
    assert "secret" in tips          # ekili parola dosyası
    assert "open_bucket" in tips     # minio public bucket
    assert data["toplam_bulgu"] >= 2
    assert data["audit_chain_valid"] is True
    assert data["halted"] is False
    for f in data["findings"]:
        assert set(f) >= {"tip", "hedef", "kanit", "zaman_damgasi", "kapsam_referansi"}


@pytest.mark.anyio
async def test_scan_tool_scope_gated_no_violation(tmp_path):
    """Tuzak host kapsam dışında: scan onu taramaz, ağa paket gitmez."""
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path),
                       transport_factory=lambda: FakeTransport())
    res = await srv.call_tool("scan", {
        "hosts": ["127.0.0.1", "203.0.113.99"],
        "endpoints": ["127.0.0.1:8081"],
    })
    data = json.loads(res.content[0].text)
    decoy_calls = [c for c in srv._transport.calls if "203.0.113.99" in c]
    assert decoy_calls == []
    assert any(e["event"] == "SCOPE_DENY" for e in _audit_events(audit.path))


# ---------------------------------------------------------------------------
# 4) kill-switch fail-closed
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_scan_tool_refuses_when_killswitch_active(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path, active_ks=True)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path),
                       transport_factory=lambda: FakeTransport())
    res = await srv.call_tool("scan", {"hosts": ["127.0.0.1"]})
    data = json.loads(res.content[0].text)
    assert data["halted"] is True
    assert "kill-switch" in data["reason"].lower()
    assert data["toplam_bulgu"] == 0


@pytest.mark.anyio
async def test_killswitch_tool_reports_state(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    res = await srv.call_tool("killswitch", {})
    data = json.loads(res.content[0].text)
    assert data["aktif"] is False
    assert data["yol"] == ks.path


# ---------------------------------------------------------------------------
# 5) stdio el sıkışması — alt süreç, gerçek protokol
# ---------------------------------------------------------------------------

def test_stdio_handshake_subprocess(tmp_path):
    pytest.importorskip("mcp")
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.session import ClientSession
    import anyio

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(SCOPE_DOC), encoding="utf-8")
    out_dir = tmp_path / "run"
    out_dir.mkdir()

    async def _client():
        # stdio_client alt sürece yalnızca beyaz liste ortam değişkeni geçirir;
        # PYTHONPATH'i açıkça taşı (anyio/mcp çözünürlüğü için)
        env = {"HOME": os.environ.get("HOME", "/home/ozkangu"),
               "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "purpleloop.mcp_server",
                  "--scope", str(scope_path),
                  "--out-dir", str(out_dir),
                  "--killswitch", str(tmp_path / "KS")],
            env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [t.name for t in tools.tools]

    names = anyio.run(_client)
    assert "scan" in names
    assert "scope_check" in names
