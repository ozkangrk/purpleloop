"""MCP campaign + gate araçları — v1.9 ekleme testleri.

Mevcut test_mcp_server.py'ye DOKUNULMAZ; yeni araçlar ayrı dosyada sınanır:
  * campaign: FakeTransport ile adim_sayisi>0 + bulgu listesi
  * campaign: kill-switch aktifken halted=True (fail-closed)
  * gate: fixture out_dir ile PASS / FAIL kararları
  * --help exit 0 (CLI sözleşmesi korunur)
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("mcp")

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
    """Port-farklılaştırılmış sahte lab: sqli leak + hata ifşası üretir."""

    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls.append(("tcp", host, port))
        return (host, port) in {(("127.0.0.1", 8081)), ("127.0.0.1", 9010)}

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(("http", host, port, path))
        if port == 8081:
            # SQLi leak probunun aradığı desen: veri sızdıran hata yanıtı
            body = "SQLError: leaked row admin:PurpleL00p\n"
            return (500, body, {"Server": "nginx"})
        if port == 9010:
            return (500, "Traceback (most recent call last): boom", {})
        return (0, "", {})


def _make_ctx(tmp_path, active_ks=False):
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    if active_ks:
        (tmp_path / "KS").write_text("STOP", encoding="utf-8")
    return scope, audit, ks


@pytest.mark.anyio
async def test_campaign_tool_runs_steps_and_returns_findings(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    camp_out = str(tmp_path / "campaign-run")
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path),
                       transport_factory=lambda: FakeTransport(),
                       campaign_out_dir=camp_out)
    res = await srv.call_tool("campaign", {
        "hosts": ["127.0.0.1"],
        "endpoints": ["127.0.0.1:8081", "127.0.0.1:9010"],
        "max_steps": 10,
    })
    data = json.loads(res.content[0].text)
    assert data["halted"] is False
    assert data["adim_sayisi"] > 0, "en az bir kampanya adımı koşmalı"
    assert isinstance(data["bulgular"], list)
    # FakeTransport sızıntı yanıtları üretir → bulgu tipi gelmeli; hiç değilse
    # bulgu listesi bile dönmeli (sözleşme alanları)
    assert "bulgu_tipleri" in data
    assert data["audit_chain_valid"] is True
    assert data["campaign_out_dir"] == camp_out
    for f in data["bulgular"]:
        assert set(f) >= {"tip", "hedef", "kanit"}


@pytest.mark.anyio
async def test_campaign_tool_halts_when_killswitch_active(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path, active_ks=True)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path),
                       transport_factory=lambda: FakeTransport(),
                       campaign_out_dir=str(tmp_path / "campaign-run"))
    res = await srv.call_tool("campaign", {
        "hosts": ["127.0.0.1"], "endpoints": ["127.0.0.1:8081"]})
    data = json.loads(res.content[0].text)
    assert data["halted"] is True
    assert data["adim_sayisi"] == 0
    assert data["bulgular"] == []
    assert "kill-switch" in data["reason"].lower()


@pytest.mark.anyio
async def test_gate_tool_pass_on_empty_and_clean(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    # Boş out_dir → 0 bulgu → PASS
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    res = await srv.call_tool("gate", {"out_dir": str(empty_dir)})
    data = json.loads(res.content[0].text)
    assert data["durum"] == "PASS"
    assert data["error"] == 0
    assert data["warning"] == 0
    assert data["bulgu_sayisi"] == 0


@pytest.mark.anyio
async def test_gate_tool_fail_on_error_finding(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    # sqli_data_leak _SEVERITY'de error seviyesidir → max_error=0 aşılır
    finding = {"tip": "sqli_data_leak", "hedef": "127.0.0.1:8081/x",
               "kanit": "leaked row", "zaman_damgasi": "2026-10-08T00:00:00Z",
               "kapsam_referansi": "scope.json"}
    (out_dir / "findings.jsonl").write_text(json.dumps(finding) + "\n",
                                            encoding="utf-8")
    res = await srv.call_tool("gate", {"out_dir": str(out_dir)})
    data = json.loads(res.content[0].text)
    assert data["durum"] == "FAIL"
    assert data["error"] >= 1
    assert data["bulgu_sayisi"] == 1


@pytest.mark.anyio
async def test_gate_tool_reads_active_findings_too(tmp_path):
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    out_dir = tmp_path / "run2"
    out_dir.mkdir()
    f1 = {"tip": "missing_header", "hedef": "127.0.0.1:8081", "kanit": "x"}
    f2 = {"tip": "error_disclosure", "hedef": "127.0.0.1:9010", "kanit": "y"}
    (out_dir / "findings.jsonl").write_text(json.dumps(f1) + "\n",
                                            encoding="utf-8")
    (out_dir / "active-findings.jsonl").write_text(json.dumps(f2) + "\n",
                                                   encoding="utf-8")
    res = await srv.call_tool("gate", {"out_dir": str(out_dir)})
    data = json.loads(res.content[0].text)
    assert data["bulgu_sayisi"] == 2


@pytest.mark.anyio
async def test_tool_list_extends_without_breaking_existing_five(tmp_path):
    """Mevcut 5 araç isim sırası korunur; yeniler SONA eklenir."""
    scope, audit, ks = _make_ctx(tmp_path)
    srv = build_server(scope=scope, audit=audit, killswitch=ks,
                       out_dir=str(tmp_path))
    tools = await srv.list_tools()
    names = [t.name for t in tools]
    assert names[:5] == ["status", "scope_check", "scan", "killswitch", "audit"]
    assert "campaign" in names and "gate" in names
    spec_names = [s["name"] for s in TOOL_SPECS]
    assert spec_names == names


def test_cli_help_still_exits_zero():
    from purpleloop.mcp_server import main
    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0
