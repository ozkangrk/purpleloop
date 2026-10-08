"""PurpleLoop MCP server — AI agent'lara scope-gated güvenlik taraması sunar.

Mimari kural: MCP katmanı İNCE sarmalayıcıdır; kontrol düzlemi (scope/audit/
kill-switch) ve tarama motoru mevcut modüllerde kalır. Server hiçbir doğrudan
ağ çağrısı yapmaz — her şey ScopeGatedTransport'tan geçer.

Araçlar (5): status, scope_check, scan, killswitch, audit.

Çalıştırma:
  python3 -m purpleloop.mcp_server --scope scope.json --out-dir run
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

from .audit import AuditLog
from .harness import Harness, HarnessContext, ReconStage, RealTransport
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# Araç şemaları — hem sunucu kaydı hem dokümantasyon için
# ---------------------------------------------------------------------------

TOOL_SPECS = [
    {
        "name": "status",
        "description": "PurpleLoop durumu: kapsam özeti, kill-switch, araç sayısı.",
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
    {
        "name": "scope_check",
        "description": "Bir (host, port) isteği kapsam sözleşmesine göre izinli mi? "
                       "Kapsam dışıysa RET + audit'e SCOPE_DENY yazılır.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "method": {"type": "string", "default": "GET"},
            },
            "required": ["host", "port"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scan",
        "description": "Kapsam içi recon taraması (port/dizin/bucket/parola keşfi) + "
                       "validator. Kill-switch aktifse reddedilir. Bulgular sabit "
                       "Finding şemasında döner.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
                "endpoints": {"type": "array", "items": {"type": "string"},
                              "description": "host:port listesi"},
                "domains": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["hosts"],
            "additionalProperties": False,
        },
    },
    {
        "name": "killswitch",
        "description": "Kill-switch durumunu döndürür (aktif/pasif + yol).",
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
    {
        "name": "audit",
        "description": "Audit zincirini doğrular ve son N kaydı döndürür.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tail": {"type": "integer", "minimum": 1, "maximum": 100,
                         "default": 10},
            },
            "additionalProperties": False,
        },
    },
]


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


def _parse_endpoints(endpoints, hosts):
    eps = []
    for ep in endpoints or []:
        host, _, p = ep.rpartition(":")
        eps.append((host, int(p)))
    if not eps:
        eps = [(h, 8081) for h in hosts]
    return eps


def _read_findings(out_dir):
    fpath = os.path.join(out_dir, "findings.jsonl")
    if not os.path.exists(fpath):
        return []
    with open(fpath, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _read_audit_records(audit):
    if not os.path.exists(audit.path):
        return []
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Sunucu kurulumu
# ---------------------------------------------------------------------------

def build_server(scope, audit, killswitch, out_dir, transport_factory=None):
    """MCPServer döndürür; transport_factory testlerde FakeTransport verir."""
    from mcp.server.mcpserver.server import MCPServer

    server = MCPServer(name="purpleloop", instructions=__doc__ or "")

    raw = transport_factory() if transport_factory else RealTransport()
    server._transport = raw  # testlerde çağrı izlemesi için

    def _status() -> str:
        return _j({
            "sunucu": "purpleloop-mcp",
            "hedef_sayisi": len(scope.targets),
            "portlar": list(getattr(scope, "ports", []) or []),
            "kill_switch_aktif": killswitch.is_active(),
            "arac_sayisi": len(TOOL_SPECS),
        })

    def _scope_check(host: str, port: int, method: str = "GET") -> str:
        allowed, reason = scope.check_request(host=host, port=port, method=method)
        if not allowed:
            audit.append("SCOPE_DENY", host=host, port=port, method=method,
                         kaynak="mcp:scope_check", reason=reason)
        return _j({"izinli": allowed, "sebep": "" if allowed else reason})

    def _scan(hosts, endpoints=None, domains=None) -> str:
        if killswitch.is_active():
            audit.append("KILLSWITCH_HALT", stage="mcp:scan")
            return _j({"halted": True, "reason": "kill-switch aktif",
                       "toplam_bulgu": 0, "findings": [],
                       "audit_chain_valid": audit.verify_chain()})
        eps = _parse_endpoints(endpoints, hosts)
        os.makedirs(out_dir, exist_ok=True)
        ctx = HarnessContext(
            scope=scope, killswitch=killswitch, audit=audit, out_dir=out_dir,
            raw_transport=raw,
            started=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        )
        harness = Harness(ctx)
        harness.agents["recon"] = ReconStage(hosts=hosts, endpoints=eps,
                                             base_domains=domains or [])
        summary = harness.run_pipeline(["recon", "validator"])
        findings = _read_findings(out_dir)
        return _j({
            "toplam_bulgu": len(findings),
            "findings": findings,
            "halted": summary["halted"],
            "reason": summary.get("reason") or "",
            "audit_chain_valid": audit.verify_chain(),
        })

    def _killswitch() -> str:
        return _j({"aktif": killswitch.is_active(), "yol": killswitch.path})

    def _audit(tail: int = 10) -> str:
        ok = audit.verify_chain()
        records = _read_audit_records(audit)
        return _j({"gecerli": ok, "kayit_sayisi": len(records),
                   "son_kayitlar": records[-tail:]})

    handlers = {
        "status": _status,
        "scope_check": _scope_check,
        "scan": _scan,
        "killswitch": _killswitch,
        "audit": _audit,
    }
    for spec in TOOL_SPECS:
        server.add_tool(handlers[spec["name"]], name=spec["name"],
                        description=spec["description"])
    return server


# ---------------------------------------------------------------------------
# CLI — stdio transport
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import anyio

    ap = argparse.ArgumentParser(prog="purpleloop.mcp_server",
                                 description="PurpleLoop MCP server (stdio)")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out-dir", default="run")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    args = ap.parse_args(argv)

    try:
        with open(args.scope, encoding="utf-8") as f:
            scope = ScopeContract(f.read())
    except Exception as e:
        print(f"FAIL-CLOSED: scope yüklenemedi: {e}", file=sys.stderr)
        return 2

    ks = KillSwitch(args.killswitch)
    if ks.is_active():
        print("FAIL-CLOSED: kill-switch aktif, sunucu başlamıyor.", file=sys.stderr)
        return 3

    os.makedirs(args.out_dir, exist_ok=True)
    audit = AuditLog(os.path.join(args.out_dir, "audit.jsonl"))
    audit.append("MCP_SERVER_START", scope=args.scope, out_dir=args.out_dir)

    server = build_server(scope=scope, audit=audit, killswitch=ks,
                          out_dir=args.out_dir)
    anyio.run(server.run_stdio_async)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
