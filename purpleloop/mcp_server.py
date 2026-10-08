"""PurpleLoop MCP server — AI agent'lara scope-gated güvenlik taraması sunar.

Mimari kural: MCP katmanı İNCE sarmalayıcıdır; kontrol düzlemi (scope/audit/
kill-switch) ve tarama motoru mevcut modüllerde kalır. Server hiçbir doğrudan
ağ çağrısı yapmaz — her şey ScopeGatedTransport'tan geçer.

Araçlar (7): status, scope_check, scan, killswitch, audit, campaign, gate.
campaign ve gate v1.9 ekleme: mevcut 5 aracın adı/davranışı değişmez
(test_mcp_server.py'deki isim sırası korunur — yeni araçlar SONA eklenir).

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
from .harness import (Harness, HarnessContext, ReconStage, RealTransport,
                      SecurityAgent)
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
    {
        "name": "campaign",
        "description": "Otonom kampanya orkestratörünü koşturur: recon → "
                       "deterministik önceliklendirme → bütçeli derin prob. "
                       "Kill-switch aktifse halted döner (fail-closed).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
                "endpoints": {"type": "array", "items": {"type": "string"}},
                "max_steps": {"type": "integer", "minimum": 1, "maximum": 100,
                              "default": 10},
            },
            "required": ["hosts"],
            "additionalProperties": False,
        },
    },
    {
        "name": "gate",
        "description": "Bir out_dir'deki findings.jsonl + active-findings.jsonl "
                       "bulgularını PolicyGate eşiklerine vurur: durum "
                       "(PASS/FAIL), error/warning sayıları.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "out_dir": {"type": "string",
                            "description": "findings.jsonl içeren dizin"},
                "max_error": {"type": "integer", "minimum": 0, "default": 0},
                "max_warning": {"type": "integer", "minimum": 0, "default": 10},
            },
            "required": ["out_dir"],
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
    import glob
    all_f = []
    # scan çıktıları + kampanya çıktıları (campaign-findings.jsonl) birlikte;
    # dosya yoksa boş — gate temiz dizinde PASS der
    for name in ("findings.jsonl", "active-findings.jsonl",
                 "campaign-findings.jsonl", "recon-findings.jsonl"):
        fpath = os.path.join(out_dir, name)
        if os.path.exists(fpath):
            with open(fpath, encoding="utf-8") as f:
                all_f.extend(json.loads(line) for line in f if line.strip())
    return all_f


def _read_audit_records(audit):
    if not os.path.exists(audit.path):
        return []
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Sunucu kurulumu
# ---------------------------------------------------------------------------

def build_server(scope, audit, killswitch, out_dir, transport_factory=None,
                 campaign_out_dir=None):
    """MCPServer döndürür; transport_factory testlerde FakeTransport verir.

    campaign_out_dir: campaign aracının bulgu/recon dosyalarını yazacağı dizin
    (default 'campaign-run'). Mevcut 5 aracın davranışı bundan etkilenmez.
    """
    from mcp.server.mcpserver.server import MCPServer

    class _ActiveStageAdapter:
        """Harness pipeline'a ActiveProbe'u SecurityAgent sözleşmesiyle sarar."""
        name = "active"
        description = "GET-only safe-mode aktif problar"

        def __init__(self, factory):
            self._factory = factory

        def run(self, ctx):
            probe = self._factory()
            return len(probe.run(list(ctx.artifacts.get("_endpoints") or [])))

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

    def _scan(hosts, endpoints=None, domains=None, active=True) -> str:
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
        ctx.artifacts["_endpoints"] = eps
        stages = ["recon", "validator"]
        if active:
            from .active import ActiveProbe
            harness.agents["active"] = _ActiveStageAdapter(
                lambda: ActiveProbe(scope=scope, killswitch=killswitch, audit=audit,
                                    out_path=os.path.join(out_dir, "active-findings.jsonl"),
                                    transport=raw))
            stages.append("active")
        summary = harness.run_pipeline(stages)
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

    # ---- v1.9: campaign + gate (yalnız EKLEME; mevcut araçlara dokunmaz) ----

    # Kampanya çıktısı HER ZAMAN out_dir içinde: görece yol SDK istemcisinin
    # cwd'sine dağılırdı (ajan bulgularını bulamıyordu). Mutlak ve keşfedilebilir.
    campaign_out = campaign_out_dir or os.path.join(out_dir, "campaign")

    def _campaign(hosts, endpoints=None, max_steps: int = 10) -> str:
        """Otonom kampanya: CampaignOrchestrator'ı koşturup özet döner.

        Fail-closed: kill-switch aktifse hiçbir prob koşmaz, halted=True.
        """
        from .campaign import CampaignOrchestrator
        from .recon import ReconAgent
        from .active import ActiveProbe

        if killswitch.is_active():
            audit.append("KILLSWITCH_HALT", stage="mcp:campaign")
            return _j({"halted": True, "adim_sayisi": 0,
                       "reason": "kill-switch aktif",
                       "bulgu_tipleri": [], "bulgular": [],
                       "uygulanan_hedefler": [],
                       "audit_chain_valid": audit.verify_chain()})

        eps = _parse_endpoints(endpoints, hosts)
        os.makedirs(campaign_out, exist_ok=True)
        probe = ActiveProbe(
            scope=scope, killswitch=killswitch, audit=audit,
            out_path=os.path.join(campaign_out, "campaign-findings.jsonl"),
            transport=raw)
        registry = {
            "sqli_data_leak": probe.probe_sqli_leak,
            "extension_filter_bypass": probe.probe_extension_bypass,
            "error_disclosure": probe.probe_error_disclosure,
        }

        def _recon():
            agent = ReconAgent(
                scope=scope, killswitch=killswitch, audit=audit,
                out_path=os.path.join(campaign_out, "recon-findings.jsonl"),
                transport=raw)
            return agent.run([], hosts, eps)

        orch = CampaignOrchestrator(
            scope=scope, killswitch=killswitch, audit=audit,
            out_dir=campaign_out, recon_findings_provider=_recon,
            probe_registry=registry, max_steps=max_steps)
        report = orch.run(eps)
        bulgular = report.get("bulgular", [])
        return _j({
            "halted": bool(report.get("killswitch_halt")),
            "adim_sayisi": report.get("adim_sayisi", 0),
            "bulgu_tipleri": sorted({f.get("tip", "") for f in bulgular}),
            "bulgular": bulgular,
            "uygulanan_hedefler": report.get("uygulanan_hedefler", []),
            "advisor_rejects": report.get("advisor_rejects", 0),
            "campaign_out_dir": campaign_out,
            "audit_chain_valid": audit.verify_chain(),
        })

    def _gate(out_dir: str, max_error: int = 0, max_warning: int = 10) -> str:
        """out_dir bulgularını PolicyGate eşiklerine vurur (PASS/FAIL).

        findings.jsonl + active-findings.jsonl + campaign-*.jsonl birlikte
        okunur. DİRÜSTLÜK KURALI: dizin yoksa veya hiç bulgu dosyası yoksa
        boş PASS döndürmek yanıltıcıdır — 'bulgu_dosyasi_yok: true' işareti
        ile döner (ajan yanlış yolu sorguladığında bunu görür).
        """
        from .platform_layer import PolicyGate
        import glob as _glob

        findings = _read_findings(out_dir)
        dosya_var = bool(_glob.glob(os.path.join(out_dir, "*.jsonl")))
        karar = PolicyGate(max_error=max_error,
                           max_warning=max_warning).evaluate(findings)
        return _j({
            "durum": karar["durum"],
            "error": karar["error"],
            "warning": karar["warning"],
            "esik": karar["esik"],
            "bulgu_sayisi": len(findings),
            "bulgu_dosyasi_yok": not dosya_var,
            "out_dir": out_dir,
        })

    handlers = {
        "status": _status,
        "scope_check": _scope_check,
        "scan": _scan,
        "killswitch": _killswitch,
        "audit": _audit,
        "campaign": _campaign,
        "gate": _gate,
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
