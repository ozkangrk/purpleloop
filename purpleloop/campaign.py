"""v1.8: Kampanya orkestratörü — deterministik otonom döngü.

Araştırma kaynağı: otonom pentest ajanları (APT-Agent, FireCompass deseni)
RECON→TRIAGE→PRIORITIZE→DEEP-PROBE döngüsüyle çalışır. PurpleLoop farkı:
**LLM'siz deterministik önceliklendirme**; LLM yalnız DANIŞMAN olur —
sıralama önerir, ağ eylemini belirleyemez; kapsam dışı önerisi kayda geçer
ve UYGULANMAZ (ADVISOR_REJECT).

Sınırlar (fail-closed):
  * kill-switch her adım öncesi kontrol edilir
  * max_steps bütçesi zorunlu (sonsuz döngü yasak)
  * her prob scope kapısından geçer (problar ActiveProbe sözleşmesini kullanır)
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# Deterministik öncelik skoru (LLM yok)
# ---------------------------------------------------------------------------

_PRIORITY = {
    # tip: skor (yüksek önce)
    "sqli_data_leak": 100,
    "secret": 90,
    "open_bucket": 85,
    "extension_filter_bypass": 70,
    "sqli_signature": 65,
    "error_disclosure": 55,
    "open_redirect": 45,
    "directory": 30,
    "bucket_service": 25,
    "missing_header": 10,
    "open_port": 5,
}

# Derin prob tetikleyen tipler: bulunduğunda o prob da koşulur
_DEEP_PROBE_FOR = {
    "sqli_data_leak": "sqli_data_leak",
    "secret": "error_disclosure",
    "directory": "extension_filter_bypass",
    "error_disclosure": "error_disclosure",
    "extension_filter_bypass": "extension_filter_bypass",
}


def prioritize_findings(findings: list) -> list:
    """Bulguları deterministik önem sırasına dizer (LLM yok).

    Finding dataclass veya dict kabul eder; hepsi dict'e normalize edilir.
    """
    def _as_dict(f):
        if isinstance(f, dict):
            return f
        if hasattr(f, "__dict__"):
            return dict(f.__dict__)
        return {"tip": str(f), "hedef": "", "kanit": ""}
    return sorted((_as_dict(f) for f in findings),
                  key=lambda f: -_PRIORITY.get(f.get("tip", ""), 0))


# ---------------------------------------------------------------------------
# Orkestratör
# ---------------------------------------------------------------------------

class CampaignOrchestrator:
    """Recon → önceliklendir → bütçeli derin prob döngüsü."""

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_dir: str,
                 recon_findings_provider: Callable[[], list],
                 probe_registry: Optional[dict] = None,
                 llm_advisor: Optional[Callable] = None,
                 max_steps: int = 50):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_dir = out_out = out_dir
        self.recon = recon_findings_provider
        self.probes = probe_registry or {}
        self.llm = llm_advisor
        self.max_steps = max_steps

    def _in_scope(self, hedef: str) -> bool:
        host, _, rest = hedef.partition(":")
        port_s, _, _ = (rest or "").partition("/")
        try:
            port = int(port_s) if port_s else 80
        except ValueError:
            return False
        ok, _ = self.scope.check_request(host=host, port=port, method="GET")
        return ok

    def run(self, endpoints: list) -> dict:
        self.audit.append("CAMPAIGN_START", max_steps=self.max_steps,
                          endpoints=[f"{h}:{p}" for h, p in endpoints])
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="campaign")
            return {"adim_sayisi": 0, "killswitch_halt": True,
                    "uygulanan_hedefler": [], "bulgular": []}

        findings = list(self.recon())
        ranked = prioritize_findings(findings)

        # LLM danışman: yalnız SIRALAMA önerir; kapsam dışı öneri RET
        advisor_rejects = 0
        if self.llm is not None:
            try:
                proposed = self.llm(ranked, {"endpoints": endpoints})
            except Exception as e:
                # danışman hatası orkestrasyonu DURDURMAZ (non-blocking)
                self.audit.append("ADVISOR_ERROR", hata=str(e)[:200])
                proposed = ranked
            if isinstance(proposed, list):
                kept, dropped = [], []
                for f in proposed:
                    (kept if self._in_scope(f.get("hedef", "")) else dropped).append(f)
                for f in dropped:
                    advisor_rejects += 1
                    self.audit.append("ADVISOR_REJECT",
                                      hedef=f.get("hedef", ""),
                                      sebep="kapsam dışı öneri")
                ranked = kept

        # Derin prob planı: her bulgunun tetiklediği prob, bütçe içinde.
        # Aynı prob tipi YALNIZ bir kez koşar (ilk tetikleyiciyle) —
        # 10 directory bulgusu 10 kez aynı probu tetiklememeli.
        plan, seen_probes = [], set()
        for f in ranked:
            probe_tip = _DEEP_PROBE_FOR.get(f.get("tip", ""))
            if probe_tip and probe_tip in self.probes and probe_tip not in seen_probes:
                seen_probes.add(probe_tip)
                plan.append((probe_tip, f))

        # Temel prob seti: kampanya her zaman çekirdek sondajlarla açılır
        # (recon bulgusu olmasa bile sqli/hata/bypass denenir — bulgu üretme
        # şansı sıfır değilse döngü kör başlamasın)
        for core in ("sqli_data_leak", "error_disclosure", "extension_filter_bypass"):
            if core in self.probes and core not in seen_probes:
                seen_probes.add(core)
                plan.insert(0, (core, {"tip": "baseline", "hedef": "*", "kanit": ""}))

        uygulanan, yeni_bulgular, adim = [], [], 0
        for probe_tip, f in plan:
            if adim >= self.max_steps:
                break
            if self.killswitch.is_active():
                self.audit.append("KILLSWITCH_HALT", stage="campaign",
                                  adim=adim)
                return {"adim_sayisi": adim, "killswitch_halt": True,
                        "uygulanan_hedefler": uygulanan, "bulgular": yeni_bulgular,
                        "advisor_rejects": advisor_rejects}
            hedef = f.get("hedef", "")
            is_baseline = f.get("tip") == "baseline"
            if not is_baseline and not self._in_scope(hedef):
                self.audit.append("SCOPE_DENY", hedef=hedef,
                                  reason="[campaign] kapsam dışı")
                continue
            for host, port in endpoints:
                self.audit.append("CAMPAIGN_STEP", adim=adim,
                                  prob=probe_tip, tetikleyen=hedef)
                res = self.probes[probe_tip](host, port)
                if res:
                    yeni_bulgular.append(res)
                    uygulanan.append(res.get("hedef", ""))
                adim += 1
                if adim >= self.max_steps:
                    break

        self.audit.append("CAMPAIGN_END", adim=adim,
                          yeni_bulgu=len(yeni_bulgular),
                          advisor_rejects=advisor_rejects)
        return {"adim_sayisi": adim, "killswitch_halt": False,
                "uygulanan_hedefler": uygulanan, "bulgular": yeni_bulgular,
                "advisor_rejects": advisor_rejects}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="purpleloop.campaign",
                                 description="Kampanya orkestratörü (otonom döngü)")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--hosts", default="127.0.0.1")
    ap.add_argument("--endpoints", default="127.0.0.1:8081,127.0.0.1:9010")
    ap.add_argument("--max-steps", type=int, default=50)
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
        print("FAIL-CLOSED: kill-switch aktif.", file=sys.stderr)
        return 3

    os.makedirs(args.out_dir, exist_ok=True)
    audit = AuditLog(os.path.join(args.out_dir, "audit.jsonl"))

    from .active import ActiveProbe
    from .recon import ReconAgent

    probe = ActiveProbe(scope=scope, killswitch=ks, audit=audit,
                        out_path=os.path.join(args.out_dir, "campaign-findings.jsonl"))
    registry = {
        "sqli_data_leak": probe.probe_sqli_leak,
        "extension_filter_bypass": probe.probe_extension_bypass,
        "error_disclosure": probe.probe_error_disclosure,
    }

    def _recon():
        out = os.path.join(args.out_dir, "recon-findings.jsonl")
        agent = ReconAgent(scope=scope, killswitch=ks, audit=audit, out_path=out)
        eps = [(ep.rpartition(":")[0], int(ep.rpartition(":")[2]))
               for ep in args.endpoints.split(",") if ep]
        return agent.run([], [h for h in args.hosts.split(",") if h], eps)

    orch = CampaignOrchestrator(
        scope=scope, killswitch=ks, audit=audit, out_dir=args.out_dir,
        recon_findings_provider=_recon, probe_registry=registry,
        max_steps=args.max_steps)
    endpoints = [(ep.rpartition(":")[0], int(ep.rpartition(":")[2]))
                 for ep in args.endpoints.split(",") if ep]
    report = orch.run(endpoints)
    print(json.dumps({**report, "audit_chain_valid": audit.verify_chain()},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
