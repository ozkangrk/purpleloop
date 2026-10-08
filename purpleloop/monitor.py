"""Sürekli izleme (continuous monitoring): tarama + delta + alert.

Döngü başına:
  1. Kill-switch kontrolü (aktif => MONITOR_HALTED + dur).
  2. ReconAgent koşusu (transport enjekte edilebilir).
  3. compute_delta ile önceki bulgu kümesiyle karşılaştırma
     (bulgu kimliği: (tip, hedef) çifti).
  4. Delta NEW içinde 'secret' veya 'open_bucket' varsa ALERT audit kaydı.
  5. monitoring.jsonl'a JSON satırı + AuditLog'a MONITOR_CYCLE kaydı.

Kullanım:
  python3 -m purpleloop.monitor --scope scope.json \
      --state monitoring-state.json --audit audit.jsonl \
      [--interval 60] [--max-cycles 3] [--hosts ...] [--endpoints ...]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .recon import ReconAgent, Transport
from .scope import ScopeContract

CRITICAL_TYPES = ("secret", "open_bucket")

MIN_INTERVAL_SECONDS = 60


# --------------------------------------------------------------------------
# Delta hesaplama (saf fonksiyon — kolay test)
# --------------------------------------------------------------------------

def _finding_key(f) -> tuple:
    """Bulgu kimliği: (tip, hedef) çifti. dict veya Finding kabul eder."""
    if isinstance(f, dict):
        return (f.get("tip"), f.get("hedef"))
    return (f.tip, f.hedef)


def compute_delta(previous: list, current: list) -> dict:
    """İki bulgu kümesini karşılaştırır.

    Returns:
        {"NEW": [...], "RESOLVED": [...], "UNCHANGED": [...]}
        Her liste bulgu sözlükleri (dict'e çevrilmiş) içerir.
    """
    prev_map = {_finding_key(f): f for f in previous}
    cur_map = {_finding_key(f): f for f in current}

    def _norm(f):
        return f if isinstance(f, dict) else {
            "tip": f.tip, "hedef": f.hedef, "kanit": f.kanit,
            "zaman_damgasi": f.zaman_damgasi,
            "kapsam_referansi": f.kapsam_referansi,
        }

    new = [_norm(cur_map[k]) for k in cur_map if k not in prev_map]
    resolved = [_norm(prev_map[k]) for k in prev_map if k not in cur_map]
    unchanged = [_norm(cur_map[k]) for k in cur_map if k in prev_map]
    return {"NEW": new, "RESOLVED": resolved, "UNCHANGED": unchanged}


def has_critical_new(delta: dict) -> list:
    """NEW kümesindeki kritik (secret/open_bucket) bulguları döndürür."""
    return [f for f in delta.get("NEW", [])
            if f.get("tip") in CRITICAL_TYPES]


# --------------------------------------------------------------------------
# Tek döngü
# --------------------------------------------------------------------------

class MonitorRun:
    """Tek bir tarama + delta döngüsü."""

    def __init__(
        self,
        *,
        scope: ScopeContract,
        killswitch: KillSwitch,
        audit: AuditLog,
        state_path: str,
        out_path: str = "monitoring.jsonl",
        transport: Optional[Transport] = None,
        base_domains: Optional[list] = None,
        hosts: Optional[list] = None,
        endpoints: Optional[list] = None,
    ):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.state_path = state_path
        self.out_path = out_path
        self.transport = transport
        self.base_domains = base_domains or []
        self.hosts = hosts or ["127.0.0.1"]
        self.endpoints = endpoints or []

    # ---- durum (önceki bulgu kümesi) ----

    def load_previous(self) -> list:
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("findings", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_state(self, findings: list) -> None:
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump({"findings": [
                x if isinstance(x, dict) else {
                    "tip": x.tip, "hedef": x.hedef, "kanit": x.kanit,
                    "zaman_damgasi": x.zaman_damgasi,
                    "kapsam_referansi": x.kapsam_referansi,
                } for x in findings
            ]}, f, ensure_ascii=False)

    # ---- döngü ----

    def execute(self) -> dict:
        previous = self.load_previous()

        agent = ReconAgent(
            scope=self.scope,
            killswitch=self.killswitch,
            audit=self.audit,
            out_path=self.out_path + ".findings.tmp.jsonl",
            transport=self.transport,
        )
        current = agent.run(
            base_domains=self.base_domains,
            hosts=self.hosts,
            endpoints=self.endpoints,
        )

        delta = compute_delta(previous, current)
        critical = has_critical_new(delta)
        for f in critical:
            self.audit.append(
                "ALERT",
                tip=f.get("tip"),
                hedef=f.get("hedef"),
                kanit=(f.get("kanit") or "")[:200],
                reason="critical new finding",
            )

        self.audit.append(
            "MONITOR_CYCLE",
            new=len(delta["NEW"]),
            resolved=len(delta["RESOLVED"]),
            unchanged=len(delta["UNCHANGED"]),
            alerts=len(critical),
            total_current=len(current),
        )

        self.save_state(current)

        line = {
            "event": "MONITOR_CYCLE",
            "new": len(delta["NEW"]),
            "resolved": len(delta["RESOLVED"]),
            "unchanged": len(delta["UNCHANGED"]),
            "alerts": len(critical),
            "deltas": delta,
        }
        with open(self.out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n")
        print(json.dumps({k: v for k, v in line.items() if k != "deltas"},
                         ensure_ascii=False), flush=True)
        return delta


# --------------------------------------------------------------------------
# Zamanlayıcı
# --------------------------------------------------------------------------

class MonitorScheduler:
    """Verilen aralıkla MonitorRun döngüleri koşar."""

    def __init__(
        self,
        run: MonitorRun,
        *,
        interval: float = MIN_INTERVAL_SECONDS,
        max_cycles: Optional[int] = None,
        sleep_fn=time.sleep,
    ):
        if interval < 0:
            raise ValueError("interval negatif olamaz")
        self.run = run
        self.interval = interval
        self.max_cycles = max_cycles
        self.sleep_fn = sleep_fn
        self.cycles = 0

    def start(self) -> int:
        """Döngüleri koş; tamamlanan döngü sayısını döndürür."""
        while True:
            if self.run.killswitch.is_active():
                self.run.audit.append("MONITOR_HALTED", cycles=self.cycles)
                break
            self.run.execute()
            self.cycles += 1
            if self.max_cycles is not None and self.cycles >= self.max_cycles:
                break
            if self.interval > 0:
                self.sleep_fn(self.interval)
        return self.cycles


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="purpleloop.monitor",
        description="PurpleLoop sürekli izleme (tarama + delta + alert)")
    ap.add_argument("--scope", required=True, help="scope sözleşme JSON yolu")
    ap.add_argument("--state", required=True, help="monitoring-state JSON yolu")
    ap.add_argument("--audit", default="audit.jsonl", help="audit zinciri dosyası")
    ap.add_argument("--killswitch", default="KILLSWITCH", help="kill-switch dosya yolu")
    ap.add_argument("--out", default="monitoring.jsonl", help="monitoring çıktısı (JSONL)")
    ap.add_argument("--interval", type=float, default=MIN_INTERVAL_SECONDS,
                    help=f"döngü aralığı saniye (default {MIN_INTERVAL_SECONDS})")
    ap.add_argument("--max-cycles", type=int, default=None,
                    help="maksimum döngü sayısı (test için; default sınırsız)")
    ap.add_argument("--domains", default="", help="alt alan keşfi taban alan adları (virgülle)")
    ap.add_argument("--hosts", default="127.0.0.1", help="port taraması hostları (virgülle)")
    ap.add_argument("--endpoints", default="127.0.0.1:8081,127.0.0.1:9010",
                    help="HTTP endpoint'ler host:port (virgülle)")
    args = ap.parse_args(argv)

    try:
        with open(args.scope, "r", encoding="utf-8") as f:
            scope = ScopeContract(f.read())
    except Exception as e:
        print(f"FAIL-CLOSED: scope yüklenemedi: {e}", file=sys.stderr)
        return 2

    ks = KillSwitch(args.killswitch)
    if ks.is_active():
        print("FAIL-CLOSED: kill-switch aktif, izleme başlatılmıyor.", file=sys.stderr)
        return 3

    audit = AuditLog(args.audit)

    endpoints = []
    for ep in filter(None, args.endpoints.split(",")):
        host, _, port = ep.rpartition(":")
        endpoints.append((host, int(port)))

    mrun = MonitorRun(
        scope=scope,
        killswitch=ks,
        audit=audit,
        state_path=args.state,
        out_path=args.out,
        base_domains=[d for d in args.domains.split(",") if d],
        hosts=[h for h in args.hosts.split(",") if h],
        endpoints=endpoints,
    )
    sched = MonitorScheduler(mrun, interval=args.interval, max_cycles=args.max_cycles)
    cycles = sched.start()

    ok = audit.verify_chain()
    print(json.dumps({"cycles": cycles, "audit_chain_valid": ok, "out": args.out},
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
