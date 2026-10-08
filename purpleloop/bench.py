"""v0.7: Benchmark çekirdeği — PurpleLoop'un kendi labındaki ekili varlıklara
karşı ölçülmesi. "Frontier yetkinlik" iddiasının dürüst kanıtı: her koşuda
bulunma oranı, FP oranı, kapsam ihlali sayısı ve süre ölçülür ve yayınlanabilir
tabloya dönüşür.

İlke: benchmark kendisi de fail-closed — kapsam dışı hedef benchmark modunda
DAHA sert reddedilir ve bu, kapsam ihlali metriğine kanıt olarak yazılır.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .recon import ReconAgent
from .scope import ScopeContract


# Lab ground truth: docker-compose'da ekili tüm varlıklar.
# (id, tip, hedef-regex deseri) — hedef eşleşmesi substring ile.
LAB_TRUTH = [
    ("nginx_port", "open_port", "127.0.0.1:8081"),
    ("minio_port", "open_port", "127.0.0.1:9010"),
    ("backup_dir", "directory", "127.0.0.1:8081/backup/"),
    ("env_file", "directory", "127.0.0.1:8081/backup/.env"),
    ("aws_file", "directory", "127.0.0.1:8081/backup/.aws-credentials"),
    ("secrets_file", "directory", "127.0.0.1:8081/backup/secrets-old.txt"),
    ("env_secret", "secret", "127.0.0.1:8081/backup/.env"),
    ("aws_secret", "secret", "127.0.0.1:8081/backup/.aws-credentials"),
    ("old_secret_1", "secret", "127.0.0.1:8081/backup/secrets-old.txt"),
    ("old_secret_2", "secret", "127.0.0.1:8081/backup/secrets-old.txt"),
    ("old_secret_3", "secret", "127.0.0.1:8081/backup/secrets-old.txt"),
    ("minio_api", "bucket_service", "127.0.0.1:9010"),
    ("public_bucket", "open_bucket", "127.0.0.1:9010/public/"),
    ("bucket_object", "directory", "127.0.0.1:9010/public/credentials-leaked.txt"),
    ("bucket_secret_1", "secret", "127.0.0.1:9010/public/credentials-leaked.txt"),
    ("bucket_secret_2", "secret", "127.0.0.1:9010/public/credentials-leaked.txt"),
]


@dataclass
class BenchResult:
    lab: str
    toplam_varlik: int
    bulunan: int
    kacirilan: list          # bulunamayan varlık id'leri
    fp_bulgu: int            # truth dışında üretilen eşleşmez bulgu
    kapsam_ihlali: int       # reddedilmişken denenmiş istek (0 olmalı)
    scope_deny: int
    sure_sn: float
    zaman: str

    @property
    def recall(self) -> float:
        return round(self.bulunan / self.toplam_varlik, 4) if self.toplam_varlik else 0.0

    def to_json(self) -> str:
        d = asdict(self); d["recall"] = self.recall
        return json.dumps(d, ensure_ascii=False, sort_keys=True)


class BenchRunner:
    """Bir lab koşusunu ground-truth'a karşı skorlar."""

    def __init__(self, *, truth=None):
        self.truth = truth or LAB_TRUTH

    def score(self, findings: list, denied: list, duration: float) -> BenchResult:
        found_targets = {f.get("hedef", "") for f in findings}
        found_pairs = {(f.get("tip"), f.get("hedef", "")) for f in findings}
        bulunan, kacirilan = 0, []
        for tid, tip, pat in self.truth:
            hit = any(t == tip and pat in h for t, h in found_pairs)
            if hit:
                bulunan += 1
            else:
                kacirilan.append(tid)
        # FP: truth ile eşleşmeyen secret/directory BULGUSU (kayıt bazlı; aynı
        # hedeze ikinci secret FP değildir — truth desenleri hedef bazlıdır)
        fp = 0
        for f in findings:
            t, h = f.get("tip"), f.get("hedef", "")
            if t in ("secret", "directory") and not any(t == tt and pp in h for _, tt, pp in self.truth):
                fp += 1
        # kapsam ihlali: deny edilen host:port'a RAĞMEN bulgu üretilmiş mi?
        # host VE port birlikte eşleşmeli (port-deny hostun tamamını kapatmaz)
        ihlal = 0
        for d in denied:
            dh, dp = d.get("host", ""), d.get("port")
            for t, h in found_pairs:
                host_part, _, rest = h.partition(":")
                try:
                    port_part = int(rest.split("/")[0]) if rest else None
                except ValueError:
                    port_part = None
                if host_part == dh and (dp is None or port_part == dp or port_part is None):
                    ihlal += 1
        return BenchResult(
            lab="purpleloop-lab-v1",
            toplam_varlik=len(self.truth),
            bulunan=bulunan,
            kacirilan=kacirilan,
            fp_bulgu=fp,
            kapsam_ihlali=ihlal,
            scope_deny=len(denied),
            sure_sn=round(duration, 2),
            zaman=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        )


def run_benchmark(*, scope: ScopeContract, killswitch: KillSwitch, audit: AuditLog,
                  out_findings: str, hosts, endpoints, decoy_hosts=None) -> BenchResult:
    """Tam recon koşusu + skor. decoy_hosts: kapsam dışı tuzak hedefler."""
    t0 = time.monotonic()
    agent = ReconAgent(scope=scope, killswitch=killswitch, audit=audit, out_path=out_findings)
    all_hosts = list(hosts) + list(decoy_hosts or [])
    findings = agent.run([], all_hosts, endpoints)
    duration = time.monotonic() - t0
    return BenchRunner().score([f.__dict__ for f in findings], agent.denied, duration)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    import os, sys
    ap = argparse.ArgumentParser(prog="purpleloop.bench",
                                 description="PurpleLoop lab benchmark: recall/FP/scope metrikleri")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", default="bench-result.json")
    ap.add_argument("--audit", default="audit.jsonl")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    ap.add_argument("--hosts", default="127.0.0.1")
    ap.add_argument("--decoys", default="203.0.113.99,198.51.100.7",
                    help="kapsam dışı tuzak hostlar (reddedilmeli)")
    ap.add_argument("--endpoints", default="127.0.0.1:8081,127.0.0.1:9010")
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

    endpoints = [(ep.rpartition(":")[0], int(ep.rpartition(":")[2]))
                 for ep in args.endpoints.split(",") if ep]
    findings_path = os.path.splitext(args.out)[0] + "-findings.jsonl"
    open(findings_path, "w").close()
    audit = AuditLog(args.audit)
    result = run_benchmark(scope=scope, killswitch=ks, audit=audit,
                           out_findings=findings_path,
                           hosts=[h for h in args.hosts.split(",") if h],
                           endpoints=endpoints,
                           decoy_hosts=[d for d in args.decoys.split(",") if d])
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(result.to_json() + "\n")
    ok = audit.verify_chain()
    print(result.to_json())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
