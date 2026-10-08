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

# OWASP Juice Shop v17.3.0 GET-recon ground truth (canlı doğrulanmış;
# bkz. evidence/v14_juice_benchmark.log). Hedef: 127.0.0.1:3100
JUICE_TRUTH = [
    ("ftp_listing", "directory", ":3100/ftp/"),
    ("ftp_kdbx", "directory", ":3100/ftp/incident-support.kdbx"),
    ("ftp_acquisitions", "directory", ":3100/ftp/acquisitions.md"),
    ("ftp_announcement", "directory", ":3100/ftp/announcement_encrypted.md"),
    ("ftp_legal", "directory", ":3100/ftp/legal.md"),
    ("metrics", "directory", ":3100/metrics"),
    ("api_docs", "directory", ":3100/api-docs/"),
    ("robots", "directory", ":3100/robots.txt"),
    ("security_txt", "directory", ":3100/security.txt"),
    ("wellknown_security", "directory", ":3100/.well-known/security.txt"),
    ("csp_missing", "missing_header", "127.0.0.1:3100|content-security-policy"),
    ("hsts_missing", "missing_header", "127.0.0.1:3100|strict-transport-security"),
    ("err_disclosure", "error_disclosure", ":3100/rest/does-not-exist"),
    ("ext_bypass", "extension_filter_bypass", ":3100/ftp/package.json.bak"),
]

# Juice Shop eşleşmesi: hedef substring yerine (hedef|kanıt-başlığı) çifti
def _juice_match(finding: dict, pattern: str) -> bool:
    if "|" not in pattern:
        return pattern in finding.get("hedef", "")
    hedef_pat, kanit_pat = pattern.split("|", 1)
    return hedef_pat in finding.get("hedef", "") and kanit_pat in finding.get("kanit", "")


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

    def __init__(self, *, truth=None, match_fn=None):
        self.truth = truth or LAB_TRUTH
        self.match_fn = match_fn  # (finding, pattern) -> bool; yoksa varsayılan substring

    def _hit(self, finding: dict, tip: str, pat: str) -> bool:
        if finding.get("tip") != tip:
            return False
        if self.match_fn is not None:
            return self.match_fn(finding, pat)
        return pat in finding.get("hedef", "")

    def score(self, findings: list, denied: list, duration: float) -> BenchResult:
        bulunan, kacirilan = 0, []
        for tid, tip, pat in self.truth:
            hit = any(self._hit(f, tip, pat) for f in findings)
            if hit:
                bulunan += 1
            else:
                kacirilan.append(tid)
        # FP: truth ile eşleşmeyen secret/directory BULGUSU (kayıt bazlı; aynı
        # hedeze ikinci secret FP değildir — truth desenleri hedef bazlıdır)
        fp = 0
        for f in findings:
            t = f.get("tip")
            if t in ("secret", "directory") and not any(self._hit(f, tt, pp) for _, tt, pp in self.truth):
                fp += 1
        # kapsam ihlali: deny edilen host:port'a RAĞMEN bulgu üretilmiş mi?
        # host VE port birlikte eşleşmeli (port-deny hostun tamamını kapatmaz)
        ihlal = 0
        for d in denied:
            dh, dp = d.get("host", ""), d.get("port")
            for f in findings:
                h = f.get("hedef", "")
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
                  out_findings: str, hosts, endpoints, decoy_hosts=None,
                  truth=None, matcher=None, run_active=False) -> BenchResult:
    """Tam recon koşusu + skor. decoy_hosts: kapsam dışı tuzak hedefler."""
    t0 = time.monotonic()
    agent = ReconAgent(scope=scope, killswitch=killswitch, audit=audit, out_path=out_findings)
    all_hosts = list(hosts) + list(decoy_hosts or [])
    findings = agent.run([], all_hosts, endpoints)
    if run_active:
        from .active import ActiveProbe
        probe = ActiveProbe(scope=scope, killswitch=killswitch, audit=audit,
                            out_path=out_findings + ".active")
        findings = list(findings) + list(probe.run(endpoints))
    duration = time.monotonic() - t0
    runner = BenchRunner(truth=truth, match_fn=matcher) if truth else BenchRunner()
    plain = [f.__dict__ if hasattr(f, "__dict__") else dict(f) for f in findings]
    return runner.score(plain, agent.denied, duration)


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
    ap.add_argument("--target", default="lab", choices=["lab", "juice"],
                    help="lab: yerel 16-varlık truth; juice: OWASP Juice Shop v17.3.0 truth")
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
    truth = JUICE_TRUTH if args.target == "juice" else None
    match_fn = _juice_match if args.target == "juice" else None
    run_active = args.target == "juice"
    result = run_benchmark(scope=scope, killswitch=ks, audit=audit,
                           out_findings=findings_path,
                           hosts=[h for h in args.hosts.split(",") if h],
                           endpoints=endpoints,
                           decoy_hosts=[d for d in args.decoys.split(",") if d],
                           truth=truth, matcher=match_fn, run_active=run_active)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(result.to_json() + "\n")
    ok = audit.verify_chain()
    print(result.to_json())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
