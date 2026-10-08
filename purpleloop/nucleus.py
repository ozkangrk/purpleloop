"""Nuclei backend adaptörü — güçlü tarayıcıyı scope+audit arkasına koşar.

Ürün konumlandırması: PurpleLoop tarayıcı DEĞİL, governance katmanıdır.
Nuclei'nin 9000+ şablon gücü buraya backend olarak bağlanır; her koşu:
  * yalnız scope İÇİ hedeflerde (hedef listesi scope.onaylıdan gelir,
    ek olarak her bulgu tekrar scope doğrulanır — çift kapı)
  * kill-switch aktifse hiç başlamaz
  * çıktı sabit Finding şemasına çevrilir (nuclei_<severity> tipiyle)
  * audit zincirine NUCLEI_START/END kaydı düşer
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
from urllib.parse import urlparse

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# nuclei severity -> SARIF uyumlu seviye etiketi
NUCLEI_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
}


class NucleiAdapter:
    """scope-gated Nuclei koşucusu (jsonl çıktı → Finding)."""

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, binary: str | None = None,
                 timeout: int = 300, templates: str | None = None):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.binary = binary or shutil.which("nuclei") or os.path.expanduser("~/.local/bin/nuclei")
        self.timeout = timeout
        self.templates = templates  # None = nuclei default template seti

    def available(self) -> bool:
        return bool(self.binary) and os.path.exists(self.binary)

    # ------------------------------------------------------------------

    def _to_findings(self, rows: list, kapsam: str) -> list:
        """Nuclei jsonl kayıtlarını Finding şemasına çevirir; scope DIŞINI atar."""
        out = []
        for r in rows:
            host = r.get("host", "")
            matched = r.get("matched-at") or host
            # matched-at URL olabilir: host:port çıkar
            hedef = matched
            if matched.startswith("http"):
                u = urlparse(matched)
                hedef = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}{u.path}"
            # çift kapı: bulgu hedefi scope'ta MI (nuclei kendi sızmışsa bile)
            host_part = hedef.partition(":")[0]
            try:
                port_part = int(hedef.partition(":")[2].split("/")[0])
            except (ValueError, IndexError):
                port_part = None
            izin = False
            if port_part is not None:
                izin, _ = self.scope.check_request(host=host_part, port=port_part,
                                                   method="GET")
            if not izin:
                self.audit.append("NUCLEI_SCOPE_DROP", hedef=hedef,
                                  sebep="bulgu kapsam dışında")
                continue
            sev = (r.get("info") or {}).get("severity", "info")
            tid = r.get("template-id", "?")
            name = (r.get("info") or {}).get("name", "")
            out.append({
                "tip": f"nuclei_{sev}",
                "hedef": hedef,
                "kanit": f"[{tid}] {name} (nuclei {sev})",
                "zaman_damgasi": r.get("timestamp") or
                _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "kapsam_referansi": kapsam,
            })
        return out

    # ------------------------------------------------------------------

    def run(self, targets: list, out_dir: str = ".") -> list:
        """targets: ['host:port', ...]. Dönüş: Finding dict listesi."""
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="nuclei")
            return []
        if not self.available():
            self.audit.append("NUCLEI_SKIP", sebep="nuclei ikilisi yok")
            return []

        # hedef listesi önceden scope filtresinden geçer (ilk kapı)
        onayli = []
        for t in targets:
            host, _, port_s = t.partition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            ok, reason = self.scope.check_request(host=host, port=port, method="GET")
            if ok:
                onayli.append(f"http://{t}")
            else:
                self.audit.append("SCOPE_DENY", host=host, port=port,
                                  reason=f"[nuclei] {reason}")
        if not onayli:
            self.audit.append("NUCLEI_END", bulgu=0, sebep="kapsam içi hedef yok")
            return []

        os.makedirs(out_dir, exist_ok=True)
        out_jsonl = os.path.join(out_dir, "nuclei-out.jsonl")
        cmd = [self.binary, "-jsonl", "-silent", "-o", out_jsonl,
               "-nc", "-stats=false"] + onayli
        if self.templates:
            cmd = [self.binary, "-jsonl", "-silent", "-o", out_jsonl,
                   "-nc", "-stats=false", "-t", self.templates] + onayli

        self.audit.append("NUCLEI_START", hedefler=onayli, komut=cmd[:6])
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            self.audit.append("NUCLEI_ERROR", sebep="timeout")
            return []

        rows = []
        if os.path.exists(out_jsonl):
            with open(out_jsonl, encoding="utf-8") as f:
                rows = [json.loads(l) for l in f if l.strip()]
        findings = self._to_findings(rows, self.scope.targets[0])
        with open(os.path.join(out_dir, "nuclei-findings.jsonl"), "a",
                  encoding="utf-8") as f:
            for fd in findings:
                f.write(json.dumps(fd, ensure_ascii=False) + "\n")
        self.audit.append("NUCLEI_END", bulgu=len(findings), taranan=len(onayli))
        return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="purpleloop.nucleus",
                                 description="Nuclei backend (scope-gated)")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--targets", required=True, help="host:port listesi (virgüllü)")
    ap.add_argument("--out-dir", default="nuclei-run")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    ap.add_argument("--templates", default=None)
    ap.add_argument("--timeout", type=int, default=300)
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
    ad = NucleiAdapter(scope=scope, killswitch=ks, audit=audit,
                       timeout=args.timeout, templates=args.templates)
    if not ad.available():
        print("nuclei ikilisi bulunamadı (kurulu değilse bu katman sessiz atlar)",
              file=sys.stderr)
        return 4
    findings = ad.run([t for t in args.targets.split(",") if t],
                      out_dir=args.out_dir)
    print(json.dumps({"bulgu": len(findings),
                      "audit_chain_valid": audit.verify_chain()},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
