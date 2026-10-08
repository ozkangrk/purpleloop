"""v1.6: Platform katmanı — SARIF 2.1.0 export, policy gate, OSV zenginleştirme.

Üç parça (hepsi saf/stdlib; OSV yalnız urllib):
  to_sarif()       — bulguları SARIF 2.1.0'a çevirir (CI kapı ortak formatı;
                     OWASP DevSecOps: security-severity ile tek sayısal eşik)
  PolicyGate       — error/warning eşikleriyle CI exit kararı (PASS/FAIL),
                     bypass bileti kaydı (ticket olmadan baypas yok)
  parse_lockfile_deps + OSVClient — sızan package.json/requirements.txt'den
                     bağımlılık çıkarımı ve OSV.dev querybatch ile bilinen
                     CVE/MAL zenginleştirme (kanıt zincirine yazılır)
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Optional

# ---------------------------------------------------------------------------
# Önem haritaları (tip -> SARIF level + security-severity)
# ---------------------------------------------------------------------------

_SEVERITY = {
    # tip: (level, security-severity 0-10)
    "sqli_data_leak": ("error", 9.8),
    "sqli_signature": ("error", 9.1),
    "error_disclosure": ("warning", 5.3),
    "extension_filter_bypass": ("warning", 6.5),
    "open_bucket": ("error", 8.6),
    "secret": ("error", 9.0),
    "directory": ("warning", 5.0),
    "missing_header": ("note", 3.1),
    "open_port": ("note", 0.0),
    "open_redirect": ("warning", 6.1),
    "bucket_service": ("warning", 4.3),
    # --- sızma (pentest/vectors/bounty) bulgu tipleri ---
    "auth_bypass": ("error", 9.5),              # kimlik aşımı: kritik
    "path_traversal": ("error", 9.3),           # dosya okuma: kritik
    "idor": ("error", 8.2),                     # yatay yetki aşımı
    "auth_anonymous_session": ("warning", 6.8), # kimliksiz veri yüzeyi
    "xss_reflection": ("warning", 6.4),
    "jwt_alg_none": ("error", 9.6),             # imzasız token
    "xxe_signature": ("error", 8.8),
    "method_abuse": ("note", 2.5),
    "default_login_surface": ("warning", 5.5),
    "bounty_solve": ("error", 8.0),             # skorboard doğrulamalı çözüm
    "agent_probe_leak": ("error", 8.5),        # ajan önerisinden kanıtlı sızıntı
    "nuclei_critical": ("error", 9.7),
    "nuclei_high": ("error", 8.5),
    "nuclei_medium": ("warning", 5.5),
    "nuclei_low": ("warning", 3.5),
    "nuclei_info": ("note", 1.0),
}


def to_sarif(findings: list, tool_version: str = "") -> dict:
    """Bulgu listesini SARIF 2.1.0 belgesine çevirir."""
    rules = {}
    results = []
    for f in findings:
        tip = f.get("tip", "bilinmeyen")
        level, sev = _SEVERITY.get(tip, ("note", 1.0))
        if tip not in rules:
            rules[tip] = {
                "id": tip,
                "shortDescription": {"text": tip},
                "properties": {"security-severity": str(sev)},
            }
        hedef = f.get("hedef", "")
        host, _, rest = hedef.partition(":")
        results.append({
            "ruleId": tip,
            "level": level,
            "message": {"text": f.get("kanit", "")[:500]},
            "locations": [{
                "physicalLocation": {
                    "logicalLocations": [{"name": hedef or host}],
                },
            }],
            "properties": {
                "zaman_damgasi": f.get("zaman_damgasi", ""),
                "kapsam_referansi": f.get("kapsam_referansi", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PurpleLoop",
                    "informationUri": "https://github.com/ozkangrk/purpleloop",
                    "version": tool_version or "1.6.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------

class PolicyGate:
    """Eşik tabanlı CI kapısı: error/warning sayısı eşiği aşarsa FAIL."""

    def __init__(self, max_error: int = 0, max_warning: int = 10):
        self.max_error = max_error
        self.max_warning = max_warning

    def evaluate(self, findings: list, bypass_ticket: str = "") -> dict:
        error = sum(1 for f in findings
                    if _SEVERITY.get(f.get("tip", ""), ("note", 0))[0] == "error")
        warning = sum(1 for f in findings
                      if _SEVERITY.get(f.get("tip", ""), ("note", 0))[0] == "warning")
        asim = error > self.max_error or warning > self.max_warning
        durum = "FAIL" if asim else "PASS"
        if asim and bypass_ticket:
            durum = "FAIL_WITH_BYPASS"  # kayıt var, karar yine flag'li
        return {"durum": durum, "error": error, "warning": warning,
                "esik": {"error": self.max_error, "warning": self.max_warning},
                "bypass_ticket": bypass_ticket or None}


# ---------------------------------------------------------------------------
# Bağımlılık çıkarımı + OSV zenginleştirme
# ---------------------------------------------------------------------------

_REQ_EQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", re.M)


def parse_lockfile_deps(text: str) -> list:
    """package.json (npm) veya requirements.txt (pip) bağımlılıklarını çıkarır.

    Dönen: [(isim, sürüm)]. Sürüm belirsizse (>=, ~siz) atlanır — OSV sorgusu
    kesin sürüm ister.
    """
    text = text.strip()
    if text.startswith("{"):
        try:
            pkg = json.loads(text)
        except json.JSONDecodeError:
            return []
        deps = []
        for bölüm in ("dependencies", "devDependencies"):
            for name, spec in (pkg.get(bölüm) or {}).items():
                m = re.match(r"^\D*(\d[^\s*^~><|]*)", str(spec))
                if m:
                    deps.append((name, m.group(1)))
        return deps
    return _REQ_EQ.findall(text)


class OSVClient:
    """OSV.dev v1 API istemcisi (querybatch; stdlib urllib)."""

    def __init__(self, base_url: str = "https://api.osv.dev/v1", timeout: int = 20):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def build_querybatch(self, deps: list, ecosystem: str = "npm") -> dict:
        return {"queries": [
            {"version": v, "package": {"name": n, "ecosystem": ecosystem}}
            for n, v in deps
        ]}

    async def query(self, deps: list, ecosystem: str = "npm") -> list:
        """Bağımlılıkları OSV'ye sorar; [(dep, vuln_dict)] döner (async)."""
        import anyio
        body = self.build_querybatch(deps, ecosystem)
        req = urllib.request.Request(
            self.base + "/querybatch",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        def _fetch():
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        raw = await anyio.to_thread.run_sync(_fetch)
        out = []
        for (name, ver), res in zip(deps, raw.get("results", [])):
            for v in res.get("vulns", []):
                out.append({"paket": f"{name}@{ver}", "id": v.get("id"),
                            "ozet": (v.get("summary") or "")[:200],
                            "guvenlik_seviyesi": max(
                                (s.get("score") or 0) for s in [v.get("severity") or {}]
                            ) if isinstance(v.get("severity"), list) else
                            (v.get("severity") or {}).get("score", None)})
        return out


# ---------------------------------------------------------------------------
# CLI: sarif + gate + osv alt komutları
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import os
    import sys
    ap = argparse.ArgumentParser(prog="purpleloop.platform",
                                 description="SARIF export / policy gate / OSV zenginleştirme")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("sarif", help="findings.jsonl -> SARIF 2.1.0")
    sp.add_argument("--findings", required=True)
    sp.add_argument("--out", required=True)

    gp = sub.add_parser("gate", help="policy gate kararı (CI exit)")
    gp.add_argument("--findings", required=True)
    gp.add_argument("--max-error", type=int, default=0)
    gp.add_argument("--max-warning", type=int, default=10)
    gp.add_argument("--bypass-ticket", default="")

    op = sub.add_parser("osv", help="sızan package.json/requirements.txt -> OSV CVE")
    op.add_argument("--file", required=True)
    op.add_argument("--ecosystem", default="npm")
    op.add_argument("--out", default="")

    args = ap.parse_args(argv)

    def _load_findings(path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    if args.cmd == "sarif":
        sarif = to_sarif(_load_findings(args.findings))
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=1)
        print(f"SARIF yazıldı: {args.out} ({len(sarif['runs'][0]['results'])} sonuç)")
        return 0

    if args.cmd == "gate":
        karar = PolicyGate(args.max_error, args.max_warning).evaluate(
            _load_findings(args.findings), args.bypass_ticket)
        print(json.dumps(karar, ensure_ascii=False))
        return 1 if karar["durum"] == "FAIL" else 0

    if args.cmd == "osv":
        text = open(args.file, encoding="utf-8").read()
        deps = parse_lockfile_deps(text)
        if not deps:
            print("bağımlılık bulunamadı", file=sys.stderr)
            return 2
        import anyio
        client = OSVClient()
        vulns = anyio.run(client.query, deps, args.ecosystem)
        satirlar = [json.dumps(v, ensure_ascii=False) for v in vulns]
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n".join(satirlar) + "\n")
        print(f"{len(deps)} bağımlılık sorgulandı, {len(vulns)} zafiyet")
        for v in vulns[:10]:
            print(f"  {v['id']:24} {v['paket']}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
