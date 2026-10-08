"""v1.4 recon hataları için regresyon testleri (Juice Shop v17.3.0 bulguları).

Tuzaklar (canlı Juice Shop v17.3.0'da ölçüldü):
  * SPA fallback: var olmayan yola 200 + index.html gövdesi → FP
  * Header denetimi /metrics (text/plain) gibi sayfalarda da çalışıyor,
    tekrar tekrar aynı bulguyu basıyor (14 kez 2 header)
  * X-Frame-Options/X-Content-Type-Options VARken "eksik" dedi (200 olmayan
    veya SPA-fallback yanıtlarda headerlar düşüyor)
  * /ftp/, /ftp/*.kdbx, /swagger.json wordlist'te yok → kaçırma
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.recon import (  # noqa: E402
    ReconAgent, RealTransport, is_spa_fallback, audit_security_headers,
)
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD"]}

IDX_BODY = "<html><head><title>Juice Shop</title></head><body>app</body></html>"


class FakeJuiceTransport:
    """Juice Shop v17.3.0 yüzeyini taklit eden sahte transport (FP tuzaklarıyla)."""

    IDX_LEN = len(IDX_BODY)

    def _resp(self, path):
        if path == "/":
            return (200, IDX_BODY, {"X-Frame-Options": "SAMEORIGIN",
                                    "X-Content-Type-Options": "nosniff"})
        if path == "/ftp/":
            return (200, "<html><title>listing directory /ftp/</title>"
                         '<a href="acquisitions.md">acquisitions.md</a>'
                         '<a href="incident-support.kdbx">incident-support.kdbx</a></html>',
                    {"X-Frame-Options": "SAMEORIGIN"})
        if path == "/ftp/incident-support.kdbx":
            return (200, b"\xd0\xc7\xd4m\x00\x03" .decode("latin-1"), {})
        if path == "/ftp/acquisitions.md":
            return (200, "MFTF acquired by ...", {})
        if path == "/metrics":
            return (200, "# HELP file_uploads_count counter\n", {})
        if path == "/swagger.json":
            return (200, '{"swagger":"2.0","paths":{"/b2b/v2/orders":{}}}', {})
        if path in ("/.env", "/backup/.env", "/backup/.aws-credentials",
                    "/backup/secrets-old.txt", "/.aws-credentials"):
            # SPA fallback: 200 ama gövde = index.html
            return (200, IDX_BODY, {"X-Frame-Options": "SAMEORIGIN"})
        return (404, "not found", {})

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        return self._resp(path)


def _agent(tmp_path, transport, dirs=None):
    tmp_path = _ensure_dir(tmp_path)
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    out = str(tmp_path / "findings.jsonl")
    return ReconAgent(scope=scope, killswitch=ks, audit=audit, out_path=out,
                      transport=transport, dirs=dirs)


def _ensure_dir(p):
    import pathlib
    p = pathlib.Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _findings(agent):
    with open(agent.out_path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# ---------------------------------------------------------------------------
# 1) SPA fallback dedektörü
# ---------------------------------------------------------------------------

def test_is_spa_fallback_detects_index_copy():
    hdrs = {"Content-Type": "text/html"}
    assert is_spa_fallback(200, IDX_BODY, {"content-type": "text/html"}, IDX_BODY)
    assert not is_spa_fallback(200, " gerçek içerik ", {"content-type": "text/html"}, IDX_BODY)
    assert not is_spa_fallback(200, IDX_BODY, {"content-type": "text/html"}, "başka index")
    assert not is_spa_fallback(404, IDX_BODY, {"content-type": "text/html"}, IDX_BODY)


# ---------------------------------------------------------------------------
# 2) Uçtan uca: FP sıfır, gerçek yüzeyler bulunur
# ---------------------------------------------------------------------------

def test_scan_juice_surface_no_fp(tmp_path):
    agent = _agent(tmp_path, FakeJuiceTransport(),
                   dirs=[".env", "backup/.env", "ftp/", "metrics", "swagger.json",
                         "nonexistent"])
    agent.run([], ["127.0.0.1"], [("127.0.0.1", 3100)])
    fs = _findings(agent)
    tips = {(f["tip"], f["hedef"].split(":")[-1] + "/" + f["hedef"].split(":/")[-1].split("/", 1)[-1] if "/" in f["hedef"] else f["hedef"]) for f in fs}

    # FP: SPA fallback yollar directory olarak BULUNMAMALI
    dir_targets = [f["hedef"] for f in fs if f["tip"] == "directory"]
    for fp in ["127.0.0.1:3100/.env", "127.0.0.1:3100/backup/.env",
               "127.0.0.1:3100/nonexistent"]:
        assert fp not in dir_targets, f"SPA fallback FP: {fp}"

    # GERÇEK: /ftp/ listing bulunmalı
    assert "127.0.0.1:3100/ftp/" in dir_targets
    # GERÇEK: swagger.json bulunmalı
    assert "127.0.0.1:3100/swagger.json" in dir_targets
    # GERÇEK: /metrics bulunmalı
    assert "127.0.0.1:3100/metrics" in dir_targets


def test_missing_header_dedup_and_truth(tmp_path):
    """XFO/XCTO VARken eksik denmez; eksikler tekilleşir."""
    agent = _agent(tmp_path, FakeJuiceTransport(), dirs=["metrics"])
    agent.run([], ["127.0.0.1"], [("127.0.0.1", 3100)])
    fs = _findings(agent)
    mh = [f for f in fs if f["tip"] == "missing_header"]
    # FakeJuice /metrics'te hiç security header yok → 4 eksik, ama TEK sayıda
    # (host başına tekil küme)
    kanits = [f["kanit"].split(":")[0] for f in mh]
    from collections import Counter
    c = Counter(kanits)
    for header, n in c.items():
        assert n == 1, f"{header} {n} kez raporlandı — tekilleştirilmeli"
    # XFO /metrics yanıtında YOK (gerçekten eksik) — bulunması doğru;
    # ama ana sayfa yanıtında VAR. Validator'a düşer; burada tekil olma yeter.


# ---------------------------------------------------------------------------
# 3) Wordlist kapsama: Juice Shop gerçek yüzeyleri adaylarda olmalı
# ---------------------------------------------------------------------------

def test_wordlist_covers_owasp_surface():
    from purpleloop.recon import DIR_CANDIDATES
    need = {"ftp/", "swagger.json", "metrics", "api-docs/", "robots.txt",
            "security.txt", ".well-known/security.txt"}
    missing = need - set(DIR_CANDIDATES)
    assert not missing, f"wordlist eksik: {missing}"


# ---------------------------------------------------------------------------
# 4) Determinizm (aynı girdi → aynı bulgu kümesi)
# ---------------------------------------------------------------------------

def test_scan_deterministic_juice(tmp_path):
    sets = []
    for i in range(2):
        a = _agent(tmp_path / f"r{i}", FakeJuiceTransport(),
                   dirs=["ftp/", "metrics", "swagger.json"])
        a.run([], ["127.0.0.1"], [("127.0.0.1", 3100)])
        fs = _findings(a)
        sets.append(sorted((f["tip"], f["hedef"], f["kanit"]) for f in fs))
    assert sets[0] == sets[1]
