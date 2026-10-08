"""v1.5 aktif prob testleri — GET-only safe-mode kontroller (Juice Shop sınıfı).

Sınıf: kimlik doğrulamasız, YALNIZ GET/HEAD, tek isteklik problar.
Her prob: kapsam kapısından geçer, kanıtla birlikte Finding üretir.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.active import ActiveProbe, is_error_disclosure  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD"]}


class FakeActiveTransport:
    """Juice Shop benzeri yanıtlar: hata ifşası, SQLi imzası, XSS yankısı, bypass."""

    calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        FakeActiveTransport.calls.append((host, port, path))
        if "/rest/products/search" in path:
            if "'" in path or "%27" in path:
                # SQLi: Sequelize/SQLite hatası ifşa
                body = ("Error: SQLITE_ERROR: near \";\": syntax error\n"
                        "at Statement.run (sqlite3/lib/sqlite3.js)")
                return (500, body, {"content-type": "text/html"})
            return (200, '{"status":"success","data":[]}', {"content-type": "application/json"})
        if path.startswith("/redirect"):
            # allowlist dışı hedef → 406; izinli → 302 + Location
            if "example.com" in path:
                return (406, "not allowed", {})
            return (302, "", {"location": "https://google.com"})
        if "/ftp/" in path:
            if path.endswith(".bak") or path.endswith(".yml"):
                return (403, "Error: Forbidden file type", {"content-type": "text/html"})
            # %2500.md bypass: sunucu .md sanır, dosya .bak içeriği döner
            if "%2500" in path:
                return (200, '{"name":"juice-shop","dependencies":{}}', {})
            return (200, "listing", {})
        if path == "/rest/does-not-exist":
            return (500, "Error: Unexpected path: /rest/does-not-existen stack trace...",
                    {"content-type": "text/html"})
        return (404, "not found", {})


def _probe(tmp_path, transport=None):
    tmp_path.mkdir(parents=True, exist_ok=True) if hasattr(tmp_path, "mkdir") else None
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    out = str(tmp_path / "findings.jsonl")
    return ActiveProbe(scope=scope, killswitch=ks, audit=audit, out_path=out,
                       transport=transport or FakeActiveTransport())


def _findings(probe):
    with open(probe.out_path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# ---------------------------------------------------------------------------
# 1) Hata ifşası dedektörü
# ---------------------------------------------------------------------------

def test_is_error_disclosure():
    assert is_error_disclosure(500, "Error: SQLITE_ERROR: near \";\" syntax error\nat sqlite3.js")
    assert is_error_disclosure(500, "TypeError: Cannot read property 'x' of undefined\n    at Layer.handle")
    assert not is_error_disclosure(500, "internal error")            # jenerik, iz yok
    assert not is_error_disclosure(200, "Error: SQLITE_ERROR ...")   # 200 hata sayacı değil
    assert not is_error_disclosure(404, "not found")


# ---------------------------------------------------------------------------
# 2) Uçtan uca problar
# ---------------------------------------------------------------------------

def test_probe_error_disclosure(tmp_path):
    p = _probe(tmp_path)
    p.run([("127.0.0.1", 3100)])
    tips = {f["tip"] for f in _findings(p)}
    assert "error_disclosure" in tips


def test_probe_sqli_signature(tmp_path):
    p = _probe(tmp_path)
    p.run([("127.0.0.1", 3100)])
    fs = _findings(p)
    sqli = [f for f in fs if f["tip"] == "sqli_signature"]
    assert sqli, "GET-param SQLi hatası bulunmalı"
    assert "SQLITE_ERROR" in sqli[0]["kanit"]


def test_probe_extension_bypass(tmp_path):
    p = _probe(tmp_path)
    p.run([("127.0.0.1", 3100)])
    fs = _findings(p)
    bp = [f for f in fs if f["tip"] == "extension_filter_bypass"]
    assert bp, "%2500 uzantı filtresi bypass'ı bulunmalı"
    assert any("%2500" in f["hedef"] for f in bp)


def test_probe_redirect_validation(tmp_path):
    p = _probe(tmp_path)
    p.run([("127.0.0.1", 3100)])
    fs = _findings(p)
    rd = [f for f in fs if f["tip"] == "open_redirect"]
    # allowlist ÇALIŞIYOR (406) → open_redirect bulgusu OLMAMALI (FP yok)
    assert rd == []


def test_probe_scope_gated(tmp_path):
    """Tuzak host'a tek istek bile gitmemeli."""
    p = _probe(tmp_path)
    FakeActiveTransport.calls = []
    p.run([("203.0.113.99", 80)])
    assert FakeActiveTransport.calls == []
    with open(p.audit.path, encoding="utf-8") as f:
        assert any(json.loads(l)["event"] == "SCOPE_DENY" for l in f)


def test_probe_killswitch_halts(tmp_path):
    (tmp_path / "KS").write_text("STOP")
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    p = ActiveProbe(scope=scope, killswitch=ks, audit=audit,
                    out_path=str(tmp_path / "f.jsonl"))
    fs = p.run([("127.0.0.1", 3100)])
    assert fs == []
