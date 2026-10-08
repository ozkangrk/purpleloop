"""propose_probe: ajanın esnek sızma önerisi — kapı + filtre + kanıt zinciri.

Ajan runtime'da 'şu path'e şu payload'ı denemeliyim' der; platform:
  1) gerekçe şart (boş öneri ret)
  2) scope kapısı (host/port izinli mi)
  3) method beyaz listesi (yalnız GET/HEAD — esneklik sınırı)
  4) zararlık filtresi (yasaklı desenler: DROP/DELETE, rm -rf, shutdown...)
  5) hız limiti (token kova: aynı ajan saniyede N öneri)
  6) koşu → kanıt çıkarıcı (ajan 'buldum' diyemez; imza fonksiyonu karar verir)
  7) her adım audit'e (PROPOSE_ACCEPT / PROPOSE_REJECT nedeniyle)
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.agent_attack import (  # noqa: E402
    ProbeProposer, DANGEROUS_PATTERNS, is_dangerous,
)
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100],
             "methods": ["GET", "HEAD"]}


class FakeAttackTransport:
    """Ajanın önerdiği path'lere zayıf/temiz yanıtlar."""

    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(path)
        if "union" in path.lower() and "users" in path.lower():
            return (200, '{"data":[{"email":"admin@x.op"},{"email":"a@b.op"}]}', {})
        if path.endswith("/api/v2/orders") or "orders" in path:
            return (200, '{"orders":[{"id":1,"total":"$9,999"}]}', {})
        if "../" in path:
            return (403, "Forbidden", {})
        return (404, "not found", {})


def _proposer(tmp_path, transport=None, rate=10):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    return ProbeProposer(scope=scope, killswitch=ks, audit=audit,
                         out_path=str(tmp_path / "probes.jsonl"),
                         transport=transport or FakeAttackTransport(),
                         rate_per_minute=rate)


def _events(p):
    return [json.loads(l) for l in open(p.audit.path) if l.strip()]


# ---------------------------------------------------------------------------
# 1) Zararlılık filtresi
# ---------------------------------------------------------------------------

def test_dangerous_patterns_block_destructive():
    assert is_dangerous("/api?cmd=DROP TABLE users")
    assert is_dangerous("/x?c=rm%20-rf%20/")
    assert is_dangerous("/admin?action=shutdown")
    assert is_dangerous("/db?query=DELETE FROM users")
    assert is_dangerous("/etc?file=../../etc/shadow; cat")
    assert not is_dangerous("/rest/products/search?q=')) union select id,email from Users--")
    assert not is_dangerous("/ftp/package.json.bak%2500.md")
    assert not is_dangerous("/api/v2/orders")


def test_dangerous_pattern_list_documented():
    for pat in DANGEROUS_PATTERNS:
        assert isinstance(pat, str) and pat  # derlenmiş desen değil, ham dize


# ---------------------------------------------------------------------------
# 2) Öneri sözleşmesi
# ---------------------------------------------------------------------------

def test_propose_requires_gerekce(tmp_path):
    p = _proposer(tmp_path)
    r = p.propose("127.0.0.1", 3100, "/x", gerekce="")
    assert r["durum"] == "RED"
    assert "gerekçe" in r["sebep"].lower() or "gerekce" in r["sebep"].lower()


def test_propose_scope_gate(tmp_path):
    p = _proposer(tmp_path)
    r = p.propose("203.0.113.99", 3100, "/x", gerekce="test")
    assert r["durum"] == "RED"
    assert any(e["event"] == "SCOPE_DENY" for e in _events(p))


def test_propose_method_whitelist(tmp_path):
    p = _proposer(tmp_path)
    r = p.propose("127.0.0.1", 3100, "/x", gerekce="t", method="POST")
    assert r["durum"] == "RED"
    assert "method" in r["sebep"].lower()


def test_propose_dangerous_payload_rejected(tmp_path):
    p = _proposer(tmp_path)
    r = p.propose("127.0.0.1", 3100, "/api?cmd=DROP TABLE users",
                  gerekce="veri silmeyi deneyeyim")
    assert r["durum"] == "RED"
    evs = _events(p)
    assert any(e["event"] == "PROPOSE_REJECT" for e in evs)
    # RED kararında istek HİÇ gönderilmedi
    assert p.tx.calls == []


def test_propose_rate_limit(tmp_path):
    p = _proposer(tmp_path, rate=3)
    sonuçlar = [p.propose("127.0.0.1", 3100, f"/r{i}", gerekce=f"deneme {i}")
                for i in range(5)]
    redler = [r for r in sonuçlar if r["durum"] == "RED"]
    assert redler, "hız limiti dolunca RED gelmeli"
    assert any("hız" in r["sebep"].lower() or "rate" in r["sebep"].lower()
               for r in redler)


# ---------------------------------------------------------------------------
# 3) Kabul edilen öneri → koşu → kanıt
# ---------------------------------------------------------------------------

def test_propose_accepted_runs_and_extracts_evidence(tmp_path):
    p = _proposer(tmp_path)
    path = "/rest/products/search?q=')) union select id,email from Users--"
    r = p.propose("127.0.0.1", 3100, path,
                  gerekçe="arama parametresi SQLi şüphesi; e-posta desenini kanıt olarak arıyorum")
    assert r["durum"] == "KABUL"
    assert r["kanit"] and "@" in r["kanit"]     # e-posta imzası çıkarıldı
    assert any(e["event"] == "PROPOSE_ACCEPT" for e in _events(p))
    # bulgu dosyasına düştü
    fs = [json.loads(l) for l in open(p.out_path) if l.strip()]
    assert any(f["tip"] == "agent_probe_leak" for f in fs)


def test_propose_accepted_no_evidence_no_finding(tmp_path):
    """Kanıt imzası yoksa 'bulgu' ÜRETİLMEZ (ajan 'buldum' diyemez)."""
    p = _proposer(tmp_path)
    r = p.propose("127.0.0.1", 3100, "/api/v2/orders",
                  gerekçe="orders yüzeyini gördüm, veri sızıyor mu bakayım")
    assert r["durum"] == "KABUL"
    # orders JSON'unda e-posta yok → kanıt yok → bulgu yok (dosya bile oluşmaz)
    assert r["kanit"] is None
    import os
    if os.path.exists(p.out_path):
        fs = [json.loads(l) for l in open(p.out_path) if l.strip()]
        assert fs == []
    else:
        assert True  # hiç yazılmaması DAHA doğru


def test_propose_killswitch(tmp_path):
    (tmp_path / "KS").write_text("STOP")
    p = _proposer(tmp_path)
    r = p.propose("127.0.0.1", 3100, "/x", gerekce="t")
    assert r["durum"] == "RED"


# ---------------------------------------------------------------------------
# 4) Oturum özeti — ajanın saldırı bütçesi görünür
# ---------------------------------------------------------------------------

def test_session_summary(tmp_path):
    p = _proposer(tmp_path)
    p.propose("127.0.0.1", 3100, "/a", gerekce="1")
    p.propose("127.0.0.1", 3100, "/api?x=DROP TABLE t", gerekce="kötü")
    s = p.summary()
    assert s["kabul"] + s["red"] >= 2
    assert s["red"] >= 1
