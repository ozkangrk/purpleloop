"""Bounty harness testleri — CTF scoreboard mekanikli sızma ölçümü.

Desen: InterCode-CTF/EnIGMA benzeri — ajan dener, UYGULAMANIN KENDİ
skorboardu (/api/challenges solved alanı) doğrular. Yanlış-çoğaltma yok:
solve kanıtı sunucudan gelir, bizden değil.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.bounty import (  # noqa: E402
    BountyHarness, BOUNTY_VECTORS, difficulty_to_severity, load_catalog,
)

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD", "POST"]}

CATALOG = [
    {"key": "scoreBoardChallenge", "name": "Score Board", "difficulty": 1,
     "solved": False, "category": "Security Misconfiguration"},
    {"key": "metricsChallenge", "name": "Exposed Metrics", "difficulty": 1,
     "solved": False, "category": "Sensitive Data Exposure"},
    {"key": "confidentialDocumentChallenge", "name": "Confidential Document",
     "difficulty": 2, "solved": False, "category": "Sensitive Data Exposure"},
    {"key": "errorHandlingChallenge", "name": "Error Handling", "difficulty": 1,
     "solved": True, "category": "Improper Error Handling"},
]


class FakeBountyTransport:
    """Vektörlere karşılık: score-board 200, metrics 200, ftp md 200,
    diğerleri 404. challenge kataloğu da transport üzerinden."""

    def __init__(self):
        self.solved_by_server = set()   # vektör çalısınca sunucunun çözdükleri
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(path)
        if path == "/api/challenges":
            cat = [dict(c, solved=c["key"] in self.solved_by_server or c["solved"])
                   for c in CATALOG]
            return (200, json.dumps({"status": "success", "data": cat}),
                    {"content-type": "application/json"})
        if path == "/score-board":
            self.solved_by_server.add("scoreBoardChallenge")
            return (200, "<html>score board</html>", {"content-type": "text/html"})
        if path == "/metrics":
            self.solved_by_server.add("metricsChallenge")
            return (200, "# HELP metric", {"content-type": "text/plain"})
        if path == "/ftp/acquisitions.md":
            self.solved_by_server.add("confidentialDocumentChallenge")
            return (200, "top secret M&A", {"content-type": "text/plain"})
        if "../" in path:
            return (403, "forbidden", {})
        return (404, "not found", {})


def _harness(tmp_path, transport=None):
    from purpleloop.scope import ScopeContract
    from purpleloop.audit import AuditLog
    from purpleloop.killswitch import KillSwitch
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    return BountyHarness(scope=scope, killswitch=ks, audit=audit,
                         out_path=str(tmp_path / "bounty.jsonl"),
                         transport=transport or FakeBountyTransport(),
                         catalog=None,   # katalog HER ÇEKİŞTE transport'tan (dinamik solved)
                         )


# ---------------------------------------------------------------------------
# Katalog + ödül haritası
# ---------------------------------------------------------------------------

def test_difficulty_to_severity():
    assert difficulty_to_severity(1) == "low"
    assert difficulty_to_severity(2) == "medium"
    assert difficulty_to_severity(3) == "high"
    assert difficulty_to_severity(5) == "critical"
    assert difficulty_to_severity(6) == "critical"


def test_load_catalog_from_api_shape():
    js = {"status": "success", "data": CATALOG}
    cat = load_catalog(js)
    assert len(cat) == 4
    assert cat[0]["key"] == "scoreBoardChallenge"


# ---------------------------------------------------------------------------
# Vektörler
# ---------------------------------------------------------------------------

def test_vectors_are_get_only_and_documented():
    for v in BOUNTY_VECTORS:
        assert v["path"].startswith("/")
        assert "hedef_challenge" in v          # None olabilir (salt keşif)
        assert v["aciklama"]
        assert isinstance(v["beklenen_status"], int)


# ---------------------------------------------------------------------------
# Uçtan uca: dene → sunucu doğrulası → skor artışı ölçülür
# ---------------------------------------------------------------------------

def test_bounty_run_solves_and_measures(tmp_path):
    h = _harness(tmp_path)
    r = h.run([("127.0.0.1", 3100)])
    # 3 vektör çözdü + Error Handling zaten çözülmüştü → toplam 4, YENİ 3
    assert r["cozulen"] == 4
    yeni = set(r["yeni"])
    assert yeni == {"scoreBoardChallenge", "metricsChallenge",
                    "confidentialDocumentChallenge"}
    assert "errorHandlingChallenge" not in yeni  # zaten vardı
    # ödül toplamı pozitif ve kayıtlı
    assert r["odul_toplami"] > 0
    # findings dosyasına yalnız YENİ çözümler için bounty_solve düştü
    fs = [json.loads(l) for l in open(h.out_path) if l.strip()]
    solves = [f for f in fs if f["tip"] == "bounty_solve"]
    assert len(solves) == 3


def test_bounty_scope_gated(tmp_path):
    h = _harness(tmp_path)
    tr = h.tx
    tr.calls = []
    h.run([("203.0.113.99", 3100)])
    assert tr.calls == []


def test_bounty_killswitch(tmp_path):
    (tmp_path / "KS").write_text("STOP")
    h = _harness(tmp_path)
    r = h.run([("127.0.0.1", 3100)])
    assert r["cozulen"] == 0
