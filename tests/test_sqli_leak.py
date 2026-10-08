"""sqli_data_leak probu testleri — UNION tablo sızıntısı doğrulaması.

Kanıt kuralı (FP kapısı): payload'ın yanıtında email/bcrypt DESENİ VAR ve
payload'sız kontrol yanıtında YOK → gerçek sızıntı. İkisi de varsa (sayfada
zaten email yazıyor) bulgu ÜRETİLMEZ.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.active import ActiveProbe, leaked_credential_evidence  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD"]}


class FakeSqliTransport:
    """Payload'a users sızıntısı, kontrol sorgusuna temiz yanıt döner."""

    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(path)
        if "union" in path.lower() and "from%20users" in path.lower().replace("+", "%20"):
            body = ('{"status":"success","data":[{"id":1,"name":"admin@juice-sh.op",'
                    '"description":"x","price":1}]}')
            return (200, body, {"content-type": "application/json"})
        if "search?q=" in path:
            return (200, '{"status":"success","data":[{"name":"Apple Juice"}]}',
                    {"content-type": "application/json"})
        return (404, "not found", {})


class FakeBenignTransport:
    """Payload da kontrol de temiz — bulgu ÜRETMEMELİ (FP kapısı)."""

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        if "/rest/products/search" in path:
            # sayfada zaten email yazıyor (ör. iletişim sayfası JSON'u)
            body = '{"data":[{"support":"support@shop.example"}]}'
            return (200, body, {"content-type": "application/json"})
        return (404, "not found", {})


def _probe(tmp_path, transport):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    return ActiveProbe(scope=scope, killswitch=ks, audit=audit,
                       out_path=str(tmp_path / "f.jsonl"), transport=transport)


def _findings(p):
    with open(p.out_path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# ---------------------------------------------------------------------------
# Kanıt çıkarıcı birim testleri
# ---------------------------------------------------------------------------

def test_leaked_credential_evidence_finds_email():
    ev = leaked_credential_evidence('{"a":"admin@juice-sh.op"}')
    assert ev and "admin@juice-sh.op" in ev


def test_leaked_credential_evidence_finds_bcrypt():
    ev = leaked_credential_evidence('{"p":"$2a$10$Nk9hzMxVfLKpaPBEcVYmYO0FHcGzSFFbtHqBoQ1cJdCXxgXx"}')
    assert ev and "$2a$" in ev


def test_leaked_credential_evidence_clean():
    assert leaked_credential_evidence('{"name":"Apple Juice"}') is None


# ---------------------------------------------------------------------------
# Prob davranışı
# ---------------------------------------------------------------------------

def test_sqli_data_leak_detected(tmp_path):
    p = _probe(tmp_path, FakeSqliTransport())
    f = p.probe_sqli_leak("127.0.0.1", 3100)
    assert f is not None
    assert f["tip"] == "sqli_data_leak"
    assert "admin@juice-sh.op" in f["kanit"]
    fs = _findings(p)
    assert any(x["tip"] == "sqli_data_leak" for x in fs)


def test_sqli_data_leak_no_fp_when_benign(tmp_path):
    """Sayfada zaten email varsa (payload farkı yoksa) bulgu ÜRETİLMEZ."""
    p = _probe(tmp_path, FakeBenignTransport())
    f = p.probe_sqli_leak("127.0.0.1", 3100)
    assert f is None, "payload ile kontrol arasında fark yoksa bulgu üretilmemeli"


def test_sqli_leak_scope_gated(tmp_path):
    p = _probe(tmp_path, FakeSqliTransport())
    f = p.probe_sqli_leak("203.0.113.99", 3100)
    assert f is None
    with open(p.audit.path, encoding="utf-8") as fh:
        assert any(json.loads(l)["event"] == "SCOPE_DENY" for l in fh)
