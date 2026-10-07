"""Hafta-3 Validator testleri: deterministik yeniden doğrulama, scope kapısı,
kill-switch, LLM danışmanın yetkisizliği."""
from __future__ import annotations

import json
import socket

import pytest

from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.recon import RealTransport
from purpleloop.scope import ScopeContract
from purpleloop.validator import ValidatorAgent, LLMAnalyzer, _parse_hedef

SCOPE_DOC = {
    "targets": ["127.0.0.1", "*.example.com"],
    "ports": [8081, 9010, 443],
    "methods": ["GET", "HEAD"],
}

FAKE_HTTP = {
    "/backup/.env": (200, "MINIO_ROOT_PASSWORD=purplelab-secret\n", "nginx"),
    "/public/": (200, "<?xml version=\"1.0\"?><ListBucketResult></ListBucketResult>", "MinIO"),
    "/gone/": (404, "<html>not found</html>", "nginx"),
}


class FakeTransport:
    def __init__(self, open_ports=(), http=None, fail_http=False):
        self.open_ports = set(open_ports)
        self.http = http or {}
        self.fail_http = fail_http

    def tcp_connect(self, host, port, timeout=2.0):
        return (host, port) in self.open_ports

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        if self.fail_http:
            return None
        return self.http.get(path)


@pytest.fixture()
def env(tmp_path):
    return {
        "audit": AuditLog(str(tmp_path / "audit.jsonl")),
        "out": str(tmp_path / "validated.jsonl"),
        "scope": ScopeContract(SCOPE_DOC),
        "ks": KillSwitch(str(tmp_path / "KS")),
        "tmp": tmp_path,
    }


def make_agent(env, tx):
    return ValidatorAgent(scope=env["scope"], killswitch=env["ks"],
                          audit=env["audit"], out_path=env["out"], transport=tx)


# ---------- yardımcı ----------

def test_parse_hedef():
    assert _parse_hedef("127.0.0.1:8081/backup/.env") == ("127.0.0.1", 8081, "/backup/.env")
    assert _parse_hedef("lab.example.com") == ("lab.example.com", None, "/")


# ---------- deterministik doğrulama ----------

def test_open_port_confirmed_and_rejected(env):
    tx = FakeTransport(open_ports={("127.0.0.1", 8081)})
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "open_port", "hedef": "127.0.0.1:8081", "kanit": "x"})
    assert v.verdict == "CONFIRMED"
    v2 = agent.validate_finding({"tip": "open_port", "hedef": "127.0.0.1:9010", "kanit": "x"})
    assert v2.verdict == "REJECTED"


def test_secret_reconfirmed_by_refetch(env):
    tx = FakeTransport(http=FAKE_HTTP)
    agent = make_agent(env, tx)
    f = {"tip": "secret", "hedef": "127.0.0.1:8081/backup/.env",
         "kanit": "MINIO_ROOT_PASSWORD=purplelab-secret"}
    v = agent.validate_finding(f)
    assert v.verdict == "CONFIRMED"
    assert env["audit"].verify_chain()


def test_secret_rejected_when_content_clean(env):
    tx = FakeTransport(http={"/ok.txt": (200, "burada parola geçiyor ama atanmış değil\n", "nginx")})
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "secret", "hedef": "127.0.0.1:8081/ok.txt",
                                "kanit": "password=eski-sifre-123"})
    assert v.verdict == "REJECTED"
    assert "yok" in v.gerekce


def test_open_bucket_confirmed(env):
    tx = FakeTransport(http=FAKE_HTTP)
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "open_bucket", "hedef": "127.0.0.1:9010/public/", "kanit": "x"})
    assert v.verdict == "CONFIRMED"


def test_directory_rejected_on_404(env):
    tx = FakeTransport(http=FAKE_HTTP)
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "directory", "hedef": "127.0.0.1:8081/gone/", "kanit": "x"})
    assert v.verdict == "REJECTED"


def test_unreachable_target_unverified(env):
    tx = FakeTransport(fail_http=True)
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "directory", "hedef": "127.0.0.1:8081/x/", "kanit": "x"})
    assert v.verdict == "UNVERIFIED"


def test_unknown_tip_unverified(env):
    agent = make_agent(env, FakeTransport())
    v = agent.validate_finding({"tip": "gelecek_tip", "hedef": "127.0.0.1:8081", "kanit": "x"})
    assert v.verdict == "UNVERIFIED"


# ---------- scope kapısı ----------

def test_out_of_scope_finding_skipped_and_denied(env):
    tx = FakeTransport(open_ports={("203.0.113.99", 8081)})
    agent = make_agent(env, tx)
    v = agent.validate_finding({"tip": "open_port", "hedef": "203.0.113.99:8081", "kanit": "x"})
    assert v.verdict == "SKIPPED_SCOPE_DENIED"
    with open(env["audit"].path) as f:
        events = [json.loads(l)["event"] for l in f if l.strip()]
    assert "SCOPE_DENY" in events and "VALIDATION" in events
    assert env["audit"].verify_chain()


# ---------- kill switch ----------

def test_killswitch_stops_validation(env):
    (env["tmp"] / "KS").write_text("stop")
    tx = FakeTransport(open_ports={("127.0.0.1", 8081)})
    agent = make_agent(env, tx)
    findings = [{"tip": "open_port", "hedef": "127.0.0.1:8081", "kanit": "x"}] * 3
    vals = agent.run(findings)
    assert len(vals) == 1 and vals[0].verdict == "UNVERIFIED"
    assert agent._stopped


# ---------- LLM danışman yetkisiz ----------

def test_llm_analyzer_failure_is_nonblocking():
    # erişılamaz endpoint => None, verdict etkilenmez
    a = LLMAnalyzer("http://127.0.0.1:1/v1")
    assert a.summarize([{"tip": "x"}], []) is None


# ---------- canlı lab ----------

def is_alive(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not (is_alive("127.0.0.1", 8081) and is_alive("127.0.0.1", 9010)),
                    reason="lab çalışmıyor")
def test_live_lab_validation(env):
    agent = make_agent(env, RealTransport())
    findings = [json.loads(l) for l in open("evidence/findings.jsonl") if l.strip()]
    vals = agent.run(findings)
    verdicts = [v.verdict for v in vals]
    assert verdicts.count("CONFIRMED") >= 10
    assert "SKIPPED_SCOPE_DENIED" not in verdicts
    assert env["audit"].verify_chain()
