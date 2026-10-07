"""Hafta-2 recon agent testleri.

Fake transport ile: kapsam kapısı, kill-switch, Finding yapısı, FP kontrolü,
lab'daki ekili varlıkların tümünün bulunması, kapsam dışı hedefin taranmaması.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import http.server

import pytest

from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.recon import Finding, ReconAgent, scan_secrets
from purpleloop.scope import ScopeContract

SCOPE_DOC = {
    "targets": ["127.0.0.1", "lab.local", "*.example.com"],
    "ports": [8081, 9010, 443],
    "methods": ["GET", "HEAD"],
}


class FakeTransport:
    """Kayıtlı çağrılar + önceden tanımlı yanıtlar."""

    def __init__(self, open_ports=(), http_responses=None):
        self.open_ports = set(open_ports)
        self.http_responses = http_responses or {}
        self.calls = []  # (kind, host, port, path?)

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls.append(("tcp", host, port, None))
        return (host, port) in self.open_ports

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(("http", host, port, path))
        return self.http_responses.get(path)


@pytest.fixture()
def env(tmp_path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    out = str(tmp_path / "findings.jsonl")
    scope = ScopeContract(SCOPE_DOC)
    ks = KillSwitch(str(tmp_path / "KILLSWITCH"))
    return {"audit": audit, "out": out, "scope": scope, "ks": ks, "tmp": tmp_path}


def make_agent(env, tx, **kw):
    return ReconAgent(scope=env["scope"], killswitch=env["ks"],
                      audit=env["audit"], out_path=env["out"], transport=tx, **kw)


# ---------------- secret regex / FP ----------------

def test_scan_secrets_finds_planted_passwords():
    text = "db_password=PurpleL00p!Lab-2026\nadmin_pwd=S3cret-Backdoor-Passw0rd\napi_token=ghp_purpleloopFAKEtoken1234567890\n"
    hits = [t for t, _ in scan_secrets(text)]
    assert hits.count("password_assignment") >= 3


def test_scan_secrets_aws_key():
    hits = scan_secrets("AWS_SECRET_ACCESS_KEY=purplelab-secret-0123456789abcdef")
    assert hits and hits[0][0] == "aws_secret_key"


def test_scan_secrets_no_fp_on_benign_file():
    benign = (
        "<html><body>Welcome to the documentation portal. "
        "This page describes password policies in general terms. "
        "The word password appears many times: password, password, password. "
        "Nothing is assigned here. See also: configparser, pasteweb,passenger.</body></html>\n"
        "key=value\nfoo = bar\n"
    )
    assert scan_secrets(benign) == []


def test_scan_secrets_redacted_mask_not_flagged():
    assert scan_secrets("MINIO_ROOT_PASSWORD=***\npassword = <password>") == []


# ---------------- scope gate ----------------

def test_out_of_scope_host_never_scanned(env):
    tx = FakeTransport(open_ports={("evil.example.net", 8081)})
    agent = make_agent(env, tx, ports=[8081])
    agent.stage_ports(["203.0.113.99"])  # kapsam dışı IP
    assert tx.calls == []  # hiç istek yapılmadı
    assert any(d["host"] == "203.0.113.99" for d in agent.denied)
    # audit'te SCOPE_DENY kanıtı
    with open(env["audit"].path) as f:
        events = [json.loads(l)["event"] for l in f if l.strip()]
    assert "SCOPE_DENY" in events


def test_out_of_scope_port_denied(env):
    tx = FakeTransport()
    agent = make_agent(env, tx, ports=[22, 8081])  # 22 kapsam dışı port
    agent.stage_ports(["127.0.0.1"])
    hosts_ports = {(c[1], c[2]) for c in tx.calls if c[0] == "tcp"}
    assert all(p == 8081 for _, p in hosts_ports)
    assert any(d.get("port") == 22 for d in agent.denied)


# ---------------- kill switch ----------------

def test_killswitch_halts_recon(env):
    ks_path = env["tmp"] / "KILLSWITCH"
    ks_path.write_text("stop")
    tx = FakeTransport(open_ports={("127.0.0.1", 8081)})
    agent = make_agent(env, tx)
    agent.stage_ports(["127.0.0.1"])
    assert agent.findings == [] and agent._stopped
    with open(env["audit"].path) as f:
        assert any(json.loads(l)["event"] == "KILLSWITCH_HALT" for l in f if l.strip())


# ---------------- finding structure ----------------

def test_finding_schema(env):
    tx = FakeTransport(open_ports={("127.0.0.1", 8081)})
    agent = make_agent(env, tx, ports=[8081])
    agent.stage_ports(["127.0.0.1"])
    assert len(agent.findings) == 1
    f = json.loads(agent.findings[0].to_json())
    assert set(f) == {"tip", "hedef", "kanit", "zaman_damgasi", "kapsam_referansi"}
    assert f["hedef"] == "127.0.0.1:8081"
    # findings dosyasına yazıldı
    lines = [json.loads(l) for l in open(env["out"]) if l.strip()]
    assert lines and lines[0]["tip"] == "open_port"
    # audit zinciri bozulmadı
    assert env["audit"].verify_chain()


# ---------------- lab ekili varlıklar (fake transport) ----------------

FAKE_HTTP = {
    "/backup/": (200, "<html><head><title>Index of /backup/</title></head><body>"
                      "<a href=\".env\">.env</a> <a href=\".aws-credentials\">.aws-credentials</a></body></html>", "nginx/1.25"),
    "/backup/.env": (200, "MINIO_ROOT_USER=purplelab\nMINIO_ROOT_PASSWORD=***\n", "nginx/1.25"),
    "/backup/.aws-credentials": (200, "AWS_ACCESS_KEY_ID=purplelab\nAWS_SECRET_ACCESS_KEY=purplelab-secret\n", "nginx/1.25"),
    "/backup/secrets-old.txt": (200, "db_password=PurpleL00p!Lab-2026\nadmin_pwd=S3cret-Backdoor-Passw0rd\napi_token=ghp_purpleloopFAKEtoken1234567890\n", "nginx/1.25"),
    "/": (403, "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code></Error>", "MinIO"),
    "/public/": (200, "<?xml version=\"1.0\"?><ListBucketResult><Contents>"
                      "<Key>credentials-leaked.txt</Key></Contents></ListBucketResult>", "MinIO"),
}


def test_all_planted_lab_entities_found(env):
    tx = FakeTransport(
        open_ports={("127.0.0.1", 8081), ("127.0.0.1", 9010)},
        http_responses=FAKE_HTTP,
    )
    agent = make_agent(env, tx, ports=[8081, 9010],
                       dirs=["backup/", "backup/.env", "backup/.aws-credentials", "backup/secrets-old.txt", "nonexistent"],
                       buckets=["public", "private-nope"])
    agent.stage_ports(["127.0.0.1"])
    agent.stage_dirs([("127.0.0.1", 8081)])
    agent.stage_buckets([("127.0.0.1", 9010)])

    tips = [f.tip for f in agent.findings]
    hosts = {f.hedef for f in agent.findings}
    evidence = " ".join(f.kanit for f in agent.findings)

    # nginx + minio + ekili parolalar
    assert tips.count("open_port") == 2                     # nginx:8081, minio:9010
    assert "directory" in tips                              # /backup/ listing
    assert "bucket_service" in tips                         # minio API
    assert "open_bucket" in tips                            # /public/ anonim
    assert evidence.count("aws_secret") + evidence.count("AWS_SECRET") >= 1
    assert tips.count("secret") >= 4                        # aws-cred + secrets-old x3
    assert "purplelab" in evidence or "PurpleL00p" in evidence
    # 404 dönmeyen ama bulunmayan dizin yok
    assert not any("nonexistent" in h for h in hosts)
    # hepsi kapsamda
    assert all(f.kapsam_referansi in SCOPE_DOC["targets"] for f in agent.findings)
    assert env["audit"].verify_chain()


def test_planted_secret_count_exact(env):
    """FP oranı: sahte istemcide yalnız ekili parolalar bayraklanır."""
    tx = FakeTransport(http_responses=FAKE_HTTP)
    agent = make_agent(env, tx, dirs=["backup/.env", "backup/.aws-credentials", "backup/secrets-old.txt", "index.html"])
    agent.stage_dirs([("127.0.0.1", 8081)])
    secrets = [f.kanit for f in agent.findings if f.tip == "secret"]
    # .env'deki ***'lü atama hariç: aws x1 + secrets-old x3 = 4 gerçek, 0 FP
    assert len(secrets) == 4


# ---------------- subdomain stage ----------------

def test_subdomain_out_of_scope_denied(env, monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda n: "127.0.0.1")
    tx = FakeTransport()
    agent = make_agent(env, tx, subdomains=["www"])
    agent.stage_subdomains(["example.com", "notinscope.net"])
    # *.example.com kapsam içinde => DNS istendi; notinscope.net reddedildi
    assert any(d["host"] == "www.notinscope.net" for d in agent.denied)
    assert len(agent.findings) == 1 and agent.findings[0].tip == "subdomain"


# ---------------- canlı lab (opsiyonel, docker ayaktaysa) ----------------

def is_alive(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not is_alive("127.0.0.1", 8081), reason="lab (docker compose) çalışmıyor")
def test_live_lab_end_to_end(env):
    tx = FakeTransport()  # gerçek RealTransport değil; canlı tarama CLI'da
    from purpleloop.recon import RealTransport
    agent = make_agent(env, RealTransport())
    agent.run([], ["127.0.0.1"], [("127.0.0.1", 8081), ("127.0.0.1", 9010)])
    evidence = " ".join(f.kanit for f in agent.findings)
    assert len(agent.findings) >= 10
    assert "MinIO" in evidence or "open_bucket" in [f.tip for f in agent.findings]
    assert env["audit"].verify_chain()
