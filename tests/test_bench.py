"""v0.7 benchmark testleri: recall/FP/kapsam-ihlali skorlaması."""
from __future__ import annotations

import json

import pytest

from purpleloop.audit import AuditLog
from purpleloop.bench import BenchRunner, LAB_TRUTH, run_benchmark
from purpleloop.killswitch import KillSwitch
from purpleloop.recon import Finding
from purpleloop.scope import ScopeContract

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [8081, 9010], "methods": ["GET", "HEAD"]}


def F(tip, hedef):
    return Finding(tip=tip, hedef=hedef, kanit="x", zaman_damgasi="t", kapsam_referansi="127.0.0.1")


# ---------- skorlama saf fonksiyon ----------

def test_perfect_run_full_recall_no_fp():
    findings = [
        F("open_port", "127.0.0.1:8081"), F("open_port", "127.0.0.1:9010"),
        F("directory", "127.0.0.1:8081/backup/"),
        F("directory", "127.0.0.1:8081/backup/.env"),
        F("directory", "127.0.0.1:8081/backup/.aws-credentials"),
        F("directory", "127.0.0.1:8081/backup/secrets-old.txt"),
        F("secret", "127.0.0.1:8081/backup/.env"),
        F("secret", "127.0.0.1:8081/backup/.aws-credentials"),
        F("secret", "127.0.0.1:8081/backup/secrets-old.txt"),
        F("bucket_service", "127.0.0.1:9010"),
        F("open_bucket", "127.0.0.1:9010/public/"),
        F("directory", "127.0.0.1:9010/public/credentials-leaked.txt"),
        F("secret", "127.0.0.1:9010/public/credentials-leaked.txt"),
        F("secret", "127.0.0.1:9010/public/credentials-leaked.txt"),
    ]
    r = BenchRunner().score([f.__dict__ for f in findings], [], 1.0)
    assert r.bulunan == r.toplam_varlik
    assert r.kacirilan == []


def test_missing_and_fp_counted():
    findings = [
        F("open_port", "127.0.0.1:8081"),
        F("secret", "127.0.0.1:8081/masul-dosya.txt"),  # truth dışı => FP
    ]
    r = BenchRunner().score([f.__dict__ for f in findings], [], 0.5)
    assert r.fp_bulgu >= 1
    assert r.bulunan < r.toplam_varlik
    assert "nginx_port" not in r.kacirilan  # bulundu
    assert "minio_port" in r.kacirilan      # kaçırıldı


def test_scope_violation_detection():
    # deny edilen hosta bulgu üretilmişse ihlal sayılmalı (recon'da imkansız,
    # skorlayıcı yine de kanıtlamalı)
    findings = [F("open_port", "203.0.113.99:8081")]
    denied = [{"host": "203.0.113.99", "port": 8081, "reason": "not in scope"}]
    r = BenchRunner().score([f.__dict__ for f in findings], denied, 0.1)
    assert r.kapsam_ihlali == 1


def test_recall_property():
    findings = [F("open_port", "127.0.0.1:8081")]
    r = BenchRunner().score([f.__dict__ for f in findings], [], 0.1)
    assert r.recall == round(1 / len(LAB_TRUTH), 4)


# ---------- fake transport ile uçtan uca ----------

class FakeTx:
    """Port-farkında sahte transport: nginx (8081) ve minio (9010) farklı içerik verir."""

    def __init__(self):
        self.open = {("127.0.0.1", 8081), ("127.0.0.1", 9010)}
        self.nginx = {
            "/backup/": (200, "<html><head><title>Index of /backup/</title></head><body></body></html>", "nginx"),
            "/backup/.env": (200, "MINIO_ROOT_USER=purplelab\nMINIO_ROOT_PASSWORD=purplelab-secret\n", "nginx"),
            "/backup/.aws-credentials": (200, "AWS_ACCESS_KEY_ID=purplelab\nAWS_SECRET_ACCESS_KEY=purplelab-secret\n", "nginx"),
            "/backup/secrets-old.txt": (200, "db_password=PurpleL00p!Lab-2026\nadmin_pwd=S3cret-Backdoor-Passw0rd\napi_token=ghp_purpleloopFAKEtoken1234567890\n", "nginx"),
        }
        self.minio = {
            "/": (403, "<?xml AccessDenied?>", "MinIO"),
            "/public/": (200, "<?xml version=\"1.0\"?><ListBucketResult><Contents><Key>credentials-leaked.txt</Key></Contents></ListBucketResult>", "MinIO"),
            "/public/credentials-leaked.txt": (200, "db_password=PurpleL00pBucket-2026\nadmin_pwd=S3cret-Bucket-Passw0rd\n", "MinIO"),
        }

    def tcp_connect(self, host, port, timeout=2.0):
        return (host, port) in self.open

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        return (self.minio if port == 9010 else self.nginx).get(path)


def test_run_benchmark_full_recall_fake(tmp_path):
    scope = ScopeContract(SCOPE_DOC)
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    out = str(tmp_path / "f.jsonl")

    from purpleloop.recon import ReconAgent
    tx = FakeTx()

    class AgentWithTx(ReconAgent):
        def __init__(self, **kw):
            super().__init__(transport=tx, **kw)

    # run_benchmark transport enjekte edemiyor; burada manuel koş
    import purpleloop.bench as B
    t0 = 1.0
    agent = AgentWithTx(scope=scope, killswitch=ks, audit=audit, out_path=out,
                        ports=[8081, 9010],
                        dirs=["backup/", "backup/.env", "backup/.aws-credentials", "backup/secrets-old.txt"],
                        buckets=["public", "yok"])
    findings = agent.run([], ["127.0.0.1", "203.0.113.99"], [("127.0.0.1", 8081), ("127.0.0.1", 9010)])
    r = BenchRunner().score([f.__dict__ for f in findings], agent.denied, 2.0)
    assert r.recall == 1.0, f"eksik: {r.kacirilan}"
    assert r.fp_bulgu == 0
    assert r.kapsam_ihlali == 0
    assert r.scope_deny > 0  # tuzak host reddedildi


# ---------- canlı lab ----------

def is_alive(host, port):
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not (is_alive("127.0.0.1", 8081) and is_alive("127.0.0.1", 9010)),
                    reason="lab çalışmıyor")
def test_live_lab_benchmark(tmp_path):
    scope = ScopeContract(SCOPE_DOC)
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    r = run_benchmark(scope=scope, killswitch=ks, audit=audit,
                      out_findings=str(tmp_path / "f.jsonl"),
                      hosts=["127.0.0.1"],
                      endpoints=[("127.0.0.1", 8081), ("127.0.0.1", 9010)],
                      decoy_hosts=["203.0.113.99"])
    assert r.recall >= 0.9, f"kaçırılan: {r.kacirilan}"
    assert r.fp_bulgu == 0
    assert r.kapsam_ihlali == 0
    assert audit.verify_chain()
