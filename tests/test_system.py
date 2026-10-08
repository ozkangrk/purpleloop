"""Sistem testleri: performans, eşzamanlılık, determinizm, fuzz/FP dayanıklılığı.
v1.0 harness optimizasyonunun kanıtları."""
from __future__ import annotations

import json
import os
import random
import string
import threading
import time

import pytest

from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.recon import (ReconAgent, RealTransport, audit_security_headers,
                              scan_secrets, DIR_CANDIDATES, PORT_CANDIDATES,
                              BUCKET_CANDIDATES)
from purpleloop.scope import ScopeContract

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [8081, 9010], "methods": ["GET", "HEAD"]}


# ---------- yeni secret desenleri ----------

def test_new_secret_patterns():
    cases = {
        "jwt": "token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "github_token": "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
        "slack_token": "SLACK=xoxp-1234567890-abcdefghijklmn",
        "google_api": "KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "stripe_key": "stripe=sk_live_ABCDEFGHIJKLMNOPQRSTUV",
        "db_url": "DATABASE_URL=postgres://admin:S3cretPw@db.internal:5432/prod",
        "private_key": "-----BEGIN PGP PRIVATE KEY-----\nabc",
    }
    for tip, text in cases.items():
        hits = [t for t, _ in scan_secrets(text)]
        assert tip in hits, f"{tip} bulunamadı: {hits}"


def test_benign_content_still_clean():
    """Genişletilmiş desenler FP patlatmamalı."""
    benign = """
    This documentation describes how tokens work. See https://docs.example.com/auth
    The id_token and access_token flows are described in OAuth2 spec.
    Password policies should require length > 12.
    """
    assert scan_secrets(benign) == []


# ---------- güvenlik başlığı denetimi ----------

def test_audit_security_headers():
    missing = audit_security_headers({"server": "nginx", "content-type": "text/html"})
    names = [h for h, _ in missing]
    assert "strict-transport-security" in names
    assert "content-security-policy" in names
    # tam set verilirse boş
    full = {h: "x" for h in ["Strict-Transport-Security", "Content-Security-Policy",
                             "X-Content-Type-Options", "X-Frame-Options"]}
    assert audit_security_headers(full) == []


# ---------- eşzamanlılık: kilitsiz emit bozuk mu? ----------

class SlowFakeTx:
    """Her çağrı ~5ms uyuyan sahte transport — yarış koşullarını yüzeye çıkarır."""

    def __init__(self, open_ports=()):
        self.open = set(open_ports)
        self.calls = 0
        self._lock = threading.Lock()

    def tcp_connect(self, host, port, timeout=2.0):
        time.sleep(0.005)
        with self._lock:
            self.calls += 1
        return (host, port) in self.open

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        time.sleep(0.005)
        return None


def test_parallel_port_scan_consistent(tmp_path):
    """Paralel tarama: bulgu sayısı deterministik + audit zinciri sağlam."""
    open_ports = {("127.0.0.1", 8081), ("127.0.0.1", 9010)}
    counts = []
    for run in range(3):
        audit = AuditLog(str(tmp_path / f"a{run}.jsonl"))
        agent = ReconAgent(scope=ScopeContract(SCOPE_DOC),
                           killswitch=KillSwitch(str(tmp_path / f"ks{run}")),
                           audit=audit, out_path=str(tmp_path / f"f{run}.jsonl"),
                           transport=SlowFakeTx(open_ports), max_workers=16)
        agent.stage_ports(["127.0.0.1"])
        counts.append(len(agent.findings))
        assert audit.verify_chain()
        # findings.jsonl satır sayısı == bulgu sayısı (yarış yoksa)
        lines = [l for l in open(agent.out_path) if l.strip()]
        assert len(lines) == len(agent.findings), "dosya/bulgu tutarsızlığı (yarış koşulu!)"
    assert counts == [2, 2, 2]


# ---------- performans ----------

class NoDelayTx:
    def __init__(self, open_ports=()):
        self.open = set(open_ports)
        self.calls = 0

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls += 1
        return (host, port) in self.open

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls += 1
        return None


def test_parallel_faster_than_serial(tmp_path):
    """Paralel motor, yapay gecikmede seri moddan hızlı olmalı."""
    open_ports = {("127.0.0.1", p) for p in [8081, 9010]}

    class Sleepy:
        def __init__(self):
            self.open = open_ports
            self.calls = 0

        def tcp_connect(self, host, port, timeout=2.0):
            time.sleep(0.02)  # gerçek ağa benzer gecikme
            self.calls += 1
            return (host, port) in self.open

        def http_get(self, *a, **k):
            return None

    def run_with(workers):
        all_ports = sorted({p for p in PORT_CANDIDATES})
        scope = ScopeContract({"targets": ["127.0.0.1"], "ports": all_ports,
                               "methods": ["GET", "HEAD"]})
        audit = AuditLog(str(tmp_path / f"p{workers}.jsonl"))
        agent = ReconAgent(scope=scope,
                           killswitch=KillSwitch(str(tmp_path / f"kp{workers}")),
                           audit=audit, out_path=str(tmp_path / f"pf{workers}.jsonl"),
                           transport=Sleepy(), max_workers=workers)
        t0 = time.monotonic()
        agent.stage_ports(["127.0.0.1"])
        return time.monotonic() - t0

    serial = run_with(1)
    parallel = run_with(32)
    # 53 port x 20ms seri ≈ 1.06s; paralel 32 işçi ~0.05s — en az 8x hız
    assert parallel < serial / 8, f"paralel kazanç yetersiz: seri={serial:.3f}s paralel={parallel:.3f}s"


# ---------- kelime listeleri kapsamı ----------

def test_wordlist_growth():
    """v1.0: genişletilmiş listeler makul boyutta ve bilinen kritik girdileri içerir."""
    assert len(PORT_CANDIDATES) >= 50
    assert len(DIR_CANDIDATES) >= 60
    assert len(BUCKET_CANDIDATES) >= 25
    for must in [".env", ".git/HEAD", "wp-config.php", "phpinfo.php", "server-status",
                 "docker-compose.yml", "swagger.json", ".aws-credentials"]:
        assert must in DIR_CANDIDATES, f"kritik dizin adı eksik: {must}"
    assert 22 in PORT_CANDIDATES and 6379 in PORT_CANDIDATES and 27017 in PORT_CANDIDATES


# ---------- fuzz: rastgele içerik FP üretmemeli ----------

def test_fuzz_random_content_no_secrets():
    rng = random.Random(42)
    fp = 0
    for _ in range(200):
        n = rng.randint(40, 400)
        text = "".join(rng.choice(string.printable[:94]) for _ in range(n))
        text = text.replace("=", " ")  # atama benzeri yapıları bilinçli bozalım bazen
        hits = scan_secrets(text)
        fp += len(hits)
    assert fp == 0, f"fuzz FP: {fp}/200 rastgele içerikte secret sanıldı"


def test_fuzz_malformed_scope_rejected():
    rng = random.Random(7)
    from purpleloop.scope import ScopeError
    rejected = 0
    for _ in range(100):
        junk = "".join(rng.choice(string.printable[:94]) for _ in range(rng.randint(1, 30)))
        try:
            ScopeContract({"targets": [junk], "ports": [80], "methods": ["GET"]})
        except ScopeError:
            rejected += 1
    # çöp hedeflerin %90+'ı reddedilmeli (fail-closed)
    assert rejected >= 90


# ---------- audit zinciri eşzamanlı yazım ----------

def test_concurrent_audit_appends_chain_intact(tmp_path):
    audit = AuditLog(str(tmp_path / "ca.jsonl"))
    errors = []

    def worker(wid):
        try:
            for i in range(20):
                audit.append("CONC_TEST", worker=wid, i=i)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    assert audit.verify_chain()
    n = sum(1 for l in open(audit.path) if l.strip())
    assert n == 8 * 20


# ---------- canlı: genişletilmiş tarama gerçek labda ----------

def is_alive(host, port):
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not (is_alive("127.0.0.1", 8081) and is_alive("127.0.0.1", 9010)),
                    reason="lab çalışmıyor")
def test_live_extended_scan_fast_and_complete(tmp_path):
    """Genişletilmiş listelerle canlı tarama: hâlâ 16/16 truth, makul sürede."""
    from purpleloop.bench import run_benchmark
    scope = ScopeContract(SCOPE_DOC)
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    t0 = time.monotonic()
    r = run_benchmark(scope=scope, killswitch=ks, audit=audit,
                      out_findings=str(tmp_path / "f.jsonl"),
                      hosts=["127.0.0.1"],
                      endpoints=[("127.0.0.1", 8081), ("127.0.0.1", 9010)],
                      decoy_hosts=["203.0.113.99"])
    dt = time.monotonic() - t0
    assert r.recall >= 0.99, f"kaçırılan: {r.kacirilan}"
    assert r.kapsam_ihlali == 0
    assert r.sure_sn < 30, f"tarama yavaş: {r.sure_sn}s"
    # yeni bulgu tipi: header denetimi nginx'de tetiklenmeli
    F = [json.loads(l) for l in open(tmp_path / "f.jsonl") if l.strip()]
    assert any(f["tip"] == "missing_header" for f in F), "header denetimi hiç tetiklenmedi"
    assert audit.verify_chain()
