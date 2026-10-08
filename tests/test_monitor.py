"""Sürekli izleme (monitor) testleri.

compute_delta saf fonksiyon testleri, fake transport ile MonitorRun (2 döngü,
RESOLVED geçişi), killswitch durdurma, secret NEW alert, CLI main() koşusu.
"""
from __future__ import annotations

import json

import pytest

from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.monitor import MonitorRun, MonitorScheduler, compute_delta, has_critical_new
from purpleloop.scope import ScopeContract

SCOPE_DOC = {
    "targets": ["127.0.0.1"],
    "ports": [8081, 9010],
    "methods": ["GET", "HEAD"],
}

BUCKET_BODY = (
    '<?xml version="1.0"?><ListBucketResult>'
    '<Name>backups</Name>'
    "<Contents><Key>old.env</Key></Contents>"
    "</ListBucketResult>"
)
SECRET_BODY = "AWS_SECRET_ACCESS_KEY=purplelab-secret-0123456789abcdef"


class FakeTransport:
    """Kayıtlı çağrılar + önceden tanımlı yanıtlar."""

    def __init__(self, http_responses=None):
        self.http_responses = http_responses or {}
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls.append(("tcp", host, port, None))
        return False

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(("http", host, port, path))
        return self.http_responses.get(path)


@pytest.fixture()
def env(tmp_path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    state = str(tmp_path / "monitoring-state.json")
    out = str(tmp_path / "monitoring.jsonl")
    scope = ScopeContract(SCOPE_DOC)
    ks = KillSwitch(str(tmp_path / "KILLSWITCH"))
    return {"audit": audit, "state": state, "out": out, "scope": scope,
            "ks": ks, "tmp": tmp_path}


def make_run(env, tx):
    return MonitorRun(
        scope=env["scope"], killswitch=env["ks"], audit=env["audit"],
        state_path=env["state"], out_path=env["out"], transport=tx,
        hosts=["127.0.0.1"], endpoints=[("127.0.0.1", 8081)],
    )


def read_audit_events(env):
    events = []
    with open(str(env["tmp"] / "audit.jsonl"), encoding="utf-8") as f:
        for line in f:
            events.append(json.loads(line))
    return events


# ---------------- compute_delta (saf) ----------------

def test_compute_delta_new():
    prev = [{"tip": "open_port", "hedef": "127.0.0.1:8081"}]
    cur = prev + [{"tip": "open_bucket", "hedef": "127.0.0.1:8081/backups/"}]
    d = compute_delta(prev, cur)
    assert [f["tip"] for f in d["NEW"]] == ["open_bucket"]
    assert d["RESOLVED"] == []
    assert len(d["UNCHANGED"]) == 1


def test_compute_delta_resolved():
    prev = [{"tip": "open_bucket", "hedef": "127.0.0.1:8081/backups/"},
            {"tip": "open_port", "hedef": "127.0.0.1:8081"}]
    cur = [{"tip": "open_port", "hedef": "127.0.0.1:8081"}]
    d = compute_delta(prev, cur)
    assert [f["tip"] for f in d["RESOLVED"]] == ["open_bucket"]
    assert d["NEW"] == []
    assert len(d["UNCHANGED"]) == 1


def test_compute_delta_unchanged_and_empty():
    cur = [{"tip": "secret", "hedef": "x/.env"}]
    d = compute_delta(list(cur), [dict(c) for c in cur])
    assert d["NEW"] == [] and d["RESOLVED"] == []
    assert [f["tip"] for f in d["UNCHANGED"]] == ["secret"]
    d0 = compute_delta([], [])
    assert d0 == {"NEW": [], "RESOLVED": [], "UNCHANGED": []}


def test_has_critical_new():
    assert len(has_critical_new({"NEW": [{"tip": "secret", "hedef": "a"}]})) == 1
    assert len(has_critical_new({"NEW": [{"tip": "open_bucket", "hedef": "a"}]})) == 1
    assert has_critical_new({"NEW": [{"tip": "open_port", "hedef": "a"}]}) == []


# ---------------- MonitorRun: 2 döngü, RESOLVED geçişi ----------------

def test_monitor_run_two_cycles_bucket_resolved(env):
    # Döngü 1: açık bucket mevcut; döngü 2: kapanır
    tx1 = FakeTransport(http_responses={
        "/backups/": (200, BUCKET_BODY, ""),
    })
    run1 = make_run(env, tx1)
    d1 = run1.execute()
    tips1 = {f["tip"] for f in d1["NEW"]}
    assert "open_bucket" in tips1

    # döngü 2: bucket artık yok
    tx2 = FakeTransport(http_responses={})
    run2 = make_run(env, tx2)
    d2 = run2.execute()
    resolved_tips = {f["tip"] for f in d2["RESOLVED"]}
    assert "open_bucket" in resolved_tips
    assert not [f for f in d2["NEW"] if f["tip"] == "open_bucket"]

    # monitoring.jsonl'de 2 satır
    with open(env["out"], encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 2
    assert lines[1]["resolved"] >= 1

    # audit'te MONITOR_CYCLE kayıtları delta sayılarıyla
    cycles = [e for e in read_audit_events(env) if e["event"] == "MONITOR_CYCLE"]
    assert len(cycles) == 2
    assert cycles[1]["resolved"] >= 1
    assert env["audit"].verify_chain()


# ---------------- killswitch ----------------

def test_scheduler_halts_on_killswitch(env, monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    # kill-switch dosyasını oluştur => döngü öncesi durmalı
    ks_path = str(env["tmp"] / "KILLSWITCH")
    open(ks_path, "w").close()

    tx = FakeTransport(http_responses={"/backups/": (200, BUCKET_BODY, "")})
    run = make_run(env, tx)
    sched = MonitorScheduler(run, interval=0, max_cycles=5)
    cycles = sched.start()
    assert cycles == 0  # hiç döngü koşulmadı
    events = read_audit_events(env)
    assert any(e["event"] == "MONITOR_HALTED" for e in events)
    assert not any(e["event"] == "MONITOR_CYCLE" for e in events)


def test_scheduler_max_cycles_and_interval(env):
    slept = []
    run = make_run(env, FakeTransport(http_responses={}))
    sched = MonitorScheduler(run, interval=5, max_cycles=3,
                             sleep_fn=lambda s: slept.append(s))
    cycles = sched.start()
    assert cycles == 3
    assert slept == [5, 5]  # son döngüden sonra uyumaz


# ---------------- alert ----------------

def test_secret_new_triggers_alert(env):
    # ilk döngü: secret barındıran bucket gövdesi
    body = BUCKET_BODY.replace("</Contents>", SECRET_BODY + "</Contents>")
    tx = FakeTransport(http_responses={"/backups/": (200, body, "")})
    run = make_run(env, tx)
    d = run.execute()
    assert has_critical_new(d)
    events = read_audit_events(env)
    alerts = [e for e in events if e["event"] == "ALERT"]
    assert alerts, "secret NEW için ALERT kaydı beklenir"
    assert any(a.get("tip") == "secret" for a in alerts)
    # ikinci döngü: aynı bulgular => yeni alert yok
    tx2 = FakeTransport(http_responses={"/backups/": (200, body, "")})
    d2 = make_run(env, tx2).execute()
    assert not has_critical_new(d2)
    alerts2 = [e for e in read_audit_events(env) if e["event"] == "ALERT"]
    assert len(alerts2) == len(alerts)


def test_open_bucket_new_triggers_alert(env):
    tx = FakeTransport(http_responses={"/backups/": (200, BUCKET_BODY, "")})
    d = make_run(env, tx).execute()
    crit = has_critical_new(d)
    assert crit and crit[0]["tip"] == "open_bucket"
    assert any(e["event"] == "ALERT" for e in read_audit_events(env))


# ---------------- CLI ----------------

def test_cli_max_cycles_one(env, capsys, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    scope_file = env["tmp"] / "scope.json"
    scope_file.write_text(json.dumps(SCOPE_DOC), encoding="utf-8")

    from purpleloop.monitor import main
    rc = main([
        "--scope", str(scope_file),
        "--state", env["state"],
        "--audit", str(env["tmp"] / "audit.jsonl"),
        "--killswitch", str(env["tmp"] / "KILLSWITCH"),
        "--out", env["out"],
        "--interval", "0",
        "--max-cycles", "1",
        "--hosts", "127.0.0.1",
        "--endpoints", "127.0.0.1:8081",
    ])
    assert rc == 0
    # monitoring.jsonl'de tam 1 satır
    with open(env["out"], encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 1
    # state dosyası yazılmış
    state = json.loads(open(env["state"], encoding="utf-8").read())
    assert isinstance(state.get("findings"), list)
    # stdout'ta döngü JSON'u + özet satırı
    out = capsys.readouterr().out
    assert '"event": "MONITOR_CYCLE"' in out or '"new":' in out
    assert '"cycles": 1' in out
