"""Hafta-4 Security Harness testleri: ajan kaydı, pipeline fail-closed davranışı,
plugin yükleme, scope-gated transport zorlaması, rapor üretimi."""
from __future__ import annotations

import json
import os

import pytest

from purpleloop.audit import AuditLog
from purpleloop.harness import (Harness, HarnessContext, HarnessError,
                                ReconStage, ReportStage, ScopeGatedTransport,
                                SecurityAgent, ValidatorStage)
from purpleloop.killswitch import KillSwitch
from purpleloop.scope import ScopeContract

SCOPE_DOC = {
    "targets": ["127.0.0.1"],
    "ports": [8081, 9010],
    "methods": ["GET", "HEAD"],
}


class FakeInner:
    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        self.calls.append(("tcp", host, port))
        return True

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(("http", host, port, path))
        return 200, "body", "srv"


@pytest.fixture()
def ctx(tmp_path):
    return HarnessContext(
        scope=ScopeContract(SCOPE_DOC),
        killswitch=KillSwitch(str(tmp_path / "KS")),
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
        out_dir=str(tmp_path),
    )


# ---------- kayıt sözleşmesi ----------

def test_register_rejects_bad_agents(ctx):
    h = Harness(ctx)
    with pytest.raises(HarnessError):
        h.register(object())                # name/run yok
    with pytest.raises(HarnessError):
        h.register(ReconStage())            # ad çakışması


def test_builtin_agents_registered(ctx):
    names = set(Harness(ctx).agents)
    assert {"recon", "validator", "report"} <= names


# ---------- pipeline fail-closed ----------

class BoomAgent(SecurityAgent):
    name = "boom"
    description = "çöken ajan"

    def run(self, ctx):
        raise RuntimeError("patladı")


def test_crashing_agent_halts_pipeline(ctx):
    h = Harness(ctx)
    h.register(BoomAgent())
    s = h.run_pipeline(["recon", "boom", "report"])
    assert s["halted"]
    assert s["stages"][1]["ok"] is False
    events = [json.loads(l)["event"] for l in open(ctx.audit.path) if l.strip()]
    assert "AGENT_ERROR" in events
    assert ctx.audit.verify_chain()


def test_unknown_stage_halts(ctx):
    h = Harness(ctx)
    s = h.run_pipeline(["recon", "yokboyle"])
    assert s["halted"] and "yokboyle" in s["reason"]


def test_killswitch_between_stages(ctx):
    h = Harness(ctx)
    h.run_pipeline(["recon"])  # ısınma, audit dolsun
    ks_file = os.path.join(os.path.dirname(ctx.audit.path), "KS")
    open(ks_file, "w").write("stop")
    s = h.run_pipeline(["recon", "report"])
    assert s["halted"] and "kill-switch" in s["reason"]
    os.remove(ks_file)


# ---------- scope-gated transport ----------

def test_gated_transport_blocks_out_of_scope(ctx):
    inner = FakeInner()
    gt = ScopeGatedTransport(ctx.scope, ctx.audit, inner)
    assert gt.tcp_connect("203.0.113.99", 8081) is False
    assert gt.http_get("203.0.113.99", 8081, "/x") is None
    assert inner.calls == []  # hiç istek sızmadı
    with open(ctx.audit.path) as f:
        assert any(json.loads(l)["event"] == "SCOPE_DENY" for l in f if l.strip())


def test_gated_transport_allows_in_scope(ctx):
    inner = FakeInner()
    gt = ScopeGatedTransport(ctx.scope, ctx.audit, inner)
    assert gt.tcp_connect("127.0.0.1", 8081) is True
    assert gt.http_get("127.0.0.1", 9010, "/public/") == (200, "body", "srv")
    assert len(inner.calls) == 2


# ---------- plugin yükleme ----------

class DummyPlugin(SecurityAgent):
    name = "dummy"
    description = "test plugin"

    def run(self, ctx):
        ctx.audit.append("DUMMY_RAN")
        return 42


def test_plugin_load_and_run(ctx, tmp_path, monkeypatch):
    # geçici modül olarak test dosyasını kullan
    h = Harness(ctx)
    monkeypatch.setitem(__import__("sys").modules, "tests.test_harness",
                         __import__("tests.test_harness", fromlist=["DummyPlugin"]))
    h.load_plugin("tests.test_harness:DummyPlugin")
    assert "dummy" in h.agents
    assert h.agents["dummy"].run(ctx) == 42


def test_plugin_bad_spec_rejected(ctx):
    h = Harness(ctx)
    with pytest.raises(HarnessError):
        h.load_plugin(":SınıfYok")
    with pytest.raises(HarnessError):
        h.load_plugin("purpleloop.yokmodul:Yok")


# ---------- rapor ----------

def test_report_generates_markdown_with_severity(ctx):
    ctx.artifacts["findings"] = [
        {"tip": "secret", "hedef": "127.0.0.1:8081/x", "kanit": "password=abc123",
         "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
        {"tip": "open_port", "hedef": "127.0.0.1:8081", "kanit": "TCP",
         "zaman_damgasi": "t", "kapan_referansi": "127.0.0.1"},
    ]
    ctx.artifacts["validations"] = [
        {"hedef": "127.0.0.1:8081/x", "tip": "secret", "verdict": "CONFIRMED",
         "gerekce": "", "kanit": "", "zaman_damgasi": "t"},
    ]
    stage = ReportStage()
    digest = stage.run(ctx)
    assert len(digest) == 64
    report = open(os.path.join(ctx.out_dir, "report.md"), encoding="utf-8").read()
    assert "medium" in report and "secret" in report and "CONFIRMED" in report
    assert report.index("medium") < report.index("info")  # önem sırası
