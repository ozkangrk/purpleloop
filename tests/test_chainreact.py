"""Hafta-6 testleri: saldırı zinciri kural motoru + uyumluluk raporu."""
from __future__ import annotations

import json
import os

import pytest

from purpleloop.audit import AuditLog
from purpleloop.chainreact import AttackPathBuilder, ComplianceReporter

FINDINGS = [
    {"tip": "secret", "hedef": "127.0.0.1:8081/backup/.env", "kanit": "MINIO_ROOT_PASSWORD=purplelab-secret",
     "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
    {"tip": "directory", "hedef": "127.0.0.1:8081/backup/", "kanit": "HTTP 200",
     "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
    {"tip": "open_bucket", "hedef": "127.0.0.1:9010/public/", "kanit": "anon list",
     "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
    {"tip": "bucket_service", "hedef": "127.0.0.1:9010", "kanit": "S3 API",
     "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
    {"tip": "open_port", "hedef": "127.0.0.1:8081", "kanit": "TCP",
     "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"},
]

VALS = [
    {"hedef": f["hedef"], "tip": f["tip"], "verdict": "CONFIRMED", "gerekce": "", "kanit": "", "zaman_damgasi": "t"}
    for f in FINDINGS
] + [
    {"hedef": "127.0.0.1:8081/gone", "tip": "directory", "verdict": "REJECTED", "gerekce": "", "kanit": "", "zaman_damgasi": "t"},
]

PROOFS = [
    {"bulgu": "127.0.0.1:8081/backup/.env", "eylem": "s3_read_probe", "sonuc": "EXPLOITED",
     "kanit_metni": "...", "zaman_damgasi": "t"},
]


@pytest.fixture()
def env(tmp_path):
    return {"audit": AuditLog(str(tmp_path / "audit.jsonl")), "tmp": tmp_path}


def test_attack_paths_built_and_audited(env):
    b = AttackPathBuilder(audit=env["audit"])
    paths = b.build(FINDINGS, VALS, PROOFS)
    ids = [p.path_id for p in paths]
    assert any("leaked-creds" in i for i in ids)
    assert any("open-directory" in i for i in ids)
    assert any("exposed-service" in i for i in ids)
    high = [p for p in paths if p.severity == "high"]
    assert len(high) >= 2
    # exploit kanıtı adımı eklendi mi
    leaked = next(p for p in paths if "leaked-creds" in p.path_id)
    tips = [a["tip"] for a in leaked.adimlar]
    assert "exploit_proof" in tips
    # audit kaydı
    events = [json.loads(l)["event"] for l in open(env["audit"].path) if l.strip()]
    assert events.count("ATTACK_PATH") == len(paths)
    assert env["audit"].verify_chain()


def test_no_paths_without_confirmation(env):
    b = AttackPathBuilder(audit=env["audit"])
    paths = b.build(FINDINGS, [], [])  # hiç CONFIRMED yok
    assert paths == []


def test_rejected_findings_excluded(env):
    b = AttackPathBuilder(audit=env["audit"])
    vals = [dict(v, verdict="REJECTED") for v in VALS]
    assert b.build(FINDINGS, vals, PROOFS) == []


def test_compliance_report_content(env):
    b = AttackPathBuilder(audit=env["audit"])
    paths = b.build(FINDINGS, VALS, PROOFS)
    r = ComplianceReporter(audit=env["audit"])
    path, digest = r.render(FINDINGS, VALS, PROOFS, paths,
                            ["127.0.0.1", "10.10.0.0/16"], str(env["tmp"]))
    assert os.path.exists(path) and len(digest) == 64
    text = open(path, encoding="utf-8").read()
    assert "Yönetim Raporu" in text
    assert "KVKK" in text and "ISO 27001" in text and "SOC 2" in text
    assert "saldırı zinciri" in text
    assert "EXPLOITED" in text
    assert "SHA256" in text
    # REJECTED bulgu tabloya CONFIRMED olarak girmez
    assert "127.0.0.1:8081/gone" not in text
    # audit kaydı
    events = [json.loads(l)["event"] for l in open(env["audit"].path) if l.strip()]
    assert "COMPLIANCE_REPORT" in events
    assert env["audit"].verify_chain()


def test_report_severity_ordering(env):
    b = AttackPathBuilder(audit=env["audit"])
    paths = b.build(FINDINGS, VALS, PROOFS)
    r = ComplianceReporter(audit=env["audit"])
    path, _ = r.render(FINDINGS, VALS, PROOFS, paths, ["127.0.0.1"], str(env["tmp"]))
    text = open(path, encoding="utf-8").read()
    assert text.index("YÜKSEK") < text.index("## 2.")  # özet en üstte


# ---------- canlı lab: uçtan uca hafta-6 ----------

def is_alive(host, port):
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not (is_alive("127.0.0.1", 8081) and is_alive("127.0.0.1", 9010)),
                    reason="lab çalışmıyor")
def test_live_lab_chainreact(env):
    from purpleloop.harness import Harness, HarnessContext
    from purpleloop.killswitch import KillSwitch
    from purpleloop.scope import ScopeContract
    scope = ScopeContract({"targets": ["127.0.0.1"], "ports": [8081, 9010],
                           "methods": ["GET", "HEAD"]})
    ctx = HarnessContext(scope=scope, killswitch=KillSwitch(str(env["tmp"] / "KS")),
                         audit=env["audit"], out_dir=str(env["tmp"]))
    h = Harness(ctx)
    h.agents["recon"].hosts = ["127.0.0.1"]
    h.agents["recon"].endpoints = [("127.0.0.1", 8081), ("127.0.0.1", 9010)]
    summary = h.run_pipeline(["recon", "validator"])
    assert not summary["halted"]
    # exploit
    from purpleloop.exploit import SafeModeExploiter
    from purpleloop.harness import ScopeGatedTransport
    validated = ctx.artifacts["validations"]
    ex = SafeModeExploiter(scope=scope, killswitch=ctx.killswitch, audit=ctx.audit,
                           out_path=str(env["tmp"] / "exploit.jsonl"),
                           transport=ScopeGatedTransport(scope, ctx.audit))
    ex.run(validated, [("127.0.0.1", 9010)])
    # chain
    b = AttackPathBuilder(audit=ctx.audit)
    paths = b.build(ctx.artifacts["findings"], validated, [p.__dict__ for p in ex.proofs])
    assert paths, "canlı labda en az bir zincir beklenir"
    r = ComplianceReporter(audit=ctx.audit)
    path, _ = r.render(ctx.artifacts["findings"], validated, [p.__dict__ for p in ex.proofs],
                       paths, scope.targets, str(env["tmp"]))
    assert "KVKK" in open(path, encoding="utf-8").read()
    assert ctx.audit.verify_chain()
