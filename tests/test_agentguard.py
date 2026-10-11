"""agentguard testleri — gözcü, kapı ve rapor düzlemi."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.agentguard import AgentGuard
from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.scope import ScopeContract

SCOPE = {
    "targets": ["10.99.0.10", "*.example.com"],
    "ports": [80],
    "methods": ["GET", "HEAD"],
}


def _guard(tmp, ks_path=None, scope=True):
    audit = AuditLog(os.path.join(tmp, "audit.jsonl"))
    ks = KillSwitch(os.path.join(tmp, "KS")) if ks_path is None else KillSwitch(ks_path)
    sc = ScopeContract(json.dumps(SCOPE)) if scope else None
    return AgentGuard(os.path.join(tmp, "guard"), audit=audit, killswitch=ks, scope=sc)


def test_observe_yazar_ve_session_dosyasi_olusur():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        rec = g.observe("test-agent", "bash", {"cmd": "ls -la"})
        assert rec["olay"] == "AGENT_ACTION"
        assert rec["karar"] == "ok"
        satirlar = open(os.path.join(tmp, "guard", "agent-session.jsonl")).read().strip().split("\n")
        assert len(satirlar) == 1
        assert json.loads(satirlar[0])["agent"] == "test-agent"


def test_check_normal_aksiyon_izin():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        r = g.check("claude-code", "edit", {"file": "src/app.py", "diff": "+x"})
        assert r["karar"] == "IZIN"


def test_check_yasak_desen_red():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        r = g.check("claude-code", "bash", {"cmd": "rm -rf /"})
        assert r["karar"] == "RED"
        assert "yıkıcı" in r["neden"]


def test_check_url_kodlanmis_yasak_desen_red():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        # kodlanmış hali: rm%20-rf%20/
        r = g.check("agent", "bash", {"cmd": "rm%20-rf%20/"})
        assert r["karar"] == "RED"


def test_check_killswitch_fail_closed():
    with tempfile.TemporaryDirectory() as tmp:
        ks = KillSwitch(os.path.join(tmp, "KS"))
        with open(ks.path, "w") as f:  # aktivasyon = dosya
            f.write("STOP")
        g = _guard(tmp)
        r = g.check("agent", "read", {"file": "ok.txt"})
        assert r["karar"] == "RED"
        assert "kill-switch" in r["neden"]


def test_check_kapsam_disi_hedef_red():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        r = g.check("agent", "network", {"host": "203.0.113.99", "port": 80})
        assert r["karar"] == "RED"
        assert "kapsam" in r["neden"]


def test_check_kapsam_ici_hedef_izin():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        r = g.check("agent", "network", {"host": "10.99.0.10", "port": 80})
        assert r["karar"] == "IZIN"


def test_report_bulgu_ve_remediation_icerir():
    with tempfile.TemporaryDirectory() as tmp:
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        with open(os.path.join(run, "findings.jsonl"), "w") as f:
            f.write(json.dumps({
                "tip": "secret_exposure", "hedef": "10.99.0.10:80/env",
                "kanit": "AWS_SECRET_ACCESS_KEY imzasi", "zaman_damgasi": "t",
                "kapsam_referansi": "sha:abc"}) + "\n")
        g = _guard(tmp)
        r = g.report(run)
        assert r["bulgu"] == 1
        md = open(r["rapor"], encoding="utf-8").read()
        assert "secret_exposure" in md
        assert "Kanıt" in md


def test_report_bulgu_yoksa_temiz():
    with tempfile.TemporaryDirectory() as tmp:
        run = os.path.join(tmp, "run-bos")
        os.makedirs(run)
        g = _guard(tmp)
        r = g.report(run)
        assert r["bulgu"] == 0
        assert "temiz" in open(r["rapor"], encoding="utf-8").read().lower()


def test_report_dedupe_ayni_tip_hedef():
    with tempfile.TemporaryDirectory() as tmp:
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        with open(os.path.join(run, "findings.jsonl"), "w") as f:
            for _ in range(3):
                f.write(json.dumps({"tip": "t1", "hedef": "h1", "kanit": "k"}) + "\n")
        g = _guard(tmp)
        assert g.report(run)["bulgu"] == 1


def test_tum_redler_sessiona_yazilir():
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard(tmp)
        g.check("a", "bash", {"cmd": "rm -rf /"})
        g.check("a", "network", {"host": "203.0.113.99", "port": 80})
        g.check("a", "read", {"file": "x"})
        sess = open(os.path.join(tmp, "guard", "agent-session.jsonl")).read()
        assert sess.count('"RED"') == 2
        assert '"IZIN"' in sess
