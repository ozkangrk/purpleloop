"""v1.8 kampanya orkestratörü testleri — otonom döngü, fail-closed sınırlar.

Mimari kural (IDIAS.md kararı): LLM yalnız DANIŞMAN; sıralama önerir ama
ağ eylemini belirleyemez. Orkestrasyon deterministik kurallarla çalışır.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.campaign import CampaignOrchestrator, prioritize_findings  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD"]}


# ---------------------------------------------------------------------------
# 1) Deterministik önceliklendirme
# ---------------------------------------------------------------------------

def test_prioritize_secret_over_directory_over_header():
    fs = [
        {"tip": "missing_header", "hedef": "h", "kanit": "x"},
        {"tip": "directory", "hedef": "h", "kanit": "x"},
        {"tip": "sqli_data_leak", "hedef": "h", "kanit": "x"},
        {"tip": "secret", "hedef": "h", "kanit": "x"},
    ]
    order = [f["tip"] for f in prioritize_findings(fs)]
    assert order.index("sqli_data_leak") < order.index("secret")
    assert order.index("secret") < order.index("directory")
    assert order.index("directory") < order.index("missing_header")


# ---------------------------------------------------------------------------
# 2) Otonom döngü — sahte ajanlarla
# ---------------------------------------------------------------------------

class FakeCampaignEnv:
    """Recon bulgusu üreten + probların kaydettiği sahte ortam."""

    def __init__(self, recon_findings):
        self.recon_findings = recon_findings
        self.prob_calls = []

    def probe_for(self, tip):
        def _probe(host, port):
            self.prob_calls.append(tip)
            return {"tip": tip, "hedef": f"{host}:{port}/prob-{tip}",
                    "kanit": f"kanıt-{tip}", "zaman_damgasi": "t",
                    "kapsam_referansi": host}
        return _probe


def _orch(tmp_path, env, findings, max_steps=50, llm=None):
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    return CampaignOrchestrator(
        scope=scope, killswitch=ks, audit=audit,
        out_dir=str(tmp_path), max_steps=max_steps,
        recon_findings_provider=lambda: findings,
        probe_registry={t: env.probe_for(t) for t in
                        ("sqli_data_leak", "extension_filter_bypass",
                         "error_disclosure", "directory", "secret")},
        llm_advisor=llm), audit


def test_campaign_runs_prioritized_probes(tmp_path):
    env = FakeCampaignEnv([
        {"tip": "directory", "hedef": "127.0.0.1:3100/ftp/", "kanit": "listing"},
        {"tip": "sqli_data_leak", "hedef": "127.0.0.1:3100/x", "kanit": "UNION"},
    ])
    orch, audit = _orch(tmp_path, env, [
        {"tip": "directory", "hedef": "127.0.0.1:3100/ftp/", "kanit": "listing"},
        {"tip": "sqli_data_leak", "hedef": "127.0.0.1:3100/x", "kanit": "UNION"},
    ])
    report = orch.run([("127.0.0.1", 3100)])
    # yüksek öncelik önce: sqli probu, directory'nin tetiklediği
    # extension_filter_bypass probundan önce çağrılmalı
    assert env.prob_calls.index("sqli_data_leak") < env.prob_calls.index("extension_filter_bypass")
    assert report["adim_sayisi"] >= 2
    assert report["killswitch_halt"] is False
    assert audit.verify_chain()


def test_campaign_respects_max_steps(tmp_path):
    # çok sayıda bulgu, budget=2: yalnız 2 prob çağrılmalı.
    # Not: temel prob seti (baseline) planın başına eklenir; bütçe onu da
    # kapsar — toplam çağrı = max_steps'i aşamaz.
    fs = [{"tip": "sqli_data_leak", "hedef": f"127.0.0.1:3100/s{i}", "kanit": "x"}
          for i in range(10)]
    env = FakeCampaignEnv(fs)
    orch, _ = _orch(tmp_path, env, fs, max_steps=2)
    report = orch.run([("127.0.0.1", 3100)])
    assert len(env.prob_calls) <= 2
    assert report["adim_sayisi"] <= 2


def test_campaign_killswitch_halts(tmp_path):
    (tmp_path / "KS").write_text("STOP")
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    orch = CampaignOrchestrator(
        scope=scope, killswitch=ks, audit=audit, out_dir=str(tmp_path),
        recon_findings_provider=lambda: [])
        # probe_registry yok — halt öncesi gerekmemeli
    report = orch.run([("127.0.0.1", 3100)])
    assert report["killswitch_halt"] is True
    assert report["adim_sayisi"] == 0


def test_campaign_llm_advisor_cannot_force_out_of_scope(tmp_path):
    """Danışman kapsam dışı hedef önerirse: KAYDA GEÇER ama UYGULANMAZ."""
    fs = [{"tip": "directory", "hedef": "127.0.0.1:3100/ftp/", "kanit": "x"}]
    env = FakeCampaignEnv(fs)

    def bad_advisor(ranked, ctx):
        # kötü öneri: öncelik listesini kapsam dışı hedefle değiştirmeye çalışır
        return [{"tip": "directory", "hedef": "203.0.113.99/evil", "kanit": "x"}] + ranked

    orch, audit = _orch(tmp_path, env, fs, llm=bad_advisor)
    report = orch.run([("127.0.0.1", 3100)])
    # yalnız kapsam içi prob koştu; kapsam dışı öneri reddedildi kaydı var
    applied = [h for h in report["uygulanan_hedefler"]]
    assert all("203.0.113.99" not in h for h in applied)
    entries = [json.loads(l) for l in open(audit.path, encoding="utf-8")]
    assert any(e["event"] == "ADVISOR_REJECT" for e in entries)
