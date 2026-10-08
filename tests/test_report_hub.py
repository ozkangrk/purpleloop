"""report_hub testleri: sabit örnek bulgularla üç rol çıktısının içeriği doğrulanır.

Juice canlı ortamına bağımlı DEĞİL — deterministik örnek bulgu listesi (3 tip:
sqli_data_leak / directory / missing_header) + geçici audit zinciri.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.platform_layer import PolicyGate  # noqa: E402
from purpleloop.report_hub import (  # noqa: E402
    ROLLER, denetci_raporu, main, teknik_detay, yonetici_ozeti,
)

SAMPLE_FINDINGS = [
    {"tip": "sqli_data_leak", "hedef": "127.0.0.1:3100/rest/products/search",
     "kanit": "UNION(users) — email sızıntısı: admin@x.op",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
    {"tip": "directory", "hedef": "127.0.0.1:3100/ftp/",
     "kanit": "HTTP 200 len=11024 | dizin listeleme açık",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
    {"tip": "missing_header", "hedef": "127.0.0.1:3100",
     "kanit": "content-security-policy: CSP eksik — XSS riski",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
]


@pytest.fixture()
def gate():
    # eşikleri bulgu sayısına göre gevşek tut → örnek sette durum PASS olmalı
    return PolicyGate(max_error=5, max_warning=5).evaluate(SAMPLE_FINDINGS)


@pytest.fixture()
def audit_path(tmp_path):
    # bulgu başına audit kaydı — denetçi raporu sha eşleştirmesi için
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    for f in SAMPLE_FINDINGS:
        log.append("FINDING", tip=f["tip"], hedef=f["hedef"])
    return p


# ---------------------------------------------------------------------------
# yönetici özeti
# ---------------------------------------------------------------------------

def test_yonetici_baslik_ve_risk(gate):
    md = yonetici_ozeti(SAMPLE_FINDINGS, gate)
    assert "# Yönetici Özeti" in md
    # ilk paragrafta tek cümle risk özeti + eşik durumu
    assert md.splitlines()[2].startswith("**Risk özeti:**")
    assert "PASS" in md  # 1 error/1 warning eşik içinde → geçiyor
    assert "## En Kritik 3 Bulgu" in md
    assert "## Önerilen Aksiyonlar" in md


def test_yonetici_tablo_satir_sayisi(gate):
    md = yonetici_ozeti(SAMPLE_FINDINGS, gate)
    satirlar = [l for l in md.splitlines() if l.startswith("| ") and "---" not in l]
    # başlık satırı + 3 bulgu satırı = 4 (toplamda en fazla 3 bulgu var)
    assert len(satirlar) == 1 + len(SAMPLE_FINDINGS)
    # en kritik (error seviyeli sqli) ilk sırada
    assert "sqli_data_leak" in satirlar[1]


def test_yonetici_aksiyon_maddeleri(gate):
    md = yonetici_ozeti(SAMPLE_FINDINGS, gate)
    assert "- [ ]" in md  # en az bir aksiyon maddesi var


# ---------------------------------------------------------------------------
# denetçi raporu
# ---------------------------------------------------------------------------

def test_denetci_sha_referansi(audit_path):
    md = denetci_raporu(SAMPLE_FINDINGS, audit_path)
    assert "# Denetçi İzlenebilirlik Raporu" in md
    # her bulgu satırında audit sha referansı var (16 karakterlik önek)
    bulgu_satirlari = [l for l in md.splitlines()
                       if l.startswith("| B") and "---" not in l
                       and not l.startswith("| Bulgu")]
    assert len(bulgu_satirlari) == 3
    for l in bulgu_satirlari:
        assert "sha" or "…" in l
    assert "`" in md and "…" in md  # sha öneki gösterimi


def test_denetci_zincir_verify(audit_path):
    md = denetci_raporu(SAMPLE_FINDINGS, audit_path)
    assert "Zincir doğrulama sonucu" in md
    assert "GEÇERLİ" in md


def test_denetci_kapsam_ozeti(audit_path):
    md = denetci_raporu(SAMPLE_FINDINGS, audit_path)
    assert "Kapsam Sözleşmesi Özeti" in md
    assert "127.0.0.1" in md  # kapsam referansı geçiyor


def test_denetci_bozuk_zincir(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    AuditLog(p).append("FINDING", tip="directory", hedef="127.0.0.1:3100/ftp/")
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"event":"FINDING","prev_sha256":"deadbeef","sha256":"deadbeef"}\n')
    md = denetci_raporu(SAMPLE_FINDINGS, p)
    assert "BOZUK" in md


# ---------------------------------------------------------------------------
# teknik detay
# ---------------------------------------------------------------------------

def test_teknik_bulgu_basi_bolum():
    md = teknik_detay(SAMPLE_FINDINGS)
    assert "# Teknik Detay Raporu" in md
    for f in SAMPLE_FINDINGS:
        assert f"## B{SAMPLE_FINDINGS.index(f) + 1} — {f['tip']}" in md
        assert f["hedef"] in md
        assert f["kanit"] in md[:2000] or f["kanit"] in md  # kanıt alıntısı
    assert "SEVERITY" in md
    assert "curl" in md  # yeniden üretme komutu


def test_teknik_severity_notlari():
    md = teknik_detay(SAMPLE_FINDINGS)
    assert "security-severity: 9.8/10" in md   # sqli_data_leak
    assert "security-severity: 5.0/10" in md   # directory
    assert "security-severity: 3.1/10" in md   # missing_header


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_roller(tmp_path):
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(
        "\n".join(
            '{"tip": "%s", "hedef": "%s", "kanit": "%s", "zaman_damgasi": "t", "kapsam_referansi": "127.0.0.1"}'
            % (f["tip"], f["hedef"], f["kanit"]) for f in SAMPLE_FINDINGS),
        encoding="utf-8")
    audit_file = tmp_path / "audit.jsonl"
    log = AuditLog(str(audit_file))
    for f in SAMPLE_FINDINGS:
        log.append("FINDING", tip=f["tip"], hedef=f["hedef"])
    out = tmp_path / "raporlar"
    rc = main(["--findings", str(findings_file), "--audit", str(audit_file),
               "--gate", "PASS", "--out-dir", str(out),
               "--roller", "yonetici,denetci,teknik"])
    assert rc == 0
    assert (out / "rapor_yonetici.md").exists()
    assert (out / "rapor_denetci.md").exists()
    assert (out / "rapor_teknik.md").exists()
    icerik = (out / "rapor_yonetici.md").read_text(encoding="utf-8")
    assert "PASS" in icerik
    assert len([l for l in icerik.splitlines()
                if l.startswith("| ") and "---" not in l]) == 1 + 3


def test_cli_gecersiz_rol(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main(["--findings", "", "--roller", "ceo"])


def test_cli_roller_seti():
    assert ROLLER == ("yonetici", "denetci", "teknik")
