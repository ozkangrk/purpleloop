"""notify modülü testleri — HİÇBİR test gerçek ağa gitmez.

Ağ taşıması (transport) enjeksiyonu ve localhost fake sunucu ile test edilir.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from purpleloop.audit import AuditLog
from purpleloop.notify import (
    FileSink,
    SlackWebhook,
    WebhookGeneric,
    _HttpJsonPoster,
    main,
    notify,
    parse_channels,
)


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def _bulgu(tip="sqli", hedef="http://hedef/api", severity="error"):
    return {"tip": tip, "hedef": hedef, "kanit": "kanit-1",
            "zaman_damgasi": "2026-10-08T00:00:00Z",
            "kapsam_referansi": "scope.json", "severity": severity}


class FakeKanal:
    """Basit fake kanal — hata enjeksiyonu da yapılabilir."""

    name = "fake"

    def __init__(self, hata=False):
        self.hata = hata
        self.gonderilen = None

    def send(self, payload):
        if self.hata:
            raise RuntimeError("kanal patladı")
        self.gonderilen = payload
        return True


class FakeTransport:
    """Ağ yerine geçen fake transport — gerçek ağa ASLA gitmez."""

    def __init__(self, hata=False):
        self.hata = hata
        self.gotirdi = []

    def post(self, body):
        if self.hata:
            raise OSError("ağ hatası (fake)")
        self.gotirdi.append(body)


# ---------------------------------------------------------------------------
# Dağıtım + hata izolasyonu
# ---------------------------------------------------------------------------
def test_dagitim_fake_kanal(tmp_path):
    audit = str(tmp_path / "audit.jsonl")
    k1, k2 = FakeKanal(), FakeKanal()
    results = notify([_bulgu()], None, [k1, k2], audit_path=audit)
    assert k1.gonderilen is not None and k2.gonderilen is not None
    assert all(r["durum"] == "ok" for r in results)
    assert results[0]["bulgu_sayisi"] == 1


def test_hata_izolasyonu_tur_dururmaz(tmp_path):
    # bir kanal exception fırlatsa bile tur devam eder, diğer kanal çalışır
    audit = str(tmp_path / "audit.jsonl")
    kotu = FakeKanal(hata=True)
    iyi = FakeKanal()
    results = notify([_bulgu()], None, [kotu, iyi], audit_path=audit)
    assert results[0]["durum"] == "hata"
    assert results[1]["durum"] == "ok"
    assert iyi.gonderilen is not None  # hata turu DURDURMADI


def test_sadece_error_seviyesi_dagitilir(tmp_path):
    audit = str(tmp_path / "audit.jsonl")
    k = FakeKanal()
    findings = [_bulgu(severity="error"), _bulgu(severity="info"), _bulgu(severity="high")]
    results = notify(findings, None, [k], audit_path=audit)
    assert results[0]["bulgu_sayisi"] == 2  # error + high
    assert len(k.gonderilen["findings"]) == 2


def test_audit_kayitlari(tmp_path):
    audit = str(tmp_path / "audit.jsonl")
    notify([_bulgu()], None, [FakeKanal(), FakeKanal(hata=True)], audit_path=audit)
    kayitlar = [json.loads(l) for l in open(audit, encoding="utf-8") if l.strip()]
    olaylar = [r["event"] for r in kayitlar]
    assert "NOTIFY" in olaylar and "NOTIFY_ERROR" in olaylar
    basarili = [r for r in kayitlar if r["event"] == "NOTIFY"][0]
    assert basarili["kanal"] == "fake" and basarili["bulgu_sayisi"] == 1
    # zincir doğrulaması (audit API)
    AuditLog(audit).verify_chain()


# ---------------------------------------------------------------------------
# Webhook kanalları — transport enjeksiyonu ile (gerçek ağ yok)
# ---------------------------------------------------------------------------
def test_slack_webhook_transport_enjeksiyonu():
    t = FakeTransport()
    ch = SlackWebhook("https://hooks.example/T000", transport_factory=lambda u: t)
    assert ch.deliver([_bulgu()], {"karar": "DUR"})
    assert t.gotirdi and "text" in t.gotirdi[0]
    assert "PurpleLoop alarm" in t.gotirdi[0]["text"]


def test_webhook_generic_transport_enjeksiyonu():
    t = FakeTransport()
    ch = WebhookGeneric("https://wh.example/hook", transport_factory=lambda u: t)
    assert ch.deliver([_bulgu()], None)
    assert t.gotirdi[0]["source"] == "purpleloop"
    assert t.gotirdi[0]["findings"][0]["tip"] == "sqli"


def test_webhook_hata_non_blocking(tmp_path):
    t = FakeTransport(hata=True)
    ch = SlackWebhook("https://hooks.example/T000", transport_factory=lambda u: t)
    results = notify([_bulgu()], None, [ch], audit_path=str(tmp_path / "a.jsonl"))
    assert results[0]["durum"] == "hata"  # exception yutuldu, tur kesilmedi


def test_file_sink(tmp_path):
    yol = str(tmp_path / "sink.jsonl")
    ch = FileSink(yol)
    assert ch.send({"findings": [_bulgu()], "policy": None})
    satirlar = [json.loads(l) for l in open(yol, encoding="utf-8")]
    assert len(satirlar) == 1 and satirlar[0]["findings"][0]["tip"] == "sqli"


# ---------------------------------------------------------------------------
# Localhost fake sunucu ile gerçek _HttpJsonPoster (gerçek dış ağ yok)
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    gelen = []

    def do_POST(self):
        uzun = int(self.headers.get("Content-Length", 0))
        _Handler.gelen.append(json.loads(self.rfile.read(uzun)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_slack_localhost_fake_server():
    _Handler.gelen = []
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        poster = _HttpJsonPoster(f"http://127.0.0.1:{srv.server_port}/hook")
        ch = SlackWebhook("http://ignored", transport_factory=lambda u: poster)
        assert ch.deliver([_bulgu()], None)
        assert len(_Handler.gelen) == 1 and "text" in _Handler.gelen[0]
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _yaz_findings(tmp_path):
    p = tmp_path / "findings.jsonl"
    p.write_text(json.dumps(_bulgu()) + "\n" +
                 json.dumps(_bulgu(tip="info", severity="info")) + "\n", encoding="utf-8")
    return str(p)


def test_cli_dry_run_ağ_yok(capsys, tmp_path):
    findings = _yaz_findings(tmp_path)
    sink = str(tmp_path / "sink.jsonl")
    rc = main(["--channels", f"slack=https://hooks.example/X,file={sink}",
               "--findings", findings, "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry_run" in out
    # ağ çağrısı YAPILMADI: dosya kanalı bile yazmadı
    assert not (tmp_path / "sink.jsonl").exists()


def test_cli_file_kanal_gercek(tmp_path, capsys):
    findings = _yaz_findings(tmp_path)
    sink = str(tmp_path / "sink.jsonl")
    rc = main(["--channels", f"file={sink}", "--findings", findings,
               "--audit", str(tmp_path / "a.jsonl")])
    assert rc == 0
    satirlar = [json.loads(l) for l in open(sink, encoding="utf-8")]
    assert len(satirlar) == 1  # sadece error-level
    assert json.loads(capsys.readouterr().out)["sonuclar"][0]["durum"] == "ok"


def test_cli_bilinmeyen_kanal(tmp_path):
    rc = main(["--channels", "sms=+90555", "--findings", _yaz_findings(tmp_path), "--dry-run"])
    assert rc == 2


def test_parse_channels():
    chs = parse_channels("slack=https://a,webhook=https://b,file=/tmp/x")
    assert [c.name for c in chs] == ["slack", "webhook-generic", "file"]


def test_help_exit_0():
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
