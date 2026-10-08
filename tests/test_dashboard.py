"""Dashboard testleri — ephemeral port + thread, düzgün shutdown."""
from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from purpleloop.audit import AuditLog
from purpleloop.dashboard import make_server

TS = "2026-10-08T04:35:10+00:00"


@pytest.fixture()
def run_dir(tmp_path):
    # bulgular
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in [
        {"hedef": "10.0.0.1:8081", "tip": "open_port", "kanit": "TCP connect succeeded",
         "kapsam_referansi": "10.0.0.1", "zaman_damgasi": TS},
        {"hedef": "10.0.0.1:8081/backup/.env", "tip": "secret", "kanit": "AWS_SECRET_ACCESS_KEY=xyz",
         "kapsam_referansi": "10.0.0.1", "zaman_damgasi": TS},
        {"hedef": "10.0.0.1:9010/public/", "tip": "open_bucket", "kanit": "HTTP 200 len=567",
         "kapsam_referansi": "10.0.0.1", "zaman_damgasi": TS},
    ]) + "\n", encoding="utf-8")
    # doğrulamalar
    (tmp_path / "findings-validated.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in [
        {"hedef": "10.0.0.1:8081", "tip": "open_port", "verdict": "CONFIRMED",
         "gerekce": "reconnect ok", "kanit": "TCP reconnect OK", "zaman_damgasi": TS},
        {"hedef": "10.0.0.1:8081/backup/.env", "tip": "secret", "verdict": "CONFIRMED",
         "gerekce": "yeniden okundu", "kanit": "200", "zaman_damgasi": TS},
        {"hedef": "10.0.0.1:9010/public/", "tip": "open_bucket", "verdict": "REJECTED",
         "gerekce": "tekrar 404", "kanit": "404", "zaman_damgasi": TS},
    ]) + "\n", encoding="utf-8")
    # exploit
    (tmp_path / "exploit.jsonl").write_text(json.dumps({
        "bulgu": "10.0.0.1:8081/backup/.env", "eylem": "s3_read_probe", "sonuc": "EXPLOITED",
        "kanit_metni": "bucket okunabilir", "zaman_damgasi": TS}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    # zincir
    (tmp_path / "attack-paths.jsonl").write_text(json.dumps({
        "path_id": "p1", "baslik": "test zinciri",
        "adimlar": [{"sira": 1, "bulgu_hedefi": "10.0.0.1:8081", "tip": "open_port",
                     "aciklama": "giriş noktası"}],
        "severity": "high", "kaynaklar": ["FINDING"], "zaman_damgasi": TS,
    }, ensure_ascii=False) + "\n", encoding="utf-8")
    # hash zincirli audit + SCOPE_DENY kayıtları
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    log.append("PIPELINE_START", stage="test")
    log.append("SCOPE_DENY", host="10.0.0.99", port=21, method="GET",
               reason="port 21 not allowed")
    log.append("SCOPE_DENY", host="10.0.0.99", port=22, method="GET",
               reason="port 22 not allowed")
    log.append("SCOPE_DENY", host="10.0.0.99", port=23, method="GET",
               reason="port 23 not allowed")
    log.append("PIPELINE_END", stage="test")
    return tmp_path


@pytest.fixture()
def server(run_dir):
    httpd = make_server(str(run_dir), "127.0.0.1", 0)  # ephemeral port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()
    t.join(timeout=5)


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read().decode("utf-8")


def test_index_html(server):
    status, body = _get(server + "/")
    assert status == 200
    assert "PurpleLoop" in body


def test_summary_fields(server):
    status, body = _get(server + "/api/summary")
    assert status == 200
    s = json.loads(body)
    assert s["toplam_bulgu"] == 3
    assert s["confirmed"] == 2
    assert s["rejected"] == 1
    assert s["exploited"] == 1
    assert s["saldiri_zinciri"] == 1
    assert s["audit_zinciri"]["ok"] is True
    assert s["audit_zinciri"]["records"] == 5


def test_audit_verify_ok(server):
    status, body = _get(server + "/api/audit/verify")
    assert status == 200
    v = json.loads(body)
    assert v["ok"] is True
    assert v["records"] == 5


def test_denies_count(server):
    status, body = _get(server + "/api/denies")
    assert status == 200
    d = json.loads(body)["denies"]
    assert len(d) == 3
    assert all(x["reason"].startswith("port") for x in d)


def test_empty_run_dir_returns_empty(server, tmp_path):
    empty = tmp_path / "empty-run"
    empty.mkdir()
    httpd = make_server(str(empty), "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        s = json.loads(_get(base + "/api/summary")[1])
        assert s["toplam_bulgu"] == 0 and s["confirmed"] == 0
        v = json.loads(_get(base + "/api/audit/verify")[1])
        assert v["ok"] is False and "error" in v
        assert json.loads(_get(base + "/api/findings")[1])["findings"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


def test_dashboard_module_runs():
    import subprocess, sys
    r = subprocess.run(
        [sys.executable, "-m", "purpleloop.dashboard", "--run-dir", "/nonexistent"],
        capture_output=True, text=True)
    assert r.returncode == 2
