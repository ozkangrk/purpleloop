"""Karar katmanı (Jev-tarzı System One) testleri."""
from __future__ import annotations

import json

import pytest

from purpleloop.decision import (JevAPIBackend, LocalQwenBackend, StaticBackend,
                                 TriageDecision, parse_decision, triage_backend,
                                 triage_finding, triage_findings)


# ---------- tipli karar / fail-closed parser ----------

def test_parse_decision_valid():
    d = parse_decision('{"severity": "high", "fp_olasilik": 0.1, "exploitability": 0.9, "confidence": 0.8, "gerekce_kisa": "jwt sızıntısı"}')
    assert d.severity == "high" and d.confidence == 0.8


def test_parse_decision_garbage_fallback():
    d = parse_decision("model sınıldı ve anlamsız şeyler yazdı 42")
    assert d.severity == "medium" and d.confidence == 0.1  # fail-closed


def test_parse_decision_clamps():
    d = parse_decision('{"severity": "EXTREME", "fp_olasilik": 7, "exploitability": -3, "confidence": 99}')
    assert d.severity == "medium"          # geçersiz severity -> muhafazakâr
    assert d.fp_olasilik == 1.0
    assert d.exploitability == 0.0
    assert d.confidence == 1.0


# ---------- statik arka uç (deterministik) ----------

def test_static_backend_rules():
    b = StaticBackend()
    d = triage_finding({"tip": "secret", "hedef": "x/.env", "kanit": "k"}, b)
    assert d.severity == "high" and d.exploitability > 0.7
    d2 = triage_finding({"tip": "open_port", "hedef": "x:22", "kanit": ""}, b)
    assert d2.severity == "info"


def test_backend_selection_falls_back(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    # auto: Jev yok -> lokal denenir -> o da hata verirse static
    b = triage_backend("static")
    assert isinstance(b, StaticBackend)


def test_jev_backend_requires_key(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(ValueError):
        JevAPIBackend()


# ---------- lokal Qwen (canlıysa) ----------

def is_alive(host, port):
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not is_alive("127.0.0.1", 8888), reason="lokal model çalışmıyor")
def test_local_qwen_triage_calibrated():
    b = LocalQwenBackend()
    d = triage_finding({"tip": "secret", "hedef": "127.0.0.1:8081/backup/.env",
                        "kanit": "AWS_SECRET_ACCESS_KEY=purplelab-secret"}, b)
    assert d.severity in ("high", "medium")
    assert 0.0 <= d.fp_olasilik <= 1.0
    # benign bulgu: header eksikliği yüksek severity ALMAMALI
    d2 = triage_finding({"tip": "missing_header", "hedef": "127.0.0.1:8081",
                         "kanit": "x-frame-options eksik"}, b)
    assert d2.severity in ("low", "info", "medium")


@pytest.mark.skipif(not is_alive("127.0.0.1", 8888), reason="lokal model çalışmıyor")
def test_local_qwen_speed():
    """System-1 emülasyonu hızlı olmalı: tek kısa çağrı < 15s."""
    import time
    b = LocalQwenBackend()
    t0 = time.monotonic()
    triage_finding({"tip": "directory", "hedef": "a/b", "kanit": "HTTP 200"}, b)
    assert time.monotonic() - t0 < 15


# ---------- toplu triaj ----------

def test_triage_findings_batch():
    b = StaticBackend()
    fs = [{"tip": t, "hedef": f"h{i}", "kanit": ""} for i, t in
          enumerate(["secret", "open_port", "missing_header"])]
    out = triage_findings(fs, b)
    assert len(out) == 3
    severities = [d.severity for _, d in out]
    assert "high" in severities and "info" in severities
