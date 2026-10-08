"""Vektör kütüphanesi testleri — her vektör: zayıf yanıt→bulgu, sağlam yanıt→bulgu YOK.

Ayrıca scope-gate ve kill-switch kapıları.
"""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.vectors import VECTORS, VectorLibrary  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100], "methods": ["GET", "HEAD"]}

CALLS = []


def _jwt(alg="none", payload='{"email":"a@b.co"}', sig=""):
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"{h}.{p}" + (f".{sig}" if sig else "")


class WeakTransport:
    """ZAYIF uygulama: her vektör gerçek kanıt imzası döndürür."""

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        CALLS.append((host, port, path))
        if path.startswith("/rest/user/"):
            if "whoami" in path:
                # JWT: body'de alg:none token
                return (200, '{"email":"anon@juice.sh"} ' + _jwt(), {})
            return (200, '{"id":2,"email":"victim@example.com"}', {})
        if path.startswith("/rest/basket/"):
            return (200, '{"id":1,"userId":3,"products":[]}', {})
        if "script" in path.lower():
            return (200, '<html><body>Sonuc: <script>alert(1)</script></body></html>',
                    {"content-type": "text/html"})
        if "doctype" in path.lower() or "%3C!DOCTYPE" in path:
            return (500, "Error: external entity: DTD is not allowed — libxml parser error",
                    {"content-type": "text/html"})
        if "to=https://example.com" in path or "redirect=https://example.com" in path:
            return (302, "", {"location": "https://example.com/evil"})
        if path == "/" or path.startswith("/rest/products/search"):
            # GET'e Allow header ile TRACE duyurusu
            return (200, "ok", {"allow": "GET, POST, TRACE"})
        return (404, "not found", {})


class SolidTransport:
    """SAĞLAM uygulama: hiçbir vektör kanıt imzası taşımaz."""

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        CALLS.append((host, port, path))
        if path.startswith("/rest/user/") or path.startswith("/rest/basket/"):
            return (403, '{"error":"unauthorized"}', {})
        if "to=https://example.com" in path:
            return (406, "not allowed", {})
        return (200, '{"status":"success","data":[]}', {"allow": "GET, HEAD, OPTIONS"})


def _lib(tmp_path, transport):
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    return VectorLibrary(scope=scope, killswitch=ks, audit=audit,
                         out_path=str(tmp_path / "findings.jsonl"),
                         transport=transport)


def _read(probe_obj):
    if not os.path.exists(probe_obj.out_path):
        return []
    with open(probe_obj.out_path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


VECTOR_IDS = [v["id"] for v in VECTORS]


# ---------------------------------------------------------------------------
# (a) zayıf yanıt → bulgu VAR
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vid", VECTOR_IDS)
def test_weak_response_produces_finding(tmp_path, vid):
    CALLS.clear()
    lib = _lib(tmp_path, WeakTransport())
    fs = lib.run_vector(vid, "127.0.0.1", 3100)
    assert len(fs) == 1, f"{vid}: zayıf yanıtta bulgu beklenir"
    assert fs[0]["kapsam_referansi"] == "127.0.0.1"
    assert set(fs[0]) == {"tip", "hedef", "kanit", "zaman_damgasi", "kapsam_referansi"}


# ---------------------------------------------------------------------------
# (b) sağlam yanıt → bulgu YOK
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vid", VECTOR_IDS)
def test_solid_response_no_finding(tmp_path, vid):
    CALLS.clear()
    lib = _lib(tmp_path, SolidTransport())
    fs = lib.run_vector(vid, "127.0.0.1", 3100)
    assert fs == [], f"{vid}: sağlam yanıtta bulgu OLMAMALI (FP kapısı)"
    assert _read(lib) == []


# ---------------------------------------------------------------------------
# scope-gate: kapsam dışı hedef → istek yok, bulgu yok, audit'de SCOPE_DENY
# ---------------------------------------------------------------------------

def test_scope_gate_blocks_out_of_scope(tmp_path):
    CALLS.clear()
    lib = _lib(tmp_path, WeakTransport())
    fs = lib.run_vector("V-IDOR-001", "10.9.9.9", 3100)  # kapsam dışı host
    assert fs == []
    with open(lib.audit.path, encoding="utf-8") as f:
        events = [json.loads(l)["event"] for l in f if l.strip()]
    assert "SCOPE_DENY" in events
    assert not any(h == "10.9.9.9" for h, p, pa in CALLS)


def test_scope_gate_blocks_port(tmp_path):
    lib = _lib(tmp_path, WeakTransport())
    assert lib.run_vector("V-XSS-001", "127.0.0.1", 9999) == []


# ---------------------------------------------------------------------------
# kill-switch: dosya VAR → hiçbir istek, hiçbir bulgu
# ---------------------------------------------------------------------------

def test_killswitch_halts(tmp_path):
    ks_path = tmp_path / "KS"
    ks_path.write_text("stop")
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    lib = VectorLibrary(scope=scope, killswitch=KillSwitch(str(ks_path)), audit=audit,
                        out_path=str(tmp_path / "f.jsonl"), transport=WeakTransport())
    CALLS.clear()
    assert lib.run([("127.0.0.1", 3100)]) == []
    assert lib.run_vector("V-IDOR-001", "127.0.0.1", 3100) == []
    assert CALLS == []
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(l)["event"] for l in f if l.strip()]
    assert "KILLSWITCH_HALT" in events


# ---------------------------------------------------------------------------
# kanıt fonksiyonu birim testleri (FP kapıları)
# ---------------------------------------------------------------------------

def test_kanit_idor_fp_gate():
    from purpleloop.vectors import kanit_idor
    assert kanit_idor(200, '{"id":2,"email":"x@y.com"}', {}) is not None
    assert kanit_idor(403, '{"error":"no"}', {}) is None
    assert kanit_idor(404, "not found", {}) is None
    assert kanit_idor(200, '<html>plain page</html>', {}) is None  # JSON değil


def test_kanit_jwt():
    from purpleloop.vectors import kanit_jwt_alg_none
    body = '{"token":"' + _jwt("none") + '"}'
    assert kanit_jwt_alg_none(200, body, {}) is not None
    assert kanit_jwt_alg_none(200, '{"token":"' + _jwt("HS256", sig="s1g") + '"}', {}) is None
    assert kanit_jwt_alg_none(403, "no", {}) is None


def test_kanit_xss():
    from purpleloop.vectors import kanit_xss_reflection
    assert kanit_xss_reflection(200, "ok <script>alert(1)</script>", {}) is not None
    assert kanit_xss_reflection(200, "temiz yanıt", {}) is None
    assert kanit_xss_reflection(403, "<script>alert(1)</script>", {}) is None


def test_kanit_xxe():
    from purpleloop.vectors import kanit_xxe
    assert kanit_xxe(500, "libxml: DTD is not allowed", {}) is not None
    assert kanit_xxe(500, "internal server error", {}) is None
    assert kanit_xxe(200, "ok", {}) is None


def test_kanit_redirect():
    from purpleloop.vectors import kanit_open_redirect
    assert kanit_open_redirect(302, "", {"location": "https://evil.io"}) is not None
    assert kanit_open_redirect(302, "", {"location": "/login"}) is None  # yerel yol
    assert kanit_open_redirect(200, "ok", {"location": "https://evil.io"}) is None


def test_kanit_method():
    from purpleloop.vectors import kanit_method_abuse
    assert kanit_method_abuse(200, "ok", {"allow": "GET, TRACE"}) is not None
    assert kanit_method_abuse(200, "ok", {"allow": "GET, HEAD, OPTIONS"}) is None
    assert kanit_method_abuse(200, "ok", {}) is None


# ---------------------------------------------------------------------------
# orkestrasyon + şema + import edilebilirlik
# ---------------------------------------------------------------------------

def test_run_all_vectors_weak(tmp_path):
    lib = _lib(tmp_path, WeakTransport())
    fs = lib.run([("127.0.0.1", 3100)])
    assert len(fs) == len(VECTORS)
    tips = {f["tip"] for f in fs}
    assert tips == {"idor", "jwt_weak_alg", "xss_reflection", "xxe_signature",
                    "open_redirect", "http_method_abuse"}
    for f in fs:
        assert set(f) == {"tip", "hedef", "kanit", "zaman_damgasi", "kapsam_referansi"}
    assert lib.audit.verify_chain()


def test_run_all_vectors_solid(tmp_path):
    lib = _lib(tmp_path, SolidTransport())
    assert lib.run([("127.0.0.1", 3100)]) == []
    assert _read(lib) == []


def test_vectors_importable_for_pentest():
    # PentestAgent'a takılabilirlik: liste import edilebilir ve şema tam
    for v in VECTORS:
        assert set(v) == {"id", "tip", "aciklama", "path_yada_payload", "kanit_fonksiyonu"}
        assert callable(v["kanit_fonksiyonu"])
    assert len({v["id"] for v in VECTORS}) == len(VECTORS)


def test_unknown_vector_id(tmp_path):
    lib = _lib(tmp_path, WeakTransport())
    with pytest.raises(ValueError):
        lib.run_vector("V-YOK-999", "127.0.0.1", 3100)
