"""Sızma vektör KÜTÜPHANESİ — pentest.py'in vektörlerini GENİŞLETİR (yerine geçmez).

Her vektör bir kayıt: {id, tip, aciklama, path_yada_payload, kanit_fonksiyonu}.
kanit_fonksiyonu(status, body, headers) -> kanıt metni | None. None = bulgu YOK.

FP KAPISI: yanıt gerçek kanıt imzasını taşımıyorsa bulgu ÜRETİLMEZ.
  * IDOR       — 200 + JSON'da başkasına ait veri (email/id) şart; 403/404/boş = yok
  * JWT        — token base64 çözülür, 'alg: none' / imzasız segment şart
  * XSS        — '<script>' zararsız işaretleyicisi gövdede AYNEN yankılanmalı
  * XXE        — DTD probu sonrası parser adı geçen hata ifşası şart
  * Redirect   — 3xx + Location'da DIŞ URL şart (yerel yol = yok)
  * Method     — Allow header'ında standart-dışı/yüksek risk metod ifşası şart

Her vektör çalışması: scope kapısı → kill-switch → istek → kanıt → audit.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import re
from typing import Callable, Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# Kanıt fonksiyonları (FP kapılı) — (status, body, headers) -> kanıt | None
# ---------------------------------------------------------------------------

_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")


def _jsonish(body: str) -> bool:
    b = body.lstrip()[:1]
    return b in ("{", "[")


def kanit_idor(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: 200 + JSON + başkasına ait veri (email / userId alanı)."""
    if status != 200 or len(body) < 10 or not _jsonish(body):
        return None
    emails = _EMAIL_RX.findall(body[:5000])
    if emails:
        return f"HTTP 200 kimliksiz erişim, başkasına ait veri: {emails[0]} | {body[:120]}"
    if re.search(r'"(?:user_?id|userId)"\s*:\s*"?[1-9]', body):
        return f"HTTP 200 kimliksiz erişim, kullanıcı kaynağı: {body[:120]}"
    return None


def _b64_candidates(text: str):
    """Gövdedeki base64 görünümü JWT adaylarını üretir (header.payload.signature)."""
    for m in re.finditer(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?", text):
        yield m.group(0)


def kanit_jwt_alg_none(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: çözülen token başlığında 'alg': 'none' (veya imzasız segment)."""
    if status != 200:
        return None
    # 1) transport header'da token veriyorsa
    auth = headers.get("authentication") or headers.get("authorization") or ""
    sources = [auth] + [body[:20000]]
    for src in sources:
        if not src:
            continue
        for tok in _b64_candidates(src):
            head = tok.split(".")[0]
            pad = "=" * (-len(head) % 4)
            try:
                decoded = base64.urlsafe_b64decode(head + pad).decode("utf-8", "replace")
            except Exception:
                continue
            if re.search(r'"alg"\s*:\s*"?(none|NONE)"?', decoded):
                return f"JWT zayıf başlık: alg=none | token={tok[:40]}... | header={decoded[:80]}"
            # imzasız 2-segment token da 'none' sınıfı zayıflıktır
            if tok.count(".") == 1 and re.search(r'"alg"', decoded):
                return f"JWT imzasız (2 segment): {tok[:40]}... | header={decoded[:80]}"
    return None


def kanit_xss_reflection(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: zararsız <script> işaretleyicisi gövdede AYNEN dönmeli."""
    if status != 200:
        return None
    if "<script>alert(1)</script>" in body.lower() or "%3cscript%3e" in body.lower():
        idx = body.lower().find("<script>")
        return f"XSS yansıması: işaretleyici gövdede AYNEN: ...{body[max(0, idx-20):idx+40]}..."
    return None


_XXE_PARSER_RX = re.compile(
    r"(?i)\b(lxml|libxml|xml\.etree|expat|saxparser|xerces|documentbuilder|"
    r"external entity|DTD (?:is )?(?:not )?(?:allowed|forbidden|disabled|processed))\b"
)


def kanit_xxe(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: DTD probuna yanıt PARSER adı geçen hata/ifşa içermeli."""
    if status >= 400 or status == 200:
        snippet = body[:800]
        m = _XXE_PARSER_RX.search(snippet)
        if m:
            return f"XXE imzası: parser ifşası '{m.group(1)}': {snippet[:160]}"
    return None


def kanit_open_redirect(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: 3xx + Location'da DIŞ (http/https) URL; yerel yol = yok."""
    if status not in (301, 302, 303, 307, 308):
        return None
    loc = headers.get("location", "")
    m = re.match(r"(?i)^https?://([^/]+)", loc)
    if m:
        return f"Open redirect: HTTP {status} Location: {loc}"
    return None


_SAFE_ALLOW = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


def kanit_method_abuse(status: int, body: str, headers: dict) -> Optional[str]:
    """FP kapısı: Allow header'ında standart-dışı metod (TRACE/CONNECT/PATCH
    listelenmesi) VEYA OPTIONS'sız sunucunun tehlikeli metod duyurusu."""
    allow = headers.get("allow", "")
    if not allow:
        return None
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = methods - _SAFE_ALLOW
    if risky or "TRACE" in methods or "CONNECT" in methods:
        return f"Allow header ifşası: '{allow}' — risky: {sorted(risky or methods & {'TRACE', 'CONNECT'})}"
    return None


# ---------------------------------------------------------------------------
# Vektör kütüphanesi
# ---------------------------------------------------------------------------

VECTORS: list = [
    {
        "id": "V-IDOR-001",
        "tip": "idor",
        "aciklama": "Başkasının kaynağına kimliksiz erişim (/rest/user/2, /rest/basket/1)",
        "path_yada_payload": ["/rest/user/2", "/rest/user/3", "/rest/basket/1", "/rest/basket/2"],
        "kanit_fonksiyonu": kanit_idor,
    },
    {
        "id": "V-JWT-001",
        "tip": "jwt_weak_alg",
        "aciklama": "/rest/user/whoami token'ını çöz, alg:none / imzasız segment ara",
        "path_yada_payload": ["/rest/user/whoami", "/rest/user/1"],
        "kanit_fonksiyonu": kanit_jwt_alg_none,
    },
    {
        "id": "V-XSS-001",
        "tip": "xss_reflection",
        "aciklama": "Zararsız <script>alert(1)</script> işaretleyicisinin AYNEN yankılanması",
        "path_yada_payload": [
            "/rest/products/search?q=<script>alert(1)</script>",
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        ],
        "kanit_fonksiyonu": kanit_xss_reflection,
    },
    {
        "id": "V-XXE-001",
        "tip": "xxe_signature",
        "aciklama": "Zararsız DOCTYPE/DTD probu — yanıtta parser ifşası ara",
        "path_yada_payload": [
            "/rest/products/search?q=<!DOCTYPE foo [<!ENTITY xxe \"pl\">]>",
            "/api/parse?xml=<!DOCTYPE r [<!ELEMENT r ANY>]><r/>",
        ],
        "kanit_fonksiyonu": kanit_xxe,
    },
    {
        "id": "V-REDIR-001",
        "tip": "open_redirect",
        "aciklama": "?to= dış URL — 3xx + Location'da dış hedef",
        "path_yada_payload": [
            "/redirect?to=https://example.com",
            "/login?redirect=https://example.com",
        ],
        "kanit_fonksiyonu": kanit_open_redirect,
    },
    {
        "id": "V-METHOD-001",
        "tip": "http_method_abuse",
        "aciklama": "HEAD/OPTIONS davranışı — Allow header metod ifşası",
        "path_yada_payload": ["/rest/products/search", "/", "/rest/user/whoami"],
        "kanit_fonksiyonu": kanit_method_abuse,
    },
]


class VectorLibrary:
    """Vektör kütüphanesi çalıştırıcısı — PentestAgent'a takılabilir.

    Kullanım:
        lib = VectorLibrary(scope=..., killswitch=..., audit=..., out_path=...)
        findings = lib.run([("127.0.0.1", 3000)])
    veya tek vektör:
        lib.run_vector("V-IDOR-001", host, port)
    """

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_path: str, transport=None):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        if transport is None:
            from .recon import RealTransport
            transport = RealTransport()
        self.tx = transport

    # ---- ortak (pentest.py deseni ile aynı) ----

    def _gate(self, host, port, method="GET") -> bool:
        ok, reason = self.scope.check_request(host=host, port=port, method=method)
        if not ok:
            self.audit.append("SCOPE_DENY", host=host, port=port, method=method,
                              reason=f"[vectors] {reason}")
            return False
        return True

    def _get(self, host, port, path):
        if not self._gate(host, port, "GET"):
            return None
        r = self.tx.http_get(host, port, path)
        if r is None:
            return None
        status, body, third = r
        if isinstance(third, str):
            third = {"server": third}
        return status, body, {k.lower(): v for k, v in third.items()}

    def _emit(self, tip, hedef, kanit) -> dict:
        f = {"tip": tip, "hedef": hedef, "kanit": kanit[:500],
             "zaman_damgasi": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
             "kapsam_referansi": self.scope.targets[0]}
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
        self.audit.append("FINDING", tip=tip, hedef=hedef, kaynak="vectors")
        return f

    # ---- çalıştırma ----

    def run_vector(self, vector_id: str, host, port) -> list:
        """Tek vektörü çalıştır; kanıt taşıyan yanıtlar için bulgu üret."""
        vec = next((v for v in VECTORS if v["id"] == vector_id), None)
        if vec is None:
            raise ValueError(f"bilinmeyen vektör: {vector_id}")
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="vectors", vector=vector_id)
            return []
        paths = vec["path_yada_payload"]
        if isinstance(paths, str):
            paths = [paths]
        findings = []
        from urllib.parse import quote
        for path in paths:
            if self.killswitch.is_active():
                self.audit.append("KILLSWITCH_HALT", stage="vectors", vector=vector_id)
                break
            # URL güvenliği: payload'daki kontrol karakterleri/boşluk kodlanır
            # (gerçek http.client InvalidURL fırlatır; fake transport fark etmez)
            safe_path = quote(path, safe="/:?=&%+.,;-_~()[]'\"<>! ")
            safe_path = safe_path.replace(" ", "%20")
            r = self._get(host, port, safe_path)
            if r is None:
                continue
            status, body, headers = r
            kanit = vec["kanit_fonksiyonu"](status, body, headers)
            if kanit:  # FP kapısı: kanıt yoksa bulgu ÜRETMEZ
                findings.append(self._emit(vec["tip"], f"{host}:{port}{path}", kanit))
                break  # vektör başına tek bulgu yeter
        return findings

    def run(self, endpoints: list, vector_ids: Optional[list] = None) -> list:
        """Tüm (veya seçili) vektörleri tüm uçlarda çalıştır."""
        ids = vector_ids or [v["id"] for v in VECTORS]
        self.audit.append("VECTORS_START", vectors=ids,
                          endpoints=[f"{h}:{p}" for h, p in endpoints])
        findings = []
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="vectors")
            return []
        for host, port in endpoints:
            for vid in ids:
                if self.killswitch.is_active():
                    self.audit.append("KILLSWITCH_HALT", stage="vectors", host=host)
                    break
                findings.extend(self.run_vector(vid, host, port))
        self.audit.append("VECTORS_END", bulgu=len(findings))
        return findings
