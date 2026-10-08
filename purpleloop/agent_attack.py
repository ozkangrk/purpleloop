"""Ajan-esnek sızma: ProbeProposer — ajan önerir, platform kapar/koşar/kanıtlar.

Felsefe: ajanın saldırı YARATICILIĞI runtime'a taşınır; kontrol kalır
platformda. Ajan hiçbir zaman doğrudan istek atamaz — propose() ile
önerir. Platform:
  gerekçe → scope kapısı → method beyaz listesi → zararlılık filtresi →
  hız limiti → koşu → imza-temelli kanıt çıkarıcı → audit zinciri.
Kanıt yoksa bulgu yok: 'buldum' diyen ajan değil, imza fonksiyonudur.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import time
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

# ---------------------------------------------------------------------------
# Zararlılık filtresi — okunmaz/yıkıcı payloadlar RED (GET-only dünya için)
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS = [
    r"(?i)\bdrop\s+table\b",
    r"(?i)\bdelete\s+from\b",
    r"(?i)\btruncate\s+table\b",
    r"(?i)\brm\s+-rf\b",
    r"(?i)\bshutdown\b",
    r"(?i)\bmkfs\b",
    r"(?i);\s*cat\s+",           # komut zinciri
    r"(?i)\bsystem\s*\(",
    r"(?i)\bpassthru\b",
    r"(?i)\bexec\s*\(",
    r"(?i)/etc/shadow",
    r"(?i)\bformat\s+[a-z]:",
]

_DANGEROUS_RX = [re.compile(p) for p in DANGEROUS_PATTERNS]


def is_dangerous(path: str) -> bool:
    """True = yıkıcı/okunmaz desen taşıyor; GET-only dünyada RED.

    URL-kodlanmış biçimler de çözülerek kontrol edilir (%20, +, %2F...).
    """
    from urllib.parse import unquote
    candidates = {path, unquote(path), unquote(path, errors="replace"),
                  path.replace("+", " ")}
    return any(rx.search(c) for c in candidates for rx in _DANGEROUS_RX)


# ---------------------------------------------------------------------------
# Kanıt çıkarıcılar — imza temelli (ajan iddiası değil)
# ---------------------------------------------------------------------------

_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
_BCRYPT_RX = re.compile(r"\$2[aby]\$[\w./$]{20,}")
_PASSWD_RX = re.compile(r"root:x:0:\d+:root:/root:")


def extract_evidence(status: int, body: str) -> Optional[str]:
    """Yanıtta gerçek sızıntı imzası ara; yoksa None (bulgu üretilemez)."""
    if status != 200:
        return None
    if _PASSWD_RX.search(body[:20000]):
        return f"/etc/passwd içerik imzası: {body[:80]!r}"
    emails = _EMAIL_RX.findall(body[:20000])
    if emails:
        uniq = sorted(set(emails))[:3]
        daha = f" (+{len(set(emails))-3} daha)" if len(set(emails)) > 3 else ""
        return f"e-posta sızıntısı: {', '.join(uniq)}{daha}"
    hashes = _BCRYPT_RX.findall(body[:20000])
    if hashes:
        return f"bcrypt parola karması: {hashes[0][:14]}..."
    return None


# ---------------------------------------------------------------------------
# ProbeProposer
# ---------------------------------------------------------------------------

class ProbeProposer:
    """Ajan önerisi → kapı → koşu → kanıt. Hız: token-vari pencere sayacı."""

    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_path: str, transport=None,
                 rate_per_minute: int = 20):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        if transport is None:
            from .recon import RealTransport
            transport = RealTransport()
        self.tx = transport
        self.rate = rate_per_minute
        self._window: list[float] = []   # son öneri zamanları
        self._kabul = 0
        self._red = 0
        self._last_was_accept = False

    # ---- kapılar ----

    def _rate_ok(self) -> bool:
        now = time.monotonic()
        self._window = [t for t in self._window if now - t < 60]
        if len(self._window) >= self.rate:
            return False
        self._window.append(now)
        return True

    def _reject(self, host, port, path, sebep) -> dict:
        self._red += 1
        self.audit.append("PROPOSE_REJECT", host=host, port=port,
                          path=path[:200], sebep=sebep[:200])
        self._last_was_accept = False
        self._persist_session()
        return {"durum": "RED", "sebep": sebep, "kanit": None}

    def _persist_session(self) -> None:
        """Stateless çağrıcılar (MCP) için sayaçları diske biriktir.

        Basit ve doğru kural: diskteki değer + 1 (her kabul/red bir artış).
        Aynı süreç içinde de tutarlı — çünkü okuma her zaman diskten.
        """
        try:
            import os
            state_p = os.path.join(
                os.path.dirname(os.path.abspath(self.out_path)),
                "agent-session.json")
            kabul = red = 0
            if os.path.exists(state_p):
                with open(state_p, encoding="utf-8") as f:
                    st = json.loads(f.read() or "{}")
                    kabul, red = st.get("kabul", 0), st.get("red", 0)
            if self._last_was_accept:
                kabul += 1
            else:
                red += 1
            with open(state_p, "w", encoding="utf-8") as f:
                json.dump({"kabul": kabul, "red": red}, f)
        except OSError:
            pass

    # ---- öneri ----

    def propose(self, host: str, port: int, path: str, **kwargs) -> dict:
        """Ajan tek sızma önerisi sunar. Dönüş: RED veya KABUL(+kanıt).

        Gerekçe anahtar kelimesi hem 'gerekçe' (Türkçe) hem 'gerekce'
        (ASCII) kabul edilir — ajan SDK'ları ikisini de yazar.
        """
        gerekce = kwargs.get("gerekçe", kwargs.get("gerekce", ""))
        method = kwargs.get("method", "GET")
        return self._propose(host, port, path, gerekce, method)

    def _propose(self, host: str, port: int, path: str, gerekce: str,
                 method: str) -> dict:
        # 1) kill-switch
        if self.killswitch.is_active():
            return self._reject(host, port, path, "kill-switch aktif")
        # 2) gerekçe şart — amaçsız tarama yasak
        if not gerekce or not gerekce.strip():
            return self._reject(host, port, path,
                                "gerekçe zorunlu: ajan neden denediğini söylemeli")
        # 3) method beyaz listesi (esneklik sınırı: GET/HEAD)
        if method.upper() not in ("GET", "HEAD"):
            return self._reject(host, port, path,
                                f"method {method} reddedildi: yalnız GET/HEAD")
        # 4) scope kapısı
        ok, reason = self.scope.check_request(host=host, port=port,
                                              method=method.upper())
        if not ok:
            self._red += 1
            self.audit.append("SCOPE_DENY", host=host, port=port,
                              reason=f"[propose] {reason}")
            return {"durum": "RED", "sebep": reason, "kanit": None}
        # 5) zararlılık filtresi
        if is_dangerous(path):
            return self._reject(host, port, path,
                                "zararlı desen: yıkıcı/okunmaz payload RED")
        # 6) hız limiti
        if not self._rate_ok():
            return self._reject(host, port, path,
                                f"hız limiti: dakikada {self.rate} öneri")

        # ---- koş ----
        self.audit.append("PROPOSE_ACCEPT", host=host, port=port,
                          path=path[:200], gerekce=gerekce[:200],
                          method=method.upper())
        self._kabul += 1
        # stateless MCP uyumu: oturum sayacını diske de yansıt
        self._last_was_accept = True
        self._persist_session()
        r = self.tx.http_get(host, port, path)
        if r is None:
            return {"durum": "KABUL", "kanit": None,
                    "http": None, "sebep": "istek başarısız"}
        status, body, third = r
        if isinstance(third, str):
            third = {"server": third}
        kanit = extract_evidence(status, body)
        if kanit:
            f = {"tip": "agent_probe_leak",
                 "hedef": f"{host}:{port}{path[:180]}",
                 "kanit": f"[ajan önerisi] {kanit}",
                 "zaman_damgasi": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                 "kapsam_referansi": self.scope.targets[0]}
            with open(self.out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
            self.audit.append("FINDING", tip=f["tip"], hedef=f["hedef"],
                              kaynak="agent_propose")
        return {"durum": "KABUL", "kanit": kanit, "http": status,
                "sebep": ""}

    def summary(self) -> dict:
        return {"kabul": self._kabul, "red": self._red,
                "rate": self.rate}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import os
    import sys
    ap = argparse.ArgumentParser(
        prog="purpleloop.agent_attack",
        description="Ajan-esnek sızma: öneri dosyasından koş (JSONL: "
                    "{host,port,path,gerekce,method})")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--proposals", required=True,
                    help="JSONL: her satır bir ajan önerisi")
    ap.add_argument("--out-dir", default="agent-attack-run")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    ap.add_argument("--rate", type=int, default=20)
    args = ap.parse_args(argv)

    try:
        with open(args.scope, encoding="utf-8") as f:
            scope = ScopeContract(f.read())
    except Exception as e:
        print(f"FAIL-CLOSED: scope yüklenemedi: {e}", file=sys.stderr)
        return 2
    ks = KillSwitch(args.killswitch)
    if ks.is_active():
        print("FAIL-CLOSED: kill-switch aktif.", file=sys.stderr)
        return 3

    os.makedirs(args.out_dir, exist_ok=True)
    audit = AuditLog(os.path.join(args.out_dir, "audit.jsonl"))
    p = ProbeProposer(scope=scope, killswitch=ks, audit=audit,
                      out_path=os.path.join(args.out_dir, "probes.jsonl"),
                      rate_per_minute=args.rate)
    kabul = kanitli = 0
    with open(args.proposals, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                pr = json.loads(line)
            except json.JSONDecodeError:
                continue
            r = p.propose(pr.get("host", ""), int(pr.get("port", 0)),
                          pr.get("path", ""), pr.get("gerekce", ""),
                          pr.get("method", "GET"))
            kabul += r["durum"] == "KABUL"
            kanitli += bool(r.get("kanit"))
            print(json.dumps(r, ensure_ascii=False))
    print(json.dumps({**p.summary(), "kanitli_bulgu": kanitli,
                      "audit_chain_valid": audit.verify_chain()},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
