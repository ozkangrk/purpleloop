"""Hafta-3: Validator katmanı — her bulgunun bağımsız yeniden doğrulanması.

İLKELER:
  1) LLM danışmandır, jüri DEĞİLDİR. Karar (verdict) yalnızca deterministik
     yeniden-doğrulamadan (replay) gelir. LLM analizi bağlam olarak audit'e yazılır.
  2) Doğrulama sırasında yapılan HER ağ isteği yine scope kapısından geçer;
     REDDET => SKIPPED_SCOPE_DENIED + SCOPE_DENY audit kaydı.
  3) Kill-switch aktif => doğrulama yarıda kesilir (fail-closed).
  4) Her karar audit zincirine VALIDATION kaydı olarak yazılır.

Harness mimarisi:
  PurpleLoop = kontrol düzlemi (scope/audit/killswitch).
  Dış harness'ler (LLM sağlayıcılar, agent framework'leri) yalnızca analiz/öneri
  üretir; ağ eylemi yapamaz. LLMAnalyzer bunun ilk adapter'ıdır
  (OpenAI-compatible endpoint — ollama/vLLM lokal dahil).

Kullanım:
  python3 -m purpleloop.validator --scope scope.json \
      --findings findings.jsonl --out findings-validated.jsonl --audit audit.jsonl
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import socket
import sys
import urllib.request
from dataclasses import dataclass, asdict
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .recon import RealTransport, scan_secrets
from .scope import ScopeContract

VERDICTS = ("CONFIRMED", "REJECTED", "UNVERIFIED", "SKIPPED_SCOPE_DENIED")


@dataclass
class Validation:
    hedef: str
    tip: str
    verdict: str
    gerekce: str
    kanit: str
    zaman_damgasi: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


def _parse_hedef(hedef: str):
    """'host:port/path' -> (host, port, path). Port yoksa None."""
    addr, _, path = hedef.partition("/")
    path = "/" + path if path else "/"
    host, _, port = addr.rpartition(":")
    if not host or not port.isdigit():
        return hedef, None, path
    return host, int(port), path


class ValidatorAgent:
    def __init__(self, *, scope: ScopeContract, killswitch: KillSwitch,
                 audit: AuditLog, out_path: str, transport=None):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        self.tx = transport or RealTransport()
        self.validations: list = []
        self._stopped = False

    # ---- gate ----

    def _gate(self, host, port, method="GET", now=None) -> bool:
        allowed, reason = self.scope.check_request(host=host, port=port, method=method, now=now)
        if not allowed:
            self.audit.append("SCOPE_DENY", host=host, port=port, method=method, reason=reason)
            return False
        return True

    def _emit(self, finding: dict, verdict: str, gerekce: str, kanit: str) -> Validation:
        v = Validation(
            hedef=finding.get("hedef", ""),
            tip=finding.get("tip", ""),
            verdict=verdict,
            gerekce=gerekce,
            kanit=kanit[:500],
            zaman_damgasi=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        )
        self.validations.append(v)
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(v.to_json() + "\n")
        self.audit.append("VALIDATION", hedef=v.hedef, tip=v.tip, verdict=v.verdict,
                          gerekce=v.gerekce, zaman=v.zaman_damgasi)
        return v

    # ---- tip bazlı deterministik doğrulama ----

    def validate_finding(self, finding: dict) -> Validation:
        tip = finding.get("tip", "")
        hedef = finding.get("hedef", "")
        kanit = finding.get("kanit", "")

        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage="validation")
            self._stopped = True
            return self._emit(finding, "UNVERIFIED", "kill-switch aktif, doğrulama kesildi", "")

        host, port, path = _parse_hedef(hedef)

        if tip == "open_port":
            if port is None or not self._gate(host, port):
                return self._emit(finding, "SKIPPED_SCOPE_DENIED", "kapsam dışı/yetkisiz istek", "")
            if self.tx.tcp_connect(host, port):
                return self._emit(finding, "CONFIRMED", "port yeniden bağlanarak doğrulandı", "TCP reconnect OK")
            return self._emit(finding, "REJECTED", "port artık kapalı", "TCP reconnect refused")

        if tip in ("directory", "bucket_service", "open_bucket", "secret"):
            if port is None or not self._gate(host, port):
                return self._emit(finding, "SKIPPED_SCOPE_DENIED", "kapsam dışı/yetkisiz istek", "")
            r = self.tx.http_get(host, port, path)
            if r is None:
                return self._emit(finding, "UNVERIFIED", "hedefe ulaşılamadı (ağ hatası)", "")
            status, body, _banner = r
            if tip == "directory":
                if status == 200:
                    return self._emit(finding, "CONFIRMED", "HTTP 200 yeniden alındı", f"status={status} len={len(body)}")
                return self._emit(finding, "REJECTED", f"HTTP {status}, içerik yok", f"status={status}")
            if tip == "bucket_service":
                if status in (200, 403) and body.lstrip().startswith("<?xml"):
                    return self._emit(finding, "CONFIRMED", "S3-benzeri API yanıtı yeniden alındı", f"status={status}")
                return self._emit(finding, "REJECTED", "S3 API yanıtı doğrulanamadı", f"status={status}")
            if tip == "open_bucket":
                if status == 200 and body.lstrip().startswith("<?xml"):
                    return self._emit(finding, "CONFIRMED", "anonim listeleme hâlâ açık", f"status={status} len={len(body)}")
                return self._emit(finding, "REJECTED", "anonim listeleme yok/kapalı", f"status={status}")
            if tip == "secret":
                hits = [k for _, k in scan_secrets(body)]
                kanit_val = kanit.partition("=")[2] if "=" in kanit else kanit
                if kanit in hits or any(kanit_val and kanit_val in h for h in hits):
                    return self._emit(finding, "CONFIRMED", "gizli bilgi yeniden fetch + regex ile doğrulandı", kanit)
                if hits:
                    return self._emit(finding, "REJECTED", "içerik değişmiş, kanıt birebir eşleşmiyor", hits[0][:120])
                return self._emit(finding, "REJECTED", "içerikte gizli bilgi artık yok (FP veya kaldırılmış)", "")

        if tip == "subdomain":
            if not self._gate(host, 443, "HEAD"):
                return self._emit(finding, "SKIPPED_SCOPE_DENIED", "kapsam dışı/yetkisiz istek", "")
            try:
                ip = socket.gethostbyname(host)
                return self._emit(finding, "CONFIRMED", "DNS yeniden çözüldü", f"resolved {ip}")
            except OSError:
                return self._emit(finding, "REJECTED", "DNS artık çözülmüyor", "")

        return self._emit(finding, "UNVERIFIED", f"bilinmeyen bulgu tipi: {tip}", "")

    def run(self, findings: list) -> list:
        self.audit.append("VALIDATION_START", findings=len(findings))
        for f in findings:
            if self._stopped:
                break
            self.validate_finding(f)
        counts = {v: sum(1 for x in self.validations if x.verdict == v) for v in VERDICTS}
        self.audit.append("VALIDATION_END", **counts, stopped=self._stopped)
        return self.validations


# --------------------------------------------------------------------------
# LLM harness adapter'ı (danışman — karar YETKİSİ YOK)
# --------------------------------------------------------------------------

class LLMAnalyzer:
    """OpenAI-compatible chat endpoint'e bağlanan opsiyonel analiz katmanı.

    ollama/vLLM gibi LOKAL sunucular da desteklenir (veri makinenden çıkmaz).
    Her hata non-blocking'dir: analiz alınamazsa doğrulama sonucu DEĞİŞMEZ.
    """

    def __init__(self, endpoint: str, model: str = "default", timeout: int = 20):
        self.endpoint = endpoint.rstrip("/") + "/chat/completions"
        self.model = model
        self.timeout = timeout

    def summarize(self, findings: list, validations: list) -> Optional[str]:
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system",
                     "content": "Sen bir güvenlik analistisin. Yalnızca özet ve öneri üret; verdict DEĞİŞTİRME."},
                    {"role": "user",
                     "content": json.dumps({"findings": findings, "validations": validations},
                                           ensure_ascii=False)[:8000]},
                ],
                "max_tokens": 500,
            }
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception:
            return None


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="purpleloop.validator")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--findings", required=True, help="recon çıktısı (findings.jsonl)")
    ap.add_argument("--out", required=True, help="doğrulanmış çıktı (findings-validated.jsonl)")
    ap.add_argument("--audit", default="audit.jsonl")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    ap.add_argument("--llm-endpoint", default=None,
                    help="OPSİYONEL OpenAI-compatible base URL (ör. http://localhost:11434/v1). Verdict'e etkisi yoktur.")
    ap.add_argument("--llm-model", default="default")
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

    findings = []
    try:
        with open(args.findings, encoding="utf-8") as f:
            findings = [json.loads(l) for l in f if l.strip()]
    except Exception as e:
        print(f"FAIL-CLOSED: findings okunamadı: {e}", file=sys.stderr)
        return 2

    audit = AuditLog(args.audit)
    open(args.out, "w").close()
    agent = ValidatorAgent(scope=scope, killswitch=ks, audit=audit, out_path=args.out)
    validations = agent.run(findings)

    llm_summary = None
    if args.llm_endpoint:
        llm_summary = LLMAnalyzer(args.llm_endpoint, args.llm_model).summarize(findings, [asdict(v) for v in validations])
        audit.append("LLM_ANALYSIS", role="advisor", verdict_changed=False,
                     summary=(llm_summary or "llm_unavailable")[:1000])

    counts = {v: sum(1 for x in validations if x.verdict == v) for v in VERDICTS}
    ok = audit.verify_chain()
    print(json.dumps({"validations": len(validations), **counts,
                      "llm": bool(llm_summary), "audit_chain_valid": ok, "out": args.out},
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
