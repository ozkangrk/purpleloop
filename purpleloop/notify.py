"""Bulgu-alarm bildirim kanalları (notify).

Dağıtım kararları ASLA ağ eylemi yapmaz — bu modül yalnızca OKUR ve
BİLDİRİR. Ağ çağrısı yapan tek yer webhook kanallarıdır (Slack / generic),
onlar da non-blocking'dir: bir kanal hatası turu DURDURMAZ, sadece
NOTIFY_ERROR audit kaydı düşer.

Kanallar:
  - SlackWebhook : Slack incoming-webhook URL'sine urllib POST (5sn timeout)
  - WebhookGeneric: keyfi JSON POST webhook
  - FileSink     : JSONL dosyasına append (ağ yok)

Fail-closed ruhuna uygun olarak: hata durumunda exception fırlatılmaz,
tur sonuçları döndürülür ve audit zincirine kaydedilir.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

from .audit import AuditLog

# Dağıtım turu SONUCU — hata izolasyonu için kanal başına ayrı tutulur.
TIMEOUT_SNIFF = 5.0  # tüm ağ çağrıları 5 saniye ile sınırlı


# ---------------------------------------------------------------------------
# Kanal soyutlaması
# ---------------------------------------------------------------------------
class NotifyChannel:
    """Bildirim kanalı soyut sınıfı. send() hata fırlatmamalı; bool dönmeli."""

    name = "abstract"

    def send(self, payload: dict) -> bool:
        raise NotImplementedError


class _HttpJsonPoster:
    """urllib ile JSON POST — testlerde transport enjeksiyonu için ayrı sınıf."""

    def __init__(self, url: str, timeout: float = TIMEOUT_SNIFF):
        self.url = url
        self.timeout = timeout

    def post(self, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp.read()  # gövdeyi tüket (bağlantıyı düzgün kapat)


class WebhookChannel(NotifyChannel):
    """Ortak webhook davranışı: transport enjeksiyonu + non-blocking hata."""

    def __init__(self, transport: _HttpJsonPoster | None = None):
        self._transport = transport

    def _build_payload(self, findings: list, policy: dict | None) -> dict:
        raise NotImplementedError

    def deliver(self, findings: list, policy: dict | None = None) -> bool:
        payload = self._build_payload(findings, policy)
        try:
            self._transport.post(payload)
            return True
        except Exception:
            return False  # non-blocking: turu durdurma, sadece başarısız işaretle


class SlackWebhook(WebhookChannel):
    """Slack incoming-webhook kanalı — {'text': ...} gövdesiyle POST."""

    name = "slack"

    def __init__(self, url: str, transport_factory: Callable[[str], _HttpJsonPoster] | None = None):
        self.url = url
        if transport_factory is None:
            transport_factory = lambda u: _HttpJsonPoster(u)  # noqa: E731
        super().__init__(transport_factory(url))

    def _build_payload(self, findings: list, policy: dict | None) -> dict:
        # Slack mesajı: alarm başlığı + bulgu satırları
        lines = [f":rotating_light: PurpleLoop alarm — {len(findings)} error-level bulgu"]
        if policy:
            karar = policy.get("karar") or policy.get("decision")
            if karar:
                lines.append(f"Policy kararı: {karar}")
        for f in findings:
            lines.append(f"• [{f.get('tip', '?')}] {f.get('hedef', '?')}")
        return {"text": "\n".join(lines)}


class WebhookGeneric(WebhookChannel):
    """Keyfi JSON POST webhook — bulgu listesini olduğu gibi iletir."""

    name = "webhook-generic"

    def __init__(self, url: str, transport_factory: Callable[[str], _HttpJsonPoster] | None = None):
        self.url = url
        if transport_factory is None:
            transport_factory = lambda u: _HttpJsonPoster(u)  # noqa: E731
        super().__init__(transport_factory(url))

    def _build_payload(self, findings: list, policy: dict | None) -> dict:
        return {"source": "purpleloop", "findings": findings, "policy": policy}


class FileSink(NotifyChannel):
    """JSONL dosyasına append — ağ YOK, yerel kanal."""

    name = "file"

    def __init__(self, path: str):
        self.path = path

    def send(self, payload: dict) -> bool:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Dağıtım çekirdeği
# ---------------------------------------------------------------------------
def _hata_seviyesi(findings: list) -> list:
    """Sadece error-level bulguları süz.

    Finding şemasında 'severity' alanı YOKTUR — tip alanından türetilir
    (platform_layer._SEVERITY ile SARIF eşleşmesi). Hem severity alanı
    taşıyan (dış kaynak) hem de tip tabanlı bulgular desteklenir.
    """
    from .platform_layer import _SEVERITY
    out = []
    for f in findings:
        if not isinstance(f, dict):
            if hasattr(f, "__dict__"):
                f = dict(f.__dict__)
            else:
                continue
        sev = str(f.get("severity", "")).lower()
        if not sev:
            level, _ = _SEVERITY.get(f.get("tip", ""), ("note", 0.0))
            sev = level
        if sev in ("error", "high"):
            out.append(f)
    return out


def notify(findings: list,
           policy: dict | None,
           channels: list,
           audit_path: str = "audit.jsonl") -> list:
    """error-level bulguları kanallara dağıt; kanal hatası turu DURDURMAZ.

    Dönüş: [{'kanal', 'bulgu_sayisi', 'durum': 'ok'|'hata'}, ...]
    Her kanal için audit'e NOTIFY (başarı) veya NOTIFY_ERROR kaydı düşülür.
    """
    hedef = _hata_seviyesi(findings)
    audit = AuditLog(audit_path)
    results = []
    for ch in channels:
        if isinstance(ch, WebhookChannel):
            payload_hint = ch._build_payload(hedef, policy)
            ok = ch.deliver(hedef, policy)
        else:
            payload_hint = {"findings": hedef, "policy": policy}
            try:
                ok = ch.send(payload_hint)
            except Exception:
                ok = False  # hata non-blocking: turu durdurma
        if ok:
            audit.append("NOTIFY", kanal=getattr(ch, "name", type(ch).__name__),
                         bulgu_sayisi=len(hedef), durum="ok")
            results.append({"kanal": getattr(ch, "name", type(ch).__name__),
                            "bulgu_sayisi": len(hedef), "durum": "ok"})
        else:
            # hata non-blocking: turu durdurmaz, kayda geçer
            audit.append("NOTIFY_ERROR", kanal=getattr(ch, "name", type(ch).__name__),
                         bulgu_sayisi=len(hedef), durum="hata")
            results.append({"kanal": getattr(ch, "name", type(ch).__name__),
                            "bulgu_sayisi": len(hedef), "durum": "hata"})
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_channels(spec: str) -> list:
    """'slack=URL|file=PATH' (virgüllü) biçimini kanal nesnelerine çevir."""
    channels = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        kind, _, val = part.partition("=")
        kind = kind.strip().lower()
        if kind == "slack":
            channels.append(SlackWebhook(val))
        elif kind in ("webhook", "generic", "webhook-generic"):
            channels.append(WebhookGeneric(val))
        elif kind == "file":
            channels.append(FileSink(val))
        else:
            raise ValueError(f"bilinmeyen kanal türü: {kind}")
    return channels


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="purpleloop.notify",
        description="Bulgu alarmları: webhook/Slack/file kanallarına dağıtım (salt-okunur karar, sadece bildirir)")
    ap.add_argument("--channels", required=True,
                    help="virgüllü liste: slack=URL|file=PATH|webhook=URL")
    ap.add_argument("--findings", required=True, help="findings.jsonl")
    ap.add_argument("--gate", default=None, help="karar.json (policy kararı, opsiyonel)")
    ap.add_argument("--audit", default="audit.jsonl", help="audit JSONL yolu")
    ap.add_argument("--dry-run", action="store_true",
                    help="ağ çağrısı YAPMA; ne gönderileceğini bas")
    args = ap.parse_args(argv)

    findings = []
    with open(args.findings, encoding="utf-8") as f:
        findings = [json.loads(l) for l in f if l.strip()]

    policy = None
    if args.gate:
        with open(args.gate, encoding="utf-8") as f:
            policy = json.load(f)

    try:
        channels = parse_channels(args.channels)
    except ValueError as e:
        print(f"kanal hatası: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        # ağ çağrısı yok: sadece payload'ları stdour bas
        hedef = _hata_seviyesi(findings)
        for ch in channels:
            if isinstance(ch, WebhookChannel):
                payload = ch._build_payload(hedef, policy)
            else:
                payload = {"findings": hedef, "policy": policy}
            print(json.dumps({"kanal": ch.name, "dry_run": True,
                              "payload": payload}, ensure_ascii=False))
        return 0

    results = notify(findings, policy, channels, audit_path=args.audit)
    print(json.dumps({"sonuclar": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
