"""v1.1: Jev-tarzı karar katmanı (System One) — bulgu triajı için.

KONSEPT (TypeSafe AI'nin Jev'inden esinlenme):
  LLM'ler (System 2) metin üretir — yavaş, serbest, denetlenmesi gerekir.
  Karar modelleri (System 1) TİPLİ karar üretir — hızlı, kısıtlı, kalibre
  güvenle. "Akıllı if-ifadesi": state girer, {seçim/skor + confidence} çıkar.

PurpleLoop kullanımı (verdict YETKİSİ YOKTUR — triaj/önceliklendirme only):
  Bir bulgu için tek soru seti: severity skoru, FP olasılığı, exploitability.
  Karar katmanı yanıtı JSON-schema ile kısıtlanır; parse edilemezse
  fail-closed: varsayılan muhafazakâr değer döner.

Arka uçlar:
  - JevAPIBackend: https://api.typesafe.ai (gerçek Jev; TYPESAFE_API_KEY ortam değişkeni)
  - LocalQwenBackend: TensorFold'daki Qwen 3.8 (System-1 emülasyonu: tek çağrı,
    sıkı JSON şeması, sıcaklık 0, düşük max_tokens — hız odaklı)

Kullanım:
  from purpleloop.decision import triage_backend, triage_finding
  t = triage_finding(finding, backend)  # -> TriageDecision
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, asdict

# --------------------------------------------------------------------------
# Tipte karar çıktısı (Jev'in typed-output felsefesi)
# --------------------------------------------------------------------------

@dataclass
class TriageDecision:
    severity: str          # "high" | "medium" | "low" | "info"
    fp_olasilik: float     # 0..1 — yanlış-pozitif olasılığı
    exploitability: float  # 0..1 — sömürülebilirlik
    confidence: float      # 0..1 — kararın kendine güveni (kalibrasyon)
    gerekce_kisa: str      # <= 80 karakter

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


VALID_SEVERITIES = {"high", "medium", "low", "info"}


def _clamp(x: float) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.5


def parse_decision(raw: str) -> TriageDecision:
    """Fail-closed parser: bozuk yanıt => muhafazakâr varsayılan."""
    fallback = TriageDecision("medium", 0.5, 0.5, 0.1, "karar-katmani-yerine-getirilemedi")
    try:
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return fallback
        d = json.loads(m.group(0))
        sev = str(d.get("severity", "medium")).lower()
        if sev not in VALID_SEVERITIES:
            sev = "medium"
        return TriageDecision(
            severity=sev,
            fp_olasilik=_clamp(d.get("fp_olasilik", 0.5)),
            exploitability=_clamp(d.get("exploitability", 0.5)),
            confidence=_clamp(d.get("confidence", 0.1)),
            gerekce_kisa=str(d.get("gerekce_kisa", ""))[:80],
        )
    except Exception:
        return fallback


# --------------------------------------------------------------------------
# Arka uçlar
# --------------------------------------------------------------------------

class JevAPIBackend:
    """Gerçek Jev (TypeSafe AI) — tipli kararlar, ~100ms, hallucination imkânsız.
    TYPESAFE_API_KEY yoksa kullanılamaz (init'te ValueError)."""

    def __init__(self, api_key: str = None, timeout: int = 10):
        self.key = api_key or os.environ.get("TYPESAFE_API_KEY", "")
        if not self.key:
            raise ValueError("TYPESAFE_API_KEY ayarlı değil")
        self.url = "https://api.typesafe.ai/v1/decide"
        self.timeout = timeout
        self.name = "jev-api"

    def decide(self, state: str, questions: dict) -> dict:
        payload = {"state": state, "questions": questions}
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.key}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())


class LocalQwenBackend:
    """System-1 emülasyonu: TensorFold Qwen 3.8 Flash Next.
    Tek çağrı + sıkı JSON şeması + temperature 0 + kısa çıktı.
    Jev değil ama DAİMA elimizde olan, veriyi dışarı çıkarmayan seçenek."""

    def __init__(self, endpoint: str = "http://127.0.0.1:8888/v1",
                 model: str = "qwen3.8-flash-next", timeout: int = 30):
        self.url = endpoint.rstrip("/") + "/chat/completions"
        self.model = model
        self.timeout = timeout
        self.name = "local-qwen-system1"

    def decide(self, state: str, questions: dict) -> dict:
        sys_p = ("You are a security TRIAGE decision function. "
                 "Output ONE JSON object only. No prose. No explanation. "
                 "Schema: {\"severity\": str in [high,medium,low,info], "
                 "\"fp_olasilik\": float 0-1, \"exploitability\": float 0-1, "
                 "\"confidence\": float 0-1, \"gerekce_kisa\": str<=80ch}. "
                 "Be calibrated: low confidence when unsure.")
        user = f"FINDING STATE:\n{state}\n\nQUESTIONS: {json.dumps(questions, ensure_ascii=False)}\n\nJSON:"
        payload = {"model": self.model,
                   "messages": [{"role": "system", "content": sys_p},
                                {"role": "user", "content": user}],
                   "max_tokens": 120, "temperature": 0.0}
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode())
        return {"raw": data["choices"][0]["message"]["content"] or ""}


class StaticBackend:
    """Deterministik kural-tabanlı yedek (LLM'siz, offline) — CI için."""

    def __init__(self):
        self.name = "static-rules"

    _RULES = {
        "secret": ("high", 0.05, 0.85),
        "open_bucket": ("high", 0.05, 0.80),
        "missing_header": ("low", 0.10, 0.40),
        "directory": ("medium", 0.10, 0.60),
        "bucket_service": ("medium", 0.10, 0.50),
        "open_port": ("info", 0.05, 0.30),
        "subdomain": ("info", 0.10, 0.20),
    }

    def decide(self, state: str, questions: dict) -> dict:
        tip = questions.get("tip", "")
        sev, fp, ex = self._RULES.get(tip, ("medium", 0.5, 0.5))
        d = TriageDecision(sev, fp, ex, 0.95, f"static-kural: {tip}")
        return {"raw": d.to_json()}


def triage_backend(prefer: str = "auto"):
    """Arka uç seçimi: auto → Jev (key varsa) → lokal Qwen → statik kurallar."""
    if prefer in ("auto", "jev"):
        try:
            return JevAPIBackend()
        except ValueError:
            pass
    if prefer in ("auto", "local"):
        try:
            b = LocalQwenBackend()
            # hızlı sağlıklık kontrolü yapmayız (maliyet); çağrıda belli olur
            return b
        except Exception:
            pass
    return StaticBackend()


# --------------------------------------------------------------------------
# Bulgu triajı
# --------------------------------------------------------------------------

_TRIAGE_QUESTIONS = {
    "soru1": "Bu bulgunun gerçek dünya severity'si nedir? (high/medium/low/info)",
    "soru2": "Bulgu yanlış-pozitif olabilir mi? (fp_olasilik)",
    "soru3": "Bulgu sömürülebilir mi? (exploitability)",
}


def triage_finding(finding: dict, backend) -> TriageDecision:
    """Tek bulgu için System-1 kararı. Hata => fail-closed fallback."""
    state = (f"tip={finding.get('tip')} | hedef={finding.get('hedef')} | "
             f"kanit={str(finding.get('kanit', ''))[:300]}")
    qs = dict(_TRIAGE_QUESTIONS)
    qs["tip"] = finding.get("tip", "")
    try:
        resp = backend.decide(state, qs)
        return parse_decision(resp.get("raw", "") if isinstance(resp, dict) else str(resp))
    except Exception:
        return parse_decision("")


def triage_findings(findings: list, backend=None) -> list:
    """Toplu triaj; her karar audit'e yazılmak üzere döner (yazım çağıranda)."""
    backend = backend or triage_backend()
    return [(f, triage_finding(f, backend)) for f in findings]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse, sys
    ap = argparse.ArgumentParser(prog="purpleloop.decision",
                                 description="Jev-tarzı karar katmanı: bulgu triajı")
    ap.add_argument("--findings", required=True, help="findings.jsonl")
    ap.add_argument("--backend", default="auto", choices=["auto", "jev", "local", "static"])
    ap.add_argument("--out", default="triage.jsonl")
    args = ap.parse_args(argv)

    findings = []
    with open(args.findings, encoding="utf-8") as f:
        findings = [json.loads(l) for l in f if l.strip()]

    backend = triage_backend(args.backend)
    print(f"arka uç: {backend.name}", file=sys.stderr)
    rows = []
    for f, d in triage_findings(findings, backend):
        rows.append({"hedef": f.get("hedef"), "tip": f.get("tip"), **asdict(d)})
    with open(args.out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    high = sum(1 for r in rows if r["severity"] == "high")
    print(json.dumps({"triage": len(rows), "high": high, "backend": backend.name},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
