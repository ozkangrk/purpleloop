"""agentguard — dış ajanların (coding agent'lar) PurpleLoop kontrol düzlemine
bağlandığı gözlem arayüzü (v2.6).

Nadella manifestosunun maddelerini koda çevirir:
  - "kontroller modelin dışında"      -> hook/rapor/fren burada, ajan değil
  - "gözlemlenemeyene güvenilmez"     -> her aksiyon hash-zincirine yazılır
  - "yetkiyi ayır"                    -> fren yetkisi kill-switch'te, ajanda değil
  - "bağımsız doğrulama"              -> rapor ajanın iddiasına değil kanıta bakar

Üç yüzey:
  1. AgentGuard.observe(tool, payload)   — her aksiyonu kaydeder (hook hattı)
  2. AgentGuard.check(...)               — aksiyon ÖNCESİ kapı: kapsam + desen
  3. AgentGuard.report(...)              — coding-agent bağlamına markdown rapor

Hiçbir ağ çağrısı YAPMAZ — gözcüdür, yürütücü değil. Fail-closed:
kill-switch aktifken check() her zaman RED döner.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from urllib.parse import unquote, unquote_plus

from .audit import AuditLog
from .killswitch import KillSwitch
from .platform_layer import _SEVERITY

# Ajan eylem tipleri — hook'lardan gelen olay adlarıyla hizalı
AKSIYON_TIPLERI = frozenset({
    "read", "write", "edit", "delete", "bash", "network", "git",
    "mcp_call", "search", "spawn", "other",
})

# Yasak desenler: kalıcı hasar / kapsam kaçışı imzaları (metin bazlı,
# URL-decode edilmiş halde eşleşir — agent_attack ile aynı disiplin)
_YASAK_DESENLER = (
    (re.compile(r"(?i)rm\s+-rf\s+/"), "yıkıcı dosya silme"),
    (re.compile(r"(?i)drop\s+table"), "yıkıcı veritabanı"),
    (re.compile(r"(?i)shutdown|halt\s+-p|poweroff"), "sistem kapatma"),
    (re.compile(r"(?i)curl[^|]{0,80}\|\s*(ba)?sh"), "uzak betik borulama"),
    (re.compile(r"(?i)chmod\s+-R\s+777\s+/"), "genel yazma izni"),
    (re.compile(r"(?i)git\s+push\s+--force\s+main"), "ana dal zorla itme"),
)


class AgentGuard:
    """Dış ajan eylemleri için gözlem + kapı + rapor düzlemi.

    Ajan PurpleLoop'un DIŞINDA çalışır; hook'ları buraya olay yazar.
    Karar vermeye yetkili tek şey kill-switch'tir (fail-closed).
    """

    def __init__(self, out_dir: str, audit: AuditLog | None = None,
                 killswitch: KillSwitch | None = None,
                 scope: "object | None" = None) -> None:
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.audit = audit
        self.ks = killswitch
        self.scope = scope
        self.session_file = os.path.join(out_dir, "agent-session.jsonl")

    # ------------------------------------------------------------------
    # 1) GÖZLEM — her ajan eylemi hash-zincirine yazılır
    # ------------------------------------------------------------------
    def observe(self, agent: str, tool: str, payload: dict,
                decision: str = "ok", detail: str = "") -> dict:
        """Ajan eylemini kaydet. return komut dosyası özetidir."""
        tip = tool.strip().lower() if tool else "other"
        if tip not in AKSIYON_TIPLERI:
            tip = "other"
        rec = {
            "olay": "AGENT_ACTION",
            "agent": str(agent)[:120],
            "aksiyon": tip,
            "payload_ozet": json.dumps(payload, ensure_ascii=False,
                                       default=str)[:2000],
            "karar": decision,
            "detay": str(detail)[:500],
            "zaman_damgasi": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
        if self.audit is not None:
            self.audit.append("AGENT_ACTION",
                              agent=rec["agent"], aksiyon=rec["aksiyon"],
                              karar=rec["karar"], detay=rec["detay"])
        with open(self.session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    # ------------------------------------------------------------------
    # 2) KAPI — aksiyon ÖNCESİ izin kontrolü (hook deny hattı)
    # ------------------------------------------------------------------
    def check(self, agent: str, tool: str, payload: dict) -> dict:
        """Ajan aksiyonuna izin verilecek mi? Fail-closed."""
        karar = "IZIN"
        neden = ""
        # (a) kill-switch her şeyden önce — fail-closed
        if self.ks is not None and self.ks.is_active():
            karar, neden = "RED", "kill-switch aktif"
        else:
            # (b) metin bazlı yıkıcı desen taraması (tüm metin alanlarında)
            # URL-decode varyantları DA TARANIR: rm%20-rf ham regex'i atlatır
            metin = json.dumps(payload, ensure_ascii=False, default=str)
            varyantlar = [metin]
            try:
                varyantlar.append(unquote(metin))
                varyantlar.append(unquote_plus(metin))
            except Exception:
                pass
            for rx, ad in _YASAK_DESENLER:
                if any(rx.search(v) for v in varyantlar):
                    karar, neden = "RED", f"yasak desen: {ad}"
                    break
            # (c) ağ hedefi varsa kapsam kontrolü
            if karar == "IZIN" and self.scope is not None:
                host = payload.get("host") or payload.get("url_host")
                port = payload.get("port")
                if host and port:
                    ok, _gerekce = self.scope.check_request(
                        host=str(host), port=int(port), method="GET")
                    if not ok:
                        karar, neden = "RED", "kapsam dışı hedef"
        self.observe(agent, tool, payload, decision=karar, detail=neden)
        return {"karar": karar, "neden": neden}

    # ------------------------------------------------------------------
    # 3) RAPOR — coding agent'in bağlamına enjekte edilebilir markdown
    # ------------------------------------------------------------------
    def report(self, run_dir: str, style: str = "coding",
               agent: str = "coding-agent") -> dict:
        """Bulguları coding-agent bağlamına uygun markdown'a çevirir.

        style="coding": her bulgunun altında dosya/satır önerisi ve
        remediation adımları — ajan bunu PR bağlamı olarak okur.
        """
        findings = []
        for ad in ("findings.jsonl", "active-findings.jsonl",
                   "campaign-findings.jsonl", "recon-findings.jsonl",
                   "bounty-findings.jsonl", "chain-findings.jsonl"):
            p = os.path.join(run_dir, ad)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        # dedupe (tip+hedef)
        gorulen = set()
        tekil = []
        for f_ in findings:
            k = (str(f_.get("tip")), str(f_.get("hedef")))
            if k not in gorulen:
                gorulen.add(k)
                tekil.append(f_)
        satirlar = [
            "# PurpleLoop Güvenlik Raporu (coding-agent bağlamı)",
            "",
            f"- Kaynak: `{run_dir}`",
            f"- Bulgu (tekil): {len(tekil)}",
            f"- Rapor zamanı: {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}",
            "",
        ]
        if not tekil:
            satirlar.append("Bulgu yok — tarama temiz.")
        for i, f_ in enumerate(tekil, 1):
            tip = f_.get("tip", "?")
            sev = _SEVERITY.get(tip, ("note", 1.0))
            satirlar.append(f"## {i}. [{sev[0].upper()}] {tip} — {f_.get('hedef', '?')}")
            satirlar.append("")
            satirlar.append(f"**Kanıt:** {str(f_.get('kanit'))[:200]}")
            satirlar.append("")
            r = remediation_for(f_)
            if r:
                satirlar.append(f"**Risk:** {r.get('risk', '')}")
                satirlar.append("**Düzeltme adımları:**")
                for adim in (r.get("steps") or [])[:5]:
                    satirlar.append(f"- {adim}")
                if r.get("owasp"):
                    satirlar.append(f"**OWASP:** {r['owasp']}")
            satirlar.append("")
        md = "\n".join(satirlar)
        out = os.path.join(self.out_dir, "agent-rapor.md")
        with open(out, "w", encoding="utf-8") as f:
            f.write(md)
        self.observe(agent, "report", {"run_dir": run_dir, "bulgu": len(tekil)},
                     decision="ok", detail="rapor üretildi")
        return {"rapor": out, "bulgu": len(tekil), "markdown": md[:400]}


def remediation_for(f_: dict) -> dict:
    """Finding -> remediation DB kaydı (yoksa boş)."""
    try:
        from .remediation import get_remediation
        return get_remediation(f_.get("tip", ""),
                               str(f_.get("kanit", ""))[:200]) or {}
    except Exception:
        return {}
