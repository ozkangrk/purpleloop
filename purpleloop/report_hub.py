"""Rol-bazlı rapor üretme merkezi — Roadmap v1.0 maddesi.

Üç üretici (hepsi saf/stdlib, additive-only — mevcut modüllere dokunmaz):
  yonetici_ozeti(findings, gate)  → yönetici özeti (risk cümlesi + eşik + top-3 + aksiyonlar)
  denetci_raporu(findings, audit)  → denetçi izlenebilirlik raporu (audit sha zinciri + verify + kapsam)
  teknik_detay(findings)          → bulgu başına yeniden üretilebilir komut/istek + kanıt + severity

CLI:
  python3 -m purpleloop.report_hub --findings F.jsonl --audit audit.jsonl \
      --gate PASS --out-dir rapor/ --roller yonetici,denetci,teknik
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .audit import AuditLog, AuditTamperError
from .platform_layer import PolicyGate, _SEVERITY

ROLLER = ("yonetici", "denetci", "teknik")

# ---------------------------------------------------------------------------


def _load_findings(findings_arg) -> list:
    """--findings argümanını (JSONL dosya yolu veya liste) bulgu listesine çevir."""
    if isinstance(findings_arg, (list, tuple)):
        return list(findings_arg)
    findings = []
    if findings_arg and os.path.exists(findings_arg):
        with open(findings_arg, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
    return findings


def _seviye(f: dict) -> str:
    """Bulgunun SARIF level'ı (error/warning/note)."""
    return _SEVERITY.get(f.get("tip", ""), ("note", 0.0))[0]


def _sev_notu(f: dict) -> str:
    """Bulgunun security-severity notu (0-10)."""
    return str(_SEVERITY.get(f.get("tip", ""), ("note", 1.0))[1])


def _md_escape(s: str) -> str:
    """Markdown tablosunda dikey çizgiyi boz."""
    return str(s).replace("|", "\\|").replace("\n", " ")


def _top_n(findings: list, n: int = 3) -> list:
    """En kritik N bulgu: önce error, sonra security-severity'ye göre."""
    order = {"error": 0, "warning": 1, "note": 2}
    ranked = sorted(
        findings,
        key=lambda f: (
            order.get(_seviye(f), 3),
            -_SEVERITY.get(f.get("tip", ""), ("note", 0.0))[1],
        ),
    )
    return ranked[:n]


# ---------------------------------------------------------------------------
# 1) Yönetici özeti
# ---------------------------------------------------------------------------

def yonetici_ozeti(findings: list, gate: dict) -> str:
    """Yönetici özeti markdown: tek cümle risk + eşik durumu + top-3 tablo + aksiyonlar."""
    durum = gate.get("durum", "BİLİNMİYOR")
    error = gate.get("error", sum(1 for f in findings if _seviye(f) == "error"))
    warning = gate.get("warning", sum(1 for f in findings if _seviye(f) == "warning"))

    if durum == "PASS":
        risk = (f"Tarama kapıdan GEÇTİ (PASS): {len(findings)} bulgu içinde "
                f"{error} error / {warning} warning seviyesinde, eşikler aşılmadı.")
    else:
        risk = (f"Tarama kapıda TAKILDI ({durum}): {error} error / {warning} warning "
                f"bulgusuyla eşik aşıldı — yayına çıkma öncesi düzeltme gerekli.")

    md = [f"# Yönetici Özeti — PurpleLoop", ""]
    md.append(f"**Risk özeti:** {risk}")
    md.append("")
    md.append(f"**Eşik durumu:** `{durum}` — error: {error}, warning: {warning} "
              f"(eşik: error≤{gate.get('esik', {}).get('error', '-')}, "
              f"warning≤{gate.get('esik', {}).get('warning', '-')})")
    md.append("")
    md.append("## En Kritik 3 Bulgu")
    md.append("")
    md.append("| # | Tip | Hedef | Seviye |")
    md.append("|---|-----|-------|--------|")
    for i, f in enumerate(_top_n(findings, 3), 1):
        md.append(f"| {i} | {_md_escape(f.get('tip', '-'))} | "
                  f"{_md_escape(f.get('hedef', '-'))} | {_seviye(f)} |")
    md.append("")

    md.append("## Önerilen Aksiyonlar")
    md.append("")
    aksiyonlar = []
    if any(_seviye(f) == "error" for f in findings):
        aksiyonlar.append("Error seviyesindeki bulgular için düzeltme görevi aç ve tekrar tara.")
    if any(f.get("tip") == "missing_header" for f in findings):
        aksiyonlar.append("Eksik güvenlik başlıklarını (CSP vb.) reverse proxy/uygulamada ekle.")
    if any(_seviye(f) == "warning" for f in findings):
        aksiyonlar.append("Warning seviyesindeki bulguları sprint içi hardening kapsamına al.")
    if durum != "PASS":
        aksiyonlar.append("Eşik aşımı nedeniyle release kapısını kilitle; bypass için bilet zorunlu.")
    if not aksiyonlar:
        aksiyonlar.append("Bulgu yükü eşik içinde — rutin izlemeyle devam et.")
    for a in aksiyonlar:
        md.append(f"- [ ] {a}")
    md.append("")
    return "\n".join(md)


# ---------------------------------------------------------------------------
# 2) Denetçi izlenebilirlik raporu
# ---------------------------------------------------------------------------

def denetci_raporu(findings: list, audit_path: str,
                   scope_path: Optional[str] = None) -> str:
    """Denetçi raporu: bulgu → audit zincir sha referansları + verify + kapsam sözleşmesi."""
    # audit kayıtlarını oku ve bulgularla eşleştir (tip+hedef alanları üzerinden)
    kayitlar = []
    verify = "DOĞRULANAMADI (audit dosyası yok)"
    if audit_path and os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        kayitlar.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        try:
            AuditLog(audit_path).verify_chain()
            verify = f"GEÇERLİ ({len(kayitlar)} kayıt, zincir sağlam)"
        except AuditTamperError as e:
            verify = f"BOZUK — {e}"

    md = [f"# Denetçi İzlenebilirlik Raporu — PurpleLoop", ""]
    md.append(f"**Audit zinciri:** `{audit_path or '-'}`")
    md.append("")
    md.append(f"**Zincir doğrulama sonucu:** {verify}")
    md.append("")

    md.append("## Bulgu İzlenebilirlik Tablosu")
    md.append("")
    md.append("| Bulgu | Tip | Hedef | Audit Event sha256 |")
    md.append("|-------|-----|-------|---------------------|")
    for i, f in enumerate(findings, 1):
        shas = [r.get("sha256", "") for r in kayitlar
                if r.get("tip") == f.get("tip") and r.get("hedef") == f.get("hedef")]
        sha_gost = ", ".join(f"`{s[:16]}…`" for s in shas) if shas else "`-`"
        md.append(f"| B{i} | {_md_escape(f.get('tip', '-'))} | "
                  f"{_md_escape(f.get('hedef', '-'))} | {sha_gost} |")
    md.append("")

    # kapsam sözleşmesi özeti
    md.append("## Kapsam Sözleşmesi Özeti")
    md.append("")
    kapsam_okundu = False
    if scope_path and os.path.exists(scope_path):
        try:
            with open(scope_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            md.append(f"- **Dosya:** `{scope_path}`")
            md.append(f"- **Hedefler:** {', '.join(map(str, doc.get('targets', [])))}")
            md.append(f"- **Portlar:** {', '.join(map(str, doc.get('ports', [])))}")
            md.append(f"- **Metotlar:** {', '.join(map(str, doc.get('methods', [])))}")
            kapsam_okundu = True
        except Exception as e:
            md.append(f"- Sözleşme okunamadı: {e}")
    if not kapsam_okundu:
        refs = sorted({str(f.get("kapsam_referansi", "-")) for f in findings})
        md.append(f"- Bulgulardan türetilen kapsam referansları: {', '.join(refs) or '-'}")
    md.append("")
    return "\n".join(md)


# ---------------------------------------------------------------------------
# 3) Teknik detay raporu
# ---------------------------------------------------------------------------

def _istek(f: dict) -> str:
    """Bulgu için yeniden üretilebilir GET isteği (curl komutu)."""
    hedef = f.get("hedef", "")
    yol = hedef.split(":", 2)[-1] if ":" in hedef else hedef
    host = hedef.split(":", 1)[0] if ":" in hedef else hedef
    # hedef "host:port/yol" biçimindeyse portu ayıkla
    port = ""
    if ":" in hedef:
        parts = hedef.split(":", 1)[1]
        if parts[:1] and parts.split("/", 1)[0].isdigit():
            port = parts.split("/", 1)[0]
    base = f"http://{host}:{port}" if port else f"http://{host}"
    yol = "/" + yol.split("/", 1)[1] if "/" in yol else "/"
    return f"curl -sS '{base}{yol}'"


def teknik_detay(findings: list) -> str:
    """Teknik detay: bulgu başına istek, kanıt alıntısı, severity notu."""
    md = ["# Teknik Detay Raporu — PurpleLoop", ""]
    for i, f in enumerate(findings, 1):
        md.append(f"## B{i} — {f.get('tip', '-')}")
        md.append("")
        md.append(f"- **Hedef:** `{f.get('hedef', '-')}`")
        md.append(f"- **SEVERITY:** `{_seviye(f)}` (security-severity: {_sev_notu(f)}/10)")
        md.append(f"- **Zaman damgası:** {f.get('zaman_damgasi', '-')}")
        md.append(f"- **Kapsam referansı:** `{f.get('kapsam_referansi', '-')}`")
        md.append(f"- **Yeniden üretme:** `{_istek(f)}`")
        md.append("")
        md.append(f"> Kanıt: {f.get('kanit', '-')}")
        md.append("")
        # --- DÜZELTME ÖNERİSİ (v2.5): her bulgu için somut fix ---
        try:
            from .remediation import get_remediation
            rem = get_remediation(f.get("tip", ""), f.get("kanit", ""))
            md.append("### Düzeltme Önerisi")
            md.append("")
            md.append(f"**Risk:** {rem['risk']}")
            md.append("")
            md.append("**Adımlar:**")
            for adim in rem["adimlar"]:
                md.append(f"1. {adim}")
            md.append("")
            md.append(f"**OWASP:** {rem['owasp']} · **Doğrulama:** {rem['dogrulama']}")
            md.append("")
        except Exception:
            pass
    return "\n".join(md)


# ---------------------------------------------------------------------------
# 4) Kapak raporu — security tool seviyesi (bounty kanıtlı executive rapor)
# ---------------------------------------------------------------------------

def executive_summary(findings: list, bounty_sonuc: Optional[dict]) -> str:
    """Kapak raporu markdown: 3 satırlık risk cümlesi + çözülen bounty tablosu
    (seviye/puan) + kalan riskler + önerilen aksiyonlar.

    bounty_sonuc: BountyHarness.run() çıktısı ({'cozulen', 'solved', 'odul_toplami', ...}).
    None ise bounty kanıtı olmayan sade kapak üretilir.
    """
    bs = bounty_sonuc or {}
    solved = bs.get("solved", []) or []
    cozulen = bs.get("cozulen", len(solved))
    odul = bs.get("odul_toplami",
                  sum(int(s.get("puan", 0)) for s in solved))
    halted = bool(bs.get("halted"))

    error = sum(1 for f in findings if _seviye(f) == "error")
    warning = sum(1 for f in findings if _seviye(f) == "warning")

    md = ["# Kapak Raporu — PurpleLoop Security Tool", ""]

    # --- 3 satırlık risk cümlesi ---
    md.append("## Risk Özeti (3 cümle)")
    md.append("")
    if halted:
        md.append(f"1. Bounty koşusu kill-switch ile DURDURULDU; {len(findings)} bulgu "
                  f"({error} error / {warning} warning) mevcut durumda değerlendirildi.")
    elif solved:
        md.append(f"1. Yetkili sızma kampanyasında hedefin kendi skorboardu "
                  f"{cozulen} challenge'ı ÇÖZÜLMÜŞ olarak doğruladı "
                  f"(toplam ödül: {odul} puan).")
    else:
        md.append(f"1. Bounty kanıtı yok: sunucu skorboardu bu koşuda çözülmüş "
                  f"challenge onaylamadı.")
    md.append(f"2. Belirlenen bulgu yükü: {len(findings)} bulgu — "
              f"{error} error, {warning} warning, "
              f"{len(findings) - error - warning} bilgi seviyesi.")
    if error:
        md.append("3. Kritik seviyede doğrulanmış zafiyetler mevcut; düzeltme "
                  "tamamlanana kadar saldırı yüzeyi aktif risk taşır.")
    else:
        md.append("3. Error seviyesinde bulgu yok; kalan riskler warning/bilgi "
                  "seviyesinde ve planlı hardening ile kapatılabilir.")
    md.append("")

    # --- Çözülen bounty'ler tablosu ---
    md.append("## Çözülen Bounty'ler (skorboard doğrulamalı)")
    md.append("")
    if solved:
        md.append("| Challenge | Zorluk | Seviye | Puan |")
        md.append("|-----------|--------|--------|------|")
        for s in sorted(solved, key=lambda x: -int(x.get("puan", 0))):
            md.append(f"| {_md_escape(s.get('ad', s.get('key', '-')))} | "
                      f"{s.get('zorluk', '-')} | {s.get('seviye', '-')} | "
                      f"{s.get('puan', 0)} |")
        md.append("")
        md.append(f"**Toplam:** {cozulen} challenge çözüldü, **{odul} puan** ödül "
                  f"(doğrulayıcı: hedef uygulamanın `/api/challenges` 'solved' alanı).")
    else:
        md.append("_Bu koşuda skorboard doğrulamalı çözülmüş challenge yok._")
    md.append("")

    # --- Kalan riskler ---
    md.append("## Kalan Riskler")
    md.append("")
    kalan = []
    if error:
        kalan.append(f"{error} error seviyesinde bulgu açık (kritik saldırı yüzeyi).")
    if warning:
        kalan.append(f"{warning} warning seviyesinde bulgu henüz kapatılmadı.")
    cozulmemis = bs.get("cozulmemis")
    if cozulmemis:
        kalan.append(f"{cozulmemis} challenge hâlâ çözülmedi (tam kapsam kanıtı eksik).")
    if halted:
        kalan.append("Bounty koşusu kill-switch ile yarım kaldı — tekrar koşulmalı.")
    if not kalan:
        kalan.append("Bilinen açık risk yükü eşik içinde; rutin izleme yeterli.")
    for k in kalan:
        md.append(f"- {k}")
    md.append("")

    # --- Önerilen aksiyonlar ---
    md.append("## Önerilen Aksiyonlar")
    md.append("")
    aksiyonlar = []
    if error:
        aksiyonlar.append("Error bulguları için acil düzeltme görevi aç ve `validate` ile yeniden doğrula.")
    if warning:
        aksiyonlar.append("Warning bulgularını bir sonraki hardening sprint'ine al.")
    if solved and bs.get("yeni"):
        aksiyonlar.append(f"Yeni çözülen {len(bs['yeni'])} challenge'ı kanıt zincirine bağla ve raporla.")
    if halted:
        aksiyonlar.append("Kill-switch sebebini incele, temizle ve bounty koşusunu tekrarla.")
    if not aksiyonlar:
        aksiyonlar.append("Rutin izleme (monitor) ile devam et; düzenli yeniden tarama planla.")
    for a in aksiyonlar:
        md.append(f"- [ ] {a}")
    md.append("")
    return "\n".join(md)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="purpleloop.report_hub",
        description="Rol-bazlı rapor üretici (yonetici/denetci/teknik)",
    )
    ap.add_argument("--findings", default="", help="bulgu JSONL dosyası")
    ap.add_argument("--audit", default="", help="audit.jsonl yolu (denetçi raporu için)")
    ap.add_argument("--gate", default="", help="gate durumu: PASS/FAIL (yönetici özeti için)")
    ap.add_argument("--out-dir", default=".", help="çıktı dizini")
    ap.add_argument("--roller", default="yonetici,denetci,teknik",
                    help="virgülle ayrılmış roller: yonetici,denetci,teknik")
    ap.add_argument("--scope", default="scope.json", help="kapsam sözleşmesi JSON yolu")
    ap.add_argument("--bounty", default="",
                    help="bounty koşu sonucu JSON dosyası (BountyHarness.run() çıktısı) — kapak raporu için")
    args = ap.parse_args(argv)

    roller = [r.strip() for r in args.roller.split(",") if r.strip()]
    gecersiz = [r for r in roller if r not in ROLLER]
    if gecersiz:
        ap.error(f"geçersiz rol(ler): {', '.join(gecersiz)} — geçerli: {', '.join(ROLLER)}")

    findings = _load_findings(args.findings)
    os.makedirs(args.out_dir, exist_ok=True)

    gate = {"durum": args.gate or "PASS"}
    if args.gate == "FAIL":
        gate = PolicyGate().evaluate(findings)
    else:
        pg = PolicyGate()
        gate.update({k: v for k, v in pg.evaluate(findings).items() if k != "durum"})

    yazilan = []
    if "yonetici" in roller:
        p = os.path.join(args.out_dir, "rapor_yonetici.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(yonetici_ozeti(findings, gate))
        yazilan.append(p)
    if "denetci" in roller:
        p = os.path.join(args.out_dir, "rapor_denetci.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(denetci_raporu(findings, args.audit, args.scope))
        yazilan.append(p)
    if "teknik" in roller:
        p = os.path.join(args.out_dir, "rapor_teknik.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(teknik_detay(findings))
        yazilan.append(p)

    # kapak raporu: --bounty verilmişse bounty sonucuyla, yoksa sade kapak
    if args.bounty:
        bounty_sonuc = None
        if os.path.exists(args.bounty):
            try:
                with open(args.bounty, "r", encoding="utf-8") as f:
                    bounty_sonuc = json.load(f)
            except json.JSONDecodeError as e:
                ap.error(f"--bounty dosyası geçerli JSON değil: {e}")
        else:
            ap.error(f"--bounty dosyası bulunamadı: {args.bounty}")
        p = os.path.join(args.out_dir, "rapor_kapak.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(executive_summary(findings, bounty_sonuc))
        yazilan.append(p)

    for p in yazilan:
        print(f"yazıldı: {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
