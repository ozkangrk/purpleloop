# PurpleLoop — Fikir Kuyruğu (yalnızca güvenlik işi)

Önceliklendirme: P0 = şimdi, P1 = sıradaki hafta, P2 = backlog.
(Karar: ses/TTS fikirleri proje DIŞI — bu dosyada güvenlik işi var.)

---

## P0 — Devam eden
- [x] Hafta 1-4 çekirdek: scope + audit zinciri + kill-switch + recon +
      validator + harness (131 test yeşil, canlı lab kanıtlı)
- [ ] Hafta-5: safe-mode exploit doğrulama (detay: ROADMAP.md)

## P1 — Ürünleşme (detay: ROADMAP.md)
1. Saldırı yolu grafiği: bulguları birleştirip zincir kanıtı
   ("sızan parola → bucket erişimi → yetki yükseltme")
2. Türkçe uyumluluk raporu: findings → KVKK / ISO 27001 / SOC 2 şablonu
3. GOAD benchmark: bulunma/kaçırma/scope-ihlali metrikleriyle tablo
4. LLM danışman entegrasyonu (Gemini API veya DGX'te lokal vLLM):
   triage + rapor özetleme — verdict'e etkisi YOK
5. `pip install purpleloop` + herkese açık GitHub repo + doküman seti

## P2 — Backlog
6. FP-sınıflandırıcı mini model: validator etiketleriyle beslenen küçük
   sınıflandırıcı (hedef FP < %1)
7. MCP/A2A dışa açılım: purpleloop-core bağımsız scope-gate kütüphanesi/servisi
8. Sürekli tarama modu: cron'lu delta tarama + değişim alert'i
9. Ticarileşme: self-hosted ücretsiz (Apache-2.0) + managed/destekli ücretli

---
Karar günlüğü:
- 2026-10-07: TTS/ses fikirleri kuyruktan ÇIKARILDI (proje dışı, ekstra not).
- 2026-10-07: LLM kullanım kararı: yalnızca danışman adapter (Gemini/vLLM);
  verdict ve ağ eylemi kontrol düzleminde kalır.
- 2026-10-07: LLM trading bot (Opus+Minara tarzı) BAĞIMSIZ PROJE OLARAK
  REDDEDİLDİ: gerçek para + kanıtlanmamış edge + affiliate funnel; desen
  (model önerir/kontrol düzlemi onaylar) PurpleLoop'ta zaten uygulanıyor.
  Olası yarı-bağımsız kol: purpleloop-core'u genel "agent güvenlik harness'i"
  kütüphanesi olarak ayırmak (P2/7 ile aynı).
