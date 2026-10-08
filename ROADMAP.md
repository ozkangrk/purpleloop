# PurpleLoop Roadmap

Vizyon: izinli sızma testleri için **fail-closed**, denetlenebilir ve
kurumsal raporlayabilen bir güvenlik harness'i.

## v0.7 — GOAD benchmark
- GOAD lab ortamında uçtan uca koşu; yayınlanmış metrik tablosu
  (bulgu doğruluk, kapsam ihlali = 0, çalışma süresi).

## v0.8 — Continuous scanning
- Cron tabanlı zamanlanmış taramalar; delta raporlama
  (yalnızca değişen bulgular).

## v0.9 — pip release + docs
- PyPI'de `pip install purpleloop`; docs sitesi (kullanım, kapsam sözleşmesi
  şeması, plugin API'si).

## v1.0 — Beta
- Çoklu hedef / çoklu proje yönetimi.
- Rol bazlı raporlar (yönetici özeti, teknik detay, KVKK ekleri).

## v1.x sonrası
- Managed/hosted sürüş (SaaS).
- MCP / A2A entegrasyonu (ajanlar arası standart protokol).
- Kurumsal destek paketleri ve eğitim.
