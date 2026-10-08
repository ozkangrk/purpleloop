# Changelog

Tüm önemli değişiklikler bu dosyada belgelenir.
Format [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) uyumludur;
sürümleme [SemVer](https://semver.org/lang/tr/) ile yapılır.

## [0.8.0] - 2026-10-08
### Added
- Sürekli izleme: `purpleloop monitor` — delta tarama (NEW/RESOLVED/UNCHANGED), kritik sızıntı alert'leri (secret/open_bucket NEW → ALERT), kill-switch'li scheduler.
- Benchmark çekirdeği: `purpleloop bench` — lab ground-truth'ye %100 recall, 0 FP, 0 kapsam ihlali; tuzak host reddi kanıtı.
- Recon: açık bucket nesnesi indirme (GET-only) + nginx autoindex tespiti.
- Unified CLI: `monitor` + `bench` alt komutları.

## [0.6.0] — 2026-10-08

İlk ürün paketi: pyproject, birleşik CLI (`purpleloop` / `python3 -m purpleloop`),
CI ve ürün dokümanları. Hafta bazlı geliştirme özetleri aşağıdadır.

### W1 — Çekirdek (core)
- Scope contract: kapsam dışı/belirsiz her durum RED + audit kaydı (fail-closed).
- SHA256 audit zinciri (hash-chained, append-only).
- Kill-switch: anında duruş.
- 147 test tabanının ilk kısmı; `scope`, `audit`, `killswitch` CLI'ları.

### W2 — Recon
- Yetkili keşif modülü: port/endpoint/domain tarama yalnızca kapsam içi hedeflerde.
- Sonuçlar audit zincirine bağlanır.

### W3 — Validator
- Bulgu doğrulama ve şema kontrolü; doğrulanmamış bulgu rapora giremez.

### W4 — Harness
- Kontrol düzlemi ile ajan ayrımı: recon/validator/report ve 3. parti plugin'ler
  değiştirilebilir; scope kapısı, audit, kill-switch harness'e ait.
- `harness` CLI + pipeline orkestrasyonu.

### W5 — Safe-mode exploit
- Kapsam içi, denetlenebilir exploit aşaması (safe-mode); her adım audit'e yazılır.

### W6 — Attack-path + KVKK raporu
- `chainreact`: saldırgan zinciri / attack-path analizi.
- KVKK uyumlu raporlama: bulguların hukuki çerçevesi ve işleme kayıtları.

### Paketleme (bu sürüm)
- Eklendi: `pyproject.toml`, `purpleloop/cli.py`, `purpleloop/__main__.py`,
  `LICENSE`, `CHANGELOG.md`, `ROADMAP.md`, `SECURITY.md`, `.github/workflows/ci.yml`.

[0.6.0]: https://github.com/ozkangrk/purpleloop/releases/tag/v0.6.0
