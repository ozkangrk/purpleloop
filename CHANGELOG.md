# Changelog

Tüm önemli değişiklikler bu dosyada belgelenir.
Format [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) uyumlu;
sürümleme [SemVer](https://semver.org/lang/tr/) ile yapılır.

## [2.0.0] - 2026-10-08
### Added
- **Nuclei backend** (`purpleloop.nucleus`): 13.8k şablonlu tarayıcı çift
  scope kapısı arkasında (hedef listesi önceden onaylı + her bulgu tekrar
  doğrulanır; kapsam dışı bulgu NUCLEI_SCOPE_DROP). Finding şemasına
  `nuclei_<severity>` tipli çevirim.
- **White-hat sızma katmanı** (`purpleloop.pentest`): GET-only kimlik aşımı
  denemeleri — auth_anonymous_session, auth_bypass (SPA-fallback FP filtreli),
  path_traversal (passwd imza kanıtı şart), default_login_surface.
- Canlı çapraz kanıt: bilinçli zayıf uygulamada 3 gerçek sızma bulgusu
  (admin bypass + /etc/passwd okuma); sağlam Juice Shop'ta 0 bulgu 0 FP.
- 10 yeni test → 291 passed.

## [1.9.1] - 2026-10-08

## [1.6.0] - 2026-10-08
### Added
- Platform katmanı (`purpleloop.platform_layer`): SARIF 2.1.0 export
  (OWASP security-severity deseni), policy gate (CI exit kararı + kayıtlı
  bypass), OSV.dev zenginleştirme (sızan package.json'dan bilinen CVE).
- Canlı kanıt: sızan /ftp/package.json.bak → 74 bağımlılık → **64 bilinen
  zafiyet** (express, js-yaml, grunt...); taze tarama → gate FAIL/exit 1.
- 10 yeni test → 235 yeşil (canlı OSV sorgusu dahil).

## [1.5.1] - 2026-10-08
### Added
- Aktif problar (`purpleloop.active`): GET-only safe-mode sonda sınıfı —
  `error_disclosure`, `sqli_signature`, `xss_reflection` (temkinli),
  `open_redirect`, `extension_filter_bypass` (%2500 null-byte).
  Her prob scope kapısından geçer; kill-switch her prob başında.
- MCP `scan` aracı artık recon+validator+active tek çağrıda (findings birleşik).
- Juice Shop canlı kanıtı: error_disclosure + Forgotten Developer Backup
  (extension_filter_bypass) bulundu; SQLi/redirect sessiz = FP yok (`evidence/v15_active_probes.log`).
- 7 yeni test → 219 yeşil.

## [1.4.0] - 2026-10-08
### Added
- OWASP Juice Shop v17.3.0 benchmark: GET-recon sınıfında %100 recall, 0 FP,
  0 kapsam ihlali (`evidence/v14_juice_benchmark.log`).
### Fixed (Juice Shop'ta bulunan kök nedenler)
- SPA fallback FP: var olmayan yollara 200 + index gövdesi → `is_spa_fallback()`
  parmak izi filtresi (taban çizgisinde 5 FP vardı → 0).
- `/ftp/` listing'i kaçırma: sunucu Content-Length'ten az gönderip bekliyor;
  RealTransport artık kısmi gövdeyle devam ediyor.
- Header denetimi statik yanıtlardan okuyup VAR olan XFO/XCTO'yu "eksik"
  diyordu; artık ana sayfa yanıtından, host başına tekil.
- Wordlist: OWASP yüzeyleri (ftp/, api-docs/, security.txt, swagger.json) +
  KNOWN_DOC_PATHS (HTML dönen gerçek doküman yüzeyleri).

## [1.3.0] - 2026-10-08
### Added
- MCP server (`purpleloop mcp` / `python3 -m purpleloop.mcp_server`): AI
  agent'lara stdio üzerinden 5 scope-gated araç — status, scope_check, scan,
  killswitch, audit. Kontrol düzlemi değişmedi; server ince sarmalayıcı.
- Kill-switch aktifken server hiç başlamaz (exit 3); scan çağrısında aktifse
  halted=True döner.
- 9 yeni test: FakeTransport uçtan uca + gerçek stdio el sıkışması.

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
