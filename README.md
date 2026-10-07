# PurpleLoop — Hafta 1 + 2 + 3 + 4 (security harness)

Güvenlik ajanı için fail-closed çekirdek + recon + validator + harness.

**İlke: kapsam dışı veya belirsiz her durum = REDDET + audit kaydı. Fail-open yok.**

## Mimari: kontrol düzlemi vs. harness

PurpleLoop bir **security harness**'tir: ajanlar (recon, validator, report,
3. parti plugin'ler) değiştirilebilir parçalardır; kontrol düzlemi
(scope kapısı, SHA256 audit zinciri, kill-switch) harness'e aittir ve
ASLA dışarıdan alınmaz. Dış LLM/harness'ler (vLLM, ollama, LangGraph, ...)
yalnızca danışman adapter'ıyla bağlanır — ağ eylemi yapamaz, verdict DEĞİŞTİREMEZ.

```
┌────────────────────────── Harness ──────────────────────────┐
│  pipeline: recon → validator → report (fail-closed)        │
│  her aşama: kill-switch kontrolü + AGENT_START/END/ERROR    │
│  plugin'ler: 'module:Class' ile yüklenir                   │
│  3. parti ajanlar ağa YALNIZCA ScopeGatedTransport ile     │
└─────────────────────────────────────────────────────────────┘
```

## Kurulum

```bash
cd purpleloop
python3 -m pip install pytest
python3 -m pytest -v            # 131 test
docker compose up -d --wait     # lab: nginx :8081, minio :9010 (public bucket)
```

## Kullanım

```bash
# Hafta-2: tekil recon
python3 -m purpleloop.recon --scope scope.json --out findings.jsonl \
  --hosts 127.0.0.1 --endpoints 127.0.0.1:8081,127.0.0.1:9010

# Hafta-3: bulgu doğrulama (deterministik replay; LLM opsiyonel danışman)
python3 -m purpleloop.validator --scope scope.json \
  --findings findings.jsonl --out findings-validated.jsonl \
  [--llm-endpoint http://localhost:11434/v1]   # verdict'e etkisi YOKTUR

# Hafta-4: tam pipeline (harness)
python3 -m purpleloop.harness --scope scope.json --out-dir run1 \
  --pipeline recon,validator,report \
  --hosts 127.0.0.1 --endpoints 127.0.0.1:8081,127.0.0.1:9010 \
  [--plugin mypkg.agents:BenimAjanim]         # 3. parti ajan takma
```

Çıktılar (`run1/`): `findings.jsonl`, `findings-validated.jsonl`,
`report.md` (önem sıralı, doğrulama durumlu), `audit.jsonl` (zincir).

## Bileşenler

| Modül | İş | Hafta |
|---|---|---|
| `scope.py` | allow-list sözleşme; her istek öncesi kapı | 1 |
| `audit.py` | SHA256 hash-zincirli append-only JSONL | 1 |
| `killswitch.py` | dosya-tabanlı stop; OSError = aktif | 1 |
| `recon.py` | port/dizin/bucket/parola taraması, CLI | 2 |
| `validator.py` | bulgu başına deterministik re-doğrulama | 3 |
| `harness.py` | ajan kayısı + pipeline + plugin + gated transport | 4 |

### Scope contract (`purpleloop/scope.py`)
JSON sözleşme; her istek öncesi `check_request(host, port, method, now)` → `(allowed, reason)`.
Geçersiz/eksik sözleşme → `ScopeError`. Sonek hilesi (`notexample.com`) → REDDET.
50 fixture'ın 50'si doğru karar (`tests/test_scope.py`).

### Audit log (`purpleloop/audit.py`)
Append-only JSONL; `prev_sha256` + `sha256` zinciri. Değiştirilen/silinen/eklenen satır → `AuditTamperError`.

### Kill switch (`purpleloop/killswitch.py`)
Dosya varsa ajan durur. Durum okunamazsa (OSError) **aktif** sayılır (fail-closed).

### Lab (`docker-compose.yml`)
- `nginx-misconfigured` → `localhost:8081` (autoindex açık, sahte cred'ler `/backup/` + `secrets-old.txt`'de 3 sahte parola)
- `minio-s3` → `localhost:9010` (S3-benzeri; cred: `purplelab` / `purplelab-secret`; `public` bucket'ı anonim listelemeye açık, içinde sahte cred dosyası; `minio-init` hazırlar)

## Test kanıtı
- Hafta-1: 97 passed (`evidence/first_run.log`)
- Hafta-2: 109 passed (`evidence/week2_run.log`) — 12 gerçek bulgu, 0 FP, kapsam dışı 203.0.113.99 → 17 SCOPE_DENY, hiç taranmadı
- Hafta-3: 121 passed (`evidence/week3_run.log`) — 12/12 bulgu CONFIRMED (deterministik replay)
- Hafta-4: 131 passed; canlı pipeline `evidence/run-week4/` — recon→validator→report uçtan uca, 12 bulgu, zincir geçerli

## Fikir kuyruğu
Bkz. `IDEAS.md` — EMA-Lightning deseni (niş+küçük+ölçülmüş+pip ürünü),
GOAD benchmark, FP-sınıflandırıcı tiny-model, Türkçe uyumluluk raporu.
