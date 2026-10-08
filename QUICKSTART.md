# PurpleLoop Quickstart — 5 dakikada ilk değer

```bash
pip install -e .            # ya da: git clone + python3 -m purpleloop
```

## 1) Hemen dene (kurulum yok, risk yok)

```bash
purpleloop demo
```

Tek komut: izole zayıf lab ayağa kaldırır → kapsam sözleşmesi yazar →
tuzak hedefin reddini KANITLAR → recon + sızma denemeleri + vektör
kütüphanesini koşturur → SARIF üretir → **policy gate FAIL/exit-1 ile
biter** (3 error: kimlik aşımı, /etc/passwd okuma, IDOR). Çıktılar:
`~/purpleloop-demo/`.

## 2) Gerçek hedefe geç (izinli sistem!)

```bash
purpleloop init                      # scope.json şablonu + rehber
$EDITOR scope.json                   # targets/ports/methods = İZİN VERDİKLERİN
purpleloop scan --scope scope.json --hosts HEDEF \
    --endpoints HEDEF:PORT --out-dir run1
purpleloop pentest --scope scope.json --targets HEDEF:PORT \
    --out-dir pt1 --killswitch KILLSWITCH
purpleloop platform gate --findings run1/findings.jsonl   # CI exit kodu
```

**Fail-closed kuralı:** scope.json'da OLMAYAN her hedef REDDEDİLİR ve
reddi audit zincirine yazılır. Kill-switch dosyası varsa her şey durur.

## 3) CI'a koy

`.github/workflows/security-gate.yml` hazır: pytest → lab → tarama →
SARIF → gate (FAIL = pipeline bloke) → GitHub Code Scanning'e yükleme.

## 4) Ajanına bağla (MCP)

```python
from purpleloop.mcp_client import PurpleLoopClient
with PurpleLoopClient(scope_path="scope.json", out_dir="mcp-run") as pl:
    pl.scope_check("HEDEF", PORT)      # izinli mi? değilse RED
    pl.scan(["HEDEF"], ["HEDEF:PORT"]) # bulgular
    pl.campaign(...); pl.gate("mcp-run/campaign")
```

## 5) Sürekli izle

```bash
purpleloop monitor --scope scope.json --state mon.json --audit mon-audit.jsonl
```

---
Tüm bulgular sabit şemada `{tip, hedef, kanit, zaman_damgasi,
kapsam_referansi}`; her adım SHA256 audit zincirinde; raporlar:
`purpleloop platform/report_hub` (yönetici/denetçi/teknik/kapak).
