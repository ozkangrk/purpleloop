# PurpleLoop Güvenlik Değerlendirmesi — Yönetim Raporu

- Rapor tarihi: 2026-10-08T04:35:10+00:00
- Değerlendirilen kapsam: 127.0.0.1, 10.10.0.0/16, *.example.com
- Toplam bulgu: 12 | Doğrulanmış: 12 | Safe-mode kanıtlanmış sömürü: 1
- Tespit edilen saldırı zinciri: 3
- Metodoloji: kapsam sözleşmeli fail-closed tarama; her bulgu bağımsız yeniden doğrulama (deterministik replay) ve SHA256 hash-zincirli audit kaydı ile desteklenir.

## 1. Yönetici Özeti
Değerlendirme kapsamında 3 çok adımlı saldırı zinciri tespit edildi; bunlardan 1 tanesi safe-mode exploit kanıtıyla doğrulandı. En kritik zincir(ler):
- **[YÜKSEK] Sızan kimlik bilgisi → herkese açık bucket → veri erişimi** — 7 adım
- **[YÜKSEK] Açık dizin listeleme → hassas dosya ifşası** — 9 adım
- **[ORTA] Erişilebilir S3 API → anonim bucket okuma** — 2 adım

Aşağıdaki bulgular kanıt zinciriyle desteklenmiştir; her satırın dayanağı audit.log içinde "FINDING/VALIDATION/EXPLOIT_PROOF" kayıtlarıdır ve zincir bütünlüğü doğrulanmıştır.

## 2. Bulgular ve Uyumluluk Eşlemesi

| # | Önem | Bulgu | Hedef | Doğrulama | Düzenleyici eşleme |
|---|------|-------|-------|-----------|---------------------|
| 1 | ORTA | secret | 127.0.0.1:8081/backup/.env | CONFIRMED +EXPLOITED | Kişisel veri güvenliği (KVKK m.12, m.19) — kimlik bilgisi ifşası; ISO 27001 A.9.4.4; SOC 2 CC6.1 |
| 2 | ORTA | secret | 127.0.0.1:8081/backup/.aws-credentials | CONFIRMED | Kişisel veri güvenliği (KVKK m.12, m.19) — kimlik bilgisi ifşası; ISO 27001 A.9.4.4; SOC 2 CC6.1 |
| 3 | ORTA | secret | 127.0.0.1:8081/backup/secrets-old.txt | CONFIRMED | Kişisel veri güvenliği (KVKK m.12, m.19) — kimlik bilgisi ifşası; ISO 27001 A.9.4.4; SOC 2 CC6.1 |
| 4 | ORTA | secret | 127.0.0.1:8081/backup/secrets-old.txt | CONFIRMED | Kişisel veri güvenliği (KVKK m.12, m.19) — kimlik bilgisi ifşası; ISO 27001 A.9.4.4; SOC 2 CC6.1 |
| 5 | ORTA | secret | 127.0.0.1:8081/backup/secrets-old.txt | CONFIRMED | Kişisel veri güvenliği (KVKK m.12, m.19) — kimlik bilgisi ifşası; ISO 27001 A.9.4.4; SOC 2 CC6.1 |
| 6 | ORTA | open_bucket | 127.0.0.1:9010/public/ | CONFIRMED | Veri envanteri ve erişim kontrolü (KVKK m.12/VERBİS bağlantılı) — halka açık depolama; ISO 27001 A.9.1.1; SOC 2 CC6.3 |
| 7 | DÜŞÜK | directory | 127.0.0.1:8081/backup/.env | CONFIRMED +EXPLOITED | Erişim kontrolü ve sistem güvenirliği — ISO 27001 A.9.4.5; SOC 2 CC6.6 |
| 8 | DÜŞÜK | directory | 127.0.0.1:8081/backup/.aws-credentials | CONFIRMED | Erişim kontrolü ve sistem güvenirliği — ISO 27001 A.9.4.5; SOC 2 CC6.6 |
| 9 | DÜŞÜK | directory | 127.0.0.1:8081/backup/secrets-old.txt | CONFIRMED | Erişim kontrolü ve sistem güvenirliği — ISO 27001 A.9.4.5; SOC 2 CC6.6 |
| 10 | DÜŞÜK | bucket_service | 127.0.0.1:9010 | CONFIRMED | Ağ servis yönetimi — ISO 27001 A.13.5.1 |
| 11 | DÜŞÜK | open_port | 127.0.0.1:8081 | CONFIRMED | Ağ güvenliği yönetimi — ISO 27001 A.13.6.2 |
| 12 | DÜŞÜK | open_port | 127.0.0.1:9010 | CONFIRMED | Ağ güvenliği yönetimi — ISO 27001 A.13.6.2 |

## 3. Saldırı Zincirleri
### Sızan kimlik bilgisi → herkese açık bucket → veri erişimi (`leaked-creds-to-open-bucket`, önem: YÜKSEK)
1. **secret** — `127.0.0.1:8081/backup/.env` — _ROOT_PASSWORD=purplelab-secret
2. **exploit_proof** — `127.0.0.1:8081/backup/.env` — safe-mode kanıt: EXPLOITED
2. **secret** — `127.0.0.1:8081/backup/.aws-credentials` — AWS_SECRET_ACCESS_KEY=purplelab-secret
3. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _password=PurpleL00p!Lab-2026
4. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _pwd=S3cret-Backdoor-Passw0rd
5. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _token=ghp_purpleloopFAKEtoken1234567890
7. **open_bucket** — `127.0.0.1:9010/public/` — anonymous list allowed (HTTP 200, len=567)

### Açık dizin listeleme → hassas dosya ifşası (`open-directory-to-secret`, önem: YÜKSEK)
1. **directory** — `127.0.0.1:8081/backup/.env` — HTTP 200 len=63
2. **exploit_proof** — `127.0.0.1:8081/backup/.env` — safe-mode kanıt: EXPLOITED
2. **directory** — `127.0.0.1:8081/backup/.aws-credentials` — HTTP 200 len=67
3. **directory** — `127.0.0.1:8081/backup/secrets-old.txt` — HTTP 200 len=174
5. **secret** — `127.0.0.1:8081/backup/.env` — _ROOT_PASSWORD=purplelab-secret
6. **secret** — `127.0.0.1:8081/backup/.aws-credentials` — AWS_SECRET_ACCESS_KEY=purplelab-secret
7. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _password=PurpleL00p!Lab-2026
8. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _pwd=S3cret-Backdoor-Passw0rd
9. **secret** — `127.0.0.1:8081/backup/secrets-old.txt` — _token=ghp_purpleloopFAKEtoken1234567890

### Erişilebilir S3 API → anonim bucket okuma (`exposed-service-to-bucket`, önem: ORTA)
1. **bucket_service** — `127.0.0.1:9010` — S3-like API exposed (HTTP 403)
2. **open_bucket** — `127.0.0.1:9010/public/` — anonymous list allowed (HTTP 200, len=567)

## 4. Öneriler
1. Sızan tüm kimlik bilgileri derhal rotasyonlanmalı (KVKK m.12 gereği veri güvenliği tedbiri).
2. Açık dizin listeleme ve `/backup/` erişimi kapatılmalı; web root dışına taşınmalı.
3. Public bucket anonim politakası kaldırılmalı; en azından kimlik doğrulamalı okumaya geçilmeli.
4. Bulgular giderildikten sonra PurpleLoop ile yeniden tarama yapılıp kapanış kanıtı üretilmesi önerilir (delta raporu).

## 5. Kanıt Zinciri Beyanı
Bu rapor, değiştirilemezliği SHA256 hash zinciriyle sağlanan audit kaydından üretilmiştir. `AuditLog.verify_chain()` bu raporun üretildiği anda başarılıdır; herhangi bir satır değişirse zincir kırılır.
