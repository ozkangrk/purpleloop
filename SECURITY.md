# Güvenlik Politikası — Security Policy

## ⚠️ Kullanım uyarısı
PurpleLoop yalnızca **sahibi olduğunuz veya yazılı test izni verdiğiniz**
sistemlerde kullanım içindir. İzinsiz sistemlerde kullanım yasa dışıdır ve
bu projenin amacına aykırıdır. Kapsam dışı veya belirsiz her durum
fail-closed ilkesi gereği reddedilir ve audit kaydına geçer.

## Desteklenen sürümler
| Sürüm | Destek |
|-------|--------|
| 0.6.x | ✔ |

## Güvenlik açığı bildirimi (responsible disclosure)
1. Lütfen güvenlik açıklarını **özel** olarak bildirin; public issue açmayın.
2. İletişim: GitHub üzerinde bu repodaki **Security Advisories**
   ("Report a vulnerability") kullanın; mümkün değilse repo sahibine
   GitHub üzerinden DM/issue aracılığıyla ulaşın.
3. Bildiriminize şunları ekleyin: etkilenen modül/sürüm, yeniden üretim
   adımları, etki değerlendirmesi.
4. Açığı doğrulamak için **yalnızca kendi lab ortamınızda / izinli
   sistemlerde** test yapın; başkalarının sistemlerinde PoC çalıştırmayın.
5. Bildirimler 90 gün içinde yanıtlanır; çözüm sonrası advisory
   yayınlanır ve CHANGELOG'a işlenir. Koordineli açıklamaya uyun;
   düzeltme öncesi detay ifşa etmeyin.

## Kapsam
Projenin kendi kodundaki güvenlik sorunları (scope bypass, audit zinciri
bozulması, fail-open davranış) önceliklidir.
