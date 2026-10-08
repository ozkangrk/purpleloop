"""Remediation bilgi tabanı — bulgu tipi → somut düzeltme önerisi.

Her öneri: başlık, neden (risk), düzeltme adımları, OWASP referansı,
doğrulama yöntemi (düzeltildikten sonra nasıl test edilir).
"""
from __future__ import annotations

REMEDIATION_DB = {
    "sqli_data_leak": {
        "baslik": "SQL Enjeksiyonu ile Veri Sızıntısı",
        "risk": "Saldırgan veritabanındaki tüm tabloları okuyabilir (kanıt: {kanit}).",
        "adimlar": [
            "Tüm sorgularda parametreli sorgu / prepared statement kullan (ORM veya paramIKE).",
            "Kullanıcı girdisini SQL'e dizme (string concatenation) YASAK — kod taraması ekle.",
            "Veritabanı kullanıcısına yalnız gerekli yetkiler (least privilege); DROP/DELETE yetkisi verme.",
            "Hata mesajlarını maskele (ayrıntılı SQL hatası istemciye dönmesin).",
            "WAF/IDS ile 'union select' imzalarını izle (savunma derinliği).",
        ],
        "owasp": "A03:2021 – Injection",
        "dogrulama": "Aynı UNION payload'ı 400/boş dönmeli; error-based sorgular detay ifşa etmemeli.",
    },
    "sqli_signature": {
        "baslik": "SQL Enjeksiyonu İmzası (Hata Ifşası)",
        "risk": "Veritabanı hata mesajları sızıyor — şema keşfine olanak verir. Kanıt: {kanit}",
        "adimlar": [
            "Genel hata sayfası döndür; sürücü hatalarını log'a yaz, istemciye yansıtma.",
            "Parametreli sorgulara geç (kök neden).",
        ],
        "owasp": "A03:2021 – Injection",
        "dogrulama": "Geçersiz girdide 500 + stack trace yerine 400 + genel mesaj dönmeli.",
    },
    "auth_bypass": {
        "baslik": "Kimlik Doğrulama Atlatma",
        "risk": "Korunan kaynağa kimlik doğrulamadan erişilebiliyor: {kanit}",
        "adimlar": [
            "Yetkilendirme kontrolünü merkezi middleware'e taşı (her endpoint'te ayrı kontrol hataya açık).",
            "Deny-by-default: yol listede yoksa 403.",
            "Endpoint bazlı rol matrisi tanımla ve test et.",
            "Kimlik doğrulama çerezlerini HttpOnly+Secure+SameSite ile yayınla.",
        ],
        "owasp": "A01:2021 – Broken Access Control",
        "dogrulama": "Oturumsuz istek korunan tüm yollarda 401/403 dönmeli.",
    },
    "idor": {
        "baslik": "IDOR — Yatay Yetki Aşımı",
        "risk": "Başka kullanıcının kaynağı nesne kimliğiyle okunabiliyor: {kanit}",
        "adimlar": [
            "Nesne erişiminde sahiplik kontrolü: kayıt kullanıcıya ait mi?",
            "Tahmin edilemez nesne kimliği (UUID) — sıralı ID kullanma.",
            "Yetkilendirme testlerini CI'a ekle (her rol x her endpoint matrisi).",
        ],
        "owasp": "A01:2021 – Broken Access Control",
        "dogrulama": "Kullanıcı A, kullanıcı B'nin kaynak kimliğiyle istek attığında 403 almalı.",
    },
    "path_traversal": {
        "baslik": "Dizin Geçişi (Path Traversal)",
        "risk": "Sunucudan keyfi dosya okunabiliyor: {kanit}",
        "adimlar": [
            "Dosya yollarını normalleştir (realpath) ve kök dizin altına hapsed.",
            "Dosya adları için allowlist; '../' ve null-byte girdilerini reddet.",
            "Statik dosyaları uygulama sürecinden ayrı, salt-okunur sun.",
        ],
        "owasp": "A01:2021 – Broken Access Control",
        "dogrulama": "'../../etc/passwd' ve null-byte varyantları 400/403 dönmeli.",
    },
    "extension_filter_bypass": {
        "baslik": "Uzantı Filtresi Atlatma (Null Byte)",
        "risk": "Yasaklı dosyalar null-byte ile okunabiliyor: {kanit}",
        "adimlar": [
            "Yol işlendikten SONRA uzantı kontrolü yap (önce değil).",
            "Null-byte içeren girdileri girişte reddet.",
            "Dosya sunumunu allowlist ile sınırla (yalnız .md/.pdf gibi).",
        ],
        "owasp": "A05:2021 – Security Misconfiguration",
        "dogrulama": "%2500 varyantları da dahil tüm bypass denemeleri 403 dönmeli.",
    },
    "auth_anonymous_session": {
        "baslik": "Kimliksiz Oturum Verisi",
        "risk": "Oturum açmadan kullanıcı verisi sızıyor: {kanit}",
        "adimlar": [
            "whoami benzeri endpoint'lerde oturum zorunlu; anonim yanıtta yalnız 'anonymous' dönsün.",
            "Hassas alanları (kart, e-posta) yanıt şemasından çıkar (need-to-know).",
        ],
        "owasp": "A01:2021 – Broken Access Control",
        "dogrulama": "Oturumsuz istekte kullanıcıya ait alanlar boş olmalı.",
    },
    "jwt_alg_none": {
        "baslik": "JWT alg:none Zayıflığı",
        "risk": "Token imzasız algoritma kabul ediliyor — sahte token üretilebilir. Kanıt: {kanit}",
        "adimlar": [
            "İzinli algoritma listesi sunucu tarafında sabit (HS256/RS256).",
            "alg header'ını istemciden alma; kitaplık seviyesinde doğrula.",
            "Token süresi (exp) ve issuer kontrolü zorunlu.",
        ],
        "owasp": "A02:2021 – Cryptographic Failures",
        "dogrulama": "alg:none token 401 dönmeli.",
    },
    "xss_reflection": {
        "baslik": "Yansıyan XSS",
        "risk": "Kullanıcı girdisi HTML'e kodlanmadan yansıyor: {kanit}",
        "adimlar": [
            "Çıktı kodlama: HTML bağlamında &lt; &gt; &amp; escape.",
            "CSP başlığı ekle (inline script engeli).",
            "Girdi doğrulama allowlist ile (blacklist değil).",
        ],
        "owasp": "A03:2021 – Injection",
        "dogrulama": "<script> girdisi kodlanmış dönmeli; CSP raporu tetiklenmemeli.",
    },
    "open_redirect": {
        "baslik": "Açık Yönlendirme",
        "risk": "Dış URL'e yönlendirme parametreyle kontrol edilebiliyor. Kanıt: {kanit}",
        "adimlar": [
            "Yönlendirme hedefleri allowlist; dış URL yasak.",
            "Kullanıcıya açık ara sayfa ('dış siteye gidiyorsunuz') koy.",
        ],
        "owasp": "A01:2021 – Broken Access Control",
        "dogrulama": "to=external 400 dönmeli; yalnız allowlist 302.",
    },
    "secret": {
        "baslik": "Sızan Kimlik Bilgisi",
        "risk": "Parola/anahtar yanıt gövdesinde görünüyor: {kanit}",
        "adimlar": [
            "Sızıntı kaynağını kaldır (dosya/environment yanıtına karışmasın).",
            "Sızan kimlik bilgilerini ROTATE et (geçersiz kıl).",
            "Secret taramasını CI'a ekle (gitleaks benzeri).",
        ],
        "owasp": "A02:2021 – Cryptographic Failures",
        "dogrulama": "Aynı yol artık kimlik bilgisi içermemeli; eski kimlik bilgisi reddedilmeli.",
    },
    "directory": {
        "baslik": "Açık Dizin / Hassas Dosya",
        "risk": "Dizin listeleme veya hassas dosya erişime açık: {kanit}",
        "adimlar": [
            "Autoindex kapat; yedek/manifest dosyalarını web kökünden kaldır.",
            "Erişilmemesi gereken yollar için 403 kuralı.",
        ],
        "owasp": "A05:2021 – Security Misconfiguration",
        "dogrulama": "Dizin listesi 403; yedek dosyalar 404.",
    },
    "error_disclosure": {
        "baslik": "Hata Mesajı Ifşası",
        "risk": "Stack trace/sürücü detayı sızıyor: {kanit}",
        "adimlar": [
            "Üretimde debug sayfaları kapat (Django DEBUG=False vb.).",
            "Genel hata yanıtı; detay yalnız sunucu log'unda.",
        ],
        "owasp": "A05:2021 – Security Misconfiguration",
        "dogrulama": "Hatalı istek stack trace döndürmemeli.",
    },
    "missing_header": {
        "baslik": "Eksik Güvenlik Başlığı",
        "risk": "CSP/HSTS başlığı yok. Kanıt: {kanit}",
        "adimlar": [
            "Content-Security-Policy ekle (nonce-tabanlı önerilir).",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            "Başlık kontrolünü CI'a ekle (securityheaders.com A derece hedefle).",
        ],
        "owasp": "A05:2021 – Security Misconfiguration",
        "dogrulama": "Başlık kontrolü A/A+ dönmeli.",
    },
    "bounty_solve": {
        "baslik": "Skorboard-Doğrulanmış Sömürü",
        "risk": "Zincir, hedefin kendi doğrulayıcısı tarafından onaylandı: {kanit}",
        "adimlar": [
            "İlgili challenge kategorisinin kök nedenine in (bkz. diğer bulgular).",
            "Regresyon testine ekle: aynı exploit artık çözememeli.",
        ],
        "owasp": "Çeşitli",
        "dogrulama": "Aynı vektör tekrar koşulduğunda skorboard 'solved' artmamalı.",
    },
    "agent_probe_leak": {
        "baslik": "Ajan Sondajından Kanıtlı Sızıntı",
        "risk": "Ajan önerisiyle kanıtlandı: {kanit}",
        "adimlar": [
            "İlgili parametrenin girdi doğrulamasını katılaştır.",
            "Sızıntı imzasını (e-posta/karma düzeni) çıktı filtresinde engelle.",
        ],
        "owasp": "A03:2021 – Injection",
        "dogrulama": "Aynı sondaj imza döndürmemeli.",
    },
    "nuclei_critical": {
        "baslik": "Nuclei: Kritik Bilinen Zafiyet",
        "risk": "Bilinen şablon eşleşmesi: {kanit}",
        "adimlar": [
            "İlgili bileşeni yamalı sürüme yükselt.",
            "Geçici azaltım: WAF kuralı / özellik kapatma.",
        ],
        "owasp": "A06:2021 – Vulnerable and Outdated Components",
        "dogrulama": "Aynı nuclei şablonu tekrar eşleşmemeli.",
    },
}


def get_remediation(tip: str, kanit: str = "") -> dict:
    """Bulgu tipi için düzeltme önerisi; risk alanına kanıt gömülür."""
    r = dict(REMEDIATION_DB.get(tip) or {
        "baslik": tip,
        "risk": "Bulgu: {kanit}",
        "adimlar": ["Kök neden analiz edin ve düzeltin."],
        "owasp": "-",
        "dogrulama": "Bulgu tekrar üretilmemeli.",
    })
    r["risk"] = r["risk"].format(kanit=kanit[:200])
    return r
