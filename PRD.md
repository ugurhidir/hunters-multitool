# Hunters-Multitool Ürün Gereksinimleri Dokümanı

## YAPILDI

- [x] Proje iskeletini oluştur (klasör yapısı, temel dosyalar).
- [x] Gerekli kütüphaneleri tanımla (`requirements.txt`).
- [x] Komut satırı arayüzünü (CLI) oluştur (`cli.py`).
- [x] Argüman ayrıştırma işlemini yapılandır.
- [x] Reconnaissance modülünü oluştur (`core/recon.py`).
- [x] Subdomain tespiti fonksiyonunu ekle (DNS zone transfer, brute force, API sorguları).
- [x] API endpoint tespiti fonksiyonunu ekle (robots.txt, sitemap.xml, JS dosyaları analizi).
- [x] JS dosyası bulma fonksiyonunu ekle.
- [x] JS dosyalarını secret key'ler için tarama fonksiyonunu ekle (regex desenleri).
- [x] Google dork taraması fonksiyonunu ekle.
- [x] GitHub dork taraması fonksiyonunu ekle.
- [x] Aktif subdomain kontrolü fonksiyonunu ekle (HTTP istekleri).
- [x] Subdomain takeover tespiti fonksiyonunu ekle (DNS kaydı kontrolü, fingerprinting).
- [x] Zaafiyet tarayıcı modülünü oluştur (`core/scanner.py`).
- [x] SQL Injection tarayıcı fonksiyonunu ekle.
- [x] XSS (Cross-Site Scripting) tarayıcı fonksiyonunu ekle.
- [x] Diğer OWASP Top 10 zaafiyetleri için tarayıcı fonksiyonları ekle (Broken Authentication, Sensitive Data Exposure, vb.).
- [x] Çoklu thread desteğini ekle (`threading`, `queue`).
- [x] Raporlama modülünü oluştur (`core/reports.py`).
- [x] Tarama sonuçlarını raporlama fonksiyonunu ekle (HTML/Markdown formatında).
- [x] Konfigürasyon dosyasını oluştur (`config.py`).
- [x] API anahtarlarını (Shodan, VirusTotal, vb.) konfigürasyon dosyasında saklama desteğini ekle.
- [x] Hata yönetimi mekanizmalarını ekle (`try...except` blokları, loglama).
- [x] İnteraktif komut satırı arayüzünü (inquirer) entegre et.
- [x] Kullanıcıya menü seçenekleri sunma (recon, scan, exit).
- [x] Dork seçeneklerini (Google, GitHub) menüden ayarlanabilir hale getir.
- [x] Rapor çıktısı için dosya adı belirtme seçeneğini ekle.
- [x] Proje belgelerini (README.md) oluştur.
- [x] Lisans bilgisini ekle.

## YAPILACAK