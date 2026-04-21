# Değişiklik Kaydı

## [2.0.0] - 2026-04-22

### Kırılan Değişiklikler
- `X-Auth-Email` / `X-Auth-Key` (Global API Key) **kaldırıldı** → Bearer Token kullanın
- `/user/firewall/access_rules/rules` → `/zones/{zone_id}/firewall/access_rules/rules`
- `config.txt` pattern formatı genişledi: URI, UA:, STATUS: prefix'leri

### Eklenenler
- Bearer Token kimlik doğrulama (güvenli, scoped)
- `UA:` prefix ile User-Agent tabanlı ban
- `STATUS:` prefix ile HTTP durum kodu tabanlı ban
- Tüm pattern'larda ERE (Extended Regular Expression) desteği
- `whitelist.txt` — banlamaması gereken IP listesi
- `--dry-run` modu — Cloudflare'e istek atmadan simüle et
- `--daemon` modu — cron yerine sürekli çalışma, systemd uyumlu
- `--json-log` modu — SIEM uyumlu JSON log çıkışı
- Lock file mekanizması — çakışma önleme
- API retry (3 deneme + rate limit bekleme)
- IPv6 tam destek (CIDR /128 normalizasyonu)
- JSON log format desteği (Nginx json_log)
- `bc` bağımlılığı kaldırıldı — saf bash aritmetiği
- `jq` opsiyonel hale getirildi — grep/sed fallback
- Log rotation güvenli tespiti
- systemd servis dosyası (README'de)
- Cloudflare Real-IP Nginx konfigürasyonu (README'de)

### Düzeltilenler
- `mktemp` sonrası atomic mv ile race condition önlendi
- Boş satır/yorum içeren config.txt satırları artık hata vermiyor
- Bloke kaldırma işleminde kural bulunamazsa hata değil uyarı loglanır

## [1.0.0] - İlk Sürüm
- Cloudflare Global API Key ile IP ban
- Combined log format desteği
- URI düz string pattern eşleme
- line.dat ile log pozisyonu takibi
- 30 dakika ban süresi
