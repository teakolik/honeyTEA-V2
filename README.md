# honeyTEA v2

Cloudflare + Web Sunucu Log Analizi ile Otomatik IP Honeypot & Ban Sistemi
Sadırganları kekleyin!

---

## Nasıl Çalışır?

honeyTEA, web sunucunuzun access log dosyasını okur. `config.txt` içindeki pattern'larla eşleşen kötü niyetli istekleri (WordPress açıklarını arayan tarayıcılar, webshell denemeleri, veritabanı dosyalarına erişim girişimleri, kötü User-Agent'lar vb.) tespit eder. Tespit ettiği IP adreslerini Cloudflare API üzerinden otomatik olarak banlar. Belirlenen süre (varsayılan: 90 dakika) sonunda banı otomatik kaldırır.

Sunucunuz Cloudflare arkasındaysa iptables/firewalld ban işe yaramaz — çünkü sunucunuza gelen istek Cloudflare'den gelir. honeyTEA bu sorunu çözer: engelleme Cloudflare katmanında yapılır, kötü IP sunucunuza hiç ulaşamaz.

---

## Gereksinimler

- Bash 4.0+
- `curl`
- `awk`, `grep`, `sed` (tüm sistemlerde mevcut)
- `jq` — opsiyonel
- Cloudflare hesabı (ücretsiz plan yeterli)
- Nginx veya Apache (`mod_cloudflare` veya `ngx_http_realip_module` kurulu olması önerilir)

---

## Kurulum

### 1. Cloudflare API Token Oluşturun

1. [Cloudflare Dashboard](https://dash.cloudflare.com) → **My Profile** → **API Tokens** → **Create Token**
2. **Custom Token** seçin
3. İzinler:
   - `Zone > Firewall Services > Edit`
   - `Zone > Zone > Read`
4. Zone filtresini ilgili domain ile sınırlandırın

> **Neden Global API Key değil?** Global key tüm hesabınıza tam erişim sağlar. Token ele geçirilse tüm hesabınız tehlikede. Scoped token sadece gerekli izinlere sahiptir, expire edilebilir ve iptal edilebilir.

### 2. Dosyaları Kopyalayın

```bash
mkdir -p /etc/honeytea
cp honeyTEA.sh config.txt whitelist.txt /etc/honeytea/
chmod +x /etc/honeytea/honeyTEA.sh
```

### 3. honeyTEA.sh'ı Yapılandırın

```bash
nano /etc/honeytea/honeyTEA.sh
```

Doldurulması gereken değerler:

```bash
CF_TOKEN="ey..."           # Cloudflare API Token
CF_ZONE_ID="a1b2c3..."     # Zone ID
BANNED_TIME=90             # Dakika cinsinden ban süresi
CF_ACTION="block"          # block | challenge | managed_challenge
LOG_FILE="/var/log/nginx/access.log"
LOG_FORMAT="combined"      # combined | json
```

### 4. Nginx Real-IP Modülü (Cloudflare Arkasındaysanız)

Ziyaretçinin gerçek IP'sini görmek için Nginx'e Cloudflare IP aralıklarını tanıtın:

```nginx
# /etc/nginx/conf.d/cloudflare-realip.conf
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
real_ip_header CF-Connecting-IP;
```

```bash
nginx -t && systemctl reload nginx
```

### 5. Crontab veya Daemon Modu

**Crontab (5 dakikada bir):**
```bash
crontab -e
# Ekleyin:
*/5 * * * * /etc/honeytea/honeyTEA.sh /etc/honeytea/config.txt >> /dev/null 2>&1
```

**Daemon modu (systemd servis):**
```bash
# /etc/systemd/system/honeytea.service
[Unit]
Description=honeyTEA Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/etc/honeytea/honeyTEA.sh --daemon /etc/honeytea/config.txt
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload
systemctl enable --now honeytea
```

---

## config.txt Pattern Formatı

```
# URI pattern (regex)
/wp-config\.php
URI:/admin/

# User-Agent pattern (regex, büyük/küçük harf duyarsız)
UA:sqlmap
UA:nikto

# HTTP Durum Kodu
STATUS:404
```

Tüm pattern'lar Extended Regular Expression (ERE) kullanır.

---

## Komut Satırı Parametreleri

```bash
# Normal çalıştırma
./honeyTEA.sh config.txt

# Cloudflare'e istek atmadan test et
./honeyTEA.sh --dry-run config.txt

# Sürekli çalışma modu (300 saniye aralık)
./honeyTEA.sh --daemon config.txt

# SIEM uyumlu JSON log çıkışı
./honeyTEA.sh --json-log config.txt

# Kombine
./honeyTEA.sh --dry-run --json-log config.txt
```

---

## Log Çıktısı

```
2026-04-22T14:35:01+0300 [INFO] honeyTEA: honeyTEA v2.0 başlatıldı | Config: config.txt | Log: /var/log/nginx/access.log
2026-04-22T14:35:02+0300 [INFO] honeyTEA: Log işleniyor | Dosya: /var/log/nginx/access.log | Yeni satır: 142
2026-04-22T14:35:02+0300 [INFO] honeyTEA: Honeypot tetiklendi | IP: 203.0.113.42 | URI: /wp-config.php | Status: 404
2026-04-22T14:35:03+0300 [INFO] honeyTEA: Bloke eklendi | IP: 203.0.113.42 | Aksiyon: block | Kural: abc123
2026-04-22T14:35:10+0300 [INFO] honeyTEA: Süre doldu, bloke kaldırılıyor | IP: 198.51.100.7 | Geçen: 5423s
```

---

## Whitelist Kullanımı

`whitelist.txt` dosyasına banlamamasını istediğiniz IP'leri ekleyin:

```
# Ofis IP
85.123.45.67

# Monitoring servisi
216.144.250.150
```

---

## Güvenlik Notları

- API Token'ı script içine yazmak yerine `/etc/honeytea/.credentials` dosyasında saklayabilir, `source` ile yükleyebilirsiniz (chmod 600)
- `whitelist.txt`'e Cloudflare health check IP'lerini ve kendi ofis IP'nizi eklemeyi unutmayın
- Dry-run ile önce test yapın, production'da aktif edin

---

## Yazar

**Hamza Şamlıoğlu**  
GitHub: [@teakolik](https://github.com/teakolik)  
LinkedIn: [linkedin.com/in/teakolik](https://www.linkedin.com/in/teakolik/)
