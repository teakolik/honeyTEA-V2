#!/usr/bin/env bash
# =============================================================================
#  honeyTEA v2.0 — Cloudflare Honeypot & Otomatik IP Ban Sistemi
# =============================================================================
#  Yazar   : Hamza Şamlıoğlu <hamza@priviasecurity.com>
#  Site    : https://priviasecurity.com
#  GitHub  : https://github.com/teakolik
# =============================================================================
# KURULUM
# =============================================================================
#
#  1) Dosyaları kopyalayın:
#       mkdir -p /etc/honeytea
#       cp honeyTEA.sh config.txt whitelist.txt /etc/honeytea/
#       chmod +x /etc/honeytea/honeyTEA.sh
#
#  2) Cloudflare API Token oluşturun:
#       Dashboard → My Profile → API Tokens → Create Token
#       İzinler: Zone > Firewall Services > Edit
#                Zone > Zone > Read
#
#  3) Aşağıdaki AYARLAR bölümünü düzenleyin.
#
#  4a) Crontab (5 dakikada bir):
#       */5 * * * * /etc/honeytea/honeyTEA.sh /etc/honeytea/config.txt
#
#  4b) Veya daemon modunda:
#       /etc/honeytea/honeyTEA.sh --daemon /etc/honeytea/config.txt
#
# =============================================================================

set -euo pipefail

# =============================================================================
# AYARLAR
# =============================================================================

## Cloudflare Bearer API Token (Dashboard > My Profile > API Tokens)
CF_TOKEN="CLOUDFLARE_API_TOKEN_BURAYA"

## Cloudflare Zone ID (Dashboard > Domain > Overview > sağ alt)
CF_ZONE_ID="ZONE_ID_BURAYA"

## IP Bloke Süresi (dakika)
BANNED_TIME=90

## Engelleme aksiyonu: block | challenge | js_challenge | managed_challenge
CF_ACTION="block"

## Log Dosyası
LOG_FILE="/var/log/nginx/access.log"
## Apache için: LOG_FILE="/var/log/httpd/access.log"
## Birden fazla log: LOG_FILES=("/var/log/nginx/access.log" "/var/log/apache2/access.log")

## Log Formatı: combined | json | cloudflare
## combined = standart Apache/Nginx Combined Log Format (varsayılan)
## json     = JSON satır formatı (örn. Nginx json log)
## cloudflare = Cloudflare Workers logları
LOG_FORMAT="combined"

## Çalışma Dizini
WORK_DIR="/etc/honeytea"

## Durum Dosyaları
LINE_FILE="${WORK_DIR}/line.dat"
BLACKLIST_FILE="${WORK_DIR}/blacklist.dat"
WHITELIST_FILE="${WORK_DIR}/whitelist.txt"
LOCK_FILE="/var/run/honeytea.lock"

## honeyTEA Log Dosyası
HONEYTEA_LOG="/var/log/honeytea.log"

## Daemon modunda bekleme süresi (saniye)
DAEMON_INTERVAL=300

## API retry ayarları
MAX_RETRIES=3
RETRY_DELAY=2

## JSON log çıkışı (SIEM entegrasyonu için)
JSON_LOG=false

## Dry-run modu (banlama yapma, sadece logla)
DRY_RUN=false

## Cloudflare API base URL
CF_API_BASE="https://api.cloudflare.com/client/v4"

# =============================================================================
# ARG PARSE
# =============================================================================

DAEMON_MODE=false
CONFIG_FILE=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)   DRY_RUN=true ;;
        --daemon)    DAEMON_MODE=true ;;
        --json-log)  JSON_LOG=true ;;
        --help|-h)
            echo "Kullanım: $0 [--dry-run] [--daemon] [--json-log] <config.txt>"
            echo ""
            echo "  --dry-run   Cloudflare'e istek atmadan simüle et"
            echo "  --daemon    Cron yerine sürekli çalışma modu (${DAEMON_INTERVAL}s aralık)"
            echo "  --json-log  SIEM uyumlu JSON log formatı"
            exit 0
            ;;
        *)
            if [ -z "$CONFIG_FILE" ]; then
                CONFIG_FILE="$arg"
            fi
            ;;
    esac
done

# =============================================================================
# FONKSİYONLAR — LOGLAMA
# =============================================================================

log() {
    local SEVERITY="$1"
    local MSG="$2"
    local TS
    TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"

    if [ "$JSON_LOG" = true ]; then
        # JSON injection önlemi: özel karakterleri escape et
        local ESCAPED_MSG
        ESCAPED_MSG=$(printf '%s' "$MSG" | sed 's/\\/\\\\/g; s/"/\\"/g')
        printf '{"timestamp":"%s","severity":"%s","app":"honeyTEA","message":"%s"}\n' \
            "$TS" "$SEVERITY" "$ESCAPED_MSG" >> "$HONEYTEA_LOG"
    else
        printf '%s [%s] honeyTEA: %s\n' "$TS" "$SEVERITY" "$MSG" >> "$HONEYTEA_LOG"
    fi

    if [ "$SEVERITY" = "ERROR" ] || [ "$SEVERITY" = "WARN" ]; then
        printf '%s [%s] %s\n' "$TS" "$SEVERITY" "$MSG" >&2
    fi
}

# =============================================================================
# FONKSİYONLAR — API
# =============================================================================

cf_api() {
    local METHOD="$1"
    local ENDPOINT="$2"
    local DATA="${3:-}"
    local ATTEMPT=0
    local RESPONSE="" HTTP_CODE="" BODY=""

    while [ $ATTEMPT -lt $MAX_RETRIES ]; do
        ATTEMPT=$((ATTEMPT + 1))

        if [ -n "$DATA" ]; then
            RESPONSE=$(curl -s -w "\n%{http_code}" \
                -X "$METHOD" \
                "${CF_API_BASE}${ENDPOINT}" \
                -H "Authorization: Bearer ${CF_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "$DATA" \
                --max-time 30 --connect-timeout 10 2>/dev/null || echo -e "\n000")
        else
            RESPONSE=$(curl -s -w "\n%{http_code}" \
                -X "$METHOD" \
                "${CF_API_BASE}${ENDPOINT}" \
                -H "Authorization: Bearer ${CF_TOKEN}" \
                -H "Content-Type: application/json" \
                --max-time 30 --connect-timeout 10 2>/dev/null || echo -e "\n000")
        fi

        HTTP_CODE=$(printf '%s' "$RESPONSE" | tail -n1)
        BODY=$(printf '%s' "$RESPONSE" | head -n -1)

        case "$HTTP_CODE" in
            200|201) echo "$BODY"; return 0 ;;
            429)
                log "WARN" "CF API rate limit. ${RETRY_DELAY}s bekleniyor... (${ATTEMPT}/${MAX_RETRIES})"
                sleep "$RETRY_DELAY"
                ;;
            000)
                log "ERROR" "CF API bağlantı hatası. (${ATTEMPT}/${MAX_RETRIES})"
                sleep "$RETRY_DELAY"
                ;;
            *)
                log "WARN" "CF API yanıt: HTTP ${HTTP_CODE} — ${BODY} (${ATTEMPT}/${MAX_RETRIES})"
                if [ $ATTEMPT -lt $MAX_RETRIES ]; then sleep "$RETRY_DELAY"; fi
                ;;
        esac
    done

    echo "$BODY"
    return 1
}

api_success() {
    echo "$1" | grep -q '"success":true'
}

# =============================================================================
# FONKSİYONLAR — IP YÖNETİMİ
# =============================================================================

# IPv6'yı CIDR formatına normalize et
normalize_ip() {
    local IP="$1"
    # IPv6 ama CIDR yok → /128 ekle
    if echo "$IP" | grep -q ':' && ! echo "$IP" | grep -q '/'; then
        echo "${IP}/128"
    else
        echo "$IP"
    fi
}

# IP whitelist kontrolü
is_whitelisted() {
    local IP="$1"
    [ ! -f "$WHITELIST_FILE" ] && return 1
    # grep -F: literal string eşleşmesi — IP içindeki nokta regex wildcard sayılmaz
    # Yorum satırları (#) ve boş satırlar önceden filtrelenir
    grep -v '^\s*#' "$WHITELIST_FILE" 2>/dev/null | grep -v '^\s*$' | grep -qF "$IP"
    return $?
}

# IP blacklist kontrolü
is_in_blacklist() {
    local IP="$1"
    grep -qE "^[0-9]+:${IP}$" "$BLACKLIST_FILE" 2>/dev/null
}

# Blacklist'e ekle
add_to_blacklist() {
    local IP="$1"
    local TS
    TS=$(date +%s)
    echo "${TS}:${IP}" >> "$BLACKLIST_FILE"
}

# Blacklist'ten kaldır (atomic)
remove_from_blacklist() {
    local IP="$1"
    local TMP
    TMP=$(mktemp)
    grep -vE "^[0-9]+:${IP}$" "$BLACKLIST_FILE" > "$TMP" 2>/dev/null || true
    mv "$TMP" "$BLACKLIST_FILE"
}

# =============================================================================
# FONKSİYONLAR — CLOUDFLARE
# =============================================================================

cf_block() {
    local IP="$1"
    IP=$(normalize_ip "$IP")
    local NOTE="honeyTEA Block | $(date '+%Y-%m-%d %H:%M') | Otomatik"

    if [ "$DRY_RUN" = true ]; then
        log "INFO" "[DRY-RUN] Block atlanıyor | IP: ${IP}"
        return 0
    fi

    local DATA
    DATA=$(printf '{"mode":"%s","configuration":{"target":"ip","value":"%s"},"notes":"%s"}' \
        "$CF_ACTION" "$IP" "$NOTE")

    local RESP
    if RESP=$(cf_api "POST" "/zones/${CF_ZONE_ID}/firewall/access_rules/rules" "$DATA"); then
        if api_success "$RESP"; then
            local RULE_ID
            RULE_ID=$(echo "$RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
            log "INFO" "Bloke eklendi | IP: ${IP} | Aksiyon: ${CF_ACTION} | Kural: ${RULE_ID}"
            return 0
        fi
    fi

    log "ERROR" "Bloke eklenemedi | IP: ${IP} | Yanıt: ${RESP:-boş}"
    return 1
}

cf_unblock() {
    local IP="$1"
    IP=$(normalize_ip "$IP")

    if [ "$DRY_RUN" = true ]; then
        log "INFO" "[DRY-RUN] Unblock atlanıyor | IP: ${IP}"
        return 0
    fi

    local ENCODED_IP
    ENCODED_IP=$(printf '%s' "$IP" | sed 's|/|%2F|g')

    local RESP
    RESP=$(cf_api "GET" \
        "/zones/${CF_ZONE_ID}/firewall/access_rules/rules?mode=${CF_ACTION}&configuration_target=ip&configuration_value=${ENCODED_IP}&per_page=1" \
        "") || true

    if ! api_success "$RESP"; then
        log "WARN" "Unblock için kural araması başarısız | IP: ${IP}"
        return 1
    fi

    local RULE_ID
    RULE_ID=$(echo "$RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$RULE_ID" ]; then
        log "INFO" "Silinecek kural yok (zaten kalkmış) | IP: ${IP}"
        return 0
    fi

    local DEL_RESP
    if DEL_RESP=$(cf_api "DELETE" "/zones/${CF_ZONE_ID}/firewall/access_rules/rules/${RULE_ID}" ""); then
        if api_success "$DEL_RESP"; then
            log "INFO" "Bloke kaldırıldı | IP: ${IP} | Kural: ${RULE_ID}"
            return 0
        fi
    fi

    log "ERROR" "Bloke kaldırılamadı | IP: ${IP} | Yanıt: ${DEL_RESP:-boş}"
    return 1
}

# =============================================================================
# FONKSİYONLAR — LOG PARSE
# =============================================================================

# Cloudflare Real-IP başlıklı Combined Log Format'dan IP çıkar
# Format: IP - - [date] "METHOD /path HTTP/1.1" STATUS size "referer" "UA"
# Cloudflare arkasındaysa gerçek IP X-Forwarded-For'da olabilir
# Bu script Nginx/Apache'nin $remote_addr'ını alır (mod_cloudflare/real_ip_module kuruluysa gerçek IP gelir)
extract_ip_combined() {
    awk '{print $1}'
}

# JSON log formatından IP çıkar (Nginx json log)
extract_ip_json() {
    grep -o '"remote_addr":"[^"]*"' | cut -d'"' -f4
}

# Log satırının hangi isteği içerdiğini döndür (URI kısmı)
extract_uri_combined() {
    awk '{print $7}'
}

extract_uri_json() {
    grep -o '"request_uri":"[^"]*"' | cut -d'"' -f4
}

# HTTP status kodu
extract_status_combined() {
    awk '{print $9}'
}

extract_status_json() {
    grep -o '"status":[0-9]*' | cut -d':' -f2
}

# User-Agent
extract_ua_combined() {
    # Combined log: 12. alan (tırnaklar arasında)
    awk -F'"' '{print $6}'
}

extract_ua_json() {
    grep -o '"http_user_agent":"[^"]*"' | cut -d'"' -f4
}

# =============================================================================
# FONKSİYONLAR — CONFIG PARSE
# =============================================================================

# Config dosyasını parse et: URI:, UA:, STATUS: prefix'lerini ayırt et
parse_config() {
    local CONFIG="$1"
    URI_PATTERNS=()
    UA_PATTERNS=()
    STATUS_PATTERNS=()

    while IFS= read -r line || [ -n "$line" ]; do
        # Boş satır ve yorum atla
        [[ -z "$line" || "$line" == \#* ]] && continue

        if [[ "$line" == UA:* ]]; then
            UA_PATTERNS+=("${line#UA:}")
        elif [[ "$line" == STATUS:* ]]; then
            STATUS_PATTERNS+=("${line#STATUS:}")
        else
            # Geriye dönük uyumluluk: prefix yoksa URI kabul et
            URI_PATTERNS+=("${line#URI:}")
        fi
    done < "$CONFIG"
}

# Bir log satırının herhangi bir pattern'la eşleşip eşleşmediğini kontrol et
matches_pattern() {
    local URI="$1"
    local STATUS="$2"
    local UA="$3"

    for pat in "${URI_PATTERNS[@]:-}"; do
        [ -z "$pat" ] && continue
        echo "$URI" | grep -qE "$pat" && return 0
    done

    for pat in "${STATUS_PATTERNS[@]:-}"; do
        [ -z "$pat" ] && continue
        echo "$STATUS" | grep -qE "^${pat}$" && return 0
    done

    for pat in "${UA_PATTERNS[@]:-}"; do
        [ -z "$pat" ] && continue
        echo "$UA" | grep -qiE "$pat" && return 0
    done

    return 1
}

# =============================================================================
# FONKSİYONLAR — BLACKLIST YÖNETİMİ
# =============================================================================

# Süresi dolan blokları Cloudflare'den kaldır, blacklist'ten temizle
process_expired_blocks() {
    local NOW
    NOW=$(date +%s)
    local BAN_SECS=$((BANNED_TIME * 60))

    [ ! -f "$BLACKLIST_FILE" ] && return

    local TMP
    TMP=$(mktemp)

    while IFS=: read -r TS IP || [ -n "$IP" ]; do
        [ -z "$TS" ] || [ -z "$IP" ] && continue

        local DIFF=$((NOW - TS))

        if [ $DIFF -gt $BAN_SECS ]; then
            log "INFO" "Süre doldu, bloke kaldırılıyor | IP: ${IP} | Geçen: ${DIFF}s"
            cf_unblock "$IP" || true
        else
            echo "${TS}:${IP}" >> "$TMP"
        fi
    done < "$BLACKLIST_FILE"

    mv "$TMP" "$BLACKLIST_FILE"
}

# =============================================================================
# FONKSİYONLAR — ANA LOG İŞLEME
# =============================================================================

process_log() {
    local LOG="$1"

    [ ! -f "$LOG" ] && {
        log "WARN" "Log dosyası bulunamadı: ${LOG}"
        return
    }

    local LOG_LINES
    LOG_LINES=$(wc -l < "$LOG")

    # line.dat oku
    local PREV_LINE=0
    if [ -f "$LINE_FILE" ]; then
        PREV_LINE=$(cat "$LINE_FILE" 2>/dev/null || echo 0)
    fi

    # Log rotation tespiti: önceki satır sayısı > şimdiki → log döndü
    if [ "$PREV_LINE" -gt "$LOG_LINES" ]; then
        log "INFO" "Log rotation tespit edildi. Baştan okuyorum."
        PREV_LINE=0
    fi

    # Yeni satır yoksa çık
    local DIFF=$((LOG_LINES - PREV_LINE))
    if [ $DIFF -le 0 ]; then
        echo "$LOG_LINES" > "$LINE_FILE"
        return
    fi

    log "INFO" "Log işleniyor | Dosya: ${LOG} | Yeni satır: ${DIFF}"

    # Yeni satırları oku ve eşleşen IP'leri bul
    tail -n "$DIFF" "$LOG" | while IFS= read -r line; do
        local URI STATUS UA IP

        case "$LOG_FORMAT" in
            json)
                IP=$(echo "$line" | extract_ip_json)
                URI=$(echo "$line" | extract_uri_json)
                STATUS=$(echo "$line" | extract_status_json)
                UA=$(echo "$line" | extract_ua_json)
                ;;
            *)
                IP=$(echo "$line" | extract_ip_combined)
                URI=$(echo "$line" | extract_uri_combined)
                STATUS=$(echo "$line" | extract_status_combined)
                UA=$(echo "$line" | extract_ua_combined)
                ;;
        esac

        [ -z "$IP" ] && continue

        # Pattern kontrolü
        matches_pattern "$URI" "$STATUS" "$UA" || continue

        # Whitelist kontrolü
        is_whitelisted "$IP" && {
            log "INFO" "Whitelist — atlandı | IP: ${IP}"
            continue
        }

        # Zaten blacklist'teyse atla
        is_in_blacklist "$IP" && continue

        log "INFO" "Honeypot tetiklendi | IP: ${IP} | URI: ${URI} | Status: ${STATUS}"

        # Blacklist'e ekle ve Cloudflare'e gönder
        add_to_blacklist "$IP"
        cf_block "$IP" || true

    done

    # line.dat güncelle
    echo "$LOG_LINES" > "$LINE_FILE"
}

# =============================================================================
# LOCK MEKANİZMASI
# =============================================================================

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local OLD_PID
        OLD_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo 0)
        if kill -0 "$OLD_PID" 2>/dev/null; then
            log "WARN" "honeyTEA zaten çalışıyor (PID: ${OLD_PID}). Çıkılıyor."
            exit 0
        else
            log "INFO" "Eski lock dosyası temizlendi (PID: ${OLD_PID} artık çalışmıyor)."
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}

# =============================================================================
# DOĞRULAMALAR
# =============================================================================

validate_config() {
    if [ -z "$CONFIG_FILE" ]; then
        echo "HATA: Config dosyası belirtilmedi."
        echo "Kullanım: $0 [--dry-run] [--daemon] <config.txt>"
        exit 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "HATA: Config dosyası bulunamadı: ${CONFIG_FILE}"
        exit 1
    fi

    if [ "$CF_TOKEN" = "CLOUDFLARE_API_TOKEN_BURAYA" ] || [ -z "$CF_TOKEN" ]; then
        echo "HATA: CF_TOKEN yapılandırılmamış. Scripti düzenleyin."
        exit 1
    fi

    if [ "$CF_ZONE_ID" = "ZONE_ID_BURAYA" ] || [ -z "$CF_ZONE_ID" ]; then
        echo "HATA: CF_ZONE_ID yapılandırılmamış. Scripti düzenleyin."
        exit 1
    fi

    command -v curl >/dev/null 2>&1 || {
        echo "HATA: curl bulunamadı. Lütfen yükleyin."
        exit 1
    }

    # Gerekli dosyalar yoksa oluştur
    mkdir -p "$WORK_DIR"
    touch "$BLACKLIST_FILE" "$LINE_FILE" "$HONEYTEA_LOG"
    [ ! -f "$WHITELIST_FILE" ] && touch "$WHITELIST_FILE"
}

# =============================================================================
# ANA DÖNGÜ
# =============================================================================

run_once() {
    # Config parse
    parse_config "$CONFIG_FILE"

    # Süresi dolan blokları temizle
    process_expired_blocks

    # Log dosyasını işle
    process_log "$LOG_FILE"
}

main() {
    validate_config

    if [ "$DRY_RUN" = true ]; then
        log "INFO" "=== DRY-RUN MODU — Cloudflare'e istek atılmayacak ==="
    fi

    acquire_lock
    trap release_lock EXIT INT TERM

    log "INFO" "honeyTEA v2.0 başlatıldı | Config: ${CONFIG_FILE} | Log: ${LOG_FILE}"

    if [ "$DAEMON_MODE" = true ]; then
        log "INFO" "Daemon modu aktif — ${DAEMON_INTERVAL}s aralıkla çalışıyor"
        while true; do
            run_once
            sleep "$DAEMON_INTERVAL"
        done
    else
        run_once
    fi

    log "INFO" "honeyTEA tamamlandı."
}

main
