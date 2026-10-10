#!/bin/bash
set -e

# Load environment
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILES="$CURRENT_PATH_DIR/*.env"

# Încarcă toate fișierele .env
for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
    fi
done

send_telegram_notification() {
    local MESSAGE="$1"

    # Variabilele vin din hosting.env (incarcat de apelant sau aici ca fallback)
    if [[ -z "$TELEGRAM_BOT_TOKEN" && -f "$CURRENT_PATH_DIR/hosting.env" ]]; then
        # shellcheck disable=SC1091
        source "$CURRENT_PATH_DIR/hosting.env" 2>/dev/null || true
    fi

    # If Telegram variables not set, just display
    if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]]; then
        echo "📢 [NOTIFICATION] $MESSAGE"
        return 0
    fi

    # Rate-limit: max N mesaje/ora (evita blocarea cronului in bucle de alerta)
    local RATE_DIR="/tmp/hg_telegram_rate"
    local RATE_LIMIT="${TELEGRAM_MAX_PER_HOUR:-20}"
    mkdir -p "$RATE_DIR" 2>/dev/null || true
    find "$RATE_DIR" -type f -mmin +60 -delete 2>/dev/null || true
    if [ "$(ls "$RATE_DIR" 2>/dev/null | wc -l)" -ge "$RATE_LIMIT" ]; then
        echo "⏳ Telegram rate-limit atins ($RATE_LIMIT/ora) — mesaj sarit" >&2
        return 0
    fi
    touch "$RATE_DIR/$(date +%s%N)" 2>/dev/null || true

    # Escape pentru HTML (parse_mode=HTML): & < > esentiale
    MESSAGE_ESC=$(echo "$MESSAGE" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    # Limit message length (Telegram max 4096)
    if [ ${#MESSAGE_ESC} -gt 4000 ]; then
        MESSAGE_ESC="${MESSAGE_ESC:0:4000}..."
    fi

    # Add timestamp
    FULL_MESSAGE="🛡️ $(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE_ESC"

    # Send notification CU timeout (inainte curl putea bloca cronul la nesfarsit)
    if curl -s --max-time 10 --retry 1 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -H "Content-Type: application/json" \
         -d "{
               \"chat_id\": \"${TELEGRAM_CHAT_ID}\",
               \"message_thread_id\": \"${TELEGRAM_THREAD_ID}\",
               \"text\": \"$FULL_MESSAGE\",
               \"parse_mode\": \"HTML\"
             }" > /dev/null; then
        echo "Telegram notification sent: $MESSAGE"
        return 0
    else
        echo "⚠️ Telegram send failed (timeout/retea) — nu blocam apelantul" >&2
        return 1
    fi
}

# If script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "-f" ]]; then
        # Compatibilitate cu apelul vechi din fail2ban-report.sh:
        #   echo "$raport" | telegram_notify.sh -f -
        # "-f -" sau "-f" fara fisier = citeste mesajul din stdin.
        # FARA acest branch, "$1" (= "-f") era trimis literal pe Telegram
        # si continutul raportului se pierdea: "🛡️ DATA - -f".
        if [[ -z "${2:-}" || "${2:-}" == "-" ]]; then
            send_telegram_notification "$(cat)"
        else
            send_telegram_notification "$(cat -- "$2")"
        fi
    elif [[ "${1:-}" == "--stdin" ]]; then
        send_telegram_notification "$(cat)"
    else
        send_telegram_notification "${1:-}"
    fi
fi