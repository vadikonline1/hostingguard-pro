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
    local ENV_FILE="$CURRENT_PATH_DIR/hosting_env.env"
    
    # Load environment variables
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
    fi
    
    # If Telegram variables not set, just display
    if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]]; then
        echo "📢 [NOTIFICATION] $MESSAGE"
        return 0
    fi
    
    # Escape message for JSON
    MESSAGE_ESC=$(echo "$MESSAGE" | sed 's/"/\\"/g' | sed "s/'/\\'/g")
    
    # Limit message length
    if [ ${#MESSAGE_ESC} -gt 4090 ]; then
        MESSAGE_ESC="${MESSAGE_ESC:0:4090}..."
    fi
    
    # Add timestamp
    FULL_MESSAGE="🛡️ $(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE_ESC"
    
    # Send notification
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -H "Content-Type: application/json" \
         -d "{
               \"chat_id\": \"${TELEGRAM_CHAT_ID}\",
               \"message_thread_id\": \"${TELEGRAM_THREAD_ID}\",
               \"text\": \"$FULL_MESSAGE\",
               \"parse_mode\": \"HTML\"
             }" > /dev/null
    
    echo "Telegram notification sent: $MESSAGE"
}

# If script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    send_telegram_notification "$1"
fi
