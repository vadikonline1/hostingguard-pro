#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

JAIL_NAME="$1"
ACTION="$2"
IP="$3"

SERVER_NAME=$(hostname -f)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Verifică dacă IP-ul a fost deja notificat recent
NOTIFICATION_CACHE="/tmp/fail2ban_notifications.cache"
touch "$NOTIFICATION_CACHE"

# Evită notificări duplicate pentru același IP în ultimele 30 de minute
if grep -q "$IP:$(date '+%Y-%m-%d %H')" "$NOTIFICATION_CACHE" 2>/dev/null; then
    echo "[*] Notificare pentru $IP deja trimisă recent. Skip."
    exit 0
fi

# Adaugă IP-ul în cache pentru 30 de minute
echo "$IP:$(date '+%Y-%m-%d %H')" >> "$NOTIFICATION_CACHE"

# Curăță cache-ul vechi (mai vechi de 2 ore)
sed -i "/$(date -d '2 hours ago' '+%Y-%m-%d %H')/d" "$NOTIFICATION_CACHE" 2>/dev/null

if [ "$ACTION" = "ban" ]; then
    MESSAGE="🚨 Fail2Ban - IP Blocat 🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP
Acțiune: Blocat 2 ore"

elif [ "$ACTION" = "unban" ]; then
    MESSAGE="✅ Fail2Ban - IP Deblocat ✅
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP
Acțiune: Deblocat"
else
    exit 0
fi

# Trimite notificarea
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
    "$NOTIFY_SCRIPT" "$MESSAGE"
fi
