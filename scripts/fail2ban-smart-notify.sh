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
BANTIME="${4:-7200}"

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

SERVER_NAME=$(hostname -f)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Determină tipul de notificare bazat pe bantime
if [ "$BANTIME" -ge 2592000 ]; then
    # Escalation - 30 days
    MESSAGE="🚨🚨 ESCALATION - IP BLOCAT 30 ZILE 🚨🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME  
Timp: $TIMESTAMP
Acțiune: BLOCAT 30 ZILE
Motiv: Atacator recidivist"
    
elif [ "$BANTIME" -ge 86400 ]; then
    # Ban lung > 1 day
    MESSAGE="🚨 IP BLOCAT - PERIOADĂ LUNGĂ 🚨
Jail: $JAIL_NAME  
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP
Durată: $((BANTIME/86400)) zile"
    
elif [ "$ACTION" = "ban" ]; then
    # Ban normal
    MESSAGE="🚨 IP Blocat 🚨
Jail: $JAIL_NAME
IP: $IP  
Server: $SERVER_NAME
Timp: $TIMESTAMP
Durată: $((BANTIME/3600)) ore"
    
elif [ "$ACTION" = "unban" ]; then
    # Unban
    MESSAGE="✅ IP Deblocat ✅
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME  
Timp: $TIMESTAMP"
fi

# Trimite notificarea
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
    "$NOTIFY_SCRIPT" "$MESSAGE"
fi
