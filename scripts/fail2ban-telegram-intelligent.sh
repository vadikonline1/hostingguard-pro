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

SERVER_NAME=$(hostname -f)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# === SISTEM ANTI-DUPLICARE ===
NOTIFICATION_CACHE="/tmp/fail2ban_notifications.cache"
touch "$NOTIFICATION_CACHE"

# Evită notificări duplicate pentru același IP în ultimele 30 de minute
CACHE_KEY="${IP}:${JAIL_NAME}:${ACTION}:$(date '+%Y-%m-%d %H')"
if grep -q "$CACHE_KEY" "$NOTIFICATION_CACHE" 2>/dev/null; then
    echo "[*] Notificare duplicat pentru $IP în jail $JAIL_NAME. Skip."
    exit 0
fi

# Adaugă în cache pentru 30 de minute
echo "$CACHE_KEY" >> "$NOTIFICATION_CACHE"

# Curăță cache-ul vechi (mai vechi de 2 ore)
sed -i "/$(date -d '2 hours ago' '+%Y-%m-%d %H')/d" "$NOTIFICATION_CACHE" 2>/dev/null

# === LOGICĂ NOTIFICĂRI INTELIGENTE ===
if [ "$ACTION" = "ban" ]; then
    # Analiză threat intelligence
    THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"
    IS_KNOWN_THREAT=""
    BANTIME_DAYS=0
    
    if [ -f "$THREAT_INTEL_DIR/combined_threats.txt" ]; then
        if grep -q "$IP" "$THREAT_INTEL_DIR/combined_threats.txt" 2>/dev/null; then
            IS_KNOWN_THREAT="🔍 IP cunoscut în liste threat intelligence"
            # SETEAZĂ BANTIME PE 30 DE ZILE PENTRU IP-URI DIN THREAT INTELLIGENCE
            BANTIME_DAYS=30
            BANTIME=$((2592000))  # 30 zile în secunde
            echo "[*] IP $IP este în IS_KNOWN_THREAT - setez bantime pe 30 de zile"
        fi
    fi
    
    # Verifică dacă este recidivist
    BAN_HISTORY=$(grep -c "Ban $IP" /var/log/fail2ban.log 2>/dev/null || echo 0)
    
    # Determină nivelul de severitate
    if [ "$BANTIME_DAYS" -eq 30 ]; then
        # BLOCARE 30 ZILE pentru threat intelligence
        MESSAGE="🚨🚨🚨 THREAT INTELLIGENCE - BLOCARE 30 ZILE 🚨🚨🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME  
Timp: $TIMESTAMP
Durată: 30 ZILE
Motiv: IP cunoscut în liste amenințări globale
Blocări anterioare: $BAN_HISTORY
Status: AMENINȚARE GLOBALĂ DETECTATĂ"
    
    elif [ "$BANTIME" -ge 2592000 ]; then
        # ESCALATION - 30 days
        MESSAGE="🚨🚨 ESCALATION FAIL2BAN - BLOCARE 30 ZILE 🚨🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME  
Timp: $TIMESTAMP
Durată: 30 ZILE
Blocări anterioare: $BAN_HISTORY
$IS_KNOWN_THREAT
Status: ATACATOR RECIDIVIST"
    
    elif [ "$BANTIME" -ge 86400 ]; then
        # Blocare lungă > 1 day
        MESSAGE="🚨🚨 FAIL2BAN - BLOCARE EXTINSĂ 🚨🚨
Jail: $JAIL_NAME  
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP
Durată: $((BANTIME/86400)) zile
Blocări anterioare: $BAN_HISTORY
$IS_KNOWN_THREAT
Status: ACTIVITATE SUSPECTĂ"
    
    elif [ "$BAN_HISTORY" -gt 3 ]; then
        # Recidivist cu blocare normală
        MESSAGE="🚨⚠️ FAIL2BAN - IP RECIDIVIST ⚠️🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP  
Durată: $((BANTIME/3600)) ore
Blocări anterioare: $BAN_HISTORY
$IS_KNOWN_THREAT
Status: ACTIVITATE REPETATĂ"
    
    else
        # Blocare normală
        MESSAGE="🚨 FAIL2BAN - IP BLOCAT 🚨
Jail: $JAIL_NAME
IP: $IP  
Server: $SERVER_NAME
Timp: $TIMESTAMP
Durată: $((BANTIME/3600)) ore
Blocări anterioare: $BAN_HISTORY
$IS_KNOWN_THREAT
Status: BLOCAT NORMAL"
    fi

elif [ "$ACTION" = "unban" ]; then
    # Notificare deblocare
    MESSAGE="✅ FAIL2BAN - IP DEBLOCAT ✅
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME  
Timp: $TIMESTAMP
Acțiune: Deblocat manual/automat"
    
else
    exit 0
fi

# === TRIMITE NOTIFICAREA ===
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
    "$NOTIFY_SCRIPT" "$MESSAGE"
    
    # Log pentru debugging
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Notificare trimisă: $JAIL_NAME $ACTION $IP Bantime: $BANTIME" >> /var/log/fail2ban-telegram.log
fi
