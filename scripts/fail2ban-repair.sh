#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

echo "[*] Încep repararea Fail2Ban..."

# Oprește serviciul
echo "[*] Oprește Fail2Ban..."
systemctl stop fail2ban 2>/dev/null || true

# Așteaptă oprirea completă
sleep 3

# Șterge socket-ul vechi
echo "[*] Șterge socket vechi..."
rm -f /var/run/fail2ban/fail2ban.sock

# Curăță reguli iptables vechi
echo "[*] Curăță reguli iptables vechi Fail2Ban..."
iptables -L | grep -i fail2ban | awk '{print $2}' | while read chain; do
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
done

# Verifică și repară configurația de bază
echo "[*] Verifică configurația..."
if ! fail2ban-client -t >/dev/null 2>&1; then
    echo "[*] Repară configurația invalidă..."
    # Creează configurație minimală
    cat > /etc/fail2ban/jail.local << 'CFG'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 7200
findtime = 600
maxretry = 3
backend = auto
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
CFG
    chmod 644 /etc/fail2ban/jail.local
fi

# Repornește serviciul
echo "[*] Repornește Fail2Ban..."
systemctl start fail2ban

# Așteaptă inițializarea
echo "[*] Așteaptă inițializarea..."
sleep 5

# Verifică rezultatul
if systemctl is-active --quiet fail2ban && [ -S "/var/run/fail2ban/fail2ban.sock" ]; then
    echo "[+] ✅ Fail2Ban reparat cu succes!"
    
    # Notificare succes
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="🔧 Fail2Ban Reparat cu Succes
Server: $(hostname -f)
Status: OPERATIONAL ✅
Timp: $(date '+%Y-%m-%d %H:%M:%S')
Detalii: Sistemul a fost reparat automat"
        
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
else
    echo "[-] ❌ Repararea a eșuat!"
    
    # Afișează erorile
    echo "[*] Ultimele erori din jurnal:"
    journalctl -u fail2ban -n 10 --no-pager
    
    # Notificare eșec
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="❌ Eroare Reparare Fail2Ban
Server: $(hostname -f)
Status: NEOPERATIONAL 🚨
Timp: $(date '+%Y-%m-%d %H:%M:%S')
Detalii: Verifică jurnalele manual"
        
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
    exit 1
fi
