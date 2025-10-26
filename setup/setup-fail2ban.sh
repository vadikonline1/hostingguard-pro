#!/bin/bash
set -e

# === CONFIGURARE DE BAZĂ ===
FAIL2BAN_DIR="/etc/fail2ban"
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# === ÎNCĂRCARE VARIABILE ENV ===
ENV_FILES="$CURRENT_PATH_DIR/../*.env"
env_loaded=0

for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
        env_loaded=1
    fi
done

if [ $env_loaded -eq 0 ]; then
    echo "[!] WARNING: No .env files found in $CURRENT_PATH_DIR/../"
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# === FUNCȚII ===

install_fail2ban() {
    echo "[*] Verific dacă Fail2Ban este instalat..."
    if command -v fail2ban-server >/dev/null 2>&1; then
        echo "[+] Fail2Ban este deja instalat"
        return
    fi
    echo "[*] Instalez Fail2Ban..."
    apt-get update && apt-get install -y fail2ban
    echo "[+] Fail2Ban instalat"
}

check_dependencies() {
    echo "[*] Verific dependențe..."
    install_fail2ban
    for cmd in ip iptables curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[-] Lipsă $cmd — instalează-l manual."
            exit 1
        fi
    done
    
    # Verifică scriptul Telegram
    if [ ! -f "$NOTIFY_SCRIPT" ]; then
        echo "[-] ERROR: Scriptul Telegram nu există: $NOTIFY_SCRIPT"
        exit 1
    fi
    if [ ! -x "$NOTIFY_SCRIPT" ]; then
        echo "[*] Setez permisiuni executabile pentru $NOTIFY_SCRIPT"
        chmod +x "$NOTIFY_SCRIPT"
    fi
    
    echo "[+] Toate dependențele sunt prezente"
}

check_telegram_script() {
    echo "[*] Verific scriptul Telegram..."
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        echo "[*] Testez notificarea Telegram..."
        if TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID" \
           "$NOTIFY_SCRIPT" "🧪 Test Fail2Ban - Script Telegram funcțional" >/dev/null 2>&1; then
            echo "[+] Script Telegram funcționează corect!"
        else
            echo "[-] Avertisment: Notificarea Telegram a eșuat"
        fi
    else
        echo "[!] Variabilele Telegram nu sunt setate. Verifică fișierele .env"
    fi
}

# === CURĂȚARE CONFIGURAȚIE VECHIE ===
clean_old_config() {
    echo "[*] Curăț configurație veche dacă există..."
    
    # Oprește Fail2Ban temporar
    systemctl stop fail2ban 2>/dev/null || true
    sleep 2
    
    # Șterge doar fișierele noastre
    rm -f "$FAIL2BAN_DIR/action.d/telegram-notify.conf"
    rm -f "$FAIL2BAN_DIR/action.d/telegram-simple.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/web-attacks.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/auth-attacks.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/web-scanners.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/server-errors.conf"
    rm -f "/usr/local/bin/fail2ban-telegram-wrapper.sh"
    
    echo "[+] Configurație veche curățată"
}

# === CREARE FILTRE ===
create_filters() {
    echo "[*] Creez filtre Fail2Ban..."

    # 🔹 Atacuri WordPress / web
    cat > "$FAIL2BAN_DIR/filter.d/web-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-login\.php|xmlrpc\.php|wp-config\.php|wp-config-sample\.php|wp-cli\.php|wp-signup\.php|wp-cron\.php|install\.php|readme\.html|license\.txt|/admin|/wp-admin|/wp-content/plugins/|/wp-includes/|/phpinfo\.php|/config\.php|/shell|/eval-stdin\.php|/composer\.json|/autoload\.php|/vendor/).*HTTP.*"
            ^<HOST> -.*"(GET|POST).*\.(bak|old|backup|sql|tar|gz|env|git).*HTTP.*"
            ^<HOST> -.*"(GET|POST).*(union|select|insert|update|delete|drop|exec).*HTTP.*"
ignoreregex =
EOF

    # 🔹 Brute-force / autentificare
    cat > "$FAIL2BAN_DIR/filter.d/auth-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST>.*(authentication failure|Failed password|invalid user|Unknown user).*
            ^<HOST> -.*"POST.*/(wp-login\.php|xmlrpc\.php|admin|login|user-login).*HTTP.*"
            ^<HOST> -.*"POST.*/phpmyadmin.*HTTP.*"
ignoreregex =
EOF

    # 🔹 Scanere / bots
    cat > "$FAIL2BAN_DIR/filter.d/web-scanners.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(nikto|acunetix|nessus|burp|sqlmap|nmap|python-requests|curl|wget).*HTTP.*"
            ^<HOST> -.*"GET.*/(phpinfo|test|debug).*HTTP.*"
            ^<HOST> -.*"GET.*/\.(git|svn|hg).*HTTP.*"
ignoreregex =
EOF

    # 🔹 Erori server (500+, PHP, timeout)
    cat > "$FAIL2BAN_DIR/filter.d/server-errors.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"GET.*HTTP.*" (500|502|503|504)
            ^<HOST>.*PHP (Fatal error|Parse error|Warning).*
            ^<HOST>.*(timeout|Time-out|connection timed out).*
ignoreregex =
EOF

    echo "[+] Filtre create în $FAIL2BAN_DIR/filter.d/"
}

# === ACȚIUNE TELEGRAM SIMPLIFICATĂ ===
create_telegram_action() {
    echo "[*] Creez acțiunea Telegram simplificată..."

    # Folosim un script wrapper pentru a evita conflictele de variabile
    cat > "/usr/local/bin/fail2ban-telegram-wrapper.sh" << 'EOF'
#!/bin/bash
JAIL_NAME="$1"
ACTION="$2"
IP="$3"

TELEGRAM_SCRIPT="/etc/automation-web-hosting/telegram_notify.sh"
SERVER_NAME=$(hostname -f)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Încarcă variabilele din .env files
if [ -f "/etc/automation-web-hosting/hosting.env" ]; then
    source "/etc/automation-web-hosting/hosting.env"
fi

if [ "$ACTION" = "ban" ]; then
    MESSAGE="🚨 Fail2Ban - IP Blocat 🚨
Jail: $JAIL_NAME
IP: $IP
Server: $SERVER_NAME
Timp: $TIMESTAMP
Acțiune: Blocat"
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
export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
"$TELEGRAM_SCRIPT" "$MESSAGE"
EOF

    chmod +x "/usr/local/bin/fail2ban-telegram-wrapper.sh"
    echo "[+] Script wrapper creat: /usr/local/bin/fail2ban-telegram-wrapper.sh"

    # Acțiune simplă care folosește wrapper-ul
    cat > "$FAIL2BAN_DIR/action.d/telegram-simple.conf" << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/local/bin/fail2ban-telegram-wrapper.sh <name> ban <ip>
actionunban = /usr/local/bin/fail2ban-telegram-wrapper.sh <name> unban <ip>

[Init]
EOF

    echo "[+] Acțiune Telegram simplă creată"
}

# === CONFIGURARE JAIL CU TELEGRAM INTEGRAT ===
create_jail_local() {
    echo "[*] Creez jail.local cu Telegram integrat..."

    if [ -f "$FAIL2BAN_DIR/jail.local" ]; then
        cp "$FAIL2BAN_DIR/jail.local" "$FAIL2BAN_DIR/jail.local.backup.$(date +%F_%H-%M-%S)"
        echo "[+] Backup creat pentru jail.local existent"
    fi

    cat > "$FAIL2BAN_DIR/jail.local" << 'EOF'
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
findtime = 600
action = %(action_)s
         telegram-simple

[web-attacks]
enabled = true
port = http,https
filter = web-attacks
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
          /var/log/apache2/other_vhosts_access.log
maxretry = 3
bantime = 7200
findtime = 600
action = %(action_)s
         telegram-simple

[auth-attacks]
enabled = true
port = http,https,ssh
filter = auth-attacks
logpath = /var/log/auth.log
          /var/log/apache2/error.log
maxretry = 3
bantime = 7200
findtime = 600
action = %(action_)s
         telegram-simple

[web-scanners]
enabled = true
port = http,https
filter = web-scanners
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 2
bantime = 10800
findtime = 300
action = %(action_)s
         telegram-simple

[server-errors]
enabled = true
port = http,https
filter = server-errors
logpath = /var/log/nginx/error.log
          /var/log/apache2/error.log
maxretry = 5
bantime = 3600
findtime = 900
action = %(action_)s
         telegram-simple
EOF

    echo "[+] jail.local cu Telegram integrat creat"
}

# === SETUP PERMISIUNI ȘI RESTART ===
setup_permissions_and_restart() {
    echo "[*] Setez permisiuni..."
    
    chmod 644 "$FAIL2BAN_DIR/jail.local"
    chmod 644 "$FAIL2BAN_DIR/filter.d"/*.conf
    chmod 644 "$FAIL2BAN_DIR/action.d/telegram-simple.conf"
    chmod +x "$NOTIFY_SCRIPT"
    chmod +x "/usr/local/bin/fail2ban-telegram-wrapper.sh"
    
    echo "[*] Verific configurația Fail2Ban..."
    if fail2ban-client -t; then
        echo "[+] Configurația Fail2Ban este validă!"
    else
        echo "[-] Eroare în configurația Fail2Ban."
        echo "[*] Verific eroarea specifică..."
        fail2ban-client -t 2>&1 | grep -i error
        exit 1
    fi
    
    echo "[*] Pornesc Fail2Ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    sleep 5
    
    echo "[*] Verific statusul Fail2Ban..."
    if systemctl is-active --quiet fail2ban; then
        echo "[+] Fail2Ban rulează cu succes"
    else
        echo "[-] Fail2Ban nu rulează. Verifică: systemctl status fail2ban"
        journalctl -u fail2ban -n 15 --no-pager
        exit 1
    fi
}

# === VERIFICARE ȘI TESTARE ===
verify_and_test() {
    echo "[*] Verific și testez configurația..."
    
    # Așteaptă puțin pentru ca Fail2Ban să se inițializeze complet
    sleep 3
    
    # Verifică statusul
    echo "[*] Status Fail2Ban:"
    if fail2ban-client status; then
        echo "[+] Fail2Ban răspunde corect"
    else
        echo "[-] Fail2Ban nu răspunde. Verifică socket-ul..."
        ls -la /var/run/fail2ban/ 2>/dev/null || echo "[-] Directorul socket nu există"
        systemctl status fail2ban --no-pager
        return 1
    fi
    
    # Testează scriptul wrapper
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        echo "[*] Testez scriptul wrapper Telegram..."
        if /usr/local/bin/fail2ban-telegram-wrapper.sh "test-jail" "ban" "123.456.789.000"; then
            echo "[+] Script wrapper Telegram funcționează"
        else
            echo "[-] Eroare la scriptul wrapper Telegram"
        fi
    fi
    
    # Trimite notificare finală
    echo "[*] Trimite notificare finală..."
    "$NOTIFY_SCRIPT" "✅ Fail2Ban configurat cu succes pe $(hostname -f)

Jails active:
- web-attacks (atacuri WordPress/web)
- auth-attacks (brute-force)  
- web-scanners (scanere/bots)
- server-errors (erori server)
- sshd (SSH attacks)

Blocare: 2 ore
Monitorizare: toate logurile server
Status: Operational 🟢"
}

# === AFIȘARE COMENZI MONITORIZARE ===
show_monitoring_commands() {
    echo ""
    echo "=== COMENZI MONITORIZARE ==="
    echo "fail2ban-client status                      # Status general"
    echo "fail2ban-client status web-attacks          # Status atacuri web"
    echo "fail2ban-client status auth-attacks         # Status autentificări"
    echo "fail2ban-client status sshd                 # Status SSH"
    echo "tail -f /var/log/fail2ban.log              # Loguri Fail2Ban"
    echo "tail -f /var/log/nginx/access.log          # Loguri Nginx"
    echo ""
    echo "=== DECOMANDARE IP ==="
    echo "fail2ban-client set web-attacks unbanip IP  # Deblochează IP"
    echo ""
    echo "=== VERIFICARE BLOCHETE ==="
    echo "iptables -L -n                             # Reguli iptables"
    echo ""
    echo "=== RESTART SERVICE ==="
    echo "systemctl restart fail2ban                 # Restart Fail2Ban"
}

# === EXECUȚIE PRINCIPALĂ ===
main() {
    echo "=================================================="
    echo "    FAIL2BAN + TELEGRAM SETUP SCRIPT"
    echo "=================================================="
    echo "📁 Director: $BOUNCER_DIR"
    echo "📱 Script Telegram: $NOTIFY_SCRIPT"
    echo "🛡️  Filtre: WordPress, SSH, Scanere, Erori"
    echo "=================================================="
    
    # Verificare root
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Rulează scriptul ca root: sudo $0"
        exit 1
    fi
    
    # Curățare configurație veche
    clean_old_config
    
    # Verificări dependențe
    check_dependencies
    check_telegram_script
    
    # Creare configurație
    create_filters
    create_telegram_action
    create_jail_local
    setup_permissions_and_restart
    verify_and_test
    
    # Afișare comenzi utile
    show_monitoring_commands
    
    echo ""
    echo "=================================================="
    echo "✅ CONFIGURARE COMPLETĂ CU SUCCES!"
    echo "✅ Fail2Ban monitorizează toate logurile server"
    echo "✅ IP-uri rău intenționate blocate 2 ore"
    echo "✅ Notificări Telegram active pentru blocare/deblocare"
    echo "=================================================="
}

# Rulează scriptul principal
main "$@"
