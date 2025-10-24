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
    echo "[+] Toate dependențele sunt prezente"
}

check_telegram_script() {
    echo "[*] Verific scriptul Telegram..."
    if [ ! -x "$NOTIFY_SCRIPT" ]; then
        echo "[!] Setez permisiuni pentru $NOTIFY_SCRIPT"
        chmod +x "$NOTIFY_SCRIPT"
    fi
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        "$NOTIFY_SCRIPT" "🧪 Test Fail2Ban Telegram OK" || echo "[!] Avertisment: notificarea Telegram a eșuat"
    fi
}

# === CREARE FILTRE ===
create_filters() {
    echo "[*] Creez filtre Fail2Ban..."

    # 🔹 Atacuri WordPress / web
    cat > "$FAIL2BAN_DIR/filter.d/web-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-login\.php|xmlrpc\.php|wp-config\.php|wp-config-sample\.php|wp-cli\.php|wp-signup\.php|wp-cron\.php|install\.php|readme\.html|license\.txt|/admin|/wp-admin|/wp-content/plugins/|/wp-includes/|/phpinfo\.php|/config\.php|/shell|/eval-stdin\.php|/composer\.json|/autoload\.php|/vendor/).*HTTP.*"
ignoreregex =
EOF

    # 🔹 Brute-force / autentificare
    cat > "$FAIL2BAN_DIR/filter.d/auth-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST>.*(authentication failure|Failed password|invalid user|Unknown user).*
            ^<HOST> -.*"POST.*/(wp-login\.php|xmlrpc\.php|admin|login|user-login).*HTTP.*"
ignoreregex =
EOF

    # 🔹 Scanere / bots
    cat > "$FAIL2BAN_DIR/filter.d/web-scanners.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(nikto|acunetix|nessus|burp|sqlmap|nmap|python-requests|curl|wget).*HTTP.*"
ignoreregex =
EOF

    # 🔹 Erori server (500+, PHP, timeout)
    cat > "$FAIL2BAN_DIR/filter.d/server-errors.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"GET.*HTTP.*" (500|502|503|504)
            ^<HOST>.*PHP (Fatal error|Parse error|Warning).*
ignoreregex =
EOF

    echo "[+] Filtre create în $FAIL2BAN_DIR/filter.d/"
}

# === ACȚIUNE TELEGRAM CORECTATĂ ===
create_telegram_action() {
    echo "[*] Creez acțiunea Telegram..."

    cat > "$FAIL2BAN_DIR/action.d/telegram-notify.conf" << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =

actionban = /etc/automation-web-hosting/telegram_notify.sh "🚨 Fail2Ban - IP blocat 🚨
 Server: <fq-hostname>
 Jail: <name>
 IP: <ip>
 Port: <port>
 Log: <logpath>
 Timp: <time>
 Eșecuri: <failures>"

actionunban = /etc/automation-web-hosting/telegram_notify.sh "✅ Fail2Ban - IP deblocat ✅
 Server: <fq-hostname>
 Jail: <name>
 IP: <ip>
 Timp: <time>"

[Init]
fq-hostname = $(hostname -f)
EOF

    sed -i "s/__HOSTNAME__/$(hostname -f)/g" "$FAIL2BAN_DIR/action.d/telegram-notify.conf"
    echo "[+] Acțiune Telegram creată"
}

# === CONFIGURARE JAIL ===
create_jail_local() {
    echo "[*] Creez jail.local..."

    if [ -f "$FAIL2BAN_DIR/jail.local" ]; then
        cp "$FAIL2BAN_DIR/jail.local" "$FAIL2BAN_DIR/jail.local.backup.$(date +%F_%H-%M-%S)"
    fi

    cat > "$FAIL2BAN_DIR/jail.local" << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 7200
findtime = 600
maxretry = 3
backend = auto
banaction = iptables-multiport
action = %(action_)s
         telegram-notify

[web-attacks]
enabled = true
port = http,https
filter = web-attacks
logpath = /var/www/*/data/logs/*-frontend.access.log
          /var/www/*/data/logs/*-backend.access.log
          /var/log/nginx/access.log
          /var/log/apache2/access.log
          /var/log/apache2/other_vhosts_access.log
maxretry = 3
findtime = 600
bantime = 7200
action = %(action_)s
         telegram-notify

[auth-attacks]
enabled = true
port = http,https,ssh
filter = auth-attacks
logpath = /var/www/*/data/logs/*-backend.error.log
          /var/log/auth.log
          /var/log/syslog
maxretry = 3
bantime = 7200
findtime = 600
action = %(action_)s
         telegram-notify

[web-scanners]
enabled = true
port = http,https
filter = web-scanners
logpath = /var/www/*/data/logs/*-frontend.access.log
          /var/log/nginx/access.log
maxretry = 2
bantime = 10800
findtime = 300
action = %(action_)s
         telegram-notify

[server-errors]
enabled = true
port = http,https
filter = server-errors
logpath = /var/www/*/data/logs/*-frontend.error.log
          /var/www/*/data/logs/*-backend.error.log
          /var/log/nginx/error.log
          /var/log/apache2/error.log
maxretry = 5
bantime = 3600
findtime = 900
action = %(action_)s
         telegram-notify

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
findtime = 600
action = %(action_)s
         telegram-notify
EOF

    echo "[+] jail.local creat"
}

# === FINAL ===
finalize_setup() {
    echo "[*] Verific configurarea..."
    if ! fail2ban-client -t; then
        echo "❌ Configurația Fail2Ban are erori."
        exit 1
    fi
    systemctl enable fail2ban
    systemctl restart fail2ban
    sleep 2
    systemctl status fail2ban --no-pager
    echo "[*] Fail2Ban rulează OK."
    echo "[*] Status jails:"
    fail2ban-client status
}

# === EXECUȚIE ===
main() {
    echo "=== SETUP FAIL2BAN + TELEGRAM (WordPress Enhanced) ==="
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Rulează ca root!"
        exit 1
    fi
    check_dependencies
    check_telegram_script
    create_filters
    create_telegram_action
    create_jail_local
    finalize_setup
    "$NOTIFY_SCRIPT" "✅ Fail2Ban instalat cu succes pe $(hostname -f)"
    echo "=== CONFIGURARE FINALIZATĂ ==="
}
main
