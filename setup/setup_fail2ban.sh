#!/bin/bash
set -e

# === CONFIGURARE AVANSATĂ ===
FAIL2BAN_DIR="/etc/fail2ban"
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="${BOUNCER_DIR}/scripts"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
BACKUP_DIR="/var/backups/fail2ban"
THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"
AUTO_HEAL_SCRIPT="$SCRIPT_DIR/fail2ban_autoheal.sh"
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

# === FUNCȚII AVANSATE ===

install_fail2ban() {
    echo "[*] Verific dacă Fail2Ban este instalat..."
    if command -v fail2ban-server >/dev/null 2>&1; then
        echo "[+] Fail2Ban este deja instalat"
        return
    fi
    echo "[*] Instalez Fail2Ban..."
    apt-get update && apt-get install -y fail2ban whois python3 python3-pip
    echo "[+] Fail2Ban instalat"
}

check_dependencies() {
    echo "[*] Verific dependențe..."
    install_fail2ban
    
    # Instalare dependințe Python pentru Threat Intelligence
    pip3 install requests beautifulsoup4 2>/dev/null || {
        echo "[*] Instalez dependințe Python..."
        apt-get install -y python3-requests python3-bs4
    }
    
    for cmd in ip iptables curl jq whois; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[*] Instalez $cmd..."
            apt-get install -y "$cmd"
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

# === CURĂȚARE CONFIGURAȚIE VECHIE ===
clean_old_config() {
    echo "[*] Curăț configurație veche Fail2Ban..."
    
    # Oprește Fail2Ban
    systemctl stop fail2ban 2>/dev/null || true
    sleep 2
    
    # Șterge toate configurările noastre vechi
    rm -f "$FAIL2BAN_DIR/jail.d/behavioral.conf"
    rm -f "$FAIL2BAN_DIR/jail.d/escalation.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/behavioral-analysis.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/web-attacks.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/auth-attacks.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/web-scanners.conf"
    rm -f "$FAIL2BAN_DIR/filter.d/server-errors.conf"
    rm -f "$FAIL2BAN_DIR/action.d/telegram-simple.conf"
    rm -f "$FAIL2BAN_DIR/action.d/telegram-escalation.conf"
    
    # Curăță iptables
    iptables -D INPUT -p tcp -m multiport --dports 80,443 -j f2b-web-attacks 2>/dev/null || true
    iptables -D INPUT -p tcp -m multiport --dports 80,443,22 -j f2b-auth-attacks 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 22 -j f2b-sshd 2>/dev/null || true
    
    echo "[+] Configurație veche curățată"
}

# === CREARE DIRECTOR SCRIPTURI ===
create_script_directory() {
    echo "[*] Creez directorul pentru scripturi: $SCRIPT_DIR"
    mkdir -p "$SCRIPT_DIR"
    chmod 755 "$SCRIPT_DIR"
    echo "[+] Director scripturi creat: $SCRIPT_DIR"
}

# === CONFIGURARE FAIL2BAN DE BAZĂ ===
setup_basic_fail2ban() {
    echo "[*] Configurare Fail2Ban de bază..."
    
    # Creare filtre de bază
    cat > "$FAIL2BAN_DIR/filter.d/web-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-login\.php|xmlrpc\.php|wp-config\.php|wp-config-sample\.php|wp-cli\.php|wp-signup\.php|wp-cron\.php|install\.php|readme\.html|license\.txt|/admin|/wp-admin|/wp-content/plugins/|/wp-includes/|/phpinfo\.php|/config\.php|/shell|/eval-stdin\.php|/composer\.json|/autoload\.php|/vendor/).*HTTP.*"
            ^<HOST> -.*"(GET|POST).*\.(bak|old|backup|sql|tar|gz|env|git).*HTTP.*"
            ^<HOST> -.*"(GET|POST).*(union|select|insert|update|delete|drop|exec).*HTTP.*"
ignoreregex =
EOF

    # Filtru pentru atacuri autentificare
    cat > "$FAIL2BAN_DIR/filter.d/auth-attacks.conf" << 'EOF'
[Definition]
failregex = ^<HOST>.*(authentication failure|Failed password|invalid user|Unknown user).*
            ^<HOST> -.*"POST.*/(wp-login\.php|xmlrpc\.php|admin|login|user-login).*HTTP.*"
            ^<HOST> -.*"POST.*/phpmyadmin.*HTTP.*"
ignoreregex =
EOF

    # Filtru pentru scanere
    cat > "$FAIL2BAN_DIR/filter.d/web-scanners.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(nikto|acunetix|nessus|burp|sqlmap|nmap|python-requests|curl|wget).*HTTP.*"
            ^<HOST> -.*"GET.*/(phpinfo|test|debug).*HTTP.*"
            ^<HOST> -.*"GET.*/\.(git|svn|hg).*HTTP.*"
ignoreregex =
EOF

    # Filtru pentru erori server
    cat > "$FAIL2BAN_DIR/filter.d/server-errors.conf" << 'EOF'
[Definition]
failregex = ^<HOST> -.*"GET.*HTTP.*" (500|502|503|504)
            ^<HOST>.*PHP (Fatal error|Parse error|Warning).*
            ^<HOST>.*(timeout|Time-out|connection timed out).*
ignoreregex =
EOF

    # Configurare jail de bază
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

[web-attacks]
enabled = true
port = http,https
filter = web-attacks
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 3
bantime = 7200

[auth-attacks]
enabled = true
port = http,https,ssh
filter = auth-attacks
logpath = /var/log/auth.log
          /var/log/apache2/error.log
maxretry = 3
bantime = 7200

[web-scanners]
enabled = true
port = http,https
filter = web-scanners
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 2
bantime = 10800
findtime = 300

[server-errors]
enabled = true
port = http,https
filter = server-errors
logpath = /var/log/nginx/error.log
          /var/log/apache2/error.log
maxretry = 5
bantime = 3600
findtime = 900
EOF

    echo "[+] Fail2Ban de bază configurat"
}

# === BEHAVIORAL ANALYSIS ===
setup_behavioral_analysis() {
    echo "[*] Configurare Behavioral Analysis..."
    
    # Filtru pentru detectie comportament anormal
    cat > "$FAIL2BAN_DIR/filter.d/behavioral-analysis.conf" << 'EOF'
[Definition]
# Detectează scanări rapide de porturi
failregex = ^<HOST> -.*".*" (404|403) .*"$
            ^<HOST> -.*"GET.*(\.php|\.asp|\.jsp).*" (404|403)
            ^<HOST> -.*"POST.*(wp-login|admin|login).*" 200
            ^<HOST> -.*" (500|502) .*"".*"python.*"
            ^<HOST> -.*".*" 200.*"curl.*"
            ^<HOST> -.*".*" 200.*"wget.*"

# Rate limiting pentru cereri anormale
ignoreregex =
[Init]
maxlines = 10
EOF

    # Jail pentru analiză comportamentală - DOAR DACA NU EXISTA DEJA
    if [ ! -f "$FAIL2BAN_DIR/jail.d/behavioral.conf" ]; then
        cat > "$FAIL2BAN_DIR/jail.d/behavioral.conf" << 'EOF'
[behavioral-analysis]
enabled = true
port = http,https,ssh
filter = behavioral-analysis
logpath = /var/log/nginx/access.log
         /var/log/apache2/access.log
         /var/log/auth.log
maxretry = 15
findtime = 300
bantime = 3600
action = %(action_)s
EOF
        echo "[+] Behavioral Analysis configurat"
    else
        echo "[+] Behavioral Analysis deja configurat"
    fi
}

# === SISTEM DE BACKUP AUTOMAT ===
setup_backup_system() {
    echo "[*] Configurare sistem backup automat..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Script de backup
    cat > "$SCRIPT_DIR/fail2ban-backup.sh" << 'EOF'
#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="$BOUNCER_DIR/scripts"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

BACKUP_DIR="/var/backups/fail2ban"
CONF_DIR="/etc/fail2ban"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
BACKUP_FILE="$BACKUP_DIR/fail2ban_backup_$DATE.tar.gz"

echo "[*] Creare backup Fail2Ban..."
tar -czf "$BACKUP_FILE" "$CONF_DIR" /var/lib/fail2ban 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] Backup creat: $BACKUP_FILE"
    
    # Notificare succes
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="💾 Backup Fail2Ban Creat
Server: $(hostname -f)
Backup: $BACKUP_FILE
Data: $(date '+%Y-%m-%d %H:%M:%S')
Status: SUCCES ✅"
        
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
    
    # Șterge backup-uri mai vechi de 7 zile
    find "$BACKUP_DIR" -name "fail2ban_backup_*.tar.gz" -mtime +7 -delete
else
    echo "[-] Eroare la crearea backup-ului"
    
    # Notificare eroare
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="❌ Eroare Backup Fail2Ban
Server: $(hostname -f)
Data: $(date '+%Y-%m-%d %H:%M:%S')
Status: EROARE ⚠️"
        
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
    exit 1
fi
EOF

    chmod +x "$SCRIPT_DIR/fail2ban-backup.sh"
    
    # Adaugă în crontab - backup zilnic la 2 AM
    (crontab -l 2>/dev/null | grep -v "fail2ban-backup.sh"; echo "0 2 * * * $SCRIPT_DIR/fail2ban-backup.sh") | crontab -
    
    echo "[+] Sistem backup configurat (backup zilnic la 2 AM)"
}

# === THREAT INTELLIGENCE INTEGRATION ===
setup_threat_intelligence() {
    echo "[*] Configurare Threat Intelligence..."
    
    mkdir -p "$THREAT_INTEL_DIR"
    
    # Script pentru descărcare liste de amenințări
    cat > "$SCRIPT_DIR/update-threat-intel.sh" << 'EOF'
#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"
mkdir -p "$THREAT_INTEL_DIR"

echo "[*] Actualizare liste Threat Intelligence..."

# Descarcă liste de amenințări
echo "[*] Descărcare Blocklist.de..."
curl -s --connect-timeout 10 "https://lists.blocklist.de/lists/all.txt" -o "$THREAT_INTEL_DIR/blocklist_de.txt" 2>/dev/null

echo "[*] Descărcare Spamhaus DROP..."
curl -s --connect-timeout 10 "https://www.spamhaus.org/drop/drop.txt" -o "$THREAT_INTEL_DIR/spamhaus_drop.txt" 2>/dev/null

echo "[*] Descărcare Spamhaus EDROP..."
curl -s --connect-timeout 10 "https://www.spamhaus.org/drop/edrop.txt" -o "$THREAT_INTEL_DIR/spamhaus_edrop.txt" 2>/dev/null

# Combina toate listele
echo "[*] Combinare liste..."
cat "$THREAT_INTEL_DIR"/*.txt 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | sort -u > "$THREAT_INTEL_DIR/combined_threats.txt"

COUNT=$(wc -l < "$THREAT_INTEL_DIR/combined_threats.txt" 2>/dev/null || echo 0)

# Notifică actualizarea
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    MESSAGE="🔍 Threat Intelligence Actualizat
Liste IP-uri malitioase: $COUNT
Server: $(hostname -f)
Timp: $(date '+%Y-%m-%d %H:%M:%S')"
    
    export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
    "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
fi

echo "[+] Threat Intelligence actualizat: $COUNT IP-uri"
EOF

    chmod +x "$SCRIPT_DIR/update-threat-intel.sh"
    
    # Rulează prima actualizare
    $SCRIPT_DIR/update-threat-intel.sh
    
    # Programează actualizări zilnice
    (crontab -l 2>/dev/null | grep -v "update-threat-intel.sh"; echo "0 3 * * * $SCRIPT_DIR/update-threat-intel.sh") | crontab -
    
    echo "[+] Threat Intelligence configurat (actualizare zilnică la 3 AM)"
}

# === AUTO-HEALING SYSTEM ===
setup_autohealing() {
    echo "[*] Configurare sistem Auto-Healing..."
    
    cat > "$AUTO_HEAL_SCRIPT" << 'EOF'
#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

send_alert() {
    local message="$1"
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$message" >/dev/null 2>&1
    fi
}

check_and_restart_service() {
    local service="$1"
    if ! systemctl is-active --quiet "$service"; then
        echo "[!] Service $service este oprit. Repornire..."
        systemctl restart "$service"
        send_alert "🔄 Auto-Healing: Service $service repornit pe $(hostname -f)"
    fi
}

# Verifică serviciile critice
check_and_restart_service "fail2ban"
check_and_restart_service "nginx" 2>/dev/null
check_and_restart_service "apache2" 2>/dev/null

# Verifică disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    send_alert "🚨 Disk space critic: ${DISK_USAGE}% pe $(hostname -f)"
fi

# Verifică memoria
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEM_USAGE" -gt 90 ]; then
    send_alert "🚨 Memorie critică: ${MEM_USAGE}% pe $(hostname -f)"
fi

echo "[+] Auto-healing verificare completă"
EOF

    chmod +x "$AUTO_HEAL_SCRIPT"
    
    # Adaugă în crontab - verificare la fiecare 5 minute
    (crontab -l 2>/dev/null | grep -v "fail2ban_autoheal.sh"; echo "*/5 * * * * $AUTO_HEAL_SCRIPT") | crontab -
    
    echo "[+] Sistem Auto-Healing configurat"
}

# === RAPORTARE AVANSATĂ ===
setup_advanced_reporting() {
    echo "[*] Configurare raportare avansată..."
    
    cat > "$SCRIPT_DIR/fail2ban-report.sh" << 'EOF'
#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOG_FILE="/var/log/fail2ban.log"
REPORT_FILE="/tmp/fail2ban_report.txt"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
fi

generate_report() {
    echo "📊 RAPORT FAIL2BAN - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
    echo ""
    
    # Statistici generale
    echo "🔍 STATISTICI GENERALE:"
    fail2ban-client status | grep -A 50 "Jail list"
    echo ""
    
    # Top IP-uri blocate
    echo "🚨 TOP IP-URI BLOCATE (ultimele 24h):"
    grep "Ban " "$LOG_FILE" | grep "$(date '+%Y-%m-%d')" | awk '{print $NF}' | sort | uniq -c | sort -nr | head -10
    echo ""
    
    # Jails cu cele mai multe acțiuni
    echo "📈 JAILS ACTIVITATE:"
    for jail in $(fail2ban-client status | grep "Jail list" | cut -d: -f2 | sed 's/,//g'); do
        count=$(fail2ban-client status "$jail" | grep "Currently banned" | awk '{print $NF}')
        total=$(fail2ban-client status "$jail" | grep "Total banned" | awk '{print $NF}')
        echo "- $jail: $count (curent), $total (total)"
    done
    echo ""
    
    # Amenințări recente
    echo "⚠️  AMENINȚĂRI RECENTE:"
    tail -5 "$LOG_FILE" | grep -E "(Ban|WARNING|ERROR)" | tail -5
}

send_report() {
    local report="$1"
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        echo "$report" | "$NOTIFY_SCRIPT" -f - >/dev/null 2>&1
    fi
}

# Raport zilnic
if [ "$1" = "daily" ]; then
    REPORT=$(generate_report)
    send_report "$REPORT"
else
    generate_report
fi
EOF

    chmod +x "$SCRIPT_DIR/fail2ban-report.sh"
    
    # Raport zilnic la 8 AM
    (crontab -l 2>/dev/null | grep -v "fail2ban-report.sh"; echo "0 8 * * * $SCRIPT_DIR/fail2ban-report.sh daily") | crontab -
    
    echo "[+] Sistem raportare avansată configurat"
}

# === MANAGEMENT SIMPLIFICAT - INTERFAȚĂ UNIFICATĂ ===
setup_unified_interface() {
    echo "[*] Configurare interfață unificată..."
    
    cat > "$SCRIPT_DIR/security-manager.sh" << 'EOF'
#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="$BOUNCER_DIR/scripts"

case "$1" in
    status)
        echo "=== STATUS SISTEM SECURITATE ==="
        fail2ban-client status
        ;;
    stats)
        echo "=== STATISTICI DETALIATE ==="
        "$SCRIPT_DIR/fail2ban-report.sh"
        ;;
    unban)
        if [ -z "$2" ]; then
            echo "Utilizare: $0 unban <IP>"
            exit 1
        fi
        echo "[*] Deblochez IP: $2"
        fail2ban-client set sshd unbanip "$2"
        fail2ban-client set web-attacks unbanip "$2"
        fail2ban-client set auth-attacks unbanip "$2"
        fail2ban-client set web-scanners unbanip "$2"
        fail2ban-client set behavioral-analysis unbanip "$2"
        ;;
    backup)
        echo "[*] Creare backup configurație..."
        "$SCRIPT_DIR/fail2ban-backup.sh"
        ;;
    update-threat)
        echo "[*] Actualizare liste amenințări..."
        "$SCRIPT_DIR/update-threat-intel.sh"
        ;;
    report)
        echo "[*] Generez raport..."
        "$SCRIPT_DIR/fail2ban-report.sh"
        ;;
    autoheal)
        echo "[*] Rulez Auto-Healing..."
        "$SCRIPT_DIR/fail2ban_autoheal.sh"
        ;;
    *)
        echo "Security Manager - Interfață Unificată"
        echo "Comenzi disponibile:"
        echo "  status        - Status sistem"
        echo "  stats         - Statistici detaliate"
        echo "  unban IP      - Deblochează IP"
        echo "  backup        - Backup configurație"
        echo "  update-threat - Actualizează liste amenințări"
        echo "  report        - Generează raport"
        echo "  autoheal      - Rulează Auto-Healing manual"
        ;;
esac
EOF

    chmod +x "$SCRIPT_DIR/security-manager.sh"
    
    # Creează symlink global pentru ușurința utilizării
    if [ -d "/usr/local/bin" ]; then
        ln -sf "$SCRIPT_DIR/security-manager.sh" "/usr/local/bin/secmgr"
        chmod +x "/usr/local/bin/secmgr"
    fi
    
    echo "[+] Interfață unificată configurată"
    echo "[+] Utilizare: secmgr [status|stats|unban|backup|update-threat|report|autoheal]"
}

# === VERIFICARE CONFIGURARE ȘI REPORNIRE ===
setup_and_verify_fail2ban() {
    echo "[*] Verificare și pornire Fail2Ban..."
    
    # Verifică configurația
    echo "[*] Verific configurația Fail2Ban..."
    if fail2ban-client -t; then
        echo "[+] Configurația Fail2Ban este validă"
    else
        echo "[-] Configurația Fail2Ban are erori"
        echo "[*] Repar configurația..."
        
        # Șterge fișierele problematice
        rm -f "$FAIL2BAN_DIR/jail.d/behavioral.conf"
        fail2ban-client -t
    fi
    
    # Porneste Fail2Ban
    echo "[*] Pornesc Fail2Ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    # Așteaptă și verifică statusul
    sleep 5
    
    if systemctl is-active --quiet fail2ban; then
        echo "[+] Fail2Ban rulează cu succes"
        return 0
    else
        echo "[-] Fail2Ban nu rulează"
        echo "[*] Verific erorile..."
        journalctl -u fail2ban -n 10 --no-pager
        return 1
    fi
}

# === VERIFICARE ȘI TESTARE EXTINSĂ ===
verify_and_test() {
    echo "[*] Verificare și testare extinsă..."
    
    # Testează toate componentele
    echo "[*] Testare servicii..."
    if systemctl is-active fail2ban; then
        echo "[+] Fail2Ban - ACTIV"
    else
        echo "[-] Fail2Ban - INACTIV"
        return 1
    fi
    
    echo "[*] Testare scripturi..."
    [ -x "$SCRIPT_DIR/fail2ban-backup.sh" ] && echo "[+] Backup Script - OK" || echo "[-] Backup Script - FAIL"
    [ -x "$SCRIPT_DIR/update-threat-intel.sh" ] && echo "[+] Threat Intel - OK" || echo "[-] Threat Intel - FAIL"
    [ -x "$SCRIPT_DIR/fail2ban-report.sh" ] && echo "[+] Reporting - OK" || echo "[-] Reporting - FAIL"
    [ -x "$AUTO_HEAL_SCRIPT" ] && echo "[+] Auto-Healing - OK" || echo "[-] Auto-Healing - FAIL"
    [ -x "$SCRIPT_DIR/security-manager.sh" ] && echo "[+] Security Manager - OK" || echo "[-] Security Manager - FAIL"
    
    # Testează notificările
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        echo "[*] Testare notificări..."
        "$NOTIFY_SCRIPT" "✅ Sistem securitate configurat cu succes pe $(hostname -f)

🔒 Componente active:
✓ Protecție Multi-Nivel
✓ Threat Intelligence  
✓ Auto-Healing
✓ Raportare Avansată
✓ Backup Automat
✓ Behavioral Analysis
✓ Management Simplificat

📁 Scripturi: $SCRIPT_DIR
Status: OPERATIONAL 🟢" >/dev/null 2>&1 && echo "[+] Notificări - OK" || echo "[-] Notificări - FAIL"
    fi
    
    echo "[+] Toate testele finalizate"
    return 0
}

# === CONFIGURARE SISTEM NOTIFICĂRI TELEGRAM AVANSAT ===
setup_advanced_telegram_system() {
    echo "[*] Configurare sistem notificări Telegram avansat..."
    
    # Script unic pentru toate notificările cu logică inteligentă
    cat > "$SCRIPT_DIR/fail2ban-telegram-intelligent.sh" << 'EOF'
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
EOF

    chmod +x "$SCRIPT_DIR/fail2ban-telegram-intelligent.sh"

    # === ACȚIUNE TELEGRAM PENTRU FAIL2BAN ===
    cat > "$FAIL2BAN_DIR/action.d/telegram-intelligent.conf" << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /etc/automation-web-hosting/scripts/fail2ban-telegram-intelligent.sh <name> ban <ip> <bantime>
actionunban = /etc/automation-web-hosting/scripts/fail2ban-telegram-intelligent.sh <name> unban <ip>

[Init]
EOF

    # === CONFIGURARE JAILS CU NOTIFICĂRI INTELIGENTE ===
    echo "[*] Actualizez jails cu notificări inteligente..."
    
    # Configurație jail.local completă
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
action = %(action_)s
         telegram-intelligent

[web-attacks]
enabled = true
port = http,https
filter = web-attacks
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 3
bantime = 7200
action = %(action_)s
         telegram-intelligent

[auth-attacks]
enabled = true
port = http,https,ssh
filter = auth-attacks
logpath = /var/log/auth.log
          /var/log/apache2/error.log
maxretry = 3
bantime = 7200
action = %(action_)s
         telegram-intelligent

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
         telegram-intelligent

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
         telegram-intelligent
EOF

    # Configurație behavioral analysis
    cat > "$FAIL2BAN_DIR/jail.d/behavioral.conf" << 'EOF'
[behavioral-analysis]
enabled = true
port = http,https,ssh
filter = behavioral-analysis
logpath = /var/log/nginx/access.log
         /var/log/apache2/access.log
         /var/log/auth.log
maxretry = 15
findtime = 300
bantime = 3600
action = %(action_)s
         telegram-intelligent
EOF

    # === CONFIGURARE ESCALATION PENTRU THREAT INTELLIGENCE ===
    cat > "$FAIL2BAN_DIR/jail.d/threat-intelligence.conf" << 'EOF'
[threat-intelligence-ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 1
findtime = 600
bantime = 2592000
action = %(action_)s
         telegram-intelligent

[threat-intelligence-web]
enabled = true
port = http,https
filter = web-attacks
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 1
findtime = 600
bantime = 2592000
action = %(action_)s
         telegram-intelligent

[threat-intelligence-auth]
enabled = true
port = http,https,ssh
filter = auth-attacks
logpath = /var/log/auth.log
          /var/log/apache2/error.log
maxretry = 1
findtime = 600
bantime = 2592000
action = %(action_)s
         telegram-intelligent
EOF

    echo "[+] Sistem notificări inteligente configurat complet cu suport threat intelligence"
}

# === EXECUȚIE PRINCIPALĂ ===
main() {
    echo "=================================================="
    echo "    SISTEM AVANSAT SECURITATE FAIL2BAN"
    echo "=================================================="
    echo "📁 Director scripturi: $SCRIPT_DIR"
    echo "✅ Protecție Multi-Nivel - De la atacuri simple la DDoS"
    echo "✅ Threat Intelligence - Integrare cu surse externe" 
    echo "✅ Auto-Healing - Sistemul se repară singur"
    echo "✅ Raportare Avansată - Insights detaliate"
    echo "✅ Backup Automat - Siguranță configurație"
    echo "✅ Behavioral Analysis - Detecție comportament anormal"
    echo "✅ Management Simplificat - Interfață unificată"
    echo "=================================================="
    
    # Verificare root
    if [ "$EUID" -ne 0 ]; then
        echo "[-] Rulează scriptul ca root: sudo $0"
        exit 1
    fi
    
    # Curățare configurație veche
    clean_old_config
    
    # Creare director scripturi
    create_script_directory
    
    # Instalare dependențe
    check_dependencies
    
    # Setup componente de bază
    setup_basic_fail2ban
    # Setup acțiuni Telegram
    setup_advanced_telegram_system
	
    # Setup componente avansate
    setup_backup_system
    setup_threat_intelligence
    setup_behavioral_analysis
    setup_autohealing
    setup_advanced_reporting
    setup_unified_interface

    # Verificare și pornire
    if setup_and_verify_fail2ban; then
        # Verificare finală
        if verify_and_test; then
            echo ""
            echo "=================================================="
            echo "✅ SISTEM SECURITATE AVANSAT CONFIGURAT CU SUCCES!"
            echo "=================================================="
        else
            echo ""
            echo "=================================================="
            echo "⚠️  SISTEM CONFIGURAT CU AVERTISMENTE"
            echo "=================================================="
        fi
    else
        echo ""
        echo "=================================================="
        echo "❌ CONFIGURARE EȘUATĂ - VERIFICĂ EROARILE"
        echo "=================================================="
        exit 1
    fi
    
    echo ""
    echo "📁 LOCAȚIE SCRIPTURI: $SCRIPT_DIR"
    echo ""
    echo "🔧 COMENZI MANAGEMENT:"
    echo "   secmgr status        - Status sistem"
    echo "   secmgr stats         - Statistici detaliate" 
    echo "   secmgr unban IP      - Deblochează IP"
    echo "   secmgr backup        - Backup configurație"
    echo "   secmgr update-threat - Actualizează amenințări"
    echo "   secmgr report        - Raport complet"
    echo "   secmgr autoheal      - Auto-Healing manual"
    echo ""
    echo "📊 MONITORIZARE:"
    echo "   tail -f /var/log/fail2ban.log"
    echo "   fail2ban-client status"
    echo ""
    echo "🔄 SERVICII AUTOMATE:"
    echo "   Backup zilnic (2 AM)       - $SCRIPT_DIR/fail2ban-backup.sh"
    echo "   Threat Intel update (3 AM) - $SCRIPT_DIR/update-threat-intel.sh" 
    echo "   Raport zilnic (8 AM)       - $SCRIPT_DIR/fail2ban-report.sh"
    echo "   Auto-Healing (la 5 minute) - $AUTO_HEAL_SCRIPT"
    echo "=================================================="
    
    # Afișare conținut director scripturi
    echo ""
    echo "📋 SCRIPTURI INSTALATE:"
    ls -la "$SCRIPT_DIR"
}

# Rulează scriptul principal
main "$@"
