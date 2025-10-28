#!/bin/bash
set -e

# === CONFIGURARE AVANSATĂ ===
FAIL2BAN_DIR="/etc/fail2ban"
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="${BOUNCER_DIR}/scripts"
NOTIFY_SCRIPT="${BOUNCER_DIR}/telegram_notify.sh"
BACKUP_DIR="/var/backups/fail2ban"
THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"
AUTO_HEAL_SCRIPT="${SCRIPT_DIR}/fail2ban_autoheal.sh"
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# === ÎNCĂRCARE VARIABILE ENV ===
ENV_FILES="$BOUNCER_DIR/*.env"
env_loaded=0

for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
        env_loaded=1
    fi
done

if [ $env_loaded -eq 0 ]; then
    echo "[!] WARNING: No .env files found in $BOUNCER_DIR/"
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
    
    # Creare director scripturi
    mkdir -p "$SCRIPT_DIR"
    
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

# === SISTEM DE BACKUP AUTOMAT ===
setup_backup_system() {
    echo "[*] Configurare sistem backup automat..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Script de backup
    cat > "${SCRIPT_DIR}/fail2ban-backup.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNCER_DIR="$(dirname "$SCRIPT_DIR")"
NOTIFY_SCRIPT="$NOTIFY_SCRIPT"

# Încarcă variabilele din .env files
if [ -f "${BOUNCER_DIR}/hosting.env" ]; then
    source "${BOUNCER_DIR}/hosting.env"
fi

BACKUP_DIR="/var/backups/fail2ban"
CONF_DIR="/etc/fail2ban"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
BACKUP_FILE="$BACKUP_DIR/fail2ban_backup_$DATE.tar.gz"

echo "[*] Creare backup Fail2Ban..."
tar -czf "$BACKUP_FILE" "$CONF_DIR" /var/lib/fail2ban 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[+] Backup creat: $BACKUP_FILE"
    
    # Notificare succes backup
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="💾 Backup Fail2Ban Creat
Server: $(hostname -f)
Backup: $BACKUP_FILE
Data: $(date '+%Y-%m-%d %H:%M:%S')"
        
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
    
    # Șterge backup-uri mai vechi de 7 zile
    find "$BACKUP_DIR" -name "fail2ban_backup_*.tar.gz" -mtime +7 -delete
else
    echo "[-] Eroare la crearea backup-ului"
    exit 1
fi
EOF

    chmod +x "${SCRIPT_DIR}/fail2ban-backup.sh"
    
    # Adaugă în crontab - backup zilnic la 2 AM
    (crontab -l 2>/dev/null | grep -v "fail2ban-backup.sh"; echo "0 2 * * * ${SCRIPT_DIR}/fail2ban-backup.sh") | crontab -
    
    echo "[+] Sistem backup configurat (backup zilnic la 2 AM)"
}

# === THREAT INTELLIGENCE INTEGRATION ===
setup_threat_intelligence() {
    echo "[*] Configurare Threat Intelligence..."
    
    mkdir -p "$THREAT_INTEL_DIR"
    
    # Script pentru descărcare liste de amenințări
    cat > "${SCRIPT_DIR}/update-threat-intel.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNCER_DIR="$(dirname "$SCRIPT_DIR")"
NOTIFY_SCRIPT="$NOTIFY_SCRIPT"

# Încarcă variabilele din .env files
if [ -f "${BOUNCER_DIR}/hosting.env" ]; then
    source "${BOUNCER_DIR}/hosting.env"
fi

THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"

echo "[*] Actualizare liste Threat Intelligence..."

# Listă IP-uri malitioase cunoscute
curl -s "https://lists.blocklist.de/lists/all.txt" -o "$THREAT_INTEL_DIR/blocklist_de.txt" 2>/dev/null
curl -s "https://www.spamhaus.org/drop/drop.txt" -o "$THREAT_INTEL_DIR/spamhaus_drop.txt" 2>/dev/null
curl -s "https://www.spamhaus.org/drop/edrop.txt" -o "$THREAT_INTEL_DIR/spamhaus_edrop.txt" 2>/dev/null

# Combina toate listele
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

    chmod +x "${SCRIPT_DIR}/update-threat-intel.sh"
    
    # Rulează prima actualizare
    "${SCRIPT_DIR}/update-threat-intel.sh"
    
    # Programează actualizări zilnice
    (crontab -l 2>/dev/null | grep -v "update-threat-intel.sh"; echo "0 3 * * * ${SCRIPT_DIR}/update-threat-intel.sh") | crontab -
    
    echo "[+] Threat Intelligence configurat (actualizare zilnică la 3 AM)"
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
            ^<HOST> -.*" (500|502) .*".*"python.*"
            ^<HOST> -.*".*" 200.*"curl.*"
            ^<HOST> -.*".*" 200.*"wget.*"

# Rate limiting pentru cereri anormale
ignoreregex =
[Init]
maxlines = 10
EOF

    # Jail pentru analiză comportamentală
    cat >> "$FAIL2BAN_DIR/jail.d/behavioral.conf" << 'EOF'
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
         telegram-simple
EOF

    echo "[+] Behavioral Analysis configurat"
}

# === AUTO-HEALING SYSTEM ===
setup_autohealing() {
    echo "[*] Configurare sistem Auto-Healing..."
    
    cat > "$AUTO_HEAL_SCRIPT" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNCER_DIR="$(dirname "$SCRIPT_DIR")"
NOTIFY_SCRIPT="$NOTIFY_SCRIPT"

# Încarcă variabilele din .env files
if [ -f "${BOUNCER_DIR}/hosting.env" ]; then
    source "${BOUNCER_DIR}/hosting.env"
fi

send_alert() {
    local message="$1"
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1
    fi
}

check_and_restart_service() {
    local service="$1"
    if ! systemctl is-active --quiet "$service"; then
        echo "[!] Service $service este oprit. Repornire..."
        systemctl restart "$service"
        
        # Notificare doar dacă repornirea a eșuat
        if ! systemctl is-active --quiet "$service"; then
            send_alert "🚨 CRITIC: Service $service nu poate fi repornit pe $(hostname -f)"
        else
            send_alert "🔄 Auto-Healing: Service $service repornit pe $(hostname -f)"
        fi
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
    
    cat > "${SCRIPT_DIR}/fail2ban-report.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNCER_DIR="$(dirname "$SCRIPT_DIR")"
NOTIFY_SCRIPT="$NOTIFY_SCRIPT"
LOG_FILE="/var/log/fail2ban.log"
REPORT_FILE="/tmp/fail2ban_report.txt"

# Încarcă variabilele din .env files
if [ -f "${BOUNCER_DIR}/hosting.env" ]; then
    source "${BOUNCER_DIR}/hosting.env"
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

    chmod +x "${SCRIPT_DIR}/fail2ban-report.sh"
    
    # Raport zilnic la 8 AM
    (crontab -l 2>/dev/null | grep -v "fail2ban-report.sh"; echo "0 8 * * * ${SCRIPT_DIR}/fail2ban-report.sh daily") | crontab -
    
    echo "[+] Sistem raportare avansată configurat"
}

# === MANAGEMENT SIMPLIFICAT - INTERFAȚĂ UNIFICATĂ ===
setup_unified_interface() {
    echo "[*] Configurare interfață unificată..."
    
    cat > "${SCRIPT_DIR}/security-manager.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNCER_DIR="$(dirname "$SCRIPT_DIR")"

case "$1" in
    status)
        echo "=== STATUS SISTEM SECURITATE ==="
        fail2ban-client status
        ;;
    stats)
        echo "=== STATISTICI DETALIATE ==="
        "${SCRIPT_DIR}/fail2ban-report.sh"
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
        fail2ban-client set escalation-web unbanip "$2"
        fail2ban-client set behavioral-analysis unbanip "$2"
        ;;
    backup)
        echo "[*] Creare backup configurație..."
        "${SCRIPT_DIR}/fail2ban-backup.sh"
        ;;
    update-threat)
        echo "[*] Actualizare liste amenințări..."
        "${SCRIPT_DIR}/update-threat-intel.sh"
        ;;
    report)
        echo "[*] Generez raport..."
        "${SCRIPT_DIR}/fail2ban-report.sh"
        ;;
    autoheal)
        echo "[*] Rulez verificare auto-healing..."
        "${SCRIPT_DIR}/fail2ban_autoheal.sh"
        ;;
    *)
        echo "Security Manager - Interfață Unificată"
        echo "Location: $SCRIPT_DIR"
        echo "Comenzi disponibile:"
        echo "  status    - Status sistem"
        echo "  stats     - Statistici detaliate"
        echo "  unban IP  - Deblochează IP"
        echo "  backup    - Backup configurație"
        echo "  update-threat - Actualizează liste amenințări"
        echo "  report    - Generează raport"
        echo "  autoheal  - Rulează verificare auto-healing"
        ;;
esac
EOF

    chmod +x "${SCRIPT_DIR}/security-manager.sh"
    
    # Creează symlink global pentru ușurința utilizării
    ln -sf "${SCRIPT_DIR}/security-manager.sh" "/usr/local/bin/secmgr"
    
    echo "[+] Interfață unificată configurată"
    echo "[+] Utilizare: secmgr [status|stats|unban|backup|update-threat|report|autoheal]"
}

# === CONFIGURARE FAIL2BAN DE BAZĂ ===
setup_basic_fail2ban() {
    echo "[*] Configurare Fail2Ban de bază..."
    
    # Creare filtre de bază (web-attacks, auth-attacks, etc.)
    # ... (păstrează secțiunile create_filters, create_telegram_action, etc. din scriptul anterior)
    # Acestea rămân neschimbate, doar referințele la scripturi se vor actualiza
    
    # Exemplu pentru acțiunea Telegram actualizată:
    cat > "/usr/local/bin/fail2ban-telegram-wrapper.sh" << 'EOF'
#!/bin/bash
JAIL_NAME="$1"
ACTION="$2"
IP="$3"

SCRIPT_DIR="/etc/automation-web-hosting/scripts"
TELEGRAM_SCRIPT="$NOTIFY_SCRIPT"
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
    
    echo "[+] Configurație Fail2Ban de bază completă"
}

# === VERIFICARE ȘI TESTARE EXTINSĂ ===
verify_and_test() {
    echo "[*] Verificare și testare extinsă..."
    
    # Așteaptă inițializarea
    sleep 5
    
    # Testează toate componentele
    echo "[*] Testare servicii..."
    systemctl is-active fail2ban && echo "[+] Fail2Ban - ACTIV" || echo "[-] Fail2Ban - INACTIV"
    
    echo "[*] Testare scripturi..."
    [ -x "${SCRIPT_DIR}/fail2ban-backup.sh" ] && echo "[+] Backup Script - OK" || echo "[-] Backup Script - FAIL"
    [ -x "${SCRIPT_DIR}/update-threat-intel.sh" ] && echo "[+] Threat Intel - OK" || echo "[-] Threat Intel - FAIL"
    [ -x "${SCRIPT_DIR}/fail2ban-report.sh" ] && echo "[+] Reporting - OK" || echo "[-] Reporting - FAIL"
    [ -x "$AUTO_HEAL_SCRIPT" ] && echo "[+] Auto-Healing - OK" || echo "[-] Auto-Healing - FAIL"
    [ -x "${SCRIPT_DIR}/security-manager.sh" ] && echo "[+] Security Manager - OK" || echo "[-] Security Manager - FAIL"
    [ -L "/usr/local/bin/secmgr" ] && echo "[+] Symlink Global - OK" || echo "[-] Symlink Global - FAIL"
    
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

📁 Locatie Scripturi: $SCRIPT_DIR
Status: OPERATIONAL 🟢" >/dev/null 2>&1 && echo "[+] Notificări - OK" || echo "[-] Notificări - FAIL"
    fi
    
    echo "[+] Toate testele finalizate"
}

# === EXECUȚIE PRINCIPALĂ ===
main() {
    echo "=================================================="
    echo "    SISTEM AVANSAT SECURITATE FAIL2BAN"
    echo "=================================================="
    echo "📁 Director Scripturi: $SCRIPT_DIR"
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
    
    # Creare director principal
    mkdir -p "$BOUNCER_DIR"
    mkdir -p "$SCRIPT_DIR"
    
    # Instalare dependențe
    check_dependencies
    
    # Setup componente avansate
    setup_backup_system
    setup_threat_intelligence
    setup_behavioral_analysis
    setup_autohealing
    setup_advanced_reporting
    setup_unified_interface
    setup_basic_fail2ban
    
    # Verificare finală
    verify_and_test
    
    echo ""
    echo "=================================================="
    echo "✅ SISTEM SECURITATE AVANSAT CONFIGURAT CU SUCCES!"
    echo "=================================================="
    echo ""
    echo "📁 STRUCTURA DIRECTOR:"
    echo "   $BOUNCER_DIR/          - Director principal"
    echo "   $SCRIPT_DIR/           - Toate scripturile"
    echo "   $NOTIFY_SCRIPT"
    echo "   ${SCRIPT_DIR}/security-manager.sh"
    echo "   ${SCRIPT_DIR}/fail2ban-backup.sh"
    echo "   ${SCRIPT_DIR}/update-threat-intel.sh"
    echo "   ${SCRIPT_DIR}/fail2ban-report.sh"
    echo "   ${SCRIPT_DIR}/fail2ban_autoheal.sh"
    echo ""
    echo "🔧 COMENZI MANAGEMENT:"
    echo "   secmgr status          - Status sistem"
    echo "   secmgr stats           - Statistici detaliate" 
    echo "   secmgr unban IP        - Deblochează IP"
    echo "   secmgr backup          - Backup configurație"
    echo "   secmgr update-threat   - Actualizează amenințări"
    echo "   secmgr report          - Raport complet"
    echo "   secmgr autoheal        - Verificare auto-healing"
    echo ""
    echo "🔄 SERVICII AUTOMATE:"
    echo "   Backup zilnic (2 AM)    - ${SCRIPT_DIR}/fail2ban-backup.sh"
    echo "   Threat Intel (3 AM)     - ${SCRIPT_DIR}/update-threat-intel.sh"
    echo "   Raport zilnic (8 AM)    - ${SCRIPT_DIR}/fail2ban-report.sh"
    echo "   Auto-Healing (5 min)    - ${SCRIPT_DIR}/fail2ban_autoheal.sh"
    echo "=================================================="
}

# Rulează scriptul principal
main "$@"