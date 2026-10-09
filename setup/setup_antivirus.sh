#!/bin/bash
# Security Stack Installer for Ubuntu 22.04 with Telegram Notifications
# Components: ClamAV + Maldet + rkhunter + inotify-tools

set -e

# =============================================================================
# CONFIGURATION - Sursa din fișierele .env
# =============================================================================

# Încarcă variabilele de environment din fișierele .env
BOUNCER_DIR="${BOUNCER_DIR:-/etc/automation-web-hosting}"
ENV_FILES="$BOUNCER_DIR/*.env"

# Încarcă toate fișierele .env
for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
    fi
done

# Setări default dacă variabilele nu sunt definite
SCRIPT_DIR="${SCRIPT_DIR:-$BOUNCER_DIR/scripts}"
LOG_DIR="${LOG_DIR:-$BOUNCER_DIR/log}"
SERVICE_DIR="${SERVICE_DIR:-/etc/systemd/system}"
NOTIFY_SCRIPT="${NOTIFY_SCRIPT:-$BOUNCER_DIR/telegram_notify.sh}"
REALTIME_SCAN_PATHS="${REALTIME_SCAN_PATHS:-/var/www}"
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/quarantine}"

# Libraria comuna: multi-OS (apt/dnf), servicii ClamAV per distributie
# shellcheck disable=SC1091
[ -f "$SCRIPT_DIR/common.sh" ] && source "$SCRIPT_DIR/common.sh"
[ -f "$BOUNCER_DIR/scripts/common.sh" ] && source "$BOUNCER_DIR/scripts/common.sh"
if type detect_os >/dev/null 2>&1; then
    detect_os
    CLAM_SVC=$(clam_daemon_service)
    FRESH_SVC=$(freshclam_service)
    CLAMD_SOCK=$(clamd_socket_path)
else
    CLAM_SVC="clamav-daemon"
    FRESH_SVC="clamav-freshclam"
    CLAMD_SOCK="/run/clamav/clamd.ctl"
fi

# =============================================================================
# FUNCTIONS
# =============================================================================

send_telegram_notification() {
    local message="$1"
    if [ -f "$NOTIFY_SCRIPT" ] && [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        bash "$NOTIFY_SCRIPT" "$message" > /dev/null 2>&1 || true
    else
        echo "📢 Telegram notification: $message"
    fi
}

# Comentează linia WEB_CMD din rkhunter.conf dacă există
fix_rkhunter_web_cmd() {
    local conf_file="/etc/rkhunter.conf"
    if [ -f "$conf_file" ]; then
        if grep -q '^WEB_CMD=' "$conf_file"; then
            echo "[*] Commenting WEB_CMD in rkhunter.conf to avoid warnings..."
            sed -i 's/^WEB_CMD=/##WEB_CMD=/' "$conf_file"
        fi
    fi
}

check_dependencies() {
    # curl/wget via package manager (apt sau dnf); systemctl trebuie sa existe
    if type pkg_install >/dev/null 2>&1; then
        pkg_install curl wget || return 1
    fi
    for dep in curl wget systemctl; do
        if ! command -v "$dep" &> /dev/null; then
            echo "❌ Dependency $dep not found"
            return 1
        fi
    done
    return 0
}

setup_directories() {
    mkdir -p "$BOUNCER_DIR" "$SCRIPT_DIR" "$LOG_DIR" "$QUARANTINE_DIR"
    chmod 755 "$BOUNCER_DIR" "$SCRIPT_DIR"
    chmod 700 "$LOG_DIR" "$QUARANTINE_DIR"
}

# Verifică dacă un pachet este deja instalat (nume Debian; mapare automata RHEL)
is_package_installed() {
    local package="$1"
    if type pkg_installed >/dev/null 2>&1; then
        pkg_installed "$package"
    elif command -v dpkg &> /dev/null; then
        dpkg -l | grep -q "^ii.*$package"
    else
        rpm -q "$package" &> /dev/null
    fi
}

# Instaleaza pachete prin abstractia multi-OS (cu fallback legacy)
os_install() {
    if type pkg_install >/dev/null 2>&1; then
        pkg_install "$@"
    elif command -v apt-get &> /dev/null; then
        apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
    else
        dnf install -y "$@" || yum install -y "$@"
    fi
}

# Verifică dacă un serviciu este deja activ
is_service_active() {
    local service="$1"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Verifică dacă un fișier/director există
is_component_installed() {
    local component="$1"
    local path="$2"
    
    case "$component" in
        "clamav")
            if command -v clamscan &> /dev/null && is_service_active "$CLAM_SVC"; then
                return 0
            fi
            ;;
        "maldet")
            if [ -f "/usr/local/maldetect/maldet" ] || [ -f "/usr/local/sbin/maldet" ]; then
                return 0
            fi
            ;;
        "rkhunter")
            if command -v rkhunter &> /dev/null; then
                return 0
            fi
            ;;
        "inotify-tools")
            if command -v inotifywait &> /dev/null; then
                return 0
            fi
            ;;
        "realtime-service")
            if [ -f "$SERVICE_DIR/realtime-monitor.service" ] && is_service_active "realtime-monitor.service"; then
                return 0
            fi
            ;;
    esac
    return 1
}

# =============================================================================
# INSTALLATION SECTIONS
# =============================================================================

install_clamav() {
    if is_component_installed "clamav"; then
        echo "✅ ClamAV is already installed and running - skipping installation"
        return 0
    fi

    echo "[*] Installing ClamAV + Daemon + Freshclam (OS: ${HG_OS_FAMILY:-auto})..."
    os_install clamav clamav-daemon clamav-freshclam

    send_telegram_notification "🔧 ClamAV installed successfully on $(hostname)"

    echo "[*] Stopping services for initial update..."
    systemctl stop "$FRESH_SVC" || true
    freshclam

    echo "[*] Configuring ClamAV daemon..."
    systemctl enable "$CLAM_SVC" "$FRESH_SVC"
    systemctl start "$CLAM_SVC" "$FRESH_SVC"
    
    # Așteptă puțin pentru a se asigura că serviciul a pornit
    sleep 5
    
    # Verifică dacă instalarea a reușit
    if is_component_installed "clamav"; then
        echo "✅ ClamAV installed successfully"
    else
        echo "❌ ClamAV installation failed"
        return 1
    fi
}

install_inotify_tools() {
    if is_component_installed "inotify-tools"; then
        echo "✅ inotify-tools is already installed - skipping installation"
        return 0
    fi

    echo "[*] Installing inotify-tools..."
    os_install inotify-tools
    
    if is_component_installed "inotify-tools"; then
        echo "✅ inotify-tools installed successfully"
        send_telegram_notification "👁️ inotify-tools installed on $(hostname)"
    else
        echo "❌ inotify-tools installation failed"
        return 1
    fi
}

install_rkhunter() {
    if is_component_installed "rkhunter"; then
        echo "✅ rkhunter is already installed - skipping installation"
        # Actualizează totuși baza de date
        rkhunter --update --propupd || echo "⚠️ rkhunter update encountered warnings"
        return 0
    fi

    echo "[*] Installing rkhunter..."
    os_install rkhunter

    echo "[*] Updating rkhunter data files..."
    rkhunter --update || echo "⚠️ rkhunter update encountered warnings, check /var/log/rkhunter.log"

    echo "[*] Updating rkhunter properties database..."
    rkhunter --propupd

    # Activează timer-ul dacă există
    if systemctl list-unit-files | grep -q rkhunter.timer; then
        systemctl enable rkhunter.timer || true
        systemctl start rkhunter.timer || true
    fi

    if is_component_installed "rkhunter"; then
        echo "✅ rkhunter installed successfully"
        send_telegram_notification "🕵️ rkhunter installed and updated on $(hostname)"
    else
        echo "❌ rkhunter installation failed"
        return 1
    fi
}

install_maldet() {
    if is_component_installed "maldet"; then
        echo "✅ Maldet is already installed - skipping installation"
        return 0
    fi

    echo "[*] Installing Maldet..."
    
    cd /usr/local/src || { echo "❌ Cannot cd to /usr/local/src"; return 1; }
    
    # Descărcare arhivă
    wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz -O maldetect-current.tar.gz || { echo "❌ Download failed"; return 1; }
    
    # Extrage arhiva
    tar -xzf maldetect-current.tar.gz || { echo "❌ Extraction failed"; return 1; }
    
    # Găsește directorul exact extras
    MALDET_DIR=$(tar -tzf maldetect-current.tar.gz | head -1 | cut -f1 -d"/")
    
    if [ -z "$MALDET_DIR" ] || [ ! -d "$MALDET_DIR" ]; then
        echo "❌ Extracted maldetect directory not found"
        return 1
    fi
    
    # Intră în director și instalează
    cd "$MALDET_DIR" || { echo "❌ Could not cd into $MALDET_DIR"; return 1; }
    ./install.sh || { echo "❌ Maldet install.sh failed"; return 1; }
    
    echo "[*] Configuring Maldet..."
    CONF="/usr/local/maldetect/conf.maldet"
    
    if [ -f "$CONF" ]; then
        # Backup configurație originală
        cp "$CONF" "$CONF.backup" || true
        
        # Configurare optimizată
        sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$CONF"
        # Socketul difera pe RHEL (/run/clamd.scan/clamd.sock) — escape pentru sed
        _sock_esc=$(echo "$CLAMD_SOCK" | sed 's|/|\\/|g')
        sed -i "s/^clamd_socket=.*/clamd_socket=\"$_sock_esc\"/" "$CONF"
        sed -i 's/^email_alert=.*/email_alert="0"/' "$CONF"
        sed -i 's/^quar_hits=.*/quar_hits="1"/' "$CONF"
        sed -i 's/^quar_clean=.*/quar_clean="1"/' "$CONF"
        sed -i 's/^quarantine_hits=.*/quarantine_hits="1"/' "$CONF"
        sed -i 's/^quar_suspend_user=.*/quar_suspend_user="1"/' "$CONF"
        sed -i 's/^scan_max_size=.*/scan_max_size="20480"/' "$CONF"
        sed -i 's/^scan_archive_maxsize=.*/scan_archive_maxsize="10240"/' "$CONF"
    else
        echo "⚠️ Maldet configuration file not found: $CONF"
    fi
    
    if is_component_installed "maldet"; then
        echo "✅ Maldet installed successfully"
        send_telegram_notification "🔍 Maldet installed and configured on $(hostname)"
    else
        echo "❌ Maldet installation failed"
        return 1
    fi
}

create_systemd_service() {
    if is_component_installed "realtime-service"; then
        echo "✅ realtime-monitor service is already installed and running - skipping creation"
        return 0
    fi

    echo "[*] Creating realtime-monitor systemd service..."
    
    # Folosește calea din variabilele de environment pentru scripturi
    local realtime_script="${REALTIME_SCRIPT:-$SCRIPT_DIR/realtime-scan.sh}"
    
    # Verifică dacă scriptul realtime există
    if [ ! -f "$realtime_script" ]; then
        echo "⚠️ Realtime script not found: $realtime_script"
        echo "⚠️ Service will be created but won't work until script is created"
    fi
    
    cat > "$SERVICE_DIR/realtime-monitor.service" << EOF
[Unit]
Description=Real-time File System Malware Monitor (low-priority)
After=network.target $CLAM_SVC.service
Requires=$CLAM_SVC.service

[Service]
Type=simple
ExecStart=$realtime_script
Restart=always
RestartSec=30
User=root
# Limite anti-blocare: max 30% CPU, 300M RAM, IO/CPU minime
CPUQuota=30%
MemoryMax=300M
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    if [ -f "$SERVICE_DIR/realtime-monitor.service" ]; then
        echo "✅ realtime-monitor service created successfully"
    else
        echo "❌ Failed to create realtime-monitor service"
        return 1
    fi
}

setup_cron_jobs() {
    echo "[*] Setting up OPTIMIZED cron jobs (staggered, low priority)..."

    local daily_script="${DAILY_SCAN_SCRIPT:-$SCRIPT_DIR/daily-scan.sh}"
    local full_script="${FULL_SCAN_SCRIPT:-$SCRIPT_DIR/full-scan.sh}"

    local tmpcron
    tmpcron=$(mktemp)
    # Curata intrarile vechi (gramada 00:00/04:00/05:00/06:00)
    (crontab -l 2>/dev/null | grep -v "$daily_script" | grep -v "$full_script" | grep -v "system_scan" \
        | grep -v "freshclam" | grep -v "maldet -u" | grep -v "rkhunter --update") > "$tmpcron" || true

    cat >> "$tmpcron" << EOF

# HOSTINGGUARD OPTIMIZED (vezi scripts/crontab.optimized)
30 2 * * * /usr/bin/flock -n /run/hg-cron-daily.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $daily_script >> $LOG_DIR/daily-cron.log 2>&1
0 4 1-7 * 0 /usr/bin/flock -n /run/hg-cron-full.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $full_script >> $LOG_DIR/full-cron.log 2>&1
15 5 1-7 * 1 /usr/bin/nice -n 19 /usr/bin/ionice -c3 /usr/local/maldetect/maldet -u > /dev/null 2>&1
EOF
    crontab "$tmpcron"
    rm -f "$tmpcron"

    echo "✅ Cron jobs set up (daily 02:30, full LUNAR, fara freshclam/rkhunter in cron)"
}

start_services() {
    echo "[*] Starting services..."
    
    # Pornește serviciul realtime-monitor dacă există
    if [ -f "$SERVICE_DIR/realtime-monitor.service" ]; then
        systemctl enable realtime-monitor.service || echo "⚠️ Failed to enable realtime-monitor.service"
        
        if systemctl start realtime-monitor.service; then
            echo "✅ realtime-monitor service started successfully"
            send_telegram_notification "✅ Realtime-monitor service started successfully on $(hostname)"
        else
            echo "❌ Failed to start realtime-monitor service"
            send_telegram_notification "❌ Realtime-monitor service failed to start on $(hostname)"
        fi
    else
        echo "⚠️ realtime-monitor.service not found - skipping start"
    fi
    
    # Asigură-te că ClamAV este running
    if is_service_active "$CLAM_SVC"; then
        echo "✅ ClamAV daemon is running"
    else
        echo "⚠️ ClamAV daemon is not running - attempting to start..."
        systemctl start "$CLAM_SVC" || echo "❌ Failed to start ClamAV daemon"
    fi
}

# =============================================================================
# MAIN INSTALLATION
# =============================================================================

main() {
    echo "[*] Starting Security Stack Installation..."
    echo "[*] Checking existing installations..."
    
    # Verificări inițiale
    check_dependencies
    setup_directories
    
    # Instalare componente (cu skip dacă sunt deja instalate)
    install_clamav
    install_inotify_tools
    fix_rkhunter_web_cmd
    install_rkhunter
    install_maldet
    
    # Configurare servicii și cron
    create_systemd_service
    setup_cron_jobs
    start_services
    
    # Raport final
    echo ""
    echo "[+] Security Stack Installation Summary:"
    echo "======================================================"
    
    local installed_components=()
    local failed_components=()
    
    if is_component_installed "clamav"; then installed_components+=("ClamAV"); else failed_components+=("ClamAV"); fi
    if is_component_installed "inotify-tools"; then installed_components+=("inotify-tools"); else failed_components+=("inotify-tools"); fi
    if is_component_installed "rkhunter"; then installed_components+=("rkhunter"); else failed_components+=("rkhunter"); fi
    if is_component_installed "maldet"; then installed_components+=("Maldet"); else failed_components+=("Maldet"); fi
    if is_component_installed "realtime-service"; then installed_components+=("realtime-service"); else failed_components+=("realtime-service"); fi
    
    echo "✅ Successfully installed/verified: ${installed_components[*]}"
    if [ ${#failed_components[@]} -gt 0 ]; then
        echo "❌ Failed components: ${failed_components[*]}"
    fi
    
    echo ""
    echo "Scan schedules:"
    echo "  - Real-time: $REALTIME_SCAN_PATHS"
    echo "  - Daily: 00:00"
    echo "  - Full: Saturday 01:00"
    echo ""
    echo "Logs directory: $LOG_DIR"
    echo "Service: realtime-monitor.service"
    echo "======================================================"
    
    if [ ${#failed_components[@]} -eq 0 ]; then
        echo "[+] Installation completed successfully!"
        send_telegram_notification "✅ Security stack installation completed successfully on $(hostname)"
    else
        echo "[!] Installation completed with warnings"
        send_telegram_notification "⚠️ Security stack installation completed with warnings on $(hostname)"
    fi
}

# Rulează instalarea principală
main "$@"