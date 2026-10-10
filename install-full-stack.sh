#!/bin/bash
set -e

# =============================================================================
# MAIN HOSTING AUTOMATION INSTALLATION SCRIPT
# =============================================================================

# Load environment and utilities
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${CURRENT_PATH_DIR}/telegram_notify.sh"
# Libraria comuna: detectie OS (Debian/RHEL) + pkg_install + servicii
# shellcheck disable=SC1091
[ -f "${CURRENT_PATH_DIR}/scripts/common.sh" ] && source "${CURRENT_PATH_DIR}/scripts/common.sh"
ENV_FILES="$CURRENT_PATH_DIR/*.env"

# Încarcă toate fișierele .env
for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
    fi
done

# Logging function
log() {
    echo -e "🔹 $(date '+%Y-%m-%d %H:%M:%S') - $1"
    logger -t "hosting-automation" "$1"
}

# Install and configure dos2unix
setup_dos2unix() {
    log "Setting up dos2unix for proper line endings..."
    
    # Install dos2unix if not already installed (apt sau dnf)
    if ! command -v dos2unix &> /dev/null; then
        log "Installing dos2unix package..."
        if type pkg_install >/dev/null 2>&1; then
            pkg_install dos2unix
        elif command -v apt-get &> /dev/null; then
            apt-get install -y dos2unix
        else
            dnf install -y dos2unix || yum install -y dos2unix
        fi
    else
        log "✅ dos2unix already installed"
    fi
    
    # Convert all scripts in BOUNCER_DIR to Unix format
    if [ -d "$BOUNCER_DIR" ]; then
        log "Converting scripts to Unix format in $BOUNCER_DIR..."
        
        # Find and convert all .sh files
        find "$BOUNCER_DIR" -type f -name "*.sh" | while read -r script; do
            if [ -f "$script" ]; then
                if file "$script" | grep -q "CRLF"; then
                    log "Converting Windows line endings: $script"
                    dos2unix "$script"
                fi
            fi
        done
        
        # Also convert .env files
        find "$BOUNCER_DIR" -type f -name "*.env" | while read -r env_file; do
            if [ -f "$env_file" ]; then
                if file "$env_file" | grep -q "CRLF"; then
                    log "Converting Windows line endings: $env_file"
                    dos2unix "$env_file"
                fi
            fi
        done
        
        log "✅ Line endings conversion completed"
    else
        log "⚠️ BOUNCER_DIR not found: $BOUNCER_DIR"
    fi
}

# Prepare system: update and install required packages (Debian + RHEL)
prepare_system() {
    log "Updating system packages and installing dependencies..."

    if type detect_os >/dev/null 2>&1; then detect_os; fi
    log "OS family: ${HG_OS_FAMILY:-unknown} (pkg: ${PKG_MGR:-none})"

    # Refresh + upgrade (echivalent pe ambele familii)
    if [ "${HG_OS_FAMILY}" = "rhel" ]; then
        $PKG_MGR makecache && $PKG_MGR upgrade -y
    else
        apt-get update && apt-get -y upgrade
    fi

    # Nume Debian — maparea pe RHEL e automata (clamav-daemon→clamd etc.)
    if type pkg_install >/dev/null 2>&1; then
        pkg_install mc inotify-tools clamav clamav-daemon clamav-freshclam curl jq sudo fail2ban dos2unix
    else
        local packages=(mc inotify-tools clamav clamav-daemon curl jq sudo fail2ban dos2unix)
        for pkg in "${packages[@]}"; do
            if ! dpkg -s "$pkg" &> /dev/null; then
                log "Installing missing package: $pkg"
                apt-get install -y "$pkg"
            else
                log "✅ Package already installed: $pkg"
            fi
        done
    fi

    # Ensure inotifywait is available (from inotify-tools)
    if ! command -v inotifywait &> /dev/null; then
        log "❌ inotifywait not found even after installing inotify-tools"
        exit 1
    fi

    # Update ClamAV database (numele serviciului difera pe RHEL)
    log "Updating ClamAV virus definitions..."
    local fresh_svc="clamav-freshclam"
    if type freshclam_service >/dev/null 2>&1; then fresh_svc=$(freshclam_service); fi
    systemctl stop "$fresh_svc.service" || true
    freshclam || log "⚠️ ClamAV database update failed"
    systemctl start "$fresh_svc.service" || true

    # Setup dos2unix for proper line endings
    setup_dos2unix

    log "✅ System preparation complete"
}

# Display banner
display_banner() {
    echo "=================================================="
    echo "    HOSTING AUTOMATION FULL-STACK INSTALLATION"
    echo "=================================================="
    echo "📁 Directory: $BOUNCER_DIR"
    echo "📝 Logs: $LOG_DIR"
    echo "🛡️  Security: Fail2Ban + ClamAV"
    echo "🔧 Utilities: dos2unix for cross-platform compatibility"
    echo "=================================================="
}

# Check system compatibility (Debian/Ubuntu + Rocky/Alma/RHEL/CentOS)
check_system() {
    log "Checking system compatibility..."

    if type detect_os >/dev/null 2>&1; then detect_os; fi
    case "${HG_OS_FAMILY:-}" in
        debian|rhel) log "✅ OS family supported: $HG_OS_FAMILY" ;;
        *)
            if [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
                log "✅ Debian/Ubuntu system detected"
            elif [ -f /etc/redhat-release ]; then
                log "✅ RHEL-family system detected"
            else
                log "❌ Unsupported OS — need Debian/Ubuntu or Rocky/Alma/RHEL/CentOS"
                exit 1
            fi
            ;;
    esac

    if command -v lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -d | cut -f2)
        log "✅ System verified: $DISTRO"
    elif [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        log "✅ System verified: $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')"
    fi

    if [ "$EUID" -ne 0 ]; then
        log "❌ Please run as root"
        exit 1
    fi
}

# Validate environment
validate_environment() {
    log "Validating environment configuration..."
    
    # Verifică dacă există cel puțin un fișier .env
    if ! compgen -G "$BOUNCER_DIR/*.env" > /dev/null; then
        log "❌ No environment files found in $BOUNCER_DIR"
        log "Please create at least one .env file (e.g. hosting.env) with your configuration"
        exit 1
    fi

    # Încarcă toate fișierele .env găsite
    for env_file in "$BOUNCER_DIR"/*.env; do
        log "Loading environment file: $env_file"
        set -o allexport
        source "$env_file"
        set +o allexport
    done
    
    # Validează variabilele obligatorii
    local required_vars=(
        "FASTPANEL_PASSWORD"
        "TELEGRAM_BOT_TOKEN"
        "TELEGRAM_CHAT_ID"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]] || [[ "${!var}" == *"your_"* ]]; then
            log "❌ Please configure $var in one of your .env files"
            exit 1
        fi
    done
    
    log "✅ Environment validation completed"
}

# Main installation sequence
main_installation() {
    log "Making all .sh scripts executable in $BOUNCER_DIR (including subfolders)..."
    find "$BOUNCER_DIR" -type f -name "*.sh" -exec chmod +x {} \;
    log "✅ All shell scripts are now executable"
    
    local steps=(
        "$SETUP_DIR/setup_directories.sh:::Creating directory structure"
        "$CURRENT_PATH_DIR/telegram_notify.sh:::Setting up Telegram notifications"
        "$SETUP_DIR/setup_fastpanel.sh:::Installing FastPanel"
        "$SETUP_DIR/setup_fail2ban.sh:::Installing Fail2Ban security"
        "$SETUP_DIR/setup_antivirus.sh:::Setting up ClamAV protection"
    )
    
    for step in "${steps[@]}"; do
        local script="${step%%:::*}"
        local description="${step##*:::}"
        
        log "➡️ $description"
        if [ -f "$script" ]; then
            # Ensure script has Unix line endings before execution
            if command -v dos2unix &> /dev/null; then
                dos2unix "$script" 2>/dev/null || true
            fi
            
            if bash "$script"; then
                log "✅ $description - SUCCESS"
            else
                log "❌ $description - FAILED"
                return 1
            fi
        else
            log "❌ Script not found: $script"
            return 1
        fi
    done
}

#!/bin/bash

# === CONFIGURARE CRON JOBS - VERSIUNE OPTIMIZATA (esalonat, anti-blocare) ===
setup_cron_jobs_simple() {
    echo "[*] Setting up OPTIMIZED scan cron jobs (staggered, low-priority)..."

    SCRIPT_DIR="/etc/automation-web-hosting"
    LOG_DIR="/etc/automation-web-hosting/log"
    mkdir -p "$LOG_DIR"

    # Sterge gramada veche de la 00:00/01:00/04:00/05:00/06:00 + autoheal la 5min
    local tmpcron
    tmpcron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "daily-scan.sh" | grep -v "full-scan.sh" \
        | grep -v "clamav-daily" | grep -v "freshclam" | grep -v "maldet -u" \
        | grep -v "rkhunter --update" | grep -v "fail2ban-backup.sh" \
        | grep -v "update-threat-intel.sh" | grep -v "fail2ban_autoheal" \
        | grep -v "whitelist-guard.sh" \
        | grep -v "self-update.sh" \
        | grep -v "prune-logs.sh" \
        | grep -v "fail2ban-report.sh" > "$tmpcron" || true

    cat >> "$tmpcron" << EOF

# ===========================================
# HOSTINGGUARD - OPTIMIZED SCHEDULE (nu modifica manual, ruleaza setup)
# esalonat + nice/ionice + flock — NU mai pune totul la 00:00
# ===========================================
5 2 * * * /usr/bin/flock -n /run/hg-cron-backup.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $SCRIPT_DIR/scripts/fail2ban-backup.sh >> $LOG_DIR/cron-backup.log 2>&1
15 1 * * * /usr/bin/flock -n /run/hg-cron-prune.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $SCRIPT_DIR/scripts/prune-logs.sh >> $LOG_DIR/prune.log 2>&1
30 2 * * * /usr/bin/flock -n /run/hg-cron-daily.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $SCRIPT_DIR/scripts/daily-scan.sh >> $LOG_DIR/daily-scan.log 2>&1
0 3 * * 0 /usr/bin/flock -n /run/hg-cron-threat.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $SCRIPT_DIR/scripts/update-threat-intel.sh >> $LOG_DIR/threat-intel.log 2>&1
0 4 1-7 * 0 /usr/bin/flock -n /run/hg-cron-full.lock /usr/bin/nice -n 19 /usr/bin/ionice -c3 $SCRIPT_DIR/scripts/full-scan.sh >> $LOG_DIR/full-scan.log 2>&1
15 5 1-7 * 1 /usr/bin/nice -n 19 /usr/bin/ionice -c3 /usr/local/maldetect/maldet -u >> $LOG_DIR/maldet-update.log 2>&1
*/15 * * * * /usr/bin/flock -n /run/hg-cron-heal.lock $SCRIPT_DIR/scripts/fail2ban_autoheal.sh >> $LOG_DIR/autoheal.log 2>&1
17 * * * * /usr/bin/flock -n /run/hg-cron-whitelist.lock $SCRIPT_DIR/scripts/whitelist-guard.sh >> $LOG_DIR/whitelist-guard.log 2>&1
0 8 * * * /usr/bin/flock -n /run/hg-cron-report.lock $SCRIPT_DIR/scripts/fail2ban-report.sh daily >> $LOG_DIR/report.log 2>&1
0 6 * * 1 /usr/bin/flock -n /run/hg-cron-update.lock $SCRIPT_DIR/scripts/self-update.sh --check >> $LOG_DIR/update.log 2>&1
# NOTA: freshclam e gestionat de daemon (clamav-freshclam), NU din cron.
# rkhunter --propupd e dezactivat implicit (ENABLE_RKHUNTER=0) — prea greu pe VPS.
# ===========================================
EOF
    crontab "$tmpcron"
    rm -f "$tmpcron"

    echo "[+] Cron jobs OPTIMIZED installed:"
    echo "    curatenie (loguri 7z): 01:15"
    echo "    backup zilnic:      02:05"
    echo "    daily scan:         02:30 (doar web/home/tmp, nice 19)"
    echo "    threat intel:       duminica 03:00 (saptamanal, nu zilnic)"
    echo "    full scan:          prima duminica 04:00 (LUNAR, nu saptamanal)"
    echo "    autoheal:           la 15 min (nu 5)"
    echo "    whitelist guard:    orar (IP-urile proprii nu sunt blocate)"
    crontab -l | grep -A20 "HOSTINGGUARD - OPTIMIZED" || true
}

# Final configuration and startup
final_setup() {
    log "Performing final configuration..."
    
    # Define log directories
    LOG_DIR="/etc/automation-web-hosting/log"
    FASTPANEL_LOG="/var/www/fastuser/data/clam_log"
    
    # Set proper permissions for main directory
    chmod 750 "$BOUNCER_DIR"
    
    # Set permissions for .env files
    for env_file in "$BOUNCER_DIR"/*.env; do
        if [ -f "$env_file" ]; then
            chmod 600 "$env_file"
        fi
    done
    
    # Set permissions for scripts
    for script_file in "$CURRENT_PATH_DIR"/*.sh; do
        if [ -f "$script_file" ]; then
            chmod 750 "$script_file"
        fi
    done
    
    # Create source log directory and essential log files FIRST
    log "📝 Creating log files in source directory..."
    mkdir -p "$LOG_DIR"
    
    # Create essential log files with some initial content
    touch "$LOG_DIR/security-install.log"
    touch "$LOG_DIR/realtime-monitor.log" 
    touch "$LOG_DIR/daily-scan.log"
    touch "$LOG_DIR/full-scan.log"
    touch "$LOG_DIR/clamav.log"
    touch "$LOG_DIR/fail2ban.log"
    
    # Add initial headers to log files
    echo "# Security Install Log - Created $(date)" > "$LOG_DIR/security-install.log"
    echo "# Realtime Monitor Log - Created $(date)" > "$LOG_DIR/realtime-monitor.log"
    echo "# Daily Scan Log - Created $(date)" > "$LOG_DIR/daily-scan.log"
    echo "# Full Scan Log - Created $(date)" > "$LOG_DIR/full-scan.log"
    echo "# ClamAV Scan Log - Created $(date)" > "$LOG_DIR/clamav.log"
    echo "# Fail2Ban Log - Created $(date)" > "$LOG_DIR/fail2ban.log"
    
    # Set permissions for log files
    chmod 644 "$LOG_DIR"/*.log
    chmod 755 "$LOG_DIR"
    
    # Create FASTPANEL log directory
    mkdir -p "$FASTPANEL_LOG"
    
    # Unmount first if already mounted
    umount "$FASTPANEL_LOG" 2>/dev/null && log "✅ Unmounted existing mount"
    
    # Create bind mount - NOW the source directory has content
    log "🔗 Creating bind mount..."
    mount --bind "$LOG_DIR" "$FASTPANEL_LOG"
    
    # Verify mount was successful
    if mountpoint -q "$FASTPANEL_LOG"; then
        log "✅ Bind mount successful: $LOG_DIR -> $FASTPANEL_LOG"
        
        # Test if files are visible
        if [ -f "$FASTPANEL_LOG/security-install.log" ]; then
            log "✅ Log files are visible in FASTPANEL directory"
        else
            log "❌ Log files NOT visible in FASTPANEL directory"
        fi
    else
        log "❌ Bind mount failed"
    fi
    
    # Demonteaza tintele vechi/stale din reinstalluri anterioare (cai diferite),
    # pastrand doar tinta canonica
    for stale in /var/www/fastuser/data/clam_log /var/www/fastuser/data/logs/clam_log /var/www/fastuser/data/log/clam_log; do
        if [ "$stale" != "$FASTPANEL_LOG" ] && mountpoint -q "$stale" 2>/dev/null; then
            umount "$stale" 2>/dev/null && log "✅ Demontat mount stal: $stale"
        fi
    done

    # Curata TOATE intrarile vechi de bind pentru loguri (altfel se acumuleaza
    # cate una la fiecare reinstall) si lasa exact una singura, canonica
    if grep -q "automation-web-hosting/log" /etc/fstab 2>/dev/null; then
        cp -a /etc/fstab /etc/fstab.bak.hg 2>/dev/null || true
        grep -v "automation-web-hosting/log" /etc/fstab > /tmp/fstab.hg \
            && cat /tmp/fstab.hg > /etc/fstab && rm -f /tmp/fstab.hg
        log "✅ Intrari fstab vechi/stale curatate (backup: /etc/fstab.bak.hg)"
    fi
    echo "$LOG_DIR $FASTPANEL_LOG none bind 0 0" >> /etc/fstab
    log "✅ Mount canonic in /etc/fstab: $LOG_DIR -> $FASTPANEL_LOG"
    
    # Set ownership
    if id "fastuser" &>/dev/null; then
        chown -R fastuser:fastuser "$FASTPANEL_LOG"
        log "✅ Set ownership to fastuser:fastuser"
    else
        log "⚠️ User 'fastuser' not found"
    fi
    
    # Set permissions
    chmod -R 755 "$FASTPANEL_LOG"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Final verification
    log "🔍 Verifying log directory structure..."
    log "Source LOG_DIR ($LOG_DIR) contents:"
    ls -la "$LOG_DIR" || log "❌ Cannot list source directory"
    
    log "FASTPANEL_LOG ($FASTPANEL_LOG) contents:"
    ls -la "$FASTPANEL_LOG" || log "❌ Cannot list FASTPANEL directory"
    
    log "Mount status:"
    mount | grep "clam_log" || log "❌ Mount not active"
    
    log "✅ Final configuration completed"
    log "📁 Log files should be available at: $FASTPANEL_LOG"
}

# Display installation summary
display_summary() {
    log "=== INSTALLATION SUMMARY ==="
    log "✅ System: $(lsb_release -d | cut -f2)"
    log "✅ Directories: $BOUNCER_DIR"
    log "✅ FastPanel: $(command -v mogwai &>/dev/null && echo 'Installed' || echo 'Not installed')"
    log "✅ Fail2Ban: $(command -v fail2ban-server &>/dev/null && echo 'Installed' || echo 'Not installed')"
    log "✅ ClamAV Monitoring: $(systemctl is-active clamav-monitor.service &>/dev/null && echo 'Active' || echo 'Inactive')"
    log "✅ dos2unix: $(command -v dos2unix &>/dev/null && echo 'Installed & Configured' || echo 'Not installed')"
    log "✅ Daily Scans: 02:30 low-priority (+ whitelist guard hourly)"
    
    # Display Fail2Ban status if installed
    if command -v fail2ban-server &>/dev/null; then
        log "✅ Fail2Ban Jails:"
        if systemctl is-active --quiet fail2ban; then
            fail2ban-client status | grep -E "Jail list:|Status" | while read -r line; do
                log "   $line"
            done
        else
            log "   ⚠️ Fail2Ban service not running"
        fi
    fi
    
    # Send completion notification
    send_telegram_notification "🎉 Hosting Automation installation completed!
🖥️ Server: $(hostname)
🛡️ Security: Fail2Ban + ClamAV active
🔧 Utilities: dos2unix configured
📊 Monitoring: File changes, malware & intrusion detection
📅 Daily scans: 02:30 low-priority
🛡️ Whitelist guard: hourly (whitelisted IPs never blocked)
✅ Status: Operational"
}

# Main execution flow
main() {
    display_banner
    check_system
    validate_environment
    prepare_system
    
    log "Starting full-stack hosting automation installation..."
    send_telegram_notification "🚀 Starting hosting automation installation on $(hostname)"
    
    if main_installation; then
        final_setup
        display_summary
		setup_cron_jobs_simple
        log "🎊 Installation completed successfully!"
		
    else
        log "❌ Installation failed - check logs for details"
        send_telegram_notification "❌ Hosting automation installation failed on $(hostname)"
        exit 1
    fi
}

# Run main function
main "$@"