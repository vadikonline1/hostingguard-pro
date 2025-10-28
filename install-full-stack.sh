#!/bin/bash
set -e

# =============================================================================
# MAIN HOSTING AUTOMATION INSTALLATION SCRIPT
# =============================================================================

# Load environment and utilities
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${CURRENT_PATH_DIR}/telegram_notify.sh"
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
    
    # Install dos2unix if not already installed
    if ! command -v dos2unix &> /dev/null; then
        log "Installing dos2unix package..."
        apt install -y dos2unix
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

# Prepare system: update and install required packages
prepare_system() {
    log "Updating system packages and installing dependencies..."

    # Update and upgrade
    apt update && apt -y upgrade

    # List of required packages
    local packages=(
        mc
        inotify-tools
        clamav
        clamav-daemon
        curl
        jq
        sudo
        fail2ban
        dos2unix
    )

    # Install packages if not already installed
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            log "Installing missing package: $pkg"
            apt install -y "$pkg"
        else
            log "✅ Package already installed: $pkg"
        fi
    done

    # Ensure inotifywait is available (from inotify-tools)
    if ! command -v inotifywait &> /dev/null; then
        log "❌ inotifywait not found even after installing inotify-tools"
        exit 1
    fi

    # Update ClamAV database
    log "Updating ClamAV virus definitions..."
    systemctl stop clamav-freshclam.service || true
    freshclam || log "⚠️ ClamAV database update failed"
    systemctl start clamav-freshclam.service || true

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

# Check system compatibility
check_system() {
    log "Checking system compatibility..."
    
    if [ ! -f /etc/debian_version ] && [ ! -f /etc/lsb-release ]; then
        log "❌ This script is only for Debian/Ubuntu systems"
        exit 1
    fi
    
    if command -v lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -d | cut -f2)
        log "✅ System verified: $DISTRO"
    else
        log "✅ Debian/Ubuntu system detected"
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

# === CONFIGURARE CRON JOBS - VERSIUNE SIMPLĂ ===
setup_cron_jobs_simple() {
    echo "[*] Setting up automated scan cron jobs..."
    
    # Directorul principal
    SCRIPT_DIR="/etc/automation-web-hosting"
    LOG_DIR="/etc/automation-web-hosting/log"
    
    # Asigură-te că directorul de log-uri există
    mkdir -p "$LOG_DIR"
    
    # Creează job-urile cron
    (crontab -l 2>/dev/null | grep -v "daily-scan.sh" | grep -v "full-scan.sh"; cat << EOF

# ===========================================
# HOSTING AUTOMATION - SECURITY SCANS
# ===========================================
# Daily quick scan - every day at 00:00
0 0 * * * $SCRIPT_DIR/daily-scan.sh >> $LOG_DIR/daily-scan.log 2>&1

# Weekly full scan - every Sunday at 01:00  
0 1 * * 0 $SCRIPT_DIR/full-scan.sh >> $LOG_DIR/full-scan.log 2>&1
# ===========================================
EOF
    ) | crontab -
    
    echo "[+] Cron jobs installed successfully"
    echo "    ✅ Daily scan: 00:00 every day"
    echo "    ✅ Full scan: 01:00 every Sunday"
    
    # Afișează job-urile adăugate
    echo "[*] Current cron jobs for hosting automation:"
    crontab -l | grep -A5 -B5 "HOSTING AUTOMATION"
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
    
    # Add to fstab if not already present
    if ! grep -q "$FASTPANEL_LOG" /etc/fstab; then
        echo "$LOG_DIR $FASTPANEL_LOG none bind 0 0" >> /etc/fstab
        log "✅ Added mount to /etc/fstab"
    fi
    
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
    log "✅ Daily Scans: Scheduled for ${DAILY_SCAN_TIME}"
    
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
📅 Daily scans: ${DAILY_SCAN_TIME}
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