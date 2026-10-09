#!/bin/bash
set -e

# =============================================================================
# SETUP DIRECTORIES SCRIPT
# =============================================================================

# Get current script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../telegram_notify.sh" 2>/dev/null || true

# Load all additional .env files
if compgen -G "$BOUNCER_DIR/*.env" > /dev/null; then
    for env_file in "$BOUNCER_DIR"/*.env; do
        echo "[*] Loading environment from: $env_file"
        source "$env_file"
    done
else
    echo "⚠️ No additional .env files found in $BOUNCER_DIR"
fi

# Logging helper
log() {
    echo -e "🔹 $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."

    local dirs=(
        "$BOUNCER_DIR"
        "$LOG_DIR"
        "$CROWDSEC_DIR/bouncers"
        "$CROWDSEC_DIR/plugins"
        "$QUARANTINE_DIR"
    )

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            chmod 750 "$dir"
            log "✅ Created: $dir"
        else
            log "✅ Exists: $dir"
        fi
    done

    # Set ownership for quarantine directory
    if id clamav &>/dev/null; then
        chown clamav:clamav "$QUARANTINE_DIR" 2>/dev/null || true
    fi
}

# Logrotate: toate logurile HostingGuard pe rotatie 7 zile (altfel umplu HDD-ul)
setup_logrotate() {
    local logdir="${LOG_DIR:-/etc/automation-web-hosting/log}"

    if ! command -v logrotate &> /dev/null; then
        log "Installing logrotate..."
        apt-get install -y logrotate
    fi

    cat > /etc/logrotate.d/hostingguard << EOF
$logdir/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}
EOF
    chmod 644 /etc/logrotate.d/hostingguard
    log "✅ Logrotate configurat: $logdir (7 zile, max 100M/fisier)"
}

# Main flow
main() {
    log "Setting up directory structure..."
    create_directories
    setup_logrotate
    log "✅ Directory setup completed"
	send_telegram_notification "✅ Directory setup completed"
}

main "$@"
