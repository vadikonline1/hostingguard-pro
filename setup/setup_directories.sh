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

# Main flow
main() {
    log "Setting up directory structure..."
    create_directories
    log "✅ Directory setup completed"
	send_telegram_notification "✅ Directory setup completed"
}

main "$@"
