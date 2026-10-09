#!/bin/bash
set -e

# Load environment
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

log() {
    echo -e "🔹 $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

install_fastpanel() {
    log "Checking FastPanel installation..."
    
    if command -v mogwai &> /dev/null; then
        log "✅ FastPanel is already installed"
        
        # Update password if needed
        log "Verifying FastPanel password..."
        if mogwai chpasswd -u "fastuser" -p "$FASTPANEL_PASSWORD" 2>/dev/null; then
            log "✅ FastPanel password updated"
        fi
        return 0
    fi
    
    log "Installing FastPanel..."
    send_telegram_notification "🔄 Installing FastPanel control panel..."

    # Install dependencies (apt sau dnf)
    if [ -f "${BOUNCER_DIR:-/etc/automation-web-hosting}/scripts/common.sh" ]; then
        # shellcheck disable=SC1091
        source "${BOUNCER_DIR:-/etc/automation-web-hosting}/scripts/common.sh"
        pkg_install ca-certificates wget
    elif command -v apt-get &> /dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates wget
    else
        dnf install -y ca-certificates wget || yum install -y ca-certificates wget
    fi
    
    # Download and install
    if wget -q https://repo.fastpanel.direct/install_fastpanel.sh -O /tmp/install_fastpanel.sh; then
        bash /tmp/install_fastpanel.sh
        sleep 30
        
        if command -v mogwai &> /dev/null; then
            if mogwai chpasswd -u "fastuser" -p "$FASTPANEL_PASSWORD" 2>/dev/null; then
                send_telegram_notification "✅ FastPanel installed and configured"
                log "✅ FastPanel installation completed"
            else
                send_telegram_notification "⚠️ FastPanel installed - verify password configuration"
                log "⚠️ FastPanel password configuration needs verification"
            fi
        else
            log "❌ FastPanel installation issues detected"
            return 1
        fi
        
        rm -f /tmp/install_fastpanel.sh
    else
        log "❌ Failed to download FastPanel installer"
        return 1
    fi
}

main() {
    log "Starting FastPanel setup..."
    install_fastpanel
    log "✅ FastPanel setup completed"
}

main "$@"
