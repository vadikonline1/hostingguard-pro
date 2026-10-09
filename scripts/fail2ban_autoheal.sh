#!/bin/bash
# =============================================================================
# HostingGuard autoheal - versiune usoara (ruleaza la 15 min, NU la 5 min)
# - flock anti-suprapunere, cooldown alerte (1/h per tip), fara restarturi oarbe
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOCK="/run/hostingguard-autoheal.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || exit 0

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi

DISK_CRIT="${DISK_CRIT:-90}"
MEM_CRIT="${MEM_CRIT:-92}"
LOAD_FACTOR="${LOAD_CRIT_FACTOR:-3.0}"
ALERT_DIR="/tmp/hg_autoheal_alerts"
mkdir -p "$ALERT_DIR" 2>/dev/null || true

# Cooldown 1h per cheie de alerta (evita spam Telegram la fiecare 5 min)
should_alert() {
    local key="$1"
    local marker="$ALERT_DIR/$key"
    if [ -f "$marker" ] && [ "$(( $(date +%s) - $(stat -c %Y "$marker" 2>/dev/null || echo 0) ))" -lt 3600 ]; then
        return 1
    fi
    touch "$marker"
    return 0
}

send_alert() {
    local message="$1"
    local key="$2"
    [ -n "$key" ] && ! should_alert "$key" && return 0
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        timeout 15 "$NOTIFY_SCRIPT" "$message" >/dev/null 2>&1 || true
    fi
}

check_and_restart_service() {
    local service="$1"
    systemctl is-active --quiet "$service" 2>/dev/null && return 0
    # fail2ban poate fi "activ" dar blocat — verifica si ping-ul
    if [ "$service" = "fail2ban" ] && fail2ban-client ping >/dev/null 2>&1; then
        return 0
    fi
    echo "[!] Service $service oprit/blocat. Repornire..."
    if timeout 60 systemctl restart "$service" 2>/dev/null; then
        send_alert "🔄 Auto-Healing: $service repornit pe $(hostname -f)" "svc_$service"
    else
        send_alert "❌ Auto-Healing ESUAT: $service nu a pornit pe $(hostname -f)" "svc_fail_$service"
    fi
}

# Verifică serviciile critice (doar daca sunt instalate — nu incerca apache cand ai nginx)
check_and_restart_service "fail2ban"
systemctl list-unit-files 2>/dev/null | grep -q "^nginx" && check_and_restart_service "nginx"
systemctl list-unit-files 2>/dev/null | grep -q "^apache2" && check_and_restart_service "apache2"
systemctl list-unit-files 2>/dev/null | grep -q "^clamav-daemon" && check_and_restart_service "clamav-daemon"

# Verifică disk space + inodes (inodes pline blocheaza la fel de rau)
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "${DISK_USAGE:-0}" -gt "$DISK_CRIT" ]; then
    send_alert "🚨 Disk space critic: ${DISK_USAGE}% pe $(hostname -f)" "disk"
fi
INODE_USAGE=$(df -i / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "${INODE_USAGE:-0}" -gt "$DISK_CRIT" ]; then
    send_alert "🚨 Inodes critice: ${INODE_USAGE}% pe $(hostname -f)" "inode"
fi

# Verifică memoria (fara swap panic: prag configurabil)
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "${MEM_USAGE:-0}" -gt "$MEM_CRIT" ]; then
    send_alert "🚨 Memorie critică: ${MEM_USAGE}% pe $(hostname -f)" "mem"
fi

# Verifică load (load > CPU*factor = ceva blocheaza)
CPUS=$(nproc 2>/dev/null || echo 1)
LOAD1=$(awk '{print $1}' /proc/loadavg)
if awk -v l="$LOAD1" -v c="$CPUS" -v f="$LOAD_FACTOR" 'BEGIN{exit !(l > c*f)}'; then
    send_alert "🚨 Load critic: $LOAD1 pe ${CPUS} CPU pe $(hostname -f)" "load"
fi

echo "[+] Auto-healing verificare completă"
