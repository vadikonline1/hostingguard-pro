#!/bin/bash
# =============================================================================
# HostingGuard prune-logs - curatenie zilnica usoara (doar comenzi find)
# Opreste umplerea HDD-ului si a /tmp-ului:
#   loguri 7 zile · carantina 30 zile · backupuri 14 zile · markeri /tmp expirati
# Ruleaza zilnic 01:15 din cron; o rulare tipica dureaza sub o secunda.
# =============================================================================
LOCK="/run/hostingguard-prune.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || exit 0

BOUNCER_DIR="/etc/automation-web-hosting"
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi
COMMON_LIB="$BOUNCER_DIR/scripts/common.sh"
[ -f "$COMMON_LIB" ] && source "$COMMON_LIB"
apply_low_priority 2>/dev/null || true

LOG_DIR="${LOG_DIR:-$BOUNCER_DIR/log}"
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/quarantine}"
BACKUP_DIR="/var/backups/fail2ban"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"
QUARANTINE_RETENTION_DAYS="${QUARANTINE_RETENTION_DAYS:-30}"
BACKUP_RETENTION_DAYS=14

freed=0
prune() { # $1=dir, restul = argumente find
    local dir="$1"; shift
    [ -d "$dir" ] || return 0
    local n
    n=$(find "$dir" "$@" -print -delete 2>/dev/null | wc -l)
    freed=$((freed + n))
}

# 1. Loguri HostingGuard (inclusiv cele rotite .1/.gz) — 7 zile
prune "$LOG_DIR" -type f -name '*.log*' -mtime "+$LOG_RETENTION_DAYS"

# 2. Carantina veche — 30 zile (scanurile fac asta deja; aici e plasa de siguranta)
prune "$QUARANTINE_DIR" -type f -mtime "+$QUARANTINE_RETENTION_DAYS"

# 3. Backupuri fail2ban vechi — 14 zile
prune "$BACKUP_DIR" -type f -name 'fail2ban_backup_*.tar.gz' -mtime "+$BACKUP_RETENTION_DAYS"

# 4. /tmp: markeri realtime expirati (asta umplea /tmp cat monitorul rula la nesfarsit)
prune /tmp/clamav_processed -type f -mmin +120
prune /tmp/hg_telegram_rate -type f -mmin +60
prune /tmp/hg_autoheal_alerts -type f -mtime +7
n=$(find /tmp -maxdepth 1 \( -name 'total_files_scanned.*' -o -name 'total_threats_detected.*' -o -name 'fail2ban_notifications.cache' -o -name 'fail2ban_report*' \) -mtime +1 -print -delete 2>/dev/null | wc -l)
freed=$((freed + n))
rm -f /var/lib/fail2ban/threat-intel/*.tmp 2>/dev/null || true

# 5. Jurnal systemd scapat de sub control (cauza clasica de HDD plin)
if [ -d /var/log/journal ]; then
    jusage=$(journalctl --disk-usage 2>/dev/null | grep -Eo '[0-9.]+[MG]' | head -1)
    case "$jusage" in
        *G) journalctl --vacuum-size=200M >/dev/null 2>&1 || true; freed=$((freed + 1)) ;;
    esac
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] prune-logs: $freed intrari vechi sterse (loguri ${LOG_RETENTION_DAYS}z)"
