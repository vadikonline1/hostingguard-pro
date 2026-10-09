#!/bin/bash
# =============================================================================
# Fail2Ban backup - versiune usoara: flock, gzip rapid, pastreaza 14 zile,
# notificare Telegram DOAR la eroare (succesul zilnic = spam care trezeste lumea)
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOCK="/run/hostingguard-f2b-backup.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || { echo "[!] Backup deja in curs — ies"; exit 0; }

if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi
# shellcheck disable=SC1091
[ -f "$BOUNCER_DIR/scripts/common.sh" ] && source "$BOUNCER_DIR/scripts/common.sh"
if type lowprio_run >/dev/null 2>&1; then
    LOWRUN="lowprio_run"
else
    LOWRUN=""
fi

BACKUP_DIR="/var/backups/fail2ban"
CONF_DIR="/etc/fail2ban"
mkdir -p "$BACKUP_DIR"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
BACKUP_FILE="$BACKUP_DIR/fail2ban_backup_$DATE.tar.gz"

echo "[*] Creare backup Fail2Ban (prioritate scazuta)..."
# gzip -1 = rapid, nu strange CPU ca default -6; prioritate minima (fara ionice lipsa = skip tacut)
if $LOWRUN tar -I 'gzip -1' -cf "$BACKUP_FILE" "$CONF_DIR" /var/lib/fail2ban 2>/dev/null; then
    echo "[+] Backup creat: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
    # Sterge backup-uri mai vechi de 14 zile
    find "$BACKUP_DIR" -name "fail2ban_backup_*.tar.gz" -mtime +14 -delete 2>/dev/null || true
else
    echo "[-] Eroare la crearea backup-ului"
    rm -f "$BACKUP_FILE" 2>/dev/null || true
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="❌ Eroare Backup Fail2Ban
Server: $(hostname -f)
Data: $(date '+%Y-%m-%d %H:%M:%S')
Status: EROARE"
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        timeout 15 "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1 || true
    fi
    exit 1
fi
