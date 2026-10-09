#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOG_FILE="/var/log/fail2ban.log"
REPORT_FILE="/tmp/fail2ban_report.txt"

# Încarcă variabilele din .env files
if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    source "$BOUNCER_DIR/hosting.env"
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
