#!/bin/bash
# =============================================================================
# HostingGuard fail2ban-report - raport zilnic informativ (versiune usoara)
# Cron 08:00:  fail2ban-report.sh daily  → Telegram o singura data
# Manual:      fail2ban-report.sh         → afiseaza pe stdout, fara Telegram
# Tolerant: daca fail2ban e oprit sau logul lipseste, raportul spune asta
# (in loc sa trimita gol).
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="$BOUNCER_DIR/scripts"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOG_FILE="/var/log/fail2ban.log"
TI_FILE="/var/lib/fail2ban/threat-intel/combined_threats.txt"
VERSION_FILE="$BOUNCER_DIR/VERSION"

if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi

jail_list() {
    fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2- | tr ',' ' '
}

generate_report() {
    local host ver up load disk mem
    host=$(hostname -f 2>/dev/null || hostname)
    ver="necunoscut"
    [ -f "$VERSION_FILE" ] && ver=$(head -1 "$VERSION_FILE" 2>/dev/null)
    up=$(uptime -p 2>/dev/null || uptime 2>/dev/null | sed 's/^ *//')
    load=$(awk '{print $1"/"$2"/"$3}' /proc/loadavg 2>/dev/null || echo "?")
    disk=$(df -h / 2>/dev/null | awk 'NR==2{print $5" folosit din "$2}')
    mem=$(free -m 2>/dev/null | awk 'NR==2{printf "%d%% (%d/%dMB)", $3*100/$2, $3, $2}')

    echo "📊 Raport zilnic HostingGuard — $host"
    echo "$(date '+%Y-%m-%d %H:%M') · versiune $ver · up $up"
    echo "Load: $load · Disk /: ${disk:-?} · Mem: ${mem:-?}"
    echo ""

    # ---- Fail2Ban pe jailuri ----
    if ! systemctl is-active --quiet fail2ban 2>/dev/null && \
       ! fail2ban-client ping >/dev/null 2>&1; then
        echo "🛡️ Fail2Ban: INACTIV (!!) — verifica systemctl status fail2ban"
        echo ""
    else
        echo "🛡️ Fail2Ban (banuri curente / totale):"
        local jails line c t
        jails=$(jail_list)
        if [ -z "$(echo "$jails" | tr -d ' ')" ]; then
            echo "  (niciun jail activ)"
        else
            for j in $jails; do
                [ -z "$j" ] && continue
                line=$(fail2ban-client status "$j" 2>/dev/null)
                c=$(echo "$line" | awk -F: '/Currently banned/{gsub(/ /,"");print $2}' | tail -1)
                t=$(echo "$line" | awk -F: '/Total banned/{gsub(/ /,"");print $2}' | tail -1)
                echo "  • $j: ${c:-?} / ${t:-?}"
            done
        fi
        echo ""
    fi

    # ---- Top IP-uri banate (ultimele ~24h din log) ----
    if [ -f "$LOG_FILE" ]; then
        echo "🚨 Top IP-uri blocate (recent):"
        local top
        top=$(grep " Ban " "$LOG_FILE" 2>/dev/null | tail -2000 \
            | awk '{print $NF}' | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
            | sort | uniq -c | sort -rn | head -5)
        if [ -n "$top" ]; then
            echo "$top" | awk '{printf "  • %s — %sx\n", $2, $1}'
        else
            echo "  (niciun ban recent — liniste ✅)"
        fi
        echo ""
        echo "🕒 Ultimele banuri:"
        local recent
        recent=$(grep " Ban " "$LOG_FILE" 2>/dev/null | tail -5 \
            | sed -E 's/^([0-9-]+ [0-9:]+).*(NOTICE|INFO) *//; s/\[//g; s/\]//g')
        if [ -n "$recent" ]; then
            echo "$recent" | sed 's/^/  • /'
        else
            echo "  (nimic in log)"
        fi
        echo ""
    else
        echo "🚨 Log fail2ban lipsa ($LOG_FILE)"
        echo ""
    fi

    # ---- Whitelist + threat-intel ----
    local wl nwl nti
    wl=""
    if [ -f "$BOUNCER_DIR/scripts/common.sh" ]; then
        # shellcheck disable=SC1091
        source "$BOUNCER_DIR/scripts/common.sh" 2>/dev/null || true
        type normalize_whitelist >/dev/null 2>&1 && wl=$(normalize_whitelist "${WHITELIST_IPS:-}")
    fi
    [ -z "$wl" ] && wl=$(echo "${WHITELIST_IPS:-}" | tr ',' ' ' | grep -v change-me)
    nwl=$(echo "$wl" | wc -w)
    nti=0
    [ -f "$TI_FILE" ] && nti=$(wc -l < "$TI_FILE" 2>/dev/null || echo 0)
    echo "✅ Whitelist: $nwl IP-uri protejate · 🔍 Threat-intel: $nti IP-uri"
}

send_report() {
    local report="$1"
    if [ -z "$(echo "$report" | tr -d ' \n')" ]; then
        echo "[-] Raport gol — nu trimit nimic" >&2
        return 1
    fi
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] && [ "$TELEGRAM_BOT_TOKEN" != "change-me" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_THREAD_ID
        # mesaj ca argument (telegram_notify.sh stie si -f -/stdin, dar
        # argumentul direct e cel mai sigur — fara pipe-uri pierdute)
        "$NOTIFY_SCRIPT" "$report" >/dev/null 2>&1
    fi
}

if [ "${1:-}" = "daily" ]; then
    send_report "$(generate_report)"
else
    generate_report
fi
