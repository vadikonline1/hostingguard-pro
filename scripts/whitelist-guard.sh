#!/bin/bash
# =============================================================================
# HostingGuard whitelist-guard - versiune usoara
# Garanteaza ca IP-urile din WHITELIST_IPS nu sunt blocate NICIODATA:
#   1. ACCEPT pe pozitia 1 in INPUT (INAINTEA lanturilor f2b-* — altfel
#      REJECT-ul fail2ban castiga chiar daca exista ACCEPT mai jos)
#   2. unban din toate jailurile fail2ban
#   3. stergere din lista threat-intel (altfel escaladarea 30 zile le reprinde)
#   4. sincronizare in fail2ban ignoreip (cu reload doar cand se schimba ceva)
# Ruleaza hourly din cron; o rulare tipica = cateva apeluri iptables/socket.
# Utilizare: whitelist-guard.sh [--status]
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOCK="/run/hostingguard-whitelist.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || exit 0

if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi

# Curata placeholder-uri / goluri
WL=""
for cand in ${WHITELIST_IPS:-}; do
    [ "$cand" = "change-me" ] && continue
    # accepta doar IPv4 valid (evita injectii in iptables)
    if [[ "$cand" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        WL="$WL $cand"
    fi
done
WL=$(echo "$WL" | tr ' ' '\n' | sort -u | tr '\n' ' ')

if [ -z "$(echo "$WL" | tr -d ' ')" ]; then
    [ "$1" = "--status" ] && echo "Whitelist goala (WHITELIST_IPS necompletat in hosting.env)"
    exit 0
fi

TI_FILE="/var/lib/fail2ban/threat-intel/combined_threats.txt"
JAIL_LOCAL="/etc/fail2ban/jail.local"
CHANGED=0
NOTES=""

jail_list() {
    fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[^:]*://p' | tr ',:\t' '   '
}

is_banned() {
    # $1=jail $2=ip → 0 daca e banat. Fallback: unban direct daca interogarea nu e suportata.
    local banned
    banned=$(fail2ban-client get "$1" banned 2>/dev/null)
    if [ $? -ne 0 ]; then
        return 0
    fi
    echo "$banned" | grep -qw "$2"
}

if [ "$1" = "--status" ]; then
    echo "=== WHITELIST STATUS ==="
    echo "Lista: $WL"
    for ip in $WL; do
        first=$(iptables -S INPUT 2>/dev/null | head -1)
        if [ "$first" = "-A INPUT -s $ip/32 -j ACCEPT" ]; then echo "  $ip: ACCEPT pe pozitia 1 OK"; else echo "  $ip: ACCEPT NU e pe pozitia 1 (va fi reparat la urmatoarea rulare)"; fi
        for j in $(jail_list); do
            if is_banned "$j" "$ip"; then echo "  $ip: BANAT in $j (!!)"; fi
        done
        [ -f "$TI_FILE" ] && grep -qx "$ip" "$TI_FILE" && echo "  $ip: prezent in threat-intel (!!)"
    done
    exit 0
fi

for ip in $WL; do
    # 1. ACCEPT pe pozitia 1 (doar daca lipsește sau e deplasat)
    first=$(iptables -S INPUT 2>/dev/null | head -1)
    if [ "$first" != "-A INPUT -s $ip/32 -j ACCEPT" ]; then
        while iptables -D INPUT -s "$ip" -j ACCEPT 2>/dev/null; do :; done
        if iptables -I INPUT 1 -s "$ip" -j ACCEPT 2>/dev/null; then
            CHANGED=1
            NOTES="$NOTES• ACCEPT $ip mutat pe pozitia 1
"
        fi
    fi

    # 2. unban din toate jailurile
    for j in $(jail_list); do
        [ -z "$j" ] && continue
        if is_banned "$j" "$ip"; then
            if fail2ban-client set "$j" unbanip "$ip" >/dev/null 2>&1; then
                CHANGED=1
                NOTES="$NOTES• $ip scos din jail $j
"
            fi
        fi
    done

    # 3. sterge din threat-intel (atomic)
    if [ -f "$TI_FILE" ] && grep -qx "$ip" "$TI_FILE" 2>/dev/null; then
        grep -vx "$ip" "$TI_FILE" > "$TI_FILE.tmp" && mv -f "$TI_FILE.tmp" "$TI_FILE"
        CHANGED=1
        NOTES="$NOTES• $ip sters din threat-intel
"
    fi

    # 4. ignoreip sync (reload doar daca a lipsit)
    if [ -f "$JAIL_LOCAL" ] && ! grep -q "$ip" "$JAIL_LOCAL" 2>/dev/null; then
        sed -i "s|^ignoreip = \(.*\)$|ignoreip = \1 $ip|" "$JAIL_LOCAL"
        CHANGED=1
        NOTES="$NOTES• $ip adaugat in fail2ban ignoreip
"
    fi
done

# Reload o singura data daca s-a modificat ignoreip
if echo "$NOTES" | grep -q "ignoreip"; then
    fail2ban-client reload >/dev/null 2>&1 || true
fi

if [ "$CHANGED" = "1" ] && [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    MSG="✅ Whitelist guard activ pe $(hostname -f)
$NOTES"
    export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
    timeout 15 "$NOTIFY_SCRIPT" "$MSG" >/dev/null 2>&1 || true
fi

echo "[+] Whitelist guard: verificat [$WL ]${CHANGED:+ (reparatii aplicate)}"
