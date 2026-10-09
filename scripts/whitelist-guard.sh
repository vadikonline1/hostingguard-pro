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
# SILENTIOS cand nu e nimic de reparat (fara Telegram, fara output in log).
# Trimite Telegram + scrie in log DOAR cand aplica efectiv o reparatie.
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
# shellcheck disable=SC1091
[ -f "$BOUNCER_DIR/scripts/common.sh" ] && source "$BOUNCER_DIR/scripts/common.sh"

# Normalizeaza lista cu virgula (si spatii, pentru compatibilitate)
WL=""
if type normalize_whitelist >/dev/null 2>&1; then
    WL=$(normalize_whitelist "${WHITELIST_IPS:-}")
else
    # fallback fara common.sh
    for cand in $(echo "${WHITELIST_IPS:-}" | tr ',' ' '); do
        [ "$cand" = "change-me" ] && continue
        if [[ "$cand" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            WL="$WL $cand"
        fi
    done
    WL=$(echo "$WL" | tr ' ' '\n' | sort -u | tr '\n' ' ')
fi

if [ -z "$(echo "$WL" | tr -d ' ')" ]; then
    [ "${1:-}" = "--status" ] && echo "Whitelist goala (WHITELIST_IPS necompletat in hosting.env)"
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
    # $1=jail $2=ip → 0 daca e banat.
    # Folosim `status <jail>` (lista "Banned IP list"), nu `get <jail> banned`,
    # pentru compatibilitate maxima. NU presupunem "banat" la eroare — altfel
    # fiecare rulare orara incerca unban + marca CHANGED + trimitea Telegram.
    local st
    st=$(fail2ban-client status "$1" 2>/dev/null) || return 1
    echo "$st" | grep -qw "$2"
}

# Prima regula din INPUT e ACCEPT-ul nostru? (tolerant la format: -s IP sau -s IP/32)
# NOTA: iptables -S afiseaza prima linie politica (-P INPUT ...), nu o regula.
# De aceea o sarim, altfel verificarea pica la fiecare rulare si scriptul
# raporta "modificare" + Telegram in fiecare ora, chiar si fara schimbari.
iptables_input_rules() {
    iptables -S INPUT 2>/dev/null | grep -v '^-P '
}

# 0 = OK: primele N reguli sunt exact ACCEPT-urile whitelist, in ordine,
# deasupra oricarui jump f2b-*. Altfel 1 = necesita reparatie.
# Cu mai multe IP-uri, un singur IP poate fi pe pozitia 1 — vechea verificare
# per-IP marca CHANGED la fiecare ora (flip-flop). Verificam blocul intreg.
whitelist_order_ok() {
    local rules n i line ip
    rules=$(iptables_input_rules)
    [ -z "$rules" ] && return 1
    n=$(echo "$WL" | wc -w)
    i=0
    for ip in $WL; do
        i=$((i + 1))
        line=$(echo "$rules" | sed -n "${i}p")
        case "$line" in
            *"-s $ip"*ACCEPT*|*"--source $ip"*ACCEPT*) ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# Compatibilitate: un singur IP pe pozitia 1 (folosit de --status)
is_top_accept() {
    local first
    first=$(iptables_input_rules | head -1)
    [[ "$first" == *"-s $1"* && "$first" == *"ACCEPT"* ]]
}

if [ "${1:-}" = "--status" ]; then
    echo "=== WHITELIST STATUS ==="
    echo "Lista: $WL"
    if whitelist_order_ok; then
        echo "  Ordine iptables OK: blocul whitelist e deasupra regulilor f2b-*"
    else
        echo "  Ordine iptables NU e OK (va fi reparata la urmatoarea rulare)"
    fi
    for ip in $WL; do
        if is_top_accept "$ip"; then echo "  $ip: ACCEPT pe pozitia 1 OK"; else echo "  $ip: ACCEPT nu e pe pozitia 1 (normal daca ai mai multe IP-uri — conteaza blocul de mai sus)"; fi
        for j in $(jail_list); do
            if is_banned "$j" "$ip"; then echo "  $ip: BANAT in $j (!!)"; fi
        done
        [ -f "$TI_FILE" ] && grep -qx "$ip" "$TI_FILE" && echo "  $ip: prezent in threat-intel (!!)"
    done
    exit 0
fi

# 1. ACCEPT-urile whitelist ca BLOC la inceputul INPUT, deasupra jump-urilor
# f2b-* (o singura reparatie atomica, nu cate una per IP — evita flip-flop-ul
# orar cu 2+ IP-uri unde fiecare rulare muta alt IP pe pozitia 1).
if ! whitelist_order_ok; then
    for ip in $WL; do
        # sterge duplicatele existente (ambele forme: -s IP si -s IP/32)
        while iptables -D INPUT -s "$ip" -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -s "$ip/32" -j ACCEPT 2>/dev/null; do :; done
    done
    # reinsereaza in ordine inversa la pozitia 1 → ordinea finala = ordinea WL
    rev=""
    for ip in $WL; do rev="$ip $rev"; done
    repaired=0
    for ip in $rev; do
        if iptables -I INPUT 1 -s "$ip" -j ACCEPT 2>/dev/null; then
            repaired=1
        fi
    done
    if [ "$repaired" = "1" ]; then
        if whitelist_order_ok; then
            CHANGED=1
            NOTES="$NOTES• Blocul whitelist ACCEPT reasezat deasupra regulilor f2b-*: $WL
"
        fi
    fi
fi

for ip in $WL; do
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

    # 4. ignoreip sync (reload doar daca a lipsit; -w evita match partial 1.2.3.4 vs 1.2.3.40)
    if [ -f "$JAIL_LOCAL" ] && ! grep -qw "$ip" "$JAIL_LOCAL" 2>/dev/null; then
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

if [ "$CHANGED" = "1" ]; then
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] && [ "$TELEGRAM_BOT_TOKEN" != "change-me" ]; then
        MSG="✅ Whitelist guard activ pe $(hostname -f)
$NOTES"
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        timeout 15 "$NOTIFY_SCRIPT" "$MSG" >/dev/null 2>&1 || true
    fi
    echo "[+] Whitelist guard: verificat [$WL ] (reparatii aplicate)"
fi
# Fara modificari: silentios (exit 0 fara output) — cronul orar nu mai
# umple logul si nu mai trimite Telegram la fiecare ora.
exit 0
