#!/bin/bash
# =============================================================================
# Threat intel update - versiune usoara: flock, curl cu timeout/retry/limita,
# scriere atomica, max 50k IP-uri (inainte sorta nelimitat si umfla RAM)
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
LOCK="/run/hostingguard-threat.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || { echo "[!] Threat update deja in curs — ies"; exit 0; }

if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi

renice -n 19 -p $$ >/dev/null 2>&1 || true

THREAT_INTEL_DIR="/var/lib/fail2ban/threat-intel"
mkdir -p "$THREAT_INTEL_DIR"
TMPDIR_WORK=$(mktemp -d)

echo "[*] Actualizare liste Threat Intelligence..."

# descarca cu limite: timeout 30s, retry 2, max 10MB per fisier (anti-OOM)
fetch() {
    local url="$1" out="$2"
    curl -sS --connect-timeout 10 --max-time 30 --retry 2 \
         --max-filesize 10485760 -o "$out.tmp" "$url" 2>/dev/null \
        && mv -f "$out.tmp" "$out" || { rm -f "$out.tmp"; echo "[!] esuat: $url"; }
}

echo "[*] Descărcare Blocklist.de..."
fetch "https://lists.blocklist.de/lists/all.txt" "$TMPDIR_WORK/blocklist_de.txt"
echo "[*] Descărcare Spamhaus DROP..."
fetch "https://www.spamhaus.org/drop/drop.txt" "$TMPDIR_WORK/spamhaus_drop.txt"

# Combina atomic, valideaza IPv4/CIDR, exclude privat/rezervat, limiteaza 50k
echo "[*] Combinare liste..."
cat "$TMPDIR_WORK"/*.txt 2>/dev/null \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
    | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.)' \
    | sort -u | head -n 50000 > "$THREAT_INTEL_DIR/combined_threats.txt.tmp" \
    && mv -f "$THREAT_INTEL_DIR/combined_threats.txt.tmp" "$THREAT_INTEL_DIR/combined_threats.txt"
cp -f "$TMPDIR_WORK"/*.txt "$THREAT_INTEL_DIR"/ 2>/dev/null || true
rm -rf "$TMPDIR_WORK"

COUNT=$(wc -l < "$THREAT_INTEL_DIR/combined_threats.txt" 2>/dev/null || echo 0)

# Notifica DOAR daca esueaza grav sau la cerere (update saptamanal de succes = zgomot)
if [ "$COUNT" -eq 0 ]; then
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        MESSAGE="⚠️ Threat Intelligence GOL (0 IP-uri) pe $(hostname -f) la $(date '+%Y-%m-%d %H:%M:%S') — verifica reteaua/DNS"
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
        timeout 15 "$NOTIFY_SCRIPT" "$MESSAGE" >/dev/null 2>&1 || true
    fi
fi

echo "[+] Threat Intelligence actualizat: $COUNT IP-uri"
