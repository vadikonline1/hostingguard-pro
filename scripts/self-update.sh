#!/bin/bash
# =============================================================================
# HostingGuard self-update - actualizare la versiune noua cu rebuild
# Compara VERSION local cu VERSION din origin/main:
#   secmgr update          → daca exista versiune noua: git pull + rebuild
#                              (install-full-stack.sh, idempotent) + Telegram
#   secmgr update --check  → doar verifica + anunta (folosit de cronul
#                              saptamanal; NU modifica nimic)
#   secmgr update --force  → pull + rebuild chiar daca versiunea e aceeasi
# Siguranta: flock anti-dublare; pull doar fast-forward; daca exista
# modificari locale pe server, pull-ul esueaza controlat (fara stricat
# configul) si primesti instructiuni — nu forteaza suprascrierea.
# Utilizare directa: self-update.sh [--check|--force]
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
NOTIFY_SCRIPT="$BOUNCER_DIR/telegram_notify.sh"
VERSION_FILE="$BOUNCER_DIR/VERSION"
INSTALL_SCRIPT="$BOUNCER_DIR/install-full-stack.sh"
LOCK="/run/hostingguard-update.lock"
exec 9>"$LOCK" 2>/dev/null || exit 0
flock -n 9 || { echo "[!] Alt update ruleaza deja — ies"; exit 0; }

if [ -f "$BOUNCER_DIR/hosting.env" ]; then
    # shellcheck disable=SC1091
    source "$BOUNCER_DIR/hosting.env"
fi

MODE="${1:-}"
HOST=$(hostname -f 2>/dev/null || hostname)

notify() {
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] && [ "$TELEGRAM_BOT_TOKEN" != "change-me" ]; then
        export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_THREAD_ID
        timeout 15 "$NOTIFY_SCRIPT" "$1" >/dev/null 2>&1 || true
    fi
}

if [ ! -d "$BOUNCER_DIR/.git" ]; then
    echo "[-] $BOUNCER_DIR nu e clone git — update imposibil"
    exit 1
fi

LOCAL_VER="necunoscut"
[ -f "$VERSION_FILE" ] && LOCAL_VER=$(head -1 "$VERSION_FILE" 2>/dev/null | tr -d ' \n')

git -C "$BOUNCER_DIR" fetch origin main --quiet 2>&1 | head -3 || true
REMOTE_VER=$(git -C "$BOUNCER_DIR" show origin/main:VERSION 2>/dev/null | head -1 | tr -d ' \n\r')

if [ -z "$REMOTE_VER" ]; then
    echo "[!] Nu pot citi VERSION de pe origin/main (retea sau fisier lipsa)"
    exit 1
fi

if [ "$LOCAL_VER" = "$REMOTE_VER" ] && [ "$MODE" != "--force" ]; then
    [ "$MODE" = "--check" ] && echo "[+] HostingGuard $LOCAL_VER — la zi, nimic de facut"
    exit 0
fi

if [ "$MODE" = "--check" ]; then
    echo "[+] Update disponibil: $LOCAL_VER → $REMOTE_VER (ruleaza: secmgr update)"
    notify "⬆️ HostingGuard update disponibil pe $HOST
Versiune instalata: $LOCAL_VER
Versiune noua: $REMOTE_VER
Actualizeaza cu: secmgr update"
    exit 2
fi

echo "[*] Update HostingGuard $LOCAL_VER → $REMOTE_VER ..."
if ! git -C "$BOUNCER_DIR" pull --ff-only origin main; then
    echo "[-] Pull esuat — probabil ai modificari locale pe server."
    echo "    Verifica cu: git -C $BOUNCER_DIR status --short"
    echo "    Pastreaza-le cu: git -C $BOUNCER_DIR stash push -m 'local'"
    echo "    Apoi re-ruleaza: secmgr update"
    notify "⚠️ HostingGuard update ESUAT pe $HOST
$LOCAL_VER → $REMOTE_VER: pull blocat de modificari locale.
Vezi: git -C $BOUNCER_DIR status --short"
    exit 1
fi

chmod +x "$INSTALL_SCRIPT" "$BOUNCER_DIR"/scripts/*.sh 2>/dev/null || true
if bash "$INSTALL_SCRIPT"; then
    NEW_VER=$(head -1 "$VERSION_FILE" 2>/dev/null | tr -d ' \n')
    echo "[+] Update complet: $LOCAL_VER → $NEW_VER (rebuild reusit)"
    notify "✅ HostingGuard actualizat pe $HOST
$LOCAL_VER → $NEW_VER (rebuild reusit)"
else
    echo "[-] Rebuild esuat dupa pull — verifica logul de instalare"
    notify "❌ HostingGuard rebuild ESUAT pe $HOST dupa pull la $REMOTE_VER"
    exit 1
fi
