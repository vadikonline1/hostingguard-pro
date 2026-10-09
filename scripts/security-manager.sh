#!/bin/bash
# =============================================================================
# HostingGuard security-manager - interfata unificata (versiune usoara)
# =============================================================================
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="$BOUNCER_DIR/scripts"
ENV_FILE="$BOUNCER_DIR/hosting.env"

case "$1" in
    status)
        echo "=== STATUS SISTEM SECURITATE ==="
        fail2ban-client status
        ;;
    stats)
        echo "=== STATISTICI DETALIATE ==="
        "$SCRIPT_DIR/fail2ban-report.sh"
        ;;
    unban)
        if [ -z "$2" ]; then
            echo "Utilizare: $0 unban <IP>"
            exit 1
        fi
        echo "[*] Deblochez IP: $2"
        for jail in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[^:]*://p' | tr ',:\t' '   '); do
            fail2ban-client set "$jail" unbanip "$2" >/dev/null 2>&1 && echo "  - scos din $jail"
        done
        ;;
    whitelist)
        echo "=== WHITELIST (IP-uri care nu sunt blocate niciodata) ==="
        "$SCRIPT_DIR/whitelist-guard.sh" --status
        ;;
    whitelist-add)
        if [ -z "$2" ]; then
            echo "Utilizare: $0 whitelist-add <IP>"
            exit 1
        fi
        if ! [[ "$2" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            echo "[-] IP invalid: $2"
            exit 1
        fi
        if grep -q "^WHITELIST_IPS=" "$ENV_FILE" 2>/dev/null; then
            if grep -q "$2" "$ENV_FILE"; then
                echo "[+] $2 e deja in whitelist"
            elif grep -q 'WHITELIST_IPS="change-me"' "$ENV_FILE"; then
                sed -i "s|^WHITELIST_IPS=.*|WHITELIST_IPS=\"$2\"|" "$ENV_FILE"
                echo "[+] $2 adaugat in whitelist"
            else
                sed -i "s|^WHITELIST_IPS=\"\(.*\)\"|WHITELIST_IPS=\"\1 $2\"|" "$ENV_FILE"
                echo "[+] $2 adaugat in whitelist"
            fi
        else
            echo "WHITELIST_IPS=\"$2\"" >> "$ENV_FILE"
            echo "[+] $2 adaugat in whitelist"
        fi
        echo "[*] Aplic protectia acum..."
        "$SCRIPT_DIR/whitelist-guard.sh"
        ;;
    backup)
        echo "[*] Creare backup configurație..."
        "$SCRIPT_DIR/fail2ban-backup.sh"
        ;;
    update-threat)
        echo "[*] Actualizare liste amenințări..."
        "$SCRIPT_DIR/update-threat-intel.sh"
        ;;
    report)
        echo "[*] Generez raport..."
        "$SCRIPT_DIR/fail2ban-report.sh"
        ;;
    autoheal)
        echo "[*] Rulez Auto-Healing..."
        "$SCRIPT_DIR/fail2ban_autoheal.sh"
        ;;
    *)
        echo "Security Manager - Interfață Unificată"
        echo "Comenzi disponibile:"
        echo "  status            - Status sistem"
        echo "  stats             - Statistici detaliate"
        echo "  unban IP          - Deblochează IP din toate jailurile"
        echo "  whitelist         - Status whitelist (IP-uri protejate)"
        echo "  whitelist-add IP  - Adauga IP in whitelist (nu mai e blocat)"
        echo "  backup            - Backup configurație"
        echo "  update-threat     - Actualizează liste amenințări"
        echo "  report            - Generează raport"
        echo "  autoheal          - Rulează Auto-Healing manual"
        ;;
esac
