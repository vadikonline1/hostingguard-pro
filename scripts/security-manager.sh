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
        for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2- | tr ',' ' '); do
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
        # accepta "1.2.3.4" sau "1.2.3.4,5.6.7.8"; normalizeaza la format cu virgula
        newips=$(echo "$2" | tr ' ' ',')
        valid=""
        for nip in $(echo "$newips" | tr ',' ' '); do
            if [[ "$nip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                valid="$valid,$nip"
            else
                echo "[-] IP invalid (ignorat): $nip"
            fi
        done
        valid=$(echo "$valid" | sed 's/^,//')
        if [ -z "$valid" ]; then
            echo "[-] Niciun IP valid"
            exit 1
        fi
        if grep -q "^WHITELIST_IPS=" "$ENV_FILE" 2>/dev/null; then
            current=$(grep "^WHITELIST_IPS=" "$ENV_FILE" | cut -d'"' -f2)
            if [ "$current" = "change-me" ] || [ -z "$current" ]; then
                merged="$valid"
            else
                merged="$current,$valid"
            fi
            # normalizeaza: virgule, fara duplicate/spatii goale
            merged=$(echo "$merged" | tr ' ' ',' | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)
            sed -i "s|^WHITELIST_IPS=.*|WHITELIST_IPS=\"$merged\"|" "$ENV_FILE"
            echo "[+] Whitelist acum: $merged"
        else
            echo "WHITELIST_IPS=\"$valid\"" >> "$ENV_FILE"
            echo "[+] $valid adaugat in whitelist"
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
    version)
        echo -n "HostingGuard versiune: "
        cat "$BOUNCER_DIR/VERSION" 2>/dev/null || echo "necunoscut (lipseste $BOUNCER_DIR/VERSION)"
        ;;
    update)
        # secmgr update [--check|--force] → pull + rebuild la versiune noua
        echo "[*] Verific update-uri..."
        bash "$SCRIPT_DIR/self-update.sh" "${2:-}"
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
        echo "  version           - Arată versiunea instalată"
        echo "  update [--check|--force] - Actualizează la versiunea nouă + rebuild"
        echo "  autoheal          - Rulează Auto-Healing manual"
        ;;
esac
