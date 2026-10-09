#!/bin/bash
BOUNCER_DIR="/etc/automation-web-hosting"
SCRIPT_DIR="$BOUNCER_DIR/scripts"

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
        fail2ban-client set sshd unbanip "$2"
        fail2ban-client set web-attacks unbanip "$2"
        fail2ban-client set auth-attacks unbanip "$2"
        fail2ban-client set web-scanners unbanip "$2"
        fail2ban-client set behavioral-analysis unbanip "$2"
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
        echo "  status        - Status sistem"
        echo "  stats         - Statistici detaliate"
        echo "  unban IP      - Deblochează IP"
        echo "  backup        - Backup configurație"
        echo "  update-threat - Actualizează liste amenințări"
        echo "  report        - Generează raport"
        echo "  autoheal      - Rulează Auto-Healing manual"
        ;;
esac
