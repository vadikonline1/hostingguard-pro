#!/bin/bash
# =============================================================================
# HostingGuard - common.sh : guard-uri comune anti-suprasarcina
# Sursa cu: source "$(dirname "$0")/common.sh"
# Ofera: apply_low_priority, check_load, acquire_lock, log_line
# =============================================================================

# Aplica nice/ionice scazut procesului curent (nu blocheaza web/mysql)
apply_low_priority() {
    local nice_val="${SCAN_NICE:-19}"
    local io_class="${SCAN_IONICE_CLASS:-3}"
    renice -n "$nice_val" -p $$ >/dev/null 2>&1 || true
    if command -v ionice >/dev/null 2>&1; then
        ionice -c "$io_class" -p $$ >/dev/null 2>&1 || true
    fi
}

# Intoarce 0 daca load-ul e OK, 1 daca e prea mare (trebuie amanat scanul)
# Foloseste MAX_LOAD_FACTOR (default 2.0) * nrCPU
check_load() {
    local factor="${MAX_LOAD_FACTOR:-2.0}"
    [ "$factor" = "0" ] && return 0
    local cpus
    cpus=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    [ "$cpus" -lt 1 ] && cpus=1
    local load1
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    # compara float cu awk
    local over
    over=$(awk -v l="$load1" -v c="$cpus" -v f="$factor" 'BEGIN{print (l > c*f) ? 1 : 0}')
    if [ "$over" = "1" ]; then
        echo "[!] Load prea mare ($load1 > ${cpus}CPU x $factor) — aman scanarea" >&2
        return 1
    fi
    return 0
}

# Lock exclusiv cu flock. Utilizare:
#   acquire_lock "/run/hostingguard-daily.lock" || exit 0
# Intoarce 1 daca alt proces ruleaza (iesi silentios, NU suprapune scanari)
acquire_lock() {
    local lockfile="$1"
    mkdir -p "$(dirname "$lockfile")" 2>/dev/null || true
    exec 9>"$lockfile" 2>/dev/null || return 1
    if ! flock -n 9; then
        echo "[!] Alta instanta ruleaza deja ($lockfile) — ies fara suprapunere" >&2
        return 1
    fi
    echo $$ >&9
    return 0
}

# Alege comanda clam optima: clamdscan (daemon, usor) sau clamscan ( greu )
# echo calea; intoarce 1 daca nimic disponibil
pick_clam_cmd() {
    if [ "${CLAM_USE_DAEMON:-1}" = "1" ] && command -v clamdscan >/dev/null 2>&1; then
        if [ -S /run/clamav/clamd.ctl ] || systemctl is-active --quiet clamav-daemon 2>/dev/null; then
            echo "clamdscan"
            return 0
        fi
    fi
    if command -v clamscan >/dev/null 2>&1; then
        echo "clamscan"
        return 0
    fi
    return 1
}

# Verifica daca un path e sistem critic (in safe-mode NU se carantineaza)
is_system_path() {
    local p="$1"
    case "$p" in
        /bin/*|/sbin/*|/usr/*|/lib*|/etc/passwd*|/etc/shadow*|/etc/ssh/*|\
        /var/lib/mysql*|/var/lib/docker*|/var/lib/postgresql*|/var/spool/*|\
        /proc/*|/sys/*|/dev/*|/run/*) return 0 ;;
    esac
    return 1
}
