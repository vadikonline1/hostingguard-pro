#!/bin/bash
# =============================================================================
# HostingGuard - common.sh : guard-uri comune + abstractie multi-OS
# Sursa cu: source "$(dirname "$0")/common.sh"
# Ofera: apply_low_priority, check_load, acquire_lock, pick_clam_cmd,
#        is_system_path, detect_os, pkg_install, normalize_whitelist,
#        clam_daemon_service, freshclam_service, clamd_socket_path, lowprio_run
# Suporta: Debian/Ubuntu (apt-get) si Rocky/Alma/RHEL/CentOS (dnf/yum).
# Se scrie numele de pachete DEBIAN; maparea pe RHEL e automata.
# =============================================================================

HG_OS_FAMILY=""
PKG_MGR=""

# Detecteaza familia OS + managerul de pachete (lazy, fara efecte la source)
detect_os() {
    [ -n "$HG_OS_FAMILY" ] && [ -n "$PKG_MGR" ] && return 0
    local id="" like=""
    if [ -f /etc/os-release ]; then
        id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
        like=$(grep '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
    fi
    case " $id $like " in
        *" debian "*|*" ubuntu "*) HG_OS_FAMILY="debian" ;;
        *" rhel "*|*" rocky "*|*" alma "*|*" centos "*|*" fedora "*|*" ol "*) HG_OS_FAMILY="rhel" ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then HG_OS_FAMILY="debian"
            elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then HG_OS_FAMILY="rhel"
            else HG_OS_FAMILY="unknown"
            fi
            ;;
    esac
    if command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"
    elif command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt-get"
    fi
    return 0
}

# Mapeaza nume de pachet Debian → nativ RHEL (pe Debian intoarce inputul)
map_pkg() {
    detect_os
    case "$1" in
        clamav-daemon)    if [ "$HG_OS_FAMILY" = "rhel" ]; then echo "clamd"; else echo "$1"; fi ;;
        clamav-freshclam) if [ "$HG_OS_FAMILY" = "rhel" ]; then echo "clamav-update"; else echo "$1"; fi ;;
        iproute2|ip)      if [ "$HG_OS_FAMILY" = "rhel" ]; then echo "iproute"; else echo "iproute2"; fi ;;
        *) echo "$1" ;;
    esac
}

# 0 daca pachetul e instalat (accepta nume Debian)
pkg_installed() {
    detect_os
    local p
    p=$(map_pkg "$1")
    if [ "$HG_OS_FAMILY" = "rhel" ]; then
        rpm -q "$p" >/dev/null 2>&1
    else
        dpkg -s "$p" >/dev/null 2>&1
    fi
}

# EPEL e obligatoriu pe RHEL pentru fail2ban/inotify-tools/clamav
ensure_epel() {
    detect_os
    [ "$HG_OS_FAMILY" = "rhel" ] || return 0
    rpm -q epel-release >/dev/null 2>&1 && return 0
    echo "[*] Activez EPEL..."
    $PKG_MGR install -y epel-release || true
}

# Instaleaza pachete (nume Debian); sare peste cele existente. Intoarce 0/1.
pkg_install() {
    detect_os
    if [ -z "$PKG_MGR" ]; then
        echo "[-] Niciun package manager gasit (apt-get/dnf/yum)" >&2
        return 1
    fi
    ensure_epel
    local to_install=() p arg
    for arg in "$@"; do
        p=$(map_pkg "$arg")
        if ! pkg_installed "$p"; then
            to_install+=("$p")
        fi
    done
    [ ${#to_install[@]} -eq 0 ] && return 0
    echo "[*] Instalez: ${to_install[*]} (via $PKG_MGR)"
    if [ "$PKG_MGR" = "apt-get" ]; then
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
    else
        $PKG_MGR install -y "${to_install[@]}"
    fi
}

# Numele serviciului ClamAV daemon difera pe RHEL (clamd@scan)
clam_daemon_service() {
    detect_os
    if [ "$HG_OS_FAMILY" = "rhel" ]; then echo "clamd@scan"; else echo "clamav-daemon"; fi
}

freshclam_service() {
    echo "clamav-freshclam"
}

# Socketul clamd difera pe RHEL
clamd_socket_path() {
    detect_os
    if [ "$HG_OS_FAMILY" = "rhel" ]; then echo "/run/clamd.scan/clamd.sock"; else echo "/run/clamav/clamd.ctl"; fi
}

# Normalizeaza WHITELIST_IPS cu virgula SI/sau spatii → o lista cu spatii, un IP/linie curat
# Utilizare: for ip in $(normalize_whitelist "$WHITELIST_IPS"); do ...
normalize_whitelist() {
    echo "$1" | tr ',' ' ' | tr ' ' '\n' | grep -v '^change-me$' | grep -v '^$' \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' | sort -u | tr '\n' ' '
}

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
        local sock
        sock=$(clamd_socket_path)
        local daemon
        daemon=$(clam_daemon_service)
        if [ -S "$sock" ] || systemctl is-active --quiet "$daemon" 2>/dev/null; then
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

# Ruleaza o comanda cu prioritate minima; ionice doar daca exista binarul
# (pe sisteme minimale fara ionice, comanda rula esua silentios — de aici helperul)
lowprio_run() {
    if command -v ionice >/dev/null 2>&1; then
        nice -n "${SCAN_NICE:-19}" ionice -c "${SCAN_IONICE_CLASS:-3}" "$@"
    else
        nice -n "${SCAN_NICE:-19}" "$@"
    fi
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
