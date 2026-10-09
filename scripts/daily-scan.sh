#!/bin/bash
# =============================================================================
# Daily Malware Scan Script (ClamAV + Maldet)
# Comprehensive version with quarantine management and proper statistics
# =============================================================================

set -e

# --- LOCATE AND LOAD ENV FILES ----------------------------------------------
CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILES="$CURRENT_PATH_DIR/../*.env"

env_loaded=0
for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        echo "[*] Loading environment from: $env_file" >&2
        source "$env_file"
        env_loaded=1
    fi
done

if [ $env_loaded -eq 0 ]; then
    echo "[!] WARNING: No .env files found in $CURRENT_PATH_DIR/../" >&2
fi

# --- CONFIGURATIONS ----------------------------------------------------------
BOUNCER_DIR="${BOUNCER_DIR:-/etc/automation-web-hosting}"
SCRIPT_DIR="${SCRIPT_DIR:-$BOUNCER_DIR/scripts}"
LOG_DIR="${LOG_DIR:-$BOUNCER_DIR/log}"
NOTIFY_SCRIPT="${NOTIFY_SCRIPT:-$BOUNCER_DIR/telegram_notify.sh}"
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/quarantine}"

# Cai sigure default: doar web/home/tmp — NU tot /var (mysql/docker/spool blocheaza IO)
DAILY_SCAN_PATHS="${DAILY_SCAN_PATHS:-/var/www /home /tmp /var/tmp /etc/nginx /etc/apache2}"
EXCLUDE_PATHS="${EXCLUDE_PATHS:-*.log *.tmp *.cache *.swp *.swx *.pid *.sock /var/lib/clamav/* /var/quarantine/*}"
MAX_FILE_SIZE="${MAX_FILE_SIZE:-25M}"
MAX_SCANSIZE="${MAX_SCANSIZE:-50M}"
DAILY_CLAMAV_TIMEOUT="${DAILY_CLAMAV_TIMEOUT:-2700}"
MALDET_TIMEOUT="${MALDET_TIMEOUT_DAILY:-1800}"
ENABLE_MALDET="${ENABLE_MALDET:-1}"
QUARANTINE_MODE="${QUARANTINE_MODE:-safe}"

# Guard-uri comune: prioritate scazuta + lock + load-check (anti-blocare VPS)
# shellcheck disable=SC1091
[ -f "$SCRIPT_DIR/common.sh" ] && source "$SCRIPT_DIR/common.sh"
apply_low_priority 2>/dev/null || true
acquire_lock "/run/hostingguard-daily.lock" || exit 0
if ! check_load 2>/dev/null; then
    echo "[!] Daily scan amanat: load prea mare. Reincearca la urmatoarea rulare." >&2
    exit 0
fi

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

# --- INIT LOG & PID ----------------------------------------------------------
TIMESTAMP=$(date '+%Y-%m-%d')
LOG_FILE="$LOG_DIR/daily_scan_$TIMESTAMP.log"
PID_FILE="$BOUNCER_DIR/daily-scan.pid"

mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Cleanup old logs and quarantine (păstrează 30 de zile)
find "$LOG_DIR" -type f -name "daily_scan_*" -mtime +7 -delete 2>/dev/null || true
find "$QUARANTINE_DIR" -type f -mtime +30 -delete 2>/dev/null || true

# --- LOG FUNCTION ------------------------------------------------------------
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" >&2
}

# --- TELEGRAM FUNCTION -------------------------------------------------------
send_telegram_notification() {
    local message="$1"
    local attempt=0
    local max_attempts=3
    
    if [ ! -f "$NOTIFY_SCRIPT" ] || [ ! -x "$NOTIFY_SCRIPT" ]; then
        log "ERROR" "Notification script not found or not executable: $NOTIFY_SCRIPT"
        return 1
    fi
    
    while [ $attempt -lt $max_attempts ]; do
        if TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID" \
           "$NOTIFY_SCRIPT" "$message" >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    log "ERROR" "Failed to send Telegram notification after $max_attempts attempts"
    return 1
}

# --- QUARANTINE FUNCTION (safe-mode: NU muta fisiere sistem) -------------------
quarantine_file() {
    local infected_file="$1"
    local virus_name="$2"
    local scanner="$3"

    # In safe-mode, fisierele sistem critice NU se carantineaza — doar raport
    if [ "${QUARANTINE_MODE:-safe}" = "safe" ] && type is_system_path >/dev/null 2>&1; then
        if is_system_path "$infected_file"; then
            log "ALERT" "SYSTEM PATH threat (NU carantinez, doar raportez): $infected_file ($virus_name)"
            return 2
        fi
    fi
    
    if [ ! -f "$infected_file" ] && [ ! -d "$infected_file" ]; then
        log "WARNING" "File not found for quarantine: $infected_file"
        return 1
    fi
    
    # Crează nume unic pentru fișierul de carantină
    local base_name=$(basename "$infected_file")
    local file_dir=$(dirname "$infected_file")
    local safe_dir_name=$(echo "$file_dir" | sed 's|^/||' | tr '/' '_')
    local current_time=$(date '+%Y%m%d_%H%M%S')
    local safe_virus_name=$(echo "$virus_name" | tr '/' '_' | tr ' ' '_' | tr '*' 'X')
    
    local quarantine_name="${scanner}_${safe_dir_name}_${base_name}_${current_time}__${safe_virus_name}"
    local quarantine_path="$QUARANTINE_DIR/$quarantine_name"
    
    # Asigură-te că numele nu este prea lung
    if [ ${#quarantine_path} -gt 240 ]; then
        local max_base_length=$((240 - ${#QUARANTINE_DIR} - 65))
        local shortened_base=$(echo "$base_name" | cut -c1-$max_base_length)
        quarantine_name="${scanner}_${safe_dir_name}_${shortened_base}_${current_time}__${safe_virus_name}"
        quarantine_path="$QUARANTINE_DIR/$quarantine_name"
    fi
    
    # Încearcă să muți fișierul în carantină
    if mv "$infected_file" "$quarantine_path" 2>/dev/null; then
        log "QUARANTINE" "Successfully quarantined: $infected_file -> $quarantine_name"
        chmod 000 "$quarantine_path" 2>/dev/null || true
        return 0
    else
        # Dacă mv eșuează, încearcă cp + rm
        if cp -r "$infected_file" "$quarantine_path" 2>/dev/null; then
            rm -rf "$infected_file" 2>/dev/null
            log "QUARANTINE" "Copied and removed (quarantine): $infected_file -> $quarantine_name"
            chmod 000 "$quarantine_path" 2>/dev/null || true
            return 0
        else
            log "ERROR" "Failed to quarantine file: $infected_file"
            return 1
        fi
    fi
}

# --- CHECK FOR DUPLICATE INSTANCE (flock e deja activ; PID e doar informativ) --
echo $$ > "$PID_FILE" 2>/dev/null || true

# --- CLEANUP FUNCTION --------------------------------------------------------
CLEANUP_DONE=0
TOTAL_FILES_SCANNED=0
TOTAL_THREATS_DETECTED=0
TOTAL_QUARANTINED=0
START_TIME=$(date +%s)

cleanup() {
    if [ $CLEANUP_DONE -eq 1 ]; then 
        return
    fi
    CLEANUP_DONE=1
    
    local runtime=$(( $(date +%s) - START_TIME ))
    
    # Final statistics
    log "INFO" "=== SCAN SUMMARY ==="
    log "INFO" "Duration: $(($runtime / 60))m $(($runtime % 60))s"
    log "INFO" "Files scanned: $TOTAL_FILES_SCANNED"
    log "INFO" "Threats detected: $TOTAL_THREATS_DETECTED"
    log "INFO" "Files quarantined: $TOTAL_QUARANTINED"
    log "INFO" "Quarantine directory: $QUARANTINE_DIR"
    
    # Send final notification
    STOP_MESSAGE="✅ *Daily Malware Scan Finished*
🖥️ Server: $(hostname)
⏰ Duration: $(($runtime / 60))m $(($runtime % 60))s
📊 Files scanned: $TOTAL_FILES_SCANNED
🦠 Threats detected: $TOTAL_THREATS_DETECTED
🔒 Files quarantined: $TOTAL_QUARANTINED
📂 Quarantine: $QUARANTINE_DIR
🚫 Excluded: /var/lib/clamav/*, /var/quarantine/*"

    if send_telegram_notification "$STOP_MESSAGE"; then
        log "INFO" "Final notification sent successfully"
    else
        log "ERROR" "Failed to send final notification"
    fi

    # Cleanup PID file
    if [ -f "$PID_FILE" ] && [ "$(cat "$PID_FILE")" = "$$" ]; then
        rm -f "$PID_FILE"
    fi
    
    log "INFO" "=== DAILY MALWARE SCAN - STOP ==="
}

trap cleanup EXIT INT TERM

# --- VERIFY REQUIRED COMMANDS (accepta clamscan SAU clamdscan) -----------------
if ! command -v clamscan >/dev/null 2>&1 && ! command -v clamdscan >/dev/null 2>&1; then
    log "ERROR" "nici clamscan, nici clamdscan gasit. Instaleaza: apt-get install clamav clamav-daemon"
    exit 1
fi

MALDET_CMD=""
MALDET_AVAILABLE=0
if command -v maldet >/dev/null 2>&1; then
    MALDET_CMD=$(command -v maldet)
    MALDET_AVAILABLE=1
    log "INFO" "Maldet found: $MALDET_CMD"
else
    log "WARNING" "Maldet not found, skipping Maldet scans"
fi

# --- VERIFY TELEGRAM VARIABLES ----------------------------------------------
if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    log "ERROR" "Missing required Telegram variables: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"
    exit 1
fi

# --- SEND START NOTIFICATION -------------------------------------------------
START_MESSAGE="🟢 *Daily Malware Scan Started*
🖥️ Server: $(hostname)
⏰ Time: $(date '+%Y-%m-%d %H:%M:%S')
📂 Scan paths: $DAILY_SCAN_PATHS
🚫 Excluded paths: /var/lib/clamav/*, /var/quarantine/*
🔍 Scanners: ClamAV (detailed) + Maldet
🔒 Auto-quarantine: ENABLED
📁 Quarantine dir: $QUARANTINE_DIR"

if send_telegram_notification "$START_MESSAGE"; then
    log "INFO" "Start notification sent successfully"
else
    log "ERROR" "Failed to send start notification"
fi

# --- MAIN SCAN FUNCTIONS -----------------------------------------------------
run_clamav_scan() {
    local total_infected=0
    local total_scanned=0
    local total_quarantined=0
    local scan_start=$(date +%s)

    log "INFO" "=== STARTING CLAMAV DETAILED SCAN ==="

    # Alege scannerul usor (clamdscan daemon) daca e disponibil — altfel clamscan
    CLAM_CMD="clamscan"
    CLAM_IS_DAEMON=0
    if type pick_clam_cmd >/dev/null 2>&1; then
        CLAM_CMD=$(pick_clam_cmd 2>/dev/null || echo "clamscan")
    fi
    [ "$CLAM_CMD" = "clamdscan" ] && CLAM_IS_DAEMON=1
    log "INFO" "Clam engine: $CLAM_CMD (daemon=$CLAM_IS_DAEMON), timeout=${DAILY_CLAMAV_TIMEOUT}s"

    # Optiuni cu limite REALE (inainte: --max-scansize=0 = nelimitat => OOM/IO stall)
    local clamav_opts=(
        --recursive
        --infected
        --max-filesize="$MAX_FILE_SIZE"
        --max-scansize="$MAX_SCANSIZE"
        --max-recursion=10
        --exclude-dir=^/proc
        --exclude-dir=^/sys
        --exclude-dir=^/dev
        --exclude-dir=^/run
        --exclude-dir=^/var/lib/mysql
        --exclude-dir=^/var/lib/docker
        --exclude-dir=^/var/lib/postgresql
        --exclude-dir=^/var/lib/clamav
        --exclude-dir=^/var/spool
        --exclude-dir=^/var/cache
    )
    # Daemonul scaneaza paralel, mult mai ieftin
    [ "$CLAM_IS_DAEMON" = "1" ] && clamav_opts+=(--multiscan --fdpass)
    
    # Adăugăm exclude patterns în array
    for pattern in $EXCLUDE_PATHS; do
        clamav_opts+=(--exclude="$pattern")
    done
    
    for path in $DAILY_SCAN_PATHS; do
        if [ ! -d "$path" ]; then 
            log "WARNING" "Path does not exist: $path"
            continue
        fi
        
        log "INFO" "Scanning: $path with ClamAV (detailed) - Excluding: $EXCLUDE_PATHS"
        local output
        local exit_code=0
        local path_infected=0
        local path_scanned=0
        local path_quarantined=0
        
        # Timeout dur per path — inainte rula nelimitat si bloca VPS-ul ore intregi
        output=$(timeout "$DAILY_CLAMAV_TIMEOUT" "$CLAM_CMD" "${clamav_opts[@]}" "$path" 2>&1) || exit_code=$?
        if [ "$exit_code" -eq 124 ]; then
            log "WARNING" "Timeout la scanarea $path dupa ${DAILY_CLAMAV_TIMEOUT}s — trec mai departe"
            continue
        fi
        
        # Extrage statistici din output - clamscan cu summary
        path_infected=$(echo "$output" | grep "Infected files:" | awk '{print $3}')
        path_scanned=$(echo "$output" | grep "Scanned files:" | awk '{print $3}')
        
        [ -z "$path_infected" ] && path_infected=0
        [ -z "$path_scanned" ] && path_scanned=0

        # Procesează fișierele infectate pentru carantină
        if [ "$path_infected" -gt 0 ]; then
            log "ALERT" "Found $path_infected infected files in $path"
            
            # Extrage fișierele infectate și le carantinează
            echo "$output" | grep "FOUND" | while read -r line; do
                local infected_file
                local virus_name
                infected_file=$(echo "$line" | awk -F: '{print $1}')
                virus_name=$(echo "$line" | awk -F: '{print $2}' | sed 's/^ *//' | sed 's/ FOUND$//')
                
                local should_exclude=0
                
                # Verifică dacă fișierul ar trebui exclus
                for pattern in $EXCLUDE_PATHS; do
                    if [[ "$infected_file" == $pattern ]] || [[ "$infected_file" == */$pattern ]]; then
                        should_exclude=1
                        log "INFO" "Excluding detected file (matches $pattern): $infected_file"
                        break
                    fi
                done
                
                if [ $should_exclude -eq 0 ]; then
                    log "ALERT" "CLAMAV THREAT: $line"
                    
                    # Carantinează fișierul
                    if quarantine_file "$infected_file" "$virus_name" "clamav"; then
                        path_quarantined=$((path_quarantined + 1))
                        total_quarantined=$((total_quarantined + 1))
                        log "QUARANTINE" "Quarantined: $infected_file (Virus: $virus_name)"
                    else
                        log "ERROR" "Failed to quarantine: $infected_file"
                    fi
                else
                    # Scădem din contor dacă am exclus un fișier
                    path_infected=$((path_infected - 1))
                    total_infected=$((total_infected - 1))
                fi
            done
        fi
        
        total_infected=$((total_infected + path_infected))
        total_scanned=$((total_scanned + path_scanned))
        
        log "INFO" "Path $path: $path_infected infected, $path_scanned scanned, $path_quarantined quarantined"
    done

    local scan_end=$(date +%s)
    local scan_duration=$((scan_end - scan_start))
    
    TOTAL_FILES_SCANNED=$total_scanned
    TOTAL_THREATS_DETECTED=$((TOTAL_THREATS_DETECTED + total_infected))
    TOTAL_QUARANTINED=$((TOTAL_QUARANTINED + total_quarantined))
    
    log "INFO" "ClamAV detailed scan completed in ${scan_duration}s"
    log "INFO" "ClamAV totals: $total_infected infected, $total_scanned scanned, $total_quarantined quarantined"
}

run_maldet_scan() {
    if [ "${ENABLE_MALDET:-1}" = "0" ]; then
        log "INFO" "Maldet dezactivat prin ENABLE_MALDET=0 (VPS mic) — skip"
        return
    fi
    if [ $MALDET_AVAILABLE -eq 0 ]; then
        return
    fi

    local scan_start=$(date +%s)
    log "INFO" "=== STARTING MALDET SCAN ==="
    
    local total_quarantined=0
    
    # Excludem path-urile pentru Maldet; timeout configurabil (inainte fix 3600s)
    local maldet_output
    maldet_output=$(timeout "$MALDET_TIMEOUT" nice -n 19 ionice -c3 $MALDET_CMD -a $DAILY_SCAN_PATHS 2>&1) || true
    
    local scan_end=$(date +%s)
    local scan_duration=$((scan_end - scan_start))
    
    local maldet_log="/usr/local/maldetect/logs/event_log"
    local threat_count=0
    local filtered_threat_count=0
    
    if [ -f "$maldet_log" ]; then
        # Extrage toate threat-urile din ultima scanare
        local scan_timestamp=$(date +"%Y-%m-%d" --date="1 minute ago")
        local recent_threats=$(grep "$scan_timestamp.*hits," "$maldet_log")
        threat_count=$(echo "$recent_threats" | wc -l 2>/dev/null || echo 0)
        
        if [ "$threat_count" -gt 0 ]; then
            # Filtrează threat-urile, excluzând path-urile specificate
            filtered_threat_count=0
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    local should_exclude=0
                    local threat_file
                    local virus_name
                    
                    threat_file=$(echo "$line" | awk '{print $4}' | sed "s/'//g")
                    virus_name=$(echo "$line" | awk '{print $6}' | sed "s/'//g")
                    
                    # Verifică dacă threat-ul ar trebui exclus
                    for pattern in $EXCLUDE_PATHS; do
                        if [[ "$threat_file" == $pattern ]] || [[ "$threat_file" == */$pattern ]]; then
                            should_exclude=1
                            log "INFO" "Excluding Maldet threat (matches $pattern): $threat_file"
                            break
                        fi
                    done
                    
                    if [ $should_exclude -eq 0 ]; then
                        log "ALERT" "MALDET THREAT: $line"
                        filtered_threat_count=$((filtered_threat_count + 1))
                        
                        # Carantinează fișierul detectat de Maldet
                        if quarantine_file "$threat_file" "$virus_name" "maldet"; then
                            total_quarantined=$((total_quarantined + 1))
                            TOTAL_QUARANTINED=$((TOTAL_QUARANTINED + 1))
                            log "QUARANTINE" "Quarantined: $threat_file (Virus: $virus_name)"
                        else
                            log "ERROR" "Failed to quarantine: $threat_file"
                        fi
                    fi
                fi
            done <<< "$recent_threats"
            
            if [ "$filtered_threat_count" -gt 0 ]; then
                log "ALERT" "Maldet found $filtered_threat_count threats (after exclusions)"
                TOTAL_THREATS_DETECTED=$((TOTAL_THREATS_DETECTED + filtered_threat_count))
            else
                log "INFO" "Maldet found no threats after exclusions"
            fi
        else
            log "INFO" "Maldet found no threats"
        fi
    else
        log "WARNING" "Maldet log not found: $maldet_log"
    fi
    
    log "INFO" "Maldet scan completed in ${scan_duration}s"
    log "INFO" "Maldet threats: $filtered_threat_count (after exclusions), quarantined: $total_quarantined"
}

# --- MAIN EXECUTION ----------------------------------------------------------
log "INFO" "=== DAILY MALWARE SCAN START ==="
log "INFO" "Script: $(basename "$0")"
log "INFO" "PID: $$"
log "INFO" "User: $(whoami)"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Quarantine directory: $QUARANTINE_DIR"
log "INFO" "Excluded paths: $EXCLUDE_PATHS"

# Verifică dacă directorul de carantină este accesibil
if [ ! -w "$QUARANTINE_DIR" ]; then
    log "ERROR" "Quarantine directory is not writable: $QUARANTINE_DIR"
    exit 1
fi

# Run scans
run_clamav_scan
run_maldet_scan

log "INFO" "=== DAILY MALWARE SCAN COMPLETED ==="

# Cleanup will be called automatically via trap