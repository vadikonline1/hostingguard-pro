#!/bin/bash
# =============================================================================
# Full System Scan Script (ClamAV + Maldet + rkhunter)
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

DAILY_SCAN_PATHS="${DAILY_SCAN_PATHS:-/var /etc/nginx /etc/apache2}"
FULL_SCAN_PATHS="${FULL_SCAN_PATHS:-/var /etc /home /root /opt /usr /tmp}"
EXCLUDE_PATHS="${EXCLUDE_PATHS:-*.log *.tmp *.cache *.swp *.swx *.pid *.sock /var/lib/clamav/* /var/quarantine/* /proc/* /sys/* /dev/* /run/*}"
MAX_FILE_SIZE="${MAX_FILE_SIZE:-100M}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

# Determine scan type from script name or parameter
SCRIPT_NAME=$(basename "$0")
if [[ "$SCRIPT_NAME" == *"full"* ]] || [[ "$1" == "full" ]]; then
    SCAN_TYPE="full"
    SCAN_PATHS="$FULL_SCAN_PATHS"
    SCAN_PATHS_DISPLAY="Full System (/var, /etc, /home, /root, /opt, /usr, /tmp)"
    MALDET_TIMEOUT=14400  # 4 hours for full scan
    CLAMAV_TIMEOUT=10800  # 3 hours for full scan
else
    SCAN_TYPE="daily"
    SCAN_PATHS="$DAILY_SCAN_PATHS"
    SCAN_PATHS_DISPLAY="Daily Scan (/var, /etc/nginx, /etc/apache2)"
    MALDET_TIMEOUT=3600   # 1 hour for daily scan
    CLAMAV_TIMEOUT=1800   # 30 minutes for daily scan
fi

# --- INIT LOG & PID ----------------------------------------------------------
TIMESTAMP=$(date '+%Y-%m-%d')
LOG_FILE="$LOG_DIR/${SCAN_TYPE}_scan_$TIMESTAMP.log"
PID_FILE="$BOUNCER_DIR/${SCAN_TYPE}-scan.pid"

mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Cleanup old logs and quarantine (păstrează 30 de zile)
find "$LOG_DIR" -type f -name "${SCAN_TYPE}_scan_*" -mtime +7 -delete 2>/dev/null || true
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

# --- QUARANTINE FUNCTION -----------------------------------------------------
quarantine_file() {
    local infected_file="$1"
    local virus_name="$2"
    local scanner="$3"
    
    if [ ! -f "$infected_file" ] && [ ! -d "$infected_file" ]; then
        log "WARNING" "File not found for quarantine: $infected_file"
        return 1
    fi
    
    # Crează nume unic pentru fișierul de carantină
    local base_name=$(basename "$infected_file")
    local file_dir=$(dirname "$infected_file")
    local safe_dir_name=$(echo "$file_dir" | sed 's|^/||' | tr '/' '_')
    local current_time=$(date '+%Y%m%d_%H%M%S')
    local safe_virus_name=$(echo "$virus_name" | tr '/' '_' | tr ' ' '_' | tr '*' 'X' | cut -c1-50)
    
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

# --- CHECK FOR DUPLICATE INSTANCE -------------------------------------------
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log "ERROR" "Another instance is already running (PID: $OLD_PID)"
        exit 1
    else
        log "WARNING" "Stale PID file found, removing..."
        rm -f "$PID_FILE"
    fi
fi
echo $$ > "$PID_FILE"

# --- CLEANUP FUNCTION --------------------------------------------------------
CLEANUP_DONE=0
TOTAL_FILES_SCANNED=0
TOTAL_THREATS_DETECTED=0
TOTAL_QUARANTINED=0
RKHUNTER_WARNINGS=0
START_TIME=$(date +%s)

cleanup() {
    if [ $CLEANUP_DONE -eq 1 ]; then 
        return
    fi
    CLEANUP_DONE=1
    
    local runtime=$(( $(date +%s) - START_TIME ))
    
    # Final statistics
    log "INFO" "=== ${SCAN_TYPE^^} SCAN SUMMARY ==="
    log "INFO" "Duration: $(($runtime / 60))m $(($runtime % 60))s"
    log "INFO" "Files scanned: $TOTAL_FILES_SCANNED"
    log "INFO" "Threats detected: $TOTAL_THREATS_DETECTED"
    log "INFO" "Files quarantined: $TOTAL_QUARANTINED"
    if [ "$SCAN_TYPE" = "full" ]; then
        log "INFO" "rkhunter warnings: $RKHUNTER_WARNINGS"
    fi
    log "INFO" "Quarantine directory: $QUARANTINE_DIR"
    
    # Send final notification
    local scan_emoji="✅"
    local scan_title="Finished"
    if [ $TOTAL_THREATS_DETECTED -gt 0 ] || ([ "$SCAN_TYPE" = "full" ] && [ $RKHUNTER_WARNINGS -gt 0 ]); then
        scan_emoji="🚨"
        scan_title="Finished with Alerts"
    fi
    
    STOP_MESSAGE="$scan_emoji *${SCAN_TYPE^^} System Scan $scan_title*
🖥️ Server: $(hostname)
⏰ Duration: $(($runtime / 60))m $(($runtime % 60))s
📊 Files scanned: $TOTAL_FILES_SCANNED
🦠 Threats detected: $TOTAL_THREATS_DETECTED
🔒 Files quarantined: $TOTAL_QUARANTINED"

    if [ "$SCAN_TYPE" = "full" ]; then
        STOP_MESSAGE="$STOP_MESSAGE
🛡️ rkhunter warnings: $RKHUNTER_WARNINGS"
    fi

    STOP_MESSAGE="$STOP_MESSAGE
📂 Scan paths: $SCAN_PATHS_DISPLAY
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
    
    log "INFO" "=== ${SCAN_TYPE^^} SYSTEM SCAN - STOP ==="
}

trap cleanup EXIT INT TERM

# --- VERIFY REQUIRED COMMANDS ------------------------------------------------
for cmd in clamscan; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "ERROR" "$cmd not found. Install: apt-get install clamav"
        exit 1
    fi
done

MALDET_CMD=""
MALDET_AVAILABLE=0
if command -v maldet >/dev/null 2>&1; then
    MALDET_CMD=$(command -v maldet)
    MALDET_AVAILABLE=1
    log "INFO" "Maldet found: $MALDET_CMD"
else
    log "WARNING" "Maldet not found, skipping Maldet scans"
fi

RKHUNTER_CMD=""
RKHUNTER_AVAILABLE=0
if command -v rkhunter >/dev/null 2>&1; then
    RKHUNTER_CMD=$(command -v rkhunter)
    RKHUNTER_AVAILABLE=1
    log "INFO" "rkhunter found: $RKHUNTER_CMD"
else
    log "WARNING" "rkhunter not found, skipping rootkit scan"
fi

# --- VERIFY TELEGRAM VARIABLES ----------------------------------------------
if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    log "ERROR" "Missing required Telegram variables: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"
    exit 1
fi

# --- MAIN SCAN FUNCTIONS -----------------------------------------------------
run_clamav_scan() {
    local total_infected=0
    local total_scanned=0
    local total_quarantined=0
    local scan_start=$(date +%s)

    log "INFO" "=== STARTING CLAMAV DETAILED SCAN ==="
    
    # Construim array-ul cu opțiuni pentru scanare
    local clamav_opts=(
        --recursive
        --infected
        --max-filesize="$MAX_FILE_SIZE"
        --max-scansize=0
    )
    
    # Adăugăm exclude patterns în array
    for pattern in $EXCLUDE_PATHS; do
        clamav_opts+=(--exclude="$pattern")
    done
    
    for path in $SCAN_PATHS; do
        if [ ! -d "$path" ] && [ ! -f "$path" ]; then 
            log "WARNING" "Path does not exist: $path"
            continue
        fi
        
        log "INFO" "Scanning: $path with ClamAV (detailed) - Excluding: $EXCLUDE_PATHS"
        local output
        local exit_code=0
        local path_infected=0
        local path_scanned=0
        local path_quarantined=0
        
        # Folosim clamscan CU array pentru a evita problemele de quoting
        output=$(timeout $CLAMAV_TIMEOUT clamscan "${clamav_opts[@]}" "$path" 2>&1) || exit_code=$?
        
        # Extrage statistici din output - clamscan cu summary
        path_infected=$(echo "$output" | grep "Infected files:" | awk '{print $3}')
        path_scanned=$(echo "$output" | grep "Scanned files:" | awk '{print $3}')
        
        [ -z "$path_infected" ] && path_infected=0
        [ -z "$path_scanned" ] && path_scanned=0

        # Procesează fișierele infectate pentru carantină
        if [ "$path_infected" -gt 0 ]; then
            log "ALERT" "Found $path_infected infected files in $path"
            
            # Extrage fișierele infectate și le carantinează
            while IFS= read -r line; do
                if echo "$line" | grep -q "FOUND"; then
                    local infected_file
                    local virus_name
                    infected_file=$(echo "$line" | awk -F: '{print $1}')
                    virus_name=$(echo "$line" | awk -F: '{print $2 $3}' | sed 's/^ *//' | sed 's/ FOUND$//')
                    
                    local should_exclude=0
                    
                    # Verifică dacă fișierul ar trebui exclus
                    for pattern in $EXCLUDE_PATHS; do
                        if [[ "$infected_file" == $pattern ]] || [[ "$infected_file" == */$pattern ]]; then
                            should_exclude=1
                            log "INFO" "Excluding detected file (matches $pattern): $infected_file"
                            break
                        fi
                    done
                    
                    if [ $should_exclude -eq 0 ] && [ -n "$infected_file" ]; then
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
                    fi
                fi
            done <<< "$output"
        fi
        
        total_infected=$((total_infected + path_infected))
        total_scanned=$((total_scanned + path_scanned))
        
        log "INFO" "Path $path: $path_infected infected, $path_scanned scanned, $path_quarantined quarantined"
    done

    local scan_end=$(date +%s)
    local scan_duration=$((scan_end - scan_start))
    
    TOTAL_FILES_SCANNED=$((TOTAL_FILES_SCANNED + total_scanned))
    TOTAL_THREATS_DETECTED=$((TOTAL_THREATS_DETECTED + total_infected))
    TOTAL_QUARANTINED=$((TOTAL_QUARANTINED + total_quarantined))
    
    log "INFO" "ClamAV detailed scan completed in ${scan_duration}s"
    log "INFO" "ClamAV totals: $total_infected infected, $total_scanned scanned, $total_quarantined quarantined"
}

run_maldet_scan() {
    if [ $MALDET_AVAILABLE -eq 0 ]; then
        return
    fi

    local scan_start=$(date +%s)
    log "INFO" "=== STARTING MALDET SCAN ==="
    
    local total_quarantined=0
    local filtered_threat_count=0
    
    # Rulează scanarea Maldet cu timeout
    log "INFO" "Running maldet scan with timeout: ${MALDET_TIMEOUT}s"
    local maldet_output
    maldet_output=$(timeout $MALDET_TIMEOUT $MALDET_CMD -a $SCAN_PATHS 2>&1) || true
    
    local scan_end=$(date +%s)
    local scan_duration=$((scan_end - scan_start))
    
    local maldet_log="/usr/local/maldetect/logs/event_log"
    
    if [ -f "$maldet_log" ]; then
        # Extrage toate threat-urile din ultima scanare
        local scan_timestamp=$(date '+%Y-%m-%d %H:%M' --date="1 minute ago")
        local recent_threats=$(grep "$scan_timestamp" "$maldet_log" | grep "hits,")
        
        if [ -n "$recent_threats" ]; then
            # Filtrează threat-urile, excluzând path-urile specificate
            filtered_threat_count=0
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    local should_exclude=0
                    local threat_file
                    local virus_name
                    
                    threat_file=$(echo "$line" | awk '{print $4}' | sed "s/'//g")
                    virus_name=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}' | sed "s/'//g" | sed 's/ *$//')
                    
                    # Verifică dacă threat-ul ar trebui exclus
                    for pattern in $EXCLUDE_PATHS; do
                        if [[ "$threat_file" == $pattern ]] || [[ "$threat_file" == */$pattern ]]; then
                            should_exclude=1
                            log "INFO" "Excluding Maldet threat (matches $pattern): $threat_file"
                            break
                        fi
                    done
                    
                    if [ $should_exclude -eq 0 ] && [ -n "$threat_file" ]; then
                        log "ALERT" "MALDET THREAT: $line"
                        filtered_threat_count=$((filtered_threat_count + 1))
                        
                        # Carantinează fișierul detectat de Maldet
                        if quarantine_file "$threat_file" "$virus_name" "maldet"; then
                            total_quarantined=$((total_quarantined + 1))
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
                TOTAL_QUARANTINED=$((TOTAL_QUARANTINED + total_quarantined))
            else
                log "INFO" "Maldet found no threats after exclusions"
            fi
        else
            log "INFO" "Maldet found no threats in the recent scan"
        fi
    else
        log "WARNING" "Maldet log not found: $maldet_log"
    fi
    
    log "INFO" "Maldet scan completed in ${scan_duration}s"
    log "INFO" "Maldet threats: $filtered_threat_count, quarantined: $total_quarantined"
}

run_rkhunter_scan() {
    if [ $RKHUNTER_AVAILABLE -eq 0 ] || [ "$SCAN_TYPE" != "full" ]; then
        return
    fi

    local scan_start=$(date +%s)
    log "INFO" "=== STARTING RKHUNTER ROOTKIT SCAN ==="
    
    # Actualizează baza de date rkhunter
    log "INFO" "Updating rkhunter database..."
    $RKHUNTER_CMD --update 2>&1 | tee -a "$LOG_FILE"
    
    # Rulează scanarea completă
    log "INFO" "Running rkhunter comprehensive scan..."
    local rkhunter_output
    rkhunter_output=$($RKHUNTER_CMD --check --sk --rwo 2>&1)
    
    local scan_end=$(date +%s)
    local scan_duration=$((scan_end - scan_start))
    
    # Analizează output-ul pentru warnings
    local warning_count=$(echo "$rkhunter_output" | grep -c "Warning" || true)
    RKHUNTER_WARNINGS=$warning_count
    
    # Loghează rezultatele importante
    echo "$rkhunter_output" | grep -E "(Warning|Notice|Checking)" | while read -r line; do
        if echo "$line" | grep -q "Warning"; then
            log "RKHUNTER_ALERT" "$line"
        else
            log "RKHUNTER_INFO" "$line"
        fi
    done
    
    # Extrage și loghează sistemul de fișiere suspecte
    local suspicious_files=$(echo "$rkhunter_output" | grep -A10 "Suspect files" | tail -n +2)
    if [ -n "$suspicious_files" ]; then
        log "RKHUNTER_ALERT" "Suspicious files detected:"
        echo "$suspicious_files" | while read -r file; do
            if [ -n "$file" ]; then
                log "RKHUNTER_ALERT" "Suspicious: $file"
            fi
        done
    fi
    
    log "INFO" "rkhunter scan completed in ${scan_duration}s"
    log "INFO" "rkhunter warnings: $warning_count"
    
    # Raport simplificat pentru notificare
    if [ $warning_count -gt 0 ]; then
        log "ALERT" "rkhunter found $warning_count warnings - Review the log for details"
    else
        log "INFO" "rkhunter found no critical issues"
    fi
}

# --- MAIN EXECUTION ----------------------------------------------------------
log "INFO" "=== ${SCAN_TYPE^^} SYSTEM SCAN START ==="
log "INFO" "Script: $(basename "$0")"
log "INFO" "PID: $$"
log "INFO" "User: $(whoami)"
log "INFO" "Scan type: $SCAN_TYPE"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Quarantine directory: $QUARANTINE_DIR"
log "INFO" "Excluded paths: $EXCLUDE_PATHS"
log "INFO" "Timeouts - ClamAV: ${CLAMAV_TIMEOUT}s, Maldet: ${MALDET_TIMEOUT}s"

# Verifică dacă directorul de carantină este accesibil
if [ ! -w "$QUARANTINE_DIR" ]; then
    log "ERROR" "Quarantine directory is not writable: $QUARANTINE_DIR"
    exit 1
fi

# Run scans
run_clamav_scan
run_maldet_scan

# Rulează rkhunter doar pentru scanări complete
if [ "$SCAN_TYPE" = "full" ]; then
    run_rkhunter_scan
fi

log "INFO" "=== ${SCAN_TYPE^^} SYSTEM SCAN COMPLETED ==="

# Cleanup will be called automatically via trap