#!/bin/bash
set -e

CURRENT_PATH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILES="$CURRENT_PATH_DIR/../*.env"

# Încarcă toate fișierele .env
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

# === CONFIG ===
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Configurații cu valori din .env sau fallback
BOUNCER_DIR="${BOUNCER_DIR:-/etc/automation-web-hosting}"
SCRIPT_DIR="${SCRIPT_DIR:-$BOUNCER_DIR/scripts}"
LOG_DIR="${LOG_DIR:-$BOUNCER_DIR/log}"
NOTIFY_SCRIPT="${NOTIFY_SCRIPT:-$BOUNCER_DIR/telegram_notify.sh}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/realtime-monitor.log}"
PID_FILE="${PID_FILE:-$BOUNCER_DIR/clamav-monitor.pid}"
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/quarantine}"

# Configurații pentru scanare
REALTIME_SCAN_PATHS="${REALTIME_SCAN_PATHS:-/var/www /etc/nginx /etc/apache2 /var/tmp /var/upload /var/backups}"
EXCLUDE_PATHS="${EXCLUDE_PATHS:-*.log *.tmp *.cache *.swp *.swx *.pid *.sock}"
MAX_FILE_SIZE="${MAX_FILE_SIZE:-25M}"

# Configurații Telegram (obligatorii)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

# === VARIABILE PENTRU RATE LIMITING ȘI ANTI-DUPLICARE ===
LAST_LOG_CLEANUP=0
LOG_CLEANUP_INTERVAL=3600
EXCLUDED_EVENTS_COUNT=0
LAST_EXCLUDED_LOG=0
EXCLUDED_LOG_INTERVAL=300
RECENTLY_PROCESSED_DIR="/tmp/clamav_processed"
RECENTLY_PROCESSED_TIMEOUT=300  # 5 minute

# === FUNCTIE LOG ===
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"
    
    echo "$log_entry" >> "$LOG_FILE"
    
    # Afișează doar mesajele importante în console
    if [[ "$level" == "ERROR" || "$level" == "ALERT" || "$level" == "WARNING" ]]; then
        echo "$log_entry" >&2
    fi
}

# === FUNCTIE LOG DEBUG (pentru evenimente excluse) ===
log_debug_excluded() {
    local file_path="$1"
    local current_time=$(date +%s)
    
    EXCLUDED_EVENTS_COUNT=$((EXCLUDED_EVENTS_COUNT + 1))
    
    # Loghează doar la fiecare 5 minute sau după 1000 de evenimente excluse
    if [ $((current_time - LAST_EXCLUDED_LOG)) -gt $EXCLUDED_LOG_INTERVAL ] || [ $EXCLUDED_EVENTS_COUNT -gt 1000 ]; then
        log "DEBUG" "Excluded $EXCLUDED_EVENTS_COUNT events (last: $file_path)"
        EXCLUDED_EVENTS_COUNT=0
        LAST_EXCLUDED_LOG=$current_time
    fi
}

# === INIT LOG ȘI DIRECTORY PENTRU ANTI-DUPLICARE ===
mkdir -p "$LOG_DIR"
mkdir -p "$QUARANTINE_DIR"
mkdir -p "$RECENTLY_PROCESSED_DIR"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Curăță fișierele procesate vechi
find "$RECENTLY_PROCESSED_DIR" -type f -mmin +$((RECENTLY_PROCESSED_TIMEOUT / 60)) -delete 2>/dev/null || true

log "INFO" "=== ClamAV Real-Time Monitor - START ==="
log "INFO" "Script directory: $CURRENT_PATH_DIR"
log "INFO" "Bouncer directory: $BOUNCER_DIR"
log "INFO" "Log directory: $LOG_DIR"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Environment loaded: $env_loaded"
log "INFO" "User: $(whoami)"
log "INFO" "PID: $$"

# === VERIFICARE VARIABILE OBLIGATORII ===
if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    log "ERROR" "Missing required Telegram variables: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"
    log "ERROR" "Please set these variables in your .env file"
    exit 1
fi

# === VERIFICARE INSTANTA DUPLA ===
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

# === VARIABILE PENTRU STATISTICI (global) ===
START_TIME=$(date +%s)
TOTAL_FILES_SCANNED=0
TOTAL_THREATS_DETECTED=0
CLEANUP_DONE=0

# === FUNCTIE CLEANUP ===
cleanup() {
    if [ $CLEANUP_DONE -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    
    log "INFO" "Performing cleanup..."
    
    # Oprește toate procesele copil
    pkill -P $$ 2>/dev/null || true
    
    # Așteaptă puțin pentru procesele copil să se închidă
    sleep 2
    
    # Curăță directorul de fișiere procesate
    rm -rf "$RECENTLY_PROCESSED_DIR" 2>/dev/null || true
    
    # Loghează statisticile finale pentru evenimente excluse
    if [ $EXCLUDED_EVENTS_COUNT -gt 0 ]; then
        log "DEBUG" "Final: Excluded $EXCLUDED_EVENTS_COUNT events in total"
    fi
    
    # Notificare de oprire doar dacă monitorizarea a rulat mai mult de 30 de secunde
    local runtime=$(( $(date +%s) - START_TIME ))
    if [ $runtime -gt 30 ]; then
        STOP_MESSAGE="🔴 ClamAV Monitor Stopped
🖥️ Server: $(hostname)
⏰ Uptime: $(($runtime / 60))m $(($runtime % 60))s
📊 Files scanned: $TOTAL_FILES_SCANNED
🦠 Threats detected: $TOTAL_THREATS_DETECTED"

        if send_telegram_notification "$STOP_MESSAGE"; then
            log "INFO" "Stop notification sent successfully"
        else
            log "ERROR" "Failed to send stop notification"
        fi
    fi

    rm -f "$PID_FILE"
    log "INFO" "=== ClamAV Real-Time Monitor - STOP ==="
}

trap cleanup EXIT INT TERM

# === FUNCTIE NOTIFICARE TELEGRAM ===
send_telegram_notification() {
    local message="$1"
    local attempt=0
    local max_attempts=3
    
    # Verifică dacă scriptul de notificare există
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
    return 1
}

# === VERIFICARE COMENZI ===
for cmd in inotifywait clamscan; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "ERROR" "$cmd not found. Please install: apt-get install ${cmd%-wait}"
        exit 1
    fi
done

INOTIFYWAIT_CMD=$(command -v inotifywait)
CLAMSCAN_CMD=$(command -v clamscan)

log "INFO" "Tools verified: inotifywait=$INOTIFYWAIT_CMD, clamscan=$CLAMSCAN_CMD"

# === VERIFICARE SCRIPT NOTIFICARE ===
if [ ! -f "$NOTIFY_SCRIPT" ] || [ ! -x "$NOTIFY_SCRIPT" ]; then
    log "ERROR" "Notification script not found or not executable: $NOTIFY_SCRIPT"
    exit 1
fi

# Testează notificarea
if ! send_telegram_notification "🧪 Test notification from ClamAV Monitor"; then
    log "ERROR" "Telegram notification test failed"
    exit 1
fi

# === MONITOR PATHS ===
MONITOR_PATHS="${REALTIME_SCAN_PATHS}"

log "INFO" "Monitor paths: $MONITOR_PATHS"
log "INFO" "Exclude patterns: $EXCLUDE_PATHS"
log "INFO" "Quarantine directory: $QUARANTINE_DIR"
log "INFO" "Max file size: $MAX_FILE_SIZE"

# Verifică existența directorelor monitorizate
for path in $MONITOR_PATHS; do
    if [ ! -d "$path" ]; then
        log "WARNING" "Monitor path does not exist: $path"
    else
        log "INFO" "Monitoring path: $path"
    fi
done

# === FUNCTIE VERIFICARE EXCLUDE ===
should_exclude() {
    local file_path="$1"
    local filename=$(basename "$file_path")
    
    # Exclude tot folderul de log-uri pentru a evita loop-uri infinite
    if [[ "$file_path" == "$LOG_FILE" ]] || [[ "$file_path" == /var/www/fastuser/data/clam_log/* ]]; then
        return 0  # true - exclude fișierul de log
    fi
    
    # Exclude based on patterns
    for pattern in $EXCLUDE_PATHS; do
        if [[ "$filename" == $pattern ]]; then
            return 0  # true - exclude
        fi
    done
    return 1  # false - don't exclude
}

# === FUNCTIE PENTRU EVITARE DUPLICARE ===
is_recently_processed() {
    local file_path="$1"
    local file_hash=$(echo -n "$file_path" | md5sum | cut -d' ' -f1)
    local marker_file="$RECENTLY_PROCESSED_DIR/$file_hash"
    
    if [ -f "$marker_file" ]; then
        return 0  # true - a fost procesat recent
    fi
    return 1  # false - nu a fost procesat recent
}

mark_as_processed() {
    local file_path="$1"
    local file_hash=$(echo -n "$file_path" | md5sum | cut -d' ' -f1)
    local marker_file="$RECENTLY_PROCESSED_DIR/$file_hash"
    
    touch "$marker_file"
}

# === FUNCTIE CARANTINA IMBUNATATITA ===
quarantine_file() {
    local file_path="$1"
    local threat_name="$2"
    
    # Verifică dacă fișierul mai există
    if [ ! -f "$file_path" ]; then
        log "WARNING" "File already removed: $file_path"
        return 1
    fi
    
    local filename=$(basename "$file_path")
    local quarantine_name="${filename}_$(date +%Y%m%d_%H%M%S)_${threat_name//[^a-zA-Z0-9._-]/_}"
    local quarantine_path="$QUARANTINE_DIR/$quarantine_name"
    
    # Folosește cp + rm pentru a evita conflictele
    if cp "$file_path" "$quarantine_path" 2>/dev/null; then
        if rm -f "$file_path" 2>/dev/null; then
            log "INFO" "File quarantined: $file_path -> $quarantine_path"
            # Setează permisiuni restrictive
            chmod 000 "$quarantine_path" 2>/dev/null || true
            return 0
        else
            # Dacă rm eșuează, șterge copia
            rm -f "$quarantine_path" 2>/dev/null
            log "ERROR" "Failed to remove original file: $file_path"
            return 1
        fi
    else
        log "ERROR" "Failed to copy file to quarantine: $file_path"
        return 1
    fi
}

# === FUNCTIE VERIFICARE DIMENSIUNE ===
check_file_size() {
    local file_path="$1"
    local max_size="$2"
    
    local file_size=$(stat -c%s "$file_path" 2>/dev/null || echo 0)
    local max_size_bytes=$(echo "$max_size" | numfmt --from=iec 2>/dev/null || echo 26214400) # 25M default
    
    if [ "$file_size" -gt "$max_size_bytes" ]; then
        log "WARNING" "File too large: $file_path ($(numfmt --to=iec "$file_size") > $max_size)"
        return 1
    fi
    return 0
}

# === SCAN FUNCTION IMBUNATATITA ===
scan_file() {
    local file_path="$1"
    local file_id="$(date +%s%N | tail -c 8)"
    
    # Verifică dacă fișierul a fost procesat recent
    if is_recently_processed "$file_path"; then
        log "DEBUG" "[$file_id] Recently processed, skipping: $file_path"
        return
    fi
    
    # Incrementăm contorul global
    (echo "$((TOTAL_FILES_SCANNED + 1))" > /tmp/total_files_scanned.$$) 2>/dev/null || true
    
    log "INFO" "[$file_id] 📁 FILE DETECTED: $file_path"

    # Verificări inițiale
    if [ ! -f "$file_path" ] || [ -L "$file_path" ]; then
        log "DEBUG" "[$file_id] Not a regular file or doesn't exist: $file_path"
        return
    fi

    # Verifică exclude patterns (inclusiv fișierul de log)
    if should_exclude "$file_path"; then
        log "DEBUG" "[$file_id] Excluded pattern match: $file_path"
        return
    fi

    # Verifică dimensiunea
    if ! check_file_size "$file_path" "$MAX_FILE_SIZE"; then
        return
    fi

    # Așteaptă să se completeze scrierea (adaptive)
    local file_size=$(stat -c%s "$file_path" 2>/dev/null || echo 0)
    local wait_time=1
    if [ "$file_size" -gt 1048576 ]; then # >1MB
        wait_time=3
    fi
    
    log "DEBUG" "[$file_id] Waiting ${wait_time}s for file write completion..."
    sleep $wait_time

    if [ ! -f "$file_path" ]; then
        log "DEBUG" "[$file_id] File disappeared after wait: $file_path"
        return
    fi

    # Marchează fișierul ca procesat pentru a evita duplicatele
    mark_as_processed "$file_path"

    # Scanare cu timeout
    log "INFO" "[$file_id] 🔍 SCANNING: $file_path ($((file_size/1024))KB)"
    
    local output
    local exit_code=0
    
    # Folosește timeout pentru scanare
    output=$(timeout 30s $CLAMSCAN_CMD --no-summary --infected "$file_path" 2>&1) || exit_code=$?
    
    # Analizează rezultatul
    case $exit_code in
        0)
            # Clean
            log "INFO" "[$file_id] ✅ CLEAN: $file_path"
            ;;
        1)
            # Virus found
            if echo "$output" | grep -q "FOUND"; then
                local threat=$(echo "$output" | grep "FOUND" | awk -F': ' '{print $NF}' | awk '{print $1}')
                # Incrementăm contorul global pentru amenințări
                (echo "$((TOTAL_THREATS_DETECTED + 1))" > /tmp/total_threats_detected.$$) 2>/dev/null || true
                
                log "ALERT" "[$file_id] 🚨 THREAT DETECTED: $file_path (${threat:-Unknown})"
                
                # Încearcă carantina
                if quarantine_file "$file_path" "${threat:-Unknown}"; then
                    local action="quarantined"
                else
                    # Fallback la ștergere
                    if rm -f "$file_path" 2>/dev/null; then
                        action="removed"
                        log "INFO" "[$file_id] File removed: $file_path"
                    else
                        action="REMOVAL_FAILED"
                        log "ERROR" "[$file_id] FAILED to remove file: $file_path"
                    fi
                fi
                
                # Trimite o singură notificare
                if [[ "$action" != "REMOVAL_FAILED" ]]; then
                    MALWARE_MESSAGE="🚨 MALWARE DETECTED & $([[ "$action" == "quarantined" ]] && echo "QUARANTINED" || echo "REMOVED")
📁 File: $(dirname "$file_path")/$(basename "$file_path")
🦠 Threat: ${threat:-Unknown}
🖥️ Server: $(hostname)
⏰ Time: $(date '+%Y-%m-%d %H:%M:%S')
🔒 Action: $action"

                    if send_telegram_notification "$MALWARE_MESSAGE"; then
                        log "INFO" "[$file_id] Telegram notification sent"
                    else
                        log "ERROR" "[$file_id] Failed to send Telegram notification"
                    fi
                fi
            else
                log "WARNING" "[$file_id] Exit code 1 but no threat found: $file_path"
            fi
            ;;
        124)
            log "WARNING" "[$file_id] Scan timeout: $file_path"
            ;;
        2)
            log "ERROR" "[$file_id] Scan error: $file_path - $output"
            ;;
        *)
            log "WARNING" "[$file_id] Unexpected exit code $exit_code: $file_path - $output"
            ;;
    esac
}

# === NOTIFICARE LA PORNIRE ===
START_MESSAGE="🟢 ClamAV Real-Time Monitor Started
🖥️ Server: $(hostname)
⏰ Time: $(date '+%Y-%m-%d %H:%M:%S')
📂 Monitoring: $MONITOR_PATHS
🔒 Quarantine: $QUARANTINE_DIR
📏 Max file size: $MAX_FILE_SIZE"

if send_telegram_notification "$START_MESSAGE"; then
    log "INFO" "Startup notification sent successfully"
else
    log "ERROR" "Startup notification failed"
fi

# === MAIN MONITOR LOOP ===
log "INFO" "=== Starting enhanced monitor loop ==="

# Test inotifywait cu mai multe evenimente
log "INFO" "Testing inotifywait with more events..."
if timeout 10s $INOTIFYWAIT_CMD -r -e create,modify,close_write,moved_to --format '%w%f' "/tmp" 2>&1 | head -3 >/dev/null; then
    log "INFO" "inotifywait test successful"
else
    log "ERROR" "inotifywait test failed"
    exit 1
fi

log "INFO" "=== Starting continuous monitoring ==="

# Rulează inotifywait cu mai multe evenimente
log "INFO" "Starting inotifywait with events: create,modify,close_write,moved_to"
log "INFO" "Excluding log file: $LOG_FILE"
log "INFO" "Excluding entire log folder: /var/www/fastuser/data/clam_log/*"

$INOTIFYWAIT_CMD -m -r -e create,modify,close_write,moved_to --format '%w%f' \
    $MONITOR_PATHS 2>> "$LOG_FILE" | while read -r file_path; do
    
    # Verifică dacă fișierul trebuie exclus (inclusiv fișierul de log)
    if should_exclude "$file_path"; then
        log_debug_excluded "$file_path"
        continue
    fi
    
    # Loghează doar evenimentele care nu sunt excluse
    log "INFO" "🎯 INOTIFY EVENT: $file_path"
    
    # Folosim o variabilă simplă pentru a număra joburile background
    background_jobs=$(jobs -r | wc -l)
    if [ "$background_jobs" -lt 5 ]; then
        scan_file "$file_path" &
    else
        # Dacă sunt prea multe procese, așteaptă
        log "DEBUG" "Too many scan jobs ($background_jobs), waiting..."
        wait
        scan_file "$file_path" &
    fi
    
    # Limită rate-ul de scanare
    sleep 0.1
    
done

log "INFO" "=== Monitor loop ended ==="