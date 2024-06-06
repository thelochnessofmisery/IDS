#!/bin/bash

# Load configuration
source ./ids.conf

# Ensure the baseline directory exists
mkdir -p "$BASELINE_DIR"

# Ensure the log directory exists
LOG_DIR=$(dirname "$LOG_FILE")
mkdir -p "$LOG_DIR"

# Function to decrypt the configuration storage
decrypt_config() {
    openssl enc -aes-256-cbc -d -in "$CONFIG_STORAGE" -out "decrypted_config.conf" -pass pass:yourpassword
    source ./decrypted_config.conf
    rm decrypted_config.conf
}

# Function to create a baseline of the current state of the directories
create_baseline() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Creating baseline..." | tee -a "$LOG_FILE"
    for DIR in $MONITORED_DIRS; do
        BASELINE_FILE="$BASELINE_DIR/$(basename $DIR)_baseline.sha256"
        find "$DIR" -type f -exec sha256sum {} \; | parallel > "$BASELINE_FILE"
        gpg --yes --default-key "$GPG_KEY" --sign "$BASELINE_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Baseline for $DIR created and signed." | tee -a "$LOG_FILE"
    done

    for REMOTE in $REMOTE_DIRS; do
        REMOTE_BASELINE_FILE="$BASELINE_DIR/$(echo $REMOTE | sed 's/[@:\/]/_/g')_baseline.sha256"
        ssh "$REMOTE" "find /path/to/dir -type f -exec sha256sum {} \;" | parallel > "$REMOTE_BASELINE_FILE"
        gpg --yes --default-key "$GPG_KEY" --sign "$REMOTE_BASELINE_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Baseline for $REMOTE created and signed." | tee -a "$LOG_FILE"
    done
}

# Function to compare the current state with the baseline
check_for_changes() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Checking for changes..." | tee -a "$LOG_FILE"
    for DIR in $MONITORED_DIRS; do
        BASELINE_FILE="$BASELINE_DIR/$(basename $DIR)_baseline.sha256"
        SIG_FILE="$BASELINE_FILE.sig"
        
        if [ ! -f "$BASELINE_FILE" ] || [ ! -f "$SIG_FILE" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Baseline or signature file for $DIR not found. Please create a baseline first using --create-baseline." | tee -a "$LOG_FILE"
            continue
        fi
        
        if ! gpg --verify "$SIG_FILE" "$BASELINE_FILE"; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Signature verification failed for $DIR." | tee -a "$LOG_FILE"
            continue
        fi

        TEMP_FILE=$(mktemp)
        find "$DIR" -type f -exec sha256sum {} \; | parallel > "$TEMP_FILE"

        # Compare the current state with the baseline
        CHANGES=$(diff "$BASELINE_FILE" "$TEMP_FILE")

        if [ -n "$CHANGES" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Changes detected in $DIR:" | tee -a "$LOG_FILE"
            echo "$CHANGES" | tee -a "$LOG_FILE"
            sqlite3 "$DATABASE" "INSERT INTO logs (timestamp, directory, changes) VALUES ('$(date '+%Y-%m-%d %H:%M:%S')', '$DIR', '$CHANGES');"
            # Send email notification
            echo -e "Subject: Intrusion Detected\n\nChanges detected in $DIR:\n$CHANGES" | sendmail "$EMAIL"
            # Send webhook notification
            curl -X POST -H "Content-Type: application/json" -d "{\"directory\":\"$DIR\", \"changes\":\"$CHANGES\"}" "$WEBHOOK_URL"
            # Send alert to REST API
            curl -X POST -H "Content-Type: application/json" -d "{\"directory\":\"$DIR\", \"changes\":\"$CHANGES\"}" "$API_ENDPOINT"
            # Send logs to Elasticsearch
            curl -X POST "$ELASTICSEARCH_SERVER/_doc" -H "Content-Type: application/json" -d "{\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\", \"directory\":\"$DIR\", \"changes\":\"$CHANGES\"}"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - No changes detected in $DIR." | tee -a "$LOG_FILE"
        fi

        # Clean up temporary file
        rm "$TEMP_FILE"
    done

    for REMOTE in $REMOTE_DIRS; do
        REMOTE_BASELINE_FILE="$BASELINE_DIR/$(echo $REMOTE | sed 's/[@:\/]/_/g')_baseline.sha256"
        SIG_FILE="$REMOTE_BASELINE_FILE.sig"
        
        if [ ! -f "$REMOTE_BASELINE_FILE" ] || [ ! -f "$SIG_FILE" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Baseline or signature file for $REMOTE not found. Please create a baseline first using --create-baseline." | tee -a "$LOG_FILE"
            continue
        fi
        
        if ! gpg --verify "$SIG_FILE" "$REMOTE_BASELINE_FILE"; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Signature verification failed for $REMOTE." | tee -a "$LOG_FILE"
            continue
        fi

        TEMP_FILE=$(mktemp)
        ssh "$REMOTE" "find /path/to/dir -type f -exec sha256sum {} \;" | parallel > "$TEMP_FILE"

        # Compare the current state with the baseline
        CHANGES=$(diff "$REMOTE_BASELINE_FILE" "$TEMP_FILE")

        if [ -n "$CHANGES" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Changes detected in $REMOTE:" | tee -a "$LOG_FILE"
            echo "$CHANGES" | tee -a "$LOG_FILE"
            sqlite3 "$DATABASE" "INSERT INTO logs (timestamp, directory, changes) VALUES ('$(date '+%Y-%m-%d %H:%M:%S')', '$REMOTE', '$CHANGES');"
            # Send email notification
            echo -e "Subject: Intrusion Detected\n\nChanges detected in $REMOTE:\n$CHANGES" | sendmail "$EMAIL"
            # Send webhook notification
            curl -X POST -H "Content-Type: application/json" -d "{\"directory\":\"$REMOTE\", \"changes\":\"$CHANGES\"}" "$WEBHOOK_URL"
            # Send alert to REST API
            curl -X POST -H "Content-Type: application/json" -d "{\"directory\":\"$REMOTE\", \"changes\":\"$CHANGES\"}" "$API_ENDPOINT"
            # Send logs to Elasticsearch
            curl -X POST "$ELASTICSEARCH_SERVER/_doc" -H "Content-Type: application/json" -d "{\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\", \"directory\":\"$REMOTE\", \"changes\":\"$CHANGES\"}"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - No changes detected in $REMOTE." | tee -a "$LOG_FILE"
        fi

        # Clean up temporary file
        rm "$TEMP_FILE"
    done
}

# Function to run the IDS in daemon mode
run_daemon() {
    while true; do
        check_for_changes
        sleep "$CHECK_INTERVAL"
    done
}

# Function to monitor directories in real-time
monitor_realtime() {
    inotifywait -m -r -e create,delete,modify,move $MONITORED_DIRS | while read path action file; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Detected $action on $path$file" | tee -a "$LOG_FILE"
        check_for_changes
    done
}

# Function to initialize the database
initialize_database() {
    sqlite3 "$DATABASE" "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, timestamp TEXT, directory TEXT, changes TEXT);"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Database initialized." | tee -a "$LOG_FILE"
}

# Function to generate a report
generate_report() {
    sqlite3 "$DATABASE" "SELECT * FROM logs;" > ids_report.txt
    gpg --yes --default-key "$GPG_KEY" --sign ids_report.txt
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Report generated and signed: ids_report.txt" | tee -a "$LOG_FILE"
}

# Function to handle errors
handle_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Error: $1" | tee -a "$LOG_FILE"
    echo -e "Subject: IDS Error\n\nError: $1" | sendmail "$EMAIL"
}

# Function to reload configuration
reload_configuration() {
    decrypt_config
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Configuration reloaded." | tee -a "$LOG_FILE"
}

# Function to backup logs and baselines
backup_data() {
    tar -czf ids_backup_$(date '+%Y-%m-%d_%H-%M-%S').tar.gz "$BASELINE_DIR" "$LOG_FILE" "$DATABASE"
    gpg --yes --default-key "$GPG_KEY" --encrypt ids_backup_$(date '+%Y-%m-%d_%H-%M-%S').tar.gz
    rm ids_backup_$(date '+%Y-%m-%d_%H-%M-%S').tar.gz
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup created and encrypted." | tee -a "$LOG_FILE"
}

# Function to restore from backup
restore_data() {
    gpg --yes --default-key "$GPG_KEY" --decrypt "$1" | tar -xzf -
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup restored from $1." | tee -a "$LOG_FILE"
}

# Function to check LDAP permissions
check_permissions() {
    USER=$(whoami)
    GROUPS=$(ldapsearch -x -LLL -H "$LDAP_SERVER" -b "$LDAP_BASE_DN" "memberUid=$USER" cn | grep -E '^cn:' | awk '{print $2}')
    
    if echo "$GROUPS" | grep -q "$ADMIN_GROUP"; then
        echo "admin"
    elif echo "$GROUPS" | grep -q "$VIEWER_GROUP"; then
        echo "viewer"
    else
        echo "none"
    fi
}

# Main script logic
PERMISSIONS=$(check_permissions)
if [ "$PERMISSIONS" = "none" ]; then
    echo "You do not have permission to run this script."
    exit 1
fi

case "$1" in
    --create-baseline)
        create_baseline
        ;;
    --check)
        check_for_changes
        ;;
    --daemon)
        run_daemon
        ;;
    --realtime)
        monitor_realtime
        ;;
    --initialize-db)
        initialize_database
        ;;
    --generate-report)
        generate_report
        ;;
    --reload-config)
        reload_configuration
        ;;
    --backup)
        backup_data
        ;;
    --restore)
        restore_data "$2"
        ;;
    *)
        echo "Usage: $0 --create-baseline | --check | --daemon | --realtime | --initialize-db | --generate-report | --reload-config | --backup | --restore <backup_file>"
        ;;
esac
