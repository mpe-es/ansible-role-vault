#!/usr/bin/env bash
###############################################################################
# Filename: vault-audit-backup.sh
# Author: Alex Ackerman
# Co-Author: Claude Code (Anthropic) - Audit log backup automation
# Date: 2025-12-19
# Summary: Automated backup of Vault audit logs with 7-day retention
# Location (deployed): /usr/local/bin/vault-audit-backup.sh
# Compliant With: RHEL 9 STIG V-205167, Application Security STIG V5R3
# Classification: UNCLASSIFIED
###############################################################################

set -euo pipefail

# Configuration
BACKUP_DIR="/opt/vault-backup"
VAULT_LOG_DIR="/var/log/vault"
AUDIT_LOG="/var/log/audit/audit.log"
RETENTION_DAYS=7
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME=$(hostname -s)

# Logging
LOG_TAG="vault-audit-backup"

# Functions
log_info() {
    logger -t "$LOG_TAG" -p daemon.info "$1"
    echo "[INFO] $1"
}

log_error() {
    logger -t "$LOG_TAG" -p daemon.err "$1"
    echo "[ERROR] $1" >&2
}

log_crit() {
    logger -t "$LOG_TAG" -p daemon.crit "$1"
    echo "[CRITICAL] $1" >&2
}

# Ensure backup directory exists
if [[ ! -d "$BACKUP_DIR" ]]; then
    mkdir -p "$BACKUP_DIR"
    chown vault:vault "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    log_info "Created backup directory: $BACKUP_DIR"
fi

# Create timestamped backup subdirectory
BACKUP_SUBDIR="$BACKUP_DIR/backup-$TIMESTAMP"
mkdir -p "$BACKUP_SUBDIR"
chown vault:vault "$BACKUP_SUBDIR"
chmod 750 "$BACKUP_SUBDIR"

log_info "Starting Vault audit log backup to $BACKUP_SUBDIR"

# Backup Vault file audit device log
if [[ -f "$VAULT_LOG_DIR/vault_audit.log" ]]; then
    cp "$VAULT_LOG_DIR/vault_audit.log" "$BACKUP_SUBDIR/vault_audit.log"
    gzip "$BACKUP_SUBDIR/vault_audit.log"
    log_info "Backed up Vault file audit log (compressed)"
else
    log_error "Vault file audit log not found: $VAULT_LOG_DIR/vault_audit.log"
fi

# Backup Vault syslog audit device log (if exists)
if [[ -f "$VAULT_LOG_DIR/vault_audit_syslog.log" ]]; then
    cp "$VAULT_LOG_DIR/vault_audit_syslog.log" "$BACKUP_SUBDIR/vault_audit_syslog.log"
    gzip "$BACKUP_SUBDIR/vault_audit_syslog.log"
    log_info "Backed up Vault syslog audit log (compressed)"
else
    log_info "Vault syslog audit log not found (may not be configured)"
fi

# Backup auditd logs (filtered for Vault-related events)
# Audit rules track: vault binary execution, config changes, data directory access
if [[ -f "$AUDIT_LOG" ]]; then
    # Extract Vault-related audit events (last 24 hours)
    ausearch -ts yesterday -te now -x /usr/bin/vault > "$BACKUP_SUBDIR/audit-vault.log" 2>/dev/null || true
    ausearch -ts yesterday -te now -f /opt/vault/data/ >> "$BACKUP_SUBDIR/audit-vault.log" 2>/dev/null || true
    ausearch -ts yesterday -te now -f /etc/vault.d/ >> "$BACKUP_SUBDIR/audit-vault.log" 2>/dev/null || true

    if [[ -s "$BACKUP_SUBDIR/audit-vault.log" ]]; then
        gzip "$BACKUP_SUBDIR/audit-vault.log"
        log_info "Backed up Vault-related auditd events (compressed)"
    else
        rm -f "$BACKUP_SUBDIR/audit-vault.log"
        log_info "No Vault-related auditd events in last 24 hours"
    fi
else
    log_error "Audit log not found: $AUDIT_LOG"
fi

# Backup Vault service logs from journald
# Extract last 24 hours of vault.service logs
journalctl -u vault.service --since "24 hours ago" > "$BACKUP_SUBDIR/vault-journal.log" 2>/dev/null || true
if [[ -s "$BACKUP_SUBDIR/vault-journal.log" ]]; then
    gzip "$BACKUP_SUBDIR/vault-journal.log"
    log_info "Backed up vault.service systemd journal (compressed)"
else
    rm -f "$BACKUP_SUBDIR/vault-journal.log"
    log_info "No vault.service journal entries in last 24 hours"
fi

# Backup Vault unseal service logs from journald (if auto-unseal is enabled)
journalctl -u vault-unseal.service --since "24 hours ago" > "$BACKUP_SUBDIR/vault-unseal-journal.log" 2>/dev/null || true
if [[ -s "$BACKUP_SUBDIR/vault-unseal-journal.log" ]]; then
    gzip "$BACKUP_SUBDIR/vault-unseal-journal.log"
    log_info "Backed up vault-unseal.service systemd journal (compressed)"
else
    rm -f "$BACKUP_SUBDIR/vault-unseal-journal.log"
    log_info "No vault-unseal.service journal entries in last 24 hours"
fi

# Set ownership and permissions on backup files
chown -R vault:vault "$BACKUP_SUBDIR"
chmod -R 640 "$BACKUP_SUBDIR"/*

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_SUBDIR" | awk '{print $1}')
log_info "Backup complete: $BACKUP_SIZE in $BACKUP_SUBDIR"

# Retention: Delete backups older than RETENTION_DAYS
log_info "Applying $RETENTION_DAYS-day retention policy"
find "$BACKUP_DIR" -maxdepth 1 -type d -name "backup-*" -mtime +$RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null || true

# Count remaining backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "backup-*" | wc -l)
log_info "Retention applied: $BACKUP_COUNT backups remaining"

# Verify backup integrity (check if files are readable)
INTEGRITY_CHECK=0
for backup_file in "$BACKUP_SUBDIR"/*.gz; do
    if [[ -f "$backup_file" ]]; then
        if gzip -t "$backup_file" 2>/dev/null; then
            log_info "Integrity verified: $(basename "$backup_file")"
        else
            log_error "Integrity check FAILED: $(basename "$backup_file")"
            INTEGRITY_CHECK=1
        fi
    fi
done

if [[ $INTEGRITY_CHECK -eq 0 ]]; then
    log_info "Vault audit backup completed successfully"
    exit 0
else
    log_crit "Vault audit backup completed with integrity errors"
    exit 1
fi
