#!/usr/bin/env bash
###############################################################################
# Filename: vault-audit-backup.sh
# Author: Alex Ackerman
# Co-Author: Claude Code (Anthropic) - Audit log backup automation
# Date: 2025-12-19
# Last Updated: 13 Aug 2026
# Summary: Automated backup of Vault audit logs with configurable retention.
#   Backup tree is root-only (dirs 0700, files 0600, root:root): it contains
#   auditd extracts that the OS protects at root-only, so the unprivileged
#   vault service account is deliberately denied read access.
# Location (deployed): /usr/local/bin/vault-audit-backup.sh
# Compliant With: RHEL 9 STIG V-205167, Application Security STIG V5R3
# Classification: UNCLASSIFIED
###############################################################################

set -euo pipefail

# Restrictive creation mask: new dirs 0700, new files 0600 (root-only tree)
umask 077

# Configuration (environment-overridable; systemd injects RETENTION_DAYS)
BACKUP_DIR="${BACKUP_DIR:-/opt/vault-backup}"
VAULT_LOG_DIR="${VAULT_LOG_DIR:-/var/log/vault}"
AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

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

# Validate retention: non-negative integer only, else fall back to 7 days
if [[ ! "$RETENTION_DAYS" =~ ^[0-9]+$ ]]; then
    log_error "Invalid RETENTION_DAYS '$RETENTION_DAYS' - using default of 7"
    RETENTION_DAYS=7
fi

# Ensure backup directory exists and is root-only, even if a prior release
# of this script left it owned by the vault service account (0750)
if [[ ! -d "$BACKUP_DIR" ]]; then
    # Missing parents (if any) are created under the default mask so the
    # umask 077 above does not lock down directories above the backup root
    (umask 022 && mkdir -p "$(dirname "$BACKUP_DIR")")
    mkdir "$BACKUP_DIR"
    log_info "Created backup directory: $BACKUP_DIR"
fi
chown root:root "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

# Create timestamped backup subdirectory (root-only)
BACKUP_SUBDIR="$BACKUP_DIR/backup-$TIMESTAMP"
mkdir -p "$BACKUP_SUBDIR"
chmod 0700 "$BACKUP_SUBDIR"

log_info "Starting Vault audit log backup to $BACKUP_SUBDIR"

# Backup Vault file audit device log
if [[ -f "$VAULT_LOG_DIR/vault_audit.log" ]]; then
    cp "$VAULT_LOG_DIR/vault_audit.log" "$BACKUP_SUBDIR/vault_audit.log"
    gzip -nf "$BACKUP_SUBDIR/vault_audit.log"
    log_info "Backed up Vault file audit log (compressed)"
else
    log_error "Vault file audit log not found: $VAULT_LOG_DIR/vault_audit.log"
fi

# Backup Vault syslog audit device log (if exists)
if [[ -f "$VAULT_LOG_DIR/vault_audit_syslog.log" ]]; then
    cp "$VAULT_LOG_DIR/vault_audit_syslog.log" "$BACKUP_SUBDIR/vault_audit_syslog.log"
    gzip -nf "$BACKUP_SUBDIR/vault_audit_syslog.log"
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
        gzip -nf "$BACKUP_SUBDIR/audit-vault.log"
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
    gzip -nf "$BACKUP_SUBDIR/vault-journal.log"
    log_info "Backed up vault.service systemd journal (compressed)"
else
    rm -f "$BACKUP_SUBDIR/vault-journal.log"
    log_info "No vault.service journal entries in last 24 hours"
fi

# Backup Vault unseal service logs from journald (if auto-unseal is enabled)
journalctl -u vault-unseal.service --since "24 hours ago" > "$BACKUP_SUBDIR/vault-unseal-journal.log" 2>/dev/null || true
if [[ -s "$BACKUP_SUBDIR/vault-unseal-journal.log" ]]; then
    gzip -nf "$BACKUP_SUBDIR/vault-unseal-journal.log"
    log_info "Backed up vault-unseal.service systemd journal (compressed)"
else
    rm -f "$BACKUP_SUBDIR/vault-unseal-journal.log"
    log_info "No vault-unseal.service journal entries in last 24 hours"
fi

# Enforce root-only ownership and permissions across the entire backup tree.
# The tree contains root-only auditd extracts: the vault service account must
# never gain read access (Secure by Default). Recursive sweep also remediates
# legacy trees created vault:vault by earlier releases of this script.
# A partial sweep failure (e.g. one bad inode in an old tree) is logged but
# must not abort the job before retention and integrity checks run.
chown -R root:root "$BACKUP_DIR" || log_error "Ownership sweep incomplete on $BACKUP_DIR"
find "$BACKUP_DIR" -type d -exec chmod 0700 {} + || log_error "Directory mode sweep incomplete on $BACKUP_DIR"
find "$BACKUP_DIR" -type f -exec chmod 0600 {} + || log_error "File mode sweep incomplete on $BACKUP_DIR"

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_SUBDIR" | awk '{print $1}')
log_info "Backup complete: $BACKUP_SIZE in $BACKUP_SUBDIR"

# Retention: Delete backups older than RETENTION_DAYS
log_info "Applying $RETENTION_DAYS-day retention policy"
find "$BACKUP_DIR" -maxdepth 1 -type d -name "backup-*" -mtime "+$RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true

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
