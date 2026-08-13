#!/usr/bin/env bash
###############################################################################
# Filename: vault-audit-backup-test.sh
# Role: ansible-role-vault
# Summary: Behavioral test harness for files/vault-audit-backup.sh.
#   Non-root friendly: external commands (chown, gzip, ausearch, journalctl,
#   logger, hostname) are mocked via a PATH shim directory; all paths are
#   overridden into a mktemp sandbox via environment variables. TAP-ish
#   ok / not ok output.
# Last Updated: 13 Aug 2026
# Classification: UNCLASSIFIED
###############################################################################

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="$TEST_DIR/../files/vault-audit-backup.sh"

PASS=0
FAIL=0
COUNT=0

ok() {
    COUNT=$((COUNT + 1))
    PASS=$((PASS + 1))
    echo "ok $COUNT - $1"
}

not_ok() {
    COUNT=$((COUNT + 1))
    FAIL=$((FAIL + 1))
    echo "not ok $COUNT - $1"
}

assert() {
    # assert <description> <command...>
    local desc="$1"
    shift
    if "$@"; then
        ok "$desc"
    else
        not_ok "$desc"
    fi
}

# Portable octal mode (GNU stat vs BSD stat)
get_mode() {
    stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}

###############################################################################
# Sandbox / shim setup
###############################################################################
SANDBOX_ROOT="$(mktemp -d)"
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

SHIM_DIR="$SANDBOX_ROOT/shims"
mkdir -p "$SHIM_DIR"

# logger: swallow syslog writes
printf '#!/usr/bin/env bash\nexit 0\n' > "$SHIM_DIR/logger"

# hostname: deterministic
printf '#!/usr/bin/env bash\necho testhost\n' > "$SHIM_DIR/hostname"

# chown: record argv, perform nothing (non-root cannot chown to root/vault)
cat > "$SHIM_DIR/chown" << 'EOF'
#!/usr/bin/env bash
echo "$*" >> "${CHOWN_LOG:?CHOWN_LOG not set}"
exit 0
EOF

# ausearch: emit a synthetic root-only audit record unless told to be empty
cat > "$SHIM_DIR/ausearch" << 'EOF'
#!/usr/bin/env bash
if [[ "${MOCK_AUSEARCH_EMPTY:-0}" == "1" ]]; then
    exit 0
fi
echo "type=SYSCALL msg=audit(0.0:1): execve /usr/bin/vault (mock record)"
exit 0
EOF

# journalctl: emit a synthetic journal line unless told to be empty
cat > "$SHIM_DIR/journalctl" << 'EOF'
#!/usr/bin/env bash
if [[ "${MOCK_JOURNAL_EMPTY:-0}" == "1" ]]; then
    exit 0
fi
echo "mock journal line for $*"
exit 0
EOF

# gzip: compress -> replace file with stub .gz; -t -> honor MOCK_GZIP_FAIL
cat > "$SHIM_DIR/gzip" << 'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-t" ]]; then
    if [[ "${MOCK_GZIP_FAIL:-0}" == "1" ]]; then
        exit 1
    fi
    exit 0
fi
for f in "$@"; do
    printf 'MOCKGZ' > "$f.gz"
    rm -f "$f"
done
exit 0
EOF

chmod 0755 "$SHIM_DIR"/*

# Scrubbed environment for every SUT invocation: only PATH plus the variables
# each scenario passes explicitly. Prevents ambient environment pollution.
SUT_PATH="$SHIM_DIR:/usr/bin:/bin:/usr/sbin:/sbin"

run_sut() {
    # run_sut <sandbox> <stdout+stderr log> [VAR=value ...]
    local sandbox="$1"
    local outlog="$2"
    shift 2
    env -i PATH="$SUT_PATH" HOME="$sandbox" \
        BACKUP_DIR="$sandbox/opt/vault-backup" \
        VAULT_LOG_DIR="$sandbox/var/log/vault" \
        AUDIT_LOG="$sandbox/var/log/audit/audit.log" \
        CHOWN_LOG="$sandbox/chown.log" \
        "$@" \
        bash "$SUT" > "$outlog" 2>&1
}

new_sandbox() {
    # Creates a sandbox with populated vault logs and auditd log; echoes path
    local sb
    sb="$(mktemp -d "$SANDBOX_ROOT/sb.XXXXXX")"
    mkdir -p "$sb/var/log/vault" "$sb/var/log/audit"
    echo '{"time":"mock","type":"request"}' > "$sb/var/log/vault/vault_audit.log"
    echo '{"time":"mock","type":"request-syslog"}' > "$sb/var/log/vault/vault_audit_syslog.log"
    echo 'type=SYSCALL mock auditd content' > "$sb/var/log/audit/audit.log"
    : > "$sb/chown.log"
    echo "$sb"
}

echo "# vault-audit-backup.sh behavioral tests"
echo "# SUT: $SUT"

###############################################################################
# Scenario 1: privilege contract - backup tree is root-only, never vault:vault
###############################################################################
echo "# scenario 1: privilege contract (root-only tree, no vault:vault grants)"
SB1="$(new_sandbox)"
run_sut "$SB1" "$SB1/run.log"
RC=$?

assert "s1: script exits 0 on happy path" test "$RC" -eq 0

# Guard against a vacuous pass: the run must actually reach the ownership
# phase (non-empty chown log) AND never grant vault:vault.
if [[ -s "$SB1/chown.log" ]] && ! grep -q 'vault:vault' "$SB1/chown.log"; then
    ok "s1: script never invokes chown with vault:vault"
else
    not_ok "s1: script never invokes chown with vault:vault"
fi

assert "s1: script enforces root:root ownership on the backup tree" \
    grep -q 'root:root' "$SB1/chown.log"

B1="$SB1/opt/vault-backup"
assert "s1: backup dir mode is 0700" test "$(get_mode "$B1")" = "700"

SUBDIR_COUNT=0
for d in "$B1"/backup-*; do
    [[ -d "$d" ]] || continue
    SUBDIR_COUNT=$((SUBDIR_COUNT + 1))
    assert "s1: backup subdir $(basename "$d") mode is 0700" \
        test "$(get_mode "$d")" = "700"
    for f in "$d"/*; do
        [[ -f "$f" ]] || continue
        assert "s1: backup file $(basename "$f") mode is 0600" \
            test "$(get_mode "$f")" = "600"
    done
done
assert "s1: exactly one backup subdir created" test "$SUBDIR_COUNT" -eq 1

###############################################################################
# Scenario 2: pre-existing legacy dir (0750) is re-hardened to 0700
###############################################################################
echo "# scenario 2: legacy backup dir re-hardened on every run"
SB2="$(new_sandbox)"
mkdir -p "$SB2/opt/vault-backup"
chmod 0750 "$SB2/opt/vault-backup"
run_sut "$SB2" "$SB2/run.log"
RC=$?

assert "s2: script exits 0 with pre-existing backup dir" test "$RC" -eq 0
assert "s2: pre-existing backup dir tightened to 0700" \
    test "$(get_mode "$SB2/opt/vault-backup")" = "700"

###############################################################################
# Scenario 3: retention honors RETENTION_DAYS from the environment
###############################################################################
echo "# scenario 3: retention driven by RETENTION_DAYS env"

# Old fixture dir: fixed timestamp well in the past (>200 days before Aug 2026)
make_retention_fixture() {
    local sb="$1"
    mkdir -p "$sb/opt/vault-backup/backup-20260101-000000"
    touch -t 202601010000 "$sb/opt/vault-backup/backup-20260101-000000"
}

# 3a: RETENTION_DAYS large -> old dir must survive
SB3A="$(new_sandbox)"
make_retention_fixture "$SB3A"
run_sut "$SB3A" "$SB3A/run.log" RETENTION_DAYS=3650
RC=$?
assert "s3a: script exits 0 with RETENTION_DAYS=3650" test "$RC" -eq 0
assert "s3a: old backup dir survives when RETENTION_DAYS=3650" \
    test -d "$SB3A/opt/vault-backup/backup-20260101-000000"

# 3b: RETENTION_DAYS small -> old dir must be purged
SB3B="$(new_sandbox)"
make_retention_fixture "$SB3B"
run_sut "$SB3B" "$SB3B/run.log" RETENTION_DAYS=1
RC=$?
assert "s3b: script exits 0 with RETENTION_DAYS=1" test "$RC" -eq 0
if [[ -d "$SB3B/opt/vault-backup/backup-20260101-000000" ]]; then
    not_ok "s3b: old backup dir purged when RETENTION_DAYS=1"
else
    ok "s3b: old backup dir purged when RETENTION_DAYS=1"
fi

# 3c: no RETENTION_DAYS in env -> default 7 purges the old dir
SB3C="$(new_sandbox)"
make_retention_fixture "$SB3C"
run_sut "$SB3C" "$SB3C/run.log"
RC=$?
assert "s3c: script exits 0 with default retention" test "$RC" -eq 0
if [[ -d "$SB3C/opt/vault-backup/backup-20260101-000000" ]]; then
    not_ok "s3c: old backup dir purged under default 7-day retention"
else
    ok "s3c: old backup dir purged under default 7-day retention"
fi

# 3d: non-numeric RETENTION_DAYS -> rejected, falls back to default 7
SB3D="$(new_sandbox)"
make_retention_fixture "$SB3D"
run_sut "$SB3D" "$SB3D/run.log" RETENTION_DAYS='7; rm -rf /'
RC=$?
assert "s3d: script exits 0 with invalid RETENTION_DAYS" test "$RC" -eq 0
assert "s3d: invalid RETENTION_DAYS is logged as an error" \
    grep -q 'Invalid RETENTION_DAYS' "$SB3D/run.log"
if [[ -d "$SB3D/opt/vault-backup/backup-20260101-000000" ]]; then
    not_ok "s3d: default 7-day retention applied after invalid value"
else
    ok "s3d: default 7-day retention applied after invalid value"
fi

###############################################################################
# Scenario 4: missing auditd log -> logged error, still exit 0
###############################################################################
echo "# scenario 4: missing auditd log is non-fatal"
SB4="$(new_sandbox)"
rm -f "$SB4/var/log/audit/audit.log"
run_sut "$SB4" "$SB4/run.log"
RC=$?
assert "s4: script exits 0 when auditd log is missing" test "$RC" -eq 0
assert "s4: missing auditd log produces logged error" \
    grep -q 'Audit log not found' "$SB4/run.log"

###############################################################################
# Scenario 5: all sources missing/empty -> still exit 0 (no glob crash)
###############################################################################
echo "# scenario 5: empty backup run is non-fatal"
SB5="$(new_sandbox)"
rm -f "$SB5/var/log/vault/vault_audit.log" \
      "$SB5/var/log/vault/vault_audit_syslog.log" \
      "$SB5/var/log/audit/audit.log"
run_sut "$SB5" "$SB5/run.log" MOCK_AUSEARCH_EMPTY=1 MOCK_JOURNAL_EMPTY=1
RC=$?
assert "s5: script exits 0 when every source is missing or empty" test "$RC" -eq 0
assert "s5: missing vault audit log produces logged error" \
    grep -q 'Vault file audit log not found' "$SB5/run.log"

###############################################################################
# Scenario 6: gzip integrity failure -> exit 1
###############################################################################
echo "# scenario 6: integrity failure path"
SB6="$(new_sandbox)"
run_sut "$SB6" "$SB6/run.log" MOCK_GZIP_FAIL=1
RC=$?
assert "s6: script exits 1 on gzip integrity failure" test "$RC" -eq 1
assert "s6: integrity failure is logged as critical" \
    grep -q 'integrity errors' "$SB6/run.log"

###############################################################################
# Summary
###############################################################################
echo "1..$COUNT"
echo "# pass $PASS / $COUNT (fail $FAIL)"
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
