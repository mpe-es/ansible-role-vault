#!/usr/bin/env bash
###############################################################################
# Filename: vault-audit-backup-test.sh
# Role: ansible-role-vault
# Summary: Behavioral test harness for files/vault-audit-backup.sh.
#   Non-root friendly: external commands (chown, gzip, ausearch, journalctl,
#   logger) are mocked via a PATH shim directory; all paths are overridden
#   into a mktemp sandbox via environment variables; every SUT invocation
#   runs under env -i so no ambient environment leaks in. TAP-ish
#   ok / not ok output with a static plan.
# Last Updated: 13 Aug 2026
# Classification: UNCLASSIFIED
###############################################################################

set -uo pipefail

# Static plan: the runner fails if any assertion vanishes or is added
# without updating this count.
PLAN=42

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="$TEST_DIR/../files/vault-audit-backup.sh"

PASS=0
FAIL=0
COUNT=0

echo "1..$PLAN"

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

assert_not() {
    # assert_not <description> <command...>
    local desc="$1"
    shift
    if "$@"; then
        not_ok "$desc"
    else
        ok "$desc"
    fi
}

# Portable octal mode (GNU stat vs BSD stat)
get_mode() {
    stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}

# Portable "set mtime to N days ago" (GNU date vs BSD date)
touch_days_ago() {
    local days="$1" path="$2" stamp
    stamp="$(date -v "-${days}d" +%Y%m%d%H%M 2>/dev/null \
        || date -d "${days} days ago" +%Y%m%d%H%M)"
    touch -t "$stamp" "$path"
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

# gzip: models the real tool's flag behavior instead of hiding it.
#   -t          integrity test (honors MOCK_GZIP_FAIL)
#   -f          overwrite an existing .gz (without it, collision -> exit 1,
#               matching real gzip's refuse-to-overwrite behavior)
#   -n          accepted no-op
# Any unmodeled flag fails loudly rather than producing junk files.
cat > "$SHIM_DIR/gzip" << 'EOF'
#!/usr/bin/env bash
test_mode=0
force=0
files=()
for a in "$@"; do
    case "$a" in
        -*)
            flags="${a#-}"
            while [[ -n "$flags" ]]; do
                c="${flags:0:1}"
                flags="${flags:1}"
                case "$c" in
                    t) test_mode=1 ;;
                    f) force=1 ;;
                    n) : ;;
                    *) echo "gzip shim: unmodeled flag -$c" >&2; exit 64 ;;
                esac
            done
            ;;
        *) files+=("$a") ;;
    esac
done
if [[ "$test_mode" == "1" ]]; then
    if [[ "${MOCK_GZIP_FAIL:-0}" == "1" ]]; then
        exit 1
    fi
    exit 0
fi
for f in "${files[@]}"; do
    if [[ -e "$f.gz" && "$force" != "1" ]]; then
        echo "gzip shim: $f.gz already exists" >&2
        exit 1
    fi
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
assert_not "s1: happy path logs no errors" grep -q '\[ERROR\]' "$SB1/run.log"

# Guard against a vacuous pass: the run must actually reach the ownership
# phase (non-empty chown log) AND never grant vault:vault.
if [[ -s "$SB1/chown.log" ]] && ! grep -q 'vault:vault' "$SB1/chown.log"; then
    ok "s1: script never invokes chown with vault:vault"
else
    not_ok "s1: script never invokes chown with vault:vault"
fi

# The recursive ownership sweep must run, not just the top-level chown
assert "s1: recursive root:root ownership sweep invoked (-R root:root)" \
    grep -q -- '-R root:root' "$SB1/chown.log"

B1="$SB1/opt/vault-backup"
assert "s1: backup dir mode is 0700" test "$(get_mode "$B1")" = "700"

SUBDIR_COUNT=0
SUBDIR=""
for d in "$B1"/backup-*; do
    [[ -d "$d" ]] || continue
    SUBDIR_COUNT=$((SUBDIR_COUNT + 1))
    SUBDIR="$d"
done
assert "s1: exactly one backup subdir created" test "$SUBDIR_COUNT" -eq 1
assert "s1: backup subdir mode is 0700" test "$(get_mode "$SUBDIR")" = "700"

# Exact expected artifact set: a silent capture regression must go red
EXPECTED_ARTIFACTS=(
    vault_audit.log.gz
    vault_audit_syslog.log.gz
    audit-vault.log.gz
    vault-journal.log.gz
    vault-unseal-journal.log.gz
)
for artifact in "${EXPECTED_ARTIFACTS[@]}"; do
    assert "s1: artifact $artifact captured" test -f "$SUBDIR/$artifact"
    assert "s1: artifact $artifact mode is 0600" \
        test "$(get_mode "$SUBDIR/$artifact")" = "600"
done
FILE_COUNT=$(find "$SUBDIR" -type f | wc -l | tr -d ' ')
assert "s1: no unexpected artifacts (exactly 5 files)" test "$FILE_COUNT" -eq 5

###############################################################################
# Scenario 2: legacy vault:vault-era tree (0750 dirs, 0640 files) re-hardened
###############################################################################
echo "# scenario 2: legacy backup tree re-hardened on every run"
SB2="$(new_sandbox)"
LEGACY_DIR="$SB2/opt/vault-backup/backup-20260801-000000"
mkdir -p "$LEGACY_DIR"
echo 'legacy audit extract' > "$LEGACY_DIR/audit-vault.log.gz"
chmod 0750 "$SB2/opt/vault-backup" "$LEGACY_DIR"
chmod 0640 "$LEGACY_DIR/audit-vault.log.gz"
run_sut "$SB2" "$SB2/run.log"
RC=$?

assert "s2: script exits 0 with pre-existing backup tree" test "$RC" -eq 0
assert "s2: pre-existing backup dir tightened to 0700" \
    test "$(get_mode "$SB2/opt/vault-backup")" = "700"
assert "s2: legacy backup subdir tightened to 0700" \
    test "$(get_mode "$LEGACY_DIR")" = "700"
assert "s2: legacy backup file tightened to 0600" \
    test "$(get_mode "$LEGACY_DIR/audit-vault.log.gz")" = "600"
assert "s2: recursive root:root ownership sweep invoked (-R root:root)" \
    grep -q -- '-R root:root' "$SB2/chown.log"

###############################################################################
# Scenario 3: retention honors RETENTION_DAYS from the environment
###############################################################################
echo "# scenario 3: retention driven by RETENTION_DAYS env"

# Fixtures: OLD (200 days) and MID (3 days). Discrimination matrix:
#   RETENTION_DAYS=3650 -> both survive
#   RETENTION_DAYS=1    -> both purged
#   default / fallback 7 -> OLD purged, MID survives
OLD_NAME="backup-20260125-000000"
MID_NAME="backup-20260810-000000"

make_retention_fixture() {
    local sb="$1"
    mkdir -p "$sb/opt/vault-backup/$OLD_NAME" "$sb/opt/vault-backup/$MID_NAME"
    touch_days_ago 200 "$sb/opt/vault-backup/$OLD_NAME"
    touch_days_ago 3 "$sb/opt/vault-backup/$MID_NAME"
}

# 3a: RETENTION_DAYS large -> everything survives
SB3A="$(new_sandbox)"
make_retention_fixture "$SB3A"
run_sut "$SB3A" "$SB3A/run.log" RETENTION_DAYS=3650
RC=$?
assert "s3a: script exits 0 with RETENTION_DAYS=3650" test "$RC" -eq 0
assert "s3a: 200-day-old backup survives when RETENTION_DAYS=3650" \
    test -d "$SB3A/opt/vault-backup/$OLD_NAME"
assert "s3a: 3-day-old backup survives when RETENTION_DAYS=3650" \
    test -d "$SB3A/opt/vault-backup/$MID_NAME"

# 3b: RETENTION_DAYS=1 -> both fixtures purged (default 7 would keep MID)
SB3B="$(new_sandbox)"
make_retention_fixture "$SB3B"
run_sut "$SB3B" "$SB3B/run.log" RETENTION_DAYS=1
RC=$?
assert "s3b: script exits 0 with RETENTION_DAYS=1" test "$RC" -eq 0
assert_not "s3b: 200-day-old backup purged when RETENTION_DAYS=1" \
    test -d "$SB3B/opt/vault-backup/$OLD_NAME"
assert_not "s3b: 3-day-old backup purged when RETENTION_DAYS=1" \
    test -d "$SB3B/opt/vault-backup/$MID_NAME"

# 3c: no RETENTION_DAYS in env -> default 7 purges OLD but keeps MID
SB3C="$(new_sandbox)"
make_retention_fixture "$SB3C"
run_sut "$SB3C" "$SB3C/run.log"
RC=$?
assert "s3c: script exits 0 with default retention" test "$RC" -eq 0
assert_not "s3c: 200-day-old backup purged under default 7-day retention" \
    test -d "$SB3C/opt/vault-backup/$OLD_NAME"
assert "s3c: 3-day-old backup survives under default 7-day retention" \
    test -d "$SB3C/opt/vault-backup/$MID_NAME"

# 3d: non-numeric RETENTION_DAYS -> rejected, falls back to default 7
SB3D="$(new_sandbox)"
make_retention_fixture "$SB3D"
run_sut "$SB3D" "$SB3D/run.log" RETENTION_DAYS='7; rm -rf /'
RC=$?
assert "s3d: script exits 0 with invalid RETENTION_DAYS" test "$RC" -eq 0
assert "s3d: invalid RETENTION_DAYS is logged as an error" \
    grep -q 'Invalid RETENTION_DAYS' "$SB3D/run.log"
assert_not "s3d: 200-day-old backup purged under fallback 7-day retention" \
    test -d "$SB3D/opt/vault-backup/$OLD_NAME"
assert "s3d: 3-day-old backup survives under fallback 7-day retention" \
    test -d "$SB3D/opt/vault-backup/$MID_NAME"

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
echo "# pass $PASS / $COUNT (fail $FAIL, plan $PLAN)"
if [[ $FAIL -gt 0 || $COUNT -ne $PLAN ]]; then
    exit 1
fi
exit 0
