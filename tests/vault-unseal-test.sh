#!/usr/bin/env bash
###############################################################################
# Filename: tests/vault-unseal-test.sh
# Role: ansible-role-vault
# Summary: Behavioral test harness for files/vault-unseal.sh using a mock
#   vault binary. No network, no root, no real Vault required.
#   Contract under test (issue #30):
#     - refuses a tokens file (or parent dir) with untrusted ownership or
#       group/other write access
#     - waits (bounded, with real back-off) for the Vault API to answer
#     - exits 0 without applying keys when Vault is already unsealed
#     - refuses to throw keys at an uninitialized Vault
#     - applies keys until unsealed, then stops
#     - exits non-zero when Vault remains sealed (honest exit code)
#     - exits non-zero with a diagnostic when the tokens file is missing,
#       unreadable, or fails to source
# Usage: bash tests/vault-unseal-test.sh
# Classification: UNCLASSIFIED
###############################################################################
set -u

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_UNDER_TEST="$HARNESS_DIR/../files/vault-unseal.sh"
FAILURES=0
TESTS=0

pass() { TESTS=$((TESTS + 1)); echo "ok $TESTS - $1"; }
fail() { TESTS=$((TESTS + 1)); FAILURES=$((FAILURES + 1)); echo "not ok $TESTS - $1"; }

assert_eq() { # actual expected label
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected '$2', got '$1')"; fi
}

assert_output_contains() { # needle label
    if grep -q "$1" "$MOCK_DIR/output.log"; then
        pass "$2"
    else
        fail "$2 (output.log does not contain '$1')"
    fi
}

###############################################################################
# Mock environment. Each scenario gets a fresh MOCK_DIR holding mock state:
#   listening_after  - mock vault invocations that fail (rc 1) before the
#                      "listener" comes up
#   seal_state       - sealed | unsealed | uninitialized
#   keys_needed      - unseal calls required before the mock flips to unsealed
#   call_count       - total mock invocations (written by mock)
#   keys.log         - one line per key passed to `operator unseal`
###############################################################################
setup_scenario() { # listening_after seal_state keys_needed
    MOCK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vault-unseal-test.XXXXXX")"
    export MOCK_DIR
    mkdir -p "$MOCK_DIR/bin"
    printf '%s\n' "$1" > "$MOCK_DIR/listening_after"
    printf '%s\n' "$2" > "$MOCK_DIR/seal_state"
    printf '%s\n' "$3" > "$MOCK_DIR/keys_needed"
    printf '0\n' > "$MOCK_DIR/call_count"
    : > "$MOCK_DIR/keys.log"

    cat > "$MOCK_DIR/bin/vault" <<'MOCK'
#!/usr/bin/env bash
set -u
n=$(cat "$MOCK_DIR/call_count")
n=$((n + 1))
printf '%s\n' "$n" > "$MOCK_DIR/call_count"
if [ "$n" -le "$(cat "$MOCK_DIR/listening_after")" ]; then
    echo "Error checking seal status: connection refused" >&2
    exit 1
fi
state=$(cat "$MOCK_DIR/seal_state")
case "${1:-}" in
    status)
        if [ "$state" = "unsealed" ]; then
            echo '{"initialized": true, "sealed": false}'
            exit 0
        elif [ "$state" = "uninitialized" ]; then
            echo '{"initialized": false, "sealed": true}'
            exit 2
        fi
        echo '{"initialized": true, "sealed": true}'
        exit 2
        ;;
    operator)
        # argv: operator unseal <key>
        printf '%s\n' "${3:-MISSING_KEY_ARG}" >> "$MOCK_DIR/keys.log"
        applied=$(wc -l < "$MOCK_DIR/keys.log" | tr -d ' ')
        if [ "$state" = "sealed" ] && [ "$applied" -ge "$(cat "$MOCK_DIR/keys_needed")" ]; then
            printf 'unsealed\n' > "$MOCK_DIR/seal_state"
        fi
        if [ "$(cat "$MOCK_DIR/seal_state")" = "unsealed" ]; then
            echo '{"sealed": false}'
        else
            echo '{"sealed": true}'
        fi
        exit 0
        ;;
esac
exit 0
MOCK
    chmod 0755 "$MOCK_DIR/bin/vault"

    # CA fixture (script requires a readable CA file)
    printf 'mock ca\n' > "$MOCK_DIR/ca.crt"

    # tokens.env fixture matching templates/tokens.env.j2 shape.
    # 0600 like production so the permission guard passes by default.
    cat > "$MOCK_DIR/tokens.env" <<'TOKENS'
# mock tokens file
VAULT_UNSEAL_KEY_1=key-one
VAULT_UNSEAL_KEY_2=key-two
VAULT_UNSEAL_KEY_3=key-three
VAULT_UNSEAL_KEY_4=key-four
VAULT_UNSEAL_KEY_5=key-five
VAULT_ROOT_TOKEN=hvs.mockroottoken
TOKENS
    chmod 0600 "$MOCK_DIR/tokens.env"
}

run_script() { # timing overrides via VAULT_UNSEAL_* set by caller
    RC=0
    # Capture caller-intended timing, then scrub ALL ambient VAULT_* so an
    # operator's shell profile (VAULT_ADDR, VAULT_UNSEAL_KEY_9, ...) cannot
    # pollute scenarios. The harness owns the env contract except the two
    # timing vars, which are caller-passed and read before the scrub.
    local timeout_v="${VAULT_UNSEAL_TIMEOUT:-10}"
    local interval_v="${VAULT_UNSEAL_RETRY_INTERVAL:-0}"
    # shellcheck disable=SC2086
    unset ${!VAULT_@} 2>/dev/null || true
    PATH="$MOCK_DIR/bin:$PATH" \
    VAULT_CACERT="$MOCK_DIR/ca.crt" \
    VAULT_TOKENS_FILE="$MOCK_DIR/tokens.env" \
    VAULT_UNSEAL_TIMEOUT="$timeout_v" \
    VAULT_UNSEAL_RETRY_INTERVAL="$interval_v" \
        bash "$SCRIPT_UNDER_TEST" > "$MOCK_DIR/output.log" 2>&1 || RC=$?
}

keys_applied() { wc -l < "$MOCK_DIR/keys.log" | tr -d ' '; }
vault_calls() { tr -d ' \n' < "$MOCK_DIR/call_count"; }

cleanup_scenario() { chmod -R u+rwx "$MOCK_DIR" 2>/dev/null; rm -rf "$MOCK_DIR"; }

###############################################################################
# Scenario 1: Vault already unsealed -> exit 0, no keys applied
###############################################################################
setup_scenario 0 unsealed 999
run_script
assert_eq "$RC" "0" "already-unsealed: exits 0"
assert_eq "$(keys_applied)" "0" "already-unsealed: applies no keys"
cleanup_scenario

###############################################################################
# Scenario 2: sealed, unseals after 3 keys -> exit 0, stops at threshold
###############################################################################
setup_scenario 0 sealed 3
run_script
assert_eq "$RC" "0" "seal-then-unseal: exits 0"
assert_eq "$(keys_applied)" "3" "seal-then-unseal: stops applying keys once unsealed"
if grep -q 'MISSING_KEY_ARG' "$MOCK_DIR/keys.log"; then
    fail "seal-then-unseal: no empty key arguments passed to vault"
else
    pass "seal-then-unseal: no empty key arguments passed to vault"
fi
cleanup_scenario

###############################################################################
# Scenario 3: remains sealed after all keys -> exit non-zero (honest exit)
###############################################################################
setup_scenario 0 sealed 999
run_script
if [ "$RC" -ne 0 ]; then
    pass "remains-sealed: exits non-zero"
else
    fail "remains-sealed: exits non-zero (got 0)"
fi
assert_eq "$(keys_applied)" "5" "remains-sealed: attempted every available key"
cleanup_scenario

###############################################################################
# Scenario 4: listener not up for the first 11 invocations, then
#   sealed->unsealed. A wait-skipping implementation makes no initial probe
#   and burns 5 keys x 2 calls = 10 dead invocations, all blocked (11 > 10),
#   so it cannot pass by luck -> the script must wait, then exit 0.
###############################################################################
setup_scenario 11 sealed 3
run_script
assert_eq "$RC" "0" "waits-for-listener: exits 0 after listener comes up"
assert_eq "$(keys_applied)" "3" "waits-for-listener: keys applied only after listener up"
cleanup_scenario

###############################################################################
# Scenario 5: listener never comes up -> bounded wait, exit non-zero, and
#   the last probe error surfaces in the failure output (journal diagnosis)
###############################################################################
setup_scenario 99999 sealed 3
VAULT_UNSEAL_TIMEOUT=1
run_script
unset VAULT_UNSEAL_TIMEOUT
if [ "$RC" -ne 0 ]; then
    pass "listener-timeout: exits non-zero when Vault never answers"
else
    fail "listener-timeout: exits non-zero when Vault never answers (got 0)"
fi
assert_eq "$(keys_applied)" "0" "listener-timeout: no keys thrown at a dead listener"
assert_output_contains "connection refused" "listener-timeout: probe stderr surfaces in output"
cleanup_scenario

###############################################################################
# Scenario 6: tokens file missing -> exit non-zero before touching vault
###############################################################################
setup_scenario 0 sealed 3
rm -f "$MOCK_DIR/tokens.env"
run_script
if [ "$RC" -ne 0 ]; then
    pass "missing-tokens: exits non-zero"
else
    fail "missing-tokens: exits non-zero (got 0)"
fi
assert_eq "$(vault_calls)" "0" "missing-tokens: vault never invoked"
cleanup_scenario

###############################################################################
# Scenario 7: retry back-off is real. interval=1s, timeout=2s, listener dead
#   -> a handful of probes. A no-sleep implementation makes hundreds of
#   calls inside the same window.
###############################################################################
setup_scenario 99999 sealed 3
VAULT_UNSEAL_TIMEOUT=2
VAULT_UNSEAL_RETRY_INTERVAL=1
run_script
unset VAULT_UNSEAL_TIMEOUT VAULT_UNSEAL_RETRY_INTERVAL
if [ "$RC" -ne 0 ]; then
    pass "backoff: exits non-zero on timeout"
else
    fail "backoff: exits non-zero on timeout (got 0)"
fi
CALLS="$(vault_calls)"
if [ "$CALLS" -ge 2 ] && [ "$CALLS" -le 6 ]; then
    pass "backoff: probe count bounded by interval ($CALLS calls in 2s window)"
else
    fail "backoff: probe count bounded by interval (got $CALLS calls; no-sleep spins hundreds)"
fi
cleanup_scenario

###############################################################################
# Scenario 8: Vault uninitialized -> refuse to apply keys, exit non-zero,
#   say why (vault status rc is 2 for uninitialized too; rc alone is not
#   enough — verified against real Vault by review round 1)
###############################################################################
setup_scenario 0 uninitialized 999
run_script
if [ "$RC" -ne 0 ]; then
    pass "uninitialized: exits non-zero"
else
    fail "uninitialized: exits non-zero (got 0)"
fi
assert_eq "$(keys_applied)" "0" "uninitialized: no keys applied"
assert_output_contains "not initialized" "uninitialized: diagnostic names the condition"
cleanup_scenario

###############################################################################
# Scenario 9: tokens file sources but a line fails (set -e trap) -> exit
#   non-zero WITH a diagnostic, not a silent rc-1 abort
###############################################################################
setup_scenario 0 sealed 3
printf 'VAULT_UNSEAL_KEY_1=key-one\nfalse\n' > "$MOCK_DIR/tokens.env"
chmod 0600 "$MOCK_DIR/tokens.env"
run_script
if [ "$RC" -ne 0 ]; then
    pass "source-failure: exits non-zero"
else
    fail "source-failure: exits non-zero (got 0)"
fi
assert_output_contains "failed to source" "source-failure: diagnostic present"
cleanup_scenario

###############################################################################
# Scenario 10: tokens file group-writable -> refuse before sourcing
#   (the file feeds a root-executed `source`; loose write bits = code exec)
###############################################################################
setup_scenario 0 sealed 3
chmod 0620 "$MOCK_DIR/tokens.env"
run_script
if [ "$RC" -ne 0 ]; then
    pass "guard-file-perms: refuses group-writable tokens file"
else
    fail "guard-file-perms: refuses group-writable tokens file (got 0)"
fi
assert_eq "$(vault_calls)" "0" "guard-file-perms: vault never invoked"
assert_output_contains "group/other" "guard-file-perms: diagnostic names the access bits"
cleanup_scenario

###############################################################################
# Scenario 10b: tokens file group-READABLE (0640) -> refuse. Key material
#   at rest must be 0600; a readable-by-group file leaks shares even when
#   nobody can replace it.
###############################################################################
setup_scenario 0 sealed 3
chmod 0640 "$MOCK_DIR/tokens.env"
run_script
if [ "$RC" -ne 0 ]; then
    pass "guard-file-read: refuses group-readable tokens file"
else
    fail "guard-file-read: refuses group-readable tokens file (got 0)"
fi
assert_eq "$(vault_calls)" "0" "guard-file-read: vault never invoked"
assert_output_contains "must be 0600" "guard-file-read: diagnostic names the required mode"
cleanup_scenario

###############################################################################
# Scenario 11: tokens parent directory other-writable -> refuse (an
#   attacker with dir write can replace the file regardless of file mode)
###############################################################################
setup_scenario 0 sealed 3
chmod 0707 "$MOCK_DIR"
run_script
chmod 0700 "$MOCK_DIR"
if [ "$RC" -ne 0 ]; then
    pass "guard-dir-perms: refuses other-writable parent directory"
else
    fail "guard-dir-perms: refuses other-writable parent directory (got 0)"
fi
assert_eq "$(vault_calls)" "0" "guard-dir-perms: vault never invoked"
cleanup_scenario

###############################################################################
# Scenario 12: tokens file unreadable -> exit non-zero (skipped as root,
#   where mode 000 is still readable)
###############################################################################
if [ "$(id -u)" -ne 0 ]; then
    setup_scenario 0 sealed 3
    chmod 0000 "$MOCK_DIR/tokens.env"
    run_script
    if [ "$RC" -ne 0 ]; then
        pass "unreadable-tokens: exits non-zero"
    else
        fail "unreadable-tokens: exits non-zero (got 0)"
    fi
    cleanup_scenario
else
    pass "unreadable-tokens: SKIPPED (running as root; mode bits do not bind)"
fi

###############################################################################
# Structural tripwires: documented defaults must exist in the script
# (README claims 60s wait / 2s interval; a default drift breaks the claim)
###############################################################################
if grep -q 'VAULT_UNSEAL_TIMEOUT:-60' "$SCRIPT_UNDER_TEST"; then
    pass "defaults: 60s wait timeout present"
else
    fail "defaults: 60s wait timeout present"
fi
if grep -q 'VAULT_UNSEAL_RETRY_INTERVAL:-2' "$SCRIPT_UNDER_TEST"; then
    pass "defaults: 2s retry interval present"
else
    fail "defaults: 2s retry interval present"
fi

###############################################################################
# Summary
###############################################################################
echo "---"
echo "$((TESTS - FAILURES))/$TESTS assertions passed"
if [ "$FAILURES" -gt 0 ]; then
    echo "RESULT: FAIL ($FAILURES failing)"
    exit 1
fi
echo "RESULT: PASS"
exit 0
