#!/usr/bin/env bash
###############################################################################
# Filename: tests/vault-unseal-test.sh
# Role: ansible-role-vault
# Summary: Behavioral test harness for files/vault-unseal.sh using a mock
#   vault binary. No network, no root, no real Vault required.
#   Contract under test (issue #30):
#     - waits (bounded) for the Vault API to answer before unsealing
#     - exits 0 without applying keys when Vault is already unsealed
#     - applies keys until unsealed, then stops
#     - exits non-zero when Vault remains sealed (honest exit code)
#     - exits non-zero when the tokens file is missing or unreadable
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

###############################################################################
# Mock environment. Each scenario gets a fresh MOCK_DIR holding mock state:
#   listening_after  - mock vault invocations that fail (rc 1) before the
#                      "listener" comes up
#   seal_state       - sealed | unsealed
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
case "${1:-}" in
    status)
        if [ "$(cat "$MOCK_DIR/seal_state")" = "unsealed" ]; then
            echo '{"initialized": true, "sealed": false}'
            exit 0
        fi
        echo '{"initialized": true, "sealed": true}'
        exit 2
        ;;
    operator)
        # argv: operator unseal <key>
        printf '%s\n' "${3:-MISSING_KEY_ARG}" >> "$MOCK_DIR/keys.log"
        applied=$(wc -l < "$MOCK_DIR/keys.log" | tr -d ' ')
        if [ "$applied" -ge "$(cat "$MOCK_DIR/keys_needed")" ]; then
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

    # tokens.env fixture matching templates/tokens.env.j2 shape
    cat > "$MOCK_DIR/tokens.env" <<'TOKENS'
# mock tokens file
VAULT_UNSEAL_KEY_1=key-one
VAULT_UNSEAL_KEY_2=key-two
VAULT_UNSEAL_KEY_3=key-three
VAULT_UNSEAL_KEY_4=key-four
VAULT_UNSEAL_KEY_5=key-five
VAULT_ROOT_TOKEN=hvs.mockroottoken
TOKENS
}

run_script() { # extra env via VAULT_UNSEAL_* already exported by caller
    RC=0
    PATH="$MOCK_DIR/bin:$PATH" \
    VAULT_CACERT="$MOCK_DIR/ca.crt" \
    VAULT_TOKENS_FILE="$MOCK_DIR/tokens.env" \
    VAULT_UNSEAL_TIMEOUT="${VAULT_UNSEAL_TIMEOUT:-10}" \
    VAULT_UNSEAL_RETRY_INTERVAL="${VAULT_UNSEAL_RETRY_INTERVAL:-0}" \
        bash "$SCRIPT_UNDER_TEST" > "$MOCK_DIR/output.log" 2>&1 || RC=$?
}

keys_applied() { wc -l < "$MOCK_DIR/keys.log" | tr -d ' '; }

cleanup_scenario() { rm -rf "$MOCK_DIR"; }

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
#   sealed->unsealed. 11 > 1 initial probe + 5 keys x 2 calls, so an
#   implementation that skips the wait exhausts every key against the dead
#   listener and cannot pass by luck -> script must wait, then exit 0.
###############################################################################
setup_scenario 11 sealed 3
run_script
assert_eq "$RC" "0" "waits-for-listener: exits 0 after listener comes up"
assert_eq "$(keys_applied)" "3" "waits-for-listener: keys applied only after listener up"
cleanup_scenario

###############################################################################
# Scenario 5: listener never comes up -> bounded wait, exit non-zero
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
cleanup_scenario

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
