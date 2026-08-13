#!/usr/bin/env bash
###############################################################################
# Filename: vault-unseal.sh
# Summary: Unseal the local Vault instance from a root-only tokens file.
#   Waits (bounded) for the Vault API to answer, applies Shamir key shares
#   until unsealed, and reports the true outcome in the exit code.
# Location (deployed): /usr/local/bin/vault-unseal.sh (root:root)
# Runs as: root, via vault-unseal.service (tokens file is root-only 0600)
# Exit codes: 0 = Vault is unsealed; 1 = failure (unreachable, missing
#   inputs, or still sealed after all keys were applied)
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail

TOKENS_FILE="${VAULT_TOKENS_FILE:-/etc/vault.d/tokens.env}"
VAULT_CA_FILE="${VAULT_CACERT:-/opt/vault/tls/ca.crt}"
WAIT_TIMEOUT="${VAULT_UNSEAL_TIMEOUT:-60}"
RETRY_INTERVAL="${VAULT_UNSEAL_RETRY_INTERVAL:-2}"

export VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
export VAULT_CACERT="$VAULT_CA_FILE"

if [[ ! -r "$TOKENS_FILE" ]]; then
    echo "Error: Tokens file not found or not readable: $TOKENS_FILE" >&2
    exit 1
fi

if [[ ! -r "$VAULT_CA_FILE" ]]; then
    echo "Error: Vault CA certificate not readable: $VAULT_CA_FILE" >&2
    exit 1
fi

# seal_status: 0 = unsealed, 2 = sealed, 1 = API not answering
seal_status() {
    local rc=0
    vault status -format=json >/dev/null 2>&1 || rc=$?
    return "$rc"
}

###############################################################################
# Wait (bounded) for the Vault API to answer. vault status exits 0 when
# unsealed and 2 when sealed; anything else means the listener is not up yet.
###############################################################################
SECONDS=0
while true; do
    rc=0
    seal_status || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        echo "Vault is already unsealed; nothing to do"
        exit 0
    elif [[ "$rc" -eq 2 ]]; then
        break
    fi
    if [[ "$SECONDS" -ge "$WAIT_TIMEOUT" ]]; then
        echo "Error: Vault API did not answer within ${WAIT_TIMEOUT}s at $VAULT_ADDR" >&2
        exit 1
    fi
    sleep "$RETRY_INTERVAL"
done

# Load VAULT_UNSEAL_KEY_* variables (plain assignments; not exported)
# shellcheck source=/dev/null
source "$TOKENS_FILE"

UNSEAL_KEYS=()
for var in $(compgen -v | grep "^VAULT_UNSEAL_KEY_" | sort -V); do
    value="${!var}"
    if [[ -n "$value" ]]; then
        UNSEAL_KEYS+=("$value")
    fi
done

if [[ ${#UNSEAL_KEYS[@]} -eq 0 ]]; then
    echo "Error: No unseal keys found in $TOKENS_FILE" >&2
    exit 1
fi

echo "Found ${#UNSEAL_KEYS[@]} unseal key(s); unsealing Vault..."

###############################################################################
# Apply keys until Vault reports unsealed. A single key failure is logged
# and the next key is tried; the final verdict comes from seal status.
###############################################################################
for key in "${UNSEAL_KEYS[@]}"; do
    if ! vault operator unseal "$key" >/dev/null 2>&1; then
        echo "Warning: unseal key rejected or call failed; trying next key" >&2
    fi
    rc=0
    seal_status || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        echo "Vault unsealed successfully"
        exit 0
    fi
done

echo "Error: Vault remains sealed after applying all available keys" >&2
exit 1
