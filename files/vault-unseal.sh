#!/bin/bash
#
# Unseal local vault instance
#

TOKENS_FILE="/etc/vault.d/tokens.env"

export VAULT_ADDR="https://localhost:8200"
export VAULT_SKIP_VERIFY=true

# Check if tokens file exists
if [[ ! -f "$TOKENS_FILE" ]]; then
    echo "Error: Tokens file not found: $TOKENS_FILE"
    exit 1
fi

# Source the tokens file to load all VAULT_UNSEAL_KEY_* variables
source "$TOKENS_FILE"

# Find all VAULT_UNSEAL_KEY_* variables and store them in an array
UNSEAL_KEYS=()
for var in $(compgen -v | grep "^VAULT_UNSEAL_KEY_" | sort -V); do
    value="${!var}"
    if [[ -n "$value" ]]; then
        UNSEAL_KEYS+=("$value")
    fi
done

# Verify we have keys
if [[ ${#UNSEAL_KEYS[@]} -eq 0 ]]; then
    echo "Error: No unseal keys found in $TOKENS_FILE"
    exit 1
fi

echo "Found ${#UNSEAL_KEYS[@]} unseal key(s)"
echo "Unsealing Vault..."

# Apply each unseal key
for key in "${UNSEAL_KEYS[@]}"; do
    vault operator unseal "$key" || echo "Warning: Unseal key failed, continuing..."
done

echo "Vault unseal process completed"
