#!/usr/bin/env bash
###############################################################################
# Filename: vault-unseal.sh
# Summary: Unseal the local Vault instance from a root-only tokens file.
#   Refuses untrusted tokens-file ownership/permissions, waits (bounded)
#   for the Vault API to answer, applies Shamir key shares until unsealed,
#   and reports the true outcome in the exit code.
# Location (deployed): /usr/local/bin/vault-unseal.sh (root:root)
# Runs as: root, via vault-unseal.service. The tokens file lives in
#   /etc/vault.d (root:vault 0750 — root-owned so no unprivileged account
#   can replace entries; vault group reads its configs). This file is
#   `source`d by root; its path chain must be trusted.
# Exit codes: 0 = Vault is unsealed; 1 = failure (untrusted tokens path,
#   unreachable API, uninitialized Vault, or still sealed after all keys)
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail

TOKENS_FILE="${VAULT_TOKENS_FILE:-/etc/vault.d/tokens.env}"
VAULT_CA_FILE="${VAULT_CACERT:-/opt/vault/tls/ca.crt}"
WAIT_TIMEOUT="${VAULT_UNSEAL_TIMEOUT:-60}"
RETRY_INTERVAL="${VAULT_UNSEAL_RETRY_INTERVAL:-2}"

export VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
export VAULT_CACERT="$VAULT_CA_FILE"

# Reject a symlinked tokens file BEFORE any follow: -r/stat/source all
# follow the link, so a symlink whose lexical parent is trusted but whose
# TARGET sits under an attacker-writable directory would pass the guard
# and then be swapped between stat and source (TOCTOU -> root exec). A
# real regular file's lexical parent IS its real parent, so validating
# the lexical parent below is sound only once symlinks are refused here.
if [[ -L "$TOKENS_FILE" ]]; then
    echo "Error: $TOKENS_FILE is a symlink; refusing (its target's parent may be untrusted)" >&2
    exit 1
fi

if [[ ! -r "$TOKENS_FILE" ]]; then
    echo "Error: Tokens file not found or not readable: $TOKENS_FILE" >&2
    exit 1
fi

if [[ ! -f "$TOKENS_FILE" ]]; then
    echo "Error: $TOKENS_FILE is not a regular file; refusing" >&2
    exit 1
fi

if [[ ! -r "$VAULT_CA_FILE" ]]; then
    echo "Error: Vault CA certificate not readable: $VAULT_CA_FILE" >&2
    exit 1
fi

###############################################################################
# Trust guard: this script `source`s the tokens file as root. Refuse unless
# the file AND its parent directory are owned by root (or the invoking uid,
# for unprivileged test runs) and carry no group/other write bits — a
# writable parent lets any local account replace the file (unlink/create
# needs only directory write, not file ownership).
###############################################################################
stat_uid_mode() { # portable: GNU coreutils first, BSD fallback
    stat -c '%u %a' "$1" 2>/dev/null || stat -f '%u %Lp' "$1" 2>/dev/null
}

# Scope: checks the target and its immediate parent. The shipped default
# lives under /etc (root-owned); a VAULT_TOKENS_FILE override placed under
# an untrusted grandparent is the operator's responsibility.
# kind=dir  -> refuse group/other WRITE bits (replacement protection;
#              group r-x is EXPECTED — /etc/vault.d is root:vault 0750 so
#              the vault group can read its own configs)
# kind=file -> refuse ANY group/other access bits (key material is 0600;
#              a group-readable tokens file leaks shares at rest)
require_trusted_path() {
    local path="$1" kind="$2" uid mode gbit obit
    if ! read -r uid mode < <(stat_uid_mode "$path"); then
        echo "Error: cannot stat $path" >&2
        exit 1
    fi
    # Fail closed on unparseable stat output (a formatter mismatch must
    # never degrade into a silently-passing guard)
    if ! [[ "$uid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]+$ ]]; then
        echo "Error: unparseable stat output for $path ('$uid $mode')" >&2
        exit 1
    fi
    # stat prints minimal digits (mode 000 -> "0"); STRING-pad to four
    # chars so the group/other slices always index real positions. Never
    # printf '%04d' here: base-0 parsing reads a leading zero as octal
    # ("0750" -> "0488") and would fail the guard open.
    mode="000${mode}"
    mode="${mode: -4}"
    if [[ "$uid" -ne 0 && "$uid" -ne "$EUID" ]]; then
        echo "Error: $path owned by uid $uid (not root); refusing to trust it" >&2
        exit 1
    fi
    gbit="${mode: -2:1}"
    obit="${mode: -1}"
    if [[ "$kind" == "file" ]]; then
        if [[ "$gbit$obit" != "00" ]]; then
            echo "Error: $path has group/other access bits (mode $mode); tokens file must be 0600" >&2
            exit 1
        fi
    else
        case "$gbit$obit" in
            *[2367]*)
                echo "Error: $path is group- or other-writable (mode $mode); refusing" >&2
                exit 1
                ;;
        esac
    fi
}

require_trusted_path "$(dirname "$TOKENS_FILE")" dir
require_trusted_path "$TOKENS_FILE" file

# seal_status: 0 = unsealed, 2 = sealed or uninitialized, other = the CLI
# could not obtain seal status (listener down, TLS/CA error, DNS — all
# surface as rc 1; verified against a real vault binary in review round 1).
# STATUS_OUT carries the JSON (or the error text) for diagnostics.
STATUS_OUT=""
seal_status() {
    local rc=0
    STATUS_OUT=$(vault status -format=json 2>&1) || rc=$?
    return "$rc"
}

###############################################################################
# Wait (bounded) for the Vault API to answer. Non-0/2 covers permanent
# errors too (bad CA, DNS), so the timeout message carries the last error.
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
        echo "Error: could not obtain Vault seal status within ${WAIT_TIMEOUT}s at $VAULT_ADDR" >&2
        echo "Last error: ${STATUS_OUT}" >&2
        exit 1
    fi
    sleep "$RETRY_INTERVAL"
done

# rc 2 also covers an UNINITIALIZED Vault (verified against a real vault
# binary); throwing unseal keys at one only produces confusing errors.
if grep -Eq '"initialized"[[:space:]]*:[[:space:]]*false' <<< "$STATUS_OUT"; then
    echo "Error: Vault is not initialized (vault operator init has not run); refusing to apply unseal keys" >&2
    exit 1
fi

# Parse VAULT_UNSEAL_KEY_<n>=<value> records WITHOUT executing the file.
# NEVER `source` a secrets file as root: content like `exit 0` would make
# the service report success while Vault stays sealed (violating the
# honest-exit contract), and `set -u` could abort on an unquoted value —
# both outside any catchable diagnostic, and $(...) would run as root.
# Order is immaterial: any threshold of distinct Shamir shares unseals.
UNSEAL_KEYS=()
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^VAULT_UNSEAL_KEY_[0-9]+=(.*)$ ]] || continue
    value="${BASH_REMATCH[1]}"
    # strip one layer of matching surrounding quotes, if present
    if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
        value="${value:1:${#value}-2}"
    fi
    [[ -n "$value" ]] && UNSEAL_KEYS+=("$value")
done < "$TOKENS_FILE"

if [[ ${#UNSEAL_KEYS[@]} -eq 0 ]]; then
    echo "Error: No unseal keys found in $TOKENS_FILE" >&2
    exit 1
fi

echo "Found ${#UNSEAL_KEYS[@]} unseal key(s); unsealing Vault..."

###############################################################################
# Apply keys until Vault reports unsealed. NOTE: `vault operator unseal`
# returns 0 even for an invalid key (verified against a real vault binary)
# — the ONLY trustworthy verdict is seal status, which is why every
# iteration re-checks status and the final error comes from it.
###############################################################################
for key in "${UNSEAL_KEYS[@]}"; do
    # Key via stdin (the "-" sentinel), NEVER argv: auditd execve records only
    # "vault operator unseal -", not the key. Do NOT revert to `unseal "$key"`
    # (issue #31). `printf '%s'` — no trailing newline into the key reader.
    if ! printf '%s' "$key" | vault operator unseal - >/dev/null 2>&1; then
        echo "Warning: unseal call failed; trying next key" >&2
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
