#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-no-unseal-argv.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #31. Fails if any Ansible task reintroduces
#   the `vault operator unseal <KEY>` CLI form (key in argv -> auditd execve
#   leak). The stdin sentinel `operator unseal -` is allowed. Scans tasks/ only;
#   the boot script (files/vault-unseal.sh) is guarded behaviorally by
#   tests/vault-unseal-test.sh. Matches logical content across a file (so the
#   idiomatic `cmd: >-` folded scalar with the command on one continuation line
#   is caught), not the module-key line.
#
#   KNOWN LIMITATION (documented, accepted): the scan is line-based, so a
#   pathological folded scalar that wrapped `operator unseal` and `{{ item }}`
#   onto SEPARATE physical lines would escape. That form is not idiomatic here;
#   Layer-1 (tests/vault-unseal-test.sh) + code review are the backstop.
#
# Usage: bash tests/assert-no-unseal-argv.sh [tasks_dir]
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN_DIR="${1:-$ROOT/tasks}"
# key-bearing arg = `{{ ... }}` or any non-hyphen, non-space token right after
# `operator unseal <space>`. `operator unseal -` (stdin sentinel) and
# `operator unseal'` (the apostrophe in the sealed-warning message) do NOT match.
PATTERN='operator[[:space:]]+unseal[[:space:]]+([{][{]|[^-[:space:]])'
violations=0

while IFS= read -r -d '' f; do
    # Strip comments (# to EOL) so commented examples never trip the gate.
    if sed 's/#.*$//' "$f" | grep -nE "$PATTERN" >/dev/null 2>&1; then
        echo "VIOLATION in ${f#"$ROOT"/}:" >&2
        sed 's/#.*$//' "$f" | grep -nE "$PATTERN" >&2 || true
        violations=1
    fi
done < <(find "$SCAN_DIR" -type f -name '*.yml' -print0)

if [ "$violations" -ne 0 ]; then
    echo "ERROR: unseal key passed via CLI argv (issue #31)." >&2
    echo "Use ansible.builtin.uri (key in body) or the 'operator unseal -' stdin sentinel." >&2
    exit 1
fi
echo "ok - no CLI-argv unseal form in ${SCAN_DIR#"$ROOT"/}"
