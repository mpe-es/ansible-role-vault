#!/usr/bin/env bash
###############################################################################
# Filename: tests/lib/list-shell-scripts.sh
# Role: ansible-role-vault
# Summary: Print every tracked shell script, one repository-relative path per
#          line. CI's shellcheck step lints exactly this list (#47).
# Usage: bash tests/lib/list-shell-scripts.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
cd "$(dirname "$0")/../.."

git ls-files -z | while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  first=""
  IFS= read -r first < "$f" || true
  if [[ "$f" == *.sh || "$first" =~ ^#![[:space:]]*(/usr)?/bin/(env[[:space:]]+)?(ba|da|k)?sh([[:space:]]|$) ]]; then
    printf '%s\n' "$f"
  fi
done
