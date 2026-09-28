#!/usr/bin/env bash
###############################################################################
# Filename: tests/init-capture-durability-test.sh
# Role: ansible-role-vault
# Summary: #94 -- the init capture guard must refuse an EPHEMERAL destination and
#   accept a DURABLE one. Both branches, no container required.
# Usage: bash tests/init-capture-durability-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# Exercises tasks/init-capture-durability.yml, not a copy of its logic.
#
# The gate keys on filesystem type, so both branches are reachable on any Linux
# host: /dev/shm is tmpfs, $HOME is a real filesystem. The test asserts that
# premise before trusting either result -- a passing run on a host where $HOME is
# tmpfs would otherwise prove nothing.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "${EPHEMERAL:-}"' EXIT
EPHEMERAL="/dev/shm/vault-i94-$$"
DURABLE="$WORK/capture"
fail=0

premise () {
  local p="$1" want="$2" got
  mkdir -p "$p" 2>/dev/null
  got="$(findmnt -n -o FSTYPE --target "$p" 2>/dev/null | tr -d ' ')"
  if [ "$want" = "ephemeral" ]; then
    case "$got" in tmpfs|ramfs|overlay|overlayfs) return 0 ;; esac
    echo "PREMISE FAILED: $p is '$got', expected an ephemeral fs — test is meaningless here"; return 1
  else
    case "$got" in tmpfs|ramfs|overlay|overlayfs)
      echo "PREMISE FAILED: $p is '$got', expected a durable fs — test is meaningless here"; return 1 ;;
    esac
    return 0
  fi
}
premise "$EPHEMERAL" ephemeral || exit 1
premise "$DURABLE" durable    || exit 1

run_case () {  # $1=label  $2=capture_dir  $3=expect(pass|fail)  $4=optional PATH override
  cat > "$WORK/case.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_init_capture_dir: "$2"
    __vault_ephemeral_fstypes: [overlay, overlayfs, tmpfs, ramfs]
  tasks:
    - ansible.builtin.include_role:
        name: ansible-role-vault
        tasks_from: init-capture-durability.yml
EOF
  if [ -n "${4:-}" ]; then
    out="$(ANSIBLE_ROLES_PATH="$ROOT/.." PATH="$4" ansible-playbook "$WORK/case.yml" 2>&1)"; rc=$?
  else
    out="$(ANSIBLE_ROLES_PATH="$ROOT/.." ansible-playbook "$WORK/case.yml" 2>&1)"; rc=$?
  fi
  if [ "$3" = "fail" ]; then
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'Refusing to initialize Vault'; then
      echo "ok: $1 -> refused, with the #94 message"
    else
      echo "FAIL: $1 -> expected refusal (rc=$rc)"; printf '%s\n' "$out" | tail -6; fail=1
    fi
  else
    if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'survives this controller'; then
      echo "ok: $1 -> accepted"
    else
      echo "FAIL: $1 -> expected acceptance (rc=$rc)"; printf '%s\n' "$out" | tail -6; fail=1
    fi
  fi
}

run_case "ephemeral destination (tmpfs)" "$EPHEMERAL" fail
run_case "durable destination"           "$DURABLE"   pass

# No usable findmnt, no proof of durability, no initialization -- fail closed on
# unseal-key custody. A minimal EE could omit util-linux, and the gate must not
# treat an unanswerable question as a pass.
#
# findmnt is SHADOWED with a stub that exits 127 rather than stripping PATH:
# stripping it breaks ansible's own tmpdir setup, which fails the play for an
# unrelated reason and proves nothing. Missing and erroring both surface as
# rc != 0, which is the branch under test.
SHADOW="$WORK/shadow"; mkdir -p "$SHADOW"
printf '#!/bin/sh\nexit 127\n' > "$SHADOW/findmnt"; chmod +x "$SHADOW/findmnt"
run_case "findmnt unusable (rc!=0)" "$DURABLE" fail "$SHADOW:$PATH"


exit "$fail"
