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
# The gate keys on filesystem type. /dev/shm is tmpfs on every Linux host, so the
# ephemeral branch is always reachable. The durable branch is NOT: `mktemp -d`
# lands in /tmp, which is tmpfs on many hosts, and an earlier revision of this test
# used it and then aborted at its own premise check on exactly those hosts -- the
# control test silently stopped being one.
#
# The durable base is therefore DISCOVERED, not assumed. Candidates are probed in
# order and the first non-ephemeral one wins; if none is durable the test fails
# loudly naming every candidate and its fstype, rather than exiting quietly.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

fstype_of () { findmnt -n -o FSTYPE --target "$1" 2>/dev/null | tr -d ' '; }
is_ephemeral () { case "$(fstype_of "$1")" in tmpfs|ramfs|overlay|overlayfs|"") return 0 ;; esac; return 1; }

DURABLE_BASE=""
probed=""
for base in "${HOME:-}" /var/tmp "$ROOT" /tmp; do
  if [ -z "$base" ] || [ ! -d "$base" ] || [ ! -w "$base" ]; then continue; fi
  probed="$probed $base=$(fstype_of "$base")"
  if ! is_ephemeral "$base"; then DURABLE_BASE="$base"; break; fi
done
if [ -z "$DURABLE_BASE" ]; then
  echo "FAIL: no durable writable base found, so the durable and fail-closed branches"
  echo "      cannot be exercised. Probed:$probed"
  exit 1
fi

WORK="$(mktemp -d -p "$DURABLE_BASE" vault-i94.XXXXXX)"
# ansible resolves a role by DIRECTORY NAME, so pointing ANSIBLE_ROLES_PATH at the
# checkout's parent only works when the checkout happens to be named
# 'ansible-role-vault'. Mounted elsewhere -- a container, a worktree, a rename --
# it is not. Link a correctly-named directory instead.
mkdir -p "$WORK/roles"
ln -sfn "$ROOT" "$WORK/roles/ansible-role-vault"
EPHEMERAL="/dev/shm/vault-i94-$$"
trap 'rm -rf "$WORK" "${EPHEMERAL:-}"' EXIT
DURABLE="$WORK/capture"
echo "durable base: $DURABLE_BASE ($(fstype_of "$DURABLE_BASE"))   ephemeral: /dev/shm ($(fstype_of /dev/shm))"

premise () {
  local p="$1" want="$2"
  mkdir -p "$p" 2>/dev/null
  if [ "$want" = "ephemeral" ]; then
    is_ephemeral "$p" && return 0
    echo "PREMISE FAILED: $p is '$(fstype_of "$p")', expected an ephemeral fs"; return 1
  else
    is_ephemeral "$p" || return 0
    echo "PREMISE FAILED: $p is '$(fstype_of "$p")', expected a durable fs"; return 1
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
    out="$(ANSIBLE_ROLES_PATH="$WORK/roles" PATH="$4" ansible-playbook "$WORK/case.yml" 2>&1)"; rc=$?
  else
    out="$(ANSIBLE_ROLES_PATH="$WORK/roles" ansible-playbook "$WORK/case.yml" 2>&1)"; rc=$?
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
