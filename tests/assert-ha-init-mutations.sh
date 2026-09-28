#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-ha-init-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for assert-ha-init-orchestration.sh (#44) -- proves the lock
#          kills each regression it claims to, and refuses a stale anchor.
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS. There is no HA behaviour testing, so that lock is the only
# thing standing between a task-level edit and a cluster that comes up wrong. A
# lock nobody has watched fail is a lock nobody should trust. An earlier revision
# of it checked only `when:` clauses, and five of the regressions its own header
# names survived -- including tokens.env reverting to the local register through
# `vars:` while its gate stayed correct.
#
# Every mutation asserts it APPLIED. A stale anchor silently mutates nothing,
# which yields a green lock indistinguishable from a complete one (#78 lesson 5).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/tests/assert-ha-init-orchestration.sh"
SRC="$ROOT/tasks/service.yml"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp "$SRC" "$WORK/service.yml.orig"
killed=0; survived=0; stale=0

mutate () {  # $1=label  $2=python body mutating `s`
  python3 - "$SRC" "$2" <<'PYEOF' || return 1
import io, sys
p, body = sys.argv[1], sys.argv[2]
s = io.open(p, encoding='utf-8').read()
before = s
exec(body)
if s == before:
    sys.exit(3)
io.open(p, 'w', encoding='utf-8').write(s)
PYEOF
}

run () {  # $1=label  $2=python body
  if ! mutate "$1" "$2"; then
    echo "STALE ANCHOR: $1 -- the mutation applied nothing, so a green lock proves nothing"
    stale=$((stale + 1)); cp "$WORK/service.yml.orig" "$SRC"; return
  fi
  if bash "$LOCK" >/dev/null 2>&1; then
    echo "SURVIVED: $1"; survived=$((survived + 1))
  else
    echo "killed:   $1"; killed=$((killed + 1))
  fi
  cp "$WORK/service.yml.orig" "$SRC"
}

run "init loses its host gate" \
  "s = s.replace('        - inventory_hostname == __vault_init_host_effective\n        - __vault_initialized is defined', '        - __vault_initialized is defined')"

run "tokens.env data reverts to the local register" \
  "s = s.replace('__vault_init_data: \"{{ __vault_init_source.stdout', '__vault_init_data: \"{{ __vault_init_output.stdout')"

run "leader unseal loop reverts to the local register" \
  "i = s.index('name: Unseal the initialization host'); j = s.index('name: Wait for this node'); seg = s[i:j].replace('__vault_init_source.stdout', '__vault_init_output.stdout'); s = s[:i] + seg + s[j:]"

run "follower unseal loop reverts to the local register" \
  "i = s.index('name: Unseal the remaining cluster nodes'); j = s.index('name: Verify Vault is unsealed'); seg = s[i:j].replace('__vault_init_source.stdout', '__vault_init_output.stdout'); s = s[:i] + seg + s[j:]"

run "capture directory widened to the shared register" \
  "i = s.index('name: Create controller capture directory'); j = s.index('name: Capture root token'); seg = s[i:j].replace('when: __vault_init_output is changed', \"when: __vault_init_source.stdout | default('') | length > 0\"); s = s[:i] + seg + s[j:]"

run "capture root token widened to the shared register" \
  "i = s.index('name: Capture root token'); j = s.index('name: Capture Shamir unseal shares'); seg = s[i:j].replace('when: __vault_init_output is changed', \"when: __vault_init_source.stdout | default('') | length > 0\"); s = s[:i] + seg + s[j:]"

run "join wait moved before the leader unseal" \
  "a = s.index('    # Leader first:'); b = s.index('    # A Shamir joiner reports'); c = s.index('    - name: Unseal the remaining cluster nodes'); s = s[:a] + s[b:c] + s[a:b] + s[c:]"

run "join wait loses its until" \
  "s = s.replace('      until: __vault_join_status.json.initialized | default(false) | bool\n', '')"

run "follower unseal stops honouring vault_init_unseal" \
  "i = s.index('name: Unseal the remaining cluster nodes'); j = s.index('name: Verify Vault is unsealed'); seg = s[i:j].replace('        - vault_init_unseal | bool\n', ''); s = s[:i] + seg + s[j:]"

run "audit enable loses its host gate" \
  "s = s.replace('        - inventory_hostname == __vault_init_host_effective\n        - __vault_init_source.stdout', '        - __vault_init_source.stdout', 1)"

run "batch assert tests the whole play instead of the batch" \
  "s = s.replace('__vault_init_host_effective in ansible_play_batch', '__vault_init_host_effective in ansible_play_hosts')"

run "batch assert loses its not-initialized gate" \
  "s = s.replace('        success_msg: \"Initialization host is in this batch\"\n      when:\n        - __vault_initialized is defined\n        - not __vault_initialized | bool', '        success_msg: \"Initialization host is in this batch\"')"

run "seal-status verify and its assert are deleted" \
  "i = s.index('    # Happy-path unseal verification'); j = s.index('    - name: Enable file audit device'); s = s[:i] + s[j:]"

run "validity assert moved after the durability include" \
  "i = s.index('    # State-free, and ahead of the durability include'); j = s.index('    - name: Assert the initialization capture destination is durable'); k = s.index('    - name: Validate key shares'); s = s[:i] + s[j:k] + s[i:j] + s[k:]"

cp "$WORK/service.yml.orig" "$SRC"
if ! bash "$LOCK" >/dev/null 2>&1; then
  echo "FAIL: the lock does not pass on the real tree"; exit 1
fi
echo "-----"
printf 'killed=%d survived=%d stale-anchor=%d\n' "$killed" "$survived" "$stale"
[ "$survived" -eq 0 ] && [ "$stale" -eq 0 ] || exit 1
echo "ok - the orchestration lock killed all $killed mutations, and the real tree passes"
