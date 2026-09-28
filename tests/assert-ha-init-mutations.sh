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
# Mutate a COPY of the tree, never the tracked file. An in-place harness whose trap
# deletes its backup leaves tasks/service.yml corrupted on any interrupt, and this
# runs in CI. assert-ha-init-orchestration.sh accepts a root argument for exactly
# this, as the four sibling *-mutations.sh harnesses do.
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SANDBOX="$WORK/tree"
mkdir -p "$SANDBOX"
cp -a "$ROOT/tasks" "$ROOT/templates" "$ROOT/defaults" "$ROOT/vars" "$SANDBOX/"
SRC="$SANDBOX/tasks/service.yml"
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
  if bash "$LOCK" "$SANDBOX" >/dev/null 2>&1; then
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

# The highest-value regression on this role: key material into an AAP job log.
run "operator init loses no_log" \
  "i = s.index('name: Run vault operator init'); j = s.index('name: Store unseal shares'); seg = s[i:j].replace('      no_log: true\n', ''); s = s[:i] + seg + s[j:]"

run "tokens.env loses no_log" \
  "i = s.index('name: Store unseal shares'); j = s.index('name: Create controller capture directory'); seg = s[i:j].replace('      no_log: true\n', ''); s = s[:i] + seg + s[j:]"

run "leader unseal loses no_log" \
  "i = s.index('name: Unseal the initialization host'); j = s.index('name: Wait for this node'); seg = s[i:j].replace('      no_log: true', ''); s = s[:i] + seg + s[j:]"

run "follower unseal loses no_log" \
  "i = s.index('name: Unseal the remaining cluster nodes'); j = s.index('name: Verify Vault is unsealed'); seg = s[i:j].replace('      no_log: true\n', ''); s = s[:i] + seg + s[j:]"

run "capture root token loses no_log" \
  "i = s.index('name: Capture root token'); j = s.index('name: Capture Shamir unseal shares'); seg = s[i:j].replace('      no_log: true\n', ''); s = s[:i] + seg + s[j:]"

run "audit enable loses no_log" \
  "i = s.index('name: Enable file audit device'); j = s.index('name: Enable syslog audit device'); seg = s[i:j].replace('      no_log: true\n', ''); s = s[:i] + seg + s[j:]"

# --- codex round 1: the lock's own blind spots, and the new gates -------------

run "operator init gains run_once" \
  "i = s.index('name: Run vault operator init'); j = s.index('name: Fail when the init host'); seg = s[i:j].replace('      register: __vault_init_output', '      register: __vault_init_output\n      run_once: true'); s = s[:i] + seg + s[j:]"

run "operator init changed_when goes constant-false" \
  "s = s.replace('changed_when: __vault_init_output.rc == 0', 'changed_when: false')"

run "a debug dumps the shared register" \
  "s = s.replace('    - name: Enable file audit device', '    - name: Show init output\n      ansible.builtin.debug:\n        var: __vault_init_source\n\n    - name: Enable file audit device')"

run "the status probe loses check_mode false" \
  "s = s.replace('      check_mode: false\n      environment:', '      environment:', 1)"

run "the join wait excludes HSM again" \
  "s = s.replace('        - (vault_hsm_enabled | bool) or (vault_init_unseal | bool)\n        - __vault_initialized is defined', '        - vault_init_unseal | bool\n        - not (vault_hsm_enabled | bool)\n        - __vault_initialized is defined')"

run "the strategy:free guard is deleted" \
  "i = s.index('    - name: Fail when the init host has produced no key material'); j = s.index('    # root:root 0600 in /etc/vault.d'); s = s[:i] + s[j:]"

run "the strategy:free guard stops testing for an empty register" \
  "s = s.replace(\"        - __vault_init_source.stdout | default('') | length == 0\", '')"

run "the cluster-identity assert is deleted" \
  "i = s.index(\"    - name: Assert every cluster node reports the same Raft cluster\"); j = s.index('    - name: Enable file audit device'); s = s[:i] + s[j:]"

run "the cluster-identity assert compares a node with itself" \
  "s = s.replace(\"{{ hostvars[__vault_init_host_effective]['__vault_cluster_identity'].json.cluster_id\", '{{ __vault_cluster_identity.json.cluster_id')"

run "the cluster-identity read becomes no_log" \
  "s = s.replace(\"      register: __vault_cluster_identity\", '      register: __vault_cluster_identity\n      no_log: true')"

# Reverts the shared definition back to the inline per-host path every site used to
# build, which is the drift that put the FOLLOWER's hostname in the rescue message.
run "the capture path goes back to inline per-host construction" \
  "s = s.replace('__vault_capture_host_dir', 'vault_init_capture_dir }}/{{ inventory_hostname')"

# --- codex round 2 -----------------------------------------------------------

run "the strategy:free guard is inverted onto the init host" \
  "i = s.index('    - name: Fail when the init host has produced no key material'); j = s.index('    # root:root 0600 in /etc/vault.d'); seg = s[i:j].replace('inventory_hostname != __vault_init_host_effective', 'inventory_hostname == __vault_init_host_effective'); s = s[:i] + seg + s[j:]"

run "the strategy:free guard stops excluding check mode" \
  "i = s.index('    - name: Fail when the init host has produced no key material'); j = s.index('    # root:root 0600 in /etc/vault.d'); seg = s[i:j].replace('        - not ansible_check_mode\n', ''); s = s[:i] + seg + s[j:]"

run "the cluster-identity assert becomes a tautology" \
  "s = s.replace('          - __vault_this_cluster_id == __vault_peer_cluster_id', '          - __vault_this_cluster_id == __vault_this_cluster_id')"

run "a task NAME carries the init register" \
  "s = s.replace('    - name: Enable file audit device', '    - name: Enable file audit device for {{ __vault_init_source }}')"

run "the status probe loses its client certificate" \
  "i = s.index('name: Check Vault initialization status'); j = s.index('name: Parse Vault status'); seg = s[i:j].replace('        VAULT_CLIENT_CERT: \"{{ __vault_client_cert }}\"\n', ''); s = s[:i] + seg + s[j:]"

run "the leader unseal loses its client certificate" \
  "i = s.index('name: Unseal the initialization host'); j = s.index('name: Wait for this node'); seg = s[i:j].replace(\"        client_cert: \\\"{{ vault_tls_cert_file if (vault_tls_require_client_cert | bool) else omit }}\\\"\n\", ''); s = s[:i] + seg + s[j:]"

# --- Hobi review: the legacy scalar could still drive a local init ------------

run "service.yml stops rejecting the legacy scalar (--skip-tags preflight path)" \
  "s = s.replace(\"          - vault_cluster_leader_addr | default('') | length == 0\\n\", '')"

run "a gate reverts to an inline member predicate" \
  "s = s.replace('        - __vault_ha_cluster | bool', '        - vault_cluster_members | default([]) | length > 0', 1)"

# This one mutates the PREFLIGHT file, not service.yml, so it restores that file itself.
cp "$SANDBOX/tasks/preflight/cluster.yml" "$WORK/cluster.yml.orig"
if python3 - "$SANDBOX/tasks/preflight/cluster.yml" <<'PYEOF'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding='utf-8').read()
i = s.index('- name: "Preflight | cluster | the legacy join scalar never drives initialization"')
j = s.index('- name: "Preflight | cluster | the peer list is a list"')
out = s[:i] + s[j:]
if out == s:
    sys.exit(3)
io.open(p, 'w', encoding='utf-8').write(out)
PYEOF
then
  if bash "$LOCK" "$SANDBOX" >/dev/null 2>&1; then
    echo "SURVIVED: the legacy-scalar initialization rejection is deleted"; survived=$((survived + 1))
  else
    echo "killed:   the legacy-scalar initialization rejection is deleted"; killed=$((killed + 1))
  fi
else
  echo "STALE ANCHOR: the legacy-scalar rejection -- mutated nothing"; stale=$((stale + 1))
fi
cp "$WORK/cluster.yml.orig" "$SANDBOX/tasks/preflight/cluster.yml"

cp "$WORK/service.yml.orig" "$SRC"
if ! bash "$LOCK" "$ROOT" >/dev/null 2>&1; then
  echo "FAIL: the lock does not pass on the real tree"; exit 1
fi
echo "-----"
printf 'killed=%d survived=%d stale-anchor=%d\n' "$killed" "$survived" "$stale"
[ "$survived" -eq 0 ] && [ "$stale" -eq 0 ] || exit 1
echo "ok - the orchestration lock killed all $killed mutations, and the real tree passes"
