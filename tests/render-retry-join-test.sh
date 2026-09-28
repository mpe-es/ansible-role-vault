#!/usr/bin/env bash
###############################################################################
# Filename: tests/render-retry-join-test.sh
# Role: ansible-role-vault
# Summary: retry_join renders one stanza per peer, brackets IPv6, and renders
#   nothing when no peers are configured (#44). No container required.
# Usage: bash tests/render-retry-join-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# Scope-free by design, like render-hsm-pin-test.sh: no role scope, no argument
# spec. The string-coercion defence (type: list) therefore CANNOT be tested here
# -- a string stays a string and renders per character. That case belongs where
# the argument spec runs; see molecule/preflight and meta/argument_specs.yml.
set -uo pipefail
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0

render () {  # $1=json extra-vars
  cat > "$WORK/r.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_listener_port: 8200
    vault_tls_ca_file: /opt/vault/tls/ca.crt
  tasks:
    - ansible.builtin.copy:
        dest: $WORK/out.txt
        content: |
          # BEGIN -- an anchor line, because copy rejects empty content with
          # "src (or content) is required" and an empty peer list renders nothing.
          {% for peer in vault_cluster_members | default([]) %}
          leader_api_addr = "https://{{ '[' ~ peer ~ ']' if ':' in peer else peer }}:{{ vault_listener_port }}"
          {% endfor %}
          {% if vault_cluster_leader_addr | default('') | length > 0 %}
          leader_api_addr = "https://{{ vault_cluster_leader_addr }}:{{ vault_listener_port }}"
          {% endif %}
        mode: '0600'
EOF
  rm -f "$WORK/out.txt"
  if ! ansible-playbook "$WORK/r.yml" -e "$1" >"$WORK/log" 2>&1; then
    echo "PLAYBOOK_FAILED"; return
  fi
  # The render must have produced a file. Without this the empty case passes
  # vacuously: grep -c over nothing also prints 0.
  if [ ! -f "$WORK/out.txt" ]; then echo "NO_OUTPUT"; return; fi
  tr -d ' ' < "$WORK/out.txt" | grep -c 'leader_api_addr' || true
}

check () {  # $1=label $2=json $3=expected-count $4=optional grep
  local got; got="$(render "$2")"
  if [ "$got" != "$3" ]; then
    echo "FAIL: $1 -- $got stanza(s), expected $3"; fail=1; return
  fi
  if [ -n "${4:-}" ] && ! grep -q "$4" "$WORK/out.txt"; then
    echo "FAIL: $1 -- expected '$4' in the render"; fail=1; return
  fi
  echo "ok: $1"
}

check "no peers, no leader address -> no stanza"  '{"vault_cluster_members": [], "vault_cluster_leader_addr": ""}' 0
check "three peers -> three stanzas"             '{"vault_cluster_members": ["v1.mpe.mil","v2.mpe.mil","v3.mpe.mil"], "vault_cluster_leader_addr": ""}' 3 'v2.mpe.mil:8200'
check "one peer -> one stanza"                   '{"vault_cluster_members": ["v1.mpe.mil"], "vault_cluster_leader_addr": ""}' 1
check "IPv4 peer is not bracketed"               '{"vault_cluster_members": ["10.1.1.5"], "vault_cluster_leader_addr": ""}' 1 'https://10.1.1.5:8200'
check "IPv6 peer IS bracketed"                   '{"vault_cluster_members": ["2001:db8::10"], "vault_cluster_leader_addr": ""}' 1 'https://\[2001:db8::10\]:8200'
check "mixed v4 and v6 -> two stanzas"           '{"vault_cluster_members": ["10.1.1.5","2001:db8::10"], "vault_cluster_leader_addr": ""}' 2
check "legacy leader address alone still works"  '{"vault_cluster_members": [], "vault_cluster_leader_addr": "vault-vip.mpe.mil"}' 1 'vault-vip.mpe.mil:8200'
check "five peers -> five stanzas"               '{"vault_cluster_members": ["v1","v2","v3","v4","v5"], "vault_cluster_leader_addr": ""}' 5

exit "$fail"
