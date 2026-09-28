#!/usr/bin/env bash
###############################################################################
# Filename: tests/render-retry-join-test.sh
# Role: ansible-role-vault
# Summary: retry_join renders one stanza per peer, brackets IPv6, and renders
#   nothing when no peers are configured (#44). No container required.
# Usage: bash tests/render-retry-join-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# Renders the REAL templates/vault.hcl.j2, like render-hsm-pin-test.sh. An earlier
# revision rendered an inline copy of the loop expression, which meant deleting the
# entire retry_join block from the template passed every test in the repository.
#
# Scope-free: no role scope, no argument spec. A string passed where a list is
# expected therefore renders per character here, so that case is NOT tested in this
# harness -- tasks/preflight/cluster.yml rejects it instead.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0

render () {  # $1=json extra-vars -> stanza count, or a loud marker
  cat > "$WORK/r.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_listener_port: 8200
    vault_tls_ca_file: /opt/vault/tls/ca.crt
    vault_tls_cert_file: /opt/vault/tls/tls.crt
    vault_tls_key_file: /opt/vault/tls/tls.key
    vault_data_dir: /opt/vault/data
    vault_config_dir: /etc/vault.d
    vault_raft_node_id: t
    vault_api_addr: https://127.0.0.1:8200
    vault_cluster_addr: https://127.0.0.1:8201
    vault_ui_enabled: true
    vault_disable_mlock: false
    vault_disable_performance_standby: true
    vault_log_level: info
    vault_listener_address: 0.0.0.0
    vault_tls_min_version: tls12
    vault_tls_max_version: tls13
    vault_tls_cipher_suites: []
    vault_tls_require_client_cert: false
    vault_tls_disable_client_certs: false
    vault_hsm_enabled: false
    vault_edition: vault
  tasks:
    - ansible.builtin.template:
        src: $ROOT/templates/vault.hcl.j2
        dest: $WORK/out.hcl
        mode: '0600'
EOF
  rm -f "$WORK/out.hcl"
  if ! ansible-playbook "$WORK/r.yml" -e "$1" >"$WORK/log" 2>&1; then
    echo "PLAYBOOK_FAILED"; return
  fi
  if [ ! -f "$WORK/out.hcl" ]; then echo "NO_OUTPUT"; return; fi
  grep -c 'leader_api_addr' "$WORK/out.hcl" || true
}

check () {  # $1=label $2=json $3=expected-count $4=optional grep
  local got; got="$(render "$2")"
  if [ "$got" != "$3" ]; then
    echo "FAIL: $1 -- $got stanza(s), expected $3"; fail=1; return
  fi
  if [ -n "${4:-}" ] && ! grep -q "$4" "$WORK/out.hcl"; then
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
# The CA pin is part of the join contract the README and CHANGELOG describe, and
# counting leader_api_addr alone does not notice its removal.
ca_count () { grep -c 'leader_ca_cert_file' "$WORK/out.hcl" || true; }
render '{"vault_cluster_members": ["v1.mpe.mil","v2.mpe.mil","v3.mpe.mil"], "vault_cluster_leader_addr": ""}' >/dev/null
if [ "$(ca_count)" = "3" ]; then
  echo "ok: every stanza pins leader_ca_cert_file"
else
  echo "FAIL: $(ca_count) of 3 stanzas pin leader_ca_cert_file"; fail=1
fi

# ULA IPv6 must bracket too -- fd00::/8 is what an airgapped enclave numbers with, and
# the FIRST version of the preflight gate REJECTED it (urlsplit read fd00 as a scheme),
# so the render was never exercised on it. The fe80:: case pins the same BRACKETING
# behaviour and nothing more: a bare link-local address cannot identify an interface and
# a zone-indexed one is rejected by the preflight gate, so link-local peers are not
# usable in practice (README says so).
check "ULA IPv6 peer IS bracketed"               '{"vault_cluster_members": ["fd00::10"], "vault_cluster_leader_addr": ""}' 1 'https://\[fd00::10\]:8200'
check "link-local IPv6 peer IS bracketed"        '{"vault_cluster_members": ["fe80::1"], "vault_cluster_leader_addr": ""}' 1 'https://\[fe80::1\]:8200'

# mTLS. With a client-cert-requiring listener, a retry_join that sends only the CA
# cannot authenticate and the follower never joins.
mtls () { grep -c "$1" "$WORK/out.hcl" || true; }
render '{"vault_cluster_members": ["v1.mpe.mil","v2.mpe.mil"], "vault_cluster_leader_addr": "", "vault_tls_require_client_cert": true}' >/dev/null
if [ "$(mtls leader_client_cert_file)" = "2" ] && [ "$(mtls leader_client_key_file)" = "2" ]; then
  echo "ok: mTLS renders client cert and key in every stanza"
else
  echo "FAIL: mTLS client credentials missing ($(mtls leader_client_cert_file) cert, $(mtls leader_client_key_file) key of 2)"; fail=1
fi
render '{"vault_cluster_members": ["v1.mpe.mil","v2.mpe.mil"], "vault_cluster_leader_addr": "", "vault_tls_require_client_cert": false}' >/dev/null
if [ "$(mtls leader_client_cert_file)" = "0" ]; then
  echo "ok: no client credentials when the listener does not require them"
else
  echo "FAIL: client credentials rendered although require_client_cert is false"; fail=1
fi

# STRUCTURE, not just field names. The mTLS fields were first added inside a macro whose
# `{%- if %}` stripped the preceding NEWLINE, rendering
#   leader_ca_cert_file = "..."    leader_client_cert_file = "..."
# and `}` on the end of another attribute line -- two attributes per line is invalid HCL,
# and a grep for field NAMES passed on it. Every check above is name-based; this one is
# the only thing here that would have caught it.
structure () {  # -> a complaint per malformed line, or nothing
  awk '
    /^[[:space:]]*#/ { next }                      # comments may contain anything
    {
      n = gsub(/[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/, "&")
      if (n > 1) print "  two or more assignments on line " NR ": " $0
      if ($0 ~ /=/ && $0 ~ /\}/) print "  assignment shares a line with a brace, line " NR ": " $0
    }
  ' "$WORK/out.hcl"
}
for js in '{"vault_cluster_members": ["a.mpe.mil","fd00::9"], "vault_cluster_leader_addr": "", "vault_tls_require_client_cert": true}' \
          '{"vault_cluster_members": ["a.mpe.mil"], "vault_cluster_leader_addr": "", "vault_tls_require_client_cert": false}' \
          '{"vault_cluster_members": [], "vault_cluster_leader_addr": "vip.mpe.mil", "vault_tls_require_client_cert": true}' \
          '{"vault_cluster_members": [], "vault_cluster_leader_addr": "fd00::99", "vault_tls_require_client_cert": true}'; do
  render "$js" >/dev/null
  bad="$(structure)"
  if [ -n "$bad" ]; then
    echo "FAIL: malformed HCL for $js"; printf '%s\n' "$bad"; fail=1
  else
    echo "ok: one assignment per line, braces on their own lines"
  fi
done

# THE LEGACY SCALAR IS THE SAME STANZA. It was a separate copy of the block and silently
# missed both the IPv6 bracketing and the mTLS credentials the peer loop had gained, so
# it is now rendered by the same macro -- and pinned here in both respects.
check "legacy scalar brackets IPv6"               '{"vault_cluster_members": [], "vault_cluster_leader_addr": "fd00::99"}' 1 'https://\[fd00::99\]:8200'
render '{"vault_cluster_members": [], "vault_cluster_leader_addr": "vip.mpe.mil", "vault_tls_require_client_cert": true}' >/dev/null
if [ "$(grep -c 'leader_client_cert_file' "$WORK/out.hcl")" = "1" ] && [ "$(grep -c 'leader_client_key_file' "$WORK/out.hcl")" = "1" ]; then
  echo "ok: legacy scalar carries the mTLS client identity too"
else
  echo "FAIL: legacy scalar stanza has no client identity under mTLS"; fail=1
fi

check "five peers -> five stanzas"               '{"vault_cluster_members": ["v1","v2","v3","v4","v5"], "vault_cluster_leader_addr": ""}' 5

exit "$fail"
