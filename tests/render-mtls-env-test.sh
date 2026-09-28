#!/usr/bin/env bash
###############################################################################
# Filename: tests/render-mtls-env-test.sh
# Role: ansible-role-vault
# Summary: The three templates that carry a Vault client identity render it when
#   the listener requires one, and never when it does not (#44).
# Usage: bash tests/render-mtls-env-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# assert-vault-calls-carry-client-certs.sh proves the client variables are PRESENT
# in each template. It cannot prove the CONDITION around them is right, and the
# condition is where this went wrong twice:
#   1. `{% if x | default(false) %}` -- bare Jinja truthiness, so the STRING "false"
#      rendered client credentials onto a non-mTLS listener.
#   2. `... | lower == 'true'` -- which then read `1` and `"yes"` as FALSE, although
#      meta/argument_specs.yml types the variable `bool` and every task-side
#      `| bool` reads them as TRUE. mTLS was therefore enabled everywhere EXCEPT
#      the rendered files.
#   3. a truthy set of true/yes/on/1/t/y -- a SUPERSET of Ansible's. MEASURED on
#      ansible-core 2.21.4: `"t" | bool` and `"y" | bool` are FALSE (with a
#      deprecation warning), so those two forms disagreed in the other direction.
# All three forms are in the table below so none can come back. The rule is that the
# template must agree with `| bool` exactly -- not a subset, not a superset.
#
# `| bool` CANNOT BE USED IN THESE TEMPLATES. tests/render-hsm-pin-test.sh renders
# vault.hcl.j2 under plain Jinja with no Ansible scope, so only Jinja builtins are
# available -- hence `| string | lower` against the truthy set. Measured against
# Ansible's own set on 18 forms.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0

render () {  # $1=template basename  $2=json extra-vars -> renders to $WORK/out
  cat > "$WORK/r.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_listener_port: 8200
    vault_listener_address: 0.0.0.0
    vault_tls_ca_file: /opt/vault/tls/ca.crt
    vault_tls_cert_file: /opt/vault/tls/tls.crt
    vault_tls_key_file: /opt/vault/tls/tls.key
    vault_tls_min_version: tls12
    vault_tls_max_version: tls13
    vault_tls_cipher_suites: []
    vault_tls_disable_client_certs: false
    vault_data_dir: /opt/vault/data
    vault_config_dir: /etc/vault.d
    vault_log_dir: /var/log/vault
    vault_raft_node_id: t
    vault_api_addr: https://127.0.0.1:8200
    vault_cluster_addr: https://127.0.0.1:8201
    vault_ui_enabled: true
    vault_disable_mlock: false
    vault_disable_performance_standby: true
    vault_log_level: info
    vault_hsm_enabled: false
    vault_hsm_pin: ""
    vault_edition: vault
    vault_user: vault
    vault_group: vault
    vault_binary: /usr/bin/vault
    vault_service_name: vault
    vault_cluster_members: [v1.mpe.mil]
    vault_cluster_leader_addr: ""
    vault_unseal_wait_timeout: 60
  tasks:
    - ansible.builtin.template:
        src: $ROOT/templates/$1
        dest: $WORK/out
        mode: '0600'
EOF
  rm -f "$WORK/out"
  ansible-playbook "$WORK/r.yml" -e "$2" >"$WORK/log" 2>&1
}

# The exact field names per template. Anchored, case-sensitive, and never a bare
# "client_cert".
pattern_for () {
  case "$1" in
    vault.hcl.j2) echo 'leader_client_cert_file|leader_client_key_file' ;;
    *)            echo 'VAULT_CLIENT_CERT|VAULT_CLIENT_KEY' ;;
  esac
}

# $1=template $2=the value written into vault_tls_require_client_cert (JSON)
# $3=yes|no -- whether a client identity must appear  $4=label
check () {
  local tpl="$1" val="$2" want="$3" label="$4" pat
  pat="$(pattern_for "$tpl")"
  if ! render "$tpl" "{\"vault_tls_require_client_cert\": $val}"; then
    echo "FAIL: $tpl $label -- render failed"; sed -n '/fatal/,+3p' "$WORK/log" | head -4; fail=1; return
  fi
  local n; n="$(grep -cE "$pat" "$WORK/out" || true)"
  if [ "$want" = yes ] && [ "$n" -lt 2 ]; then
    echo "FAIL: $tpl $label -- expected a client cert AND key, found $n line(s)"; fail=1; return
  fi
  if [ "$want" = no ] && [ "$n" -ne 0 ]; then
    echo "FAIL: $tpl $label -- rendered $n client line(s) on a non-mTLS listener"; fail=1; return
  fi
  echo "ok: $tpl $label -> $( [ "$want" = yes ] && echo 'client identity present' || echo 'no client identity' )"
}

# Ansible's truthy set, MEASURED on the pinned core: true / yes / on / 1,
# case-insensitive. "t" and "y" are FALSE there and must be FALSE here.
for tpl in vault.hcl.j2 vault-unseal.service.j2 vault.env.j2; do
  check "$tpl" 'true'    yes 'bool true'
  check "$tpl" '"true"'  yes 'string "true"'
  check "$tpl" '"True"'  yes 'string "True"'
  check "$tpl" '"yes"'   yes 'string "yes"   (the == comparison read this FALSE)'
  check "$tpl" '1'       yes 'integer 1      (the == comparison read this FALSE)'
  check "$tpl" '"on"'    yes 'string "on"'
  check "$tpl" 'false'   no  'bool false'
  check "$tpl" '"false"' no  'string "false" (bare truthiness rendered this)'
  check "$tpl" '"no"'    no  'string "no"'
  check "$tpl" '0'       no  'integer 0'
  check "$tpl" '"t"'     no  'string "t"     (a superset read this TRUE; | bool says false)'
  check "$tpl" '"y"'     no  'string "y"     (a superset read this TRUE; | bool says false)'
done

# The LISTENER value, not just the retry_join fields. `| lower` on the string "yes"
# rendered `tls_require_and_verify_client_cert = yes`, which is not an HCL boolean
# literal -- an accepted input producing invalid configuration.
listener () {  # $1=json value -> the rendered listener line's value
  render vault.hcl.j2 "{\"vault_tls_require_client_cert\": $1}" || { echo RENDER_FAILED; return; }
  sed -n 's/^  tls_require_and_verify_client_cert = \(.*\)$/\1/p' "$WORK/out"
}
for pair in 'true:true' '"true":true' '"yes":true' '1:true' '"on":true' \
            'false:false' '"false":false' '"no":false' '0:false' '"t":false' '"y":false'; do
  val="${pair%:*}"; want="${pair##*:}"
  got="$(listener "$val")"
  if [ "$got" = "$want" ]; then
    echo "ok: listener value for $val -> $got"
  else
    echo "FAIL: listener value for $val -> '$got', expected '$want' (must be an HCL boolean literal)"
    fail=1
  fi
done

# Non-vacuity: the grep must be capable of matching at all, or every "no" case above
# passes for the wrong reason.
# Non-vacuity, PER TEMPLATE: each pattern must be capable of matching in that
# template, or its negative cases pass for the wrong reason. The first version of this
# test checked only vault.env.j2 and so never noticed that its vault.hcl.j2 pattern was
# matching the listener stanza instead of the retry_join stanza.
for tpl in vault.hcl.j2 vault-unseal.service.j2 vault.env.j2; do
  render "$tpl" '{"vault_tls_require_client_cert": true}'
  if ! grep -qE "$(pattern_for "$tpl")" "$WORK/out"; then
    echo "FAIL: $tpl -- its pattern never matches, so its negative cases prove nothing"
    fail=1
  else
    echo "ok: $tpl pattern is non-vacuous"
  fi
done

exit "$fail"
