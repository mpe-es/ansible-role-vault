#!/usr/bin/env bash
###############################################################################
# Filename: tests/render-hsm-pin-test.sh
# Role: ansible-role-vault
# Summary: Local render check for issue #41 — the HSM PIN lands in vault.env
#   (double-quoted) and NEVER in vault.hcl. No container/HSM required.
# Usage: bash tests/render-hsm-pin-test.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SENTINEL='S3NTINEL-hsm-pin-DO-NOT-SHIP'

cat > "$WORK/render.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_hsm_enabled: true
    vault_hsm_pin: "$SENTINEL"
    vault_hsm_lib_path: /usr/lib64/pkcs11/lib.so
    vault_hsm_key_label: vault-key
    vault_hsm_hmac_key_label: vault-hmac
    vault_hsm_hmac_mechanism: "0x0251"
    vault_hsm_generate_key: false
    vault_hsm_max_parallel: 1
    vault_hsm_slot: ""
    vault_hsm_token_label: ""
    vault_hsm_mechanism: ""
    vault_listener_port: 8200
    vault_tls_cert_file: /opt/vault/tls/tls.crt
    vault_tls_key_file: /opt/vault/tls/tls.key
    vault_tls_ca_file: /opt/vault/tls/ca.crt
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
    vault_raft_node_id: t
    vault_api_addr: https://127.0.0.1:8200
    vault_cluster_addr: https://127.0.0.1:8201
    vault_cluster_leader_addr: ""
    vault_edition: "vault"
    vault_data_dir: /opt/vault/data
  tasks:
    - template: { src: "$ROOT/templates/vault.hcl.j2", dest: "$WORK/vault.hcl" }
    - template: { src: "$ROOT/templates/vault.env.j2", dest: "$WORK/vault.env" }
EOF
ansible-playbook "$WORK/render.yml" >/dev/null

fail=0
if grep -q "$SENTINEL" "$WORK/vault.hcl"; then echo "FAIL: PIN present in vault.hcl"; fail=1; else echo "ok: no PIN in vault.hcl"; fi
if grep -q "^VAULT_HSM_PIN=\"$SENTINEL\"$" "$WORK/vault.env"; then echo "ok: double-quoted PIN in vault.env"; else echo "FAIL: PIN not in vault.env (double-quoted)"; fail=1; fi
exit "$fail"
