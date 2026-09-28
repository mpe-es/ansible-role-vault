#!/usr/bin/env bash
###############################################################################
# Filename: tests/license-state-table-test.sh
# Role: ansible-role-vault
# Summary: Truth table for __vault_license_desired_state (#42) -- the licence is
#   a STATE (present / absent / unmanaged), and the operator's NARROW reading of
#   vault_license_manage_state must hold: the flag withholds the REMOVAL only,
#   never a deploy. No container required.
# Usage: bash tests/license-state-table-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS. The review that produced this variable found that the licence
# had no absent state at all: clearing vault_license_content left a withdrawn
# entitlement on disk AND still referenced by license_path, so an Enterprise node
# kept running on a licence the desired state had retired, and the role reported
# success. The fix collapsed two hand-written complementary conditions into one
# derived value, because two complements drift and the gap between them is
# invisible -- exactly how the #41 diff:false guard silently stopped binding.
#
# This test loads vars/main.yml and evaluates the REAL expression. It does NOT
# transcribe it: a copied expression is a verification that cannot fail, the
# same class as the ANSIBLE_INJECT_FACT_VARS typo (#78) and the failed_when:false
# port gate (#36).
#
# No molecule scenario covers this. Every scenario runs ONE licence posture, so
# the transitions are unreachable from the container suite; molecule/hsm asserts
# the on-disk result of a single state, not the mapping that chose it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/table.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    cases:
      # edition                          content         manage  expected
      - {ed: "vault-enterprise-fips1403",     c: "BLOB", m: true,  want: "present"}
      # THE NARROW READING: manage_state=false must NOT withhold a deploy.
      - {ed: "vault-enterprise-fips1403",     c: "BLOB", m: false, want: "present"}
      - {ed: "vault-enterprise-fips1403",     c: "",     m: true,  want: "absent"}
      - {ed: "vault-enterprise-fips1403",     c: "",     m: false, want: "unmanaged"}
      # whitespace-only is not a licence (matches the #41 PIN trim idiom)
      - {ed: "vault-enterprise-fips1403",     c: "   ",  m: true,  want: "absent"}
      # a bare 'vault_license_content:' key is YAML null, not ''
      - {ed: "vault-enterprise-fips1403",     c: null,   m: true,  want: "absent"}
      - {ed: "vault-enterprise-hsm-fips1403", c: "BLOB", m: true,  want: "present"}
      # Community renders no license_path: keeping the file is pure exposure
      - {ed: "vault",                         c: "BLOB", m: true,  want: "absent"}
      - {ed: "vault",                         c: "BLOB", m: false, want: "unmanaged"}
      - {ed: "vault",                         c: "",     m: true,  want: "absent"}
  tasks:
    - name: Load the role's REAL vars file (never a transcription)
      ansible.builtin.include_vars:
        file: "$ROOT/vars/main.yml"

    - name: Evaluate every case
      ansible.builtin.set_fact:
        results: >-
          {{ (results | default([])) + [{
               'case': item.ed ~ ' content=' ~ (item.c | string | default('~')) ~ ' manage=' ~ item.m,
               'got': lookup('vars', '__vault_license_desired_state'),
               'want': item.want,
               'ok': lookup('vars', '__vault_license_desired_state') == item.want
             }] }}
      vars:
        vault_edition: "{{ item.ed }}"
        vault_license_content: "{{ item.c }}"
        vault_license_manage_state: "{{ item.m }}"
      loop: "{{ cases }}"
      loop_control: {label: "{{ item.ed }} / {{ item.m }}"}

    - name: Every case must match
      ansible.builtin.assert:
        that: [results | rejectattr('ok') | list | length == 0]
        success_msg: "ALL {{ results | length }} CASES MATCH"
        fail_msg: "MISMATCH: {{ results | rejectattr('ok') | list }}"
EOF

out="$(ansible-playbook "$WORK/table.yml" 2>&1)" || { echo "$out" | grep -E 'MISMATCH|fatal' | head -4; echo "FAIL: __vault_license_desired_state truth table"; exit 1; }
n="$(echo "$out" | grep -oE 'ALL [0-9]+ CASES MATCH' | grep -oE '[0-9]+')"
echo "ok: __vault_license_desired_state truth table, ${n} cases (narrow manage_state reading holds)"
