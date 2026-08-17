#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-root-owned-posture.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #38 — the vault process must own NOTHING
#   that defines its posture. Parses the config/TLS deploy tasks (PyYAML) and
#   asserts EVERY copy/template of a posture file, and the TLS directory, sets
#   owner: root. The vault-owned data/log dirs are intentionally NOT checked.
# Usage: bash tests/assert-root-owned-posture.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, yaml
root = sys.argv[1]
POSTURE = ('vault_config_file', 'vault_env_file',
           'vault_tls_cert_file', 'vault_tls_key_file', 'vault_tls_ca_file')
fail = []


def modules(tasks):
    """Yield every copy/template module dict, recursing block/rescue/always."""
    for t in tasks or []:
        if not isinstance(t, dict):
            continue
        for m in ('copy', 'template',
                  'ansible.builtin.copy', 'ansible.builtin.template'):
            if isinstance(t.get(m), dict):
                yield t[m]
        for k in ('block', 'rescue', 'always'):
            if k in t:
                yield from modules(t[k])


# 1. Every copy/template writing a posture dest must be owner: root.
checked = 0
for rel in ('tasks/configure.yml', 'tasks/tls.yml'):
    tasks = yaml.safe_load(open(os.path.join(root, rel)))
    for mod in modules(tasks):
        dest = str(mod.get('dest', ''))
        if any(v in dest for v in POSTURE):
            checked += 1
            if mod.get('owner') != 'root':
                fail.append(f"{rel}: dest {dest} owner={mod.get('owner')!r} != root")
# 2 config (hcl+env) + 6 TLS (cert/key/ca x file-branch + pki-branch) = 8.
# This count is a deliberate tripwire: a legitimate topology change (dropping
# vault_pki, adding a posture file) will fail here — bump the constant ONLY after
# confirming the new/removed deploy is intentional and correctly root-owned.
if checked != 8:
    fail.append(f"posture-file deploy count = {checked}, expected 8 (block missed/renamed?)")

# 2. The vault_tls_dir loop entry in system.yml must be owner: root.
found = False
for t in yaml.safe_load(open(os.path.join(root, 'tasks/system.yml'))) or []:
    if not isinstance(t, dict):
        continue
    if (t.get('file') or t.get('ansible.builtin.file')) and isinstance(t.get('loop'), list):
        for item in t['loop']:
            if isinstance(item, dict) and 'vault_tls_dir' in str(item.get('path', '')):
                found = True
                if item.get('owner') != 'root':
                    fail.append(f"system.yml tls_dir owner={item.get('owner')!r} != root")
if not found:
    fail.append("system.yml: vault_tls_dir loop entry not found")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - all {checked} posture-file deploys + tls_dir set owner: root")
PY
