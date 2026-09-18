#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-vault-root-dir-managed.sh
# Role: ansible-role-vault
# Summary: Regression lock — the role must assert on the COMMON PARENT of its
#   /opt/vault children, not only on the children themselves.
#
#   Found on live hardware 2026-09-18 (Rocky 9.8, STIG-hardened). STIG mandates
#   `umask 077`. On the DEFAULT path (vault_manage_tls: false) the role's own
#   preflight instructs the operator to stage TLS material at vault_tls_dir, so
#   they run `mkdir -p /opt/vault/tls` — which under that umask creates
#   /opt/vault as 0700 root:root. The role then converged vault_data_dir to
#   vault:vault 0750 and vault_tls_dir to root:vault 0750, both correct, and
#   Vault still could not TRAVERSE the parent to reach either:
#
#     Error initializing storage of type raft: failed to create fsm: failed to
#     open bolt file: error checking raft FSM db file "/opt/vault/data/vault.db":
#     stat /opt/vault/data/vault.db: permission denied
#
#   All 12 preflight gates passed and 78 tasks converged first, so the host was
#   fully mutated — package installed, config written, STIG hardening applied,
#   firewall opened — before it failed. Same class as #77: the role enforced the
#   contents and left the container that holds them unasserted.
#
#   A FRESH install was never affected: ansible.builtin.file propagates owner
#   AND mode to implicitly created parents (measured). The defect requires
#   /opt/vault to pre-exist restrictively, which following the role's own
#   staging instruction on a STIG host reliably produces.
#
#   Locked here:
#     - vault_root_dir is defined, and is a genuine ANCESTOR of both
#       vault_data_dir and vault_tls_dir. Derived from the real values rather
#       than asserted as a literal: if someone repoints vault_data_dir, this
#       guard must fail rather than keep passing about a path nothing uses.
#     - the system.yml directory loop contains an entry for vault_root_dir.
#     - that entry is GROUP-TRAVERSABLE by the vault group: group owner is
#       vault_group and the mode's group digit carries execute. A parent that
#       is root:root 0700, or root:vault 0640, reproduces the outage exactly.
#     - the entry is ordered BEFORE its own children in the loop, so the parent
#       exists at the right posture before anything is created inside it.
#
#   Structural and container-free. Behavioural proof is a live converge on a
#   host where /opt/vault pre-exists as 0700 root:root.
# Usage: bash tests/assert-vault-root-dir-managed.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, yaml, posixpath

root = sys.argv[1]
fail = []

rolevars = yaml.safe_load(open(os.path.join(root, 'vars/main.yml'))) or {}
tasks = yaml.safe_load(open(os.path.join(root, 'tasks/system.yml'))) or []


def dir_loop(ts):
    """The file-module task whose loop declares the role's directories."""
    for t in ts or []:
        if not isinstance(t, dict):
            continue
        args = t.get('ansible.builtin.file') or t.get('file')
        if isinstance(args, dict) and args.get('state') == 'directory' \
           and isinstance(t.get('loop'), list):
            return t, args
        for k in ('block', 'rescue', 'always'):
            if k in t:
                got = dir_loop(t[k])
                if got != (None, None):
                    return got
    return None, None


task, args = dir_loop(tasks)
if task is None:
    print("FAIL - no state:directory file task with a literal loop in tasks/system.yml")
    sys.exit(1)

# --- vault_root_dir exists and is a REAL ancestor of the children ------------
rootdir = rolevars.get('vault_root_dir')
if not rootdir:
    fail.append("vars/main.yml does not define vault_root_dir; the common parent "
                "of the /opt/vault children is unmanaged (live outage 2026-09-18)")
else:
    for child_var in ('vault_data_dir', 'vault_tls_dir'):
        child = rolevars.get(child_var)
        if not child:
            fail.append(f"vars/main.yml does not define {child_var}")
            continue
        # Genuine ancestry, not a string prefix: /opt/vault-backup must NOT
        # count as a child of /opt/vault.
        rel = posixpath.relpath(child, rootdir)
        if rel.startswith('..') or rel == '.':
            fail.append(f"{child_var} ({child}) is not inside vault_root_dir "
                        f"({rootdir}); the guard would otherwise pass about a "
                        f"path the role does not actually use")

# --- the loop manages it -----------------------------------------------------
def names_var(value, var):
    return isinstance(value, str) and var in value

entries = [e for e in task['loop'] if isinstance(e, dict)]
idx = [i for i, e in enumerate(entries) if names_var(e.get('path'), 'vault_root_dir')]

if not idx:
    fail.append("the tasks/system.yml directory loop has no entry for "
                "vault_root_dir; children are enforced but the parent that "
                "holds them is not, so vault cannot traverse to its own data "
                "dir when the parent pre-exists as 0700 root:root")
else:
    entry = entries[idx[0]]

    # Group-traversable by the vault group, asserted on BOTH halves. Either
    # half alone is satisfiable while the outage persists: root:root 0750
    # denies vault, and root:vault 0640 denies vault.
    if not names_var(entry.get('group'), 'vault_group'):
        fail.append(f"vault_root_dir entry group is {entry.get('group')!r}, not "
                    f"vault_group; vault reaches its data dir by GROUP traversal")

    mode = entry.get('mode', '')
    mode_var = mode.strip('{} ').strip() if isinstance(mode, str) else ''
    literal = rolevars.get(mode_var.strip(), mode) if mode_var else mode
    digits = ''.join(ch for ch in str(literal) if ch.isdigit())
    if len(digits) < 3 or int(digits[-2]) & 1 == 0:
        fail.append(f"vault_root_dir mode ({literal!r}) does not grant GROUP "
                    f"execute; without the traverse bit the vault process gets "
                    f"EACCES on stat of everything beneath it")

    # Parent before children, so it is at the right posture before anything is
    # created inside it.
    for i, e in enumerate(entries):
        p = e.get('path')
        if i in idx or not isinstance(p, str):
            continue
        for child_var in ('vault_data_dir', 'vault_tls_dir'):
            if names_var(p, child_var) and i < idx[0]:
                fail.append(f"{child_var} is created at loop position {i}, before "
                            f"vault_root_dir at {idx[0]}; the parent must be "
                            f"posture-correct before its children are created")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print("ok - vault_root_dir defined, a real ancestor of data/tls dirs, managed "
      "in the directory loop, group-traversable by vault_group, ordered before "
      "its children")
PY
