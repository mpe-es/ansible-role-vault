#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-facts-guard-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for tests/assert-facts-via-ansible-facts.sh (#78) — proves
#   that guard can FAIL, and for the right reason.
#
#   The guard demonstrably rejects the pre-#78 tree, which proves it catches the
#   sites that existed. That says nothing about the two failure modes that
#   actually matter going forward:
#     1. a NEWLY introduced fact the migration never touched (ansible_kernel),
#        which a denylist-shaped guard would wave through, and
#     2. an ALLOW list widened until it no longer guards anything — the same
#        "fix by disabling the control" shape called out in #83.
#   Both are mutated here.
#
#   SURVIVE matters as much: a guard that flags prose could not document what it
#   forbids, and one that flags `ansible_user` would block legitimate connection
#   variables. Over-fitting is its own failure.
# Usage: bash tests/assert-facts-guard-mutations.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import os, shutil, subprocess, sys, tempfile

root = sys.argv[1]
GUARD = 'tests/assert-facts-via-ansible-facts.sh'
DEF = 'defaults/main.yml'

guard_src = open(os.path.join(root, GUARD)).read()
def_src = open(os.path.join(root, DEF)).read()

CLEAN = "vault_api_addr: \"https://{{ ansible_facts['fqdn'] }}:{{ vault_listener_port }}\""
if CLEAN not in def_src:
    print(f"FAIL - anchor not found in {DEF}; harness is stale")
    sys.exit(1)


def run(new_def, new_guard):
    with tempfile.TemporaryDirectory() as tmp:
        for d in ('defaults', 'tests', 'tasks', 'vars', 'meta', 'handlers'):
            os.makedirs(os.path.join(tmp, d), exist_ok=True)
        # Copy the real tree so the guard has something representative to scan.
        for d in ('tasks', 'vars', 'meta', 'handlers'):
            src = os.path.join(root, d)
            if os.path.isdir(src):
                shutil.rmtree(os.path.join(tmp, d), ignore_errors=True)
                shutil.copytree(src, os.path.join(tmp, d))
        open(os.path.join(tmp, DEF), 'w').write(new_def)
        open(os.path.join(tmp, GUARD), 'w').write(new_guard)
        return subprocess.run(['bash', os.path.join(tmp, GUARD)],
                              capture_output=True, text=True)


# (label, defaults-transform, guard-transform, expected failure text)
KILL = [
    ("reintroduce ansible_fqdn (the original defect)",
     lambda s: s.replace(CLEAN,
         'vault_api_addr: "https://{{ ansible_fqdn }}:{{ vault_listener_port }}"'),
     None, "`ansible_fqdn` read as a top-level variable"),

    ("introduce a NEW fact the migration never touched (deny-by-default)",
     lambda s: s + '\nvault_probe_kernel: "{{ ansible_kernel }}"\n',
     None, "`ansible_kernel` read as a top-level variable"),

    ("a fact inside a nested structure, not a bare scalar",
     lambda s: s + '\nvault_probe_nested:\n  a:\n    - "{{ ansible_os_family }}"\n',
     None, "`ansible_os_family` read as a top-level variable"),

    ("widen ALLOW until it no longer guards (add 'fqdn')",
     lambda s: s.replace(CLEAN,
         'vault_api_addr: "https://{{ ansible_fqdn }}:{{ vault_listener_port }}"'),
     lambda g: g.replace("    'facts',", "    'facts', 'fqdn',"),
     "ALLOW contains names that ARE facts"),

    ("guard scans nothing at all (vacuous pass)",
     None,
     lambda g: g.replace("SCAN_YAML = ['tasks', 'defaults', 'vars', 'meta', 'handlers', 'molecule']",
                         "SCAN_YAML = []").replace("SCAN_RAW = ['templates']", "SCAN_RAW = []"),
     "scanned no files at all"),
]

# Behaviour-preserving. The guard must ACCEPT all of these.
SURVIVE = [
    ("prose in a comment naming the forbidden form",
     lambda s: s + "\n# ansible_fqdn is what this migration removed (see #78)\n", None),
    ("legitimate connection variables",
     lambda s: s + '\nvault_probe_conn: "{{ ansible_user }}-{{ ansible_python_interpreter }}"\n', None),
    ("a rescue magic variable",
     lambda s: s + '\nvault_probe_magic: "{{ ansible_failed_task }}"\n', None),
    ("the correct ansible_facts form, dotted and bracketed",
     lambda s: s + '\nvault_probe_ok: "{{ ansible_facts[\'kernel\'] }}"\n', None),
]

bad = []
for label, fd, fg, expect in KILL:
    nd = fd(def_src) if fd else def_src
    ng = fg(guard_src) if fg else guard_src
    if nd == def_src and ng == guard_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(nd, ng)
    if p.returncode == 0:
        bad.append(f"SURVIVED (guard is blind): {label}")
    elif expect not in p.stdout:
        first = p.stdout.strip().splitlines()
        bad.append(f"WRONG REASON: {label} -- expected {expect!r}; got: {first[:1]}")

for label, fd, fg in SURVIVE:
    nd = fd(def_src) if fd else def_src
    ng = fg(guard_src) if fg else guard_src
    if nd == def_src and ng == guard_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(nd, ng)
    if p.returncode != 0:
        first = p.stdout.strip().splitlines()
        bad.append(f"OVER-FITTED (rejects a valid construct): {label} -- "
                   f"{first[0] if first else '(no output)'}")

if run(def_src, guard_src).returncode != 0:
    bad.append("the UNMUTATED tree does not pass the guard; every result above is meaningless")

if bad:
    for x in bad:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - guard killed all {len(KILL)} mutations with the right message, and "
      f"accepted all {len(SURVIVE)} valid constructs")
PY
