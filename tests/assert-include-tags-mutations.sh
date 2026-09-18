#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-include-tags-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for tests/assert-include-tags-apply.sh (#28) — proves that
#   guard can FAIL, and for the right reason.
#
#   The guard rejects the pre-#28 tree, which proves it catches the shape that
#   existed. That says nothing about the shapes a future edit could introduce:
#   an apply: that exists but does NOT mirror (the subtle one — the include is
#   selectable by a tag that never reaches its tasks), a single include quietly
#   reverted to the bare-string form, or an include that loses its tags: and so
#   becomes unreachable by any tag-scoped run. All are mutated here.
#
#   SURVIVE matters equally. The guard compares tag SETS, so reordering a tag
#   list is a refactor and must be accepted; YAML's scalar form for a
#   single-item tags: is valid and must be accepted; and adding a new,
#   correctly-formed include must not trip it.
# Usage: bash tests/assert-include-tags-mutations.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import os, shutil, subprocess, sys, tempfile
import yaml

root = sys.argv[1]
GUARD = 'tests/assert-include-tags-apply.sh'
MAIN = 'tasks/main.yml'

guard_src = open(os.path.join(root, GUARD)).read()
main_src = open(os.path.join(root, MAIN)).read()

STIG_OK = """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags:
        - vault
        - stig
  tags:
    - vault
    - stig"""
if STIG_OK not in main_src:
    print(f"FAIL - anchor not found in {MAIN}; harness is stale")
    sys.exit(1)


def run(new_main):
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, 'tasks'))
        os.makedirs(os.path.join(tmp, 'tests'))
        shutil.copy(os.path.join(root, GUARD), os.path.join(tmp, GUARD))
        open(os.path.join(tmp, MAIN), 'w').write(new_main)
        return subprocess.run(['bash', os.path.join(tmp, GUARD)],
                              capture_output=True, text=True)


KILL = [
    ("revert one include to the bare-string form (the pre-#28 shape)",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks: stig.yml
  tags:
    - vault
    - stig"""),
     "bare-string form"),

    ("delete one apply: block, keeping the mapping form",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
  tags:
    - vault
    - stig"""),
     "no `apply:` block"),

    # The subtle one: apply exists, so a presence-only check passes, but `vault`
    # never reaches stig.yml's tasks -- `--tags vault` silently skips the phase.
    ("apply: present but NOT mirroring (drops vault)",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags:
        - stig
  tags:
    - vault
    - stig"""),
     "do not mirror"),

    ("apply: mirrors a tag the include does NOT carry",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags:
        - vault
        - stig
        - hardening
  tags:
    - vault
    - stig"""),
     "do not mirror"),

    ("include loses its tags: entirely (unreachable by any tag)",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags:
        - vault
        - stig"""),
     "no `tags:`"),

    ("no includes at all (vacuous pass)",
     lambda s: "---\n- name: nothing\n  ansible.builtin.debug: {msg: x}\n",
     "would pass vacuously"),
]

SURVIVE = [
    ("tag order differs between tags: and apply: (sets, not sequences)",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags:
        - stig
        - vault
  tags:
    - vault
    - stig""")),

    ("a new, correctly-formed include is added",
     lambda s: s + """
- name: Include an extra phase
  ansible.builtin.include_tasks:
    file: extra.yml
    apply:
      tags:
        - vault
        - extra
  tags:
    - vault
    - extra
"""),

    ("YAML scalar form for a single-item tags:/apply:",
     lambda s: s.replace(STIG_OK, """- name: Include STIG hardening tasks
  ansible.builtin.include_tasks:
    file: stig.yml
    apply:
      tags: stig
  tags: stig""")),
]

bad = []
for label, fm, expect in KILL:
    new_main = fm(main_src)
    if new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    try:
        yaml.safe_load(new_main)
    except Exception as e:
        bad.append(f"MUTATION IS NOT WHAT IT CLAIMS: {label} -- does not parse: {e}")
        continue
    p = run(new_main)
    if p.returncode == 0:
        bad.append(f"SURVIVED (guard is blind): {label}")
    elif expect not in p.stdout:
        first = p.stdout.strip().splitlines()
        bad.append(f"WRONG REASON: {label} -- expected {expect!r}; got: {first[:1]}")

for label, fm in SURVIVE:
    new_main = fm(main_src)
    if new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(new_main)
    if p.returncode != 0:
        first = p.stdout.strip().splitlines()
        bad.append(f"OVER-FITTED (rejects a valid construct): {label} -- "
                   f"{first[0] if first else '(no output)'}")

if run(main_src).returncode != 0:
    bad.append("the UNMUTATED tree does not pass the guard; every result above is meaningless")

if bad:
    for x in bad:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - guard killed all {len(KILL)} mutations with the right message, and "
      f"accepted all {len(SURVIVE)} valid constructs")
PY
