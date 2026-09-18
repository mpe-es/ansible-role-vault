#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-parent-dir-and-seuser-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for the two guards added after the 2026-09-18 live
#   converge — proves assert-vault-root-dir-managed.sh and
#   assert-restorecon-forces-seuser.sh can actually FAIL, and for the right
#   reason.
#
#   Both defects they lock existed precisely because a check reported success
#   while the thing it named was untrue. Shipping guards for them without
#   mutating those guards would repeat the mistake one level up.
#
#   Two suites:
#     KILL     — the guard must reject the mutation AND say why. Each case
#                carries the text its failure must contain, so an unrelated
#                complaint cannot be miscounted as a kill.
#     SURVIVE  — behaviour-preserving refactors the guard must ACCEPT.
#                A guard that rejects `restorecon -R -F -v` because it only
#                recognises one spelling is over-fitted, not strict.
#
#   Families covered deliberately, because bounds come in families (#77 r4):
#     - the parent's traversability is TWO halves (group owner, group-execute
#       bit); each is mutated alone, since either alone still reproduces the
#       outage.
#     - the ancestry premise is mutated from BOTH ends: move the child out,
#       and move the parent away.
#     - every restorecon flag is dropped individually, not just -F.
# Usage: bash tests/assert-parent-dir-and-seuser-mutations.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import os, shutil, subprocess, sys, tempfile
import yaml

root = sys.argv[1]
GUARD_DIR = 'tests/assert-vault-root-dir-managed.sh'
GUARD_SEL = 'tests/assert-restorecon-forces-seuser.sh'
SYSTEM, VARS = 'tasks/system.yml', 'vars/main.yml'

sys_src = open(os.path.join(root, SYSTEM)).read()
var_src = open(os.path.join(root, VARS)).read()

PARENT_ENTRY = ('    - path: "{{ vault_root_dir }}"\n'
                '      owner: root\n'
                '      group: "{{ vault_group }}"\n'
                '      mode: "{{ vault_root_dir_mode }}"\n')
DATA_ENTRY = ('    - path: "{{ vault_data_dir }}"\n'
              '      owner: "{{ vault_user }}"\n')
RESTORECON = "restorecon -RFv {{ item.path"

for anchor, src, where in ((PARENT_ENTRY, sys_src, SYSTEM),
                           (DATA_ENTRY, sys_src, SYSTEM),
                           (RESTORECON, sys_src, SYSTEM),
                           ("vault_root_dir: /opt/vault\n", var_src, VARS),
                           ("vault_root_dir_mode: '0750'\n", var_src, VARS)):
    if anchor not in src:
        print(f"FAIL - anchor not found in {where}: {anchor!r}; harness is stale")
        sys.exit(1)


def sub(old, new):
    def f(s):
        return s.replace(old, new, 1)
    return f


def run(guard, new_sys, new_var):
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, 'tasks'))
        os.makedirs(os.path.join(tmp, 'vars'))
        os.makedirs(os.path.join(tmp, 'tests'))
        shutil.copy(os.path.join(root, guard), os.path.join(tmp, guard))
        open(os.path.join(tmp, SYSTEM), 'w').write(new_sys)
        open(os.path.join(tmp, VARS), 'w').write(new_var)
        return subprocess.run(['bash', os.path.join(tmp, guard)],
                              capture_output=True, text=True)


# (label, guard, system-transform, vars-transform, expected failure text)
KILL = [
    # --- defect A: the parent directory --------------------------------------
    ("delete the parent entry from the directory loop", GUARD_DIR,
     sub(PARENT_ENTRY, ''), None, "no entry for vault_root_dir"),
    ("delete vault_root_dir from vars", GUARD_DIR,
     None, sub("vault_root_dir: /opt/vault\n", ''), "does not define vault_root_dir"),

    # the traversability family: each half alone still reproduces the outage
    ("parent group root:root instead of root:vault", GUARD_DIR,
     sub('      group: "{{ vault_group }}"\n      mode: "{{ vault_root_dir_mode }}"',
         '      group: root\n      mode: "{{ vault_root_dir_mode }}"'),
     None, "vault reaches its data dir by GROUP traversal"),
    ("parent mode 0700 (no group execute)", GUARD_DIR,
     None, sub("vault_root_dir_mode: '0750'", "vault_root_dir_mode: '0700'"),
     "does not grant GROUP execute"),
    ("parent mode 0640 (group read, no traverse)", GUARD_DIR,
     None, sub("vault_root_dir_mode: '0750'", "vault_root_dir_mode: '0640'"),
     "does not grant GROUP execute"),

    # ordering
    ("parent created AFTER its data child", GUARD_DIR,
     lambda s: s.replace(PARENT_ENTRY, '', 1).replace(
         DATA_ENTRY, DATA_ENTRY + PARENT_ENTRY, 1),
     None, "posture-correct before its children"),

    # the ancestry premise, broken from BOTH ends
    ("repoint the child outside the parent", GUARD_DIR,
     None, sub("vault_data_dir: /opt/vault/data", "vault_data_dir: /var/lib/vault/data"),
     "is not inside vault_root_dir"),
    ("repoint the parent away from its children", GUARD_DIR,
     None, sub("vault_root_dir: /opt/vault\n", "vault_root_dir: /opt/vault-backup\n"),
     "is not inside vault_root_dir"),

    # --- defect B: the seuser ------------------------------------------------
    ("revert restorecon to -Rv (the shipped defect)", GUARD_SEL,
     sub(RESTORECON, "restorecon -Rv {{ item.path"), None, "does not pass -F"),
    ("drop -R from restorecon", GUARD_SEL,
     sub(RESTORECON, "restorecon -Fv {{ item.path"), None, "lost -R"),
    ("drop -v, so changed_when can never fire", GUARD_SEL,
     sub(RESTORECON, "restorecon -RF {{ item.path"), None, "lost -v"),
    ("delete the restorecon task's command entirely", GUARD_SEL,
     sub(RESTORECON, "true {{ item.path"), None, "no restorecon command found"),
    ("strip every seuser declaration (premise gone)", GUARD_SEL,
     None, lambda s: s.replace("    seuser: system_u\n", ""),
     "declares no seuser"),
]

# Behaviour-preserving. The guards must ACCEPT all of these.
SURVIVE = [
    ("parent hoisted to the very first loop entry", GUARD_DIR,
     lambda s: s.replace(PARENT_ENTRY, '', 1).replace(
         '  loop:\n', '  loop:\n' + PARENT_ENTRY, 1), None),
    ("parent mode 0755 (still group-traversable)", GUARD_DIR,
     None, sub("vault_root_dir_mode: '0750'", "vault_root_dir_mode: '0755'")),
    ("parent mode written as a literal instead of a variable", GUARD_DIR,
     sub('      mode: "{{ vault_root_dir_mode }}"\n    - path: "{{ vault_data_dir }}"',
         "      mode: '0750'\n    - path: \"{{ vault_data_dir }}\""), None),
    ("restorecon flags split into separate tokens", GUARD_SEL,
     sub(RESTORECON, "restorecon -R -F -v {{ item.path"), None),
    ("restorecon flags reordered", GUARD_SEL,
     sub(RESTORECON, "restorecon -vFR {{ item.path"), None),
]

bad = []


def parses(new_sys, new_var):
    for label, src in ((SYSTEM, new_sys), (VARS, new_var)):
        try:
            yaml.safe_load(src)
        except Exception as e:
            return f"{label} no longer parses: {e}"
    return None


for label, guard, fs, fv, expect in KILL:
    new_sys = fs(sys_src) if fs else sys_src
    new_var = fv(var_src) if fv else var_src
    if new_sys == sys_src and new_var == var_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    broken = parses(new_sys, new_var)
    if broken:
        bad.append(f"MUTATION IS NOT WHAT IT CLAIMS: {label} -- {broken}")
        continue
    p = run(guard, new_sys, new_var)
    if p.returncode == 0:
        bad.append(f"SURVIVED (guard is blind): {label}")
    elif expect not in p.stdout:
        first = p.stdout.strip().splitlines()
        bad.append(f"WRONG REASON: {label} -- failure did not mention {expect!r}; "
                   f"got: {first[:1]}")

for label, guard, fs, fv in SURVIVE:
    new_sys = fs(sys_src) if fs else sys_src
    new_var = fv(var_src) if fv else var_src
    if new_sys == sys_src and new_var == var_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(guard, new_sys, new_var)
    if p.returncode != 0:
        first = p.stdout.strip().splitlines()
        bad.append(f"OVER-FITTED (rejects a valid refactor): {label} -- "
                   f"{first[0] if first else '(no output)'}")

for guard in (GUARD_DIR, GUARD_SEL):
    if run(guard, sys_src, var_src).returncode != 0:
        bad.append(f"the UNMUTATED tree does not pass {guard}; every result "
                   f"above is meaningless")

if bad:
    for x in bad:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - guards killed all {len(KILL)} mutations with the right message, and "
      f"accepted all {len(SURVIVE)} behaviour-preserving refactors")
PY
