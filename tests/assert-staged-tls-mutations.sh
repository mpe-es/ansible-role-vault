#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-staged-tls-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for issue #77 — proves tests/assert-staged-tls-posture.sh
#   can actually FAIL, and fails for the right reason.
#
#   A guard nobody has mutated is a guard nobody knows works. #36 shipped a
#   port gate that could not fail (failed_when: false made its assert a
#   tautology) and the first two revisions of the staged-TLS guard were
#   defeated the same way: revision 1 passed a `path: "{{ vault_tls_dir }}"` +
#   `state: touch` implementation, revision 2 passed four different relaxations
#   of the vault_tls_dir bound including the always-true expression
#   `vault_tls_dir | dirname is defined`. Both were caught by adversarial
#   review, not by CI. This file is the answer to that.
#
#   Two suites, and BOTH matter:
#     KILL     — each mutation breaks the enforcement in exactly one way and
#                the guard must reject it. A survivor is a blind spot.
#     SURVIVE  — behaviour-preserving refactors the guard must NOT reject.
#                Over-fitting is its own failure: a guard that rejects valid
#                code teaches maintainers to delete it.
#
#   Operates entirely on copies in a temporary directory; the repository is
#   never modified. If an anchor no longer matches, the mutation reports
#   NO-OP and this gate fails — a deliberate tripwire, like the `checked != 8`
#   count in tests/assert-root-owned-posture.sh. Re-anchor only after
#   confirming the refactor is intentional.
# Usage: bash tests/assert-staged-tls-mutations.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import os, re, shutil, subprocess, sys, tempfile

root = sys.argv[1]
GUARD = 'tests/assert-staged-tls-posture.sh'
SYSTEM = 'tasks/system.yml'
MAIN = 'tasks/main.yml'

sys_src = open(os.path.join(root, SYSTEM)).read()
main_src = open(os.path.join(root, MAIN)).read()

ENF = '- name: Enforce ownership on operator-staged TLS material'
REP = '- name: Report staged TLS material the role will not converge'
SEL = '\n###############################################################################\n# SELinux File Contexts'
INS = '- name: Inspect operator-staged TLS material'

DIRNAME = '    - item.item | dirname == vault_tls_dir'
ISLNK = '    - not (item.stat.islnk | default(false))'
ISREG = '    - item.stat.isreg | default(false)'
EXISTS = '    - item.stat.exists | default(false)\n'
MANAGE = '    - not (vault_manage_tls | bool)'

SECOND_TASK = '''
- name: Second enforcement sneaking the trio to the vault account
  ansible.builtin.file:
    path: "{{ item }}"
    state: file
    owner: vault
    group: vault
    mode: '0600'
  loop:
    - "{{ vault_tls_cert_file }}"
    - "{{ vault_tls_key_file }}"
    - "{{ vault_tls_ca_file }}"
'''


def drop_region(s):
    head, rest = s.split(INS, 1)
    _, tail = rest.split(SEL, 1)
    return head + SEL.lstrip('\n') + tail


def drop_task(s, start, end):
    i, j = s.index(start), s.index(end)
    return s[:i] + s[j:]


# (label, system.yml transform, main.yml transform)
KILL = [
    ("delete the whole enforcement region", drop_region, None),
    ("delete only the file-module enforcer", lambda s: drop_task(s, ENF, REP), None),
    ("delete the report task (exclusions become silent)",
     lambda s: drop_task(s, REP, SEL.lstrip('\n')), None),
    ("path targets the DIRECTORY, not the loop item",
     lambda s: s.replace('    path: "{{ item.item }}"', '    path: "{{ vault_tls_dir }}"'), None),
    ("state: file -> state: touch (manufactures material)",
     lambda s: s.replace('    state: file\n', '    state: touch\n'), None),
    ("drop follow: false from the file module (default is true)",
     lambda s: s.replace('    state: file\n    follow: false\n', '    state: file\n'), None),
    ("flip the file module to follow: true",
     lambda s: s.replace('    state: file\n    follow: false\n', '    state: file\n    follow: true\n'), None),
    ("drop follow: false from the stat (islnk becomes meaningless)",
     lambda s: s.replace('    follow: false\n    get_checksum: false', '    get_checksum: false'), None),
    ("invert the vault_tls_dir bound (== -> !=)",
     lambda s: s.replace(DIRNAME, '    - item.item | dirname != vault_tls_dir'), None),
    ("weaken vault_tls_dir to a prefix search (path traversal reopens)",
     lambda s: s.replace(DIRNAME, '    - item.item | dirname is search(vault_tls_dir)'), None),
    ("weaken vault_tls_dir to substring containment",
     lambda s: s.replace(DIRNAME, '    - vault_tls_dir in (item.item | dirname)'), None),
    ("weaken vault_tls_dir to a match() prefix test",
     lambda s: s.replace(DIRNAME, '    - item.item | dirname is match(vault_tls_dir)'), None),
    ("replace the vault_tls_dir bound with an always-true expression",
     lambda s: s.replace(DIRNAME, '    - vault_tls_dir | dirname is defined'), None),
    ("drop the vault_tls_dir bound entirely",
     lambda s: s.replace('\n' + DIRNAME, ''), None),
    ("invert the symlink bound (converge ONLY symlinks)",
     lambda s: s.replace(ISLNK, '    - item.stat.islnk | default(false)'), None),
    ("drop the symlink bound entirely",
     lambda s: s.replace('\n' + ISLNK, ''), None),
    ("drop the regular-file bound (a directory aborts the play at Phase 4)",
     lambda s: s.replace('\n' + ISREG, ''), None),
    ("invert the regular-file bound",
     lambda s: s.replace(ISREG, '    - not (item.stat.isreg | default(false))'), None),
    ("invert the existence bound",
     lambda s: s.replace(EXISTS, '    - not (item.stat.exists | default(false))\n'), None),
    ("drop the existence bound", lambda s: s.replace(EXISTS, '', 1), None),
    ("drop the vault_manage_tls guard from the enforcer",
     lambda s: s.replace('\n' + MANAGE + '\n    - item.stat is defined', '\n    - item.stat is defined', 1), None),
    ("invert the vault_manage_tls polarity",
     lambda s: s.replace(MANAGE + '\n    - item.stat is defined',
                         '    - vault_manage_tls | bool\n    - item.stat is defined', 1), None),
    ("narrow the stat loop to 2 of 3 paths",
     lambda s: s.replace('    - "{{ vault_tls_ca_file }}"\n', '', 1), None),
    ("give the vault account ownership (owner: vault)",
     lambda s: s.replace('    owner: root\n', '    owner: vault\n'), None),
    ("hardcode the group instead of vault_group",
     lambda s: s.replace('    group: "{{ vault_group }}"\n', '    group: vault\n'), None),
    ("hardcode the mode instead of vault_tls_file_mode",
     lambda s: s.replace('    mode: "{{ vault_tls_file_mode }}"\n', "    mode: '0640'\n"), None),
    ("add a SECOND file task handing the trio to vault:vault",
     lambda s: s.replace(SEL, SECOND_TASK + SEL, 1), None),
    ("ungate tls.yml in tasks/main.yml (the premise disappears)", None,
     lambda m: m.replace('  ansible.builtin.include_tasks: tls.yml\n'
                         '  when: vault_manage_tls | bool\n',
                         '  ansible.builtin.include_tasks: tls.yml\n', 1)),
]

# Behaviour-preserving. The guard must accept all of these.
SURVIVE = [
    ("drop the optional parens: `not vault_manage_tls | bool`",
     lambda s: s.replace(MANAGE, '    - not vault_manage_tls | bool'), None),
    ("derive path as vault_tls_dir ~ basename (same target, given the bound)",
     lambda s: s.replace('    path: "{{ item.item }}"',
                         '    path: "{{ vault_tls_dir }}/{{ item.item | basename }}"'), None),
    ("extra whitespace around the vault_tls_dir comparison",
     lambda s: s.replace(DIRNAME, '    - item.item   |   dirname   ==   vault_tls_dir'), None),
    ("reorder the when: terms",
     lambda s: s.replace(ISREG + '\n' + ISLNK, ISLNK + '\n' + ISREG), None),
]


def run(new_sys, new_main):
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, 'tasks'))
        os.makedirs(os.path.join(tmp, 'tests'))
        shutil.copy(os.path.join(root, GUARD), os.path.join(tmp, GUARD))
        open(os.path.join(tmp, SYSTEM), 'w').write(new_sys)
        open(os.path.join(tmp, MAIN), 'w').write(new_main)
        return subprocess.run(['bash', os.path.join(tmp, GUARD)],
                              capture_output=True, text=True)


bad = []
for label, fs, fm in KILL:
    new_sys = fs(sys_src) if fs else sys_src
    new_main = fm(main_src) if fm else main_src
    if new_sys == sys_src and new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    if run(new_sys, new_main).returncode == 0:
        bad.append(f"SURVIVED (guard is blind): {label}")

overfit = []
for label, fs, fm in SURVIVE:
    new_sys = fs(sys_src) if fs else sys_src
    new_main = fm(main_src) if fm else main_src
    if new_sys == sys_src and new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(new_sys, new_main)
    if p.returncode != 0:
        first = p.stdout.strip().splitlines()
        overfit.append(f"{label} -> {first[0] if first else '(no output)'}")

# The unmutated tree must pass, or every result above is meaningless.
if run(sys_src, main_src).returncode != 0:
    bad.append("the UNMUTATED tree does not pass the guard; suite is meaningless")

if bad or overfit:
    for x in bad:
        print("FAIL -", x)
    for x in overfit:
        print("FAIL - guard is OVER-FITTED, rejects a valid refactor:", x)
    sys.exit(1)
print(f"ok - guard killed all {len(KILL)} mutations and accepted all "
      f"{len(SURVIVE)} behaviour-preserving refactors")
PY
