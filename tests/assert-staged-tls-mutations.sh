#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-staged-tls-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for issue #77 — proves tests/assert-staged-tls-posture.sh
#   can actually FAIL, and fails for the RIGHT REASON.
#
#   A guard nobody has mutated is a guard nobody knows works. #36 shipped a port
#   gate that could not fail. Three successive revisions of the staged-TLS guard
#   were each defeated by adversarial review rather than by CI:
#     r1  passed `path: "{{ vault_tls_dir }}"` + `state: touch`,
#     r2  passed four relaxations of the vault_tls_dir bound, including the
#         always-true `vault_tls_dir | dirname is defined`,
#     r3  passed a one-term polarity flip on the STAT task -- a SIBLING of the
#         term r2 had hardened -- which makes every downstream task skip.
#     r4  (codex, the first blind reviewer outside this harness) passed five
#         more: the stat pinned to one variable so every item carried the
#         CERT's metadata, an enforcement writing `{{ item.item }}.bak`, and an
#         always-false term on the enforcer or the stat -- r3 had added that
#         rejection to the REPORTER only. Same family, same miss, third time.
#   That last one is the lesson this file encodes: bounds come in families, and
#   a mutation suite that covers one member of a family proves nothing about the
#   others. Every `when:` in the region is mutated at every site it appears.
#
#   Two suites, both load-bearing:
#     KILL     — the guard must reject the mutation AND say why. Each case
#                carries the text its failure must contain, so a YAML parse
#                error or an unrelated complaint cannot be miscounted as a kill.
#     SURVIVE  — behaviour-preserving refactors the guard must ACCEPT.
#                Over-fitting is its own failure: a guard that rejects valid
#                code teaches maintainers to delete it.
#
#   Mutations are applied to a SLICE of tasks/system.yml (the stat, enforce or
#   report task specifically), never file-globally: an earlier revision replaced
#   `    owner: root` across the whole file and silently flipped three unrelated
#   directory entries, so "each mutation breaks exactly one thing" was false.
#
#   Operates entirely on copies in a temporary directory; the repository is
#   never modified. A stale anchor reports NO-OP and fails — the same tripwire
#   idiom as the `checked != 8` count in tests/assert-root-owned-posture.sh.
# Usage: bash tests/assert-staged-tls-mutations.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import os, shutil, subprocess, sys, tempfile
import yaml

root = sys.argv[1]
GUARD = 'tests/assert-staged-tls-posture.sh'
SYSTEM = 'tasks/system.yml'
MAIN = 'tasks/main.yml'

sys_src = open(os.path.join(root, SYSTEM)).read()
main_src = open(os.path.join(root, MAIN)).read()

INS = '- name: Inspect operator-staged TLS material'
ENF = '- name: Enforce ownership on operator-staged TLS material'
REP = '- name: Report staged TLS material the role will not converge'
SEL = '# SELinux File Contexts'

for anchor in (INS, ENF, REP, SEL):
    if anchor not in sys_src:
        print(f"FAIL - anchor not found in {SYSTEM}: {anchor!r}; harness is stale")
        sys.exit(1)

I_INS, I_ENF, I_REP = (sys_src.index(x) for x in (INS, ENF, REP))
I_SEL = sys_src.index(SEL, I_REP)
# The '#####' banner line above the SELinux header belongs to that section.
_BANNER = sys_src.rindex('#' * 40, I_REP, I_SEL)
# rindex returns the LAST start offset of a 40-char run inside that 79-hash
# banner -- i.e. 39 characters into the line. Splicing there puts a task name
# inside a comment and makes its remaining lines keys of the previous task.
I_END = sys_src.rindex('\n', 0, _BANNER) + 1

SLICES = {'stat': (I_INS, I_ENF), 'enforce': (I_ENF, I_REP), 'report': (I_REP, I_END)}

MANAGE = '    - not (vault_manage_tls | bool)'
DIRNAME = '    - item.item | dirname == vault_tls_dir'
ISLNK = '    - not (item.stat.islnk | default(false))'
ISREG = '    - item.stat.isreg | default(false)'
NLINK = '    - item.stat.nlink | default(1) == 1'
EXISTS = '    - item.stat.exists | default(false)'

SECOND_FILE = '''
- name: Second file task re-posturing the trio
  ansible.builtin.file:
    path: "{{ item }}"
    state: file
    owner: root
    group: vault
    mode: '0666'
  loop:
    - "{{ vault_tls_cert_file }}"
    - "{{ vault_tls_key_file }}"
    - "{{ vault_tls_ca_file }}"
'''

SECOND_COPY = '''
- name: Second copy task re-posturing the key
  ansible.builtin.copy:
    content: "x"
    dest: "{{ vault_tls_key_file }}"
    owner: vault
    group: vault
    mode: '0600'
'''


SECOND_UNBOUNDED = '''
- name: Converge staged TLS material (simplified)
  ansible.builtin.file:
    path: "{{ item }}"
    state: touch
    follow: true
    owner: root
    group: "{{ vault_group }}"
    mode: "{{ vault_tls_file_mode }}"
  loop:
    - "{{ vault_tls_cert_file }}"
    - "{{ vault_tls_key_file }}"
    - "{{ vault_tls_ca_file }}"
'''

SECOND_LITERAL = '''
- name: Converge staged TLS material by literal path
  ansible.builtin.file:
    path: "{{ item }}"
    state: touch
    owner: root
    group: "{{ vault_group }}"
    mode: "{{ vault_tls_file_mode }}"
  loop:
    - /opt/vault/tls/tls.crt
    - /opt/vault/tls/tls.key
    - /opt/vault/tls/ca.crt
'''


def wrap_in_block(s):
    """Hoist the thrice-repeated condition into an ancestor block -- the obvious
    tidy-up -- with the polarity slipped. Every inner term stays intact."""
    region = s[I_INS:I_END]
    indented = '\n'.join(('  ' + ln) if ln.strip() else ln
                          for ln in region.rstrip('\n').split('\n'))
    block = ('- name: Operator-staged TLS material\n'
             '  when: vault_manage_tls | bool\n'
             '  block:\n' + indented + '\n\n')
    return s[:I_INS] + block + s[I_END:]


def reorder(s):
    """Put the consumers before the producer: the register is undefined, the
    loop falls back to default([]) and the role silently does nothing."""
    stat_blk = s[I_INS:I_ENF]
    rest = s[I_ENF:I_END]
    return s[:I_INS] + rest + stat_blk + s[I_END:]


def edit(where, old, new):
    """Replace `old` with `new` ONLY inside the named task slice."""
    def f(s):
        a, b = SLICES[where]
        seg = s[a:b]
        if old not in seg:
            return s
        return s[:a] + seg.replace(old, new, 1) + s[b:]
    return f


def append_task(text):
    return lambda s: s[:I_END] + text.lstrip('\n') + '\n' + s[I_END:]


def drop_slice(where):
    def f(s):
        a, b = SLICES[where]
        return s[:a] + s[b:]
    return f


def drop_region(s):
    return s[:I_INS] + s[I_END:]


# (label, system-transform, main-transform, text the guard's failure must contain)
KILL = [
    ("delete the whole enforcement region", drop_region, None, "no stat task loops"),
    ("delete the file-module enforcer", drop_slice('enforce'), None, "enforcement is missing"),
    ("delete the report task", drop_slice('report'), None, "no debug task loops"),

    # --- the polarity family: the SAME term at THREE sibling sites.
    ("invert the STAT when: polarity (everything downstream skips)",
     edit('stat', '  when: not (vault_manage_tls | bool)', '  when: vault_manage_tls | bool'),
     None, "stat when: is missing the exact term"),
    ("drop the STAT when: entirely",
     edit('stat', '\n  when: not (vault_manage_tls | bool)', ''), None,
     "stat when: is missing the exact term"),
    ("invert the ENFORCE when: polarity",
     edit('enforce', MANAGE, '    - vault_manage_tls | bool'), None,
     "enforcement when: is missing the exact term"),
    ("drop the ENFORCE when: polarity term",
     edit('enforce', '\n' + MANAGE, ''), None, "enforcement when: is missing the exact term"),
    ("invert the REPORT when: polarity",
     edit('report', MANAGE, '    - vault_manage_tls | bool'), None,
     "report when: is missing the exact term"),
    ("disable the REPORT with an always-false term",
     edit('report', MANAGE, MANAGE + '\n    - false'), None, "always-false term"),

    # --- the vault_tls_dir bound and every way to weaken it.
    ("invert the vault_tls_dir bound (== -> !=)",
     edit('enforce', DIRNAME, '    - item.item | dirname != vault_tls_dir'), None,
     "dirname == vault_tls_dir"),
    ("weaken vault_tls_dir to a prefix search",
     edit('enforce', DIRNAME, '    - item.item | dirname is search(vault_tls_dir)'), None,
     "dirname == vault_tls_dir"),
    ("weaken vault_tls_dir to substring containment",
     edit('enforce', DIRNAME, '    - vault_tls_dir in (item.item | dirname)'), None,
     "dirname == vault_tls_dir"),
    ("weaken vault_tls_dir to a match() prefix test",
     edit('enforce', DIRNAME, '    - item.item | dirname is match(vault_tls_dir)'), None,
     "dirname == vault_tls_dir"),
    ("replace vault_tls_dir bound with an always-true expression",
     edit('enforce', DIRNAME, '    - vault_tls_dir | dirname is defined'), None,
     "dirname == vault_tls_dir"),
    ("drop the vault_tls_dir bound", edit('enforce', '\n' + DIRNAME, ''), None,
     "dirname == vault_tls_dir"),

    # --- the stat-shape bounds, each inverted and each dropped.
    ("invert the symlink bound", edit('enforce', ISLNK, '    - item.stat.islnk | default(false)'),
     None, "not (item.stat.islnk | default(false))"),
    ("drop the symlink bound", edit('enforce', '\n' + ISLNK, ''), None, "not (item.stat.islnk | default(false))"),
    ("invert the regular-file bound",
     edit('enforce', ISREG, '    - not (item.stat.isreg | default(false))'), None, "item.stat.isreg | default(false)"),
    ("drop the regular-file bound", edit('enforce', '\n' + ISREG, ''), None, "item.stat.isreg | default(false)"),
    ("invert the hardlink bound",
     edit('enforce', NLINK, '    - item.stat.nlink | default(1) != 1'), None, "item.stat.nlink | default(1) == 1"),
    ("drop the hardlink bound", edit('enforce', '\n' + NLINK, ''), None, "item.stat.nlink | default(1) == 1"),
    ("invert the existence bound",
     edit('enforce', EXISTS, '    - not (item.stat.exists | default(false))'), None, "item.stat.exists | default(false)"),
    ("drop the existence bound", edit('enforce', '\n' + EXISTS, ''), None, "item.stat.exists | default(false)"),
    ("drop the failed-stat cause from the REPORT or-chain",
     edit('report', '    - item.stat is not defined\n      or not', '    - not'), None,
     "missing the exact disjunct `item.stat is not defined`"),

    # --- module arguments.
    ("path targets the DIRECTORY, not the loop item",
     edit('enforce', '    path: "{{ item.item }}"', '    path: "{{ vault_tls_dir }}"'), None,
     "not one of the supported forms"),
    ("path laundered through stat output (writes through the link)",
     edit('enforce', '    path: "{{ item.item }}"',
          '    path: "{{ item.stat.lnk_target | default(item.item) }}"'), None,
     "not one of the supported forms"),
    ("state: file -> state: touch", edit('enforce', '    state: file', '    state: touch'),
     None, "state='touch'"),
    ("drop follow: false from the file module",
     edit('enforce', '\n    follow: false', ''), None, "enforcement follow=None"),
    ("flip the file module to follow: true",
     edit('enforce', '    follow: false', '    follow: true'), None, "enforcement follow=True"),
    ("drop follow: false from the stat", edit('stat', '\n    follow: false', ''), None,
     "stat follow=None"),
    ("give the vault account ownership", edit('enforce', '    owner: root', '    owner: vault'),
     None, "owner='vault'"),
    ("hardcode the group", edit('enforce', '    group: "{{ vault_group }}"', '    group: vault'),
     None, "not exactly {{ vault_group }}"),
    ("hardcode the mode",
     edit('enforce', '    mode: "{{ vault_tls_file_mode }}"', "    mode: '0640'"), None,
     "not exactly {{ vault_tls_file_mode }}"),
    ("launder the mode through a filter",
     edit('enforce', '    mode: "{{ vault_tls_file_mode }}"',
          '    mode: "{{ vault_tls_file_mode | regex_replace(\'0640\', \'0644\') }}"'), None,
     "not exactly {{ vault_tls_file_mode }}"),
    ("narrow the stat loop to 2 of 3 paths",
     edit('stat', '    - "{{ vault_tls_ca_file }}"\n', ''), None, "no stat task loops"),

    # --- structure: conditions and order that no per-task check can see.
    ("hoist the condition into an ancestor block with inverted polarity",
     wrap_in_block, None, "not top-level"),
    ("reorder so the enforcer runs before the stat that feeds it",
     reorder, None, "out of order"),

    # --- a second writer undoing the first. EXPECT_TASK proves the splice
    # actually produced the task: an earlier revision spliced into the middle
    # of a banner comment and scored kills off a mangled report task.
    ("add a second file task loosening the trio to 0666", append_task(SECOND_FILE), None,
     "also writes the staged"),
    ("add a second copy task handing the key to vault:vault", append_task(SECOND_COPY), None,
     "also writes the staged"),
    ("add a second writer with correct posture but NO bounds",
     append_task(SECOND_UNBOUNDED), None, "also writes the staged"),
    ("add a second writer naming the trio by literal path",
     append_task(SECOND_LITERAL), None, "also writes the staged"),

    # --- the report's or-chain: polarity and the joining operator.
    ("flip the report's dirname disjunct (out-of-tree becomes silent)",
     edit('report', 'or item.item | dirname != vault_tls_dir',
          'or item.item | dirname == vault_tls_dir'), None,
     "missing the exact disjunct"),
    ("collapse the report's or-chain to and (unsatisfiable, never fires)",
     edit('report', '\n      or ', '\n      and '), None, "joins its causes with `and`"),
    ("drop the symlink disjunct from the report",
     edit('report', '\n      or (item.stat.islnk | default(false))', ''), None,
     "missing the exact disjunct"),

    # --- codex round 1: the guard established facts about the path the STAT
    # inspected, then never bound the write to that same path, and rejected an
    # always-false term on the reporter but not on its siblings.
    ("pin the inspector to one variable (every item carries the CERT's metadata)",
     edit('stat', '    path: "{{ item }}"', '    path: "{{ vault_tls_cert_file }}"'),
     None, "is not exactly {{ item }}"),
    ("enforce a DIFFERENT path than the one inspected (.bak)",
     edit('enforce', '    path: "{{ item.item }}"', '    path: "{{ item.item }}.bak"'),
     None, "not one of the supported forms"),
    ("disable the ENFORCER with an always-false term",
     edit('enforce', MANAGE, '    - false\n' + MANAGE), None,
     "enforcement when: contains an always-false term"),
    ("disable the STAT with an always-false term",
     edit('stat', '  when: not (vault_manage_tls | bool)',
          '  when:\n    - false\n    - not (vault_manage_tls | bool)'), None,
     "stat when: contains an always-false term"),
    ("invert the reporter's skipped-item term",
     edit('report', '    - not (item.skipped | default(false))',
          '    - item.skipped | default(false)'), None,
     "not (item.skipped | default(false))"),
    ("drop failed_when: false from the inspector",
     edit('stat', '\n  failed_when: false', ''), None, "stat failed_when=None"),

    # --- the premise in tasks/main.yml, and every way to break it.
    # Anchored on the `when:` alone, not on the include's surrounding form: #28
    # rewrote every include from the bare-string shape to the mapping shape with
    # apply:, which turned the old full-literal anchor into a silent NO-OP. The
    # gate line is unique in main.yml (vault_manage_tls appears in no other
    # when:), so deleting it is exactly "ungate tls.yml".
    ("ungate tls.yml in tasks/main.yml", None,
     lambda m: m.replace('  when: vault_manage_tls | bool\n', '', 1),
     "no longer gates tls.yml"),
    ("weaken the tls.yml gate to `is defined`", None,
     lambda m: m.replace('  when: vault_manage_tls | bool\n',
                         '  when: vault_manage_tls is defined\n', 1),
     "no longer gates tls.yml"),
    ("invert the tls.yml gate polarity", None,
     lambda m: m.replace('  when: vault_manage_tls | bool\n',
                         '  when: not (vault_manage_tls | bool)\n', 1),
     "no longer gates tls.yml"),
]

# Behaviour-preserving. The guard must accept all of these.
SURVIVE = [
    ("drop the optional parens on the ENFORCE polarity term",
     edit('enforce', MANAGE, '    - not vault_manage_tls | bool'), None),
    ("derive path as vault_tls_dir ~ basename of the item",
     edit('enforce', '    path: "{{ item.item }}"',
          '    path: "{{ vault_tls_dir }}/{{ item.item | basename }}"'), None),
    ("extra whitespace around the vault_tls_dir comparison",
     edit('enforce', DIRNAME, '    - item.item   |   dirname   ==   vault_tls_dir'), None),
    ("reorder the when: terms", edit('enforce', ISREG + '\n' + ISLNK, ISLNK + '\n' + ISREG), None),
    ("whitespace inside the group template",
     edit('enforce', '    group: "{{ vault_group }}"', '    group: "{{  vault_group  }}"'), None),
]


def parses(text, expect_task=None):
    """The mutated document must load, and must contain the task it claims.

    Without this a splice into a comment scores a 'kill' off an unrelated
    complaint -- which is exactly what the two second-writer cases did.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return f"mutated tasks/system.yml does not parse: {e.__class__.__name__}"
    if expect_task:
        names = [t.get('name') for t in (doc or []) if isinstance(t, dict)]
        if expect_task not in names:
            return (f"mutation claims to add {expect_task!r} but the loaded task "
                    f"list is {names!r}")
    return None


def run(new_sys, new_main):
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, 'tasks'))
        os.makedirs(os.path.join(tmp, 'tests'))
        shutil.copy(os.path.join(root, GUARD), os.path.join(tmp, GUARD))
        open(os.path.join(tmp, SYSTEM), 'w').write(new_sys)
        open(os.path.join(tmp, MAIN), 'w').write(new_main)
        return subprocess.run(['bash', os.path.join(tmp, GUARD)],
                              capture_output=True, text=True)


EXPECT_TASK = {
    "add a second file task loosening the trio to 0666":
        "Second file task re-posturing the trio",
    "add a second copy task handing the key to vault:vault":
        "Second copy task re-posturing the key",
    "add a second writer with correct posture but NO bounds":
        "Converge staged TLS material (simplified)",
    "add a second writer naming the trio by literal path":
        "Converge staged TLS material by literal path",
    "hoist the condition into an ancestor block with inverted polarity":
        "Operator-staged TLS material",
}

bad = []
for label, fs, fm, expect in KILL:
    new_sys = fs(sys_src) if fs else sys_src
    new_main = fm(main_src) if fm else main_src
    if new_sys == sys_src and new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    broken = parses(new_sys, EXPECT_TASK.get(label))
    if broken:
        bad.append(f"MUTATION IS NOT WHAT IT CLAIMS: {label} -- {broken}")
        continue
    p = run(new_sys, new_main)
    if p.returncode == 0:
        bad.append(f"SURVIVED (guard is blind): {label}")
    elif expect not in p.stdout:
        bad.append(f"WRONG REASON: {label} -- failure did not mention {expect!r}; "
                   f"got: {p.stdout.strip().splitlines()[:1]}")

for label, fs, fm in SURVIVE:
    new_sys = fs(sys_src) if fs else sys_src
    new_main = fm(main_src) if fm else main_src
    if new_sys == sys_src and new_main == main_src:
        bad.append(f"NO-OP (anchor stale): {label}")
        continue
    p = run(new_sys, new_main)
    if p.returncode != 0:
        first = p.stdout.strip().splitlines()
        bad.append(f"OVER-FITTED (rejects a valid refactor): {label} -- "
                   f"{first[0] if first else '(no output)'}")

if run(sys_src, main_src).returncode != 0:
    bad.append("the UNMUTATED tree does not pass the guard; every result above is meaningless")

if bad:
    for x in bad:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - guard killed all {len(KILL)} mutations with the right message, and "
      f"accepted all {len(SURVIVE)} behaviour-preserving refactors")
PY
