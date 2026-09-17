#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-staged-tls-posture.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #77 — when the role is NOT managing TLS,
#   tasks/tls.yml never runs (tasks/main.yml gates it on vault_manage_tls), so
#   nothing there can set ownership on the operator-staged trio. The role must
#   converge that posture itself, in tasks/system.yml, exactly as it already
#   does unconditionally for vault_tls_dir.
#
#   The enforcement WRITES to three free-form `type: path` variables, so every
#   bound on that write is asserted by EXACT FORM, not by substring. A substring
#   test cannot see polarity or exact-vs-prefix semantics: `vault_tls_dir |
#   dirname is defined` is always true and contains both of the words a naive
#   check looks for, which would restore the unbounded behaviour with a green
#   guard. Each condition below is matched as a whole term.
#
#   Locked:
#     - stat inspects with follow: false (see the link, not its target),
#     - the file module sets state: file and follow: false,
#     - path is derived from the loop item,
#     - ALL THREE tasks carry the exact term `not (vault_manage_tls | bool)`.
#       They are siblings: inverting the STAT's copy alone makes every
#       downstream task skip and regresses #77 in full, silently.
#     - the enforcement when: also carries `item.stat.exists | default(false)`,
#       `item.stat.isreg | default(false)`,
#       `not (item.stat.islnk | default(false))`,
#       `item.stat.nlink | default(1) == 1` and
#       `item.item | dirname == vault_tls_dir`,
#     - the report when: names every one of those exclusion causes plus the
#       failed-stat shape, and contains no always-false term,
#     - no OTHER file/copy/template task in system.yml re-postures the trio,
#     - the PREMISE holds: tasks/main.yml still gates tls.yml on the exact term
#       `vault_manage_tls | bool` (without it this task is redundant and the
#       two fight over the same files).
#
#   Structural and container-free by design. Behavioural proof lives in
#   molecule/default (staged root:root 0600 -> root:vault 0640, a symlinked CA
#   and its out-of-tree target proven untouched, runuser read/write probes) and
#   molecule/init (a real vault server starting on role-converged material).
# Usage: bash tests/assert-staged-tls-posture.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, re, yaml

root = sys.argv[1]
STAGED = ('vault_tls_cert_file', 'vault_tls_key_file', 'vault_tls_ca_file')
fail = []

tasks = yaml.safe_load(open(os.path.join(root, 'tasks/system.yml'))) or []


def mods(ts, names):
    """Yield (task, args) for every task using one of `names`, recursing blocks."""
    for t in ts or []:
        if not isinstance(t, dict):
            continue
        for m in names:
            if isinstance(t.get(m), dict):
                yield t, t[m]
        for k in ('block', 'rescue', 'always'):
            if k in t:
                yield from mods(t[k], names)


def when_terms(task):
    """when: may be a string or a list; return the terms, parens/space-normalised."""
    w = task.get('when', '')
    terms = w if isinstance(w, list) else ([w] if w else [])
    return [' '.join(str(t).split()) for t in terms]


MANAGE_RX = r'not\s*\(?\s*vault_manage_tls\s*\|\s*bool\s*\)?'


def has_term(terms, pattern):
    """True when SOME whole term matches `pattern` end-to-end (parens tolerated)."""
    rx = re.compile(r'^\(?\s*' + pattern + r'\s*\)?$')
    return any(rx.match(t) for t in terms)


# --- 1. The inspector: a stat that sees the LINK, over all three staged paths.
inspectors = [(t, m) for t, m in mods(tasks, ('stat', 'ansible.builtin.stat'))
              if isinstance(t.get('loop'), list)
              and all(v in str(t['loop']) for v in STAGED)]

register = None
if not inspectors:
    fail.append("tasks/system.yml: no stat task loops over all three staged TLS "
                "paths; the enforcement cannot tell a symlink or a directory "
                "from a regular file")
elif len(inspectors) > 1:
    fail.append(f"tasks/system.yml: {len(inspectors)} stat tasks cover the staged "
                "TLS trio; expected exactly 1")
else:
    task, mod = inspectors[0]
    register = task.get('register')
    if mod.get('follow') is not False:
        fail.append(f"staged-TLS stat follow={mod.get('follow')!r}; must be false, "
                    "or it reports the link TARGET and a symlink is converged as "
                    "though it were a regular file")
    if not register:
        fail.append("staged-TLS stat has no register:; the enforcement has nothing "
                    "to consume")
    # SIBLING SITE. Flipping THIS when: skips the stat per item, so every result
    # carries skipped: true and no stat key, and the enforcement and the report
    # both fall through -- #77 regresses in full, silently. Same term, same lock.
    if not has_term(when_terms(task), MANAGE_RX):
        fail.append(f"staged-TLS stat when: is missing the exact term "
                    f"`not (vault_manage_tls | bool)` (found {when_terms(task)!r}); "
                    "inverting or dropping it makes every downstream task skip")

# --- 2. The enforcer: the file module that consumes it.
enforcers = [(t, m) for t, m in mods(tasks, ('file', 'ansible.builtin.file'))
             if register and register in str(t.get('loop', ''))]

if register and not enforcers:
    fail.append(f"tasks/system.yml: no file-module task loops over {register}; "
                "issue #77 enforcement is missing")
elif len(enforcers) > 1:
    fail.append(f"tasks/system.yml: {len(enforcers)} file tasks consume {register}; "
                "expected exactly 1 so posture has one owner")
elif enforcers:
    task, mod = enforcers[0]
    terms = when_terms(task)
    path = str(mod.get('path', ''))

    # --- posture: the pairing tasks/tls.yml applies on the managed path.
    if mod.get('owner') != 'root':
        fail.append(f"staged-TLS enforcement owner={mod.get('owner')!r} != root "
                    "(#38: vault must not own what defines its posture)")
    # Substring would accept laundering through a filter, e.g.
    # `{{ vault_tls_file_mode | regex_replace('0640','0644') }}` -- it contains
    # the variable name and resolves to something else entirely. Whole value.
    if not re.match(r'^\{\{\s*vault_group\s*\}\}$', str(mod.get('group', ''))):
        fail.append(f"staged-TLS enforcement group={mod.get('group')!r} is not "
                    "exactly {{ vault_group }}")
    if not re.match(r'^\{\{\s*vault_tls_file_mode\s*\}\}$', str(mod.get('mode', ''))):
        fail.append(f"staged-TLS enforcement mode={mod.get('mode')!r} is not "
                    "exactly {{ vault_tls_file_mode }} (a filter could launder it "
                    "to any value while still naming the var)")

    # --- target derived per item, so one fixed path cannot stand in for the trio.
    # item.stat is specifically excluded: `item.stat.lnk_target` names `item` and
    # would write straight through a symlink, defeating the islnk bound.
    if 'item.item' not in path:
        fail.append(f"staged-TLS enforcement path={path!r} is not derived from "
                    "item.item; it would converge one fixed path, not the trio")
    if 'item.stat' in path:
        fail.append(f"staged-TLS enforcement path={path!r} is derived from stat "
                    "output; lnk_target and friends resolve OUTSIDE vault_tls_dir")

    # --- state: touch would CREATE material the operator was told to supply.
    if mod.get('state') != 'file':
        fail.append(f"staged-TLS enforcement state={mod.get('state')!r} != 'file' "
                    "(touch/absent/directory would create or destroy material)")

    # --- follow: the module default is TRUE; unset rewrites a link's target.
    if mod.get('follow') is not False:
        fail.append(f"staged-TLS enforcement follow={mod.get('follow')!r}; must be "
                    "explicitly false (the module default is true, which rewrites "
                    "the symlink TARGET outside vault_tls_dir)")

    # --- bounds, matched as WHOLE TERMS. Substring tests cannot see polarity,
    # and cannot tell `== vault_tls_dir` from `is search(vault_tls_dir)`.
    REQUIRED = [
        (MANAGE_RX,
         "not (vault_manage_tls | bool)",
         "without it the task double-applies with tasks/tls.yml on the managed path"),
        (r'item\.stat\.exists\s*\|\s*default\(\s*false\s*\)',
         "item.stat.exists | default(false)",
         "state: file on a missing path fails the play at Phase 4"),
        (r'item\.stat\.isreg\s*\|\s*default\(\s*false\s*\)',
         "item.stat.isreg | default(false)",
         "a DIRECTORY at a staged path aborts state: file with "
         "'is directory, cannot continue' at Phase 4, after the package install"),
        (r'not\s*\(\s*item\.stat\.islnk\s*\|\s*default\(\s*false\s*\)\s*\)',
         "not (item.stat.islnk | default(false))",
         "a symlink would be converged as if it were a regular file"),
        (r'item\.stat\.nlink\s*\|\s*default\(\s*1\s*\)\s*==\s*1',
         "item.stat.nlink | default(1) == 1",
         "a HARDLINK into vault_tls_dir shares an inode with out-of-tree "
         "material, so chgrp/chmod lands on that material anyway"),
        (r'item\.item\s*\|\s*dirname\s*==\s*vault_tls_dir',
         "item.item | dirname == vault_tls_dir",
         "anything weaker than EXACT parent equality lets an operator pointing "
         "vault_tls_ca_file at a shared anchor have it chgrp'd away from the host"),
    ]
    for pattern, literal, why in REQUIRED:
        if not has_term(terms, pattern):
            fail.append(f"staged-TLS enforcement when: is missing the exact term "
                        f"`{literal}` (found {terms!r}) -- {why}")

# --- 3. Every excluded path must be explained, not silently skipped. The report
# is a SIBLING of the enforcer and gets the same treatment: its own polarity
# term locked, and its or-chain required to name every exclusion cause. A report
# that exists but can never fire is worse than none -- README and CHANGELOG both
# promise the operator an explanation.
reporters = [t for t, _ in mods(tasks, ('debug', 'ansible.builtin.debug'))
             if register and register in str(t.get('loop', ''))]
if register and not reporters:
    fail.append(f"tasks/system.yml: no debug task loops over {register}; paths the "
                "enforcement excludes (missing, symlinked, non-regular, hardlinked, "
                "out of vault_tls_dir, un-stat-able) would be skipped with no "
                "explanation, and README and CHANGELOG both claim they are reported")
elif reporters:
    rterms = when_terms(reporters[0])
    if not has_term(rterms, MANAGE_RX):
        fail.append(f"staged-TLS report when: is missing the exact term "
                    f"`not (vault_manage_tls | bool)` (found {rterms!r})")
    if any(t.strip().lower() in ('false', 'no', 'off') for t in rterms):
        fail.append(f"staged-TLS report when: contains an always-false term "
                    f"({rterms!r}); every exclusion would be silent")
    chain = ' '.join(rterms)
    # The failed-stat shape (ENOTDIR and friends) returns NO stat key. Requiring
    # `item.stat is defined` here made it fall through BOTH tasks and vanish.
    if 'item.stat is not defined' not in chain:
        fail.append(f"staged-TLS report when: does not treat a failed stat as a "
                    f"reportable cause (found {rterms!r}); stat fail_json's on "
                    "every OSError but ENOENT, returning no stat key, and that "
                    "shape would be silently skipped by the enforcer too")
    for cause in ('exists', 'isreg', 'islnk', 'nlink', 'dirname'):
        if cause not in chain:
            fail.append(f"staged-TLS report when: never fires for the {cause} "
                        f"exclusion (found {rterms!r}); it must be the exact "
                        "complement of the enforcement")

# --- 4. No OTHER task may re-posture the staged trio. Scans every module that
# can write a file's ownership, not just `file` -- `copy` and `template` set
# owner/group/mode too, and a second task undoing this one is the obvious way
# for the fix to be lost in a later refactor.
for name in ('file', 'ansible.builtin.file', 'copy', 'ansible.builtin.copy',
             'template', 'ansible.builtin.template'):
    for t, m in mods(tasks, (name,)):
        if enforcers and t is enforcers[0][0]:
            continue
        blob = str(t.get('loop', '')) + str(m.get('path', '')) + str(m.get('dest', ''))
        if not any(v in blob for v in STAGED):
            continue
        label = t.get('name', '<unnamed>')
        if m.get('owner') != 'root':
            fail.append(f"tasks/system.yml: task {label!r} also writes the staged "
                        f"TLS trio with owner={m.get('owner')!r}; only root may own "
                        "the material that defines the service's posture (#38)")
        if 'vault_group' not in str(m.get('group', '')):
            fail.append(f"tasks/system.yml: task {label!r} also writes the staged "
                        f"TLS trio with group={m.get('group')!r}, not vault_group")
        if 'vault_tls_file_mode' not in str(m.get('mode', '')):
            fail.append(f"tasks/system.yml: task {label!r} also writes the staged "
                        f"TLS trio with mode={m.get('mode')!r}, not "
                        "vault_tls_file_mode")

# --- 5. The premise: tasks/tls.yml really is gated off on the default path.
gated = False
for t in yaml.safe_load(open(os.path.join(root, 'tasks/main.yml'))) or []:
    if not isinstance(t, dict):
        continue
    inc = t.get('include_tasks') or t.get('ansible.builtin.include_tasks') or ''
    target = inc.get('file', '') if isinstance(inc, dict) else str(inc)
    # Exact term, for the same reason every other bound is: `vault_manage_tls is
    # defined` and `not (vault_manage_tls | bool)` both contain the variable name
    # and both make tls.yml run on the default path, fighting this enforcement.
    if 'tls.yml' in target and has_term(when_terms(t),
                                        r'vault_manage_tls\s*\|\s*bool'):
        gated = True
if not gated:
    fail.append("tasks/main.yml no longer gates tls.yml on vault_manage_tls; the "
                "premise of the system.yml enforcement is gone and the two would "
                "both write the staged trio")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print("ok - staged TLS trio converged to root:vault_group/vault_tls_file_mode; "
      "bounds (exists/isreg/not-islnk/exact-parent) locked by exact term; "
      "exclusions reported; tls.yml still gated")
PY
