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
#     - the when: carries exactly `not (vault_manage_tls | bool)`,
#       `item.stat.exists | default(false)`, `item.stat.isreg | default(false)`,
#       `not (item.stat.islnk | default(false))` and
#       `item.item | dirname == vault_tls_dir`,
#     - every excluded path is REPORTED by a debug task over the same results,
#     - no OTHER task in system.yml hands the staged trio to a non-root owner,
#     - the PREMISE holds: tasks/main.yml still gates tls.yml on
#       vault_manage_tls (without it this task is redundant and the two fight).
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
    if 'vault_group' not in str(mod.get('group', '')):
        fail.append(f"staged-TLS enforcement group={mod.get('group')!r} does not "
                    "resolve from vault_group")
    if 'vault_tls_file_mode' not in str(mod.get('mode', '')):
        fail.append(f"staged-TLS enforcement mode={mod.get('mode')!r} does not "
                    "resolve from vault_tls_file_mode (hardcoding drifts from vars)")

    # --- target derived per item, so one fixed path cannot stand in for the trio.
    if 'item' not in path:
        fail.append(f"staged-TLS enforcement path={path!r} is not derived from the "
                    "loop item; it would converge one fixed path, not the trio")

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
        (r'not\s*\(?\s*vault_manage_tls\s*\|\s*bool\s*\)?',
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
        (r'item\.item\s*\|\s*dirname\s*==\s*vault_tls_dir',
         "item.item | dirname == vault_tls_dir",
         "anything weaker than EXACT parent equality lets an operator pointing "
         "vault_tls_ca_file at a shared anchor have it chgrp'd away from the host"),
    ]
    for pattern, literal, why in REQUIRED:
        if not has_term(terms, pattern):
            fail.append(f"staged-TLS enforcement when: is missing the exact term "
                        f"`{literal}` (found {terms!r}) -- {why}")

# --- 3. Every excluded path must be explained, not silently skipped.
reporters = [t for t, _ in mods(tasks, ('debug', 'ansible.builtin.debug'))
             if register and register in str(t.get('loop', ''))]
if register and not reporters:
    fail.append(f"tasks/system.yml: no debug task loops over {register}; paths the "
                "enforcement excludes (missing, symlinked, non-regular, out of "
                "vault_tls_dir) would be skipped with no explanation, and README "
                "and CHANGELOG both claim they are reported")

# --- 4. No second task may hand the staged trio to a non-root owner.
for t, m in mods(tasks, ('file', 'ansible.builtin.file')):
    if enforcers and t is enforcers[0][0]:
        continue
    blob = str(t.get('loop', '')) + str(m.get('path', ''))
    if any(v in blob for v in STAGED) and m.get('owner') != 'root':
        fail.append(f"tasks/system.yml: a second file task touches the staged TLS "
                    f"trio with owner={m.get('owner')!r}; only root may own the "
                    "material that defines the service's posture (#38)")

# --- 5. The premise: tasks/tls.yml really is gated off on the default path.
gated = False
for t in yaml.safe_load(open(os.path.join(root, 'tasks/main.yml'))) or []:
    if not isinstance(t, dict):
        continue
    inc = t.get('include_tasks') or t.get('ansible.builtin.include_tasks') or ''
    target = inc.get('file', '') if isinstance(inc, dict) else str(inc)
    if 'tls.yml' in target and any('vault_manage_tls' in x for x in when_terms(t)):
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
