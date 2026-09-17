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
# The defaults, for writers that name a path literally instead of a variable.
LITERALS = ('/opt/vault/tls/tls.crt', '/opt/vault/tls/tls.key',
            '/opt/vault/tls/ca.crt')
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


FALSEY = ('false', 'no', 'off', 'none', '0')


def disabled(terms):
    """A term that can never be true switches the task off outright."""
    return [t for t in terms if t.strip().lower() in FALSEY]


def has_term(terms, pattern):
    """True when SOME whole term matches `pattern` end-to-end (parens tolerated)."""
    rx = re.compile(r'^\(?\s*' + pattern + r'\s*\)?$')
    return any(rx.match(t) for t in terms)


def top_index(t):
    """Position of `t` in the TOP-LEVEL task list, or None when it is nested.

    A task inside a block inherits that block's when:, which this guard cannot
    see -- wrapping the region in `block: {when: vault_manage_tls | bool}` skips
    all three tasks on the default path with every inner term still intact.
    Requiring top level makes the ancestor condition impossible instead of
    trying to evaluate it.
    """
    for i, x in enumerate(tasks):
        if x is t:
            return i
    return None


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
    if not re.match(r'^\{\{\s*item\s*\}\}$', str(mod.get('path', ''))):
        fail.append(f"staged-TLS stat path={mod.get('path', '')!r} is not exactly "
                    "{{ item }}; pinning it to one variable gives EVERY loop item "
                    "that file's metadata, so a hardlinked key passes the "
                    "certificate's nlink check and its shared inode is rewritten")
    if mod.get('follow') is not False:
        fail.append(f"staged-TLS stat follow={mod.get('follow')!r}; must be false, "
                    "or it reports the link TARGET and a symlink is converged as "
                    "though it were a regular file")
    # SF2c: without it an un-stat-able path aborts the play instead of routing
    # to the report, and the report's `item.stat is not defined` branch becomes
    # unreachable.
    # failed_when is a TASK keyword, not a module argument.
    if task.get('failed_when') is not False:
        fail.append(f"staged-TLS stat failed_when={task.get('failed_when')!r}; must "
                    "be false, or an un-inspectable path (ENOTDIR, EACCES) fails "
                    "the play at Phase 4 instead of being reported")
    if disabled(when_terms(task)):
        fail.append(f"staged-TLS stat when: contains an always-false term "
                    f"({when_terms(task)!r}); the whole region goes dead")
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

    # --- the write target is an ALLOW-LIST, not a substring test. Everything
    # above establishes facts about the path the stat INSPECTED; the module must
    # then write that exact path. `{{ item.item }}.bak` contains `item.item` and
    # writes a different, never-inspected file; `item.stat.lnk_target` resolves
    # outside vault_tls_dir. Both pass any substring rule.
    ALLOWED_PATHS = (
        r'\{\{\s*item\.item\s*\}\}',
        r'\{\{\s*vault_tls_dir\s*\}\}/\{\{\s*item\.item\s*\|\s*basename\s*\}\}',
    )
    if not any(re.match('^' + a + '$', path) for a in ALLOWED_PATHS):
        fail.append(f"staged-TLS enforcement path={path!r} is not one of the "
                    "supported forms ({{ item.item }} or "
                    "{{ vault_tls_dir }}/{{ item.item | basename }}); anything "
                    "else writes a path the stat above never inspected")

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
    if disabled(terms):
        fail.append(f"staged-TLS enforcement when: contains an always-false term "
                    f"({terms!r}); every required term is still present and the "
                    "repair never runs")
    # The LOOP, not just the conditions: every bound can be intact while the
    # task iterates an empty list. codex demonstrated that against the sibling
    # dns classifier; the same shape applies here.
    if register not in str(task.get('loop', '')):
        fail.append(f"staged-TLS enforcement no longer loops over {register}; "
                    f"its loop is {task.get('loop')!r}. Every bound below can be "
                    "intact while the task iterates nothing.")
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
    if disabled(rterms):
        fail.append(f"staged-TLS report when: contains an always-false term "
                    f"({rterms!r}); every exclusion would be silent")
    if not has_term(rterms, r'not\s*\(\s*item\.skipped\s*\|\s*default\(\s*false\s*\)\s*\)'):
        fail.append(f"staged-TLS report when: is missing the exact term "
                    f"`not (item.skipped | default(false))` (found {rterms!r}); "
                    "inverted, it fires ONLY for the managed path's skipped "
                    "results and every real exclusion goes unreported")
    # The or-chain is ONE yaml term. Substring-checking its causes cannot see
    # polarity (`dirname != dir` flipped to `==` silently drops the shared-anchor
    # case) nor the joining operator (`or` collapsed to `and` makes the chain
    # unsatisfiable and the report unreachable). Split and match each disjunct.
    chains = [t for t in rterms if ' or ' in t]
    if not chains:
        fail.append(f"staged-TLS report when: has no or-chain of exclusion causes "
                    f"(found {rterms!r}); it must be the exact complement of the "
                    "enforcement")
    else:
        chain = chains[0]
        if ' and ' in chain:
            fail.append(f"staged-TLS report when: joins its causes with `and` "
                        f"({chain!r}); the chain is then unsatisfiable and the "
                        "report can never fire")
        disjuncts = [' '.join(d.split()) for d in chain.split(' or ')]
        COMPLEMENT = [
            (r'item\.stat is not defined',
             'item.stat is not defined',
             "stat fail_json's on every OSError but ENOENT, returning no stat "
             "key; without this term that shape falls through BOTH tasks"),
            (r'not\s*\(\s*item\.stat\.exists\s*\|\s*default\(\s*false\s*\)\s*\)',
             'not (item.stat.exists | default(false))', "missing paths"),
            (r'not\s*\(\s*item\.stat\.isreg\s*\|\s*default\(\s*false\s*\)\s*\)',
             'not (item.stat.isreg | default(false))', "directories and devices"),
            (r'\(?\s*item\.stat\.islnk\s*\|\s*default\(\s*false\s*\)\s*\)?',
             '(item.stat.islnk | default(false))', "symlinks"),
            (r'\(?\s*item\.stat\.nlink\s*\|\s*default\(\s*1\s*\)\s*\)?\s*!=\s*1',
             '(item.stat.nlink | default(1)) != 1', "hardlinks"),
            (r'item\.item\s*\|\s*dirname\s*!=\s*vault_tls_dir',
             'item.item | dirname != vault_tls_dir',
             "material outside vault_tls_dir -- the shared-anchor case README "
             "names explicitly"),
        ]
        for pattern, literal, why in COMPLEMENT:
            if not any(re.match(r'^\(?\s*' + pattern + r'\s*\)?$', d) for d in disjuncts):
                fail.append(f"staged-TLS report when: is missing the exact "
                            f"disjunct `{literal}` (found {disjuncts!r}) -- "
                            f"{why} would be silently skipped while README, "
                            "CHANGELOG and argument_specs all promise a report")

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
        # Match the literal default paths too: a second writer naming
        # /opt/vault/tls/tls.key directly -- the form every molecule fixture
        # uses -- mentions no variable at all.
        if not any(v in blob for v in STAGED + LITERALS):
            continue
        # REJECTED OUTRIGHT, not posture-checked. A second writer that keeps
        # root:vault 0640 but adds `state: touch` and `follow: true` re-admits
        # every defect the bounds above exist to prevent, through a parallel
        # surface. There is exactly one writer of this material, or the guard
        # is meaningless.
        label = t.get('name', '<unnamed>')
        fail.append(f"tasks/system.yml: task {label!r} also writes the staged TLS "
                    "trio; exactly one task may, so its bounds (state, follow, "
                    "dirname, islnk, nlink) cannot be bypassed by a sibling")

# --- 4b. Placement and order. Every term above is read from a task in
# isolation; neither an ancestor block's when: nor the execution order is
# visible to any of them, and both regress #77 in full while leaving every
# inner term intact.
if inspectors and enforcers and reporters:
    idx = {'stat': top_index(inspectors[0][0]),
           'enforce': top_index(enforcers[0][0]),
           'report': top_index(reporters[0])}
    nested = [k for k, v in idx.items() if v is None]
    if nested:
        fail.append(f"staged-TLS {', '.join(nested)} task(s) are not top-level in "
                    "tasks/system.yml; an enclosing block's when: would gate them "
                    "invisibly to every check above")
    elif not idx['stat'] < idx['enforce'] < idx['report']:
        fail.append(f"staged-TLS tasks are out of order ({idx}); the enforcement "
                    "and the report both consume the stat's register, and an "
                    "undefined register loops over `default([])` -- doing nothing, "
                    "silently")

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
