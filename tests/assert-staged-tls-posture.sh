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
#   This task WRITES to three free-form `type: path` variables, so the guard
#   locks the bounds as hard as it locks the posture:
#     - stat inspects with follow: false (see the link, not its target),
#     - the file module sets state: file and follow: false,
#     - path comes from the loop item, never from vault_tls_dir itself,
#     - the when: excludes symlinks, excludes non-existent paths, and confines
#       the write to direct children of vault_tls_dir,
#     - the when: is negated on vault_manage_tls so it cannot double-apply.
#   It also asserts the PREMISE in tasks/main.yml (tls.yml is gated on
#   vault_manage_tls); without that gate this task would be redundant and the
#   two would fight.
#
#   Deliberately structural and container-free: the behavioural proof is
#   molecule/default (staged root:root 0600, verified root:vault 0640, plus
#   runuser read/write probes) and molecule/init (a real vault server starting
#   on role-converged material), both of which need podman.
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


def when_text(task):
    """when: may be a string or a list of strings; normalise to one blob."""
    w = task.get('when', '')
    return ' and '.join(str(x) for x in w) if isinstance(w, list) else str(w)


# --- 1. The inspector: a stat that sees the LINK, over all three staged paths.
inspectors = []
for task, mod in mods(tasks, ('stat', 'ansible.builtin.stat')):
    loop = task.get('loop')
    if isinstance(loop, list) and all(v in str(loop) for v in STAGED):
        inspectors.append((task, mod))

register = None
if not inspectors:
    fail.append("tasks/system.yml: no stat task loops over all three staged TLS "
                "paths; the enforcement cannot tell a symlink from a regular file")
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
enforcers = []
for task, mod in mods(tasks, ('file', 'ansible.builtin.file')):
    loop = str(task.get('loop', ''))
    if register and register in loop:
        enforcers.append((task, mod))

if register and not enforcers:
    fail.append(f"tasks/system.yml: no file-module task loops over {register}; "
                "issue #77 enforcement is missing")
elif len(enforcers) > 1:
    fail.append(f"tasks/system.yml: {len(enforcers)} file tasks consume {register}; "
                "expected exactly 1 so posture has one owner")
elif enforcers:
    task, mod = enforcers[0]
    when = when_text(task)
    path = str(mod.get('path', ''))

    # --- posture: the same pairing tasks/tls.yml applies on the managed path.
    if mod.get('owner') != 'root':
        fail.append(f"staged-TLS enforcement owner={mod.get('owner')!r} != root "
                    "(#38: vault must not own what defines its posture)")
    if 'vault_group' not in str(mod.get('group', '')):
        fail.append(f"staged-TLS enforcement group={mod.get('group')!r} does not "
                    "resolve from vault_group")
    if 'vault_tls_file_mode' not in str(mod.get('mode', '')):
        fail.append(f"staged-TLS enforcement mode={mod.get('mode')!r} does not "
                    "resolve from vault_tls_file_mode (hardcoding drifts from vars)")

    # --- target: the loop item, never the directory. A guard that omits this
    # passes an implementation that chmods vault_tls_dir itself to 0640 and
    # never touches a single certificate.
    if 'item' not in path:
        fail.append(f"staged-TLS enforcement path={path!r} is not the loop item; "
                    "it would converge one fixed path, not the staged trio")
    if 'vault_tls_dir' in path:
        fail.append(f"staged-TLS enforcement path={path!r} targets the DIRECTORY; "
                    "0640 on vault_tls_dir removes group traversal and breaks Vault")

    # --- state: touch would CREATE a zero-byte certificate where one is expected.
    if mod.get('state') != 'file':
        fail.append(f"staged-TLS enforcement state={mod.get('state')!r} != 'file' "
                    "(touch/absent/directory would create or destroy material)")

    # --- follow: the default is TRUE; leaving it unset rewrites a link's target.
    if mod.get('follow') is not False:
        fail.append(f"staged-TLS enforcement follow={mod.get('follow')!r}; must be "
                    "explicitly false (the module default is true, which rewrites "
                    "the symlink TARGET outside vault_tls_dir)")

    # --- bounds on a write driven by free-form path variables.
    if not re.search(r"not\s*\(?\s*vault_manage_tls", when):
        if 'vault_manage_tls' not in when:
            fail.append(f"staged-TLS enforcement when={when!r} does not reference "
                        "vault_manage_tls; it would double-apply with tasks/tls.yml")
        else:
            fail.append(f"staged-TLS enforcement when={when!r} references "
                        "vault_manage_tls but is not negated; polarity is inverted")
    if 'dirname' not in when or 'vault_tls_dir' not in when:
        fail.append(f"staged-TLS enforcement when={when!r} does not confine the "
                    "write to vault_tls_dir; an operator pointing vault_tls_ca_file "
                    "at a shared anchor would have it chgrp'd away from the host")
    if 'islnk' not in when:
        fail.append(f"staged-TLS enforcement when={when!r} does not exclude "
                    "symlinks; state: file aborts on a dangling or directory link")
    if 'exists' not in when:
        fail.append(f"staged-TLS enforcement when={when!r} does not require the "
                    "path to exist; state: file would fail the play at Phase 4")

# --- 3. The premise: tasks/tls.yml really is gated off on the default path.
# Without this the enforcement is redundant and the two fight over the files.
gated = False
for t in yaml.safe_load(open(os.path.join(root, 'tasks/main.yml'))) or []:
    if not isinstance(t, dict):
        continue
    inc = t.get('include_tasks') or t.get('ansible.builtin.include_tasks') or ''
    target = inc.get('file', '') if isinstance(inc, dict) else str(inc)
    if 'tls.yml' in target and 'vault_manage_tls' in when_text(t):
        gated = True
if not gated:
    fail.append("tasks/main.yml no longer gates tls.yml on vault_manage_tls; the "
                "premise of the system.yml enforcement is gone and the two would "
                "both write the staged trio")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print("ok - staged TLS trio converged to root:vault_group/vault_tls_file_mode, "
      "bounded to vault_tls_dir, symlinks excluded, tls.yml still gated")
PY
