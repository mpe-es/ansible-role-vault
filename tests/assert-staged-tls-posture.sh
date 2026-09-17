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
#   Asserts a single file-module task in tasks/system.yml that:
#     - covers ALL THREE staged paths (cert, key, CA),
#     - sets owner root, group vault_group, mode vault_tls_file_mode,
#     - is guarded so it does NOT fight tasks/tls.yml on the managed path.
#
#   Deliberately structural and container-free: the behavioural proof is the
#   molecule/default fixture (staged root:root 0600, verified root:vault 0640),
#   which needs podman. This guard runs in the lint job and fails fast when the
#   enforcement is deleted or silently narrowed to fewer than three paths.
# Usage: bash tests/assert-staged-tls-posture.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, yaml

root = sys.argv[1]
STAGED = ('vault_tls_cert_file', 'vault_tls_key_file', 'vault_tls_ca_file')
fail = []

tasks = yaml.safe_load(open(os.path.join(root, 'tasks/system.yml'))) or []


def file_modules(ts):
    """Yield (task, module-args) for every file module, recursing block/rescue/always."""
    for t in ts or []:
        if not isinstance(t, dict):
            continue
        for m in ('file', 'ansible.builtin.file'):
            if isinstance(t.get(m), dict):
                yield t, t[m]
        for k in ('block', 'rescue', 'always'):
            if k in t:
                yield from file_modules(t[k])


# Locate the enforcement task by WHAT IT COVERS, not by its name: a name is
# cosmetic and renaming it must not silently disable this guard.
candidates = []
for task, mod in file_modules(tasks):
    loop = task.get('loop')
    if not isinstance(loop, list):
        continue
    blob = str(loop)
    covered = [v for v in STAGED if v in blob]
    if covered:
        candidates.append((task, mod, covered))

if not candidates:
    fail.append("tasks/system.yml: no file-module task loops over the staged TLS "
                "paths (vault_tls_cert_file/_key_file/_ca_file) — issue #77 "
                "enforcement is missing")
elif len(candidates) > 1:
    fail.append(f"tasks/system.yml: {len(candidates)} file-module tasks touch the "
                "staged TLS paths; expected exactly 1 so posture has one owner")
else:
    task, mod, covered = candidates[0]

    # All three, not a subset. A partial implementation must not pass.
    missing = [v for v in STAGED if v not in covered]
    if missing:
        fail.append(f"staged-TLS enforcement misses {', '.join(missing)} "
                    f"(covers only {len(covered)}/3)")

    # root:vault 0640 — the same pairing tasks/tls.yml applies on the managed
    # path and system.yml already applies to vault_tls_dir (#38).
    if mod.get('owner') != 'root':
        fail.append(f"staged-TLS enforcement owner={mod.get('owner')!r} != root "
                    "(#38: vault must not own what defines its posture)")
    if 'vault_group' not in str(mod.get('group', '')):
        fail.append(f"staged-TLS enforcement group={mod.get('group')!r} does not "
                    "resolve from vault_group")
    if 'vault_tls_file_mode' not in str(mod.get('mode', '')):
        fail.append(f"staged-TLS enforcement mode={mod.get('mode')!r} does not "
                    "resolve from vault_tls_file_mode (hardcoding drifts from vars)")

    # Must not fight tasks/tls.yml, which owns posture on the managed path.
    when = str(task.get('when', ''))
    if 'vault_manage_tls' not in when:
        fail.append(f"staged-TLS enforcement when={when!r} does not reference "
                    "vault_manage_tls; it would double-apply on the managed path")
    elif 'not' not in when:
        fail.append(f"staged-TLS enforcement when={when!r} references "
                    "vault_manage_tls but is not negated; polarity is inverted")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print("ok - staged TLS trio converged to root:vault_group/vault_tls_file_mode "
      "when the role does not manage TLS")
PY
