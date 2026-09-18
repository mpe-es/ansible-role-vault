#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-include-tags-apply.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #28 — every dynamic include in
#   tasks/main.yml must carry an `apply:` whose tags MIRROR the include's own
#   `tags:`, or tag-scoped runs execute nothing while reporting success.
#
#   `include_tasks` does not propagate its own tags to the tasks in the included
#   file; only `import_tasks` does. An include with `tags:` alone is therefore
#   selected by `--tags <phase>` -- the include task itself runs, so the output
#   looks right -- and then not one task inside it executes.
#
#   Measured on a live host before the fix:
#
#     --tags configure  ->  Gathering Facts / argspec / "Include Vault
#                           configuration tasks" and NOTHING ELSE.
#                           ok=3 changed=0 failed=0 -- a green run that
#                           configured nothing.
#     --tags stig       ->  "Include STIG hardening tasks" fires, then every
#                           subsequent task belongs to fapolicyd, which was the
#                           only include already carrying apply:.
#
#   An operator running `--tags stig` on a DoD host gets a green play and zero
#   hardening. That is the worst failure shape in this repository: it does not
#   look like a failure.
#
#   WHY MIRRORING IS CORRECT, and why the older warning no longer applies.
#   tasks/preflight.yml's header warns that mirroring both tags would make
#   `--tags vault` run the gates "and then nothing else -- a run that looks like
#   it worked". That was true only while the OTHER nine includes were broken:
#   the trap was the PARTIAL state, not the mirroring. With every include fixed,
#   `--tags vault` runs every phase, which is the intended meaning of that tag.
#
#   Nested includes need no second-level change. Measured with a throwaway
#   two-level role: an outer `apply:` propagates THROUGH a nested include into
#   its tasks, so tasks/preflight.yml's inner `apply: [preflight]` still yields
#   running gates under `--tags vault` once main.yml's include supplies it.
#   Tags accumulate down the chain.
# Usage: bash tests/assert-include-tags-apply.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, yaml

root = sys.argv[1]
MAIN = 'tasks/main.yml'
tasks = yaml.safe_load(open(os.path.join(root, MAIN))) or []
fail = []
seen = 0

for t in tasks:
    if not isinstance(t, dict):
        continue
    key = ('ansible.builtin.include_tasks' if 'ansible.builtin.include_tasks' in t
           else 'include_tasks' if 'include_tasks' in t else None)
    if key is None:
        continue
    seen += 1
    name = t.get('name', '<unnamed>')
    inc = t[key]

    if not isinstance(inc, dict):
        fail.append(f"{name}: `{key}` uses the bare-string form, which cannot carry "
                    f"`apply:`. Use the mapping form with file: and apply:.")
        continue

    own = t.get('tags')
    if not own:
        fail.append(f"{name}: include has no `tags:`, so it cannot be selected by "
                    f"any tag-scoped run at all")
        continue
    if isinstance(own, str):
        own = [own]

    applied = (inc.get('apply') or {}).get('tags')
    if not applied:
        fail.append(f"{name}: include carries tags {sorted(own)} but no `apply:` "
                    f"block, so --tags {sorted(own)[-1]!r} selects the INCLUDE and "
                    f"then runs none of its tasks -- a green run that did nothing "
                    f"(#28)")
        continue
    if isinstance(applied, str):
        applied = [applied]

    if sorted(applied) != sorted(own):
        fail.append(f"{name}: apply tags {sorted(applied)} do not mirror the "
                    f"include's own tags {sorted(own)}. Every tag that selects the "
                    f"include must also reach its tasks, or that tag produces a "
                    f"run that looks like it worked")

if seen == 0:
    print(f"FAIL - no include_tasks found in {MAIN}; this guard would pass vacuously")
    sys.exit(1)

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - all {seen} includes in {MAIN} apply their own tags to the tasks they include")
PY
