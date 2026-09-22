#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-configure-gates-the-render.sh
# Role: ansible-role-vault
# Summary: tasks/configure.yml must reach the edition gate BEFORE it renders
#          vault.hcl, and must deploy the licence with the declared posture.
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS. tasks/preflight/edition.yml is unreachable on a
# --tags configure or --skip-tags preflight run, and every converge molecule
# scenario takes exactly that path, so configure.yml includes the same gate
# before the render (#62). Nothing else locks that:
#   - no molecule scenario can fire it (they all now run an HSM-capable edition)
#   - assert-root-owned-posture.sh parses configure.yml for copy/template only
#   - assert-preflight-gate-order.sh reads tasks/preflight.yml
# Deleting the include leaves the entire suite green. So does loosening the
# licence file's mode, group or no_log -- a posture claimed in four documents
# and, before this guard, enforced by none.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import sys, yaml

root = sys.argv[1]
with open(f"{root}/tasks/configure.yml") as fh:
    tasks = yaml.safe_load(fh) or []

fail = []
gate_at = render_at = licence = None

for i, t in enumerate(tasks):
    inc = t.get("ansible.builtin.include_tasks") or t.get("include_tasks")
    if inc:
        f = inc.get("file") if isinstance(inc, dict) else str(inc)
        if f and "preflight/edition.yml" in str(f):
            gate_at = i
    tpl = t.get("ansible.builtin.template") or t.get("template")
    if tpl and "vault.hcl.j2" in str(tpl.get("src", "")):
        render_at = i
    cp = t.get("ansible.builtin.copy") or t.get("copy")
    if cp and "vault.hclic" in str(cp.get("dest", "")):
        licence = (i, t, cp)

if gate_at is None:
    fail.append("tasks/configure.yml does not include preflight/edition.yml. The "
                "edition gate is then unreachable on --tags configure and "
                "--skip-tags preflight, and a PKCS#11 seal can be rendered for a "
                "binary that cannot provide it (#62).")
elif render_at is None:
    fail.append("no template task rendering vault.hcl.j2 found in tasks/configure.yml")
elif gate_at > render_at:
    fail.append(f"the edition gate is included at index {gate_at} but vault.hcl is "
                f"rendered at {render_at}. A gate after the render does not gate it.")

# The #41 PIN lock. molecule/hsm/verify.yml asserts `'diff: false' in <the whole
# file>`, which stopped binding the moment the licence task added a SECOND
# `diff: false` (#42): deleting the vault.env one leaves that substring check
# green. Bind it per-task here, where the file is parsed rather than grepped.
env_task = None
for t in tasks:
    tpl = t.get("ansible.builtin.template") or t.get("template")
    if tpl and "vault_env_file" in str(tpl.get("dest", "")):
        env_task = t
if env_task is None:
    fail.append("no template task deploying vault_env_file found in tasks/configure.yml")
elif env_task.get("diff") is not False:
    fail.append("the vault.env deploy has no `diff: false`; VAULT_HSM_PIN could leak "
                "into --diff (#41). A whole-file substring check no longer catches "
                "this -- the licence task also carries diff: false.")

if licence is None:
    fail.append("no copy task deploying vault.hclic found in tasks/configure.yml (#42)")
else:
    i, t, cp = licence
    if cp.get("owner") != "root":
        fail.append(f"vault.hclic owner={cp.get('owner')!r}, expected 'root' (#38, #77)")
    if "vault_group" not in str(cp.get("group", "")):
        fail.append(f"vault.hclic group={cp.get('group')!r}, expected vault_group (#38, #77)")
    if str(cp.get("mode")) != "0640":
        fail.append(f"vault.hclic mode={cp.get('mode')!r}, expected '0640' -- it holds a licence")
    if t.get("no_log") is not True:
        fail.append("the vault.hclic deploy has no `no_log: true`; the licence would "
                    "appear in job output")
    if t.get("diff") is not False:
        fail.append("the vault.hclic deploy has no `diff: false`; the licence would "
                    "appear under --diff")

if fail:
    print("FAIL: configure.yml render gating / licence posture")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print("ok: edition gate precedes the render; vault.hclic is root:vault 0640, no_log, no diff")
PYEOF
