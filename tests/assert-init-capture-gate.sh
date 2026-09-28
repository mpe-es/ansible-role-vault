#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-init-capture-gate.sh
# Role: ansible-role-vault
# Summary: The #94 durability gate must sit inside the vault_initialize block and
#          BEFORE `vault operator init`, and the capture tasks must stay no_log.
# Classification: UNCLASSIFIED
###############################################################################
# A gate that runs AFTER init leaves a Vault initialized with keys nobody holds --
# the exact outcome #94 exists to prevent -- and ordering is not something the
# runtime test can assert. No molecule scenario reaches here either: every
# scenario sets vault_initialize false or skips service_start.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import sys, yaml

root = sys.argv[1]
with open(f"{root}/tasks/service.yml") as fh:
    tasks = yaml.safe_load(fh) or []

fail = []
init_block = None
for t in tasks:
    if t.get("name") == "Initialize Vault" and "block" in t:
        init_block = t

if init_block is None:
    fail.append("no 'Initialize Vault' block found in tasks/service.yml")
else:
    when = str(init_block.get("when", ""))
    if "vault_initialize" not in when:
        fail.append(f"the Initialize Vault block is not gated on vault_initialize (when={when!r}); "
                    f"the durability gate would then run on the default path")
    inner = init_block["block"]
    gate_at = init_at = None
    for i, t in enumerate(inner):
        inc = t.get("ansible.builtin.include_tasks") or t.get("include_tasks")
        if inc:
            f = inc.get("file") if isinstance(inc, dict) else str(inc)
            if f and "init-capture-durability.yml" in str(f):
                gate_at = i
        for key in ("ansible.builtin.command", "command", "ansible.builtin.shell", "shell"):
            v = t.get(key)
            if v and "operator init" in str(v):
                init_at = i

    if gate_at is None:
        fail.append("tasks/service.yml does not include init-capture-durability.yml inside the "
                    "Initialize Vault block. Without it, an ephemeral controller captures the root "
                    "token and every unseal share and destroys them on exit, reporting success (#94).")
    elif init_at is None:
        fail.append("no `operator init` task found inside the Initialize Vault block")
    elif gate_at > init_at:
        fail.append(f"the durability gate is at index {gate_at} but `operator init` runs at {init_at}. "
                    f"A gate after init leaves a Vault initialized with keys nobody holds.")

    # no_log must not regress on the capture tasks while a guard is added around them.
    captures = []
    for t in inner:
        cp = t.get("ansible.builtin.copy") or t.get("copy")
        dest = str(cp.get("dest", "")) if cp else ""
        if cp and ("vault_init_capture_dir" in dest or "__vault_capture_host_dir" in dest):
            captures.append(t)
    if len(captures) < 3:
        fail.append(f"expected at least 3 capture copy tasks (root token, unseal shares, recovery "
                    f"keys); found {len(captures)}")
    for t in captures:
        if t.get("no_log") is not True:
            fail.append(f"capture task {t.get('name')!r} lost `no_log: true` -- key material would "
                        f"appear in job output")

# The findmnt probe carries failed_when: false, which DEFINES .failed as False,
# so only an explicit rc test discriminates (#66). Without it the gate passes
# when findmnt is missing -- exactly when durability is unproven.
with open(f"{root}/tasks/init-capture-durability.yml") as fh:
    gate = yaml.safe_load(fh) or []
probe = assertion = None
for t in gate:
    cmd = t.get("ansible.builtin.command") or t.get("command")
    if cmd and "findmnt" in str(cmd):
        probe = t
    a = t.get("ansible.builtin.assert") or t.get("assert")
    if a:
        assertion = a
if probe is None:
    fail.append("tasks/init-capture-durability.yml has no findmnt probe")
elif probe.get("check_mode") is not False:
    fail.append("the findmnt probe has no `check_mode: false`; the gate would not run under --check")
if assertion is None:
    fail.append("tasks/init-capture-durability.yml has no assert")
else:
    conds = " ".join(str(c) for c in assertion.get("that", []))
    if ".rc == 0" not in conds:
        fail.append("the durability assert does not test the findmnt probe's rc explicitly. "
                    "failed_when: false defines .failed as False, so without an rc test the gate "
                    "passes when findmnt is missing (#66).")
    if "__vault_ephemeral_fstypes" not in conds:
        fail.append("the durability assert does not compare against __vault_ephemeral_fstypes")

if fail:
    print("FAIL: #94 init capture durability gate")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print("ok: durability gate precedes operator init inside the vault_initialize block; "
      "captures stay no_log; the probe's rc is tested explicitly")
PYEOF
