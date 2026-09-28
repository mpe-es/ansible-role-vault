#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-ha-init-orchestration.sh
# Role: ansible-role-vault
# Summary: Locks the #44 cluster orchestration in tasks/service.yml -- who
#          initializes, who gets the shared register, and who must not.
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS. There is no HA behaviour testing (operator ruling): CI proves
# configuration presence, not cluster formation. So nothing else catches a
# regression here. Each lock below corresponds to a failure that produced a GREEN
# play in measurement:
#   - init not host-scoped        -> every node initializes, N independent Vaults
#   - tokens.env on the local
#     register                    -> followers skip it, boot unseal exits 1
#   - capture on the shared
#     register                    -> the same root token in N directories
#   - audit enable unscoped       -> "path already in use", rescue, failed play
#   - no join wait                -> 400 "server is not yet initialized"
#   - seal-status verify no_log   -> the fail-fast diagnostic disappears
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import sys, yaml

root = sys.argv[1]
with open(f"{root}/tasks/service.yml") as fh:
    tasks = yaml.safe_load(fh) or []

fail = []
block = next((t for t in tasks if t.get("name") == "Initialize Vault" and "block" in t), None)
if block is None:
    sys.exit("FAIL: no 'Initialize Vault' block in tasks/service.yml")
inner = block["block"]

def find(pred):
    return [(i, t) for i, t in enumerate(inner) if pred(t)]

def whenstr(t):
    return " ".join(str(c) for c in (t.get("when") if isinstance(t.get("when"), list) else [t.get("when", "")]))

HOST_GATE = "inventory_hostname == __vault_init_host_effective"
SHARED = "__vault_init_source"
LOCAL = "__vault_init_output"

# 1. exactly one init, and it is host-scoped
init = find(lambda t: "operator init" in str(t.get("ansible.builtin.command", "")))
if len(init) != 1:
    fail.append(f"expected exactly one `operator init` task, found {len(init)}")
else:
    i_init, t_init = init[0]
    if HOST_GATE not in whenstr(t_init):
        fail.append("`operator init` is not scoped to the init host. Every node would "
                    "initialize itself, producing one independent Vault per node with a "
                    "green play.")

# 2. the validity assert precedes the durability include
inc = find(lambda t: "init-capture-durability" in str(t.get("ansible.builtin.include_tasks", "")))
val = find(lambda t: t.get("name") == "Validate the initialization host")
if not inc:
    fail.append("the init-capture durability include is gone")
elif not val:
    fail.append("no 'Validate the initialization host' assert")
elif val[0][0] > inc[0][0]:
    fail.append(f"the validity assert is at index {val[0][0]} but the durability include is at "
                f"{inc[0][0]}. An invalid init host would skip that fail-closed gate on every host.")

# 3. the batch assert exists and only guards runs about to initialize
batch = find(lambda t: t.get("name") == "Assert the initialization host is in this batch")
if not batch:
    fail.append("no in-batch assert; a serial or --limit run could initialize a second Vault")
elif "ansible_play_batch" not in " ".join(str(c) for c in batch[0][1].get("ansible.builtin.assert", {}).get("that", [])):
    fail.append("the in-batch assert does not test ansible_play_batch. ansible_play_hosts is the "
                "WHOLE play even under serial, so it cannot detect the split it guards.")
elif "not __vault_initialized" not in whenstr(batch[0][1]):
    fail.append("the in-batch assert is not gated on `not __vault_initialized`; it would fail "
                "serial runs on an already-initialized cluster, which is the day-2 workflow.")

# 4. The DATA expressions, not just the gates. A task can carry the right `when:`
# and still read the wrong register through vars:, loop: or environment:.
def datastr(t):
    parts = [str(t.get("vars", "")), str(t.get("loop", "")), str(t.get("environment", ""))]
    for k in ("ansible.builtin.template", "ansible.builtin.copy", "ansible.builtin.uri"):
        parts.append(str(t.get(k, "")))
    return " ".join(parts)

def one(frag):
    m = find(lambda t: frag in str(t.get("name", "")))
    if not m:
        fail.append(f"task matching {frag!r} not found")
        return None
    return m[0][1]

for frag, want_shared, why in [
    ("Store unseal shares on the node", True,
     "followers would skip it and files/vault-unseal.sh exits 1 at every boot"),
    ("Unseal the initialization host", True, "the leader would have no key source"),
    ("Unseal the remaining cluster nodes", True, "followers would have no key source"),
    ("Create controller capture directory", False,
     "N per-host directories would be created on the controller"),
    ("Capture root token", False,
     "the same root token would be written to N controller directories"),
    ("Capture Shamir unseal shares", False,
     "the same shares would be written to N controller directories"),
    ("Capture HSM recovery keys", False,
     "the same recovery keys would be written to N controller directories"),
]:
    t = one(frag)
    if t is None:
        continue
    both = whenstr(t) + " " + datastr(t)
    if want_shared:
        # BOTH halves must use the shared register. Checking "either" lets a vars:
        # or loop: revert hide behind a still-correct when:.
        if SHARED not in both:
            fail.append(f"{frag!r} does not read {SHARED}: {why}")
        if LOCAL in both:
            fail.append(f"{frag!r} still references {LOCAL}, which is a skipped dict on every "
                        f"host but the init host: {why}")
    elif SHARED in both:
        fail.append(f"{frag!r} reads {SHARED}: {why}")

# 5. both audit-enable tasks are init-host scoped (audit devices are cluster-wide)
audits = find(lambda t: "audit enable" in str(t.get("ansible.builtin.command", "")))
if len(audits) < 2:
    fail.append(f"expected two `audit enable` tasks (file and syslog), found {len(audits)}")
for i, t in audits:
    if HOST_GATE not in whenstr(t):
        fail.append(f"audit-enable task {t.get('name')!r} is not init-host scoped; the second "
                    f"node returns 'path already in use', rc!=0 with no failed_when, and the "
                    f"rescue fails the play.")

# 6. LEADER unseal -> join wait -> FOLLOWER unseal, in that order. A Shamir
# operator init leaves the node sealed, and a sealed node cannot serve the raft
# bootstrap challenge, so a wait placed before the leader unseal deadlocks.
lead = find(lambda t: "Unseal the initialization host" in str(t.get("name", "")))
wait = find(lambda t: t.get("name") == "Wait for this node to join the cluster")
foll = find(lambda t: "Unseal the remaining cluster nodes" in str(t.get("name", "")))
if not lead:
    fail.append("no leader unseal task; followers cannot join a sealed leader")
if not wait:
    fail.append("no join wait; a follower is unsealed before it has joined and Vault answers "
                "400 'server is not yet initialized'")
if not foll:
    fail.append("no follower unseal task; the cluster comes up as one unsealed leader")
if lead and wait and lead[0][0] > wait[0][0]:
    fail.append(f"the leader unseal is at index {lead[0][0]} but the join wait is at "
                f"{wait[0][0]}. A Shamir leader is sealed after init and cannot serve the raft "
                f"bootstrap challenge, so the wait would never satisfy and the play deadlocks.")
if wait and foll and wait[0][0] > foll[0][0]:
    fail.append("the join wait runs after the follower unseal")
if wait and "until" not in wait[0][1]:
    fail.append("the join wait has no `until` -- a single probe does not wait")
if lead and HOST_GATE not in whenstr(lead[0][1]):
    fail.append("the leader unseal is not scoped to the init host")
if foll and HOST_GATE.replace("==", "!=") not in whenstr(foll[0][1]):
    fail.append("the follower unseal is not scoped away from the init host")

# 7. both unseals respect the STATED desired state, not the seal type alone
for m, label in ((lead, "leader"), (foll, "follower")):
    if m and "vault_init_unseal" not in whenstr(m[0][1]):
        fail.append(f"the {label} unseal is not gated on vault_init_unseal. Desired state is "
                    f"stated, not inferred from the seal type.")

# 8. seal status carries no key material and must NOT be no_log
for frag in ("Verify Vault is unsealed", "Assert the unseal succeeded"):
    t = one(frag)
    if t is None:
        continue
    if t.get("no_log") is True:
        fail.append(f"{frag!r} sets no_log: true. Seal status carries no key material, and "
                    f"silencing it removes the fail-fast diagnostic.")

if fail:
    print("FAIL: #44 HA init orchestration")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print("ok: init is host-scoped; tokens.env and unseal read the shared register; capture and "
      "audit do not;\n    the join wait precedes the unseal; the unseal honours vault_init_unseal; "
      "seal status stays visible")
PYEOF
