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
elif "not __vault_initialized" not in whenstr(batch[0][1]):
    fail.append("the in-batch assert is not gated on `not __vault_initialized`; it would fail "
                "serial runs on an already-initialized cluster, which is the day-2 workflow.")

# 4. tokens.env and unseal read the SHARED register; capture and audit do NOT
def gate_of(name_fragment):
    m = find(lambda t: name_fragment in str(t.get("name", "")))
    return (m[0][1], whenstr(m[0][1])) if m else (None, None)

for frag, want_shared, why in [
    ("Store unseal shares on the node", True,
     "followers would skip it and files/vault-unseal.sh exits 1 at every boot"),
    ("Unseal Vault after initialization", True,
     "followers would have no key source"),
    ("Capture root token", False,
     "the same root token would be written to N controller directories"),
    ("Capture Shamir unseal shares", False,
     "the same shares would be written to N controller directories"),
]:
    t, g = gate_of(frag)
    if t is None:
        fail.append(f"task matching {frag!r} not found")
        continue
    has = SHARED in g
    if want_shared and not has:
        fail.append(f"{frag!r} does not read {SHARED}: {why}")
    if not want_shared and has:
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

# 6. a join wait precedes the unseal
wait = find(lambda t: t.get("name") == "Wait for this node to join the cluster")
uns = find(lambda t: "Unseal Vault after initialization" in str(t.get("name", "")))
if not wait:
    fail.append("no join wait; a follower is unsealed before it has joined and Vault answers "
                "400 'server is not yet initialized'")
elif uns and wait[0][0] > uns[0][0]:
    fail.append("the join wait runs after the unseal")
elif "until" not in wait[0][1]:
    fail.append("the join wait has no `until` -- a single probe does not wait")

# 7. follower unseal respects the STATED desired state
if uns and "vault_init_unseal" not in whenstr(uns[0][1]):
    fail.append("the unseal is not gated on vault_init_unseal. Desired state is stated, not "
                "inferred from the seal type: vault_init_unseal=false means leave it sealed.")

# 8. seal status carries no key material and must NOT be no_log
for frag in ("Verify Vault is unsealed", "Assert the unseal succeeded"):
    t, _ = gate_of(frag)
    if t is not None and t.get("no_log") is True:
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
