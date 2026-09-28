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
# The rescue runs on the failure path, where printing the register for diagnosis is
# the obvious thing to reach for. Lock 8a sweeps it too. Empty today.
rescue = block.get("rescue") or []

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

# 8a. POSITIVE no_log lock. Any task whose gate, data or module args touch the root
# token or the key shares must carry no_log: true. Measured: without it the shares
# appear in the job output AND under --diff, and on this role that output is an AAP
# job log. The repo already asserts this for vault.hclic -- a licence file, far less
# sensitive -- at tests/assert-configure-gates-the-render.sh:81-86; the key-material
# tasks were never covered.
# Data expressions only. A task that merely GATES on the register's presence
# (`stdout | length > 0`) renders nothing and needs no no_log -- Warn left sealed is
# the case that distinguishes the two.
# __vault_init_data is how tokens.env.j2 receives the shares -- the literal key
# names never appear in that task, only in the template it renders.
# The WHOLE task, not datastr()'s module allow-list. That list names template, copy
# and uri; it misses a `debug: msg`, a `command: cmd`, an assert `fail_msg` and a
# `set_fact` -- all four module types already appear in this block, and a debug added
# during a bring-up incident is the likeliest of them. Measured: this selects the same
# nine tasks the allow-list did, with no false positives, because a task that only
# GATES on the register (Warn left sealed) names no key at all.
# datastr() is left alone: lock 4 asserts the ABSENCE of a register name, where
# widening the haystack would weaken it.
# `when` is excluded with `name`. A gate that merely TESTS the register renders
# nothing -- `Warn left sealed`, the capture directory, and the strategy:free guard
# all reference it only there -- so including `when` would demand no_log on tasks
# that print no key material and would hide the seal-status diagnostics.
def wholetask(t):
    return str({k: v for k, v in t.items() if k not in ("name", "when")})

# The REGISTER NAMES are in the list, not only the JSON field names. `debug: var=
# __vault_init_source` names no field and dumps the entire init output, root token
# included; keying on field names alone let that through.
KEY_MATERIAL = ("root_token", "unseal_keys_b64", "recovery_keys_b64",
                "__vault_init_data", "__vault_init_source", "__vault_init_output")
for t in inner + rescue:
    name = str(t.get("name", ""))
    renders_material = any(k in wholetask(t) for k in KEY_MATERIAL)
    # `operator init` renders nothing but its REGISTERED OUTPUT is the token and the
    # shares, so it is the one task that must be no_log for what it returns.
    registers_material = t.get("register") == "__vault_init_output"
    if not (renders_material or registers_material):
        continue
    if t.get("no_log") is not True:
        why = ("its registered output is the root token and every share"
               if registers_material else "it renders key material")
        fail.append(f"{name!r} has no `no_log: true` and {why}. Measured: without it the shares "
                    f"appear in the job output and under --diff, and on this role that output is "
                    f"an AAP job log.")

# WHAT THIS LOCK LEAVES TO RUNTIME, so a reader does not assume wider coverage:
# swapping /v1/sys/unseal for /v1/sys/seal, truncating the threshold slice, dropping
# the HSM exclusion from the leader unseal, and pointing the join wait at the wrong
# endpoint all fail LOUDLY on a real run -- via `Assert the unseal succeeded`, a 400 on
# a null key, or a 503 that outlasts the retries. None yields a green play over a wrong
# cluster, which is why they are not pinned statically here.

# 8b. seal status carries no key material and must NOT be no_log
for frag in ("Verify Vault is unsealed", "Assert the unseal succeeded",
             "Read this node's cluster identity", "Assert every cluster node reports"):
    t = one(frag)
    if t is None:
        continue
    if t.get("no_log") is True:
        fail.append(f"{frag!r} sets no_log: true. Seal status carries no key material, and "
                    f"silencing it removes the fail-fast diagnostic.")

# 9. `operator init` must stay host-scoped by `when`, never by run_once, and its
# changed_when must stay the rc test.
init = one("Run vault operator init")
if init is not None:
    if "run_once" in init:
        fail.append("`operator init` carries run_once. run_once picks the FIRST host of the "
                    "play, not the init host, and it propagates the registered root token and "
                    "shares to EVERY host -- which widens the controller capture to N "
                    "directories. Host scoping is the `when`, never run_once.")
    cw = str(init.get("changed_when", ""))
    if "__vault_init_output.rc" not in cw:
        fail.append(f"`operator init` changed_when is {cw!r}, not the rc test. Every capture "
                    f"task is gated on `__vault_init_output is changed`, so a constant-false "
                    f"changed_when silently skips the root-token and share capture after a "
                    f"SUCCESSFUL init -- the keys are then held nowhere.")

# 10. The status probe must run under --check. A skipped command still reports
# rc=0 with empty stdout, so the parse below it raises inside from_json and the
# rescue reports an initialization failure that never happened.
st = one("Check Vault initialization status")
if st is not None and st.get("check_mode") is not False:
    fail.append("`Check Vault initialization status` has no `check_mode: false`. Measured on "
                "core 2.21.4: under --check the command is skipped but still carries rc=0 with "
                "an EMPTY stdout, the rc gate passes, from_json('') raises, and the rescue "
                "reports a false initialization failure.")

# 11. The join wait must cover an HSM cluster. HSM nodes unseal themselves but
# still have to JOIN; excluding them let a follower with broken retry_join stay
# uninitialized under a green play.
jw = one("Wait for this node to join the cluster")
if jw is not None:
    w = whenstr(jw)
    if "not (vault_hsm_enabled" in w or "not vault_hsm_enabled" in w:
        fail.append("the join wait excludes HSM. Those nodes auto-unseal but still have to "
                    "JOIN the Raft cluster; excluding them means a follower that never joins "
                    "passes. Gate the seal TYPE like the audit tasks do: "
                    "`(vault_hsm_enabled | bool) or (vault_init_unseal | bool)`.")

# 12. A follower with no key material must FAIL, not skip. Without this,
# `strategy: free` lets a follower run ahead of the init host, read an empty
# register, skip every task below, and leave a sealed unjoined node under a green
# play. The condition must stay in `when:` so the task renders no register.
fr = one("Fail when the init host has produced no key material")
if fr is None:
    fail.append("the strategy:free guard is gone. Without it a follower that reaches this "
                "block before the init host reads an empty register and SKIPS the unseal, the "
                "join wait and every verification -- a sealed, unjoined node under a green play.")
else:
    w = whenstr(fr)
    if "length == 0" not in w or SHARED not in w:
        fail.append(f"the strategy:free guard no longer tests {SHARED} for emptiness in its "
                    f"`when`, so it cannot fire on the case it exists for.")
    if "ansible.builtin.fail" not in fr:
        fail.append("the strategy:free guard is not a `fail` task, so it cannot stop the play.")

# 13. Cross-node cluster identity. N independently initialized nodes each report
# initialized=true, so every gate above skips and the play is green over N
# separate Vaults with N key sets -- the exact failure #44 exists to prevent.
ci = one("Assert every cluster node reports the same Raft cluster")
if ci is None:
    fail.append("the cluster-identity assert is gone. Nothing else compares nodes: each keys "
                "on its OWN initialized flag, so N independent Vaults pass as one HA cluster.")
else:
    d = wholetask(ci)
    if "cluster_id" not in d:
        fail.append("the cluster-identity assert no longer reads cluster_id, which is the only "
                    "cross-node identity in seal-status.")
    if "hostvars[__vault_init_host_effective]" not in d:
        fail.append("the cluster-identity assert no longer compares against the INIT HOST, so "
                    "it compares a node with itself and always passes.")

# 14. The rescue must name the host that actually holds the capture. Capture runs
# on the init host alone, so a follower failure that cites inventory_hostname
# sends an operator to a directory that was never created.
# Searched across block AND rescue: this task lives in the rescue, where `one()`
# does not look.
_res = [t for t in (inner + rescue)
        if "Surface Vault initialization failure state" in str(t.get("name", ""))]
if not _res:
    fail.append("the rescue's 'Surface Vault initialization failure state' task is gone; the "
                "failure path no longer tells an operator where the root token was captured.")
for t in _res:
    d = str(t.get("ansible.builtin.fail", ""))
    if "vault_init_capture_dir" in d and "__vault_init_host_effective" not in d:
        fail.append("the rescue cites the capture directory without "
                    "__vault_init_host_effective. Capture happens on the init host only, so on "
                    "a follower failure this names a directory that does not exist -- during an "
                    "incident, for the root token.")

if fail:
    print("FAIL: #44 HA init orchestration")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print("ok: init is host-scoped; tokens.env and unseal read the shared register; capture and "
      "audit do not;\n    leader unseal precedes the wait precedes the follower unseal; both honour "
      "vault_init_unseal;\n    every key-material task is no_log; seal status stays visible")
PYEOF
