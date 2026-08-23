#!/usr/bin/env bash
# Static structural lock for the preflight gate sequence (issue #36).
#
# Per-gate molecule cases cannot catch an orchestrator that omits a gate,
# reorders it, or loses a tag: they only exercise the gate files they name.
# A RUNTIME orchestrator check is not an option either -- executing
# tasks/preflight.yml hits the kernel-inherited FIPS and SELinux gates, which
# fail on a non-FIPS CI runner before the remaining gates are reached.
#
# So this is a static parse. It needs no container and runs in under a second.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT

python3 - <<'PY'
import os, sys, yaml

root = os.environ["ROOT"]
orch = os.path.join(root, "tasks", "preflight.yml")

# The canonical sequence. Order is load-bearing: cheap platform facts first, so
# an unsupported OS is reported as such rather than through a downstream gate's
# symptom, and rhsm precedes repo_source so an unregistered host is told it is
# not registered.
EXPECTED = [
    "os_family", "os_version", "fips", "selinux", "chrony", "firewalld",
    "rhsm", "repo_source", "tls", "port", "dns",
]
# A dynamic include does not propagate its own tags. With only apply: the
# include is skipped entirely under --tags; with only tags: the file is
# included but none of its tasks run. Both surfaces are required.
# apply: carries [preflight] ONLY -- mirroring [vault, preflight] would make
# --tags vault run the gates and then nothing else (the #28 trap).
WANT_TAGS = ["vault", "preflight"]
WANT_APPLY_TAGS = ["preflight"]

fail = []
with open(orch) as fh:
    tasks = yaml.safe_load(fh) or []

got = []
for t in tasks:
    inc = t.get("ansible.builtin.include_tasks") or t.get("include_tasks")
    if not inc:
        fail.append(f"non-include task in the orchestrator: {t.get('name')!r}")
        continue
    f = inc["file"] if isinstance(inc, dict) else inc
    gate = os.path.basename(f).removesuffix(".yml")
    got.append(gate)

    if t.get("tags") != WANT_TAGS:
        fail.append(f"{gate}: tags {t.get('tags')!r}, want {WANT_TAGS!r}")
    apply_tags = (inc.get("apply") or {}).get("tags") if isinstance(inc, dict) else None
    if apply_tags != WANT_APPLY_TAGS:
        fail.append(f"{gate}: apply.tags {apply_tags!r}, want {WANT_APPLY_TAGS!r}")

if got != EXPECTED:
    fail.append(f"gate sequence is\n    {got}\n  want\n    {EXPECTED}")

for gate in EXPECTED:
    p = os.path.join(root, "tasks", "preflight", gate + ".yml")
    if not os.path.isfile(p):
        fail.append(f"missing gate file: tasks/preflight/{gate}.yml")

# Existence is not enough. Molecule deliberately does not exercise fips or
# selinux -- a FIPS runner and an enforcing container are both out of reach --
# so emptying either file would stay CI-green with only the check above. Lock
# the conditions they actually assert.
# These are the predicates as they stand today, read from the files rather than
# assumed -- the first draft of this lock guessed them and was caught by its own
# report. #64 will make both conditional (a role must not be unusable on a host
# that is not STIG-hardened); this lock is expected to be updated THERE, in the
# same change that alters the gates, which is the point.
# Gates with no behavioural coverage in molecule/preflight are locked here
# instead. fips and selinux have no runner; os_family and os_version are never
# included directly by verify.yml, so emptying either while leaving the file
# present kept every guard and the whole scenario green.
#
# dns is deliberately absent from this map: it is ADVISORY by design (warn-only,
# documented as such in the README), so "must assert something" is the wrong
# requirement. What it must not lose is the warning itself, checked separately
# below.
WANT_PREDICATES = {
    "fips": ["(__vault_fips_status.content | b64decode | trim) == '1'"],
    "selinux": ["ansible_selinux.status == 'enabled'",
                "ansible_selinux.mode == 'enforcing'"],
    # Pinned to the EXACT conditions, not merely "asserts something": a semantic
    # mutation -- widening the family, or adding a version the role does not
    # support -- would otherwise pass CI, because no behavioural case can run on
    # a platform the container is not.
    "os_family": ["ansible_os_family == 'RedHat'"],
    "os_version": ["ansible_distribution_major_version in ['8', '9', '10']"],
}

def asserts_in(tasks):
    for t in tasks or []:
        a = t.get("ansible.builtin.assert") or t.get("assert")
        if a:
            yield t, a
        for key in ("block", "rescue", "always"):
            yield from asserts_in(t.get(key))

for gate, want in WANT_PREDICATES.items():
    path = os.path.join(root, "tasks", "preflight", gate + ".yml")
    if not os.path.isfile(path):
        continue
    with open(path) as fh:
        body = yaml.safe_load(fh) or []
    conds = [" ".join(str(c).split())
             for _, a in asserts_in(body)
             for c in (a.get("that") or [])]
    if want is None:
        # No pinned wording, but the gate must still assert SOMETHING that can
        # fail. An empty file, or one asserting only truisms, is the hole.
        TRIVIAL = {"true", "True", "1", "yes"}
        real = [c for c in conds if c not in TRIVIAL]
        if not real:
            fail.append(f"tasks/preflight/{gate}.yml asserts nothing that can fail "
                        f"(conditions: {conds!r}). This gate has no Molecule coverage, "
                        "so nothing else would notice it being emptied.")
        continue
    missing = [w for w in want if w not in conds]
    if missing:
        fail.append(f"tasks/preflight/{gate}.yml no longer asserts {missing!r}. "
                    f"Asserted conditions are {conds!r}. This gate has no Molecule "
                    f"coverage, so nothing else would notice it being emptied.")

# dns is advisory, so lock the ADVICE: a conditional warning that fires when
# resolution failed. Losing the `when:` would warn on every host; losing the
# task would drop the warning entirely, and neither is visible anywhere else.
dns_path = os.path.join(root, "tasks", "preflight", "dns.yml")
if os.path.isfile(dns_path):
    with open(dns_path) as fh:
        dns_tasks = yaml.safe_load(fh) or []
    # The DIRECTION, not merely that 'rc' appears: flipping `rc != 0` to
    # `rc == 0` warns every healthy host and stays silent on the failures the
    # advice exists for, and a substring check accepts both.
    WANT_DNS_WHEN = "__vault_dns_check.rc != 0"
    warns = [t for t in dns_tasks
             if "ansible.builtin.debug" in t
             and " ".join(str(t.get("when", "")).split()) == WANT_DNS_WHEN
             and "WARNING" in str(t["ansible.builtin.debug"].get("msg", ""))]
    if not warns:
        fail.append("tasks/preflight/dns.yml no longer emits a WARNING conditioned on "
                    f"exactly {WANT_DNS_WHEN!r}. It is advisory by design, so this warning is "
                    "the entire contract; nothing else would notice it disappearing.")

# tasks/main.yml must still route to the orchestrator under the same tags.
with open(os.path.join(root, "tasks", "main.yml")) as fh:
    for t in yaml.safe_load(fh) or []:
        inc = t.get("ansible.builtin.include_tasks") or t.get("include_tasks")
        f = (inc["file"] if isinstance(inc, dict) else inc) if inc else None
        if f == "preflight.yml":
            if "preflight" not in (t.get("tags") or []):
                fail.append("tasks/main.yml preflight include lost its preflight tag")
            break
    else:
        fail.append("tasks/main.yml no longer includes preflight.yml")

if fail:
    print("FAIL: preflight gate-order lock")
    for f in fail:
        print("  -", f)
    sys.exit(1)
print(f"ok - preflight gate order locked ({len(EXPECTED)} gates, tags verified)")
PY
