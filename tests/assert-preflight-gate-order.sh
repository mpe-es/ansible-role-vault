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
# managed_tls sits immediately after tls because the two are exact mirrors:
# tls fires when vault_manage_tls is FALSE (the operator staged the material),
# managed_tls when it is TRUE (the role will place it). Adjacency keeps the
# inverted-polarity pair readable, and an operator reading the output sees the
# TLS question answered in one place whichever mode they are in (#80).
EXPECTED = [
    "os_family", "os_version", "fips", "selinux", "chrony", "firewalld",
    "rhsm", "repo_source", "tls", "managed_tls", "port", "dns",
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
# dns WAS advisory-only and is now a conditional hard gate (#79): it fails when
# the hostname resolves to no routable address AND the advertised addresses are
# still derived from that hostname. Its predicate is pinned here like any other;
# the residual warning for the pinned-address case is checked separately below.
# Every entry here is an exact condition list -- there is no
# "assert something" fallback, because a gate with no pinned predicate is a gate
# whose semantics nothing checks.
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
    # The whole point of #79: "length > 0" over the ROUTABLE set, never over the
    # raw resolver answer. `__vault_dns_check.rc == 0` would pass on a host whose
    # name resolves only to 127.0.1.1 -- which is the defect this gate replaced.
    "dns": ["__vault_dns_routable | length > 0"],
    # managed_tls was shipped without an entry here, which made it the only gate
    # in tasks/preflight/ whose semantics nothing pinned -- in the guard whose
    # own comment above forbids exactly that. `stat.readable` in particular was
    # deletable with every test and every guard green while README,
    # argument_specs and CHANGELOG all promised the source "must be readable".
    "managed_tls": ["item.stat is defined",
                    "item.stat.exists | default(false)",
                    "item.stat.isreg | default(false)",
                    "item.stat.readable | default(false)"],
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
    missing = [w for w in want if w not in conds]
    if missing:
        fail.append(f"tasks/preflight/{gate}.yml no longer asserts {missing!r}. "
                    f"Asserted conditions are {conds!r}. Molecule coverage for this "
                    f"gate is partial or absent, so nothing else reliably notices "
                    f"it being emptied.")

# dns POLARITY (#79). The predicate above proves the gate asks about routable
# addresses; these two checks prove it fires on the right hosts. The gate is a
# hard failure ONLY where the advertised addresses depend on the hostname, and a
# warning where the operator pinned them -- inverting either condition silently
# swaps which population is protected, and no behavioural case would notice on a
# container whose name resolves one particular way.
dns_path = os.path.join(root, "tasks", "preflight", "dns.yml")
if os.path.isfile(dns_path):
    with open(dns_path) as fh:
        dns_tasks = yaml.safe_load(fh) or []

    def _norm(v):
        return " ".join(str(v).split())

    # The DERIVATION, not just the variable name. Pinning only
    # "__vault_dns_routable | length > 0" leaves the set that name refers to
    # entirely free: deleting the reject filters, or reverting `getent ahosts`
    # to `getent hosts`, restores the exact "did resolution return an answer"
    # defect #79 removed -- with every guard green. Both were verified to
    # survive the first version of this lock.
    WANT_PROBE = "getent ahosts {{ ansible_fqdn }}"
    probes = [t for t in dns_tasks
              if _norm((t.get("ansible.builtin.command") or {}).get("cmd", "")) == WANT_PROBE]
    if not probes:
        fail.append("tasks/preflight/dns.yml no longer probes with exactly "
                    f"{WANT_PROBE!r}. `getent hosts` returns the FIRST match only "
                    "and prefers IPv6, so a loopback AAAA masks a routable A -- "
                    "which is the defect this gate was rewritten to remove.")

    # Each exclusion by exact filter form. Loopback is the case the gate exists
    # for; link-local is what a failed DHCP lease leaves behind, and an
    # advertised address on either is equally unreachable.
    # Each exclusion by exact filter form, INCLUDING the IPv4-mapped
    # normalisation. Codex found this list pinning a defective regex: `fe80:`
    # covers only fe80, while the IPv6 link-local range is fe80 THROUGH febf --
    # the first ten bits -- so fe90:: and febf:: were admitted as reachable, and
    # `::ffff:127.0.0.1` matched no IPv4 pattern at all. A lock that pins the
    # wrong predicate is worse than none: it certifies the defect.
    WANT_REJECTS = ["map('regex_replace', '^::[Ff]{4}:', '')",
                    "reject('match', '^127\\.')",
                    "reject('equalto', '::1')",
                    "reject('equalto', '0.0.0.0')",
                    "reject('match', '^169\\.254\\.')",
                    "reject('match', '^[Ff][Ee][89AaBb]')"]
    derivations = [_norm(v) for t in dns_tasks
                   for k, v in (t.get("ansible.builtin.set_fact") or {}).items()
                   if k == "__vault_dns_routable"]
    if not derivations:
        fail.append("tasks/preflight/dns.yml no longer derives __vault_dns_routable; "
                    "the predicate above pins a name with nothing behind it.")
    else:
        derivation = derivations[0]
        missing_rejects = [r for r in WANT_REJECTS if _norm(r) not in derivation]
        if missing_rejects:
            fail.append("tasks/preflight/dns.yml __vault_dns_routable no longer excludes "
                        f"{missing_rejects!r}. Without every exclusion the 'routable' set "
                        "admits an address nothing can reach, and the gate passes exactly "
                        f"the hosts it exists to fail. Derivation is: {derivation!r}")

    # The assert must be gated ON the dependency, so a host with explicitly
    # pinned addresses is never failed for a name it does not use.
    WANT_ASSERT_WHEN = "__vault_dns_required | bool"
    gated = [t for t in dns_tasks
             if ("ansible.builtin.assert" in t or "assert" in t)
             and _norm(t.get("when", "")) == WANT_ASSERT_WHEN]
    if not gated:
        fail.append("tasks/preflight/dns.yml no longer gates its assert on exactly "
                    f"{WANT_ASSERT_WHEN!r}. Ungated it fails operators who pinned "
                    "vault_api_addr/vault_cluster_addr and have no dependency on "
                    "the hostname resolving; inverted, it protects nobody.")

    # The residual warning must remain for the pinned-address population, and
    # must be conditioned on BOTH the absence of the dependency and the absence
    # of a routable address -- dropping either warns every host or none.
    WANT_WARN_WHEN = ["not (__vault_dns_required | bool)",
                      "__vault_dns_routable | length == 0"]
    warns = [t for t in dns_tasks
             if "ansible.builtin.debug" in t
             and [_norm(c) for c in (t.get("when") or [])] == WANT_WARN_WHEN
             and "WARNING" in str(t["ansible.builtin.debug"].get("msg", ""))]
    if not warns:
        fail.append("tasks/preflight/dns.yml no longer emits a WARNING conditioned on "
                    f"exactly {WANT_WARN_WHEN!r}. That warning is the entire contract "
                    "for hosts whose advertised addresses are pinned; nothing else "
                    "would notice it disappearing.")

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
