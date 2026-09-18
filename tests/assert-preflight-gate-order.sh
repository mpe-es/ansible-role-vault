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
import os, re, sys, yaml

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
    "rhsm", "repo_source", "tls", "managed_tls", "san", "port", "dns",
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
    # Both halves pinned (#66). `content is defined` is what keeps the gate from
    # raising on a host where the read never happened, and the defaulted decode
    # is what keeps it from raising when content is absent. Dropping either
    # restores the crash-at-the-probe behaviour with a green guard.
    "fips": ["__vault_fips_status.content is defined",
             "(__vault_fips_status.content | default('') | b64decode | trim) == '1'"],
    "selinux": ["ansible_facts['selinux']['status'] == 'enabled'",
                "ansible_facts['selinux']['mode'] == 'enforcing'"],
    # Pinned to the EXACT conditions, not merely "asserts something": a semantic
    # mutation -- widening the family, or adding a version the role does not
    # support -- would otherwise pass CI, because no behavioural case can run on
    # a platform the container is not.
    "os_family": ["ansible_facts['os_family'] == 'RedHat'"],
    "os_version": ["ansible_facts['distribution_major_version'] in ['8', '9', '10']"],
    # The whole point of #79: "length > 0" over the ROUTABLE set, never over the
    # raw resolver answer. `__vault_dns_check.rc == 0` would pass on a host whose
    # name resolves only to 127.0.1.1 -- which is the defect this gate replaced.
    "dns": ["__vault_dns_routable | length > 0"],
    # managed_tls was shipped without an entry here, which made it the only gate
    # in tasks/preflight/ whose semantics nothing pinned -- in the guard whose
    # own comment above forbids exactly that. `stat.readable` in particular was
    # deletable with every test and every guard green while README,
    # argument_specs and CHANGELOG all promised the source "must be readable".
    # san sits immediately after managed_tls so the whole TLS question -- does
    # the material exist, and does it carry the SANs this role's callers need --
    # is answered in one place whichever mode is in use. Both halves pinned:
    # the loopback SAN is what tasks/service.yml and the unseal unit depend on,
    # and `stdout is defined` is what keeps the assert from raising on a host
    # where the read never happened.
    "san": ["__vault_san_raw.stdout is defined",
            "'127.0.0.1' in __vault_san_ip"],
    "managed_tls": ["item.stat is defined",
                    "item.stat.exists | default(false)",
                    "item.stat.isreg | default(false)",
                    "item.stat.readable | default(false)"],
}

def _norm(v):
    """Collapse whitespace so a folded scalar compares like a single line."""
    return " ".join(str(v).split())


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

# managed_tls: the predicate lock above pins WHAT the readable assert checks;
# this pins WHAT IT ITERATES. Every conjunct can be intact while the task loops
# an empty list, which asserts nothing about anything -- codex demonstrated that
# shape against the sibling dns classifier and it applies here identically.
mt_path = os.path.join(root, "tasks", "preflight", "managed_tls.yml")
if os.path.isfile(mt_path):
    with open(mt_path) as fh:
        mt_tasks = yaml.safe_load(fh) or []
    readable = [t for t, a in asserts_in(mt_tasks)
                if any("item.stat.readable" in _norm(str(c)) for c in (a.get("that") or []))]
    if not readable:
        fail.append("tasks/preflight/managed_tls.yml no longer asserts "
                    "item.stat.readable; the controller-side source could be "
                    "unreadable and the gate would still pass.")
    elif "__vault_managed_tls_stat" not in _norm(str(readable[0].get("loop", ""))):
        fail.append("tasks/preflight/managed_tls.yml readable assert no longer "
                    "iterates __vault_managed_tls_stat; its loop is "
                    f"{readable[0].get('loop')!r}. An empty loop asserts nothing "
                    "while every conjunct above stays intact.")

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

    # The DERIVATION, not just the variable name. Pinning only
    # "__vault_dns_routable | length > 0" leaves the set that name refers to
    # entirely free.
    #
    # Classification is now delegated to ansible.utils.ipaddr rather than
    # hand-rolled regexes -- three review rounds each defeated a regex
    # enumeration (::ffff:127.0.0.1, then ::, then 255.255.255.255), because
    # reachability is address arithmetic. What this locks is that the delegation
    # is still in place AND that the two checks the library provably does not
    # cover on its own are still present: netaddr does not unwrap IPv4-mapped
    # addresses, and it counts the unspecified and limited-broadcast addresses
    # as unicast.
    # EXACT TERMS, not substrings and not occurrence counts. Counting was the
    # previous approach and codex defeated it by appending ` or true` to one
    # condition: the substring still appeared the required number of times while
    # the check it named had been neutered. A whole-term match makes the text of
    # each condition the contract.
    #
    # Every class test appears TWICE -- once against the address as resolved and
    # once against its canonical (IPv4-unwrapped) form -- because netaddr does
    # not unwrap IPv4-mapped addresses, and because it converts '::1' to
    # '0.0.0.1', which is neither loopback nor non-unicast. Checking one form
    # only is what let ::ffff:224.0.0.1 and ::ffff:0.0.0.0 through.
    WANT_TERMS = [
        "(item | ansible.utils.ipaddr('unicast')) is truthy",
        "(__vault_dns_canon | ansible.utils.ipaddr('unicast')) is truthy",
        "(item | ansible.utils.ipaddr('loopback')) is falsy",
        "(__vault_dns_canon | ansible.utils.ipaddr('loopback')) is falsy",
        "(item | ansible.utils.ipaddr('link-local')) is falsy",
        "(__vault_dns_canon | ansible.utils.ipaddr('link-local')) is falsy",
        "(item | ansible.utils.ipaddr('multicast')) is falsy",
        "(__vault_dns_canon | ansible.utils.ipaddr('multicast')) is falsy",
        "__vault_dns_canon not in ['0.0.0.0', '255.255.255.255']",
        "item not in ['::', '0::0', '0:0:0:0:0:0:0:0']",
    ]
    classifiers = [t for t in dns_tasks
                   if "__vault_dns_routable" in str((t.get("ansible.builtin.set_fact") or {}))
                   and t.get("when")]
    if not classifiers:
        fail.append("tasks/preflight/dns.yml no longer derives __vault_dns_routable "
                    "under a when:; the predicate above pins a name with nothing "
                    "behind it.")
    else:
        got = [_norm(c) for c in (classifiers[0].get("when") or [])]
        for term in WANT_TERMS:
            if _norm(term) not in got:
                fail.append(f"tasks/preflight/dns.yml classification is missing the "
                            f"exact condition `{term}`. Conditions are: {got!r}")
        # The LOOP, not just the conditions. Every term above can be intact
        # while the task iterates an empty list, which passes a text-only lock
        # and makes the gate accept everything. Caught by the harness, but a
        # structural guard that ignores its own input is half a guard.
        loop_src = _norm(str(classifiers[0].get("loop", "")))
        for frag in ("__vault_dns_check.stdout_lines", "regex_replace"):
            if _norm(frag) not in loop_src:
                fail.append(f"tasks/preflight/dns.yml classification no longer loops "
                            f"over the resolver's own answer ({frag!r} absent). Its "
                            f"loop is: {loop_src!r}")

        # The canonical form must still be DERIVED, or every __vault_dns_canon
        # term above is testing an undefined variable.
        canon = _norm(str((classifiers[0].get("vars") or {}).get("__vault_dns_canon", "")))
        for frag in ("ansible.utils.ipaddr('ipv4')", "ansible.utils.ipaddr('address')"):
            if _norm(frag) not in canon:
                fail.append(f"tasks/preflight/dns.yml no longer builds "
                            f"__vault_dns_canon with {frag!r}. ipaddr('ipv4') returns "
                            "a CIDR, so without ipaddr('address') the bare-string "
                            "exclusions never match and mapped unspecified and "
                            f"broadcast addresses pass. Derivation is: {canon!r}")

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
