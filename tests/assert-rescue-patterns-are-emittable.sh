#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-rescue-patterns-are-emittable.sh
# Role: ansible-role-vault
# Summary: Every search() literal a rescue asserts on must be text THE GATE
#   UNDER TEST can actually emit.
#
#   tests/assert-verify-rescues-discriminate.sh proves a rescue's pattern does
#   not collide with its own scaffold message. That is one half. The other half
#   is whether the pattern matches anything the gate produces: a message that is
#   reworded, or a case left behind when the behaviour it asserted was removed,
#   leaves a rescue hunting for a string nothing emits. The assert then fails for
#   a reason unrelated to the gate, in CI, on every matrix cell.
#
#   SCOPE IS THE WHOLE POINT. An earlier version matched against every task file
#   concatenated together, which made it a uniqueness lottery: rewording
#   managed_tls's "not a regular file" left the guard green, because the sibling
#   tls gate emits the same phrase -- while the managed_tls case could only fail.
#   Each pattern is therefore matched against the ONE gate its case names in
#   `tasks_from:`, resolved by the nearest preceding include in the file.
#
#   THE CORPUS IS THE GATE'S MESSAGES, NOT ITS SOURCE TEXT. An earlier version
#   read the whole file, so a phrase surviving in a COMMENT counted as emitted:
#   rewording dns's "it does not resolve at all" left the guard green while the
#   harness case it backs went red, because the header comment still carried the
#   words. Messages are parsed out of fail_msg / success_msg / msg fields.
#
#   The literal is treated as a REGEX against a whitespace-normalised corpus.
#   Normalising the corpus (not the pattern) is what makes folded scalars
#   searchable -- a message wraps across source lines with indentation -- and
#   leaving the pattern untouched is what keeps a genuine regex, `rc \d+` or
#   `^Listen`, from being mangled into something unmatchable.
#
#   AN EXEMPTION MUST NAME WHAT IT DEPENDS ON. Text rendered at runtime cannot
#   be found statically, but declaring it must not disable the check: an earlier
#   version skipped RUNTIME_RENDERED patterns outright, so rewording
#   `{{ item.var }} is empty` left the guard green while the case it backs went
#   red. Every entry now carries the gate and the template fragment it renders
#   from, and that fragment is verified to still exist. Delete the template and
#   the exemption fails with it.
# Usage: bash tests/assert-rescue-patterns-are-emittable.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import glob
import os
import re
import sys

import yaml

root = sys.argv[1]

# Values rendered from a register or a loop variable at runtime. Keyed by the
# pattern; the value names where the text comes from.
RUNTIME_RENDERED = {
    # Fragments must CO-OCCUR IN ONE MESSAGE, not merely somewhere in the file.
    # managed_tls carries `{{ item.var }} is empty` in two different messages, so
    # a file-wide anchor let a reword of one be covered by the other -- codex
    # demonstrated exactly that. The source discriminator pins which message.
    "127.0.1.1": ("preflight/dns.yml",
                  ["__vault_dns_check.stdout_lines", "resolves to no reachable address"],
                  "the fail_msg interpolates the resolver's own answer"),
    "169.254.7.7": ("preflight/dns.yml",
                    ["__vault_dns_check.stdout_lines", "resolves to no reachable address"],
                    "the fail_msg interpolates the resolver's own answer"),
    "vault_tls_src_cert is empty": ("preflight/managed_tls.yml",
                                    ["vault_tls_source 'file'", "{{ item.var }} is empty"],
                                    "the variable NAME is the loop item, so the "
                                    "assertion proves the message names the right one"),
    "vault_pki_mount is empty": ("preflight/managed_tls.yml",
                                 ["vault_tls_source 'vault_pki'", "{{ item.var }} is empty"],
                                 "sibling of the above, pinned to the PKI message"),
    "not the vault-share service": ("preflight/port.yml",
                                    ["{{ vault_service_name }} service"],
                                    "the case sets a fixture service name to prove "
                                    "prefix matching does not accept a different unit"),
    "not the vault-shared service": ("preflight/port.yml",
                                     ["{{ vault_service_name }} service"],
                                     "sibling of the above"),
}


def messages(gate_path):
    """Whitespace-normalised join of every message a gate can EMIT.

    Comments are excluded by construction -- yaml.safe_load drops them -- which
    is the point: a phrase surviving in a comment is not text the gate emits.
    """
    def walk(tasks):
        for t in tasks or []:
            if not isinstance(t, dict):
                continue
            for v in t.values():
                if isinstance(v, dict):
                    for key in ("fail_msg", "success_msg", "msg"):
                        if key in v:
                            yield str(v[key])
            for k in ("block", "rescue", "always"):
                if k in t:
                    yield from walk(t[k])
    with open(gate_path) as fh:
        return [" ".join(str(m).split()) for m in walk(yaml.safe_load(fh) or [])]


# Files whose rescues assert on rendered artefacts rather than on a gate's
# message, so there is no `tasks_from:` to scope them to.
UNSCOPED_OK = {"molecule/default/verify.yml": "asserts on rendered config and "
                                              "unit content, not on gate messages"}

# Every file that drives gates through block/rescue. The local harness is
# included deliberately: it carries rescue literals too, and being the newest
# artifact it is where this defect class would rot unobserved.
sources = sorted(glob.glob(os.path.join(root, "molecule", "*", "verify.yml")) +
                 glob.glob(os.path.join(root, "tests", "local-preflight-harness", "*.yml")))

fail = []
checked = 0
scoped = 0
for path in sources:
    rel = os.path.relpath(path, root)
    body = open(path).read()
    # Where each `tasks_from:` sits, so a pattern can be attributed to the gate
    # its own case named.
    includes = [(m.start(), m.group(1))
                for m in re.finditer(r"tasks_from:\s*(\S+)", body)]
    for m in re.finditer(r"""is\s+search\(\s*(['"])(.+?)\1\s*\)""", body):
        literal = m.group(2)
        checked += 1
        if literal in RUNTIME_RENDERED:
            gate_rel, anchor, _why = RUNTIME_RENDERED[literal]
            gate_path = os.path.join(root, "tasks", gate_rel)
            if not os.path.isfile(gate_path):
                fail.append(f"RUNTIME_RENDERED[{literal!r}] names tasks/{gate_rel}, "
                            "which does not exist.")
            elif not any(all(" ".join(a.split()) in msg for a in anchor)
                         for msg in messages(gate_path)):
                fail.append(f"RUNTIME_RENDERED[{literal!r}] claims the text is "
                            f"rendered from {anchor!r} in tasks/{gate_rel}, but no "
                            "message there contains that template any more. The "
                            "exemption has outlived what it depended on, and the "
                            "case it backs can now only fail.")
            continue
        # Jinja string concatenation inside the pattern itself: the assertion
        # builds the expected text from a variable at runtime, so no static read
        # of the gate can contain it.
        if " ~ " in literal:
            continue
        prior = [g for pos, g in includes if pos < m.start()]
        if not prior:
            if rel in UNSCOPED_OK:
                continue
            fail.append(f"{rel}: search({literal!r}) has no preceding tasks_from:, "
                        "so it cannot be attributed to a gate. Scope the case, or "
                        "declare the file in UNSCOPED_OK with a reason.")
            continue
        gate = os.path.join(root, "tasks", prior[-1])
        if not os.path.isfile(gate):
            fail.append(f"{rel}: search({literal!r}) is scoped to {prior[-1]}, "
                        "which does not exist under tasks/.")
            continue
        scoped += 1
        corpus = " ".join(messages(gate))
        try:
            hit = re.search(literal, corpus)
        except re.error:
            hit = literal in corpus
        if not hit:
            fail.append(f"{rel}: rescue asserts search({literal!r}) but "
                        f"tasks/{prior[-1]} -- the gate that case runs -- cannot "
                        "emit that text. Either the message was reworded, or the "
                        "case outlived the behaviour it tested; the assert can now "
                        "only fail. If the value is rendered from a register, "
                        "declare it in RUNTIME_RENDERED.")

if checked == 0 or scoped == 0:
    fail.append(f"checked={checked} scoped={scoped} -- with no gate-scoped patterns "
                "this lock passes vacuously")

if fail:
    print("FAIL: rescue patterns that their own gate cannot emit")
    for x in fail:
        print("  -", x)
    sys.exit(1)
print(f"ok - all {checked} rescue search() patterns ({scoped} gate-scoped) are "
      "emittable by the gate their case runs")
PY
