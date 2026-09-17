#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-rescue-patterns-are-emittable.sh
# Role: ansible-role-vault
# Summary: Every search() literal a molecule rescue asserts on must be text the
#   role can ACTUALLY emit.
#
#   tests/assert-verify-rescues-discriminate.sh proves a rescue's pattern does
#   not collide with its own scaffold message. That is one half. The other half
#   is whether the pattern matches anything at all: a gate whose message is
#   reworded, or a case left behind when the behaviour it asserted was removed,
#   leaves a rescue hunting for a string nothing produces. The assert then fails
#   for a reason that has nothing to do with the gate under test.
#
#   This is not hypothetical. A review round found molecule/preflight/verify.yml
#   still carrying a case asserting `search('not an absolute path')` after the
#   gate stopped rejecting relative paths. Nothing emitted that string any more,
#   so the scenario failed in CI on every EL cell -- and no local guard noticed.
#
#   TWO normalisations are required or this lock is useless:
#     - Messages are FOLDED scalars, so a phrase wraps across source lines with
#       indentation. Whitespace is collapsed on both sides before comparing.
#     - Messages interpolate. `not the {{ vault_service_name }} service` cannot
#       be found by searching for `not the vault-share service`, so every
#       `{{ ... }}` in the corpus becomes a wildcard and the comparison is a
#       regex match, not a substring test.
#   A pattern that still cannot be matched is either a real defect or a value
#   rendered from a register, and the latter must be DECLARED below with its
#   source. Declaring one is a deliberate act; forgetting to is what this catches.
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

root = sys.argv[1]

# Text rendered from a REGISTER at runtime, which no static read of the source
# can contain. Each entry names where the value comes from.
RUNTIME_RENDERED = {
    "127.0.1.1": "dns fail_msg interpolates __vault_dns_check.stdout_lines",
    "169.254.7.7": "dns fail_msg interpolates __vault_dns_check.stdout_lines",
    "(?m)^Environment=RETENTION_DAYS=14$":
        "rendered unit content; 14 comes from vault_stig_audit_backup_retention_days, "
        "set non-default by molecule/default/converge.yml so the assertion proves "
        "the override flowed through the real template",
    "not the vault-share service":
        "port gate fail_msg interpolates vault_service_name; the case sets it to "
        "a fixture value to prove prefix matching does not pass a different unit",
    "not the vault-shared service":
        "port gate fail_msg interpolates vault_service_name; sibling of the above",
    "vault_tls_src_cert is empty":
        "managed_tls fail_msg is '{{ item.var }} is empty'; the variable NAME is "
        "the loop item, so the assertion proves the message names the right one",
    "vault_pki_mount is empty":
        "managed_tls fail_msg is '{{ item.var }} is empty'; sibling of the above",
}

# The role's own message sources. templates/ is included because molecule cases
# also assert on rendered unit/config content.
corpus_files = []
for pat in ("tasks/**/*.yml", "templates/**/*"):
    corpus_files += glob.glob(os.path.join(root, pat), recursive=True)

corpus = "\n".join(open(f, errors="replace").read()
                   for f in sorted(corpus_files) if os.path.isfile(f))

fail = []
checked = 0
for vpath in sorted(glob.glob(os.path.join(root, "molecule", "*", "verify.yml"))):
    body = open(vpath).read()
    rel = os.path.relpath(vpath, root)
    for m in re.finditer(r"""is\s+search\(\s*(['"])(.+?)\1\s*\)""", body):
        literal = m.group(2)
        checked += 1
        if literal in RUNTIME_RENDERED:
            continue
        # Jinja string concatenation inside the pattern itself is runtime by
        # construction; the assertion builds it from a variable.
        if " ~ " in literal:
            continue
        probe = " ".join(literal.replace("\\", "").split())
        probe = re.sub(r"^\(\?m\)\^?|\$$", "", probe)
        # CONTIGUOUS phrase, with whitespace the only flexibility. An earlier
        # version joined the words with `.*?` to be tolerant of interpolation,
        # which made the lock vacuous: across a corpus this size, almost any
        # four words match in order somewhere. It passed its own negative
        # control, which is how that was found. Interpolated text belongs in
        # RUNTIME_RENDERED, not in a looser regex.
        phrase = r"\s+".join(re.escape(w) for w in probe.split())
        if not re.search(phrase, corpus):
            fail.append(f"{rel}: rescue asserts search({literal!r}) but nothing in "
                        "tasks/ or templates/ can emit that text. Either the "
                        "message was reworded, or the case outlived the behaviour "
                        "it tested -- the assert can now only fail. If the value is "
                        "rendered from a register, declare it in RUNTIME_RENDERED.")

if checked == 0:
    fail.append("no search() patterns found in any molecule verify.yml -- this "
                "lock would pass vacuously")

if fail:
    print("FAIL: rescue patterns that nothing can emit")
    for x in fail:
        print("  -", x)
    sys.exit(1)
print(f"ok - all {checked} rescue search() patterns are emittable by the role")
PY
