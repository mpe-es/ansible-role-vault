#!/usr/bin/env bash
# Guard against rescue assertions that match their OWN scaffold message
# (issue #36).
#
# The fires-case shape is: block -> include the gate -> fail("gate did not
# fire") ; rescue -> assert the gate's message names the right cause. If the
# rescue's search() pattern also matches the scaffold's fail message, the case
# passes when the gate does NOT fire -- false coverage that reads as proof.
# Two such cases shipped before this check existed; a mutation battery found
# one and a YAML parse found the second.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT

python3 - <<'PY'
import glob, os, re, sys, yaml

root = os.environ["ROOT"]
bad = []
for rel in ("molecule/preflight/verify.yml",):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        continue
    for play in yaml.safe_load(open(path)) or []:
        def walk(tl):
            for t in tl or []:
                if "block" in t and "rescue" in t:
                    scaffolds = [
                        str(b["ansible.builtin.fail"]["msg"])
                        for b in t["block"] if "ansible.builtin.fail" in b
                    ]
                    # An empty rescue contains no bad pattern and so passed,
                    # while the final message claimed every rescue asserts
                    # unique gate text. A rescue that asserts nothing swallows
                    # the failure entirely -- worse than a weak pattern.
                    # An assert whose conditions are trivially true is the
                    # same hole as no assert: `that: [true]` passes, and the
                    # rescue swallows the failure while looking like a check.
                    TRIVIAL = {"true", "True", "1", "yes", "[true]"}
                    real = [
                        r for r in t["rescue"]
                        if "ansible.builtin.assert" in r
                        and [c for c in (r["ansible.builtin.assert"].get("that") or [])
                             if " ".join(str(c).split()) not in TRIVIAL]
                    ]
                    if not real:
                        bad.append((rel, t.get("name", "?"),
                                    "<rescue asserts nothing that can fail>"))
                    for r in t["rescue"]:
                        a = r.get("ansible.builtin.assert") or {}
                        for cond in a.get("that", []):
                            for pat in re.findall(r"is search\('([^']+)'\)", str(cond)):
                                for sc in scaffolds:
                                    if re.search(pat, sc):
                                        bad.append((rel, t.get("name", "?"), pat))
                if "block" in t:
                    walk(t["block"])
        walk(play.get("tasks"))

# A search() argument containing literal {{ }} is not recursively rendered, so
# the pattern can never match the message it was written for and the assert
# silently degrades to whatever its other conjuncts say. Interpolate with ~.
jinja = []
for path in sorted(glob.glob(os.path.join(root, "molecule", "**", "*.yml"), recursive=True)):
    with open(path) as fh:
        for i, line in enumerate(fh, 1):
            if "search(" not in line:
                continue
            args = re.findall(r"search\(\s*'([^']*)'", line)
            args += re.findall(r'search\(\s*"([^"]*)"', line)
            for arg in args:
                if "{{" in arg:
                    jinja.append((os.path.relpath(path, root), i, arg))

if jinja:
    print("FAIL: search() patterns containing literal Jinja")
    for rel, i, arg in jinja:
        print(f"  - {rel}:{i}: {arg!r} is never rendered, so it cannot match.")
        print("      Use search('literal ' ~ var ~ ' literal') instead.")
    sys.exit(1)

if bad:
    print("FAIL: rescue assertions that match their own scaffold message")
    for rel, name, pat in bad:
        print(f"  - {rel}: {name}")
        if pat.startswith("<"):
            print(f"      {pat}")
        else:
            print(f"      pattern {pat!r} also matches the scaffold's fail msg")
    sys.exit(1)
print("ok - every rescue asserts text unique to the gate, not to the scaffold")
PY
