#!/usr/bin/env bash
# Every read-only probe in tasks/preflight/ must carry check_mode: false.
#
# ansible.builtin.command and .shell are SKIPPED under --check. A skipped probe
# registers rc 0 with empty stdout, and downstream asserts misread that in BOTH
# directions -- either is wrong, and they are not the same wrong:
#   - FALSE NEGATIVE: the port gate's ownership block never runs, so a foreign
#     listener passes. A dry run that greens a host it would have rejected is
#     worse than no dry run.
#   - FALSE POSITIVE: chrony sees no "Leap status: Normal" in the empty output
#     and fails a perfectly healthy host.
# tasks/configure.yml carried the correct precedent before this.
#
# This is a CLASS lock, not a per-site one: the same omission shipped across
# every probe at once, so checking sites individually is how it recurs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT

python3 - <<'PY'
import glob, os, sys, yaml

root = os.environ["ROOT"]
fail = []

def walk(tasks):
    for t in tasks or []:
        yield t
        for key in ("block", "rescue", "always"):
            yield from walk(t.get(key))

files = sorted(glob.glob(os.path.join(root, "tasks", "preflight", "*.yml")))
# The EXACT set, not a floor: ">= 11" would let a twelfth leftover gate file sit
# in the directory unreferenced by the orchestrator, which is precisely what a
# split leaves behind.
CANONICAL = {"os_family", "os_version", "fips", "edition", "selinux", "chrony", "firewalld",
             "rhsm", "repo_source", "tls", "managed_tls", "san", "port", "dns"}
found = {os.path.basename(f)[:-4] for f in files}
if found != CANONICAL:
    extra, missing = sorted(found - CANONICAL), sorted(CANONICAL - found)
    fail.append(f"tasks/preflight/ does not hold exactly the canonical gates. "
                f"unexpected: {extra or 'none'}; missing: {missing or 'none'}")

probes = 0
for path in files:
    with open(path) as fh:
        body = yaml.safe_load(fh) or []
    for t in walk(body):
        if "ansible.builtin.command" not in t and "ansible.builtin.shell" not in t:
            continue
        probes += 1
        if t.get("check_mode") is not False:
            fail.append(f"tasks/preflight/{os.path.basename(path)}: "
                        f"{t.get('name', '?')!r} has no check_mode: false, so under "
                        "--check it is skipped and registers rc 0 with empty output.")

if probes == 0:
    fail.append("no command/shell probes found under tasks/preflight/ -- this lock "
                "would pass vacuously; the parse is probably wrong.")

if fail:
    print("FAIL: preflight probes under --check")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print(f"ok - all {probes} preflight command/shell probes run under --check")
PY
