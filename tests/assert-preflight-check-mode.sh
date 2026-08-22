#!/usr/bin/env bash
# Every read-only probe in tasks/preflight/ must carry check_mode: false.
#
# ansible.builtin.command and .shell are SKIPPED under --check. A skipped probe
# registers rc 0 with empty stdout, and every assert downstream reads that as a
# healthy host: chrony reports no "Leap status: Normal" and fails a good host,
# while the port gate's ownership block never runs at all and a foreign listener
# passes. A dry run that greens a host it would have rejected is worse than no
# dry run. tasks/configure.yml carried the correct precedent before this.
#
# This is a CLASS lock, not a per-site one: the same omission shipped in six
# files at once, so checking the files individually is how it recurs.
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
if len(files) < 11:
    fail.append(f"expected at least 11 gate files, found {len(files)}")

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
