#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-lint-job-can-run-the-tests.sh
# Role: ansible-role-vault
# Summary: Any CI job that runs the behavioural suites must install the runtime
#          dependencies those suites exercise.
# Usage: bash tests/assert-lint-job-can-run-the-tests.sh [ci.yml]
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS. The lint job installed requirements-dev.txt only, with a
# comment stating it "needs no runtime deps". That was true while it only linted.
# It stopped being true when the behavioural suites were globbed into the same
# job, and nothing noticed until tests/peer-shape-table-test.sh -- which evaluates
# the REAL preflight expressions, and so needs netaddr for ansible.utils.ipaddr --
# went red in CI while passing on every developer machine, because a developer
# machine has the runtime deps installed.
#
# That is the same shape as the defect the behavioural glob itself was added to
# fix: a test that CI cannot actually execute is not coverage. So the rule is
# structural rather than a reminder -- a job that runs tests/*-test.sh must
# install requirements.txt in the same job.
set -euo pipefail
CI="${1:-$(cd "$(dirname "$0")/.." && pwd)/.github/workflows/ci.yml}"
python3 - "$CI" <<'PYEOF'
import io, re, sys, yaml

# `"requirements.txt" in body` is TRUE for a job that installs only
# requirements-dev.txt, because the one is a substring of the other -- so the first
# version of this guard passed on the very ci.yml whose defect it was written for.
# Anchored on a boundary instead.
RUNTIME_REQ = re.compile(r'(^|[\s/])requirements\.txt\b')


def uncommented(run):
    """Shell comments are prose. The ci.yml this guard was written for carried the
    literal words "so requirements.txt is not installed here" in a comment, which
    satisfied a check for requirements.txt -- a guard contented by the text of the
    very thing it forbids."""
    return "\n".join(l for l in run.splitlines() if not l.lstrip().startswith("#"))

path = sys.argv[1]
wf = yaml.safe_load(io.open(path, encoding="utf-8"))
jobs = wf.get("jobs") or {}
fail = []
runners = []

for name, job in jobs.items():
    steps = job.get("steps") or []
    body = "\n".join(uncommented(str(s.get("run", ""))) for s in steps)
    # Does this job execute the behavioural suites?
    if "tests/*-test.sh" not in body:
        continue
    runners.append(name)
    if not RUNTIME_REQ.search(body):
        fail.append(
            f"job {name!r} runs tests/*-test.sh but never installs requirements.txt. "
            f"The behavioural suites evaluate the role's REAL expressions, and "
            f"ansible.utils.ipaddr needs netaddr on the controller -- so the suite fails "
            f"in CI while passing on any machine that happens to have runtime deps.")

if not runners:
    print("FAIL - no job runs tests/*-test.sh, so either the suites are not in CI at all "
          "or this guard's discovery has gone stale; both are worse than a red build")
    sys.exit(1)

if fail:
    print("FAIL: CI cannot run the behavioural suites it globs")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print(f"ok - {len(runners)} job(s) run the behavioural suites ({', '.join(sorted(runners))}) "
      f"and each installs the runtime dependencies they exercise")
PYEOF
