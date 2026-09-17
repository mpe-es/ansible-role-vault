#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-generator-lock-cooldown.sh
# Role: ansible-role-vault
# Summary: Enforces the repository's dependency cooldown floor on
#   requirements-generator.txt, and refuses yanked pins.
#
#   WHY THIS EXISTS. .github/dependabot.yml applies a 7-day floor to the pip
#   ecosystem so a malicious or yanked upstream release has time to be caught
#   before it is consumed. That same file IGNORES the generator stack by name,
#   because Dependabot would otherwise bump the generator without regenerating
#   the lock the generator produced -- silently breaking reproducibility. The
#   ignore is correct, but it removes the generator pins from the only
#   automated enforcement path they had. This guard is the replacement: the
#   floor stays a control rather than becoming a comment.
#
#   It is time-monotonic and therefore stable: a version that has cleared the
#   floor has cleared it forever, so this can only fail when someone introduces
#   a pin that is genuinely too fresh -- which is exactly the event it exists to
#   catch. (It caught nothing retroactively; it was written because a
#   ONE-DAY-OLD pyproject-hooks reached a commit on this very branch.)
#
# Usage: bash tests/assert-generator-lock-cooldown.sh
# Exit:  0 all pins clear the floor | 1 violation | 2 could not verify
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, re, json, datetime, urllib.request, urllib.error

root = sys.argv[1]
lock = os.path.join(root, 'requirements-generator.txt')
ddog = os.path.join(root, '.github', 'dependabot.yml')

if not os.path.exists(lock):
    print(f"FAIL: {lock} is missing -- the pinned generator toolchain is what makes")
    print("      requirements.txt reproducible. Restore it or drop this guard.")
    sys.exit(1)

# The floor is READ from dependabot.yml, never hardcoded here. One source of
# truth: raising the policy there tightens this guard automatically, and the two
# can never disagree.
try:
    import yaml
    with open(ddog) as fh:
        cfg = yaml.safe_load(fh)
    floors = [u['cooldown']['default-days'] for u in cfg.get('updates', [])
              if u.get('package-ecosystem') == 'pip' and 'cooldown' in u]
    if not floors:
        raise KeyError('no pip cooldown in dependabot.yml')
    floor = int(min(floors))
except Exception as exc:                                   # noqa: BLE001
    print(f"FAIL: cannot read the pip cooldown floor from {ddog}: {exc}")
    print("      This guard mirrors that policy; it must not invent its own.")
    sys.exit(1)

pins = re.findall(r'^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)', open(lock).read(), re.M)
if not pins:
    print(f"FAIL: parsed zero pins from {lock} -- this guard would pass vacuously.")
    sys.exit(1)

now = datetime.datetime.now(datetime.timezone.utc)
violations, yanked, unverified = [], [], []

for name, ver in sorted(pins):
    url = f"https://pypi.org/pypi/{name}/{ver}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
    except Exception as exc:                               # noqa: BLE001
        unverified.append((name, ver, str(exc)))
        continue
    files = data.get('urls') or []
    if not files:
        unverified.append((name, ver, 'no files listed on PyPI'))
        continue
    if any(f.get('yanked') for f in files):
        yanked.append((name, ver))
    ts = min(f['upload_time_iso_8601'] for f in files)
    up = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
    age = (now - up).total_seconds() / 86400.0
    flag = 'YANKED' if any(f.get('yanked') for f in files) else ''
    print(f"  {name:<18} {ver:<10} uploaded {up.date()}  age {age:7.2f}d  {flag}")
    if age < floor:
        violations.append((name, ver, age, up + datetime.timedelta(days=floor)))

# Unverifiable is NOT the same as clean. Fail closed, with a distinct exit code
# so an offline developer can tell "I could not check" from "this is too fresh".
if unverified:
    print()
    print("COULD NOT VERIFY -- treating as failure, because an unchecked pin is")
    print("not a cleared pin. Offline? Re-run where PyPI is reachable.")
    for name, ver, why in unverified:
        print(f"  {name}=={ver}: {why}")
    sys.exit(2)

rc = 0
if yanked:
    print()
    print("FAIL: the generator lock pins a YANKED release:")
    for name, ver in yanked:
        print(f"  {name}=={ver}")
    print("  Repin to a non-yanked release and regenerate the lock.")
    rc = 1

if violations:
    print()
    print(f"FAIL: {len(violations)} generator pin(s) inside the {floor}-day cooldown floor:")
    for name, ver, age, clears in violations:
        print(f"  {name}=={ver} is {age:.2f} days old; clears {clears:%Y-%m-%d %H:%M} UTC")
    print()
    print("  The floor exists so a malicious or yanked upstream release has time to")
    print("  be caught. It applies to INDIRECT dependencies too -- a transitive of a")
    print("  build tool is precisely where nobody looks.")
    print()
    print("  Fix: pin the offending package DOWN in requirements-generator.in to a")
    print("  release that has cleared the floor, then regenerate BOTH locks and")
    print("  confirm requirements.txt is unchanged. See requirements-generator.in.")
    rc = 1

if rc == 0:
    print()
    print(f"PASS: all {len(pins)} generator pins clear the {floor}-day floor; none yanked.")
sys.exit(rc)
PY
