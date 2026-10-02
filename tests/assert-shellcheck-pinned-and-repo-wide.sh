#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-shellcheck-pinned-and-repo-wide.sh
# Role: ansible-role-vault
# Summary: CI's shellcheck is a pinned, digest-verified version, and it lints
#          every shell script in the repository without a CI edit.
# Usage: bash tests/assert-shellcheck-pinned-and-repo-wide.sh [ci.yml]
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CI="${1:-$ROOT/.github/workflows/ci.yml}"
python3 - "$CI" "$ROOT" <<'PYEOF'
import io, re, subprocess, sys, yaml

ci_path, root = sys.argv[1], sys.argv[2]
SHELL_SHEBANG = re.compile(r'^#!\s*(/usr)?/bin/(env\s+)?(ba|da|k)?sh\b')
fail = []


def uncommented(run):
    return "\n".join(l for l in run.splitlines() if not l.lstrip().startswith("#"))


steps = (yaml.safe_load(io.open(ci_path, encoding="utf-8"))["jobs"]["lint"].get("steps") or [])

install = [s for s in steps if "shellcheck" in uncommented(str(s.get("run", ""))) and "sha256sum -c" in str(s.get("run", ""))]
if len(install) != 1:
    fail.append(f"expected exactly one lint step that installs shellcheck and verifies its digest, found {len(install)}")
else:
    env = install[0].get("env") or {}
    if not re.fullmatch(r"v\d+\.\d+\.\d+", str(env.get("SHELLCHECK_VERSION", ""))):
        fail.append("SHELLCHECK_VERSION is not an exact vX.Y.Z pin")
    if not re.fullmatch(r"[0-9a-f]{64}", str(env.get("SHELLCHECK_SHA256", ""))):
        fail.append("SHELLCHECK_SHA256 is not a 64-hex SHA-256 digest")

runs = [uncommented(str(s.get("run", ""))) for s in steps]
linters = [r for r in runs if re.search(r'(^|[\s;&|])shellcheck\s+"\$\{scripts\[@\]\}"', r)]
if len(linters) != 1:
    fail.append(f"expected exactly one step that runs shellcheck over the discovered scripts, found {len(linters)}")
elif "tests/lib/list-shell-scripts.sh" not in linters[0]:
    fail.append("the shellcheck step does not take its file list from tests/lib/list-shell-scripts.sh")
for r in runs:
    for line in r.splitlines():
        if re.search(r'(^|[\s;&|])shellcheck\s+(?!"\$\{scripts|--version)\S', line):
            fail.append(f"shellcheck invoked on a hand-written file list: {line.strip()!r}")

tracked = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True,
                         capture_output=True).stdout.decode().split("\0")
expected = set()
for f in filter(None, tracked):
    try:
        with open(f"{root}/{f}", "rb") as fh:
            first = fh.readline().decode("utf-8", "replace")
    except (IsADirectoryError, FileNotFoundError):
        continue
    if f.endswith(".sh") or SHELL_SHEBANG.match(first):
        expected.add(f)

listed = subprocess.run(["bash", f"{root}/tests/lib/list-shell-scripts.sh"], check=True,
                        capture_output=True, text=True).stdout.split()
listed_set = set(listed)
if len(expected) < 3:
    fail.append(f"the oracle found only {len(expected)} shell script(s) -- its discovery has gone stale")
for f in sorted(expected - listed_set):
    fail.append(f"not linted: {f}")
for f in sorted(listed_set - expected):
    fail.append(f"listed but not a tracked shell script: {f}")
if len(listed) != len(listed_set):
    fail.append("the lister prints duplicates")

if fail:
    print("FAIL: CI shellcheck is not pinned and repo-wide")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print(f"ok - shellcheck is pinned and digest-verified, and lints all {len(expected)} tracked shell scripts")
PYEOF
