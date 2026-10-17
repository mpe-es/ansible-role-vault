#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-core-pin-coupling.sh
# Role: ansible-role-vault
# Summary: Fail closed when a coupled Ansible Core update leaves any consumer
#          or the secret-bearing release job on a different toolchain.
# Usage: bash tests/assert-core-pin-coupling.sh [--check-root <repository>]
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK_ONLY=0
if [ "${1:-}" = "--check-root" ]; then
    ROOT="${2:?--check-root requires a repository path}"
    CHECK_ONLY=1
fi

check_root() {
    python3 - "$1" <<'PYEOF'
import io
import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
fail = []


def read(name):
    path = root / name
    if not path.is_file():
        fail.append(f"missing required coupled-pin file: {name}")
        return ""
    return path.read_text(encoding="utf-8")


def exact_pin(text, name):
    pins = re.findall(r"(?m)^ansible-core==([0-9]+(?:\.[0-9]+){2})\s*$", text)
    if len(pins) != 1:
        fail.append(f"{name} must contain exactly one standalone ansible-core==X.Y.Z pin; found {pins}")
        return None
    return pins[0]


def lock_pin(text, name, package):
    pins = re.findall(rf"(?m)^{re.escape(package)}==([0-9]+(?:\.[0-9]+){{2}})\s+\\$", text)
    if len(pins) != 1:
        fail.append(f"{name} must contain exactly one hash-locked {package}==X.Y.Z entry; found {pins}")
        return None
    return pins[0]


dev_in = read("requirements-dev.in")
release_in = read("requirements-release.in")
dev_lock = read("requirements-dev.txt")
release_lock = read("requirements-release.txt")
pre_commit_text = read(".pre-commit-config.yaml")
ci_text = read(".github/workflows/ci.yml")
release_text = read(".github/workflows/release.yml")
dependabot_text = read(".github/dependabot.yml")

core = exact_pin(dev_in, "requirements-dev.in")
release_source = exact_pin(release_in, "requirements-release.in")
dev_core = lock_pin(dev_lock, "requirements-dev.txt", "ansible-core")
release_core = lock_pin(release_lock, "requirements-release.txt", "ansible-core")
lint_lock = lock_pin(dev_lock, "requirements-dev.txt", "ansible-lint")

values = {
    "requirements-release.in": release_source,
    "requirements-dev.txt": dev_core,
    "requirements-release.txt": release_core,
}
for place, value in values.items():
    if core and value and value != core:
        fail.append(f"ansible-core drift: requirements-dev.in is {core}, {place} is {value}")

try:
    pre_commit = yaml.safe_load(pre_commit_text) or {}
except yaml.YAMLError as exc:
    fail.append(f"cannot parse .pre-commit-config.yaml: {exc}")
    pre_commit = {}

hooks = []
for repo in pre_commit.get("repos", []) or []:
    if str(repo.get("repo", "")).rstrip("/").endswith("ansible-lint"):
        hooks.extend(repo.get("hooks") or [])
if len(hooks) != 1:
    fail.append(f"expected exactly one ansible-lint pre-commit hook, found {len(hooks)}")
else:
    hook = hooks[0]
    deps = hook.get("additional_dependencies") or []
    expected = f"ansible-core=={core}" if core else None
    if expected not in deps:
        fail.append(f"pre-commit additional_dependencies must contain {expected!r}; found {deps!r}")
    repo = next(r for r in pre_commit["repos"] if str(r.get("repo", "")).rstrip("/").endswith("ansible-lint"))
    expected_rev = f"v{lint_lock}" if lint_lock else None
    if repo.get("rev") != expected_rev:
        fail.append(f"pre-commit ansible-lint rev must be {expected_rev!r}; found {repo.get('rev')!r}")

try:
    ci = yaml.safe_load(ci_text) or {}
    release = yaml.safe_load(release_text) or {}
    dependabot = yaml.safe_load(dependabot_text) or {}
except yaml.YAMLError as exc:
    fail.append(f"cannot parse workflow YAML: {exc}")
    ci, release, dependabot = {}, {}, {}

ci_python = str((ci.get("env") or {}).get("PYTHON_VERSION", ""))
release_steps = ((release.get("jobs") or {}).get("release") or {}).get("steps") or []
setup = [s for s in release_steps if str(s.get("uses", "")).startswith("actions/setup-python@")]
if len(setup) != 1:
    fail.append(f"expected exactly one release setup-python step, found {len(setup)}")
else:
    release_python = str((setup[0].get("with") or {}).get("python-version", ""))
    if not ci_python or release_python != ci_python:
        fail.append(f"Python drift: CI uses {ci_python!r}; release uses {release_python!r}")

if len(hooks) == 1 and ci_python and hooks[0].get("language_version") != f"python{ci_python}":
    fail.append(
        f"Python drift: CI uses {ci_python!r}; ansible-lint pre-commit uses "
        f"{hooks[0].get('language_version')!r}")

release_runs = "\n".join(str(step.get("run", "")) for step in release_steps)
if not re.search(r"pip\s+install\s+--require-hashes\s+-r\s+requirements-release\.txt\b", release_runs):
    fail.append("release job must install only hash-pinned requirements-release.txt")
if "requirements-dev.txt" in release_runs:
    fail.append("release job must not install requirements-dev.txt while holding GALAXY_API_KEY")
if re.search(r"pip\s+install\s+--upgrade\s+pip", release_runs):
    fail.append("release job must not resolve an unpinned pip upgrade while holding GALAXY_API_KEY")

pip_updates = [
    update for update in dependabot.get("updates", []) or []
    if update.get("package-ecosystem") == "pip" and update.get("directory") == "/"
]
if len(pip_updates) != 1:
    fail.append(f"expected exactly one root pip Dependabot update, found {len(pip_updates)}")
else:
    pip_update = pip_updates[0]
    groups = pip_update.get("groups") or {}
    core_group = groups.get("ansible-core") or {}
    if core_group.get("patterns") != ["ansible-core"]:
        fail.append("Dependabot must isolate ansible-core in its own exact group")
    python_group = groups.get("python-deps") or {}
    if "ansible-core" not in (python_group.get("exclude-patterns") or []):
        fail.append("Dependabot python-deps group must exclude ansible-core")
    for ignored in pip_update.get("ignore", []) or []:
        if ignored.get("dependency-name") == "ansible-core":
            fail.append("Dependabot must not ignore ansible-core security updates")

if fail:
    print("FAIL: Ansible Core coupling is incomplete")
    for item in fail:
        print(f"  - {item}")
    raise SystemExit(1)
print(f"ok - Ansible Core {core} is coupled across development, release, CI, and pre-commit")
PYEOF
}

check_root "$ROOT"

if [ "$CHECK_ONLY" -eq 1 ]; then
    exit 0
fi

# Negative controls: every parsed coupling surface must prove that it can make
# the same guard fail. A fresh fixture per case preserves one-to-one evidence.
current_core="$(awk -F== '/^ansible-core==/ {print $2}' "$ROOT/requirements-dev.in")"
current_lint="$(awk -F'[ =\\\\]+' '/^ansible-lint==/ {print $2}' "$ROOT/requirements-dev.txt")"
fixture=""

cleanup_fixture() {
    if [ -n "$fixture" ] && [ -d "$fixture" ]; then
        rm -rf -- "$fixture"
    fi
    fixture=""
}
trap cleanup_fixture EXIT

make_fixture() {
    local fixture_path
    cleanup_fixture
    fixture="$(mktemp -d)"
    for fixture_path in requirements-dev.in requirements-release.in requirements-dev.txt \
                        requirements-release.txt .pre-commit-config.yaml \
                        .github/workflows/ci.yml .github/workflows/release.yml \
                        .github/dependabot.yml; do
        mkdir -p "$fixture/$(dirname "$fixture_path")"
        cp "$ROOT/$fixture_path" "$fixture/$fixture_path"
    done
}

negative_control() {
    local name="$1" path="$2" old="$3" new="$4" expected_failure="$5"
    local output
    make_fixture
    if ! output="$(bash "$0" --check-root "$fixture" 2>&1)"; then
        echo "FAIL: coupling fixture is invalid before mutation: $name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    python3 - "$fixture/$path" "$old" "$new" <<'PYEOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old, new = sys.argv[2:]
text = path.read_text(encoding="utf-8")
count = text.count(old)
if count != 1:
    raise SystemExit(f"fixture anchor must occur exactly once in {path}: {old!r} occurred {count} times")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PYEOF
    if output="$(bash "$0" --check-root "$fixture" 2>&1)"; then
        echo "FAIL: coupling guard accepted mutation: $name" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected_failure" <<<"$output"; then
        echo "FAIL: coupling guard rejected mutation for the wrong reason: $name" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    echo "ok - coupling guard rejects mutated $name: $expected_failure"
    cleanup_fixture
}

negative_control "development source pin" "requirements-dev.in" \
    "ansible-core==${current_core}" "ansible-core==0.0.0" "ansible-core drift:"
negative_control "release source pin" "requirements-release.in" \
    "ansible-core==${current_core}" "ansible-core==0.0.0" "ansible-core drift:"
negative_control "development lock pin" "requirements-dev.txt" \
    "ansible-core==${current_core}" "ansible-core==0.0.0" "ansible-core drift:"
negative_control "release lock pin" "requirements-release.txt" \
    "ansible-core==${current_core}" "ansible-core==0.0.0" "ansible-core drift:"
negative_control "pre-commit Core pin" ".pre-commit-config.yaml" \
    "ansible-core==${current_core}" "ansible-core==0.0.0" "pre-commit additional_dependencies"
negative_control "ansible-lint lock pin" "requirements-dev.txt" \
    "ansible-lint==${current_lint}" "ansible-lint==0.0.0" "pre-commit ansible-lint rev"
negative_control "pre-commit ansible-lint revision" ".pre-commit-config.yaml" \
    "rev: v${current_lint}" "rev: v0.0.0" "pre-commit ansible-lint rev"
negative_control "CI Python version" ".github/workflows/ci.yml" \
    'PYTHON_VERSION: "3.12"' 'PYTHON_VERSION: "3.13"' "Python drift:"
negative_control "release Python version" ".github/workflows/release.yml" \
    "python-version: '3.12'" "python-version: '3.13'" "Python drift:"
negative_control "pre-commit Python version" ".pre-commit-config.yaml" \
    "language_version: python3.12" "language_version: python3.13" "Python drift:"
negative_control "Dependabot Core group" ".github/dependabot.yml" \
    $'ansible-core:\n        patterns:\n          - "ansible-core"' \
    $'ansible-core-disabled:\n        patterns:\n          - "ansible-core"' \
    "Dependabot must isolate ansible-core"
negative_control "release development lock install" ".github/workflows/release.yml" \
    "pip install --require-hashes -r requirements-release.txt" \
    $'pip install --require-hashes -r requirements-release.txt\n          pip install -r requirements-dev.txt' \
    "release job must not install requirements-dev.txt"
negative_control "release unpinned pip upgrade" ".github/workflows/release.yml" \
    "pip install --require-hashes -r requirements-release.txt" \
    $'pip install --require-hashes -r requirements-release.txt\n          python -m pip install --upgrade pip' \
    "release job must not resolve an unpinned pip upgrade"
negative_control "Dependabot python-deps exclusion" ".github/dependabot.yml" \
    $'python-deps:\n        patterns:\n          - "*"\n        exclude-patterns:\n          - "ansible-core"' \
    $'python-deps:\n        patterns:\n          - "*"\n        exclude-patterns:\n          - "not-ansible-core"' \
    "Dependabot python-deps group must exclude ansible-core"
negative_control "Dependabot ignore" ".github/dependabot.yml" \
    "    groups:" \
    $'    ignore:\n      - dependency-name: "ansible-core"\n    groups:' \
    "Dependabot must not ignore ansible-core security updates"
