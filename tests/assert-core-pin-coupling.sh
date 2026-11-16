#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-core-pin-coupling.sh
# Role: ansible-role-vault
# Summary: Fail closed when a coupled Ansible Core update leaves any consumer
#          or the secret-bearing release job on a different toolchain, or when
#          a pre-commit hook stops running from the hash-pinned dev lock.
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

floor = pre_commit.get("minimum_pre_commit_version")
if not isinstance(floor, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", floor):
    fail.append(f"minimum_pre_commit_version must be an X.Y.Z string; found {floor!r}")
elif tuple(int(part) for part in floor.split(".")) < (4, 5, 0):
    fail.append(f"minimum_pre_commit_version must be >= 4.5.0; found {floor!r}")

for key in ("default_stages", "files", "exclude"):
    if key in pre_commit:
        fail.append(f"top-level {key} must not narrow which hooks or files run; found {pre_commit.get(key)!r}")

repos = pre_commit.get("repos", []) or []
for repo in repos:
    if repo.get("repo") != "local":
        fail.append(f"only repo: local is allowed; found {repo.get('repo')!r}")
    elif "rev" in repo:
        fail.append(f"local hook repo must not carry rev; found {repo.get('rev')!r}")

for repo in repos:
    for hook in repo.get("hooks") or []:
        hook_id = hook.get("id")
        if hook.get("language") != "unsupported":
            fail.append(f"{hook_id} language must be unsupported; found {hook.get('language')!r}")
        if "additional_dependencies" in hook:
            fail.append(f"{hook_id} hook must not carry additional_dependencies")

for hook_id in ("ansible-lint", "yamllint"):
    found = [(repo, hook) for repo in repos for hook in (repo.get("hooks") or [])
             if hook.get("id") == hook_id]
    if len(found) != 1:
        fail.append(f"expected exactly one {hook_id} hook, found {len(found)}")
        continue
    repo, hook = found[0]
    if repo.get("repo") != "local":
        fail.append(f"{hook_id} hook must be in a repo: local block")
    if hook.get("entry") != hook_id:
        fail.append(f"{hook_id} entry must be {hook_id!r}; found {hook.get('entry')!r}")
    for key in ("stages", "files", "exclude", "types_or", "exclude_types"):
        if key in hook:
            fail.append(f"{hook_id} hook must not narrow when it runs ({key}: {hook.get(key)!r})")
    expected_shape = {
        "yamllint": {"args": ["-c", ".yamllint"], "types": ["yaml"]},
        "ansible-lint": {"args": None, "types": None},
    }[hook_id]
    for key, expected in expected_shape.items():
        if hook.get(key) != expected:
            fail.append(f"{hook_id} {key} must be {expected!r}; found {hook.get(key)!r}")
    if hook_id == "ansible-lint":
        if hook.get("pass_filenames") is not False:
            fail.append("ansible-lint pass_filenames must be false")
        if hook.get("always_run") is not True:
            fail.append("ansible-lint always_run must be true")

hooks_source = re.findall(r"(?m)^pre-commit-hooks==([0-9]+(?:\.[0-9]+){2})\s*$", dev_in)
hooks_lock = lock_pin(dev_lock, "requirements-dev.txt", "pre-commit-hooks")
if len(hooks_source) != 1:
    fail.append(f"pre-commit-hooks must be pinned in requirements-dev.in exactly once; found {hooks_source}")
elif hooks_lock and hooks_source[0] != hooks_lock:
    fail.append(f"pre-commit-hooks drift: requirements-dev.in is {hooks_source[0]}, requirements-dev.txt is {hooks_lock}")

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
print(f"ok - Ansible Core {core} is coupled across development, release, and CI; "
      "every pre-commit hook runs from the dev lock")
PYEOF
}

check_root "$ROOT"

if [ "$CHECK_ONLY" -eq 1 ]; then
    exit 0
fi

# Negative controls: every parsed coupling surface must prove that it can make
# the same guard fail. A fresh fixture per case preserves one-to-one evidence.
current_core="$(awk -F== '/^ansible-core==/ {print $2}' "$ROOT/requirements-dev.in")"
current_hooks="$(awk -F== '/^pre-commit-hooks==/ {print $2}' "$ROOT/requirements-dev.in")"
current_floor="$(awk '/^minimum_pre_commit_version:/ {print $2}' "$ROOT/.pre-commit-config.yaml")"
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
negative_control "CI Python version" ".github/workflows/ci.yml" \
    'PYTHON_VERSION: "3.12"' 'PYTHON_VERSION: "3.13"' "Python drift:"
negative_control "release Python version" ".github/workflows/release.yml" \
    "python-version: '3.12'" "python-version: '3.13'" "Python drift:"
negative_control "ansible-lint hook removed" ".pre-commit-config.yaml" \
    $'      - id: ansible-lint\n        name: ansible-lint\n' \
    $'      - id: ansible-lint-disabled\n        name: ansible-lint\n' \
    "exactly one ansible-lint hook"
negative_control "yamllint hook removed" ".pre-commit-config.yaml" \
    $'      - id: yamllint\n        name: yamllint\n' \
    $'      - id: yamllint-disabled\n        name: yamllint\n' \
    "exactly one yamllint hook"
negative_control "hooks moved to an upstream repo" ".pre-commit-config.yaml" \
    "  - repo: local" "  - repo: https://github.com/ansible/ansible-lint" \
    "must be in a repo: local block"
negative_control "ansible-lint hook language" ".pre-commit-config.yaml" \
    $'        entry: ansible-lint\n        language: unsupported' \
    $'        entry: ansible-lint\n        language: python' \
    "language must be unsupported"
negative_control "local repo revision" ".pre-commit-config.yaml" \
    "  - repo: local" $'  - repo: local\n    rev: v26.10.1' \
    "local hook repo must not carry rev"
negative_control "ansible-lint additional_dependencies" ".pre-commit-config.yaml" \
    "        pass_filenames: false" \
    $'        additional_dependencies: [ansible-core==2.21.5]\n        pass_filenames: false' \
    "must not carry additional_dependencies"
negative_control "ansible-lint pass_filenames" ".pre-commit-config.yaml" \
    "        pass_filenames: false" "        pass_filenames: true" \
    "pass_filenames must be false"
negative_control "ansible-lint always_run" ".pre-commit-config.yaml" \
    $'        always_run: true\n' "" \
    "always_run must be true"
negative_control "pre-commit floor removed" ".pre-commit-config.yaml" \
    "minimum_pre_commit_version: ${current_floor}" "" \
    "minimum_pre_commit_version must be an X.Y.Z string"
negative_control "pre-commit floor lowered" ".pre-commit-config.yaml" \
    "minimum_pre_commit_version: ${current_floor}" "minimum_pre_commit_version: '4.4.0'" \
    "minimum_pre_commit_version must be >= 4.5.0"
negative_control "remote hook repo appended" ".pre-commit-config.yaml" \
    $'        entry: detect-private-key\n        language: unsupported\n        types: [text]\n' \
    $'        entry: detect-private-key\n        language: unsupported\n        types: [text]\n\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v5.0.0\n    hooks:\n      - id: check-json\n' \
    "only repo: local is allowed"
negative_control "pre-commit-hooks source pin" "requirements-dev.in" \
    "pre-commit-hooks==${current_hooks}" "pre-commit-hooks" \
    "pre-commit-hooks must be pinned in requirements-dev.in"
negative_control "pre-commit-hooks lock drift" "requirements-dev.txt" \
    "pre-commit-hooks==${current_hooks} \\" "pre-commit-hooks==0.0.0 \\" \
    "pre-commit-hooks drift"
negative_control "hygiene hook downloads its own environment" ".pre-commit-config.yaml" \
    $'        entry: detect-private-key\n        language: unsupported' \
    $'        entry: detect-private-key\n        language: python\n        additional_dependencies: [pre-commit-hooks==4.0.0]' \
    "detect-private-key language must be unsupported"
negative_control "yamllint hook language" ".pre-commit-config.yaml" \
    $'        args: [-c, .yamllint]\n        language: unsupported' \
    $'        args: [-c, .yamllint]\n        language: python' \
    "yamllint language must be unsupported"
negative_control "ansible-lint entry replaced" ".pre-commit-config.yaml" \
    "        entry: ansible-lint" "        entry: \"true\"" \
    "ansible-lint entry must be 'ansible-lint'"
negative_control "ansible-lint limited to a manual stage" ".pre-commit-config.yaml" \
    "        always_run: true" $'        always_run: true\n        stages: [manual]' \
    "ansible-lint hook must not narrow when it runs"
negative_control "top-level default_stages" ".pre-commit-config.yaml" \
    "minimum_pre_commit_version: ${current_floor}" "minimum_pre_commit_version: ${current_floor}"$'\ndefault_stages: [manual]' \
    "top-level default_stages must not narrow"
negative_control "top-level exclude" ".pre-commit-config.yaml" \
    "minimum_pre_commit_version: ${current_floor}" "minimum_pre_commit_version: ${current_floor}"$'\nexclude: "."' \
    "top-level exclude must not narrow"
negative_control "yamllint entry replaced" ".pre-commit-config.yaml" \
    "        entry: yamllint" "        entry: \"true\"" \
    "yamllint entry must be 'yamllint'"
negative_control "yamllint types narrowed" ".pre-commit-config.yaml" \
    $'        language: unsupported\n        types: [yaml]\n\n      - id: ansible-lint' \
    $'        language: unsupported\n        types: [json]\n\n      - id: ansible-lint' \
    "yamllint types must be ['yaml']"
negative_control "yamllint rules disabled by args" ".pre-commit-config.yaml" \
    "        args: [-c, .yamllint]" "        args: [-d, '{rules: {}}']" \
    "yamllint args must be ['-c', '.yamllint']"
negative_control "ansible-lint args exclude everything" ".pre-commit-config.yaml" \
    $'        entry: ansible-lint\n' $'        entry: ansible-lint\n        args: [--exclude, .]\n' \
    "ansible-lint args must be None"
negative_control "yamllint excluding every file" ".pre-commit-config.yaml" \
    $'        args: [-c, .yamllint]\n' $'        args: [-c, .yamllint]\n        exclude: "."\n' \
    "yamllint hook must not narrow when it runs"
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
