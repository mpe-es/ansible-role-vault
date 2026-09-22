#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-install-uses-resolved-version.sh
# Role: ansible-role-vault
# Summary: tasks/install.yml must build its dnf name: from the RESOLVED version.
# Classification: UNCLASSIFIED
###############################################################################
# The six RESOLVES cases in molecule/preflight/verify.yml assert the VARS-level
# value only. Every molecule scenario sets vault_manage_install: false, so no
# dnf transaction ever runs and reverting install.yml's name: expression is
# invisible to the entire suite -- the one thing #62 Defect 2 exists to fix
# would be unprotected. This is that lock.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import sys, yaml

root = sys.argv[1]
with open(f"{root}/tasks/install.yml") as fh:
    tasks = yaml.safe_load(fh) or []

fail, found = [], False
for t in tasks:
    dnf = t.get("ansible.builtin.dnf") or t.get("dnf")
    if not dnf:
        continue
    name = str(dnf.get("name", ""))
    if "vault_package_name" not in name:
        continue
    found = True
    if "__vault_package_version_resolved" not in name:
        fail.append(
            "the Vault dnf name: does not use __vault_package_version_resolved; "
            f"got {name!r}. A bare vault_package_version drops the Enterprise "
            "+ent suffix, and dnf then matches no package (#62 Defect 2)."
        )

if not found:
    fail.append("no dnf task installing vault_package_name found in tasks/install.yml")

if fail:
    print("FAIL: install version resolution")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
print("ok: install uses the resolved version")
PYEOF
