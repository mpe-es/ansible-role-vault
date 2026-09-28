#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-vault-calls-carry-client-certs.sh
# Role: ansible-role-vault
# Summary: Every surface that talks to Vault must present a client certificate
#          when the listener requires one (#44).
# Usage: bash tests/assert-vault-calls-carry-client-certs.sh
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS, AND WHY IT IS NOT INSIDE THE #44 ORCHESTRATION LOCK. That lock
# reads the `Initialize Vault` block of tasks/service.yml, so when client
# credentials were first added there it reported the work complete -- while
# templates/vault-unseal.service.j2 still set only VAULT_CACERT. The boot
# auto-unseal helper runs `vault status` and `vault operator unseal`, so on a
# listener with tls_require_and_verify_client_cert the unit failed TLS at every
# boot and the cluster stayed sealed: the precise failure that service exists to
# prevent, missed because the guard was scoped to one file.
#
# So this sweeps EVERY surface and is keyed on the CA, which is the marker that a
# call is talking to Vault over TLS at all:
#   task `environment:` with VAULT_CACERT  -> needs VAULT_CLIENT_CERT and _KEY
#   module args with `ca_path`             -> needs client_cert and client_key
#   a template or script SETTING VAULT_CACERT -> needs both client variables
#
# BOTH halves are required, never just the certificate: a certificate without its
# key is not a usable client identity, and requiring only the cert left "delete the
# key line" green.
set -euo pipefail
# Accepts a root so its meta-gate can point it at a sandbox copy, exactly as the
# sibling *-mutations.sh harnesses do. Without this the guard silently re-checks the
# real tree and every mutation "survives".
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import io, os, re, sys, yaml

root = sys.argv[1]
fail = []
checked = 0

# Files that legitimately reference the CA without owning the client identity.
# A reason is mandatory: an exemption without one is how a guard stops guarding.
EXEMPT = {
    "files/vault-unseal.sh":
        "consumes the environment its systemd unit exports and defines no authoritative "
        "value; templates/vault-unseal.service.j2 is the surface that sets it and IS "
        "checked here",
}


def tasks_of(node):
    """Every task in a task file, including block/rescue/always."""
    if isinstance(node, list):
        for x in node:
            yield from tasks_of(x)
    elif isinstance(node, dict):
        yield node
        for k in ("block", "rescue", "always"):
            if k in node:
                yield from tasks_of(node[k])


for dirpath, _, names in os.walk(os.path.join(root, "tasks")):
    for n in sorted(names):
        if not n.endswith((".yml", ".yaml")):
            continue
        rel = os.path.relpath(os.path.join(dirpath, n), root)
        doc = yaml.safe_load(io.open(os.path.join(dirpath, n), encoding="utf-8"))
        if not doc:
            continue
        checked += 1
        for t in tasks_of(doc):
            name = str(t.get("name", "<unnamed>"))
            env = str(t.get("environment", ""))
            if "VAULT_CACERT" in env:
                for want in ("VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
                    if want not in env:
                        fail.append(f"{rel}: {name!r} sets VAULT_CACERT without {want}. On a "
                                    f"listener with tls_require_and_verify_client_cert the CLI "
                                    f"call fails TLS before it does anything.")
            for key, val in t.items():
                if isinstance(val, dict) and "ca_path" in val:
                    for want in ("client_cert", "client_key"):
                        if want not in val:
                            fail.append(f"{rel}: {name!r} sets ca_path without {want}. Same "
                                        f"failure on the API path.")

# Templates and shipped scripts: a SET of the CA, not a mention of it in prose.
SETS_CA = re.compile(r'(^|[\s=])VAULT_CACERT\s*=')
for sub in ("templates", "files"):
    base = os.path.join(root, sub)
    if not os.path.isdir(base):
        continue
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            src = io.open(os.path.join(dirpath, n), encoding="utf-8", errors="replace").read()
            # Jinja comments are prose, not configuration.
            body = re.sub(r'\{#.*?#\}', ' ', src, flags=re.S)
            if not SETS_CA.search(body):
                continue
            checked += 1
            if rel in EXEMPT:
                continue
            for want in ("VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
                if want not in body:
                    fail.append(f"{rel}: sets VAULT_CACERT without {want}. Anything that runs "
                                f"the vault CLI against an mTLS listener needs a client "
                                f"identity; without it this surface fails TLS every time.")

# The exemption map must not name a file that no longer exists, or it is silently
# excusing nothing while looking like coverage.
for rel, why in EXEMPT.items():
    if not os.path.exists(os.path.join(root, rel)):
        fail.append(f"EXEMPT names {rel}, which does not exist -- a stale exemption.")
    if not why.strip():
        fail.append(f"EXEMPT[{rel}] has no reason recorded.")

if checked == 0:
    print("FAIL - this guard inspected nothing; it would pass vacuously")
    sys.exit(1)

if fail:
    print("FAIL: mTLS reachability")
    for f in sorted(set(fail)):
        print(f"  - {f}")
    sys.exit(1)
print(f"ok - {checked} surfaces inspected; every Vault call carries a client certificate "
      f"AND key when the listener requires one")
PYEOF
