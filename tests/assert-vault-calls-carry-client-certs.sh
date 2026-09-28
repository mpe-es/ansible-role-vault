#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-vault-calls-carry-client-certs.sh
# Role: ansible-role-vault
# Summary: Every surface that talks to Vault must carry a complete TLS client
#          identity, so the role still works when the listener requires one (#44).
# Usage: bash tests/assert-vault-calls-carry-client-certs.sh [root]
# Classification: UNCLASSIFIED
###############################################################################
# WHY THIS EXISTS, AND WHY IT IS NOT INSIDE THE #44 ORCHESTRATION LOCK. That lock
# reads the `Initialize Vault` block of tasks/service.yml, so when client
# credentials were first added there it reported the work complete -- while
# templates/vault-unseal.service.j2 still had none. The boot auto-unseal helper runs
# `vault status` and `vault operator unseal`, so on a listener with
# tls_require_and_verify_client_cert that unit failed TLS at every boot and the
# cluster stayed sealed: the precise failure that service exists to prevent, missed
# because the guard was scoped to one file.
#
# DISCOVERY IS FAIL-CLOSED, AND THAT IS THE WHOLE POINT. The first version of this
# guard found callers by looking for VAULT_CACERT or ca_path -- so deleting a task's
# entire `environment:` block, or deleting ca_path together with the client fields,
# made the caller INVISIBLE and the guard green. Worse, that deletion is not benign:
# `Check Vault initialization status` carries failed_when: false, so without a CA it
# fails TLS, rc is non-zero, `Parse Vault status` is skipped, __vault_initialized is
# undefined, every downstream gate skips on `is defined`, and the play reports SUCCESS
# having initialized nothing.
#
# So a caller is identified by WHAT IT INVOKES, and must then carry the full set:
#   a task running the vault binary  -> VAULT_ADDR, VAULT_CACERT,
#                                       VAULT_CLIENT_CERT, VAULT_CLIENT_KEY
#   a uri task addressing the API    -> url, ca_path, client_cert, client_key
#   a template or script running it  -> all four variable names present
# BOTH halves of the identity are required, never just the certificate: a
# certificate without its key is not an identity, and requiring only the cert left
# "delete the key line" green.
#
# COMMENTS ARE STRIPPED BEFORE THE RAW SCAN. Commenting out
# `Environment=VAULT_CLIENT_KEY` left the literal token in the file, so a raw grep
# counted it as present -- a guard satisfied by the text of the thing it forbids.
set -euo pipefail
# Accepts a root so its meta-gate can point it at a sandbox copy, as the sibling
# *-mutations.sh harnesses do. Without this the guard silently re-checks the real tree
# and every mutation "survives" -- which is exactly what happened on its first run.
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 - "$root" <<'PYEOF'
import io, os, re, sys, yaml

root = sys.argv[1]
fail = []
callers = {"cli": 0, "api": 0, "file": 0}

CLI_ENV = ("VAULT_ADDR", "VAULT_CACERT", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY")
URI_ARGS = ("url", "ca_path", "client_cert", "client_key")

# Runs the vault binary: the role's own variable, or the bare command with a
# subcommand that talks to a server.
RUNS_VAULT = re.compile(
    r'vault_binary|\bvault\s+(status|operator|audit|write|read|login|token|policy|secrets|auth)\b')
# Addresses the Vault API over HTTPS.
HITS_API = re.compile(r'vault_listener_port|/v1/sys/')

# Directories exempted wholesale, each with a reason that is CHECKED below, not
# merely asserted. An exemption nobody verifies is how a guard stops guarding.
EXEMPT_DIRS = {
    "molecule": "scenario code, and no scenario enables mTLS -- verified below, so these "
                "callers never face a listener that requests a client certificate",
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


def strip_comments(src, jinja=True):
    if jinja:
        src = re.sub(r'\{#.*?#\}', ' ', src, flags=re.S)
    # systemd / shell / YAML line comments. A commented-out directive must not satisfy
    # a check for that directive.
    return "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))


for sub in ("tasks", "handlers"):
    base = os.path.join(root, sub)
    if not os.path.isdir(base):
        continue
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            if not n.endswith((".yml", ".yaml")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            doc = yaml.safe_load(io.open(os.path.join(dirpath, n), encoding="utf-8"))
            if not doc:
                continue
            for t in tasks_of(doc):
                name = str(t.get("name", "<unnamed>"))
                env = str(t.get("environment", ""))

                # CLI callers: command/shell running the vault binary.
                mods = {k: v for k, v in t.items()
                        if k.startswith("ansible.builtin.") or k in ("command", "shell")}
                cli = any(RUNS_VAULT.search(str(v)) for k, v in mods.items()
                          if k in ("ansible.builtin.command", "ansible.builtin.shell",
                                   "command", "shell"))
                if cli:
                    callers["cli"] += 1
                    for want in CLI_ENV:
                        if want not in env:
                            fail.append(f"{rel}: {name!r} runs the vault binary without {want} "
                                        f"in its environment. On a listener with "
                                        f"tls_require_and_verify_client_cert the call fails TLS "
                                        f"before it does anything, and with failed_when: false "
                                        f"that failure is silent.")

                # API callers: uri addressing the Vault API.
                uri = t.get("ansible.builtin.uri") or t.get("uri")
                if isinstance(uri, dict) and HITS_API.search(str(uri.get("url", ""))):
                    callers["api"] += 1
                    for want in URI_ARGS:
                        if want not in uri:
                            fail.append(f"{rel}: {name!r} addresses the Vault API without "
                                        f"{want!r}. Same failure on the API path.")

# Templates and shipped scripts.
for sub in ("templates", "files"):
    base = os.path.join(root, sub)
    if not os.path.isdir(base):
        continue
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            raw = io.open(os.path.join(dirpath, n), encoding="utf-8", errors="replace").read()
            body = strip_comments(raw)
            # A surface that runs the vault binary, or that configures the environment
            # something else will run it in.
            if not (RUNS_VAULT.search(body) or re.search(r'VAULT_ADDR\s*=', body)):
                continue
            callers["file"] += 1
            for want in CLI_ENV:
                if want not in body:
                    fail.append(f"{rel}: runs or configures the vault CLI without {want}. "
                                f"Anything invoking vault against an mTLS listener needs a "
                                f"complete client identity; the boot auto-unseal unit is how "
                                f"this was missed the first time.")

# Verify the molecule exemption instead of trusting it: if a scenario ever turns mTLS
# on, its callers DO face a client-cert-requiring listener and the exemption is wrong.
mol = os.path.join(root, "molecule")
if os.path.isdir(mol) and "molecule" in EXEMPT_DIRS:
    for dirpath, _, names in os.walk(mol):
        for n in names:
            if not n.endswith((".yml", ".yaml")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            src = io.open(os.path.join(dirpath, n), encoding="utf-8", errors="replace").read()
            for m in re.finditer(r'vault_tls_require_client_cert\s*:\s*(\S+)', src):
                if m.group(1).strip('"\'').lower() in ("true", "yes", "on", "1"):
                    fail.append(f"{rel} sets vault_tls_require_client_cert true, so the "
                                f"molecule exemption in this guard is no longer valid: those "
                                f"callers now face a listener that requests a client "
                                f"certificate. Give them one, or narrow the exemption.")

for d, why in EXEMPT_DIRS.items():
    if not os.path.isdir(os.path.join(root, d)):
        fail.append(f"EXEMPT_DIRS names {d}/, which does not exist -- a stale exemption.")
    if not why.strip():
        fail.append(f"EXEMPT_DIRS[{d}] has no reason recorded.")

# NON-VACUITY, per caller class. Counting files would pass while the discovery
# patterns matched nothing at all -- the first version counted every non-empty task
# file and so could not tell coverage from silence.
MINIMUM = {"cli": 4, "api": 4, "file": 2}
for kind, least in MINIMUM.items():
    if callers[kind] < least:
        fail.append(f"only {callers[kind]} {kind} caller(s) discovered, expected at least "
                    f"{least}. The discovery pattern has stopped matching, so this guard is "
                    f"reporting on almost nothing.")

if fail:
    print("FAIL: mTLS reachability")
    for f in sorted(set(fail)):
        print(f"  - {f}")
    sys.exit(1)
print(f"ok - {callers['cli']} CLI, {callers['api']} API and {callers['file']} file callers "
      f"discovered; every one carries a complete client identity")
PYEOF
