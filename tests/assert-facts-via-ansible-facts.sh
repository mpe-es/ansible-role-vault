#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-facts-via-ansible-facts.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #78 — no fact may be read as a top-level
#   `ansible_*` variable. Facts must be read through `ansible_facts[...]`.
#
#   `INJECT_FACTS_AS_VARS` is what makes `ansible_fqdn` exist alongside
#   `ansible_facts['fqdn']`. Its default-True behaviour is deprecated and slated
#   for removal, at which point every such reference becomes undefined. Measured
#   on ansible-core 2.21.4 with injection disabled, the role did not merely fail
#   a gate: it died on its FIRST task, because meta/argument_specs.yml embedded
#   `{{ ansible_fqdn }}` in a default and argument-spec validation could not
#   resolve it. Blast radius is total, and CI installs ansible-core unpinned, so
#   it would land with no commit to blame.
#
#   NOTE ON THE ENV VAR. The setting is INJECT_FACTS_AS_VARS but the environment
#   variable is `ANSIBLE_INJECT_FACT_VARS` — no "AS", and "FACT" singular.
#   `ANSIBLE_INJECT_FACTS_AS_VARS` is silently ignored, which makes a
#   verification run using it pass while proving nothing. Confirmed with
#   `ansible-config list`. Reproduce the failure with:
#
#       ANSIBLE_INJECT_FACT_VARS=False ansible-playbook <play>
#
#   DENY BY DEFAULT. Any `ansible_<name>` token is a failure unless <name> is in
#   ALLOW below. The inverse — denylisting today's fact names — would pass a
#   NEWLY introduced fact such as `ansible_kernel`, which is exactly the silent
#   reintroduction this guard exists to prevent. A false positive here is loud
#   and is fixed by adding the name to ALLOW with a reason, which is a
#   deliberate act; a false negative is invisible.
#
#   tests/ IS IN SCOPE. It was omitted from the first version of this guard, and
#   CI caught what the guard missed: tests/local-preflight-harness/run.yml drives
#   eighteen DNS cases by overriding the fqdn fact per include, and those
#   overrides stopped reaching the gate for exactly the reason this issue exists.
#   Any playbook that runs the role is subject to the same failure, wherever it
#   lives. The .sh guards in tests/ are not YAML and are skipped naturally, which
#   is correct -- assert-preflight-gate-order.sh legitimately holds the literal
#   strings it pins.
#
#   COMMENTS ARE NOT SCANNED, deliberately. YAML files are PARSED and only
#   string VALUES are walked, so prose that discusses `ansible_fqdn` — including
#   this file's own explanation and the migration notes in
#   molecule/preflight/ — is not flagged. Grepping raw lines would make the
#   guard unable to describe the thing it forbids.
# Usage: bash tests/assert-facts-via-ansible-facts.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, re, yaml

root = sys.argv[1]
SCAN_YAML = ['tasks', 'defaults', 'vars', 'meta', 'handlers', 'molecule', 'tests']
SCAN_RAW = ['templates']

# Non-fact ansible_* variables. Each is a connection setting, a magic variable
# or a config value -- none is affected by INJECT_FACTS_AS_VARS.
ALLOW = {
    'facts',                                    # the correct form
    'managed',                                  # config string for templates
    'failed_task', 'failed_result',             # rescue magic vars
    'pipelining',                               # connection setting (#84)
    'user', 'host', 'port', 'connection',       # connection/inventory
    'ssh_private_key_file', 'ssh_common_args', 'ssh_extra_args',
    'become', 'become_user', 'become_method', 'become_password',
    'python_interpreter',
    'check_mode', 'diff_mode', 'verbosity',     # run-state magic vars
    'play_hosts', 'play_batch', 'playbook_python',
    'loop', 'loop_var', 'index_var',
    'parent_role_names', 'parent_role_paths', 'role_name', 'collection_name',
    'search_path', 'version', 'limit', 'run_tags', 'skip_tags',
}

TOKEN = re.compile(r'\bansible_([a-z0-9_]+)')
fail = []


def walk(node, path, where):
    if isinstance(node, str):
        for m in TOKEN.finditer(node):
            name = m.group(1)
            if name in ALLOW:
                continue
            # ansible_facts['x'] already matched as 'facts'; nothing else here.
            fail.append(f"{where}: `ansible_{name}` read as a top-level variable "
                        f"at {path or '<root>'} -- use ansible_facts['{name}'] "
                        f"(the ansible_ prefix is dropped inside the dict). If "
                        f"this is a connection or magic variable and not a fact, "
                        f"add it to ALLOW in this guard with a reason.")
    elif isinstance(node, dict):
        for k, v in node.items():
            walk(k, f"{path}.{k}" if path else str(k), where)
            walk(v, f"{path}.{k}" if path else str(k), where)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, f"{path}[{i}]", where)


scanned = 0
for d in SCAN_YAML:
    base = os.path.join(root, d)
    if not os.path.isdir(base):
        continue
    for dirpath, _, names in os.walk(base):
        for n in names:
            if not n.endswith(('.yml', '.yaml')):
                continue
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            try:
                docs = list(yaml.safe_load_all(open(os.path.join(dirpath, n))))
            except Exception as e:
                fail.append(f"{rel}: does not parse as YAML, so this guard cannot "
                            f"inspect it: {e}")
                continue
            scanned += 1
            for doc in docs:
                walk(doc, '', rel)

# Templates are not YAML; scan raw but drop Jinja comment blocks.
for d in SCAN_RAW:
    base = os.path.join(root, d)
    if not os.path.isdir(base):
        continue
    for dirpath, _, names in os.walk(base):
        for n in names:
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            src = open(os.path.join(dirpath, n)).read()
            src = re.sub(r'\{#.*?#\}', ' ', src, flags=re.S)
            scanned += 1
            for m in TOKEN.finditer(src):
                if m.group(1) not in ALLOW:
                    fail.append(f"{rel}: `ansible_{m.group(1)}` in a template -- "
                                f"use ansible_facts['{m.group(1)}']")

if scanned == 0:
    print("FAIL - this guard scanned no files at all; it would pass vacuously")
    sys.exit(1)

# The premise: ALLOW must not have grown to cover a name that IS a fact.
KNOWN_FACTS = {'fqdn', 'hostname', 'domain', 'os_family', 'distribution',
               'distribution_version', 'distribution_major_version', 'selinux',
               'kernel', 'architecture', 'service_mgr', 'pkg_mgr', 'env',
               'python_version', 'date_time', 'default_ipv4', 'default_ipv6',
               'all_ipv4_addresses', 'memtotal_mb', 'processor_cores'}
leaked = ALLOW & KNOWN_FACTS
if leaked:
    fail.append(f"ALLOW contains names that ARE facts: {sorted(leaked)} -- the "
                f"allowlist has been widened until it no longer guards anything")

if fail:
    for x in sorted(set(fail)):
        print("FAIL -", x)
    sys.exit(1)
print(f"ok - {scanned} files scanned; every fact is read through ansible_facts[...]")
PY
