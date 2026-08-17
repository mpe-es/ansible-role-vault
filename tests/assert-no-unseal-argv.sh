#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-no-unseal-argv.sh
# Role: ansible-role-vault
# Summary: Regression lock for issue #31. Fails if any Ansible task reintroduces
#   the `vault operator unseal <ARG>` CLI form (key in argv -> auditd execve
#   leak). The ONLY allowed form is the bare stdin sentinel `operator unseal -`
#   (with no further characters on that argument). Scans tasks/ only; the boot
#   script (files/vault-unseal.sh) is guarded behaviorally by
#   tests/vault-unseal-test.sh.
#
#   YAML-AWARE: parses each task file with PyYAML and scans the resolved scalar
#   string values. This means folded scalars (`cmd: >-` with the command wrapped
#   across MULTIPLE physical lines, as this repo does for `operator init`) are
#   joined into one string before matching, so a multi-line reintroduction
#   cannot slip past a line-anchored grep; and YAML comments never enter the
#   scan at all (no fragile text-level comment stripping).
#
# Usage: bash tests/assert-no-unseal-argv.sh [tasks_dir]
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN_DIR="${1:-$ROOT/tasks}"

python3 - "$SCAN_DIR" <<'PY'
import sys, os, re, glob
try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required for the issue-#31 unseal-argv gate", file=sys.stderr)
    sys.exit(2)

scan_dir = sys.argv[1]

# A COMMAND is a violation unless the argument after `operator unseal` is EXACTLY
# the bare stdin sentinel `-` AND that `-` is the TERMINAL argument — followed only
# by end-of-command or a pipeline/list operator (`|`, `;`, `&`). Anything else after
# `operator unseal` is rejected. This deliberately does NOT try to allow inline
# redirections: shell removes redirections from anywhere in a simple command, so
# `- < f SECRET` still leaves SECRET in argv — a regex cannot safely permit a
# redirect without reopening that hole. The bare sentinel must be terminal; feed
# the key by pipe (as the boot script does), never a redirect, in a command.
# Requiring whitespace after `unseal` keeps `operator unseal'` (the apostrophe in
# the sealed-warning message, were it ever a command) out.
#   operator unseal -              -> ALLOWED (bare, terminal sentinel)
#   printf %s k | vault ... unseal -  -> ALLOWED (sentinel at end of pipeline)
#   operator unseal - {{ item }}   -> VIOLATION (key follows the sentinel)
#   operator unseal - < f SECRET   -> VIOLATION (SECRET still reaches argv)
#   operator unseal - &>f SECRET   -> VIOLATION (&> is a redirect; SECRET in argv)
#   operator unseal --key=x        -> VIOLATION
#   operator unseal {{ item }}     -> VIOLATION
# `&` is allowed as a background/list operator only when NOT part of `&>`/`&>>`
# (those are redirections, which can be followed by a leaking argument).
# LIMITATION (accepted): the scan is regex, not a shell parser, so prose INSIDE an
# executed shell block (a `# comment` or `echo 'operator unseal SECRET'` in a
# `shell: |` script), or a dynamically-constructed/quoted command, can
# false-positive/negative. No such multi-line shell tasks exist in this role; the
# failure is safe (fail-closed) and a maintainer can reword.
PATTERN = re.compile(r'operator\s+unseal\s+(?!-\s*(?:$|[|;]|&(?!>)))\S')

# Only scan values that are actually executed as shell/exec commands — never
# `msg:`/`name:`/prose — so legitimate text mentioning "operator unseal" cannot
# false-positive. Covers free-form (`command: <str>`), dict (`{cmd:}`/`{argv:}`),
# and the `action:`/`local_action:` free-form forms; short and FQCN module names.
CMD_KEYS = {
    'command', 'shell',
    'ansible.builtin.command', 'ansible.builtin.shell',
    'ansible.legacy.command', 'ansible.legacy.shell',
    'action', 'local_action',
}

def commands(node):
    """Yield every string that a task actually executes as a command."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in CMD_KEYS:
                if isinstance(v, str):
                    yield v
                elif isinstance(v, dict):
                    if isinstance(v.get('cmd'), str):
                        yield v['cmd']
                    if isinstance(v.get('argv'), list):
                        yield ' '.join(str(x) for x in v['argv'])
            yield from commands(v)
    elif isinstance(node, list):
        for v in node:
            yield from commands(v)

violations = []
for path in sorted(glob.glob(os.path.join(scan_dir, '**', '*.yml'), recursive=True)):
    with open(path) as fh:
        try:
            docs = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as e:
            print(f"ERROR: {path}: unparseable YAML ({e})", file=sys.stderr)
            sys.exit(2)
    rel = os.path.relpath(path, scan_dir)
    for doc in docs:
        for cmd in commands(doc):
            if PATTERN.search(cmd):
                violations.append((rel, ' '.join(cmd.split())[:120]))

if violations:
    for rel, snippet in violations:
        print(f"VIOLATION in {rel}: {snippet}", file=sys.stderr)
    print("ERROR: unseal key passed via CLI argv (issue #31).", file=sys.stderr)
    print("Use ansible.builtin.uri (key in body) or the bare 'operator unseal -' stdin sentinel.", file=sys.stderr)
    sys.exit(1)

print(f"ok - no CLI-argv unseal form in {scan_dir}")
PY
