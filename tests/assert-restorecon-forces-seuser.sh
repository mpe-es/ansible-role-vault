#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-restorecon-forces-seuser.sh
# Role: ansible-role-vault
# Summary: Regression lock — when the role declares a seuser in an fcontext
#   spec, the restorecon that applies it must carry -F, or the declaration is
#   never enforced and the task reports success anyway.
#
#   Found on live hardware 2026-09-18. vars/main.yml states the intent outright:
#   "RPM sets /opt/vault/* to unconfined_u:object_r:usr_t — we enforce system_u".
#   It did not. Measured after a full converge on a real host:
#
#     fcontext rule installed:  /opt/vault(/.*)?  system_u:object_r:usr_t:s0
#     restorecon -Rv  (shipped) -> EMPTY OUTPUT, rc=0
#     /opt/vault/data still      unconfined_u:object_r:usr_t:s0
#     restorecon -RFv           -> "Relabeled ... unconfined_u -> system_u"
#
#   restorecon WITHOUT -F repairs only the TYPE; it never resets the SELinux
#   user. The type was already usr_t, so it found nothing to do, printed
#   nothing and exited 0 — and `changed_when: stdout | length > 0` therefore
#   reported not-changed and SUCCESS. The success oracle could not fail. This
#   is the "derive from the authority, not the projection" class: the task
#   measured type convergence while claiming seuser convergence.
#
#   /etc/vault.d masked the gap, because its TYPE differed (etc_t) which forced
#   a relabel that carried the user along. Only the paths whose type already
#   matched were silently left alone.
#
#   Locked here:
#     - the premise: at least one entry in vault_selinux_contexts declares a
#       seuser. If that ever stops being true this guard says so rather than
#       passing vacuously.
#     - the restorecon command carries -F as a real FLAG token: matched in the
#       option cluster, never as a substring of a path or of -Rv.
#     - the command still carries -R (recursive) and -v, because changed_when
#       keys on stdout and a silent restorecon can never report changed.
# Usage: bash tests/assert-restorecon-forces-seuser.sh
# Classification: UNCLASSIFIED
###############################################################################
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import sys, os, re, yaml

root = sys.argv[1]
fail = []

rolevars = yaml.safe_load(open(os.path.join(root, 'vars/main.yml'))) or {}
tasks = yaml.safe_load(open(os.path.join(root, 'tasks/system.yml'))) or []

# --- premise: a seuser is actually declared ---------------------------------
contexts = rolevars.get('vault_selinux_contexts') or []
declares_seuser = [c for c in contexts
                   if isinstance(c, dict) and str(c.get('seuser', '')).strip()]
if not declares_seuser:
    print("FAIL - vault_selinux_contexts declares no seuser; this guard's premise "
          "is gone. Either restore the seuser declarations or retire this guard "
          "deliberately -- do not let it pass vacuously.")
    sys.exit(1)


def commands(ts):
    for t in ts or []:
        if not isinstance(t, dict):
            continue
        args = t.get('ansible.builtin.command') or t.get('command')
        if isinstance(args, dict) and 'cmd' in args:
            yield t, str(args['cmd'])
        elif isinstance(args, str):
            yield t, args
        for k in ('block', 'rescue', 'always'):
            if k in t:
                yield from commands(t[k])


def flags(cmd):
    """Short-option letters actually passed, ignoring paths and Jinja."""
    out = set()
    # Strip Jinja expressions so a path containing 'F' cannot be read as a flag.
    bare = re.sub(r'\{\{.*?\}\}', ' ', cmd)
    for tok in bare.split():
        if tok.startswith('--') or not tok.startswith('-'):
            continue
        out.update(tok[1:])
    return out


found = False
for t, cmd in commands(tasks):
    if not re.search(r'(^|/|\s)restorecon(\s|$)', cmd):
        continue
    found = True
    have = flags(cmd)
    name = t.get('name', '<unnamed>')
    if 'F' not in have:
        fail.append(f"restorecon in task {name!r} does not pass -F, so the "
                    f"seuser declared in vault_selinux_contexts "
                    f"({declares_seuser[0].get('seuser')}) is never applied when "
                    f"the type already matches -- and the task still reports "
                    f"success. cmd: {cmd}")
    if 'R' not in have:
        fail.append(f"restorecon in task {name!r} lost -R; it would stop "
                    f"descending into the paths it claims to relabel. cmd: {cmd}")
    if 'v' not in have:
        fail.append(f"restorecon in task {name!r} lost -v; changed_when keys on "
                    f"stdout, so a silent restorecon can never report changed. "
                    f"cmd: {cmd}")

if not found:
    fail.append("no restorecon command found in tasks/system.yml, but "
                "vault_selinux_contexts declares a seuser that something must "
                "apply")

if fail:
    for x in fail:
        print("FAIL -", x)
    sys.exit(1)
print("ok - restorecon passes -F (seuser actually enforced), keeps -R and -v")
PY
