#!/usr/bin/env bash
###############################################################################
# Filename: tests/assert-mtls-reachability-mutations.sh
# Role: ansible-role-vault
# Summary: Meta-gate for assert-vault-calls-carry-client-certs.sh -- proves it
#          kills each omission it claims to, and refuses a stale anchor.
# Classification: UNCLASSIFIED
###############################################################################
# The guard it tests exists because a per-file check reported the mTLS work
# complete while templates/vault-unseal.service.j2 still had no client identity.
# A guard written in response to a missed surface is exactly the guard that needs
# watching fail, so every omission below is exercised.
#
# Mutates a COPY of the tree. Every mutation asserts it APPLIED: a stale anchor
# mutates nothing and yields a green guard indistinguishable from a complete one
# (#78 lesson 5).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/tests/assert-vault-calls-carry-client-certs.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SANDBOX="$WORK/tree"; mkdir -p "$SANDBOX"
cp -a "$ROOT/tasks" "$ROOT/templates" "$ROOT/files" "$ROOT/handlers" "$ROOT/molecule" "$SANDBOX/"
cp -a "$SANDBOX" "$WORK/pristine"
killed=0; survived=0; stale=0

# NEGATIVE CONTROL: the UNMUTATED sandbox must pass. Without this, a sandbox that is
# incomplete in some way the guard notices makes every mutation report "killed" for a
# reason that has nothing to do with the mutation -- which is exactly what happened
# when the sandbox omitted molecule/ and the guard failed on a stale exemption.
if ! bash "$GUARD" "$SANDBOX" >/dev/null 2>&1; then
  echo "FAIL: the guard does not pass on an UNMUTATED sandbox copy, so every 'killed'"
  echo "      below would be killed by the sandbox, not by the mutation:"
  bash "$GUARD" "$SANDBOX" 2>&1 | sed 's/^/      /' | head -12
  exit 1
fi
echo "ok(control): the unmutated sandbox passes, so each kill below is attributable"

run () {  # $1=label $2=relative path $3=python body mutating `s`
  local rel="$2"
  if ! python3 - "$SANDBOX/$rel" "$3" <<'PYEOF'
import io, sys
p, body = sys.argv[1], sys.argv[2]
s = io.open(p, encoding='utf-8').read()
before = s
exec(body)
if s == before:
    sys.exit(3)
io.open(p, 'w', encoding='utf-8').write(s)
PYEOF
  then
    echo "STALE ANCHOR: $1 -- mutated nothing, so a green guard proves nothing"
    stale=$((stale + 1))
  else
    if bash "$GUARD" "$SANDBOX" >/dev/null 2>&1; then
      echo "SURVIVED: $1"; survived=$((survived + 1))
    else
      echo "killed:   $1"; killed=$((killed + 1))
    fi
  fi
  rm -rf "$SANDBOX"; cp -a "$WORK/pristine" "$SANDBOX"
}

run "the status probe loses VAULT_CLIENT_CERT" tasks/service.yml \
  "s = s.replace('        VAULT_CLIENT_CERT: \"{{ __vault_client_cert }}\"\n', '', 1)"

run "the status probe loses only VAULT_CLIENT_KEY" tasks/service.yml \
  "s = s.replace('        VAULT_CLIENT_KEY: \"{{ __vault_client_key }}\"\n', '', 1)"

run "a uri call loses only client_key" tasks/service.yml \
  "s = s.replace('        client_key: \"{{ vault_tls_key_file if (vault_tls_require_client_cert | bool) else omit }}\"\n', '', 1)"

run "the boot unseal unit loses its client identity" templates/vault-unseal.service.j2 \
  "i = s.index('Environment=VAULT_CLIENT_CERT'); j = s.index('{% endif %}', i) + len('{% endif %}\n'); s = s[:i] + s[j:]"

run "the CLI env file loses its client identity" templates/vault.env.j2 \
  "i = s.index('VAULT_CLIENT_CERT'); j = s.index('{% endif %}', i) + len('{% endif %}\n'); s = s[:i] + s[j:]"

run "the status probe loses its whole environment block" tasks/service.yml \
  "i = s.index('      register: __vault_status'); j = s.index('    - name: Parse Vault status'); seg = s[i:j]; k = seg.index('      environment:'); s = s[:i] + seg[:k] + s[j:]"

run "a uri call loses ca_path and BOTH client fields together" tasks/service.yml \
  "import re as _r; i = s.index('name: Unseal the initialization host'); j = s.index('name: Wait for this node'); seg = _r.sub(r'        (ca_path|client_cert|client_key):[^\n]*\n', '', s[i:j]); s = s[:i] + seg + s[j:]"

run "a bare vault caller with no environment at all is added" tasks/service.yml \
  "s = s.replace('    - name: Enable file audit device', '    - name: Probe Vault\n      ansible.builtin.command:\n        cmd: vault status\n      changed_when: false\n\n    - name: Enable file audit device', 1)"

run "the unit client key is COMMENTED OUT rather than deleted" templates/vault-unseal.service.j2 \
  "s = s.replace('Environment=VAULT_CLIENT_KEY=', '#Environment=VAULT_CLIENT_KEY=', 1)"

run "a molecule scenario turns mTLS on, invalidating the exemption" molecule/init/molecule.yml \
  "s = s.replace('        vault_init_unseal:', '        vault_tls_require_client_cert: true\n        vault_init_unseal:', 1)"

run "a new CA-only caller is added" tasks/service.yml \
  "s = s.replace('    - name: Enable file audit device', '    - name: Probe Vault\n      ansible.builtin.command:\n        cmd: vault status\n      changed_when: false\n      environment:\n        VAULT_ADDR: \"https://127.0.0.1:8200\"\n        VAULT_CACERT: \"{{ vault_tls_ca_file }}\"\n\n    - name: Enable file audit device', 1)"

# The directory exemption must go stale loudly when molecule/ disappears, rather than
# quietly excusing nothing.
rm -rf "$SANDBOX/molecule"
if bash "$GUARD" "$SANDBOX" >/dev/null 2>&1; then
  echo "SURVIVED: the directory exemption goes stale when molecule/ disappears"; survived=$((survived + 1))
else
  echo "killed:   the directory exemption goes stale when molecule/ disappears"; killed=$((killed + 1))
fi
rm -rf "$SANDBOX"; cp -a "$WORK/pristine" "$SANDBOX"

if ! bash "$GUARD" "$ROOT" >/dev/null 2>&1; then
  echo "FAIL: the guard does not pass on the real tree"; exit 1
fi
echo "-----"
printf 'killed=%d survived=%d stale-anchor=%d\n' "$killed" "$survived" "$stale"
[ "$survived" -eq 0 ] && [ "$stale" -eq 0 ] || exit 1
echo "ok - the mTLS reachability guard killed all $killed omissions, and the real tree passes"
