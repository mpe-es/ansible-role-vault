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
cp -a "$ROOT/tasks" "$ROOT/templates" "$ROOT/files" "$SANDBOX/"
cp -a "$SANDBOX" "$WORK/pristine"
killed=0; survived=0; stale=0

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

run "a new CA-only caller is added" tasks/service.yml \
  "s = s.replace('    - name: Enable file audit device', '    - name: Probe Vault\n      ansible.builtin.command:\n        cmd: vault status\n      changed_when: false\n      environment:\n        VAULT_ADDR: \"https://127.0.0.1:8200\"\n        VAULT_CACERT: \"{{ vault_tls_ca_file }}\"\n\n    - name: Enable file audit device', 1)"

# The stale-exemption arm cannot be expressed as a text mutation, so it is exercised
# directly: EXEMPT names files/vault-unseal.sh, and the guard must refuse when that
# path is gone rather than silently excusing nothing.
rm -f "$SANDBOX/files/vault-unseal.sh"
if bash "$GUARD" "$SANDBOX" >/dev/null 2>&1; then
  echo "SURVIVED: the exemption goes stale when its file disappears"; survived=$((survived + 1))
else
  echo "killed:   the exemption goes stale when its file disappears"; killed=$((killed + 1))
fi
rm -rf "$SANDBOX"; cp -a "$WORK/pristine" "$SANDBOX"

if ! bash "$GUARD" "$ROOT" >/dev/null 2>&1; then
  echo "FAIL: the guard does not pass on the real tree"; exit 1
fi
echo "-----"
printf 'killed=%d survived=%d stale-anchor=%d\n' "$killed" "$survived" "$stale"
[ "$survived" -eq 0 ] && [ "$stale" -eq 0 ] || exit 1
echo "ok - the mTLS reachability guard killed all $killed omissions, and the real tree passes"
