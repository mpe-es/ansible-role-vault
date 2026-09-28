#!/usr/bin/env bash
###############################################################################
# Filename: tests/peer-shape-table-test.sh
# Role: ansible-role-vault
# Summary: Truth table for the vault_cluster_members peer-shape gate (#44).
# Usage: bash tests/peer-shape-table-test.sh
# Classification: UNCLASSIFIED
###############################################################################
# It LOADS the real expressions out of tasks/preflight/cluster.yml and the real
# pattern out of vars/main.yml, then evaluates them. A transcribed copy of an
# expression is a verification that cannot fail -- the lesson
# license-state-table-test.sh already carries.
#
# WHY A TABLE. The first version of this gate used `urlsplit('scheme')` and was
# wrong in BOTH directions, which no happy-path case can show:
#   FALSE REJECT  fd00::10, fe80::1, abcd::1 -- a URI scheme may begin with any
#                 letter, so every letter-leading IPv6 parsed as scheme=fd00, and
#                 fd00::/8 is the ULA range an airgapped enclave numbers with.
#   FALSE ACCEPT  10.0.0.1:8200 -> rendered https://[10.0.0.1:8200]:8200, plus
#                 "", "   ", node1/path, node1?q=1 and 999.999.999.999.
# Both directions are in the table so neither can come back.
#
# NON-STRING ELEMENTS ARE IN THE TABLE. meta/argument_specs.yml types the LIST,
# not its elements, and the type_debug gate checks the CONTAINER. Measured: an
# integer element raised "argument of type 'int' is not iterable", and a YAML null
# was ACCEPTED as the hostname "None", rendering https://None:8200.
#
# One row exists solely to make the 253-byte cap load-bearing: FOUR 63-byte labels is
# 255 bytes with every individual label legal, so the per-label 63 in the pattern does
# not reject it and only the total cap does. Without that row the cap's mutation probe
# below flipped no verdict -- this harness caught that in its own first run.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Case values, in table order. Non-string rows are real YAML types.
CASES_JSON='{"cases": ["node1.example.mil","node1","NODE1.EXAMPLE.MIL","node1.example.mil.",
  "localhost","xn--bcher-kva.example.mil","10.0.0.1","2001:db8::10","fd00::10","fe80::1",
  "abcd::1","FD00::10","::1","::ffff:10.0.0.1",
  "10.0.0.1:8200","vault-el:8200","https://node1","","   "," node1 ","node1/path",
  "node1?q=1","999.999.999.999","10","10.0.0.0/24","fd00::/64","[2001:db8::10]",
  "-bad.example.mil","node_1","a..b","user@host","fe80::1%eth0",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.mil",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  null, 10, ["10.0.0.1"]]}'

# Expected verdicts, same order, one per line. Verdicts only -- several case values
# contain spaces, so pairing them on one line cannot be parsed reliably.
EXPECT="ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT ACCEPT
ACCEPT ACCEPT ACCEPT ACCEPT
REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT
REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT REJECT
REJECT"

# $1 = optional python body mutating `ip` / `name`, so this harness can prove it
# is able to fail.
build () {
  python3 - "$ROOT" "$WORK" "${1:-}" <<'PYEOF'
import io, sys, yaml
root, work, mut = sys.argv[1], sys.argv[2], sys.argv[3]

tasks = yaml.safe_load(io.open(f"{root}/tasks/preflight/cluster.yml", encoding="utf-8"))
t = next((x for x in tasks if "peers are bare host or IP" in str(x.get("name", ""))), None)
if t is None:
    sys.exit("the peer-shape task is gone from tasks/preflight/cluster.yml")
try:
    ip, name = t["vars"]["__vault_peer_is_ip"], t["vars"]["__vault_peer_is_name"]
except KeyError as e:
    sys.exit(f"the peer-shape task no longer defines {e}")

pattern = yaml.safe_load(io.open(f"{root}/vars/main.yml", encoding="utf-8")).get("__vault_peer_name_re")
if not pattern:
    sys.exit("__vault_peer_name_re is gone from vars/main.yml")

if mut:
    exec(mut)

# The loaded expressions reference `item`, so they are evaluated verbatim inside a
# loop over the case list -- nothing is rewritten.
yaml.safe_dump([{
    "hosts": "localhost", "connection": "local", "gather_facts": False,
    "vars": {"__vault_peer_name_re": pattern},
    "tasks": [{
        "name": "evaluate the real peer-shape expressions",
        "ansible.builtin.debug": {
            "msg": "{{ 'ACCEPT' if (__ip or __nm) else 'REJECT' }}"},
        "vars": {"__ip": ip, "__nm": name},
        "loop": "{{ cases }}",
        "loop_control": {"label": "{{ item | string }}"},
    }],
}], io.open(f"{work}/eval.yml", "w"), default_flow_style=False)
PYEOF
}

verdicts () {  # -> one ACCEPT|REJECT per line in case order, or PLAYBOOK_FAILED
  if ! ansible-playbook "$WORK/eval.yml" -e "$CASES_JSON" >"$WORK/log" 2>&1; then
    echo "PLAYBOOK_FAILED"; return
  fi
  grep -oE '"msg": "(ACCEPT|REJECT)"' "$WORK/log" | sed 's/.*"\(ACCEPT\|REJECT\)"/\1/'
}

fail=0
if ! build; then echo "FAIL: could not load the real expressions"; exit 1; fi
got="$(verdicts)"
if [ "$got" = "PLAYBOOK_FAILED" ]; then
  echo "FAIL: the gate expressions raised instead of returning a verdict:"
  grep -E 'fatal|FAILED' "$WORK/log" | head -3
  exit 1
fi

want="$(printf '%s\n' "$EXPECT" | tr ' ' '\n' | grep -c .)"
have="$(printf '%s\n' "$got" | grep -c .)"
if [ "$want" != "$have" ]; then
  echo "FAIL: $have verdicts for $want cases -- the table and the case list disagree"
  exit 1
fi
if [ "$have" = 0 ]; then
  echo "FAIL: no verdicts at all; this test would pass vacuously"; exit 1
fi

n=0; bad=0
while IFS= read -r w; do
  [ -z "$w" ] && continue
  n=$((n + 1))
  g="$(printf '%s\n' "$got" | sed -n "${n}p")"
  if [ "$g" != "$w" ]; then
    label="$(grep -oE 'item=[^)]*' "$WORK/log" | sed -n "${n}p")"
    echo "FAIL: case $n ${label:-} -> $g, expected $w"; bad=$((bad + 1)); fail=1
  fi
done < <(printf '%s\n' "$EXPECT" | tr ' ' '\n')

[ "$bad" = 0 ] && echo "ok - $n peer cases, every verdict as expected (false-accept and false-reject both covered)"

# The harness must be able to fail. Each mutation removes one clause and must flip a
# verdict or make the expression raise. A mutation that changes nothing means the
# clause it targets guards nothing, or the anchor went stale (#78 lesson 5).
probe () {  # $1=label $2=python body
  if ! build "$2"; then echo "FAIL(mutation): $1 did not load"; fail=1; return; fi
  local out; out="$(verdicts)"
  if [ "$out" = "PLAYBOOK_FAILED" ]; then
    echo "ok(mutation): $1 -- the gate raises under that change"
  elif [ "$out" = "$got" ]; then
    echo "FAIL(mutation): $1 changed no verdict, so that clause guards nothing"; fail=1
  else
    echo "ok(mutation): $1 flips a verdict"
  fi
}

probe "drop the is-string lead" \
  "ip = ip.replace('item is string and ', ''); name = name.replace('item is string and ', '')"
probe "drop the dot-or-colon test" \
  "ip = ip.replace(\"and ('.' in item or ':' in item)\", '')"
probe "drop the 253-byte cap" \
  "ip = ip.replace('and item | length <= 253', ''); name = name.replace('and item | length <= 253', '')"
probe "drop the all-numeric rejection" \
  "name = name.replace(\"and not (item is match('^[0-9.]+\$'))\", '')"
probe "drop the prefix rejection" \
  "ip = ip.replace(\"and '/' not in item\", '')"
probe "revert to urlsplit('scheme')" \
  "ip = \"{{ (item | urlsplit('scheme')) | length == 0 and '[' not in item }}\"; name = '{{ false }}'"

# Restore the unmutated build so a reader running this by hand is left with the real
# expressions in the work dir, and re-confirm the real tree still passes.
build >/dev/null
[ "$(verdicts)" = "$got" ] || { echo "FAIL: the real expressions no longer reproduce"; fail=1; }

exit "$fail"
