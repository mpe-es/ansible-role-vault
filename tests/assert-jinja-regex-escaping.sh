#!/usr/bin/env bash
# A doubled backslash before a regex class letter, inside a FOLDED (>) or
# LITERAL (|) block scalar, silently never matches.
#
# Measured on a live gate rather than reasoned about: a regex_findall in a
# folded scalar returned [] with '\\S' and matched with '\S', and the gate that
# consumed it fired only in the second case. (That particular expression lives
# on the branch for #68; the rule it demonstrates is general.)
#
# SCOPE MATTERS, and this lock got it wrong the first time. In a PLAIN scalar --
# how every assert `that:` item is written -- BOTH forms match. Flagging those
# produced a false CRITICAL against tasks/preflight/chrony.yml, whose expression
# was never broken. This lock is limited to block scalars, where the defect is
# real, and says so rather than claiming a universal rule.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT
exec python3 "$ROOT/tests/lib/check_block_scalar_regex.py"
