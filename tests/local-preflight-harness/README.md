# Local preflight-gate harness

Runs the `managed_tls` (#80) and `dns` (#79) gates against `localhost` with
controlled fixtures — **no podman, no container, a few seconds**.

```bash
cd tests/local-preflight-harness
PATH="$PWD:$PATH" GETENT_FIXTURE_DB="$PWD/hosts.db" \
  ANSIBLE_ROLES_PATH="$(git rev-parse --show-toplevel)/.." \
  ansible-playbook run.yml
```

Expect `failed=0`. The `fatal:` lines in the output are in-block failures the
rescues catch — a case that must FIRE is wrapped in `block`/`rescue` and asserts
the gate's *own* remediation text, because "it failed" cannot distinguish the
gate under test from an unrelated defect.

## Why this exists

These two gates were written, reviewed twice, and remediated twice before anyone
executed them. Both rounds of review found defects that **only execution** could
surface — including one that would have failed CI on every EL cell — and both
times the excuse was that molecule needs podman, which this machine does not
have. The gates themselves never needed a container. This harness removes the
excuse.

## What the fixtures buy

`getent` is a shim, not the real tool. That is deliberate twice over:

- macOS has no `getent` at all, so the dns gate is otherwise unrunnable on a
  common developer machine. **Run without the shim on PATH** and you exercise the
  gate's missing-tool assert for real.
- Resolution outcomes (loopback-only, link-local-only, mixed, absent) are
  controlled by `hosts.db` rather than by editing the developer's `/etc/hosts`,
  which a test has no business doing.

`GETENT_FIXTURE_DB` is required by the shim; unset, it exits non-zero rather
than silently answering nothing, so a mis-invocation cannot look like a pass.

## Relationship to molecule

**What this harness cannot prove.** `run.yml` is `hosts: localhost` with
`connection: local`, so the controller and the target are the same machine. No
case here can distinguish them, which means `delegate_to: localhost` on the
gate's stat could be deleted and the harness would stay green. Only
`molecule/preflight` proves that, because there the fixtures exist solely on the
controller and the container cannot see them.

**This now RUNS IN CI**, as a step in the `syntax` job — that job already
installs `requirements.txt` (netaddr, which `ansible.utils.ipaddr` needs) and the
collections. It is deliberately outside the lint job's `tests/assert-*.sh` glob,
so it is wired in explicitly rather than by naming convention. Until that step
existed, the dns regression cases — IPv4-mapped loopback, mapped multicast, the
case-folding fix — were exercised only on a developer machine and would have
rotted unobserved.

`molecule/preflight` remains the authority for what this cannot reach: the real
EL 8/9/10 images, the real `getent`, cross-machine delegation, and the
container-dependent gates (firewalld, port, rhsm). Run this while iterating;
trust molecule before merging.

## Coverage

| Case | Proves |
|---|---|
| M1 | unset source fails, naming the variable |
| M2 | a `null` override gets the gate's message, not a Jinja type error |
| M3 | an absolute source that does not exist, and that the message points the operator at the controller. It does **not** prove the stat ran on the controller — see below |
| M4 | a directory in place of a certificate |
| M5 | `vault_pki` with an empty mount |
| M6 | a **relative** source is skipped by the stat, the report task fires for exactly it, and the gate does not fail — the shape this project's own README examples use |
| M7 | a symlinked source is accepted (`follow: true` is load-bearing) |
| M8 | the gate is suppressed, not merely non-failing, when the operator stages TLS |
| M9 | an absolute source that exists but is unreadable. Skipped when running as root, where `os.access()` answers True regardless of mode — so it is meaningful on a developer machine and deliberately vacuous in molecule's root container |
| D1 | loopback-only resolution fails, naming the address |
| D2 | link-local-only fails |
| D3 | no resolution at all fails, with its own branch |
| D4 | `vault_manage_tls: true` with `vault_tls_source: vault_pki` arms the gate **even with pinned addresses**, because `tasks/tls.yml` issues against `ansible_fqdn` |
| D5 | a routable answer passes, with the routable set exactly right |
| D6 | loopback alongside a routable address does **not** mask it |
| D7 | pinned addresses with no PKI remove the dependency entirely |
| D8 | `::ffff:127.0.0.1` — loopback in IPv6 clothing — is not reachable |
| D9 | `fe90::1` is link-local: `fe80::/10` is ten bits (fe80–febf), not sixteen |
| D10 | the unspecified address (`::`) is excluded; RFC 4291 §2.5.2 prohibits it as a destination |
| D11 | IPv4 multicast (224.0.0.0/4) is not a unicast endpoint a peer can dial |
| D12 | IPv6 multicast (ff00::/8) likewise |
| D13 | an advertised address spelling the name in CAPS still arms the gate — DNS names are case-insensitive, and a case-sensitive test failed OPEN |
