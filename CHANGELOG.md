# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Vault role implementing all nine task phases: install, user and
  directory layout, TLS, configuration, systemd, initialization, audit, STIG
  remediation, and verification. (#1)
- EL10 support in CI, and capture of Vault initialization output. (#21)
- fapolicyd trust management for the Vault binary and the role's helper
  scripts, so the role remains functional on hosts with fapolicyd enforcing.
  (#29)
- Secure-by-default initialization key handling: unseal shares and the root
  token are no longer written to the node by default. The root token is
  returned to the controller only, and whether shares land on the node is
  gated explicitly by `vault_auto_unseal_enabled`. (#53, closes #34)
- Explicit happy-path unseal verification. The role previously had none;
  success depended implicitly on later `audit enable` calls failing against a
  sealed Vault. Now performs a `GET /v1/sys/seal-status` and asserts
  `sealed == false`. (#54)
- Static regression gate asserting that no unseal key can reach process argv,
  wired into the CI `lint` job so the fixed defect cannot be reintroduced.
  (#54)
- Static ownership lock asserting that every posture-defining file deploy,
  including the Vault-PKI branch that has no runtime coverage, remains
  root-owned, with a count tripwire so a dropped or renamed deploy fails
  rather than being silently skipped. (#56)
- New systemd-capable `molecule/hsm` scenario (EL8/9/10) verifying HSM PIN
  delivery without requiring a real HSM. (#55)
- Community health files: `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
  issue forms, and a pull request template.
- CODEOWNERS and Dependabot conventions aligned with the sibling repositories.
  (#24)


- **`vault_repo_source`** (`hashicorp` | `mirror` | `satellite`, default
  `hashicorp`) — declares how the Vault RPM reaches the host and decides which
  repo gates apply. `satellite` writes **no** repo file, since
  `subscription-manager` owns the client repo configuration; preflight verifies
  registration instead. Content-view reachability and install scoping are
  tracked in #68. RHEL only. (#36)
- **TLS material gate** — with `vault_manage_tls: false` (the default),
  preflight now verifies the certificate, key and CA all exist and are regular
  files, instead of letting a missing file surface at service start. (#36)
- **Repo-source coherence gate** — `mirror` mode must not NAME the public
  HashiCorp host, checked for both `vault_repo_url` and `vault_repo_gpg_key`.
  It compares the parsed hostname and performs no name resolution, so an alias
  or CNAME to the public endpoint still passes;
  the target fetches the key directly, so overriding only the URL still reaches
  the internet. (#36)
- **Certificate SAN contract** documented with a worked `openssl` request:
  a `127.0.0.1` IP SAN plus whatever `vault_api_addr` advertises (the host
  FQDN by default). No `localhost` DNS SAN is required —
  the issue body's claim to the contrary was wrong and is corrected there. (#36)
- `tests/assert-preflight-gate-order.sh` — static lock on the gate sequence and
  the tag surfaces, wired into the CI lint job. (#36)
- `molecule/preflight` scenario proving that each COVERED gate fires on its own
  cause and stays silent when its feature is toggled off. FIPS, SELinux, OS family,
  OS version and DNS are not exercised behaviourally and are locked statically
  instead; the "ss entirely absent" arm is untested. (#36)

### Deferred to follow-up issues

- **Satellite content reachability and install-transaction scoping** — verifying
  that the content view publishes Vault, and scoping `dnf` to the verified
  repository set, are tracked in
  [#68](https://github.com/mpe-es/ansible-role-vault/issues/68). In `satellite`
  mode `dnf` still resolves across every enabled repository.
- **TLS readability by the Vault account** — the staged-material gate proves the
  files exist and are regular files. Proving the service account can read them
  (ACL evaluation and full pathname resolution) is tracked in
  [#69](https://github.com/mpe-es/ansible-role-vault/issues/69).

### Changed
- Molecule now executes the real role rather than a hand-copied replica, so
  the tests exercise what ships. (#50, closes #43)
- Initialization is now a single transaction that unseals and enables audit by
  default, with `vault_auto_unseal_enabled` split out from `vault_init_unseal`
  so the boot-time key-at-rest decision is distinct from the init-time unseal
  behavior. (#51, closes #33)
- `vault.env` tightened from `0640` to `0600`. (#55)
- Galaxy namespace changed from `darkhonor` to `mpe-es`; the role is now
  referenced as `mpe-es.vault` and all README examples updated to match.
- Role description no longer advertises HA cluster support unqualified.
  Single-node is the supported path; multi-node Raft HA is labelled
  developmental. (#44)
- Placeholder hostnames in README examples now use the `closednetwork.local`
  convention shared with the sibling MPE-ES roles, replacing `*.internal.mil`
  and `*.enclave.mil`.


**BREAKING CHANGES**


- **`--tags preflight` now runs the gates.** It previously matched nothing and
  reported success having done nothing. A tag-scoped job that was green may now
  go red — which is the point. `--tags vault|install|stig|fapolicyd` run the
  fapolicyd phase alone (measured); the remaining tags still do nothing. (#36)
- **The TLS material gate fires under shipped defaults.** `vault_manage_tls`
  defaults to `false` and the certificate paths default under `/opt/vault/tls/`,
  which the role does not populate. A deployment that stages certificates in a
  later play or out of band passed before and now fails at preflight.
  Remediation: stage them before the role, or set `vault_manage_tls: true`
  **and** populate `vault_tls_src_cert` / `_key` / `_ca`. (#36)
- **The port gate requires `iproute`.** A missing `ss` is a hard failure, not a
  skip: degrading to a skip would silently restore the inert gate this repairs.
  Install `iproute` on minimal images. (#36)

### Fixed
- **Operator-staged TLS material was never made readable by the Vault service.**
  `vault_manage_tls: false` is the role default and a documented path — preflight
  instructs the operator to stage the certificate, key and CA — but the only code
  setting ownership on them lived in `tasks/tls.yml`, which `tasks/main.yml` gates
  on `vault_manage_tls`. On the default path that file never ran, so a host
  converged cleanly and then failed at service start because `vault` could not
  read its own private key. `tasks/system.yml` now converges the trio to
  `root:vault 0640`, the same posture it already applied unconditionally to
  `/opt/vault/tls` itself. Bounded deliberately: only direct children of
  `vault_tls_dir` are touched, and symlinks are never followed — an operator may
  legitimately point `vault_tls_ca_file` at a shared system anchor, and
  certmonger/certbot material is normally a link to material outside the
  directory. Both excluded cases are reported rather than silently skipped;
  proving such material is *readable* remains #69. (#77)
- **The API port-availability assert could never fail.** `wait_for` with
  `failed_when: false` forces the result's `failed` key to False, so the assert
  was a tautology and an occupied port surfaced as an opaque Vault
  service-start error. The gate now identifies the port's listener and passes
  only when the port is free or already held by the Vault service itself —
  decided by systemd cgroup, not process name, since any process may be named
  `vault`. A listener with no attributable PID fails closed. (#36)
- **A missing `chronyc` crashed the task instead of failing the assert**, so
  the remediation text was never reached. Presence is now detected first, and
  a stopped `chronyd`, an unrecognised exit code and an unsynchronised clock
  each carry their own message. (#36)
- **firewalld was required even when `vault_manage_firewall: false`** — the
  feature toggle did not reach preflight. It now does, and a host with no
  firewalld package is told that, rather than to start a service it lacks.
  (#36)
- **The RHSM gate rejected every compatible EL distribution** for a dependency
  the role does not have: under the `hashicorp` and `mirror` sources
  `tasks/repo.yml` deploys a repo file with HashiCorp's GPG key and needs no
  subscription. (Under `satellite` it branches: it writes no repo file, removes
  any role-written one, and skips the key import.) Registration is now checked
  only when Vault is sourced from Satellite. Rocky, AlmaLinux, CentOS Stream
  and Oracle Linux pass. (#36)


- Vault auto-unseal repaired: the service now runs as root, exits honestly
  rather than reporting success on failure, and uses a hardened tokens path.
  (#49, closes #30)
- Audit backups are now root-only, and the retention variable is correctly
  wired. (#46, closes #32)

### Documentation
- Added a **Known Limitations** section covering developmental multi-node HA
  (#44), the silent no-op on tag-scoped runs (#28 — `--tags preflight` is now
  an exception), the preflight gaps (#36 — since repaired and removed),
  and the tracked functional gaps (#35, #39, #40, #42, #45).
- Requirements now document every prerequisite `tasks/preflight.yml` actually
  hard-fails on — FIPS mode, SELinux enforcing, chrony synchronization,
  firewalld running, and RHSM registration — none of which were previously
  listed. **Superseded below:** the gates it described as broken are now
  repaired, and the table has been rebuilt with a "fires when" column. (#36)
- Corrected the "or compatible EL distribution" platform claim: the RHSM gate
  structurally rejects Rocky, AlmaLinux and CentOS Stream today.
  **Superseded below:** compatible EL distributions now pass. (#36)
- HA example playbook now states plainly that running it unchanged across
  three hosts produces three independent Vaults, not one Raft cluster. (#44)

### Removed
- `vault_log_file_mode` from `vars/main.yml` — defined but never consumed by
  any task or template. (#37)

### Security
- **Shamir unseal shares moved off the command-line argument vector.** Both
  unseal paths passed each share as a CLI argument, which `auditd` records in
  `execve` argv on any STIG-baseline RHEL host; `no_log` suppresses Ansible's
  output but not the host audit trail. The init-time path now uses
  `POST /v1/sys/unseal` and carries the share in the HTTP request body; the
  boot-time path pipes the key through stdin using the `-` sentinel. Severity
  HIGH. (#54, closes #31)
- **PKCS#11 HSM seal PIN moved out of plaintext `vault.hcl` and out of
  `--diff` output.** The PIN is now delivered through `VAULT_HSM_PIN` in
  `/etc/vault.d/vault.env`, read by the packaged unit's `EnvironmentFile=`.
  Adds fail-closed validation of the value, a drop-in-aware delivery check so a
  host whose unit will not load `vault.env` fails loudly instead of silently
  failing to unseal, `no_log` on the variable in `argument_specs`, and
  `diff: false` on the env-file render. (#55, closes #41)
- **Least-privilege ownership.** The `vault` service account no longer owns,
  with write, the artifacts that define its own security posture. `vault.hcl`
  is `root:vault 0640`, `vault.env` is `root:root 0600`, the TLS certificate,
  key, and CA are `root:vault 0640`, and `/opt/vault/tls` is `root:vault 0750`.
  Root-owning the directory is the load-bearing part: write access to a
  directory permits unlink and replace regardless of file ownership.
  `/opt/vault/data` and `/var/log/vault` deliberately remain `vault:vault`.
  (#56, closes #38)
- Least-privilege `GITHUB_TOKEN` scope declared on the CI and release
  workflows. Both default to `contents: read` at workflow level, inherited by
  every job; the security-scan job additionally declares
  `security-events: write`, the scope the (still-commented) SARIF upload will
  require once the repository is public and Advanced Security is available.
  Resolves `actions/missing-workflow-permissions`. This matters specifically
  because fork pull requests will run CI once the repository is public.

### Dependencies
- Bump certifi from 2026.2.25 to 2026.4.22 (#3)
- Bump idna from 3.11 to 3.13 (#4)
- Bump urllib3 from 2.6.3 to 2.7.0 (#5)
- Bump requests from 2.33.1 to 2.34.2 (#8)
- Bump idna from 3.13 to 3.18 (#13)
- Bump certifi from 2026.4.22 to 2026.6.17 (#15)
- Bump charset-normalizer from 3.4.7 to 3.4.9 (#23)
- Bump certifi from 2026.6.17 to 2026.7.22 (#27)
- Bump aquasecurity/trivy-action from 0.35.0 to 0.36.0 (#2)
- Bump actions/checkout from 6.0.2 to 7.0.0 (#14)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#25)
- Bump actions/setup-python from 6.2.0 to 6.3.0 (#16)
- Bump actions/setup-python from 6.3.0 to 7.0.0 (#26)

[Unreleased]: https://github.com/mpe-es/ansible-role-vault/commits/main
