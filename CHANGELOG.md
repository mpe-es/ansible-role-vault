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

### Changed

- Molecule now executes the real role rather than a hand-copied replica, so
  the tests exercise what ships. (#50, closes #43)
- Initialization is now a single transaction that unseals and enables audit by
  default, with `vault_auto_unseal_enabled` split out from `vault_init_unseal`
  so the boot-time key-at-rest decision is distinct from the init-time unseal
  behavior. (#51, closes #33)
- `vault.env` tightened from `0640` to `0600`. (#55)

### Fixed

- Vault auto-unseal repaired: the service now runs as root, exits honestly
  rather than reporting success on failure, and uses a hardened tokens path.
  (#49, closes #30)
- Audit backups are now root-only, and the retention variable is correctly
  wired. (#46, closes #32)

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
- Least-privilege `permissions` set explicitly on all CI and release workflow
  jobs, resolving the CodeQL `actions/missing-workflow-permissions` findings.

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
