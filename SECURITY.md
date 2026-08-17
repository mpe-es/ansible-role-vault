# Security Policy

## Reporting a Vulnerability

The `ansible-role-vault` project takes security seriously. This role installs
and configures HashiCorp Vault on RHEL hosts intended for DoD enclaves, and it
handles the most sensitive material a system can hold: Shamir unseal shares,
the initial root token, the PKCS#11 HSM seal PIN, and the TLS private key that
terminates every client connection. Vulnerability handling is treated as the
highest priority in this repository.

**Do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.**

### How to Report

Report vulnerabilities privately through GitHub's built-in **private
vulnerability reporting**:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** (under *Advisories*).
3. Complete the advisory form with the details below.

This opens a private security advisory visible only to the reporter and the
project maintainer ([@darkhonor](https://github.com/darkhonor)); it is never
publicly visible unless and until a fix is published. If you require encrypted
communication beyond the private advisory channel, request a public key in your
initial report and one will be provided out-of-band.

**Never include real key material in a report.** If a finding involves an
unseal share, a root token, an HSM PIN, or a TLS private key, describe the
exposure path and redact the value. A report is not more convincing for
carrying a live secret, and the advisory channel is not an appropriate store
for one.

### What to Include

- The role version (release tag or git commit hash)
- The target platform (RHEL 8, 9, or 10)
- The Vault version under management
- The Ansible / ansible-core version used to run the role
- The seal configuration in use: Shamir, auto-unseal service, or PKCS#11 HSM
  (`vault_hsm_enabled`, `vault_auto_unseal_enabled`, `vault_init_unseal`)
- Whether the deployment is single-node or an HA Raft cluster
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code or playbook (please mark clearly as such)
- Suggested mitigations or fixes if you have them

Findings in the following areas are of particular interest, because they
correspond to the role's highest-consequence failure modes:

- **Secret exposure through a side channel**: key material reaching process
  argv (and therefore `auditd` `execve` records on a STIG baseline), a
  `--check --diff` render, AAP job output, a config backup, or a support
  bundle.
- **Secret persistence on the node**: unseal shares, recovery keys, or the
  root token remaining on a target host when the configured capture policy
  says they should not.
- **Least-privilege regressions**: the `vault` service account gaining write
  access to any artifact that defines its own security posture, including
  `vault.hcl`, `vault.env`, the TLS material, or the directory containing it.
- **Transport weakening**: a path that lowers `vault_tls_min_version`, widens
  the cipher list, or bypasses certificate verification.
- **Seal and unseal integrity**: any path that leaves Vault unsealed when the
  configuration intended it sealed, or that reports a successful unseal
  without verifying seal status.

### What to Expect

You can expect the following response from the maintainer:

| Phase | Target Time |
| ----- | ----------- |
| Initial acknowledgment | Within 3 business days |
| Initial assessment and severity rating | Within 7 business days |
| Patch development for confirmed Critical/High issues | Within 30 days |
| Patch development for confirmed Medium issues | Within 90 days |
| Coordinated disclosure (if applicable) | After patch release |

For DoD enclave deployments, vulnerability information may need to be handled
under controlled channels per the relevant Information System Security Officer
(ISSO) and Authorizing Official (AO) guidance. The maintainer will coordinate
with the reporter on appropriate handling.

## Supported Versions

`ansible-role-vault` follows [Semantic Versioning](https://semver.org/).
Security fixes are applied to the most recent release.

| Version | Supported |
| ------- | --------- |
| 0.x.x | Active development |

Once the project reaches a stable 1.0.0 release, this matrix will be updated to
reflect the supported version policy.

## Security Practices

This project follows these supply chain and code security practices:

- **Dependency monitoring:** Dependabot maintains the Python toolchain (pip)
  and the GitHub Actions used in CI.
- **Pinned dependencies:** the Python toolchain is hash-pinned
  (`pip-compile --generate-hashes`, installed with `--require-hashes`), and all
  GitHub Actions are pinned to full commit SHAs rather than tags.
- **Vulnerability scanning:** Trivy scans run in CI, with results published as
  SARIF to GitHub code scanning.
- **Static analysis:** CodeQL analyzes the GitHub Actions workflows for script
  injection, insecure action usage, and over-broad token permissions.
- **Least-privilege CI:** the default `GITHUB_TOKEN` is read-only; individual
  jobs grant only the additional scopes they require.
- **Enforced gating:** `CI Status` is the single required status context and
  requires `success` from every job it aggregates, including the security scan.
  A job that is cancelled or skipped does not satisfy the gate.
- **Static regression gates:** dedicated checks wired into the `lint` job
  assert that unseal key material cannot reach process argv and that
  posture-defining files remain root-owned, so a future change cannot quietly
  reintroduce a fixed class of defect.
- **Behavioral verification:** the `default`, `init`, and `hsm` Molecule
  scenarios exercise the role on real systemd-capable containers across
  EL8/9/10, including negative tests that assert the `vault` account is denied
  writes it should not have.
- **Vulnerability alerts:** GitHub Dependabot alerts and automated security
  updates are enabled.
- **Branch hygiene:** delete-branch-on-merge, conventional commit messages, and
  review via pull request.

## Role-Specific Security Considerations

Operators deploying this role should be aware of the following. These are
properties of the role's design, not defects, but they define the security
envelope you are accepting.

- **Key material capture is opt-in and off by default.** `vault_initialize`
  and `vault_init_capture_dir` govern whether initialization output is
  retained, and the root token is never stored on the node. Enabling capture
  writes unseal or recovery shares at `0600`. Treat any host where capture has
  been enabled as holding key material until you have verified removal.
- **`vault_auto_unseal_enabled` is a key-at-rest decision, not a convenience
  toggle.** Deploying the boot-time auto-unseal service means unseal shares
  persist on the node so it can unseal itself without an operator. That is a
  deliberate availability-for-confidentiality trade. It is distinct from
  `vault_init_unseal`, which only controls whether the role unseals as part of
  the initialization transaction.
- **The HSM PIN is delivered through the environment, never the config file.**
  `vault_hsm_pin` is rendered into `/etc/vault.d/vault.env` (`0600`,
  `root:root`) and consumed through the unit's `EnvironmentFile=`, not into
  `vault.hcl`. Do not reintroduce a `pin` attribute in the `seal "pkcs11"`
  stanza; `vault.hcl` is group-readable and is swept into config backups and
  support bundles.
- **The `vault` process owns nothing that defines its posture.** `vault.hcl`,
  `vault.env`, the TLS certificate, key, and CA, and the directory
  `/opt/vault/tls` are root-owned; the service account reads them through group
  membership. Only `/opt/vault/data` and `/var/log/vault` are writable by the
  service, because it legitimately writes Raft data and audit logs there. Do
  not relax the TLS directory ownership: write access to a directory permits
  unlink and replace regardless of the ownership of the files inside it.
- **`vault_listener_address` defaults to `0.0.0.0`.** The listener is exposed
  on every interface unless you constrain it. Pair this role with host firewall
  configuration appropriate to your enclave.
- **TLS defaults to `tls12` minimum.** Lowering `vault_tls_min_version` or
  populating `vault_tls_cipher_suites` with weak suites will pass the role and
  fail your accreditation. `vault_tls_disable_client_certs` and
  `vault_tls_require_client_cert` interact; review both before changing either.
- **Applying a config change restarts Vault.** On a Shamir-sealed host this
  re-seals it, and the node will require unsealing before it serves requests
  again. This is standing behavior and is expected on first application of any
  configuration change to an existing node.

## Dependencies and Third-Party Code

This role depends on third-party Python packages, Ansible collections, and
container base images used only for testing. It manages the HashiCorp Vault
binary itself, which is installed from a source you configure. Vulnerabilities
in those dependencies are addressed by updating the relevant dependency to a
patched version. If no patched version exists, the maintainer will document the
risk and apply appropriate mitigations.
