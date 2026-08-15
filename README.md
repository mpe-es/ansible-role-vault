# Ansible Role: HashiCorp Vault

Install and configure HashiCorp Vault on RHEL systems with DISA STIG compliance.
Supports single-node and HA (3/5-node) Raft clusters in airgap or internet-connected environments.

## Requirements

### Platform

- RHEL 8, 9, or 10 (or compatible EL distribution)

### Ansible

- ansible-core >= **2.17.0** (required by `community.hashi_vault` collection)
- Python >= **3.10** (required by ansible-core 2.17+)

### Collections

Install via `ansible-galaxy collection install -r requirements.yml`:

| Collection | Min Version | Purpose |
|------------|-------------|---------|
| `ansible.posix` | 1.6.0 | `firewalld` module for port management |
| `community.hashi_vault` | 7.0.0 | Vault initialization and post-install configuration |

### Python Libraries

Install via `pip install --require-hashes -r requirements.txt`:

| Library | Version | Purpose |
|---------|---------|---------|
| `hvac` | 2.4.0 | HashiCorp Vault API client (required by `community.hashi_vault`) |

Python dependencies are managed via `pip-compile` with SHA-256 hash pinning
for supply chain integrity (NIST 800-53 SI-7). To regenerate after updating
`requirements.in`:

```bash
pip-compile --generate-hashes requirements.in
```

### Execution Environment (AAP)

For Ansible Automation Platform 2.6+, ensure your Execution Environment includes:

- The collections listed in `requirements.yml`
- The Python packages listed in `requirements.txt`
- System packages listed in `bindep.txt`

The role provides `meta/argument_specs.yml` for AAP Job Template survey
auto-generation and input validation.

### Other

- TLS certificates for the Vault listener (provided externally or via this role)
- For airgap: a local RPM mirror (e.g., Red Hat Satellite content view) hosting the HashiCorp Vault package and GPG key

## Role Variables

### RPM Repository

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_repo` | `true` | Create `/etc/yum.repos.d/hashicorp.repo` |
| `vault_repo_url` | HashiCorp official | RPM repository base URL |
| `vault_repo_gpg_key` | HashiCorp official | GPG key URL for RPM verification |
| `vault_repo_gpgcheck` | `true` | Enable GPG signature checking |

### Package

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_package_version` | `latest` | Version to install (e.g., `1.18.3-1`) |
| `vault_package_state` | `present` | DNF state: `present` or `latest` |
| `vault_edition` | `vault` | Package/edition: `vault` (Community), `vault-enterprise`, `vault-enterprise-fips1403` (Enterprise FIPS 140-3) |

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_ui_enabled` | `true` | Enable the Vault web UI |
| `vault_disable_mlock` | `false` | Disable memory lock (false = mlock ON) |
| `vault_disable_performance_standby` | `true` | Disable performance standby |
| `vault_log_level` | `info` | Log level: trace, debug, info, warn, error |

### Listener (TLS)

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_listener_address` | `0.0.0.0` | Listener bind address |
| `vault_listener_port` | `8200` | Listener port |
| `vault_tls_cert_file` | `/opt/vault/tls/tls.crt` | Path to TLS certificate on target |
| `vault_tls_key_file` | `/opt/vault/tls/tls.key` | Path to TLS private key on target |
| `vault_tls_ca_file` | `/opt/vault/tls/ca.crt` | Path to CA certificate on target |
| `vault_tls_min_version` | `tls12` | Minimum TLS version |
| `vault_tls_cipher_suites` | `[]` | TLS 1.2 cipher suites (empty = OS/FIPS defaults) |
| `vault_tls_require_client_cert` | `false` | Require mutual TLS client certs |
| `vault_tls_disable_client_certs` | `false` | Disable client cert handling entirely |

### Cluster / HA

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_raft_node_id` | `{{ inventory_hostname_short }}` | Raft node identifier |
| `vault_api_addr` | `https://{{ ansible_fqdn }}:8200` | Advertised API address |
| `vault_cluster_addr` | `https://{{ ansible_fqdn }}:8201` | Cluster replication address |
| `vault_cluster_leader_addr` | `""` | LB/leader address for HA retry_join |

### TLS Certificate Deployment

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_tls` | `false` | Deploy TLS certs from controller |
| `vault_tls_src_cert` | `""` | Source cert path on controller |
| `vault_tls_src_key` | `""` | Source key path on controller |
| `vault_tls_src_ca` | `""` | Source CA path on controller |

### STIG Compliance

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_stig_logrotate_enabled` | `true` | Deploy logrotate config |
| `vault_stig_logrotate_days` | `90` | Log retention (min 90 for STIG) |
| `vault_stig_audit_backup_enabled` | `true` | Deploy audit backup service/timer |
| `vault_stig_audit_backup_retention_days` | `7` | Audit backup retention in days (injected into the backup service as `RETENTION_DAYS`) |
| `vault_stig_aide_check_enabled` | `false` | Deploy AIDE integrity check timer (when aide installed) |
| `vault_init_unseal` | `true` | Unseal after init as part of the init transaction (so audit devices enable); non-HSM |
| `vault_auto_unseal_enabled` | `false` | Deploy the boot-time auto-unseal service (key-at-rest decision; not post-init unseal) |
| `vault_key_shares` | `5` | Shamir key shares for initialization |
| `vault_key_threshold` | `3` | Shamir keys required to unseal |
| `vault_init_capture_dir` | `""` | **Required** controller directory for per-file init-key capture (root token + one file per unseal/recovery share). Root token is never stored on the node |
| `vault_init_capture_mode` | `0600` | File mode for the per-file captured key material on the controller |
| `vault_rsyslog_enabled` | `false` | Enable remote syslog forwarding |
| `vault_rsyslog_host` | `""` | Remote syslog target |
| `vault_rsyslog_port` | `514` | Remote syslog port |

> **AIDE and rsyslog are host-owned.** The role integrates with them only
> when their binary is present and never installs them; enabled-but-absent
> logs a warning and skips. On a STIG host, install `aide` via the host
> baseline and opt in with `vault_stig_aide_check_enabled: true`.

### Firewall

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_firewall` | `true` | Configure firewalld rules |
| `vault_firewall_ports` | `["8200/tcp", "8201/tcp"]` | Ports to open |

### fapolicyd Trust

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_fapolicyd` | `true` | Manage fapolicyd file-trust entries (skips without failure, logging the reason, when fapolicyd/trust.d absent) |
| `vault_fapolicyd_trusted_files` | see defaults | Files registered in fapolicyd file trust (existing regular files only) |

## Dependencies

See `requirements.yml` for Ansible collection dependencies and `requirements.txt`
for Python library dependencies. No other Ansible role dependencies.

## Example Playbook

### Single-Node Deployment (Internet-Connected)

```yaml
- hosts: vault
  become: true
  roles:
    - role: darkhonor.vault
      vars:
        vault_manage_tls: true
        vault_tls_src_cert: "files/vault-tls.crt"
        vault_tls_src_key: "files/vault-tls.key"
        vault_tls_src_ca: "files/ca.crt"
```

### Single-Node Deployment (Airgap)

```yaml
- hosts: vault
  become: true
  roles:
    - role: darkhonor.vault
      vars:
        vault_repo_url: "https://repo.internal.mil/hashicorp/RHEL/$releasever/$basearch/stable"
        vault_repo_gpg_key: "https://repo.internal.mil/hashicorp/gpg"
        vault_package_version: "1.18.3-1"
```

### HA Cluster (3-Node with Load Balancer)

```yaml
- hosts: vault_cluster
  become: true
  roles:
    - role: darkhonor.vault
      vars:
        vault_cluster_leader_addr: "vault-lb.enclave.mil"
        vault_manage_tls: true
        vault_tls_src_cert: "files/{{ inventory_hostname }}-tls.crt"
        vault_tls_src_key: "files/{{ inventory_hostname }}-tls.key"
        vault_tls_src_ca: "files/ca.crt"
        vault_rsyslog_enabled: true
        vault_rsyslog_host: "syslog.enclave.mil"
```

### Migrating from the pre-#34 key-handling variables

The initialization key-handling variables changed to be secure by default (breaking):

| Removed / renamed | Replacement |
|---|---|
| `vault_init_store_target` (default `true`) | **removed** — unseal shares land on the node only when `vault_auto_unseal_enabled: true` (shares only; the root token is never on the node) |
| `vault_init_controller_capture_enabled` | **removed** — controller capture is now unconditional when `vault_initialize: true` |
| `vault_init_controller_output_path` (a JSON file) | `vault_init_capture_dir` — a **required** base directory; the role writes per-file (`root-token`, `unseal-key-*`/`recovery-key-*`) under `<dir>/<inventory_hostname>/`, `0600` each |
| `vault_init_controller_output_mode` | `vault_init_capture_mode` (default `0600`; must be owner-only) |

Unknown variables are silently ignored by Ansible, so an old `vault_init_store_target: false` is simply dropped — the new required-`vault_init_capture_dir` assert fails closed until you set it.

**Upgrading an already-initialized node.** The "no key material on the node by
default" posture is enforced for *new* initializations. On a pre-#34 node that
already has `/etc/vault.d/tokens.env` (shares + root token), running the role
with the new secure default (`vault_auto_unseal_enabled: false`) **disables the
boot auto-unseal service and warns**, but does **NOT delete `tokens.env`** — on
an already-initialized node it may be your only copy of the keys. Preserve the
shares and root token to an approved store, then remove `/etc/vault.d/tokens.env`
from the node yourself.

### Greenfield Initialization — secure key handling

When `vault_initialize: true`, initialization material is secret-bearing, and
the role is **secure by default**:

- **No key material on the node by default.** Unseal shares land in
  `/etc/vault.d/tokens.env` **only** when `vault_auto_unseal_enabled: true`
  (they feed the boot-time unseal service), and even then the file holds
  **shares only** — never the root token.
- **The root token always leaves the node.** It is captured to the controller,
  never persisted on the Vault node.
- **Per-file capture.** The role writes, to the **required** controller
  directory `vault_init_capture_dir`, one file each: `root-token`, and
  `unseal-key-1 … unseal-key-N` (Shamir) or `recovery-key-*` (HSM), `0600`
  each — so you hand each share to a distinct key custodian.

```yaml
- hosts: vault
  become: true
  roles:
    - role: darkhonor.vault
      vars:
        vault_initialize: true
        # REQUIRED base controller directory for per-file key capture. The role
        # writes each host's keys under a per-host subdirectory
        # (<vault_init_capture_dir>/<inventory_hostname>/), so a shared base is safe.
        vault_init_capture_dir: "/runner/artifacts/vault-init"
        # Secure default: no keys on the node. Set true ONLY to accept
        # on-node shares for boot-time auto-unseal (availability trade-off).
        vault_auto_unseal_enabled: false
```

The role uses `no_log: true` for all key-handling tasks and never prints key
material. Distribute each `unseal-key-*` to a custodian / an approved store and
move the `root-token` to your approved secret store, then delete the capture
directory.

> **⚠ Reboot → sealed (secure default).** With `vault_auto_unseal_enabled: false`
> the node has no on-node keys and no boot-unseal service, so **the first reboot
> leaves Vault sealed** — you must run `vault operator unseal` with the
> custodian-held threshold shares. This is the intended secure trade-off. **Do
> NOT delete the capture directory until the shares are preserved** in an
> approved store / with custodians, or the Raft data becomes unrecoverable.

## Initialization Transaction

When `vault_initialize: true`, the role runs a single init **transaction**:
`vault operator init` → **unseal** (Shamir threshold, from the in-memory init
output) → **enable the file and syslog audit devices**. It is all-or-nothing:
an initialized-but-sealed Vault with no audit devices is not a valid end
state of this role.

Two distinct flags control unsealing — do not confuse them:

- **`vault_init_unseal`** (default `true`) — unseal immediately after init,
  as **part of the init transaction**, so audit devices can be enabled. This
  is what makes the transaction complete on a fresh node; it is independent
  of the boot-time service below. (Non-HSM only; an HSM seal auto-unseals
  regardless.)
- **`vault_auto_unseal_enabled`** (default `false`) — deploy the **boot-time**
  `vault-unseal.service` (next section). A standing key-at-rest decision, NOT
  about completing initialization.

**Rare opt-out.** Set `vault_init_unseal: false` only to "initialize but leave
sealed" (e.g. a manual key ceremony). The role then skips unseal **and** audit
enablement and prints a warning that audit devices must be enabled manually
after the first `vault operator unseal` — it does **not** fail mid-run.
Combining `vault_init_unseal: false` with `vault_auto_unseal_enabled: true`
**in the same run is rejected** (it would auto-unseal on boot into a
never-audited state).

**Known limitation.** The audit-before-auto-unseal invariant is enforced at
init time only. If you initialize-without-unseal in one run and later enable
the boot-time auto-unseal service in a **separate** run, the role cannot
detect the missing audit devices — enable audit devices before enabling the
boot-time service.

## Auto-Unseal (Community Edition, Shamir Keys)

This section covers the **boot-time** auto-unseal service, distinct from the
post-init unseal (`vault_init_unseal`) described above. When
`vault_auto_unseal_enabled` is `true` (and `vault_hsm_enabled` is
`false`), the role deploys `vault-unseal.service`, a oneshot unit
(`RemainAfterExit=yes`) that runs after `vault.service` on boot and applies
the Shamir key shares stored in `/etc/vault.d/tokens.env`. Explicit
restarts of Vault propagate to the unit (`Requires=`/`PartOf=`), and the
unit is also wanted by `vault.service` itself so a stop-then-start cycle
re-pulls it; both couplings are noted as open verification items in the
behavior contract at the end of this section.

**Privilege model.** The service runs as **root** by design: the tokens
file is `root:root` mode `0600`, and `/etc/vault.d` itself is
`root:vault 0750` (enforced by the role on every full run), so the vault
service account can read its own configs via group access but can neither
read the keys at rest nor replace the tokens file — the parent directory
matters because the file is `source`d by root, and write access to a
directory allows file replacement regardless of file ownership. During
the unseal window itself the keys currently transit
`vault operator unseal` argv, which is visible in the process table;
closing that channel by moving unseal to the API is tracked as issue #31.
The script at `/usr/local/bin/vault-unseal.sh` is `root:root` so the
service account cannot edit what root executes, and the script itself
refuses to run if the directory is untrusted (not root-owned, or
group/other-writable) or if the tokens file carries ANY group/other
access bits (key material must be `0600`). An operator-placed tokens
file (when the unseal shares are managed out-of-band rather than written by
the role) goes at the same path with the same `root:root 0600` posture — the script refuses
anything looser. Do not add a service-account directive to the unit
without changing that model. Note the model's residual scope:
`vault.hcl`/`vault.env` file ownership remains `vault:vault` pending
issue #38, and an out-of-band `dnf update vault` may revert
`/etc/vault.d` to the RPM's shipped ownership until the next role run —
the unseal script fails closed (refuses to unseal) rather than trusting
an unexpected parent, so re-run the **full** role after out-of-band
package updates. A `--tags system` run does not suffice: the role's
phases are dynamically included, so tags do not propagate to the
ownership-remediation task (see the fapolicyd note and issue #28).

**Upgrading from earlier role versions.** The tokens file path is
unchanged; on the next full role run the directory ownership tightens
(`vault:vault` to `root:vault`) and the role repairs the unseal unit's
`[Install]` links by state: it checks for the `vault.service.wants`
symlink every run and re-enables the unit when the link is missing (a
plain `enabled: true` cannot refresh `[Install]` symlinks on
already-enabled hosts, and a notify-based repair would be lost if a run
aborts). When the AIDE check is enabled, AIDE will report the
`/etc/vault.d` ownership change on every daily check until the baseline is
refreshed — after the upgrade, run
`aide --update` and move `/var/lib/aide/aide.db.new.gz` to
`/var/lib/aide/aide.db.gz` (the file the daily check reads), or delete
`aide.db.gz` and re-run the role, which re-initializes the baseline.

**Behavior contract.** The script waits (bounded, default 60 s, 2 s
retry interval) for the Vault API to answer before unsealing, refuses to
apply keys to an uninitialized Vault, applies keys only until Vault
reports unsealed, and its exit code is honest: `0` only when Vault is
unsealed, non-zero when the API never answered, the tokens path is
untrusted, or Vault remained sealed — so a failed boot-time unseal shows
as a failed unit in `systemctl`/monitoring instead of silently reporting
success. The script's behavior is covered by `tests/vault-unseal-test.sh`
(run in CI); unit-level behavior (root execution, ordering, restart
coupling, and the start re-pull via `WantedBy=vault.service`) and
end-to-end reboot verification on a physical RHEL 9 host remain open
verification items.

**Security trade-off.** Storing Shamir shares on the node defeats the
split-knowledge intent of `vault_key_shares`/`vault_key_threshold` for any
adversary with root or disk access. Prefer the HSM PKCS#11 seal
(`vault_hsm_enabled`, Enterprise) or manual unseal where operationally
feasible; see issue #34 for the planned secure-by-default init handoff.

## fapolicyd File Trust

When `vault_manage_fapolicyd` is `true` (the default) and a
trust.d-capable fapolicyd is detected, the role renders a declarative
ancillary trust file at `/etc/fapolicyd/trust.d/vault.trust` containing
size + SHA-256 entries for the Vault binary, a pre-positioned
`/usr/local/bin/vault` (future binary-install location), and the two helper
scripts the role deploys to `/usr/local/bin`; then — when the daemon is
running and the trust file or the vault package changed — hot-reloads the
daemon's trust database with `fapolicyd-cli --update` before the Vault
service is started. Entries are computed from the files actually present at run time,
so the hashes always match the installed version. Duplicate list entries
are deduped by the role. Paths containing whitespace cannot be represented
in the space-delimited trust format and are silently excluded.

**rpmdb vs file trust.** The RPM-installed `/usr/bin/vault` is already
trusted via fapolicyd's rpmdb backend; the explicit file-trust entry
documents intent and covers file-trust-only configurations. When the same
path appears in both backends, fapolicyd's duplicate resolution is
version-dependent and has not been confirmed for all target releases.

**Operational contract.** Re-run this role after every vault package
transaction. An out-of-band upgrade (e.g. a Satellite patch cycle without
a role run) leaves the trust.d entry with the old size/hash; depending on
the host's `integrity =` setting and duplicate resolution, that stale
entry MAY deny execution of the upgraded binary. Operators who cannot
guarantee re-runs should override `vault_fapolicyd_trusted_files` to drop
`{{ vault_binary }}`. In-band upgrades (performed by this role) are
covered when detection passes and the daemon is active — contingent on
`fapolicyd-cli --update` refreshing the rpmdb backend (see the
verification-items disposition) or on trust.d winning duplicate
precedence.

**Host-baseline dependencies** (this role manages none of these):

- `trust =` in `/etc/fapolicyd/fapolicyd.conf` must include `file` for
  trust.d to be consulted at all (the role warns when an *uncommented*
  `trust =` line omits `file`; an absent or commented-out key is NOT
  detected — the no-key branch assumes the compiled-in default includes
  `file`, pending verification item 8); `integrity =` governs whether
  size/hash are verified at execution time; `permissive = 0` is required
  for enforcement.
- A trust.d-capable fapolicyd. Older EL8 builds using the single
  `/etc/fapolicyd/fapolicyd.trust` file are detected and skipped — the
  role provides no refresh there at all. Minimum trust.d-capable version
  per EL major: pending verification item 4.
- The fapolicyd dnf plugin keeps the rpmdb trust snapshot fresh for
  out-of-band upgrades (presence on target hosts: pending verification
  item 9); without it, staleness persists until the daemon reloads. This also applies when `vault_manage_fapolicyd` is `false` (or
  detection skips) and an upgrade occurs on an enforcing plugin-less
  host — that combination is not benign.
- The shipped rules.d must honor trust for `ftype=text/x-shellscript` on
  the interpreter-open path — both helper scripts reach execution via
  interpreter-open (env-bash shebangs), and the nominally direct-exec
  `vault-audit-backup.service` path also fires an exec-perm check on the
  script file, so both exec and open rules apply there.

**Disabling.** Setting `vault_manage_fapolicyd: false` stops the role from
touching fapolicyd entirely — including a previously deployed trust file.
Manual cleanup: `rm /etc/fapolicyd/trust.d/vault.trust && fapolicyd-cli
--update`.

## Audit Log Backups

When `vault_stig_audit_backup_enabled` is true (the default), a daily
systemd timer runs `vault-audit-backup.sh` as root to stage Vault audit
device logs, Vault-related auditd extracts, and service journals under
`/opt/vault-backup` (RHEL 9 STIG V-205167).

**Privilege model (Secure by Default).** The backup job copies auditd
content that the operating system protects at root-only (`/var/log/audit/`
is 0600 root, and auditd records can contain execve argv). The backup tree
therefore stays root-only end to end:

- `/opt/vault-backup` and every `backup-*` subdirectory: `root:root`, mode
  `0700`.
- Every backup file: `root:root`, mode `0600`.
- The unprivileged `vault` service account has **no read access** to the
  backup tree. A compromised vault process cannot read historical audit
  extracts about itself. `find /opt/vault-backup ! -user root` returns
  nothing after a run.
- The script re-enforces this ownership/mode contract on every run. On
  hosts upgraded from earlier releases (which created the `backup-*`
  subdirectories `vault:vault`), the role immediately sets the top-level
  directory to `root:root` mode `0700` - denying the vault account all
  access to the subtree - and the remaining legacy content is swept to
  `root:root` `0700`/`0600` by the first backup run after the upgrade.

There is no supported way to grant the vault account read access through
role variables; operators who need to export backups should pull them via
a root-privileged transfer path.

**Retention.** `vault_stig_audit_backup_retention_days` (default 7) is
injected into `vault-audit-backup.service` as the `RETENTION_DAYS`
environment variable and controls when `backup-*` directories are purged.
The script falls back to 7 days if the value is unset or not a
non-negative integer.

**Local-staging boundary.** This job is local staging only: backups remain
plaintext on the same host, and integrity checking is limited to
`gzip -t`. Off-host transfer is the enclave's log-forwarding path (see the
`vault_rsyslog_*` variables for remote syslog forwarding); it is out of
scope for this backup job.

## Compliance

This role implements controls from:

- **DISA STIG**: Application Security and Development STIG, RHEL 9 STIG
- **NIST SP 800-53 Rev 5**: AC-6, AU-4, AU-6 (remote syslog forwarding when rsyslogd is present), AU-9 (root-only audit backup staging), CM-7(5) (when a trust.d-capable fapolicyd is installed and enforcing with file trust enabled), SC-7, SC-8, SC-13, SC-23, SC-28, SI-7 (AIDE integrity check is opt-in and presence-gated)
- **CNSSI 1253**: Moderate-Moderate-Moderate dimensional baselines
- **CNSA 1.0** (CNSSP-15 / APSC-DV-002010): ECDSA P-384, RSA-3072+, SHA-384, AES-256-GCM
- **FIPS 140-3**: TLS 1.2+ enforcement, FIPS-validated cryptographic modules

Auto-unseal uses the configured CA certificate path for TLS verification. The
role does not disable certificate verification for Vault API calls.

AC-6 qualifier: `vault-unseal.service` (when `vault_auto_unseal_enabled` is
`true`) runs as root — a deliberate exception so unseal key material stays
root-only rather than readable by the service account; see the Auto-Unseal
section for the model and its trade-offs.

## License

Apache-2.0

## Author Information

Alex Ackerman ([@darkhonor](https://github.com/darkhonor))
