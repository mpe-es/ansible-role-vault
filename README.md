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
| `vault_stig_audit_backup_retention_days` | `7` | Audit backup retention |
| `vault_stig_aide_check_enabled` | `true` | Deploy AIDE integrity check timer |
| `vault_auto_unseal_enabled` | `false` | Deploy auto-unseal service |
| `vault_key_shares` | `5` | Shamir key shares for initialization |
| `vault_key_threshold` | `3` | Shamir keys required to unseal |
| `vault_init_store_target` | `true` | Store init output on the target in `/etc/vault.d/tokens.env` |
| `vault_init_controller_capture_enabled` | `false` | Capture init output back to the Ansible controller/AAP execution environment |
| `vault_init_controller_output_path` | `""` | Controller-side path for captured init JSON |
| `vault_init_controller_output_mode` | `0600` | File mode for controller-side captured init JSON |
| `vault_rsyslog_enabled` | `false` | Enable remote syslog forwarding |
| `vault_rsyslog_host` | `""` | Remote syslog target |
| `vault_rsyslog_port` | `514` | Remote syslog port |

### Firewall

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_firewall` | `true` | Configure firewalld rules |
| `vault_firewall_ports` | `["8200/tcp", "8201/tcp"]` | Ports to open |

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

### Greenfield Initialization with AAP Capture

When `vault_initialize` is enabled, initialization material is secret-bearing.
By default, the role preserves existing behavior and writes
`/etc/vault.d/tokens.env` on the target with mode `0600`. For Ansible
Automation Platform workflows, capture the raw init JSON back to the execution
environment and immediately move it into an approved secret store:

```yaml
- hosts: vault
  become: true
  roles:
    - role: darkhonor.vault
      vars:
        vault_initialize: true
        vault_init_store_target: false
        vault_init_controller_capture_enabled: true
        vault_init_controller_output_path: "/runner/artifacts/vault-init-{{ inventory_hostname }}.json"
```

The role uses `no_log: true` for initialization tasks and never prints the root
token or unseal keys. Treat the controller-side artifact as temporary key
material and remove it after transfer to the approved credential store.

## Compliance

This role implements controls from:

- **DISA STIG**: Application Security and Development STIG, RHEL 9 STIG
- **NIST SP 800-53 Rev 5**: AC-6, AU-4, AU-6, SC-7, SC-8, SC-13, SC-23, SC-28, SI-7
- **CNSSI 1253**: Moderate-Moderate-Moderate dimensional baselines
- **CNSA 1.0** (CNSSP-15 / APSC-DV-002010): ECDSA P-384, RSA-3072+, SHA-384, AES-256-GCM
- **FIPS 140-3**: TLS 1.2+ enforcement, FIPS-validated cryptographic modules

Auto-unseal uses the configured CA certificate path for TLS verification. The
role does not disable certificate verification for Vault API calls.

## License

Apache-2.0

## Author Information

Alex Ackerman ([@darkhonor](https://github.com/darkhonor))
