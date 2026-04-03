# Ansible Role: HashiCorp Vault

Install and configure HashiCorp Vault on RHEL systems with DISA STIG compliance.
Supports single-node and HA (3/5-node) Raft clusters in airgap or internet-connected environments.

## Requirements

- RHEL 8 or 9 (or compatible EL distribution)
- Ansible 2.10+
- `ansible.posix` collection (for firewalld module)
- TLS certificates for the Vault listener (provided externally or via this role)
- For airgap: a local RPM mirror hosting the HashiCorp Vault package and GPG key

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
| `vault_rsyslog_enabled` | `false` | Enable remote syslog forwarding |
| `vault_rsyslog_host` | `""` | Remote syslog target |
| `vault_rsyslog_port` | `514` | Remote syslog port |

### Firewall

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_firewall` | `true` | Configure firewalld rules |
| `vault_firewall_ports` | `["8200/tcp", "8201/tcp"]` | Ports to open |

## Dependencies

None.

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

## Compliance

This role implements controls from:

- **DISA STIG**: Application Security and Development STIG
- **NIST SP 800-53 Rev 5**: AC-6, AU-4, AU-6, SC-7, SC-8, SC-23, SC-28, SI-7
- **FIPS 140-3**: TLS 1.2+ enforcement, approved cryptographic algorithms

## License

Apache-2.0

## Author Information

Alex Ackerman ([@darkhonor](https://github.com/darkhonor))
