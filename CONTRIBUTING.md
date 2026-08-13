# Contributing to ansible-role-vault

Thank you for your interest in contributing to this Ansible role!

## Code of Conduct

Please be respectful and constructive in all interactions.

## Development Environment Setup

### RHEL 9 Python Configuration

RHEL 9 system tools (like `subscription-manager`, `dnf`, etc.) require Python 3.9.
However, `ansible-core` 2.17+ requires Python 3.10+. To avoid breaking system tools,
we use a dual-Python setup:

| Command    | Version | Purpose                                    |
|------------|---------|------------------------------------------- |
| `python3`  | 3.9.x   | System tools (subscription-manager, dnf)  |
| `python`   | 3.11.x  | Development tools (ansible, pre-commit)   |

#### Installing Python 3.11 on RHEL 9

```bash
# Install Python 3.11 from EPEL
sudo dnf install -y epel-release
sudo dnf install -y python3.11 python3.11-pip python3.11-devel

# Configure alternatives (keep python3 pointing to 3.9 for system tools)
sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 3
sudo alternatives --set python3 /usr/bin/python3.9

# Set python (without the 3) to use 3.11 for development
sudo alternatives --install /usr/bin/python python /usr/bin/python3.11 2
sudo alternatives --set python /usr/bin/python3.11

# Verify configuration
python3 --version   # Should show Python 3.9.x
python --version    # Should show Python 3.11.x
```

> **WARNING**: Do NOT change `python3` to point to Python 3.11. This will break
> `subscription-manager`, `dnf`, and other RHEL system tools. Recovery requires
> manually creating a temporary repo with entitlement certificates to reinstall
> `subscription-manager`. Don't ask how we know this.

#### Installing Development Dependencies

All Python dependencies are pinned in `requirements.txt` for consistency between
local development and CI/CD. Choose **one** of the following installation methods:

##### Option A: System-wide Installation (Simpler)

Install tools directly using the `python` (3.11) command:

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install all dev dependencies from requirements.txt
python -m pip install -r requirements.txt
```

##### Option B: Virtual Environment (Isolated)

Use a venv to isolate development dependencies from the system:

```bash
# Create a virtual environment with Python 3.11
python3.11 -m venv ~/.venv/ansible-dev

# Add activation alias to your shell (optional convenience)
echo 'alias ansible-dev="source ~/.venv/ansible-dev/bin/activate"' >> ~/.bashrc
source ~/.bashrc

# Activate the virtual environment
source ~/.venv/ansible-dev/bin/activate
# Or use the alias: ansible-dev

# Install dependencies inside the venv
pip install --upgrade pip
pip install -r requirements.txt

# Deactivate when done
deactivate
```

> **Note**: When using a venv, you must activate it before running any development
> commands (ansible-lint, molecule, pre-commit, etc.).

##### Verify Installation

Regardless of which method you chose:

```bash
ansible --version      # Should show Python 3.11.x
ansible-lint --version
yamllint --version
pre-commit --version
molecule --version
```

### Pre-commit Hooks

This repository uses pre-commit hooks to ensure code quality before commits:

```bash
# Install hooks (one-time setup)
pre-commit install

# Run manually on all files
pre-commit run --all-files

# Hooks will run automatically on git commit
```

The following hooks are configured:
- **yamllint** - YAML syntax and style validation
- **ansible-lint** - Ansible best practices (production profile)
- **trailing-whitespace** - Remove trailing whitespace
- **end-of-file-fixer** - Ensure files end with newline
- **check-yaml** - Validate YAML syntax
- **check-added-large-files** - Prevent large files (>500KB)
- **check-merge-conflict** - Detect merge conflict markers
- **detect-private-key** - Prevent accidental key commits

### Shell Script Testing

`files/vault-audit-backup.sh` has a behavioral test harness at
`tests/vault-audit-backup-test.sh`. The CI lint job runs shellcheck and
the harness; run them locally before submitting:

```bash
shellcheck files/vault-audit-backup.sh tests/vault-audit-backup-test.sh
bash tests/vault-audit-backup-test.sh
```

Coverage for `files/vault-unseal.sh` lands with the auto-unseal
hardening work (issue #30). New helper scripts should ship with their
own harness and be added to both CI steps.

The harness is non-root friendly: external commands are mocked via PATH
shims (chmod is a pass-through shim with targeted failure injection) and
all paths are redirected into a temporary sandbox.

### Molecule Testing

Molecule tests require Podman (not Docker) on RHEL:

```bash
# Install Podman
sudo dnf install -y podman

# Run full test suite
molecule test

# Development workflow (faster iteration)
molecule converge   # Create and apply role
molecule verify     # Run verification tests
molecule destroy    # Clean up
```

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Include RHEL version, Ansible version, Vault version, and relevant STIG IDs
- Provide steps to reproduce the issue

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/vault-stig-brief-description
   ```
3. **Follow the code style**:
   - Comments wrap at 80 characters
   - Use FQCN for all modules (`ansible.builtin.*`)
   - Include STIG/NIST comment blocks for all compliance tasks
4. **Test your changes**:
   ```bash
   yamllint .
   ansible-lint
   molecule test
   ```
5. **Commit** with a descriptive message:
   ```bash
   git commit -m "Add NIST-SC-8: Configure TLS minimum version"
   ```
6. **Push** and open a Pull Request

### Task Structure

All compliance-related tasks must follow this format:

```yaml
###########################################################
# NIST 800-53: SC-8 (Transmission Confidentiality)
# STIG Ref: Application Security STIG V-XXXXXX (if applicable)
# Severity: CAT I | CAT II | CAT III
# Description: Brief description of what this control
#   ensures (wrap at 80 chars)
###########################################################
- name: vault | Configure TLS minimum version
  ansible.builtin.template:
    src: vault.hcl.j2
    dest: /etc/vault.d/vault.hcl
    owner: vault
    group: vault
    mode: '0640'
  notify: Restart vault
  tags:
    - vault
    - configure
    - NIST-SC-8
```

Non-compliance tasks (e.g., package installation, directory creation) use a
simpler format:

```yaml
- name: vault | Install HashiCorp Vault package
  ansible.builtin.dnf:
    name: "vault-{{ vault_package_version }}"
    state: "{{ vault_package_state }}"
  tags:
    - vault
    - install
```

### Adding New STIG/NIST Controls

1. Reference the authoritative STIG XCCDF or NIST 800-53 control catalog
2. Add variables to `defaults/main.yml` (user-configurable) or
   `vars/main.yml` (internal)
3. Update the README.md compliance and variables tables
4. Include verification in `molecule/default/verify.yml`

### Task File Organization

Tasks are split into logical phases in `tasks/`:

| File | Purpose |
|------|---------|
| `preflight.yml` | Pre-flight validation |
| `repo.yml` | RPM repository configuration |
| `install.yml` | Package installation |
| `system.yml` | Directories, users, permissions |
| `tls.yml` | TLS certificate deployment |
| `configure.yml` | vault.hcl deployment |
| `firewall.yml` | firewalld rules |
| `stig.yml` | STIG hardening (audit, AIDE, logrotate) |
| `service.yml` | systemd service management |

## Questions?

Open an issue with the `question` label.
