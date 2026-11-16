# Contributing to ansible-role-vault

Thank you for your interest in contributing to this Ansible role!

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Please be
respectful and constructive in all interactions.

## Reporting a Security Vulnerability

Do not open a public issue or pull request for a security vulnerability, and
never paste real key material (unseal shares, root tokens, HSM PINs, TLS
private keys) into either. See [SECURITY.md](SECURITY.md) for the private
disclosure process.

## Development Environment Setup

### RHEL 9 Python Configuration

RHEL 9 system tools (like `subscription-manager`, `dnf`, etc.) require Python 3.9.
However, `ansible-core` 2.20+ requires Python 3.12+. To avoid breaking system tools,
we use a dual-Python setup:

| Command    | Version | Purpose                                    |
|------------|---------|------------------------------------------- |
| `python3`  | 3.9.x   | System tools (subscription-manager, dnf)  |
| `python`   | 3.12.x  | Development tools (ansible, pre-commit)   |

#### Installing Python 3.12 on RHEL 9

```bash
# python3.12 is in AppStream on EL8/9/10 -- no EPEL needed
sudo dnf install -y python3.12 python3.12-pip python3.12-devel

# Configure alternatives (keep python3 pointing to 3.9 for system tools)
sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 3
sudo alternatives --set python3 /usr/bin/python3.9

# Set python (without the 3) to use 3.12 for development
sudo alternatives --install /usr/bin/python python /usr/bin/python3.12 2
sudo alternatives --set python /usr/bin/python3.12

# Verify configuration
python3 --version   # Should show Python 3.9.x
python --version    # Should show Python 3.12.x
```

> **WARNING**: Do NOT change `python3` to point to Python 3.12. This will break
> `subscription-manager`, `dnf`, and other RHEL system tools. Recovery requires
> manually creating a temporary repo with entitlement certificates to reinstall
> `subscription-manager`. Don't ask how we know this.

#### Installing Development Dependencies

This repository keeps **three** pinned manifests. Contributors need the first
two; the release workflow uses the third. They are not
interchangeable:

| File | Contains | Who needs it |
|------|----------|--------------|
| `requirements.txt` | The **runtime** dependency chain only — `hvac` (for `community.hashi_vault` on the target) and `netaddr` (for `ansible.utils.ipaddr` on the controller) | The role at run time |
| `requirements-dev.txt` | The **development toolchain** — `ansible-core`, `ansible-lint`, `yamllint`, `molecule`, `molecule-plugins[podman]`, `pre-commit`, `pre-commit-hooks` | You, to run the gates below |
| `requirements-release.txt` | The **minimal release toolchain** — `ansible-core` and only its closure | The Galaxy publication job while it holds `GALAXY_API_KEY` |

Both are compiled with `pip-compile --generate-hashes` from their `.in` source
files, so installs are reproducible and hash-verified. **CI installs from the
same two files**, which is what keeps your local toolchain and CI's identical —
`ansible-core` in particular is pinned to one version across the development
and release source/lock pairs, `.github/workflows/ci.yml`, and
`.github/workflows/release.yml`. The pre-commit hooks run from
`requirements-dev.txt` and carry no versions of their own.
`tests/assert-core-pin-coupling.sh` makes a partial update fail closed and
enforces that every hook stays local. Dependabot keeps the pip locks and the
GitHub Actions current; Renovate keeps the exact Galaxy collection pins in
`requirements.yml` current.

> **NOTE**: `shellcheck` is not a Python distribution, and it is not in
> `bindep.txt` either — that file feeds the Execution Environment build, and
> shellcheck is a development tool, not a runtime dependency. CI installs
> **v0.11.0** from the upstream release, verified against its SHA-256 digest
> (`.github/workflows/ci.yml`, "Install shellcheck (pinned)"). Install the same
> version locally: versions disagree on findings (v0.11.0 does not report SC2015
> where older builds do), so a pass on a different version is not CI evidence.

Choose **one** of the following installation methods:

##### Option A: System-wide Installation (Simpler)

Install tools directly using the `python` (3.12) command:

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install the development toolchain (linters, molecule, pre-commit)
python -m pip install --require-hashes -r requirements-dev.txt

# Install the runtime dependency chain
python -m pip install --require-hashes -r requirements.txt

# Install the Ansible collections the role and its lint run need
ansible-galaxy collection install -r requirements.yml
```

##### Option B: Virtual Environment (Isolated)

Use a venv to isolate development dependencies from the system:

```bash
# Create a virtual environment with Python 3.12
python3.12 -m venv ~/.venv/ansible-dev

# Add activation alias to your shell (optional convenience)
echo 'alias ansible-dev="source ~/.venv/ansible-dev/bin/activate"' >> ~/.bashrc
source ~/.bashrc

# Activate the virtual environment
source ~/.venv/ansible-dev/bin/activate
# Or use the alias: ansible-dev

# Install dependencies inside the venv -- both manifests
pip install --upgrade pip
pip install --require-hashes -r requirements-dev.txt
pip install --require-hashes -r requirements.txt

# Install the Ansible collections the role and its lint run need
ansible-galaxy collection install -r requirements.yml

# Deactivate when done
deactivate
```

> **Note**: When using a venv, you must activate it before running any development
> commands (ansible-lint, molecule, pre-commit, etc.).

##### Verify Installation

Regardless of which method you chose:

```bash
ansible --version      # Should show Python 3.12.x
ansible-lint --version
yamllint --version
pre-commit --version
molecule --version
```

### Pre-commit Hooks

This repository uses pre-commit hooks to ensure code quality before commits:

```bash
# Install hooks with the requirements-dev.txt toolchain (see below)
python -m pre_commit install

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
- **check-added-large-files** - Reject any file over 500 KB, new or
  existing (`--enforce-all`)
- **check-merge-conflict** - Reject conflict markers in any file, even
  outside a merge (`--assume-in-merge`; it matches the standard Git marker
  lines, so a Markdown heading underlined with exactly `=======` is also
  rejected)
- **detect-private-key** - Prevent accidental key commits

The CI lint job runs these hooks with `pre-commit run --all-files`, plus
actionlint on the workflows, shellcheck, the behavioral suites
(`tests/*-test.sh`), and the static guards (`tests/assert-*.sh`). At commit
time ansible-lint scans the whole project, but the other hooks check only the
files the commit stages, so run `pre-commit run --all-files` before pushing.

#### Every hook uses your installed toolchain

Every hook is a `repo: local` hook. pre-commit does not build an environment or
download anything for them (ansible-lint runs `offline` and uses the collections
installed from `requirements.yml`); each runs the matching command (`yamllint`,
`ansible-lint`, `trailing-whitespace-fixer`, and the other `pre-commit-hooks`
commands) that is first on your `PATH`. Those are the versions you installed
from the hash-pinned `requirements-dev.txt`, which are the same versions CI
runs, so a rule that fails in CI also fails your commit for the files it stages,
and there is no second copy of any version in `.pre-commit-config.yaml` to keep
in sync. For Python tooling, Dependabot updates `requirements-dev.in` and
`requirements-dev.txt` only. The ansible-lint hook runs on every commit,
including commits that only change the lock.

This means:

- **Install the dependencies before running pre-commit.** Use Option A or Option
  B above, including the `ansible-galaxy collection install` step. With a venv,
  activate it before `git commit`. Commits made from an IDE or GUI Git client
  use that tool's environment, which may not include the venv.
- **Run `pre-commit install` with the locked pre-commit.** The config requires
  pre-commit 4.5.0 or later. `pre-commit install` records the Python
  interpreter that ran it, and every later `git commit` uses that interpreter's
  pre-commit, even with the venv active. Run `python -m pre_commit install`
  (with the venv active, for Option B) so the locked pre-commit is recorded.
  If you installed the hooks earlier with a distro or pipx pre-commit, run it
  again.
- **Reinstall after the lock changes.** When you pull a change to
  `requirements-dev.txt` or `requirements.txt`, such as a merged Dependabot
  update, rerun:

  ```bash
  python -m pip install --require-hashes -r requirements-dev.txt -r requirements.txt
  ```

  When `requirements.yml` changes, also rerun
  `ansible-galaxy collection install -r requirements.yml`. Until you do, the
  hooks run the previous versions and can disagree with CI.
- **Check the versions match.** `ansible-lint --version` reports the
  ansible-lint and ansible-core versions in use, `yamllint --version` the
  yamllint version, and `python -m pip show pre-commit-hooks` the hygiene
  hooks' version. They should equal the pins in `requirements-dev.txt`.
- **When `pre-commit-hooks` is bumped,** the local hook definitions in
  `.pre-commit-config.yaml` are a copy of upstream's `.pre-commit-hooks.yaml`
  for the pinned version. Compare them with the new version's file in the same
  pull request and carry over any changed `entry`, `types`, or `stages`.

Troubleshooting:

- ``Executable `<command>` not found``: the dependencies are not installed or
  the venv is not active.
- ``jinja[invalid]: ... No filter named 'ansible.utils.ipaddr' found``, or
  ansible-lint warnings about `resolved_fqcn`: the `requirements.yml`
  collections are not installed. Run the `ansible-galaxy collection install`
  step above.
- `pre-commit version 4.5.0 is required but version X is installed`: the git
  hook was installed by an older pre-commit. Rerun `pre-commit install` as
  described above.
- A traceback, or results that differ from CI: another copy of the tool
  earlier on your `PATH` (for example a pipx or distro copy) is being used.
  Check that `command -v ansible-lint` (or the failing command) points into
  your venv or Option A install, and that the version check above matches
  `requirements-dev.txt`.

### Shell Script Testing

`files/vault-audit-backup.sh` has a behavioral test harness at
`tests/vault-audit-backup-test.sh`. The CI lint job runs shellcheck over
every tracked shell script, as listed by `tests/lib/list-shell-scripts.sh`, and
runs the harness; run them locally before submitting:

```bash
bash tests/lib/list-shell-scripts.sh | xargs shellcheck
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
   pre-commit run --all-files
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
    name: "{{ vault_package_name }}-{{ __vault_package_version_resolved }}"
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
