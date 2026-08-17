<!--
  Thank you for contributing to ansible-role-vault.
  Please complete the sections below. See CONTRIBUTING.md for full guidance.
-->

## Summary

<!-- What does this change do, and why? -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New STIG / NIST 800-53 control coverage
- [ ] Seal, unseal, or key-handling behavior
- [ ] TLS or listener configuration
- [ ] HA Raft cluster behavior
- [ ] Change to a default value in `defaults/main.yml`
- [ ] CI / tooling / supply-chain
- [ ] Documentation
- [ ] Breaking change (existing behavior changes for consumers)

## Related issues

<!-- e.g. "Closes #123". Use "Refs #123" for partial work. -->

## Control references

<!--
  If this touches remediation, list the affected NIST 800-53 control or STIG
  rule IDs and the baseline version. Write "N/A" if not applicable.
-->

## Testing performed

<!--
  Paste the result of the local checks, and name which Molecule scenarios you
  ran. State honestly if a scenario was not run.
-->

```
yamllint .
ansible-lint
ansible-playbook tests/test.yml --syntax-check
molecule test -s default    # and/or -s init, -s hsm
```

## Checklist

- [ ] Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `deps:`, `chore:`)
- [ ] `yamllint` passes locally
- [ ] `ansible-lint` passes locally
- [ ] Playbook `--syntax-check` passes
- [ ] Molecule passes for every scenario affected by this change
- [ ] Every new or modified YAML file carries the UNCLASSIFIED classification banner
- [ ] `Last Updated` is current in the banner of every file I changed
- [ ] All modules use FQCN (`ansible.builtin.*`)
- [ ] Documentation (README / CONTRIBUTING / defaults) updated as needed
- [ ] `CHANGELOG.md` `[Unreleased]` section updated

## Security checklist

<!--
  This role handles unseal shares, root tokens, the HSM PIN, and TLS private
  keys. Every item below corresponds to a defect class already fixed in this
  repository. Confirm each, or explain why it does not apply.
-->

- [ ] No secret is passed as a command-line argument (it would land in `auditd` `execve` argv)
- [ ] No secret is rendered into a group-readable file such as `vault.hcl`
- [ ] Any task that could emit a secret sets `no_log: true`, and any template that could is `diff: false`
- [ ] No change grants the `vault` service account write access to `vault.hcl`, `vault.env`, the TLS material, or `/opt/vault/tls`
- [ ] `gpgcheck`, `vault_tls_min_version`, and cipher defaults are not weakened
- [ ] Unseal success is verified by re-reading seal status, not inferred from a command exiting zero
- [ ] No real key material appears in code, comments, tests, fixtures, or commit messages
- [ ] This PR does not report a security vulnerability (use private reporting instead)

<!--
  Do not report security vulnerabilities in a public pull request.
  See SECURITY.md for private reporting.
-->
