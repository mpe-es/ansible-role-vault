# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Preflight gate for the certificate SAN contract.** Preflight verified that the
  TLS trio *exists* and never looked inside it, so a certificate missing the
  `127.0.0.1` IP SAN passed all twelve gates, the role converged the host in full
  — package installed, config written, STIG hardening applied, firewall opened —
  and only then did init and unseal fail at service start. Same
  late-failure-after-mutation class Phase 1 exists to eliminate, on the **default**
  TLS path. Measured on live hardware rather than inferred: a certificate carrying
  `DNS:<fqdn>` and the node's own IP but no loopback SAN yields `x509: certificate
  is valid for 10.110.11.55, not 127.0.0.1` from the loopback callers, while the
  **same certificate works via the FQDN** — it is not invalid, merely unusable by
  this role. The gate checks the two things the role itself depends on: the
  loopback IP SAN, and the `vault_api_addr` host encoded to match its **type**
  (a `DNS:` SAN does not validate `https://10.0.0.5`). It inspects on the
  **controller** for the managed path and the **target** for the staged path,
  since that is where each certificate lives; a relative `vault_tls_src_cert` and
  `vault_tls_source: vault_pki` are **reported as uninspectable, never rejected**,
  following the precedent set by #80. DNS comparison is case-insensitive and
  trailing-dot tolerant per RFC 4343. Scope is deliberately narrow — expiry, key
  size, chain trust and EKU are out of scope, so a pass is never mistaken for
  "this certificate is good". Five behavioural cases in the container-free
  harness. (#85)
- **Preflight gate for the role-managed TLS path.** `vault_manage_tls: true` had
  no preflight coverage at all: `vault_tls_src_cert`/`_key`/`_ca` and
  `vault_pki_mount`/`_role` all default to `""` and pass argspec validation, so an
  operator who enabled managed TLS and forgot the sources got a converged
  repository, an installed package, created directories and applied SELinux
  contexts — and only then a copy failure on an empty `src`. The new
  `managed_tls` gate is the exact mirror of the existing `tls` gate's inverted
  polarity. A source being **set** is always required — no search order rescues
  an unset variable. Beyond that the gate verifies only what it can answer
  without guessing: an **absolute** path is statted **on the Ansible controller**
  (where `copy` resolves `src`; checking the target would answer a different
  question) and must be readable, while a **relative** path — the
  `files/vault-tls.crt` shape this project's own examples use — is reported as
  unverifiable and left to `copy`'s search path, never rejected. Reimplementing
  that search order inside a gate is how a gate becomes a subsystem. Also
  documents that `vault_pki` cannot
  bootstrap a first node, since issuing from Vault's PKI engine requires a Vault
  already serving on the certificate being requested. (#80)

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

- **CI pins `ansible-core` and the Python version together.** `ansible-core` was
  installed unpinned at five sites; the #36 close-out had already identified that
  as the cause of local/CI divergence, where a "verified" claim was measured on
  one version while CI resolved another. Both values now come from one
  workflow-level `env:` block so the five sites cannot drift apart. **They are
  coupled:** `ansible-core` 2.20+ requires Python >= 3.12, so raising the core
  version without raising `PYTHON_VERSION` fails at install time with "No
  matching distribution found" — which is how the first attempt at this pin
  broke, having been set to the version a developer ran locally without checking
  what CI installs. That constraint is now written into the workflow. `2.19.13`
  is the newest core available for Python 3.11 and is what CI already resolved
  unpinned; pinning does not by itself make local and CI agree, but it makes CI's
  version known and changeable only by a reviewed commit. (#78)
- **The DNS preflight check is now a conditional gate, not warn-only.** It probed
  `getent hosts` and warned only on a non-zero rc, measuring *"did resolution
  return an answer"* rather than *"is the answer reachable"* — while
  `vault_api_addr` and `vault_cluster_addr` are both derived from that same name.
  A Debian-style `127.0.1.1` line satisfied it completely; the host converged and
  Vault then advertised an address no client or Raft peer could reach, surfacing
  at cluster-join time far from its cause. It now resolves with `getent ahosts`
  across every address family — `getent hosts` returns the first match only and
  prefers IPv6, so a loopback AAAA masked a routable A — and requires at least
  one address that is neither loopback nor link-local, the latter being what a
  failed DHCP lease leaves behind. This is a **local** resolution check: it does
  not prove a peer can resolve the name, because `nss-myhostname` answers with
  the machine's own configured addresses, so a host with a working NIC and no DNS
  record passes. The gate is armed **only when the role still needs the name to
  resolve** — when `vault_api_addr`/`vault_cluster_addr` still contain
  `ansible_fqdn`, **or** when the role is managing TLS with
  `vault_tls_source: vault_pki`, because `tasks/tls.yml` issues that certificate
  with `common_name: "{{ ansible_fqdn }}"` whatever the advertised addresses say.
  Pin both addresses explicitly and, absent PKI issuance, the role has no such
  dependency, so the check downgrades to a warning rather than failing a
  deployment it does not affect. Classification of "reachable" is delegated to
  `ansible.utils.ipaddr` rather than pattern-matched. (#79)

- **`netaddr` added to `requirements.txt`** for `ansible.utils.ipaddr`, which the
  DNS preflight gate now uses for address classification. Adding a dependency is
  the one edit Dependabot does not make, so the lock was regenerated by hand —
  in a `linux/amd64` Python 3.11 container matching CI, because
  `--generate-hashes` enumerates the wheels the resolver can see and that set is
  platform-dependent, and against the existing `requirements.txt` rather than a
  fresh path, so no pin moved behind Dependabot's back. No version changed; the
  regeneration also removed 172 duplicated `charset-normalizer` hash lines that
  were already in the lock. Version *updates* remain Dependabot's, under the
  cooldown rules in `.github/dependabot.yml`.

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

- **A host whose FQDN does not resolve, or resolves only to loopback or
  link-local, now fails preflight** when the role still needs that name. All
  three populations converged before this release and produced a Vault
  advertising an address nothing could reach; the previous check warned and
  continued. The gate is armed when `vault_api_addr`/`vault_cluster_addr` are
  left at their defaults (they are templated from `ansible_fqdn`), **or** when
  the role is managing TLS (`vault_manage_tls: true`) with
  `vault_tls_source: vault_pki`, because `tasks/tls.yml` issues that
  certificate with `common_name: "{{ ansible_fqdn }}"` whatever the advertised
  addresses say. Fix the DNS record or the `/etc/hosts` entry; pinning both
  addresses downgrades the check to a warning only when PKI issuance is not also
  in play. Note the gate now also hard-fails when `getent` is absent, which is a
  broken host rather than a DNS problem — the same posture the port gate takes
  for a missing `ss`. (#79)


- **`--tags preflight` now runs the gates.** It previously matched nothing and
  reported success having done nothing. A tag-scoped job that was green may now
  go red — which is the point. (#36)

  **Historical note, superseded within this same release.** When #36 shipped,
  every *other* tag was still broken: `--tags vault|install|stig|fapolicyd` ran
  the fapolicyd phase alone and the remaining tags did nothing. **#28 repaired
  all of them** — see the Fixed entry below for the behaviour this release
  actually ships. Read the two together; #36 describes an intermediate state
  that no longer exists.
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

- **Tag-scoped runs executed almost nothing and reported success.**
  `include_tasks` does not propagate its own tags to the tasks in the included
  file — only `import_tasks` does — and nine of the ten includes in
  `tasks/main.yml` carried `tags:` with no `apply:` block. A tag therefore
  selected the **include**, which ran and made the output look right, and then
  executed **none of its tasks**. Measured on a live host before the fix:
  `--tags configure` ran exactly three tasks — `Gathering Facts`, argument-spec
  validation, and `Include Vault configuration tasks` — and reported
  `ok=3 changed=0 failed=0`. A green run that configured nothing. `--tags stig`
  included `stig.yml` and then ran only the fapolicyd phase, which was the sole
  include already carrying `apply:`; an operator hardening a DoD host that way
  got a successful play and zero hardening. Every include now applies its own
  tags. After the fix, on the same host: `--tags configure` `ok=5`,
  `--tags stig` `ok=16`, `--tags install` `ok=18`, `--tags preflight` `ok=47`,
  `--tags vault` `ok=88`, all `changed=0 failed=0`, and `--tags tls` correctly
  runs nothing while `vault_manage_tls` is false because the `when:` gates the
  include itself. (#28)

  Mirroring is what the older warning in `tasks/preflight.yml` cautioned
  against — it said mirroring both tags would make `--tags vault` "a run that
  looks like it worked." That was true only of the **partial** state: the trap
  was the other nine includes being broken, not the mirroring. `preflight.yml`
  needs no second-level change, which was **measured** with a throwaway
  two-level role rather than reasoned about: an outer `apply:` propagates
  *through* a nested include into its tasks, so `main.yml`'s
  `apply: [vault, preflight]` reaches the gates even though `preflight.yml`'s
  own `apply:` names only `[preflight]`. Confirmed live — `--tags vault` runs
  15 gate tasks. Tags accumulate down the chain.

- **The FIPS preflight probe crashed instead of asserting when the sysctl was
  absent or unreadable.** `tasks/preflight/fips.yml` read
  `/proc/sys/crypto/fips_enabled` with a bare `slurp` and no `failed_when`, so a
  kernel built without `CONFIG_CRYPTO_FIPS` — or a container with a masked
  `/proc` — killed the play at the **probe** with
  `File not found: /proc/sys/crypto/fips_enabled`. The assert below it, and its
  remediation text, were unreachable on exactly the hosts that needed them: the
  operator got a module error instead of an instruction. Same defect class #36
  repaired for chrony, whose branch structure this copies.
  **The causes are now reported separately, because they are different findings
  for SC-13:** FIPS off (enable and reboot), sysctl absent (*unobservable*, which
  is explicitly **not** the same as disabled), sysctl unreadable (a privilege
  problem — use `become: true`), a readable path that returned nothing, and a
  value that is neither `1` nor `0` (reported unverified, never assumed off).
  Discrimination is on `content is defined`, never on `.failed` — `failed_when:
  false` *defines* `.failed` as `False`, measured again here, and keying on it
  would be a tautology. Not keyed on size either: procfs reports `st_size` 0 for
  this file even when it reads as `1`. (#66)

- **Facts are now read through `ansible_facts[...]`, so the role survives the
  removal of `INJECT_FACTS_AS_VARS`.** That setting is what makes `ansible_fqdn`
  exist alongside `ansible_facts['fqdn']`; its default-`True` behaviour is
  deprecated and slated for removal. Measured with injection disabled, the role
  did not merely fail a gate — it died on its **first task**, because
  `meta/argument_specs.yml` embedded `{{ ansible_fqdn }}` in a default and
  argument-spec validation could not resolve it. Blast radius was total, and CI
  installed `ansible-core` unpinned, so the break would have landed on a
  scheduled run with no commit to blame. Converted across `defaults/`, `vars/`,
  `meta/`, `tasks/` and the molecule scenarios; `main` emitted 16 deprecation
  warnings on a preflight run and now emits none. Verified on live hardware with
  `ANSIBLE_INJECT_FACT_VARS=False`: full converge `ok=87 changed=0 failed=0`,
  byte-identical to the run with injection on. (#78)

- **The molecule fixtures and the container-free preflight harness overrode facts
  in a way that silently stopped working.** They set `ansible_fqdn:`/`ansible_distribution:` as task vars
  (precedence 21 beats host facts 15) to drive per-case behaviour. Once the gates
  read `ansible_facts[...]`, those overrides no longer reach them and each case
  would have exercised the container's real values while still claiming to test a
  fixture. Three candidate replacements were measured rather than assumed:
  overriding `ansible_facts` in `vars:` self-references and dies with "Recursive
  loop detected"; replacing the whole dict loses every other fact
  (`os_family` came back empty); and `set_fact` is host-global, so cases leak into
  each other. The working form snapshots the real facts once into a plain var and
  rebuilds per include — `ansible_facts: "{{ __real_facts | combine({...}) }}"` —
  which is scoped, leak-free and preserves untouched facts. Proven with a
  three-case probe where the third case, which overrides nothing, still sees the
  real value. `tests/local-preflight-harness/run.yml` drives eighteen DNS cases
  the same way and needed the same treatment; CI caught it because the guard's
  first version did not scan `tests/`, which it now does. (#78)

- **The common parent `/opt/vault` was never asserted on, so a STIG-hardened host
  could not start Vault.** The role created and enforced `vault_data_dir`,
  `vault_tls_dir`, `vault_log_dir`, `vault_config_dir` and `vault_backup_dir` — but
  nothing owned the directory that *holds* the first two. STIG mandates `umask 077`,
  and on the default path (`vault_manage_tls: false`) `tasks/preflight/tls.yml`
  instructs the operator to stage TLS material at `vault_tls_dir`; their
  `mkdir -p /opt/vault/tls` therefore creates `/opt/vault` as `0700 root:root`. Both
  children then converged correctly and the service account still could not
  **traverse** to reach them, dying on `stat /opt/vault/data/vault.db: permission
  denied`. All twelve preflight gates passed and 78 tasks converged first, so the
  host was fully mutated — package installed, config written, STIG hardening
  applied, firewall opened — before it failed. Now managed as `vault_root_dir`
  (`root:vault`, `vault_root_dir_mode` `0750`), ordered **before** its children so
  the parent is posture-correct before anything is created inside it. Fresh installs
  were never affected: `ansible.builtin.file` propagates owner *and* mode to
  implicitly created parents, so this required `/opt/vault` to pre-exist
  restrictively — which following the role's own staging instruction on a STIG host
  reliably produces. Found on live hardware (Rocky 9.8, FIPS, SELinux enforcing);
  containers never reproduced it because nothing pre-created the path. Locked by
  `tests/assert-vault-root-dir-managed.sh`, which derives the parent/child
  relationship from the real variables rather than a literal, so repointing a child
  fails the guard instead of passing vacuously.

- **`restorecon` ran without `-F`, so the declared `seuser` was never enforced —
  and the task reported success.** `vars/main.yml` states the intent outright
  ("RPM sets `/opt/vault/*` to `unconfined_u:object_r:usr_t` — we enforce
  `system_u`"). It did not. `restorecon` without `-F` repairs only the **type**,
  never the SELinux **user**; the type already matched, so it found nothing to do,
  printed nothing and exited 0 — and `changed_when: stdout | length > 0` read that
  as a clean no-op. Measured on a live host: `/opt/vault` and everything beneath it
  sat at `unconfined_u` through a full converge, while `/etc/vault.d` masked the gap
  because *its* type differed (`etc_t`), forcing a relabel that carried the user
  along. The command now passes `-RFv`. This is the "derive from the authority, not
  the projection" class: the task measured type convergence while claiming seuser
  convergence, and its success oracle could not fail. Locked by
  `tests/assert-restorecon-forces-seuser.sh`; both new guards are mutation-proven by
  `tests/assert-parent-dir-and-seuser-mutations.sh` (13 kills, 5 accepted refactors).
- **Operator-staged TLS material was never made readable by the Vault service.**
  `vault_manage_tls: false` is the role default and a documented path — preflight
  instructs the operator to stage the certificate, key and CA — but the only code
  setting ownership on them lived in `tasks/tls.yml`, which `tasks/main.yml` gates
  on `vault_manage_tls`. On the default path that file never ran, so a host
  converged cleanly and then failed at service start because `vault` could not
  read its own private key. `tasks/system.yml` now converges the trio to
  `root:vault 0640`, the same posture it already applied unconditionally to
  `/opt/vault/tls` itself. Bounded deliberately: only direct children of
  `vault_tls_dir` are touched, and symlinks, hardlinks and non-regular files are
  left alone — an operator may legitimately point `vault_tls_ca_file` at a shared
  system anchor, certmonger/certbot material is normally a link to material
  outside the directory, a hardlink shares its inode with such material, and a
  directory left where a certificate was expected would otherwise abort the run
  after the package phase. Every excluded case is reported with its cause,
  including a path that cannot be inspected at all, rather than silently skipped;
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

- **The README's controller-Python claim now matches what CI tests.** It advertised
  `>= 3.10` — a correct derivation from the ansible-core 2.17 floor, but one
  nothing verified, since CI installs 3.11 only. Pinning the Python version (#78)
  turned that from incidental into explicit and made the untested claim visible.
  The entry now states 3.11, notes that core 2.20+ requires Python 3.12+ so the
  controller's Python and core version move together, and separates the managed
  host's Python (EL platform Python, 3.9 on RHEL/Rocky 9) which is a different
  axis entirely. Same "reconcile the README with what is actually enforced" class
  as #36, on a new axis. (#78)

- **Documented that pipelining is a hard requirement on fapolicyd-enforcing
  hosts.** This role targets STIG-hardened RHEL-family systems, where fapolicyd
  enforcing is itself a STIG requirement (RHEL-09-433010/433015) and where the
  role's own trust phase supports RHEL-09-433016 — yet on exactly those hosts
  Ansible could not reach the target at all. The shipped fapolicyd policy denies
  opening untrusted files typed `%languages`; Ansible's `AnsiballZ_<module>.py`
  carries a `#!/usr/bin/python3` shebang, is generated at runtime and so is
  absent from the rpmdb-backed trust database, and the open is denied with
  `[Errno 1] Operation not permitted` — during `gather_facts`, before the role's
  first task, and potentially with **no audit record at all** (`ausearch -m AVC`
  and `-m FANOTIFY` both empty). It presents as a file-permission bug and is not
  one. README now documents the symptom verbatim so it is searchable, both
  control-node levers (`ansible_pipelining: true` in inventory, or
  `[ssh_connection] pipelining = True`), and why trusting `~/.ansible/tmp`
  instead is the wrong repair — that disables the very control the fapolicyd
  phase exists to support. Also records why **no preflight gate can cover this**:
  detecting the condition requires running a module, and the condition is that no
  module can run; the failure additionally precedes role entry, so no gate could
  fire in any ordering. No `ansible.cfg` is shipped with the role — a role
  directory is never on Ansible's config search path (`ANSIBLE_CONFIG` →
  `./ansible.cfg` → `~/.ansible.cfg` → `/etc/ansible/ansible.cfg`), so one would
  be inert once installed from Galaxy and would merely look like coverage. Found
  on live hardware; containers cannot reproduce it because they do not run
  fapolicyd. Documentation only — no behaviour change.
- Added a **Known Limitations** section covering developmental multi-node HA
  (#44), the silent no-op on tag-scoped runs (#28 — since repaired, and that
  limitation entry replaced by a per-tag reference table), the preflight gaps
  (#36 — since repaired and removed), and the tracked functional gaps
  (#35, #39, #40, #42, #45).
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
