# Ansible Role: HashiCorp Vault

Install and configure HashiCorp Vault on RHEL systems with DISA STIG compliance,
in airgap or internet-connected environments.

> **Maturity.** Single-node deployments are the supported, CI-exercised path.
> **Multi-node Raft HA is developmental** — the role renders cluster
> configuration but does not yet implement a complete cluster standup. Read
> [Known Limitations](#known-limitations) before planning a cluster.

## Requirements

### Platform

- RHEL 8, 9, or 10, **or a compatible EL distribution** — Rocky, AlmaLinux,
  CentOS Stream and Oracle Linux all pass. The RHSM gate that previously
  rejected them now fires only when Vault is sourced from Red Hat Satellite,
  which is a licensed Red Hat product that does not manage EL rebuilds.
- **Supported platform is not the same claim as supported host baseline.**
  Preflight requires FIPS mode and SELinux enforcing on *every* platform,
  including Red Hat proper. Those are prerequisites the role **verifies and
  never provides** — a stock Rocky or RHEL host that is not already hardened
  is rejected at Phase 1. There is no opt-out today; one is tracked in
  [#64](https://github.com/mpe-es/ansible-role-vault/issues/64).

### Target Host Prerequisites

`tasks/preflight.yml` **hard-fails the play** when any gate below is unmet.
These are gates, not things the role configures for you — provision them in
your image or an earlier play. The **Fires when** column matters: six of the
gates are conditional — firewalld, RHSM, repo source, TLS material, managed TLS
inputs and DNS — so the set that applies depends on how you configure the role.
The two TLS gates are exact mirrors: whichever way `vault_manage_tls` is set,
one of them applies and the other does not.

| Gate | Fires when | Requirement |
|------|-----------|-------------|
| OS family / version | always | RedHat-family, EL 8/9/10 |
| FIPS | always | `/proc/sys/crypto/fips_enabled` is `1`. This is the kernel flag only — it does not establish a validated module version, nor that a FIPS Vault edition was selected via `vault_edition`. **"FIPS is off" and "FIPS state could not be observed" are reported separately**, because they are different findings for SC-13: an absent sysctl (a kernel without `CONFIG_CRYPTO_FIPS`, or a container with a masked `/proc`) is *unobservable*, not disabled, and an unreadable one is a privilege problem telling you to use `become: true`. A value that is neither `1` nor `0` is reported as unverified rather than assumed off (#66) |
| SELinux | always | `enabled` **and** `enforcing` |
| Time sync | always | `chronyc tracking` reports `Leap status : Normal`. A missing `chronyc` or a stopped `chronyd` now fails the **assert** with remediation text, not the task |
| firewalld | `vault_manage_firewall` | service `ActiveState == active`. Honours the toggle — disable firewall management and this gate does not apply |
| RHSM | RHEL **and** `vault_manage_repo` **and** `vault_repo_source: satellite` | host registered. Only meaningful for Satellite-sourced content; the role-managed repository — HashiCorp's or your mirror's — needs no Red Hat subscription |
| Repo source | `vault_manage_repo` | `mirror` mode must not name `rpm.releases.hashicorp.com` — checked for **both** `vault_repo_url` and `vault_repo_gpg_key`, since the target host fetches the key directly. This proves inequality with the shipped host, **not** that the endpoint is internal or airgap-safe. `satellite` mode requires RHEL |
| TLS material | `vault_manage_tls: false` **(the default)** | `vault_tls_cert_file`, `vault_tls_key_file` and `vault_tls_ca_file` all exist and are regular files (symlinks followed). Whether the Vault account can READ them is tracked separately |
| Managed TLS inputs | `vault_manage_tls: true` | under `vault_tls_source: file`, `vault_tls_src_cert`/`_key`/`_ca` are **set**. An *absolute* path is additionally statted **on the Ansible controller** and must be readable — `copy` resolves `src` there, so checking the target would answer a different question. A *relative* path (`files/vault-tls.crt`, as the examples below use) is reported as unverifiable and left to `copy`'s own search path, never rejected. Under `vault_tls_source: vault_pki`, `vault_pki_mount` and `vault_pki_role` are set; reachability of the PKI engine is not proven (#80) |
| Certificate SANs | `vault_manage_tls: false` **(the default)**, or `vault_manage_tls: true` with `vault_tls_source: file` and an **absolute** `vault_tls_src_cert` | the certificate carries a **`127.0.0.1` IP SAN** and the host identity from `vault_api_addr`, encoded to match its type (DNS SAN for a name, IP SAN for an address). Verification is **delegated to `openssl x509 -checkhost` / `-checkip`**, so wildcard and label-boundary semantics are RFC 6125's rather than a reimplementation — `DNS:*.example.com` satisfies `vault.example.com` but not `a.b.example.com`. A certificate matching only through its **Common Name is rejected**: openssl still falls back to CN when no `dNSName` SAN is present, but Vault's client is Go, which has ignored CN since 1.15, so such a certificate would fail at service start. `vault_api_addr` is parsed with `urlsplit`, so a bracketed IPv6 form (`https://[2001:db8::10]:8200`) works. Inspected on the **controller** for the managed path and the **target** for the staged path, since that is where each certificate lives. **A missing `openssl` fails the gate** — the same posture the port gate takes for a missing `ss` and the DNS gate for a missing `getent`: a host without the tool is broken, not merely unverified, and skipping would let the gate stop gating without saying so. An openssl that is *present but lacks* `-checkhost`/`-checkip` (LibreSSL, which is what a stock macOS controller resolves) instead **reports the contract as unverified and skips**, since the tool works for everything else and failing would block a legitimate setup. A *relative* `vault_tls_src_cert` and `vault_tls_source: vault_pki` are **reported as uninspectable, never rejected**. This checks only what the role itself depends on: expiry, key size, chain trust and EKU are out of scope, so a pass here is not a statement that the certificate is otherwise good (#85) |
| API port | always | `vault_listener_port` is free, or already held by the Vault service itself. Requires `iproute` (`ss`) — a missing query tool is a hard failure, not a skip |
| DNS | `vault_api_addr` or `vault_cluster_addr` still contain `ansible_facts['fqdn']` (the default), **or** `vault_manage_tls: true` **with** `vault_tls_source: vault_pki` (which issues against `ansible_facts['fqdn']`) | the FQDN resolves **locally** to at least one address that is not loopback (`127.0.0.0/8`, `::1`) or link-local (`169.254.0.0/16`, `fe80::/10`). Checked with `getent ahosts` rather than `getent hosts`, which returns the first match only and prefers IPv6, so a loopback AAAA masks a routable A. Classification is delegated to `ansible.utils.ipaddr` rather than pattern-matched, so loopback, link-local (the full `fe80::/10`), multicast, unspecified and broadcast are excluded — while RFC1918, CGNAT and reserved ranges stay valid, since "not globally routable" is not the same claim as "no peer can reach it". Note `ahosts` applies `AI_ADDRCONFIG`, so it reports the families the host itself has configured — a host with no IPv6 address will not be told about AAAA records. Pin `vault_api_addr`/`vault_cluster_addr` explicitly and this becomes a warning instead (#79) |

Every gate above is a hard failure. The DNS gate is the one that changes shape:
pin `vault_api_addr` and `vault_cluster_addr` to explicit reachable addresses and
it downgrades to a warning — **unless** the role is also managing TLS
(`vault_manage_tls: true`) with `vault_tls_source: vault_pki`, which issues a
certificate whose common name is `ansible_facts['fqdn']` regardless of what the
advertised addresses say. Note that the
availability of `getent` itself is checked unconditionally and is a hard failure
for everyone, the same posture the port gate takes for a missing `ss`: a host
without it is broken, not misconfigured.

**What the DNS gate does not prove.** It resolves the name the way the *target
host* does, so it catches a name mapped to loopback or link-local, or one that
does not resolve at all. It does **not** prove that a client or a Raft peer can
resolve the name: `nss-myhostname` answers the local hostname with the machine's
own configured addresses, so a host with a working NIC and no DNS record at all
passes this gate. Verifying the record exists in the zone your clients query is
a different check from a different vantage point, and the role does not attempt
it.

The port gate covers the API port only. A conflict on the cluster port (8201)
still surfaces at service start; see [#39](https://github.com/mpe-es/ansible-role-vault/issues/39).

#### Certificate SAN contract

The **final listener certificate** must carry these, regardless of who puts it
there — the requirement is about what the role's own callers connect to, not
about who deployed the file. It therefore applies equally when
`vault_manage_tls: true`, since that path copies the certificate you supply
without altering its SANs:

- a **`127.0.0.1` IP SAN**, and
- the host identity in `vault_api_addr`, encoded to match its TYPE: a **DNS
  SAN** for a hostname (the host FQDN by default), or an **IP SAN** if you set
  `vault_api_addr` to an address. `argument_specs` permits either, and
  `DNS:10.0.0.5` will not validate `https://10.0.0.5`.

The role's own callers use the loopback address — `tasks/service.yml` verifies
against `https://127.0.0.1:<port>`, and `files/vault-unseal.sh` and the unseal
unit both set `VAULT_ADDR` to it. A certificate without the IP SAN fails
hostname verification and breaks init and unseal.

**No `localhost` DNS SAN is required.** Nothing in the role contacts
`https://localhost:<port>`; requiring one is not free, since enclave ADCS/RHCS
policy routinely refuses to issue it.

```bash
openssl req -new -newkey rsa:3072 -nodes \
  -keyout vault.key -out vault.csr \
  -subj "/CN=$(hostname -f)" \
  -addext "subjectAltName=DNS:$(hostname -f),IP:127.0.0.1"
```

**This contract is enforced at preflight** as of [#85](https://github.com/mpe-es/ansible-role-vault/issues/85) — a certificate missing
the `127.0.0.1` IP SAN now fails Phase 1 with an actionable message, rather than
converging the host in full and then failing at service start.

Measured on a live host: a certificate carrying `DNS:<fqdn>` and the node's own
IP but no loopback SAN produces

```
x509: certificate is valid for 10.110.11.55, not 127.0.0.1
```

from the loopback callers, while the **same** certificate works via the FQDN. The
certificate is not invalid — it is unusable by this role.

> **If your issuing CA refuses IP SANs**, that conflict must be resolved before
> this role can initialise Vault. Enterprise ADCS/RHCS policy sometimes declines
> them. The gate surfaces the problem at Phase 1 instead of at service start, but
> it cannot remove the dependency: `templates/vault-unseal.service.j2` sets
> `VAULT_ADDR` to the loopback address because the unit runs before DNS is
> dependable.

This contract covers `vault_tls_source: file` (the default). The
`vault_pki` source cannot satisfy it until [#63](https://github.com/mpe-es/ansible-role-vault/issues/63) lands, and multi-node
HA adds the cluster-leader name — see [#44](https://github.com/mpe-es/ansible-role-vault/issues/44).

#### Migrating from `vault_manage_repo: false`

Earlier documentation told Satellite users to set `vault_manage_repo: false`.
That still works — the role writes no repo file — but it also means
**preflight verifies nothing**: not registration, and not that the host is a
RHEL system Satellite can actually serve.
Satellite users should instead leave `vault_manage_repo` at its default and set
`vault_repo_source: satellite`, which writes no repo file *and* runs those
checks.

#### Satellite-sourced content

With `vault_repo_source: satellite` the role writes **no** repo file:
`subscription-manager` owns the client repo configuration and generates it from
the host's content-view bindings. Three things are therefore your
responsibility on the Satellite side:

- the host is **registered**;
- the Vault product is in the host's **content view** (otherwise no Vault
  package resolves — the generated repo file may still carry every OS
  repository);
- the **GPG key is associated with the custom product** — the role does not
  import it in this mode.

> **This release verifies only the first of those three.** Preflight checks the
> host is registered, and that `satellite` was selected on RHEL. It does **not** query
> whether your content view publishes Vault, and the install transaction is
> **not** scoped to Satellite content — `dnf` resolves across every enabled
> repository, so a stray HashiCorp, EPEL or internal mirror can satisfy the
> install while your content view publishes no Vault package. That is the
> curated-content bypass, and closing it is tracked in
> [#68](https://github.com/mpe-es/ansible-role-vault/issues/68).

**Migrating an existing host to `satellite`.** If the role previously ran with
`hashicorp` or `mirror`, `/etc/yum.repos.d/hashicorp.repo` is still present.
The role removes it automatically in Phase 2 when the source is `satellite`;
no manual step is required.

### Ansible

- ansible-core >= **2.17.0** (required by `community.hashi_vault` collection)
- Python >= **3.11** on the CONTROLLER — the version CI installs and tests.
  ansible-core 2.17 itself permits 3.10, but nothing verifies that floor, so
  3.11 is what this role claims. Note that ansible-core **2.20+ requires Python
  3.12+**; the role works on either, but the controller's Python and core
  version move together. The MANAGED HOST's Python is a separate matter — the
  role runs against EL8/9/10 platform Python (3.9 on RHEL/Rocky 9).
- **`min_ansible_version` in `meta/main.yml` is advisory.** ansible-core does not
  enforce it — verified with a probe role declaring `99.0`, which executed
  normally — so the floor above is a statement of intent, not a gate. A run below
  it produces no error, no warning and no failed job.
- **Under AAP the controller is the execution environment**, so these are
  properties of the EE rather than of any host. `mpe-ee-rhel9` provides
  ansible-core 2.21.4 on Python 3.12.13; the stock supported EE provides 2.16.19,
  which is *below* the floor above. See the AAP section.
- **Pipelining must be enabled** on any target where fapolicyd is enforcing —
  see immediately below. This is a hard requirement on this role's primary
  target platform, not a performance tuning knob.

#### Connection: pipelining is required on fapolicyd-enforcing hosts

This role targets STIG-hardened RHEL-family hosts, where fapolicyd is itself a
STIG requirement (RHEL-09-433010 / 433015; the role's own
[fapolicyd Trust](#fapolicyd-trust) phase supports RHEL-09-433016). **On such a
host, Ansible cannot run this role — or any role — without pipelining.**

The failure arrives during fact-gathering, before the role's first task:

```
/usr/bin/python3: can't open file
'/home/<user>/.ansible/tmp/ansible-tmp-.../AnsiballZ_setup.py':
[Errno 1] Operation not permitted
```

It reads like a file-permission bug and is not one. fapolicyd's shipped policy
denies opening untrusted files whose libmagic type falls in `%languages`:

```
%languages=...,text/x-script.python,text/x-python,...
allow      perm=open all : ftype=%languages trust=1
deny_audit perm=any  all : ftype=%languages
```

Ansible writes `AnsiballZ_<module>.py` with a `#!/usr/bin/python3` shebang, so
libmagic types it `text/x-script.python`. It is generated at runtime and is
therefore **not in fapolicyd's trust database** (which is populated from the RPM
database), the `trust=1` allow does not match, and the next rule denies it with
`EPERM`. Note that the denial may leave **no audit record at all** — `ausearch -m
AVC` and `ausearch -m FANOTIFY` can both come back empty — so there is nothing to
correlate the error against.

Enable pipelining by whichever route suits your setup. Both are **control-node**
settings; a role cannot set them for you (see below):

```yaml
# Inventory — per host or group, travels with the inventory that already
# describes these hosts. group_vars/vault_servers.yml:
ansible_pipelining: true
```

```ini
# Or a project-level ansible.cfg, in the directory you run from:
[ssh_connection]
pipelining = True
```

`ANSIBLE_PIPELINING=True` works for a one-off invocation. Pipelining streams
module source into the remote interpreter's stdin, so the untrusted file is never
written and there is nothing for fapolicyd to deny. It requires `requiretty` to
be disabled in sudoers, which is the default on EL8/9/10.

> **Do not** add `~/.ansible/tmp` to the fapolicyd trust database instead. That
> trades a STIG control for convenience, and grants blanket open/execute on a
> path the connecting user can write at will. If a fix requires disabling an
> existing control, re-examine the finding rather than the control.

**Why no preflight gate covers this.** Detecting the condition requires running a
module, and the condition *is* that no module can run. The failure also precedes
the role entirely — it happens during `gather_facts`, before any role task
exists — so there is no ordering in which a gate could fire. The one saving
grace is that it fails immediately and loudly, with nothing on the target
mutated.

### Collections

Install via `ansible-galaxy collection install -r requirements.yml`:

| Collection | Min Version | Purpose |
|------------|-------------|---------|
| `ansible.posix` | 1.6.0 | `firewalld` module for port management |
| `ansible.utils` | 6.0.0 | `ipaddr` filters — address classification in the DNS and SAN preflight gates |
| `community.general` | 9.0.0 | `sefcontext` module — SELinux file contexts (`tasks/system.yml`), on by default via `vault_manage_selinux` |
| `community.hashi_vault` | 7.0.0 | `vault_pki_generate_certificate` — used **only** when `vault_tls_source: vault_pki` |

### Python Libraries

Install via `pip install --require-hashes -r requirements.txt`:

| Library | Version | Purpose |
|---------|---------|---------|
| `hvac` | 2.4.0 | HashiCorp Vault API client (required by `community.hashi_vault`) |
| `netaddr` | 1.3.0 | Address classification for `ansible.utils.ipaddr` (required by that collection). **Controller-side only** — the filter runs on the controller, so the managed host needs nothing |

Python dependencies are hash-pinned with `pip-compile --generate-hashes` for
supply chain integrity (NIST 800-53 SI-7). **Version updates are Dependabot's
job** — `.github/dependabot.yml` sets a 7-day release cooldown and maintains
`requirements.txt` directly; do not hand-bump a pin.

`requirements.in` is edited only to **add or remove** a dependency, which
Dependabot does not do. The regeneration command and the two constraints that
make it safe (run it on `linux/amd64` Python 3.11 to match CI; run it against
the existing `requirements.txt`, never a fresh path) are documented in
`requirements.in` itself.

### Ansible Automation Platform (AAP)

The default supported Execution Environment does **not** carry everything this
role declares. `mpe-es/mpe-ee-rhel9` exists to close that gap; the rest of this
section is the compliance checklist for anyone not using it.

Everything below was **measured**, not derived from documentation, against
`registry.redhat.io/ansible-automation-platform-2{6,7}/ee-supported-rhel9` and a
built MPE image on 2026-09-22. Re-measure when your EE changes; the commands are
given so you can.

#### The MPE execution environment

**`mpe-ee-rhel9` satisfies every collection requirement in this role.** Measured
on a built AAP 2.6 image:

| Requirement | Role declares | MPE EE provides |
|---|---|---|
| `ansible-core` | >= 2.17.0 | **2.21.4** |
| Python (controller) | >= 3.11 | **3.12.13** |
| `ansible.posix` | >= 1.6.0 | 2.1.0 |
| `ansible.utils` | >= 6.0.0 | 6.0.3 |
| `community.general` | >= 9.0.0 | **13.2.0** |
| `community.hashi_vault` | >= 7.0.0 | **7.1.0** |
| `openssl` (SAN gate) | any with `-checkhost`/`-checkip` | 3.5.5 |
| `netaddr` (for `ansible.utils.ipaddr`) | >= 0.10.1 | 1.3.0 |

Two things that follow from it, neither of which the table conveys:

**It does not fix the initialization problem.** The warning above is about
*where the controller writes*, not *what the controller contains*. The MPE EE is
still an ephemeral job container, so `vault_initialize: true` still loses the
root token and every unseal share without an explicit mount.

**The role is not tested on what the EE runs.** CI verifies Python 3.11 /
ansible-core **2.19.13**; the MPE EE runs 3.12.13 / **2.21.4**. Every "verified"
claim in this repository — the preflight gates, the SAN contract, the full
molecule matrix — is measured on a pair the execution path does not use. Closing
that is tracked in [#87](https://github.com/mpe-es/ansible-role-vault/issues/87)
(matrix) and [#91](https://github.com/mpe-es/ansible-role-vault/issues/91)
(floor). Treat a green AAP job and a green CI run as evidence about different
runtimes until then.

#### STOP — read this before running with `vault_initialize: true` on AAP

**The role captures the root token and every unseal share to the Ansible
controller. Under AAP the controller is the ephemeral EE job container, so on a
default configuration that material is destroyed when the job pod exits — and
the job still reports success.**

`tasks/service.yml` writes all initialization secrets with
`delegate_to: localhost`:

| Line | Task | Destination |
|---|---|---|
| 141 | Create controller capture directory | `{{ vault_init_capture_dir }}/{{ inventory_hostname }}/` |
| 150 | Capture **root token** | `…/root-token` |
| 160 | Capture **Shamir unseal shares** | `…/unseal-key-N` (one per share) |
| 173 | Capture **HSM recovery keys** | `…/recovery-key-N` (one per key) |

This is deliberate and correct on a persistent control node — the design
guarantees the root token never rests on the Vault node (see *Security Model*
below). On AAP it inverts: Vault is initialized and unsealed, the job goes
green, and **nobody holds the root token or a single unseal key.** Recovery is
not possible.

The preflight check at `tasks/service.yml:46` does not catch this. It asserts
`vault_init_capture_dir` is set and absolute; a path inside the EE satisfies
both.

> **Choosing an execution node does not fix this.** Mesh execution nodes run
> jobs through `ansible-runner` under Podman isolation exactly as container
> groups do, so `delegate_to: localhost` still writes *inside* the job's
> execution environment. "A node with real storage" is not custody — the host's
> disk is not visible to the container unless a path is explicitly exposed.

**Required mitigation — one of. Options 1 and 2 keep initialization in AAP and
therefore depend on an explicit host-to-container mount; verify that mount
exists before the first initializing run, not after. Option 3 avoids the
mount entirely by moving initialization out of AAP.**

1. **Container group** — a custom pod spec declaring a volume mounted at
   `vault_init_capture_dir`.
2. **Execution node** — expose the host directory through **Paths to expose to
   isolated jobs** (Settings → Automation Execution → Job, or
   `AWX_ISOLATION_SHOW_PATHS` at `/api/v2/settings/jobs`):

   ```
   AWX_ISOLATION_SHOW_PATHS = ['/srv/vault-init-capture']
   ```

   Note that naming a *file* mounts its containing directory. Without this entry
   an execution node loses the material exactly as a container group does.
3. **Neither** — leave `vault_initialize: false` in AAP and perform
   initialization as a separate, deliberate operation with custody arranged in
   advance. This is the only option that does not depend on a mount being
   configured correctly, and is the safest default.

**Verify, do not assume.** After configuring a mount, run one initializing job
against a throwaway target and confirm the files exist on the host afterwards.
A missing mount produces a green job and no files — the same silent success this
whole section is about.

Non-initializing runs (`vault_initialize: false`, the default) are unaffected —
no secrets are captured and every item below still applies normally.

#### Already provided — no action required

| Requirement | Declared minimum | In the default EE | Used by |
|---|---|---|---|
| `ansible.posix` | 1.6.0 | **2.2.2** | `firewalld` (`tasks/firewall.yml`) |
| `ansible.utils` | 6.0.0 | **6.1.0** | `ipaddr` filter (DNS + SAN gates) |
| `netaddr` (controller Python) | 0.10.1 | **1.3.0** | backs `ansible.utils.ipaddr` |
| `openssl` CLI (controller) | any with `-checkhost`/`-checkip` | **3.5.5** | certificate SAN gate, managed TLS path |

`bindep.txt` is **not** consulted in this model. It feeds `ansible-builder` when
constructing a custom EE; on a default EE nothing reads it.

#### Must be added to AAP

**Not required when running `mpe-ee-rhel9`** — it carries items 1–3 already. This
is the checklist for the stock supported EE.

| # | Item | Why | Scope |
|---|---|---|---|
| 1 | **`community.general` >= 9.0.0** | `community.general.sefcontext` (`tasks/system.yml`) sets the SELinux file contexts for every Vault path. On by default (`vault_manage_selinux: true`). The default EE ships **46 collections and none in the `community` namespace**, so this resolves nowhere. | **Required.** Blocks Phase 4 on a default install. |
| 2 | **`community.hashi_vault` >= 7.0.0** | `vault_pki_generate_certificate` (`tasks/tls.yml`). | **Conditional** — only when `vault_tls_source: vault_pki`. Not needed for the default `file` / operator-staged paths. |
| 3 | **`hvac` >= 2.0.0 on the managed host** | Required by `community.hashi_vault`, which is **not** delegated and therefore executes on the target, not in the EE. A STIG-hardened EL host has no `pip` and no repo carrying it. | **Conditional**, same trigger as item 2. |
| 4 | **A `collections/requirements.yml` in the consuming AAP project** | Automation controller discovers collection dependencies for SCM projects **only** at `collections/requirements.yml`. This role ships a top-level `requirements.yml`, which the controller does **not** read — so project sync installs nothing from it and `community.general.sefcontext` is still unresolvable at Phase 4. See below. | **Required** if items 1–2 are delivered by project sync. |
| 5 | **A Galaxy credential at the Organization level** | With item 4 in place, the controller runs `ansible-galaxy collection install` during project sync and needs a `kind=galaxy` credential naming the content source — your private automation hub in a darksite. Without it the install resolves nothing. A credential **without** item 4 changes nothing at all. | **Required** alongside item 4. |
| 6 | **`policycoreutils-python-utils` on the managed host** | `sefcontext` needs the `seobject` Python bindings on the target. Satellite can supply it; this is a target prerequisite, not an EE one. | **Required** whenever `vault_manage_selinux: true`. |

##### Where the collection manifest has to live

This is the step most likely to be missed, because the role *looks* like it
already declares its dependencies.

Automation controller installs project collections from
**`collections/requirements.yml`** in the SCM project, during the implicit sync
before a job run. It does not read a top-level `requirements.yml`, and it does
not read this role's manifest. So the consuming AAP project needs its own
`collections/requirements.yml`, and something has to keep it aligned with
`requirements.yml` here — they are two files with one meaning, which is a drift
source. Prefer baking the collections into the execution environment and
treating the project manifest as the fallback.

The system-wide toggle is **Settings → Automation Execution → Job → Enable
Collection(s) Download**; with it unchecked, project collections are not
installed at all.

> **Project collections override the execution environment, in both directions.**
> Red Hat: *"if the collection specified in `requirements.yml` is older than the
> collection within the execution environment, the collection specified in
> `requirements.yml` is used."* A project manifest pinning an older
> `community.general` silently downgrades a newer one baked into the EE. If both
> are in play, they must be kept in lockstep or the project pin wins.

Items 1 and 2 are `community.*` collections. Red Hat's supported EE ships
**certified** content only, so neither will ever appear there regardless of AAP
version — they must be synced into your private automation hub (or the role must
stop depending on them). Building a custom EE is the third option and is
deliberately **not** recommended here: it adds a multi-gigabyte image to move
across the airgap to solve a two-collection problem.

#### Version alignment — read this before trusting a green job

The default EE and this role's CI do **not** run the same toolchain:

| | Default supported EE (2.7) | What CI verifies |
|---|---|---|
| Python | **3.12.14** | 3.11 |
| ansible-core | **2.16.19** | 2.19.13 |

`meta/main.yml` declares `min_ansible_version: '2.17'` and this README's Ansible
section states `>= 2.17.0`. The EE is **below** that floor. **`min_ansible_version`
is advisory galaxy metadata — ansible-core does not enforce it**, verified with a
probe role declaring `min_ansible_version: '99.0'` that executed normally. So the
shortfall produces no error, no warning, and no failed job. It is silent.

Treat a green AAP job as evidence about `3.12.14 / 2.16.19`, and a green CI run as
evidence about `3.11 / 2.19.13`. Neither is evidence about the other until the CI
matrix covers the pair AAP actually runs.

#### Verify your own EE

Substitute the image your Job Templates reference:

```bash
EE=registry.redhat.io/ansible-automation-platform-27/ee-supported-rhel9:latest

# runtime versions
podman run --rm "$EE" sh -c 'python3 --version; ansible --version | head -1'

# are the required collections present?
podman run --rm "$EE" ansible-galaxy collection list \
  | grep -E 'community.general|community.hashi_vault|ansible.posix|ansible.utils'

# controller-side libraries and the SAN gate's openssl
podman run --rm "$EE" sh -c \
  'python3 -c "import netaddr; print(netaddr.__version__)"; openssl version'
```

#### Job Template notes

The role provides `meta/argument_specs.yml` for Job Template survey
auto-generation and input validation.

See the initialization warning at the top of this section before enabling
`vault_initialize` in any Job Template.

### Other

- TLS certificates for the Vault listener (provided externally or via this
  role). **Preflight verifies that all three exist and are regular files** when
  `vault_manage_tls: false`, and **SAN correctness is now enforced** by the
  certificate SAN gate — see the SAN contract in the gate table above for what
  is and is not checked (#85).
- For airgap: an internal RPM mirror hosting the Vault package and GPG key
  (`vault_repo_source: mirror`), or a Red Hat Satellite content view
  (`vault_repo_source: satellite`, RHEL only — the role then writes no repo
  file at all).

## Role Variables

### RPM Repository

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_repo` | `true` | Master switch: whether the role touches repo configuration at all. When `false` it writes nothing **and fires none of the repo preflight gates** |
| `vault_repo_source` | `hashicorp` | How the Vault RPM reaches the host: `hashicorp` \| `mirror` \| `satellite`. Decides which repo gates apply. `satellite` writes **no** repo file and is RHEL-only |
| `vault_repo_url` | HashiCorp official | RPM repository base URL |
| `vault_repo_gpg_key` | HashiCorp official | GPG key URL for RPM verification |
| `vault_repo_gpgcheck` | `true` | Enable GPG signature checking |

### Package

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_package_version` | `2.1.1` | Version to install. **Pinned by default.** Enterprise editions get the `+ent` NEVRA suffix appended automatically, so one value works on any edition. `latest` means *newest at first install*, not kept current — see below |
| `vault_package_state` | `present` | DNF state: `present` or `latest` |
| `vault_edition` | `vault` | Package/edition — three choices: `vault` (Community), `vault-enterprise-fips1403` (Enterprise FIPS 140-3), `vault-enterprise-hsm-fips1403` (Enterprise + HSM). General Enterprise and both FIPS 140-2 builds are **excluded**: preflight requires FIPS mode and cites FIPS 140-3. `vault_hsm_enabled` requires the `-hsm` build |
| `vault_license_content` | `""` | Vault Enterprise license, the **plain text** contents of a `.hclic`. Supply from an AAP credential or Ansible Vault — never commit it. Rendered to `/etc/vault.d/vault.hclic` as `root:vault 0640`, `no_log`. Empty deploys nothing; an Enterprise edition without one fails at service start, deliberately ungated |

> **`latest` does not mean "kept current".** `vault_package_version: latest`
> omits the version from the dnf transaction, so dnf resolves whatever is newest
> **at that moment**; the default `vault_package_state: present` then installs
> only if Vault is absent and never upgrades it. A host built in March and one
> built today therefore run different versions and neither ever moves — estate
> drift nobody chose and nothing reports. `vault_package_state: latest` would
> converge, but makes every run a potential upgrade, which is unacceptable for
> HA Vault where upgrades are ordered and deliberate. Pin unless you want drift.
>
> **Enterprise NEVRA carries `+ent` in the version field** — `vault-enterprise`
> is `2.1.1+ent-1` where Community `vault` is `2.1.1-1`. The role appends it for
> you, so `2.1.1` resolves `vault-2.1.1` on Community and
> `vault-enterprise-fips1403-2.1.1+ent` on Enterprise. Writing `2.1.1+ent`
> yourself is accepted and not doubled, and a release field is preserved in
> place: `1.18.3-1` becomes `1.18.3+ent-1`, never `1.18.3-1+ent` (which dnf
> reads as release `1+ent` and matches nothing). The role reports the applied
> suffix in the job log.

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
| `vault_api_addr` | `https://{{ ansible_facts['fqdn'] }}:8200` | Advertised API address |
| `vault_cluster_addr` | `https://{{ ansible_facts['fqdn'] }}:8201` | Cluster replication address |
| `vault_cluster_leader_addr` | `""` | LB/leader address for HA retry_join |

### TLS Certificate Deployment

| Variable | Default | Description |
|----------|---------|-------------|
| `vault_manage_tls` | `false` | Deploy TLS certs from controller |
| `vault_tls_src_cert` | `""` | Source cert path on controller. Absolute → verified by preflight; relative → resolved by `copy`, unverifiable |
| `vault_tls_src_key` | `""` | Source key path on controller. Absolute → verified by preflight; relative → resolved by `copy`, unverifiable |
| `vault_tls_src_ca` | `""` | Source CA path on controller. Absolute → verified by preflight; relative → resolved by `copy`, unverifiable |

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

> On a host where fapolicyd is **enforcing**, Ansible itself cannot run without
> pipelining — the connection fails at fact-gathering, before this or any other
> phase. See
> [Connection: pipelining is required on fapolicyd-enforcing hosts](#connection-pipelining-is-required-on-fapolicyd-enforcing-hosts).

## Dependencies

See `requirements.yml` for Ansible collection dependencies and `requirements.txt`
for Python library dependencies. No other Ansible role dependencies.

## Example Playbook

### Single-Node Deployment (Internet-Connected)

```yaml
- hosts: vault
  become: true
  roles:
    - role: mpe-es.vault
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
    - role: mpe-es.vault
      vars:
        vault_repo_source: mirror
        vault_repo_url: "https://repo.closednetwork.local/hashicorp/RHEL/$releasever/$basearch/stable"
        vault_repo_gpg_key: "https://repo.closednetwork.local/hashicorp/gpg"
        vault_package_version: "2.1.1"
```

### Single-Node Deployment (Red Hat Satellite)

```yaml
- hosts: vault
  become: true
  roles:
    - role: mpe-es.vault
      vars:
        vault_repo_source: satellite
        vault_package_version: "2.1.1"
```

> **Enterprise editions need a license.** Satellite deployments are usually
> Enterprise, and `vault_edition: vault-enterprise-fips1403` selects that
> package — but Vault Enterprise **cannot start unlicensed**. The example above
> uses the Community default, which starts without one. Licence delivery is
> covered in the Enterprise licensing section below.

#### Enterprise licensing

Supply the licence as **plain text** in `vault_license_content` — the contents
of your `.hclic`, not a path to it:

```yaml
vault_edition: vault-enterprise-fips1403
vault_license_content: "{{ lookup('env', 'VAULT_LICENSE') }}"   # or an AAP credential
```

The role writes it to `/etc/vault.d/vault.hclic` as `root:vault 0640` — vault
reads it through the group but does not own it, the same posture as the TLS
material (#38, #77) — with `no_log` and `diff: false` on the task.

**There is no preflight gate for a missing licence, deliberately.** An
Enterprise edition selected without one fails at service start, which is loud,
immediate and attributable. A gate would add a code path and a test axis to
prevent a failure that already reports itself clearly.

> **Enterprise configs now reference `license_path` unconditionally.** Before
> this, an Enterprise render carried no `license_path` and operators licensed
> out of band. The config now always names `/etc/vault.d/vault.hclic`, while the
> file itself is written only when `vault_license_content` is set. Vault's
> precedence is `VAULT_LICENSE` > `VAULT_LICENSE_PATH` > `license_path`, so
> existing environment-variable deployments keep working unchanged — but if you
> stage a `.hclic` at a non-default path with no environment variable set, set
> `vault_license_content` as well or the start failure will point at the new
> `license_path`.

Satellite mode writes no `.repo` file: `subscription-manager` owns
`/etc/yum.repos.d/redhat.repo` and generates it from the host's content-view
bindings, and the GPG key is associated with the product server-side. The role
does not register the host — that is a prerequisite. Preflight verifies that
the host is registered and that `satellite` was selected on a RHEL system.

Verifying that your content view actually publishes Vault, and scoping the
install transaction to Satellite-published content, are **not** part of this
release — see [#68](https://github.com/mpe-es/ansible-role-vault/issues/68).
Until then `dnf` resolves across every enabled repository, so a foreign build
can win even in `satellite` mode.

`satellite` requires Red Hat Enterprise Linux — Satellite does not manage EL
rebuilds, so use `mirror` with an internal reposync URL on Rocky, Alma or
Oracle Linux.

The airgap and Satellite examples leave `vault_manage_tls` at its default of
`false`, so the certificate, key and CA must already be staged at `vault_tls_cert_file`,
`vault_tls_key_file` and `vault_tls_ca_file` before the role runs — preflight
rejects the host otherwise. Set `vault_manage_tls: true` **and** populate
`vault_tls_src_cert` / `_key` / `_ca` if you want the role to place them.

#### Operator-staged TLS material

On that staged path the role also **rewrites the ownership and mode of the files
you staged**, to `root:vault 0640` — otherwise the `vault` account cannot read
its own private key and the service fails at start (#77). Two bounds apply, and
material outside them is reported and left alone rather than silently changed:
only paths whose direct parent is `vault_tls_dir` are touched, and symlinks are
never followed. So pointing `vault_tls_ca_file` at a shared anchor such as
`/etc/ipa/ca.crt`, or at certmonger/certbot-managed links, is safe — but you
must make that material readable by the `vault` group yourself. A hardlink is
treated the same way, because its inode is shared with the other name for it. A
path that exists but is not a regular file (a directory left where a certificate
was expected), or one that cannot be inspected at all, is likewise reported and
skipped rather than converged.

Two further caveats. The parent check is **lexical**: if `vault_tls_dir` is itself a
symlink, a staged path under it still matches and the write lands on the
resolved target. A `--tags system` run performs this repair, since [#28](https://github.com/mpe-es/ansible-role-vault/issues/28) made every
include apply its own tags to the tasks it includes; on revisions before that
fix, only a full role run did.

### HA Cluster (3-Node with Load Balancer) — developmental

> **This example configures nodes; it does not stand up a working cluster.**
> The role renders a single `retry_join` block pointing at
> `vault_cluster_leader_addr`, and stops there. It performs no leader election
> ordering, no per-peer join, and no follower unseal. Running this playbook
> across three hosts unchanged will **initialize each node as its own
> independent Vault**, not form one Raft cluster. See
> [Known Limitations](#known-limitations) and
> [#44](https://github.com/mpe-es/ansible-role-vault/issues/44) for the full
> gap analysis and the manual steps currently required.

```yaml
- hosts: vault_cluster
  become: true
  roles:
    - role: mpe-es.vault
      vars:
        # Renders exactly one retry_join block. Raft expects one per peer.
        vault_cluster_leader_addr: "vault-lb.closednetwork.local"
        vault_manage_tls: true
        vault_tls_src_cert: "files/{{ inventory_hostname }}-tls.crt"
        vault_tls_src_key: "files/{{ inventory_hostname }}-tls.key"
        vault_tls_src_ca: "files/ca.crt"
        vault_rsyslog_enabled: true
        vault_rsyslog_host: "syslog.closednetwork.local"
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
    - role: mpe-es.vault
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
directory allows file replacement regardless of file ownership. Unseal
never places key material on the command line: the Ansible init path submits
each share to `POST /v1/sys/unseal` via `ansible.builtin.uri` (key in the request
body), and the boot-time `vault-unseal.sh` pipes each share to
`vault operator unseal -` over stdin. Neither channel exposes the key in a
process argument vector, so it cannot be captured by auditd `execve` records
(issue #31). **Do not "simplify" either path back to
`vault operator unseal <key>` — that reintroduces the leak** (a CI gate,
`tests/assert-no-unseal-argv.sh`, blocks the Ansible form).
**Verifying on a real host:** after an unseal cycle, run `ausearch -x vault`
(and, if applicable, `ausearch -x curl`) — no unseal key should appear in any
recorded argument. This confirmation is manual: CI proves argv-cleanliness
structurally (API body / stdin) and via the boot-script argv-capture test, but
the molecule/UBI-init container cannot run auditd.
The script at `/usr/local/bin/vault-unseal.sh` is `root:root` so the
service account cannot edit what root executes, and the script itself
refuses to run if the directory is untrusted (not root-owned, or
group/other-writable) or if the tokens file carries ANY group/other
access bits (key material must be `0600`). An operator-placed tokens
file (when the unseal shares are managed out-of-band rather than written by
the role) goes at the same path with the same `root:root 0600` posture — the script refuses
anything looser. Do not add a service-account directive to the unit
without changing that model.

**Least-privilege ownership (issue #38).** The vault service account READS what
it needs and OWNS nothing that defines its posture. The role sets:

| Artifact | Owner:group | Mode | Why |
|---|---|---|---|
| `vault.hcl` | `root:vault` | `0640` | process reads config via the group; cannot rewrite it |
| `vault.env` | `root:root` | `0600` | only systemd (root) reads it via `EnvironmentFile`; holds the HSM PIN (#41) — the process needs no access |
| TLS cert / key / CA | `root:vault` | `0640` | process reads the key via the group; cannot swap its trust anchors — for operator-staged material (`vault_manage_tls: false`) the bounds in [Operator-staged TLS material](#operator-staged-tls-material) apply |
| `/opt/vault` (dir) | `root:vault` | `0750` | the PARENT of `data/` and `tls/`. Group `r-x` is what makes it **traversable**: without it the process gets `EACCES` on everything beneath, however correct the children are. STIG mandates `umask 077`, so an operator staging TLS where preflight instructs creates this `0700 root:root` |
| `/opt/vault/tls` (dir) | `root:vault` | `0750` | root-owned dir blocks the process from unlink/replacing cert files (dir write ≠ file ownership) |
| `vault.hcl`/`vault.env` dir `/etc/vault.d` | `root:vault` | `0750` | (already; #30/#34) |
| helper scripts | `root:root` | `0750` | (already; #30) — the process cannot edit what root executes |
| `/opt/vault/data`, `/var/log/vault` | `vault:vault` | `0750` | the process legitimately WRITES its data and audit logs |

Two CI gates (`tests/assert-root-owned-posture.sh` for the deploys the role
writes, `tests/assert-staged-tls-posture.sh` for material the *operator* stages
under `vault_manage_tls: false`) and a molecule negative test (`runuser -u vault`
writes to the posture files are denied — including `tls.key` — while reads of
`tls.key` and writes to the data dir succeed) enforce this. The fapolicyd trust file pins size+sha256, which ownership
does not change, so trust stays valid. Note: an out-of-band `dnf update vault` may
revert `/etc/vault.d` to the RPM's shipped ownership until the next role run —
the unseal script fails closed (refuses to unseal) rather than trusting
an unexpected parent, so re-run the role after out-of-band
package updates. `--tags system` is sufficient for the ownership repair as of
[#28](https://github.com/mpe-es/ansible-role-vault/issues/28); before that fix only a full run reached it.

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

### HSM PKCS#11 seal PIN (`vault_hsm_pin`)

The PKCS#11 seal PIN is **never written to `vault.hcl`** (issue #41). The role
omits the `pin` attribute from the `seal "pkcs11"` stanza and supplies it via the
**`VAULT_HSM_PIN` environment variable** in `/etc/vault.d/vault.env`, which the
packaged `vault.service` unit reads through `EnvironmentFile=` — HashiCorp's
[documented and *strongly recommended*](https://developer.hashicorp.com/vault/docs/configuration/seal/pkcs11)
channel for the PIN. This keeps the PIN out of `vault.hcl` (which lands in config
backups and support bundles), out of `--diff`/check-mode output (`diff: false` on
the env-file render), and out of AAP surveys/logs (`no_log` on `vault_hsm_pin`).

- **Provide the PIN via an AAP credential or a vault-encrypted variable** — never
  in plain inventory.
- **PIN character constraint (fail-closed):** the PIN must not contain a
  double-quote (`"`), a backslash (`\`), a newline/tab, or any C0/DEL control
  character — the residue systemd `EnvironmentFile` double-quoting cannot carry.
  Leading/trailing spaces *are* preserved. The role asserts this (and that the PIN
  is non-empty, and that the installed unit exposes `EnvironmentFile`) before
  rendering, so a bad PIN fails the play loudly instead of silently corrupting the
  value into a failed unseal.
- **Version basis:** delivery relies on systemd's surrounding-quote-pair removal
  (stable on EL8/9/10, systemd ≥239) and Vault 2.0.0+'s `VAULT_HSM_PIN` contract.
  (Vault ≥1.16 also supports a `pin = "env://VAULT_HSM_PIN"` indirect reference;
  the direct env-var form was chosen for universal version support.)
- **`vault.env` is mode `0600`** (owner-only; only the systemd manager, as root,
  reads it to populate the environment).

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

## Known Limitations

Current, deliberate gaps. Each is tracked; none is a surprise. Read this before
committing the role to a production design.

### Multi-node Raft HA is developmental ([#44](https://github.com/mpe-es/ansible-role-vault/issues/44))

The role configures a node; it does not orchestrate a cluster.

- `vault_cluster_leader_addr` is a **single scalar** and renders exactly **one**
  `retry_join` block. Raft expects a `retry_join` per peer, so a joining node
  has one fixed contact point and no fallback.
- There is **no init orchestration**. With `vault_initialize: true` across a
  play, every host initializes itself — you get N independent single-node
  Vaults, each with its own root token and key shares, not one cluster.
- There is **no follower unseal step** after join.

Until #44 lands, treat cluster standup as a manual runbook: run the role for
configuration, then initialize exactly one node, join and unseal followers by
hand.

### Tag-scoped runs

Every include in `tasks/main.yml` carries an `apply:` block whose tags mirror the
include's own, so a tag reaches the tasks inside the phase it names:

| Tag | Runs |
|-----|------|
| `vault` | every phase — the whole role |
| `preflight` | all twelve gates, and nothing else |
| `repo`, `install`, `system`, `tls`, `configure`, `firewall`, `stig`, `service` | that phase only |
| `fapolicyd` | the fapolicyd trust phase |

`install` and `stig` additionally run the fapolicyd trust phase, which carries
both tags deliberately: the trust entries are part of installing and of
hardening.

Conditional phases still honour their own toggles — `--tags tls` does nothing
when `vault_manage_tls` is false, because the `when:` gates the include itself.

> **Before [#28](https://github.com/mpe-es/ansible-role-vault/issues/28), this did not work and failed silently.** `include_tasks` does not
> propagate its own tags; nine of the ten includes carried `tags:` without
> `apply:`, so a tag selected the *include* — which ran, making the output look
> right — and then executed none of its tasks. Measured on a live host:
> `--tags configure` ran three tasks (facts, argument-spec validation, and the
> include itself) and reported `ok=3 changed=0 failed=0`. A green run that
> configured nothing. If you are on an older revision, do not use tag-scoped
> runs to apply a subset of hardening.

### Other tracked gaps

| Area | Status | Issue |
|------|--------|-------|
| Raft snapshot backup | Not implemented — the role has no Vault **data** backup, only audit-log backup | [#35](https://github.com/mpe-es/ansible-role-vault/issues/35) |
| rsyslog audit forwarding | Plaintext TCP; no TLS | [#40](https://github.com/mpe-es/ansible-role-vault/issues/40) |
| Vault Enterprise editions | Cannot start unlicensed; no license management | [#42](https://github.com/mpe-es/ansible-role-vault/issues/42) |
| Cluster port 8201 | Opened unconditionally, not scoped by source or gated on clustering | [#39](https://github.com/mpe-es/ansible-role-vault/issues/39) |
| Compliance citations | Several control/STIG IDs are pending verification against authoritative sources | [#45](https://github.com/mpe-es/ansible-role-vault/issues/45) |

### Distribution

The role is **not yet published to Ansible Galaxy** and has no tagged release.
Install from git until a `v*` tag exists. Metadata targets the `mpe-es`
namespace; examples in this README use `mpe-es.vault` accordingly.

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
