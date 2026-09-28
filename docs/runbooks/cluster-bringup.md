# Runbook: Vault Raft cluster bring-up

Classification: UNCLASSIFIED · Last Updated: 28 Sep 2026 · Issue: #44

Executable without reading the issue. Every manual step is stated.

## What the role does and does not do

**Does:** renders one `retry_join` stanza per peer, runs `operator init` on exactly
one node, unseals that node, waits for each other node to **join** — on the Shamir and
HSM paths alike — unseals the followers when asked to, compares every node's
`cluster_id` against the initialization host's, captures the key material on the
controller, and enables the audit devices once. Under an HSM seal each node unseals
*itself*, so the role skips only the follower **unseal**, not the join wait: an HSM
follower that never joins would otherwise pass unnoticed.

**Does not:** any day-2 operation. No autopilot tuning, no peer add or remove, no
cluster snapshot restore, no quorum-loss recovery, **and no re-unsealing.** A role
re-run against an initialized cluster skips initialization, and therefore skips every
unseal step — see *After a reboot* below.

**Not verified by automation.** CI proves the rendered configuration and the task
structure. Cluster formation, leader election, follower join and unseal convergence
are **not** exercised by any test.

## Before you start

| | |
|---|---|
| Peers | Every entry in `vault_cluster_members` must be a **SAN on that peer's listener certificate**, and all peers must chain to the CA in `vault_tls_ca_file`. A name that is not a SAN fails the join with `x509: certificate is valid for …, not …` **after** the role has configured the host. |
| Peer form | Bare host or IP. No scheme, no port, no CIDR prefix. Preflight rejects `https://host`, `host:8200`, `10.0.0.1:8200`, `10.0.0.0/24`, an empty entry and an out-of-range dotted quad. IPv6 is written bare — `fd00::10`, not `[fd00::10]` — and the template brackets it. |
| mTLS | If `vault_tls_require_client_cert` is `true`, `retry_join` presents the node's own `vault_tls_cert_file` / `vault_tls_key_file` to the leader. That certificate needs **`clientAuth` in its extended key usage**; a server-only certificate fails the join and the role cannot inspect the EKU. |
| Init host | `vault_init_host` must name a host in the play. Preflight fails closed otherwise. |
| VIP | The HA VIP is for **client traffic**, not for joining — an operator ruling. Do not put it in `vault_cluster_members`; preflight rejects it alongside the peer list. |
| HSM clusters | Every node must reach the **same** HSM partition with the same `vault_hsm_key_label`. Keep `vault_hsm_generate_key: false` and pre-provision the key out of band — that variable is role-wide with no per-node semantics. |
| Capture volume | **`vault_init_capture_dir` must be on encrypted, persistent storage.** V-256898 / APAS-AT-000012 (CAT I) requires the Automation Controller filesystem on a LUKS volume with FIPS ciphers; V-263600 (CAT II) requires protected storage for cryptographic keys. The role refuses an ephemeral destination but cannot tell whether the volume is encrypted. |

## Inventory

```yaml
all:
  children:
    vault:
      hosts:
        vault-01.mpe.mil:
        vault-02.mpe.mil:
        vault-03.mpe.mil:
      vars:
        vault_cluster_members:
          - vault-01.mpe.mil
          - vault-02.mpe.mil
          - vault-03.mpe.mil
        vault_init_host: vault-01.mpe.mil
        vault_initialize: true
        vault_init_unseal: true
        vault_init_capture_dir: /srv/vault-init-capture
```

Each node keeps its own `vault_raft_node_id`, `vault_api_addr` and
`vault_cluster_addr`; the defaults derive them per host.

## Bring-up

1. **Run the role against the whole group, no `serial`, no `--limit`, and not
   `strategy: free`.**
   ```
   ansible-playbook -i inventory site.yml --limit vault
   ```
   Preflight fails closed if `vault_init_host` is absent from the play, so a partial
   run cannot quietly initialize a second cluster. `strategy: free` removes the task
   barrier that orders followers after the init host; the role detects the resulting
   empty register and fails the play rather than skipping to a green result, but it
   cannot make `free` work.

2. **Confirm what the play reported.** `vault_init_host` initializes; the others wait
   to join and are then unsealed. A node left sealed prints
   `WARNING: Vault initialized but left SEALED`.

3. **Take custody of the key material immediately.** On the controller:
   ```
   ls -l /srv/vault-init-capture/vault-01.mpe.mil/
   ```
   One `root-token`, one `unseal-key-N` per share (or `recovery-key-N` under an HSM
   seal). **There is one key set for the whole cluster, not one per node.** Distribute
   one share per custodian per local policy and remove them from the controller.

4. **Verify membership.**
   ```
   vault operator raft list-peers
   ```
   Three peers, one leader. **A freshly joined node shows `Voter false` until
   autopilot's stabilization window elapses** — that is normal, not a broken join.
   If a node is *missing* from the list, its join failed; check the certificate SAN
   first.

5. **Verify seal state per node**, against each node directly rather than the VIP:
   ```
   for h in vault-01 vault-02 vault-03; do
     curl -s --cacert /opt/vault/tls/ca.crt https://$h.mpe.mil:8200/v1/sys/health -o /dev/null -w "$h %{http_code}\n"
   done
   ```
   `200` = active, `429` = unsealed standby, `503` = still sealed.

## After a reboot

**A Shamir cluster with `vault_auto_unseal_enabled: false` (the default) comes back
sealed, and re-running the role does not unseal it** — initialization is skipped, so
every unseal step is skipped, and **the play reports success while the cluster is
unavailable.** Unseal each node manually with the threshold shares.

Two ways to avoid that, both operator decisions:

- **`vault_auto_unseal_enabled: true`** installs a boot-time unseal service and writes
  the threshold to `/etc/vault.d/tokens.env` on **every** node. The variable's own
  comment calls this *"a key-at-rest decision"*: any node's disk then yields enough
  shares to unseal the cluster.
- **An HSM seal** (`vault_hsm_enabled: true`) — every node unseals itself from the HSM
  with no shares on disk. This is the recommended posture where an HSM exists.

## If the play fails

| Symptom | Cause |
|---|---|
| `x509: certificate is valid for …, not …` | A member name is not a SAN on that peer's certificate. |
| `400 server is not yet initialized` on a follower | The join has not completed within the 60s wait. Check that the init host was unsealed — a sealed leader cannot serve the raft bootstrap challenge, so no follower can join. |
| `path already in use at file/` | An audit device already exists. Audit devices are cluster-wide and enabled once, on the init host. |
| Preflight: `not in this play` | `vault_init_host` is misspelled or excluded by `--limit`. |
| Play green, nothing initialized | Should not happen: preflight fails closed on an absent init host. If it does, report it. |
| `has produced no init output for it to read` | Either the play uses `strategy: free`, or the cluster was already initialized and this node is a new peer. Adding a peer to a live cluster is day-2 and out of scope — the existing shares are not available to the run. |
| `reports Raft cluster … while the initialization host reports …` | These are **separate clusters with separate key sets**, not one HA cluster: `retry_join` never took effect, or the nodes were initialized independently before `vault_cluster_members` was set. An already-initialized node cannot be joined to another cluster. Destroy `vault_data_dir` on every node except the init host and re-run. |
| Followers never join, leader sealed | `vault_init_unseal: false` leaves the leader sealed, and a sealed leader cannot serve the raft bootstrap challenge. Unseal the init host by hand first, then the rest. |
| Join fails only when `vault_tls_require_client_cert` is true | The node's listener certificate lacks `clientAuth` in its extended key usage, so it cannot authenticate to the leader. |
