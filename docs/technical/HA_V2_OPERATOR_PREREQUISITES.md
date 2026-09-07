# HA v2 operator prerequisites

This document records the external operator inputs required before the optional two-node HA v2 runtime can start. It is an implementation prerequisite, not a qualification claim or a deployment guide.

## Fixed topology and authority

HA v2 accepts exactly two statically identified nodes in one cluster epoch. Configure exactly one node as `writer` and the other as `standby`. The writer is the only node allowed to originate runtime firewall mutations. The standby only applies authenticated replication received from its configured peer.

The operator owns role assignment, cluster epoch changes, certificate issuance, certificate rotation, secret distribution, firewall reachability, backups, and explicit recovery decisions. SysWarden does not elect a writer and does not automatically promote a standby.

## Required configuration

Set `integrations.ha.enabled = true` and `integrations.ha.v2_enabled = true` only after all of these values are ready:

- `cluster_id`: the same lowercase identifier on both nodes.
- `epoch`: the same nonzero integer on both nodes. Never change it while retained replication state is non-empty.
- `node_id` and `peer_id`: opposite lowercase identifiers on the two nodes.
- `role`: `writer` on exactly one node and `standby` on exactly one node.
- `peer_ips`: one exact canonical IP address, not a CIDR.
- `peer_port`: the same reachable TLS port used by the peer.
- `token`: the existing outer HTTP bearer credential, without whitespace.
- `v2_secret_file`: a distinct 32 to 256 byte message-authentication secret shared by the two nodes.
- `tls_cert_file`, `tls_key_file`, and `tls_ca_file`: the local mutual TLS identity and its issuing CA.
- `peer_tls_name`: exactly equal to `peer_id`.
- `peer_cert_sha256`: one current SHA-256 certificate fingerprint, or current and next fingerprints during a bounded rotation.
- `state_file` and `transaction_file`: different absolute canonical paths on local durable storage.
- bounded heartbeat and request timeouts accepted by the configuration validator.
- When BunkerWeb is enabled, `integrations.bunkerweb.scheduler_ips`: the exact canonical source IPs or bounded CIDRs used by its schedulers. These scopes are independent from `peer_ips` and are durable ownership identities. Do not remove, narrow, replace, or shadow a retained scope with a more-specific overlapping scope while its provenance ledger is non-empty; HA v2 restart refuses that change instead of silently orphaning bans.

The first successful opt-in binds the local node ID, peer ID, and static role into the durable state for that cluster epoch. Later startup refuses any identity or role change against that retained epoch, including an otherwise empty model. Change membership or roles only through an operator-controlled epoch migration with preserved evidence.

The directories containing secrets, TLS material, replication state, and the transaction journal must be real owner-only directories. Every secret, certificate, key, state, and journal file must be a real owner-only regular file with mode `0600`. Symbolic links are refused. The configured service user must own the directories and files.

TLS files must contain only bounded PEM material and whitespace. The certificate file may contain the node leaf followed by its intermediate chain, the key file must contain exactly one unencrypted private-key block, and the CA file must contain unique CA certificates only. Comments, unrelated PEM blocks, encrypted-key headers, duplicate roots, and trailing data are refused.

Before the first HA v2 start, engage the existing native-sync fence from a complete operator-attested member and legacy-writer inventory, close or migrate every legacy writer, and drain the legacy temporary-ban provenance ledger. Keep that fence in `active_drained` for the whole HA v2 epoch. First activation refuses an inactive fence or a non-empty legacy ledger, so no untracked legacy write can race the replicated ownership model. A later restart of the same durable writer may retain its non-empty BunkerWeb provenance ledger only when the state and anchor, or one valid pending recovery journal, attest the exact configured writer identity, every recorded scheduler scope is still configured exactly, and every non-expired active or pending-apply record is covered by its durable HA v2 claim. The standby always requires an empty legacy provenance ledger.

## Certificate contract

Issue each node certificate from the configured CA with all of the following properties:

- a DNS subject alternative name exactly equal to that node's `node_id`;
- both TLS server-authentication and client-authentication extended key usages;
- validity at service start;
- a private key matching the certificate;
- a peer leaf-certificate SHA-256 fingerprint listed on the opposite node.

HA v2 uses TLS 1.3 only. The legacy HA and BunkerWeb routes remain on the shared listener, so client certificates are enforced again at every HA v2 route after the TLS chain verification. A bearer token without the pinned peer certificate cannot reach HA v2 coordination state.

The configured HA v2 node certificate becomes the certificate presented by the shared listener. Before enabling HA v2, distribute its issuing CA or exact leaf fingerprint to every retained legacy reader and BunkerWeb client through an operator-controlled channel. Do not assume that the earlier zero-touch `server.crt` remains the live listener identity.

## Network contract

Allow the configured peer IP to reach the HA TLS port in both directions. Do not place a redirecting proxy between the nodes. The outbound client refuses redirects and environment proxy settings. Source-address authorization, bearer authentication, the pinned mutual TLS identity, the cluster and epoch, sender and recipient identities, message freshness, per-node sequence, operation digest, and message MAC must all validate before a replicated mutation is accepted.

After opt-in, `/ha/sync`, `/ha/status`, and `/ha/telemetry` retain their existing paths and wire formats. Legacy static POST writes remain stopped by the active native-sync fence. Enriched BunkerWeb mutations are accepted only by the healthy static writer after a recent mutually authenticated peer heartbeat; the standby rejects them before changing its provenance ledger. Accepted mutations pass through the same recoverable HA v2 firewall and model transaction as local runtime actions.

The pinned BunkerWeb 1.11 client does not select the HA v2 writer from `replication_v2.role`. A two-endpoint `SYSWARDEN_PEERS` deployment is therefore qualified only when `SYSWARDEN_FENCE_MANIFEST` contains the complete two-node membership and every member proves the same active drained fence: the plugin sends enriched mutations to the writer and holds the standby's legacy plan without writing it. Without that complete manifest, configure only the healthy static writer endpoint or keep BunkerWeb ban push disabled. A partial manifest, two endpoints without the manifest, or an automatic standby mutation path is not a supported HA v2 contract.

## Persistence and recovery

The transaction journal couples one desired firewall state to one complete candidate replication model. It binds the exact pre-state, candidate-state and fenced-recovery digests, cluster epoch, genesis identity, operation, and durable transaction stage. A `prepared` journal permits only the ordered crash states pre-state/pre-anchor, candidate-state/pre-anchor and candidate-state/candidate-anchor. An `applied` journal permits only candidate-state/candidate-anchor, recovery-state/candidate-anchor and recovery-state/recovery-anchor. A `recovered` journal permits only recovery-state/recovery-anchor. Every other state and anchor pair fails closed. An older canonical journal therefore cannot roll a newer state and anchor back within the same epoch, and a second crash during recovery remains resumable. SysWarden holds the shared inter-process firewall lock while it durably prepares the journal, mutates and verifies nftables, persists the candidate model, advances the journal stage, persists the recovery fence, and commits the journal. Startup replays an intact journal idempotently and then reconciles every address retained by the durable model before exposing any HA v2 writer. A clean restart also reapplies active timed and permanent entries and retained absence tombstones to the authoritative firewall.

Every state and anchor update outside a firewall mutation uses a separate owner-only head journal containing the complete candidate model and its pre-state and candidate digests. This includes first initialization, acknowledgements, coordination state, recovery and compaction. Startup accepts only absent/absent, pre-state/pre-anchor, candidate-state/pre-anchor or candidate-state/candidate-anchor as appropriate, completes the candidate publication and retires the journal. A head journal and firewall journal are mutually exclusive during live mutation and startup recovery. Their simultaneous presence is rejected before any firewall or model mutation.

The runtime also holds a non-blocking exclusive lock at `state_file.instance.lock` for the full process lifetime. The lock is an owner-only regular file with one link and is never removed during release. Its open file is retained in a package-level lease registry after successful startup and is released only by the operating system at process exit; cancelling the runtime context does not release it while older handlers or manager references may still execute. Startup failures release it before returning. The path is attested both before and after lock acquisition to reject replacement races. The lock is acquired before reading or mutating HA state, so it serializes the state, anchor, head journal and firewall journal even when `transaction_file` is located in another validated directory. A second runtime invocation fails before recovery or mutation. Each durable update is additionally compare-and-swap bound to the state digest observed by its store; a stale snapshot cannot replace a newer durable fence.

The first successful initialization creates an owner-only state anchor beside `state_file`, using the suffix `.anchor.json`. Its random genesis identity is bound into every later model snapshot, and its durable head digest advances with each committed state. Startup fails closed if an established state file is missing, if its anchor is missing, or if a replacement or rolled-back state does not match the retained head. Back up and restore the state file, its anchor, and any pending transaction journal as one unit. Complete loss or rollback of that whole unit cannot be detected from the same rolled-back local evidence. Fence both nodes and advance the operator-controlled epoch before restoring such a unit; never boot both nodes from an old checkpoint under its former epoch.

Every authenticated heartbeat carries the cluster epoch, a canonical digest of the peer-comparable replicated checkpoint, its canonical checkpoint time, and the bounded delivery outbox depth. Peer availability expires from the local authenticated receipt time, so a future peer clock cannot extend the timeout. Status recomputes its local checkpoint at the peer's exact checkpoint time, including expiry and tombstone boundaries. A digest mismatch can exist temporarily only while an authenticated writer has pending delivery. It blocks a quiescent healthy checkpoint and new untracked progress. A mismatch with no pending delivery moves the node to explicit recovery, and recovery activation requires identical quiescent peer checkpoints.

A missing heartbeat, asymmetric peer view, role conflict, identity conflict, or mutation failure stops new writer mutations by moving coordination out of `healthy`. A fenced, degraded, or recovering node never self-promotes. Recovery requires an authenticated peer `prepare` request with the exact local state digest reported by `/ha/status`, followed by a separate `activate` request while a recent authenticated peer heartbeat exists. Activation is rejected unless that exact prepare phase completed. A bounded heartbeat grace permits the two recovering nodes to be activated in sequence, but automatically returns a one-sided recovery to `recovering` if the peer does not become healthy before the deadline.

Before authorizing recovery, the operator must determine why the nodes diverged, correct roles and network reachability, compare the durable state evidence on both nodes, and select the authoritative state. If the retained states are not equivalent, keep both nodes fenced and restore the intended state from an operator-controlled backup. Changing the epoch or deleting state is an operator migration action and must never be used as an automatic recovery shortcut.

The read-only `firewall.HAReplicationStateReporter` capability exposes a bounded lifecycle snapshot for diagnostics. It distinguishes active, naturally expired, explicitly deleted, and expiry-tombstoned claims without exposing secrets or a mutation method.
