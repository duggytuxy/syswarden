# HA writer recovery with retained delivery

## Preserved native observation

Candidate `7a840026a6fde9804860d5c5f61ec9d61bde7e4a`, from protected signed-package run `36311884626`, was exercised on the native writer and standby on 27 September 2026. The crash observer stopped the real writer at a durable firewall-WAL boundary. One restart recovered the transaction and removed the pending WAL. The writer remained fenced with one durable outbound operation; the standby did not yet have that claim.

The encrypted crash capture is retained privately as `ha7a84-crash-wrapper-wal-node02-20260927t104349z.json`, SHA-256 `ac0db09d513a5a37a90fe8db356681f3b05ffd8299e0b230f3ed78e09b612154`. The single-restart capture is `ha7a84-restart-native-recover-once-node02-20260927t104356z.json`, SHA-256 `f574eca8015ccd282003cd3adc298e01d7d4462dcba3b226ab0f59f4eec4f2f6`. The full real 30-minute observation is retained as `ha7a84-r1-20260927-monitor-node02-20260927t103635z.json`, SHA-256 `6e16e5c6d6fc36c4546af811facd93d890e5cf1da3bcf55a5b4027a951598197`. That campaign remains incomplete. These references do not assert a passing native verdict.

Local regressions reproduce the same recovery dead end after WAL preparation, firewall mutation and model persistence. The original failing logs remain separate from the corrected runs. The standby recovery case also runs through retained replay, acknowledgement and explicit activation. Local fixtures use simulated firewall and HTTP components and are development evidence only.

## Correction and retained boundaries

Previously, ordinary delivery rejected every recovering coordinator. Explicit activation required equal checkpoints and empty outboxes. Consequently, the recovered writer could neither deliver its retained claim nor activate to clear the queue.

Successful, durable operator preparation now captures an in-memory allowlist of the writer's existing outbound operations. A recovering writer can emit an operation only when it matches both that allowlist and the current durable model exactly, no local transaction is pending, and a recent authenticated heartbeat identifies a recovering peer with a recovering view and an empty outbox. A process restart requires fresh preparation. A failed preparation grants no delivery authority. The signed operation envelope, mutual TLS, peer identity, epoch, replay checks and receiver delivery budget are unchanged.

No new local mutation is accepted in recovery. No outbox item is erased to force convergence. Acknowledgements retain the existing durable persistence path, including idempotent replay after a lost response. Both nodes still require separate explicit activation after equal quiescent checkpoints. The negative tests cover lost preparation, failed durable preparation, stale receipts, unexpected peer states, pending WAL, role conflicts and operations that changed, disappeared or were added after preparation.

## Explicit candidate and replay policy

1. Preserve the failed native candidate, raw captures, encrypted exports and exact timestamps. Keep the pre-fix local reproduction. Do not relabel either as a successful campaign after this change.
2. This correction changes the core runtime. After review and merge, build new packages from the exact merged commit, obtain protected signatures, independently verify the complete signed inventory and compare the actual package contents and executable identities. Development binaries must not be substituted for signed native candidates.
3. Replay both complete native 30-minute HA campaigns on that new candidate, including writer WAL recovery, head-journal recovery, partitions, monotonic heartbeat receipt timeout, instance exclusion, explicit rejoin, rolling upgrade and rollback. Preparation and local regression tests are not native evidence. Keep the frozen HA contract unchanged and obtain external attestation through the protected producer.
4. Replay APK-324 under the frozen contract with restoration inside its deadline. Its earlier functional captures and late restoration remain historical; neither this change nor a continuity decision waives that failed deadline.
5. Reassess native capability, lifecycle and performance evidence that executes the changed core. Replay affected controls, including installation and restart recovery. Any selective reuse of unaffected observations requires a separately reviewed, protected continuity decision that binds exact old and new source closures, package and executable hashes, test inputs and contract requirements. No verdict is transferred by unchanged catalogue data alone.
6. Unchanged catalogue and evidence-validator sources can retain their source-level analysis after exact comparison. Runtime, signature, package, native provenance and global acceptance claims require current candidate bindings. Rebuilds alone do not establish behavioural continuity.
7. Restore the original native nodes and network associations, preserve the new evidence, and execute protected global acceptance only when all required inputs have valid candidate bindings. This correction does not qualify v4.10.0 and authorizes no release publication.
