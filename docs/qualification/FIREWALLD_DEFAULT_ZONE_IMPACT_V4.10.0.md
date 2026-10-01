# firewalld default-zone heading: IVV impact for v4.10.0

Status: intermediate release validation blocked. This correction does not accept,
qualify, tag or publish v4.10.0.

Failed product candidate: `f334beaddc5c6005f40d79c7bab4e43598bfc5ed`.
Correction branch base: `324b6e5c97f3f06d38cd9409f1269190fde8bac7`.

## Native reproduction retained

On 30 September 2026, the signed standard AlmaLinux 10 package reached native
HA peer bootstrap with firewalld 2.4.3. Its `firewall-cmd --get-active-zones`
output included:

```text
public (default)
  interfaces: eth0
trusted
  sources: 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
```

The CLI rejected the annotated header as malformed. Compatibility preflight
failed before committing new nftables rules and retained the previous ruleset.
SSH and SELinux Enforcing were observed during diagnosis. HA bootstrap did not
pass, and no HA campaign verdict is issued for this attempt.

The encrypted private evidence retains the failed bootstrap capture with SHA-256
`9fa3bc6e27f70665fb69615a0faaaed8d92d4879156d7817ac723d9282f6cd2d`
and the independent read-only diagnosis with SHA-256
`290b8b663437b77898fbca20e887806191fe3d48a6219b375ae3ea78fa65efc8`.
The native failure is preserved independently of this correction.

A separate Ubuntu bootstrap observation failed in the local Python checker after
the native reload succeeded: that checker treated a legitimate port-scoped HA
whitelist entry as an ordinary IP network. This is a harness limitation, not a
successful HA verdict or evidence of another product failure. Its failed capture
is retained with SHA-256
`5f6343f643ad3c4c56b60ea124180f6ff8c3f5bc898ff3a79326cc358f40c38f`.
Any checker repair must preserve the distinction between unscoped seed entries
and exact authorized peer/port entries, with positive and negative regressions.

## Correction boundary and regression evidence

The active-zone parser accepts exactly one additional display token, `(default)`,
after a valid zone name. The annotation never selects a zone. Exactly one active
interface-bound zone is still required. Source-only zones, missing interfaces,
multiple interface-bound zones, unsafe zone names, unknown annotations, duplicate
annotations and trailing tokens retain their rejection behavior. Port ownership
continues to record the explicit selected zone; no default-zone fallback is added.

The runtime daemon, HA wire protocol, catalogue, package lifecycle scripts,
version files and frozen acceptance contracts are unchanged by this correction.
The CLI executable changes and all distributed packages containing it must be
rebuilt with fresh provenance and signatures.

The new positive cases fail against the unchanged parser and pass after the fix.
Negative cases assert refusal before the nftables commit. Local validation used
the repository-required Go 1.26.6 toolchain with dependency downloads disabled:

- `go test ./pkg/firewall -count=1`: passed.
- `go test -race ./...` in `src/core/syswarden-cli`: passed.

Retained output hashes:

| Output | SHA-256 |
| --- | --- |
| Before correction, positive reproduction fails | `12512cfb9821ad9e17a29f93b5b599462a5a736acb37d4d46e8ad21143dbca54` |
| Complete firewall suite after correction | `661ef299006805713b352d904cebc85e15acf74a6b2206cf2b2602d0d559b34e` |
| Complete CLI race suite after correction | `5df005c05a1a845d42634a3bad3721b612ca43bc407adde438a07c975b0750a2` |

## Explicit candidate and replay policy

1. Bind the next candidate to the reviewed merged commit. Build and verify every
   affected package variant, package digest, attestation, signature and installed
   CLI/core identity. Do not rename old artifacts or change old receipt bindings.
2. Replay native AlmaLinux 10 standard HA bootstrap with the observed annotated
   header, peer reachability, replication, fencing and cleanup. Verify rollback
   and original host restoration. Local parser tests do not replace native HA.
3. Review all firewalld-backed paths that resolve a compatibility port zone,
   including standard and RHELPO RPM profiles on AlmaLinux 9 and 10. Replay the
   affected activation, reload, ownership and cleanup controls on rebuilt
   packages. Use the complete gate where the frozen verifier cannot admit a
   scoped replay.
4. Keep the earlier two 30-minute HA campaigns attached only to candidate
   `24c3c6e1548b8db0ccf64c37a33e05b351be5a18`. Assess them under the intermediate
   IVV policy with an explicit protected continuity decision and fresh functional
   HA evidence. They are not passes for this new candidate. If the applicable
   frozen gate requires fresh full campaigns, execute both native campaigns.
5. Preserve the other f334bead native results with their original package hashes.
   For unaffected behavior, require a documented source-closure and binary-binding
   decision supported by the protected verifier. Replay controls invalidated by
   the CLI change or candidate binding. Unchanged source alone grants no pass.
6. Keep the independent updater producer and verifier frozen. Do not adapt them
   to accept the correction or any previously refused evidence.
7. Run protected global acceptance only once all candidate-bound prerequisites,
   continuity decisions, required replays and final restorations are verified.
   Publication remains blocked until that acceptance succeeds.

The version stays v4.10.0. Under the recorded release policy it follows IVV;
Upgrade releases follow full IVVQ. This distinction does not waive a failed
control, artifact provenance, signatures or restoration requirements.
