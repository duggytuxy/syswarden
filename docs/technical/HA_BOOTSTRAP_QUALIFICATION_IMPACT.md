# HA peer setup: native failure and qualification impact

## Preserved reproduction

The native preparation of candidate `5649b0836306bbc2d9c0fde4c54020deca8c549a` on 27 September 2026 failed before either required 30-minute HA campaign started. Signed packages had been installed and their signatures, installed executables and process identities verified on the two nodes.

On the first node, enabling legacy inbound-only HA and running `syswarden reload` invoked `whitelist <peer>` without a port. That operation acquired the legacy unban fence before TLS bootstrap and created `ha/fence/native-sync-fence.lock`. No fence state or TLS certificate/key existed. The peer whitelist failed, and the restarted core refused the incomplete TLS identity. The restart loop was stopped explicitly. The second node was not bootstrapped.

Private, encrypted captures and verified recovery copies retain these exact records:

| Record | SHA-256 |
| --- | --- |
| Native failed bootstrap, `ha5649-bootstrap-listener-node02-20260927t074955z.json` | `ba9cf5cab52c99d62d44b3217fe7711ebdf7edf8eb6c58ccb238a0f7a45abbae3c` |
| Read-only diagnosis, `ha5649-diagnose-bootstrap-readonly-node02-20260927t075240z.json` | `86a8964948b04344de48c846b6fcb8ba818e3289223afc3ae3e24ffe9ffc7753` |
| Stopped core and retained directory inventory, `ha5649-stop-bootstrap-loop-node02-20260927t075416z.json` | `730a8f396b966aabfe0f13c30439dc6034ceee28098dac93455a863d4abbae3c` |

These are failed-candidate evidence, not successful HA campaign receipts. Raw records, private configuration and node addresses are not published here.

## Correction and boundaries

The CLI now invokes the packaged executable directly with `whitelist <peer> --port <peer_port>`. Both target and port must be canonical and valid before a command is returned. Port-scoped whitelisting preserves global block ownership and does not acquire the legacy unban fence. HA v2 setup keeps the owned legacy synchronization cron disabled, including for exact peer addresses. Invalid peers and failed whitelist setup also disable that cron.

The core TLS loader, fence validation, replication protocol, capability catalogue, frozen native contracts and contract deadlines are unchanged. No incomplete identity is accepted. Existing unscoped whitelist and unban commands retain their fence and HA v2 ownership restrictions.

## Explicit replay policy

1. Preserve all earlier results under their actual commit and package hashes. Do not relabel the failed bootstrap or earlier passes with the corrected candidate.
2. Build and sign fresh artifacts from the reviewed, merged commit. Record source and catalogue differences, package hashes, signature checks, Go build identities and installed/process executable hashes for each native profile.
3. Replay first-enable HA bootstrap, exact-peer and inbound-only peer setup, configured-port access, rejection of invalid scopes, legacy cron closure, HA v2 reload and package lifecycle paths invoking this CLI. Start from an attested pre-bootstrap state and verify restoration.
4. Execute both real 30-minute native HA campaigns with all required scenarios on the new artifacts. Local regression tests and preparation captures cannot satisfy those campaigns.
5. For other native evidence, require an explicit protected continuity decision based on source closure, executable identity and contract policy, or replay the affected controls. An unchanged core source tree does not automatically transfer a verdict to a rebuilt binary or package.
6. APK-324's previous functional captures remain historical evidence. Its late network restoration exceeded the frozen campaign window; this change does not waive that deadline or create a global APK verdict. A conforming replay is still required.
7. Run protected global acceptance only after candidate-bound evidence, all necessary replays and final restorations are complete. The version remains unqualified and this change authorizes no release publication.
