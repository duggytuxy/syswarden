# HA manifest creation with no legacy writers

## Preserved native failure

Candidate `8082bc9bb433e594e5f7979561cd7a7495298271`, built and signed by protected run `36307575362`, failed during native HA preparation on 27 September 2026. Both native nodes had completed TLS listener bootstrap. No HA v2 campaign had started.

The operator verified that the isolated two-node inventory had no legacy writers: the owned legacy synchronization cron was absent, BunkerWeb integration was disabled and the legacy ban ledger was absent or empty. The protected inventory explicitly contained `"legacy_writer_ids": []` and included both receiving endpoints. The unmodified signed CLI probed the members, then rejected its own generated manifest with `invalid HA fence manifest envelope`.

The encrypted failure capture is retained privately as `ha8082-manifest-create-node02-20260927t092904z.json`, SHA-256 `3c7f31ec3ae1f6d320e836c36c87a8e12d7e0ea5879929aca7d281654202c7fd`. Its recovery decryption was verified. No invented writer, manually generated replacement manifest or patched native binary was used. The failed candidate remains failed for this preparation step.

## Cause and correction

Manifest creation copied the validated writer slice with a nil destination. An explicitly empty array therefore became nil, and the strict manifest validator correctly rejected it as missing inventory. Creation now preserves a non-nil empty slice. The resulting canonical JSON retains `[]` and its existing normative empty-inventory digest.

The regression suite reproduces the failure before the correction and checks successful creation and strict round-trip verification afterward. It also checks sorted nonempty inventories and rejection of null, missing, duplicate or invalid writers, missing completeness assertion, stale member challenges and missing TLS identity. Rejected creation must leave no output manifest.

The strict validators, member authentication, TLS verification, challenge freshness, ownership and mode checks, fence administration, core replication runtime, capability catalogue and frozen evidence contracts are unchanged. The inventory validation still runs before any empty list is copied.

## Explicit candidate and replay policy

1. Keep all prior captures, verdicts, failed attempts and timestamps bound to their actual source and package hashes. Neither local regressions nor this preparation failure count as a native HA campaign.
2. After review and merge, build and sign new candidate packages. Independently verify signatures and artifact provenance, record package and executable differences, and bind installed and running executable identities to the merged candidate.
3. Replay native manifest creation using the verified complete inventory with no legacy writers, strict manifest verification, fence engagement and the subsequent HA v2 activation. Retain the original failed reproduction separately.
4. Execute both required real 30-minute native campaigns with their complete scenario evidence and verified restoration. Preparation and unit tests do not replace those campaigns.
5. The CLI executable changes. Prior CLI and package-lifecycle evidence needs an explicit protected continuity decision or a replay of invalidated controls. Compare actual rebuilt artifacts; unchanged core source alone does not transfer any verdict.
6. Earlier APK-324 functional results remain historical. The restoration deadline failure is not waived; a conforming candidate-bound replay remains required.
7. Global protected acceptance requires all necessary candidate-bound evidence and final restorations. This correction does not qualify v4.10.0 or authorize a release publication.
