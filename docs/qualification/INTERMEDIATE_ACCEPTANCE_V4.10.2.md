# v4.10.2 Patch IVV acceptance plan

This plan defines the acceptance requirements. Local checks and completed native
experiments are prerequisites, not a protected release verdict. The reviewed
producer must pass on the publication commit before publication can proceed.

## Source and signed material

[PR #287](https://github.com/duggytuxy/syswarden/pull/287) introduced the
`Patch :` transition from v4.10.1 to v4.10.2 at
`59d7854bc4a21ddb950da2f1509edb432f54402a`. The last public release remains
v4.10.0. The impact review includes all changes since that public release,
including the unpublished v4.10.1 changes. Intermediate releases require
**IVV**. An `Upgrade` requires complete **IVVQ**.

The frozen product and native-tested source are both
`94d97f07cb5a054669dd66d6efd28ba55db5d173`. The native campaign used the exact
signed DEB and its attested CLI. A later publication commit may change only the
listed acceptance tooling, tests and documentation. Product packages and their
original source, signatures, binary bundle, SBOM and updater remain frozen.

| Material | Exact producer | Artifact |
| --- | --- | --- |
| Four signed native package variants | [37030270841](https://github.com/duggytuxy/syswarden/actions/runs/37030270841) | `11237882878` |
| Candidate updater and Ed25519 manifest | [37033510001](https://github.com/duggytuxy/syswarden/actions/runs/37033510001) | `11237844323` |
| Attested CLI, Core and TUI bundle | [37028743201](https://github.com/duggytuxy/syswarden/actions/runs/37028743201) | `11236648575` |
| Product SBOM | Same Security Audit run | `11236456750` |

The [machine-readable plan](../../scripts/ci/release_ivv_v4102_plan.json) pins
these identities and every package digest. The
[impact record](../../scripts/ci/release_ivv_v4102_impact.json) binds complete
Git tree identities, the public-release delta and all 219 non-test Go module
inputs. No source-continuity exception is needed between the native-tested
candidate and signed product.

## Native Debian 13 coverage

The campaign reconstructed recognized historical WireGuard templates with
synthetic keys under the relevant hardening subset. It exercised actual systemd,
WireGuard, nftables, dpkg and APT operations, including two reboots.

| Area | Observed behavior |
| --- | --- |
| Two configuration generations | Active historical VPN blockers and ordinary ambiguity refusals preserve host state. Explicit retirement uses a fresh digest-bound plan after the historical service is stopped and disabled. |
| Interrupted older removal | The real older uninstall failure leaves its removal barrier. Normal update remains blocked. A separately verified candidate CLI can inspect and retire the recognized historical configuration through that barrier, followed by native purge. |
| Retry and repeat | A stale plan is refused. A controlled archive I/O failure after exact rule cleanup retains configuration and ownership evidence. Fresh inspection and retry complete the private archive; repeating the completed operation is harmless. |
| Ownership boundaries | Custom configuration, missing modern ownership, transaction presence, duplicate matching rules, a foreign marker and foreign reserved-table topology are refused. Unrelated administrator rules, configuration and interfaces are preserved. |
| Current VPN | Retirement preserves the exact modern tokenized table and manifest; reconciliation restores the current VPN. |
| Package consistency | Direct CLI uninstall refuses installed, unpacked and genuinely half-configured native registration without changes. Native purge and same-version reinstall complete with consistent registration and executable payload. |
| Older missing payload | Real v4.10.0 uninstall leaves dpkg registered with a missing CLI. Same-version APT can skip unpacking; its configure-only path reproduces postinst exit 127. Verified unpack followed by package-specific configuration repairs that state. |
| Recurrence prevention | Namespace conflicts fail before install, reload or creation of a new removal barrier. Retirement persists through signed update, reinstall and their reboots. |
| Single-generation residue | Native purge removes the exact recognized unmarked legacy table and shared rules when bound to retained modern ownership, while preserving administrator state. |
| Restoration | Original package registration, service states, table inventory, network configuration digest and Geo/ASN settings match the pre-campaign baseline. Test state is absent. |

The private input graph retains every original script, output, return code and
archive digest. Four captures retain their nonzero harness results: the initial
fixture expected modern PostDown to remove its table, a negative test incorrectly
expected rejection of an unrelated compound rule, and two repair steps assumed
that native unpack would not recreate empty directories. The corrected runs are
separate captures. The initial unsupported version-flag probe is also retained.
No failed execution is rewritten as a successful one.

## Scope and retained evidence

This is a targeted intermediate campaign. It does not reproduce the reporter's
exact machine, the complete private hardening reference or every historical
upgrade chain since v3. Geo/ASN was temporarily disabled with approval to isolate
WireGuard and was restored afterward. The controlled archive failure is not a
power-loss or process-kill durability test.

Operator configuration and lists were explicitly restored from private backups
after native purge. The campaign does not claim automatic retention across
purge. The attested candidate CLI invoked the protected qualification updater;
it was not the installed older production updater. Delivery of the recovery
command to an already blocked older installation is documented in the
[recovery runbook](../technical/WIREGUARD_LEGACY_RECOVERY.md).

The original v4.10.0 protected IVV report remains historical support under
product `8c3405758a9b369924f466d12652e99d3a84dc56`, producer
`3cc06b62d42b5adadc46fc9a252fece5adf670c1`, run `36853355288` and artifact
`11156960777`. Current package assembly, transaction regressions, product CI,
source review and signature verification support the selected unchanged paths.
No fresh all-platform native lifecycle, HA endurance or broad performance result
is claimed, and no historical verdict is transferred to v4.10.2.

## Protected acceptance and publication

The main-only producer runs in the owner-reviewed
`syswarden-release-qualification` environment. It verifies the private evidence
graph, exact native payload, restored baseline, all five product CI checks and
all five publication CI checks. It freshly verifies both RPM signatures, the
APK signature and detached DEB signature under the publishing policy, together
with updater provenance, Ed25519 manifest, original binary attestation and SBOM.

Private captures, configurations, operational identifiers and test credentials
stay outside the public artifact. The public report contains bounded assertions,
opaque digests and original product identities. It can set
`intermediate_release_validated=true` only after all required checks pass, while
keeping `full_qualification_passed=false` and `publication_authorized=false`.

The coordinator, staging job and privileged publisher independently select and
authenticate this exact versioned producer and its immutable report. The signed
tag, production environment approval, Sigstore release attestation and final
downloaded public-asset verification remain mandatory.

Private draft validation discovers a unique matching release through the
[GitHub release inventory](https://docs.github.com/en/rest/releases/releases#list-releases),
then reads that numeric release ID and downloads exact numeric asset IDs. It
retains the original notes, complete asset digest checks, provenance checks and
before/after snapshot equality. Immediately before publication, the publisher
rechecks the same release ID and snapshot. Failure keeps the draft private.
Public documentation is maintained at [syswarden.io/docs](https://syswarden.io/docs/).
