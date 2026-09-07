# HA v2 native qualification candidate

Status: implemented evidence gate, not qualified.

The v4.10.0 release requires a real two-node AMD64 campaign before it may claim
HA v2 qualification. Unit tests, simulated clocks, fake sockets and generated
JSON are development evidence only and cannot satisfy this gate.

The frozen machine-readable contract is
`scripts/ci/ha_v2_native_contract_v4.10.0.json`. Each campaign is bound to one
full candidate SHA, release tag, repository, cluster identity and epoch. It
requires exactly one static writer and one static standby with distinct node,
certificate, boot and instance-lease identities.

Both nodes must attest TLS 1.3 mutual authentication and the exact peer,
cluster and epoch identity. The campaign must capture raw, digest-bound
observations for normal replication, acknowledgement and checkpoints;
heartbeat timeout measured from monotonic receipt time; symmetric and
asymmetric partitions; durable split-brain fencing; explicit rejoin; WAL and
head-journal crash recovery completed by one restart; instance-lease exclusion;
and rolling upgrade and rollback.

The evidence document must be signed through a supported external attestation
mechanism. The release-owner gate verifies that attestation before recording
`verification_status` as `verified`. The validator does not create an
attestation and does not turn self-authored observations into native evidence.

In the official v4.10.0 chain, the protected native-evidence workflow attests
`NATIVE_RELEASE_EVIDENCE_MANIFEST.json` with
`actions/attest-build-provenance` pinned at commit
`4d101475d8b20a2381f78447822ac1eab6504dd8`. Release qualification then runs
`gh attestation verify` against the exact repository before accepting the
manifest. The internal file seal and GitHub artifact digest are required
integrity bindings, but neither substitutes for that provenance attestation.

Run the validator only after the protected artifact and its attestation have
been independently verified:

```console
python3 scripts/ci/ha_v2_native_evidence.py \
  --bundle /path/to/verified-ha-v2-artifact \
  --evidence HA_V2_NATIVE_EVIDENCE.json \
  --candidate-sha FULL_40_CHARACTER_SHA \
  --release-tag v4.10.0 \
  --output HA_V2_NATIVE_VERDICT.json
```

Any missing, duplicate, synthetic, unsigned, cross-candidate or ambiguous
observation fails closed. A passing validator verdict is one required release
input. It is not by itself a release or support claim.

## Protected pre-stage layout

The protected producer reads no operator-selected path. Before its manual
dispatch, the release owner stages the real observations under this exact
runner-local directory:

```text
/var/lib/syswarden/native-release-evidence/FULL_40_CHARACTER_SHA/
  ha-v2/HA_V2_NATIVE_EVIDENCE.json
  ha-v2/raw/node01-attestation.json
  ha-v2/raw/node02-attestation.json
  ha-v2/raw/SCENARIO_ID.json
  native-capability/DEB-13.json
  native-capability/DEB-U2604.json
  native-capability/RPM-A10.json
  native-capability/APK-324.json
  native-capability/RPM-A9-RHELPO.json
  native-capability/RPM-A10-RHELPO.json
  native-lifecycle/node05-almalinux9.8-rhelpo.json
  native-lifecycle/node03-almalinux10.2-rhelpo.json
  native-signing/rhel-package-owned/
  performance/EVIDENCE.json
```

`SCENARIO_ID.json` represents each of the ten scenario identifiers in the
contract. The root and child directories must be owned by the runner account
with mode `0700`. Every input must be a singly linked, non-symlink regular file
owned by that account with mode `0600`. The producer revalidates HA v2, the
six-profile native capability aggregate and the performance gate before it
creates and attests one canonical manifest. Release qualification resolves and
downloads that exact run artifact by REST identity, reconstructs the manifest
inventory and repeats the validations.

The package-owned RHEL profile is part of the v4.10.0 candidate scope. Its
distinct `1.rhelpo` RPM and signing provenance are excluded from the standard
updater channel but included in the protected release inventory. Qualification
requires independent AlmaLinux 9 and AlmaLinux 10 campaigns, including offline
mock or chroot staging, first real boot and two subsequent reboots.
