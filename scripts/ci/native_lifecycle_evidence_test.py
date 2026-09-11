#!/usr/bin/env python3
"""Adversarial tests for the v4.10.0 native lifecycle evidence."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

try:
    from scripts.ci import native_lifecycle_bundle_verify as bundle_verify
    from scripts.ci import native_lifecycle_evidence as evidence
except ModuleNotFoundError:
    import native_lifecycle_bundle_verify as bundle_verify
    import native_lifecycle_evidence as evidence


class NativeLifecycleEvidenceTests(unittest.TestCase):
    candidate = "a" * 40
    rpm_signer = "A" * 40
    deb_signer = "D" * 40
    apk_key = "e" * 64
    rpm_package_sha256 = "e" * 64
    rpm_package_size = 11_111_111
    rhel_rpm_package_sha256 = "7" * 64
    rhel_rpm_package_size = 11_222_222
    deb_package_sha256 = "c" * 64
    deb_package_size = 12_345_678
    apk_package_sha256 = "9" * 64
    apk_package_size = 9_876_543
    node02_ssh = "SHA256:" + "A" * 43
    node04_ssh = "SHA256:" + "B" * 43
    node05_ssh = "SHA256:" + "C" * 43
    node03_ssh = "SHA256:" + "D" * 43
    validation_time = dt.datetime(2026, 9, 10, 10, 0, tzinfo=dt.timezone.utc)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.contract, self.contract_sha256 = evidence.load_contract()
        self.records: dict[str, str] = {}
        self.observations = [
            self.make_observation(profile) for profile in self.contract["profiles"]
        ]
        self.paths = [
            self.write_json(
                self.root / f"observation-{index}.json", observation
            )
            for index, observation in enumerate(self.observations)
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> Path:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def raw(
        self,
        profile_id: str,
        name: str,
        payload: dict[str, object] | None = None,
    ) -> tuple[str, str]:
        reference = f"{profile_id}/raw/{name}.json"
        path = self.artifacts / reference
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.write_json(
            path,
            payload
            or {
                "capture": name,
                "origin": "real-native-host",
                "profile_id": profile_id,
                "nonce": len(self.records) + 1,
            },
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in self.records.values():
            raise AssertionError("fixture raw evidence digest collision")
        self.records[reference] = digest
        return reference, digest

    def attach(
        self,
        value: dict[str, object],
        profile_id: str,
        name: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        reference, digest = self.raw(profile_id, name, payload)
        value["evidence_ref"] = reference
        value["evidence_sha256"] = digest

    def package(self, profile: dict[str, object], release: str, index: int) -> dict[str, object]:
        profile_id = str(profile["id"])
        candidate = release == evidence.TARGET_RELEASE
        signer = {
            "DEB-U2604": self.deb_signer,
            "RPM-A9": self.rpm_signer,
            "APK-324": self.apk_key,
            "RPM-A9-RHELPO": self.rpm_signer,
            "RPM-A10-RHELPO": self.rpm_signer,
        }[profile_id]
        baseline = evidence.BASELINE_TRUST["baseline_packages"][
            str(profile["package_family"])
        ]
        candidate_record = {
            "DEB-U2604": (self.deb_package_sha256, self.deb_package_size),
            "RPM-A9": (self.rpm_package_sha256, self.rpm_package_size),
            "APK-324": (self.apk_package_sha256, self.apk_package_size),
            "RPM-A9-RHELPO": (
                self.rhel_rpm_package_sha256,
                self.rhel_rpm_package_size,
            ),
            "RPM-A10-RHELPO": (
                self.rhel_rpm_package_sha256,
                self.rhel_rpm_package_size,
            ),
        }[profile_id]
        package_sha256 = candidate_record[0] if candidate else baseline["sha256"]
        package_size = candidate_record[1] if candidate else baseline["size"]
        proof_sha256 = hashlib.sha256(
            f"{profile_id}:{release}:verification-proof".encode("utf-8")
        ).hexdigest()
        item: dict[str, object] = {
            "release_tag": release,
            "producer_commit": self.candidate if candidate else evidence.BASELINE_COMMIT,
            "filename": evidence.PACKAGE_NAMES[(profile_id, release)],
            "package_sha256": package_sha256,
            "package_size": package_size,
            "package_role": (
                str(profile["package_variant"]) if candidate else "standard"
            ),
            "origin": "protected-native-signing-artifact" if candidate else "github-release-v4.04.3",
            "digest_source": "native-signing-provenance" if candidate else "release-sha256sums",
            "release_asset_digest_verified": True,
            "verification_mechanism": (
                str(profile["candidate_signature_mechanism"])
                if candidate
                else "release-sha256sums"
            ),
            "verification_identity": signer if candidate else "github-release-v4.04.3",
            "verification_proof_sha256": proof_sha256,
            "native_signature_verified": candidate,
            "package_payload_verified": True,
            "verified_before_install": True,
        }
        if candidate:
            item["signing_provenance_profile"] = (
                evidence.RHEL_PACKAGE_OWNED_SIGNING_PROFILE
                if profile["package_variant"] == "rhel-package-owned"
                else evidence.STANDARD_SIGNING_PROFILE
            )
            item["updater_manifest_included"] = (
                profile["package_variant"] == "standard"
            )
        else:
            tag_signature = evidence.BASELINE_TRUST["baseline_tag_signature"]
            item.update(
                {
                    "release_id": evidence.BASELINE_TRUST["baseline_release_id"],
                    "release_asset_id": baseline["id"],
                    "checksum_asset_sha256": evidence.BASELINE_TRUST[
                        "baseline_checksum_asset"
                    ]["sha256"],
                    "release_tag_object": evidence.BASELINE_TRUST[
                        "baseline_tag_object"
                    ],
                    "release_tag_signature_mechanism": tag_signature["mechanism"],
                    "release_tag_signature_payload_sha256": tag_signature[
                        "payload_sha256"
                    ],
                    "release_tag_signature_sha256": tag_signature["signature_sha256"],
                    "release_tag_signature_verified": True,
                    "release_tag_signature_verified_at": tag_signature["verified_at"],
                }
            )
        self.attach(item, profile_id, f"package-{index + 1}")
        return item

    def checkpoint(
        self,
        profile: dict[str, object],
        obligation: dict[str, object],
        index: int,
    ) -> dict[str, object]:
        profile_id = str(profile["id"])
        version = str(obligation["version"])
        absent = version == "absent"
        baseline_package = evidence.BASELINE_TRUST["baseline_packages"][
            str(profile["package_family"])
        ]["sha256"]
        candidate_package = {
            "DEB-U2604": self.deb_package_sha256,
            "RPM-A9": self.rpm_package_sha256,
            "APK-324": self.apk_package_sha256,
            "RPM-A9-RHELPO": self.rhel_rpm_package_sha256,
            "RPM-A10-RHELPO": self.rhel_rpm_package_sha256,
        }[profile_id]
        boot_generation = 1 if index < 6 else 2 if index == 6 else 3
        boot = hashlib.sha256(
            f"{profile_id}:boot:{boot_generation}".encode("utf-8")
        ).hexdigest()
        if profile["installation_mode"] == "offline-chroot-first-boot" and index == 0:
            boot = "not-applicable"
        preserved = str(obligation["id"]) in {
            "candidate-configured",
            "stable-v4043-configured",
            "candidate-v4100-upgraded",
            "candidate-v4100-reboot1",
            "candidate-v4100-reboot2",
            "stable-v4043-rollback",
            "candidate-v4100-reupgraded",
            "candidate-v4100-recovered",
        }
        item: dict[str, object] = {
            "id": obligation["id"],
            "sequence": obligation["sequence"],
            "observed_at": f"2026-09-10T08:00:{index + 1:02d}Z",
            "installed_version": version,
            "installed_commit": (
                "absent"
                if absent
                else evidence.BASELINE_COMMIT
                if version == evidence.BASELINE_RELEASE
                else self.candidate
            ),
            "installed_package_sha256": (
                "absent"
                if absent
                else baseline_package
                if version == evidence.BASELINE_RELEASE
                else candidate_package
            ),
            "boot_id_sha256": boot,
            "configuration_semantic_sha256": (
                "absent" if absent else "6" * 64 if preserved else "8" * 64
            ),
            "operator_state_canary_sha256": "4" * 64,
            "persistent_state_canary_sha256": (
                "absent" if absent else "7" * 64 if preserved else "9" * 64
            ),
            "third_party_firewall_sha256": "5" * 64,
            "syswarden_firewall_sha256": (
                "absent" if absent else "a" * 64 if preserved else "b" * 64
            ),
            "core_service_state": obligation["service_state"],
            "firewall_service_state": obligation["service_state"],
            "package_manager_healthy": True,
            "package_database_consistent": True,
            "unexpected_owned_residue_count": 0,
        }
        self.attach(item, profile_id, f"checkpoint-{index + 1:02d}")
        return item

    def scenario(
        self,
        profile: dict[str, object],
        obligation: dict[str, object],
        packages: list[dict[str, object]],
        index: int,
    ) -> dict[str, object]:
        profile_id = str(profile["id"])
        package_by_release = {str(item["release_tag"]): item for item in packages}
        verifications = []
        for release in self.contract["scenario_package_verifications"][obligation["id"]]:
            package = package_by_release[release]
            verifications.append(
                {
                    "release_tag": release,
                    "package_sha256": package["package_sha256"],
                    "verification_identity": package["verification_identity"],
                    "verification_proof_sha256": package["verification_proof_sha256"],
                    "verified_before_install": True,
                }
            )
        item: dict[str, object] = {
            "id": obligation["id"],
            "sequence": obligation["sequence"],
            "status": "pass",
            "observed_at": f"2026-09-10T08:{index + 1:02d}:00Z",
            "from_checkpoint": obligation["from_checkpoint"],
            "to_checkpoint": obligation["to_checkpoint"],
            "checks": {
                name: True
                for name in (
                    list(obligation["required_checks"])
                    + self.contract["profile_scenario_checks"]
                    .get(profile_id, {})
                    .get(str(obligation["id"]), [])
                )
            },
            "package_verifications": verifications,
        }
        raw_payload = None
        if (
            profile["package_variant"] == "rhel-package-owned"
            and obligation["id"] == "verified-rollback-v4100-v4043"
        ):
            rollback_paths = self.contract[
                "rhel_package_owned_rollback_absence_paths"
            ]
            raw_payload = {
                "schema": evidence.RHEL_PACKAGE_OWNED_ROLLBACK_EVIDENCE_SCHEMA,
                "profile_id": profile_id,
                "scenario_id": "verified-rollback-v4100-v4043",
                "candidate_release": evidence.TARGET_RELEASE,
                "installed_release": evidence.BASELINE_RELEASE,
                "package_variant": "rhel-package-owned",
                "observation_origin": "real-native-host",
                "observed_at": item["observed_at"],
                "probe": "lstat-no-follow",
                "checked_path_count": len(rollback_paths),
                "present_path_count": 0,
                "path_inventory": [
                    {"path": path, "state": "absent", "errno": "ENOENT"}
                    for path in rollback_paths
                ],
                "standard_ordering_dropin": copy.deepcopy(evidence.STANDARD_ROLLBACK_ORDERING),
            }
        self.attach(
            item,
            profile_id,
            f"scenario-{index + 1:02d}",
            raw_payload,
        )
        return item

    def make_observation(self, profile: dict[str, object]) -> dict[str, object]:
        profile_id = str(profile["id"])
        packages = [
            self.package(profile, evidence.BASELINE_RELEASE, 0),
            self.package(profile, evidence.TARGET_RELEASE, 1),
        ]
        host: dict[str, object] = {
            "profile_id": profile_id,
            "host_id": profile["host_id"],
            "os_id": profile["os_id"],
            "os_version": profile["os_version"],
            "architecture": profile["architecture"] if "architecture" in profile else "amd64",
            "package_family": profile["package_family"],
            "package_variant": profile["package_variant"],
            "installation_mode": profile["installation_mode"],
            "package_manager": profile["package_manager"],
            "service_manager": profile["service_manager"],
            "firewall_backend": profile["firewall_backend"],
            "ssh_host_key_sha256": {
                "DEB-U2604": self.node02_ssh,
                "RPM-A9": self.node05_ssh,
                "APK-324": self.node04_ssh,
                "RPM-A9-RHELPO": self.node05_ssh,
                "RPM-A10-RHELPO": self.node03_ssh,
            }[profile_id],
            "instance_identity_sha256": hashlib.sha256(
                f"{profile_id}:instance".encode("utf-8")
            ).hexdigest(),
            "provider_firewall_policy_sha256": "0" * 64,
            "provider_firewall_default_policy": "drop",
            "ssh_allowlist_verified": True,
            "candidate_commit": self.candidate,
        }
        self.attach(host, profile_id, "host-attestation")
        checkpoints = [
            self.checkpoint(profile, obligation, index)
            for index, obligation in enumerate(self.contract["checkpoints"])
        ]
        scenarios = [
            self.scenario(profile, obligation, packages, index)
            for index, obligation in enumerate(self.contract["scenarios"])
        ]
        final_state: dict[str, object] = {
            "checkpoint_id": "final-purged",
            "package_records": 0,
            "service_units": 0,
            "running_processes": 0,
            "firewall_objects": 0,
            "dedicated_paths": 0,
            "dedicated_users_groups": 0,
            "scheduled_jobs": 0,
            "residue_count": 0,
            "verified_paths": self.contract["zero_residue_paths"],
            "operator_state_canary_sha256": checkpoints[-1]["operator_state_canary_sha256"],
            "third_party_firewall_sha256": checkpoints[-1]["third_party_firewall_sha256"],
        }
        self.attach(final_state, profile_id, "final-state")
        profile_records = {
            reference: digest
            for reference, digest in self.records.items()
            if reference.startswith(f"{profile_id}/")
        }
        attestation: dict[str, object] = {
            "mechanism": "github-artifact-attestation",
            "statement_sha256": hashlib.sha256(
                f"{profile_id}:attestation-statement".encode("utf-8")
            ).hexdigest(),
            "signature_sha256": hashlib.sha256(
                f"{profile_id}:attestation-signature".encode("utf-8")
            ).hexdigest(),
            "signer_identity": "github:duggytuxy/syswarden/native-release-evidence",
            "verification_status": "verified",
            "verified_by": "release-owner-gate",
            "attested_profile_id": profile_id,
            "attested_candidate_commit": self.candidate,
            "attested_contract_sha256": self.contract_sha256,
            "attested_evidence_inventory_sha256": evidence._inventory_sha256(profile_records),
        }
        self.attach(attestation, profile_id, "final-attestation")
        return {
            "schema": evidence.OBSERVATION_SCHEMA,
            "repository": evidence.REPOSITORY,
            "target_release": evidence.TARGET_RELEASE,
            "candidate_commit": self.candidate,
            "contract_sha256": self.contract_sha256,
            "qualification_state": "candidate-not-qualified",
            "publishing": False,
            "campaign": {
                "id": f"{profile_id.lower()}-native-lifecycle",
                "started_at": "2026-09-10T08:00:00Z",
                "completed_at": "2026-09-10T09:00:00Z",
                "operator_identity": "syswarden-release-operator",
                "observation_origin": "real-native-host",
                "synthetic": False,
                "network_boundary": "provider-firewall-default-drop",
                "snapshot_reference": f"{profile_id.lower()}-pre-v4100",
            },
            "host": host,
            "packages": packages,
            "checkpoints": checkpoints,
            "scenarios": scenarios,
            "final_state": final_state,
            "attestation": attestation,
        }

    def assemble(self, paths: list[Path] | None = None) -> dict[str, object]:
        return evidence.assemble(
            self.candidate,
            paths or self.paths,
            self.artifacts,
            rpm_signer_fingerprint=self.rpm_signer,
            deb_signer_fingerprint=self.deb_signer,
            apk_public_key_sha256=self.apk_key,
            rpm_package_name=evidence.PACKAGE_NAMES[
                ("RPM-A9", evidence.TARGET_RELEASE)
            ],
            rpm_package_sha256=self.rpm_package_sha256,
            rpm_package_size=self.rpm_package_size,
            rhel_rpm_package_name=evidence.PACKAGE_NAMES[
                ("RPM-A9-RHELPO", evidence.TARGET_RELEASE)
            ],
            rhel_rpm_package_sha256=self.rhel_rpm_package_sha256,
            rhel_rpm_package_size=self.rhel_rpm_package_size,
            deb_package_name=evidence.PACKAGE_NAMES[
                ("DEB-U2604", evidence.TARGET_RELEASE)
            ],
            deb_package_sha256=self.deb_package_sha256,
            deb_package_size=self.deb_package_size,
            apk_package_name=evidence.PACKAGE_NAMES[
                ("APK-324", evidence.TARGET_RELEASE)
            ],
            apk_package_sha256=self.apk_package_sha256,
            apk_package_size=self.apk_package_size,
            node02_ssh_host_key_sha256=self.node02_ssh,
            node04_ssh_host_key_sha256=self.node04_ssh,
            node05_ssh_host_key_sha256=self.node05_ssh,
            node03_ssh_host_key_sha256=self.node03_ssh,
            validation_time=self.validation_time,
        )

    def rewrite(self, index: int, document: dict[str, object]) -> list[Path]:
        self.write_json(self.paths[index], document)
        return self.paths

    def assert_invalid(self, paths: list[Path] | None = None, message: str | None = None) -> None:
        with self.assertRaises(evidence.LifecycleEvidenceError) as caught:
            self.assemble(paths)
        if message:
            self.assertIn(message, str(caught.exception))

    def signing_evidence(
        self,
    ) -> tuple[Path, dict[str, object], dict[str, dict[str, object]]]:
        signing_root = self.root / "signing-evidence"
        signing_root.mkdir(mode=0o700)
        package_names = bundle_verify.native_package_signing_bundle.package_names(
            evidence.TARGET_RELEASE
        )
        signed = [
            {
                "name": package_names["rpm"],
                "sha256": self.rpm_package_sha256,
                "size": self.rpm_package_size,
            },
            {
                "name": package_names["deb"],
                "sha256": self.deb_package_sha256,
                "size": self.deb_package_size,
            },
            {
                "name": package_names["apk"],
                "sha256": self.apk_package_sha256,
                "size": self.apk_package_size,
            },
        ]
        rpm_key = {
            "fingerprint": self.rpm_signer,
            "id": "rpm-2026",
            "public_key": "native-package-keys/rpm-2026.asc",
            "public_key_sha256": "5" * 64,
        }
        deb_key = {
            "fingerprint": self.deb_signer,
            "id": "deb-2026",
            "public_key": "native-package-keys/deb-2026.asc",
            "public_key_sha256": "6" * 64,
        }
        apk_key = {
            "fingerprint": self.apk_key,
            "id": "apk-2026",
            "public_key": "native-package-keys/apk-2026.rsa.pub",
            "public_key_sha256": self.apk_key,
        }
        detached_signature = {
            "created_at": "2026-09-03T12:00:00Z",
            "name": package_names["deb"] + ".asc",
            "sha256": "3" * 64,
            "size": 512,
        }
        policy_sha256 = "4" * 64
        signing = bundle_verify.native_package_signing_bundle
        bootstrap = {
            "schema_version": 1,
            "profile": signing.BOOTSTRAP_REFERENCE_PROFILE,
            "repository": signing.BOOTSTRAP_REPOSITORY,
            "release_sha": signing.BOOTSTRAP_RELEASE_SHA,
            "policy_sha256": signing.FOUNDATION_POLICY_SHA256,
            "signing_run": {
                "attempt": 1,
                "id": signing.BOOTSTRAP_SIGNING_RUN_ID,
                "workflow": ".github/workflows/native-package-signing.yml",
                "workflow_sha": signing.BOOTSTRAP_RELEASE_SHA,
            },
            "artifact": {
                "digest": signing.BOOTSTRAP_SIGNED_ARTIFACT_DIGEST,
                "id": signing.BOOTSTRAP_SIGNED_ARTIFACT_ID,
                "name": signing.BOOTSTRAP_SIGNED_ARTIFACT_NAME,
                "size": signing.BOOTSTRAP_SIGNED_ARTIFACT_SIZE,
            },
        }
        provenance: dict[str, object] = {
            "bootstrap_qualification": bootstrap,
            "apk_signature": {
                "exact_unsigned_suffix": True,
                "key": apk_key,
                "signature_entry": ".SIGN.RSA256.apk-2026.rsa.pub",
                "signature_prefix_sha256": "1" * 64,
                "signature_prefix_size": 1024,
                "signature_sha256": "2" * 64,
            },
            "deb_signature": {
                "bytes_unchanged": True,
                "detached": True,
                "key": deb_key,
                "signature": detached_signature,
            },
            "packages": {
                "signed": signed,
                "unsigned": [
                    {**record, "sha256": str(index) * 64}
                    for index, record in enumerate(signed, start=1)
                ],
            },
            "policy_sha256": policy_sha256,
            "profile": bundle_verify.native_package_signing_bundle.SCHEMA_PROFILE,
            "public_release": False,
            "release_qualified": False,
            "repository": "duggytuxy/syswarden",
            "rpm_signature": {
                "immutable_header_preserved": True,
                "key": rpm_key,
                "payload_preserved": True,
            },
            "schema_version": 1,
            "signer_image": (
                "registry.example/syswarden/apk-signer@sha256:" + "5" * 64
            ),
            "signing_run": {
                "attempt": 1,
                "id": 300,
                "workflow": ".github/workflows/native-package-signing.yml",
                "workflow_sha": self.candidate,
            },
            "source": {
                "release_sha": self.candidate,
                "release_tag": evidence.TARGET_RELEASE,
                "source_date_epoch": 1780000000,
                "unsigned_artifact_digest": "sha256:" + "8" * 64,
                "unsigned_artifact_id": 200,
                "unsigned_artifact_name": "syswarden-packages-4.10.0",
                "unsigned_package_run_id": 100,
            },
            "status": (
                bundle_verify.native_package_signing_bundle.QUALIFIED_PROVENANCE_STATUS
            ),
        }
        verifications: dict[str, dict[str, object]] = {}
        mechanisms = {
            "rpm": "rpm-openpgp",
            "deb": "openpgp-detached",
            "apk": "apk-rsa256",
        }
        for family, key in (("rpm", rpm_key), ("deb", deb_key), ("apk", apk_key)):
            verification: dict[str, object] = {
                "as_of": "2026-09-03",
                "family": family,
                "key": copy.deepcopy(key),
                "mechanism": mechanisms[family],
                "package": copy.deepcopy(
                    next(
                        record
                        for record in signed
                        if record["name"] == package_names[family]
                    )
                ),
                "policy_sha256": policy_sha256,
                "profile": (
                    bundle_verify.native_package_signing_bundle.VERIFICATION_PROFILE
                ),
                "purpose": "qualification",
                "release": evidence.TARGET_RELEASE,
                "schema_version": 1,
                "status": "verified",
            }
            if family == "deb":
                verification["signature"] = copy.deepcopy(detached_signature)
            verifications[family] = verification
            self.write_json(
                signing_root / f"{family.upper()}_NATIVE_VERIFICATION.json",
                verification,
            )
        self.write_json(
            signing_root / "NATIVE_SIGNING_PROVENANCE.json", provenance
        )
        rhel_evidence_root = (
            signing_root.parent
            / bundle_verify.native_package_signing_bundle.RHEL_PACKAGE_OWNED_DIRECTORY
            / "evidence"
        )
        rhel_evidence_root.mkdir(parents=True, mode=0o700)
        rhel_package = {
            "name": evidence.PACKAGE_NAMES[
                ("RPM-A9-RHELPO", evidence.TARGET_RELEASE)
            ],
            "sha256": self.rhel_rpm_package_sha256,
            "size": self.rhel_rpm_package_size,
        }
        rhel_verification = {
            "as_of": "2026-09-03",
            "family": "rpm",
            "key": copy.deepcopy(rpm_key),
            "mechanism": "rpm-openpgp",
            "package": copy.deepcopy(rhel_package),
            "policy_sha256": policy_sha256,
            "profile": bundle_verify.native_package_signing_bundle.VERIFICATION_PROFILE,
            "purpose": "qualification",
            "release": evidence.TARGET_RELEASE,
            "schema_version": 1,
            "status": "verified",
        }
        rhel_provenance = {
            "bootstrap_qualification": copy.deepcopy(bootstrap),
            "package_role": "rhel-package-owned",
            "packages": {
                "signed": copy.deepcopy(rhel_package),
                "unsigned": {
                    **rhel_package,
                    "sha256": "0" * 64,
                    "size": self.rhel_rpm_package_size - 1,
                },
            },
            "policy_sha256": policy_sha256,
            "profile": (
                bundle_verify.native_package_signing_bundle.RHEL_PACKAGE_OWNED_PROFILE
            ),
            "public_release": False,
            "release_qualified": False,
            "repository": "duggytuxy/syswarden",
            "rpm_identity": {
                "architecture": "x86_64",
                "filename": rhel_package["name"],
                "name": "syswarden",
                "release": "1.rhelpo",
                "version": "4.10.0",
            },
            "rpm_signature": {
                "immutable_header_preserved": True,
                "key": copy.deepcopy(rpm_key),
                "payload_preserved": True,
            },
            "schema_version": 1,
            "signing_run": copy.deepcopy(provenance["signing_run"]),
            "source": {
                "release_sha": self.candidate,
                "release_tag": evidence.TARGET_RELEASE,
                "source_date_epoch": 1780000000,
                "unsigned_artifact_digest": "sha256:" + "9" * 64,
                "unsigned_artifact_id": 201,
                "unsigned_artifact_name": "syswarden-rhel-package-owned-4.10.0",
                "unsigned_package_run_id": 100,
            },
            "status": (
                bundle_verify.native_package_signing_bundle.QUALIFIED_PROVENANCE_STATUS
            ),
            "updater_manifest_included": False,
        }
        self.write_json(
            rhel_evidence_root / "RPM_NATIVE_VERIFICATION.json",
            rhel_verification,
        )
        self.write_json(
            rhel_evidence_root / "SIGNING_PROVENANCE.json",
            rhel_provenance,
        )
        return signing_root, provenance, verifications

    def test_valid_profile_set_passes_without_qualifying_or_publishing(self) -> None:
        result = self.assemble()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["profile_count"], 5)
        self.assertEqual(result["raw_evidence_count"], 145)
        self.assertEqual(result["qualification_state"], "candidate-not-qualified")
        self.assertIs(result["publishing"], False)
        self.assertEqual(
            [item["host"]["profile_id"] for item in result["profiles"]],
            [
                "APK-324",
                "DEB-U2604",
                "RPM-A10-RHELPO",
                "RPM-A9",
                "RPM-A9-RHELPO",
            ],
        )

    def test_contract_digest_and_closed_scope_are_pinned(self) -> None:
        self.assertEqual(evidence.contract_digest(), evidence.CONTRACT_SHA256)
        self.assertEqual(self.contract["qualification_state"], "candidate-not-qualified")
        self.assertIs(self.contract["publishing"], False)
        self.assertEqual(self.contract["architecture"], "amd64")
        self.assertEqual(
            [profile["host_id"] for profile in self.contract["profiles"]],
            ["node02", "node05", "node04", "node05", "node03"],
        )
        changed = self.root / "contract.json"
        changed.write_bytes(evidence.DEFAULT_CONTRACT.read_bytes() + b"\n")
        with self.assertRaisesRegex(evidence.LifecycleEvidenceError, "reviewed"):
            evidence.load_contract(changed)

    def test_rhel_package_owned_payload_and_transition_proofs_are_mandatory(self) -> None:
        vendor_paths = {
            "/var/lib/syswarden/removal-in-progress-v1.new",
            "/var/lib/.syswarden-removal-finalizing-v1.new",
            "/var/lib/.syswarden-rhelpo-erase-ready-v1",
            "/var/lib/.syswarden-rhelpo-erase-ready-v1.new",
            "/var/lib/.syswarden-rhelpo-preset-pending-v1",
            "/var/lib/.syswarden-rhelpo-preset-pending-v1.new",
            "/var/lib/.syswarden-rhelpo-postun-recovery-v1",
            "/var/lib/.syswarden-rhelpo-postun-recovery-v1.new",
            "/usr/lib/systemd/system/syswarden-core.service",
            "/usr/lib/systemd/system/syswarden-firewall.service",
            "/usr/lib/systemd/system/syswarden-firewall.service.d",
            "/usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf",
            "/usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset",
            "/usr/libexec/syswarden/rhelpo-postun-recovery-v1",
            "/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration",
            "/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration",
        }
        self.assertTrue(
            vendor_paths.issubset(set(self.contract["zero_residue_paths"]))
        )
        for profile_id in ("RPM-A9-RHELPO", "RPM-A10-RHELPO"):
            checks = self.contract["profile_scenario_checks"][profile_id]
            self.assertEqual(
                set(checks["candidate-upgrade-v4043-v4100"]),
                {
                    "legacy_systemd_units_migrated",
                    "package_owned_units_authoritative",
                    "package_owned_profile_attested",
                },
            )
            self.assertEqual(
                set(checks["candidate-reupgrade-v4043-v4100"]),
                set(checks["candidate-upgrade-v4043-v4100"]),
            )
            self.assertEqual(
                set(checks["verified-rollback-v4100-v4043"]),
                {
                    "standard_systemd_units_authoritative",
                    "package_owned_vendor_payload_absent",
                    "standard_ordering_dropin_owned_and_intact",
                },
            )
            for scenario_id in (
                "clean-cycle-uninstall-purge",
                "candidate-final-uninstall-purge",
            ):
                self.assertEqual(
                    set(checks[scenario_id]),
                    {
                        "package_owned_units_removed",
                        "package_owned_dropin_removed",
                        "package_owned_preset_removed",
                        "package_owned_profile_removed",
                        "package_owned_enablement_removed",
                        "erase_ready_boundary_consumed",
                    },
                )

    def test_rhel_rollback_vendor_absence_raw_proof_is_exact(self) -> None:
        scenario_index = 8
        for profile_index in (3, 4):
            observation = self.observations[profile_index]
            scenario = observation["scenarios"][scenario_index]
            reference = scenario["evidence_ref"]
            raw_path = self.artifacts / reference
            original = raw_path.read_bytes()
            raw_document = json.loads(original)
            self.assertEqual(
                [item["path"] for item in raw_document["path_inventory"]],
                self.contract["rhel_package_owned_rollback_absence_paths"],
            )
            self.assertEqual(raw_document["present_path_count"], 0)

            mutations = (
                (
                    "missing standard ordering payload",
                    lambda value: value.pop("standard_ordering_dropin"),
                    "keys are not exact",
                ),
                (
                    "wrong standard ordering digest",
                    lambda value: value["standard_ordering_dropin"]["file"].update({"sha256": "0" * 64}),
                    "ordering payload",
                ),
                (
                    "wrong standard package owner",
                    lambda value: value["standard_ordering_dropin"]["file"].update({"rpm_owner": "syswarden-4.10.0-1.rhelpo.x86_64"}),
                    "ordering payload",
                ),
                (
                    "unsafe standard ordering directory",
                    lambda value: value["standard_ordering_dropin"]["directory"].update({"type": "symlink"}),
                    "ordering payload",
                ),
                (
                    "boolean standard file owner",
                    lambda value: value["standard_ordering_dropin"]["file"].update({"uid": False}),
                    "ordering payload",
                ),
                (
                    "present vendor path",
                    lambda value: value["path_inventory"][0].update(
                        {"state": "present", "errno": "NONE"}
                    ),
                    "vendor payload remains",
                ),
                (
                    "missing vendor path",
                    lambda value: value["path_inventory"].pop(),
                    "path inventory is not exact",
                ),
                (
                    "extra vendor path",
                    lambda value: value["path_inventory"].append(
                        {
                            "path": "/usr/lib/systemd/system/unexpected.service",
                            "state": "absent",
                            "errno": "ENOENT",
                        }
                    ),
                    "path inventory is not exact",
                ),
                (
                    "reordered vendor paths",
                    lambda value: value["path_inventory"].reverse(),
                    "path inventory is not exact",
                ),
                (
                    "wrong profile binding",
                    lambda value: value.update({"profile_id": "RPM-A9"}),
                    "identity is invalid",
                ),
                (
                    "wrong installed release",
                    lambda value: value.update({"installed_release": "v4.04.2"}),
                    "identity is invalid",
                ),
                (
                    "boolean present count",
                    lambda value: value.update({"present_path_count": False}),
                    "identity is invalid",
                ),
                (
                    "wrong scenario time",
                    lambda value: value.update(
                        {"observed_at": "2026-09-10T08:10:01Z"}
                    ),
                    "identity is invalid",
                ),
            )
            for label, mutate, message in mutations:
                with self.subTest(profile=profile_index, mutation=label):
                    changed = copy.deepcopy(observation)
                    changed_raw = copy.deepcopy(raw_document)
                    mutate(changed_raw)
                    self.write_json(raw_path, changed_raw)
                    changed["scenarios"][scenario_index]["evidence_sha256"] = (
                        hashlib.sha256(raw_path.read_bytes()).hexdigest()
                    )
                    self.assert_invalid(
                        self.rewrite(profile_index, changed), message
                    )
                    raw_path.write_bytes(original)
                    self.write_json(self.paths[profile_index], observation)

    def test_observation_cannot_self_qualify_or_enable_publication(self) -> None:
        for key, value in (
            ("qualification_state", "qualified"),
            ("publishing", True),
            ("target_release", "v4.10.1"),
            ("candidate_commit", "0" * 40),
            ("contract_sha256", "0" * 64),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[0])
                changed[key] = value
                self.assert_invalid(self.rewrite(0, changed), "identity")
                self.write_json(self.paths[0], self.observations[0])

    def test_exact_profiles_real_origin_and_candidate_binding_are_required(self) -> None:
        mutations = (
            ("profile_id", "DEB-13"),
            ("host_id", "NODE03"),
            ("os_id", "debian"),
            ("os_version", "24.04"),
            ("architecture", "arm64"),
            ("package_family", "rpm"),
            ("package_manager", "apt"),
            ("service_manager", "openrc"),
            ("firewall_backend", "firewalld"),
            ("candidate_commit", "0" * 40),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[0])
                changed["host"][key] = value
                self.assert_invalid(self.rewrite(0, changed))
                self.write_json(self.paths[0], self.observations[0])
        for key, value in (
            ("synthetic", True),
            ("observation_origin", "container-lab"),
            ("network_boundary", "uncontrolled"),
        ):
            with self.subTest(campaign=key):
                changed = copy.deepcopy(self.observations[0])
                changed["campaign"][key] = value
                self.assert_invalid(self.rewrite(0, changed), "non-native")
                self.write_json(self.paths[0], self.observations[0])

    def test_operator_pinned_ssh_keys_and_provider_firewall_fail_closed(self) -> None:
        with self.assertRaisesRegex(evidence.LifecycleEvidenceError, "operator pin"):
            evidence.assemble(
                self.candidate,
                self.paths,
                self.artifacts,
                rpm_signer_fingerprint=self.rpm_signer,
                deb_signer_fingerprint=self.deb_signer,
                apk_public_key_sha256=self.apk_key,
                rpm_package_name=evidence.PACKAGE_NAMES[
                    ("RPM-A9", evidence.TARGET_RELEASE)
                ],
                rpm_package_sha256=self.rpm_package_sha256,
                rpm_package_size=self.rpm_package_size,
                rhel_rpm_package_name=evidence.PACKAGE_NAMES[
                    ("RPM-A9-RHELPO", evidence.TARGET_RELEASE)
                ],
                rhel_rpm_package_sha256=self.rhel_rpm_package_sha256,
                rhel_rpm_package_size=self.rhel_rpm_package_size,
                deb_package_name=evidence.PACKAGE_NAMES[
                    ("DEB-U2604", evidence.TARGET_RELEASE)
                ],
                deb_package_sha256=self.deb_package_sha256,
                deb_package_size=self.deb_package_size,
                apk_package_name=evidence.PACKAGE_NAMES[
                    ("APK-324", evidence.TARGET_RELEASE)
                ],
                apk_package_sha256=self.apk_package_sha256,
                apk_package_size=self.apk_package_size,
                node02_ssh_host_key_sha256="SHA256:" + "Z" * 43,
                node04_ssh_host_key_sha256=self.node04_ssh,
                node05_ssh_host_key_sha256=self.node05_ssh,
                node03_ssh_host_key_sha256=self.node03_ssh,
                validation_time=self.validation_time,
            )
        for key, value in (
            ("provider_firewall_default_policy", "accept"),
            ("ssh_allowlist_verified", False),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[0])
                changed["host"][key] = value
                self.assert_invalid(self.rewrite(0, changed), "firewall boundary")
                self.write_json(self.paths[0], self.observations[0])

    def test_native_candidate_signatures_and_baseline_provenance_are_exact(self) -> None:
        for package_index, key, value in (
            (0, "origin", "mirror"),
            (0, "release_asset_digest_verified", False),
            (0, "native_signature_verified", True),
            (1, "origin", "local-file"),
            (1, "verification_mechanism", "checksum-only"),
            (1, "verification_identity", "0" * 40),
            (1, "native_signature_verified", False),
            (1, "package_payload_verified", False),
            (1, "verified_before_install", False),
        ):
            with self.subTest(package=package_index, key=key):
                changed = copy.deepcopy(self.observations[0])
                changed["packages"][package_index][key] = value
                self.assert_invalid(self.rewrite(0, changed))
                self.write_json(self.paths[0], self.observations[0])
        for profile_index, invalid_identity in ((1, "F" * 40), (2, "f" * 64)):
            changed = copy.deepcopy(self.observations[profile_index])
            changed["packages"][1]["verification_identity"] = invalid_identity
            self.assert_invalid(
                self.rewrite(profile_index, changed), "native package signature"
            )
            self.write_json(
                self.paths[profile_index], self.observations[profile_index]
            )
        changed = copy.deepcopy(self.observations[1])
        changed["packages"][1]["verification_mechanism"] = "openpgp-detached"
        self.assert_invalid(self.rewrite(1, changed), "native package signature")
        self.write_json(self.paths[1], self.observations[1])

    def test_baseline_release_package_checksum_and_tag_signature_are_exact(self) -> None:
        mutations = (
            ("filename", "syswarden-4.04.3-2.x86_64.rpm"),
            ("package_sha256", "f" * 64),
            ("package_size", 1),
            ("package_role", "rhel-package-owned"),
            ("producer_commit", "0" * 40),
            ("release_id", 1),
            ("release_asset_id", 1),
            ("checksum_asset_sha256", "f" * 64),
            ("release_tag_object", "0" * 40),
            ("release_tag_signature_mechanism", "gpg"),
            ("release_tag_signature_payload_sha256", "f" * 64),
            ("release_tag_signature_sha256", "f" * 64),
            ("release_tag_signature_verified", False),
            ("release_tag_signature_verified_at", "2026-09-07T11:10:47Z"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[3])
                changed["packages"][0][key] = value
                self.assert_invalid(self.rewrite(3, changed))
                self.write_json(self.paths[3], self.observations[3])

    def test_rhel_package_owned_profiles_cannot_reuse_standard_candidate_proof(self) -> None:
        for profile_index in (3, 4):
            with self.subTest(profile=profile_index):
                changed = copy.deepcopy(self.observations[profile_index])
                own_reference = changed["packages"][1]["evidence_ref"]
                own_digest = changed["packages"][1]["evidence_sha256"]
                changed["packages"][1] = copy.deepcopy(
                    self.observations[1]["packages"][1]
                )
                changed["packages"][1]["evidence_ref"] = own_reference
                changed["packages"][1]["evidence_sha256"] = own_digest
                self.assert_invalid(self.rewrite(profile_index, changed), "package")
                self.write_json(
                    self.paths[profile_index], self.observations[profile_index]
                )

        changed = copy.deepcopy(self.observations[3])
        changed["packages"][1]["verification_proof_sha256"] = self.observations[1][
            "packages"
        ][1]["verification_proof_sha256"]
        for scenario in changed["scenarios"]:
            for verification in scenario["package_verifications"]:
                if verification["release_tag"] == evidence.TARGET_RELEASE:
                    verification["verification_proof_sha256"] = changed["packages"][1][
                        "verification_proof_sha256"
                    ]
        self.assert_invalid(self.rewrite(3, changed), "proof is reused")

    def test_campaign_snapshot_instance_and_boot_namespaces_are_distinct(self) -> None:
        for field in ("id", "snapshot_reference"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.observations[3])
                changed["campaign"][field] = self.observations[1]["campaign"][field]
                self.assert_invalid(self.rewrite(3, changed), field.split("_")[0])
                self.write_json(self.paths[3], self.observations[3])
        changed = copy.deepcopy(self.observations[3])
        changed["host"]["instance_identity_sha256"] = self.observations[1]["host"][
            "instance_identity_sha256"
        ]
        self.assert_invalid(self.rewrite(3, changed), "instance")
        self.write_json(self.paths[3], self.observations[3])
        changed = copy.deepcopy(self.observations[3])
        for index, checkpoint in enumerate(changed["checkpoints"][1:], start=1):
            checkpoint["boot_id_sha256"] = self.observations[1]["checkpoints"][index][
                "boot_id_sha256"
            ]
        self.assert_invalid(self.rewrite(3, changed), "boot identities")

    def test_candidate_package_name_digest_and_size_are_bundle_bound(self) -> None:
        for profile_index, key, value in (
            (0, "filename", "syswarden_4.10.0_other.deb"),
            (0, "package_sha256", "f" * 64),
            (0, "package_size", self.deb_package_size + 1),
            (1, "filename", "syswarden-4.10.0-1.packageowned1.x86_64.rpm"),
            (1, "package_sha256", "f" * 64),
            (1, "package_size", self.rpm_package_size + 1),
            (2, "filename", "syswarden_4.10.0_other.apk"),
            (2, "package_sha256", "f" * 64),
            (2, "package_size", self.apk_package_size + 1),
        ):
            with self.subTest(profile=profile_index, key=key):
                changed = copy.deepcopy(self.observations[profile_index])
                changed["packages"][1][key] = value
                self.assert_invalid(
                    self.rewrite(profile_index, changed),
                    "package" if key == "filename" else "protected signing provenance",
                )
                self.write_json(
                    self.paths[profile_index], self.observations[profile_index]
                )

        with self.assertRaisesRegex(
            evidence.LifecycleEvidenceError, "protected signing provenance"
        ):
            evidence.assemble(
                self.candidate,
                self.paths,
                self.artifacts,
                rpm_signer_fingerprint=self.rpm_signer,
                deb_signer_fingerprint=self.deb_signer,
                apk_public_key_sha256=self.apk_key,
                rpm_package_name=evidence.PACKAGE_NAMES[
                    ("RPM-A9", evidence.TARGET_RELEASE)
                ],
                rpm_package_sha256=self.rpm_package_sha256,
                rpm_package_size=self.rpm_package_size,
                rhel_rpm_package_name=evidence.PACKAGE_NAMES[
                    ("RPM-A9-RHELPO", evidence.TARGET_RELEASE)
                ],
                rhel_rpm_package_sha256=self.rhel_rpm_package_sha256,
                rhel_rpm_package_size=self.rhel_rpm_package_size,
                deb_package_name=evidence.PACKAGE_NAMES[
                    ("DEB-U2604", evidence.TARGET_RELEASE)
                ],
                deb_package_sha256="f" * 64,
                deb_package_size=self.deb_package_size,
                apk_package_name=evidence.PACKAGE_NAMES[
                    ("APK-324", evidence.TARGET_RELEASE)
                ],
                apk_package_sha256=self.apk_package_sha256,
                apk_package_size=self.apk_package_size,
                node02_ssh_host_key_sha256=self.node02_ssh,
                node04_ssh_host_key_sha256=self.node04_ssh,
                node05_ssh_host_key_sha256=self.node05_ssh,
                node03_ssh_host_key_sha256=self.node03_ssh,
                validation_time=self.validation_time,
            )

    def test_bundle_revalidator_derives_one_provenance_identity(self) -> None:
        signing_root, provenance, _ = self.signing_evidence()
        (
            rpm_key,
            deb_key,
            apk_key,
            packages,
            rhel_package,
        ) = bundle_verify._validated_signing_inputs(signing_root, self.candidate)
        self.assertEqual(rpm_key, provenance["rpm_signature"]["key"])
        self.assertEqual(deb_key, provenance["deb_signature"]["key"])
        self.assertEqual(apk_key, provenance["apk_signature"]["key"])
        self.assertEqual(
            set(packages),
            set(
                bundle_verify.native_package_signing_bundle.package_names(
                    evidence.TARGET_RELEASE
                ).values()
            ),
        )
        self.assertEqual(
            rhel_package["name"],
            evidence.PACKAGE_NAMES[("RPM-A9-RHELPO", evidence.TARGET_RELEASE)],
        )

    def test_bundle_revalidator_requires_reviewed_bootstrap_for_each_package_role(self) -> None:
        signing_root, _, _ = self.signing_evidence()
        paths = (
            signing_root / "NATIVE_SIGNING_PROVENANCE.json",
            signing_root.parent / "rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
        )
        for path in paths:
            original = json.loads(path.read_text(encoding="utf-8"))
            mutations = []
            missing = copy.deepcopy(original)
            del missing["bootstrap_qualification"]
            mutations.append(missing)
            for key_path, value in (
                (("schema_version",), True),
                (("release_sha",), self.candidate),
                (("repository",), "other/repository"),
                (("policy_sha256",), "0" * 64),
                (("unexpected",), True),
                (("signing_run", "id"), 1),
                (("artifact", "digest"), "sha256:" + "0" * 64),
            ):
                changed = copy.deepcopy(original)
                target = changed["bootstrap_qualification"]
                for component in key_path[:-1]:
                    target = target[component]
                target[key_path[-1]] = value
                mutations.append(changed)
            for changed in mutations:
                with self.subTest(path=path, reference=changed.get("bootstrap_qualification")):
                    self.write_json(path, changed)
                    with self.assertRaises(
                        bundle_verify.native_package_signing_bundle.SigningBundleError
                    ):
                        bundle_verify._validated_signing_inputs(
                            signing_root, self.candidate
                        )
            self.write_json(path, original)

    def test_bundle_revalidator_rejects_unqualified_provenance_status(self) -> None:
        signing_root, provenance, _ = self.signing_evidence()
        for status in (
            "garbage",
            bundle_verify.native_package_signing_bundle.BOOTSTRAP_PROVENANCE_STATUS,
        ):
            with self.subTest(status=status):
                changed = copy.deepcopy(provenance)
                changed["status"] = status
                self.write_json(
                    signing_root / "NATIVE_SIGNING_PROVENANCE.json", changed
                )
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )

    def test_bundle_revalidator_rejects_incomplete_provenance(self) -> None:
        signing_root, provenance, _ = self.signing_evidence()
        mutations = []
        without_source = copy.deepcopy(provenance)
        del without_source["source"]
        mutations.append(without_source)
        without_source_key = copy.deepcopy(provenance)
        del without_source_key["source"]["release_sha"]
        mutations.append(without_source_key)
        without_key_field = copy.deepcopy(provenance)
        del without_key_field["deb_signature"]["key"]["public_key_sha256"]
        mutations.append(without_key_field)
        without_rpm_key_field = copy.deepcopy(provenance)
        del without_rpm_key_field["rpm_signature"]["key"]["fingerprint"]
        mutations.append(without_rpm_key_field)
        for field in ("immutable_header_preserved", "payload_preserved"):
            unproven_rpm = copy.deepcopy(provenance)
            unproven_rpm["rpm_signature"][field] = False
            mutations.append(unproven_rpm)
        for changed in mutations:
            with self.subTest(keys=sorted(changed)):
                self.write_json(
                    signing_root / "NATIVE_SIGNING_PROVENANCE.json", changed
                )
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )

    def test_bundle_revalidator_requires_rpm_native_verification(self) -> None:
        signing_root, _, _ = self.signing_evidence()
        (signing_root / "RPM_NATIVE_VERIFICATION.json").unlink()
        with self.assertRaises(
            bundle_verify.native_package_signing_bundle.SigningBundleError
        ):
            bundle_verify._validated_signing_inputs(signing_root, self.candidate)

    def test_bundle_revalidator_rejects_contradictory_verification_identity(
        self,
    ) -> None:
        signing_root, provenance, verifications = self.signing_evidence()
        contradictions = {
            "rpm": {"fingerprint": "B" * 40},
            "deb": {"fingerprint": "E" * 40},
            "apk": {
                "fingerprint": "f" * 64,
                "public_key_sha256": "f" * 64,
            },
        }
        for family, changes in contradictions.items():
            with self.subTest(family=family):
                self.write_json(
                    signing_root / "NATIVE_SIGNING_PROVENANCE.json", provenance
                )
                verification = copy.deepcopy(verifications[family])
                verification["key"].update(changes)
                self.write_json(
                    signing_root / f"{family.upper()}_NATIVE_VERIFICATION.json",
                    verification,
                )
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )
                self.write_json(
                    signing_root / f"{family.upper()}_NATIVE_VERIFICATION.json",
                    verifications[family],
                )

    def test_bundle_revalidator_binds_exact_standard_rpm_verification_tuple(
        self,
    ) -> None:
        signing_root, _, verifications = self.signing_evidence()
        rpm_verification = verifications["rpm"]
        mutations = (
            (
                "package-owned filename",
                lambda item: item["package"].__setitem__(
                    "name", "syswarden-4.10.0-1.packageowned1.x86_64.rpm"
                ),
            ),
            (
                "package digest",
                lambda item: item["package"].__setitem__("sha256", "f" * 64),
            ),
            (
                "package size",
                lambda item: item["package"].__setitem__(
                    "size", self.rpm_package_size + 1
                ),
            ),
            (
                "verification mechanism",
                lambda item: item.__setitem__("mechanism", "openpgp-detached"),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(case=label):
                changed = copy.deepcopy(rpm_verification)
                mutation(changed)
                self.write_json(
                    signing_root / "RPM_NATIVE_VERIFICATION.json", changed
                )
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )
                self.write_json(
                    signing_root / "RPM_NATIVE_VERIFICATION.json",
                    rpm_verification,
                )

    def test_bundle_revalidator_binds_exact_rhel_package_owned_provenance(self) -> None:
        signing_root, _, _ = self.signing_evidence()
        rhel_root = (
            signing_root.parent
            / bundle_verify.native_package_signing_bundle.RHEL_PACKAGE_OWNED_DIRECTORY
            / "evidence"
        )
        provenance_path = rhel_root / "SIGNING_PROVENANCE.json"
        verification_path = rhel_root / "RPM_NATIVE_VERIFICATION.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        mutations = (
            (
                "package role",
                lambda item: item.__setitem__("package_role", "standard"),
            ),
            (
                "updater manifest",
                lambda item: item.__setitem__("updater_manifest_included", True),
            ),
            (
                "NEVRA release",
                lambda item: item["rpm_identity"].__setitem__("release", "1"),
            ),
            (
                "standard artifact ID reuse",
                lambda item: item["source"].__setitem__("unsigned_artifact_id", 200),
            ),
            (
                "standard candidate digest reuse",
                lambda item: item["packages"]["signed"].__setitem__(
                    "sha256", self.rpm_package_sha256
                ),
            ),
            (
                "bootstrap status",
                lambda item: item.__setitem__(
                    "status",
                    bundle_verify.native_package_signing_bundle.BOOTSTRAP_PROVENANCE_STATUS,
                ),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(case=label):
                changed = copy.deepcopy(provenance)
                mutation(changed)
                self.write_json(provenance_path, changed)
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )
                self.write_json(provenance_path, provenance)

        changed_verification = copy.deepcopy(verification)
        changed_verification["package"]["size"] = self.rhel_rpm_package_size + 1
        self.write_json(verification_path, changed_verification)
        with self.assertRaises(
            bundle_verify.native_package_signing_bundle.SigningBundleError
        ):
            bundle_verify._validated_signing_inputs(signing_root, self.candidate)

    def test_bundle_revalidator_requires_rhel_package_owned_provenance(self) -> None:
        signing_root, _, _ = self.signing_evidence()
        rhel_provenance = (
            signing_root.parent
            / bundle_verify.native_package_signing_bundle.RHEL_PACKAGE_OWNED_DIRECTORY
            / "evidence"
            / "SIGNING_PROVENANCE.json"
        )
        rhel_provenance.unlink()
        with self.assertRaises(
            bundle_verify.native_package_signing_bundle.SigningBundleError
        ):
            bundle_verify._validated_signing_inputs(signing_root, self.candidate)

    def test_sealed_bundle_revalidates_all_five_profiles(self) -> None:
        signing_root, _, _ = self.signing_evidence()
        bundle_root = self.root / "lifecycle-bundle"
        bundle_root.mkdir(mode=0o700)
        for path, observation in zip(self.paths, self.observations, strict=True):
            observation["campaign"]["started_at"] = "2026-09-07T17:00:00Z"
            observation["campaign"]["completed_at"] = "2026-09-07T18:00:00Z"
            for index, checkpoint in enumerate(observation["checkpoints"]):
                checkpoint["observed_at"] = f"2026-09-07T17:00:{index + 1:02d}Z"
            for index, scenario in enumerate(observation["scenarios"]):
                scenario["observed_at"] = f"2026-09-07T17:{index + 1:02d}:00Z"
            if observation["host"]["package_variant"] == "rhel-package-owned":
                rollback = observation["scenarios"][8]
                raw_path = self.artifacts / rollback["evidence_ref"]
                raw_document = json.loads(raw_path.read_bytes())
                raw_document["observed_at"] = rollback["observed_at"]
                self.write_json(raw_path, raw_document)
                rollback["evidence_sha256"] = hashlib.sha256(
                    raw_path.read_bytes()
                ).hexdigest()
                preceding_records = {
                    item["evidence_ref"]: item["evidence_sha256"]
                    for item in (
                        [observation["host"]]
                        + observation["packages"]
                        + observation["checkpoints"]
                        + observation["scenarios"]
                        + [observation["final_state"]]
                    )
                }
                observation["attestation"][
                    "attested_evidence_inventory_sha256"
                ] = evidence._inventory_sha256(preceding_records)
            self.write_json(path, observation)
        verdict = self.assemble()
        (bundle_root / "VERDICT.json").write_text(
            json.dumps(verdict, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        observation_names = (
            "node02-ubuntu26.04.json",
            "node05-almalinux9.8.json",
            "node04-alpine3.24.json",
            "node05-almalinux9.8-rhelpo.json",
            "node03-almalinux10.2-rhelpo.json",
        )
        with tarfile.open(bundle_root / "RAW_EVIDENCE.tar", mode="w:") as stream:
            for path, name in zip(self.paths, observation_names, strict=True):
                stream.add(path, arcname=name, recursive=False)
            stream.add(self.artifacts, arcname="artifacts", recursive=True)
        bundle_verify.verify(
            bundle_root,
            signing_root,
            self.candidate,
            self.node02_ssh,
            self.node04_ssh,
            self.node05_ssh,
            self.node03_ssh,
        )

    def test_bundle_revalidator_rejects_extra_or_duplicate_signed_package(
        self,
    ) -> None:
        signing_root, provenance, _ = self.signing_evidence()
        signed = provenance["packages"]["signed"]
        extra = copy.deepcopy(signed)
        extra.append(
            {
                "name": "syswarden_4.10.0_extra.deb",
                "sha256": "f" * 64,
                "size": 123,
            }
        )
        duplicate = copy.deepcopy(signed)
        duplicate[0] = copy.deepcopy(duplicate[1])
        for label, records in (("extra", extra), ("duplicate", duplicate)):
            with self.subTest(case=label):
                changed = copy.deepcopy(provenance)
                changed["packages"]["signed"] = records
                self.write_json(
                    signing_root / "NATIVE_SIGNING_PROVENANCE.json", changed
                )
                with self.assertRaises(
                    bundle_verify.native_package_signing_bundle.SigningBundleError
                ):
                    bundle_verify._validated_signing_inputs(
                        signing_root, self.candidate
                    )

    def test_checkpoint_order_health_services_and_package_binding_are_exact(self) -> None:
        mutations = (
            ("sequence", 99),
            ("installed_version", "v4.10.1"),
            ("installed_commit", "0" * 40),
            ("installed_package_sha256", "0" * 64),
            ("core_service_state", "failed"),
            ("firewall_service_state", "failed"),
            ("package_manager_healthy", False),
            ("package_database_consistent", False),
            ("unexpected_owned_residue_count", 1),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[0])
                changed["checkpoints"][5][key] = value
                self.assert_invalid(self.rewrite(0, changed))
                self.write_json(self.paths[0], self.observations[0])
        changed = copy.deepcopy(self.observations[0])
        changed["checkpoints"][0]["configuration_semantic_sha256"] = "0" * 64
        self.assert_invalid(self.rewrite(0, changed), "absent checkpoint")

    def test_configuration_state_operator_firewall_and_two_reboots_are_proven(self) -> None:
        for index, key, value, message in (
            (6, "configuration_semantic_sha256", "0" * 64, "configuration"),
            (8, "persistent_state_canary_sha256", "0" * 64, "persistent"),
            (9, "syswarden_firewall_sha256", "0" * 64, "firewall semantics"),
            (10, "operator_state_canary_sha256", "0" * 64, "operator"),
            (4, "third_party_firewall_sha256", "0" * 64, "firewall"),
        ):
            with self.subTest(index=index, key=key):
                changed = copy.deepcopy(self.observations[0])
                changed["checkpoints"][index][key] = value
                self.assert_invalid(self.rewrite(0, changed), message)
                self.write_json(self.paths[0], self.observations[0])

        for index, source_index in ((6, 5), (7, 6), (9, 6)):
            with self.subTest(index=index, key="boot_id_sha256"):
                changed = copy.deepcopy(self.observations[0])
                changed["checkpoints"][index]["boot_id_sha256"] = changed[
                    "checkpoints"
                ][source_index]["boot_id_sha256"]
                self.assert_invalid(self.rewrite(0, changed), "two-reboot")
                self.write_json(self.paths[0], self.observations[0])

        changed = copy.deepcopy(self.observations[1])
        changed["checkpoints"][7]["boot_id_sha256"] = changed["checkpoints"][6][
            "boot_id_sha256"
        ]
        self.assert_invalid(self.rewrite(1, changed), "two-reboot")
        self.write_json(self.paths[1], self.observations[1])

    def test_every_required_scenario_check_is_fail_closed(self) -> None:
        for scenario_index, scenario in enumerate(self.contract["scenarios"]):
            for check in scenario["required_checks"]:
                with self.subTest(scenario=scenario["id"], check=check):
                    changed = copy.deepcopy(self.observations[0])
                    changed["scenarios"][scenario_index]["checks"][check] = False
                    self.assert_invalid(self.rewrite(0, changed), "check failed")
                    self.write_json(self.paths[0], self.observations[0])
        scenario_indexes = {
            scenario["id"]: index
            for index, scenario in enumerate(self.contract["scenarios"])
        }
        for profile_index in (3, 4):
            profile_id = self.observations[profile_index]["host"]["profile_id"]
            for scenario_id, checks in self.contract["profile_scenario_checks"][
                profile_id
            ].items():
                scenario_index = scenario_indexes[scenario_id]
                for check in checks:
                    with self.subTest(
                        profile=profile_index,
                        scenario=scenario_id,
                        check=check,
                    ):
                        changed = copy.deepcopy(self.observations[profile_index])
                        changed["scenarios"][scenario_index]["checks"][check] = False
                        self.assert_invalid(
                            self.rewrite(profile_index, changed), "check failed"
                        )
                        self.write_json(
                            self.paths[profile_index],
                            self.observations[profile_index],
                        )

    def test_rhel_package_owned_stages_offline_then_activates_on_first_boot(self) -> None:
        for profile_index in (3, 4):
            observation = self.observations[profile_index]
            self.assertEqual(
                observation["host"]["installation_mode"],
                "offline-chroot-first-boot",
            )
            self.assertEqual(
                observation["checkpoints"][0]["boot_id_sha256"], "not-applicable"
            )
            self.assertNotEqual(
                observation["checkpoints"][1]["boot_id_sha256"], "not-applicable"
            )
            changed = copy.deepcopy(observation)
            changed["checkpoints"][0]["boot_id_sha256"] = changed["checkpoints"][1][
                "boot_id_sha256"
            ]
            self.assert_invalid(
                self.rewrite(profile_index, changed), "offline chroot checkpoint"
            )
            self.write_json(self.paths[profile_index], observation)

    def test_every_install_reverifies_the_exact_package_before_install(self) -> None:
        installing = [1, 4, 5, 8, 9]
        for scenario_index in installing:
            for key, value in (
                ("package_sha256", "0" * 64),
                ("verification_identity", "wrong"),
                ("verification_proof_sha256", "0" * 64),
                ("verified_before_install", False),
            ):
                with self.subTest(scenario=scenario_index, key=key):
                    changed = copy.deepcopy(self.observations[0])
                    changed["scenarios"][scenario_index]["package_verifications"][0][key] = value
                    self.assert_invalid(self.rewrite(0, changed), "reverified")
                    self.write_json(self.paths[0], self.observations[0])

    def test_campaign_and_scenario_timestamps_are_bounded_and_ordered(self) -> None:
        for key, value, message in (
            ("completed_at", "2026-09-10T07:59:59Z", "follow"),
            ("completed_at", "2026-09-10T20:00:00Z", "duration"),
        ):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.observations[0])
                changed["campaign"][key] = value
                self.assert_invalid(self.rewrite(0, changed), message)
                self.write_json(self.paths[0], self.observations[0])
        changed = copy.deepcopy(self.observations[0])
        changed["scenarios"][5]["observed_at"] = "2026-09-10T08:00:05Z"
        self.assert_invalid(self.rewrite(0, changed), "order")
        self.write_json(self.paths[0], self.observations[0])

    def test_final_purge_requires_zero_residue_and_exact_path_inventory(self) -> None:
        counters = (
            "package_records",
            "service_units",
            "running_processes",
            "firewall_objects",
            "dedicated_paths",
            "dedicated_users_groups",
            "scheduled_jobs",
            "residue_count",
        )
        for key in counters:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[1])
                changed["final_state"][key] = 1
                self.assert_invalid(self.rewrite(1, changed), "residue-free")
                self.write_json(self.paths[1], self.observations[1])
        changed = copy.deepcopy(self.observations[1])
        changed["final_state"]["verified_paths"] = changed["final_state"]["verified_paths"][:-1]
        self.assert_invalid(self.rewrite(1, changed), "final state binding")
        self.write_json(self.paths[1], self.observations[1])
        for path_index, path_value in enumerate(self.contract["zero_residue_paths"]):
            with self.subTest(path=path_value):
                changed = copy.deepcopy(self.observations[1])
                changed["final_state"]["verified_paths"].pop(path_index)
                self.assert_invalid(self.rewrite(1, changed), "final state binding")
                self.write_json(self.paths[1], self.observations[1])

    def test_final_attestation_binds_candidate_contract_profile_and_inventory(self) -> None:
        for key, value in (
            ("verification_status", "unverified"),
            ("verified_by", "self"),
            ("attested_profile_id", "DEB-U2604"),
            ("attested_candidate_commit", "0" * 40),
            ("attested_contract_sha256", "0" * 64),
            ("attested_evidence_inventory_sha256", "0" * 64),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.observations[1])
                changed["attestation"][key] = value
                self.assert_invalid(self.rewrite(1, changed), "final attestation")
                self.write_json(self.paths[1], self.observations[1])

    def test_profile_count_duplicates_and_cross_profile_reuse_are_rejected(self) -> None:
        self.assert_invalid(self.paths[:4], "exactly 5")
        self.assert_invalid(
            [self.paths[0], self.paths[0], self.paths[2], self.paths[3], self.paths[4]],
            "reused",
        )
        changed = copy.deepcopy(self.observations[1])
        changed["host"]["evidence_ref"] = self.observations[0]["host"]["evidence_ref"]
        changed["host"]["evidence_sha256"] = self.observations[0]["host"]["evidence_sha256"]
        self.assert_invalid(self.rewrite(1, changed))

    def test_missing_extra_symlink_hardlink_and_digest_tampering_are_rejected(self) -> None:
        target = self.artifacts / self.observations[0]["host"]["evidence_ref"]
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        self.assert_invalid(message="digest mismatch")
        target.write_bytes(original)

        extra = self.artifacts / "DEB-U2604/raw/extra.json"
        self.write_json(extra, {"unexpected": True})
        self.assert_invalid(message="inventory is not exact")
        extra.unlink()

        extra_directory = self.artifacts / "unexpected"
        extra_directory.mkdir()
        self.assert_invalid(message="directory inventory")
        extra_directory.rmdir()

        target.unlink()
        self.assert_invalid(message="missing raw evidence")
        target.write_bytes(original)

        target.unlink()
        outside = self.root / "outside.json"
        self.write_json(outside, {"outside": True})
        target.symlink_to(outside)
        self.assert_invalid(message="escaped its root")
        target.unlink()
        target.write_bytes(original)

        hardlink = self.root / "hardlink.json"
        os.link(target, hardlink)
        self.assert_invalid(message="regular file")

    def test_duplicate_json_nonfinite_time_and_unsafe_output_are_rejected(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":1,"schema":2}\n', encoding="utf-8")
        with self.assertRaisesRegex(evidence.LifecycleEvidenceError, "duplicate JSON"):
            evidence._load_json(duplicate, 1024, "duplicate")
        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text('{"value":NaN}\n', encoding="utf-8")
        with self.assertRaisesRegex(evidence.LifecycleEvidenceError, "constant"):
            evidence._load_json(nonfinite, 1024, "nonfinite")
        changed = copy.deepcopy(self.observations[0])
        changed["campaign"]["completed_at"] = "2026-09-10T11:00:00Z"
        self.assert_invalid(self.rewrite(0, changed), "future")
        self.write_json(self.paths[0], self.observations[0])
        output = self.root / "verdict.json"
        result = self.assemble()
        evidence._write_new_private(output, result)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(evidence.LifecycleEvidenceError, "new absolute"):
            evidence._write_new_private(output, result)


if __name__ == "__main__":
    unittest.main()
