#!/usr/bin/env python3
"""Adversarial tests for the NODE01 native migration evidence harness."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

try:
    from scripts.ci import node01_migration_evidence as evidence
except ModuleNotFoundError:
    import node01_migration_evidence as evidence


class Node01MigrationEvidenceTests(unittest.TestCase):
    candidate = "a" * 40
    openpgp_fingerprint = "A" * 40
    candidate_package_name = evidence.CANDIDATE_PACKAGE_NAME
    candidate_package_sha256 = "d" * 64
    candidate_package_size = 12_345_678
    validation_time = dt.datetime(2026, 1, 1, 9, 0, tzinfo=dt.timezone.utc)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "artifacts"
        self.raw_root = self.artifact_root / "raw"
        self.raw_root.mkdir(parents=True)
        self.observations_path = self.root / "observations.json"
        self.contract = json.loads(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        self.observations = self.make_observations()
        self.write_json(self.observations_path, self.observations)
        self.valid = evidence.assemble_evidence(
            self.observations_path,
            artifact_root=self.artifact_root,
            candidate_sha=self.candidate,
            openpgp_fingerprint=self.openpgp_fingerprint,
            candidate_package_name=self.candidate_package_name,
            candidate_package_sha256=self.candidate_package_sha256,
            candidate_package_size=self.candidate_package_size,
            validation_time=self.validation_time,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def raw(self, name: str) -> str:
        path = self.raw_root / f"{name}.json"
        self.write_json(path, {"capture": name, "origin": "native-node01"})
        return f"raw/{name}.json"

    def manifest(self, tag: str, scenario_id: str) -> dict[str, object]:
        candidate = tag == evidence.TARGET_RELEASE
        rollback = scenario_id == "signed-rollback-v4100-to-v4043"
        source_firewall_sha256 = (
            "9" * 64
            if scenario_id == "verified-reupgrade-v4028-through-v4043-to-v4100"
            else "4" * 64
        )
        channel = (
            "offline-qualification-bundle"
            if candidate
            else "verified-native-rollback" if rollback else "production-online-latest"
        )
        result: dict[str, object] = {
            "release_tag": tag,
            "producer_commit_sha": self.candidate if candidate else evidence.STABLE_COMMIT,
            "manifest_contains_producer_commit": False,
            "manifest_sha256": "1" * 64,
            "manifest_signature_sha256": "2" * 64,
            "package_sha256": "d" * 64 if candidate else "c" * 64,
            "manifest_signature_algorithm": "Ed25519",
            "manifest_signature_verified": True,
            "manifest_package_digest_verified": True,
            "manifest_signer_key_id": "syswarden-update-2026-01",
            "manifest_signer_public_key_sha256": "4234be4f695141ffd7c2e136745d9742934b139c0d097a6ab5ce425b1dd8fda6",
            "detached_package_signature_algorithm": "OpenPGP-RSA-SHA256" if candidate else "not-applicable",
            "detached_package_signature_sha256": "4" * 64 if candidate else "not-applicable",
            "detached_package_signature_verified": candidate,
            "detached_package_signer_fingerprint": self.openpgp_fingerprint if candidate else "not-applicable",
            "installation_channel": channel,
            "normalized_invocation": (
                self.contract["candidate_channel"]["command"]
                if candidate
                else "native-deb-rollback-after-manifest-verification"
                if rollback
                else "syswarden update"
            ),
            "updater_executable_sha256": "5" * 64 if not rollback else "not-applicable",
            "updater_executable_source_package_sha256": (
                "d" * 64 if candidate else "not-applicable" if rollback else "7" * 64
            ),
            "updater_executable_attested": not rollback,
            "qualification_bundle_identity": (
                "github:duggytuxy/syswarden:native-signing:12345"
                if candidate else "not-applicable"
            ),
            "qualification_bundle_descriptor_sha256": "6" * 64 if candidate else "not-applicable",
            "qualification_bundle_producer_attestation_sha256": "9" * 64 if candidate else "not-applicable",
            "network_requests": 0 if candidate or rollback else 4,
            "fallback_used": False,
            "offline_mode_confirmed": candidate,
            "operation_stdout_sha256": "a" * 64,
            "installed_package_record_sha256": "b" * 64,
            "qualification_prevalidation": {
                "config_loads": 0,
                "firewall_recovery_runs": 0,
                "operator_state_before_sha256": "6" * 64,
                "operator_state_at_install_sha256": "6" * 64,
                "firewall_state_before_sha256": source_firewall_sha256,
                "firewall_state_at_install_sha256": source_firewall_sha256,
                "install_started_after_bundle_validation": True,
                "exact_flags_gate": True,
            } if candidate else "not-applicable",
        }
        if candidate:
            result["package_name"] = self.candidate_package_name
            result["package_size"] = self.candidate_package_size
        return result

    def checkpoint(self, expected: dict[str, object], index: int) -> dict[str, object]:
        version = str(expected["version"])
        purged = version == "absent"
        commit = {
            evidence.BASELINE_RELEASE: evidence.BASELINE_COMMIT,
            evidence.TRUST_BOOTSTRAP_RELEASE: evidence.TRUST_BOOTSTRAP_COMMIT,
            evidence.STABLE_RELEASE: evidence.STABLE_COMMIT,
            evidence.TARGET_RELEASE: self.candidate,
            "absent": "absent",
        }[version]
        package = {
            evidence.BASELINE_RELEASE: "b" * 64,
            evidence.TRUST_BOOTSTRAP_RELEASE: "7" * 64,
            evidence.STABLE_RELEASE: "c" * 64,
            evidence.TARGET_RELEASE: "d" * 64,
            "absent": "absent",
        }[version]
        after_snapshot = index >= 5
        return {
            "id": expected["id"],
            "sequence": expected["sequence"],
            "observed_at": f"2026-01-01T08:00:{10 + index:02d}Z",
            "installed_version": version,
            "installed_commit": commit,
            "installed_package_sha256": package,
            "boot_id_sha256": "9" * 64 if after_snapshot else "8" * 64,
            "configuration_semantic_sha256": "absent" if purged else "5" * 64,
            "operator_state_canary_sha256": "absent" if purged else "6" * 64,
            "persistent_state_inventory_sha256": "absent" if purged else f"{index + 1:x}" * 64,
            "syswarden_firewall_sha256": "absent" if purged else f"{index + 2:x}" * 64,
            "core_service_state": expected["service_state"],
            "firewall_service_state": expected["service_state"],
            "package_manager_healthy": True,
            "evidence_ref": self.raw(f"checkpoint-{index + 1}"),
        }

    def scenario(self, expected: dict[str, object], index: int) -> dict[str, object]:
        bootstrap = str(expected["id"]) in {
            "verified-manual-trust-bootstrap-v4028-to-v4032",
            "verified-reupgrade-v4028-through-v4043-to-v4100",
        }
        return {
            "id": expected["id"],
            "sequence": expected["sequence"],
            "status": "pass",
            "observed_at": f"2026-01-01T08:{index + 1:02d}:00Z",
            "from_checkpoint": expected["from_checkpoint"],
            "to_checkpoint": expected["to_checkpoint"],
            "verified_manifests": [
                self.manifest(tag, str(expected["id"]))
                for tag in expected["verified_manifests"]
            ],
            "trust_bootstrap_verification": {
                "release_tag": evidence.TRUST_BOOTSTRAP_RELEASE,
                "producer_commit_sha": evidence.TRUST_BOOTSTRAP_COMMIT,
                "release_tag_signature_verified": True,
                "release_checksums_sha256": "e" * 64,
                "package_sha256": "7" * 64,
                "package_digest_matched": True,
                "download_origin": "github-release-assets-separated",
                "manual_first_hop": True,
                "historical_updater_used": False,
            } if bootstrap else "not-applicable",
            "checks": {name: True for name in expected["required_checks"]},
            "evidence_ref": self.raw(f"scenario-{index + 1}"),
        }

    def make_observations(self) -> dict[str, object]:
        return {
            "schema": evidence.OBSERVATIONS_SCHEMA,
            "campaign": {
                "id": "node01-v4100-migration-1",
                "started_at": "2026-01-01T08:00:00Z",
                "completed_at": "2026-01-01T08:20:00Z",
                "operator_identity": "syswarden-release-operator",
                "observation_origin": "real-native-node01",
                "synthetic": False,
                "network_control": "provider-firewall",
                "snapshot_reference": "node01-v4028-native-baseline",
            },
            "host": {
                "node_id": "node01",
                "profile_id": "DEB-13",
                "os_id": "debian",
                "os_version": "13",
                "architecture": "amd64",
                "package_family": "deb",
                "service_manager": "systemd",
                "ssh_host_key_sha256": "SHA256:" + "A" * 43,
                "candidate_sha": self.candidate,
                "attestation_ref": self.raw("host-attestation"),
            },
            "checkpoints": [
                self.checkpoint(item, index)
                for index, item in enumerate(self.contract["checkpoints"])
            ],
            "scenarios": [
                self.scenario(item, index)
                for index, item in enumerate(self.contract["scenarios"])
            ],
            "attestation": {
                "mechanism": "github-artifact-attestation",
                "statement_sha256": "e" * 64,
                "signature_sha256": "f" * 64,
                "signer_identity": "github:duggytuxy/syswarden/release-qualification",
                "verification_status": "verified",
                "verified_by": "release-owner-gate",
                "attested_candidate_sha": self.candidate,
                "native_bundle_verified": True,
                "evidence_ref": self.raw("campaign-attestation"),
            },
        }

    def validate(self, document: dict[str, object] | None = None) -> dict[str, object]:
        return evidence.validate_evidence(
            document or self.valid,
            artifact_root=self.artifact_root,
            candidate_sha=self.candidate,
            openpgp_fingerprint=self.openpgp_fingerprint,
            candidate_package_name=self.candidate_package_name,
            candidate_package_sha256=self.candidate_package_sha256,
            candidate_package_size=self.candidate_package_size,
            validation_time=self.validation_time,
        )

    def assert_invalid(self, document: dict[str, object], message: str | None = None) -> None:
        with self.assertRaises(evidence.MigrationEvidenceError) as caught:
            self.validate(document)
        if message:
            self.assertIn(message, str(caught.exception))

    def test_valid_native_migration_evidence_passes(self) -> None:
        verdict = self.validate()
        self.assertEqual(verdict["status"], "pass")
        self.assertEqual(verdict["checkpoint_count"], 10)
        self.assertEqual(verdict["scenario_count"], 11)
        self.assertEqual(verdict["raw_evidence_count"], 23)

    def test_contract_digest_is_pinned(self) -> None:
        self.assertEqual(evidence.contract_digest(), evidence.CONTRACT_SHA256)
        changed = self.root / "contract.json"
        changed.write_text(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(evidence.MigrationEvidenceError, "reviewed"):
            evidence.contract_digest(changed)

    def test_contract_preserves_the_historical_trust_bootstrap_boundary(self) -> None:
        scenarios = {item["id"]: item for item in self.contract["scenarios"]}
        manual = scenarios["verified-manual-trust-bootstrap-v4028-to-v4032"]
        self.assertEqual(manual["verified_manifests"], [])
        self.assertIn("historical_updater_not_used", manual["required_checks"])
        signed = scenarios["signed-update-v4032-to-v4043"]
        self.assertEqual(signed["verified_manifests"], ["v4.04.3"])
        candidate = scenarios["verified-candidate-install-v4043-to-v4100"]
        self.assertIn("offline_qualification_update_channel_used", candidate["required_checks"])
        self.assertNotIn("syswarden_update_used", candidate["required_checks"])
        self.assertEqual(
            self.contract["guardrails"]["post_publication_updater_acceptance"],
            "separate-required-check-after-publication",
        )

    def test_historical_bootstrap_is_structurally_bound_to_v4032_package(self) -> None:
        for scenario_index in (1, 9):
            for key, value in (
                ("release_tag", "v4.03.3"),
                ("producer_commit_sha", "0" * 40),
                ("release_tag_signature_verified", False),
                ("package_sha256", "0" * 64),
                ("package_digest_matched", False),
                ("manual_first_hop", False),
                ("historical_updater_used", True),
            ):
                with self.subTest(scenario_index=scenario_index, key=key):
                    changed = copy.deepcopy(self.valid)
                    changed["scenarios"][scenario_index]["trust_bootstrap_verification"][key] = value
                    self.assert_invalid(changed, "trust bootstrap")

    def test_non_bootstrap_scenario_cannot_claim_manual_bootstrap(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][3]["trust_bootstrap_verification"] = copy.deepcopy(
            changed["scenarios"][1]["trust_bootstrap_verification"]
        )
        self.assert_invalid(changed, "must not claim")

    def test_assembler_computes_digests_and_rejects_caller_supplied_digest(self) -> None:
        host_wire = (self.artifact_root / self.valid["host"]["attestation_ref"]).read_bytes()
        self.assertEqual(self.valid["host"]["attestation_sha256"], hashlib.sha256(host_wire).hexdigest())
        changed = copy.deepcopy(self.observations)
        changed["host"]["attestation_sha256"] = "0" * 64
        self.write_json(self.observations_path, changed)
        with self.assertRaisesRegex(evidence.MigrationEvidenceError, "must not supply"):
            evidence.assemble_evidence(
                self.observations_path,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint=self.openpgp_fingerprint,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256=self.candidate_package_sha256,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )

    def test_candidate_release_and_repository_binding_are_exact(self) -> None:
        mutations = (
            ("candidate_sha", "0" * 40),
            ("release_tag", "v4.10.1"),
            ("repository", "example/syswarden"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed[key] = value
                self.assert_invalid(changed)

    def test_synthetic_and_non_native_campaigns_fail_closed(self) -> None:
        for key, value in (
            ("synthetic", True),
            ("observation_origin", "container-lab"),
            ("network_control", "uncontrolled"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["campaign"][key] = value
                self.assert_invalid(changed, "non-native")

    def test_node01_identity_platform_and_candidate_are_exact(self) -> None:
        mutations = (
            ("node_id", "node02"),
            ("profile_id", "DEB-U2604"),
            ("os_id", "ubuntu"),
            ("os_version", "12"),
            ("architecture", "arm64"),
            ("package_family", "rpm"),
            ("service_manager", "openrc"),
            ("candidate_sha", "0" * 40),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["host"][key] = value
                self.assert_invalid(changed)

    def test_ssh_host_key_must_be_pinned_sha256_fingerprint(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["host"]["ssh_host_key_sha256"] = "accept-new"
        self.assert_invalid(changed, "SSH host key")

    def test_campaign_time_bounds_and_order_are_enforced(self) -> None:
        mutations = (
            ("completed_at", "2026-01-01T07:59:59Z"),
            ("completed_at", "2026-01-01T15:00:01Z"),
            ("completed_at", "2026-01-02T09:00:00Z"),
        )
        for key, value in mutations:
            with self.subTest(value=value):
                changed = copy.deepcopy(self.valid)
                changed["campaign"][key] = value
                self.assert_invalid(changed)

    def test_checkpoint_inventory_order_and_versions_are_exact(self) -> None:
        for mutation in ("missing", "reordered", "wrong-version"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.valid)
                if mutation == "missing":
                    changed["checkpoints"].pop()
                elif mutation == "reordered":
                    changed["checkpoints"][0], changed["checkpoints"][1] = changed["checkpoints"][1], changed["checkpoints"][0]
                else:
                    changed["checkpoints"][2]["installed_version"] = "v4.10.1"
                self.assert_invalid(changed, "checkpoint")

    def test_checkpoint_commit_package_manager_and_service_fail_closed(self) -> None:
        mutations = (
            (3, "installed_commit", "0" * 40),
            (1, "package_manager_healthy", False),
            (3, "core_service_state", "failed"),
            (4, "firewall_service_state", "inactive"),
        )
        for index, key, value in mutations:
            with self.subTest(index=index, key=key):
                changed = copy.deepcopy(self.valid)
                changed["checkpoints"][index][key] = value
                self.assert_invalid(changed)

    def test_purge_requires_exact_absence(self) -> None:
        for key, value in (
            ("installed_package_sha256", "0" * 64),
            ("configuration_semantic_sha256", "0" * 64),
            ("core_service_state", "inactive"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["checkpoints"][-1][key] = value
                self.assert_invalid(changed, "purged checkpoint")
        changed = copy.deepcopy(self.valid)
        changed["checkpoints"][-1]["boot_id_sha256"] = "absent"
        self.assert_invalid(changed, "boot_id_sha256")

    def test_configuration_and_operator_state_must_survive_every_installed_checkpoint(self) -> None:
        for index, key in ((1, "configuration_semantic_sha256"), (8, "operator_state_canary_sha256")):
            with self.subTest(index=index, key=key):
                changed = copy.deepcopy(self.valid)
                changed["checkpoints"][index][key] = "0" * 64
                self.assert_invalid(changed, "changed across migration")

    def test_same_release_must_install_identical_package_bytes(self) -> None:
        for index in (4, 7):
            with self.subTest(index=index):
                changed = copy.deepcopy(self.valid)
                changed["checkpoints"][index]["installed_package_sha256"] = "0" * 64
                self.assert_invalid(changed, "package bytes changed")

    def test_snapshot_and_reupgrade_require_new_boot_evidence(self) -> None:
        for index, source in ((5, 0), (8, 3)):
            with self.subTest(index=index):
                changed = copy.deepcopy(self.valid)
                changed["checkpoints"][index]["boot_id_sha256"] = changed["checkpoints"][source]["boot_id_sha256"]
                self.assert_invalid(changed, "boot")

    def test_checkpoint_and_scenario_timestamps_are_ordered_and_bounded(self) -> None:
        mutations = (
            ("checkpoints", 1, "observed_at", "2026-01-01T07:59:59Z"),
            ("checkpoints", 1, "observed_at", "2026-01-01T08:00:10Z"),
            ("checkpoints", 2, "observed_at", "2026-01-01T08:00:10Z"),
            ("scenarios", 3, "observed_at", "2026-01-01T08:01:00Z"),
            ("scenarios", 9, "observed_at", "2026-01-01T08:21:00Z"),
        )
        for collection, index, key, value in mutations:
            with self.subTest(collection=collection, index=index):
                changed = copy.deepcopy(self.valid)
                changed[collection][index][key] = value
                self.assert_invalid(changed, "timestamps")

    def test_scenario_inventory_order_status_and_checks_are_exact(self) -> None:
        mutations = ("missing", "reordered", "failed", "missing-check", "false-check")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.valid)
                if mutation == "missing":
                    changed["scenarios"].pop()
                elif mutation == "reordered":
                    changed["scenarios"][0], changed["scenarios"][1] = changed["scenarios"][1], changed["scenarios"][0]
                elif mutation == "failed":
                    changed["scenarios"][6]["status"] = "fail"
                elif mutation == "missing-check":
                    changed["scenarios"][6]["checks"].pop("hids_real_event_detected")
                else:
                    changed["scenarios"][6]["checks"]["waap_controlled_request_classified"] = False
                self.assert_invalid(changed)

    def test_manifest_inventory_and_order_are_exact(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][9]["verified_manifests"].reverse()
        self.assert_invalid(changed, "manifest")
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][2]["verified_manifests"] = []
        self.assert_invalid(changed, "manifest")

    def test_manifest_signature_and_package_digest_must_verify(self) -> None:
        for key in ("manifest_signature_verified", "manifest_package_digest_verified"):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][4]["verified_manifests"][0][key] = False
                self.assert_invalid(changed, "verification failed")

    def test_embedded_update_trust_root_is_exact(self) -> None:
        for key, value in (
            ("manifest_signer_key_id", "untrusted-key"),
            ("manifest_signer_public_key_sha256", "0" * 64),
            ("manifest_signature_algorithm", "RSA"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][4]["verified_manifests"][0][key] = value
                self.assert_invalid(changed, "embedded trust root")

    def test_manifest_v1_cannot_claim_the_external_commit_binding(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][4]["verified_manifests"][0]["manifest_contains_producer_commit"] = True
        self.assert_invalid(changed, "must not be credited")

    def test_candidate_offline_channel_is_exact_and_networkless(self) -> None:
        mutations = (
            ("installation_channel", "production-online-latest"),
            ("normalized_invocation", "syswarden update"),
            ("network_requests", 1),
            ("fallback_used", True),
            ("offline_mode_confirmed", False),
            ("updater_executable_attested", False),
            ("updater_executable_source_package_sha256", "0" * 64),
            ("qualification_bundle_identity", "unsafe value"),
            ("qualification_bundle_descriptor_sha256", "0"),
            ("qualification_bundle_producer_attestation_sha256", "0"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][4]["verified_manifests"][0][key] = value
                self.assert_invalid(changed)

    def test_candidate_prevalidation_cannot_touch_configuration_or_firewall(self) -> None:
        mutations = (
            ("config_loads", 1),
            ("config_loads", False),
            ("firewall_recovery_runs", 1),
            ("firewall_recovery_runs", False),
            ("operator_state_at_install_sha256", "0" * 64),
            ("firewall_state_at_install_sha256", "0" * 64),
            ("install_started_after_bundle_validation", False),
            ("exact_flags_gate", False),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                prevalidation = changed["scenarios"][4]["verified_manifests"][0]["qualification_prevalidation"]
                prevalidation[key] = value
                self.assert_invalid(changed, "offline qualification channel")

    def test_candidate_prevalidation_is_bound_to_its_source_checkpoint(self) -> None:
        for scenario_index, manifest_index, key in (
            (4, 0, "operator_state_before_sha256"),
            (4, 0, "firewall_state_before_sha256"),
            (9, 1, "operator_state_at_install_sha256"),
            (9, 1, "firewall_state_at_install_sha256"),
        ):
            with self.subTest(scenario_index=scenario_index, key=key):
                changed = copy.deepcopy(self.valid)
                prevalidation = changed["scenarios"][scenario_index]["verified_manifests"][manifest_index][
                    "qualification_prevalidation"
                ]
                replacement = "0" * 64
                paired = key.replace("before", "at_install") if "before" in key else key.replace("at_install", "before")
                prevalidation[key] = replacement
                prevalidation[paired] = replacement
                self.assert_invalid(changed, "source checkpoint")

    def test_stable_update_and_rollback_channels_cannot_be_swapped(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][2]["verified_manifests"][0]["installation_channel"] = "verified-native-rollback"
        self.assert_invalid(changed, "does not match")
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][7]["verified_manifests"][0]["installation_channel"] = "production-online-latest"
        self.assert_invalid(changed, "does not match")

    def test_stable_online_updater_is_bound_to_bootstrap_package(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][2]["verified_manifests"][0]["updater_executable_source_package_sha256"] = "0" * 64
        self.assert_invalid(changed, "production signed updater")

    def test_qualified_openpgp_fingerprint_is_an_external_validation_input(self) -> None:
        with self.assertRaisesRegex(evidence.MigrationEvidenceError, "signing-policy binding"):
            evidence.validate_evidence(
                self.valid,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint="B" * 40,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256=self.candidate_package_sha256,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )

    def test_manifest_release_commit_and_installed_package_are_bound(self) -> None:
        mutations = (
            (2, "producer_commit_sha", "0" * 40),
            (4, "producer_commit_sha", "0" * 40),
            (4, "package_sha256", "0" * 64),
        )
        for scenario_index, key, value in mutations:
            with self.subTest(scenario_index=scenario_index, key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][scenario_index]["verified_manifests"][0][key] = value
                self.assert_invalid(changed)

    def test_candidate_package_name_digest_and_size_are_bundle_bound(self) -> None:
        for key, value in (
            ("package_name", "syswarden_4.10.0_other.deb"),
            ("package_sha256", "0" * 64),
            ("package_size", self.candidate_package_size + 1),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][4]["verified_manifests"][0][key] = value
                self.assert_invalid(changed)

        changed = copy.deepcopy(self.valid)
        changed["candidate_package"]["size"] += 1
        self.assert_invalid(changed, "package binding")

        with self.assertRaisesRegex(
            evidence.MigrationEvidenceError, "protected signing provenance"
        ):
            evidence.validate_evidence(
                self.valid,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint=self.openpgp_fingerprint,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256="0" * 64,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )

    def test_candidate_detached_deb_signature_is_mandatory(self) -> None:
        for key, value in (
            ("detached_package_signature_algorithm", "not-applicable"),
            ("detached_package_signature_sha256", "not-applicable"),
            ("detached_package_signature_verified", False),
            ("detached_package_signer_fingerprint", "a" * 40),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["scenarios"][4]["verified_manifests"][0][key] = value
                self.assert_invalid(changed)

    def test_stable_release_cannot_claim_unpublished_detached_deb_signature(self) -> None:
        changed = copy.deepcopy(self.valid)
        manifest = changed["scenarios"][2]["verified_manifests"][0]
        manifest["detached_package_signature_algorithm"] = "OpenPGP-RSA-SHA256"
        manifest["detached_package_signature_sha256"] = "4" * 64
        manifest["detached_package_signature_verified"] = True
        manifest["detached_package_signer_fingerprint"] = "A" * 40
        self.assert_invalid(changed, "must not invent")

    def test_campaign_attestation_is_verified_candidate_bound_and_native(self) -> None:
        for key, value in (
            ("verification_status", "pending"),
            ("verified_by", "self-report"),
            ("attested_candidate_sha", "0" * 40),
            ("native_bundle_verified", False),
            ("mechanism", "plain-json"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.valid)
                changed["attestation"][key] = value
                self.assert_invalid(changed, "attestation")

    def test_raw_evidence_digest_tamper_fails(self) -> None:
        target = self.artifact_root / self.valid["scenarios"][6]["evidence_ref"]
        self.write_json(target, {"capture": "tampered"})
        self.assert_invalid(self.valid, "digest mismatch")

    def test_raw_evidence_must_remain_valid_duplicate_free_json(self) -> None:
        target = self.artifact_root / self.valid["scenarios"][6]["evidence_ref"]
        target.write_text('{"capture":"one","capture":"two"}\n', encoding="utf-8")
        self.assert_invalid(self.valid, "duplicate JSON key")

    def test_raw_evidence_reference_reuse_and_extra_inventory_fail(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["scenarios"][1]["evidence_ref"] = changed["scenarios"][0]["evidence_ref"]
        changed["scenarios"][1]["evidence_sha256"] = changed["scenarios"][0]["evidence_sha256"]
        self.assert_invalid(changed, "reused")
        self.raw("unexpected")
        self.assert_invalid(self.valid, "inventory is not exact")

    def test_raw_symlink_and_hardlink_are_rejected(self) -> None:
        target = self.raw_root / "host-attestation.json"
        target.unlink()
        target.symlink_to(self.raw_root / "checkpoint-1.json")
        with self.assertRaises(evidence.MigrationEvidenceError):
            evidence.assemble_evidence(
                self.observations_path,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint=self.openpgp_fingerprint,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256=self.candidate_package_sha256,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )
        target.unlink()
        os.link(self.raw_root / "checkpoint-1.json", target)
        with self.assertRaises(evidence.MigrationEvidenceError):
            evidence.assemble_evidence(
                self.observations_path,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint=self.openpgp_fingerprint,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256=self.candidate_package_sha256,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )

    def test_duplicate_json_keys_and_unknown_fields_fail(self) -> None:
        self.observations_path.write_text('{"schema":"x","schema":"y"}\n', encoding="utf-8")
        with self.assertRaisesRegex(evidence.MigrationEvidenceError, "duplicate JSON key"):
            evidence.assemble_evidence(
                self.observations_path,
                artifact_root=self.artifact_root,
                candidate_sha=self.candidate,
                openpgp_fingerprint=self.openpgp_fingerprint,
                candidate_package_name=self.candidate_package_name,
                candidate_package_sha256=self.candidate_package_sha256,
                candidate_package_size=self.candidate_package_size,
                validation_time=self.validation_time,
            )
        changed = copy.deepcopy(self.valid)
        changed["unexpected"] = True
        self.assert_invalid(changed, "keys are not exact")

    def test_cli_assemble_validate_and_atomic_private_output(self) -> None:
        assembled = self.root / "assembled.json"
        self.assertEqual(
            evidence.main([
                "assemble", "--observations", str(self.observations_path),
                "--artifact-root", str(self.artifact_root), "--candidate-sha", self.candidate,
                "--openpgp-fingerprint", self.openpgp_fingerprint,
                "--candidate-package-name", self.candidate_package_name,
                "--candidate-package-sha256", self.candidate_package_sha256,
                "--candidate-package-size", str(self.candidate_package_size),
                "--output", str(assembled),
            ]),
            0,
        )
        self.assertEqual(stat.S_IMODE(assembled.stat().st_mode), 0o600)
        verdict = self.root / "verdict.json"
        self.assertEqual(
            evidence.main([
                "validate", "--evidence", str(assembled), "--artifact-root", str(self.artifact_root),
                "--candidate-sha", self.candidate,
                "--openpgp-fingerprint", self.openpgp_fingerprint,
                "--candidate-package-name", self.candidate_package_name,
                "--candidate-package-sha256", self.candidate_package_sha256,
                "--candidate-package-size", str(self.candidate_package_size),
                "--output", str(verdict),
            ]),
            0,
        )
        self.assertEqual(json.loads(verdict.read_text(encoding="utf-8"))["status"], "pass")


if __name__ == "__main__":
    unittest.main()
