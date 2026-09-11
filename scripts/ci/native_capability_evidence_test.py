#!/usr/bin/env python3
"""Adversarial tests for the v4.10.0 native capability evidence harness."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_capability_evidence as evidence
except ModuleNotFoundError:
    import native_capability_evidence as evidence


class NativeCapabilityEvidenceTests(unittest.TestCase):
    candidate = "a" * 40
    validation_time = dt.datetime(2026, 9, 10, 8, 20, tzinfo=dt.timezone.utc)
    native_control_ids = (
        "operator-policy-tcp-apply", "operator-policy-udp-apply",
        "operator-policy-concurrent-mutation", "operator-policy-rollback-restart",
        "operator-policy-third-party-preservation", "hids-log-rotation",
        "hids-log-truncation", "hids-log-replacement", "hids-delayed-write",
        "hids-unsafe-path-refusal", "hips-bf-slow", "waap-exploit-severity",
        "waap-deduplication", "waap-backpressure", "waap-non-recursion",
    )
    package_owned_control_ids = (
        "rhelpo-go-runtime-only",
        "rhelpo-package-owned-system-state",
        "rhelpo-first-boot-after-chroot",
    )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        self.signing_bundle = self.root / "signing-bundle"
        self.make_signing_bundle()
        self.verify_bundle_patcher = mock.patch.object(
            evidence.signing_bundle, "verify_bundle"
        )
        self.verify_bundle = self.verify_bundle_patcher.start()
        self.addCleanup(self.verify_bundle_patcher.stop)
        contract = json.loads(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        self.package_bindings = evidence._load_package_bindings(
            self.signing_bundle, self.candidate, contract
        )
        self.attestation = self.root / "host-attestation.json"
        self.campaign = self.root / "campaign.json"
        self.observations = self.root / "observations.json"
        self.evidence_path = self.root / "evidence.json"
        self.artifact_root = self.root / "artifacts"
        raw_root = self.artifact_root / "raw"
        raw_root.mkdir(parents=True)
        self.artifact_digests: dict[str, str] = {}
        for name in (
            "hids",
            "hips",
            "waap",
            "asn",
            "geo",
            "osint",
            "tui-grc",
            "lifecycle-deletion",
            "lifecycle-expiry-trigger",
            "lifecycle-expiry",
            *self.native_control_ids,
            *self.package_owned_control_ids,
        ):
            wire = (json.dumps({"native_capture": name}, sort_keys=True) + "\n").encode("utf-8")
            (raw_root / f"{name}.json").write_bytes(wire)
            self.artifact_digests[name] = hashlib.sha256(wire).hexdigest()
        self.attestation.write_text(
            json.dumps(self.attestation_document(), sort_keys=True) + "\n", encoding="utf-8"
        )
        campaign = evidence.build_campaign(
            candidate_commit=self.candidate,
            campaign_id="standard-deb-u2604-capability-1",
            created_at="2026-09-10T08:00:00Z",
            host_attestation_path=self.attestation,
            signing_bundle_path=self.signing_bundle,
        )
        self.write_json(self.campaign, campaign)
        self.write_json(self.observations, self.observation_document())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, path: Path, document: object) -> None:
        path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")

    def write_manifest(self, path: Path, records: dict[str, bytes]) -> None:
        path.write_text(
            "".join(
                f"{hashlib.sha256(records[name]).hexdigest()}  {name}\n"
                for name in sorted(records)
            ),
            encoding="ascii",
        )

    def make_signing_bundle(self) -> None:
        packages = self.signing_bundle / "packages"
        evidence_root = self.signing_bundle / "evidence"
        rhel_packages = self.signing_bundle / "rhel-package-owned/packages"
        rhel_evidence = self.signing_bundle / "rhel-package-owned/evidence"
        for directory in (packages, evidence_root, rhel_packages, rhel_evidence):
            directory.mkdir(parents=True, exist_ok=True)
        version = "4.10.0"
        names = {
            "deb": f"syswarden_{version}_amd64.deb",
            "rpm": f"syswarden-{version}-1.x86_64.rpm",
            "apk": f"syswarden_{version}_x86_64.apk",
        }
        package_data = {
            "deb": b"qualified-deb-package\n",
            "rpm": b"qualified-standard-rpm-package\n",
            "apk": b"qualified-apk-package\n",
        }
        for family, name in names.items():
            (packages / name).write_bytes(package_data[family])
        rhel_name = f"syswarden-{version}-1.rhelpo.x86_64.rpm"
        rhel_data = b"qualified-rhel-package-owned-rpm\n"
        (rhel_packages / rhel_name).write_bytes(rhel_data)
        rpm_key = {
            "fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
            "id": "rpm-2026",
            "public_key": "native-package-keys/syswarden-rpm-2026.asc",
            "public_key_sha256": "1" * 64,
        }
        deb_key = {
            "fingerprint": "FEDCBA9876543210FEDCBA9876543210FEDCBA98",
            "id": "deb-2026",
            "public_key": "native-package-keys/syswarden-deb-2026.asc",
            "public_key_sha256": "2" * 64,
        }
        apk_key = {
            "fingerprint": "3" * 64,
            "id": "apk-2026",
            "public_key": "native-package-keys/syswarden-apk-2026.rsa.pub",
            "public_key_sha256": "3" * 64,
        }
        signed_records = [
            {
                "name": name,
                "sha256": hashlib.sha256(package_data[family]).hexdigest(),
                "size": len(package_data[family]),
            }
            for family, name in sorted(names.items(), key=lambda item: item[1])
        ]
        signing_run = {
            "attempt": 1,
            "id": 300,
            "workflow": ".github/workflows/native-package-signing.yml",
            "workflow_sha": self.candidate,
        }
        source = {
            "release_sha": self.candidate,
            "release_tag": "v4.10.0",
            "source_date_epoch": 1780000000,
            "unsigned_artifact_digest": "sha256:" + "4" * 64,
            "unsigned_artifact_id": 200,
            "unsigned_artifact_name": "syswarden-packages-4.10.0",
            "unsigned_package_run_id": 100,
        }
        signing = evidence.signing_bundle
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
        standard = {
            "bootstrap_qualification": bootstrap,
            "apk_signature": {
                "exact_unsigned_suffix": True,
                "key": apk_key,
                "signature_entry": ".SIGN.RSA256.syswarden-apk-2026.rsa.pub",
                "signature_prefix_sha256": "5" * 64,
                "signature_prefix_size": 512,
                "signature_sha256": "6" * 64,
            },
            "deb_signature": {
                "bytes_unchanged": True,
                "detached": True,
                "key": deb_key,
                "signature": {
                    "created_at": "2026-09-03T12:00:00Z",
                    "name": "syswarden_4.10.0_amd64.deb.asc",
                    "sha256": "7" * 64,
                    "size": 512,
                },
            },
            "packages": {"signed": signed_records, "unsigned": signed_records},
            "policy_sha256": "8" * 64,
            "profile": evidence.signing_bundle.SCHEMA_PROFILE,
            "public_release": False,
            "release_qualified": False,
            "repository": "duggytuxy/syswarden",
            "rpm_signature": {
                "immutable_header_preserved": True,
                "key": rpm_key,
                "payload_preserved": True,
            },
            "schema_version": 1,
            "signer_image": "registry.example/syswarden/apk-signer@sha256:" + "9" * 64,
            "signing_run": signing_run,
            "source": source,
            "status": evidence.signing_bundle.QUALIFIED_PROVENANCE_STATUS,
        }
        rhel_record = {
            "name": rhel_name,
            "sha256": hashlib.sha256(rhel_data).hexdigest(),
            "size": len(rhel_data),
        }
        rhel = {
            "bootstrap_qualification": copy.deepcopy(bootstrap),
            "package_role": "rhel-package-owned",
            "packages": {"signed": rhel_record, "unsigned": rhel_record},
            "policy_sha256": standard["policy_sha256"],
            "profile": evidence.signing_bundle.RHEL_PACKAGE_OWNED_PROFILE,
            "public_release": False,
            "release_qualified": False,
            "repository": standard["repository"],
            "rpm_identity": {
                "architecture": "x86_64",
                "filename": rhel_name,
                "name": "syswarden",
                "release": "1.rhelpo",
                "version": version,
            },
            "rpm_signature": {
                "immutable_header_preserved": True,
                "key": rpm_key,
                "payload_preserved": True,
            },
            "schema_version": 1,
            "signing_run": signing_run,
            "source": {
                **source,
                "unsigned_artifact_id": 201,
                "unsigned_artifact_name": "syswarden-rhel-package-owned-4.10.0",
            },
            "status": evidence.signing_bundle.QUALIFIED_PROVENANCE_STATUS,
            "updater_manifest_included": False,
        }
        self.write_json(
            evidence_root / "NATIVE_SIGNING_PROVENANCE.json", standard
        )
        self.write_json(rhel_evidence / "SIGNING_PROVENANCE.json", rhel)
        rhel_members = {
            "evidence/SIGNING_PROVENANCE.json": (
                rhel_evidence / "SIGNING_PROVENANCE.json"
            ).read_bytes(),
            f"packages/{rhel_name}": rhel_data,
        }
        rhel_seal = self.signing_bundle / "rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt"
        self.write_manifest(rhel_seal, rhel_members)
        root_members = {
            "evidence/NATIVE_SIGNING_PROVENANCE.json": (
                evidence_root / "NATIVE_SIGNING_PROVENANCE.json"
            ).read_bytes(),
            "rhel-package-owned/evidence/SIGNING_PROVENANCE.json": (
                rhel_evidence / "SIGNING_PROVENANCE.json"
            ).read_bytes(),
            "rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt": rhel_seal.read_bytes(),
            f"rhel-package-owned/packages/{rhel_name}": rhel_data,
        }
        root_members.update(
            {f"packages/{name}": package_data[family] for family, name in names.items()}
        )
        self.write_manifest(
            self.signing_bundle / "SIGNED_ARTIFACT_SHA256SUMS.txt", root_members
        )

    def attestation_document(self, profile_id: str = "DEB-U2604") -> dict[str, object]:
        contract = json.loads(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        profile = next(
            item for item in contract["host_profiles"] if item["id"] == profile_id
        )
        return {
            "schema_version": 1,
            "attestation_id": profile["evidence_namespace"] + "-boot-1",
            "captured_at": "2026-09-10T07:59:00Z",
            "host_id": profile["host_id"],
            "profile_id": profile_id,
            "os_id": profile["os_id"],
            "os_version": profile["os_version"],
            "architecture": "amd64",
            "package_family": profile["package_family"],
            "kernel_release": "6.17.0-generic",
            "boot_id_sha256": "b" * 64,
            "installed_version": "v4.10.0",
            "candidate_commit": self.candidate,
            "package_binding": copy.deepcopy(self.package_bindings[profile_id]),
            "installed_signature_catalog_sha256": self.catalog_sha256(),
        }

    def attack(
        self,
        capability: str,
        rule_id: str,
        category: str,
        origin: str,
        hits: int,
        action: str,
        threshold: int,
        window: int,
        peak: int,
    ) -> dict[str, object]:
        score = evidence._severity_score(category, action, hits, peak, True, threshold)
        if capability == "hips":
            first_observed_at = "2026-09-10T08:01:10Z"
            last_observed_at = "2026-09-10T08:01:20Z"
            enforced_at = "2026-09-10T08:01:20Z"
        else:
            first_observed_at = "2026-09-10T08:04:30Z"
            last_observed_at = "2026-09-10T08:04:30Z"
            enforced_at = "2026-09-10T08:04:31Z"
        return {
            "status": "pass",
            "scenario_id": (
                "hips-native-ssh-bruteforce"
                if capability == "hips"
                else "waap-native-sqli-request"
            ),
            "evidence_ref": f"raw/{capability}.json",
            "evidence_sha256": self.artifact_digests[capability],
            "source_ip": "8.8.8.8",
            "observation_origin": origin,
            "rule_id": rule_id,
            "first_observed_at": first_observed_at,
            "last_observed_at": last_observed_at,
            "enforced_at": enforced_at,
            "risk_category": category,
            "rule_action": action,
            "effective_threshold": threshold,
            "effective_window_seconds": window,
            "observed_events": hits,
            "admitted_events": hits,
            "rejected_events": 0,
            "excluded_events": 0,
            "physical_hits": hits,
            "jail_hits": hits,
            "policy_hits": hits,
            "peak_window_hits": peak,
            "threshold_reached": True,
            "threshold_evidence": "observed-window" if action == "track" else "immediate-rule",
            "enforcement_action": "BANNED",
            "severity_score": score,
            "severity_label": evidence._severity_label(score),
        }

    def lifecycle_state(self, name: str, observed_at: str) -> dict[str, object]:
        return {
            "state": name,
            "observed_at": observed_at,
            "active": int(name == "active"),
            "expired": int(name == "expired"),
            "deleted": int(name == "deleted"),
            "tombstoned": int(name == "tombstoned"),
            "currently_blocked": name == "active",
            "tui_registry_visible": name == "active",
            "tui_history_visible": True,
            "grc_state": name,
            "runtime_state_linked": True,
        }

    def observation_document(
        self, profile_id: str = "DEB-U2604"
    ) -> dict[str, object]:
        hips = self.attack(
            "hips", "ssh-auth", "brute_force", "real-controlled-network-attempts",
            4, "track", 4, 60, 4,
        )
        waap = self.attack(
            "waap", "sqli", "exploit", "real-controlled-http-request",
            1, "ban", 1, 0, 0,
        )
        selected = hips
        contract = json.loads(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        controls = []
        expected_controls = list(contract["native_controls"])
        if profile_id.endswith("-RHELPO"):
            expected_controls.extend(contract["package_owned_controls"])
        for index, expected in enumerate(expected_controls):
            control_id = expected["id"]
            controls.append({
                "id": control_id,
                "status": "pass",
                "candidate_commit": self.candidate,
                "observed_at": f"2026-09-10T08:01:{1 + index * 3:02d}Z",
                "evidence_ref": f"raw/{control_id}.json",
                "evidence_sha256": self.artifact_digests[control_id],
                "assertions": expected["assertions"],
            })
        capabilities = {
            "hids": {
                "status": "pass",
                "scenario_id": "hids-native-auth-log-detection",
                "evidence_ref": "raw/hids.json",
                "evidence_sha256": self.artifact_digests["hids"],
                "source_ip": "8.8.8.8",
                "observation_origin": "native-authentication-journal",
                "transport": "rsyslog-imfile-to-uds",
                "rule_id": "ssh-auth",
                "first_observed_at": "2026-09-10T08:01:10Z",
                "last_observed_at": "2026-09-10T08:01:20Z",
                "observed_events": 4,
                "matched_events": 4,
                "rejected_events": 0,
            },
            "hips": hips,
            "waap": waap,
            "extended_controls": {
                "status": "pass",
                "scenario_id": "native-extended-controls",
                "controls": controls,
            },
            "asn": {
                "status": "pass",
                "scenario_id": "asn-attested-enrichment",
                "evidence_ref": "raw/asn.json",
                "evidence_sha256": self.artifact_digests["asn"],
                "source_ip": "8.8.8.8",
                "provider": "ip.wiredalter.com",
                "lookup_count": 1,
                "value": "AS15169",
                "tui_value": "AS15169",
                "verified": True,
            },
            "geo": {
                "status": "pass",
                "scenario_id": "geo-attested-enrichment",
                "evidence_ref": "raw/geo.json",
                "evidence_sha256": self.artifact_digests["geo"],
                "source_ip": "8.8.8.8",
                "provider": "ip.wiredalter.com",
                "lookup_count": 1,
                "value": "US",
                "tui_value": "US",
                "verified": True,
            },
            "osint": {
                "status": "pass",
                "scenario_id": "osint-history-enrichment",
                "evidence_ref": "raw/osint.json",
                "evidence_sha256": self.artifact_digests["osint"],
                "source_ip": "8.8.8.8",
                "provider": "ip.wiredalter.com",
                "history_hits": 5,
                "country": "US",
                "asn": "AS15169",
                "organization": "Google LLC",
                "threat": "controlled-lab-source",
                "tui_country": "US",
                "tui_asn": "AS15169",
                "tui_organization": "Google LLC",
                "tui_threat": "controlled-lab-source",
            },
            "tui_grc": {
                "status": "pass",
                "scenario_id": "tui-grc-kpi-coherence",
                "evidence_ref": "raw/tui-grc.json",
                "evidence_sha256": self.artifact_digests["tui-grc"],
                "source_ip": "8.8.8.8",
                "physical_hits": 5,
                "selected_jail": selected["rule_id"],
                "jail_hits": selected["jail_hits"],
                "policy_hits": selected["policy_hits"],
                "tui_hits": 5,
                "grc_hits": 5,
                "tui_severity_score": selected["severity_score"],
                "grc_severity_score": selected["severity_score"],
                "tui_severity_label": selected["severity_label"],
                "grc_severity_label": selected["severity_label"],
                "metric_quality": "attested",
                "policy_quality": "attested",
                "hit_quality": "measured",
                "degraded_hits": 0,
                "catalog_version": "sw-signatures-v1",
                "catalog_sha256": self.catalog_sha256(),
                "risk_model_version": "sw-risk-v1",
            },
        }
        return {
            "started_at": "2026-09-10T08:01:00Z",
            "completed_at": "2026-09-10T08:10:00Z",
            "guardrails": {
                "authentication_journal_access": "read-only",
                "authentication_event_source": "real-controlled-network-attempts",
                "synthetic_authentication_journal_writes": False,
                "native_lab_executed": True,
                "host_changes": "native-lab-only-ephemeral-and-restored",
                "baseline_restored": True,
            },
            "capabilities": capabilities,
            "lifecycle": [
                {
                    "id": "manual-deletion",
                    "binding_type": "bound-attack",
                    "capability": "hips",
                    "scenario_id": "hips-native-ssh-bruteforce",
                    "source_ip": "8.8.8.8",
                    "rule_id": "ssh-auth",
                    "attack_evidence_sha256": self.artifact_digests["hips"],
                    "evidence_ref": "raw/lifecycle-deletion.json",
                    "evidence_sha256": self.artifact_digests["lifecycle-deletion"],
                    "states": [
                        self.lifecycle_state("active", "2026-09-10T08:02:00Z"),
                        self.lifecycle_state("deleted", "2026-09-10T08:03:00Z"),
                        self.lifecycle_state("tombstoned", "2026-09-10T08:04:00Z"),
                    ],
                },
                {
                    "id": "ttl-expiry",
                    "binding_type": "controlled-temporary-ban",
                    "source_ip": "8.8.4.4",
                    "source_controlled": True,
                    "source": "native-capability-lab",
                    "requested_ttl_seconds": 60,
                    "requested_at": "2026-09-10T08:04:50Z",
                    "enforced_at": "2026-09-10T08:05:00Z",
                    "trigger_evidence_ref": "raw/lifecycle-expiry-trigger.json",
                    "trigger_evidence_sha256": self.artifact_digests[
                        "lifecycle-expiry-trigger"
                    ],
                    "evidence_ref": "raw/lifecycle-expiry.json",
                    "evidence_sha256": self.artifact_digests["lifecycle-expiry"],
                    "states": [
                        self.lifecycle_state("active", "2026-09-10T08:05:00Z"),
                        self.lifecycle_state("expired", "2026-09-10T08:06:00Z"),
                        self.lifecycle_state("tombstoned", "2026-09-10T08:07:00Z"),
                    ],
                },
            ],
        }

    def catalog_sha256(self) -> str:
        return hashlib.sha256(evidence.DEFAULT_SIGNATURE_CATALOG.read_bytes()).hexdigest()

    def build_evidence(self) -> dict[str, object]:
        return evidence.build_bound_evidence(
            candidate_commit=self.candidate,
            campaign_path=self.campaign,
            observations_path=self.observations,
            artifact_root=self.artifact_root,
            host_attestation_path=self.attestation,
            signing_bundle_path=self.signing_bundle,
            validation_time=self.validation_time,
        )

    def assert_invalid_observations(self, document: dict[str, object], pattern: str) -> None:
        self.write_json(self.observations, document)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, pattern):
            self.build_evidence()

    def test_valid_native_observations_bind_and_validate(self) -> None:
        document = self.build_evidence()
        self.write_json(self.evidence_path, document)
        report = evidence.validate_evidence_file(
            candidate_commit=self.candidate,
            campaign_path=self.campaign,
            evidence_path=self.evidence_path,
            artifact_root=self.artifact_root,
            host_attestation_path=self.attestation,
            signing_bundle_path=self.signing_bundle,
            validation_time=self.validation_time,
        )
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["profile_id"], "DEB-U2604")
        self.assertEqual(
            report["capabilities"],
            ["hids", "hips", "waap", "asn", "geo", "osint", "tui_grc", "extended_controls"],
        )
        self.assertEqual(
            report["lifecycle_sequences"], ["manual-deletion", "ttl-expiry"]
        )
        self.assertRegex(report["campaign_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["evidence_sha256"], r"^[0-9a-f]{64}$")

    def test_contract_has_exact_distinct_standard_and_package_owned_profiles(self) -> None:
        contract, _ = evidence.load_contract()
        self.assertEqual(
            [profile["id"] for profile in contract["host_profiles"]],
            [
                "DEB-13",
                "DEB-U2604",
                "RPM-A10",
                "APK-324",
                "RPM-A9-RHELPO",
                "RPM-A10-RHELPO",
            ],
        )
        package_owned = contract["host_profiles"][-2:]
        self.assertEqual(
            [
                (
                    profile["host_id"],
                    profile["os_id"],
                    profile["os_version"],
                    profile["package_variant"],
                    profile["evidence_namespace"],
                )
                for profile in package_owned
            ],
            [
                ("node05", "almalinux", "9.8", "package-owned", "rhelpo-rpm-a9"),
                ("node03", "almalinux", "10.2", "package-owned", "rhelpo-rpm-a10"),
            ],
        )

    def test_package_owned_profiles_bind_all_capabilities_to_sealed_rpm(self) -> None:
        expected_capabilities = [
            "hids",
            "hips",
            "waap",
            "asn",
            "geo",
            "osint",
            "tui_grc",
            "extended_controls",
        ]
        for profile_id, namespace in (
            ("RPM-A9-RHELPO", "rhelpo-rpm-a9"),
            ("RPM-A10-RHELPO", "rhelpo-rpm-a10"),
        ):
            with self.subTest(profile_id=profile_id):
                self.write_json(
                    self.attestation, self.attestation_document(profile_id)
                )
                campaign = evidence.build_campaign(
                    candidate_commit=self.candidate,
                    campaign_id=namespace + "-capability-1",
                    created_at="2026-09-10T08:00:00Z",
                    host_attestation_path=self.attestation,
                    signing_bundle_path=self.signing_bundle,
                )
                self.write_json(
                    self.observations, self.observation_document(profile_id)
                )
                binding = campaign["host"]["package_binding"]
                self.assertEqual(binding["package_variant"], "package-owned")
                self.assertEqual(
                    binding["filename"],
                    "syswarden-4.10.0-1.rhelpo.x86_64.rpm",
                )
                self.assertEqual(binding["rpm_identity"]["name"], "syswarden")
                self.assertEqual(binding["rpm_identity"]["release"], "1.rhelpo")
                self.assertEqual(binding["signature"]["mechanism"], "rpm-openpgp")
                self.assertRegex(
                    binding["signature"]["key"]["fingerprint"],
                    r"^[0-9A-F]{40}$",
                )
                self.assertRegex(
                    binding["signed_subbundle_seal_sha256"], r"^[0-9a-f]{64}$"
                )
                self.write_json(self.campaign, campaign)
                document = self.build_evidence()
                self.write_json(self.evidence_path, document)
                verdict = evidence.validate_evidence_file(
                    candidate_commit=self.candidate,
                    campaign_path=self.campaign,
                    evidence_path=self.evidence_path,
                    artifact_root=self.artifact_root,
                    host_attestation_path=self.attestation,
                    signing_bundle_path=self.signing_bundle,
                    validation_time=self.validation_time,
                )
                self.assertEqual(verdict["profile_id"], profile_id)
                self.assertEqual(verdict["evidence_namespace"], namespace)
                self.assertEqual(verdict["package_binding"], binding)
                self.assertEqual(verdict["capabilities"], expected_capabilities)
                self.assertEqual(
                    [
                        item["id"]
                        for item in document["capabilities"]["extended_controls"][
                            "controls"
                        ][-3:]
                    ],
                    list(self.package_owned_control_ids),
                )

    def test_package_owned_attestation_refuses_standard_or_forged_binding(self) -> None:
        profile_id = "RPM-A9-RHELPO"
        correct = self.attestation_document(profile_id)
        mutations = []
        changed = copy.deepcopy(correct)
        changed["package_binding"] = copy.deepcopy(self.package_bindings["RPM-A10"])
        mutations.append(changed)
        for path, value in (
            (("package_variant",), "standard"),
            (("filename",), "syswarden-4.10.0-1.x86_64.rpm"),
            (("sha256",), "0" * 64),
            (("size",), correct["package_binding"]["size"] + 1),
            (("rpm_identity", "release"), "1"),
            (("signature", "key", "fingerprint"), "A" * 40),
            (("signing_provenance_sha256",), "b" * 64),
            (("signed_subbundle_seal_sha256",), "c" * 64),
        ):
            changed = copy.deepcopy(correct)
            target = changed["package_binding"]
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = value
            mutations.append(changed)
        for changed in mutations:
            with self.subTest(binding=changed["package_binding"]):
                self.write_json(self.attestation, changed)
                with self.assertRaisesRegex(
                    evidence.NativeCapabilityEvidenceError,
                    "differs from signed provenance",
                ):
                    evidence.build_campaign(
                        candidate_commit=self.candidate,
                        campaign_id="rhelpo-rpm-a9-capability-forged",
                        created_at="2026-09-10T08:00:00Z",
                        host_attestation_path=self.attestation,
                        signing_bundle_path=self.signing_bundle,
                    )

    def test_package_owned_campaign_and_attestation_namespaces_are_isolated(self) -> None:
        attestation = self.attestation_document("RPM-A10-RHELPO")
        attestation["attestation_id"] = "standard-rpm-a10-boot-reused"
        self.write_json(self.attestation, attestation)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "outside its profile namespace"
        ):
            evidence.build_campaign(
                candidate_commit=self.candidate,
                campaign_id="rhelpo-rpm-a10-capability-1",
                created_at="2026-09-10T08:00:00Z",
                host_attestation_path=self.attestation,
                signing_bundle_path=self.signing_bundle,
            )
        attestation = self.attestation_document("RPM-A10-RHELPO")
        self.write_json(self.attestation, attestation)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "campaign identifier is outside its profile namespace",
        ):
            evidence.build_campaign(
                candidate_commit=self.candidate,
                campaign_id="standard-rpm-a10-capability-reused",
                created_at="2026-09-10T08:00:00Z",
                host_attestation_path=self.attestation,
                signing_bundle_path=self.signing_bundle,
            )

    def test_package_binding_requires_verified_qualified_and_untampered_bundle(self) -> None:
        contract, _ = evidence.load_contract()
        self.verify_bundle.reset_mock()
        evidence._load_package_bindings(
            self.signing_bundle, self.candidate, contract
        )
        self.verify_bundle.assert_called_once_with(
            self.signing_bundle, "v4.10.0", self.candidate
        )

        self.verify_bundle.side_effect = evidence.signing_bundle.SigningBundleError(
            "verification refused"
        )
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "native signing bundle verification failed",
        ):
            evidence._load_package_bindings(
                self.signing_bundle, self.candidate, contract
            )
        self.verify_bundle.side_effect = None

        rhel_provenance_path = (
            self.signing_bundle
            / "rhel-package-owned/evidence/SIGNING_PROVENANCE.json"
        )
        rhel = json.loads(rhel_provenance_path.read_text(encoding="utf-8"))
        rhel["rpm_identity"]["release"] = "1"
        self.write_json(rhel_provenance_path, rhel)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "qualified signing provenance|signed seal"
        ):
            evidence._load_package_bindings(
                self.signing_bundle, self.candidate, contract
            )

    def test_bootstrap_reference_is_required_and_validated_for_each_package_role(self) -> None:
        contract, _ = evidence.load_contract()
        paths = (
            self.signing_bundle / "evidence/NATIVE_SIGNING_PROVENANCE.json",
            self.signing_bundle / "rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
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
                    with self.assertRaisesRegex(
                        evidence.NativeCapabilityEvidenceError,
                        "keys are not exact|bootstrap qualification is invalid",
                    ):
                        evidence._load_package_bindings(
                            self.signing_bundle, self.candidate, contract
                        )
            self.write_json(path, original)

    def test_bootstrap_signing_provenance_is_not_capability_qualification(self) -> None:
        contract, _ = evidence.load_contract()
        standard_path = self.signing_bundle / "evidence/NATIVE_SIGNING_PROVENANCE.json"
        standard = json.loads(standard_path.read_text(encoding="utf-8"))
        standard["status"] = evidence.signing_bundle.BOOTSTRAP_PROVENANCE_STATUS
        self.write_json(standard_path, standard)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "requires the qualified signing provenance",
        ):
            evidence._load_package_bindings(
                self.signing_bundle, self.candidate, contract
            )

    def test_bind_and_validate_cli_create_private_outputs(self) -> None:
        bound = self.root / "cli-evidence.json"
        verdict = self.root / "cli-verdict.json"
        common = [
            "--candidate-commit",
            self.candidate,
            "--campaign",
            str(self.campaign),
            "--artifact-root",
            str(self.artifact_root),
            "--host-attestation",
            str(self.attestation),
            "--signing-bundle",
            str(self.signing_bundle),
            "--validation-time",
            "2026-09-10T08:20:00Z",
        ]
        self.assertEqual(
            evidence.main(
                [
                    "bind",
                    *common,
                    "--observations",
                    str(self.observations),
                    "--output",
                    str(bound),
                ]
            ),
            0,
        )
        self.assertEqual(
            evidence.main(
                [
                    "validate",
                    *common,
                    "--evidence",
                    str(bound),
                    "--output",
                    str(verdict),
                ]
            ),
            0,
        )
        self.assertEqual(bound.stat().st_mode & 0o777, 0o600)
        self.assertEqual(verdict.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(verdict.read_text(encoding="utf-8"))["verdict"], "pass")

    def test_duplicate_and_unknown_json_are_rejected(self) -> None:
        self.observations.write_text(
            '{"started_at":"2026-09-10T08:01:00Z","started_at":"2026-09-10T08:02:00Z"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "duplicate JSON key"):
            self.build_evidence()

        changed = self.observation_document()
        changed["capabilities"]["hids"]["unknown"] = True
        self.assert_invalid_observations(changed, "keys are not exact")

        self.observations.write_text(
            '{"started_at":NaN}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "non-standard JSON constant"
        ):
            self.build_evidence()

    def test_candidate_and_sha_bindings_are_rejected_when_mismatched(self) -> None:
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "candidate_commit binding"):
            evidence.build_bound_evidence(
                candidate_commit="9" * 40,
                campaign_path=self.campaign,
                observations_path=self.observations,
                artifact_root=self.artifact_root,
                host_attestation_path=self.attestation,
                signing_bundle_path=self.signing_bundle,
                validation_time=self.validation_time,
            )

        campaign = json.loads(self.campaign.read_text(encoding="utf-8"))
        campaign["host"]["attestation_sha256"] = "0" * 64
        self.write_json(self.campaign, campaign)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "attestation SHA binding"):
            self.build_evidence()

    def test_installed_signature_catalog_must_match_candidate_catalog(self) -> None:
        attestation = json.loads(self.attestation.read_text(encoding="utf-8"))
        attestation["installed_signature_catalog_sha256"] = "0" * 64
        self.write_json(self.attestation, attestation)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "installed signature catalog binding is invalid",
        ):
            evidence.build_campaign(
                candidate_commit=self.candidate,
                campaign_id="standard-deb-u2604-capability-2",
                created_at="2026-09-10T08:00:00Z",
                host_attestation_path=self.attestation,
                signing_bundle_path=self.signing_bundle,
            )

    def test_referenced_artifact_sha_mismatch_is_rejected(self) -> None:
        (self.artifact_root / "raw/hips.json").write_text(
            '{"native_capture":"tampered"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "SHA-256 mismatch"):
            self.build_evidence()

    def test_artifact_references_and_directory_chain_are_safe(self) -> None:
        changed = self.observation_document()
        changed["capabilities"]["asn"]["evidence_ref"] = changed["capabilities"]["geo"][
            "evidence_ref"
        ]
        changed["capabilities"]["asn"]["evidence_sha256"] = changed["capabilities"]["geo"][
            "evidence_sha256"
        ]
        self.assert_invalid_observations(changed, "references are duplicated")
        self.write_json(self.observations, self.observation_document())

        original_raw = self.artifact_root / "raw"
        moved_raw = self.artifact_root / "raw-private"
        original_raw.rename(moved_raw)
        original_raw.symlink_to(moved_raw, target_is_directory=True)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "must be a real directory"
        ):
            self.build_evidence()

        artifact_link = self.root / "artifact-link"
        artifact_link.symlink_to(self.artifact_root, target_is_directory=True)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "must be a real directory"
        ):
            evidence.build_bound_evidence(
                candidate_commit=self.candidate,
                campaign_path=self.campaign,
                observations_path=self.observations,
                artifact_root=artifact_link,
                host_attestation_path=self.attestation,
                signing_bundle_path=self.signing_bundle,
                validation_time=self.validation_time,
            )

    def test_missing_capability_and_inconsistent_counts_are_rejected(self) -> None:
        changed = self.observation_document()
        del changed["capabilities"]["waap"]
        self.assert_invalid_observations(changed, "capabilities.*not exact")

        changed = self.observation_document()
        changed["capabilities"]["hips"]["physical_hits"] = 3
        self.assert_invalid_observations(changed, "counters are inconsistent")

        changed = self.observation_document()
        changed["capabilities"]["tui_grc"]["grc_hits"] = 4
        self.assert_invalid_observations(changed, "grc_hits.*inconsistent")

    def test_extended_native_controls_are_exact_ordered_and_candidate_bound(self) -> None:
        mutations = []
        changed = self.observation_document()
        changed["capabilities"]["extended_controls"]["controls"][0]["candidate_commit"] = "b" * 40
        mutations.append((changed, "binding is invalid"))
        changed = self.observation_document()
        changed["capabilities"]["extended_controls"]["controls"][0]["assertions"]["protocol"] = "udp"
        mutations.append((changed, "binding is invalid"))
        changed = self.observation_document()
        changed["capabilities"]["extended_controls"]["controls"][1]["observed_at"] = changed["capabilities"]["extended_controls"]["controls"][0]["observed_at"]
        mutations.append((changed, "ordered campaign time"))
        changed = self.observation_document()
        changed["capabilities"]["extended_controls"]["controls"].pop()
        mutations.append((changed, "inventory is not exact"))
        changed = self.observation_document()
        changed["capabilities"]["extended_controls"]["controls"][0]["unknown"] = True
        mutations.append((changed, "keys are not exact"))
        for document, message in mutations:
            with self.subTest(message=message):
                self.assert_invalid_observations(document, message)

    def test_hids_must_bind_to_the_native_hips_observation(self) -> None:
        mutations = (
            ("source_ip", "8.8.4.4"),
            ("rule_id", "other-rule"),
            ("observed_events", 5),
            ("matched_events", 3),
            ("observation_origin", "synthetic-file"),
            ("transport", "direct-write"),
            ("first_observed_at", "2026-09-10T08:01:11Z"),
            ("last_observed_at", "2026-09-10T08:01:21Z"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = self.observation_document()
                changed["capabilities"]["hids"][field] = value
                self.assert_invalid_observations(changed, rf"hids\.{field} is invalid")

    def test_attack_timeline_and_lifecycle_bindings_are_exact(self) -> None:
        changed = self.observation_document()
        changed["capabilities"]["hips"]["last_observed_at"] = "2026-09-10T08:01:09Z"
        self.assert_invalid_observations(changed, "observation times are incoherent")

        changed = self.observation_document()
        changed["lifecycle"][0]["capability"] = "waap"
        self.assert_invalid_observations(changed, "capability binding is invalid")

        changed = self.observation_document()
        changed["lifecycle"][1]["requested_ttl_seconds"] = 61
        self.assert_invalid_observations(changed, "requested_ttl_seconds binding is invalid")

        changed = self.observation_document()
        changed["lifecycle"][1]["source_ip"] = "8.8.8.8"
        self.assert_invalid_observations(changed, "independent from attack bans")

        changed = self.observation_document()
        changed["lifecycle"][0]["states"][2]["observed_at"] = "2026-09-10T08:04:40Z"
        self.assert_invalid_observations(
            changed, "WAAP observation begins before the HIPS ban deletion is complete"
        )

        changed = self.observation_document()
        changed["lifecycle"][1]["states"][0]["observed_at"] = "2026-09-10T08:04:30Z"
        self.assert_invalid_observations(
            changed, "begins before its bound enforcement"
        )

        changed = self.observation_document()
        changed["lifecycle"][1]["states"][1]["observed_at"] = "2026-09-10T08:05:59Z"
        self.assert_invalid_observations(changed, "expires before its requested TTL")

    def test_forged_timestamps_are_rejected(self) -> None:
        changed = self.observation_document()
        changed["completed_at"] = "2026-09-10T08:30:00Z"
        self.assert_invalid_observations(changed, "future")

        changed = self.observation_document()
        changed["started_at"] = "2026-09-10T07:59:59Z"
        self.assert_invalid_observations(changed, "timestamps are incoherent")

        changed = self.observation_document()
        changed["lifecycle"][0]["states"][1]["observed_at"] = "2026-09-10T08:01:30Z"
        self.assert_invalid_observations(changed, "ordered campaign time")

    def test_oversized_symlink_and_hardlink_inputs_are_rejected(self) -> None:
        oversized = self.root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(1048577)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "outside bounds"):
            evidence._load_json(oversized, 1048576, "oversized")

        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(target)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "regular file"):
            evidence._load_json(symlink, 1048576, "symlink")
        hardlink = self.root / "hardlink.json"
        os.link(target, hardlink)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "regular file"):
            evidence._load_json(target, 1048576, "hardlink")

        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        (real_parent / "input.json").write_text("{}\n", encoding="utf-8")
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "real directory"):
            evidence._load_json(linked_parent / "input.json", 1048576, "linked-parent")

    def test_open_directory_descriptor_anchors_input_against_parent_replacement(self) -> None:
        stable = self.root / "stable"
        stable.mkdir()
        (stable / "input.json").write_text('{"source":"original"}\n', encoding="utf-8")
        descriptor, _, _ = evidence._open_real_directory(stable, "stable input parent")
        try:
            moved = self.root / "moved"
            stable.rename(moved)
            stable.mkdir()
            (stable / "input.json").write_text('{"source":"replacement"}\n', encoding="utf-8")
            wire = evidence._read_regular_bytes_at(
                descriptor, "input.json", "stable/input.json", 1024
            )
        finally:
            os.close(descriptor)
        self.assertEqual(json.loads(wire), {"source": "original"})

    def test_same_size_concurrent_input_mutation_is_rejected(self) -> None:
        changing = self.root / "changing.bin"
        changing.write_bytes(b"a" * 70000)
        original_read = evidence.os.read
        mutated = False

        def read_then_mutate(descriptor: int, count: int) -> bytes:
            nonlocal mutated
            chunk = original_read(descriptor, count)
            if not mutated:
                mutated = True
                with changing.open("r+b") as stream:
                    stream.seek(65536)
                    stream.write(b"b")
                    stream.flush()
                    os.fsync(stream.fileno())
            return chunk

        with mock.patch.object(evidence.os, "read", side_effect=read_then_mutate):
            with self.assertRaisesRegex(
                evidence.NativeCapabilityEvidenceError, "changed while reading"
            ):
                evidence._read_regular_bytes(changing, 100000)

    def test_artifact_parent_replacement_during_read_is_rejected(self) -> None:
        observations = self.observation_document()
        original_read = evidence.os.read
        replaced = False

        def read_then_replace(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            chunk = original_read(descriptor, count)
            if not replaced:
                replaced = True
                raw = self.artifact_root / "raw"
                raw.rename(self.artifact_root / "raw-opened")
                raw.mkdir()
                (raw / "hids.json").write_text(
                    '{"native_capture":"replacement"}\n', encoding="utf-8"
                )
            return chunk

        with mock.patch.object(evidence.os, "read", side_effect=read_then_replace):
            with self.assertRaisesRegex(
                evidence.NativeCapabilityEvidenceError,
                "artifact directory.*changed during operation",
            ):
                evidence._validate_evidence_artifacts(
                    observations,
                    self.artifact_root,
                    1048576,
                )

    def test_lifecycle_deletion_expiry_and_tombstone_incoherence_is_rejected(self) -> None:
        mutations = (
            lambda item: item["lifecycle"][0]["states"][1].__setitem__("state", "expired"),
            lambda item: item["lifecycle"][1]["states"][1].__setitem__("deleted", 1),
            lambda item: item["lifecycle"][0]["states"][2].__setitem__("currently_blocked", True),
            lambda item: item["lifecycle"][1]["states"][2].__setitem__("runtime_state_linked", False),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = self.observation_document()
                mutate(changed)
                self.assert_invalid_observations(changed, "lifecycle")

    def test_signature_policy_and_severity_are_candidate_derived(self) -> None:
        changed = self.observation_document()
        changed["capabilities"]["waap"]["rule_action"] = "detect"
        self.assert_invalid_observations(changed, "candidate catalog")

        changed = self.observation_document()
        changed["capabilities"]["hips"]["severity_score"] = 79
        self.assert_invalid_observations(changed, "severity")

    def test_public_source_and_enrichment_identifiers_are_canonical(self) -> None:
        for address in ("::ffff:808:808", "ff0e::1"):
            with self.subTest(address=address):
                changed = self.observation_document()
                changed["capabilities"]["hips"]["source_ip"] = address
                self.assert_invalid_observations(changed, "canonical public address")

        changed = self.observation_document()
        changed["capabilities"]["geo"]["value"] = "12"
        changed["capabilities"]["geo"]["tui_value"] = "12"
        self.assert_invalid_observations(changed, "uppercase country code")

        changed = self.observation_document()
        changed["capabilities"]["asn"]["value"] = "AS4294967296"
        changed["capabilities"]["asn"]["tui_value"] = "AS4294967296"
        self.assert_invalid_observations(changed, "canonical ASN")

    def test_guardrail_forbids_synthetic_authentication_journal_writes(self) -> None:
        changed = self.observation_document()
        changed["guardrails"]["synthetic_authentication_journal_writes"] = True
        self.assert_invalid_observations(changed, "guardrails")

    def test_output_is_new_private_and_symlink_safe(self) -> None:
        output = self.root / "output.json"
        evidence._write_new_json(output, {"status": "bound"})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "already exist"):
            evidence._write_new_json(output, {})
        output.unlink()
        target = self.root / "operator-data"
        target.write_text("keep\n", encoding="utf-8")
        output.symlink_to(target)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "already exist"):
            evidence._write_new_json(output, {})
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

        real_parent = self.root / "real-output-parent"
        real_parent.mkdir()
        linked_parent = self.root / "linked-output-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "real directory"):
            evidence._write_new_json(linked_parent / "output.json", {})
        self.assertFalse((real_parent / "output.json").exists())

        oversized_output = self.root / "oversized-output.json"
        with self.assertRaisesRegex(evidence.NativeCapabilityEvidenceError, "size is outside bounds"):
            evidence._write_new_json(
                oversized_output, {"payload": "x" * evidence.OUTPUT_MAXIMUM_BYTES}
            )
        self.assertFalse(oversized_output.exists())

    def test_output_parent_replacement_fails_without_redirecting_output(self) -> None:
        output_parent = self.root / "swappable-output-parent"
        output_parent.mkdir()
        output = output_parent / "output.json"
        moved_parent = self.root / "opened-output-parent"
        original_link = evidence.os.link
        replaced = False

        def link_then_replace(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            original_link(*args, **kwargs)
            if not replaced:
                replaced = True
                output_parent.rename(moved_parent)
                output_parent.mkdir()

        with mock.patch.object(evidence.os, "link", side_effect=link_then_replace):
            with self.assertRaisesRegex(
                evidence.NativeCapabilityEvidenceError,
                "output parent changed during operation",
            ):
                evidence._write_new_json(output, {"status": "bound"})
        self.assertFalse(output.exists())
        self.assertFalse((moved_parent / "output.json").exists())

    def test_aggregate_requires_exact_native_profile_inventory(self) -> None:
        document = self.build_evidence()
        self.write_json(self.evidence_path, document)
        base = evidence.validate_evidence_file(
            candidate_commit=self.candidate,
            campaign_path=self.campaign,
            evidence_path=self.evidence_path,
            artifact_root=self.artifact_root,
            host_attestation_path=self.attestation,
            signing_bundle_path=self.signing_bundle,
            validation_time=self.validation_time,
        )
        profiles = [
            "DEB-13",
            "DEB-U2604",
            "RPM-A10",
            "APK-324",
            "RPM-A9-RHELPO",
            "RPM-A10-RHELPO",
        ]
        contract = json.loads(evidence.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        profile_records = {item["id"]: item for item in contract["host_profiles"]}
        paths: list[Path] = []
        for index, profile in enumerate(profiles):
            verdict = copy.deepcopy(base)
            verdict["profile_id"] = profile
            profile_record = profile_records[profile]
            verdict["host_id"] = profile_record["host_id"]
            verdict["evidence_namespace"] = profile_record["evidence_namespace"]
            verdict["campaign_id"] = (
                profile_record["evidence_namespace"] + f"-campaign-{index + 1}"
            )
            verdict["package_binding"] = copy.deepcopy(
                self.package_bindings[profile]
            )
            verdict["host_attestation_sha256"] = f"{index + 9:x}" * 64
            verdict["campaign_sha256"] = f"{index + 1:x}" * 64
            verdict["evidence_sha256"] = f"{index + 5:x}" * 64
            verdict["evidence_artifact_set_sha256"] = f"{index + 10:x}" * 64
            path = self.root / f"verdict-{index}.json"
            self.write_json(path, verdict)
            paths.append(path)
        aggregate = evidence.aggregate_verdicts(
            candidate_commit=self.candidate,
            verdict_paths=list(reversed(paths)),
            signing_bundle_path=self.signing_bundle,
        )
        self.assertEqual(aggregate["verdict"], "pass")
        self.assertEqual(
            [item["profile_id"] for item in aggregate["profiles"]], profiles
        )

        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "inventory is incomplete"
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths[:-1],
                signing_bundle_path=self.signing_bundle,
            )
        wrong_host = json.loads(paths[0].read_text(encoding="utf-8"))
        wrong_host["host_id"] = "node99"
        self.write_json(paths[0], wrong_host)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "host is not bound to its profile"
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths,
                signing_bundle_path=self.signing_bundle,
            )
        wrong_host["host_id"] = profile_records[profiles[0]]["host_id"]
        self.write_json(paths[0], wrong_host)

        reused_evidence = json.loads(paths[1].read_text(encoding="utf-8"))
        reused_evidence["evidence_sha256"] = wrong_host["evidence_sha256"]
        self.write_json(paths[1], reused_evidence)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "attestation, campaign, evidence, or raw artifact set is duplicated",
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths,
                signing_bundle_path=self.signing_bundle,
            )
        reused_evidence["evidence_sha256"] = "6" * 64
        self.write_json(paths[1], reused_evidence)

        reused_raw = json.loads(paths[4].read_text(encoding="utf-8"))
        standard_rpm = json.loads(paths[2].read_text(encoding="utf-8"))
        reused_raw["evidence_artifact_set_sha256"] = standard_rpm[
            "evidence_artifact_set_sha256"
        ]
        self.write_json(paths[4], reused_raw)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "raw artifact set is duplicated"
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths,
                signing_bundle_path=self.signing_bundle,
            )
        reused_raw["evidence_artifact_set_sha256"] = "e" * 64
        self.write_json(paths[4], reused_raw)

        reused_binding = json.loads(paths[4].read_text(encoding="utf-8"))
        reused_binding["package_binding"] = standard_rpm["package_binding"]
        self.write_json(paths[4], reused_binding)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError,
            "package_binding differs from signed provenance",
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths,
                signing_bundle_path=self.signing_bundle,
            )
        reused_binding["package_binding"] = copy.deepcopy(
            self.package_bindings["RPM-A9-RHELPO"]
        )
        self.write_json(paths[4], reused_binding)

        duplicate = json.loads(paths[-1].read_text(encoding="utf-8"))
        duplicate["profile_id"] = "RPM-A10"
        self.write_json(paths[-1], duplicate)
        with self.assertRaisesRegex(
            evidence.NativeCapabilityEvidenceError, "unknown or duplicated"
        ):
            evidence.aggregate_verdicts(
                candidate_commit=self.candidate,
                verdict_paths=paths,
                signing_bundle_path=self.signing_bundle,
            )

    def test_harness_contains_no_native_execution_primitive(self) -> None:
        source = Path(evidence.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "ssh ", "journalctl", "nft "):
            self.assertNotIn(forbidden, source)

    def test_package_workflow_runs_only_harness_tests(self) -> None:
        workflow = (evidence.ROOT / ".github/workflows/package.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            workflow.count("scripts/ci/native_capability_evidence_test.py"), 1
        )
        self.assertNotIn("scripts/ci/native_capability_evidence.py ", workflow)
        self.assertNotIn("native capability qualification", workflow.lower())


if __name__ == "__main__":
    unittest.main()
