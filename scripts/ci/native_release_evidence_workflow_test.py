#!/usr/bin/env python3
"""Static contract tests for the protected native evidence producer."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/native-release-evidence.yml"


class NativeReleaseEvidenceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_protected_ephemeral_fixed_source_contract(self) -> None:
        for contract in (
            "runs-on: [self-hosted, linux, x64, syswarden-native-evidence]",
            "environment: native-release-evidence",
            'source_root="/var/lib/syswarden/native-release-evidence/${RELEASE_SHA}"',
            'test "${GITHUB_REF}" = "refs/heads/main"',
            'test "${GITHUB_SHA}" = "${RELEASE_SHA}"',
            "test \"${GITHUB_RUN_ATTEMPT}\" = \"1\"",
            "stat -c '%a'",
            "stat -c '%h'",
            "test ! -L",
        ):
            self.assertIn(contract, self.workflow)
        self.assertNotIn("source_path:", self.workflow)

    def test_candidate_bound_gates_and_one_artifact(self) -> None:
        for contract in (
            "ha_v2_native_evidence.py",
            "native_capability_evidence.py aggregate",
            "performance_gate.py",
            "source_allocation_gate.py assemble",
            "source_allocation_gate.py validate",
            "performance_channel_aggregate.py",
            "source_allocation_contract_v4.10.0.json",
            "node01_migration_evidence.py assemble",
            "node01_migration_evidence.py validate",
            "node01_migration_contract_v4.10.0.json",
            "native_lifecycle_evidence.py",
            "native_lifecycle_contract_v4.10.0.json",
            "node02-ubuntu26.04.json",
            "node04-alpine3.24.json",
            "node05-almalinux9.8.json",
            "node05-almalinux9.8-rhelpo.json",
            "node03-almalinux10.2-rhelpo.json",
            "RPM-A9-RHELPO",
            "RPM-A10-RHELPO",
            "native-lifecycle/RAW_EVIDENCE.tar",
            "NATIVE_RELEASE_EVIDENCE_MANIFEST.json",
            "syswarden-native-evidence-${RELEASE_TAG}-${RELEASE_SHA}",
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        ):
            self.assertIn(contract, self.workflow)
        self.assertEqual(self.workflow.count("actions/upload-artifact@"), 1)
        self.assertEqual(self.workflow.count("actions/attest-build-provenance@"), 1)
        self.assertIn('test "${#lifecycle_references[@]}" -eq 145', self.workflow)
        self.assertIn(
            '--signing-bundle "${signing_validation_root}"', self.workflow
        )

    def test_source_allocation_bundle_is_exact_and_pre_staged(self) -> None:
        for contract in (
            "allocation_metadata=(environment.json execution-control-attestation.json build-attestation.json benchmark-source.go fixture.json signature-catalog.json)",
            "allocation_probes=(baseline-probe candidate-probe)",
            "allocation_campaigns=(allocation-campaign-01 allocation-campaign-02 allocation-campaign-03)",
            "allocation_roles=(baseline candidate)",
            "allocation_samples=(01 02 03 04 05 06 07 08 09 10)",
            'require_input "source-allocation/${name}" 700',
            'install -m 0700 -- "${source_root}/source-allocation/${name}"',
            'expected_source+=("source-allocation/raw/${campaign}/${role}-${sample}.json")',
            '"source_allocation": hashlib.sha256(pathlib.Path(\'scripts/ci/source_allocation_contract_v4.10.0.json\').read_bytes()).hexdigest()',
            '--output "${output_root}/performance/AGGREGATE.json"',
        ):
            self.assertIn(contract, self.workflow)
        self.assertEqual(self.workflow.count("source_allocation_gate.py assemble"), 1)
        self.assertEqual(self.workflow.count("source_allocation_gate.py validate"), 1)
        self.assertEqual(self.workflow.count("performance_channel_aggregate.py"), 1)
        source_inventory = self.workflow.split(
            "mapfile -t actual_source", 1
        )[0].split("expected_source=", 1)[1]
        self.assertNotIn("source-allocation/EVIDENCE.json", source_inventory)
        self.assertNotIn("source-allocation/REPORT.json", source_inventory)
        self.assertNotIn("source_allocation_producer.py", self.workflow)

    def test_native_performance_adapter_and_config_are_sealed(self) -> None:
        for contract in (
            "performance/ADAPTER_CONFIG.json",
            '--adapter-config "${output_root}/performance/ADAPTER_CONFIG.json"',
            "native_performance_adapter_test.py",
        ):
            if contract == "native_performance_adapter_test.py":
                package_workflow = (ROOT / ".github/workflows/package.yml").read_text(
                    encoding="utf-8"
                )
                self.assertIn(contract, package_workflow)
            else:
                self.assertIn(contract, self.workflow)

    def test_permissions_and_actions_are_bounded(self) -> None:
        self.assertIn("contents: read", self.workflow)
        self.assertIn("attestations: write", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertNotIn("pull-requests: write", self.workflow)
        self.assertNotIn("actions: write", self.workflow)

    def test_lifecycle_ssh_trust_roots_are_protected_environment_variables(self) -> None:
        self.assertIn("NODE02_SSH_HOST_KEY_SHA256: ${{ vars.NODE02_SSH_HOST_KEY_SHA256 }}", self.workflow)
        self.assertIn("NODE03_SSH_HOST_KEY_SHA256: ${{ vars.NODE03_SSH_HOST_KEY_SHA256 }}", self.workflow)
        self.assertIn("NODE04_SSH_HOST_KEY_SHA256: ${{ vars.NODE04_SSH_HOST_KEY_SHA256 }}", self.workflow)
        self.assertIn("NODE05_SSH_HOST_KEY_SHA256: ${{ vars.NODE05_SSH_HOST_KEY_SHA256 }}", self.workflow)
        self.assertIn('[[ "${NODE02_SSH_HOST_KEY_SHA256}" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]', self.workflow)
        self.assertIn('[[ "${NODE03_SSH_HOST_KEY_SHA256}" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]', self.workflow)
        self.assertIn('[[ "${NODE04_SSH_HOST_KEY_SHA256}" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]', self.workflow)
        self.assertIn('[[ "${NODE05_SSH_HOST_KEY_SHA256}" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]', self.workflow)
        for left, right in (
            ("NODE02", "NODE03"),
            ("NODE02", "NODE04"),
            ("NODE02", "NODE05"),
            ("NODE03", "NODE04"),
            ("NODE03", "NODE05"),
            ("NODE04", "NODE05"),
        ):
            self.assertIn(
                f'test "${{{left}_SSH_HOST_KEY_SHA256}}" != "${{{right}_SSH_HOST_KEY_SHA256}}"',
                self.workflow,
            )
        self.assertNotIn("jq -er '.host.ssh_host_key_sha256'", self.workflow)
        self.assertIn('"trusted_host_keys": {"node02": sys.argv[6], "node03": sys.argv[7], "node04": sys.argv[8], "node05": sys.argv[9]}', self.workflow)

    def test_native_signing_identity_is_rotation_safe_and_bundle_bound(self) -> None:
        for contract in (
            "native-signing/SIGNED_ARTIFACT_SHA256SUMS.txt",
            "native-signing/evidence/NATIVE_SIGNING_PROVENANCE.json",
            "native-signing/packages/syswarden-${candidate_version}-1.x86_64.rpm",
            "native-signing/packages/syswarden_${candidate_version}_amd64.deb",
            "native-signing/packages/syswarden_${candidate_version}_x86_64.apk",
            "native-signing/rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt",
            "native-signing/rhel-package-owned/evidence/RPM_NATIVE_VERIFICATION.json",
            "native-signing/rhel-package-owned/evidence/RPM_PAYLOAD_PROOF.json",
            "native-signing/rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
            "native-signing/rhel-package-owned/evidence/UNSIGNED_SHA256SUMS.txt",
            "native-signing/rhel-package-owned/packages/SHA256SUMS.txt",
            "native-signing/rhel-package-owned/packages/syswarden-${candidate_version}-1.rhelpo.x86_64.rpm",
            "native_package_signing_bundle.py verify",
            'signing_provenance="${signing_validation_root}/evidence/NATIVE_SIGNING_PROVENANCE.json"',
            'rhel_signing_provenance="${signing_validation_root}/rhel-package-owned/evidence/SIGNING_PROVENANCE.json"',
            'rpm_signer_fingerprint="$(jq -er \'.rpm.fingerprint\'',
            'deb_signer_fingerprint="$(jq -er \'.deb.fingerprint\'',
            'apk_public_key_sha256="$(jq -er \'.apk.public_key_sha256\'',
            'openpgp_fingerprint="${deb_signer_fingerprint}"',
            ".packages.signed[]",
            'rpm_package_name="$(jq -er \'.rpm.name\'',
            'deb_package_name="$(jq -er \'.deb.name\'',
            'apk_package_name="$(jq -er \'.apk.name\'',
            '--candidate-package-name "${deb_package_name}"',
            '--candidate-package-sha256 "${deb_package_sha256}"',
            '--candidate-package-size "${deb_package_size}"',
            '--rpm-signer-fingerprint "${rpm_signer_fingerprint}"',
            '--rpm-package-name "${rpm_package_name}"',
            '--rpm-package-sha256 "${rpm_package_sha256}"',
            '--rpm-package-size "${rpm_package_size}"',
            '--rhel-rpm-package-name "${rhel_rpm_package_name}"',
            '--rhel-rpm-package-sha256 "${rhel_rpm_package_sha256}"',
            '--rhel-rpm-package-size "${rhel_rpm_package_size}"',
            '--deb-package-name "${deb_package_name}"',
            '--deb-package-sha256 "${deb_package_sha256}"',
            '--deb-package-size "${deb_package_size}"',
            '--apk-package-name "${apk_package_name}"',
            '--apk-package-sha256 "${apk_package_sha256}"',
            '--apk-package-size "${apk_package_size}"',
            '"schema_version": 2',
            '"native_signing": {"policy_sha256": provenance["policy_sha256"]',
            '"provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest()',
            '"selected_keys": {"rpm": provenance["rpm_signature"]["key"]',
            '"status": provenance["status"]',
            '"rhel_package_owned": {"package": rhel_provenance["packages"]["signed"]',
            '"updater_manifest_included": rhel_provenance["updater_manifest_included"]',
        ):
            self.assertIn(contract, self.workflow)
        self.assertNotIn("select(.revoked == false)", self.workflow)
        self.assertNotIn("one active DEB key is required", self.workflow)
        self.assertIn(
            '.status == "native-signatures-verified-not-release-qualified"',
            self.workflow,
        )
        self.assertIn('.policy_sha256 == $policy_sha256', self.workflow)
        self.assertIn('expected_source+=("${native_signing_files[@]}")', self.workflow)
        signing_inventory = self.workflow.split("native_signing_files=(", 1)[1].split(
            "\n          )", 1
        )[0]
        self.assertEqual(
            tuple(
                line.strip().strip('"')
                for line in signing_inventory.splitlines()
                if line.strip()
            ),
            (
                "native-signing/SIGNED_ARTIFACT_SHA256SUMS.txt",
                "native-signing/evidence/APK_NATIVE_VERIFICATION.json",
                "native-signing/evidence/DEB_NATIVE_VERIFICATION.json",
                "native-signing/evidence/NATIVE_SIGNING_PROVENANCE.json",
                "native-signing/evidence/RPM_NATIVE_VERIFICATION.json",
                "native-signing/evidence/RPM_PAYLOAD_PROOF.json",
                "native-signing/evidence/UNSIGNED_SHA256SUMS.txt",
                "native-signing/packages/SHA256SUMS.txt",
                "native-signing/packages/syswarden-${candidate_version}-1.x86_64.rpm",
                "native-signing/packages/syswarden_${candidate_version}_amd64.deb",
                "native-signing/packages/syswarden_${candidate_version}_amd64.deb.asc",
                "native-signing/packages/syswarden_${candidate_version}_x86_64.apk",
                "native-signing/rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt",
                "native-signing/rhel-package-owned/evidence/RPM_NATIVE_VERIFICATION.json",
                "native-signing/rhel-package-owned/evidence/RPM_PAYLOAD_PROOF.json",
                "native-signing/rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
                "native-signing/rhel-package-owned/evidence/UNSIGNED_SHA256SUMS.txt",
                "native-signing/rhel-package-owned/packages/SHA256SUMS.txt",
                "native-signing/rhel-package-owned/packages/"
                "syswarden-${candidate_version}-1.rhelpo.x86_64.rpm",
            ),
        )

    def test_rhel_package_owned_campaigns_are_separate_and_fail_closed(self) -> None:
        for contract in (
            '"${source_root}/native-lifecycle/node05-almalinux9.8-rhelpo.json"',
            '"${source_root}/native-lifecycle/node03-almalinux10.2-rhelpo.json"',
            "native-capability/RPM-A9-RHELPO.json",
            "native-capability/RPM-A10-RHELPO.json",
            'test "${rhel_rpm_package_name}" != "${rpm_package_name}"',
            'test "${rhel_rpm_package_sha256}" != "${rpm_package_sha256}"',
            '--node03-ssh-host-key-sha256 "${NODE03_SSH_HOST_KEY_SHA256}"',
        ):
            self.assertIn(contract, self.workflow)
        for index in range(5):
            self.assertEqual(
                self.workflow.count(
                    f'--observation "${{lifecycle_observations[{index}]}}"'
                ),
                1,
            )
        lifecycle_inventory = self.workflow.split(
            "lifecycle_observations=(", 1
        )[1].split("\n          )", 1)[0]
        self.assertEqual(
            tuple(
                line.strip().strip('"')
                for line in lifecycle_inventory.splitlines()
                if line.strip()
            ),
            (
                "${source_root}/native-lifecycle/node02-ubuntu26.04.json",
                "${source_root}/native-lifecycle/node05-almalinux9.8.json",
                "${source_root}/native-lifecycle/node04-alpine3.24.json",
                "${source_root}/native-lifecycle/node05-almalinux9.8-rhelpo.json",
                "${source_root}/native-lifecycle/node03-almalinux10.2-rhelpo.json",
            ),
        )
        self.assertEqual(
            self.workflow.count("native-capability/RPM-A9-RHELPO.json"),
            1,
        )
        self.assertEqual(
            self.workflow.count("native-capability/RPM-A10-RHELPO.json"),
            1,
        )
        self.assertIn(
            "for profile in DEB-13 DEB-U2604 RPM-A10 APK-324 "
            "RPM-A9-RHELPO RPM-A10-RHELPO; do",
            self.workflow,
        )
        for legacy in (
            "extensions/rhel-package-owned/native_qualification.py",
            "rhel-package-owned/alma9-dedicated.json",
            "rhel-package-owned/node03-alma10.2.json",
            "rhel-package-owned/VERDICT.json",
        ):
            self.assertNotIn(legacy, self.workflow)


if __name__ == "__main__":
    unittest.main()
