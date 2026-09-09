#!/usr/bin/env python3
"""Static and adversarial contract for the protected candidate updater producer."""

from __future__ import annotations

import re
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/candidate-update-bundle.yml"


def workflow_step(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    remainder = workflow.split(marker, 1)[1]
    boundaries: list[int] = []
    next_step = remainder.find("\n      - name:")
    if next_step >= 0:
        boundaries.append(next_step)
    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\n", remainder)
    if next_job is not None:
        boundaries.append(next_job.start())
    return marker + (remainder[: min(boundaries)] if boundaries else remainder)


def literal_run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*\|\s*$", lines[index])
        if match is None:
            index += 1
            continue
        indentation = len(match.group(1))
        body: list[str] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
                break
            body.append(candidate)
            index += 1
        blocks.append(textwrap.dedent("\n".join(body)))
    return blocks


class CandidateUpdateBundleWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.run_blocks = literal_run_blocks(cls.workflow)

    def test_manual_exact_main_contract_and_inputs_are_fail_closed(self) -> None:
        trigger = self.workflow.split("\nenv:", 1)[0]
        self.assertIn("  workflow_dispatch:\n", trigger)
        for name in (
            "release_tag",
            "release_sha",
            "native_signing_run_id",
            "native_signing_artifact_id",
            "authorization",
        ):
            self.assertRegex(
                trigger,
                rf"(?ms)^      {name}:\n.*?^        required: true$",
            )
        for forbidden in (
            "push:",
            "pull_request:",
            "pull_request_target:",
            "release:",
            "schedule:",
            "repository_dispatch:",
            "workflow_run:",
        ):
            self.assertNotIn(forbidden, trigger)
        for contract in (
            '"${EVENT_REF_NAME}" != "main"',
            '"${EVENT_REF}" != "refs/heads/main"',
            '"${EVENT_SHA}" != "${RELEASE_SHA}"',
            '"${WORKFLOW_SHA}" != "${RELEASE_SHA}"',
            '"${EVENT_ACTOR}" != "${REPOSITORY_OWNER}"',
            '"${EVENT_TRIGGERING_ACTOR}" != "${REPOSITORY_OWNER}"',
            '"${RUN_ATTEMPT}" != "1"',
            '"${RUNNER_ENVIRONMENT_CONTEXT}" != "github-hosted"',
            '"${RELEASE_TAG}" != "v4.10.0"',
            '"${AUTHORIZATION}" != "SIGN-CANDIDATE-UPDATE-NO-PUBLISH"',
        ):
            self.assertIn(contract, self.workflow)

    def test_protected_environment_contract_is_exact(self) -> None:
        self.assertIn(
            "environment:\n      name: syswarden-release-qualification",
            self.workflow,
        )
        for contract in (
            "Validate Protected Qualification Environment",
            'reviewer_rule_count="$(jq',
            'owner_reviewer_count="$(jq',
            'prevent_self_review="$(jq',
            '$(top_level_boolean can_admins_bypass)" != "false"',
            "deployment-branch-policies",
            '.name == "main" and .type == "branch"',
            '"${reviewer_rule_count}" != "1"',
            '"${reviewer_entry_count}" != "1"',
            '"${owner_reviewer_count}" != "1"',
        ):
            self.assertIn(contract, self.workflow)
        self.assertEqual(self.workflow.count("    environment:\n"), 1)

    def test_permissions_actions_and_shell_sources_are_bounded(self) -> None:
        for contract in (
            "actions: read",
            "contents: read",
            "attestations: write",
            "id-token: write",
        ):
            self.assertIn(contract, self.workflow)
        for forbidden in (
            "actions: write",
            "contents: write",
            "packages: write",
            "pull-requests: write",
            "persist-credentials: true",
            "gh release",
            "git push",
            "git tag",
            "softprops/action-gh-release",
        ):
            self.assertNotIn(forbidden, self.workflow)
        references = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.workflow)
        self.assertEqual(
            references,
            [
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            ],
        )
        for reference in references:
            self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")
        self.assertTrue(self.run_blocks)
        for block in self.run_blocks:
            self.assertNotIn("${{ inputs.", block)
            self.assertNotIn("${{ secrets.", block)
            self.assertNotIn("${{ vars.", block)
            result = subprocess.run(
                ["bash", "-n"],
                input=block,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_source_is_immutable_unique_and_qualified(self) -> None:
        for contract in (
            "actions/workflows/native-package-signing.yml/runs",
            '--argjson requested "${REQUESTED_RUN_ID}"',
            ".run_attempt == 1",
            '.status == "completed"',
            '.conclusion == "success"',
            'expected_name="syswarden-native-signed-packages-qualified-${version}-${REQUESTED_RUN_ID}-1-${RELEASE_SHA}"',
            '"repos/${GITHUB_REPOSITORY}/actions/runs/${REQUESTED_RUN_ID}/artifacts"',
            "[.[] | .artifacts[]?] | length",
            '.id == $id and .name == $name',
            '.workflow_run.id == $run and .workflow_run.head_sha == $sha',
            '^sha256:[0-9a-f]{64}$',
            "artifact-ids: ${{ inputs.native_signing_artifact_id }}",
            "run-id: ${{ inputs.native_signing_run_id }}",
            "native_package_signing_bundle.py verify",
            '.status == "qualified" and .publishing == true',
        ):
            self.assertIn(contract, self.workflow)
        self.assertIn("Enforce One Successful Candidate Producer Per Commit", self.workflow)
        self.assertIn("successful_prior_runs", self.workflow)

    def test_signing_happens_once_after_all_preconditions(self) -> None:
        secret = (
            "SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY: "
            "${{ secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY }}"
        )
        self.assertEqual(self.workflow.count(secret), 1)
        self.assertEqual(
            self.workflow.count("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"), 1
        )
        signing = workflow_step(
            self.workflow, "Generate and Verify Protected Candidate Manifest"
        )
        self.assertIn(secret, signing)
        self.assertIn('unset SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', signing)
        self.assertIn('env -u SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', signing)
        self.assertIn('trap clear_signing_material EXIT HUP INT TERM', signing)
        self.assertIn('rm -f -- "${manifest_path}" "${signature_path}"', signing)
        self.assertNotIn("set -x", signing)
        for prior in (
            "Validate Protected Manual Candidate Context",
            "Validate Protected Qualification Environment",
            "Validate Exact Untagged Candidate Source",
            "Enforce One Successful Candidate Producer Per Commit",
            "Verify Exact Qualified Native Package Source",
            "Build and Test Candidate Manifest Tool",
            "Revalidate Candidate Manifest Tool Before Secret Exposure",
        ):
            self.assertLess(
                self.workflow.index(prior),
                self.workflow.index("Generate and Verify Protected Candidate Manifest"),
            )

    def test_descriptor_attestation_and_inventory_are_exact(self) -> None:
        for contract in (
            '"profile": "syswarden-candidate-update-bundle/v1"',
            '"status": "candidate-signed-not-release-qualified"',
            '"public_release": False',
            '"release_qualified": False',
            '"workflow": ".github/workflows/candidate-update-bundle.yml"',
            '"native_signing_artifact_id": native_artifact_id',
            '"native_signing_artifact_digest": native_artifact_digest',
            '"exact_file_count": 3',
            '"bundle_path": "verification/producer-attestation.jsonl"',
            "subject-path: ${{ steps.bundle.outputs.descriptor }}",
            'gh attestation download "${BUNDLE_ROOT}/CANDIDATE_UPDATE_BUNDLE.json"',
            '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/candidate-update-bundle.yml"',
            '--signer-digest "${RELEASE_SHA}"',
            '--source-digest "${RELEASE_SHA}"',
            '--source-ref "refs/heads/main"',
            "--deny-self-hosted-runners",
            'test "$(wc -l < "${source_bundle}")" -eq 1',
            "CANDIDATE_UPDATE_SHA256SUMS.txt",
            'test "${directories[*]}" = "node01 verification"',
            "retention-days: 14",
            "compression-level: 0",
        ):
            self.assertIn(contract, self.workflow)
        expected_files = (
            "CANDIDATE_UPDATE_BUNDLE.json",
            "CANDIDATE_UPDATE_SHA256SUMS.txt",
            "node01/syswarden-update-manifest-v1.json",
            "node01/syswarden-update-manifest-v1.json.sig",
            '"node01/syswarden_${RELEASE_TAG#v}_amd64.deb"',
            "verification/producer-attestation.jsonl",
            '"verification/syswarden_${RELEASE_TAG#v}_amd64.deb.asc"',
        )
        finalizer = workflow_step(
            self.workflow, "Finalize Exact Candidate Update Artifact Inventory"
        )
        for path in expected_files:
            self.assertIn(path, finalizer)

    def test_order_cleanup_and_terminal_verdict_are_exact(self) -> None:
        ordered = (
            "Validate Protected Manual Candidate Context",
            "Validate Protected Qualification Environment",
            "Checkout Exact Candidate Source",
            "Validate Exact Untagged Candidate Source",
            "Enforce One Successful Candidate Producer Per Commit",
            "Create Private Candidate Workspace",
            "Resolve Exact Qualified Native Signing Bundle",
            "Download Exact Native Signing Bundle by Artifact ID",
            "Verify Exact Qualified Native Package Source",
            "Build and Test Candidate Manifest Tool",
            "Revalidate Candidate Manifest Tool Before Secret Exposure",
            "Generate and Verify Protected Candidate Manifest",
            "Seal Candidate Descriptor and Exact Inventory",
            "Attest Candidate Bundle Descriptor",
            "Capture and Verify Exact Candidate Producer Attestation",
            "Finalize Exact Candidate Update Artifact Inventory",
            "Upload Exact Candidate Update Artifact",
            "Validate Uploaded Candidate Artifact Identity",
            "Remove Ephemeral Candidate Signing Material",
        )
        positions = [self.workflow.index(name) for name in ordered]
        self.assertEqual(positions, sorted(positions))
        cleanup = workflow_step(
            self.workflow, "Remove Ephemeral Candidate Signing Material"
        )
        self.assertIn("if: ${{ always() }}", cleanup)
        self.assertIn('rm -rf -- "${CANDIDATE_ROOT}"', cleanup)
        self.assertIn('test ! -e "${CANDIDATE_ROOT}"', cleanup)
        self.assertIn("needs: [produce-candidate-update]", self.workflow)
        self.assertIn('test "${PRODUCER_RESULT}" = "success"', self.workflow)

    def test_critical_static_mutations_are_rejected(self) -> None:
        def assert_contract(workflow: str) -> None:
            self.assertIn('"${WORKFLOW_SHA}" != "${RELEASE_SHA}"', workflow)
            self.assertIn('"${RUN_ATTEMPT}" != "1"', workflow)
            self.assertIn('$(top_level_boolean can_admins_bypass)" != "false"', workflow)
            self.assertIn(
                'if [[ "$(jq \'[.[] | .artifacts[]?] | length\' <<< "${artifacts}")" != "1" ]]; then',
                workflow,
            )
            self.assertIn("--deny-self-hosted-runners", workflow)
            self.assertEqual(
                workflow.count("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"), 1
            )
            self.assertIn(
                'sha256sum "${sorted_checksummed[@]}" > CANDIDATE_UPDATE_SHA256SUMS.txt',
                workflow,
            )

        mutations = (
            ('"${WORKFLOW_SHA}" != "${RELEASE_SHA}"', '"${WORKFLOW_SHA}" != ""'),
            ('"${RUN_ATTEMPT}" != "1"', '"${RUN_ATTEMPT}" != "2"'),
            ('$(top_level_boolean can_admins_bypass)" != "false"', '"false" != "false"'),
            (
                'if [[ "$(jq \'[.[] | .artifacts[]?] | length\' <<< "${artifacts}")" != "1" ]]; then',
                'if [[ "$(jq \'[.[] | .artifacts[]?] | length\' <<< "${artifacts}")" != "2" ]]; then',
            ),
            ("--deny-self-hosted-runners", "--no-public-good"),
            (
                "secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY",
                "secrets.OTHER_KEY",
            ),
            (
                'sha256sum "${sorted_checksummed[@]}" > CANDIDATE_UPDATE_SHA256SUMS.txt',
                'sha256sum "${sorted_checksummed[@]}" > CANDIDATE_UPDATE_CHECKSUMS.txt',
            ),
        )
        for old, new in mutations:
            with self.subTest(contract=old), self.assertRaises(AssertionError):
                assert_contract(self.workflow.replace(old, new, 1))


if __name__ == "__main__":
    unittest.main()
