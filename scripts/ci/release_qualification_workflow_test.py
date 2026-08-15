#!/usr/bin/env python3
"""Static and adversarial controls for the pre-tag qualification workflow."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY / ".github" / "workflows" / "release-qualification.yml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTION = re.compile(r"(?m)^\s*uses:\s*([^@\s]+)@([^\s#]+)")


class ReleaseQualificationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def assert_read_only(self, workflow: str) -> None:
        self.assertIn("permissions:\n  actions: read\n  contents: read", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s*(?:contents|actions):\s*write\s*$")
        self.assertNotRegex(workflow, r"(?m)^\s*(?:id-token|attestations|packages):\s*write\s*$")
        self.assertNotRegex(
            workflow,
            r"(?m)^\s*git\s+(?:add|commit|tag|push)(?:\s|$)",
        )
        self.assertNotRegex(workflow, r"(?m)^\s*gh\s+release\s+(?:create|edit|upload)")
        self.assertNotIn("persist-credentials: true", workflow)

    def assert_actions_are_pinned(self, workflow: str) -> None:
        actions = ACTION.findall(workflow)
        self.assertGreaterEqual(len(actions), 4)
        for name, revision in actions:
            self.assertRegex(
                revision,
                FULL_SHA,
                f"{name} must be pinned to a full commit SHA",
            )

    def test_is_manual_only_with_three_required_inputs(self) -> None:
        trigger = self.workflow.split("\nenv:", 1)[0]
        self.assertIn("  workflow_dispatch:\n", trigger)
        for name in ("release_tag", "release_sha", "previous_tag"):
            self.assertRegex(
                trigger,
                rf"(?ms)^      {name}:\n.*?^        required: true$",
            )
        for forbidden in ("push:", "pull_request:", "workflow_run:", "schedule:"):
            self.assertNotIn(forbidden, trigger)

    def test_permissions_are_read_only_and_git_is_not_mutated(self) -> None:
        self.assert_read_only(self.workflow)

    def test_all_actions_are_immutable_existing_pins(self) -> None:
        self.assert_actions_are_pinned(self.workflow)
        expected = {
            "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
            "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        }
        observed = dict(ACTION.findall(self.workflow))
        self.assertEqual(observed, expected)

    def test_runner_is_dedicated_serialized_and_protected(self) -> None:
        for label in (
            "- self-hosted",
            "- linux",
            "- x64",
            "- ${{ 'syswarden-release-lab' }}",
        ):
            self.assertIn(label, self.workflow)
        self.assertIn("group: syswarden-release-qualification", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn("required_tools=(", self.workflow)
        for tool in ("git", "go", "jq", "podman", "python3", "scp", "ssh"):
            self.assertRegex(self.workflow, rf"(?m)^            {tool}$")
        self.assertEqual(
            self.workflow.count("name: syswarden-release-qualification"), 2
        )

    def test_environment_api_enforces_automatic_qualification_and_main_only(self) -> None:
        required = (
            "environments/syswarden-release-qualification",
            '.type == "required_reviewers"',
            '.type == "branch_policy"',
            '"${reviewer_rule_count}" != "0"',
            '"${branch_policy_rule_count}" != "1"',
            '"${protection_rule_count}" != "1"',
            "must require no reviewer or wait gate",
            ".deployment_branch_policy.protected_branches",
            ".deployment_branch_policy.custom_branch_policies",
            "deployment-branch-policies",
            '.name == "main" and .type == "branch"',
            '"${policy_count}" != "1"',
            '"${main_policy_count}" != "1"',
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertNotIn(".prevent_self_review == true", self.workflow)
        self.assertNotIn("(.reviewers | length) > 0", self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("gh api --paginate --slurp --method GET"), 3
        )

    def test_candidate_context_is_exact_main_sha_and_pre_tag(self) -> None:
        required = (
            '"${EVENT_NAME}" != "workflow_dispatch"',
            '"${EVENT_REF_TYPE}" != "branch"',
            '"${EVENT_REF_NAME}" != "main"',
            '"${EVENT_REF}" != "refs/heads/main"',
            '"${EVENT_SHA}" != "${RELEASE_SHA}"',
            "^[0-9a-f]{40}$",
            "./scripts/versioning.sh inspect",
            "./scripts/versioning.sh validate-commit",
            "git merge-base --is-ancestor",
            "git show-ref --verify --quiet",
            "git ls-remote --exit-code --refs origin",
            "remote candidate-tag absence could not be proven",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertNotIn("--tag-phase", self.workflow)
        self.assertNotIn("--require-tag", self.workflow)

    def test_candidate_packages_come_from_one_exact_successful_main_push(self) -> None:
        required = (
            "actions/workflows/package.yml/runs",
            "-f event=push",
            '-f head_sha="${RELEASE_SHA}"',
            '.head_branch == "main"',
            '.event == "push"',
            '"$(jq \'length\' <<< "${matches}")" != "1"',
            '"${run_status}" != "completed"',
            '"${run_conclusion}" != "success"',
            "actions/runs/${run_id}/artifacts",
            '"$(jq \'length\' <<< "${artifact_matches}")" != "1"',
            "run-id: ${{ steps.candidate.outputs.run_id }}",
            "github-token: ${{ github.token }}",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)

    def test_previous_packages_use_latest_public_release_asset_ids(self) -> None:
        required = (
            '"repos/${GITHUB_REPOSITORY}/releases/latest"',
            '"repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets"',
            '"$(jq -r \'.tag_name\' <<< "${release_json}")" != "${PREVIOUS_TAG}"',
            '"$(jq -r \'.draft\' <<< "${release_json}")" != "false"',
            '"$(jq -r \'.prerelease\' <<< "${release_json}")" != "false"',
            "syswarden_${previous_version}_amd64.deb",
            "syswarden_${previous_version}_arm64.deb",
            "syswarden-${previous_version}-1.x86_64.rpm",
            "syswarden-${previous_version}-1.aarch64.rpm",
            "syswarden_${previous_version}_x86_64.apk",
            "syswarden_${previous_version}_aarch64.apk",
            "syswarden-${previous_version}.txz",
            '"SHA256SUMS.txt"',
            '"repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}"',
            "-H 'Accept: application/octet-stream'",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("gh api --paginate --slurp --method GET"), 4
        )
        self.assertEqual(self.workflow.count("verify-packages"), 2)

    def test_arm64_requires_exact_enabled_fix_binary_binfmt(self) -> None:
        required = (
            "SYSWARDEN_QEMU_AARCH64_STATIC",
            "/proc/sys/fs/binfmt_misc/qemu-aarch64",
            "sed -n 's/^interpreter //p'",
            '"${binfmt_interpreters[0]}" != "${QEMU_AARCH64_STATIC}"',
            '"${binfmt_flags}" != *F*',
            "--arm64-emulator \"${QEMU_AARCH64_STATIC}\"",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)

    def test_all_real_labs_are_fail_closed_and_never_pull_images(self) -> None:
        for script in (
            "scripts/ci/package_lifecycle_lab.py",
            "scripts/ci/freebsd_vm_lab.py",
            "scripts/ci/nftables_kernel_lab.py",
        ):
            self.assertEqual(self.workflow.count(script), 1)
        self.assertEqual(self.workflow.count("--pull-policy never"), 2)
        for status in (
            "package-lab.rc",
            "freebsd-lab.rc",
            "nftables-lab.rc",
        ):
            self.assertIn(status, self.workflow)
        self.assertGreaterEqual(self.workflow.count("set +e"), 5)
        self.assertIn("--ssh-host 127.0.0.1", self.workflow)

    def test_signed_freebsd_updater_is_built_bound_run_and_recomputed(self) -> None:
        build = self.workflow.split(
            "      - name: Build Exact FreeBSD Signed Updater Qualification Binary\n",
            1,
        )[1].split("      - name:", 1)[0]
        probe = self.workflow.split(
            "      - name: Run and Recompute Signed FreeBSD Updater Transition\n",
            1,
        )[1].split("      - name:", 1)[0]
        self.assertIn("GOOS=freebsd", build)
        self.assertIn("GOARCH=amd64", build)
        self.assertIn("GOAMD64=v1", build)
        self.assertIn("CGO_ENABLED=0", build)
        self.assertIn("GOFLAGS=-mod=readonly", build)
        self.assertIn("GOTOOLCHAIN=local", build)
        self.assertIn("-buildvcs=true", build)
        self.assertIn("./pkg/system", build)
        self.assertIn(
            "freeBSDUpdaterQualificationSourceSHA=${RELEASE_SHA}", build
        )
        self.assertIn('test -z "$(git status --porcelain=v1 --untracked-files=all)"', build)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", build)

        for contract in (
            "scripts/ci/freebsd_updater_vm_probe.py",
            'run "${common_arguments[@]}"',
            'verify "${common_arguments[@]}"',
            '--packages-dir "${CANDIDATE_PACKAGES_DIR}"',
            '--previous-packages-dir "${PREVIOUS_PACKAGES_DIR}"',
            '--manifest "${ARTIFACT_ROOT}/update/syswarden-update-manifest-v1.json"',
            '--signature "${ARTIFACT_ROOT}/update/syswarden-update-manifest-v1.json.sig"',
            '--test-binary "${TOOLS_DIR}/syswarden-updater-freebsd.test"',
            '--release-sha "${RELEASE_SHA}"',
            '--ssh-host 127.0.0.1',
            '--vm-marker-token-file "${FREEBSD_MARKER_TOKEN_FILE}"',
            '--output "${report}"',
            '"${STATUS_DIR}/freebsd-updater.rc"',
            '"${STATUS_DIR}/freebsd-updater-verify.rc"',
        ):
            self.assertIn(contract, probe)
        self.assertNotIn("set -x", probe)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", probe)
        self.assertLess(
            self.workflow.index("Generate and Verify Signed Update Manifest"),
            self.workflow.index("Run and Recompute Signed FreeBSD Updater Transition"),
        )
        self.assertLess(
            self.workflow.index("Run and Recompute Signed FreeBSD Updater Transition"),
            self.workflow.index("Seal Exact Qualification Evidence Inventory"),
        )
        verdict = self.workflow.split(
            "      - name: Enforce Final Release Qualification Verdict\n",
            1,
        )[1]
        self.assertIn(
            "SIGNED_UPDATE_REQUIRED: ${{ steps.update_contract.outputs.required }}",
            verdict,
        )
        self.assertIn(
            'jq --argjson signed_update_required "${SIGNED_UPDATE_REQUIRED}"',
            verdict,
        )
        self.assertIn('if $signed_update_required then [', verdict)
        self.assertEqual(verdict.count('"freebsd_updater"'), 1)
        self.assertEqual(verdict.count('"freebsd_updater_verify"'), 1)

    def test_freebsd_secrets_are_files_mode_0600_and_token_is_never_an_argument(self) -> None:
        for secret in (
            "secrets.SYSWARDEN_FREEBSD_SSH_PRIVATE_KEY",
            "secrets.SYSWARDEN_FREEBSD_KNOWN_HOSTS",
            "secrets.SYSWARDEN_FREEBSD_VM_MARKER_TOKEN",
        ):
            self.assertIn(secret, self.workflow)
        self.assertIn(
            'chmod 0600 "${identity_file}" "${known_hosts_file}" "${marker_token_file}"',
            self.workflow,
        )
        self.assertIn(
            '--vm-marker-token-file "${FREEBSD_MARKER_TOKEN_FILE}"',
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"--vm-marker-token(?:\s|$)")
        self.assertNotIn("FREEBSD_MARKER_TOKEN}" + " \\\n", self.workflow)
        upload = self.workflow.index("Upload Exact Qualification Evidence")
        cleanup = self.workflow.index("Remove Ephemeral Transport Secrets")
        verdict = self.workflow.index("Enforce Final Release Qualification Verdict")
        self.assertLess(upload, cleanup)
        self.assertLess(cleanup, verdict)

    def test_adapter_build_verify_and_release_gate_contracts_are_exact(self) -> None:
        required = (
            "release_qualification_adapter.py",
            '--nft-raw "${RAW_DIR}/nftables-raw.json"',
            '--package-raw "${RAW_DIR}/package-lifecycle-raw.json"',
            '--freebsd-raw "${RAW_DIR}/freebsd-vm-raw.json"',
            '--nft-output "${BOUND_DIR}/nftables-bound.json"',
            '--package-output "${BOUND_DIR}/package-lifecycle-bound.json"',
            '--freebsd-output "${BOUND_DIR}/freebsd-vm-bound.json"',
            '--nft-envelope "${BOUND_DIR}/nftables-bound.json"',
            '--package-envelope "${BOUND_DIR}/package-lifecycle-bound.json"',
            '--freebsd-envelope "${BOUND_DIR}/freebsd-vm-bound.json"',
            "--max-age-seconds 172800",
            "--max-report-skew-seconds 0",
            "release_qualification_gate.py",
            "--profile release",
            '--aggregate "${AGGREGATE_DIR}/release-qualification.json"',
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertNotIn("--profile characterization", self.workflow)

    def test_artifact_inventory_is_exact_bound_and_byte_verifiable(self) -> None:
        required = (
            "aggregate/release-qualification.json",
            "bound/freebsd-vm-bound.json",
            "bound/nftables-bound.json",
            "bound/package-lifecycle-bound.json",
            "raw/freebsd-vm-raw.json",
            "raw/freebsd-updater-raw.json",
            "raw/nftables-raw.json",
            "raw/package-lifecycle-raw.json",
            "packages/candidate/SHA256SUMS.txt",
            "packages/previous/SHA256SUMS.txt",
            "qualification-context.json",
            "status/qualification-exit-codes.json",
            "tools/syswarden-updater-freebsd.test",
            'if [[ "${SIGNED_UPDATE_REQUIRED}" == "true" ]]; then',
            "update/syswarden-update-manifest-v1.json",
            "update/syswarden-update-manifest-v1.json.sig",
            "EVIDENCE_SHA256SUMS.txt",
            "sha256sum --check --strict EVIDENCE_SHA256SUMS.txt",
            '-eq "$(( ${#sorted_expected[@]} + 1 ))"',
            "expected_directories=(",
            "qualification evidence directory inventory is not exact",
            "test ! -L",
            "find -P",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)

    def test_product_blocked_evidence_uploads_before_final_failure(self) -> None:
        upload = self.workflow.index("Upload Exact Qualification Evidence")
        verdict = self.workflow.index("Enforce Final Release Qualification Verdict")
        self.assertLess(upload, verdict)
        self.assertIn(
            "if: ${{ always() && steps.inventory.outcome == 'success' }}",
            self.workflow,
        )
        self.assertIn("name: syswarden-release-qualification", self.workflow[upload:])
        self.assertIn("if-no-files-found: error", self.workflow[upload:verdict])
        self.assertIn('"${UPLOAD_OUTCOME}" != "success"', self.workflow[verdict:])
        self.assertIn("all(.[]; . == 0)", self.workflow[verdict:])

    def test_adversarial_changes_are_detected_by_core_guards(self) -> None:
        with self.assertRaises(AssertionError):
            self.assert_read_only(
                self.workflow.replace("contents: read", "contents: write", 1)
            )
        checkout_pin = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        with self.assertRaises(AssertionError):
            self.assert_actions_are_pinned(
                self.workflow.replace(checkout_pin, "v7.0.1", 1)
            )


if __name__ == "__main__":
    unittest.main()
