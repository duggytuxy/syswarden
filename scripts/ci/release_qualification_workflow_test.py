#!/usr/bin/env python3
"""Static and adversarial controls for the pre-tag qualification workflow."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY / ".github" / "workflows" / "release-qualification.yml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTION = re.compile(r"(?m)^\s*uses:\s*([^@\s]+)@([^\s#]+)")
RETIRED_PLATFORM = "free" + "bsd"
RETIRED_PACKAGE_SUFFIX = "." + "txz"


def workflow_step_script(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1:
        raise AssertionError(f"expected one shell body for workflow step {step_name}")
    return textwrap.dedent(step.split(run_marker, 1)[1])


def run_environment_gate(
    script: str,
    environment: dict[str, object],
    policies: list[dict[str, object]],
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        binary_directory = Path(temporary) / "bin"
        binary_directory.mkdir()
        gh = binary_directory / "gh"
        gh.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *"/deployment-branch-policies"*)
    printf '%s\\n' "${TEST_POLICIES_JSON:?}"
    ;;
  *"/environments/"*)
    printf '%s\\n' "${TEST_ENVIRONMENT_JSON:?}"
    ;;
  *)
    echo "unexpected gh invocation: $*" >&2
    exit 64
    ;;
esac
""",
            encoding="utf-8",
        )
        gh.chmod(0o700)
        process_environment = os.environ.copy()
        process_environment.update(
            {
                "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                "GITHUB_REPOSITORY_OWNER": "duggytuxy",
                "PATH": f"{binary_directory}{os.pathsep}{process_environment['PATH']}",
                "TEST_ENVIRONMENT_JSON": json.dumps(
                    environment, separators=(",", ":")
                ),
                "TEST_POLICIES_JSON": json.dumps(policies, separators=(",", ":")),
            }
        )
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )


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
        for tool in ("git", "go", "jq", "podman", "python3"):
            self.assertRegex(self.workflow, rf"(?m)^            {tool}$")
        self.assertEqual(
            self.workflow.count("name: syswarden-release-qualification"), 2
        )
        self.assertEqual(self.workflow.count("runs-on: ubuntu-24.04-arm"), 1)
        self.assertEqual(self.workflow.count("- self-hosted"), 1)
        self.assertIn("needs: package-lifecycle-arm64", self.workflow)
        self.assertIn('test "$(uname -m)" = "aarch64"', self.workflow)

    def test_environment_api_enforces_automatic_qualification_and_main_only(self) -> None:
        required = (
            "environments/syswarden-release-qualification",
            '.type == "required_reviewers"',
            '.type == "branch_policy"',
            '"${reviewer_rule_count}" != "0"',
            '"${branch_policy_rule_count}" != "1"',
            '"${protection_rule_count}" != "1"',
            "must require no reviewer or wait gate",
            ".deployment_branch_policy[$field]",
            "required_environment_boolean",
            "required_top_level_environment_boolean",
            '"${can_admins_bypass}" != "false"',
            "forbid administrator bypass",
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

    def test_environment_boolean_gate_is_typed_and_fail_closed(self) -> None:
        step_name = "Require Restricted Automatic Qualification Environment"
        script = workflow_step_script(self.workflow, step_name)
        self.assertIn("required_environment_boolean()", script)
        self.assertIn('if type == "boolean" then', script)
        self.assertIn("tostring", script)
        self.assertNotIn('// "missing"', script)

        valid = {
            "name": "syswarden-release-qualification",
            "can_admins_bypass": False,
            "protection_rules": [{"type": "branch_policy"}],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        policies = [
            {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "branch"}],
            }
        ]
        result = run_environment_gate(script, valid, policies)
        self.assertEqual(result.returncode, 0, result.stderr)

        for name, field, value in (
            ("protected true", "protected_branches", True),
            ("custom false", "custom_branch_policies", False),
        ):
            with self.subTest(name=name):
                mutated = json.loads(json.dumps(valid))
                mutated["deployment_branch_policy"][field] = value
                result = run_environment_gate(script, mutated, policies)
                diagnostic = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, diagnostic)
                self.assertNotIn("must be boolean", diagnostic)
                self.assertIn("must require no reviewer or wait gate", diagnostic)

        mutated = json.loads(json.dumps(valid))
        mutated["can_admins_bypass"] = True
        result = run_environment_gate(script, mutated, policies)
        diagnostic = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, diagnostic)
        self.assertIn("forbid administrator bypass", diagnostic)

        for name, value, missing in (
            ("bypass missing", None, True),
            ("bypass null", None, False),
            ("bypass string", "false", False),
        ):
            with self.subTest(name=name):
                mutated = json.loads(json.dumps(valid))
                if missing:
                    del mutated["can_admins_bypass"]
                else:
                    mutated["can_admins_bypass"] = value
                result = run_environment_gate(script, mutated, policies)
                diagnostic = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, diagnostic)
                self.assertIn("can_admins_bypass must be boolean", diagnostic)

        for name, field, value, missing in (
            ("protected missing", "protected_branches", None, True),
            ("protected null", "protected_branches", None, False),
            ("protected string", "protected_branches", "false", False),
            ("custom missing", "custom_branch_policies", None, True),
            ("custom null", "custom_branch_policies", None, False),
            ("custom string", "custom_branch_policies", "true", False),
        ):
            with self.subTest(name=name):
                mutated = json.loads(json.dumps(valid))
                if missing:
                    del mutated["deployment_branch_policy"][field]
                else:
                    mutated["deployment_branch_policy"][field] = value
                result = run_environment_gate(script, mutated, policies)
                diagnostic = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, diagnostic)
                self.assertIn(
                    f"deployment_branch_policy.{field} must be boolean",
                    diagnostic,
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
            '"SHA256SUMS.txt"',
            '"repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}"',
            "-H 'Accept: application/octet-stream'",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertNotIn(RETIRED_PACKAGE_SUFFIX, self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("gh api --paginate --slurp --method GET"), 4
        )
        self.assertEqual(self.workflow.count("verify-packages"), 4)

    def test_v4028_transition_is_exact_private_and_fails_closed(self) -> None:
        exact_counts = {
            'if [[ "${PREVIOUS_TAG}" == "v4.02.8" ]]': 2,
            "normalize-v4028-linux-packages": 2,
            "public-release-assets.json": 2,
            "public-SHA256SUMS.txt": 2,
            "v4.02.8-linux-transition.json": 2,
            "jq -cS '[.[] | .[] | {digest, id, name, size, state}]'": 2,
            'cat "${transition_provenance}"': 2,
            'sha256sum "${transition_provenance}"': 2,
        }
        for contract, expected_count in exact_counts.items():
            self.assertEqual(self.workflow.count(contract), expected_count, contract)
        for argument in (
            '--repository "${GITHUB_REPOSITORY}"',
            '--release-id "${release_id}"',
            '--tag "${PREVIOUS_TAG}"',
            '--source-manifest "${transition_source_manifest}"',
            '--asset-metadata "${transition_metadata}"',
            '--output-manifest "${ARM_PREVIOUS_PACKAGES_DIR}/SHA256SUMS.txt"',
            '--output-manifest "${PREVIOUS_PACKAGES_DIR}/SHA256SUMS.txt"',
            '--provenance-output "${transition_provenance}"',
        ):
            self.assertIn(argument, self.workflow)
        self.assertEqual(self.workflow.count("transition_required=false"), 2)
        self.assertEqual(self.workflow.count("transition_required=true"), 2)
        self.assertNotIn(RETIRED_PACKAGE_SUFFIX, self.workflow)
        for step_name in (
            "Download Exact ARM64 Previous Packages",
            "Download Latest Public Previous Packages by Asset ID",
        ):
            script = workflow_step_script(self.workflow, step_name)
            self.assertLess(
                script.index("normalize-v4028-linux-packages"),
                script.index("verify-packages"),
            )
            self.assertIn('destination="${transition_source_manifest}"', script)
        cleanup = workflow_step_script(
            self.workflow, "Remove Ephemeral Signing Material"
        )
        for contract in (
            '"${TRANSITION_DIR}" != "${QUALIFICATION_ROOT}/historical-transition"',
            'find -P "${TRANSITION_DIR}" -xdev -mindepth 1 -delete',
            'rmdir -- "${TRANSITION_DIR}"',
        ):
            self.assertIn(contract, cleanup)

    def test_arm64_is_native_and_emulation_is_forbidden(self) -> None:
        required = (
            "runs-on: ubuntu-24.04-arm",
            "--architecture-shard arm64",
            "--architecture-shard amd64",
            "package-lifecycle-arm64.json",
            "package-lifecycle-amd64.json",
            "--aggregate-amd64-report",
            "--aggregate-arm64-report",
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        for forbidden in (
            "SYSWARDEN_QEMU_AARCH64_STATIC",
            "/proc/sys/fs/binfmt_misc/qemu-aarch64",
            "--arm64-emulator",
            "host_binfmt_qemu_aarch64",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_native_shards_are_bound_to_one_run_sha_and_package_source(self) -> None:
        for argument in (
            "--qualification-repository",
            "--qualification-release-sha",
            "--qualification-release-tag",
            "--qualification-previous-tag",
            "--qualification-workflow-run-id",
            "--qualification-workflow-run-attempt",
            "--qualification-candidate-run-id",
            "--qualification-candidate-artifact-id",
            "--qualification-candidate-artifact-name",
            "--qualification-previous-release-id",
        ):
            self.assertEqual(self.workflow.count(argument), 2)
        for argument in (
            "--package-amd64-shard",
            "--package-arm64-shard",
            "--expected-repository",
            "--expected-workflow-run-id",
            "--expected-workflow-run-attempt",
            "--expected-candidate-run-id",
            "--expected-candidate-artifact-id",
            "--expected-candidate-artifact-name",
            "--expected-previous-release-id",
        ):
            self.assertEqual(self.workflow.count(argument), 2)
        self.assertIn("sha256sum --check --strict SHA256SUMS.txt", self.workflow)
        self.assertIn('test "${actual_arm_sha256}" = "${ARM_REPORT_SHA256}"', self.workflow)
        self.assertIn(
            '"${ARM_CANDIDATE_RUN_ID}" != "${CANDIDATE_RUN_ID}"',
            self.workflow,
        )
        self.assertIn(
            "a native shard returned nonzero while the aggregate claimed success",
            self.workflow,
        )

    def test_all_real_labs_are_fail_closed_and_never_pull_images(self) -> None:
        self.assertEqual(
            self.workflow.count("scripts/ci/package_lifecycle_lab.py"), 3
        )
        self.assertEqual(self.workflow.count("scripts/ci/nftables_kernel_lab.py"), 1)
        self.assertEqual(self.workflow.count("--pull-policy never"), 2)
        self.assertEqual(self.workflow.count("--pull-policy always"), 1)
        for status in (
            "package-lab.rc",
            "nftables-lab.rc",
        ):
            self.assertIn(status, self.workflow)
        self.assertGreaterEqual(self.workflow.count("set +e"), 5)
        self.assertNotIn("--ssh-host", self.workflow)

    def test_signed_linux_update_manifest_is_gated_and_recomputed(self) -> None:
        signing = workflow_step_script(
            self.workflow, "Generate and Verify Signed Update Manifest"
        )
        for contract in (
            '--packages "${CANDIDATE_PACKAGES_DIR}"',
            '--manifest "${manifest_path}"',
            '--signature "${signature_path}"',
            "SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY",
            "env -u SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY",
        ):
            self.assertIn(contract, signing)
        self.assertNotIn("set -x", signing)
        self.assertLess(
            self.workflow.index("Require Successful Qualification Before Release Signing"),
            self.workflow.index("Generate and Verify Signed Update Manifest"),
        )
        self.assertLess(
            self.workflow.index("Generate and Verify Signed Update Manifest"),
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
        self.assertIn('"${SIGNED_UPDATE_REQUIRED}" != "true"', verdict)
        self.assertIn("all(.[]; . == 0)", verdict)

    def test_linux_only_contract_has_no_retired_platform_transport_or_tools(self) -> None:
        lowered = self.workflow.lower()
        for forbidden in (
            RETIRED_PLATFORM,
            RETIRED_PACKAGE_SUFFIX,
            "syswarden_" + RETIRED_PLATFORM,
            "--" + RETIRED_PLATFORM + "-raw",
            "--" + RETIRED_PLATFORM + "-output",
            "--" + RETIRED_PLATFORM + "-envelope",
            "--" + RETIRED_PLATFORM + "-report",
            "tools_dir",
            "secrets_dir",
        ):
            self.assertNotIn(forbidden, lowered)
        upload = self.workflow.index("Upload Exact Qualification Evidence")
        cleanup = self.workflow.index("Remove Ephemeral Signing Material")
        verdict = self.workflow.index("Enforce Final Release Qualification Verdict")
        self.assertLess(upload, cleanup)
        self.assertLess(cleanup, verdict)

    def test_nftables_uses_private_verified_tmpdir_and_safe_cleanup(self) -> None:
        required = (
            'test "$(stat -c \'%a\' "${qualification_root}")" = "700"',
            'nftables_tmp_dir="${qualification_root}/nftables-tmp"',
            'TMPDIR="${NFTABLES_TMP_DIR}"',
            'GOTMPDIR="${NFTABLES_TMP_DIR}"',
            '"${NFTABLES_TMP_DIR}" != "${QUALIFICATION_ROOT}/nftables-tmp"',
            'find -P "${NFTABLES_TMP_DIR}" -xdev -mindepth 1 -delete',
            'rmdir -- "${NFTABLES_TMP_DIR}"',
        )
        for contract in required:
            self.assertIn(contract, self.workflow)

    def test_adapter_build_verify_and_release_gate_contracts_are_exact(self) -> None:
        required = (
            "release_qualification_adapter.py",
            '--nft-raw "${RAW_DIR}/nftables-raw.json"',
            '--package-raw "${RAW_DIR}/package-lifecycle-raw.json"',
            '--nft-output "${BOUND_DIR}/nftables-bound.json"',
            '--package-output "${BOUND_DIR}/package-lifecycle-bound.json"',
            '--nft-envelope "${BOUND_DIR}/nftables-bound.json"',
            '--package-envelope "${BOUND_DIR}/package-lifecycle-bound.json"',
            "--max-age-seconds 172800",
            "--max-report-skew-seconds 0",
            "release_qualification_gate.py",
            "--profile release",
            '--aggregate "${AGGREGATE_DIR}/release-qualification.json"',
        )
        for contract in required:
            self.assertIn(contract, self.workflow)
        self.assertNotIn("--profile characterization", self.workflow)
        self.assertNotIn("--" + RETIRED_PLATFORM + "-", self.workflow)

    def test_artifact_inventory_is_exact_bound_and_byte_verifiable(self) -> None:
        required = (
            "aggregate/release-qualification.json",
            "bound/nftables-bound.json",
            "bound/package-lifecycle-bound.json",
            "raw/nftables-raw.json",
            "raw/package-lifecycle-amd64.json",
            "raw/package-lifecycle-arm64.json",
            "raw/package-lifecycle-raw.json",
            "packages/candidate/SHA256SUMS.txt",
            "packages/previous/SHA256SUMS.txt",
            "qualification-context.json",
            "status/qualification-exit-codes.json",
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
