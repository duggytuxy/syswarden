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


def workflow_step(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
    return marker + step


def workflow_step_script(workflow: str, step_name: str) -> str:
    step = workflow_step(workflow, step_name)
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1:
        raise AssertionError(f"expected one shell body for workflow step {step_name}")
    return textwrap.dedent(step.split(run_marker, 1)[1])


def workflow_job(workflow: str, job_name: str) -> str:
    marker = f"  {job_name}:\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow job named {job_name}")
    remainder = workflow.split(marker, 1)[1]
    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\n", remainder)
    if next_job is not None:
        remainder = remainder[: next_job.start()]
    return marker + remainder


def valid_environment() -> dict[str, object]:
    return {
        "name": "syswarden-release-qualification",
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {"login": "duggytuxy", "id": 1},
                    }
                ],
            },
            {"type": "branch_policy"},
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def valid_policies() -> list[dict[str, object]]:
    return [
        {
            "total_count": 1,
            "branch_policies": [{"name": "main", "type": "branch"}],
        }
    ]


def run_environment_gate(
    script: str,
    environment: dict[str, object],
    policies: list[dict[str, object]],
    *,
    context_overrides: dict[str, str] | None = None,
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
                "EVENT_ACTOR": "duggytuxy",
                "EVENT_NAME": "workflow_dispatch",
                "EVENT_REF": "refs/heads/main",
                "EVENT_REF_NAME": "main",
                "EVENT_REF_TYPE": "branch",
                "EVENT_SHA": "a" * 40,
                "EVENT_TRIGGERING_ACTOR": "duggytuxy",
                "RELEASE_SHA": "a" * 40,
                "RELEASE_TAG": "v4.03.2",
                "REPOSITORY_OWNER": "duggytuxy",
                "RUN_ATTEMPT": "1",
                "RUNNER_ARCH_CONTEXT": "X64",
                "RUNNER_ENVIRONMENT_CONTEXT": "github-hosted",
                "RUNNER_OS_CONTEXT": "Linux",
                "PATH": f"{binary_directory}{os.pathsep}{process_environment['PATH']}",
                "TEST_ENVIRONMENT_JSON": json.dumps(
                    environment, separators=(",", ":")
                ),
                "TEST_POLICIES_JSON": json.dumps(policies, separators=(",", ":")),
            }
        )
        if context_overrides is not None:
            process_environment.update(context_overrides)
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )


def run_runner_gate(
    script: str,
    *,
    context_overrides: dict[str, str] | None = None,
    runner_config_overrides: dict[str, object] | None = None,
    runner_root_mode: int = 0o700,
    runner_work_mode: int = 0o700,
    runner_identity_mode: int = 0o600,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        runner_root = Path(temporary) / "runner"
        runner_temp = runner_root / "_work" / "_temp"
        runner_temp.mkdir(parents=True)
        runner_root.chmod(runner_root_mode)
        runner_temp.parent.chmod(runner_work_mode)
        runner_temp.chmod(runner_work_mode)
        runner_config: dict[str, object] = {
            "AgentId": 29,
            "AgentName": "syswarden-release-lab-123456-a1",
            "PoolId": 1,
            "PoolName": "Default",
            "DisableUpdate": True,
            "Ephemeral": True,
            "GitHubUrl": "https://github.com/duggytuxy/syswarden",
            "WorkFolder": "_work",
        }
        if runner_config_overrides is not None:
            runner_config.update(runner_config_overrides)
        for name, content in (
            (".runner", json.dumps(runner_config, separators=(",", ":"))),
            (".credentials", "{}"),
            (".credentials_rsaparams", "{}"),
        ):
            identity = runner_root / name
            identity.write_text(content, encoding="utf-8")
            identity.chmod(runner_identity_mode)
        process_environment = os.environ.copy()
        process_environment.update(
            {
                "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                "EVENT_ACTOR": "duggytuxy",
                "EVENT_TRIGGERING_ACTOR": "duggytuxy",
                "REPOSITORY_OWNER": "duggytuxy",
                "RUN_ATTEMPT": "1",
                "RUN_ID": "123456",
                "RUNNER_ARCH_CONTEXT": "X64",
                "RUNNER_NAME_CONTEXT": "syswarden-release-lab-123456-a1",
                "RUNNER_OS_CONTEXT": "Linux",
                "RUNNER_TEMP": str(runner_temp),
            }
        )
        if context_overrides is not None:
            process_environment.update(context_overrides)
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )


def run_unsigned_artifact_resolver(
    script: str,
    artifacts: list[dict[str, object]],
    *,
    context_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        binary_directory = temporary_path / "bin"
        binary_directory.mkdir()
        gh = binary_directory / "gh"
        gh.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *"/actions/runs/123456/artifacts"*)
    printf '%s\\n' "${TEST_ARTIFACTS_JSON:?}"
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
        output = temporary_path / "github-output"
        release_sha = "a" * 40
        artifact_name = (
            "syswarden-release-qualification-unsigned-123456-1-" + release_sha
        )
        process_environment = os.environ.copy()
        process_environment.update(
            {
                "EXPECTED_UNSIGNED_ARTIFACT_NAME": artifact_name,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                "PATH": f"{binary_directory}{os.pathsep}{process_environment['PATH']}",
                "RELEASE_SHA": release_sha,
                "RUN_ATTEMPT": "1",
                "RUN_ID": "123456",
                "TEST_ARTIFACTS_JSON": json.dumps(
                    [{"artifacts": artifacts}], separators=(",", ":")
                ),
            }
        )
        if context_overrides is not None:
            process_environment.update(context_overrides)
        result = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output_text = output.read_text(encoding="utf-8") if output.exists() else ""
        return result, output_text


class ReleaseQualificationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def assert_read_only(self, workflow: str) -> None:
        self.assertIn("permissions:\n  actions: read\n  contents: read", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s*(?:contents|actions):\s*write\s*$")
        self.assertNotRegex(
            workflow,
            r"(?m)^\s*(?:id-token|attestations|packages):\s*write\s*$",
        )
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
        self.assertEqual(dict(ACTION.findall(self.workflow)), expected)

    def test_self_hosted_and_hosted_jobs_are_strictly_split(self) -> None:
        arm = workflow_job(self.workflow, "package-lifecycle-arm64")
        x64 = workflow_job(self.workflow, "qualify-release")
        hosted = workflow_job(self.workflow, "seal-release")
        self.assertIn("runs-on: ubuntu-24.04-arm", arm)
        for label in (
            "- self-hosted",
            "- linux",
            "- x64",
            "- ${{ 'syswarden-release-lab' }}",
        ):
            self.assertIn(label, x64)
        self.assertIn("needs: package-lifecycle-arm64", x64)
        self.assertNotIn("environment:", x64)
        self.assertNotIn("${{ secrets.", x64)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", x64)
        self.assertIn("needs: qualify-release", hosted)
        self.assertIn("runs-on: ubuntu-24.04\n", hosted)
        self.assertNotIn("self-hosted", hosted)
        self.assertIn(
            "environment:\n      name: syswarden-release-qualification",
            hosted,
        )
        self.assertEqual(hosted.count("${{ secrets."), 1)
        self.assertEqual(self.workflow.count("    environment:\n"), 1)
        self.assertEqual(self.workflow.count("- self-hosted"), 1)

    def test_runner_api_is_absent_and_local_runner_hardening_is_non_authoritative(self) -> None:
        self.assertNotIn("/actions/runners", self.workflow)
        script = workflow_step_script(
            self.workflow, "Validate Dedicated Ephemeral Qualification Runner"
        )
        for contract in (
            'expected_runner_name="syswarden-release-lab-${RUN_ID}-a${RUN_ATTEMPT}"',
            '"${RUNNER_NAME_CONTEXT}" != "${expected_runner_name}"',
            '"${RUNNER_OS_CONTEXT}" != "Linux"',
            '"${RUNNER_ARCH_CONTEXT}" != "X64"',
            '"$(stat -c \'%a\' "${directory}")" != "700"',
            "for identity_file in .runner .credentials .credentials_rsaparams",
            ".DisableUpdate == true",
            ".Ephemeral == true",
            '.GitHubUrl == $expected_url',
            '.WorkFolder == "_work"',
            '.PoolName == "Default"',
        ):
            self.assertIn(contract, script)
        self.assertNotIn("gh api", script)
        self.assertNotIn("GH_TOKEN", script)
        result = run_runner_gate(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_runner_context_identity_and_permissions_fail_closed(self) -> None:
        script = workflow_step_script(
            self.workflow, "Validate Dedicated Ephemeral Qualification Runner"
        )
        for name, overrides in (
            ("actor", {"EVENT_ACTOR": "contributor"}),
            ("triggering actor", {"EVENT_TRIGGERING_ACTOR": "contributor"}),
            ("attempt", {"RUN_ATTEMPT": "2"}),
            ("run id", {"RUN_ID": "0"}),
            ("runner name", {"RUNNER_NAME_CONTEXT": "shared"}),
            ("runner os", {"RUNNER_OS_CONTEXT": "Windows"}),
            ("runner arch", {"RUNNER_ARCH_CONTEXT": "ARM64"}),
            ("runner path", {"RUNNER_TEMP": "/tmp"}),
        ):
            with self.subTest(context=name):
                result = run_runner_gate(script, context_overrides=overrides)
                self.assertNotEqual(result.returncode, 0, result.stderr)
        for name, overrides in (
            ("persistent", {"Ephemeral": False}),
            ("updates enabled", {"DisableUpdate": False}),
            ("wrong repository", {"GitHubUrl": "https://github.com/example/repo"}),
            ("wrong work folder", {"WorkFolder": "work"}),
            ("wrong pool", {"PoolName": "Untrusted"}),
            ("missing id", {"AgentId": 0}),
            ("string id", {"AgentId": "29"}),
        ):
            with self.subTest(runner=name):
                result = run_runner_gate(script, runner_config_overrides=overrides)
                self.assertNotEqual(result.returncode, 0, result.stderr)
        for name, root_mode, work_mode, identity_mode in (
            ("open root", 0o755, 0o700, 0o600),
            ("open work", 0o700, 0o755, 0o600),
            ("open identity", 0o700, 0o700, 0o644),
        ):
            with self.subTest(permissions=name):
                result = run_runner_gate(
                    script,
                    runner_root_mode=root_mode,
                    runner_work_mode=work_mode,
                    runner_identity_mode=identity_mode,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_hosted_environment_requires_owner_review_main_only_and_no_bypass(self) -> None:
        script = workflow_step_script(
            self.workflow, "Validate Protected Hosted Signing Context"
        )
        for contract in (
            "environments/syswarden-release-qualification",
            '.type == "required_reviewers"',
            '.type == "branch_policy"',
            '"${reviewer_rule_count}" != "1"',
            '"${reviewer_entry_count}" != "1"',
            '"${owner_reviewer_count}" != "1"',
            '"${prevent_self_review}" != "false"',
            '"${protection_rule_count}" != "2"',
            ".deployment_branch_policy[$field]",
            "required_environment_boolean",
            "required_top_level_environment_boolean",
            '"${can_admins_bypass}" != "false"',
            "forbid administrator bypass",
            "deployment-branch-policies",
            '.name == "main" and .type == "branch"',
            '"${policy_count}" != "1"',
            '"${main_policy_count}" != "1"',
            '"${RUNNER_ENVIRONMENT_CONTEXT}" != "github-hosted"',
        ):
            self.assertIn(contract, script)
        self.assertIn('.reviewer.login == $owner', script)
        self.assertNotIn("/actions/runners", script)
        result = run_environment_gate(script, valid_environment(), valid_policies())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hosted_environment_and_context_are_adversarially_fail_closed(self) -> None:
        script = workflow_step_script(
            self.workflow, "Validate Protected Hosted Signing Context"
        )
        for name, overrides in (
            ("actor", {"EVENT_ACTOR": "contributor"}),
            ("triggering actor", {"EVENT_TRIGGERING_ACTOR": "contributor"}),
            ("attempt", {"RUN_ATTEMPT": "2"}),
            ("event", {"EVENT_NAME": "push"}),
            ("ref", {"EVENT_REF": "refs/heads/release"}),
            ("sha", {"EVENT_SHA": "b" * 40}),
            ("host type", {"RUNNER_ENVIRONMENT_CONTEXT": "self-hosted"}),
            ("os", {"RUNNER_OS_CONTEXT": "Windows"}),
            ("arch", {"RUNNER_ARCH_CONTEXT": "ARM64"}),
        ):
            with self.subTest(context=name):
                result = run_environment_gate(
                    script,
                    valid_environment(),
                    valid_policies(),
                    context_overrides=overrides,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)

        mutations: list[tuple[str, dict[str, object]]] = []
        for field, value in (
            ("can_admins_bypass", True),
            ("can_admins_bypass", "false"),
        ):
            mutated = json.loads(json.dumps(valid_environment()))
            mutated[field] = value
            mutations.append((f"top-level {field}={value!r}", mutated))
        for field, value in (
            ("protected_branches", True),
            ("protected_branches", "false"),
            ("custom_branch_policies", False),
            ("custom_branch_policies", "true"),
        ):
            mutated = json.loads(json.dumps(valid_environment()))
            mutated["deployment_branch_policy"][field] = value
            mutations.append((f"branch policy {field}={value!r}", mutated))
        for name, reviewer, prevent_self_review in (
            ("missing reviewer", [], False),
            (
                "wrong reviewer",
                [{"type": "User", "reviewer": {"login": "other", "id": 2}}],
                False,
            ),
            (
                "team reviewer",
                [{"type": "Team", "reviewer": {"login": "owners", "id": 3}}],
                False,
            ),
            (
                "self review forbidden",
                [
                    {
                        "type": "User",
                        "reviewer": {"login": "duggytuxy", "id": 1},
                    }
                ],
                True,
            ),
        ):
            mutated = json.loads(json.dumps(valid_environment()))
            mutated["protection_rules"][0]["reviewers"] = reviewer
            mutated["protection_rules"][0][
                "prevent_self_review"
            ] = prevent_self_review
            mutations.append((name, mutated))
        for name, environment in mutations:
            with self.subTest(environment=name):
                result = run_environment_gate(script, environment, valid_policies())
                self.assertNotEqual(result.returncode, 0, result.stderr)

        for name, policies in (
            ("no policy", [{"total_count": 0, "branch_policies": []}]),
            (
                "wrong branch",
                [
                    {
                        "total_count": 1,
                        "branch_policies": [{"name": "release", "type": "branch"}],
                    }
                ],
            ),
            (
                "extra branch",
                [
                    {
                        "total_count": 2,
                        "branch_policies": [
                            {"name": "main", "type": "branch"},
                            {"name": "release", "type": "branch"},
                        ],
                    }
                ],
            ),
        ):
            with self.subTest(policy=name):
                result = run_environment_gate(script, valid_environment(), policies)
                self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_candidate_context_is_exact_main_sha_and_pre_tag_in_both_stages(self) -> None:
        for step_name in (
            "Validate Manual Main Pre-Tag Context",
            "Revalidate Exact Hosted Candidate Commit",
        ):
            script = workflow_step_script(self.workflow, step_name)
            for contract in (
                "./scripts/versioning.sh inspect",
                "./scripts/versioning.sh validate-commit",
                "git merge-base --is-ancestor",
                "git show-ref --verify --quiet",
                "git ls-remote --exit-code --refs origin",
            ):
                self.assertIn(contract, script)
        arm_context = workflow_step_script(
            self.workflow, "Validate Native ARM64 Shard Context"
        )
        for contract in (
            '"${EVENT_ACTOR}" != "${REPOSITORY_OWNER}"',
            '"${EVENT_TRIGGERING_ACTOR}" != "${REPOSITORY_OWNER}"',
            '"${RUN_ATTEMPT}" != "1"',
        ):
            self.assertIn(contract, arm_context)
        self.assertNotIn("--tag-phase", self.workflow)
        self.assertNotIn("--require-tag", self.workflow)

    def test_package_main_is_independently_resolved_on_hosted_runner(self) -> None:
        for step_name in (
            "Resolve Unique Successful Main Package Artifact",
            "Resolve Exact Package Main Artifact for Hosted Signing",
        ):
            script = workflow_step_script(self.workflow, step_name)
            for contract in (
                "actions/workflows/package.yml/runs",
                "-f event=push",
                '-f head_sha="${RELEASE_SHA}"',
                '.head_branch == "main"',
                '.event == "push"',
                '"${run_status}" != "completed"',
                '"${run_conclusion}" != "success"',
                "actions/runs/${run_id}/artifacts",
                '"$(jq \'length\' <<< "${artifact_matches}")" != "1"',
            ):
                self.assertIn(contract, script)
        self.assertEqual(self.workflow.count("actions/workflows/package.yml/runs"), 3)

    def test_unsigned_artifact_is_resolved_by_exact_run_bound_identity(self) -> None:
        script = workflow_step_script(
            self.workflow, "Resolve Exact Unsigned Qualification Artifact"
        )
        release_sha = "a" * 40
        artifact_name = (
            "syswarden-release-qualification-unsigned-123456-1-" + release_sha
        )
        valid_artifact: dict[str, object] = {
            "id": 987654,
            "name": artifact_name,
            "expired": False,
            "size_in_bytes": 4096,
            "workflow_run": {"id": 123456, "head_sha": release_sha},
        }
        result, output = run_unsigned_artifact_resolver(script, [valid_artifact])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            output,
            f"artifact_id=987654\nartifact_name={artifact_name}\n",
        )

        invalid_cases: list[tuple[list[dict[str, object]], dict[str, str] | None]] = [
            ([valid_artifact, valid_artifact], None),
            ([{**valid_artifact, "expired": True}], None),
            ([{**valid_artifact, "size_in_bytes": 0}], None),
            (
                [
                    {
                        **valid_artifact,
                        "workflow_run": {"id": 123457, "head_sha": release_sha},
                    }
                ],
                None,
            ),
            (
                [
                    {
                        **valid_artifact,
                        "workflow_run": {"id": 123456, "head_sha": "b" * 40},
                    }
                ],
                None,
            ),
            (
                [valid_artifact],
                {"EXPECTED_UNSIGNED_ARTIFACT_NAME": "unexpected-artifact"},
            ),
        ]
        for artifacts, overrides in invalid_cases:
            with self.subTest(artifacts=artifacts, overrides=overrides):
                result, _ = run_unsigned_artifact_resolver(
                    script, artifacts, context_overrides=overrides
                )
                self.assertNotEqual(result.returncode, 0)

    def test_hosted_package_byte_gate_precedes_the_only_secret_reference(self) -> None:
        gate_name = "Require Successful Qualification Before Release Signing"
        gate = workflow_step_script(self.workflow, gate_name)
        signing_name = "Generate and Verify Signed Update Manifest"
        signing = workflow_step_script(self.workflow, signing_name)
        for contract in (
            "sha256sum --check --strict EVIDENCE_SHA256SUMS.txt",
            "expected_manifest_files",
            "manifest_line_count",
            "unsigned qualification checksum coverage is not exact",
            "verify-packages",
            "cmp -s",
            '"${CANDIDATE_RUN_ID}" != "${EXPECTED_CANDIDATE_RUN_ID}"',
            "release_qualification_adapter.py",
            "release_qualification_gate.py",
            "all(.[]; . == 0)",
            "printf 'verified=true\\n'",
        ):
            self.assertIn(contract, gate)
        self.assertEqual(gate.count("verify-packages"), 2)
        self.assertNotIn("${{ secrets.", gate)
        self.assertEqual(self.workflow.count("${{ secrets."), 1)
        self.assertLess(self.workflow.index(gate_name), self.workflow.index(signing_name))
        secret_index = self.workflow.index("${{ secrets.")
        self.assertGreater(secret_index, self.workflow.index(gate_name))
        self.assertIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", signing)
        self.assertIn("env -u SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", signing)
        self.assertNotIn("set -x", signing)

    def test_unsigned_and_final_artifact_names_and_inventories_are_exact(self) -> None:
        x64 = workflow_job(self.workflow, "qualify-release")
        hosted = workflow_job(self.workflow, "seal-release")
        unsigned_name = (
            "syswarden-release-qualification-unsigned-"
            "${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RELEASE_SHA}"
        )
        self.assertIn(unsigned_name, x64)
        self.assertIn(
            "EXPECTED_UNSIGNED_ARTIFACT_NAME: ${{ needs.qualify-release.outputs.unsigned_artifact_name }}",
            hosted,
        )
        self.assertIn(
            "artifact-ids: ${{ steps.unsigned_artifact.outputs.artifact_id }}",
            hosted,
        )
        self.assertIn("merge-multiple: true", hosted)
        self.assertIn("name: syswarden-release-qualification", hosted)
        self.assertNotIn("name: syswarden-release-qualification\n", x64)
        unsigned_seal = workflow_step_script(
            self.workflow, "Seal Exact Unsigned Qualification Evidence Inventory"
        )
        self.assertNotIn("update/syswarden-update-manifest-v1.json", unsigned_seal)
        final_seal = workflow_step_script(
            self.workflow, "Seal Exact Qualification Evidence Inventory"
        )
        for contract in (
            "update/syswarden-update-manifest-v1.json",
            "update/syswarden-update-manifest-v1.json.sig",
            'rm -f -- "${UNSIGNED_EVIDENCE_ROOT}/EVIDENCE_SHA256SUMS.txt"',
            "sha256sum --check --strict EVIDENCE_SHA256SUMS.txt",
            '-eq "$(( ${#sorted_expected[@]} + 1 ))"',
        ):
            self.assertIn(contract, final_seal)

    def test_hosted_signing_tool_is_built_tested_and_revalidated_from_checkout(self) -> None:
        hosted = workflow_job(self.workflow, "seal-release")
        checkout = hosted.index("Checkout Exact Hosted Signing Commit")
        byte_gate = hosted.index("Require Successful Qualification Before Release Signing")
        build = hosted.index("Build and Test Signed Update Manifest Tool")
        revalidate = hosted.index("Revalidate Hosted Signing Tool Before Secret Exposure")
        sign = hosted.index("Generate and Verify Signed Update Manifest")
        self.assertLess(checkout, byte_gate)
        self.assertLess(byte_gate, build)
        self.assertLess(build, revalidate)
        self.assertLess(revalidate, sign)
        build_script = workflow_step_script(
            self.workflow, "Build and Test Signed Update Manifest Tool"
        )
        self.assertIn("GOFLAGS=-mod=readonly go test", build_script)
        self.assertIn("GOFLAGS=-mod=readonly go build", build_script)
        self.assertIn("update_manifest_test.go", build_script)
        self.assertEqual(build_script.count("git rev-parse --verify 'HEAD^{commit}'"), 2)
        self.assertEqual(build_script.count("git status --porcelain=v1"), 2)
        revalidate_script = workflow_step_script(
            self.workflow, "Revalidate Hosted Signing Tool Before Secret Exposure"
        )
        self.assertIn("EXPECTED_MANIFEST_TOOL_SHA256", revalidate_script)
        self.assertIn("actual_tool_sha256", revalidate_script)

    def test_previous_release_transition_and_native_labs_remain_fail_closed(self) -> None:
        for contract, count in {
            'if [[ "${PREVIOUS_TAG}" == "v4.02.8" ]]': 2,
            "normalize-v4028-linux-packages": 2,
            "public-release-assets.json": 2,
            "public-SHA256SUMS.txt": 2,
            "v4.02.8-linux-transition.json": 2,
            "transition_required=false": 2,
            "transition_required=true": 2,
        }.items():
            self.assertEqual(self.workflow.count(contract), count, contract)
        self.assertEqual(self.workflow.count("scripts/ci/package_lifecycle_lab.py"), 3)
        self.assertEqual(self.workflow.count("scripts/ci/nftables_kernel_lab.py"), 1)
        self.assertEqual(self.workflow.count("--pull-policy never"), 2)
        self.assertEqual(self.workflow.count("--pull-policy always"), 1)
        self.assertIn("--architecture-shard arm64", self.workflow)
        self.assertIn("--architecture-shard amd64", self.workflow)
        self.assertIn('test "$(uname -m)" = "aarch64"', self.workflow)

    def test_previous_packages_use_exact_latest_public_release_asset_ids(self) -> None:
        for contract in (
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
            '"repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}"',
            "-H 'Accept: application/octet-stream'",
        ):
            self.assertIn(contract, self.workflow)
        self.assertEqual(self.workflow.count("verify-packages"), 6)

    def test_nftables_uses_private_verified_tmpdir_and_safe_cleanup(self) -> None:
        for contract in (
            'test "$(stat -c \'%a\' "${qualification_root}")" = "700"',
            'nftables_tmp_dir="${qualification_root}/nftables-tmp"',
            'TMPDIR="${NFTABLES_TMP_DIR}"',
            'GOTMPDIR="${NFTABLES_TMP_DIR}"',
            '"${NFTABLES_TMP_DIR}" != "${QUALIFICATION_ROOT}/nftables-tmp"',
            'find -P "${NFTABLES_TMP_DIR}" -xdev -mindepth 1 -delete',
            'rmdir -- "${NFTABLES_TMP_DIR}"',
        ):
            self.assertIn(contract, self.workflow)

    def test_unsigned_failure_evidence_uploads_before_x64_verdict(self) -> None:
        x64 = workflow_job(self.workflow, "qualify-release")
        upload = x64.index("Upload Exact Unsigned Qualification Evidence")
        cleanup = x64.index("Remove Ephemeral Qualification Material")
        verdict = x64.index("Enforce Final Release Qualification Verdict")
        self.assertLess(upload, cleanup)
        self.assertLess(cleanup, verdict)
        self.assertIn(
            "if: ${{ always() && steps.inventory.outcome == 'success' }}",
            x64,
        )
        self.assertIn('"${UPLOAD_OUTCOME}" != "success"', x64[verdict:])
        self.assertIn("all(.[]; . == 0)", x64[verdict:])

    def test_hosted_gate_sign_seal_upload_cleanup_and_verdict_order_is_exact(self) -> None:
        hosted = workflow_job(self.workflow, "seal-release")
        ordered = (
            "Require Successful Qualification Before Release Signing",
            "Build and Test Signed Update Manifest Tool",
            "Revalidate Hosted Signing Tool Before Secret Exposure",
            "Generate and Verify Signed Update Manifest",
            "Seal Exact Qualification Evidence Inventory",
            "Upload Exact Final Qualification Evidence",
            "Remove Ephemeral Signing Material",
            "Enforce Hosted Qualification Seal Verdict",
        )
        positions = [hosted.index(name) for name in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("if-no-files-found: error", hosted)
        self.assertIn("name: syswarden-release-qualification", hosted)
        self.assertIn('"${FINAL_UPLOAD_OUTCOME}" != "success"', hosted)

    def test_native_shards_and_evidence_are_bound_to_one_run_and_source(self) -> None:
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
            self.assertEqual(self.workflow.count(argument), 2, argument)
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
            self.assertGreaterEqual(self.workflow.count(argument), 3, argument)
        self.assertIn('test "${actual_arm_sha256}" = "${ARM_REPORT_SHA256}"', self.workflow)
        self.assertIn(
            '"${ARM_CANDIDATE_RUN_ID}" != "${CANDIDATE_RUN_ID}"',
            self.workflow,
        )

    def test_optional_rhel_image_extension_has_a_protected_offline_gate(self) -> None:
        x64 = workflow_job(self.workflow, "qualify-release")
        step_name = "Qualify Optional RHEL Image Extension Offline Contract"
        script = workflow_step_script(self.workflow, step_name)
        self.assertIn(step_name, x64)
        self.assertIn("command -v unshare", script)
        self.assertIn(
            "bash -n \\\n"
            "  extensions/rhel-image/stage-syswarden-rhel-image.sh \\\n"
            "  extensions/rhel-image/tests/test-stage.sh",
            script,
        )
        self.assertIn("extensions/rhel-image/tests/test-stage.sh", script)
        self.assertLess(
            x64.index("Validate Manual Main Pre-Tag Context"),
            x64.index(step_name),
        )
        self.assertLess(
            x64.index(step_name),
            x64.index("Create Isolated Qualification Workspace"),
        )

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
        for forbidden in (
            "SYSWARDEN_QEMU_AARCH64_STATIC",
            "/proc/sys/fs/binfmt_misc/qemu-aarch64",
            "--arm64-emulator",
            "host_binfmt_qemu_aarch64",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_adversarial_static_mutations_are_detected(self) -> None:
        with self.assertRaises(AssertionError):
            self.assert_read_only(
                self.workflow.replace("contents: read", "contents: write", 1)
            )
        checkout_pin = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        with self.assertRaises(AssertionError):
            self.assert_actions_are_pinned(
                self.workflow.replace(checkout_pin, "v7.0.1", 1)
            )
        x64 = workflow_job(self.workflow, "qualify-release")
        hosted = workflow_job(self.workflow, "seal-release")
        self.assertNotIn("environment:", x64)
        self.assertNotIn("${{ secrets.", x64)
        self.assertIn("runs-on: ubuntu-24.04\n", hosted)
        self.assertIn("needs: qualify-release", hosted)


if __name__ == "__main__":
    unittest.main()
