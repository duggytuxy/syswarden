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
PACKAGE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "package.yml"
PACKAGE_LAB = REPOSITORY / "scripts" / "ci" / "package_lifecycle_lab.py"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTION = re.compile(r"(?m)^\s*uses:\s*([^@\s]+)@([^\s#]+)")
RETIRED_PLATFORM = "free" + "bsd"
RETIRED_PACKAGE_SUFFIX = "." + "txz"


def workflow_step(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    remainder = workflow.split(marker, 1)[1]
    boundaries = []
    next_step = remainder.find("\n      - name:")
    if next_step >= 0:
        boundaries.append(next_step)
    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\n", remainder)
    if next_job is not None:
        boundaries.append(next_job.start())
    step = remainder[: min(boundaries)] if boundaries else remainder
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
    runner_config_removals: tuple[str, ...] = (),
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
            "agentId": 29,
            "agentName": "syswarden-release-lab-123456-a1",
            "poolId": 1,
            "poolName": "Default",
            "disableUpdate": True,
            "ephemeral": True,
            "gitHubUrl": "https://github.com/duggytuxy/syswarden",
            "workFolder": "_work",
        }
        if runner_config_overrides is not None:
            runner_config.update(runner_config_overrides)
        for key in runner_config_removals:
            runner_config.pop(key, None)
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


def run_arm_verdict(
    script: str,
    report: dict[str, object],
    status: str = "0\n",
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        evidence_directory = Path(temporary)
        (evidence_directory / "package-lifecycle-arm64.json").write_text(
            json.dumps(report, separators=(",", ":")),
            encoding="utf-8",
        )
        (evidence_directory / "package-lifecycle-arm64.rc").write_text(
            status,
            encoding="utf-8",
        )
        process_environment = os.environ.copy()
        process_environment["ARM_EVIDENCE_DIR"] = str(evidence_directory)
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )


def run_arm_seal(
    script: str,
    report: dict[str, object] | None,
    status: str = "0\n",
) -> tuple[subprocess.CompletedProcess[str], str]:
    with tempfile.TemporaryDirectory() as temporary:
        evidence_directory = Path(temporary) / "evidence"
        evidence_directory.mkdir()
        if report is not None:
            (evidence_directory / "package-lifecycle-arm64.json").write_text(
                json.dumps(report, separators=(",", ":")),
                encoding="utf-8",
            )
        (evidence_directory / "package-lifecycle-arm64.rc").write_text(
            status,
            encoding="utf-8",
        )
        github_output = Path(temporary) / "github-output"
        process_environment = os.environ.copy()
        process_environment.update(
            {
                "ARM_EVIDENCE_DIR": str(evidence_directory),
                "GITHUB_OUTPUT": str(github_output),
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_RUN_ID": "123456",
                "RELEASE_SHA": "a" * 40,
            }
        )
        result = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=REPOSITORY,
            env=process_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = github_output.read_text(encoding="utf-8") if github_output.exists() else ""
        return result, output


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
        cls.package_workflow = PACKAGE_WORKFLOW.read_text(encoding="utf-8")
        cls.package_lab = PACKAGE_LAB.read_text(encoding="utf-8")

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

    def assert_arm64_delegated_owner_contract(self, workflow: str) -> None:
        script = workflow_step_script(
            workflow, "Run Native ARM64 Package Lifecycle Shard"
        )
        required = (
            'host_owner_identity="${user_id}:${user_group}"',
            '! "${host_owner_identity}" =~ ^[1-9][0-9]*:[0-9]+$',
            '"$(stat -c \'%u\' "${HOME}")" != \\\n'
            '        "${user_id}"',
            '"${host_owner_identity}:700:${ARM_SHARD_ROOT_INODE}"',
            '"${host_owner_identity}:700:${ARM_CRUN_DIRECTORY_INODE}"',
            '"${host_owner_identity}:700:3298128:${ARM_CRUN_INODE}"',
            '"$(stat -c \'%u:%g:%a\' "${containers_conf}")" !=',
            '"$(stat -c \'%u:%g:%a\' "${podman_local}")" !=',
            '"$(stat -c \'%u:%g:%a\' "${podman_info}")" !=',
            '--setenv="SYSWARDEN_HOST_OWNER=${host_owner_identity}"',
            '--setenv="SYSWARDEN_HOST_UID=${user_id}"',
            '! "${SYSWARDEN_HOST_UID}" =~ ^[1-9][0-9]*$',
            '! "${SYSWARDEN_HOST_OWNER}" =~ ^[1-9][0-9]*:[0-9]+$',
            '"${SYSWARDEN_HOST_OWNER%%:*}" != "${SYSWARDEN_HOST_UID}"',
            'delegated_uid="$(id -u)"',
            '"${delegated_uid}" != "${SYSWARDEN_HOST_UID}"',
            "native ARM64 delegated UID differs from the exported host UID",
            '"$(stat -c "%u:%g:%a" "${CONTAINERS_CONF}")" != '
            '"${SYSWARDEN_HOST_OWNER}:600"',
            '"$(stat -c "%u:%g:%a" "${SYSWARDEN_PODMAN_LOCAL}")" != '
            '"${SYSWARDEN_HOST_OWNER}:700"',
            'expected_crun_parent_identity="${SYSWARDEN_HOST_OWNER}:700:'
            '${SYSWARDEN_CRUN_DIRECTORY_INODE}"',
            '"${crun_parent_identity}" != "${expected_crun_parent_identity}"',
            "native ARM64 crun parent identity changed inside the delegated session",
            'expected_crun_identity="${SYSWARDEN_HOST_OWNER}:700:3298128:'
            '${SYSWARDEN_CRUN_INODE}"',
            '"${crun_identity}" != "${expected_crun_identity}"',
            "native ARM64 crun identity changed inside the delegated session",
            'printf "%s  %s\\n" "${SYSWARDEN_CRUN_SHA256}" '
            '"${SYSWARDEN_CRUN_PATH}"',
            'crun_version_output="$("${SYSWARDEN_CRUN_PATH}" --root '
            '"${crun_parent}" --version)"',
            '"${crun_version_lines[2]:-}" != "rundir: ${crun_parent}"',
            r'\+SYSTEMD($|[[:space:]])',
            'expected_podman_info_identity="${SYSWARDEN_HOST_OWNER}:600:'
            '${SYSWARDEN_PODMAN_INFO_INODE}"',
            '"${podman_info_identity}" != "${expected_podman_info_identity}"',
            "native ARM64 Podman info evidence changed identity or permissions",
            "(expected=%s observed=%s)",
        )
        for contract in required:
            self.assertIn(contract, script)
        self.assertEqual(
            script.count('--setenv="SYSWARDEN_HOST_OWNER=${host_owner_identity}"'),
            1,
        )
        self.assertEqual(
            script.count('--setenv="SYSWARDEN_HOST_UID=${user_id}"'), 1
        )
        self.assertNotIn('account_owner_identity=', script)

        systemd_run = script.index("sudo -n systemd-run")
        delegated_shell = script.index(
            "/usr/bin/bash --noprofile --norc -e -o pipefail -c", systemd_run
        )
        lifecycle_lab = script.index("scripts/ci/package_lifecycle_lab.py")
        delegated_script = script[delegated_shell:lifecycle_lab]
        self.assertNotIn("$(id -g)", delegated_script)
        self.assertNotIn('$(id -g "${user_name}")', script)

        ordered = (
            "native ARM64 delegated host owner identity is incomplete",
            "native ARM64 delegated UID differs from the exported host UID",
            "native ARM64 Podman configuration isolation is incomplete",
            "native ARM64 local-only Podman launcher is unavailable",
            "native ARM64 Podman info target is unavailable",
            "native ARM64 crun delegated identity is incomplete",
            "native ARM64 crun parent is not a real delegated directory",
            "native ARM64 crun parent identity is unavailable inside the delegated session",
            "native ARM64 crun parent identity changed inside the delegated session",
            "native ARM64 crun is not a real delegated executable",
            "native ARM64 crun identity is unavailable inside the delegated session",
            "native ARM64 crun identity changed inside the delegated session",
            "native ARM64 crun changed bytes inside the delegated session",
            "native ARM64 crun is not executable inside the delegated session",
            "native ARM64 crun lacks the exact delegated version or systemd capability",
            "native ARM64 conmon is not executable inside the delegated session",
            "native ARM64 Podman could not attest its isolated runtime configuration",
            "native ARM64 Podman info evidence is not a real non-empty file",
            "native ARM64 Podman info evidence identity is unavailable",
            "native ARM64 Podman info evidence changed identity or permissions",
            "native ARM64 Podman resolved an unexpected local runtime configuration",
        )
        positions = [delegated_script.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))

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
        self.assertIn("if: ${{ !cancelled() }}", x64)
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
            "def has_exact_key($canonical):",
            'has_exact_key("agentId")',
            'has_exact_key("agentName")',
            'has_exact_key("disableUpdate")',
            'has_exact_key("ephemeral")',
            'has_exact_key("gitHubUrl")',
            'has_exact_key("workFolder")',
            'has_exact_key("poolName")',
            ".agentName == $expected_name",
            ".disableUpdate == true",
            ".ephemeral == true",
            '.gitHubUrl == $expected_url',
            '.workFolder == "_work"',
            '.poolName == "Default"',
            '(.agentId | type == "number" and . > 0 and floor == .)',
        ):
            self.assertIn(contract, script)
        for forbidden_alias in (
            ".AgentId",
            ".AgentName",
            ".DisableUpdate",
            ".Ephemeral",
            ".GitHubUrl",
            ".WorkFolder",
            ".PoolName",
        ):
            self.assertNotIn(forbidden_alias, script)
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
            ("wrong configured name", {"agentName": "shared-runner"}),
            ("persistent", {"ephemeral": False}),
            ("updates enabled", {"disableUpdate": False}),
            ("wrong repository", {"gitHubUrl": "https://github.com/example/repo"}),
            ("wrong work folder", {"workFolder": "work"}),
            ("wrong pool", {"poolName": "Untrusted"}),
            ("missing id", {"agentId": 0}),
            ("string id", {"agentId": "29"}),
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

    def test_local_runner_schema_rejects_case_aliases_and_collisions(self) -> None:
        script = workflow_step_script(
            self.workflow, "Validate Dedicated Ephemeral Qualification Runner"
        )
        canonical_values: dict[str, object] = {
            "agentId": 29,
            "agentName": "syswarden-release-lab-123456-a1",
            "disableUpdate": True,
            "ephemeral": True,
            "gitHubUrl": "https://github.com/duggytuxy/syswarden",
            "workFolder": "_work",
            "poolName": "Default",
        }
        pascal_aliases = {
            "agentId": "AgentId",
            "agentName": "AgentName",
            "disableUpdate": "DisableUpdate",
            "ephemeral": "Ephemeral",
            "gitHubUrl": "GitHubUrl",
            "workFolder": "WorkFolder",
            "poolName": "PoolName",
        }
        mixed_case_aliases = {
            "agentId": "AGENTID",
            "agentName": "aGeNtNaMe",
            "disableUpdate": "disableupdate",
            "ephemeral": "ePhEmErAl",
            "gitHubUrl": "githuburl",
            "workFolder": "wOrKfOlDeR",
            "poolName": "poolname",
        }
        conflicting_values: dict[str, object] = {
            "agentId": 30,
            "agentName": "shared-runner",
            "disableUpdate": False,
            "ephemeral": False,
            "gitHubUrl": "https://github.com/example/repo",
            "workFolder": "work",
            "poolName": "Untrusted",
        }
        for canonical, alias in pascal_aliases.items():
            with self.subTest(field=canonical, representation="PascalCase alias"):
                result = run_runner_gate(
                    script,
                    runner_config_overrides={alias: canonical_values[canonical]},
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
            with self.subTest(field=canonical, representation="PascalCase only"):
                result = run_runner_gate(
                    script,
                    runner_config_overrides={alias: canonical_values[canonical]},
                    runner_config_removals=(canonical,),
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
        for canonical, alias in mixed_case_aliases.items():
            with self.subTest(field=canonical, representation="mixed-case conflict"):
                result = run_runner_gate(
                    script,
                    runner_config_overrides={alias: conflicting_values[canonical]},
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
            'podman_path="/usr/local/bin/podman"',
            "for parent in /usr /usr/local /usr/local/bin; do",
            '"$(stat -c \'%u:%g\' "${parent}")" != "0:0"',
            "(( (8#${parent_mode} & 0022) != 0 ))",
            '[[ ! -f "${podman_path}" || -L "${podman_path}"',
            '! -x "${podman_path}"',
            '"$(stat -c \'%u:%g\' "${podman_path}")" != "0:0"',
            "(( (8#${podman_mode} & 0022) != 0 ))",
        ):
            self.assertIn(contract, arm_context)
        self.assertNotIn("command -v podman", arm_context)
        self.assertNotIn("--tag-phase", self.workflow)
        self.assertNotIn("--require-tag", self.workflow)

    def test_arm64_podman_trust_path_is_sealed_before_checkout(self) -> None:
        step_name = "Seal Native ARM64 Podman Trust Path"
        step = workflow_step(self.workflow, step_name)
        self.assertIn(
            "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}", step
        )
        script = workflow_step_script(self.workflow, step_name)
        for contract in (
            'podman_parent="/usr/local/bin"',
            "for trusted_parent in /usr /usr/bin /usr/local; do",
            '"$(/usr/bin/stat -c \'%u:%g\' "${trusted_parent}")" != "0:0"',
            "(( (8#${trusted_parent_mode} & 0022) != 0 ))",
            "/usr/bin/bash",
            "/usr/bin/chmod",
            "/usr/bin/curl",
            "/usr/bin/install",
            "/usr/bin/rm",
            "/usr/bin/rmdir",
            "/usr/bin/sha256sum",
            "/usr/bin/stat",
            "/usr/bin/sudo",
            'podman_bin_tools=(',
            "/usr/local/bin/podman",
            "/usr/local/bin/crun",
            "/usr/local/bin/runc",
            "/usr/local/bin/pasta",
            "/usr/local/bin/fuse-overlayfs",
            "for podman_library_parent in /usr/local/lib /usr/local/lib/podman; do",
            'podman_library_tools=(',
            "/usr/local/lib/podman/conmon",
            "/usr/local/lib/podman/rootlessport",
            "/usr/local/lib/podman/netavark",
            "/usr/local/lib/podman/catatonit",
            "/usr/local/lib/podman/aardvark-dns",
            "/usr/bin/sudo -n /usr/bin/chmod 0755 --",
            '"${podman_parent}" "${podman_bin_tools[@]}"',
            '"$(/usr/bin/stat -c \'%u:%g:%a\' "${podman_parent}")" != "0:0:755"',
            "a2f6b73cc0f7018e2e8518338a4ec27db70148e1af86e16719235605aefd1df3",
            "5884e882b252f4a8073fc22c66633993fb8e0adf79ecd1631b4d3e1f382f6f90",
            "eb61412faa7ea9ee395b21f3a70def43238de0d7e120ae5e93f4f9528af5f5f4",
            "4efb64a7a1125462cec5023c09384651654c15f294b3c59e0753e8e1536c068b",
            "54461fe89d55222cde826b917e96b92c450031446841eeab672c6c70fcdc9822",
            "36c2f2886f132e568636d018e491570c36364d9984f4df30a4616133f89c0119",
            "dcc03958b573a8ddc189f5cd87b78913df129384cba59cb03093f1ff03417c53",
            "b0fa7e4a1aacaed6dffe28131cff7d1d295f2d7653bc963d507f6a67009225d9",
            "2d80e408dd2d393673e8970f201165df96f84e0dd91976d64b9c1cc77fde6bf9",
            "75e90ba96e3fbe6c9ed9f994f821fc4e7af89273acb5022790b682674b6911df",
            "844e4d8900fd6856d3f8f03a81599d6add195b69015de6b040c2da3b99bb7b95",
            "/usr/bin/sha256sum --check --strict",
            'test "$(/usr/local/bin/podman --version)" = "podman version 5.8.4"',
            'runc_version="$(/usr/local/bin/runc --version)"',
            '"${runc_version%%$\'\\n\'*}" != "runc version 1.4.3"',
            'runc_help="$(/usr/local/bin/runc --help)"',
            '"${runc_help}" != *"--systemd-cgroup"*',
            'conmon_version="$(/usr/local/lib/podman/conmon --version)"',
            '"${conmon_version%%$\'\\n\'*}" != "conmon version 2.2.1"',
            'conmon_help="$(/usr/local/lib/podman/conmon --help)"',
            '"${conmon_help}" != *"--systemd-cgroup"*',
            'expected_native_runtime="/usr/local/bin/crun"',
            'if ! native_runtime_path="$(/usr/local/bin/podman info --format "{{.Host.OCIRuntime.Path}}")"',
            "native ARM64 Podman could not resolve its OCI runtime before checkout",
            '"${native_runtime_path}" != "${expected_native_runtime}"',
            "native ARM64 Podman resolved an unexpected OCI runtime path",
        ):
            self.assertIn(contract, script)
        structure_guard = script.index(
            'if [[ ! -d "${podman_parent}" || -L "${podman_parent}"'
        )
        tool_guard = script.index('for podman_tool in "${podman_bin_tools[@]}"; do')
        seal = script.index("/usr/bin/sudo -n /usr/bin/chmod 0755 --")
        attestation = script.index(
            '"$(/usr/bin/stat -c \'%u:%g:%a\' "${podman_parent}")" != "0:0:755"'
        )
        digest = script.index("/usr/bin/sha256sum --check --strict")
        version = script.index('/usr/local/bin/podman --version')
        runc_version = script.index('/usr/local/bin/runc --version')
        runc_help = script.index('/usr/local/bin/runc --help')
        conmon_version = script.index('/usr/local/lib/podman/conmon --version')
        conmon_help = script.index('/usr/local/lib/podman/conmon --help')
        runtime_probe = script.index('/usr/local/bin/podman info --format')
        self.assertLess(structure_guard, tool_guard)
        self.assertLess(tool_guard, seal)
        self.assertLess(seal, attestation)
        self.assertLess(attestation, digest)
        self.assertLess(digest, version)
        self.assertLess(version, runc_version)
        self.assertLess(runc_version, runc_help)
        self.assertLess(runc_help, conmon_version)
        self.assertLess(conmon_version, conmon_help)
        self.assertLess(conmon_help, runtime_probe)
        seal_step = self.workflow.index(f"      - name: {step_name}\n")
        checkout_step = self.workflow.index(
            "      - name: Checkout Exact ARM64 Candidate Commit\n"
        )
        context_step = self.workflow.index(
            "      - name: Validate Native ARM64 Shard Context\n"
        )
        self.assertLess(seal_step, checkout_step)
        self.assertLess(checkout_step, context_step)
        for forbidden in (
            "./scripts/",
            "git ",
            "curl ",
            "/usr/bin/curl --",
            "apt-get",
            "command -v",
            "chmod -R",
            "|| true",
        ):
            self.assertNotIn(forbidden, script)

    def test_arm64_crun_runtime_is_pinned_attested_and_ordered(self) -> None:
        step_name = "Install Exact Native ARM64 crun Runtime"
        step = workflow_step(self.workflow, step_name)
        self.assertIn(
            "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}", step
        )
        for contract in (
            "CRUN_COMMIT: 54f16ffbefcd022bf032af768b5c5ce075c18bfc",
            "CRUN_SHA256: cc1e8ec89aef1422e0741be196f9ed099e2e09d2f48f30f27cd44a22ef1f0342",
            "CRUN_SIZE_BYTES: '3298128'",
            "CRUN_SPEC_VERSION: 1.0.0",
            "CRUN_URL: https://github.com/containers/crun/releases/download/1.28/crun-1.28-linux-arm64",
            "CRUN_VERSION: '1.28'",
        ):
            self.assertIn(contract, step)
        workspace_script = workflow_step_script(
            self.workflow, "Create Native ARM64 Shard Workspace"
        )
        for contract in (
            'shard_root_inode="$(stat -c \'%d:%i\' "${shard_root}")"',
            '"$(stat -c \'%u:%g:%a:%d:%i\' "${shard_root}")" !=',
            '"$(id -u):$(id -g):700:${shard_root_inode}"',
            "printf 'ARM_SHARD_ROOT_INODE=%s\\n' \"${shard_root_inode}\"",
        ):
            self.assertIn(contract, workspace_script)
        script = workflow_step_script(self.workflow, step_name)
        for contract in (
            'runtime_directory="${SHARD_ROOT}/runtime"',
            'crun_download="${runtime_directory}/.crun-1.28-linux-arm64.download"',
            'crun_path="${runtime_directory}/crun-1.28-linux-arm64"',
            'runtime_directory_inode=""',
            'install_completed=false',
            'attest_install_shard_root() {',
            '"${user_id}:${user_group}:700:${ARM_SHARD_ROOT_INODE}"',
            'attest_install_runtime_directory() {',
            '"${user_id}:${user_group}:700:${runtime_directory_inode}"',
            'cleanup_failed_crun_install() {',
            'if [[ -L "${runtime_directory}" ]]; then',
            '/usr/bin/rm -f -- "${runtime_directory}"',
            'if [[ ! -e "${runtime_directory}" ]]; then',
            'cleanup_failed_crun_install_on_exit() {',
            'trap cleanup_failed_crun_install_on_exit EXIT',
            '-e "${runtime_directory}" || -L "${runtime_directory}"',
            '/usr/bin/install -d -m 0700 -- "${runtime_directory}"',
            'runtime_directory_inode="$(/usr/bin/stat -c \'%d:%i\' '
            '"${runtime_directory}")"',
            '/usr/bin/curl --disable --fail --location',
            "--proto '=https'",
            "--proto-redir '=https'",
            "--tlsv1.2",
            "--connect-timeout 10",
            "--max-time 120",
            "--max-redirs 5",
            "--retry 3",
            "--retry-all-errors",
            "--retry-delay 1",
            "--retry-max-time 120",
            '--max-filesize "${CRUN_SIZE_BYTES}"',
            "--remove-on-error",
            "--silent",
            "--show-error",
            '--output "${crun_download}"',
            '"${CRUN_URL}"',
            '[[ ! -f "${crun_download}" || -L "${crun_download}"',
            '"${user_id}:${user_group}:600:${CRUN_SIZE_BYTES}"',
            '/usr/bin/install -m 0700 -- "${crun_download}" "${crun_path}"',
            '/usr/bin/rm -f -- "${crun_download}"',
            '[[ -e "${crun_download}" || -L "${crun_download}"',
            '! -f "${crun_path}" || -L "${crun_path}"',
            '"${user_id}:${user_group}:700:${CRUN_SIZE_BYTES}"',
            'crun_inode="$(/usr/bin/stat -c \'%d:%i\' "${crun_path}")"',
            '"${crun_inode}" =~ ^[0-9]+:[0-9]+$',
            'crun_version_output="$("${crun_path}" --root '
            '"${runtime_directory}" --version)"',
            '"${crun_version_lines[0]:-}" != "crun version ${CRUN_VERSION}"',
            '"${crun_version_lines[1]:-}" != "commit: ${CRUN_COMMIT}"',
            '"${crun_version_lines[2]:-}" != "rundir: ${runtime_directory}"',
            '"${crun_version_lines[3]:-}" != "spec: ${CRUN_SPEC_VERSION}"',
            r'\+SYSTEMD($|[[:space:]])',
            "printf 'ARM_CRUN_PATH=%s\\n' \"${crun_path}\"",
            "printf 'ARM_CRUN_SHA256=%s\\n' \"${CRUN_SHA256}\"",
            "printf 'ARM_CRUN_INODE=%s\\n' \"${crun_inode}\"",
            "printf 'ARM_CRUN_DIRECTORY_INODE=%s\\n' "
            '"${runtime_directory_inode}"',
            '} >> "${GITHUB_ENV}"',
            'install_completed=true',
            'trap - EXIT',
        ):
            self.assertIn(contract, script)
        for forbidden in ("set +e", "|| true", "--insecure"):
            self.assertNotIn(forbidden, script)
        self.assertEqual(script.count("/usr/bin/curl --disable"), 1)
        self.assertEqual(script.count("/usr/bin/sha256sum --check --strict"), 2)
        cleanup_trap = script.index("trap cleanup_failed_crun_install_on_exit EXIT")
        runtime_create = script.index(
            '/usr/bin/install -d -m 0700 -- "${runtime_directory}"'
        )
        runtime_inode = script.index(
            'runtime_directory_inode="$(/usr/bin/stat -c \'%d:%i\''
        )
        target_guard = script.index('if [[ -e "${crun_download}"')
        download = script.index("/usr/bin/curl --disable")
        downloaded_identity = script.index(
            '[[ ! -f "${crun_download}" || -L "${crun_download}"'
        )
        source_digest = script.index("/usr/bin/sha256sum --check --strict")
        install = script.index('/usr/bin/install -m 0700 -- "${crun_download}"')
        installed_identity = script.index('! -f "${crun_path}" || -L "${crun_path}"')
        destination_digest = script.index(
            "/usr/bin/sha256sum --check --strict", source_digest + 1
        )
        version = script.index(
            '"${crun_path}" --root "${runtime_directory}" --version'
        )
        export = script.index("printf 'ARM_CRUN_PATH=%s\\n'")
        mark_complete = script.index("install_completed=true")
        disarm_trap = script.index("trap - EXIT", mark_complete)
        self.assertLess(cleanup_trap, runtime_create)
        self.assertLess(runtime_create, runtime_inode)
        self.assertLess(runtime_inode, target_guard)
        self.assertLess(target_guard, download)
        self.assertLess(download, downloaded_identity)
        self.assertLess(downloaded_identity, source_digest)
        self.assertLess(source_digest, install)
        self.assertLess(install, installed_identity)
        self.assertLess(installed_identity, destination_digest)
        self.assertLess(destination_digest, version)
        self.assertLess(version, export)
        self.assertLess(export, mark_complete)
        self.assertLess(mark_complete, disarm_trap)

        arm_job = workflow_job(self.workflow, "package-lifecycle-arm64")
        checkout = arm_job.index("Checkout Exact ARM64 Candidate Commit")
        workspace = arm_job.index("Create Native ARM64 Shard Workspace")
        install_step = arm_job.index(step_name)
        download_command = arm_job.index("/usr/bin/curl --disable")
        lifecycle = arm_job.index("Run Native ARM64 Package Lifecycle Shard")
        final_cleanup = arm_job.index("Remove Exact Native ARM64 crun Runtime")
        self.assertLess(checkout, workspace)
        self.assertLess(workspace, install_step)
        self.assertLess(install_step, download_command)
        self.assertLess(download_command, lifecycle)
        self.assertLess(lifecycle, final_cleanup)
        self.assertNotIn("/usr/local/bin/crun", script)

    def test_arm64_crun_final_cleanup_is_fail_closed_and_symlink_safe(self) -> None:
        step_name = "Remove Exact Native ARM64 crun Runtime"
        step = workflow_step(self.workflow, step_name)
        self.assertIn(
            "if: ${{ always() && steps.arm_workspace.outcome == 'success' }}",
            step,
        )
        self.assertIn(
            "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}", step
        )
        script = workflow_step_script(self.workflow, step_name)
        required = (
            'crun_directory="${SHARD_ROOT}/runtime"',
            'attest_final_arm_shard_root() {',
            '"${user_id}:${user_group}:700:${ARM_SHARD_ROOT_INODE}"',
            'attest_final_crun_directory() {',
            '"${user_id}:${user_group}:700:${ARM_CRUN_DIRECTORY_INODE}"',
            'cleanup_final_crun_runtime() {',
            'if [[ -L "${SHARD_ROOT}" ]]; then',
            'if [[ ! -e "${SHARD_ROOT}" ]]; then',
            'if [[ -L "${crun_directory}" ]]; then',
            '/usr/bin/rm -f -- "${crun_directory}"',
            'if [[ ! -e "${crun_directory}" ]]; then',
            'if ! attest_final_crun_directory; then',
            '/usr/bin/rm -f -- "${expected_crun_path}" "${crun_download}"',
            '/usr/bin/rmdir -- "${crun_directory}"',
            'if ! cleanup_final_crun_runtime; then',
            "final native ARM64 crun cleanup was not identity-safe",
            '[[ -e "${crun_directory}" || -L "${crun_directory}" ]]',
            "final native ARM64 crun cleanup did not attest exact absence",
        )
        expected_return_failures = script.count("return 1")
        expected_exit_failures = script.count("exit 1")

        def assert_fail_closed(candidate: str) -> None:
            for contract in required:
                self.assertIn(contract, candidate)
            for forbidden in ("set +e", "|| true", "--insecure"):
                self.assertNotIn(forbidden, candidate)
            self.assertEqual(candidate.count("return 1"), expected_return_failures)
            self.assertEqual(candidate.count("exit 1"), expected_exit_failures)

        self.assertGreaterEqual(expected_return_failures, 5)
        self.assertGreaterEqual(expected_exit_failures, 3)
        assert_fail_closed(script)
        mutations = (
            script.replace("return 1", "return 0", 1),
            script.replace(
                "if ! attest_final_crun_directory; then",
                "if attest_final_crun_directory; then",
                1,
            ),
            script.replace(
                '/usr/bin/rm -f -- "${crun_directory}"',
                '/usr/bin/rm -rf -- "${crun_directory}/"',
                1,
            ),
            script.replace("exit 1", "exit 0", 1),
            script + "\nset +e\n",
            script + "\ncleanup_final_crun_runtime || true\n",
            script + "\ncurl --insecure https://example.invalid\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]), self.assertRaises(
                AssertionError
            ):
                assert_fail_closed(mutation)

        def inode(path: Path) -> str:
            identity = path.stat()
            return f"{identity.st_dev}:{identity.st_ino}"

        def invoke(shard_root: Path, runtime_inode: str | None) -> subprocess.CompletedProcess[str]:
            environment = os.environ.copy()
            environment.update(
                {
                    "SHARD_ROOT": str(shard_root),
                    "ARM_SHARD_ROOT_INODE": inode(shard_root),
                }
            )
            if runtime_inode is None:
                environment.pop("ARM_CRUN_DIRECTORY_INODE", None)
            else:
                environment["ARM_CRUN_DIRECTORY_INODE"] = runtime_inode
            return subprocess.run(
                ["/usr/bin/bash", "-c", script],
                cwd=REPOSITORY,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "sentinel-exact"
            sentinel.write_text("preserve-exact\n", encoding="utf-8")
            shard_root = root / "shard-exact"
            shard_root.mkdir(mode=0o700)
            shard_root.chmod(0o700)
            runtime = shard_root / "runtime"
            runtime.mkdir(mode=0o700)
            runtime.chmod(0o700)
            crun = runtime / "crun-1.28-linux-arm64"
            crun.write_bytes(b"exact-runtime")
            crun.chmod(0o700)
            (runtime / ".crun-1.28-linux-arm64.download").symlink_to(sentinel)
            result = invoke(shard_root, inode(runtime))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(runtime.exists())
            self.assertFalse(runtime.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve-exact\n")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "sentinel-absent"
            sentinel.write_text("preserve-absent\n", encoding="utf-8")
            shard_root = root / "shard-absent"
            shard_root.mkdir(mode=0o700)
            shard_root.chmod(0o700)
            result = invoke(shard_root, None)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((shard_root / "runtime").exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve-absent\n")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside-runtime"
            outside.mkdir(mode=0o700)
            sentinel = outside / "sentinel-symlink"
            sentinel.write_text("preserve-symlink\n", encoding="utf-8")
            shard_root = root / "shard-symlink"
            shard_root.mkdir(mode=0o700)
            shard_root.chmod(0o700)
            runtime = shard_root / "runtime"
            runtime.symlink_to(outside, target_is_directory=True)
            result = invoke(shard_root, None)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(runtime.exists())
            self.assertFalse(runtime.is_symlink())
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "preserve-symlink\n"
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "sentinel-changed-inode"
            sentinel.write_text("preserve-changed\n", encoding="utf-8")
            shard_root = root / "shard-changed-inode"
            shard_root.mkdir(mode=0o700)
            shard_root.chmod(0o700)
            runtime = shard_root / "runtime"
            runtime.mkdir(mode=0o700)
            runtime.chmod(0o700)
            crun = runtime / "crun-1.28-linux-arm64"
            crun.write_bytes(b"must-remain")
            runtime_stat = runtime.stat()
            changed_inode = f"{runtime_stat.st_dev}:{runtime_stat.st_ino + 1}"
            result = invoke(shard_root, changed_inode)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(runtime.is_dir())
            self.assertEqual(crun.read_bytes(), b"must-remain")
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "preserve-changed\n"
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside_shard = root / "outside-shard"
            outside_shard.mkdir(mode=0o700)
            outside_shard.chmod(0o700)
            outside_runtime = outside_shard / "runtime"
            outside_runtime.mkdir(mode=0o700)
            sentinel = outside_runtime / "sentinel-parent-symlink"
            sentinel.write_text("preserve-parent-symlink\n", encoding="utf-8")
            shard_root = root / "shard-parent-symlink"
            shard_root.symlink_to(outside_shard, target_is_directory=True)
            result = invoke(shard_root, inode(outside_runtime))
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(shard_root.is_symlink())
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"),
                "preserve-parent-symlink\n",
            )

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

    def test_arm64_lab_uses_exact_transient_systemd_delegation(self) -> None:
        self.assert_arm64_delegated_owner_contract(self.workflow)
        script = workflow_step_script(
            self.workflow, "Run Native ARM64 Package Lifecycle Shard"
        )
        for contract in (
            'host_owner_identity="${user_id}:${user_group}"',
            '! "${host_owner_identity}" =~ ^[1-9][0-9]*:[0-9]+$',
            '"${user_name}" != "runner"',
            '"${HOME}" != "/home/runner"',
            '"$(stat -c \'%u\' "${HOME}")" != \\\n'
            '        "${user_id}"',
            '"${self_cgroup}" == /user.slice/*',
            'delegate_drop_in="${delegate_directory}/syswarden-release-qualification.conf"',
            'delegate_drop_in_owned=false',
            'original_user_service_active=false',
            'arm_cleanup_completed=false',
            'trap cleanup_arm_cgroup_session_on_exit EXIT',
            'if [[ "${delegate_drop_in_owned}" == "true" ]]; then',
            'delegate_drop_in_owned=true',
            "'Delegate=cpu io memory pids'",
            'sudo -n test -L "${delegate_directory}"',
            'sudo -n test -d "${delegate_directory}"',
            'sudo -n stat -c \'%u:%g:%a\' "${delegate_drop_in}"',
            'containers_conf="${SHARD_ROOT}/containers.conf"',
            'podman_info="${SHARD_ROOT}/podman-info.json"',
            'podman_local="${SHARD_ROOT}/podman-local"',
            'crun_directory="${SHARD_ROOT}/runtime"',
            'crun_download="${crun_directory}/.crun-1.28-linux-arm64.download"',
            'expected_crun_path="${crun_directory}/crun-1.28-linux-arm64"',
            '"${ARM_CRUN_PATH:-}" != "${expected_crun_path}"',
            '"${ARM_CRUN_SHA256:-}" != '
            '"cc1e8ec89aef1422e0741be196f9ed099e2e09d2f48f30f27cd44a22ef1f0342"',
            '! "${ARM_CRUN_INODE:-}" =~ ^[0-9]+:[0-9]+$',
            '! "${ARM_CRUN_DIRECTORY_INODE:-}" =~ ^[0-9]+:[0-9]+$',
            '! "${ARM_SHARD_ROOT_INODE:-}" =~ ^[0-9]+:[0-9]+$',
            'attest_arm_shard_root() {',
            '"${host_owner_identity}:700:${ARM_SHARD_ROOT_INODE}"',
            'attest_arm_crun_directory() {',
            '"${host_owner_identity}:700:${ARM_CRUN_DIRECTORY_INODE}"',
            'attest_arm_crun() {',
            '"$(stat -c \'%u:%g:%a:%s:%d:%i\' "${ARM_CRUN_PATH}")" !=',
            '"${host_owner_identity}:700:3298128:${ARM_CRUN_INODE}"',
            'printf \'%s  %s\\n\' "${ARM_CRUN_SHA256}" "${ARM_CRUN_PATH}"',
            'crun_version_output="$("${ARM_CRUN_PATH}"',
            '--root "${crun_directory}" --version)" || return 1',
            '"${crun_version_lines[0]:-}" != "crun version 1.28"',
            '"commit: 54f16ffbefcd022bf032af768b5c5ce075c18bfc"',
            '"${crun_version_lines[2]:-}" != "rundir: ${crun_directory}"',
            '"${crun_version_lines[3]:-}" != "spec: 1.0.0"',
            r'\+SYSTEMD($|[[:space:]])',
            'cleanup_arm_crun_runtime() {',
            'if [[ -L "${crun_directory}" ]]; then',
            '/usr/bin/rm -f -- "${crun_directory}"',
            'if [[ ! -e "${crun_directory}" ]]; then',
            'if ! attest_arm_crun_directory; then',
            'if ! cleanup_arm_crun_runtime; then',
            "native ARM64 crun parent identity changed before use",
            'if ! attest_arm_crun; then',
            "native ARM64 crun runtime changed before delegated use",
            "'cgroup_manager=\"systemd\"'",
            "'conmon_path=[\"/usr/local/lib/podman/conmon\"]'",
            "'remote=false'",
            "'runtime=\"crun\"'",
            "'[engine.runtimes]'",
            '"crun=[\\"${ARM_CRUN_PATH}\\"]"',
            "'[engine.platform_to_oci_runtime]'",
            "'\"linux/arm64\"=\"crun\"'",
            '"$(stat -c \'%u:%g:%a\' "${containers_conf}")" !=',
            '"${host_owner_identity}:600"',
            "'unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY'",
            "'exec /usr/local/bin/podman --remote=false \"$@\"'",
            'chmod 0700 "${podman_local}"',
            '"$(stat -c \'%u:%g:%a\' "${podman_local}")" !=',
            '"${host_owner_identity}:700"',
            "local-only Podman launcher is not a private runner-owned executable",
            ': > "${podman_info}"',
            'chmod 0600 "${podman_info}"',
            'podman_info_inode="$(stat -c \'%d:%i\' "${podman_info}")"',
            "native ARM64 Podman info target is not a private runner-owned file",
            'unit_name="syswarden-arm64-lifecycle-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            'sudo -n systemd-run',
            '--machine="${user_name}@"',
            '--property=\'Type=exec\'',
            "--property='Delegate=cpu io memory pids'",
            "--property='MemoryMax=1G'",
            "--property='TasksMax=512'",
            "--property='UMask=0077'",
            '--setenv="CONTAINERS_CONF=${containers_conf}"',
            "--setenv='CONTAINERS_CONF_OVERRIDE='",
            '--setenv="DBUS_SESSION_BUS_ADDRESS=unix:path=${runtime_dir}/bus"',
            "--setenv='PYTHONDONTWRITEBYTECODE=1'",
            '--setenv="SYSWARDEN_CRUN_DIRECTORY_INODE=${ARM_CRUN_DIRECTORY_INODE}"',
            '--setenv="SYSWARDEN_CRUN_INODE=${ARM_CRUN_INODE}"',
            '--setenv="SYSWARDEN_CRUN_PATH=${ARM_CRUN_PATH}"',
            '--setenv="SYSWARDEN_CRUN_SHA256=${ARM_CRUN_SHA256}"',
            '--setenv="SYSWARDEN_HOST_OWNER=${host_owner_identity}"',
            '--setenv="SYSWARDEN_HOST_UID=${user_id}"',
            '--setenv="SYSWARDEN_PODMAN_INFO=${podman_info}"',
            '--setenv="SYSWARDEN_PODMAN_INFO_INODE=${podman_info_inode}"',
            '--setenv="SYSWARDEN_PODMAN_LOCAL=${podman_local}"',
            "/usr/bin/bash --noprofile --norc -e -o pipefail -c",
            "unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY;",
            '-z "${CONTAINERS_CONF:-}" || -n "${CONTAINERS_CONF_OVERRIDE:-}"',
            "native ARM64 Podman configuration isolation is incomplete",
            '-z "${SYSWARDEN_PODMAN_LOCAL:-}"',
            "native ARM64 local-only Podman launcher is unavailable",
            '-z "${SYSWARDEN_PODMAN_INFO:-}"',
            '-z "${SYSWARDEN_PODMAN_INFO_INODE:-}"',
            "native ARM64 Podman info target is unavailable",
            '-z "${SYSWARDEN_CRUN_PATH:-}"',
            '"${SYSWARDEN_CRUN_SHA256:-}" != '
            '"cc1e8ec89aef1422e0741be196f9ed099e2e09d2f48f30f27cd44a22ef1f0342"',
            '! "${SYSWARDEN_CRUN_INODE:-}" =~ ^[0-9]+:[0-9]+$',
            '! "${SYSWARDEN_CRUN_DIRECTORY_INODE:-}" =~ ^[0-9]+:[0-9]+$',
            '-z "${SYSWARDEN_HOST_UID:-}"',
            '! "${SYSWARDEN_HOST_UID}" =~ ^[1-9][0-9]*$',
            '-z "${SYSWARDEN_HOST_OWNER:-}"',
            '! "${SYSWARDEN_HOST_OWNER}" =~ ^[1-9][0-9]*:[0-9]+$',
            '"${SYSWARDEN_HOST_OWNER%%:*}" != "${SYSWARDEN_HOST_UID}"',
            "native ARM64 delegated host owner identity is incomplete",
            'delegated_uid="$(id -u)"',
            '"${delegated_uid}" != "${SYSWARDEN_HOST_UID}"',
            "native ARM64 delegated UID differs from the exported host UID",
            "native ARM64 crun delegated identity is incomplete",
            'crun_parent="${SYSWARDEN_CRUN_PATH%/*}"',
            'if [[ ! -d "${crun_parent}" || -L "${crun_parent}" ]]',
            "native ARM64 crun parent is not a real delegated directory",
            'crun_parent_identity="$(stat -c "%u:%g:%a:%d:%i" '
            '"${crun_parent}")"',
            'expected_crun_parent_identity="${SYSWARDEN_HOST_OWNER}:700:'
            '${SYSWARDEN_CRUN_DIRECTORY_INODE}"',
            '"${crun_parent_identity}" != "${expected_crun_parent_identity}"',
            "native ARM64 crun parent identity changed inside the delegated session",
            'if [[ ! -f "${SYSWARDEN_CRUN_PATH}" || '
            '-L "${SYSWARDEN_CRUN_PATH}" || ! -x "${SYSWARDEN_CRUN_PATH}" ]]',
            "native ARM64 crun is not a real delegated executable",
            'crun_identity="$(stat -c "%u:%g:%a:%s:%d:%i" '
            '"${SYSWARDEN_CRUN_PATH}")"',
            'expected_crun_identity="${SYSWARDEN_HOST_OWNER}:700:3298128:'
            '${SYSWARDEN_CRUN_INODE}"',
            '"${crun_identity}" != "${expected_crun_identity}"',
            "native ARM64 crun identity changed inside the delegated session",
            'printf "%s  %s\\n" "${SYSWARDEN_CRUN_SHA256}" '
            '"${SYSWARDEN_CRUN_PATH}"',
            "native ARM64 crun changed bytes inside the delegated session",
            'crun_version_output="$("${SYSWARDEN_CRUN_PATH}" --root '
            '"${crun_parent}" --version)"',
            '"${crun_version_lines[2]:-}" != "rundir: ${crun_parent}"',
            "native ARM64 crun is not executable inside the delegated session",
            "native ARM64 crun lacks the exact delegated version or systemd capability",
            "if ! /usr/local/lib/podman/conmon --version >/dev/null",
            "native ARM64 conmon is not executable inside the delegated session",
            '"${SYSWARDEN_PODMAN_LOCAL}" --out "${SYSWARDEN_PODMAN_INFO}" '
            "info --format json",
            "native ARM64 Podman could not attest its isolated runtime configuration",
            'podman_info_identity="$(stat -c "%u:%g:%a:%d:%i" '
            '"${SYSWARDEN_PODMAN_INFO}")"',
            'expected_podman_info_identity="${SYSWARDEN_HOST_OWNER}:600:'
            '${SYSWARDEN_PODMAN_INFO_INODE}"',
            '"${podman_info_identity}" != "${expected_podman_info_identity}"',
            "native ARM64 Podman info evidence changed identity or permissions",
            '.host.conmon.path == "/usr/local/lib/podman/conmon"',
            '.host.ociRuntime.name == "crun"',
            '.host.ociRuntime.path == $crun_path',
            'startswith("crun version 1.28\\ncommit: '
            '54f16ffbefcd022bf032af768b5c5ce075c18bfc\\n")',
            'contains("\\nspec: 1.0.0\\n")',
            'contains("\\n+SYSTEMD ")',
            '.host.cgroupManager == "systemd"',
            ".host.security.rootless == true",
            ".host.serviceIsRemote == false",
            '.host.arch == "arm64"',
            '.host.os == "linux"',
            "native ARM64 Podman resolved an unexpected local runtime configuration",
            'exec "$@"',
            "syswarden-arm64-lifecycle",
            '/usr/bin/python3 "${GITHUB_WORKSPACE}/scripts/ci/package_lifecycle_lab.py"',
            '--podman "${podman_local}"',
            'sudo -n rm -f -- "${delegate_drop_in}"',
            'sudo -n test -e "${delegate_drop_in}"',
            'shard_rc=0',
            'if sudo -n systemd-run',
            'else\n  shard_rc=$?',
            '"${crun_download}"',
            '-e "${expected_crun_path}" || -L "${expected_crun_path}"',
            '/usr/bin/rmdir -- "${crun_directory}"',
            '[[ -e "${crun_directory}" || -L "${crun_directory}" ]]',
            'sudo -n systemctl start "${user_service}"',
            'cleanup_rc=0',
            'arm_cleanup_completed=true',
            'trap - EXIT',
            'ARM64 delegated session cleanup or restoration failed.',
            'report="${ARM_EVIDENCE_DIR}/package-lifecycle-arm64.json"',
            'if [[ ! -e "${report}" && ! -L "${report}" ]]',
            "native ARM64 lifecycle command exited before producing its canonical report",
            "schema_version: 4",
            'unexpected_failed_checks: ["harness:" + $error]',
            'chmod 0600 "${report}"',
        ):
            self.assertIn(contract, script)
        for forbidden in (
            "apt-get",
            "cgroup_manager=\"cgroupfs\"",
            "runtime=\"/usr/local/bin/runc\"",
            "runtime=\"runc\"",
            "/usr/local/bin/runc",
            "/usr/local/bin/crun",
            "OCIRuntime.Name",
            "podman_runtime=",
            "{{.Host.Conmon.Path}}",
            'CONTAINERS_CONF_OVERRIDE=${containers_conf}',
            "containers_override",
            "loginctl enable-linger",
            "--privileged",
            "podman system reset",
            "podman system migrate",
            "--setenv='CONTAINER_HOST='",
            "--setenv='CONTAINER_CONNECTION='",
            "set +e",
            "|| true",
            "--insecure",
        ):
            self.assertNotIn(forbidden, script)
        self.assertEqual(script.count("sudo -n systemd-run"), 1)
        self.assertEqual(script.count("--property='MemoryMax=1G'"), 1)
        self.assertEqual(script.count("--property='TasksMax=512'"), 1)
        self.assertEqual(script.count("scripts/ci/package_lifecycle_lab.py"), 1)
        self.assertEqual(script.count("'conmon_path=[\"/usr/local/lib/podman/conmon\"]'"), 1)
        self.assertEqual(script.count("'remote=false'"), 1)
        self.assertEqual(script.count("'runtime=\"crun\"'"), 1)
        self.assertEqual(script.count("'[engine.runtimes]'"), 1)
        self.assertEqual(script.count('"crun=[\\"${ARM_CRUN_PATH}\\"]"'), 1)
        self.assertEqual(script.count("'[engine.platform_to_oci_runtime]'"), 1)
        self.assertEqual(
            script.count("'\"linux/arm64\"=\"crun\"'"), 1
        )
        self.assertEqual(
            script.count("'exec /usr/local/bin/podman --remote=false \"$@\"'"), 1
        )
        self.assertEqual(
            script.count(
                '"${SYSWARDEN_PODMAN_LOCAL}" --out '
                '"${SYSWARDEN_PODMAN_INFO}" info --format json'
            ),
            1,
        )
        self.assertEqual(script.count(".host.serviceIsRemote == false"), 1)
        self.assertEqual(script.count(".host.security.rootless == true"), 1)
        self.assertEqual(
            script.count('--setenv="CONTAINERS_CONF=${containers_conf}"'), 1
        )
        self.assertEqual(
            script.count("--setenv='CONTAINERS_CONF_OVERRIDE='"), 1
        )
        self.assertEqual(
            script.count(
                '--setenv="SYSWARDEN_CRUN_DIRECTORY_INODE=${ARM_CRUN_DIRECTORY_INODE}"'
            ),
            1,
        )
        self.assertEqual(
            script.count('--setenv="SYSWARDEN_CRUN_INODE=${ARM_CRUN_INODE}"'), 1
        )
        self.assertEqual(
            script.count('--setenv="SYSWARDEN_CRUN_PATH=${ARM_CRUN_PATH}"'), 1
        )
        self.assertEqual(
            script.count('--setenv="SYSWARDEN_CRUN_SHA256=${ARM_CRUN_SHA256}"'), 1
        )
        self.assertEqual(script.count("if ! attest_arm_crun; then"), 1)
        cleanup_start = script.index("cleanup_arm_cgroup_session() {")
        cleanup_end = script.index("cleanup_arm_cgroup_session_on_exit() {")
        cleanup_script = script[cleanup_start:cleanup_end]
        self.assertIn('/usr/bin/rm -f --', cleanup_script)
        self.assertIn('if ! cleanup_arm_crun_runtime; then', cleanup_script)
        self.assertNotIn('"${ARM_CRUN_PATH}"', cleanup_script)
        runtime_cleanup_start = script.index("cleanup_arm_crun_runtime() {")
        runtime_cleanup_end = script.index("cleanup_arm_cgroup_session() {")
        runtime_cleanup = script[runtime_cleanup_start:runtime_cleanup_end]
        self.assertIn('"${expected_crun_path}"', runtime_cleanup)
        self.assertIn('"${crun_download}"', runtime_cleanup)
        self.assertIn('/usr/bin/rm -f -- "${crun_directory}"', runtime_cleanup)
        self.assertIn('/usr/bin/rmdir -- "${crun_directory}"', runtime_cleanup)
        self.assertNotIn('"${ARM_CRUN_PATH}"', runtime_cleanup)
        cleanup_trap = script.index("trap cleanup_arm_cgroup_session_on_exit EXIT")
        exported_identity_guard = script.index(
            'if [[ "${ARM_CRUN_PATH:-}" != "${expected_crun_path}"'
        )
        self.assertLess(cleanup_trap, exported_identity_guard)
        self.assertNotIn("--podman /usr/bin/podman", self.workflow)
        self.assertNotIn("--podman /usr/local/bin/podman", script)
        ownership_guard = script.index(
            'if sudo -n test -e "${delegate_drop_in}"'
        )
        create_drop_in = script.index(
            'sudo -n tee "${delegate_drop_in}" >/dev/null'
        )
        mark_owned = script.index("delegate_drop_in_owned=true")
        conmon_pin = script.index("'conmon_path=[\"/usr/local/lib/podman/conmon\"]'")
        remote_pin = script.index("'remote=false'")
        runtime_pin = script.index("'runtime=\"crun\"'")
        runtime_table = script.index("'[engine.runtimes]'")
        runtime_path = script.index('"crun=[\\"${ARM_CRUN_PATH}\\"]"')
        platform_table = script.index("'[engine.platform_to_oci_runtime]'")
        platform_pin = script.index("'\"linux/arm64\"=\"crun\"'")
        wrapper_unset = script.index(
            "'unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY'"
        )
        wrapper_exec = script.index(
            "'exec /usr/local/bin/podman --remote=false \"$@\"'"
        )
        systemd_run = script.index("sudo -n systemd-run")
        systemd_command = script.index(
            "/usr/bin/bash --noprofile --norc -e -o pipefail -c",
            systemd_run,
        )
        transient_properties = re.findall(
            r"--property='([^']+)'", script[systemd_run:systemd_command]
        )
        self.assertEqual(
            transient_properties,
            [
                "Type=exec",
                "Delegate=cpu io memory pids",
                "MemoryMax=1G",
                "TasksMax=512",
                "UMask=0077",
            ],
        )
        configuration_guard = script.index(
            "native ARM64 Podman configuration isolation is incomplete"
        )
        info_target = script.index(': > "${podman_info}"')
        host_crun_attestation = script.index("if ! attest_arm_crun; then")
        delegated_crun_parent_identity = script.index(
            "native ARM64 crun parent identity changed inside the delegated session",
            systemd_run,
        )
        delegated_crun_identity = script.index(
            "native ARM64 crun identity changed inside the delegated session",
            systemd_run,
        )
        delegated_crun_digest = script.index(
            "native ARM64 crun changed bytes inside the delegated session",
            systemd_run,
        )
        crun_probe = script.index(
            'crun_version_output="$("${SYSWARDEN_CRUN_PATH}" --root '
            '"${crun_parent}" --version)"',
            systemd_run,
        )
        crun_version_verdict = script.index(
            "native ARM64 crun lacks the exact delegated version or systemd capability",
            systemd_run,
        )
        conmon_probe = script.index(
            "/usr/local/lib/podman/conmon --version", systemd_run
        )
        podman_probe = script.index(
            '"${SYSWARDEN_PODMAN_LOCAL}" --out "${SYSWARDEN_PODMAN_INFO}" '
            "info --format json"
        )
        podman_verdict = script.index(".host.serviceIsRemote == false")
        lifecycle_lab = script.index("scripts/ci/package_lifecycle_lab.py")
        self.assertLess(ownership_guard, mark_owned)
        self.assertLess(mark_owned, create_drop_in)
        self.assertLess(create_drop_in, conmon_pin)
        self.assertLess(conmon_pin, remote_pin)
        self.assertLess(remote_pin, runtime_pin)
        self.assertLess(runtime_pin, runtime_table)
        self.assertLess(runtime_table, runtime_path)
        self.assertLess(runtime_path, platform_table)
        self.assertLess(runtime_pin, platform_table)
        self.assertLess(platform_table, platform_pin)
        self.assertLess(platform_pin, wrapper_unset)
        self.assertLess(wrapper_unset, wrapper_exec)
        self.assertLess(wrapper_exec, info_target)
        self.assertLess(info_target, host_crun_attestation)
        self.assertLess(host_crun_attestation, systemd_run)
        self.assertLess(platform_pin, systemd_run)
        self.assertLess(systemd_run, configuration_guard)
        self.assertLess(configuration_guard, delegated_crun_parent_identity)
        self.assertLess(delegated_crun_parent_identity, delegated_crun_identity)
        self.assertLess(configuration_guard, delegated_crun_identity)
        self.assertLess(delegated_crun_identity, delegated_crun_digest)
        self.assertLess(delegated_crun_digest, crun_probe)
        self.assertLess(crun_probe, crun_version_verdict)
        self.assertLess(crun_version_verdict, conmon_probe)
        self.assertLess(crun_probe, conmon_probe)
        self.assertLess(conmon_probe, podman_probe)
        self.assertLess(podman_probe, podman_verdict)
        self.assertLess(podman_verdict, lifecycle_lab)
        self.assertLess(podman_probe, lifecycle_lab)

    def test_arm64_delegated_owner_contract_rejects_identity_mutations(self) -> None:
        def replace_exact(source: str, old: str, new: str) -> str:
            self.assertEqual(source.count(old), 1, old)
            return source.replace(old, new, 1)

        host_owner = 'host_owner_identity="${user_id}:${user_group}"'
        home_owner = (
            '"$(stat -c \'%u\' "${HOME}")" != \\\n'
            '                  "${user_id}"'
        )
        owner_export = '--setenv="SYSWARDEN_HOST_OWNER=${host_owner_identity}"'
        uid_export = '--setenv="SYSWARDEN_HOST_UID=${user_id}"'
        delegated_uid = 'delegated_uid="$(id -u)"'
        parent_identity = (
            'expected_crun_parent_identity="${SYSWARDEN_HOST_OWNER}:700:'
            '${SYSWARDEN_CRUN_DIRECTORY_INODE}"'
        )
        crun_identity = (
            'expected_crun_identity="${SYSWARDEN_HOST_OWNER}:700:3298128:'
            '${SYSWARDEN_CRUN_INODE}"'
        )
        podman_identity = (
            'expected_podman_info_identity="${SYSWARDEN_HOST_OWNER}:600:'
            '${SYSWARDEN_PODMAN_INFO_INODE}"'
        )
        mutations = (
            replace_exact(
                self.workflow,
                host_owner,
                'host_owner_identity="${user_id}:$(id -g "${user_name}")"',
            ),
            replace_exact(
                self.workflow,
                home_owner,
                '"$(stat -c \'%u:%g\' "${HOME}")" != '
                '"${host_owner_identity}"',
            ),
            replace_exact(self.workflow, owner_export, "# owner export removed"),
            replace_exact(self.workflow, uid_export, "# UID export removed"),
            replace_exact(self.workflow, delegated_uid, 'delegated_uid="$(id -g)"'),
            replace_exact(
                self.workflow,
                parent_identity,
                'expected_crun_parent_identity="$(id -u):$(id -g):700:'
                '${SYSWARDEN_CRUN_DIRECTORY_INODE}"',
            ),
            replace_exact(
                self.workflow,
                crun_identity,
                'expected_crun_identity="$(id -u):$(id -g):700:3298128:'
                '${SYSWARDEN_CRUN_INODE}"',
            ),
            replace_exact(
                self.workflow,
                '"$(stat -c "%u:%g:%a" "${CONTAINERS_CONF}")" != '
                '"${SYSWARDEN_HOST_OWNER}:600"',
                '"$(stat -c "%u:%g:%a" "${CONTAINERS_CONF}")" != '
                '"$(id -u):$(id -g):600"',
            ),
            replace_exact(
                self.workflow,
                podman_identity,
                'expected_podman_info_identity="$(id -u):$(id -g):600:'
                '${SYSWARDEN_PODMAN_INFO_INODE}"',
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-160:]), self.assertRaises(
                AssertionError
            ):
                self.assert_arm64_delegated_owner_contract(mutation)

        first = "native ARM64 delegated UID differs from the exported host UID"
        second = "native ARM64 Podman configuration isolation is incomplete"
        placeholder = "ARM64_ORDER_MUTATION_PLACEHOLDER"
        reordered = self.workflow.replace(first, placeholder, 1)
        reordered = reordered.replace(second, first, 1).replace(placeholder, second, 1)
        with self.assertRaises(AssertionError):
            self.assert_arm64_delegated_owner_contract(reordered)

    def test_arm64_delegated_owner_uses_host_gid_not_delegated_primary_gid(
        self,
    ) -> None:
        if os.getuid() == 0:
            self.skipTest("delegated non-root identity behavior requires a non-root test user")
        script = workflow_step_script(
            self.workflow, "Run Native ARM64 Package Lifecycle Shard"
        )
        command_line = next(
            line.strip()
            for line in script.splitlines()
            if line.strip().startswith(
                "'unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY;"
            )
        )
        identity_prefix, separator, _ = command_line.partition(
            'if ! printf "%s  %s\\n" "${SYSWARDEN_CRUN_SHA256}"'
        )
        self.assertTrue(separator)
        self.assertTrue(identity_prefix.startswith("'"))
        identity_prefix = identity_prefix[1:] + "exit 0"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            runtime.chmod(0o700)
            crun = runtime / "crun-1.28-linux-arm64"
            crun.touch(mode=0o700)
            os.truncate(crun, 3_298_128)
            crun.chmod(0o700)
            containers_conf = root / "containers.conf"
            containers_conf.write_text("[engine]\n", encoding="utf-8")
            containers_conf.chmod(0o600)
            podman_local = root / "podman-local"
            podman_local.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            podman_local.chmod(0o700)
            podman_info = root / "podman-info.json"
            podman_info.touch(mode=0o600)
            podman_info.chmod(0o600)

            binary_directory = root / "bin"
            binary_directory.mkdir(mode=0o700)
            delegated_id = binary_directory / "id"
            delegated_id.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = \"-u\" ]; then\n"
                "  printf '%s\\n' \"${FAKE_DELEGATED_UID:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"${1:-}\" = \"-g\" ]; then\n"
                "  echo 'delegated id -g must not be queried' >&2\n"
                "  exit 97\n"
                "fi\n"
                "exec /usr/bin/id \"$@\"\n",
                encoding="utf-8",
            )
            delegated_id.chmod(0o700)

            def inode(path: Path) -> str:
                identity = path.stat()
                return f"{identity.st_dev}:{identity.st_ino}"

            user_id = os.getuid()
            user_group = os.getgid()
            environment = os.environ.copy()
            environment.update(
                {
                    "CONTAINERS_CONF": str(containers_conf),
                    "CONTAINERS_CONF_OVERRIDE": "",
                    "FAKE_DELEGATED_UID": str(user_id),
                    "PATH": f"{binary_directory}{os.pathsep}{environment['PATH']}",
                    "SYSWARDEN_CRUN_DIRECTORY_INODE": inode(runtime),
                    "SYSWARDEN_CRUN_INODE": inode(crun),
                    "SYSWARDEN_CRUN_PATH": str(crun),
                    "SYSWARDEN_CRUN_SHA256": (
                        "cc1e8ec89aef1422e0741be196f9ed099e2e09d2f48f30f27cd44a22ef1f0342"
                    ),
                    "SYSWARDEN_HOST_OWNER": f"{user_id}:{user_group}",
                    "SYSWARDEN_HOST_UID": str(user_id),
                    "SYSWARDEN_PODMAN_INFO": str(podman_info),
                    "SYSWARDEN_PODMAN_INFO_INODE": inode(podman_info),
                    "SYSWARDEN_PODMAN_LOCAL": str(podman_local),
                }
            )
            accepted = subprocess.run(
                ["/bin/bash", "-e", "-o", "pipefail", "-c", identity_prefix],
                cwd=REPOSITORY,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertNotIn("delegated id -g must not be queried", accepted.stderr)

            environment["FAKE_DELEGATED_UID"] = str(user_id + 1)
            rejected = subprocess.run(
                ["/bin/bash", "-e", "-o", "pipefail", "-c", identity_prefix],
                cwd=REPOSITORY,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "delegated UID differs from the exported host UID", rejected.stderr
            )

    def test_premerge_package_workflow_runs_every_qualification_validator(self) -> None:
        step = workflow_step(
            self.package_workflow, "Test Package and Release Validators"
        )
        for test_file in (
            "scripts/ci/package_lifecycle_lab_test.py",
            "scripts/ci/release_qualification_adapter_test.py",
            "scripts/ci/release_qualification_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
        ):
            self.assertEqual(step.count(test_file), 1, test_file)

    def test_native_active_runtime_lanes_are_isolated_and_have_no_fallback(self) -> None:
        self.assertIn('"runtime_mode": "active-real-init"', self.package_lab)
        self.assertIn('"--network=none"', self.package_lab)
        self.assertIn('"--pid=private"', self.package_lab)
        self.assertIn('"--cgroupns=private"', self.package_lab)
        self.assertIn('"--ipc=private"', self.package_lab)
        self.assertIn('"--uts=private"', self.package_lab)
        self.assertIn('"--security-opt=no-new-privileges"', self.package_lab)
        self.assertIn('"cgroups_version": "v2"', self.package_lab)
        self.assertIn('"cgroup_manager": "systemd"', self.package_lab)
        self.assertIn('"cgroup_delegation": "rootless-systemd-v2"', self.package_lab)
        self.assertIn('"service_is_remote": False', self.package_lab)
        self.assertIn('"CAP_NET_ADMIN", "CAP_SYS_BOOT"', self.package_lab)
        self.assertIn('"--cap-add=SYS_ADMIN"', self.package_lab)
        self.assertIn('"--cap-add=SYS_PTRACE"', self.package_lab)
        self.assertIn('"--bounding-set=-sys_admin"', self.package_lab)
        self.assertIn('"--inh-caps=-sys_admin"', self.package_lab)
        self.assertIn('"--ambient-caps=-sys_admin"', self.package_lab)
        self.assertIn('"--no-new-privs"', self.package_lab)
        self.assertIn("SYS_ADMIN_CAPABILITY_BIT = 21", self.package_lab)
        self.assertIn("SYS_PTRACE_CAPABILITY_BIT = 19", self.package_lab)
        self.assertIn(
            '{"CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"}',
            self.package_lab,
        )
        self.assertIn('"dbus-org.freedesktop.oom1.service"', self.package_lab)
        self.assertIn('"dbus-org.freedesktop.resolve1.service"', self.package_lab)
        self.assertIn('ALPINE_OPENRC_VERSION = "0.62.6-r0"', self.package_lab)
        self.assertIn('rc_cgroup_mode=\\"legacy\\"', self.package_lab)
        self.assertIn("rc-update add rsyslog default &&", self.package_lab)
        self.assertIn('"rc-update -u\\n"', self.package_lab)
        self.assertIn("cap_drop=()", self.package_lab)
        self.assertIn('"pid1_uid_map"', self.package_lab)
        self.assertIn('"pid1_gid_map"', self.package_lab)
        self.assertIn('host.get("idMappings")', self.package_lab)
        self.assertIn('"effective_uid": effective_uid', self.package_lab)
        self.assertIn('"effective_gid": effective_gid', self.package_lab)
        self.assertIn('"lifecycle_exec_security"', self.package_lab)
        self.assertIn('"core_process_security"', self.package_lab)
        for forbidden in (
            '"--privileged"',
            '"--network=host"',
            '"--pid=host"',
            '"--ipc=host"',
            '"--uts=host"',
            "/run/podman/podman.sock",
            "/var/run/docker.sock",
            '"--device"',
        ):
            self.assertNotIn(forbidden, self.package_lab)
        x64_job = workflow_job(self.workflow, "qualify-release")
        self.assertNotRegex(x64_job, r"(?m)^\s*sudo(?:\s|$)")
        arm_job = workflow_job(self.workflow, "package-lifecycle-arm64")
        delegated_step = workflow_step(
            self.workflow, "Run Native ARM64 Package Lifecycle Shard"
        )
        self.assertIn(delegated_step, arm_job)
        self.assertNotRegex(
            arm_job.replace(delegated_step, ""), r"(?m)^\s*sudo(?:\s|$)"
        )

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

    def test_arm64_failure_evidence_uploads_before_shard_verdict(self) -> None:
        arm = workflow_job(self.workflow, "package-lifecycle-arm64")
        upload = arm.index("Upload Native ARM64 Package Lifecycle Shard")
        verdict = arm.index("Enforce Native ARM64 Package Lifecycle Verdict")
        self.assertLess(upload, verdict)
        verdict_script = workflow_step_script(
            self.workflow, "Enforce Native ARM64 Package Lifecycle Verdict"
        )
        for contract in (
            'shard_rc="$(cat "${status}")"',
            '"${shard_rc}" != "0"',
            '.status == "pass"',
            ".harness_complete == true",
            ".release_ready == true",
            '(.blocker_ids | type == "array" and length == 0)',
            '(.unexpected_failed_checks | type == "array" and length == 0)',
            '(has("error") | not)',
        ):
            self.assertIn(contract, verdict_script)

        valid_report: dict[str, object] = {
            "status": "pass",
            "harness_complete": True,
            "release_ready": True,
            "blocker_ids": [],
            "unexpected_failed_checks": [],
        }
        accepted = run_arm_verdict(verdict_script, valid_report)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        rejected_reports = (
            {**valid_report, "status": "fail"},
            {**valid_report, "harness_complete": False},
            {**valid_report, "release_ready": False},
            {**valid_report, "blocker_ids": ["arm64:blocker"]},
            {
                **valid_report,
                "unexpected_failed_checks": ["arm64:unexpected"],
            },
            {**valid_report, "error": "harness failed"},
        )
        for report in rejected_reports:
            with self.subTest(report=report):
                rejected = run_arm_verdict(verdict_script, report)
                self.assertNotEqual(rejected.returncode, 0)
        rejected_rc = run_arm_verdict(verdict_script, valid_report, "1\n")
        self.assertNotEqual(rejected_rc.returncode, 0)

    def test_arm64_missing_report_recovery_and_seal_failure_evidence(self) -> None:
        lifecycle_script = workflow_step_script(
            self.workflow, "Run Native ARM64 Package Lifecycle Shard"
        )
        recovery_marker = 'report="${ARM_EVIDENCE_DIR}/package-lifecycle-arm64.json"'
        self.assertEqual(lifecycle_script.count(recovery_marker), 1)
        recovery_script = (
            "set -euo pipefail\nshard_rc=1\n"
            + recovery_marker
            + lifecycle_script.split(recovery_marker, 1)[1]
        )
        with tempfile.TemporaryDirectory() as temporary:
            process_environment = os.environ.copy()
            process_environment["ARM_EVIDENCE_DIR"] = temporary
            recovered = subprocess.run(
                ["/bin/bash", "-c", recovery_script],
                cwd=REPOSITORY,
                env=process_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            recovered_report_path = Path(temporary) / "package-lifecycle-arm64.json"
            recovered_report = json.loads(
                recovered_report_path.read_text(encoding="utf-8")
            )
            self.assertEqual(recovered_report["schema_version"], 4)
            self.assertEqual(recovered_report["status"], "fail")
            self.assertFalse(recovered_report["harness_complete"])
            self.assertFalse(recovered_report["release_ready"])
            self.assertIn("rc=1", recovered_report["error"])
            self.assertEqual(recovered_report_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (Path(temporary) / "package-lifecycle-arm64.rc").read_text(
                    encoding="utf-8"
                ),
                "1\n",
            )

        seal_script = workflow_step_script(
            self.workflow, "Seal Native ARM64 Package Lifecycle Shard"
        )
        valid_report: dict[str, object] = {
            "status": "pass",
            "harness_complete": True,
            "release_ready": True,
            "blocker_ids": [],
            "unexpected_failed_checks": [],
        }
        accepted, github_output = run_arm_seal(seal_script, valid_report)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("artifact_name=syswarden-package-lifecycle-arm64-", github_output)
        self.assertRegex(github_output, r"(?m)^report_sha256=[0-9a-f]{64}$")

        missing, _ = run_arm_seal(seal_script, None)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("lifecycle evidence file is absent or invalid", missing.stderr)

        failure_evidence, github_output = run_arm_seal(
            seal_script, valid_report, "1\n"
        )
        self.assertEqual(failure_evidence.returncode, 0, failure_evidence.stderr)
        self.assertRegex(github_output, r"(?m)^report_sha256=[0-9a-f]{64}$")

    def test_unsigned_inventory_diff_uses_supported_gnu_invocation(self) -> None:
        inventory = workflow_step_script(
            self.workflow, "Seal Exact Unsigned Qualification Evidence Inventory"
        )
        self.assertIn("diff -u", inventory)
        self.assertNotIn("diff --no-index", inventory)
        self.assertIn("exit 1", inventory)

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
