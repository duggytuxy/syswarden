#!/usr/bin/env python3
"""Static safety contract for protected native package signing."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/native-package-signing.yml"
POLICY = ROOT / "scripts/ci/native_package_signature_policy_v4100.json"


def literal_run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*\|\s*$", line)
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
        blocks.append("\n".join(body))
    return blocks


def named_literal_run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    marker = f"      - name: {step_name}"
    try:
        index = lines.index(marker) + 1
    except ValueError as exc:
        raise AssertionError(f"workflow step not found: {step_name}") from exc
    while index < len(lines) and not re.match(r"^        run:\s*\|\s*$", lines[index]):
        if lines[index].startswith("      - name:"):
            raise AssertionError(f"workflow step has no literal run block: {step_name}")
        index += 1
    if index == len(lines):
        raise AssertionError(f"workflow step has no literal run block: {step_name}")
    indentation = len(lines[index]) - len(lines[index].lstrip())
    body: list[str] = []
    index += 1
    while index < len(lines):
        candidate = lines[index]
        if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
            break
        body.append(candidate)
        index += 1
    return textwrap.dedent("\n".join(body))


class NativePackageSigningWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.run_blocks = literal_run_blocks(cls.workflow)

    def test_trigger_is_manual_only_and_environment_is_protected(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^on:\n  workflow_dispatch:\n")
        for forbidden in (
            "push:",
            "pull_request:",
            "pull_request_target:",
            "release:",
            "schedule:",
            "repository_dispatch:",
            "workflow_run:",
        ):
            self.assertNotIn(forbidden, self.workflow)
        self.assertIn(
            "environment: syswarden-native-package-signing-v4100", self.workflow
        )
        self.assertIn("SIGN-NATIVE-PACKAGES-NO-PUBLISH", self.workflow)
        self.assertIn('"${RUN_ATTEMPT}" != "1"', self.workflow)
        self.assertIn('"${EVENT_ACTOR}" != "${REPOSITORY_OWNER}"', self.workflow)
        self.assertIn(
            "git rev-parse --verify 'origin/main^{commit}'", self.workflow
        )
        for deterministic_environment in ("LANG: C", "LC_ALL: C", "TZ: UTC"):
            self.assertIn(deterministic_environment, self.workflow)

    def test_exact_environment_contract_is_attested_before_checkout_or_secrets(self) -> None:
        gate_name = "Validate Exact Native Signing Environment Protection"
        gate = self.workflow.index(f"      - name: {gate_name}")
        first_step = self.workflow.index("      - name:", self.workflow.index("    steps:"))
        checkout = self.workflow.index("      - name: Checkout Exact Candidate Source")
        first_secret = self.workflow.index("${{ secrets.")
        self.assertEqual(gate, first_step)
        self.assertLess(gate, checkout)
        self.assertLess(gate, first_secret)
        for contract in (
            'environment_name="syswarden-native-package-signing-v4100"',
            'reviewer_rule_count="$(jq',
            'reviewer_entry_count="$(jq',
            'owner_reviewer_count="$(jq',
            'prevent_self_review="$(jq',
            '"${reviewer_rule_count}" != "1"',
            '"${reviewer_entry_count}" != "1"',
            '"${owner_reviewer_count}" != "1"',
            '"${prevent_self_review}" != "false"',
            '$(required_boolean protected_branches)" != "false"',
            '$(required_boolean custom_branch_policies)" != "true"',
            '$(top_level_boolean can_admins_bypass)" != "false"',
            "deployment-branch-policies",
            '.name == "main" and .type == "branch"',
        ):
            self.assertIn(contract, self.workflow)

    def test_environment_gate_accepts_only_the_exact_reviewed_contract(self) -> None:
        gate = named_literal_run_block(
            self.workflow, "Validate Exact Native Signing Environment Protection"
        )
        valid_environment = {
            "name": "syswarden-native-package-signing-v4100",
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {"login": "duggytuxy"},
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
        valid_policies = {
            "total_count": 1,
            "branch_policies": [{"name": "main", "type": "branch"}],
        }

        def run_gate(
            environment: dict[str, Any], policies: dict[str, Any]
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                environment_path = root / "environment.json"
                policies_path = root / "policies.json"
                environment_path.write_text(json.dumps(environment), encoding="utf-8")
                policies_path.write_text(json.dumps(policies), encoding="utf-8")
                gh = root / "gh"
                gh.write_text(
                    """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

environment_endpoint = (
    "repos/duggytuxy/syswarden/environments/"
    "syswarden-native-package-signing-v4100"
)
policy_endpoint = environment_endpoint + "/deployment-branch-policies"
endpoints = [argument for argument in sys.argv[1:] if argument.startswith("repos/")]
if endpoints == [environment_endpoint]:
    document = json.loads(Path(os.environ["TEST_ENVIRONMENT_JSON"]).read_text())
elif endpoints == [policy_endpoint] and "--paginate" in sys.argv and "--slurp" in sys.argv:
    document = [json.loads(Path(os.environ["TEST_POLICIES_JSON"]).read_text())]
else:
    raise SystemExit("unexpected gh api request: " + repr(sys.argv[1:]))
print(json.dumps(document, separators=(",", ":")))
""",
                    encoding="utf-8",
                )
                gh.chmod(0o700)
                environment_variables = os.environ.copy()
                environment_variables.update(
                    {
                        "GH_TOKEN": "test-token",
                        "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                        "PATH": f"{root}:{environment_variables['PATH']}",
                        "REPOSITORY_OWNER": "duggytuxy",
                        "TEST_ENVIRONMENT_JSON": str(environment_path),
                        "TEST_POLICIES_JSON": str(policies_path),
                    }
                )
                return subprocess.run(
                    ["bash", "-c", gate],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment_variables,
                )

        result = run_gate(valid_environment, valid_policies)
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

        def mutated_environment() -> dict[str, Any]:
            return json.loads(json.dumps(valid_environment))

        def mutated_policies() -> dict[str, Any]:
            return json.loads(json.dumps(valid_policies))

        environment = mutated_environment()
        environment["name"] = "syswarden-release-qualification"
        mutations.append(("wrong environment name", environment, mutated_policies()))

        environment = mutated_environment()
        environment["can_admins_bypass"] = True
        mutations.append(("administrator bypass", environment, mutated_policies()))

        environment = mutated_environment()
        environment["protection_rules"][0]["prevent_self_review"] = True
        mutations.append(("self review forbidden", environment, mutated_policies()))

        environment = mutated_environment()
        environment["protection_rules"][0]["reviewers"][0]["reviewer"][
            "login"
        ] = "other"
        mutations.append(("reviewer is not owner", environment, mutated_policies()))

        environment = mutated_environment()
        environment["protection_rules"][0]["reviewers"].append(
            {"type": "User", "reviewer": {"login": "other"}}
        )
        mutations.append(("multiple reviewers", environment, mutated_policies()))

        environment = mutated_environment()
        environment["deployment_branch_policy"]["protected_branches"] = True
        mutations.append(("protected branches enabled", environment, mutated_policies()))

        environment = mutated_environment()
        environment["deployment_branch_policy"]["custom_branch_policies"] = False
        mutations.append(("custom policies disabled", environment, mutated_policies()))

        policies = mutated_policies()
        policies["branch_policies"][0]["name"] = "release/*"
        mutations.append(("non-main policy", mutated_environment(), policies))

        policies = mutated_policies()
        policies["branch_policies"][0]["type"] = "tag"
        mutations.append(("tag policy", mutated_environment(), policies))

        policies = mutated_policies()
        policies["total_count"] = 2
        policies["branch_policies"].append({"name": "release/*", "type": "branch"})
        mutations.append(("multiple policies", mutated_environment(), policies))

        for label, environment, policies in mutations:
            with self.subTest(mutation=label):
                result = run_gate(environment, policies)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_permissions_cannot_publish_or_attest(self) -> None:
        self.assertGreaterEqual(self.workflow.count("contents: read"), 2)
        self.assertGreaterEqual(self.workflow.count("actions: read"), 2)
        for forbidden in (
            "contents: write",
            "actions: write",
            "id-token: write",
            "packages: write",
            "gh release",
            "git push",
            "git tag",
            "softprops/action-gh-release",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_every_action_is_pinned_to_an_exact_commit(self) -> None:
        action_references = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.workflow)
        self.assertEqual(
            action_references,
            [
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            ],
        )
        for reference in action_references:
            self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            action_references,
        )
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            action_references,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            action_references,
        )

    def test_untrusted_inputs_are_never_interpolated_into_shell_source(self) -> None:
        self.assertTrue(self.run_blocks)
        for block in self.run_blocks:
            self.assertNotIn("${{ inputs.", block)
            self.assertNotIn("${{ secrets.", block)
            self.assertNotIn("${{ vars.", block)

    def test_every_literal_run_block_parses_as_bash(self) -> None:
        for index, block in enumerate(self.run_blocks):
            result = subprocess.run(
                ["bash", "-n"],
                input=textwrap.dedent(block),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"run block {index} is not valid bash: {result.stderr}",
            )

    def test_unsigned_artifact_identity_is_exact_and_immutable(self) -> None:
        for required in (
            "artifact-ids: ${{ inputs.unsigned_artifact_id }}",
            "artifact-ids: ${{ inputs.rhel_package_owned_artifact_id }}",
            '.[0].digest // ""',
            "^sha256:[0-9a-f]{64}$",
            '.[0].path',
            '".github/workflows/package.yml"',
            '"${REQUESTED_RUN_ID}"',
            "native_package_signing_bundle.py",
            "inventory --release",
            "release_gate.py verify-packages",
        ):
            self.assertIn(required, self.workflow)

    def test_rhel_package_owned_lane_is_distinct_and_bound_to_the_same_run(self) -> None:
        for required in (
            "rhel_package_owned_artifact_id:",
            'expected_rhel_name="syswarden-rhel-package-owned-${version}"',
            'expected_inventory}" == "[\\"${expected_name}\\",\\"${expected_rhel_name}\\"]"',
            'rhel_rpm_name="syswarden-${version}-1.rhelpo.x86_64.rpm"',
            '"${RHEL_UNSIGNED_DIR}/${rhel_rpm_name}"',
            '"${RHEL_SIGNED_DIR}/${rhel_rpm_name}"',
            '"${PROOF_DIR}/rhel-rpm-proof.json"',
            "--package-role rhel-package-owned",
            '"${PROOF_DIR}/rhel-rpm-verification.json"',
            '--rhel-unsigned-artifact-id "${RHEL_UNSIGNED_ARTIFACT_ID}"',
            '--rhel-unsigned-artifact-digest "${RHEL_UNSIGNED_ARTIFACT_DIGEST}"',
            '--rhel-rpm-proof "${PROOF_DIR}/rhel-rpm-proof.json"',
            '--rhel-rpm-verification "${PROOF_DIR}/rhel-rpm-verification.json"',
        ):
            self.assertIn(required, self.workflow)
        self.assertEqual(
            self.workflow.count("actions/download-artifact@"),
            3,
        )
        self.assertEqual(
            self.workflow.count('run-id: ${{ inputs.unsigned_package_run_id }}'),
            2,
        )
        rpm_start = self.workflow.index(
            "- name: Sign Exact RPM in Family-Scoped Private Workspace"
        )
        rpm_end = self.workflow.index("\n      - name:", rpm_start + 1)
        rpm_step = self.workflow[rpm_start:rpm_end]
        self.assertEqual(rpm_step.count("rpmsign \\"), 2)
        self.assertIn("${rpm_expected_fingerprint}", rpm_step)
        self.assertNotIn("APK_SIGNING_PRIVATE_KEY", rpm_step)
        self.assertNotIn("DEB_SIGNING_PRIVATE_KEY", rpm_step)

    def test_signing_tools_are_prepared_before_secrets_are_loaded(self) -> None:
        tools = self.workflow.index("Prepare Native Signing Tools Before Loading Secrets")
        rpm = self.workflow.index("Sign Exact RPM in Family-Scoped Private Workspace")
        deb = self.workflow.index("Sign Exact DEB in Family-Scoped Private Workspace")
        apk = self.workflow.index("Sign Exact APK in Family-Scoped Private Workspace")
        cleanup = self.workflow.index("Attest Family-Scoped Private Material Is Absent")
        upload = self.workflow.index("Upload Exact Signed Package Bundle")
        self.assertLess(tools, rpm)
        self.assertLess(rpm, deb)
        self.assertLess(deb, apk)
        self.assertLess(apk, cleanup)
        self.assertLess(cleanup, upload)
        self.assertNotIn("set -x", self.workflow)
        self.assertIn("unset RPM_SIGNING_PRIVATE_KEY RPM_SIGNING_PASSPHRASE", self.workflow)
        self.assertIn("unset APK_SIGNING_PRIVATE_KEY", self.workflow)
        self.assertIn("APK_SIGNING_PASSPHRASE", self.workflow)
        self.assertIn("unset DEB_SIGNING_PRIVATE_KEY DEB_SIGNING_PASSPHRASE", self.workflow)
        self.assertIn("SYSWARDEN_DEB_SIGNING_PRIVATE_KEY", self.workflow)
        self.assertIn("SYSWARDEN_DEB_SIGNING_PASSPHRASE", self.workflow)
        self.assertIn('document["apk"]["signer_image"] != signer_image', self.workflow)
        self.assertIn("APK signer image differs from the committed signature policy", self.workflow)
        self.assertIn('-passin "file:${apk_passphrase}"', self.workflow)
        self.assertIn("protected RPM private key must require a non-empty passphrase", self.workflow)
        self.assertIn("protected APK private key must require a non-empty passphrase", self.workflow)
        self.assertIn("protected DEB private key must require a non-empty passphrase", self.workflow)
        self.assertIn("gpgconf --homedir", self.workflow)
        fingerprint_check = self.workflow.index(
            "protected RPM private key does not match the committed key identity"
        )
        unprotected_probe = self.workflow.index("rpm_unprotected_probe=")
        agent_reset = self.workflow.index(
            'gpgconf --homedir "${rpm_gnupg}" --kill gpg-agent',
            fingerprint_check,
        )
        self.assertLess(agent_reset, unprotected_probe)
        self.assertIn("--passphrase ''", self.workflow)
        self.assertIn("-passin file:/dev/null", self.workflow)
        for family in ("rpm", "deb", "apk"):
            self.assertIn(f'cleanup_{family}_secret() {{', self.workflow)
            self.assertIn(f'trap cleanup_{family}_secret EXIT', self.workflow)
        self.assertIn('test ! -e "${rpm_secret_dir}"', self.workflow)
        self.assertIn('test ! -e "${deb_secret_dir}"', self.workflow)
        self.assertIn('test ! -e "${apk_secret_dir}"', self.workflow)

    def test_each_secret_bearing_step_is_scoped_to_one_package_family(self) -> None:
        family_secrets = {
            "RPM": (
                "SYSWARDEN_RPM_SIGNING_PRIVATE_KEY",
                "SYSWARDEN_RPM_SIGNING_PASSPHRASE",
            ),
            "DEB": (
                "SYSWARDEN_DEB_SIGNING_PRIVATE_KEY",
                "SYSWARDEN_DEB_SIGNING_PASSPHRASE",
            ),
            "APK": (
                "SYSWARDEN_APK_SIGNING_PRIVATE_KEY",
                "SYSWARDEN_APK_SIGNING_PASSPHRASE",
            ),
        }
        for family, own_secrets in family_secrets.items():
            start = self.workflow.index(
                f"- name: Sign Exact {family} in Family-Scoped Private Workspace"
            )
            end = self.workflow.index("\n      - name:", start + 1)
            step = self.workflow[start:end]
            for secret in own_secrets:
                self.assertIn(secret, step)
            for other_family, other_secrets in family_secrets.items():
                if other_family == family:
                    continue
                for secret in other_secrets:
                    self.assertNotIn(secret, step)

    def test_family_secrets_are_deexported_before_any_subprocess(self) -> None:
        families = {
            "RPM": "rpm",
            "DEB": "deb",
            "APK": "apk",
        }
        subprocess_markers = (
            "$(basename ",
            "$(gpgconf ",
            "$(id ",
            "$(jq ",
            "$(realpath ",
            "\n          chmod ",
            "\n          docker ",
            "\n          gpg ",
            "\n          gpgconf ",
            "\n          install ",
            "\n          openssl ",
            "\n          rm ",
            "\n          rpm ",
            "\n          rpm2cpio ",
            "\n          rpmsign ",
            "\n          sha256sum ",
            "\n              sleep ",
        )
        for family, lower in families.items():
            with self.subTest(family=family):
                start = self.workflow.index(
                    f"- name: Sign Exact {family} in Family-Scoped Private Workspace"
                )
                end = self.workflow.index("\n      - name:", start + 1)
                step = self.workflow[start:end]
                capture_private = step.index(
                    f'declare +x {lower}_private_material="${{{family}_SIGNING_PRIVATE_KEY-}}"'
                )
                capture_passphrase = step.index(
                    f'declare +x {lower}_passphrase_material="${{{family}_SIGNING_PASSPHRASE-}}"'
                )
                deexport = step.index(
                    f"unset {family}_SIGNING_PRIVATE_KEY {family}_SIGNING_PASSPHRASE"
                )
                self.assertLess(capture_private, deexport)
                self.assertLess(capture_passphrase, deexport)
                self.assertLess(
                    deexport,
                    step.index(f'test -n "${{{lower}_private_material}}"'),
                )
                self.assertLess(
                    deexport,
                    step.index(f'test -n "${{{lower}_passphrase_material}}"'),
                )
                for marker in subprocess_markers:
                    position = step.find(marker)
                    if position >= 0:
                        self.assertLess(
                            deexport,
                            position,
                            f"{family} secret environment reaches subprocess {marker!r}",
                        )

                cleanup_start = step.index(f"cleanup_{lower}_secret() {{")
                cleanup_end = step.index("\n          }", cleanup_start)
                cleanup = step[cleanup_start:cleanup_end]
                local_unset = cleanup.index(
                    f"unset -v {family}_SIGNING_PRIVATE_KEY {family}_SIGNING_PASSPHRASE"
                )
                self.assertLess(local_unset, cleanup.index("local cleanup_status=0"))
                for marker in (
                    "local cleanup_status=0",
                    "command -v",
                    "gpgconf ",
                    "chmod ",
                    "rm -rf",
                ):
                    position = cleanup.find(marker)
                    if position >= 0:
                        self.assertLess(local_unset, position)

    def test_gnupg_agent_cache_cleanup_is_fail_closed(self) -> None:
        for family in ("rpm", "deb"):
            with self.subTest(family=family):
                self.assertIn(f"{family}_agent_socket=", self.workflow)
                self.assertIn(f"wait_for_{family}_agent_stop() {{", self.workflow)
                self.assertIn(f'[[ ! -S "${{{family}_agent_socket}}" ]]', self.workflow)
                self.assertIn(
                    f"ERROR: {family.upper()} GnuPG agent did not stop after the cache reset.",
                    self.workflow,
                )
        self.assertNotRegex(
            self.workflow,
            r"--kill gpg-agent[^\n]*\|\|\s*:",
        )
        self.assertIn("cleanup_status=0", self.workflow)
        self.assertIn('exit "${cleanup_status}"', self.workflow)

    def test_bootstrap_mode_is_explicit_and_strictly_non_publishing(self) -> None:
        for required in (
            "qualification_mode:",
            "bootstrap-qualification",
            "qualified-policy",
            "foundation-not-qualified",
            "implemented-not-qualified",
            'document["publishing"] is not False',
            "--bootstrap-qualification",
            "--purpose qualification",
        ):
            self.assertIn(required, self.workflow)
        self.assertNotIn("--purpose publishing", self.workflow)

    def test_qualified_mode_requires_one_exact_prior_bootstrap(self) -> None:
        for required in (
            "bootstrap_release_sha:",
            "bootstrap_signing_run_id:",
            "bootstrap_signed_artifact_id:",
            "bootstrap_policy_sha256:",
            "APPROVED_BOOTSTRAP_ARTIFACT_DIGEST: sha256:e06ab6cf35c0c71a512588867e13715e7d754dc70e0ce2fb4c8c073b36429d1a",
            'APPROVED_BOOTSTRAP_ARTIFACT_ID: "10734465160"',
            "APPROVED_BOOTSTRAP_ARTIFACT_NAME: syswarden-native-signed-packages-4.10.0-35822833447-1-c741c775e990ac6c877847b3a99ca3a5c392e35b",
            'APPROVED_BOOTSTRAP_ARTIFACT_SIZE: "64068607"',
            "APPROVED_BOOTSTRAP_RELEASE_SHA: c741c775e990ac6c877847b3a99ca3a5c392e35b",
            "APPROVED_BOOTSTRAP_REPOSITORY: duggytuxy/syswarden",
            'APPROVED_BOOTSTRAP_RUN_ID: "35822833447"',
            "FOUNDATION_POLICY_SHA256: 6b98b3b5bca83b9bc611c3b2e384636b5bbcbecc9e818e0f06104255200b011d",
            '"${BOOTSTRAP_POLICY_SHA256}" != "${FOUNDATION_POLICY_SHA256}"',
            '"${BOOTSTRAP_RELEASE_SHA}" != "${APPROVED_BOOTSTRAP_RELEASE_SHA}"',
            '"${BOOTSTRAP_SIGNING_RUN_ID}" != "${APPROVED_BOOTSTRAP_RUN_ID}"',
            '"${BOOTSTRAP_SIGNED_ARTIFACT_ID}" != "${APPROVED_BOOTSTRAP_ARTIFACT_ID}"',
            "Resolve Exact Prior Bootstrap Run and Artifact",
            '"${BOOTSTRAP_RELEASE_SHA}" == "${RELEASE_SHA}"',
            'git merge-base --is-ancestor "${BOOTSTRAP_RELEASE_SHA}" "${RELEASE_SHA}"',
            'policy_size="$(git cat-file -s "${policy_object}")"',
            '"${policy_size}" -gt 131072',
            '.path // ""',
            '".github/workflows/native-package-signing.yml"',
            '.event // ""',
            '"workflow_dispatch"',
            '.run_attempt | tostring',
            '.conclusion // ""',
            '.actor.login // ""',
            '.triggering_actor.login // ""',
            "bootstrap signing run must expose exactly one artifact",
            '.workflow_run.id == $run and .workflow_run.head_sha == $sha and',
            '.workflow_run.head_branch == "main"',
            '"${artifact_size}" != "${APPROVED_BOOTSTRAP_ARTIFACT_SIZE}"',
            '"${artifact_digest}" != "${APPROVED_BOOTSTRAP_ARTIFACT_DIGEST}"',
            "--bootstrap-bundle",
            "--bootstrap-policy-sha256",
            "--bootstrap-signed-artifact-size",
            "validate_bootstrap_binding",
        ):
            self.assertIn(required, self.workflow)
        guard = self.workflow.index(
            "Validate Exact Bootstrap Policy Transition and Bundle"
        )
        first_secret = self.workflow.index("${{ secrets.")
        self.assertLess(guard, first_secret)

    def test_recovery_requires_explicit_authorization_and_owner_context(self) -> None:
        script = named_literal_run_block(self.workflow, "Validate Protected Manual Context")
        environment = dict(os.environ)
        environment.update({
            "APK_SIGNER_IMAGE": json.loads(POLICY.read_text())["apk"]["signer_image"],
            "AUTHORIZATION": "REQUALIFY-NATIVE-BOOTSTRAP-NO-PUBLISH",
            "EVENT_ACTOR": "duggytuxy", "EVENT_TRIGGERING_ACTOR": "duggytuxy",
            "REPOSITORY_OWNER": "duggytuxy", "EVENT_REPOSITORY": "duggytuxy/syswarden",
            "EVENT_NAME": "workflow_dispatch", "EVENT_REF_TYPE": "branch",
            "EVENT_REF_NAME": "main", "EVENT_REF": "refs/heads/main",
            "EVENT_SHA": "a" * 40, "WORKFLOW_SHA": "a" * 40,
            "RELEASE_SHA": "a" * 40, "RELEASE_TAG": "v4.10.0", "RUN_ATTEMPT": "1",
            "UNSIGNED_PACKAGE_RUN_ID": "101", "UNSIGNED_ARTIFACT_ID": "102",
            "RHEL_PACKAGE_OWNED_ARTIFACT_ID": "103",
            "RPM_KEY_ID": "rpm-prod-2026-01", "APK_KEY_ID": "apk-prod-2026-01",
            "DEB_KEY_ID": "deb-prod-2026-01", "QUALIFICATION_MODE": "bootstrap-recovery",
            "BOOTSTRAP_RELEASE_SHA": "", "BOOTSTRAP_SIGNING_RUN_ID": "",
            "BOOTSTRAP_SIGNED_ARTIFACT_ID": "", "BOOTSTRAP_POLICY_SHA256": "",
        })

        def execute(changes: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(["bash", "-c", script], env=environment | changes,
                                  capture_output=True, text=True, timeout=10)

        accepted = execute({})
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for changes in (
            {"AUTHORIZATION": "SIGN-NATIVE-PACKAGES-NO-PUBLISH"},
            {"QUALIFICATION_MODE": "bootstrap-qualification"},
            {"EVENT_ACTOR": "another-user"}, {"EVENT_TRIGGERING_ACTOR": "another-user"},
            {"RUN_ATTEMPT": "2"}, {"EVENT_REF_NAME": "feature"},
            {"WORKFLOW_SHA": "b" * 40}, {"RELEASE_TAG": "v4.10.1"},
            {"BOOTSTRAP_SIGNED_ARTIFACT_ID": "10734465160"},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(execute(changes).returncode, 0)
        accepted = execute({"QUALIFICATION_MODE": "bootstrap-qualification",
                            "AUTHORIZATION": "SIGN-NATIVE-PACKAGES-NO-PUBLISH"})
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_recovery_cannot_change_foundation_keys_or_qualified_policy(self) -> None:
        script = named_literal_run_block(self.workflow, "Validate Source and Signature Policy Foundation")
        python_script = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        foundation = ROOT / "scripts/ci/native_package_signature_foundation_v4100.json"
        foundation_bytes = foundation.read_bytes()
        current_bytes = POLICY.read_bytes()
        signer = json.loads(current_bytes)["apk"]["signer_image"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged_foundation, staged_current = root / "foundation.json", root / "current.json"

            def execute(base: bytes, current: bytes, day: str = "2026-09-23",
                        rpm_key: str = "rpm-prod-2026-01", image: str = signer) -> subprocess.CompletedProcess[str]:
                staged_foundation.write_bytes(base)
                staged_current.write_bytes(current)
                return subprocess.run(
                    [sys.executable, "-B", "-c", python_script, str(staged_foundation), day,
                     rpm_key, "apk-prod-2026-01", "deb-prod-2026-01", image,
                     "bootstrap-recovery", str(staged_current)],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )

            accepted = execute(foundation_bytes, current_bytes)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            for family in ("rpm", "apk", "deb"):
                changed = json.loads(current_bytes)
                changed[family]["trusted_keys"][0]["public_key_sha256"] = "0" * 64
                with self.subTest(family=family):
                    self.assertNotEqual(execute(foundation_bytes, json.dumps(changed).encode()).returncode, 0)
            for base, current in ((foundation_bytes + b"\n", current_bytes),
                                  (current_bytes, current_bytes),
                                  (foundation_bytes, foundation_bytes)):
                self.assertNotEqual(execute(base, current).returncode, 0)
            self.assertNotEqual(execute(foundation_bytes, current_bytes, day="2029-01-01").returncode, 0)
            self.assertNotEqual(execute(foundation_bytes, current_bytes, rpm_key="other").returncode, 0)
            self.assertNotEqual(execute(foundation_bytes, current_bytes, image="unreviewed").returncode, 0)

    def test_recovery_keeps_native_verification_and_separate_bootstrap_output(self) -> None:
        selection = named_literal_run_block(self.workflow, "Validate Source and Signature Policy Foundation")
        self.assertIn("validate_policy_transition", selection)
        self.assertIn("SIGNING_POLICY_PATH", selection)
        verification = named_literal_run_block(self.workflow, "Verify Native Signatures with Isolated Trust Roots")
        self.assertIn('policy="${SIGNING_POLICY_PATH:?validated signing policy is required}"', verification)
        self.assertIn('"${QUALIFICATION_MODE}" == "bootstrap-recovery"', verification)
        self.assertEqual(verification.count('--policy "${policy}"'), 4)
        self.assertIn("retention-days: 90", self.workflow)

    def test_bootstrap_and_qualified_artifact_names_are_unambiguous(self) -> None:
        self.assertIn(
            'expected_name="syswarden-native-signed-packages-${version}-${REQUESTED_RUN_ID}-1-${BOOTSTRAP_RELEASE_SHA}"',
            self.workflow,
        )
        self.assertIn(
            'artifact_name="syswarden-native-signed-packages-${RELEASE_TAG#v}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RELEASE_SHA}"',
            self.workflow,
        )
        self.assertIn(
            'artifact_name="syswarden-native-signed-packages-qualified-${RELEASE_TAG#v}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RELEASE_SHA}"',
            self.workflow,
        )
        self.assertIn('verify_args+=(--mode bootstrap)', self.workflow)

    def test_recovered_bootstrap_extracts_foundation_from_its_own_commit(self) -> None:
        script = named_literal_run_block(
            self.workflow, "Validate Exact Bootstrap Policy Transition and Bundle"
        ).split("PYTHONDONTWRITEBYTECODE=1 python3 -", 1)[0]
        environment = dict(os.environ)
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            environment.pop(name, None)
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        foundation_bytes = (ROOT / "scripts/ci/native_package_signature_foundation_v4100.json").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                     "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
                    cwd=root, env=environment, text=True, stderr=subprocess.PIPE,
                ).strip()

            git("init", "--quiet")
            policy_dir = root / "scripts/ci"
            policy_dir.mkdir(parents=True)
            foundation = policy_dir / "native_package_signature_foundation_v4100.json"
            foundation.write_bytes(foundation_bytes)
            (policy_dir / POLICY.name).write_bytes(POLICY.read_bytes())
            git("add", ".")
            git("commit", "--quiet", "-m", "Recovery source with separate foundation")
            bootstrap_sha = git("rev-parse", "HEAD")
            foundation.write_text("successor bytes must never replace the ancestor policy\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "Distinct successor")
            signing_root = root / "signing"
            signing_root.mkdir()
            result = subprocess.run(
                ["bash", "-c", script], cwd=root, env=environment | {
                    "BOOTSTRAP_RELEASE_SHA": bootstrap_sha,
                    "RELEASE_SHA": git("rev-parse", "HEAD"),
                    "SIGNING_ROOT": str(signing_root),
                }, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            extracted = signing_root / "bootstrap-policy.json"
            self.assertEqual(extracted.read_bytes(), foundation_bytes)
            self.assertNotEqual(extracted.read_bytes(), POLICY.read_bytes())
            self.assertEqual(extracted.stat().st_mode & 0o777, 0o600)

    def test_bootstrap_run_resolver_fails_closed(self) -> None:
        resolver = named_literal_run_block(
            self.workflow, "Resolve Exact Prior Bootstrap Run and Artifact"
        )
        bootstrap_sha = "c741c775e990ac6c877847b3a99ca3a5c392e35b"
        run_id = 35822833447
        artifact_id = 10734465160
        artifact_size = 64068607
        artifact_digest = (
            "sha256:e06ab6cf35c0c71a512588867e13715e7d754dc70e0ce2fb4c8c073b36429d1a"
        )
        artifact_name = (
            "syswarden-native-signed-packages-4.10.0-"
            f"{run_id}-1-{bootstrap_sha}"
        )
        valid_run = {
            "actor": {"login": "duggytuxy"},
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": bootstrap_sha,
            "id": run_id,
            "path": ".github/workflows/native-package-signing.yml",
            "run_attempt": 1,
            "status": "completed",
            "triggering_actor": {"login": "duggytuxy"},
        }
        valid_artifact = {
            "digest": artifact_digest,
            "expired": False,
            "id": artifact_id,
            "name": artifact_name,
            "size_in_bytes": artifact_size,
            "workflow_run": {
                "head_branch": "main",
                "head_sha": bootstrap_sha,
                "id": run_id,
            },
        }

        def execute(
            run_document: dict[str, Any], artifacts: list[dict[str, Any]]
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run_path = root / "run.json"
                artifacts_path = root / "artifacts.json"
                output_path = root / "output.txt"
                run_path.write_text(json.dumps(run_document), encoding="utf-8")
                artifacts_path.write_text(
                    json.dumps({"artifacts": artifacts}), encoding="utf-8"
                )
                gh = root / "gh"
                gh.write_text(
                    """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

endpoint = next(
    argument for argument in sys.argv[1:] if argument.startswith("repos/")
)
if endpoint.endswith("/artifacts"):
    payload = [json.loads(Path(os.environ["TEST_ARTIFACTS_JSON"]).read_text())]
else:
    payload = json.loads(Path(os.environ["TEST_RUN_JSON"]).read_text())
print(json.dumps(payload, separators=(",", ":")))
""",
                    encoding="utf-8",
                )
                gh.chmod(0o700)
                environment = os.environ.copy()
                environment.update(
                    {
                        "BOOTSTRAP_RELEASE_SHA": bootstrap_sha,
                        "APPROVED_BOOTSTRAP_ARTIFACT_DIGEST": artifact_digest,
                        "APPROVED_BOOTSTRAP_ARTIFACT_ID": str(artifact_id),
                        "APPROVED_BOOTSTRAP_ARTIFACT_NAME": artifact_name,
                        "APPROVED_BOOTSTRAP_ARTIFACT_SIZE": str(artifact_size),
                        "APPROVED_BOOTSTRAP_RELEASE_SHA": bootstrap_sha,
                        "APPROVED_BOOTSTRAP_REPOSITORY": "duggytuxy/syswarden",
                        "APPROVED_BOOTSTRAP_RUN_ID": str(run_id),
                        "GITHUB_OUTPUT": str(output_path),
                        "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                        "GH_TOKEN": "test-token",
                        "PATH": f"{root}:{environment['PATH']}",
                        "RELEASE_TAG": "v4.10.0",
                        "REPOSITORY_OWNER": "duggytuxy",
                        "REQUESTED_ARTIFACT_ID": str(artifact_id),
                        "REQUESTED_RUN_ID": str(run_id),
                        "TEST_ARTIFACTS_JSON": str(artifacts_path),
                        "TEST_RUN_JSON": str(run_path),
                    }
                )
                return subprocess.run(
                    ["bash", "-c", resolver],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )

        accepted = execute(valid_run, [valid_artifact])
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        rejected_cases = []
        wrong_attempt = json.loads(json.dumps(valid_run))
        wrong_attempt["run_attempt"] = 2
        rejected_cases.append((wrong_attempt, [valid_artifact]))
        extra_artifact = json.loads(json.dumps(valid_artifact))
        extra_artifact["id"] = artifact_id + 1
        rejected_cases.append((valid_run, [valid_artifact, extra_artifact]))
        wrong_sha = json.loads(json.dumps(valid_artifact))
        wrong_sha["workflow_run"]["head_sha"] = "c" * 40
        rejected_cases.append((valid_run, [wrong_sha]))
        wrong_branch = json.loads(json.dumps(valid_artifact))
        wrong_branch["workflow_run"]["head_branch"] = "other"
        rejected_cases.append((valid_run, [wrong_branch]))
        bad_digest = json.loads(json.dumps(valid_artifact))
        bad_digest["digest"] = "sha256:" + "a" * 63
        rejected_cases.append((valid_run, [bad_digest]))
        wrong_digest = json.loads(json.dumps(valid_artifact))
        wrong_digest["digest"] = "sha256:" + "0" * 64
        rejected_cases.append((valid_run, [wrong_digest]))
        wrong_size = json.loads(json.dumps(valid_artifact))
        wrong_size["size_in_bytes"] = artifact_size + 1
        rejected_cases.append((valid_run, [wrong_size]))
        expired = json.loads(json.dumps(valid_artifact))
        expired["expired"] = True
        expired_result = execute(valid_run, [expired])
        self.assertNotEqual(expired_result.returncode, 0)
        self.assertIn("approved bootstrap artifact has expired", expired_result.stderr)
        wrong_id = json.loads(json.dumps(valid_artifact))
        wrong_id["id"] = artifact_id + 1
        rejected_cases.append((valid_run, [wrong_id]))
        false_bootstrap_suffix = json.loads(json.dumps(valid_artifact))
        false_bootstrap_suffix["name"] = (
            "syswarden-native-signed-packages-bootstrap-4.10.0-"
            f"{run_id}-1-{bootstrap_sha}"
        )
        rejected_cases.append((valid_run, [false_bootstrap_suffix]))
        for run_document, artifacts in rejected_cases:
            with self.subTest(run=run_document, artifacts=artifacts):
                self.assertNotEqual(execute(run_document, artifacts).returncode, 0)

    def test_apk_operations_are_offline_and_container_hardened(self) -> None:
        self.assertGreaterEqual(self.workflow.count("--network none"), 2)
        self.assertGreaterEqual(self.workflow.count("--read-only"), 2)
        self.assertGreaterEqual(self.workflow.count("--cap-drop ALL"), 2)
        self.assertGreaterEqual(self.workflow.count("--security-opt no-new-privileges"), 2)
        self.assertGreaterEqual(self.workflow.count("--pull never"), 2)
        self.assertIn("@sha256:[0-9a-f]{64}", self.workflow)
        signing = named_literal_run_block(
            self.workflow, "Sign Exact APK in Family-Scoped Private Workspace"
        )
        self.assertIn("apk-control --unsigned-package", signing)
        self.assertIn("apk-assemble --unsigned-package", signing)
        self.assertIn('abuild-sign -t RSA256 -k "$1" -p "$2" "$3"', signing)
        self.assertIn('"/work/${apk_control_name}"', signing)
        self.assertNotIn('abuild-sign -t RSA256 -k "$1" "$2"', signing)
        self.assertIn('--env "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"', self.workflow)
        self.assertIn("apk_verify_isolated.sh", self.workflow)
        self.assertIn('apk_work_dir="${signing_root}/apk-work"', self.workflow)
        self.assertNotIn('src=${signed_real},dst=/work', self.workflow)

    def test_uploaded_artifact_identity_is_checked(self) -> None:
        self.assertIn("id: signed-upload", self.workflow)
        self.assertIn("steps.signed-upload.outputs.artifact-id", self.workflow)
        self.assertIn("steps.signed-upload.outputs.artifact-digest", self.workflow)
        self.assertIn(
            '[[ "${SIGNED_ARTIFACT_DIGEST}" =~ ^[0-9a-f]{64}$ ]]',
            self.workflow,
        )

    def test_rpm_payload_and_header_are_preserved_and_reverified(self) -> None:
        self.assertIn("%{SHA256HEADER}", self.workflow)
        self.assertGreaterEqual(self.workflow.count("rpm2cpio"), 3)
        self.assertIn('"${rpm_header_after}" == "${rpm_header_before}"', self.workflow)
        self.assertIn('"${rpm_payload_after}" == "${rpm_payload_before}"', self.workflow)
        self.assertIn("native_package_signature_gate.py rpm", self.workflow)
        self.assertIn("rhel-rpm-proof.json", self.workflow)
        self.assertIn("rhel-rpm-verification.json", self.workflow)
        self.assertIn("--purpose qualification", self.workflow)

    def test_deb_uses_a_real_detached_openpgp_signature(self) -> None:
        self.assertNotRegex(self.workflow, r"(?i)(dpkg-sig|debsig|InRelease)")
        for required in (
            "deb_key_id:",
            "SYSWARDEN_DEB_SIGNING_PRIVATE_KEY",
            "SYSWARDEN_DEB_SIGNING_PASSPHRASE",
            "--digest-algo SHA256",
            "--detach-sign",
            "native_package_signature_gate.py deb",
            "--signature \"${PROOF_DIR}/syswarden_${version}_amd64.deb.asc\"",
            "gpgv",
        ):
            self.assertIn(required, self.workflow)
        self.assertIn("DEB_NATIVE_VERIFICATION.json", (
            ROOT / "scripts/ci/native_package_signing_bundle.py"
        ).read_text(encoding="utf-8"))

    def test_bundle_is_sealed_verified_and_not_release_qualified(self) -> None:
        helper = (ROOT / "scripts/ci/native_package_signing_bundle.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("SIGNED_ARTIFACT_SHA256SUMS.txt", helper)
        self.assertIn('RHEL_PACKAGE_OWNED_DIRECTORY = "rhel-package-owned"', helper)
        self.assertIn('"updater_manifest_included": False', helper)
        self.assertIn("verify_rhel_package_owned_bundle", helper)
        self.assertIn("native-signatures-verified-not-release-qualified", helper)
        self.assertIn('"public_release": False', helper)
        self.assertIn('"release_qualified": False', helper)
        self.assertIn("native_package_signing_bundle.py verify", self.workflow)
        self.assertIn("compression-level: 0", self.workflow)

    def test_committed_policy_is_qualified_and_approved_for_publishing(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(policy["status"], "qualified")
        self.assertTrue(policy["publishing"])
        self.assertEqual(policy["deb"]["implementation"], "qualified")
        selected = []
        for family in ("rpm", "apk", "deb"):
            self.assertEqual(len(policy[family]["trusted_keys"]), 1)
            selected.append(policy[family]["trusted_keys"][0])
        self.assertEqual(len({item["id"] for item in selected}), 3)
        self.assertEqual(len({item["public_key_sha256"] for item in selected}), 3)
        self.assertNotEqual(
            policy["rpm"]["trusted_keys"][0]["fingerprint"],
            policy["deb"]["trusted_keys"][0]["fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()
