#!/usr/bin/env python3
"""Static safety contract for protected native package signing."""

from __future__ import annotations

import json
import os
import re
import subprocess
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
            2,
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

    def test_apk_operations_are_offline_and_container_hardened(self) -> None:
        self.assertGreaterEqual(self.workflow.count("--network none"), 2)
        self.assertGreaterEqual(self.workflow.count("--read-only"), 2)
        self.assertGreaterEqual(self.workflow.count("--cap-drop ALL"), 2)
        self.assertGreaterEqual(self.workflow.count("--security-opt no-new-privileges"), 2)
        self.assertGreaterEqual(self.workflow.count("--pull never"), 2)
        self.assertIn("@sha256:[0-9a-f]{64}", self.workflow)
        self.assertIn("abuild-sign -t RSA256", self.workflow)
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

    def test_committed_policy_remains_fail_closed_without_real_keys(self) -> None:
        policy = POLICY.read_text(encoding="utf-8")
        self.assertIn('"status": "foundation-not-qualified"', policy)
        self.assertIn('"publishing": false', policy)
        self.assertGreaterEqual(policy.count('"trusted_keys": []'), 3)


if __name__ == "__main__":
    unittest.main()
