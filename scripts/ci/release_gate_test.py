#!/usr/bin/env python3
"""Unit tests for the fail-closed release asset gate."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import release_gate


class ReleaseGateTests(unittest.TestCase):
    tag = "v4.02.8"
    version = "4.02.8"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write_file(self, path: Path, content: bytes = b"evidence\n") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def make_packages(self) -> Path:
        directory = self.root / "packages"
        directory.mkdir()
        lines = []
        for name in release_gate.package_names(self.version):
            content = f"package:{name}\n".encode()
            self.write_file(directory / name, content)
            lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
        (directory / release_gate.PACKAGE_CHECKSUM_NAME).write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        return directory

    def make_bundle(self, extra: str | None = None) -> Path:
        directory = self.root / "bundle"
        directory.mkdir()
        with tarfile.open(directory / release_gate.BUNDLE_NAME, "w:gz") as archive:
            names = sorted(release_gate.BUNDLE_FILES | ({extra} if extra else set()))
            for name in names:
                payload = f"bundle:{name}\n".encode()
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return directory

    def make_sbom(self) -> Path:
        directory = self.root / "sbom"
        directory.mkdir()
        (directory / release_gate.SBOM_NAME).write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "creationInfo": {"creators": ["Tool: trivy-0.70.0"]},
                    "packages": [
                        {"name": name, "primaryPackagePurpose": "APPLICATION"}
                        for name in sorted(release_gate.EXPECTED_SBOM_APPLICATIONS)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return directory

    def make_compliance(self) -> Path:
        directory = self.root / "compliance"
        self.write_file(directory / "native" / "report.json", b'{"score": 100}\n')
        return directory

    def make_repository(self, heading: str | None = None) -> Path:
        directory = self.root / "repository"
        directory.mkdir()
        (directory / "changelog.md").write_text(
            f"# Release {heading or self.tag}\n\n### FIXED\n- Safe release.\n\n---\n",
            encoding="utf-8",
        )
        return directory

    def prepare(self) -> tuple[Path, Path]:
        output = self.root / "output"
        notes = self.root / "release_notes.md"
        args = type(
            "Args",
            (),
            {
                "repository": self.make_repository(),
                "tag": self.tag,
                "packages": self.make_packages(),
                "bundle": self.make_bundle(),
                "sbom": self.make_sbom(),
                "compliance": self.make_compliance(),
                "output": output,
                "notes_output": notes,
            },
        )()
        release_gate.prepare(args)
        return output, notes

    def test_prepare_and_verify_exact_inventory(self) -> None:
        output, notes = self.prepare()
        release_gate.verify_assets(output, self.tag)
        self.assertEqual(
            {path.name for path in output.iterdir()},
            release_gate.expected_release_assets(self.tag),
        )
        self.assertIn("# Release v4.02.8", notes.read_text(encoding="utf-8"))
        with zipfile.ZipFile(output / release_gate.COMPLIANCE_ARCHIVE_NAME) as archive:
            self.assertEqual(archive.namelist(), ["native/report.json"])

    def test_signed_update_asset_contract_starts_after_legacy_first_hop(self) -> None:
        self.assertFalse(release_gate.signed_update_required("v4.02.8"))
        self.assertTrue(release_gate.signed_update_required("v4.02.9"))
        self.assertTrue(release_gate.signed_update_required("v5.00.0"))
        legacy = release_gate.expected_release_assets("v4.02.8")
        signed = release_gate.expected_release_assets("v4.02.9")
        self.assertNotIn(release_gate.UPDATE_MANIFEST_NAME, legacy)
        self.assertNotIn(release_gate.UPDATE_SIGNATURE_NAME, legacy)
        self.assertIn(release_gate.UPDATE_MANIFEST_NAME, signed)
        self.assertIn(release_gate.UPDATE_SIGNATURE_NAME, signed)

    def test_signed_update_predicate_cli_is_semantic_and_machine_readable(self) -> None:
        for tag, expected in (
            ("v4.02.7", "false"),
            ("v4.02.8", "false"),
            ("v4.02.9", "true"),
            ("v4.02.10", "true"),
            ("v5.00.0", "true"),
        ):
            with self.subTest(tag=tag), mock.patch(
                "sys.argv", ["release_gate.py", "requires-signed-update", "--tag", tag]
            ), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(release_gate.main(), 0)
                self.assertEqual(output.getvalue(), expected + "\n")

    def test_signed_release_fails_closed_without_qualification_manifest(self) -> None:
        self.tag = "v4.02.9"
        self.version = "4.02.9"
        args = type(
            "Args",
            (),
            {
                "repository": self.make_repository(),
                "tag": self.tag,
                "packages": self.make_packages(),
                "bundle": self.make_bundle(),
                "sbom": self.make_sbom(),
                "compliance": self.make_compliance(),
                "output": self.root / "output",
                "notes_output": self.root / "release_notes.md",
                "update_manifest_dir": None,
            },
        )()
        with self.assertRaisesRegex(
            release_gate.ReleaseGateError, "signed update manifest directory is required"
        ):
            release_gate.prepare(args)

    def test_signed_prepare_binds_manifest_into_exact_release_inventory(self) -> None:
        self.tag = "v4.02.9"
        self.version = "4.02.9"
        update = self.root / "update"
        self.write_file(update / release_gate.UPDATE_MANIFEST_NAME, b"manifest\n")
        self.write_file(update / release_gate.UPDATE_SIGNATURE_NAME, b"signature\n")
        repository = self.make_repository()
        output = self.root / "output"
        args = type(
            "Args",
            (),
            {
                "repository": repository,
                "tag": self.tag,
                "packages": self.make_packages(),
                "bundle": self.make_bundle(),
                "sbom": self.make_sbom(),
                "compliance": self.make_compliance(),
                "output": output,
                "notes_output": self.root / "release_notes.md",
                "update_manifest_dir": update,
            },
        )()
        with mock.patch("release_gate.verify_signed_update_manifest") as verifier:
            release_gate.prepare(args)
            release_gate.verify_assets(output, self.tag, repository)
        self.assertGreaterEqual(verifier.call_count, 3)
        self.assertEqual(
            {path.name for path in output.iterdir()},
            release_gate.expected_release_assets(self.tag),
        )
        checksums = release_gate.parse_checksum_manifest(
            output / release_gate.RELEASE_CHECKSUM_NAME
        )
        self.assertIn(release_gate.UPDATE_MANIFEST_NAME, checksums)
        self.assertIn(release_gate.UPDATE_SIGNATURE_NAME, checksums)

    def test_public_verifier_strips_private_secret_from_subprocess(self) -> None:
        repository = self.root / "repository"
        repository.mkdir()
        packages = self.root / "packages"
        packages.mkdir()
        manifest = self.root / release_gate.UPDATE_MANIFEST_NAME
        signature = self.root / release_gate.UPDATE_SIGNATURE_NAME
        self.write_file(manifest)
        self.write_file(signature)
        marker = "PRIVATE-KEY-MUST-NOT-REACH-GO-RUN"
        with mock.patch.dict(
            os.environ,
            {release_gate.UPDATE_PRIVATE_KEY_ENV: marker},
        ), mock.patch(
            "release_gate.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as runner:
            release_gate.verify_signed_update_manifest(
                repository, "v4.02.9", packages, manifest, signature
            )
        call = runner.call_args
        command = call.args[0]
        environment = call.kwargs["env"]
        self.assertNotIn(release_gate.UPDATE_PRIVATE_KEY_ENV, environment)
        self.assertNotIn(marker, command)
        self.assertEqual(environment["GOFLAGS"], "-mod=readonly")
        self.assertNotIn("shell", call.kwargs)

    def test_package_artifact_rejects_extra_file(self) -> None:
        packages = self.make_packages()
        self.write_file(packages / "unexpected.deb")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_packages(packages, self.version)

    def test_package_artifact_rejects_bad_checksum(self) -> None:
        packages = self.make_packages()
        first = release_gate.package_names(self.version)[0]
        (packages / first).write_bytes(b"tampered\n")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_packages(packages, self.version)

    def test_bundle_rejects_unexpected_file(self) -> None:
        bundle = self.make_bundle(extra="unexpected") / release_gate.BUNDLE_NAME
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_bundle(bundle)

    def test_verify_bundle_cli_uses_the_exact_inventory_contract(self) -> None:
        bundle = self.make_bundle() / release_gate.BUNDLE_NAME
        with mock.patch(
            "sys.argv", ["release_gate.py", "verify-bundle", "--bundle", str(bundle)]
        ):
            self.assertEqual(release_gate.main(), 0)
        bundle.write_bytes(b"not a tar archive\n")
        with mock.patch(
            "sys.argv", ["release_gate.py", "verify-bundle", "--bundle", str(bundle)]
        ):
            self.assertEqual(release_gate.main(), 1)

    def test_sbom_rejects_empty_package_inventory(self) -> None:
        sbom = self.make_sbom() / release_gate.SBOM_NAME
        sbom.write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "packages": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_sbom(sbom)

    def test_sbom_rejects_partial_or_wrong_tool_inventory(self) -> None:
        sbom = self.make_sbom() / release_gate.SBOM_NAME
        document = json.loads(sbom.read_text(encoding="utf-8"))
        document["packages"].pop()
        sbom.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_sbom(sbom)
        document["packages"] = [
            {"name": name, "primaryPackagePurpose": "APPLICATION"}
            for name in sorted(release_gate.EXPECTED_SBOM_APPLICATIONS)
        ]
        document["creationInfo"]["creators"] = ["Tool: trivy-dev"]
        sbom.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_sbom(sbom)

    def test_verify_sbom_cli_uses_the_strict_contract(self) -> None:
        sbom = self.make_sbom() / release_gate.SBOM_NAME
        with mock.patch(
            "sys.argv", ["release_gate.py", "verify-sbom", "--sbom", str(sbom)]
        ):
            self.assertEqual(release_gate.main(), 0)
        document = json.loads(sbom.read_text(encoding="utf-8"))
        document["packages"] = []
        sbom.write_text(json.dumps(document), encoding="utf-8")
        with mock.patch(
            "sys.argv", ["release_gate.py", "verify-sbom", "--sbom", str(sbom)]
        ):
            self.assertEqual(release_gate.main(), 1)

    def test_compliance_rejects_empty_native_report(self) -> None:
        compliance = self.root / "compliance"
        self.write_file(compliance / "report.json", b"")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.write_compliance_archive(
                compliance, self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
            )

    def test_compliance_archive_accepts_native_directories(self) -> None:
        archive = self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("native/", b"")
            output.writestr("native/report.json", b'{"score": 100}\n')
        release_gate.validate_compliance_archive(archive)

    def test_notes_reject_previous_release(self) -> None:
        repository = self.make_repository("v4.02.7")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.release_notes(repository, self.tag)

    def test_workflow_extracts_remote_notes_without_appending_a_newline(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("jq -j '.body'"), 2)
        self.assertNotIn("jq -r '.body'", workflow)

    def test_qualification_signer_compiles_before_protected_secret_exposure(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-qualification.yml"
        ).read_text(encoding="utf-8")
        build = workflow.split(
            "      - name: Build and Test Signed Update Manifest Tool\n", 1
        )[1].split("      - name:", 1)[0]
        signer = workflow.split(
            "      - name: Generate and Verify Signed Update Manifest\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn(
            "if: ${{ steps.update_contract.outputs.required == 'true' }}", build
        )
        self.assertIn("GOFLAGS=-mod=readonly go build", build)
        self.assertIn("update_manifest_test.go", build)
        self.assertIn('"${SIGNING_TOOL_DIR}/syswarden-update-manifest"', build)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", build)
        self.assertIn(
            "SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY: "
            "${{ secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY }}",
            signer,
        )
        self.assertIn('unset SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', signer)
        self.assertIn('env -u SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', signer)
        self.assertNotIn("go run", signer)
        self.assertNotIn("sha256sum", signer)
        self.assertNotIn("stat -c", signer)
        self.assertNotIn("$(id", signer)
        self.assertNotIn("set -x", signer)
        self.assertNotIn('echo "${SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY}', signer)
        self.assertNotIn("printf '%s' \"${SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY}", signer)
        self.assertEqual(
            workflow.count("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"), 1
        )
        self.assertIn('"update/syswarden-update-manifest-v1.json"', workflow)
        self.assertIn('"update/syswarden-update-manifest-v1.json.sig"', workflow)
        self.assertLess(
            workflow.index("Require Successful Qualification Before Release Signing"),
            workflow.index("Generate and Verify Signed Update Manifest"),
        )
        self.assertLess(
            workflow.index("Generate and Verify Signed Update Manifest"),
            workflow.index("Seal Exact Qualification Evidence Inventory"),
        )
        self.assertIn("refusing to sign because ${status_file}", workflow)
        self.assertIn('rm -f -- "${manifest_path}" "${signature_path}"', signer)
        self.assertIn(
            '"${update_dir}/syswarden-update-manifest-v1.json.sig"', workflow
        )

    def test_release_manager_revalidates_signed_assets_and_preserves_v4028(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("qualification_root_directories+=(update)"), 2)
        self.assertEqual(
            workflow.count("go run ./scripts/ci/update_manifest.go verify"), 2
        )
        self.assertEqual(workflow.count('--repository "${GITHUB_WORKSPACE}"'), 7)
        self.assertNotIn('if [[ "${RELEASE_TAG}" != "v4.02.8" ]]', workflow)
        self.assertEqual(workflow.count("requires-signed-update --tag"), 3)
        self.assertEqual(workflow.count('if [[ "${SIGNED_UPDATE_REQUIRED}" == "true" ]]'), 6)
        self.assertIn("--update-manifest-dir", workflow)
        self.assertIn("Set Up Go for Signed Update Verification", workflow)
        self.assertNotIn("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", workflow)

    def publish_script(self) -> str:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        step = workflow.split(
            "      - name: Publish Validated Draft Release\n", 1
        )[1].split("      - name: Verify Published Release Assets\n", 1)[0]
        indented_script = step.split("        run: |\n", 1)[1]
        return "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in indented_script.splitlines()
        )

    def ruleset_script(self) -> str:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        step = workflow.split(
            "      - name: Require Immutable Release Tag Ruleset Before Publication\n",
            1,
        )[1].split("      - name: Publish Validated Draft Release\n", 1)[0]
        indented_script = step.split("        run: |\n", 1)[1]
        return "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in indented_script.splitlines()
        )

    def run_publish_script(
        self, remote_sequence: list[str], *, existing_public: str = "false"
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        state = self.root / "remote-state"
        log = self.root / "publish-command-order"
        state.write_text("0\n", encoding="utf-8")
        log.write_text("", encoding="utf-8")
        git = fake_bin / "git"
        git.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf 'git\\n' >> "${FAKE_LOG}"
call_index="$(<"${FAKE_STATE}")"
call_index=$((call_index + 1))
printf '%s\\n' "${call_index}" > "${FAKE_STATE}"
IFS=',' read -r -a resolutions <<< "${REMOTE_SEQUENCE}"
array_index=$((call_index - 1))
if (( array_index >= ${#resolutions[@]} )); then
  array_index=$((${#resolutions[@]} - 1))
fi
resolution="${resolutions[${array_index}]}"
case "${resolution}" in
  missing)
    exit 2
    ;;
  annotated)
    printf '%s\\trefs/tags/%s\\n' "1111111111111111111111111111111111111111" "${RELEASE_TAG}"
    printf '%s\\trefs/tags/%s^{}\\n' "${RELEASE_SHA}" "${RELEASE_TAG}"
    ;;
  *)
    printf '%s\\trefs/tags/%s\\n' "${resolution}" "${RELEASE_TAG}"
    ;;
esac
""",
            encoding="utf-8",
        )
        gh = fake_bin / "gh"
        gh.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf 'gh\\n' >> "${FAKE_LOG}"
[[ "$#" -eq 5 ]]
[[ "$1" == "release" && "$2" == "edit" ]]
[[ "$3" == "${RELEASE_TAG}" && "$4" == "--draft=false" && "$5" == "--latest" ]]
""",
            encoding="utf-8",
        )
        git.chmod(0o755)
        gh.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_LOG": str(log),
                "FAKE_STATE": str(state),
                "EXISTING_PUBLIC": existing_public,
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "RELEASE_SHA": "a" * 40,
                "RELEASE_TAG": self.tag,
                "REMOTE_SEQUENCE": ",".join(remote_sequence),
            }
        )
        result = subprocess.run(
            ["bash", "-c", self.publish_script()],
            cwd=Path(__file__).resolve().parents[2],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        command_order = (
            log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        )
        return result, command_order

    def test_release_publication_rechecks_remote_tag_immediately_around_edit(self) -> None:
        script = self.publish_script()
        pre = 'revalidate_remote_release_tag "pre-publication"'
        publish = 'gh release edit "${RELEASE_TAG}" --draft=false --latest'
        post = 'revalidate_remote_release_tag "post-publication"'
        self.assertEqual(script.count("git ls-remote --exit-code origin"), 1)
        self.assertEqual(script.count(pre), 1)
        self.assertEqual(script.count(post), 1)
        self.assertLess(script.index(pre), script.index(publish))
        self.assertLess(script.index(publish), script.index(post))
        self.assertLess(
            script.index('if [[ "${EXISTING_PUBLIC}" == "true" ]]'),
            script.index(pre),
        )

        success, command_order = self.run_publish_script(["annotated", "a" * 40])
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(command_order, ["git", "gh", "git"])

    def test_release_publication_fails_closed_on_pre_publication_tag_move(self) -> None:
        mismatch, command_order = self.run_publish_script(["b" * 40])
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(command_order, ["git"])
        self.assertIn("pre-publication", mismatch.stderr)
        self.assertIn("the draft remains private", mismatch.stderr)

    def test_release_publication_reports_post_publication_tag_move(self) -> None:
        mismatch, command_order = self.run_publish_script(["a" * 40, "b" * 40])
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(command_order, ["git", "gh", "git"])
        self.assertIn("the release was made public", mismatch.stderr)
        self.assertIn("expected " + "a" * 40, mismatch.stderr)

    def test_existing_public_release_revalidates_tag_without_mutation(self) -> None:
        success, command_order = self.run_publish_script(
            ["a" * 40], existing_public="true"
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(command_order, ["git"])
        self.assertIn("no publication mutation was attempted", success.stdout)

        mismatch, command_order = self.run_publish_script(
            ["b" * 40], existing_public="true"
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(command_order, ["git"])
        self.assertIn("the release was made public", mismatch.stderr)

    def test_ruleset_gate_fails_closed_before_api_when_privileged_secret_is_missing(
        self,
    ) -> None:
        fake_bin = self.root / "ruleset-fake-bin"
        fake_bin.mkdir()
        command_log = self.root / "ruleset-command-log"
        for command in ("gh", "git"):
            executable = fake_bin / command
            executable.write_text(
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$0" >> "${FAKE_LOG}"\n'
                "exit 99\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_LOG": str(command_log),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "RELEASE_SHA": "a" * 40,
                "RELEASE_TAG": self.tag,
                "RULESET_READ_TOKEN": "",
            }
        )
        result = subprocess.run(
            ["bash", "-c", self.ruleset_script()],
            cwd=Path(__file__).resolve().parents[2],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(command_log.exists())
        self.assertIn("SYSWARDEN_RULESET_READ_TOKEN must be", result.stderr)
        self.assertIn("Repository Administration: write", result.stderr)

    def test_release_workflow_binds_one_exact_pre_tag_qualification_run(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        coordinate = workflow.split("  coordinate-release:", 1)[1].split(
            "  dispatch-release:", 1
        )[0]
        dispatch = workflow.split("  dispatch-release:", 1)[1].split(
            "  validate-and-stage:", 1
        )[0]
        validate = workflow.split("  validate-and-stage:", 1)[1].split(
            "  attest-and-publish:", 1
        )[0]
        privileged = workflow.split("  attest-and-publish:", 1)[1]

        self.assertIn(
            "qualification_run_id:\n"
            "        description: Exact successful pre-tag release qualification workflow run ID\n"
            "        required: true\n"
            "        type: string",
            workflow,
        )
        self.assertIn(
            "qualification_run_id: ${{ steps.upstream.outputs.qualification_run_id }}",
            coordinate,
        )
        self.assertIn(
            "qualification_run_id: ${{ steps.upstream.outputs.qualification_run_id }}",
            validate,
        )
        self.assertIn(
            '--raw-field "qualification_run_id=${QUALIFICATION_RUN_ID}"', dispatch
        )
        self.assertIn(
            "QUALIFICATION_RUN_ID: ${{ needs.coordinate-release.outputs.qualification_run_id }}",
            dispatch,
        )
        self.assertIn(
            "REQUESTED_QUALIFICATION_RUN_ID: ${{ inputs.qualification_run_id }}",
            validate,
        )
        self.assertIn(
            '"${qualification_run_id}" != "${REQUESTED_QUALIFICATION_RUN_ID}"',
            validate,
        )
        self.assertIn(
            "QUALIFICATION_RUN_ID: ${{ needs.validate-and-stage.outputs.qualification_run_id }}",
            privileged,
        )
        self.assertIn(
            '"${QUALIFICATION_RUN_ID}" != "${REQUESTED_QUALIFICATION_RUN_ID}"',
            privileged,
        )

        for job in (coordinate, validate, privileged):
            self.assertIn(
                "actions/workflows/release-qualification.yml/runs", job
            )
            self.assertIn("gh api --paginate --slurp --method GET", job)
            self.assertIn('.head_branch == "main"', job)
            self.assertIn('.event == "workflow_dispatch"', job)
            self.assertIn('.status == "completed"', job)
            self.assertIn('.conclusion == "success"', job)
            self.assertIn(".run_attempt == 1", job)
            self.assertIn('.status != "completed"', job)
            self.assertIn('"${qualification_active_count}" -ne 0', job)
            self.assertIn(
                'select(.name == "syswarden-release-qualification")', job
            )
            self.assertIn(".[0].expired", job)
            self.assertIn(".[0].size_in_bytes", job)
            self.assertIn("qualification_artifact_id=", job)
            self.assertIn("-f per_page=100", job)
        self.assertIn(
            '.path == ".github/workflows/release-qualification.yml"', privileged
        )
        self.assertIn(
            "actions/artifacts/${qualification_artifact_id}", privileged
        )
        self.assertIn(".workflow_run.id == $run_id", privileged)
        self.assertNotIn("gh run watch", workflow)
        self.assertNotIn("sleep ", workflow)
        self.assertNotIn("--retry", workflow)

    def test_release_workflow_revalidates_original_qualification_before_release(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        validate = workflow.split("  validate-and-stage:", 1)[1].split(
            "  attest-and-publish:", 1
        )[0]
        privileged = workflow.split("  attest-and-publish:", 1)[1]

        self.assertEqual(
            workflow.count(
                "python3 scripts/ci/release_qualification_adapter.py verify"
            ),
            2,
        )
        self.assertEqual(
            workflow.count("python3 scripts/ci/release_qualification_gate.py verify"),
            2,
        )
        self.assertEqual(workflow.count("--max-age-seconds 172800"), 4)
        self.assertEqual(workflow.count("--max-report-skew-seconds 0"), 4)
        self.assertEqual(workflow.count("--require-tag"), 2)
        self.assertEqual(
            workflow.count("sha256sum --check --strict EVIDENCE_SHA256SUMS.txt"),
            2,
        )
        self.assertEqual(
            workflow.count(
                'gh run download "${qualification_run_id}" \\\n'
                "            --name syswarden-release-qualification"
            ),
            1,
        )
        self.assertEqual(
            workflow.count(
                'gh run download "${QUALIFICATION_RUN_ID}" \\\n'
                "            --name syswarden-release-qualification"
            ),
            1,
        )
        for section in (validate, privileged):
            self.assertIn("EVIDENCE_SHA256SUMS.txt qualification-context.json", section)
            self.assertIn("aggregate bound packages raw status", section)
            self.assertIn(
                "freebsd-vm-raw.json nftables-raw.json package-lifecycle-raw.json",
                section,
            )
            self.assertIn(
                "freebsd-vm-bound.json nftables-bound.json package-lifecycle-bound.json",
                section,
            )
            self.assertIn("qualification-exit-codes.json", section)
            self.assertIn("test -z \"$(find \"${QUALIFICATION_ROOT}\" -type l", section)
            self.assertIn("! -type f ! -type d -print -quit", section)
            self.assertIn(
                "aggregate bound packages packages/candidate packages/previous raw status",
                section,
            )
            self.assertIn('.repository == $repository', section)
            self.assertIn('.release_tag == $release_tag', section)
            self.assertIn('.release_sha == $release_sha', section)
            self.assertIn(
                '.previous_tag == $aggregate[0].bindings.previous_version', section
            )
            self.assertIn("all(.[]; . == 0)", section)
            self.assertLess(
                section.index("sed -E -n 's#^[0-9a-f]{64}"),
                section.index("sha256sum --check --strict EVIDENCE_SHA256SUMS.txt"),
            )
            self.assertIn('--candidate-packages-dir "${QUALIFICATION_ROOT}/packages/candidate"', section)
            self.assertIn('--previous-packages-dir "${QUALIFICATION_ROOT}/packages/previous"', section)
            self.assertIn('--nft-raw "${QUALIFICATION_ROOT}/raw/nftables-raw.json"', section)
            self.assertIn('--nft-envelope "${QUALIFICATION_ROOT}/bound/nftables-bound.json"', section)
            self.assertIn(
                '--aggregate "${QUALIFICATION_ROOT}/aggregate/release-qualification.json"',
                section,
            )
            self.assertIn(
                '"${QUALIFICATION_ROOT}/packages/candidate/${package_name}"', section
            )
            self.assertIn('for package_name in "${package_names[@]}"; do', section)
            self.assertNotIn("continue-on-error", section)
            self.assertNotIn("|| true", section)
            for package_template in (
                "syswarden_${VERSION}_amd64.deb",
                "syswarden_${VERSION}_arm64.deb",
                "syswarden-${VERSION}-1.x86_64.rpm",
                "syswarden-${VERSION}-1.aarch64.rpm",
                "syswarden_${VERSION}_x86_64.apk",
                "syswarden_${VERSION}_aarch64.apk",
                "syswarden-${VERSION}.txz",
                "SHA256SUMS.txt",
            ):
                self.assertIn(f'"{package_template}"', section)

        self.assertIn(
            '"incoming/syswarden-packages-${VERSION}/${package_name}"', validate
        )
        self.assertIn(
            '"release_payload/assets/${package_name}"', privileged
        )

        self.assertLess(
            validate.index("release_qualification_adapter.py verify"),
            validate.index("release_gate.py prepare"),
        )
        self.assertLess(
            validate.index(
                '"${QUALIFICATION_ROOT}/packages/candidate/${package_name}"'
            ),
            validate.index("release_gate.py prepare"),
        )
        self.assertLess(
            privileged.index("release_qualification_adapter.py verify"),
            privileged.index("actions/attest-build-provenance"),
        )
        self.assertLess(
            privileged.index(
                '"${QUALIFICATION_ROOT}/packages/candidate/${package_name}"'
            ),
            privileged.index("gh release create"),
        )
        self.assertIn(
            'QUALIFICATION_ROOT="${RUNNER_TEMP}/syswarden-release-qualification-stage"',
            validate,
        )
        self.assertIn(
            'QUALIFICATION_ROOT="${RUNNER_TEMP}/syswarden-release-qualification-privileged"',
            privileged,
        )
        validated_payload_upload = validate.split(
            "      - name: Upload Validated Release Payload", 1
        )[1]
        self.assertIn("path: release_payload/", validated_payload_upload)
        self.assertNotIn("path: ${RUNNER_TEMP}", validated_payload_upload)
        attestation_step = privileged.split(
            "      - name: Generate GitHub Build Provenance Attestations", 1
        )[1].split("      - name: Create Private Draft Release", 1)[0]
        self.assertIn("subject-path: release_payload/assets/*", attestation_step)
        self.assertNotIn("syswarden-release-qualification", attestation_step)
        release_creation = privileged.split(
            "      - name: Create Private Draft Release", 1
        )[1].split("      - name: Verify Private Draft Assets Before Publication", 1)[0]
        self.assertIn("release_payload/assets/*", release_creation)
        self.assertNotIn("syswarden-release-qualification", release_creation)

    def test_privileged_publisher_requires_a_protected_maintainer_environment(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("name: syswarden-release-production"),
            1,
        )
        self.assertIn(
            "Require Protected Maintainer Release Environment",
            workflow,
        )
        self.assertIn(
            'repos/${GITHUB_REPOSITORY}/environments/syswarden-release-production',
            workflow,
        )
        self.assertIn('.type == "required_reviewers"', workflow)
        self.assertIn('(.reviewers | length) > 0', workflow)
        privileged_job = workflow.split("  attest-and-publish:", 1)[1]
        self.assertIn("environment:\n      name: syswarden-release-production", privileged_job)

    def test_privileged_publisher_requires_exact_immutable_tag_ruleset(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-manager.yml"
        ).read_text(encoding="utf-8")
        privileged = workflow.split("  attest-and-publish:", 1)[1]
        gate_name = "Require Immutable Release Tag Ruleset Before Publication"
        publish_name = "Publish Validated Draft Release"
        self.assertEqual(privileged.count(gate_name), 1)
        self.assertLess(privileged.index(gate_name), privileged.index(publish_name))
        gate_header = privileged.split(f"      - name: {gate_name}\n", 1)[1].split(
            "        shell: bash\n", 1
        )[0]
        publish_header = privileged.split(f"      - name: {publish_name}\n", 1)[1].split(
            "        shell: bash\n", 1
        )[0]
        self.assertEqual(gate_header.strip(), "if: ${{ env.ACT != 'true' }}")
        self.assertEqual(publish_header.strip(), "if: ${{ env.ACT != 'true' }}")
        between = privileged.split(f"      - name: {gate_name}\n", 1)[1].split(
            f"      - name: {publish_name}\n", 1
        )[0]

        self.assertIn(
            'RULESET_READ_TOKEN: ${{ secrets.SYSWARDEN_RULESET_READ_TOKEN }}',
            between,
        )
        self.assertIn('if [[ -z "${RULESET_READ_TOKEN}" ]]', between)
        self.assertIn("GitHub App/fine-grained PAT credential", between)
        self.assertIn("Repository Administration: write", between)
        self.assertIn("used only for read-only GET requests", between)
        self.assertEqual(
            between.count('GH_TOKEN="${RULESET_READ_TOKEN}" gh api'),
            2,
        )
        self.assertEqual(between.count("RULESET_READ_TOKEN='' jq"), 4)
        self.assertEqual(between.count("unset RULESET_READ_TOKEN"), 1)
        self.assertLess(
            between.rindex('GH_TOKEN="${RULESET_READ_TOKEN}" gh api'),
            between.index("unset RULESET_READ_TOKEN"),
        )
        self.assertLess(
            between.index("unset RULESET_READ_TOKEN"),
            between.index("python3 scripts/ci/tag_ruleset_gate.py"),
        )
        self.assertNotIn('GH_TOKEN: ${{ github.token }}', between)
        self.assertIn('readonly ruleset_name="syswarden-release-tags-immutable"', between)
        self.assertIn("gh api --paginate --slurp --method GET", between)
        self.assertIn('"repos/${GITHUB_REPOSITORY}/rulesets"', between)
        self.assertIn("-f targets=tag", between)
        self.assertIn("-f per_page=100", between)
        self.assertIn('select(.name == $name)', between)
        self.assertIn('"${ruleset_count}" -ne 1', between)
        self.assertIn(
            '"repos/${GITHUB_REPOSITORY}/rulesets/${ruleset_id}"', between
        )
        self.assertIn("python3 scripts/ci/tag_ruleset_gate.py", between)
        self.assertIn('--expected-id "${ruleset_id}"', between)
        self.assertEqual(between.count("--method GET"), 2)
        self.assertNotIn("--method POST", between)
        self.assertNotIn("--method PUT", between)
        self.assertNotIn("--method PATCH", between)
        self.assertNotIn("--method DELETE", between)
        self.assertEqual(
            workflow.count("secrets.SYSWARDEN_RULESET_READ_TOKEN"),
            1,
        )
        self.assertNotIn(
            "SYSWARDEN_RULESET_READ_TOKEN",
            privileged.split(f"      - name: {gate_name}\n", 1)[0],
        )
        self.assertNotIn(
            "SYSWARDEN_RULESET_READ_TOKEN",
            privileged.split(f"      - name: {publish_name}\n", 1)[1],
        )
        self.assertNotIn('echo "${RULESET_READ_TOKEN}', between)
        self.assertNotIn('printf \'%s\' "${RULESET_READ_TOKEN}', between)

        validate_ruleset = "python3 scripts/ci/tag_ruleset_gate.py"
        revalidate_tag = "git ls-remote --exit-code origin"
        self.assertEqual(between.count(revalidate_tag), 1)
        self.assertLess(between.index(validate_ruleset), between.index(revalidate_tag))
        self.assertIn('"${resolved_sha}" != "${RELEASE_SHA}"', between)
        self.assertIn("release validation is blocked", between)
        self.assertIn(
            "Publication is blocked until the maintainer configures that external GitHub ruleset.",
            between,
        )

    def test_verify_rejects_missing_final_asset(self) -> None:
        output, _ = self.prepare()
        (output / release_gate.SBOM_NAME).unlink()
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.verify_assets(output, self.tag)


if __name__ == "__main__":
    unittest.main(verbosity=2)
