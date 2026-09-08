#!/usr/bin/env python3
"""Unit tests for the fail-closed release asset gate."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import release_gate
import release_qualification_adapter


REPOSITORY = Path(__file__).resolve().parents[2]
RELEASE_MANAGER_WORKFLOW = (
    REPOSITORY / ".github" / "workflows" / "release-manager.yml"
)
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


def workflow_step_scripts(workflow: str, step_name: str) -> list[str]:
    marker = f"      - name: {step_name}\n"
    scripts = []
    for remainder in workflow.split(marker)[1:]:
        step = remainder.split("\n      - name:", 1)[0]
        run_marker = "        run: |\n"
        if step.count(run_marker) != 1:
            raise AssertionError(f"expected one shell body for workflow step {step_name}")
        scripts.append(textwrap.dedent(step.split(run_marker, 1)[1]))
    if not scripts:
        raise AssertionError(f"workflow step {step_name} is missing")
    return scripts


def continued_shell_commands(script: str, needle: str) -> list[list[str]]:
    """Return tokenized shell commands, including their continued lines."""
    lines = script.splitlines()
    commands: list[list[str]] = []
    for start, line in enumerate(lines):
        if needle not in line:
            continue
        fragments: list[str] = []
        index = start
        while True:
            fragment = lines[index].strip()
            continued = fragment.endswith("\\")
            if continued:
                fragment = fragment[:-1].rstrip()
            fragments.append(fragment)
            if not continued:
                break
            index += 1
            if index >= len(lines):
                raise AssertionError(f"unterminated shell command containing {needle}")
        commands.append(shlex.split(" ".join(fragments)))
    return commands


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

    def plumber_report(self) -> dict[str, object]:
        return {
            "passed": True,
            "ciValid": True,
            "ciMissing": False,
            "minPoints": 100,
            "plumberScore": {
                "score": "A",
                "finalPoints": 100,
                "counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            },
        }

    def plumber_report_bytes(self) -> bytes:
        return (
            json.dumps(self.plumber_report(), sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")

    def make_compliance_archive(
        self,
        entries: list[tuple[str, bytes]],
        *,
        compression: int = zipfile.ZIP_DEFLATED,
    ) -> Path:
        archive = self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
        with zipfile.ZipFile(archive, "w", compression=compression) as output:
            for name, content in entries:
                output.writestr(name, content)
        return archive

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

    def make_historical_transition(
        self, name: str = "historical-transition"
    ) -> dict[str, object]:
        transition = self.root / name
        transition.mkdir()
        source_manifest = transition / "public-SHA256SUMS.txt"
        source_manifest.write_text(
            "".join(
                f"{digest}  {asset_name}\n"
                for asset_name, digest in (
                    release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS
                )
            ),
            encoding="utf-8",
        )
        metadata_records = [
            {
                "digest": expected["digest"],
                "id": expected["id"],
                "name": asset_name,
                "size": expected["size"],
                "state": "uploaded",
            }
            for asset_name, expected in sorted(
                release_gate.HISTORICAL_LINUX_TRANSITION_ASSETS.items()
            )
        ]
        metadata_records.append(
            {
                "digest": "sha256:" + "a" * 64,
                "id": 999999999,
                "name": "syswarden-release.tar.gz",
                "size": 1,
                "state": "uploaded",
            }
        )
        asset_metadata = transition / "public-release-assets.json"
        asset_metadata.write_text(
            json.dumps(metadata_records, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        packages = self.root / f"{name}-packages"
        packages.mkdir()
        for asset_name in release_gate.package_names(self.version):
            self.write_file(packages / asset_name, f"package:{asset_name}\n".encode())
        return {
            "asset_metadata": asset_metadata,
            "metadata_records": metadata_records,
            "output_manifest": packages / release_gate.PACKAGE_CHECKSUM_NAME,
            "packages": packages,
            "provenance_output": transition / "v4.02.8-linux-transition.json",
            "source_manifest": source_manifest,
        }

    def historical_sha256(self, packages: Path, mismatch: str | None = None):
        expected = dict(release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS)
        package_root = packages.absolute()

        def digest(path: Path) -> str:
            candidate = Path(path).absolute()
            if candidate.parent == package_root and candidate.name in expected:
                if candidate.name == mismatch:
                    return "0" * 64
                return expected[candidate.name]
            return hashlib.sha256(candidate.read_bytes()).hexdigest()

        return digest

    def normalize_historical_transition(
        self,
        fixture: dict[str, object],
        *,
        mismatch: str | None = None,
        **overrides: object,
    ) -> dict[str, object]:
        arguments = {
            "repository": release_gate.HISTORICAL_LINUX_TRANSITION_REPOSITORY,
            "release_id": release_gate.HISTORICAL_LINUX_TRANSITION_RELEASE_ID,
            "tag": release_gate.HISTORICAL_LINUX_TRANSITION_TAG,
            "source_manifest": fixture["source_manifest"],
            "asset_metadata": fixture["asset_metadata"],
            "packages": fixture["packages"],
            "output_manifest": fixture["output_manifest"],
            "provenance_output": fixture["provenance_output"],
        }
        arguments.update(overrides)
        with mock.patch(
            "release_gate.sha256",
            side_effect=self.historical_sha256(
                Path(arguments["packages"]), mismatch=mismatch
            ),
        ):
            return release_gate.normalize_v4028_linux_packages(**arguments)

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
        self.write_file(
            directory / release_gate.PLUMBER_REPORT_NAME,
            self.plumber_report_bytes(),
        )
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
            self.assertEqual(archive.namelist(), [release_gate.PLUMBER_REPORT_NAME])

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

    def test_v4100_release_requires_exact_deb_detached_signature_asset(self) -> None:
        self.assertFalse(release_gate.native_package_signatures_required("v4.04.2"))
        self.assertTrue(release_gate.native_package_signatures_required("v4.10.0"))
        self.assertTrue(release_gate.native_package_signatures_required("v5.00.0"))
        signature_name = "syswarden_4.10.0_amd64.deb.asc"
        self.assertNotIn(
            signature_name, release_gate.expected_release_assets("v4.04.2")
        )
        self.assertIn(signature_name, release_gate.expected_release_assets("v4.10.0"))
        signature = self.root / signature_name
        signature.write_bytes(
            b"-----BEGIN PGP SIGNATURE-----\nproof\n-----END PGP SIGNATURE-----\n"
        )
        release_gate.validate_deb_signature(signature)
        signature.write_bytes(
            b"-----BEGIN PGP SIGNATURE-----\nproof\n-----END PGP SIGNATURE-----\nextra\n"
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_deb_signature(signature)

    def test_v4100_release_requires_opt_in_rhel_package_owned_asset(self) -> None:
        self.assertFalse(release_gate.rhel_package_owned_required("v4.04.3"))
        self.assertTrue(release_gate.rhel_package_owned_required("v4.10.0"))
        self.assertTrue(release_gate.rhel_package_owned_required("v5.00.0"))
        package_name = "syswarden-4.10.0-1.rhelpo.x86_64.rpm"
        assets = release_gate.expected_release_assets("v4.10.0")
        self.assertEqual(len(assets), 12)
        self.assertIn(package_name, assets)
        package = self.root / package_name
        package.write_bytes(b"signed-rhel-package-owned-rpm\n")
        release_gate.validate_rhel_package_owned_rpm(package, "4.10.0")
        wrong = self.root / "syswarden-4.10.0-2.rhelpo.x86_64.rpm"
        wrong.write_bytes(b"wrong-release\n")
        with self.assertRaisesRegex(
            release_gate.ReleaseGateError, "filename is not canonical"
        ):
            release_gate.validate_rhel_package_owned_rpm(wrong, "4.10.0")

    def test_v4100_prepare_fails_before_staging_without_rhel_package_owned_rpm(
        self,
    ) -> None:
        self.tag = "v4.10.0"
        self.version = "4.10.0"
        signature = self.root / release_gate.deb_signature_name(self.version)
        signature.write_bytes(
            b"-----BEGIN PGP SIGNATURE-----\nproof\n-----END PGP SIGNATURE-----\n"
        )
        args = type(
            "Args",
            (),
            {
                "repository": self.make_repository(),
                "tag": self.tag,
                "packages": self.make_packages(),
                "bundle": self.root / "unused-bundle",
                "sbom": self.root / "unused-sbom",
                "compliance": self.root / "unused-compliance",
                "output": self.root / "output",
                "notes_output": self.root / "notes",
                "update_manifest_dir": None,
                "deb_signature": signature,
                "rhel_package_owned_rpm": None,
            },
        )()
        with self.assertRaisesRegex(
            release_gate.ReleaseGateError, "RHEL package-owned RPM is required"
        ):
            release_gate.prepare(args)
        self.assertFalse(args.output.exists())

    def test_v4100_prepare_fails_before_staging_without_deb_signature(self) -> None:
        self.tag = "v4.10.0"
        self.version = "4.10.0"
        args = type(
            "Args",
            (),
            {
                "repository": self.make_repository(),
                "tag": self.tag,
                "packages": self.make_packages(),
                "bundle": self.root / "unused-bundle",
                "sbom": self.root / "unused-sbom",
                "compliance": self.root / "unused-compliance",
                "output": self.root / "output",
                "notes_output": self.root / "notes",
                "update_manifest_dir": None,
                "deb_signature": None,
            },
        )()
        with self.assertRaisesRegex(
            release_gate.ReleaseGateError, "DEB detached signature is required"
        ):
            release_gate.prepare(args)
        self.assertFalse(args.output.exists())

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

    def test_github_signed_tag_object_is_exact_and_verified(self) -> None:
        tag_object_sha = "1" * 40
        commit_sha = "2" * 40
        document = {
            "tag": "v4.03.2",
            "sha": tag_object_sha,
            "message": "SysWarden v4.03.2",
            "tagger": {
                "name": "SysWarden Maintainer",
                "email": "maintainer@example.invalid",
                "date": "2026-08-25T12:00:00Z",
            },
            "object": {
                "type": "commit",
                "sha": commit_sha,
            },
            "verification": {
                "verified": True,
                "reason": "valid",
                "signature": "-----BEGIN SSH SIGNATURE-----\nproof\n",
                "payload": "object payload",
                "verified_at": "2026-08-25T12:00:01Z",
            },
        }
        path = self.root / "signed-tag.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        release_gate.verify_github_signed_tag_object(
            path, "v4.03.2", tag_object_sha, commit_sha
        )

        mutations = {
            "tag": lambda value: value.update(tag="v4.03.3"),
            "tag object": lambda value: value.update(sha="3" * 40),
            "commit": lambda value: value["object"].update(sha="4" * 40),
            "target type": lambda value: value["object"].update(type="tree"),
            "unsigned": lambda value: value["verification"].update(
                verified=False, reason="unsigned", signature=None
            ),
            "unverified": lambda value: value["verification"].update(
                verified=False, reason="unknown_key"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = json.loads(json.dumps(document))
                mutate(changed)
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.verify_github_signed_tag_object(
                        path, "v4.03.2", tag_object_sha, commit_sha
                    )

        with self.assertRaisesRegex(
            release_gate.ReleaseGateError, "annotated tag object"
        ):
            release_gate.verify_github_signed_tag_object(
                path, "v4.03.2", commit_sha, commit_sha
            )

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

    def test_historical_transition_derives_exact_private_linux_manifest(self) -> None:
        fixture = self.make_historical_transition()
        provenance = self.normalize_historical_transition(fixture)
        output_manifest = Path(fixture["output_manifest"])
        provenance_output = Path(fixture["provenance_output"])
        linux_names = release_gate.package_names(self.version)
        expected_records = dict(
            release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS
        )
        expected_manifest = "".join(
            f"{expected_records[name]}  {name}\n" for name in linux_names
        )

        self.assertEqual(output_manifest.read_text(encoding="utf-8"), expected_manifest)
        self.assertNotIn(RETIRED_PACKAGE_SUFFIX, expected_manifest)
        self.assertEqual(output_manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(provenance_output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            provenance["source_manifest"]["sha256"],
            release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_SHA256,
        )
        self.assertEqual(provenance["source_manifest"]["package_count"], 7)
        self.assertEqual(provenance["derived_linux_manifest"]["package_count"], 3)
        self.assertEqual(len(provenance["source_package_assets"]), 7)
        self.assertEqual(
            provenance["provenance_sha256"],
            hashlib.sha256(provenance_output.read_bytes()).hexdigest(),
        )
        persisted = json.loads(provenance_output.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["source_manifest"]["asset_digest"],
            "sha256:" + release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_SHA256,
        )

    def test_historical_transition_is_restricted_to_one_exact_release(self) -> None:
        fixture = self.make_historical_transition()
        for name, override in (
            ("repository", {"repository": "fork/syswarden"}),
            ("release id", {"release_id": 1}),
            ("older version", {"tag": "v4.02.7"}),
            ("newer version", {"tag": "v4.03.0"}),
        ):
            with self.subTest(name=name), self.assertRaises(
                release_gate.ReleaseGateError
            ):
                self.normalize_historical_transition(fixture, **override)
            self.assertFalse(Path(fixture["output_manifest"]).exists())
            self.assertFalse(Path(fixture["provenance_output"]).exists())

    def test_historical_transition_rejects_manifest_inventory_mutations(self) -> None:
        original_records = list(
            release_gate.HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS
        )
        mutations = {
            "missing": original_records[:-1],
            "duplicate": original_records + [original_records[0]],
            "extra": original_records + [("unexpected.deb", "a" * 64)],
            "wrong version": [
                (
                    asset_name.replace("4.02.8", "4.03.0", 1),
                    digest,
                )
                if index == 0
                else (asset_name, digest)
                for index, (asset_name, digest) in enumerate(original_records)
            ],
        }
        for name, records in mutations.items():
            with self.subTest(name=name):
                fixture = self.make_historical_transition(f"manifest-{name}")
                Path(fixture["source_manifest"]).write_text(
                    "".join(
                        f"{digest}  {asset_name}\n"
                        for asset_name, digest in records
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    self.normalize_historical_transition(fixture)
                self.assertFalse(Path(fixture["output_manifest"]).exists())
                self.assertFalse(Path(fixture["provenance_output"]).exists())

    def test_historical_transition_rejects_public_asset_metadata_mutations(self) -> None:
        for name in (
            "missing",
            "duplicate",
            "extra-version",
            "wrong-digest",
            "duplicate-id",
        ):
            with self.subTest(name=name):
                fixture = self.make_historical_transition(f"metadata-{name}")
                records = json.loads(json.dumps(fixture["metadata_records"]))
                retired_name = release_gate.HISTORICAL_RETIRED_PACKAGE_NAME
                retired_index = next(
                    index
                    for index, record in enumerate(records)
                    if record["name"] == retired_name
                )
                if name == "missing":
                    records.pop(retired_index)
                elif name == "duplicate":
                    duplicate = dict(records[retired_index])
                    duplicate["id"] = 999999998
                    records.append(duplicate)
                elif name == "extra-version":
                    records.append(
                        {
                            "digest": "sha256:" + "b" * 64,
                            "id": 999999997,
                            "name": "syswarden_4.03.0_amd64.deb",
                            "size": 1,
                            "state": "uploaded",
                        }
                    )
                elif name == "wrong-digest":
                    records[retired_index]["digest"] = "sha256:" + "c" * 64
                else:
                    records[-1]["id"] = records[retired_index]["id"]
                Path(fixture["asset_metadata"]).write_text(
                    json.dumps(records, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    self.normalize_historical_transition(fixture)
                self.assertFalse(Path(fixture["output_manifest"]).exists())
                self.assertFalse(Path(fixture["provenance_output"]).exists())

    def test_historical_transition_rejects_package_or_path_ambiguity(self) -> None:
        fixture = self.make_historical_transition()
        first_package = release_gate.package_names(self.version)[0]
        with self.assertRaises(release_gate.ReleaseGateError):
            self.normalize_historical_transition(fixture, mismatch=first_package)
        self.assertFalse(Path(fixture["output_manifest"]).exists())
        self.assertFalse(Path(fixture["provenance_output"]).exists())

        Path(fixture["provenance_output"]).symlink_to(fixture["source_manifest"])
        with self.assertRaises(release_gate.ReleaseGateError):
            self.normalize_historical_transition(fixture)
        self.assertFalse(Path(fixture["output_manifest"]).exists())

        Path(fixture["provenance_output"]).unlink()
        with self.assertRaises(release_gate.ReleaseGateError):
            self.normalize_historical_transition(
                fixture,
                provenance_output=Path(fixture["packages"]) / "provenance.json",
            )
        self.assertFalse(Path(fixture["output_manifest"]).exists())

    def test_historical_transition_cli_dispatches_the_exact_contract(self) -> None:
        fixture = self.make_historical_transition()
        returned = {
            "derived_linux_manifest": {"sha256": "b" * 64},
            "provenance_sha256": "c" * 64,
            "source_manifest": {"sha256": "a" * 64},
        }
        arguments = [
            "release_gate.py",
            "normalize-v4028-linux-packages",
            "--repository",
            release_gate.HISTORICAL_LINUX_TRANSITION_REPOSITORY,
            "--release-id",
            str(release_gate.HISTORICAL_LINUX_TRANSITION_RELEASE_ID),
            "--tag",
            release_gate.HISTORICAL_LINUX_TRANSITION_TAG,
            "--source-manifest",
            str(fixture["source_manifest"]),
            "--asset-metadata",
            str(fixture["asset_metadata"]),
            "--packages",
            str(fixture["packages"]),
            "--output-manifest",
            str(fixture["output_manifest"]),
            "--provenance-output",
            str(fixture["provenance_output"]),
        ]
        with mock.patch("sys.argv", arguments), mock.patch(
            "release_gate.normalize_v4028_linux_packages", return_value=returned
        ) as normalizer, mock.patch(
            "sys.stdout", new_callable=io.StringIO
        ) as output:
            self.assertEqual(release_gate.main(), 0)
        normalizer.assert_called_once()
        self.assertIn("source=" + "a" * 64, output.getvalue())
        self.assertIn("derived=" + "b" * 64, output.getvalue())
        self.assertIn("provenance=" + "c" * 64, output.getvalue())

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
        self.write_file(compliance / release_gate.PLUMBER_REPORT_NAME, b"")
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.write_compliance_archive(
                compliance, self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
            )

    def test_compliance_writer_validates_the_published_verdict(self) -> None:
        compliance = self.root / "compliance"
        report = self.plumber_report()
        report["passed"] = False
        self.write_file(
            compliance / release_gate.PLUMBER_REPORT_NAME,
            json.dumps(report).encode("utf-8"),
        )
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "passed"):
            release_gate.write_compliance_archive(
                compliance, self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
            )

    def test_compliance_archive_accepts_safe_companions_and_unknown_fields(self) -> None:
        report = self.plumber_report()
        report["futureRootField"] = {"enabled": True}
        score = report["plumberScore"]
        self.assertIsInstance(score, dict)
        score["futureScoreField"] = "preserved"
        counts = score["counts"]
        self.assertIsInstance(counts, dict)
        counts["informational"] = 7
        report_content = json.dumps(report).encode("utf-8")
        archive = self.make_compliance_archive(
            [
                ("native/", b""),
                (release_gate.PLUMBER_REPORT_NAME, report_content),
                ("native/pbom.json", b'{"version":1}\n'),
            ]
        )
        release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_requires_one_normalized_root_report(self) -> None:
        cases = (
            ("missing", [("pbom.json", b"{}\n")]),
            (
                "nested-only",
                [("native/plumber-report.json", self.plumber_report_bytes())],
            ),
            (
                "normalized-duplicate",
                [
                    (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                    ("./plumber-report.json", self.plumber_report_bytes()),
                ],
            ),
            (
                "root-plus-nested-report",
                [
                    (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                    ("native/plumber-report.json", self.plumber_report_bytes()),
                ],
            ),
            (
                "report-directory-file-conflict",
                [
                    ("plumber-report.json/", b""),
                    (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                ],
            ),
            (
                "directory-file-conflict",
                [
                    (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                    ("native/", b""),
                    ("native", b"companion\n"),
                ],
            ),
            (
                "normalized-duplicate-directory",
                [
                    (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                    ("native/", b""),
                    ("./native/", b""),
                ],
            ),
        )
        for label, entries in cases:
            with self.subTest(label=label):
                archive = self.make_compliance_archive(entries)
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_preserves_safe_path_and_nonempty_contracts(self) -> None:
        for unsafe_name in (
            "../escape.json",
            "/absolute.json",
            "./../escape.json",
            "..\\escape.json",
            "native\\..\\escape.json",
            "C:\\escape.json",
            "C:/escape.json",
        ):
            with self.subTest(unsafe_name=unsafe_name):
                archive = self.make_compliance_archive(
                    [
                        (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                        (unsafe_name, b"unsafe\n"),
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        archive = self.make_compliance_archive(
            [
                (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                ("empty-companion.json", b""),
            ]
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_rejects_non_regular_unix_entries(self) -> None:
        archive = self.root / release_gate.COMPLIANCE_ARCHIVE_NAME
        report_info = zipfile.ZipInfo(release_gate.PLUMBER_REPORT_NAME)
        report_info.create_system = 3
        report_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(report_info, self.plumber_report_bytes())
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_compliance_archive(archive)

        for label, member_type in (
            ("symlink", stat.S_IFLNK),
            ("fifo", stat.S_IFIFO),
            ("character-device", stat.S_IFCHR),
        ):
            with self.subTest(label=label):
                companion = zipfile.ZipInfo(f"native/{label}")
                companion.create_system = 3
                companion.external_attr = (member_type | 0o600) << 16
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr(
                        release_gate.PLUMBER_REPORT_NAME,
                        self.plumber_report_bytes(),
                    )
                    output.writestr(companion, b"special\n")
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_rejects_file_descendant_conflicts(self) -> None:
        conflict_pairs = (
            (
                ("native", b"file\n"),
                ("native/pbom.json", b"{}\n"),
            ),
            (
                (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                ("plumber-report.json/child", b"conflict\n"),
            ),
        )
        for pair in conflict_pairs:
            for reverse in (False, True):
                with self.subTest(pair=pair[0][0], reverse=reverse):
                    conflict_entries = list(reversed(pair)) if reverse else list(pair)
                    if not any(
                        name == release_gate.PLUMBER_REPORT_NAME
                        for name, _ in conflict_entries
                    ):
                        conflict_entries.insert(
                            0,
                            (
                                release_gate.PLUMBER_REPORT_NAME,
                                self.plumber_report_bytes(),
                            ),
                        )
                    archive = self.make_compliance_archive(conflict_entries)
                    with self.assertRaises(release_gate.ReleaseGateError):
                        release_gate.validate_compliance_archive(archive)

        mismatches = (
            ("native/", stat.S_IFREG),
            ("native", stat.S_IFDIR),
        )
        for name, member_type in mismatches:
            with self.subTest(name=name, member_type=member_type):
                companion = zipfile.ZipInfo(name)
                companion.create_system = 3
                companion.external_attr = (member_type | 0o700) << 16
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr(
                        release_gate.PLUMBER_REPORT_NAME,
                        self.plumber_report_bytes(),
                    )
                    output.writestr(companion, b"" if name.endswith("/") else b"file\n")
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_preserves_crc_validation(self) -> None:
        report_content = self.plumber_report_bytes()
        archive = self.make_compliance_archive(
            [(release_gate.PLUMBER_REPORT_NAME, report_content)],
            compression=zipfile.ZIP_STORED,
        )
        archive_content = bytearray(archive.read_bytes())
        payload_offset = archive_content.index(report_content)
        archive_content[payload_offset] ^= 1
        archive.write_bytes(archive_content)
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "CRC"):
            release_gate.validate_compliance_archive(archive)

    def test_compliance_report_has_a_bounded_uncompressed_size(self) -> None:
        report_content = self.plumber_report_bytes()
        exact_limit = report_content + b" " * (
            release_gate.PLUMBER_REPORT_MAX_UNCOMPRESSED_BYTES - len(report_content)
        )
        archive = self.make_compliance_archive(
            [(release_gate.PLUMBER_REPORT_NAME, exact_limit)]
        )
        release_gate.validate_compliance_archive(archive)

        over_limit = exact_limit + b" "
        archive = self.make_compliance_archive(
            [(release_gate.PLUMBER_REPORT_NAME, over_limit)]
        )
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "768-KiB"):
            release_gate.validate_compliance_archive(archive)

    def test_bound_plumber_report_matches_commit_and_exact_workflows(self) -> None:
        repository = self.root / "bound-repository"
        workflows = repository / ".github" / "workflows"
        self.write_file(workflows / "package.yml", b"name: Package\n")
        self.write_file(workflows / "security.yml", b"name: Security\n")
        expected_commit = "a" * 40
        report = self.plumber_report()
        report.update(
            {
                "headCommitSha": expected_commit,
                "dataCollectionDegraded": False,
                "degradedReasons": [],
                "warnings": [],
                "branchProtectionResult": {
                    "enabled": True,
                    "status": "passed",
                    "data": [
                        {
                            "branchName": "main",
                            "protectionDetailsKnown": True,
                        }
                    ],
                    "metrics": {
                        "branchesToProtect": 1,
                        "nonCompliantBranches": 0,
                        "projectsCorrectlyProtected": 1,
                    },
                },
                "analyzedCiConfig": {
                    "workflows": [
                        {
                            "path": ".github/workflows/package.yml",
                            "content": "name: Package\n",
                        },
                        {
                            "path": ".github/workflows/security.yml",
                            "content": "name: Security\n",
                        },
                    ]
                },
            }
        )

        def validate(document: dict[str, object]) -> None:
            content = (
                json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            archive = self.make_compliance_archive(
                [(release_gate.PLUMBER_REPORT_NAME, content)]
            )
            release_gate.validate_compliance_archive(
                archive,
                repository=repository,
                expected_commit=expected_commit,
            )

        validate(report)
        omitted_healthy_fields = json.loads(json.dumps(report))
        for field in ("dataCollectionDegraded", "degradedReasons", "warnings"):
            omitted_healthy_fields.pop(field)
        validate(omitted_healthy_fields)
        mutations = {
            "wrong commit": lambda value: value.update(headCommitSha="b" * 40),
            "degraded": lambda value: value.update(dataCollectionDegraded=True),
            "degraded reason": lambda value: value.update(
                degradedReasons=["metadata unavailable"]
            ),
            "warning": lambda value: value.update(warnings=["warning"]),
            "partial control": lambda value: value.update(
                partialControls=[{"control": "branchMustBeProtected"}]
            ),
            "branch status": lambda value: value["branchProtectionResult"].update(
                status="error"
            ),
            "branch control disabled": lambda value: value[
                "branchProtectionResult"
            ].update(enabled=False),
            "unknown protection details": lambda value: value[
                "branchProtectionResult"
            ]["data"][0].update(protectionDetailsKnown=False),
            "noncompliant branch": lambda value: value[
                "branchProtectionResult"
            ]["metrics"].update(nonCompliantBranches=1),
            "no protected project": lambda value: value[
                "branchProtectionResult"
            ]["metrics"].update(projectsCorrectlyProtected=0),
            "invalid metric type": lambda value: value[
                "branchProtectionResult"
            ]["metrics"].update(branchesToProtect=True),
            "changed workflow": lambda value: value["analyzedCiConfig"][
                "workflows"
            ][0].update(content="name: Changed\n"),
            "unexpected workflow path": lambda value: value[
                "analyzedCiConfig"
            ]["workflows"][0].update(path="package.yml"),
            "duplicate workflow": lambda value: value["analyzedCiConfig"][
                "workflows"
            ][1].update(path=".github/workflows/package.yml"),
            "missing workflow": lambda value: value["analyzedCiConfig"][
                "workflows"
            ].pop(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = json.loads(json.dumps(report))
                mutate(changed)
                with self.assertRaises(release_gate.ReleaseGateError):
                    validate(changed)

    def test_compliance_archive_accepts_only_bounded_aggregate_size(self) -> None:
        report = self.plumber_report_bytes()
        companion_size = (
            release_gate.COMPLIANCE_ARCHIVE_MAX_UNCOMPRESSED_BYTES - len(report)
        )
        archive = self.make_compliance_archive(
            [
                (release_gate.PLUMBER_REPORT_NAME, report),
                ("native/companion.bin", b"A" * companion_size),
            ]
        )
        release_gate.validate_compliance_archive(archive)

        archive = self.make_compliance_archive(
            [
                (release_gate.PLUMBER_REPORT_NAME, report),
                ("native/companion.bin", b"A" * (companion_size + 1)),
            ]
        )
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "aggregate"):
            release_gate.validate_compliance_archive(archive)

    def test_compliance_archive_bounds_companion_expansion_and_member_count(
        self,
    ) -> None:
        oversized_companion = b"A" * release_gate.COMPLIANCE_ARCHIVE_MAX_UNCOMPRESSED_BYTES
        archive = self.make_compliance_archive(
            [
                (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes()),
                ("native/oversized.txt", oversized_companion),
            ]
        )
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "aggregate"):
            release_gate.validate_compliance_archive(archive)

        entries = [
            (release_gate.PLUMBER_REPORT_NAME, self.plumber_report_bytes())
        ]
        entries.extend(
            (f"native/companion-{index}.txt", b"evidence\n")
            for index in range(release_gate.COMPLIANCE_ARCHIVE_MAX_MEMBERS)
        )
        archive = self.make_compliance_archive(entries)
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "128-entry"):
            release_gate.validate_compliance_archive(archive)

    def test_compliance_report_requires_strict_utf8_and_json(self) -> None:
        valid = self.plumber_report_bytes()
        malformed_reports = (
            ("invalid-utf8", valid + b"\xff"),
            ("trailing-json", valid + b"{}"),
            ("array-root", b"[]"),
            (
                "duplicate-key",
                valid.replace(b'"passed":true', b'"passed":true,"passed":true'),
            ),
            (
                "nested-duplicate-key",
                valid.replace(b'"critical":0', b'"critical":0,"critical":0'),
            ),
            (
                "nan",
                valid.replace(b'"finalPoints":100', b'"finalPoints":NaN'),
            ),
            (
                "infinity",
                valid.replace(b'"finalPoints":100', b'"finalPoints":Infinity'),
            ),
            (
                "negative-infinity",
                valid.replace(b'"finalPoints":100', b'"finalPoints":-Infinity'),
            ),
            (
                "overflowing-number",
                valid.replace(b'"finalPoints":100', b'"finalPoints":1e9999'),
            ),
        )
        for label, content in malformed_reports:
            with self.subTest(label=label):
                archive = self.make_compliance_archive(
                    [(release_gate.PLUMBER_REPORT_NAME, content)]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

    def test_compliance_report_requires_exact_boolean_verdicts(self) -> None:
        cases = (
            ("passed", False),
            ("passed", 1),
            ("passed", "true"),
            ("ciValid", False),
            ("ciValid", 1),
            ("ciValid", "true"),
            ("ciMissing", True),
            ("ciMissing", 0),
            ("ciMissing", "false"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                report = self.plumber_report()
                report[field] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        for field in ("passed", "ciValid", "ciMissing"):
            with self.subTest(field=field, value="missing"):
                report = self.plumber_report()
                report.pop(field)
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

    def test_compliance_report_proves_the_strict_points_gate(self) -> None:
        for value in (True, "100", 99, -100, None):
            with self.subTest(field="minPoints", value=value):
                report = self.plumber_report()
                report["minPoints"] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        report.pop("minPoints")
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_compliance_archive(archive)

        for value in (False, 0, 80, "null"):
            with self.subTest(field="threshold", value=value):
                report = self.plumber_report()
                report["threshold"] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        self.assertNotIn("threshold", report)
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        report["minPoints"] = 100.0
        report["threshold"] = None
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        release_gate.validate_compliance_archive(archive)

    def test_compliance_report_rejects_points_that_round_to_binary_100(self) -> None:
        valid = self.plumber_report_bytes()
        for field, exact_token in (
            ("minPoints", b'"minPoints":100'),
            ("finalPoints", b'"finalPoints":100'),
        ):
            for value in (
                b"99.999999999999999999999",
                b"100.000000000000000000001",
            ):
                with self.subTest(field=field, value=value.decode("ascii")):
                    mutated = valid.replace(
                        exact_token,
                        exact_token.split(b":", 1)[0] + b":" + value,
                    )
                    archive = self.make_compliance_archive(
                        [(release_gate.PLUMBER_REPORT_NAME, mutated)]
                    )
                    with self.assertRaises(release_gate.ReleaseGateError):
                        release_gate.validate_compliance_archive(archive)

    def test_compliance_report_requires_exact_a_100_score(self) -> None:
        for field, value in (
            ("score", "B"),
            ("score", True),
            ("finalPoints", True),
            ("finalPoints", "100"),
            ("finalPoints", 99),
            ("finalPoints", -100),
            ("finalPoints", 10**400),
        ):
            with self.subTest(field=field, value=value):
                report = self.plumber_report()
                score = report["plumberScore"]
                self.assertIsInstance(score, dict)
                score[field] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        for field in ("score", "finalPoints"):
            with self.subTest(field=field, value="missing"):
                report = self.plumber_report()
                score = report["plumberScore"]
                self.assertIsInstance(score, dict)
                score.pop(field)
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        score = report["plumberScore"]
        self.assertIsInstance(score, dict)
        score["finalPoints"] = 100.0
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        release_gate.validate_compliance_archive(archive)

    def test_compliance_report_requires_score_and_counts_objects(self) -> None:
        for value in (None, [], "A"):
            with self.subTest(field="plumberScore", value=value):
                report = self.plumber_report()
                report["plumberScore"] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        report.pop("plumberScore")
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_compliance_archive(archive)

        for value in (None, [], 0):
            with self.subTest(field="counts", value=value):
                report = self.plumber_report()
                score = report["plumberScore"]
                self.assertIsInstance(score, dict)
                score["counts"] = value
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_compliance_archive(archive)

        report = self.plumber_report()
        score = report["plumberScore"]
        self.assertIsInstance(score, dict)
        score.pop("counts")
        archive = self.make_compliance_archive(
            [
                (
                    release_gate.PLUMBER_REPORT_NAME,
                    json.dumps(report).encode("utf-8"),
                )
            ]
        )
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_compliance_archive(archive)

    def test_compliance_report_requires_zero_integer_severity_counts(self) -> None:
        severities = ("critical", "high", "medium", "low")
        for severity in severities:
            for value in (False, 0.0, "0", 1, -1):
                with self.subTest(severity=severity, value=value):
                    report = self.plumber_report()
                    score = report["plumberScore"]
                    self.assertIsInstance(score, dict)
                    counts = score["counts"]
                    self.assertIsInstance(counts, dict)
                    counts[severity] = value
                    archive = self.make_compliance_archive(
                        [
                            (
                                release_gate.PLUMBER_REPORT_NAME,
                                json.dumps(report).encode("utf-8"),
                            )
                        ]
                    )
                    with self.assertRaises(release_gate.ReleaseGateError):
                        release_gate.validate_compliance_archive(archive)

            with self.subTest(severity=severity, value="missing"):
                report = self.plumber_report()
                score = report["plumberScore"]
                self.assertIsInstance(score, dict)
                counts = score["counts"]
                self.assertIsInstance(counts, dict)
                counts.pop(severity)
                archive = self.make_compliance_archive(
                    [
                        (
                            release_gate.PLUMBER_REPORT_NAME,
                            json.dumps(report).encode("utf-8"),
                        )
                    ]
                )
                with self.assertRaises(release_gate.ReleaseGateError):
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

    def test_workflow_uses_portable_byte_exact_release_inventory_comparisons(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        comparisons = (
            (
                "release_payload/assets/RELEASE_SHA256SUMS.txt",
                "existing_release_assets/RELEASE_SHA256SUMS.txt",
            ),
            (
                "release_payload/assets/RELEASE_SHA256SUMS.txt",
                "draft_release_assets/RELEASE_SHA256SUMS.txt",
            ),
            (
                "release_payload/assets/RELEASE_SHA256SUMS.txt",
                "published_release_assets/RELEASE_SHA256SUMS.txt",
            ),
        )

        self.assertNotIn("diff --no-index", workflow)
        for expected, actual in comparisons:
            comparison = (
                "cmp --silent \\\n"
                f"            {expected} \\\n"
                f"            {actual}"
            )
            self.assertEqual(workflow.count(comparison), 1, actual)

    def assert_generic_release_validation_contract(self, workflow: str) -> None:
        scripts = workflow_step_scripts(
            workflow, "Validate Tag, Source, Changelog, and Main Ancestry"
        )
        self.assertEqual(len(scripts), 2)
        self.assertEqual(scripts[0], scripts[1])
        self.assertEqual(
            workflow.count("./scripts/versioning.sh validate-release"), 2
        )
        self.assertNotIn("./scripts/versioning.sh validate-commit", workflow)
        self.assertNotIn("./scripts/versioning.sh validate-tag", workflow)

        expected_release_lines = [
            "./scripts/versioning.sh validate-release " + chr(92),
            '  --repo "${GITHUB_WORKSPACE}" ' + chr(92),
            '  --tag "${RELEASE_TAG}"',
        ]
        ordered_fragments = (
            'test "$(git rev-parse HEAD)" = "${RELEASE_SHA}"',
            'TAG_SHA="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"',
            'if [[ "${TAG_SHA}" != "${RELEASE_SHA}" ]]; then',
            'if ! git merge-base --is-ancestor "${RELEASE_SHA}" origin/main; then',
            "(cd scripts/versionctl && GOWORK=off go test ./...)",
            "./scripts/versioning.sh validate-release",
            "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover",
            "GOFLAGS=-mod=readonly go test",
        )
        historical_markers = (
            "validate-commit",
            "validate-tag",
            "v4033",
            "v4032",
            "v4.03.3",
            "v4.03.2",
            "v4.03.0",
        )

        for script in scripts:
            for fragment in ordered_fragments:
                self.assertEqual(script.count(fragment), 1, fragment)
            release_start = script.index(
                "./scripts/versioning.sh validate-release"
            )
            release_end = script.index(
                "\nPYTHONDONTWRITEBYTECODE=1", release_start
            )
            self.assertEqual(
                script[release_start:release_end].splitlines(),
                expected_release_lines,
            )
            positions = [script.index(fragment) for fragment in ordered_fragments]
            self.assertEqual(positions, sorted(positions))
            self.assertIn("-p 'release_gate_test.py'", script)
            self.assertIn("./scripts/ci/update_manifest.go", script)
            self.assertIn("./scripts/ci/update_manifest_test.go", script)
            for marker in historical_markers:
                self.assertNotIn(marker, script)

    def test_release_manager_uses_two_exact_generic_release_validations(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        self.assert_generic_release_validation_contract(workflow)

    def test_release_manager_binds_every_full_plumber_verification_to_commit(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        binding = '            --expected-plumber-commit "${RELEASE_SHA}" '
        self.assertEqual(workflow.count(binding + chr(92)), 5)
        assemble = workflow_step_script(
            workflow, "Validate and Assemble Exact Release Inventory"
        )
        self.assertIn(
            '--expected-plumber-commit "${RELEASE_SHA}" ' + chr(92),
            assemble,
        )

    def test_release_manager_generic_release_validation_rejects_mutations(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        invocation = "\n".join(
            (
                "          ./scripts/versioning.sh validate-release " + chr(92),
                '            --repo "${GITHUB_WORKSPACE}" ' + chr(92),
                '            --tag "${RELEASE_TAG}"',
            )
        )
        self.assertEqual(workflow.count(invocation), 2)
        mutations = {
            "missing invocation": workflow.replace(invocation, "", 1),
            "duplicate invocation": workflow.replace(
                invocation, invocation + "\n" + invocation, 1
            ),
            "command": workflow.replace(
                "./scripts/versioning.sh validate-release",
                "./scripts/versioning.sh validate-commit",
                1,
            ),
            "repository": workflow.replace(
                '            --repo "${GITHUB_WORKSPACE}" ',
                '            --repo "." ',
                1,
            ),
            "tag": workflow.replace(
                '            --tag "${RELEASE_TAG}"',
                '            --tag "v4.03.3"',
                1,
            ),
            "HEAD binding": workflow.replace(
                '          test "$(git rev-parse HEAD)" = "${RELEASE_SHA}"',
                '          test "$(git rev-parse HEAD^)" = "${RELEASE_SHA}"',
                1,
            ),
            "tag peel": workflow.replace(
                '"refs/tags/${RELEASE_TAG}^{commit}"',
                '"refs/tags/${RELEASE_TAG}"',
                1,
            ),
            "main ancestry": workflow.replace(
                'git merge-base --is-ancestor "${RELEASE_SHA}" origin/main',
                'git merge-base --is-ancestor "${RELEASE_SHA}" HEAD^',
                1,
            ),
            "versionctl test": workflow.replace(
                "(cd scripts/versionctl && GOWORK=off go test ./...)",
                "(cd scripts/versionctl && go test ./...)",
                1,
            ),
            "release gate test": workflow.replace(
                "-p 'release_gate_test.py'",
                "-p 'release_gate.py'",
                1,
            ),
            "update manifest test": workflow.replace(
                "./scripts/ci/update_manifest_test.go",
                "./scripts/ci/update_manifest.go",
                1,
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutation, workflow)
                with self.assertRaises(AssertionError):
                    self.assert_generic_release_validation_contract(mutation)

    def test_qualification_signer_compiles_before_protected_secret_exposure(self) -> None:
        qualification = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "release-qualification.yml"
        ).read_text(encoding="utf-8")
        candidate = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "candidate-update-bundle.yml"
        ).read_text(encoding="utf-8")
        build = candidate.split(
            "      - name: Build and Test Candidate Manifest Tool\n", 1
        )[1].split("      - name:", 1)[0]
        revalidate = candidate.split(
            "      - name: Revalidate Candidate Manifest Tool Before Secret Exposure\n", 1
        )[1].split("      - name:", 1)[0]
        signer = candidate.split(
            "      - name: Generate and Verify Protected Candidate Manifest\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn("GOFLAGS=-mod=readonly go build", build)
        self.assertIn("update_manifest_test.go", build)
        self.assertIn('"${MANIFEST_TOOL_DIR}/syswarden-update-manifest"', build)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", build)
        self.assertIn("EXPECTED_TOOL_SHA256", revalidate)
        self.assertIn("actual_tool_sha256", revalidate)
        self.assertNotIn("SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", revalidate)
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
            candidate.count("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"), 1
        )
        self.assertEqual(
            qualification.count("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"), 0
        )
        self.assertIn("Reuse and Verify Exact Candidate Update Manifest", qualification)
        reuse = qualification.split(
            "      - name: Reuse and Verify Exact Candidate Update Manifest\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertEqual(reuse.count("cmp --"), 2)
        self.assertIn("env -u SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", reuse)
        self.assertNotIn(" generate ", reuse)
        self.assertIn('"update/syswarden-update-manifest-v1.json"', qualification)
        self.assertIn('"update/syswarden-update-manifest-v1.json.sig"', qualification)
        self.assertLess(
            candidate.index("Build and Test Candidate Manifest Tool"),
            candidate.index("Revalidate Candidate Manifest Tool Before Secret Exposure"),
        )
        self.assertLess(
            candidate.index("Revalidate Candidate Manifest Tool Before Secret Exposure"),
            candidate.index("Generate and Verify Protected Candidate Manifest"),
        )
        self.assertLess(
            candidate.index("Generate and Verify Protected Candidate Manifest"),
            candidate.index("Attest Candidate Bundle Descriptor"),
        )
        self.assertLess(
            qualification.index("Require Successful Qualification Before Release Signing"),
            qualification.index("Revalidate Attested Candidate Update Before Final Seal"),
        )
        self.assertLess(
            qualification.index("Revalidate Attested Candidate Update Before Final Seal"),
            qualification.index("Reuse and Verify Exact Candidate Update Manifest"),
        )
        self.assertLess(
            qualification.index("Reuse and Verify Exact Candidate Update Manifest"),
            qualification.index("Seal Exact Qualification Evidence Inventory"),
        )
        self.assertIn("qualification status ${failed_status}", qualification)
        self.assertIn(
            "refusing to sign because qualification status is not uniformly zero",
            qualification,
        )
        self.assertIn('rm -f -- "${manifest_path}" "${signature_path}"', signer)
        self.assertIn(
            '"${update_dir}/syswarden-update-manifest-v1.json.sig"', qualification
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
        self.assertNotIn(RETIRED_PLATFORM, workflow.lower())
        self.assertNotIn(RETIRED_PACKAGE_SUFFIX, workflow)
        self.assertEqual(workflow.count('--repository "${GITHUB_WORKSPACE}"'), 7)
        self.assertNotIn('if [[ "${RELEASE_TAG}" != "v4.02.8" ]]', workflow)
        self.assertEqual(workflow.count("requires-signed-update --tag"), 3)
        self.assertEqual(workflow.count('if [[ "${SIGNED_UPDATE_REQUIRED}" == "true" ]]'), 6)
        self.assertIn("--update-manifest-dir", workflow)
        self.assertIn("Set Up Go for Signed Update Verification", workflow)
        self.assertNotIn("secrets.SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY", workflow)
        for candidate_path in (
            '"${QUALIFICATION_ROOT}/native-release-evidence/candidate-update/node01/syswarden-update-manifest-v1.json"',
            '"${QUALIFICATION_ROOT}/native-release-evidence/candidate-update/node01/syswarden-update-manifest-v1.json.sig"',
        ):
            self.assertEqual(workflow.count(candidate_path), 2)
        for candidate_directory in (
            "native-release-evidence/candidate-update",
            "native-release-evidence/candidate-update/node01",
            "native-release-evidence/candidate-update/verification",
        ):
            self.assertEqual(
                len(
                    re.findall(
                        rf"(?<![/A-Za-z0-9_.-]){re.escape(candidate_directory)}(?=[ )\n])",
                        workflow,
                    )
                ),
                2,
            )
        self.assertEqual(
            workflow.count(
                "([.previous_package_asset_ids[].name] | sort) == (["
            ),
            2,
        )
        for exact_name in (
            '("syswarden-" + (.previous_tag | ltrimstr("v")) + "-1.x86_64.rpm")',
            '("syswarden_" + (.previous_tag | ltrimstr("v")) + "_amd64.deb")',
            '("syswarden_" + (.previous_tag | ltrimstr("v")) + "_x86_64.apk")',
        ):
            self.assertEqual(workflow.count(exact_name), 2)

    def test_privileged_publisher_requires_a_verified_signed_annotated_tag(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        script = workflow_step_script(
            workflow, "Verify Signed Annotated Release Tag"
        )
        self.assertIn(
            'tag_object_sha="$(git rev-parse "refs/tags/${RELEASE_TAG}")"',
            script,
        )
        self.assertIn(
            'tag_commit_sha="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"',
            script,
        )
        self.assertIn('"${tag_object_sha}" == "${tag_commit_sha}"', script)
        self.assertIn('"${tag_commit_sha}" != "${RELEASE_SHA}"', script)
        self.assertIn("git ls-remote --exit-code origin", script)
        self.assertIn(
            '"repos/${GITHUB_REPOSITORY}/git/tags/${tag_object_sha}"',
            script,
        )
        self.assertIn("verify-github-signed-tag", script)
        self.assertIn('--expected-tag "${RELEASE_TAG}"', script)
        self.assertIn('--expected-tag-object-sha "${tag_object_sha}"', script)
        self.assertIn('--expected-commit-sha "${RELEASE_SHA}"', script)
        self.assertLess(
            workflow.index("Verify Signed Annotated Release Tag"),
            workflow.index("Generate GitHub Build Provenance Attestations"),
        )
        self.assertLess(
            workflow.index("Verify Signed Annotated Release Tag"),
            workflow.index("Create Private Draft Release"),
        )

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
        self,
        remote_sequence: list[str],
        *,
        existing_public: str = "false",
        draft_metadata: dict[str, object] | None = None,
        expected_draft_metadata: dict[str, object] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        valid_draft: dict[str, object] = {
            "id": 4242,
            "tag_name": self.tag,
            "name": self.tag,
            "draft": True,
            "prerelease": False,
            "body": "exact release notes\n",
            "assets": [
                {
                    "id": 9001,
                    "name": "release-asset.bin",
                    "size": 9,
                    "digest": "sha256:" + "b" * 64,
                    "state": "uploaded",
                }
            ],
        }
        served_draft = draft_metadata or valid_draft
        expected_draft = expected_draft_metadata or valid_draft
        canonical_snapshot = {
            key: expected_draft[key]
            for key in ("id", "tag_name", "name", "draft", "prerelease", "body")
        }
        expected_assets = expected_draft["assets"]
        self.assertIsInstance(expected_assets, list)
        canonical_snapshot["assets"] = sorted(
            (
                {
                    key: asset[key]
                    for key in ("id", "name", "size", "digest", "state")
                }
                for asset in expected_assets
                if isinstance(asset, dict)
            ),
            key=lambda asset: str(asset["name"]),
        )
        snapshot_sha256 = hashlib.sha256(
            (
                json.dumps(
                    canonical_snapshot,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest()
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
if [[ "$#" -eq 4 && "$1" == "api" && "$2" == "--method" && "$3" == "GET" ]]; then
  [[ "$4" == "repos/${GITHUB_REPOSITORY}/releases/tags/${RELEASE_TAG}" ]]
  printf 'gh-get\\n' >> "${FAKE_LOG}"
  printf '%s\\n' "${TEST_DRAFT_METADATA:?}"
  exit 0
fi
if [[ "$#" -eq 6 && "$1" == "api" && "$2" == "--method" && "$3" == "PATCH" ]]; then
  [[ "$4" == "repos/${GITHUB_REPOSITORY}/releases/${EXPECTED_DRAFT_RELEASE_ID}" ]]
  [[ "$5" == "--input" && "$6" == "-" ]]
  payload="$(cat)"
  jq -e '. == {draft:false, make_latest:"true"}' <<< "${payload}" >/dev/null
  printf 'gh-publish\\n' >> "${FAKE_LOG}"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 64
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
                "EXPECTED_DRAFT_RELEASE_ID": str(expected_draft["id"]),
                "EXPECTED_DRAFT_SNAPSHOT_SHA256": snapshot_sha256,
                "GITHUB_REPOSITORY": "duggytuxy/syswarden",
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "RELEASE_SHA": "a" * 40,
                "RELEASE_TAG": self.tag,
                "REMOTE_SEQUENCE": ",".join(remote_sequence),
                "TEST_DRAFT_METADATA": json.dumps(
                    served_draft, separators=(",", ":")
                ),
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
        draft = "revalidate_exact_draft_snapshot"
        publish = 'gh api --method PATCH \\'
        post = 'revalidate_remote_release_tag "post-publication"'
        self.assertEqual(script.count("git ls-remote --exit-code origin"), 1)
        self.assertEqual(script.count(pre), 1)
        self.assertEqual(script.count(post), 1)
        self.assertEqual(script.count(draft), 2)
        self.assertLess(script.index(pre), script.rindex(draft))
        self.assertLess(script.rindex(draft), script.index(publish))
        self.assertLess(script.index(publish), script.index(post))
        self.assertLess(
            script.index('if [[ "${EXISTING_PUBLIC}" == "true" ]]'),
            script.index(pre),
        )

        success, command_order = self.run_publish_script(["annotated", "a" * 40])
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(command_order, ["git", "gh-get", "gh-publish", "git"])

    def test_release_publication_fails_closed_on_pre_publication_tag_move(self) -> None:
        mismatch, command_order = self.run_publish_script(["b" * 40])
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(command_order, ["git"])
        self.assertIn("pre-publication", mismatch.stderr)
        self.assertIn("the draft remains private", mismatch.stderr)

    def test_release_publication_reports_post_publication_tag_move(self) -> None:
        mismatch, command_order = self.run_publish_script(["a" * 40, "b" * 40])
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertEqual(command_order, ["git", "gh-get", "gh-publish", "git"])
        self.assertIn("the release was made public", mismatch.stderr)
        self.assertIn("expected " + "a" * 40, mismatch.stderr)

    def test_release_publication_fails_closed_on_draft_snapshot_change(self) -> None:
        base: dict[str, object] = {
            "id": 4242,
            "tag_name": self.tag,
            "name": self.tag,
            "draft": True,
            "prerelease": False,
            "body": "exact release notes\n",
            "assets": [
                {
                    "id": 9001,
                    "name": "release-asset.bin",
                    "size": 9,
                    "digest": "sha256:" + "b" * 64,
                    "state": "uploaded",
                }
            ],
        }
        mutations: list[tuple[str, dict[str, object]]] = []
        for field, value in (
            ("id", 4243),
            ("tag_name", "v4.02.9"),
            ("name", "changed-title"),
            ("draft", False),
            ("prerelease", True),
            ("body", "changed notes\n"),
        ):
            changed = json.loads(json.dumps(base))
            changed[field] = value
            mutations.append((field, changed))
        for field, value in (
            ("id", 9002),
            ("name", "replacement.bin"),
            ("size", 10),
            ("digest", "sha256:" + "c" * 64),
            ("state", "new"),
        ):
            changed = json.loads(json.dumps(base))
            assets = changed["assets"]
            self.assertIsInstance(assets, list)
            self.assertIsInstance(assets[0], dict)
            assets[0][field] = value
            mutations.append((f"asset {field}", changed))
        changed = json.loads(json.dumps(base))
        assets = changed["assets"]
        self.assertIsInstance(assets, list)
        assets.append(
            {
                "id": 9002,
                "name": "extra.bin",
                "size": 1,
                "digest": "sha256:" + "c" * 64,
                "state": "uploaded",
            }
        )
        mutations.append(("asset count", changed))

        for name, changed in mutations:
            with self.subTest(mutation=name):
                result, command_order = self.run_publish_script(
                    ["a" * 40],
                    draft_metadata=changed,
                    expected_draft_metadata=base,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(command_order, ["git", "gh-get"])
                self.assertIn("refusing publication", result.stderr)

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
        self.assertEqual(workflow.count("--slurpfile qualification_matrix"), 2)
        self.assertEqual(workflow.count('"previous_commit_sha",'), 2)
        self.assertEqual(workflow.count(".schema_version == 5"), 2)
        self.assertNotIn(".schema_version == 1", workflow)
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
            self.assertIn("native_lifecycle_bundle_verify.py", section)
            self.assertIn("native-release-evidence/native-lifecycle", section)
            self.assertIn("--node02-ssh-host-key-sha256", section)
            self.assertIn("--node03-ssh-host-key-sha256", section)
            self.assertIn("--node05-ssh-host-key-sha256", section)
            self.assertIn("--node04-ssh-host-key-sha256", section)
            for argument in (
                "--package-amd64-shard",
                "--expected-repository",
                "--expected-workflow-run-id",
                "--expected-workflow-run-attempt 1",
                "--expected-candidate-run-id",
                "--expected-candidate-artifact-id",
                "--expected-candidate-artifact-name",
                "--expected-previous-release-id",
            ):
                self.assertIn(argument, section)
            self.assertIn("EVIDENCE_SHA256SUMS.txt qualification-context.json", section)
            self.assertIn(
                "qualification_root_directories=(aggregate bound "
                "go127-evidence native-release-evidence native-signing packages raw status)",
                section,
            )
            self.assertIn(
                "native-release-evidence/ha-v2 "
                "native-release-evidence/ha-v2/raw "
                "native-release-evidence/native-capability "
                "native-release-evidence/native-lifecycle "
                "native-release-evidence/node01-migration "
                "native-release-evidence/performance",
                section,
            )
            self.assertNotIn("native-release-evidence/rhel-package-owned", section)
            self.assertIn(
                "native-release-evidence/source-allocation "
                "native-release-evidence/source-allocation/raw "
                "native-release-evidence/source-allocation/raw/allocation-campaign-01 "
                "native-release-evidence/source-allocation/raw/allocation-campaign-02 "
                "native-release-evidence/source-allocation/raw/allocation-campaign-03",
                section,
            )
            self.assertIn("qualification_root_directories+=(update)", section)
            self.assertIn("qualification_all_directories+=(update)", section)
            for raw_name in (
                "nftables-raw.json",
                "package-lifecycle-amd64.json",
                "package-lifecycle-raw.json",
            ):
                self.assertIn(raw_name, section)
            self.assertIn(
                "nftables-bound.json package-lifecycle-bound.json",
                section,
            )
            self.assertIn("qualification-exit-codes.json", section)
            self.assertNotIn(RETIRED_PLATFORM, section.lower())
            self.assertNotIn(RETIRED_PACKAGE_SUFFIX, section)
            self.assertNotIn("${QUALIFICATION_ROOT}/tools", section)
            self.assertIn("test -z \"$(find \"${QUALIFICATION_ROOT}\" -type l", section)
            self.assertIn("! -type f ! -type d -print -quit", section)
            self.assertIn(
                "native-signing native-signing/evidence native-signing/packages "
                "native-signing/rhel-package-owned "
                "native-signing/rhel-package-owned/evidence "
                "native-signing/rhel-package-owned/packages "
                "packages packages/candidate packages/previous raw status",
                section,
            )
            self.assertIn('.repository == $repository', section)
            self.assertIn('.release_tag == $release_tag', section)
            self.assertIn('.release_sha == $release_sha', section)
            self.assertIn('(.previous_commit_sha | type) == "string"', section)
            self.assertIn(
                '.previous_tag == $aggregate[0].bindings.previous_version', section
            )
            self.assertIn(
                ".previous_commit_sha ==\n"
                "              $qualification_matrix[0].package_sources.baseline.commit",
                section,
            )
            self.assertIn("(.previous_package_asset_ids | length) == 4", section)
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
            self.assertIn("go run ./scripts/ci/update_manifest.go verify", section)
            self.assertIn(
                '--manifest "${QUALIFICATION_ROOT}/update/'
                'syswarden-update-manifest-v1.json"',
                section,
            )
            self.assertIn(
                '--signature "${QUALIFICATION_ROOT}/update/'
                'syswarden-update-manifest-v1.json.sig"',
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
                "syswarden-${VERSION}-1.x86_64.rpm",
                "syswarden_${VERSION}_x86_64.apk",
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

    def test_release_manager_adapter_calls_match_the_live_cli_contract(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        needle = "python3 scripts/ci/release_qualification_adapter.py verify"
        commands = continued_shell_commands(workflow, needle)
        self.assertEqual(len(commands), 2)

        parser = release_qualification_adapter.build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if "verify" in (getattr(action, "choices", None) or {})
        )
        verify_parser = subparsers.choices["verify"]
        known_options = {
            option
            for action in verify_parser._actions
            for option in action.option_strings
            if option.startswith("--")
        }
        required_options = {
            option
            for action in verify_parser._actions
            if action.required
            for option in action.option_strings
            if option.startswith("--")
        }
        expected_arguments = {
            "--repo-root": "${GITHUB_WORKSPACE}",
            "--expected-sha": "${RELEASE_SHA}",
            "--expected-version": "${RELEASE_TAG}",
            "--candidate-packages-dir": "${QUALIFICATION_ROOT}/packages/candidate",
            "--previous-packages-dir": "${QUALIFICATION_ROOT}/packages/previous",
            "--nft-raw": "${QUALIFICATION_ROOT}/raw/nftables-raw.json",
            "--package-raw": "${QUALIFICATION_ROOT}/raw/package-lifecycle-raw.json",
            "--package-amd64-shard": (
                "${QUALIFICATION_ROOT}/raw/package-lifecycle-amd64.json"
            ),
            "--qualification-matrix": (
                "${GITHUB_WORKSPACE}/${QUALIFICATION_MATRIX_PATH}"
            ),
            "--expected-repository": "${GITHUB_REPOSITORY}",
            "--expected-workflow-run-id": "${QUALIFICATION_RUN_ID}",
            "--expected-workflow-run-attempt": "1",
            "--expected-candidate-run-id": "${candidate_run_id}",
            "--expected-candidate-artifact-id": "${candidate_artifact_id}",
            "--expected-candidate-artifact-name": "${candidate_artifact_name}",
            "--expected-previous-release-id": "${previous_release_id}",
            "--max-age-seconds": "172800",
            "--max-report-skew-seconds": "0",
            "--nft-envelope": "${QUALIFICATION_ROOT}/bound/nftables-bound.json",
            "--package-envelope": (
                "${QUALIFICATION_ROOT}/bound/package-lifecycle-bound.json"
            ),
        }

        for command in commands:
            with self.subTest(command=" ".join(command)):
                verify_index = command.index("verify")
                argument_tokens = command[verify_index + 1 :]
                self.assertEqual(len(argument_tokens) % 2, 0)
                provided_arguments: dict[str, str] = {}
                for option, value in zip(
                    argument_tokens[0::2], argument_tokens[1::2], strict=True
                ):
                    self.assertTrue(option.startswith("--"), option)
                    self.assertIn(option, known_options)
                    self.assertNotIn(option, provided_arguments)
                    self.assertTrue(value, option)
                    self.assertFalse(value.startswith("--"), option)
                    provided_arguments[option] = value
                self.assertEqual(
                    required_options - set(provided_arguments),
                    set(),
                )
                self.assertEqual(provided_arguments, expected_arguments)

    def test_release_manager_executes_schema_v5_native_evidence_context_contract(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "QUALIFICATION_MATRIX_PATH: ${{ inputs.release_tag == 'v4.10.0' && "
            "'scripts/ci/package_qualification_matrix_v4.10.0.json' || "
            "'scripts/ci/package_qualification_matrix.json' }}",
            workflow,
        )
        self.assertNotIn(
            "${GITHUB_WORKSPACE}/scripts/ci/package_qualification_matrix.json",
            workflow,
        )

        validate = workflow.split("  validate-and-stage:", 1)[1].split(
            "  attest-and-publish:", 1
        )[0]
        privileged = workflow.split("  attest-and-publish:", 1)[1]
        repository = "duggytuxy/syswarden"
        release_tag = "v4.10.0"
        release_sha = "a" * 40
        previous_tag = "v4.04.2"
        previous_commit_sha = "7a03d40f427a825917561e2a0930298e8fbbbc8b"
        context = {
            "schema_version": 5,
            "repository": repository,
            "release_tag": release_tag,
            "release_sha": release_sha,
            "previous_tag": previous_tag,
            "previous_commit_sha": previous_commit_sha,
            "candidate_package_workflow": "package.yml",
            "candidate_package_run_id": 101,
            "candidate_package_artifact_id": 102,
            "candidate_package_artifact_name": "syswarden-packages-4.10.0",
            "candidate_package_artifact_digest": "sha256:" + "d" * 64,
            "native_signing_workflow": "native-package-signing.yml",
            "native_signing_run_id": 104,
            "native_signing_artifact_id": 105,
            "native_signing_artifact_name": "syswarden-native-signed-packages-4.10.0-104-1-" + release_sha,
            "native_signing_artifact_digest": "sha256:" + "e" * 64,
            "native_evidence_workflow": "native-release-evidence.yml",
            "native_evidence_run_id": 106,
            "native_evidence_artifact_id": 107,
            "native_evidence_artifact_name": "syswarden-native-evidence-v4.10.0-" + release_sha,
            "native_evidence_artifact_digest": "sha256:" + "f" * 64,
            "go127_workflow": "go-127-evaluation.yml",
            "go127_run_id": 108,
            "go127_artifact_id": 109,
            "go127_artifact_name": "syswarden-go127-evaluation-" + release_sha,
            "go127_artifact_digest": "sha256:" + "1" * 64,
            "previous_release_id": 381364611,
            "previous_package_asset_ids": [
                {"id": 541354557, "name": "SHA256SUMS.txt"},
                {"id": 541354554, "name": "syswarden-4.04.2-1.x86_64.rpm"},
                {"id": 541354594, "name": "syswarden_4.04.2_amd64.deb"},
                {"id": 541354596, "name": "syswarden_4.04.2_x86_64.apk"},
            ],
        }
        aggregate = {"bindings": {"previous_version": previous_tag}}
        qualification_matrix = {
            "package_sources": {
                "baseline": {"commit": previous_commit_sha},
            }
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aggregate_path = root / "aggregate.json"
            matrix_path = root / "matrix.json"
            context_path = root / "qualification-context.json"
            aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
            matrix_path.write_text(json.dumps(qualification_matrix), encoding="utf-8")

            for stage, section in (("validate", validate), ("privileged", privileged)):
                start_marker = "'(keys | sort) == ["
                end_marker = "' \"${QUALIFICATION_ROOT}/qualification-context.json\""
                self.assertEqual(section.count(start_marker), 1, stage)
                start = section.index(start_marker) + 1
                end = section.index(end_marker, start)
                predicate = section[start:end]

                def execute(candidate: dict[str, object]) -> subprocess.CompletedProcess[str]:
                    context_path.write_text(json.dumps(candidate), encoding="utf-8")
                    return subprocess.run(
                        [
                            "jq",
                            "--exit-status",
                            "--slurpfile",
                            "aggregate",
                            str(aggregate_path),
                            "--slurpfile",
                            "qualification_matrix",
                            str(matrix_path),
                            "--arg",
                            "repository",
                            repository,
                            "--arg",
                            "release_tag",
                            release_tag,
                            "--arg",
                            "release_sha",
                            release_sha,
                            predicate,
                            str(context_path),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                with self.subTest(stage=stage, mutation="valid"):
                    result = execute(context)
                    self.assertEqual(result.returncode, 0, result.stderr)
                for mutation, mutate in (
                    ("schema", lambda value: value.__setitem__("schema_version", 1)),
                    ("commit", lambda value: value.__setitem__("previous_commit_sha", "b" * 40)),
                    ("unsigned digest", lambda value: value.__setitem__("candidate_package_artifact_digest", "sha256:" + "0" * 63)),
                    ("native run", lambda value: value.__setitem__("native_signing_run_id", 999)),
                    ("native artifact", lambda value: value.__setitem__("native_signing_artifact_id", 0)),
                    ("native name", lambda value: value.__setitem__("native_signing_artifact_name", "wrong")),
                    ("native digest", lambda value: value.__setitem__("native_signing_artifact_digest", "sha256:" + "0" * 63)),
                    ("native evidence run", lambda value: value.__setitem__("native_evidence_run_id", 0)),
                    ("native evidence artifact", lambda value: value.__setitem__("native_evidence_artifact_id", 0)),
                    ("native evidence name", lambda value: value.__setitem__("native_evidence_artifact_name", "wrong")),
                    ("native evidence digest", lambda value: value.__setitem__("native_evidence_artifact_digest", "sha256:" + "0" * 63)),
                    ("extra", lambda value: value.__setitem__("unexpected", True)),
                    ("missing", lambda value: value.pop("previous_commit_sha")),
                ):
                    candidate = json.loads(json.dumps(context))
                    mutate(candidate)
                    with self.subTest(stage=stage, mutation=mutation):
                        self.assertNotEqual(execute(candidate).returncode, 0)

    def test_workflow_run_coordination_resolves_v4100_matrix_from_resolved_tag(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        coordinate = workflow.split("  coordinate-release:", 1)[1].split(
            "  dispatch-release:", 1
        )[0]
        self.assertNotIn("inputs.release_tag", coordinate)
        self.assertIn(
            "RELEASE_TAG: ${{ steps.context.outputs.release_tag }}", coordinate
        )
        self.assertIn(
            'v4.10.0) matrix_path="scripts/ci/package_qualification_matrix_v4.10.0.json"',
            coordinate,
        )
        self.assertIn(
            '--check "${matrix_path}" --expected-target-release "${RELEASE_TAG}"',
            coordinate,
        )

    def test_publisher_uses_only_qualified_signed_packages_and_signatures(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        stage = workflow.split(
            "      - name: Validate and Assemble Exact Release Inventory", 1
        )[1].split("      - name: Upload Validated Release Payload", 1)[0]
        self.assertIn(
            '--packages "${RUNNER_TEMP}/syswarden-release-qualification-stage/packages/candidate"',
            stage,
        )
        self.assertIn(
            '--deb-signature "${RUNNER_TEMP}/syswarden-release-qualification-stage/native-signing/packages/syswarden_${VERSION}_amd64.deb.asc"',
            stage,
        )
        self.assertIn(
            '--rhel-package-owned-rpm "${RUNNER_TEMP}/syswarden-release-qualification-stage/native-signing/rhel-package-owned/packages/syswarden-${VERSION}-1.rhelpo.x86_64.rpm"',
            stage,
        )
        self.assertNotIn('--packages "incoming/syswarden-packages-${VERSION}"', stage)
        revalidation = workflow.split(
            "      - name: Revalidate Exact Pre-Tag Qualification and Candidate Packages",
            1,
        )[1].split("      - name: Validate and Assemble Exact Release Inventory", 1)[0]
        self.assertIn("native-signing/evidence/UNSIGNED_SHA256SUMS.txt", revalidation)
        self.assertIn("native-signing/packages/${package_name}", revalidation)
        privileged = workflow.split("  attest-and-publish:", 1)[1]
        self.assertIn(
            'native-signing/rhel-package-owned/packages/syswarden-${VERSION}-1.rhelpo.x86_64.rpm',
            privileged,
        )
        self.assertIn(
            'release_payload/assets/syswarden-${VERSION}-1.rhelpo.x86_64.rpm',
            privileged,
        )

    def test_privileged_publisher_requires_a_protected_maintainer_environment(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
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
        self.assertIn('.prevent_self_review == false', workflow)
        self.assertIn('(.reviewers | length) == 1', workflow)
        self.assertIn('.reviewers[0].reviewer.login == $owner', workflow)
        self.assertIn('"${protection_rule_count}" != "2"', workflow)
        self.assertIn('deployment-branch-policies', workflow)
        self.assertIn('.name == "v*" and .type == "tag"', workflow)
        self.assertIn('"${release_tag_policy_count}" != "1"', workflow)
        environment_script = workflow_step_script(
            workflow, "Require Protected Maintainer Release Environment"
        )
        self.assertIn("required_environment_boolean()", environment_script)
        self.assertIn("required_top_level_environment_boolean()", environment_script)
        self.assertIn('if type == "boolean" then', environment_script)
        self.assertIn("tostring", environment_script)
        self.assertNotIn('// "missing"', environment_script)
        privileged_job = workflow.split("  attest-and-publish:", 1)[1]
        self.assertIn("environment:\n      name: syswarden-release-production", privileged_job)

    def test_production_environment_boolean_gate_is_typed_and_fail_closed(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        script = workflow_step_script(
            workflow, "Require Protected Maintainer Release Environment"
        )
        valid = {
            "name": "syswarden-release-production",
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
        policies = [
            {
                "total_count": 1,
                "branch_policies": [{"name": "v*", "type": "tag"}],
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
                self.assertIn(
                    "must forbid administrator bypass", diagnostic
                )

        mutated = json.loads(json.dumps(valid))
        mutated["can_admins_bypass"] = True
        result = run_environment_gate(script, mutated, policies)
        diagnostic = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, diagnostic)
        self.assertNotIn("must be boolean", diagnostic)
        self.assertIn("must forbid administrator bypass", diagnostic)

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

        for name, value, missing in (
            ("admin bypass missing", None, True),
            ("admin bypass null", None, False),
            ("admin bypass string", "false", False),
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
        self.assertEqual(
            between.count('--expected-repository "${GITHUB_REPOSITORY}"'),
            1,
        )
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
