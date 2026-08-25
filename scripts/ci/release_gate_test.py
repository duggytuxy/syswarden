#!/usr/bin/env python3
"""Unit tests for the fail-closed release asset gate."""

from __future__ import annotations

import hashlib
import io
import json
import os
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
        self.assertEqual(provenance["derived_linux_manifest"]["package_count"], 6)
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
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "64-KiB"):
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

    def assert_preserved_version_recovery_contract(self, workflow: str) -> None:
        scripts = workflow_step_scripts(
            workflow, "Validate Tag, Source, Changelog, and Main Ancestry"
        )
        self.assertEqual(len(scripts), 2)
        self.assertEqual(scripts[0], scripts[1])
        self.assertEqual(
            workflow.count("if ! ./scripts/versioning.sh validate-commit"), 2
        )
        self.assertEqual(
            workflow.count('if [[ "${RELEASE_TAG}" != "v4.03.0" ]]'), 2
        )
        self.assertEqual(
            workflow.count('case "${current_parent_sha}" in'), 2
        )
        self.assertEqual(
            workflow.count("295275baf021adc2efe22e5e14e38e2184c635a1)"), 2
        )
        self.assertEqual(
            workflow.count("10af4a7b754e1007fa8167e8c5222ac183cb288a)"), 2
        )
        self.assertEqual(
            workflow.count('release_base_sha="$(git rev-parse HEAD^^)"'), 2
        )
        self.assertEqual(
            workflow.count(
                '\n                release_base_sha="$(git rev-parse HEAD^^^)"'
            ),
            2,
        )
        self.assertEqual(workflow.count('--base-ref "${release_base_sha}"'), 4)
        self.assertNotIn("--base-ref HEAD^^", workflow)
        self.assertEqual(
            workflow.count('--base-ref "${previous_fix_parent_sha}"'), 2
        )
        self.assertEqual(
            workflow.count(
                "a preserved-version release fix requires a Qualification "
                "commit subject"
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                "second_fix_subject_pattern='^Qualification : isolate nft "
                "golden helper TMPDIR \\(#[1-9][0-9]*\\)$'"
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                '[[ ! "${commit_subject}" =~ ${second_fix_subject_pattern} ]]'
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                'previous_fix_parent_sha="$(git rev-parse HEAD^^)"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                '"${previous_fix_parent_sha}" != '
                '"295275baf021adc2efe22e5e14e38e2184c635a1"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count("git rev-list --parents -n 1 HEAD)"), 6
        )
        self.assertEqual(
            workflow.count("git rev-list --parents -n 1 HEAD^)"), 4
        )
        self.assertEqual(
            workflow.count(
                'previous_fix_line <<< "$(git rev-list --parents -n 1 HEAD^)"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                "a preserved-version release fix requires one linear commit "
                "after one versioning commit"
            ),
            2,
        )
        self.assertEqual(workflow.count("git diff --quiet HEAD^ HEAD --"), 4)
        self.assertEqual(
            workflow.count(
                '\n                parent_commit_message="$(git log -1 --format=%B HEAD^)"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count('previous_fix_message="$(git log -1 --format=%B HEAD^)"'),
            2,
        )
        self.assertEqual(
            workflow.count(
                'versioning_commit_message="$(git log -1 --format=%B HEAD^^)"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                '"${release_base_sha}" != '
                '"dfb8dfcf52bd1f82dcd2cd3b311119f01270af1e"'
            ),
            2,
        )
        for script in scripts:
            self.assertEqual(script.count("--tag-phase"), 4)
            self.assertEqual(script.count("./scripts/versioning.sh validate-commit"), 12)
            self.assertEqual(
                script.count("# BEGIN exact second preserved-version fix diff contract"),
                1,
            )
            self.assertEqual(
                script.count("# END exact second preserved-version fix diff contract"),
                1,
            )
            self.assertEqual(
                script.count(
                    "git diff-tree --no-commit-id --name-status -r --no-renames -z HEAD^ HEAD"
                ),
                2,
            )
            self.assertEqual(script.count('for tree_ref in HEAD^ HEAD; do'), 2)
            self.assertEqual(
                script.count('tree_entry="$(git ls-tree "${tree_ref}" -- "${fix_path}")"'),
                16,
            )
            self.assertEqual(script.count('"${tree_mode}" != "100644"'), 15)
            self.assertEqual(script.count('"${tree_type}" != "blob"'), 16)
            expected_path_counts = {
                ".github/workflows/release-manager.yml": 28,
                "scripts/ci/release_gate_test.py": 28,
                "src/core/syswarden-cli/pkg/firewall/firewall_linux_golden_test.go": 2,
            }
            for path, count in expected_path_counts.items():
                self.assertEqual(script.count(f'"{path}"'), count)

    def v4032_recovery_blocks(self, workflow: str) -> list[str]:
        scripts = workflow_step_scripts(
            workflow, "Validate Tag, Source, Changelog, and Main Ancestry"
        )
        self.assertEqual(len(scripts), 2)
        self.assertEqual(scripts[0], scripts[1])
        start = 'if [[ "${RELEASE_TAG}" == "v4.03.2" ]]; then\n'
        end = "\n  else\n"
        blocks = []
        for script in scripts:
            self.assertEqual(script.count(start), 1)
            remainder = script.split(start, 1)[1]
            self.assertIn(end, remainder)
            blocks.append(start + remainder.split(end, 1)[0])
        self.assertEqual(blocks[0], blocks[1])
        return blocks

    def assert_v4032_preserved_version_recovery_contract(
        self, workflow: str
    ) -> None:
        blocks = self.v4032_recovery_blocks(workflow)
        self.assertEqual(
            workflow.count(
                'commit_subject="$(git log -1 --format=%s HEAD)"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count('if [[ "${RELEASE_TAG}" == "v4.03.2" ]]; then'), 2
        )
        pinned_contracts = (
            (
                'if [[ "${v4032_arm64_attestation_parent_sha}" != '
                '"8e3ef2a0f50e4833f3078a7a09c2d07bf984f6ef" ]]; then'
            ),
            (
                'if [[ "${v4032_docs_parent_sha}" != '
                '"3d95b9e53fabf01f73ed36b7fb7dcdaaec0dc4a0" ]]; then'
            ),
            (
                'if [[ "${v4032_systemd_parent_sha}" != '
                '"540bab73a477c76d6301d276383602db06d36acd" ]]; then'
            ),
            (
                'if [[ "${v4032_cli_toml_parent_sha}" != '
                '"4eacbae34561ae09611a7adb1f78717ca56e52a6" ]]; then'
            ),
            (
                'if [[ "${v4032_core_toml_parent_sha}" != '
                '"3513acaee928cdd0aa235024f6ebfc5b2efe1dff" ]]; then'
            ),
            (
                'if [[ "${v4032_crun_parent_sha}" != '
                '"b74756b71e26e39b98c7fa60b65a3486adfde3e8" ]]; then'
            ),
            (
                'if [[ "${v4032_compliance_parent_sha}" != '
                '"ba1e853c11033f6abcd674dc7c251848f347e55b" ]]; then'
            ),
            (
                'if [[ "${v4032_init_runtime_parent_sha}" != '
                '"97ebc9991fdeec293abd04444ad6600f11c30ee4" ]]; then'
            ),
            (
                'if [[ "${v4032_stabilization_parent_sha}" != '
                '"41d7a7da2895f5d3949cc63f3e45308c03f7f93a" ]]; then'
            ),
            (
                'if [[ "${v4032_local_parent_sha}" != '
                '"93bb85a657d8f8927cd6617c4105653732c59114" ]]; then'
            ),
            (
                'if [[ "${v4032_runc_parent_sha}" != '
                '"d025f5ee7b1d453a64d11ea2f5afcab13fc01a97" ]]; then'
            ),
            (
                'if [[ "${v4032_runtime_parent_sha}" != '
                '"0e7fc0a3437d69cea8086abacd0a30e032a0579f" ]]; then'
            ),
            (
                'if [[ "${v4032_arm64_parent_sha}" != '
                '"8387b3e8b96a3778b333504dc9c948dfe06777d5" ]]; then'
            ),
            (
                'if [[ "${v4032_merge_parent_sha}" != '
                '"14ccbf1d32c221ee1e430dbad5eac40b1c5bd2c1" ]]; then'
            ),
            (
                'if [[ "${v4032_parent_sha}" != '
                '"3839d592467a4f92f24b613412d8d89bb6905251" ]]; then'
            ),
            (
                'if [[ "${v4032_grandparent_sha}" != '
                '"3655abe045deffc669e0ba9c11a6e4cf17a317a5" ]]; then'
            ),
            (
                'if [[ "${v4032_release_base_sha}" != '
                '"f2270a2a8138f1f2b72a6200f6febbdc83fa5eaa" ]]; then'
            ),
        )
        for contract in pinned_contracts:
            self.assertEqual(workflow.count(contract), 2)
        arm64_attestation_subject_contract = (
            "v4032_arm64_attestation_expected_subject='Qualification : stabilize "
            "ARM64 crun version attestation (#111)'"
        )
        docs_subject_contract = (
            "v4032_docs_expected_subject='Security : preserve read-only config "
            "preflight and centralize v4.03.2 docs (#110)'"
        )
        systemd_subject_contract = (
            "v4032_systemd_expected_subject='Qualification : seal "
            "systemd-capable ARM64 crun runtime (#109)'"
        )
        cli_toml_subject_contract = (
            "v4032_cli_toml_expected_subject='Bump "
            "github.com/pelletier/go-toml/v2 in /src/core/syswarden-cli (#105)'"
        )
        core_toml_subject_contract = (
            "v4032_core_toml_expected_subject='Bump "
            "github.com/pelletier/go-toml/v2 in /src/core/syswarden-core (#106)'"
        )
        crun_subject_contract = (
            "v4032_crun_expected_subject='Qualification : restore v4.03.2 "
            "ARM64 lifecycle under crun (#108)'"
        )
        compliance_subject_contract = (
            "v4032_compliance_expected_subject='Security : enforce v4.03.2 "
            "compliance release verdict (#104)'"
        )
        init_runtime_subject_contract = (
            "v4032_init_runtime_expected_subject='Qualification : repair "
            "v4.03.2 ARM64 init runtime (#103)'"
        )
        stabilization_subject_contract = (
            "v4032_stabilization_expected_subject='Qualification : stabilize "
            "v4.03.2 ARM64 lifecycle evidence (#102)'"
        )
        local_subject_contract = (
            "v4032_local_expected_subject='Qualification : repair v4.03.2 "
            "ARM64 lab and config root handling (#101)'"
        )
        runc_subject_contract = (
            "v4032_runc_expected_subject='Qualification : pin v4.03.2 "
            "ARM64 runc runtime path (#99)'"
        )
        runtime_subject_contract = (
            "v4032_runtime_expected_subject='Qualification : repair v4.03.2 "
            "ARM64 OCI runtime resolution (#98)'"
        )
        arm64_subject_contract = (
            "v4032_arm64_expected_subject='Qualification : repair v4.03.2 "
            "native ARM64 Podman path contract (#97)'"
        )
        merge_subject_contract = (
            "v4032_merge_expected_subject='Qualification : repair v4.03.2 "
            "merged squash subject contract (#96)'"
        )
        repair_subject_contract = (
            "v4032_expected_subject='Qualification : repair v4.03.2 "
            "package lifecycle qualification (#95) (#95)'"
        )
        arm64_attestation_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "README.md",
            "assets/syswarden_hero.svg",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
            "scripts/ci/workflow_required_checks_test.py",
        )
        docs_paths = (
            ".github/workflows/release-manager.yml",
            "README.md",
            "assets/syswarden_hero.svg",
            "scripts/ci/documentation_contract.json",
            "scripts/ci/documentation_gate.py",
            "scripts/ci/documentation_gate_test.py",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/workflow_required_checks_test.py",
            "src/core/syswarden-cli/cmd/root.go",
            "src/core/syswarden-cli/cmd/root_config_guard_test.go",
        )
        systemd_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
        )
        cli_toml_paths = (
            "src/core/syswarden-cli/go.mod",
            "src/core/syswarden-cli/go.sum",
        )
        core_toml_paths = (
            "src/core/syswarden-core/go.mod",
            "src/core/syswarden-core/go.sum",
        )
        compliance_paths = (
            ".github/dependabot.yml",
            ".github/workflows/compliance.yml",
            ".github/workflows/release-manager.yml",
            ".plumber.yaml",
            "CONTRIBUTING.md",
            "README.md",
            "assets/syswarden_architecture.svg",
            "assets/syswarden_bunkerweb_integration.svg",
            "assets/syswarden_hero.svg",
            "scripts/ci/release_gate.py",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/workflow_required_checks_test.py",
        )
        init_runtime_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "scripts/ci/package_lifecycle_lab.py",
            "scripts/ci/package_lifecycle_lab_test.py",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
            "src/core/syswarden-cli/pkg/integration/waf_logs_linux.go",
            "src/core/syswarden-cli/pkg/integration/waf_logs_linux_test.go",
        )
        arm64_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
        )
        crun_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
            "src/core/syswarden-cli/pkg/security/hardening_linux_test.go",
            "src/core/syswarden-cli/pkg/security/os_hardening_linux.go",
        )
        stabilization_paths = init_runtime_paths
        local_paths = (
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
            "src/core/syswarden-cli/config/config_contract_test.go",
            "src/core/syswarden-cli/config/config_loader.go",
        )
        runc_paths = arm64_paths
        runtime_paths = arm64_paths
        merge_paths = (
            ".github/workflows/release-manager.yml",
            "scripts/ci/release_gate_test.py",
        )
        repair_paths = (
            ".github/workflows/package.yml",
            ".github/workflows/release-manager.yml",
            ".github/workflows/release-qualification.yml",
            "build_packages.sh",
            "scripts/ci/package_lifecycle_contract_test.py",
            "scripts/ci/package_lifecycle_lab.py",
            "scripts/ci/package_lifecycle_lab_test.py",
            "scripts/ci/package_webtui_retirement.sh",
            "scripts/ci/release_gate_test.py",
            "scripts/ci/release_qualification_workflow_test.py",
            "src/core/syswarden-cli/pkg/integration/waf_logs_linux.go",
            "src/core/syswarden-cli/pkg/integration/waf_logs_linux_test.go",
            "src/core/syswarden-cli/pkg/security/hardening_linux_helpers.go",
            "src/core/syswarden-cli/pkg/security/hardening_linux_test.go",
            "src/core/syswarden-cli/pkg/system/firewall_optimizer.go",
            "src/core/syswarden-cli/pkg/system/firewall_optimizer_test.go",
            "src/core/syswarden-cli/pkg/system/service_linux.go",
            "src/core/syswarden-cli/pkg/system/service_linux_test.go",
            "src/core/syswarden-cli/pkg/system/uninstall_linux.go",
            "src/core/syswarden-cli/pkg/system/uninstall_prepare_linux_test.go",
        )
        expected_paths = tuple(
            dict.fromkeys(
                compliance_paths
                + repair_paths
                + crun_paths
                + arm64_attestation_paths
                + docs_paths
                + systemd_paths
                + cli_toml_paths
                + core_toml_paths
            )
        )
        unchanged_targets = (
            "changelog.md",
            "src/core/syswarden-cli/pkg/system/upgrade.go",
            "src/core/syswarden-tui/main.go",
            "src/core/syswarden-cli/cmd/install.go",
            "src/core/syswarden-cli/config/default.go",
            "src/core/syswarden-cli/pkg/integration/webhook.go",
            "src/core/syswarden-core/webhook/discord.go",
        )
        for block in blocks:
            self.assertEqual(block.count(arm64_attestation_subject_contract), 1)
            self.assertEqual(block.count(docs_subject_contract), 1)
            self.assertEqual(block.count(systemd_subject_contract), 1)
            self.assertEqual(block.count(cli_toml_subject_contract), 1)
            self.assertEqual(block.count(core_toml_subject_contract), 1)
            self.assertEqual(block.count(crun_subject_contract), 1)
            self.assertEqual(block.count(compliance_subject_contract), 1)
            self.assertEqual(block.count(init_runtime_subject_contract), 1)
            self.assertEqual(block.count(stabilization_subject_contract), 1)
            self.assertEqual(block.count(local_subject_contract), 1)
            self.assertEqual(block.count(runc_subject_contract), 1)
            self.assertEqual(block.count(runtime_subject_contract), 1)
            self.assertEqual(block.count(arm64_subject_contract), 1)
            self.assertEqual(block.count(merge_subject_contract), 1)
            self.assertEqual(block.count(repair_subject_contract), 1)
            self.assertEqual(
                block.count(
                    '[[ "${commit_subject}" != '
                    '"${v4032_arm64_attestation_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_attestation_parent_sha="$(git rev-parse HEAD^)"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_attestation_head_line <<< '
                    '"$(git rev-list --parents -n 1 HEAD)"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_arm64_attestation_head_line[@]} != 2"), 1
            )
            arm64_attestation_diff = block.split(
                "# BEGIN exact v4.03.2 deterministic ARM64 crun attestation "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 deterministic ARM64 crun attestation "
                "diff contract",
                1,
            )[0]
            self.assertEqual(
                arm64_attestation_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z HEAD^ HEAD"
                ),
                1,
            )
            self.assertEqual(
                arm64_attestation_diff.count("for tree_ref in HEAD^ HEAD; do"), 1
            )
            for path in arm64_attestation_paths:
                self.assertEqual(arm64_attestation_diff.count(f'"{path}"'), 2)
                self.assertEqual(arm64_attestation_diff.count(f'M "{path}"'), 1)
            self.assertEqual(block.count("v4032_docs_ref=HEAD^\n"), 1)
            self.assertEqual(
                block.count(
                    'v4032_docs_parent_sha="$(git rev-parse '
                    '"${v4032_docs_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_docs_subject="$(git log -1 --format=%s '
                    '"${v4032_docs_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_docs_subject}" != '
                    '"${v4032_docs_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_docs_head_line <<< '
                    '"$(git rev-list --parents -n 1 "${v4032_docs_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_docs_head_line[@]} != 2"), 1
            )
            docs_diff = block.split(
                "# BEGIN exact v4.03.2 read-only configuration and documentation "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 read-only configuration and documentation "
                "diff contract",
                1,
            )[0]
            self.assertEqual(
                docs_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_docs_ref}^" "${v4032_docs_ref}"'
                ),
                1,
            )
            self.assertEqual(
                docs_diff.count(
                    'for tree_ref in "${v4032_docs_ref}^" '
                    '"${v4032_docs_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                docs_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                docs_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                docs_diff.count(
                    "! \"${tree_object}\" =~ ^[0-9a-f]{40}$"
                ),
                1,
            )
            self.assertEqual(
                docs_diff.count(
                    "${#actual_v4032_docs_diff[@]} != "
                    "${#expected_v4032_docs_diff[@]}"
                ),
                1,
            )
            for path in docs_paths:
                self.assertEqual(docs_diff.count(f'"{path}"'), 2)
                self.assertEqual(docs_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_systemd_ref="${v4032_docs_ref}^"\n'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_systemd_parent_sha="$(git rev-parse '
                    '"${v4032_systemd_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_systemd_subject="$(git log -1 --format=%s '
                    '"${v4032_systemd_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_systemd_subject}" != '
                    '"${v4032_systemd_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_systemd_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_systemd_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_systemd_head_line[@]} != 2"), 1
            )
            systemd_diff = block.split(
                "# BEGIN exact v4.03.2 systemd-capable ARM64 crun runtime "
                "correction diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 systemd-capable ARM64 crun runtime "
                "correction diff contract",
                1,
            )[0]
            self.assertEqual(
                systemd_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_systemd_ref}^" '
                    '"${v4032_systemd_ref}"'
                ),
                1,
            )
            self.assertEqual(
                systemd_diff.count(
                    'for tree_ref in "${v4032_systemd_ref}^" '
                    '"${v4032_systemd_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                systemd_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                systemd_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                systemd_diff.count(
                    "! \"${tree_object}\" =~ ^[0-9a-f]{40}$"
                ),
                1,
            )
            self.assertEqual(
                systemd_diff.count(
                    "${#actual_v4032_systemd_diff[@]} != "
                    "${#expected_v4032_systemd_diff[@]}"
                ),
                1,
            )
            for path in systemd_paths:
                self.assertEqual(systemd_diff.count(f'"{path}"'), 2)
                self.assertEqual(systemd_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_cli_toml_ref="${v4032_systemd_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_cli_toml_parent_sha="$(git rev-parse '
                    '"${v4032_cli_toml_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_cli_toml_subject="$(git log -1 --format=%s '
                    '"${v4032_cli_toml_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_cli_toml_subject}" != '
                    '"${v4032_cli_toml_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_cli_toml_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_cli_toml_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_cli_toml_head_line[@]} != 2"), 1
            )
            cli_toml_diff = block.split(
                "# BEGIN exact v4.03.2 syswarden-cli go-toml dependency "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 syswarden-cli go-toml dependency "
                "diff contract",
                1,
            )[0]
            self.assertEqual(
                cli_toml_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_cli_toml_ref}^" '
                    '"${v4032_cli_toml_ref}"'
                ),
                1,
            )
            self.assertEqual(
                cli_toml_diff.count(
                    'for tree_ref in "${v4032_cli_toml_ref}^" '
                    '"${v4032_cli_toml_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                cli_toml_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                cli_toml_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                cli_toml_diff.count(
                    "! \"${tree_object}\" =~ ^[0-9a-f]{40}$"
                ),
                1,
            )
            for path in cli_toml_paths:
                self.assertEqual(cli_toml_diff.count(f'"{path}"'), 2)
                self.assertEqual(cli_toml_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_core_toml_ref="${v4032_cli_toml_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_core_toml_parent_sha="$(git rev-parse '
                    '"${v4032_core_toml_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_core_toml_subject="$(git log -1 --format=%s '
                    '"${v4032_core_toml_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_core_toml_subject}" != '
                    '"${v4032_core_toml_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_core_toml_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_core_toml_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_core_toml_head_line[@]} != 2"), 1
            )
            core_toml_diff = block.split(
                "# BEGIN exact v4.03.2 syswarden-core go-toml dependency "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 syswarden-core go-toml dependency "
                "diff contract",
                1,
            )[0]
            self.assertEqual(
                core_toml_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_core_toml_ref}^" '
                    '"${v4032_core_toml_ref}"'
                ),
                1,
            )
            self.assertEqual(
                core_toml_diff.count(
                    'for tree_ref in "${v4032_core_toml_ref}^" '
                    '"${v4032_core_toml_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                core_toml_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                core_toml_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                core_toml_diff.count(
                    "! \"${tree_object}\" =~ ^[0-9a-f]{40}$"
                ),
                1,
            )
            for path in core_toml_paths:
                self.assertEqual(core_toml_diff.count(f'"{path}"'), 2)
                self.assertEqual(core_toml_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_crun_ref="${v4032_core_toml_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_crun_parent_sha="$(git rev-parse '
                    '"${v4032_crun_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_crun_subject="$(git log -1 --format=%s '
                    '"${v4032_crun_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_crun_subject}" != '
                    '"${v4032_crun_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_crun_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_crun_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_crun_head_line[@]} != 2"), 1
            )
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 crun runtime restoration "
                    "diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 ARM64 crun runtime restoration "
                    "diff contract"
                ),
                1,
            )
            crun_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 crun runtime restoration "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 ARM64 crun runtime restoration diff contract",
                1,
            )[0]
            self.assertEqual(
                crun_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_crun_ref}^" "${v4032_crun_ref}"'
                ),
                1,
            )
            self.assertEqual(
                crun_diff.count(
                    'for tree_ref in "${v4032_crun_ref}^" '
                    '"${v4032_crun_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                crun_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                crun_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                crun_diff.count(
                    "${#actual_v4032_crun_diff[@]} != "
                    "${#expected_v4032_crun_diff[@]}"
                ),
                1,
            )
            for path in crun_paths:
                self.assertEqual(crun_diff.count(f'"{path}"'), 2)
                self.assertEqual(crun_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_compliance_ref="${v4032_crun_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_compliance_parent_sha="$(git rev-parse '
                    '"${v4032_compliance_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_compliance_subject="$(git log -1 --format=%s '
                    '"${v4032_compliance_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_compliance_subject}" != '
                    '"${v4032_compliance_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_compliance_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_compliance_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_compliance_head_line[@]} != 2"), 1
            )
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 compliance release verdict diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 compliance release verdict diff contract"
                ),
                1,
            )
            compliance_diff = block.split(
                "# BEGIN exact v4.03.2 compliance release verdict diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 compliance release verdict diff contract",
                1,
            )[0]
            self.assertEqual(
                compliance_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_compliance_ref}^" '
                    '"${v4032_compliance_ref}"'
                ),
                1,
            )
            self.assertEqual(
                compliance_diff.count(
                    'for tree_ref in "${v4032_compliance_ref}^" '
                    '"${v4032_compliance_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                compliance_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                compliance_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                compliance_diff.count(
                    "${#actual_v4032_compliance_diff[@]} != "
                    "${#expected_v4032_compliance_diff[@]}"
                ),
                1,
            )
            for path in compliance_paths:
                self.assertEqual(compliance_diff.count(f'"{path}"'), 2)
                self.assertEqual(compliance_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_init_runtime_ref="${v4032_compliance_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_init_runtime_parent_sha="$(git rev-parse '
                    '"${v4032_init_runtime_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_init_runtime_subject="$(git log -1 --format=%s '
                    '"${v4032_init_runtime_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_init_runtime_subject}" != '
                    '"${v4032_init_runtime_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_init_runtime_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_init_runtime_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_init_runtime_head_line[@]} != 2"), 1
            )
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 init runtime repair diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 ARM64 init runtime repair diff contract"
                ),
                1,
            )
            init_runtime_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 init runtime repair diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 ARM64 init runtime repair diff contract",
                1,
            )[0]
            self.assertEqual(
                init_runtime_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_init_runtime_ref}^" '
                    '"${v4032_init_runtime_ref}"'
                ),
                1,
            )
            self.assertEqual(
                init_runtime_diff.count(
                    'for tree_ref in "${v4032_init_runtime_ref}^" '
                    '"${v4032_init_runtime_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                init_runtime_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                init_runtime_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                init_runtime_diff.count(
                    "${#actual_v4032_init_runtime_diff[@]} != "
                    "${#expected_v4032_init_runtime_diff[@]}"
                ),
                1,
            )
            for path in init_runtime_paths:
                self.assertEqual(init_runtime_diff.count(f'"{path}"'), 2)
                self.assertEqual(init_runtime_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_stabilization_ref="${v4032_init_runtime_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_stabilization_parent_sha="$(git rev-parse '
                    '"${v4032_stabilization_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_stabilization_subject="$(git log -1 --format=%s '
                    '"${v4032_stabilization_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_stabilization_subject}" != '
                    '"${v4032_stabilization_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_stabilization_head_line <<< '
                    '"$(git rev-list --parents -n 1 '
                    '"${v4032_stabilization_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count("${#v4032_stabilization_head_line[@]} != 2"), 1
            )
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 lifecycle stabilization "
                    "diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 ARM64 lifecycle stabilization "
                    "diff contract"
                ),
                1,
            )
            stabilization_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 lifecycle stabilization "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 ARM64 lifecycle stabilization diff contract",
                1,
            )[0]
            self.assertEqual(
                stabilization_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_stabilization_ref}^" '
                    '"${v4032_stabilization_ref}"'
                ),
                1,
            )
            self.assertEqual(
                stabilization_diff.count(
                    'for tree_ref in "${v4032_stabilization_ref}^" '
                    '"${v4032_stabilization_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                stabilization_diff.count('"${tree_mode}" != "100644"'), 1
            )
            self.assertEqual(
                stabilization_diff.count('"${tree_type}" != "blob"'), 1
            )
            self.assertEqual(
                stabilization_diff.count(
                    "${#actual_v4032_stabilization_diff[@]} != "
                    "${#expected_v4032_stabilization_diff[@]}"
                ),
                1,
            )
            for path in stabilization_paths:
                self.assertEqual(stabilization_diff.count(f'"{path}"'), 2)
                self.assertEqual(stabilization_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count(
                    'v4032_local_ref="${v4032_stabilization_ref}^"\n'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_local_parent_sha="$(git rev-parse '
                    '"${v4032_local_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_local_subject="$(git log -1 --format=%s '
                    '"${v4032_local_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_local_subject}" != '
                    '"${v4032_local_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_local_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_local_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_local_head_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 final qualification repair diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 final qualification repair diff contract"
                ),
                1,
            )
            local_diff = block.split(
                "# BEGIN exact v4.03.2 final qualification repair diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 final qualification repair diff contract", 1
            )[0]
            self.assertEqual(
                local_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_local_ref}^" "${v4032_local_ref}"'
                ),
                1,
            )
            self.assertEqual(
                local_diff.count(
                    'for tree_ref in "${v4032_local_ref}^" '
                    '"${v4032_local_ref}"; do'
                ),
                1,
            )
            self.assertEqual(local_diff.count('"${tree_mode}" != "100644"'), 1)
            self.assertEqual(local_diff.count('"${tree_type}" != "blob"'), 1)
            self.assertEqual(
                local_diff.count(
                    "${#actual_v4032_local_diff[@]} != "
                    "${#expected_v4032_local_diff[@]}"
                ),
                1,
            )
            for path in local_paths:
                self.assertEqual(local_diff.count(f'"{path}"'), 2)
                self.assertEqual(local_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_runc_ref="${v4032_local_ref}^"\n'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_runc_parent_sha="$(git rev-parse '
                    '"${v4032_runc_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_runc_subject="$(git log -1 --format=%s '
                    '"${v4032_runc_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_runc_subject}" != '
                    '"${v4032_runc_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_runc_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_runc_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_runc_head_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 runc pin diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count("# END exact v4.03.2 ARM64 runc pin diff contract"),
                1,
            )
            runc_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 runc pin diff contract\n", 1
            )[1].split(
                "# END exact v4.03.2 ARM64 runc pin diff contract", 1
            )[0]
            self.assertEqual(
                runc_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_runc_ref}^" "${v4032_runc_ref}"'
                ),
                1,
            )
            self.assertEqual(
                runc_diff.count(
                    'for tree_ref in "${v4032_runc_ref}^" '
                    '"${v4032_runc_ref}"; do'
                ),
                1,
            )
            self.assertEqual(runc_diff.count('"${tree_mode}" != "100644"'), 1)
            self.assertEqual(runc_diff.count('"${tree_type}" != "blob"'), 1)
            self.assertEqual(
                runc_diff.count(
                    "${#actual_v4032_runc_diff[@]} != "
                    "${#expected_v4032_runc_diff[@]}"
                ),
                1,
            )
            for path in runc_paths:
                self.assertEqual(runc_diff.count(f'"{path}"'), 2)
                self.assertEqual(runc_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_runtime_ref="${v4032_runc_ref}^"\n'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_runtime_parent_sha="$(git rev-parse '
                    '"${v4032_runtime_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_runtime_subject="$(git log -1 --format=%s '
                    '"${v4032_runtime_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_runtime_subject}" != '
                    '"${v4032_runtime_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_runtime_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_runtime_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_runtime_head_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 OCI runtime resolution "
                    "diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 ARM64 OCI runtime resolution "
                    "diff contract"
                ),
                1,
            )
            runtime_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 OCI runtime resolution "
                "diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 ARM64 OCI runtime resolution diff contract",
                1,
            )[0]
            self.assertEqual(
                runtime_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_runtime_ref}^" "${v4032_runtime_ref}"'
                ),
                1,
            )
            self.assertEqual(
                runtime_diff.count(
                    'for tree_ref in "${v4032_runtime_ref}^" '
                    '"${v4032_runtime_ref}"; do'
                ),
                1,
            )
            self.assertEqual(runtime_diff.count('"${tree_mode}" != "100644"'), 1)
            self.assertEqual(runtime_diff.count('"${tree_type}" != "blob"'), 1)
            self.assertEqual(
                runtime_diff.count(
                    "${#actual_v4032_runtime_diff[@]} != "
                    "${#expected_v4032_runtime_diff[@]}"
                ),
                1,
            )
            for path in runtime_paths:
                self.assertEqual(runtime_diff.count(f'"{path}"'), 2)
                self.assertEqual(runtime_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_arm64_ref="${v4032_runtime_ref}^"\n'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_parent_sha="$(git rev-parse '
                    '"${v4032_arm64_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_subject="$(git log -1 --format=%s '
                    '"${v4032_arm64_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_arm64_subject}" != '
                    '"${v4032_arm64_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_arm64_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_arm64_head_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 ARM64 Podman path repair diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 ARM64 Podman path repair diff contract"
                ),
                1,
            )
            arm64_diff = block.split(
                "# BEGIN exact v4.03.2 ARM64 Podman path repair diff contract\n",
                1,
            )[1].split(
                "# END exact v4.03.2 ARM64 Podman path repair diff contract", 1
            )[0]
            self.assertEqual(
                arm64_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_arm64_ref}^" "${v4032_arm64_ref}"'
                ),
                1,
            )
            self.assertEqual(
                arm64_diff.count(
                    'for tree_ref in "${v4032_arm64_ref}^" '
                    '"${v4032_arm64_ref}"; do'
                ),
                1,
            )
            self.assertEqual(arm64_diff.count('"${tree_mode}" != "100644"'), 1)
            self.assertEqual(arm64_diff.count('"${tree_type}" != "blob"'), 1)
            self.assertEqual(
                arm64_diff.count(
                    "${#actual_v4032_arm64_diff[@]} != "
                    "${#expected_v4032_arm64_diff[@]}"
                ),
                1,
            )
            for path in arm64_paths:
                self.assertEqual(arm64_diff.count(f'"{path}"'), 2)
                self.assertEqual(arm64_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_merge_ref="${v4032_arm64_ref}^"'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_merge_parent_sha="$(git rev-parse '
                    '"${v4032_merge_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_merge_subject="$(git log -1 --format=%s '
                    '"${v4032_merge_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_merge_subject}" != '
                    '"${v4032_merge_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_merge_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_merge_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_merge_head_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 merge-subject repair diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 merge-subject repair diff contract"
                ),
                1,
            )
            merge_diff = block.split(
                "# BEGIN exact v4.03.2 merge-subject repair diff contract\n", 1
            )[1].split(
                "# END exact v4.03.2 merge-subject repair diff contract", 1
            )[0]
            self.assertEqual(
                merge_diff.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\\n"
                    '        "${v4032_merge_ref}^" "${v4032_merge_ref}"'
                ),
                1,
            )
            self.assertEqual(
                merge_diff.count(
                    'for tree_ref in "${v4032_merge_ref}^" '
                    '"${v4032_merge_ref}"; do'
                ),
                1,
            )
            self.assertEqual(merge_diff.count('"${tree_mode}" != "100644"'), 1)
            self.assertEqual(merge_diff.count('"${tree_type}" != "blob"'), 1)
            self.assertEqual(
                merge_diff.count(
                    "${#actual_v4032_merge_diff[@]} != "
                    "${#expected_v4032_merge_diff[@]}"
                ),
                1,
            )
            for path in merge_paths:
                self.assertEqual(merge_diff.count(f'"{path}"'), 2)
                self.assertEqual(merge_diff.count(f'M "{path}"'), 1)
            self.assertEqual(
                block.count('v4032_repair_ref="${v4032_merge_ref}^"'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_parent_sha="$(git rev-parse '
                    '"${v4032_repair_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_repair_subject="$(git log -1 --format=%s '
                    '"${v4032_repair_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    '[[ "${v4032_repair_subject}" != '
                    '"${v4032_expected_subject}" ]]'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_head_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_repair_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_parent_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_repair_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_release_line <<< "$(git rev-list --parents -n 1 '
                    '"${v4032_repair_ref}^^")"'
                ),
                1,
            )
            self.assertEqual(block.count("${#v4032_head_line[@]} != 2"), 1)
            self.assertEqual(block.count("${#v4032_parent_line[@]} != 2"), 1)
            self.assertEqual(block.count("${#v4032_release_line[@]} != 2"), 1)
            self.assertEqual(
                block.count(
                    'v4032_grandparent_sha="$(git rev-parse '
                    '"${v4032_repair_ref}^^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_release_base_sha="$(git rev-parse '
                    '"${v4032_repair_ref}^^^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# BEGIN exact v4.03.2 preserved-version recovery diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "# END exact v4.03.2 preserved-version recovery diff contract"
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    "git diff-tree --no-commit-id --name-status -r "
                    "--no-renames -z \\"
                ),
                14,
            )
            self.assertEqual(
                block.count(
                    '"${v4032_repair_ref}^" "${v4032_repair_ref}"'
                ),
                3,
            )
            self.assertEqual(
                block.count(
                    'for tree_ref in "${v4032_repair_ref}^" '
                    '"${v4032_repair_ref}"; do'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'tree_entry="$(git ls-tree "${tree_ref}" -- "${fix_path}")"'
                ),
                15,
            )
            self.assertEqual(
                block.count('"${tree_mode}" != "${expected_mode}"'), 1
            )
            self.assertEqual(block.count('"${tree_type}" != "blob"'), 15)
            self.assertEqual(block.count('expected_mode="100644"'), 1)
            self.assertEqual(
                block.count('[[ "${fix_path}" == "build_packages.sh" ]]'), 1
            )
            self.assertEqual(block.count('expected_mode="100755"'), 1)
            self.assertEqual(
                block.count("${#actual_v4032_diff[@]} != "
                            "${#expected_v4032_diff[@]}"),
                1,
            )
            for path in expected_paths:
                expected_count = 2 if path in repair_paths else 0
                expected_count += 2 if path in docs_paths else 0
                expected_count += 2 if path in crun_paths else 0
                expected_count += 2 if path in compliance_paths else 0
                expected_count += 2 if path in merge_paths else 0
                expected_count += 2 if path in arm64_attestation_paths else 0
                expected_count += 2 if path in arm64_paths else 0
                expected_count += 2 if path in runtime_paths else 0
                expected_count += 2 if path in runc_paths else 0
                expected_count += 2 if path in local_paths else 0
                expected_count += 2 if path in stabilization_paths else 0
                expected_count += 2 if path in init_runtime_paths else 0
                expected_count += 2 if path in systemd_paths else 0
                expected_count += 2 if path in cli_toml_paths else 0
                expected_count += 2 if path in core_toml_paths else 0
                expected_count += 1 if path == "build_packages.sh" else 0
                self.assertEqual(block.count(f'"{path}"'), expected_count)
                expected_status_count = 1 if path in repair_paths else 0
                expected_status_count += 1 if path in docs_paths else 0
                expected_status_count += 1 if path in crun_paths else 0
                expected_status_count += 1 if path in compliance_paths else 0
                expected_status_count += 1 if path in merge_paths else 0
                expected_status_count += (
                    1 if path in arm64_attestation_paths else 0
                )
                expected_status_count += 1 if path in arm64_paths else 0
                expected_status_count += 1 if path in runtime_paths else 0
                expected_status_count += 1 if path in runc_paths else 0
                expected_status_count += 1 if path in local_paths else 0
                expected_status_count += 1 if path in stabilization_paths else 0
                expected_status_count += 1 if path in init_runtime_paths else 0
                expected_status_count += 1 if path in systemd_paths else 0
                expected_status_count += 1 if path in cli_toml_paths else 0
                expected_status_count += 1 if path in core_toml_paths else 0
                self.assertEqual(
                    block.count(f'M "{path}"'), expected_status_count
                )
            self.assertEqual(
                block.count(
                    'git diff --quiet "${v4032_repair_ref}^" '
                    '"${v4032_repair_ref}" --'
                ),
                1,
            )
            for path in unchanged_targets:
                self.assertEqual(block.count(path), 1)
            self.assertEqual(
                block.count(
                    'v4032_parent_commit_message="$(git log -1 --format=%B '
                    '"${v4032_repair_ref}^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('./scripts/versioning.sh validate-commit'), 7
            )
            self.assertEqual(
                block.count(
                    'v4032_runc_commit_message="$(git log -1 --format=%B '
                    '"${v4032_runc_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_runc_parent_sha}"'), 1
            )
            self.assertEqual(
                block.count('--commit-message "${v4032_runc_commit_message}"'),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_runtime_commit_message="$(git log -1 --format=%B '
                    '"${v4032_runtime_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_runtime_parent_sha}"'), 1
            )
            self.assertEqual(
                block.count(
                    '--commit-message "${v4032_runtime_commit_message}"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_arm64_commit_message="$(git log -1 --format=%B '
                    '"${v4032_arm64_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_arm64_parent_sha}"'), 1
            )
            self.assertEqual(
                block.count(
                    '--commit-message "${v4032_arm64_commit_message}"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_merge_commit_message="$(git log -1 --format=%B '
                    '"${v4032_merge_ref}")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_merge_parent_sha}"'), 1
            )
            self.assertEqual(
                block.count(
                    '--commit-message "${v4032_merge_commit_message}"'
                ),
                1,
            )
            self.assertEqual(
                block.count(
                    'v4032_repair_commit_message="$(git log -1 --format=%B '
                    '"${v4032_repair_ref}")"'
                ),
                1,
            )
            self.assertEqual(block.count('--base-ref "${v4032_parent_sha}"'), 1)
            self.assertEqual(
                block.count(
                    '--commit-message "${v4032_repair_commit_message}"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_grandparent_sha}"'), 1
            )
            self.assertEqual(
                block.count(
                    'v4032_release_commit_message="$(git log -1 --format=%B '
                    '"${v4032_repair_ref}^^")"'
                ),
                1,
            )
            self.assertEqual(
                block.count('--base-ref "${v4032_release_base_sha}"'), 1
            )
            self.assertEqual(block.count("--tag-phase"), 1)
            self.assertEqual(
                block.count('--commit-message "${v4032_parent_commit_message}"'),
                1,
            )
            self.assertEqual(
                block.count('--commit-message "${v4032_release_commit_message}"'),
                1,
            )
            parent_validation = block.split(
                'v4032_parent_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}^")"',
                1,
            )[1].split(
                'v4032_release_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}^^")"',
                1,
            )[0]
            self.assertNotIn("--tag-phase", parent_validation)

    def exact_v4032_arm64_attestation_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 deterministic ARM64 crun attestation "
            "diff contract\n"
        )
        end = (
            "# END exact v4.03.2 deterministic ARM64 crun attestation "
            "diff contract"
        )
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return "set -euo pipefail\n" + block.split(begin, 1)[1].split(end, 1)[0]

    def v4032_arm64_attestation_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_arm64_attestation_expected_subject="
        end = (
            'read -r -a v4032_arm64_attestation_head_line <<< '
            '"$(git rev-list --parents -n 1 HEAD)"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        return 'set -euo pipefail\ncommit_subject="${COMMIT_SUBJECT:?}"\n' + fragment

    def exact_v4032_docs_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 read-only configuration and documentation "
            "diff contract\n"
        )
        end = (
            "# END exact v4.03.2 read-only configuration and documentation "
            "diff contract"
        )
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_docs_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_docs_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_docs_expected_subject="
        subject_assignment = (
            'v4032_docs_subject="$(git log -1 --format=%s '
            '"${v4032_docs_ref}")"'
        )
        end = (
            'read -r -a v4032_docs_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_docs_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_docs_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_systemd_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 systemd-capable ARM64 crun runtime "
            "correction diff contract\n"
        )
        end = (
            "# END exact v4.03.2 systemd-capable ARM64 crun runtime "
            "correction diff contract"
        )
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_systemd_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_systemd_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_systemd_expected_subject="
        subject_assignment = (
            'v4032_systemd_subject="$(git log -1 --format=%s '
            '"${v4032_systemd_ref}")"'
        )
        end = (
            'read -r -a v4032_systemd_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_systemd_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_systemd_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_cli_toml_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 syswarden-cli go-toml dependency diff "
            "contract\n"
        )
        end = "# END exact v4.03.2 syswarden-cli go-toml dependency diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_cli_toml_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_cli_toml_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_cli_toml_expected_subject="
        subject_assignment = (
            'v4032_cli_toml_subject="$(git log -1 --format=%s '
            '"${v4032_cli_toml_ref}")"'
        )
        end = (
            'read -r -a v4032_cli_toml_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_cli_toml_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_cli_toml_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_core_toml_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 syswarden-core go-toml dependency diff "
            "contract\n"
        )
        end = "# END exact v4.03.2 syswarden-core go-toml dependency diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_core_toml_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_core_toml_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_core_toml_expected_subject="
        subject_assignment = (
            'v4032_core_toml_subject="$(git log -1 --format=%s '
            '"${v4032_core_toml_ref}")"'
        )
        end = (
            'read -r -a v4032_core_toml_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_core_toml_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_core_toml_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_crun_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 ARM64 crun runtime restoration diff "
            "contract\n"
        )
        end = "# END exact v4.03.2 ARM64 crun runtime restoration diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_crun_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_crun_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_crun_expected_subject="
        subject_assignment = (
            'v4032_crun_subject="$(git log -1 --format=%s '
            '"${v4032_crun_ref}")"'
        )
        end = (
            'read -r -a v4032_crun_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_crun_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_crun_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_compliance_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 compliance release verdict diff contract\n"
        end = "# END exact v4.03.2 compliance release verdict diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_compliance_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_compliance_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_compliance_expected_subject="
        subject_assignment = (
            'v4032_compliance_subject="$(git log -1 --format=%s '
            '"${v4032_compliance_ref}")"'
        )
        end = (
            'read -r -a v4032_compliance_head_line <<< '
            '"$(git rev-list --parents -n 1 '
            '"${v4032_compliance_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment,
            'v4032_compliance_subject="${COMMIT_SUBJECT:?}"',
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_init_runtime_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 ARM64 init runtime repair diff contract\n"
        end = "# END exact v4.03.2 ARM64 init runtime repair diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_init_runtime_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_init_runtime_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_init_runtime_expected_subject="
        subject_assignment = (
            'v4032_init_runtime_subject="$(git log -1 --format=%s '
            '"${v4032_init_runtime_ref}")"'
        )
        end = (
            'read -r -a v4032_init_runtime_head_line <<< '
            '"$(git rev-list --parents -n 1 '
            '"${v4032_init_runtime_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment,
            'v4032_init_runtime_subject="${COMMIT_SUBJECT:?}"',
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_stabilization_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 ARM64 lifecycle stabilization diff contract\n"
        )
        end = "# END exact v4.03.2 ARM64 lifecycle stabilization diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_stabilization_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_stabilization_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_stabilization_expected_subject="
        subject_assignment = (
            'v4032_stabilization_subject="$(git log -1 --format=%s '
            '"${v4032_stabilization_ref}")"'
        )
        end = (
            'read -r -a v4032_stabilization_head_line <<< '
            '"$(git rev-list --parents -n 1 '
            '"${v4032_stabilization_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment,
            'v4032_stabilization_subject="${COMMIT_SUBJECT:?}"',
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_local_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 final qualification repair diff contract\n"
        end = "# END exact v4.03.2 final qualification repair diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_local_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_local_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_local_expected_subject="
        subject_assignment = (
            'v4032_local_subject="$(git log -1 --format=%s '
            '"${v4032_local_ref}")"'
        )
        end = (
            'read -r -a v4032_local_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_local_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_local_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_runc_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 ARM64 runc pin diff contract\n"
        end = "# END exact v4.03.2 ARM64 runc pin diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_runc_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_runc_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_runc_expected_subject="
        subject_assignment = (
            'v4032_runc_subject="$(git log -1 --format=%s '
            '"${v4032_runc_ref}")"'
        )
        end = (
            'read -r -a v4032_runc_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_runc_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_runc_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_runtime_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = (
            "# BEGIN exact v4.03.2 ARM64 OCI runtime resolution diff contract\n"
        )
        end = "# END exact v4.03.2 ARM64 OCI runtime resolution diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_runtime_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_runtime_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_runtime_expected_subject="
        subject_assignment = (
            'v4032_runtime_subject="$(git log -1 --format=%s '
            '"${v4032_runtime_ref}")"'
        )
        end = (
            'read -r -a v4032_runtime_head_line <<< '
            '"$(git rev-list --parents -n 1 "${v4032_runtime_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_runtime_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def exact_v4032_arm64_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 ARM64 Podman path repair diff contract\n"
        end = "# END exact v4.03.2 ARM64 Podman path repair diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_arm64_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_arm64_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_arm64_expected_subject="
        subject_assignment = (
            'v4032_arm64_subject="$(git log -1 --format=%s '
            '"${v4032_arm64_ref}")"'
        )
        end = (
            'read -r -a v4032_arm64_head_line <<< "$(git rev-list --parents -n 1 '
            '"${v4032_arm64_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(subject_assignment), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            subject_assignment, 'v4032_arm64_subject="${COMMIT_SUBJECT:?}"'
        )
        return "set -euo pipefail\n" + fragment

    def make_v4032_regular_diff_repository(
        self,
        name: str,
        relative_paths: tuple[str, ...],
        mutation: str | None,
    ) -> Path:
        repository = self.root / name
        repository.mkdir()
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "Release Gate Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                repository,
                "config",
                "user.email",
                "release-gate@example.invalid",
            ],
            check=True,
        )
        paths = [repository / relative_path for relative_path in relative_paths]
        for path in paths:
            self.write_file(path, b"reviewed parent\n")
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "reviewed parent"],
            check=True,
        )
        for path in paths:
            path.write_bytes(b"reviewed repair\n")
        if mutation == "extra file":
            self.write_file(repository / "unauthorized.txt", b"unexpected\n")
        elif mutation == "unchanged file":
            paths[-1].write_bytes(b"reviewed parent\n")
        elif mutation == "mode":
            paths[0].chmod(0o755)
        elif mutation == "symlink":
            paths[1].unlink()
            paths[1].symlink_to("unauthorized-target")
        elif mutation == "rename":
            paths[-1].rename(paths[-1].with_name("renamed-" + paths[-1].name))
        elif mutation == "delete":
            paths[-1].unlink()
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "reviewed repair"],
            check=True,
        )
        return repository

    def assert_exact_subject_gate(
        self, script: str, cases: dict[str, tuple[str, bool]]
    ) -> None:
        for name, (subject, accepted) in cases.items():
            with self.subTest(name=name):
                environment = dict(os.environ)
                environment["COMMIT_SUBJECT"] = subject
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=REPOSITORY,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def assert_regular_diff_gate(
        self, script: str, name_prefix: str, relative_paths: tuple[str, ...]
    ) -> None:
        mutations = (
            None,
            "extra file",
            "unchanged file",
            "mode",
            "symlink",
            "rename",
            "delete",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation or "exact"):
                repository = self.make_v4032_regular_diff_repository(
                    f"{name_prefix}-{index}", relative_paths, mutation
                )
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=repository,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if mutation is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )

    def exact_v4032_fix_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        begin = "# BEGIN exact v4.03.2 preserved-version recovery diff contract\n"
        end = "# END exact v4.03.2 preserved-version recovery diff contract"
        self.assertEqual(block.count(begin), 1)
        self.assertEqual(block.count(end), 1)
        return (
            "set -euo pipefail\nv4032_repair_ref=HEAD\n"
            + block.split(begin, 1)[1].split(end, 1)[0]
        )

    def v4032_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        block = self.v4032_recovery_blocks(workflow)[0]
        start = "v4032_expected_subject="
        end = (
            'read -r -a v4032_head_line <<< "$(git rev-list --parents -n 1 '
            '"${v4032_repair_ref}")"'
        )
        self.assertEqual(block.count(start), 1)
        self.assertEqual(block.count(end), 1)
        fragment = start + block.split(start, 1)[1].split(end, 1)[0]
        fragment = fragment.replace(
            'v4032_repair_subject="$(git log -1 --format=%s '
            '"${v4032_repair_ref}")"',
            'v4032_repair_subject="${COMMIT_SUBJECT:?}"',
        )
        return "set -euo pipefail\n" + fragment

    def make_v4032_fix_diff_repository(
        self, name: str, mutation: str | None
    ) -> Path:
        repository = self.root / name
        repository.mkdir()
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "Release Gate Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                repository,
                "config",
                "user.email",
                "release-gate@example.invalid",
            ],
            check=True,
        )
        paths = [
            repository / ".github/workflows/package.yml",
            repository / ".github/workflows/release-manager.yml",
            repository / ".github/workflows/release-qualification.yml",
            repository / "build_packages.sh",
            repository / "scripts/ci/package_lifecycle_contract_test.py",
            repository / "scripts/ci/package_lifecycle_lab.py",
            repository / "scripts/ci/package_lifecycle_lab_test.py",
            repository / "scripts/ci/package_webtui_retirement.sh",
            repository / "scripts/ci/release_gate_test.py",
            repository / "scripts/ci/release_qualification_workflow_test.py",
            repository / "src/core/syswarden-cli/pkg/integration/waf_logs_linux.go",
            repository
            / "src/core/syswarden-cli/pkg/integration/waf_logs_linux_test.go",
            repository
            / "src/core/syswarden-cli/pkg/security/hardening_linux_helpers.go",
            repository
            / "src/core/syswarden-cli/pkg/security/hardening_linux_test.go",
            repository
            / "src/core/syswarden-cli/pkg/system/firewall_optimizer.go",
            repository
            / "src/core/syswarden-cli/pkg/system/firewall_optimizer_test.go",
            repository / "src/core/syswarden-cli/pkg/system/service_linux.go",
            repository / "src/core/syswarden-cli/pkg/system/service_linux_test.go",
            repository / "src/core/syswarden-cli/pkg/system/uninstall_linux.go",
            repository
            / "src/core/syswarden-cli/pkg/system/uninstall_prepare_linux_test.go",
        ]
        for path in paths:
            self.write_file(path, b"reviewed parent\n")
        (repository / "build_packages.sh").chmod(0o755)
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "reviewed parent"],
            check=True,
        )
        for path in paths:
            path.write_bytes(b"reviewed qualification repair\n")
        if mutation == "extra file":
            self.write_file(repository / "unauthorized.txt", b"unexpected\n")
        elif mutation == "unchanged file":
            paths[3].write_bytes(b"reviewed parent\n")
        elif mutation == "mode":
            paths[0].chmod(0o755)
        elif mutation == "executable mode":
            (repository / "build_packages.sh").chmod(0o644)
        elif mutation == "symlink":
            paths[1].unlink()
            paths[1].symlink_to("unauthorized-target")
        elif mutation == "rename":
            paths[2].rename(paths[2].with_name("renamed_release_gate_test.py"))
        elif mutation == "delete":
            paths[3].unlink()
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                repository,
                "commit",
                "-q",
                "-m",
                "reviewed qualification repair",
            ],
            check=True,
        )
        return repository

    def exact_second_fix_diff_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        script = workflow_step_scripts(
            workflow, "Validate Tag, Source, Changelog, and Main Ancestry"
        )[0]
        begin = "# BEGIN exact second preserved-version fix diff contract\n"
        end = "# END exact second preserved-version fix diff contract"
        self.assertEqual(script.count(begin), 1)
        self.assertEqual(script.count(end), 1)
        return "set -euo pipefail\n" + script.split(begin, 1)[1].split(end, 1)[0]

    def second_fix_subject_gate_script(self) -> str:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        script = workflow_step_scripts(
            workflow, "Validate Tag, Source, Changelog, and Main Ancestry"
        )[0]
        start = "second_fix_subject_pattern="
        end = 'previous_fix_parent_sha="$(git rev-parse HEAD^^)"'
        self.assertEqual(script.count(start), 1)
        self.assertEqual(script.count(end), 1)
        fragment = start + script.split(start, 1)[1].split(end, 1)[0]
        return 'set -euo pipefail\ncommit_subject="${COMMIT_SUBJECT:?}"\n' + fragment

    def make_second_fix_diff_repository(self, name: str, mutation: str | None) -> Path:
        repository = self.root / name
        repository.mkdir()
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "Release Gate Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repository, "config", "user.email", "release-gate@example.invalid"],
            check=True,
        )
        paths = [
            repository / ".github/workflows/release-manager.yml",
            repository / "scripts/ci/release_gate_test.py",
            repository
            / "src/core/syswarden-cli/pkg/firewall/firewall_linux_golden_test.go",
        ]
        for path in paths:
            self.write_file(path, b"reviewed parent\n")
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "reviewed parent"],
            check=True,
        )
        for path in paths:
            path.write_bytes(b"reviewed follow-up\n")
        if mutation == "extra file":
            self.write_file(repository / "unauthorized.txt", b"unexpected\n")
        elif mutation == "mode":
            paths[0].chmod(0o755)
        elif mutation == "symlink":
            paths[1].unlink()
            paths[1].symlink_to("unauthorized-target")
        elif mutation == "rename":
            paths[2].rename(paths[2].with_name("renamed_golden_test.go"))
        subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-q", "-m", "reviewed fix"],
            check=True,
        )
        return repository

    def test_release_manager_v4032_arm64_attestation_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_arm64_attestation_subject_gate_script(),
            {
                "valid": (
                    "Qualification : stabilize ARM64 crun version attestation (#111)",
                    True,
                ),
                "bare": (
                    "Qualification : stabilize ARM64 crun version attestation",
                    False,
                ),
                "previous pull request": (
                    "Qualification : stabilize ARM64 crun version attestation (#110)",
                    False,
                ),
                "wrong verb": (
                    "Qualification : repair ARM64 crun version attestation (#111)",
                    False,
                ),
                "wrong scope": (
                    "Qualification : stabilize ARM64 runc version attestation (#111)",
                    False,
                ),
                "trailing space": (
                    "Qualification : stabilize ARM64 crun version attestation (#111) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_arm64_attestation_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_arm64_attestation_diff_script(),
            "v4032-arm64-attestation-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "README.md",
                "assets/syswarden_hero.svg",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
                "scripts/ci/workflow_required_checks_test.py",
            ),
        )

    def test_release_manager_v4032_docs_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_docs_subject_gate_script(),
            {
                "valid": (
                    "Security : preserve read-only config preflight and centralize v4.03.2 docs (#110)",
                    True,
                ),
                "bare": (
                    "Security : preserve read-only config preflight and centralize v4.03.2 docs",
                    False,
                ),
                "previous pull request": (
                    "Security : preserve read-only config preflight and centralize v4.03.2 docs (#109)",
                    False,
                ),
                "wrong version": (
                    "Security : preserve read-only config preflight and centralize v4.03.3 docs (#110)",
                    False,
                ),
                "wrong scope": (
                    "Security : weaken config preflight and centralize v4.03.2 docs (#110)",
                    False,
                ),
                "trailing space": (
                    "Security : preserve read-only config preflight and centralize v4.03.2 docs (#110) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_docs_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_docs_diff_script(),
            "v4032-docs-diff",
            (
                ".github/workflows/release-manager.yml",
                "README.md",
                "assets/syswarden_hero.svg",
                "scripts/ci/documentation_contract.json",
                "scripts/ci/documentation_gate.py",
                "scripts/ci/documentation_gate_test.py",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/workflow_required_checks_test.py",
                "src/core/syswarden-cli/cmd/root.go",
                "src/core/syswarden-cli/cmd/root_config_guard_test.go",
            ),
        )

    def test_release_manager_v4032_systemd_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_systemd_subject_gate_script(),
            {
                "valid": (
                    "Qualification : seal systemd-capable ARM64 crun runtime (#109)",
                    True,
                ),
                "bare": (
                    "Qualification : seal systemd-capable ARM64 crun runtime",
                    False,
                ),
                "previous pull request": (
                    "Qualification : seal systemd-capable ARM64 crun runtime (#108)",
                    False,
                ),
                "wrong verb": (
                    "Qualification : repair systemd-capable ARM64 crun runtime (#109)",
                    False,
                ),
                "previous scope": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#109)",
                    False,
                ),
                "trailing space": (
                    "Qualification : seal systemd-capable ARM64 crun runtime (#109) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_systemd_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_systemd_diff_script(),
            "v4032-systemd-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
            ),
        )

    def test_release_manager_v4032_cli_toml_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_cli_toml_subject_gate_script(),
            {
                "valid": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-cli (#105)",
                    True,
                ),
                "bare": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-cli",
                    False,
                ),
                "wrong pull request": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-cli (#106)",
                    False,
                ),
                "wrong module": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-core (#105)",
                    False,
                ),
                "trailing space": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-cli (#105) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_cli_toml_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_cli_toml_diff_script(),
            "v4032-cli-toml-diff",
            (
                "src/core/syswarden-cli/go.mod",
                "src/core/syswarden-cli/go.sum",
            ),
        )

    def test_release_manager_v4032_core_toml_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_core_toml_subject_gate_script(),
            {
                "valid": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-core (#106)",
                    True,
                ),
                "bare": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-core",
                    False,
                ),
                "wrong pull request": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-core (#105)",
                    False,
                ),
                "wrong module": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-cli (#106)",
                    False,
                ),
                "trailing space": (
                    "Bump github.com/pelletier/go-toml/v2 in "
                    "/src/core/syswarden-core (#106) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_core_toml_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_core_toml_diff_script(),
            "v4032-core-toml-diff",
            (
                "src/core/syswarden-core/go.mod",
                "src/core/syswarden-core/go.sum",
            ),
        )

    def test_release_manager_v4032_dependency_squashes_match_local_objects(
        self,
    ) -> None:
        contracts = (
            (
                "540bab73a477c76d6301d276383602db06d36acd",
                "4eacbae34561ae09611a7adb1f78717ca56e52a6",
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-cli (#105)",
                {
                    "src/core/syswarden-cli/go.mod": (
                        "66f6623dabd59b30d48906180ab51faf2b3de617",
                        "ff807092dd11a281e8cc08380bc5152aeb55ac61",
                    ),
                    "src/core/syswarden-cli/go.sum": (
                        "c4f38878c8a489144a549a19de19f49fd7e600b3",
                        "ce676e05fabca3828da4ef31f5e82ee0ce8a7223",
                    ),
                },
            ),
            (
                "4eacbae34561ae09611a7adb1f78717ca56e52a6",
                "3513acaee928cdd0aa235024f6ebfc5b2efe1dff",
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-core (#106)",
                {
                    "src/core/syswarden-core/go.mod": (
                        "26e4105948f496ba8cbf8efea067c252c2b4d94d",
                        "3181e179994324ae7ff5eb769051b529a9bc7a39",
                    ),
                    "src/core/syswarden-core/go.sum": (
                        "b7e67fd6352f003613d3f4c63bc99203172d2449",
                        "227d3d731718cf79ae9eb7e9841a52db283ba050",
                    ),
                },
            ),
        )
        for commit, parent, subject, paths in contracts:
            with self.subTest(commit=commit):
                self.assertEqual(
                    subprocess.run(
                        ["git", "rev-parse", f"{commit}^"],
                        cwd=REPOSITORY,
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip(),
                    parent,
                )
                self.assertEqual(
                    subprocess.run(
                        ["git", "log", "-1", "--format=%s", commit],
                        cwd=REPOSITORY,
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip(),
                    subject,
                )
                for path, (parent_blob, commit_blob) in paths.items():
                    for ref, expected_blob in (
                        (parent, parent_blob),
                        (commit, commit_blob),
                    ):
                        entry = subprocess.run(
                            ["git", "ls-tree", ref, "--", path],
                            cwd=REPOSITORY,
                            check=True,
                            capture_output=True,
                            text=True,
                        ).stdout.strip()
                        self.assertEqual(
                            entry,
                            f"100644 blob {expected_blob}\t{path}",
                        )

    def test_release_manager_v4032_crun_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_crun_subject_gate_script(),
            {
                "valid": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#108)",
                    True,
                ),
                "bare": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun",
                    False,
                ),
                "previous pull request": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#107)",
                    False,
                ),
                "next pull request": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#109)",
                    False,
                ),
                "wrong verb": (
                    "Qualification : repair v4.03.2 ARM64 lifecycle under crun (#108)",
                    False,
                ),
                "wrong runtime": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under runc (#108)",
                    False,
                ),
                "previous scope": (
                    "Qualification : restore v4.03.2 ARM64 crun runtime (#108)",
                    False,
                ),
                "trailing space": (
                    "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#108) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_crun_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_crun_diff_script(),
            "v4032-crun-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
                "src/core/syswarden-cli/pkg/security/hardening_linux_test.go",
                "src/core/syswarden-cli/pkg/security/os_hardening_linux.go",
            ),
        )

    def test_release_manager_v4032_compliance_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_compliance_subject_gate_script(),
            {
                "valid": (
                    "Security : enforce v4.03.2 compliance release verdict (#104)",
                    True,
                ),
                "bare": (
                    "Security : enforce v4.03.2 compliance release verdict",
                    False,
                ),
                "previous pull request": (
                    "Security : enforce v4.03.2 compliance release verdict (#103)",
                    False,
                ),
                "next pull request": (
                    "Security : enforce v4.03.2 compliance release verdict (#105)",
                    False,
                ),
                "wrong verb": (
                    "Security : relax v4.03.2 compliance release verdict (#104)",
                    False,
                ),
                "trailing space": (
                    "Security : enforce v4.03.2 compliance release verdict (#104) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_compliance_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_compliance_diff_script(),
            "v4032-compliance-diff",
            (
                ".github/dependabot.yml",
                ".github/workflows/compliance.yml",
                ".github/workflows/release-manager.yml",
                ".plumber.yaml",
                "CONTRIBUTING.md",
                "README.md",
                "assets/syswarden_architecture.svg",
                "assets/syswarden_bunkerweb_integration.svg",
                "assets/syswarden_hero.svg",
                "scripts/ci/release_gate.py",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/workflow_required_checks_test.py",
            ),
        )

    def test_release_manager_v4032_init_runtime_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_init_runtime_subject_gate_script(),
            {
                "valid": (
                    "Qualification : repair v4.03.2 ARM64 init runtime (#103)",
                    True,
                ),
                "bare": (
                    "Qualification : repair v4.03.2 ARM64 init runtime",
                    False,
                ),
                "previous pull request": (
                    "Qualification : repair v4.03.2 ARM64 init runtime (#102)",
                    False,
                ),
                "next pull request": (
                    "Qualification : repair v4.03.2 ARM64 init runtime (#104)",
                    False,
                ),
                "wrong verb": (
                    "Qualification : stabilize v4.03.2 ARM64 init runtime (#103)",
                    False,
                ),
                "trailing space": (
                    "Qualification : repair v4.03.2 ARM64 init runtime (#103) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_init_runtime_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_init_runtime_diff_script(),
            "v4032-init-runtime-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/package_lifecycle_lab.py",
                "scripts/ci/package_lifecycle_lab_test.py",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
                "src/core/syswarden-cli/pkg/integration/waf_logs_linux.go",
                "src/core/syswarden-cli/pkg/integration/waf_logs_linux_test.go",
            ),
        )

    def test_release_manager_v4032_stabilization_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_stabilization_subject_gate_script(),
            {
                "valid": (
                    "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence (#102)",
                    True,
                ),
                "bare": (
                    "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence",
                    False,
                ),
                "previous pull request": (
                    "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence (#101)",
                    False,
                ),
                "next pull request": (
                    "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence (#103)",
                    False,
                ),
                "wrong verb": (
                    "Qualification : repair v4.03.2 ARM64 lifecycle evidence (#102)",
                    False,
                ),
                "trailing space": (
                    "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence (#102) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_stabilization_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_stabilization_diff_script(),
            "v4032-stabilization-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/package_lifecycle_lab.py",
                "scripts/ci/package_lifecycle_lab_test.py",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
                "src/core/syswarden-cli/pkg/integration/waf_logs_linux.go",
                "src/core/syswarden-cli/pkg/integration/waf_logs_linux_test.go",
            ),
        )

    def test_release_manager_v4032_local_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_local_subject_gate_script(),
            {
                "valid": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling (#101)",
                    True,
                ),
                "bare": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling",
                    False,
                ),
                "double pull request suffix": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling (#101) (#101)",
                    False,
                ),
                "previous pull request": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling (#100)",
                    False,
                ),
                "next pull request": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling (#102)",
                    False,
                ),
                "wrong version": (
                    "Qualification : repair v4.03.3 ARM64 lab and config root handling (#101)",
                    False,
                ),
                "trailing space": (
                    "Qualification : repair v4.03.2 ARM64 lab and config root handling (#101) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_local_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_local_diff_script(),
            "v4032-local-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
                "src/core/syswarden-cli/config/config_contract_test.go",
                "src/core/syswarden-cli/config/config_loader.go",
            ),
        )

    def test_release_manager_v4032_runc_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_runc_subject_gate_script(),
            {
                "valid": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path (#99)",
                    True,
                ),
                "bare": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path",
                    False,
                ),
                "double pull request suffix": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path (#99) (#99)",
                    False,
                ),
                "previous pull request": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path (#98)",
                    False,
                ),
                "next pull request": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path (#100)",
                    False,
                ),
                "wrong version": (
                    "Qualification : pin v4.03.3 ARM64 runc runtime path (#99)",
                    False,
                ),
                "trailing space": (
                    "Qualification : pin v4.03.2 ARM64 runc runtime path (#99) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_runc_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_runc_diff_script(),
            "v4032-runc-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
            ),
        )

    def test_release_manager_v4032_runtime_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_runtime_subject_gate_script(),
            {
                "valid": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#98)",
                    True,
                ),
                "bare": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution",
                    False,
                ),
                "double pull request suffix": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#98) (#98)",
                    False,
                ),
                "previous pull request": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#97)",
                    False,
                ),
                "next pull request": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#99)",
                    False,
                ),
                "wrong version": (
                    "Qualification : repair v4.03.3 ARM64 OCI runtime resolution (#98)",
                    False,
                ),
                "trailing space": (
                    "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#98) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_runtime_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_runtime_diff_script(),
            "v4032-runtime-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
            ),
        )

    def test_release_manager_v4032_arm64_subject_is_exact_github_squash(
        self,
    ) -> None:
        self.assert_exact_subject_gate(
            self.v4032_arm64_subject_gate_script(),
            {
                "valid": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract (#97)",
                    True,
                ),
                "bare": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract",
                    False,
                ),
                "double pull request suffix": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract (#97) (#97)",
                    False,
                ),
                "previous pull request": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract (#96)",
                    False,
                ),
                "next pull request": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract (#98)",
                    False,
                ),
                "wrong version": (
                    "Qualification : repair v4.03.3 native ARM64 Podman path contract (#97)",
                    False,
                ),
                "trailing space": (
                    "Qualification : repair v4.03.2 native ARM64 Podman path contract (#97) ",
                    False,
                ),
            },
        )

    def test_release_manager_v4032_arm64_diff_rejects_git_shape_mutations(
        self,
    ) -> None:
        self.assert_regular_diff_gate(
            self.exact_v4032_arm64_diff_script(),
            "v4032-arm64-diff",
            (
                ".github/workflows/release-manager.yml",
                ".github/workflows/release-qualification.yml",
                "scripts/ci/release_gate_test.py",
                "scripts/ci/release_qualification_workflow_test.py",
            ),
        )

    def test_release_manager_bounds_v4032_repair_to_exact_reviewed_chain(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        self.assert_v4032_preserved_version_recovery_contract(workflow)

    def test_release_manager_v4032_contract_rejects_mutations(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        mutations = {
            "release tag": workflow.replace(
                'if [[ "${RELEASE_TAG}" == "v4.03.2" ]]; then',
                'if [[ "${RELEASE_TAG}" == "v4.03.3" ]]; then',
            ),
            "ARM64 attestation parent resolution": workflow.replace(
                'v4032_arm64_attestation_parent_sha="$(git rev-parse HEAD^)"',
                'v4032_arm64_attestation_parent_sha="$(git rev-parse HEAD^^)"',
            ),
            "exact ARM64 attestation parent": workflow.replace(
                "8e3ef2a0f50e4833f3078a7a09c2d07bf984f6ef",
                "9e3ef2a0f50e4833f3078a7a09c2d07bf984f6ef",
            ),
            "ARM64 attestation canonical subject": workflow.replace(
                "Qualification : stabilize ARM64 crun version attestation (#111)",
                "Qualification : repair ARM64 crun version attestation (#111)",
            ),
            "ARM64 attestation subject source": workflow.replace(
                'commit_subject="$(git log -1 --format=%s HEAD)"',
                'commit_subject="$(git log -1 --format=%s HEAD^)"',
            ),
            "ARM64 attestation linear head": workflow.replace(
                'v4032_arm64_attestation_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
                'v4032_arm64_attestation_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD^)"',
            ),
            "documentation reference": workflow.replace(
                "v4032_docs_ref=HEAD^",
                "v4032_docs_ref=HEAD^^",
            ),
            "documentation parent resolution": workflow.replace(
                'v4032_docs_parent_sha="$(git rev-parse '
                '"${v4032_docs_ref}^")"',
                'v4032_docs_parent_sha="$(git rev-parse '
                '"${v4032_docs_ref}^^")"',
            ),
            "exact documentation parent": workflow.replace(
                "3d95b9e53fabf01f73ed36b7fb7dcdaaec0dc4a0",
                "4d95b9e53fabf01f73ed36b7fb7dcdaaec0dc4a0",
            ),
            "documentation canonical subject": workflow.replace(
                "Security : preserve read-only config preflight and centralize v4.03.2 docs (#110)",
                "Security : preserve read-only config preflight and centralize v4.03.3 docs (#110)",
            ),
            "documentation subject source": workflow.replace(
                'v4032_docs_subject="$(git log -1 --format=%s '
                '"${v4032_docs_ref}")"',
                'v4032_docs_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "documentation linear head": workflow.replace(
                'v4032_docs_head_line <<< '
                '"$(git rev-list --parents -n 1 "${v4032_docs_ref}")"',
                'v4032_docs_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "systemd reference": workflow.replace(
                'v4032_systemd_ref="${v4032_docs_ref}^"',
                'v4032_systemd_ref="${v4032_docs_ref}^^"',
            ),
            "systemd parent resolution": workflow.replace(
                'v4032_systemd_parent_sha="$(git rev-parse '
                '"${v4032_systemd_ref}^")"',
                'v4032_systemd_parent_sha="$(git rev-parse '
                '"${v4032_systemd_ref}^^")"',
            ),
            "exact systemd parent": workflow.replace(
                "540bab73a477c76d6301d276383602db06d36acd",
                "640bab73a477c76d6301d276383602db06d36acd",
            ),
            "systemd canonical subject": workflow.replace(
                "Qualification : seal systemd-capable ARM64 crun runtime (#109)",
                "Qualification : repair systemd-capable ARM64 crun runtime (#109)",
            ),
            "systemd subject source": workflow.replace(
                'v4032_systemd_subject="$(git log -1 --format=%s '
                '"${v4032_systemd_ref}")"',
                'v4032_systemd_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "systemd linear head": workflow.replace(
                'v4032_systemd_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_systemd_ref}")"',
                'v4032_systemd_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "CLI dependency reference": workflow.replace(
                'v4032_cli_toml_ref="${v4032_systemd_ref}^"',
                'v4032_cli_toml_ref="${v4032_systemd_ref}^^"',
            ),
            "CLI dependency parent resolution": workflow.replace(
                'v4032_cli_toml_parent_sha="$(git rev-parse '
                '"${v4032_cli_toml_ref}^")"',
                'v4032_cli_toml_parent_sha="$(git rev-parse '
                '"${v4032_cli_toml_ref}^^")"',
            ),
            "exact CLI dependency parent": workflow.replace(
                "4eacbae34561ae09611a7adb1f78717ca56e52a6",
                "5eacbae34561ae09611a7adb1f78717ca56e52a6",
            ),
            "CLI dependency canonical subject": workflow.replace(
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-cli (#105)",
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-cli (#106)",
            ),
            "CLI dependency subject source": workflow.replace(
                'v4032_cli_toml_subject="$(git log -1 --format=%s '
                '"${v4032_cli_toml_ref}")"',
                'v4032_cli_toml_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "CLI dependency linear head": workflow.replace(
                'v4032_cli_toml_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_cli_toml_ref}")"',
                'v4032_cli_toml_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "core dependency reference": workflow.replace(
                'v4032_core_toml_ref="${v4032_cli_toml_ref}^"',
                'v4032_core_toml_ref="${v4032_cli_toml_ref}^^"',
            ),
            "core dependency parent resolution": workflow.replace(
                'v4032_core_toml_parent_sha="$(git rev-parse '
                '"${v4032_core_toml_ref}^")"',
                'v4032_core_toml_parent_sha="$(git rev-parse '
                '"${v4032_core_toml_ref}^^")"',
            ),
            "exact core dependency parent": workflow.replace(
                "3513acaee928cdd0aa235024f6ebfc5b2efe1dff",
                "4513acaee928cdd0aa235024f6ebfc5b2efe1dff",
            ),
            "core dependency canonical subject": workflow.replace(
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-core (#106)",
                "Bump github.com/pelletier/go-toml/v2 in "
                "/src/core/syswarden-core (#105)",
            ),
            "core dependency subject source": workflow.replace(
                'v4032_core_toml_subject="$(git log -1 --format=%s '
                '"${v4032_core_toml_ref}")"',
                'v4032_core_toml_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "core dependency linear head": workflow.replace(
                'v4032_core_toml_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_core_toml_ref}")"',
                'v4032_core_toml_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "crun reference": workflow.replace(
                'v4032_crun_ref="${v4032_core_toml_ref}^"',
                'v4032_crun_ref="${v4032_core_toml_ref}^^"',
            ),
            "crun parent resolution": workflow.replace(
                'v4032_crun_parent_sha="$(git rev-parse '
                '"${v4032_crun_ref}^")"',
                'v4032_crun_parent_sha="$(git rev-parse '
                '"${v4032_crun_ref}^^")"',
            ),
            "exact crun parent": workflow.replace(
                "b74756b71e26e39b98c7fa60b65a3486adfde3e8",
                "a74756b71e26e39b98c7fa60b65a3486adfde3e8",
            ),
            "crun canonical subject": workflow.replace(
                "Qualification : restore v4.03.2 ARM64 lifecycle under crun (#108)",
                "Qualification : repair v4.03.2 ARM64 lifecycle under crun (#108)",
            ),
            "crun subject source": workflow.replace(
                'v4032_crun_subject="$(git log -1 --format=%s '
                '"${v4032_crun_ref}")"',
                'v4032_crun_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "crun linear head": workflow.replace(
                'v4032_crun_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_crun_ref}")"',
                'v4032_crun_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "compliance reference": workflow.replace(
                'v4032_compliance_ref="${v4032_crun_ref}^"',
                'v4032_compliance_ref="${v4032_crun_ref}^^"',
            ),
            "compliance parent resolution": workflow.replace(
                'v4032_compliance_parent_sha="$(git rev-parse '
                '"${v4032_compliance_ref}^")"',
                'v4032_compliance_parent_sha="$(git rev-parse '
                '"${v4032_compliance_ref}^^")"',
            ),
            "exact compliance parent": workflow.replace(
                "ba1e853c11033f6abcd674dc7c251848f347e55b",
                "ca1e853c11033f6abcd674dc7c251848f347e55b",
            ),
            "compliance canonical subject": workflow.replace(
                "Security : enforce v4.03.2 compliance release verdict (#104)",
                "Security : relax v4.03.2 compliance release verdict (#104)",
            ),
            "compliance subject source": workflow.replace(
                'v4032_compliance_subject="$(git log -1 --format=%s '
                '"${v4032_compliance_ref}")"',
                'v4032_compliance_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "compliance linear head": workflow.replace(
                'v4032_compliance_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_compliance_ref}")"',
                'v4032_compliance_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "init runtime reference": workflow.replace(
                'v4032_init_runtime_ref="${v4032_compliance_ref}^"',
                'v4032_init_runtime_ref="${v4032_compliance_ref}^^"',
            ),
            "init runtime parent resolution": workflow.replace(
                'v4032_init_runtime_parent_sha="$(git rev-parse '
                '"${v4032_init_runtime_ref}^")"',
                'v4032_init_runtime_parent_sha="$(git rev-parse '
                '"${v4032_init_runtime_ref}^^")"',
            ),
            "exact init runtime parent": workflow.replace(
                "97ebc9991fdeec293abd04444ad6600f11c30ee4",
                "87ebc9991fdeec293abd04444ad6600f11c30ee4",
            ),
            "init runtime canonical subject": workflow.replace(
                "Qualification : repair v4.03.2 ARM64 init runtime (#103)",
                "Qualification : arbitrary v4.03.2 ARM64 init runtime (#103)",
            ),
            "init runtime subject source": workflow.replace(
                'v4032_init_runtime_subject="$(git log -1 --format=%s '
                '"${v4032_init_runtime_ref}")"',
                'v4032_init_runtime_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "init runtime linear head": workflow.replace(
                'v4032_init_runtime_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_init_runtime_ref}")"',
                'v4032_init_runtime_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "stabilization reference": workflow.replace(
                'v4032_stabilization_ref="${v4032_init_runtime_ref}^"',
                'v4032_stabilization_ref="${v4032_init_runtime_ref}^^"',
            ),
            "stabilization parent resolution": workflow.replace(
                'v4032_stabilization_parent_sha="$(git rev-parse '
                '"${v4032_stabilization_ref}^")"',
                'v4032_stabilization_parent_sha="$(git rev-parse '
                '"${v4032_stabilization_ref}^^")"',
            ),
            "exact stabilization parent": workflow.replace(
                "41d7a7da2895f5d3949cc63f3e45308c03f7f93a",
                "51d7a7da2895f5d3949cc63f3e45308c03f7f93a",
            ),
            "stabilization canonical subject": workflow.replace(
                "Qualification : stabilize v4.03.2 ARM64 lifecycle evidence (#102)",
                "Qualification : arbitrary v4.03.2 stabilization (#102)",
            ),
            "stabilization subject source": workflow.replace(
                'v4032_stabilization_subject="$(git log -1 --format=%s '
                '"${v4032_stabilization_ref}")"',
                'v4032_stabilization_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "stabilization linear head": workflow.replace(
                'v4032_stabilization_head_line <<< '
                '"$(git rev-list --parents -n 1 '
                '"${v4032_stabilization_ref}")"',
                'v4032_stabilization_head_line <<< '
                '"$(git rev-list --parents -n 1 HEAD)"',
            ),
            "local reference": workflow.replace(
                'v4032_local_ref="${v4032_stabilization_ref}^"',
                'v4032_local_ref="${v4032_stabilization_ref}^^"',
            ),
            "local parent resolution": workflow.replace(
                'v4032_local_parent_sha="$(git rev-parse '
                '"${v4032_local_ref}^")"',
                'v4032_local_parent_sha="$(git rev-parse '
                '"${v4032_local_ref}^^")"',
            ),
            "exact local parent": workflow.replace(
                "93bb85a657d8f8927cd6617c4105653732c59114",
                "a3bb85a657d8f8927cd6617c4105653732c59114",
            ),
            "local canonical subject": workflow.replace(
                "Qualification : repair v4.03.2 ARM64 lab and config root handling (#101)",
                "Qualification : arbitrary v4.03.2 final repair (#101)",
            ),
            "local subject source": workflow.replace(
                'v4032_local_subject="$(git log -1 --format=%s '
                '"${v4032_local_ref}")"',
                'v4032_local_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "local linear head": workflow.replace(
                'v4032_local_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_local_ref}")"',
                'v4032_local_head_line <<< "$(git rev-list --parents -n 1 HEAD)"',
            ),
            "runc reference": workflow.replace(
                'v4032_runc_ref="${v4032_local_ref}^"',
                'v4032_runc_ref="${v4032_local_ref}^^"',
            ),
            "runc parent resolution": workflow.replace(
                'v4032_runc_parent_sha="$(git rev-parse '
                '"${v4032_runc_ref}^")"',
                'v4032_runc_parent_sha="$(git rev-parse '
                '"${v4032_runc_ref}^^")"',
            ),
            "exact runc parent": workflow.replace(
                "d025f5ee7b1d453a64d11ea2f5afcab13fc01a97",
                "e025f5ee7b1d453a64d11ea2f5afcab13fc01a97",
            ),
            "runc canonical subject": workflow.replace(
                "Qualification : pin v4.03.2 ARM64 runc runtime path (#99)",
                "Qualification : arbitrary v4.03.2 ARM64 runc pin (#99)",
            ),
            "runc subject source": workflow.replace(
                'v4032_runc_subject="$(git log -1 --format=%s '
                '"${v4032_runc_ref}")"',
                'v4032_runc_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "runc linear head": workflow.replace(
                'v4032_runc_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_runc_ref}")"',
                'v4032_runc_head_line <<< "$(git rev-list --parents -n 1 HEAD)"',
            ),
            "runc message source": workflow.replace(
                'v4032_runc_commit_message="$(git log -1 --format=%B '
                '"${v4032_runc_ref}")"',
                'v4032_runc_commit_message="$(git log -1 --format=%B HEAD)"',
            ),
            "runc validation base": workflow.replace(
                '--base-ref "${v4032_runc_parent_sha}"', '--base-ref HEAD^'
            ),
            "runtime reference": workflow.replace(
                'v4032_runtime_ref="${v4032_runc_ref}^"',
                'v4032_runtime_ref="${v4032_runc_ref}^^"',
            ),
            "runtime parent resolution": workflow.replace(
                'v4032_runtime_parent_sha="$(git rev-parse '
                '"${v4032_runtime_ref}^")"',
                'v4032_runtime_parent_sha="$(git rev-parse '
                '"${v4032_runtime_ref}^^")"',
            ),
            "exact runtime parent": workflow.replace(
                "0e7fc0a3437d69cea8086abacd0a30e032a0579f",
                "1e7fc0a3437d69cea8086abacd0a30e032a0579f",
            ),
            "runtime canonical subject": workflow.replace(
                "Qualification : repair v4.03.2 ARM64 OCI runtime resolution (#98)",
                "Qualification : arbitrary v4.03.2 ARM64 OCI repair (#98)",
            ),
            "runtime linear head": workflow.replace(
                'v4032_runtime_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_runtime_ref}")"',
                'v4032_runtime_head_line <<< "$(git rev-list --parents -n 1 HEAD)"',
            ),
            "runtime subject source": workflow.replace(
                'v4032_runtime_subject="$(git log -1 --format=%s '
                '"${v4032_runtime_ref}")"',
                'v4032_runtime_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "runtime message source": workflow.replace(
                'v4032_runtime_commit_message="$(git log -1 --format=%B '
                '"${v4032_runtime_ref}")"',
                'v4032_runtime_commit_message="$(git log -1 --format=%B HEAD)"',
            ),
            "runtime validation base": workflow.replace(
                '--base-ref "${v4032_runtime_parent_sha}"', '--base-ref HEAD^'
            ),
            "ARM64 reference": workflow.replace(
                'v4032_arm64_ref="${v4032_runtime_ref}^"',
                'v4032_arm64_ref="${v4032_runtime_ref}^^"',
            ),
            "ARM64 parent resolution": workflow.replace(
                'v4032_arm64_parent_sha="$(git rev-parse '
                '"${v4032_arm64_ref}^")"',
                'v4032_arm64_parent_sha="$(git rev-parse '
                '"${v4032_arm64_ref}^^")"',
            ),
            "exact ARM64 parent": workflow.replace(
                "8387b3e8b96a3778b333504dc9c948dfe06777d5",
                "9387b3e8b96a3778b333504dc9c948dfe06777d5",
            ),
            "ARM64 canonical subject": workflow.replace(
                "Qualification : repair v4.03.2 native ARM64 Podman path contract (#97)",
                "Qualification : arbitrary v4.03.2 ARM64 Podman repair (#97)",
            ),
            "ARM64 subject source": workflow.replace(
                'v4032_arm64_subject="$(git log -1 --format=%s '
                '"${v4032_arm64_ref}")"',
                'v4032_arm64_subject="$(git log -1 --format=%s HEAD)"',
            ),
            "ARM64 linear head": workflow.replace(
                'v4032_arm64_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_arm64_ref}")"',
                'v4032_arm64_head_line <<< "$(git rev-list --parents -n 1 HEAD)"',
            ),
            "ARM64 validation base": workflow.replace(
                '--base-ref "${v4032_arm64_parent_sha}"', '--base-ref HEAD^'
            ),
            "parent resolution": workflow.replace(
                'v4032_parent_sha="$(git rev-parse "${v4032_repair_ref}^")"',
                'v4032_parent_sha="$(git rev-parse "${v4032_repair_ref}^^")"',
            ),
            "exact parent": workflow.replace(
                "3839d592467a4f92f24b613412d8d89bb6905251",
                "4839d592467a4f92f24b613412d8d89bb6905251",
            ),
            "canonical subject": workflow.replace(
                "Qualification : repair v4.03.2 package lifecycle qualification (#95)",
                "Qualification : arbitrary v4.03.2 repair (#95)",
            ),
            "linear head": workflow.replace(
                'v4032_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}")"',
                'v4032_head_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}^")"',
            ),
            "linear parent": workflow.replace(
                'v4032_parent_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}^")"',
                'v4032_parent_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}^^")"',
            ),
            "linear release": workflow.replace(
                'v4032_release_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}^^")"',
                'v4032_release_line <<< "$(git rev-list --parents -n 1 '
                '"${v4032_repair_ref}^")"',
            ),
            "grandparent resolution": workflow.replace(
                'v4032_grandparent_sha="$(git rev-parse '
                '"${v4032_repair_ref}^^")"',
                'v4032_grandparent_sha="$(git rev-parse '
                '"${v4032_repair_ref}^")"',
            ),
            "exact grandparent": workflow.replace(
                "3655abe045deffc669e0ba9c11a6e4cf17a317a5",
                "4655abe045deffc669e0ba9c11a6e4cf17a317a5",
            ),
            "release base resolution": workflow.replace(
                'v4032_release_base_sha="$(git rev-parse '
                '"${v4032_repair_ref}^^^")"',
                'v4032_release_base_sha="$(git rev-parse '
                '"${v4032_repair_ref}^^")"',
            ),
            "exact release base": workflow.replace(
                "f2270a2a8138f1f2b72a6200f6febbdc83fa5eaa",
                "e2270a2a8138f1f2b72a6200f6febbdc83fa5eaa",
            ),
            "allowlist": workflow.replace(
                ".github/workflows/release-qualification.yml",
                ".github/workflows/unauthorized.yml",
            ),
            "modified status": workflow.replace(
                'M ".github/workflows/release-qualification.yml"',
                'A ".github/workflows/release-qualification.yml"',
            ),
            "rename detection": workflow.replace(
                "--no-renames -z HEAD^ HEAD", "-z HEAD^ HEAD"
            ),
            "both trees": workflow.replace(
                "for tree_ref in HEAD^ HEAD; do", "for tree_ref in HEAD; do"
            ),
            "regular mode": workflow.replace('"100644"', '"100755"'),
            "executable mode selector": workflow.replace(
                '[[ "${fix_path}" == "build_packages.sh" ]]',
                '[[ "${fix_path}" == "unauthorized.sh" ]]',
            ),
            "executable mode": workflow.replace(
                'expected_mode="100755"', 'expected_mode="100644"'
            ),
            "regular blob": workflow.replace('"${tree_type}" != "blob"',
                                              '"${tree_type}" != "tree"'),
            "changelog identity": workflow.replace(
                "changelog.md", "changelog-rewritten.md"
            ),
            "version target identity": workflow.replace(
                "src/core/syswarden-cli/pkg/system/upgrade.go",
                "src/core/syswarden-cli/pkg/system/upgrade_rewritten.go",
            ),
            "parent message": workflow.replace(
                'v4032_parent_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}^")"',
                'v4032_parent_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}")"',
            ),
            "parent validation base": workflow.replace(
                '--base-ref "${v4032_grandparent_sha}"', '--base-ref HEAD^'
            ),
            "repair message": workflow.replace(
                'v4032_repair_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}")"',
                'v4032_repair_commit_message="$(git log -1 --format=%B HEAD)"',
            ),
            "repair validation base": workflow.replace(
                '--base-ref "${v4032_parent_sha}"', '--base-ref HEAD^'
            ),
            "release message": workflow.replace(
                'v4032_release_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}^^")"',
                'v4032_release_commit_message="$(git log -1 --format=%B '
                '"${v4032_repair_ref}^")"',
            ),
            "release validation base": workflow.replace(
                '--base-ref "${v4032_release_base_sha}"', '--base-ref HEAD^^'
            ),
            "release tag phase": workflow.replace(
                "--tag-phase", "--ordinary-phase"
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutation, workflow)
                with self.assertRaises(AssertionError):
                    self.assert_v4032_preserved_version_recovery_contract(mutation)

    def test_release_manager_v4032_subject_is_exact_github_squash(self) -> None:
        script = self.v4032_subject_gate_script()
        cases = {
            "valid": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#95) (#95)",
                True,
            ),
            "single pull request suffix": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#95)",
                False,
            ),
            "bare": (
                "Qualification : repair v4.03.2 package lifecycle qualification",
                False,
            ),
            "previous pull request": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#94)",
                False,
            ),
            "different pull request": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#96)",
                False,
            ),
            "non-numeric": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#PR)",
                False,
            ),
            "wrong version": (
                "Qualification : repair v4.03.3 package lifecycle qualification (#95)",
                False,
            ),
            "double space": (
                "Qualification : repair v4.03.2  package lifecycle qualification (#95)",
                False,
            ),
            "trailing space": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#95) ",
                False,
            ),
            "extra text": (
                "Qualification : repair v4.03.2 package lifecycle qualification (#95) extra",
                False,
            ),
        }
        for name, (subject, accepted) in cases.items():
            with self.subTest(name=name):
                environment = dict(os.environ)
                environment["COMMIT_SUBJECT"] = subject
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=REPOSITORY,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_release_manager_v4032_diff_gate_rejects_git_shape_mutations(
        self,
    ) -> None:
        script = self.exact_v4032_fix_diff_script()
        mutations = (
            None,
            "extra file",
            "unchanged file",
            "mode",
            "executable mode",
            "symlink",
            "rename",
            "delete",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation or "exact"):
                repository = self.make_v4032_fix_diff_repository(
                    f"v4032-fix-diff-{index}", mutation
                )
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=repository,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if mutation is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )

    def test_release_manager_bounds_two_preserved_version_fixes_to_exact_chain(
        self,
    ) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        self.assert_preserved_version_recovery_contract(workflow)

    def test_release_manager_second_followup_contract_rejects_mutations(self) -> None:
        workflow = RELEASE_MANAGER_WORKFLOW.read_text(encoding="utf-8")
        mutations = {
            "release tag": workflow.replace('"v4.03.0" ]]', '"v4.03.1" ]]'),
            "exact parent": workflow.replace(
                "10af4a7b754e1007fa8167e8c5222ac183cb288a)",
                "20af4a7b754e1007fa8167e8c5222ac183cb288a)",
            ),
            "canonical subject": workflow.replace(
                "Qualification : isolate nft golden helper TMPDIR",
                "Qualification : arbitrary follow-up",
            ),
            "linear history": workflow.replace(
                'previous_fix_line <<< "$(git rev-list --parents -n 1 HEAD^)"',
                'previous_fix_line <<< "$(git rev-list --parents -n 1 HEAD^^)"',
            ),
            "byte identity": workflow.replace(
                "git diff --quiet HEAD^ HEAD --", "git diff --quiet HEAD^^ HEAD --"
            ),
            "ordinary prior fix": workflow.replace(
                '--base-ref "${previous_fix_parent_sha}"',
                '--base-ref "${release_base_sha}"',
            ),
            "original bump": workflow.replace(
                'versioning_commit_message="$(git log -1 --format=%B HEAD^^)"',
                'versioning_commit_message="$(git log -1 --format=%B HEAD^)"',
            ),
            "pinned bump parent": workflow.replace(
                "dfb8dfcf52bd1f82dcd2cd3b311119f01270af1e",
                "efb8dfcf52bd1f82dcd2cd3b311119f01270af1e",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.assert_preserved_version_recovery_contract(mutation)

    def test_release_manager_second_followup_subject_is_exact_github_squash(
        self,
    ) -> None:
        script = self.second_fix_subject_gate_script()
        cases = {
            "valid": ("Qualification : isolate nft golden helper TMPDIR (#91)", True),
            "bare": ("Qualification : isolate nft golden helper TMPDIR", False),
            "zero": ("Qualification : isolate nft golden helper TMPDIR (#0)", False),
            "non-numeric": (
                "Qualification : isolate nft golden helper TMPDIR (#PR)",
                False,
            ),
            "numeric prefix with suffix": (
                "Qualification : isolate nft golden helper TMPDIR (#91a)",
                False,
            ),
            "double space": (
                "Qualification : isolate nft golden helper TMPDIR  (#91)",
                False,
            ),
            "trailing space": (
                "Qualification : isolate nft golden helper TMPDIR (#91) ",
                False,
            ),
            "leading zero": (
                "Qualification : isolate nft golden helper TMPDIR (#091)",
                False,
            ),
            "extra text": (
                "Qualification : isolate nft golden helper TMPDIR (#91) extra",
                False,
            ),
        }
        for name, (subject, accepted) in cases.items():
            with self.subTest(name=name):
                environment = dict(os.environ)
                environment["COMMIT_SUBJECT"] = subject
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=REPOSITORY,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_release_manager_exact_fix_diff_gate_rejects_git_shape_mutations(
        self,
    ) -> None:
        script = self.exact_second_fix_diff_script()
        for index, mutation in enumerate((None, "extra file", "mode", "symlink", "rename")):
            with self.subTest(mutation=mutation or "exact"):
                repository = self.make_second_fix_diff_repository(
                    f"fix-diff-{index}", mutation
                )
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    cwd=repository,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if mutation is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

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
        self.assertIn("qualification status ${failed_status}", workflow)
        self.assertIn(
            "refusing to sign because qualification status is not uniformly zero",
            workflow,
        )
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
        self.assertNotIn(RETIRED_PLATFORM, workflow.lower())
        self.assertNotIn(RETIRED_PACKAGE_SUFFIX, workflow)
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
            for argument in (
                "--package-amd64-shard",
                "--package-arm64-shard",
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
            self.assertIn("aggregate bound packages raw status", section)
            self.assertIn("qualification_root_directories+=(update)", section)
            self.assertIn("qualification_all_directories+=(update)", section)
            for raw_name in (
                "nftables-raw.json",
                "package-lifecycle-amd64.json",
                "package-lifecycle-arm64.json",
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
                "aggregate bound packages packages/candidate packages/previous raw status",
                section,
            )
            self.assertIn('.repository == $repository', section)
            self.assertIn('.release_tag == $release_tag', section)
            self.assertIn('.release_sha == $release_sha', section)
            self.assertIn(
                '.previous_tag == $aggregate[0].bindings.previous_version', section
            )
            self.assertIn("(.previous_package_asset_ids | length) == 7", section)
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
                "syswarden_${VERSION}_arm64.deb",
                "syswarden-${VERSION}-1.x86_64.rpm",
                "syswarden-${VERSION}-1.aarch64.rpm",
                "syswarden_${VERSION}_x86_64.apk",
                "syswarden_${VERSION}_aarch64.apk",
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
