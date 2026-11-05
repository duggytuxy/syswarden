#!/usr/bin/env python3
"""Unsigned package identity inventory and publication boundary regressions."""

from __future__ import annotations

import argparse
import hashlib
import io
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_gate


class ReleaseGateInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def expected_names(self, version: str, *, include_base: bool) -> list[str]:
        names = [
            f"syswarden_{version}_amd64.deb",
            f"syswarden-{version}-1.x86_64.rpm",
            f"syswarden_{version}_x86_64.apk",
        ]
        if include_base:
            names += [
                f"syswarden-base_{version}_amd64.deb",
                f"syswarden-base-{version}-1.x86_64.rpm",
                f"syswarden-base_{version}_x86_64.apk",
            ]
        return names

    def make_packages(self, label: str, names: list[str]) -> Path:
        directory = self.root / label
        directory.mkdir()
        for name in names:
            (directory / name).write_bytes(f"synthetic unsigned package:{name}\n".encode())
        self.write_checksums(directory, names)
        return directory

    def write_checksums(self, directory: Path, names: list[str]) -> None:
        records = [
            f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
            for name in names
        ]
        (directory / "SHA256SUMS.txt").write_text("".join(records), encoding="utf-8")

    def snapshot(self) -> dict[str, tuple[object, ...]]:
        result: dict[str, tuple[object, ...]] = {}
        for path in sorted(self.root.rglob("*")):
            metadata = path.lstat()
            content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
            result[path.relative_to(self.root).as_posix()] = (
                metadata.st_mode,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                content,
            )
        return result

    def test_unsigned_inventory_has_exact_versioned_identity_order(self) -> None:
        for version, include_base in (
            ("4.02.8", False),
            ("4.10.4", False),
            ("5.00.0", True),
            ("5.01.0", True),
            ("6.00.0", True),
        ):
            with self.subTest(version=version):
                expected = self.expected_names(version, include_base=include_base)
                directory = self.make_packages(version, expected)
                before = self.snapshot()
                self.assertEqual(release_gate.package_names(version), expected)
                self.assertEqual(release_gate.validate_packages(directory, version), expected)
                self.assertEqual(self.snapshot(), before)

    def test_unsigned_inventory_rejects_missing_compatibility_or_base_package(self) -> None:
        version = "5.00.0"
        names = self.expected_names(version, include_base=True)
        for index, missing in enumerate(names):
            with self.subTest(missing=missing):
                remaining = [name for name in names if name != missing]
                directory = self.make_packages(f"missing-{index}", remaining)
                with self.assertRaisesRegex(release_gate.ReleaseGateError, "inventory mismatch"):
                    release_gate.validate_packages(directory, version)

    def test_unsigned_inventory_rejects_foreign_extra_and_separate_rhel_lane(self) -> None:
        for version, include_base, unexpected in (
            ("4.10.4", False, "syswarden-base_4.10.4_amd64.deb"),
            ("5.00.0", True, "syswarden-custom_5.00.0_amd64.deb"),
            ("5.00.0", True, "syswarden-base_5.00.1_amd64.deb"),
            ("5.00.0", True, "syswarden-5.00.0-1.rhelpo.x86_64.rpm"),
            ("5.00.0", True, "unexpected.txt"),
        ):
            with self.subTest(version=version, unexpected=unexpected):
                names = self.expected_names(version, include_base=include_base)
                directory = self.make_packages(unexpected, names + [unexpected])
                with self.assertRaisesRegex(release_gate.ReleaseGateError, "inventory mismatch"):
                    release_gate.validate_packages(directory, version)

    def test_unsigned_inventory_rejects_substituted_identity_despite_valid_checksums(self) -> None:
        names = self.expected_names("5.00.0", include_base=True)
        names[3] = "syswarden-custom_5.00.0_amd64.deb"
        directory = self.make_packages("substituted", names)
        with self.assertRaisesRegex(release_gate.ReleaseGateError, "inventory mismatch"):
            release_gate.validate_packages(directory, "5.00.0")

    def test_unsigned_inventory_rejects_checksum_inventory_and_digest_changes(self) -> None:
        names = self.expected_names("5.00.0", include_base=True)
        for mutation in ("missing-base", "foreign", "duplicate", "bad-digest"):
            with self.subTest(mutation=mutation):
                directory = self.make_packages(mutation, names)
                manifest = directory / "SHA256SUMS.txt"
                lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
                if mutation == "missing-base":
                    lines.pop()
                elif mutation == "foreign":
                    lines.append("0" * 64 + "  syswarden-custom_5.00.0_amd64.deb\n")
                elif mutation == "duplicate":
                    lines.append(lines[-1])
                else:
                    lines[-1] = "0" * 64 + lines[-1][64:]
                manifest.write_text("".join(lines), encoding="utf-8")
                with self.assertRaises(release_gate.ReleaseGateError):
                    release_gate.validate_packages(directory, "5.00.0")

    def test_unsigned_inventory_rejects_package_checksum_and_root_symlinks(self) -> None:
        names = self.expected_names("5.00.0", include_base=True)
        for index, entry in enumerate((names[0], names[3], "SHA256SUMS.txt")):
            with self.subTest(entry=entry):
                directory = self.make_packages(f"link-{index}", names)
                path = directory / entry
                target = self.root / f"link-target-{index}"
                path.rename(target)
                path.symlink_to(target)
                with self.assertRaisesRegex(release_gate.ReleaseGateError, "symbolic link"):
                    release_gate.validate_packages(directory, "5.00.0")
        directory = self.make_packages("root-target", names)
        link = self.root / "root-link"
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(release_gate.ReleaseGateError):
            release_gate.validate_packages(link, "5.00.0")
        with mock.patch("sys.argv", [
            "release_gate.py", "verify-packages", "--tag", "v5.00.0",
            "--packages", str(link),
        ]), mock.patch("sys.stderr", new_callable=io.StringIO) as error:
            self.assertEqual(release_gate.main(), 1)
        self.assertIn("directory is missing", error.getvalue())

    def test_unsigned_inventory_cli_accepts_v4_and_v5(self) -> None:
        for version, include_base in (("4.10.4", False), ("5.00.0", True)):
            with self.subTest(version=version):
                directory = self.make_packages(
                    version, self.expected_names(version, include_base=include_base)
                )
                with mock.patch("sys.argv", [
                    "release_gate.py", "verify-packages", "--tag", f"v{version}",
                    "--packages", str(directory),
                ]), mock.patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(release_gate.main(), 0)

    def test_v5_publication_cli_refuses_before_resolving_input_or_output_paths(self) -> None:
        for version in ("5.00.0", "6.00.0"):
            for command in ("prepare", "verify"):
                with self.subTest(version=version, command=command):
                    arguments = ["release_gate.py", command, "--tag", f"v{version}"]
                    if command == "prepare":
                        for option in (
                            "repository", "packages", "bundle", "sbom", "compliance",
                            "output", "notes-output",
                        ):
                            arguments.extend([f"--{option}", str(self.root / option)])
                    else:
                        arguments.extend([
                            "--assets", str(self.root / "assets"),
                            "--repository", str(self.root / "repository"),
                        ])
                    with mock.patch("sys.argv", arguments), \
                            mock.patch("sys.stderr", new_callable=io.StringIO) as error, \
                            mock.patch.object(Path, "resolve") as resolution:
                        self.assertEqual(release_gate.main(), 1)
                        resolution.assert_not_called()
                    self.assertIn(
                        "publication requires identity-bound native signature proofs",
                        error.getvalue(),
                    )
                    self.assertEqual(list(self.root.iterdir()), [])

    def test_v4_publication_inventory_and_rhel_lane_remain_exact(self) -> None:
        version = "4.10.4"
        expected = set(self.expected_names(version, include_base=False)) | {
            "SHA256SUMS.txt", "RELEASE_SHA256SUMS.txt", "syswarden-release.tar.gz",
            "syswarden-sbom.spdx.json", "plumber-report.zip",
            "syswarden-update-manifest-v1.json", "syswarden-update-manifest-v1.json.sig",
            "syswarden_4.10.4_amd64.deb.asc", "syswarden-4.10.4-1.rhelpo.x86_64.rpm",
        }
        self.assertEqual(release_gate.expected_release_assets(f"v{version}"), expected)
        self.assertNotIn(
            "syswarden-4.10.4-1.rhelpo.x86_64.rpm", release_gate.package_names(version)
        )

    def test_v5_and_later_publication_refuses_before_staging_or_verification(self) -> None:
        for version in ("5.00.0", "5.01.0", "6.00.0"):
            for existing_output in (False, True):
                with self.subTest(version=version, existing_output=existing_output):
                    directory = self.make_packages(
                        f"publication-{version}-{existing_output}",
                        self.expected_names(version, include_base=True),
                    )
                    output = directory.parent / f"output-{version}-{existing_output}"
                    notes = directory.parent / f"notes-{version}-{existing_output}"
                    if existing_output:
                        output.mkdir()
                        (output / "administrator-content").write_bytes(b"preserve output\n")
                        notes.write_bytes(b"preserve notes\n")
                    args = argparse.Namespace(
                        tag=f"v{version}", repository=self.root, packages=directory,
                        bundle=self.root / "unused-bundle", sbom=self.root / "unused-sbom",
                        compliance=self.root / "unused-compliance", output=output,
                        notes_output=notes, update_manifest_dir=self.root / "unused-manifest",
                        deb_signature=self.root / "unused-signature",
                        rhel_package_owned_rpm=self.root / "unused-rhel-rpm",
                    )
                    before = self.snapshot()
                    with mock.patch("release_gate.validate_packages") as packages, \
                            mock.patch("release_gate.exact_root_files") as inventory, \
                            mock.patch("release_gate.ensure_empty_output") as staging, \
                            mock.patch("release_gate.verify_signed_update_manifest") as verifier:
                        for operation in (
                            lambda: release_gate.prepare(args),
                            lambda: release_gate.verify_assets(directory, args.tag, self.root),
                            lambda: release_gate.expected_release_assets(args.tag),
                        ):
                            with self.assertRaisesRegex(
                                release_gate.ReleaseGateError,
                                "publication requires identity-bound native signature proofs",
                            ):
                                operation()
                        packages.assert_not_called()
                        inventory.assert_not_called()
                        staging.assert_not_called()
                        verifier.assert_not_called()
                    self.assertEqual(self.snapshot(), before)
                    self.assertTrue(release_gate.native_package_signatures_required(args.tag))
                    self.assertTrue(release_gate.signed_update_required(args.tag))


if __name__ == "__main__":
    unittest.main()
