#!/usr/bin/env python3
"""Tests for the exact package-staging inventory gate."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_stage_gate


class PackageStageGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "stage"

    def create_stage(
        self, expected: dict[str, package_stage_gate.ExpectedEntry]
    ) -> None:
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        for relative, contract in expected.items():
            if relative == ".":
                continue
            path = self.root / relative
            if contract.kind == "directory":
                path.mkdir(mode=contract.mode or 0o755)
                path.chmod(contract.mode or 0o755)
            elif contract.kind == "file":
                path.write_bytes(b"package payload\n")
                path.chmod(contract.mode or 0o600)
            elif contract.kind == "symlink":
                path.symlink_to(contract.target)

    def test_accepts_exact_linux_stage(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_unexpected_stale_file(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        (self.root / "opt/syswarden/stale.conf").write_text(
            "stale\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "unexpected"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_missing_file(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        (self.root / "opt/syswarden/bin/syswarden-core").unlink()
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "missing"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_empty_payload(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        (self.root / "opt/syswarden/signatures.json").write_bytes(b"")
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "non-empty"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_incorrect_file_mode(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        (self.root / "opt/syswarden/bin/syswarden-cli").chmod(0o755)
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "mode 0750"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_incorrect_directory_mode(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        (self.root / "opt/syswarden").chmod(0o700)
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "mode 0755"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_incorrect_symlink_target(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        link = self.root / "usr/local/bin/syswarden"
        link.unlink()
        link.symlink_to("/tmp/not-syswarden")
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "expected target"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_symlink_instead_of_regular_file(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        payload = self.root / "opt/syswarden/bin/syswarden-cli"
        payload.unlink()
        payload.symlink_to("/tmp/external-payload")
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "expected file"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_symlink_as_staging_root(self) -> None:
        real_root = Path(self.temporary_directory.name) / "real-stage"
        real_root.mkdir()
        os.symlink(real_root, self.root)
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "real directory"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_symlink_instead_of_directory(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        directory = self.root / "opt/syswarden/bin"
        shutil.rmtree(directory)
        directory.symlink_to("/tmp")
        with self.assertRaises(package_stage_gate.PackageStageError):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_fifo_instead_of_regular_file(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        payload = self.root / "opt/syswarden/signatures.json"
        payload.unlink()
        os.mkfifo(payload, mode=0o640)
        with self.assertRaisesRegex(package_stage_gate.PackageStageError, "unsupported"):
            package_stage_gate.validate(self.root, package_stage_gate.LINUX_ENTRIES)

    def test_rejects_unix_socket_instead_of_regular_file(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        entries = package_stage_gate.inventory(self.root)
        relative = "opt/syswarden/signatures.json"
        path, _ = entries[relative]
        entries[relative] = (
            path,
            os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
        )
        with mock.patch.object(package_stage_gate, "inventory", return_value=entries):
            with self.assertRaisesRegex(
                package_stage_gate.PackageStageError, "unsupported"
            ):
                package_stage_gate.validate(
                    self.root, package_stage_gate.LINUX_ENTRIES
                )

    def test_special_and_device_entry_types_are_unsupported(self) -> None:
        for file_type in (
            stat.S_IFIFO,
            stat.S_IFSOCK,
            stat.S_IFCHR,
            stat.S_IFBLK,
        ):
            with self.subTest(file_type=file_type):
                metadata = os.stat_result(
                    (file_type | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                )
                self.assertEqual(package_stage_gate.entry_kind(metadata), "unsupported")


if __name__ == "__main__":
    unittest.main()
