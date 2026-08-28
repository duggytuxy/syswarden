#!/usr/bin/env python3
"""Tests for the exact package-staging inventory gate."""

from __future__ import annotations

import hashlib
import json
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

    def test_accepts_exact_completion_content_contract(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        completion = self.root / "usr/share/bash-completion/completions/syswarden"
        payload = completion.read_bytes()
        contract = package_stage_gate.ContentContract(
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
        )
        package_stage_gate.validate(
            self.root,
            package_stage_gate.LINUX_ENTRIES,
            contract,
        )

    def test_accepts_exact_geoip_data_license_source(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        copyright_path = (
            self.root / "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt"
        )
        payload = copyright_path.read_bytes()
        contract = package_stage_gate.ContentContract(
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
        )
        package_stage_gate.validate(
            self.root,
            package_stage_gate.LINUX_ENTRIES,
            geoip_data_license_contract=contract,
        )

    def test_rejects_geoip_data_license_content_drift(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        copyright_path = (
            self.root / "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt"
        )
        payload = copyright_path.read_bytes()
        contract = package_stage_gate.ContentContract(
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
        )
        copyright_path.write_bytes(b"altered attribution\n")
        with self.assertRaisesRegex(
            package_stage_gate.PackageStageError, "size mismatch|SHA-256 mismatch"
        ):
            package_stage_gate.validate(
                self.root,
                package_stage_gate.LINUX_ENTRIES,
                geoip_data_license_contract=contract,
            )

    def test_rejects_symlinked_geoip_data_license_source(self) -> None:
        source = Path(self.temporary_directory.name) / "LICENSE-CC0-1.0.txt"
        source.symlink_to("/tmp/external-copyright")
        with self.assertRaises(package_stage_gate.PackageStageError):
            package_stage_gate.validate_exact_content(
                source,
                package_stage_gate.ContentContract(sha256="0" * 64, size=1),
            )

    def test_repository_geoip_data_license_matches_pinned_contract(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        contract = package_stage_gate.load_content_contract(
            repository_root
            / "scripts/ci/package_geoip_data_license_contract.json"
        )
        package_stage_gate.validate_exact_content(
            repository_root
            / "src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt",
            contract,
        )

    def test_rejects_completion_size_or_digest_drift(self) -> None:
        self.create_stage(package_stage_gate.LINUX_ENTRIES)
        completion = self.root / "usr/share/bash-completion/completions/syswarden"
        payload = completion.read_bytes()
        for contract, message in (
            (
                package_stage_gate.ContentContract(
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size=len(payload) + 1,
                ),
                "size mismatch",
            ),
            (
                package_stage_gate.ContentContract(
                    sha256="0" * 64,
                    size=len(payload),
                ),
                "SHA-256 mismatch",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(package_stage_gate.PackageStageError, message):
                    package_stage_gate.validate(
                        self.root,
                        package_stage_gate.LINUX_ENTRIES,
                        contract,
                    )

    def test_loads_only_strict_completion_contract_schema(self) -> None:
        contract_path = Path(self.temporary_directory.name) / "completion.json"
        valid = {"sha256": "a" * 64, "size": 42}
        contract_path.write_text(json.dumps(valid) + "\n", encoding="ascii")
        self.assertEqual(
            package_stage_gate.load_content_contract(contract_path),
            package_stage_gate.ContentContract(sha256="a" * 64, size=42),
        )
        for document in (
            {"sha256": "a" * 63, "size": 42},
            {"sha256": "a" * 64, "size": 0},
            {"sha256": "a" * 64, "size": True},
            {"sha256": "a" * 64, "size": 42, "extra": 1},
        ):
            with self.subTest(document=document):
                contract_path.write_text(json.dumps(document), encoding="ascii")
                with self.assertRaises(package_stage_gate.PackageStageError):
                    package_stage_gate.load_content_contract(contract_path)

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
