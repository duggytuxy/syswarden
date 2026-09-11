#!/usr/bin/env python3

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_systemd_ordering_artifact_gate as gate


CONTENT = b"[Unit]\nAfter=wg-quick@wg-syswarden.service\n"
CONTRACT = gate.ContentContract(
    "8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483",
    43,
)


class OrderingArtifactGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_source(self, content: bytes = CONTENT, mode: int = 0o644) -> Path:
        path = self.root / "source.conf"
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def test_contract_and_stage_are_exact(self) -> None:
        contract_path = self.root / "contract.json"
        contract_path.write_text(
            json.dumps({"sha256": CONTRACT.sha256, "size": CONTRACT.size}),
            encoding="utf-8",
        )
        source = self.write_source()
        stage = self.root / "stage" / gate.RELATIVE_PATH
        stage.parent.mkdir(parents=True)
        stage.write_bytes(CONTENT)
        stage.chmod(0o644)
        loaded = gate.load_contract(contract_path)
        self.assertEqual(loaded, CONTRACT)
        self.assertEqual(gate.validate_source_and_stage(source, loaded, stage.parents[5]), CONTENT)

    def test_contract_schema_is_fail_closed(self) -> None:
        contract_path = self.root / "contract.json"
        invalid_documents = (
            {"sha256": "a" * 63, "size": CONTRACT.size},
            {"sha256": CONTRACT.sha256, "size": 0},
            {"sha256": CONTRACT.sha256, "size": True},
            {"sha256": CONTRACT.sha256, "size": 4097},
            {"sha256": CONTRACT.sha256, "size": CONTRACT.size, "extra": 1},
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                contract_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(gate.OrderingArtifactError):
                    gate.load_contract(contract_path)

    def test_stage_rejects_content_and_mode_drift(self) -> None:
        source = self.write_source()
        stage_root = self.root / "stage"
        stage = stage_root / gate.RELATIVE_PATH
        stage.parent.mkdir(parents=True)
        stage.write_bytes(CONTENT + b"drift")
        stage.chmod(0o644)
        with self.assertRaises(gate.OrderingArtifactError):
            gate.validate_source_and_stage(source, CONTRACT, stage_root)
        stage.write_bytes(CONTENT)
        stage.chmod(0o600)
        with self.assertRaises(gate.OrderingArtifactError):
            gate.validate_source_and_stage(source, CONTRACT, stage_root)

    def test_source_accepts_private_hermetic_archive_mode(self) -> None:
        source = self.write_source(mode=0o600)
        stage_root = self.root / "stage"
        stage = stage_root / gate.RELATIVE_PATH
        stage.parent.mkdir(parents=True)
        stage.write_bytes(CONTENT)
        stage.chmod(0o644)
        self.assertEqual(
            gate.validate_source_and_stage(source, CONTRACT, stage_root), CONTENT
        )

    def test_source_rejects_unexpected_mode(self) -> None:
        source = self.write_source(mode=0o640)
        with self.assertRaisesRegex(
            gate.OrderingArtifactError, "ordering source identity or mode is not exact"
        ):
            gate.validate_source_and_stage(source, CONTRACT)

    def deb_tar(self, *, mode: int = 0o644, content: bytes = CONTENT) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            member = tarfile.TarInfo("./" + gate.RELATIVE_PATH)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        return buffer.getvalue()

    def deb_run_results(self, archive: bytes) -> list[subprocess.CompletedProcess]:
        return [
            subprocess.CompletedProcess(
                [], 0, "debian-binary\ncontrol.tar.gz\ndata.tar.gz\n", ""
            ),
            subprocess.CompletedProcess([], 0, archive, b""),
        ]

    def test_deb_member_contract_is_exact(self) -> None:
        with mock.patch.object(
            gate.subprocess, "run", side_effect=self.deb_run_results(self.deb_tar())
        ):
            gate.validate_deb(self.root / "candidate.deb", CONTENT, CONTRACT)
        with mock.patch.object(
            gate.subprocess,
            "run",
            side_effect=self.deb_run_results(self.deb_tar(mode=0o600)),
        ):
            with self.assertRaises(gate.OrderingArtifactError):
                gate.validate_deb(self.root / "candidate.deb", CONTENT, CONTRACT)

    def test_deb_rejects_ambiguous_data_archive_inventory(self) -> None:
        inventory = subprocess.CompletedProcess(
            [], 0, "debian-binary\ndata.tar.gz\ndata.tar.gz\n", ""
        )
        with mock.patch.object(gate.subprocess, "run", return_value=inventory):
            with self.assertRaisesRegex(
                gate.OrderingArtifactError, "data archive inventory is not exact"
            ):
                gate.validate_deb(self.root / "candidate.deb", CONTENT, CONTRACT)

    def test_deb_rejects_duplicate_or_non_root_ordering_member(self) -> None:
        duplicate_buffer = io.BytesIO()
        with tarfile.open(fileobj=duplicate_buffer, mode="w") as archive:
            for _ in range(2):
                member = tarfile.TarInfo("./" + gate.RELATIVE_PATH)
                member.mode = 0o644
                member.uid = 0
                member.gid = 0
                member.size = len(CONTENT)
                archive.addfile(member, io.BytesIO(CONTENT))
        with mock.patch.object(
            gate.subprocess,
            "run",
            side_effect=self.deb_run_results(duplicate_buffer.getvalue()),
        ):
            with self.assertRaisesRegex(
                gate.OrderingArtifactError,
                "member count is not exactly one",
            ):
                gate.validate_deb(self.root / "candidate.deb", CONTENT, CONTRACT)

        non_root_buffer = io.BytesIO()
        with tarfile.open(fileobj=non_root_buffer, mode="w") as archive:
            member = tarfile.TarInfo("./" + gate.RELATIVE_PATH)
            member.mode = 0o644
            member.uid = 1000
            member.gid = 1000
            member.size = len(CONTENT)
            archive.addfile(member, io.BytesIO(CONTENT))
        with mock.patch.object(
            gate.subprocess,
            "run",
            side_effect=self.deb_run_results(non_root_buffer.getvalue()),
        ):
            with self.assertRaisesRegex(
                gate.OrderingArtifactError,
                "member metadata is not exact",
            ):
                gate.validate_deb(self.root / "candidate.deb", CONTENT, CONTRACT)

    def test_rpm_member_contract_is_exact(self) -> None:
        inventory = (
            f"{gate.ABSOLUTE_PATH}\t-rw-r--r--\troot\troot\t43\t{CONTRACT.sha256}\n"
            f"{gate.DIRECTORY_PATH}\tdrwxr-xr-x\troot\troot\t0\t\n"
        )
        run_results = [
            subprocess.CompletedProcess([], 0, "8\n", ""),
            subprocess.CompletedProcess([], 0, inventory, ""),
            subprocess.CompletedProcess([], 0, CONTENT, b""),
        ]

        class Producer:
            def __init__(self) -> None:
                self.stdout = io.BytesIO(b"cpio")
                self.stderr = io.BytesIO(b"")

            def wait(self) -> int:
                return 0

        with mock.patch.object(gate.subprocess, "run", side_effect=run_results), mock.patch.object(
            gate.subprocess, "Popen", return_value=Producer()
        ):
            gate.validate_rpm(self.root / "candidate.rpm", CONTENT, CONTRACT)

    def test_rpm_requires_one_safe_owned_ordering_directory(self) -> None:
        member = (
            f"{gate.ABSOLUTE_PATH}\t-rw-r--r--\troot\troot\t43\t{CONTRACT.sha256}\n"
        )
        directory = f"{gate.DIRECTORY_PATH}\tdrwxr-xr-x\troot\troot\t0\t\n"
        for record in (
            "",
            directory + directory,
            directory.replace("drwxr-xr-x", "lrwxrwxrwx"),
            directory.replace("drwxr-xr-x", "drwxrwxrwx"),
            directory.replace("\troot\troot\t", "\toperator\troot\t"),
            directory.replace("\t0\t\n", "\t0\t" + CONTRACT.sha256 + "\n"),
        ):
            with self.subTest(record=record), mock.patch.object(
                gate.subprocess,
                "run",
                side_effect=(
                    subprocess.CompletedProcess([], 0, "8\n", ""),
                    subprocess.CompletedProcess([], 0, member + record, ""),
                ),
            ):
                with self.assertRaisesRegex(gate.OrderingArtifactError, "ordering directory"):
                    gate.validate_rpm(self.root / "candidate.rpm", CONTENT, CONTRACT)

    def test_rpm_rejects_non_sha256_or_ambiguous_inventory(self) -> None:
        bad_algorithm = subprocess.CompletedProcess([], 0, "1\n", "")
        with mock.patch.object(gate.subprocess, "run", return_value=bad_algorithm):
            with self.assertRaisesRegex(
                gate.OrderingArtifactError,
                "digest algorithm is not exactly SHA-256",
            ):
                gate.validate_rpm(self.root / "candidate.rpm", CONTENT, CONTRACT)

        record = (
            f"{gate.ABSOLUTE_PATH}\t-rw-r--r--\troot\troot\t43\t"
            f"{CONTRACT.sha256}\n"
        )
        duplicate_inventory = subprocess.CompletedProcess([], 0, record + record, "")
        with mock.patch.object(
            gate.subprocess,
            "run",
            side_effect=(
                subprocess.CompletedProcess([], 0, "8\n", ""),
                duplicate_inventory,
            ),
        ):
            with self.assertRaisesRegex(
                gate.OrderingArtifactError,
                "member count is not exactly one",
            ):
                gate.validate_rpm(self.root / "candidate.rpm", CONTENT, CONTRACT)

    def test_source_rejects_hardlinks(self) -> None:
        source = self.write_source()
        os.link(source, self.root / "alias.conf")
        with self.assertRaises(gate.OrderingArtifactError):
            gate.validate_source_and_stage(source, CONTRACT)

    def test_socket_policy_cli_requires_its_own_exact_payload(self) -> None:
        repository = Path.cwd()
        while not (repository / "scripts/ci/package_stage_gate.py").is_file():
            if repository.parent == repository:
                self.fail("repository root is unavailable")
            repository = repository.parent
        source = repository / (
            "src/init/systemd/syswarden-core.service.d/"
            "10-syswarden-socket-ownership.conf"
        )
        stage = self.root / "stage"
        staged = stage / (
            "usr/lib/systemd/system/syswarden-core.service.d/"
            "10-syswarden-socket-ownership.conf"
        )
        staged.parent.mkdir(parents=True)
        command = [
            sys.executable,
            str(repository / "scripts/ci/package_systemd_ordering_artifact_gate.py"),
            "--artifact", "socket", "--format", "stage", "--root", str(stage),
            "--source", str(source), "--contract",
            str(repository / "scripts/ci/package_systemd_socket_capability_contract.json"),
        ]
        for payload, expected in ((CONTENT, 1), (source.read_bytes(), 0),
                                  (source.read_bytes().replace(b"CAP_CHOWN", b"CAP_KILL"), 1)):
            with self.subTest(expected=expected, payload=payload):
                staged.write_bytes(payload)
                staged.chmod(0o644)
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
