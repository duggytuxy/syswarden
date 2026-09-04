#!/usr/bin/env python3
"""Tests for the package binary provenance gate."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_binary_provenance_gate as gate


REVISION = "a" * 40
VCS_TIME = "2026-09-04T20:03:22Z"


def valid_build_info() -> str:
    return (
        "/proc/self/fd/3: go1.26.6\n"
        "\tbuild\t-buildmode=pie\n"
        "\tbuild\t-trimpath=true\n"
        "\tbuild\tCGO_ENABLED=0\n"
        "\tbuild\tGOARCH=amd64\n"
        "\tbuild\tGOAMD64=v1\n"
        "\tbuild\tGOOS=linux\n"
        "\tbuild\tvcs=git\n"
        f"\tbuild\tvcs.revision={REVISION}\n"
        f"\tbuild\tvcs.time={VCS_TIME}\n"
        "\tbuild\tvcs.modified=false\n"
    )


class PackageBinaryProvenanceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "payload"
        self.reference = Path(self.temporary.name) / "reference"
        self.signatures = Path(self.temporary.name) / "signatures.json"
        for root in (self.root, self.reference):
            (root / "opt/syswarden/bin").mkdir(parents=True)
            for relative in gate.BINARY_PATHS:
                (root / relative).write_bytes(b"ELF fixture\n")
            (root / gate.SIGNATURE_PATH).write_bytes(b"{}\n")
        self.signatures.write_bytes(b"{}\n")

    @staticmethod
    def fake_tool(command: list[str], descriptor: int, label: str) -> str:
        del descriptor, label
        if command[:2] == ["readelf", "--file-header"]:
            return "  Type: DYN (Position-Independent Executable file)\n  Machine: Advanced Micro Devices X86-64\n"
        if command[:3] == ["go", "version", "-m"]:
            return valid_build_info()
        raise AssertionError(command)

    def test_accepts_exact_pie_payload_and_reference(self) -> None:
        with mock.patch.object(gate, "run_tool", side_effect=self.fake_tool):
            gate.validate_root(
                self.root,
                "pie",
                REVISION,
                VCS_TIME,
                self.signatures,
                self.reference,
            )

    def test_static_mode_dereferences_retained_descriptor_for_file(self) -> None:
        commands: list[list[str]] = []

        def static_tool(command: list[str], descriptor: int, label: str) -> str:
            del descriptor, label
            commands.append(command)
            if command[:2] == ["readelf", "--file-header"]:
                return (
                    "  Type: EXEC (Executable file)\n"
                    "  Machine: Advanced Micro Devices X86-64\n"
                )
            if command[:2] == ["readelf", "--program-headers"]:
                return "Program Headers:\n"
            if command == ["file", "--brief", "--dereference"]:
                return "ELF 64-bit LSB executable, statically linked\n"
            if command[:3] == ["go", "version", "-m"]:
                return valid_build_info()
            raise AssertionError(command)

        target = self.root / gate.BINARY_PATHS[0]
        with mock.patch.object(gate, "run_tool", side_effect=static_tool):
            gate.validate_binary(target, "static", REVISION, VCS_TIME, None)
        self.assertIn(["file", "--brief", "--dereference"], commands)

    def test_rejects_packaged_binary_different_from_reference(self) -> None:
        (self.root / gate.BINARY_PATHS[1]).write_bytes(b"different fixture\n")
        with mock.patch.object(gate, "run_tool", side_effect=self.fake_tool):
            with self.assertRaisesRegex(gate.ProvenanceError, "differs"):
                gate.validate_root(
                    self.root,
                    "pie",
                    REVISION,
                    VCS_TIME,
                    self.signatures,
                    self.reference,
                )

    def test_rejects_missing_duplicate_or_extra_vcs_fields(self) -> None:
        base = valid_build_info()
        cases = (
            base.replace("\tbuild\tvcs.modified=false\n", ""),
            base + f"\tbuild\tvcs.revision={REVISION}\n",
            base + "\tbuild\tvcs.extra=unexpected\n",
        )
        for build_info in cases:
            with self.subTest(build_info=build_info):
                with self.assertRaises(gate.ProvenanceError):
                    gate.validate_build_info(
                        build_info,
                        Path("artifact"),
                        REVISION,
                        VCS_TIME,
                    )

    def test_rejects_symlinked_payload_and_root(self) -> None:
        payload = self.root / gate.BINARY_PATHS[0]
        payload.unlink()
        payload.symlink_to(self.reference / gate.BINARY_PATHS[0])
        with self.assertRaises(gate.ProvenanceError):
            gate.read_stable_digest(payload)
        linked_root = Path(self.temporary.name) / "linked-root"
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(gate.ProvenanceError):
            gate.require_directory(linked_root, "payload root")

    def test_rejects_symlinked_payload_parent(self) -> None:
        shutil.rmtree(self.root / "opt")
        (self.root / "opt").symlink_to(
            self.reference / "opt", target_is_directory=True
        )
        with self.assertRaisesRegex(gate.ProvenanceError, "parent"):
            gate.validate_root(
                self.root,
                "pie",
                REVISION,
                VCS_TIME,
                self.signatures,
                self.reference,
            )

    def test_rejects_binary_path_replaced_after_open(self) -> None:
        target = self.root / gate.BINARY_PATHS[0]
        original_tool = self.fake_tool
        replaced = False

        def replacing_tool(command: list[str], descriptor: int, label: str) -> str:
            nonlocal replaced
            if not replaced:
                os.replace(target, target.with_suffix(".opened"))
                target.write_bytes(b"replacement\n")
                replaced = True
            return original_tool(command, descriptor, label)

        with mock.patch.object(gate, "run_tool", side_effect=replacing_tool):
            with self.assertRaisesRegex(gate.ProvenanceError, "changed"):
                gate.validate_binary(
                    target,
                    "pie",
                    REVISION,
                    VCS_TIME,
                    self.reference / gate.BINARY_PATHS[0],
                )

    def test_rejects_regular_payload_path_replaced_while_reading(self) -> None:
        target = self.root / gate.SIGNATURE_PATH
        original_digest = gate.digest_descriptor

        def replacing_digest(descriptor: int) -> gate.FileDigest:
            digest = original_digest(descriptor)
            os.replace(target, target.with_suffix(".opened"))
            target.write_bytes(b"replacement\n")
            return digest

        with mock.patch.object(gate, "digest_descriptor", side_effect=replacing_digest):
            with self.assertRaisesRegex(gate.ProvenanceError, "changed"):
                gate.read_stable_digest(target)

    def test_rejects_payload_parent_replaced_between_binary_reads(self) -> None:
        original_validator = gate.validate_binary
        calls = 0

        def replacing_parent(*args: object, **kwargs: object) -> None:
            nonlocal calls
            original_validator(*args, **kwargs)
            calls += 1
            if calls == 1:
                opened = self.root / "opt.opened"
                os.replace(self.root / "opt", opened)
                (self.root / "opt").symlink_to(
                    self.reference / "opt", target_is_directory=True
                )

        with mock.patch.object(gate, "run_tool", side_effect=self.fake_tool):
            with mock.patch.object(
                gate, "validate_binary", side_effect=replacing_parent
            ):
                with self.assertRaises(gate.ProvenanceError):
                    gate.validate_root(
                        self.root,
                        "pie",
                        REVISION,
                        VCS_TIME,
                        self.signatures,
                        self.reference,
                    )

    def test_rejects_validated_binary_rewritten_before_final_verdict(self) -> None:
        original_validator = gate.validate_binary
        calls = 0

        def rewriting_first_binary(*args: object, **kwargs: object) -> None:
            nonlocal calls
            original_validator(*args, **kwargs)
            calls += 1
            if calls == 1:
                target = self.root / gate.BINARY_PATHS[0]
                target.write_bytes(b"rewritten after validation\n")

        with mock.patch.object(gate, "run_tool", side_effect=self.fake_tool):
            with mock.patch.object(
                gate, "validate_binary", side_effect=rewriting_first_binary
            ):
                with self.assertRaisesRegex(
                    gate.ProvenanceError, "before validation completed"
                ):
                    gate.validate_root(
                        self.root,
                        "pie",
                        REVISION,
                        VCS_TIME,
                        self.signatures,
                        self.reference,
                    )

    def test_digest_contract_rejects_interstep_payload_mutation(self) -> None:
        with mock.patch.object(gate, "run_tool", side_effect=self.fake_tool):
            contract = gate.validate_root(
                self.root,
                "pie",
                REVISION,
                VCS_TIME,
                self.signatures,
                self.reference,
            )
            target = self.root / gate.BINARY_PATHS[1]
            with target.open("ab") as stream:
                stream.write(b"interstep mutation\n")
            with self.assertRaisesRegex(
                gate.ProvenanceError, "validated before packaging"
            ):
                gate.validate_root(
                    self.root,
                    "pie",
                    REVISION,
                    VCS_TIME,
                    self.signatures,
                    self.root,
                    contract,
                )

    def test_rejects_malformed_or_noncanonical_digest_contract(self) -> None:
        valid = "v1;" + ";".join(
            f"{relative}={'a' * 64}:1"
            for relative in gate.DIGEST_CONTRACT_PATHS
        )
        cases = (
            "",
            valid.replace("v1;", "v2;", 1),
            valid.replace(gate.DIGEST_CONTRACT_PATHS[0], "unexpected", 1),
            valid.replace(":1", ":01", 1),
            valid + ";extra",
        )
        for contract in cases:
            with self.subTest(contract=contract):
                with self.assertRaises(gate.ProvenanceError):
                    gate.require_expected_digest_contract(valid, contract)

    def test_rejects_noncanonical_revision_and_time_at_cli_boundary(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "gate",
                "--root",
                str(self.root),
                "--mode",
                "pie",
                "--revision",
                "A" * 40,
                "--vcs-time",
                VCS_TIME,
                "--signatures-source",
                str(self.signatures),
            ],
        ):
            self.assertEqual(gate.main(), 1)


if __name__ == "__main__":
    unittest.main()
