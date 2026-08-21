#!/usr/bin/env python3
"""Tests for the rootless package lifecycle laboratory."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_lifecycle_lab


class FakePodmanRunner(package_lifecycle_lab.CommandRunner):
    def __init__(
        self,
        event_status: str = "pass",
        unavailable_architectures: set[str] | None = None,
        reported_architectures: dict[str, str] | None = None,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.event_status = event_status
        self.unavailable_architectures = unavailable_architectures or set()
        self.reported_architectures = reported_architectures or {}
        self.containers: dict[str, dict[str, object]] = {}

    @staticmethod
    def write_inventory_evidence(
        result_root: Path, family: str, scenario: str
    ) -> None:
        if family == "deb":
            paths = sorted(package_lifecycle_lab.DEB_PACKAGE_PATHS)
        elif family == "apk":
            paths = sorted(package_lifecycle_lab.APK_PACKAGE_PATHS)
        else:
            paths = sorted(
                set(package_lifecycle_lab.PACKAGE_PAYLOAD_PATHS)
                | {
                    "/usr/lib/.build-id",
                    "/usr/lib/.build-id/11",
                    "/usr/lib/.build-id/11/" + "1" * 38,
                    "/usr/lib/.build-id/11/" + "2" * 38,
                    "/usr/lib/.build-id/33",
                    "/usr/lib/.build-id/33/" + "3" * 38,
                }
            )
        file_modes = {
            "/opt/syswarden/bin/syswarden-cli": "750",
            "/opt/syswarden/bin/syswarden-core": "750",
            "/opt/syswarden/bin/syswarden-tui": "750",
            "/opt/syswarden/signatures.json": "640",
        }
        link_targets = {
            "/usr/local/bin/syswarden": "/opt/syswarden/bin/syswarden-cli",
            "/usr/local/bin/syswarden-tui": "/opt/syswarden/bin/syswarden-tui",
        }
        build_targets = {
            "/usr/lib/.build-id/11/" + "1" * 38: (
                "../../../../opt/syswarden/bin/syswarden-cli"
            ),
            "/usr/lib/.build-id/11/" + "2" * 38: (
                "../../../../opt/syswarden/bin/syswarden-core"
            ),
            "/usr/lib/.build-id/33/" + "3" * 38: (
                "../../../../opt/syswarden/bin/syswarden-tui"
            ),
        }
        filesystem = []
        for path in paths:
            if path in file_modes:
                kind, mode, value = "file", file_modes[path], "a" * 64
            elif path in link_targets:
                kind, mode, value = "symlink", "777", link_targets[path]
            elif path == "/usr/share/doc/syswarden/changelog.gz":
                kind, mode, value = "file", "644", "b" * 64
            elif path in build_targets:
                kind, mode, value = "symlink", "777", build_targets[path]
            else:
                kind, mode, value = "directory", "755", "-"
            filesystem.append(
                f"{path}\t{kind}\t{mode}\t0\t0\t{value}\n"
            )
        inventory_root = result_root / "inventories"
        inventory_root.mkdir()
        for label in package_lifecycle_lab.expected_inventory_phase_labels(
            scenario
        ):
            inventory_root.joinpath(
                f"{scenario}-{label}-manager.tsv"
            ).write_text("".join(f"{path}\n" for path in paths), encoding="utf-8")
            inventory_root.joinpath(
                f"{scenario}-{label}-filesystem.tsv"
            ).write_text("".join(filesystem), encoding="utf-8")

    def run(
        self,
        args: list[str] | tuple[str, ...],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> package_lifecycle_lab.CommandResult:
        del timeout, cwd
        command = tuple(args)
        self.calls.append(command)
        stdout = ""
        returncode = 0
        if command[1] == "version":
            stdout = "5.6.0\n"
        elif command[1] == "info":
            stdout = "true\n"
        elif command[1:3] == ("image", "exists"):
            returncode = 0
        elif command[1:3] == ("image", "inspect"):
            spec = next(
                item
                for item in package_lifecycle_lab.DEFAULT_PLATFORMS
                if item.image == command[-1]
            )
            stdout = (
                command[-1].rsplit("@", 1)[1]
                + "\t"
                + spec.podman_platform
                + "\n"
            )
        elif command[1] == "run":
            platform_name = command[command.index("--platform") + 1]
            architecture = platform_name.split("/", 1)[1]
            if architecture in self.unavailable_architectures:
                returncode = 126
                stderr = "exec format error\n"
            else:
                stdout = self.reported_architectures.get(
                    architecture,
                    "x86_64" if architecture == "amd64" else "aarch64",
                ) + "\n"
            return package_lifecycle_lab.CommandResult(
                args=command,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr if returncode else "",
            )
        elif command[1] == "create":
            volume_index = command.index("--volume")
            volumes: list[str] = []
            while True:
                try:
                    volume_index = command.index("--volume", volume_index)
                except ValueError:
                    break
                volumes.append(command[volume_index + 1])
                volume_index += 2
            result_mount = next(
                (
                    value
                    for value in volumes
                    if value.endswith(":/results:rw")
                ),
                None,
            )
            name = command[command.index("--name") + 1]
            if result_mount is None:
                self.containers[name] = {"bootstrap": True, "starts": 0}
                return package_lifecycle_lab.CommandResult(
                    args=command, returncode=0, stdout="", stderr=""
                )
            result_root = Path(result_mount.removesuffix(":/results:rw"))
            environment = [
                command[index + 1]
                for index, value in enumerate(command)
                if value == "--env"
            ]
            family = next(
                value.split("=", 1)[1]
                for value in environment
                if value.startswith("PACKAGE_FAMILY=")
            )
            scenario = next(
                value.split("=", 1)[1]
                for value in environment
                if value.startswith("SCENARIO=")
            )
            self.containers[name] = {
                "family": family,
                "scenario": scenario,
                "result_root": result_root,
                "starts": 0,
            }
        elif command[1] == "start":
            name = command[-1]
            container = self.containers[name]
            if container.get("bootstrap") is True:
                container["starts"] = int(container["starts"]) + 1
                return package_lifecycle_lab.CommandResult(
                    args=command, returncode=0, stdout="", stderr=""
                )
            result_root = container["result_root"]
            assert isinstance(result_root, Path)
            starts = int(container["starts"])
            if starts == 0:
                family = str(container["family"])
                scenario = str(container["scenario"])
                checks = package_lifecycle_lab.expected_event_checks(
                    family, scenario
                )
                result_root.joinpath("events.tsv").write_text(
                    "".join(
                        f"{self.event_status}\t{check}\tfake verified evidence\n"
                        for check in checks
                    ),
                    encoding="utf-8",
                )
                result_root.joinpath("commands.log").write_text(
                    "fake lifecycle commands\n", encoding="utf-8"
                )
                self.write_inventory_evidence(result_root, family, scenario)
            if container["scenario"] == "upgrade-rollback":
                result_root.joinpath("restart-state").write_text(
                    ("restart-one", "restart-two", "complete")[
                        min(starts, 2)
                    ]
                    + "\n",
                    encoding="utf-8",
                )
            container["starts"] = starts + 1
            if self.event_status == "fail":
                returncode = 1
        elif command[1:3] == ("rm", "--force"):
            self.containers.pop(command[-1], None)
        elif command[1] == "commit":
            pass
        return package_lifecycle_lab.CommandResult(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr="",
        )


class PackageLifecycleLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.candidate = self.root / "candidate"
        self.previous = self.root / "previous"
        self.candidate.mkdir()
        self.previous.mkdir()
        self.emulator = self.root / "qemu-aarch64-static"
        self.emulator.write_bytes(b"explicit fake static emulator")
        self.emulator.chmod(0o700)
        self.binfmt = self.root / "qemu-aarch64"
        self.binfmt.write_text(
            "enabled\n"
            f"interpreter {self.emulator}\n"
            "flags: POCF\n"
            "offset 0\n"
            "magic 7f454c46\n"
            "mask ffffffff\n",
            encoding="utf-8",
        )
        self.binfmt.chmod(0o600)
        self.create_package_set(self.candidate, b"candidate", "4.02.8")
        self.create_package_set(self.previous, b"previous", "4.02.7")

    @staticmethod
    def create_package_set(root: Path, content: bytes, version: str) -> None:
        names = (
            f"syswarden_{version}_amd64.deb",
            f"syswarden_{version}_arm64.deb",
            f"syswarden-{version}-1.x86_64.rpm",
            f"syswarden-{version}-1.aarch64.rpm",
            f"syswarden_{version}_x86_64.apk",
            f"syswarden_{version}_aarch64.apk",
        )
        checksums = []
        for name in names:
            payload = content + b"-" + name.encode("ascii")
            (root / name).write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            checksums.append(f"{digest}  {name}\n")
        (root / "SHA256SUMS.txt").write_text(
            "".join(checksums), encoding="utf-8"
        )

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "packages_dir": self.candidate,
            "previous_packages_dir": self.previous,
            "podman": "podman",
            "pull_policy": "never",
            "scenario_timeout": 60,
            "arm64_emulator": self.emulator,
            "_arm64_binfmt_registration": self.binfmt,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def qualification_args(self, architecture: str, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            **vars(self.args()),
            "architecture_shard": architecture,
            "arm64_emulator": None,
            "qualification_repository": "duggytuxy/syswarden",
            "qualification_release_sha": "a" * 40,
            "qualification_release_tag": "v4.02.8",
            "qualification_previous_tag": "v4.02.7",
            "qualification_workflow_run_id": "1001",
            "qualification_workflow_run_attempt": "1",
            "qualification_candidate_run_id": "900",
            "qualification_candidate_artifact_id": "901",
            "qualification_candidate_artifact_name": "syswarden-packages-4.02.8",
            "qualification_previous_release_id": "800",
            "aggregate_amd64_report": None,
            "aggregate_arm64_report": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def native_shard_reports(self) -> tuple[dict[str, object], dict[str, object]]:
        reports = []
        for architecture, host in (("amd64", "x86_64"), ("arm64", "aarch64")):
            platforms = tuple(
                spec
                for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
                if spec.architecture == architecture
            )
            reports.append(
                package_lifecycle_lab.run_lab(
                    self.qualification_args(architecture),
                    runner=FakePodmanRunner(),
                    platforms=platforms,
                    host_architecture=host,
                )
            )
        return reports[0], reports[1]

    def aggregate_args(
        self,
        amd64_path: Path,
        arm64_path: Path,
        **overrides: object,
    ) -> argparse.Namespace:
        values = {
            **vars(self.qualification_args("amd64")),
            "architecture_shard": None,
            "aggregate_amd64_report": amd64_path,
            "aggregate_arm64_report": arm64_path,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def run_embedded_inventory_contract(
        self,
        family: str,
        manifest_lines: list[str],
        inventory_lines: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        manifest = self.root / f"{family}-manifest.tsv"
        inventory = self.root / f"{family}-inventory.tsv"
        manifest.write_text(
            "\n".join(sorted(manifest_lines)) + "\n", encoding="utf-8"
        )
        inventory.write_text(
            "\n".join(sorted(inventory_lines or [])) + "\n",
            encoding="utf-8",
        )
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        functions = source[
            source.index("hash_file() {") : source.index(
                "\nverify_package_artifact() {"
            )
        ]
        shell = self.root / f"validate-{family}-inventory.sh"
        validation = (
            f'PACKAGE_FAMILY={family}\n'
            + functions
            + '\nvalidate_manifest_contract "$1"\n'
            + (
                'validate_inventory_contract "$2"\n'
                if inventory_lines is not None
                else ""
            )
        )
        shell.write_text(validation, encoding="utf-8")
        shell.chmod(0o700)
        return subprocess.run(
            ("/bin/sh", str(shell), str(manifest), str(inventory)),
            check=False,
            capture_output=True,
            text=True,
        )

    def test_discovers_and_verifies_each_package_family(self) -> None:
        candidate, previous, pairs = package_lifecycle_lab.validate_inputs(
            self.candidate,
            self.previous,
            package_lifecycle_lab.DEFAULT_PLATFORMS,
        )
        self.assertEqual(candidate, self.candidate)
        self.assertEqual(previous, self.previous)
        self.assertEqual(
            set(pairs),
            {
                "deb:amd64",
                "deb:arm64",
                "rpm:x86_64",
                "rpm:aarch64",
                "apk:x86_64",
                "apk:aarch64",
            },
        )
        self.assertNotEqual(
            pairs["deb:amd64"].candidate.sha256,
            pairs["deb:amd64"].previous.sha256,
        )
        self.assertEqual(pairs["deb:amd64"].candidate.version, "4.02.8")
        self.assertEqual(pairs["deb:amd64"].previous.version, "4.02.7")

    def test_forward_only_apk_contract_is_fixture_bound_per_architecture(self) -> None:
        fixture = json.loads(
            Path(__file__)
            .with_name("fixtures")
            .joinpath("package-forward-only-v4.02.8.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            fixture["artifacts"],
            package_lifecycle_lab.FORWARD_ONLY_APK_PREVIOUS,
        )
        self.assertEqual(
            fixture["candidate_version"],
            package_lifecycle_lab.FORWARD_ONLY_APK_CANDIDATE_VERSION,
        )
        self.assertEqual(
            fixture["previous_version"],
            package_lifecycle_lab.FORWARD_ONLY_APK_PREVIOUS_VERSION,
        )
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            if spec.family != "apk":
                continue
            historical = fixture["artifacts"][spec.package_architecture]
            pair = package_lifecycle_lab.PackagePair(
                candidate=package_lifecycle_lab.PackageArtifact(
                    self.candidate
                    / f"syswarden_4.03.0_{spec.package_architecture}.apk",
                    "4.03.0",
                    "a" * 64,
                ),
                previous=package_lifecycle_lab.PackageArtifact(
                    self.previous / historical["filename"],
                    "4.02.8",
                    historical["sha256"],
                ),
            )
            self.assertTrue(
                package_lifecycle_lab.validate_forward_only_apk_pair(spec, pair)
            )
            tampered = package_lifecycle_lab.PackagePair(
                candidate=pair.candidate,
                previous=package_lifecycle_lab.PackageArtifact(
                    pair.previous.path,
                    pair.previous.version,
                    "0" * 64,
                ),
            )
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError,
                "exact byte-bound",
            ):
                package_lifecycle_lab.validate_forward_only_apk_pair(
                    spec, tampered
                )

    def test_syswarden_version_parser_is_canonical_and_numeric(self) -> None:
        self.assertEqual(
            package_lifecycle_lab.parse_syswarden_version("4.02.10"),
            (4, 2, 10),
        )
        for version in (
            "v4.02.8",
            "4.2.8",
            "04.02.8",
            "4.002.8",
            "4.02.08",
            "4.02",
            "4.02.8.1",
            "2147483648.02.8",
        ):
            with self.subTest(version=version):
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.parse_syswarden_version(version)

    def test_rejects_different_builds_with_the_same_version(self) -> None:
        for child in self.previous.iterdir():
            child.unlink()
        self.create_package_set(self.previous, b"different-build", "4.02.8")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "two builds of 4.02.8 cannot prove upgrade or rollback",
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_rejects_reverse_or_equal_numeric_version_order(self) -> None:
        for child in self.previous.iterdir():
            child.unlink()
        self.create_package_set(self.previous, b"newer-previous", "4.02.10")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "must be numerically older",
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_numeric_order_accepts_patch_ten_after_patch_nine(self) -> None:
        pair = package_lifecycle_lab.PackagePair(
            candidate=package_lifecycle_lab.PackageArtifact(
                Path("syswarden_4.02.10_amd64.deb"), "4.02.10", "a" * 64
            ),
            previous=package_lifecycle_lab.PackageArtifact(
                Path("syswarden_4.02.9_amd64.deb"), "4.02.9", "b" * 64
            ),
        )
        contract = package_lifecycle_lab.build_package_version_contract(
            {"deb:amd64": pair}
        )
        self.assertEqual(contract["previous_numeric"], [4, 2, 9])
        self.assertEqual(contract["candidate_numeric"], [4, 2, 10])

    def test_rejects_inconsistent_versions_across_candidate_artifacts(self) -> None:
        old_name = "syswarden_4.02.8_amd64.deb"
        new_name = "syswarden_4.02.9_amd64.deb"
        self.candidate.joinpath(old_name).rename(self.candidate / new_name)
        manifest = self.candidate / "SHA256SUMS.txt"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(old_name, new_name),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "candidate package versions are inconsistent",
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_rejects_same_candidate_and_previous_directory(self) -> None:
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "must be distinct"
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.candidate,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_rejects_identical_previous_and_candidate_package_bytes(self) -> None:
        candidate_package = self.candidate / "syswarden_4.02.8_amd64.deb"
        previous_package = self.previous / "syswarden_4.02.7_amd64.deb"
        previous_package.write_bytes(candidate_package.read_bytes())
        manifest = self.previous / "SHA256SUMS.txt"
        lines = manifest.read_text(encoding="utf-8").splitlines()
        digest = hashlib.sha256(previous_package.read_bytes()).hexdigest()
        manifest.write_text(
            "\n".join(
                f"{digest}  {previous_package.name}"
                if line.endswith("  " + previous_package.name)
                else line
                for line in lines
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "bytes are identical"
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_rejects_checksum_mismatch(self) -> None:
        package = self.candidate / "syswarden_4.02.8_amd64.deb"
        package.write_bytes(b"tampered")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "checksum mismatch"
        ):
            package_lifecycle_lab.discover_artifact(
                self.candidate,
                package_lifecycle_lab.DEFAULT_PLATFORMS[0].package_pattern,
            )

    def test_rejects_duplicate_checksum_entry(self) -> None:
        manifest = self.candidate / "SHA256SUMS.txt"
        first = manifest.read_text(encoding="utf-8").splitlines()[0]
        with manifest.open("a", encoding="utf-8") as stream:
            stream.write(first + "\n")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "exactly one checksum"
        ):
            package_lifecycle_lab.discover_artifact(
                self.candidate,
                package_lifecycle_lab.DEFAULT_PLATFORMS[0].package_pattern,
            )

    def test_rejects_symlink_package(self) -> None:
        package = self.candidate / "syswarden_4.02.8_amd64.deb"
        target = self.root / "external.deb"
        target.write_bytes(package.read_bytes())
        package.unlink()
        package.symlink_to(target)
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "regular file"
        ):
            package_lifecycle_lab.discover_artifact(
                self.candidate,
                package_lifecycle_lab.DEFAULT_PLATFORMS[0].package_pattern,
            )

    def test_requires_immutable_image_digest(self) -> None:
        for image in (
            "docker.io/library/debian:stable-slim",
            "debian@sha256:short",
            "Docker.IO/library/debian@sha256:" + "a" * 64,
        ):
            with self.subTest(image=image):
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError, "immutable sha256"
                ):
                    package_lifecycle_lab.validate_image_reference(image)

    def test_arm64_emulator_must_be_executable_regular_and_non_symlink(self) -> None:
        artifact = package_lifecycle_lab.validate_arm64_emulator(self.emulator)
        assert artifact is not None
        self.assertEqual(artifact.path, self.emulator)
        self.assertEqual(
            artifact.sha256,
            hashlib.sha256(self.emulator.read_bytes()).hexdigest(),
        )

        non_executable = self.root / "qemu-non-executable"
        non_executable.write_bytes(b"not executable")
        non_executable.chmod(0o600)
        empty = self.root / "qemu-empty"
        empty.touch(mode=0o700)
        symlink = self.root / "qemu-symlink"
        symlink.symlink_to(self.emulator)
        directory = self.root / "qemu-directory"
        directory.mkdir()
        cases = {
            "not executable": non_executable,
            "empty": empty,
            "non-symlink": symlink,
            "regular non-symlink": directory,
        }
        for message, path in cases.items():
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError, message
                ):
                    package_lifecycle_lab.validate_arm64_emulator(path)

    def test_arm64_emulator_checksum_change_invalidates_the_run(self) -> None:
        original = package_lifecycle_lab.validate_arm64_emulator
        calls = 0

        def changing(
            path: Path | None,
        ) -> package_lifecycle_lab.EmulatorArtifact | None:
            nonlocal calls
            calls += 1
            artifact = original(path)
            if calls == 2 and artifact is not None:
                return replace(artifact, sha256="f" * 64)
            return artifact

        with mock.patch.object(
            package_lifecycle_lab,
            "validate_arm64_emulator",
            side_effect=changing,
        ):
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError,
                "emulator changed",
            ):
                package_lifecycle_lab.run_lab(
                    self.args(), runner=FakePodmanRunner()
                )

    def test_arm64_binfmt_requires_exact_interpreter_enabled_and_flag_f(self) -> None:
        emulator = package_lifecycle_lab.validate_arm64_emulator(self.emulator)
        assert emulator is not None
        registration = package_lifecycle_lab.validate_arm64_binfmt(
            emulator, self.binfmt
        )
        self.assertEqual(registration.interpreter, str(self.emulator))
        self.assertIn("F", registration.flags)

        mutations = {
            "not enabled": "disabled\n",
            "does not exactly match": (
                "enabled\ninterpreter /tmp/other-qemu\nflags: POCF\n"
            ),
            "lacks the persistent": (
                f"enabled\ninterpreter {self.emulator}\nflags: POC\n"
            ),
        }
        original = self.binfmt.read_text(encoding="utf-8")
        for message, content in mutations.items():
            with self.subTest(message=message):
                self.binfmt.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError, message
                ):
                    package_lifecycle_lab.validate_arm64_binfmt(
                        emulator, self.binfmt
                    )
        self.binfmt.write_text(original, encoding="utf-8")

    def test_default_matrix_is_official_digest_pinned_and_complete(self) -> None:
        platforms = package_lifecycle_lab.DEFAULT_PLATFORMS
        self.assertEqual(len(platforms), 10)
        self.assertEqual(
            {package_lifecycle_lab.platform_coordinate(spec) for spec in platforms},
            package_lifecycle_lab.REQUIRED_PLATFORM_COORDINATES,
        )
        for spec in platforms:
            with self.subTest(platform=package_lifecycle_lab.platform_coordinate(spec)):
                package_lifecycle_lab.validate_image_reference(spec.image)
                self.assertEqual(
                    package_lifecycle_lab.image_repository(spec.image),
                    package_lifecycle_lab.OFFICIAL_REPOSITORIES[spec.distribution],
                )
                self.assertEqual(spec.podman_platform, f"linux/{spec.architecture}")
        self.assertEqual(
            {
                (spec.family, spec.package_architecture)
                for spec in platforms
                if spec.architecture == "arm64"
            },
            {("deb", "arm64"), ("rpm", "aarch64"), ("apk", "aarch64")},
        )
        self.assertIn(
            "sed -i '\\|^path-exclude /usr/share/doc/\\*$|d'",
            package_lifecycle_lab.DEB_BOOTSTRAP,
        )
        self.assertIn("curl-minimal", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertIn("diffutils", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertNotIn(" ipset curl wget", package_lifecycle_lab.RPM_BOOTSTRAP)

    def test_rejects_non_official_or_wrong_architecture_platform(self) -> None:
        baseline = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        non_official = replace(
            baseline,
            image="quay.io/example/debian:stable@sha256:" + "a" * 64,
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "official image repository"
        ):
            package_lifecycle_lab.validate_platforms((non_official,))

        wrong_architecture = replace(
            baseline,
            podman_platform="linux/arm64",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "Podman platform mismatch"
        ):
            package_lifecycle_lab.validate_platforms((wrong_architecture,))

        wrong_package = replace(
            baseline,
            package_pattern=package_lifecycle_lab.EXPECTED_PACKAGE_PATTERNS[
                ("deb", "arm64")
            ],
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "package filename contract mismatch",
        ):
            package_lifecycle_lab.validate_platforms((wrong_package,))

        missing_scenario = replace(
            baseline, scenarios=("upgrade-rollback", "remove")
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "lifecycle scenario contract mismatch",
        ):
            package_lifecycle_lab.validate_platforms((missing_scenario,))

    def test_missing_arm64_artifact_fails_before_container_execution(self) -> None:
        package = self.candidate / "syswarden_4.02.8_arm64.deb"
        package.unlink()
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "arm64"
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_containerfile_uses_exact_base_and_bootstrap_only(self) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        containerfile = package_lifecycle_lab.build_containerfile(spec)
        self.assertEqual(containerfile.count("FROM "), 1)
        self.assertIn(f"FROM {spec.image}\n", containerfile)
        self.assertIn("apt-get install", containerfile)
        self.assertNotIn("syswarden", containerfile.lower())

    def test_container_run_is_networkless_and_mounts_packages_read_only(self) -> None:
        pair = package_lifecycle_lab.PackagePair(
            package_lifecycle_lab.PackageArtifact(
                self.candidate / "syswarden_4.02.8_amd64.deb",
                "4.02.8",
                "a" * 64,
            ),
            package_lifecycle_lab.PackageArtifact(
                self.previous / "syswarden_4.02.7_amd64.deb",
                "4.02.7",
                "b" * 64,
            ),
        )
        script = self.root / "lab.sh"
        results = self.root / "results"
        args = package_lifecycle_lab.container_run_arguments(
            "podman",
            "localhost/lab",
            "safe-name",
            self.candidate,
            self.previous,
            script,
            results,
            package_lifecycle_lab.DEFAULT_PLATFORMS[0],
            "upgrade-rollback",
            pair,
        )
        self.assertEqual(args[1], "create")
        self.assertNotIn("--rm", args)
        self.assertIn("--network=none", args)
        self.assertEqual(
            [args[index + 1] for index, value in enumerate(args) if value == "--cap-add"],
            ["NET_ADMIN"],
        )
        self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertIn(f"{self.candidate}:/candidate:ro", args)
        self.assertIn(f"{self.previous}:/previous:ro", args)
        self.assertNotIn("--privileged", args)
        for host_namespace in (
            "--network=host",
            "--pid=host",
            "--ipc=host",
            "--uts=host",
            "--userns=host",
        ):
            self.assertNotIn(host_namespace, args)
        self.assertNotIn("/run/podman/podman.sock", " ".join(args))
        self.assertIn("EXPECTED_PACKAGE_ARCHITECTURE=amd64", args)
        self.assertIn("EXPECTED_UNAME_ARCHITECTURE=x86_64", args)
        self.assertIn("EXPECTED_CANDIDATE_VERSION=4.02.8", args)
        self.assertIn("EXPECTED_PREVIOUS_VERSION=4.02.7", args)

    def test_arm64_probe_and_lifecycle_arguments_are_explicit_and_bounded(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "alpine" and item.architecture == "arm64"
        )
        probe = package_lifecycle_lab.architecture_probe_arguments("podman", spec)
        self.assertEqual(probe[probe.index("--platform") + 1], "linux/arm64")
        self.assertIn("--network=none", probe)
        self.assertIn("--read-only", probe)
        self.assertIn("--cap-drop=all", probe)
        self.assertNotIn("--cap-add", probe)
        self.assertNotIn("--privileged", probe)
        self.assertNotIn("--volume", probe)

        self.assertNotIn("--entrypoint", probe)
        self.assertNotIn(str(self.emulator), probe)

        pair = package_lifecycle_lab.PackagePair(
            package_lifecycle_lab.PackageArtifact(
                self.candidate / "syswarden_4.02.8_aarch64.apk",
                "4.02.8",
                "a" * 64,
            ),
            package_lifecycle_lab.PackageArtifact(
                self.previous / "syswarden_4.02.7_aarch64.apk",
                "4.02.7",
                "b" * 64,
            ),
        )
        lifecycle = package_lifecycle_lab.container_run_arguments(
            "podman",
            "localhost/lab",
            "safe-name",
            self.candidate,
            self.previous,
            self.root / "lab.sh",
            self.root / "results",
            spec,
            "upgrade-rollback",
            pair,
        )
        self.assertEqual(
            lifecycle[lifecycle.index("--platform") + 1], "linux/arm64"
        )
        self.assertIn("EXPECTED_PACKAGE_ARCHITECTURE=aarch64", lifecycle)
        self.assertIn("EXPECTED_UNAME_ARCHITECTURE=aarch64", lifecycle)
        self.assertEqual(
            [
                lifecycle[index + 1]
                for index, value in enumerate(lifecycle)
                if value == "--cap-add"
            ],
            ["NET_ADMIN"],
        )

        self.assertNotIn("--entrypoint", lifecycle)
        self.assertNotIn(str(self.emulator), lifecycle)

    def test_arm64_pull_is_explicitly_platform_selected_and_digest_checked(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "ubuntu" and item.architecture == "arm64"
        )
        runner = FakePodmanRunner()
        package_lifecycle_lab.ensure_image(runner, "podman", spec, "always")
        pull = next(call for call in runner.calls if call[1] == "pull")
        self.assertEqual(pull[pull.index("--platform") + 1], "linux/arm64")
        self.assertEqual(pull[-1], spec.image)
        inspect = next(
            call for call in runner.calls if call[1:3] == ("image", "inspect")
        )
        self.assertIn("{{.Digest}}", inspect[inspect.index("--format") + 1])
        self.assertIn("{{.Architecture}}", inspect[inspect.index("--format") + 1])

    def test_shell_exercises_real_lifecycle_and_preservation_checks(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        for operation in (
            "dpkg --install",
            "rpm -Uvh --replacepkgs --oldpackage",
            "apk add --allow-untrusted --no-network",
            "dpkg --remove",
            "dpkg --purge",
            "rpm -e",
            "apk del --purge",
        ):
            with self.subTest(operation=operation):
                self.assertIn(operation, script)
        for state_path in (
            "/etc/syswarden/config/lifecycle-operator.conf",
            "/etc/syswarden/config/modules/99-user.toml",
            "/etc/syswarden/lists/syswarden_blacklist.ipv4",
            "/etc/syswarden/lists/syswarden_blacklist.ipv6",
            "/var/lib/syswarden/ui/data.json",
            "/etc/syswarden/tls/operator.pem",
        ):
            with self.subTest(state_path=state_path):
                self.assertIn(state_path, script)
        self.assertIn("assert_all_state_preserved candidate", script)
        self.assertIn("assert_all_state_preserved reinstall", script)
        self.assertIn("assert_all_state_preserved rollback", script)
        self.assertIn("assert_all_state_preserved recovery", script)
        self.assertIn("assert_all_state_preserved restart-one", script)
        self.assertIn("assert_all_state_preserved restart-two", script)
        self.assertIn("verify_installed_inventory", script)
        self.assertIn("run_install_step", script)
        self.assertIn("maintainer script emitted a Go panic", script)
        self.assertIn('record_check="$2"', script)
        self.assertNotIn('record() {\n    status="$1"', script)
        self.assertIn("installed_manager_manifest", script)
        self.assertIn("validate_manifest_contract", script)
        self.assertIn("validate_inventory_contract", script)
        self.assertIn("/opt/syswarden/bin/syswarden-cli --help", script)
        self.assertIn('"install ok installed"', script)
        self.assertIn("apk info --installed syswarden", script)
        self.assertIn("dpkg-deb --field \"${package}\" Architecture", script)
        self.assertIn("rpm -qp --queryformat '%{ARCH}'", script)
        self.assertIn("sed -n 's/^arch = //p'", script)
        self.assertIn('check_equal platform.uname "${EXPECTED_UNAME_ARCHITECTURE}"', script)
        self.assertIn(
            'check_equal metadata.previous.version "${EXPECTED_PREVIOUS_VERSION}"',
            script,
        )
        self.assertIn(
            'check_equal metadata.candidate.version "${EXPECTED_CANDIDATE_VERSION}"',
            script,
        )
        self.assertIn("normalize_apk_version", script)
        self.assertIn("package_runtime_dependencies", script)
        self.assertIn("expected_runtime_dependencies", script)
        self.assertIn("metadata.${label}.runtime_dependencies", script)
        self.assertIn("probe_postinstall_contract", script)
        lifecycle_order = (
            'run_install_step install.previous "${PREVIOUS_PACKAGE}"',
            'run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"',
            'run_install_step reinstall.candidate "${CANDIDATE_PACKAGE}"',
            'run_install_step rollback.previous "${PREVIOUS_PACKAGE}"',
            'run_install_step recovery.candidate "${CANDIDATE_PACKAGE}"',
        )
        self.assertEqual(
            [script.index(fragment) for fragment in lifecycle_order],
            sorted(script.index(fragment) for fragment in lifecycle_order),
        )

    def test_seed_state_uses_separate_address_family_files(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        seed = source[
            source.index("seed_state() {") : source.index("\nload_state_contract() {")
        ]
        for family, path in (
            (4, "/etc/syswarden/lists/syswarden_blacklist.ipv4"),
            (6, "/etc/syswarden/lists/syswarden_blacklist.ipv6"),
        ):
            producers = [
                line.strip()
                for line in seed.splitlines()
                if line.lstrip().startswith("printf ") and path in line
            ]
            with self.subTest(path=path):
                self.assertEqual(len(producers), 1)
                tokens = shlex.split(producers[0])
                redirect = tokens.index(">")
                self.assertEqual(tokens[redirect + 1], path)
                addresses = tokens[2:redirect]
                self.assertGreaterEqual(len(addresses), 1)
                self.assertTrue(
                    all(
                        ipaddress.ip_address(value).version == family
                        for value in addresses
                    )
                )
        self.assertIn("list_ipv6", package_lifecycle_lab.OPERATOR_STATE_KEYS)
        token_writer = source[
            source.index("write_seeded_operator_token() {") : source.index(
                "\nseed_state() {"
            )
        ]
        self.assertIn("'[network]' 'interfaces = \"lo\"'", token_writer)
        self.assertNotIn('interfaces = "eth0"', token_writer)

    def test_previous_package_is_installed_and_probed_before_operator_seed(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        initial = source[
            source.index("scenario_upgrade_rollback_initial() {") : source.index(
                "\nscenario_upgrade_rollback_restart_one() {"
            )
        ]
        install = initial.index(
            'run_install_step install.previous "${PREVIOUS_PACKAGE}"'
        )
        probes = (
            initial.index("probe_forward_only_apk_payload previous"),
            initial.index('probe_payload previous previous "${PREVIOUS_VERSION}"'),
        )
        seed = initial.index("seed_state")
        preserved = initial.index("assert_all_state_preserved previous")
        candidate = initial.index(
            'run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"'
        )
        self.assertTrue(all(install < probe < seed for probe in probes))
        self.assertLess(seed, preserved)
        self.assertLess(preserved, candidate)

    def test_forward_only_apk_downgrade_flag_is_exactly_bounded(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        install_function = source[
            source.index("is_exact_forward_only_apk_rollback() {") : source.index(
                "\nremove_package() {"
            )
        ]
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        apk = fake_bin / "apk"
        apk.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"${APK_ARGUMENTS}\"\n",
            encoding="utf-8",
        )
        apk.chmod(0o700)
        shell = self.root / "apk-install-contract.sh"
        shell.write_text(
            "#!/bin/sh\n"
            "set -u\n"
            "hash_file() { sha256sum \"$1\" | awk '{ print $1 }'; }\n"
            + install_function
            + '\ninstall_package "${PACKAGE_PATH}" "${CHECK}"\n',
            encoding="utf-8",
        )
        shell.chmod(0o700)
        previous_path = self.root / "syswarden_4.02.8_x86_64.apk"
        previous_path.write_bytes(b"exact historical APK fixture")
        previous = str(previous_path)
        candidate_path = self.root / "syswarden_4.03.0_x86_64.apk"
        candidate_path.write_bytes(b"candidate APK fixture")
        candidate = str(candidate_path)
        previous_sha256 = hashlib.sha256(previous_path.read_bytes()).hexdigest()
        cases = (
            ("exact-rollback", "1", "rollback.previous", previous, previous_sha256, 0, True),
            ("regular-upgrade", "1", "upgrade.candidate", candidate, previous_sha256, 0, False),
            (
                "non-forward-rollback",
                "0",
                "rollback.previous",
                previous,
                previous_sha256,
                0,
                False,
            ),
            ("wrong-package", "1", "rollback.previous", candidate, previous_sha256, 1, False),
            ("wrong-digest", "1", "rollback.previous", previous, "0" * 64, 1, False),
        )
        for (
            name,
            transition,
            check,
            package,
            expected_sha256,
            expected_rc,
            expected_force,
        ) in cases:
            with self.subTest(name=name):
                arguments = self.root / f"{name}.args"
                env = os.environ.copy()
                env.update(
                    {
                        "PATH": f"{fake_bin}:{env.get('PATH', '')}",
                        "APK_ARGUMENTS": str(arguments),
                        "PACKAGE_FAMILY": "apk",
                        "PACKAGE_PATH": package,
                        "CHECK": check,
                        "FORWARD_ONLY_APK_TRANSITION": transition,
                        "PREVIOUS_PACKAGE": previous,
                        "EXPECTED_PREVIOUS_VERSION": "4.02.8",
                        "EXPECTED_PREVIOUS_SHA256": expected_sha256,
                    }
                )
                result = subprocess.run(
                    (str(shell),),
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)
                observed = (
                    arguments.read_text(encoding="utf-8").splitlines()
                    if arguments.exists()
                    else []
                )
                self.assertEqual("--force-old-apk" in observed, expected_force)
                if expected_rc == 0:
                    self.assertEqual(observed[-1], package)

    def test_forward_only_probe_recomputes_version_after_restart(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        probe = source[
            source.index("probe_forward_only_apk_payload() {") : source.index(
                "\nprobe_postinstall_contract() {"
            )
        ]
        self.assertIn(
            'actual_version="$(installed_version 2>/dev/null || true)"', probe
        )
        self.assertIn(
            'check_equal "${label}.version" "${EXPECTED_PREVIOUS_VERSION}" '
            '"${actual_version}"',
            probe,
        )
        self.assertNotIn("${PREVIOUS_VERSION}", probe)

    def test_forward_only_shell_invokes_historical_and_recovery_package_steps(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        functions = source[
            source.index("scenario_upgrade_rollback_initial() {") : source.index(
                "\nscenario_remove() {"
            )
        ]
        shell = self.root / "forward-only-order.sh"
        calls = self.root / "package-manager-calls"
        restart = self.root / "restart-state"
        shell.write_text(
            "#!/bin/sh\n"
            "set -u\n"
            f'CALLS="{calls}"\n'
            f'RESTART_STATE_FILE="{restart}"\n'
            'PREVIOUS_PACKAGE="/previous/exact-v4.02.8.apk"\n'
            'CANDIDATE_PACKAGE="/candidate/v4.03.0.apk"\n'
            'PREVIOUS_VERSION="4.02.8"\n'
            'CANDIDATE_VERSION="4.03.0"\n'
            'EXPECTED_PREVIOUS_VERSION="4.02.8"\n'
            'EXPECTED_CANDIDATE_VERSION="4.03.0"\n'
            'FORWARD_ONLY_APK_TRANSITION="1"\n'
            "prepare_expected_payloads() { return 0; }\n"
            "seed_state() { :; }\n"
            "seed_legacy_webtui_upgrade_state() { :; }\n"
            "seed_live_legacy_webtui_process() { :; }\n"
            "seed_legacy_saas_monitor_state() { :; }\n"
            "install_service_manager_sentinels() { :; }\n"
            "remove_service_manager_sentinels() { :; }\n"
            "load_state_contract() { return 0; }\n"
            'run_install_step() { printf "%s\\n" "$1" >> "${CALLS}"; }\n'
            "probe_forward_only_apk_payload() { :; }\n"
            "probe_payload() { :; }\n"
            "assert_all_state_preserved() { :; }\n"
            + functions
            + "\nscenario_upgrade_rollback_initial\n"
            + "scenario_upgrade_rollback_restart_two\n",
            encoding="utf-8",
        )
        shell.chmod(0o700)
        result = subprocess.run(
            (str(shell),), check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls.read_text(encoding="utf-8").splitlines(),
            [
                "install.previous",
                "upgrade.candidate",
                "reinstall.candidate",
                "rollback.previous",
                "recovery.candidate",
            ],
        )

    def test_maintainer_panic_is_canonical_only_when_manager_returns_zero(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        functions = source[
            source.index("record() {") : source.index("\ncheck_equal() {")
        ]
        shell = self.root / "maintainer-result-contract.sh"
        shell.write_text(
            "#!/bin/sh\n"
            "set -u\n"
            'RESULT_FILE="$1"\n'
            'COMMAND_LOG="$2"\n'
            'MOCK_RC="$3"\n'
            'PREFIX="upgrade-rollback"\n'
            'INVOCATION="initial"\n'
            "FAILURES=0\n"
            + functions
            + "\ninstall_package() {\n"
            "    printf '%s\\n' 'panic: synthetic post-install failure'\n"
            '    return "${MOCK_RC}"\n'
            "}\n"
            'run_install_step install.previous /tmp/fake-package || true\n',
            encoding="utf-8",
        )
        shell.chmod(0o700)

        expected = {
            0: (
                "pass\tupgrade-rollback.install.previous\tcommand completed\n"
                "fail\tupgrade-rollback.install.previous.maintainer_script\t"
                "package manager returned success after maintainer script emitted "
                "a Go panic\n"
            ),
            1: (
                "fail\tupgrade-rollback.install.previous\tcommand failed with exit "
                "code 1\n"
                "fail\tupgrade-rollback.install.previous.maintainer_script\t"
                "maintainer script emitted a Go panic and package manager returned "
                "exit code 1\n"
            ),
        }
        for manager_rc, expected_events in expected.items():
            with self.subTest(manager_rc=manager_rc):
                events = self.root / f"maintainer-events-{manager_rc}.tsv"
                commands = self.root / f"maintainer-commands-{manager_rc}.log"
                result = subprocess.run(
                    (str(shell), str(events), str(commands), str(manager_rc)),
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    events.read_text(encoding="utf-8"), expected_events
                )

    def test_embedded_manifest_contracts_reject_extra_and_duplicate_paths(self) -> None:
        payload = [
            "/opt/syswarden/bin/syswarden-cli",
            "/opt/syswarden/bin/syswarden-core",
            "/opt/syswarden/bin/syswarden-tui",
            "/opt/syswarden/signatures.json",
            "/usr/local/bin/syswarden",
            "/usr/local/bin/syswarden-tui",
        ]
        deb = payload + [
            "/opt",
            "/opt/syswarden",
            "/opt/syswarden/bin",
            "/usr",
            "/usr/local",
            "/usr/local/bin",
            "/usr/share",
            "/usr/share/doc",
            "/usr/share/doc/syswarden",
            "/usr/share/doc/syswarden/changelog.gz",
        ]
        apk = list(payload)
        rpm = payload + [
            "/usr/lib/.build-id",
            "/usr/lib/.build-id/11",
            "/usr/lib/.build-id/11/" + "1" * 38,
            "/usr/lib/.build-id/22",
            "/usr/lib/.build-id/22/" + "2" * 38,
            "/usr/lib/.build-id/33",
            "/usr/lib/.build-id/33/" + "3" * 38,
        ]
        for family, manifest in (("deb", deb), ("rpm", rpm), ("apk", apk)):
            with self.subTest(family=family):
                accepted = self.run_embedded_inventory_contract(
                    family, manifest
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                unexpected = self.run_embedded_inventory_contract(
                    family, [*manifest, "/etc/shadow"]
                )
                self.assertNotEqual(unexpected.returncode, 0)
                duplicate = self.run_embedded_inventory_contract(
                    family, [*manifest, manifest[-1]]
                )
                self.assertNotEqual(duplicate.returncode, 0)

    def test_rpm_build_id_prefix_collision_requires_exact_unique_parents(
        self,
    ) -> None:
        links = [
            "/usr/lib/.build-id/1d/" + "1" * 38,
            "/usr/lib/.build-id/1d/" + "2" * 38,
            "/usr/lib/.build-id/5b/" + "3" * 38,
        ]
        valid = sorted(
            [
                *package_lifecycle_lab.PACKAGE_PAYLOAD_PATHS,
                "/usr/lib/.build-id",
                "/usr/lib/.build-id/1d",
                "/usr/lib/.build-id/5b",
                *links,
            ]
        )

        package_lifecycle_lab._validate_manager_paths("rpm", valid)
        accepted = self.run_embedded_inventory_contract("rpm", valid)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        mutations = {
            "orphan-directory": [*valid, "/usr/lib/.build-id/aa"],
            "missing-parent": [
                path for path in valid if path != "/usr/lib/.build-id/1d"
            ],
            "additional-link": [
                *valid,
                "/usr/lib/.build-id/5b/" + "4" * 38,
            ],
            "missing-link": [path for path in valid if path != links[1]],
            "unexpected-path": [*valid, "/etc/shadow"],
        }
        for name, mutation in mutations.items():
            adversarial = sorted(mutation)
            with self.subTest(name=name):
                with self.assertRaises(
                    package_lifecycle_lab.LifecycleLabError
                ):
                    package_lifecycle_lab._validate_manager_paths(
                        "rpm", adversarial
                    )
                rejected = self.run_embedded_inventory_contract(
                    "rpm", adversarial
                )
                self.assertNotEqual(rejected.returncode, 0)

    def test_embedded_inventory_contract_rejects_type_mode_owner_and_link_drift(
        self,
    ) -> None:
        digest = "a" * 64
        inventory = [
            f"/opt/syswarden/bin/syswarden-cli\tfile\t750\t0\t0\t{digest}",
            f"/opt/syswarden/bin/syswarden-core\tfile\t750\t0\t0\t{digest}",
            f"/opt/syswarden/bin/syswarden-tui\tfile\t750\t0\t0\t{digest}",
            f"/opt/syswarden/signatures.json\tfile\t640\t0\t0\t{digest}",
            "/usr/local/bin/syswarden\tsymlink\t777\t0\t0\t/opt/syswarden/bin/syswarden-cli",
            "/usr/local/bin/syswarden-tui\tsymlink\t777\t0\t0\t/opt/syswarden/bin/syswarden-tui",
            "/usr/lib/.build-id\tdirectory\t755\t0\t0\t-",
        ]
        manifest = [line.split("\t", 1)[0] for line in inventory]
        for prefix, suffix, binary in (
            ("11", "1" * 38, "syswarden-cli"),
            ("22", "2" * 38, "syswarden-core"),
            ("33", "3" * 38, "syswarden-tui"),
        ):
            directory = f"/usr/lib/.build-id/{prefix}"
            link = f"{directory}/{suffix}"
            manifest.extend((directory, link))
            inventory.extend(
                (
                    f"{directory}\tdirectory\t755\t0\t0\t-",
                    f"{link}\tsymlink\t777\t0\t0\t../../../../opt/syswarden/bin/{binary}",
                )
            )
        accepted = self.run_embedded_inventory_contract(
            "rpm", manifest, inventory
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        mutations = {
            "type": [
                line.replace("\tfile\t750\t", "\tdirectory\t750\t", 1)
                if line.startswith("/opt/syswarden/bin/syswarden-cli\t")
                else line
                for line in inventory
            ],
            "mode": [
                line.replace("\t750\t", "\t755\t", 1)
                if line.startswith("/opt/syswarden/bin/syswarden-core\t")
                else line
                for line in inventory
            ],
            "owner": [
                line.replace("\t0\t0\t", "\t1\t0\t", 1)
                if line.startswith("/opt/syswarden/signatures.json\t")
                else line
                for line in inventory
            ],
            "link": [
                line.replace(
                    "/opt/syswarden/bin/syswarden-cli",
                    "/tmp/forged-cli",
                )
                if line.startswith("/usr/local/bin/syswarden\t")
                else line
                for line in inventory
            ],
        }
        for name, adversarial in mutations.items():
            with self.subTest(name=name):
                rejected = self.run_embedded_inventory_contract(
                    "rpm", manifest, adversarial
                )
                self.assertNotEqual(rejected.returncode, 0)

    def test_parses_machine_readable_events_and_rejects_invalid_data(self) -> None:
        event_file = self.root / "events.tsv"
        event_file.write_text(
            "pass\tinstall.payload\tmatched\ninfo\tcontainer\trootless\n",
            encoding="utf-8",
        )
        events = package_lifecycle_lab.parse_events(event_file)
        self.assertEqual(events[0]["status"], "pass")
        event_file.write_text("success\tbad\tvalue\n", encoding="utf-8")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "invalid lifecycle event"
        ):
            package_lifecycle_lab.parse_events(event_file)

    def test_event_contract_rejects_unknown_duplicate_missing_and_reordered_checks(
        self,
    ) -> None:
        checks = package_lifecycle_lab.expected_event_checks(
            "deb", "upgrade-rollback"
        )
        baseline = [
            {"status": "pass", "check": check, "detail": "verified"}
            for check in checks
        ]
        package_lifecycle_lab.validate_event_contract(
            baseline, "deb", "upgrade-rollback"
        )
        mutations = {
            "unknown": baseline
            + [
                {
                    "status": "pass",
                    "check": "upgrade-rollback.synthetic",
                    "detail": "forged",
                }
            ],
            "duplicate": baseline + [dict(baseline[-1])],
            "missing": baseline[:-1],
            "reordered": [baseline[1], baseline[0], *baseline[2:]],
            "informational": [
                {**baseline[0], "status": "info"}, *baseline[1:]
            ],
        }
        for name, adversarial in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(
                    package_lifecycle_lab.LifecycleLabError
                ):
                    package_lifecycle_lab.validate_event_contract(
                        adversarial, "deb", "upgrade-rollback"
                    )

    def test_fake_rootless_run_reports_linux_container_scope(self) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["schema_version"], package_lifecycle_lab.SCHEMA_VERSION
        )
        version_contract = report["package_version_contract"]
        self.assertEqual(version_contract["previous_version"], "4.02.7")
        self.assertEqual(version_contract["candidate_version"], "4.02.8")
        self.assertEqual(version_contract["previous_numeric"], [4, 2, 7])
        self.assertEqual(version_contract["candidate_numeric"], [4, 2, 8])
        self.assertEqual(len(version_contract["coordinates"]), 6)
        self.assertTrue(
            all(
                item["previous_version"] == "4.02.7"
                and item["candidate_version"] == "4.02.8"
                and item["previous"]["version"] == "4.02.7"
                and item["candidate"]["version"] == "4.02.8"
                for item in report["platforms"]
            )
        )
        self.assertTrue(report["engine"]["rootless"])
        self.assertTrue(report["harness_complete"])
        self.assertTrue(report["release_ready"])
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(report["unexpected_failed_checks"], [])
        self.assertEqual(
            report["engine"]["arm64_emulator"]["sha256"],
            hashlib.sha256(self.emulator.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["engine"]["arm64_binfmt"]["interpreter"],
            str(self.emulator),
        )
        self.assertIn("F", report["engine"]["arm64_binfmt"]["flags"])
        self.assertEqual(
            {item["distribution"] for item in report["platforms"]},
            {"debian", "ubuntu", "fedora", "almalinux", "alpine"},
        )
        self.assertEqual(len(report["platforms"]), 10)
        self.assertTrue(all(item["status"] == "pass" for item in report["platforms"]))
        deb_upgrade = next(
            scenario
            for item in report["platforms"]
            if item["family"] == "deb"
            for scenario in item["scenarios"]
            if scenario["name"] == "upgrade-rollback"
        )
        self.assertEqual(
            set(deb_upgrade["inventory_evidence"]),
            set(
                package_lifecycle_lab.expected_inventory_phase_labels(
                    "upgrade-rollback"
                )
            ),
        )
        self.assertEqual(
            len(
                deb_upgrade["inventory_evidence"]["restart-two"][
                    "manager_paths"
                ]
            ),
            16,
        )
        self.assertEqual(
            report["scope"]["architectures_completed"],
            ["amd64/x86_64", "arm64/aarch64"],
        )
        self.assertEqual(report["scope"]["missing_platform_coordinates"], [])
        arm_family_coverage = {
            item["family"]: item["status"]
            for item in report["scope"]["family_architecture_coverage"]
            if item["architecture_id"] == "arm64"
        }
        self.assertEqual(
            arm_family_coverage, {"deb": "pass", "rpm": "pass", "apk": "pass"}
        )
        self.assertIn("not a SysWarden product rollback", report["scope"]["rollback_model"])
        run_calls = [call for call in runner.calls if call[1] == "run"]
        self.assertEqual(len(run_calls), 10)
        lifecycle_creates = [
            call
            for call in runner.calls
            if call[1] == "create" and any(
                value.endswith(":/results:rw") for value in call
            )
        ]
        self.assertEqual(len(lifecycle_creates), 26)
        self.assertTrue(all("--network=none" in call for call in lifecycle_creates))
        bootstrap_creates = [
            call
            for call in runner.calls
            if call[1] == "create" and call not in lifecycle_creates
        ]
        self.assertEqual(bootstrap_creates, [])
        start_calls = [call for call in runner.calls if call[1] == "start"]
        self.assertEqual(len(start_calls), 46)
        self.assertEqual(
            len([call for call in runner.calls if call[1] == "commit"]), 0
        )
        build_calls = [call for call in runner.calls if call[1] == "build"]
        self.assertEqual(len(build_calls), 10)
        self.assertTrue(all("--platform" in call for call in build_calls))
        self.assertTrue(all("--network=host" not in call for call in build_calls))

    def test_native_shards_cover_exact_architecture_without_emulation(self) -> None:
        amd64, arm64 = self.native_shard_reports()
        for architecture, report in (("amd64", amd64), ("arm64", arm64)):
            with self.subTest(architecture=architecture):
                self.assertEqual(report["status"], "pass")
                self.assertEqual(
                    report["native_shard"],
                    {"schema_version": 1, "architecture": architecture},
                )
                self.assertEqual(
                    {item["architecture_id"] for item in report["platforms"]},
                    {architecture},
                )
                self.assertEqual(len(report["platforms"]), 5)
                self.assertIsNone(report["engine"]["arm64_emulator"])
                self.assertIsNone(report["engine"]["arm64_binfmt"])
                self.assertTrue(
                    all(
                        item["architecture_probe"]["execution_mode"] == "native"
                        and item["architecture_probe"]["emulator"] is None
                        and item["architecture_probe"]["binfmt"] is None
                        for item in report["platforms"]
                    )
                )

    def test_native_shard_rejects_wrong_host_and_any_emulator(self) -> None:
        amd64_platforms = tuple(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.architecture == "amd64"
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "requires a native amd64 host",
        ):
            package_lifecycle_lab.run_lab(
                self.qualification_args("amd64"),
                runner=FakePodmanRunner(),
                platforms=amd64_platforms,
                host_architecture="aarch64",
            )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "forbid ARM64 emulation",
        ):
            package_lifecycle_lab.run_lab(
                self.qualification_args("amd64", arm64_emulator=self.emulator),
                runner=FakePodmanRunner(),
                platforms=amd64_platforms,
                host_architecture="x86_64",
            )

    def test_native_shard_aggregate_is_exact_digest_bound_and_adapter_compatible(self) -> None:
        amd64, arm64 = self.native_shard_reports()
        amd64_path = self.root / "package-lifecycle-amd64.json"
        arm64_path = self.root / "package-lifecycle-arm64.json"
        for path, report in ((amd64_path, amd64), (arm64_path, arm64)):
            path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        aggregate = package_lifecycle_lab.aggregate_native_shard_reports(
            self.aggregate_args(amd64_path, arm64_path)
        )
        self.assertEqual(aggregate["status"], "pass")
        self.assertTrue(aggregate["harness_complete"])
        self.assertTrue(aggregate["release_ready"])
        self.assertEqual(
            aggregate["scope"]["host_architecture"],
            package_lifecycle_lab.NATIVE_AGGREGATE_HOST,
        )
        self.assertEqual(len(aggregate["platforms"]), 10)
        self.assertEqual(
            [item["architecture"] for item in aggregate["native_shards"]["reports"]],
            ["amd64", "arm64"],
        )
        for path, record in zip(
            (amd64_path, arm64_path),
            aggregate["native_shards"]["reports"],
            strict=True,
        ):
            self.assertEqual(
                record["report_sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        package_lifecycle_lab.validate_report_version_contract(aggregate)

    def test_native_shard_aggregate_propagates_product_failure(self) -> None:
        amd64, arm64 = self.native_shard_reports()
        arm64_platforms = tuple(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.architecture == "arm64"
        )
        arm64 = package_lifecycle_lab.run_lab(
            self.qualification_args("arm64"),
            runner=FakePodmanRunner(event_status="fail"),
            platforms=arm64_platforms,
            host_architecture="aarch64",
        )
        amd64_path = self.root / "failed-aggregate-amd64.json"
        arm64_path = self.root / "failed-aggregate-arm64.json"
        amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
        arm64_path.write_text(json.dumps(arm64) + "\n", encoding="utf-8")

        aggregate = package_lifecycle_lab.aggregate_native_shard_reports(
            self.aggregate_args(amd64_path, arm64_path)
        )
        self.assertEqual(aggregate["status"], "fail")
        self.assertFalse(aggregate["harness_complete"])
        self.assertFalse(aggregate["release_ready"])
        self.assertTrue(aggregate["unexpected_failed_checks"])

    def test_native_shard_aggregate_rejects_mutated_binding_matrix_and_execution(self) -> None:
        baseline_amd64, baseline_arm64 = self.native_shard_reports()
        mutations = {
            "run mismatch": lambda report: report["qualification_binding"].__setitem__(
                "workflow_run_id", 1002
            ),
            "manifest mismatch": lambda report: report[
                "qualification_binding"
            ].__setitem__("candidate_manifest_sha256", "0" * 64),
            "binding missing": lambda report: report[
                "qualification_binding"
            ].pop("workflow_run_id"),
            "binding null": lambda report: report[
                "qualification_binding"
            ].__setitem__("workflow_run_id", None),
            "binding string": lambda report: report[
                "qualification_binding"
            ].__setitem__("workflow_run_id", "1001"),
            "emulated arm64": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("execution_mode", "host_binfmt_qemu_aarch64"),
            "wrong native uname": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("actual_uname", "x86_64"),
            "missing coordinate": lambda report: report["platforms"].pop(),
            "duplicate coordinate": lambda report: report["platforms"].__setitem__(
                -1, dict(report["platforms"][0])
            ),
            "reordered coordinates": lambda report: report["platforms"].reverse(),
            "package contract mismatch": lambda report: report[
                "package_version_contract"
            ]["coordinates"][0].__setitem__("candidate_version", "4.02.9"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                amd64 = json.loads(json.dumps(baseline_amd64))
                arm64 = json.loads(json.dumps(baseline_arm64))
                target = arm64 if name in {
                    "emulated arm64",
                    "wrong native uname",
                    "missing coordinate",
                    "duplicate coordinate",
                    "reordered coordinates",
                } else amd64
                mutate(target)
                amd64_path = self.root / f"{name}-amd64.json"
                arm64_path = self.root / f"{name}-arm64.json"
                amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
                arm64_path.write_text(json.dumps(arm64) + "\n", encoding="utf-8")
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.aggregate_native_shard_reports(
                        self.aggregate_args(amd64_path, arm64_path)
                    )

        single = self.root / "same-shard.json"
        single.write_text(json.dumps(baseline_amd64) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "distinct inodes",
        ):
            package_lifecycle_lab.aggregate_native_shard_reports(
                self.aggregate_args(single, single)
            )

    def test_native_shard_reader_rejects_duplicate_json_keys(self) -> None:
        amd64, arm64 = self.native_shard_reports()
        amd64_path = self.root / "duplicate-amd64.json"
        arm64_path = self.root / "duplicate-arm64.json"
        payload = json.dumps(amd64)
        amd64_path.write_text(
            payload.replace("{", '{"schema_version":3,', 1) + "\n",
            encoding="utf-8",
        )
        arm64_path.write_text(json.dumps(arm64) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "duplicate JSON key",
        ):
            package_lifecycle_lab.aggregate_native_shard_reports(
                self.aggregate_args(amd64_path, arm64_path)
            )

    def test_native_shard_aggregate_cli_writes_exact_report(self) -> None:
        amd64, arm64 = self.native_shard_reports()
        amd64_path = self.root / "cli-amd64.json"
        arm64_path = self.root / "cli-arm64.json"
        output = self.root / "cli-aggregate.json"
        amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
        arm64_path.write_text(json.dumps(arm64) + "\n", encoding="utf-8")
        arguments = (
            "--packages-dir",
            str(self.candidate),
            "--previous-packages-dir",
            str(self.previous),
            "--aggregate-amd64-report",
            str(amd64_path),
            "--aggregate-arm64-report",
            str(arm64_path),
            "--qualification-repository",
            "duggytuxy/syswarden",
            "--qualification-release-sha",
            "a" * 40,
            "--qualification-release-tag",
            "v4.02.8",
            "--qualification-previous-tag",
            "v4.02.7",
            "--qualification-workflow-run-id",
            "1001",
            "--qualification-workflow-run-attempt",
            "1",
            "--qualification-candidate-run-id",
            "900",
            "--qualification-candidate-artifact-id",
            "901",
            "--qualification-candidate-artifact-name",
            "syswarden-packages-4.02.8",
            "--qualification-previous-release-id",
            "800",
            "--output",
            str(output),
            "--pretty",
        )
        with mock.patch("sys.stdout") as stdout:
            self.assertEqual(package_lifecycle_lab.main(arguments), 0)
        written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(written["status"], "pass")
        self.assertEqual(len(written["platforms"]), 10)
        stdout.write.assert_called_once()

    def test_report_version_contract_rejects_schema_order_and_platform_tampering(
        self,
    ) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        mutations = {
            "schema": lambda item: item.update(schema_version=2),
            "order": lambda item: item["package_version_contract"].update(
                candidate_version="4.02.7", candidate_numeric=[4, 2, 7]
            ),
            "platform": lambda item: item["platforms"][0].update(
                candidate_version="4.02.9"
            ),
            "coordinate": lambda item: item["package_version_contract"][
                "coordinates"
            ][0].update(candidate_numeric=[4, 2, 9]),
            "numeric_type": lambda item: item["package_version_contract"].update(
                candidate_numeric=[4.0, 2, 8]
            ),
            "filename": lambda item: item["platforms"][0]["candidate"].update(
                filename="syswarden_4.02.9_amd64.deb"
            ),
            "event": lambda item: item["platforms"][0]["scenarios"][0][
                "events"
            ][0].update(check="upgrade-rollback.synthetic"),
            "restart": lambda item: item["platforms"][0]["scenarios"][0].update(
                container_restart_count=1
            ),
            "classification": lambda item: item.update(release_ready=False),
            "emulator": lambda item: item["engine"]["arm64_emulator"].update(
                sha256="0" * 64
            ),
            "binfmt": lambda item: item["engine"]["arm64_binfmt"].update(
                interpreter="/tmp/wrong-qemu"
            ),
            "inventory": lambda item: item["platforms"][0]["scenarios"][0][
                "inventory_evidence"
            ]["previous"]["filesystem"][0].update(mode="777"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                adversarial = json.loads(json.dumps(report))
                mutate(adversarial)
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_report_version_contract(
                        adversarial
                    )

    def test_alpine_rc127_failures_are_never_a_generic_waiver(self) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        for platform_result in platforms:
            if platform_result["distribution"] != "alpine":
                continue
            platform_result["status"] = "fail"
            for scenario in platform_result["scenarios"]:
                scenario["status"] = "fail"
                scenario["container_exit_code"] = 1
                scenario["container_start_exit_codes"] = [
                    1
                    for _ in scenario["container_start_exit_codes"]
                ]
                for event in scenario["events"]:
                    if event["check"].endswith(".executable"):
                        event["status"] = "fail"
                        event["detail"] = (
                            "CLI execution failed with exit code 127"
                        )
        classification = package_lifecycle_lab.classify_lifecycle_evidence(
            platforms
        )
        self.assertFalse(classification["harness_complete"])
        self.assertFalse(classification["release_ready"])
        self.assertEqual(classification["blocker_ids"], [])
        self.assertTrue(classification["unexpected_failed_checks"])
        alpine_coordinates = [
            item
            for item in classification["coordinate_classification"]
            if item["distribution"] == "alpine"
        ]
        self.assertTrue(
            all(item["status"] == "incomplete" for item in alpine_coordinates)
        )

        adversarial = json.loads(json.dumps(platforms))
        unexpected_event = next(
            event
            for event in adversarial[0]["scenarios"][0]["events"]
            if not event["check"].endswith(".executable")
        )
        unexpected_event["status"] = "fail"
        unexpected_event["detail"] = "synthetic additional failure"
        adversarial[0]["status"] = "fail"
        adversarial[0]["scenarios"][0]["status"] = "fail"
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(
            adversarial
        )
        self.assertFalse(rejected["harness_complete"])
        self.assertFalse(rejected["release_ready"])
        self.assertEqual(rejected["blocker_ids"], [])
        self.assertTrue(rejected["unexpected_failed_checks"])

        incomplete_set = json.loads(json.dumps(platforms))
        alpine_remove = next(
            scenario
            for item in incomplete_set
            if item["distribution"] == "alpine"
            and item["architecture_id"] == "amd64"
            for scenario in item["scenarios"]
            if scenario["name"] == "remove"
        )
        executable = next(
            event
            for event in alpine_remove["events"]
            if event["check"].endswith(".executable")
        )
        executable.update(status="pass", detail="CLI executed and emitted help")
        alpine_remove.update(
            status="pass",
            container_exit_code=0,
            container_start_exit_codes=[0],
        )
        missing_expected_failure = (
            package_lifecycle_lab.classify_lifecycle_evidence(incomplete_set)
        )
        self.assertFalse(missing_expected_failure["harness_complete"])
        self.assertEqual(missing_expected_failure["blocker_ids"], [])
        self.assertTrue(
            missing_expected_failure["unexpected_failed_checks"]
        )

    def test_exact_forward_only_apk_evidence_requires_candidate_recovery(self) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        for platform_result in platforms:
            if platform_result["family"] != "apk":
                continue
            architecture = platform_result["package_architecture"]
            historical = package_lifecycle_lab.FORWARD_ONLY_APK_PREVIOUS[
                architecture
            ]
            platform_result.update(
                candidate_version="4.03.0",
                previous_version="4.02.8",
                candidate={
                    "filename": f"syswarden_4.03.0_{architecture}.apk",
                    "version": "4.03.0",
                    "sha256": "c" * 64,
                },
                previous={
                    "filename": historical["filename"],
                    "version": "4.02.8",
                    "sha256": historical["sha256"],
                },
            )
            scenario = next(
                item
                for item in platform_result["scenarios"]
                if item["name"] == "upgrade-rollback"
            )
            details = {
                "upgrade-rollback.previous.executable": (
                    "historical glibc loader refusal matched exit code 127"
                ),
                "upgrade-rollback.previous.elf_contract": (
                    "historical payload matched DYN plus exact glibc PT_INTERP failure class"
                ),
                "upgrade-rollback.rollback.executable": (
                    "historical glibc loader refusal matched exit code 127"
                ),
                "upgrade-rollback.rollback.elf_contract": (
                    "historical payload matched DYN plus exact glibc PT_INTERP failure class"
                ),
                "upgrade-rollback.recovery.candidate": "command completed",
                "upgrade-rollback.recovery.candidate.maintainer_script": (
                    "maintainer script emitted no Go panic or fatal runtime diagnostic"
                ),
            }
            for event in scenario["events"]:
                if event["check"] in details:
                    event["detail"] = details[event["check"]]

        classification = package_lifecycle_lab.classify_lifecycle_evidence(
            platforms
        )
        self.assertTrue(classification["harness_complete"])
        self.assertTrue(classification["release_ready"])
        self.assertEqual(classification["blocker_ids"], [])

        missing_recovery = json.loads(json.dumps(platforms))
        recovery = next(
            event
            for platform_result in missing_recovery
            if platform_result["distribution"] == "alpine"
            and platform_result["architecture_id"] == "amd64"
            for scenario in platform_result["scenarios"]
            if scenario["name"] == "upgrade-rollback"
            for event in scenario["events"]
            if event["check"] == "upgrade-rollback.recovery.candidate"
        )
        recovery["detail"] = "candidate recovery was skipped"
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(
            missing_recovery
        )
        self.assertFalse(rejected["harness_complete"])
        self.assertTrue(rejected["unexpected_failed_checks"])

        wrong_hash = json.loads(json.dumps(platforms))
        next(
            item
            for item in wrong_hash
            if item["distribution"] == "alpine"
            and item["architecture_id"] == "arm64"
        )["previous"]["sha256"] = "0" * 64
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(wrong_hash)
        self.assertFalse(rejected["harness_complete"])
        self.assertTrue(rejected["unexpected_failed_checks"])

    def test_config_panics_are_unexpected_after_cfg_closure(self) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        detail = (
            "package manager returned success after maintainer script emitted a Go panic"
        )
        for platform_result in platforms:
            if platform_result["distribution"] == "alpine":
                continue
            platform_result["status"] = "fail"
            for scenario in platform_result["scenarios"]:
                scenario["status"] = "fail"
                scenario["container_exit_code"] = 1
                scenario["container_start_exit_codes"] = [
                    1 for _ in scenario["container_start_exit_codes"]
                ]
                for event in scenario["events"]:
                    if event["check"].endswith(".maintainer_script"):
                        event.update(status="fail", detail=detail)
        classification = package_lifecycle_lab.classify_lifecycle_evidence(
            platforms
        )
        self.assertFalse(classification["harness_complete"])
        self.assertFalse(classification["release_ready"])
        self.assertEqual(classification["blocker_ids"], [])
        self.assertTrue(classification["unexpected_failed_checks"])

        partial = json.loads(json.dumps(platforms))
        event = next(
            event
            for platform_result in partial
            if platform_result["distribution"] == "debian"
            and platform_result["architecture_id"] == "amd64"
            for scenario in platform_result["scenarios"]
            for event in scenario["events"]
            if event["check"].endswith(".maintainer_script")
        )
        event.update(
            status="pass",
            detail="maintainer script emitted no Go panic or fatal runtime diagnostic",
        )
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(partial)
        self.assertFalse(rejected["harness_complete"])
        self.assertEqual(rejected["blocker_ids"], [])
        self.assertTrue(rejected["unexpected_failed_checks"])

    def test_exact_amd64_blockers_stay_canonical_when_arm64_is_unavailable(self) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        config_detail = (
            "package manager returned success after maintainer script emitted a Go panic"
        )
        for platform_result in platforms:
            if platform_result["architecture_id"] == "arm64":
                platform_result.update(status="incomplete", scenarios=[])
                continue
            platform_result["status"] = "fail"
            for scenario in platform_result["scenarios"]:
                scenario["status"] = "fail"
                scenario["container_exit_code"] = 1
                scenario["container_start_exit_codes"] = [
                    1 for _ in scenario["container_start_exit_codes"]
                ]
                for event in scenario["events"]:
                    if (
                        platform_result["distribution"] == "alpine"
                        and event["check"].endswith(".executable")
                    ):
                        event.update(
                            status="fail",
                            detail="CLI execution failed with exit code 127",
                        )
                    elif (
                        platform_result["distribution"] != "alpine"
                        and event["check"].endswith(".maintainer_script")
                    ):
                        event.update(status="fail", detail=config_detail)

        classification = package_lifecycle_lab.classify_lifecycle_evidence(
            platforms
        )
        self.assertFalse(classification["harness_complete"])
        self.assertFalse(classification["release_ready"])
        self.assertEqual(classification["blocker_ids"], [])
        self.assertTrue(classification["unexpected_failed_checks"])
        self.assertNotIn("SW-CFG-001", repr(classification))

        changed_detail = json.loads(json.dumps(platforms))
        drifted = next(
            event
            for platform_result in changed_detail
            if platform_result["distribution"] == "ubuntu"
            and platform_result["architecture_id"] == "amd64"
            for scenario in platform_result["scenarios"]
            for event in scenario["events"]
            if event["check"].endswith(".maintainer_script")
        )
        drifted["detail"] = "maintainer panic text changed"
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(
            changed_detail
        )
        self.assertFalse(rejected["harness_complete"])
        self.assertEqual(rejected["blocker_ids"], [])
        self.assertIn(
            f"ubuntu/amd64:{drifted['check']}",
            rejected["unexpected_failed_checks"],
        )

    def test_rpm_remove_is_verified_as_final_purge_equivalent(self) -> None:
        checks = package_lifecycle_lab.expected_event_checks("rpm", "remove")
        self.assertIn("remove.final-removal", checks)
        self.assertIn("remove.final-removal.purge-equivalent", checks)
        self.assertIn("remove.final-removal.generated.systemd_core", checks)
        self.assertIn(
            "remove.final-removal.generated.systemd_core_enablement", checks
        )
        self.assertIn(
            "remove.final-removal.generated.openrc_firewall_enablement", checks
        )
        self.assertIn("remove.final-removal.service_manager_calls", checks)
        self.assertIn("remove.final-removal.generated.openrc_webtui", checks)
        self.assertIn("remove.final-removal.generated.completion", checks)
        self.assertIn("remove.final-removal.generated.cron_reference", checks)
        self.assertIn("remove.final-removal.generated.cron_unrelated", checks)
        self.assertFalse(any("not_applicable" in check for check in checks))
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        for platform_result in report["platforms"]:
            if platform_result["family"] == "rpm":
                self.assertEqual(
                    [item["name"] for item in platform_result["scenarios"]],
                    ["upgrade-rollback", "remove"],
                )
                self.assertTrue(
                    all(
                        item["status"] != "not_applicable"
                        for item in platform_result["scenarios"]
                    )
                )

    def test_remove_and_purge_seed_and_verify_generated_runtime_artifacts(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        self.assertIn("seed_generated_runtime_artifacts", script)
        self.assertIn("assert_generated_runtime_artifacts_absent", script)
        self.assertIn("/etc/systemd/system/syswarden-firewall.service", script)

    def test_systemd_enablement_target_depends_on_scenario_provenance(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("expected_systemd_enablement_prefix() {")
        end = source.index("\nprobe_postinstall_contract() {", start)
        function = source[start:end]
        cases = {
            **{
                ("upgrade-rollback", label): "/etc/systemd/system"
                for label in (
                    "previous",
                    "candidate",
                    "reinstall",
                    "restart-one",
                    "restart-two",
                    "rollback",
                    "recovery",
                )
            },
            ("remove", "fresh"): "..",
            ("purge", "fresh"): "..",
        }
        for (scenario, label), expected in cases.items():
            with self.subTest(scenario=scenario, label=label):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        function
                        + '\nSCENARIO="$1"; expected_systemd_enablement_prefix "$2"',
                        "probe",
                        scenario,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout.strip(), expected)

        rejected = subprocess.run(
            [
                "/bin/sh",
                "-c",
                function
                + '\nSCENARIO="$1"; expected_systemd_enablement_prefix "$2"',
                "probe",
                "remove",
                "candidate",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0, rejected)

    def test_cleanup_shell_events_match_declared_contract_exactly(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = script.index("assert_generated_runtime_artifacts_absent() {")
        end = script.index("\nprepare_expected_payloads() {", start)
        emitted = list(
            dict.fromkeys(
                re.findall(r"\$\{label\}\.([a-z0-9_.-]+)", script[start:end])
            )
        )
        declared = [
            check.removeprefix("remove.remove.")
            for check in package_lifecycle_lab.expected_event_checks("deb", "remove")
            if check.startswith("remove.remove.generated.")
            or check == "remove.remove.service_manager_calls"
        ]
        self.assertEqual(emitted, declared)

    def test_offline_package_lab_enforces_manager_sentinels_and_boot_links(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        self.assertIn("install_service_manager_sentinels", script)
        self.assertIn("/tmp/syswarden-service-manager-calls", script)
        self.assertIn("/tmp/syswarden-manager-original-path", script)
        self.assertIn('PATH="${SYSWARDEN_MANAGER_ORIGINAL_PATH:-${PATH}}"', script)
        self.assertIn(
            'record fail "${PREFIX}.${label}.service_manager_calls"', script
        )
        self.assertIn(
            "scenario_upgrade_rollback_restart_one() {\n"
            "    load_state_contract || return\n"
            "    install_service_manager_sentinels || return",
            script,
        )
        self.assertIn(
            "scenario_upgrade_rollback_restart_two() {\n"
            "    load_state_contract || return\n"
            "    install_service_manager_sentinels || return",
            script,
        )
        for command in ("systemctl", "rc-service", "rc-update", "service"):
            self.assertIn(command, script)
        self.assertIn("[ -s /tmp/syswarden-service-manager-calls ]", script)
        for link in (
            "/etc/systemd/system/multi-user.target.wants/syswarden-core.service",
            "/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service",
            "/etc/runlevels/default/syswarden-core",
            "/etc/runlevels/default/syswarden-firewall",
        ):
            self.assertIn(link, script)
        self.assertIn("/etc/init.d/syswarden-firewall", script)
        self.assertIn("/etc/bash_completion.d/syswarden", script)
        self.assertIn("/etc/rsyslog.d/99-syswarden-siem.conf", script)
        self.assertIn("/opt/syswarden/bin/syswarden-cli update-feeds", script)
        self.assertIn(
            "19 4 * * * /opt/syswarden/bin/syswarden-cli update-feeds --operator-option",
            script,
        )
        for adversarial in (
            "# operator note mentioning syswarden-cli",
            " */30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1",
            "17  * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1",
            "*/30\\t* * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1",
            "23 * * * * /srv/operator/bin/syswarden-cli update-feeds >/dev/null 2>&1",
        ):
            with self.subTest(adversarial=adversarial):
                self.assertIn(adversarial, script)
        self.assertIn("printf '%s \\n' '17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1'", script)
        self.assertIn("printf ' \\t \\n'", script)
        self.assertIn(
            "LC_ALL=C crontab -l > /tmp/syswarden-existing-cron "
            "2>/tmp/syswarden-existing-cron.error || return 1",
            script,
        )
        self.assertIn(
            'LC_ALL=C crontab -l 2>/tmp/syswarden-remove-cron.error',
            script,
        )
        self.assertIn(
            '$0 == "*/30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync '
            '>/dev/null 2>&1"',
            script,
        )
        self.assertIn(
            '$0 == $1 " * * * * /opt/syswarden/bin/syswarden-cli '
            'update-feeds >/dev/null 2>&1"',
            script,
        )
        self.assertIn(
            'while IFS= read -r operator_cron_line || [ -n "${operator_cron_line}" ]',
            script,
        )
        for family, scenario in (
            ("deb", "remove"),
            ("deb", "purge"),
            ("rpm", "remove"),
            ("apk", "remove"),
            ("apk", "purge"),
        ):
            with self.subTest(family=family, scenario=scenario):
                checks = package_lifecycle_lab.expected_event_checks(family, scenario)
                generated = [check for check in checks if ".generated." in check]
                label = "final-removal" if family == "rpm" else scenario
                expected_generated = [
                    f"{scenario}.{label}.generated.{key}"
                    for key in (
                        "systemd_core",
                        "systemd_firewall",
                        "systemd_webtui",
                        "openrc_core",
                        "openrc_firewall",
                        "openrc_webtui",
                        "systemd_core_enablement",
                        "systemd_firewall_enablement",
                        "openrc_core_enablement",
                        "openrc_firewall_enablement",
                        "completion",
                        "rsyslog_siem",
                        "rsyslog_waf_bridge",
                        "cron_reference",
                        "cron_unrelated",
                    )
                ]
                self.assertEqual(generated, expected_generated)
                self.assertIn(
                    f"{scenario}.{label}.service_manager_calls", checks
                )

    def test_candidate_dependency_and_postinstall_events_are_mandatory(self) -> None:
        for family, scenarios in package_lifecycle_lab.EXPECTED_SCENARIOS.items():
            for scenario in scenarios:
                with self.subTest(family=family, scenario=scenario):
                    checks = package_lifecycle_lab.expected_event_checks(
                        family, scenario
                    )
                    self.assertIn(
                        f"{scenario}.metadata.candidate.runtime_dependencies",
                        checks,
                    )
                    candidate_labels = (
                        ("candidate", "reinstall", "recovery")
                        if scenario == "upgrade-rollback"
                        else ("fresh",)
                    )
                    for label in candidate_labels:
                        self.assertIn(
                            f"{scenario}.{label}.postinstall_contract", checks
                        )

    def test_apk_postinstall_contract_covers_fresh_upgrade_reinstall_and_recovery(self) -> None:
        upgrade_checks = package_lifecycle_lab.expected_event_checks(
            "apk", "upgrade-rollback"
        )
        for label in ("candidate", "reinstall", "recovery"):
            self.assertIn(
                f"upgrade-rollback.{label}.postinstall_contract",
                upgrade_checks,
            )
        for scenario in ("remove", "purge"):
            self.assertIn(
                f"{scenario}.fresh.postinstall_contract",
                package_lifecycle_lab.expected_event_checks("apk", scenario),
            )

    def test_candidate_nft_runtime_is_not_required_after_container_restart(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("candidate_nft_runtime_required() {")
        end = source.index("\noperator_listener_process_identity() {", start)
        function = source[start:end]
        cases = {
            ("upgrade-rollback", "candidate"): 0,
            ("upgrade-rollback", "reinstall"): 0,
            ("upgrade-rollback", "recovery"): 0,
            ("remove", "fresh"): 0,
            ("purge", "fresh"): 0,
            ("upgrade-rollback", "restart-one"): 1,
            ("upgrade-rollback", "restart-two"): 1,
        }
        for (scenario, label), expected in cases.items():
            with self.subTest(scenario=scenario, label=label):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        function
                        + '\nSCENARIO="$1"; candidate_nft_runtime_required "$2"',
                        "probe",
                        scenario,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_seed_scopes_legacy_saas_adoption_to_upgrade_rollback(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        writer_start = source.index("write_seeded_operator_token() {")
        writer_end = source.index("\nseed_state() {", writer_start)
        writer = source[writer_start:writer_end]
        token = self.root / "seeded-operator-token.toml"
        base_fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[user]\nprofile_name = "lifecycle-operator"\n'
        )
        upgrade_fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[network.saas]\nallow_monitors = true\n\n'
            b'[user]\nprofile_name = "lifecycle-operator"\n'
        )
        for scenario, expected in (
            ("upgrade-rollback", upgrade_fixture),
            ("remove", base_fixture),
            ("purge", base_fixture),
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        writer
                        + '\nSCENARIO="$1"; write_seeded_operator_token "$2"',
                        "seed",
                        scenario,
                        str(token),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(token.read_bytes(), expected)

        seed_start = source.index("seed_state() {")
        seed_end = source.index("\nseed_legacy_webtui_upgrade_state() {", seed_start)
        seed = source[seed_start:seed_end]
        self.assertIn(
            "write_seeded_operator_token /etc/syswarden/config/modules/99-user.toml",
            seed,
        )
        self.assertIn("STATE_TOKEN_HASH=", seed)
        self.assertLess(
            seed.index("write_seeded_operator_token"),
            seed.index("STATE_TOKEN_HASH="),
        )
        self.assertLess(
            source.index("seed_state\n", source.index("scenario_upgrade_rollback_initial() {")),
            source.index("seed_legacy_saas_monitor_state || return"),
        )

    def test_postinstall_failure_detail_codes_keep_existing_event_ids(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        probe_start = source.index("probe_postinstall_contract() {")
        probe_end = source.index("\nverify_installed_inventory() {", probe_start)
        probe = source[probe_start:probe_end]
        self.assertIn('mark_postinstall_failure legacy-saas-ipv6', probe)
        self.assertIn('mark_postinstall_failure nft-runtime', probe)
        self.assertIn('mark_postinstall_failure operator-listener', probe)
        self.assertIn(
            'record fail "${PREFIX}.${label}.postinstall_contract"', probe
        )

    def test_historical_rollback_token_exception_is_exact_and_recovery_is_strict(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("sanitize_historical_rollback_token() {")
        end = source.index("\nassert_package_absent() {", start)
        contract = source[start:end]
        self.assertIn('/^webtui_password = "[0-9a-f]+"$/', contract)
        self.assertIn('length(secret) != 32', contract)
        self.assertIn('credentials != 1', contract)
        self.assertIn('! grep -Fq "${rollback_secret}" "${COMMAND_LOG}"', contract)
        self.assertIn('upgrade-rollback:rollback:deb', contract)
        self.assertIn('upgrade-rollback:rollback:rpm', contract)
        self.assertIn(
            'assert_preserved "${label}" token /etc/syswarden/config/modules/99-user.toml',
            contract,
        )
        self.assertIn('[REDACTED]', source)

    def test_historical_rollback_token_sanitizer_restores_exact_seed_bytes(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("sanitize_historical_rollback_token() {")
        end = source.index("\nassert_historical_rollback_token() {", start)
        function = source[start:end]
        fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[network.saas]\nallow_monitors = true\n\n'
            b'[user]\nprofile_name = "lifecycle-operator"\n'
        )
        secret = b"0123456789abcdef0123456789abcdef"
        token = self.root / "rollback-token.toml"
        sanitized = self.root / "rollback-token.sanitized"
        secret_file = self.root / "rollback-token.secret"
        command = function + '\nsanitize_historical_rollback_token "$1" "$2" "$3"'

        token.write_bytes(
            fixture + b'\nwebtui_password = "' + secret + b'"'
        )
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                command,
                "sanitize",
                str(token),
                str(sanitized),
                str(secret_file),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sanitized.read_bytes(), fixture)
        self.assertEqual(secret_file.read_bytes(), secret + b"\n")
        self.assertEqual(sanitized.stat().st_mode & 0o777, 0o600)
        self.assertEqual(secret_file.stat().st_mode & 0o777, 0o600)

        for suffix in (
            b'webtui_password = "' + secret + b'"',
            b'\nwebtui_password = "' + secret + b'"\n',
        ):
            with self.subTest(suffix=suffix):
                sanitized.unlink(missing_ok=True)
                secret_file.unlink(missing_ok=True)
                token.write_bytes(fixture + suffix)
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                        "sanitize",
                        str(token),
                        str(sanitized),
                        str(secret_file),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_upgrade_seeds_and_proves_exact_browser_retirement_with_port_isolation(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn("seed_legacy_webtui_upgrade_state", script)
        self.assertIn("seed_live_legacy_webtui_process", script)
        self.assertLess(
            script.index("seed_legacy_webtui_upgrade_state || return"),
            script.index('run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"'),
        )
        self.assertIn("Description=SYSWARDEN Web-TUI (WebTTY)", script)
        self.assertIn("ExecStart=/opt/syswarden/bin/syswarden-cli web-tui", script)
        self.assertIn('command_args="web-tui"', script)
        self.assertIn('webtui_password = "lot0-lifecycle-retired-token"', script)
        self.assertIn("/run/syswarden-webtui.pid", script)
        self.assertIn("TCP-LISTEN:62027,bind=127.0.0.1", script)
        self.assertIn("TCP:127.0.0.1:62027", script)
        self.assertIn("syswarden-operator-62027", script)
        self.assertIn("--bind=127.0.0.1:62028", script)
        self.assertIn("https://127.0.0.1:62028/", script)
        self.assertIn("syswarden-legacy-webtui-process.pid", script)
        self.assertIn("007765622d74756900", script)
        self.assertIn('tcp dport 62027 accept comment "syswarden legacy Web-TUI"', script)
        self.assertIn("nft list table inet syswarden", script)
        self.assertIn("/opt/syswarden/bin/syswarden-tui", script)
        self.assertIn("/usr/local/bin/syswarden-tui", script)
        self.assertIn("syswarden-webtui.service.syswarden-retiring", script)
        self.assertIn(
            "legacy_webtui_runtime_absent / || mark_postinstall_failure legacy-webtui-runtime",
            script,
        )
        seed_function = script.split("seed_legacy_webtui_upgrade_state() {", 1)[1].split(
            "\n}\n\nseed_legacy_saas_monitor_state() {", 1
        )[0]
        self.assertIn("[ ! -e /run/openrc ] && [ ! -L /run/openrc ] || return 1", seed_function)
        self.assertNotIn("rc-service", seed_function)
        self.assertNotIn("rc-update", seed_function)
        for retired_override in (
            "/etc/systemd/system/syswarden-webtui.service.d",
            "/run/systemd/system/syswarden-webtui.service",
            "/run/systemd/system/syswarden-webtui.service.d",
            "/etc/conf.d/syswarden-webtui",
        ):
            self.assertIn(retired_override, script)
        openrc_marker = (
            "cat > /etc/init.d/syswarden-webtui "
            "<<'SYSWARDEN_OPENRC_WEBTUI'\n"
        )
        openrc_payload = script.split(openrc_marker, 1)[1].split(
            "\nSYSWARDEN_OPENRC_WEBTUI\n", 1
        )[0]
        self.assertNotIn("seed_", openrc_payload)
        self.assertEqual(
            openrc_payload,
            "#!/sbin/openrc-run\n\n"
            'name="syswarden-webtui"\n'
            'description="SYSWARDEN Web-TUI (WebTTY)"\n'
            'command="/opt/syswarden/bin/syswarden-cli"\n'
            'command_args="web-tui"\n'
            "command_background=true\n"
            'pidfile="/run/syswarden-webtui.pid"\n'
            'retry="TERM/5/KILL/5"\n\n'
            "depend() {\n\tneed net\n}",
        )
        self.assertIn(
            '[ "${operator_listener_ready}" -eq 1 ] || return 1',
            seed_function,
        )
        self.assertIn(
            'SEEDED_OPERATOR_LISTENER_PID="${operator_listener_pid}"',
            seed_function,
        )
        self.assertIn("operator_listener_process_identity", seed_function)
        self.assertEqual(script.count("seed_legacy_saas_monitor_state() {"), 1)
        self.assertEqual(script.count("seed_live_legacy_webtui_process() {"), 1)
        self.assertIn("seed_legacy_saas_monitor_state", script)
        self.assertLess(
            script.index("seed_legacy_saas_monitor_state || return"),
            script.index('run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"'),
        )
        self.assertIn(
            "printf '%s\\n%s' '192.0.2.10' '198.51.100.0/24'",
            script,
        )
        self.assertIn("syswarden_saas_monitors.ipv4", script)
        self.assertIn("syswarden_saas_monitors.ipv6", script)
        self.assertIn("syswarden_saas_monitors.pair", script)
        self.assertIn("syswarden-saas-pair-v1", script)
        self.assertIn(
            "daf3972b7d1f162ae7c9b5da4a53efed5ab9cb8fb4a2385139931c37287f440c",
            script,
        )
        self.assertIn(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            script,
        )
        probe = script[
            script.index("operator_listener_preservation_required() {") : script.index(
                "\nverify_installed_inventory() {"
            )
        ]
        self.assertIn(
            'upgrade-rollback:candidate|upgrade-rollback:reinstall)',
            probe,
        )
        listener_requirement = script[
            script.index("operator_listener_preservation_required() {") : script.index(
                "\ncandidate_nft_runtime_required() {"
            )
        ]
        self.assertIn(
            'probe_seeded_operator_listener_preservation "${label}" || mark_postinstall_failure operator-listener',
            probe,
        )
        self.assertIn(
            'operator_listener_pid_path=/tmp/syswarden-operator-62027.pid',
            probe,
        )
        self.assertIn("0:0:600", probe)
        self.assertIn('kill -0 "${operator_listener_pid}"', probe)
        self.assertIn("TCP:127.0.0.1:62027", probe)
        self.assertNotIn("upgrade-rollback:restart-one", listener_requirement)
        self.assertNotIn("upgrade-rollback:restart-two", listener_requirement)
        self.assertNotIn("upgrade-rollback:recovery", listener_requirement)
        self.assertNotIn("remove:fresh", listener_requirement)
        self.assertNotIn("purge:fresh", listener_requirement)
        self.assertIn(
            "(umask 077 && printf '%s\\n' \"${operator_listener_pid}\" > "
            "/tmp/syswarden-operator-62027.pid)",
            script,
        )
        self.assertIn(
            'SEEDED_OPERATOR_LISTENER_PID="${operator_listener_pid}"',
            script,
        )
        self.assertIn("SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY", script)
        self.assertIn("SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY", script)
        self.assertIn("/proc/${operator_identity_pid}/stat", probe)
        self.assertIn("/proc/${operator_identity_pid}/exe", probe)
        self.assertIn("operator_listener_matches_seeded_proof", probe)
        self.assertNotIn("export SEEDED_OPERATOR_LISTENER", script)
        self.assertNotIn("pkill", script)
        self.assertNotIn("killall", script)
        for bootstrap in (
            package_lifecycle_lab.DEB_BOOTSTRAP,
            package_lifecycle_lab.RPM_BOOTSTRAP,
            package_lifecycle_lab.APK_BOOTSTRAP,
        ):
            self.assertRegex(bootstrap, r"(?:^|\s)socat(?:\s|$)")

    def test_operator_listener_preservation_scope_matches_seed_lifetime(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("operator_listener_preservation_required() {")
        end = source.index("\n}\n\noperator_listener_process_identity() {", start)
        function = source[start : end + len("\n}\n")]
        shell = self.root / "operator-listener-scope.sh"
        shell.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            + function
            + "\n"
            + "assert_scope() {\n"
            + "    SCENARIO=\"$1\"\n"
            + "    label=\"$2\"\n"
            + "    expected=\"$3\"\n"
            + "    if operator_listener_preservation_required \"${label}\"; then\n"
            + "        actual=required\n"
            + "    else\n"
            + "        actual=skipped\n"
            + "    fi\n"
            + "    [ \"${actual}\" = \"${expected}\" ]\n"
            + "}\n"
            + "assert_scope upgrade-rollback candidate required\n"
            + "assert_scope upgrade-rollback reinstall required\n"
            + "assert_scope upgrade-rollback restart-one skipped\n"
            + "assert_scope upgrade-rollback restart-two skipped\n"
            + "assert_scope upgrade-rollback recovery skipped\n"
            + "assert_scope remove fresh skipped\n"
            + "assert_scope purge fresh skipped\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            ("/bin/sh", str(shell)),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_operator_listener_proof_rejects_post_hook_substitution(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("operator_listener_matches_seeded_proof() {")
        end = source.index(
            "\n}\n\nprobe_seeded_operator_listener_preservation() {", start
        )
        function = source[start : end + len("\n}\n")]
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                function
                + "\nset -eu\n"
                + "SEEDED_OPERATOR_LISTENER_PID=101\n"
                + "SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY=process-a\n"
                + "SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY=pidfile-a\n"
                + "operator_listener_matches_seeded_proof 101 process-a pidfile-a\n"
                + "if operator_listener_matches_seeded_proof 202 process-b pidfile-b; then exit 11; fi\n"
                + "if operator_listener_matches_seeded_proof 101 process-b pidfile-a; then exit 12; fi\n"
                + "if operator_listener_matches_seeded_proof 101 process-a pidfile-b; then exit 13; fi\n"
                + "unset SEEDED_OPERATOR_LISTENER_PID\n"
                + "if operator_listener_matches_seeded_proof 101 process-a pidfile-a; then exit 14; fi\n",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result)

    def test_lab_webtui_runtime_probe_rejects_override_and_dangling_surfaces(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("legacy_webtui_runtime_absent() {")
        end = source.index("\n}\n", start) + len("\n}\n")
        function = source[start:end]
        surfaces = (
            "etc/systemd/system/syswarden-webtui.service.d",
            "run/systemd/system/syswarden-webtui.service",
            "run/systemd/system/syswarden-webtui.service.d",
            "etc/conf.d/syswarden-webtui",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            clean = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    function + '\nlegacy_webtui_runtime_absent "$1"',
                    "probe",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(clean.returncode, 0, clean)

        for relative in surfaces:
            with self.subTest(surface=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                residue = root / relative
                residue.parent.mkdir(parents=True)
                residue.write_text("operator-owned override\n", encoding="utf-8")
                rejected = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        function + '\nlegacy_webtui_runtime_absent "$1"',
                        "probe",
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(rejected.returncode, 0, rejected)
                self.assertEqual(
                    residue.read_text(encoding="utf-8"),
                    "operator-owned override\n",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            residue = root / "etc/conf.d/syswarden-webtui"
            residue.parent.mkdir(parents=True)
            residue.symlink_to("/srv/operator/missing")
            rejected = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    function + '\nlegacy_webtui_runtime_absent "$1"',
                    "probe",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0, rejected)
            self.assertTrue(residue.is_symlink())

    def test_bootstrap_preinstalls_every_declared_runtime_dependency(self) -> None:
        expected = {
            "deb": (
                package_lifecycle_lab.DEB_BOOTSTRAP,
                {
                    "nftables", "ipset", "curl", "wget", "rsyslog", "cron",
                    "bash-completion", "wireguard-tools", "qrencode", "jq",
                    "unattended-upgrades", "apt-listchanges", "procps",
                    "e2fsprogs",
                },
            ),
            "rpm": (
                package_lifecycle_lab.RPM_BOOTSTRAP,
                {
                    "nftables", "ipset", "wget", "rsyslog", "cronie",
                    "bash-completion", "wireguard-tools", "qrencode", "jq",
                    "checkpolicy", "policycoreutils-python-utils",
                    "dnf-automatic", "procps-ng",
                    "e2fsprogs",
                },
            ),
            "apk": (
                package_lifecycle_lab.APK_BOOTSTRAP,
                {
                    "nftables", "curl", "wget", "rsyslog", "rsyslog-uxsock",
                    "bash-completion", "wireguard-tools", "libqrencode-tools", "jq",
                    "openrc",
                    "procps-ng",
                    "e2fsprogs-extra",
                    "shadow",
                },
            ),
        }
        for family, (bootstrap, dependencies) in expected.items():
            with self.subTest(family=family):
                for dependency in dependencies:
                    self.assertRegex(
                        bootstrap,
                        rf"(?:^|\s){re.escape(dependency)}(?:\s|$)",
                    )
        self.assertIn("epel-release", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertIn("test -x /usr/bin/gpasswd", package_lifecycle_lab.APK_BOOTSTRAP)

    def test_failed_event_fails_platform_and_overall_report(self) -> None:
        runner = FakePodmanRunner(event_status="fail")
        report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(all(item["status"] == "fail" for item in report["platforms"]))

    def test_missing_arm64_emulation_is_incomplete_and_never_coverage(self) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(
            self.args(arm64_emulator=None),
            runner=runner,
            host_architecture="x86_64",
        )
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["harness_complete"])
        self.assertFalse(report["release_ready"])
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(report["unexpected_failed_checks"])
        self.assertFalse(report["scope"]["container_lab_complete"])
        self.assertEqual(report["scope"]["architectures_completed"], ["amd64/x86_64"])
        arm_coverage = next(
            item
            for item in report["scope"]["architecture_coverage"]
            if item["architecture_id"] == "arm64"
        )
        self.assertEqual(arm_coverage["status"], "incomplete")
        arm_results = [
            item for item in report["platforms"] if item["architecture_id"] == "arm64"
        ]
        self.assertEqual(len(arm_results), 5)
        self.assertTrue(all(item["status"] == "incomplete" for item in arm_results))
        self.assertTrue(
            all(
                item["architecture_probe"]["execution_mode"]
                == "explicit_emulator_required"
                for item in arm_results
            )
        )
        arm_builds = [
            call
            for call in runner.calls
            if call[1] == "build"
            and call[call.index("--platform") + 1] == "linux/arm64"
        ]
        self.assertEqual(arm_builds, [])
        arm_probes = [
            call
            for call in runner.calls
            if call[1] == "run"
            and call[call.index("--platform") + 1] == "linux/arm64"
        ]
        self.assertEqual(arm_probes, [])

    def test_missing_arm64_binfmt_is_incomplete_without_any_arm_execution(self) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(
            self.args(_arm64_binfmt_registration=self.root / "missing-binfmt"),
            runner=runner,
            host_architecture="x86_64",
        )
        arm_results = [
            item for item in report["platforms"] if item["architecture_id"] == "arm64"
        ]
        self.assertTrue(all(item["status"] == "incomplete" for item in arm_results))
        self.assertTrue(
            all(
                item["architecture_probe"]["execution_mode"]
                == "host_binfmt_required"
                for item in arm_results
            )
        )
        arm_commands = [
            call
            for call in runner.calls
            if "--platform" in call
            and call[call.index("--platform") + 1] == "linux/arm64"
            and call[1] in {"run", "build", "create"}
        ]
        self.assertEqual(arm_commands, [])

    def test_wrong_emulated_uname_is_incomplete(self) -> None:
        runner = FakePodmanRunner(reported_architectures={"arm64": "x86_64"})
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=runner, host_architecture="x86_64"
        )
        self.assertEqual(report["status"], "incomplete")
        arm_results = [
            item for item in report["platforms"] if item["architecture_id"] == "arm64"
        ]
        self.assertTrue(all(item["status"] == "incomplete" for item in arm_results))
        self.assertTrue(
            all(
                item["architecture_probe"]["actual_uname"] == "x86_64"
                for item in arm_results
            )
        )

    def test_partial_distribution_matrix_is_incomplete_fail_closed(self) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(
            self.args(),
            runner=runner,
            platforms=package_lifecycle_lab.DEFAULT_PLATFORMS[:2],
            host_architecture="x86_64",
        )
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["scope"]["container_lab_complete"])
        self.assertEqual(len(report["scope"]["missing_platform_coordinates"]), 8)
        self.assertEqual(report["scope"]["architectures_completed"], [])

    def test_image_inspection_architecture_mismatch_is_rejected(self) -> None:
        runner = FakePodmanRunner()
        original_run = runner.run

        def wrong_platform(
            args: list[str] | tuple[str, ...],
            *,
            timeout: int,
            cwd: Path | None = None,
        ) -> package_lifecycle_lab.CommandResult:
            result = original_run(args, timeout=timeout, cwd=cwd)
            command = tuple(args)
            if command[1:3] == ("image", "inspect"):
                digest = command[-1].rsplit("@", 1)[1]
                return package_lifecycle_lab.CommandResult(
                    args=command,
                    returncode=0,
                    stdout=f"{digest}\tlinux/arm64\n",
                    stderr="",
                )
            return result

        with mock.patch.object(runner, "run", side_effect=wrong_platform):
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError,
                "image architecture mismatch",
            ):
                package_lifecycle_lab.ensure_image(
                    runner,
                    "podman",
                    package_lifecycle_lab.DEFAULT_PLATFORMS[0],
                    "never",
                )

    def test_rootful_podman_is_rejected(self) -> None:
        runner = FakePodmanRunner()
        original_run = runner.run

        def rootful(
            args: list[str] | tuple[str, ...],
            *,
            timeout: int,
            cwd: Path | None = None,
        ) -> package_lifecycle_lab.CommandResult:
            result = original_run(args, timeout=timeout, cwd=cwd)
            if tuple(args)[1] == "info":
                return package_lifecycle_lab.CommandResult(
                    args=tuple(args), returncode=0, stdout="false\n", stderr=""
                )
            return result

        with mock.patch.object(runner, "run", side_effect=rootful):
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError, "requires rootless"
            ):
                package_lifecycle_lab.run_lab(self.args(), runner=runner)

    def test_report_write_is_atomic_and_rejects_symlink_destination(self) -> None:
        report = {"schema_version": 1, "status": "pass"}
        destination = self.root / "report.json"
        package_lifecycle_lab.write_report(destination, report, pretty=True)
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), report)
        destination.unlink()
        target = self.root / "target.json"
        target.write_text("do not overwrite\n", encoding="utf-8")
        destination.symlink_to(target)
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "absent or a regular file"
        ):
            package_lifecycle_lab.write_report(destination, report, pretty=False)
        self.assertEqual(target.read_text(encoding="utf-8"), "do not overwrite\n")

    def test_main_emits_fail_closed_json_for_invalid_timeout(self) -> None:
        output = self.root / "report.json"
        with mock.patch("sys.stdout") as stdout:
            return_code = package_lifecycle_lab.main(
                (
                    "--packages-dir",
                    str(self.candidate),
                    "--previous-packages-dir",
                    str(self.previous),
                    "--scenario-timeout",
                    "1",
                    "--output",
                    str(output),
                )
            )
        self.assertEqual(return_code, 1)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "fail")
        stdout.write.assert_called_once()

    def test_main_returns_nonzero_for_incomplete_architecture_report(self) -> None:
        incomplete = {
            "schema_version": package_lifecycle_lab.SCHEMA_VERSION,
            "status": "incomplete",
            "scope": {"container_lab_complete": False},
        }
        with mock.patch.object(
            package_lifecycle_lab, "run_lab", return_value=incomplete
        ), mock.patch("sys.stdout") as stdout:
            return_code = package_lifecycle_lab.main(
                (
                    "--packages-dir",
                    str(self.candidate),
                    "--previous-packages-dir",
                    str(self.previous),
                )
            )
        self.assertEqual(return_code, 1)
        stdout.write.assert_called_once()

    def test_parser_exposes_separate_digest_pinned_images_for_both_architectures(self) -> None:
        parser = package_lifecycle_lab.build_parser()
        args = parser.parse_args(
            (
                "--packages-dir",
                str(self.candidate),
                "--previous-packages-dir",
                str(self.previous),
            )
        )
        configured = package_lifecycle_lab.configured_platforms(args)
        self.assertIsNone(args.arm64_emulator)
        self.assertEqual(len(configured), 10)
        self.assertEqual(
            {package_lifecycle_lab.platform_coordinate(spec) for spec in configured},
            package_lifecycle_lab.REQUIRED_PLATFORM_COORDINATES,
        )
        self.assertTrue(all("@sha256:" in spec.image for spec in configured))

        arm_shard = parser.parse_args(
            (
                "--packages-dir",
                str(self.candidate),
                "--previous-packages-dir",
                str(self.previous),
                "--architecture-shard",
                "arm64",
            )
        )
        arm_configured = package_lifecycle_lab.configured_platforms(arm_shard)
        self.assertEqual(len(arm_configured), 5)
        self.assertEqual(
            {spec.architecture for spec in arm_configured},
            {"arm64"},
        )

        replacement_image = (
            "docker.io/library/ubuntu:24.04@sha256:" + "f" * 64
        )
        overridden = parser.parse_args(
            (
                "--packages-dir",
                str(self.candidate),
                "--previous-packages-dir",
                str(self.previous),
                "--ubuntu-arm64-image",
                replacement_image,
                "--arm64-emulator",
                str(self.emulator),
            )
        )
        ubuntu_arm64 = next(
            spec
            for spec in package_lifecycle_lab.configured_platforms(overridden)
            if package_lifecycle_lab.platform_coordinate(spec)
            == ("ubuntu", "arm64")
        )
        self.assertEqual(ubuntu_arm64.image, replacement_image)
        self.assertEqual(overridden.arm64_emulator, self.emulator)


if __name__ == "__main__":
    unittest.main()
