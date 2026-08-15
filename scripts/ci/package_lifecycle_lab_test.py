#!/usr/bin/env python3
"""Tests for the rootless package lifecycle laboratory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
                    "/usr/lib/.build-id/22",
                    "/usr/lib/.build-id/22/" + "2" * 38,
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
            "/usr/lib/.build-id/22/" + "2" * 38: (
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
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            if spec.family != "apk":
                continue
            historical = fixture["artifacts"][spec.package_architecture]
            pair = package_lifecycle_lab.PackagePair(
                candidate=package_lifecycle_lab.PackageArtifact(
                    self.candidate
                    / f"syswarden_4.02.11_{spec.package_architecture}.apk",
                    "4.02.11",
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
        self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertIn(f"{self.candidate}:/candidate:ro", args)
        self.assertIn(f"{self.previous}:/previous:ro", args)
        self.assertNotIn("--privileged", args)
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
            'CANDIDATE_PACKAGE="/candidate/v4.02.11.apk"\n'
            'PREVIOUS_VERSION="4.02.8"\n'
            'CANDIDATE_VERSION="4.02.11"\n'
            'EXPECTED_PREVIOUS_VERSION="4.02.8"\n'
            'EXPECTED_CANDIDATE_VERSION="4.02.11"\n'
            'FORWARD_ONLY_APK_TRANSITION="1"\n'
            "prepare_expected_payloads() { return 0; }\n"
            "seed_state() { :; }\n"
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
            "pass\tinstall.payload\tmatched\ninfo\tfreebsd\tvm required\n",
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

    def test_fake_rootless_run_reports_container_scope_and_freebsd_gap(self) -> None:
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
        self.assertEqual(report["scope"]["freebsd"]["status"], "vm_required")
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
                candidate_version="4.02.11",
                previous_version="4.02.8",
                candidate={
                    "filename": f"syswarden_4.02.11_{architecture}.apk",
                    "version": "4.02.11",
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
        self.assertIn("/etc/init.d/syswarden-firewall", script)
        self.assertIn("/etc/bash_completion.d/syswarden", script)
        self.assertIn("/etc/rsyslog.d/99-syswarden-siem.conf", script)
        self.assertIn("/opt/syswarden/bin/syswarden-cli update-feeds", script)
        self.assertIn(
            "19 4 * * * /opt/syswarden/bin/syswarden-cli update-feeds --operator-option",
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
                self.assertEqual(len(generated), 11)

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

    def test_bootstrap_preinstalls_every_declared_runtime_dependency(self) -> None:
        expected = {
            "deb": (
                package_lifecycle_lab.DEB_BOOTSTRAP,
                {
                    "nftables", "ipset", "curl", "wget", "rsyslog", "cron",
                    "bash-completion", "wireguard-tools", "qrencode", "jq",
                },
            ),
            "rpm": (
                package_lifecycle_lab.RPM_BOOTSTRAP,
                {
                    "nftables", "ipset", "wget", "rsyslog", "cronie",
                    "bash-completion", "wireguard-tools", "qrencode", "jq",
                    "checkpolicy", "policycoreutils-python-utils",
                },
            ),
            "apk": (
                package_lifecycle_lab.APK_BOOTSTRAP,
                {
                    "nftables", "curl", "wget", "rsyslog", "rsyslog-uxsock",
                    "bash-completion", "wireguard-tools", "libqrencode-tools", "jq",
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
