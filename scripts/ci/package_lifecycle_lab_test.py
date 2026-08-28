#!/usr/bin/env python3
"""Tests for the rootless package lifecycle laboratory."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_lifecycle_lab


def set_capability_bit(mask: str, bit: int, *, present: bool) -> str:
    value = int(mask, 16)
    encoded_bit = 1 << bit
    value = value | encoded_bit if present else value & ~encoded_bit
    return f"{value:016x}"


def namespace_failure_record(
    predicate: str,
    status: int | str,
    actual: str,
    expected: str,
) -> str:
    actual_bytes = actual.encode()
    expected_bytes = expected.encode()
    prefix_bytes = package_lifecycle_lab.NAMESPACE_DIAGNOSTIC_PREFIX_BYTES
    return (
        package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
        + f"\tpredicate={predicate}\trc={status}"
        + f"\tactual_bytes={len(actual_bytes)}"
        + f"\tactual_hex_prefix={actual_bytes[:prefix_bytes].hex()}"
        + f"\texpected_bytes={len(expected_bytes)}"
        + f"\texpected_hex_prefix={expected_bytes[:prefix_bytes].hex()}\n"
    )


class _LegacyFakePodmanRunner(package_lifecycle_lab.CommandRunner):
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
        result_root: Path,
        family: str,
        scenario: str,
        previous_version: str,
        candidate_version: str,
    ) -> None:
        file_modes = {
            "/opt/syswarden/bin/syswarden-cli": "750",
            "/opt/syswarden/bin/syswarden-core": "750",
            "/opt/syswarden/bin/syswarden-tui": "750",
            "/opt/syswarden/signatures.json": "640",
            package_lifecycle_lab.BASH_COMPLETION_PATH: "644",
            package_lifecycle_lab.GEOIP_DATA_LICENSE_PATH: "644",
            package_lifecycle_lab.PROJECT_LICENSE_PATH: "644",
        }
        file_digests = {
            package_lifecycle_lab.GEOIP_DATA_LICENSE_PATH: (
                package_lifecycle_lab.GEOIP_DATA_LICENSE_SHA256
            ),
            package_lifecycle_lab.PROJECT_LICENSE_PATH: (
                package_lifecycle_lab.PROJECT_LICENSE_SHA256
            ),
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

        def render(version: str) -> tuple[list[str], list[str]]:
            licensed = (
                package_lifecycle_lab.parse_syswarden_version(version)
                >= package_lifecycle_lab.parse_syswarden_version("4.04.0")
            )
            if family == "deb":
                paths = sorted(
                    package_lifecycle_lab.LICENSED_DEB_PACKAGE_PATHS
                    if licensed
                    else package_lifecycle_lab.DEB_PACKAGE_PATHS
                )
            elif family == "apk":
                paths = sorted(
                    package_lifecycle_lab.LICENSED_APK_PACKAGE_PATHS
                    if licensed
                    else package_lifecycle_lab.APK_PACKAGE_PATHS
                )
            else:
                paths = sorted(
                    set(
                        package_lifecycle_lab.LICENSED_PACKAGE_PAYLOAD_PATHS
                        if licensed
                        else package_lifecycle_lab.PACKAGE_PAYLOAD_PATHS
                    )
                    | {
                        "/usr/lib/.build-id",
                        "/usr/lib/.build-id/11",
                        "/usr/lib/.build-id/11/" + "1" * 38,
                        "/usr/lib/.build-id/11/" + "2" * 38,
                        "/usr/lib/.build-id/33",
                        "/usr/lib/.build-id/33/" + "3" * 38,
                    }
                )
            filesystem: list[str] = []
            for path in paths:
                if path in file_modes:
                    kind, mode, value = (
                        "file",
                        file_modes[path],
                        file_digests.get(path, "a" * 64),
                    )
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
            return paths, filesystem

        snapshots = {
            "previous": render(previous_version),
            "candidate": render(candidate_version),
        }
        inventory_root = result_root / "inventories"
        inventory_root.mkdir()
        for label in package_lifecycle_lab.expected_inventory_phase_labels(
            scenario
        ):
            role = (
                "previous"
                if label in {"previous", "rollback"}
                else "candidate"
            )
            paths, filesystem = snapshots[role]
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
                    "x86_64",
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
            candidate_version = next(
                value.split("=", 1)[1]
                for value in environment
                if value.startswith("EXPECTED_CANDIDATE_VERSION=")
            )
            previous_version = next(
                value.split("=", 1)[1]
                for value in environment
                if value.startswith("EXPECTED_PREVIOUS_VERSION=")
            )
            self.containers[name] = {
                "family": family,
                "scenario": scenario,
                "previous_version": previous_version,
                "candidate_version": candidate_version,
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
                    family,
                    scenario,
                    candidate_version=str(container["candidate_version"]),
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
                self.write_inventory_evidence(
                    result_root,
                    family,
                    scenario,
                    str(container["previous_version"]),
                    str(container["candidate_version"]),
                )
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


class FakePodmanRunner(package_lifecycle_lab.CommandRunner):
    """Exact stateful Podman double for ACTIVE raw-v5 lifecycle evidence."""

    def __init__(
        self,
        event_status: str = "pass",
        unavailable_architectures: set[str] | None = None,
        reported_architectures: dict[str, str] | None = None,
        reported_distributions: dict[str, str] | None = None,
        reported_distribution_versions: dict[str, str] | None = None,
        host_architecture: str = "amd64",
        namespace_failures: int = 0,
        namespace_failure_stderr: str = "runtime not ready\n",
        inspect_cap_add: list[str] | None = None,
        inspect_run_tmpfs: str = "rw,nodev,nosuid,exec,size=64m,mode=755",
        inspect_memory: object = 1_073_741_824,
        inspect_pids_limit: object = 512,
        uid_map: list[dict[str, int]] | None = None,
        gid_map: list[dict[str, int]] | None = None,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.event_status = event_status
        self.unavailable_architectures = unavailable_architectures or set()
        self.reported_architectures = reported_architectures or {}
        self.reported_distributions = reported_distributions or {}
        self.reported_distribution_versions = reported_distribution_versions or {}
        self.host_architecture = host_architecture
        self.namespace_failures = namespace_failures
        self.namespace_failure_stderr = namespace_failure_stderr
        self.inspect_cap_add = inspect_cap_add
        self.inspect_run_tmpfs = inspect_run_tmpfs
        self.inspect_memory = inspect_memory
        self.inspect_pids_limit = inspect_pids_limit
        self.uid_map = uid_map if uid_map is not None else [
            {"container_id": 0, "host_id": os.geteuid(), "size": 1},
            {"container_id": 1, "host_id": 524288, "size": 65536},
        ]
        self.gid_map = gid_map if gid_map is not None else [
            {"container_id": 0, "host_id": os.getegid(), "size": 1},
            {"container_id": 1, "host_id": 524288, "size": 65536},
        ]
        self.containers: dict[str, dict[str, object]] = {}
        self.images: set[str] = set()

    write_inventory_evidence = staticmethod(
        _LegacyFakePodmanRunner.write_inventory_evidence
    )

    @staticmethod
    def _spec_from_image(image: str) -> package_lifecycle_lab.PlatformSpec:
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            slug = package_lifecycle_lab.platform_slug(spec)
            if image == spec.image or f"syswarden-lifecycle-{slug}-" in image:
                return spec
        raise AssertionError(f"fake Podman received an unknown image: {image}")

    @staticmethod
    def _volume_values(command: tuple[str, ...]) -> list[str]:
        return [
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--volume"
        ]

    @staticmethod
    def _environment_values(command: tuple[str, ...]) -> dict[str, str]:
        values = [
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--env"
        ]
        return dict(value.split("=", 1) for value in values)

    @staticmethod
    def _product_state(script: str) -> str:
        match = re.search(
            r"syswarden_expected_product_state='(active|absent|unasserted)'",
            script,
        )
        if match is None:
            raise AssertionError("fake runtime snapshot lacks product state")
        return match.group(1)

    @staticmethod
    def _exec_security_marker(
        spec: package_lifecycle_lab.PlatformSpec,
    ) -> str:
        effective = (
            "00000000800c15fb"
            if spec.family != "apk"
            else "00000000a80425fb"
        )
        return "\t".join(
            (
                package_lifecycle_lab.EXEC_SECURITY_MARKER,
                "0000000000000000",
                effective,
                effective,
                effective,
                "0000000000000000",
                "1",
            )
        ) + "\n"

    def _runtime_snapshot(
        self,
        spec: package_lifecycle_lab.PlatformSpec,
        product_state: str,
        boot_index: int,
    ) -> str:
        systemd = spec.family != "apk"
        pid1_comm = "systemd" if systemd else "openrc-init"
        pid1_exe = "/usr/lib/systemd/systemd" if systemd else "/sbin/openrc-init"
        manager_runtime = "running" if systemd else "default"
        cron_service = (
            "cron.service"
            if spec.family == "deb"
            else "crond.service" if spec.family == "rpm" else "cronie"
        )
        cron_executable = package_lifecycle_lab.expected_cron_executable(spec)
        cron_fragment = (
            "/usr/lib/systemd/system/cron.service"
            if spec.family == "deb"
            else "/usr/lib/systemd/system/crond.service"
            if spec.family == "rpm"
            else "/etc/init.d/cronie"
        )
        cron_package = "cron" if spec.family == "deb" else "cronie"
        fragment_package = (
            "cronie-openrc" if spec.family == "apk" else cron_package
        )
        fragment_mode = "81ed" if spec.family == "apk" else "81a4"
        if spec.distribution == "fedora":
            cron_dropin_fields = (
                package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH,
                "10:22:81a4:0:0|"
                + "f" * 64
                + f"|systemd|259.8-1.fc44|{spec.package_architecture}|8",
            )
        else:
            cron_dropin_fields = ("-", "-")
        starttime = 1000 + boot_index * 100
        cron_pid = 2000 + boot_index * 100
        rsyslog_pid = 3000 + boot_index * 100
        core_digest = "a" * 64
        if systemd:
            pid1_security = (
                "0000000000000000",
                "00000000802c15fb",
                "00000000802c15fb",
                "00000000802c15fb",
                "0000000000000000",
                "1",
            )
            setpriv_fields = (
                "/usr/bin/setpriv",
                "10:30:81ed:0:0",
                "e" * 64,
                "util-linux",
                "2.41-5",
                spec.package_architecture,
            )
        else:
            pid1_security = (
                "0000000000000000",
                "00000000a80425fb",
                "00000000a80425fb",
                "00000000a80425fb",
                "0000000000000000",
                "1",
            )
            setpriv_fields = ("-", "-", "-", "-", "-", "-")
        core_security = (
            "0000000000000000",
            "000000000000100a",
            "000000000000100a",
            "000000000000100a",
            "0000000000000000",
            "1",
        )
        if product_state == "active":
            core_fragment = (
                "/etc/init.d/syswarden-core"
                if spec.family == "apk"
                else "/etc/systemd/system/syswarden-core.service"
            )
            firewall_fragment = (
                "/etc/init.d/syswarden-firewall"
                if spec.family == "apk"
                else "/etc/systemd/system/syswarden-firewall.service"
            )
            product_fields = (
                "loaded",
                core_fragment,
                "enabled",
                "active",
                str(4000 + boot_index * 100),
                "/opt/syswarden/bin/syswarden-core",
                f"11:22:81e8:0:0|{core_digest}",
                (
                    f"1:2:{4000 + boot_index * 100}:0:0:644"
                    if spec.family == "apk"
                    else "-"
                ),
                *core_security,
                "loaded",
                firewall_fragment,
                "enabled",
                "active",
                "0",
            )
        elif product_state == "absent":
            product_fields = (
                "absent",
                "-",
                "disabled",
                "inactive",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "absent",
                "-",
                "disabled",
                "inactive",
                "-",
            )
        else:
            product_fields = (
                "unasserted",
                "-",
                "unasserted",
                "unasserted",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "unasserted",
                "-",
                "unasserted",
                "unasserted",
                "-",
            )
        fields = (
            pid1_comm,
            pid1_exe,
            str(starttime),
            *pid1_security,
            ",".join(
                f"{item['container_id']}:{item['host_id']}:{item['size']}"
                for item in self.uid_map
            ),
            ",".join(
                f"{item['container_id']}:{item['host_id']}:{item['size']}"
                for item in self.gid_map
            ),
            *setpriv_fields,
            "ACTIVE",
            manager_runtime,
            "enabled",
            "active",
            str(cron_pid),
            cron_executable,
            "10:20:81ed:0:0|" + "c" * 64,
            cron_fragment,
            f"10:21:{fragment_mode}:0:0|" + "d" * 64,
            *cron_dropin_fields,
            cron_package,
            "1.0-r0",
            spec.package_architecture,
            fragment_package,
            "1.0-r0",
            spec.package_architecture,
            "enabled",
            "active",
            str(rsyslog_pid),
            "eth0:dummy:up",
            product_state,
            *product_fields,
            cron_service,
        )
        assert len(fields) == 59
        return "\t".join(fields) + "\n"

    def _write_lifecycle_evidence(self, container: dict[str, object]) -> None:
        result_root = container["result_root"]
        assert isinstance(result_root, Path)
        family = str(container["family"])
        scenario = str(container["scenario"])
        if not result_root.joinpath("events.tsv").exists():
            digest_labels = (
                {"candidate", "reinstall", "restart-one", "restart-two", "recovery"}
                if scenario == "upgrade-rollback"
                else {"fresh"}
            )
            records: list[str] = []
            for check in package_lifecycle_lab.expected_event_checks(
                family,
                scenario,
                candidate_version=str(container["candidate_version"]),
            ):
                detail = "fake verified evidence"
                if self.event_status == "pass" and check.endswith(
                    ".postinstall_contract"
                ):
                    label = check.split(".")[-2]
                    if label in digest_labels:
                        detail = (
                            "modular config, native TUI, services, completion, feed "
                            "cron, and browser-service retirement match the installed "
                            "version; core process sha256="
                            + "a" * 64
                            + " match the installed version"
                        )
                records.append(f"{self.event_status}\t{check}\t{detail}\n")
            result_root.joinpath("events.tsv").write_text(
                "".join(records), encoding="utf-8"
            )
            result_root.joinpath("commands.log").write_text(
                "fake lifecycle commands\n", encoding="utf-8"
            )
            self.write_inventory_evidence(
                result_root,
                family,
                scenario,
                str(container["previous_version"]),
                str(container["candidate_version"]),
            )
        invocation_index = int(container["invocation_index"])
        if scenario == "upgrade-rollback":
            result_root.joinpath("restart-state").write_text(
                ("restart-one", "restart-two", "complete")[invocation_index]
                + "\n",
                encoding="utf-8",
            )
        container["invocation_index"] = invocation_index + 1

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
        stderr = ""
        returncode = 0
        if command[1] == "version":
            stdout = "5.6.0\n"
        elif command[1] == "info":
            if command[-1] == "json":
                stdout = json.dumps(
                    {
                        "host": {
                            "security": {"rootless": True},
                            "cgroupVersion": "v2",
                            "cgroupManager": "systemd",
                            "cgroupControllers": ["cpu", "io", "memory", "pids"],
                            "arch": self.host_architecture,
                            "serviceIsRemote": False,
                            "os": "linux",
                            "idMappings": {
                                "uidmap": self.uid_map,
                                "gidmap": self.gid_map,
                            },
                        }
                    }
                )
            else:
                stdout = "true\n"
        elif command[1:3] == ("image", "exists"):
            image = command[-1]
            returncode = 0 if "@sha256:" in image or image in self.images else 1
        elif command[1:3] == ("image", "inspect"):
            spec = self._spec_from_image(command[-1])
            stdout = (
                command[-1].rsplit("@", 1)[1]
                + "\t"
                + spec.podman_platform
                + "\n"
            )
        elif command[1] == "build":
            self.images.add(command[command.index("--tag") + 1])
        elif command[1] == "run":
            platform_name = command[command.index("--platform") + 1]
            architecture = platform_name.split("/", 1)[1]
            spec = self._spec_from_image(
                next(
                    value
                    for value in command
                    if value.startswith("docker.io/") and "@sha256:" in value
                )
            )
            if architecture in self.unavailable_architectures:
                returncode = 126
                stderr = "exec format error\n"
            else:
                reported_version = self.reported_distribution_versions.get(
                    spec.cell_id, spec.version
                )
                reported_distribution = self.reported_distributions.get(
                    spec.cell_id, spec.distribution
                )
                stdout = (
                    self.reported_architectures.get(architecture, "x86_64")
                    + "\t"
                    + reported_distribution
                    + "\t"
                    + reported_version
                    + "\n"
                )
                if (
                    reported_distribution != spec.distribution
                    or not package_lifecycle_lab.distribution_version_matches(
                        spec.distribution,
                        spec.version,
                        reported_version,
                    )
                ):
                    returncode = 1
                    stderr = "distribution os-release identity mismatch\n"
        elif command[1] == "create":
            volumes = self._volume_values(command)
            result_mount = next(
                (value for value in volumes if value.endswith(":/results:rw")),
                None,
            )
            name = command[command.index("--name") + 1]
            if result_mount is None:
                self.containers[name] = {"bootstrap": True, "running": False}
            else:
                environment = self._environment_values(command)
                self.containers[name] = {
                    "family": environment["PACKAGE_FAMILY"],
                    "scenario": environment["SCENARIO"],
                    "previous_version": environment[
                        "EXPECTED_PREVIOUS_VERSION"
                    ],
                    "candidate_version": environment[
                        "EXPECTED_CANDIDATE_VERSION"
                    ],
                    "spec": self._spec_from_image(command[-1]),
                    "result_root": Path(result_mount.removesuffix(":/results:rw")),
                    "volumes": volumes,
                    "invocation_index": 0,
                    "boot_index": 0,
                    "running": False,
                }
        elif command[1] == "inspect":
            container = self.containers[command[-1]]
            spec = container["spec"]
            assert isinstance(spec, package_lifecycle_lab.PlatformSpec)
            mounts = []
            for value in container["volumes"]:
                source, destination, mode = str(value).rsplit(":", 2)
                mounts.append(
                    {
                        "Type": "bind",
                        "Source": source,
                        "Destination": destination,
                        "RW": mode == "rw",
                    }
                )
            caps = ["CAP_NET_ADMIN"]
            if spec.family == "apk":
                caps.append("CAP_SYS_BOOT")
            else:
                caps.append("CAP_SYS_ADMIN")
                caps.append("CAP_SYS_PTRACE")
            if self.inspect_cap_add is not None:
                caps = list(self.inspect_cap_add)
            stdout = json.dumps(
                [
                    {
                        "HostConfig": {
                            "Privileged": False,
                            "NetworkMode": "none",
                            "PidMode": "private",
                            "IpcMode": "private",
                            "UTSMode": "private",
                            "CgroupMode": "private",
                            "UsernsMode": "",
                            "Memory": self.inspect_memory,
                            "PidsLimit": self.inspect_pids_limit,
                            "CapAdd": caps,
                            "CapDrop": [],
                            "Devices": [],
                            "SecurityOpt": ["no-new-privileges", "label=disable"],
                            "Tmpfs": {
                                "/run": self.inspect_run_tmpfs,
                                "/tmp": "rw,nodev,nosuid,exec,size=256m,mode=1777",
                            },
                        },
                        "Config": {
                            "StopSignal": (
                                "SIGINT" if spec.family == "apk" else "SIGRTMIN+3"
                            )
                        },
                        "Mounts": mounts,
                    }
                ]
            )
        elif command[1] == "start":
            container = self.containers[command[-1]]
            container["running"] = True
            container["boot_index"] = 0
        elif command[1] == "restart":
            container = self.containers[command[-1]]
            container["running"] = True
            container["boot_index"] = int(container["boot_index"]) + 1
        elif command[1] == "exec":
            container = self.containers[command[2]]
            spec = container["spec"]
            assert isinstance(spec, package_lifecycle_lab.PlatformSpec)
            script = command[-1]
            stdout = self._exec_security_marker(spec)
            if "exec /bin/sh /lab/package-lifecycle.sh" in script:
                self._write_lifecycle_evidence(container)
                returncode = 1 if self.event_status == "fail" else 0
            else:
                if "capture_snapshot()" in script:
                    stdout += self._runtime_snapshot(
                        spec,
                        self._product_state(script),
                        int(container["boot_index"]),
                    )
                elif self.namespace_failures > 0:
                    self.namespace_failures -= 1
                    returncode = 1
                    stderr = self.namespace_failure_stderr
        elif command[1:3] == ("rm", "--force"):
            self.containers.pop(command[-1], None)
        elif command[1:3] == ("container", "exists"):
            returncode = 0 if command[-1] in self.containers else 1
        elif command[1:3] == ("image", "rm"):
            self.images.discard(command[-1])
        return package_lifecycle_lab.CommandResult(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )


class PackageLifecycleLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.candidate = self.root / "candidate"
        self.previous = self.root / "previous"
        self.package_tmp = self.root / "package-tmp"
        self.candidate.mkdir()
        self.previous.mkdir()
        self.package_tmp.mkdir(mode=0o700)
        self.create_package_set(self.candidate, b"candidate", "4.02.8")
        self.create_package_set(self.previous, b"previous", "4.02.7")

    @staticmethod
    def create_package_set(root: Path, content: bytes, version: str) -> None:
        names = (
            f"syswarden_{version}_amd64.deb",
            f"syswarden-{version}-1.x86_64.rpm",
            f"syswarden_{version}_x86_64.apk",
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
            "package_tmp_dir": self.package_tmp,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def qualification_args(self, architecture: str, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            **vars(self.args()),
            "architecture_shard": architecture,
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
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def native_shard_report(self) -> dict[str, object]:
        platforms = tuple(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.architecture == "amd64"
        )
        return package_lifecycle_lab.run_lab(
            self.qualification_args("amd64"),
            runner=FakePodmanRunner(host_architecture="amd64"),
            platforms=platforms,
            host_architecture="x86_64",
        )

    def aggregate_args(
        self,
        amd64_path: Path,
        **overrides: object,
    ) -> argparse.Namespace:
        values = {
            **vars(self.qualification_args("amd64")),
            "architecture_shard": None,
            "aggregate_amd64_report": amd64_path,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def run_embedded_inventory_contract(
        self,
        family: str,
        manifest_lines: list[str],
        inventory_lines: list[str] | None = None,
        *,
        role: str = "candidate",
        version: str = "4.03.3",
        candidate_version: str = "4.03.3",
        forward_only_apk: bool = False,
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
        expected_previous_version = (
            "4.02.8"
            if forward_only_apk
            else (version if role == "previous" else "4.03.2")
        )
        validation = (
            f'PACKAGE_FAMILY={family}\n'
            + f'EXPECTED_PREVIOUS_VERSION={expected_previous_version}\n'
            + f'EXPECTED_CANDIDATE_VERSION={candidate_version}\n'
            + f'FORWARD_ONLY_APK_TRANSITION={1 if forward_only_apk else 0}\n'
            + functions
            + f'\nvalidate_manifest_contract "$1" {role}\n'
            + (
                f'validate_inventory_contract "$2" {role}\n'
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
                "rpm:x86_64",
                "apk:x86_64",
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
                    / f"syswarden_4.03.2_{spec.package_architecture}.apk",
                    "4.03.2",
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

    def test_historical_ubuntu_deb_recovery_pair_is_exactly_byte_bound(self) -> None:
        ubuntu = next(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.distribution == "ubuntu"
        )
        debian = next(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.distribution == "debian"
        )
        historical = package_lifecycle_lab.HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS
        pair = package_lifecycle_lab.PackagePair(
            candidate=package_lifecycle_lab.PackageArtifact(
                self.candidate / "syswarden_4.03.3_amd64.deb",
                "4.03.3",
                "a" * 64,
            ),
            previous=package_lifecycle_lab.PackageArtifact(
                self.previous / historical["filename"],
                "4.03.2",
                historical["sha256"],
            ),
        )
        self.assertTrue(
            package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_pair(
                ubuntu, pair
            )
        )
        self.assertFalse(
            package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_pair(
                debian, pair
            )
        )

        mutations = (
            package_lifecycle_lab.PackagePair(
                candidate=pair.candidate,
                previous=package_lifecycle_lab.PackageArtifact(
                    pair.previous.path, pair.previous.version, "0" * 64
                ),
            ),
            package_lifecycle_lab.PackagePair(
                candidate=package_lifecycle_lab.PackageArtifact(
                    self.candidate / "syswarden_4.03.4_amd64.deb",
                    "4.03.3",
                    pair.candidate.sha256,
                ),
                previous=pair.previous,
            ),
            package_lifecycle_lab.PackagePair(
                candidate=pair.candidate,
                previous=package_lifecycle_lab.PackageArtifact(
                    pair.previous.path, "4.03.1", pair.previous.sha256
                ),
            ),
        )
        for tampered in mutations:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError,
                    "exact byte-bound",
                ):
                    package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_pair(
                        ubuntu, tampered
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

    def test_default_matrix_is_official_digest_pinned_and_complete(self) -> None:
        platforms = package_lifecycle_lab.DEFAULT_PLATFORMS
        self.assertEqual(len(platforms), 8)
        self.assertEqual(
            [spec.cell_id for spec in platforms],
            [
                "DEB-13",
                "DEB-U2404",
                "DEB-U2604",
                "RPM-F44",
                "RPM-A9",
                "RPM-A10",
                "APK-322",
                "APK-324",
            ],
        )
        self.assertEqual(
            [(spec.distribution, spec.version) for spec in platforms],
            [
                ("debian", "13"),
                ("ubuntu", "24.04"),
                ("ubuntu", "26.04"),
                ("fedora", "44"),
                ("almalinux", "9"),
                ("almalinux", "10"),
                ("alpine", "3.22"),
                ("alpine", "3.24"),
            ],
        )
        self.assertEqual(
            package_lifecycle_lab.QUALIFICATION_MATRIX_SHA256,
            hashlib.sha256(
                package_lifecycle_lab.QUALIFICATION_MATRIX_PATH.read_bytes()
            ).hexdigest(),
        )
        for spec, cell in zip(
            platforms,
            package_lifecycle_lab.QUALIFICATION_MATRIX_DOCUMENT["cells"],
            strict=True,
        ):
            with self.subTest(cell_id=spec.cell_id):
                self.assertEqual(spec.cell_id, cell["id"])
                self.assertEqual(spec.distribution, cell["distribution"])
                self.assertEqual(spec.version, cell["version"])
                self.assertEqual(spec.family, cell["family"])
                self.assertEqual(spec.image, cell["image"])
                self.assertEqual(
                    spec.scenarios,
                    tuple(cell["container_scenarios"]),
                )
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
            },
            {("deb", "amd64"), ("rpm", "x86_64"), ("apk", "x86_64")},
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
            podman_platform="linux/unsupported",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "Podman platform mismatch"
        ):
            package_lifecycle_lab.validate_platforms((wrong_architecture,))

        wrong_package = replace(
            baseline,
            package_pattern=r"^unsupported$",
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

        altered_runtime = replace(
            baseline,
            bootstrap_command=baseline.bootstrap_command + " && true",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "runtime contract differs from the frozen definition",
        ):
            package_lifecycle_lab.validate_platforms((altered_runtime,))

    def test_matrix_binding_rejects_semantically_equal_but_different_bytes(self) -> None:
        rewritten = self.root / "qualification-matrix.json"
        rewritten.write_text(
            json.dumps(package_lifecycle_lab.QUALIFICATION_MATRIX_DOCUMENT),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "matrix bytes differ",
        ):
            package_lifecycle_lab.qualification_matrix_binding(rewritten)

    def test_removed_arm64_architecture_is_rejected(self) -> None:
        removed = replace(
            package_lifecycle_lab.DEFAULT_PLATFORMS[0], architecture="arm64"
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "unsupported package lifecycle architecture",
        ):
            package_lifecycle_lab.validate_platforms((removed,))

    def test_missing_amd64_artifact_fails_before_container_execution(self) -> None:
        package = self.candidate / "syswarden_4.02.8_amd64.deb"
        package.unlink()
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "amd64"
        ):
            package_lifecycle_lab.validate_inputs(
                self.candidate,
                self.previous,
                package_lifecycle_lab.DEFAULT_PLATFORMS,
            )

    def test_package_temporary_directory_is_private_real_and_owner_bound(self) -> None:
        self.assertEqual(
            package_lifecycle_lab.require_private_directory(
                self.package_tmp, "package temporary directory"
            ),
            self.package_tmp.absolute(),
        )

        self.package_tmp.chmod(0o755)
        try:
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError, "mode 0700"
            ):
                package_lifecycle_lab.require_private_directory(
                    self.package_tmp, "package temporary directory"
                )
        finally:
            self.package_tmp.chmod(0o700)

        direct_link = self.root / "package-tmp-link"
        direct_link.symlink_to(self.package_tmp, target_is_directory=True)
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "real directory"
        ):
            package_lifecycle_lab.require_private_directory(
                direct_link, "package temporary directory"
            )

        ancestor_link = self.root / "root-link"
        ancestor_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "symlinked path components"
        ):
            package_lifecycle_lab.require_private_directory(
                ancestor_link / self.package_tmp.name,
                "package temporary directory",
            )

        with mock.patch.object(
            os, "geteuid", return_value=os.geteuid() + 1
        ), self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "owned by effective uid"
        ):
            package_lifecycle_lab.require_private_directory(
                self.package_tmp, "package temporary directory"
            )

    def test_unsafe_package_temporary_directory_fails_before_podman(self) -> None:
        unsafe = self.root / "unsafe-package-tmp"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        runner = FakePodmanRunner()
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError, "mode 0700"
        ):
            package_lifecycle_lab.run_lab(
                self.args(package_tmp_dir=unsafe), runner=runner
            )
        self.assertEqual(runner.calls, [])

        missing_runner = FakePodmanRunner()
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "--package-tmp-dir is required",
        ):
            package_lifecycle_lab.run_lab(
                self.args(package_tmp_dir=None), runner=missing_runner
            )
        self.assertEqual(missing_runner.calls, [])

    def test_workspace_is_created_beneath_explicit_package_temporary_directory(
        self,
    ) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "pass")
        build_calls = [call for call in runner.calls if call[1] == "build"]
        self.assertEqual(len(build_calls), len(package_lifecycle_lab.DEFAULT_PLATFORMS))
        for call in build_calls:
            with self.subTest(call=call):
                self.assertTrue(
                    Path(call[-1]).is_relative_to(self.package_tmp),
                    call[-1],
                )

    def test_containerfile_uses_exact_base_and_bootstrap_only(self) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        containerfile = package_lifecycle_lab.build_containerfile(spec)
        self.assertEqual(containerfile.count("FROM "), 1)
        self.assertIn(f"FROM {spec.image}\n", containerfile)
        self.assertIn("apt-get install", containerfile)
        self.assertIn("syswarden-lab-network", containerfile)
        self.assertIn("systemctl enable", containerfile)
        self.assertNotIn("/opt/syswarden", containerfile)
        self.assertNotIn("COPY ", containerfile)

    def test_fedora_mask_inventory_is_the_exact_seven_unit_set(self) -> None:
        expected = (
            "dbus-org.freedesktop.oom1.service",
            "dbus-org.freedesktop.resolve1.service",
            "systemd-oomd.service",
            "systemd-oomd.socket",
            "systemd-resolved-monitor.socket",
            "systemd-resolved-varlink.socket",
            "systemd-resolved.service",
        )
        self.assertEqual(package_lifecycle_lab.FEDORA_LAB_MASKED_UNITS, expected)
        self.assertEqual(
            package_lifecycle_lab.FEDORA_LAB_MASK_TARGETS,
            expected[2:],
        )
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "fedora"
        )
        containerfile = package_lifecycle_lab.build_containerfile(spec)
        self.assertIn(
            "RUN systemctl mask " + " ".join(expected[2:]) + "\n",
            containerfile,
        )
        self.assertNotIn("systemctl mask dbus-org.", containerfile)
        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        expected_masks = "\n".join(expected)
        self.assertIn(expected_masks, runtime)
        self.assertNotIn("\\n".join(expected), runtime)
        self.assertIn("list-unit-files --state=masked", runtime)
        self.assertNotIn("grep -v", runtime)
        for predicate in (
            "NS01_HELPER_SHA",
            "NS02_HELPER_STAT",
            "NS03_ETH0_LINK",
            "NS04_ETH0_DUMMY",
            "NS05_ETH0_UP_SOURCE",
            "NS06_ETH0_UP",
            "NS07_UNIT_SHA",
            "NS08_UNIT_STAT",
            "NS09_NET_ENABLED",
            "NS10_NET_ACTIVE",
            "NS11_RSYSLOG_ENABLED",
            "NS12_RSYSLOG_ACTIVE",
            "NS13_FAILED_UNITS",
            "NS14_FEDORA_MASKS",
        ):
            self.assertEqual(runtime.count(predicate), 1, predicate)
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=package_lifecycle_lab._exec_security_guard_script(spec) + runtime,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        masks_start = runtime.rindex(
            "syswarden_namespace_status=0\n", 0, runtime.index("actual_masks=")
        )
        masks_guard = runtime[masks_start:]

        def attest_masks(value: str) -> subprocess.CompletedProcess[str]:
            probe = (
                package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                + "systemctl() { printf '%s\\n' \"${MASK_INVENTORY}\"; }\n"
                + masks_guard
            )
            return subprocess.run(
                ["/bin/sh", "-eu", "-c", probe],
                env={**os.environ, "MASK_INVENTORY": value},
                text=True,
                capture_output=True,
                check=False,
            )

        canonical = attest_masks(expected_masks)
        self.assertEqual(canonical.returncode, 0, canonical.stderr)
        self.assertEqual(canonical.stdout, "")
        self.assertEqual(canonical.stderr, "")
        reordered = attest_masks(
            "\n".join((expected[1], expected[0], *expected[2:]))
        )
        self.assertEqual(reordered.returncode, 0, reordered.stderr)
        for label, adversarial in (
            ("literal-backslash-n", "\\n".join(expected)),
            ("missing", "\n".join(expected[:-1])),
            ("extra", expected_masks + "\noperator.service"),
            ("duplicate", expected_masks + "\n" + expected[-1]),
        ):
            with self.subTest(mask_inventory=label):
                rejected = attest_masks(adversarial)
                self.assertEqual(rejected.returncode, 1)
                self.assertEqual(rejected.stdout, "")
                self.assertIn(
                    package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                    + "\tpredicate=NS14_FEDORA_MASKS\trc=0\t",
                    rejected.stderr,
                )

        command_failure_probe = (
            package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
            + "systemctl() { printf 'permission denied\\n'; return 7; }\n"
            + masks_guard
        )
        command_failure = subprocess.run(
            ["/bin/sh", "-eu", "-c", command_failure_probe],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(command_failure.returncode, 1)
        self.assertIn(
            package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
            + "\tpredicate=NS14_FEDORA_MASKS\trc=7"
            + "\tactual_bytes=17"
            + f"\tactual_hex_prefix={'permission denied'.encode().hex()}",
            command_failure.stderr,
        )

    def test_namespace_failure_record_is_numbered_hex_and_injection_safe(
        self,
    ) -> None:
        actual = "first\\nsecond\noperator\tvalue"
        expected = "first\nsecond\noperator\tvalue"
        probe = (
            package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
            + 'syswarden_namespace_expect_equal NS14_FEDORA_MASKS 0 "$1" "$2"\n'
        )
        rejected = subprocess.run(
            ["/bin/sh", "-eu", "-c", probe, "probe", actual, expected],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(rejected.stdout, "")
        self.assertEqual(
            rejected.stderr,
            namespace_failure_record("NS14_FEDORA_MASKS", 0, actual, expected),
        )

        accepted = subprocess.run(
            ["/bin/sh", "-eu", "-c", probe, "probe", expected, expected],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, "")
        self.assertEqual(accepted.stderr, "")

        status_probe = (
            package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
            + 'syswarden_namespace_expect_status NS03_ETH0_LINK 7 "$1"\n'
        )
        failed_command = subprocess.run(
            ["/bin/sh", "-eu", "-c", status_probe, "probe", actual],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(failed_command.returncode, 1)
        self.assertIn("\tpredicate=NS03_ETH0_LINK\trc=7\t", failed_command.stderr)

        integer_probe = (
            package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
            + 'syswarden_namespace_expect_integer NS20_APK_RC_SYS_LINE '
            + '"$1" "$2" 1\n'
        )
        for actual in ("1", "01", "+1"):
            with self.subTest(integer=actual):
                numeric = subprocess.run(
                    ["/bin/sh", "-eu", "-c", integer_probe, "probe", "0", actual],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(numeric.returncode, 0, numeric.stderr)
                self.assertEqual(numeric.stdout, "")
                self.assertEqual(numeric.stderr, "")
        for status, actual in (("0", "2"), ("0", "invalid"), ("7", "1")):
            with self.subTest(status=status, rejected_integer=actual):
                numeric = subprocess.run(
                    [
                        "/bin/sh",
                        "-eu",
                        "-c",
                        integer_probe,
                        "probe",
                        status,
                        actual,
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(numeric.returncode, 1)
                self.assertEqual(numeric.stdout, "")
                self.assertIn(
                    namespace_failure_record(
                        "NS20_APK_RC_SYS_LINE", status, actual, "1"
                    ),
                    numeric.stderr,
                )

        oversized = "operator\n" + "x" * 32_768
        bounded = subprocess.run(
            ["/bin/sh", "-eu", "-c", probe, "probe", oversized, "exact"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(bounded.returncode, 1)
        self.assertEqual(
            bounded.stderr,
            namespace_failure_record("NS14_FEDORA_MASKS", 0, oversized, "exact"),
        )
        actual_hex_prefix = bounded.stderr.split(
            "\tactual_hex_prefix=", 1
        )[1].split("\t", 1)[0]
        self.assertEqual(len(actual_hex_prefix), 512)
        self.assertLess(len(bounded.stderr), 800)

    def test_alpine_containerfile_and_runtime_attest_exact_openrc_boundary(
        self,
    ) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        containerfile = package_lifecycle_lab.build_containerfile(spec)
        self.assertIn("apk info -e 'openrc=0.62.6-r0'", containerfile)
        self.assertIn(package_lifecycle_lab.ALPINE_RC_CONF_PRE_SHA256, containerfile)
        self.assertIn(package_lifecycle_lab.ALPINE_RC_CONF_APPEND_BASE64, containerfile)
        self.assertIn(package_lifecycle_lab.ALPINE_RC_CONF_POST_SHA256, containerfile)
        self.assertIn('rc_sys="podman"', containerfile)
        self.assertIn('rc_cgroup_mode="legacy"', containerfile)
        self.assertNotIn('rc_cgroup_mode="none"', containerfile)
        self.assertNotIn('rc_cgroup_mode="hybrid"', containerfile)
        self.assertNotIn('rc_cgroup_mode="unified"', containerfile)
        self.assertIn(
            package_lifecycle_lab.ALPINE_HOSTNAME_INIT_PRE_SHA256,
            containerfile,
        )
        self.assertIn(
            package_lifecycle_lab.ALPINE_HOSTNAME_INIT_POST_SHA256,
            containerfile,
        )
        self.assertIn("keyword -prefix -lxc -docker\\)$/\\1 -podman", containerfile)
        self.assertIn(
            "rc-update add rsyslog default && "
            "rc-update add syswarden-lab-rsyslog-ready default && "
            "rc-update -u\n",
            containerfile,
        )
        rsyslog_readiness = (
            package_lifecycle_lab.ALPINE_RSYSLOG_READINESS_PROVIDER
        )
        self.assertIn(
            base64.b64encode(rsyslog_readiness.encode()).decode(),
            containerfile,
        )
        self.assertIn(
            "/etc/init.d/syswarden-lab-rsyslog-ready",
            containerfile,
        )
        self.assertNotIn("/tmp/syswarden-openrc-config", containerfile)

        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        for expected in (
            "openrc=0.62.6-r0",
            package_lifecycle_lab.ALPINE_RC_CONF_POST_SHA256,
            package_lifecycle_lab.ALPINE_HOSTNAME_INIT_POST_SHA256,
            'container=podman',
            "syswarden_namespace_openrc_file=",
            'openrc --sys > "${syswarden_namespace_openrc_file}" 2>&1',
            "syswarden_namespace_file_record",
            package_lifecycle_lab.ALPINE_OPENRC_SYS_ATTESTATION_HEX,
            '$(separator + 1) != "cgroup2"',
            "field_number = 7",
            'options[option] == "ro"',
            'options[option] == "rw"',
            'options[option] == "nosuid"',
            'options[option] == "nodev"',
            'options[option] == "noexec"',
            "delegated-cgroup2",
            "find /sys/fs/cgroup -mindepth 1 -maxdepth 1",
            "rc-service syswarden-lab-net status",
            "rc-service cronie status",
            "rc-service rsyslog status",
        ):
            self.assertIn(expected, runtime)
        self.assertNotIn("rc-service rsyslog start", runtime)
        self.assertNotIn("rc-service rsyslog restart", runtime)
        self.assertNotIn("for (index =", runtime)
        predicates = (
            "NS15_OPENRC_PACKAGE",
            "NS16_APK_PROVIDER_SHA",
            "NS17_APK_PROVIDER_STAT",
            "NS18_APK_RC_CONF_STAT",
            "NS19_APK_RC_CONF_SHA",
            "NS20_APK_RC_SYS_LINE",
            "NS21_APK_RC_CGROUP_LINE",
            "NS22_APK_RC_SYS_COUNT",
            "NS23_APK_RC_CGROUP_COUNT",
            "NS24_APK_OPENRC_SYS",
            "NS25_APK_HOSTNAME_STAT",
            "NS26_APK_HOSTNAME_SHA",
            "NS27_APK_HOSTNAME_KEYWORD",
            "NS28_APK_PID1_ENV",
            "NS29_APK_CGROUP_MOUNT",
            "NS30_APK_CGROUP_BOUNDARY",
            "NS31_APK_NET_RUNLEVEL",
            "NS32_APK_CRON_RUNLEVEL",
            "NS33_APK_RSYSLOG_RUNLEVEL",
            "NS34_APK_NET_ACTIVE",
            "NS35_APK_CRON_ACTIVE",
            "NS36_APK_RSYSLOG_ACTIVE",
        )
        for predicate in predicates:
            self.assertEqual(runtime.count(predicate), 1, predicate)
            self.assertRegex(
                runtime,
                rf"syswarden_namespace_expect_(?:equal|integer|status) "
                rf"{re.escape(predicate)}(?: |$)",
            )
        alpine_tail_start = runtime.index('syswarden_apk_info_actual="$(')
        alpine_tail = runtime[alpine_tail_start:]
        self.assertFalse(
            any(line.startswith("[ ") for line in alpine_tail.splitlines())
        )
        self.assertFalse(
            any(line.startswith("awk ") for line in alpine_tail.splitlines())
        )
        self.assertFalse(
            any(
                line.startswith("rc-service ")
                for line in alpine_tail.splitlines()
            )
        )
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=package_lifecycle_lab._exec_security_guard_script(spec) + runtime,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        runtime_lines = runtime.splitlines()
        apk_guard_start = runtime_lines.index('syswarden_apk_info_actual="$(')
        apk_guard_end = next(
            index
            for index in range(apk_guard_start, len(runtime_lines))
            if runtime_lines[index].startswith(
                "syswarden_namespace_expect_equal NS15_OPENRC_PACKAGE"
            )
        )
        apk_guard = "\n".join(
            runtime_lines[apk_guard_start : apk_guard_end + 1]
        )
        self.assertIn("NS15_OPENRC_PACKAGE", apk_guard)
        for output, command_status, accepted in (
            ("openrc\n", 0, True),
            ("openrc", 0, False),
            ("openrc\n\n", 0, False),
            ("", 0, False),
            ("OpenRC\n", 0, False),
            ("openrc\nextra\n", 0, False),
            ("openrc\n", 7, False),
        ):
            with self.subTest(apk_info=output, command_status=command_status):
                probe = (
                    "apk() {\n"
                    "    [ \"$#\" -eq 3 ] && [ \"$1\" = info ] && "
                    "[ \"$2\" = -e ] && "
                    "[ \"$3\" = 'openrc=0.62.6-r0' ] || return 96\n"
                    f"    printf '%s' {shlex.quote(output)}\n"
                    f"    return {command_status}\n"
                    "}\n"
                    + package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                    + apk_guard
                    + "\n"
                )
                result = subprocess.run(
                    ["/bin/sh", "-c", probe],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, accepted)
                self.assertEqual(result.stdout, "")
                if accepted:
                    self.assertEqual(result.stderr, "")
                else:
                    self.assertIn(
                        package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                        + "\tpredicate=NS15_OPENRC_PACKAGE\t",
                        result.stderr,
                    )

        expected_openrc_attestation = b"PODMAN\n"
        self.assertEqual(
            package_lifecycle_lab.ALPINE_OPENRC_SYS_ATTESTATION_HEX,
            expected_openrc_attestation.hex(),
        )
        openrc_file_index = runtime_lines.index(
            'syswarden_namespace_openrc_file="$(mktemp '
            '/tmp/syswarden-openrc-sys.XXXXXX 2>&1)" '
            '|| syswarden_namespace_status=$?'
        )
        guard_start = openrc_file_index - 1
        guard_end = next(
            index
            for index in range(guard_start, len(runtime_lines))
            if runtime_lines[index].startswith(
                "syswarden_namespace_expect_equal NS24_APK_OPENRC_SYS"
            )
        )
        openrc_sys_guard = "\n".join(runtime_lines[guard_start : guard_end + 1])
        for output, command_status, expected_status in (
            (b"PODMAN", 0, 1),
            (b"PODMAN\n", 0, 0),
            (b"PODMAN\n\n", 0, 1),
            (b"podman\n", 0, 1),
            (b"PODMAN\nEXTRA\n", 0, 1),
            (b"", 0, 1),
            (b"PODMAN\n", 7, 1),
            (b"PODMAN\x00\n", 0, 1),
            (b"PODMAN\n\x00", 0, 1),
        ):
            with self.subTest(openrc_sys=output, command_status=command_status):
                output_format = "".join(f"\\{byte:03o}" for byte in output)
                probe = (
                    "openrc() { [ \"$1\" = --sys ] || return 2; "
                    f"printf {shlex.quote(output_format)}; "
                    f"return {command_status}; }}\n"
                    + package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                    + openrc_sys_guard
                    + "\n"
                )
                result = subprocess.run(
                    ["/bin/sh", "-eu", "-c", probe],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, expected_status == 0)
                if expected_status == 0:
                    self.assertEqual(result.stderr, "")
                else:
                    self.assertIn(
                        package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                        + "\tpredicate=NS24_APK_OPENRC_SYS\t",
                        result.stderr,
                    )
                    if command_status:
                        self.assertIn(f"\trc={command_status}\t", result.stderr)

        with mock.patch.object(
            package_lifecycle_lab,
            "ALPINE_RC_CONF_APPEND_BASE64",
            "Cg==",
        ):
            with self.assertRaisesRegex(
                package_lifecycle_lab.LifecycleLabError,
                "configuration payload is not exact",
            ):
                package_lifecycle_lab.build_containerfile(spec)

    def test_alpine_rsyslog_readiness_provider_is_fail_closed_and_portable(
        self,
    ) -> None:
        provider = package_lifecycle_lab.ALPINE_RSYSLOG_READINESS_PROVIDER
        self.assertTrue(provider.startswith("#!/sbin/openrc-run\n"))
        self.assertIn("need syswarden-lab-net", provider)
        self.assertIn("after rsyslog", provider)
        self.assertEqual(provider.count("rc-service rsyslog status"), 2)
        self.assertEqual(provider.count("rc-service rsyslog start"), 1)
        self.assertNotIn("|| true", provider)
        syntax = subprocess.run(
            [shutil.which("dash") or "/bin/sh", "-n"],
            input=provider,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        mocks = r'''syswarden_test_status_calls=0
ebegin() {
    printf 'ebegin:%s\n' "$1" >> "${SYSWARDEN_TEST_CALLS}"
}
eend() {
    printf 'eend:%s\n' "$1" >> "${SYSWARDEN_TEST_CALLS}"
}
rc_service() {
    [ "$#" -eq 2 ] || return 96
    printf 'rc-service:%s:%s\n' "$1" "$2" >> "${SYSWARDEN_TEST_CALLS}"
    case "$2" in
        status)
            syswarden_test_status_calls=$((syswarden_test_status_calls + 1))
            if [ "${syswarden_test_status_calls}" -eq 1 ]; then
                return "${SYSWARDEN_TEST_INITIAL_STATUS}"
            fi
            return "${SYSWARDEN_TEST_FINAL_STATUS}"
            ;;
        start)
            return "${SYSWARDEN_TEST_START_STATUS}"
            ;;
        *) return 96 ;;
    esac
}
'''
        probe = mocks + provider.replace("rc-service", "rc_service") + "\nstart\n"
        shells = [("posix", [shutil.which("dash") or "/bin/sh"])]
        busybox = shutil.which("busybox")
        if busybox is not None:
            shells.append(("busybox-ash", [busybox, "ash"]))
        cases = (
            (
                "already-active",
                "0",
                "7",
                "0",
                0,
                (
                    "ebegin:Attesting isolated lifecycle rsyslog service",
                    "rc-service:rsyslog:status",
                    "rc-service:rsyslog:status",
                    "eend:0",
                ),
            ),
            (
                "start-stopped-service",
                "3",
                "0",
                "0",
                0,
                (
                    "ebegin:Attesting isolated lifecycle rsyslog service",
                    "rc-service:rsyslog:status",
                    "rc-service:rsyslog:start",
                    "rc-service:rsyslog:status",
                    "eend:0",
                ),
            ),
            (
                "start-fails",
                "3",
                "7",
                "0",
                1,
                (
                    "ebegin:Attesting isolated lifecycle rsyslog service",
                    "rc-service:rsyslog:status",
                    "rc-service:rsyslog:start",
                    "eend:1",
                ),
            ),
            (
                "start-does-not-become-active",
                "3",
                "0",
                "3",
                1,
                (
                    "ebegin:Attesting isolated lifecycle rsyslog service",
                    "rc-service:rsyslog:status",
                    "rc-service:rsyslog:start",
                    "rc-service:rsyslog:status",
                    "eend:1",
                ),
            ),
            (
                "active-service-stops-before-final-check",
                "0",
                "0",
                "3",
                1,
                (
                    "ebegin:Attesting isolated lifecycle rsyslog service",
                    "rc-service:rsyslog:status",
                    "rc-service:rsyslog:status",
                    "eend:1",
                ),
            ),
        )
        for shell_name, shell in shells:
            for (
                label,
                initial_status,
                start_status,
                final_status,
                expected_returncode,
                expected_calls,
            ) in cases:
                with self.subTest(shell=shell_name, case=label):
                    with tempfile.TemporaryDirectory() as temporary:
                        calls = Path(temporary) / "calls"
                        result = subprocess.run(
                            [*shell, "-eu", "-c", probe],
                            env={
                                **os.environ,
                                "SYSWARDEN_TEST_CALLS": str(calls),
                                "SYSWARDEN_TEST_INITIAL_STATUS": initial_status,
                                "SYSWARDEN_TEST_START_STATUS": start_status,
                                "SYSWARDEN_TEST_FINAL_STATUS": final_status,
                            },
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                        self.assertEqual(
                            result.returncode,
                            expected_returncode,
                            result.stderr,
                        )
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(result.stderr, "")
                        self.assertEqual(
                            calls.read_text(encoding="utf-8").splitlines(),
                            list(expected_calls),
                        )

        with tempfile.TemporaryDirectory() as temporary:
            calls = Path(temporary) / "calls"
            calls.write_text("", encoding="utf-8")
            stopped = subprocess.run(
                [
                    shutil.which("dash") or "/bin/sh",
                    "-eu",
                    "-c",
                    mocks
                    + provider.replace("rc-service", "rc_service")
                    + "\nstop\n",
                ],
                env={
                    **os.environ,
                    "SYSWARDEN_TEST_CALLS": str(calls),
                    "SYSWARDEN_TEST_INITIAL_STATUS": "96",
                    "SYSWARDEN_TEST_START_STATUS": "96",
                    "SYSWARDEN_TEST_FINAL_STATUS": "96",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            self.assertEqual(stopped.stdout, "")
            self.assertEqual(stopped.stderr, "")
            self.assertEqual(calls.read_text(encoding="utf-8"), "")

    def test_alpine_file_and_configuration_guards_are_behavioral(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        runtime_lines = package_lifecycle_lab.runtime_namespace_script(
            spec
        ).splitlines()
        provider_sha256 = hashlib.sha256(
            package_lifecycle_lab.ALPINE_LAB_NETWORK_PROVIDER.encode()
        ).hexdigest()
        cases = (
            (
                "NS16_APK_PROVIDER_SHA",
                "sha256sum",
                f"{provider_sha256}  /etc/init.d/syswarden-lab-net",
                "0" * 64 + "  /etc/init.d/syswarden-lab-net",
            ),
            (
                "NS17_APK_PROVIDER_STAT",
                "stat",
                "regular file:0:0:755",
                "symbolic link:0:0:755",
            ),
            (
                "NS18_APK_RC_CONF_STAT",
                "stat",
                "regular file:0:0:644",
                "symbolic link:0:0:644",
            ),
            (
                "NS19_APK_RC_CONF_SHA",
                "sha256sum",
                package_lifecycle_lab.ALPINE_RC_CONF_POST_SHA256
                + "  /etc/rc.conf",
                "0" * 64 + "  /etc/rc.conf",
            ),
            ("NS20_APK_RC_SYS_LINE", "grep", "1", "0"),
            ("NS21_APK_RC_CGROUP_LINE", "grep", "1", "0"),
            ("NS22_APK_RC_SYS_COUNT", "awk", "1", "2"),
            ("NS23_APK_RC_CGROUP_COUNT", "awk", "1", "2"),
            (
                "NS25_APK_HOSTNAME_STAT",
                "stat",
                "regular file:0:0:755",
                "symbolic link:0:0:755",
            ),
            (
                "NS26_APK_HOSTNAME_SHA",
                "sha256sum",
                package_lifecycle_lab.ALPINE_HOSTNAME_INIT_POST_SHA256
                + "  /etc/init.d/hostname",
                "0" * 64 + "  /etc/init.d/hostname",
            ),
            ("NS27_APK_HOSTNAME_KEYWORD", "grep", "1", "0"),
        )

        def guard_for(predicate: str) -> str:
            end = next(
                index
                for index, line in enumerate(runtime_lines)
                if predicate in line
                and line.startswith("syswarden_namespace_expect_")
            )
            start = max(
                index
                for index in range(end)
                if runtime_lines[index] == "syswarden_namespace_status=0"
            )
            return "\n".join(runtime_lines[start : end + 1]) + "\n"

        for predicate, command, valid, mismatch in cases:
            command_mock = (
                f"{command}() {{\n"
                "    printf '%s\\n' \"${SYSWARDEN_MOCK_OUTPUT}\"\n"
                "    return \"${SYSWARDEN_MOCK_STATUS}\"\n"
                "}\n"
            )
            probe = (
                package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                + command_mock
                + guard_for(predicate)
            )
            for label, output, status, accepted in (
                ("valid", valid, "0", True),
                ("mismatch", mismatch, "0", False),
                ("producer failure", valid, "7", False),
            ):
                with self.subTest(predicate=predicate, case=label):
                    result = subprocess.run(
                        ["/bin/sh", "-eu", "-c", probe],
                        env={
                            **os.environ,
                            "SYSWARDEN_MOCK_OUTPUT": output,
                            "SYSWARDEN_MOCK_STATUS": status,
                        },
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual(result.stdout, "")
                    if accepted:
                        self.assertEqual(result.stderr, "")
                    else:
                        self.assertEqual(
                            result.stderr.count(
                                package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                            ),
                            1,
                        )
                        self.assertIn(
                            package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                            + f"\tpredicate={predicate}\trc={status}\t",
                            result.stderr,
                        )

    def test_alpine_pid1_environment_guard_preserves_each_status(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        runtime_lines = package_lifecycle_lab.runtime_namespace_script(
            spec
        ).splitlines()
        end = next(
            index
            for index, line in enumerate(runtime_lines)
            if line.startswith(
                "syswarden_namespace_expect_integer NS28_APK_PID1_ENV"
            )
        )
        start = max(
            index
            for index in range(end)
            if runtime_lines[index] == "syswarden_namespace_status=0"
        )
        guard = "\n".join(runtime_lines[start : end + 1]) + "\n"
        mocks = r'''tr() {
    if [ "$1" = '\000' ]; then
        printf 'container=podman\n'
        return "${SYSWARDEN_TR_STATUS}"
    fi
    command tr "$@"
}
grep() {
    printf '%s\n' "${SYSWARDEN_GREP_OUTPUT}"
    return "${SYSWARDEN_GREP_STATUS}"
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            environ = Path(temporary) / "environ"
            environ.write_bytes(b"container=podman\0")
            probe = (
                package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                + mocks
                + guard.replace("/proc/1/environ", str(environ))
            )
            for label, tr_status, grep_status, grep_output, accepted in (
                ("valid", "0", "0", "1", True),
                ("count mismatch", "0", "0", "0", False),
                ("parser failure", "0", "7", "1", False),
                ("producer failure with valid output", "7", "0", "1", False),
            ):
                with self.subTest(case=label):
                    result = subprocess.run(
                        ["/bin/sh", "-eu", "-c", probe],
                        env={
                            **os.environ,
                            "SYSWARDEN_TR_STATUS": tr_status,
                            "SYSWARDEN_GREP_STATUS": grep_status,
                            "SYSWARDEN_GREP_OUTPUT": grep_output,
                        },
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual(result.stdout, "")
                    if accepted:
                        self.assertEqual(result.stderr, "")
                    else:
                        expected_status = tr_status if tr_status != "0" else grep_status
                        self.assertEqual(
                            result.stderr.count(
                                package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                            ),
                            1,
                        )
                        self.assertIn(
                            package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                            + "\tpredicate=NS28_APK_PID1_ENV"
                            + f"\trc={expected_status}\t",
                            result.stderr,
                        )

    def test_complete_alpine_tail_runs_under_pinned_ash_when_available(
        self,
    ) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "alpine" and item.architecture == "amd64"
        )
        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        ns15 = runtime.index(
            "syswarden_namespace_expect_equal NS15_OPENRC_PACKAGE"
        )
        tail = runtime[runtime.index("\n", ns15) + 1 :]
        provider_sha256 = hashlib.sha256(
            package_lifecycle_lab.ALPINE_LAB_NETWORK_PROVIDER.encode()
        ).hexdigest()
        mocks = f'''sha256sum() {{
    case "$1" in
        /etc/init.d/syswarden-lab-net)
            printf '%s  %s\n' '{provider_sha256}' "$1" ;;
        /etc/rc.conf)
            printf '%s  %s\n' '{package_lifecycle_lab.ALPINE_RC_CONF_POST_SHA256}' "$1" ;;
        /etc/init.d/hostname)
            printf '%s  %s\n' '{package_lifecycle_lab.ALPINE_HOSTNAME_INIT_POST_SHA256}' "$1" ;;
        *) return 96 ;;
    esac
}}
stat() {{
    case "$3" in
        /etc/init.d/syswarden-lab-net|/etc/init.d/hostname)
            printf 'regular file:0:0:755\n' ;;
        /etc/rc.conf) printf 'regular file:0:0:644\n' ;;
        *) return 96 ;;
    esac
}}
grep() {{ printf '1\n'; }}
awk() {{
    case " $* " in
        *"/proc/self/mountinfo"*) printf 'rw\n' ;;
        *) printf '1\n' ;;
    esac
}}
tr() {{
    if [ "$1" = '\\000' ]; then
        printf 'container=podman\n'
    else
        command tr "$@"
    fi
}}
openrc() {{
    [ "$#" -eq 1 ] && [ "$1" = --sys ] || return 96
    printf 'PODMAN\n'
}}
rc_update() {{
    printf 'syswarden-lab-net | default\ncronie | default\nrsyslog | default\n'
}}
rc_service() {{ return 0; }}
'''
        base_probe = package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS + mocks
        with tempfile.TemporaryDirectory() as temporary:
            pid1_environment = Path(temporary) / "pid1-environ"
            pid1_environment.write_bytes(b"container=podman\0")
            cgroup_root = Path(temporary) / "cgroup"
            cgroup_root.mkdir()
            (cgroup_root / "memory.max").write_text(
                "1073741824\n", encoding="utf-8"
            )
            (cgroup_root / "pids.max").write_text("512\n", encoding="utf-8")
            self_cgroup = Path(temporary) / "self.cgroup"
            self_cgroup.write_text("0::/\n", encoding="utf-8")
            host_tail = (
                tail.replace("/proc/1/environ", str(pid1_environment))
                .replace("/proc/self/cgroup", str(self_cgroup))
                .replace("/sys/fs/cgroup", str(cgroup_root))
                .replace("rc-update show -v", "rc_update show -v")
                .replace("rc-service ", "rc_service ")
            )
            host = subprocess.run(
                [
                    shutil.which("dash") or "/bin/sh",
                    "-eu",
                    "-c",
                    base_probe + host_tail,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(host.returncode, 0, host.stderr)
            self.assertEqual(host.stdout, "")
            self.assertEqual(host.stderr, "")

        podman = shutil.which("podman")
        if podman is None or subprocess.run(
            [podman, "image", "exists", spec.image],
            capture_output=True,
            check=False,
        ).returncode != 0:
            self.skipTest("pinned local Alpine image required for ash execution")
        alpine_environment = "/tmp/syswarden-test-pid1-environ"
        alpine_cgroup_root = "/tmp/syswarden-test-cgroup"
        alpine_self_cgroup = "/tmp/syswarden-test-self.cgroup"
        alpine_tail = (
            tail.replace("/proc/1/environ", alpine_environment)
            .replace("/proc/self/cgroup", alpine_self_cgroup)
            .replace("/sys/fs/cgroup", alpine_cgroup_root)
            .replace("rc-update show -v", "rc_update show -v")
            .replace("rc-service ", "rc_service ")
        )
        alpine_probe = (
            f": > {alpine_environment}\n"
            + f"mkdir {alpine_cgroup_root}\n"
            + f"printf '1073741824\\n' > {alpine_cgroup_root}/memory.max\n"
            + f"printf '512\\n' > {alpine_cgroup_root}/pids.max\n"
            + f"printf '0::/\\n' > {alpine_self_cgroup}\n"
            + base_probe
            + alpine_tail
        )
        alpine = subprocess.run(
            [
                podman,
                "run",
                "--rm",
                "--interactive",
                "--pull=never",
                "--platform=linux/amd64",
                "--network=none",
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--security-opt=label=disable",
                "--pids-limit=32",
                "--memory=64m",
                "--tmpfs=/tmp:rw,nodev,nosuid,noexec,size=1m,mode=1777",
                "--user=65534:65534",
                spec.image,
                "/bin/ash",
                "-eu",
                "-s",
            ],
            input=alpine_probe,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(alpine.returncode, 0, alpine.stderr)
        self.assertEqual(alpine.stdout, "")
        self.assertEqual(alpine.stderr, "")

    def test_alpine_cgroup_mountinfo_awk_is_busybox_safe_and_fail_closed(
        self,
    ) -> None:
        program = package_lifecycle_lab.ALPINE_CGROUP_MOUNTINFO_AWK
        self.assertIn("for (field_number = 7;", program)
        self.assertNotRegex(program, r"\bindex\b")
        busybox = shutil.which("busybox")
        if busybox is not None:
            command = [busybox, "awk", program]
        else:
            podman = shutil.which("podman")
            alpine = next(
                spec
                for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
                if spec.distribution == "alpine" and spec.architecture == "amd64"
            )
            if podman is None or subprocess.run(
                [podman, "image", "exists", alpine.image],
                capture_output=True,
                check=False,
            ).returncode != 0:
                self.skipTest("BusyBox binary or pinned local Alpine image required")
            command = [
                podman,
                "run",
                "--rm",
                "--interactive",
                "--pull=never",
                "--platform=linux/amd64",
                "--network=none",
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--security-opt=label=disable",
                "--pids-limit=32",
                "--user=65534:65534",
                alpine.image,
                "awk",
                program,
            ]
        valid = (
            "29 23 0:26 / /sys/fs/cgroup "
            "ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
        )
        valid_rw = valid.replace("ro,nosuid", "rw,nosuid")
        cases = (
            ("read-only", valid, 0, "ro\n"),
            ("delegated-read-write", valid_rw, 0, "rw\n"),
            ("missing", "", 1, ""),
            (
                "contradictory-access",
                valid.replace("ro,nosuid", "ro,rw,nosuid"),
                1,
                "",
            ),
            ("missing-access", valid.replace("ro,", ""), 1, ""),
            ("duplicate-access", valid.replace("ro,", "ro,ro,"), 1, ""),
            ("missing-nosuid", valid.replace("nosuid,", ""), 1, ""),
            ("missing-nodev", valid.replace("nodev,", ""), 1, ""),
            ("missing-noexec", valid.replace("noexec,", ""), 1, ""),
            ("wrong-root", valid.replace("0:26 / /sys", "0:26 /host /sys"), 1, ""),
            ("cgroup-v1", valid.replace("- cgroup2", "- cgroup"), 1, ""),
            ("duplicate", valid + valid, 1, ""),
            (
                "wrong-mountpoint",
                valid.replace("/sys/fs/cgroup", "/cgroup"),
                1,
                "",
            ),
            (
                "missing-separator",
                valid.replace(" - cgroup2", " cgroup2"),
                1,
                "",
            ),
        )
        for label, mountinfo, expected_status, expected_output in cases:
            with self.subTest(mountinfo=label):
                result = subprocess.run(
                    command,
                    input=mountinfo,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertEqual(result.stdout, expected_output)
                self.assertEqual(result.stderr, "")

        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        runtime_lines = runtime.splitlines()
        assignment = next(
            index
            for index, line in enumerate(runtime_lines)
            if line.startswith('syswarden_namespace_actual="$(awk ')
            and "/proc/self/mountinfo" in line
        )
        guard_end = next(
            index
            for index in range(assignment, len(runtime_lines))
            if runtime_lines[index].startswith(
                "syswarden_namespace_expect_equal NS29_APK_CGROUP_MOUNT"
            )
        )
        cgroup_guard = "\n".join(runtime_lines[assignment - 1 : guard_end + 1])
        with tempfile.TemporaryDirectory() as temporary:
            mountinfo_path = Path(temporary) / "mountinfo"
            cgroup_guard = cgroup_guard.replace(
                "/proc/self/mountinfo", str(mountinfo_path)
            )
            for label, mountinfo, expected_status, _ in cases:
                with self.subTest(runtime_mountinfo=label):
                    mountinfo_path.write_text(mountinfo, encoding="utf-8")
                    guarded = subprocess.run(
                        [
                            "/bin/sh",
                            "-eu",
                            "-c",
                            package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                            + cgroup_guard,
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(
                        guarded.returncode,
                        expected_status,
                        guarded.stderr,
                    )
                    self.assertEqual(guarded.stdout, "")
                    if expected_status == 0:
                        self.assertEqual(guarded.stderr, "")
                    else:
                        self.assertIn(
                            package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                            + "\tpredicate=NS29_APK_CGROUP_MOUNT\t",
                            guarded.stderr,
                        )

    def test_alpine_cgroup_boundary_accepts_only_exact_ro_or_bounded_rw(
        self,
    ) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        start = runtime.index("syswarden_namespace_cgroup_boundary() {")
        predicate = "syswarden_namespace_expect_equal NS30_APK_CGROUP_BOUNDARY"
        end = runtime.index("\n", runtime.index(predicate, start)) + 1
        guard = runtime[start:end]

        def run_guard(
            access: str,
            *,
            cgroup: str = "0::/",
            memory: str = "1073741824",
            pids: str = "512",
            child: str | None = None,
            broken_symlink: bool = False,
            missing: str | None = None,
            unreadable: bool = False,
            find_failure: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as temporary:
                temporary_root = Path(temporary)
                cgroup_root = temporary_root / "cgroup"
                cgroup_root.mkdir()
                proc_self_cgroup = temporary_root / "self.cgroup"
                proc_self_cgroup.write_text(cgroup + "\n", encoding="utf-8")
                if access == "rw":
                    (cgroup_root / "memory.max").write_text(
                        memory + "\n", encoding="utf-8"
                    )
                    (cgroup_root / "pids.max").write_text(
                        pids + "\n", encoding="utf-8"
                    )
                if missing is not None:
                    target = (
                        proc_self_cgroup
                        if missing == "cgroup"
                        else cgroup_root / missing
                    )
                    target.unlink()
                if child is not None:
                    child_path = cgroup_root / child
                    if broken_symlink:
                        child_path.symlink_to("missing")
                    else:
                        child_path.mkdir()
                prefix = "find() { return 7; }\n" if find_failure else ""
                probe = (
                    package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                    + prefix
                    + f"syswarden_namespace_cgroup_access={shlex.quote(access)}\n"
                    + guard.replace("/proc/self/cgroup", str(proc_self_cgroup))
                    .replace("/sys/fs/cgroup", str(cgroup_root))
                )
                if unreadable:
                    cgroup_root.chmod(0)
                try:
                    return subprocess.run(
                        ["/bin/sh", "-eu", "-c", probe],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                finally:
                    if unreadable:
                        cgroup_root.chmod(0o700)

        for access in ("ro", "rw"):
            with self.subTest(accepted_access=access):
                accepted = run_guard(access)
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertEqual(accepted.stdout, "")
                self.assertEqual(accepted.stderr, "")

        rejected_cases = (
            ("wrong cgroup root", {"cgroup": "0::/delegated"}),
            ("wrong memory maximum", {"memory": "max"}),
            ("wrong PID maximum", {"pids": "max"}),
            ("missing cgroup", {"missing": "cgroup"}),
            ("missing memory maximum", {"missing": "memory.max"}),
            ("missing PID maximum", {"missing": "pids.max"}),
            ("arbitrary child", {"child": "operator.scope"}),
            (
                "broken symlink",
                {"child": "operator.broken", "broken_symlink": True},
            ),
            ("find producer failure", {"find_failure": True}),
        )
        for label, options in rejected_cases:
            with self.subTest(rejected=label):
                rejected = run_guard("rw", **options)
                self.assertEqual(rejected.returncode, 1)
                self.assertEqual(rejected.stdout, "")
                self.assertEqual(
                    rejected.stderr.count(
                        package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                    ),
                    1,
                )
                self.assertIn(
                    package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                    + "\tpredicate=NS30_APK_CGROUP_BOUNDARY\t",
                    rejected.stderr,
                )
        if os.geteuid() != 0:
            unreadable = run_guard("rw", unreadable=True)
            self.assertEqual(unreadable.returncode, 1)
            self.assertIn(
                package_lifecycle_lab.NAMESPACE_FAILURE_MARKER
                + "\tpredicate=NS30_APK_CGROUP_BOUNDARY\t",
                unreadable.stderr,
            )

    def test_alpine_runlevel_and_service_guards_are_independent_and_diagnostic(
        self,
    ) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        runtime = package_lifecycle_lab.runtime_namespace_script(spec)
        runtime_lines = runtime.splitlines()
        start = runtime_lines.index("syswarden_namespace_runlevel_count() {")
        end = next(
            index
            for index in range(start, len(runtime_lines))
            if runtime_lines[index].startswith(
                "syswarden_namespace_expect_status NS36_APK_RSYSLOG_ACTIVE"
            )
        )
        guarded_tail = (
            "\n".join(runtime_lines[start : end + 1])
            .replace("rc-update show -v", "rc_update show -v")
            .replace("rc-service ", "rc_service ")
            + "\n"
        )

        with tempfile.TemporaryDirectory() as temporary:
            calls = Path(temporary) / "rc-update.calls"
            mocks = r'''rc_update() {
    [ "$#" -eq 2 ] && [ "$1" = show ] && [ "$2" = -v ] || return 96
    printf 'call\n' >> "${SYSWARDEN_RC_UPDATE_CALLS}"
    if [ "${SYSWARDEN_FAIL_RC_UPDATE:-}" = 1 ]; then
        printf 'rc-update denied\n'
        return 7
    fi
    for service in syswarden-lab-net cronie rsyslog; do
        if [ "${service}" != "${SYSWARDEN_OMIT_SERVICE:-}" ]; then
            printf '%s | default\n' "${service}"
        fi
    done
}
rc_service() {
    [ "$#" -eq 2 ] && [ "$2" = status ] || return 96
    if [ "$1" = "${SYSWARDEN_FAIL_SERVICE:-}" ]; then
        printf '%s is stopped\n' "$1"
        return 7
    fi
    printf '%s is started\n' "$1"
}
'''

            def run_guard(**overrides: str) -> subprocess.CompletedProcess[str]:
                calls.write_text("", encoding="utf-8")
                return subprocess.run(
                    [
                        shutil.which("dash") or "/bin/sh",
                        "-eu",
                        "-c",
                        package_lifecycle_lab.NAMESPACE_ATTESTATION_HELPERS
                        + mocks
                        + guarded_tail,
                    ],
                    env={
                        **os.environ,
                        "SYSWARDEN_RC_UPDATE_CALLS": str(calls),
                        **overrides,
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )

            passed = run_guard()
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(passed.stdout, "")
            self.assertEqual(passed.stderr, "")
            self.assertEqual(calls.read_text(encoding="utf-8"), "call\n" * 3)

            for service, predicate, call_count in (
                ("syswarden-lab-net", "NS31_APK_NET_RUNLEVEL", 1),
                ("cronie", "NS32_APK_CRON_RUNLEVEL", 2),
                ("rsyslog", "NS33_APK_RSYSLOG_RUNLEVEL", 3),
            ):
                with self.subTest(missing_runlevel=service):
                    missing = run_guard(SYSWARDEN_OMIT_SERVICE=service)
                    self.assertEqual(missing.returncode, 1)
                    self.assertEqual(missing.stdout, "")
                    self.assertEqual(
                        calls.read_text(encoding="utf-8"),
                        "call\n" * call_count,
                    )
                    self.assertEqual(
                        missing.stderr,
                        namespace_failure_record(predicate, 0, "0", "1"),
                    )

            failed_update = run_guard(SYSWARDEN_FAIL_RC_UPDATE="1")
            self.assertEqual(failed_update.returncode, 1)
            self.assertEqual(failed_update.stdout, "")
            self.assertEqual(calls.read_text(encoding="utf-8"), "call\n")
            self.assertEqual(
                failed_update.stderr,
                namespace_failure_record(
                    "NS31_APK_NET_RUNLEVEL", 7, "rc-update denied", "1"
                ),
            )

            for service, predicate in (
                ("syswarden-lab-net", "NS34_APK_NET_ACTIVE"),
                ("cronie", "NS35_APK_CRON_ACTIVE"),
                ("rsyslog", "NS36_APK_RSYSLOG_ACTIVE"),
            ):
                with self.subTest(failed_service=service):
                    failed = run_guard(SYSWARDEN_FAIL_SERVICE=service)
                    self.assertEqual(failed.returncode, 1)
                    self.assertEqual(failed.stdout, "")
                    self.assertEqual(
                        calls.read_text(encoding="utf-8"), "call\n" * 3
                    )
                    self.assertEqual(
                        failed.stderr,
                        namespace_failure_record(
                            predicate, 7, f"{service} is stopped", ""
                        ),
                    )

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
            self.root / "helper.sh",
            results,
            package_lifecycle_lab.DEFAULT_PLATFORMS[0],
            "upgrade-rollback",
            pair,
        )
        self.assertEqual(args[1], "create")
        self.assertNotIn("--rm", args)
        self.assertIn("--network=none", args)
        self.assertIn("--cap-add=NET_ADMIN", args)
        self.assertIn("--cap-add=SYS_ADMIN", args)
        self.assertIn("--cap-add=SYS_PTRACE", args)
        self.assertNotIn("--uidmap", args)
        self.assertNotIn("--gidmap", args)
        self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertIn("--memory=1g", args)
        self.assertIn("--pids-limit=512", args)
        self.assertEqual(
            [value for value in args if value.startswith("--tmpfs=")],
            [
                "--tmpfs=/run:rw,nodev,nosuid,exec,size=64m,mode=755,notmpcopyup",
                "--tmpfs=/tmp:rw,nodev,nosuid,exec,size=256m,mode=1777",
            ],
        )
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
        self.assertIn("EXPECTED_DISTRIBUTION=debian", args)
        self.assertIn("EXPECTED_CANDIDATE_VERSION=4.02.8", args)
        self.assertIn("EXPECTED_PREVIOUS_VERSION=4.02.7", args)

    def test_systemd_exec_boundary_uses_package_owned_setpriv_and_same_shell_guard(
        self,
    ) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        arguments = package_lifecycle_lab.lifecycle_exec_arguments(
            "podman",
            "safe-name",
            spec,
            "exec /bin/sh /lab/package-lifecycle.sh",
        )
        self.assertEqual(arguments[:3], ("podman", "exec", "safe-name"))
        self.assertEqual(
            arguments[3:-1], package_lifecycle_lab.SYSTEMD_EXEC_LAUNCHER
        )
        self.assertNotIn("--cap-drop=SYS_ADMIN", arguments)
        self.assertNotIn("--bounding-set=-sys_ptrace", arguments)
        script = arguments[-1]
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertIn(key, script)
        self.assertIn('syswarden_read_status_value "$$"', script)
        self.assertIn("NoNewPrivs", script)
        self.assertIn("0x00200000", script)
        self.assertIn("0x00080000", script)
        self.assertIn("syswarden_expect_sys_ptrace=1", script)
        self.assertIn(package_lifecycle_lab.EXEC_SECURITY_MARKER, script)
        self.assertTrue(
            script.endswith("exec /bin/sh /lab/package-lifecycle.sh")
        )
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_apk_exec_boundary_is_direct_but_uses_the_same_fail_closed_guard(
        self,
    ) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk"
        )
        arguments = package_lifecycle_lab.lifecycle_exec_arguments(
            "podman", "safe-name", spec, "true"
        )
        self.assertEqual(
            arguments[:5],
            ("podman", "exec", "safe-name", "/bin/sh", "-ceu"),
        )
        self.assertNotIn("/usr/bin/setpriv", arguments)
        self.assertNotIn("--cap-add=SYS_PTRACE", arguments)
        self.assertIn(package_lifecycle_lab.EXEC_SECURITY_MARKER, arguments[-1])
        self.assertIn("syswarden_expect_sys_ptrace=0", arguments[-1])
        self.assertTrue(arguments[-1].endswith("true"))

    def test_exec_security_marker_is_first_unique_and_rejects_every_unsafe_field(
        self,
    ) -> None:
        marker = FakePodmanRunner._exec_security_marker(
            package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        )
        evidence, remainder = package_lifecycle_lab.parse_exec_security_output(
            marker + "payload\n",
            "test boundary",
            package_lifecycle_lab.DEFAULT_PLATFORMS[0],
        )
        self.assertTrue(evidence.no_new_privileges)
        self.assertEqual(remainder, "payload\n")
        marker_fields = marker.rstrip("\n").split("\t")
        adversarial = {
            "absent": "",
            "not_first": "payload\n" + marker,
            "missing_newline": marker.rstrip("\n"),
            "duplicate": marker + marker,
            "extra_field": marker.rstrip("\n") + "\textra\n",
            "noncanonical_mask": "\t".join(
                [marker_fields[0], "0", *marker_fields[2:]]
            )
            + "\n",
            "nnp_false": "\t".join([*marker_fields[:-1], "0"]) + "\n",
        }
        for index, name in enumerate(
            ("inheritable", "permitted", "effective", "bounding", "ambient"),
            start=1,
        ):
            fields = list(marker_fields)
            fields[index] = set_capability_bit(
                fields[index],
                package_lifecycle_lab.SYS_ADMIN_CAPABILITY_BIT,
                present=True,
            )
            adversarial[f"sys_admin_{name}"] = "\t".join(fields) + "\n"
            fields = list(marker_fields)
            fields[index] = set_capability_bit(
                fields[index],
                package_lifecycle_lab.SYS_PTRACE_CAPABILITY_BIT,
                present=name not in {"permitted", "effective", "bounding"},
            )
            adversarial[f"sys_ptrace_{name}"] = "\t".join(fields) + "\n"
        for name, output in adversarial.items():
            with self.subTest(name=name):
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.parse_exec_security_output(
                        output,
                        "test boundary",
                        package_lifecycle_lab.DEFAULT_PLATFORMS[0],
                    )

    def test_rootless_id_map_parser_rejects_identity_overlap_and_wrong_shape(
        self,
    ) -> None:
        expected = package_lifecycle_lab._parse_id_map(
            "0:1000:1,1:524288:65536", "uid_map"
        )
        self.assertEqual(len(expected), 2)
        adversarial = {
            "host_root": "0:0:1,1:524288:65536",
            "outside_overlap": "0:1001:1,1:1000:65536",
            "missing_subordinate": "0:1000:1",
            "extra_range": "0:1000:1,1:524288:65536,65537:700000:1",
            "wrong_inside": "0:1000:1,2:524288:65536",
            "wrong_length": "0:1000:1,1:524288:65535",
            "noncanonical": "00:1000:1,1:524288:65536",
        }
        for name, value in adversarial.items():
            with self.subTest(name=name):
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab._parse_id_map(value, "uid_map")

    def test_snapshot_binds_rootless_map_to_live_host_ids_and_setpriv_packages(
        self,
    ) -> None:
        deb = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        rpm = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "rpm"
        )
        deb_source = package_lifecycle_lab.runtime_snapshot_script(deb, "active")
        rpm_source = package_lifecycle_lab.runtime_snapshot_script(rpm, "active")
        self.assertIn(f'"0:{os.geteuid()}:1"', deb_source)
        self.assertIn(f'"0:{os.getegid()}:1"', deb_source)
        self.assertIn("dpkg-query -S", deb_source)
        self.assertIn('"util-linux: ${setpriv_path}"', deb_source)
        self.assertIn("rpm -qf --qf", rpm_source)
        self.assertIn("= util-linux", rpm_source)
        self.assertIn("util-linux", package_lifecycle_lab.DEB_BOOTSTRAP)
        self.assertIn("util-linux", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertNotIn("util-linux-core", package_lifecycle_lab.RPM_BOOTSTRAP)

    def test_cron_executable_path_is_exact_per_distribution(self) -> None:
        expected = {
            "debian": "/usr/sbin/cron",
            "ubuntu": "/usr/sbin/cron",
            "fedora": "/usr/bin/crond",
            "almalinux": "/usr/sbin/crond",
            "alpine": "/usr/sbin/crond",
        }
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            with self.subTest(
                distribution=spec.distribution,
                architecture=spec.architecture,
            ):
                executable = package_lifecycle_lab.expected_cron_executable(spec)
                self.assertEqual(executable, expected[spec.distribution])
                source = package_lifecycle_lab.runtime_snapshot_script(spec, "active")
                self.assertIn(
                    f'cron_executable_path}}" != "{executable}"', source
                )
                for forbidden in set(expected.values()) - {executable}:
                    self.assertNotIn(
                        f'cron_executable_path}}" != "{forbidden}"', source
                    )

    def test_fedora_snapshot_accepts_only_exact_vendor_cron_dropin_provenance(
        self,
    ) -> None:
        fedora = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "fedora" and item.architecture == "amd64"
        )
        alma = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "almalinux" and item.architecture == "amd64"
        )
        fedora_source = package_lifecycle_lab.runtime_snapshot_script(
            fedora, "active"
        )
        alma_source = package_lifecycle_lab.runtime_snapshot_script(alma, "active")
        self.assertIn('cron_executable_path}" != "/usr/bin/crond"', fedora_source)
        self.assertIn('cron_executable_path}" != "/usr/sbin/crond"', alma_source)
        self.assertNotIn('cron_executable_path}" != "/usr/sbin/crond"', fedora_source)
        self.assertNotIn('cron_executable_path}" != "/usr/bin/crond"', alma_source)
        self.assertIn(
            'syswarden_snapshot_fail RS07_CRON_EXECUTABLE_PATH 82',
            fedora_source,
        )
        self.assertIn(
            '"${cron_executable_path}" "/usr/bin/crond"', fedora_source
        )
        self.assertIn(package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH, fedora_source)
        self.assertNotIn(package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH, alma_source)
        for required in (
            "%{NAME}\t%{EVR}\t%{ARCH}\t%{FILEDIGESTALGO}",
            "[%{FILENAMES}\t%{FILEDIGESTS}\n]",
            "RS01_CRON_DROPIN_PATHS",
            "RS02_CRON_DROPIN_FILE",
            "RS03_CRON_DROPIN_SHA256",
            "RS04_CRON_DROPIN_PACKAGE",
            "RS05_CRON_DROPIN_RPM_DIGEST",
            "RS06_CRON_DROPIN_DRIFT",
            "RS07_CRON_EXECUTABLE_PATH",
            'first="$(capture_snapshot)"',
            'second="$(capture_snapshot)"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, fedora_source)

        helper_start = fedora_source.index("syswarden_snapshot_hex_prefix() {")
        helper_end = fedora_source.index("\nattest_no_syswarden_core_runtime() {")
        helper = fedora_source[helper_start:helper_end]
        rpm_probe_start = fedora_source.index(
            "        cron_dropin_package_status=0"
        )
        rpm_probe_end = fedora_source.index(
            '        cron_dropin_after="$(', rpm_probe_start
        )
        rpm_probe = fedora_source[rpm_probe_start:rpm_probe_end]
        for package_status, metadata_status, accepted, predicate in (
            (0, 0, True, ""),
            (7, 0, False, "RS04_CRON_DROPIN_PACKAGE"),
            (0, 7, False, "RS05_CRON_DROPIN_RPM_DIGEST"),
        ):
            with self.subTest(
                package_status=package_status,
                metadata_status=metadata_status,
            ):
                digest = "f" * 64
                probe = f"""
syswarden_fake_package_status={package_status}
syswarden_fake_metadata_status={metadata_status}
cron_dropin_path='{package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH}'
cron_dropin_sha256='{digest}'
rpm() {{
    [ "$#" -eq 4 ] && [ "$1" = -qf ] && [ "$2" = --qf ] && \
        [ "$4" = "${{cron_dropin_path}}" ] || return 96
    case "$3" in
        *'%{{NAME}}'*)
            printf 'systemd\t259.8-1.fc44\tx86_64\t8\n'
            return "${{syswarden_fake_package_status}}"
            ;;
        *'%{{FILENAMES}}'*)
            printf '%s\t%s\n' "${{cron_dropin_path}}" "${{cron_dropin_sha256}}"
            return "${{syswarden_fake_metadata_status}}"
            ;;
        *) return 96 ;;
    esac
}}
{helper}
probe() {{
{rpm_probe}
}}
probe
"""
                result = subprocess.run(
                    ["/bin/sh", "-c", probe],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, accepted, result)
                self.assertEqual(result.stdout, "")
                if accepted:
                    self.assertEqual(result.stderr, "")
                else:
                    self.assertEqual(result.returncode, 82)
                    self.assertIn(
                        package_lifecycle_lab.SNAPSHOT_FAILURE_MARKER
                        + f"\tpredicate={predicate}\trc=82",
                        result.stderr,
                    )

        runner = FakePodmanRunner()
        record = runner._runtime_snapshot(fedora, "active", 0)
        security, remainder = package_lifecycle_lab.parse_exec_security_output(
            runner._exec_security_marker(fedora), "test snapshot", fedora
        )
        self.assertEqual(remainder, "")
        parsed = package_lifecycle_lab.parse_runtime_snapshot(
            record, fedora, "active", security
        )
        self.assertEqual(
            parsed.cron_dropin_paths,
            (package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH,),
        )
        fields = record.removesuffix("\n").split("\t")
        self.assertEqual(len(fields), 59)
        self.assertEqual(fields[26], package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH)
        self.assertEqual(fields[22], "/usr/bin/crond")
        self.assertIn("|systemd|", fields[27])
        mutations = {
            "wrong_cron_executable_path": lambda values: values.__setitem__(
                22, "/usr/sbin/crond"
            ),
            "missing_path": lambda values: values.__setitem__(26, "-"),
            "extra_path": lambda values: values.__setitem__(
                26, package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH + " /tmp/operator"
            ),
            "symlink_or_mode": lambda values: values.__setitem__(
                27, values[27].replace(":81a4:0:0|", ":a1ff:0:0|")
            ),
            "uppercase_hash": lambda values: values.__setitem__(
                27, values[27].replace("f" * 64, "F" * 64)
            ),
            "wrong_package": lambda values: values.__setitem__(
                27, values[27].replace("|systemd|", "|cronie|")
            ),
            "wrong_arch": lambda values: values.__setitem__(
                27, values[27].replace("|x86_64|8", "|unsupported|8")
            ),
            "wrong_digest_algorithm": lambda values: values.__setitem__(
                27, values[27].removesuffix("|8") + "|1"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                adversarial = list(fields)
                mutate(adversarial)
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.parse_runtime_snapshot(
                        "\t".join(adversarial) + "\n",
                        fedora,
                        "active",
                        security,
                    )

        oversized = "operator\n" + "x" * 4096
        diagnostic = subprocess.run(
            [
                "/bin/sh",
                "-c",
                helper
                + "\nsyswarden_snapshot_fail RS01_CRON_DROPIN_PATHS 82 \"$1\" exact",
                "probe",
                oversized,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        self.assertEqual(diagnostic.stdout, "")
        self.assertIn(
            package_lifecycle_lab.SNAPSHOT_FAILURE_MARKER
            + "\tpredicate=RS01_CRON_DROPIN_PATHS\trc=82"
            + f"\tactual_bytes={len(oversized.encode())}",
            diagnostic.stderr,
        )
        prefix = diagnostic.stderr.split("\tactual_hex_prefix=", 1)[1].split(
            "\t", 1
        )[0]
        self.assertEqual(len(prefix), 512)

    def test_inspect_rejects_missing_or_extra_systemd_capability(self) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        platforms = (spec,)
        cases = {
            "missing_sys_admin": ["CAP_NET_ADMIN", "CAP_SYS_PTRACE"],
            "missing_sys_ptrace": ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"],
            "duplicate_sys_ptrace": [
                "CAP_NET_ADMIN",
                "CAP_SYS_ADMIN",
                "CAP_SYS_PTRACE",
                "CAP_SYS_PTRACE",
            ],
            "extra_capability": [
                "CAP_NET_ADMIN",
                "CAP_SYS_ADMIN",
                "CAP_SYS_PTRACE",
                "CAP_SYS_MODULE",
            ],
        }
        for name, cap_add in cases.items():
            with self.subTest(name=name):
                report = package_lifecycle_lab.run_lab(
                    self.args(),
                    runner=FakePodmanRunner(inspect_cap_add=cap_add),
                    platforms=platforms,
                    host_architecture="x86_64",
                )
                scenario = report["platforms"][0]["scenarios"][0]
                self.assertEqual(scenario["status"], "fail")
                self.assertIn(
                    "namespace/capability isolation is not exact",
                    scenario["orchestration_error"],
                )

    def test_inspect_requires_exact_memory_and_pid_limits(self) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        for label, overrides in (
            ("missing memory", {"inspect_memory": None}),
            ("unlimited memory", {"inspect_memory": 0}),
            ("text memory", {"inspect_memory": "1073741824"}),
            ("float memory", {"inspect_memory": 1_073_741_824.0}),
            ("missing PID limit", {"inspect_pids_limit": None}),
            ("unlimited PIDs", {"inspect_pids_limit": 0}),
            ("text PID limit", {"inspect_pids_limit": "512"}),
            ("float PID limit", {"inspect_pids_limit": 512.0}),
        ):
            with self.subTest(label=label):
                report = package_lifecycle_lab.run_lab(
                    self.args(),
                    runner=FakePodmanRunner(**overrides),
                    platforms=(spec,),
                    host_architecture="x86_64",
                )
                scenario = report["platforms"][0]["scenarios"][0]
                self.assertEqual(scenario["status"], "fail")
                self.assertIn(
                    "container memory/PID limits are not exact",
                    scenario["orchestration_error"],
                )

    def test_run_tmpfs_copyup_attestation_is_fail_closed(self) -> None:
        expected = tuple(
            sorted({"rw", "nodev", "nosuid", "exec", "mode=755", "size=64m"})
        )
        self.assertEqual(
            package_lifecycle_lab._canonical_tmpfs_options(
                "rw,nodev,nosuid,exec,size=67108864,mode=755,rprivate",
                expected_mode="755",
                expected_size="size=64m",
                allow_tmpcopyup=False,
            ),
            expected,
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "copy-up is not disabled",
        ):
            package_lifecycle_lab._canonical_tmpfs_options(
                "rw,nodev,nosuid,exec,size=64m,mode=755,tmpcopyup",
                expected_mode="755",
                expected_size="size=64m",
                allow_tmpcopyup=False,
            )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "options differ from the exact contract",
        ):
            package_lifecycle_lab._canonical_tmpfs_options(
                "rw,nodev,nosuid,size=64m,mode=755",
                expected_mode="755",
                expected_size="size=64m",
                allow_tmpcopyup=False,
            )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "tmpfs options are not strings",
        ):
            package_lifecycle_lab._canonical_tmpfs_options(
                None,
                expected_mode="755",
                expected_size="size=64m",
                allow_tmpcopyup=False,
            )
        self.assertEqual(
            package_lifecycle_lab._canonical_tmpfs_options(
                "rw,nodev,nosuid,exec,size=64m,mode=755,tmpcopyup",
                expected_mode="755",
                expected_size="size=64m",
                allow_tmpcopyup=True,
            ),
            expected,
        )

    def test_alpine_restart_contract_requires_non_copyup_run_tmpfs(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "alpine" and item.architecture == "amd64"
        )
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(
            self.args(),
            runner=runner,
            platforms=(spec,),
            host_architecture="x86_64",
        )
        platform = report["platforms"][0]
        self.assertEqual(platform["status"], "pass")
        self.assertEqual(
            platform["restart_contract"],
            package_lifecycle_lab.ACTIVE_RESTART_CONTRACT,
        )
        self.assertTrue(
            all(
                scenario["isolation"]["tmpfs"]["/run"]
                == sorted(
                    {"rw", "nodev", "nosuid", "exec", "mode=755", "size=64m"}
                )
                for scenario in platform["scenarios"]
            )
        )
        upgrade = next(
            scenario
            for scenario in platform["scenarios"]
            if scenario["name"] == "upgrade-rollback"
        )
        self.assertEqual(
            [boot["invocation"] for boot in upgrade["boots"]],
            ["initial", "restart-one", "restart-two"],
        )
        lifecycle_creates = [
            call
            for call in runner.calls
            if call[1] == "create"
            and any(value.endswith(":/results:rw") for value in call)
        ]
        self.assertTrue(lifecycle_creates)
        self.assertTrue(
            all(
                "--tmpfs=/run:rw,nodev,nosuid,exec,size=64m,mode=755,notmpcopyup"
                in call
                for call in lifecycle_creates
            )
        )

        rejected = package_lifecycle_lab.run_lab(
            self.args(),
            runner=FakePodmanRunner(
                inspect_run_tmpfs=(
                    "rw,nodev,nosuid,exec,size=64m,mode=755,tmpcopyup"
                )
            ),
            platforms=(spec,),
            host_architecture="x86_64",
        )
        self.assertEqual(rejected["platforms"][0]["status"], "fail")
        self.assertTrue(
            all(
                "copy-up is not disabled" in scenario["orchestration_error"]
                for scenario in rejected["platforms"][0]["scenarios"]
            )
        )

    def test_amd64_probe_and_lifecycle_arguments_are_explicit_and_bounded(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "alpine" and item.architecture == "amd64"
        )
        probe = package_lifecycle_lab.architecture_probe_arguments("podman", spec)
        self.assertEqual(probe[probe.index("--platform") + 1], "linux/amd64")
        self.assertIn("--network=none", probe)
        self.assertIn("--read-only", probe)
        self.assertIn("--cap-drop=all", probe)
        self.assertNotIn("--cap-add", probe)
        self.assertNotIn("--privileged", probe)
        self.assertNotIn("--volume", probe)
        self.assertIn(
            f"EXPECTED_DISTRIBUTION_VERSION={spec.version}", probe
        )
        self.assertIn(f"EXPECTED_DISTRIBUTION={spec.distribution}", probe)
        self.assertEqual(probe[-3:-1], ("/bin/sh", "-ceu"))
        self.assertIn("/etc/os-release", probe[-1])
        self.assertIn("actual_distribution", probe[-1])
        self.assertIn("almalinux)", probe[-1])
        self.assertIn("alpine)", probe[-1])

        self.assertNotIn("--entrypoint", probe)
        pair = package_lifecycle_lab.PackagePair(
            package_lifecycle_lab.PackageArtifact(
                self.candidate / "syswarden_4.02.8_x86_64.apk",
                "4.02.8",
                "a" * 64,
            ),
            package_lifecycle_lab.PackageArtifact(
                self.previous / "syswarden_4.02.7_x86_64.apk",
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
            self.root / "helper.sh",
            self.root / "results",
            spec,
            "upgrade-rollback",
            pair,
        )
        self.assertEqual(
            lifecycle[lifecycle.index("--platform") + 1], "linux/amd64"
        )
        self.assertIn("EXPECTED_PACKAGE_ARCHITECTURE=x86_64", lifecycle)
        self.assertIn("EXPECTED_UNAME_ARCHITECTURE=x86_64", lifecycle)
        self.assertIn(
            f"EXPECTED_DISTRIBUTION_VERSION={spec.version}", lifecycle
        )
        self.assertIn("--cap-add=NET_ADMIN", lifecycle)
        self.assertIn("--cap-add=SYS_BOOT", lifecycle)
        self.assertNotIn("--cap-add=SYS_ADMIN", lifecycle)
        self.assertEqual(
            [value for value in lifecycle if value.startswith("--tmpfs=/run:")],
            [
                "--tmpfs=/run:rw,nodev,nosuid,exec,size=64m,mode=755,notmpcopyup"
            ],
        )

        self.assertNotIn("--entrypoint", lifecycle)

    def test_distribution_version_line_matching_is_closed(self) -> None:
        accepted = (
            ("debian", "13", "13"),
            ("ubuntu", "24.04", "24.04"),
            ("fedora", "44", "44"),
            ("almalinux", "9", "9"),
            ("almalinux", "9", "9.7"),
            ("almalinux", "10", "10.1"),
            ("alpine", "3.22", "3.22"),
            ("alpine", "3.22", "3.22.5"),
            ("alpine", "3.24", "3.24.1"),
        )
        rejected = (
            ("debian", "13", "13.1"),
            ("ubuntu", "24.04", "24.04.1"),
            ("fedora", "44", "44.1"),
            ("almalinux", "9", "10"),
            ("almalinux", "9", "90.1"),
            ("almalinux", "9.0", "9.0"),
            ("alpine", "3.22", "3.23"),
            ("alpine", "3.22", "3.220.1"),
            ("alpine", "3.22", "3.22x"),
            ("alpine", "3.22", "3.22."),
            ("unknown", "1", "1"),
        )
        for distribution, expected, actual in accepted:
            with self.subTest(
                verdict="accepted",
                distribution=distribution,
                expected=expected,
                actual=actual,
            ):
                self.assertTrue(
                    package_lifecycle_lab.distribution_version_matches(
                        distribution, expected, actual
                    )
                )
        for distribution, expected, actual in rejected:
            with self.subTest(
                verdict="rejected",
                distribution=distribution,
                expected=expected,
                actual=actual,
            ):
                self.assertFalse(
                    package_lifecycle_lab.distribution_version_matches(
                        distribution, expected, actual
                    )
                )

    def test_runtime_distribution_line_patch_versions_are_accepted(self) -> None:
        observed_versions = {
            "RPM-A9": "9.7",
            "RPM-A10": "10.1",
            "APK-322": "3.22.5",
            "APK-324": "3.24.1",
        }
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            if spec.cell_id not in observed_versions:
                continue
            observed = observed_versions[spec.cell_id]
            with self.subTest(cell_id=spec.cell_id, observed=observed):
                report = package_lifecycle_lab.run_lab(
                    self.args(),
                    runner=FakePodmanRunner(
                        reported_distribution_versions={spec.cell_id: observed}
                    ),
                    platforms=(spec,),
                    host_architecture="x86_64",
                )
                platform = report["platforms"][0]
                self.assertEqual(platform["status"], "pass")
                probe = platform["architecture_probe"]
                self.assertEqual(probe["status"], "available")
                self.assertEqual(probe["actual_distribution"], spec.distribution)
                self.assertEqual(probe["actual_distribution_version"], observed)

    def test_runtime_probe_shell_enforces_distribution_line_boundaries(self) -> None:
        cases = (
            ("RPM-A9", "almalinux", "9.8", 0),
            ("RPM-A9", "almalinux", "10.0", 1),
            ("RPM-A9", "alpine", "9.8", 1),
            ("APK-322", "alpine", "3.22.5", 0),
            ("APK-322", "alpine", "3.23.0", 1),
            ("DEB-U2404", "ubuntu", "24.04", 0),
            ("DEB-U2404", "ubuntu", "24.04.1", 1),
        )
        specs = {
            spec.cell_id: spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
        }
        for index, (cell_id, actual_id, actual_version, expected_rc) in enumerate(
            cases
        ):
            with self.subTest(
                cell_id=cell_id,
                actual_id=actual_id,
                actual_version=actual_version,
            ):
                spec = specs[cell_id]
                os_release = self.root / f"probe-os-release-{index}"
                os_release.write_text(
                    f"ID={actual_id}\nVERSION_ID={actual_version}\n",
                    encoding="ascii",
                )
                probe = package_lifecycle_lab.architecture_probe_arguments(
                    "podman", spec
                )[-1].replace('. /etc/os-release', '. "$1"', 1)
                lifecycle_source = package_lifecycle_lab.LIFECYCLE_SCRIPT
                lifecycle_guard = lifecycle_source[
                    lifecycle_source.index("[ -r /etc/os-release ]") :
                    lifecycle_source.index('\nRESULT_FILE="/results/events.tsv"')
                ]
                lifecycle_guard = lifecycle_guard.replace(
                    "[ -r /etc/os-release ]", '[ -r "$1" ]'
                ).replace(". /etc/os-release", '. "$1"')
                environment = {
                    **os.environ,
                    "EXPECTED_DISTRIBUTION": spec.distribution,
                    "EXPECTED_DISTRIBUTION_VERSION": spec.version,
                }
                for script_kind, script in (
                    ("architecture-probe", probe),
                    ("lifecycle-guard", lifecycle_guard),
                ):
                    result = subprocess.run(
                        (
                            shutil.which("dash") or "/bin/sh",
                            "-ceu",
                            script,
                            "distribution-probe",
                            str(os_release),
                        ),
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertEqual(
                        result.returncode == 0,
                        expected_rc == 0,
                        f"{script_kind}: {result.stderr}",
                    )

    def test_runtime_distribution_version_mismatch_is_fail_closed(self) -> None:
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            with self.subTest(cell_id=spec.cell_id):
                report = package_lifecycle_lab.run_lab(
                    self.args(),
                    runner=FakePodmanRunner(
                        reported_distribution_versions={spec.cell_id: "0"}
                    ),
                    platforms=(spec,),
                    host_architecture="x86_64",
                )
                platform = report["platforms"][0]
                self.assertEqual(platform["status"], "incomplete")
                probe = platform["architecture_probe"]
                self.assertEqual(probe["status"], "unavailable")
                self.assertEqual(
                    probe["expected_distribution_version"], spec.version
                )
                self.assertEqual(probe["actual_distribution_version"], "0")
                self.assertIn("VERSION_ID", probe["reason"])

    def test_runtime_distribution_id_mismatch_is_fail_closed(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.cell_id == "RPM-A9"
        )
        report = package_lifecycle_lab.run_lab(
            self.args(),
            runner=FakePodmanRunner(
                reported_distributions={spec.cell_id: "alpine"}
            ),
            platforms=(spec,),
            host_architecture="x86_64",
        )
        platform = report["platforms"][0]
        self.assertEqual(platform["status"], "incomplete")
        probe = platform["architecture_probe"]
        self.assertEqual(probe["status"], "unavailable")
        self.assertEqual(probe["expected_distribution"], "almalinux")
        self.assertEqual(probe["actual_distribution"], "alpine")
        self.assertIn("ID", probe["reason"])

    def test_amd64_pull_is_explicitly_platform_selected_and_digest_checked(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == "ubuntu" and item.architecture == "amd64"
        )
        runner = FakePodmanRunner()
        package_lifecycle_lab.ensure_image(runner, "podman", spec, "always")
        pull = next(call for call in runner.calls if call[1] == "pull")
        self.assertEqual(pull[pull.index("--platform") + 1], "linux/amd64")
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
            "/var/lib/syswarden/ui/lifecycle-operator.json",
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

    def test_lifecycle_shell_is_syntactically_valid(self) -> None:
        script = self.root / "package-lifecycle-syntax.sh"
        script.write_text(
            package_lifecycle_lab.LIFECYCLE_SCRIPT,
            encoding="utf-8",
        )
        result = subprocess.run(
            (shutil.which("dash") or "/bin/sh", "-n", str(script)),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_native_license_metadata_is_versioned_and_exact(self) -> None:
        check = "upgrade-rollback.metadata.candidate.license"
        baseline = package_lifecycle_lab.expected_event_checks(
            "deb",
            "upgrade-rollback",
            candidate_version="4.03.3",
        )
        candidate = package_lifecycle_lab.expected_event_checks(
            "deb",
            "upgrade-rollback",
            candidate_version="4.04.0",
        )
        future = package_lifecycle_lab.expected_event_checks(
            "deb",
            "upgrade-rollback",
            candidate_version="5.00.0",
        )
        self.assertNotIn(check, baseline)
        self.assertIn(check, candidate)
        self.assertIn(check, future)
        self.assertNotIn("upgrade-rollback.metadata.previous.license", candidate)
        self.assertLess(
            candidate.index("upgrade-rollback.metadata.candidate.architecture"),
            candidate.index(check),
        )
        self.assertLess(
            candidate.index(check),
            candidate.index("upgrade-rollback.metadata.previous.manager_manifest"),
        )

        events = [
            {"status": "pass", "check": item, "detail": "verified"}
            for item in candidate
        ]
        package_lifecycle_lab.validate_event_contract(
            events,
            "deb",
            "upgrade-rollback",
            candidate_version="4.04.0",
        )
        without_license = [event for event in events if event["check"] != check]
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "event contract mismatch",
        ):
            package_lifecycle_lab.validate_event_contract(
                without_license,
                "deb",
                "upgrade-rollback",
                candidate_version="4.04.0",
            )

    def test_native_package_license_extraction_is_fail_closed_for_all_families(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        function = source[
            source.index("package_license() {") : source.index(
                "\nexpected_runtime_dependencies() {"
            )
        ]
        fake_bin = self.root / "license-bin"
        fake_bin.mkdir()
        tool = (
            "#!/bin/sh\n"
            "case \"${0##*/}:$1\" in\n"
            "  dpkg-deb:--field|rpm:-qp)\n"
            "    printf '%s' \"${TEST_LICENSE-}\"\n"
            "    exit \"${TEST_STATUS-0}\"\n"
            "    ;;\n"
            "  tar:--list)\n"
            "    printf '%s' \"${TEST_APK_MEMBERS-}\"\n"
            "    exit \"${TEST_LIST_STATUS-0}\"\n"
            "    ;;\n"
            "  tar:--extract)\n"
            "    printf '%s' \"${TEST_APK_METADATA-}\"\n"
            "    exit \"${TEST_EXTRACT_STATUS-0}\"\n"
            "    ;;\n"
            "esac\n"
            "exit 90\n"
        )
        for name in ("dpkg-deb", "rpm", "tar"):
            path = fake_bin / name
            path.write_text(tool, encoding="ascii")
            path.chmod(0o700)

        harness = self.root / "package-license.sh"
        harness.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            + function
            + "\nactual=\"$(package_license \"$1\")\"\n"
            + "[ \"${actual}\" = GPL-3.0-or-later ]\n",
            encoding="ascii",
        )
        harness.chmod(0o700)

        def validate(
            family: str,
            *,
            license_value: str = package_lifecycle_lab.PROJECT_LICENSE_EXPRESSION,
            status: str = "0",
            members: str = ".PKGINFO\n",
            metadata: str | None = None,
            list_status: str = "0",
            extract_status: str = "0",
        ) -> subprocess.CompletedProcess[bytes]:
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "PACKAGE_FAMILY": family,
                "TEST_LICENSE": license_value,
                "TEST_STATUS": status,
                "TEST_APK_MEMBERS": members,
                "TEST_APK_METADATA": (
                    f"license = {license_value}\n"
                    if metadata is None
                    else metadata
                ),
                "TEST_LIST_STATUS": list_status,
                "TEST_EXTRACT_STATUS": extract_status,
            }
            return subprocess.run(
                ("/bin/sh", str(harness), str(self.root / "package")),
                check=False,
                capture_output=True,
                env=environment,
            )

        for family in ("deb", "rpm", "apk"):
            with self.subTest(family=family, mutation="accepted"):
                self.assertEqual(validate(family).returncode, 0)
            with self.subTest(family=family, mutation="wrong-license"):
                self.assertNotEqual(
                    validate(family, license_value="unknown").returncode,
                    0,
                )
            with self.subTest(family=family, mutation="missing-license"):
                self.assertNotEqual(
                    validate(family, license_value="").returncode,
                    0,
                )
            with self.subTest(family=family, mutation="metadata-command-failure"):
                kwargs = (
                    {"extract_status": "42"}
                    if family == "apk"
                    else {"status": "42"}
                )
                self.assertNotEqual(validate(family, **kwargs).returncode, 0)

        for name, arguments in {
            "missing-license": {"metadata": "pkgname = syswarden\n"},
            "duplicate-license": {
                "metadata": (
                    "license = GPL-3.0-or-later\n"
                    "license = GPL-3.0-or-later\n"
                )
            },
            "duplicate-pkginfo": {"members": ".PKGINFO\n.PKGINFO\n"},
            "list-failure": {"list_status": "42"},
        }.items():
            with self.subTest(family="apk", mutation=name):
                self.assertNotEqual(validate("apk", **arguments).returncode, 0)

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
        self.assertIn("operator_data", package_lifecycle_lab.OPERATOR_STATE_KEYS)
        self.assertNotIn("data", package_lifecycle_lab.OPERATOR_STATE_KEYS)
        token_writer = source[
            source.index("write_seeded_operator_token() {") : source.index(
                "\nseed_state() {"
            )
        ]
        self.assertIn("'[network]' 'interfaces = \"lo\"'", token_writer)
        self.assertNotIn('interfaces = "eth0"', token_writer)

    def test_networkless_preconfiguration_precedes_previous_install_and_full_seed_follows_probe(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        initial = source[
            source.index("scenario_upgrade_rollback_initial() {") : source.index(
                "\nscenario_upgrade_rollback_restart_one() {"
            )
        ]
        networkless = initial.index(
            "seed_and_attest_preinstall_networkless_config || return"
        )
        prepare = initial.index("prepare_package_transition || return")
        install = initial.index(
            'run_install_step install.previous "${PREVIOUS_PACKAGE}"'
        )
        postinstall_attestation = initial.index(
            "attest_preinstall_networkless_config_after_previous || return"
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
        self.assertLess(networkless, prepare)
        self.assertLess(prepare, install)
        self.assertLess(install, postinstall_attestation)
        self.assertTrue(
            all(postinstall_attestation < probe < seed for probe in probes)
        )
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
        candidate_path = self.root / "syswarden_4.03.2_x86_64.apk"
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

    def test_historical_ubuntu_deb_recovery_is_bounded_and_fail_closed(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        functions = source[
            source.index("record() {") : source.index("\ncheck_equal() {")
        ]
        recovery = source[
            source.index("is_exact_historical_ubuntu_deb_recovery() {") : source.index(
                "\nrun_install_step() {"
            )
        ]
        self.assertEqual(recovery.count("dpkg --configure syswarden"), 1)
        self.assertNotIn("dpkg --configure -a", recovery)
        self.assertNotIn("kill ", recovery)
        self.assertNotIn("pkill", recovery)
        self.assertIn('"${syswarden_historical_wait_attempt}" -lt 20', recovery)
        self.assertIn('"${syswarden_historical_clean_scans}" -lt 2', recovery)
        self.assertIn("syswarden_verify_webtui_retirement / || return 1", recovery)

        previous = self.root / "syswarden_4.03.2_amd64.deb"
        candidate = self.root / "syswarden_4.03.3_amd64.deb"
        previous.write_bytes(b"historical deb fixture")
        candidate.write_bytes(b"candidate deb fixture")
        persist = self.root / "persist"
        persist.mkdir()
        shell = self.root / "historical-deb-recovery.sh"
        shell.write_text(
            "#!/bin/sh\n"
            "set -u\n"
            'RESULT_FILE="$1"\n'
            'COMMAND_LOG="$2"\n'
            'CONFIGURE_CALLS="$3"\n'
            'CONFIGURED_STATE="$4"\n'
            'PREVIOUS_PACKAGE="$5"\n'
            'CANDIDATE_PACKAGE="$6"\n'
            'PERSIST_ROOT="$7"\n'
            'PREFIX="upgrade-rollback"\n'
            'INVOCATION="initial"\n'
            'FAILURES=0\n'
            + functions
            + "\n"
            "hash_file() {\n"
            '    case "$1" in\n'
            '        "${PREVIOUS_PACKAGE}") printf "%s\\n" "${MOCK_PREVIOUS_HASH}" ;;\n'
            '        "${CANDIDATE_PACKAGE}") printf "%s\\n" "${EXPECTED_CANDIDATE_SHA256}" ;;\n'
            '        *) printf "%s\\n" "${MOCK_CLI_HASH}" ;;\n'
            "    esac\n"
            "}\n"
            "historical_ubuntu_deb_package_state() {\n"
            '    if [ -f "${CONFIGURED_STATE}" ]; then cat "${CONFIGURED_STATE}"; '
            'else printf "%s" "${MOCK_INITIAL_STATE}"; fi\n'
            "}\n"
            "historical_ubuntu_deb_cli_payload_is_exact() {\n"
            '    return "${MOCK_PAYLOAD_RC}"\n'
            "}\n"
            "historical_ubuntu_deb_wait_for_cli_quiescence() {\n"
            '    return "${MOCK_WAIT_RC}"\n'
            "}\n"
            "syswarden_verify_webtui_retirement() {\n"
            '    return "${MOCK_HELPER_RC}"\n'
            "}\n"
            "dpkg() {\n"
            '    printf "%s\\n" "$*" >> "${CONFIGURE_CALLS}"\n'
            '    [ "$*" = "--configure syswarden" ] || return 97\n'
            '    [ "${MOCK_CONFIGURE_RC}" -eq 0 ] || return "${MOCK_CONFIGURE_RC}"\n'
            '    printf "%s" "${MOCK_FINAL_STATE}" > "${CONFIGURED_STATE}"\n'
            "}\n"
            "install_package() {\n"
            '    if [ "${MOCK_DIAGNOSTIC}" = exact ]; then\n'
            "        printf '%s\\n' \\\n"
            "            '[SYSWARDEN] v4.03.2 native installation complete.' \\\n"
            "            'dpkg: error processing package syswarden (--install):' \\\n"
            "            ' installed syswarden package post-installation script subprocess returned error exit status 1'\n"
            "    else\n"
            "        printf '%s\\n' 'different package failure'\n"
            "    fi\n"
            '    return "${MOCK_INSTALL_RC}"\n'
            "}\n"
            'run_install_step rollback.previous "${PREVIOUS_PACKAGE}"\n',
            encoding="utf-8",
        )
        shell.chmod(0o700)

        exact_sha = package_lifecycle_lab.HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS[
            "sha256"
        ]
        installed = "ii |install ok installed|4.03.2|amd64"
        half_configured = "iF |install ok half-configured|4.03.2|amd64"
        cases = {
            "normal-success": ({"MOCK_INSTALL_RC": "0"}, 0, 0, "command completed"),
            "exact-recovery": ({}, 0, 1, package_lifecycle_lab.HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL),
            "wrong-distribution": ({"EXPECTED_DISTRIBUTION": "debian"}, 1, 0, "command failed with exit code 1"),
            "wrong-hash": ({"EXPECTED_PREVIOUS_SHA256": "0" * 64}, 1, 0, "command failed with exit code 1"),
            "wrong-diagnostic": ({"MOCK_DIAGNOSTIC": "other"}, 1, 0, "command failed with exit code 1"),
            "wrong-initial-rc": ({"MOCK_INSTALL_RC": "2"}, 2, 0, "command failed with exit code 2"),
            "wrong-state": ({"MOCK_INITIAL_STATE": installed}, 1, 0, "command failed with exit code 1"),
            "payload-invalid": ({"MOCK_PAYLOAD_RC": "1"}, 1, 0, "command failed with exit code 1"),
            "quiescence-invalid": ({"MOCK_WAIT_RC": "1"}, 1, 0, "command failed with exit code 1"),
            "helper-invalid": ({"MOCK_HELPER_RC": "1"}, 1, 0, "command failed with exit code 1"),
            "configure-failed": ({"MOCK_CONFIGURE_RC": "1"}, 1, 1, "command failed with exit code 1"),
            "final-state-invalid": ({"MOCK_FINAL_STATE": half_configured}, 1, 1, "command failed with exit code 1"),
        }
        for name, (overrides, expected_rc, configure_count, expected_detail) in cases.items():
            with self.subTest(name=name):
                events = self.root / f"{name}.events"
                commands = self.root / f"{name}.commands"
                configure_calls = self.root / f"{name}.configure"
                configured_state = self.root / f"{name}.state"
                env = os.environ.copy()
                env.update(
                    {
                        "PACKAGE_FAMILY": "deb",
                        "SCENARIO": "upgrade-rollback",
                        "EXPECTED_DISTRIBUTION": "ubuntu",
                        "EXPECTED_PACKAGE_ARCHITECTURE": "amd64",
                        "HISTORICAL_UBUNTU_DEB_RECOVERY": "1",
                        "FORWARD_ONLY_APK_TRANSITION": "0",
                        "EXPECTED_PREVIOUS_VERSION": "4.03.2",
                        "EXPECTED_CANDIDATE_VERSION": "4.03.3",
                        "EXPECTED_PREVIOUS_SHA256": exact_sha,
                        "EXPECTED_CANDIDATE_SHA256": "c" * 64,
                        "MOCK_PREVIOUS_HASH": exact_sha,
                        "MOCK_CLI_HASH": "d" * 64,
                        "MOCK_DIAGNOSTIC": "exact",
                        "MOCK_INSTALL_RC": "1",
                        "MOCK_INITIAL_STATE": half_configured,
                        "MOCK_FINAL_STATE": installed,
                        "MOCK_PAYLOAD_RC": "0",
                        "MOCK_WAIT_RC": "0",
                        "MOCK_HELPER_RC": "0",
                        "MOCK_CONFIGURE_RC": "0",
                    }
                )
                env.update(overrides)
                result = subprocess.run(
                    (
                        str(shell),
                        str(events),
                        str(commands),
                        str(configure_calls),
                        str(configured_state),
                        str(previous),
                        str(candidate),
                        str(persist),
                    ),
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(result.returncode, expected_rc, result)
                calls = (
                    configure_calls.read_text(encoding="utf-8").splitlines()
                    if configure_calls.exists()
                    else []
                )
                self.assertEqual(calls, ["--configure syswarden"] * configure_count)
                event = events.read_text(encoding="utf-8").splitlines()[0].split("\t")
                self.assertEqual(event[0], "pass" if expected_rc == 0 else "fail")
                self.assertEqual(event[1], "upgrade-rollback.rollback.previous")
                self.assertEqual(event[2], expected_detail)

    def test_historical_ubuntu_deb_process_wait_uses_exact_inode_identity(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        inventory = source[
            source.index("historical_ubuntu_deb_cli_process_inventory_empty() {") : source.index(
                "\nhistorical_ubuntu_deb_wait_for_cli_quiescence() {"
            )
        ]
        proc_root = self.root / "proc"
        proc_root.mkdir()
        cli = self.root / "syswarden-cli"
        other = self.root / "other-cli"
        cli.write_bytes(b"exact cli")
        other.write_bytes(b"other cli")
        shell = self.root / "historical-process-inventory.sh"
        shell.write_text(
            "#!/bin/sh\nset -u\n"
            "syswarden_webtui_process_starttime() { sed -n 's/^start=//p' \"$1\"; }\n"
            + inventory
            + '\nhistorical_ubuntu_deb_cli_process_inventory_empty "$1" "$2"\n',
            encoding="utf-8",
        )
        shell.chmod(0o700)

        def probe() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                (str(shell), str(proc_root), str(cli)),
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(probe().returncode, 0)
        process = proc_root / "4242"
        process.mkdir()
        (process / "stat").write_text("start=17\n", encoding="utf-8")
        (process / "exe").symlink_to(other)
        self.assertEqual(probe().returncode, 0)
        (process / "exe").unlink()
        (process / "exe").symlink_to(cli)
        self.assertEqual(probe().returncode, 1)

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
            'CANDIDATE_PACKAGE="/candidate/v4.03.2.apk"\n'
            'PREVIOUS_VERSION="4.02.8"\n'
            'CANDIDATE_VERSION="4.03.2"\n'
            'EXPECTED_PREVIOUS_VERSION="4.02.8"\n'
            'EXPECTED_CANDIDATE_VERSION="4.03.2"\n'
            'FORWARD_ONLY_APK_TRANSITION="1"\n'
            "prepare_expected_payloads() { return 0; }\n"
            "seed_and_attest_preinstall_networkless_config() { :; }\n"
            "attest_preinstall_networkless_config_after_previous() { :; }\n"
            "seed_state() { :; }\n"
            "seed_legacy_webtui_upgrade_state() { :; }\n"
            "seed_live_legacy_webtui_process() { :; }\n"
            "seed_legacy_saas_monitor_state() { :; }\n"
            "prepare_service_runtime_fixture() { :; }\n"
            "prepare_package_transition() { prepare_service_runtime_fixture; }\n"
            "prepare_alma_v4028_rpm_rsyslog_fixture() { :; }\n"
            "attest_alma_v4028_rpm_rsyslog_fixture() { :; }\n"
            "attest_alma_v4028_rpm_rsyslog_after_previous() { :; }\n"
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

    def test_scenario_dispatch_propagates_unrecorded_failure_exit_codes(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        dispatch_start = source.index('if [ "${INVOCATION}" = "initial" ]; then')
        scenario_functions = source[
            source.index("scenario_upgrade_rollback_initial() {") : dispatch_start
        ]
        dispatch = source[dispatch_start:]
        shell = self.root / "scenario-dispatch-fail-close.sh"
        shell.write_text(
            "#!/bin/sh\n"
            "set -u\n"
            'SCENARIO="${SCENARIO:?}"\n'
            'INVOCATION="initial"\n'
            'RESULT_FILE="${RESULT_FILE:?}"\n'
            'CALLS="${CALLS:?}"\n'
            'RESTART_STATE_FILE="${RESTART_STATE_FILE:?}"\n'
            'PREVIOUS_PACKAGE="/previous/exact-v4.02.8.apk"\n'
            'CANDIDATE_PACKAGE="/candidate/v4.03.2.apk"\n'
            'PREVIOUS_VERSION="4.02.8"\n'
            'CANDIDATE_VERSION="4.03.2"\n'
            'FORWARD_ONLY_APK_TRANSITION="0"\n'
            "FAILURES=0\n"
            "probe_execution_architecture() { return 0; }\n"
            "prepare_package_transition() { return 0; }\n"
            "seed_and_attest_preinstall_networkless_config() { return 0; }\n"
            "attest_preinstall_networkless_config_after_previous() { return 0; }\n"
            "prepare_alma_v4028_rpm_rsyslog_fixture() { return 0; }\n"
            "attest_alma_v4028_rpm_rsyslog_fixture() { return 0; }\n"
            "attest_alma_v4028_rpm_rsyslog_after_previous() { return 0; }\n"
            "prepare_expected_payloads() {\n"
            '    case "${SCENARIO}" in\n'
            "        upgrade-rollback) return 0 ;;\n"
            "        remove) return 93 ;;\n"
            "        purge) return 94 ;;\n"
            "    esac\n"
            "}\n"
            'run_install_step() { printf "%s\\n" "$1" >> "${CALLS}"; }\n'
            "probe_payload() { :; }\n"
            "seed_state() { :; }\n"
            "assert_all_state_preserved() { :; }\n"
            "seed_legacy_webtui_upgrade_state() {\n"
            '    if [ "${RECORD_SEED_FAILURE:-0}" = "1" ]; then\n'
            '        record fail "upgrade-rollback.seed" "seed failed"\n'
            "    fi\n"
            "    return 92\n"
            "}\n"
            "record() {\n"
            '    printf "%s\\t%s\\t%s\\n" "$1" "$2" "$3" >> "${RESULT_FILE}"\n'
            '    if [ "$1" = "fail" ]; then FAILURES=$((FAILURES + 1)); fi\n'
            "}\n"
            + scenario_functions
            + dispatch,
            encoding="utf-8",
        )
        shell.chmod(0o700)
        for label, scenario, expected_rc, expected_calls, recorded_failure in (
            ("upgrade-rollback", "upgrade-rollback", 92, ["install.previous"], False),
            ("remove", "remove", 93, [], False),
            ("purge", "purge", 94, [], False),
            (
                "upgrade-rollback-recorded",
                "upgrade-rollback",
                92,
                ["install.previous"],
                True,
            ),
        ):
            with self.subTest(label=label):
                result_file = self.root / f"{label}-scenario-events"
                calls = self.root / f"{label}-scenario-calls"
                restart = self.root / f"{label}-scenario-restart-state"
                result_file.write_text("", encoding="utf-8")
                calls.write_text("", encoding="utf-8")
                env = os.environ.copy()
                env.update(
                    {
                        "SCENARIO": scenario,
                        "RESULT_FILE": str(result_file),
                        "CALLS": str(calls),
                        "RESTART_STATE_FILE": str(restart),
                        "RECORD_SEED_FAILURE": "1" if recorded_failure else "0",
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
                expected_event = (
                    "fail\tupgrade-rollback.seed\tseed failed\n"
                    if recorded_failure
                    else "fail\tscenario.execution\t"
                    f"scenario returned exit code {expected_rc}\n"
                )
                self.assertEqual(result_file.read_text(encoding="utf-8"), expected_event)
                self.assertEqual(
                    calls.read_text(encoding="utf-8").splitlines(), expected_calls
                )
                self.assertFalse(restart.exists())

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
            package_lifecycle_lab.BASH_COMPLETION_PATH,
        ]
        deb = payload + [
            "/opt",
            "/opt/syswarden",
            "/opt/syswarden/bin",
            "/usr",
            "/usr/local",
            "/usr/local/bin",
            "/usr/share",
            "/usr/share/bash-completion",
            "/usr/share/bash-completion/completions",
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
                missing_completion = self.run_embedded_inventory_contract(
                    family,
                    [
                        path
                        for path in manifest
                        if path != package_lifecycle_lab.BASH_COMPLETION_PATH
                    ],
                )
                self.assertNotEqual(missing_completion.returncode, 0)

    def test_v4040_packages_require_exact_license_payloads(self) -> None:
        build_id_paths = {
            "/usr/lib/.build-id",
            "/usr/lib/.build-id/11",
            "/usr/lib/.build-id/11/" + "1" * 38,
            "/usr/lib/.build-id/22",
            "/usr/lib/.build-id/22/" + "2" * 38,
            "/usr/lib/.build-id/33",
            "/usr/lib/.build-id/33/" + "3" * 38,
        }
        manifests = {
            "deb": sorted(package_lifecycle_lab.LICENSED_DEB_PACKAGE_PATHS),
            "apk": sorted(package_lifecycle_lab.LICENSED_APK_PACKAGE_PATHS),
            "rpm": sorted(
                set(package_lifecycle_lab.LICENSED_PACKAGE_PAYLOAD_PATHS)
                | build_id_paths
            ),
        }
        file_modes = {
            "/opt/syswarden/bin/syswarden-cli": "750",
            "/opt/syswarden/bin/syswarden-core": "750",
            "/opt/syswarden/bin/syswarden-tui": "750",
            "/opt/syswarden/signatures.json": "640",
            package_lifecycle_lab.BASH_COMPLETION_PATH: "644",
            package_lifecycle_lab.GEOIP_DATA_LICENSE_PATH: "644",
            package_lifecycle_lab.PROJECT_LICENSE_PATH: "644",
        }
        link_targets = {
            "/usr/local/bin/syswarden": "/opt/syswarden/bin/syswarden-cli",
            "/usr/local/bin/syswarden-tui": "/opt/syswarden/bin/syswarden-tui",
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
        for family, manifest in manifests.items():
            inventory = []
            for path in manifest:
                if path in file_modes:
                    value = (
                        package_lifecycle_lab.GEOIP_DATA_LICENSE_SHA256
                        if path == package_lifecycle_lab.GEOIP_DATA_LICENSE_PATH
                        else (
                            package_lifecycle_lab.PROJECT_LICENSE_SHA256
                            if path == package_lifecycle_lab.PROJECT_LICENSE_PATH
                            else "a" * 64
                        )
                    )
                    kind, mode = "file", file_modes[path]
                elif path == "/usr/share/doc/syswarden/changelog.gz":
                    kind, mode, value = "file", "644", "b" * 64
                elif path in link_targets:
                    kind, mode, value = "symlink", "777", link_targets[path]
                else:
                    kind, mode, value = "directory", "755", "-"
                inventory.append(f"{path}\t{kind}\t{mode}\t0\t0\t{value}")
            with self.subTest(family=family):
                filesystem = [
                    {
                        "path": fields[0],
                        "type": fields[1],
                        "mode": fields[2],
                        "uid": int(fields[3]),
                        "gid": int(fields[4]),
                        "value": fields[5],
                    }
                    for fields in (line.split("\t") for line in inventory)
                ]
                package_lifecycle_lab._validate_manager_paths(
                    family,
                    manifest,
                    role="candidate",
                    version="4.04.0",
                    candidate_version="4.04.0",
                )
                package_lifecycle_lab.validate_inventory_snapshot(
                    family,
                    manifest,
                    filesystem,
                    role="candidate",
                    version="4.04.0",
                    candidate_version="4.04.0",
                )
                accepted = self.run_embedded_inventory_contract(
                    family,
                    manifest,
                    inventory,
                    version="4.04.0",
                    candidate_version="4.04.0",
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)

                without_attribution = [
                    path
                    for path in manifest
                    if path != package_lifecycle_lab.GEOIP_DATA_LICENSE_PATH
                ]
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        without_attribution,
                        version="4.04.0",
                        candidate_version="4.04.0",
                    ).returncode,
                    0,
                )

                without_project_license = [
                    path
                    for path in manifest
                    if path != package_lifecycle_lab.PROJECT_LICENSE_PATH
                ]
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        without_project_license,
                        version="4.04.0",
                        candidate_version="4.04.0",
                    ).returncode,
                    0,
                )

                altered_inventory = [
                    line.replace(
                        package_lifecycle_lab.GEOIP_DATA_LICENSE_SHA256,
                        "0" * 64,
                    )
                    for line in inventory
                ]
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        manifest,
                        altered_inventory,
                        version="4.04.0",
                        candidate_version="4.04.0",
                    ).returncode,
                    0,
                )

                altered_project_license_inventory = [
                    line.replace(
                        package_lifecycle_lab.PROJECT_LICENSE_SHA256,
                        "0" * 64,
                    )
                    for line in inventory
                ]
                altered_project_filesystem = [
                    {
                        "path": fields[0],
                        "type": fields[1],
                        "mode": fields[2],
                        "uid": int(fields[3]),
                        "gid": int(fields[4]),
                        "value": fields[5],
                    }
                    for fields in (
                        line.split("\t")
                        for line in altered_project_license_inventory
                    )
                ]
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError,
                    "project license payload",
                ):
                    package_lifecycle_lab.validate_inventory_snapshot(
                        family,
                        manifest,
                        altered_project_filesystem,
                        role="candidate",
                        version="4.04.0",
                        candidate_version="4.04.0",
                    )
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        manifest,
                        altered_project_license_inventory,
                        version="4.04.0",
                        candidate_version="4.04.0",
                    ).returncode,
                    0,
                )

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

        package_lifecycle_lab._validate_manager_paths(
            "rpm",
            valid,
            role="candidate",
            version="4.03.3",
            candidate_version="4.03.3",
        )
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
                        "rpm",
                        adversarial,
                        role="candidate",
                        version="4.03.3",
                        candidate_version="4.03.3",
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
            f"{package_lifecycle_lab.BASH_COMPLETION_PATH}\tfile\t644\t0\t0\t{digest}",
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
        legacy_manifest = [
            path
            for path in manifest
            if path != package_lifecycle_lab.BASH_COMPLETION_PATH
        ]
        legacy_inventory = [
            line
            for line in inventory
            if not line.startswith(
                package_lifecycle_lab.BASH_COMPLETION_PATH + "\t"
            )
        ]
        accepted_previous = self.run_embedded_inventory_contract(
            "rpm",
            legacy_manifest,
            legacy_inventory,
            role="previous",
            version="4.03.2",
            candidate_version="4.03.3",
        )
        self.assertEqual(
            accepted_previous.returncode, 0, accepted_previous.stderr
        )
        previous_filesystem = []
        for line in sorted(legacy_inventory):
            path, kind, mode, uid, gid, value = line.split("\t")
            previous_filesystem.append(
                {
                    "path": path,
                    "type": kind,
                    "mode": mode,
                    "uid": int(uid),
                    "gid": int(gid),
                    "value": value,
                }
            )
        package_lifecycle_lab.validate_inventory_snapshot(
            "rpm",
            sorted(legacy_manifest),
            previous_filesystem,
            role="previous",
            version="4.03.2",
            candidate_version="4.03.3",
        )
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
            "completion-mode": [
                line.replace("\t644\t", "\t600\t", 1)
                if line.startswith(
                    package_lifecycle_lab.BASH_COMPLETION_PATH + "\t"
                )
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

    def test_active_namespace_readiness_retries_until_real_init_is_ready(self) -> None:
        runner = FakePodmanRunner(namespace_failures=2)
        with mock.patch.object(package_lifecycle_lab.time, "sleep") as sleep:
            report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(sleep.call_count, 2)
        failed_then_ready = [
            call
            for call in runner.calls
            if call[1] == "exec"
            and call[-1] != "/lab/package-lifecycle.sh"
            and "capture_snapshot()" not in call[-1]
        ][:3]
        self.assertEqual(len(failed_then_ready), 3)

    def test_active_namespace_readiness_exhaustion_is_fail_closed(self) -> None:
        runner = FakePodmanRunner(namespace_failures=30)
        platforms = (package_lifecycle_lab.DEFAULT_PLATFORMS[0],)
        with mock.patch.object(package_lifecycle_lab.time, "sleep") as sleep:
            report = package_lifecycle_lab.run_lab(
                self.args(),
                runner=runner,
                platforms=platforms,
                host_architecture="x86_64",
            )
        first = report["platforms"][0]["scenarios"][0]
        self.assertEqual(first["status"], "fail")
        self.assertIn("failed after 30 bounded attempts", first["orchestration_error"])
        self.assertEqual(sleep.call_count, 29)

    def test_namespace_failure_record_is_preserved_in_report(self) -> None:
        diagnostic = namespace_failure_record(
            "NS14_FEDORA_MASKS", 0, "operator", "exact"
        )
        runner = FakePodmanRunner(
            namespace_failures=30,
            namespace_failure_stderr=diagnostic,
        )
        platforms = (
            next(
                spec
                for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
                if spec.distribution == "fedora" and spec.architecture == "amd64"
            ),
        )
        with mock.patch.object(package_lifecycle_lab.time, "sleep"):
            report = package_lifecycle_lab.run_lab(
                self.args(),
                runner=runner,
                platforms=platforms,
                host_architecture="x86_64",
            )
        first = report["platforms"][0]["scenarios"][0]
        self.assertEqual(first["status"], "fail")
        self.assertIn(diagnostic.strip(), first["orchestration_error"])

    def test_absent_core_runtime_rejects_pidfile_process_and_deleted_executable(
        self,
    ) -> None:
        spec = package_lifecycle_lab.DEFAULT_PLATFORMS[0]
        source = package_lifecycle_lab.runtime_snapshot_script(spec, "absent")
        start = source.index("attest_no_syswarden_core_runtime() {")
        end = source.index("\n}\ncapture_snapshot() {", start) + len("\n}\n")
        function = source[start:end]
        self.assertIn(
            "attest_no_syswarden_core_runtime /proc /run/syswarden-core.pid",
            source,
        )
        proc_root = self.root / "proc"
        proc_root.mkdir()
        pidfile = self.root / "syswarden-core.pid"

        def attest() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    function
                    + '\nattest_no_syswarden_core_runtime "$1" "$2"',
                    "probe",
                    str(proc_root),
                    str(pidfile),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(attest().returncode, 0)
        pidfile.write_text("123\n", encoding="utf-8")
        self.assertNotEqual(attest().returncode, 0)
        pidfile.unlink()
        process = proc_root / "123"
        process.mkdir()
        process.joinpath("comm").write_text("syswarden-core\n", encoding="utf-8")
        process.joinpath("exe").symlink_to("/usr/bin/other")
        self.assertNotEqual(attest().returncode, 0)
        process.joinpath("comm").write_text("other\n", encoding="utf-8")
        process.joinpath("exe").unlink()
        process.joinpath("exe").symlink_to("/opt/syswarden/bin/syswarden-core")
        self.assertNotEqual(attest().returncode, 0)
        process.joinpath("exe").unlink()
        process.joinpath("exe").symlink_to(
            "/opt/syswarden/bin/syswarden-core (deleted)"
        )
        self.assertNotEqual(attest().returncode, 0)

    def test_openrc_webtui_pidfile_is_attested_before_manager_and_no_follow_created(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        attestation = source.index(
            "attest_openrc_webtui_pidfile_before_manager \\\n                    /run/syswarden-webtui.pid /proc"
        )
        manager_status = source.index(
            "rc-service syswarden-webtui status", attestation
        )
        self.assertLess(attestation, manager_status)
        self.assertIn("present:0)", source[attestation:manager_status + 1000])
        self.assertIn("absent:3)", source[attestation:manager_status + 1000])
        self.assertIn(
            "write_exclusive_root_pidfile /run/syswarden-webtui.pid 4194303",
            source,
        )
        apk_seed = source.split("seed_legacy_webtui_upgrade_state() {", 1)[1].split(
            "\nSYSWARDEN_OPENRC_WEBTUI\n", 1
        )[0]
        self.assertNotIn("rm -f /run/syswarden-webtui.pid", apk_seed)
        self.assertNotIn("> /run/syswarden-webtui.pid", apk_seed)
        self.assertIn("chmod 0644 /run/syswarden-webtui.pid", apk_seed)
        start = source.index("attest_openrc_webtui_pidfile_before_manager() {")
        end = source.index("\n}\n\nwrite_exclusive_root_pidfile() {", start) + len("\n}\n")
        function = source[start:end]
        pidfile = self.root / "webtui.pid"
        pidfile.symlink_to(self.root / "operator-target")
        rejected = subprocess.run(
            [
                "/bin/sh",
                "-c",
                function
                + '\nattest_openrc_webtui_pidfile_before_manager "$1" "$2"',
                "probe",
                str(pidfile),
                str(self.root / "proc"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        writer_start = source.index("write_exclusive_root_pidfile() {")
        writer_end = source.index(
            "\n}\n\nquiesce_previous_webtui_runtime() {", writer_start
        ) + len("\n}\n")
        writer = source[writer_start:writer_end]
        mock_bin = self.root / "mock-bin"
        mock_bin.mkdir()
        mock_stat = mock_bin / "stat"
        mock_stat.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -c ] && [ \"$2\" = '%u:%g:%a' ]; then\n"
            "    printf '%s\\n' 0:0:600\n"
            "    exit 0\n"
            "fi\n"
            "exec /usr/bin/stat \"$@\"\n",
            encoding="utf-8",
        )
        mock_stat.chmod(0o700)
        writer_root = self.root / "writer"
        writer_root.mkdir()
        destination = writer_root / "webtui.pid"
        target = writer_root / "operator-target"
        target.write_text("operator-owned\n", encoding="utf-8")
        destination.symlink_to(target)
        environment = {
            **os.environ,
            "PATH": f"{mock_bin}:{os.environ['PATH']}",
        }

        def write_pid() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    writer + '\nwrite_exclusive_root_pidfile "$1" 4194303',
                    "probe",
                    str(destination),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

        self.assertNotEqual(write_pid().returncode, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "operator-owned\n")
        destination.unlink()
        self.assertEqual(write_pid().returncode, 0)
        self.assertTrue(destination.is_file())
        self.assertFalse(destination.is_symlink())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(destination.read_text(encoding="utf-8"), "4194303\n")

    def test_fake_rootless_run_reports_linux_container_scope(self) -> None:
        runner = FakePodmanRunner()
        report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["schema_version"], package_lifecycle_lab.SCHEMA_VERSION
        )
        self.assertEqual(
            report["qualification_matrix"],
            {
                "matrix_id": package_lifecycle_lab.QUALIFICATION_MATRIX_ID,
                "sha256": package_lifecycle_lab.QUALIFICATION_MATRIX_SHA256,
            },
        )
        version_contract = report["package_version_contract"]
        self.assertEqual(version_contract["previous_version"], "4.02.7")
        self.assertEqual(version_contract["candidate_version"], "4.02.8")
        self.assertEqual(version_contract["previous_numeric"], [4, 2, 7])
        self.assertEqual(version_contract["candidate_numeric"], [4, 2, 8])
        self.assertEqual(len(version_contract["coordinates"]), 3)
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
            {item["distribution"] for item in report["platforms"]},
            {"debian", "ubuntu", "fedora", "almalinux", "alpine"},
        )
        self.assertEqual(len(report["platforms"]), 8)
        self.assertEqual(
            [item["cell_id"] for item in report["platforms"]],
            [spec.cell_id for spec in package_lifecycle_lab.DEFAULT_PLATFORMS],
        )
        self.assertTrue(
            all(
                item["version"]
                == item["architecture_probe"]["actual_distribution_version"]
                for item in report["platforms"]
            )
        )
        self.assertTrue(
            all(
                item["distribution"]
                == item["architecture_probe"]["actual_distribution"]
                for item in report["platforms"]
            )
        )
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
            19,
        )
        self.assertEqual(
            report["scope"]["architectures_completed"],
            ["amd64/x86_64"],
        )
        self.assertEqual(report["scope"]["missing_platform_coordinates"], [])
        self.assertEqual(report["scope"]["evidence_kind"], "container-lifecycle")
        self.assertEqual(
            report["scope"]["coverage_kind"], "container_scenarios_only"
        )
        self.assertIs(report["scope"]["real_host_evidence_included"], False)
        self.assertIs(report["scope"]["required_checks_complete"], False)
        self.assertEqual(
            report["scope"]["covered_scenarios"],
            package_lifecycle_lab.qualification_matrix_container_scenarios(),
        )
        self.assertEqual(
            report["scope"]["architecture_coverage"][0]["required_cells"],
            [spec.cell_id for spec in package_lifecycle_lab.DEFAULT_PLATFORMS],
        )
        family_coverage = {
            item["family"]: item["status"]
            for item in report["scope"]["family_architecture_coverage"]
            if item["architecture_id"] == "amd64"
        }
        self.assertEqual(
            family_coverage, {"deb": "pass", "rpm": "pass", "apk": "pass"}
        )
        self.assertIn("not a SysWarden product rollback", report["scope"]["rollback_model"])
        run_calls = [call for call in runner.calls if call[1] == "run"]
        self.assertEqual(len(run_calls), 8)
        lifecycle_creates = [
            call
            for call in runner.calls
            if call[1] == "create" and any(
                value.endswith(":/results:rw") for value in call
            )
        ]
        self.assertEqual(len(lifecycle_creates), 21)
        self.assertTrue(all("--network=none" in call for call in lifecycle_creates))
        bootstrap_creates = [
            call
            for call in runner.calls
            if call[1] == "create" and call not in lifecycle_creates
        ]
        self.assertEqual(bootstrap_creates, [])
        start_calls = [call for call in runner.calls if call[1] == "start"]
        restart_calls = [call for call in runner.calls if call[1] == "restart"]
        lifecycle_execs = [
            call
            for call in runner.calls
            if call[1] == "exec"
            and "exec /bin/sh /lab/package-lifecycle.sh" in call[-1]
        ]
        self.assertEqual(len(start_calls), 21)
        self.assertEqual(len(restart_calls), 16)
        self.assertEqual(len(lifecycle_execs), 37)
        self.assertEqual(
            len([call for call in runner.calls if call[1] == "commit"]), 0
        )
        build_calls = [call for call in runner.calls if call[1] == "build"]
        self.assertEqual(len(build_calls), 8)
        self.assertTrue(all("--platform" in call for call in build_calls))
        self.assertTrue(all("--network=host" not in call for call in build_calls))

    def test_v4040_fake_matrix_distinguishes_previous_and_licensed_candidate(self) -> None:
        candidate = self.root / "candidate-v4040"
        previous = self.root / "previous-v4033"
        candidate.mkdir()
        previous.mkdir()
        self.create_package_set(candidate, b"candidate-v4040", "4.04.0")
        self.create_package_set(previous, b"previous-v4033", "4.03.3")
        report = package_lifecycle_lab.run_lab(
            self.args(
                packages_dir=candidate,
                previous_packages_dir=previous,
            ),
            runner=FakePodmanRunner(),
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["platforms"]), 8)
        for platform in report["platforms"]:
            upgrade = next(
                item
                for item in platform["scenarios"]
                if item["name"] == "upgrade-rollback"
            )
            previous_paths = upgrade["inventory_evidence"]["previous"][
                "manager_paths"
            ]
            candidate_paths = upgrade["inventory_evidence"]["candidate"][
                "manager_paths"
            ]
            self.assertNotIn(
                package_lifecycle_lab.PROJECT_LICENSE_PATH, previous_paths
            )
            self.assertIn(
                package_lifecycle_lab.PROJECT_LICENSE_PATH, candidate_paths
            )

    def test_native_shard_covers_exact_amd64_architecture(self) -> None:
        report = self.native_shard_report()
        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["native_shard"],
            {"schema_version": 1, "architecture": "amd64"},
        )
        self.assertEqual(
            {item["architecture_id"] for item in report["platforms"]},
            {"amd64"},
        )
        self.assertEqual(len(report["platforms"]), 8)
        self.assertTrue(
            all(
                item["architecture_probe"]["execution_mode"] == "native"
                for item in report["platforms"]
            )
        )

    def test_native_shard_rejects_missing_duplicate_or_reordered_cells(self) -> None:
        platforms = package_lifecycle_lab.DEFAULT_PLATFORMS
        invalid_matrices = {
            "missing": platforms[:-1],
            "duplicate": platforms[:-1] + (platforms[0],),
            "reordered": tuple(reversed(platforms)),
        }
        for name, matrix in invalid_matrices.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    package_lifecycle_lab.LifecycleLabError,
                    "exact eight matrix cells in canonical order",
                ):
                    package_lifecycle_lab.run_lab(
                        self.qualification_args("amd64"),
                        runner=FakePodmanRunner(),
                        platforms=matrix,
                        host_architecture="x86_64",
                    )

    def test_native_shard_rejects_non_amd64_host(self) -> None:
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
                host_architecture="unsupported",
            )

    def test_native_shard_aggregate_is_exact_digest_bound_and_adapter_compatible(self) -> None:
        amd64 = self.native_shard_report()
        amd64_path = self.root / "package-lifecycle-amd64.json"
        amd64_path.write_text(
            json.dumps(amd64, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        aggregate = package_lifecycle_lab.aggregate_native_shard_reports(
            self.aggregate_args(amd64_path)
        )
        self.assertEqual(aggregate["status"], "pass")
        self.assertTrue(aggregate["harness_complete"])
        self.assertTrue(aggregate["release_ready"])
        self.assertEqual(
            aggregate["scope"]["host_architecture"],
            package_lifecycle_lab.NATIVE_AGGREGATE_HOST,
        )
        self.assertEqual(len(aggregate["platforms"]), 8)
        self.assertEqual(
            [item["architecture"] for item in aggregate["native_shards"]["reports"]],
            ["amd64"],
        )
        self.assertEqual(
            aggregate["native_shards"]["reports"][0]["report_sha256"],
            hashlib.sha256(amd64_path.read_bytes()).hexdigest(),
        )
        package_lifecycle_lab.validate_report_version_contract(aggregate)

    def test_native_shard_aggregate_propagates_product_failure(self) -> None:
        amd64_platforms = tuple(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.architecture == "amd64"
        )
        amd64 = package_lifecycle_lab.run_lab(
            self.qualification_args("amd64"),
            runner=FakePodmanRunner(
                event_status="fail", host_architecture="amd64"
            ),
            platforms=amd64_platforms,
            host_architecture="x86_64",
        )
        amd64_path = self.root / "failed-aggregate-amd64.json"
        amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")

        aggregate = package_lifecycle_lab.aggregate_native_shard_reports(
            self.aggregate_args(amd64_path)
        )
        self.assertEqual(aggregate["status"], "fail")
        self.assertFalse(aggregate["harness_complete"])
        self.assertFalse(aggregate["release_ready"])
        self.assertTrue(aggregate["unexpected_failed_checks"])

    def test_native_shard_aggregate_rejects_mutated_binding_matrix_and_execution(self) -> None:
        baseline_amd64 = self.native_shard_report()
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
            "translated execution": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("execution_mode", "translated"),
            "wrong native uname": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("actual_uname", "unsupported"),
            "wrong distribution version": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("actual_distribution_version", "12"),
            "wrong distribution id": lambda report: report["platforms"][0][
                "architecture_probe"
            ].__setitem__("actual_distribution", "alpine"),
            "matrix digest mismatch": lambda report: report[
                "qualification_matrix"
            ].__setitem__("sha256", "0" * 64),
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
                mutate(amd64)
                amd64_path = self.root / f"{name}-amd64.json"
                amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.aggregate_native_shard_reports(
                        self.aggregate_args(amd64_path)
                    )

    def test_native_shard_reader_rejects_duplicate_json_keys(self) -> None:
        amd64 = self.native_shard_report()
        amd64_path = self.root / "duplicate-amd64.json"
        payload = json.dumps(amd64)
        amd64_path.write_text(
            payload.replace("{", '{"schema_version":3,', 1) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "duplicate JSON key",
        ):
            package_lifecycle_lab.aggregate_native_shard_reports(
                self.aggregate_args(amd64_path)
            )

    def test_native_shard_aggregate_cli_writes_exact_report(self) -> None:
        amd64 = self.native_shard_report()
        amd64_path = self.root / "cli-amd64.json"
        output = self.root / "cli-aggregate.json"
        amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
        arguments = (
            "--packages-dir",
            str(self.candidate),
            "--previous-packages-dir",
            str(self.previous),
            "--aggregate-amd64-report",
            str(amd64_path),
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
        self.assertEqual(len(written["platforms"]), 8)
        stdout.write.assert_called_once()

    def test_report_version_contract_rejects_schema_order_and_platform_tampering(
        self,
    ) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        mutations = {
            "schema": lambda item: item.update(schema_version=2),
            "matrix_id": lambda item: item["qualification_matrix"].update(
                matrix_id="syswarden-package-qualification/v2"
            ),
            "matrix_sha256": lambda item: item["qualification_matrix"].update(
                sha256="0" * 64
            ),
            "coverage_kind": lambda item: item["scope"].update(
                coverage_kind="full-qualification"
            ),
            "real_host_scope": lambda item: item["scope"].update(
                real_host_evidence_included=True
            ),
            "required_checks_scope": lambda item: item["scope"].update(
                required_checks_complete=True
            ),
            "scope_extra_key": lambda item: item["scope"].update(
                global_qualification_complete=True
            ),
            "covered_scenarios": lambda item: item["scope"][
                "covered_scenarios"
            ].reverse(),
            "order": lambda item: item["package_version_contract"].update(
                candidate_version="4.02.7", candidate_numeric=[4, 2, 7]
            ),
            "platform": lambda item: item["platforms"][0].update(
                candidate_version="4.02.9"
            ),
            "cell_id": lambda item: item["platforms"][0].update(
                cell_id="DEB-U2404"
            ),
            "distribution_version": lambda item: item["platforms"][0].update(
                version="12"
            ),
            "runtime_distribution_version": lambda item: item["platforms"][0][
                "architecture_probe"
            ].update(actual_distribution_version="12"),
            "runtime_distribution_id": lambda item: item["platforms"][0][
                "architecture_probe"
            ].update(actual_distribution="alpine"),
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
                restart_state="restart-one"
            ),
            "exec_rc": lambda item: item["platforms"][0]["scenarios"][0][
                "lifecycle_exec_exit_codes"
            ].__setitem__(0, 92),
            "restart_distinct": lambda item: item["platforms"][0]["scenarios"][
                0
            ]["boots"][1]["restart"].update(distinct=False),
            "restart_contract": lambda item: item["platforms"][0].update(
                restart_contract="operator-defined restart"
            ),
            "capability": lambda item: item["platforms"][0]["scenarios"][0][
                "isolation"
            ]["cap_add"].append("CAP_SYS_MODULE"),
            "container_cleanup_rc": lambda item: item["platforms"][0][
                "scenarios"
            ][0]["cleanup"].update(remove_exit_code=125),
            "image_cleanup_rc": lambda item: item["platforms"][0][
                "bootstrap_image_cleanup"
            ].update(remove_exit_code=125),
            "cron_executable": lambda item: item["platforms"][0]["scenarios"][
                0
            ]["boots"][0]["pre_exec"].update(
                cron_executable_path="/tmp/cron"
            ),
            "cron_fragment_mode": lambda item: item["platforms"][0][
                "scenarios"
            ][0]["boots"][0]["pre_exec"].update(
                cron_fragment_identity="1:2:81ed:0:0|" + "d" * 64
            ),
            "core_process_digest": lambda item: item["platforms"][0][
                "scenarios"
            ][0]["boots"][0]["post_exec"]["product_services"].update(
                core_executable_identity="11:22:81e8:0:0|" + "0" * 64
            ),
            "classification": lambda item: item.update(release_ready=False),
            "cgroup_manager": lambda item: item["engine"].update(
                cgroup_manager="cgroupfs"
            ),
            "helper_digest": lambda item: item["engine"][
                "lifecycle_helper"
            ].update(sha256="0" * 64),
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

    def test_report_rejects_every_capability_boundary_bit_and_schema_mutation(
        self,
    ) -> None:
        baseline = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )

        def security(item: dict[str, object], boundary: str) -> dict[str, object]:
            boot = item["platforms"][0]["scenarios"][0]["boots"][0]
            if boundary == "pid1":
                return boot["pre_exec"]["pid1_process_security"]
            if boundary == "attestation":
                return boot["pre_exec"]["attestation_process_security"]
            if boundary == "lifecycle":
                return boot["lifecycle_exec_security"]
            return boot["post_exec"]["product_services"][
                "core_process_security"
            ]

        capability_fields = (
            "cap_inheritable",
            "cap_permitted",
            "cap_effective",
            "cap_bounding",
            "cap_ambient",
        )
        systemd_present = {
            "cap_permitted",
            "cap_effective",
            "cap_bounding",
        }
        expected_fields = {
            "SYS_ADMIN": {
                "pid1": systemd_present,
                "attestation": set(),
                "lifecycle": set(),
                "core": set(),
            },
            "SYS_PTRACE": {
                "pid1": systemd_present,
                "attestation": systemd_present,
                "lifecycle": systemd_present,
                "core": set(),
            },
        }
        for boundary in ("pid1", "attestation", "lifecycle", "core"):
            for capability, bit in (
                ("SYS_ADMIN", package_lifecycle_lab.SYS_ADMIN_CAPABILITY_BIT),
                ("SYS_PTRACE", package_lifecycle_lab.SYS_PTRACE_CAPABILITY_BIT),
            ):
                for field in capability_fields:
                    with self.subTest(
                        boundary=boundary,
                        capability=capability,
                        field=field,
                    ):
                        adversarial = json.loads(json.dumps(baseline))
                        target = security(adversarial, boundary)
                        target[field] = set_capability_bit(
                            target[field],
                            bit,
                            present=field not in expected_fields[capability][boundary],
                        )
                        with self.assertRaises(
                            package_lifecycle_lab.LifecycleLabError
                        ):
                            package_lifecycle_lab.validate_report_version_contract(
                                adversarial
                            )
            with self.subTest(boundary=boundary, field="no_new_privileges"):
                adversarial = json.loads(json.dumps(baseline))
                security(adversarial, boundary)["no_new_privileges"] = False
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_report_version_contract(
                        adversarial
                    )
        for name, mutate in {
            "missing_process_key": lambda value: value.pop("cap_ambient"),
            "extra_process_key": lambda value: value.update(extra=False),
        }.items():
            with self.subTest(name=name):
                adversarial = json.loads(json.dumps(baseline))
                mutate(security(adversarial, "lifecycle"))
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_report_version_contract(
                        adversarial
                    )

    def test_apk_rejects_every_cross_family_sys_ptrace_boundary(self) -> None:
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.family == "apk" and item.architecture == "amd64"
        )
        baseline = package_lifecycle_lab.run_lab(
            self.args(),
            runner=FakePodmanRunner(),
            platforms=(spec,),
            host_architecture="x86_64",
        )
        platform = baseline["platforms"][0]
        original = platform["scenarios"][0]

        def add_ptrace(mask: str) -> str:
            return set_capability_bit(
                mask,
                package_lifecycle_lab.SYS_PTRACE_CAPABILITY_BIT,
                present=True,
            )

        mutations = {
            "isolation": lambda item: item["isolation"]["cap_add"].append(
                "CAP_SYS_PTRACE"
            ),
            "pid1": lambda item: item["boots"][0]["pre_exec"][
                "pid1_process_security"
            ].__setitem__(
                "cap_effective",
                add_ptrace(
                    item["boots"][0]["pre_exec"]["pid1_process_security"][
                        "cap_effective"
                    ]
                ),
            ),
            "attestation": lambda item: item["boots"][0]["pre_exec"][
                "attestation_process_security"
            ].__setitem__(
                "cap_permitted",
                add_ptrace(
                    item["boots"][0]["pre_exec"][
                        "attestation_process_security"
                    ]["cap_permitted"]
                ),
            ),
            "lifecycle": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__(
                "cap_bounding",
                add_ptrace(
                    item["boots"][0]["lifecycle_exec_security"][
                        "cap_bounding"
                    ]
                ),
            ),
            "core": lambda item: item["boots"][0]["post_exec"][
                "product_services"
            ]["core_process_security"].__setitem__(
                "cap_ambient",
                add_ptrace(
                    item["boots"][0]["post_exec"]["product_services"][
                        "core_process_security"
                    ]["cap_ambient"]
                ),
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                scenario = json.loads(json.dumps(original))
                mutate(scenario)
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_passing_active_scenario_runtime(
                        platform,
                        scenario,
                    )

    def test_report_rejects_isolation_launcher_cap_drop_map_and_setpriv_tampering(
        self,
    ) -> None:
        baseline = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        different_uid = os.geteuid() + 1

        def isolation(item: dict[str, object]) -> dict[str, object]:
            return item["platforms"][0]["scenarios"][0]["isolation"]

        def snapshot(item: dict[str, object]) -> dict[str, object]:
            return item["platforms"][0]["scenarios"][0]["boots"][0][
                "pre_exec"
            ]

        def engine_valid_but_different(item: dict[str, object]) -> None:
            item["engine"]["effective_uid"] = different_uid
            item["engine"]["uid_map"][0]["outside_id"] = different_uid

        def engine_overlapping_map(item: dict[str, object]) -> None:
            item["engine"]["effective_uid"] = 524289
            item["engine"]["uid_map"][0]["outside_id"] = 524289

        def setpriv(item: dict[str, object]) -> dict[str, object]:
            return snapshot(item)["setpriv"]

        mutations = {
            "cap_add_missing_sys_admin": lambda item: isolation(item)[
                "cap_add"
            ].remove("CAP_SYS_ADMIN"),
            "cap_add_missing_sys_ptrace": lambda item: isolation(item)[
                "cap_add"
            ].remove("CAP_SYS_PTRACE"),
            "cap_add_duplicate_sys_ptrace": lambda item: isolation(item)[
                "cap_add"
            ].append("CAP_SYS_PTRACE"),
            "cap_add_extra": lambda item: isolation(item)["cap_add"].append(
                "CAP_SYS_MODULE"
            ),
            "cap_drop_missing": lambda item: isolation(item).pop("cap_drop"),
            "cap_drop_nonempty": lambda item: isolation(item)[
                "cap_drop"
            ].append("CAP_SYS_ADMIN"),
            "launcher_missing_bounding_drop": lambda item: isolation(item)[
                "lifecycle_exec_launcher"
            ].remove("--bounding-set=-sys_admin"),
            "launcher_missing_nnp": lambda item: isolation(item)[
                "lifecycle_exec_launcher"
            ].remove("--no-new-privs"),
            "launcher_extra": lambda item: isolation(item)[
                "lifecycle_exec_launcher"
            ].append("--dump"),
            "explicit_userns": lambda item: isolation(item).update(
                userns_mode="private-explicit"
            ),
            "engine_effective_uid_only": lambda item: item["engine"].update(
                effective_uid=different_uid
            ),
            "engine_only_valid_map": engine_valid_but_different,
            "engine_host_root_map": lambda item: item["engine"]["uid_map"][0].update(
                outside_id=0
            ),
            "engine_overlapping_map": engine_overlapping_map,
            "engine_map_missing_range": lambda item: item["engine"]["uid_map"].pop(),
            "engine_map_extra_range": lambda item: item["engine"]["uid_map"].append(
                {"inside_id": 65537, "outside_id": 700000, "length": 1}
            ),
            "engine_map_extra_key": lambda item: item["engine"]["uid_map"][0].update(
                extra=1
            ),
            "scenario_only_map": lambda item: snapshot(item)["pid1_uid_map"][0].update(
                outside_id=different_uid
            ),
            "scenario_map_host_root": lambda item: snapshot(item)[
                "pid1_gid_map"
            ][0].update(outside_id=0),
            "setpriv_missing": lambda item: snapshot(item).update(setpriv=None),
            "setpriv_path": lambda item: setpriv(item).update(path="/bin/setpriv"),
            "setpriv_owner": lambda item: setpriv(item).update(
                file_identity="10:30:81ed:1000:0"
            ),
            "setpriv_mode": lambda item: setpriv(item).update(
                file_identity="10:30:81a4:0:0"
            ),
            "setpriv_hash": lambda item: setpriv(item).update(sha256="E" * 64),
            "setpriv_package": lambda item: setpriv(item).update(
                package_name="util-linux-core"
            ),
            "setpriv_version": lambda item: setpriv(item).update(
                package_version=""
            ),
            "setpriv_architecture": lambda item: setpriv(item).update(
                package_architecture="unsupported"
            ),
            "setpriv_missing_key": lambda item: setpriv(item).pop("sha256"),
            "setpriv_extra_key": lambda item: setpriv(item).update(extra=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                adversarial = json.loads(json.dumps(baseline))
                mutate(adversarial)
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_report_version_contract(
                        adversarial
                    )

    def test_runtime_boundary_continuity_rejects_valid_but_changed_evidence(
        self,
    ) -> None:
        baseline = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platform_result = baseline["platforms"][0]
        different_uid = os.geteuid() + 1

        def scenario_copy() -> tuple[dict[str, object], dict[str, object]]:
            platform = json.loads(json.dumps(platform_result))
            return platform, platform["scenarios"][0]

        cases = {}

        def post_map(platform: dict[str, object], scenario: dict[str, object]) -> None:
            del platform
            scenario["boots"][0]["post_exec"]["pid1_uid_map"][0][
                "outside_id"
            ] = different_uid

        cases["pre_post_map"] = post_map

        def post_setpriv(
            platform: dict[str, object], scenario: dict[str, object]
        ) -> None:
            del platform
            scenario["boots"][0]["post_exec"]["setpriv"]["sha256"] = "f" * 64

        cases["pre_post_setpriv"] = post_setpriv

        def post_pid1(platform: dict[str, object], scenario: dict[str, object]) -> None:
            del platform
            scenario["boots"][0]["post_exec"]["pid1_process_security"][
                "cap_permitted"
            ] = "00000000802415fa"

        cases["pre_post_pid1"] = post_pid1

        def lifecycle_mismatch(
            platform: dict[str, object], scenario: dict[str, object]
        ) -> None:
            del platform
            scenario["boots"][0]["lifecycle_exec_security"][
                "cap_permitted"
            ] = "00000000800415fa"

        cases["lifecycle_attestation"] = lifecycle_mismatch

        def inter_boot(platform: dict[str, object], scenario: dict[str, object]) -> None:
            del platform
            for phase in ("pre_exec", "post_exec"):
                scenario["boots"][1][phase]["pid1_uid_map"][0][
                    "outside_id"
                ] = different_uid

        cases["inter_boot_map"] = inter_boot

        for name, mutate in cases.items():
            with self.subTest(name=name):
                platform, scenario = scenario_copy()
                mutate(platform, scenario)
                with self.assertRaises(package_lifecycle_lab.LifecycleLabError):
                    package_lifecycle_lab.validate_passing_active_scenario_runtime(
                        platform, scenario
                    )

    def test_aggregate_binds_native_amd64_identity_map(self) -> None:
        amd64 = self.native_shard_report()
        amd64_path = self.root / "map-aggregate-amd64.json"
        amd64_path.write_text(json.dumps(amd64) + "\n", encoding="utf-8")
        aggregate = package_lifecycle_lab.aggregate_native_shard_reports(
            self.aggregate_args(amd64_path)
        )
        records = aggregate["native_shards"]["reports"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["architecture"], "amd64")
        self.assertEqual(records[0]["uid_map"], amd64["engine"]["uid_map"])
        self.assertIsNone(aggregate["engine"]["effective_uid"])
        self.assertIsNone(aggregate["engine"]["uid_map"])

        def shard_only_map(item: dict[str, object]) -> None:
            record = item["native_shards"]["reports"][0]
            different_uid = int(record["effective_uid"]) + 1
            record["effective_uid"] = different_uid
            record["uid_map"][0]["outside_id"] = different_uid

        mutations = {
            "shard_only_map": shard_only_map,
            "shard_missing_map": lambda item: item["native_shards"]["reports"][
                0
            ].pop("uid_map"),
            "shard_extra_map_key": lambda item: item["native_shards"]["reports"][
                0
            ]["uid_map"][0].update(extra=1),
            "aggregate_fabricated_identity": lambda item: item["engine"].update(
                effective_uid=1000,
                effective_gid=1000,
                uid_map=records[0]["uid_map"],
                gid_map=records[0]["gid_map"],
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                adversarial = json.loads(json.dumps(aggregate))
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
                scenario["lifecycle_exec_exit_codes"] = [
                    1
                    for _ in scenario["lifecycle_exec_exit_codes"]
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
            if item["cell_id"] in {"APK-322", "APK-324"}
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
        alpine_remove.update(status="pass", lifecycle_exec_exit_codes=[0])
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
                candidate_version="4.03.2",
                previous_version="4.02.8",
                candidate={
                    "filename": f"syswarden_4.03.2_{architecture}.apk",
                    "version": "4.03.2",
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
            for inventory_scenario in platform_result["scenarios"]:
                for phase in inventory_scenario["inventory_evidence"].values():
                    phase["manager_paths"] = [
                        path
                        for path in phase["manager_paths"]
                        if path != package_lifecycle_lab.BASH_COMPLETION_PATH
                    ]
                    phase["filesystem"] = [
                        entry
                        for entry in phase["filesystem"]
                        if entry["path"]
                        != package_lifecycle_lab.BASH_COMPLETION_PATH
                    ]

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
            and item["architecture_id"] == "amd64"
        )["previous"]["sha256"] = "0" * 64
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(wrong_hash)
        self.assertFalse(rejected["harness_complete"])
        self.assertTrue(rejected["unexpected_failed_checks"])

    def test_historical_ubuntu_deb_recovery_evidence_is_exactly_sealed(self) -> None:
        historical = package_lifecycle_lab.HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS
        platform_result: dict[str, object] = {
            "family": "deb",
            "distribution": "ubuntu",
            "architecture_id": "amd64",
            "package_architecture": "amd64",
            "previous_version": "4.03.2",
            "candidate_version": "4.03.3",
            "previous": {
                "filename": historical["filename"],
                "version": "4.03.2",
                "sha256": historical["sha256"],
            },
            "candidate": {
                "filename": "syswarden_4.03.3_amd64.deb",
                "version": "4.03.3",
                "sha256": "c" * 64,
            },
        }
        detail = package_lifecycle_lab.HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL
        scenario_result: dict[str, object] = {
            "name": "upgrade-rollback",
            "events": [
                {
                    "status": "pass",
                    "check": "upgrade-rollback.rollback.previous",
                    "detail": detail,
                },
                {
                    "status": "pass",
                    "check": "upgrade-rollback.rollback.previous.maintainer_script",
                    "detail": "maintainer script emitted no Go panic or fatal runtime diagnostic",
                },
                {
                    "status": "pass",
                    "check": "upgrade-rollback.recovery.candidate",
                    "detail": "command completed",
                },
                {
                    "status": "pass",
                    "check": "upgrade-rollback.recovery.candidate.maintainer_script",
                    "detail": "maintainer script emitted no Go panic or fatal runtime diagnostic",
                },
            ],
        }
        self.assertEqual(
            package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_events(
                platform_result, scenario_result
            ),
            [],
        )

        normal = json.loads(json.dumps(scenario_result))
        normal["events"][0]["detail"] = "command completed"
        self.assertEqual(
            package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_events(
                platform_result, normal
            ),
            [],
        )

        mutations = {
            "wrong-hash": (
                lambda platform, scenario: platform["previous"].update(
                    sha256="0" * 64
                )
            ),
            "wrong-distribution": (
                lambda platform, scenario: platform.update(distribution="debian")
            ),
            "missing-candidate-recovery": (
                lambda platform, scenario: scenario["events"][2].update(
                    detail="candidate recovery skipped"
                )
            ),
            "arbitrary-rollback-detail": (
                lambda platform, scenario: scenario["events"][0].update(
                    detail="recovery accepted"
                )
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed_platform = json.loads(json.dumps(platform_result))
                changed_scenario = json.loads(json.dumps(scenario_result))
                mutate(changed_platform, changed_scenario)
                self.assertTrue(
                    package_lifecycle_lab.validate_historical_ubuntu_deb_recovery_events(
                        changed_platform, changed_scenario
                    )
                )

        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        rollback = next(
            event
            for platform in platforms
            if platform["distribution"] == "ubuntu"
            for scenario in platform["scenarios"]
            if scenario["name"] == "upgrade-rollback"
            for event in scenario["events"]
            if event["check"] == "upgrade-rollback.rollback.previous"
        )
        rollback["detail"] = detail
        rejected = package_lifecycle_lab.classify_lifecycle_evidence(platforms)
        self.assertFalse(rejected["harness_complete"])
        self.assertTrue(
            any(
                "historical-ubuntu-deb-recovery-binding-not-exact" in failure
                for failure in rejected["unexpected_failed_checks"]
            )
        )

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
                scenario["lifecycle_exec_exit_codes"] = [
                    1 for _ in scenario["lifecycle_exec_exit_codes"]
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

    def test_exact_amd64_failures_stay_canonical(self) -> None:
        report = package_lifecycle_lab.run_lab(
            self.args(), runner=FakePodmanRunner()
        )
        platforms = json.loads(json.dumps(report["platforms"]))
        config_detail = (
            "package manager returned success after maintainer script emitted a Go panic"
        )
        for platform_result in platforms:
            platform_result["status"] = "fail"
            for scenario in platform_result["scenarios"]:
                scenario["status"] = "fail"
                scenario["lifecycle_exec_exit_codes"] = [
                    1 for _ in scenario["lifecycle_exec_exit_codes"]
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
            f"DEB-U2404/amd64:{drifted['check']}",
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
        self.assertIn("remove.final-removal.generated.runtime_socket", checks)
        self.assertIn("remove.final-removal.generated.runtime_lock", checks)
        self.assertIn(
            "remove.final-removal.generated.rsyslog_antiforging_exact_removed",
            checks,
        )
        self.assertIn(
            "remove.final-removal.generated.rsyslog_selinux_provenance_removed",
            checks,
        )
        self.assertIn("remove.final-removal.generated.completion_residual", checks)
        self.assertIn("remove.final-removal.generated.cron_d_owned", checks)
        self.assertIn("remove.final-removal.generated.cron_d_pending", checks)
        self.assertIn("remove.final-removal.generated.root_crontab_bytes", checks)
        self.assertIn(
            "remove.final-removal.generated.root_crontab_legacy_residual", checks
        )
        for key in ("opt_root", "config_root", "data_root", "log_root"):
            self.assertIn(f"remove.final-removal.state.{key}", checks)
        self.assertFalse(
            any(
                check.startswith(
                    "remove.final-removal.state.operator_data."
                )
                for check in checks
            )
        )
        self.assertFalse(
            any(
                check.startswith("remove.final-removal.state.telemetry.")
                for check in checks
            )
        )
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
        self.assertIn("assert_generated_runtime_artifact_contract", script)
        self.assertIn("/etc/systemd/system/syswarden-firewall.service", script)

    def test_deb_remove_qualifies_reinstall_then_deferred_purge(self) -> None:
        checks = package_lifecycle_lab.expected_event_checks("deb", "remove")
        ordered = (
            "remove.install.candidate",
            "remove.remove",
            "remove.remove.state.deferred_purge_marker.hash",
            "remove.reinstall-after-remove.candidate",
            "remove.reinstall-after-remove.state.deferred_purge_marker",
            "remove.remove-before-purge",
            "remove.remove-before-purge.state.deferred_purge_marker.hash",
            "remove.purge-after-remove",
            "remove.purge-after-remove.state.opt_root",
            "remove.purge-after-remove.state.config_root",
            "remove.purge-after-remove.state.data_root",
            "remove.purge-after-remove.state.log_root",
        )
        positions = [checks.index(check) for check in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(
            package_lifecycle_lab.expected_inventory_phase_labels("remove"),
            ("fresh",),
        )

        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("scenario_remove() {")
        end = source.index("\nscenario_purge() {", start)
        scenario = source[start:end]
        sequence = (
            'run_step remove remove_package',
            'run_install_step reinstall-after-remove.candidate',
            'run_step remove-before-purge remove_package',
            'run_step purge-after-remove purge_package',
        )
        sequence_positions = [scenario.index(fragment) for fragment in sequence]
        self.assertEqual(sequence_positions, sorted(sequence_positions))
        self.assertIn("assert_all_state_preserved remove", scenario)
        self.assertIn("assert_deb_removal_log_preserved remove", scenario)
        self.assertIn("assert_deferred_purge_marker remove", scenario)
        self.assertIn(
            "reinstall-after-remove.state.deferred_purge_marker", scenario
        )
        self.assertIn(
            "assert_dedicated_roots_absent purge-after-remove", scenario
        )
        self.assertIn(
            'probe_payload reinstall-after-remove candidate "${CANDIDATE_VERSION}" 0',
            scenario,
        )

        marker = b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
        self.assertEqual(len(marker), 39)
        self.assertIn(hashlib.sha256(marker).hexdigest(), source)
        roots_start = source.index("assert_dedicated_roots_absent() {")
        roots_end = source.index("\n}\n\nassert_package_absent() {", roots_start)
        roots = source[roots_start:roots_end]
        for path in (
            "/opt/syswarden",
            "/etc/syswarden",
            "/var/lib/syswarden",
            "/var/log/syswarden",
        ):
            self.assertIn(path, roots)

        direct_purge = package_lifecycle_lab.expected_event_checks("deb", "purge")
        for key in ("opt_root", "config_root", "data_root", "log_root"):
            self.assertIn(f"purge.purge.state.{key}", direct_purge)

    def test_owned_cron_seed_state_exception_is_exact_and_fail_closed(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("attest_owned_cron_seed_state() {")
        end = source.index("\n}\n\nseed_generated_runtime_artifacts() {", start)
        function = source[start : end + 2]
        self.assertIn("deb:remove:remove-before-purge)", function)
        self.assertEqual(function.count("deb:remove:remove-before-purge)"), 1)
        self.assertIn('[ ! -e "${syswarden_owned_cron_path}" ]', function)
        self.assertIn('[ ! -L "${syswarden_owned_cron_path}" ]', function)
        self.assertIn('[ -f "${syswarden_owned_cron_path}" ]', function)

        harness = (
            function
            + '\nattest_owned_cron_seed_state "${TEST_CRON_PATH}" "${TEST_LABEL}"\n'
        )
        cases = (
            ("first-regular", "deb", "remove", "remove", "regular", 0),
            ("first-absent", "deb", "remove", "remove", "absent", 1),
            ("first-directory", "deb", "remove", "remove", "directory", 1),
            ("first-symlink", "deb", "remove", "remove", "symlink", 1),
            (
                "second-absent",
                "deb",
                "remove",
                "remove-before-purge",
                "absent",
                0,
            ),
            (
                "second-regular",
                "deb",
                "remove",
                "remove-before-purge",
                "regular",
                1,
            ),
            (
                "second-directory",
                "deb",
                "remove",
                "remove-before-purge",
                "directory",
                1,
            ),
            (
                "second-symlink",
                "deb",
                "remove",
                "remove-before-purge",
                "symlink",
                1,
            ),
            (
                "second-broken-symlink",
                "deb",
                "remove",
                "remove-before-purge",
                "broken-symlink",
                1,
            ),
            (
                "wrong-family",
                "rpm",
                "remove",
                "remove-before-purge",
                "absent",
                1,
            ),
            (
                "wrong-scenario",
                "deb",
                "purge",
                "remove-before-purge",
                "absent",
                1,
            ),
            (
                "wrong-label",
                "deb",
                "remove",
                "other",
                "absent",
                1,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "syswarden"
            symlink_target = root / "operator-cron"
            symlink_target.write_text("operator\n", encoding="ascii")
            for label, family, scenario, evidence, path_kind, expected in cases:
                with self.subTest(case=label):
                    if target.is_symlink() or target.is_file():
                        target.unlink()
                    elif target.is_dir():
                        target.rmdir()
                    if path_kind == "regular":
                        target.write_text("managed\n", encoding="ascii")
                    elif path_kind == "directory":
                        target.mkdir()
                    elif path_kind == "symlink":
                        target.symlink_to(symlink_target)
                    elif path_kind == "broken-symlink":
                        target.symlink_to(root / "missing-operator-cron")
                    elif path_kind != "absent":
                        self.fail(f"unsupported path fixture: {path_kind}")
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "PACKAGE_FAMILY": family,
                            "SCENARIO": scenario,
                            "TEST_CRON_PATH": str(target),
                            "TEST_LABEL": evidence,
                        }
                    )
                    result = subprocess.run(
                        ["/bin/sh", "-eu", "-c", harness],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)

        seed_start = source.index("seed_generated_runtime_artifacts() {")
        seed_end = source.index(
            "\n}\n\nassert_generated_runtime_artifact_contract() {", seed_start
        )
        seed = source[seed_start:seed_end]
        self.assertEqual(seed.count("attest_owned_cron_seed_state \\"), 1)
        self.assertIn('/etc/cron.d/syswarden "${evidence_label}"', seed)
        pending = "printf '%s' '# Managed by' > /etc/cron.d/.syswarden.pending-v1"
        root_crontab_attestation = (
            "cmp -s /tmp/syswarden-root-cron-before "
            "/tmp/syswarden-root-cron-confirmed"
        )
        cron_seed_attestation = "attest_owned_cron_seed_state \\"
        self.assertIn(pending, seed)
        self.assertIn(root_crontab_attestation, seed)
        self.assertLess(
            seed.index(root_crontab_attestation),
            seed.index(cron_seed_attestation),
        )
        self.assertLess(seed.index(cron_seed_attestation), seed.index(pending))

    def test_rpm_and_apk_final_removal_require_dedicated_roots_absent(self) -> None:
        for family, scenario, label in (
            ("rpm", "remove", "final-removal"),
            ("apk", "remove", "remove"),
            ("apk", "purge", "purge"),
        ):
            with self.subTest(family=family, scenario=scenario):
                checks = package_lifecycle_lab.expected_event_checks(
                    family, scenario
                )
                for key in ("opt_root", "config_root", "data_root", "log_root"):
                    self.assertIn(
                        f"{scenario}.{label}.state.{key}", checks
                    )
                self.assertFalse(
                    any(
                        check.startswith(
                            f"{scenario}.{label}.state.operator_data."
                        )
                        for check in checks
                    )
                )
                self.assertFalse(
                    any(
                        check.startswith(
                            f"{scenario}.{label}.state.telemetry."
                        )
                        for check in checks
                    )
                )

        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        remove_start = source.index("scenario_remove() {")
        remove_end = source.index("\nscenario_purge() {", remove_start)
        remove = source[remove_start:remove_end]
        self.assertGreaterEqual(
            remove.count("assert_dedicated_roots_absent"), 3
        )
        purge = source[remove_end:]
        self.assertGreaterEqual(
            purge.count("assert_dedicated_roots_absent"), 2
        )

    def test_exact_generated_rsyslog_cleanup_is_separate_from_ambiguity(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        seed_start = source.index("seed_generated_runtime_artifacts() {")
        seed_end = source.index(
            "\n}\n\nassert_generated_runtime_artifact_contract() {",
            seed_start,
        )
        seed = source[seed_start:seed_end]
        exact_start = seed.index("exact-rsyslog)")
        ambiguous_start = seed.index("ambiguous-rsyslog)", exact_start)
        exact = seed[exact_start:ambiguous_start]
        ambiguous = seed[ambiguous_start:]
        for path in (
            "/etc/rsyslog.d/99-syswarden-siem.conf",
            "/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
        ):
            self.assertIn(path, exact)
            self.assertNotIn(f"> {path}", exact)
            self.assertRegex(
                ambiguous,
                rf"> \\\n\s+{re.escape(path)}",
            )
        self.assertIn(".syswarden-rsyslog-provenance-v1", exact)
        self.assertIn("syswarden-rsyslog-provenance-v1", exact)
        self.assertIn("*.* @127.0.0.1:5514", exact)
        forbidden_start = exact.index("for forbidden_fragment in")
        forbidden_end = exact.index("\n            done", forbidden_start)
        forbidden = exact[forbidden_start:forbidden_end]
        for fragment in (
            "'imfile'",
            "'/var/log/syswarden/waf.json'",
            "'syswarden-waf-json'",
            "'Facility=\"local7\"'",
        ):
            self.assertIn(fragment, forbidden)
        self.assertIn("99-syswarden-siem.conf", forbidden)
        self.assertNotIn("99-syswarden-waf-bridge.conf", forbidden)
        self.assertIn("waf_telemetry_input_block", exact)
        telemetry_start = exact.index("for telemetry_fragment in")
        telemetry_end = exact.index("\n            done", telemetry_start)
        telemetry = exact[telemetry_start:telemetry_end]
        self.assertIn("waf_telemetry_input_block", telemetry)
        for fragment in (
            'File="/var/log/syswarden/waf.json"',
            'Tag="syswarden-waf-json"',
            'Facility="local7"',
        ):
            self.assertIn(fragment, telemetry)
        module_count_start = exact.index(
            "grep -F -x -c 'module(load=\"imfile\")'"
        )
        module_count_end = exact.index("|| return 1", module_count_start)
        self.assertIn(
            "99-syswarden-waf-bridge.conf",
            exact[module_count_start:module_count_end],
        )
        telemetry_input_start = exact.index(
            "grep -F -x -c 'input(type=\"imfile\"'"
        )
        telemetry_input_end = exact.index("|| return 1", telemetry_input_start)
        self.assertIn(
            "99-syswarden-waf-bridge.conf",
            exact[telemetry_input_start:telemetry_input_end],
        )
        ruleset_guard_start = exact.index(
            "! printf '%s\\n' \"${waf_telemetry_input_block}\""
        )
        ruleset_guard_end = exact.index("|| return 1", ruleset_guard_start)
        self.assertIn(
            'ruleset="waf_bridge"',
            exact[ruleset_guard_start:ruleset_guard_end],
        )
        self.assertIn('module(load="omuxsock")', exact)
        self.assertIn("$OMUxSockSocket /var/run/syswarden.sock", exact)
        self.assertIn('/var/log/nginx/*.log', exact)
        self.assertIn('/var/log/auth.log', exact)
        self.assertIn("*.* :omuxsock:;SYSWARDENRaw", exact)
        self.assertIn("/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf", exact)
        self.assertIn("operator-owned ambiguous SIEM bridge", ambiguous)
        self.assertIn("operator-owned ambiguous WAF bridge", ambiguous)

        assertion_start = source.index(
            "assert_generated_runtime_artifact_contract() {"
        )
        assertion_end = source.index(
            "\n}\n\nprepare_expected_payloads() {", assertion_start
        )
        assertion = source[assertion_start:assertion_end]
        exact_assertion_start = assertion.index("exact-rsyslog)")
        ambiguous_assertion_start = assertion.index(
            "ambiguous-rsyslog)", exact_assertion_start
        )
        exact_assertion = assertion[
            exact_assertion_start:ambiguous_assertion_start
        ]
        ambiguous_assertion = assertion[ambiguous_assertion_start:]
        self.assertIn("/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf", assertion)
        self.assertIn("-p ExecReload --value", assertion)
        self.assertNotIn("ReloadResult", source)
        self.assertIn("-p ActiveEnterTimestampMonotonic --value", source)
        self.assertIn("rsyslog_reactivation_mode", exact_assertion)
        self.assertIn("rsyslog_siem_exact_removed", assertion)
        self.assertIn("rsyslog_waf_bridge_exact_removed", assertion)
        self.assertIn("rsyslog_siem_residual", assertion)
        self.assertIn("rsyslog_waf_bridge_residual", assertion)
        self.assertIn("rsyslog_provenance_removed", exact_assertion)
        self.assertNotIn("rsyslog_provenance_residual", exact_assertion)
        self.assertIn("rsyslog_provenance_residual", ambiguous_assertion)
        self.assertNotIn("rsyslog_provenance_removed", ambiguous_assertion)

        remove_checks = package_lifecycle_lab.expected_event_checks(
            "deb", "remove"
        )
        for label in ("remove", "remove-before-purge"):
            for key in (
                "rsyslog_siem_exact_generated",
                "rsyslog_waf_bridge_exact_generated",
                "rsyslog_provenance_exact",
            ):
                self.assertIn(
                    f"remove.{label}.generated.{key}", remove_checks
                )
            for key in (
                "rsyslog_siem_exact_removed",
                "rsyslog_waf_bridge_exact_removed",
                "rsyslog_provenance_removed",
                "rsyslog_configuration_valid",
                "rsyslog_reactivated",
            ):
                self.assertIn(
                    f"remove.{label}.generated.{key}", remove_checks
                )
        purge_checks = package_lifecycle_lab.expected_event_checks("deb", "purge")
        self.assertIn("purge.purge.generated.rsyslog_siem_residual", purge_checks)
        self.assertIn(
            "purge.purge.generated.rsyslog_waf_bridge_residual", purge_checks
        )
        self.assertIn(
            "purge.purge.generated.rsyslog_provenance_residual", purge_checks
        )
        self.assertIn(
            "/tmp/syswarden-rsyslog-provenance-before", ambiguous
        )
        self.assertIn(
            "/tmp/syswarden-rsyslog-provenance-before",
            ambiguous_assertion,
        )

        writer_start = source.index("write_seeded_operator_token() {")
        writer_end = source.index("\nseed_state() {", writer_start)
        writer = source[writer_start:writer_end]
        token = self.root / "deb-removal-token.toml"
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                writer
                + '\nPACKAGE_FAMILY=deb; SCENARIO=remove; '
                + 'write_seeded_operator_token "$1"',
                "deb-removal-token",
                str(token),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = token.read_text(encoding="utf-8")
        self.assertIn("[integrations.siem]", rendered)
        self.assertIn("enabled = true", rendered)
        self.assertIn('ip = "127.0.0.1"', rendered)
        self.assertIn('port = "5514"', rendered)
        self.assertIn('protocol = "udp"', rendered)

    def test_rsyslog_reactivation_proof_is_systemd_255_257_compatible(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        helpers_start = source.index("rsyslog_exec_reload_succeeded() {")
        helpers_end = source.index(
            "\nseed_generated_runtime_artifacts() {", helpers_start
        )
        helpers = source[helpers_start:helpers_end]
        self.assertNotIn("ReloadResult", helpers)
        self.assertIn("code=exited", helpers)
        self.assertIn("status=0", helpers)
        self.assertIn("start_time=[n/a]", helpers)
        self.assertIn("stop_time=[n/a]", helpers)

        def reload_record(
            pid: int,
            *,
            start: str = "Tue 2026-08-25 12:00:00 UTC",
            stop: str = "Tue 2026-08-25 12:00:01 UTC",
            code: str = "exited",
            status: str = "0/SUCCESS",
        ) -> str:
            return (
                "{ path=/bin/kill ; argv[]=/bin/kill -HUP 4242 ; "
                "ignore_errors=no ; "
                f"start_time=[{start}] ; stop_time=[{stop}] ; "
                f"pid={pid} ; code={code} ; status={status} }}"
            )

        def run_success_predicate(value: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    helpers + '\nrsyslog_exec_reload_succeeded "$1"',
                    "rsyslog-exec-reload",
                    value,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        successful_records = (
            reload_record(500),
            reload_record(501, status="0"),
            reload_record(502) + "\n" + reload_record(503),
        )
        for value in successful_records:
            with self.subTest(success=value):
                result = run_success_predicate(value)
                self.assertEqual(result.returncode, 0, result.stderr)

        adversarial_records = {
            "empty": "",
            "whitespace": " ",
            "start-not-run": reload_record(500, start="n/a"),
            "stop-not-run": reload_record(500, stop="n/a"),
            "pid-zero": reload_record(0),
            "pid-one": reload_record(1),
            "wrong-code": reload_record(500, code="killed"),
            "failed-status": reload_record(500, status="1/FAILURE"),
            "missing-open": reload_record(500)[1:],
            "suffix": reload_record(500) + " forged",
            "missing-argv": reload_record(500).replace(
                "argv[]=/bin/kill -HUP 4242 ; ", ""
            ),
            "mixed-records": reload_record(500) + "\nforged",
        }
        for name, value in adversarial_records.items():
            with self.subTest(adversarial=name):
                self.assertNotEqual(
                    run_success_predicate(value).returncode,
                    0,
                )

        old_reload = reload_record(500)
        new_reload = reload_record(
            501,
            start="Tue 2026-08-25 12:01:00 UTC",
            stop="Tue 2026-08-25 12:01:01 UTC",
        )
        failed_reload = reload_record(
            502,
            start="Tue 2026-08-25 12:02:00 UTC",
            stop="Tue 2026-08-25 12:02:01 UTC",
            status="1/FAILURE",
        )

        def run_mode(
            before: str,
            after: str,
            pid_before: str,
            pid_after: str,
            active_before: str,
            active_after: str,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    helpers
                    + '\nrsyslog_reactivation_mode "$1" "$2" "$3" '
                    + '"$4" "$5" "$6"',
                    "rsyslog-reactivation",
                    before,
                    after,
                    pid_before,
                    pid_after,
                    active_before,
                    active_after,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        accepted_modes = (
            (old_reload, new_reload, "100", "100", "1000", "1000", "reload"),
            ("", "", "100", "101", "1000", "1001", "restart"),
            (
                old_reload,
                failed_reload,
                "100",
                "101",
                "1000",
                "1001",
                "restart",
            ),
        )
        for before, after, pid_before, pid_after, active_before, active_after, mode in accepted_modes:
            with self.subTest(accepted_mode=mode, after=after):
                result = run_mode(
                    before,
                    after,
                    pid_before,
                    pid_after,
                    active_before,
                    active_after,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, mode + "\n")

        rejected_modes = (
            ("", "", "100", "100", "1000", "1000"),
            (old_reload, old_reload, "100", "100", "1000", "1000"),
            (old_reload, "forged", "100", "100", "1000", "1000"),
            (old_reload, new_reload, "100", "101", "1000", "1000"),
            ("", "", "100", "101", "1000", "999"),
            ("", "", "invalid", "101", "1000", "1001"),
            ("", "", "100", "101", "", "1001"),
        )
        for case in rejected_modes:
            with self.subTest(rejected_mode=case):
                self.assertNotEqual(run_mode(*case).returncode, 0)

    def test_completion_is_package_owned_and_legacy_path_is_only_ambiguous(self) -> None:
        completion = package_lifecycle_lab.BASH_COMPLETION_PATH
        legacy_completion = package_lifecycle_lab.LEGACY_BASH_COMPLETION_PATH
        self.assertIn(completion, package_lifecycle_lab.PACKAGE_PAYLOAD_PATHS)
        self.assertNotIn(
            completion, package_lifecycle_lab.LEGACY_PACKAGE_PAYLOAD_PATHS
        )
        self.assertIn(completion, package_lifecycle_lab.DEB_PACKAGE_PATHS)
        self.assertNotIn(
            completion, package_lifecycle_lab.LEGACY_DEB_PACKAGE_PATHS
        )
        self.assertIn(completion, package_lifecycle_lab.APK_PACKAGE_PATHS)
        self.assertNotIn(
            completion, package_lifecycle_lab.LEGACY_APK_PACKAGE_PATHS
        )

        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        postinstall_start = source.index("probe_postinstall_contract() {")
        postinstall_end = source.index(
            "\n}\n\nverify_installed_inventory() {", postinstall_start
        )
        postinstall = source[postinstall_start:postinstall_end]
        self.assertIn(completion, postinstall)
        self.assertIn("0:0:644:1", postinstall)
        self.assertIn("legacy_bash_completion_is_exact", postinstall)
        self.assertIn(legacy_completion, source)
        self.assertIn(
            package_lifecycle_lab.LEGACY_BASH_COMPLETION_SHA256,
            source,
        )
        self.assertIn("0:0:644:1:16339", source)
        self.assertIn("completion-legacy-residual", postinstall)
        self.assertIn("completion-package-owned-residual", postinstall)

        seed_start = source.index("seed_generated_runtime_artifacts() {")
        seed_end = source.index(
            "\n}\n\nassert_generated_runtime_artifact_contract() {",
            seed_start,
        )
        seed = source[seed_start:seed_end]
        self.assertIn("/etc/bash_completion.d/syswarden", seed)
        self.assertIn("operator-owned ambiguous SysWarden completion", seed)

        manifest_start = source.index("validate_manifest_contract() {")
        manifest_end = source.index(
            "\n}\n\ninventory_has_exact_entry() {", manifest_start
        )
        manifest_contract = source[manifest_start:manifest_end]
        self.assertIn(completion, manifest_contract)
        self.assertIn("package_uses_legacy_completion_payload", manifest_contract)
        inventory_start = source.index("validate_inventory_contract() {")
        inventory_end = source.index(
            "\n}\n\nverify_package_artifact() {", inventory_start
        )
        inventory_contract = source[inventory_start:inventory_end]
        self.assertIn(completion, inventory_contract)
        self.assertIn("file 644", inventory_contract)

    def test_completion_manifest_exception_is_bound_to_previous_v4032(self) -> None:
        current_by_family = {
            "deb": sorted(package_lifecycle_lab.DEB_PACKAGE_PATHS),
            "apk": sorted(package_lifecycle_lab.APK_PACKAGE_PATHS),
        }
        legacy_by_family = {
            "deb": sorted(package_lifecycle_lab.LEGACY_DEB_PACKAGE_PATHS),
            "apk": sorted(package_lifecycle_lab.LEGACY_APK_PACKAGE_PATHS),
        }
        rpm_build_ids = {
            "/usr/lib/.build-id",
            "/usr/lib/.build-id/11",
            "/usr/lib/.build-id/11/" + "1" * 38,
            "/usr/lib/.build-id/22",
            "/usr/lib/.build-id/22/" + "2" * 38,
            "/usr/lib/.build-id/33",
            "/usr/lib/.build-id/33/" + "3" * 38,
        }
        current_by_family["rpm"] = sorted(
            set(package_lifecycle_lab.PACKAGE_PAYLOAD_PATHS) | rpm_build_ids
        )
        legacy_by_family["rpm"] = sorted(
            set(package_lifecycle_lab.LEGACY_PACKAGE_PAYLOAD_PATHS)
            | rpm_build_ids
        )

        for family in ("deb", "rpm", "apk"):
            with self.subTest(family=family):
                legacy = legacy_by_family[family]
                current = current_by_family[family]
                accepted_previous = self.run_embedded_inventory_contract(
                    family,
                    legacy,
                    role="previous",
                    version="4.03.2",
                    candidate_version="4.03.3",
                )
                self.assertEqual(
                    accepted_previous.returncode,
                    0,
                    accepted_previous.stderr,
                )
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        current,
                        role="previous",
                        version="4.03.2",
                        candidate_version="4.03.3",
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        legacy,
                        role="candidate",
                        version="4.03.3",
                        candidate_version="4.03.3",
                    ).returncode,
                    0,
                )
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        family,
                        legacy,
                        role="previous",
                        version="4.03.1",
                        candidate_version="4.03.3",
                    ).returncode,
                    0,
                )

                package_lifecycle_lab._validate_manager_paths(
                    family,
                    legacy,
                    role="previous",
                    version="4.03.2",
                    candidate_version="4.03.3",
                )
                for role, version, paths in (
                    ("previous", "4.03.2", current),
                    ("candidate", "4.03.3", legacy),
                    ("previous", "4.03.1", legacy),
                ):
                    with self.assertRaises(
                        package_lifecycle_lab.LifecycleLabError
                    ):
                        package_lifecycle_lab._validate_manager_paths(
                            family,
                            paths,
                            role=role,
                            version=version,
                            candidate_version="4.03.3",
                        )

        legacy_apk = sorted(package_lifecycle_lab.LEGACY_APK_PACKAGE_PATHS)
        current_apk = sorted(package_lifecycle_lab.APK_PACKAGE_PATHS)
        for role, version in (
            ("previous", "4.02.8"),
            ("candidate", "4.03.2"),
        ):
            with self.subTest(forward_only_apk_role=role):
                accepted = self.run_embedded_inventory_contract(
                    "apk",
                    legacy_apk,
                    role=role,
                    version=version,
                    candidate_version="4.03.2",
                    forward_only_apk=True,
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertNotEqual(
                    self.run_embedded_inventory_contract(
                        "apk",
                        current_apk,
                        role=role,
                        version=version,
                        candidate_version="4.03.2",
                        forward_only_apk=True,
                    ).returncode,
                    0,
                )
                package_lifecycle_lab._validate_manager_paths(
                    "apk",
                    legacy_apk,
                    role=role,
                    version=version,
                    candidate_version="4.03.2",
                    forward_only_apk=True,
                )

    def test_systemd_enablement_target_depends_on_scenario_provenance(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("v4028_to_v4032_transition_selected() {")
        end = source.index("\nprobe_postinstall_contract() {", start)
        functions = source[start:end]
        command = (
            functions
            + '\nSCENARIO="$1"; EXPECTED_PREVIOUS_VERSION="$2"; '
            'EXPECTED_CANDIDATE_VERSION="$3"; '
            'expected_systemd_enablement_prefix "$4"'
        )
        upgrade_labels = (
            "previous",
            "candidate",
            "reinstall",
            "restart-one",
            "restart-two",
            "rollback",
            "recovery",
        )
        cases = [
            *(
                ("upgrade-rollback", "4.02.8", "4.03.2", label, "/etc/systemd/system")
                for label in upgrade_labels
            ),
            *(
                ("upgrade-rollback", "4.03.2", "4.03.3", label, "..")
                for label in upgrade_labels
            ),
            ("remove", "4.03.2", "4.03.3", "fresh", ".."),
            (
                "remove",
                "4.03.2",
                "4.03.3",
                "reinstall-after-remove",
                "..",
            ),
            ("purge", "4.03.2", "4.03.3", "fresh", ".."),
        ]
        for scenario, previous, candidate, label, expected in cases:
            with self.subTest(
                scenario=scenario,
                previous=previous,
                candidate=candidate,
                label=label,
            ):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                        "probe",
                        scenario,
                        previous,
                        candidate,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout.strip(), expected)

        rejected = (
            ("upgrade-rollback", "4.03.1", "4.03.3", "previous"),
            ("upgrade-rollback", "4.03.2", "4.03.4", "candidate"),
            ("upgrade-rollback", "4.02.8", "4.03.3", "rollback"),
            ("upgrade-rollback", "4.03.2", "4.03.3", "unknown"),
            ("remove", "4.03.2", "4.03.3", "candidate"),
        )
        for scenario, previous, candidate, label in rejected:
            with self.subTest(
                rejected_scenario=scenario,
                previous=previous,
                candidate=candidate,
                label=label,
            ):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                        "probe",
                        scenario,
                        previous,
                        candidate,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)

    def test_cleanup_shell_events_match_declared_contract_exactly(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = script.index("assert_generated_runtime_artifact_contract() {")
        end = script.index("\nprepare_expected_payloads() {", start)
        emitted = list(
            dict.fromkeys(
                re.findall(r"\$\{label\}\.([a-z0-9_.-]+)", script[start:end])
            )
        )
        declared = {
            "service_manager_calls",
            *(
                check.removeprefix("remove.remove.")
                for check in package_lifecycle_lab._generated_cleanup_event_checks(
                    "remove", "remove", exact_rsyslog=True
                )
            ),
            *(
                check.removeprefix("remove.remove.")
                for check in package_lifecycle_lab._generated_cleanup_event_checks(
                    "remove", "remove"
                )
            ),
        }
        self.assertEqual(set(emitted), declared)

    def test_package_lab_enforces_active_init_and_alpine_crond_provider(self) -> None:
        script = package_lifecycle_lab.LIFECYCLE_SCRIPT
        self.assertNotIn("install_service_manager_sentinels", script)
        self.assertIn("prepare_service_runtime_fixture", script)
        self.assertIn("attest_alpine_crond_provider", script)
        self.assertIn("apk info --installed cronie", script)
        self.assertIn("apk info --installed cronie-openrc", script)
        self.assertIn("bash-completion cronie cronie-openrc curl", script)
        self.assertIn("apk info --who-owns", script)
        self.assertIn(
            'syswarden_crond_target="$(readlink -f "${syswarden_crond_path}")"',
            script,
        )
        self.assertIn('[ "${syswarden_crond_target##*/}" = crond ]', script)
        self.assertIn(
            'alpine_apk_owner_version "${syswarden_crond_target}" cronie',
            script,
        )
        self.assertIn(
            "alpine_apk_owner_version /etc/init.d/cronie cronie-openrc", script
        )
        self.assertIn(
            '[ "${syswarden_crond_version}" = "${syswarden_init_version}" ]',
            script,
        )
        self.assertIn("validate_alpine_cronie_runlevels required", script)
        self.assertIn('"openrc_service=cronie"', script)
        self.assertIn("NF != 3 || $2 != \"|\" || $3 != \"default\"", script)
        self.assertIn(
            '[ "${syswarden_provider_first}" = "${syswarden_provider_second}" ]',
            script,
        )
        self.assertNotIn("rc-update add cronie default", script)
        self.assertNotIn("rc-service cronie start", script)
        self.assertIn("rc-service cronie status", script)
        self.assertNotIn("/tmp/syswarden-service-manager-calls", script)
        self.assertNotIn("/tmp/syswarden-manager-original-path", script)
        self.assertIn(
            'record fail "${PREFIX}.${label}.service_manager_calls"', script
        )
        removal_start = script.index("assert_generated_runtime_artifact_contract() {")
        removal_assertion = script[
            removal_start : script.index(
                "\nprepare_expected_payloads() {", removal_start
            )
        ]
        self.assertIn("prepare_service_runtime_fixture", removal_assertion)
        self.assertNotIn("rc-update add", removal_assertion)
        self.assertNotIn("rc-service cronie start", removal_assertion)
        self.assertIn(
            "scenario_upgrade_rollback_restart_one() {\n"
            "    load_state_contract || return\n"
            "    prepare_service_runtime_fixture || return",
            script,
        )
        self.assertIn(
            "scenario_upgrade_rollback_restart_two() {\n"
            "    load_state_contract || return\n"
            "    prepare_service_runtime_fixture || return",
            script,
        )
        for command in ("systemctl", "rc-service", "rc-update", "service"):
            self.assertIn(command, script)
        self.assertIn(
            'syswarden_classify_service_manager / "${syswarden_runtime_manager}"',
            script,
        )
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
        seed = script[
            script.index("seed_generated_runtime_artifacts() {") : script.index(
                "\n}\n\nassert_generated_runtime_artifact_contract() {"
            )
        ]
        canonical = (
            "17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds "
            ">/dev/null 2>&1"
        )
        self.assertEqual(seed.count(canonical), 1)
        for preserved in (
            "# operator note mentioning syswarden-cli",
            "23 * * * * /srv/operator/bin/syswarden-cli update-feeds "
            ">/dev/null 2>&1",
            "printf ' \\t \\n'",
        ):
            with self.subTest(preserved=preserved):
                self.assertIn(preserved, seed)
        for noncanonical_lookalike in (
            "19 4 * * * /opt/syswarden/bin/syswarden-cli update-feeds "
            "--operator-option",
            " */30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1",
            "printf '%s \\n' " + repr(canonical),
            "17  * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1",
            "*/30\\t* * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1",
        ):
            with self.subTest(noncanonical_lookalike=noncanonical_lookalike):
                self.assertNotIn(noncanonical_lookalike, seed)
        self.assertIn(
            "if LC_ALL=C crontab -l > /tmp/syswarden-existing-cron "
            "2>/tmp/syswarden-existing-cron.error; then",
            script,
        )
        self.assertIn(
            'LC_ALL=C crontab -l > /tmp/syswarden-root-cron-after 2>/tmp/syswarden-remove-cron.error',
            script,
        )
        self.assertIn(
            "cmp -s /tmp/syswarden-root-cron-before /tmp/syswarden-root-cron-after",
            script,
        )
        self.assertIn(
            "one exact inert legacy record remains as a bounded residual",
            script,
        )
        self.assertIn("/etc/cron.d/.syswarden.pending-v1", script)
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
                if family == "deb" and scenario == "remove":
                    labels = ("remove", "remove-before-purge")
                    exact_rsyslog = True
                else:
                    labels = (
                        "final-removal" if family == "rpm" else scenario,
                    )
                    exact_rsyslog = False
                expected_generated = [
                    check
                    for label in labels
                    for check in (
                        package_lifecycle_lab._generated_rsyslog_pre_removal_event_checks(
                            scenario,
                            label,
                        )
                        if exact_rsyslog
                        else ()
                    )
                    + package_lifecycle_lab._generated_cleanup_event_checks(
                            scenario,
                            label,
                            exact_rsyslog=exact_rsyslog,
                    )
                ]
                self.assertEqual(generated, expected_generated)
                for label in labels:
                    self.assertIn(
                        f"{scenario}.{label}.service_manager_calls", checks
                    )

    def test_alma_v4028_rpm_rsyslog_transition_fixture_is_exact_and_fail_closed(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("# The exact historical AlmaLinux v4.02.8 RPM")
        end = source.index("\nprepare_package_transition() {", start)
        functions = source[start:end]
        scenario_start = source.index("scenario_upgrade_rollback_initial() {")
        scenario_end = source.index("\nscenario_remove() {", scenario_start)
        scenarios = source[scenario_start:scenario_end]

        self.assertIn("RefuseManualStop=yes", functions)
        self.assertIn(
            "896e27cd6a65891cd2184253fcfba7e691f0d46047f41d08ee11be81a7d06098",
            functions,
        )
        self.assertEqual(functions.count("systemctl daemon-reload"), 1)
        for forbidden in (
            "systemctl start rsyslog",
            "systemctl stop rsyslog",
            "systemctl restart rsyslog",
            "systemctl reset-failed rsyslog",
        ):
            self.assertNotIn(forbidden, functions)
        self.assertEqual(
            scenarios.count("prepare_alma_v4028_rpm_rsyslog_fixture \\\n"),
            1,
        )
        self.assertEqual(
            scenarios.count("attest_alma_v4028_rpm_rsyslog_fixture \\\n"),
            1,
        )
        self.assertEqual(
            scenarios.count(
                "attest_alma_v4028_rpm_rsyslog_after_previous \\\n"
            ),
            2,
        )
        for candidate_step in (
            'run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"',
            'run_install_step reinstall.candidate "${CANDIDATE_PACKAGE}"',
            'run_install_step recovery.candidate "${CANDIDATE_PACKAGE}"',
        ):
            candidate_index = scenarios.index(candidate_step)
            preceding = scenarios[:candidate_index].splitlines()[-2:]
            self.assertNotIn("alma_v4028", "\n".join(preceding))

        harness = (
            "#!/bin/sh\nset -u\n"
            + functions
            + r'''
hash_file() {
    sha256sum "$1" | awk '{ print $1 }'
}
installed_version() {
    printf '%s\n' "${TEST_INSTALLED_VERSION:-4.02.8}"
}
syswarden_classify_service_manager() {
    printf '%s\n' "${TEST_MANAGER_STATE:-ACTIVE}"
}
rpm() {
    printf 'rpm %s\n' "$*" >> "${TEST_CALLS}"
    case "$1" in
        -qp)
            printf '%s' "${TEST_ARTIFACT_RECORD:-syswarden|0|4.02.8|1|x86_64}"
            ;;
        -q)
            printf '%s' "${TEST_INSTALLED_RECORD:-syswarden|0|4.02.8|1|x86_64}"
            ;;
        *) return 97 ;;
    esac
}
systemctl() {
    printf 'systemctl %s\n' "$*" >> "${TEST_CALLS}"
    syswarden_test_reloaded=0
    [ ! -f "${TEST_RELOADED}" ] || syswarden_test_reloaded=1
    case "$*" in
        'show -p RefuseManualStop --value rsyslog.service')
            if [ "${syswarden_test_reloaded}" -eq 1 ]; then
                printf '%s\n' "${TEST_FINAL_PROPERTY:-yes}"
            else
                printf '%s\n' "${TEST_INITIAL_PROPERTY:-no}"
            fi
            ;;
        'is-enabled rsyslog.service')
            if [ "${syswarden_test_reloaded}" -eq 1 ]; then
                printf '%s\n' "${TEST_FINAL_ENABLED:-enabled}"
            else
                printf '%s\n' "${TEST_INITIAL_ENABLED:-enabled}"
            fi
            ;;
        'is-active rsyslog.service')
            if [ "${syswarden_test_reloaded}" -eq 1 ]; then
                printf '%s\n' "${TEST_FINAL_ACTIVE:-active}"
            else
                printf '%s\n' "${TEST_INITIAL_ACTIVE:-active}"
            fi
            ;;
        'show -p MainPID --value rsyslog.service')
            if [ "${syswarden_test_reloaded}" -eq 1 ]; then
                printf '%s\n' "${TEST_FINAL_PID:-123}"
            else
                printf '%s\n' "${TEST_INITIAL_PID:-123}"
            fi
            ;;
        'daemon-reload')
            syswarden_test_reload_rc="${TEST_DAEMON_RELOAD_RC:-0}"
            if [ "${syswarden_test_reload_rc}" -eq 0 ]; then
                : > "${TEST_RELOADED}"
            fi
            return "${syswarden_test_reload_rc}"
            ;;
        *) return 97 ;;
    esac
}
kill() {
    printf 'kill %s\n' "$*" >> "${TEST_CALLS}"
    return "${TEST_KILL_RC:-0}"
}

case "${TEST_ACTION:-full}" in
    prepare)
        prepare_alma_v4028_rpm_rsyslog_fixture \
            "${TEST_PROC_ROOT}" "${TEST_SYSTEMD_ROOT}" "${TEST_OWNER}" \
            "${TEST_RSYSLOGD}"
        ;;
    full)
        prepare_alma_v4028_rpm_rsyslog_fixture \
            "${TEST_PROC_ROOT}" "${TEST_SYSTEMD_ROOT}" "${TEST_OWNER}" \
            "${TEST_RSYSLOGD}" &&
        attest_alma_v4028_rpm_rsyslog_after_previous \
            "${TEST_PROC_ROOT}" "${TEST_SYSTEMD_ROOT}" "${TEST_OWNER}" \
            "${TEST_RSYSLOGD}"
        ;;
    tamper)
        prepare_alma_v4028_rpm_rsyslog_fixture \
            "${TEST_PROC_ROOT}" "${TEST_SYSTEMD_ROOT}" "${TEST_OWNER}" \
            "${TEST_RSYSLOGD}" || exit $?
        printf '%s\n' tampered > \
            "${TEST_SYSTEMD_ROOT}/rsyslog.service.d/90-syswarden-lifecycle-v4028.conf"
        attest_alma_v4028_rpm_rsyslog_after_previous \
            "${TEST_PROC_ROOT}" "${TEST_SYSTEMD_ROOT}" "${TEST_OWNER}" \
            "${TEST_RSYSLOGD}"
        ;;
    *) exit 98 ;;
esac
'''
        )

        def run_case(
            overrides: dict[str, str] | None = None,
            *,
            invalid_map: bool = False,
            wrong_process: bool = False,
            preexisting_dropin: bool = False,
            wrong_package_name: bool = False,
        ) -> tuple[subprocess.CompletedProcess[str], list[str], Path]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            proc_root = root / "proc"
            pid1 = proc_root / "1"
            process = proc_root / "123"
            pid1.mkdir(parents=True)
            process.mkdir()
            (pid1 / "comm").write_text("systemd\n", encoding="ascii")
            identity_map = (
                "0 0 4294967295\n"
                if invalid_map
                else "0 1000 1\n1 524288 65536\n"
            )
            (pid1 / "uid_map").write_text(identity_map, encoding="ascii")
            (pid1 / "gid_map").write_text(identity_map, encoding="ascii")
            (process / "comm").write_text(
                "unexpected\n" if wrong_process else "rsyslogd\n",
                encoding="ascii",
            )
            (process / "exe").symlink_to("/usr/sbin/rsyslogd")
            systemd_root = root / "systemd"
            systemd_root.mkdir(mode=0o755)
            if preexisting_dropin:
                dropin_dir = systemd_root / "rsyslog.service.d"
                dropin_dir.mkdir(mode=0o755)
                (dropin_dir / "90-syswarden-lifecycle-v4028.conf").write_text(
                    "unexpected\n", encoding="ascii"
                )
            package = root / (
                "unexpected.rpm"
                if wrong_package_name
                else "syswarden-4.02.8-1.x86_64.rpm"
            )
            package.write_bytes(b"exact historical RPM fixture")
            rsyslogd = root / "rsyslogd"
            rsyslogd.write_text(
                "#!/bin/sh\n"
                "printf 'rsyslogd %s\\n' \"$*\" >> \"${TEST_CALLS}\"\n"
                "exit \"${TEST_VALIDATE_RC:-0}\"\n",
                encoding="ascii",
            )
            rsyslogd.chmod(0o755)
            calls = root / "calls"
            calls.write_text("", encoding="ascii")
            command_log = root / "commands.log"
            reloaded = root / "daemon-reloaded"
            environment = {
                **os.environ,
                "container": "podman",
                "PACKAGE_FAMILY": "rpm",
                "SCENARIO": "upgrade-rollback",
                "EXPECTED_DISTRIBUTION": "almalinux",
                "EXPECTED_PREVIOUS_VERSION": "4.02.8",
                "EXPECTED_CANDIDATE_VERSION": "4.03.2",
                "EXPECTED_PREVIOUS_SHA256": hashlib.sha256(
                    package.read_bytes()
                ).hexdigest(),
                "EXPECTED_PACKAGE_ARCHITECTURE": "x86_64",
                "PREVIOUS_PACKAGE": str(package),
                "COMMAND_LOG": str(command_log),
                "TEST_CALLS": str(calls),
                "TEST_RELOADED": str(reloaded),
                "TEST_PROC_ROOT": str(proc_root),
                "TEST_SYSTEMD_ROOT": str(systemd_root),
                "TEST_OWNER": f"{systemd_root.stat().st_uid}:{systemd_root.stat().st_gid}",
                "TEST_RSYSLOGD": str(rsyslogd),
                "syswarden_transition_rsyslog_pid_before": "123",
            }
            environment.update(overrides or {})
            result = subprocess.run(
                [shutil.which("dash") or "/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            observed = calls.read_text(encoding="ascii").splitlines()
            return result, observed, systemd_root

        accepted, calls, systemd_root = run_case()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(calls.count("systemctl daemon-reload"), 1)
        self.assertGreaterEqual(
            sum(call.endswith(" -N1 -f /etc/rsyslog.conf") for call in calls), 3
        )
        self.assertFalse(
            any(
                call.startswith(
                    (
                        "systemctl start ",
                        "systemctl stop ",
                        "systemctl restart ",
                        "systemctl reload rsyslog",
                    )
                )
                for call in calls
            )
        )
        dropin = (
            systemd_root
            / "rsyslog.service.d"
            / "90-syswarden-lifecycle-v4028.conf"
        )
        self.assertEqual(dropin.read_bytes(), b"[Unit]\nRefuseManualStop=yes\n")
        self.assertEqual(dropin.stat().st_mode & 0o777, 0o644)

        for label, overrides in (
            ("other-family", {"PACKAGE_FAMILY": "deb"}),
            ("other-scenario", {"SCENARIO": "remove"}),
            ("other-distribution", {"EXPECTED_DISTRIBUTION": "fedora"}),
            ("other-version", {"EXPECTED_PREVIOUS_VERSION": "4.02.7"}),
            ("other-candidate", {"EXPECTED_CANDIDATE_VERSION": "4.03.3"}),
        ):
            with self.subTest(noop=label):
                result, observed, root = run_case(overrides)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(observed, [])
                self.assertFalse((root / "rsyslog.service.d").exists())

        failures: tuple[
            tuple[str, dict[str, str], dict[str, bool]], ...
        ] = (
            ("artifact-digest", {"EXPECTED_PREVIOUS_SHA256": "0" * 64}, {}),
            ("artifact-identity", {"TEST_ARTIFACT_RECORD": "other"}, {}),
            ("artifact-name", {}, {"wrong_package_name": True}),
            ("invalid-config", {"TEST_VALIDATE_RC": "1"}, {}),
            ("inactive-before", {"TEST_INITIAL_ACTIVE": "inactive"}, {}),
            ("wrong-pid-before", {"TEST_INITIAL_PID": "124"}, {}),
            ("reload-failure", {"TEST_DAEMON_RELOAD_RC": "1"}, {}),
            ("property-not-loaded", {"TEST_FINAL_PROPERTY": "no"}, {}),
            ("inactive-after", {"TEST_FINAL_ACTIVE": "failed"}, {}),
            ("wrong-pid-after", {"TEST_FINAL_PID": "124"}, {}),
            ("installed-identity", {"TEST_INSTALLED_RECORD": "other"}, {}),
            ("installed-version", {"TEST_INSTALLED_VERSION": "4.03.2"}, {}),
            ("rootless-map", {}, {"invalid_map": True}),
            ("process-identity", {}, {"wrong_process": True}),
            ("preexisting-dropin", {}, {"preexisting_dropin": True}),
        )
        for label, overrides, options in failures:
            with self.subTest(fail_closed=label):
                result, observed, _ = run_case(overrides, **options)
                self.assertNotEqual(result.returncode, 0, result)
                self.assertNotIn("systemctl restart rsyslog.service", observed)

        tampered, _, _ = run_case({"TEST_ACTION": "tamper"})
        self.assertNotEqual(tampered.returncode, 0, tampered)

    def test_package_transitions_reset_only_an_active_rsyslog_rate_limit(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("prepare_package_transition() {")
        end = source.index("\nexpected_systemd_enablement_prefix() {", start)
        function = source[start:end]

        self.assertIn("prepare_service_runtime_fixture || return 1", function)
        self.assertIn("systemctl is-enabled rsyslog.service", function)
        self.assertIn("systemctl is-active rsyslog.service", function)
        self.assertIn("systemctl reset-failed rsyslog.service", function)
        self.assertNotIn("systemctl start", function)
        self.assertNotIn("systemctl restart", function)
        self.assertNotIn("systemctl try-restart", function)
        self.assertLess(
            function.index("systemctl is-active rsyslog.service"),
            function.index("systemctl reset-failed rsyslog.service"),
        )
        self.assertLess(
            function.index("systemctl reset-failed rsyslog.service"),
            function.rindex("systemctl is-active rsyslog.service"),
        )
        self.assertIn(
            '[ "${syswarden_transition_rsyslog_pid_after}" = '
            '"${syswarden_transition_rsyslog_pid_before}" ]',
            function,
        )
        self.assertEqual(function.count("kill -0"), 2)

        commands = (
            ('upgrade.candidate "${CANDIDATE_PACKAGE}"', 1),
            ('reinstall.candidate "${CANDIDATE_PACKAGE}"', 1),
            ('recovery.candidate "${CANDIDATE_PACKAGE}"', 1),
            ('install.candidate "${CANDIDATE_PACKAGE}"', 2),
        )
        for command, expected_count in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    source.count(
                        "    prepare_package_transition || return\n"
                        f"    run_install_step {command} || return"
                    ),
                    expected_count,
                )
        self.assertEqual(
            source.count(
                "    prepare_package_transition || return\n"
                "    prepare_alma_v4028_rpm_rsyslog_fixture \\\n"
                "        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return\n"
                '    run_install_step install.previous "${PREVIOUS_PACKAGE}" || return'
            ),
            1,
        )
        self.assertEqual(
            source.count(
                "    prepare_package_transition || return\n"
                "    attest_alma_v4028_rpm_rsyslog_fixture \\\n"
                "        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return\n"
                '    run_install_step rollback.previous "${PREVIOUS_PACKAGE}" || return'
            ),
            1,
        )

        harness = function + r'''
prepare_service_runtime_fixture() {
    printf '%s\n' prepare-service-runtime >> "${TEST_CALLS}"
    return "${TEST_FIXTURE_RC:-0}"
}
systemctl() {
    printf 'systemctl %s\n' "$*" >> "${TEST_CALLS}"
    case "$*" in
        'is-enabled rsyslog.service') printf '%s\n' "${TEST_ENABLED:-enabled}" ;;
        'is-active rsyslog.service') printf '%s\n' "${TEST_ACTIVE:-active}" ;;
        'show -p MainPID --value rsyslog.service')
            if [ -n "${TEST_PID_AFTER:-}" ] && grep -q '^systemctl reset-failed ' "${TEST_CALLS}"; then
                printf '%s\n' "${TEST_PID_AFTER}"
            else
                printf '%s\n' "${TEST_PID_BEFORE:-123}"
            fi
            ;;
        'reset-failed rsyslog.service') return "${TEST_RESET_RC:-0}" ;;
        *) return 97 ;;
    esac
}
kill() {
    printf 'kill %s\n' "$*" >> "${TEST_CALLS}"
    return "${TEST_KILL_RC:-0}"
}
syswarden_classify_service_manager() {
    printf '%s\n' "${TEST_MANAGER_STATE:-ACTIVE}"
}
prepare_package_transition
'''

        with tempfile.TemporaryDirectory() as temporary:
            calls = Path(temporary) / "calls"
            environment = os.environ.copy()
            environment.update(
                {
                    "PACKAGE_FAMILY": "deb",
                    "TEST_CALLS": str(calls),
                }
            )
            accepted = subprocess.run(
                ["/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(accepted.returncode, 0, accepted)
            accepted_calls = calls.read_text(encoding="ascii").splitlines()
            self.assertEqual(accepted_calls.count("systemctl reset-failed rsyslog.service"), 1)
            self.assertEqual(accepted_calls.count("kill -0 123"), 2)

            calls.unlink()
            environment["TEST_ACTIVE"] = "inactive"
            rejected = subprocess.run(
                ["/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(rejected.returncode, 0, rejected)
            self.assertNotIn(
                "systemctl reset-failed rsyslog.service",
                calls.read_text(encoding="ascii").splitlines(),
            )

            calls.unlink()
            environment.pop("TEST_ACTIVE")
            environment["TEST_PID_AFTER"] = "124"
            changed_pid = subprocess.run(
                ["/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(changed_pid.returncode, 0, changed_pid)
            self.assertIn(
                "systemctl reset-failed rsyslog.service",
                calls.read_text(encoding="ascii").splitlines(),
            )

    def test_alpine_crond_provider_attestation_rejects_ambiguous_evidence(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("alpine_apk_owner_version() {")
        end = source.index("\nprepare_service_runtime_fixture() {", start)
        functions = source[start:end]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_directory = root / "bin"
            binary_directory.mkdir()
            calls = root / "calls"
            counter = root / "runlevel-counter"

            def write_executable(name: str, content: str) -> Path:
                path = binary_directory / name
                path.write_text(textwrap.dedent(content).lstrip(), encoding="ascii")
                path.chmod(0o755)
                return path

            crond = write_executable(
                "crond",
                """
                #!/bin/sh
                exit 0
                """,
            )
            write_executable(
                "apk",
                r"""
                #!/bin/sh
                printf 'apk %s\n' "$*" >> "${TEST_CALLS}"
                case "$1:$2:$3" in
                    info:--installed:cronie)
                        exit 0
                        ;;
                    info:--installed:cronie-openrc)
                        [ "${TEST_MISSING_OPENRC:-0}" != 1 ]
                        exit
                        ;;
                    info:--who-owns:*)
                        if [ "$3" = "${TEST_CROND_TARGET}" ]; then
                            package="${TEST_DAEMON_PACKAGE:-cronie}"
                            version="${TEST_DAEMON_VERSION:-1.7.2-r0}"
                            multiline="${TEST_MULTILINE_OWNER:-}"
                        elif [ "$3" = /etc/init.d/cronie ]; then
                            package="${TEST_INIT_PACKAGE:-cronie-openrc}"
                            version="${TEST_INIT_VERSION:-1.7.2-r0}"
                            multiline="${TEST_MULTILINE_OWNER:-}"
                        else
                            exit 1
                        fi
                        printf '%s is owned by %s-%s\n' "$3" "${package}" "${version}"
                        if [ "${multiline}" = "$3" ]; then
                            printf '%s is owned by %s-%s\n' "$3" "${package}" "${version}"
                        fi
                        ;;
                    *)
                        exit 1
                        ;;
                esac
                """,
            )
            write_executable(
                "rc-service",
                r"""
                #!/bin/sh
                printf 'rc-service %s\n' "$*" >> "${TEST_CALLS}"
                case "$*" in
                    '--exists cronie')
                        exit 0
                        ;;
                    'cronie status')
                        [ "${TEST_STATUS_FAILURE:-0}" != 1 ] || exit 3
                        printf '%s\n' "${TEST_STATUS_OUTPUT:-status: started}"
                        ;;
                    'cronie start')
                        exit 0
                        ;;
                    *)
                        exit 1
                        ;;
                esac
                """,
            )
            write_executable(
                "rc-update",
                r"""
                #!/bin/sh
                printf 'rc-update %s\n' "$*" >> "${TEST_CALLS}"
                case "$*" in
                    show)
                        if [ "${TEST_RUNLEVEL_MODE:-stable}" = drift ]; then
                            value=0
                            [ ! -f "${TEST_COUNTER}" ] || value="$(cat "${TEST_COUNTER}")"
                            if [ "${value}" -eq 0 ]; then
                                printf '%s\n' 1 > "${TEST_COUNTER}"
                                printf 'cronie | default\nalpha | default\n'
                            else
                                printf 'cronie | default\nbeta | default\n'
                            fi
                        else
                            printf '%s' "${TEST_RUNLEVELS:-cronie | default
}"
                        fi
                        ;;
                    'add cronie default')
                        exit 0
                        ;;
                    *)
                        exit 1
                        ;;
                esac
                """,
            )

            base_environment = {
                **os.environ,
                "LC_ALL": "C",
                "PACKAGE_FAMILY": "apk",
                "PATH": f"{binary_directory}:/usr/bin:/bin",
                "TEST_CALLS": str(calls),
                "TEST_COUNTER": str(counter),
                "TEST_CROND_TARGET": str(crond),
                "TEST_RUNLEVELS": "cronie | default\n",
            }

            def run_helper(
                name: str, overrides: dict[str, str] | None = None
            ) -> tuple[subprocess.CompletedProcess[str], str]:
                calls.write_text("", encoding="ascii")
                counter.unlink(missing_ok=True)
                environment = dict(base_environment)
                environment.update(overrides or {})
                result = subprocess.run(
                    ["/bin/sh", "-c", functions + f"\n{name}"],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                return result, calls.read_text(encoding="ascii")

            success, success_calls = run_helper("attest_alpine_crond_provider")
            self.assertEqual(success.returncode, 0, success)
            self.assertEqual(success_calls.count("rc-update show\n"), 2)
            self.assertEqual(success_calls.count("rc-service cronie status\n"), 2)
            self.assertGreaterEqual(
                success_calls.count("apk info --installed cronie-openrc\n"), 2
            )
            self.assertNotIn("rc-update add", success_calls)
            self.assertNotIn("rc-service cronie start", success_calls)

            adversarial = {
                "missing openrc package": {"TEST_MISSING_OPENRC": "1"},
                "wrong daemon package": {"TEST_DAEMON_PACKAGE": "operator"},
                "ambiguous daemon package prefix": {
                    "TEST_DAEMON_PACKAGE": "cronie-operator"
                },
                "wrong init package": {"TEST_INIT_PACKAGE": "operator"},
                "version mismatch": {"TEST_INIT_VERSION": "1.7.3-r0"},
                "multiple owner records": {
                    "TEST_MULTILINE_OWNER": str(crond)
                },
                "missing runlevel": {"TEST_RUNLEVELS": "sshd | default\n"},
                "daemon name is not service name": {
                    "TEST_RUNLEVELS": "crond | default\n"
                },
                "extra runlevel": {
                    "TEST_RUNLEVELS": "cronie | default boot\n"
                },
                "duplicate record": {
                    "TEST_RUNLEVELS": "cronie | default\ncronie | default\n"
                },
                "status failure": {"TEST_STATUS_FAILURE": "1"},
                "complete snapshot drift": {"TEST_RUNLEVEL_MODE": "drift"},
            }
            for label, overrides in adversarial.items():
                with self.subTest(label=label):
                    result, _ = run_helper(
                        "attest_alpine_crond_provider", overrides
                    )
                    self.assertNotEqual(result.returncode, 0, result)

            rejected_prepare, prepare_calls = run_helper(
                "prepare_alpine_crond_provider",
                {"TEST_INIT_PACKAGE": "operator"},
            )
            self.assertNotEqual(rejected_prepare.returncode, 0, rejected_prepare)
            self.assertNotIn("rc-update add cronie default", prepare_calls)
            self.assertNotIn("rc-service cronie start", prepare_calls)

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
            ("remove", "reinstall-after-remove"): 0,
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

    def test_preinstall_networkless_configuration_is_minimal_exact_and_attested(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        writer_start = source.index("write_preinstall_networkless_config() {")
        writer_end = source.index(
            "\nseed_and_attest_preinstall_networkless_config() {", writer_start
        )
        writer = source[writer_start:writer_end]
        destination = self.root / "preinstall-networkless.toml"
        expected = (
            b'# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".\n'
            b'[network.blocklists]\n'
            b'list_choice = "4"\n'
            b'custom_url = ""\n'
            b'custom_url_ipv6 = ""\n'
            b'custom_hash = ""\n'
            b'custom_hash_ipv6 = ""\n'
            b'use_spamhaus = false\n\n'
        )
        rendered = subprocess.run(
            [
                "/bin/sh",
                "-c",
                writer + '\nwrite_preinstall_networkless_config "$1"',
                "preinstall",
                str(destination),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual(destination.read_bytes(), expected)
        self.assertEqual(
            hashlib.sha256(expected).hexdigest(),
            "e0a6d764d1786c3661c6f25fa7b688bd8c8922d8fd0a00135925ae982f274d68",
        )
        self.assertNotIn("[network.saas]", writer)
        self.assertNotIn("[user]", writer)
        attester = source[
            writer_end : source.index("\nwrite_seeded_operator_token() {", writer_end)
        ]
        for contract in (
            "stat -c '%u:%g:%a:%h'",
            "0:0:640:1",
            "[ ! -L",
            "${PREFIX}.preinstall.networkless_config",
            "e0a6d764d1786c3661c6f25fa7b688bd8c8922d8fd0a00135925ae982f274d68",
        ):
            self.assertIn(contract, attester)
        seed_attester = source[
            source.index("seed_and_attest_preinstall_networkless_config() {") : source.index(
                "\nattest_preinstall_networkless_config_after_previous() {"
            )
        ]
        publication = seed_attester.index(
            'write_preinstall_networkless_config "${preinstall_networkless_path}"'
        )
        self.assertLess(
            seed_attester.index('[ -e "${preinstall_networkless_path}" ]'),
            publication,
        )
        self.assertLess(
            seed_attester.index('[ -L "${preinstall_networkless_path}" ]'),
            publication,
        )
        for directory in (
            "/etc/syswarden",
            "/etc/syswarden/config",
            "/etc/syswarden/config/modules",
        ):
            self.assertIn(directory, seed_attester)
        self.assertGreaterEqual(seed_attester.count("!= 0:0"), 2)
        checks = package_lifecycle_lab.expected_event_checks(
            "deb", "upgrade-rollback"
        )
        self.assertLess(
            checks.index("upgrade-rollback.preinstall.networkless_config"),
            checks.index("upgrade-rollback.install.previous"),
        )
        self.assertLess(
            checks.index("upgrade-rollback.install.previous.maintainer_script"),
            checks.index("upgrade-rollback.previous.networkless_config_preserved"),
        )
        self.assertLess(
            checks.index("upgrade-rollback.previous.networkless_config_preserved"),
            checks.index("upgrade-rollback.previous.version"),
        )

    def test_seed_scopes_legacy_saas_and_exact_networkless_feed_override(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        writer_start = source.index("write_seeded_operator_token() {")
        writer_end = source.index("\nseed_state() {", writer_start)
        writer = source[writer_start:writer_end]
        token = self.root / "seeded-operator-token.toml"
        feed_override = (
            b'# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".\n'
            b'[network.blocklists]\n'
            b'list_choice = "4"\n'
            b'custom_url = ""\n'
            b'custom_url_ipv6 = ""\n'
            b'custom_hash = ""\n'
            b'custom_hash_ipv6 = ""\n'
            b'use_spamhaus = false\n\n'
        )
        base_fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            + feed_override
            + b'[user]\nprofile_name = "lifecycle-operator"\n'
        )
        upgrade_fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[network.saas]\nallow_monitors = true\n\n'
            + feed_override
            + b'[user]\nprofile_name = "lifecycle-operator"\n'
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
        for scenario_name in ("scenario_remove() {", "scenario_purge() {"):
            scenario_start = source.index(scenario_name)
            scenario_end = source.index("\n}", scenario_start)
            scenario_source = source[scenario_start:scenario_end]
            self.assertLess(
                scenario_source.index("seed_state"),
                scenario_source.index("run_install_step install.candidate"),
            )
        self.assertNotIn("lan_mode", writer)

    def test_legacy_saas_seed_uses_exact_public_positive_fixture_bytes(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("seed_legacy_saas_monitor_state() {")
        end = source.index("\n}\n\nseed_live_legacy_webtui_process() {", start) + 2
        function = source[start:end]
        lists = self.root / "saas-lists"
        persist = self.root / "saas-persist"
        persist.mkdir()
        fake_bin = self.root / "saas-fake-bin"
        fake_bin.mkdir()
        fake_chown = fake_bin / "chown"
        fake_chown.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_chown.chmod(0o700)
        function = function.replace("/etc/syswarden/lists", str(lists))
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                function + '\nPERSIST_ROOT="$1"; seed_legacy_saas_monitor_state',
                "seed-saas",
                str(persist),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        payload = lists.joinpath("syswarden_saas_monitors.ipv4").read_bytes()
        self.assertEqual(payload, b"8.8.8.8\n1.1.1.0/24")
        self.assertFalse(payload.endswith(b"\n"))
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "7337141ed136cb92b166db379d6bd2ceba3ddf64cef41583e469485e0048dedc",
        )
        self.assertEqual(
            source.count(
                "7337141ed136cb92b166db379d6bd2ceba3ddf64cef41583e469485e0048dedc"
            ),
            2,
        )
        for entry in payload.decode("ascii").splitlines():
            with self.subTest(entry=entry):
                self.assertEqual(ipaddress.ip_network(entry, strict=False).version, 4)
                self.assertTrue(ipaddress.ip_network(entry, strict=False).is_global)
        self.assertFalse(lists.joinpath("syswarden_saas_monitors.ipv6").exists())
        self.assertFalse(lists.joinpath("syswarden_saas_monitors.pair").exists())
        self.assertTrue(persist.joinpath("legacy-saas-seeded").is_file())

    def test_operator_sentinel_is_byte_stable_and_live_telemetry_is_not_hashed(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("seed_state() {")
        end = source.index("\n}\n\nattest_openrc_webtui_pidfile_before_manager() {", start) + 2
        seed = source[start:end]

        sentinel_line = next(
            line.strip()
            for line in seed.splitlines()
            if line.strip().endswith(
                "> /var/lib/syswarden/ui/lifecycle-operator.json"
            )
        )
        sentinel_tokens = shlex.split(sentinel_line)
        self.assertEqual(sentinel_tokens[-2:], [">", "/var/lib/syswarden/ui/lifecycle-operator.json"])
        sentinel_payload = sentinel_tokens[2].encode("utf-8") + b"\n"
        self.assertEqual(
            sentinel_payload,
            b'{"schema":1,"sentinel":"lifecycle-operator-preserve-exactly"}\n',
        )
        self.assertEqual(
            hashlib.sha256(sentinel_payload).hexdigest(),
            "1538931c74bbb4770cb879eff48012d7cff7fa0cef46104cb7552d40d6ee9fae",
        )

        telemetry_line = next(
            line.strip()
            for line in seed.splitlines()
            if line.strip().endswith("> /var/lib/syswarden/ui/data.json")
        )
        telemetry_tokens = shlex.split(telemetry_line)
        telemetry = json.loads(telemetry_tokens[2])
        self.assertEqual(telemetry["profile_name"], "lifecycle-operator")
        self.assertEqual(len(telemetry["waf"]["sparkline_24h"]), 24)
        self.assertNotIn("ha", telemetry)
        self.assertNotIn("hash_file /var/lib/syswarden/ui/data.json", source)
        self.assertNotIn("STATE_DATA_HASH", source)
        self.assertIn(
            'STATE_OPERATOR_DATA_HASH="$(hash_file /var/lib/syswarden/ui/lifecycle-operator.json)"',
            seed,
        )
        self.assertIn(
            'assert_preserved "${label}" operator_data /var/lib/syswarden/ui/lifecycle-operator.json "${STATE_OPERATOR_DATA_HASH}" 600',
            source,
        )
        self.assertIn('assert_live_telemetry_data "${label}"', source)
        state_contract = source[
            source.index("assert_all_state_preserved() {") : source.index(
                "\n}\n\nassert_package_absent() {",
                source.index("assert_all_state_preserved() {"),
            )
        ]
        ordered_state_fragments = (
            '"${label}" config ',
            '"${label}" token ',
            '"${label}" list ',
            '"${label}" list_ipv6 ',
            '"${label}" operator_data ',
            '"${label}" certificate ',
            'assert_live_telemetry_data "${label}"',
        )
        positions = [state_contract.index(item) for item in ordered_state_fragments]
        self.assertEqual(positions, sorted(positions))

        checks = package_lifecycle_lab.expected_event_checks("deb", "remove")
        for label in ("fresh", "remove"):
            for attribute in package_lifecycle_lab.LIVE_TELEMETRY_STATE_ATTRIBUTES:
                self.assertIn(
                    f"remove.{label}.state.telemetry.{attribute}", checks
                )
            self.assertNotIn(f"remove.{label}.state.telemetry.hash", checks)

    def test_live_telemetry_schema_is_exact_and_rejects_adversarial_drift(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("live_telemetry_schema_valid() {")
        end = source.index("\n}\n\nassert_live_telemetry_data() {", start) + 2
        function = source[start:end]
        fixture_path = (
            Path(__file__).resolve().parents[2]
            / "testdata/contracts/dashboard-data-v4.02.8.json"
        )
        baseline = json.loads(fixture_path.read_text(encoding="utf-8"))

        def accepted(payload: bytes) -> bool:
            path = self.root / "live-telemetry.json"
            path.unlink(missing_ok=True)
            path.write_bytes(payload)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    function + '\nlive_telemetry_schema_valid "$1"',
                    "telemetry-schema",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            return result.returncode == 0

        self.assertTrue(accepted(json.dumps(baseline).encode("utf-8")))
        assertion_end = source.index(
            "\n}\n\nsanitize_historical_rollback_token() {", start
        ) + 2
        assertion_contract = source[start:assertion_end]
        asserted = self.root / "asserted-live-telemetry.json"
        asserted.write_text(json.dumps(baseline), encoding="utf-8")
        asserted.chmod(0o600)
        assertion = subprocess.run(
            [
                "/bin/sh",
                "-c",
                "file_mode() { stat -c '%a' \"$1\"; }\n"
                "check_equal() { printf '%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                + assertion_contract
                + '\nassert_live_telemetry_data phase "$1"',
                "telemetry-assertion",
                str(asserted),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(assertion.returncode, 0, assertion.stderr)
        assertion_lines = [line.split("\t") for line in assertion.stdout.splitlines()]
        self.assertEqual(
            [line[0] for line in assertion_lines],
            [
                "phase.state.telemetry.type",
                "phase.state.telemetry.mode",
                "phase.state.telemetry.owner",
                "phase.state.telemetry.json",
                "phase.state.telemetry.schema",
            ],
        )
        self.assertEqual(assertion_lines[0][2], "regular")
        self.assertEqual(assertion_lines[1][2], "600")
        self.assertEqual(assertion_lines[3][2], "valid")
        self.assertEqual(assertion_lines[4][2], "dashboard-data-v1")
        changed = json.loads(json.dumps(baseline))
        changed["timestamp"] = "2026-08-23T12:34:56Z"
        changed["system"]["ram_used_mb"] += 1
        self.assertTrue(accepted(json.dumps(changed).encode("utf-8")))
        nullable_slices = json.loads(json.dumps(baseline))
        nullable_slices["waf"]["targeted_ports"] = None
        nullable_slices["waf"]["risk_radar"] = None
        nullable_slices["waf"]["allowed_events"] = None
        self.assertTrue(accepted(json.dumps(nullable_slices).encode("utf-8")))

        adversarial: dict[str, bytes] = {"malformed": b"{"}
        variants: dict[str, dict[str, object]] = {}
        missing = json.loads(json.dumps(baseline))
        del missing["timestamp"]
        variants["missing required field"] = missing
        unexpected = json.loads(json.dumps(baseline))
        unexpected["ha"] = {}
        variants["HA must remain absent"] = unexpected
        top_extension = json.loads(json.dumps(baseline))
        top_extension["unexpected"] = True
        variants["unexpected top-level key"] = top_extension
        system_extension = json.loads(json.dumps(baseline))
        system_extension["system"]["unexpected"] = True
        variants["unexpected system key"] = system_extension
        wrong_type = json.loads(json.dumps(baseline))
        wrong_type["layer3"]["global_blocked"] = "0"
        variants["wrong scalar type"] = wrong_type
        fractional = json.loads(json.dumps(baseline))
        fractional["waf"]["total_banned"] = 1.5
        variants["non-integer counter"] = fractional
        wrong_sparkline = json.loads(json.dumps(baseline))
        wrong_sparkline["waf"]["sparkline_24h"] = [0] * 23
        variants["wrong sparkline cardinality"] = wrong_sparkline
        for name, document in variants.items():
            adversarial[name] = json.dumps(document).encode("utf-8")
        for name, payload in adversarial.items():
            with self.subTest(name=name):
                self.assertFalse(accepted(payload))

        target = self.root / "live-telemetry-target.json"
        target.write_text(json.dumps(baseline), encoding="utf-8")
        link = self.root / "live-telemetry-link.json"
        link.symlink_to(target)
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                function + '\nlive_telemetry_schema_valid "$1"',
                "telemetry-schema",
                str(link),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("8388608", function)
        self.assertIn('(keys == ["github_release", "github_stars"', function)
        self.assertIn('(has("ha") | not)', function)

    def test_production_feed_default_and_install_failure_remain_fail_closed(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        migrator = repository.joinpath(
            "src/core/syswarden-cli/config/migrator.go"
        ).read_text(encoding="utf-8")
        install = repository.joinpath(
            "src/core/syswarden-cli/cmd/install.go"
        ).read_text(encoding="utf-8")
        update_feeds = repository.joinpath(
            "src/core/syswarden-cli/cmd/update_feeds.go"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'legacyValue(oldConfig, "SYSWARDEN_LIST_CHOICE", "1")',
            migrator,
        )
        download = install.index("if err := network.DownloadFeedsForInstall(")
        fatal = install.index(
            'return installStageError("failed to download threat intelligence feeds", err)',
            download,
        )
        cron = install.index("if err := network.SetupFeedsCron()", fatal)
        self.assertLess(download, fatal)
        self.assertLess(fatal, cron)
        self.assertIn("return network.DownloadFeeds(", update_feeds)
        self.assertNotIn("DownloadFeedsForInstall", update_feeds)

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
        self.assertIn("if v4028_to_v4032_transition_selected; then", contract)
        self.assertIn("elif v4032_to_v4033_transition_selected; then", contract)
        self.assertIn("historical-webtui-credential", contract)
        self.assertIn("byte-exact", contract)
        self.assertIn(
            'record_unsupported_rollback_token_contract "${label}"', contract
        )
        self.assertIn(
            'assert_preserved "${label}" token /etc/syswarden/config/modules/99-user.toml',
            contract,
        )
        self.assertIn('[REDACTED]', source)

    def test_upgrade_rollback_token_contract_is_exactly_version_bound(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        predicates_start = source.index("v4028_to_v4032_transition_selected() {")
        predicates_end = source.index(
            "\nexpected_systemd_enablement_prefix() {", predicates_start
        )
        contract_start = source.index(
            "expected_upgrade_rollback_token_contract() {"
        )
        contract_end = source.index(
            "\nrecord_unsupported_rollback_token_contract() {", contract_start
        )
        functions = (
            source[predicates_start:predicates_end]
            + "\n"
            + source[contract_start:contract_end]
        )
        command = (
            functions
            + '\nSCENARIO="$1"; EXPECTED_PREVIOUS_VERSION="$2"; '
            'EXPECTED_CANDIDATE_VERSION="$3"; PACKAGE_FAMILY="$4"; '
            'expected_upgrade_rollback_token_contract "$5"'
        )
        accepted = (
            (
                "upgrade-rollback",
                "4.02.8",
                "4.03.2",
                family,
                "rollback",
                "historical-webtui-credential",
            )
            for family in ("deb", "rpm")
        )
        current = (
            (
                "upgrade-rollback",
                "4.03.2",
                "4.03.3",
                family,
                "rollback",
                "byte-exact",
            )
            for family in ("deb", "rpm")
        )
        for scenario, previous, candidate, family, label, expected in (
            *accepted,
            *current,
        ):
            with self.subTest(
                scenario=scenario,
                previous=previous,
                candidate=candidate,
                family=family,
                label=label,
            ):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                        "token-contract",
                        scenario,
                        previous,
                        candidate,
                        family,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout.strip(), expected)

        rejected = (
            ("upgrade-rollback", "4.03.1", "4.03.3", "deb", "rollback"),
            ("upgrade-rollback", "4.03.2", "4.03.4", "rpm", "rollback"),
            ("upgrade-rollback", "4.02.8", "4.03.3", "deb", "rollback"),
            ("upgrade-rollback", "4.03.2", "4.03.3", "apk", "rollback"),
            ("upgrade-rollback", "4.03.2", "4.03.3", "deb", "recovery"),
            ("remove", "4.03.2", "4.03.3", "deb", "rollback"),
        )
        for scenario, previous, candidate, family, label in rejected:
            with self.subTest(
                rejected_scenario=scenario,
                previous=previous,
                candidate=candidate,
                family=family,
                label=label,
            ):
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        command,
                        "token-contract",
                        scenario,
                        previous,
                        candidate,
                        family,
                        label,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)

    def test_v4032_rollback_token_state_is_byte_exact_and_fail_closed(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("assert_preserved() {")
        end = source.index("\nlive_telemetry_schema_valid() {", start)
        function = source[start:end]
        fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[network.saas]\nallow_monitors = true\n\n'
            b'# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".\n'
            b'[network.blocklists]\n'
            b'list_choice = "4"\n'
            b'custom_url = ""\n'
            b'custom_url_ipv6 = ""\n'
            b'custom_hash = ""\n'
            b'custom_hash_ipv6 = ""\n'
            b'use_spamhaus = false\n\n'
            b'[user]\nprofile_name = "lifecycle-operator"\n'
        )
        expected_hash = hashlib.sha256(fixture).hexdigest()
        self.assertEqual(
            expected_hash,
            "75ba724333aa74769db97901ad0efc8c2724364cfbb860a7ac2ae02538892a69",
        )
        harness = (
            function
            + r'''
hash_file() {
    sha256sum "$1" | awk '{ print $1 }'
}
file_mode() {
    /usr/bin/stat -c '%a' "$1"
}
stat() {
    if [ "$1" = -c ] && [ "$2" = '%u:%g' ]; then
        printf '%s\n' "${TEST_OWNER}"
    else
        command stat "$@"
    fi
}
check_equal() {
    if [ "$2" = "$3" ]; then
        status=pass
    else
        status=fail
    fi
    printf '%s\t%s\n' "${status}" "$1"
}
PREFIX=upgrade-rollback
assert_preserved rollback token "$1" "$2" 640
'''
        )

        def run_state(
            kind: str,
            *,
            content: bytes = fixture,
            mode: int = 0o640,
            owner: str = "0:0",
        ) -> dict[str, str]:
            with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root = Path(temporary)
                token = root / "99-user.toml"
                if kind == "regular":
                    token.write_bytes(content)
                    token.chmod(mode)
                elif kind == "symlink":
                    target = root / "operator-token.toml"
                    target.write_bytes(content)
                    target.chmod(mode)
                    token.symlink_to(target)
                elif kind == "directory":
                    token.mkdir()
                elif kind != "missing":
                    self.fail(f"unknown token state {kind}")
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        harness,
                        "token-state",
                        str(token),
                        expected_hash,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "TEST_OWNER": owner},
                )
                self.assertEqual(result.returncode, 0, result)
                return {
                    check: status
                    for status, check in (
                        line.split("\t", 1)
                        for line in result.stdout.splitlines()
                    )
                }

        exact = run_state("regular")
        self.assertEqual(set(exact.values()), {"pass"})

        retired_hex_value = b"01234567" * 4
        adversarial = (
            ("changed-bytes", "regular", fixture + b"# drift\n", 0o640, "0:0", "rollback.state.token.hash"),
            (
                "retired-credential",
                "regular",
                fixture + b'webtui_password = "' + retired_hex_value + b'"\n',
                0o640,
                "0:0",
                "rollback.state.token.hash",
            ),
            ("wrong-mode", "regular", fixture, 0o600, "0:0", "rollback.state.token.mode"),
            ("wrong-owner", "regular", fixture, 0o640, "1:1", "rollback.state.token.owner"),
            ("symlink", "symlink", fixture, 0o640, "0:0", "rollback.state.token.type"),
            ("directory", "directory", fixture, 0o640, "0:0", "rollback.state.token.type"),
            ("missing", "missing", fixture, 0o640, "0:0", "rollback.state.token.type"),
        )
        for name, kind, content, mode, owner, failed_check in adversarial:
            with self.subTest(state=name):
                statuses = run_state(
                    kind,
                    content=content,
                    mode=mode,
                    owner=owner,
                )
                self.assertEqual(statuses[failed_check], "fail")

    def test_historical_rollback_token_sanitizer_restores_exact_seed_bytes(self) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("sanitize_historical_rollback_token() {")
        end = source.index("\nassert_historical_rollback_token() {", start)
        function = source[start:end]
        fixture = (
            b'[network]\ninterfaces = "lo"\n\n'
            b'[network.saas]\nallow_monitors = true\n\n'
            b'# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".\n'
            b'[network.blocklists]\n'
            b'list_choice = "4"\n'
            b'custom_url = ""\n'
            b'custom_url_ipv6 = ""\n'
            b'custom_hash = ""\n'
            b'custom_hash_ipv6 = ""\n'
            b'use_spamhaus = false\n\n'
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

    def test_v4032_to_v4033_previous_webtui_retirement_is_exact_and_fail_closed(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        functions_start = source.index("legacy_webtui_runtime_absent() {")
        functions_end = source.index(
            "\n\nalpine_apk_owner_version() {", functions_start
        )
        transitions_start = source.index(
            "v4028_to_v4032_transition_selected() {"
        )
        transitions_end = source.index(
            "\nexpected_systemd_enablement_prefix() {", transitions_start
        )
        transitions = source[transitions_start:transitions_end]
        functions = transitions + "\n" + source[functions_start:functions_end]
        quiesce_start = source.index("quiesce_previous_webtui_runtime() {")
        quiesce_end = source.index(
            "\n}\n\nlifecycle_seed_hex_prefix() {", quiesce_start
        )
        quiesce = source[quiesce_start:quiesce_end]
        probe_start = source.index("probe_postinstall_contract() {")
        probe_end = source.index("\n}\n\nverify_installed_inventory() {", probe_start)
        probe = source[probe_start:probe_end]

        exact_transition = (
            '[ "${SCENARIO}" = upgrade-rollback ] && \\\n'
            '        [ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ] && \\\n'
            '        [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.3 ]'
        )
        self.assertIn(exact_transition, transitions)
        self.assertIn(
            "v4032_to_v4033_upgrade_selected() {\n"
            "    v4032_to_v4033_transition_selected && \\\n"
            '        [ "$(installed_version 2>/dev/null || true)" = 4.03.2 ]\n'
            "}",
            functions,
        )
        self.assertIn(
            'legacy_webtui_runtime_absent "${previous_webtui_root}" || return 1',
            functions,
        )
        self.assertIn("syswarden_verify_no_exact_webtui_process \\", functions)
        self.assertIn("for previous_webtui_port in 62027 62028", functions)
        self.assertIn(
            "if v4032_to_v4033_upgrade_selected; then\n"
            "        attest_v4032_previous_webtui_retirement || return 1\n"
            "        return 0\n"
            "    fi",
            quiesce,
        )
        self.assertIn(
            "if v4032_to_v4033_upgrade_selected; then\n"
            "            attest_v4032_previous_webtui_retirement || \\\n"
            "                mark_postinstall_failure previous-webtui-retirement\n"
            "        else",
            probe,
        )
        for legacy_fragment in (
            "/etc/systemd/system/syswarden-webtui.service",
            "/etc/init.d/syswarden-webtui",
            "syswarden_read_exact_webtui_unit",
        ):
            self.assertIn(legacy_fragment, quiesce)

        harness = (
            "#!/bin/sh\nset -u\n"
            + functions
            + r'''
installed_version() {
    printf '%s\n' "${TEST_INSTALLED_VERSION:-4.03.2}"
}
syswarden_verify_no_exact_webtui_process() {
    [ "${TEST_PROCESS_STATE:-absent}" = absent ]
}
ss() {
    case "${TEST_SS_FAILURE:-none}" in
        nonzero) return 42 ;;
        stderr)
            printf '%s\n' 'netlink attestation unavailable' >&2
            return 0
            ;;
    esac
    case "$*" in
        *":${TEST_LISTENER_PORT:-none}"*) printf '%s\n' listener ;;
    esac
}
attest_v4032_previous_webtui_retirement "${TEST_ROOT}" "${TEST_ROOT}/proc"
'''
        )

        def run_case(
            overrides: dict[str, str] | None = None,
            *,
            residual: tuple[str, str] | None = None,
        ) -> subprocess.CompletedProcess[str]:
            temporary = tempfile.TemporaryDirectory(dir=self.root)
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            (root / "proc").mkdir()
            if residual is not None:
                relative, kind = residual
                path = root / relative.lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                if kind == "directory":
                    path.mkdir()
                elif kind == "symlink":
                    path.symlink_to(root / "missing-operator-target")
                else:
                    path.write_text("operator-residual\n", encoding="ascii")
            environment = {
                **os.environ,
                "SCENARIO": "upgrade-rollback",
                "EXPECTED_PREVIOUS_VERSION": "4.03.2",
                "EXPECTED_CANDIDATE_VERSION": "4.03.3",
                "TEST_INSTALLED_VERSION": "4.03.2",
                "TEST_ROOT": str(root),
            }
            environment.update(overrides or {})
            return subprocess.run(
                [shutil.which("dash") or "/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

        accepted = run_case()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        bounds = (
            ("scenario", {"SCENARIO": "remove"}),
            ("previous", {"EXPECTED_PREVIOUS_VERSION": "4.03.1"}),
            ("candidate", {"EXPECTED_CANDIDATE_VERSION": "4.03.4"}),
            ("installed", {"TEST_INSTALLED_VERSION": "4.03.1"}),
        )
        for label, overrides in bounds:
            with self.subTest(bound=label):
                self.assertNotEqual(run_case(overrides).returncode, 0)

        residuals = (
            ("systemd-unit", "/etc/systemd/system/syswarden-webtui.service", "file"),
            (
                "systemd-retiring",
                "/etc/systemd/system/syswarden-webtui.service.syswarden-retiring",
                "file",
            ),
            (
                "systemd-dropin",
                "/etc/systemd/system/syswarden-webtui.service.d",
                "directory",
            ),
            (
                "systemd-enablement",
                "/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service",
                "symlink",
            ),
            ("runtime-unit", "/run/systemd/system/syswarden-webtui.service", "file"),
            (
                "runtime-dropin",
                "/run/systemd/system/syswarden-webtui.service.d",
                "directory",
            ),
            ("openrc-unit", "/etc/init.d/syswarden-webtui", "file"),
            ("openrc-config", "/etc/conf.d/syswarden-webtui", "file"),
            (
                "openrc-enablement",
                "/etc/runlevels/default/syswarden-webtui",
                "symlink",
            ),
            ("pidfile", "/run/syswarden-webtui.pid", "file"),
        )
        for label, relative, kind in residuals:
            with self.subTest(residual=label):
                self.assertNotEqual(
                    run_case(residual=(relative, kind)).returncode,
                    0,
                )

        self.assertNotEqual(
            run_case({"TEST_PROCESS_STATE": "present"}).returncode,
            0,
        )
        for port in ("62027", "62028"):
            with self.subTest(listener=port):
                self.assertNotEqual(
                    run_case({"TEST_LISTENER_PORT": port}).returncode,
                    0,
                )
        for failure in ("nonzero", "stderr"):
            with self.subTest(ss_failure=failure):
                self.assertNotEqual(
                    run_case({"TEST_SS_FAILURE": failure}).returncode,
                    0,
                )

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
        self.assertIn("TCP4-LISTEN:62027,bind=127.0.0.1", script)
        self.assertNotIn("TCP-LISTEN:62027,bind=127.0.0.1", script)
        self.assertEqual(script.count("TCP4:127.0.0.1:62027"), 2)
        self.assertNotIn("TCP:127.0.0.1:62027", script)
        self.assertIn("syswarden-operator-62027", script)
        self.assertIn("--bind=127.0.0.1:62028", script)
        self.assertIn("https://127.0.0.1:62028/", script)
        self.assertIn("${PERSIST_ROOT}/legacy-webtui-process.pid", script)
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
        self.assertIn("quiesce_previous_webtui_runtime || return 1", seed_function)
        self.assertIn("[ -d /run ] && [ ! -L /run ] || return 1", seed_function)
        self.assertIn("prepare_service_runtime_fixture || return 1", seed_function)
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
        self.assertIn('LS01_OPERATOR_LISTENER_READY', seed_function)
        self.assertIn('LS02_OPERATOR_EXECUTABLE_PATH', seed_function)
        self.assertIn('LS03_OPERATOR_PROCESS_IDENTITY', seed_function)
        self.assertIn('LS04_OPERATOR_PIDFILE_IDENTITY', seed_function)
        self.assertIn('LS05_OPERATOR_SOCKET_IDENTITY', seed_function)
        self.assertIn('LS06_LIVE_WEBTUI_READY', script)
        self.assertIn(package_lifecycle_lab.SEED_FAILURE_MARKER, script)
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
            "printf '%s\\n%s' '8.8.8.8' '1.1.1.0/24'",
            script,
        )
        self.assertIn("syswarden_saas_monitors.ipv4", script)
        self.assertIn("syswarden_saas_monitors.ipv6", script)
        self.assertIn("syswarden_saas_monitors.pair", script)
        self.assertIn("syswarden-saas-pair-v1", script)
        self.assertIn(
            "7337141ed136cb92b166db379d6bd2ceba3ddf64cef41583e469485e0048dedc",
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
            'operator_listener_pid_path="${PERSIST_ROOT}/operator-62027.pid"',
            probe,
        )
        self.assertIn("0:0:600", probe)
        self.assertIn('kill -0 "${operator_listener_pid}"', probe)
        self.assertIn("TCP4:127.0.0.1:62027", probe)
        self.assertNotIn("upgrade-rollback:restart-one", listener_requirement)
        self.assertNotIn("upgrade-rollback:restart-two", listener_requirement)
        self.assertNotIn("upgrade-rollback:recovery", listener_requirement)
        self.assertNotIn("remove:fresh", listener_requirement)
        self.assertNotIn("purge:fresh", listener_requirement)
        self.assertIn(
            "(umask 077 && printf '%s\\n' \"${operator_listener_pid}\" > "
            '"${PERSIST_ROOT}/operator-62027.pid")',
            script,
        )
        self.assertIn(
            'SEEDED_OPERATOR_LISTENER_PID="${operator_listener_pid}"',
            script,
        )
        self.assertIn("SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY", script)
        self.assertIn("SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY", script)
        self.assertIn("SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY", script)
        self.assertIn("operator_listener_socket_identity", probe)
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

    def test_v4032_to_v4033_skips_only_the_impossible_live_webtui_seed(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        guard_start = source.index("v4032_to_v4033_upgrade_selected() {")
        guard_end = source.index(
            "\n}\n\nattest_v4032_previous_webtui_retirement() {", guard_start
        ) + 2
        guard = source[guard_start:guard_end]
        transition_start = source.index(
            "v4032_to_v4033_transition_selected() {"
        )
        transition_end = source.index(
            "\n}\n\nexpected_systemd_enablement_prefix() {", transition_start
        ) + 2
        transition = source[transition_start:transition_end]
        seed_start = source.index("seed_live_legacy_webtui_process() {")
        seed_end = source.index("\n}\n\nload_state_contract() {", seed_start) + 2
        seed = source[seed_start:seed_end]
        scenario_start = source.index("scenario_upgrade_rollback_initial() {")
        scenario_end = source.index(
            "\n}\n\nscenario_upgrade_rollback_restart_one() {", scenario_start
        ) + 2
        scenario = source[scenario_start:scenario_end]

        exact_skip = (
            "if v4032_to_v4033_upgrade_selected; then\n"
            "        return 0\n"
            "    fi"
        )
        self.assertEqual(seed.count(exact_skip), 1)
        self.assertLess(
            seed.index(exact_skip),
            seed.index("/opt/syswarden/bin/syswarden-cli web-tui"),
        )
        self.assertLess(
            scenario.index("seed_legacy_webtui_upgrade_state || return"),
            scenario.index("seed_live_legacy_webtui_process || return"),
        )
        self.assertLess(
            scenario.index("seed_live_legacy_webtui_process || return"),
            scenario.index('run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}"'),
        )

        command = "/opt/syswarden/bin/syswarden-cli web-tui"
        self.assertEqual(seed.count(command), 1)
        fake_command = self.root / "legacy-webtui-command"
        fake_command.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" > \"${TEST_LIVE_SEED_MARKER}\"\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake_command.chmod(0o700)
        fake_bin = self.root / "live-seed-bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text("#!/bin/sh\nprintf '%s' 000\n", encoding="utf-8")
        fake_curl.chmod(0o700)
        seed_log = self.root / "legacy-webtui-process.log"
        seed = seed.replace(command, f"{shlex.quote(str(fake_command))} web-tui")
        seed = seed.replace(
            "/tmp/syswarden-legacy-webtui-process.log", str(seed_log)
        )
        persist = self.root / "live-seed-persist"
        persist.mkdir()
        marker = self.root / "live-seed-invoked"
        harness = (
            "#!/bin/sh\nset -u\n"
            + transition
            + "\n"
            + guard
            + "\n"
            + seed
            + r'''
installed_version() {
    printf '%s\n' "${TEST_INSTALLED_VERSION}"
}
record_lifecycle_seed_failure() {
    :
}
stop_lifecycle_seed_process() {
    wait "$1" 2>/dev/null || true
}
seed_live_legacy_webtui_process
'''
        )

        def run_case(
            *,
            family: str = "deb",
            scenario_name: str = "upgrade-rollback",
            previous: str = "4.03.2",
            candidate: str = "4.03.3",
            installed: str = "4.03.2",
        ) -> subprocess.CompletedProcess[str]:
            marker.unlink(missing_ok=True)
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "PACKAGE_FAMILY": family,
                "SCENARIO": scenario_name,
                "EXPECTED_PREVIOUS_VERSION": previous,
                "EXPECTED_CANDIDATE_VERSION": candidate,
                "TEST_INSTALLED_VERSION": installed,
                "TEST_LIVE_SEED_MARKER": str(marker),
                "PERSIST_ROOT": str(persist),
            }
            return subprocess.run(
                [shutil.which("dash") or "/bin/sh", "-c", harness],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

        for family in ("deb", "rpm"):
            with self.subTest(exact_family=family):
                exact = run_case(family=family)
                self.assertEqual(exact.returncode, 0, exact.stderr)
                self.assertFalse(marker.exists())

        bounds = (
            ("scenario", {"scenario_name": "remove"}),
            ("previous", {"previous": "4.03.1"}),
            ("candidate", {"candidate": "4.03.4"}),
            ("installed", {"installed": "4.03.1"}),
        )
        for label, overrides in bounds:
            with self.subTest(bound=label):
                rejected = run_case(**overrides)
                self.assertNotEqual(rejected.returncode, 0, rejected.stderr)
                self.assertTrue(marker.is_file())

        apk = run_case(family="apk", previous="4.02.8")
        self.assertEqual(apk.returncode, 0, apk.stderr)
        self.assertFalse(marker.exists())

    def test_lifecycle_seed_failure_diagnostic_is_bounded_hex_and_fail_closed(
        self,
    ) -> None:
        source = package_lifecycle_lab.LIFECYCLE_SCRIPT
        start = source.index("lifecycle_seed_hex_prefix() {")
        end = source.index("\nseed_legacy_webtui_upgrade_state() {", start)
        helper = source[start:end]
        command_log = self.root / "seed-command.log"
        operator_log = self.root / "syswarden-operator-62027.log"
        operator_log.write_bytes(b"private-fixture\n" + b"x" * 4096)
        helper = helper.replace(
            "/tmp/syswarden-operator-62027.log", str(operator_log)
        )
        invocation = (
            helper
            + '\nCOMMAND_LOG="$1"\n'
            + ': > "${COMMAND_LOG}"\n'
            + 'record_lifecycle_seed_failure "$2" 1 "$3" expected "$4"\n'
        )
        valid = subprocess.run(
            [
                "/bin/sh",
                "-c",
                invocation,
                "seed-diagnostic",
                str(command_log),
                "LS01_OPERATOR_LISTENER_READY",
                "ready=0|alive=0",
                str(operator_log),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        diagnostic = command_log.read_text(encoding="utf-8")
        self.assertIn(
            package_lifecycle_lab.SEED_FAILURE_MARKER
            + "\tpredicate=LS01_OPERATOR_LISTENER_READY\trc=1",
            diagnostic,
        )
        self.assertNotIn("private-fixture", diagnostic)
        log_prefix = diagnostic.split("\tlog_hex_prefix=", 1)[1].rstrip("\n")
        self.assertEqual(len(log_prefix), 512)

        adversarial = {
            "predicate": ("INVALID", "actual", operator_log),
            "oversized_actual": (
                "LS01_OPERATOR_LISTENER_READY",
                "x" * 257,
                operator_log,
            ),
        }
        for name, (predicate, actual, log_path) in adversarial.items():
            with self.subTest(name=name):
                rejected = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        invocation,
                        "seed-diagnostic",
                        str(command_log),
                        predicate,
                        actual,
                        str(log_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(rejected.returncode, 97, rejected)

        log_target = self.root / "seed-log-target"
        log_target.write_text("target\n", encoding="utf-8")
        operator_log.unlink()
        operator_log.symlink_to(log_target)
        symlink = subprocess.run(
            [
                "/bin/sh",
                "-c",
                invocation,
                "seed-diagnostic",
                str(command_log),
                "LS01_OPERATOR_LISTENER_READY",
                "actual",
                str(operator_log),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(symlink.returncode, 97, symlink)

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
                + "SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY=socket-a\n"
                + "operator_listener_matches_seeded_proof 101 process-a pidfile-a socket-a\n"
                + "if operator_listener_matches_seeded_proof 202 process-b pidfile-b socket-b; then exit 11; fi\n"
                + "if operator_listener_matches_seeded_proof 101 process-b pidfile-a socket-a; then exit 12; fi\n"
                + "if operator_listener_matches_seeded_proof 101 process-a pidfile-b socket-a; then exit 13; fi\n"
                + "if operator_listener_matches_seeded_proof 101 process-a pidfile-a socket-b; then exit 15; fi\n"
                + "unset SEEDED_OPERATOR_LISTENER_PID\n"
                + "if operator_listener_matches_seeded_proof 101 process-a pidfile-a socket-a; then exit 14; fi\n",
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
                    "bash-completion", "wireguard-tools", "jq",
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
                    "openrc", "cronie", "cronie-openrc",
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
        self.assertNotIn("epel-release", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertNotIn("qrencode", package_lifecycle_lab.RPM_BOOTSTRAP)
        self.assertIn(
            "apk add --no-cache openrc openrc-init && apk add --no-cache",
            package_lifecycle_lab.APK_BOOTSTRAP,
        )
        self.assertIn("test -x /usr/bin/gpasswd", package_lifecycle_lab.APK_BOOTSTRAP)

    def test_v4032_rpm_transition_restores_only_historical_lab_dependencies(
        self,
    ) -> None:
        fedora = next(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.distribution == "fedora"
        )
        alma = next(
            spec
            for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
            if spec.distribution == "almalinux"
        )
        common_images = {
            spec.distribution: (
                f"localhost/syswarden-lifecycle-{package_lifecycle_lab.platform_slug(spec)}-"
                + "a" * 32
            )
            for spec in (fedora, alma)
        }
        fedora_common = package_lifecycle_lab.build_containerfile(fedora)
        alma_common = package_lifecycle_lab.build_containerfile(alma)
        for common in (fedora_common, alma_common):
            self.assertNotIn("dnf -y install qrencode", common)
            self.assertNotIn("dnf -y install epel-release", common)
            self.assertIn(
                "! rpm -q qrencode >/dev/null 2>&1 && "
                "! rpm -q epel-release >/dev/null 2>&1",
                common,
            )

        fedora_v4032 = package_lifecycle_lab.build_historical_transition_containerfile(
            fedora, "4.03.2", common_images["fedora"]
        )
        alma_v4032 = package_lifecycle_lab.build_historical_transition_containerfile(
            alma, "4.03.2", common_images["almalinux"]
        )
        self.assertIsInstance(fedora_v4032, str)
        self.assertIsInstance(alma_v4032, str)
        assert fedora_v4032 is not None
        assert alma_v4032 is not None
        self.assertTrue(fedora_v4032.startswith(f"FROM {common_images['fedora']}\n"))
        self.assertTrue(alma_v4032.startswith(f"FROM {common_images['almalinux']}\n"))
        self.assertIn(
            "RUN dnf -y install qrencode && rpm -q qrencode >/dev/null && "
            "! rpm -q epel-release >/dev/null 2>&1 && dnf clean all\n",
            fedora_v4032,
        )
        self.assertIn(
            "RUN dnf -y install epel-release && dnf -y install qrencode && "
            "rpm -q epel-release >/dev/null && rpm -q qrencode >/dev/null && "
            "dnf clean all\n",
            alma_v4032,
        )

        for spec in (fedora, alma):
            with self.subTest(distribution=spec.distribution, previous="4.03.3"):
                self.assertIsNone(
                    package_lifecycle_lab.build_historical_transition_containerfile(
                        spec, "4.03.3", common_images[spec.distribution]
                    )
                )
        for spec in package_lifecycle_lab.DEFAULT_PLATFORMS:
            if spec.family == "rpm":
                continue
            with self.subTest(distribution=spec.distribution):
                self.assertEqual(
                    package_lifecycle_lab.historical_transition_bootstrap(
                        spec, "4.03.2"
                    ),
                    "",
                )

        unsupported = replace(fedora, distribution="unsupported-rpm")
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "unsupported RPM distribution",
        ):
            package_lifecycle_lab.historical_transition_bootstrap(
                unsupported, "4.03.2"
            )

        for spec in (fedora, alma):
            with self.subTest(distribution=spec.distribution, routing=True):
                runner = FakePodmanRunner()
                transition = package_lifecycle_lab.historical_transition_bootstrap(
                    spec, "4.03.2"
                )
                with mock.patch.object(
                    package_lifecycle_lab,
                    "historical_transition_bootstrap",
                    return_value=transition,
                ):
                    report = package_lifecycle_lab.run_lab(
                        self.args(),
                        runner=runner,
                        platforms=(spec,),
                        host_architecture="x86_64",
                    )
                self.assertEqual(
                    report["platforms"][0]["status"],
                    "pass",
                    report["platforms"][0],
                )
                builds = [call for call in runner.calls if call[1] == "build"]
                self.assertEqual(len(builds), 2)
                common_tag = builds[0][builds[0].index("--tag") + 1]
                historical_tag = builds[1][builds[1].index("--tag") + 1]
                self.assertNotEqual(common_tag, historical_tag)
                self.assertTrue(historical_tag.endswith("-historical-upgrade"))
                creates = [
                    call
                    for call in runner.calls
                    if call[1] == "create"
                    and any(value.endswith(":/results:rw") for value in call)
                ]
                scenario_images = {
                    next(
                        value.removeprefix("SCENARIO=")
                        for index, value in enumerate(call)
                        if call[index - 1] == "--env"
                        and value.startswith("SCENARIO=")
                    ): call[-1]
                    for call in creates
                }
                self.assertEqual(
                    scenario_images,
                    {
                        "upgrade-rollback": historical_tag,
                        "remove": common_tag,
                    },
                )
                removed_tags = [
                    call[-1]
                    for call in runner.calls
                    if call[1:3] == ("image", "rm")
                ]
                self.assertEqual(removed_tags, [historical_tag, common_tag])
                for tag in (common_tag, historical_tag):
                    self.assertIn(
                        ("podman", "image", "exists", tag), runner.calls
                    )

    def test_failed_event_fails_platform_and_overall_report(self) -> None:
        runner = FakePodmanRunner(event_status="fail")
        report = package_lifecycle_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(all(item["status"] == "fail" for item in report["platforms"]))

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
        self.assertEqual(len(report["scope"]["missing_platform_coordinates"]), 6)
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
                    stdout=f"{digest}\tlinux/unsupported\n",
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

    def test_parser_exposes_digest_pinned_amd64_images(self) -> None:
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
        self.assertEqual(
            args.qualification_matrix,
            package_lifecycle_lab.QUALIFICATION_MATRIX_PATH,
        )
        self.assertEqual(len(configured), 8)
        self.assertEqual(
            {package_lifecycle_lab.platform_coordinate(spec) for spec in configured},
            package_lifecycle_lab.REQUIRED_PLATFORM_COORDINATES,
        )
        self.assertTrue(all("@sha256:" in spec.image for spec in configured))

        amd64_shard = parser.parse_args(
            (
                "--packages-dir",
                str(self.candidate),
                "--previous-packages-dir",
                str(self.previous),
                "--architecture-shard",
                "amd64",
            )
        )
        shard_configured = package_lifecycle_lab.configured_platforms(amd64_shard)
        self.assertEqual(len(shard_configured), 8)
        self.assertEqual(
            {spec.architecture for spec in shard_configured},
            {"amd64"},
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
                "--ubuntu-amd64-image",
                replacement_image,
            )
        )
        ubuntu_amd64 = next(
            spec
            for spec in package_lifecycle_lab.configured_platforms(overridden)
            if package_lifecycle_lab.platform_coordinate(spec)
            == ("DEB-U2404", "amd64")
        )
        self.assertEqual(ubuntu_amd64.image, replacement_image)
        with self.assertRaisesRegex(
            package_lifecycle_lab.LifecycleLabError,
            "frozen image identity mismatch",
        ):
            package_lifecycle_lab.validate_platforms(
                package_lifecycle_lab.configured_platforms(overridden)
            )


if __name__ == "__main__":
    unittest.main()
