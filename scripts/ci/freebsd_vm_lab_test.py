#!/usr/bin/env python3
"""Unit tests for the fail-closed FreeBSD VM package/PF laboratory."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import freebsd_vm_lab


TOKEN = "".join(("0123456789abcdef", "0123456789abcdef"))
PF_FIXTURE_TEXT = "pass in quick on vtnet-test0 proto tcp to any port 22\n"
PF_FIXTURE_SHA256 = hashlib.sha256(PF_FIXTURE_TEXT.encode("utf-8")).hexdigest()
ANCHOR_NONCE = "d" * 32
ANCHOR_NAME = f"syswarden_lot0_{ANCHOR_NONCE}"
RESTART_METADATA_INVENTORY = "\n".join(
    (
        "/etc/syswarden\tDirectory\t755\t0\t0\t-",
        "/etc/syswarden/config\tDirectory\t750\t0\t0\t-",
        "/etc/syswarden/config/lifecycle-user.conf\tRegular File\t600\t0\t0\t-",
        "/usr/local/bin/syswarden\tSymbolic Link\t755\t0\t0\t/usr/local/syswarden/bin/syswarden-cli",
        "/usr/local/syswarden/bin/syswarden-cli\tRegular File\t750\t0\t0\t-",
    )
)


def marker_output(values: dict[str, str]) -> str:
    lines = []
    for key, value in values.items():
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        lines.append(f"SWL0\t{key}\t{encoded}")
    return "\n".join(lines) + "\n"


def carries_script(input_text: str | None, script: str) -> bool:
    return bool(input_text and input_text.endswith(script + "\n"))


def passing_evidence() -> dict[str, str]:
    values = {key: "1" for key in freebsd_vm_lab.EVIDENCE_KEYS}
    values.update(
        {
            "ROOT_UID": "0",
            "OS_NAME": "FreeBSD",
            "OS_RELEASE": "14.4-RELEASE-p2",
            "MACHINE": "amd64",
            "DEPENDENCIES_INSTALL_RC": "0",
            "DEPENDENCY_INVENTORY": "\n".join(
                sorted(freebsd_vm_lab.EXPECTED_FREEBSD_DEPENDENCIES)
            ),
            "PREVIOUS_PACKAGE_SHA256": "b" * 64,
            "CANDIDATE_PACKAGE_SHA256": "a" * 64,
            "PF_BASELINE_STATUS": "Disabled",
            "PF_SNAPSHOT_PROVENANCE": "exact_live",
            "PF_INITIAL_KLDLOAD_RC": "0",
            "PF_ABSENT_INSTALL_RC": "0",
            "PF_ABSENT_INSTALL_POSTINSTALL_MARKER_STATE": (
                freebsd_vm_lab.EXPECTED_POSTINSTALL_MARKER_STATE
            ),
            "PF_ABSENT_INSTALL_DIAGNOSTICS_CLEAN": "1",
            "PF_ABSENT_SNAPSHOT_SCHEMA_VERSION": "2",
            "PF_ABSENT_SNAPSHOT_PROVENANCE": "exact_live",
            "PF_ABSENT_SNAPSHOT_INITIAL_KERNEL_STATE": "module_absent",
            "PF_ABSENT_SNAPSHOT_MUTATION_STARTED": "true",
            "PF_ABSENT_POLICY_STATUS": "Enabled",
            "PF_ABSENT_POLICY_RULE_COUNT": "20",
            "PF_ABSENT_DELETE_RC": "0",
            "PF_ABSENT_DELETE_DIAGNOSTICS_CLEAN": "1",
            "PF_ABSENT_DELETE_CONFIGURED_STATUS": "Disabled",
            "PF_ABSENT_DELETE_PROBE_LOAD_RC": "0",
            "PF_ABSENT_DELETE_PROBE_STATUS": "Disabled",
            "PF_ABSENT_DELETE_PROBE_UNLOAD_RC": "0",
            "PF_FINAL_GUEST_KLDUNLOAD_RC": "0",
            "PF_FRESH_CAPTURE_RC": "0",
            "PF_FRESH_PROVENANCE": "exact_live",
            "PF_FRESH_RESTORE_RC": "0",
            "PF_NONEMPTY_SEED_APPLY_RC": "0",
            "PF_NONEMPTY_CAPTURE_REJECTED": "1",
            "PF_NONEMPTY_ANCHOR_PRESERVED": "1",
            "PF_NONEMPTY_FILTER_PRESERVED": "1",
            "PF_NONEMPTY_NAT_PRESERVED": "1",
            "PF_NONEMPTY_TABLES_PRESERVED": "1",
            "PF_NONEMPTY_STATUS_PRESERVED": "1",
            "PF_NONEMPTY_STATE_PRESERVED": "1",
            "MIGRATION_BACKUP_BASELINE": freebsd_vm_lab.EXPECTED_MIGRATION_BACKUP_STATE,
            "PF_FINAL_STATUS": "Disabled",
            "PF_SNAPSHOT_SHA256": hashlib.sha256(b"").hexdigest(),
            "PF_FIXTURE_SHA256": PF_FIXTURE_SHA256,
            "PF_FIXTURE_SHA_MATCH": "1",
            "PF_ANCHOR_NAME": ANCHOR_NAME,
            "LAB_LOCK_ACQUIRED": "1",
            "LAB_LOCK_RELEASED": "1",
            "RESTART_BASELINE_INVENTORY": RESTART_METADATA_INVENTORY,
            "RESTART_ONE_INVENTORY": RESTART_METADATA_INVENTORY,
            "RESTART_TWO_INVENTORY": RESTART_METADATA_INVENTORY,
            "RSYSLOG_CONFIG_VALIDATE_RC": "0",
            "RSYSLOG_ENABLED": "YES",
            "RSYSLOG_STATUS_RC": "0",
            "SYSLOGD_INACTIVE": "1",
            "LOG_BASELINE_SYSLOGD_STATUS_RC": "0",
            "LOG_BASELINE_RSYSLOGD_STATUS_RC": "1",
            "LOG_BASELINE_SYSLOGD_ENABLE": "present:YES",
            "LOG_BASELINE_RSYSLOGD_ENABLE": "absent",
            "LOG_BASELINE_RSYSLOGD_PIDFILE": "absent",
            "CRON_ALLOW_BASELINE": f"file:{'c' * 64}:600:0:0",
            "CRON_DENY_BASELINE": f"file:{'d' * 64}:600:0:0",
            "MODE_CLI": "750",
            "MODE_CORE": "750",
            "MODE_TUI": "750",
            "MODE_SIGNATURES": "640",
            "LINK_CLI": "/usr/local/syswarden/bin/syswarden-cli",
            "LINK_TUI": "/usr/local/syswarden/bin/syswarden-tui",
            "CLI_DIRECT_RC": "0",
            "CLI_LINK_RC": "0",
            "TUI_REINSTALL_RC": "124",
            "TUI_RECOVERY_RC": "124",
            "RC_CORE_MODE": "755",
            "RC_WEB_MODE": "755",
            "RC_CORE_COMMAND": "/usr/local/syswarden/bin/syswarden-core",
            "RC_WEB_COMMAND": "/usr/local/syswarden/bin/syswarden-cli",
            "RC_CORE_ENABLED": "YES",
            "RC_WEB_ENABLED": "YES",
            "UPGRADE_RC_CORE_ENABLED": "YES",
            "UPGRADE_RC_WEB_ENABLED": "YES",
            "UPGRADE_RC_CORE_STATUS_RC": "0",
            "UPGRADE_RC_WEB_STATUS_RC": "0",
            "RC_CORE_START_RC": "0",
            "RC_CORE_STATUS_RC": "0",
            "RC_CORE_RESTART_ONE_RC": "0",
            "RC_CORE_RESTART_ONE_STATUS_RC": "0",
            "RC_CORE_RESTART_TWO_RC": "0",
            "RC_CORE_RESTART_TWO_STATUS_RC": "0",
            "RC_WEB_START_RC": "0",
            "RC_WEB_STATUS_RC": "0",
            "RC_WEB_RESTART_ONE_RC": "0",
            "RC_WEB_RESTART_ONE_STATUS_RC": "0",
            "RC_WEB_RESTART_TWO_RC": "0",
            "RC_WEB_RESTART_TWO_STATUS_RC": "0",
            "PF_INTERFACE": "vtnet0",
            "PF_FIXTURE_SYNTAX_RC": "0",
            "PF_FIXTURE_APPLY_RC": "0",
            "PF_FIXTURE_RULE_COUNT": "24",
            "PF_HONEYPORT_SOURCE_BAD": "0",
            "PF_HONEYPORT_EXACT_VALUE": "23, 6379",
            "PF_HONEYPORT_SYNTAX_RC": "0",
            "REMOVE_RC": "0",
            "REMOVE_PKG_INVENTORY": "",
            "REMOVE_USER_STATE_INVENTORY": "\n".join(
                sorted(freebsd_vm_lab.EXPECTED_USER_STATE_INVENTORY)
            ),
            "REMOVE_USER_CONFIG_SHA256": freebsd_vm_lab.USER_CONFIG_SHA256,
            "REMOVE_USER_DATA_SHA256": freebsd_vm_lab.USER_DATA_SHA256,
            "REMOVE_MIGRATION_BACKUP_STATE": freebsd_vm_lab.EXPECTED_MIGRATION_BACKUP_STATE,
            "REMOVE_SYSLOGD_STATUS_RC": "0",
            "REMOVE_RSYSLOGD_STATUS_RC": "1",
            "REMOVE_SYSLOGD_ENABLE": "present:YES",
            "REMOVE_RSYSLOGD_ENABLE": "absent",
            "REMOVE_RSYSLOGD_PIDFILE": "absent",
            "REMOVE_LOGGING_BASELINE_RESTORED": "1",
            "REMOVE_CRON_ALLOW_STATE": f"file:{'c' * 64}:600:0:0",
            "REMOVE_CRON_DENY_STATE": f"file:{'d' * 64}:600:0:0",
            "REMOVE_CRON_ACCESS_PRESERVED": "1",
            "REMOVE_HOST_STATE_ABSENT": "1",
            "REMOVE_PF_STATUS": "Disabled",
            "REMOVE_PF_SNAPSHOT_SHA256": hashlib.sha256(b"").hexdigest(),
            "REMOVE_PF_BASELINE_RESTORED": "1",
            "REMOVE_PF_SYSWARDEN_TABLE_ABSENT": "1",
        }
    )
    for phase, version in (
        ("PREVIOUS_INSTALL", "4.02.7"),
        ("CANDIDATE_UPGRADE", "4.02.8"),
        ("CANDIDATE_REINSTALL", "4.02.8"),
        ("CANDIDATE_RESTART_IDEMPOTENCE", "4.02.8"),
        ("PREVIOUS_ROLLBACK", "4.02.7"),
    ):
        values.update(
            {
                f"{phase}_OPERATION_RC": "0",
                f"{phase}_PKG_INSTALLED": "1",
                f"{phase}_PKG_NAME": "syswarden",
                f"{phase}_PKG_VERSION": version,
                f"{phase}_PKG_ARCH": "FreeBSD:14:amd64",
                f"{phase}_PKG_INVENTORY": "\n".join(
                    sorted(freebsd_vm_lab.EXPECTED_PACKAGE_INVENTORY)
                ),
                f"{phase}_ELF_CLI_ARCH": "amd64",
                f"{phase}_ELF_CORE_ARCH": "amd64",
                f"{phase}_ELF_TUI_ARCH": "amd64",
                f"{phase}_USER_STATE_INVENTORY": "\n".join(
                    sorted(freebsd_vm_lab.EXPECTED_USER_STATE_INVENTORY)
                ),
                f"{phase}_USER_CONFIG_SHA256": freebsd_vm_lab.USER_CONFIG_SHA256,
                f"{phase}_USER_DATA_SHA256": freebsd_vm_lab.USER_DATA_SHA256,
                f"{phase}_SIGNATURE_RULE_COUNT": str(
                    freebsd_vm_lab.EXPECTED_SIGNATURE_RULE_COUNT
                ),
                f"{phase}_SIGNATURE_ENGINE_COUNT": str(
                    freebsd_vm_lab.EXPECTED_ENGINE_SIGNATURE_COUNT
                ),
                f"{phase}_SIGNATURE_PROBE_RC": "124",
                f"{phase}_SIGNATURE_LOAD_ERROR": "0",
                f"{phase}_SIGNATURE_STATE_BEFORE": "absent",
                f"{phase}_SIGNATURE_STATE_AFTER": "absent",
                f"{phase}_SIGNATURE_STATE_RESTORED": "1",
                f"{phase}_POSTINSTALL_MARKER_STATE": freebsd_vm_lab.EXPECTED_POSTINSTALL_MARKER_STATE,
                f"{phase}_POSTINSTALL_DIAGNOSTICS_CLEAN": "1",
                f"{phase}_MODULAR_CONFIG_INVENTORY": "\n".join(
                    sorted(freebsd_vm_lab.EXPECTED_MODULAR_CONFIG_INVENTORY)
                ),
            }
        )
    return values


class FakeRunner(freebsd_vm_lab.CommandRunner):
    def __init__(self, evidence: dict[str, str]) -> None:
        self.evidence = evidence
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def run(
        self,
        args: tuple[str, ...],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> freebsd_vm_lab.CommandResult:
        del timeout
        command = tuple(args)
        self.calls.append((command, input_text))
        stdout = ""
        if command[0] == "ssh" and carries_script(
            input_text, freebsd_vm_lab.PROBE_SCRIPT
        ):
            stdout = marker_output(
                {
                    "MARKER_MATCH": "1",
                    "MARKER_SAFE": "1",
                    "OS_NAME": "FreeBSD",
                    "OS_RELEASE": "14.4-RELEASE-p2",
                    "MACHINE": "amd64",
                    "SUDO_READY": "1",
                    "BASE64_READY": "1",
                }
            )
        elif command[0] == "ssh" and carries_script(
            input_text, freebsd_vm_lab.REMOTE_LAB_SCRIPT
        ):
            evidence = dict(self.evidence)
            evidence["PF_ANCHOR_NAME"] = f"syswarden_lot0_{command[-2]}"
            stdout = marker_output(evidence)
        return freebsd_vm_lab.CommandResult(command, 0, stdout, "")


class FailingCopyRunner(FakeRunner):
    def run(
        self,
        args: tuple[str, ...],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> freebsd_vm_lab.CommandResult:
        result = super().run(args, timeout=timeout, input_text=input_text)
        if args[0] == "scp":
            return freebsd_vm_lab.CommandResult(tuple(args), 1, "", "copy failed")
        return result


class SequencedCleanupRunner(FakeRunner):
    def __init__(
        self,
        evidence: dict[str, str],
        cleanup_outcomes: list[int | BaseException],
        *,
        remote_returncode: int = 0,
        remote_stdout: str | None = None,
    ) -> None:
        super().__init__(evidence)
        self.cleanup_outcomes = list(cleanup_outcomes)
        self.remote_returncode = remote_returncode
        self.remote_stdout = remote_stdout

    def run(
        self,
        args: tuple[str, ...],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> freebsd_vm_lab.CommandResult:
        result = super().run(args, timeout=timeout, input_text=input_text)
        if carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT):
            if not self.cleanup_outcomes:
                raise AssertionError("unexpected cleanup attempt")
            outcome = self.cleanup_outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return freebsd_vm_lab.CommandResult(
                tuple(args),
                outcome,
                f"untrusted-cleanup-stdout-{TOKEN}",
                f"untrusted-cleanup-stderr-{TOKEN}",
            )
        if carries_script(input_text, freebsd_vm_lab.REMOTE_LAB_SCRIPT):
            stdout = result.stdout
            if self.remote_stdout is not None:
                stdout = self.remote_stdout
            return freebsd_vm_lab.CommandResult(
                tuple(args),
                self.remote_returncode,
                stdout,
                f"untrusted-remote-stderr-{TOKEN}",
            )
        return result


class FailingCopySequencedCleanupRunner(SequencedCleanupRunner):
    def run(
        self,
        args: tuple[str, ...],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> freebsd_vm_lab.CommandResult:
        result = super().run(args, timeout=timeout, input_text=input_text)
        if args[0] == "scp":
            return freebsd_vm_lab.CommandResult(
                tuple(args), 1, f"copy stdout {TOKEN}", f"copy failed {TOKEN}"
            )
        return result


class FreeBSDVMLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.packages = self.root / "packages"
        self.previous_packages = self.root / "previous-packages"
        self.repo.mkdir()
        self.packages.mkdir()
        self.previous_packages.mkdir()

        fixture = self.repo / "testdata/firewall/pf-v4.02.8.conf"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(
            PF_FIXTURE_TEXT,
            encoding="utf-8",
        )
        source = (
            self.repo
            / "src/core/syswarden-cli/pkg/firewall/firewall_freebsd.go"
        )
        source.parent.mkdir(parents=True)
        source.write_text(
            "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)\n",
            encoding="utf-8",
        )

        self.package = self.packages / "syswarden-4.02.8.txz"
        self.package.write_bytes(b"synthetic FreeBSD package")
        self.package_sha = hashlib.sha256(self.package.read_bytes()).hexdigest()
        (self.packages / "SHA256SUMS.txt").write_text(
            f"{self.package_sha}  {self.package.name}\n", encoding="utf-8"
        )
        self.previous_package = (
            self.previous_packages / "syswarden-4.02.7.txz"
        )
        self.previous_package.write_bytes(b"synthetic previous FreeBSD package")
        self.previous_package_sha = hashlib.sha256(
            self.previous_package.read_bytes()
        ).hexdigest()
        (self.previous_packages / "SHA256SUMS.txt").write_text(
            f"{self.previous_package_sha}  {self.previous_package.name}\n",
            encoding="utf-8",
        )

        self.identity = self.root / "id_ed25519"
        self.identity.write_text("synthetic private key\n", encoding="utf-8")
        self.identity.chmod(0o600)
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text(
            "[127.0.0.1]:2222 ssh-ed25519 AAAAsynthetic\n",
            encoding="utf-8",
        )
        self.marker_token_file = self.root / "marker-token"
        self.marker_token_file.write_text(TOKEN + "\n", encoding="ascii")
        self.marker_token_file.chmod(0o600)

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "repo_root": self.repo,
            "packages_dir": self.packages,
            "previous_packages_dir": self.previous_packages,
            "ssh_host": "127.0.0.1",
            "ssh_port": 2222,
            "ssh_user": "syswarden",
            "identity_file": self.identity,
            "known_hosts_file": self.known_hosts,
            "vm_marker_token": None,
            "vm_marker_token_file": self.marker_token_file,
            "ssh": "ssh",
            "scp": "scp",
            "command_timeout": 600,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def artifact(self) -> freebsd_vm_lab.PackageArtifact:
        return freebsd_vm_lab.PackageArtifact(
            self.package, "4.02.8", self.package_sha
        )

    def previous_artifact(self) -> freebsd_vm_lab.PackageArtifact:
        return freebsd_vm_lab.PackageArtifact(
            self.previous_package, "4.02.7", self.previous_package_sha
        )

    def forward_candidate_artifact(self) -> freebsd_vm_lab.PackageArtifact:
        return freebsd_vm_lab.PackageArtifact(
            self.root / "syswarden-4.02.15.txz", "4.02.15", self.package_sha
        )

    def forward_previous_artifact(self) -> freebsd_vm_lab.PackageArtifact:
        return freebsd_vm_lab.PackageArtifact(
            self.root / freebsd_vm_lab.FORWARD_ONLY_PREVIOUS_PACKAGE,
            freebsd_vm_lab.FORWARD_ONLY_PREVIOUS_VERSION,
            freebsd_vm_lab.FORWARD_ONLY_PREVIOUS_SHA256,
        )

    def test_discovers_exact_txz_and_verifies_checksum(self) -> None:
        artifact = freebsd_vm_lab.discover_package(self.packages)
        self.assertEqual(artifact.path, self.package)
        self.assertEqual(artifact.version, "4.02.8")
        self.assertEqual(artifact.sha256, self.package_sha)
        candidate, previous = freebsd_vm_lab.discover_package_pair(
            self.packages, self.previous_packages
        )
        self.assertEqual(candidate, self.artifact())
        self.assertEqual(previous, self.previous_artifact())

    def test_candidate_v40215_requires_exact_dependency_manifest(self) -> None:
        self.package.unlink()
        candidate = self.packages / "syswarden-4.02.15.txz"
        candidate.write_bytes(b"candidate with dependency gate")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        (self.packages / "SHA256SUMS.txt").write_text(
            f"{digest}  {candidate.name}\n", encoding="utf-8"
        )
        with mock.patch.object(
            freebsd_vm_lab.freebsd_package_manifest,
            "verify",
            side_effect=ValueError("missing deps"),
        ):
            with self.assertRaisesRegex(
                freebsd_vm_lab.FreeBSDVMLabError,
                "dependency manifest is invalid",
            ):
                freebsd_vm_lab.discover_package_pair(
                    self.packages, self.previous_packages
                )
        with mock.patch.object(
            freebsd_vm_lab.freebsd_package_manifest, "verify"
        ) as verify:
            freebsd_vm_lab.discover_package_pair(
                self.packages, self.previous_packages
            )
            verify.assert_called_once_with(candidate)

    def test_package_pair_is_distinct_ordered_and_independently_checksummed(self) -> None:
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "directories must be distinct"
        ):
            freebsd_vm_lab.discover_package_pair(self.packages, self.packages)

        self.previous_package.write_bytes(self.package.read_bytes())
        duplicate_sha = hashlib.sha256(self.previous_package.read_bytes()).hexdigest()
        (self.previous_packages / "SHA256SUMS.txt").write_text(
            f"{duplicate_sha}  {self.previous_package.name}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "checksums must be distinct"
        ):
            freebsd_vm_lab.discover_package_pair(
                self.packages, self.previous_packages
            )

    def test_forward_only_transition_is_version_name_and_byte_bound(self) -> None:
        candidate = self.forward_candidate_artifact()
        previous = self.forward_previous_artifact()
        self.assertTrue(
            freebsd_vm_lab.is_forward_only_transition(candidate, previous)
        )
        for mutation in (
            freebsd_vm_lab.PackageArtifact(
                previous.path, previous.version, "0" * 64
            ),
            freebsd_vm_lab.PackageArtifact(
                previous.path.with_name("syswarden-4.02.8-copy.txz"),
                previous.version,
                previous.sha256,
            ),
            freebsd_vm_lab.PackageArtifact(
                previous.path, "4.02.7", previous.sha256
            ),
        ):
            with self.subTest(previous=mutation):
                self.assertFalse(
                    freebsd_vm_lab.is_forward_only_transition(candidate, mutation)
                )
                with self.assertRaisesRegex(
                    freebsd_vm_lab.FreeBSDVMLabError,
                    "exact v4.02.8 package bytes",
                ):
                    freebsd_vm_lab.validate_forward_only_binding(
                        candidate, mutation
                    )

        (self.previous_packages / "SHA256SUMS.txt").write_text(
            f"{'0' * 64}  {self.previous_package.name}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "checksum mismatch"
        ):
            freebsd_vm_lab.discover_package_pair(
                self.packages, self.previous_packages
            )

    def test_rejects_checksum_mismatch_and_symlink_package(self) -> None:
        self.package.write_bytes(b"tampered")
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "checksum mismatch"
        ):
            freebsd_vm_lab.discover_package(self.packages)

        self.package.unlink()
        target = self.root / "external.txz"
        target.write_bytes(b"synthetic FreeBSD package")
        self.package.symlink_to(target)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "regular file"
        ):
            freebsd_vm_lab.discover_package(self.packages)

    def test_requires_loopback_explicit_key_marker_and_known_host(self) -> None:
        for host in ("192.0.2.10", "freebsd.example.test"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(
                    freebsd_vm_lab.FreeBSDVMLabError, "loopback"
                ):
                    freebsd_vm_lab.validate_loopback(host)
        self.assertEqual(freebsd_vm_lab.validate_loopback("::1"), "::1")
        self.assertEqual(
            freebsd_vm_lab.validate_loopback("localhost"), "127.0.0.1"
        )

        self.identity.chmod(0o644)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "group/world"
        ):
            freebsd_vm_lab.validate_transport_inputs(
                "127.0.0.1",
                2222,
                "syswarden",
                self.identity,
                self.known_hosts,
                TOKEN,
            )
        self.identity.chmod(0o600)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "32 to 128"
        ):
            freebsd_vm_lab.validate_transport_inputs(
                "127.0.0.1",
                2222,
                "syswarden",
                self.identity,
                self.known_hosts,
                "short",
            )

        self.assertEqual(
            freebsd_vm_lab.resolve_marker_token(self.args()), TOKEN
        )
        self.marker_token_file.chmod(0o644)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "group/world"
        ):
            freebsd_vm_lab.resolve_marker_token(self.args())
        self.marker_token_file.chmod(0o600)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "direct VM marker tokens are disabled"
        ):
            freebsd_vm_lab.resolve_marker_token(
                self.args(vm_marker_token=TOKEN)
            )
        parser_options = freebsd_vm_lab.build_parser()._option_string_actions
        self.assertIn("--vm-marker-token-file", parser_options)
        self.assertNotIn("--vm-marker-token", parser_options)

    def test_ssh_transport_is_pinned_and_scp_is_bounded_to_remote_lab(self) -> None:
        args = freebsd_vm_lab.ssh_arguments(
            "ssh",
            "127.0.0.1",
            2222,
            "syswarden",
            self.identity,
            self.known_hosts,
        )
        joined = " ".join(args)
        self.assertIn("BatchMode=yes", joined)
        self.assertIn("IdentitiesOnly=yes", joined)
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn("ProxyCommand=none", joined)
        self.assertIn("ProxyJump=none", joined)
        self.assertIn("ClearAllForwardings=yes", joined)
        self.assertIn("/dev/null", joined)
        self.assertIn(f"UserKnownHostsFile={self.known_hosts}", joined)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "unsafe remote copy"
        ):
            freebsd_vm_lab.scp_arguments(
                "scp",
                "127.0.0.1",
                2222,
                "syswarden",
                self.identity,
                self.known_hosts,
                self.package,
                "/tmp/not-the-lab/package.txz",
            )
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "ssh transport"
        ):
            freebsd_vm_lab.validate_transport_program("pfctl", "ssh")

    def test_marker_parser_rejects_partial_duplicate_and_untrusted_lines(self) -> None:
        expected = frozenset({"ONE", "TWO"})
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "markers differ"
        ):
            freebsd_vm_lab.parse_markers(marker_output({"ONE": "1"}), expected)
        duplicate = marker_output({"ONE": "1", "TWO": "2"}) + marker_output(
            {"ONE": "again"}
        )
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "duplicate"
        ):
            freebsd_vm_lab.parse_markers(duplicate, expected)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "invalid VM evidence line"
        ) as raised:
            freebsd_vm_lab.parse_markers(
                f"host command output {TOKEN}\n", frozenset()
            )
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_product_report_can_pass_only_with_every_real_contract(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "pass")
        self.assertIs(report["release_ready"], True)
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(report["unexpected_failed_check_ids"], [])
        self.assertEqual(
            set(report["lifecycle_phases"]),
            {
                "previous_install",
                "candidate_upgrade",
                "candidate_reinstall",
                "candidate_restart_idempotence",
                "previous_rollback",
                "remove",
            },
        )
        self.assertEqual(
            report["lifecycle_phases"]["candidate_reinstall"]["signatures"][
                "rule_definitions"
            ],
            "78",
        )

    def test_standalone_txz_prerequisites_are_installed_before_pkg_add(self) -> None:
        refresh = (
            'pkg update -f \\\n'
            '    </dev/null \\\n'
            '    >"$work/repository-update.log" 2>&1'
        )
        prerequisite = (
            'pkg install -y \\\n'
            "    curl jq libqrencode rsyslog wireguard-tools \\\n"
            "    </dev/null"
        )

        def assert_contract(script: str) -> None:
            self.assertEqual(script.count(refresh), 1)
            self.assertEqual(script.count(prerequisite), 1)
            self.assertLess(script.index(refresh), script.index(prerequisite))
            self.assertLess(
                script.index(prerequisite),
                script.index('pkg add -f "$work/$previous_package_name"'),
            )
            self.assertIn(
                "sed -n '1,200p' \"$work/repository-update.log\" >&2\n"
                "    exit 99",
                script,
            )
            self.assertIn(
                "sed -n '1,200p' \"$work/dependencies-install.log\" >&2\n"
                "    exit 97",
                script,
            )

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        with self.assertRaises(AssertionError):
            assert_contract(script.replace(refresh, ": refresh removed", 1))
        self.assertIn("DEPENDENCIES_INSTALL_RC", freebsd_vm_lab.EVIDENCE_KEYS)
        self.assertIn("DEPENDENCY_INVENTORY", freebsd_vm_lab.EVIDENCE_KEYS)

    def test_dependency_and_generated_cleanup_evidence_fail_closed(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["DEPENDENCY_INVENTORY"] = "curl\njq"
        evidence["REMOVE_CRON_REFERENCE_ABSENT"] = "0"
        evidence["REMOVE_RSYSLOG_SIEM_ABSENT"] = "0"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertFalse(report["release_ready"])
        self.assertIn(
            "SW-PKG-FBSD-DEPS-001", report["unexpected_failed_check_ids"]
        )
        self.assertIn(
            "SW-PKG-FBSD-GENERATED-CLEANUP-001",
            report["unexpected_failed_check_ids"],
        )

    def test_freebsd_removal_seeds_and_verifies_dead_reference_cleanup(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        for fragment in (
            "# syswarden-freebsd-lab-preserve",
            "# syswarden-freebsd-lab-operator-preserve",
            "/usr/local/syswarden/bin/syswarden-cli update-feeds",
            "/opt/syswarden/bin/syswarden-cli ha-sync",
            "/opt/syswarden/bin/syswarden-cli update-feeds",
            "/usr/local/etc/rsyslog.d/99-syswarden-siem.conf",
            "/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
            "REMOVE_CRON_REFERENCE_ABSENT",
            "REMOVE_CRON_UNRELATED_PRESERVED",
        ):
            self.assertIn(fragment, script)

    def test_cron_access_and_removal_seed_are_validated_fail_closed(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        allow_seed = "printf '%s\\n' root nobody >/var/cron/allow"
        deny_seed = "printf '%s\\n' 'daemon' >/var/cron/deny"
        access_metadata = (
            'stat -f \'%u:%g:%Lp\' "$cron_access_path" 2>/dev/null)" '
            '!= "0:0:600"'
        )
        round_trip = (
            'validate_root_crontab_round_trip '
            '"$work/cron-access-round-trip"'
        )
        removal_install = (
            'if ! LC_ALL=C crontab - <"$removal_cron_expected" \\\n'
            '    >"$removal_cron_stdout" 2>"$removal_cron_error"; then'
        )
        removal_readback = (
            'cmp -s "$removal_cron_expected" "$removal_cron_readback"'
        )

        def assert_contract(candidate: str) -> None:
            self.assertIn(allow_seed, candidate)
            self.assertIn(deny_seed, candidate)
            self.assertNotIn("'root,nobody'", candidate)
            self.assertIn(access_metadata, candidate)
            self.assertIn('if [ "$(id -un)" != root ]; then', candidate)
            self.assertIn(
                'cmp -s "$work/cron-allow-expected" /var/cron/allow',
                candidate,
            )
            self.assertIn(
                'cmp -s "$work/cron-deny-expected" /var/cron/deny',
                candidate,
            )
            self.assertIn(round_trip, candidate)
            self.assertIn(
                'LC_ALL=C crontab - <"$root_crontab_probe"', candidate
            )
            self.assertIn(
                'cmp -s "$root_crontab_probe" "$root_crontab_after"',
                candidate,
            )
            transaction_start = candidate.index(
                'LC_ALL=C crontab - <"$root_crontab_probe"'
            )
            restoration_start = candidate.index(
                "# Once the probe command has run, restoration is mandatory",
                transaction_start,
            )
            self.assertNotIn(
                "return 1", candidate[transaction_start:restoration_start]
            )
            self.assertIn(
                'cmp -s "$root_crontab_before" "$root_crontab_restored"',
                candidate,
            )
            self.assertIn(
                'if [ "$root_crontab_primary_failed" -ne 0 ] ||',
                candidate,
            )
            self.assertIn(
                '[ "$root_crontab_restore_failed" -ne 0 ]; then',
                candidate,
            )
            self.assertIn(removal_install, candidate)
            self.assertIn(removal_readback, candidate)
            self.assertIn('exit 100', candidate)
            self.assertIn('exit 101', candidate)
            self.assertLess(
                candidate.index(round_trip),
                candidate.index('pkg add -f "$work/$candidate_package_name"'),
            )
            self.assertLess(
                candidate.index(removal_install),
                candidate.index(
                    "pkg delete -fy syswarden", candidate.index(removal_install)
                ),
            )
            self.assertIn(
                "grep -F -x -q \\\n"
                "\t       '17 3 * * * /usr/bin/true "
                "# syswarden-freebsd-lab-preserve'",
                candidate,
            )
            self.assertIn(
                "grep -F -x -q \\\n"
                "\t       '19 4 * * * /usr/local/syswarden/bin/"
                "syswarden-cli update-feeds --operator-option >/dev/null "
                "2>&1 # syswarden-freebsd-lab-operator-preserve'",
                candidate,
            )

        assert_contract(script)
        for mutation in (
            script.replace(
                allow_seed,
                "printf '%s\\n' 'root,nobody' >/var/cron/allow",
                1,
            ),
            script.replace(allow_seed, "printf '%s\\n' nobody >/var/cron/allow", 1),
            script.replace(removal_install, removal_install.removeprefix("if ! "), 1),
            script.replace(removal_readback, ': removal crontab readback ignored', 1),
        ):
            with self.assertRaises(AssertionError):
                assert_contract(mutation)

    def test_crontab_round_trip_restores_state_after_adversarial_failures(
        self,
    ) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        helper_start = script.index("read_root_crontab_state() {")
        helper_end = script.index("probe_signatures() {", helper_start)
        helpers = script[helper_start:helper_end]
        driver = helpers + r'''
set +e
scenario="$1"
test_root="$2"
state="$test_root/state"
initial="$test_root/initial"
incoming="$test_root/incoming"
read_count=0
install_count=0

case "$scenario" in
    *_present)
        printf '%s\n' \
            'SHELL=/bin/sh' \
            '17 3 * * * /usr/bin/true # byte-exact-operator-state' \
            >"$state"
        cp "$state" "$initial"
        ;;
    *_absent)
        rm -f "$state" "$initial"
        ;;
    *) exit 90 ;;
esac

crontab() {
    case "$1" in
        -l)
            read_count=$((read_count + 1))
            if [ "$scenario" = readback_error_present ] && \
               [ "$read_count" -eq 2 ]; then
                printf '%s\n' 'synthetic readback failure' >&2
                return 2
            fi
            if [ "$scenario" = restore_readback_error_present ] && \
               [ "$read_count" -eq 3 ]; then
                printf '%s\n' 'synthetic restoration readback failure' >&2
                return 2
            fi
            if [ "$scenario" = cmp_mismatch_present ] && \
               [ "$read_count" -eq 2 ]; then
                cat "$state"
                printf '%s\n' '# synthetic mismatch'
                return 0
            fi
            if [ -f "$state" ]; then
                cat "$state"
                return 0
            fi
            printf '%s\n' 'no crontab for root' >&2
            return 1
            ;;
        -)
            install_count=$((install_count + 1))
            cat >"$incoming" || return 2
            if [ "$scenario" = restore_write_failure_present ] && \
               [ "$install_count" -eq 2 ]; then
                printf '%s\n' 'synthetic restoration write failure' >&2
                return 2
            fi
            cp "$incoming" "$state" || return 2
            if [ "$scenario" = post_install_diagnostic_present ] && \
               [ "$install_count" -eq 1 ]; then
                printf '%s\n' 'synthetic post-install diagnostic' >&2
            fi
            return 0
            ;;
        -r)
            if [ "$scenario" = restore_remove_failure_absent ]; then
                printf '%s\n' 'synthetic restoration remove failure' >&2
                return 2
            fi
            rm -f "$state"
            return $?
            ;;
        *) return 2 ;;
    esac
}

validate_root_crontab_round_trip "$test_root/round-trip"
validation_rc=$?
restored=0
case "$scenario" in
    *_present)
        if [ -f "$state" ] && cmp -s "$initial" "$state"; then
            restored=1
        fi
        ;;
    *_absent)
        if [ ! -e "$state" ]; then
            restored=1
        fi
        ;;
esac
printf '%s %s\n' "$validation_rc" "$restored"
'''
        scenarios = {
            "success_present": (0, 1),
            "success_absent": (0, 1),
            "post_install_diagnostic_present": (1, 1),
            "readback_error_present": (1, 1),
            "cmp_mismatch_present": (1, 1),
            "restore_write_failure_present": (1, 0),
            "restore_readback_error_present": (1, 1),
            "restore_remove_failure_absent": (1, 0),
        }
        for scenario, expected in scenarios.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as root:
                result = subprocess.run(
                    ("/bin/sh", "-s", "--", scenario, root),
                    input=driver,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout,
                    f"{expected[0]} {expected[1]}\n",
                    result.stderr,
                )

    def test_host_state_and_legacy_cron_cannot_leak_between_vm_runs(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        preclean = script[script.index("preclean=1") : script.index("emit PRECLEAN")]
        self.assertIn("/var/db/syswarden", preclean)
        self.assertIn("/var/log/syswarden", preclean)
        self.assertIn("/var/cron/allow", preclean)
        self.assertIn("/var/cron/deny", preclean)
        self.assertIn("/var/db/syswarden/pf-policy-snapshot.json", script)
        self.assertIn("/var/db/syswarden/pf-transition-v4.02.8", script)
        self.assertIn("REMOVE_HOST_STATE_ABSENT", script)
        cleanup_function = script[
            script.index("cleanup_vm() {") : script.index("final_cleanup() {")
        ]
        self.assertIn("rm -rf /var/db/syswarden", cleanup_function)
        self.assertIn("/var/log/syswarden", cleanup_function)
        self.assertIn('$6 == "/opt/syswarden/bin/syswarden-cli"', cleanup_function)
        final_cleanup = script[script.rindex("cleanup_ok=1") :]
        self.assertIn("/var/db/syswarden", final_cleanup)
        self.assertIn("/var/log/syswarden", final_cleanup)
        self.assertIn("/(usr/local|opt)/syswarden/bin/syswarden-cli", final_cleanup)
        self.assertEqual(script.count("/var/log/syswarden"), 3)

        def assert_log_residue_contract(candidate: str) -> None:
            candidate_preclean = candidate[
                candidate.index("preclean=1") : candidate.index("emit PRECLEAN")
            ]
            cleanup_start = candidate.index("cleanup_vm() {")
            cleanup_end = candidate.index("final_cleanup() {")
            candidate_cleanup = candidate[cleanup_start:cleanup_end]
            candidate_final = candidate[candidate.rindex("cleanup_ok=1") :]
            self.assertIn("/var/log/syswarden", candidate_preclean)
            self.assertIn("/var/log/syswarden", candidate_cleanup)
            self.assertIn("/var/log/syswarden", candidate_final)

        assert_log_residue_contract(script)
        with self.assertRaises(AssertionError):
            assert_log_residue_contract(
                script.replace("/var/log/syswarden", "", 1)
            )

    def test_candidate_postinstall_marker_and_tui_probes_are_fail_closed(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        self.assertIn("POSTINSTALL_MARKER_STATE", freebsd_vm_lab.PHASE_EVIDENCE_SUFFIXES)
        self.assertIn(
            "POSTINSTALL_DIAGNOSTICS_CLEAN",
            freebsd_vm_lab.PHASE_EVIDENCE_SUFFIXES,
        )
        self.assertIn("MODULAR_CONFIG_INVENTORY", freebsd_vm_lab.PHASE_EVIDENCE_SUFFIXES)
        self.assertIn("signature_state /usr/local/syswarden/.postinstall-ok", script)
        self.assertIn("post-install script failed", script)
        self.assertIn("env TERM=xterm timeout 5 script -q /dev/null", script)
        self.assertIn("TUI_REINSTALL_RC", freebsd_vm_lab.BASE_EVIDENCE_KEYS)
        self.assertIn("TUI_RECOVERY_RC", freebsd_vm_lab.BASE_EVIDENCE_KEYS)

        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["CANDIDATE_UPGRADE_POSTINSTALL_MARKER_STATE"] = "absent"
        evidence["CANDIDATE_REINSTALL_MODULAR_CONFIG_INVENTORY"] = ""
        evidence["TUI_RECOVERY_RC"] = "0"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertFalse(report["release_ready"])
        self.assertIn(
            "SW-PKG-FBSD-CANDIDATE-UPGRADE-POSTINSTALL-001",
            report["unexpected_failed_check_ids"],
        )
        self.assertIn(
            "SW-PKG-FBSD-CANDIDATE-REINSTALL-POSTINSTALL-001",
            report["unexpected_failed_check_ids"],
        )
        self.assertIn(
            "SW-PKG-FBSD-TUI-EXEC-001",
            report["unexpected_failed_check_ids"],
        )

    def test_each_phase_inventory_user_state_and_signature_load_fail_closed(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["CANDIDATE_REINSTALL_PKG_INVENTORY"] = ""
        evidence["PREVIOUS_ROLLBACK_USER_DATA_SHA256"] = "0" * 64
        evidence["CANDIDATE_UPGRADE_SIGNATURE_RULE_COUNT"] = "77"
        evidence["PREVIOUS_INSTALL_SIGNATURE_ENGINE_COUNT"] = ""
        evidence["REMOVE_USER_CONFIG_SHA256"] = "0" * 64
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        blockers = {
            item["id"]
            for item in report["checks"]
            if item["status"] == "blocker"
        }
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "fail")
        self.assertIs(report["release_ready"], False)
        self.assertTrue(
            {
                "SW-PKG-FBSD-CANDIDATE-REINSTALL-INVENTORY-001",
                "SW-PKG-FBSD-PREVIOUS-ROLLBACK-STATE-001",
                "SW-PKG-FBSD-CANDIDATE-UPGRADE-SIGNATURES-001",
                "SW-PKG-FBSD-PREVIOUS-INSTALL-SIGNATURES-001",
                "SW-PKG-FBSD-REMOVE-STATE-001",
            }.issubset(blockers)
        )
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(blockers.issubset(report["unexpected_failed_check_ids"]))

    def test_exact_v4028_forward_only_transition_can_recover_candidate(self) -> None:
        evidence = passing_evidence()
        evidence["PF_SNAPSHOT_PROVENANCE"] = "legacy_derived"
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = (
            freebsd_vm_lab.FORWARD_ONLY_PREVIOUS_SHA256
        )
        for phase in (
            "CANDIDATE_UPGRADE",
            "CANDIDATE_REINSTALL",
            "CANDIDATE_RESTART_IDEMPOTENCE",
        ):
            evidence[f"{phase}_PKG_VERSION"] = "4.02.15"
        for phase in ("PREVIOUS_INSTALL", "PREVIOUS_ROLLBACK"):
            evidence[f"{phase}_PKG_VERSION"] = "4.02.8"
            evidence[f"{phase}_PKG_ARCH"] = "FreeBSD:13:amd64"
            evidence[f"{phase}_ELF_CORE_ARCH"] = "arm64"
            evidence[f"{phase}_ELF_TUI_ARCH"] = "arm64"
            evidence[f"{phase}_PKG_INVENTORY"] = "\n".join(
                sorted(freebsd_vm_lab.FORWARD_ONLY_PREVIOUS_INVENTORY)
            )
            evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"] = ""
            evidence[f"{phase}_SIGNATURE_PROBE_RC"] = "2"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.forward_candidate_artifact(),
            self.forward_previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["product_status"], "pass")
        self.assertIs(report["release_ready"], True)
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(report["unexpected_failed_check_ids"], [])
        previous_package = report["lifecycle_phases"]["previous_install"][
            "package"
        ]
        self.assertEqual(
            previous_package["elf_architectures"],
            {"cli": "amd64", "core": "arm64", "tui": "arm64"},
        )

    def test_pf_snapshot_provenance_is_transition_bound(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["PF_SNAPSHOT_PROVENANCE"] = "legacy_derived"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        provenance = next(
            item
            for item in report["checks"]
            if item["id"] == "SW-PKG-FBSD-PF-PROVENANCE-001"
        )
        self.assertEqual(provenance["status"], "blocker")
        self.assertFalse(report["release_ready"])

    def test_migration_backup_metadata_drift_blocks_release(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["REMOVE_MIGRATION_BACKUP_STATE"] = "symlink:bad:777:1001:1001"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        backup = next(
            item
            for item in report["checks"]
            if item["id"] == "SW-PKG-FBSD-MIGRATION-BACKUP-001"
        )
        self.assertEqual(backup["status"], "blocker")
        self.assertFalse(report["release_ready"])

    def test_fresh_pf_nonempty_mutation_or_acceptance_blocks_release(self) -> None:
        mutations = {
            "PF_NONEMPTY_SEED_APPLY_RC": "1",
            "PF_NONEMPTY_CAPTURE_REJECTED": "0",
            "PF_NONEMPTY_ANCHOR_PRESERVED": "0",
            "PF_NONEMPTY_FILTER_PRESERVED": "0",
            "PF_NONEMPTY_NAT_PRESERVED": "0",
            "PF_NONEMPTY_TABLES_PRESERVED": "0",
            "PF_NONEMPTY_STATUS_PRESERVED": "0",
            "PF_NONEMPTY_STATE_PRESERVED": "0",
        }
        for key, invalid_value in mutations.items():
            with self.subTest(key=key):
                evidence = passing_evidence()
                evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
                evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
                evidence[key] = invalid_value
                report = freebsd_vm_lab.build_report(
                    evidence,
                    self.artifact(),
                    self.previous_artifact(),
                    freebsd_vm_lab.inspect_product_assets(self.repo),
                    "127.0.0.1",
                    2222,
                )
                boundary = next(
                    item
                    for item in report["checks"]
                    if item["id"] == "SW-PKG-FBSD-PF-FRESH-BOUNDARY-001"
                )
                self.assertEqual(boundary["status"], "blocker")
                self.assertFalse(report["release_ready"])

    def test_fresh_pf_preservation_uses_stable_separate_views(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        self.assertIn(
            'emit PF_NONEMPTY_SEED_APPLY_RC "$fresh_seed_apply_rc"', script
        )
        for component in ("ANCHOR", "FILTER", "NAT", "TABLES", "STATUS"):
            self.assertIn(
                f'emit PF_NONEMPTY_{component}_PRESERVED '
                f'"$fresh_{component.lower()}_preserved"',
                script,
            )
        for view in ("filter", "nat", "tables"):
            self.assertIn(f'"$work/pf-fresh-{view}-before"', script)
            self.assertIn(f'"$work/pf-fresh-{view}-after"', script)
        self.assertIn(
            "fresh_status_before=\"$(awk '/^Status:/{print $2; exit}' "
            "\"$work/pf-fresh-info-before\")\"",
            script,
        )
        self.assertIn(
            "fresh_status_after=\"$(awk '/^Status:/{print $2; exit}' "
            "\"$work/pf-fresh-info-after\")\"",
            script,
        )
        self.assertNotIn("pf-fresh-main-before", script)
        self.assertNotIn("pf-fresh-main-after", script)
        self.assertNotIn(
            'cmp -s "$work/pf-fresh-info-before" '
            '"$work/pf-fresh-info-after"',
            script,
        )

    def test_module_absent_pkg_lifecycle_is_ordered_and_fail_closed(self) -> None:
        def assert_contract(candidate: str) -> None:
            self.assertNotIn(".schema_version == 1", candidate)
            initial_absent = candidate.index(
                'emit PF_INITIAL_MODULE_ABSENT "$initial_pf_module_absent"'
            )
            initial_load = candidate.index(
                '/sbin/kldload -n -q pf >"$work/kldload.log" 2>&1',
                initial_absent,
            )
            historical_remove = candidate.index(
                'emit REMOVE_PF_SYSWARDEN_TABLE_ABSENT', initial_load
            )
            absent_unload = candidate.index(
                '/sbin/kldunload -n pf >"$work/pf-absent-pre-unload.log" 2>&1',
                historical_remove,
            )
            absent_add = candidate.index(
                'pkg add -f "$work/$candidate_package_name"', absent_unload
            )
            snapshot_schema = candidate.index(
                "PF_ABSENT_SNAPSHOT_SCHEMA_VERSION", absent_add
            )
            self.assertIn("PF_ABSENT_SNAPSHOT_MUTATION_STARTED", candidate)
            mutation_started = candidate.index(
                "PF_ABSENT_SNAPSHOT_MUTATION_STARTED", snapshot_schema
            )
            absent_delete = candidate.index(
                "timeout -f 120 pkg delete -fy syswarden", mutation_started
            )
            snapshot_absent = candidate.index(
                "PF_ABSENT_DELETE_SNAPSHOT_ABSENT", absent_delete
            )
            fresh_capture = candidate.index(
                '"$work/syswarden-cli-pf-probe" package-capture-pf',
                snapshot_absent,
            )
            nonempty_load = candidate.index(
                '/sbin/kldload -n -q pf >"$work/pf-nonempty-kldload.log" 2>&1',
                fresh_capture,
            )
            nonempty_seed = candidate.index(
                'pfctl -a "$anchor" -f "$work/pf-fresh-reject.conf"',
                nonempty_load,
            )
            self.assertIn(
                '/sbin/kldunload -n pf >"$work/pf-final-guest-unload.log" 2>&1',
                candidate,
            )
            final_unload = candidate.index(
                '/sbin/kldunload -n pf >"$work/pf-final-guest-unload.log" 2>&1',
                nonempty_seed,
            )
            lock_release = candidate.index("lock_released=0", final_unload)
            self.assertEqual(
                [
                    initial_absent,
                    initial_load,
                    historical_remove,
                    absent_unload,
                    absent_add,
                    snapshot_schema,
                    mutation_started,
                    absent_delete,
                    snapshot_absent,
                    fresh_capture,
                    nonempty_load,
                    nonempty_seed,
                    final_unload,
                    lock_release,
                ],
                sorted(
                    [
                        initial_absent,
                        initial_load,
                        historical_remove,
                        absent_unload,
                        absent_add,
                        snapshot_schema,
                        mutation_started,
                        absent_delete,
                        snapshot_absent,
                        fresh_capture,
                        nonempty_load,
                        nonempty_seed,
                        final_unload,
                        lock_release,
                    ]
                ),
            )
            self.assertIn("select(.schema_version == 2)", candidate)
            self.assertIn(
                'select(.schema_version == 2 and .provenance == "exact_live")',
                candidate,
            )
            for view in ("filter", "nat", "tables", "anchors", "states"):
                self.assertIn(
                    f'"$work/pf-absent-delete-probe-{view}"', candidate
                )
            self.assertEqual(candidate.count("pfctl -ss"), 2)
            self.assertNotIn(
                '/sbin/kldload -n -q pf >"$work/kldload.log" 2>&1 || true',
                candidate,
            )
            self.assertIn("PF_ABSENT_SNAPSHOT_SAFE", candidate)
            self.assertIn("PF_FINAL_GUEST_MODULE_ABSENT", candidate)
            self.assertIn("PF_FINAL_GUEST_DEVICE_ABSENT", candidate)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        for mutation in (
            script.replace("select(.schema_version == 2)", "select(.schema_version == 1)", 1),
            script.replace(
                "PF_ABSENT_SNAPSHOT_MUTATION_STARTED",
                "PF_ABSENT_SNAPSHOT_MUTATION_IGNORED",
                1,
            ),
            script.replace("pfctl -ss", ": states probe removed", 1),
            script.replace(
                '/sbin/kldunload -n pf >"$work/pf-final-guest-unload.log" 2>&1',
                ": final unload removed",
                1,
            ),
        ):
            with self.assertRaises(AssertionError):
                assert_contract(mutation)

    def test_module_absent_pkg_lifecycle_observations_block_release(self) -> None:
        mutations = {
            "PF_ABSENT_PRE_MODULE_ABSENT": "0",
            "PF_ABSENT_PRE_DEVICE_ABSENT": "0",
            "PF_ABSENT_INSTALL_RC": "1",
            "PF_ABSENT_INSTALL_POSTINSTALL_MARKER_STATE": "absent",
            "PF_ABSENT_INSTALL_DIAGNOSTICS_CLEAN": "0",
            "PF_ABSENT_SNAPSHOT_SAFE": "0",
            "PF_ABSENT_SNAPSHOT_SCHEMA_VERSION": "1",
            "PF_ABSENT_SNAPSHOT_PROVENANCE": "legacy_derived",
            "PF_ABSENT_SNAPSHOT_INITIAL_KERNEL_STATE": "available",
            "PF_ABSENT_SNAPSHOT_MUTATION_STARTED": "false",
            "PF_ABSENT_POLICY_MODULE_PRESENT": "0",
            "PF_ABSENT_POLICY_DEVICE_READY": "0",
            "PF_ABSENT_POLICY_STATUS": "Disabled",
            "PF_ABSENT_POLICY_RULE_COUNT": "0",
            "PF_ABSENT_DELETE_RC": "1",
            "PF_ABSENT_DELETE_DIAGNOSTICS_CLEAN": "0",
            "PF_ABSENT_DELETE_PACKAGE_ABSENT": "0",
            "PF_ABSENT_DELETE_SNAPSHOT_ABSENT": "0",
            "PF_ABSENT_DELETE_CONFIGURED_STATUS": "Enabled",
            "PF_ABSENT_DELETE_MODULE_ABSENT": "0",
            "PF_ABSENT_DELETE_DEVICE_ABSENT": "0",
            "PF_ABSENT_DELETE_PROBE_LOAD_RC": "1",
            "PF_ABSENT_DELETE_PROBE_STATUS": "Enabled",
            "PF_ABSENT_DELETE_PROBE_POLICY_EMPTY": "0",
            "PF_ABSENT_DELETE_PROBE_UNLOAD_RC": "1",
            "PF_ABSENT_DELETE_FINAL_MODULE_ABSENT": "0",
            "PF_ABSENT_DELETE_FINAL_DEVICE_ABSENT": "0",
        }
        for key, invalid_value in mutations.items():
            with self.subTest(key=key):
                evidence = passing_evidence()
                evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
                evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
                evidence[key] = invalid_value
                report = freebsd_vm_lab.build_report(
                    evidence,
                    self.artifact(),
                    self.previous_artifact(),
                    freebsd_vm_lab.inspect_product_assets(self.repo),
                    "127.0.0.1",
                    2222,
                )
                expected_id = (
                    "SW-PKG-FBSD-PF-MODULE-ABSENT-INSTALL-001"
                    if key.startswith("PF_ABSENT_PRE_")
                    or key.startswith("PF_ABSENT_INSTALL_")
                    or key.startswith("PF_ABSENT_SNAPSHOT_")
                    or key.startswith("PF_ABSENT_POLICY_")
                    else "SW-PKG-FBSD-PF-MODULE-ABSENT-REMOVE-001"
                )
                check = next(
                    item for item in report["checks"] if item["id"] == expected_id
                )
                self.assertEqual(check["status"], "blocker")
                self.assertFalse(report["release_ready"])

    def test_rsyslog_validation_enablement_and_status_are_mandatory(self) -> None:
        for key, failure in (
            ("RSYSLOG_CONFIG_VALIDATE_RC", "1"),
            ("RSYSLOG_ENABLED", "NO"),
            ("RSYSLOG_STATUS_RC", "1"),
            ("SYSLOGD_INACTIVE", "0"),
            ("REMOVE_LOGGING_BASELINE_RESTORED", "0"),
            ("REMOVE_CRON_ACCESS_PRESERVED", "0"),
            ("REMOVE_HOST_STATE_ABSENT", "0"),
        ):
            with self.subTest(key=key):
                evidence = passing_evidence()
                evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
                evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
                evidence[key] = failure
                report = freebsd_vm_lab.build_report(
                    evidence,
                    self.artifact(),
                    self.previous_artifact(),
                    freebsd_vm_lab.inspect_product_assets(self.repo),
                    "127.0.0.1",
                    2222,
                )
                self.assertFalse(report["release_ready"])

    def test_arbitrary_abi_elf_or_loader_failure_is_never_expected(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["PREVIOUS_INSTALL_PKG_ARCH"] = "FreeBSD:12:amd64"
        evidence["CANDIDATE_REINSTALL_ELF_CORE_ARCH"] = "invalid"
        evidence["PREVIOUS_ROLLBACK_ELF_CORE_ARCH"] = "arm64"
        evidence["PREVIOUS_ROLLBACK_ELF_TUI_ARCH"] = "arm64"
        evidence["PREVIOUS_ROLLBACK_SIGNATURE_ENGINE_COUNT"] = ""
        evidence["PREVIOUS_ROLLBACK_SIGNATURE_PROBE_RC"] = "127"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["product_status"], "fail")
        self.assertIn(
            "SW-PKG-FBSD-PREVIOUS-INSTALL-ABI-001",
            report["unexpected_failed_check_ids"],
        )
        self.assertIn(
            "SW-PKG-FBSD-CANDIDATE-REINSTALL-ELF-001",
            report["unexpected_failed_check_ids"],
        )
        self.assertIn(
            "SW-PKG-FBSD-PREVIOUS-ROLLBACK-SIGNATURES-001",
            report["unexpected_failed_check_ids"],
        )

    def test_pf_honeyport_regression_is_an_unexpected_failure(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
                "PF_HONEYPORT_SOURCE_BAD": "1",
                "PF_HONEYPORT_EXACT_VALUE": "236379",
                "PF_HONEYPORT_SYNTAX_RC": "1",
                "PF_FIXTURE_SYNTAX_RC": "1",
                "PF_FIXTURE_APPLY_RC": "125",
                "PF_FIXTURE_RULE_COUNT": "0",
            }
        )
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["product_status"], "fail")
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(
            {
                "SW-PF-FBSD-FIXTURE-SYNTAX-001",
                "SW-PF-FBSD-FIXTURE-APPLY-001",
                "SW-PF-FBSD-HONEYPORT-001",
            }.issubset(report["unexpected_failed_check_ids"])
        )

        evidence["PF_HONEYPORT_EXACT_VALUE"] = "236380"
        arbitrary_report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(arbitrary_report["blocker_ids"], [])
        self.assertTrue(
            {
                "SW-PF-FBSD-FIXTURE-SYNTAX-001",
                "SW-PF-FBSD-FIXTURE-APPLY-001",
                "SW-PF-FBSD-HONEYPORT-001",
            }.issubset(arbitrary_report["unexpected_failed_check_ids"])
        )

    def test_real_run_manifestations_reduce_to_only_canonical_blockers(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
                "SIGNATURE_RUNTIME_PATH": "0",
                "RC_CORE_PRESENT": "0",
                "RC_WEB_PRESENT": "0",
                "RC_CORE_MODE": "",
                "RC_WEB_MODE": "",
                "RC_CORE_COMMAND": "",
                "RC_WEB_COMMAND": "",
                "RC_CORE_ENABLED": "",
                "RC_WEB_ENABLED": "",
                "CANDIDATE_RESTART_IDEMPOTENCE_OPERATION_RC": "1",
                "PF_FIXTURE_SYNTAX_RC": "1",
                "PF_FIXTURE_APPLY_RC": "125",
                "PF_FIXTURE_RULE_COUNT": "0",
                "PF_HONEYPORT_SOURCE_BAD": "1",
                "PF_HONEYPORT_EXACT_VALUE": "236379",
                "PF_HONEYPORT_SYNTAX_RC": "1",
            }
        )
        for key in (
            "RC_CORE_START_RC",
            "RC_CORE_STATUS_RC",
            "RC_CORE_RESTART_ONE_RC",
            "RC_CORE_RESTART_ONE_STATUS_RC",
            "RC_CORE_RESTART_TWO_RC",
            "RC_CORE_RESTART_TWO_STATUS_RC",
            "RC_WEB_START_RC",
            "RC_WEB_STATUS_RC",
            "RC_WEB_RESTART_ONE_RC",
            "RC_WEB_RESTART_ONE_STATUS_RC",
            "RC_WEB_RESTART_TWO_RC",
            "RC_WEB_RESTART_TWO_STATUS_RC",
        ):
            evidence[key] = "1"
        for phase in freebsd_vm_lab.LIFECYCLE_PHASES:
            evidence[f"{phase}_PKG_ARCH"] = "FreeBSD:13:amd64"
        for phase in ("PREVIOUS_INSTALL", "PREVIOUS_ROLLBACK"):
            evidence[f"{phase}_ELF_CORE_ARCH"] = "arm64"
            evidence[f"{phase}_ELF_TUI_ARCH"] = "arm64"
            evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"] = ""
            evidence[f"{phase}_SIGNATURE_PROBE_RC"] = "2"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "fail")
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(
            {
                "SW-PF-FBSD-FIXTURE-SYNTAX-001",
                "SW-PF-FBSD-FIXTURE-APPLY-001",
                "SW-PF-FBSD-HONEYPORT-001",
            }.issubset(report["unexpected_failed_check_ids"])
        )

    def test_second_restart_is_a_required_idempotence_check(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["RC_CORE_RESTART_TWO_RC"] = "1"
        evidence["RC_WEB_RESTART_TWO_STATUS_RC"] = "1"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        blockers = {
            item["id"]
            for item in report["checks"]
            if item["status"] == "blocker"
        }
        self.assertIn("SW-PKG-FBSD-RESTART-CORE-001", blockers)
        self.assertIn("SW-PKG-FBSD-RESTART-WEB-001", blockers)
        self.assertEqual(report["product_status"], "fail")
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(
            report["unexpected_failed_check_ids"],
            [
                "SW-PKG-FBSD-RESTART-CORE-001",
                "SW-PKG-FBSD-RESTART-WEB-001",
            ],
        )
        self.assertIs(report["release_ready"], False)

    def test_current_prefix_rcd_are_blockers_but_honeyport_regression_is_not(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
                "SIGNATURE_RUNTIME_PATH": "0",
                "RC_CORE_PRESENT": "0",
                "RC_WEB_PRESENT": "0",
                "RC_CORE_MODE": "",
                "RC_WEB_MODE": "",
                "RC_CORE_COMMAND": "",
                "RC_WEB_COMMAND": "",
                "RC_CORE_ENABLED": "",
                "RC_WEB_ENABLED": "",
                "RC_CORE_START_RC": "1",
                "RC_CORE_STATUS_RC": "1",
                "RC_CORE_RESTART_ONE_RC": "1",
                "RC_CORE_RESTART_ONE_STATUS_RC": "1",
                "RC_CORE_RESTART_TWO_RC": "1",
                "RC_CORE_RESTART_TWO_STATUS_RC": "1",
                "RC_WEB_START_RC": "1",
                "RC_WEB_STATUS_RC": "1",
                "RC_WEB_RESTART_ONE_RC": "1",
                "RC_WEB_RESTART_ONE_STATUS_RC": "1",
                "RC_WEB_RESTART_TWO_RC": "1",
                "RC_WEB_RESTART_TWO_STATUS_RC": "1",
                "CANDIDATE_RESTART_IDEMPOTENCE_OPERATION_RC": "1",
                "PF_HONEYPORT_SOURCE_BAD": "1",
                "PF_HONEYPORT_EXACT_VALUE": "236379",
                "PF_HONEYPORT_SYNTAX_RC": "1",
            }
        )
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        blockers = {
            item["id"]
            for item in report["checks"]
            if item["status"] == "blocker"
        }
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "fail")
        self.assertIs(report["release_ready"], False)
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(
            {
                "SW-PKG-FBSD-PREFIX-001",
                "SW-PKG-FBSD-RCD-CORE-001",
                "SW-PKG-FBSD-RCD-WEB-001",
                "SW-PF-FBSD-HONEYPORT-001",
            }.issubset(report["unexpected_failed_check_ids"])
        )
        self.assertTrue(
            {
                "SW-PKG-FBSD-PREFIX-001",
                "SW-PKG-FBSD-RCD-CORE-001",
                "SW-PKG-FBSD-RCD-WEB-001",
                "SW-PKG-FBSD-RCD-CORE-PATH-001",
                "SW-PKG-FBSD-RCD-WEB-PATH-001",
                "SW-PKG-FBSD-START-CORE-001",
                "SW-PKG-FBSD-START-WEB-001",
            }.issubset(blockers)
        )

    def test_cleanup_evidence_is_harness_critical(self) -> None:
        mutations = {
            "ruleset_not_restored": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="0"
            ),
            "filesystem_residue": lambda evidence: evidence.update(
                LAB_CLEANUP_OK="0"
            ),
            "pf_left_enabled": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="1",
                PF_FINAL_STATUS="Enabled",
            ),
            "pf_status_missing": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="1",
                PF_FINAL_STATUS="",
            ),
            "initial_module_present": lambda evidence: evidence.update(
                PF_INITIAL_MODULE_ABSENT="0"
            ),
            "initial_device_present": lambda evidence: evidence.update(
                PF_INITIAL_DEVICE_ABSENT="0"
            ),
            "initial_load_failed": lambda evidence: evidence.update(
                PF_INITIAL_KLDLOAD_RC="1"
            ),
            "final_unload_failed": lambda evidence: evidence.update(
                PF_FINAL_GUEST_KLDUNLOAD_RC="1"
            ),
            "final_module_present": lambda evidence: evidence.update(
                PF_FINAL_GUEST_MODULE_ABSENT="0"
            ),
            "final_device_present": lambda evidence: evidence.update(
                PF_FINAL_GUEST_DEVICE_ABSENT="0"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                evidence = passing_evidence()
                evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
                evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
                mutate(evidence)
                report = freebsd_vm_lab.build_report(
                    evidence,
                    self.artifact(),
                    self.previous_artifact(),
                    freebsd_vm_lab.inspect_product_assets(self.repo),
                    "127.0.0.1",
                    2222,
                )
                self.assertEqual(report["harness_status"], "fail")
                self.assertIs(report["release_ready"], False)

        passing = passing_evidence()
        passing["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        passing["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        report = freebsd_vm_lab.build_report(
            passing,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["environment"]["pf_final_status"], "Disabled")

    def test_fixture_lock_and_anchor_evidence_are_harness_critical(self) -> None:
        mutations = {
            "fixture": lambda evidence: evidence.update(
                PF_FIXTURE_SHA256="0" * 64,
                PF_FIXTURE_SHA_MATCH="1",
            ),
            "lock_acquire": lambda evidence: evidence.update(LAB_LOCK_ACQUIRED="0"),
            "lock_release": lambda evidence: evidence.update(LAB_LOCK_RELEASED="0"),
            "anchor": lambda evidence: evidence.update(
                PF_ANCHOR_NAME="syswarden_lot0_static"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                evidence = passing_evidence()
                evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
                evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
                mutate(evidence)
                report = freebsd_vm_lab.build_report(
                    evidence,
                    self.artifact(),
                    self.previous_artifact(),
                    freebsd_vm_lab.inspect_product_assets(self.repo),
                    "127.0.0.1",
                    2222,
                )
                self.assertEqual(report["harness_status"], "fail")
                self.assertIs(report["release_ready"], False)

        valid_but_wrong_anchor = passing_evidence()
        valid_but_wrong_anchor["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        valid_but_wrong_anchor["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        valid_but_wrong_anchor["PF_ANCHOR_NAME"] = "syswarden_lot0_" + "e" * 32
        bound_report = freebsd_vm_lab.build_report(
            valid_but_wrong_anchor,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
            ANCHOR_NAME,
        )
        self.assertEqual(bound_report["harness_status"], "fail")

    def test_restart_metadata_inventory_is_complete_and_fail_closed(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["RESTART_TWO_INVENTORY"] = RESTART_METADATA_INVENTORY.replace(
            "Regular File\t750\t0\t0",
            "Regular File\t700\t0\t0",
            1,
        )
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["product_status"], "fail")
        self.assertIn(
            "SW-PKG-FBSD-RESTART-METADATA-001",
            report["unexpected_failed_check_ids"],
        )
        self.assertIs(report["release_ready"], False)

        malformed = passing_evidence()
        malformed["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        malformed["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        malformed["RESTART_ONE_INVENTORY"] = "/outside/scope\tDirectory\t755\t0\t0\t-"
        malformed_report = freebsd_vm_lab.build_report(
            malformed,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertIn(
            "SW-PKG-FBSD-RESTART-METADATA-001",
            malformed_report["unexpected_failed_check_ids"],
        )

    def test_signature_probe_restoration_failure_is_unexpected(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
        evidence["CANDIDATE_REINSTALL_SIGNATURE_STATE_BEFORE"] = (
            "file:" + "a" * 64 + ":640:0:0"
        )
        evidence["CANDIDATE_REINSTALL_SIGNATURE_STATE_AFTER"] = (
            "file:" + "a" * 64 + ":600:0:0"
        )
        evidence["CANDIDATE_REINSTALL_SIGNATURE_STATE_RESTORED"] = "0"
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        check_id = "SW-PKG-FBSD-CANDIDATE-REINSTALL-SIGNATURE-RESTORE-001"
        self.assertEqual(report["product_status"], "fail")
        self.assertIn(check_id, report["unexpected_failed_check_ids"])
        self.assertEqual(report["blocker_ids"], [])

    def test_every_unmet_nontransition_contract_is_unexpected(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
                "SIGNATURE_RUNTIME_PATH": "0",
                "CANDIDATE_UPGRADE_PKG_INVENTORY": "",
            }
        )
        report = freebsd_vm_lab.build_report(
            evidence,
            self.artifact(),
            self.previous_artifact(),
            freebsd_vm_lab.inspect_product_assets(self.repo),
            "127.0.0.1",
            2222,
        )
        self.assertEqual(report["product_status"], "fail")
        self.assertEqual(report["blocker_ids"], [])
        self.assertTrue(
            {
                "SW-PKG-FBSD-PREFIX-001",
                "SW-PKG-FBSD-CANDIDATE-UPGRADE-INVENTORY-001",
            }.issubset(report["unexpected_failed_check_ids"])
        )

    def test_fake_run_uses_only_ssh_scp_and_never_a_host_pf_command(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
                "PF_HONEYPORT_SOURCE_BAD": "1",
                "PF_HONEYPORT_EXACT_VALUE": "236379",
                "PF_HONEYPORT_SYNTAX_RC": "1",
            }
        )
        runner = FakeRunner(evidence)
        report = freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "fail")
        self.assertNotIn(TOKEN, json.dumps(report, sort_keys=True))
        self.assertEqual({call[0][0] for call in runner.calls}, {"ssh", "scp"})
        self.assertFalse(
            any(TOKEN in argument for call in runner.calls for argument in call[0])
        )
        self.assertFalse(any(call[0][0] == "pfctl" for call in runner.calls))
        scp_calls = [call[0] for call in runner.calls if call[0][0] == "scp"]
        self.assertEqual(len(scp_calls), 3)
        self.assertTrue(any(str(self.previous_package) in call for call in scp_calls))
        self.assertTrue(any(str(self.package) in call for call in scp_calls))
        remote_call = next(
            call
            for call in runner.calls
            if carries_script(call[1], freebsd_vm_lab.REMOTE_LAB_SCRIPT)
        )
        self.assertIn("sudo", remote_call[0])
        self.assertIn("pfctl", remote_call[1] or "")
        self.assertFalse(any(TOKEN in value for value in remote_call[0]))
        self.assertIn(f"token={TOKEN}\n", remote_call[1] or "")
        self.assertFalse(
            any(
                carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            "in-band cleanup proof unexpectedly opened another SSH session",
        )
        for value in (
            self.previous_package.name,
            self.previous_package_sha,
            "4.02.7",
            self.package.name,
            self.package_sha,
            "4.02.8",
            PF_FIXTURE_SHA256,
        ):
            self.assertIn(value, remote_call[0])
        nonce_values = [
            value
            for value in remote_call[0]
            if isinstance(value, str) and len(value) == 32 and value.isalnum()
        ]
        self.assertTrue(
            any(
                value != TOKEN and re.fullmatch(r"[a-f0-9]{32}", value)
                for value in nonce_values
            )
        )

    def test_transport_workspace_cleanup_runs_after_copy_failure(self) -> None:
        runner = FailingCopyRunner(passing_evidence())
        with self.assertRaisesRegex(freebsd_vm_lab.FreeBSDVMLabError, "copy"):
            freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertTrue(
            any(
                carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            "root cleanup was not attempted after SCP failure",
        )

    def test_transport_failure_diagnostics_are_redacted(self) -> None:
        result = freebsd_vm_lab.CommandResult(
            ("ssh",), 255, f"hostile stdout {TOKEN}", f"hostile stderr {TOKEN}"
        )
        with self.assertRaises(freebsd_vm_lab.FreeBSDVMLabError) as raised:
            freebsd_vm_lab.require_transport_success(result, "transport probe")
        message = str(raised.exception)
        self.assertEqual(message, "transport probe failed with exit code 255")
        self.assertNotIn(
            TOKEN,
            json.dumps(
                freebsd_vm_lab.error_report(raised.exception), sort_keys=True
            ),
        )

    def test_in_band_cleanup_proof_skips_external_cleanup(self) -> None:
        evidence = passing_evidence()
        evidence.update(
            {
                "CANDIDATE_PACKAGE_SHA256": self.package_sha,
                "PREVIOUS_PACKAGE_SHA256": self.previous_package_sha,
            }
        )
        runner = SequencedCleanupRunner(evidence, [])
        report = freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertEqual(report["harness_status"], "pass")
        cleanup_calls = [
            call
            for call in runner.calls
            if carries_script(call[1], freebsd_vm_lab.CLEANUP_SCRIPT)
        ]
        self.assertEqual(cleanup_calls, [])

    def test_invalid_in_band_cleanup_markers_trigger_cleanup_and_fail(self) -> None:
        for marker_mode in (
            "missing_workspace",
            "false_workspace",
            "false_lock",
        ):
            with self.subTest(marker_mode=marker_mode):
                evidence = passing_evidence()
                if marker_mode == "missing_workspace":
                    evidence.pop("REMOTE_WORKSPACE_REMOVED")
                elif marker_mode == "false_workspace":
                    evidence["REMOTE_WORKSPACE_REMOVED"] = "0"
                else:
                    evidence["LAB_LOCK_RELEASED"] = "0"
                runner = SequencedCleanupRunner(evidence, [255, 0])
                with mock.patch.object(freebsd_vm_lab.time, "sleep") as sleep:
                    with self.assertRaises(
                        freebsd_vm_lab.FreeBSDVMLabError
                    ) as raised:
                        freebsd_vm_lab.run_lab(self.args(), runner=runner)
                message = str(raised.exception)
                expected = (
                    "markers differ"
                    if marker_mode == "missing_workspace"
                    else "remote cleanup markers did not prove"
                )
                self.assertIn(expected, message)
                self.assertNotIn(TOKEN, message)
                self.assertEqual(
                    sum(
                        carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                        for _, input_text in runner.calls
                    ),
                    2,
                )
                sleep.assert_called_once_with(
                    freebsd_vm_lab.CLEANUP_RETRY_DELAY_SECONDS
                )

    def test_malformed_remote_output_triggers_cleanup_and_is_redacted(self) -> None:
        runner = SequencedCleanupRunner(
            passing_evidence(),
            [0],
            remote_stdout=f"malformed remote output {TOKEN}\n",
        )
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError,
            "invalid VM evidence line",
        ) as raised:
            freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(
            sum(
                carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            1,
        )

    def test_cleanup_exhaustion_fails_closed_without_transport_output(self) -> None:
        evidence = passing_evidence()
        evidence["REMOTE_WORKSPACE_REMOVED"] = "0"
        runner = SequencedCleanupRunner(evidence, [255, 255, 255])
        with mock.patch.object(freebsd_vm_lab.time, "sleep") as sleep:
            with self.assertRaisesRegex(
                freebsd_vm_lab.FreeBSDVMLabError,
                "not proven after 3 attempts",
            ) as raised:
                freebsd_vm_lab.run_lab(self.args(), runner=runner)
        message = str(raised.exception)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("untrusted-cleanup", message)
        self.assertNotIn(
            TOKEN,
            json.dumps(
                freebsd_vm_lab.error_report(raised.exception), sort_keys=True
            ),
        )
        self.assertEqual(message.count("exit_255"), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_remote_failure_preserves_primary_error_and_retries_cleanup(self) -> None:
        runner = SequencedCleanupRunner(
            passing_evidence(),
            [255, 0],
            remote_returncode=9,
        )
        with mock.patch.object(freebsd_vm_lab.time, "sleep"):
            with self.assertRaisesRegex(
                freebsd_vm_lab.FreeBSDVMLabError,
                "laboratory failed with exit code 9",
            ) as raised:
                freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(
            sum(
                carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            2,
        )

    def test_primary_error_survives_transient_cleanup_failure(self) -> None:
        runner = FailingCopySequencedCleanupRunner(
            passing_evidence(), [255, 0]
        )
        with mock.patch.object(freebsd_vm_lab.time, "sleep"):
            with self.assertRaisesRegex(
                freebsd_vm_lab.FreeBSDVMLabError,
                "copy .* failed with exit code 1",
            ) as raised:
                freebsd_vm_lab.run_lab(self.args(), runner=runner)
        self.assertNotIn("cleanup", str(raised.exception))
        self.assertEqual(
            sum(
                carries_script(input_text, freebsd_vm_lab.CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            2,
        )

    def test_primary_and_cleanup_errors_are_combined_without_cleanup_secret(self) -> None:
        runner = FailingCopySequencedCleanupRunner(
            passing_evidence(), [255, 255, 255]
        )
        with mock.patch.object(freebsd_vm_lab.time, "sleep"):
            with self.assertRaisesRegex(
                freebsd_vm_lab.FreeBSDVMLabError,
                "copy .* failed.*clean .*not proven",
            ) as raised:
                freebsd_vm_lab.run_lab(self.args(), runner=runner)
        message = str(raised.exception)
        self.assertIn("failed with exit code 1", message)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("untrusted-cleanup", message)
        self.assertEqual(message.count("exit_255"), 3)

    def test_remote_script_orders_full_lifecycle_and_real_signature_probes(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        syntax = subprocess.run(
            ("/bin/sh", "-n"),
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for required in (
            'sealed_work="${transport_work}.sealed"',
            'transport_entries="$(find "$transport_work" -mindepth 1 -maxdepth 1 -print',
            'sealed_entries="$(find "$sealed_work" -mindepth 1 -maxdepth 1 -print',
            'cp -P "$transport_work/$input_name" "$sealed_work/$input_name"',
            'stat -f \'%u:%g:%Mp:%Lp\' /tmp',
            'emit SEALED_INPUTS 1',
            'verify_sealed_input "$work/$previous_package_name"',
            'verify_sealed_input "$work/$candidate_package_name"',
            'verify_sealed_input "$work/pf-v4.02.8.conf"',
            '[ -e "$transport_work" ] || [ -L "$transport_work" ]',
            'emit REMOTE_WORKSPACE_REMOVED "$workspace_removed"',
        ):
            self.assertIn(required, script)
        self.assertIn("REMOTE_WORKSPACE_REMOVED", freebsd_vm_lab.EVIDENCE_KEYS)
        workspace_remove = script.rindex('rm -rf "$work"')
        workspace_marker = script.rindex(
            'emit REMOTE_WORKSPACE_REMOVED "$workspace_removed"'
        )
        self.assertLess(workspace_remove, workspace_marker)
        self.assertLess(workspace_marker, script.rindex("trap - EXIT HUP INT TERM"))
        self.assertEqual(
            script.count('verify_sealed_input "$work/$previous_package_name"'),
            2,
        )
        self.assertEqual(
            script.count('verify_sealed_input "$work/$candidate_package_name"'),
            4,
        )
        user_state_seed = script.index(
            ">/etc/syswarden/config/lifecycle-user.conf"
        )
        previous_install = script.index('pkg add -f "$work/$previous_package_name"')
        candidate_upgrade = script.index(
            'pkg add -f "$work/$candidate_package_name"', previous_install
        )
        candidate_reinstall = script.index(
            'pkg add -f "$work/$candidate_package_name"', candidate_upgrade + 1
        )
        previous_rollback = script.index(
            'pkg add -f "$work/$previous_package_name"', candidate_reinstall
        )
        candidate_recovery = script.index(
            'pkg add -f "$work/$candidate_package_name"',
            previous_rollback,
        )
        restart_capture = script.index(
            "capture_installed_phase CANDIDATE_RESTART_IDEMPOTENCE",
            candidate_recovery,
        )
        removal = script.index("pkg delete -fy syswarden", restart_capture)
        self.assertLess(user_state_seed, previous_install)
        self.assertLess(previous_install, candidate_upgrade)
        self.assertLess(candidate_upgrade, candidate_reinstall)
        self.assertLess(candidate_reinstall, previous_rollback)
        self.assertLess(previous_rollback, candidate_recovery)
        self.assertLess(candidate_recovery, restart_capture)
        self.assertLess(restart_capture, removal)
        self.assertEqual(script.count("service syswarden onerestart"), 2)
        self.assertEqual(script.count("service syswardenwebtui onerestart"), 2)
        fixture_verification = script.index(
            'verify_sealed_input "$work/pf-v4.02.8.conf"',
            script.index("if [ \"$interface\" != \"INVALID\" ]"),
        )
        pf_application = script.index('pfctl -n -a "$anchor"', fixture_verification)
        self.assertLess(fixture_verification, pf_application)
        lock_acquire = script.index('mkdir "$lock_path"')
        first_pf_mutation = script.index('/sbin/kldload -n -q pf', lock_acquire)
        lock_release = script.index('rmdir "$lock_path"', first_pf_mutation)
        self.assertLess(lock_acquire, first_pf_mutation)
        self.assertLess(first_pf_mutation, lock_release)
        signature_before = script.index(
            'signature_before="$(signature_state "$signature_file")"'
        )
        signature_execution = script.index(
            "timeout 8 /usr/local/syswarden/bin/syswarden-core",
            signature_before,
        )
        signature_after = script.index(
            'signature_after="$(signature_state "$signature_file")"',
            signature_execution,
        )
        self.assertLess(signature_before, signature_execution)
        self.assertLess(signature_execution, signature_after)
        self.assertIn(
            "signature_file=/usr/local/syswarden/signatures.json", script
        )
        self.assertNotIn("runtime_signature=/opt/syswarden", script)
        self.assertIn('SIGNATURE_STATE_RESTORED" "$signature_restored"', script)
        restart_baseline = script.index("emit RESTART_BASELINE_INVENTORY")
        restart_one = script.index("emit RESTART_ONE_INVENTORY")
        restart_two = script.index("emit RESTART_TWO_INVENTORY")
        self.assertLess(restart_baseline, restart_one)
        self.assertLess(restart_one, restart_two)
        self.assertIn("stat -f '%HT'", script)
        self.assertIn("stat -f '%Lp'", script)
        self.assertIn("stat -f '%u'", script)
        self.assertIn("stat -f '%g'", script)
        self.assertIn("SIGNATURE_RULE_COUNT", script)
        self.assertIn("SIGNATURE_ENGINE_COUNT", script)
        self.assertIn("Loaded \\([0-9][0-9]*\\) threat signatures", script)
        self.assertIn("REMOVE_USER_CONFIG_SHA256", script)
        self.assertIn("quiet_boolean() {", script)
        self.assertIn(
            'emit "${phase}_PKG_INSTALLED" "$(quiet_boolean pkg info -e syswarden)"',
            script,
        )
        for command in ("pkg", "pfctl", "timeout", "file"):
            self.assertIn(
                f'emit {command.upper().replace("PFCTL", "PF").replace("TIMEOUT", "TIMEOUT")}_TOOL_READY '
                f'"$(quiet_boolean command -v {command})"',
                script,
            )
        self.assertNotRegex(script, r"\$\(boolean [^)]*>/dev/null")
        self.assertEqual(script.count("pkg query '%Fp' syswarden"), 2)
        self.assertNotIn("pkg query -l '%Fp'", script)
        self.assertIn("elf_arch_of() {", script)
        self.assertIn('ELF*64-bit*LSB*x86-64*) printf amd64', script)
        self.assertIn('ELF*64-bit*LSB*ARM*aarch64*) printf arm64', script)
        self.assertIn("honeyports='23 6379'", script)
        self.assertIn("tr -d ' '", script)
        self.assertIn(
            'emit PF_HONEYPORT_EXACT_VALUE "$honeyport_exact_value"', script
        )
        self.assertNotIn('token="$1"', script)
        for phase in freebsd_vm_lab.LIFECYCLE_PHASES:
            self.assertIn(f"capture_installed_phase {phase}", script)
        for suffix in freebsd_vm_lab.PHASE_EVIDENCE_SUFFIXES:
            self.assertIn(f'emit "${{phase}}_{suffix}"', script)

    def test_daemonizing_lifecycle_commands_use_foreground_timeout(self) -> None:
        service_wrappers = {
            "timeout -f 20 service syswarden onestart": 2,
            "timeout -f 20 service syswardenwebtui onestart": 2,
            "timeout -f 20 service syswarden onerestart": 2,
            "timeout -f 20 service syswardenwebtui onerestart": 2,
        }
        package_wrapper = 'timeout -f "$command_timeout" pkg add -f'

        def assert_contract(candidate: str) -> None:
            # Every daemonizing service operation keeps the exact 20-second
            # bound while -f prevents FreeBSD timeout(1) from reaping the
            # successfully detached service descendants.
            for wrapper, expected_count in service_wrappers.items():
                service_command = wrapper.removeprefix("timeout -f 20 ")
                self.assertEqual(
                    candidate.count(service_command), expected_count
                )
                self.assertEqual(candidate.count(wrapper), expected_count)
            # A package hook can start the same services, so each lifecycle
            # package operation needs the caller-provided bound and -f too.
            self.assertEqual(candidate.count('pkg add -f "$work/$'), 6)
            self.assertEqual(candidate.count(package_wrapper), 6)
            self.assertNotIn(
                'timeout "$command_timeout" pkg add -f', candidate
            )
            self.assertEqual(
                candidate.count("timeout -f 120 pkg delete -fy syswarden"),
                2,
            )

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        for mutation in (
            script.replace(
                "timeout -f 20 service syswarden onestart",
                "timeout 20 service syswarden onestart",
                1,
            ),
            script.replace(
                "timeout -f 20 service syswarden onestart",
                "timeout -f 120 service syswarden onestart",
                1,
            ),
            script.replace(
                package_wrapper,
                'timeout "$command_timeout" pkg add -f',
                1,
            ),
            script.replace(
                package_wrapper,
                'timeout -f 1800 pkg add -f',
                1,
            ),
            script.replace(
                "timeout -f 120 pkg delete -fy syswarden",
                "timeout 120 pkg delete -fy syswarden",
                1,
            ),
        ):
            with self.assertRaises(AssertionError):
                assert_contract(mutation)

    def test_tmp_sticky_bit_uses_freebsd_high_and_low_mode_fields(self) -> None:
        corrected = (
            '[ "$(stat -f \'%u:%g:%Mp:%Lp\' /tmp 2>/dev/null)" '
            '!= "0:0:1:777" ]'
        )
        truncated = (
            '[ "$(stat -f \'%u:%g:%Lp\' /tmp 2>/dev/null)" '
            '!= "0:0:1777" ]'
        )

        def assert_contract(script: str) -> None:
            self.assertEqual(script.count(corrected), 1)
            self.assertNotIn(truncated, script)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        with self.assertRaises(AssertionError):
            assert_contract(script.replace(corrected, truncated, 1))

    def test_streamed_remote_commands_use_fixed_standard_input(self) -> None:
        def assert_contract(script: str) -> None:
            logical_script = script.replace("\\\n", " ")
            commands = [
                line.strip()
                for line in logical_script.splitlines()
                if not line.lstrip().startswith("#")
            ]
            pkg_commands = [
                line
                for line in commands
                if re.search(r"\bpkg (?:update|install|add|delete)\b", line)
            ]
            tui_commands = [
                line for line in commands if "script -q /dev/null" in line
            ]
            self.assertEqual(len(pkg_commands), 11)
            self.assertEqual(len(tui_commands), 2)
            for command in pkg_commands + tui_commands:
                self.assertIn("</dev/null", command)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        redirect_positions = [
            match.start() for match in re.finditer(r"</dev/null", script)
        ]
        self.assertEqual(len(redirect_positions), 13)
        for mutation_index, position in enumerate(redirect_positions):
            mutated = script[:position] + script[position + len("</dev/null") :]
            with self.subTest(mutation_index=mutation_index):
                with self.assertRaises(AssertionError):
                    assert_contract(mutated)

    def test_signal_traps_use_canonical_status_then_exit_cleanup(self) -> None:
        def assert_contract(script: str) -> None:
            expected = (
                'trap \'final_cleanup "$?"\' EXIT',
                "trap 'exit 129' HUP",
                "trap 'exit 130' INT",
                "trap 'exit 143' TERM",
            )
            positions = []
            for line in expected:
                self.assertEqual(script.count(line), 1)
                positions.append(script.index(line))
            self.assertEqual(positions, sorted(positions))
            self.assertNotIn(
                'trap \'final_cleanup "$?"\' EXIT HUP INT TERM', script
            )
            self.assertNotIn("trap 'final_cleanup 129' HUP", script)
            cleanup_start = script.index("final_cleanup() {")
            cleanup_end = script.index("\n}\n", cleanup_start)
            cleanup_body = script[cleanup_start:cleanup_end]
            self.assertIn("trap - EXIT HUP INT TERM", cleanup_body)
            self.assertIn('exit "$cleanup_exit_status"', cleanup_body)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        for expected in (
            'trap \'final_cleanup "$?"\' EXIT',
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(AssertionError):
                    assert_contract(script.replace(expected, ": trap removed", 1))

    def test_final_trap_always_cleans_vm_work_and_guest_lock(self) -> None:
        def assert_contract(script: str) -> None:
            trap_line = 'trap \'final_cleanup "$?"\' EXIT'
            self.assertEqual(script.count(trap_line), 1)
            self.assertNotIn(
                'trap \'rmdir "$lock_path" >/dev/null 2>&1 || true; '
                'rm -rf "$work"\'',
                script,
            )
            self.assertNotIn(
                'trap \'cleanup_vm; rm -rf "$work"\' EXIT HUP INT TERM',
                script,
            )
            function_start = script.index("final_cleanup() {")
            function_end = script.index("\n}\n", function_start)
            body = script[function_start:function_end]
            self.assertIn('rmdir "$lock_path"', body)
            self.assertIn(
                'rmdir "$lock_path" >/dev/null 2>&1 || true', body
            )
            cleanup = body.index("cleanup_vm")
            work = body.index('for cleanup_path in "$work"')
            self.assertIn('rm -rf "$cleanup_path"', body)
            self.assertIn('[ -e "$cleanup_path" ] || [ -L "$cleanup_path" ]', body)
            self.assertIn('"$transport_work" "$sealed_work"', body)
            lock = body.index('rmdir "$lock_path"')
            self.assertLess(cleanup, work)
            self.assertLess(work, lock)
            trap_install = script.index(trap_line)
            lock_mkdir = script.index('mkdir "$lock_path"')
            self.assertLess(trap_install, lock_mkdir)
            lock_owned = script.index("lock_acquired=1", lock_mkdir)
            lock_chmod = script.index('chmod 700 "$lock_path"', lock_mkdir)
            self.assertLess(lock_owned, lock_chmod)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        assert_contract(script)
        with self.assertRaises(AssertionError):
            assert_contract(
                script.replace(
                    'rmdir "$lock_path" >/dev/null 2>&1 || true',
                    ': lock-release-removed',
                    1,
                )
            )

    def test_pf_restore_fact_requires_exact_disabled_final_status(self) -> None:
        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        explicit_cleanup = script.rindex("\ncleanup_vm\n")
        final_info = script.index(
            'pfctl -s info >"$work/pf-info-after" 2>&1', explicit_cleanup
        )
        final_fact = script.index('emit PF_FINAL_STATUS "$final_status"', final_info)
        restored_fact = script.index(
            'emit PF_BASELINE_RESTORED "$restored"', final_fact
        )
        self.assertLess(explicit_cleanup, final_info)
        self.assertLess(final_info, final_fact)
        self.assertLess(final_fact, restored_fact)
        self.assertIn('[ "$info_after_rc" -eq 0 ]', script[final_info:restored_fact])
        self.assertIn(
            '[ "$final_status" = "Disabled" ]', script[final_info:restored_fact]
        )
        self.assertIn(
            '[ "$baseline_status" = "Disabled" ]',
            script[final_info:restored_fact],
        )
        self.assertIn("PF_FINAL_STATUS", freebsd_vm_lab.BASE_EVIDENCE_KEYS)

    def test_report_write_is_atomic_and_rejects_symlink(self) -> None:
        destination = self.root / "report.json"
        report = {"harness_status": "pass", "release_ready": False}
        freebsd_vm_lab.write_report(destination, report, pretty=True)
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8")), report
        )
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        destination.unlink()
        target = self.root / "target.json"
        target.write_text("keep\n", encoding="utf-8")
        destination.symlink_to(target)
        with self.assertRaisesRegex(
            freebsd_vm_lab.FreeBSDVMLabError, "absent or a regular file"
        ):
            freebsd_vm_lab.write_report(destination, report, pretty=False)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_main_returns_one_for_trustworthy_product_blockers(self) -> None:
        destination = self.root / "blocked-report.json"
        blocked = {
            "harness_status": "pass",
            "product_status": "known_blocker",
            "release_ready": False,
        }
        arguments = (
            "--repo-root",
            str(self.repo),
            "--packages-dir",
            str(self.packages),
            "--previous-packages-dir",
            str(self.previous_packages),
            "--ssh-host",
            "127.0.0.1",
            "--ssh-port",
            "2222",
            "--ssh-user",
            "syswarden",
            "--identity-file",
            str(self.identity),
            "--known-hosts-file",
            str(self.known_hosts),
            "--vm-marker-token-file",
            str(self.marker_token_file),
            "--output",
            str(destination),
        )
        with mock.patch.object(freebsd_vm_lab, "run_lab", return_value=blocked):
            self.assertEqual(freebsd_vm_lab.main(arguments), 1)
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8")), blocked
        )


if __name__ == "__main__":
    unittest.main()
