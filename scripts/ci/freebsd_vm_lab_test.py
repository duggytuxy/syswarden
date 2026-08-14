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
            "PREVIOUS_PACKAGE_SHA256": "b" * 64,
            "CANDIDATE_PACKAGE_SHA256": "a" * 64,
            "PF_BASELINE_STATUS": "Disabled",
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
            "MODE_CLI": "750",
            "MODE_CORE": "750",
            "MODE_TUI": "750",
            "MODE_SIGNATURES": "640",
            "LINK_CLI": "/usr/local/syswarden/bin/syswarden-cli",
            "LINK_TUI": "/usr/local/syswarden/bin/syswarden-tui",
            "CLI_DIRECT_RC": "0",
            "CLI_LINK_RC": "0",
            "RC_CORE_MODE": "755",
            "RC_WEB_MODE": "755",
            "RC_CORE_COMMAND": "/usr/local/syswarden/bin/syswarden-core",
            "RC_WEB_COMMAND": "/usr/local/syswarden/bin/syswarden-cli",
            "RC_CORE_ENABLED": "YES",
            "RC_WEB_ENABLED": "YES",
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
            "PF_HONEYPORT_EXACT_VALUE": "",
            "PF_HONEYPORT_SYNTAX_RC": "not_run",
            "REMOVE_RC": "0",
            "REMOVE_PKG_INVENTORY": "",
            "REMOVE_USER_STATE_INVENTORY": "\n".join(
                sorted(freebsd_vm_lab.EXPECTED_USER_STATE_INVENTORY)
            ),
            "REMOVE_USER_CONFIG_SHA256": freebsd_vm_lab.USER_CONFIG_SHA256,
            "REMOVE_USER_DATA_SHA256": freebsd_vm_lab.USER_DATA_SHA256,
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
            'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")\n',
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
        ):
            freebsd_vm_lab.parse_markers("host command output\n", frozenset())

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

    def test_exact_legacy_abi_and_previous_mixed_elf_are_known_bsd_blocker(self) -> None:
        evidence = passing_evidence()
        evidence["CANDIDATE_PACKAGE_SHA256"] = self.package_sha
        evidence["PREVIOUS_PACKAGE_SHA256"] = self.previous_package_sha
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
        self.assertEqual(report["product_status"], "known_blocker")
        self.assertEqual(report["blocker_ids"], ["SW-BSD-001"])
        self.assertEqual(report["unexpected_failed_check_ids"], [])
        previous_package = report["lifecycle_phases"]["previous_install"][
            "package"
        ]
        self.assertEqual(
            previous_package["elf_architectures"],
            {"cli": "amd64", "core": "arm64", "tui": "arm64"},
        )

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

    def test_pf_failures_are_known_only_with_exact_236379_proof(self) -> None:
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
        self.assertEqual(report["product_status"], "known_blocker")
        self.assertEqual(report["blocker_ids"], ["SW-FW-004"])
        self.assertEqual(report["unexpected_failed_check_ids"], [])

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
        self.assertEqual(report["product_status"], "known_blocker")
        self.assertEqual(report["blocker_ids"], ["SW-BSD-001", "SW-FW-004"])
        self.assertEqual(report["unexpected_failed_check_ids"], [])

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

    def test_current_prefix_rcd_startup_and_pf_defects_are_blockers(self) -> None:
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
        self.assertEqual(report["product_status"], "known_blocker")
        self.assertIs(report["release_ready"], False)
        self.assertEqual(report["blocker_ids"], ["SW-BSD-001", "SW-FW-004"])
        self.assertEqual(report["unexpected_failed_check_ids"], [])
        self.assertTrue(
            {
                "SW-PKG-FBSD-PREFIX-001",
                "SW-PKG-FBSD-RCD-CORE-001",
                "SW-PKG-FBSD-RCD-WEB-001",
                "SW-PKG-FBSD-RCD-CORE-PATH-001",
                "SW-PKG-FBSD-RCD-WEB-PATH-001",
                "SW-PKG-FBSD-START-CORE-001",
                "SW-PKG-FBSD-START-WEB-001",
                "SW-PF-FBSD-HONEYPORT-001",
            }.issubset(blockers)
        )

    def test_cleanup_evidence_is_harness_critical(self) -> None:
        mutations = {
            "ruleset_not_restored": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="0"
            ),
            "pf_left_enabled": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="1",
                PF_FINAL_STATUS="Enabled",
            ),
            "pf_status_missing": lambda evidence: evidence.update(
                PF_BASELINE_RESTORED="1",
                PF_FINAL_STATUS="",
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
        self.assertNotIn(check_id, freebsd_vm_lab.EXPECTED_FAILED_CHECK_BLOCKERS)

    def test_expected_and_unexpected_failures_are_classified_separately(self) -> None:
        self.assertEqual(
            set(freebsd_vm_lab.EXPECTED_FAILED_CHECK_BLOCKERS.values()),
            freebsd_vm_lab.CANONICAL_BLOCKER_IDS,
        )
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
        self.assertEqual(report["blocker_ids"], ["SW-BSD-001"])
        self.assertEqual(
            report["unexpected_failed_check_ids"],
            ["SW-PKG-FBSD-CANDIDATE-UPGRADE-INVENTORY-001"],
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
        restart_capture = script.index(
            "capture_installed_phase CANDIDATE_RESTART_IDEMPOTENCE",
            candidate_reinstall,
        )
        previous_rollback = script.index(
            'pkg add -f "$work/$previous_package_name"', restart_capture
        )
        removal = script.index("pkg delete -fy syswarden", previous_rollback)
        self.assertLess(user_state_seed, previous_install)
        self.assertLess(previous_install, candidate_upgrade)
        self.assertLess(candidate_upgrade, candidate_reinstall)
        self.assertLess(candidate_reinstall, restart_capture)
        self.assertLess(restart_capture, previous_rollback)
        self.assertLess(previous_rollback, removal)
        self.assertEqual(script.count("service syswarden onerestart"), 2)
        self.assertEqual(script.count("service syswardenwebtui onerestart"), 2)
        fixture_verification = script.index(
            'sha256 -q "$work/pf-v4.02.8.conf"',
            script.index("if [ \"$interface\" != \"INVALID\" ]"),
        )
        pf_application = script.index('pfctl -n -a "$anchor"', fixture_verification)
        self.assertLess(fixture_verification, pf_application)
        lock_acquire = script.index('mkdir "$lock_path"')
        first_pf_mutation = script.index('kldload pf', lock_acquire)
        lock_release = script.index('rmdir "$lock_path"', first_pf_mutation)
        self.assertLess(lock_acquire, first_pf_mutation)
        self.assertLess(first_pf_mutation, lock_release)
        signature_trap = script.index(
            "trap 'restore_signature_state >/dev/null 2>&1' EXIT"
        )
        signature_mutation = script.index(
            'rm -rf "$runtime_signature"', signature_trap
        )
        self.assertLess(signature_trap, signature_mutation)
        self.assertIn('cp -p "$runtime_signature"', script)
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

    def test_final_trap_always_cleans_vm_work_and_guest_lock(self) -> None:
        def assert_contract(script: str) -> None:
            trap_line = 'trap \'final_cleanup "$?"\' EXIT HUP INT TERM'
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
            cleanup = body.index("cleanup_vm")
            work = body.index('rm -rf "$work"')
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
