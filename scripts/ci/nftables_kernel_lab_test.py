#!/usr/bin/env python3
"""Tests for the isolated nftables kernel characterization laboratory."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nftables_kernel_lab


IMAGE = (
    "docker.io/catthehacker/ubuntu:act-24.04@sha256:"
    "b839c14c4410998529ec18f951262bdf87a2b23bc1467304d07b491b9455e074"
)


class FakeRunner(nftables_kernel_lab.CommandRunner):
    def __init__(
        self,
        *,
        service_is_remote: bool = False,
        server_os: str = "linux",
        server_architecture: str = "amd64",
        server_kernel: str | None = None,
        container_architecture: str = "x86_64",
        container_kernel: str | None = None,
        mutate_binary: bool = False,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.service_is_remote = service_is_remote
        self.server_os = server_os
        self.server_architecture = server_architecture
        self.server_kernel = server_kernel or platform.release()
        self.container_architecture = container_architecture
        self.container_kernel = container_kernel or self.server_kernel
        self.mutate_binary = mutate_binary

    def run(self, args: tuple[str, ...], *, timeout: int) -> nftables_kernel_lab.CommandResult:
        del timeout
        self.calls.append(tuple(args))
        if args[0] == "env" and "go" in args and "-c" in args:
            destination = Path(args[args.index("-o") + 1])
            destination.write_bytes(b"static Go test fixture")
            destination.chmod(0o700)
            return nftables_kernel_lab.CommandResult(0, "", "")
        if args[0] == "env" and "go" in args:
            return nftables_kernel_lab.CommandResult(
                0,
                "--- PASS: TestNftablesRulesGolden_SW_QA_001 (0.01s)\nPASS\n",
                "",
            )
        if args[1] == "info":
            return nftables_kernel_lab.CommandResult(
                0,
                json.dumps(
                    {
                        "host": {
                            "security": {"rootless": True},
                            "serviceIsRemote": self.service_is_remote,
                            "os": self.server_os,
                            "arch": self.server_architecture,
                            "kernel": self.server_kernel,
                        }
                    }
                ),
                "",
            )
        if args[1] == "version":
            return nftables_kernel_lab.CommandResult(0, "5.6.0\n", "")
        if args[1:3] == ("image", "exists"):
            return nftables_kernel_lab.CommandResult(0, "", "")
        if args[1:3] == ("image", "inspect"):
            return nftables_kernel_lab.CommandResult(
                0, IMAGE.rsplit("@", 1)[1] + "\n", ""
            )
        if args[1] == "run":
            if self.mutate_binary:
                mount = next(
                    value
                    for value in args
                    if value.endswith(
                        ":/fixture/syswarden-core-firewall.test:ro"
                    )
                )
                binary = Path(mount.split(":/fixture/", 1)[0])
                binary.chmod(0o700)
                binary.write_bytes(b"changed binary")
                binary.chmod(0o500)
            host_netns = os.readlink("/proc/self/ns/net")
            return nftables_kernel_lab.CommandResult(
                0,
                "\n".join(
                    (
                        f"NETNS={host_netns}-isolated",
                        f"KERNEL_VERSION={self.container_kernel}",
                        f"KERNEL_MACHINE={self.container_architecture}",
                        "NFT_VERSION=nftables v1.1.6 (Commodore Bullmoose #2)",
                        "LEGACY_CHECK_RC=1",
                        "LEGACY_LIST_RC=0",
                        "LEGACY_OBJECTS=0",
                        "CANDIDATE_APPLY_RC=0",
                        "CANDIDATE_LIST_RC=0",
                        "CANDIDATE_OBJECTS=42",
                        "MANAGER_KERNEL_RC=0",
                        "MANAGER_KERNEL_PASS=1",
                        "MANAGER_RAW_INTERVALS_OK=1",
                        "CLEANUP_RC=0",
                        "ERROR_BEGIN",
                        "/fixture/syswarden.nft:81: Service out of range",
                        "ERROR_END",
                    )
                )
                + "\n",
                "",
            )
        raise AssertionError(args)


class NftablesKernelLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".actrc").write_text(
            "-P ubuntu-24.04=" + IMAGE + "\n", encoding="utf-8"
        )
        golden = self.root / "testdata/firewall/nftables-v4.02.8.nft"
        golden.parent.mkdir(parents=True)
        golden.write_text(
            "tcp dport { 236379 }\ntcp dport { 236379 }\n", encoding="utf-8"
        )
        loader = self.root / "src/core/syswarden-cli/config/config_loader.go"
        generator = (
            self.root
            / "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
        )
        loader.parent.mkdir(parents=True)
        generator.parent.mkdir(parents=True)
        serializer = (
            self.root
            / "src/core/syswarden-cli/pkg/firewall/honeyports.go"
        )
        loader.write_text(
            'strings.Join(m.Security.Honeyports, " ")\n', encoding="utf-8"
        )
        generator.write_text(
            "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)\n",
            encoding="utf-8",
        )
        serializer.write_text(
            'strings.Join(canonical, ", ")\n', encoding="utf-8"
        )
        (generator.parent / "firewall_linux_golden_test.go").write_text(
            "func TestNftablesRulesGolden_SW_QA_001() {}\n", encoding="utf-8"
        )
        manager = self.root / "src/core/syswarden-core/firewall/manager_linux.go"
        manager.parent.mkdir(parents=True)
        manager.write_text("package firewall\n", encoding="utf-8")
        (manager.parent / "manager_kernel_integration_linux_test.go").write_text(
            "package firewall\n", encoding="utf-8"
        )
        subprocess.run(("git", "init", "-q"), cwd=self.root, check=True)
        subprocess.run(
            ("git", "config", "user.email", "nft-lab-tests@example.invalid"),
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ("git", "config", "user.name", "nftables lab tests"),
            cwd=self.root,
            check=True,
        )
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(
            ("git", "commit", "-qm", "fixture"), cwd=self.root, check=True
        )

    def test_proves_corrected_candidate_and_claims_local_lab_ready(self) -> None:
        runner = FakeRunner()
        report = nftables_kernel_lab.run_lab(
            self.root, "podman", "never", runner=runner
        )
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "pass")
        self.assertEqual(report["finding_id"], "SW-FW-004")
        self.assertEqual(report["schema_version"], 3)
        self.assertIs(report["release_ready"], True)
        self.assertTrue(all(report["conditions"].values()))
        self.assertIs(
            report["conditions"]["native_manager_interval_contract_passed"],
            True,
        )
        self.assertIs(report["repository_binding"]["worktree_clean"], True)
        self.assertRegex(
            report["repository_binding"]["commit_sha"], r"^[0-9a-f]{40}$"
        )
        self.assertRegex(
            report["repository_binding"]["tree_sha"], r"^[0-9a-f]{40}$"
        )
        self.assertIs(report["source_snapshot"]["read_only"], True)
        self.assertIs(
            report["source_snapshot"]["revalidated_after_container"], True
        )
        self.assertRegex(
            report["source_snapshot"]["archive_sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            [item["path"] for item in report["source_snapshot"]["critical_files"]],
            list(nftables_kernel_lab.SOURCE_BINDING_PATHS),
        )
        self.assertEqual(
            report["manager_test_binary"]["before"],
            report["manager_test_binary"]["after"],
        )
        self.assertIs(report["manager_test_binary"]["identical"], True)
        self.assertEqual(
            report["manager_test_binary"]["before"]["mode"], "0500"
        )
        self.assertIs(report["engine"]["service_is_remote"], False)
        self.assertEqual(report["engine"]["server_os"], "linux")
        self.assertEqual(report["engine"]["server_architecture"], "amd64")
        self.assertEqual(report["engine"]["container_architecture"], "amd64")
        self.assertEqual(
            report["engine"]["container_kernel"], report["engine"]["server_kernel"]
        )
        run = next(call for call in runner.calls if call[1] == "run")
        self.assertIn("--pull=never", run)
        self.assertIn("--network=none", run)
        self.assertIn("--platform=linux/amd64", run)
        self.assertIn("--read-only", run)
        self.assertIn("--cap-drop=all", run)
        self.assertIn("--cap-add=NET_ADMIN", run)
        self.assertIn(
            "--tmpfs=/tmp:rw,nodev,nosuid,noexec,size=64m,mode=1777", run
        )
        self.assertNotIn("--privileged", run)
        self.assertEqual(sum(value.endswith(":ro") for value in run), 3)
        self.assertTrue(
            any(
                value.endswith(":/fixture/syswarden-core-firewall.test:ro")
                for value in run
            )
        )
        self.assertNotIn("nft add element", nftables_kernel_lab.CONTAINER_SCRIPT)
        generator = next(
            call
            for call in runner.calls
            if "-run=^TestNftablesRulesGolden_SW_QA_001$" in call
        )
        self.assertIn("-mod=readonly", generator)
        manager_build = next(
            call
            for call in runner.calls
            if "CGO_ENABLED=0" in call and "-c" in call
        )
        for command in (generator, manager_build):
            self.assertIn("GOENV=off", command)
            self.assertIn("GOWORK=off", command)
            self.assertIn("GOFLAGS=-buildvcs=false", command)
        self.assertIn("-mod=readonly", manager_build)
        self.assertIn("-c", manager_build)
        self.assertIn("./firewall", manager_build)
        generator_root = Path(generator[generator.index("-C") + 1])
        manager_root = Path(manager_build[manager_build.index("-C") + 1])
        self.assertNotEqual(generator_root, self.root / "src/core/syswarden-cli")
        self.assertNotEqual(manager_root, self.root / "src/core/syswarden-core")

    def test_rejects_remote_podman_endpoint_before_container_execution(self) -> None:
        runner = FakeRunner(service_is_remote=True)
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "local non-remote"
        ):
            nftables_kernel_lab.run_lab(
                self.root, "podman", "never", runner=runner
            )
        self.assertFalse(any(call[1] == "run" for call in runner.calls))

    def test_rejects_container_kernel_not_bound_to_server(self) -> None:
        runner = FakeRunner(container_kernel="different-kernel")
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError,
            "does not prove the corrected honeyport contract",
        ):
            nftables_kernel_lab.run_lab(
                self.root, "podman", "never", runner=runner
            )

    def test_rejects_manager_binary_changed_by_container_run(self) -> None:
        runner = FakeRunner(mutate_binary=True)
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "binary changed"
        ):
            nftables_kernel_lab.run_lab(
                self.root, "podman", "never", runner=runner
            )

    def test_rejects_dirty_worktree_before_compiling_evidence(self) -> None:
        generator = self.root / "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
        generator.write_text(
            generator.read_text(encoding="utf-8") + "// uncommitted\n",
            encoding="utf-8",
        )
        runner = FakeRunner()
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "requires a clean Git worktree"
        ):
            nftables_kernel_lab.run_lab(
                self.root, "podman", "never", runner=runner
            )
        self.assertEqual(runner.calls, [])

    def test_rejects_missing_frozen_regression_baseline(self) -> None:
        golden = self.root / "testdata/firewall/nftables-v4.02.8.nft"
        golden.write_text("tcp dport { 23, 6379 }\n", encoding="utf-8")
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "no longer contains"
        ):
            nftables_kernel_lab.verify_corrected_source_contract(self.root, golden)

    def test_repository_golden_preserves_frozen_regression_baseline(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        golden = repository / "testdata/firewall/nftables-v4.02.8.nft"
        text = golden.read_text(encoding="utf-8")
        self.assertEqual(text.count("tcp dport { 236379 }"), 2)
        self.assertNotIn("tcp dport { 23, 6379 }", text)

    def test_rejects_non_isolated_or_partial_kernel_evidence(self) -> None:
        output = "\n".join(
            (
                f"NETNS={os.readlink('/proc/self/ns/net')}",
                f"KERNEL_VERSION={platform.release()}",
                "KERNEL_MACHINE=x86_64",
                "NFT_VERSION=nftables v1.1.6 (Commodore Bullmoose #2)",
                "LEGACY_CHECK_RC=1",
                "LEGACY_LIST_RC=0",
                "LEGACY_OBJECTS=1",
                "CANDIDATE_APPLY_RC=0",
                "CANDIDATE_LIST_RC=0",
                "CANDIDATE_OBJECTS=42",
                "MANAGER_KERNEL_RC=0",
                "MANAGER_KERNEL_PASS=1",
                "MANAGER_RAW_INTERVALS_OK=1",
                "CLEANUP_RC=0",
                "ERROR_BEGIN",
                "Service out of range",
                "ERROR_END",
            )
        )
        markers, error = nftables_kernel_lab.parse_container_output(output)
        self.assertEqual(markers["LEGACY_OBJECTS"], "1")
        self.assertEqual(error, "Service out of range")

    def test_requires_exact_digest_pinned_act_image(self) -> None:
        (self.root / ".actrc").write_text(
            "-P ubuntu-24.04=catthehacker/ubuntu:act-24.04\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "exactly one"
        ):
            nftables_kernel_lab.pinned_act_image(self.root)

    def test_rejects_symlink_golden(self) -> None:
        golden = self.root / "testdata/firewall/nftables-v4.02.8.nft"
        target = self.root / "external.nft"
        target.write_text(golden.read_text(encoding="utf-8"), encoding="utf-8")
        golden.unlink()
        golden.symlink_to(target)
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "real regular file"
        ):
            nftables_kernel_lab.require_regular_file(golden, "golden")


if __name__ == "__main__":
    unittest.main()
