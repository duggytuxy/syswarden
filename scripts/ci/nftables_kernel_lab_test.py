#!/usr/bin/env python3
"""Tests for the isolated nftables kernel characterization laboratory."""

from __future__ import annotations

import os
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
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, args: tuple[str, ...], *, timeout: int) -> nftables_kernel_lab.CommandResult:
        del timeout
        self.calls.append(tuple(args))
        if args[0] == "go":
            return nftables_kernel_lab.CommandResult(
                0,
                "--- PASS: TestNftablesRulesGolden_SW_QA_001 (0.01s)\nPASS\n",
                "",
            )
        if args[1] == "info":
            return nftables_kernel_lab.CommandResult(0, "true\n", "")
        if args[1] == "version":
            return nftables_kernel_lab.CommandResult(0, "5.6.0\n", "")
        if args[1:3] == ("image", "exists"):
            return nftables_kernel_lab.CommandResult(0, "", "")
        if args[1:3] == ("image", "inspect"):
            return nftables_kernel_lab.CommandResult(
                0, IMAGE.rsplit("@", 1)[1] + "\n", ""
            )
        if args[1] == "run":
            host_netns = os.readlink("/proc/self/ns/net")
            return nftables_kernel_lab.CommandResult(
                0,
                "\n".join(
                    (
                        f"NETNS={host_netns}-isolated",
                        "NFT_VERSION=nftables v1.1.6 (Commodore Bullmoose #2)",
                        "LEGACY_CHECK_RC=1",
                        "LEGACY_LIST_RC=0",
                        "LEGACY_OBJECTS=0",
                        "CANDIDATE_APPLY_RC=0",
                        "CANDIDATE_LIST_RC=0",
                        "CANDIDATE_OBJECTS=42",
                        "DYNAMIC_ADD_RC=0",
                        "DYNAMIC_LIST_RC=0",
                        "DYNAMIC_TIMEOUT_OK=1",
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

    def test_proves_corrected_candidate_and_claims_local_lab_ready(self) -> None:
        runner = FakeRunner()
        report = nftables_kernel_lab.run_lab(
            self.root, "podman", "never", runner=runner
        )
        self.assertEqual(report["harness_status"], "pass")
        self.assertEqual(report["product_status"], "pass")
        self.assertEqual(report["finding_id"], "SW-FW-004")
        self.assertIs(report["release_ready"], True)
        self.assertTrue(all(report["conditions"].values()))
        run = next(call for call in runner.calls if call[1] == "run")
        self.assertIn("--network=none", run)
        self.assertIn("--cap-add=NET_ADMIN", run)
        self.assertNotIn("--privileged", run)
        self.assertEqual(sum(value.endswith(":ro") for value in run), 2)
        generator = next(call for call in runner.calls if call[0] == "go")
        self.assertIn("-mod=readonly", generator)

    def test_rejects_missing_frozen_regression_baseline(self) -> None:
        golden = self.root / "testdata/firewall/nftables-v4.02.8.nft"
        golden.write_text("tcp dport { 23, 6379 }\n", encoding="utf-8")
        with self.assertRaisesRegex(
            nftables_kernel_lab.NftablesLabError, "no longer contains"
        ):
            nftables_kernel_lab.verify_corrected_source_contract(self.root, golden)

    def test_rejects_non_isolated_or_partial_kernel_evidence(self) -> None:
        output = "\n".join(
            (
                f"NETNS={os.readlink('/proc/self/ns/net')}",
                "NFT_VERSION=nftables v1.1.6 (Commodore Bullmoose #2)",
                "LEGACY_CHECK_RC=1",
                "LEGACY_LIST_RC=0",
                "LEGACY_OBJECTS=1",
                "CANDIDATE_APPLY_RC=0",
                "CANDIDATE_LIST_RC=0",
                "CANDIDATE_OBJECTS=42",
                "DYNAMIC_ADD_RC=0",
                "DYNAMIC_LIST_RC=0",
                "DYNAMIC_TIMEOUT_OK=1",
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
