#!/usr/bin/env python3
"""Adversarial tests for the fail-closed release qualification gate."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_qualification_gate as gate


class QualificationFixture:
    version = "v4.02.8"
    previous_version = "v4.02.7"

    def __init__(self, root: Path, *, profile: str = "release") -> None:
        self.root = root
        self.repo = root / "repo"
        self.evidence = root / "evidence"
        self.repo.mkdir()
        self.evidence.mkdir()
        self.now = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
        self._make_repository()
        self.commit = self._git("rev-parse", "HEAD")
        self.tree = self._git("rev-parse", "HEAD^{tree}")
        self._git("tag", self.version)
        self.packages = self._make_packages()
        self.manifest_sha = gate.read_snapshot(
            self.packages / "SHA256SUMS.txt", "fixture manifest"
        ).sha256
        self.checksums = self._read_checksums()
        self.reports = {
            "nftables_kernel": self.evidence / "nft.json",
            "linux_package_lifecycle": self.evidence / "packages.json",
        }
        self.write_reports(profile)

    def _run(self, *args: str, cwd: Path | None = None) -> str:
        process = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        if process.returncode != 0:
            raise AssertionError(process.stderr or process.stdout)
        return process.stdout.strip()

    def _git(self, *args: str) -> str:
        return self._run("git", "-c", "core.fsmonitor=false", *args, cwd=self.repo)

    def _make_repository(self) -> None:
        self._run("git", "init", "-q", cwd=self.repo)
        self._git("config", "user.email", "tests@example.invalid")
        self._git("config", "user.name", "Qualification Tests")
        for path, count in gate.SOURCE_TARGETS:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join([f"// {self.version}"] * count) + "\n", encoding="utf-8")
        (self.repo / "README.md").write_text(
            f"Current source version: **{self.version}**.\n", encoding="utf-8"
        )
        (self.repo / "changelog.md").write_text(
            f"# Release {self.version}\n\n### TEST\n- qualification\n\n---\n",
            encoding="utf-8",
        )
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")

    def _make_packages(self) -> Path:
        directory = self.evidence / "candidate-packages"
        directory.mkdir()
        records: list[str] = []
        for name in gate.package_names(self.version):
            payload = f"candidate:{name}\n".encode()
            (directory / name).write_bytes(payload)
            records.append(f"{hashlib.sha256(payload).hexdigest()}  {name}")
        (directory / "SHA256SUMS.txt").write_text(
            "\n".join(sorted(records)) + "\n", encoding="utf-8"
        )
        return directory

    def _read_checksums(self) -> dict[str, str]:
        records: dict[str, str] = {}
        for line in (self.packages / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            records[name] = digest
        return records

    def binding(self) -> dict[str, object]:
        return {
            "commit_sha": self.commit,
            "tree_sha": self.tree,
            "version": self.version,
            "tag": self.version,
            "package_manifest_sha256": self.manifest_sha,
            "package_checksums": self.checksums,
        }

    def lifecycle(self, kind: str) -> dict[str, object]:
        previous_checksums = {
            name: hashlib.sha256(f"previous:{name}\n".encode()).hexdigest()
            for name in gate.package_names(self.previous_version)
        }
        return {
            "previous_version": self.previous_version,
            "candidate_version": self.version,
            "runtime_mode": "active-real-init",
            "active_service_manager": True,
            "active_postinstall": True,
            "legacy_runtime_retirement": True,
            "fresh_install": True,
            "upgrade": True,
            "reinstall": True,
            "rollback": True,
            "remove": True,
            "purge": True,
            "second_restart": True,
            "previous_package_checksums": previous_checksums,
        }

    def linux_coordinates(self, *, blocker: bool = False) -> list[dict[str, str]]:
        result = []
        for platform in ("almalinux", "alpine", "debian", "fedora", "ubuntu"):
            for architecture in ("amd64", "arm64"):
                status = "blocker" if blocker else "pass"
                result.append(
                    {"platform": platform, "architecture": architecture, "status": status}
                )
        return result

    def report(self, kind: str, profile: str) -> dict[str, object]:
        blockers = {
            "nftables_kernel": ["SW-FW-004"],
            "linux_package_lifecycle": ["SW-CFG-001", "SW-PKG-001"],
        }
        characterization = profile == "characterization"
        if kind == "linux_package_lifecycle":
            coordinates = self.linux_coordinates(blocker=characterization)
        else:
            coordinates = []
        common = {
            "kind": kind,
            "generated_at": self.now.isoformat(),
            "raw_report_sha256": hashlib.sha256(f"raw:{kind}".encode()).hexdigest(),
            "bindings": self.binding(),
            "harness_complete": True,
            "release_ready": not characterization,
            "blocker_ids": blockers[kind] if characterization else [],
        }
        if kind == "nftables_kernel":
            return gate.build_bound_report(
                **common,
                conditions={
                    "network_namespace_isolated": True,
                    "host_namespace_untouched": True,
                    "kernel_apply_executed": True,
                    "cleanup_complete": True,
                },
                network_namespaces={
                    "host": "net:[100]",
                    "laboratory": "net:[200]",
                },
            )
        return gate.build_bound_report(
            **common,
            coordinates=coordinates,
            lifecycle=self.lifecycle(kind),
        )

    def write_reports(self, profile: str) -> None:
        for kind, path in self.reports.items():
            path.write_text(
                json.dumps(self.report(kind, profile), sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def load_report(self, kind: str) -> dict[str, object]:
        return json.loads(self.reports[kind].read_text(encoding="utf-8"))

    def save_report(self, kind: str, document: dict[str, object]) -> None:
        self.reports[kind].write_text(
            json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
        )

    def args(self, profile: str = "release", *, output: Path | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            command="generate",
            profile=profile,
            repo_root=self.repo,
            expected_sha=self.commit,
            expected_version=self.version,
            candidate_packages_dir=self.packages,
            nft_report=self.reports["nftables_kernel"],
            package_report=self.reports["linux_package_lifecycle"],
            max_age_seconds=3600,
            max_report_skew_seconds=300,
            output=output or (self.evidence / "aggregate.json"),
        )


class ReleaseQualificationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = QualificationFixture(Path(self.temporary.name))

    def assertEvidenceError(self, args: argparse.Namespace) -> None:
        with self.assertRaises(gate.EvidenceError):
            gate.run_gate(args, now=self.fixture.now)

    def traversal_path(self, target: Path) -> Path:
        hop = target.parent / "traversal-hop"
        hop.mkdir(exist_ok=True)
        return hop / ".." / target.name

    def test_release_profile_passes_and_writes_bound_aggregate(self) -> None:
        code, aggregate = gate.run_gate(self.fixture.args(), now=self.fixture.now)
        self.assertEqual(code, 0)
        self.assertEqual(aggregate["verdict"], "pass")
        self.assertTrue(aggregate["release_ready"])
        self.assertEqual(aggregate["bindings"]["commit_sha"], self.fixture.commit)
        self.assertEqual(set(aggregate["reports"]), set(self.fixture.reports))
        self.assertTrue(self.fixture.args().output.is_file())

    def test_characterization_accepts_only_the_exact_canonical_allowlist(self) -> None:
        self.fixture.write_reports("characterization")
        code, aggregate = gate.run_gate(
            self.fixture.args("characterization"), now=self.fixture.now
        )
        self.assertEqual(code, 0)
        self.assertFalse(aggregate["release_ready"])
        self.assertEqual(
            aggregate["allowlisted_findings"],
            ["SW-CFG-001", "SW-FW-004", "SW-PKG-001"],
        )

    def test_legacy_report_without_bindings_is_invalid(self) -> None:
        self.fixture.reports["nftables_kernel"].write_text(
            '{"schema_version":1,"generated_at":"2026-08-14T12:00:00+00:00"}\n',
            encoding="utf-8",
        )
        self.assertEvidenceError(self.fixture.args())

    def test_legacy_report_returns_cli_exit_2(self) -> None:
        self.fixture.reports["nftables_kernel"].write_text(
            '{"schema_version":1,"generated_at":"2026-08-14T12:00:00+00:00"}\n',
            encoding="utf-8",
        )
        argv = [
            "generate",
            "--profile",
            "release",
            "--repo-root",
            str(self.fixture.repo),
            "--expected-sha",
            self.fixture.commit,
            "--expected-version",
            self.fixture.version,
            "--candidate-packages-dir",
            str(self.fixture.packages),
            "--nft-report",
            str(self.fixture.reports["nftables_kernel"]),
            "--package-report",
            str(self.fixture.reports["linux_package_lifecycle"]),
            "--max-age-seconds",
            "172800",
            "--output",
            str(self.fixture.evidence / "cli-aggregate.json"),
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(argv), 2)

    def test_report_symlink_inside_repo_and_duplicate_inode_are_rejected(self) -> None:
        original = self.fixture.reports["nftables_kernel"]
        symlink = self.fixture.evidence / "nft-link.json"
        symlink.symlink_to(original)
        args = self.fixture.args()
        args.nft_report = symlink
        self.assertEvidenceError(args)

        inside = self.fixture.repo / "evidence.json"
        inside.write_bytes(original.read_bytes())
        args = self.fixture.args()
        args.nft_report = inside
        self.assertEvidenceError(args)

        duplicate = self.fixture.evidence / "duplicate.json"
        os.link(original, duplicate)
        args = self.fixture.args()
        args.package_report = duplicate
        self.assertEvidenceError(args)

    def test_duplicate_json_key_unknown_key_wrong_type_and_schema_are_invalid(self) -> None:
        path = self.fixture.reports["nftables_kernel"]
        content = path.read_text(encoding="utf-8").rstrip()[:-1]
        path.write_text(content + ',"bindings":{}}\n', encoding="utf-8")
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("nftables_kernel")
        document["waiver"] = True
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("nftables_kernel")
        document["harness_complete"] = "true"
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("linux_package_lifecycle")
        document["schema_version"] = 3
        self.fixture.save_report("linux_package_lifecycle", document)
        self.assertEvidenceError(self.fixture.args())

    def test_every_report_schema_version_requires_an_exact_integer(self) -> None:
        for kind, expected in gate.REPORT_SCHEMA_VERSIONS.items():
            for invalid in (True, float(expected)):
                with self.subTest(report=kind, schema_version=repr(invalid)):
                    self.fixture.write_reports("release")
                    document = self.fixture.load_report(kind)
                    document["schema_version"] = invalid
                    self.fixture.save_report(kind, document)
                    self.assertEvidenceError(self.fixture.args())

    def test_stale_future_and_inter_report_skew_are_invalid(self) -> None:
        document = self.fixture.load_report("nftables_kernel")
        document["generated_at"] = (self.fixture.now - timedelta(hours=2)).isoformat()
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("nftables_kernel")
        document["generated_at"] = (self.fixture.now + timedelta(minutes=3)).isoformat()
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("nftables_kernel")
        document["generated_at"] = (self.fixture.now - timedelta(minutes=10)).isoformat()
        self.fixture.save_report("nftables_kernel", document)
        args = self.fixture.args()
        args.max_age_seconds = 3600
        args.max_report_skew_seconds = 300
        self.assertEvidenceError(args)

    def test_git_sha_tree_source_version_and_report_binding_mismatches_are_invalid(self) -> None:
        args = self.fixture.args()
        args.expected_sha = "0" * 40
        self.assertEvidenceError(args)

        document = self.fixture.load_report("nftables_kernel")
        document["bindings"]["tree_sha"] = "0" * 40
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("nftables_kernel")
        document["bindings"]["version"] = "v4.02.9"
        self.fixture.save_report("nftables_kernel", document)
        self.assertEvidenceError(self.fixture.args())

    def test_manifest_and_artifact_checksum_tampering_is_invalid(self) -> None:
        name = gate.package_names(self.fixture.version)[0]
        (self.fixture.packages / name).write_bytes(b"tampered\n")
        self.assertEvidenceError(self.fixture.args())

    def test_package_inventory_and_raw_report_identity_are_exact(self) -> None:
        (self.fixture.packages / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        self.assertEvidenceError(self.fixture.args())
        (self.fixture.packages / "unexpected.txt").unlink()

        nft = self.fixture.load_report("nftables_kernel")
        package = self.fixture.load_report("linux_package_lifecycle")
        package["raw_report_sha256"] = nft["raw_report_sha256"]
        self.fixture.save_report("linux_package_lifecycle", package)
        self.assertEvidenceError(self.fixture.args())

    def test_missing_report_age_bound_and_non_utc_timestamp_are_invalid(self) -> None:
        args = self.fixture.args()
        args.nft_report = self.fixture.evidence / "missing.json"
        self.assertEvidenceError(args)

        args = self.fixture.args()
        args.max_age_seconds = 59
        self.assertEvidenceError(args)

        nft = self.fixture.load_report("nftables_kernel")
        nft["generated_at"] = "2026-08-14T14:00:00+02:00"
        self.fixture.save_report("nftables_kernel", nft)
        self.assertEvidenceError(self.fixture.args())

    def test_committed_source_version_mismatch_is_invalid(self) -> None:
        target = self.fixture.repo / gate.SOURCE_TARGETS[0][0]
        target.write_text("// v4.02.9\n", encoding="utf-8")
        self.fixture._git("add", gate.SOURCE_TARGETS[0][0])
        self.fixture._git("commit", "-qm", "mismatched source version")
        args = self.fixture.args()
        args.expected_sha = self.fixture._git("rev-parse", "HEAD")
        self.assertEvidenceError(args)

    def test_incomplete_harness_platform_architecture_vm_and_unknown_blocker_block(self) -> None:
        document = self.fixture.load_report("nftables_kernel")
        document["harness_complete"] = False
        self.fixture.save_report("nftables_kernel", document)
        code, aggregate = gate.run_gate(self.fixture.args(), now=self.fixture.now)
        self.assertEqual(code, 1)
        self.assertEqual(aggregate["verdict"], "blocked")

        self.fixture.write_reports("release")
        document = self.fixture.load_report("linux_package_lifecycle")
        document["coverage"]["coordinates"].pop()
        self.fixture.save_report("linux_package_lifecycle", document)
        code, _ = gate.run_gate(self.fixture.args(), now=self.fixture.now)
        self.assertEqual(code, 1)

        self.fixture.write_reports("characterization")
        document = self.fixture.load_report("nftables_kernel")
        document["blocker_ids"] = ["SW-FW-HONEYPORT-001"]
        self.fixture.save_report("nftables_kernel", document)
        code, aggregate = gate.run_gate(
            self.fixture.args("characterization"), now=self.fixture.now
        )
        self.assertEqual(code, 1)
        self.assertIn("unregistered", " ".join(aggregate["reasons"]))

    def test_release_profile_rejects_allowlisted_blockers(self) -> None:
        self.fixture.write_reports("characterization")
        code, aggregate = gate.run_gate(self.fixture.args("release"), now=self.fixture.now)
        self.assertEqual(code, 1)
        self.assertFalse(aggregate["release_ready"])

    def test_equal_or_non_ordered_versions_are_invalid(self) -> None:
        document = self.fixture.load_report("linux_package_lifecycle")
        document["lifecycle"]["previous_version"] = self.fixture.version
        self.fixture.save_report("linux_package_lifecycle", document)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        document = self.fixture.load_report("linux_package_lifecycle")
        document["lifecycle"]["previous_version"] = "v5.00.0"
        self.fixture.save_report("linux_package_lifecycle", document)
        self.assertEvidenceError(self.fixture.args())

    def test_active_runtime_mode_and_every_derived_claim_are_mandatory(self) -> None:
        package = self.fixture.load_report("linux_package_lifecycle")
        package["lifecycle"]["runtime_mode"] = "offline"
        self.fixture.save_report("linux_package_lifecycle", package)
        self.assertEvidenceError(self.fixture.args())

        boolean_claims = gate.LIFECYCLE_KEYS - {
            "previous_version",
            "candidate_version",
            "runtime_mode",
            "previous_package_checksums",
        }
        for claim in sorted(boolean_claims):
            with self.subTest(claim=claim):
                self.fixture.write_reports("release")
                package = self.fixture.load_report("linux_package_lifecycle")
                package["lifecycle"][claim] = False
                self.fixture.save_report("linux_package_lifecycle", package)
                code, aggregate = gate.run_gate(
                    self.fixture.args(), now=self.fixture.now
                )
                self.assertEqual(code, 1)
                self.assertIn(
                    "lifecycle is incomplete", " ".join(aggregate["reasons"])
                )

    def test_lifecycle_schema_rejects_legacy_or_unknown_claims(self) -> None:
        package = self.fixture.load_report("linux_package_lifecycle")
        package["lifecycle"]["purge_semantics"] = package["lifecycle"].pop(
            "purge"
        )
        self.fixture.save_report("linux_package_lifecycle", package)
        self.assertEvidenceError(self.fixture.args())

        self.fixture.write_reports("release")
        package = self.fixture.load_report("linux_package_lifecycle")
        package["lifecycle"]["offline_service_manager"] = True
        self.fixture.save_report("linux_package_lifecycle", package)
        self.assertEvidenceError(self.fixture.args())

    def test_output_symlink_and_output_inside_repo_are_rejected(self) -> None:
        target = self.fixture.evidence / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        symlink = self.fixture.evidence / "output-link.json"
        symlink.symlink_to(target)
        self.assertEvidenceError(self.fixture.args(output=symlink))
        self.assertEvidenceError(self.fixture.args(output=self.fixture.repo / "aggregate.json"))

    def test_parent_traversal_is_rejected_for_all_generation_paths(self) -> None:
        safe_inside = self.fixture.repo / "inside.json"
        safe_inside.write_bytes(self.fixture.reports["nftables_kernel"].read_bytes())
        traversed_inside = self.fixture.evidence / ".." / "repo" / safe_inside.name
        with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
            gate._absolute_without_symlinks(traversed_inside, "adversarial evidence")
        with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
            gate._inside(traversed_inside.absolute(), self.fixture.repo.absolute())

        generation_paths = {
            "candidate_packages_dir": self.fixture.packages,
            "nft_report": self.fixture.reports["nftables_kernel"],
            "package_report": self.fixture.reports["linux_package_lifecycle"],
        }
        for attribute, target in generation_paths.items():
            with self.subTest(path=attribute):
                args = self.fixture.args()
                setattr(args, attribute, self.traversal_path(target))
                with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
                    gate.run_gate(args, now=self.fixture.now)

        output = self.fixture.evidence / "traversed-aggregate.json"
        with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
            gate.run_gate(
                self.fixture.args(output=self.traversal_path(output)),
                now=self.fixture.now,
            )
        self.assertFalse(output.exists())

    def test_parent_traversal_is_rejected_for_aggregate_and_verify_reports(self) -> None:
        generation_args = self.fixture.args()
        code, _ = gate.run_gate(generation_args, now=self.fixture.now)
        self.assertEqual(code, 0)

        def verify_args() -> argparse.Namespace:
            args = self.fixture.args()
            args.command = "verify"
            args.aggregate = generation_args.output
            args.require_tag = False
            del args.output
            return args

        args = verify_args()
        args.aggregate = self.traversal_path(generation_args.output)
        with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
            gate.verify_aggregate(args, now=self.fixture.now)

        report_paths = {
            "nft_report": self.fixture.reports["nftables_kernel"],
            "package_report": self.fixture.reports["linux_package_lifecycle"],
        }
        for attribute, target in report_paths.items():
            with self.subTest(path=attribute):
                args = verify_args()
                setattr(args, attribute, self.traversal_path(target))
                with self.assertRaisesRegex(gate.EvidenceError, "parent traversal"):
                    gate.verify_aggregate(args, now=self.fixture.now)

    def test_aggregate_schema_version_requires_an_exact_integer(self) -> None:
        generation_args = self.fixture.args()
        code, _ = gate.run_gate(generation_args, now=self.fixture.now)
        self.assertEqual(code, 0)
        original = generation_args.output.read_bytes()

        verify_args = self.fixture.args()
        verify_args.command = "verify"
        verify_args.aggregate = generation_args.output
        verify_args.require_tag = False
        del verify_args.output
        for invalid in (True, float(gate.SCHEMA_VERSION)):
            with self.subTest(schema_version=repr(invalid)):
                document = json.loads(original)
                document["schema_version"] = invalid
                generation_args.output.write_text(
                    json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
                )
                with self.assertRaises(gate.EvidenceError):
                    gate.verify_aggregate(verify_args, now=self.fixture.now)

    def test_toctou_revalidation_detects_change(self) -> None:
        path = self.fixture.reports["nftables_kernel"]
        snapshot = gate.read_snapshot(path, "nft report")
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(gate.EvidenceError):
            gate.revalidate(snapshot, "nft report")

    def test_verify_recomputes_release_aggregate_without_rewriting(self) -> None:
        args = self.fixture.args()
        code, _ = gate.run_gate(args, now=self.fixture.now)
        self.assertEqual(code, 0)
        before = hashlib.sha256(args.output.read_bytes()).hexdigest()
        verify_args = self.fixture.args()
        verify_args.command = "verify"
        verify_args.aggregate = args.output
        del verify_args.output
        relocated = self.fixture.evidence / "relocated-reports"
        relocated.mkdir()
        for kind, source in self.fixture.reports.items():
            destination = relocated / source.name
            destination.write_bytes(source.read_bytes())
            if kind == "nftables_kernel":
                verify_args.nft_report = destination
            elif kind == "linux_package_lifecycle":
                verify_args.package_report = destination
        aggregate = gate.verify_aggregate(verify_args, now=self.fixture.now)
        self.assertTrue(aggregate["release_ready"])
        self.assertEqual(before, hashlib.sha256(args.output.read_bytes()).hexdigest())

        document = json.loads(args.output.read_text(encoding="utf-8"))
        document["bindings"]["tree_sha"] = "0" * 40
        args.output.write_text(json.dumps(document) + "\n", encoding="utf-8")
        with self.assertRaises(gate.EvidenceError):
            gate.verify_aggregate(verify_args, now=self.fixture.now)

    def test_release_generation_is_pre_tag_but_publication_verify_can_require_tag(self) -> None:
        self.fixture._git("tag", "-d", self.fixture.version)
        args = self.fixture.args()
        code, _ = gate.run_gate(args, now=self.fixture.now)
        self.assertEqual(code, 0)

        verify_args = self.fixture.args()
        verify_args.command = "verify"
        verify_args.aggregate = args.output
        verify_args.require_tag = False
        del verify_args.output
        gate.verify_aggregate(verify_args, now=self.fixture.now)
        verify_args.require_tag = True
        with self.assertRaises(gate.EvidenceError):
            gate.verify_aggregate(verify_args, now=self.fixture.now)

    def test_previous_checksums_are_kind_specific_and_distinct(self) -> None:
        nft = self.fixture.load_report("nftables_kernel")
        self.assertNotIn("lifecycle", nft)
        linux = self.fixture.load_report("linux_package_lifecycle")
        self.assertEqual(len(linux["lifecycle"]["previous_package_checksums"]), 6)

        previous_name = next(iter(linux["lifecycle"]["previous_package_checksums"]))
        index = gate.package_names(self.fixture.previous_version).index(previous_name)
        candidate_name = gate.package_names(self.fixture.version)[index]
        linux["lifecycle"]["previous_package_checksums"][previous_name] = (
            self.fixture.checksums[candidate_name]
        )
        self.fixture.save_report("linux_package_lifecycle", linux)
        self.assertEvidenceError(self.fixture.args())


if __name__ == "__main__":
    unittest.main()
