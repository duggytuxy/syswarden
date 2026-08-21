#!/usr/bin/env python3
"""Adversarial tests for raw-to-bound release qualification adaptation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_lifecycle_lab
import release_qualification_adapter as adapter
import release_qualification_gate as gate
from package_lifecycle_lab_test import FakePodmanRunner


ACT_IMAGE = (
    "docker.io/catthehacker/ubuntu:act-24.04@sha256:"
    "b839c14c4410998529ec18f951262bdf87a2b23bc1467304d07b491b9455e074"
)


class AdapterFixture:
    version = "v4.02.8"
    previous_version = "v4.02.7"
    repository = "duggytuxy/syswarden"
    workflow_run_id = 1001
    workflow_run_attempt = 1
    candidate_run_id = 900
    candidate_artifact_id = 901
    candidate_artifact_name = "syswarden-packages-4.02.8"
    previous_release_id = 800

    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "repo"
        self.evidence = root / "evidence"
        self.candidate = self.evidence / "packages" / "candidate"
        self.previous = self.evidence / "packages" / "previous"
        self.raw = self.evidence / "raw"
        self.bound = self.evidence / "bound"
        for directory in (
            self.repo,
            self.candidate,
            self.previous,
            self.raw,
            self.bound,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.emulator = self.root / "qemu-aarch64-static"
        self.emulator.write_bytes(b"synthetic executable aarch64 emulator\n")
        self.emulator.chmod(0o700)
        self.binfmt = self.root / "qemu-aarch64-binfmt"
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
        self.now = datetime.now(UTC).replace(microsecond=0)
        self._make_repository()
        self.commit = self._git("rev-parse", "HEAD")
        self._make_package_set(self.candidate, "4.02.8", b"candidate")
        self._make_package_set(self.previous, "4.02.7", b"previous")
        self._make_raw_reports()

    def _run(self, *arguments: str, cwd: Path | None = None) -> str:
        process = subprocess.run(
            arguments,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        if process.returncode != 0:
            raise AssertionError(process.stderr or process.stdout)
        return process.stdout.strip()

    def _git(self, *arguments: str) -> str:
        return self._run(
            "git", "-c", "core.fsmonitor=false", *arguments, cwd=self.repo
        )

    def _make_repository(self) -> None:
        self._run("git", "init", "-q", cwd=self.repo)
        self._git("config", "user.email", "adapter-tests@example.invalid")
        self._git("config", "user.name", "Adapter Tests")
        for relative, count in gate.SOURCE_TARGETS:
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "\n".join([f"// {self.version}"] * count) + "\n",
                encoding="utf-8",
            )
        (self.repo / "README.md").write_text(
            f"Current source version: **{self.version}**.\n", encoding="utf-8"
        )
        (self.repo / "changelog.md").write_text(
            f"# Release {self.version}\n\n### TEST\n- adapter\n\n---\n",
            encoding="utf-8",
        )
        (self.repo / ".actrc").write_text(
            f"-P ubuntu-24.04={ACT_IMAGE}\n", encoding="utf-8"
        )
        golden = self.repo / "testdata/firewall/nftables-v4.02.8.nft"
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(
            "tcp dport { 236379 }\ntcp dport { 236379 }\n", encoding="utf-8"
        )
        loader = self.repo / "src/core/syswarden-cli/config/config_loader.go"
        loader.parent.mkdir(parents=True, exist_ok=True)
        loader.write_text(
            'strings.Join(m.Security.Honeyports, " ")\n', encoding="utf-8"
        )
        linux = self.repo / "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
        linux.parent.mkdir(parents=True, exist_ok=True)
        linux.write_text(
            "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)\n",
            encoding="utf-8",
        )
        (linux.parent / "honeyports.go").write_text(
            'strings.Join(canonical, ", ")\n', encoding="utf-8"
        )
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")

    @staticmethod
    def _make_package_set(
        directory: Path, version: str, prefix: bytes
    ) -> None:
        records: list[str] = []
        for name in gate.package_names("v" + version):
            payload = prefix + b":" + name.encode("ascii") + b"\n"
            (directory / name).write_bytes(payload)
            records.append(f"{hashlib.sha256(payload).hexdigest()}  {name}")
        (directory / "SHA256SUMS.txt").write_text(
            "\n".join(sorted(records)) + "\n", encoding="utf-8"
        )

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _make_raw_reports(self) -> None:
        common_package_args = {
            "packages_dir": self.candidate,
            "previous_packages_dir": self.previous,
            "podman": "podman",
            "pull_policy": "never",
            "scenario_timeout": 60,
            "arm64_emulator": None,
            "qualification_repository": self.repository,
            "qualification_release_sha": self.commit,
            "qualification_release_tag": self.version,
            "qualification_previous_tag": self.previous_version,
            "qualification_workflow_run_id": str(self.workflow_run_id),
            "qualification_workflow_run_attempt": str(self.workflow_run_attempt),
            "qualification_candidate_run_id": str(self.candidate_run_id),
            "qualification_candidate_artifact_id": str(self.candidate_artifact_id),
            "qualification_candidate_artifact_name": self.candidate_artifact_name,
            "qualification_previous_release_id": str(self.previous_release_id),
            "aggregate_amd64_report": None,
            "aggregate_arm64_report": None,
        }
        shard_paths: dict[str, Path] = {}
        for offset, (architecture, host) in enumerate(
            (("amd64", "x86_64"), ("arm64", "aarch64")),
            1,
        ):
            package_args = argparse.Namespace(
                **common_package_args,
                architecture_shard=architecture,
            )
            platforms = tuple(
                spec
                for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
                if spec.architecture == architecture
            )
            shard = package_lifecycle_lab.run_lab(
                package_args,
                runner=FakePodmanRunner(),
                platforms=platforms,
                host_architecture=host,
            )
            shard["generated_at"] = (
                self.now + timedelta(seconds=offset)
            ).isoformat()
            shard_path = self.raw / f"package-lifecycle-{architecture}.json"
            shard_path.write_text(
                json.dumps(shard, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            shard_paths[architecture] = shard_path
        aggregate_args = argparse.Namespace(
            **{
                **common_package_args,
                "architecture_shard": None,
                "aggregate_amd64_report": shard_paths["amd64"],
                "aggregate_arm64_report": shard_paths["arm64"],
            }
        )
        package_report = package_lifecycle_lab.aggregate_native_shard_reports(
            aggregate_args
        )
        package_report["generated_at"] = (self.now + timedelta(seconds=11)).isoformat()

        nft_report = {
            "schema_version": 1,
            "generated_at": self.now.isoformat(),
            "harness_status": "pass",
            "product_status": "pass",
            "release_ready": True,
            "finding_id": "SW-FW-004",
            "summary": "The corrected honeyport serialization is accepted by the kernel.",
            "engine": {
                "name": "podman",
                "version": "5.6.0",
                "rootless": True,
                "image": ACT_IMAGE,
                "network": "none",
                "nftables": "nftables v1.1.6",
            },
            "network_namespaces": {
                "host": "net:[100]",
                "container": "net:[200]",
            },
            "conditions": {
                "separate_network_namespace": True,
                "historical_concatenation_rejected_before_mutation": True,
                "kernel_reported_invalid_port": True,
                "corrected_ruleset_applied": True,
                "current_generator_contract_passed": True,
                "dynamic_timeout_replication_applied": True,
                "isolated_ruleset_cleanup_succeeded": True,
            },
            "kernel_error": "Service out of range",
        }
        for name, report in (
            ("nftables-raw.json", nft_report),
            ("package-lifecycle-raw.json", package_report),
        ):
            (self.raw / name).write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def args(self, command: str = "build", **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "command": command,
            "repo_root": self.repo,
            "expected_sha": self.commit,
            "expected_version": self.version,
            "candidate_packages_dir": self.candidate,
            "previous_packages_dir": self.previous,
            "nft_raw": self.raw / "nftables-raw.json",
            "package_raw": self.raw / "package-lifecycle-raw.json",
            "package_amd64_shard": self.raw / "package-lifecycle-amd64.json",
            "package_arm64_shard": self.raw / "package-lifecycle-arm64.json",
            "expected_repository": self.repository,
            "expected_workflow_run_id": self.workflow_run_id,
            "expected_workflow_run_attempt": self.workflow_run_attempt,
            "expected_candidate_run_id": self.candidate_run_id,
            "expected_candidate_artifact_id": self.candidate_artifact_id,
            "expected_candidate_artifact_name": self.candidate_artifact_name,
            "expected_previous_release_id": self.previous_release_id,
            "max_age_seconds": 172800,
            "max_report_skew_seconds": 0,
            "nft_output": self.bound / "nftables-bound.json",
            "package_output": self.bound / "package-lifecycle-bound.json",
            "nft_envelope": self.bound / "nftables-bound.json",
            "package_envelope": self.bound / "package-lifecycle-bound.json",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def load_raw(self, name: str) -> dict[str, object]:
        return json.loads((self.raw / name).read_text(encoding="utf-8"))

    def save_raw(self, name: str, value: dict[str, object]) -> None:
        (self.raw / name).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


class ReleaseQualificationAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = AdapterFixture(Path(self.temporary.name))

    def assertAdapterError(self, args: argparse.Namespace) -> None:
        with self.assertRaises(gate.EvidenceError):
            if args.command == "build":
                adapter.run_build(args)
            else:
                adapter.run_verify(args)

    def test_build_and_verify_are_canonical_and_use_earliest_raw_timestamp(self) -> None:
        envelopes = adapter.run_build(self.fixture.args())
        expected_time = self.fixture.now.isoformat()
        self.assertEqual({item["generated_at"] for item in envelopes.values()}, {expected_time})
        verified = adapter.run_verify(self.fixture.args("verify"))
        self.assertEqual(verified, envelopes)
        for key, name in adapter.OUTPUT_NAMES.items():
            payload = (self.fixture.bound / name).read_bytes()
            self.assertEqual(payload, adapter._canonical(envelopes[key]))

    def test_evidence_bundle_can_be_relocated_before_verify(self) -> None:
        adapter.run_build(self.fixture.args())
        relocated = self.fixture.root / "downloaded"
        shutil.copytree(self.fixture.evidence, relocated)
        shutil.rmtree(self.fixture.evidence)
        args = self.fixture.args(
            "verify",
            candidate_packages_dir=relocated / "packages/candidate",
            previous_packages_dir=relocated / "packages/previous",
            nft_raw=relocated / "raw/nftables-raw.json",
            package_raw=relocated / "raw/package-lifecycle-raw.json",
            package_amd64_shard=relocated / "raw/package-lifecycle-amd64.json",
            package_arm64_shard=relocated / "raw/package-lifecycle-arm64.json",
            nft_envelope=relocated / "bound/nftables-bound.json",
            package_envelope=relocated / "bound/package-lifecycle-bound.json",
        )
        adapter.run_verify(args)

    def test_package_runtime_failures_are_never_waived(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        for platform in report["platforms"]:
            if platform["distribution"] != "alpine":
                continue
            platform["status"] = "fail"
            for scenario in platform["scenarios"]:
                scenario["status"] = "fail"
                scenario["container_exit_code"] = 1
                scenario["container_start_exit_codes"] = [
                    1 for _ in scenario["container_start_exit_codes"]
                ]
                for event in scenario["events"]:
                    if event["check"].endswith(".executable"):
                        event["status"] = "fail"
                        event["detail"] = "CLI execution failed with exit code 127"
        classification = package_lifecycle_lab.classify_lifecycle_evidence(
            report["platforms"]
        )
        report.update(
            status="fail",
            harness_complete=classification["harness_complete"],
            release_ready=classification["release_ready"],
            blocker_ids=classification["blocker_ids"],
            unexpected_failed_checks=classification["unexpected_failed_checks"],
        )
        report["scope"]["container_lab_complete"] = False
        report["scope"]["coordinate_classification"] = classification[
            "coordinate_classification"
        ]
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        event = report["platforms"][0]["scenarios"][0]["events"][0]
        event["status"] = "fail"
        event["detail"] = "synthetic failure"
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_maintainer_script_failures_are_rejected_alone_and_with_alpine_blocker(self) -> None:
        def classify(*, include_alpine: bool) -> dict[str, object]:
            report = self.fixture.load_raw("package-lifecycle-raw.json")
            for platform in report["platforms"]:
                config_coordinate = platform["distribution"] != "alpine"
                alpine_coordinate = include_alpine and not config_coordinate
                if not config_coordinate and not alpine_coordinate:
                    continue
                platform["status"] = "fail"
                for scenario in platform["scenarios"]:
                    scenario["status"] = "fail"
                    scenario["container_exit_code"] = 1
                    scenario["container_start_exit_codes"] = [
                        1 for _ in scenario["container_start_exit_codes"]
                    ]
                    for event in scenario["events"]:
                        if config_coordinate and event["check"].endswith(
                            ".maintainer_script"
                        ):
                            event["status"] = "fail"
                            event["detail"] = (
                                "package manager returned success after maintainer "
                                "script emitted a Go panic"
                            )
                        if alpine_coordinate and event["check"].endswith(
                            ".executable"
                        ):
                            event["status"] = "fail"
                            event["detail"] = (
                                "CLI execution failed with exit code 127"
                            )
            result = package_lifecycle_lab.classify_lifecycle_evidence(
                report["platforms"]
            )
            report.update(
                status="fail",
                harness_complete=result["harness_complete"],
                release_ready=result["release_ready"],
                blocker_ids=result["blocker_ids"],
                unexpected_failed_checks=result["unexpected_failed_checks"],
            )
            report["scope"]["container_lab_complete"] = False
            report["scope"]["coordinate_classification"] = result[
                "coordinate_classification"
            ]
            return report

        config_only = classify(include_alpine=False)
        self.assertEqual(config_only["blocker_ids"], [])
        self.assertTrue(config_only["unexpected_failed_checks"])
        self.fixture.save_raw("package-lifecycle-raw.json", config_only)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        combined = classify(include_alpine=True)
        self.assertEqual(combined["blocker_ids"], [])
        self.assertTrue(combined["unexpected_failed_checks"])
        self.fixture.save_raw("package-lifecycle-raw.json", combined)
        self.assertAdapterError(self.fixture.args())

    def test_duplicate_json_key_and_unknown_schema_key_are_rejected(self) -> None:
        path = self.fixture.raw / "nftables-raw.json"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "{", '{"schema_version": 1,', 1
            ),
            encoding="utf-8",
        )
        self.assertAdapterError(self.fixture.args())
        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("nftables-raw.json")
        report["unreviewed"] = True
        self.fixture.save_raw("nftables-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_package_top_level_claim_and_nested_event_tampering_are_rejected(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["release_ready"] = False
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_arm64_probe_must_be_native_and_report_the_native_uname(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        arm64 = next(
            item
            for item in report["platforms"]
            if item["architecture_id"] == "arm64"
        )
        arm64["architecture_probe"]["actual_uname"] = "x86_64"
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_native_shard_files_and_workflow_binding_are_independently_revalidated(self) -> None:
        arm_path = self.fixture.raw / "package-lifecycle-arm64.json"
        arm = self.fixture.load_raw("package-lifecycle-arm64.json")
        arm["qualification_binding"]["workflow_run_id"] += 1
        self.fixture.save_raw("package-lifecycle-arm64.json", arm)
        aggregate = self.fixture.load_raw("package-lifecycle-raw.json")
        record = next(
            item
            for item in aggregate["native_shards"]["reports"]
            if item["architecture"] == "arm64"
        )
        record["report_sha256"] = hashlib.sha256(arm_path.read_bytes()).hexdigest()
        self.fixture.save_raw("package-lifecycle-raw.json", aggregate)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        self.assertAdapterError(
            self.fixture.args(expected_workflow_run_id=self.fixture.workflow_run_id + 1)
        )

        self.fixture._make_raw_reports()
        self.assertAdapterError(
            self.fixture.args(
                package_arm64_shard=self.fixture.raw / "package-lifecycle-amd64.json"
            )
        )

        self.fixture._make_raw_reports()
        aggregate = self.fixture.load_raw("package-lifecycle-raw.json")
        aggregate["native_shards"]["reports"].reverse()
        self.fixture.save_raw("package-lifecycle-raw.json", aggregate)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        arm64 = next(
            item
            for item in report["platforms"]
            if item["architecture_id"] == "arm64"
        )
        arm64["architecture_probe"].update(
            execution_mode="host_binfmt_qemu_aarch64",
        )
        arm64["bootstrap_execution"] = "podman_platform_with_validated_host_binfmt"
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())
        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["platforms"][0]["scenarios"][0]["events"][0]["status"] = "fail"
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["platforms"][0]["scenarios"][0]["events"][0]["detail"] = (
            "aggregate-only forged detail"
        )
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["scope"]["architecture_coverage"][0][
            "completed_distributions"
        ].reverse()
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_package_digest_and_previous_version_binding_are_rejected(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["platforms"][0]["candidate"]["sha256"] = "0" * 64
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_raw_symlink_hardlink_alias_and_in_repo_output_are_rejected(self) -> None:
        original = self.fixture.raw / "nftables-raw.json"
        target = self.fixture.root / "nft-target.json"
        original.replace(target)
        original.symlink_to(target)
        self.assertAdapterError(self.fixture.args())
        original.unlink()
        target.replace(original)
        alias = self.fixture.bound / "nftables-bound.json"
        os.link(original, alias)
        self.assertAdapterError(self.fixture.args())
        alias.unlink()
        self.assertAdapterError(
            self.fixture.args(nft_output=self.fixture.repo / "nftables-bound.json")
        )

    def test_verify_requires_byte_exact_envelopes_and_stable_basenames(self) -> None:
        adapter.run_build(self.fixture.args())
        path = self.fixture.bound / "nftables-bound.json"
        path.write_bytes(path.read_bytes() + b" \n")
        self.assertAdapterError(self.fixture.args("verify"))
        wrong = self.fixture.bound / "nft.json"
        self.assertAdapterError(self.fixture.args(nft_output=wrong))

    def test_stale_future_wrong_type_and_nested_unknown_key_are_rejected(self) -> None:
        report = self.fixture.load_raw("nftables-raw.json")
        report["generated_at"] = (self.fixture.now - timedelta(days=3)).isoformat()
        self.fixture.save_raw("nftables-raw.json", report)
        self.assertAdapterError(self.fixture.args())
        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("nftables-raw.json")
        report["release_ready"] = 0
        self.fixture.save_raw("nftables-raw.json", report)
        self.assertAdapterError(self.fixture.args())
        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("nftables-raw.json")
        report["engine"]["unknown"] = "value"
        self.fixture.save_raw("nftables-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_toctou_raw_change_is_detected_before_output(self) -> None:
        original = gate.revalidate
        changed = False

        def mutate(snapshot: gate.FileSnapshot, label: str) -> None:
            nonlocal changed
            if not changed and label == "nft raw report":
                changed = True
                snapshot.path.write_bytes(snapshot.payload + b" ")
            original(snapshot, label)

        with mock.patch.object(adapter.gate, "revalidate", side_effect=mutate):
            self.assertAdapterError(self.fixture.args())

    def test_toctou_package_inventory_growth_is_detected(self) -> None:
        original = gate.revalidate
        changed = False

        def mutate(snapshot: gate.FileSnapshot, label: str) -> None:
            nonlocal changed
            if not changed and label == "candidate package evidence":
                changed = True
                (self.fixture.candidate / "late-extra-file").write_text(
                    "late mutation\n", encoding="utf-8"
                )
            original(snapshot, label)

        with mock.patch.object(adapter.gate, "revalidate", side_effect=mutate):
            self.assertAdapterError(self.fixture.args())

    def test_raw_collection_window_is_bounded_but_zero_normalized_skew_is_valid(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["generated_at"] = (
            self.fixture.now + timedelta(seconds=adapter.RAW_REPORT_MAX_SKEW_SECONDS + 1)
        ).isoformat()
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())


if __name__ == "__main__":
    unittest.main()
