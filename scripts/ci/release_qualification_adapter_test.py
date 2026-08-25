#!/usr/bin/env python3
"""Adversarial tests for raw-to-bound release qualification adaptation."""

from __future__ import annotations

import argparse
import copy
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
from typing import Any
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


def set_sys_admin(mask: str, *, present: bool) -> str:
    value = int(mask, 16)
    bit = 1 << adapter.SYS_ADMIN_CAPABILITY_BIT
    value = value | bit if present else value & ~bit
    return f"{value:016x}"


def set_sys_ptrace(mask: str, *, present: bool) -> str:
    value = int(mask, 16)
    bit = 1 << adapter.SYS_PTRACE_CAPABILITY_BIT
    value = value | bit if present else value & ~bit
    return f"{value:016x}"


def replace_snapshot_identity_maps(
    platform: dict[str, Any],
    uid_map: list[dict[str, int]],
    gid_map: list[dict[str, int]],
) -> None:
    for scenario in platform["scenarios"]:
        for boot in scenario["boots"]:
            for phase in ("pre_exec", "post_exec"):
                boot[phase]["pid1_uid_map"] = copy.deepcopy(uid_map)
                boot[phase]["pid1_gid_map"] = copy.deepcopy(gid_map)


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
        }
        shard_paths: dict[str, Path] = {}
        for offset, (architecture, host) in enumerate((("amd64", "x86_64"),), 1):
            package_args = argparse.Namespace(
                **common_package_args,
                architecture_shard=architecture,
            )
            platforms = tuple(
                spec
                for spec in package_lifecycle_lab.DEFAULT_PLATFORMS
                if spec.architecture == architecture
            )
            subordinate_uid = 524_288
            subordinate_gid = 524_288
            shard = package_lifecycle_lab.run_lab(
                package_args,
                runner=FakePodmanRunner(
                    host_architecture=architecture,
                    uid_map=[
                        {"container_id": 0, "host_id": os.geteuid(), "size": 1},
                        {
                            "container_id": 1,
                            "host_id": subordinate_uid,
                            "size": 65_536,
                        },
                    ],
                    gid_map=[
                        {"container_id": 0, "host_id": os.getegid(), "size": 1},
                        {
                            "container_id": 1,
                            "host_id": subordinate_gid,
                            "size": 65_536,
                        },
                    ],
                ),
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
                scenario["lifecycle_exec_exit_codes"] = [
                    1 for _ in scenario["lifecycle_exec_exit_codes"]
                ]
                for boot in scenario["boots"]:
                    boot["script_exec_exit_code"] = 1
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
                    scenario["lifecycle_exec_exit_codes"] = [
                        1 for _ in scenario["lifecycle_exec_exit_codes"]
                    ]
                    for boot in scenario["boots"]:
                        boot["script_exec_exit_code"] = 1
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

    def test_active_runtime_schema_rejects_offline_restart_and_isolation_mutations(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        platform = report["platforms"][0]
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == platform["distribution"]
            and item.architecture == platform["architecture_id"]
        )
        original = platform["scenarios"][0]
        adapter._validate_runtime_scenario(
            original, spec, original["name"], "fixture.scenario"
        )
        restarted_rsyslog = copy.deepcopy(original)
        restarted_rsyslog["boots"][0]["post_exec"]["rsyslog_main_pid"] += 1
        adapter._validate_runtime_scenario(
            restarted_rsyslog,
            spec,
            restarted_rsyslog["name"],
            "fixture.rsyslog-restart",
        )
        debian_lib_fragment = copy.deepcopy(original)
        for boot in debian_lib_fragment["boots"]:
            for phase in ("pre_exec", "post_exec"):
                boot[phase]["cron_fragment_path"] = (
                    "/lib/systemd/system/cron.service"
                )
        adapter._validate_runtime_scenario(
            debian_lib_fragment,
            spec,
            debian_lib_fragment["name"],
            "fixture.debian-lib-fragment",
        )

        def change_identity_mode(
            snapshot: dict[str, Any], key: str, mode: str
        ) -> None:
            stat_fields, digest = snapshot[key].split("|", 1)
            fields = stat_fields.split(":")
            fields[2] = mode
            snapshot[key] = ":".join(fields) + "|" + digest

        def assert_rejected(mutator: Any) -> None:
            scenario = copy.deepcopy(original)
            mutator(scenario)
            with self.assertRaises(adapter.AdapterError):
                adapter._validate_runtime_scenario(
                    scenario, spec, original["name"], "fixture.scenario"
                )

        mutations = {
            "offline": lambda item: item.__setitem__("runtime_mode", "offline"),
            "privileged": lambda item: item["isolation"].__setitem__(
                "privileged", True
            ),
            "privileged-integer": lambda item: item["isolation"].__setitem__(
                "privileged", 0
            ),
            "sys-admin-duplicate": lambda item: item["isolation"]["cap_add"].append(
                "CAP_SYS_ADMIN"
            ),
            "sys-admin-missing": lambda item: item["isolation"]["cap_add"].remove(
                "CAP_SYS_ADMIN"
            ),
            "sys-ptrace-duplicate": lambda item: item["isolation"]["cap_add"].append(
                "CAP_SYS_PTRACE"
            ),
            "sys-ptrace-missing": lambda item: item["isolation"]["cap_add"].remove(
                "CAP_SYS_PTRACE"
            ),
            "cap-drop": lambda item: item["isolation"]["cap_drop"].append(
                "CAP_NET_RAW"
            ),
            "launcher-path": lambda item: item["isolation"][
                "lifecycle_exec_launcher"
            ].__setitem__(0, "/bin/sh"),
            "launcher-option": lambda item: item["isolation"][
                "lifecycle_exec_launcher"
            ].__setitem__(1, "--bounding-set=+sys_admin"),
            "launcher-extra": lambda item: item["isolation"][
                "lifecycle_exec_launcher"
            ].append("unexpected"),
            "host-network": lambda item: item["isolation"].__setitem__(
                "network_mode", "host"
            ),
            "device": lambda item: item["isolation"]["devices"].append(
                "/dev/net/tun"
            ),
            "socket": lambda item: item["isolation"]["mounts"].append(
                {
                    "role": "socket",
                    "destination": "/run/podman/podman.sock",
                    "read_only": False,
                }
            ),
            "mount-boolean-integer": lambda item: item["isolation"]["mounts"][
                0
            ].__setitem__("read_only", 1),
            "manager-offline": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "manager_state", "OFFLINE"
            ),
            "scenario-extra": lambda item: item.__setitem__("unknown", True),
            "scenario-missing": lambda item: item.pop("isolation"),
            "snapshot-extra": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "unknown", True
            ),
            "snapshot-missing": lambda item: item["boots"][0]["pre_exec"].pop(
                "cron_package_name"
            ),
            "single-capture": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "capture_count", 1
            ),
            "pid1-permitted-sys-admin-missing": lambda item: item["boots"][0][
                "pre_exec"
            ]["pid1_process_security"].__setitem__(
                "cap_permitted",
                set_sys_admin(
                    item["boots"][0]["pre_exec"]["pid1_process_security"][
                        "cap_permitted"
                    ],
                    present=False,
                ),
            ),
            "pid1-inheritable-sys-admin-present": lambda item: item["boots"][0][
                "pre_exec"
            ]["pid1_process_security"].__setitem__(
                "cap_inheritable",
                set_sys_admin(
                    item["boots"][0]["pre_exec"]["pid1_process_security"][
                        "cap_inheritable"
                    ],
                    present=True,
                ),
            ),
            "attestation-sys-admin": lambda item: item["boots"][0]["pre_exec"][
                "attestation_process_security"
            ].__setitem__(
                "cap_effective",
                set_sys_admin(
                    item["boots"][0]["pre_exec"][
                        "attestation_process_security"
                    ]["cap_effective"],
                    present=True,
                ),
            ),
            "lifecycle-exec-sys-admin": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__(
                "cap_bounding",
                set_sys_admin(
                    item["boots"][0]["lifecycle_exec_security"][
                        "cap_bounding"
                    ],
                    present=True,
                ),
            ),
            "lifecycle-exec-nnp": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__("no_new_privileges", False),
            "core-sys-admin": lambda item: item["boots"][0]["post_exec"][
                "product_services"
            ]["core_process_security"].__setitem__(
                "cap_ambient",
                set_sys_admin(
                    item["boots"][0]["post_exec"]["product_services"][
                        "core_process_security"
                    ]["cap_ambient"],
                    present=True,
                ),
            ),
            "core-nnp": lambda item: item["boots"][0]["post_exec"][
                "product_services"
            ]["core_process_security"].__setitem__(
                "no_new_privileges", False
            ),
            "cap-mask-width": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__("cap_effective", "0" * 15),
            "nnp-integer": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__("no_new_privileges", 1),
            "uid-map-host-root": lambda item: item["boots"][0]["pre_exec"][
                "pid1_uid_map"
            ][0].__setitem__("outside_id", 0),
            "uid-map-length": lambda item: item["boots"][0]["pre_exec"][
                "pid1_uid_map"
            ][1].__setitem__("length", 65_535),
            "uid-map-overlap": lambda item: item["boots"][0]["pre_exec"][
                "pid1_uid_map"
            ][1].__setitem__(
                "outside_id",
                item["boots"][0]["pre_exec"]["pid1_uid_map"][0][
                    "outside_id"
                ],
            ),
            "uid-map-extra": lambda item: item["boots"][0]["pre_exec"][
                "pid1_uid_map"
            ].append({"inside_id": 65_537, "outside_id": 200_000, "length": 1}),
            "gid-map-inside": lambda item: item["boots"][0]["pre_exec"][
                "pid1_gid_map"
            ][1].__setitem__("inside_id", 2),
            "setpriv-null": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "setpriv", None
            ),
            "setpriv-path": lambda item: item["boots"][0]["pre_exec"][
                "setpriv"
            ].__setitem__("path", "/usr/local/bin/setpriv"),
            "setpriv-identity": lambda item: item["boots"][0]["pre_exec"][
                "setpriv"
            ].__setitem__("file_identity", "1:2:81a4:0:0"),
            "setpriv-digest": lambda item: item["boots"][0]["pre_exec"][
                "setpriv"
            ].__setitem__("sha256", "f" * 63),
            "setpriv-package": lambda item: item["boots"][0]["pre_exec"][
                "setpriv"
            ].__setitem__("package_name", "unbound"),
            "setpriv-architecture": lambda item: item["boots"][0]["pre_exec"][
                "setpriv"
            ].__setitem__("package_architecture", "wrong"),
            "cron-executable-mode": lambda item: change_identity_mode(
                item["boots"][0]["pre_exec"],
                "cron_executable_identity",
                "81a4",
            ),
            "cron-fragment-cross-family-mode": lambda item: change_identity_mode(
                item["boots"][0]["pre_exec"],
                "cron_fragment_identity",
                "81ed",
            ),
            "cron-identity": lambda item: item["boots"][0]["post_exec"].__setitem__(
                "cron_executable_identity",
                "1:2:81ed:0:0|" + "0" * 64,
            ),
            "cron-version": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "cron_package_version", ""
            ),
            "cron-fragment-identity": lambda item: item["boots"][0][
                "pre_exec"
            ].__setitem__("cron_fragment_identity", "forged"),
            "cron-fragment-package": lambda item: item["boots"][0][
                "pre_exec"
            ].__setitem__("cron_fragment_package_name", "unbound"),
            "cron-fragment-version": lambda item: item["boots"][0][
                "pre_exec"
            ].__setitem__("cron_fragment_package_version", "0"),
            "cron-dropin": lambda item: item["boots"][0]["pre_exec"].__setitem__(
                "cron_dropin_paths", ["/etc/systemd/system/cron.service.d/override.conf"]
            ),
            "product-extra": lambda item: item["boots"][1]["pre_exec"][
                "product_services"
            ].__setitem__("unknown", True),
            "product-missing": lambda item: item["boots"][1]["pre_exec"][
                "product_services"
            ].pop("core_executable_path"),
            "core-path": lambda item: item["boots"][1]["pre_exec"][
                "product_services"
            ].__setitem__("core_executable_path", "/usr/local/bin/syswarden-core"),
            "core-identity": lambda item: item["boots"][1]["pre_exec"][
                "product_services"
            ].__setitem__(
                "core_executable_identity", "1:2:81ed:0:0|" + "0" * 64
            ),
            "core-pidfile-identity": lambda item: item["boots"][1]["pre_exec"][
                "product_services"
            ].__setitem__("core_pidfile_identity", "1:2:33188:0:0:644"),
            "restart-not-distinct": lambda item: item["boots"][1][
                "restart"
            ].__setitem__("distinct", False),
            "initial-restart-boolean-integer": lambda item: item["boots"][0][
                "restart"
            ].__setitem__("performed", 0),
            "restart-state": lambda item: item.__setitem__(
                "restart_state", "restart-two"
            ),
            "exec-code": lambda item: item["lifecycle_exec_exit_codes"].__setitem__(
                0, 1
            ),
            "exec-code-boolean": lambda item: item[
                "lifecycle_exec_exit_codes"
            ].__setitem__(0, False),
            "cleanup-remove": lambda item: item["cleanup"].__setitem__(
                "remove_exit_code", 1
            ),
            "cleanup-exists": lambda item: item["cleanup"].__setitem__(
                "exists_probe_exit_code", 0
            ),
            "cleanup-presence": lambda item: item["cleanup"].__setitem__(
                "absent_after_cleanup", False
            ),
            "orchestration": lambda item: item.__setitem__(
                "orchestration_error", "synthetic"
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                assert_rejected(mutation)

        schema_objects = (
            ("scenario", lambda item: item, adapter.PACKAGE_SCENARIO_KEYS),
            (
                "isolation",
                lambda item: item["isolation"],
                adapter.RUNTIME_ISOLATION_KEYS,
            ),
            ("boot", lambda item: item["boots"][0], adapter.RUNTIME_BOOT_KEYS),
            (
                "restart",
                lambda item: item["boots"][0]["restart"],
                adapter.RUNTIME_RESTART_KEYS,
            ),
            (
                "snapshot",
                lambda item: item["boots"][0]["pre_exec"],
                adapter.RUNTIME_SNAPSHOT_KEYS,
            ),
            (
                "lifecycle-process-security",
                lambda item: item["boots"][0]["lifecycle_exec_security"],
                adapter.PROCESS_SECURITY_KEYS,
            ),
            (
                "pid1-process-security",
                lambda item: item["boots"][0]["pre_exec"][
                    "pid1_process_security"
                ],
                adapter.PROCESS_SECURITY_KEYS,
            ),
            (
                "attestation-process-security",
                lambda item: item["boots"][0]["pre_exec"][
                    "attestation_process_security"
                ],
                adapter.PROCESS_SECURITY_KEYS,
            ),
            (
                "uid-map-range",
                lambda item: item["boots"][0]["pre_exec"]["pid1_uid_map"][0],
                adapter.ID_MAP_RANGE_KEYS,
            ),
            (
                "setpriv",
                lambda item: item["boots"][0]["pre_exec"]["setpriv"],
                adapter.SETPRIV_KEYS,
            ),
            (
                "product",
                lambda item: item["boots"][0]["pre_exec"]["product_services"],
                adapter.PRODUCT_SERVICES_KEYS,
            ),
            (
                "core-process-security",
                lambda item: item["boots"][0]["post_exec"][
                    "product_services"
                ]["core_process_security"],
                adapter.PROCESS_SECURITY_KEYS,
            ),
            (
                "mount",
                lambda item: item["isolation"]["mounts"][0],
                adapter.RUNTIME_MOUNT_KEYS,
            ),
            (
                "event",
                lambda item: item["events"][0],
                frozenset({"status", "check", "detail"}),
            ),
            (
                "tmpfs",
                lambda item: item["isolation"]["tmpfs"],
                frozenset({"/run", "/tmp"}),
            ),
            (
                "cleanup",
                lambda item: item["cleanup"],
                adapter.RUNTIME_CLEANUP_KEYS,
            ),
        )
        for object_name, locate, keys in schema_objects:
            for key in sorted(keys):
                with self.subTest(schema=object_name, missing=key):
                    scenario = copy.deepcopy(original)
                    locate(scenario).pop(key)
                    with self.assertRaises(adapter.AdapterError):
                        adapter._validate_runtime_scenario(
                            scenario,
                            spec,
                            original["name"],
                            "fixture.scenario",
                        )
            with self.subTest(schema=object_name, extra="unknown"):
                scenario = copy.deepcopy(original)
                locate(scenario)["unknown"] = True
                with self.assertRaises(adapter.AdapterError):
                    adapter._validate_runtime_scenario(
                        scenario, spec, original["name"], "fixture.scenario"
                    )

    def test_adapter_rejects_every_capability_process_boundary_bit(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        platform = report["platforms"][0]
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == platform["distribution"]
            and item.architecture == platform["architecture_id"]
        )
        original = platform["scenarios"][0]
        fields = (
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

        def boundary(
            scenario: dict[str, Any], name: str
        ) -> dict[str, Any]:
            boot = scenario["boots"][0]
            if name == "pid1":
                return boot["pre_exec"]["pid1_process_security"]
            if name == "attestation":
                return boot["pre_exec"]["attestation_process_security"]
            if name == "lifecycle":
                return boot["lifecycle_exec_security"]
            return boot["post_exec"]["product_services"][
                "core_process_security"
            ]

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
        for name in ("pid1", "attestation", "lifecycle", "core"):
            for capability, setter in (
                ("SYS_ADMIN", set_sys_admin),
                ("SYS_PTRACE", set_sys_ptrace),
            ):
                for field in fields:
                    with self.subTest(
                        boundary=name,
                        capability=capability,
                        field=field,
                    ):
                        scenario = copy.deepcopy(original)
                        security = boundary(scenario, name)
                        security[field] = setter(
                            security[field],
                            present=field not in expected_fields[capability][name],
                        )
                        with self.assertRaises(adapter.AdapterError):
                            adapter._validate_runtime_scenario(
                                scenario,
                                spec,
                                original["name"],
                                "fixture.scenario",
                            )

    def test_alpine_cron_fragment_mode_is_family_bound(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        platform = next(
            item for item in report["platforms"] if item["family"] == "apk"
        )
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == platform["distribution"]
            and item.architecture == platform["architecture_id"]
        )
        original = copy.deepcopy(platform["scenarios"][0])
        scenario = copy.deepcopy(original)
        adapter._validate_runtime_scenario(
            scenario, spec, scenario["name"], "fixture.alpine"
        )
        snapshot = scenario["boots"][0]["pre_exec"]
        self.assertIn(":81ed:0:0|", snapshot["cron_fragment_identity"])
        snapshot["cron_fragment_identity"] = snapshot[
            "cron_fragment_identity"
        ].replace(":81ed:0:0|", ":81a4:0:0|")
        with self.assertRaises(adapter.AdapterError):
            adapter._validate_runtime_scenario(
                scenario, spec, scenario["name"], "fixture.alpine"
            )

        systemd_platform = next(
            item for item in report["platforms"] if item["family"] != "apk"
        )
        systemd_setpriv = copy.deepcopy(
            systemd_platform["scenarios"][0]["boots"][0]["pre_exec"]["setpriv"]
        )
        openrc_mutations = {
            "sys-admin-cap-add": lambda item: item["isolation"]["cap_add"].append(
                "CAP_SYS_ADMIN"
            ),
            "sys-ptrace-cap-add": lambda item: item["isolation"]["cap_add"].append(
                "CAP_SYS_PTRACE"
            ),
            "systemd-launcher": lambda item: item["isolation"].__setitem__(
                "lifecycle_exec_launcher",
                list(adapter.SYSTEMD_LIFECYCLE_EXEC_LAUNCHER),
            ),
            "setpriv-provenance": lambda item: item["boots"][0][
                "pre_exec"
            ].__setitem__("setpriv", systemd_setpriv),
            "pid1-sys-admin": lambda item: item["boots"][0]["pre_exec"][
                "pid1_process_security"
            ].__setitem__(
                "cap_bounding",
                set_sys_admin(
                    item["boots"][0]["pre_exec"]["pid1_process_security"][
                        "cap_bounding"
                    ],
                    present=True,
                ),
            ),
            "pid1-sys-ptrace": lambda item: item["boots"][0]["pre_exec"][
                "pid1_process_security"
            ].__setitem__(
                "cap_bounding",
                set_sys_ptrace(
                    item["boots"][0]["pre_exec"]["pid1_process_security"][
                        "cap_bounding"
                    ],
                    present=True,
                ),
            ),
            "lifecycle-sys-ptrace": lambda item: item["boots"][0][
                "lifecycle_exec_security"
            ].__setitem__(
                "cap_effective",
                set_sys_ptrace(
                    item["boots"][0]["lifecycle_exec_security"][
                        "cap_effective"
                    ],
                    present=True,
                ),
            ),
            "core-sys-ptrace": lambda item: item["boots"][0]["post_exec"][
                "product_services"
            ]["core_process_security"].__setitem__(
                "cap_permitted",
                set_sys_ptrace(
                    item["boots"][0]["post_exec"]["product_services"][
                        "core_process_security"
                    ]["cap_permitted"],
                    present=True,
                ),
            ),
        }
        for name, mutation in openrc_mutations.items():
            with self.subTest(openrc_mutation=name):
                changed = copy.deepcopy(original)
                mutation(changed)
                with self.assertRaises(adapter.AdapterError):
                    adapter._validate_runtime_scenario(
                        changed, spec, changed["name"], "fixture.alpine"
                    )

    def test_lifecycle_claims_are_derived_from_active_event_evidence(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        for coordinate_platform in report["platforms"]:
            coordinate_spec = next(
                item
                for item in package_lifecycle_lab.DEFAULT_PLATFORMS
                if item.distribution == coordinate_platform["distribution"]
                and item.architecture == coordinate_platform["architecture_id"]
            )
            with self.subTest(
                distribution=coordinate_platform["distribution"],
                architecture=coordinate_platform["architecture_id"],
            ):
                coordinate_claims = adapter._derive_platform_lifecycle_claims(
                    coordinate_platform, coordinate_spec
                )
                self.assertTrue(all(coordinate_claims.values()))
        platform = copy.deepcopy(report["platforms"][0])
        spec = next(
            item
            for item in package_lifecycle_lab.DEFAULT_PLATFORMS
            if item.distribution == platform["distribution"]
            and item.architecture == platform["architecture_id"]
        )
        claims = adapter._derive_platform_lifecycle_claims(platform, spec)
        self.assertEqual(set(claims), set(adapter.LIFECYCLE_CLAIM_KEYS))
        self.assertEqual(len(adapter.LIFECYCLE_CLAIM_KEYS), 10)
        self.assertFalse(
            any("sys_admin" in claim for claim in adapter.LIFECYCLE_CLAIM_KEYS)
        )
        self.assertFalse(
            any("sys_ptrace" in claim for claim in adapter.LIFECYCLE_CLAIM_KEYS)
        )
        self.assertTrue(all(claims.values()))

        def scenario(item: dict[str, Any], name: str) -> dict[str, Any]:
            return next(value for value in item["scenarios"] if value["name"] == name)

        def event(
            item: dict[str, Any], scenario_name: str, check: str
        ) -> dict[str, Any]:
            return next(
                value
                for value in scenario(item, scenario_name)["events"]
                if value["check"] == check
            )

        claim_mutations = {
            "active_service_manager": lambda item: scenario(
                item, "upgrade-rollback"
            )["boots"][0]["pre_exec"].__setitem__("manager_state", "OFFLINE"),
            "active_postinstall": lambda item: event(
                item,
                "upgrade-rollback",
                "upgrade-rollback.candidate.postinstall_contract",
            ).__setitem__("status", "fail"),
            "legacy_runtime_retirement": lambda item: event(
                item,
                "upgrade-rollback",
                "upgrade-rollback.candidate.postinstall_contract",
            ).__setitem__(
                "detail", "postinstall contract passed without retirement proof"
            ),
            "fresh_install": lambda item: event(
                item, "remove", "remove.install.candidate"
            ).__setitem__("status", "fail"),
            "upgrade": lambda item: event(
                item,
                "upgrade-rollback",
                "upgrade-rollback.upgrade.candidate",
            ).__setitem__("status", "fail"),
            "reinstall": lambda item: event(
                item,
                "upgrade-rollback",
                "upgrade-rollback.reinstall.candidate",
            ).__setitem__("status", "fail"),
            "rollback": lambda item: event(
                item,
                "upgrade-rollback",
                "upgrade-rollback.rollback.previous",
            ).__setitem__("status", "fail"),
            "remove": lambda item: event(
                item, "remove", "remove.remove"
            ).__setitem__("status", "fail"),
            "purge": lambda item: event(
                item, "purge", "purge.purge"
            ).__setitem__("status", "fail"),
            "second_restart": lambda item: scenario(
                item, "upgrade-rollback"
            )["boots"][2]["restart"].__setitem__("distinct", False),
        }
        self.assertEqual(set(claim_mutations), set(adapter.LIFECYCLE_CLAIM_KEYS))
        for claim, mutation in claim_mutations.items():
            with self.subTest(claim=claim):
                changed_platform = copy.deepcopy(platform)
                mutation(changed_platform)
                changed = adapter._derive_platform_lifecycle_claims(
                    changed_platform, spec
                )
                self.assertFalse(changed[claim])
                if claim == "legacy_runtime_retirement":
                    self.assertTrue(changed["active_postinstall"])

        boundary_mutations = {
            "active_service_manager": lambda item: scenario(
                item, "upgrade-rollback"
            )["boots"][0]["pre_exec"]["pid1_process_security"].__setitem__(
                "cap_permitted",
                set_sys_admin(
                    scenario(item, "upgrade-rollback")["boots"][0]["pre_exec"][
                        "pid1_process_security"
                    ]["cap_permitted"],
                    present=False,
                ),
            ),
            "active_postinstall": lambda item: scenario(
                item, "upgrade-rollback"
            )["boots"][0]["lifecycle_exec_security"].__setitem__(
                "cap_effective",
                set_sys_admin(
                    scenario(item, "upgrade-rollback")["boots"][0][
                        "lifecycle_exec_security"
                    ]["cap_effective"],
                    present=True,
                ),
            ),
        }
        for claim, mutation in boundary_mutations.items():
            with self.subTest(boundary_prerequisite=claim):
                changed_platform = copy.deepcopy(platform)
                mutation(changed_platform)
                changed = adapter._derive_platform_lifecycle_claims(
                    changed_platform, spec
                )
                self.assertFalse(changed[claim])

    def test_raw_v4_engine_helper_cleanup_and_native_records_are_exact(self) -> None:
        original = self.fixture.load_raw("package-lifecycle-raw.json")
        adapter._validate_package_schema(original)
        self.assertEqual(len(original["platforms"]), 5)
        native_records = {
            record["architecture"]: record
            for record in original["native_shards"]["reports"]
        }
        self.assertEqual(set(native_records), {"amd64"})
        self.assertEqual(len(native_records["amd64"]["uid_map"]), 2)
        self.assertEqual(len(native_records["amd64"]["gid_map"]), 2)
        self.assertEqual(
            {
                (item["distribution"], item["architecture_id"])
                for item in original["platforms"]
            },
            package_lifecycle_lab.REQUIRED_PLATFORM_COORDINATES,
        )
        self.assertEqual(
            {item["runtime_mode"] for item in original["platforms"]},
            {"active-real-init"},
        )

        def assert_rejected(mutator: Any) -> None:
            report = copy.deepcopy(original)
            mutator(report)
            with self.assertRaises(adapter.AdapterError):
                adapter._validate_package_schema(report)

        def mismatch_native_effective_uid_map(item: dict[str, Any]) -> None:
            record = item["native_shards"]["reports"][0]
            record["uid_map"][0]["outside_id"] = record["effective_uid"] + 1

        mutations = {
            "engine-rootless": lambda item: item["engine"].__setitem__(
                "rootless", False
            ),
            "engine-cgroups-v1": lambda item: item["engine"].__setitem__(
                "cgroups_version", "v1"
            ),
            "engine-cgroupfs": lambda item: item["engine"].__setitem__(
                "cgroup_manager", "cgroupfs"
            ),
            "engine-delegation": lambda item: item["engine"].__setitem__(
                "cgroup_delegation", "rootless-systemd-v2"
            ),
            "engine-controller-missing": lambda item: item["engine"][
                "cgroup_controllers"
            ].remove("memory"),
            "engine-controller-order": lambda item: item["engine"].__setitem__(
                "cgroup_controllers",
                list(reversed(item["engine"]["cgroup_controllers"])),
            ),
            "engine-remote": lambda item: item["engine"].__setitem__(
                "service_is_remote", True
            ),
            "engine-host": lambda item: item["engine"].__setitem__(
                "host_architecture", "amd64"
            ),
            "aggregate-effective-uid": lambda item: item["engine"].__setitem__(
                "effective_uid", 1000
            ),
            "aggregate-uid-map": lambda item: item["engine"].__setitem__(
                "uid_map",
                copy.deepcopy(item["native_shards"]["reports"][0]["uid_map"]),
            ),
            "helper-digest": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("sha256", "0" * 64),
            "helper-size": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("size_bytes", 0),
            "helper-source": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("source", "/tmp/package_webtui_retirement.sh"),
            "helper-symlink": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("snapshot_symlink", True),
            "helper-mode": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("snapshot_mode", "0644"),
            "helper-not-revalidated": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("revalidated_before_report", False),
            "helper-boolean-integer": lambda item: item["engine"][
                "lifecycle_helper"
            ].__setitem__("source_regular_file", 1),
            "native-controller": lambda item: item["native_shards"]["reports"][
                0
            ]["cgroup_controllers"].remove("pids"),
            "native-effective-id-type": lambda item: item["native_shards"][
                "reports"
            ][0].__setitem__("effective_uid", True),
            "native-effective-id-map-mismatch": mismatch_native_effective_uid_map,
            "native-helper-binding": lambda item: item["native_shards"][
                "reports"
            ][0]["lifecycle_helper"].__setitem__("sha256", "f" * 64),
            "bootstrap-cleanup-remove": lambda item: item["platforms"][0][
                "bootstrap_image_cleanup"
            ].__setitem__("remove_exit_code", 1),
            "bootstrap-cleanup-exists": lambda item: item["platforms"][0][
                "bootstrap_image_cleanup"
            ].__setitem__("exists_probe_exit_code", 0),
            "bootstrap-cleanup-presence": lambda item: item["platforms"][0][
                "bootstrap_image_cleanup"
            ].__setitem__("absent_after_cleanup", False),
            "platform-restart-contract": lambda item: item["platforms"][
                0
            ].__setitem__("restart_contract", "operator-defined restart"),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                assert_rejected(mutation)

        schema_objects = (
            ("engine", lambda item: item["engine"], adapter.PACKAGE_ENGINE_KEYS),
            (
                "aggregate-helper",
                lambda item: item["engine"]["lifecycle_helper"],
                adapter.LIFECYCLE_HELPER_KEYS,
            ),
            (
                "native-record",
                lambda item: item["native_shards"]["reports"][0],
                adapter.PACKAGE_NATIVE_SHARD_RECORD_KEYS,
            ),
            (
                "native-helper",
                lambda item: item["native_shards"]["reports"][0][
                    "lifecycle_helper"
                ],
                adapter.LIFECYCLE_HELPER_KEYS,
            ),
            (
                "bootstrap-cleanup",
                lambda item: item["platforms"][0]["bootstrap_image_cleanup"],
                adapter.RUNTIME_CLEANUP_KEYS,
            ),
        )
        for object_name, locate, keys in schema_objects:
            for key in sorted(keys):
                with self.subTest(schema=object_name, missing=key):
                    assert_rejected(lambda item, key=key: locate(item).pop(key))
            with self.subTest(schema=object_name, extra="unknown"):
                assert_rejected(
                    lambda item: locate(item).__setitem__("unknown", True)
                )

    def test_fedora_vendor_cron_dropin_is_exact_for_amd64(
        self,
    ) -> None:
        original = self.fixture.load_raw("package-lifecycle-raw.json")
        adapter._validate_package_schema(original)

        def platform(
            report: dict[str, Any], distribution: str, architecture: str
        ) -> dict[str, Any]:
            return next(
                item
                for item in report["platforms"]
                if item["distribution"] == distribution
                and item["architecture_id"] == architecture
            )

        def snapshots(item: dict[str, Any]) -> list[dict[str, Any]]:
            return [
                boot[phase]
                for scenario in item["scenarios"]
                for boot in scenario["boots"]
                for phase in ("pre_exec", "post_exec")
            ]

        expected = [package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH]
        fedora_snapshots = snapshots(platform(original, "fedora", "amd64"))
        self.assertTrue(
            all(
                snapshot["cron_dropin_paths"] == expected
                for snapshot in fedora_snapshots
            )
        )
        self.assertTrue(
            all(
                snapshot["cron_executable_path"] == "/usr/bin/crond"
                for snapshot in fedora_snapshots
            )
        )
        alma_snapshots = snapshots(platform(original, "almalinux", "amd64"))
        self.assertTrue(
            all(
                snapshot["cron_executable_path"] == "/usr/sbin/crond"
                for snapshot in alma_snapshots
            )
        )
        for distribution in ("debian", "ubuntu", "almalinux", "alpine"):
            self.assertTrue(
                all(
                    snapshot["cron_dropin_paths"] == []
                    for snapshot in snapshots(
                        platform(original, distribution, "amd64")
                    )
                )
            )

        def assert_rejected(
            distribution: str,
            architecture: str,
            value: list[str],
        ) -> None:
            report = copy.deepcopy(original)
            snapshots(platform(report, distribution, architecture))[0][
                "cron_dropin_paths"
            ] = value
            with self.assertRaises(adapter.AdapterError):
                adapter._validate_package_schema(report)

        for name, distribution, architecture, value in (
            ("missing", "fedora", "amd64", []),
            (
                "extra",
                "fedora",
                "amd64",
                [
                    package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH,
                    "/etc/systemd/system/crond.service.d/operator.conf",
                ],
            ),
            (
                "duplicate",
                "fedora",
                "amd64",
                [
                    package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH,
                    package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH,
                ],
            ),
            (
                "wrong",
                "fedora",
                "amd64",
                ["/etc/systemd/system/crond.service.d/operator.conf"],
            ),
            (
                "cross_distribution",
                "almalinux",
                "amd64",
                [package_lifecycle_lab.FEDORA_CRON_DROPIN_PATH],
            ),
        ):
            with self.subTest(mutation=name):
                assert_rejected(distribution, architecture, value)

        for name, distribution, architecture, value in (
            ("fedora_alias", "fedora", "amd64", "/usr/sbin/crond"),
            ("alma_fedora_path", "almalinux", "amd64", "/usr/bin/crond"),
        ):
            with self.subTest(mutation=name):
                report = copy.deepcopy(original)
                snapshots(platform(report, distribution, architecture))[0][
                    "cron_executable_path"
                ] = value
                with self.assertRaises(adapter.AdapterError):
                    adapter._validate_package_schema(report)

    def test_amd64_probe_must_report_the_native_uname(self) -> None:
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        amd64 = next(
            item
            for item in report["platforms"]
            if item["architecture_id"] == "amd64"
        )
        amd64["architecture_probe"]["actual_uname"] = "unsupported"
        self.fixture.save_raw("package-lifecycle-raw.json", report)
        self.assertAdapterError(self.fixture.args())

    def test_native_shard_files_and_workflow_binding_are_independently_revalidated(self) -> None:
        amd_path = self.fixture.raw / "package-lifecycle-amd64.json"
        amd = self.fixture.load_raw("package-lifecycle-amd64.json")
        amd["qualification_binding"]["workflow_run_id"] += 1
        self.fixture.save_raw("package-lifecycle-amd64.json", amd)
        aggregate = self.fixture.load_raw("package-lifecycle-raw.json")
        record = aggregate["native_shards"]["reports"][0]
        record["report_sha256"] = hashlib.sha256(amd_path.read_bytes()).hexdigest()
        self.fixture.save_raw("package-lifecycle-raw.json", aggregate)
        self.assertAdapterError(self.fixture.args())

        self.fixture._make_raw_reports()
        self.assertAdapterError(
            self.fixture.args(expected_workflow_run_id=self.fixture.workflow_run_id + 1)
        )

        self.fixture._make_raw_reports()
        self.assertAdapterError(
            self.fixture.args(
                package_amd64_shard=self.fixture.raw / "package-lifecycle-raw.json"
            )
        )

        self.fixture._make_raw_reports()
        report = self.fixture.load_raw("package-lifecycle-raw.json")
        report["platforms"][0]["architecture_probe"]["execution_mode"] = "translated"
        report["platforms"][0]["bootstrap_execution"] = "cross_architecture"
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

        self.fixture._make_raw_reports()
        amd_path = self.fixture.raw / "package-lifecycle-amd64.json"
        amd = self.fixture.load_raw("package-lifecycle-amd64.json")
        changed_uid_map = copy.deepcopy(amd["engine"]["uid_map"])
        changed_uid_map[0]["outside_id"] += 1
        amd["engine"]["effective_uid"] += 1
        amd["engine"]["uid_map"] = changed_uid_map
        for platform in amd["platforms"]:
            replace_snapshot_identity_maps(
                platform,
                changed_uid_map,
                amd["engine"]["gid_map"],
            )
        self.fixture.save_raw("package-lifecycle-amd64.json", amd)
        aggregate = self.fixture.load_raw("package-lifecycle-raw.json")
        amd_record = aggregate["native_shards"]["reports"][0]
        amd_record["report_sha256"] = hashlib.sha256(
            amd_path.read_bytes()
        ).hexdigest()
        self.fixture.save_raw("package-lifecycle-raw.json", aggregate)
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
