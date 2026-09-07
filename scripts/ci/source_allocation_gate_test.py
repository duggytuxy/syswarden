#!/usr/bin/env python3
"""Adversarial tests for the source-bound allocation evidence gate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

try:
    from scripts.ci import source_allocation_gate as gate
except ModuleNotFoundError:
    import source_allocation_gate as gate


def compact(document: object) -> bytes:
    return gate._compact_json_wire(document)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class BundleFixture:
    def __init__(
        self,
        parent: Path,
        *,
        candidate: str = "a" * 40,
        allocation_delta: Callable[[str, str, int], int] | None = None,
        byte_delta: Callable[[str, str, int], int] | None = None,
    ) -> None:
        self.candidate = candidate
        self.root = parent / "bundle"
        self.root.mkdir(mode=0o700)
        self.contract = gate.load_contract()
        allocation_delta = allocation_delta or (lambda _campaign, _role, _index: 2048)
        byte_delta = byte_delta or (lambda _campaign, _role, _index: 65536)

        self.execution_control = {
            "schema_version": 1,
            "schema_id": gate.EXECUTION_CONTROL_SCHEMA,
            "candidate_commit": candidate,
            "architecture": gate.ARCHITECTURE,
            "recorded_at": "2026-09-10T07:55:00Z",
            "attested_by": "qualification-owner",
            "producer_egress_denied": True,
            "repository_source_read_only": True,
            "build_checkouts_producer_writable": True,
            "persistent_writes_limited_to_evidence_root": True,
            "probe_egress_denied": True,
            "probe_persistent_filesystem_read_only": True,
            "sandbox_kind": "bubblewrap-minimal-root-unshared-network/v2",
            "sandbox_executable_path": "/usr/bin/bwrap",
            "sandbox_executable_sha256": "f" * 64,
            "python_executable_path": "/usr/bin/python3.14",
            "python_executable_sha256": "e" * 64,
            "shell_executable_path": "/usr/bin/bash",
            "shell_executable_sha256": "d" * 64,
            "outer_unix_socket_canary_passed": True,
            "probe_unix_socket_canary_required": True,
            "runner_threat_model": "protected-dedicated-runner-trusted-launch-environment-no-hostile-same-uid-process/v1",
        }
        execution_wire = compact(self.execution_control)
        self.write("execution-control-attestation.json", execution_wire)

        self.environment = {
            "schema_version": 1,
            "schema_id": gate.ENVIRONMENT_SCHEMA,
            "repository": gate.REPOSITORY,
            "candidate_commit": candidate,
            "recorded_at": "2026-09-10T08:00:00Z",
            "architecture": gate.ARCHITECTURE,
            "kernel_machine": gate.KERNEL_MACHINE,
            "kernel_release": "6.18.44-0-virt",
            "os_release_sha256": "1" * 64,
            "logical_cpu_count": 2,
            "page_size": 4096,
            "execution_control_attestation_sha256": digest(execution_wire),
            "execution_controls": self.execution_control,
        }
        environment_wire = compact(self.environment)
        self.write("environment.json", environment_wire)

        self.benchmark_wire = b"//go:build linux\n\npackage main\n"
        self.fixture_wire = compact({"schema_version": 1, "record": "fixture"})
        self.catalog_wire = compact({"schema_version": 1, "signatures": []})
        self.probe_wires = {
            "baseline": b"baseline-probe-bytes",
            "candidate": b"candidate-probe-bytes",
        }
        self.write("benchmark-source.go", self.benchmark_wire)
        self.write("fixture.json", self.fixture_wire)
        self.write("signature-catalog.json", self.catalog_wire)
        for role in gate.ROLES:
            self.write(f"{role}-probe", self.probe_wires[role], mode=0o700)

        graph = [
            {
                "path": "syswarden-core",
                "version": "",
                "sum": "",
                "go_mod_sum": "",
                "main": True,
            }
        ]
        graph_sha = digest(compact(graph))
        self.subjects = {
            "baseline": {
                "release": gate.BASELINE_RELEASE,
                "commit": gate.BASELINE_COMMIT,
                "tree": "b" * 40,
                "module_graph_sha256": graph_sha,
                "module_graph": graph,
                "probe_binary_sha256": digest(self.probe_wires["baseline"]),
                "reproducible_build": True,
            },
            "candidate": {
                "release": gate.TARGET_RELEASE,
                "commit": candidate,
                "tree": "c" * 40,
                "module_graph_sha256": graph_sha,
                "module_graph": graph,
                "probe_binary_sha256": digest(self.probe_wires["candidate"]),
                "reproducible_build": True,
            },
        }
        self.build = {
            "schema_version": 1,
            "schema_id": gate.BUILD_ATTESTATION_SCHEMA,
            "repository": gate.REPOSITORY,
            "target_release": gate.TARGET_RELEASE,
            "candidate_commit": candidate,
            "baseline_release": gate.BASELINE_RELEASE,
            "baseline_commit": gate.BASELINE_COMMIT,
            "environment_sha256": digest(environment_wire),
            "bindings": {
                "benchmark_source_sha256": digest(self.benchmark_wire),
                "fixture_sha256": digest(self.fixture_wire),
                "signature_catalog_sha256": digest(self.catalog_wire),
                "toolchain_version": self.contract["toolchain_version"],
                "toolchain_archive_sha256": self.contract[
                    "toolchain_archive_sha256"
                ],
                "toolchain_executable_sha256": "2" * 64,
                "toolchain_version_output": "go version go1.26.6 linux/amd64",
                "workload_id": gate.WORKLOAD_ID,
            },
            "build_contract": {
                "gowork": "off",
                "goflags": "-mod=readonly",
                "cgo_enabled": "0",
                "goos": "linux",
                "goarch": "amd64",
                "gotoolchain": "local",
                "goproxy": "off",
                "gosumdb": "off",
                "trimpath": True,
                "buildvcs": False,
                "command": [
                    "go",
                    "-C",
                    "{subject_module}",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    "-o",
                    "{probe_output}",
                    "{benchmark_source}",
                ],
            },
            "subjects": self.subjects,
        }
        build_wire = compact(self.build)
        self.write("build-attestation.json", build_wire)

        self.bindings = {
            "architecture": gate.ARCHITECTURE,
            "kernel_machine": gate.KERNEL_MACHINE,
            "environment_sha256": digest(environment_wire),
            "build_attestation_sha256": digest(build_wire),
            "benchmark_source_sha256": digest(self.benchmark_wire),
            "fixture_sha256": digest(self.fixture_wire),
            "signature_catalog_sha256": digest(self.catalog_wire),
            "toolchain_version": self.contract["toolchain_version"],
            "toolchain_archive_sha256": self.contract[
                "toolchain_archive_sha256"
            ],
            "workload_id": gate.WORKLOAD_ID,
        }
        raw_root = self.root / "raw"
        raw_root.mkdir(mode=0o700)
        nonce_counter = 0
        for campaign_number, campaign_id in enumerate(gate.CAMPAIGN_IDS, start=1):
            campaign_root = raw_root / campaign_id
            campaign_root.mkdir(mode=0o700)
            campaign_recorded_at = f"2026-09-{9 + campaign_number:02d}T08:00:00Z"
            for sample_index in range(1, 11):
                for role in gate.ROLES:
                    nonce_counter += 1
                    invocation_index = gate._expected_invocation(sample_index, role)
                    malloc_delta = allocation_delta(campaign_id, role, sample_index)
                    alloc_bytes_delta = byte_delta(campaign_id, role, sample_index)
                    malloc_before = 100000 + nonce_counter
                    bytes_before = 5000000 + nonce_counter
                    raw = {
                        "schema_version": 1,
                        "schema_id": gate.RAW_SCHEMA,
                        "repository": gate.REPOSITORY,
                        "target_release": gate.TARGET_RELEASE,
                        "candidate_commit": candidate,
                        "baseline_release": gate.BASELINE_RELEASE,
                        "baseline_commit": gate.BASELINE_COMMIT,
                        "campaign_id": campaign_id,
                        "campaign_recorded_at": campaign_recorded_at,
                        "sample_started_at": f"2026-09-{9 + campaign_number:02d}T08:{invocation_index:02d}:00Z",
                        "sample_completed_at": f"2026-09-{9 + campaign_number:02d}T08:{invocation_index:02d}:01Z",
                        "sample_index": sample_index,
                        "invocation_index": invocation_index,
                        "sample_id": f"{campaign_id}-{role}-{sample_index:02d}",
                        "process_nonce": f"{nonce_counter:032x}",
                        "subject": {
                            "role": role,
                            "release": self.subjects[role]["release"],
                            "commit": self.subjects[role]["commit"],
                            "tree": self.subjects[role]["tree"],
                            "probe_binary_sha256": self.subjects[role][
                                "probe_binary_sha256"
                            ],
                            "module_graph_sha256": self.subjects[role][
                                "module_graph_sha256"
                            ],
                        },
                        "bindings": self.bindings,
                        "workload": {
                            key: value
                            for key, value in self.contract["workload"].items()
                            if key not in {"id", "entrypoint"}
                        },
                        "counters": {
                            "mallocs_before": str(malloc_before),
                            "mallocs_after": str(malloc_before + malloc_delta),
                            "total_alloc_bytes_before": str(bytes_before),
                            "total_alloc_bytes_after": str(
                                bytes_before + alloc_bytes_delta
                            ),
                            "gc_cycles_before": "5",
                            "gc_cycles_after": "5",
                        },
                    }
                    self.write(
                        f"raw/{campaign_id}/{role}-{sample_index:02d}.json",
                        compact(raw),
                    )

    def path(self, relative: str) -> Path:
        return self.root / relative

    def write(self, relative: str, raw: bytes, mode: int = 0o600) -> None:
        path = self.path(relative)
        path.write_bytes(raw)
        path.chmod(mode)

    def load_json(self, relative: str) -> dict[str, Any]:
        return json.loads(self.path(relative).read_bytes())

    def write_json(self, relative: str, document: object, mode: int = 0o600) -> None:
        self.write(relative, compact(document), mode=mode)

    def raw_path(
        self,
        campaign: str = "allocation-campaign-01",
        role: str = "baseline",
        index: int = 1,
    ) -> Path:
        return self.path(f"raw/{campaign}/{role}-{index:02d}.json")

    def assemble(self) -> dict[str, Any]:
        return gate.assemble(
            contract_path=gate.DEFAULT_CONTRACT,
            bundle_root=self.root,
            candidate_commit=self.candidate,
            evidence_path=self.path("EVIDENCE.json"),
            report_path=self.path("REPORT.json"),
        )


class SourceAllocationGateTests(unittest.TestCase):
    def new_fixture(self, **kwargs: object) -> tuple[tempfile.TemporaryDirectory[str], BundleFixture]:
        temporary = tempfile.TemporaryDirectory(dir="/tmp")
        return temporary, BundleFixture(Path(temporary.name), **kwargs)  # type: ignore[arg-type]

    def test_complete_bundle_assembles_and_validates_exact_evidence(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            raw_report = gate.validate_raw_bundle(
                contract_path=gate.DEFAULT_CONTRACT,
                bundle_root=fixture.root,
                candidate_commit=fixture.candidate,
            )
            self.assertEqual(raw_report["verdict"], "pass")
            self.assertFalse(fixture.path("EVIDENCE.json").exists())
            self.assertFalse(fixture.path("REPORT.json").exists())
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "pass")
            self.assertEqual(report["failed_metrics"], [])
            self.assertEqual(report["measurement_scope"], gate.MEASUREMENT_SCOPE)
            self.assertFalse(report["native_package_runtime_measurement"])
            self.assertEqual(fixture.path("EVIDENCE.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(fixture.path("REPORT.json").stat().st_mode & 0o777, 0o600)
            evidence = json.loads(fixture.path("EVIDENCE.json").read_bytes())
            self.assertEqual(len(evidence["raw_inventory"]), 60)
            self.assertEqual(len(evidence["campaigns"]), 3)
            self.assertEqual(
                evidence["campaigns"][0]["order"][:4],
                ["baseline", "candidate", "candidate", "baseline"],
            )
            metric = evidence["metrics"][gate.METRIC_NAMES[0]]["baseline"][0]
            self.assertEqual(metric["raw_numerator"], "2048")
            self.assertEqual(metric["raw_denominator"], "2048")
            self.assertEqual((metric["numerator"], metric["denominator"]), ("1", "1"))
            validated = gate.validate(
                contract_path=gate.DEFAULT_CONTRACT,
                bundle_root=fixture.root,
                candidate_commit=fixture.candidate,
                evidence_path=fixture.path("EVIDENCE.json"),
                report_path=fixture.path("REPORT.json"),
            )
            self.assertEqual(validated, report)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "already exists"):
                fixture.assemble()

    def test_contract_is_exact_and_has_no_waiver_surface(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            source = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
            for field, value in (
                ("waivers", {}),
                ("campaigns", list(gate.CAMPAIGN_IDS[:2])),
            ):
                with self.subTest(field=field):
                    document = copy.deepcopy(source)
                    document[field] = value
                    path = Path(directory) / f"{field}.json"
                    path.write_bytes(compact(document))
                    path.chmod(0o600)
                    with self.assertRaises(gate.SourceAllocationGateError):
                        gate.load_contract(path)
            document = copy.deepcopy(source)
            document["workload"]["goroutines_before"] = 1
            path = Path(directory) / "goroutines.json"
            path.write_bytes(compact(document))
            path.chmod(0o600)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "goroutines_before"):
                gate.load_contract(path)

    def test_counter_string_formats_and_uint64_bound_are_enforced(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            path = fixture.raw_path()
            original = fixture.load_json(str(path.relative_to(fixture.root)))
            invalid = ("-1", "+1", "01", "1.0", "1e3", str(1 << 64))
            for value in invalid:
                with self.subTest(value=value):
                    changed = copy.deepcopy(original)
                    changed["counters"]["mallocs_before"] = value
                    fixture.write_json(str(path.relative_to(fixture.root)), changed)
                    with self.assertRaises(gate.SourceAllocationGateError):
                        gate.load_raw_records(
                            raw_root=fixture.path("raw"),
                            contract=fixture.contract,
                            candidate_commit=fixture.candidate,
                        )
            fixture.write_json(str(path.relative_to(fixture.root)), original)

    def test_counter_order_gc_and_zero_state_are_enforced(self) -> None:
        cases = (
            ("decreased", {"mallocs_before": "200000", "mallocs_after": "1"}),
            ("gc", {"gc_cycles_after": "6"}),
            (
                "zero-state",
                {
                    "mallocs_after": "100001",
                    "total_alloc_bytes_after": "5001000",
                },
            ),
        )
        for name, counters in cases:
            with self.subTest(name=name):
                temporary, fixture = self.new_fixture()
                with temporary:
                    relative = str(fixture.raw_path().relative_to(fixture.root))
                    raw = fixture.load_json(relative)
                    raw["counters"].update(counters)
                    fixture.write_json(relative, raw)
                    with self.assertRaises(gate.SourceAllocationGateError):
                        fixture.assemble()

    def test_workload_entrypoint_goroutines_and_bindings_are_fail_closed(self) -> None:
        for field, value in (
            ("goroutines_before", 1),
            ("goroutines_after", 3),
            ("gomaxprocs", 2),
            ("admitted_events", 2047),
            ("garbage_collection_during_measurement", True),
        ):
            with self.subTest(field=field):
                temporary, fixture = self.new_fixture()
                with temporary:
                    relative = str(fixture.raw_path().relative_to(fixture.root))
                    raw = fixture.load_json(relative)
                    raw["workload"][field] = value
                    fixture.write_json(relative, raw)
                    with self.assertRaisesRegex(gate.SourceAllocationGateError, field):
                        fixture.assemble()
        temporary, fixture = self.new_fixture()
        with temporary:
            relative = str(fixture.raw_path().relative_to(fixture.root))
            raw = fixture.load_json(relative)
            raw["bindings"]["workload_id"] = "other-workload/v1"
            fixture.write_json(relative, raw)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "workload_id"):
                fixture.assemble()

    def test_invocation_order_nonce_and_subject_role_are_exact(self) -> None:
        mutations = (
            ("invocation_index", 2),
            ("sample_id", "allocation-campaign-01-candidate-01"),
            ("subject.role", "candidate"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                temporary, fixture = self.new_fixture()
                with temporary:
                    relative = str(fixture.raw_path().relative_to(fixture.root))
                    raw = fixture.load_json(relative)
                    if field == "subject.role":
                        raw["subject"]["role"] = value
                    else:
                        raw[field] = value
                    fixture.write_json(relative, raw)
                    with self.assertRaises(gate.SourceAllocationGateError):
                        fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            first = fixture.load_json("raw/allocation-campaign-01/baseline-01.json")
            second = fixture.load_json("raw/allocation-campaign-01/candidate-01.json")
            second["process_nonce"] = first["process_nonce"]
            fixture.write_json("raw/allocation-campaign-01/candidate-01.json", second)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "nonce"):
                fixture.assemble()

    def test_raw_inventory_modes_links_and_extra_files_are_rejected(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            fixture.raw_path().chmod(0o644)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "safe mode"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            os.link(fixture.raw_path(), Path(temporary.name) / "raw-hardlink")
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "regular file"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            fixture.write("raw/allocation-campaign-01/extra.json", b"{}\n")
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "inventory"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            target = fixture.raw_path()
            replacement = Path(temporary.name) / "replacement.json"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            target.unlink()
            target.symlink_to(replacement)
            with self.assertRaises(gate.SourceAllocationGateError):
                fixture.assemble()

    def test_bundle_file_hashes_execution_control_and_probe_are_bound(self) -> None:
        for relative, replacement in (
            ("fixture.json", b'{"changed":true}\n'),
            ("baseline-probe", b"replacement-probe"),
            ("execution-control-attestation.json", b'{"changed":true}\n'),
        ):
            with self.subTest(relative=relative):
                temporary, fixture = self.new_fixture()
                with temporary:
                    fixture.write(
                        relative,
                        replacement,
                        mode=0o700 if relative.endswith("probe") else 0o600,
                    )
                    with self.assertRaises(gate.SourceAllocationGateError):
                        fixture.assemble()

    def test_probe_sandbox_execution_controls_are_fail_closed(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            mutations = (
                ("probe_egress_denied", False),
                ("probe_persistent_filesystem_read_only", False),
                ("sandbox_kind", "other-sandbox/v1"),
                ("sandbox_executable_sha256", "not-a-digest"),
                ("python_executable_path", "/tmp/python3"),
                ("python_executable_sha256", "not-a-digest"),
                ("shell_executable_path", "/tmp/bash"),
                ("shell_executable_sha256", "not-a-digest"),
                ("outer_unix_socket_canary_passed", False),
                ("probe_unix_socket_canary_required", False),
            )
            for field, value in mutations:
                with self.subTest(field=field):
                    control = copy.deepcopy(fixture.execution_control)
                    control[field] = value
                    with self.assertRaises(gate.SourceAllocationGateError):
                        gate._validate_execution_control(
                            control,
                            candidate_commit=fixture.candidate,
                        )

    def test_zero_to_zero_is_valid_and_uses_zero_over_one(self) -> None:
        zero = lambda _campaign, _role, _index: 0
        temporary, fixture = self.new_fixture(allocation_delta=zero, byte_delta=zero)
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "pass")
            for metric in report["metrics"].values():
                self.assertEqual(
                    metric["aggregate_regression"],
                    {"classification": "zero-to-zero", "percent": None},
                )
                self.assertEqual(
                    metric["baseline"]["median"],
                    {"numerator": "0", "denominator": "1"},
                )

    def test_zero_introduction_fails_and_improvement_to_zero_passes(self) -> None:
        def introduced(_campaign: str, role: str, _index: int) -> int:
            return 0 if role == "baseline" else 1

        temporary, fixture = self.new_fixture(
            allocation_delta=introduced, byte_delta=introduced
        )
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "fail")
            self.assertTrue(
                all(
                    metric["aggregate_regression"]["classification"]
                    == "introduced-from-zero"
                    for metric in report["metrics"].values()
                )
            )

        def improved(_campaign: str, role: str, _index: int) -> int:
            return 1 if role == "baseline" else 0

        temporary, fixture = self.new_fixture(
            allocation_delta=improved, byte_delta=improved
        )
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "pass")
            self.assertTrue(
                all(
                    metric["aggregate_regression"]["classification"]
                    == "improved-to-zero"
                    for metric in report["metrics"].values()
                )
            )

    def test_exact_ten_percent_passes_and_above_ten_fails(self) -> None:
        def exact(_campaign: str, role: str, _index: int) -> int:
            return 1000 if role == "baseline" else 1100

        temporary, fixture = self.new_fixture(allocation_delta=exact, byte_delta=exact)
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "pass")
            self.assertTrue(
                all(
                    metric["aggregate_regression"]["percent"] == "10.000000"
                    for metric in report["metrics"].values()
                )
            )

        def above(_campaign: str, role: str, _index: int) -> int:
            return 1000 if role == "baseline" else 1101

        temporary, fixture = self.new_fixture(allocation_delta=above, byte_delta=above)
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "fail")
            self.assertEqual(set(report["failed_metrics"]), set(gate.METRIC_NAMES))

    def test_two_regressed_campaigns_are_required_for_stability(self) -> None:
        def one(campaign: str, role: str, _index: int) -> int:
            if role == "candidate" and campaign == gate.CAMPAIGN_IDS[0]:
                return 2000
            return 1000

        temporary, fixture = self.new_fixture(allocation_delta=one, byte_delta=one)
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "pass")
            self.assertTrue(
                all(metric["regressed_campaigns"] == 1 for metric in report["metrics"].values())
            )

        def two(campaign: str, role: str, _index: int) -> int:
            if role == "candidate" and campaign in gate.CAMPAIGN_IDS[:2]:
                return 1200
            return 1000

        temporary, fixture = self.new_fixture(allocation_delta=two, byte_delta=two)
        with temporary:
            report = fixture.assemble()
            self.assertEqual(report["verdict"], "fail")
            self.assertTrue(
                all(metric["regressed_campaigns"] == 2 for metric in report["metrics"].values())
            )

    def test_evidence_and_report_tamper_are_rejected(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            fixture.assemble()
            evidence = fixture.load_json("EVIDENCE.json")
            evidence["measurement_scope"] = "native-package-runtime"
            fixture.write("EVIDENCE.json", gate._json_wire(evidence))
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "reproduce"):
                gate.validate(
                    contract_path=gate.DEFAULT_CONTRACT,
                    bundle_root=fixture.root,
                    candidate_commit=fixture.candidate,
                    evidence_path=fixture.path("EVIDENCE.json"),
                    report_path=fixture.path("REPORT.json"),
                )

        temporary, fixture = self.new_fixture()
        with temporary:
            fixture.assemble()
            report = fixture.load_json("REPORT.json")
            report["verdict"] = "fail"
            fixture.write("REPORT.json", gate._json_wire(report))
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "reproduce"):
                gate.validate(
                    contract_path=gate.DEFAULT_CONTRACT,
                    bundle_root=fixture.root,
                    candidate_commit=fixture.candidate,
                    evidence_path=fixture.path("EVIDENCE.json"),
                    report_path=fixture.path("REPORT.json"),
                )

    def test_noncanonical_evidence_encoding_is_rejected(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            fixture.assemble()
            evidence = fixture.load_json("EVIDENCE.json")
            fixture.path("EVIDENCE.json").write_text(
                json.dumps(evidence), encoding="utf-8"
            )
            fixture.path("EVIDENCE.json").chmod(0o600)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "encoding"):
                gate.validate(
                    contract_path=gate.DEFAULT_CONTRACT,
                    bundle_root=fixture.root,
                    candidate_commit=fixture.candidate,
                    evidence_path=fixture.path("EVIDENCE.json"),
                    report_path=fixture.path("REPORT.json"),
                )

    def test_raw_unknown_ratio_duplicate_key_and_trailing_json_are_rejected(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            relative = "raw/allocation-campaign-01/baseline-01.json"
            raw = fixture.load_json(relative)
            raw["allocations_per_event"] = 1.0
            fixture.write_json(relative, raw)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "keys"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            relative = "raw/allocation-campaign-01/baseline-01.json"
            wire = fixture.path(relative).read_text(encoding="utf-8")
            fixture.write(relative, (wire.rstrip() + " {}\n").encode())
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "exact JSON"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            relative = "raw/allocation-campaign-01/baseline-01.json"
            fixture.write(relative, b'{"schema_version":1,"schema_version":1}\n')
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "duplicate"):
                fixture.assemble()

    def test_campaign_timestamps_must_be_unique_and_consistent(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            source = fixture.load_json("raw/allocation-campaign-01/baseline-01.json")
            target_relative = "raw/allocation-campaign-02/baseline-01.json"
            target = fixture.load_json(target_relative)
            target["campaign_recorded_at"] = source["campaign_recorded_at"]
            fixture.write_json(target_relative, target)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "differs within"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            first_time = fixture.load_json(
                "raw/allocation-campaign-01/baseline-01.json"
            )["campaign_recorded_at"]
            for role in gate.ROLES:
                for index in range(1, 11):
                    relative = f"raw/allocation-campaign-02/{role}-{index:02d}.json"
                    raw = fixture.load_json(relative)
                    raw["campaign_recorded_at"] = first_time
                    fixture.write_json(relative, raw)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "duplicated"):
                fixture.assemble()

        temporary, fixture = self.new_fixture()
        with temporary:
            for role in gate.ROLES:
                for index in range(1, 11):
                    relative = f"raw/allocation-campaign-02/{role}-{index:02d}.json"
                    raw = fixture.load_json(relative)
                    raw["campaign_recorded_at"] = "2026-09-09T08:00:00Z"
                    fixture.write_json(relative, raw)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "campaign order"):
                fixture.assemble()

    def test_exact_median_and_nearest_rank_p95_are_reported(self) -> None:
        def values(_campaign: str, _role: str, index: int) -> int:
            return index

        temporary, fixture = self.new_fixture(
            allocation_delta=values,
            byte_delta=values,
        )
        with temporary:
            report = fixture.assemble()
            for metric in report["metrics"].values():
                self.assertEqual(
                    metric["baseline"]["median"],
                    {"numerator": "11", "denominator": "4096"},
                )
                self.assertEqual(
                    metric["baseline"]["p95"],
                    {"numerator": "5", "denominator": "1024"},
                )

    def test_output_symlink_and_nonprivate_parent_are_rejected(self) -> None:
        temporary, fixture = self.new_fixture()
        with temporary:
            target = Path(temporary.name) / "operator-data"
            target.write_text("keep\n", encoding="utf-8")
            fixture.path("EVIDENCE.json").symlink_to(target)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "already exists"):
                fixture.assemble()
            self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            with self.assertRaisesRegex(gate.SourceAllocationGateError, "0700"):
                gate.write_new_json(parent / "output.json", {}, "test output")

    def test_build_attestation_module_graph_and_command_are_exact(self) -> None:
        for mutation in ("graph", "command", "reproducible"):
            with self.subTest(mutation=mutation):
                temporary, fixture = self.new_fixture()
                with temporary:
                    build = fixture.load_json("build-attestation.json")
                    if mutation == "graph":
                        build["subjects"]["baseline"]["module_graph"][0]["main"] = False
                    elif mutation == "command":
                        build["build_contract"]["command"].append("-x")
                    else:
                        build["subjects"]["candidate"]["reproducible_build"] = False
                    fixture.write_json("build-attestation.json", build)
                    with self.assertRaises(gate.SourceAllocationGateError):
                        fixture.assemble()


if __name__ == "__main__":
    unittest.main()
