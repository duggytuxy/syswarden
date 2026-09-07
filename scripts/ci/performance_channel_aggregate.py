#!/usr/bin/env python3
"""Bind native-package and source-allocation performance verdicts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    import performance_gate as native_gate
    import source_allocation_gate as allocation_gate
except ModuleNotFoundError:  # Imported as scripts.ci.performance_channel_aggregate.
    from scripts.ci import performance_gate as native_gate
    from scripts.ci import source_allocation_gate as allocation_gate


REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_NATIVE_CONTRACT = REPOSITORY / "scripts" / "ci" / "performance_contract_v4.10.0.json"
DEFAULT_ALLOCATION_CONTRACT = REPOSITORY / "scripts" / "ci" / "source_allocation_contract_v4.10.0.json"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 16 * 1024 * 1024


class PerformanceAggregateError(ValueError):
    """Raised when either mandatory performance channel is invalid."""


def _read_json(
    path: Path, label: str, *, allowed_modes: set[int]
) -> tuple[dict[str, Any], bytes]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PerformanceAggregateError(f"{label} must be one regular non-symlink file")
    if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) not in allowed_modes:
        raise PerformanceAggregateError(f"{label} owner or mode is unsafe")
    if before.st_size <= 0 or before.st_size > MAX_JSON_BYTES:
        raise PerformanceAggregateError(f"{label} size is outside the accepted bound")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        initial = (
            opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid,
            opened.st_nlink, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
        )
        if initial[:6] != (
            before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink,
        ):
            raise PerformanceAggregateError(f"{label} identity changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_JSON_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise PerformanceAggregateError(f"{label} exceeded the accepted bound")
        after = os.fstat(descriptor)
        final = (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
            after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        )
        if final != initial or total != opened.st_size:
            raise PerformanceAggregateError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PerformanceAggregateError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(token: str) -> None:
        raise PerformanceAggregateError(f"{label} contains non-finite number {token}")

    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PerformanceAggregateError(f"{label} is invalid JSON") from exc
    if not isinstance(document, dict):
        raise PerformanceAggregateError(f"{label} must be one JSON object")
    return document, raw


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PerformanceAggregateError(f"{label} keys are not exact")
    return value


def _write_new(path: Path, document: dict[str, Any]) -> None:
    parent = path.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise PerformanceAggregateError("aggregate output parent must be an owner-controlled 0700 directory")
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PerformanceAggregateError("short write while creating aggregate")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def aggregate(
    native_contract: dict[str, Any],
    native_contract_raw: bytes,
    allocation_contract: dict[str, Any],
    allocation_contract_raw: bytes,
    native_evidence: dict[str, Any],
    native_evidence_raw: bytes,
    native_report: dict[str, Any],
    native_report_raw: bytes,
    allocation_evidence: dict[str, Any],
    allocation_evidence_raw: bytes,
    allocation_report: dict[str, Any],
    allocation_report_raw: bytes,
    candidate_commit: str,
    native_bindings: dict[str, str],
) -> dict[str, Any]:
    if SHA_PATTERN.fullmatch(candidate_commit) is None:
        raise PerformanceAggregateError("candidate commit is not canonical")
    _exact(
        native_contract,
        {
            "schema_version", "contract_id", "target_release", "baseline_release",
            "baseline_commit", "minimum_campaigns", "stable_regression_percent",
            "metrics",
        },
        "native performance contract",
    )
    _exact(
        allocation_contract,
        {
            "schema_version", "schema_id", "repository", "target_release",
            "baseline_release", "baseline_commit", "architecture", "kernel_machine",
            "toolchain_version", "toolchain_archive_sha256", "workload", "schemas",
            "campaigns", "samples_per_subject_per_campaign", "stable_regression",
            "metrics",
        },
        "source allocation contract",
    )
    native_metrics = native_contract.get("metrics")
    if not isinstance(native_metrics, dict) or not native_metrics:
        raise PerformanceAggregateError("native performance contract metric inventory is invalid")
    if "allocations_per_event" in native_metrics:
        raise PerformanceAggregateError("native performance contract still claims unobservable allocations_per_event")
    source_metrics = allocation_contract.get("metrics")
    if not isinstance(source_metrics, dict) or set(source_metrics) != {
        "waap_detection_allocations_per_admitted_event",
        "waap_detection_allocated_bytes_per_admitted_event",
    }:
        raise PerformanceAggregateError("source allocation contract metric inventory is invalid")
    if allocation_contract.get("schemas", {}).get("aggregate") != "syswarden-performance-aggregate/v1":
        raise PerformanceAggregateError("source allocation aggregate schema binding is invalid")

    metric_contracts: dict[str, native_gate.MetricContract] = {}
    for name, raw_metric in native_metrics.items():
        metric = _exact(
            raw_metric,
            {"unit", "direction", "minimum_samples"},
            f"native contract metric {name}",
        )
        metric_contracts[name] = native_gate.MetricContract(
            unit=metric["unit"],
            direction=metric["direction"],
            minimum_samples=metric["minimum_samples"],
        )
    try:
        expected_native_report = native_gate.evaluate(
            native_evidence,
            native_contract,
            metric_contracts,
            {},
            candidate_commit,
            **native_bindings,
        )
    except (KeyError, TypeError, ValueError, native_gate.PerformanceGateError) as exc:
        raise PerformanceAggregateError(
            f"native performance evidence is invalid: {exc}"
        ) from exc
    if native_report != expected_native_report:
        raise PerformanceAggregateError(
            "native performance report does not reproduce exactly from its evidence"
        )
    if native_evidence.get("baseline_commit") != allocation_contract["baseline_commit"] or native_report.get("baseline_commit") != allocation_contract["baseline_commit"]:
        raise PerformanceAggregateError("native channel baseline binding is invalid")
    if native_report.get("verdict") != "pass" or native_report.get("failed_metrics") != []:
        raise PerformanceAggregateError("native performance channel is not passing")
    if not isinstance(native_report.get("metrics"), dict) or set(native_report["metrics"]) != set(native_metrics):
        raise PerformanceAggregateError("native report metric inventory is not exact")
    if not isinstance(native_evidence.get("metrics"), dict) or set(native_evidence["metrics"]) != set(native_metrics):
        raise PerformanceAggregateError("native evidence metric inventory is not exact")

    _exact(
        allocation_evidence,
        {
            "schema_version", "schema_id", "repository", "target_release",
            "candidate_commit", "baseline_release", "baseline_commit",
            "measurement_scope", "native_package_runtime_measurement", "bindings",
            "subjects", "campaigns", "raw_inventory", "metrics",
        },
        "allocation evidence",
    )
    for document, label in ((allocation_evidence, "allocation evidence"), (allocation_report, "allocation report")):
        if document.get("candidate_commit") != candidate_commit or document.get("target_release") != "v4.10.0":
            raise PerformanceAggregateError(f"{label} candidate binding is invalid")
        if document.get("baseline_commit") != allocation_contract["baseline_commit"]:
            raise PerformanceAggregateError(f"{label} baseline binding is invalid")
        if document.get("measurement_scope") != "deterministic-source-bound-waap-engine-scan" or document.get("native_package_runtime_measurement") is not False:
            raise PerformanceAggregateError(f"{label} scope is invalid")
    if allocation_evidence.get("schema_id") != "syswarden-allocation-evidence/v1" or allocation_report.get("schema_id") != "syswarden-allocation-report/v1":
        raise PerformanceAggregateError("allocation schema ID is invalid")
    allocation_evidence_sha = hashlib.sha256(allocation_evidence_raw).hexdigest()
    if allocation_report.get("evidence_sha256") != allocation_evidence_sha:
        raise PerformanceAggregateError("allocation report does not bind the exact evidence bytes")
    try:
        expected_allocation_report = allocation_gate.build_report(
            contract=allocation_contract,
            candidate_commit=candidate_commit,
            evidence=allocation_evidence,
            evidence_sha256=allocation_evidence_sha,
        )
    except (KeyError, TypeError, ValueError, allocation_gate.SourceAllocationGateError) as exc:
        raise PerformanceAggregateError(
            f"source allocation evidence is invalid: {exc}"
        ) from exc
    if allocation_report != expected_allocation_report:
        raise PerformanceAggregateError(
            "source allocation report does not reproduce exactly from its evidence"
        )
    if allocation_report.get("verdict") != "pass" or allocation_report.get("failed_metrics") != []:
        raise PerformanceAggregateError("source allocation channel is not passing")
    if not isinstance(allocation_report.get("metrics"), dict) or set(allocation_report["metrics"]) != set(source_metrics):
        raise PerformanceAggregateError("allocation report metric inventory is not exact")
    if not isinstance(allocation_evidence.get("metrics"), dict) or set(allocation_evidence["metrics"]) != set(source_metrics):
        raise PerformanceAggregateError("allocation evidence metric inventory is not exact")

    return {
        "schema_version": 1,
        "schema_id": "syswarden-performance-aggregate/v1",
        "repository": "duggytuxy/syswarden",
        "target_release": "v4.10.0",
        "candidate_commit": candidate_commit,
        "baseline_release": allocation_contract["baseline_release"],
        "baseline_commit": allocation_contract["baseline_commit"],
        "channels_independent": True,
        "neither_channel_substitutes_for_other": True,
        "channels": {
            "native_package": {
                "measurement_scope": "installed-package-runtime",
                "native_package_runtime_measurement": True,
                "contract_sha256": hashlib.sha256(native_contract_raw).hexdigest(),
                "evidence_sha256": hashlib.sha256(native_evidence_raw).hexdigest(),
                "report_sha256": hashlib.sha256(native_report_raw).hexdigest(),
                "metrics": sorted(native_metrics),
                "verdict": "pass",
            },
            "source_bound_allocations": {
                "measurement_scope": "deterministic-source-bound-waap-engine-scan",
                "native_package_runtime_measurement": False,
                "contract_sha256": hashlib.sha256(allocation_contract_raw).hexdigest(),
                "evidence_sha256": allocation_evidence_sha,
                "report_sha256": hashlib.sha256(allocation_report_raw).hexdigest(),
                "metrics": sorted(source_metrics),
                "verdict": "pass",
            },
        },
        "verdict": "pass",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-contract", type=Path, default=DEFAULT_NATIVE_CONTRACT)
    parser.add_argument("--allocation-contract", type=Path, default=DEFAULT_ALLOCATION_CONTRACT)
    parser.add_argument("--native-evidence", type=Path, required=True)
    parser.add_argument("--native-report", type=Path, required=True)
    parser.add_argument("--allocation-evidence", type=Path, required=True)
    parser.add_argument("--allocation-report", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--adapter-config", type=Path, required=True)
    parser.add_argument("--native-lifecycle-verdict", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        native_contract, native_contract_raw = _read_json(
            args.native_contract, "native contract", allowed_modes={0o600, 0o644}
        )
        allocation_contract, allocation_contract_raw = _read_json(
            args.allocation_contract, "allocation contract", allowed_modes={0o600, 0o644}
        )
        validated_native_contract, _ = native_gate.load_contract(args.native_contract)
        validated_allocation_contract = allocation_gate.load_contract(
            args.allocation_contract
        )
        if validated_native_contract != native_contract:
            raise PerformanceAggregateError(
                "native performance contract changed between validation and aggregation"
            )
        if validated_allocation_contract != allocation_contract:
            raise PerformanceAggregateError(
                "source allocation contract changed between validation and aggregation"
            )
        native_evidence, native_evidence_raw = _read_json(
            args.native_evidence, "native evidence", allowed_modes={0o600}
        )
        native_report, native_report_raw = _read_json(
            args.native_report, "native report", allowed_modes={0o600}
        )
        allocation_evidence, allocation_evidence_raw = _read_json(
            args.allocation_evidence, "allocation evidence", allowed_modes={0o600}
        )
        allocation_report, allocation_report_raw = _read_json(
            args.allocation_report, "allocation report", allowed_modes={0o600}
        )
        native_bindings = native_gate.reviewed_bindings(
            args.adapter_config,
            args.native_lifecycle_verdict,
            args.candidate_commit,
            native_contract,
        )
        result = aggregate(
            native_contract, native_contract_raw,
            allocation_contract, allocation_contract_raw,
            native_evidence, native_evidence_raw, native_report, native_report_raw,
            allocation_evidence, allocation_evidence_raw, allocation_report, allocation_report_raw,
            args.candidate_commit,
            native_bindings,
        )
        _write_new(args.output, result)
        print("Performance aggregate pass: native package and source allocation channels are independently passing.")
        return 0
    except (
        OSError,
        PerformanceAggregateError,
        native_gate.PerformanceGateError,
        native_gate.native_adapter.NativePerformanceAdapterError,
        allocation_gate.SourceAllocationGateError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
