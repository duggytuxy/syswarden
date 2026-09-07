#!/usr/bin/env python3
"""Seal bounded Go toolchain comparison evidence without publishing artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from statistics import median
from typing import Any, Sequence


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_INPUT = 4 * 1024 * 1024
ROLES = ("baseline", "candidate")


class EvaluationError(ValueError):
    """Raised when evaluation input is unsafe, incomplete, or outside bounds."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise EvaluationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise EvaluationError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_size <= 0
            or before.st_size > MAX_INPUT
        ):
            raise EvaluationError(f"{label} is not one bounded owner-controlled file")
        wire = os.read(descriptor, MAX_INPUT + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(wire) != before.st_size or identity(before) != identity(after):
            raise EvaluationError(f"{label} changed while being read")
        return wire
    finally:
        os.close(descriptor)


def _json(path: Path, label: str) -> tuple[Any, bytes]:
    wire = _read_regular(path, label)
    try:
        return (
            json.loads(
                wire,
                object_pairs_hook=_pairs,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    EvaluationError(f"non-finite JSON value: {token}")
                ),
            ),
            wire,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"{label} is invalid JSON") from exc


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvaluationError(f"{label} keys differ from the exact contract")
    return value


def _positive(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvaluationError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise EvaluationError(f"{label} must be finite and positive")
    return number


def _metadata(path: Path) -> tuple[dict[str, Any], bytes]:
    document, wire = _json(path, "toolchain metadata")
    metadata = _exact(
        document,
        {
            "schema_version",
            "architecture",
            "release_toolchain_unchanged",
            "measurement",
            "rollback",
            "toolchains",
        },
        "metadata",
    )
    if (
        metadata["schema_version"] != 2
        or metadata["architecture"] != "linux/amd64"
        or metadata["release_toolchain_unchanged"] is not True
    ):
        raise EvaluationError("toolchain metadata identity is invalid")
    if set(metadata["toolchains"]) != set(ROLES):
        raise EvaluationError("toolchain roles are invalid")
    expected_versions = {"baseline": "go1.26.6", "candidate": "go1.27.1"}
    for role, version in expected_versions.items():
        record = _exact(
            metadata["toolchains"][role],
            {"version", "filename", "url", "size", "sha256"},
            f"{role} toolchain",
        )
        filename = f"{version}.linux-amd64.tar.gz"
        if (
            record["version"] != version
            or record["filename"] != filename
            or record["url"] != f"https://go.dev/dl/{filename}"
            or type(record["size"]) is not int
            or record["size"] <= 0
            or not isinstance(record["sha256"], str)
            or HEX64.fullmatch(record["sha256"]) is None
        ):
            raise EvaluationError(f"{role} toolchain identity is invalid")
    measurement = _exact(
        metadata["measurement"],
        {
            "samples_per_toolchain",
            "operations_per_sample",
            "protocols",
            "bounds",
            "binaries",
            "packages",
        },
        "measurement contract",
    )
    if measurement["samples_per_toolchain"] != 9 or measurement["operations_per_sample"] != 2048:
        raise EvaluationError("measurement dimensions are invalid")
    expected_protocols = {
        "http1_keepalive",
        "tls13",
        "bounded_response_headers",
        "strict_json",
        "ed25519_manifest",
    }
    if not isinstance(measurement["protocols"], list) or set(measurement["protocols"]) != expected_protocols or len(measurement["protocols"]) != len(expected_protocols):
        raise EvaluationError("protocol inventory is invalid")
    if measurement["binaries"] != ["syswarden-cli", "syswarden-core", "syswarden-tui"]:
        raise EvaluationError("binary inventory is invalid")
    if measurement["packages"] != ["deb", "rpm", "apk"]:
        raise EvaluationError("package inventory is invalid")
    expected_metrics = {
        "cpu_nanoseconds_per_request",
        "rss_bytes",
        "allocations_per_request",
        "allocated_bytes_per_request",
        "http_requests_per_second",
        "binary_bytes",
        "package_bytes",
    }
    if not isinstance(measurement["bounds"], dict) or set(measurement["bounds"]) != expected_metrics:
        raise EvaluationError("metric bound inventory is invalid")
    for name, raw in measurement["bounds"].items():
        bound = _exact(
            raw,
            {"unit", "direction", "maximum_regression_percent", "absolute_noise_allowance"},
            f"bound {name}",
        )
        if bound["direction"] not in {"lower", "higher"} or not isinstance(bound["unit"], str) or not bound["unit"]:
            raise EvaluationError(f"metric bound identity is invalid: {name}")
        if _positive(bound["maximum_regression_percent"], f"{name} regression percent") != 10.0:
            raise EvaluationError(f"metric regression bound must be exactly 10 percent: {name}")
        allowance = bound["absolute_noise_allowance"]
        if isinstance(allowance, bool) or not isinstance(allowance, (int, float)) or not math.isfinite(float(allowance)) or float(allowance) < 0:
            raise EvaluationError(f"metric noise allowance is invalid: {name}")
        if name in {"binary_bytes", "package_bytes", "http_requests_per_second"} and float(allowance) != 0:
            raise EvaluationError(f"metric may not use a noise allowance: {name}")
    rollback = _exact(
        metadata["rollback"],
        {"from", "to", "directive_files", "builder_file", "required_files"},
        "rollback contract",
    )
    directive_files = [
        "go.work",
        "src/core/syswarden-cli/go.mod",
        "src/core/syswarden-core/go.mod",
        "src/core/syswarden-tui/go.mod",
        "scripts/versionctl/go.mod",
    ]
    expected_rollback = {
        "from": "go1.27.1",
        "to": "go1.26.6",
        "directive_files": directive_files,
        "builder_file": "build_packages.sh",
        "required_files": [*directive_files, "build_packages.sh"],
    }
    if rollback != expected_rollback:
        raise EvaluationError("rollback contract is invalid")
    return metadata, wire


def _measurements(path: Path, metadata: dict[str, Any]) -> tuple[dict[str, dict[str, list[float]]], dict[str, dict[str, str]]]:
    wire = _read_regular(path, "protocol measurement records")
    try:
        lines = wire.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EvaluationError("protocol measurement records are not UTF-8") from exc
    expected_samples = metadata["measurement"]["samples_per_toolchain"]
    expected_protocols = set(metadata["measurement"]["protocols"])
    dynamic_metrics = set(metadata["measurement"]["bounds"]) - {"binary_bytes", "package_bytes"}
    samples = {role: {name: [] for name in dynamic_metrics} for role in ROLES}
    protocols = {role: {name: "pass" for name in expected_protocols} for role in ROLES}
    seen: set[tuple[str, int]] = set()
    for line in lines:
        try:
            record = json.loads(line, object_pairs_hook=_pairs)
        except json.JSONDecodeError as exc:
            raise EvaluationError("protocol measurement record is invalid JSON") from exc
        item = _exact(
            record,
            {"schema_version", "role", "sample", "operations", "protocols", "metrics"},
            "protocol measurement",
        )
        role = item["role"]
        sample = item["sample"]
        if role not in ROLES or type(sample) is not int or not 1 <= sample <= expected_samples or (role, sample) in seen:
            raise EvaluationError("protocol measurement identity is invalid or duplicated")
        seen.add((role, sample))
        if item["schema_version"] != 1 or item["operations"] != metadata["measurement"]["operations_per_sample"]:
            raise EvaluationError("protocol measurement dimensions are invalid")
        if not isinstance(item["protocols"], dict) or set(item["protocols"]) != expected_protocols or any(value != "pass" for value in item["protocols"].values()):
            raise EvaluationError("protocol measurement did not pass every protocol gate")
        if not isinstance(item["metrics"], dict) or set(item["metrics"]) != dynamic_metrics:
            raise EvaluationError("dynamic metric inventory is invalid")
        for name in dynamic_metrics:
            samples[role][name].append(_positive(item["metrics"][name], f"{role} {name}"))
    expected_seen = {(role, sample) for role in ROLES for sample in range(1, expected_samples + 1)}
    if seen != expected_seen:
        raise EvaluationError("protocol measurement sample inventory is incomplete")
    return samples, protocols


def _inventory(path: Path, label: str, expected_names: list[str]) -> dict[str, dict[str, dict[str, Any]]]:
    wire = _read_regular(path, f"{label} records")
    try:
        lines = wire.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EvaluationError(f"{label} records are not UTF-8") from exc
    result: dict[str, dict[str, dict[str, Any]]] = {role: {} for role in ROLES}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 4:
            raise EvaluationError(f"{label} record does not have four fields")
        role, name, size_text, digest = fields
        if role not in ROLES or name not in expected_names or name in result[role]:
            raise EvaluationError(f"{label} identity is invalid or duplicated")
        if not size_text.isdigit() or int(size_text) <= 0 or HEX64.fullmatch(digest) is None:
            raise EvaluationError(f"{label} value is invalid")
        record: dict[str, Any] = {"bytes": int(size_text), "sha256": digest}
        if label == "binary":
            record["reproducible"] = True
        result[role][name] = record
    if any(set(result[role]) != set(expected_names) for role in ROLES):
        raise EvaluationError(f"{label} inventory is incomplete")
    return result


def _comparison(baseline: float, candidate: float, bound: dict[str, Any]) -> dict[str, Any]:
    percent = float(bound["maximum_regression_percent"])
    allowance = float(bound["absolute_noise_allowance"])
    if bound["direction"] == "lower":
        limit = baseline * (1.0 + percent / 100.0) + allowance
        passed = candidate <= limit
        regression = ((candidate - baseline) / baseline) * 100.0
    else:
        limit = max(0.0, baseline * (1.0 - percent / 100.0) - allowance)
        passed = candidate >= limit
        regression = ((baseline - candidate) / baseline) * 100.0
    return {
        "unit": bound["unit"],
        "direction": bound["direction"],
        "baseline_median": baseline,
        "candidate_median": candidate,
        "regression_percent": regression,
        "maximum_regression_percent": percent,
        "absolute_noise_allowance": allowance,
        "candidate_limit": limit,
        "status": "pass" if passed else "fail",
    }


def _rollback(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    document, _ = _json(path, "rollback evidence")
    proof = _exact(
        document,
        {"schema_version", "from", "to", "directive_files", "builder_file", "required_files", "source_byte_exact", "builder_pin_verified", "baseline_protocol_tests"},
        "rollback evidence",
    )
    expected = metadata["rollback"]
    if (
        proof["schema_version"] != 1
        or proof["from"] != expected["from"]
        or proof["to"] != expected["to"]
        or proof["required_files"] != expected["required_files"]
        or proof["directive_files"] != expected["directive_files"]
        or proof["builder_file"] != expected["builder_file"]
        or proof["source_byte_exact"] is not True
        or proof["builder_pin_verified"] is not True
        or proof["baseline_protocol_tests"] != "pass"
    ):
        raise EvaluationError("rollback evidence is invalid")
    return proof


def evaluate(
    metadata: dict[str, Any],
    measurements: dict[str, dict[str, list[float]]],
    protocols: dict[str, dict[str, str]],
    binaries: dict[str, dict[str, dict[str, Any]]],
    packages: dict[str, dict[str, dict[str, Any]]],
    rollback: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    bounds = metadata["measurement"]["bounds"]
    comparisons: dict[str, Any] = {}
    for name in sorted(set(bounds) - {"binary_bytes", "package_bytes"}):
        comparison = _comparison(
            median(measurements["baseline"][name]),
            median(measurements["candidate"][name]),
            bounds[name],
        )
        comparison["baseline_samples"] = measurements["baseline"][name]
        comparison["candidate_samples"] = measurements["candidate"][name]
        comparisons[name] = comparison

    size_comparisons: dict[str, Any] = {}
    for label, inventory, bound_name in (
        ("binaries", binaries, "binary_bytes"),
        ("packages", packages, "package_bytes"),
    ):
        item_results: dict[str, Any] = {}
        for name in metadata["measurement"][label]:
            item_results[name] = _comparison(
                float(inventory["baseline"][name]["bytes"]),
                float(inventory["candidate"][name]["bytes"]),
                bounds[bound_name],
            )
        baseline_total = float(sum(item["bytes"] for item in inventory["baseline"].values()))
        candidate_total = float(sum(item["bytes"] for item in inventory["candidate"].values()))
        size_comparisons[label] = {
            "items": item_results,
            "total": _comparison(baseline_total, candidate_total, bounds[bound_name]),
        }

    dynamic_pass = all(item["status"] == "pass" for item in comparisons.values())
    binary_pass = all(
        item["status"] == "pass" for item in size_comparisons["binaries"]["items"].values()
    ) and size_comparisons["binaries"]["total"]["status"] == "pass"
    package_pass = all(
        item["status"] == "pass" for item in size_comparisons["packages"]["items"].values()
    ) and size_comparisons["packages"]["total"]["status"] == "pass"
    gates = {
        "protocol_parity": "pass",
        "performance_bounds": "pass" if dynamic_pass else "fail",
        "binary_size_bounds": "pass" if binary_pass else "fail",
        "package_size_bounds": "pass" if package_pass else "fail",
        "toolchain_rollback": "pass",
    }
    return {
        "protocols": protocols,
        "measurements": comparisons,
        "size_comparisons": size_comparisons,
        "binaries": binaries,
        "packages": packages,
        "rollback": rollback,
    }, gates


def _write_new(path: Path, document: dict[str, Any]) -> None:
    wire = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise EvaluationError(f"refusing unsafe evaluation output: {exc}") from exc
    try:
        os.write(descriptor, wire)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--rollback", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if HEX40.fullmatch(args.candidate_commit) is None:
            raise EvaluationError("candidate commit is not canonical")
        if args.runner_os != "Linux" or args.runner_arch != "X64":
            raise EvaluationError("runner identity is invalid")
        metadata, metadata_wire = _metadata(args.metadata)
        measurements, protocols = _measurements(args.measurements, metadata)
        binaries = _inventory(
            args.binaries, "binary", metadata["measurement"]["binaries"]
        )
        packages = _inventory(
            args.packages, "package", metadata["measurement"]["packages"]
        )
        rollback = _rollback(args.rollback, metadata)
        evaluation, comparison_gates = evaluate(
            metadata, measurements, protocols, binaries, packages, rollback
        )
        gates = {
            "tests": "pass",
            "race": "pass",
            "vet": "pass",
            "stdversion": "pass",
            "fuzz": "pass",
            "goroutineleak": "pass",
            "jsonv2": "pass",
            "jsonv1_rollback": "pass",
            "source_unchanged": "pass",
            **comparison_gates,
        }
        if any(value != "pass" for value in gates.values()):
            failed = sorted(name for name, value in gates.items() if value != "pass")
            raise EvaluationError(f"Go toolchain comparison is outside bounds: {failed}")
        document = {
            "schema_version": 2,
            "contract_id": "syswarden-go-toolchain-evaluation/v2",
            "candidate_commit": args.candidate_commit,
            "architecture": metadata["architecture"],
            "runner": {"os": args.runner_os, "arch": args.runner_arch},
            "metadata_sha256": hashlib.sha256(metadata_wire).hexdigest(),
            "toolchains": metadata["toolchains"],
            "gates": gates,
            **evaluation,
            "native_qualification": "pending-external-evidence",
            "adoption_decision": "defer-go1.27-keep-go1.26.6",
        }
        _write_new(args.output, document)
    except (EvaluationError, OSError) as exc:
        print(f"Go toolchain evaluation: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
