#!/usr/bin/env python3
"""Validate Go 1.27 evaluation evidence and emit an explicit release decision."""

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


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON = 128 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def load(path: Path, label: str) -> tuple[dict, bytes]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or before.st_size <= 0 or before.st_size > MAX_JSON:
            fail(f"{label} must be one bounded owner-controlled regular file")
        raw = os.read(descriptor, MAX_JSON + 1)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after):
            fail(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                fail(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is invalid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value, raw


def exact(value: dict, keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} keys differ from the exact contract")


def positive(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        fail(f"{label} must be finite and positive")
    return number


def close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-9)


def validate_comparison(
    record: object,
    bound: dict,
    label: str,
    baseline_samples: list[float] | None = None,
    candidate_samples: list[float] | None = None,
) -> None:
    if not isinstance(record, dict):
        fail(f"{label} comparison must be an object")
    expected_keys = {
        "unit", "direction", "baseline_median", "candidate_median",
        "regression_percent", "maximum_regression_percent",
        "absolute_noise_allowance", "candidate_limit", "status",
    }
    if baseline_samples is not None or candidate_samples is not None:
        expected_keys |= {"baseline_samples", "candidate_samples"}
    exact(record, expected_keys, f"{label} comparison")
    if record["unit"] != bound["unit"] or record["direction"] != bound["direction"]:
        fail(f"{label} comparison identity is invalid")
    if (
        positive(record["maximum_regression_percent"], f"{label} percent") != 10.0
        or record["maximum_regression_percent"] != bound["maximum_regression_percent"]
        or record["absolute_noise_allowance"] != bound["absolute_noise_allowance"]
    ):
        fail(f"{label} comparison bound is invalid")
    if baseline_samples is None:
        baseline = positive(record["baseline_median"], f"{label} baseline")
        candidate = positive(record["candidate_median"], f"{label} candidate")
    else:
        if record["baseline_samples"] != baseline_samples or record["candidate_samples"] != candidate_samples:
            fail(f"{label} comparison samples are invalid")
        baseline = median(baseline_samples)
        candidate = median(candidate_samples)
        if not close(float(record["baseline_median"]), baseline) or not close(float(record["candidate_median"]), candidate):
            fail(f"{label} comparison medians are invalid")
    percent = float(bound["maximum_regression_percent"])
    allowance = float(bound["absolute_noise_allowance"])
    if bound["direction"] == "lower":
        expected_limit = baseline * (1.0 + percent / 100.0) + allowance
        expected_regression = ((candidate - baseline) / baseline) * 100.0
        expected_status = "pass" if candidate <= expected_limit else "fail"
    else:
        expected_limit = max(0.0, baseline * (1.0 - percent / 100.0) - allowance)
        expected_regression = ((baseline - candidate) / baseline) * 100.0
        expected_status = "pass" if candidate >= expected_limit else "fail"
    if (
        not close(float(record["candidate_limit"]), expected_limit)
        or not close(float(record["regression_percent"]), expected_regression)
        or record["status"] != expected_status
    ):
        fail(f"{label} comparison calculation is invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--pinned-toolchain", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.release_tag != "v4.10.0" or not HEX40.fullmatch(args.release_sha):
        fail("release identity is invalid")
    if args.repository != "duggytuxy/syswarden" or args.run_id <= 0 or args.artifact_id <= 0:
        fail("workflow provenance is invalid")
    expected_name = f"syswarden-go127-evaluation-{args.release_sha}"
    if args.artifact_name != expected_name or not DIGEST.fullmatch(args.artifact_digest):
        fail("artifact identity is invalid")
    metadata, metadata_raw = load(args.metadata, "toolchain metadata")
    exact(metadata, {"schema_version", "architecture", "release_toolchain_unchanged", "measurement", "rollback", "toolchains"}, "metadata")
    if metadata["schema_version"] != 2 or metadata["architecture"] != "linux/amd64" or metadata["release_toolchain_unchanged"] is not True:
        fail("toolchain metadata identity is invalid")
    if set(metadata["toolchains"]) != {"baseline", "candidate"}:
        fail("toolchain metadata roles are invalid")
    expected_versions = {"baseline": "go1.26.6", "candidate": "go1.27.1"}
    for role, version in expected_versions.items():
        record = metadata["toolchains"][role]
        exact(record, {"version", "filename", "url", "size", "sha256"}, f"metadata {role}")
        filename = f"{version}.linux-amd64.tar.gz"
        if record["version"] != version or record["filename"] != filename or record["url"] != f"https://go.dev/dl/{filename}" or type(record["size"]) is not int or record["size"] <= 0 or not HEX64.fullmatch(record["sha256"]):
            fail(f"metadata {role} identity is invalid")
    measurement = metadata["measurement"]
    exact(measurement, {"samples_per_toolchain", "operations_per_sample", "protocols", "bounds", "binaries", "packages"}, "measurement metadata")
    if measurement["samples_per_toolchain"] != 9 or measurement["operations_per_sample"] != 2048:
        fail("measurement dimensions are invalid")
    expected_protocols = {"http1_keepalive", "tls13", "bounded_response_headers", "strict_json", "ed25519_manifest"}
    expected_metrics = {"cpu_nanoseconds_per_request", "rss_bytes", "allocations_per_request", "allocated_bytes_per_request", "http_requests_per_second", "binary_bytes", "package_bytes"}
    if not isinstance(measurement["protocols"], list) or set(measurement["protocols"]) != expected_protocols or len(measurement["protocols"]) != len(expected_protocols):
        fail("protocol metadata is invalid")
    if measurement["binaries"] != ["syswarden-cli", "syswarden-core", "syswarden-tui"] or measurement["packages"] != ["deb", "rpm", "apk"]:
        fail("artifact metadata inventory is invalid")
    if not isinstance(measurement["bounds"], dict) or set(measurement["bounds"]) != expected_metrics:
        fail("metric metadata inventory is invalid")
    for name, bound in measurement["bounds"].items():
        exact(bound, {"unit", "direction", "maximum_regression_percent", "absolute_noise_allowance"}, f"metadata bound {name}")
        if bound["direction"] not in {"lower", "higher"} or not isinstance(bound["unit"], str) or not bound["unit"] or positive(bound["maximum_regression_percent"], f"metadata bound {name}") != 10.0:
            fail(f"metadata bound {name} is invalid")
        allowance = bound["absolute_noise_allowance"]
        if isinstance(allowance, bool) or not isinstance(allowance, (int, float)) or not math.isfinite(float(allowance)) or float(allowance) < 0:
            fail(f"metadata allowance {name} is invalid")
    exact(metadata["rollback"], {"from", "to", "directive_files", "builder_file", "required_files"}, "rollback metadata")
    if (
        metadata["rollback"]["from"] != "go1.27.1"
        or metadata["rollback"]["to"] != "go1.26.6"
        or len(metadata["rollback"]["directive_files"]) != 5
        or metadata["rollback"]["builder_file"] != "build_packages.sh"
        or metadata["rollback"]["required_files"] != [*metadata["rollback"]["directive_files"], "build_packages.sh"]
    ):
        fail("rollback metadata is invalid")
    evidence, evidence_raw = load(args.evidence, "evaluation evidence")
    exact(evidence, {"schema_version", "contract_id", "candidate_commit", "architecture", "runner", "metadata_sha256", "toolchains", "gates", "protocols", "measurements", "size_comparisons", "binaries", "packages", "rollback", "native_qualification", "adoption_decision"}, "evidence")
    if evidence["schema_version"] != 2 or evidence["contract_id"] != "syswarden-go-toolchain-evaluation/v2" or evidence["candidate_commit"] != args.release_sha:
        fail("evaluation release binding is invalid")
    if evidence["architecture"] != "linux/amd64" or evidence["runner"] != {"os": "Linux", "arch": "X64"}:
        fail("evaluation runner identity is invalid")
    if evidence["metadata_sha256"] != hashlib.sha256(metadata_raw).hexdigest() or evidence["toolchains"] != metadata["toolchains"]:
        fail("evaluation metadata binding is invalid")
    expected_gates = {name: "pass" for name in ("tests", "race", "vet", "stdversion", "fuzz", "goroutineleak", "jsonv2", "jsonv1_rollback", "source_unchanged", "protocol_parity", "performance_bounds", "binary_size_bounds", "package_size_bounds", "toolchain_rollback")}
    if (
        evidence["gates"] != expected_gates
        or evidence["native_qualification"] != "pending-external-evidence"
        or evidence["adoption_decision"] != "defer-go1.27-keep-go1.26.6"
    ):
        fail("evaluation gates or preliminary decision are invalid")
    if evidence["protocols"] != {
        role: {name: "pass" for name in metadata["measurement"]["protocols"]}
        for role in ("baseline", "candidate")
    }:
        fail("protocol evidence is invalid")
    dynamic_metrics = set(measurement["bounds"]) - {"binary_bytes", "package_bytes"}
    if not isinstance(evidence["measurements"], dict) or set(evidence["measurements"]) != dynamic_metrics:
        fail("performance evidence inventory is invalid")
    for name in dynamic_metrics:
        record = evidence["measurements"][name]
        if not isinstance(record, dict):
            fail("performance evidence is invalid")
        baseline_samples = record.get("baseline_samples")
        candidate_samples = record.get("candidate_samples")
        if (
            not isinstance(baseline_samples, list)
            or not isinstance(candidate_samples, list)
            or len(baseline_samples) != 9
            or len(candidate_samples) != 9
        ):
            fail("performance sample count is invalid")
        baseline_values = [positive(value, f"{name} baseline sample") for value in baseline_samples]
        candidate_values = [positive(value, f"{name} candidate sample") for value in candidate_samples]
        validate_comparison(record, measurement["bounds"][name], name, baseline_values, candidate_values)
    if set(evidence["binaries"]) != {"baseline", "candidate"}:
        fail("binary roles are invalid")
    for role in ("baseline", "candidate"):
        if set(evidence["binaries"][role]) != {"syswarden-cli", "syswarden-core", "syswarden-tui"}:
            fail("binary inventory is incomplete")
        for record in evidence["binaries"][role].values():
            if set(record) != {"bytes", "sha256", "reproducible"} or type(record["bytes"]) is not int or record["bytes"] <= 0 or not HEX64.fullmatch(record["sha256"]) or record["reproducible"] is not True:
                fail("binary evidence is invalid")
    if set(evidence["packages"]) != {"baseline", "candidate"}:
        fail("package roles are invalid")
    for role in ("baseline", "candidate"):
        if set(evidence["packages"][role]) != {"deb", "rpm", "apk"}:
            fail("package inventory is incomplete")
        for record in evidence["packages"][role].values():
            if set(record) != {"bytes", "sha256"} or type(record["bytes"]) is not int or record["bytes"] <= 0 or not HEX64.fullmatch(record["sha256"]):
                fail("package evidence is invalid")
    if not isinstance(evidence["size_comparisons"], dict) or set(evidence["size_comparisons"]) != {"binaries", "packages"}:
        fail("size comparison inventory is invalid")
    for group_name, inventory, bound_name in (
        ("binaries", evidence["binaries"], "binary_bytes"),
        ("packages", evidence["packages"], "package_bytes"),
    ):
        group = evidence["size_comparisons"][group_name]
        if not isinstance(group, dict) or set(group) != {"items", "total"} or set(group["items"]) != set(inventory["baseline"]):
            fail(f"{group_name} size comparison inventory is invalid")
        for name in inventory["baseline"]:
            expected_baseline = float(inventory["baseline"][name]["bytes"])
            expected_candidate = float(inventory["candidate"][name]["bytes"])
            validate_comparison(group["items"][name], measurement["bounds"][bound_name], f"{group_name}/{name}")
            if not close(float(group["items"][name]["baseline_median"]), expected_baseline) or not close(float(group["items"][name]["candidate_median"]), expected_candidate):
                fail(f"{group_name}/{name} size binding is invalid")
        validate_comparison(group["total"], measurement["bounds"][bound_name], f"{group_name}/total")
        baseline_total = float(sum(item["bytes"] for item in inventory["baseline"].values()))
        candidate_total = float(sum(item["bytes"] for item in inventory["candidate"].values()))
        if not close(float(group["total"]["baseline_median"]), baseline_total) or not close(float(group["total"]["candidate_median"]), candidate_total):
            fail(f"{group_name} total size binding is invalid")
    if evidence["rollback"] != {
        "schema_version": 1,
        "from": "go1.27.1",
        "to": "go1.26.6",
        "required_files": metadata["rollback"]["required_files"],
        "directive_files": metadata["rollback"]["directive_files"],
        "builder_file": "build_packages.sh",
        "source_byte_exact": True,
        "builder_pin_verified": True,
        "baseline_protocol_tests": "pass",
    }:
        fail("toolchain rollback evidence is invalid")
    baseline = metadata["toolchains"]["baseline"]["version"]
    candidate = metadata["toolchains"]["candidate"]["version"]
    if args.pinned_toolchain == baseline:
        decision = "defer-go1.27-keep-go1.26.6"
    elif args.pinned_toolchain == candidate:
        fail("Go 1.27.1 adoption requires separately bound green native evidence")
    else:
        fail("source toolchain does not match an evaluated toolchain")
    verdict = {
        "schema_version": 1, "contract_id": "syswarden-go-toolchain-release-verdict/v1",
        "repository": args.repository, "release_tag": args.release_tag, "release_sha": args.release_sha,
        "run_id": args.run_id, "run_attempt": 1, "artifact_id": args.artifact_id,
        "artifact_name": args.artifact_name, "artifact_digest": args.artifact_digest,
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        "evaluation_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "pinned_toolchain": args.pinned_toolchain, "decision": decision, "status": "pass",
    }
    wire = (json.dumps(verdict, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        fail(f"refusing unsafe release verdict output: {exc}")
    try:
        os.write(descriptor, wire)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
