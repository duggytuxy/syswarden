#!/usr/bin/env python3
"""Validate repeatable SysWarden performance evidence and regressions."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any, Sequence

try:
    from scripts.ci import native_lifecycle_evidence as native_lifecycle
    from scripts.ci import native_performance_adapter as native_adapter
except ModuleNotFoundError:
    import native_lifecycle_evidence as native_lifecycle
    import native_performance_adapter as native_adapter


REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = REPOSITORY / "scripts" / "ci" / "performance_contract_v4.10.0.json"
DEFAULT_PROBE = REPOSITORY / "scripts" / "ci" / "native_performance_probe.py"
DEFAULT_ADAPTER = REPOSITORY / "scripts" / "ci" / "native_performance_adapter.py"
MAX_INPUT_BYTES = 4 * 1024 * 1024
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_CAMPAIGNS_PER_METRIC = 32
MAX_SAMPLES_PER_SIDE = 10000
STATIC_SIZE_METRICS = frozenset({"binary_bytes", "package_bytes"})
NONNEGATIVE_METRICS = frozenset(
    {"idle_cpu_percent", "loaded_cpu_percent", "disk_io_bytes_per_event"}
)


class PerformanceGateError(ValueError):
    """Raised when performance evidence is unsafe, ambiguous or incomplete."""


@dataclass(frozen=True)
class MetricContract:
    unit: str
    direction: str
    minimum_samples: int


def _load_regular_json(path: Path, maximum: int = MAX_INPUT_BYTES) -> Any:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise PerformanceGateError(f"input must not be a symbolic link: {path}")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PerformanceGateError(f"input must be one regular file: {path}")
    if info.st_size <= 0 or info.st_size > maximum:
        raise PerformanceGateError(f"input size is outside the accepted bounds: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if identity != (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_uid,
            info.st_gid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ):
            raise PerformanceGateError(f"input changed while opening: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise PerformanceGateError(f"input exceeds the accepted bound: {path}")
        after = os.fstat(descriptor)
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or total != opened.st_size:
            raise PerformanceGateError(f"input changed while reading: {path}")
        wire = b"".join(chunks)
    finally:
        os.close(descriptor)

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PerformanceGateError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_nonfinite(token: str) -> None:
        raise PerformanceGateError(f"non-finite JSON number: {token}")

    try:
        return json.loads(
            wire,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PerformanceGateError(f"invalid JSON in {path}") from exc


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PerformanceGateError(f"{label} keys are not exact")
    return value


def _sha256_regular(path: Path, maximum: int = MAX_INPUT_BYTES) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PerformanceGateError(f"binding input must be one regular file: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise PerformanceGateError(f"binding input size is outside bounds: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if identity != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise PerformanceGateError(f"binding input changed while opening: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise PerformanceGateError(f"binding input changed while reading: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def load_contract(path: Path = DEFAULT_CONTRACT) -> tuple[dict[str, Any], dict[str, MetricContract]]:
    document = _exact_mapping(
        _load_regular_json(path),
        {
            "schema_version",
            "contract_id",
            "target_release",
            "baseline_release",
            "baseline_commit",
            "minimum_campaigns",
            "stable_regression_percent",
            "metrics",
        },
        "contract",
    )
    if document["schema_version"] != 1 or document["contract_id"] != "syswarden-performance/v1":
        raise PerformanceGateError("unsupported performance contract")
    if document["target_release"] != "v4.10.0" or document["baseline_release"] != "v4.04.3":
        raise PerformanceGateError("unexpected performance release binding")
    if SHA_PATTERN.fullmatch(str(document["baseline_commit"])) is None:
        raise PerformanceGateError("baseline commit is not canonical")
    if type(document["minimum_campaigns"]) is not int or document["minimum_campaigns"] < 3:
        raise PerformanceGateError("minimum_campaigns must be at least three")
    threshold = document["stable_regression_percent"]
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or threshold <= 0:
        raise PerformanceGateError("stable regression threshold must be positive")
    raw_metrics = document["metrics"]
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        raise PerformanceGateError("contract metrics must be a non-empty object")
    metrics: dict[str, MetricContract] = {}
    for name, raw in raw_metrics.items():
        if IDENTIFIER_PATTERN.fullmatch(name) is None:
            raise PerformanceGateError(f"invalid metric identifier: {name!r}")
        item = _exact_mapping(raw, {"unit", "direction", "minimum_samples"}, f"metric {name}")
        if not isinstance(item["unit"], str) or IDENTIFIER_PATTERN.fullmatch(item["unit"]) is None:
            raise PerformanceGateError(f"invalid metric unit: {name}")
        if item["direction"] not in {"lower", "higher"}:
            raise PerformanceGateError(f"invalid metric direction: {name}")
        if type(item["minimum_samples"]) is not int or item["minimum_samples"] < 3:
            raise PerformanceGateError(f"invalid metric sample minimum: {name}")
        metrics[name] = MetricContract(
            unit=item["unit"],
            direction=item["direction"],
            minimum_samples=item["minimum_samples"],
        )
    return document, metrics


def _samples(
    value: object, minimum: int, label: str, *, allow_zero: bool = False
) -> list[float]:
    if not isinstance(value, list) or len(value) < minimum:
        raise PerformanceGateError(f"{label} requires at least {minimum} samples")
    if len(value) > MAX_SAMPLES_PER_SIDE:
        raise PerformanceGateError(
            f"{label} accepts at most {MAX_SAMPLES_PER_SIDE} samples"
        )
    result: list[float] = []
    for sample in value:
        if type(sample) not in (int, float):
            raise PerformanceGateError(f"{label} contains a non-numeric sample")
        number = float(sample)
        if not math.isfinite(number) or (number < 0 if allow_zero else number <= 0):
            qualifier = "nonnegative" if allow_zero else "positive"
            raise PerformanceGateError(
                f"{label} samples must be finite and {qualifier}"
            )
        result.append(number)
    return result


def _canonical_utc_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PerformanceGateError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PerformanceGateError(
            f"{label} must be a canonical UTC timestamp"
        ) from exc
    if parsed.tzinfo != dt.timezone.utc or parsed.microsecond != 0:
        raise PerformanceGateError(f"{label} must use whole UTC seconds")
    canonical = parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    if canonical != value:
        raise PerformanceGateError(f"{label} must be canonical")
    return value


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _regression_percent(
    baseline: float, candidate: float, direction: str
) -> float | None:
    if baseline == 0:
        return None
    if direction == "lower":
        return ((candidate - baseline) / baseline) * 100.0
    return ((baseline - candidate) / baseline) * 100.0


def _regressed(
    baseline: float, candidate: float, direction: str, threshold: float
) -> bool:
    if baseline == 0:
        return direction == "lower" and candidate > 0
    regression = _regression_percent(baseline, candidate, direction)
    return regression is not None and regression > threshold


def _load_waivers(path: Path | None, candidate_commit: str, as_of: dt.date) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    document = _exact_mapping(
        _load_regular_json(path),
        {"schema_version", "candidate_commit", "waivers"},
        "waiver document",
    )
    if document["schema_version"] != 1 or document["candidate_commit"] != candidate_commit:
        raise PerformanceGateError("waiver candidate binding is invalid")
    if not isinstance(document["waivers"], dict):
        raise PerformanceGateError("waivers must be an object")
    result: dict[str, dict[str, Any]] = {}
    for metric, raw in document["waivers"].items():
        item = _exact_mapping(
            raw,
            {"approved_by", "reason", "evidence", "expires_on"},
            f"waiver {metric}",
        )
        if not all(isinstance(item[key], str) for key in item):
            raise PerformanceGateError(f"waiver {metric} values must be strings")
        if len(item["approved_by"].strip()) < 3 or len(item["reason"].strip()) < 20:
            raise PerformanceGateError(f"waiver {metric} approval is incomplete")
        if not item["evidence"].startswith("https://"):
            raise PerformanceGateError(f"waiver {metric} evidence must use HTTPS")
        try:
            expiry = dt.date.fromisoformat(item["expires_on"])
        except ValueError as exc:
            raise PerformanceGateError(f"waiver {metric} expiry is invalid") from exc
        if expiry < as_of:
            raise PerformanceGateError(f"waiver {metric} is expired")
        result[metric] = item
    return result


def evaluate(
    evidence: object,
    contract: dict[str, Any],
    metric_contracts: dict[str, MetricContract],
    waivers: dict[str, dict[str, Any]],
    expected_candidate: str,
    *,
    expected_probe_sha256: str | None = None,
    expected_adapter_sha256: str | None = None,
    expected_adapter_config_sha256: str | None = None,
    expected_baseline_binary_sha256: str | None = None,
    expected_candidate_binary_sha256: str | None = None,
    expected_baseline_package_sha256: str | None = None,
    expected_candidate_package_sha256: str | None = None,
) -> dict[str, Any]:
    document = _exact_mapping(
        evidence,
        {
            "schema_version",
            "contract_id",
            "target_release",
            "baseline_release",
            "baseline_commit",
            "candidate_commit",
            "metrics",
        },
        "evidence",
    )
    expected_values = {
        "schema_version": 2,
        "contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "baseline_commit": contract["baseline_commit"],
        "candidate_commit": expected_candidate,
    }
    for key, expected in expected_values.items():
        if document[key] != expected:
            raise PerformanceGateError(f"evidence {key} binding is invalid")
    if SHA_PATTERN.fullmatch(expected_candidate) is None:
        raise PerformanceGateError("candidate commit is not canonical")
    raw_metrics = document["metrics"]
    if not isinstance(raw_metrics, dict) or set(raw_metrics) != set(metric_contracts):
        raise PerformanceGateError("evidence metric inventory is not exact")
    unknown_waivers = set(waivers) - set(metric_contracts)
    if unknown_waivers:
        raise PerformanceGateError(f"waiver references unknown metrics: {sorted(unknown_waivers)}")

    threshold = float(contract["stable_regression_percent"])
    minimum_campaigns = int(contract["minimum_campaigns"])
    results: dict[str, Any] = {}
    failures: list[str] = []
    expected_campaign_ids: set[str] | None = None
    campaign_bindings: dict[str, tuple[Any, ...]] = {}
    shared_campaign_binding: tuple[Any, ...] | None = None
    campaign_timestamps: set[str] = set()
    sample_documents: set[str] = set()
    dynamic_sample_pairs: dict[str, set[tuple[tuple[float, ...], tuple[float, ...]]]] = {
        name: set()
        for name, metric in metric_contracts.items()
        if name not in STATIC_SIZE_METRICS
        and math.ceil(metric.minimum_samples / minimum_campaigns) > 1
    }
    for name, metric_contract in metric_contracts.items():
        metric = _exact_mapping(raw_metrics[name], {"unit", "campaigns"}, f"evidence metric {name}")
        if metric["unit"] != metric_contract.unit:
            raise PerformanceGateError(f"metric unit mismatch: {name}")
        campaigns = metric["campaigns"]
        if (
            not isinstance(campaigns, list)
            or len(campaigns) < minimum_campaigns
            or len(campaigns) > MAX_CAMPAIGNS_PER_METRIC
        ):
            raise PerformanceGateError(f"metric {name} requires at least {minimum_campaigns} campaigns")
        raw_identifiers = {
            campaign.get("id")
            for campaign in campaigns
            if isinstance(campaign, dict)
        }
        if expected_campaign_ids is not None and raw_identifiers != expected_campaign_ids:
            raise PerformanceGateError(
                f"campaign inventory differs across metrics: {name}"
            )
        identifiers: set[str] = set()
        baseline_all: list[float] = []
        candidate_all: list[float] = []
        campaign_results: list[dict[str, Any]] = []
        regressed_campaigns = 0
        for raw_campaign in campaigns:
            campaign = _exact_mapping(
                raw_campaign,
                {
                    "id",
                    "recorded_at",
                    "environment_id",
                    "environment_sha256",
                    "probe_sha256",
                    "adapter_sha256",
                    "adapter_config_sha256",
                    "baseline_samples_sha256",
                    "candidate_samples_sha256",
                    "baseline_binary_sha256",
                    "candidate_binary_sha256",
                    "baseline_package_sha256",
                    "candidate_package_sha256",
                    "baseline",
                    "candidate",
                },
                f"campaign {name}",
            )
            identifier = campaign["id"]
            if not isinstance(identifier, str) or IDENTIFIER_PATTERN.fullmatch(identifier) is None:
                raise PerformanceGateError(f"invalid campaign identifier for {name}")
            if identifier in identifiers:
                raise PerformanceGateError(f"duplicate campaign identifier for {name}: {identifier}")
            identifiers.add(identifier)
            _canonical_utc_timestamp(
                campaign["recorded_at"], f"{name}/{identifier}/recorded_at"
            )
            environment_id = campaign["environment_id"]
            if (
                not isinstance(environment_id, str)
                or IDENTIFIER_PATTERN.fullmatch(environment_id) is None
            ):
                raise PerformanceGateError(
                    f"invalid environment identifier for {name}/{identifier}"
                )
            digest_names = (
                "environment_sha256",
                "probe_sha256",
                "adapter_sha256",
                "adapter_config_sha256",
                "baseline_samples_sha256",
                "candidate_samples_sha256",
                "baseline_binary_sha256",
                "candidate_binary_sha256",
                "baseline_package_sha256",
                "candidate_package_sha256",
            )
            for digest_name in digest_names:
                digest = campaign[digest_name]
                if (
                    not isinstance(digest, str)
                    or SHA256_PATTERN.fullmatch(digest) is None
                ):
                    raise PerformanceGateError(
                        f"invalid {digest_name} for {name}/{identifier}"
                    )
            binding = (
                campaign["recorded_at"],
                environment_id,
                *(campaign[key] for key in digest_names),
            )
            if identifier in campaign_bindings and campaign_bindings[identifier] != binding:
                raise PerformanceGateError(
                    f"campaign provenance differs across metrics: {identifier}"
                )
            if identifier not in campaign_bindings:
                expected_tool_bindings = {
                    "probe_sha256": expected_probe_sha256,
                    "adapter_sha256": expected_adapter_sha256,
                    "adapter_config_sha256": expected_adapter_config_sha256,
                    "baseline_binary_sha256": expected_baseline_binary_sha256,
                    "candidate_binary_sha256": expected_candidate_binary_sha256,
                    "baseline_package_sha256": expected_baseline_package_sha256,
                    "candidate_package_sha256": expected_candidate_package_sha256,
                }
                for key, expected_digest in expected_tool_bindings.items():
                    if expected_digest is not None and campaign[key] != expected_digest:
                        raise PerformanceGateError(
                            f"campaign {key} does not match the reviewed input"
                        )
                shared_binding = (
                    environment_id,
                    campaign["environment_sha256"],
                    campaign["probe_sha256"],
                    campaign["adapter_sha256"],
                    campaign["adapter_config_sha256"],
                    campaign["baseline_binary_sha256"],
                    campaign["candidate_binary_sha256"],
                    campaign["baseline_package_sha256"],
                    campaign["candidate_package_sha256"],
                )
                if shared_campaign_binding is None:
                    shared_campaign_binding = shared_binding
                elif shared_binding != shared_campaign_binding:
                    raise PerformanceGateError(
                        "campaign environment, probe, adapter, or artifact binding differs"
                    )
                recorded_at = campaign["recorded_at"]
                if recorded_at in campaign_timestamps:
                    raise PerformanceGateError("campaign timestamps are duplicated")
                campaign_timestamps.add(recorded_at)
                baseline_document = campaign["baseline_samples_sha256"]
                candidate_document = campaign["candidate_samples_sha256"]
                if baseline_document == candidate_document:
                    raise PerformanceGateError("paired sample documents are identical")
                for digest in (baseline_document, candidate_document):
                    if digest in sample_documents:
                        raise PerformanceGateError(
                            "sample document is reused across campaigns"
                        )
                    sample_documents.add(digest)
            campaign_bindings[identifier] = binding
            baseline_samples = _samples(
                campaign["baseline"],
                1,
                f"{name}/{identifier}/baseline",
                allow_zero=name in NONNEGATIVE_METRICS,
            )
            candidate_samples = _samples(
                campaign["candidate"],
                1,
                f"{name}/{identifier}/candidate",
                allow_zero=name in NONNEGATIVE_METRICS,
            )
            if len(baseline_samples) != len(candidate_samples):
                raise PerformanceGateError(
                    f"{name}/{identifier} baseline and candidate sample counts differ"
                )
            required_per_campaign = math.ceil(
                metric_contract.minimum_samples / minimum_campaigns
            )
            if len(baseline_samples) != required_per_campaign:
                raise PerformanceGateError(
                    f"{name}/{identifier} requires exactly {required_per_campaign} samples per side"
                )
            if name in dynamic_sample_pairs:
                sample_pair = (tuple(baseline_samples), tuple(candidate_samples))
                has_zero_vector = any(
                    all(value == 0 for value in values) for values in sample_pair
                )
                if sample_pair in dynamic_sample_pairs[name] and not has_zero_vector:
                    raise PerformanceGateError(
                        f"dynamic sample vectors are cloned across campaigns: {name}"
                    )
                dynamic_sample_pairs[name].add(sample_pair)
            baseline_all.extend(baseline_samples)
            candidate_all.extend(candidate_samples)
            baseline_median = median(baseline_samples)
            candidate_median = median(candidate_samples)
            regression = _regression_percent(baseline_median, candidate_median, metric_contract.direction)
            if _regressed(
                baseline_median,
                candidate_median,
                metric_contract.direction,
                threshold,
            ):
                regressed_campaigns += 1
            campaign_results.append(
                {
                    "id": identifier,
                    "recorded_at": campaign["recorded_at"],
                    "environment_id": environment_id,
                    "environment_sha256": campaign["environment_sha256"],
                    "probe_sha256": campaign["probe_sha256"],
                    "adapter_sha256": campaign["adapter_sha256"],
                    "adapter_config_sha256": campaign[
                        "adapter_config_sha256"
                    ],
                    "baseline_samples_sha256": campaign["baseline_samples_sha256"],
                    "candidate_samples_sha256": campaign["candidate_samples_sha256"],
                    "baseline_binary_sha256": campaign["baseline_binary_sha256"],
                    "candidate_binary_sha256": campaign["candidate_binary_sha256"],
                    "baseline_package_sha256": campaign["baseline_package_sha256"],
                    "candidate_package_sha256": campaign["candidate_package_sha256"],
                    "baseline_median": baseline_median,
                    "candidate_median": candidate_median,
                    "regression_percent": regression,
                }
            )
        if expected_campaign_ids is None:
            expected_campaign_ids = identifiers
        elif identifiers != expected_campaign_ids:
            raise PerformanceGateError(
                f"campaign inventory differs across metrics: {name}"
            )
        if len(baseline_all) < metric_contract.minimum_samples or len(candidate_all) < metric_contract.minimum_samples:
            raise PerformanceGateError(
                f"metric {name} requires at least {metric_contract.minimum_samples} samples per side"
            )
        baseline_median = median(baseline_all)
        candidate_median = median(candidate_all)
        aggregate_regression = _regression_percent(
            baseline_median, candidate_median, metric_contract.direction
        )
        stable = _regressed(
            baseline_median,
            candidate_median,
            metric_contract.direction,
            threshold,
        ) and regressed_campaigns >= math.ceil(len(campaigns) / 2)
        waived = stable and name in waivers
        if stable and not waived:
            failures.append(name)
        results[name] = {
            "unit": metric_contract.unit,
            "direction": metric_contract.direction,
            "baseline": {
                "samples": len(baseline_all),
                "minimum": min(baseline_all),
                "median": baseline_median,
                "p95": _percentile(baseline_all, 0.95),
                "maximum": max(baseline_all),
            },
            "candidate": {
                "samples": len(candidate_all),
                "minimum": min(candidate_all),
                "median": candidate_median,
                "p95": _percentile(candidate_all, 0.95),
                "maximum": max(candidate_all),
            },
            "aggregate_regression_percent": aggregate_regression,
            "regressed_campaigns": regressed_campaigns,
            "campaign_count": len(campaigns),
            "stable_regression": stable,
            "waived": waived,
            "campaigns": campaign_results,
        }
    return {
        "schema_version": 2,
        "contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_commit": contract["baseline_commit"],
        "candidate_commit": expected_candidate,
        "threshold_percent": threshold,
        "verdict": "pass" if not failures else "fail",
        "failed_metrics": failures,
        "metrics": results,
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("short performance report write")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def reviewed_bindings(
    adapter_config_path: Path,
    lifecycle_verdict_path: Path,
    candidate_commit: str,
    contract: dict[str, Any],
) -> dict[str, str]:
    adapter_config_sha256 = _sha256_regular(
        adapter_config_path, native_adapter.MAX_CONFIG_BYTES
    )
    config_descriptor = os.open(
        adapter_config_path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        adapter_config = native_adapter._read_config(
            config_descriptor, adapter_config_sha256
        )
    finally:
        os.close(config_descriptor)
    if adapter_config["candidate_commit"] != candidate_commit:
        raise PerformanceGateError(
            "adapter config candidate_commit does not match the gate"
        )
    if (
        adapter_config["subjects"]["baseline"]["release"]
        != contract["baseline_release"]
        or adapter_config["subjects"]["baseline"]["artifact_commit"]
        != contract["baseline_commit"]
        or adapter_config["subjects"]["candidate"]["release"]
        != contract["target_release"]
        or adapter_config["subjects"]["candidate"]["artifact_commit"]
        != candidate_commit
    ):
        raise PerformanceGateError(
            "adapter config subject bindings do not match the contract"
        )

    lifecycle = _exact_mapping(
        _load_regular_json(lifecycle_verdict_path),
        {
            "schema",
            "repository",
            "target_release",
            "candidate_commit",
            "contract_sha256",
            "qualification_state",
            "publishing",
            "status",
            "profile_count",
            "raw_evidence_count",
            "raw_evidence_inventory_sha256",
            "profiles",
        },
        "native lifecycle verdict",
    )
    if (
        lifecycle["schema"] != "syswarden-native-package-lifecycle-verdict/v1"
        or lifecycle["repository"] != "duggytuxy/syswarden"
        or lifecycle["target_release"] != contract["target_release"]
        or lifecycle["candidate_commit"] != candidate_commit
        or lifecycle["contract_sha256"] != native_lifecycle.CONTRACT_SHA256
        or lifecycle["qualification_state"] != "candidate-not-qualified"
        or lifecycle["publishing"] is not False
        or lifecycle["status"] != "pass"
        or lifecycle["profile_count"] != 3
        or lifecycle["raw_evidence_count"] != 87
        or not isinstance(lifecycle["raw_evidence_inventory_sha256"], str)
        or SHA256_PATTERN.fullmatch(lifecycle["raw_evidence_inventory_sha256"])
        is None
    ):
        raise PerformanceGateError("native lifecycle verdict binding is invalid")
    profiles = lifecycle["profiles"]
    if not isinstance(profiles, list):
        raise PerformanceGateError("native lifecycle profiles are invalid")
    profile_ids = [
        profile.get("host", {}).get("profile_id")
        if isinstance(profile, dict) and isinstance(profile.get("host"), dict)
        else None
        for profile in profiles
    ]
    if sorted(profile_ids, key=lambda value: "" if value is None else str(value)) != [
        "APK-324",
        "DEB-U2604",
        "RPM-A9",
    ]:
        raise PerformanceGateError("native lifecycle profile inventory is invalid")
    deb_profiles = [
        profile
        for profile in profiles
        if isinstance(profile, dict)
        and isinstance(profile.get("host"), dict)
        and profile["host"].get("profile_id") == "DEB-U2604"
    ]
    if len(deb_profiles) != 1:
        raise PerformanceGateError("DEB-U2604 lifecycle profile is not unique")
    packages = deb_profiles[0].get("packages")
    if not isinstance(packages, list) or len(packages) != 2:
        raise PerformanceGateError("DEB-U2604 lifecycle packages are incomplete")
    lifecycle_packages: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise PerformanceGateError("DEB-U2604 lifecycle package is invalid")
        release = package.get("release_tag")
        digest = package.get("package_sha256")
        expected_commit = (
            contract["baseline_commit"]
            if release == contract["baseline_release"]
            else candidate_commit
        )
        if (
            release not in {contract["baseline_release"], contract["target_release"]}
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
            or package.get("producer_commit") != expected_commit
            or package.get("release_asset_digest_verified") is not True
            or package.get("package_payload_verified") is not True
            or package.get("verified_before_install") is not True
            or release in lifecycle_packages
        ):
            raise PerformanceGateError("DEB-U2604 lifecycle package binding is invalid")
        lifecycle_packages[release] = digest
    baseline = adapter_config["subjects"]["baseline"]
    candidate = adapter_config["subjects"]["candidate"]
    if (
        baseline["binary_path"] != native_adapter.EXPECTED_BINARY_PATH
        or candidate["binary_path"] != native_adapter.EXPECTED_BINARY_PATH
    ):
        raise PerformanceGateError(
            "performance binary path is not the packaged syswarden-core executable"
        )
    if (
        baseline["package_sha256"]
        != lifecycle_packages.get(contract["baseline_release"])
        or candidate["package_sha256"]
        != lifecycle_packages.get(contract["target_release"])
    ):
        raise PerformanceGateError(
            "performance packages do not match the verified DEB-U2604 lifecycle packages"
        )
    return {
        "expected_probe_sha256": _sha256_regular(DEFAULT_PROBE),
        "expected_adapter_sha256": _sha256_regular(DEFAULT_ADAPTER),
        "expected_adapter_config_sha256": adapter_config_sha256,
        "expected_baseline_binary_sha256": baseline["binary_sha256"],
        "expected_candidate_binary_sha256": candidate["binary_sha256"],
        "expected_baseline_package_sha256": baseline["package_sha256"],
        "expected_candidate_package_sha256": candidate["package_sha256"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--adapter-config", type=Path, required=True)
    parser.add_argument("--native-lifecycle-verdict", type=Path, required=True)
    parser.add_argument("--waivers", type=Path)
    parser.add_argument("--as-of", type=dt.date.fromisoformat, default=dt.date.today())
    parser.add_argument("--report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        contract, metrics = load_contract(args.contract)
        bindings = reviewed_bindings(
            args.adapter_config,
            args.native_lifecycle_verdict,
            args.candidate_commit,
            contract,
        )
        waivers = _load_waivers(args.waivers, args.candidate_commit, args.as_of)
        report = evaluate(
            _load_regular_json(args.evidence),
            contract,
            metrics,
            waivers,
            args.candidate_commit,
            **bindings,
        )
        if args.report is not None:
            _write_report(args.report, report)
        print(
            f"Performance gate {report['verdict']}: "
            f"{len(report['metrics'])} metrics, "
            f"{len(report['failed_metrics'])} unwaived stable regressions."
        )
        return 0 if report["verdict"] == "pass" else 1
    except (
        OSError,
        PerformanceGateError,
        native_adapter.NativePerformanceAdapterError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
