#!/usr/bin/env python3
"""Strictly bind raw SysWarden runtime-lab reports to release evidence.

The native package shards carry an explicit qualification-run binding so their
cross-run aggregation is independently reproducible. This adapter validates all
exact schemas and shard digests, independently re-verifies the Git checkout and
both package sets, derives decisions from nested evidence, and emits the two
canonical envelopes consumed by ``release_qualification_gate.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Sequence

import package_lifecycle_lab as package_lab
import release_qualification_gate as gate


OUTPUT_NAMES = {
    "nft": "nftables-bound.json",
    "package": "package-lifecycle-bound.json",
}
RAW_NAMES = {
    "nft": "nftables-raw.json",
    "package": "package-lifecycle-raw.json",
}
# Laboratories run sequentially, so raw timestamps cannot be byte-identical.
# The CLI skew applies to the normalized envelopes; independently bound the raw
# collection window and stamp all envelopes with the earliest raw timestamp.
RAW_REPORT_MAX_SKEW_SECONDS = 3600
RAW_TOP_KEYS = {
    "nft": frozenset(
        {
            "schema_version",
            "generated_at",
            "harness_status",
            "product_status",
            "release_ready",
            "finding_id",
            "summary",
            "engine",
            "network_namespaces",
            "conditions",
            "kernel_error",
        }
    ),
    "package": frozenset(
        {
            "schema_version",
            "generated_at",
            "status",
            "harness_complete",
            "release_ready",
            "blocker_ids",
            "unexpected_failed_checks",
            "package_version_contract",
            "scope",
            "engine",
            "package_roots",
            "platforms",
            "qualification_binding",
            "native_shards",
        }
    ),
}


class AdapterError(gate.EvidenceError):
    """Raised when raw evidence cannot be safely normalized."""


@dataclass(frozen=True)
class RawReport:
    label: str
    snapshot: gate.FileSnapshot
    document: dict[str, Any]
    generated_at: datetime


@dataclass(frozen=True)
class ValidatedInputs:
    binding: gate.RepositoryBinding
    candidate: gate.PackageManifest
    previous: gate.PackageManifest
    raws: dict[str, RawReport]
    package_shards: dict[str, RawReport]
    envelopes: dict[str, dict[str, Any]]


def _fail(message: str) -> None:
    raise AdapterError(message)


def _exact_keys(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    expected = frozenset(keys)
    actual = frozenset(value)
    if actual != expected:
        _fail(
            f"{label} schema keys differ; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _string(value: Any, label: str, *, empty: bool = False) -> str:
    if type(value) is not str or (not empty and not value):
        _fail(f"{label} must be {'a string' if empty else 'a non-empty string'}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        _fail(f"{label} must be an integer")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        _fail(f"{label} must be an array")
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    sorted_unique: bool = False,
    allow_empty_items: bool = False,
) -> list[str]:
    result = _list(value, label)
    if any(
        type(item) is not str or (not allow_empty_items and not item)
        for item in result
    ):
        _fail(f"{label} must contain only valid strings")
    if sorted_unique and result != sorted(set(result)):
        _fail(f"{label} must be sorted and unique")
    return result


def _sha256(value: Any, label: str) -> str:
    result = _string(value, label)
    if gate.SHA256_RE.fullmatch(result) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return result


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _git_blob_bytes(binding: gate.RepositoryBinding, relative: str) -> bytes:
    try:
        process = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(binding.root),
                "show",
                f"{binding.commit_sha}:{relative}",
            ),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(f"cannot read Git blob {relative}: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        _fail(f"cannot read Git blob {relative}: {detail}")
    return process.stdout


def _load_raw(
    path: Path,
    label: str,
    repo: Path,
    now: datetime,
    max_age_seconds: int,
) -> RawReport:
    snapshot = gate.read_snapshot(path, f"{label} raw report")
    if _inside(snapshot.path, repo):
        _fail(f"{label} raw report must be outside the repository")
    document = gate.strict_json(snapshot.payload, f"{label} raw report")
    generated_at = gate.parse_timestamp(document.get("generated_at"), f"{label}.generated_at")
    if generated_at > now + timedelta(seconds=gate.FUTURE_SKEW_SECONDS):
        _fail(f"{label} raw report timestamp is too far in the future")
    if now - generated_at > timedelta(seconds=max_age_seconds):
        _fail(f"{label} raw report is stale")
    return RawReport(label, snapshot, document, generated_at)


def _validate_nft(document: dict[str, Any], binding: gate.RepositoryBinding) -> dict[str, Any]:
    _exact_keys(document, RAW_TOP_KEYS["nft"], "nft raw report")
    if _integer(document["schema_version"], "nft.schema_version") != 1:
        _fail("nft raw report schema version must be 1")
    engine = _exact_keys(
        document["engine"],
        {"name", "version", "rootless", "image", "network", "nftables"},
        "nft.engine",
    )
    for key in ("name", "version", "image", "network", "nftables"):
        _string(engine[key], f"nft.engine.{key}")
    if (
        engine["name"] != "podman"
        or _boolean(engine["rootless"], "nft.engine.rootless") is not True
        or engine["network"] != "none"
        or re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", engine["image"]) is None
    ):
        _fail("nft engine isolation/pinning evidence is invalid")
    namespaces = _exact_keys(
        document["network_namespaces"], {"host", "container"}, "nft.network_namespaces"
    )
    host_namespace = _string(namespaces["host"], "nft.network_namespaces.host")
    lab_namespace = _string(namespaces["container"], "nft.network_namespaces.container")
    if host_namespace == lab_namespace:
        _fail("nft laboratory namespace is not distinct from the host namespace")
    condition_keys = {
        "separate_network_namespace",
        "historical_concatenation_rejected_before_mutation",
        "kernel_reported_invalid_port",
        "corrected_ruleset_applied",
        "current_generator_contract_passed",
        "dynamic_timeout_replication_applied",
        "isolated_ruleset_cleanup_succeeded",
    }
    conditions = _exact_keys(document["conditions"], condition_keys, "nft.conditions")
    if any(_boolean(value, f"nft.conditions.{key}") is not True for key, value in conditions.items()):
        _fail("nft raw report no longer proves the corrected kernel contract")
    if "Service out of range" not in _string(document["kernel_error"], "nft.kernel_error"):
        _fail("nft kernel error does not prove the reviewed invalid-port rejection")
    _string(document["summary"], "nft.summary")
    derived_harness = all(conditions.values()) and engine["rootless"] is True
    if (
        document["harness_status"] != ("pass" if derived_harness else "fail")
        or document["product_status"] != "pass"
        or _boolean(document["release_ready"], "nft.release_ready") is not True
        or document["finding_id"] != "SW-FW-004"
    ):
        _fail("nft top-level classification is inconsistent with nested evidence")

    # Bind the characterization to the reviewed source and pinned Act image in HEAD.
    golden = gate._blob(binding.root, "testdata/firewall/nftables-v4.02.8.nft")
    loader = gate._blob(binding.root, "src/core/syswarden-cli/config/config_loader.go")
    generator = gate._blob(
        binding.root, "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
    )
    serializer = gate._blob(
        binding.root, "src/core/syswarden-cli/pkg/firewall/honeyports.go"
    )
    if (
        golden.count("tcp dport { 236379 }") != 2
        or 'strings.Join(m.Security.Honeyports, " ")' not in loader
        or "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)" not in generator
        or 'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")' in generator
        or 'strings.Join(canonical, ", ")' not in serializer
    ):
        _fail("nft raw characterization does not match the expected Git source contract")
    act_images = re.findall(
        r"(?m)^\s*-P ubuntu-24\.04=([^\s]+@sha256:[0-9a-f]{64})\s*$",
        gate._blob(binding.root, ".actrc"),
    )
    if act_images != [engine["image"]]:
        _fail("nft engine image does not match the digest-pinned Act image in Git")
    return {
        "harness_complete": derived_harness,
        "release_ready": True,
        "blocker_ids": [],
        "conditions": {
            "network_namespace_isolated": conditions["separate_network_namespace"],
            "host_namespace_untouched": (
                engine["rootless"] is True
                and engine["network"] == "none"
                and host_namespace != lab_namespace
            ),
            "kernel_apply_executed": conditions["corrected_ruleset_applied"],
            "cleanup_complete": conditions["isolated_ruleset_cleanup_succeeded"],
        },
        "network_namespaces": {"host": host_namespace, "laboratory": lab_namespace},
    }


PACKAGE_CONTRACT_KEYS = frozenset(
    {
        "scheme",
        "relation",
        "previous_version",
        "candidate_version",
        "previous_numeric",
        "candidate_numeric",
        "coordinates",
    }
)
PACKAGE_CONTRACT_COORDINATE_KEYS = frozenset(
    {
        "coordinate",
        "family",
        "package_architecture",
        "previous_version",
        "candidate_version",
        "previous_numeric",
        "candidate_numeric",
    }
)
PACKAGE_SCOPE_KEYS = frozenset(
    {
        "container_lab_complete",
        "coordinate_classification",
        "host_architecture",
        "network_during_image_bootstrap",
        "network_during_package_operations",
        "host_mutation",
        "architectures_completed",
        "architectures_incomplete_or_failed",
        "architecture_coverage",
        "family_architecture_coverage",
        "required_platform_coordinates",
        "missing_platform_coordinates",
        "arm64_coverage_policy",
        "rollback_model",
    }
)
PACKAGE_QUALIFICATION_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "release_sha",
        "release_tag",
        "previous_tag",
        "workflow_run_id",
        "workflow_run_attempt",
        "candidate_run_id",
        "candidate_artifact_id",
        "candidate_artifact_name",
        "previous_release_id",
        "candidate_manifest_sha256",
        "previous_manifest_sha256",
    }
)
PACKAGE_NATIVE_SHARDS_KEYS = frozenset({"schema_version", "mode", "reports"})
PACKAGE_NATIVE_SHARD_RECORD_KEYS = frozenset(
    {
        "architecture",
        "host_architecture",
        "report_sha256",
        "engine_name",
        "engine_version",
    }
)
PACKAGE_NATIVE_SHARD_NAMES = {
    "amd64": "package-lifecycle-amd64.json",
    "arm64": "package-lifecycle-arm64.json",
}
PACKAGE_NATIVE_AGGREGATE_HOST = "native-shards:amd64,arm64"
PACKAGE_PLATFORM_KEYS = frozenset(
    {
        "name",
        "distribution",
        "family",
        "architecture",
        "architecture_id",
        "package_architecture",
        "podman_platform",
        "image",
        "purge_semantics",
        "candidate_version",
        "previous_version",
        "candidate",
        "previous",
        "package_bytes_differ",
        "bootstrap_execution",
        "lifecycle_network",
        "restart_contract",
        "scenarios",
        "architecture_probe",
        "status",
    }
)


def _package_versions(document: dict[str, Any], expected_version: str) -> tuple[str, str]:
    _exact_keys(document, RAW_TOP_KEYS["package"], "package raw report")
    if _integer(document["schema_version"], "package.schema_version") != 3:
        _fail("package raw report schema version must be 3")
    contract = _exact_keys(
        document["package_version_contract"], PACKAGE_CONTRACT_KEYS, "package.version_contract"
    )
    previous = _string(contract["previous_version"], "package.previous_version")
    candidate = _string(contract["candidate_version"], "package.candidate_version")
    if "v" + candidate != expected_version:
        _fail("package raw candidate version does not match the expected Git version")
    try:
        if gate.version_tuple("v" + previous) >= gate.version_tuple("v" + candidate):
            _fail("package raw report does not prove previous < candidate")
    except gate.EvidenceError as exc:
        raise AdapterError(str(exc)) from exc
    return previous, candidate


def _validate_package_qualification_binding(
    value: Any,
) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        PACKAGE_QUALIFICATION_BINDING_KEYS,
        "package.qualification_binding",
    )
    if _integer(binding["schema_version"], "package.qualification_binding.schema_version") != 1:
        _fail("package qualification binding schema version must be 1")
    for key in (
        "repository",
        "release_sha",
        "release_tag",
        "previous_tag",
        "candidate_artifact_name",
    ):
        _string(binding[key], f"package.qualification_binding.{key}")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", binding["repository"]) is None:
        _fail("package qualification repository is not canonical")
    if gate.SHA_RE.fullmatch(binding["release_sha"]) is None:
        _fail("package qualification release SHA is not canonical")
    for key in ("release_tag", "previous_tag"):
        if gate.VERSION_RE.fullmatch(binding[key]) is None:
            _fail(f"package qualification {key} is not canonical")
    if binding["release_tag"] == binding["previous_tag"]:
        _fail("package qualification release and previous tags must differ")
    for key in (
        "workflow_run_id",
        "workflow_run_attempt",
        "candidate_run_id",
        "candidate_artifact_id",
        "previous_release_id",
    ):
        if _integer(binding[key], f"package.qualification_binding.{key}") <= 0:
            _fail(f"package qualification {key} must be positive")
    for key in ("candidate_manifest_sha256", "previous_manifest_sha256"):
        _sha256(binding[key], f"package.qualification_binding.{key}")
    return binding


def _validate_package_native_shards(value: Any) -> dict[str, dict[str, Any]]:
    native_shards = _exact_keys(
        value,
        PACKAGE_NATIVE_SHARDS_KEYS,
        "package.native_shards",
    )
    if _integer(native_shards["schema_version"], "package.native_shards.schema_version") != 1:
        _fail("package native shard schema version must be 1")
    if native_shards["mode"] != "native_architecture_shards_v1":
        _fail("package native shard mode is invalid")
    reports = _list(native_shards["reports"], "package.native_shards.reports")
    if len(reports) != 2:
        _fail("package native shard inventory must contain exactly two reports")
    by_architecture: dict[str, dict[str, Any]] = {}
    architecture_order: list[str] = []
    for index, value in enumerate(reports):
        report = _exact_keys(
            value,
            PACKAGE_NATIVE_SHARD_RECORD_KEYS,
            f"package.native_shards.reports[{index}]",
        )
        architecture = _string(
            report["architecture"],
            f"package.native_shards.reports[{index}].architecture",
        )
        for key in ("host_architecture", "engine_name", "engine_version"):
            _string(
                report[key],
                f"package.native_shards.reports[{index}].{key}",
            )
        _sha256(
            report["report_sha256"],
            f"package.native_shards.reports[{index}].report_sha256",
        )
        if architecture in by_architecture or architecture not in {"amd64", "arm64"}:
            _fail("package native shard architecture is duplicate or unsupported")
        if report["host_architecture"] != architecture or report["engine_name"] != "podman":
            _fail("package native shard host or engine identity is invalid")
        by_architecture[architecture] = report
        architecture_order.append(architecture)
    if set(by_architecture) != {"amd64", "arm64"}:
        _fail("package native shard architecture inventory is incomplete")
    if architecture_order != ["amd64", "arm64"]:
        _fail("package native shard inventory order must be amd64 then arm64")
    return by_architecture


def _validate_package_shard_binding(
    document: dict[str, Any],
    package_shards: dict[str, RawReport],
    expected_binding: dict[str, Any],
) -> None:
    binding = _validate_package_qualification_binding(
        document["qualification_binding"]
    )
    if binding != expected_binding:
        _fail("package qualification binding differs from the exact workflow inputs")
    records = _validate_package_native_shards(document["native_shards"])
    if set(package_shards) != {"amd64", "arm64"}:
        _fail("package native shard file inventory is incomplete")
    for architecture in ("amd64", "arm64"):
        raw = package_shards[architecture]
        record = records[architecture]
        if raw.snapshot.path.name != PACKAGE_NATIVE_SHARD_NAMES[architecture]:
            _fail(f"package {architecture} shard basename is invalid")
        if raw.snapshot.sha256 != record["report_sha256"]:
            _fail(f"package {architecture} shard digest differs from the aggregate")
        try:
            package_lab.validate_native_shard_report(
                raw.document,
                architecture=architecture,
                expected_binding=expected_binding,
            )
        except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
            raise AdapterError(
                f"invalid package {architecture} native shard evidence: {exc}"
            ) from exc
        engine = raw.document["engine"]
        scope = raw.document["scope"]
        if record != {
            "architecture": architecture,
            "host_architecture": package_lab.normalize_host_architecture(
                scope["host_architecture"]
            ),
            "report_sha256": raw.snapshot.sha256,
            "engine_name": engine["name"],
            "engine_version": engine["version"],
        }:
            _fail(f"package {architecture} shard metadata differs from its report")
    shard_platforms = [
        platform
        for architecture in ("amd64", "arm64")
        for platform in package_shards[architecture].document["platforms"]
    ]
    if document.get("platforms") != shard_platforms:
        _fail("package aggregate platform evidence differs from its native shards")
    try:
        aggregate_status, aggregate_classification, aggregate_scope = (
            package_lab._aggregate_matrix_summary(shard_platforms)
        )
    except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError(
            f"invalid package native shard aggregate evidence: {exc}"
        ) from exc
    if (
        document.get("status") != aggregate_status
        or document.get("harness_complete")
        != aggregate_classification["harness_complete"]
        or document.get("release_ready")
        != aggregate_classification["release_ready"]
        or document.get("blocker_ids") != aggregate_classification["blocker_ids"]
        or document.get("unexpected_failed_checks")
        != aggregate_classification["unexpected_failed_checks"]
        or document.get("scope") != aggregate_scope
    ):
        _fail("package aggregate summary differs from its native shards")

    shard_contracts = [
        package_shards[architecture].document["package_version_contract"]
        for architecture in ("amd64", "arm64")
    ]
    expected_contract = {
        key: shard_contracts[0][key]
        for key in (
            "scheme",
            "relation",
            "previous_version",
            "candidate_version",
            "previous_numeric",
            "candidate_numeric",
        )
    }
    expected_contract["coordinates"] = sorted(
        [
            coordinate
            for contract in shard_contracts
            for coordinate in contract["coordinates"]
        ],
        key=lambda coordinate: coordinate["coordinate"],
    )
    if document.get("package_version_contract") != expected_contract:
        _fail("package aggregate version contract differs from its native shards")
    expected_engine_version = ";".join(
        f"{architecture}={records[architecture]['engine_version']}"
        for architecture in ("amd64", "arm64")
    )
    engine = document.get("engine")
    if not isinstance(engine, dict) or engine.get("version") != expected_engine_version:
        _fail("package aggregate engine version differs from native shard reports")


def _validate_package_schema(document: dict[str, Any]) -> None:
    _validate_package_qualification_binding(document["qualification_binding"])
    _validate_package_native_shards(document["native_shards"])
    contract = _exact_keys(
        document["package_version_contract"], PACKAGE_CONTRACT_KEYS, "package.version_contract"
    )
    for key in ("scheme", "relation", "previous_version", "candidate_version"):
        _string(contract[key], f"package.version_contract.{key}")
    for key in ("previous_numeric", "candidate_numeric"):
        numbers = _list(contract[key], f"package.version_contract.{key}")
        if len(numbers) != 3 or any(type(item) is not int or item < 0 for item in numbers):
            _fail(f"package.version_contract.{key} must contain three non-negative integers")
    coordinates = _list(contract["coordinates"], "package.version_contract.coordinates")
    if len(coordinates) != 6:
        _fail("package version contract must contain exactly six package coordinates")
    for index, item in enumerate(coordinates):
        coordinate = _exact_keys(
            item, PACKAGE_CONTRACT_COORDINATE_KEYS, f"package.version_contract.coordinates[{index}]"
        )
        for key in ("coordinate", "family", "package_architecture", "previous_version", "candidate_version"):
            _string(coordinate[key], f"package.version_contract.coordinates[{index}].{key}")
        for key in ("previous_numeric", "candidate_numeric"):
            values = _list(coordinate[key], f"package.version_contract.coordinates[{index}].{key}")
            if len(values) != 3 or any(type(value) is not int for value in values):
                _fail("package coordinate numeric version is invalid")

    scope = _exact_keys(document["scope"], PACKAGE_SCOPE_KEYS, "package.scope")
    _boolean(scope["container_lab_complete"], "package.scope.container_lab_complete")
    for key in (
        "host_architecture",
        "network_during_image_bootstrap",
        "network_during_package_operations",
        "host_mutation",
        "arm64_coverage_policy",
        "rollback_model",
    ):
        _string(scope[key], f"package.scope.{key}")
    normalized_host_architecture = package_lab.normalize_host_architecture(
        scope["host_architecture"]
    )
    native_aggregate = scope["host_architecture"] == PACKAGE_NATIVE_AGGREGATE_HOST
    if not native_aggregate or normalized_host_architecture is not None:
        _fail("package report must identify the exact amd64 plus arm64 native shard model")
    if scope["network_during_package_operations"] != "disabled":
        _fail("package operations were not network-isolated")
    classification = _list(scope["coordinate_classification"], "package.scope.coordinate_classification")
    if len(classification) != 10:
        _fail("package coordinate classification must contain exactly ten coordinates")
    for index, item in enumerate(classification):
        entry = _exact_keys(
            item,
            {"distribution", "architecture_id", "family", "status", "blocker_ids"},
            f"package.scope.coordinate_classification[{index}]",
        )
        for key in ("distribution", "architecture_id", "family", "status"):
            _string(entry[key], f"package.scope.coordinate_classification[{index}].{key}")
        _string_list(entry["blocker_ids"], f"package.scope.coordinate_classification[{index}].blocker_ids", sorted_unique=True)
    for key in ("architectures_completed",):
        _string_list(scope[key], f"package.scope.{key}")
    incomplete = _list(scope["architectures_incomplete_or_failed"], "package.scope.architectures_incomplete_or_failed")
    for index, item in enumerate(incomplete):
        entry = _exact_keys(item, {"architecture", "status", "reason"}, f"package.scope.architectures_incomplete_or_failed[{index}]")
        for key in entry:
            _string(entry[key], f"package.scope.architectures_incomplete_or_failed[{index}].{key}")
    architecture_coverage = _list(scope["architecture_coverage"], "package.scope.architecture_coverage")
    if len(architecture_coverage) != 2:
        _fail("package architecture coverage must contain amd64 and arm64")
    for index, item in enumerate(architecture_coverage):
        entry = _exact_keys(item, {"architecture", "architecture_id", "status", "required_distributions", "completed_distributions", "incomplete_or_failed_distributions"}, f"package.scope.architecture_coverage[{index}]")
        for key in ("architecture", "architecture_id", "status"):
            _string(entry[key], f"package.scope.architecture_coverage[{index}].{key}")
        for key in ("required_distributions", "completed_distributions", "incomplete_or_failed_distributions"):
            _string_list(entry[key], f"package.scope.architecture_coverage[{index}].{key}")
    family_coverage = _list(scope["family_architecture_coverage"], "package.scope.family_architecture_coverage")
    if len(family_coverage) != 6:
        _fail("package family/architecture coverage must contain six coordinates")
    for index, item in enumerate(family_coverage):
        entry = _exact_keys(item, {"family", "architecture", "architecture_id", "status", "required_distributions", "completed_distributions"}, f"package.scope.family_architecture_coverage[{index}]")
        for key in ("family", "architecture", "architecture_id", "status"):
            _string(entry[key], f"package.scope.family_architecture_coverage[{index}].{key}")
        for key in ("required_distributions", "completed_distributions"):
            _string_list(entry[key], f"package.scope.family_architecture_coverage[{index}].{key}")
    for key in ("required_platform_coordinates", "missing_platform_coordinates"):
        entries = _list(scope[key], f"package.scope.{key}")
        for index, item in enumerate(entries):
            entry = _exact_keys(item, {"distribution", "architecture"}, f"package.scope.{key}[{index}]")
            _string(entry["distribution"], f"package.scope.{key}[{index}].distribution")
            _string(entry["architecture"], f"package.scope.{key}[{index}].architecture")

    engine = _exact_keys(document["engine"], {"name", "version", "rootless", "arm64_emulator", "arm64_binfmt"}, "package.engine")
    if engine["name"] != "podman" or not _string(engine["version"], "package.engine.version") or _boolean(engine["rootless"], "package.engine.rootless") is not True:
        _fail("package raw report lacks rootless Podman evidence")
    emulator = engine["arm64_emulator"]
    if emulator is not None:
        emulator = _exact_keys(emulator, {"path", "sha256", "regular_file", "executable", "symlink", "role"}, "package.engine.arm64_emulator")
        _string(emulator["path"], "package.engine.arm64_emulator.path")
        _sha256(emulator["sha256"], "package.engine.arm64_emulator.sha256")
        if emulator["regular_file"] is not True or emulator["executable"] is not True or emulator["symlink"] is not False or emulator["role"] != "host binfmt interpreter":
            _fail("package ARM64 emulator evidence is invalid")
    binfmt = engine["arm64_binfmt"]
    if binfmt is not None:
        binfmt = _exact_keys(
            binfmt,
            {"path", "sha256", "interpreter", "flags"},
            "package.engine.arm64_binfmt",
        )
        _string(binfmt["path"], "package.engine.arm64_binfmt.path")
        _sha256(binfmt["sha256"], "package.engine.arm64_binfmt.sha256")
        _string(binfmt["interpreter"], "package.engine.arm64_binfmt.interpreter")
        if "F" not in _string(binfmt["flags"], "package.engine.arm64_binfmt.flags"):
            _fail("package ARM64 binfmt evidence lacks the fix-binary flag")
        if emulator is None or binfmt["interpreter"] != emulator["path"]:
            _fail("package ARM64 binfmt interpreter does not match the emulator")
    if emulator is not None or binfmt is not None:
        _fail("package native shard qualification forbids ARM64 emulation")

    roots = _exact_keys(document["package_roots"], {"candidate", "previous", "mount_mode"}, "package.package_roots")
    _string(roots["candidate"], "package.package_roots.candidate")
    _string(roots["previous"], "package.package_roots.previous")
    if roots["mount_mode"] != "read-only":
        _fail("package roots were not mounted read-only")

    platforms = _list(document["platforms"], "package.platforms")
    if len(platforms) != 10:
        _fail("package report must contain exactly ten platform results")
    seen: set[tuple[str, str]] = set()
    specs = {(item.distribution, item.architecture): item for item in package_lab.DEFAULT_PLATFORMS}
    for index, item in enumerate(platforms):
        platform = _exact_keys(item, PACKAGE_PLATFORM_KEYS, f"package.platforms[{index}]")
        for key in ("name", "distribution", "family", "architecture", "architecture_id", "package_architecture", "podman_platform", "image", "purge_semantics", "candidate_version", "previous_version", "bootstrap_execution", "lifecycle_network", "restart_contract", "status"):
            _string(platform[key], f"package.platforms[{index}].{key}")
        coordinate = (platform["distribution"], platform["architecture_id"])
        if coordinate in seen or coordinate not in specs:
            _fail(f"package platform coordinate is duplicate or unsupported: {coordinate}")
        seen.add(coordinate)
        spec = specs[coordinate]
        expected = {
            "name": spec.name,
            "family": spec.family,
            "architecture": package_lab.ARCHITECTURE_LABELS[spec.architecture],
            "package_architecture": spec.package_architecture,
            "podman_platform": spec.podman_platform,
            "image": spec.image,
            "purge_semantics": spec.purge_semantics,
        }
        if any(platform[key] != value for key, value in expected.items()):
            _fail(f"package platform metadata differs from the pinned matrix at {coordinate}")
        if platform["lifecycle_network"] != "disabled" or _boolean(platform["package_bytes_differ"], f"package.platforms[{index}].package_bytes_differ") is not True:
            _fail(f"package lifecycle isolation/byte distinction is invalid at {coordinate}")
        for artifact_key in ("candidate", "previous"):
            artifact = _exact_keys(platform[artifact_key], {"filename", "version", "sha256"}, f"package.platforms[{index}].{artifact_key}")
            _string(artifact["filename"], f"package.platforms[{index}].{artifact_key}.filename")
            _string(artifact["version"], f"package.platforms[{index}].{artifact_key}.version")
            _sha256(artifact["sha256"], f"package.platforms[{index}].{artifact_key}.sha256")
        probe = _exact_keys(platform["architecture_probe"], {"status", "execution_mode", "podman_platform", "expected_uname", "actual_uname", "container_exit_code", "network", "filesystem", "emulator", "binfmt"}, f"package.platforms[{index}].architecture_probe")
        for key in ("status", "execution_mode", "podman_platform", "expected_uname", "actual_uname", "network", "filesystem"):
            _string(probe[key], f"package.platforms[{index}].architecture_probe.{key}")
        if (
            probe["status"] != "available"
            or probe["network"] != "disabled"
            or _integer(
                probe["container_exit_code"],
                f"package.platforms[{index}].architecture_probe.container_exit_code",
            )
            != 0
            or probe["podman_platform"] != spec.podman_platform
            or probe["expected_uname"] != spec.uname_architecture
            or probe["actual_uname"] != spec.uname_architecture
        ):
            _fail(f"package architecture execution probe is incomplete at {coordinate}")
        probe_emulator = probe["emulator"]
        if probe_emulator is not None:
            probe_emulator = _exact_keys(probe_emulator, {"path", "sha256", "role"}, f"package.platforms[{index}].architecture_probe.emulator")
            _string(probe_emulator["path"], "package probe emulator path")
            _sha256(probe_emulator["sha256"], "package probe emulator sha256")
            if probe_emulator["role"] != "host binfmt interpreter":
                _fail("package probe emulator role is invalid")
        probe_binfmt = probe["binfmt"]
        if probe_binfmt is not None:
            probe_binfmt = _exact_keys(
                probe_binfmt,
                {"path", "sha256", "interpreter", "flags"},
                f"package.platforms[{index}].architecture_probe.binfmt",
            )
            _string(probe_binfmt["path"], "package probe binfmt path")
            _sha256(probe_binfmt["sha256"], "package probe binfmt sha256")
            _string(probe_binfmt["interpreter"], "package probe binfmt interpreter")
            if "F" not in _string(probe_binfmt["flags"], "package probe binfmt flags"):
                _fail("package probe binfmt flags are invalid")
        native_coordinate = native_aggregate
        cross_arm64_coordinate = (
            spec.architecture == "arm64"
            and normalized_host_architecture != "arm64"
        )
        if native_coordinate:
            if (
                probe["execution_mode"] != "native"
                or probe_emulator is not None
                or probe_binfmt is not None
                or platform["bootstrap_execution"] != "native_container_build"
            ):
                _fail(
                    f"package native execution evidence is inconsistent at {coordinate}"
                )
        elif cross_arm64_coordinate:
            expected_probe_emulator = (
                {
                    "path": emulator["path"],
                    "sha256": emulator["sha256"],
                    "role": emulator["role"],
                }
                if emulator is not None
                else None
            )
            if (
                probe["execution_mode"] != "host_binfmt_qemu_aarch64"
                or probe_emulator != expected_probe_emulator
                or probe_binfmt != binfmt
                or emulator is None
                or binfmt is None
                or platform["bootstrap_execution"]
                != "podman_platform_with_validated_host_binfmt"
            ):
                _fail(
                    f"package cross-ARM64 execution lacks exact emulator/binfmt evidence at {coordinate}"
                )
        else:
            _fail(
                f"package coordinate {coordinate} cannot execute natively on host "
                f"{normalized_host_architecture!r} and has no approved cross-architecture mode"
            )
        scenarios = _list(platform["scenarios"], f"package.platforms[{index}].scenarios")
        for scenario_index, scenario_value in enumerate(scenarios):
            scenario = _exact_keys(scenario_value, {"name", "status", "container_exit_code", "container_start_exit_codes", "container_restart_count", "events", "inventory_evidence", "log_tail"}, f"package.platforms[{index}].scenarios[{scenario_index}]")
            for key in ("name", "status", "log_tail"):
                _string(scenario[key], f"package.platforms[{index}].scenarios[{scenario_index}].{key}", empty=key == "log_tail")
            _integer(scenario["container_exit_code"], "package scenario exit code")
            codes = _list(scenario["container_start_exit_codes"], "package scenario start exit codes")
            if any(type(code) is not int for code in codes):
                _fail("package scenario start exit codes must be integers")
            _integer(scenario["container_restart_count"], "package scenario restart count")
            events = _list(scenario["events"], "package scenario events")
            for event_index, event_value in enumerate(events):
                event = _exact_keys(event_value, {"status", "check", "detail"}, f"package scenario event[{event_index}]")
                if event["status"] not in {"pass", "fail"}:
                    _fail("package event status is invalid")
                _string(event["check"], "package event check")
                _string(event["detail"], "package event detail", empty=True)
            inventory = _exact_keys(
                scenario["inventory_evidence"],
                set(package_lab.expected_inventory_phase_labels(scenario["name"])),
                "package scenario inventory evidence",
            )
            for phase_name, phase_value in inventory.items():
                phase = _exact_keys(phase_value, {"manager_paths", "filesystem"}, f"package inventory {phase_name}")
                _string_list(phase["manager_paths"], f"package inventory {phase_name}.manager_paths")
                filesystem = _list(phase["filesystem"], f"package inventory {phase_name}.filesystem")
                for entry_index, entry_value in enumerate(filesystem):
                    entry = _exact_keys(entry_value, {"path", "type", "mode", "uid", "gid", "value"}, f"package inventory {phase_name}.filesystem[{entry_index}]")
                    for key in ("path", "type", "mode", "value"):
                        _string(entry[key], f"package inventory filesystem.{key}", empty=key == "value")
                    for key in ("uid", "gid"):
                        _integer(entry[key], f"package inventory filesystem.{key}")
    if seen != package_lab.REQUIRED_PLATFORM_COORDINATES:
        _fail("package platform matrix is incomplete")


def _validate_package(
    document: dict[str, Any],
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
    package_shards: dict[str, RawReport],
    expected_qualification_binding: dict[str, Any],
) -> dict[str, Any]:
    _validate_package_schema(document)
    _validate_package_shard_binding(
        document,
        package_shards,
        expected_qualification_binding,
    )
    try:
        package_lab.validate_report_version_contract(document)
        classification = package_lab.classify_lifecycle_evidence(document["platforms"])
    except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError(f"invalid package lifecycle evidence: {exc}") from exc
    for key in ("harness_complete", "release_ready"):
        _boolean(document[key], f"package.{key}")
    blockers = _string_list(document["blocker_ids"], "package.blocker_ids", sorted_unique=True)
    unexpected = _string_list(document["unexpected_failed_checks"], "package.unexpected_failed_checks", sorted_unique=True)
    for key in ("harness_complete", "release_ready", "blocker_ids", "unexpected_failed_checks"):
        if document[key] != classification[key]:
            _fail(f"package.{key} is not derived from lifecycle evidence")
    if classification["harness_complete"] is not True or unexpected:
        _fail("package lifecycle harness is incomplete or contains unexpected failures")
    if blockers:
        _fail("package lifecycle evidence may not carry a generic product waiver")
    expected_status = "pass" if classification["release_ready"] else "fail"
    if document["status"] != expected_status:
        _fail("package status is inconsistent with recomputed lifecycle evidence")
    # These paths are provenance only.  Durable artifacts are intentionally
    # extracted elsewhere; basenames and independently verified digests below
    # are the relocation-safe package binding.
    roots = document["package_roots"]
    raw_candidate_root = Path(roots["candidate"])
    raw_previous_root = Path(roots["previous"])
    if (
        not raw_candidate_root.is_absolute()
        or not raw_previous_root.is_absolute()
        or raw_candidate_root == raw_previous_root
    ):
        _fail("package raw roots must record two distinct absolute laboratory paths")
    contract = document["package_version_contract"]
    candidate_version = contract["candidate_version"]
    previous_version = contract["previous_version"]
    if "v" + candidate_version != binding.version:
        _fail("package candidate version does not match the Git binding")
    for index, platform in enumerate(document["platforms"]):
        for side, manifest, version in (
            ("candidate", candidate, candidate_version),
            ("previous", previous, previous_version),
        ):
            artifact = platform[side]
            if (
                artifact["filename"] not in manifest.checksums
                or artifact["sha256"] != manifest.checksums[artifact["filename"]]
                or artifact["version"] != version
                or platform[f"{side}_version"] != version
            ):
                _fail(f"package platform artifact binding is invalid at index {index}/{side}")
        if platform["candidate"]["sha256"] == platform["previous"]["sha256"]:
            _fail("package previous and candidate bytes are identical")
    coordinates = [
        {
            "platform": item["distribution"],
            "architecture": item["architecture_id"],
            "status": item["status"],
        }
        for item in classification["coordinate_classification"]
    ]
    lifecycle = {
        "previous_version": "v" + previous_version,
        "candidate_version": "v" + candidate_version,
        "fresh_install": True,
        "upgrade": True,
        "reinstall": True,
        "rollback": True,
        "remove": True,
        "purge_semantics": True,
        "second_restart": True,
        "previous_package_checksums": {
            name: digest
            for name, digest in previous.checksums.items()
        },
    }
    return {
        "harness_complete": True,
        "release_ready": classification["release_ready"],
        "blocker_ids": blockers,
        "coordinates": coordinates,
        "lifecycle": lifecycle,
    }


def _package_identity_set(*manifests: gate.PackageManifest) -> set[tuple[int, int]]:
    return {(item.device, item.inode) for manifest in manifests for item in manifest.snapshots}


def _revalidate_all(
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
    raws: dict[str, RawReport],
    package_shards: dict[str, RawReport],
) -> None:
    for raw in (*raws.values(), *package_shards.values()):
        gate.revalidate(raw.snapshot, f"{raw.label} raw report")
    for manifest, label in ((candidate, "candidate package evidence"), (previous, "previous package evidence")):
        for snapshot in manifest.snapshots:
            gate.revalidate(snapshot, label)
    current_candidate = gate.verify_packages(candidate.directory, binding)
    previous_deb = next(
        name for name in previous.checksums if name.endswith("_amd64.deb")
    )
    previous_version = "v" + previous_deb.removeprefix("syswarden_").removesuffix(
        "_amd64.deb"
    )
    current_previous = gate.verify_packages(
        previous.directory,
        gate.RepositoryBinding(
            binding.root,
            binding.commit_sha,
            binding.tree_sha,
            previous_version,
        ),
    )
    if current_candidate != candidate or current_previous != previous:
        _fail("package directory inventory changed after validation")
    current = gate.verify_repository(binding.root, binding.commit_sha, binding.version)
    if current != binding:
        _fail("Git binding changed during adapter validation")


def build_expected(args: argparse.Namespace, *, now: datetime | None = None) -> ValidatedInputs:
    if args.max_age_seconds < 60 or args.max_age_seconds > gate.MAX_EVIDENCE_AGE:
        _fail(f"max evidence age must be between 60 and {gate.MAX_EVIDENCE_AGE} seconds")
    if args.max_report_skew_seconds < 0 or args.max_report_skew_seconds > 3600:
        _fail("max report skew must be between 0 and 3600 seconds")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    binding = gate.verify_repository(args.repo_root, args.expected_sha, args.expected_version)
    candidate = gate.verify_packages(args.candidate_packages_dir, binding)
    raw_paths = {"nft": args.nft_raw, "package": args.package_raw}
    raws = {key: _load_raw(path, key, binding.root, current, args.max_age_seconds) for key, path in raw_paths.items()}
    package_shard_paths = {
        "amd64": args.package_amd64_shard,
        "arm64": args.package_arm64_shard,
    }
    package_shards = {
        architecture: _load_raw(
            path,
            f"package-{architecture}-shard",
            binding.root,
            current,
            args.max_age_seconds,
        )
        for architecture, path in package_shard_paths.items()
    }
    for key, raw in raws.items():
        if raw.snapshot.path.name != RAW_NAMES[key]:
            _fail(f"{key} raw basename must be exactly {RAW_NAMES[key]!r}")
    all_raws = [*raws.values(), *package_shards.values()]
    if (
        len({(item.snapshot.device, item.snapshot.inode) for item in all_raws}) != 4
        or len({item.snapshot.path for item in all_raws}) != 4
        or len({item.snapshot.path.name for item in all_raws}) != 4
    ):
        _fail("the raw reports and native shards must have distinct files, inodes, paths, and basenames")
    timestamps = [item.generated_at for item in raws.values()]
    if max(timestamps) - min(timestamps) > timedelta(seconds=RAW_REPORT_MAX_SKEW_SECONDS):
        _fail("raw report timestamps exceed the bounded laboratory collection window")
    previous_version, _ = _package_versions(raws["package"].document, binding.version)
    previous_binding = gate.RepositoryBinding(binding.root, binding.commit_sha, binding.tree_sha, "v" + previous_version)
    previous = gate.verify_packages(args.previous_packages_dir, previous_binding)
    expected_qualification_binding = {
        "schema_version": 1,
        "repository": args.expected_repository,
        "release_sha": binding.commit_sha,
        "release_tag": binding.version,
        "previous_tag": previous_binding.version,
        "workflow_run_id": args.expected_workflow_run_id,
        "workflow_run_attempt": args.expected_workflow_run_attempt,
        "candidate_run_id": args.expected_candidate_run_id,
        "candidate_artifact_id": args.expected_candidate_artifact_id,
        "candidate_artifact_name": args.expected_candidate_artifact_name,
        "previous_release_id": args.expected_previous_release_id,
        "candidate_manifest_sha256": candidate.sha256,
        "previous_manifest_sha256": previous.sha256,
    }
    _validate_package_qualification_binding(expected_qualification_binding)
    if args.expected_candidate_artifact_name != (
        "syswarden-packages-" + binding.version.removeprefix("v")
    ):
        _fail("candidate package artifact name does not match the release version")
    candidate_dir_stat = candidate.directory.stat()
    previous_dir_stat = previous.directory.stat()
    if candidate.directory == previous.directory or (
        candidate_dir_stat.st_dev,
        candidate_dir_stat.st_ino,
    ) == (previous_dir_stat.st_dev, previous_dir_stat.st_ino):
        _fail("candidate and previous package directories must be distinct")
    identities = _package_identity_set(candidate, previous)
    if len(identities) != len(candidate.snapshots) + len(previous.snapshots):
        _fail("candidate and previous package evidence must not share files/inodes")
    raw_identities = {
        (item.snapshot.device, item.snapshot.inode) for item in all_raws
    }
    if raw_identities & identities:
        _fail("raw reports must not alias candidate or previous package evidence")
    if (
        candidate.directory.name != "candidate"
        or previous.directory.name != "previous"
        or candidate.directory.parent.name != "packages"
        or previous.directory.parent != candidate.directory.parent
    ):
        _fail("package directories do not match packages/{candidate,previous}")
    artifact_root = candidate.directory.parent.parent
    if any(
        raw.snapshot.path.parent.name != "raw"
        or raw.snapshot.path.parent.parent != artifact_root
        for raw in all_raws
    ):
        _fail("raw reports and package directories do not share the exact artifact layout")
    for old_name, new_name in zip(gate.package_names("v" + previous_version), gate.package_names(binding.version)):
        if previous.checksums[old_name] == candidate.checksums[new_name]:
            _fail(f"previous and candidate package bytes are identical: {old_name}/{new_name}")
    nft = _validate_nft(raws["nft"].document, binding)
    package = _validate_package(
        raws["package"].document,
        binding,
        candidate,
        previous,
        package_shards,
        expected_qualification_binding,
    )
    generated_at = min(timestamps).isoformat()
    bindings = {
        "commit_sha": binding.commit_sha,
        "tree_sha": binding.tree_sha,
        "version": binding.version,
        "tag": binding.version,
        "package_manifest_sha256": candidate.sha256,
        "package_checksums": candidate.checksums,
    }
    envelopes = {
        "nft": gate.build_bound_report(kind="nftables_kernel", generated_at=generated_at, raw_report_sha256=raws["nft"].snapshot.sha256, bindings=bindings, **nft),
        "package": gate.build_bound_report(kind="linux_package_lifecycle", generated_at=generated_at, raw_report_sha256=raws["package"].snapshot.sha256, bindings=bindings, **package),
    }
    _revalidate_all(binding, candidate, previous, raws, package_shards)
    return ValidatedInputs(
        binding,
        candidate,
        previous,
        raws,
        package_shards,
        envelopes,
    )


def _destination_paths(args: argparse.Namespace) -> dict[str, Path]:
    if args.command == "build":
        return {"nft": args.nft_output, "package": args.package_output}
    return {"nft": args.nft_envelope, "package": args.package_envelope}


def _validate_destinations(paths: dict[str, Path], state: ValidatedInputs, *, must_exist: bool) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    protected = {
        (item.snapshot.device, item.snapshot.inode)
        for item in (*state.raws.values(), *state.package_shards.values())
    } | _package_identity_set(state.candidate, state.previous)
    existing: set[tuple[int, int]] = set()
    for key, path in paths.items():
        if path.name != OUTPUT_NAMES[key]:
            _fail(f"{key} envelope basename must be exactly {OUTPUT_NAMES[key]!r}")
        absolute = gate._absolute_without_symlinks(path, f"{key} envelope", leaf_may_absent=not must_exist)
        artifact_root = state.candidate.directory.parent.parent
        if absolute.parent.name != "bound" or absolute.parent.parent != artifact_root:
            _fail(f"{key} envelope does not match the exact bound/ artifact layout")
        if _inside(absolute, state.binding.root) or _inside(absolute, state.candidate.directory) or _inside(absolute, state.previous.directory):
            _fail(f"{key} envelope must be outside the repository and package directories")
        resolved[key] = absolute
        if absolute.exists():
            metadata = absolute.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                _fail(f"{key} envelope must be a regular non-symlink file")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in protected or identity in existing:
                _fail(f"{key} envelope aliases raw/package/other envelope evidence")
            existing.add(identity)
        elif must_exist:
            _fail(f"{key} envelope does not exist")
    if len(set(resolved.values())) != 2:
        _fail("the two envelope paths must be distinct")
    return resolved


def run_build(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    destinations = _validate_destinations(_destination_paths(args), state, must_exist=False)
    for key, destination in destinations.items():
        gate.write_atomic(destination, state.envelopes[key], state.binding.root)
    snapshots = {key: gate.read_snapshot(path, f"{key} generated envelope") for key, path in destinations.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 2:
        _fail("generated envelopes do not have distinct inodes")
    for key, snapshot in snapshots.items():
        if snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope atomic write was not byte-exact")
    _revalidate_all(
        state.binding,
        state.candidate,
        state.previous,
        state.raws,
        state.package_shards,
    )
    return state.envelopes


def run_verify(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    paths = _validate_destinations(_destination_paths(args), state, must_exist=True)
    snapshots = {key: gate.read_snapshot(path, f"{key} envelope") for key, path in paths.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 2:
        _fail("the two envelopes must have distinct inodes")
    for key, snapshot in snapshots.items():
        document = gate.strict_json(snapshot.payload, f"{key} envelope")
        if document != state.envelopes[key] or snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope is not the byte-exact canonical recomputation")
    for key, snapshot in snapshots.items():
        gate.revalidate(snapshot, f"{key} envelope")
    _revalidate_all(
        state.binding,
        state.candidate,
        state.previous,
        state.raws,
        state.package_shards,
    )
    return state.envelopes


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--candidate-packages-dir", type=Path, required=True)
    parser.add_argument("--previous-packages-dir", type=Path, required=True)
    parser.add_argument("--nft-raw", type=Path, required=True)
    parser.add_argument("--package-raw", type=Path, required=True)
    parser.add_argument("--package-amd64-shard", type=Path, required=True)
    parser.add_argument("--package-arm64-shard", type=Path, required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-workflow-run-id", type=int, required=True)
    parser.add_argument("--expected-workflow-run-attempt", type=int, required=True)
    parser.add_argument("--expected-candidate-run-id", type=int, required=True)
    parser.add_argument("--expected-candidate-artifact-id", type=int, required=True)
    parser.add_argument("--expected-candidate-artifact-name", required=True)
    parser.add_argument("--expected-previous-release-id", type=int, required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    parser.add_argument("--max-report-skew-seconds", type=int, default=300)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build bound qualification envelopes")
    _common_arguments(build)
    build.add_argument("--nft-output", type=Path, required=True)
    build.add_argument("--package-output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify byte-exact bound envelopes")
    _common_arguments(verify)
    verify.add_argument("--nft-envelope", type=Path, required=True)
    verify.add_argument("--package-envelope", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        envelopes = run_build(args) if args.command == "build" else run_verify(args)
    except (gate.EvidenceError, package_lab.LifecycleLabError, OSError, ValueError) as exc:
        print(f"release qualification adapter invalid: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(envelopes, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
