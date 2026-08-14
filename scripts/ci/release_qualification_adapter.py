#!/usr/bin/env python3
"""Strictly bind raw SysWarden runtime-lab reports to release evidence.

The laboratory reports deliberately contain no Git or release-package binding.
This adapter validates their exact schemas, independently re-verifies the Git
checkout and both package sets, derives all qualification decisions from nested
evidence, and emits the three canonical envelopes consumed by
``release_qualification_gate.py``.
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

import freebsd_vm_lab as freebsd_lab
import package_lifecycle_lab as package_lab
import release_qualification_gate as gate


OUTPUT_NAMES = {
    "nft": "nftables-bound.json",
    "package": "package-lifecycle-bound.json",
    "freebsd": "freebsd-vm-bound.json",
}
RAW_NAMES = {
    "nft": "nftables-raw.json",
    "package": "package-lifecycle-raw.json",
    "freebsd": "freebsd-vm-raw.json",
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
        }
    ),
    "freebsd": frozenset(
        {
            "schema_version",
            "generated_at",
            "harness_status",
            "product_status",
            "release_ready",
            "blocker_ids",
            "unexpected_failed_check_ids",
            "scope",
            "environment",
            "inputs",
            "restart_metadata_inventories",
            "lifecycle_phases",
            "harness_conditions",
            "checks",
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
        "exact_ruleset_rejected",
        "exact_ruleset_left_no_objects",
        "kernel_reported_invalid_port",
        "honeyport_only_normalization_passed_syntax_check",
        "isolated_ruleset_cleanup_succeeded",
    }
    conditions = _exact_keys(document["conditions"], condition_keys, "nft.conditions")
    if any(_boolean(value, f"nft.conditions.{key}") is not True for key, value in conditions.items()):
        _fail("nft raw report no longer proves the exact reviewed kernel blocker")
    if "Service out of range" not in _string(document["kernel_error"], "nft.kernel_error"):
        _fail("nft kernel error does not prove the reviewed invalid-port rejection")
    _string(document["summary"], "nft.summary")
    derived_harness = all(conditions.values()) and engine["rootless"] is True
    if (
        document["harness_status"] != ("pass" if derived_harness else "fail")
        or document["product_status"] != "known_blocker"
        or _boolean(document["release_ready"], "nft.release_ready") is not False
        or document["finding_id"] != "SW-FW-004"
    ):
        _fail("nft top-level classification is inconsistent with nested evidence")

    # Bind the characterization to the reviewed source and pinned Act image in HEAD.
    golden = gate._blob(binding.root, "testdata/firewall/nftables-v4.02.8.nft")
    loader = gate._blob(binding.root, "src/core/syswarden-cli/config/config_loader.go")
    generator = gate._blob(
        binding.root, "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
    )
    if (
        golden.count("tcp dport { 236379 }") != 2
        or 'strings.Join(m.Security.Honeyports, " ")' not in loader
        or 'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")' not in generator
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
        "release_ready": False,
        "blocker_ids": ["SW-FW-004"],
        "conditions": {
            "network_namespace_isolated": conditions["separate_network_namespace"],
            "host_namespace_untouched": (
                engine["rootless"] is True
                and engine["network"] == "none"
                and host_namespace != lab_namespace
            ),
            "kernel_apply_executed": conditions["exact_ruleset_rejected"],
            "cleanup_complete": (
                conditions["exact_ruleset_left_no_objects"]
                and conditions["isolated_ruleset_cleanup_succeeded"]
            ),
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
        "freebsd",
    }
)
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


def _validate_package_schema(document: dict[str, Any]) -> None:
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
    if normalized_host_architecture is None:
        _fail("package host architecture is unsupported or ambiguous")
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
    freebsd_gap = _exact_keys(scope["freebsd"], {"status", "reason"}, "package.scope.freebsd")
    if freebsd_gap["status"] != "vm_required" or not _string(freebsd_gap["reason"], "package.scope.freebsd.reason"):
        _fail("package raw report does not preserve the explicit FreeBSD VM gap")

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
        native_coordinate = spec.architecture == normalized_host_architecture
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
) -> dict[str, Any]:
    _validate_package_schema(document)
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
    if blockers not in (
        [],
        ["SW-CFG-001"],
        ["SW-PKG-001"],
        ["SW-CFG-001", "SW-PKG-001"],
    ):
        _fail("package lifecycle blocker mapping is not canonical")
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
            if not name.endswith(".txz")
        },
    }
    return {
        "harness_complete": True,
        "release_ready": classification["release_ready"],
        "blocker_ids": blockers,
        "coordinates": coordinates,
        "lifecycle": lifecycle,
    }


FREEBSD_SCOPE_KEYS = frozenset(
    {
        "guest",
        "ssh_endpoint",
        "ssh_scope",
        "host_firewall_mutation",
        "pf_scope",
        "guest_lock",
        "pf_snapshot",
        "lifecycle",
        "remove_purge_semantics",
        "signature_probe",
        "restart_inventory",
        "vm_disposition",
    }
)
FREEBSD_SCOPE_STATIC = {
    "guest": "explicitly marked disposable FreeBSD VM",
    "ssh_scope": "local loopback only",
    "pf_scope": "unique unattached anchor plus disposable-VM package behavior",
    "guest_lock": "atomic root-owned /var/run lock held through PF restoration",
    "pf_snapshot": "empty guest ruleset and exact Disabled status captured before mutation and restored after cleanup",
    "lifecycle": "previous install -> candidate upgrade -> candidate reinstall -> previous rollback -> pkg delete",
    "remove_purge_semantics": "FreeBSD pkg has no separate purge operation; pkg delete must remove package-owned artifacts and preserve unowned operator state",
    "signature_probe": "each installed phase temporarily presents the packaged database at the core's hard-coded runtime path, requires exactly 78 rule definitions and a real loader report of 194 effective signatures, then trap-restores and verifies exact type/bytes/mode/uid/gid or absence",
    "restart_inventory": "complete scoped path/type/mode/uid/gid/link inventory must remain identical after both restart cycles",
    "vm_disposition": "discard or externally revert the disposable VM snapshot after the lab; the installer intentionally mutates guest state beyond package and PF paths",
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FREEBSD_PHASE_KEYS = frozenset({"operation_return_code", "package", "user_state", "signatures"})
FREEBSD_CHECK_KEYS = frozenset({"id", "category", "status", "expected", "observed", "detail"})
PHASE_PREFIXES = (
    ("PREVIOUS-INSTALL", "previous_install"),
    ("CANDIDATE-UPGRADE", "candidate_upgrade"),
    ("CANDIDATE-REINSTALL", "candidate_reinstall"),
    ("CANDIDATE-RESTART-IDEMPOTENCE", "candidate_restart_idempotence"),
    ("PREVIOUS-ROLLBACK", "previous_rollback"),
)
PHASE_SUFFIXES = ("", "-ABI", "-ELF", "-INVENTORY", "-STATE", "-SIGNATURES", "-SIGNATURE-RESTORE")
FREEBSD_TAIL_CHECKS = (
    "SW-PKG-FBSD-MODE-CLI-001", "SW-PKG-FBSD-MODE-CORE-001", "SW-PKG-FBSD-MODE-TUI-001", "SW-PKG-FBSD-MODE-SIG-001",
    "SW-PKG-FBSD-LINK-CLI-001", "SW-PKG-FBSD-LINK-TUI-001", "SW-PKG-FBSD-EXEC-DIRECT-001", "SW-PKG-FBSD-EXEC-LINK-001",
    "SW-PKG-FBSD-SIG-PACKAGED-001", "SW-PKG-FBSD-PREFIX-001", "SW-PKG-FBSD-RCD-CORE-001", "SW-PKG-FBSD-RCD-WEB-001",
    "SW-PKG-FBSD-RCD-CORE-PATH-001", "SW-PKG-FBSD-RCD-WEB-PATH-001", "SW-PKG-FBSD-RCD-ENABLE-001", "SW-PKG-FBSD-START-CORE-001",
    "SW-PKG-FBSD-RESTART-CORE-001", "SW-PKG-FBSD-START-WEB-001", "SW-PKG-FBSD-RESTART-WEB-001", "SW-PKG-FBSD-RESTART-METADATA-001",
    "SW-PF-FBSD-FIXTURE-SYNTAX-001", "SW-PF-FBSD-FIXTURE-APPLY-001", "SW-PF-FBSD-HONEYPORT-001", "SW-PKG-FBSD-REMOVE-001",
    "SW-PKG-FBSD-REMOVE-STATE-001", "SW-PKG-FBSD-RCD-CLEANUP-001",
)


def _expected_freebsd_checks() -> list[str]:
    result = [f"SW-PKG-FBSD-{prefix}{suffix}-001" for prefix, _ in PHASE_PREFIXES for suffix in PHASE_SUFFIXES]
    result.extend(FREEBSD_TAIL_CHECKS)
    return result


def _dict_strings(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    result = _exact_keys(value, keys, label)
    for key in keys:
        _string(result[key], f"{label}.{key}", empty=True)
    return result


def _marker_boolean(value: Any, label: str) -> bool:
    marker = _string(value, label, empty=True)
    if marker not in {"0", "1"}:
        _fail(f"{label} must be the exact marker '0' or '1'")
    return marker == "1"


def _freebsd_check_passes(check_id: str, observed: Any, versions: dict[str, str]) -> bool:
    for prefix, phase in PHASE_PREFIXES:
        stem = f"SW-PKG-FBSD-{prefix}"
        if not check_id.startswith(stem):
            continue
        suffix = check_id[len(stem) : -4]
        if suffix == "":
            value = _dict_strings(observed, {"return_code", "installed", "name", "version", "architecture"}, f"{check_id}.observed")
            return value["return_code"] == "0" and value["installed"] == "1" and value["name"] == "syswarden" and value["version"] == versions[phase]
        if suffix == "-ABI":
            return _string(observed, f"{check_id}.observed", empty=True) == freebsd_lab.EXPECTED_FREEBSD_PACKAGE_ABI
        if suffix == "-ELF":
            value = _dict_strings(observed, {"cli", "core", "tui"}, f"{check_id}.observed")
            return set(value.values()) == {freebsd_lab.EXPECTED_NATIVE_ELF_ARCH}
        if suffix == "-INVENTORY":
            return _string_list(observed, f"{check_id}.observed", sorted_unique=True) == sorted(freebsd_lab.EXPECTED_PACKAGE_INVENTORY)
        if suffix == "-STATE":
            value = _exact_keys(observed, {"inventory", "config_sha256", "data_sha256"}, f"{check_id}.observed")
            return _string_list(value["inventory"], f"{check_id}.observed.inventory", sorted_unique=True) == sorted(freebsd_lab.EXPECTED_USER_STATE_INVENTORY) and value["config_sha256"] == freebsd_lab.USER_CONFIG_SHA256 and value["data_sha256"] == freebsd_lab.USER_DATA_SHA256
        if suffix == "-SIGNATURES":
            value = _dict_strings(observed, {"rule_definitions", "engine_loaded", "probe_return_code", "loader_error", "runtime_state_before", "runtime_state_after", "runtime_state_restored"}, f"{check_id}.observed")
            return value["rule_definitions"] == str(freebsd_lab.EXPECTED_SIGNATURE_RULE_COUNT) and value["engine_loaded"] == str(freebsd_lab.EXPECTED_ENGINE_SIGNATURE_COUNT) and value["probe_return_code"] == "124" and value["loader_error"] == "0"
        if suffix == "-SIGNATURE-RESTORE":
            value = _dict_strings(observed, {"before", "after", "restored"}, f"{check_id}.observed")
            return freebsd_lab.valid_signature_state(value["before"]) and value["before"] == value["after"] and value["restored"] == "1"
    exact_strings = {
        "SW-PKG-FBSD-MODE-CLI-001": "750", "SW-PKG-FBSD-MODE-CORE-001": "750", "SW-PKG-FBSD-MODE-TUI-001": "750", "SW-PKG-FBSD-MODE-SIG-001": "640",
        "SW-PKG-FBSD-LINK-CLI-001": "/usr/local/syswarden/bin/syswarden-cli", "SW-PKG-FBSD-LINK-TUI-001": "/usr/local/syswarden/bin/syswarden-tui",
        "SW-PKG-FBSD-EXEC-DIRECT-001": "0", "SW-PKG-FBSD-EXEC-LINK-001": "0",
        "SW-PKG-FBSD-RCD-CORE-PATH-001": "/usr/local/syswarden/bin/syswarden-core", "SW-PKG-FBSD-RCD-WEB-PATH-001": "/usr/local/syswarden/bin/syswarden-cli",
        "SW-PF-FBSD-FIXTURE-SYNTAX-001": "0",
    }
    if check_id in exact_strings:
        return _string(observed, f"{check_id}.observed", empty=True) == exact_strings[check_id]
    if check_id in {"SW-PKG-FBSD-SIG-PACKAGED-001", "SW-PKG-FBSD-PREFIX-001"}:
        return _boolean(observed, f"{check_id}.observed") is True
    if check_id in {"SW-PKG-FBSD-RCD-CORE-001", "SW-PKG-FBSD-RCD-WEB-001"}:
        value = _dict_strings(observed, {"present", "mode"}, f"{check_id}.observed")
        return value == {"present": "1", "mode": "755"}
    if check_id == "SW-PKG-FBSD-RCD-ENABLE-001":
        return _dict_strings(observed, {"core", "web"}, f"{check_id}.observed") == {"core": "YES", "web": "YES"}
    if check_id in {"SW-PKG-FBSD-START-CORE-001", "SW-PKG-FBSD-START-WEB-001"}:
        return set(_dict_strings(observed, {"start", "status"}, f"{check_id}.observed").values()) == {"0"}
    if check_id in {"SW-PKG-FBSD-RESTART-CORE-001", "SW-PKG-FBSD-RESTART-WEB-001"}:
        value = _exact_keys(observed, set(observed) if type(observed) is dict else set(), f"{check_id}.observed")
        if len(value) != 4 or any(type(item) is not str for item in value.values()):
            _fail(f"{check_id}.observed has an invalid restart schema")
        return set(value.values()) == {"0"}
    if check_id == "SW-PKG-FBSD-RESTART-METADATA-001":
        value = _exact_keys(observed, {"baseline", "after_first_restart", "after_second_restart"}, f"{check_id}.observed")
        inventories = [value[key] for key in ("baseline", "after_first_restart", "after_second_restart")]
        return all(type(item) is list and item for item in inventories) and inventories[0] == inventories[1] == inventories[2]
    if check_id == "SW-PF-FBSD-FIXTURE-APPLY-001":
        value = _dict_strings(observed, {"return_code", "rules"}, f"{check_id}.observed")
        return value["return_code"] == "0" and value["rules"].isdigit() and int(value["rules"]) > 0
    if check_id == "SW-PF-FBSD-HONEYPORT-001":
        value = _exact_keys(observed, {"source_concatenates_ports", "exact_port_value", "native_syntax_return_code"}, f"{check_id}.observed")
        _boolean(value["source_concatenates_ports"], f"{check_id}.observed.source_concatenates_ports")
        _string(value["exact_port_value"], f"{check_id}.observed.exact_port_value", empty=True)
        _string(value["native_syntax_return_code"], f"{check_id}.observed.native_syntax_return_code", empty=True)
        return value == {"source_concatenates_ports": False, "exact_port_value": "", "native_syntax_return_code": "not_run"}
    if check_id == "SW-PKG-FBSD-REMOVE-001":
        value = _exact_keys(observed, {"return_code", "package_absent", "inventory", "payload_absent", "links_absent"}, f"{check_id}.observed")
        _string_list(value["inventory"], f"{check_id}.observed.inventory", sorted_unique=True)
        return all(value[key] == "1" for key in ("package_absent", "payload_absent", "links_absent")) and value["return_code"] == "0" and value["inventory"] == []
    if check_id == "SW-PKG-FBSD-REMOVE-STATE-001":
        value = _exact_keys(observed, {"inventory", "config_sha256", "data_sha256"}, f"{check_id}.observed")
        return _string_list(value["inventory"], f"{check_id}.observed.inventory", sorted_unique=True) == sorted(freebsd_lab.EXPECTED_USER_STATE_INVENTORY) and value["config_sha256"] == freebsd_lab.USER_CONFIG_SHA256 and value["data_sha256"] == freebsd_lab.USER_DATA_SHA256
    if check_id == "SW-PKG-FBSD-RCD-CLEANUP-001":
        value = _exact_keys(observed, set(observed) if type(observed) is dict else set(), f"{check_id}.observed")
        return len(value) == 4 and set(value.values()) == {"1"}
    _fail(f"unsupported FreeBSD check ID: {check_id}")
    raise AssertionError


def _freebsd_blocker(
    check_id: str,
    observed: dict[str, Any],
    phases: dict[str, Any],
) -> str | None:
    mapped = freebsd_lab.EXPECTED_FAILED_CHECK_BLOCKERS.get(check_id)
    if mapped is None:
        return None
    if check_id in freebsd_lab.ABI_CHECK_PHASES:
        return mapped if observed[check_id] == freebsd_lab.KNOWN_LEGACY_FREEBSD_PACKAGE_ABI else None
    if check_id in freebsd_lab.PREVIOUS_MIXED_ELF_CHECK_PHASES:
        phase_prefix = check_id.removeprefix("SW-PKG-FBSD-").split("-ELF-001", 1)[0].split("-SIGNATURES-001", 1)[0]
        phase_name = dict(PHASE_PREFIXES).get(phase_prefix)
        if phase_name is None:
            return None
        elf = phases[phase_name]["package"]["elf_architectures"]
        if elf != {"cli": "amd64", "core": "arm64", "tui": "arm64"}:
            return None
        if check_id.endswith("-SIGNATURES-001"):
            value = observed[check_id]
            return mapped if value["rule_definitions"] == str(freebsd_lab.EXPECTED_SIGNATURE_RULE_COUNT) and value["engine_loaded"] == "" and value["probe_return_code"] == "2" and value["loader_error"] == "0" and value["runtime_state_restored"] == "1" and freebsd_lab.valid_signature_state(value["runtime_state_before"]) and value["runtime_state_before"] == value["runtime_state_after"] else None
        return mapped
    prefix_mismatch = observed["SW-PKG-FBSD-SIG-PACKAGED-001"] is True and observed["SW-PKG-FBSD-PREFIX-001"] is False
    starts = ("SW-PKG-FBSD-START-CORE-001", "SW-PKG-FBSD-RESTART-CORE-001", "SW-PKG-FBSD-START-WEB-001", "SW-PKG-FBSD-RESTART-WEB-001")
    all_start_values_one = all(type(observed[item]) is dict and set(observed[item].values()) == {"1"} for item in starts)
    exact_missing_rcd = prefix_mismatch and observed["SW-PKG-FBSD-RCD-CORE-001"] == {"present": "0", "mode": ""} and observed["SW-PKG-FBSD-RCD-WEB-001"] == {"present": "0", "mode": ""} and observed["SW-PKG-FBSD-RCD-CORE-PATH-001"] == "" and observed["SW-PKG-FBSD-RCD-WEB-PATH-001"] == "" and observed["SW-PKG-FBSD-RCD-ENABLE-001"] == {"core": "", "web": ""} and all_start_values_one and phases["candidate_restart_idempotence"]["operation_return_code"] == "1"
    legacy_paths = observed["SW-PKG-FBSD-RCD-CORE-PATH-001"] == freebsd_lab.KNOWN_FREEBSD_CORE_COMMAND and observed["SW-PKG-FBSD-RCD-WEB-PATH-001"] == freebsd_lab.KNOWN_FREEBSD_WEB_COMMAND
    absence_ids = {"SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-001", "SW-PKG-FBSD-RCD-CORE-001", "SW-PKG-FBSD-RCD-WEB-001", "SW-PKG-FBSD-RCD-ENABLE-001"}
    path_ids = {"SW-PKG-FBSD-RCD-CORE-PATH-001", "SW-PKG-FBSD-RCD-WEB-PATH-001"}
    runtime_ids = set(starts)
    if check_id == "SW-PKG-FBSD-PREFIX-001":
        return mapped if prefix_mismatch else None
    if check_id in absence_ids:
        return mapped if exact_missing_rcd else None
    if check_id in path_ids:
        return mapped if exact_missing_rcd or legacy_paths else None
    if check_id in runtime_ids:
        return mapped if exact_missing_rcd or (legacy_paths and all_start_values_one) else None
    honey = observed["SW-PF-FBSD-HONEYPORT-001"]
    exact_honey = honey == {"source_concatenates_ports": True, "exact_port_value": "236379", "native_syntax_return_code": "1"}
    if check_id == "SW-PF-FBSD-HONEYPORT-001":
        return mapped if exact_honey else None
    if check_id == "SW-PF-FBSD-FIXTURE-SYNTAX-001":
        return mapped if exact_honey and observed[check_id] == "1" else None
    if check_id == "SW-PF-FBSD-FIXTURE-APPLY-001":
        return mapped if exact_honey and observed["SW-PF-FBSD-FIXTURE-SYNTAX-001"] == "1" and observed[check_id] == {"return_code": "125", "rules": "0"} else None
    return None


def _validate_freebsd_schema(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    _exact_keys(document, RAW_TOP_KEYS["freebsd"], "freebsd raw report")
    if _integer(document["schema_version"], "freebsd.schema_version") != 2:
        _fail("FreeBSD raw report schema version must be 2")
    scope = _exact_keys(document["scope"], FREEBSD_SCOPE_KEYS, "freebsd.scope")
    for key in FREEBSD_SCOPE_KEYS - {"host_firewall_mutation"}:
        _string(scope[key], f"freebsd.scope.{key}")
    if _boolean(scope["host_firewall_mutation"], "freebsd.scope.host_firewall_mutation") is not False or scope["ssh_scope"] != "local loopback only":
        _fail("FreeBSD raw report does not prove VM-only mutation and loopback SSH")
    if any(scope[key] != value for key, value in FREEBSD_SCOPE_STATIC.items()):
        _fail("FreeBSD scope differs from the reviewed disposable-VM contract")
    endpoint_match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", scope["ssh_endpoint"])
    if (
        endpoint_match is None
        or int(endpoint_match.group(1)) < 1
        or int(endpoint_match.group(1)) > 65535
    ):
        _fail("FreeBSD SSH endpoint is not an explicit local-loopback port")
    environment = _exact_keys(document["environment"], {"os", "release", "machine", "pf_interface", "pf_initial_status", "pf_final_status", "pf_snapshot_sha256", "pf_anchor"}, "freebsd.environment")
    for key in ("os", "release", "machine", "pf_interface", "pf_initial_status", "pf_final_status", "pf_anchor"):
        _string(environment[key], f"freebsd.environment.{key}")
    _sha256(environment["pf_snapshot_sha256"], "freebsd.environment.pf_snapshot_sha256")
    if environment["os"] != "FreeBSD" or not environment["release"].startswith("14.4-RELEASE") or environment["machine"] != "amd64" or freebsd_lab.ANCHOR_NAME_PATTERN.fullmatch(environment["pf_anchor"]) is None:
        _fail("FreeBSD guest/environment identity is invalid")
    if (
        environment["pf_initial_status"] != "Disabled"
        or environment["pf_final_status"] != "Disabled"
        or environment["pf_snapshot_sha256"] != EMPTY_SHA256
    ):
        _fail("FreeBSD PF baseline was not restored to the exact disabled empty snapshot")
    inputs = _exact_keys(document["inputs"], {"candidate", "previous", "pf_fixture", "pf_fixture_sha256", "pf_fixture_guest_sha256"}, "freebsd.inputs")
    for side in ("candidate", "previous"):
        item = _exact_keys(inputs[side], {"package", "version", "sha256"}, f"freebsd.inputs.{side}")
        _string(item["package"], f"freebsd.inputs.{side}.package")
        _string(item["version"], f"freebsd.inputs.{side}.version")
        _sha256(item["sha256"], f"freebsd.inputs.{side}.sha256")
    _string(inputs["pf_fixture"], "freebsd.inputs.pf_fixture")
    _sha256(inputs["pf_fixture_sha256"], "freebsd.inputs.pf_fixture_sha256")
    _sha256(inputs["pf_fixture_guest_sha256"], "freebsd.inputs.pf_fixture_guest_sha256")
    inventories = _exact_keys(document["restart_metadata_inventories"], {"baseline", "after_first_restart", "after_second_restart"}, "freebsd.restart_metadata_inventories")
    for key in inventories:
        _string_list(inventories[key], f"freebsd.restart_metadata_inventories.{key}", sorted_unique=True)
    phases = _exact_keys(document["lifecycle_phases"], {item[1] for item in PHASE_PREFIXES} | {"remove"}, "freebsd.lifecycle_phases")
    for _, phase_name in PHASE_PREFIXES:
        phase = _exact_keys(phases[phase_name], FREEBSD_PHASE_KEYS, f"freebsd.lifecycle_phases.{phase_name}")
        _string(phase["operation_return_code"], f"freebsd.lifecycle_phases.{phase_name}.operation_return_code", empty=True)
        package = _exact_keys(phase["package"], {"installed", "name", "version", "architecture", "elf_architectures", "inventory"}, f"freebsd.lifecycle_phases.{phase_name}.package")
        _boolean(package["installed"], f"freebsd.lifecycle_phases.{phase_name}.package.installed")
        for key in ("name", "version", "architecture"):
            _string(package[key], f"freebsd.lifecycle_phases.{phase_name}.package.{key}", empty=True)
        elf = _exact_keys(package["elf_architectures"], {"cli", "core", "tui"}, f"freebsd.lifecycle_phases.{phase_name}.package.elf_architectures")
        for key, value in elf.items():
            if _string(value, f"freebsd.lifecycle_phases.{phase_name}.package.elf_architectures.{key}") not in {"amd64", "arm64", "invalid"}:
                _fail("FreeBSD ELF architecture evidence is not normalized")
        _string_list(package["inventory"], f"freebsd.lifecycle_phases.{phase_name}.package.inventory", sorted_unique=True)
        user_state = _exact_keys(phase["user_state"], {"inventory", "config_sha256", "data_sha256"}, f"freebsd.lifecycle_phases.{phase_name}.user_state")
        _string_list(user_state["inventory"], f"freebsd.lifecycle_phases.{phase_name}.user_state.inventory", sorted_unique=True)
        _sha256(user_state["config_sha256"], f"freebsd.lifecycle_phases.{phase_name}.user_state.config_sha256")
        _sha256(user_state["data_sha256"], f"freebsd.lifecycle_phases.{phase_name}.user_state.data_sha256")
        signatures = _exact_keys(phase["signatures"], {"rule_definitions", "engine_loaded", "probe_return_code", "loader_error", "runtime_state_before", "runtime_state_after", "runtime_state_restored"}, f"freebsd.lifecycle_phases.{phase_name}.signatures")
        for key in ("rule_definitions", "engine_loaded", "probe_return_code", "runtime_state_before", "runtime_state_after"):
            _string(signatures[key], f"freebsd.lifecycle_phases.{phase_name}.signatures.{key}", empty=True)
        _boolean(signatures["loader_error"], f"freebsd.lifecycle_phases.{phase_name}.signatures.loader_error")
        _boolean(signatures["runtime_state_restored"], f"freebsd.lifecycle_phases.{phase_name}.signatures.runtime_state_restored")
    remove = _exact_keys(phases["remove"], {"operation_return_code", "package_absent", "package_inventory", "user_state", "semantics"}, "freebsd.lifecycle_phases.remove")
    _string(remove["operation_return_code"], "freebsd.lifecycle_phases.remove.operation_return_code", empty=True)
    _boolean(remove["package_absent"], "freebsd.lifecycle_phases.remove.package_absent")
    _string_list(remove["package_inventory"], "freebsd.lifecycle_phases.remove.package_inventory", sorted_unique=True)
    _string(remove["semantics"], "freebsd.lifecycle_phases.remove.semantics")
    remove_state = _exact_keys(remove["user_state"], {"inventory", "config_sha256", "data_sha256"}, "freebsd.lifecycle_phases.remove.user_state")
    _string_list(remove_state["inventory"], "freebsd.lifecycle_phases.remove.user_state.inventory", sorted_unique=True)
    _sha256(remove_state["config_sha256"], "freebsd.lifecycle_phases.remove.user_state.config_sha256")
    _sha256(remove_state["data_sha256"], "freebsd.lifecycle_phases.remove.user_state.data_sha256")
    conditions = _exact_keys(document["harness_conditions"], set(freebsd_lab.harness_conditions({key: "" for key in freebsd_lab.EVIDENCE_KEYS})), "freebsd.harness_conditions")
    for key, value in conditions.items():
        _boolean(value, f"freebsd.harness_conditions.{key}")
    checks = _list(document["checks"], "freebsd.checks")
    expected_ids = _expected_freebsd_checks()
    if [item.get("id") if type(item) is dict else None for item in checks] != expected_ids:
        _fail("FreeBSD check inventory/order is not exact")
    versions = {
        "previous_install": inputs["previous"]["version"],
        "candidate_upgrade": inputs["candidate"]["version"],
        "candidate_reinstall": inputs["candidate"]["version"],
        "candidate_restart_idempotence": inputs["candidate"]["version"],
        "previous_rollback": inputs["previous"]["version"],
    }
    observed: dict[str, Any] = {}
    failed: list[str] = []
    for index, value in enumerate(checks):
        item = _exact_keys(value, FREEBSD_CHECK_KEYS, f"freebsd.checks[{index}]")
        check_id = _string(item["id"], f"freebsd.checks[{index}].id")
        _string(item["category"], f"freebsd.checks[{index}].category")
        _string(item["detail"], f"freebsd.checks[{index}].detail")
        if item["status"] not in {"pass", "blocker"}:
            _fail(f"freebsd.checks[{index}].status is invalid")
        observed[check_id] = item["observed"]
        derived_pass = _freebsd_check_passes(check_id, item["observed"], versions)
        if item["status"] != ("pass" if derived_pass else "blocker"):
            _fail(f"FreeBSD check {check_id} status is inconsistent with observed evidence")
        if not derived_pass:
            failed.append(check_id)

    # The raw schema deliberately carries both human-oriented lifecycle phases
    # and machine-oriented checks.  Neither representation may be edited
    # independently: require exact value equality for every duplicated fact.
    for prefix, phase_name in PHASE_PREFIXES:
        phase = phases[phase_name]
        package = phase["package"]
        user_state = phase["user_state"]
        signatures = phase["signatures"]
        stem = f"SW-PKG-FBSD-{prefix}"
        lifecycle_observed = observed[f"{stem}-001"]
        abi_observed = observed[f"{stem}-ABI-001"]
        elf_observed = observed[f"{stem}-ELF-001"]
        inventory_observed = observed[f"{stem}-INVENTORY-001"]
        state_observed = observed[f"{stem}-STATE-001"]
        signatures_observed = observed[f"{stem}-SIGNATURES-001"]
        restore_observed = observed[f"{stem}-SIGNATURE-RESTORE-001"]
        if (
            phase["operation_return_code"] != lifecycle_observed["return_code"]
            or package["installed"]
            != _marker_boolean(
                lifecycle_observed["installed"],
                f"{stem}-001.observed.installed",
            )
            or package["name"] != lifecycle_observed["name"]
            or package["version"] != lifecycle_observed["version"]
            or package["architecture"] != lifecycle_observed["architecture"]
            or package["architecture"] != abi_observed
            or package["elf_architectures"] != elf_observed
            or package["inventory"] != inventory_observed
            or user_state != state_observed
        ):
            _fail(
                f"FreeBSD lifecycle phase {phase_name} disagrees with its check evidence"
            )
        expected_signature_phase = {
            "rule_definitions": signatures_observed["rule_definitions"],
            "engine_loaded": signatures_observed["engine_loaded"],
            "probe_return_code": signatures_observed["probe_return_code"],
            "loader_error": _marker_boolean(
                signatures_observed["loader_error"],
                f"{stem}-SIGNATURES-001.observed.loader_error",
            ),
            "runtime_state_before": signatures_observed["runtime_state_before"],
            "runtime_state_after": signatures_observed["runtime_state_after"],
            "runtime_state_restored": _marker_boolean(
                signatures_observed["runtime_state_restored"],
                f"{stem}-SIGNATURES-001.observed.runtime_state_restored",
            ),
        }
        expected_restore_phase = {
            "runtime_state_before": restore_observed["before"],
            "runtime_state_after": restore_observed["after"],
            "runtime_state_restored": _marker_boolean(
                restore_observed["restored"],
                f"{stem}-SIGNATURE-RESTORE-001.observed.restored",
            ),
        }
        if signatures != expected_signature_phase or any(
            signatures[key] != value
            for key, value in expected_restore_phase.items()
        ):
            _fail(
                f"FreeBSD lifecycle phase {phase_name} signature evidence is inconsistent"
            )

    remove = phases["remove"]
    remove_observed = observed["SW-PKG-FBSD-REMOVE-001"]
    remove_state_observed = observed["SW-PKG-FBSD-REMOVE-STATE-001"]
    if (
        remove["operation_return_code"] != remove_observed["return_code"]
        or remove["package_absent"]
        != _marker_boolean(
            remove_observed["package_absent"],
            "SW-PKG-FBSD-REMOVE-001.observed.package_absent",
        )
        or remove["package_inventory"] != remove_observed["inventory"]
        or remove["user_state"] != remove_state_observed
        or remove["semantics"]
        != "pkg delete; no separate FreeBSD purge operation"
    ):
        _fail("FreeBSD removal phase disagrees with its check evidence")
    if document["restart_metadata_inventories"] != observed[
        "SW-PKG-FBSD-RESTART-METADATA-001"
    ]:
        _fail("FreeBSD restart phase inventory disagrees with its check evidence")
    return phases, observed, failed


def _validate_freebsd(
    document: dict[str, Any],
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
) -> dict[str, Any]:
    phases, observed, failed = _validate_freebsd_schema(document)
    blockers_for_failed = {item: _freebsd_blocker(item, observed, phases) for item in failed}
    derived_blockers = sorted({value for value in blockers_for_failed.values() if value})
    unexpected = sorted(item for item, value in blockers_for_failed.items() if value is None)
    if unexpected:
        _fail(f"FreeBSD report contains unexpected failed checks: {unexpected}")
    if not set(derived_blockers).issubset(freebsd_lab.CANONICAL_BLOCKER_IDS):
        _fail("FreeBSD report contains a non-canonical blocker")
    derived_product = "pass" if not failed else "known_blocker"
    inputs = document["inputs"]
    expected_candidate = next(name for name in candidate.checksums if name.endswith(".txz"))
    expected_previous = next(name for name in previous.checksums if name.endswith(".txz"))
    for side, item, manifest, name in (("candidate", inputs["candidate"], candidate, expected_candidate), ("previous", inputs["previous"], previous, expected_previous)):
        if item != {"package": name, "version": binding.version.removeprefix("v") if side == "candidate" else name.removeprefix("syswarden-").removesuffix(".txz"), "sha256": manifest.checksums[name]}:
            _fail(f"FreeBSD {side} package input does not match verified release assets")
    fixture_path = inputs["pf_fixture"]
    if fixture_path != "testdata/firewall/pf-v4.02.8.conf" or Path(fixture_path).is_absolute() or ".." in Path(fixture_path).parts:
        _fail("FreeBSD PF fixture path is not the reviewed repository-relative asset")
    fixture_sha = hashlib.sha256(_git_blob_bytes(binding, fixture_path)).hexdigest()
    if inputs["pf_fixture_sha256"] != fixture_sha or inputs["pf_fixture_guest_sha256"] != fixture_sha:
        _fail("FreeBSD PF fixture is not byte-bound to Git and the guest transfer")
    scope = document["scope"]
    environment = document["environment"]
    guest_identity = (
        environment["os"] == "FreeBSD"
        and environment["release"].startswith("14.4-RELEASE")
        and environment["machine"] == "amd64"
        and scope["guest"] == FREEBSD_SCOPE_STATIC["guest"]
    )
    clean_pf_baseline = (
        environment["pf_initial_status"] == "Disabled"
        and environment["pf_snapshot_sha256"] == EMPTY_SHA256
        and scope["pf_snapshot"] == FREEBSD_SCOPE_STATIC["pf_snapshot"]
    )
    anchor_valid = (
        freebsd_lab.ANCHOR_NAME_PATTERN.fullmatch(environment["pf_anchor"])
        is not None
        and scope["pf_scope"] == FREEBSD_SCOPE_STATIC["pf_scope"]
    )
    package_transfers = {
        "previous": inputs["previous"]["sha256"]
        == previous.checksums[expected_previous],
        "candidate": inputs["candidate"]["sha256"]
        == candidate.checksums[expected_candidate],
    }
    expected_conditions = {
        "root inside guest": guest_identity,
        "disposable VM marker revalidated": (
            guest_identity and scope["guest"] == FREEBSD_SCOPE_STATIC["guest"]
        ),
        "root-owned VM marker revalidated": (
            guest_identity and scope["guest_lock"] == FREEBSD_SCOPE_STATIC["guest_lock"]
        ),
        "FreeBSD 14.4 amd64 revalidated": guest_identity,
        "native tools available": (
            guest_identity and len(observed) == len(_expected_freebsd_checks())
        ),
        "clean disposable snapshot": clean_pf_baseline,
        "verified previous package transfer": package_transfers["previous"],
        "verified candidate package transfer": package_transfers["candidate"],
        "verified PF fixture transfer": (
            inputs["pf_fixture_sha256"] == fixture_sha
            and inputs["pf_fixture_guest_sha256"] == fixture_sha
        ),
        "exclusive guest lock": (
            scope["guest_lock"] == FREEBSD_SCOPE_STATIC["guest_lock"]
        ),
        "unique validated PF anchor": anchor_valid,
        "PF anchor removed": anchor_valid and clean_pf_baseline,
        "lab filesystem cleanup": (
            phases["remove"]["operation_return_code"] == "0"
            and phases["remove"]["package_absent"] is True
            and phases["remove"]["package_inventory"] == []
        ),
        "PF snapshot restored": (
            clean_pf_baseline
            and anchor_valid
            and environment["pf_final_status"] == "Disabled"
        ),
    }
    conditions = document["harness_conditions"]
    if conditions != expected_conditions:
        _fail("FreeBSD harness conditions are inconsistent with factual evidence")
    derived_harness = all(expected_conditions.values())
    derived_release = derived_harness and not failed
    if document["harness_status"] != ("pass" if derived_harness else "fail") or document["product_status"] != derived_product or _boolean(document["release_ready"], "freebsd.release_ready") != derived_release:
        _fail("FreeBSD top-level status is inconsistent with nested evidence")
    if _string_list(document["blocker_ids"], "freebsd.blocker_ids", sorted_unique=True) != derived_blockers or _string_list(document["unexpected_failed_check_ids"], "freebsd.unexpected_failed_check_ids", sorted_unique=True) != unexpected:
        _fail("FreeBSD top-level failure classification is not recomputed evidence")
    if not derived_harness:
        _fail("FreeBSD harness is incomplete")
    previous_version = inputs["previous"]["version"]
    candidate_version = inputs["candidate"]["version"]
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
        "previous_package_checksums": {expected_previous: previous.checksums[expected_previous]},
    }
    return {
        "harness_complete": True,
        "release_ready": derived_release,
        "blocker_ids": derived_blockers,
        "coordinates": [{"platform": "freebsd", "architecture": "amd64", "status": "pass" if derived_release else "blocker"}],
        "lifecycle": lifecycle,
    }


def _package_identity_set(*manifests: gate.PackageManifest) -> set[tuple[int, int]]:
    return {(item.device, item.inode) for manifest in manifests for item in manifest.snapshots}


def _revalidate_all(
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
    raws: dict[str, RawReport],
) -> None:
    for raw in raws.values():
        gate.revalidate(raw.snapshot, f"{raw.label} raw report")
    for manifest, label in ((candidate, "candidate package evidence"), (previous, "previous package evidence")):
        for snapshot in manifest.snapshots:
            gate.revalidate(snapshot, label)
    current_candidate = gate.verify_packages(candidate.directory, binding)
    previous_txz = next(
        name for name in previous.checksums if name.endswith(".txz")
    )
    previous_version = "v" + previous_txz.removeprefix("syswarden-").removesuffix(
        ".txz"
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
    raw_paths = {"nft": args.nft_raw, "package": args.package_raw, "freebsd": args.freebsd_raw}
    raws = {key: _load_raw(path, key, binding.root, current, args.max_age_seconds) for key, path in raw_paths.items()}
    for key, raw in raws.items():
        if raw.snapshot.path.name != RAW_NAMES[key]:
            _fail(f"{key} raw basename must be exactly {RAW_NAMES[key]!r}")
    if len({(item.snapshot.device, item.snapshot.inode) for item in raws.values()}) != 3 or len({item.snapshot.path for item in raws.values()}) != 3 or len({item.snapshot.path.name for item in raws.values()}) != 3:
        _fail("the three raw reports must have distinct files, inodes, paths, and basenames")
    timestamps = [item.generated_at for item in raws.values()]
    if max(timestamps) - min(timestamps) > timedelta(seconds=RAW_REPORT_MAX_SKEW_SECONDS):
        _fail("raw report timestamps exceed the bounded laboratory collection window")
    previous_version, _ = _package_versions(raws["package"].document, binding.version)
    freebsd_inputs = raws["freebsd"].document.get("inputs")
    if type(freebsd_inputs) is not dict or type(freebsd_inputs.get("previous")) is not dict or freebsd_inputs["previous"].get("version") != previous_version:
        _fail("Linux and FreeBSD raw reports do not bind the same previous version")
    previous_binding = gate.RepositoryBinding(binding.root, binding.commit_sha, binding.tree_sha, "v" + previous_version)
    previous = gate.verify_packages(args.previous_packages_dir, previous_binding)
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
        (item.snapshot.device, item.snapshot.inode) for item in raws.values()
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
        for raw in raws.values()
    ):
        _fail("raw reports and package directories do not share the exact artifact layout")
    for old_name, new_name in zip(gate.package_names("v" + previous_version), gate.package_names(binding.version)):
        if previous.checksums[old_name] == candidate.checksums[new_name]:
            _fail(f"previous and candidate package bytes are identical: {old_name}/{new_name}")
    nft = _validate_nft(raws["nft"].document, binding)
    package = _validate_package(raws["package"].document, binding, candidate, previous)
    freebsd = _validate_freebsd(raws["freebsd"].document, binding, candidate, previous)
    if package["lifecycle"]["previous_version"] != freebsd["lifecycle"]["previous_version"]:
        _fail("Linux and FreeBSD lifecycle evidence disagrees on the previous version")
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
        "package": gate.build_bound_report(kind="linux_package_lifecycle", generated_at=generated_at, raw_report_sha256=raws["package"].snapshot.sha256, bindings=bindings, real_freebsd_vm=False, **package),
        "freebsd": gate.build_bound_report(kind="freebsd_vm", generated_at=generated_at, raw_report_sha256=raws["freebsd"].snapshot.sha256, bindings=bindings, real_freebsd_vm=True, **freebsd),
    }
    _revalidate_all(binding, candidate, previous, raws)
    return ValidatedInputs(binding, candidate, previous, raws, envelopes)


def _destination_paths(args: argparse.Namespace) -> dict[str, Path]:
    if args.command == "build":
        return {"nft": args.nft_output, "package": args.package_output, "freebsd": args.freebsd_output}
    return {"nft": args.nft_envelope, "package": args.package_envelope, "freebsd": args.freebsd_envelope}


def _validate_destinations(paths: dict[str, Path], state: ValidatedInputs, *, must_exist: bool) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    protected = {(item.snapshot.device, item.snapshot.inode) for item in state.raws.values()} | _package_identity_set(state.candidate, state.previous)
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
    if len(set(resolved.values())) != 3:
        _fail("the three envelope paths must be distinct")
    return resolved


def run_build(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    destinations = _validate_destinations(_destination_paths(args), state, must_exist=False)
    for key, destination in destinations.items():
        gate.write_atomic(destination, state.envelopes[key], state.binding.root)
    snapshots = {key: gate.read_snapshot(path, f"{key} generated envelope") for key, path in destinations.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 3:
        _fail("generated envelopes do not have distinct inodes")
    for key, snapshot in snapshots.items():
        if snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope atomic write was not byte-exact")
    _revalidate_all(state.binding, state.candidate, state.previous, state.raws)
    return state.envelopes


def run_verify(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    paths = _validate_destinations(_destination_paths(args), state, must_exist=True)
    snapshots = {key: gate.read_snapshot(path, f"{key} envelope") for key, path in paths.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 3:
        _fail("the three envelopes must have distinct inodes")
    for key, snapshot in snapshots.items():
        document = gate.strict_json(snapshot.payload, f"{key} envelope")
        if document != state.envelopes[key] or snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope is not the byte-exact canonical recomputation")
    for key, snapshot in snapshots.items():
        gate.revalidate(snapshot, f"{key} envelope")
    _revalidate_all(state.binding, state.candidate, state.previous, state.raws)
    return state.envelopes


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--candidate-packages-dir", type=Path, required=True)
    parser.add_argument("--previous-packages-dir", type=Path, required=True)
    parser.add_argument("--nft-raw", type=Path, required=True)
    parser.add_argument("--package-raw", type=Path, required=True)
    parser.add_argument("--freebsd-raw", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    parser.add_argument("--max-report-skew-seconds", type=int, default=300)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build bound qualification envelopes")
    _common_arguments(build)
    build.add_argument("--nft-output", type=Path, required=True)
    build.add_argument("--package-output", type=Path, required=True)
    build.add_argument("--freebsd-output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify byte-exact bound envelopes")
    _common_arguments(verify)
    verify.add_argument("--nft-envelope", type=Path, required=True)
    verify.add_argument("--package-envelope", type=Path, required=True)
    verify.add_argument("--freebsd-envelope", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        envelopes = run_build(args) if args.command == "build" else run_verify(args)
    except (gate.EvidenceError, package_lab.LifecycleLabError, freebsd_lab.FreeBSDVMLabError, OSError, ValueError) as exc:
        print(f"release qualification adapter invalid: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(envelopes, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
