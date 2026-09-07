#!/usr/bin/env python3
"""Assemble and validate source-bound Go allocation evidence for v4.10.0."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = (
    REPOSITORY_ROOT / "scripts" / "ci" / "source_allocation_contract_v4.10.0.json"
)

MAX_CONTRACT_BYTES = 1024 * 1024
MAX_RAW_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_PROBE_BYTES = 64 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1

CONTRACT_SCHEMA = "syswarden-source-allocation-contract/v1"
RAW_SCHEMA = "syswarden-allocation-raw-sample/v1"
EVIDENCE_SCHEMA = "syswarden-allocation-evidence/v1"
REPORT_SCHEMA = "syswarden-allocation-report/v1"
AGGREGATE_SCHEMA = "syswarden-performance-aggregate/v1"
WORKLOAD_ID = "syswarden-waap-engine-scan-allocation-workload/v1"
WORKLOAD_ENTRYPOINT = "syswarden-core/engine.Engine.Scan"
MEASUREMENT_SCOPE = "deterministic-source-bound-waap-engine-scan"
ENVIRONMENT_SCHEMA = "syswarden-allocation-environment/v1"
BUILD_ATTESTATION_SCHEMA = "syswarden-allocation-build-attestation/v1"
EXECUTION_CONTROL_SCHEMA = (
    "syswarden-allocation-execution-control-attestation/v1"
)

REPOSITORY = "duggytuxy/syswarden"
TARGET_RELEASE = "v4.10.0"
BASELINE_RELEASE = "v4.04.3"
BASELINE_COMMIT = "381c1f8d91459a9b20605629c725900abd81dee8"
ARCHITECTURE = "linux/amd64"
KERNEL_MACHINE = "x86_64"
TOOLCHAIN_VERSION = "go1.26.6"
TOOLCHAIN_ARCHIVE_SHA256 = (
    "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89"
)

CAMPAIGN_IDS = tuple(f"allocation-campaign-{index:02d}" for index in range(1, 4))
ROLES = ("baseline", "candidate")
SAMPLES_PER_ROLE_PER_CAMPAIGN = 10
SAMPLES_PER_ROLE = len(CAMPAIGN_IDS) * SAMPLES_PER_ROLE_PER_CAMPAIGN
INVOCATIONS_PER_CAMPAIGN = len(ROLES) * SAMPLES_PER_ROLE_PER_CAMPAIGN

METRIC_NAMES = (
    "waap_detection_allocations_per_admitted_event",
    "waap_detection_allocated_bytes_per_admitted_event",
)
METRIC_UNITS = {
    METRIC_NAMES[0]: "count_per_event",
    METRIC_NAMES[1]: "bytes_per_event",
}

SHA40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UINT_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)$")
NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class SourceAllocationGateError(ValueError):
    """Raised when source-bound allocation evidence is unsafe or incomplete."""


@dataclass(frozen=True)
class AttestedBytes:
    wire: bytes
    sha256: str
    identity: tuple[int, ...]


@dataclass(frozen=True)
class RawRecord:
    document: dict[str, Any]
    relative_path: str
    sha256: str
    allocation_delta: int
    allocated_bytes_delta: int


@dataclass(frozen=True)
class BundleAttestation:
    root_identity: tuple[int, ...]
    file_identities: tuple[tuple[str, tuple[int, ...]], ...]
    environment: dict[str, Any]
    environment_sha256: str
    build_attestation: dict[str, Any]
    build_attestation_sha256: str
    benchmark_source_sha256: str
    fixture_sha256: str
    signature_catalog_sha256: str
    subjects: dict[str, dict[str, Any]]


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SourceAllocationGateError(f"{label} keys are not exact")
    return value


def _exact_list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceAllocationGateError(f"{label} must be an array")
    return value


def _exact_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SourceAllocationGateError(f"{label} must be a string")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise SourceAllocationGateError(f"{label} must be an integer")
    return value


def _expect(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise SourceAllocationGateError(f"{label} binding is invalid")


def _sha40(value: object, label: str) -> str:
    text = _exact_string(value, label)
    if SHA40_PATTERN.fullmatch(text) is None:
        raise SourceAllocationGateError(f"{label} is not a canonical commit or tree")
    return text


def _sha256(value: object, label: str) -> str:
    text = _exact_string(value, label)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise SourceAllocationGateError(f"{label} is not a canonical SHA-256")
    return text


def _uint64(value: object, label: str) -> int:
    text = _exact_string(value, label)
    if UINT_PATTERN.fullmatch(text) is None:
        raise SourceAllocationGateError(f"{label} is not a canonical unsigned integer")
    number = int(text, 10)
    if number > UINT64_MAX:
        raise SourceAllocationGateError(f"{label} exceeds uint64")
    return number


def _timestamp(value: object, label: str) -> str:
    text = _exact_string(value, label)
    if not text.endswith("Z"):
        raise SourceAllocationGateError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise SourceAllocationGateError(
            f"{label} must be a canonical UTC timestamp"
        ) from exc
    if parsed.tzinfo != dt.timezone.utc or parsed.microsecond != 0:
        raise SourceAllocationGateError(f"{label} must use whole UTC seconds")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise SourceAllocationGateError(f"{label} must be canonical")
    return text


def _timestamp_value(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value[:-1] + "+00:00")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceAllocationGateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(wire: bytes, label: str) -> Any:
    try:
        text = wire.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SourceAllocationGateError(f"{label} is not valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise SourceAllocationGateError(f"{label} contains a UTF-8 BOM")

    def reject_constant(token: str) -> None:
        raise SourceAllocationGateError(f"{label} contains invalid number {token}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise SourceAllocationGateError(f"{label} is not exact JSON") from exc


def _json_wire(document: object) -> bytes:
    return (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def _compact_json_wire(document: object) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _canonical_absolute(path: Path, label: str) -> Path:
    text = os.fspath(path)
    if not path.is_absolute() or os.path.normpath(text) != text or path.name in {"", ".", ".."}:
        raise SourceAllocationGateError(f"{label} path must be absolute and canonical")
    return path


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_handle_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
    )


def _open_directory_no_symlinks(
    path: Path, *, private: bool, label: str
) -> tuple[int, tuple[int, ...]]:
    path = _canonical_absolute(path, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise SourceAllocationGateError(f"{label} must be a real directory")
        if private and (
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise SourceAllocationGateError(
                f"{label} owner or mode is unsafe; expected current owner and 0700"
            )
        return descriptor, _identity(info)
    except Exception:
        os.close(descriptor)
        raise


def _read_at(
    parent_descriptor: int,
    name: str,
    *,
    maximum: int,
    expected_modes: set[int],
    label: str,
) -> AttestedBytes:
    if not name or "/" in name or name in {".", ".."}:
        raise SourceAllocationGateError(f"{label} filename is not canonical")
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise SourceAllocationGateError(f"cannot inspect {label}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) not in expected_modes
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise SourceAllocationGateError(
            f"{label} must be one owner-controlled regular file with an exact safe mode"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise SourceAllocationGateError(f"{label} changed while opening")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total > maximum:
                raise SourceAllocationGateError(f"{label} exceeds its size bound")
        after = os.fstat(descriptor)
        if _identity(after) != _identity(opened) or total != opened.st_size:
            raise SourceAllocationGateError(f"{label} changed while reading")
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if _identity(current) != _identity(opened):
            raise SourceAllocationGateError(f"{label} changed after reading")
        return AttestedBytes(b"".join(chunks), digest.hexdigest(), _identity(after))
    finally:
        os.close(descriptor)


def _read_attested_file(
    path: Path,
    *,
    maximum: int,
    expected_modes: set[int],
    label: str,
) -> AttestedBytes:
    path = _canonical_absolute(path, label)
    parent_descriptor, _ = _open_directory_no_symlinks(
        path.parent, private=False, label=f"{label} parent"
    )
    try:
        return _read_at(
            parent_descriptor,
            path.name,
            maximum=maximum,
            expected_modes=expected_modes,
            label=label,
        )
    finally:
        os.close(parent_descriptor)


def _same_directory_at_path(path: Path, identity: tuple[int, ...], label: str) -> None:
    descriptor, current = _open_directory_no_symlinks(path, private=True, label=label)
    os.close(descriptor)
    if current != identity:
        raise SourceAllocationGateError(f"{label} changed during processing")


def _same_directory_handle_at_path(
    path: Path, identity: tuple[int, ...], label: str
) -> None:
    descriptor, _ = _open_directory_no_symlinks(path, private=True, label=label)
    try:
        current = _directory_handle_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    if current != identity:
        raise SourceAllocationGateError(f"{label} identity changed during processing")


def _read_json_file(
    path: Path,
    *,
    maximum: int,
    expected_modes: set[int],
    label: str,
    require_canonical_wire: bool = False,
) -> tuple[Any, AttestedBytes]:
    attested = _read_attested_file(
        path, maximum=maximum, expected_modes=expected_modes, label=label
    )
    document = _parse_json(attested.wire, label)
    if require_canonical_wire and attested.wire != _json_wire(document):
        raise SourceAllocationGateError(f"{label} JSON encoding is not canonical")
    return document, attested


def _fraction_object(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _fraction_from_object(value: object, label: str) -> Fraction:
    item = _exact_mapping(value, {"numerator", "denominator"}, label)
    numerator = _uint64(item["numerator"], f"{label} numerator")
    denominator = _uint64(item["denominator"], f"{label} denominator")
    if denominator == 0:
        raise SourceAllocationGateError(f"{label} denominator must be positive")
    result = Fraction(numerator, denominator)
    if str(result.numerator) != item["numerator"] or str(result.denominator) != item["denominator"]:
        raise SourceAllocationGateError(f"{label} fraction is not normalized")
    return result


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    document, _ = _read_json_file(
        path,
        maximum=MAX_CONTRACT_BYTES,
        expected_modes={0o600, 0o644},
        label="source allocation contract",
        require_canonical_wire=False,
    )
    contract = _exact_mapping(
        document,
        {
            "schema_version",
            "schema_id",
            "repository",
            "target_release",
            "baseline_release",
            "baseline_commit",
            "architecture",
            "kernel_machine",
            "toolchain_version",
            "toolchain_archive_sha256",
            "workload",
            "schemas",
            "campaigns",
            "samples_per_subject_per_campaign",
            "stable_regression",
            "metrics",
        },
        "source allocation contract",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", CONTRACT_SCHEMA),
        ("repository", REPOSITORY),
        ("target_release", TARGET_RELEASE),
        ("baseline_release", BASELINE_RELEASE),
        ("baseline_commit", BASELINE_COMMIT),
        ("architecture", ARCHITECTURE),
        ("kernel_machine", KERNEL_MACHINE),
        ("toolchain_version", TOOLCHAIN_VERSION),
        ("toolchain_archive_sha256", TOOLCHAIN_ARCHIVE_SHA256),
        ("samples_per_subject_per_campaign", SAMPLES_PER_ROLE_PER_CAMPAIGN),
    ):
        _expect(contract[key], expected, f"contract {key}")
    _sha40(contract["baseline_commit"], "contract baseline_commit")
    _sha256(contract["toolchain_archive_sha256"], "contract toolchain archive")

    workload = _exact_mapping(
        contract["workload"],
        {
            "id",
            "entrypoint",
            "warmup_events",
            "requested_events",
            "admitted_events",
            "rejected_events",
            "duplicate_events",
            "degraded_events",
            "gomaxprocs",
            "goroutines_before",
            "goroutines_after",
            "garbage_collection_during_measurement",
        },
        "contract workload",
    )
    for key, expected in (
        ("id", WORKLOAD_ID),
        ("entrypoint", WORKLOAD_ENTRYPOINT),
        ("warmup_events", 256),
        ("requested_events", 2048),
        ("admitted_events", 2048),
        ("rejected_events", 0),
        ("duplicate_events", 0),
        ("degraded_events", 0),
        ("gomaxprocs", 1),
        ("goroutines_before", 2),
        ("goroutines_after", 2),
        ("garbage_collection_during_measurement", False),
    ):
        _expect(workload[key], expected, f"contract workload {key}")

    schemas = _exact_mapping(
        contract["schemas"], {"raw", "evidence", "report", "aggregate"},
        "contract schemas",
    )
    for key, expected in (
        ("raw", RAW_SCHEMA),
        ("evidence", EVIDENCE_SCHEMA),
        ("report", REPORT_SCHEMA),
        ("aggregate", AGGREGATE_SCHEMA),
    ):
        _expect(schemas[key], expected, f"contract schema {key}")
    campaigns = _exact_list(contract["campaigns"], "contract campaigns")
    if any(not isinstance(item, str) for item in campaigns) or tuple(campaigns) != CAMPAIGN_IDS:
        raise SourceAllocationGateError("contract campaign inventory is not exact")

    stable = _exact_mapping(
        contract["stable_regression"],
        {"threshold_numerator", "threshold_denominator", "minimum_regressed_campaigns"},
        "contract stable regression",
    )
    _expect(stable["threshold_numerator"], "1", "contract threshold numerator")
    _expect(stable["threshold_denominator"], "10", "contract threshold denominator")
    _expect(stable["minimum_regressed_campaigns"], 2, "contract regressed campaigns")
    _uint64(stable["threshold_numerator"], "contract threshold numerator")
    _uint64(stable["threshold_denominator"], "contract threshold denominator")

    metrics = _exact_mapping(contract["metrics"], set(METRIC_NAMES), "contract metrics")
    for name in METRIC_NAMES:
        metric = _exact_mapping(metrics[name], {"unit", "direction"}, f"contract metric {name}")
        _expect(metric["unit"], METRIC_UNITS[name], f"contract metric {name} unit")
        _expect(metric["direction"], "lower", f"contract metric {name} direction")
    return contract


def _bounded_text(value: object, label: str, *, minimum: int = 1, maximum: int = 512) -> str:
    text = _exact_string(value, label)
    if text != text.strip() or not (minimum <= len(text) <= maximum):
        raise SourceAllocationGateError(f"{label} length or whitespace is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise SourceAllocationGateError(f"{label} contains a control character")
    return text


def _validate_execution_control(
    value: object, *, candidate_commit: str
) -> dict[str, Any]:
    control = _exact_mapping(
        value,
        {
            "schema_version",
            "schema_id",
            "candidate_commit",
            "architecture",
            "recorded_at",
            "attested_by",
            "producer_egress_denied",
            "repository_source_read_only",
            "build_checkouts_producer_writable",
            "persistent_writes_limited_to_evidence_root",
            "probe_egress_denied",
            "probe_persistent_filesystem_read_only",
            "sandbox_kind",
            "sandbox_executable_path",
            "sandbox_executable_sha256",
            "python_executable_path",
            "python_executable_sha256",
            "shell_executable_path",
            "shell_executable_sha256",
            "outer_unix_socket_canary_passed",
            "probe_unix_socket_canary_required",
            "runner_threat_model",
        },
        "execution control attestation",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", EXECUTION_CONTROL_SCHEMA),
        ("candidate_commit", candidate_commit),
        ("architecture", ARCHITECTURE),
        ("producer_egress_denied", True),
        ("repository_source_read_only", True),
        ("build_checkouts_producer_writable", True),
        ("persistent_writes_limited_to_evidence_root", True),
        ("probe_egress_denied", True),
        ("probe_persistent_filesystem_read_only", True),
        ("sandbox_kind", "bubblewrap-minimal-root-unshared-network/v2"),
        ("sandbox_executable_path", "/usr/bin/bwrap"),
        ("shell_executable_path", "/usr/bin/bash"),
        ("outer_unix_socket_canary_passed", True),
        ("probe_unix_socket_canary_required", True),
        (
            "runner_threat_model",
            "protected-dedicated-runner-trusted-launch-environment-no-hostile-same-uid-process/v1",
        ),
    ):
        _expect(control[key], expected, f"execution control {key}")
    _sha40(control["candidate_commit"], "execution control candidate commit")
    _sha256(
        control["sandbox_executable_sha256"],
        "execution control sandbox executable",
    )
    python_path = _exact_string(
        control["python_executable_path"],
        "execution control Python executable path",
    )
    if re.fullmatch(r"/usr/bin/python3(?:\.[0-9]+)?", python_path) is None:
        raise SourceAllocationGateError(
            "execution control Python executable path is invalid"
        )
    _sha256(
        control["python_executable_sha256"],
        "execution control Python executable",
    )
    _sha256(
        control["shell_executable_sha256"],
        "execution control shell executable",
    )
    _timestamp(control["recorded_at"], "execution control recorded_at")
    _bounded_text(control["attested_by"], "execution control attested_by", minimum=3, maximum=200)
    return control


def _validate_environment(
    value: object,
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    execution_control: Mapping[str, Any],
    execution_control_sha256: str,
) -> dict[str, Any]:
    environment = _exact_mapping(
        value,
        {
            "schema_version",
            "schema_id",
            "repository",
            "candidate_commit",
            "recorded_at",
            "architecture",
            "kernel_machine",
            "kernel_release",
            "os_release_sha256",
            "logical_cpu_count",
            "page_size",
            "execution_control_attestation_sha256",
            "execution_controls",
        },
        "allocation environment",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", ENVIRONMENT_SCHEMA),
        ("repository", contract["repository"]),
        ("candidate_commit", candidate_commit),
        ("architecture", contract["architecture"]),
        ("kernel_machine", contract["kernel_machine"]),
        ("execution_control_attestation_sha256", execution_control_sha256),
    ):
        _expect(environment[key], expected, f"environment {key}")
    recorded_at = _timestamp(environment["recorded_at"], "environment recorded_at")
    if _timestamp_value(recorded_at) < _timestamp_value(execution_control["recorded_at"]):
        raise SourceAllocationGateError(
            "environment predates its execution control attestation"
        )
    _bounded_text(environment["kernel_release"], "environment kernel_release")
    _sha256(environment["os_release_sha256"], "environment os-release SHA-256")
    logical_cpus = _exact_int(environment["logical_cpu_count"], "environment logical CPU count")
    if logical_cpus < 1 or logical_cpus > 4096:
        raise SourceAllocationGateError("environment logical CPU count is outside bounds")
    page_size = _exact_int(environment["page_size"], "environment page size")
    if page_size < 1024 or page_size > 1024 * 1024 or page_size & (page_size - 1):
        raise SourceAllocationGateError("environment page size is outside bounds")
    if _json_wire(environment["execution_controls"]) != _json_wire(execution_control):
        raise SourceAllocationGateError(
            "embedded execution controls differ from their attested file"
        )
    return environment


def _validate_module_graph(value: object, label: str) -> tuple[list[Any], str]:
    graph = _exact_list(value, label)
    if not graph or len(graph) > 4096:
        raise SourceAllocationGateError(f"{label} size is outside bounds")
    paths: list[str] = []
    main_count = 0
    for index, raw in enumerate(graph):
        item = _exact_mapping(
            raw, {"path", "version", "sum", "go_mod_sum", "main"},
            f"{label} entry {index}",
        )
        path = _bounded_text(item["path"], f"{label} path", maximum=512)
        paths.append(path)
        for key in ("version", "sum", "go_mod_sum"):
            text = _exact_string(item[key], f"{label} {key}")
            if len(text) > 512 or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in text
            ):
                raise SourceAllocationGateError(f"{label} {key} is invalid")
        if type(item["main"]) is not bool:
            raise SourceAllocationGateError(f"{label} main must be a boolean")
        main_count += int(item["main"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise SourceAllocationGateError(f"{label} paths are not canonical and unique")
    if main_count != 1:
        raise SourceAllocationGateError(f"{label} must contain exactly one main module")
    return graph, hashlib.sha256(_compact_json_wire(graph)).hexdigest()


def _validate_build_attestation(
    value: object,
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    environment_sha256: str,
    benchmark_source_sha256: str,
    fixture_sha256: str,
    signature_catalog_sha256: str,
    probe_sha256: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    build = _exact_mapping(
        value,
        {
            "schema_version",
            "schema_id",
            "repository",
            "target_release",
            "candidate_commit",
            "baseline_release",
            "baseline_commit",
            "environment_sha256",
            "bindings",
            "build_contract",
            "subjects",
        },
        "allocation build attestation",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", BUILD_ATTESTATION_SCHEMA),
        ("repository", contract["repository"]),
        ("target_release", contract["target_release"]),
        ("candidate_commit", candidate_commit),
        ("baseline_release", contract["baseline_release"]),
        ("baseline_commit", contract["baseline_commit"]),
        ("environment_sha256", environment_sha256),
    ):
        _expect(build[key], expected, f"build attestation {key}")
    bindings = _exact_mapping(
        build["bindings"],
        {
            "benchmark_source_sha256",
            "fixture_sha256",
            "signature_catalog_sha256",
            "toolchain_version",
            "toolchain_archive_sha256",
            "toolchain_executable_sha256",
            "toolchain_version_output",
            "workload_id",
        },
        "build attestation bindings",
    )
    for key, expected in (
        ("benchmark_source_sha256", benchmark_source_sha256),
        ("fixture_sha256", fixture_sha256),
        ("signature_catalog_sha256", signature_catalog_sha256),
        ("toolchain_version", contract["toolchain_version"]),
        ("toolchain_archive_sha256", contract["toolchain_archive_sha256"]),
        (
            "toolchain_version_output",
            f"go version {contract['toolchain_version']} linux/amd64",
        ),
        ("workload_id", contract["workload"]["id"]),
    ):
        _expect(bindings[key], expected, f"build binding {key}")
    for key in (
        "benchmark_source_sha256",
        "fixture_sha256",
        "signature_catalog_sha256",
        "toolchain_archive_sha256",
        "toolchain_executable_sha256",
    ):
        _sha256(bindings[key], f"build binding {key}")

    build_contract = _exact_mapping(
        build["build_contract"],
        {
            "gowork",
            "goflags",
            "cgo_enabled",
            "goos",
            "goarch",
            "gotoolchain",
            "goproxy",
            "gosumdb",
            "trimpath",
            "buildvcs",
            "command",
        },
        "build command contract",
    )
    expected_build_contract: dict[str, Any] = {
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
    }
    if _json_wire(build_contract) != _json_wire(expected_build_contract):
        raise SourceAllocationGateError("build command contract is not exact")

    raw_subjects = _exact_mapping(build["subjects"], set(ROLES), "build subjects")
    subjects: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        subject = _exact_mapping(
            raw_subjects[role],
            {
                "release",
                "commit",
                "tree",
                "module_graph_sha256",
                "module_graph",
                "probe_binary_sha256",
                "reproducible_build",
            },
            f"build subject {role}",
        )
        expected_release = contract["baseline_release"] if role == "baseline" else contract["target_release"]
        expected_commit = contract["baseline_commit"] if role == "baseline" else candidate_commit
        _expect(subject["release"], expected_release, f"build subject {role} release")
        _expect(subject["commit"], expected_commit, f"build subject {role} commit")
        _sha40(subject["commit"], f"build subject {role} commit")
        _sha40(subject["tree"], f"build subject {role} tree")
        _expect(
            subject["probe_binary_sha256"], probe_sha256[role],
            f"build subject {role} probe SHA-256",
        )
        _sha256(subject["probe_binary_sha256"], f"build subject {role} probe SHA-256")
        graph, graph_sha256 = _validate_module_graph(
            subject["module_graph"], f"build subject {role} module graph"
        )
        _expect(
            subject["module_graph_sha256"], graph_sha256,
            f"build subject {role} module graph SHA-256",
        )
        _expect(subject["reproducible_build"], True, f"build subject {role} reproducible build")
        subjects[role] = {
            "release": subject["release"],
            "commit": subject["commit"],
            "tree": subject["tree"],
            "module_graph_sha256": graph_sha256,
            "probe_binary_sha256": subject["probe_binary_sha256"],
        }
    return build, subjects


def load_bundle(
    *,
    bundle_root: Path,
    contract: Mapping[str, Any],
    candidate_commit: str,
    include_outputs: bool = False,
) -> BundleAttestation:
    root_descriptor, root_identity = _open_directory_no_symlinks(
        bundle_root, private=True, label="allocation bundle root"
    )
    expected_entries = {
        "environment.json",
        "execution-control-attestation.json",
        "build-attestation.json",
        "benchmark-source.go",
        "fixture.json",
        "signature-catalog.json",
        "baseline-probe",
        "candidate-probe",
        "raw",
    }
    if include_outputs:
        expected_entries.update({"EVIDENCE.json", "REPORT.json"})
    try:
        if set(os.listdir(root_descriptor)) != expected_entries:
            raise SourceAllocationGateError("allocation bundle inventory is not exact")
        raw_info = os.stat("raw", dir_fd=root_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(raw_info.st_mode)
            or raw_info.st_uid != os.geteuid()
            or stat.S_IMODE(raw_info.st_mode) != 0o700
        ):
            raise SourceAllocationGateError("allocation bundle raw directory is unsafe")
        inputs: dict[str, AttestedBytes] = {}
        for name, maximum, modes in (
            ("environment.json", MAX_CONTRACT_BYTES, {0o600}),
            ("execution-control-attestation.json", MAX_CONTRACT_BYTES, {0o600}),
            ("build-attestation.json", MAX_CONTRACT_BYTES, {0o600}),
            ("benchmark-source.go", MAX_CONTRACT_BYTES, {0o600}),
            ("fixture.json", MAX_CONTRACT_BYTES, {0o600}),
            ("signature-catalog.json", MAX_CONTRACT_BYTES, {0o600}),
            ("baseline-probe", MAX_PROBE_BYTES, {0o700}),
            ("candidate-probe", MAX_PROBE_BYTES, {0o700}),
        ):
            inputs[name] = _read_at(
                root_descriptor,
                name,
                maximum=maximum,
                expected_modes=modes,
                label=f"allocation bundle {name}",
            )
        for name in ("fixture.json", "signature-catalog.json"):
            parsed_input = _parse_json(inputs[name].wire, f"allocation bundle {name}")
            if not isinstance(parsed_input, dict):
                raise SourceAllocationGateError(
                    f"allocation bundle {name} must contain one JSON object"
                )
        execution_control = _validate_execution_control(
            _parse_json(
                inputs["execution-control-attestation.json"].wire,
                "execution control attestation",
            ),
            candidate_commit=candidate_commit,
        )
        environment = _validate_environment(
            _parse_json(inputs["environment.json"].wire, "allocation environment"),
            contract=contract,
            candidate_commit=candidate_commit,
            execution_control=execution_control,
            execution_control_sha256=inputs[
                "execution-control-attestation.json"
            ].sha256,
        )
        probe_sha256 = {
            role: inputs[f"{role}-probe"].sha256 for role in ROLES
        }
        build, subjects = _validate_build_attestation(
            _parse_json(
                inputs["build-attestation.json"].wire,
                "allocation build attestation",
            ),
            contract=contract,
            candidate_commit=candidate_commit,
            environment_sha256=inputs["environment.json"].sha256,
            benchmark_source_sha256=inputs["benchmark-source.go"].sha256,
            fixture_sha256=inputs["fixture.json"].sha256,
            signature_catalog_sha256=inputs["signature-catalog.json"].sha256,
            probe_sha256=probe_sha256,
        )
        current_root = os.fstat(root_descriptor)
        if _identity(current_root) != root_identity:
            raise SourceAllocationGateError("allocation bundle root changed")
    finally:
        os.close(root_descriptor)
    _same_directory_at_path(bundle_root, root_identity, "allocation bundle root")
    identities = tuple(
        sorted((name, item.identity) for name, item in inputs.items())
    )
    return BundleAttestation(
        root_identity=root_identity,
        file_identities=identities,
        environment=environment,
        environment_sha256=inputs["environment.json"].sha256,
        build_attestation=build,
        build_attestation_sha256=inputs["build-attestation.json"].sha256,
        benchmark_source_sha256=inputs["benchmark-source.go"].sha256,
        fixture_sha256=inputs["fixture.json"].sha256,
        signature_catalog_sha256=inputs["signature-catalog.json"].sha256,
        subjects=subjects,
    )


def _expected_invocation(sample_index: int, role: str) -> int:
    first_role = "baseline" if sample_index % 2 == 1 else "candidate"
    offset = 0 if role == first_role else 1
    return (sample_index - 1) * 2 + 1 + offset


def _validate_subject(
    value: object, role: str, candidate_commit: str
) -> dict[str, Any]:
    subject = _exact_mapping(
        value,
        {"role", "release", "commit", "tree", "probe_binary_sha256", "module_graph_sha256"},
        "raw subject",
    )
    expected_release = BASELINE_RELEASE if role == "baseline" else TARGET_RELEASE
    expected_commit = BASELINE_COMMIT if role == "baseline" else candidate_commit
    _expect(subject["role"], role, "raw subject role")
    _expect(subject["release"], expected_release, "raw subject release")
    _expect(subject["commit"], expected_commit, "raw subject commit")
    _sha40(subject["commit"], "raw subject commit")
    _sha40(subject["tree"], "raw subject tree")
    _sha256(subject["probe_binary_sha256"], "raw subject probe binary")
    _sha256(subject["module_graph_sha256"], "raw subject module graph")
    return subject


def _validate_bindings(value: object, contract: Mapping[str, Any]) -> dict[str, Any]:
    bindings = _exact_mapping(
        value,
        {
            "architecture",
            "kernel_machine",
            "environment_sha256",
            "build_attestation_sha256",
            "benchmark_source_sha256",
            "fixture_sha256",
            "signature_catalog_sha256",
            "toolchain_version",
            "toolchain_archive_sha256",
            "workload_id",
        },
        "raw bindings",
    )
    for key, expected in (
        ("architecture", contract["architecture"]),
        ("kernel_machine", contract["kernel_machine"]),
        ("toolchain_version", contract["toolchain_version"]),
        ("toolchain_archive_sha256", contract["toolchain_archive_sha256"]),
        ("workload_id", contract["workload"]["id"]),
    ):
        _expect(bindings[key], expected, f"raw binding {key}")
    for key in (
        "environment_sha256",
        "build_attestation_sha256",
        "benchmark_source_sha256",
        "fixture_sha256",
        "signature_catalog_sha256",
        "toolchain_archive_sha256",
    ):
        _sha256(bindings[key], f"raw binding {key}")
    return bindings


def _validate_workload(value: object, contract: Mapping[str, Any]) -> dict[str, Any]:
    expected_workload = {
        key: value
        for key, value in contract["workload"].items()
        if key not in {"id", "entrypoint"}
    }
    workload = _exact_mapping(value, set(expected_workload), "raw workload")
    for key, expected in expected_workload.items():
        _expect(workload[key], expected, f"raw workload {key}")
    return workload


def _validate_raw_document(
    document: object,
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    campaign_id: str,
    role: str,
    sample_index: int,
    invocation_index: int,
) -> tuple[dict[str, Any], int, int]:
    raw = _exact_mapping(
        document,
        {
            "schema_version",
            "schema_id",
            "repository",
            "target_release",
            "candidate_commit",
            "baseline_release",
            "baseline_commit",
            "campaign_id",
            "campaign_recorded_at",
            "sample_started_at",
            "sample_completed_at",
            "sample_index",
            "invocation_index",
            "sample_id",
            "process_nonce",
            "subject",
            "bindings",
            "workload",
            "counters",
        },
        "raw sample",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", contract["schemas"]["raw"]),
        ("repository", contract["repository"]),
        ("target_release", contract["target_release"]),
        ("candidate_commit", candidate_commit),
        ("baseline_release", contract["baseline_release"]),
        ("baseline_commit", contract["baseline_commit"]),
        ("campaign_id", campaign_id),
        ("sample_index", sample_index),
        ("invocation_index", invocation_index),
        ("sample_id", f"{campaign_id}-{role}-{sample_index:02d}"),
    ):
        _expect(raw[key], expected, f"raw {key}")
    _sha40(raw["candidate_commit"], "raw candidate commit")
    _sha40(raw["baseline_commit"], "raw baseline commit")
    nonce = _exact_string(raw["process_nonce"], "raw process nonce")
    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise SourceAllocationGateError("raw process nonce is not canonical 128-bit hex")
    campaign_time = _timestamp(raw["campaign_recorded_at"], "campaign recorded_at")
    started = _timestamp(raw["sample_started_at"], "sample started_at")
    completed = _timestamp(raw["sample_completed_at"], "sample completed_at")
    if not (
        _timestamp_value(campaign_time)
        <= _timestamp_value(started)
        <= _timestamp_value(completed)
    ):
        raise SourceAllocationGateError("raw sample timestamps are out of order")
    _validate_subject(raw["subject"], role, candidate_commit)
    _validate_bindings(raw["bindings"], contract)
    _validate_workload(raw["workload"], contract)

    counters = _exact_mapping(
        raw["counters"],
        {
            "mallocs_before",
            "mallocs_after",
            "total_alloc_bytes_before",
            "total_alloc_bytes_after",
            "gc_cycles_before",
            "gc_cycles_after",
        },
        "raw counters",
    )
    parsed = {key: _uint64(counters[key], f"raw counter {key}") for key in counters}
    if parsed["mallocs_after"] < parsed["mallocs_before"]:
        raise SourceAllocationGateError("raw malloc counter decreased")
    if parsed["total_alloc_bytes_after"] < parsed["total_alloc_bytes_before"]:
        raise SourceAllocationGateError("raw allocated-byte counter decreased")
    if parsed["gc_cycles_before"] != parsed["gc_cycles_after"]:
        raise SourceAllocationGateError("garbage collection occurred during measurement")
    allocation_delta = parsed["mallocs_after"] - parsed["mallocs_before"]
    allocated_bytes_delta = (
        parsed["total_alloc_bytes_after"] - parsed["total_alloc_bytes_before"]
    )
    if (allocation_delta == 0) != (allocated_bytes_delta == 0):
        raise SourceAllocationGateError(
            "object and byte allocation deltas do not share zero or positive state"
        )
    return raw, allocation_delta, allocated_bytes_delta


def load_raw_records(
    *,
    raw_root: Path,
    contract: Mapping[str, Any],
    candidate_commit: str,
    bundle: BundleAttestation | None = None,
) -> list[RawRecord]:
    if SHA40_PATTERN.fullmatch(candidate_commit) is None or candidate_commit == BASELINE_COMMIT:
        raise SourceAllocationGateError("candidate commit is not canonical or distinct")
    root_descriptor, root_identity = _open_directory_no_symlinks(
        raw_root, private=True, label="raw root"
    )
    records: list[RawRecord] = []
    seen_nonces: set[str] = set()
    seen_sample_ids: set[str] = set()
    seen_digests: set[str] = set()
    campaign_timestamps: dict[str, str] = {}
    common_bindings: dict[str, Any] | None = None
    role_subjects: dict[str, dict[str, Any]] = {}
    try:
        if set(os.listdir(root_descriptor)) != set(CAMPAIGN_IDS):
            raise SourceAllocationGateError("raw root campaign inventory is not exact")
        for campaign_id in CAMPAIGN_IDS:
            before = os.stat(campaign_id, dir_fd=root_descriptor, follow_symlinks=False)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            campaign_descriptor = os.open(campaign_id, flags, dir_fd=root_descriptor)
            try:
                opened = os.fstat(campaign_descriptor)
                if (
                    _identity(opened) != _identity(before)
                    or not stat.S_ISDIR(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    raise SourceAllocationGateError(
                        f"raw campaign directory is unsafe: {campaign_id}"
                    )
                expected_names = {
                    f"{role}-{sample_index:02d}.json"
                    for role in ROLES
                    for sample_index in range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1)
                }
                if set(os.listdir(campaign_descriptor)) != expected_names:
                    raise SourceAllocationGateError(
                        f"raw file inventory is not exact: {campaign_id}"
                    )
                per_campaign_invocations: set[int] = set()
                for sample_index in range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1):
                    for role in ROLES:
                        invocation_index = _expected_invocation(sample_index, role)
                        filename = f"{role}-{sample_index:02d}.json"
                        attested = _read_at(
                            campaign_descriptor,
                            filename,
                            maximum=MAX_RAW_BYTES,
                            expected_modes={0o600},
                            label=f"raw sample {campaign_id}/{filename}",
                        )
                        raw, allocation_delta, allocated_bytes_delta = _validate_raw_document(
                            _parse_json(attested.wire, f"raw sample {campaign_id}/{filename}"),
                            contract=contract,
                            candidate_commit=candidate_commit,
                            campaign_id=campaign_id,
                            role=role,
                            sample_index=sample_index,
                            invocation_index=invocation_index,
                        )
                        nonce = raw["process_nonce"]
                        sample_id = raw["sample_id"]
                        if nonce in seen_nonces:
                            raise SourceAllocationGateError("raw process nonce is duplicated")
                        if sample_id in seen_sample_ids:
                            raise SourceAllocationGateError("raw sample identifier is duplicated")
                        if attested.sha256 in seen_digests:
                            raise SourceAllocationGateError("raw file digest is duplicated")
                        if invocation_index in per_campaign_invocations:
                            raise SourceAllocationGateError("raw invocation index is duplicated")
                        seen_nonces.add(nonce)
                        seen_sample_ids.add(sample_id)
                        seen_digests.add(attested.sha256)
                        per_campaign_invocations.add(invocation_index)
                        timestamp = raw["campaign_recorded_at"]
                        if campaign_id in campaign_timestamps and campaign_timestamps[campaign_id] != timestamp:
                            raise SourceAllocationGateError(
                                "campaign timestamp differs within one campaign"
                            )
                        campaign_timestamps[campaign_id] = timestamp
                        if common_bindings is None:
                            common_bindings = raw["bindings"]
                        elif _json_wire(common_bindings) != _json_wire(raw["bindings"]):
                            raise SourceAllocationGateError("raw bindings drift across subjects or campaigns")
                        if role not in role_subjects:
                            role_subjects[role] = raw["subject"]
                        elif _json_wire(role_subjects[role]) != _json_wire(raw["subject"]):
                            raise SourceAllocationGateError(f"raw {role} subject binding drifted")
                        records.append(
                            RawRecord(
                                document=raw,
                                relative_path=f"raw/{campaign_id}/{filename}",
                                sha256=attested.sha256,
                                allocation_delta=allocation_delta,
                                allocated_bytes_delta=allocated_bytes_delta,
                            )
                        )
                if per_campaign_invocations != set(range(1, INVOCATIONS_PER_CAMPAIGN + 1)):
                    raise SourceAllocationGateError(
                        f"raw invocation inventory is incomplete: {campaign_id}"
                    )
                current = os.stat(campaign_id, dir_fd=root_descriptor, follow_symlinks=False)
                if _identity(current) != _identity(opened):
                    raise SourceAllocationGateError(
                        f"raw campaign directory changed: {campaign_id}"
                    )
            finally:
                os.close(campaign_descriptor)
        if len(set(campaign_timestamps.values())) != len(CAMPAIGN_IDS):
            raise SourceAllocationGateError("campaign timestamps are duplicated")
        ordered_campaign_times = [
            _timestamp_value(campaign_timestamps[campaign_id])
            for campaign_id in CAMPAIGN_IDS
        ]
        if ordered_campaign_times != sorted(ordered_campaign_times):
            raise SourceAllocationGateError(
                "campaign timestamps are not in campaign order"
            )
        current_root = os.fstat(root_descriptor)
        if _identity(current_root) != root_identity:
            raise SourceAllocationGateError("raw root changed during processing")
    finally:
        os.close(root_descriptor)
    _same_directory_at_path(raw_root, root_identity, "raw root")
    if len(records) != len(CAMPAIGN_IDS) * len(ROLES) * SAMPLES_PER_ROLE_PER_CAMPAIGN:
        raise SourceAllocationGateError("raw inventory does not contain exactly 60 samples")
    records.sort(
        key=lambda item: (
            CAMPAIGN_IDS.index(item.document["campaign_id"]),
            item.document["invocation_index"],
        )
    )
    for campaign_id in CAMPAIGN_IDS:
        ordered = [
            item
            for item in records
            if item.document["campaign_id"] == campaign_id
        ]
        for previous, current in zip(ordered, ordered[1:]):
            if _timestamp_value(previous.document["sample_completed_at"]) > _timestamp_value(
                current.document["sample_started_at"]
            ):
                raise SourceAllocationGateError(
                    f"raw invocation chronology overlaps in {campaign_id}"
                )
    if bundle is not None:
        environment_time = _timestamp_value(bundle.environment["recorded_at"])
        if any(
            _timestamp_value(campaign_timestamps[campaign_id]) < environment_time
            for campaign_id in CAMPAIGN_IDS
        ):
            raise SourceAllocationGateError(
                "a raw campaign predates the bound environment attestation"
            )
        if common_bindings is None:
            raise SourceAllocationGateError("raw bindings are missing")
        expected_bindings = {
            "architecture": contract["architecture"],
            "kernel_machine": contract["kernel_machine"],
            "environment_sha256": bundle.environment_sha256,
            "build_attestation_sha256": bundle.build_attestation_sha256,
            "benchmark_source_sha256": bundle.benchmark_source_sha256,
            "fixture_sha256": bundle.fixture_sha256,
            "signature_catalog_sha256": bundle.signature_catalog_sha256,
            "toolchain_version": contract["toolchain_version"],
            "toolchain_archive_sha256": contract["toolchain_archive_sha256"],
            "workload_id": contract["workload"]["id"],
        }
        if _json_wire(common_bindings) != _json_wire(expected_bindings):
            raise SourceAllocationGateError(
                "raw bindings do not match the attested bundle files"
            )
        for role in ROLES:
            expected_subject = {
                "role": role,
                **bundle.subjects[role],
            }
            if role not in role_subjects or _json_wire(role_subjects[role]) != _json_wire(expected_subject):
                raise SourceAllocationGateError(
                    f"raw {role} subject does not match the build attestation"
                )
    return records


def _records_by_campaign(records: Sequence[RawRecord], campaign_id: str) -> list[RawRecord]:
    return [item for item in records if item.document["campaign_id"] == campaign_id]


def build_evidence(
    *, contract: Mapping[str, Any], candidate_commit: str, records: Sequence[RawRecord]
) -> dict[str, Any]:
    if len(records) != 60:
        raise SourceAllocationGateError("cannot build evidence without exactly 60 raw samples")
    first = records[0].document
    bindings = dict(first["bindings"])
    subjects: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        matches = [item.document["subject"] for item in records if item.document["subject"]["role"] == role]
        if len(matches) != SAMPLES_PER_ROLE:
            raise SourceAllocationGateError(f"evidence {role} subject inventory is incomplete")
        subjects[role] = {
            key: matches[0][key]
            for key in ("release", "commit", "tree", "probe_binary_sha256", "module_graph_sha256")
        }

    campaigns: list[dict[str, Any]] = []
    raw_inventory: list[dict[str, Any]] = []
    for campaign_id in CAMPAIGN_IDS:
        campaign_records = sorted(
            _records_by_campaign(records, campaign_id),
            key=lambda item: item.document["invocation_index"],
        )
        campaigns.append(
            {
                "id": campaign_id,
                "recorded_at": campaign_records[0].document["campaign_recorded_at"],
                "environment_sha256": bindings["environment_sha256"],
                "order": [item.document["subject"]["role"] for item in campaign_records],
                "sample_pairs": [
                    {
                        "sample_index": sample_index,
                        "baseline_invocation_index": next(
                            item.document["invocation_index"]
                            for item in campaign_records
                            if item.document["sample_index"] == sample_index
                            and item.document["subject"]["role"] == "baseline"
                        ),
                        "baseline_sample_id": f"{campaign_id}-baseline-{sample_index:02d}",
                        "baseline_raw_sha256": next(
                            item.sha256
                            for item in campaign_records
                            if item.document["sample_index"] == sample_index
                            and item.document["subject"]["role"] == "baseline"
                        ),
                        "candidate_invocation_index": next(
                            item.document["invocation_index"]
                            for item in campaign_records
                            if item.document["sample_index"] == sample_index
                            and item.document["subject"]["role"] == "candidate"
                        ),
                        "candidate_sample_id": f"{campaign_id}-candidate-{sample_index:02d}",
                        "candidate_raw_sha256": next(
                            item.sha256
                            for item in campaign_records
                            if item.document["sample_index"] == sample_index
                            and item.document["subject"]["role"] == "candidate"
                        ),
                    }
                    for sample_index in range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1)
                ],
            }
        )
        raw_inventory.extend(
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "campaign_id": campaign_id,
                "subject_role": item.document["subject"]["role"],
                "sample_index": item.document["sample_index"],
                "invocation_index": item.document["invocation_index"],
                "sample_id": item.document["sample_id"],
                "process_nonce": item.document["process_nonce"],
            }
            for item in campaign_records
        )

    metrics: dict[str, Any] = {}
    admitted_events = int(contract["workload"]["admitted_events"])
    for metric_name in METRIC_NAMES:
        role_values: dict[str, list[dict[str, Any]]] = {}
        for role in ROLES:
            values: list[dict[str, Any]] = []
            for campaign_id in CAMPAIGN_IDS:
                role_records = sorted(
                    (
                        item
                        for item in records
                        if item.document["campaign_id"] == campaign_id
                        and item.document["subject"]["role"] == role
                    ),
                    key=lambda item: item.document["sample_index"],
                )
                for item in role_records:
                    numerator = (
                        item.allocation_delta
                        if metric_name == METRIC_NAMES[0]
                        else item.allocated_bytes_delta
                    )
                    value = Fraction(numerator, admitted_events)
                    values.append(
                        {
                            "campaign_id": campaign_id,
                            "sample_index": item.document["sample_index"],
                            "raw_numerator": str(numerator),
                            "raw_denominator": str(admitted_events),
                            **_fraction_object(value),
                        }
                    )
            role_values[role] = values
        metrics[metric_name] = {
            "unit": METRIC_UNITS[metric_name],
            "direction": "lower",
            "baseline": role_values["baseline"],
            "candidate": role_values["candidate"],
        }
    return {
        "schema_version": 1,
        "schema_id": contract["schemas"]["evidence"],
        "repository": contract["repository"],
        "target_release": contract["target_release"],
        "candidate_commit": candidate_commit,
        "baseline_release": contract["baseline_release"],
        "baseline_commit": contract["baseline_commit"],
        "measurement_scope": MEASUREMENT_SCOPE,
        "native_package_runtime_measurement": False,
        "bindings": bindings,
        "subjects": subjects,
        "campaigns": campaigns,
        "raw_inventory": raw_inventory,
        "metrics": metrics,
    }


def _fixed_six_percent(value: Fraction) -> str:
    scaled_numerator = abs(value.numerator) * 100 * 1_000_000
    quotient, remainder = divmod(scaled_numerator, value.denominator)
    if remainder * 2 >= value.denominator:
        quotient += 1
    sign = "-" if value < 0 and quotient != 0 else ""
    return f"{sign}{quotient // 1_000_000}.{quotient % 1_000_000:06d}"


def _median(values: Sequence[Fraction]) -> Fraction:
    if not values:
        raise SourceAllocationGateError("cannot calculate a median without samples")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _p95(values: Sequence[Fraction]) -> Fraction:
    if not values:
        raise SourceAllocationGateError("cannot calculate p95 without samples")
    ordered = sorted(values)
    rank = max(1, (95 * len(ordered) + 99) // 100)
    return ordered[rank - 1]


def _distribution(values: Sequence[Fraction]) -> dict[str, Any]:
    if len(values) != SAMPLES_PER_ROLE:
        raise SourceAllocationGateError("report distribution requires exactly 30 samples")
    return {
        "samples": len(values),
        "minimum": _fraction_object(min(values)),
        "median": _fraction_object(_median(values)),
        "p95": _fraction_object(_p95(values)),
        "maximum": _fraction_object(max(values)),
    }


def _regression(
    baseline: Fraction, candidate: Fraction
) -> tuple[dict[str, str | None], Fraction | None]:
    if baseline == 0 and candidate == 0:
        return {"classification": "zero-to-zero", "percent": None}, Fraction(0, 1)
    if baseline == 0:
        return {"classification": "introduced-from-zero", "percent": None}, None
    if candidate == 0:
        return {"classification": "improved-to-zero", "percent": None}, Fraction(-1, 1)
    ratio = (candidate - baseline) / baseline
    return {
        "classification": "finite",
        "percent": _fixed_six_percent(ratio),
    }, ratio


def _is_regression_over_threshold(
    baseline: Fraction, candidate: Fraction, threshold: Fraction
) -> bool:
    if baseline == 0:
        return candidate > 0
    return (candidate - baseline) / baseline > threshold


def _metric_values(metric: Mapping[str, Any], role: str) -> list[Fraction]:
    raw = _exact_list(metric[role], f"evidence metric {role}")
    if len(raw) != SAMPLES_PER_ROLE:
        raise SourceAllocationGateError(f"evidence metric {role} requires exactly 30 samples")
    values: list[Fraction] = []
    expected_positions = [
        (campaign_id, sample_index)
        for campaign_id in CAMPAIGN_IDS
        for sample_index in range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1)
    ]
    for item, (campaign_id, sample_index) in zip(raw, expected_positions):
        entry = _exact_mapping(
            item,
            {
                "campaign_id",
                "sample_index",
                "raw_numerator",
                "raw_denominator",
                "numerator",
                "denominator",
            },
            f"evidence metric {role} sample",
        )
        _expect(entry["campaign_id"], campaign_id, "evidence metric campaign")
        _expect(entry["sample_index"], sample_index, "evidence metric sample_index")
        raw_numerator = _uint64(
            entry["raw_numerator"], f"evidence metric {role} raw numerator"
        )
        raw_denominator = _uint64(
            entry["raw_denominator"], f"evidence metric {role} raw denominator"
        )
        if raw_denominator != 2048:
            raise SourceAllocationGateError(
                f"evidence metric {role} raw denominator is not 2048"
            )
        value = _fraction_from_object(
            {
                "numerator": entry["numerator"],
                "denominator": entry["denominator"],
            },
            f"evidence metric {role} value",
        )
        if value != Fraction(raw_numerator, raw_denominator):
            raise SourceAllocationGateError(
                f"evidence metric {role} ratio differs from its raw delta"
            )
        values.append(value)
    return values


def _validate_evidence_shape(
    evidence: Mapping[str, Any],
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
) -> None:
    document = _exact_mapping(
        evidence,
        {
            "schema_version",
            "schema_id",
            "repository",
            "target_release",
            "candidate_commit",
            "baseline_release",
            "baseline_commit",
            "measurement_scope",
            "native_package_runtime_measurement",
            "bindings",
            "subjects",
            "campaigns",
            "raw_inventory",
            "metrics",
        },
        "allocation evidence",
    )
    for key, expected in (
        ("schema_version", 1),
        ("schema_id", contract["schemas"]["evidence"]),
        ("repository", contract["repository"]),
        ("target_release", contract["target_release"]),
        ("candidate_commit", candidate_commit),
        ("baseline_release", contract["baseline_release"]),
        ("baseline_commit", contract["baseline_commit"]),
        ("measurement_scope", MEASUREMENT_SCOPE),
        ("native_package_runtime_measurement", False),
    ):
        _expect(document[key], expected, f"evidence {key}")
    _sha40(document["candidate_commit"], "evidence candidate commit")
    _sha40(document["baseline_commit"], "evidence baseline commit")
    bindings = _validate_bindings(document["bindings"], contract)

    subjects = _exact_mapping(document["subjects"], set(ROLES), "evidence subjects")
    for role in ROLES:
        subject = _exact_mapping(
            subjects[role],
            {"release", "commit", "tree", "probe_binary_sha256", "module_graph_sha256"},
            f"evidence subject {role}",
        )
        expected_release = contract["baseline_release"] if role == "baseline" else contract["target_release"]
        expected_commit = contract["baseline_commit"] if role == "baseline" else candidate_commit
        _expect(subject["release"], expected_release, f"evidence subject {role} release")
        _expect(subject["commit"], expected_commit, f"evidence subject {role} commit")
        _sha40(subject["commit"], f"evidence subject {role} commit")
        _sha40(subject["tree"], f"evidence subject {role} tree")
        _sha256(subject["probe_binary_sha256"], f"evidence subject {role} probe")
        _sha256(subject["module_graph_sha256"], f"evidence subject {role} module graph")

    campaigns = _exact_list(document["campaigns"], "evidence campaigns")
    if len(campaigns) != len(CAMPAIGN_IDS):
        raise SourceAllocationGateError("evidence requires exactly three campaigns")
    campaign_times: set[str] = set()
    pair_digests: dict[tuple[str, str, int], str] = {}
    expected_order = [
        role
        for sample_index in range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1)
        for role in (
            ("baseline", "candidate")
            if sample_index % 2 == 1
            else ("candidate", "baseline")
        )
    ]
    for raw_campaign, expected_id in zip(campaigns, CAMPAIGN_IDS):
        campaign = _exact_mapping(
            raw_campaign,
            {"id", "recorded_at", "environment_sha256", "order", "sample_pairs"},
            "evidence campaign",
        )
        _expect(campaign["id"], expected_id, "evidence campaign id")
        recorded_at = _timestamp(campaign["recorded_at"], "evidence campaign recorded_at")
        if recorded_at in campaign_times:
            raise SourceAllocationGateError("evidence campaign timestamps are duplicated")
        campaign_times.add(recorded_at)
        _expect(
            campaign["environment_sha256"], bindings["environment_sha256"],
            "evidence campaign environment",
        )
        order = _exact_list(campaign["order"], "evidence campaign order")
        if order != expected_order:
            raise SourceAllocationGateError("evidence campaign invocation order is invalid")
        pairs = _exact_list(campaign["sample_pairs"], "evidence sample pairs")
        if len(pairs) != SAMPLES_PER_ROLE_PER_CAMPAIGN:
            raise SourceAllocationGateError("evidence campaign requires exactly ten pairs")
        for raw_pair, sample_index in zip(
            pairs, range(1, SAMPLES_PER_ROLE_PER_CAMPAIGN + 1)
        ):
            pair = _exact_mapping(
                raw_pair,
                {
                    "sample_index",
                    "baseline_invocation_index",
                    "baseline_sample_id",
                    "baseline_raw_sha256",
                    "candidate_invocation_index",
                    "candidate_sample_id",
                    "candidate_raw_sha256",
                },
                "evidence sample pair",
            )
            _expect(pair["sample_index"], sample_index, "evidence pair sample_index")
            for role in ROLES:
                _expect(
                    pair[f"{role}_invocation_index"],
                    _expected_invocation(sample_index, role),
                    f"evidence pair {role} invocation_index",
                )
                _expect(
                    pair[f"{role}_sample_id"],
                    f"{expected_id}-{role}-{sample_index:02d}",
                    f"evidence pair {role} sample_id",
                )
                pair_digests[(expected_id, role, sample_index)] = _sha256(
                    pair[f"{role}_raw_sha256"],
                    f"evidence pair {role} raw SHA-256",
                )

    inventory = _exact_list(document["raw_inventory"], "evidence raw inventory")
    if len(inventory) != 60:
        raise SourceAllocationGateError("evidence raw inventory requires exactly 60 entries")
    seen_digests: set[str] = set()
    seen_nonces: set[str] = set()
    for raw_entry, expected_position in zip(
        inventory,
        (
            (campaign_id, invocation_index)
            for campaign_id in CAMPAIGN_IDS
            for invocation_index in range(1, INVOCATIONS_PER_CAMPAIGN + 1)
        ),
    ):
        campaign_id, invocation_index = expected_position
        sample_index = (invocation_index + 1) // 2
        first_role = "baseline" if sample_index % 2 == 1 else "candidate"
        role = first_role if invocation_index % 2 == 1 else (
            "candidate" if first_role == "baseline" else "baseline"
        )
        entry = _exact_mapping(
            raw_entry,
            {
                "path",
                "sha256",
                "campaign_id",
                "subject_role",
                "sample_index",
                "invocation_index",
                "sample_id",
                "process_nonce",
            },
            "evidence raw inventory entry",
        )
        for key, expected in (
            ("path", f"raw/{campaign_id}/{role}-{sample_index:02d}.json"),
            ("campaign_id", campaign_id),
            ("subject_role", role),
            ("sample_index", sample_index),
            ("invocation_index", invocation_index),
            ("sample_id", f"{campaign_id}-{role}-{sample_index:02d}"),
            ("sha256", pair_digests[(campaign_id, role, sample_index)]),
        ):
            _expect(entry[key], expected, f"evidence raw inventory {key}")
        raw_digest = _sha256(entry["sha256"], "evidence raw inventory SHA-256")
        nonce = _exact_string(entry["process_nonce"], "evidence raw inventory nonce")
        if NONCE_PATTERN.fullmatch(nonce) is None:
            raise SourceAllocationGateError("evidence raw inventory nonce is invalid")
        if raw_digest in seen_digests or nonce in seen_nonces:
            raise SourceAllocationGateError("evidence raw digest or nonce is duplicated")
        seen_digests.add(raw_digest)
        seen_nonces.add(nonce)

    metrics = _exact_mapping(document["metrics"], set(METRIC_NAMES), "evidence metrics")
    for name in METRIC_NAMES:
        metric = _exact_mapping(
            metrics[name], {"unit", "direction", "baseline", "candidate"},
            f"evidence metric {name}",
        )
        _expect(metric["unit"], METRIC_UNITS[name], f"evidence metric {name} unit")
        _expect(metric["direction"], "lower", f"evidence metric {name} direction")
        _metric_values(metric, "baseline")
        _metric_values(metric, "candidate")


def build_report(
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    evidence: Mapping[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    _sha256(evidence_sha256, "evidence SHA-256")
    threshold = Fraction(
        int(contract["stable_regression"]["threshold_numerator"]),
        int(contract["stable_regression"]["threshold_denominator"]),
    )
    minimum_regressed = int(contract["stable_regression"]["minimum_regressed_campaigns"])
    metrics: dict[str, Any] = {}
    failures: list[str] = []
    for name in METRIC_NAMES:
        metric = _exact_mapping(
            evidence["metrics"][name],
            {"unit", "direction", "baseline", "candidate"},
            f"evidence metric {name}",
        )
        _expect(metric["unit"], METRIC_UNITS[name], f"evidence metric {name} unit")
        _expect(metric["direction"], "lower", f"evidence metric {name} direction")
        baseline = _metric_values(metric, "baseline")
        candidate = _metric_values(metric, "candidate")
        baseline_median = _median(baseline)
        candidate_median = _median(candidate)
        aggregate, _ = _regression(baseline_median, candidate_median)
        regressed_campaigns = 0
        for campaign_id in CAMPAIGN_IDS:
            indexes = [
                index
                for index, item in enumerate(metric["baseline"])
                if item["campaign_id"] == campaign_id
            ]
            campaign_baseline = _median([baseline[index] for index in indexes])
            campaign_candidate = _median([candidate[index] for index in indexes])
            if _is_regression_over_threshold(
                campaign_baseline, campaign_candidate, threshold
            ):
                regressed_campaigns += 1
        stable = (
            _is_regression_over_threshold(baseline_median, candidate_median, threshold)
            and regressed_campaigns >= minimum_regressed
        )
        verdict = "fail" if stable else "pass"
        if stable:
            failures.append(name)
        metrics[name] = {
            "unit": METRIC_UNITS[name],
            "direction": "lower",
            "baseline": _distribution(baseline),
            "candidate": _distribution(candidate),
            "aggregate_regression": aggregate,
            "regressed_campaigns": regressed_campaigns,
            "stable_regression": stable,
            "verdict": verdict,
        }
    return {
        "schema_version": 1,
        "schema_id": contract["schemas"]["report"],
        "target_release": contract["target_release"],
        "candidate_commit": candidate_commit,
        "baseline_commit": contract["baseline_commit"],
        "evidence_sha256": evidence_sha256,
        "measurement_scope": MEASUREMENT_SCOPE,
        "native_package_runtime_measurement": False,
        "threshold": {
            "numerator": contract["stable_regression"]["threshold_numerator"],
            "denominator": contract["stable_regression"]["threshold_denominator"],
        },
        "campaign_count": len(CAMPAIGN_IDS),
        "samples_per_subject": SAMPLES_PER_ROLE,
        "verdict": "pass" if not failures else "fail",
        "failed_metrics": failures,
        "metrics": metrics,
    }


def validate_evidence(
    document: object,
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    records: Sequence[RawRecord],
) -> dict[str, Any]:
    expected = build_evidence(
        contract=contract, candidate_commit=candidate_commit, records=records
    )
    if _json_wire(document) != _json_wire(expected):
        raise SourceAllocationGateError("evidence does not reproduce exactly from raw samples")
    return expected


def validate_report(
    document: object,
    *,
    contract: Mapping[str, Any],
    candidate_commit: str,
    evidence: Mapping[str, Any],
    evidence_sha256: str,
) -> dict[str, Any]:
    _validate_evidence_shape(
        evidence, contract=contract, candidate_commit=candidate_commit
    )
    expected = build_report(
        contract=contract,
        candidate_commit=candidate_commit,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
    )
    if _json_wire(document) != _json_wire(expected):
        raise SourceAllocationGateError("report does not reproduce exactly from evidence")
    return expected


def validate_raw_bundle(
    *,
    contract_path: Path,
    bundle_root: Path,
    candidate_commit: str,
) -> dict[str, Any]:
    """Validate one raw producer bundle without creating derived evidence."""
    contract = load_contract(contract_path)
    bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
    )
    records = load_raw_records(
        raw_root=bundle_root / "raw",
        contract=contract,
        candidate_commit=candidate_commit,
        bundle=bundle,
    )
    repeated_bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
    )
    if repeated_bundle != bundle:
        raise SourceAllocationGateError(
            "allocation bundle changed during raw validation"
        )
    repeated_records = load_raw_records(
        raw_root=bundle_root / "raw",
        contract=contract,
        candidate_commit=candidate_commit,
        bundle=repeated_bundle,
    )
    if repeated_records != records:
        raise SourceAllocationGateError(
            "raw samples changed during raw validation"
        )
    evidence = build_evidence(
        contract=contract,
        candidate_commit=candidate_commit,
        records=records,
    )
    _validate_evidence_shape(
        evidence,
        contract=contract,
        candidate_commit=candidate_commit,
    )
    return build_report(
        contract=contract,
        candidate_commit=candidate_commit,
        evidence=evidence,
        evidence_sha256=hashlib.sha256(_json_wire(evidence)).hexdigest(),
    )


def _output_parent(path: Path, label: str) -> tuple[int, tuple[int, ...]]:
    path = _canonical_absolute(path, label)
    descriptor, _ = _open_directory_no_symlinks(
        path.parent, private=True, label=f"{label} parent"
    )
    identity = _directory_handle_identity(os.fstat(descriptor))
    try:
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return descriptor, identity
        raise SourceAllocationGateError(f"{label} already exists")
    except Exception:
        os.close(descriptor)
        raise


def _preflight_new_output(path: Path, label: str) -> None:
    descriptor, _ = _output_parent(path, label)
    os.close(descriptor)


def _write_new_bytes(path: Path, wire: bytes, label: str) -> str:
    descriptor, parent_identity = _output_parent(path, label)
    temporary = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        output = os.open(temporary, flags, 0o600, dir_fd=descriptor)
        temporary_created = True
        try:
            os.fchmod(output, 0o600)
            view = memoryview(wire)
            written = 0
            while written < len(view):
                count = os.write(output, view[written:])
                if count <= 0:
                    raise SourceAllocationGateError(f"short write for {label}")
                written += count
            os.fsync(output)
            info = os.fstat(output)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(wire)
            ):
                raise SourceAllocationGateError(f"temporary {label} is unsafe")
        finally:
            os.close(output)
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise SourceAllocationGateError(f"{label} already exists") from exc
        os.unlink(temporary, dir_fd=descriptor)
        temporary_created = False
        target = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(target.st_mode)
            or target.st_nlink != 1
            or target.st_uid != os.geteuid()
            or stat.S_IMODE(target.st_mode) != 0o600
            or target.st_size != len(wire)
        ):
            os.unlink(path.name, dir_fd=descriptor)
            raise SourceAllocationGateError(f"written {label} is unsafe")
        attested = _read_at(
            descriptor,
            path.name,
            maximum=len(wire),
            expected_modes={0o600},
            label=f"written {label}",
        )
        if attested.wire != wire:
            os.unlink(path.name, dir_fd=descriptor)
            raise SourceAllocationGateError(f"written {label} bytes changed")
        os.fsync(descriptor)
        _same_directory_handle_at_path(
            path.parent, parent_identity, f"{label} parent"
        )
        return attested.sha256
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)


def write_new_json(path: Path, document: object, label: str) -> str:
    return _write_new_bytes(path, _json_wire(document), label)


def _require_output_layout(
    bundle_root: Path, evidence_path: Path, report_path: Path
) -> None:
    root = _canonical_absolute(bundle_root, "allocation bundle root")
    evidence = _canonical_absolute(evidence_path, "evidence output")
    report = _canonical_absolute(report_path, "report output")
    if evidence != root / "EVIDENCE.json" or report != root / "REPORT.json":
        raise SourceAllocationGateError(
            "evidence and report must use the canonical bundle output paths"
        )


def assemble(
    *,
    contract_path: Path,
    bundle_root: Path,
    candidate_commit: str,
    evidence_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    contract = load_contract(contract_path)
    _require_output_layout(bundle_root, evidence_path, report_path)
    _preflight_new_output(evidence_path, "evidence output")
    _preflight_new_output(report_path, "report output")
    bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
    )
    records = load_raw_records(
        raw_root=bundle_root / "raw",
        contract=contract,
        candidate_commit=candidate_commit,
        bundle=bundle,
    )
    repeated_bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
    )
    if repeated_bundle != bundle:
        raise SourceAllocationGateError("allocation bundle changed during assembly")
    evidence = build_evidence(
        contract=contract, candidate_commit=candidate_commit, records=records
    )
    evidence_sha256 = hashlib.sha256(_json_wire(evidence)).hexdigest()
    report = build_report(
        contract=contract,
        candidate_commit=candidate_commit,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
    )
    written_evidence_sha256 = write_new_json(
        evidence_path, evidence, "evidence output"
    )
    if written_evidence_sha256 != evidence_sha256:
        raise SourceAllocationGateError("written evidence digest is inconsistent")
    write_new_json(report_path, report, "report output")
    return validate(
        contract_path=contract_path,
        bundle_root=bundle_root,
        candidate_commit=candidate_commit,
        evidence_path=evidence_path,
        report_path=report_path,
    )


def validate(
    *,
    contract_path: Path,
    bundle_root: Path,
    candidate_commit: str,
    evidence_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    contract = load_contract(contract_path)
    _require_output_layout(bundle_root, evidence_path, report_path)
    bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
        include_outputs=True,
    )
    records = load_raw_records(
        raw_root=bundle_root / "raw",
        contract=contract,
        candidate_commit=candidate_commit,
        bundle=bundle,
    )
    evidence_document, evidence_file = _read_json_file(
        evidence_path,
        maximum=MAX_EVIDENCE_BYTES,
        expected_modes={0o600},
        label="allocation evidence",
        require_canonical_wire=True,
    )
    evidence = validate_evidence(
        evidence_document,
        contract=contract,
        candidate_commit=candidate_commit,
        records=records,
    )
    report_document, report_file = _read_json_file(
        report_path,
        maximum=MAX_REPORT_BYTES,
        expected_modes={0o600},
        label="allocation report",
        require_canonical_wire=True,
    )
    result = validate_report(
        report_document,
        contract=contract,
        candidate_commit=candidate_commit,
        evidence=evidence,
        evidence_sha256=evidence_file.sha256,
    )
    repeated_bundle = load_bundle(
        bundle_root=bundle_root,
        contract=contract,
        candidate_commit=candidate_commit,
        include_outputs=True,
    )
    if repeated_bundle != bundle:
        raise SourceAllocationGateError("allocation bundle changed during validation")
    repeated_records = load_raw_records(
        raw_root=bundle_root / "raw",
        contract=contract,
        candidate_commit=candidate_commit,
        bundle=repeated_bundle,
    )
    if repeated_records != records:
        raise SourceAllocationGateError("raw samples changed during validation")
    repeated_evidence = _read_attested_file(
        evidence_path,
        maximum=MAX_EVIDENCE_BYTES,
        expected_modes={0o600},
        label="allocation evidence",
    )
    repeated_report = _read_attested_file(
        report_path,
        maximum=MAX_REPORT_BYTES,
        expected_modes={0o600},
        label="allocation report",
    )
    if repeated_evidence != evidence_file or repeated_report != report_file:
        raise SourceAllocationGateError(
            "allocation evidence or report changed during validation"
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("assemble", "validate", "validate-raw"):
        command = subparsers.add_parser(name)
        command.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
        command.add_argument("--bundle-root", type=Path, required=True)
        command.add_argument("--candidate-commit", required=True)
        if name != "validate-raw":
            command.add_argument("--evidence", type=Path, required=True)
            command.add_argument("--report", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "assemble":
            report = assemble(
                contract_path=arguments.contract,
                bundle_root=arguments.bundle_root,
                candidate_commit=arguments.candidate_commit,
                evidence_path=arguments.evidence,
                report_path=arguments.report,
            )
        elif arguments.command == "validate":
            report = validate(
                contract_path=arguments.contract,
                bundle_root=arguments.bundle_root,
                candidate_commit=arguments.candidate_commit,
                evidence_path=arguments.evidence,
                report_path=arguments.report,
            )
        else:
            report = validate_raw_bundle(
                contract_path=arguments.contract,
                bundle_root=arguments.bundle_root,
                candidate_commit=arguments.candidate_commit,
            )
        print(
            f"Source allocation gate {report['verdict']}: "
            f"{len(report['metrics'])} exact metrics, "
            f"{len(report['failed_metrics'])} stable regressions."
        )
        return 0 if report["verdict"] == "pass" else 1
    except (OSError, SourceAllocationGateError) as exc:
        print(f"source allocation gate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
