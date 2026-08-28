#!/usr/bin/env python3
"""Fail-closed aggregation of SysWarden release-qualification evidence.

The gate consumes two *normalized, bound envelopes*, not the current raw lab
reports. Raw nftables and package reports intentionally fail with exit 2
because they do not yet carry the mandatory Git/package bindings.  A producer
or workflow adapter must validate each raw schema and construct the envelope
described by :func:`build_bound_report`; this module does not infer or invent
missing bindings from command-line declarations.
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
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Sequence

import package_qualification_matrix as qualification_matrix


SCHEMA_VERSION = 2
REPORT_SCHEMA_VERSIONS = {
    "nftables_kernel": 1,
    "linux_package_lifecycle": 5,
}
REPORT_LIMIT = 8 * 1024 * 1024
PACKAGE_LIMIT = 128 * 1024 * 1024
MAX_EVIDENCE_AGE = 172_800
FUTURE_SKEW_SECONDS = 120
VERSION_RE = re.compile(r"^v([0-9]+)\.([0-9]{2})\.([0-9]+)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$")

ALLOWLIST = frozenset(
    {"SW-CFG-001", "SW-FW-004", "SW-PKG-001"}
)
REPORT_ALLOWLIST = {
    "nftables_kernel": frozenset({"SW-FW-004"}),
    "linux_package_lifecycle": frozenset({"SW-CFG-001", "SW-PKG-001"}),
}


class EvidenceError(ValueError):
    """Raised when evidence is structurally unsafe or unverifiable."""


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    device: int
    inode: int
    size: int
    mtime_ns: int
    sha256: str
    payload: bytes


@dataclass(frozen=True)
class RepositoryBinding:
    root: Path
    commit_sha: str
    tree_sha: str
    version: str


@dataclass(frozen=True)
class PackageManifest:
    directory: Path
    sha256: str
    checksums: dict[str, str]
    snapshots: tuple[FileSnapshot, ...]


@dataclass(frozen=True)
class ReportEvidence:
    kind: str
    snapshot: FileSnapshot
    document: dict[str, Any]
    generated_at: datetime
    blockers: tuple[str, ...]
    harness_complete: bool
    release_ready: bool
    previous_version: str | None
    previous_checksums: dict[str, str]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON value is forbidden: {value}")


def strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise EvidenceError(f"{label} root must be a JSON object")
    return document


def _reject_parent_traversal(path: Path, label: str) -> Path:
    """Return the expanded lexical path only when it cannot traverse upward.

    ``Path.absolute()`` deliberately does not collapse ``..`` components.  That
    is useful when checking components with ``lstat()``, but it also means a
    lexical path such as ``evidence/hop/../repo`` can name a file in ``repo``
    while evading a later lexical containment check.  Resolving the path is not
    an acceptable fix because it follows symbolic links.  Reject the traversal
    syntax itself instead, before touching the filesystem.
    """

    expanded = path.expanduser()
    if any(part == os.pardir for part in expanded.parts):
        raise EvidenceError(f"{label} path contains forbidden parent traversal: {path}")
    return expanded


def _absolute_without_symlinks(path: Path, label: str, *, leaf_may_absent: bool = False) -> Path:
    absolute = _reject_parent_traversal(path, label).absolute()
    if not absolute.is_absolute() or any(part == os.pardir for part in absolute.parts):
        raise EvidenceError(f"{label} path is not a safe absolute path: {absolute}")
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.is_absolute() else absolute.parts
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if leaf_may_absent and index == len(parts) - 1:
                return absolute
            raise EvidenceError(f"{label} path component does not exist: {current}")
        except OSError as exc:
            raise EvidenceError(f"cannot inspect {label} path component {current}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"{label} path contains a symbolic link: {current}")
    return absolute


def _inside(path: Path, root: Path) -> bool:
    for candidate, label in ((path, "path"), (root, "containment root")):
        if not candidate.is_absolute():
            raise EvidenceError(f"{label} must be an absolute path: {candidate}")
        if any(part == os.pardir for part in candidate.parts):
            raise EvidenceError(
                f"{label} contains forbidden parent traversal: {candidate}"
            )
    return path == root or root in path.parents


def read_snapshot(path: Path, label: str, *, limit: int = REPORT_LIMIT) -> FileSnapshot:
    absolute = _absolute_without_symlinks(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open {label} {absolute}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"{label} must be a regular non-symlink file: {absolute}")
        if before.st_size <= 0 or before.st_size > limit:
            raise EvidenceError(f"{label} size must be between 1 and {limit} bytes: {absolute}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EvidenceError(f"{label} changed while being read: {absolute}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceError(f"{label} grew while being read: {absolute}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise EvidenceError(f"{label} changed while being read: {absolute}")
    payload = b"".join(chunks)
    return FileSnapshot(
        path=absolute,
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        mtime_ns=before.st_mtime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
        payload=payload,
    )


def revalidate(snapshot: FileSnapshot, label: str) -> None:
    current = read_snapshot(snapshot.path, label, limit=max(REPORT_LIMIT, snapshot.size))
    if (
        current.device,
        current.inode,
        current.size,
        current.mtime_ns,
        current.sha256,
    ) != (
        snapshot.device,
        snapshot.inode,
        snapshot.size,
        snapshot.mtime_ns,
        snapshot.sha256,
    ):
        raise EvidenceError(f"{label} changed after validation: {snapshot.path}")


def _git(root: Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            ("git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"cannot execute Git: {exc}") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        raise EvidenceError(f"Git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            ("git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"cannot execute Git: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"Git {' '.join(arguments)} failed: {detail}")
    return process.stdout


SOURCE_TARGETS = (
    ("src/core/syswarden-cli/pkg/system/upgrade.go", 1),
    ("src/core/syswarden-tui/main.go", 1),
    ("src/core/syswarden-cli/cmd/install.go", 1),
    ("src/core/syswarden-cli/config/default.go", 1),
    ("src/core/syswarden-cli/pkg/integration/webhook.go", 1),
    ("src/core/syswarden-core/webhook/discord.go", 3),
)


def _blob(root: Path, path: str) -> str:
    return _git(root, "show", f"HEAD:{path}")


def verify_source_version(root: Path, expected: str) -> None:
    tokens: list[str] = []
    token_re = re.compile(r"v[0-9]+\.[0-9]{2}\.[0-9]+")
    for path, count in SOURCE_TARGETS:
        matches = token_re.findall(_blob(root, path))
        if len(matches) != count:
            raise EvidenceError(
                f"version source {path} contains {len(matches)} version tokens; expected {count}"
            )
        tokens.extend(matches)
    readme = _blob(root, "README.md")
    matches = re.findall(
        r"(?m)^Current source version: \*\*(v[0-9]+\.[0-9]{2}\.[0-9]+)\*\*\.$",
        readme,
    )
    if matches != [expected]:
        raise EvidenceError("README current source version does not match the release version")
    tokens.extend(matches)
    if any(token != expected for token in tokens):
        raise EvidenceError("source version targets do not all match the release version")
    changelog = _blob(root, "changelog.md").replace("\r\n", "\n").lstrip("\ufeff")
    if not changelog.startswith(f"# Release {expected}\n"):
        raise EvidenceError("changelog first release heading does not match the release version")


def verify_repository(repo_root: Path, expected_sha: str, expected_version: str) -> RepositoryBinding:
    if SHA_RE.fullmatch(expected_sha) is None:
        raise EvidenceError("expected SHA must be a full lowercase 40-character Git SHA")
    if VERSION_RE.fullmatch(expected_version) is None:
        raise EvidenceError("expected version must be canonical vMAJOR.MINOR.PATCH")
    root = _absolute_without_symlinks(repo_root, "repository")
    if not root.is_dir():
        raise EvidenceError(f"repository root is not a directory: {root}")
    actual_root = Path(_git(root, "rev-parse", "--show-toplevel")).absolute()
    if actual_root != root:
        raise EvidenceError(f"repository root mismatch: expected {root}, Git reports {actual_root}")
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")
    if head != expected_sha:
        raise EvidenceError(f"repository HEAD mismatch: expected {expected_sha}, found {head}")
    if SHA_RE.fullmatch(tree) is None:
        raise EvidenceError(f"Git returned an invalid tree SHA: {tree!r}")
    verify_source_version(root, expected_version)
    return RepositoryBinding(root, head, tree, expected_version)


def qualification_matrix_binding(
    binding: RepositoryBinding,
) -> tuple[dict[str, str], dict[str, Any]]:
    payload = _git_bytes(
        binding.root,
        "show",
        f"{binding.commit_sha}:{QUALIFICATION_MATRIX_PATH}",
    )
    try:
        document = qualification_matrix.validate_document(
            strict_json(payload, "committed package qualification matrix")
        )
    except qualification_matrix.QualificationMatrixError as exc:
        raise EvidenceError(f"committed package qualification matrix is invalid: {exc}") from exc
    if document["target_release"] != binding.version:
        raise EvidenceError(
            "committed package qualification matrix target differs from the release"
        )
    return (
        {
            "matrix_id": str(document["matrix_id"]),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        document,
    )


def package_names(version: str) -> tuple[str, ...]:
    raw = version.removeprefix("v")
    return (
        f"syswarden_{raw}_amd64.deb",
        f"syswarden-{raw}-1.x86_64.rpm",
        f"syswarden_{raw}_x86_64.apk",
    )


def verify_packages(directory: Path, binding: RepositoryBinding) -> PackageManifest:
    root = _absolute_without_symlinks(directory, "candidate package directory")
    if not root.is_dir():
        raise EvidenceError(f"candidate package directory is missing: {root}")
    expected_names = set(package_names(binding.version))
    actual_entries: set[str] = set()
    for entry in root.iterdir():
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(
                f"candidate package directory contains a non-regular entry: {entry}"
            )
        actual_entries.add(entry.name)
    expected_entries = expected_names | {"SHA256SUMS.txt"}
    if actual_entries != expected_entries:
        raise EvidenceError(
            "candidate package directory inventory is not exact; "
            f"missing={sorted(expected_entries - actual_entries)}, "
            f"unexpected={sorted(actual_entries - expected_entries)}"
        )
    manifest_snapshot = read_snapshot(root / "SHA256SUMS.txt", "package checksum manifest")
    records: dict[str, str] = {}
    try:
        lines = manifest_snapshot.payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise EvidenceError("package checksum manifest must be UTF-8") from exc
    for number, line in enumerate(lines, 1):
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise EvidenceError(f"invalid package checksum line {number}: {line!r}")
        digest, name = match.groups()
        if name in records:
            raise EvidenceError(f"duplicate package checksum entry: {name}")
        records[name] = digest
    if set(records) != expected_names:
        raise EvidenceError(
            f"package manifest inventory mismatch; expected={sorted(expected_names)}, actual={sorted(records)}"
        )
    snapshots: list[FileSnapshot] = [manifest_snapshot]
    for name in sorted(records):
        snapshot = read_snapshot(root / name, f"package {name}", limit=PACKAGE_LIMIT)
        if snapshot.sha256 != records[name]:
            raise EvidenceError(f"package checksum mismatch for {name}")
        snapshots.append(snapshot)
    identities = {(item.device, item.inode) for item in snapshots}
    if len(identities) != len(snapshots):
        raise EvidenceError("package manifest and artifacts must be distinct files")
    return PackageManifest(root, manifest_snapshot.sha256, records, tuple(snapshots))


def _exact_keys(document: dict[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(document)
    if actual != expected:
        raise EvidenceError(
            f"{label} schema keys differ; missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )


COMMON_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "report_type",
        "generated_at",
        "raw_report_sha256",
        "bindings",
        "harness_complete",
        "release_ready",
        "blocker_ids",
    }
)
REPORT_KEYS = {
    "nftables_kernel": COMMON_REPORT_KEYS
    | {"conditions", "network_namespaces"},
    "linux_package_lifecycle": COMMON_REPORT_KEYS
    | {
        "coverage",
        "lifecycle",
        "evidence_kind",
        "evidence_scope",
        "qualification_matrix",
    },
}
BINDING_KEYS = frozenset(
    {
        "commit_sha",
        "tree_sha",
        "version",
        "tag",
        "package_manifest_sha256",
        "package_checksums",
    }
)
COVERAGE_KEYS = frozenset({"coordinates"})
COORDINATE_KEYS = frozenset({"cell_id", "architecture", "status"})
QUALIFICATION_MATRIX_BINDING_KEYS = frozenset({"matrix_id", "sha256"})
QUALIFICATION_MATRIX_PATH = "scripts/ci/package_qualification_matrix.json"
EVIDENCE_SCOPE_KEYS = frozenset(
    {
        "coverage_kind",
        "real_host_evidence_included",
        "required_checks_complete",
        "covered_scenarios",
    }
)
COVERED_SCENARIO_KEYS = frozenset({"cell_id", "scenarios"})
NFT_CONDITION_KEYS = frozenset(
    {
        "network_namespace_isolated",
        "host_namespace_untouched",
        "kernel_apply_executed",
        "cleanup_complete",
    }
)
NETWORK_NAMESPACE_KEYS = frozenset({"host", "laboratory"})
LIFECYCLE_KEYS = frozenset(
    {
        "previous_version",
        "candidate_version",
        "runtime_mode",
        "active_service_manager",
        "active_postinstall",
        "legacy_runtime_retirement",
        "fresh_install",
        "upgrade",
        "reinstall",
        "rollback",
        "remove",
        "purge",
        "second_container_restart",
        "previous_manifest_sha256",
        "previous_package_checksums",
    }
)


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be an ISO-8601 UTC string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EvidenceError(f"{label} must be timezone-aware UTC")
    return parsed.astimezone(UTC)


def build_bound_report(
    *,
    kind: str,
    generated_at: str,
    raw_report_sha256: str,
    bindings: dict[str, Any],
    harness_complete: bool,
    release_ready: bool,
    blocker_ids: Sequence[str],
    coordinates: Sequence[dict[str, str]] = (),
    lifecycle: dict[str, Any] | None = None,
    evidence_kind: str | None = None,
    evidence_scope: dict[str, Any] | None = None,
    qualification_matrix_binding: dict[str, str] | None = None,
    conditions: dict[str, bool] | None = None,
    network_namespaces: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the exact normalized-envelope shape expected by this gate.

    This is a shape constructor, not a raw-report validator.  The adapter is
    responsible for deriving every supplied status from the named raw report;
    ``raw_report_sha256`` preserves that explicit provenance boundary.
    """

    if kind not in REPORT_SCHEMA_VERSIONS:
        raise EvidenceError(f"unsupported qualification report kind: {kind!r}")
    if SHA256_RE.fullmatch(raw_report_sha256) is None:
        raise EvidenceError("raw report SHA256 must be a lowercase 64-character digest")
    envelope: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSIONS[kind],
        "report_type": kind,
        "generated_at": generated_at,
        "raw_report_sha256": raw_report_sha256,
        "bindings": bindings,
        "harness_complete": harness_complete,
        "release_ready": release_ready,
        "blocker_ids": list(blocker_ids),
    }
    if kind == "nftables_kernel":
        if conditions is None or network_namespaces is None:
            raise EvidenceError(
                "nftables envelope requires conditions and network namespaces"
            )
        if (
            lifecycle is not None
            or coordinates
            or evidence_kind is not None
            or evidence_scope is not None
            or qualification_matrix_binding is not None
        ):
            raise EvidenceError(
                "nftables envelope cannot claim package lifecycle or container scenario coverage"
            )
        envelope["conditions"] = conditions
        envelope["network_namespaces"] = network_namespaces
    else:
        if lifecycle is None:
            raise EvidenceError(f"{kind} envelope requires package lifecycle evidence")
        if (
            evidence_kind != "container-lifecycle"
            or evidence_scope is None
            or qualification_matrix_binding is None
        ):
            raise EvidenceError(
                f"{kind} envelope requires an exact container-lifecycle matrix binding"
            )
        if conditions is not None or network_namespaces is not None:
            raise EvidenceError(f"{kind} envelope cannot contain nftables namespace evidence")
        envelope["coverage"] = {"coordinates": list(coordinates)}
        envelope["evidence_kind"] = evidence_kind
        envelope["evidence_scope"] = evidence_scope
        envelope["qualification_matrix"] = qualification_matrix_binding
        envelope["lifecycle"] = lifecycle
    return envelope


def version_tuple(version: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(version)
    if match is None:
        raise EvidenceError(f"non-canonical SysWarden version: {version!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _validate_nft_evidence(document: dict[str, Any]) -> None:
    conditions = document["conditions"]
    namespaces = document["network_namespaces"]
    if not isinstance(conditions, dict):
        raise EvidenceError("nftables_kernel.conditions must be an object")
    _exact_keys(conditions, NFT_CONDITION_KEYS, "nftables_kernel.conditions")
    if any(type(value) is not bool for value in conditions.values()):
        raise EvidenceError("nftables_kernel conditions must be booleans")
    if not isinstance(namespaces, dict):
        raise EvidenceError("nftables_kernel.network_namespaces must be an object")
    _exact_keys(
        namespaces,
        NETWORK_NAMESPACE_KEYS,
        "nftables_kernel.network_namespaces",
    )
    if any(not isinstance(value, str) or not value for value in namespaces.values()):
        raise EvidenceError("nftables kernel namespace identifiers must be non-empty strings")
    if namespaces["host"] == namespaces["laboratory"]:
        raise EvidenceError("nftables laboratory did not use a separate network namespace")


def _validate_package_matrix_evidence(
    kind: str,
    document: dict[str, Any],
    binding: RepositoryBinding,
) -> dict[str, Any]:
    if document["evidence_kind"] != "container-lifecycle":
        raise EvidenceError(
            f"{kind}.evidence_kind must be exactly container-lifecycle"
        )
    report_matrix = document["qualification_matrix"]
    if not isinstance(report_matrix, dict):
        raise EvidenceError(f"{kind}.qualification_matrix must be an object")
    _exact_keys(
        report_matrix,
        QUALIFICATION_MATRIX_BINDING_KEYS,
        f"{kind}.qualification_matrix",
    )
    if (
        not isinstance(report_matrix["matrix_id"], str)
        or not isinstance(report_matrix["sha256"], str)
        or SHA256_RE.fullmatch(report_matrix["sha256"]) is None
    ):
        raise EvidenceError(f"{kind}.qualification_matrix is not canonical")
    expected, matrix_document = qualification_matrix_binding(binding)
    if report_matrix != expected:
        raise EvidenceError(
            f"{kind}.qualification_matrix differs from the exact committed bytes"
        )
    evidence_scope = document["evidence_scope"]
    if not isinstance(evidence_scope, dict):
        raise EvidenceError(f"{kind}.evidence_scope must be an object")
    _exact_keys(evidence_scope, EVIDENCE_SCOPE_KEYS, f"{kind}.evidence_scope")
    if (
        evidence_scope["coverage_kind"] != "container_scenarios_only"
        or type(evidence_scope["real_host_evidence_included"]) is not bool
        or evidence_scope["real_host_evidence_included"] is not False
        or type(evidence_scope["required_checks_complete"]) is not bool
        or evidence_scope["required_checks_complete"] is not False
    ):
        raise EvidenceError(
            f"{kind}.evidence_scope overstates container lifecycle coverage"
        )
    covered = evidence_scope["covered_scenarios"]
    if not isinstance(covered, list):
        raise EvidenceError(f"{kind}.evidence_scope.covered_scenarios must be an array")
    expected_covered = [
        {
            "cell_id": str(cell["id"]),
            "scenarios": list(cell["container_scenarios"]),
        }
        for cell in matrix_document["cells"]
    ]
    for index, record in enumerate(covered):
        if not isinstance(record, dict):
            raise EvidenceError(
                f"{kind}.evidence_scope.covered_scenarios[{index}] must be an object"
            )
        _exact_keys(
            record,
            COVERED_SCENARIO_KEYS,
            f"{kind}.evidence_scope.covered_scenarios[{index}]",
        )
        if (
            not isinstance(record["cell_id"], str)
            or not isinstance(record["scenarios"], list)
            or any(not isinstance(item, str) for item in record["scenarios"])
        ):
            raise EvidenceError(
                f"{kind}.evidence_scope.covered_scenarios[{index}] has invalid types"
            )
    if covered != expected_covered:
        raise EvidenceError(
            f"{kind}.evidence_scope.covered_scenarios differs from the ordered matrix"
        )
    return matrix_document


def _validate_coverage(
    kind: str,
    document: dict[str, Any],
    matrix_document: dict[str, Any],
) -> None:
    coverage = document["coverage"]
    if not isinstance(coverage, dict):
        raise EvidenceError(f"{kind}.coverage must be an object")
    _exact_keys(coverage, COVERAGE_KEYS, f"{kind}.coverage")
    if not isinstance(coverage["coordinates"], list):
        raise EvidenceError(f"{kind}.coverage has invalid types")
    seen: set[tuple[str, str]] = set()
    expected_cell_ids = [str(cell["id"]) for cell in matrix_document["cells"]]
    if len(coverage["coordinates"]) != len(expected_cell_ids):
        raise EvidenceError(
            f"{kind}.coverage must contain exactly {len(expected_cell_ids)} matrix cells"
        )
    for index, coordinate in enumerate(coverage["coordinates"]):
        if not isinstance(coordinate, dict):
            raise EvidenceError(
                f"{kind}.coverage.coordinates[{index}] must be an object"
            )
        _exact_keys(
            coordinate,
            COORDINATE_KEYS,
            f"{kind}.coverage.coordinates[{index}]",
        )
        if not all(isinstance(coordinate[key], str) for key in COORDINATE_KEYS):
            raise EvidenceError(
                f"{kind}.coverage.coordinates[{index}] values must be strings"
            )
        key = (coordinate["cell_id"], coordinate["architecture"])
        if key in seen:
            raise EvidenceError(f"duplicate {kind} coverage coordinate: {key}")
        seen.add(key)
        if key != (expected_cell_ids[index], "amd64"):
            raise EvidenceError(
                f"{kind}.coverage coordinate at index {index} differs from the "
                "frozen matrix cell order"
            )
        if coordinate["status"] not in {"pass", "blocker"}:
            raise EvidenceError(f"{kind} coverage status cannot be skipped/unknown")


def _validate_lifecycle(
    kind: str,
    document: dict[str, Any],
    binding: RepositoryBinding,
    packages: PackageManifest,
    matrix_document: dict[str, Any],
) -> tuple[str, dict[str, str]]:
    lifecycle = document["lifecycle"]
    if not isinstance(lifecycle, dict):
        raise EvidenceError(f"{kind}.lifecycle must be an object")
    _exact_keys(lifecycle, LIFECYCLE_KEYS, f"{kind}.lifecycle")
    boolean_keys = LIFECYCLE_KEYS - {
        "previous_version",
        "candidate_version",
        "runtime_mode",
        "previous_manifest_sha256",
        "previous_package_checksums",
    }
    for key in boolean_keys:
        if type(lifecycle[key]) is not bool:
            raise EvidenceError(f"{kind}.lifecycle.{key} must be a boolean")
    previous = lifecycle["previous_version"]
    candidate = lifecycle["candidate_version"]
    if not isinstance(previous, str) or not isinstance(candidate, str):
        raise EvidenceError(f"{kind} lifecycle versions must be strings")
    if candidate != binding.version or version_tuple(previous) >= version_tuple(candidate):
        raise EvidenceError(f"{kind} lifecycle must prove previous_version < candidate_version")
    if lifecycle["runtime_mode"] != "active-container-init":
        raise EvidenceError(
            f"{kind} lifecycle runtime_mode must be active-container-init"
        )
    previous_checksums = lifecycle["previous_package_checksums"]
    if not isinstance(previous_checksums, dict):
        raise EvidenceError(
            f"{kind}.lifecycle.previous_package_checksums must be an object"
        )
    pairs = list(zip(package_names(previous), package_names(candidate)))
    expected_previous_names = {previous_name for previous_name, _ in pairs}
    if set(previous_checksums) != expected_previous_names:
        raise EvidenceError(f"{kind} previous package checksum inventory is incomplete")
    if any(
        not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None
        for digest in previous_checksums.values()
    ):
        raise EvidenceError(f"{kind} previous package checksums are invalid")
    previous_manifest_sha256 = lifecycle["previous_manifest_sha256"]
    if (
        not isinstance(previous_manifest_sha256, str)
        or SHA256_RE.fullmatch(previous_manifest_sha256) is None
    ):
        raise EvidenceError(f"{kind} previous package manifest SHA256 is invalid")
    baseline = matrix_document["package_sources"]["baseline"]
    if previous != baseline["release"]:
        raise EvidenceError(
            f"{kind} previous version differs from the frozen baseline release"
        )
    baseline_assets = {
        asset["name"]: asset for asset in baseline["assets"]
    }
    expected_baseline_names = expected_previous_names | {"SHA256SUMS.txt"}
    if set(baseline_assets) != expected_baseline_names:
        raise EvidenceError(
            f"{kind} qualification matrix baseline asset inventory is incomplete"
        )
    expected_previous_checksums = {
        name: baseline_assets[name]["sha256"] for name in expected_previous_names
    }
    if previous_checksums != expected_previous_checksums:
        raise EvidenceError(
            f"{kind} previous package checksums differ from the frozen baseline assets"
        )
    if previous_manifest_sha256 != baseline_assets["SHA256SUMS.txt"]["sha256"]:
        raise EvidenceError(
            f"{kind} previous package manifest differs from the frozen baseline asset"
        )
    for previous_name, candidate_name in pairs:
        if previous_checksums[previous_name] == packages.checksums[candidate_name]:
            raise EvidenceError(
                f"{kind} previous/candidate package bytes are not distinct"
            )
    return previous, previous_checksums


def parse_report(
    kind: str,
    path: Path,
    binding: RepositoryBinding,
    packages: PackageManifest,
    now: datetime,
    max_age_seconds: int,
) -> ReportEvidence:
    snapshot = read_snapshot(path, f"{kind} report")
    if _inside(snapshot.path, binding.root):
        raise EvidenceError(f"{kind} report must be outside the repository")
    document = strict_json(snapshot.payload, f"{kind} report")
    if "bindings" not in document:
        raise EvidenceError(f"{kind} report is legacy/unbound: mandatory bindings are missing")
    _exact_keys(document, frozenset(REPORT_KEYS[kind]), f"{kind} report")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != REPORT_SCHEMA_VERSIONS[kind]
        or document["report_type"] != kind
    ):
        raise EvidenceError(f"{kind} report schema version/type mismatch")
    if (
        not isinstance(document["raw_report_sha256"], str)
        or SHA256_RE.fullmatch(document["raw_report_sha256"]) is None
    ):
        raise EvidenceError(f"{kind}.raw_report_sha256 is invalid")
    generated_at = parse_timestamp(document["generated_at"], f"{kind}.generated_at")
    if generated_at > now + timedelta(seconds=FUTURE_SKEW_SECONDS):
        raise EvidenceError(f"{kind} report timestamp is too far in the future")
    if now - generated_at > timedelta(seconds=max_age_seconds):
        raise EvidenceError(f"{kind} report is stale")
    report_binding = document["bindings"]
    if not isinstance(report_binding, dict):
        raise EvidenceError(f"{kind}.bindings must be an object")
    _exact_keys(report_binding, BINDING_KEYS, f"{kind}.bindings")
    expected_binding = {
        "commit_sha": binding.commit_sha,
        "tree_sha": binding.tree_sha,
        "version": binding.version,
        "tag": binding.version,
        "package_manifest_sha256": packages.sha256,
        "package_checksums": packages.checksums,
    }
    if report_binding != expected_binding:
        raise EvidenceError(f"{kind} report bindings do not match verified Git/package evidence")
    for key in ("harness_complete", "release_ready"):
        if type(document[key]) is not bool:
            raise EvidenceError(f"{kind}.{key} must be a boolean")
    blocker_ids = document["blocker_ids"]
    if not isinstance(blocker_ids, list) or any(not isinstance(item, str) for item in blocker_ids):
        raise EvidenceError(f"{kind}.blocker_ids must be a string array")
    if blocker_ids != sorted(set(blocker_ids)):
        raise EvidenceError(f"{kind}.blocker_ids must be sorted and unique")
    if kind == "nftables_kernel":
        _validate_nft_evidence(document)
        previous: str | None = None
        previous_checksums: dict[str, str] = {}
    else:
        matrix_document = _validate_package_matrix_evidence(
            kind, document, binding
        )
        _validate_coverage(kind, document, matrix_document)
        previous, previous_checksums = _validate_lifecycle(
            kind, document, binding, packages, matrix_document
        )
    return ReportEvidence(
        kind,
        snapshot,
        document,
        generated_at,
        tuple(blocker_ids),
        document["harness_complete"],
        document["release_ready"],
        previous,
        previous_checksums,
    )


ARCHITECTURES = frozenset({"amd64"})
QUALIFICATION_CELL_IDS = tuple(
    cell.identifier for cell in qualification_matrix.EXPECTED_CELLS
)
ALPINE_CELL_IDS = frozenset(
    cell.identifier
    for cell in qualification_matrix.EXPECTED_CELLS
    if cell.family == "apk"
)


def policy_reasons(profile: str, reports: tuple[ReportEvidence, ...]) -> list[str]:
    reasons: list[str] = []
    by_kind = {report.kind: report for report in reports}
    if any(not report.harness_complete for report in reports):
        reasons.append("every laboratory must report harness_complete=true")
    previous_versions = {
        report.previous_version
        for report in reports
        if report.previous_version is not None
    }
    if len(previous_versions) != 1:
        reasons.append("package evidence must bind exactly one previous version")
    previous_checksums: dict[str, str] = {}
    for report in reports:
        overlap = set(previous_checksums) & set(report.previous_checksums)
        if overlap:
            reasons.append("previous package checksum coordinates overlap between reports")
        previous_checksums.update(report.previous_checksums)
    if len(previous_versions) == 1:
        previous_version = next(iter(previous_versions))
        if set(previous_checksums) != set(package_names(previous_version)):
            reasons.append("combined previous package checksum inventory is incomplete")
    linux = by_kind["linux_package_lifecycle"].document["coverage"]
    linux_coordinates = {
        (item["cell_id"], item["architecture"]): item["status"]
        for item in linux["coordinates"]
    }
    expected_linux_coordinates = {
        (cell_id, architecture)
        for cell_id in QUALIFICATION_CELL_IDS
        for architecture in ARCHITECTURES
    }
    if set(linux_coordinates) != expected_linux_coordinates:
        reasons.append(
            "Linux container coverage must contain exactly the eight frozen AMD64 cells"
        )
    package_blockers = set(by_kind["linux_package_lifecycle"].blockers)
    alpine_statuses = {
        status
        for (cell_id, _), status in linux_coordinates.items()
        if cell_id in ALPINE_CELL_IDS
    }
    if "SW-PKG-001" in package_blockers and alpine_statuses != {"blocker"}:
        reasons.append("SW-PKG-001 must be bound to the Alpine AMD64 blocker")
    if "SW-PKG-001" not in package_blockers and "blocker" in alpine_statuses:
        reasons.append("Alpine blocker coverage lacks canonical SW-PKG-001")
    config_statuses = {
        status
        for (cell_id, _), status in linux_coordinates.items()
        if cell_id not in ALPINE_CELL_IDS
    }
    if "SW-CFG-001" in package_blockers and config_statuses != {"blocker"}:
        reasons.append(
            "SW-CFG-001 must be bound to every non-Alpine package coordinate"
        )
    if "SW-CFG-001" not in package_blockers and "blocker" in config_statuses:
        reasons.append(
            "non-Alpine package blocker coverage lacks canonical SW-CFG-001"
        )
    nft_conditions = by_kind["nftables_kernel"].document["conditions"]
    if not all(nft_conditions.values()):
        reasons.append("nftables kernel isolation/apply/cleanup evidence is incomplete")
    for report in reports:
        if report.kind != "nftables_kernel":
            lifecycle = report.document["lifecycle"]
            if not all(
                lifecycle[key]
                for key in LIFECYCLE_KEYS
                - {
                    "previous_version",
                    "candidate_version",
                    "runtime_mode",
                    "previous_manifest_sha256",
                    "previous_package_checksums",
                }
            ):
                reasons.append(f"{report.kind} lifecycle is incomplete")
        unknown = set(report.blockers) - REPORT_ALLOWLIST[report.kind]
        if unknown:
            reasons.append(f"{report.kind} contains unregistered blocker IDs: {sorted(unknown)}")
        if report.release_ready and report.blockers:
            reasons.append(f"{report.kind} is release-ready while still declaring blockers")
        if not report.release_ready and not report.blockers:
            reasons.append(f"{report.kind} is not release-ready without an explicit canonical blocker")
        if report.kind != "nftables_kernel":
            has_blocked_coordinate = any(
                item["status"] == "blocker"
                for item in report.document["coverage"]["coordinates"]
            )
            if has_blocked_coordinate and not report.blockers:
                reasons.append(f"{report.kind} has a blocked coordinate without a finding")
            if report.release_ready and has_blocked_coordinate:
                reasons.append(f"{report.kind} is release-ready with a blocked coordinate")
    if profile == "characterization":
        if any(set(report.blockers) - ALLOWLIST for report in reports):
            reasons.append("characterization contains a blocker outside the fixed roadmap allowlist")
    else:
        if any(report.blockers for report in reports):
            reasons.append("release profile forbids every blocker or waiver")
        if any(not report.release_ready for report in reports):
            reasons.append("release profile requires every report release_ready=true")
        all_coordinates = [
            item
            for report in reports
            if report.kind != "nftables_kernel"
            for item in report.document["coverage"]["coordinates"]
        ]
        if any(item["status"] != "pass" for item in all_coordinates):
            reasons.append("release profile requires every coverage coordinate to pass")
    return sorted(set(reasons))


def write_atomic(path: Path, payload: dict[str, Any], repo_root: Path) -> None:
    destination = _absolute_without_symlinks(path, "output", leaf_may_absent=True)
    if _inside(destination, repo_root):
        raise EvidenceError("qualification output must be outside the repository")
    parent = _absolute_without_symlinks(destination.parent, "output parent")
    if not parent.is_dir():
        raise EvidenceError(f"output parent is not a directory: {parent}")
    if destination.exists():
        metadata = destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("qualification output must be absent or a regular non-symlink file")
    serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    temporary = Path(temporary_raw)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(serialized):
            count = os.write(descriptor, serialized[written:])
            if count <= 0:
                raise EvidenceError("atomic qualification output write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if destination.is_symlink():
            raise EvidenceError("qualification output became a symbolic link")
        os.replace(temporary, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def evaluate_gate(
    args: argparse.Namespace, *, now: datetime | None = None
) -> tuple[int, dict[str, Any], RepositoryBinding]:
    if args.profile not in {"characterization", "release"}:
        raise EvidenceError(f"unsupported qualification profile: {args.profile!r}")
    if args.max_age_seconds < 60 or args.max_age_seconds > MAX_EVIDENCE_AGE:
        raise EvidenceError(f"max evidence age must be between 60 and {MAX_EVIDENCE_AGE} seconds")
    if args.max_report_skew_seconds < 0 or args.max_report_skew_seconds > 3600:
        raise EvidenceError("max report skew must be between 0 and 3600 seconds")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    binding = verify_repository(args.repo_root, args.expected_sha, args.expected_version)
    packages = verify_packages(args.candidate_packages_dir, binding)
    paths = {
        "nftables_kernel": args.nft_report,
        "linux_package_lifecycle": args.package_report,
    }
    reports = tuple(
        parse_report(kind, path, binding, packages, current, args.max_age_seconds)
        for kind, path in paths.items()
    )
    report_identities = {(item.snapshot.device, item.snapshot.inode) for item in reports}
    if len(report_identities) != 2:
        raise EvidenceError("the two reports must be distinct files/inodes")
    if len({item.snapshot.path for item in reports}) != 2:
        raise EvidenceError("the two reports must have distinct resolved paths")
    if len({item.snapshot.path.name for item in reports}) != 2:
        raise EvidenceError("the two reports must have distinct stable filenames")
    if len({item.document["raw_report_sha256"] for item in reports}) != 2:
        raise EvidenceError("the two envelopes must bind distinct raw reports")
    timestamps = [item.generated_at for item in reports]
    if max(timestamps) - min(timestamps) > timedelta(seconds=args.max_report_skew_seconds):
        raise EvidenceError("report timestamps exceed the allowed inter-report skew")
    reasons = policy_reasons(args.profile, reports)
    for report in reports:
        revalidate(report.snapshot, f"{report.kind} report")
    for snapshot in packages.snapshots:
        revalidate(snapshot, "package evidence")
    expires_at = min(item.generated_at for item in reports) + timedelta(seconds=args.max_age_seconds)
    all_blockers = sorted({blocker for report in reports for blocker in report.blockers})
    lifecycle_reports = [
        report for report in reports if report.previous_version is not None
    ]
    previous_version = lifecycle_reports[0].previous_version
    previous_checksums: dict[str, str] = {}
    for report in lifecycle_reports:
        previous_checksums.update(report.previous_checksums)
    passed = not reasons
    package_report = next(
        report for report in reports if report.kind == "linux_package_lifecycle"
    )
    aggregate = {
        "schema_version": SCHEMA_VERSION,
        "profile": args.profile,
        "generated_at": current.isoformat(),
        "expires_at": expires_at.isoformat(),
        "bindings": {
            "commit_sha": binding.commit_sha,
            "tree_sha": binding.tree_sha,
            "version": binding.version,
            "tag": binding.version,
            "package_manifest_sha256": packages.sha256,
            "package_checksums": packages.checksums,
            "previous_version": previous_version,
            "previous_manifest_sha256": package_report.document["lifecycle"][
                "previous_manifest_sha256"
            ],
            "previous_package_checksums": previous_checksums,
            "qualification_matrix": package_report.document[
                "qualification_matrix"
            ],
        },
        "reports": {
            report.kind: {
                "filename": report.snapshot.path.name,
                "sha256": report.snapshot.sha256,
                "raw_report_sha256": report.document["raw_report_sha256"],
                "generated_at": report.generated_at.isoformat(),
                "harness_complete": report.harness_complete,
                "release_ready": report.release_ready,
                **(
                    {
                        "evidence_kind": report.document["evidence_kind"],
                        "evidence_scope": report.document["evidence_scope"],
                        "qualification_matrix": report.document[
                            "qualification_matrix"
                        ],
                    }
                    if report.kind == "linux_package_lifecycle"
                    else {}
                ),
            }
            for report in reports
        },
        "harness_complete": all(report.harness_complete for report in reports),
        "release_ready": passed and args.profile == "release",
        "allowlisted_findings": all_blockers if args.profile == "characterization" else [],
        "verdict": "pass" if passed else "blocked",
        "reasons": reasons,
    }
    return (0 if passed else 1), aggregate, binding


def run_gate(args: argparse.Namespace, *, now: datetime | None = None) -> tuple[int, dict[str, Any]]:
    return_code, aggregate, binding = evaluate_gate(args, now=now)
    write_atomic(args.output, aggregate, binding.root)
    return return_code, aggregate


AGGREGATE_KEYS = frozenset(
    {
        "schema_version",
        "profile",
        "generated_at",
        "expires_at",
        "bindings",
        "reports",
        "harness_complete",
        "release_ready",
        "allowlisted_findings",
        "verdict",
        "reasons",
    }
)


def verify_aggregate(
    args: argparse.Namespace, *, now: datetime | None = None
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    aggregate_snapshot = read_snapshot(args.aggregate, "qualification aggregate")
    document = strict_json(aggregate_snapshot.payload, "qualification aggregate")
    _exact_keys(document, AGGREGATE_KEYS, "qualification aggregate")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["profile"] != "release"
        or document["verdict"] != "pass"
        or document["release_ready"] is not True
        or document["harness_complete"] is not True
        or document["reasons"] != []
        or document["allowlisted_findings"] != []
    ):
        raise EvidenceError(
            "aggregate is not an exact container-lifecycle-scoped release gate PASS verdict"
        )
    generated_at = parse_timestamp(document["generated_at"], "aggregate.generated_at")
    expires_at = parse_timestamp(document["expires_at"], "aggregate.expires_at")
    if generated_at > current + timedelta(seconds=FUTURE_SKEW_SECONDS):
        raise EvidenceError("aggregate timestamp is too far in the future")
    if current > expires_at:
        raise EvidenceError("qualification aggregate has expired")

    evaluation_args = argparse.Namespace(**vars(args))
    evaluation_args.profile = "release"
    return_code, expected, binding = evaluate_gate(evaluation_args, now=current)
    if return_code != 0:
        raise EvidenceError("current evidence no longer satisfies the release profile")
    if _inside(aggregate_snapshot.path, binding.root):
        raise EvidenceError("qualification aggregate must be outside the repository")
    if getattr(args, "require_tag", False):
        tagged = _git(
            binding.root,
            "rev-parse",
            "--verify",
            f"refs/tags/{binding.version}^{{commit}}",
        )
        if tagged != binding.commit_sha:
            raise EvidenceError(
                f"release tag {binding.version} resolves to {tagged}, expected {binding.commit_sha}"
            )
    latest_report_time = max(
        parse_timestamp(item["generated_at"], "aggregate report generated_at")
        for item in expected["reports"].values()
    )
    if generated_at < latest_report_time or generated_at > expires_at:
        raise EvidenceError(
            "aggregate generation/expiry timestamps are inconsistent with its reports"
        )
    expected["generated_at"] = document["generated_at"]
    if document != expected:
        raise EvidenceError("aggregate content does not match freshly recomputed evidence")
    revalidate(aggregate_snapshot, "qualification aggregate")
    return document


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--candidate-packages-dir", type=Path, required=True)
    parser.add_argument("--nft-report", type=Path, required=True)
    parser.add_argument("--package-report", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    parser.add_argument("--max-report-skew-seconds", type=int, default=300)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", help="generate a qualification aggregate")
    _add_common_arguments(generate)
    generate.add_argument(
        "--profile", choices=("characterization", "release"), required=True
    )
    generate.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="recompute and verify a release aggregate")
    _add_common_arguments(verify)
    verify.add_argument("--aggregate", type=Path, required=True)
    verify.add_argument(
        "--require-tag",
        action="store_true",
        help="require the version tag to exist and resolve to the expected release SHA",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            return_code, aggregate = run_gate(args)
        else:
            aggregate = verify_aggregate(args)
            return_code = 0
    except EvidenceError as exc:
        print(f"release qualification evidence invalid: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
