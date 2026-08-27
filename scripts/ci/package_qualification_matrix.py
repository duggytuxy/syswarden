#!/usr/bin/env python3
"""Validate the frozen SysWarden AMD64 package qualification matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


DEFAULT_MATRIX = Path(__file__).with_suffix(".json")
MAX_MATRIX_BYTES = 128 * 1024
IMAGE_PATTERN = re.compile(
    r"^(?P<repository>[a-z0-9][a-z0-9./_-]*):"
    r"(?P<tag>[A-Za-z0-9._-]+)@sha256:(?P<digest>[0-9a-f]{64})$"
)
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class QualificationMatrixError(ValueError):
    """Raised when the package qualification matrix violates its contract."""


@dataclass(frozen=True)
class CellContract:
    identifier: str
    distribution: str
    version: str
    family: str
    image: str
    container_scenarios: tuple[str, ...]
    required_checks: tuple[str, ...]
    real_host_mode: str
    reboot_count: int


@dataclass(frozen=True)
class BaselineAsset:
    name: str
    identifier: int
    size: int
    architecture: str
    sha256: str


EXPECTED_ARCHITECTURE = {
    "oci_platform": "linux/amd64",
    "kernel": "x86_64",
    "deb": "amd64",
    "rpm": "x86_64",
    "apk": "x86_64",
}

EXPECTED_CANDIDATE_SOURCE = {
    "workflow": "package.yml",
    "successful_run_count": 1,
    "commit_binding": "same-candidate-commit",
    "local_rebuild_allowed": False,
}

EXPECTED_BASELINE_SOURCE = {
    "release": "v4.03.3",
    "commit": "cdd66600a1505bae1f1e754dea096ee71e9cee82",
    "release_id": 377680978,
    "release_state": "public-stable",
    "asset_selection": "github-asset-id",
}

EXPECTED_BASELINE_ASSETS = (
    BaselineAsset(
        "SHA256SUMS.txt",
        532015727,
        283,
        "metadata",
        "91c89428bf20d2386adf0d7529dc5edb26da6d490db872fab0771ddfce5364c2",
    ),
    BaselineAsset(
        "syswarden_4.03.3_amd64.deb",
        532015759,
        13874730,
        "amd64",
        "4d17e74b16022be31a3e6db8851386f8c0df14772ea38f04f7df45540c818c9b",
    ),
    BaselineAsset(
        "syswarden-4.03.3-1.x86_64.rpm",
        532015720,
        14160347,
        "x86_64",
        "42e207f7f5ae47384c0c35764cf4da179feed1cac34f4fb3bfbd3b59aee8881e",
    ),
    BaselineAsset(
        "syswarden_4.03.3_x86_64.apk",
        532015763,
        14039148,
        "x86_64",
        "73f2d1cf67f62e781dc3d78cc9f9b2d5732ec876fee6587b305aeaaa3830f3d5",
    ),
)

EXPECTED_ARTIFACT_INVENTORY = (
    "deb:amd64",
    "rpm:x86_64",
    "apk:x86_64",
    "SHA256SUMS.txt",
)

EXPECTED_BUDGETS = {
    "protected_qualification_seconds": 21600,
    "package_build_or_extract_seconds": 900,
    "lifecycle_scenario_seconds": 600,
    "kernel_lab": {
        "seconds": 240,
        "pids": 128,
        "memory_mib": 512,
        "tmpfs_mib": 64,
    },
    "container_cell_seconds": 2700,
    "real_host_cell_seconds": 5400,
    "post_reboot_ready_seconds": 600,
    "updater_download_seconds": 600,
    "updater_install_seconds": 1800,
}

EXPECTED_EVIDENCE = (
    "immutable-base-identity",
    "kernel-architecture-and-package-manager",
    "candidate-source-commit",
    "candidate-workflow-run-id",
    "candidate-artifact-id",
    "baseline-release-asset-id",
    "package-name-size-and-sha256",
    "package-inventory-before-and-after",
    "redacted-configuration-before-and-after",
    "services-and-init-system",
    "nftables-state-and-rule-ownership",
    "selinux-and-firewalld-when-required",
    "openrc-and-cronie-when-required",
    "lifecycle-scenario-results",
    "owned-residue-absence",
    "required-real-reboots",
    "complete-private-logs",
    "redacted-public-summary",
    "same-candidate-commit-verdict",
)

EXPECTED_CELLS = (
    CellContract(
        "DEB-13",
        "debian",
        "13",
        "deb",
        "docker.io/library/debian:13-slim@sha256:"
        "d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132",
        ("upgrade-rollback", "remove", "purge"),
        (
            "install",
            "upgrade",
            "rollback",
            "remove",
            "reinstall",
            "purge",
        ),
        "required",
        2,
    ),
    CellContract(
        "DEB-U2404",
        "ubuntu",
        "24.04",
        "deb",
        "docker.io/library/ubuntu:24.04@sha256:"
        "019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467",
        ("upgrade-rollback", "remove", "purge"),
        (
            "install",
            "upgrade",
            "confined-recovery",
            "remove",
            "reinstall",
            "purge",
        ),
        "none",
        0,
    ),
    CellContract(
        "DEB-U2604",
        "ubuntu",
        "26.04",
        "deb",
        "docker.io/library/ubuntu:26.04@sha256:"
        "2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b",
        ("upgrade-rollback", "remove", "purge"),
        (
            "install",
            "signed-updater",
            "confined-recovery",
            "remove",
            "reinstall",
            "purge",
        ),
        "required",
        2,
    ),
    CellContract(
        "RPM-F44",
        "fedora",
        "44",
        "rpm",
        "docker.io/library/fedora:44@sha256:"
        "89f61a124414261868224666aa7fb8df1b78397a53623774bdfb105d1612b48b",
        ("upgrade-rollback", "remove"),
        (
            "install",
            "upgrade",
            "nftables",
            "cronie",
            "remove",
        ),
        "conditional",
        1,
    ),
    CellContract(
        "RPM-A9",
        "almalinux",
        "9",
        "rpm",
        "docker.io/library/almalinux:9@sha256:"
        "28db580abb508f7ccbc0ac6d53e1d8da9d42a26c77fa3dcc26ac2726673fbe3e",
        ("upgrade-rollback", "remove"),
        ("install", "upgrade", "selinux-enforcing", "firewalld", "remove"),
        "none",
        0,
    ),
    CellContract(
        "RPM-A10",
        "almalinux",
        "10",
        "rpm",
        "docker.io/library/almalinux:10@sha256:"
        "cc24bc5b6ac7e284f2f62a07bdaa1b15d3319fdcf46413c6b8fe9fa245068ddd",
        ("upgrade-rollback", "remove"),
        (
            "install",
            "upgrade",
            "selinux-enforcing",
            "firewalld",
            "remove",
        ),
        "required",
        2,
    ),
    CellContract(
        "APK-322",
        "alpine",
        "3.22",
        "apk",
        "docker.io/library/alpine:3.22@sha256:"
        "7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6",
        ("upgrade-rollback", "remove", "purge"),
        (
            "payload-only",
            "activation",
            "upgrade",
            "openrc",
            "cronie",
            "remove",
            "purge",
        ),
        "none",
        0,
    ),
    CellContract(
        "APK-324",
        "alpine",
        "3.24",
        "apk",
        "docker.io/library/alpine:3.24@sha256:"
        "28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        ("upgrade-rollback", "remove", "purge"),
        (
            "payload-only",
            "activation",
            "upgrade",
            "openrc",
            "cronie",
            "remove",
            "purge",
        ),
        "required",
        2,
    ),
)

TOP_LEVEL_KEYS = {
    "schema_version",
    "matrix_id",
    "target_release",
    "architecture",
    "package_sources",
    "budgets",
    "required_evidence",
    "cells",
}
CELL_KEYS = {
    "id",
    "distribution",
    "version",
    "family",
    "image",
    "container_scenarios",
    "required_checks",
    "real_host",
}
REAL_HOST_KEYS = {"mode", "reboot_count"}
REAL_HOST_REBOOT_COUNTS = {"none": 0, "conditional": 1, "required": 2}
BASELINE_ASSET_KEYS = {"name", "id", "size", "architecture", "sha256"}


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationMatrixError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise QualificationMatrixError(f"non-finite JSON value is forbidden: {value}")


def _stable_regular_file_bytes(path: Path) -> bytes:
    absolute = path.expanduser().absolute()
    try:
        before = absolute.lstat()
    except OSError as exc:
        raise QualificationMatrixError(f"cannot inspect matrix {absolute}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise QualificationMatrixError(f"matrix is not a regular non-symlink file: {absolute}")
    if before.st_size <= 0 or before.st_size > MAX_MATRIX_BYTES:
        raise QualificationMatrixError(
            f"matrix size must be between 1 and {MAX_MATRIX_BYTES} bytes: {absolute}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise QualificationMatrixError(f"cannot open matrix {absolute}: {exc}") from exc
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise QualificationMatrixError(f"opened matrix is not a regular file: {absolute}")
        if (before.st_dev, before.st_ino) != (
            opened_before.st_dev,
            opened_before.st_ino,
        ):
            raise QualificationMatrixError(f"matrix identity changed before read: {absolute}")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_MATRIX_BYTES + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > MAX_MATRIX_BYTES:
                raise QualificationMatrixError(f"matrix exceeds size limit: {absolute}")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(opened_before, field) != getattr(opened_after, field)
        for field in identity_fields
    ):
        raise QualificationMatrixError(f"matrix changed while being read: {absolute}")
    data = b"".join(chunks)
    if len(data) != opened_after.st_size:
        raise QualificationMatrixError(f"matrix read size changed: {absolute}")
    return data


def _strict_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationMatrixError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise QualificationMatrixError(f"{label} root must be a JSON object")
    return document


def _require_exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationMatrixError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise QualificationMatrixError(
            f"{label} keys are not exact; missing={missing}, unexpected={unexpected}"
        )
    return value


def _reject_active_arm_tokens(value: object, path: str = "matrix") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_active_arm_tokens(key, f"{path}.<key>")
            _reject_active_arm_tokens(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_active_arm_tokens(item, f"{path}[{index}]")
        return
    if isinstance(value, str):
        folded = value.casefold()
        if "arm64" in folded or "aarch64" in folded:
            raise QualificationMatrixError(
                f"retired architecture token is forbidden at {path}"
            )


def _require_exact_mapping(value: object, expected: dict[str, Any], label: str) -> None:
    mapping = _require_exact_keys(value, set(expected), label)
    for key, expected_value in expected.items():
        actual = mapping[key]
        if type(actual) is not type(expected_value) or actual != expected_value:
            raise QualificationMatrixError(f"{label} does not match the frozen contract")


def _require_exact_list(value: object, expected: tuple[str, ...], label: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise QualificationMatrixError(f"{label} must be a string array")
    if tuple(value) != expected:
        raise QualificationMatrixError(f"{label} does not match the frozen order")


def _validate_baseline_assets(value: object) -> None:
    if not isinstance(value, list):
        raise QualificationMatrixError("package_sources.baseline.assets must be an array")
    if len(value) != len(EXPECTED_BASELINE_ASSETS):
        raise QualificationMatrixError(
            "package_sources.baseline.assets must contain exactly four entries"
        )
    names: list[str] = []
    identifiers: list[int] = []
    for index, (raw, contract) in enumerate(
        zip(value, EXPECTED_BASELINE_ASSETS, strict=True)
    ):
        label = f"package_sources.baseline.assets[{index}]"
        asset = _require_exact_keys(raw, BASELINE_ASSET_KEYS, label)
        expected = {
            "name": contract.name,
            "id": contract.identifier,
            "size": contract.size,
            "architecture": contract.architecture,
            "sha256": contract.sha256,
        }
        _require_exact_mapping(asset, expected, label)
        if type(asset["id"]) is not int or asset["id"] <= 0:
            raise QualificationMatrixError(f"{label}.id must be a positive integer")
        if type(asset["size"]) is not int or asset["size"] <= 0:
            raise QualificationMatrixError(f"{label}.size must be a positive integer")
        if re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]) is None:
            raise QualificationMatrixError(f"{label}.sha256 is not canonical")
        names.append(asset["name"])
        identifiers.append(asset["id"])
    if len(set(names)) != len(names):
        raise QualificationMatrixError("baseline asset names must be unique")
    if len(set(identifiers)) != len(identifiers):
        raise QualificationMatrixError("baseline asset IDs must be unique")


def _validate_package_sources(value: object) -> None:
    sources = _require_exact_keys(
        value, {"candidate", "baseline", "artifact_inventory"}, "package_sources"
    )
    _require_exact_mapping(
        sources["candidate"], EXPECTED_CANDIDATE_SOURCE, "package_sources.candidate"
    )
    baseline = _require_exact_keys(
        sources["baseline"],
        set(EXPECTED_BASELINE_SOURCE) | {"assets"},
        "package_sources.baseline",
    )
    _require_exact_mapping(
        {key: baseline[key] for key in EXPECTED_BASELINE_SOURCE},
        EXPECTED_BASELINE_SOURCE,
        "package_sources.baseline identity",
    )
    if COMMIT_PATTERN.fullmatch(baseline["commit"]) is None:
        raise QualificationMatrixError("baseline commit is not a full lowercase SHA")
    if type(baseline["release_id"]) is not int or baseline["release_id"] <= 0:
        raise QualificationMatrixError("baseline release_id must be a positive integer")
    _validate_baseline_assets(baseline["assets"])
    _require_exact_list(
        sources["artifact_inventory"],
        EXPECTED_ARTIFACT_INVENTORY,
        "package_sources.artifact_inventory",
    )


def _validate_budgets(value: object) -> None:
    budgets = _require_exact_keys(value, set(EXPECTED_BUDGETS), "budgets")
    kernel = _require_exact_keys(
        budgets["kernel_lab"], set(EXPECTED_BUDGETS["kernel_lab"]), "budgets.kernel_lab"
    )
    for label, actual, expected in (
        *(
            (f"budgets.{key}", budgets[key], expected)
            for key, expected in EXPECTED_BUDGETS.items()
            if key != "kernel_lab"
        ),
        *(
            (f"budgets.kernel_lab.{key}", kernel[key], expected)
            for key, expected in EXPECTED_BUDGETS["kernel_lab"].items()
        ),
    ):
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            raise QualificationMatrixError(
                f"{label} must equal the frozen positive integer {expected}"
            )


def _validate_image(image: object, contract: CellContract, label: str) -> None:
    if not isinstance(image, str):
        raise QualificationMatrixError(f"{label} must be a string")
    match = IMAGE_PATTERN.fullmatch(image)
    if match is None:
        raise QualificationMatrixError(
            f"{label} must be an official tag-and-sha256 OCI reference"
        )
    expected_match = IMAGE_PATTERN.fullmatch(contract.image)
    if expected_match is None:
        raise AssertionError(f"invalid built-in image contract for {contract.identifier}")
    if match.group("repository") != expected_match.group("repository"):
        raise QualificationMatrixError(f"{label} does not use the frozen official repository")
    if match.group("tag") != expected_match.group("tag"):
        raise QualificationMatrixError(f"{label} does not use the frozen readable tag")
    if image != contract.image:
        raise QualificationMatrixError(f"{label} does not match the frozen OCI digest")


def _validate_real_host(value: object, contract: CellContract, label: str) -> None:
    real_host = _require_exact_keys(value, REAL_HOST_KEYS, label)
    mode = real_host["mode"]
    reboot_count = real_host["reboot_count"]
    if not isinstance(mode, str) or mode not in REAL_HOST_REBOOT_COUNTS:
        raise QualificationMatrixError(f"{label}.mode is unsupported")
    if type(reboot_count) is not int or reboot_count < 0:
        raise QualificationMatrixError(f"{label}.reboot_count must be a non-negative integer")
    if reboot_count != REAL_HOST_REBOOT_COUNTS[mode]:
        raise QualificationMatrixError(
            f"{label} mode and reboot_count are an invalid combination"
        )
    if mode != contract.real_host_mode or reboot_count != contract.reboot_count:
        raise QualificationMatrixError(f"{label} does not match the frozen obligation")


def _validate_cells(value: object) -> None:
    if not isinstance(value, list):
        raise QualificationMatrixError("cells must be an array")
    if len(value) != len(EXPECTED_CELLS):
        raise QualificationMatrixError(
            f"cells must contain exactly {len(EXPECTED_CELLS)} entries"
        )
    identifiers: list[str] = []
    images: list[str] = []
    for index, (raw, contract) in enumerate(zip(value, EXPECTED_CELLS, strict=True)):
        label = f"cells[{index}]"
        cell = _require_exact_keys(raw, CELL_KEYS, label)
        for field, expected in (
            ("id", contract.identifier),
            ("distribution", contract.distribution),
            ("version", contract.version),
            ("family", contract.family),
        ):
            actual = cell[field]
            if not isinstance(actual, str) or actual != expected:
                raise QualificationMatrixError(
                    f"{label}.{field} must equal the frozen value {expected!r}"
                )
        _validate_image(cell["image"], contract, f"{label}.image")
        _require_exact_list(
            cell["container_scenarios"],
            contract.container_scenarios,
            f"{label}.container_scenarios",
        )
        _require_exact_list(
            cell["required_checks"],
            contract.required_checks,
            f"{label}.required_checks",
        )
        if any("reboot" in check.casefold() for check in cell["required_checks"]):
            raise QualificationMatrixError(
                f"{label}.required_checks must not encode real-host reboots"
            )
        _validate_real_host(cell["real_host"], contract, f"{label}.real_host")
        identifiers.append(cell["id"])
        images.append(cell["image"])
    if len(set(identifiers)) != len(identifiers):
        raise QualificationMatrixError("cell identifiers must be unique")
    if len(set(images)) != len(images):
        raise QualificationMatrixError("cell image identities must be unique")


def validate_document(document: object) -> dict[str, Any]:
    matrix = _require_exact_keys(document, TOP_LEVEL_KEYS, "matrix")
    _reject_active_arm_tokens(matrix)
    if type(matrix["schema_version"]) is not int or matrix["schema_version"] != 1:
        raise QualificationMatrixError("schema_version must equal integer 1")
    if matrix["matrix_id"] != "syswarden-package-qualification/v1":
        raise QualificationMatrixError("matrix_id does not match the v1 contract")
    if matrix["target_release"] != "v4.04.0":
        raise QualificationMatrixError("target_release must equal v4.04.0")
    _require_exact_mapping(matrix["architecture"], EXPECTED_ARCHITECTURE, "architecture")
    _validate_package_sources(matrix["package_sources"])
    _validate_budgets(matrix["budgets"])
    _require_exact_list(matrix["required_evidence"], EXPECTED_EVIDENCE, "required_evidence")
    _validate_cells(matrix["cells"])
    return matrix


def load_matrix_snapshot(
    path: Path = DEFAULT_MATRIX,
) -> tuple[dict[str, Any], str]:
    data = _stable_regular_file_bytes(path)
    document = validate_document(_strict_json(data, str(path)))
    return document, hashlib.sha256(data).hexdigest()


def load_matrix(path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    document, _ = load_matrix_snapshot(path)
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        type=Path,
        default=DEFAULT_MATRIX,
        metavar="PATH",
        help=f"matrix to validate (default: {DEFAULT_MATRIX})",
    )
    parser.add_argument(
        "--expected-target-release",
        help="require the matrix target to match this exact release tag",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        matrix, matrix_sha256 = load_matrix_snapshot(args.check)
        if (
            args.expected_target_release is not None
            and matrix["target_release"] != args.expected_target_release
        ):
            raise QualificationMatrixError(
                "matrix target_release does not match --expected-target-release"
            )
    except QualificationMatrixError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "Package qualification matrix validated: "
        f"{len(matrix['cells'])} AMD64 cells for {matrix['target_release']}; "
        f"sha256={matrix_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
