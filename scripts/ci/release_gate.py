#!/usr/bin/env python3
"""Validate and assemble the exact SysWarden release asset inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


VERSION_PATTERN = re.compile(r"^v([0-9]+)\.([0-9]{2})\.([0-9]+)$")
CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$")
BUNDLE_NAME = "syswarden-release.tar.gz"
SBOM_NAME = "syswarden-sbom.spdx.json"
COMPLIANCE_ARCHIVE_NAME = "plumber-report.zip"
PACKAGE_CHECKSUM_NAME = "SHA256SUMS.txt"
RELEASE_CHECKSUM_NAME = "RELEASE_SHA256SUMS.txt"
UPDATE_MANIFEST_NAME = "syswarden-update-manifest-v1.json"
UPDATE_SIGNATURE_NAME = f"{UPDATE_MANIFEST_NAME}.sig"
UPDATE_MANIFEST_TOOL = "scripts/ci/update_manifest.go"
UPDATE_PRIVATE_KEY_ENV = "SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY"
FIRST_SIGNED_UPDATE_TAG = "v4.02.9"
# One-release bridge for qualifying v4.03.0 against its exact public predecessor.
# Delete this bridge once v4.02.8 is no longer the qualification predecessor.
HISTORICAL_LINUX_TRANSITION_TAG = "v4.02.8"
HISTORICAL_LINUX_TRANSITION_REPOSITORY = "duggytuxy/syswarden"
HISTORICAL_LINUX_TRANSITION_RELEASE_ID = 369665546
HISTORICAL_LINUX_TRANSITION_MANIFEST_SHA256 = (
    "1d706ac8e1c68742ed990899e42846594159962d57a626b59242d3e951d40424"
)
HISTORICAL_RETIRED_PACKAGE_SUFFIX = "." + "txz"
HISTORICAL_RETIRED_PACKAGE_NAME = (
    "syswarden-4.02.8" + HISTORICAL_RETIRED_PACKAGE_SUFFIX
)
HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS = (
    (
        "syswarden_4.02.8_amd64.deb",
        "0497748e73b5ec4859a15c8f62732c6c07ce588c9a1e3198288dec79605c22b0",
    ),
    (
        "syswarden_4.02.8_arm64.deb",
        "b49802ae91d64947ac80e67df166dac2499bc152652e54e34a22592498e39d4e",
    ),
    (
        "syswarden-4.02.8-1.aarch64.rpm",
        "9a972228b7fd54aff1f043102501f74e3f5fdf94211e5279c8e8ac7ffc11f21c",
    ),
    (
        "syswarden-4.02.8-1.x86_64.rpm",
        "fdc6145fca4a8134f33533b59b18f7d2c212c412f9b242f6f7cb1c205a6947a2",
    ),
    (
        HISTORICAL_RETIRED_PACKAGE_NAME,
        "8b3b489821450b3afd74548c6db5ad92001b8a69f923e2b9a99ce550353b6e37",
    ),
    (
        "syswarden_4.02.8_aarch64.apk",
        "80a16b099d299db4053249f7bcb3d7c234ee662ad1e10e7081ae92553d13d275",
    ),
    (
        "syswarden_4.02.8_x86_64.apk",
        "c0869bcb6f9adc1e4ca191ae5f5ed7962c9c89fb2bac9a4d52c0c246b09036d4",
    ),
)
HISTORICAL_LINUX_TRANSITION_ASSETS = {
    "SHA256SUMS.txt": {
        "id": 512484364,
        "size": 655,
        "digest": "sha256:" + HISTORICAL_LINUX_TRANSITION_MANIFEST_SHA256,
    },
    "syswarden-4.02.8-1.aarch64.rpm": {
        "id": 512484365,
        "size": 11510311,
        "digest": "sha256:9a972228b7fd54aff1f043102501f74e3f5fdf94211e5279c8e8ac7ffc11f21c",
    },
    "syswarden-4.02.8-1.x86_64.rpm": {
        "id": 512484361,
        "size": 12718934,
        "digest": "sha256:fdc6145fca4a8134f33533b59b18f7d2c212c412f9b242f6f7cb1c205a6947a2",
    },
    HISTORICAL_RETIRED_PACKAGE_NAME: {
        "id": 512484362,
        "size": 7517668,
        "digest": "sha256:8b3b489821450b3afd74548c6db5ad92001b8a69f923e2b9a99ce550353b6e37",
    },
    "syswarden_4.02.8_aarch64.apk": {
        "id": 512484371,
        "size": 12229632,
        "digest": "sha256:80a16b099d299db4053249f7bcb3d7c234ee662ad1e10e7081ae92553d13d275",
    },
    "syswarden_4.02.8_amd64.deb": {
        "id": 512484391,
        "size": 12727958,
        "digest": "sha256:0497748e73b5ec4859a15c8f62732c6c07ce588c9a1e3198288dec79605c22b0",
    },
    "syswarden_4.02.8_arm64.deb": {
        "id": 512484392,
        "size": 11519454,
        "digest": "sha256:b49802ae91d64947ac80e67df166dac2499bc152652e54e34a22592498e39d4e",
    },
    "syswarden_4.02.8_x86_64.apk": {
        "id": 512484393,
        "size": 13452637,
        "digest": "sha256:c0869bcb6f9adc1e4ca191ae5f5ed7962c9c89fb2bac9a4d52c0c246b09036d4",
    },
}
EXPECTED_SBOM_APPLICATIONS = {
    "scripts/versionctl/go.mod",
    "src/core/syswarden-cli/go.mod",
    "src/core/syswarden-core/go.mod",
    "src/core/syswarden-tui/go.mod",
}

BUNDLE_FILES = {
    "bin/syswarden-cli",
    "bin/syswarden-core",
    "bin/syswarden-tui",
    "linux-arm64/bin/syswarden-cli",
    "linux-arm64/bin/syswarden-core",
    "linux-arm64/bin/syswarden-tui",
    "signatures.json",
    "linux-arm64/signatures.json",
}


class ReleaseGateError(ValueError):
    """Raised when release evidence is incomplete or inconsistent."""


def parse_tag(tag: str) -> str:
    match = VERSION_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseGateError(
            f"invalid release tag {tag!r}; expected vMAJOR.MINOR.PATCH with a two-digit minor"
        )
    return tag[1:]


def tag_components(tag: str) -> tuple[int, int, int]:
    match = VERSION_PATTERN.fullmatch(tag)
    if match is None:
        parse_tag(tag)
        raise AssertionError("unreachable")
    return tuple(int(component) for component in match.groups())


def signed_update_required(tag: str) -> bool:
    return tag_components(tag) >= tag_components(FIRST_SIGNED_UPDATE_TAG)


def package_names(version: str) -> list[str]:
    return [
        f"syswarden_{version}_amd64.deb",
        f"syswarden_{version}_arm64.deb",
        f"syswarden-{version}-1.x86_64.rpm",
        f"syswarden-{version}-1.aarch64.rpm",
        f"syswarden_{version}_x86_64.apk",
        f"syswarden_{version}_aarch64.apk",
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_nonempty_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ReleaseGateError(f"{label} is not a regular file: {path}")
    if path.stat().st_size == 0:
        raise ReleaseGateError(f"{label} is empty: {path}")


def directory_files(directory: Path, label: str) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise ReleaseGateError(f"{label} directory is missing: {directory}")
    files: list[Path] = []
    for entry in sorted(directory.rglob("*")):
        if entry.is_symlink():
            raise ReleaseGateError(f"{label} contains a symbolic link: {entry}")
        if entry.is_file():
            regular_nonempty_file(entry, label)
            files.append(entry)
        elif not entry.is_dir():
            raise ReleaseGateError(f"{label} contains an unsupported entry: {entry}")
    return files


def exact_root_files(directory: Path, expected: Iterable[str], label: str) -> None:
    files = directory_files(directory, label)
    actual = {path.relative_to(directory).as_posix() for path in files}
    expected_set = set(expected)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        unexpected = sorted(actual - expected_set)
        raise ReleaseGateError(
            f"{label} inventory mismatch; missing={missing}, unexpected={unexpected}"
        )


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    regular_nonempty_file(path, "checksum manifest")
    records: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ReleaseGateError(
                f"invalid checksum record at {path}:{line_number}: {line!r}"
            )
        digest, name = match.groups()
        if name in records:
            raise ReleaseGateError(f"duplicate checksum entry for {name} in {path}")
        records[name] = digest
    return records


def validate_manifest(directory: Path, manifest_name: str, expected_names: set[str]) -> None:
    records = parse_checksum_manifest(directory / manifest_name)
    if set(records) != expected_names:
        raise ReleaseGateError(
            f"{manifest_name} inventory mismatch; expected={sorted(expected_names)}, "
            f"actual={sorted(records)}"
        )
    for name, expected_digest in records.items():
        path = directory / name
        regular_nonempty_file(path, f"asset listed by {manifest_name}")
        actual_digest = sha256(path)
        if actual_digest != expected_digest:
            raise ReleaseGateError(
                f"checksum mismatch for {name}: expected {expected_digest}, got {actual_digest}"
            )


def validate_packages(directory: Path, version: str) -> list[str]:
    names = package_names(version)
    expected = set(names) | {PACKAGE_CHECKSUM_NAME}
    exact_root_files(directory, expected, "package artifact")
    validate_manifest(directory, PACKAGE_CHECKSUM_NAME, set(names))
    return names


def _strict_json_file(path: Path, label: str) -> Any:
    regular_nonempty_file(path, label)
    if path.stat().st_size > 1024 * 1024:
        raise ReleaseGateError(f"{label} exceeds the one-megabyte limit: {path}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseGateError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ReleaseGateError(f"{label} contains non-finite number {value!r}")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"cannot read {label} {path}: {exc}") from exc


def _write_exclusive_file(path: Path, content: bytes, label: str) -> None:
    if not content:
        raise ReleaseGateError(f"refusing to write empty {label}")
    if path.exists() or path.is_symlink():
        raise ReleaseGateError(f"{label} output already exists: {path}")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReleaseGateError(f"{label} output parent is not a real directory: {parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReleaseGateError(f"cannot create {label} output {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise ReleaseGateError(f"cannot write {label} output {path}: {exc}") from exc


def _require_unused_output(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseGateError(f"{label} output already exists: {path}")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReleaseGateError(
            f"{label} output parent is not a real directory: {path.parent}"
        )


def normalize_v4028_linux_packages(
    *,
    repository: str,
    release_id: int,
    tag: str,
    source_manifest: Path,
    asset_metadata: Path,
    packages: Path,
    output_manifest: Path,
    provenance_output: Path,
) -> dict[str, Any]:
    """Derive the one-time Linux checksum view from the exact v4.02.8 release."""

    if repository != HISTORICAL_LINUX_TRANSITION_REPOSITORY:
        raise ReleaseGateError("historical package transition repository is not canonical")
    if release_id != HISTORICAL_LINUX_TRANSITION_RELEASE_ID:
        raise ReleaseGateError("historical package transition release ID is not exact")
    if tag != HISTORICAL_LINUX_TRANSITION_TAG:
        raise ReleaseGateError(
            "historical package transition is restricted to exact v4.02.8 evidence"
        )

    source_manifest = source_manifest.absolute()
    asset_metadata = asset_metadata.absolute()
    packages = packages.absolute()
    output_manifest = output_manifest.absolute()
    provenance_output = provenance_output.absolute()
    if source_manifest == asset_metadata:
        raise ReleaseGateError("historical manifest and asset metadata must be distinct files")
    regular_nonempty_file(source_manifest, "historical package checksum manifest")
    if source_manifest.stat().st_size != HISTORICAL_LINUX_TRANSITION_ASSETS[
        PACKAGE_CHECKSUM_NAME
    ]["size"]:
        raise ReleaseGateError("historical package checksum manifest size is not exact")
    source_manifest_sha256 = sha256(source_manifest)
    if source_manifest_sha256 != HISTORICAL_LINUX_TRANSITION_MANIFEST_SHA256:
        raise ReleaseGateError("historical package checksum manifest digest is not exact")

    source_records = parse_checksum_manifest(source_manifest)
    expected_source_records = dict(HISTORICAL_LINUX_TRANSITION_MANIFEST_RECORDS)
    if source_records != expected_source_records:
        raise ReleaseGateError("historical package checksum records are not exact")

    metadata_document = _strict_json_file(
        asset_metadata, "historical public release asset metadata"
    )
    if not isinstance(metadata_document, list) or not metadata_document:
        raise ReleaseGateError("historical public release asset metadata must be an array")
    metadata_by_name: dict[str, dict[str, Any]] = {}
    metadata_ids: set[int] = set()
    for index, record in enumerate(metadata_document):
        if not isinstance(record, dict) or set(record) != {
            "digest",
            "id",
            "name",
            "size",
            "state",
        }:
            raise ReleaseGateError(
                f"historical public release asset metadata record {index} is not exact"
            )
        name = record["name"]
        asset_id = record["id"]
        size = record["size"]
        if (
            not isinstance(name, str)
            or not name
            or type(asset_id) is not int
            or asset_id <= 0
            or type(size) is not int
            or size <= 0
            or record["state"] != "uploaded"
            or not isinstance(record["digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"]) is None
        ):
            raise ReleaseGateError(
                f"historical public release asset metadata record {index} is invalid"
            )
        if name in metadata_by_name or asset_id in metadata_ids:
            raise ReleaseGateError("historical public release asset metadata is ambiguous")
        metadata_by_name[name] = record
        metadata_ids.add(asset_id)

    package_suffixes = (".deb", ".rpm", ".apk", HISTORICAL_RETIRED_PACKAGE_SUFFIX)
    public_package_names = {
        name
        for name in metadata_by_name
        if name.startswith("syswarden") and name.endswith(package_suffixes)
    }
    expected_public_package_names = set(expected_source_records)
    if public_package_names != expected_public_package_names:
        raise ReleaseGateError(
            "historical public package asset inventory is not exactly seven packages"
        )
    expected_asset_names = expected_public_package_names | {PACKAGE_CHECKSUM_NAME}
    for name in sorted(expected_asset_names):
        record = metadata_by_name.get(name)
        expected = HISTORICAL_LINUX_TRANSITION_ASSETS.get(name)
        if record is None or expected is None:
            raise ReleaseGateError(f"historical public release asset is missing: {name}")
        if any(record[field] != expected[field] for field in ("id", "size", "digest")):
            raise ReleaseGateError(
                f"historical public release asset identity changed: {name}"
            )

    linux_names = package_names(HISTORICAL_LINUX_TRANSITION_TAG.removeprefix("v"))
    exact_root_files(packages, linux_names, "historical Linux package artifact")
    for name in linux_names:
        actual_digest = sha256(packages / name)
        if actual_digest != expected_source_records[name]:
            raise ReleaseGateError(f"historical Linux package checksum mismatch: {name}")

    if output_manifest.parent != packages or output_manifest.name != PACKAGE_CHECKSUM_NAME:
        raise ReleaseGateError(
            "derived Linux checksum manifest must be the exact package-directory SHA256SUMS.txt"
        )
    if provenance_output.parent == packages:
        raise ReleaseGateError(
            "historical transition provenance must remain outside the package directory"
        )
    if len(
        {
            source_manifest,
            asset_metadata,
            output_manifest,
            provenance_output,
        }
    ) != 4:
        raise ReleaseGateError("historical transition inputs and outputs must be distinct")
    _require_unused_output(output_manifest, "derived Linux checksum manifest")
    _require_unused_output(provenance_output, "historical transition provenance")
    derived_content = "".join(
        f"{expected_source_records[name]}  {name}\n" for name in linux_names
    ).encode("utf-8")
    derived_sha256 = hashlib.sha256(derived_content).hexdigest()

    selected_package_assets = [
        {
            "digest": metadata_by_name[name]["digest"],
            "id": metadata_by_name[name]["id"],
            "name": name,
            "size": metadata_by_name[name]["size"],
        }
        for name in sorted(expected_public_package_names)
    ]
    provenance: dict[str, Any] = {
        "derived_linux_manifest": {
            "name": PACKAGE_CHECKSUM_NAME,
            "package_count": len(linux_names),
            "sha256": derived_sha256,
        },
        "repository": repository,
        "release_id": release_id,
        "schema": "syswarden-historical-linux-package-transition/v1",
        "source_manifest": {
            "asset_id": metadata_by_name[PACKAGE_CHECKSUM_NAME]["id"],
            "asset_digest": metadata_by_name[PACKAGE_CHECKSUM_NAME]["digest"],
            "asset_size": metadata_by_name[PACKAGE_CHECKSUM_NAME]["size"],
            "name": PACKAGE_CHECKSUM_NAME,
            "package_count": len(expected_source_records),
            "sha256": source_manifest_sha256,
        },
        "source_package_assets": selected_package_assets,
        "source_tag": tag,
    }
    provenance_content = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    provenance_sha256 = hashlib.sha256(provenance_content).hexdigest()

    created_outputs: list[Path] = []
    try:
        _write_exclusive_file(
            provenance_output, provenance_content, "historical transition provenance"
        )
        created_outputs.append(provenance_output)
        _write_exclusive_file(
            output_manifest, derived_content, "derived Linux checksum manifest"
        )
        created_outputs.append(output_manifest)
        if sha256(output_manifest) != derived_sha256:
            raise ReleaseGateError(
                "derived Linux checksum manifest changed after publication"
            )
        if sha256(provenance_output) != provenance_sha256:
            raise ReleaseGateError(
                "historical transition provenance changed after publication"
            )
        validate_packages(packages, HISTORICAL_LINUX_TRANSITION_TAG.removeprefix("v"))
    except (OSError, ReleaseGateError):
        for created_output in reversed(created_outputs):
            try:
                created_output.unlink()
            except FileNotFoundError:
                pass
        raise
    provenance["provenance_sha256"] = provenance_sha256
    return provenance


def normalize_archive_name(raw_name: str) -> str:
    name = raw_name
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ReleaseGateError(f"unsafe bundle entry: {raw_name!r}")
    return path.as_posix()


def validate_bundle(path: Path) -> None:
    regular_nonempty_file(path, "release bundle")
    files: set[str] = set()
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive.getmembers():
                name = normalize_archive_name(member.name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ReleaseGateError(
                        f"release bundle contains a non-regular entry: {member.name}"
                    )
                if member.size <= 0:
                    raise ReleaseGateError(f"release bundle contains an empty file: {member.name}")
                if name in files:
                    raise ReleaseGateError(f"release bundle contains duplicate file {name}")
                files.add(name)
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseGateError(f"cannot read release bundle {path}: {exc}") from exc
    if files != BUNDLE_FILES:
        raise ReleaseGateError(
            f"release bundle inventory mismatch; missing={sorted(BUNDLE_FILES - files)}, "
            f"unexpected={sorted(files - BUNDLE_FILES)}"
        )


def validate_sbom(path: Path) -> None:
    regular_nonempty_file(path, "SPDX SBOM")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"cannot read SPDX SBOM {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ReleaseGateError("SPDX SBOM root must be a JSON object")
    spdx_version = document.get("spdxVersion")
    if spdx_version != "SPDX-2.3":
        raise ReleaseGateError("SPDX SBOM must use SPDX-2.3")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ReleaseGateError("SPDX SBOM has no SPDXRef-DOCUMENT identifier")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseGateError("SPDX SBOM contains no package inventory")
    creation = document.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, dict) else None
    if not isinstance(creators, list) or "Tool: trivy-0.70.0" not in creators:
        raise ReleaseGateError("SPDX SBOM was not generated by pinned Trivy 0.70.0")
    applications = {
        str(package.get("name", ""))
        for package in packages
        if isinstance(package, dict)
        and package.get("primaryPackagePurpose") == "APPLICATION"
    }
    if applications != EXPECTED_SBOM_APPLICATIONS:
        raise ReleaseGateError(
            "SPDX application inventory mismatch; "
            f"expected={sorted(EXPECTED_SBOM_APPLICATIONS)}, "
            f"actual={sorted(applications)}"
        )


def write_compliance_archive(source: Path, destination: Path) -> None:
    files = directory_files(source, "Plumber report artifact")
    if not files:
        raise ReleaseGateError("Plumber report artifact contains no report files")
    with zipfile.ZipFile(
        destination, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in files:
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    regular_nonempty_file(destination, "Plumber report archive")


def validate_compliance_archive(path: Path) -> None:
    regular_nonempty_file(path, "Plumber report archive")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members:
                raise ReleaseGateError("Plumber report archive contains no native report")
            names: set[str] = set()
            for member in members:
                name = normalize_archive_name(member.filename)
                if member.is_dir():
                    continue
                if member.file_size <= 0:
                    raise ReleaseGateError(
                        f"Plumber report archive contains an empty entry: {member.filename}"
                    )
                if name in names:
                    raise ReleaseGateError(
                        f"Plumber report archive contains duplicate entry {name}"
                    )
                names.add(name)
            if not names:
                raise ReleaseGateError("Plumber report archive contains no native report file")
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ReleaseGateError(
                    f"Plumber report archive failed CRC validation at {bad_member}"
                )
    except zipfile.BadZipFile as exc:
        raise ReleaseGateError(f"invalid Plumber report archive: {exc}") from exc


def release_notes(repository: Path, tag: str) -> str:
    path = repository / "changelog.md"
    try:
        content = path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseGateError(f"cannot read changelog.md: {exc}") from exc
    lines = content.splitlines()
    expected_heading = f"# Release {tag}"
    if not lines or lines[0] != expected_heading:
        actual = lines[0] if lines else ""
        raise ReleaseGateError(
            f"changelog first heading is {actual!r}; expected {expected_heading!r}"
        )
    try:
        separator = lines.index("---", 1)
    except ValueError as exc:
        raise ReleaseGateError("changelog first release block has no exact --- separator") from exc
    block = lines[:separator]
    if not any(line.startswith("### ") for line in block[1:]):
        raise ReleaseGateError("changelog first release block has no ### section")
    if not any(line.startswith("- ") and line[2:].strip() for line in block[1:]):
        raise ReleaseGateError("changelog first release block has no non-empty bullet")
    evidence = [
        "",
        "## RELEASE EVIDENCE",
        "- Package integrity is recorded in `SHA256SUMS.txt`.",
        "- The complete release inventory is recorded in `RELEASE_SHA256SUMS.txt`.",
        "- The SPDX SBOM is attached as `syswarden-sbom.spdx.json`.",
        "- The native Plumber compliance report is preserved in `plumber-report.zip`.",
        "- GitHub build provenance attestations cover the exact published asset inventory.",
    ]
    if signed_update_required(tag):
        evidence.append(
            "- The updater package set is bound by the authenticated "
            "`syswarden-update-manifest-v1.json` and detached Ed25519 signature."
        )
    return "\n".join(block + evidence) + "\n"


def ensure_empty_output(directory: Path) -> None:
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise ReleaseGateError(f"release output is not a directory: {directory}")
        if any(directory.iterdir()):
            raise ReleaseGateError(f"release output must be empty: {directory}")
    else:
        directory.mkdir(parents=True)


def write_checksum_manifest(directory: Path, names: Iterable[str], output_name: str) -> None:
    lines = [f"{sha256(directory / name)}  {name}" for name in sorted(names)]
    (directory / output_name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_signed_update_manifest(
    repository: Path,
    tag: str,
    packages: Path,
    manifest_path: Path,
    signature_path: Path,
) -> None:
    regular_nonempty_file(manifest_path, "signed update manifest")
    regular_nonempty_file(signature_path, "signed update manifest signature")
    environment = os.environ.copy()
    environment.pop(UPDATE_PRIVATE_KEY_ENV, None)
    environment["GOFLAGS"] = "-mod=readonly"
    command = [
        "go",
        "run",
        f"./{UPDATE_MANIFEST_TOOL}",
        "verify",
        "--repository",
        str(repository),
        "--tag",
        tag,
        "--packages",
        str(packages),
        "--manifest",
        str(manifest_path),
        "--signature",
        str(signature_path),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseGateError(f"cannot execute signed update manifest verifier: {exc}") from exc
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or "verifier exited unsuccessfully"
        raise ReleaseGateError(f"signed update manifest verification failed: {diagnostic}")


def prepare(args: argparse.Namespace) -> None:
    repository = args.repository.resolve()
    version = parse_tag(args.tag)
    packages = args.packages.resolve()
    bundle_dir = args.bundle.resolve()
    sbom_dir = args.sbom.resolve()
    compliance = args.compliance.resolve()
    output = args.output.resolve()
    notes_output = args.notes_output.resolve()

    package_assets = validate_packages(packages, version)

    signed_assets: list[str] = []
    if signed_update_required(args.tag):
        update_manifest_directory = getattr(args, "update_manifest_dir", None)
        if update_manifest_directory is None:
            raise ReleaseGateError(
                f"signed update manifest directory is required for {args.tag}"
            )
        update_manifest_directory = update_manifest_directory.resolve()
        exact_root_files(
            update_manifest_directory,
            {UPDATE_MANIFEST_NAME, UPDATE_SIGNATURE_NAME},
            "signed update manifest artifact",
        )
        verify_signed_update_manifest(
            repository,
            args.tag,
            packages,
            update_manifest_directory / UPDATE_MANIFEST_NAME,
            update_manifest_directory / UPDATE_SIGNATURE_NAME,
        )
        signed_assets = [UPDATE_MANIFEST_NAME, UPDATE_SIGNATURE_NAME]

    exact_root_files(bundle_dir, {BUNDLE_NAME}, "bundle artifact")
    exact_root_files(sbom_dir, {SBOM_NAME}, "SBOM artifact")
    bundle = bundle_dir / BUNDLE_NAME
    sbom = sbom_dir / SBOM_NAME
    validate_bundle(bundle)
    validate_sbom(sbom)
    ensure_empty_output(output)

    for name in package_assets + [PACKAGE_CHECKSUM_NAME]:
        shutil.copyfile(packages / name, output / name)
    shutil.copyfile(bundle, output / BUNDLE_NAME)
    shutil.copyfile(sbom, output / SBOM_NAME)
    write_compliance_archive(compliance, output / COMPLIANCE_ARCHIVE_NAME)
    if signed_assets:
        update_manifest_directory = args.update_manifest_dir.resolve()
        for name in signed_assets:
            shutil.copyfile(update_manifest_directory / name, output / name)

    inventory_without_release_manifest = set(package_assets) | {
        PACKAGE_CHECKSUM_NAME,
        BUNDLE_NAME,
        SBOM_NAME,
        COMPLIANCE_ARCHIVE_NAME,
    } | set(signed_assets)
    write_checksum_manifest(
        output, inventory_without_release_manifest, RELEASE_CHECKSUM_NAME
    )
    verify_assets(output, args.tag, repository)

    notes = release_notes(repository, args.tag)
    notes_output.parent.mkdir(parents=True, exist_ok=True)
    notes_output.write_text(notes, encoding="utf-8")


def expected_release_assets(tag: str) -> set[str]:
    version = parse_tag(tag)
    assets = set(package_names(version)) | {
        PACKAGE_CHECKSUM_NAME,
        RELEASE_CHECKSUM_NAME,
        BUNDLE_NAME,
        SBOM_NAME,
        COMPLIANCE_ARCHIVE_NAME,
    }
    if signed_update_required(tag):
        assets |= {UPDATE_MANIFEST_NAME, UPDATE_SIGNATURE_NAME}
    return assets


def verify_assets(directory: Path, tag: str, repository: Path | None = None) -> None:
    expected = expected_release_assets(tag)
    exact_root_files(directory, expected, "release asset")
    version = parse_tag(tag)
    validate_manifest(directory, PACKAGE_CHECKSUM_NAME, set(package_names(version)))
    validate_manifest(directory, RELEASE_CHECKSUM_NAME, expected - {RELEASE_CHECKSUM_NAME})
    validate_bundle(directory / BUNDLE_NAME)
    validate_sbom(directory / SBOM_NAME)
    compliance_archive = directory / COMPLIANCE_ARCHIVE_NAME
    regular_nonempty_file(compliance_archive, "Plumber report archive")
    validate_compliance_archive(compliance_archive)
    if signed_update_required(tag):
        if repository is None:
            raise ReleaseGateError(
                f"repository is required to verify signed update assets for {tag}"
            )
        verify_signed_update_manifest(
            repository.resolve(),
            tag,
            directory,
            directory / UPDATE_MANIFEST_NAME,
            directory / UPDATE_SIGNATURE_NAME,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare", help="validate and stage release assets")
    prepare_parser.add_argument("--repository", type=Path, required=True)
    prepare_parser.add_argument("--tag", required=True)
    prepare_parser.add_argument("--packages", type=Path, required=True)
    prepare_parser.add_argument("--bundle", type=Path, required=True)
    prepare_parser.add_argument("--sbom", type=Path, required=True)
    prepare_parser.add_argument("--compliance", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--notes-output", type=Path, required=True)
    prepare_parser.add_argument("--update-manifest-dir", type=Path)

    verify_parser = subparsers.add_parser("verify", help="verify a final release asset directory")
    verify_parser.add_argument("--tag", required=True)
    verify_parser.add_argument("--assets", type=Path, required=True)
    verify_parser.add_argument("--repository", type=Path)

    packages_parser = subparsers.add_parser(
        "verify-packages", help="verify a package workflow artifact directory"
    )
    packages_parser.add_argument("--tag", required=True)
    packages_parser.add_argument("--packages", type=Path, required=True)

    bundle_parser = subparsers.add_parser(
        "verify-bundle", help="verify the exact compiled release bundle contract"
    )
    bundle_parser.add_argument("--bundle", type=Path, required=True)

    sbom_parser = subparsers.add_parser(
        "verify-sbom", help="verify the pinned source SBOM contract"
    )
    sbom_parser.add_argument("--sbom", type=Path, required=True)

    signed_update_parser = subparsers.add_parser(
        "requires-signed-update",
        help="print whether a release tag requires the signed update contract",
    )
    signed_update_parser.add_argument("--tag", required=True)

    historical_parser = subparsers.add_parser(
        "normalize-v4028-linux-packages",
        help="derive the exact Linux-only checksum view from public v4.02.8 evidence",
    )
    historical_parser.add_argument("--repository", required=True)
    historical_parser.add_argument("--release-id", type=int, required=True)
    historical_parser.add_argument("--tag", required=True)
    historical_parser.add_argument("--source-manifest", type=Path, required=True)
    historical_parser.add_argument("--asset-metadata", type=Path, required=True)
    historical_parser.add_argument("--packages", type=Path, required=True)
    historical_parser.add_argument("--output-manifest", type=Path, required=True)
    historical_parser.add_argument("--provenance-output", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args)
            print(f"Release asset validation passed for {args.tag}")
        elif args.command == "verify":
            repository = args.repository.resolve() if args.repository is not None else None
            verify_assets(args.assets.resolve(), args.tag, repository)
            print(f"Release asset inventory passed for {args.tag}")
        elif args.command == "verify-packages":
            validate_packages(args.packages.resolve(), parse_tag(args.tag))
            print(f"Package artifact validation passed for {args.tag}")
        elif args.command == "verify-bundle":
            validate_bundle(args.bundle.resolve())
            print("Release bundle validation passed")
        elif args.command == "verify-sbom":
            validate_sbom(args.sbom.resolve())
            print("Source SBOM validation passed")
        elif args.command == "requires-signed-update":
            print("true" if signed_update_required(args.tag) else "false")
        else:
            provenance = normalize_v4028_linux_packages(
                repository=args.repository,
                release_id=args.release_id,
                tag=args.tag,
                source_manifest=args.source_manifest,
                asset_metadata=args.asset_metadata,
                packages=args.packages,
                output_manifest=args.output_manifest,
                provenance_output=args.provenance_output,
            )
            print(
                "Historical v4.02.8 Linux package transition passed: "
                f"source={provenance['source_manifest']['sha256']} "
                f"derived={provenance['derived_linux_manifest']['sha256']} "
                f"provenance={provenance['provenance_sha256']}"
            )
    except (ReleaseGateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
