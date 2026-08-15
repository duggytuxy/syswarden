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
from typing import Iterable


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
    "freebsd/bin/syswarden-cli",
    "freebsd/bin/syswarden-core",
    "freebsd/bin/syswarden-tui",
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
        f"syswarden-{version}.txz",
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
        else:
            print("true" if signed_update_required(args.tag) else "false")
    except (ReleaseGateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
