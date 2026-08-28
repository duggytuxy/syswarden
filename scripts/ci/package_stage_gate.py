#!/usr/bin/env python3
"""Validate exact package-staging inventories before package creation."""

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


class PackageStageError(ValueError):
    """Raised when a package-staging tree violates its contract."""


@dataclass(frozen=True)
class ExpectedEntry:
    kind: str
    mode: int | None = None
    target: str | None = None
    nonempty: bool = False


@dataclass(frozen=True)
class ContentContract:
    sha256: str
    size: int


DIRECTORY = ExpectedEntry("directory", mode=0o755)

LINUX_ENTRIES = {
    ".": DIRECTORY,
    "opt": DIRECTORY,
    "opt/syswarden": DIRECTORY,
    "opt/syswarden/bin": DIRECTORY,
    "opt/syswarden/bin/syswarden-cli": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "opt/syswarden/bin/syswarden-core": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "opt/syswarden/bin/syswarden-tui": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "opt/syswarden/signatures.json": ExpectedEntry(
        "file", mode=0o640, nonempty=True
    ),
    "usr": DIRECTORY,
    "usr/local": DIRECTORY,
    "usr/local/bin": DIRECTORY,
    "usr/local/bin/syswarden": ExpectedEntry(
        "symlink", target="/opt/syswarden/bin/syswarden-cli"
    ),
    "usr/local/bin/syswarden-tui": ExpectedEntry(
        "symlink", target="/opt/syswarden/bin/syswarden-tui"
    ),
    "usr/share": DIRECTORY,
    "usr/share/bash-completion": DIRECTORY,
    "usr/share/bash-completion/completions": DIRECTORY,
    "usr/share/bash-completion/completions/syswarden": ExpectedEntry(
        "file", mode=0o644, nonempty=True
    ),
    "usr/share/doc": DIRECTORY,
    "usr/share/doc/syswarden": DIRECTORY,
    "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt": ExpectedEntry(
        "file", mode=0o644, nonempty=True
    ),
    "usr/share/doc/syswarden/LICENSE.txt": ExpectedEntry(
        "file", mode=0o644, nonempty=True
    ),
}

def entry_kind(metadata: os.stat_result) -> str:
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "unsupported"


def inventory(root: Path) -> dict[str, tuple[Path, os.stat_result]]:
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise PackageStageError(f"cannot inspect staging root {root}: {exc}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise PackageStageError(f"staging root is not a real directory: {root}")

    entries: dict[str, tuple[Path, os.stat_result]] = {
        ".": (root, root_metadata)
    }

    def visit(directory: Path, prefix: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda child: child.name)
        except OSError as exc:
            raise PackageStageError(
                f"cannot enumerate staging directory {directory}: {exc}"
            ) from exc
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise PackageStageError(
                    f"cannot inspect staging entry {relative}: {exc}"
                ) from exc
            entries[relative] = (path, metadata)
            if stat.S_ISDIR(metadata.st_mode):
                visit(path, relative)

    visit(root, "")
    return entries


def validate_exact_content(path: Path, contract: ContentContract) -> None:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise PackageStageError(f"cannot open contracted content {path}: {exc}") from exc
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise PackageStageError(f"contracted content is not a regular file: {path}")
        if (before.st_dev, before.st_ino) != (opened_before.st_dev, opened_before.st_ino):
            raise PackageStageError(f"contracted content identity changed: {path}")
        if opened_before.st_size != contract.size:
            raise PackageStageError(
                f"contracted content size mismatch for {path}: "
                f"expected {contract.size}, found {opened_before.st_size}"
            )
        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > contract.size:
                raise PackageStageError(f"contracted content grew while reading: {path}")
            digest.update(chunk)
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
        raise PackageStageError(f"contracted content changed while reading: {path}")
    if consumed != contract.size:
        raise PackageStageError(
            f"contracted content read-size mismatch for {path}: "
            f"expected {contract.size}, read {consumed}"
        )
    if digest.hexdigest() != contract.sha256:
        raise PackageStageError(f"contracted content SHA-256 mismatch: {path}")


def load_content_contract(path: Path) -> ContentContract:
    try:
        metadata_before = path.lstat()
    except OSError as exc:
        raise PackageStageError(f"cannot inspect content contract {path}: {exc}") from exc
    if not stat.S_ISREG(metadata_before.st_mode) or stat.S_ISLNK(metadata_before.st_mode):
        raise PackageStageError(f"content contract is not a regular file: {path}")
    if metadata_before.st_size > 512:
        raise PackageStageError(f"content contract is unexpectedly large: {path}")
    try:
        raw = path.read_bytes()
        metadata_after = path.lstat()
    except OSError as exc:
        raise PackageStageError(f"cannot read content contract {path}: {exc}") from exc
    if (metadata_before.st_dev, metadata_before.st_ino, metadata_before.st_size) != (
        metadata_after.st_dev,
        metadata_after.st_ino,
        metadata_after.st_size,
    ):
        raise PackageStageError(f"content contract changed while reading: {path}")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageStageError(f"invalid content contract {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"sha256", "size"}:
        raise PackageStageError(f"invalid content contract schema: {path}")
    digest = document["sha256"]
    size = document["size"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise PackageStageError(f"invalid content contract SHA-256: {path}")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= 1024 * 1024:
        raise PackageStageError(f"invalid content contract size: {path}")
    return ContentContract(sha256=digest, size=size)


def validate(
    root: Path,
    expected: dict[str, ExpectedEntry],
    completion_contract: ContentContract | None = None,
    geoip_data_license_contract: ContentContract | None = None,
    project_license_contract: ContentContract | None = None,
) -> None:
    actual = inventory(root)
    actual_paths = set(actual)
    expected_paths = set(expected)
    missing = sorted(expected_paths - actual_paths)
    unexpected = sorted(actual_paths - expected_paths)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise PackageStageError("staging inventory mismatch (" + "; ".join(details) + ")")

    violations: list[str] = []
    for relative in sorted(expected):
        path, metadata = actual[relative]
        contract = expected[relative]
        actual_kind = entry_kind(metadata)
        if actual_kind != contract.kind:
            violations.append(
                f"{relative}: expected {contract.kind}, found {actual_kind}"
            )
            continue
        if contract.mode is not None:
            actual_mode = stat.S_IMODE(metadata.st_mode)
            if actual_mode != contract.mode:
                violations.append(
                    f"{relative}: expected mode {contract.mode:04o}, "
                    f"found {actual_mode:04o}"
                )
        if contract.nonempty and metadata.st_size == 0:
            violations.append(f"{relative}: expected a non-empty file")
        if contract.target is not None:
            try:
                actual_target = os.readlink(path)
            except OSError as exc:
                violations.append(f"{relative}: cannot read symlink target: {exc}")
            else:
                if actual_target != contract.target:
                    violations.append(
                        f"{relative}: expected target {contract.target!r}, "
                        f"found {actual_target!r}"
                    )
    if violations:
        raise PackageStageError("staging contract violation: " + "; ".join(violations))
    if completion_contract is not None:
        validate_exact_content(
            root / "usr/share/bash-completion/completions/syswarden",
            completion_contract,
        )
    if geoip_data_license_contract is not None:
        validate_exact_content(
            root / "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt",
            geoip_data_license_contract,
        )
    if project_license_contract is not None:
        validate_exact_content(
            root / "usr/share/doc/syswarden/LICENSE.txt",
            project_license_contract,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("linux",))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--completion-contract", type=Path, required=True)
    parser.add_argument("--geoip-data-license-contract", type=Path, required=True)
    parser.add_argument("--geoip-data-license-source", type=Path, required=True)
    parser.add_argument("--project-license-contract", type=Path, required=True)
    parser.add_argument("--project-license-source", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        completion_contract = load_content_contract(args.completion_contract)
        geoip_data_license_contract = load_content_contract(
            args.geoip_data_license_contract
        )
        project_license_contract = load_content_contract(
            args.project_license_contract
        )
        validate_exact_content(
            args.geoip_data_license_source, geoip_data_license_contract
        )
        validate_exact_content(args.project_license_source, project_license_contract)
        validate(
            args.root,
            LINUX_ENTRIES,
            completion_contract,
            geoip_data_license_contract,
            project_license_contract,
        )
    except PackageStageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Validated exact {args.platform} staging inventory: {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
