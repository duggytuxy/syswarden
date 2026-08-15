#!/usr/bin/env python3
"""Validate exact package-staging inventories before package creation."""

from __future__ import annotations

import argparse
import os
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
}

FREEBSD_ENTRIES = {
    ".": DIRECTORY,
    "usr": DIRECTORY,
    "usr/local": DIRECTORY,
    "usr/local/etc": DIRECTORY,
    "usr/local/etc/rc.d": DIRECTORY,
    "usr/local/etc/rc.d/syswarden": ExpectedEntry(
        "file", mode=0o755, nonempty=True
    ),
    "usr/local/etc/rc.d/syswardenwebtui": ExpectedEntry(
        "file", mode=0o755, nonempty=True
    ),
    "usr/local/syswarden": DIRECTORY,
    "usr/local/syswarden/bin": DIRECTORY,
    "usr/local/syswarden/bin/syswarden-cli": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "usr/local/syswarden/bin/syswarden-core": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "usr/local/syswarden/bin/syswarden-tui": ExpectedEntry(
        "file", mode=0o750, nonempty=True
    ),
    "usr/local/syswarden/signatures.json": ExpectedEntry(
        "file", mode=0o640, nonempty=True
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


def validate(root: Path, expected: dict[str, ExpectedEntry]) -> None:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="platform", required=True)
    for platform in ("linux", "freebsd"):
        platform_parser = subparsers.add_parser(platform)
        platform_parser.add_argument("--root", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    expected = LINUX_ENTRIES if args.platform == "linux" else FREEBSD_ENTRIES
    try:
        validate(args.root, expected)
    except PackageStageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Validated exact {args.platform} staging inventory: {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
