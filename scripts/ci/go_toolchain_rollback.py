#!/usr/bin/env python3
"""Apply the exact v4.10.0 Go toolchain source rollback in an isolated checkout."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from pathlib import Path
from typing import Sequence


FROM_LINE = b"go 1.27.1\n"
TO_LINE = b"go 1.26.6\n"
DIRECTIVE_FILES = (
    "go.work",
    "src/core/syswarden-cli/go.mod",
    "src/core/syswarden-core/go.mod",
    "src/core/syswarden-tui/go.mod",
    "scripts/versionctl/go.mod",
)
BUILDER_FILE = "build_packages.sh"
REQUIRED_FILES = (*DIRECTIVE_FILES, BUILDER_FILE)
MAX_SOURCE_BYTES = 4 * 1024 * 1024


class RollbackError(ValueError):
    """Raised when the rollback target differs from the exact source contract."""


def _prepare_one(root: Path, relative: str) -> tuple[Path, int, bytes]:
    path = root / relative
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o022
        or before.st_size <= 0
        or before.st_size > MAX_SOURCE_BYTES
    ):
        raise RollbackError(f"unsafe rollback source: {relative}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        wire = os.read(descriptor, MAX_SOURCE_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after) or len(wire) != before.st_size:
        raise RollbackError(f"rollback source changed while being read: {relative}")
    if relative == BUILDER_FILE:
        if (
            wire.count(b"go1.27.1") != 2
            or wire.count(b"Go 1.27.1") != 3
            or b"go1.26.6" in wire
            or b"Go 1.26.6" in wire
        ):
            raise RollbackError("package builder does not contain the exact Go 1.27.1 pin and labels")
        replacement = wire.replace(b"go1.27.1", b"go1.26.6").replace(
            b"Go 1.27.1", b"Go 1.26.6"
        )
    else:
        if wire.count(FROM_LINE) != 1 or TO_LINE in wire:
            raise RollbackError(
                f"rollback source does not contain exactly one Go 1.27.1 directive: {relative}"
            )
        replacement = wire.replace(FROM_LINE, TO_LINE, 1)
    return path, stat.S_IMODE(before.st_mode), replacement


def _publish_one(path: Path, mode: int, replacement: bytes) -> None:
    temporary_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(temporary_descriptor, mode)
        os.write(temporary_descriptor, replacement)
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        os.replace(temporary_name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def rollback(root: Path) -> None:
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise RollbackError("repository must be one absolute canonical directory")
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid():
        raise RollbackError("repository ownership or type is unsafe")
    prepared = [_prepare_one(root, relative) for relative in REQUIRED_FILES]
    for path, mode, replacement in prepared:
        _publish_one(path, mode, replacement)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--from-toolchain", required=True)
    parser.add_argument("--to-toolchain", required=True)
    args = parser.parse_args(argv)
    try:
        if args.from_toolchain != "go1.27.1" or args.to_toolchain != "go1.26.6":
            raise RollbackError("only the exact Go 1.27.1 to Go 1.26.6 rollback is supported")
        rollback(args.repository)
    except (OSError, RollbackError) as exc:
        print(f"Go toolchain rollback: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
