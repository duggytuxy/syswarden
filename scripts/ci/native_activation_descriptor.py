#!/usr/bin/env python3
"""Bind staged CLI/core bytes to their exact runtime approval contract.

The descriptor is authenticated by the signed native artifact digest. Producing
or validating it does not grant permission to replace or activate a host.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import re
import stat
from pathlib import Path

DESCRIPTOR_PATH = "opt/syswarden/activation-contract-v1.json"
MAXIMUM_BINARY_BYTES = 128 << 20


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class Capture:
    """Keep the complete input set and every ancestor pinned until validation."""

    def __init__(self, root: Path, stack: ExitStack):
        self.root = root
        self.stack = stack
        self.directories = {}
        self.files = []
        self.bindings = []
        before = root.lstat()
        descriptor = self._open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._directory(before)
        if _identity(os.fstat(descriptor)) != _identity(before):
            raise ValueError("staged root changed while opening")
        self.directories[""] = descriptor
        self.bindings.append((None, str(root), descriptor, _identity(before)))
        for relative in ("opt", "opt/syswarden", "opt/syswarden/bin"):
            parent, _, name = relative.rpartition("/")
            parent_fd = self.directories[parent]
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            self._directory(before)
            descriptor = self._open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=parent_fd)
            if _identity(os.fstat(descriptor)) != _identity(before):
                raise ValueError("staged runtime directory changed while opening")
            self.directories[relative] = descriptor
            self.bindings.append((parent_fd, name, descriptor, _identity(before)))

    @staticmethod
    def _directory(metadata):
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022 or
                metadata.st_uid != os.geteuid()):
            raise ValueError("unsafe staged runtime directory")

    def _open(self, path, flags, mode=0o777, **arguments):
        descriptor = os.open(path, flags | os.O_CLOEXEC, mode, **arguments)
        self.stack.callback(os.close, descriptor)
        return descriptor

    def read(self, relative: str, mode: int, maximum: int, retain=False):
        parent, _, name = relative.rpartition("/")
        parent_fd = self.directories[parent]
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode or
                before.st_uid != os.geteuid() or before.st_nlink != 1 or
                not 0 < before.st_size <= maximum):
            raise ValueError(f"unsafe staged runtime file: {relative}")
        descriptor = self._open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=parent_fd)
        if _identity(os.fstat(descriptor)) != _identity(before):
            raise ValueError(f"staged runtime changed while opening: {relative}")
        digest, chunks, size = hashlib.sha256(), [], 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > before.st_size:
                raise ValueError(f"staged runtime grew: {relative}")
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
        if size != before.st_size:
            raise ValueError(f"staged runtime size changed: {relative}")
        self.files.append((parent_fd, name, descriptor, _identity(before)))
        return b"".join(chunks) if retain else digest.hexdigest()

    def expected(self):
        cli = self.read("opt/syswarden/bin/syswarden-cli", 0o750, MAXIMUM_BINARY_BYTES)
        core = self.read("opt/syswarden/bin/syswarden-core", 0o750, MAXIMUM_BINARY_BYTES)
        self.revalidate()
        return descriptor_for_digests(cli, core)

    def revalidate(self, created_in=None):
        for parent, name, descriptor, expected in self.bindings + self.files:
            opened = os.fstat(descriptor)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            # Exclusive output creation legitimately changes only its parent's
            # directory size/timestamps. Device/inode/mode/owner/link count stay
            # bound, and every input file retains its complete identity.
            if created_in == descriptor:
                if _identity(opened)[:6] != expected[:6] or _identity(linked) != _identity(opened):
                    raise ValueError("staged output parent changed during creation")
            elif _identity(opened) != expected or _identity(linked) != expected:
                raise ValueError(f"staged runtime capture changed: {name}")


def expected_descriptor(root: Path) -> bytes:
    with ExitStack() as stack:
        return Capture(root, stack).expected()


def descriptor_for_digests(cli: str, core: str, *, legacy: bool = False) -> bytes:
    if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (cli, core)):
        raise ValueError("runtime capability requires exact lowercase SHA-256 digests")
    value = {
        "schema": "syswarden-native-activation-v1" if legacy else "syswarden-native-activation-v2",
        "architecture": "linux-amd64",
        "approval_schema": "syswarden-activation-approval-v1",
        "source_contract": "syswarden-toml-source-v1",
        "environment": "toml-only-reject-modular-environment-v1",
        "cli_sha256": cli,
        "core_sha256": core,
    }
    if not legacy:
        value["publication_exclusion"] = "config-directory-flock-and-native-debt-v1"
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("ascii")


def validate(root: Path) -> None:
    with ExitStack() as stack:
        capture = Capture(root, stack)
        expected = capture.expected()
        actual = capture.read(DESCRIPTOR_PATH, 0o644, 4096, retain=True)
        capture.revalidate()
        if actual != expected:
            raise ValueError("native activation descriptor disagrees with staged CLI/core or contract")


def generate(root: Path) -> None:
    # Failure preserves any exclusively created output for build diagnostics;
    # no path-based cleanup can erase a concurrently substituted file.
    with ExitStack() as stack:
        capture = Capture(root, stack)
        raw = capture.expected()
        parent = capture.directories["opt/syswarden"]
        output = capture._open("activation-contract-v1.json",
                               os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o644, dir_fd=parent)
        os.fchmod(output, 0o644)
        remaining = raw
        while remaining:
            written = os.write(output, remaining)
            if written <= 0:
                raise OSError("native activation descriptor write made no progress")
            remaining = remaining[written:]
        os.fsync(output)
        os.fsync(parent)
        actual = capture.read(DESCRIPTOR_PATH, 0o644, 4096, retain=True)
        if actual != raw or _identity(os.fstat(output)) != capture.files[-1][-1]:
            raise ValueError("native activation descriptor changed during publication")
        capture.revalidate(created_in=parent)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.check:
        validate(arguments.root)
    else:
        generate(arguments.root)


if __name__ == "__main__":
    main()
