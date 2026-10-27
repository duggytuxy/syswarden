#!/usr/bin/env python3
"""Check the exact launcher-free APK layout without extracting archive members.

This is a build-artifact check, not transition approval or signature verification.
The native coordinator must independently authenticate and approve its candidate.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

import package_stage_gate


class APKTransitionPayloadError(ValueError):
    """The APK is not the bounded launcher-free transition payload."""


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 128
MAX_CONTROL_BYTES = 1024 * 1024
HOOKS = {
    ".pre-install": "preinst.sh",
    ".pre-upgrade": "preupgrade.sh",
    ".post-install": "postinst.sh",
    ".post-upgrade": "postupgrade.sh",
    ".pre-deinstall": "prerm.sh",
    ".post-deinstall": "postrm.sh",
}
# The complete shared launcher subtree stays outside APK ownership. An empty
# directory payload could still change administrator parent metadata.
TRANSITION_ENTRIES = {
    name: entry for name, entry in package_stage_gate.APK_LINUX_ENTRIES.items()
    if name != "usr/local" and not name.startswith("usr/local/")
}


class BoundedReader:
    def __init__(self, source, limit: int):
        self.source = source
        self.remaining = limit

    def read(self, size: int = -1) -> bytes:
        wanted = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        data = self.source.read(wanted)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise APKTransitionPayloadError("APK exceeds its expanded-byte bound")
        return data


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_gid, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def file_contract(path: Path, expected_mode: int) -> tuple[int, str]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != expected_mode:
        raise APKTransitionPayloadError("reference file is not a regular file with the required mode")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if identity(opened) != identity(before) or not 0 < opened.st_size <= MAX_ARCHIVE_BYTES:
            raise APKTransitionPayloadError("reference file identity or size changed")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        if identity(os.fstat(source.fileno())) != identity(opened):
            raise APKTransitionPayloadError("reference file changed while hashing")
    if identity(path.lstat()) != identity(before):
        raise APKTransitionPayloadError("reference file was replaced while hashing")
    return opened.st_size, digest


def member_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    if (not name or not name.isascii() or name.startswith(("/", "./"))
            or any(part in ("", ".", "..") for part in name.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise APKTransitionPayloadError("APK has an ambiguous member path")
    return name


def read_member(source: BoundedReader, size: int, capture: bool = False):
    digest = hashlib.sha256()
    # APK's legacy checksum is checked as archive metadata, never as artifact
    # authentication. The staged content contract always uses SHA-256.
    apk_checksum = hashlib.sha1(usedforsecurity=False)
    content = bytearray()
    remaining = size
    while remaining:
        data = source.read(min(65536, remaining))
        if not data:
            raise APKTransitionPayloadError("APK member data is truncated")
        remaining -= len(data)
        digest.update(data)
        apk_checksum.update(data)
        if capture:
            content.extend(data)
    padding = (-size) % 512
    if source.read(padding) != bytes(padding):
        raise APKTransitionPayloadError("APK member padding is invalid")
    return bytes(content) if capture else (digest.hexdigest(), apk_checksum.hexdigest())


def validate(archive_path: Path, stage: Path, scripts: Path) -> dict[str, str]:
    # This also verifies the required canonical activation descriptor against
    # both staged runtime binaries before trusting any reference-file hashes.
    package_stage_gate.validate(stage, TRANSITION_ENTRIES)
    contracts = {
        name: file_contract(stage / name, entry.mode)
        for name, entry in TRANSITION_ENTRIES.items() if entry.kind == "file"
    }
    contracts.update({name: file_contract(scripts / source, 0o755) for name, source in HOOKS.items()})
    expected = set(TRANSITION_ENTRIES) - {"."}
    expected.update(HOOKS)
    expected.add(".PKGINFO")
    before = archive_path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise APKTransitionPayloadError("APK is not a bounded regular file")
    descriptor = os.open(archive_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    seen: set[str] = set()
    hashes: dict[str, str] = {}
    signatures = 0
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if identity(opened) != identity(before):
            raise APKTransitionPayloadError("APK changed while opening")
        with gzip.GzipFile(fileobj=source, mode="rb") as expanded:
            bounded = BoundedReader(expanded, MAX_EXPANDED_BYTES)
            zero_blocks = 0
            extended = None
            header_count = 0
            while True:
                block = bounded.read(512)
                if not block:
                    if zero_blocks < 2 or extended:
                        raise APKTransitionPayloadError("APK data archive has no complete tar ending")
                    break
                if len(block) != 512:
                    raise APKTransitionPayloadError("APK has a truncated tar header")
                if block == bytes(512):
                    if extended:
                        raise APKTransitionPayloadError("APK extended header has no file")
                    zero_blocks += 1
                    continue
                zero_blocks = 0
                header_count += 1
                if header_count > MAX_MEMBERS:
                    raise APKTransitionPayloadError("APK has excessive tar headers")
                member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
                if not 0 <= member.size <= MAX_ARCHIVE_BYTES:
                    raise APKTransitionPayloadError("APK member size exceeds its bound")
                if member.type == tarfile.XHDTYPE:
                    if extended or not 0 < member.size <= 4096:
                        raise APKTransitionPayloadError("APK extended header is excessive or repeated")
                    data = read_member(bounded, member.size, capture=True)
                    prefix, separator, record = data.partition(b" ")
                    expected_record = re.fullmatch(rb"APK-TOOLS\.checksum\.SHA1=[0-9a-f]{40}\n", record)
                    if not separator or prefix != str(len(data)).encode("ascii") or expected_record is None:
                        raise APKTransitionPayloadError("APK has unsupported extended metadata")
                    extended = record.split(b"=", 1)[1].rstrip(b"\n").decode("ascii")
                    continue
                if extended and member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    raise APKTransitionPayloadError("APK checksum metadata does not describe a regular file")
                checksum = extended
                extended = None
                name = member_name(member)
                if name in seen:
                    raise APKTransitionPayloadError("APK has duplicate members")
                seen.add(name)
                if name == "usr/local" or name.startswith("usr/local/"):
                    raise APKTransitionPayloadError("APK must not own the command-launcher subtree")
                if member.uid != 0 or member.gid != 0 or member.linkname or member.issparse():
                    raise APKTransitionPayloadError("APK member has unsupported ownership or link framing")
                signature = re.fullmatch(r"\.SIGN\.RSA\.[A-Za-z0-9_.+-]+", name) is not None
                if signature:
                    signatures += 1
                    if signatures != 1 or len(seen) != 1:
                        raise APKTransitionPayloadError("APK signature framing is ambiguous")
                elif name not in expected:
                    raise APKTransitionPayloadError("APK contains an unlisted member")
                entry = TRANSITION_ENTRIES.get(name)
                if entry is not None and entry.kind == "directory":
                    if not member.isdir() or member.mode != entry.mode or member.size != 0:
                        raise APKTransitionPayloadError("APK directory metadata differs from staging")
                    continue
                mode = 0o755 if name in HOOKS else entry.mode if entry is not None else 0o644
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.mode != mode or member.size == 0:
                    raise APKTransitionPayloadError("APK file type, mode or size is invalid")
                if name.startswith(".") and member.size > MAX_CONTROL_BYTES:
                    raise APKTransitionPayloadError("APK control member is excessive")
                digest, actual_checksum = read_member(bounded, member.size)
                if checksum is not None and actual_checksum != checksum:
                    raise APKTransitionPayloadError("APK member checksum differs from its bytes")
                hashes[name] = digest
                if name in contracts and (member.size, digest) != contracts[name]:
                    raise APKTransitionPayloadError("APK file bytes differ from the staged contract")
        if identity(os.fstat(source.fileno())) != identity(opened):
            raise APKTransitionPayloadError("APK changed during validation")
    if identity(archive_path.lstat()) != identity(before) or expected - seen:
        raise APKTransitionPayloadError("APK changed or is missing required members")
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--scripts", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(args.apk, args.stage, args.scripts)
    except (APKTransitionPayloadError, package_stage_gate.PackageStageError, OSError, EOFError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Validated exact launcher-free APK payload and hook bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
