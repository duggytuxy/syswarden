#!/usr/bin/env python3
"""Verify the exact package-owned SysWarden systemd ordering artifact."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path


RELATIVE_PATH = (
    "usr/lib/systemd/system/syswarden-firewall.service.d/"
    "10-syswarden-wireguard-ordering.conf"
)
ABSOLUTE_PATH = "/" + RELATIVE_PATH
RPM_QUERY_FORMAT = (
    "[%{FILENAMES}\\t%{FILEMODES:perms}\\t%{FILEUSERNAME}\\t"
    "%{FILEGROUPNAME}\\t%{FILESIZES}\\t%{FILEDIGESTS}\\n]"
)


class OrderingArtifactError(ValueError):
    """Raised when the ordering artifact violates its exact contract."""


@dataclass(frozen=True)
class ContentContract:
    sha256: str
    size: int


def load_contract(path: Path) -> ContentContract:
    try:
        document = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OrderingArtifactError(f"cannot read ordering contract {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"sha256", "size"}:
        raise OrderingArtifactError("ordering contract schema is not exact")
    digest = document["sha256"]
    size = document["size"]
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or size > 4096
    ):
        raise OrderingArtifactError("ordering contract values are invalid")
    return ContentContract(digest, size)


def require_content(content: bytes, contract: ContentContract, label: str) -> None:
    if len(content) != contract.size:
        raise OrderingArtifactError(f"{label} size differs from the exact contract")
    if hashlib.sha256(content).hexdigest() != contract.sha256:
        raise OrderingArtifactError(f"{label} SHA-256 differs from the exact contract")


def read_regular(path: Path, allowed_modes: tuple[int, ...], label: str) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise OrderingArtifactError(f"cannot open {label} {path}: {exc}") from exc
    try:
        opened_before = os.fstat(descriptor)
        content = b""
        while len(content) <= 4096:
            chunk = os.read(descriptor, 4097 - len(content))
            if not chunk:
                break
            content += chunk
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise OrderingArtifactError(f"cannot reattest {label} {path}: {exc}") from exc
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        identity(before) != identity(opened_before)
        or identity(opened_before) != identity(opened_after)
        or identity(opened_after) != identity(after)
        or not stat.S_ISREG(after.st_mode)
        or stat.S_IMODE(after.st_mode) not in allowed_modes
        or after.st_nlink != 1
        or len(content) > 4096
    ):
        raise OrderingArtifactError(f"{label} identity or mode is not exact")
    return content


def validate_source_and_stage(
    source: Path,
    contract: ContentContract,
    root: Path | None = None,
) -> bytes:
    # A normal checkout exposes the tracked non-executable file as 0644. The
    # hermetic builder extracts the same Git object below umask 077, which
    # intentionally narrows it to 0600. Only those two source representations
    # are valid; the installed package payload remains exactly 0644.
    source_content = read_regular(source, (0o600, 0o644), "ordering source")
    require_content(source_content, contract, "ordering source")
    if root is not None:
        staged = read_regular(
            root / RELATIVE_PATH, (0o644,), "staged ordering artifact"
        )
        require_content(staged, contract, "staged ordering artifact")
        if staged != source_content:
            raise OrderingArtifactError("staged ordering bytes differ from the exact source")
    return source_content


def validate_deb(package: Path, expected: bytes, contract: ContentContract) -> None:
    inventory = subprocess.run(
        ["ar", "t", str(package)],
        check=False,
        capture_output=True,
        text=True,
    )
    if (
        inventory.returncode != 0
        or inventory.stderr
        or "\x00" in inventory.stdout
        or "\r" in inventory.stdout
        or inventory.stdout.splitlines().count("data.tar.gz") != 1
    ):
        raise OrderingArtifactError("DEB data archive inventory is not exact")
    completed = subprocess.run(
        ["ar", "p", str(package), "data.tar.gz"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0 or completed.stderr or not completed.stdout:
        raise OrderingArtifactError("cannot extract the DEB filesystem archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:*") as archive:
            matches = [item for item in archive.getmembers() if item.name == "./" + RELATIVE_PATH]
            if len(matches) != 1:
                raise OrderingArtifactError("DEB ordering member count is not exactly one")
            member = matches[0]
            if (
                not member.isreg()
                or member.mode != 0o644
                or member.uid != 0
                or member.gid != 0
                or member.size != contract.size
                or member.linkname != ""
            ):
                raise OrderingArtifactError("DEB ordering member metadata is not exact")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise OrderingArtifactError("DEB ordering member cannot be read")
            content = extracted.read(contract.size + 1)
    except (tarfile.TarError, OSError) as exc:
        raise OrderingArtifactError(f"invalid DEB filesystem archive: {exc}") from exc
    require_content(content, contract, "DEB ordering member")
    if content != expected:
        raise OrderingArtifactError("DEB ordering member differs from the exact source")


def validate_rpm(package: Path, expected: bytes, contract: ContentContract) -> None:
    digest_algorithm = subprocess.run(
        ["rpm", "-qp", "--qf", "%{FILEDIGESTALGO}\\n", str(package)],
        check=False,
        capture_output=True,
        text=True,
    )
    if digest_algorithm.returncode != 0 or digest_algorithm.stdout != "8\n":
        raise OrderingArtifactError("RPM file digest algorithm is not exactly SHA-256")
    inventory = subprocess.run(
        ["rpm", "-qp", "--qf", RPM_QUERY_FORMAT, str(package)],
        check=False,
        capture_output=True,
        text=True,
    )
    if inventory.returncode != 0 or "\x00" in inventory.stdout or "\r" in inventory.stdout:
        raise OrderingArtifactError("cannot inspect the RPM ordering inventory")
    matches = []
    for line in inventory.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise OrderingArtifactError("RPM inventory record is malformed")
        if fields[0] == ABSOLUTE_PATH:
            matches.append(fields)
    if len(matches) != 1:
        raise OrderingArtifactError("RPM ordering member count is not exactly one")
    path, permissions, owner, group, size, digest = matches[0]
    if (
        path != ABSOLUTE_PATH
        or permissions != "-rw-r--r--"
        or owner != "root"
        or group != "root"
        or size != str(contract.size)
        or digest != contract.sha256
    ):
        raise OrderingArtifactError("RPM ordering member metadata is not exact")

    producer = subprocess.Popen(
        ["rpm2cpio", str(package)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert producer.stdout is not None
    consumer = subprocess.run(
        ["cpio", "--extract", "--to-stdout", "--quiet", "." + ABSOLUTE_PATH],
        stdin=producer.stdout,
        check=False,
        capture_output=True,
    )
    producer.stdout.close()
    producer_stderr = producer.stderr.read() if producer.stderr is not None else b""
    producer_status = producer.wait()
    if producer_status != 0 or producer_stderr or consumer.returncode != 0 or consumer.stderr:
        raise OrderingArtifactError("cannot extract the exact RPM ordering member")
    require_content(consumer.stdout, contract, "RPM ordering member")
    if consumer.stdout != expected:
        raise OrderingArtifactError("RPM ordering member differs from the exact source")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("stage", "deb", "rpm"), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--package", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        contract = load_contract(args.contract)
        expected = validate_source_and_stage(
            args.source, contract, args.root if args.format == "stage" else None
        )
        if args.format == "stage":
            if args.root is None or args.package is not None:
                raise OrderingArtifactError("stage validation requires only --root")
        elif args.root is not None or args.package is None:
            raise OrderingArtifactError("package validation requires only --package")
        elif args.format == "deb":
            validate_deb(args.package, expected, contract)
        else:
            validate_rpm(args.package, expected, contract)
    except OrderingArtifactError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Validated exact systemd ordering artifact for {args.format}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
