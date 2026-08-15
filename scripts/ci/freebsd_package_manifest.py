#!/usr/bin/env python3
"""Finalize and verify the exact SysWarden FreeBSD package dependency manifest."""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
import tarfile
import tempfile
from pathlib import Path


FREEBSD_RUNTIME_DEPENDENCIES = {
    "curl": {"origin": "ftp/curl", "version": "*"},
    "jq": {"origin": "textproc/jq", "version": "*"},
    "libqrencode": {"origin": "graphics/libqrencode", "version": "*"},
    "rsyslog": {"origin": "sysutils/rsyslog8", "version": "*"},
    "wireguard-tools": {"origin": "net/wireguard-tools", "version": "*"},
}
MANIFEST_NAMES = ("+COMPACT_MANIFEST", "+MANIFEST")


class FreeBSDManifestError(RuntimeError):
    pass


def package_path(value: Path) -> Path:
    path = value.absolute()
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FreeBSDManifestError("FreeBSD package must be a regular non-symlink file")
    return path


def manifest_bytes(raw: bytes, name: str) -> bytes:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreeBSDManifestError(f"invalid JSON in {name}") from exc
    if not isinstance(document, dict):
        raise FreeBSDManifestError(f"{name} must contain an object")
    existing = document.get("deps")
    if existing not in (None, {}, FREEBSD_RUNTIME_DEPENDENCIES):
        raise FreeBSDManifestError(f"{name} carries unexpected dependencies")
    document["deps"] = FREEBSD_RUNTIME_DEPENDENCIES
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def finalize(path_value: Path) -> None:
    path = package_path(path_value)
    with tarfile.open(path, "r:xz") as source:
        members = source.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or names.count("+MANIFEST") != 1 or names.count("+COMPACT_MANIFEST") != 1:
            raise FreeBSDManifestError("FreeBSD package member inventory is ambiguous")
        payloads: dict[str, bytes | None] = {}
        for member in members:
            if member.isfile():
                stream = source.extractfile(member)
                if stream is None:
                    raise FreeBSDManifestError(f"cannot read package member {member.name}")
                payloads[member.name] = stream.read()
            else:
                payloads[member.name] = None

    ordered = sorted(members, key=lambda item: (item.name not in MANIFEST_NAMES, MANIFEST_NAMES.index(item.name) if item.name in MANIFEST_NAMES else 0))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, "w:xz", format=tarfile.PAX_FORMAT) as target:
            for member in ordered:
                data = payloads[member.name]
                if member.name in MANIFEST_NAMES:
                    if data is None:
                        raise FreeBSDManifestError(f"{member.name} is not a regular file")
                    data = manifest_bytes(data, member.name)
                    member.size = len(data)
                target.addfile(member, io.BytesIO(data) if data is not None else None)
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    verify(path)


def verify(path_value: Path) -> None:
    path = package_path(path_value)
    with tarfile.open(path, "r:xz") as package:
        for name in MANIFEST_NAMES:
            matches = package.getmembers()
            member_matches = [member for member in matches if member.name == name]
            if len(member_matches) != 1:
                raise FreeBSDManifestError(f"missing exact {name}")
            stream = package.extractfile(member_matches[0])
            if stream is None:
                raise FreeBSDManifestError(f"cannot read {name}")
            document = json.loads(stream.read())
            if document.get("deps") != FREEBSD_RUNTIME_DEPENDENCIES:
                raise FreeBSDManifestError(f"{name} dependency contract is not exact")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("finalize", "verify"))
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    if args.command == "finalize":
        finalize(args.package)
    else:
        verify(args.package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
