#!/usr/bin/env python3
"""Atomically stage the explicit RHEL package-owned RPM profile."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


class StageError(RuntimeError):
    pass


EXTENSION_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = EXTENSION_ROOT.parent.parent
INVENTORY_PATH = EXTENSION_ROOT / "inventory.json"
PROFILE = "rhel-package-owned-runtime/v2"
MAX_INVENTORY_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHARED_PAYLOADS = (
    PurePosixPath(
        "usr/lib/systemd/system/syswarden-firewall.service.d/"
        "10-syswarden-wireguard-ordering.conf"
    ),
)
AT_FDCWD = -100
RENAME_NOREPLACE = 1
EXPECTED_KEYS = {
    "source",
    "destination",
    "type",
    "mode",
    "uid",
    "gid",
    "link_target",
    "sha256",
    "rpm_ownership",
    "rpm_package",
    "role",
}
EXPECTED_ROLES = (
    "configuration-root",
    "configuration-directory",
    "configuration-modules-directory",
    "lists-directory",
    "tls-directory",
    "state-directory",
    "ui-state-directory",
    "log-directory",
    "systemd-unit",
    "systemd-unit",
    "systemd-drop-in",
    "systemd-preset",
    "openrc-source",
    "openrc-source",
    "rpm-postun-recovery",
    "rpm-pre-install",
    "rpm-post-install",
    "rpm-pre-uninstall",
    "rpm-post-uninstall",
    "rpm-profile",
)


def fail(message: str) -> None:
    raise StageError(message)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        repository = REPOSITORY_ROOT.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve {label}: {exc}")
    if lexical != resolved or not resolved.is_relative_to(repository):
        fail(f"{label} must be a canonical repository path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_size < 0
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            fail(f"{label} is not a protected singly-linked regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) > maximum
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or after.st_nlink != 1
        ):
            fail(f"{label} changed while reading or exceeds its size bound")
        current = path.lstat()
        if (
            current.st_dev != before.st_dev
            or current.st_ino != before.st_ino
            or current.st_size != before.st_size
            or current.st_mode != before.st_mode
            or current.st_uid != before.st_uid
            or current.st_gid != before.st_gid
            or current.st_mtime_ns != before.st_mtime_ns
            or current.st_ctime_ns != before.st_ctime_ns
            or current.st_nlink != 1
        ):
            fail(f"{label} path changed while reading")
        return data
    finally:
        os.close(descriptor)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"inventory contains duplicate JSON key {key!r}")
        value[key] = item
    return value


def checked_relative(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{label} is not a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} is not a safe relative path")
    return path


def validate_entry(entry: object, index: int) -> dict[str, Any]:
    if not isinstance(entry, dict) or set(entry) != EXPECTED_KEYS:
        fail(f"inventory entry {index} keys are not exact")
    destination = checked_relative(entry["destination"], f"entry {index} destination")
    object_type = entry["type"]
    if object_type not in {"directory", "regular"}:
        fail(f"entry {index} type is unsupported")
    if entry["mode"] not in ({"0750"} if object_type == "directory" else {"0644", "0755"}):
        fail(f"entry {index} mode is unsupported")
    if entry["uid"] != 0 or entry["gid"] != 0:
        fail(f"entry {index} package ownership must be root:root")
    if entry["link_target"] is not None:
        fail(f"entry {index} link target must be null for {object_type}")
    ownership = entry["rpm_ownership"]
    package = entry["rpm_package"]
    if ownership not in {"payload", "scriptlet", "none"}:
        fail(f"entry {index} RPM ownership is unsupported")
    if ownership in {"payload", "scriptlet"}:
        if package != "syswarden":
            fail(f"entry {index} RPM package identity is invalid")
    elif package is not None:
        fail(f"entry {index} non-package source claims RPM ownership")
    if ownership == "payload" and destination.parts[0] != "payload":
        fail(f"entry {index} RPM payload destination is invalid")
    if ownership == "scriptlet" and destination.parts[0] != "rpm-scriptlets":
        fail(f"entry {index} RPM scriptlet destination is invalid")
    if object_type == "directory":
        if entry["source"] is not None or entry["sha256"] is not None:
            fail(f"entry {index} directory source metadata is invalid")
    else:
        checked_relative(entry["source"], f"entry {index} source")
        if not isinstance(entry["sha256"], str) or SHA256.fullmatch(entry["sha256"]) is None:
            fail(f"entry {index} digest is malformed")
    if not isinstance(entry["role"], str) or not entry["role"]:
        fail(f"entry {index} role is invalid")
    return entry


def load_inventory() -> tuple[dict[str, Any], bytes]:
    raw = read_regular(INVENTORY_PATH, MAX_INVENTORY_BYTES, "inventory")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid inventory: {exc}")
    if not isinstance(document, dict) or set(document) != {"schema_version", "profile", "entries"}:
        fail("inventory keys are not exact")
    if document["schema_version"] != 2 or document["profile"] != PROFILE:
        fail("inventory identity is unsupported")
    entries = document["entries"]
    if not isinstance(entries, list) or len(entries) != len(EXPECTED_ROLES):
        fail("inventory entry count is not exact")
    validated = [validate_entry(entry, index) for index, entry in enumerate(entries)]
    if tuple(entry["role"] for entry in validated) != EXPECTED_ROLES:
        fail("inventory role order is not exact")
    destinations = [entry["destination"] for entry in validated]
    if len(set(destinations)) != len(destinations):
        fail("inventory destinations must be unique")
    sources = [entry["source"] for entry in validated if entry["source"] is not None]
    if len(set(sources)) != len(sources):
        fail("inventory sources must be unique")
    return document, raw


def secure_output_parent(output: Path) -> Path:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        fail("output must be an absolute path")
    try:
        parent = output.parent.resolve(strict=True)
        lexical_parent = output.parent.absolute()
        metadata = parent.lstat()
    except OSError as exc:
        fail(f"cannot inspect output parent: {exc}")
    if lexical_parent != parent or not stat.S_ISDIR(metadata.st_mode) or output.parent.is_symlink():
        fail("output parent must be a canonical real directory")
    mode = stat.S_IMODE(metadata.st_mode)
    protected_owner = metadata.st_uid == os.geteuid() and mode & 0o022 == 0
    protected_sticky = metadata.st_uid == 0 and mode & stat.S_ISVTX != 0
    if not (protected_owner or protected_sticky):
        fail("output parent is not owner-controlled or root-owned sticky")
    try:
        output.lstat()
    except FileNotFoundError:
        return parent
    except OSError as exc:
        fail(f"cannot inspect output path: {exc}")
    fail("output path must not already exist")


def write_regular(path: Path, data: bytes, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                fail(f"short write while staging {path.name}")
            written += count
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a staged directory without replacing any path."""
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        fail("atomic no-replace publication is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        fail(f"atomic no-replace publication failed: {os.strerror(error_number)}")


def prepare_sources(entries: list[dict[str, Any]]) -> dict[str, bytes]:
    prepared: dict[str, bytes] = {}
    for entry in entries:
        if entry["type"] != "regular":
            continue
        source_rel = checked_relative(entry["source"], "inventory source")
        source = REPOSITORY_ROOT.joinpath(*source_rel.parts)
        data = read_regular(source, MAX_SOURCE_BYTES, f"source {source_rel}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            fail(f"source digest mismatch: {source_rel}")
        prepared[entry["source"]] = data
    return prepared


def verify_staged(root: Path, entries: list[dict[str, Any]], prepared: dict[str, bytes]) -> None:
    for entry in entries:
        relative = checked_relative(entry["destination"], "staged destination")
        path = root.joinpath(*relative.parts)
        metadata = path.lstat()
        if entry["type"] == "directory":
            if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                fail(f"staged directory type changed: {relative}")
        else:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"staged file type changed: {relative}")
            data = path.read_bytes()
            if data != prepared[entry["source"]] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                fail(f"staged file bytes changed: {relative}")
        if stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8):
            fail(f"staged mode changed: {relative}")


def protected_file_identity(path: Path, root: Path, label: str) -> tuple[bytes, int, int, int]:
    try:
        canonical_root = root.resolve(strict=True)
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if (
        lexical != resolved
        or not resolved.is_relative_to(canonical_root)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail(f"{label} is not a protected singly-linked regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) > MAX_SOURCE_BYTES
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mode != opened.st_mode
            or after.st_uid != opened.st_uid
            or after.st_gid != opened.st_gid
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_nlink != 1
        ):
            fail(f"{label} changed while reading or exceeds its size bound")
        return data, stat.S_IMODE(opened.st_mode), opened.st_uid, opened.st_gid
    finally:
        os.close(descriptor)


def verify_shared_payloads(profile_payload: Path, base_payload: Path) -> None:
    try:
        lexical = base_payload.absolute()
        canonical = base_payload.resolve(strict=True)
        metadata = canonical.lstat()
    except OSError as exc:
        fail(f"cannot inspect shared base payload: {exc}")
    if (
        lexical != canonical
        or not stat.S_ISDIR(metadata.st_mode)
        or base_payload.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail("shared base payload must be an owner-controlled real directory")
    for relative in SHARED_PAYLOADS:
        profile_path = profile_payload.joinpath(*relative.parts)
        base_path = base_payload.joinpath(*relative.parts)
        profile_identity = protected_file_identity(
            profile_path, profile_payload, f"profile shared payload {relative}"
        )
        base_identity = protected_file_identity(
            base_path, base_payload, f"base shared payload {relative}"
        )
        if profile_identity != base_identity:
            fail(
                "shared package payload differs in bytes, mode or owner: "
                f"{relative}"
            )


def stage(output: Path, shared_base_payload: Path | None = None) -> None:
    parent = secure_output_parent(output)
    inventory, inventory_raw = load_inventory()
    entries = inventory["entries"]
    prepared = prepare_sources(entries)
    temporary = Path(tempfile.mkdtemp(prefix=".syswarden-rhel-profile.", dir=parent))
    os.chmod(temporary, 0o700)
    published = False
    try:
        for entry in entries:
            relative = checked_relative(entry["destination"], "inventory destination")
            destination = temporary.joinpath(*relative.parts)
            if entry["type"] == "directory":
                destination.mkdir(mode=int(entry["mode"], 8), parents=True, exist_ok=False)
                os.chmod(destination, int(entry["mode"], 8))
                continue
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                fail(f"staged destination already exists: {relative}")
            write_regular(
                destination,
                prepared[entry["source"]],
                int(entry["mode"], 8),
            )
        manifest = {
            "schema_version": 1,
            "profile": PROFILE,
            "status": "staged-not-installed",
            "inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
            "managed_entry_count": len(entries),
            "rpm_payload_entry_count": sum(
                entry["rpm_ownership"] == "payload" for entry in entries
            ),
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_regular(temporary / "assembly-manifest.json", manifest_bytes, 0o600)
        verify_staged(temporary, entries, prepared)
        if shared_base_payload is not None:
            verify_shared_payloads(temporary / "payload", shared_base_payload)
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(temporary, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        publish_noreplace(temporary, output)
        published = True
        parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if not published and temporary.exists() and temporary.parent == parent and temporary.name.startswith(
            ".syswarden-rhel-profile."
        ):
            shutil.rmtree(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--enable-rhel-package-owned-profile", action="store_true")
    parser.add_argument("--shared-base-payload", type=Path)
    args = parser.parse_args(argv)
    if not args.enable_rhel_package_owned_profile:
        print("ERROR: explicit profile opt-in is required", file=sys.stderr)
        return 1
    try:
        stage(args.output, args.shared_base_payload)
    except (OSError, StageError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("RHEL package-owned profile staged; no host or service mutation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
