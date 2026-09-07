#!/usr/bin/env python3
"""Verify the package-owned profile in an RPM without installing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


class VerificationError(RuntimeError):
    pass


EXTENSION_ROOT = Path(__file__).resolve().parent
INVENTORY_PATH = EXTENSION_ROOT / "inventory.json"
PROFILE_PATH = EXTENSION_ROOT / "profile.json"
RPM_TOOL = Path("/usr/bin/rpm")
MAX_RPM_BYTES = 256 * 1024 * 1024
MAX_QUERY_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PACKAGE_RELEASE = "1.rhelpo"


def fail(message: str) -> None:
    raise VerificationError(message)


def regular_bytes(path: Path, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_size <= 0
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
            or before_path.st_dev != before.st_dev
            or before_path.st_ino != before.st_ino
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
        return data, before
    finally:
        os.close(descriptor)


def load_json(path: Path, label: str) -> dict[str, Any]:
    data, _ = regular_bytes(path, 128 * 1024, label)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def unmapped_overflow_owner_is_expected() -> bool:
    if os.geteuid() == 65534:
        return False
    try:
        if Path("/").lstat().st_uid != 65534:
            return False
        mappings = Path("/proc/self/uid_map").read_text(encoding="ascii").splitlines()
        parsed = [tuple(int(field) for field in line.split()) for line in mappings]
    except (OSError, UnicodeError, ValueError):
        return False
    if not parsed or any(len(mapping) != 3 or mapping[2] <= 0 for mapping in parsed):
        return False
    return not any(start <= 65534 < start + length for start, _, length in parsed)


def trusted_rpm_tool() -> Path:
    try:
        resolved = RPM_TOOL.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        fail(f"cannot inspect RPM query tool: {exc}")
    allowed_owners = {0}
    if unmapped_overflow_owner_is_expected():
        allowed_owners.add(65534)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in allowed_owners
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(resolved, os.X_OK)
        or resolved.parent != Path("/usr/bin")
    ):
        fail("RPM query tool is not a protected system executable")
    for parent in (Path("/"), Path("/usr"), Path("/usr/bin")):
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.is_symlink()
            or parent_metadata.st_uid not in allowed_owners
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            fail("RPM query tool ancestry is not protected")
    return resolved


def rpm_query(package: Path, query: str, *options: str) -> str:
    tool = trusted_rpm_tool()
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    try:
        completed = subprocess.run(
            [str(tool), "--noplugins", "--query", "--package", *options, "--queryformat", query, str(package)],
            check=False,
            capture_output=True,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"RPM query failed: {exc}")
    if completed.returncode != 0:
        error = completed.stderr[:512].decode("utf-8", errors="replace").strip()
        fail(f"RPM query rejected the package: {error}")
    if len(completed.stdout) > MAX_QUERY_BYTES:
        fail("RPM query output exceeds its size bound")
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("RPM query output is not UTF-8") from exc


def parse_file_inventory(raw: str) -> dict[str, tuple[str, str, str, str, str, str]]:
    records: dict[str, tuple[str, str, str, str, str, str]] = {}
    for number, line in enumerate(raw.splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 7:
            fail(f"RPM file inventory line {number} is malformed")
        path, permissions, user, group, target, digest, link_count = fields
        if (
            not path.startswith("/")
            or path in records
            or not link_count.isascii()
            or not link_count.isdecimal()
            or any(ord(character) < 32 or ord(character) == 127 for character in "".join(fields))
        ):
            fail(f"RPM file inventory line {number} is unsafe")
        records[path] = (permissions, user, group, target, digest, link_count)
    if not records:
        fail("RPM file inventory is empty")
    return records


def expected_permissions(entry: dict[str, Any]) -> str:
    mode = int(entry["mode"], 8)
    kind = stat.S_IFDIR if entry["type"] == "directory" else stat.S_IFREG
    return stat.filemode(kind | mode)


def validate_payload(
    entries: list[dict[str, Any]],
    records: dict[str, tuple[str, str, str, str, str, str]],
    digest_algorithm: str,
) -> None:
    if digest_algorithm != "8":
        fail("RPM payload file digest algorithm is not SHA-256")
    expected_paths: set[str] = set()
    for entry in entries:
        if entry.get("rpm_ownership") != "payload":
            continue
        destination = entry.get("destination")
        if not isinstance(destination, str) or not destination.startswith("payload/"):
            fail("inventory contains an invalid RPM payload destination")
        package_path = "/" + destination.removeprefix("payload/")
        if package_path in expected_paths:
            fail("inventory contains a duplicate RPM payload path")
        expected_paths.add(package_path)
        actual = records.get(package_path)
        if actual is None:
            fail(f"RPM is missing package-owned payload path {package_path}")
        permissions, user, group, target, digest, link_count = actual
        if permissions != expected_permissions(entry):
            fail(f"RPM mode or type mismatch for {package_path}")
        if user != "root" or group != "root":
            fail(f"RPM owner mismatch for {package_path}")
        if target:
            fail(f"RPM contains an unexpected link target for {package_path}")
        if link_count != "1":
            fail(f"RPM contains a hard-linked profile payload path {package_path}")
        if entry["type"] == "regular":
            if digest != entry["sha256"]:
                fail(f"RPM payload digest mismatch for {package_path}")
        elif digest not in {"", "(none)"}:
            fail(f"RPM directory contains an unexpected digest for {package_path}")
    forbidden = {
        "/etc/init.d/syswarden-core",
        "/etc/init.d/syswarden-firewall",
    }
    if forbidden & set(records):
        fail("RHEL RPM unexpectedly packages OpenRC service files")
    integration_roots = (
        "/usr/lib/systemd/system",
        "/usr/lib/systemd/system-preset",
    )
    integration_prefixes = (
        "/usr/lib/systemd/system/",
        "/usr/lib/systemd/system-preset/",
    )
    protected_state_prefixes = (
        "/etc/syswarden/",
        "/var/lib/syswarden/",
        "/var/log/syswarden/",
    )
    for path, record in records.items():
        permissions, user, group, target, _, link_count = record
        if path in integration_roots:
            if (
                permissions != "drwxr-xr-x"
                or user != "root"
                or group != "root"
                or target
                or link_count != "1"
            ):
                fail(f"RHEL RPM contains an unsafe integration parent {path}")
            continue
        if path not in expected_paths and (
            path.startswith(integration_prefixes)
            or path.startswith("/etc/init.d/syswarden")
            or path.startswith(protected_state_prefixes)
        ):
            fail(f"RHEL RPM contains an undeclared package-owned path {path}")


def normalize_scriptlet(value: str) -> str:
    return value.rstrip("\n")


def validate_scriptlets(package: Path, profile: dict[str, Any]) -> None:
    rpm = profile.get("rpm")
    if not isinstance(rpm, dict):
        fail("profile RPM contract is invalid")
    lifecycle = rpm.get("lifecycle")
    expected_lifecycle = {
        "pre_install": "PREIN",
        "post_install": "POSTIN",
        "pre_uninstall": "PREUN",
        "post_uninstall": "POSTUN",
    }
    if not isinstance(lifecycle, dict) or set(lifecycle) != set(expected_lifecycle):
        fail("profile lifecycle keys are not exact")
    combined: list[str] = []
    for lifecycle_name, tag in expected_lifecycle.items():
        relative = lifecycle[lifecycle_name]
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            fail(f"profile {lifecycle_name} path is unsafe")
        expected_data, _ = regular_bytes(EXTENSION_ROOT / relative, 128 * 1024, lifecycle_name)
        try:
            expected = expected_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(f"profile {lifecycle_name} is not UTF-8") from exc
        actual = rpm_query(package, f"%{{{tag}}}")
        interpreter = rpm_query(package, f"%{{{tag}PROG}}")
        if normalize_scriptlet(actual) != normalize_scriptlet(expected):
            fail(f"RPM {lifecycle_name} bytes do not match the reviewed source")
        if interpreter != "/bin/sh":
            fail(f"RPM {lifecycle_name} interpreter is not /bin/sh")
        combined.append(actual)
    scriptlets = "\n".join(combined)
    for forbidden in (
        "/opt/syswarden/bin",
        "syswarden-cli",
        "firewall-cmd",
        "firewalld.service",
        "nftables.service",
        "/usr/bin/nft",
        "/usr/sbin/nft",
        "/usr/bin/curl",
        "/usr/bin/wget",
    ):
        if forbidden in scriptlets:
            fail(f"RPM scriptlets contain forbidden token {forbidden!r}")


def validate_dependencies(package: Path) -> None:
    requirements = set(rpm_query(package, "[%{REQUIRENAME}\n]").splitlines())
    if not {"systemd", "nftables"}.issubset(requirements):
        fail("RPM profile dependencies do not include systemd and nftables")
    if "firewalld" in requirements:
        fail("RPM profile must not force installation of a firewall frontend")


def verify(package: Path, expected_sha256: str) -> None:
    if SHA256.fullmatch(expected_sha256) is None:
        fail("expected RPM digest must be 64 lowercase hexadecimal characters")
    package_data, identity = regular_bytes(package, MAX_RPM_BYTES, "RPM package")
    if hashlib.sha256(package_data).hexdigest() != expected_sha256:
        fail("RPM package bytes do not match the expected digest")
    inventory = load_json(INVENTORY_PATH, "inventory")
    profile = load_json(PROFILE_PATH, "profile")
    if (
        inventory.get("schema_version") != 2
        or inventory.get("profile") != "rhel-package-owned-runtime/v2"
        or profile.get("schema_version") != 2
        or profile.get("profile") != "rhel-package-owned-runtime/v2"
    ):
        fail("profile identity is unsupported")
    with tempfile.TemporaryDirectory(prefix="syswarden-rhel-rpm-verify.") as raw_snapshot:
        snapshot_directory = Path(raw_snapshot)
        os.chmod(snapshot_directory, 0o700)
        snapshot = snapshot_directory / "candidate.rpm"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(snapshot, flags, 0o600)
        try:
            written = 0
            while written < len(package_data):
                count = os.write(descriptor, package_data[written:])
                if count <= 0:
                    fail("short write while snapshotting RPM package")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = rpm_query(
            snapshot,
            "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{FILEDIGESTALGO}\n",
        ).splitlines()
        if len(metadata) != 5:
            fail("RPM identity metadata is malformed")
        name, version, package_release, architecture, digest_algorithm = metadata
        expected_filename = f"syswarden-{version}-{PACKAGE_RELEASE}.x86_64.rpm"
        if (
            name != "syswarden"
            or VERSION.fullmatch(version) is None
            or package_release != PACKAGE_RELEASE
            or architecture != "x86_64"
            or package.name != expected_filename
        ):
            fail("RPM identity does not match the RHEL package-owned profile")
        records = parse_file_inventory(
            rpm_query(
                snapshot,
                "[%{FILENAMES}\\t%{FILEMODES:perms}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\t%{FILELINKTOS}\\t%{FILEDIGESTS}\\t%{FILENLINKS}\\n]",
            )
        )
        entries = inventory.get("entries")
        if not isinstance(entries, list):
            fail("inventory entries are invalid")
        validate_payload(entries, records, digest_algorithm)
        validate_scriptlets(snapshot, profile)
        validate_dependencies(snapshot)
        snapshot_data, _ = regular_bytes(snapshot, MAX_RPM_BYTES, "RPM snapshot")
        if snapshot_data != package_data:
            fail("RPM snapshot changed during verification")
    _, after = regular_bytes(package, MAX_RPM_BYTES, "RPM package")
    if (
        after.st_dev != identity.st_dev
        or after.st_ino != identity.st_ino
        or after.st_size != identity.st_size
        or after.st_mtime_ns != identity.st_mtime_ns
        or after.st_ctime_ns != identity.st_ctime_ns
    ):
        fail("RPM package changed during verification")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        verify(args.rpm, args.sha256)
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("RHEL package-owned RPM profile verified without installation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
