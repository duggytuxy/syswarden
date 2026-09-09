#!/usr/bin/env python3
"""Build and verify the fail-closed native package signing evidence bundle."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zlib
from pathlib import Path
from typing import Any

try:
    from scripts.ci import native_package_signature_gate as signature_gate
except ModuleNotFoundError:
    import native_package_signature_gate as signature_gate


class SigningBundleError(RuntimeError):
    pass


TARGET_RELEASE = "v4.10.0"
SCHEMA_PROFILE = "syswarden-native-package-signing/v4.10.0"
VERIFICATION_PROFILE = "syswarden-native-package-verification/v4.10.0"
RPM_PROOF_PROFILE = "syswarden-rpm-payload-preservation/v4.10.0"
RHEL_PACKAGE_OWNED_PROFILE = "syswarden-rhel-package-owned-signing/v4.10.0"
RHEL_PACKAGE_OWNED_DIRECTORY = "rhel-package-owned"
QUALIFIED_PROVENANCE_STATUS = "native-signatures-verified-not-release-qualified"
BOOTSTRAP_PROVENANCE_STATUS = (
    "native-signatures-bootstrap-verified-not-release-qualified"
)
BOOTSTRAP_REFERENCE_PROFILE = (
    "syswarden-native-package-signing-bootstrap-reference/v4.10.0"
)
BOOTSTRAP_REPOSITORY = "duggytuxy/syswarden"
BOOTSTRAP_RELEASE_SHA = "9598861f1be80a651658bf3ca8c10424bd70db6c"
BOOTSTRAP_SIGNING_RUN_ID = 34292701745
BOOTSTRAP_SIGNED_ARTIFACT_ID = 10088398939
BOOTSTRAP_SIGNED_ARTIFACT_NAME = (
    "syswarden-native-signed-packages-4.10.0-34292701745-1-"
    "9598861f1be80a651658bf3ca8c10424bd70db6c"
)
BOOTSTRAP_SIGNED_ARTIFACT_SIZE = 63065295
BOOTSTRAP_SIGNED_ARTIFACT_DIGEST = (
    "sha256:a76917630d5d5a90bddcf936d47ec75a987f098c9048bce0d320d1ffda131ad3"
)
FOUNDATION_POLICY_SHA256 = (
    "6b98b3b5bca83b9bc611c3b2e384636b5bbcbecc9e818e0f06104255200b011d"
)
QUALIFIED_BUNDLE_MODE = "qualified"
BOOTSTRAP_BUNDLE_MODE = "bootstrap"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GITHUB_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KEY_ID = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
OCI_DIGEST = signature_gate.OCI_DIGEST
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_APK_SIGNATURE_PREFIX_BYTES = 1024 * 1024
MAX_APK_CONTROL_TAR_BYTES = 16 * 1024 * 1024
MAX_APK_SIGNED_CONTROL_BYTES = 32 * 1024 * 1024
MAX_DEB_SIGNATURE_BYTES = signature_gate.MAX_DEB_SIGNATURE_BYTES


def fail(message: str) -> None:
    raise SigningBundleError(message)


def package_names(release: str) -> dict[str, str]:
    if release != TARGET_RELEASE:
        fail(f"native signing workflow is frozen to {TARGET_RELEASE}")
    version = release.removeprefix("v")
    return {
        "deb": f"syswarden_{version}_amd64.deb",
        "rpm": f"syswarden-{version}-1.x86_64.rpm",
        "apk": f"syswarden_{version}_x86_64.apk",
    }


def deb_signature_name(release: str) -> str:
    return package_names(release)["deb"] + ".asc"


def rhel_package_owned_name(release: str) -> str:
    if release != TARGET_RELEASE:
        fail(f"RHEL package-owned signing is frozen to {TARGET_RELEASE}")
    return f"syswarden-{release.removeprefix('v')}-1.rhelpo.x86_64.rpm"


def regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a singly-linked regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            fail(f"{label} changed while opening")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) > maximum
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
            fail(f"{label} changed while reading or exceeds its bound")
        current = path.lstat()
        if (
            current.st_dev != opened.st_dev
            or current.st_ino != opened.st_ino
            or current.st_size != opened.st_size
            or current.st_mode != opened.st_mode
            or current.st_uid != opened.st_uid
            or current.st_gid != opened.st_gid
            or current.st_mtime_ns != opened.st_mtime_ns
            or current.st_ctime_ns != opened.st_ctime_ns
            or current.st_nlink != 1
        ):
            fail(f"{label} path changed while reading")
        return data
    finally:
        os.close(descriptor)


def load_json(path: Path, label: str) -> dict[str, Any]:
    raw = regular_bytes(path, MAX_JSON_BYTES, label)

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"{label} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda token: fail(
                f"{label} contains non-finite JSON number {token}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigningBundleError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        fail(f"{label} must be a JSON object")
    return document


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys are not exact")
    return value


def exact_json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if set(left) != set(right):
            return False
        return all(exact_json_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(
            exact_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(name: str, data: bytes) -> dict[str, object]:
    return {"name": name, "sha256": sha256(data), "size": len(data)}


def ensure_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a real directory")


def ensure_protected_directory(path: Path, label: str) -> None:
    try:
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    mode = stat.S_IMODE(metadata.st_mode)
    owner_controlled = metadata.st_uid == os.geteuid() and mode & 0o022 == 0
    root_sticky = metadata.st_uid == 0 and mode & stat.S_ISVTX != 0
    if (
        lexical != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or not (owner_controlled or root_sticky)
    ):
        fail(f"{label} must be a protected real directory")


def exact_directory_files(path: Path, expected: set[str], label: str) -> None:
    ensure_real_directory(path, label)
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        fail(f"cannot enumerate {label}: {exc}")
    if {entry.name for entry in entries} != expected:
        fail(f"{label} inventory is not exact")
    for entry in entries:
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"{label} contains an unsafe entry")


def manifest_records(path: Path, label: str) -> dict[str, str]:
    raw = regular_bytes(path, MAX_MANIFEST_BYTES, label)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SigningBundleError(f"{label} must be ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        fail(f"{label} is not canonical")
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*)",
            line,
        )
        if match is None or match.group(2) in records:
            fail(f"{label} contains a malformed or duplicate record")
        records[match.group(2)] = match.group(1)
    return records


def parse_manifest(path: Path, expected: dict[str, bytes], label: str) -> None:
    records = manifest_records(path, label)
    if set(records) != set(expected):
        fail(f"{label} package inventory is not exact")
    for name, data in expected.items():
        if records[name] != sha256(data):
            fail(f"{label} digest mismatch for {name}")


def canonical_manifest(records: dict[str, bytes]) -> bytes:
    return "".join(
        f"{sha256(records[name])}  {name}\n" for name in sorted(records)
    ).encode("ascii")


def package_set(
    directory: Path,
    release: str,
    require_manifest: bool,
    include_deb_signature: bool = False,
) -> dict[str, bytes]:
    names = package_names(release)
    expected = set(names.values())
    signature_name = deb_signature_name(release)
    if include_deb_signature:
        expected.add(signature_name)
    if require_manifest:
        expected.add("SHA256SUMS.txt")
    exact_directory_files(directory, expected, "package directory")
    packages = {
        family: regular_bytes(directory / name, MAX_PACKAGE_BYTES, f"{family} package")
        for family, name in names.items()
    }
    if require_manifest:
        manifest_content = {names[family]: data for family, data in packages.items()}
        if include_deb_signature:
            manifest_content[signature_name] = regular_bytes(
                directory / signature_name,
                MAX_DEB_SIGNATURE_BYTES,
                "DEB detached signature",
            )
        parse_manifest(
            directory / "SHA256SUMS.txt",
            manifest_content,
            "package checksum manifest",
        )
    return packages


def rhel_package_owned_set(
    directory: Path, release: str, require_manifest: bool
) -> bytes:
    name = rhel_package_owned_name(release)
    expected = {name}
    if require_manifest:
        expected.add("SHA256SUMS.txt")
    exact_directory_files(directory, expected, "RHEL package-owned directory")
    package = regular_bytes(
        directory / name, MAX_PACKAGE_BYTES, "RHEL package-owned RPM"
    )
    if require_manifest:
        parse_manifest(
            directory / "SHA256SUMS.txt",
            {name: package},
            "RHEL package-owned checksum manifest",
        )
    return package


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    ensure_protected_directory(path.parent, "output directory")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        fail(f"cannot create {path.name}: {exc}")
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            count = os.write(descriptor, data[offset:])
            if count <= 0:
                fail(f"short write while creating {path.name}")
            offset += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != mode
            or current.st_dev != opened.st_dev
            or current.st_ino != opened.st_ino
            or current.st_size != opened.st_size
            or current.st_mode != opened.st_mode
            or current.st_uid != opened.st_uid
            or current.st_gid != opened.st_gid
            or current.st_mtime_ns != opened.st_mtime_ns
            or current.st_ctime_ns != opened.st_ctime_ns
            or current.st_nlink != 1
        ):
            fail(f"{path.name} changed while being created")
    finally:
        os.close(descriptor)


def write_json(path: Path, document: dict[str, Any]) -> None:
    write_exclusive(
        path,
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def build_inventory(directory: Path, release: str) -> dict[str, Any]:
    packages = package_set(directory, release, require_manifest=True)
    names = package_names(release)
    return {
        "artifacts": [
            file_record(names[family], packages[family])
            for family in sorted(packages)
        ],
        "release": release,
        "schema_version": 1,
    }


def build_rhel_package_owned_inventory(
    directory: Path, release: str
) -> dict[str, Any]:
    package = rhel_package_owned_set(directory, release, require_manifest=True)
    return {
        "artifacts": [file_record(rhel_package_owned_name(release), package)],
        "release": release,
        "schema_version": 1,
    }


def validate_verification(
    document: dict[str, Any],
    family: str,
    release: str,
    package_name: str,
    package_data: bytes,
    policy_sha256: str,
    signature_name: str | None = None,
    signature_data: bytes | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "as_of",
        "family",
        "key",
        "mechanism",
        "package",
        "policy_sha256",
        "profile",
        "purpose",
        "release",
        "schema_version",
        "status",
    }
    if family == "deb":
        expected_keys.add("signature")
    exact_keys(
        document,
        expected_keys,
        f"{family} verification evidence",
    )
    mechanism = {
        "rpm": "rpm-openpgp",
        "apk": "apk-rsa256",
        "deb": "openpgp-detached",
    }[family]
    if (
        document["schema_version"] != 1
        or document["profile"] != VERIFICATION_PROFILE
        or document["status"] != "verified"
        or document["purpose"] != "qualification"
        or document["release"] != release
        or document["family"] != family
        or document["mechanism"] != mechanism
        or document["policy_sha256"] != policy_sha256
    ):
        fail(f"{family} verification identity is invalid")
    try:
        dt.date.fromisoformat(document["as_of"])
    except (TypeError, ValueError) as exc:
        raise SigningBundleError(
            f"{family} verification date is invalid"
        ) from exc
    package = exact_keys(
        document["package"], {"name", "sha256", "size"}, f"{family} package evidence"
    )
    if package != file_record(package_name, package_data):
        fail(f"{family} verification is not bound to the signed package")
    key = exact_keys(
        document["key"],
        {"fingerprint", "id", "public_key", "public_key_sha256"},
        f"{family} key evidence",
    )
    fingerprint_pattern = (
        SHA256 if family == "apk" else signature_gate.OPENPGP_FINGERPRINT
    )
    if (
        not isinstance(key["id"], str)
        or KEY_ID.fullmatch(key["id"]) is None
        or not isinstance(key["public_key"], str)
        or signature_gate.SAFE_RELATIVE_KEY_PATH.fullmatch(key["public_key"]) is None
        or Path(key["public_key"]).is_absolute()
        or ".." in Path(key["public_key"]).parts
        or not key["public_key"].startswith("native-package-keys/")
        or not isinstance(key["fingerprint"], str)
        or fingerprint_pattern.fullmatch(key["fingerprint"]) is None
        or not isinstance(key["public_key_sha256"], str)
        or SHA256.fullmatch(key["public_key_sha256"]) is None
    ):
        fail(f"{family} key evidence is malformed")
    if family == "apk" and key["fingerprint"] != key["public_key_sha256"]:
        fail("APK key fingerprint and public-key digest differ")
    if family == "deb":
        if signature_name is None or signature_data is None:
            fail("DEB verification requires detached signature bytes")
        signature = exact_keys(
            document["signature"],
            {"created_at", "name", "sha256", "size"},
            "DEB detached signature evidence",
        )
        expected_signature = file_record(signature_name, signature_data)
        if (
            {key: signature[key] for key in ("name", "sha256", "size")}
            != expected_signature
            or not isinstance(signature["created_at"], str)
        ):
            fail("DEB verification is not bound to the detached signature")
        try:
            created_at = dt.datetime.fromisoformat(
                signature["created_at"].replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise SigningBundleError("DEB signature creation time is invalid") from exc
        if (
            created_at.tzinfo != dt.timezone.utc
            or created_at.date().isoformat() != document["as_of"]
            or created_at.isoformat().replace("+00:00", "Z")
            != signature["created_at"]
        ):
            fail("DEB signature creation time is not canonical or coherent")
    return key


def validate_apk_signature_archive(
    prefix: bytes, public_key: str, source_date_epoch: int
) -> tuple[str, bytes]:
    expected_name = ".SIGN.RSA256." + Path(public_key).name
    if (
        len(prefix) < 18
        or prefix[:4] != b"\x1f\x8b\x08\x00"
        or prefix[4:8] != b"\x00\x00\x00\x00"
        or prefix[8] != 2
        or prefix[9] not in {0, 3, 255}
    ):
        fail("APK signature gzip header is not canonical")
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        tar_bytes = decompressor.decompress(prefix, 64 * 1024 + 1)
        if decompressor.unconsumed_tail or len(tar_bytes) > 64 * 1024:
            fail("APK signature gzip stream exceeds its decompressed size bound")
        tar_bytes += decompressor.flush(64 * 1024 + 1 - len(tar_bytes))
        if (
            not decompressor.eof
            or decompressor.unused_data
            or decompressor.unconsumed_tail
            or len(tar_bytes) > 64 * 1024
        ):
            fail("APK signature gzip stream is not singular and bounded")
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != 1:
                fail("APK signature archive must contain exactly one entry")
            member = members[0]
            if (
                member.name != expected_name
                or not member.isfile()
                or member.issym()
                or member.islnk()
                or member.size < 128
                or member.size > 1024
                or member.uid != 0
                or member.gid != 0
                or member.mode != 0o644
                or member.mtime != source_date_epoch
                or member.linkname != ""
                or member.uname not in {"", "root"}
                or member.gname not in {"", "root"}
                or member.pax_headers != {"atime": "0", "ctime": "0"}
            ):
                fail("APK signature archive entry is invalid")
            stream = archive.extractfile(member)
            if stream is None:
                fail("APK signature archive entry cannot be read")
            signature = stream.read(1025)
            if len(signature) != member.size or len(signature) > 1024:
                fail("APK signature archive payload is invalid")
            payload_end = member.offset_data + ((member.size + 511) // 512) * 512
            if payload_end > len(tar_bytes) or any(tar_bytes[payload_end:]):
                fail("APK signature tar padding contains unexpected data")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise SigningBundleError("APK signature prefix is not a valid tar archive") from exc
    return expected_name, signature


def unsigned_apk_control_stream(package: bytes) -> bytes:
    """Return the exact first gzip member from an unsigned APK v2 package."""

    if len(package) < 20 or not package.startswith(b"\x1f\x8b\x08"):
        fail("unsigned APK does not start with a gzip control stream")
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        control_tar = decompressor.decompress(
            package, MAX_APK_CONTROL_TAR_BYTES + 1
        )
        if decompressor.unconsumed_tail or len(control_tar) > MAX_APK_CONTROL_TAR_BYTES:
            fail("unsigned APK control archive exceeds its decompressed size bound")
        control_tar += decompressor.flush()
    except zlib.error as exc:
        raise SigningBundleError(
            "unsigned APK control stream is not valid gzip"
        ) from exc
    if (
        not decompressor.eof
        or decompressor.unconsumed_tail
        or len(control_tar) > MAX_APK_CONTROL_TAR_BYTES
        or not decompressor.unused_data.startswith(b"\x1f\x8b\x08")
    ):
        fail("unsigned APK must contain distinct control and data gzip streams")
    control_size = len(package) - len(decompressor.unused_data)
    if control_size <= 0 or control_size >= len(package):
        fail("unsigned APK control stream boundary is invalid")

    try:
        with tarfile.open(fileobj=io.BytesIO(control_tar), mode="r:") as archive:
            members = archive.getmembers()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise SigningBundleError(
            "unsigned APK control stream is not a valid tar archive"
        ) from exc
    names = [member.name for member in members]
    if (
        not members
        or len(names) != len(set(names))
        or names.count(".PKGINFO") != 1
        or any(name.startswith(".SIGN.") for name in names)
    ):
        fail("unsigned APK control archive identity is invalid")
    for member in members:
        parts = Path(member.name).parts
        if (
            not member.isfile()
            or member.issym()
            or member.islnk()
            or not parts
            or Path(member.name).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            fail("unsigned APK control archive contains an unsafe entry")
    return package[:control_size]


def apk_control_command(args: argparse.Namespace) -> None:
    package = regular_bytes(
        args.unsigned_package, MAX_PACKAGE_BYTES, "unsigned APK package"
    )
    write_exclusive(args.output, unsigned_apk_control_stream(package), 0o600)


def apk_assemble_command(args: argparse.Namespace) -> None:
    positive_integer(args.source_date_epoch, "source date epoch")
    if (
        Path(args.public_key_name).name != args.public_key_name
        or re.fullmatch(r"[A-Za-z0-9._+-]+\.rsa\.pub", args.public_key_name)
        is None
    ):
        fail("APK public key filename is invalid")
    unsigned = regular_bytes(
        args.unsigned_package, MAX_PACKAGE_BYTES, "unsigned APK package"
    )
    control = unsigned_apk_control_stream(unsigned)
    signed_control = regular_bytes(
        args.signed_control,
        MAX_APK_SIGNED_CONTROL_BYTES,
        "signed APK control stream",
    )
    if (
        len(signed_control) <= len(control)
        or not signed_control.endswith(control)
    ):
        fail("signed APK control stream did not preserve the exact unsigned control")
    signature_prefix = signed_control[: -len(control)]
    if len(signature_prefix) > MAX_APK_SIGNATURE_PREFIX_BYTES:
        fail("APK signature prefix exceeds its compressed size bound")
    validate_apk_signature_archive(
        signature_prefix, args.public_key_name, args.source_date_epoch
    )
    signed_package = signature_prefix + unsigned
    if (
        len(signed_package) > MAX_PACKAGE_BYTES + MAX_APK_SIGNATURE_PREFIX_BYTES
        or not signed_package.endswith(unsigned)
    ):
        fail("signed APK did not preserve the exact unsigned package suffix")
    write_exclusive(args.output, signed_package, 0o600)


def validate_rpm_proof(document: dict[str, Any]) -> None:
    exact_keys(
        document,
        {"profile", "schema_version", "signed", "status", "unsigned"},
        "RPM preservation proof",
    )
    if (
        document["schema_version"] != 1
        or document["profile"] != RPM_PROOF_PROFILE
        or document["status"] != "preserved"
    ):
        fail("RPM preservation proof identity is invalid")
    expected_keys = {"immutable_header_sha256", "payload_cpio_sha256"}
    unsigned = exact_keys(document["unsigned"], expected_keys, "unsigned RPM proof")
    signed = exact_keys(document["signed"], expected_keys, "signed RPM proof")
    for field in sorted(expected_keys):
        if (
            not isinstance(unsigned[field], str)
            or SHA256.fullmatch(unsigned[field]) is None
            or not isinstance(signed[field], str)
            or SHA256.fullmatch(signed[field]) is None
            or unsigned[field] != signed[field]
        ):
            fail(f"RPM {field} was not proven byte-identical")


def create_output_root(path: Path) -> tuple[Path, Path]:
    ensure_protected_directory(path.parent, "signing bundle parent")
    try:
        path.mkdir(mode=0o700)
        packages = path / "packages"
        evidence = path / "evidence"
        packages.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
    except OSError as exc:
        fail(f"cannot create signing bundle output: {exc}")
    return packages, evidence


def create_rhel_package_owned_output(root: Path) -> tuple[Path, Path, Path]:
    profile_root = root / RHEL_PACKAGE_OWNED_DIRECTORY
    try:
        profile_root.mkdir(mode=0o700)
        packages = profile_root / "packages"
        evidence = profile_root / "evidence"
        packages.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
    except OSError as exc:
        fail(f"cannot create RHEL package-owned signing sub-bundle: {exc}")
    return profile_root, packages, evidence


def finalization_provenance_status(
    policy: dict[str, Any],
    policy_path: Path,
    day: dt.date,
    purpose: str,
    bootstrap_qualification: bool,
) -> str:
    if purpose != "qualification":
        fail("native signing bundle finalization cannot be used for publishing")
    if not bootstrap_qualification:
        if policy["status"] != "qualified":
            fail("native signature policy is not qualified")
        return QUALIFIED_PROVENANCE_STATUS

    if (
        policy["status"] != "foundation-not-qualified"
        or policy["publishing"] is not False
        or policy["deb"]["implementation"] != "implemented-not-qualified"
    ):
        fail("bootstrap qualification requires the exact non-publishing foundation policy")
    for family in ("rpm", "apk", "deb"):
        keys = policy[family]["trusted_keys"]
        if len(keys) != 1:
            fail(
                "bootstrap qualification requires exactly one reviewed trusted key "
                f"for {family}"
            )
        signature_gate.select_key(policy, family, keys[0]["id"], day)
        signature_gate.key_path(policy_path, keys[0])
    return BOOTSTRAP_PROVENANCE_STATUS


def signed_artifact_name(
    release: str,
    mode: str,
    run_id: int,
    run_attempt: int,
    release_sha: str,
) -> str:
    if mode not in {QUALIFIED_BUNDLE_MODE, BOOTSTRAP_BUNDLE_MODE}:
        fail("native signing artifact mode is invalid")
    positive_integer(run_id, "signing run ID")
    positive_integer(run_attempt, "signing run attempt")
    if run_attempt != 1:
        fail("native signing artifact requires attempt 1")
    if COMMIT_SHA.fullmatch(release_sha) is None:
        fail("native signing artifact SHA is malformed")
    package_names(release)
    version = release.removeprefix("v")
    if mode == BOOTSTRAP_BUNDLE_MODE:
        # Phase A is already immutable. Preserve its exact historical artifact
        # name so Phase B can consume the evidence that the ancestor produced.
        return (
            "syswarden-native-signed-packages-"
            f"{version}-{run_id}-{run_attempt}-{release_sha}"
        )
    return (
        "syswarden-native-signed-packages-qualified-"
        f"{version}-{run_id}-{run_attempt}-{release_sha}"
    )


def validate_policy_transition(
    foundation_policy_bytes: bytes,
    qualified_policy: dict[str, Any],
    expected_foundation_policy_sha256: str,
    day: dt.date,
) -> str:
    if SHA256.fullmatch(expected_foundation_policy_sha256) is None:
        fail("foundation policy SHA-256 is malformed")
    if expected_foundation_policy_sha256 != FOUNDATION_POLICY_SHA256:
        fail("foundation policy SHA-256 is not the immutable Phase A digest")
    actual_foundation_digest = sha256(foundation_policy_bytes)
    if actual_foundation_digest != expected_foundation_policy_sha256:
        fail("foundation policy digest differs from the exact approved digest")
    foundation_policy = signature_gate.decode_json(
        foundation_policy_bytes, "foundation signature policy"
    )
    signature_gate.validate_policy(foundation_policy, day)
    signature_gate.validate_policy(qualified_policy, day)
    if (
        foundation_policy["status"] != "foundation-not-qualified"
        or foundation_policy["publishing"] is not False
        or foundation_policy["deb"]["implementation"]
        != "implemented-not-qualified"
    ):
        fail("bootstrap policy is not the exact non-publishing foundation state")
    if (
        qualified_policy["status"] != "qualified"
        or qualified_policy["deb"]["implementation"] != "qualified"
    ):
        fail("current policy is not the exact qualified state")
    expected_qualified = copy.deepcopy(foundation_policy)
    expected_qualified["status"] = "qualified"
    expected_qualified["deb"]["implementation"] = "qualified"
    expected_qualified["publishing"] = qualified_policy["publishing"]
    if not exact_json_equal(qualified_policy, expected_qualified):
        fail("qualified policy changes fields outside the approved transition")
    return actual_foundation_digest


def validate_bootstrap_binding(
    *,
    bundle_root: Path,
    release: str,
    repository: str,
    foundation_release_sha: str,
    foundation_policy_bytes: bytes,
    foundation_policy_sha256: str,
    qualified_policy: dict[str, Any],
    qualified_release_sha: str,
    signing_run_id: int,
    artifact_id: int,
    artifact_name: str,
    artifact_size: int,
    artifact_digest: str,
    day: dt.date,
) -> dict[str, Any]:
    if REPOSITORY.fullmatch(repository) is None:
        fail("bootstrap repository identity is malformed")
    if COMMIT_SHA.fullmatch(foundation_release_sha) is None:
        fail("bootstrap release SHA is malformed")
    if foundation_release_sha == qualified_release_sha:
        fail("bootstrap and qualified release SHAs must be distinct")
    positive_integer(signing_run_id, "bootstrap signing run ID")
    positive_integer(artifact_id, "bootstrap signed artifact ID")
    positive_integer(artifact_size, "bootstrap signed artifact size")
    if GITHUB_DIGEST.fullmatch(artifact_digest) is None:
        fail("bootstrap signed artifact digest is malformed")
    expected_artifact_name = signed_artifact_name(
        release,
        BOOTSTRAP_BUNDLE_MODE,
        signing_run_id,
        1,
        foundation_release_sha,
    )
    if artifact_name != expected_artifact_name:
        fail("bootstrap signed artifact name is not canonical")
    if (
        repository != BOOTSTRAP_REPOSITORY
        or foundation_release_sha != BOOTSTRAP_RELEASE_SHA
        or signing_run_id != BOOTSTRAP_SIGNING_RUN_ID
        or artifact_id != BOOTSTRAP_SIGNED_ARTIFACT_ID
        or artifact_name != BOOTSTRAP_SIGNED_ARTIFACT_NAME
        or artifact_size != BOOTSTRAP_SIGNED_ARTIFACT_SIZE
        or artifact_digest != BOOTSTRAP_SIGNED_ARTIFACT_DIGEST
    ):
        fail("bootstrap evidence is not the exact reviewed Phase A result")
    policy_digest = validate_policy_transition(
        foundation_policy_bytes,
        qualified_policy,
        foundation_policy_sha256,
        day,
    )
    verify_bundle(
        bundle_root,
        release,
        foundation_release_sha,
        mode=BOOTSTRAP_BUNDLE_MODE,
    )
    provenance = load_json(
        bundle_root / "evidence" / "NATIVE_SIGNING_PROVENANCE.json",
        "bootstrap native signing provenance",
    )
    signing_run = provenance["signing_run"]
    if (
        provenance["repository"] != repository
        or provenance["policy_sha256"] != policy_digest
        or provenance["source"]["release_sha"] != foundation_release_sha
        or signing_run["id"] != signing_run_id
        or signing_run["attempt"] != 1
        or signing_run["workflow"]
        != ".github/workflows/native-package-signing.yml"
        or signing_run["workflow_sha"] != foundation_release_sha
    ):
        fail("bootstrap bundle differs from the exact prior signing run")
    return {
        "artifact": {
            "digest": artifact_digest,
            "id": artifact_id,
            "name": artifact_name,
            "size": artifact_size,
        },
        "policy_sha256": policy_digest,
        "profile": BOOTSTRAP_REFERENCE_PROFILE,
        "repository": repository,
        "release_sha": foundation_release_sha,
        "schema_version": 1,
        "signing_run": {
            "attempt": 1,
            "id": signing_run_id,
            "workflow": ".github/workflows/native-package-signing.yml",
            "workflow_sha": foundation_release_sha,
        },
    }


def validate_bootstrap_reference(
    reference: object,
    release: str,
    qualified_release_sha: str,
    repository: str,
) -> dict[str, Any]:
    checked = exact_keys(
        reference,
        {
            "artifact",
            "policy_sha256",
            "profile",
            "repository",
            "release_sha",
            "schema_version",
            "signing_run",
        },
        "bootstrap qualification reference",
    )
    if (
        type(checked["schema_version"]) is not int
        or checked["schema_version"] != 1
        or checked["profile"] != BOOTSTRAP_REFERENCE_PROFILE
        or not isinstance(checked["repository"], str)
        or REPOSITORY.fullmatch(checked["repository"]) is None
        or checked["repository"] != repository
        or checked["repository"] != BOOTSTRAP_REPOSITORY
        or not isinstance(checked["release_sha"], str)
        or COMMIT_SHA.fullmatch(checked["release_sha"]) is None
        or checked["release_sha"] == qualified_release_sha
        or checked["release_sha"] != BOOTSTRAP_RELEASE_SHA
        or not isinstance(checked["policy_sha256"], str)
        or SHA256.fullmatch(checked["policy_sha256"]) is None
        or checked["policy_sha256"] != FOUNDATION_POLICY_SHA256
    ):
        fail("bootstrap qualification reference identity is invalid")
    signing_run = exact_keys(
        checked["signing_run"],
        {"attempt", "id", "workflow", "workflow_sha"},
        "bootstrap signing run reference",
    )
    if (
        type(signing_run["attempt"]) is not int
        or signing_run["attempt"] != 1
        or signing_run["workflow"]
        != ".github/workflows/native-package-signing.yml"
        or signing_run["workflow_sha"] != checked["release_sha"]
        or signing_run["id"] != BOOTSTRAP_SIGNING_RUN_ID
    ):
        fail("bootstrap signing run reference is invalid")
    positive_integer(signing_run["id"], "bootstrap signing run ID")
    artifact = exact_keys(
        checked["artifact"],
        {"digest", "id", "name", "size"},
        "bootstrap signed artifact reference",
    )
    positive_integer(artifact["id"], "bootstrap signed artifact ID")
    positive_integer(artifact["size"], "bootstrap signed artifact size")
    if (
        not isinstance(artifact["digest"], str)
        or GITHUB_DIGEST.fullmatch(artifact["digest"]) is None
        or artifact["id"] != BOOTSTRAP_SIGNED_ARTIFACT_ID
        or artifact["size"] != BOOTSTRAP_SIGNED_ARTIFACT_SIZE
        or artifact["digest"] != BOOTSTRAP_SIGNED_ARTIFACT_DIGEST
        or artifact["name"] != BOOTSTRAP_SIGNED_ARTIFACT_NAME
        or artifact["name"]
        != signed_artifact_name(
            release,
            BOOTSTRAP_BUNDLE_MODE,
            signing_run["id"],
            1,
            checked["release_sha"],
        )
    ):
        fail("bootstrap signed artifact reference is invalid")
    return checked


def finalize(args: argparse.Namespace) -> None:
    release = args.release
    names = package_names(release)
    if COMMIT_SHA.fullmatch(args.release_sha) is None:
        fail("release SHA is malformed")
    if REPOSITORY.fullmatch(args.repository) is None:
        fail("repository identity is malformed")
    for label in (
        "unsigned_run_id",
        "unsigned_artifact_id",
        "rhel_unsigned_artifact_id",
        "signing_run_id",
        "signing_run_attempt",
    ):
        positive_integer(getattr(args, label), label.replace("_", " "))
    expected_artifact_name = f"syswarden-packages-{release.removeprefix('v')}"
    if args.unsigned_artifact_name != expected_artifact_name:
        fail("unsigned artifact name is not canonical")
    expected_rhel_artifact_name = (
        f"syswarden-rhel-package-owned-{release.removeprefix('v')}"
    )
    if args.rhel_unsigned_artifact_name != expected_rhel_artifact_name:
        fail("RHEL package-owned unsigned artifact name is not canonical")
    if GITHUB_DIGEST.fullmatch(args.unsigned_artifact_digest) is None:
        fail("unsigned GitHub artifact digest is malformed")
    if GITHUB_DIGEST.fullmatch(args.rhel_unsigned_artifact_digest) is None:
        fail("RHEL package-owned unsigned GitHub artifact digest is malformed")
    if COMMIT_SHA.fullmatch(args.signing_workflow_sha) is None:
        fail("signing workflow SHA is malformed")
    positive_integer(args.source_date_epoch, "source date epoch")
    if OCI_DIGEST.fullmatch(args.signer_image) is None:
        fail("APK signer image must be pinned by SHA-256 digest")
    bootstrap_fields = (
        "bootstrap_bundle",
        "bootstrap_release_sha",
        "bootstrap_policy",
        "bootstrap_policy_sha256",
        "bootstrap_signing_run_id",
        "bootstrap_signed_artifact_id",
        "bootstrap_signed_artifact_name",
        "bootstrap_signed_artifact_size",
        "bootstrap_signed_artifact_digest",
    )
    supplied_bootstrap_fields = {
        field for field in bootstrap_fields if getattr(args, field) is not None
    }
    if args.bootstrap_qualification:
        if supplied_bootstrap_fields:
            fail("bootstrap mode cannot claim a prior bootstrap qualification")
    elif supplied_bootstrap_fields != set(bootstrap_fields):
        fail("qualified mode requires one complete prior bootstrap qualification")

    unsigned = package_set(args.unsigned_packages, release, require_manifest=True)
    signed = package_set(args.signed_packages, release, require_manifest=True)
    rhel_unsigned = rhel_package_owned_set(
        args.rhel_unsigned_packages, release, require_manifest=True
    )
    rhel_signed = rhel_package_owned_set(
        args.rhel_signed_packages, release, require_manifest=True
    )
    if unsigned["deb"] != signed["deb"]:
        fail("DEB bytes changed while creating the detached signature")
    signature_name = deb_signature_name(release)
    if args.deb_signature.name != signature_name:
        fail("DEB detached signature filename is not canonical")
    deb_signature_data = regular_bytes(
        args.deb_signature,
        MAX_DEB_SIGNATURE_BYTES,
        "DEB detached signature",
    )
    if unsigned["rpm"] == signed["rpm"]:
        fail("RPM package bytes did not change during native signing")
    if rhel_unsigned == rhel_signed:
        fail("RHEL package-owned RPM bytes did not change during native signing")
    if rhel_unsigned == unsigned["rpm"] or rhel_signed == signed["rpm"]:
        fail("standard and RHEL package-owned RPM identities are not byte-distinct")
    if unsigned["apk"] == signed["apk"]:
        fail("APK package bytes did not change during native signing")
    if len(signed["apk"]) <= len(unsigned["apk"]):
        fail("signed APK is not larger than its unsigned input")
    apk_prefix = signed["apk"][: -len(unsigned["apk"])]
    if (
        len(apk_prefix) > MAX_APK_SIGNATURE_PREFIX_BYTES
        or not apk_prefix.startswith(b"\x1f\x8b")
        or not signed["apk"].endswith(unsigned["apk"])
    ):
        fail("APK signature did not preserve the exact unsigned package suffix")

    rpm_proof = load_json(args.rpm_proof, "RPM preservation proof")
    validate_rpm_proof(rpm_proof)
    rhel_rpm_proof = load_json(
        args.rhel_rpm_proof, "RHEL package-owned RPM preservation proof"
    )
    validate_rpm_proof(rhel_rpm_proof)
    policy_bytes = regular_bytes(args.policy, MAX_JSON_BYTES, "signature policy")
    policy_document = signature_gate.decode_json(
        policy_bytes, "signature policy"
    )
    day = signature_gate.parse_day(args.as_of, "signing date")
    signature_gate.validate_policy(policy_document, day)
    provenance_status = finalization_provenance_status(
        policy_document,
        args.policy,
        day,
        args.purpose,
        args.bootstrap_qualification,
    )
    if policy_document["apk"]["signer_image"] != args.signer_image:
        fail("APK signer image differs from the committed signature policy")
    policy_digest = sha256(policy_bytes)
    bootstrap_reference: dict[str, Any] | None = None
    if not args.bootstrap_qualification:
        if args.bootstrap_signing_run_id == args.signing_run_id:
            fail("bootstrap and qualified signing run IDs must be distinct")
        foundation_policy_bytes = regular_bytes(
            args.bootstrap_policy,
            MAX_JSON_BYTES,
            "bootstrap signature policy",
        )
        bootstrap_reference = validate_bootstrap_binding(
            bundle_root=args.bootstrap_bundle,
            release=release,
            repository=args.repository,
            foundation_release_sha=args.bootstrap_release_sha,
            foundation_policy_bytes=foundation_policy_bytes,
            foundation_policy_sha256=args.bootstrap_policy_sha256,
            qualified_policy=policy_document,
            qualified_release_sha=args.release_sha,
            signing_run_id=args.bootstrap_signing_run_id,
            artifact_id=args.bootstrap_signed_artifact_id,
            artifact_name=args.bootstrap_signed_artifact_name,
            artifact_size=args.bootstrap_signed_artifact_size,
            artifact_digest=args.bootstrap_signed_artifact_digest,
            day=day,
        )
    rpm_verification = load_json(args.rpm_verification, "RPM verification evidence")
    rhel_rpm_verification = load_json(
        args.rhel_rpm_verification,
        "RHEL package-owned RPM verification evidence",
    )
    apk_verification = load_json(args.apk_verification, "APK verification evidence")
    deb_verification = load_json(args.deb_verification, "DEB verification evidence")
    rpm_key = validate_verification(
        rpm_verification,
        "rpm",
        release,
        names["rpm"],
        signed["rpm"],
        policy_digest,
    )
    rhel_rpm_name = rhel_package_owned_name(release)
    rhel_rpm_key = validate_verification(
        rhel_rpm_verification,
        "rpm",
        release,
        rhel_rpm_name,
        rhel_signed,
        policy_digest,
    )
    apk_key = validate_verification(
        apk_verification,
        "apk",
        release,
        names["apk"],
        signed["apk"],
        policy_digest,
    )
    deb_key = validate_verification(
        deb_verification,
        "deb",
        release,
        names["deb"],
        signed["deb"],
        policy_digest,
        signature_name,
        deb_signature_data,
    )
    if any(
        verification["as_of"] != args.as_of
        for verification in (
            rpm_verification,
            rhel_rpm_verification,
            apk_verification,
            deb_verification,
        )
    ):
        fail("native verification dates differ from the signing date")
    for family, evidence_key in (
        ("rpm", rpm_key),
        ("apk", apk_key),
        ("deb", deb_key),
    ):
        selected = signature_gate.select_key(
            policy_document, family, evidence_key["id"], day
        )
        expected_key = {
            "fingerprint": selected["fingerprint"],
            "id": selected["id"],
            "public_key": selected["public_key"],
            "public_key_sha256": selected["public_key_sha256"],
        }
        if evidence_key != expected_key:
            fail(f"{family} verification key differs from the committed policy")
    if rhel_rpm_key != rpm_key:
        fail("RHEL package-owned RPM is not signed by the selected RPM family key")
    apk_signature_entry, apk_signature = validate_apk_signature_archive(
        apk_prefix, apk_key["public_key"], args.source_date_epoch
    )
    if regular_bytes(
        args.deb_signature,
        MAX_DEB_SIGNATURE_BYTES,
        "DEB detached signature",
    ) != deb_signature_data:
        fail("DEB detached signature changed during bundle finalization")
    if regular_bytes(args.policy, MAX_JSON_BYTES, "signature policy") != policy_bytes:
        fail("signature policy changed during bundle finalization")

    package_output, evidence_output = create_output_root(args.output)
    signed_named = {names[family]: data for family, data in signed.items()}
    signed_output = dict(signed_named)
    signed_output[signature_name] = deb_signature_data
    for name in sorted(signed_output):
        write_exclusive(package_output / name, signed_output[name], 0o600)
    signed_manifest = canonical_manifest(signed_output)
    write_exclusive(package_output / "SHA256SUMS.txt", signed_manifest)
    unsigned_named = {names[family]: data for family, data in unsigned.items()}
    write_exclusive(
        evidence_output / "UNSIGNED_SHA256SUMS.txt",
        canonical_manifest(unsigned_named),
    )
    write_json(evidence_output / "RPM_PAYLOAD_PROOF.json", rpm_proof)
    write_json(evidence_output / "RPM_NATIVE_VERIFICATION.json", rpm_verification)
    write_json(evidence_output / "APK_NATIVE_VERIFICATION.json", apk_verification)
    write_json(evidence_output / "DEB_NATIVE_VERIFICATION.json", deb_verification)
    provenance = {
        "apk_signature": {
            "exact_unsigned_suffix": True,
            "key": apk_key,
            "signature_entry": apk_signature_entry,
            "signature_prefix_sha256": sha256(apk_prefix),
            "signature_prefix_size": len(apk_prefix),
            "signature_sha256": sha256(apk_signature),
        },
        "deb_signature": {
            "bytes_unchanged": True,
            "detached": True,
            "key": deb_key,
            "signature": deb_verification["signature"],
        },
        "packages": {
            "signed": [file_record(name, signed_named[name]) for name in sorted(signed_named)],
            "unsigned": [file_record(name, unsigned_named[name]) for name in sorted(unsigned_named)],
        },
        "policy_sha256": policy_digest,
        "profile": SCHEMA_PROFILE,
        "public_release": False,
        "release_qualified": False,
        "repository": args.repository,
        "rpm_signature": {
            "immutable_header_preserved": True,
            "key": rpm_key,
            "payload_preserved": True,
        },
        "schema_version": 1,
        "signer_image": args.signer_image,
        "signing_run": {
            "attempt": args.signing_run_attempt,
            "id": args.signing_run_id,
            "workflow": ".github/workflows/native-package-signing.yml",
            "workflow_sha": args.signing_workflow_sha,
        },
        "source": {
            "release_sha": args.release_sha,
            "release_tag": release,
            "source_date_epoch": args.source_date_epoch,
            "unsigned_artifact_digest": args.unsigned_artifact_digest,
            "unsigned_artifact_id": args.unsigned_artifact_id,
            "unsigned_artifact_name": args.unsigned_artifact_name,
            "unsigned_package_run_id": args.unsigned_run_id,
        },
        "status": provenance_status,
    }
    if bootstrap_reference is not None:
        provenance["bootstrap_qualification"] = bootstrap_reference
    write_json(evidence_output / "NATIVE_SIGNING_PROVENANCE.json", provenance)

    (
        rhel_output,
        rhel_package_output,
        rhel_evidence_output,
    ) = create_rhel_package_owned_output(args.output)
    write_exclusive(rhel_package_output / rhel_rpm_name, rhel_signed, 0o600)
    write_exclusive(
        rhel_package_output / "SHA256SUMS.txt",
        canonical_manifest({rhel_rpm_name: rhel_signed}),
    )
    write_exclusive(
        rhel_evidence_output / "UNSIGNED_SHA256SUMS.txt",
        canonical_manifest({rhel_rpm_name: rhel_unsigned}),
    )
    write_json(rhel_evidence_output / "RPM_PAYLOAD_PROOF.json", rhel_rpm_proof)
    write_json(
        rhel_evidence_output / "RPM_NATIVE_VERIFICATION.json",
        rhel_rpm_verification,
    )
    rhel_provenance = {
        "package_role": "rhel-package-owned",
        "packages": {
            "signed": file_record(rhel_rpm_name, rhel_signed),
            "unsigned": file_record(rhel_rpm_name, rhel_unsigned),
        },
        "policy_sha256": policy_digest,
        "profile": RHEL_PACKAGE_OWNED_PROFILE,
        "public_release": False,
        "release_qualified": False,
        "repository": args.repository,
        "rpm_identity": {
            "architecture": "x86_64",
            "filename": rhel_rpm_name,
            "name": "syswarden",
            "release": "1.rhelpo",
            "version": release.removeprefix("v"),
        },
        "rpm_signature": {
            "immutable_header_preserved": True,
            "key": rhel_rpm_key,
            "payload_preserved": True,
        },
        "schema_version": 1,
        "signing_run": provenance["signing_run"],
        "source": {
            "release_sha": args.release_sha,
            "release_tag": release,
            "source_date_epoch": args.source_date_epoch,
            "unsigned_artifact_digest": args.rhel_unsigned_artifact_digest,
            "unsigned_artifact_id": args.rhel_unsigned_artifact_id,
            "unsigned_artifact_name": args.rhel_unsigned_artifact_name,
            "unsigned_package_run_id": args.unsigned_run_id,
        },
        "status": provenance_status,
        "updater_manifest_included": False,
    }
    if bootstrap_reference is not None:
        rhel_provenance["bootstrap_qualification"] = bootstrap_reference
    write_json(
        rhel_evidence_output / "SIGNING_PROVENANCE.json", rhel_provenance
    )
    rhel_members: dict[str, bytes] = {}
    for directory_name in ("packages", "evidence"):
        directory = rhel_output / directory_name
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            rhel_members[f"{directory_name}/{child.name}"] = regular_bytes(
                child,
                MAX_PACKAGE_BYTES if directory_name == "packages" else MAX_JSON_BYTES,
                "RHEL package-owned signing sub-bundle member",
            )
    write_exclusive(
        rhel_output / "SIGNED_ARTIFACT_SHA256SUMS.txt",
        canonical_manifest(rhel_members),
    )

    members: dict[str, bytes] = {}
    for child in sorted(args.output.rglob("*")):
        if child.is_dir():
            continue
        relative = child.relative_to(args.output).as_posix()
        if relative == "SIGNED_ARTIFACT_SHA256SUMS.txt":
            continue
        members[relative] = regular_bytes(
            child,
            MAX_PACKAGE_BYTES if "/packages/" in f"/{relative}" else MAX_JSON_BYTES,
            "signing bundle member",
        )
    write_exclusive(
        args.output / "SIGNED_ARTIFACT_SHA256SUMS.txt",
        canonical_manifest(members),
    )
    verify_bundle(
        args.output,
        release,
        args.release_sha,
        mode=(
            BOOTSTRAP_BUNDLE_MODE
            if args.bootstrap_qualification
            else QUALIFIED_BUNDLE_MODE
        ),
    )


def expected_bundle_files(release: str) -> tuple[set[str], set[str]]:
    names = package_names(release)
    return (
        set(names.values()) | {deb_signature_name(release), "SHA256SUMS.txt"},
        {
            "APK_NATIVE_VERIFICATION.json",
            "DEB_NATIVE_VERIFICATION.json",
            "NATIVE_SIGNING_PROVENANCE.json",
            "RPM_NATIVE_VERIFICATION.json",
            "RPM_PAYLOAD_PROOF.json",
            "UNSIGNED_SHA256SUMS.txt",
        },
    )


def verify_rhel_package_owned_bundle(
    root: Path,
    release: str,
    release_sha: str,
    standard_rpm_key: dict[str, Any],
    standard_provenance: dict[str, Any],
    standard_rpm: bytes,
) -> None:
    ensure_real_directory(root, "RHEL package-owned signing sub-bundle")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) != {"SIGNED_ARTIFACT_SHA256SUMS.txt", "evidence", "packages"}:
        fail("RHEL package-owned signing sub-bundle inventory is not exact")
    package_name = rhel_package_owned_name(release)
    package_files = {package_name, "SHA256SUMS.txt"}
    evidence_files = {
        "RPM_NATIVE_VERIFICATION.json",
        "RPM_PAYLOAD_PROOF.json",
        "SIGNING_PROVENANCE.json",
        "UNSIGNED_SHA256SUMS.txt",
    }
    exact_directory_files(entries["packages"], package_files, "RHEL package-owned signed packages")
    exact_directory_files(entries["evidence"], evidence_files, "RHEL package-owned signing evidence")
    signed = rhel_package_owned_set(entries["packages"], release, require_manifest=True)
    if signed == standard_rpm:
        fail("signed standard and RHEL package-owned RPMs are byte-identical")
    provenance = load_json(
        entries["evidence"] / "SIGNING_PROVENANCE.json",
        "RHEL package-owned signing provenance",
    )
    expected_provenance_keys = {
        "package_role",
        "packages",
        "policy_sha256",
        "profile",
        "public_release",
        "release_qualified",
        "repository",
        "rpm_identity",
        "rpm_signature",
        "schema_version",
        "signing_run",
        "source",
        "status",
        "updater_manifest_included",
    }
    if standard_provenance["status"] == QUALIFIED_PROVENANCE_STATUS:
        expected_provenance_keys.add("bootstrap_qualification")
    exact_keys(
        provenance,
        expected_provenance_keys,
        "RHEL package-owned signing provenance",
    )
    if (
        type(provenance["schema_version"]) is not int
        or provenance["schema_version"] != 1
        or provenance["profile"] != RHEL_PACKAGE_OWNED_PROFILE
        or provenance["status"] != standard_provenance["status"]
        or provenance["package_role"] != "rhel-package-owned"
        or provenance["public_release"] is not False
        or provenance["release_qualified"] is not False
        or provenance["updater_manifest_included"] is not False
        or provenance["policy_sha256"] != standard_provenance["policy_sha256"]
        or provenance["repository"] != standard_provenance["repository"]
        or not exact_json_equal(
            provenance["signing_run"], standard_provenance["signing_run"]
        )
    ):
        fail("RHEL package-owned signing provenance identity is invalid")
    if standard_provenance["status"] == QUALIFIED_PROVENANCE_STATUS:
        reference = validate_bootstrap_reference(
            provenance["bootstrap_qualification"],
            release,
            release_sha,
            standard_provenance["repository"],
        )
        if not exact_json_equal(
            reference, standard_provenance["bootstrap_qualification"]
        ):
            fail(
                "RHEL package-owned bootstrap reference differs from the standard bundle"
            )
    identity = exact_keys(
        provenance["rpm_identity"],
        {"architecture", "filename", "name", "release", "version"},
        "RHEL package-owned RPM identity",
    )
    if identity != {
        "architecture": "x86_64",
        "filename": package_name,
        "name": "syswarden",
        "release": "1.rhelpo",
        "version": release.removeprefix("v"),
    }:
        fail("RHEL package-owned RPM NEVRA is invalid")
    source = exact_keys(
        provenance["source"],
        {
            "release_sha",
            "release_tag",
            "source_date_epoch",
            "unsigned_artifact_digest",
            "unsigned_artifact_id",
            "unsigned_artifact_name",
            "unsigned_package_run_id",
        },
        "RHEL package-owned unsigned artifact binding",
    )
    if (
        source["release_sha"] != release_sha
        or source["release_tag"] != release
        or source["source_date_epoch"]
        != standard_provenance["source"]["source_date_epoch"]
        or source["unsigned_package_run_id"]
        != standard_provenance["source"]["unsigned_package_run_id"]
        or source["unsigned_artifact_name"]
        != f"syswarden-rhel-package-owned-{release.removeprefix('v')}"
        or not isinstance(source["unsigned_artifact_digest"], str)
        or GITHUB_DIGEST.fullmatch(source["unsigned_artifact_digest"]) is None
    ):
        fail("RHEL package-owned unsigned artifact binding is invalid")
    positive_integer(source["unsigned_artifact_id"], "RHEL package-owned artifact ID")
    packages = exact_keys(
        provenance["packages"],
        {"signed", "unsigned"},
        "RHEL package-owned package provenance",
    )
    signed_record = exact_keys(
        packages["signed"], {"name", "sha256", "size"}, "signed RHEL package-owned RPM"
    )
    unsigned_record = exact_keys(
        packages["unsigned"], {"name", "sha256", "size"}, "unsigned RHEL package-owned RPM"
    )
    if signed_record != file_record(package_name, signed):
        fail("RHEL package-owned provenance differs from signed RPM bytes")
    if (
        unsigned_record["name"] != package_name
        or not isinstance(unsigned_record["sha256"], str)
        or SHA256.fullmatch(unsigned_record["sha256"]) is None
        or type(unsigned_record["size"]) is not int
        or unsigned_record["size"] <= 0
        or unsigned_record["size"] > MAX_PACKAGE_BYTES
        or unsigned_record["sha256"] == signed_record["sha256"]
    ):
        fail("RHEL package-owned unsigned RPM provenance is invalid")
    unsigned_manifest = manifest_records(
        entries["evidence"] / "UNSIGNED_SHA256SUMS.txt",
        "RHEL package-owned unsigned checksum manifest",
    )
    if unsigned_manifest != {package_name: unsigned_record["sha256"]}:
        fail("RHEL package-owned unsigned checksum manifest is inconsistent")
    proof = load_json(
        entries["evidence"] / "RPM_PAYLOAD_PROOF.json",
        "RHEL package-owned RPM preservation proof",
    )
    validate_rpm_proof(proof)
    verification = load_json(
        entries["evidence"] / "RPM_NATIVE_VERIFICATION.json",
        "RHEL package-owned RPM native verification",
    )
    key = validate_verification(
        verification,
        "rpm",
        release,
        package_name,
        signed,
        provenance["policy_sha256"],
    )
    rpm_signature = exact_keys(
        provenance["rpm_signature"],
        {"immutable_header_preserved", "key", "payload_preserved"},
        "RHEL package-owned RPM signature provenance",
    )
    if (
        rpm_signature["immutable_header_preserved"] is not True
        or rpm_signature["payload_preserved"] is not True
        or rpm_signature["key"] != key
        or key != standard_rpm_key
    ):
        fail("RHEL package-owned RPM signature provenance is inconsistent")
    members: dict[str, bytes] = {}
    for directory_name, filenames in (
        ("packages", package_files),
        ("evidence", evidence_files),
    ):
        for name in sorted(filenames):
            members[f"{directory_name}/{name}"] = regular_bytes(
                root / directory_name / name,
                MAX_PACKAGE_BYTES if directory_name == "packages" else MAX_JSON_BYTES,
                "RHEL package-owned signing sub-bundle member",
            )
    parse_manifest(
        root / "SIGNED_ARTIFACT_SHA256SUMS.txt",
        members,
        "RHEL package-owned signed artifact seal",
    )


def verify_bundle(
    root: Path,
    release: str,
    release_sha: str,
    mode: str = QUALIFIED_BUNDLE_MODE,
) -> None:
    if COMMIT_SHA.fullmatch(release_sha) is None:
        fail("expected release SHA is malformed")
    if mode not in {QUALIFIED_BUNDLE_MODE, BOOTSTRAP_BUNDLE_MODE}:
        fail("signed bundle verification mode is invalid")
    ensure_real_directory(root, "signed bundle")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) != {
        "SIGNED_ARTIFACT_SHA256SUMS.txt",
        "evidence",
        "packages",
        RHEL_PACKAGE_OWNED_DIRECTORY,
    }:
        fail("signed bundle top-level inventory is not exact")
    if not entries["packages"].is_dir() or entries["packages"].is_symlink():
        fail("signed package directory is unsafe")
    if not entries["evidence"].is_dir() or entries["evidence"].is_symlink():
        fail("signing evidence directory is unsafe")
    if (
        not entries[RHEL_PACKAGE_OWNED_DIRECTORY].is_dir()
        or entries[RHEL_PACKAGE_OWNED_DIRECTORY].is_symlink()
    ):
        fail("RHEL package-owned signing sub-bundle is unsafe")
    package_files, evidence_files = expected_bundle_files(release)
    exact_directory_files(entries["packages"], package_files, "signed package directory")
    exact_directory_files(entries["evidence"], evidence_files, "signing evidence directory")
    signed = package_set(
        entries["packages"],
        release,
        require_manifest=True,
        include_deb_signature=True,
    )
    names = package_names(release)
    signature_name = deb_signature_name(release)
    deb_signature_data = regular_bytes(
        entries["packages"] / signature_name,
        MAX_DEB_SIGNATURE_BYTES,
        "DEB detached signature",
    )
    signature_gate.validate_detached_signature_container(deb_signature_data)
    provenance = load_json(
        entries["evidence"] / "NATIVE_SIGNING_PROVENANCE.json",
        "native signing provenance",
    )
    expected_provenance_keys = {
        "apk_signature",
        "deb_signature",
        "packages",
        "policy_sha256",
        "profile",
        "public_release",
        "release_qualified",
        "repository",
        "rpm_signature",
        "schema_version",
        "signer_image",
        "signing_run",
        "source",
        "status",
    }
    expected_status = BOOTSTRAP_PROVENANCE_STATUS
    if mode == QUALIFIED_BUNDLE_MODE:
        expected_provenance_keys.add("bootstrap_qualification")
        expected_status = QUALIFIED_PROVENANCE_STATUS
    exact_keys(
        provenance,
        expected_provenance_keys,
        "native signing provenance",
    )
    if (
        type(provenance["schema_version"]) is not int
        or provenance["schema_version"] != 1
        or provenance["profile"] != SCHEMA_PROFILE
        or provenance["status"] != expected_status
        or provenance["release_qualified"] is not False
        or provenance["public_release"] is not False
    ):
        fail("native signing provenance identity is invalid")
    if mode == QUALIFIED_BUNDLE_MODE:
        validate_bootstrap_reference(
            provenance["bootstrap_qualification"],
            release,
            release_sha,
            provenance["repository"],
        )
    if (
        not isinstance(provenance["policy_sha256"], str)
        or SHA256.fullmatch(provenance["policy_sha256"]) is None
        or not isinstance(provenance["repository"], str)
        or REPOSITORY.fullmatch(provenance["repository"]) is None
        or not isinstance(provenance["signer_image"], str)
        or OCI_DIGEST.fullmatch(provenance["signer_image"]) is None
    ):
        fail("native signing provenance trust binding is malformed")
    source = exact_keys(
        provenance["source"],
        {
            "release_sha",
            "release_tag",
            "source_date_epoch",
            "unsigned_artifact_digest",
            "unsigned_artifact_id",
            "unsigned_artifact_name",
            "unsigned_package_run_id",
        },
        "unsigned artifact source binding",
    )
    expected_unsigned_name = f"syswarden-packages-{release.removeprefix('v')}"
    if (
        source["release_sha"] != release_sha
        or source["release_tag"] != release
        or source["unsigned_artifact_name"] != expected_unsigned_name
        or not isinstance(source["unsigned_artifact_digest"], str)
        or GITHUB_DIGEST.fullmatch(source["unsigned_artifact_digest"]) is None
    ):
        fail("unsigned artifact source binding is invalid")
    positive_integer(source["unsigned_artifact_id"], "unsigned artifact ID")
    positive_integer(source["unsigned_package_run_id"], "unsigned package run ID")
    source_date_epoch = positive_integer(source["source_date_epoch"], "source date epoch")
    signing_run = exact_keys(
        provenance["signing_run"],
        {"attempt", "id", "workflow", "workflow_sha"},
        "signing run binding",
    )
    if (
        type(signing_run["attempt"]) is not int
        or signing_run["workflow"]
        != ".github/workflows/native-package-signing.yml"
        or signing_run["workflow_sha"] != release_sha
        or signing_run["attempt"] != 1
    ):
        fail("signing run binding is invalid")
    positive_integer(signing_run["id"], "signing run ID")
    signed_records_by_name = {names[family]: signed[family] for family in signed}
    expected_signed_records = [
        file_record(name, signed_records_by_name[name])
        for name in sorted(signed_records_by_name)
    ]
    packages_evidence = exact_keys(
        provenance["packages"], {"signed", "unsigned"}, "package provenance"
    )
    if packages_evidence["signed"] != expected_signed_records:
        fail("native signing provenance differs from signed package bytes")
    unsigned_records = packages_evidence["unsigned"]
    if not isinstance(unsigned_records, list) or len(unsigned_records) != 3:
        fail("unsigned package provenance is incomplete")
    unsigned_by_name: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(unsigned_records):
        checked = exact_keys(
            record, {"name", "sha256", "size"}, f"unsigned package record {index}"
        )
        if (
            checked["name"] not in set(names.values())
            or checked["name"] in unsigned_by_name
            or not isinstance(checked["sha256"], str)
            or SHA256.fullmatch(checked["sha256"]) is None
            or type(checked["size"]) is not int
            or checked["size"] <= 0
            or checked["size"] > MAX_PACKAGE_BYTES
        ):
            fail("unsigned package provenance record is malformed")
        unsigned_by_name[checked["name"]] = checked
    if set(unsigned_by_name) != set(names.values()):
        fail("unsigned package provenance inventory is not exact")
    unsigned_manifest = manifest_records(
        entries["evidence"] / "UNSIGNED_SHA256SUMS.txt",
        "unsigned package checksum manifest",
    )
    if unsigned_manifest != {
        name: record["sha256"] for name, record in unsigned_by_name.items()
    }:
        fail("unsigned checksum manifest differs from package provenance")

    deb_signature = exact_keys(
        provenance["deb_signature"],
        {
            "bytes_unchanged",
            "detached",
            "key",
            "signature",
        },
        "DEB signature provenance",
    )
    deb_unsigned = unsigned_by_name[names["deb"]]
    if (
        deb_signature["bytes_unchanged"] is not True
        or deb_signature["detached"] is not True
        or deb_unsigned["sha256"] != sha256(signed["deb"])
        or deb_unsigned["size"] != len(signed["deb"])
    ):
        fail("DEB detached-signature provenance is inconsistent")
    deb_verification = load_json(
        entries["evidence"] / "DEB_NATIVE_VERIFICATION.json",
        "DEB native verification",
    )
    deb_key = validate_verification(
        deb_verification,
        "deb",
        release,
        names["deb"],
        signed["deb"],
        provenance["policy_sha256"],
        signature_name,
        deb_signature_data,
    )
    if (
        deb_signature["key"] != deb_key
        or deb_signature["signature"] != deb_verification["signature"]
    ):
        fail("DEB provenance differs from detached-signature verification")

    rpm_proof = load_json(
        entries["evidence"] / "RPM_PAYLOAD_PROOF.json", "RPM preservation proof"
    )
    validate_rpm_proof(rpm_proof)
    rpm_signature = exact_keys(
        provenance["rpm_signature"],
        {"immutable_header_preserved", "key", "payload_preserved"},
        "RPM signature provenance",
    )
    if (
        rpm_signature["immutable_header_preserved"] is not True
        or rpm_signature["payload_preserved"] is not True
        or sha256(signed["rpm"]) == unsigned_by_name[names["rpm"]]["sha256"]
    ):
        fail("RPM signature transformation is not proven")
    rpm_verification = load_json(
        entries["evidence"] / "RPM_NATIVE_VERIFICATION.json",
        "RPM native verification",
    )
    rpm_key = validate_verification(
        rpm_verification,
        "rpm",
        release,
        names["rpm"],
        signed["rpm"],
        provenance["policy_sha256"],
    )
    if rpm_signature["key"] != rpm_key:
        fail("RPM provenance key differs from native verification")

    apk_signature = exact_keys(
        provenance["apk_signature"],
        {
            "exact_unsigned_suffix",
            "key",
            "signature_entry",
            "signature_prefix_sha256",
            "signature_prefix_size",
            "signature_sha256",
        },
        "APK signature provenance",
    )
    apk_unsigned = unsigned_by_name[names["apk"]]
    prefix_size = apk_signature["signature_prefix_size"]
    if (
        apk_signature["exact_unsigned_suffix"] is not True
        or type(prefix_size) is not int
        or prefix_size <= 0
        or prefix_size > MAX_APK_SIGNATURE_PREFIX_BYTES
        or len(signed["apk"]) != apk_unsigned["size"] + prefix_size
        or not isinstance(apk_signature["signature_prefix_sha256"], str)
        or SHA256.fullmatch(apk_signature["signature_prefix_sha256"]) is None
    ):
        fail("APK signature transformation metadata is invalid")
    apk_prefix = signed["apk"][:prefix_size]
    apk_suffix = signed["apk"][prefix_size:]
    apk_signature_entry, apk_signature_bytes = validate_apk_signature_archive(
        apk_prefix,
        exact_keys(
            apk_signature["key"],
            {"fingerprint", "id", "public_key", "public_key_sha256"},
            "APK provenance key",
        )["public_key"],
        source_date_epoch,
    )
    if (
        not apk_prefix.startswith(b"\x1f\x8b")
        or sha256(apk_prefix) != apk_signature["signature_prefix_sha256"]
        or sha256(apk_suffix) != apk_unsigned["sha256"]
        or len(apk_suffix) != apk_unsigned["size"]
        or apk_signature["signature_entry"] != apk_signature_entry
        or not isinstance(apk_signature["signature_sha256"], str)
        or SHA256.fullmatch(apk_signature["signature_sha256"]) is None
        or apk_signature["signature_sha256"] != sha256(apk_signature_bytes)
    ):
        fail("signed APK does not contain the attested exact unsigned suffix")
    apk_verification = load_json(
        entries["evidence"] / "APK_NATIVE_VERIFICATION.json",
        "APK native verification",
    )
    apk_key = validate_verification(
        apk_verification,
        "apk",
        release,
        names["apk"],
        signed["apk"],
        provenance["policy_sha256"],
    )
    if apk_signature["key"] != apk_key:
        fail("APK provenance key differs from native verification")
    if not (
        rpm_verification["as_of"]
        == apk_verification["as_of"]
        == deb_verification["as_of"]
    ):
        fail("native verification dates are inconsistent")

    verify_rhel_package_owned_bundle(
        entries[RHEL_PACKAGE_OWNED_DIRECTORY],
        release,
        release_sha,
        rpm_key,
        provenance,
        signed["rpm"],
    )

    members: dict[str, bytes] = {}
    for child in sorted(root.rglob("*")):
        if child.is_dir():
            continue
        relative = child.relative_to(root).as_posix()
        if relative == "SIGNED_ARTIFACT_SHA256SUMS.txt":
            continue
        members[relative] = regular_bytes(
            child,
            MAX_PACKAGE_BYTES if "/packages/" in f"/{relative}" else MAX_JSON_BYTES,
            "signed bundle member",
        )
    parse_manifest(
        root / "SIGNED_ARTIFACT_SHA256SUMS.txt",
        members,
        "signed artifact seal",
    )
def inventory_command(args: argparse.Namespace) -> None:
    document = build_inventory(args.packages, args.release)
    write_json(args.output, document)


def rhel_inventory_command(args: argparse.Namespace) -> None:
    document = build_rhel_package_owned_inventory(args.packages, args.release)
    write_json(args.output, document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("--packages", required=True, type=Path)
    inventory.add_argument("--release", required=True)
    inventory.add_argument("--output", required=True, type=Path)

    rhel_inventory = subparsers.add_parser("rhel-package-owned-inventory")
    rhel_inventory.add_argument("--packages", required=True, type=Path)
    rhel_inventory.add_argument("--release", required=True)
    rhel_inventory.add_argument("--output", required=True, type=Path)

    apk_control = subparsers.add_parser("apk-control")
    apk_control.add_argument("--unsigned-package", required=True, type=Path)
    apk_control.add_argument("--output", required=True, type=Path)

    apk_assemble = subparsers.add_parser("apk-assemble")
    apk_assemble.add_argument("--unsigned-package", required=True, type=Path)
    apk_assemble.add_argument("--signed-control", required=True, type=Path)
    apk_assemble.add_argument("--public-key-name", required=True)
    apk_assemble.add_argument("--source-date-epoch", required=True, type=int)
    apk_assemble.add_argument("--output", required=True, type=Path)

    final = subparsers.add_parser("finalize")
    final.add_argument("--release", required=True)
    final.add_argument("--release-sha", required=True)
    final.add_argument("--repository", required=True)
    final.add_argument("--unsigned-packages", required=True, type=Path)
    final.add_argument("--signed-packages", required=True, type=Path)
    final.add_argument("--rhel-unsigned-packages", required=True, type=Path)
    final.add_argument("--rhel-signed-packages", required=True, type=Path)
    final.add_argument("--unsigned-run-id", required=True, type=int)
    final.add_argument("--unsigned-artifact-id", required=True, type=int)
    final.add_argument("--unsigned-artifact-name", required=True)
    final.add_argument("--unsigned-artifact-digest", required=True)
    final.add_argument("--rhel-unsigned-artifact-id", required=True, type=int)
    final.add_argument("--rhel-unsigned-artifact-name", required=True)
    final.add_argument("--rhel-unsigned-artifact-digest", required=True)
    final.add_argument("--signing-run-id", required=True, type=int)
    final.add_argument("--signing-run-attempt", required=True, type=int)
    final.add_argument("--signing-workflow-sha", required=True)
    final.add_argument("--source-date-epoch", required=True, type=int)
    final.add_argument("--signer-image", required=True)
    final.add_argument("--policy", required=True, type=Path)
    final.add_argument("--as-of", required=True)
    final.add_argument(
        "--purpose", choices=("qualification", "publishing"), default="qualification"
    )
    final.add_argument("--bootstrap-qualification", action="store_true")
    final.add_argument("--bootstrap-bundle", type=Path)
    final.add_argument("--bootstrap-release-sha")
    final.add_argument("--bootstrap-policy", type=Path)
    final.add_argument("--bootstrap-policy-sha256")
    final.add_argument("--bootstrap-signing-run-id", type=int)
    final.add_argument("--bootstrap-signed-artifact-id", type=int)
    final.add_argument("--bootstrap-signed-artifact-name")
    final.add_argument("--bootstrap-signed-artifact-size", type=int)
    final.add_argument("--bootstrap-signed-artifact-digest")
    final.add_argument("--rpm-proof", required=True, type=Path)
    final.add_argument("--rpm-verification", required=True, type=Path)
    final.add_argument("--rhel-rpm-proof", required=True, type=Path)
    final.add_argument("--rhel-rpm-verification", required=True, type=Path)
    final.add_argument("--apk-verification", required=True, type=Path)
    final.add_argument("--deb-signature", required=True, type=Path)
    final.add_argument("--deb-verification", required=True, type=Path)
    final.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True, type=Path)
    verify.add_argument("--release", required=True)
    verify.add_argument("--release-sha", required=True)
    verify.add_argument(
        "--mode",
        choices=(QUALIFIED_BUNDLE_MODE, BOOTSTRAP_BUNDLE_MODE),
        default=QUALIFIED_BUNDLE_MODE,
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "inventory":
            inventory_command(args)
        elif args.command == "rhel-package-owned-inventory":
            rhel_inventory_command(args)
        elif args.command == "apk-control":
            apk_control_command(args)
        elif args.command == "apk-assemble":
            apk_assemble_command(args)
        elif args.command == "finalize":
            finalize(args)
        else:
            verify_bundle(args.bundle, args.release, args.release_sha, args.mode)
    except (SigningBundleError, signature_gate.SignatureGateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
