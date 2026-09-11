#!/usr/bin/env python3
"""Build and validate candidate-bound native capability evidence for v4.10.0."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Sequence

try:
    from scripts.ci import native_package_signing_bundle as signing_bundle
except ModuleNotFoundError:
    import native_package_signing_bundle as signing_bundle


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "scripts/ci/native_capability_contract_v4.10.0.json"
DEFAULT_SIGNATURE_CATALOG = ROOT / "src/core/syswarden-core/signatures.json"
CONTRACT_SHA256 = "3dba153c60517d1d5bba5d7bd2d89626f0f6748adad6a18428dfe066aded1d42"
CAMPAIGN_SCHEMA = "syswarden-native-capability-campaign/v1"
EVIDENCE_SCHEMA = "syswarden-native-capability-evidence/v1"
VERDICT_SCHEMA = "syswarden-native-capability-verdict/v1"
AGGREGATE_SCHEMA = "syswarden-native-capability-aggregate/v1"
SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OPENPGP_FINGERPRINT_PATTERN = re.compile(r"^[0-9A-F]{40}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
UTC_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ASN_PATTERN = re.compile(r"^AS[1-9][0-9]{0,9}$")
COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")
RISK_BASE = {
    "exploit": 50,
    "brute_force": 20,
    "reconnaissance": 20,
    "denial_of_service": 40,
    "abuse": 10,
}
OUTPUT_MAXIMUM_BYTES = 1024 * 1024


class NativeCapabilityEvidenceError(ValueError):
    """Raised when native capability evidence is unsafe or unsupported."""


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeCapabilityEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _open_child_directory(parent_descriptor: int, component: str, label: str) -> int:
    if not component or component in {".", ".."} or "/" in component:
        raise NativeCapabilityEvidenceError(f"{label} contains an unsafe directory component")
    try:
        before = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"cannot inspect {label}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise NativeCapabilityEvidenceError(f"{label} must be a real directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(component, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"cannot safely open {label}") from exc
    try:
        opened = os.fstat(descriptor)
        after = os.stat(component, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(before) != _directory_identity(opened)
            or _directory_identity(opened) != _directory_identity(after)
        ):
            raise NativeCapabilityEvidenceError(f"{label} changed while opening")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_real_directory(path: Path, label: str) -> tuple[int, Path, tuple[int, int]]:
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise NativeCapabilityEvidenceError(f"{label} path is invalid") from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"cannot open {label}") from exc
    try:
        for component in absolute.parts[1:]:
            next_descriptor = _open_child_directory(descriptor, component, label)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise NativeCapabilityEvidenceError(f"{label} must be a real directory")
        return descriptor, absolute, _directory_identity(info)
    except Exception:
        os.close(descriptor)
        raise


def _verify_directory_binding(path: Path, expected: tuple[int, int], label: str) -> None:
    descriptor, _, actual = _open_real_directory(path, label)
    try:
        if actual != expected:
            raise NativeCapabilityEvidenceError(f"{label} changed during operation")
    finally:
        os.close(descriptor)


def _verify_child_directory_binding(
    parent_descriptor: int,
    component: str,
    expected: tuple[int, int],
    label: str,
) -> None:
    try:
        actual = os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"{label} changed during operation") from exc
    if not stat.S_ISDIR(actual.st_mode) or _directory_identity(actual) != expected:
        raise NativeCapabilityEvidenceError(f"{label} changed during operation")


def _read_regular_bytes_at(
    parent_descriptor: int,
    name: str,
    display: str,
    maximum: int,
) -> bytes:
    if type(maximum) is not int or maximum <= 0:
        raise NativeCapabilityEvidenceError("input size bound is invalid")
    if not name or name in {".", ".."} or "/" in name:
        raise NativeCapabilityEvidenceError(f"input path is unsafe: {display}")
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"cannot inspect input: {display}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise NativeCapabilityEvidenceError(f"input must be one regular file: {display}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise NativeCapabilityEvidenceError(f"input size is outside bounds: {display}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise NativeCapabilityEvidenceError(f"cannot safely open input: {display}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _file_identity(opened) != _file_identity(before)
        ):
            raise NativeCapabilityEvidenceError(f"input changed while opening: {display}")
        wire = bytearray()
        while len(wire) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(wire)))
            if not chunk:
                break
            wire.extend(chunk)
        after = os.fstat(descriptor)
        try:
            named_after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise NativeCapabilityEvidenceError(
                f"input namespace changed while reading: {display}"
            ) from exc
    finally:
        os.close(descriptor)
    if (
        len(wire) != before.st_size
        or len(wire) > maximum
        or _file_identity(after) != _file_identity(opened)
        or _file_identity(named_after) != _file_identity(opened)
    ):
        raise NativeCapabilityEvidenceError(f"input changed while reading: {display}")
    return bytes(wire)


def _read_regular_bytes(path: Path, maximum: int) -> bytes:
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise NativeCapabilityEvidenceError("input path is invalid") from exc
    parent_descriptor, parent, parent_identity = _open_real_directory(
        absolute.parent, "input parent"
    )
    try:
        wire = _read_regular_bytes_at(
            parent_descriptor, absolute.name, str(path), maximum
        )
        _verify_directory_binding(parent, parent_identity, "input parent")
        return wire
    finally:
        os.close(parent_descriptor)


def _decode_json(wire: bytes, label: str) -> Any:
    def reject_constant(value: str) -> None:
        raise NativeCapabilityEvidenceError(
            f"invalid non-standard JSON constant in {label}: {value}"
        )

    try:
        return json.loads(
            wire,
            object_pairs_hook=_duplicates_rejected,
            parse_constant=reject_constant,
        )
    except NativeCapabilityEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise NativeCapabilityEvidenceError(f"invalid JSON in {label}: {exc}") from exc


def _load_json(path: Path, maximum: int, label: str) -> tuple[Any, bytes]:
    wire = _read_regular_bytes(path, maximum)
    return _decode_json(wire, label), wire


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeCapabilityEvidenceError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unexpected = sorted(actual - keys)
        raise NativeCapabilityEvidenceError(
            f"{label} keys are not exact; missing={missing}, unexpected={unexpected}"
        )
    return value


def _positive_integer(value: object, label: str, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        raise NativeCapabilityEvidenceError(f"{label} must be a bounded positive integer")
    return value


def _nonnegative_integer(value: object, label: str, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise NativeCapabilityEvidenceError(f"{label} must be a bounded non-negative integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise NativeCapabilityEvidenceError(f"{label} must be a boolean")
    return value


def _bounded_text(value: object, label: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise NativeCapabilityEvidenceError(f"{label} must be a string")
    if (not allow_empty and not value) or len(value.encode("utf-8")) > maximum:
        raise NativeCapabilityEvidenceError(f"{label} is outside text bounds")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise NativeCapabilityEvidenceError(f"{label} contains control characters")
    return value


def _canonical_timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or UTC_PATTERN.fullmatch(value) is None:
        raise NativeCapabilityEvidenceError(f"{label} must be canonical UTC seconds")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise NativeCapabilityEvidenceError(f"{label} is not a valid timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise NativeCapabilityEvidenceError(f"{label} is not canonical")
    return parsed


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise NativeCapabilityEvidenceError(f"{label} must be a canonical SHA-256")
    return value


def _candidate_commit(value: object, label: str = "candidate commit") -> str:
    if not isinstance(value, str) or SHA1_PATTERN.fullmatch(value) is None:
        raise NativeCapabilityEvidenceError(f"{label} is not canonical")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise NativeCapabilityEvidenceError(f"{label} is not canonical")
    return value


def _evidence_reference(value: object, label: str, maximum: int) -> str:
    text = _bounded_text(value, label, maximum)
    parts = Path(text).parts
    if (
        REFERENCE_PATTERN.fullmatch(text) is None
        or text.startswith("/")
        or ":" in text
        or ".." in parts
        or "." in parts
        or "//" in text
    ):
        raise NativeCapabilityEvidenceError(f"{label} is not a safe evidence reference")
    return text


def _validate_artifact(
    artifact_root_descriptor: int,
    reference: str,
    expected_sha256: str,
    maximum: int,
) -> None:
    relative = Path(reference)
    descriptors = [os.dup(artifact_root_descriptor)]
    bindings: list[tuple[int, str, tuple[int, int]]] = []
    try:
        for component in relative.parts[:-1]:
            next_descriptor = _open_child_directory(
                descriptors[-1],
                component,
                f"evidence artifact directory for {reference}",
            )
            bindings.append(
                (
                    descriptors[-1],
                    component,
                    _directory_identity(os.fstat(next_descriptor)),
                )
            )
            descriptors.append(next_descriptor)
        wire = _read_regular_bytes_at(
            descriptors[-1],
            relative.name,
            reference,
            maximum,
        )
        for parent_descriptor, component, identity in bindings:
            _verify_child_directory_binding(
                parent_descriptor,
                component,
                identity,
                f"evidence artifact directory for {reference}",
            )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    if hashlib.sha256(wire).hexdigest() != expected_sha256:
        raise NativeCapabilityEvidenceError(
            f"evidence artifact SHA-256 mismatch: {reference}"
        )


def _artifact_bindings(evidence: dict[str, Any]) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    for capability_id, capability in evidence["capabilities"].items():
        if capability_id == "extended_controls":
            for control in capability["controls"]:
                bindings.append((control["evidence_ref"], control["evidence_sha256"]))
        else:
            bindings.append((capability["evidence_ref"], capability["evidence_sha256"]))
    for lifecycle in evidence["lifecycle"]:
        bindings.append((lifecycle["evidence_ref"], lifecycle["evidence_sha256"]))
        if "trigger_evidence_ref" in lifecycle:
            bindings.append(
                (
                    lifecycle["trigger_evidence_ref"],
                    lifecycle["trigger_evidence_sha256"],
                )
            )
    return bindings


def _artifact_binding_sha256(evidence: dict[str, Any]) -> str:
    bindings = _artifact_bindings(evidence)
    canonical = json.dumps(
        sorted(
            ({"reference": reference, "sha256": digest} for reference, digest in bindings),
            key=lambda item: item["reference"],
        ),
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_evidence_artifacts(
    evidence: dict[str, Any], artifact_root: Path, maximum: int
) -> None:
    bindings = _artifact_bindings(evidence)
    references = [reference for reference, _ in bindings]
    if len(references) != len(set(references)):
        raise NativeCapabilityEvidenceError("evidence artifact references are duplicated")
    if (
        not isinstance(artifact_root, Path)
        or not artifact_root.is_absolute()
        or Path(os.path.normpath(artifact_root)) != artifact_root
    ):
        raise NativeCapabilityEvidenceError(
            "evidence artifact root must be absolute, canonical, and symlink-free"
        )
    root_descriptor, opened_root, root_identity = _open_real_directory(
        artifact_root, "evidence artifact root"
    )
    try:
        if opened_root != artifact_root:
            raise NativeCapabilityEvidenceError(
                "evidence artifact root must be absolute, canonical, and symlink-free"
            )
        for reference, digest in bindings:
            _validate_artifact(root_descriptor, reference, digest, maximum)
        _verify_directory_binding(
            artifact_root, root_identity, "evidence artifact root"
        )
    finally:
        os.close(root_descriptor)


def _read_bundle_member_at(
    root_descriptor: int, reference: str, maximum: int, label: str
) -> bytes:
    relative = Path(reference)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise NativeCapabilityEvidenceError(f"{label} reference is unsafe")
    descriptors = [os.dup(root_descriptor)]
    bindings: list[tuple[int, str, tuple[int, int]]] = []
    try:
        for component in relative.parts[:-1]:
            next_descriptor = _open_child_directory(
                descriptors[-1], component, f"{label} directory"
            )
            bindings.append(
                (
                    descriptors[-1],
                    component,
                    _directory_identity(os.fstat(next_descriptor)),
                )
            )
            descriptors.append(next_descriptor)
        wire = _read_regular_bytes_at(
            descriptors[-1], relative.name, reference, maximum
        )
        for parent_descriptor, component, identity in bindings:
            _verify_child_directory_binding(
                parent_descriptor,
                component,
                identity,
                f"{label} directory",
            )
        return wire
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _manifest_records_wire(wire: bytes, label: str) -> dict[str, str]:
    try:
        text = wire.decode("ascii")
    except UnicodeDecodeError as exc:
        raise NativeCapabilityEvidenceError(f"{label} must be ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise NativeCapabilityEvidenceError(f"{label} is not canonical")
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*)",
            line,
        )
        if match is None or match.group(2) in records:
            raise NativeCapabilityEvidenceError(
                f"{label} contains a malformed or duplicate record"
            )
        records[match.group(2)] = match.group(1)
    if not records:
        raise NativeCapabilityEvidenceError(f"{label} is empty")
    return records


def _sealed_member(
    records: dict[str, str], reference: str, wire: bytes, label: str
) -> None:
    if records.get(reference) != hashlib.sha256(wire).hexdigest():
        raise NativeCapabilityEvidenceError(f"{label} is not bound by its signed seal")


def _package_record(raw: object, label: str) -> dict[str, Any]:
    record = _exact_mapping(raw, {"name", "sha256", "size"}, label)
    _bounded_text(record["name"], f"{label}.name", 256)
    _sha256(record["sha256"], f"{label}.sha256")
    _positive_integer(record["size"], f"{label}.size", 256 * 1024 * 1024)
    return record


def _signing_key(raw: object, family: str, label: str) -> dict[str, Any]:
    key = _exact_mapping(
        raw,
        {"fingerprint", "id", "public_key", "public_key_sha256"},
        label,
    )
    if (
        not isinstance(key["id"], str)
        or KEY_ID_PATTERN.fullmatch(key["id"]) is None
    ):
        raise NativeCapabilityEvidenceError(f"{label}.id is not canonical")
    _evidence_reference(key["public_key"], f"{label}.public_key", 256)
    _sha256(key["public_key_sha256"], f"{label}.public_key_sha256")
    fingerprint = key["fingerprint"]
    if family == "apk":
        _sha256(fingerprint, f"{label}.fingerprint")
        if fingerprint != key["public_key_sha256"]:
            raise NativeCapabilityEvidenceError(
                f"{label} APK fingerprint differs from its public-key digest"
            )
    elif (
        not isinstance(fingerprint, str)
        or OPENPGP_FINGERPRINT_PATTERN.fullmatch(fingerprint) is None
    ):
        raise NativeCapabilityEvidenceError(
            f"{label}.fingerprint is not a canonical OpenPGP fingerprint"
        )
    return key


def _validate_package_binding(
    raw: object, expected: dict[str, Any], label: str
) -> dict[str, Any]:
    binding = _exact_mapping(
        raw,
        {
            "filename",
            "package_family",
            "package_variant",
            "rpm_identity",
            "sha256",
            "signature",
            "signed_bundle_seal_sha256",
            "signed_subbundle_seal_sha256",
            "signing_provenance_profile",
            "signing_provenance_sha256",
            "size",
        },
        label,
    )
    for field in (
        "filename",
        "package_family",
        "package_variant",
        "signing_provenance_profile",
    ):
        _bounded_text(binding[field], f"{label}.{field}", 256)
    _sha256(binding["sha256"], f"{label}.sha256")
    _sha256(
        binding["signed_bundle_seal_sha256"],
        f"{label}.signed_bundle_seal_sha256",
    )
    _sha256(
        binding["signing_provenance_sha256"],
        f"{label}.signing_provenance_sha256",
    )
    if binding["signed_subbundle_seal_sha256"] is not None:
        _sha256(
            binding["signed_subbundle_seal_sha256"],
            f"{label}.signed_subbundle_seal_sha256",
        )
    _positive_integer(binding["size"], f"{label}.size", 256 * 1024 * 1024)
    signature = _exact_mapping(
        binding["signature"], {"key", "mechanism"}, f"{label}.signature"
    )
    mechanism = _bounded_text(
        signature["mechanism"], f"{label}.signature.mechanism", 64
    )
    mechanisms = {
        "rpm": "rpm-openpgp",
        "deb": "openpgp-detached",
        "apk": "apk-rsa256",
    }
    if mechanisms.get(binding["package_family"]) != mechanism:
        raise NativeCapabilityEvidenceError(
            f"{label}.signature.mechanism is inconsistent"
        )
    _signing_key(
        signature["key"], binding["package_family"], f"{label}.signature.key"
    )
    rpm_identity = binding["rpm_identity"]
    if binding["package_family"] == "rpm":
        checked_identity = _exact_mapping(
            rpm_identity,
            {"architecture", "filename", "name", "release", "version"},
            f"{label}.rpm_identity",
        )
        for field in checked_identity:
            _bounded_text(
                checked_identity[field], f"{label}.rpm_identity.{field}", 128
            )
    elif rpm_identity is not None:
        raise NativeCapabilityEvidenceError(
            f"{label}.rpm_identity must be null for a non-RPM package"
        )
    if binding != expected:
        raise NativeCapabilityEvidenceError(f"{label} differs from signed provenance")
    return binding


def _load_package_bindings(
    signing_bundle_path: Path,
    candidate_commit: str,
    contract: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    _candidate_commit(candidate_commit)
    if (
        not isinstance(signing_bundle_path, Path)
        or not signing_bundle_path.is_absolute()
        or Path(os.path.normpath(signing_bundle_path)) != signing_bundle_path
    ):
        raise NativeCapabilityEvidenceError(
            "native signing bundle path must be absolute and canonical"
        )
    root_descriptor, opened_root, root_identity = _open_real_directory(
        signing_bundle_path, "native signing bundle"
    )
    version = contract["target_release"].removeprefix("v")
    standard_names = {
        "deb": f"syswarden_{version}_amd64.deb",
        "rpm": f"syswarden-{version}-1.x86_64.rpm",
        "apk": f"syswarden_{version}_x86_64.apk",
    }
    rhel_filename = f"syswarden-{version}-1.rhelpo.x86_64.rpm"
    member_limits = {
        "evidence/NATIVE_SIGNING_PROVENANCE.json": 1024 * 1024,
        "rhel-package-owned/evidence/SIGNING_PROVENANCE.json": 1024 * 1024,
        "SIGNED_ARTIFACT_SHA256SUMS.txt": 1024 * 1024,
        "rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt": 1024 * 1024,
        **{
            f"packages/{filename}": 256 * 1024 * 1024
            for filename in standard_names.values()
        },
        f"rhel-package-owned/packages/{rhel_filename}": 256 * 1024 * 1024,
    }
    anchored_members: dict[str, bytes] = {}
    try:
        if opened_root != signing_bundle_path:
            raise NativeCapabilityEvidenceError(
                "native signing bundle path must be absolute and canonical"
            )
        try:
            signing_bundle.verify_bundle(
                signing_bundle_path, contract["target_release"], candidate_commit
            )
        except signing_bundle.SigningBundleError as exc:
            raise NativeCapabilityEvidenceError(
                f"native signing bundle verification failed: {exc}"
            ) from exc
        for reference, maximum in member_limits.items():
            anchored_members[reference] = _read_bundle_member_at(
                root_descriptor,
                reference,
                maximum,
                "native signing bundle member",
            )
        _verify_directory_binding(
            signing_bundle_path, root_identity, "native signing bundle"
        )
    finally:
        os.close(root_descriptor)

    standard_wire = anchored_members[
        "evidence/NATIVE_SIGNING_PROVENANCE.json"
    ]
    rhel_wire = anchored_members[
        "rhel-package-owned/evidence/SIGNING_PROVENANCE.json"
    ]
    standard_provenance = _decode_json(
        standard_wire, "native signing provenance"
    )
    rhel_provenance = _decode_json(
        rhel_wire,
        "RHEL package-owned signing provenance",
    )
    standard = _exact_mapping(
        standard_provenance,
        {
            "apk_signature",
            "bootstrap_qualification",
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
        },
        "native signing provenance",
    )
    rhel = _exact_mapping(
        rhel_provenance,
        {
            "bootstrap_qualification",
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
        },
        "RHEL package-owned signing provenance",
    )
    qualified_status = signing_bundle.QUALIFIED_PROVENANCE_STATUS
    if (
        type(standard["schema_version"]) is not int
        or standard["schema_version"] != 1
        or standard["profile"] != signing_bundle.SCHEMA_PROFILE
        or standard["status"] != qualified_status
        or standard["public_release"] is not False
        or standard["release_qualified"] is not False
        or type(rhel["schema_version"]) is not int
        or rhel["schema_version"] != 1
        or rhel["profile"] != signing_bundle.RHEL_PACKAGE_OWNED_PROFILE
        or rhel["status"] != qualified_status
        or rhel["package_role"] != "rhel-package-owned"
        or rhel["public_release"] is not False
        or rhel["release_qualified"] is not False
        or rhel["updater_manifest_included"] is not False
    ):
        raise NativeCapabilityEvidenceError(
            "native capability evidence requires the qualified signing provenance"
        )
    try:
        for provenance in (standard, rhel):
            signing_bundle.validate_bootstrap_reference(
                provenance["bootstrap_qualification"],
                contract["target_release"],
                candidate_commit,
                provenance["repository"],
            )
    except signing_bundle.SigningBundleError as exc:
        raise NativeCapabilityEvidenceError(
            f"native signing bootstrap qualification is invalid: {exc}"
        ) from exc
    if rhel["bootstrap_qualification"] != standard["bootstrap_qualification"]:
        raise NativeCapabilityEvidenceError(
            "native signing bootstrap qualification references differ"
        )
    standard_source = _exact_mapping(
        standard["source"],
        {
            "release_sha",
            "release_tag",
            "source_date_epoch",
            "unsigned_artifact_digest",
            "unsigned_artifact_id",
            "unsigned_artifact_name",
            "unsigned_package_run_id",
        },
        "native signing provenance source",
    )
    rhel_source = _exact_mapping(
        rhel["source"],
        {
            "release_sha",
            "release_tag",
            "source_date_epoch",
            "unsigned_artifact_digest",
            "unsigned_artifact_id",
            "unsigned_artifact_name",
            "unsigned_package_run_id",
        },
        "RHEL package-owned signing provenance source",
    )
    if (
        standard_source["release_sha"] != candidate_commit
        or rhel_source["release_sha"] != candidate_commit
        or standard_source["release_tag"] != contract["target_release"]
        or rhel_source["release_tag"] != contract["target_release"]
        or rhel["policy_sha256"] != standard["policy_sha256"]
        or rhel["signing_run"] != standard["signing_run"]
    ):
        raise NativeCapabilityEvidenceError(
            "native signing provenance candidate binding is invalid"
        )

    root_seal_wire = anchored_members["SIGNED_ARTIFACT_SHA256SUMS.txt"]
    rhel_seal_wire = anchored_members[
        "rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt"
    ]
    root_records = _manifest_records_wire(
        root_seal_wire, "native signed artifact seal"
    )
    rhel_records = _manifest_records_wire(
        rhel_seal_wire, "RHEL package-owned signed artifact seal"
    )
    _sealed_member(
        root_records,
        "evidence/NATIVE_SIGNING_PROVENANCE.json",
        standard_wire,
        "native signing provenance",
    )
    _sealed_member(
        root_records,
        "rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
        rhel_wire,
        "RHEL package-owned signing provenance",
    )
    _sealed_member(
        root_records,
        "rhel-package-owned/SIGNED_ARTIFACT_SHA256SUMS.txt",
        rhel_seal_wire,
        "RHEL package-owned sub-bundle seal",
    )

    standard_packages = _exact_mapping(
        standard["packages"], {"signed", "unsigned"}, "native package provenance"
    )
    signed_records = standard_packages["signed"]
    if not isinstance(signed_records, list) or len(signed_records) != 3:
        raise NativeCapabilityEvidenceError(
            "native signed package provenance inventory is not exact"
        )
    standard_by_name: dict[str, dict[str, Any]] = {}
    for index, raw_record in enumerate(signed_records):
        record = _package_record(raw_record, f"native signed package {index}")
        if record["name"] in standard_by_name:
            raise NativeCapabilityEvidenceError(
                "native signed package provenance contains a duplicate filename"
            )
        standard_by_name[record["name"]] = record

    if set(standard_by_name) != set(standard_names.values()):
        raise NativeCapabilityEvidenceError(
            "native signed package provenance filenames are not exact"
        )
    standard_keys = {
        "deb": _signing_key(
            _exact_mapping(
                standard["deb_signature"],
                {"bytes_unchanged", "detached", "key", "signature"},
                "DEB signature provenance",
            )["key"],
            "deb",
            "DEB signature key",
        ),
        "rpm": _signing_key(
            _exact_mapping(
                standard["rpm_signature"],
                {"immutable_header_preserved", "key", "payload_preserved"},
                "RPM signature provenance",
            )["key"],
            "rpm",
            "RPM signature key",
        ),
        "apk": _signing_key(
            _exact_mapping(
                standard["apk_signature"],
                {
                    "exact_unsigned_suffix",
                    "key",
                    "signature_entry",
                    "signature_prefix_sha256",
                    "signature_prefix_size",
                    "signature_sha256",
                },
                "APK signature provenance",
            )["key"],
            "apk",
            "APK signature key",
        ),
    }
    mechanisms = {
        "deb": "openpgp-detached",
        "rpm": "rpm-openpgp",
        "apk": "apk-rsa256",
    }
    root_seal_sha256 = hashlib.sha256(root_seal_wire).hexdigest()
    bindings_by_family: dict[str, dict[str, Any]] = {}
    for family, filename in standard_names.items():
        record = standard_by_name[filename]
        package_wire = anchored_members[f"packages/{filename}"]
        if (
            record["sha256"] != hashlib.sha256(package_wire).hexdigest()
            or record["size"] != len(package_wire)
        ):
            raise NativeCapabilityEvidenceError(
                f"signed {family} package differs from signing provenance"
            )
        _sealed_member(
            root_records,
            f"packages/{filename}",
            package_wire,
            f"signed {family} package",
        )
        rpm_identity: dict[str, str] | None = None
        if family == "rpm":
            rpm_identity = {
                "architecture": "x86_64",
                "filename": filename,
                "name": "syswarden",
                "release": "1",
                "version": version,
            }
        bindings_by_family[family] = {
            "filename": filename,
            "package_family": family,
            "package_variant": "standard",
            "rpm_identity": rpm_identity,
            "sha256": record["sha256"],
            "signature": {
                "key": standard_keys[family],
                "mechanism": mechanisms[family],
            },
            "signed_bundle_seal_sha256": root_seal_sha256,
            "signed_subbundle_seal_sha256": None,
            "signing_provenance_profile": standard["profile"],
            "signing_provenance_sha256": hashlib.sha256(standard_wire).hexdigest(),
            "size": record["size"],
        }

    rhel_packages = _exact_mapping(
        rhel["packages"], {"signed", "unsigned"},
        "RHEL package-owned package provenance",
    )
    rhel_record = _package_record(
        rhel_packages["signed"], "RHEL package-owned signed package"
    )
    if rhel_record["name"] != rhel_filename:
        raise NativeCapabilityEvidenceError(
            "RHEL package-owned signed package filename is invalid"
        )
    rhel_package_wire = anchored_members[
        f"rhel-package-owned/packages/{rhel_filename}"
    ]
    if (
        rhel_record["sha256"] != hashlib.sha256(rhel_package_wire).hexdigest()
        or rhel_record["size"] != len(rhel_package_wire)
    ):
        raise NativeCapabilityEvidenceError(
            "RHEL package-owned signed package differs from signing provenance"
        )
    _sealed_member(
        rhel_records,
        f"packages/{rhel_filename}",
        rhel_package_wire,
        "RHEL package-owned signed package",
    )
    _sealed_member(
        root_records,
        f"rhel-package-owned/packages/{rhel_filename}",
        rhel_package_wire,
        "RHEL package-owned signed package",
    )
    rhel_identity = _exact_mapping(
        rhel["rpm_identity"],
        {"architecture", "filename", "name", "release", "version"},
        "RHEL package-owned RPM identity",
    )
    expected_rhel_identity = {
        "architecture": "x86_64",
        "filename": rhel_filename,
        "name": "syswarden",
        "release": "1.rhelpo",
        "version": version,
    }
    if rhel_identity != expected_rhel_identity or any(
        not isinstance(value, str) for value in rhel_identity.values()
    ):
        raise NativeCapabilityEvidenceError(
            "RHEL package-owned RPM identity is invalid"
        )
    rhel_signature = _exact_mapping(
        rhel["rpm_signature"],
        {"immutable_header_preserved", "key", "payload_preserved"},
        "RHEL package-owned RPM signature provenance",
    )
    rhel_key = _signing_key(
        rhel_signature["key"], "rpm", "RHEL package-owned RPM signature key"
    )
    if rhel_key != standard_keys["rpm"]:
        raise NativeCapabilityEvidenceError(
            "RHEL package-owned RPM does not use the qualified RPM identity"
        )
    rhel_binding = {
        "filename": rhel_filename,
        "package_family": "rpm",
        "package_variant": "package-owned",
        "rpm_identity": expected_rhel_identity,
        "sha256": rhel_record["sha256"],
        "signature": {"key": rhel_key, "mechanism": "rpm-openpgp"},
        "signed_bundle_seal_sha256": root_seal_sha256,
        "signed_subbundle_seal_sha256": hashlib.sha256(rhel_seal_wire).hexdigest(),
        "signing_provenance_profile": rhel["profile"],
        "signing_provenance_sha256": hashlib.sha256(rhel_wire).hexdigest(),
        "size": rhel_record["size"],
    }

    result: dict[str, dict[str, Any]] = {}
    for profile in contract["host_profiles"]:
        binding = (
            rhel_binding
            if profile["package_variant"] == "package-owned"
            else bindings_by_family[profile["package_family"]]
        )
        result[profile["id"]] = binding
    return result


def load_contract(path: Path = DEFAULT_CONTRACT) -> tuple[dict[str, Any], bytes]:
    raw, wire = _load_json(path, 128 * 1024, "native capability contract")
    digest = hashlib.sha256(wire).hexdigest()
    if path == DEFAULT_CONTRACT and digest != CONTRACT_SHA256:
        raise NativeCapabilityEvidenceError("native capability contract digest is not frozen")
    contract = _exact_mapping(
        raw,
        {
            "schema_version",
            "contract_id",
            "target_release",
            "architecture",
            "limits",
            "guardrails",
            "host_profiles",
            "capabilities",
            "native_controls",
            "package_owned_controls",
            "attack_scenarios",
            "lifecycle_sequences",
        },
        "contract",
    )
    if (
        contract["schema_version"] != 1
        or contract["contract_id"] != "syswarden-native-capability-qualification/v1"
        or contract["target_release"] != "v4.10.0"
        or contract["architecture"] != "amd64"
    ):
        raise NativeCapabilityEvidenceError("contract identity is unsupported")
    if type(contract["schema_version"]) is not int:
        raise NativeCapabilityEvidenceError("contract schema type is invalid")
    limits = _exact_mapping(
        contract["limits"],
        {
            "maximum_input_bytes",
            "maximum_campaign_seconds",
            "maximum_future_skew_seconds",
            "maximum_identifier_bytes",
            "maximum_evidence_reference_bytes",
        },
        "contract.limits",
    )
    expected_limits = {
        "maximum_input_bytes": 1048576,
        "maximum_campaign_seconds": 5400,
        "maximum_future_skew_seconds": 300,
        "maximum_identifier_bytes": 64,
        "maximum_evidence_reference_bytes": 256,
    }
    if limits != expected_limits:
        raise NativeCapabilityEvidenceError("contract limits are not frozen")
    if any(type(limits[key]) is not int for key in expected_limits):
        raise NativeCapabilityEvidenceError("contract limit types are invalid")
    guardrails = _exact_mapping(
        contract["guardrails"],
        {
            "ci_execution",
            "authentication_journal_access",
            "authentication_event_source",
            "synthetic_authentication_journal_writes",
            "host_changes",
        },
        "contract.guardrails",
    )
    expected_guardrails = {
        "ci_execution": "harness-tests-only",
        "authentication_journal_access": "read-only",
        "authentication_event_source": "real-controlled-network-attempts",
        "synthetic_authentication_journal_writes": False,
        "host_changes": "native-lab-only-ephemeral-and-restored",
    }
    if guardrails != expected_guardrails:
        raise NativeCapabilityEvidenceError("contract guardrails are not frozen")
    if type(guardrails["synthetic_authentication_journal_writes"]) is not bool:
        raise NativeCapabilityEvidenceError("contract guardrail types are invalid")

    expected_profiles = (
        ("DEB-13", "node01", "debian", "13", "deb", "standard", "standard-deb13"),
        ("DEB-U2604", "node02", "ubuntu", "26.04", "deb", "standard", "standard-deb-u2604"),
        ("RPM-A10", "node03", "almalinux", "10.2", "rpm", "standard", "standard-rpm-a10"),
        ("APK-324", "node04", "alpine", "3.24", "apk", "standard", "standard-apk-324"),
        ("RPM-A9-RHELPO", "node05", "almalinux", "9.8", "rpm", "package-owned", "rhelpo-rpm-a9"),
        ("RPM-A10-RHELPO", "node03", "almalinux", "10.2", "rpm", "package-owned", "rhelpo-rpm-a10"),
    )
    profiles = contract["host_profiles"]
    if not isinstance(profiles, list) or len(profiles) != len(expected_profiles):
        raise NativeCapabilityEvidenceError("contract host profile inventory is not exact")
    for index, expected in enumerate(expected_profiles):
        profile = _exact_mapping(
            profiles[index],
            {
                "id",
                "host_id",
                "os_id",
                "os_version",
                "package_family",
                "package_variant",
                "evidence_namespace",
            },
            f"contract.host_profiles[{index}]",
        )
        if tuple(
            profile[key]
            for key in (
                "id",
                "host_id",
                "os_id",
                "os_version",
                "package_family",
                "package_variant",
                "evidence_namespace",
            )
        ) != expected:
            raise NativeCapabilityEvidenceError("contract host profile order is not frozen")
        if any(not isinstance(profile[key], str) for key in profile):
            raise NativeCapabilityEvidenceError("contract host profile types are invalid")

    expected_capabilities = (
        ("hids", "hids-native-auth-log-detection"),
        ("hips", "hips-native-ssh-bruteforce"),
        ("waap", "waap-native-sqli-request"),
        ("asn", "asn-attested-enrichment"),
        ("geo", "geo-attested-enrichment"),
        ("osint", "osint-history-enrichment"),
        ("tui_grc", "tui-grc-kpi-coherence"),
        ("extended_controls", "native-extended-controls"),
    )
    capabilities = contract["capabilities"]
    if not isinstance(capabilities, list) or len(capabilities) != len(expected_capabilities):
        raise NativeCapabilityEvidenceError("contract capability inventory is not exact")
    for index, expected in enumerate(expected_capabilities):
        capability = _exact_mapping(
            capabilities[index], {"id", "scenario_id"},
            f"contract.capabilities[{index}]",
        )
        if (capability["id"], capability["scenario_id"]) != expected:
            raise NativeCapabilityEvidenceError("contract capability order is not frozen")
        if any(not isinstance(capability[key], str) for key in capability):
            raise NativeCapabilityEvidenceError("contract capability types are invalid")

    expected_native_controls = (
        ("operator-policy-tcp-apply", {"protocol": "tcp", "exact_nft_ruleset_verified": True}),
        ("operator-policy-udp-apply", {"protocol": "udp", "exact_nft_ruleset_verified": True}),
        ("operator-policy-concurrent-mutation", {"serialized": True, "lost_update": False}),
        ("operator-policy-rollback-restart", {"rollback_verified": True, "restart_verified": True}),
        ("operator-policy-third-party-preservation", {"third_party_rules_unchanged": True}),
        ("hids-log-rotation", {"events_preserved": True, "duplicates": 0}),
        ("hids-log-truncation", {"events_preserved": True, "duplicates": 0}),
        ("hids-log-replacement", {"replacement_attested": True, "events_preserved": True}),
        ("hids-delayed-write", {"delayed_event_observed": True, "duplicates": 0}),
        ("hids-unsafe-path-refusal", {"symlink_refused": True, "special_file_refused": True, "wrong_owner_refused": True, "wrong_mode_refused": True}),
        ("hips-bf-slow", {"real_network_attempts": True, "admitted_hits_match": True, "jail_match": True}),
        ("waap-exploit-severity", {"signature_catalog_bound": True, "severity_match": True}),
        ("waap-deduplication", {"duplicate_events_suppressed": True, "physical_hits_preserved": True}),
        ("waap-backpressure", {"queue_bounded": True, "degraded_evidence_reported": True}),
        ("waap-non-recursion", {"recursive_alerts": 0}),
    )
    native_controls = contract["native_controls"]
    if not isinstance(native_controls, list) or len(native_controls) != len(expected_native_controls):
        raise NativeCapabilityEvidenceError("contract native control inventory is not exact")
    for index, (expected_id, expected_assertions) in enumerate(expected_native_controls):
        control = _exact_mapping(native_controls[index], {"id", "assertions"}, f"contract.native_controls[{index}]")
        if control["id"] != expected_id or control["assertions"] != expected_assertions:
            raise NativeCapabilityEvidenceError("contract native controls are not frozen")

    expected_package_owned_controls = (
        (
            "rhelpo-go-runtime-only",
            {
                "go_runtime_scope": "runtime-only",
                "system_configuration_mutations": False,
            },
        ),
        (
            "rhelpo-package-owned-system-state",
            {
                "configuration_owned_by_package": True,
                "firewall_owned_by_package": True,
                "systemd_units_owned_by_package": True,
            },
        ),
        (
            "rhelpo-first-boot-after-chroot",
            {
                "installation_context": "rhel9-image-chroot",
                "first_boot_verified": True,
            },
        ),
    )
    package_owned_controls = contract["package_owned_controls"]
    if (
        not isinstance(package_owned_controls, list)
        or len(package_owned_controls) != len(expected_package_owned_controls)
    ):
        raise NativeCapabilityEvidenceError(
            "contract package-owned control inventory is not exact"
        )
    for index, (expected_id, expected_assertions) in enumerate(
        expected_package_owned_controls
    ):
        control = _exact_mapping(
            package_owned_controls[index],
            {"id", "assertions"},
            f"contract.package_owned_controls[{index}]",
        )
        assertions = _exact_mapping(
            control["assertions"],
            set(expected_assertions),
            f"contract.package_owned_controls[{index}].assertions",
        )
        if (
            control["id"] != expected_id
            or assertions != expected_assertions
            or any(
                type(assertions[key]) is not type(expected_value)
                for key, expected_value in expected_assertions.items()
            )
        ):
            raise NativeCapabilityEvidenceError(
                "contract package-owned controls are not frozen"
            )

    expected_attacks = (
        (
            "hips-native-ssh-bruteforce",
            "hips",
            "ssh-auth",
            "brute_force",
            "real-controlled-network-attempts",
            4,
        ),
        (
            "waap-native-sqli-request",
            "waap",
            "sqli",
            "exploit",
            "real-controlled-http-request",
            1,
        ),
    )
    attacks = contract["attack_scenarios"]
    attack_keys = {
        "id",
        "capability",
        "rule_id",
        "risk_category",
        "observation_origin",
        "required_event_count",
    }
    if not isinstance(attacks, list) or len(attacks) != len(expected_attacks):
        raise NativeCapabilityEvidenceError("contract attack scenario inventory is not exact")
    for index, expected in enumerate(expected_attacks):
        attack = _exact_mapping(attacks[index], attack_keys, f"contract.attack_scenarios[{index}]")
        actual = tuple(
            attack[key]
            for key in (
                "id",
                "capability",
                "rule_id",
                "risk_category",
                "observation_origin",
                "required_event_count",
            )
        )
        if actual != expected:
            raise NativeCapabilityEvidenceError("contract attack scenarios are not frozen")
        if type(attack["required_event_count"]) is not int:
            raise NativeCapabilityEvidenceError("contract attack count type is invalid")

    lifecycle = contract["lifecycle_sequences"]
    if not isinstance(lifecycle, list) or len(lifecycle) != 2:
        raise NativeCapabilityEvidenceError("contract lifecycle inventory is not exact")
    deletion = _exact_mapping(
        lifecycle[0],
        {"id", "binding_type", "capability", "scenario_id", "rule_id", "states"},
        "contract.lifecycle_sequences[0]",
    )
    expected_deletion = {
        "id": "manual-deletion",
        "binding_type": "bound-attack",
        "capability": "hips",
        "scenario_id": "hips-native-ssh-bruteforce",
        "rule_id": "ssh-auth",
        "states": ["active", "deleted", "tombstoned"],
    }
    if deletion != expected_deletion:
        raise NativeCapabilityEvidenceError("contract deletion lifecycle is not frozen")
    temporary = _exact_mapping(
        lifecycle[1],
        {"id", "binding_type", "source", "ttl_seconds", "states"},
        "contract.lifecycle_sequences[1]",
    )
    expected_temporary = {
        "id": "ttl-expiry",
        "binding_type": "controlled-temporary-ban",
        "source": "native-capability-lab",
        "ttl_seconds": 60,
        "states": ["active", "expired", "tombstoned"],
    }
    if temporary != expected_temporary:
        raise NativeCapabilityEvidenceError("contract expiry lifecycle is not frozen")
    if (
        any(type(value) is not str for key, value in deletion.items() if key != "states")
        or any(type(value) is not str for key, value in temporary.items() if key not in {"states", "ttl_seconds"})
        or type(temporary["ttl_seconds"]) is not int
        or any(
            not isinstance(state_name, str)
            for sequence in lifecycle
            for state_name in sequence["states"]
        )
    ):
        raise NativeCapabilityEvidenceError("contract lifecycle types are invalid")
    return contract, wire


def _profile_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in contract["host_profiles"]}


def _validate_host_attestation(
    raw: object,
    contract: dict[str, Any],
    candidate_commit: str,
    signature_catalog_sha256: str,
    package_bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    attestation = _exact_mapping(
        raw,
        {
            "schema_version",
            "attestation_id",
            "captured_at",
            "host_id",
            "profile_id",
            "os_id",
            "os_version",
            "architecture",
            "package_family",
            "kernel_release",
            "boot_id_sha256",
            "installed_version",
            "candidate_commit",
            "package_binding",
            "installed_signature_catalog_sha256",
        },
        "host attestation",
    )
    if attestation["schema_version"] != 1:
        raise NativeCapabilityEvidenceError("host attestation schema is unsupported")
    if type(attestation["schema_version"]) is not int:
        raise NativeCapabilityEvidenceError("host attestation schema type is invalid")
    for field in ("attestation_id", "host_id"):
        _identifier(attestation[field], f"host attestation {field}")
    _canonical_timestamp(attestation["captured_at"], "host attestation captured_at")
    profiles = _profile_map(contract)
    profile_id = _bounded_text(
        attestation["profile_id"], "host attestation profile_id", 64
    )
    profile = profiles.get(profile_id)
    if profile is None:
        raise NativeCapabilityEvidenceError("host attestation profile is unsupported")
    if not attestation["attestation_id"].startswith(
        profile["evidence_namespace"] + "-"
    ):
        raise NativeCapabilityEvidenceError(
            "host attestation identity is outside its profile namespace"
        )
    expected = {
        "host_id": profile["host_id"],
        "os_id": profile["os_id"],
        "os_version": profile["os_version"],
        "architecture": contract["architecture"],
        "package_family": profile["package_family"],
        "installed_version": contract["target_release"],
        "candidate_commit": candidate_commit,
    }
    for key, value in expected.items():
        if attestation[key] != value:
            raise NativeCapabilityEvidenceError(f"host attestation {key} binding is invalid")
    _bounded_text(attestation["kernel_release"], "host attestation kernel_release", 128)
    _sha256(attestation["boot_id_sha256"], "host attestation boot_id_sha256")
    _validate_package_binding(
        attestation["package_binding"],
        package_bindings[profile_id],
        "host attestation package_binding",
    )
    _sha256(
        attestation["installed_signature_catalog_sha256"],
        "host attestation installed_signature_catalog_sha256",
    )
    if attestation["installed_signature_catalog_sha256"] != signature_catalog_sha256:
        raise NativeCapabilityEvidenceError(
            "host attestation installed signature catalog binding is invalid"
        )
    return attestation


def _load_signature_catalog(path: Path, maximum: int) -> tuple[dict[str, Any], bytes, dict[str, dict[str, Any]]]:
    raw, wire = _load_json(path, maximum, "signature catalog")
    catalog = _exact_mapping(
        raw,
        {"catalog_version", "risk_model_version", "risk_categories", "metric_excluded_rules", "rules"},
        "signature catalog",
    )
    if catalog["catalog_version"] != "sw-signatures-v1" or catalog["risk_model_version"] != "sw-risk-v1":
        raise NativeCapabilityEvidenceError("signature catalog identity is unsupported")
    categories = catalog["risk_categories"]
    if not isinstance(categories, dict) or set(categories) != set(RISK_BASE):
        raise NativeCapabilityEvidenceError("signature risk category inventory is not exact")
    category_by_rule: dict[str, str] = {}
    for category, rule_ids in categories.items():
        if not isinstance(rule_ids, list) or not rule_ids:
            raise NativeCapabilityEvidenceError(f"signature category {category} is empty")
        for rule_id in rule_ids:
            if (
                not isinstance(rule_id, str)
                or not rule_id
                or len(rule_id.encode("utf-8")) > 128
                or any(ord(character) < 32 or ord(character) == 127 for character in rule_id)
                or rule_id in category_by_rule
            ):
                raise NativeCapabilityEvidenceError("signature category contains an invalid or duplicate rule")
            category_by_rule[rule_id] = category
    rules = catalog["rules"]
    if not isinstance(rules, list) or not rules:
        raise NativeCapabilityEvidenceError("signature catalog rules are empty")
    result: dict[str, dict[str, Any]] = {}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise NativeCapabilityEvidenceError(f"signature rule {index} must be an object")
        rule_id = rule.get("id")
        if (
            not isinstance(rule_id, str)
            or not rule_id
            or len(rule_id.encode("utf-8")) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in rule_id)
            or rule_id in result
        ):
            raise NativeCapabilityEvidenceError("signature catalog rule identity is invalid")
        if rule_id not in category_by_rule:
            raise NativeCapabilityEvidenceError(f"signature rule {rule_id} is not classified")
        action = rule.get("action", "ban")
        if not isinstance(action, str) or action not in {"ban", "detect", "track"}:
            raise NativeCapabilityEvidenceError(f"signature rule {rule_id} has an unsupported action")
        result[rule_id] = {"category": category_by_rule[rule_id], "action": action}
    if set(category_by_rule) != set(result):
        raise NativeCapabilityEvidenceError("signature categories reference unknown rules")
    excluded = catalog["metric_excluded_rules"]
    if (
        not isinstance(excluded, list)
        or any(not isinstance(item, str) for item in excluded)
        or len(excluded) != len(set(excluded))
        or any(item not in result for item in excluded)
    ):
        raise NativeCapabilityEvidenceError("signature metric exclusions are invalid")
    return catalog, wire, result


def build_campaign(
    *,
    candidate_commit: str,
    campaign_id: str,
    created_at: str,
    host_attestation_path: Path,
    signing_bundle_path: Path,
    signature_catalog_path: Path = DEFAULT_SIGNATURE_CATALOG,
    contract_path: Path = DEFAULT_CONTRACT,
) -> dict[str, Any]:
    contract, contract_wire = load_contract(contract_path)
    maximum = contract["limits"]["maximum_input_bytes"]
    _candidate_commit(candidate_commit)
    _identifier(campaign_id, "campaign identifier")
    created = _canonical_timestamp(created_at, "campaign created_at")
    catalog, catalog_wire, _ = _load_signature_catalog(signature_catalog_path, maximum)
    catalog_sha256 = hashlib.sha256(catalog_wire).hexdigest()
    raw_attestation, attestation_wire = _load_json(
        host_attestation_path, maximum, "host attestation"
    )
    package_bindings = _load_package_bindings(
        signing_bundle_path, candidate_commit, contract
    )
    attestation = _validate_host_attestation(
        raw_attestation,
        contract,
        candidate_commit,
        catalog_sha256,
        package_bindings,
    )
    profile = _profile_map(contract)[attestation["profile_id"]]
    if not campaign_id.startswith(profile["evidence_namespace"] + "-"):
        raise NativeCapabilityEvidenceError(
            "campaign identifier is outside its profile namespace"
        )
    captured = _canonical_timestamp(attestation["captured_at"], "host attestation captured_at")
    if captured > created + dt.timedelta(seconds=contract["limits"]["maximum_future_skew_seconds"]):
        raise NativeCapabilityEvidenceError("host attestation was captured after campaign creation")
    return {
        "schema_version": 1,
        "schema_id": CAMPAIGN_SCHEMA,
        "contract_id": contract["contract_id"],
        "contract_sha256": hashlib.sha256(contract_wire).hexdigest(),
        "target_release": contract["target_release"],
        "candidate_commit": candidate_commit,
        "campaign_id": campaign_id,
        "created_at": created_at,
        "host": {
            "attestation_id": attestation["attestation_id"],
            "host_id": attestation["host_id"],
            "profile_id": attestation["profile_id"],
            "evidence_namespace": profile["evidence_namespace"],
            "package_binding": attestation["package_binding"],
            "attestation_sha256": hashlib.sha256(attestation_wire).hexdigest(),
        },
        "signature_catalog": {
            "catalog_version": catalog["catalog_version"],
            "risk_model_version": catalog["risk_model_version"],
            "sha256": catalog_sha256,
        },
    }


def _validate_campaign(
    raw: object,
    *,
    candidate_commit: str,
    host_attestation_path: Path,
    signing_bundle_path: Path,
    signature_catalog_path: Path,
    contract_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    contract, contract_wire = load_contract(contract_path)
    maximum = contract["limits"]["maximum_input_bytes"]
    _candidate_commit(candidate_commit)
    campaign = _exact_mapping(
        raw,
        {
            "schema_version",
            "schema_id",
            "contract_id",
            "contract_sha256",
            "target_release",
            "candidate_commit",
            "campaign_id",
            "created_at",
            "host",
            "signature_catalog",
        },
        "campaign",
    )
    expected = {
        "schema_version": 1,
        "schema_id": CAMPAIGN_SCHEMA,
        "contract_id": contract["contract_id"],
        "contract_sha256": hashlib.sha256(contract_wire).hexdigest(),
        "target_release": contract["target_release"],
        "candidate_commit": candidate_commit,
    }
    for key, value in expected.items():
        if campaign[key] != value:
            raise NativeCapabilityEvidenceError(f"campaign {key} binding is invalid")
    if type(campaign["schema_version"]) is not int:
        raise NativeCapabilityEvidenceError("campaign schema type is invalid")
    _identifier(campaign["campaign_id"], "campaign identifier")
    _canonical_timestamp(campaign["created_at"], "campaign created_at")
    catalog, catalog_wire, rules = _load_signature_catalog(signature_catalog_path, maximum)
    catalog_sha256 = hashlib.sha256(catalog_wire).hexdigest()
    raw_attestation, attestation_wire = _load_json(
        host_attestation_path, maximum, "host attestation"
    )
    package_bindings = _load_package_bindings(
        signing_bundle_path, candidate_commit, contract
    )
    attestation = _validate_host_attestation(
        raw_attestation,
        contract,
        candidate_commit,
        catalog_sha256,
        package_bindings,
    )
    host = _exact_mapping(
        campaign["host"],
        {
            "attestation_id",
            "host_id",
            "profile_id",
            "evidence_namespace",
            "package_binding",
            "attestation_sha256",
        },
        "campaign.host",
    )
    profile = _profile_map(contract)[attestation["profile_id"]]
    expected_host = {
        "attestation_id": attestation["attestation_id"],
        "host_id": attestation["host_id"],
        "profile_id": attestation["profile_id"],
        "evidence_namespace": profile["evidence_namespace"],
        "package_binding": package_bindings[attestation["profile_id"]],
        "attestation_sha256": hashlib.sha256(attestation_wire).hexdigest(),
    }
    _validate_package_binding(
        host["package_binding"],
        package_bindings[attestation["profile_id"]],
        "campaign.host.package_binding",
    )
    if host != expected_host:
        raise NativeCapabilityEvidenceError("campaign host attestation SHA binding is invalid")
    if not campaign["campaign_id"].startswith(
        profile["evidence_namespace"] + "-"
    ):
        raise NativeCapabilityEvidenceError(
            "campaign identifier is outside its profile namespace"
        )
    catalog_binding = _exact_mapping(
        campaign["signature_catalog"], {"catalog_version", "risk_model_version", "sha256"},
        "campaign.signature_catalog",
    )
    expected_catalog = {
        "catalog_version": catalog["catalog_version"],
        "risk_model_version": catalog["risk_model_version"],
        "sha256": catalog_sha256,
    }
    if catalog_binding != expected_catalog:
        raise NativeCapabilityEvidenceError("campaign signature catalog SHA binding is invalid")
    return campaign, contract, rules


def _severity_score(category: str, action: str, policy_hits: int, peak: int, reached: bool, threshold: int) -> int:
    score = RISK_BASE[category]
    if action == "ban":
        score += 20 + 10 * min(policy_hits, 4)
    elif action == "detect":
        score += 10 + 10 * min(policy_hits, 4)
    else:
        effective_peak = peak
        if reached and effective_peak < threshold:
            effective_peak = threshold
        score += (40 * min(effective_peak, threshold) + threshold - 1) // threshold
        if peak >= threshold or reached:
            score += 20
    return max(0, min(score, 100))


def _severity_label(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High Risk"
    return "Suspicious"


ATTACK_KEYS = {
    "status",
    "scenario_id",
    "evidence_ref",
    "evidence_sha256",
    "source_ip",
    "observation_origin",
    "rule_id",
    "first_observed_at",
    "last_observed_at",
    "enforced_at",
    "risk_category",
    "rule_action",
    "effective_threshold",
    "effective_window_seconds",
    "observed_events",
    "admitted_events",
    "rejected_events",
    "excluded_events",
    "physical_hits",
    "jail_hits",
    "policy_hits",
    "peak_window_hits",
    "threshold_reached",
    "threshold_evidence",
    "enforcement_action",
    "severity_score",
    "severity_label",
}


def _public_address(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise NativeCapabilityEvidenceError(f"{label} must be a string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise NativeCapabilityEvidenceError(f"{label} is not an IP address") from exc
    if (
        str(address) != value
        or not address.is_global
        or address.is_multicast
        or "%" in value
        or getattr(address, "ipv4_mapped", None) is not None
    ):
        raise NativeCapabilityEvidenceError(f"{label} must be one canonical public address")
    return value


def _validate_attack(
    raw: object,
    scenario: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    label: str,
    reference_maximum: int,
    started: dt.datetime,
    completed: dt.datetime,
) -> dict[str, Any]:
    attack = _exact_mapping(raw, ATTACK_KEYS, label)
    expected_text = {
        "status": "pass",
        "scenario_id": scenario["id"],
        "observation_origin": scenario["observation_origin"],
        "rule_id": scenario["rule_id"],
        "risk_category": scenario["risk_category"],
        "enforcement_action": "BANNED",
    }
    for key, expected in expected_text.items():
        if attack[key] != expected:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is invalid")
    _evidence_reference(attack["evidence_ref"], f"{label}.evidence_ref", reference_maximum)
    _sha256(attack["evidence_sha256"], f"{label}.evidence_sha256")
    _public_address(attack["source_ip"], f"{label}.source_ip")
    first_observed = _canonical_timestamp(
        attack["first_observed_at"], f"{label}.first_observed_at"
    )
    last_observed = _canonical_timestamp(
        attack["last_observed_at"], f"{label}.last_observed_at"
    )
    enforced = _canonical_timestamp(attack["enforced_at"], f"{label}.enforced_at")
    if not (
        started <= first_observed <= last_observed <= enforced <= completed
    ):
        raise NativeCapabilityEvidenceError(f"{label} observation times are incoherent")
    catalog_rule = rules.get(scenario["rule_id"])
    if catalog_rule is None or catalog_rule["category"] != scenario["risk_category"]:
        raise NativeCapabilityEvidenceError(f"{label} rule is not classified by the candidate catalog")
    if attack["rule_action"] != catalog_rule["action"]:
        raise NativeCapabilityEvidenceError(f"{label}.rule_action does not match the candidate catalog")
    counters = {
        key: _nonnegative_integer(attack[key], f"{label}.{key}")
        for key in (
            "observed_events",
            "admitted_events",
            "rejected_events",
            "excluded_events",
            "physical_hits",
            "jail_hits",
            "policy_hits",
            "peak_window_hits",
        )
    }
    required = scenario["required_event_count"]
    if not (
        counters["observed_events"]
        == counters["admitted_events"]
        == counters["physical_hits"]
        == counters["jail_hits"]
        == counters["policy_hits"]
        == required
        and counters["rejected_events"] == 0
        and counters["excluded_events"] == 0
    ):
        raise NativeCapabilityEvidenceError(f"{label} counters are inconsistent")
    threshold = _positive_integer(attack["effective_threshold"], f"{label}.effective_threshold")
    window = _nonnegative_integer(
        attack["effective_window_seconds"],
        f"{label}.effective_window_seconds",
        31_536_000,
    )
    reached = _boolean(attack["threshold_reached"], f"{label}.threshold_reached")
    peak = counters["peak_window_hits"]
    action = attack["rule_action"]
    if action == "track":
        if (
            window <= 0
            or peak > counters["policy_hits"]
            or not reached
            or peak < threshold
            or attack["threshold_evidence"] != "observed-window"
        ):
            raise NativeCapabilityEvidenceError(f"{label} tracked threshold evidence is inconsistent")
    elif (
        threshold != 1
        or window != 0
        or peak != 0
        or not reached
        or attack["threshold_evidence"] != "immediate-rule"
    ):
        raise NativeCapabilityEvidenceError(f"{label} immediate threshold evidence is inconsistent")
    score = _nonnegative_integer(attack["severity_score"], f"{label}.severity_score", 100)
    expected_score = _severity_score(
        scenario["risk_category"], action, counters["policy_hits"], peak, reached, threshold
    )
    if score != expected_score or attack["severity_label"] != _severity_label(score):
        raise NativeCapabilityEvidenceError(f"{label} severity does not match candidate policy evidence")
    return attack


def _validate_hids(
    raw: object,
    scenario_id: str,
    hips: dict[str, Any],
    reference_maximum: int,
) -> dict[str, Any]:
    label = "evidence.capabilities.hids"
    hids = _exact_mapping(
        raw,
        {
            "status",
            "scenario_id",
            "evidence_ref",
            "evidence_sha256",
            "source_ip",
            "observation_origin",
            "transport",
            "rule_id",
            "first_observed_at",
            "last_observed_at",
            "observed_events",
            "matched_events",
            "rejected_events",
        },
        label,
    )
    expected = {
        "status": "pass",
        "scenario_id": scenario_id,
        "source_ip": hips["source_ip"],
        "observation_origin": "native-authentication-journal",
        "transport": "rsyslog-imfile-to-uds",
        "rule_id": hips["rule_id"],
        "first_observed_at": hips["first_observed_at"],
        "last_observed_at": hips["last_observed_at"],
        "observed_events": hips["observed_events"],
        "matched_events": hips["admitted_events"],
        "rejected_events": 0,
    }
    for key, value in expected.items():
        if hids[key] != value:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is invalid")
    for key in ("observed_events", "matched_events", "rejected_events"):
        _nonnegative_integer(hids[key], f"{label}.{key}")
    _canonical_timestamp(hids["first_observed_at"], f"{label}.first_observed_at")
    _canonical_timestamp(hids["last_observed_at"], f"{label}.last_observed_at")
    _evidence_reference(hids["evidence_ref"], f"{label}.evidence_ref", reference_maximum)
    _sha256(hids["evidence_sha256"], f"{label}.evidence_sha256")
    return hids


def _validate_enrichment(
    raw: object,
    *,
    capability: str,
    scenario_id: str,
    source_ip: str,
    reference_maximum: int,
) -> dict[str, Any]:
    label = f"evidence.capabilities.{capability}"
    item = _exact_mapping(
        raw,
        {
            "status",
            "scenario_id",
            "evidence_ref",
            "evidence_sha256",
            "source_ip",
            "provider",
            "lookup_count",
            "value",
            "tui_value",
            "verified",
        },
        label,
    )
    expected = {
        "status": "pass",
        "scenario_id": scenario_id,
        "source_ip": source_ip,
        "provider": "ip.wiredalter.com",
        "lookup_count": 1,
        "verified": True,
    }
    for key, value in expected.items():
        if item[key] != value:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is invalid")
    _positive_integer(item["lookup_count"], f"{label}.lookup_count")
    _boolean(item["verified"], f"{label}.verified")
    _evidence_reference(item["evidence_ref"], f"{label}.evidence_ref", reference_maximum)
    _sha256(item["evidence_sha256"], f"{label}.evidence_sha256")
    _bounded_text(item["value"], f"{label}.value", 256)
    if item["value"] in {"N/A", "UNKNOWN", "unknown"} or item["tui_value"] != item["value"]:
        raise NativeCapabilityEvidenceError(f"{label} value is absent or differs from the TUI")
    if capability == "asn" and (
        ASN_PATTERN.fullmatch(item["value"]) is None
        or int(item["value"][2:]) > 4_294_967_295
    ):
        raise NativeCapabilityEvidenceError(f"{label}.value is not a canonical ASN")
    if capability == "geo" and COUNTRY_PATTERN.fullmatch(item["value"]) is None:
        raise NativeCapabilityEvidenceError(f"{label}.value is not an uppercase country code")
    return item


def _validate_osint(
    raw: object,
    *,
    scenario_id: str,
    source_ip: str,
    asn: str,
    country: str,
    physical_hits: int,
    reference_maximum: int,
) -> dict[str, Any]:
    label = "evidence.capabilities.osint"
    item = _exact_mapping(
        raw,
        {
            "status",
            "scenario_id",
            "evidence_ref",
            "evidence_sha256",
            "source_ip",
            "provider",
            "history_hits",
            "country",
            "asn",
            "organization",
            "threat",
            "tui_country",
            "tui_asn",
            "tui_organization",
            "tui_threat",
        },
        label,
    )
    expected = {
        "status": "pass",
        "scenario_id": scenario_id,
        "source_ip": source_ip,
        "provider": "ip.wiredalter.com",
        "history_hits": physical_hits,
        "country": country,
        "asn": asn,
    }
    for key, value in expected.items():
        if item[key] != value:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is invalid")
    _positive_integer(item["history_hits"], f"{label}.history_hits")
    _evidence_reference(item["evidence_ref"], f"{label}.evidence_ref", reference_maximum)
    _sha256(item["evidence_sha256"], f"{label}.evidence_sha256")
    for key, maximum in (("organization", 256), ("threat", 128)):
        value = _bounded_text(item[key], f"{label}.{key}", maximum)
        if value in {"N/A", "UNKNOWN", "unknown"}:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is not attested")
    for field in ("country", "asn", "organization", "threat"):
        if item[f"tui_{field}"] != item[field]:
            raise NativeCapabilityEvidenceError(f"{label}.{field} differs from the TUI")
    return item


def _validate_projection(
    raw: object,
    *,
    scenario_id: str,
    source_ip: str,
    attacks: list[dict[str, Any]],
    catalog_sha256: str,
    catalog_version: str,
    risk_model_version: str,
    reference_maximum: int,
) -> dict[str, Any]:
    label = "evidence.capabilities.tui_grc"
    item = _exact_mapping(
        raw,
        {
            "status",
            "scenario_id",
            "evidence_ref",
            "evidence_sha256",
            "source_ip",
            "physical_hits",
            "selected_jail",
            "jail_hits",
            "policy_hits",
            "tui_hits",
            "grc_hits",
            "tui_severity_score",
            "grc_severity_score",
            "tui_severity_label",
            "grc_severity_label",
            "metric_quality",
            "policy_quality",
            "hit_quality",
            "degraded_hits",
            "catalog_version",
            "catalog_sha256",
            "risk_model_version",
        },
        label,
    )
    _evidence_reference(item["evidence_ref"], f"{label}.evidence_ref", reference_maximum)
    _sha256(item["evidence_sha256"], f"{label}.evidence_sha256")
    selected = sorted(
        attacks,
        key=lambda attack: (
            -attack["severity_score"],
            -attack["policy_hits"],
            -attack["jail_hits"],
            attack["rule_id"],
        ),
    )[0]
    total_hits = sum(attack["physical_hits"] for attack in attacks)
    expected = {
        "status": "pass",
        "scenario_id": scenario_id,
        "source_ip": source_ip,
        "physical_hits": total_hits,
        "selected_jail": selected["rule_id"],
        "jail_hits": selected["jail_hits"],
        "policy_hits": selected["policy_hits"],
        "tui_hits": total_hits,
        "grc_hits": total_hits,
        "tui_severity_score": selected["severity_score"],
        "grc_severity_score": selected["severity_score"],
        "tui_severity_label": selected["severity_label"],
        "grc_severity_label": selected["severity_label"],
        "metric_quality": "attested",
        "policy_quality": "attested",
        "hit_quality": "measured",
        "degraded_hits": 0,
        "catalog_version": catalog_version,
        "catalog_sha256": catalog_sha256,
        "risk_model_version": risk_model_version,
    }
    for key, value in expected.items():
        if item[key] != value:
            raise NativeCapabilityEvidenceError(f"{label}.{key} is inconsistent")
    for key in (
        "physical_hits",
        "jail_hits",
        "policy_hits",
        "tui_hits",
        "grc_hits",
        "tui_severity_score",
        "grc_severity_score",
        "degraded_hits",
    ):
        _nonnegative_integer(item[key], f"{label}.{key}")
    return item


def _validate_lifecycle(
    raw: object,
    contract: dict[str, Any],
    attacks: dict[str, dict[str, Any]],
    started: dt.datetime,
    completed: dt.datetime,
    reference_maximum: int,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) != len(contract["lifecycle_sequences"]):
        raise NativeCapabilityEvidenceError("evidence lifecycle inventory is not exact")
    state_keys = {
        "state",
        "observed_at",
        "active",
        "expired",
        "deleted",
        "tombstoned",
        "currently_blocked",
        "tui_registry_visible",
        "tui_history_visible",
        "grc_state",
        "runtime_state_linked",
    }

    def validate_states(
        sequence: dict[str, Any],
        expected: dict[str, Any],
        label: str,
        earliest_active: dt.datetime,
    ) -> list[dt.datetime]:
        states = sequence["states"]
        if not isinstance(states, list) or len(states) != len(expected["states"]):
            raise NativeCapabilityEvidenceError(f"{label}.states inventory is not exact")
        previous_time: dt.datetime | None = None
        observed_times: list[dt.datetime] = []
        for state_index, state_name in enumerate(expected["states"]):
            state_label = f"{label}.states[{state_index}]"
            state = _exact_mapping(states[state_index], state_keys, state_label)
            observed = _canonical_timestamp(state["observed_at"], f"{state_label}.observed_at")
            if observed < started or observed > completed or (previous_time is not None and observed <= previous_time):
                raise NativeCapabilityEvidenceError(f"{state_label}.observed_at is outside ordered campaign time")
            previous_time = observed
            observed_times.append(observed)
            if state["state"] != state_name or state["grc_state"] != state_name:
                raise NativeCapabilityEvidenceError(f"{state_label} lifecycle state is incoherent")
            counts = {
                name: _nonnegative_integer(state[name], f"{state_label}.{name}")
                for name in ("active", "expired", "deleted", "tombstoned")
            }
            if sum(counts.values()) != 1 or counts[state_name] != 1:
                raise NativeCapabilityEvidenceError(f"{state_label} lifecycle counters are incoherent")
            blocked = _boolean(state["currently_blocked"], f"{state_label}.currently_blocked")
            registry = _boolean(state["tui_registry_visible"], f"{state_label}.tui_registry_visible")
            history = _boolean(state["tui_history_visible"], f"{state_label}.tui_history_visible")
            linked = _boolean(state["runtime_state_linked"], f"{state_label}.runtime_state_linked")
            if blocked != (state_name == "active") or registry != (state_name == "active") or not history or not linked:
                raise NativeCapabilityEvidenceError(f"{state_label} lifecycle projection is incoherent")
        if observed_times[0] < earliest_active:
            raise NativeCapabilityEvidenceError(
                f"{label} begins before its bound enforcement"
            )
        return observed_times

    deletion_contract = contract["lifecycle_sequences"][0]
    deletion_label = "evidence.lifecycle[0]"
    deletion = _exact_mapping(
        raw[0],
        {
            "id",
            "binding_type",
            "capability",
            "scenario_id",
            "source_ip",
            "rule_id",
            "attack_evidence_sha256",
            "evidence_ref",
            "evidence_sha256",
            "states",
        },
        deletion_label,
    )
    hips = attacks["hips"]
    expected_deletion = {
        "id": deletion_contract["id"],
        "binding_type": deletion_contract["binding_type"],
        "capability": deletion_contract["capability"],
        "scenario_id": deletion_contract["scenario_id"],
        "source_ip": hips["source_ip"],
        "rule_id": deletion_contract["rule_id"],
        "attack_evidence_sha256": hips["evidence_sha256"],
    }
    for key, value in expected_deletion.items():
        if deletion[key] != value:
            raise NativeCapabilityEvidenceError(
                f"{deletion_label}.{key} binding is invalid"
            )
    _evidence_reference(
        deletion["evidence_ref"],
        f"{deletion_label}.evidence_ref",
        reference_maximum,
    )
    _sha256(deletion["evidence_sha256"], f"{deletion_label}.evidence_sha256")
    _sha256(
        deletion["attack_evidence_sha256"],
        f"{deletion_label}.attack_evidence_sha256",
    )
    hips_enforced = _canonical_timestamp(
        hips["enforced_at"], "evidence.capabilities.hips.enforced_at"
    )
    manual_times = validate_states(
        deletion, deletion_contract, deletion_label, hips_enforced
    )

    waap_first = _canonical_timestamp(
        attacks["waap"]["first_observed_at"],
        "evidence.capabilities.waap.first_observed_at",
    )
    if manual_times[-1] > waap_first:
        raise NativeCapabilityEvidenceError(
            "WAAP observation begins before the HIPS ban deletion is complete"
        )

    temporary_contract = contract["lifecycle_sequences"][1]
    temporary_label = "evidence.lifecycle[1]"
    temporary = _exact_mapping(
        raw[1],
        {
            "id",
            "binding_type",
            "source_ip",
            "source_controlled",
            "source",
            "requested_ttl_seconds",
            "requested_at",
            "enforced_at",
            "trigger_evidence_ref",
            "trigger_evidence_sha256",
            "evidence_ref",
            "evidence_sha256",
            "states",
        },
        temporary_label,
    )
    expected_temporary = {
        "id": temporary_contract["id"],
        "binding_type": temporary_contract["binding_type"],
        "source": temporary_contract["source"],
        "requested_ttl_seconds": temporary_contract["ttl_seconds"],
        "source_controlled": True,
    }
    for key, value in expected_temporary.items():
        if temporary[key] != value:
            raise NativeCapabilityEvidenceError(
                f"{temporary_label}.{key} binding is invalid"
            )
    temporary_source = _public_address(
        temporary["source_ip"], f"{temporary_label}.source_ip"
    )
    if temporary_source in {hips["source_ip"], attacks["waap"]["source_ip"]}:
        raise NativeCapabilityEvidenceError(
            f"{temporary_label}.source_ip must be independent from attack bans"
        )
    _boolean(temporary["source_controlled"], f"{temporary_label}.source_controlled")
    ttl_seconds = _positive_integer(
        temporary["requested_ttl_seconds"],
        f"{temporary_label}.requested_ttl_seconds",
        contract["limits"]["maximum_campaign_seconds"],
    )
    requested_at = _canonical_timestamp(
        temporary["requested_at"], f"{temporary_label}.requested_at"
    )
    temporary_enforced = _canonical_timestamp(
        temporary["enforced_at"], f"{temporary_label}.enforced_at"
    )
    waap_enforced = _canonical_timestamp(
        attacks["waap"]["enforced_at"],
        "evidence.capabilities.waap.enforced_at",
    )
    if not (
        started <= requested_at <= temporary_enforced <= completed
        and requested_at >= waap_enforced
    ):
        raise NativeCapabilityEvidenceError(
            f"{temporary_label} trigger times are incoherent"
        )
    for field in ("trigger_evidence_ref", "evidence_ref"):
        _evidence_reference(
            temporary[field], f"{temporary_label}.{field}", reference_maximum
        )
    for field in ("trigger_evidence_sha256", "evidence_sha256"):
        _sha256(temporary[field], f"{temporary_label}.{field}")
    temporary_times = validate_states(
        temporary,
        temporary_contract,
        temporary_label,
        temporary_enforced,
    )
    expiry_not_before = temporary_enforced + dt.timedelta(seconds=ttl_seconds)
    if temporary_times[1] < expiry_not_before:
        raise NativeCapabilityEvidenceError(
            f"{temporary_label} expires before its requested TTL"
        )
    return [deletion, temporary]


def _validate_extended_controls(
    raw: object,
    contract: dict[str, Any],
    package_variant: str,
    candidate_commit: str,
    scenario_id: str,
    started: dt.datetime,
    completed: dt.datetime,
    reference_maximum: int,
) -> dict[str, Any]:
    label = "evidence.capabilities.extended_controls"
    item = _exact_mapping(raw, {"status", "scenario_id", "controls"}, label)
    if item["status"] != "pass" or item["scenario_id"] != scenario_id:
        raise NativeCapabilityEvidenceError(f"{label} identity is invalid")
    controls = item["controls"]
    expected_controls = list(contract["native_controls"])
    if package_variant == "package-owned":
        expected_controls.extend(contract["package_owned_controls"])
    if not isinstance(controls, list) or len(controls) != len(expected_controls):
        raise NativeCapabilityEvidenceError(f"{label}.controls inventory is not exact")
    previous: dt.datetime | None = None
    for index, expected in enumerate(expected_controls):
        control_label = f"{label}.controls[{index}]"
        control = _exact_mapping(
            controls[index],
            {"id", "status", "candidate_commit", "observed_at", "evidence_ref", "evidence_sha256", "assertions"},
            control_label,
        )
        if (
            control["id"] != expected["id"]
            or control["status"] != "pass"
            or control["candidate_commit"] != candidate_commit
            or control["assertions"] != expected["assertions"]
            or not isinstance(control["assertions"], dict)
            or any(
                key not in control["assertions"]
                or type(control["assertions"][key]) is not type(expected_value)
                for key, expected_value in expected["assertions"].items()
            )
        ):
            raise NativeCapabilityEvidenceError(f"{control_label} binding is invalid")
        _candidate_commit(control["candidate_commit"], f"{control_label}.candidate_commit")
        observed = _canonical_timestamp(control["observed_at"], f"{control_label}.observed_at")
        if observed < started or observed > completed or (previous is not None and observed <= previous):
            raise NativeCapabilityEvidenceError(f"{control_label}.observed_at is outside ordered campaign time")
        previous = observed
        _evidence_reference(control["evidence_ref"], f"{control_label}.evidence_ref", reference_maximum)
        _sha256(control["evidence_sha256"], f"{control_label}.evidence_sha256")
    return item


def validate_evidence_document(
    raw: object,
    *,
    campaign: dict[str, Any],
    contract: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    validation_time: dt.datetime,
    artifact_root: Path,
) -> dict[str, Any]:
    evidence = _exact_mapping(
        raw,
        {
            "schema_version",
            "schema_id",
            "contract_id",
            "contract_sha256",
            "target_release",
            "candidate_commit",
            "campaign_id",
            "profile_id",
            "evidence_namespace",
            "package_binding",
            "host_attestation_sha256",
            "signature_catalog_sha256",
            "started_at",
            "completed_at",
            "guardrails",
            "capabilities",
            "lifecycle",
            "verdict",
        },
        "evidence",
    )
    expected_bindings = {
        "schema_version": 1,
        "schema_id": EVIDENCE_SCHEMA,
        "contract_id": campaign["contract_id"],
        "contract_sha256": campaign["contract_sha256"],
        "target_release": campaign["target_release"],
        "candidate_commit": campaign["candidate_commit"],
        "campaign_id": campaign["campaign_id"],
        "profile_id": campaign["host"]["profile_id"],
        "evidence_namespace": campaign["host"]["evidence_namespace"],
        "package_binding": campaign["host"]["package_binding"],
        "host_attestation_sha256": campaign["host"]["attestation_sha256"],
        "signature_catalog_sha256": campaign["signature_catalog"]["sha256"],
        "verdict": "pass",
    }
    for key, value in expected_bindings.items():
        if evidence[key] != value:
            raise NativeCapabilityEvidenceError(f"evidence {key} binding is invalid")
    if type(evidence["schema_version"]) is not int:
        raise NativeCapabilityEvidenceError("evidence schema type is invalid")
    _validate_package_binding(
        evidence["package_binding"],
        campaign["host"]["package_binding"],
        "evidence.package_binding",
    )
    started = _canonical_timestamp(evidence["started_at"], "evidence.started_at")
    completed = _canonical_timestamp(evidence["completed_at"], "evidence.completed_at")
    created = _canonical_timestamp(campaign["created_at"], "campaign.created_at")
    maximum_duration = dt.timedelta(seconds=contract["limits"]["maximum_campaign_seconds"])
    future_skew = dt.timedelta(seconds=contract["limits"]["maximum_future_skew_seconds"])
    if started < created or completed <= started or completed - started > maximum_duration:
        raise NativeCapabilityEvidenceError("evidence campaign timestamps are incoherent")
    if not isinstance(validation_time, dt.datetime) or validation_time.tzinfo is None:
        raise NativeCapabilityEvidenceError("validation time must have a timezone")
    if completed > validation_time.astimezone(dt.timezone.utc) + future_skew:
        raise NativeCapabilityEvidenceError("evidence completion timestamp is in the future")
    guardrails = _exact_mapping(
        evidence["guardrails"],
        {
            "authentication_journal_access",
            "authentication_event_source",
            "synthetic_authentication_journal_writes",
            "native_lab_executed",
            "host_changes",
            "baseline_restored",
        },
        "evidence.guardrails",
    )
    expected_guardrails = {
        "authentication_journal_access": contract["guardrails"]["authentication_journal_access"],
        "authentication_event_source": contract["guardrails"]["authentication_event_source"],
        "synthetic_authentication_journal_writes": False,
        "native_lab_executed": True,
        "host_changes": contract["guardrails"]["host_changes"],
        "baseline_restored": True,
    }
    if guardrails != expected_guardrails:
        raise NativeCapabilityEvidenceError("evidence guardrails are not satisfied")

    expected_capabilities = [item["id"] for item in contract["capabilities"]]
    capabilities = _exact_mapping(
        evidence["capabilities"], set(expected_capabilities), "evidence.capabilities"
    )
    scenario_by_capability = {
        item["id"]: item["scenario_id"] for item in contract["capabilities"]
    }
    reference_maximum = contract["limits"]["maximum_evidence_reference_bytes"]
    attack_contracts = {item["capability"]: item for item in contract["attack_scenarios"]}
    hips = _validate_attack(
        capabilities["hips"], attack_contracts["hips"], rules,
        "evidence.capabilities.hips", reference_maximum, started, completed,
    )
    waap = _validate_attack(
        capabilities["waap"], attack_contracts["waap"], rules,
        "evidence.capabilities.waap", reference_maximum, started, completed,
    )
    if hips["source_ip"] != waap["source_ip"]:
        raise NativeCapabilityEvidenceError("HIPS and WAAP must use the same controlled source")
    _validate_hids(
        capabilities["hids"], scenario_by_capability["hids"], hips, reference_maximum
    )
    source_ip = hips["source_ip"]
    asn = _validate_enrichment(
        capabilities["asn"], capability="asn", scenario_id=scenario_by_capability["asn"],
        source_ip=source_ip, reference_maximum=reference_maximum,
    )
    geo = _validate_enrichment(
        capabilities["geo"], capability="geo", scenario_id=scenario_by_capability["geo"],
        source_ip=source_ip, reference_maximum=reference_maximum,
    )
    total_hits = hips["physical_hits"] + waap["physical_hits"]
    _validate_osint(
        capabilities["osint"], scenario_id=scenario_by_capability["osint"],
        source_ip=source_ip, asn=asn["value"], country=geo["value"],
        physical_hits=total_hits, reference_maximum=reference_maximum,
    )
    _validate_projection(
        capabilities["tui_grc"], scenario_id=scenario_by_capability["tui_grc"],
        source_ip=source_ip, attacks=[hips, waap],
        catalog_sha256=campaign["signature_catalog"]["sha256"],
        catalog_version=campaign["signature_catalog"]["catalog_version"],
        risk_model_version=campaign["signature_catalog"]["risk_model_version"],
        reference_maximum=reference_maximum,
    )
    _validate_extended_controls(
        capabilities["extended_controls"], contract,
        campaign["host"]["package_binding"]["package_variant"],
        campaign["candidate_commit"],
        scenario_by_capability["extended_controls"], started, completed,
        reference_maximum,
    )
    _validate_lifecycle(
        evidence["lifecycle"],
        contract,
        {"hips": hips, "waap": waap},
        started,
        completed,
        reference_maximum,
    )
    _validate_evidence_artifacts(
        evidence, artifact_root, contract["limits"]["maximum_input_bytes"]
    )
    return evidence


def build_bound_evidence(
    *,
    candidate_commit: str,
    campaign_path: Path,
    observations_path: Path,
    artifact_root: Path,
    host_attestation_path: Path,
    signing_bundle_path: Path,
    signature_catalog_path: Path = DEFAULT_SIGNATURE_CATALOG,
    contract_path: Path = DEFAULT_CONTRACT,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    contract, _ = load_contract(contract_path)
    maximum = contract["limits"]["maximum_input_bytes"]
    campaign_raw, _ = _load_json(campaign_path, maximum, "campaign")
    campaign, contract, rules = _validate_campaign(
        campaign_raw,
        candidate_commit=candidate_commit,
        host_attestation_path=host_attestation_path,
        signing_bundle_path=signing_bundle_path,
        signature_catalog_path=signature_catalog_path,
        contract_path=contract_path,
    )
    observations_raw, _ = _load_json(observations_path, maximum, "native observations")
    observations = _exact_mapping(
        observations_raw,
        {"started_at", "completed_at", "guardrails", "capabilities", "lifecycle"},
        "native observations",
    )
    evidence = {
        "schema_version": 1,
        "schema_id": EVIDENCE_SCHEMA,
        "contract_id": campaign["contract_id"],
        "contract_sha256": campaign["contract_sha256"],
        "target_release": campaign["target_release"],
        "candidate_commit": campaign["candidate_commit"],
        "campaign_id": campaign["campaign_id"],
        "profile_id": campaign["host"]["profile_id"],
        "evidence_namespace": campaign["host"]["evidence_namespace"],
        "package_binding": campaign["host"]["package_binding"],
        "host_attestation_sha256": campaign["host"]["attestation_sha256"],
        "signature_catalog_sha256": campaign["signature_catalog"]["sha256"],
        "started_at": observations["started_at"],
        "completed_at": observations["completed_at"],
        "guardrails": observations["guardrails"],
        "capabilities": observations["capabilities"],
        "lifecycle": observations["lifecycle"],
        "verdict": "pass",
    }
    validate_evidence_document(
        evidence,
        campaign=campaign,
        contract=contract,
        rules=rules,
        validation_time=validation_time or dt.datetime.now(dt.timezone.utc),
        artifact_root=artifact_root,
    )
    return evidence


def validate_evidence_file(
    *,
    candidate_commit: str,
    campaign_path: Path,
    evidence_path: Path,
    artifact_root: Path,
    host_attestation_path: Path,
    signing_bundle_path: Path,
    signature_catalog_path: Path = DEFAULT_SIGNATURE_CATALOG,
    contract_path: Path = DEFAULT_CONTRACT,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    contract, _ = load_contract(contract_path)
    maximum = contract["limits"]["maximum_input_bytes"]
    campaign_raw, campaign_wire = _load_json(campaign_path, maximum, "campaign")
    campaign, contract, rules = _validate_campaign(
        campaign_raw,
        candidate_commit=candidate_commit,
        host_attestation_path=host_attestation_path,
        signing_bundle_path=signing_bundle_path,
        signature_catalog_path=signature_catalog_path,
        contract_path=contract_path,
    )
    evidence_raw, evidence_wire = _load_json(evidence_path, maximum, "evidence")
    validate_evidence_document(
        evidence_raw,
        campaign=campaign,
        contract=contract,
        rules=rules,
        validation_time=validation_time or dt.datetime.now(dt.timezone.utc),
        artifact_root=artifact_root,
    )
    return {
        "schema_version": 1,
        "schema_id": VERDICT_SCHEMA,
        "contract_id": campaign["contract_id"],
        "contract_sha256": campaign["contract_sha256"],
        "target_release": campaign["target_release"],
        "candidate_commit": candidate_commit,
        "campaign_id": campaign["campaign_id"],
        "host_id": campaign["host"]["host_id"],
        "profile_id": campaign["host"]["profile_id"],
        "evidence_namespace": campaign["host"]["evidence_namespace"],
        "package_binding": campaign["host"]["package_binding"],
        "host_attestation_sha256": campaign["host"]["attestation_sha256"],
        "signature_catalog_sha256": campaign["signature_catalog"]["sha256"],
        "campaign_sha256": hashlib.sha256(campaign_wire).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_wire).hexdigest(),
        "evidence_artifact_set_sha256": _artifact_binding_sha256(evidence_raw),
        "capabilities": [item["id"] for item in contract["capabilities"]],
        "lifecycle_sequences": [
            item["id"] for item in contract["lifecycle_sequences"]
        ],
        "verdict": "pass",
        "blockers": [],
    }


def aggregate_verdicts(
    *,
    candidate_commit: str,
    verdict_paths: Sequence[Path],
    signing_bundle_path: Path,
    contract_path: Path = DEFAULT_CONTRACT,
) -> dict[str, Any]:
    contract, contract_wire = load_contract(contract_path)
    contract_sha256 = hashlib.sha256(contract_wire).hexdigest()
    _candidate_commit(candidate_commit)
    package_bindings = _load_package_bindings(
        signing_bundle_path, candidate_commit, contract
    )
    expected_profiles = [profile["id"] for profile in contract["host_profiles"]]
    expected_hosts = {
        profile["id"]: profile["host_id"] for profile in contract["host_profiles"]
    }
    if len(verdict_paths) != len(expected_profiles):
        raise NativeCapabilityEvidenceError("native verdict profile inventory is incomplete")
    maximum = contract["limits"]["maximum_input_bytes"]
    expected_capabilities = [item["id"] for item in contract["capabilities"]]
    expected_lifecycle = [item["id"] for item in contract["lifecycle_sequences"]]
    by_profile: dict[str, dict[str, Any]] = {}
    campaign_ids: set[str] = set()
    host_attestations: set[str] = set()
    campaign_digests: set[str] = set()
    evidence_digests: set[str] = set()
    evidence_artifact_sets: set[str] = set()
    signature_catalog_sha256 = ""
    for index, path in enumerate(verdict_paths):
        raw, _ = _load_json(path, maximum, f"native verdict {index}")
        verdict = _exact_mapping(
            raw,
            {
                "schema_version",
                "schema_id",
                "contract_id",
                "contract_sha256",
                "target_release",
                "candidate_commit",
                "campaign_id",
                "host_id",
                "profile_id",
                "evidence_namespace",
                "package_binding",
                "host_attestation_sha256",
                "signature_catalog_sha256",
                "campaign_sha256",
                "evidence_sha256",
                "evidence_artifact_set_sha256",
                "capabilities",
                "lifecycle_sequences",
                "verdict",
                "blockers",
            },
            f"native verdict {index}",
        )
        expected = {
            "schema_version": 1,
            "schema_id": VERDICT_SCHEMA,
            "contract_id": contract["contract_id"],
            "contract_sha256": contract_sha256,
            "target_release": contract["target_release"],
            "candidate_commit": candidate_commit,
            "capabilities": expected_capabilities,
            "lifecycle_sequences": expected_lifecycle,
            "verdict": "pass",
            "blockers": [],
        }
        for key, value in expected.items():
            if verdict[key] != value:
                raise NativeCapabilityEvidenceError(f"native verdict {index} {key} is invalid")
        if type(verdict["schema_version"]) is not int:
            raise NativeCapabilityEvidenceError(f"native verdict {index} schema type is invalid")
        for field in ("campaign_id", "host_id"):
            _identifier(verdict[field], f"native verdict {index} {field}")
        for field in (
            "host_attestation_sha256",
            "signature_catalog_sha256",
            "campaign_sha256",
            "evidence_sha256",
            "evidence_artifact_set_sha256",
        ):
            _sha256(verdict[field], f"native verdict {index} {field}")
        profile_id = verdict["profile_id"]
        if profile_id not in expected_profiles or profile_id in by_profile:
            raise NativeCapabilityEvidenceError("native verdict profiles are unknown or duplicated")
        if verdict["host_id"] != expected_hosts[profile_id]:
            raise NativeCapabilityEvidenceError(
                "native verdict host is not bound to its profile"
            )
        profile = _profile_map(contract)[profile_id]
        if verdict["evidence_namespace"] != profile["evidence_namespace"]:
            raise NativeCapabilityEvidenceError(
                "native verdict evidence namespace is not bound to its profile"
            )
        if not verdict["campaign_id"].startswith(
            profile["evidence_namespace"] + "-"
        ):
            raise NativeCapabilityEvidenceError(
                "native verdict campaign is outside its profile namespace"
            )
        _validate_package_binding(
            verdict["package_binding"],
            package_bindings[profile_id],
            f"native verdict {index} package_binding",
        )
        if (
            verdict["campaign_id"] in campaign_ids
            or verdict["host_attestation_sha256"] in host_attestations
            or verdict["campaign_sha256"] in campaign_digests
            or verdict["evidence_sha256"] in evidence_digests
            or verdict["evidence_artifact_set_sha256"] in evidence_artifact_sets
        ):
            raise NativeCapabilityEvidenceError(
                "native verdict attestation, campaign, evidence, or raw artifact set is duplicated"
            )
        if signature_catalog_sha256 and verdict["signature_catalog_sha256"] != signature_catalog_sha256:
            raise NativeCapabilityEvidenceError("native verdict signature catalogs differ")
        signature_catalog_sha256 = verdict["signature_catalog_sha256"]
        campaign_ids.add(verdict["campaign_id"])
        host_attestations.add(verdict["host_attestation_sha256"])
        campaign_digests.add(verdict["campaign_sha256"])
        evidence_digests.add(verdict["evidence_sha256"])
        evidence_artifact_sets.add(verdict["evidence_artifact_set_sha256"])
        by_profile[profile_id] = verdict
    if set(by_profile) != set(expected_profiles):
        raise NativeCapabilityEvidenceError("native verdict profile inventory is incomplete")
    return {
        "schema_version": 1,
        "schema_id": AGGREGATE_SCHEMA,
        "contract_id": contract["contract_id"],
        "contract_sha256": contract_sha256,
        "target_release": contract["target_release"],
        "candidate_commit": candidate_commit,
        "signature_catalog_sha256": signature_catalog_sha256,
        "profiles": [
            {
                "profile_id": profile_id,
                "host_id": by_profile[profile_id]["host_id"],
                "campaign_id": by_profile[profile_id]["campaign_id"],
                "evidence_namespace": by_profile[profile_id]["evidence_namespace"],
                "package_binding": by_profile[profile_id]["package_binding"],
                "host_attestation_sha256": by_profile[profile_id]["host_attestation_sha256"],
                "campaign_sha256": by_profile[profile_id]["campaign_sha256"],
                "evidence_sha256": by_profile[profile_id]["evidence_sha256"],
                "evidence_artifact_set_sha256": by_profile[profile_id]["evidence_artifact_set_sha256"],
            }
            for profile_id in expected_profiles
        ],
        "capabilities": expected_capabilities,
        "lifecycle_sequences": expected_lifecycle,
        "verdict": "pass",
        "blockers": [],
    }


def _write_new_json(path: Path, document: object) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or not path.name
        or path.name in {".", ".."}
    ):
        raise NativeCapabilityEvidenceError("output path must be absolute and canonical")
    parent = path.parent
    try:
        wire = (
            json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise NativeCapabilityEvidenceError("output document is not strict JSON") from exc
    if not wire or len(wire) > OUTPUT_MAXIMUM_BYTES:
        raise NativeCapabilityEvidenceError("output document size is outside bounds")
    parent_descriptor, opened_parent, parent_identity = _open_real_directory(
        parent, "output parent"
    )
    if opened_parent != parent:
        os.close(parent_descriptor)
        raise NativeCapabilityEvidenceError("output parent must be absolute and canonical")
    descriptor = -1
    temporary = ""
    published = False
    completed = False
    published_identity: tuple[int, int] | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        for _ in range(64):
            temporary = f".syswarden-native-capability-{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    temporary,
                    flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0:
            raise NativeCapabilityEvidenceError(
                "cannot allocate a unique temporary output"
            )
        os.fchmod(descriptor, 0o600)
        stream = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = -1
        with stream:
            stream.write(wire)
            stream.flush()
            os.fsync(stream.fileno())
            written_info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(written_info.st_mode)
                or written_info.st_nlink != 1
                or written_info.st_size != len(wire)
                or stat.S_IMODE(written_info.st_mode) != 0o600
            ):
                raise NativeCapabilityEvidenceError("temporary output is unsafe")
            temporary_identity = _directory_identity(written_info)
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise NativeCapabilityEvidenceError(
                    "output must not already exist"
                ) from exc
            raise
        published = True
        published_identity = temporary_identity
        temporary_info = os.stat(
            temporary, dir_fd=parent_descriptor, follow_symlinks=False
        )
        output_info = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(output_info.st_mode)
            or temporary_info.st_nlink != 2
            or output_info.st_nlink != 2
            or temporary_identity is None
            or _directory_identity(temporary_info) != temporary_identity
            or _directory_identity(temporary_info)
            != _directory_identity(output_info)
        ):
            raise NativeCapabilityEvidenceError(
                "output changed while publishing"
            )
        os.unlink(temporary, dir_fd=parent_descriptor)
        temporary = ""
        final_info = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(final_info.st_mode)
            or final_info.st_nlink != 1
            or final_info.st_size != len(wire)
            or stat.S_IMODE(final_info.st_mode) != 0o600
        ):
            raise NativeCapabilityEvidenceError("published output is unsafe")
        published_wire = _read_regular_bytes_at(
            parent_descriptor,
            path.name,
            str(path),
            OUTPUT_MAXIMUM_BYTES,
        )
        if not secrets.compare_digest(published_wire, wire):
            raise NativeCapabilityEvidenceError("published output content changed")
        _verify_directory_binding(parent, parent_identity, "output parent")
        os.fsync(parent_descriptor)
        completed = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        if published and not completed and published_identity is not None:
            try:
                output_info = os.stat(
                    path.name, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if _directory_identity(output_info) == published_identity:
                    os.unlink(path.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare", help="prepare one candidate-bound native campaign")
    prepare.add_argument("--candidate-commit", required=True)
    prepare.add_argument("--campaign-id", required=True)
    prepare.add_argument("--created-at", required=True)
    prepare.add_argument("--host-attestation", type=Path, required=True)
    prepare.add_argument("--signing-bundle", type=Path, required=True)
    prepare.add_argument("--signature-catalog", type=Path, default=DEFAULT_SIGNATURE_CATALOG)
    prepare.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    prepare.add_argument("--output", type=Path, required=True)
    bind = subparsers.add_parser("bind", help="bind and validate native observations")
    bind.add_argument("--candidate-commit", required=True)
    bind.add_argument("--campaign", type=Path, required=True)
    bind.add_argument("--observations", type=Path, required=True)
    bind.add_argument("--artifact-root", type=Path, required=True)
    bind.add_argument("--host-attestation", type=Path, required=True)
    bind.add_argument("--signing-bundle", type=Path, required=True)
    bind.add_argument("--signature-catalog", type=Path, default=DEFAULT_SIGNATURE_CATALOG)
    bind.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    bind.add_argument("--validation-time")
    bind.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate", help="validate bound native evidence")
    validate.add_argument("--candidate-commit", required=True)
    validate.add_argument("--campaign", type=Path, required=True)
    validate.add_argument("--evidence", type=Path, required=True)
    validate.add_argument("--artifact-root", type=Path, required=True)
    validate.add_argument("--host-attestation", type=Path, required=True)
    validate.add_argument("--signing-bundle", type=Path, required=True)
    validate.add_argument("--signature-catalog", type=Path, default=DEFAULT_SIGNATURE_CATALOG)
    validate.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    validate.add_argument("--validation-time")
    validate.add_argument("--output", type=Path, required=True)
    aggregate = subparsers.add_parser(
        "aggregate", help="aggregate the exact native host verdict inventory"
    )
    aggregate.add_argument("--candidate-commit", required=True)
    aggregate.add_argument("--verdict", type=Path, action="append", required=True)
    aggregate.add_argument("--signing-bundle", type=Path, required=True)
    aggregate.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    aggregate.add_argument("--output", type=Path, required=True)
    return parser


def _validation_time(value: str | None) -> dt.datetime | None:
    return None if value is None else _canonical_timestamp(value, "validation_time")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "prepare":
            document = build_campaign(
                candidate_commit=arguments.candidate_commit,
                campaign_id=arguments.campaign_id,
                created_at=arguments.created_at,
                host_attestation_path=arguments.host_attestation,
                signing_bundle_path=arguments.signing_bundle,
                signature_catalog_path=arguments.signature_catalog,
                contract_path=arguments.contract,
            )
        elif arguments.command == "bind":
            document = build_bound_evidence(
                candidate_commit=arguments.candidate_commit,
                campaign_path=arguments.campaign,
                observations_path=arguments.observations,
                artifact_root=arguments.artifact_root,
                host_attestation_path=arguments.host_attestation,
                signing_bundle_path=arguments.signing_bundle,
                signature_catalog_path=arguments.signature_catalog,
                contract_path=arguments.contract,
                validation_time=_validation_time(arguments.validation_time),
            )
        elif arguments.command == "validate":
            document = validate_evidence_file(
                candidate_commit=arguments.candidate_commit,
                campaign_path=arguments.campaign,
                evidence_path=arguments.evidence,
                artifact_root=arguments.artifact_root,
                host_attestation_path=arguments.host_attestation,
                signing_bundle_path=arguments.signing_bundle,
                signature_catalog_path=arguments.signature_catalog,
                contract_path=arguments.contract,
                validation_time=_validation_time(arguments.validation_time),
            )
        else:
            document = aggregate_verdicts(
                candidate_commit=arguments.candidate_commit,
                verdict_paths=arguments.verdict,
                signing_bundle_path=arguments.signing_bundle,
                contract_path=arguments.contract,
            )
        _write_new_json(arguments.output, document)
        return 0
    except (OSError, NativeCapabilityEvidenceError) as exc:
        print(f"native capability evidence: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
