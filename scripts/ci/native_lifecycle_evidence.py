#!/usr/bin/env python3
"""Validate real native package lifecycle evidence for the v4.10.0 profiles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "scripts/ci/native_lifecycle_contract_v4.10.0.json"
CONTRACT_SHA256 = "9fe39c5d1529a809e0e76e1db3601af2596c4d30d5aeeb80898104de464da7ad"
OBSERVATION_SCHEMA = "syswarden-native-package-lifecycle-observation/v1"
VERDICT_SCHEMA = "syswarden-native-package-lifecycle-verdict/v1"
REPOSITORY = "duggytuxy/syswarden"
TARGET_RELEASE = "v4.10.0"
BASELINE_RELEASE = "v4.04.3"
BASELINE_COMMIT = "381c1f8d91459a9b20605629c725900abd81dee8"
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPENPGP_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{1,255}$")
CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RAW_REFERENCE = re.compile(
    r"^(DEB-U2604|RPM-A9|APK-324|RPM-A9-RHELPO|RPM-A10-RHELPO)/raw/"
    r"[a-z0-9][a-z0-9._-]{0,95}\.json$"
)
UTC = re.compile(
    r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
EXPECTED_PROFILES = (
    {
        "id": "DEB-U2604",
        "host_id": "node02",
        "os_id": "ubuntu",
        "os_version": "26.04",
        "package_family": "deb",
        "package_variant": "standard",
        "installation_mode": "native-live-host",
        "package_manager": "dpkg",
        "service_manager": "systemd",
        "firewall_backend": "nftables",
        "candidate_signature_mechanism": "openpgp-detached",
    },
    {
        "id": "RPM-A9",
        "host_id": "node05",
        "os_id": "almalinux",
        "os_version": "9.8",
        "package_family": "rpm",
        "package_variant": "standard",
        "installation_mode": "native-live-host",
        "package_manager": "rpm",
        "service_manager": "systemd",
        "firewall_backend": "nftables",
        "candidate_signature_mechanism": "rpm-openpgp",
    },
    {
        "id": "APK-324",
        "host_id": "node04",
        "os_id": "alpine",
        "os_version": "3.24",
        "package_family": "apk",
        "package_variant": "standard",
        "installation_mode": "native-live-host",
        "package_manager": "apk",
        "service_manager": "openrc",
        "firewall_backend": "nftables",
        "candidate_signature_mechanism": "apk-rsa256",
    },
    {
        "id": "RPM-A9-RHELPO",
        "host_id": "node05",
        "os_id": "almalinux",
        "os_version": "9.8",
        "package_family": "rpm",
        "package_variant": "rhel-package-owned",
        "installation_mode": "offline-chroot-first-boot",
        "package_manager": "rpm",
        "service_manager": "systemd",
        "firewall_backend": "nftables",
        "candidate_signature_mechanism": "rpm-openpgp",
    },
    {
        "id": "RPM-A10-RHELPO",
        "host_id": "node03",
        "os_id": "almalinux",
        "os_version": "10.2",
        "package_family": "rpm",
        "package_variant": "rhel-package-owned",
        "installation_mode": "offline-chroot-first-boot",
        "package_manager": "rpm",
        "service_manager": "systemd",
        "firewall_backend": "nftables",
        "candidate_signature_mechanism": "rpm-openpgp",
    },
)
RHEL_PACKAGE_OWNED_SCENARIO_CHECKS = {
    "candidate-clean-install": [
        "offline_chroot_stage_succeeded",
        "active_systemd_not_required_during_stage",
        "package_owned_units_installed",
        "package_owned_configuration_installed",
        "package_owned_firewall_assets_installed",
        "first_real_boot_observed",
        "first_real_boot_services_activated",
        "first_real_boot_firewall_activated",
    ]
}
EXPECTED_PROFILE_SCENARIO_CHECKS = {
    "RPM-A9-RHELPO": RHEL_PACKAGE_OWNED_SCENARIO_CHECKS,
    "RPM-A10-RHELPO": RHEL_PACKAGE_OWNED_SCENARIO_CHECKS,
}
STANDARD_SIGNING_PROFILE = "syswarden-native-package-signing/v4.10.0"
RHEL_PACKAGE_OWNED_SIGNING_PROFILE = (
    "syswarden-rhel-package-owned-signing/v4.10.0"
)
BASELINE_TRUST = {
    "baseline_origin": "github-release-v4.04.3",
    "baseline_digest_source": "release-sha256sums",
    "baseline_release_id": 384037482,
    "baseline_tag_object": "2f37c7e61c68c1d07318ab0286a9eedff54725be",
    "baseline_tag_signature": {
        "mechanism": "ssh",
        "payload_sha256": (
            "0cac52c6cef90d1aa42b322204afbd7aa20399a4c2ac28dd29d8a3631b9b2dbc"
        ),
        "signature_sha256": (
            "dc62181289036f6022d7a1ab8bdacc2aa00d8aaa4caf303d9d7d466050f70182"
        ),
        "status": "verified",
        "verified_at": "2026-09-07T11:10:46Z",
    },
    "baseline_checksum_asset": {
        "id": 548677391,
        "name": "SHA256SUMS.txt",
        "sha256": (
            "331bd7ae9d8afeee7e9a76f0925b057d12287215574c5dc11bb891912cc755d0"
        ),
        "size": 283,
    },
    "baseline_packages": {
        "apk": {
            "id": 548677418,
            "name": "syswarden_4.04.3_x86_64.apk",
            "sha256": (
                "adab88015ac97d6c351a4e4cecae85658bceca1af047b83055fec3fa091e1538"
            ),
            "size": 15327844,
        },
        "deb": {
            "id": 548677417,
            "name": "syswarden_4.04.3_amd64.deb",
            "sha256": (
                "e9ea3252de5668eaa10794333b4cb533a0acedfeac60105b50e512aa915b2612"
            ),
            "size": 15129624,
        },
        "rpm": {
            "id": 548677392,
            "name": "syswarden-4.04.3-1.x86_64.rpm",
            "sha256": (
                "15271aecd6bc5801eb80387a2e40928ac5cf8851cf2da9899fa1a0905efae4fd"
            ),
            "size": 15415655,
        },
    },
    "candidate_origin": "protected-native-signing-artifact",
    "candidate_digest_source": "native-signing-provenance",
    "verification_timing": "before-every-installation",
}
PACKAGE_NAMES = {
    ("DEB-U2604", BASELINE_RELEASE): "syswarden_4.04.3_amd64.deb",
    ("DEB-U2604", TARGET_RELEASE): "syswarden_4.10.0_amd64.deb",
    ("RPM-A9", BASELINE_RELEASE): "syswarden-4.04.3-1.x86_64.rpm",
    ("RPM-A9", TARGET_RELEASE): "syswarden-4.10.0-1.x86_64.rpm",
    ("APK-324", BASELINE_RELEASE): "syswarden_4.04.3_x86_64.apk",
    ("APK-324", TARGET_RELEASE): "syswarden_4.10.0_x86_64.apk",
    ("RPM-A9-RHELPO", BASELINE_RELEASE): "syswarden-4.04.3-1.x86_64.rpm",
    ("RPM-A9-RHELPO", TARGET_RELEASE): (
        "syswarden-4.10.0-1.rhelpo.x86_64.rpm"
    ),
    ("RPM-A10-RHELPO", BASELINE_RELEASE): "syswarden-4.04.3-1.x86_64.rpm",
    ("RPM-A10-RHELPO", TARGET_RELEASE): (
        "syswarden-4.10.0-1.rhelpo.x86_64.rpm"
    ),
}


class LifecycleEvidenceError(ValueError):
    """Raised when native lifecycle evidence is incomplete or unsafe."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _identity(item: os.stat_result) -> tuple[int, ...]:
    return (
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


def _regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise LifecycleEvidenceError(f"cannot inspect {label}: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise LifecycleEvidenceError(f"{label} must be one regular file: {path}")
    if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022:
        raise LifecycleEvidenceError(f"{label} ownership or mode is unsafe: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise LifecycleEvidenceError(f"{label} size is outside bounds: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleEvidenceError(f"cannot safely open {label}: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise LifecycleEvidenceError(f"{label} changed while opening: {path}")
        wire = bytearray()
        while len(wire) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(wire)))
            if not chunk:
                break
            wire.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = path.lstat()
    except OSError as exc:
        raise LifecycleEvidenceError(f"{label} namespace changed: {path}") from exc
    if (
        len(wire) != before.st_size
        or len(wire) > maximum
        or _identity(after) != _identity(opened)
        or _identity(named_after) != _identity(opened)
    ):
        raise LifecycleEvidenceError(f"{label} changed while reading: {path}")
    return bytes(wire)


def _decode_json(wire: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise LifecycleEvidenceError(f"invalid JSON constant in {label}: {value}")

    try:
        document = json.loads(
            wire,
            object_pairs_hook=_reject_duplicates,
            parse_constant=reject_constant,
        )
    except LifecycleEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise LifecycleEvidenceError(f"invalid JSON in {label}") from exc
    if type(document) is not dict:
        raise LifecycleEvidenceError(f"{label} root must be an object")
    return document


def _load_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    wire = _regular_bytes(path, maximum, label)
    return _decode_json(wire, label), wire


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise LifecycleEvidenceError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise LifecycleEvidenceError(
            f"{label} keys are not exact; missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )
    return value


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise LifecycleEvidenceError(f"invalid {label}")
    return value


def _package_record(
    value: object, expected_name: str, label: str
) -> dict[str, Any]:
    record = _exact(value, {"name", "sha256", "size"}, label)
    if record["name"] != expected_name:
        raise LifecycleEvidenceError(f"{label} name is invalid")
    _string(record["sha256"], SHA256, f"{label} digest")
    if (
        type(record["size"]) is not int
        or record["size"] <= 0
        or record["size"] > MAX_PACKAGE_BYTES
    ):
        raise LifecycleEvidenceError(f"{label} size is invalid")
    return record


def _timestamp(value: object, label: str) -> dt.datetime:
    text = _string(value, UTC, label)
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise LifecycleEvidenceError(f"invalid {label}") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _reference(value: object, profile_id: str, maximum: int, label: str) -> str:
    reference = _string(value, RAW_REFERENCE, label)
    if not reference.startswith(f"{profile_id}/raw/"):
        raise LifecycleEvidenceError(f"{label} is cross-profile")
    if len(reference.encode("utf-8")) > maximum:
        raise LifecycleEvidenceError(f"{label} is too long")
    path = PurePosixPath(reference)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LifecycleEvidenceError(f"{label} is unsafe")
    return reference


def _safe_root(path: Path, label: str) -> Path:
    try:
        lexical = path.absolute()
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise LifecycleEvidenceError(f"cannot inspect {label}") from exc
    if (
        lexical != resolved
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise LifecycleEvidenceError(f"{label} must be a protected real directory")
    return resolved


def _raw_artifact(
    artifact_root: Path,
    resolved_root: Path,
    reference: str,
    expected_sha256: object,
    maximum: int,
) -> None:
    digest = _string(expected_sha256, SHA256, f"raw evidence digest {reference}")
    path = artifact_root.joinpath(*PurePosixPath(reference).parts)
    _safe_root(artifact_root / PurePosixPath(reference).parts[0], "profile artifact directory")
    _safe_root(path.parent, "raw evidence directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LifecycleEvidenceError(f"missing raw evidence: {reference}") from exc
    if resolved_root not in resolved.parents:
        raise LifecycleEvidenceError(f"raw evidence escaped its root: {reference}")
    wire = _regular_bytes(path, maximum, f"raw evidence {reference}")
    _decode_json(wire, f"raw evidence {reference}")
    if hashlib.sha256(wire).hexdigest() != digest:
        raise LifecycleEvidenceError(f"raw evidence digest mismatch: {reference}")


def _inventory_sha256(records: dict[str, str]) -> str:
    return _canonical_sha256(
        [{"reference": reference, "sha256": records[reference]} for reference in sorted(records)]
    )


def load_contract(path: Path = DEFAULT_CONTRACT) -> tuple[dict[str, Any], str]:
    _safe_root(path.parent, "native lifecycle contract parent")
    document, wire = _load_json(path, 1024 * 1024, "native lifecycle contract")
    digest = hashlib.sha256(wire).hexdigest()
    if digest != CONTRACT_SHA256:
        raise LifecycleEvidenceError(
            "native lifecycle contract bytes are not the reviewed v4.10.0 contract"
        )
    _exact(
        document,
        {
            "schema_version",
            "contract_id",
            "target_release",
            "baseline_release",
            "baseline_commit",
            "qualification_state",
            "publishing",
            "architecture",
            "profiles",
            "limits",
            "guardrails",
            "package_trust",
            "checkpoints",
            "scenarios",
            "scenario_package_verifications",
            "profile_scenario_checks",
            "zero_residue_paths",
        },
        "native lifecycle contract",
    )
    if (
        document["schema_version"] != 1
        or document["contract_id"] != "syswarden-native-package-lifecycle/v1"
        or document["target_release"] != TARGET_RELEASE
        or document["baseline_release"] != BASELINE_RELEASE
        or document["baseline_commit"] != BASELINE_COMMIT
        or document["qualification_state"] != "candidate-not-qualified"
        or document["publishing"] is not False
        or document["architecture"] != "amd64"
    ):
        raise LifecycleEvidenceError("native lifecycle contract identity is invalid")
    if tuple(document["profiles"]) != EXPECTED_PROFILES:
        raise LifecycleEvidenceError("native lifecycle profile inventory is not exact")
    if document["package_trust"] != BASELINE_TRUST:
        raise LifecycleEvidenceError("native lifecycle package trust is not exact")
    if document["profile_scenario_checks"] != EXPECTED_PROFILE_SCENARIO_CHECKS:
        raise LifecycleEvidenceError("profile-specific lifecycle checks are not exact")
    limits = _exact(
        document["limits"],
        {
            "maximum_input_bytes",
            "maximum_raw_evidence_bytes",
            "maximum_campaign_seconds",
            "maximum_future_skew_seconds",
            "maximum_reference_bytes",
            "required_raw_evidence_per_profile",
        },
        "native lifecycle limits",
    )
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise LifecycleEvidenceError("native lifecycle limits are invalid")
    if limits["required_raw_evidence_per_profile"] != 29:
        raise LifecycleEvidenceError("raw evidence count is not exact")
    checkpoints = document["checkpoints"]
    scenarios = document["scenarios"]
    if type(checkpoints) is not list or type(scenarios) is not list:
        raise LifecycleEvidenceError("native lifecycle sequence is invalid")
    if len(checkpoints) != 12 or len(scenarios) != 12:
        raise LifecycleEvidenceError("native lifecycle sequence count is invalid")
    checkpoint_ids: list[str] = []
    for index, checkpoint in enumerate(checkpoints, start=1):
        item = _exact(
            checkpoint,
            {"id", "sequence", "version", "service_state", "syswarden_firewall_state"},
            f"contract checkpoint {index}",
        )
        if item["sequence"] != index:
            raise LifecycleEvidenceError("contract checkpoint order is invalid")
        checkpoint_ids.append(_string(item["id"], CAMPAIGN_ID, "checkpoint id"))
    if len(set(checkpoint_ids)) != len(checkpoint_ids):
        raise LifecycleEvidenceError("contract checkpoint IDs are duplicated")
    scenario_ids: list[str] = []
    for index, scenario in enumerate(scenarios, start=1):
        item = _exact(
            scenario,
            {"id", "sequence", "from_checkpoint", "to_checkpoint", "required_checks"},
            f"contract scenario {index}",
        )
        if item["sequence"] != index:
            raise LifecycleEvidenceError("contract scenario order is invalid")
        scenario_id = _string(item["id"], CAMPAIGN_ID, "scenario id")
        scenario_ids.append(scenario_id)
        if item["from_checkpoint"] not in checkpoint_ids or item["to_checkpoint"] not in checkpoint_ids:
            raise LifecycleEvidenceError("contract scenario checkpoint is unknown")
        checks = item["required_checks"]
        if (
            type(checks) is not list
            or not checks
            or len(checks) != len(set(checks))
            or any(type(check) is not str or CAMPAIGN_ID.fullmatch(check) is None for check in checks)
        ):
            raise LifecycleEvidenceError("contract scenario checks are invalid")
    if len(set(scenario_ids)) != len(scenario_ids):
        raise LifecycleEvidenceError("contract scenario IDs are duplicated")
    package_map = _exact(
        document["scenario_package_verifications"],
        set(scenario_ids),
        "scenario package verification map",
    )
    for scenario_id, releases in package_map.items():
        if type(releases) is not list or any(
            release not in {BASELINE_RELEASE, TARGET_RELEASE} for release in releases
        ):
            raise LifecycleEvidenceError(
                f"contract package verification is invalid: {scenario_id}"
            )
    residue = document["zero_residue_paths"]
    if (
        type(residue) is not list
        or len(residue) != 36
        or len(set(residue)) != len(residue)
        or any(type(path_value) is not str or not path_value.startswith("/") for path_value in residue)
    ):
        raise LifecycleEvidenceError("zero residue path inventory is invalid")
    return document, digest


def contract_digest(path: Path = DEFAULT_CONTRACT) -> str:
    return load_contract(path)[1]


def _add_reference(
    records: dict[str, str],
    value: dict[str, Any],
    profile_id: str,
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
    label: str,
) -> None:
    reference = _reference(
        value["evidence_ref"],
        profile_id,
        contract["limits"]["maximum_reference_bytes"],
        f"{label} evidence reference",
    )
    digest = _string(value["evidence_sha256"], SHA256, f"{label} evidence digest")
    if reference in records or digest in records.values():
        raise LifecycleEvidenceError("raw evidence reference or digest is reused")
    _raw_artifact(
        artifact_root,
        resolved_root,
        reference,
        digest,
        contract["limits"]["maximum_raw_evidence_bytes"],
    )
    records[reference] = digest


def _validate_host(
    value: object,
    profile: dict[str, Any],
    candidate_commit: str,
    expected_ssh_fingerprint: str,
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> dict[str, Any]:
    host = _exact(
        value,
        {
            "profile_id",
            "host_id",
            "os_id",
            "os_version",
            "architecture",
            "package_family",
            "package_variant",
            "installation_mode",
            "package_manager",
            "service_manager",
            "firewall_backend",
            "ssh_host_key_sha256",
            "instance_identity_sha256",
            "provider_firewall_policy_sha256",
            "provider_firewall_default_policy",
            "ssh_allowlist_verified",
            "candidate_commit",
            "evidence_ref",
            "evidence_sha256",
        },
        "host attestation",
    )
    for key in (
        "id",
        "host_id",
        "os_id",
        "os_version",
        "architecture",
        "package_family",
        "package_variant",
        "installation_mode",
        "package_manager",
        "service_manager",
        "firewall_backend",
    ):
        observation_key = "profile_id" if key == "id" else key
        expected = "amd64" if key == "architecture" else profile[key]
        if host[observation_key] != expected:
            raise LifecycleEvidenceError(f"host profile mismatch: {observation_key}")
    if host["candidate_commit"] != candidate_commit:
        raise LifecycleEvidenceError("host attestation is not candidate-bound")
    _string(host["ssh_host_key_sha256"], SSH_FINGERPRINT, "SSH host key fingerprint")
    if host["ssh_host_key_sha256"] != expected_ssh_fingerprint:
        raise LifecycleEvidenceError("SSH host key does not match the operator pin")
    _string(host["instance_identity_sha256"], SHA256, "instance identity digest")
    _string(host["provider_firewall_policy_sha256"], SHA256, "provider firewall policy digest")
    if (
        host["provider_firewall_default_policy"] != "drop"
        or host["ssh_allowlist_verified"] is not True
    ):
        raise LifecycleEvidenceError("provider firewall boundary is not verified")
    _add_reference(
        records, host, profile["id"], contract, artifact_root, resolved_root, "host"
    )
    return host


def _validate_packages(
    value: object,
    profile: dict[str, Any],
    candidate_commit: str,
    expected_signer_identity: str,
    expected_candidate_package: dict[str, Any],
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) != 2:
        raise LifecycleEvidenceError("exactly two package artifacts are required")
    packages: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(value):
        expected_release = (BASELINE_RELEASE, TARGET_RELEASE)[index]
        package_keys = {
            "release_tag",
            "producer_commit",
            "filename",
            "package_sha256",
            "package_size",
            "package_role",
            "origin",
            "digest_source",
            "release_asset_digest_verified",
            "verification_mechanism",
            "verification_identity",
            "verification_proof_sha256",
            "native_signature_verified",
            "package_payload_verified",
            "verified_before_install",
            "evidence_ref",
            "evidence_sha256",
        }
        if index == 0:
            package_keys.update(
                {
                    "release_id",
                    "release_asset_id",
                    "checksum_asset_sha256",
                    "release_tag_object",
                    "release_tag_signature_mechanism",
                    "release_tag_signature_payload_sha256",
                    "release_tag_signature_sha256",
                    "release_tag_signature_verified",
                    "release_tag_signature_verified_at",
                }
            )
        else:
            package_keys.update(
                {"signing_provenance_profile", "updater_manifest_included"}
            )
        package = _exact(
            raw,
            package_keys,
            f"package artifact {index}",
        )
        if package["release_tag"] != expected_release or expected_release in packages:
            raise LifecycleEvidenceError("package release inventory or order is invalid")
        expected_commit = BASELINE_COMMIT if index == 0 else candidate_commit
        if package["producer_commit"] != expected_commit:
            raise LifecycleEvidenceError("package producer commit is invalid")
        if package["filename"] != PACKAGE_NAMES[(profile["id"], expected_release)]:
            raise LifecycleEvidenceError("package filename is invalid")
        _string(package["package_sha256"], SHA256, "package digest")
        if (
            type(package["package_size"]) is not int
            or package["package_size"] <= 0
            or package["package_size"] > MAX_PACKAGE_BYTES
        ):
            raise LifecycleEvidenceError("package size is invalid")
        _string(package["verification_proof_sha256"], SHA256, "package verification proof digest")
        if (
            package["release_asset_digest_verified"] is not True
            or package["package_payload_verified"] is not True
            or package["verified_before_install"] is not True
        ):
            raise LifecycleEvidenceError("package verification is incomplete")
        if index == 0:
            baseline = BASELINE_TRUST["baseline_packages"][profile["package_family"]]
            tag_signature = BASELINE_TRUST["baseline_tag_signature"]
            if (
                package["package_role"] != "standard"
                or package["filename"] != baseline["name"]
                or package["package_sha256"] != baseline["sha256"]
                or package["package_size"] != baseline["size"]
                or package["origin"] != "github-release-v4.04.3"
                or package["digest_source"] != "release-sha256sums"
                or package["verification_mechanism"] != "release-sha256sums"
                or package["verification_identity"] != "github-release-v4.04.3"
                or package["native_signature_verified"] is not False
                or package["release_id"] != BASELINE_TRUST["baseline_release_id"]
                or package["release_asset_id"] != baseline["id"]
                or package["checksum_asset_sha256"]
                != BASELINE_TRUST["baseline_checksum_asset"]["sha256"]
                or package["release_tag_object"]
                != BASELINE_TRUST["baseline_tag_object"]
                or package["release_tag_signature_mechanism"]
                != tag_signature["mechanism"]
                or package["release_tag_signature_payload_sha256"]
                != tag_signature["payload_sha256"]
                or package["release_tag_signature_sha256"]
                != tag_signature["signature_sha256"]
                or package["release_tag_signature_verified"] is not True
                or package["release_tag_signature_verified_at"]
                != tag_signature["verified_at"]
            ):
                raise LifecycleEvidenceError("baseline package provenance is invalid")
        else:
            expected_profile = (
                RHEL_PACKAGE_OWNED_SIGNING_PROFILE
                if profile["package_variant"] == "rhel-package-owned"
                else STANDARD_SIGNING_PROFILE
            )
            if (
                package["package_role"] != profile["package_variant"]
                or package["origin"] != "protected-native-signing-artifact"
                or package["digest_source"] != "native-signing-provenance"
                or package["verification_mechanism"]
                != profile["candidate_signature_mechanism"]
                or package["verification_identity"] != expected_signer_identity
                or package["native_signature_verified"] is not True
                or package["signing_provenance_profile"] != expected_profile
                or package["updater_manifest_included"]
                is not (profile["package_variant"] == "standard")
            ):
                raise LifecycleEvidenceError("candidate native package signature is invalid")
            observed_candidate = {
                "name": package["filename"],
                "sha256": package["package_sha256"],
                "size": package["package_size"],
            }
            if observed_candidate != expected_candidate_package:
                raise LifecycleEvidenceError(
                    "candidate package does not match protected signing provenance"
                )
        _add_reference(
            records,
            package,
            profile["id"],
            contract,
            artifact_root,
            resolved_root,
            f"package {expected_release}",
        )
        packages[expected_release] = package
    return packages


def _validate_checkpoints(
    value: object,
    profile: dict[str, Any],
    candidate_commit: str,
    packages: dict[str, dict[str, Any]],
    started: dt.datetime,
    completed: dt.datetime,
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> list[dict[str, Any]]:
    expected = contract["checkpoints"]
    if type(value) is not list or len(value) != len(expected):
        raise LifecycleEvidenceError("checkpoint inventory is not exact")
    checkpoints: list[dict[str, Any]] = []
    previous = started
    for index, (raw, obligation) in enumerate(zip(value, expected, strict=True), start=1):
        checkpoint = _exact(
            raw,
            {
                "id",
                "sequence",
                "observed_at",
                "installed_version",
                "installed_commit",
                "installed_package_sha256",
                "boot_id_sha256",
                "configuration_semantic_sha256",
                "operator_state_canary_sha256",
                "persistent_state_canary_sha256",
                "third_party_firewall_sha256",
                "syswarden_firewall_sha256",
                "core_service_state",
                "firewall_service_state",
                "package_manager_healthy",
                "package_database_consistent",
                "unexpected_owned_residue_count",
                "evidence_ref",
                "evidence_sha256",
            },
            f"checkpoint {index}",
        )
        if checkpoint["id"] != obligation["id"] or checkpoint["sequence"] != index:
            raise LifecycleEvidenceError("checkpoint identity or order is invalid")
        observed = _timestamp(checkpoint["observed_at"], "checkpoint timestamp")
        if observed <= previous or observed > completed:
            raise LifecycleEvidenceError("checkpoint timestamp order is invalid")
        previous = observed
        if checkpoint["installed_version"] != obligation["version"]:
            raise LifecycleEvidenceError(f"checkpoint version mismatch: {checkpoint['id']}")
        if (
            checkpoint["core_service_state"] != obligation["service_state"]
            or checkpoint["firewall_service_state"] != obligation["service_state"]
            or checkpoint["package_manager_healthy"] is not True
            or checkpoint["package_database_consistent"] is not True
            or type(checkpoint["unexpected_owned_residue_count"]) is not int
            or checkpoint["unexpected_owned_residue_count"] != 0
        ):
            raise LifecycleEvidenceError(f"checkpoint health mismatch: {checkpoint['id']}")
        for key in (
            "operator_state_canary_sha256",
            "third_party_firewall_sha256",
        ):
            _string(checkpoint[key], SHA256, f"{checkpoint['id']} {key}")
        if (
            profile["installation_mode"] == "offline-chroot-first-boot"
            and checkpoint["id"] == "clean-host"
        ):
            if checkpoint["boot_id_sha256"] != "not-applicable":
                raise LifecycleEvidenceError(
                    "offline chroot checkpoint must not claim a runtime boot ID"
                )
        else:
            _string(
                checkpoint["boot_id_sha256"],
                SHA256,
                f"{checkpoint['id']} boot_id_sha256",
            )
        if obligation["version"] == "absent":
            for key in (
                "installed_commit",
                "installed_package_sha256",
                "configuration_semantic_sha256",
                "persistent_state_canary_sha256",
                "syswarden_firewall_sha256",
            ):
                if checkpoint[key] != "absent":
                    raise LifecycleEvidenceError(
                        f"absent checkpoint contains SysWarden state: {checkpoint['id']}"
                    )
        else:
            release = obligation["version"]
            expected_commit = BASELINE_COMMIT if release == BASELINE_RELEASE else candidate_commit
            if checkpoint["installed_commit"] != expected_commit:
                raise LifecycleEvidenceError(f"installed commit mismatch: {checkpoint['id']}")
            if checkpoint["installed_package_sha256"] != packages[release]["package_sha256"]:
                raise LifecycleEvidenceError(f"installed package mismatch: {checkpoint['id']}")
            for key in (
                "configuration_semantic_sha256",
                "persistent_state_canary_sha256",
                "syswarden_firewall_sha256",
            ):
                _string(checkpoint[key], SHA256, f"{checkpoint['id']} {key}")
        _add_reference(
            records,
            checkpoint,
            profile["id"],
            contract,
            artifact_root,
            resolved_root,
            f"checkpoint {checkpoint['id']}",
        )
        checkpoints.append(checkpoint)

    operator_digests = {item["operator_state_canary_sha256"] for item in checkpoints}
    firewall_digests = {item["third_party_firewall_sha256"] for item in checkpoints}
    if len(operator_digests) != 1 or len(firewall_digests) != 1:
        raise LifecycleEvidenceError("operator or third-party firewall state was not preserved")

    preserved_ids = {
        "candidate-configured",
        "stable-v4043-configured",
        "candidate-v4100-upgraded",
        "candidate-v4100-reboot1",
        "candidate-v4100-reboot2",
        "stable-v4043-rollback",
        "candidate-v4100-reupgraded",
        "candidate-v4100-recovered",
    }
    preserved = [item for item in checkpoints if item["id"] in preserved_ids]
    if (
        len({item["configuration_semantic_sha256"] for item in preserved}) != 1
        or len({item["persistent_state_canary_sha256"] for item in preserved}) != 1
        or len({item["syswarden_firewall_sha256"] for item in preserved}) != 1
    ):
        raise LifecycleEvidenceError(
            "configuration, persistent state, or SysWarden firewall semantics were not preserved"
        )

    boot_ids = [item["boot_id_sha256"] for item in checkpoints]
    if profile["installation_mode"] == "offline-chroot-first-boot":
        valid_boot_sequence = (
            boot_ids[0] == "not-applicable"
            and len(set(boot_ids[1:6])) == 1
            and boot_ids[6] != boot_ids[5]
            and boot_ids[7] not in {boot_ids[5], boot_ids[6]}
            and len(set(boot_ids[7:])) == 1
        )
    else:
        valid_boot_sequence = (
            len(set(boot_ids[:6])) == 1
            and boot_ids[6] != boot_ids[5]
            and boot_ids[7] not in {boot_ids[5], boot_ids[6]}
            and len(set(boot_ids[7:])) == 1
        )
    if not valid_boot_sequence:
        raise LifecycleEvidenceError("the exact two-reboot lifecycle is not attested")
    return checkpoints


def _validate_scenarios(
    value: object,
    profile: dict[str, Any],
    packages: dict[str, dict[str, Any]],
    checkpoints: list[dict[str, Any]],
    started: dt.datetime,
    completed: dt.datetime,
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> list[dict[str, Any]]:
    expected = contract["scenarios"]
    if type(value) is not list or len(value) != len(expected):
        raise LifecycleEvidenceError("scenario inventory is not exact")
    scenarios: list[dict[str, Any]] = []
    checkpoint_times = {
        item["id"]: _timestamp(item["observed_at"], "checkpoint timestamp")
        for item in checkpoints
    }
    previous = started
    for index, (raw, obligation) in enumerate(zip(value, expected, strict=True), start=1):
        scenario = _exact(
            raw,
            {
                "id",
                "sequence",
                "status",
                "observed_at",
                "from_checkpoint",
                "to_checkpoint",
                "checks",
                "package_verifications",
                "evidence_ref",
                "evidence_sha256",
            },
            f"scenario {index}",
        )
        for key in ("id", "sequence", "from_checkpoint", "to_checkpoint"):
            if scenario[key] != obligation[key]:
                raise LifecycleEvidenceError(f"scenario field mismatch: {key}")
        if scenario["status"] != "pass":
            raise LifecycleEvidenceError(f"scenario did not pass: {scenario['id']}")
        observed = _timestamp(scenario["observed_at"], "scenario timestamp")
        if observed <= previous or observed > completed:
            raise LifecycleEvidenceError("scenario timestamp order is invalid")
        if observed < checkpoint_times[scenario["to_checkpoint"]]:
            raise LifecycleEvidenceError("scenario predates its target checkpoint")
        previous = observed
        profile_checks = contract["profile_scenario_checks"].get(
            profile["id"], {}
        ).get(scenario["id"], [])
        expected_checks = set(obligation["required_checks"]) | set(profile_checks)
        checks = _exact(
            scenario["checks"],
            expected_checks,
            f"scenario checks {scenario['id']}",
        )
        if any(value is not True for value in checks.values()):
            raise LifecycleEvidenceError(f"scenario check failed: {scenario['id']}")
        expected_releases = contract["scenario_package_verifications"][scenario["id"]]
        verifications = scenario["package_verifications"]
        if type(verifications) is not list or len(verifications) != len(expected_releases):
            raise LifecycleEvidenceError(
                f"package verification inventory mismatch: {scenario['id']}"
            )
        for verification, release in zip(verifications, expected_releases, strict=True):
            item = _exact(
                verification,
                {
                    "release_tag",
                    "package_sha256",
                    "verification_identity",
                    "verification_proof_sha256",
                    "verified_before_install",
                },
                f"scenario package verification {scenario['id']}",
            )
            package = packages[release]
            if (
                item["release_tag"] != release
                or item["package_sha256"] != package["package_sha256"]
                or item["verification_identity"] != package["verification_identity"]
                or item["verification_proof_sha256"] != package["verification_proof_sha256"]
                or item["verified_before_install"] is not True
            ):
                raise LifecycleEvidenceError(
                    f"package was not reverified before install: {scenario['id']}"
                )
        _add_reference(
            records,
            scenario,
            profile["id"],
            contract,
            artifact_root,
            resolved_root,
            f"scenario {scenario['id']}",
        )
        scenarios.append(scenario)
    return scenarios


def _validate_final_state(
    value: object,
    profile_id: str,
    checkpoints: list[dict[str, Any]],
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> dict[str, Any]:
    final_state = _exact(
        value,
        {
            "checkpoint_id",
            "package_records",
            "service_units",
            "running_processes",
            "firewall_objects",
            "dedicated_paths",
            "dedicated_users_groups",
            "scheduled_jobs",
            "residue_count",
            "verified_paths",
            "operator_state_canary_sha256",
            "third_party_firewall_sha256",
            "evidence_ref",
            "evidence_sha256",
        },
        "final state",
    )
    for key in (
        "package_records",
        "service_units",
        "running_processes",
        "firewall_objects",
        "dedicated_paths",
        "dedicated_users_groups",
        "scheduled_jobs",
        "residue_count",
    ):
        if type(final_state[key]) is not int or final_state[key] != 0:
            raise LifecycleEvidenceError(f"final state is not residue-free: {key}")
    if (
        final_state["checkpoint_id"] != "final-purged"
        or final_state["verified_paths"] != contract["zero_residue_paths"]
        or final_state["operator_state_canary_sha256"]
        != checkpoints[-1]["operator_state_canary_sha256"]
        or final_state["third_party_firewall_sha256"]
        != checkpoints[-1]["third_party_firewall_sha256"]
    ):
        raise LifecycleEvidenceError("final state binding is invalid")
    _add_reference(
        records,
        final_state,
        profile_id,
        contract,
        artifact_root,
        resolved_root,
        "final state",
    )
    return final_state


def _validate_attestation(
    value: object,
    profile_id: str,
    candidate_commit: str,
    contract_sha256: str,
    records: dict[str, str],
    contract: dict[str, Any],
    artifact_root: Path,
    resolved_root: Path,
) -> dict[str, Any]:
    attestation = _exact(
        value,
        {
            "mechanism",
            "statement_sha256",
            "signature_sha256",
            "signer_identity",
            "verification_status",
            "verified_by",
            "attested_profile_id",
            "attested_candidate_commit",
            "attested_contract_sha256",
            "attested_evidence_inventory_sha256",
            "evidence_ref",
            "evidence_sha256",
        },
        "final attestation",
    )
    if attestation["mechanism"] not in {
        "github-artifact-attestation",
        "sigstore-bundle",
        "operator-signed-in-toto",
    }:
        raise LifecycleEvidenceError("final attestation mechanism is unsupported")
    for key in (
        "statement_sha256",
        "signature_sha256",
        "attested_contract_sha256",
        "attested_evidence_inventory_sha256",
    ):
        _string(attestation[key], SHA256, f"final attestation {key}")
    _string(attestation["signer_identity"], IDENTIFIER, "attestation signer identity")
    expected_inventory = _inventory_sha256(records)
    if (
        attestation["verification_status"] != "verified"
        or attestation["verified_by"] != "release-owner-gate"
        or attestation["attested_profile_id"] != profile_id
        or attestation["attested_candidate_commit"] != candidate_commit
        or attestation["attested_contract_sha256"] != contract_sha256
        or attestation["attested_evidence_inventory_sha256"] != expected_inventory
    ):
        raise LifecycleEvidenceError("final attestation is not bound to the evidence inventory")
    _add_reference(
        records,
        attestation,
        profile_id,
        contract,
        artifact_root,
        resolved_root,
        "final attestation",
    )
    return attestation


def validate_observation(
    document: dict[str, Any],
    *,
    contract: dict[str, Any],
    contract_sha256: str,
    candidate_commit: str,
    artifact_root: Path,
    profile: dict[str, Any],
    expected_ssh_fingerprint: str,
    expected_signer_identity: str,
    expected_candidate_package: dict[str, Any],
    validation_time: dt.datetime | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    _exact(
        document,
        {
            "schema",
            "repository",
            "target_release",
            "candidate_commit",
            "contract_sha256",
            "qualification_state",
            "publishing",
            "campaign",
            "host",
            "packages",
            "checkpoints",
            "scenarios",
            "final_state",
            "attestation",
        },
        "native lifecycle observation",
    )
    if (
        document["schema"] != OBSERVATION_SCHEMA
        or document["repository"] != REPOSITORY
        or document["target_release"] != TARGET_RELEASE
        or document["candidate_commit"] != candidate_commit
        or document["contract_sha256"] != contract_sha256
        or document["qualification_state"] != "candidate-not-qualified"
        or document["publishing"] is not False
    ):
        raise LifecycleEvidenceError("native lifecycle observation identity is invalid")
    campaign = _exact(
        document["campaign"],
        {
            "id",
            "started_at",
            "completed_at",
            "operator_identity",
            "observation_origin",
            "synthetic",
            "network_boundary",
            "snapshot_reference",
        },
        "native lifecycle campaign",
    )
    _string(campaign["id"], CAMPAIGN_ID, "campaign id")
    _string(campaign["operator_identity"], IDENTIFIER, "operator identity")
    _string(campaign["snapshot_reference"], IDENTIFIER, "snapshot reference")
    if (
        campaign["observation_origin"] != "real-native-host"
        or campaign["synthetic"] is not False
        or campaign["network_boundary"] != "provider-firewall-default-drop"
    ):
        raise LifecycleEvidenceError("synthetic or non-native observations are forbidden")
    started = _timestamp(campaign["started_at"], "campaign start")
    completed = _timestamp(campaign["completed_at"], "campaign completion")
    if completed <= started:
        raise LifecycleEvidenceError("campaign completion must follow its start")
    if (completed - started).total_seconds() > contract["limits"]["maximum_campaign_seconds"]:
        raise LifecycleEvidenceError("campaign exceeded its duration bound")
    now = validation_time or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise LifecycleEvidenceError("validation time must be timezone-aware")
    if completed > now.astimezone(dt.timezone.utc) + dt.timedelta(
        seconds=contract["limits"]["maximum_future_skew_seconds"]
    ):
        raise LifecycleEvidenceError("campaign completion is in the future")

    resolved_root = _safe_root(artifact_root, "artifact root")
    records: dict[str, str] = {}
    _validate_host(
        document["host"],
        profile,
        candidate_commit,
        expected_ssh_fingerprint,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    packages = _validate_packages(
        document["packages"],
        profile,
        candidate_commit,
        expected_signer_identity,
        expected_candidate_package,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    checkpoints = _validate_checkpoints(
        document["checkpoints"],
        profile,
        candidate_commit,
        packages,
        started,
        completed,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    _validate_scenarios(
        document["scenarios"],
        profile,
        packages,
        checkpoints,
        started,
        completed,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    _validate_final_state(
        document["final_state"],
        profile["id"],
        checkpoints,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    _validate_attestation(
        document["attestation"],
        profile["id"],
        candidate_commit,
        contract_sha256,
        records,
        contract,
        artifact_root,
        resolved_root,
    )
    if len(records) != contract["limits"]["required_raw_evidence_per_profile"]:
        raise LifecycleEvidenceError("raw evidence count is not exact")
    return document, records


def _exact_artifact_inventory(artifact_root: Path, expected: set[str]) -> None:
    resolved_root = _safe_root(artifact_root, "artifact root")
    actual: set[str] = set()
    actual_directories: set[str] = set()
    for path in artifact_root.rglob("*"):
        try:
            info = path.lstat()
        except OSError as exc:
            raise LifecycleEvidenceError("cannot inspect artifact inventory") from exc
        if stat.S_ISLNK(info.st_mode):
            raise LifecycleEvidenceError("artifact inventory contains a symlink")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise LifecycleEvidenceError("artifact inventory ownership or mode is unsafe")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(path.relative_to(artifact_root).as_posix())
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LifecycleEvidenceError("artifact inventory contains an unsafe entry")
        resolved = path.resolve(strict=True)
        if resolved_root not in resolved.parents:
            raise LifecycleEvidenceError("artifact inventory escaped its root")
        actual.add(path.relative_to(artifact_root).as_posix())
    if actual != expected:
        raise LifecycleEvidenceError(
            f"raw evidence inventory is not exact; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    expected_directories = {
        directory
        for profile in EXPECTED_PROFILES
        for directory in (profile["id"], f"{profile['id']}/raw")
    }
    if actual_directories != expected_directories:
        raise LifecycleEvidenceError("raw evidence directory inventory is not exact")


def assemble(
    candidate_commit: str,
    observations: Sequence[Path],
    artifact_root: Path,
    *,
    rpm_signer_fingerprint: str,
    deb_signer_fingerprint: str,
    apk_public_key_sha256: str,
    rpm_package_name: str,
    rpm_package_sha256: str,
    rpm_package_size: int,
    rhel_rpm_package_name: str,
    rhel_rpm_package_sha256: str,
    rhel_rpm_package_size: int,
    deb_package_name: str,
    deb_package_sha256: str,
    deb_package_size: int,
    apk_package_name: str,
    apk_package_sha256: str,
    apk_package_size: int,
    node02_ssh_host_key_sha256: str,
    node04_ssh_host_key_sha256: str,
    node05_ssh_host_key_sha256: str,
    node03_ssh_host_key_sha256: str,
    contract_path: Path = DEFAULT_CONTRACT,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    _string(candidate_commit, SHA1, "candidate commit")
    if candidate_commit == BASELINE_COMMIT:
        raise LifecycleEvidenceError("candidate commit must differ from the baseline commit")
    _string(rpm_signer_fingerprint, OPENPGP_FINGERPRINT, "RPM signer fingerprint")
    _string(deb_signer_fingerprint, OPENPGP_FINGERPRINT, "DEB signer fingerprint")
    _string(apk_public_key_sha256, SHA256, "APK public key digest")
    candidate_packages = {
        "DEB-U2604": _package_record(
            {
                "name": deb_package_name,
                "sha256": deb_package_sha256,
                "size": deb_package_size,
            },
            PACKAGE_NAMES[("DEB-U2604", TARGET_RELEASE)],
            "DEB candidate package record",
        ),
        "RPM-A9": _package_record(
            {
                "name": rpm_package_name,
                "sha256": rpm_package_sha256,
                "size": rpm_package_size,
            },
            PACKAGE_NAMES[("RPM-A9", TARGET_RELEASE)],
            "RPM candidate package record",
        ),
        "RPM-A9-RHELPO": _package_record(
            {
                "name": rhel_rpm_package_name,
                "sha256": rhel_rpm_package_sha256,
                "size": rhel_rpm_package_size,
            },
            PACKAGE_NAMES[("RPM-A9-RHELPO", TARGET_RELEASE)],
            "RHEL package-owned RPM candidate package record",
        ),
        "RPM-A10-RHELPO": _package_record(
            {
                "name": rhel_rpm_package_name,
                "sha256": rhel_rpm_package_sha256,
                "size": rhel_rpm_package_size,
            },
            PACKAGE_NAMES[("RPM-A10-RHELPO", TARGET_RELEASE)],
            "RHEL package-owned RPM candidate package record",
        ),
        "APK-324": _package_record(
            {
                "name": apk_package_name,
                "sha256": apk_package_sha256,
                "size": apk_package_size,
            },
            PACKAGE_NAMES[("APK-324", TARGET_RELEASE)],
            "APK candidate package record",
        ),
    }
    _string(node02_ssh_host_key_sha256, SSH_FINGERPRINT, "NODE02 SSH host key fingerprint")
    _string(node04_ssh_host_key_sha256, SSH_FINGERPRINT, "NODE04 SSH host key fingerprint")
    _string(node05_ssh_host_key_sha256, SSH_FINGERPRINT, "NODE05 SSH host key fingerprint")
    _string(node03_ssh_host_key_sha256, SSH_FINGERPRINT, "NODE03 SSH host key fingerprint")
    if len(
        {
            node02_ssh_host_key_sha256,
            node04_ssh_host_key_sha256,
            node05_ssh_host_key_sha256,
            node03_ssh_host_key_sha256,
        }
    ) != 4:
        raise LifecycleEvidenceError("native lifecycle host SSH identities are ambiguous")
    contract, contract_sha256 = load_contract(contract_path)
    profile_count = len(EXPECTED_PROFILES)
    if len(observations) != profile_count:
        raise LifecycleEvidenceError(
            f"exactly {profile_count} native lifecycle observations are required"
        )
    by_profile = {profile["id"]: profile for profile in contract["profiles"]}
    ssh_pins = {
        "DEB-U2604": node02_ssh_host_key_sha256,
        "APK-324": node04_ssh_host_key_sha256,
        "RPM-A9": node05_ssh_host_key_sha256,
        "RPM-A9-RHELPO": node05_ssh_host_key_sha256,
        "RPM-A10-RHELPO": node03_ssh_host_key_sha256,
    }
    signers = {
        "DEB-U2604": deb_signer_fingerprint,
        "APK-324": apk_public_key_sha256,
        "RPM-A9": rpm_signer_fingerprint,
        "RPM-A9-RHELPO": rpm_signer_fingerprint,
        "RPM-A10-RHELPO": rpm_signer_fingerprint,
    }
    validated: list[dict[str, Any]] = []
    combined_records: dict[str, str] = {}
    for path in observations:
        _safe_root(path.parent, "native lifecycle observation parent")
        document, _ = _load_json(
            path, contract["limits"]["maximum_input_bytes"], "native lifecycle observation"
        )
        host = document.get("host")
        profile_id = host.get("profile_id") if type(host) is dict else None
        profile = by_profile.get(profile_id)
        if profile is None:
            raise LifecycleEvidenceError("observation profile is unknown")
        item, records = validate_observation(
            document,
            contract=contract,
            contract_sha256=contract_sha256,
            candidate_commit=candidate_commit,
            artifact_root=artifact_root,
            profile=profile,
            expected_ssh_fingerprint=ssh_pins[profile_id],
            expected_signer_identity=signers[profile_id],
            expected_candidate_package=candidate_packages[profile_id],
            validation_time=validation_time,
        )
        if set(combined_records).intersection(records):
            raise LifecycleEvidenceError("raw evidence is reused across profiles")
        if set(combined_records.values()).intersection(records.values()):
            raise LifecycleEvidenceError("raw evidence digest is reused across profiles")
        combined_records.update(records)
        validated.append(item)
    validated.sort(key=lambda item: item["host"]["profile_id"])
    expected_profiles = sorted(by_profile)
    if [item["host"]["profile_id"] for item in validated] != expected_profiles:
        raise LifecycleEvidenceError("exactly one observation per required profile is required")
    if len({item["campaign"]["id"] for item in validated}) != profile_count:
        raise LifecycleEvidenceError("native lifecycle campaign identities are ambiguous")
    if (
        len({item["campaign"]["snapshot_reference"] for item in validated})
        != profile_count
    ):
        raise LifecycleEvidenceError("native lifecycle snapshot identities are ambiguous")
    if (
        len({item["host"]["instance_identity_sha256"] for item in validated})
        != profile_count
    ):
        raise LifecycleEvidenceError("native lifecycle instance identities are ambiguous")
    observed_package_records = {
        (package["filename"], package["package_sha256"], package["package_size"])
        for item in validated
        for package in item["packages"]
    }
    expected_package_records = {
        (record["name"], record["sha256"], record["size"])
        for record in BASELINE_TRUST["baseline_packages"].values()
    } | {
        (record["name"], record["sha256"], record["size"])
        for record in candidate_packages.values()
    }
    if (
        len(expected_package_records) != 7
        or observed_package_records != expected_package_records
    ):
        raise LifecycleEvidenceError("native lifecycle package identities are ambiguous")
    candidate_proofs = {
        item["packages"][1]["verification_proof_sha256"] for item in validated
    }
    if len(candidate_proofs) != profile_count:
        raise LifecycleEvidenceError("candidate verification proof is reused across profiles")
    all_boot_ids = {
        checkpoint["boot_id_sha256"]
        for item in validated
        for checkpoint in item["checkpoints"]
        if checkpoint["boot_id_sha256"] != "not-applicable"
    }
    if len(all_boot_ids) != profile_count * 3:
        raise LifecycleEvidenceError("native lifecycle boot identities are reused")
    if (
        len({item["attestation"]["statement_sha256"] for item in validated})
        != profile_count
        or len({item["attestation"]["signature_sha256"] for item in validated})
        != profile_count
    ):
        raise LifecycleEvidenceError("native lifecycle attestations are reused")
    _exact_artifact_inventory(artifact_root, set(combined_records))
    return {
        "schema": VERDICT_SCHEMA,
        "repository": REPOSITORY,
        "target_release": TARGET_RELEASE,
        "candidate_commit": candidate_commit,
        "contract_sha256": contract_sha256,
        "qualification_state": "candidate-not-qualified",
        "publishing": False,
        "status": "pass",
        "profile_count": profile_count,
        "raw_evidence_count": len(combined_records),
        "raw_evidence_inventory_sha256": _inventory_sha256(combined_records),
        "profiles": validated,
    }


def _write_new_private(path: Path, document: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise LifecycleEvidenceError("output must be a new absolute path")
    parent = path.parent
    _safe_root(parent, "output parent")
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise LifecycleEvidenceError("short write while creating verdict")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise LifecycleEvidenceError("output already exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--observation", action="append", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--rpm-signer-fingerprint", required=True)
    parser.add_argument("--deb-signer-fingerprint", required=True)
    parser.add_argument("--apk-public-key-sha256", required=True)
    parser.add_argument("--rpm-package-name", required=True)
    parser.add_argument("--rpm-package-sha256", required=True)
    parser.add_argument("--rpm-package-size", required=True, type=int)
    parser.add_argument("--rhel-rpm-package-name", required=True)
    parser.add_argument("--rhel-rpm-package-sha256", required=True)
    parser.add_argument("--rhel-rpm-package-size", required=True, type=int)
    parser.add_argument("--deb-package-name", required=True)
    parser.add_argument("--deb-package-sha256", required=True)
    parser.add_argument("--deb-package-size", required=True, type=int)
    parser.add_argument("--apk-package-name", required=True)
    parser.add_argument("--apk-package-sha256", required=True)
    parser.add_argument("--apk-package-size", required=True, type=int)
    parser.add_argument("--node02-ssh-host-key-sha256", required=True)
    parser.add_argument("--node04-ssh-host-key-sha256", required=True)
    parser.add_argument("--node05-ssh-host-key-sha256", required=True)
    parser.add_argument("--node03-ssh-host-key-sha256", required=True)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = assemble(
            args.candidate_commit,
            args.observation,
            args.artifact_root,
            rpm_signer_fingerprint=args.rpm_signer_fingerprint,
            deb_signer_fingerprint=args.deb_signer_fingerprint,
            apk_public_key_sha256=args.apk_public_key_sha256,
            rpm_package_name=args.rpm_package_name,
            rpm_package_sha256=args.rpm_package_sha256,
            rpm_package_size=args.rpm_package_size,
            rhel_rpm_package_name=args.rhel_rpm_package_name,
            rhel_rpm_package_sha256=args.rhel_rpm_package_sha256,
            rhel_rpm_package_size=args.rhel_rpm_package_size,
            deb_package_name=args.deb_package_name,
            deb_package_sha256=args.deb_package_sha256,
            deb_package_size=args.deb_package_size,
            apk_package_name=args.apk_package_name,
            apk_package_sha256=args.apk_package_sha256,
            apk_package_size=args.apk_package_size,
            node02_ssh_host_key_sha256=args.node02_ssh_host_key_sha256,
            node04_ssh_host_key_sha256=args.node04_ssh_host_key_sha256,
            node05_ssh_host_key_sha256=args.node05_ssh_host_key_sha256,
            node03_ssh_host_key_sha256=args.node03_ssh_host_key_sha256,
            contract_path=args.contract,
        )
        _write_new_private(args.output, result)
    except (LifecycleEvidenceError, OSError) as exc:
        print(f"Native lifecycle evidence: {exc}", file=sys.stderr)
        return 1
    print(f"Native lifecycle evidence written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
