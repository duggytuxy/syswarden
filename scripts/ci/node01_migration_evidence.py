#!/usr/bin/env python3
"""Assemble and validate real NODE01 migration evidence for v4.10.0."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "scripts/ci/node01_migration_contract_v4.10.0.json"
CONTRACT_SHA256 = "c5a4ad44c0d5f8a5e1d13fdbea4cdd89e235941ab10f837160fb97d3624f459e"
OBSERVATIONS_SCHEMA = "syswarden-node01-migration-observations/v1"
EVIDENCE_SCHEMA = "syswarden-node01-migration-evidence/v1"
VERDICT_SCHEMA = "syswarden-node01-migration-verdict/v1"
REPOSITORY = "duggytuxy/syswarden"
TARGET_RELEASE = "v4.10.0"
BASELINE_RELEASE = "v4.02.8"
STABLE_RELEASE = "v4.04.3"
TRUST_BOOTSTRAP_RELEASE = "v4.03.2"
BASELINE_COMMIT = "371d353e871fedb410b08f0618a1ae6aa2f7fedc"
TRUST_BOOTSTRAP_COMMIT = "2eae757bbdee510fdd1058ba7770f2c5564ecb23"
STABLE_COMMIT = "381c1f8d91459a9b20605629c725900abd81dee8"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPENPGP_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REFERENCE = re.compile(r"^raw/[a-z0-9][a-z0-9._-]{0,95}\.json$")
SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{2,255}$")
UTC = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAXIMUM_INPUT_BYTES = 1024 * 1024
MAXIMUM_PACKAGE_BYTES = 256 * 1024 * 1024
CANDIDATE_PACKAGE_NAME = "syswarden_4.10.0_amd64.deb"


class MigrationEvidenceError(ValueError):
    """Raised when NODE01 evidence is incomplete, ambiguous, or unsafe."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MigrationEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, maximum: int = MAXIMUM_INPUT_BYTES) -> bytes:
    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_uid,
            item.st_gid, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )

    try:
        before = path.lstat()
    except OSError as exc:
        raise MigrationEvidenceError(f"cannot inspect input: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise MigrationEvidenceError(f"input must be a regular file: {path}")
    if before.st_nlink != 1:
        raise MigrationEvidenceError(f"input must have exactly one link: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise MigrationEvidenceError(f"input size is outside bounds: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MigrationEvidenceError(f"cannot safely open input: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or identity(opened) != identity(before)
        ):
            raise MigrationEvidenceError(f"input changed while opening: {path}")
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
        raise MigrationEvidenceError(f"input namespace changed while reading: {path}") from exc
    if len(wire) != before.st_size or len(wire) > maximum:
        raise MigrationEvidenceError(f"input changed while reading: {path}")
    if identity(after) != identity(opened) or identity(named_after) != identity(opened):
        raise MigrationEvidenceError(f"input changed while reading: {path}")
    return bytes(wire)


def _decode_json(wire: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise MigrationEvidenceError(f"invalid JSON constant in {label}: {value}")

    try:
        document = json.loads(
            wire,
            object_pairs_hook=_reject_duplicates,
            parse_constant=reject_constant,
        )
    except MigrationEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise MigrationEvidenceError(f"invalid JSON in {label}") from exc
    if type(document) is not dict:
        raise MigrationEvidenceError(f"{label} root must be an object")
    return document


def _load_json(path: Path, label: str, maximum: int = MAXIMUM_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    wire = _read_regular(path, maximum)
    return _decode_json(wire, label), wire


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise MigrationEvidenceError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise MigrationEvidenceError(
            f"{label} keys are not exact; missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )
    return value


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise MigrationEvidenceError(f"invalid {label}")
    return value


def _candidate_package_record(
    name: object, sha256: object, size: object
) -> dict[str, Any]:
    if name != CANDIDATE_PACKAGE_NAME:
        raise MigrationEvidenceError("candidate package name is invalid")
    _string(sha256, SHA256, "candidate package digest")
    if (
        type(size) is not int
        or size <= 0
        or size > MAXIMUM_PACKAGE_BYTES
    ):
        raise MigrationEvidenceError("candidate package size is invalid")
    return {"name": name, "sha256": sha256, "size": size}


def _timestamp(value: object, label: str) -> dt.datetime:
    text = _string(value, UTC, label)
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise MigrationEvidenceError(f"invalid {label}") from exc


def _contract(path: Path) -> tuple[dict[str, Any], str]:
    contract, wire = _load_json(path, "migration contract")
    digest = hashlib.sha256(wire).hexdigest()
    if digest != CONTRACT_SHA256:
        raise MigrationEvidenceError("migration contract bytes are not the reviewed v4.10.0 contract")
    _exact(
        contract,
        {
            "schema_version", "contract_id", "target_release", "qualification_state",
            "repository", "host", "versions", "update_trust", "native_package_trust",
            "candidate_channel", "limits", "guardrails", "checkpoints", "scenarios",
        },
        "migration contract",
    )
    if (
        contract["schema_version"] != 1
        or contract["contract_id"] != "syswarden-node01-native-migration/v1"
        or contract["target_release"] != TARGET_RELEASE
        or contract["qualification_state"] != "candidate-not-qualified"
        or contract["repository"] != REPOSITORY
    ):
        raise MigrationEvidenceError("unsupported migration contract identity")
    return contract, digest


def contract_digest(path: Path = DEFAULT_CONTRACT) -> str:
    return _contract(path)[1]


def _raw_bytes(artifact_root: Path, reference: object, maximum_reference_bytes: int) -> tuple[str, bytes]:
    ref = _string(reference, REFERENCE, "evidence reference")
    if len(ref.encode("utf-8")) > maximum_reference_bytes:
        raise MigrationEvidenceError("evidence reference is too long")
    try:
        root_info = artifact_root.lstat()
    except OSError as exc:
        raise MigrationEvidenceError("artifact root cannot be inspected") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise MigrationEvidenceError("artifact root must be a real directory")
    raw_root = artifact_root / "raw"
    try:
        raw_info = raw_root.lstat()
    except OSError as exc:
        raise MigrationEvidenceError("raw evidence directory cannot be inspected") from exc
    if stat.S_ISLNK(raw_info.st_mode) or not stat.S_ISDIR(raw_info.st_mode):
        raise MigrationEvidenceError("raw evidence directory must be a real directory")
    return ref, _read_regular(artifact_root / ref)


def _manifest_verification(
    value: object,
    expected_tag: str,
    candidate_sha: str,
    openpgp_fingerprint: str,
    contract: dict[str, Any],
    expected_channel: str,
    expected_updater_source_package_sha256: str,
    expected_candidate_package: dict[str, Any],
) -> dict[str, Any]:
    manifest_keys = {
        "release_tag", "producer_commit_sha", "manifest_contains_producer_commit",
        "manifest_sha256", "manifest_signature_sha256", "package_sha256",
        "manifest_signature_algorithm", "manifest_signature_verified",
        "manifest_package_digest_verified", "manifest_signer_key_id",
        "manifest_signer_public_key_sha256", "detached_package_signature_algorithm",
        "detached_package_signature_sha256", "detached_package_signature_verified",
        "detached_package_signer_fingerprint", "installation_channel",
        "normalized_invocation", "updater_executable_sha256",
        "updater_executable_source_package_sha256", "updater_executable_attested",
        "qualification_bundle_identity", "qualification_bundle_descriptor_sha256",
        "qualification_bundle_producer_attestation_sha256", "network_requests",
        "fallback_used", "offline_mode_confirmed", "operation_stdout_sha256",
        "installed_package_record_sha256", "qualification_prevalidation",
    }
    if expected_tag == TARGET_RELEASE:
        manifest_keys.update({"package_name", "package_size"})
    item = _exact(
        value,
        manifest_keys,
        f"manifest verification {expected_tag}",
    )
    if item["release_tag"] != expected_tag:
        raise MigrationEvidenceError("verified manifest order or release is incorrect")
    expected_commit = STABLE_COMMIT if expected_tag == STABLE_RELEASE else candidate_sha
    if item["producer_commit_sha"] != expected_commit:
        raise MigrationEvidenceError(f"release commit mismatch for {expected_tag}")
    if item["manifest_contains_producer_commit"] is not False:
        raise MigrationEvidenceError("update manifest v1 must not be credited with a commit binding")
    for key in (
        "manifest_sha256", "manifest_signature_sha256", "package_sha256",
        "manifest_signer_public_key_sha256", "operation_stdout_sha256",
        "installed_package_record_sha256",
    ):
        _string(item[key], SHA256, f"{expected_tag} {key}")
    _string(item["manifest_signer_key_id"], IDENTIFIER, f"{expected_tag} manifest signer key id")
    update_trust = contract["update_trust"]
    if (
        item["manifest_signature_algorithm"] != update_trust["manifest_signature_algorithm"]
        or item["manifest_signer_key_id"] != update_trust["key_id"]
        or item["manifest_signer_public_key_sha256"] != update_trust["public_key_sha256"]
    ):
        raise MigrationEvidenceError("update manifest signer is not the v4.04.3 embedded trust root")
    if item["manifest_signature_verified"] is not True or item["manifest_package_digest_verified"] is not True:
        raise MigrationEvidenceError(f"manifest or package verification failed for {expected_tag}")
    if type(item["network_requests"]) is not int or not 0 <= item["network_requests"] <= 16:
        raise MigrationEvidenceError("network request count is invalid")
    if item["fallback_used"] is not False:
        raise MigrationEvidenceError("update fallback is forbidden")
    if expected_tag == TARGET_RELEASE:
        if item["package_name"] != CANDIDATE_PACKAGE_NAME:
            raise MigrationEvidenceError("candidate package name is invalid")
        if (
            type(item["package_size"]) is not int
            or item["package_size"] <= 0
            or item["package_size"] > MAXIMUM_PACKAGE_BYTES
        ):
            raise MigrationEvidenceError("candidate package size is invalid")
        if {
            "name": item["package_name"],
            "sha256": item["package_sha256"],
            "size": item["package_size"],
        } != expected_candidate_package:
            raise MigrationEvidenceError(
                "candidate package does not match protected signing provenance"
            )
        if item["detached_package_signature_algorithm"] != contract["native_package_trust"]["signature_algorithm"]:
            raise MigrationEvidenceError("candidate DEB detached signature algorithm is invalid")
        _string(item["detached_package_signature_sha256"], SHA256, "candidate DEB signature digest")
        _string(item["detached_package_signer_fingerprint"], OPENPGP_FINGERPRINT, "candidate DEB signer fingerprint")
        if item["detached_package_signer_fingerprint"] != openpgp_fingerprint:
            raise MigrationEvidenceError("candidate DEB signer differs from the qualified signing policy")
        if item["detached_package_signature_verified"] is not True:
            raise MigrationEvidenceError("candidate DEB detached signature was not verified")
        channel = contract["candidate_channel"]
        prevalidation = _exact(
            item["qualification_prevalidation"],
            {
                "config_loads", "firewall_recovery_runs", "operator_state_before_sha256",
                "operator_state_at_install_sha256", "firewall_state_before_sha256",
                "firewall_state_at_install_sha256", "install_started_after_bundle_validation",
                "exact_flags_gate",
            },
            "candidate qualification prevalidation",
        )
        for key in (
            "operator_state_before_sha256", "operator_state_at_install_sha256",
            "firewall_state_before_sha256", "firewall_state_at_install_sha256",
        ):
            _string(prevalidation[key], SHA256, f"candidate {key}")
        if (
            expected_channel != "offline-qualification-bundle"
            or item["installation_channel"] != expected_channel
            or item["normalized_invocation"] != channel["command"]
            or item["network_requests"] != channel["network_requests"]
            or item["fallback_used"] is not channel["fallback"]
            or item["offline_mode_confirmed"] is not True
            or item["updater_executable_attested"] is not True
            or item["updater_executable_source_package_sha256"] != item["package_sha256"]
            or type(prevalidation["config_loads"]) is not int
            or prevalidation["config_loads"] != channel["prevalidation_config_loads"]
            or type(prevalidation["firewall_recovery_runs"]) is not int
            or prevalidation["firewall_recovery_runs"]
            != channel["prevalidation_firewall_recovery_runs"]
            or prevalidation["operator_state_before_sha256"]
            != prevalidation["operator_state_at_install_sha256"]
            or prevalidation["firewall_state_before_sha256"]
            != prevalidation["firewall_state_at_install_sha256"]
            or prevalidation["install_started_after_bundle_validation"] is not True
            or prevalidation["exact_flags_gate"] is not True
        ):
            raise MigrationEvidenceError("candidate did not use the exact offline qualification channel")
        _string(item["updater_executable_sha256"], SHA256, "candidate updater executable digest")
        _string(item["qualification_bundle_identity"], IDENTITY, "qualification bundle identity")
        _string(item["qualification_bundle_descriptor_sha256"], SHA256, "qualification bundle descriptor digest")
        _string(
            item["qualification_bundle_producer_attestation_sha256"],
            SHA256,
            "qualification bundle producer attestation digest",
        )
    else:
        if item["qualification_prevalidation"] != "not-applicable":
            raise MigrationEvidenceError("stable release must not claim candidate prevalidation")
        if (
            item["detached_package_signature_algorithm"] != "not-applicable"
            or item["detached_package_signature_sha256"] != "not-applicable"
            or item["detached_package_signer_fingerprint"] != "not-applicable"
            or item["detached_package_signature_verified"] is not False
        ):
            raise MigrationEvidenceError("stable release must not invent a detached DEB signature")
        if item["installation_channel"] != expected_channel:
            raise MigrationEvidenceError("stable installation channel does not match its scenario")
        if expected_channel == "production-online-latest":
            if (
                item["normalized_invocation"] != "syswarden update"
                or item["network_requests"] <= 0
                or item["offline_mode_confirmed"] is not False
                or item["updater_executable_attested"] is not True
                or item["updater_executable_source_package_sha256"]
                != expected_updater_source_package_sha256
            ):
                raise MigrationEvidenceError("stable update did not use the production signed updater")
            for key in ("updater_executable_sha256", "updater_executable_source_package_sha256"):
                _string(item[key], SHA256, f"stable {key}")
        elif expected_channel == "verified-native-rollback":
            if (
                item["normalized_invocation"] != "native-deb-rollback-after-manifest-verification"
                or item["network_requests"] != 0
                or item["offline_mode_confirmed"] is not False
                or item["updater_executable_attested"] is not False
                or item["updater_executable_sha256"] != "not-applicable"
                or item["updater_executable_source_package_sha256"] != "not-applicable"
            ):
                raise MigrationEvidenceError("stable rollback channel is invalid")
        else:
            raise MigrationEvidenceError("stable installation channel is invalid")
        for key in (
            "qualification_bundle_identity", "qualification_bundle_descriptor_sha256",
            "qualification_bundle_producer_attestation_sha256",
        ):
            if item[key] != "not-applicable":
                raise MigrationEvidenceError("stable release must not claim a qualification bundle")
    return item


def _validate_host(value: object, contract: dict[str, Any], candidate_sha: str) -> str:
    host = _exact(
        value,
        {
            "node_id", "profile_id", "os_id", "os_version", "architecture", "package_family",
            "service_manager", "ssh_host_key_sha256", "candidate_sha", "attestation_ref",
            "attestation_sha256",
        },
        "host attestation",
    )
    for key, expected in contract["host"].items():
        if host[key] != expected:
            raise MigrationEvidenceError(f"NODE01 host field mismatch: {key}")
    _string(host["ssh_host_key_sha256"], SSH_FINGERPRINT, "NODE01 SSH host key fingerprint")
    if host["candidate_sha"] != candidate_sha:
        raise MigrationEvidenceError("host attestation is not candidate-bound")
    _string(host["attestation_sha256"], SHA256, "host attestation digest")
    return _string(host["attestation_ref"], REFERENCE, "host attestation reference")


def _validate_checkpoint(
    value: object,
    expected: dict[str, Any],
    candidate_sha: str,
) -> tuple[dict[str, Any], str, dt.datetime]:
    checkpoint = _exact(
        value,
        {
            "id", "sequence", "observed_at", "installed_version", "installed_commit",
            "installed_package_sha256", "boot_id_sha256", "configuration_semantic_sha256",
            "operator_state_canary_sha256", "persistent_state_inventory_sha256",
            "syswarden_firewall_sha256", "core_service_state", "firewall_service_state",
            "package_manager_healthy", "evidence_ref", "evidence_sha256",
        },
        "checkpoint",
    )
    if checkpoint["id"] != expected["id"] or checkpoint["sequence"] != expected["sequence"]:
        raise MigrationEvidenceError("checkpoint order or identity is incorrect")
    if checkpoint["installed_version"] != expected["version"]:
        raise MigrationEvidenceError(f"checkpoint version mismatch: {expected['id']}")
    if checkpoint["package_manager_healthy"] is not True:
        raise MigrationEvidenceError(f"package manager is unhealthy at {expected['id']}")
    observed_at = _timestamp(checkpoint["observed_at"], "checkpoint timestamp")
    _string(checkpoint["boot_id_sha256"], SHA256, f"{expected['id']} boot_id_sha256")
    if expected["version"] == "absent":
        absent_fields = (
            "installed_commit", "installed_package_sha256", "configuration_semantic_sha256",
            "operator_state_canary_sha256", "persistent_state_inventory_sha256",
            "syswarden_firewall_sha256",
        )
        if any(checkpoint[key] != "absent" for key in absent_fields):
            raise MigrationEvidenceError("purged checkpoint must attest absence")
        if checkpoint["core_service_state"] != "absent" or checkpoint["firewall_service_state"] != "absent":
            raise MigrationEvidenceError("purged checkpoint still exposes a SysWarden service")
    else:
        expected_commit = {
            BASELINE_RELEASE: BASELINE_COMMIT,
            TRUST_BOOTSTRAP_RELEASE: TRUST_BOOTSTRAP_COMMIT,
            STABLE_RELEASE: STABLE_COMMIT,
            TARGET_RELEASE: candidate_sha,
        }[expected["version"]]
        if checkpoint["installed_commit"] != expected_commit:
            raise MigrationEvidenceError(f"installed commit mismatch: {expected['id']}")
        for key in (
            "installed_package_sha256", "configuration_semantic_sha256",
            "operator_state_canary_sha256", "persistent_state_inventory_sha256",
            "syswarden_firewall_sha256",
        ):
            _string(checkpoint[key], SHA256, f"{expected['id']} {key}")
        if checkpoint["core_service_state"] != expected["service_state"]:
            raise MigrationEvidenceError(f"core service state mismatch: {expected['id']}")
        if checkpoint["firewall_service_state"] != expected["service_state"]:
            raise MigrationEvidenceError(f"firewall service state mismatch: {expected['id']}")
    _string(checkpoint["evidence_sha256"], SHA256, "checkpoint evidence digest")
    ref = _string(checkpoint["evidence_ref"], REFERENCE, "checkpoint evidence reference")
    return checkpoint, ref, observed_at


def _validate_scenario(
    value: object,
    expected: dict[str, Any],
    candidate_sha: str,
    openpgp_fingerprint: str,
    contract: dict[str, Any],
    checkpoint_packages: dict[str, str],
    expected_candidate_package: dict[str, Any],
) -> tuple[dict[str, Any], str, dt.datetime]:
    scenario = _exact(
        value,
        {
            "id", "sequence", "status", "observed_at", "from_checkpoint", "to_checkpoint",
            "verified_manifests", "trust_bootstrap_verification", "checks", "evidence_ref",
            "evidence_sha256",
        },
        "migration scenario",
    )
    for key in ("id", "sequence", "from_checkpoint", "to_checkpoint"):
        if scenario[key] != expected[key]:
            raise MigrationEvidenceError(f"scenario field mismatch: {key}")
    if scenario["status"] != "pass":
        raise MigrationEvidenceError(f"migration scenario did not pass: {scenario['id']}")
    checks = _exact(scenario["checks"], set(expected["required_checks"]), f"{scenario['id']} checks")
    if any(value is not True for value in checks.values()):
        raise MigrationEvidenceError(f"migration scenario check failed: {scenario['id']}")
    manifests = scenario["verified_manifests"]
    expected_tags = expected["verified_manifests"]
    if type(manifests) is not list or len(manifests) != len(expected_tags):
        raise MigrationEvidenceError(f"verified manifest inventory mismatch: {scenario['id']}")
    for item, tag in zip(manifests, expected_tags, strict=True):
        if tag == TARGET_RELEASE:
            channel = "offline-qualification-bundle"
            source_package = checkpoint_packages[
                "candidate-v4100-initial"
                if scenario["id"] == "verified-candidate-install-v4043-to-v4100"
                else "candidate-v4100-reupgrade"
            ]
        elif scenario["id"] == "signed-rollback-v4100-to-v4043":
            channel = "verified-native-rollback"
            source_package = "not-applicable"
        else:
            channel = "production-online-latest"
            source_package = checkpoint_packages[
                "bootstrap-v4032-initial"
                if scenario["id"] == "signed-update-v4032-to-v4043"
                else "bootstrap-v4032-reupgrade"
            ]
        _manifest_verification(
            item,
            tag,
            candidate_sha,
            openpgp_fingerprint,
            contract,
            channel,
            source_package,
            expected_candidate_package,
        )
    bootstrap_scenarios = {
        "verified-manual-trust-bootstrap-v4028-to-v4032": "bootstrap-v4032-initial",
        "verified-reupgrade-v4028-through-v4043-to-v4100": "bootstrap-v4032-reupgrade",
    }
    if scenario["id"] in bootstrap_scenarios:
        bootstrap = _exact(
            scenario["trust_bootstrap_verification"],
            {
                "release_tag", "producer_commit_sha", "release_tag_signature_verified",
                "release_checksums_sha256", "package_sha256", "package_digest_matched",
                "download_origin", "manual_first_hop", "historical_updater_used",
            },
            "v4.03.2 trust bootstrap verification",
        )
        if (
            bootstrap["release_tag"] != TRUST_BOOTSTRAP_RELEASE
            or bootstrap["producer_commit_sha"] != TRUST_BOOTSTRAP_COMMIT
            or bootstrap["release_tag_signature_verified"] is not True
            or bootstrap["package_digest_matched"] is not True
            or bootstrap["download_origin"] != "github-release-assets-separated"
            or bootstrap["manual_first_hop"] is not True
            or bootstrap["historical_updater_used"] is not False
            or bootstrap["package_sha256"]
            != checkpoint_packages[bootstrap_scenarios[scenario["id"]]]
        ):
            raise MigrationEvidenceError("historical v4.03.2 trust bootstrap is invalid")
        for key in ("release_checksums_sha256", "package_sha256"):
            _string(bootstrap[key], SHA256, f"trust bootstrap {key}")
    elif scenario["trust_bootstrap_verification"] != "not-applicable":
        raise MigrationEvidenceError("non-bootstrap scenario must not claim the historical trust bootstrap")
    observed_at = _timestamp(scenario["observed_at"], "scenario timestamp")
    _string(scenario["evidence_sha256"], SHA256, "scenario evidence digest")
    ref = _string(scenario["evidence_ref"], REFERENCE, "scenario evidence reference")
    return scenario, ref, observed_at


def _validate_attestation(value: object, candidate_sha: str) -> str:
    attestation = _exact(
        value,
        {
            "mechanism", "statement_sha256", "signature_sha256", "signer_identity",
            "verification_status", "verified_by", "attested_candidate_sha",
            "native_bundle_verified", "evidence_ref", "evidence_sha256",
        },
        "campaign attestation",
    )
    if attestation["mechanism"] not in {
        "github-artifact-attestation", "sigstore-bundle", "operator-signed-in-toto"
    }:
        raise MigrationEvidenceError("unsupported campaign attestation mechanism")
    for key in ("statement_sha256", "signature_sha256", "evidence_sha256"):
        _string(attestation[key], SHA256, f"campaign attestation {key}")
    _string(attestation["signer_identity"], IDENTITY, "campaign attestation signer identity")
    if (
        attestation["verification_status"] != "verified"
        or attestation["verified_by"] != "release-owner-gate"
        or attestation["attested_candidate_sha"] != candidate_sha
        or attestation["native_bundle_verified"] is not True
    ):
        raise MigrationEvidenceError("campaign attestation is not verified and candidate-bound")
    return _string(attestation["evidence_ref"], REFERENCE, "campaign attestation reference")


def _verify_raw_inventory(
    document: dict[str, Any],
    artifact_root: Path,
    references: set[str],
    maximum_reference_bytes: int,
) -> None:
    raw_root = artifact_root / "raw"
    try:
        names = list(raw_root.iterdir())
    except OSError as exc:
        raise MigrationEvidenceError("cannot enumerate raw evidence directory") from exc
    actual: set[str] = set()
    for path in names:
        try:
            info = path.lstat()
        except OSError as exc:
            raise MigrationEvidenceError("cannot inspect raw evidence inventory") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MigrationEvidenceError("raw evidence inventory contains an unsafe entry")
        actual.add(f"raw/{path.name}")
    if actual != references:
        raise MigrationEvidenceError("raw evidence inventory is not exact")

    digest_by_ref: dict[str, str] = {}
    host = document["host"]
    digest_by_ref[host["attestation_ref"]] = host["attestation_sha256"]
    for collection in (document["checkpoints"], document["scenarios"]):
        for item in collection:
            digest_by_ref[item["evidence_ref"]] = item["evidence_sha256"]
    attestation = document["attestation"]
    digest_by_ref[attestation["evidence_ref"]] = attestation["evidence_sha256"]
    if set(digest_by_ref) != references:
        raise MigrationEvidenceError("raw evidence references are reused or ambiguous")
    for ref, expected in digest_by_ref.items():
        _, wire = _raw_bytes(artifact_root, ref, maximum_reference_bytes)
        _decode_json(wire, ref)
        if hashlib.sha256(wire).hexdigest() != expected:
            raise MigrationEvidenceError(f"raw evidence digest mismatch: {ref}")


def validate_evidence(
    document: dict[str, Any],
    *,
    artifact_root: Path,
    candidate_sha: str,
    openpgp_fingerprint: str,
    candidate_package_name: str,
    candidate_package_sha256: str,
    candidate_package_size: int,
    release_tag: str = TARGET_RELEASE,
    contract_path: Path = DEFAULT_CONTRACT,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    _string(candidate_sha, SHA1, "candidate SHA")
    _string(openpgp_fingerprint, OPENPGP_FINGERPRINT, "qualified OpenPGP fingerprint")
    candidate_package_record = _candidate_package_record(
        candidate_package_name, candidate_package_sha256, candidate_package_size
    )
    if candidate_sha in {BASELINE_COMMIT, TRUST_BOOTSTRAP_COMMIT, STABLE_COMMIT}:
        raise MigrationEvidenceError("candidate SHA must differ from every historical release")
    if release_tag != TARGET_RELEASE:
        raise MigrationEvidenceError("unsupported release tag")
    contract, contract_sha256 = _contract(contract_path)
    _exact(
        document,
        {
            "schema", "repository", "release_tag", "candidate_sha", "candidate_package",
            "openpgp_signer_fingerprint",
            "contract_sha256", "observations_sha256", "campaign", "host", "checkpoints",
            "scenarios", "attestation",
        },
        "migration evidence",
    )
    if document["schema"] != EVIDENCE_SCHEMA or document["repository"] != REPOSITORY:
        raise MigrationEvidenceError("migration evidence identity mismatch")
    if document["release_tag"] != release_tag or document["candidate_sha"] != candidate_sha:
        raise MigrationEvidenceError("migration evidence candidate binding mismatch")
    if document["openpgp_signer_fingerprint"] != openpgp_fingerprint:
        raise MigrationEvidenceError("migration evidence signing-policy binding mismatch")
    if document["candidate_package"] != candidate_package_record:
        raise MigrationEvidenceError(
            "migration evidence package binding differs from protected signing provenance"
        )
    if document["contract_sha256"] != contract_sha256:
        raise MigrationEvidenceError("migration contract digest mismatch")
    _string(document["observations_sha256"], SHA256, "source observations digest")

    campaign = _exact(
        document["campaign"],
        {
            "id", "started_at", "completed_at", "operator_identity", "observation_origin",
            "synthetic", "network_control", "snapshot_reference",
        },
        "migration campaign",
    )
    _string(campaign["id"], IDENTIFIER, "campaign id")
    _string(campaign["operator_identity"], IDENTITY, "operator identity")
    _string(campaign["snapshot_reference"], IDENTITY, "snapshot reference")
    if (
        campaign["observation_origin"] != contract["guardrails"]["observation_origin"]
        or campaign["synthetic"] is not False
        or campaign["network_control"] != "provider-firewall"
    ):
        raise MigrationEvidenceError("synthetic or non-native migration observations are forbidden")
    started = _timestamp(campaign["started_at"], "campaign start")
    completed = _timestamp(campaign["completed_at"], "campaign completion")
    if completed <= started:
        raise MigrationEvidenceError("campaign completion must follow its start")
    limits = contract["limits"]
    if (completed - started).total_seconds() > limits["maximum_campaign_seconds"]:
        raise MigrationEvidenceError("migration campaign exceeded its duration bound")
    now = validation_time or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise MigrationEvidenceError("validation time must be timezone-aware")
    now = now.astimezone(dt.timezone.utc)
    if completed > now + dt.timedelta(seconds=limits["maximum_future_skew_seconds"]):
        raise MigrationEvidenceError("migration campaign completion is in the future")

    references: set[str] = set()
    host_ref = _validate_host(document["host"], contract, candidate_sha)
    references.add(host_ref)

    expected_checkpoints = contract["checkpoints"]
    checkpoints_value = document["checkpoints"]
    if type(checkpoints_value) is not list or len(checkpoints_value) != len(expected_checkpoints):
        raise MigrationEvidenceError("checkpoint inventory is not exact")
    checkpoints: list[dict[str, Any]] = []
    checkpoint_times: list[dt.datetime] = []
    for value, expected in zip(checkpoints_value, expected_checkpoints, strict=True):
        checkpoint, ref, observed_at = _validate_checkpoint(value, expected, candidate_sha)
        if ref in references:
            raise MigrationEvidenceError("raw evidence reference is reused")
        references.add(ref)
        checkpoints.append(checkpoint)
        checkpoint_times.append(observed_at)
    if any(later <= earlier for earlier, later in zip(checkpoint_times, checkpoint_times[1:])) or any(
        timestamp < started or timestamp > completed for timestamp in checkpoint_times
    ):
        raise MigrationEvidenceError("checkpoint timestamps are outside the ordered campaign")

    by_checkpoint = {item["id"]: item for item in checkpoints}
    baseline = by_checkpoint["baseline-v4028"]
    installed = [item for item in checkpoints if item["installed_version"] != "absent"]
    for item in installed:
        if item["configuration_semantic_sha256"] != baseline["configuration_semantic_sha256"]:
            raise MigrationEvidenceError("configuration semantics changed across migration")
        if item["operator_state_canary_sha256"] != baseline["operator_state_canary_sha256"]:
            raise MigrationEvidenceError("operator state canary changed across migration")
    for version, ids in {
        BASELINE_RELEASE: ("baseline-v4028", "baseline-v4028-snapshot"),
        TRUST_BOOTSTRAP_RELEASE: ("bootstrap-v4032-initial", "bootstrap-v4032-reupgrade"),
        STABLE_RELEASE: ("stable-v4043-initial", "stable-v4043-rollback", "stable-v4043-reupgrade"),
        TARGET_RELEASE: ("candidate-v4100-initial", "candidate-v4100-reupgrade"),
    }.items():
        package_hashes = {by_checkpoint[item]["installed_package_sha256"] for item in ids}
        if len(package_hashes) != 1:
            raise MigrationEvidenceError(f"installed package bytes changed for {version}")
    if by_checkpoint["baseline-v4028-snapshot"]["boot_id_sha256"] == baseline["boot_id_sha256"]:
        raise MigrationEvidenceError("snapshot recovery did not attest a new boot")
    if by_checkpoint["candidate-v4100-reupgrade"]["boot_id_sha256"] == by_checkpoint["candidate-v4100-initial"]["boot_id_sha256"]:
        raise MigrationEvidenceError("re-upgrade did not occur after the attested snapshot boot")

    expected_scenarios = contract["scenarios"]
    scenarios_value = document["scenarios"]
    if type(scenarios_value) is not list or len(scenarios_value) != len(expected_scenarios):
        raise MigrationEvidenceError("migration scenario inventory is not exact")
    scenarios: list[dict[str, Any]] = []
    scenario_times: list[dt.datetime] = []
    checkpoint_packages = {
        checkpoint_id: value["installed_package_sha256"]
        for checkpoint_id, value in by_checkpoint.items()
    }
    for value, expected in zip(scenarios_value, expected_scenarios, strict=True):
        scenario, ref, observed_at = _validate_scenario(
            value,
            expected,
            candidate_sha,
            openpgp_fingerprint,
            contract,
            checkpoint_packages,
            candidate_package_record,
        )
        if ref in references:
            raise MigrationEvidenceError("raw evidence reference is reused")
        references.add(ref)
        scenarios.append(scenario)
        scenario_times.append(observed_at)
    if any(later <= earlier for earlier, later in zip(scenario_times, scenario_times[1:])) or any(
        timestamp < started or timestamp > completed for timestamp in scenario_times
    ):
        raise MigrationEvidenceError("scenario timestamps are outside the ordered campaign")

    candidate_source_checkpoints = {
        "verified-candidate-install-v4043-to-v4100": "stable-v4043-initial",
        "verified-reupgrade-v4028-through-v4043-to-v4100": "stable-v4043-reupgrade",
    }
    for scenario in scenarios:
        source_id = candidate_source_checkpoints.get(scenario["id"])
        if source_id is None:
            continue
        candidate_manifests = [
            item
            for item in scenario["verified_manifests"]
            if item["release_tag"] == TARGET_RELEASE
        ]
        if len(candidate_manifests) != 1:
            raise MigrationEvidenceError("candidate prevalidation manifest is ambiguous")
        prevalidation = candidate_manifests[0]["qualification_prevalidation"]
        source = by_checkpoint[source_id]
        if (
            prevalidation["operator_state_before_sha256"]
            != source["operator_state_canary_sha256"]
            or prevalidation["operator_state_at_install_sha256"]
            != source["operator_state_canary_sha256"]
            or prevalidation["firewall_state_before_sha256"]
            != source["syswarden_firewall_sha256"]
            or prevalidation["firewall_state_at_install_sha256"]
            != source["syswarden_firewall_sha256"]
        ):
            raise MigrationEvidenceError(
                "candidate prevalidation state differs from the attested source checkpoint"
            )

    stable_package = by_checkpoint["stable-v4043-initial"]["installed_package_sha256"]
    candidate_package = by_checkpoint["candidate-v4100-initial"]["installed_package_sha256"]
    if candidate_package != candidate_package_record["sha256"]:
        raise MigrationEvidenceError(
            "installed candidate package differs from protected signing provenance"
        )
    for scenario in scenarios:
        for manifest in scenario["verified_manifests"]:
            expected_package = stable_package if manifest["release_tag"] == STABLE_RELEASE else candidate_package
            if manifest["package_sha256"] != expected_package:
                raise MigrationEvidenceError("verified manifest package digest differs from installed bytes")

    attestation_ref = _validate_attestation(document["attestation"], candidate_sha)
    if attestation_ref in references:
        raise MigrationEvidenceError("raw evidence reference is reused")
    references.add(attestation_ref)
    _verify_raw_inventory(document, artifact_root, references, limits["maximum_reference_bytes"])

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": VERDICT_SCHEMA,
        "status": "pass",
        "repository": REPOSITORY,
        "release_tag": release_tag,
        "candidate_sha": candidate_sha,
        "candidate_package": candidate_package_record,
        "openpgp_signer_fingerprint": openpgp_fingerprint,
        "contract_sha256": contract_sha256,
        "campaign_id": campaign["id"],
        "node_id": document["host"]["node_id"],
        "checkpoint_count": len(checkpoints),
        "scenario_count": len(scenarios),
        "raw_evidence_count": len(references),
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _add_digest(
    item: object,
    artifact_root: Path,
    maximum_reference_bytes: int,
    digest_key: str,
    reference_key: str = "evidence_ref",
) -> dict[str, Any]:
    if type(item) is not dict:
        raise MigrationEvidenceError("observation entry must be an object")
    result = dict(item)
    if digest_key in result:
        raise MigrationEvidenceError(f"observations must not supply {digest_key}")
    if reference_key not in result:
        raise MigrationEvidenceError(f"observation entry is missing {reference_key}")
    ref, wire = _raw_bytes(artifact_root, result[reference_key], maximum_reference_bytes)
    result[reference_key] = ref
    result[digest_key] = hashlib.sha256(wire).hexdigest()
    return result


def assemble_evidence(
    observations_path: Path,
    *,
    artifact_root: Path,
    candidate_sha: str,
    openpgp_fingerprint: str,
    candidate_package_name: str,
    candidate_package_sha256: str,
    candidate_package_size: int,
    release_tag: str = TARGET_RELEASE,
    contract_path: Path = DEFAULT_CONTRACT,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    _string(candidate_sha, SHA1, "candidate SHA")
    _string(openpgp_fingerprint, OPENPGP_FINGERPRINT, "qualified OpenPGP fingerprint")
    candidate_package_record = _candidate_package_record(
        candidate_package_name, candidate_package_sha256, candidate_package_size
    )
    if release_tag != TARGET_RELEASE:
        raise MigrationEvidenceError("unsupported release tag")
    contract, contract_sha256 = _contract(contract_path)
    observations, wire = _load_json(observations_path, "migration observations")
    _exact(
        observations,
        {"schema", "campaign", "host", "checkpoints", "scenarios", "attestation"},
        "migration observations",
    )
    if observations["schema"] != OBSERVATIONS_SCHEMA:
        raise MigrationEvidenceError("unsupported migration observations schema")
    maximum_reference_bytes = contract["limits"]["maximum_reference_bytes"]
    host = _add_digest(
        observations["host"],
        artifact_root,
        maximum_reference_bytes,
        "attestation_sha256",
        "attestation_ref",
    )
    checkpoints_value = observations["checkpoints"]
    scenarios_value = observations["scenarios"]
    if type(checkpoints_value) is not list or type(scenarios_value) is not list:
        raise MigrationEvidenceError("observations checkpoints and scenarios must be arrays")
    checkpoints = [
        _add_digest(item, artifact_root, maximum_reference_bytes, "evidence_sha256")
        if type(item) is dict else item
        for item in checkpoints_value
    ]
    scenarios = [
        _add_digest(item, artifact_root, maximum_reference_bytes, "evidence_sha256")
        if type(item) is dict else item
        for item in scenarios_value
    ]
    attestation = _add_digest(
        observations["attestation"], artifact_root, maximum_reference_bytes, "evidence_sha256"
    )
    document = {
        "schema": EVIDENCE_SCHEMA,
        "repository": REPOSITORY,
        "release_tag": release_tag,
        "candidate_sha": candidate_sha,
        "candidate_package": candidate_package_record,
        "openpgp_signer_fingerprint": openpgp_fingerprint,
        "contract_sha256": contract_sha256,
        "observations_sha256": hashlib.sha256(wire).hexdigest(),
        "campaign": observations["campaign"],
        "host": host,
        "checkpoints": checkpoints,
        "scenarios": scenarios,
        "attestation": attestation,
    }
    validate_evidence(
        document,
        artifact_root=artifact_root,
        candidate_sha=candidate_sha,
        openpgp_fingerprint=openpgp_fingerprint,
        candidate_package_name=candidate_package_name,
        candidate_package_sha256=candidate_package_sha256,
        candidate_package_size=candidate_package_size,
        release_tag=release_tag,
        contract_path=contract_path,
        validation_time=validation_time,
    )
    return document


def _write_json(path: Path, document: dict[str, Any]) -> None:
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    parent = path.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise MigrationEvidenceError("output parent cannot be inspected") from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise MigrationEvidenceError("output parent must be a real directory")
    if path.is_symlink():
        raise MigrationEvidenceError("output must not be a symbolic link")
    temporary = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest_parser = subparsers.add_parser("contract-digest")
    digest_parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    assemble_parser.add_argument("--observations", type=Path, required=True)
    assemble_parser.add_argument("--artifact-root", type=Path, required=True)
    assemble_parser.add_argument("--candidate-sha", required=True)
    assemble_parser.add_argument("--openpgp-fingerprint", required=True)
    assemble_parser.add_argument("--candidate-package-name", required=True)
    assemble_parser.add_argument("--candidate-package-sha256", required=True)
    assemble_parser.add_argument("--candidate-package-size", required=True, type=int)
    assemble_parser.add_argument("--release-tag", default=TARGET_RELEASE)
    assemble_parser.add_argument("--output", type=Path, required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    validate_parser.add_argument("--evidence", type=Path, required=True)
    validate_parser.add_argument("--artifact-root", type=Path, required=True)
    validate_parser.add_argument("--candidate-sha", required=True)
    validate_parser.add_argument("--openpgp-fingerprint", required=True)
    validate_parser.add_argument("--candidate-package-name", required=True)
    validate_parser.add_argument("--candidate-package-sha256", required=True)
    validate_parser.add_argument("--candidate-package-size", required=True, type=int)
    validate_parser.add_argument("--release-tag", default=TARGET_RELEASE)
    validate_parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "contract-digest":
            print(contract_digest(args.contract))
            return 0
        if args.command == "assemble":
            document = assemble_evidence(
                args.observations,
                artifact_root=args.artifact_root,
                candidate_sha=args.candidate_sha,
                openpgp_fingerprint=args.openpgp_fingerprint,
                candidate_package_name=args.candidate_package_name,
                candidate_package_sha256=args.candidate_package_sha256,
                candidate_package_size=args.candidate_package_size,
                release_tag=args.release_tag,
                contract_path=args.contract,
            )
            _write_json(args.output, document)
            return 0
        evidence, _ = _load_json(args.evidence, "migration evidence")
        verdict = validate_evidence(
            evidence,
            artifact_root=args.artifact_root,
            candidate_sha=args.candidate_sha,
            openpgp_fingerprint=args.openpgp_fingerprint,
            candidate_package_name=args.candidate_package_name,
            candidate_package_sha256=args.candidate_package_sha256,
            candidate_package_size=args.candidate_package_size,
            release_tag=args.release_tag,
            contract_path=args.contract,
        )
        if args.output:
            _write_json(args.output, verdict)
        else:
            print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
        return 0
    except (MigrationEvidenceError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
