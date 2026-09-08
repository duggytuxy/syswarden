#!/usr/bin/env python3
"""Validate candidate-bound native update-feeds evidence from NODE02."""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

try:
    from scripts.ci import native_package_signature_gate as signature_gate
    from scripts.ci import osint_tls_fixture as tls_fixture
except ModuleNotFoundError:
    import native_package_signature_gate as signature_gate
    import osint_tls_fixture as tls_fixture


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "scripts/ci/native_feed_contract_v4.10.0.json"
CONTRACT_SHA256 = "5ce9288637df56cd1303351c83023730b4cd1796236151b2a814a14c0846b035"
EVIDENCE_SCHEMA = "syswarden-native-feed-qualification-evidence/v1"
VERDICT_SCHEMA = "syswarden-native-feed-qualification-verdict/v1"
REPOSITORY = "duggytuxy/syswarden"
TARGET_RELEASE = "v4.10.0"
PACKAGE_NAME = "syswarden_4.10.0_amd64.deb"
PACKAGE_VERSION = "4.10.0"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPENPGP_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
UTC = re.compile(
    r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)

EXPECTED_PROFILE = {
    "id": "DEB-U2604",
    "host_id": "node02",
    "os_id": "ubuntu",
    "os_version": "26.04",
    "architecture": "amd64",
    "package_family": "deb",
    "package_manager": "dpkg",
    "service_manager": "systemd",
    "firewall_backend": "nftables",
    "candidate_signature_mechanism": "openpgp-detached",
}
EXPECTED_SCENARIOS = (
    {
        "id": "success-with-filtered-6to4",
        "sequence": 1,
        "fixture_mode": "success",
        "command_exit": "zero",
        "diagnostic": (
            "[WARNING] OSINT source https://lists.blocklist.de ignored 1 "
            "non-public or special-use CIDR entry."
        ),
    },
    {
        "id": "reject-malformed-syntax",
        "sequence": 2,
        "fixture_mode": "malformed",
        "command_exit": "nonzero",
        "diagnostic": "invalid CIDR at line 5",
    },
    {
        "id": "reject-valid-volume-below-minimum",
        "sequence": 3,
        "fixture_mode": "below-minimum",
        "command_exit": "nonzero",
        "diagnostic": (
            "feed contains 3 canonical entries after ignoring 1 non-public or "
            "special-use entries, minimum is 4"
        ),
    },
)
EXPECTED_PROVENANCE = {
    "schema": "syswarden.feed-provenance.v1",
    "allowed_states": ["current", "stale", "unavailable", "rejected"],
    "allowed_freshness": [
        "current",
        "stale",
        "unavailable",
        "rejected",
        "expired",
    ],
    "required_attestation_status": "verified",
}
EXPECTED_FIREWALL = {
    "family": "inet",
    "table": "syswarden",
    "sets": ["syswarden_blacklist", "syswarden_blacklist6"],
    "digest_encoding": "canonical-json-sha256",
}
EXPECTED_GUARDRAILS = {
    "observations": "real-native-node02-lab-only",
    "synthetic_observations": False,
    "node_scope": "node02-only",
    "network_fixture": "deterministic-tls-system-trust-only",
    "product_url_override": False,
    "product_downloader_override": False,
    "product_validation_override": False,
    "product_trust_bypass": False,
    "proxy_bypass": False,
    "failure_modes": "existing-fixture-modes-only",
    "runtime_quarantined": True,
    "snapshot_restore_required": True,
}
EXPECTED_LIMITS = {
    "maximum_input_bytes": 1048576,
    "maximum_package_bytes": 268435456,
    "maximum_raw_total_bytes": 134217728,
    "maximum_feed_bytes": 16777216,
    "maximum_certificate_bytes": 1048576,
    "maximum_campaign_seconds": 3600,
    "maximum_future_skew_seconds": 300,
    "maximum_source_origin_bytes": 2048,
    "maximum_counter": 5000000,
}


class NativeFeedEvidenceError(ValueError):
    """Raised when native feed evidence is incomplete or unsafe."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeFeedEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise NativeFeedEvidenceError(f"non-finite JSON number: {value}")


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
        raise NativeFeedEvidenceError(f"cannot inspect {label}: {path}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise NativeFeedEvidenceError(f"{label} is not one bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise NativeFeedEvidenceError(f"cannot open {label}: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        consumed = 0
        while consumed <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _identity(before) != _identity(opened) or _identity(opened) != _identity(after):
        raise NativeFeedEvidenceError(f"{label} changed while reading")
    wire = b"".join(chunks)
    if not wire or len(wire) > maximum or len(wire) != opened.st_size:
        raise NativeFeedEvidenceError(f"{label} size is outside accepted bounds")
    return wire


def _load_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    wire = _regular_bytes(path, maximum, label)
    try:
        document = json.loads(
            wire.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeFeedEvidenceError(f"invalid JSON in {label}: {path}") from exc
    if type(document) is not dict:
        raise NativeFeedEvidenceError(f"{label} JSON root must be an object")
    return document, wire


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise NativeFeedEvidenceError(f"{label} keys are not exact")
    return value


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise NativeFeedEvidenceError(f"invalid {label}")
    return value


def _sha256(value: object, label: str) -> str:
    return _string(value, SHA256, label)


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise NativeFeedEvidenceError(f"invalid {label}")
    return value


def _timestamp(value: object, label: str) -> dt.datetime:
    text = _string(value, UTC, label)
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise NativeFeedEvidenceError(f"invalid {label}") from exc


def _script_digest(relative: str, maximum: int) -> str:
    path = ROOT / relative
    if path.resolve().parent != (ROOT / "scripts/ci").resolve():
        raise NativeFeedEvidenceError("contract script path escaped scripts/ci")
    return hashlib.sha256(_regular_bytes(path, maximum, "qualification script")).hexdigest()


def load_contract(
    path: Path = DEFAULT_CONTRACT,
) -> tuple[dict[str, Any], str]:
    document, wire = _load_json(path, EXPECTED_LIMITS["maximum_input_bytes"], "contract")
    _exact(
        document,
        {
            "schema_version",
            "contract_id",
            "target_release",
            "qualification_state",
            "publishing",
            "profile",
            "fixture",
            "provenance",
            "firewall",
            "guardrails",
            "limits",
            "raw_evidence",
        },
        "contract",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["contract_id"] != "syswarden-native-feed-qualification/v1"
        or document["target_release"] != TARGET_RELEASE
        or document["qualification_state"] != "candidate-not-qualified"
        or document["publishing"] is not False
    ):
        raise NativeFeedEvidenceError("native feed contract identity is invalid")
    if document["profile"] != EXPECTED_PROFILE:
        raise NativeFeedEvidenceError("native feed profile contract is not exact")

    fixture = _exact(
        document["fixture"],
        {
            "lab_script",
            "fixture_script",
            "minimum_tls_version",
            "filtered_six_to_four_entry",
            "scenarios",
        },
        "fixture contract",
    )
    if (
        fixture["lab_script"] != "scripts/ci/osint_tls_qualification_lab.sh"
        or fixture["fixture_script"] != "scripts/ci/osint_tls_fixture.py"
        or fixture["minimum_tls_version"] != "TLS1.3"
        or fixture["filtered_six_to_four_entry"]
        != "2002:982a:b983::982a:b983"
    ):
        raise NativeFeedEvidenceError("native feed fixture contract is not exact")
    scenarios = fixture["scenarios"]
    if type(scenarios) is not list or len(scenarios) != len(EXPECTED_SCENARIOS):
        raise NativeFeedEvidenceError("native feed fixture scenario inventory is not exact")
    for observed, expected in zip(scenarios, EXPECTED_SCENARIOS, strict=True):
        _exact(
            observed,
            {"id", "sequence", "fixture_mode", "command_exit", "diagnostic"},
            "fixture scenario contract",
        )
        _integer(observed["sequence"], 1, 3, "fixture scenario sequence")
        if observed != expected:
            raise NativeFeedEvidenceError("native feed fixture scenario is not exact")
    if document["provenance"] != EXPECTED_PROVENANCE:
        raise NativeFeedEvidenceError("native feed provenance contract is not exact")
    if document["firewall"] != EXPECTED_FIREWALL:
        raise NativeFeedEvidenceError("native feed firewall contract is not exact")
    raw = _exact(document["raw_evidence"], {"manifest", "inventory"}, "raw evidence")
    if raw["manifest"] != "SHA256SUMS":
        raise NativeFeedEvidenceError("raw evidence manifest name is not exact")
    inventory = raw["inventory"]
    if (
        type(inventory) is not list
        or not inventory
        or any(type(item) is not str for item in inventory)
        or inventory != sorted(set(inventory))
        or any(
            not item
            or item.startswith("/")
            or "\\" in item
            or Path(item).as_posix() != item
            or ".." in Path(item).parts
            for item in inventory
        )
    ):
        raise NativeFeedEvidenceError("raw evidence inventory is not exact")
    if document["guardrails"] != EXPECTED_GUARDRAILS:
        raise NativeFeedEvidenceError("native feed guardrails are not exact")
    for key, expected in EXPECTED_GUARDRAILS.items():
        if type(expected) is bool and document["guardrails"][key] is not expected:
            raise NativeFeedEvidenceError("native feed guardrail boolean is not exact")
    if document["limits"] != EXPECTED_LIMITS:
        raise NativeFeedEvidenceError("native feed limits are not exact")
    if any(type(value) is not int for value in document["limits"].values()):
        raise NativeFeedEvidenceError("native feed limit type is not exact")

    digest = hashlib.sha256(wire).hexdigest()
    if path == DEFAULT_CONTRACT and digest != CONTRACT_SHA256:
        raise NativeFeedEvidenceError("committed native feed contract digest mismatch")
    return document, digest


def contract_digest(path: Path = DEFAULT_CONTRACT) -> str:
    """Return the validated contract digest."""

    return load_contract(path)[1]


def _validate_source_origin(value: object, maximum: int) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise NativeFeedEvidenceError("invalid feed source origin")
    origins = value.split(",")
    if not 1 <= len(origins) <= 16 or origins != sorted(set(origins)):
        raise NativeFeedEvidenceError("feed source origin inventory is ambiguous")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
            or origin != f"https://{parsed.netloc}"
        ):
            raise NativeFeedEvidenceError("feed source origin is not a canonical HTTPS origin")
    return value


def _validate_provenance(
    value: object,
    contract: dict[str, Any],
    started: dt.datetime,
    observed: dt.datetime,
) -> dict[str, Any]:
    provenance = _exact(
        value,
        {
            "schema",
            "state",
            "freshness",
            "source_origin",
            "retrieved_at",
            "sha256",
            "last_known_good_sha256",
            "accepted_count",
            "skipped_count",
            "rejected_count",
            "attestation_status",
        },
        "scenario provenance",
    )
    policy = contract["provenance"]
    if provenance["schema"] != policy["schema"]:
        raise NativeFeedEvidenceError("feed provenance schema is invalid")
    state = provenance["state"]
    freshness = provenance["freshness"]
    if state not in policy["allowed_states"] or freshness not in policy["allowed_freshness"]:
        raise NativeFeedEvidenceError("feed provenance state or freshness is invalid")
    if freshness != state and not (state == "current" and freshness == "expired"):
        raise NativeFeedEvidenceError("feed provenance state and freshness are inconsistent")
    _validate_source_origin(
        provenance["source_origin"], contract["limits"]["maximum_source_origin_bytes"]
    )
    retrieved = _timestamp(provenance["retrieved_at"], "feed retrieval timestamp")
    skew = dt.timedelta(seconds=contract["limits"]["maximum_future_skew_seconds"])
    if retrieved < started - skew or retrieved > observed + skew:
        raise NativeFeedEvidenceError("feed retrieval timestamp is outside campaign bounds")
    digest = _sha256(provenance["sha256"], "feed provenance digest")
    last_known_good = _sha256(
        provenance["last_known_good_sha256"], "last-known-good digest"
    )
    if digest != last_known_good:
        raise NativeFeedEvidenceError("feed provenance is not bound to last-known-good")
    maximum = contract["limits"]["maximum_counter"]
    accepted = _integer(provenance["accepted_count"], 1, maximum, "accepted count")
    del accepted
    _integer(provenance["skipped_count"], 0, maximum, "skipped count")
    rejected = _integer(provenance["rejected_count"], 0, maximum, "rejected count")
    if (
        (state == "current" and rejected != 0)
        or (state == "rejected" and rejected == 0)
        or (state == "unavailable" and rejected != 0)
    ):
        raise NativeFeedEvidenceError("feed provenance state counters are inconsistent")
    if provenance["attestation_status"] != policy["required_attestation_status"]:
        raise NativeFeedEvidenceError("active feed attestation is not verified")
    return provenance


def _validate_feeds(value: object, provenance: dict[str, Any]) -> dict[str, Any]:
    feeds = _exact(
        value,
        {
            "ipv4_sha256",
            "ipv4_size",
            "ipv6_sha256",
            "ipv6_size",
            "manifest_sha256",
            "snapshot_sha256",
            "snapshot_size",
            "last_known_good_bytes_preserved",
            "six_to_four_absent",
        },
        "scenario feeds",
    )
    ipv4 = _sha256(feeds["ipv4_sha256"], "IPv4 feed digest")
    ipv4_size = _integer(feeds["ipv4_size"], 1, 16 * 1024 * 1024, "IPv4 feed size")
    if feeds["ipv6_sha256"] is None:
        if _integer(feeds["ipv6_size"], 0, 0, "IPv6 feed size") != 0:
            raise NativeFeedEvidenceError("absent IPv6 feed has a nonzero size")
    else:
        _sha256(feeds["ipv6_sha256"], "IPv6 feed digest")
        _integer(feeds["ipv6_size"], 1, 16 * 1024 * 1024, "IPv6 feed size")
    _sha256(feeds["manifest_sha256"], "feed manifest digest")
    snapshot = _sha256(feeds["snapshot_sha256"], "active feed snapshot digest")
    snapshot_size = _integer(
        feeds["snapshot_size"], 1, 16 * 1024 * 1024, "active feed snapshot size"
    )
    if (
        ipv4 != snapshot
        or ipv4_size != snapshot_size
        or snapshot != provenance["sha256"]
        or feeds["last_known_good_bytes_preserved"] is not True
        or feeds["six_to_four_absent"] is not True
    ):
        raise NativeFeedEvidenceError("feed bytes are not bound to the active last-known-good")
    return feeds


def _validate_firewall(
    value: object, contract: dict[str, Any]
) -> dict[str, Any]:
    firewall = _exact(
        value,
        {
            "family",
            "table",
            "sets",
            "semantic_sha256",
            "post_update_capture_verified",
            "reapply_completed",
        },
        "scenario firewall",
    )
    expected = contract["firewall"]
    if (
        firewall["family"] != expected["family"]
        or firewall["table"] != expected["table"]
        or firewall["sets"] != expected["sets"]
        or firewall["post_update_capture_verified"] is not True
        or firewall["reapply_completed"] is not True
    ):
        raise NativeFeedEvidenceError("firewall reapply evidence is incomplete")
    _sha256(firewall["semantic_sha256"], "firewall semantic digest")
    return firewall


EMPTY_RAW_FILES = frozenset(
    {
        "concurrency/process-before.txt",
        "concurrency/process-drained.txt",
        "concurrency/root-crontab.txt",
        "concurrency/schedule-conflicts.txt",
        "concurrency/timers.txt",
        "package/dpkg-verify.stderr",
        "package/dpkg-verify.stdout",
        "package/extraction.stderr",
        "package/gpgv.stderr",
        "transport/fixture.stdout.log",
    }
    | {
        f"scenarios/{scenario['id']}/ipv6.feed" for scenario in EXPECTED_SCENARIOS
    }
)


def _raw_bytes(path: Path, maximum: int, label: str, *, allow_empty: bool) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise NativeFeedEvidenceError(f"cannot inspect {label}: {path}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > maximum
        or (before.st_size == 0 and not allow_empty)
    ):
        raise NativeFeedEvidenceError(f"{label} is not one private bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        consumed = 0
        while consumed <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    wire = b"".join(chunks)
    if (
        _identity(before) != _identity(opened)
        or _identity(opened) != _identity(after)
        or len(wire) != opened.st_size
        or len(wire) > maximum
        or (not wire and not allow_empty)
    ):
        raise NativeFeedEvidenceError(f"{label} changed or exceeded its bound")
    return wire


def _strict_json_bytes(wire: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            wire.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeFeedEvidenceError(f"invalid JSON in {label}") from exc
    if type(value) is not dict:
        raise NativeFeedEvidenceError(f"{label} JSON root must be an object")
    return value


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _check_private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise NativeFeedEvidenceError(f"cannot inspect {label}: {path}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeFeedEvidenceError(f"{label} must be one private owner-controlled directory")


def load_raw_bundle(
    root: Path, contract: dict[str, Any]
) -> tuple[dict[str, bytes], str]:
    """Load and authenticate the exact raw evidence inventory."""

    if not root.is_absolute() or Path(os.path.normpath(root)) != root:
        raise NativeFeedEvidenceError("raw evidence root must be canonical and absolute")
    _check_private_directory(root, "raw evidence root")
    expected = contract["raw_evidence"]["inventory"]
    expected_directories = {"."}
    for relative in expected:
        parent = Path(relative).parent
        while parent != Path("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories = {"."}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            _check_private_directory(path, f"raw evidence directory {relative}")
            actual_directories.add(relative)
        elif stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            actual_files.add(relative)
        else:
            raise NativeFeedEvidenceError(f"unsafe raw evidence object: {relative}")
    manifest_name = contract["raw_evidence"]["manifest"]
    if actual_directories != expected_directories or actual_files != set(expected) | {
        manifest_name
    }:
        raise NativeFeedEvidenceError("raw evidence filesystem inventory is not exact")
    limit = contract["limits"]["maximum_raw_total_bytes"]
    files: dict[str, bytes] = {}
    total = 0
    for relative in expected:
        maximum = (
            contract["limits"]["maximum_feed_bytes"]
            if relative.endswith((".feed", ".snapshot", ".body"))
            else contract["limits"]["maximum_input_bytes"]
        )
        wire = _raw_bytes(
            root / relative,
            maximum,
            f"raw evidence {relative}",
            allow_empty=relative in EMPTY_RAW_FILES,
        )
        upper_wire = wire.upper()
        # Build the sentinels without storing complete private-key headers in
        # source, so repository scanners do not mistake the guardrail itself
        # for secret material.
        private_markers = tuple(
            b"-----BEGIN " + key_type + b"-----"
            for key_type in (
                b"PRIVATE KEY",
                b"ENCRYPTED PRIVATE KEY",
                b"RSA PRIVATE KEY",
                b"EC PRIVATE KEY",
                b"DSA PRIVATE KEY",
                b"OPENSSH PRIVATE KEY",
                b"PGP PRIVATE KEY BLOCK",
            )
        ) + (b"OPENSSH-KEY-V1\x00",)
        if any(marker in upper_wire for marker in private_markers):
            raise NativeFeedEvidenceError(f"private key material entered raw evidence: {relative}")
        total += len(wire)
        if total > limit:
            raise NativeFeedEvidenceError("raw evidence total size exceeds its bound")
        files[relative] = wire
    manifest = _raw_bytes(
        root / manifest_name,
        contract["limits"]["maximum_input_bytes"],
        "raw evidence manifest",
        allow_empty=False,
    )
    expected_manifest = b"".join(
        f"{hashlib.sha256(files[relative]).hexdigest()}  {relative}\n".encode("ascii")
        for relative in expected
    )
    if manifest != expected_manifest:
        raise NativeFeedEvidenceError("raw evidence manifest bytes are not canonical")
    try:
        lines = manifest.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise NativeFeedEvidenceError("raw evidence manifest is not ASCII") from exc
    observed: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-zA-Z0-9][a-zA-Z0-9._/-]*)", line)
        if match is None or match.group(2) in observed:
            raise NativeFeedEvidenceError("raw evidence manifest is malformed or ambiguous")
        observed[match.group(2)] = match.group(1)
    if list(observed) != expected or set(observed) != set(expected):
        raise NativeFeedEvidenceError("raw evidence manifest inventory or order is not exact")
    for relative, wire in files.items():
        if hashlib.sha256(wire).hexdigest() != observed[relative]:
            raise NativeFeedEvidenceError(f"raw evidence manifest digest mismatch: {relative}")
    return files, hashlib.sha256(manifest).hexdigest()


def _one_line(wire: bytes, label: str, *, allow_empty: bool = False) -> str:
    try:
        text = wire.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NativeFeedEvidenceError(f"{label} is not UTF-8") from exc
    if (not text and allow_empty) or (text.endswith("\n") and "\n" not in text[:-1]):
        return text[:-1] if text else ""
    raise NativeFeedEvidenceError(f"{label} must contain one canonical line")


def _digest_line(wire: bytes, expected_name: str, label: str) -> str:
    match = re.fullmatch(
        rb"([0-9a-f]{64})  " + re.escape(expected_name.encode("ascii")) + rb"\n",
        wire,
    )
    if match is None:
        raise NativeFeedEvidenceError(f"{label} is not one canonical SHA-256 record")
    return match.group(1).decode("ascii")


def _exit_code(wire: bytes, label: str) -> int:
    value = _one_line(wire, label)
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", value) is None:
        raise NativeFeedEvidenceError(f"{label} is not a canonical exit code")
    result = int(value)
    if result > 255:
        raise NativeFeedEvidenceError(f"{label} exceeds the process exit-code range")
    return result


def _hosts_state(wire: bytes, label: str) -> dict[str, Any]:
    value = _strict_json_bytes(wire, label)
    _exact(
        value,
        {"device", "gid", "inode", "mode", "nlink", "sha256", "size", "uid"},
        label,
    )
    if (
        type(value["device"]) is not int
        or value["device"] < 0
        or type(value["inode"]) is not int
        or value["inode"] <= 0
        or value["uid"] != 0
        or type(value["gid"]) is not int
        or value["gid"] < 0
        or value["mode"] not in {"0644", "0600"}
        or value["nlink"] != 1
        or type(value["size"]) is not int
        or value["size"] < 0
    ):
        raise NativeFeedEvidenceError(f"{label} metadata is not qualification-safe")
    _sha256(value["sha256"], f"{label} digest")
    return value


def _list_state(wire: bytes, label: str) -> dict[str, Any]:
    value = _strict_json_bytes(wire, label)
    _exact(value, {"entries", "root", "schema"}, label)
    if value["schema"] != "syswarden-native-list-state/v1":
        raise NativeFeedEvidenceError(f"{label} schema is invalid")
    root = value["root"]
    if type(root) is not dict:
        raise NativeFeedEvidenceError(f"{label} root metadata is invalid")
    _exact(root, {"gid", "mode", "uid"}, f"{label} root")
    if (
        root["uid"] != 0
        or type(root["gid"]) is not int
        or root["gid"] < 0
        or type(root["mode"]) is not str
        or re.fullmatch(r"0[0-7]{3}", root["mode"]) is None
        or int(root["mode"], 8) & 0o022
    ):
        raise NativeFeedEvidenceError(f"{label} root is not protected")
    entries = value["entries"]
    if type(entries) is not list or len(entries) > 4096:
        raise NativeFeedEvidenceError(f"{label} inventory is invalid")
    paths: list[str] = []
    for entry in entries:
        if type(entry) is not dict or type(entry.get("type")) is not str:
            raise NativeFeedEvidenceError(f"{label} entry is invalid")
        entry_type = entry["type"]
        common = {"gid", "mode", "path", "type", "uid"}
        _exact(
            entry,
            common if entry_type == "directory" else common | {"nlink", "sha256", "size"},
            f"{label} entry",
        )
        path = entry["path"]
        if (
            type(path) is not str
            or not path
            or path.startswith("/")
            or Path(path).as_posix() != path
            or ".." in Path(path).parts
            or type(entry["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", entry["mode"]) is None
            or type(entry["uid"]) is not int
            or type(entry["gid"]) is not int
            or min(entry["uid"], entry["gid"]) < 0
        ):
            raise NativeFeedEvidenceError(f"{label} entry metadata is invalid")
        if entry_type == "regular":
            if (
                entry["nlink"] != 1
                or type(entry["size"]) is not int
                or not 0 <= entry["size"] <= EXPECTED_LIMITS["maximum_feed_bytes"]
            ):
                raise NativeFeedEvidenceError(f"{label} regular entry is invalid")
            _sha256(entry["sha256"], f"{label} entry digest")
        elif entry_type != "directory":
            raise NativeFeedEvidenceError(f"{label} contains an unsupported object")
        paths.append(path)
    if paths != sorted(set(paths)):
        raise NativeFeedEvidenceError(f"{label} paths are not an exact sorted inventory")
    return value


def inspect_deb_payload(package: Path) -> dict[str, Any]:
    """Stream one DEB payload and attest the exact privileged CLI entry."""

    if not package.is_absolute() or Path(os.path.normpath(package)) != package:
        raise NativeFeedEvidenceError("DEB package path must be canonical and absolute")
    package_wire = _regular_bytes(package, EXPECTED_LIMITS["maximum_package_bytes"], "DEB package")
    target = "opt/syswarden/bin/syswarden-cli"
    found: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="syswarden-deb-payload-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        snapshot = root / package.name
        descriptor = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(package_wire):
                count = os.write(descriptor, package_wire[written:])
                if count <= 0:
                    raise NativeFeedEvidenceError("short write while staging DEB snapshot")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        stderr_file = tempfile.TemporaryFile()
        try:
            process = subprocess.Popen(
                ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(snapshot)],
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
            if process.stdout is None:
                raise NativeFeedEvidenceError("dpkg-deb did not provide its payload stream")
            try:
                with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
                    members = 0
                    for member in archive:
                        members += 1
                        if members > 100000:
                            raise NativeFeedEvidenceError("DEB payload member count exceeds its bound")
                        normalized = member.name.removeprefix("./")
                        if normalized != target:
                            continue
                        if (
                            member.name not in {target, "./" + target}
                            or not member.isreg()
                            or member.linkname
                            or member.uid != 0
                            or member.gid != 0
                            or member.mode & 0o7777 != 0o750
                            or not 1 <= member.size <= 64 * 1024 * 1024
                        ):
                            raise NativeFeedEvidenceError("DEB CLI payload metadata is unsafe")
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise NativeFeedEvidenceError("DEB CLI payload is unreadable")
                        payload = stream.read(member.size + 1)
                        if len(payload) != member.size:
                            raise NativeFeedEvidenceError("DEB CLI payload size is inconsistent")
                        found.append(
                            {
                                "gid": member.gid,
                                "mode": "0750",
                                "path": target,
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "size": member.size,
                                "type": "regular",
                                "uid": member.uid,
                            }
                        )
            except (tarfile.TarError, OSError) as exc:
                process.kill()
                process.wait()
                raise NativeFeedEvidenceError(f"cannot parse DEB payload: {exc}") from exc
            return_code = process.wait(timeout=60)
            stderr_file.seek(0)
            stderr = stderr_file.read(EXPECTED_LIMITS["maximum_input_bytes"] + 1)
        finally:
            stderr_file.close()
    if return_code != 0 or stderr:
        raise NativeFeedEvidenceError("dpkg-deb payload streaming did not finish cleanly")
    if len(found) != 1:
        raise NativeFeedEvidenceError("DEB must contain exactly one SysWarden CLI payload")
    return {
        "package": {
            "name": package.name,
            "sha256": hashlib.sha256(package_wire).hexdigest(),
            "size": len(package_wire),
        },
        "payload": found[0],
        "schema": "syswarden-deb-cli-payload/v1",
    }


def _signature_binding(
    files: dict[str, bytes],
    *,
    package: Path,
    signature: Path,
    policy: Path,
    key_id: str,
    signature_date: str,
) -> dict[str, Any]:
    for path, label in ((package, "DEB package"), (signature, "DEB signature"), (policy, "signature policy")):
        if not path.is_absolute() or Path(os.path.normpath(path)) != path:
            raise NativeFeedEvidenceError(f"{label} path must be canonical and absolute")
    raw_evidence = _strict_json_bytes(
        files["package/native-signature-evidence.json"], "native signature evidence"
    )
    inventory_path: Path | None = None
    expected_path: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="native-feed-signature-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            inventory_path = root / "signed-inventory.json"
            inventory_path.write_bytes(files["package/signature-inventory.json"])
            inventory_path.chmod(0o600)
            expected_path = root / "expected.json"
            policy_document = signature_gate.decode_json(
                signature_gate.regular_bytes(policy, signature_gate.MAX_JSON_BYTES, "signature policy"),
                "signature policy",
            )
            bootstrap = policy_document["deb"]["implementation"] == "implemented-not-qualified"
            arguments = [
                "deb",
                "--policy",
                str(policy),
                "--inventory",
                str(inventory_path),
                "--package",
                str(package),
                "--signature",
                str(signature),
                "--release",
                TARGET_RELEASE,
                "--key-id",
                key_id,
                "--as-of",
                signature_date,
                "--purpose",
                "qualification",
                "--evidence-output",
                str(expected_path),
            ]
            if bootstrap:
                arguments.append("--bootstrap-qualification")
            if signature_gate.main(arguments) != 0:
                raise NativeFeedEvidenceError("shared native DEB signature gate rejected the package")
            expected_wire = expected_path.read_bytes()
    except signature_gate.SignatureGateError as exc:
        raise NativeFeedEvidenceError(f"native DEB signature binding failed: {exc}") from exc
    if expected_wire != _canonical_json(raw_evidence):
        raise NativeFeedEvidenceError("raw native signature evidence is not reproducible")
    policy_sha = _one_line(files["package/signature-policy.sha256"], "signature policy digest")
    if policy_sha != hashlib.sha256(_regular_bytes(policy, 1048576, "signature policy")).hexdigest():
        raise NativeFeedEvidenceError("signature policy digest does not match the checked-out policy")
    status_text = files["package/gpgv.status"].decode("utf-8")
    gpgv_logger = files["package/gpgv.stderr"]
    if gpgv_logger and b"Good signature" not in gpgv_logger:
        raise NativeFeedEvidenceError("gpgv logger channel is not an accepted success record")
    try:
        statuses = signature_gate.parse_gpgv_status_output(status_text)
        policy_doc = signature_gate.decode_json(
            signature_gate.regular_bytes(policy, signature_gate.MAX_JSON_BYTES, "signature policy"),
            "signature policy",
        )
        selected = signature_gate.select_verification_key(
            policy_doc,
            "deb",
            key_id,
            dt.date.fromisoformat(signature_date),
            "qualification",
            policy_doc["deb"]["implementation"] == "implemented-not-qualified",
        )
        raw_signing_fingerprint, raw_signed_at = signature_gate.validate_deb_gpgv_status(
            statuses, selected, dt.date.fromisoformat(signature_date)
        )
    except (UnicodeDecodeError, ValueError, signature_gate.SignatureGateError) as exc:
        raise NativeFeedEvidenceError(f"raw gpgv status is invalid: {exc}") from exc
    if (
        raw_evidence.get("key", {}).get("fingerprint") != selected["fingerprint"]
        or raw_signing_fingerprint != raw_evidence["key"]["fingerprint"]
        or raw_signed_at != raw_evidence.get("signature", {}).get("created_at")
    ):
        raise NativeFeedEvidenceError("raw gpgv status is not bound to signature evidence")
    return raw_evidence


def _parse_os_release(wire: bytes) -> dict[str, str]:
    try:
        lines = wire.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise NativeFeedEvidenceError("os-release is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match is None or match.group(1) in values:
            raise NativeFeedEvidenceError("os-release is malformed or ambiguous")
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[match.group(1)] = value
    if values.get("ID") != "ubuntu" or values.get("VERSION_ID") != "26.04":
        raise NativeFeedEvidenceError("native host is not Ubuntu 26.04")
    return values


def _ssh_fingerprint(public_key: bytes) -> str:
    try:
        line = public_key.decode("ascii").strip()
        fields = line.split()
        if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
            raise ValueError
        blob = base64.b64decode(fields[1], validate=True)
    except (UnicodeDecodeError, ValueError) as exc:
        raise NativeFeedEvidenceError("NODE02 public host key is malformed") from exc
    encoded = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + encoded


def _normalize_nft(value: object) -> object:
    if type(value) is dict:
        return {
            key: _normalize_nft(item)
            for key, item in sorted(value.items())
            if key not in {"bytes", "expires", "handle", "packets"}
        }
    if type(value) is list:
        items = [_normalize_nft(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value


def _nft_document(wire: bytes, expected_name: str, expected_type: str) -> dict[str, Any]:
    document = _strict_json_bytes(wire, f"nftables set {expected_name}")
    nftables = document.get("nftables")
    if type(nftables) is not list:
        raise NativeFeedEvidenceError("nftables JSON does not contain an exact statement array")
    sets = []
    for statement in nftables:
        if type(statement) is dict and type(statement.get("set")) is dict:
            sets.append(statement["set"])
    if len(sets) != 1:
        raise NativeFeedEvidenceError(f"nftables evidence for {expected_name} is ambiguous")
    candidate = sets[0]
    if (
        candidate.get("family") != "inet"
        or candidate.get("table") != "syswarden"
        or candidate.get("name") != expected_name
        or candidate.get("type") != expected_type
    ):
        raise NativeFeedEvidenceError(f"nftables set identity is invalid: {expected_name}")
    return candidate


def _feed_manifest(wire: bytes, ipv4: bytes, ipv6: bytes) -> str:
    expected = [
        f"{hashlib.sha256(ipv4).hexdigest()}  syswarden_threatintel.ipv4\n"
    ]
    if ipv6:
        expected.append(
            f"{hashlib.sha256(ipv6).hexdigest()}  syswarden_threatintel.ipv6\n"
        )
    expected_wire = "".join(expected).encode("ascii")
    if wire != expected_wire:
        raise NativeFeedEvidenceError("feed manifest does not match transported feed bytes")
    return hashlib.sha256(wire).hexdigest()


def _expected_fixture_ipv4() -> bytes:
    addresses = {
        ipaddress.ip_address(line)
        for line in tls_fixture.DATA_SHIELD.decode("ascii").splitlines()
        if line
    }
    if len(addresses) != 16 or any(address.version != 4 for address in addresses):
        raise NativeFeedEvidenceError("checked-out Data-Shield fixture inventory is invalid")
    return "".join(
        f"{ipaddress.ip_network(f'{address}/32', strict=True)}\n"
        for address in sorted(addresses)
    ).encode("ascii")


def _nft_networks(candidate: dict[str, Any], version: int) -> set[ipaddress._BaseNetwork]:
    """Parse only the attested set element field from nft JSON.

    Searching the whole document would let an address in unrelated metadata satisfy
    the enforcement assertion while the actual set remained empty.
    """

    elements = candidate.get("elem", [])
    if type(elements) is not list:
        raise NativeFeedEvidenceError("nftables set element inventory is not an array")
    networks: set[ipaddress._BaseNetwork] = set()
    for item in elements:
        value: str
        if type(item) is str:
            value = item
        elif type(item) is dict and set(item) == {"prefix"}:
            prefix = item["prefix"]
            if (
                type(prefix) is not dict
                or set(prefix) != {"addr", "len"}
                or type(prefix["addr"]) is not str
                or type(prefix["len"]) is not int
            ):
                raise NativeFeedEvidenceError("nftables prefix element is malformed")
            value = f"{prefix['addr']}/{prefix['len']}"
        else:
            raise NativeFeedEvidenceError("nftables set contains an unsupported element form")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise NativeFeedEvidenceError("nftables set contains an invalid network") from exc
        if network.version != version:
            raise NativeFeedEvidenceError("nftables set element family is invalid")
        networks.add(network)
    return networks


def _require_exact_nft_sets(
    nft4: dict[str, Any],
    nft6: dict[str, Any],
    expected_ipv4: set[ipaddress._BaseNetwork],
) -> None:
    """Require the policy sets to contain exactly the deterministic feed."""

    observed_ipv4 = _nft_networks(nft4, 4)
    observed_ipv6 = _nft_networks(nft6, 6)
    if observed_ipv4 != expected_ipv4 or observed_ipv6:
        raise NativeFeedEvidenceError(
            "nftables sets do not enforce the exact deterministic feed"
        )


AUDIT_PATTERN = re.compile(
    r"^  \[OBSERVED\] Threat feed syswarden_threatintel\.ipv4 "
    r"state=(current|stale|unavailable|rejected) "
    r"freshness=(current|stale|unavailable|rejected|expired) "
    r"age_seconds=(-?[0-9]+) evidence=([^ ]+) source_origin=([^ ]+) "
    r"retrieved_at=([^ ]+) sha256=([0-9a-f]{64}) accepted=([0-9]+) "
    r"skipped=([0-9]+) rejected=([0-9]+) license=([^ ]+)\.$"
)


def _scenario_from_raw(
    files: dict[str, bytes], expected: dict[str, Any]
) -> dict[str, Any]:
    prefix = f"scenarios/{expected['id']}/"
    result = _strict_json_bytes(files[prefix + "result.json"], "scenario result")
    _exact(
        result,
        {
            "id",
            "sequence",
            "fixture_mode",
            "status",
            "command_exit_code",
            "started_at",
            "observed_at",
        },
        "scenario result",
    )
    if (
        result["id"] != expected["id"]
        or result["sequence"] != expected["sequence"]
        or result["fixture_mode"] != expected["fixture_mode"]
        or result["status"] != "pass"
        or type(result["command_exit_code"]) is not int
        or not 0 <= result["command_exit_code"] <= 255
        or (expected["command_exit"] == "zero") != (result["command_exit_code"] == 0)
    ):
        raise NativeFeedEvidenceError("scenario result identity or exit is invalid")
    scenario_started = _timestamp(result["started_at"], "scenario start timestamp")
    scenario_observed = _timestamp(result["observed_at"], "scenario observation timestamp")
    if scenario_started > scenario_observed:
        raise NativeFeedEvidenceError("scenario observation predates its start")
    try:
        command = files[prefix + "command.log"].decode("utf-8")
        audit = files[prefix + "audit.log"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NativeFeedEvidenceError("scenario command or audit log is not UTF-8") from exc
    diagnostic = expected["diagnostic"]
    expected_diagnostic_occurrences = 1 if expected["command_exit"] == "zero" else 2
    if command.count(diagnostic) != expected_diagnostic_occurrences:
        raise NativeFeedEvidenceError("scenario diagnostic occurrence is not exact")
    if expected["command_exit"] == "nonzero" and command.count(
        "[WARNING] Threat-intelligence refresh or validation failed. Reapplying configured policy before returning failure..."
    ) != 1:
        raise NativeFeedEvidenceError("refused feed did not prove the normal firewall reapply")
    lines = [line for line in audit.splitlines() if line.startswith("  [OBSERVED] Threat feed syswarden_threatintel.ipv4 ")]
    if len(lines) != 1 or (match := AUDIT_PATTERN.fullmatch(lines[0])) is None:
        raise NativeFeedEvidenceError("audit did not expose one exact IPv4 feed observation")
    provenance = _strict_json_bytes(files[prefix + "provenance.json"], "feed provenance")
    required = {
        "schema_version", "feed_name", "source_url", "source_identity", "retrieved_at",
        "license_identifier", "evidence_quality", "byte_size", "sha256", "accepted_count",
        "skipped_count", "rejected_count", "state", "last_known_good_sha256",
    }
    if not required.issubset(provenance) or set(provenance) - (required | {"authority_sha256"}):
        raise NativeFeedEvidenceError("feed provenance shape is invalid")
    (
        audit_state, freshness, _age, evidence_quality, source_origin, retrieved_at,
        audit_sha, accepted, skipped, rejected, license_identifier,
    ) = match.groups()
    pairs = {
        "schema_version": "syswarden.feed-provenance.v1",
        "feed_name": "syswarden_threatintel.ipv4",
        "state": audit_state,
        "source_url": source_origin,
        "retrieved_at": retrieved_at,
        "sha256": audit_sha,
        "evidence_quality": evidence_quality,
        "accepted_count": int(accepted),
        "skipped_count": int(skipped),
        "rejected_count": int(rejected),
        "license_identifier": license_identifier,
    }
    if any(provenance.get(key) != value for key, value in pairs.items()):
        raise NativeFeedEvidenceError("audit and provenance evidence disagree")
    ipv4 = files[prefix + "ipv4.feed"]
    snapshot = files[prefix + "ipv4.snapshot"]
    ipv6 = files[prefix + "ipv6.feed"]
    ipv4_sha = hashlib.sha256(ipv4).hexdigest()
    expected_ipv4 = _expected_fixture_ipv4()
    if (
        ipv4 != expected_ipv4
        or ipv6
        or ipv4 != snapshot
        or provenance.get("byte_size") != len(ipv4)
        or provenance.get("sha256") != ipv4_sha
        or provenance.get("last_known_good_sha256") != ipv4_sha
        or tls_fixture.SIX_TO_FOUR.rstrip(b"\n") in ipv4
        or tls_fixture.SIX_TO_FOUR.rstrip(b"\n") in ipv6
    ):
        raise NativeFeedEvidenceError("active feed bytes are not the exact safe last-known-good")
    manifest_sha = _feed_manifest(files[prefix + "feeds.sha256"], ipv4, ipv6)
    expected_cins = tls_fixture.fixture_response(
        "cinsscore.com", "/list/ci-badguys.txt", expected["fixture_mode"]
    )[1]
    expected_blocklist = tls_fixture.fixture_response(
        "lists.blocklist.de", "/lists/all.txt", expected["fixture_mode"]
    )[1]
    if files[prefix + "fixture-cins.body"] != expected_cins or files[prefix + "fixture-blocklist.body"] != expected_blocklist:
        raise NativeFeedEvidenceError("scenario fixture bodies do not match the checked-out fixture")
    nft4 = _nft_document(files[prefix + "nft-ipv4.json"], "syswarden_blacklist", "ipv4_addr")
    nft6 = _nft_document(files[prefix + "nft-ipv6.json"], "syswarden_blacklist6", "ipv6_addr")
    expected_networks = {
        ipaddress.ip_network(line, strict=True)
        for line in expected_ipv4.decode("ascii").splitlines()
    }
    _require_exact_nft_sets(nft4, nft6, expected_networks)
    canonical = _canonical_json(_normalize_nft([nft4, nft6]))
    if canonical != files[prefix + "nft-canonical.json"]:
        raise NativeFeedEvidenceError("canonical nftables evidence is not reproducible")
    semantic_sha = hashlib.sha256(canonical).hexdigest()
    return {
        "audit_sha256": hashlib.sha256(files[prefix + "audit.log"]).hexdigest(),
        "command_exit_code": result["command_exit_code"],
        "command_log_sha256": hashlib.sha256(files[prefix + "command.log"]).hexdigest(),
        "diagnostic": diagnostic,
        "diagnostic_occurrences": expected_diagnostic_occurrences,
        "feeds": {
            "ipv4_sha256": ipv4_sha,
            "ipv4_size": len(ipv4),
            "ipv6_sha256": hashlib.sha256(ipv6).hexdigest() if ipv6 else None,
            "ipv6_size": len(ipv6),
            "last_known_good_bytes_preserved": True,
            "manifest_sha256": manifest_sha,
            "six_to_four_absent": True,
            "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
            "snapshot_size": len(snapshot),
        },
        "firewall": {
            "family": "inet",
            "post_update_capture_verified": True,
            "reapply_completed": True,
            "semantic_sha256": semantic_sha,
            "sets": ["syswarden_blacklist", "syswarden_blacklist6"],
            "table": "syswarden",
        },
        "fixture_mode": expected["fixture_mode"],
        "id": expected["id"],
        "observed_at": result["observed_at"],
        "provenance": {
            "accepted_count": provenance["accepted_count"],
            "attestation_status": "verified",
            "freshness": freshness,
            "last_known_good_sha256": provenance["last_known_good_sha256"],
            "rejected_count": provenance["rejected_count"],
            "retrieved_at": provenance["retrieved_at"],
            "schema": provenance["schema_version"],
            "sha256": provenance["sha256"],
            "skipped_count": provenance["skipped_count"],
            "source_origin": provenance["source_url"],
            "state": provenance["state"],
        },
        "sequence": expected["sequence"],
        "status": "pass",
    }


def assemble_from_raw(
    raw_root: Path,
    *,
    candidate_sha: str,
    package_path: Path,
    signature_path: Path,
    signature_policy: Path,
    deb_key_id: str,
    signature_date: str,
    ssh_host_key_sha256: str,
    contract: dict[str, Any],
    contract_sha256: str,
) -> dict[str, Any]:
    """Recompute canonical evidence from one exact sealed raw bundle."""

    _string(candidate_sha, SHA1, "candidate SHA")
    _string(ssh_host_key_sha256, SSH_FINGERPRINT, "NODE02 SSH host key fingerprint")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", deb_key_id):
        raise NativeFeedEvidenceError("DEB key identifier is invalid")
    try:
        dt.date.fromisoformat(signature_date)
    except ValueError as exc:
        raise NativeFeedEvidenceError("DEB signature date is invalid") from exc
    files, raw_manifest_sha256 = load_raw_bundle(raw_root, contract)

    campaign = _strict_json_bytes(files["campaign.json"], "campaign")
    _exact(
        campaign,
        {
            "id",
            "started_at",
            "completed_at",
            "observation_origin",
            "runtime_quarantined",
            "snapshot_restore_required",
            "synthetic",
            "candidate_sha",
        },
        "campaign",
    )
    if (
        campaign["candidate_sha"] != candidate_sha
        or campaign["observation_origin"] != "real-native-node02-lab-only"
        or campaign["synthetic"] is not False
        or campaign["runtime_quarantined"] is not True
        or campaign["snapshot_restore_required"] is not True
    ):
        raise NativeFeedEvidenceError("raw campaign identity is invalid")

    _parse_os_release(files["host/os-release"])
    if _one_line(files["host/dpkg-architecture.txt"], "dpkg architecture") != "amd64":
        raise NativeFeedEvidenceError("native package architecture is not amd64")
    systemd_version = _one_line(files["host/systemd-version.txt"], "systemd version")
    nft_version = _one_line(files["host/nft-version.txt"], "nftables version")
    if re.fullmatch(r"systemd [0-9]+", systemd_version) is None:
        raise NativeFeedEvidenceError("systemd availability evidence is invalid")
    if re.fullmatch(r"nftables v[0-9][0-9A-Za-z.+~-]*", nft_version) is None:
        raise NativeFeedEvidenceError("nftables availability evidence is invalid")
    uname = _one_line(files["host/uname.txt"], "uname evidence")
    if not uname.startswith("Linux ") or " x86_64" not in uname:
        raise NativeFeedEvidenceError("native kernel architecture evidence is invalid")
    public_key = files["host/ssh-host-ed25519.pub"]
    derived_ssh_fingerprint = _ssh_fingerprint(public_key)
    fingerprint_line = _one_line(files["host/ssh-host-ed25519.fingerprint"], "SSH fingerprint")
    match = re.fullmatch(r"256 (SHA256:[A-Za-z0-9+/]{43}) .+ \(ED25519\)", fingerprint_line)
    if (
        match is None
        or match.group(1) != derived_ssh_fingerprint
        or derived_ssh_fingerprint != ssh_host_key_sha256
    ):
        raise NativeFeedEvidenceError("NODE02 SSH host identity does not match the operator pin")

    if any(
        files[relative]
        for relative in (
            "concurrency/process-before.txt",
            "concurrency/process-drained.txt",
            "concurrency/process-quarantined.txt",
        )
    ):
        raise NativeFeedEvidenceError("a concurrent update-feeds writer was observed")
    if files["concurrency/root-crontab.txt"]:
        raise NativeFeedEvidenceError("a legacy root-crontab update-feeds writer was observed")
    if files["concurrency/schedule-conflicts.txt"]:
        raise NativeFeedEvidenceError("an unsupported update-feeds cron schedule was observed")
    if files["concurrency/timers.txt"]:
        raise NativeFeedEvidenceError("an unsupported update-feeds systemd timer was observed")
    service_documents = {
        phase: _strict_json_bytes(
            files[f"concurrency/service-{phase}.txt"], f"writer service {phase} state"
        )
        for phase in ("before", "quiesced", "quarantined")
    }
    service_keys = {
        "active_state", "exe_device", "exe_inode", "exe_path", "fragment_path",
        "main_pid", "process_state", "start_time_ticks", "sub_state", "unit_file_state",
    }
    for phase, service_state in service_documents.items():
        if set(service_state) != {"cron.service", "syswarden-core.service"}:
            raise NativeFeedEvidenceError("writer service inventory is not exact")
        for unit, state in service_state.items():
            _exact(state, service_keys, f"{unit} {phase} state")
            if (
                state["active_state"] != "active"
                or type(state["main_pid"]) is not int
                or state["main_pid"] <= 1
                or type(state["exe_device"]) is not int
                or type(state["exe_inode"]) is not int
                or type(state["start_time_ticks"]) is not int
                or not isinstance(state["exe_path"], str)
                or not isinstance(state["fragment_path"], str)
                or not state["fragment_path"].endswith("/" + unit)
                or not isinstance(state["process_state"], str)
                or re.fullmatch(r"[A-Z]", state["process_state"]) is None
            ):
                raise NativeFeedEvidenceError("writer service identity is not qualification-safe")
    baseline_services = service_documents["before"]
    for unit in ("cron.service", "syswarden-core.service"):
        baseline = dict(baseline_services[unit])
        if baseline.pop("process_state") == "T":
            raise NativeFeedEvidenceError("writer service was already suspended before qualification")
        for phase in ("quiesced", "quarantined"):
            observed = dict(service_documents[phase][unit])
            if observed.pop("process_state") != "T" or observed != baseline:
                raise NativeFeedEvidenceError("writer service did not remain identity-bound in quarantine")

    disposition = _strict_json_bytes(files["product/disposition.json"], "product disposition")
    if disposition != {
        "product_state_restored": False,
        "runtime_resumed": False,
        "schema": "syswarden-native-feed-disposition/v1",
        "snapshot_restore_required": True,
    }:
        raise NativeFeedEvidenceError("native product disposition is not fail-closed")
    barrier = _strict_json_bytes(
        files["concurrency/quarantine-barrier.json"], "quarantine barrier"
    )
    _exact(barrier, {"marker", "schema", "snapshot_restore_required", "units"}, "quarantine barrier")
    if (
        barrier["schema"] != "syswarden-native-feed-quarantine/v1"
        or barrier["snapshot_restore_required"] is not True
        or set(barrier["units"]) != {
            "cron.service",
            "syswarden-core.service",
            "syswarden-firewall.service",
        }
    ):
        raise NativeFeedEvidenceError("native quarantine barrier inventory is not exact")
    marker_path = "/var/lib/syswarden/.native-feed-snapshot-restore-required"
    marker_wire = (
        f"campaign_id={campaign['id']}\n"
        f"candidate_sha={candidate_sha}\n"
        "snapshot_restore_required=true\n"
    ).encode("ascii")
    dropin_wire = f"[Unit]\nConditionPathExists=!{marker_path}\n".encode("ascii")
    expected_objects = {
        "marker": (marker_path, marker_wire, "0600"),
        **{
            unit: (
                f"/etc/systemd/system/{unit}.d/90-syswarden-native-feed-quarantine.conf",
                dropin_wire,
                "0644",
            )
            for unit in barrier["units"]
        },
    }
    for name, (path, wire, mode) in expected_objects.items():
        record = barrier["marker"] if name == "marker" else barrier["units"][name]
        expected_keys = {"gid", "mode", "nlink", "path", "sha256", "size", "uid"}
        if name != "marker":
            expected_keys.add("loaded")
        _exact(record, expected_keys, f"quarantine {name}")
        if (
            record["gid"] != 0
            or record["mode"] != mode
            or record["nlink"] != 1
            or record["path"] != path
            or record["sha256"] != hashlib.sha256(wire).hexdigest()
            or record["size"] != len(wire)
            or record["uid"] != 0
            or (name != "marker" and record["loaded"] is not True)
        ):
            raise NativeFeedEvidenceError("native quarantine barrier object is invalid")
    cron_text = files["concurrency/cron-before.txt"].decode("utf-8")
    canonical_feed_cron = re.compile(
        r"^([1-9]|[1-5][0-9]) \* \* \* \* root /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1$",
        re.MULTILINE,
    )
    if len(canonical_feed_cron.findall(cron_text)) != 1:
        raise NativeFeedEvidenceError("owned feed cron inventory is not exact")

    signature_evidence = _signature_binding(
        files,
        package=package_path,
        signature=signature_path,
        policy=signature_policy,
        key_id=deb_key_id,
        signature_date=signature_date,
    )
    if package_path.name != PACKAGE_NAME or signature_path.name != PACKAGE_NAME + ".asc":
        raise NativeFeedEvidenceError("candidate DEB or detached signature name is not exact")
    package_sha = _digest_line(files["package/deb.sha256"], PACKAGE_NAME, "DEB digest")
    signature_sha = _digest_line(
        files["package/signature.sha256"], PACKAGE_NAME + ".asc", "DEB signature digest"
    )
    package_size_text = _one_line(files["package/deb.size"], "DEB size")
    if re.fullmatch(r"[1-9][0-9]*", package_size_text) is None:
        raise NativeFeedEvidenceError("DEB size is not canonical")
    package_size = int(package_size_text)
    payload = inspect_deb_payload(package_path)
    if files["package/payload-inspection.json"] != _canonical_json(payload):
        raise NativeFeedEvidenceError("DEB payload inspection is not reproducible")
    if files["package/extraction.stdout"] != b"payload inspection passed\n" or files[
        "package/extraction.stderr"
    ]:
        raise NativeFeedEvidenceError("DEB payload streaming did not finish cleanly")
    installed_cli_sha = _digest_line(
        files["package/installed-cli.sha256"], "/opt/syswarden/bin/syswarden-cli", "installed CLI digest"
    )
    payload_cli_sha = _digest_line(
        files["package/extracted-cli.sha256"], "opt/syswarden/bin/syswarden-cli", "DEB CLI payload digest"
    )
    if (
        payload["package"] != {"name": PACKAGE_NAME, "sha256": package_sha, "size": package_size}
        or signature_evidence["package"] != payload["package"]
        or signature_evidence["signature"]["sha256"] != signature_sha
        or payload["payload"]["sha256"] != payload_cli_sha
        or payload_cli_sha != installed_cli_sha
    ):
        raise NativeFeedEvidenceError("signed DEB bytes and installed CLI are not exactly bound")
    expected_record = b"syswarden\t4.10.0\tamd64\tinstall ok installed\n"
    if files["package/dpkg-query.tsv"] != expected_record:
        raise NativeFeedEvidenceError("installed dpkg identity is not exact")
    if files["package/dpkg-deb-fields.txt"] != b"syswarden\t4.10.0\tamd64\n":
        raise NativeFeedEvidenceError("DEB control identity is not exact")
    if files["package/dpkg-owner.txt"] != b"syswarden: /opt/syswarden/bin/syswarden-cli\n":
        raise NativeFeedEvidenceError("installed CLI is not owned by the syswarden package")
    if files["package/dpkg-verify.exit"] != b"0\n" or files[
        "package/dpkg-verify.stdout"
    ] or files["package/dpkg-verify.stderr"]:
        raise NativeFeedEvidenceError("dpkg --verify syswarden did not produce an empty clean result")
    stat_record = _strict_json_bytes(files["package/installed-cli.stat"], "installed CLI stat")
    if stat_record != {
        "gid": 0,
        "mode": "0750",
        "nlink": 1,
        "path": "/opt/syswarden/bin/syswarden-cli",
        "size": payload["payload"]["size"],
        "type": "regular",
        "uid": 0,
    }:
        raise NativeFeedEvidenceError("installed CLI metadata does not match the DEB payload")
    md5_lines = files["package/dpkg-md5sums.txt"].decode("ascii").splitlines()
    target_md5 = [
        line.split()[0]
        for line in md5_lines
        if len(line.split()) == 2 and line.split()[1] == "opt/syswarden/bin/syswarden-cli"
    ]
    if len(target_md5) != 1 or re.fullmatch(r"[0-9a-f]{32}", target_md5[0]) is None:
        raise NativeFeedEvidenceError("dpkg file manifest does not bind the installed CLI")
    if signature_evidence["policy_sha256"] != _one_line(
        files["package/signature-policy.sha256"], "signature policy digest"
    ):
        raise NativeFeedEvidenceError("signature evidence policy digest is inconsistent")
    if signature_evidence["signature"]["name"] != PACKAGE_NAME + ".asc":
        raise NativeFeedEvidenceError("signature evidence detached artifact is not exact")

    environment_names = (
        "ALL_PROXY", "CURL_CA_BUNDLE", "CURL_HOME", "CURL_SSL_BACKEND",
        "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_NO_VERIFY", "GODEBUG",
        "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "OPENSSL_CONF",
        "OPENSSL_CONF_INCLUDE", "OPENSSL_ENGINES", "OPENSSL_MODULES",
        "REQUESTS_CA_BUNDLE", "SSLKEYLOGFILE", "SSL_CERT_DIR", "SSL_CERT_FILE",
        "all_proxy", "http_proxy", "https_proxy", "no_proxy",
    )
    expected_environment = "".join(
        f"{name}=unset\n" for name in sorted(environment_names)
    ).encode("ascii")
    if files["transport/environment.txt"] != expected_environment:
        raise NativeFeedEvidenceError("proxy or trust environment was not fully neutralized")
    resolution = _strict_json_bytes(files["transport/resolution.json"], "fixture DNS resolution")
    hosts = sorted(tls_fixture.DATA_SHIELD_HOSTS | {"cinsscore.com", "lists.blocklist.de"})
    if resolution != {
        "hosts": {host: ["127.0.0.1"] for host in hosts},
        "schema": "syswarden-osint-fixture-resolution/v1",
    }:
        raise NativeFeedEvidenceError("fixture DNS resolution is not exact loopback isolation")
    fixture_hosts = (
        f"# syswarden-native-feed-qualification campaign={campaign['id']}\n"
        + "".join(f"127.0.0.1 {host}\n" for host in hosts)
    ).encode("ascii")
    if files["transport/hosts-fixture.txt"] != fixture_hosts:
        raise NativeFeedEvidenceError("fixture hosts mapping is not exact")
    hosts_before = _hosts_state(files["transport/hosts-before.json"], "hosts before")
    hosts_active = _hosts_state(files["transport/hosts-active.json"], "hosts active")
    hosts_restored = _hosts_state(files["transport/hosts-restored.json"], "hosts restored")
    if hosts_before != hosts_restored:
        raise NativeFeedEvidenceError("/etc/hosts metadata and bytes were not restored exactly")
    if (
        hosts_active["uid"] != hosts_before["uid"]
        or hosts_active["gid"] != hosts_before["gid"]
        or hosts_active["mode"] != hosts_before["mode"]
        or hosts_active["nlink"] != 1
        or hosts_active["size"] != hosts_before["size"] + len(fixture_hosts)
        or hosts_active["sha256"] == hosts_before["sha256"]
        or hosts_active["inode"] == hosts_before["inode"]
    ):
        raise NativeFeedEvidenceError("active fixture hosts state is not an isolated atomic replacement")

    ca_before = _digest_line(
        files["transport/ca-bundle-before.sha256"],
        "ca-certificates.crt",
        "CA bundle before digest",
    )
    ca_active = _digest_line(
        files["transport/ca-bundle-active.sha256"],
        "ca-certificates.crt",
        "CA bundle active digest",
    )
    ca_restored = _digest_line(
        files["transport/ca-bundle-restored.sha256"],
        "ca-certificates.crt",
        "CA bundle restored digest",
    )
    if ca_before != ca_restored or ca_active == ca_before:
        raise NativeFeedEvidenceError("Ubuntu CA bundle lifecycle was not changed and restored exactly")
    if (
        _exit_code(files["transport/ca-before.verify.exit"], "CA verify before exit") == 0
        or _exit_code(files["transport/ca-active.verify.exit"], "CA verify active exit") != 0
        or _exit_code(files["transport/ca-restored.verify.exit"], "CA verify restored exit") == 0
    ):
        raise NativeFeedEvidenceError("fixture default-trust transition is invalid")
    for relative in ("transport/ca-before.verify.log", "transport/ca-restored.verify.log"):
        log = files[relative].decode("utf-8", "strict")
        if not log.strip() or ": OK" in log:
            raise NativeFeedEvidenceError("fixture certificate was trusted outside the active window")
    if not files["transport/ca-active.verify.log"].decode("utf-8", "strict").endswith(": OK\n"):
        raise NativeFeedEvidenceError("fixture certificate was not trusted in the active window")
    install_log = files["transport/ca-install.log"].decode("utf-8", "strict")
    remove_log = files["transport/ca-remove.log"].decode("utf-8", "strict")
    if "1 added, 0 removed" not in install_log or "0 added, 1 removed" not in remove_log:
        raise NativeFeedEvidenceError("Ubuntu CA update did not add and remove exactly one certificate")
    if files["transport/readiness.body"] != b"fixture-ready\n":
        raise NativeFeedEvidenceError("TLS fixture readiness body is invalid")
    for relative in ("transport/fixture-cert.pem", "transport/fixture-ca.pem"):
        wire = files[relative]
        if not wire.startswith(b"-----BEGIN CERTIFICATE-----\n") or not wire.endswith(
            b"-----END CERTIFICATE-----\n"
        ):
            raise NativeFeedEvidenceError("fixture public certificate container is invalid")
    key_match_lines = files["transport/certificate-key-match.sha256"].decode("ascii").splitlines()
    if (
        len(key_match_lines) != 2
        or not key_match_lines[0].startswith("certificate_public_key_sha256=")
        or not key_match_lines[1].startswith("private_key_public_key_sha256=")
        or key_match_lines[0].split("=", 1)[1] != key_match_lines[1].split("=", 1)[1]
        or SHA256.fullmatch(key_match_lines[0].split("=", 1)[1]) is None
    ):
        raise NativeFeedEvidenceError("fixture certificate and private key do not match")
    cert_details = files["transport/fixture-cert-details.txt"].decode("utf-8")
    if any(f"DNS:{host}" not in cert_details for host in hosts):
        raise NativeFeedEvidenceError("fixture certificate SAN inventory is incomplete")
    ca_details = files["transport/fixture-ca-details.txt"].decode("utf-8")
    if not all(
        marker in ca_details for marker in ("subject=", "issuer=", "sha256 Fingerprint=")
    ):
        raise NativeFeedEvidenceError("fixture CA identity evidence is incomplete")
    if files["transport/fixture.stdout.log"]:
        raise NativeFeedEvidenceError("TLS fixture emitted unexpected standard output")
    fixture_stopped = _strict_json_bytes(
        files["transport/fixture-stopped.json"], "fixture stopped state"
    )
    _exact(
        fixture_stopped,
        {"exit_code", "pid", "proc_absent", "schema"},
        "fixture stopped state",
    )
    if (
        fixture_stopped["schema"] != "syswarden-native-feed-fixture-stop/v1"
        or type(fixture_stopped["pid"]) is not int
        or fixture_stopped["pid"] <= 1
        or fixture_stopped["exit_code"] not in {0, 143}
        or type(fixture_stopped["exit_code"]) is not int
        or fixture_stopped["proc_absent"] is not True
    ):
        raise NativeFeedEvidenceError("TLS fixture was not proven stopped")
    default_trust = files["transport/default-trust.verify.log"].decode("utf-8", "strict")
    tls_probe = files["transport/tls13.probe.log"].decode("utf-8", "strict")
    supplied_ca = files["transport/supplied-ca.verify.log"].decode("utf-8", "strict")
    if (
        "Verification: OK" not in default_trust
        or "Verify return code: 0 (ok)" not in default_trust
        or "TLSv1.3" not in default_trust
        or "SSL certificate verify ok" not in tls_probe
        or "TLSv1.3" not in tls_probe
        or ": OK" not in supplied_ca
    ):
        raise NativeFeedEvidenceError("TLS 1.3 system-trust proof is incomplete")
    try:
        fixture_log = files["transport/fixture.stderr.log"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NativeFeedEvidenceError("fixture request log is not UTF-8") from exc
    fixture_pattern = re.compile(
        r"^fixture timestamp=(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z) "
        r"mode=(safe|success|malformed|below-minimum) client=127\.0\.0\.1 "
        r"host=([^ ]+) path=([^ ]+) user_agent=([^ ]+) tls=TLSv1\.3 status=([0-9]{3})$"
    )
    fixture_records: list[tuple[str, str, str, str, str, str]] = []
    for line in fixture_log.splitlines():
        match_log = fixture_pattern.fullmatch(line)
        if match_log is None:
            raise NativeFeedEvidenceError("fixture request log contains an unparseable record")
        fixture_records.append(match_log.groups())
    started_at = _timestamp(campaign["started_at"], "campaign start")
    completed_at = _timestamp(campaign["completed_at"], "campaign completion")
    scenario_windows: dict[str, tuple[dt.datetime, dt.datetime]] = {}
    for expected in EXPECTED_SCENARIOS:
        relative = f"scenarios/{expected['id']}/result.json"
        raw_result = _strict_json_bytes(files[relative], "scenario request window")
        window = (
            _timestamp(raw_result.get("started_at"), "scenario request start"),
            _timestamp(raw_result.get("observed_at"), "scenario request completion"),
        )
        if window[0] > window[1] or window[0] < started_at or window[1] > completed_at:
            raise NativeFeedEvidenceError("scenario request window is outside the campaign")
        scenario_windows[expected["fixture_mode"]] = window
    observed_requests: collections.Counter[tuple[str, str, str, str, str]] = collections.Counter()
    for timestamp, mode, host, path, user_agent, status in fixture_records:
        observed = _timestamp(timestamp, "fixture request timestamp")
        if observed < started_at or observed > completed_at:
            raise NativeFeedEvidenceError("fixture request occurred outside the campaign window")
        if mode != "safe":
            if mode not in scenario_windows or not (
                scenario_windows[mode][0] <= observed <= scenario_windows[mode][1]
            ):
                raise NativeFeedEvidenceError("fixture request occurred outside its scenario window")
        ua_class = "go" if user_agent == "Go-http-client/1.1" else "curl" if user_agent.startswith("curl/") else "other"
        observed_requests[(mode, host, path, ua_class, status)] += 1
    expected_requests: collections.Counter[tuple[str, str, str, str, str]] = collections.Counter(
        {
            ("safe", "raw.githubusercontent.com", "/", "curl", "200"): 1,
            ("safe", "lists.blocklist.de", "/lists/all.txt", "curl", "200"): 1,
        }
    )
    data_shield_routes = (
        ("raw.githubusercontent.com", "/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"),
        ("gitlab.com", "/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"),
        ("cdn.jsdelivr.net", "/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_data-shield_ipv4_blocklist.txt"),
        ("bitbucket.org", "/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt"),
        ("codeberg.org", "/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt"),
    )
    for mode in ("success", "malformed", "below-minimum"):
        expected_requests[(mode, "cinsscore.com", "/list/ci-badguys.txt", "curl", "200")] += 1
        expected_requests[(mode, "lists.blocklist.de", "/lists/all.txt", "curl", "200")] += 1
        for host, path in data_shield_routes:
            expected_requests[(mode, host, path, "go", "200")] += 1
        expected_requests[(mode, "cinsscore.com", "/list/ci-badguys.txt", "go", "200")] += 1
        expected_requests[(mode, "lists.blocklist.de", "/lists/all.txt", "go", "200")] += 1
    if observed_requests != expected_requests:
        raise NativeFeedEvidenceError("fixture request inventory is not the exact product and probe contract")

    expected_inputs = b"".join(
        f"{hashlib.sha256(wire).hexdigest()}  {name}\n".encode("ascii")
        for name, wire in (
            ("scripts/ci/osint_tls_qualification_lab.sh", _regular_bytes(ROOT / "scripts/ci/osint_tls_qualification_lab.sh", 1048576, "lab script")),
            ("scripts/ci/osint_tls_fixture.py", _regular_bytes(ROOT / "scripts/ci/osint_tls_fixture.py", 1048576, "fixture script")),
            ("scripts/ci/native_feed_contract_v4.10.0.json", _regular_bytes(DEFAULT_CONTRACT, 1048576, "native feed contract")),
            ("fixture-cert.pem", files["transport/fixture-cert.pem"]),
            ("fixture-ca.pem", files["transport/fixture-ca.pem"]),
        )
    )
    if files["inputs.sha256"] != expected_inputs:
        raise NativeFeedEvidenceError("qualification input digest inventory is not reproducible")

    scenarios = [_scenario_from_raw(files, expected) for expected in EXPECTED_SCENARIOS]
    return {
        "campaign": {
            "completed_at": campaign["completed_at"],
            "id": campaign["id"],
            "observation_origin": campaign["observation_origin"],
            "runtime_quarantined": campaign["runtime_quarantined"],
            "snapshot_restore_required": campaign["snapshot_restore_required"],
            "started_at": campaign["started_at"],
            "synthetic": campaign["synthetic"],
        },
        "candidate_sha": candidate_sha,
        "contract_sha256": contract_sha256,
        "host": {
            "architecture": "amd64",
            "firewall_backend": "nftables",
            "host_id": "node02",
            "os_id": "ubuntu",
            "os_version": "26.04",
            "package_family": "deb",
            "package_manager": "dpkg",
            "profile_id": "DEB-U2604",
            "service_manager": "systemd",
            "ssh_host_key_sha256": derived_ssh_fingerprint,
        },
        "inputs": {
            "fixture_script_sha256": hashlib.sha256(_regular_bytes(ROOT / "scripts/ci/osint_tls_fixture.py", 1048576, "fixture script")).hexdigest(),
            "installed_cli_sha256": installed_cli_sha,
            "lab_script_sha256": hashlib.sha256(_regular_bytes(ROOT / "scripts/ci/osint_tls_qualification_lab.sh", 1048576, "lab script")).hexdigest(),
            "payload_cli_sha256": payload_cli_sha,
            "raw_manifest_sha256": raw_manifest_sha256,
        },
        "package": {
            "architecture": "amd64",
            "cli_owned_by_package": True,
            "cli_owner_record_sha256": hashlib.sha256(files["package/dpkg-owner.txt"]).hexdigest(),
            "dpkg_verify_stderr_sha256": hashlib.sha256(files["package/dpkg-verify.stderr"]).hexdigest(),
            "dpkg_verify_stdout_sha256": hashlib.sha256(files["package/dpkg-verify.stdout"]).hexdigest(),
            "filename": PACKAGE_NAME,
            "installed_cli_sha256": installed_cli_sha,
            "installed_record_sha256": hashlib.sha256(files["package/dpkg-query.tsv"]).hexdigest(),
            "installed_record_verified": True,
            "package_database_integrity_verified": True,
            "package_file_manifest_sha256": hashlib.sha256(files["package/dpkg-md5sums.txt"]).hexdigest(),
            "payload_cli_sha256": payload_cli_sha,
            "producer_commit": candidate_sha,
            "sha256": package_sha,
            "signature_created_at": signature_evidence["signature"]["created_at"],
            "signature_inventory_sha256": hashlib.sha256(files["package/signature-inventory.json"]).hexdigest(),
            "signature_mechanism": "openpgp-detached",
            "signature_policy_sha256": signature_evidence["policy_sha256"],
            "signature_sha256": signature_sha,
            "signature_verified_before_execution": True,
            "signer_fingerprint": signature_evidence["key"]["fingerprint"],
            "size": package_size,
            "version": PACKAGE_VERSION,
        },
        "release_tag": TARGET_RELEASE,
        "repository": REPOSITORY,
        "scenarios": scenarios,
        "schema": EVIDENCE_SCHEMA,
        "transport": {
            "fixture_certificate_verified": True,
            "minimum_tls_version": "TLS1.3",
            "product_bypass_used": False,
            "proxy_bypass_used": False,
            "system_trust_store_used": True,
        },
    }


def validate(
    document: dict[str, Any],
    *,
    candidate_sha: str,
    package_name: str,
    package_sha256: str,
    package_size: int,
    signer_fingerprint: str,
    ssh_host_key_sha256: str,
    contract: dict[str, Any],
    contract_sha256: str,
    validation_time: dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate one exact NODE02 campaign and return its deterministic verdict."""

    _string(candidate_sha, SHA1, "candidate SHA")
    if package_name != PACKAGE_NAME:
        raise NativeFeedEvidenceError("DEB package name is not exact")
    _sha256(package_sha256, "DEB package digest")
    _integer(
        package_size,
        1,
        contract["limits"]["maximum_package_bytes"],
        "DEB package size",
    )
    _string(signer_fingerprint, OPENPGP_FINGERPRINT, "DEB signer fingerprint")
    _string(ssh_host_key_sha256, SSH_FINGERPRINT, "NODE02 SSH host key fingerprint")

    _exact(
        document,
        {
            "schema",
            "repository",
            "release_tag",
            "candidate_sha",
            "contract_sha256",
            "campaign",
            "host",
            "package",
            "inputs",
            "transport",
            "scenarios",
        },
        "evidence",
    )
    if (
        document["schema"] != EVIDENCE_SCHEMA
        or document["repository"] != REPOSITORY
        or document["release_tag"] != TARGET_RELEASE
        or document["candidate_sha"] != candidate_sha
        or document["contract_sha256"] != contract_sha256
    ):
        raise NativeFeedEvidenceError("native feed evidence identity is invalid")

    campaign = _exact(
        document["campaign"],
        {
            "id",
            "started_at",
            "completed_at",
            "observation_origin",
            "runtime_quarantined",
            "snapshot_restore_required",
            "synthetic",
        },
        "campaign",
    )
    campaign_id = _string(campaign["id"], CAMPAIGN_ID, "campaign id")
    started = _timestamp(campaign["started_at"], "campaign start")
    completed = _timestamp(campaign["completed_at"], "campaign completion")
    if (
        completed <= started
        or (completed - started).total_seconds()
        > contract["limits"]["maximum_campaign_seconds"]
        or campaign["observation_origin"] != contract["guardrails"]["observations"]
        or campaign["runtime_quarantined"] is not True
        or campaign["snapshot_restore_required"] is not True
        or campaign["synthetic"] is not False
    ):
        raise NativeFeedEvidenceError("campaign bounds or origin are invalid")
    now = validation_time or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise NativeFeedEvidenceError("validation time must be timezone-aware")
    now = now.astimezone(dt.timezone.utc)
    if completed > now + dt.timedelta(
        seconds=contract["limits"]["maximum_future_skew_seconds"]
    ):
        raise NativeFeedEvidenceError("campaign completion exceeds the future skew allowance")

    host = _exact(
        document["host"],
        {
            "profile_id",
            "host_id",
            "os_id",
            "os_version",
            "architecture",
            "package_family",
            "package_manager",
            "service_manager",
            "firewall_backend",
            "ssh_host_key_sha256",
        },
        "host",
    )
    profile = contract["profile"]
    for field in (
        "host_id",
        "os_id",
        "os_version",
        "architecture",
        "package_family",
        "package_manager",
        "service_manager",
        "firewall_backend",
    ):
        if host[field] != profile[field]:
            raise NativeFeedEvidenceError(f"host profile mismatch: {field}")
    if (
        host["profile_id"] != profile["id"]
        or host["ssh_host_key_sha256"] != ssh_host_key_sha256
    ):
        raise NativeFeedEvidenceError("NODE02 host identity does not match the operator pin")

    package = _exact(
        document["package"],
        {
            "filename",
            "version",
            "architecture",
            "sha256",
            "size",
            "producer_commit",
            "signature_mechanism",
            "signer_fingerprint",
            "signature_verified_before_execution",
            "installed_record_verified",
            "cli_owned_by_package",
            "package_database_integrity_verified",
            "signature_sha256",
            "signature_created_at",
            "signature_policy_sha256",
            "signature_inventory_sha256",
            "payload_cli_sha256",
            "installed_cli_sha256",
            "dpkg_verify_stdout_sha256",
            "dpkg_verify_stderr_sha256",
            "installed_record_sha256",
            "cli_owner_record_sha256",
            "package_file_manifest_sha256",
        },
        "package",
    )
    expected_package_identity = {
        "filename": package_name,
        "version": PACKAGE_VERSION,
        "architecture": "amd64",
        "sha256": package_sha256,
        "size": package_size,
        "producer_commit": candidate_sha,
        "signature_mechanism": profile["candidate_signature_mechanism"],
        "signer_fingerprint": signer_fingerprint,
        "signature_verified_before_execution": True,
        "installed_record_verified": True,
        "cli_owned_by_package": True,
        "package_database_integrity_verified": True,
    }
    if any(
        package[field] != expected for field, expected in expected_package_identity.items()
    ):
        raise NativeFeedEvidenceError("candidate DEB identity or signature binding is invalid")
    for field in (
        "signature_verified_before_execution",
        "installed_record_verified",
        "cli_owned_by_package",
        "package_database_integrity_verified",
    ):
        if package[field] is not True:
            raise NativeFeedEvidenceError("candidate DEB verification boolean is not exact")
    for field in (
        "installed_record_sha256",
        "cli_owner_record_sha256",
        "package_file_manifest_sha256",
        "signature_sha256",
        "signature_policy_sha256",
        "signature_inventory_sha256",
        "payload_cli_sha256",
        "installed_cli_sha256",
        "dpkg_verify_stdout_sha256",
        "dpkg_verify_stderr_sha256",
    ):
        _sha256(package[field], field.replace("_", " "))
    _timestamp(package["signature_created_at"], "DEB signature timestamp")
    if package["payload_cli_sha256"] != package["installed_cli_sha256"]:
        raise NativeFeedEvidenceError("installed CLI does not match the signed DEB payload")

    inputs = _exact(
        document["inputs"],
        {
            "lab_script_sha256",
            "fixture_script_sha256",
            "installed_cli_sha256",
            "payload_cli_sha256",
            "raw_manifest_sha256",
        },
        "qualification inputs",
    )
    for field in inputs:
        _sha256(inputs[field], field.replace("_", " "))
    if (
        inputs["installed_cli_sha256"] != package["installed_cli_sha256"]
        or inputs["payload_cli_sha256"] != package["payload_cli_sha256"]
    ):
        raise NativeFeedEvidenceError("qualification inputs do not match DEB CLI binding")
    if inputs["lab_script_sha256"] != _script_digest(
        contract["fixture"]["lab_script"], contract["limits"]["maximum_input_bytes"]
    ):
        raise NativeFeedEvidenceError("lab script is not bound to the checked-out candidate")
    if inputs["fixture_script_sha256"] != _script_digest(
        contract["fixture"]["fixture_script"],
        contract["limits"]["maximum_input_bytes"],
    ):
        raise NativeFeedEvidenceError("fixture script is not bound to the checked-out candidate")

    transport = _exact(
        document["transport"],
        {
            "minimum_tls_version",
            "fixture_certificate_verified",
            "system_trust_store_used",
            "proxy_bypass_used",
            "product_bypass_used",
        },
        "transport",
    )
    if transport != {
        "minimum_tls_version": contract["fixture"]["minimum_tls_version"],
        "fixture_certificate_verified": True,
        "system_trust_store_used": True,
        "proxy_bypass_used": False,
        "product_bypass_used": False,
    }:
        raise NativeFeedEvidenceError("TLS system-trust evidence contains a bypass")
    for field in (
        "fixture_certificate_verified",
        "system_trust_store_used",
        "proxy_bypass_used",
        "product_bypass_used",
    ):
        if type(transport[field]) is not bool:
            raise NativeFeedEvidenceError("TLS transport boolean is not exact")

    scenarios = document["scenarios"]
    if type(scenarios) is not list or len(scenarios) != len(EXPECTED_SCENARIOS):
        raise NativeFeedEvidenceError("scenario inventory is not exact")
    validated: list[dict[str, Any]] = []
    prior_observed = started
    for index, (scenario, expected) in enumerate(
        zip(scenarios, contract["fixture"]["scenarios"], strict=True)
    ):
        item = _exact(
            scenario,
            {
                "id",
                "sequence",
                "fixture_mode",
                "status",
                "observed_at",
                "command_exit_code",
                "command_log_sha256",
                "audit_sha256",
                "diagnostic",
                "diagnostic_occurrences",
                "provenance",
                "feeds",
                "firewall",
            },
            f"scenario {index + 1}",
        )
        sequence = _integer(item["sequence"], 1, 3, "scenario sequence")
        expected_occurrences = 1 if expected["command_exit"] == "zero" else 2
        occurrences = _integer(
            item["diagnostic_occurrences"],
            expected_occurrences,
            expected_occurrences,
            "diagnostic occurrence count",
        )
        if (
            item["id"] != expected["id"]
            or sequence != expected["sequence"]
            or item["fixture_mode"] != expected["fixture_mode"]
            or item["status"] != "pass"
            or item["diagnostic"] != expected["diagnostic"]
            or occurrences != expected_occurrences
        ):
            raise NativeFeedEvidenceError("scenario identity or diagnostic is not exact")
        exit_code = _integer(item["command_exit_code"], 0, 255, "command exit code")
        if (expected["command_exit"] == "zero" and exit_code != 0) or (
            expected["command_exit"] == "nonzero" and exit_code == 0
        ):
            raise NativeFeedEvidenceError("scenario command exit does not match the contract")
        observed = _timestamp(item["observed_at"], "scenario observation timestamp")
        if observed < prior_observed or observed > completed:
            raise NativeFeedEvidenceError("scenario timestamps are not ordered inside the campaign")
        prior_observed = observed
        _sha256(item["command_log_sha256"], "command log digest")
        _sha256(item["audit_sha256"], "audit digest")
        provenance = _validate_provenance(item["provenance"], contract, started, observed)
        feeds = _validate_feeds(item["feeds"], provenance)
        firewall = _validate_firewall(item["firewall"], contract)
        if index == 0 and (
            provenance["state"] != "current"
            or provenance["freshness"] != "current"
            or provenance["rejected_count"] != 0
        ):
            raise NativeFeedEvidenceError("successful feed publication is not current")
        validated.append(
            {"record": item, "provenance": provenance, "feeds": feeds, "firewall": firewall}
        )

    baseline = validated[0]
    preserved_feed_fields = {
        "ipv4_sha256",
        "ipv4_size",
        "ipv6_sha256",
        "ipv6_size",
        "manifest_sha256",
        "snapshot_sha256",
        "snapshot_size",
    }
    for refused in validated[1:]:
        if (
            refused["provenance"]["sha256"] != baseline["provenance"]["sha256"]
            or refused["provenance"]["last_known_good_sha256"]
            != baseline["provenance"]["last_known_good_sha256"]
            or any(
                refused["feeds"][field] != baseline["feeds"][field]
                for field in preserved_feed_fields
            )
            or refused["firewall"]["semantic_sha256"]
            != baseline["firewall"]["semantic_sha256"]
        ):
            raise NativeFeedEvidenceError(
                "refused candidate changed the last-known-good feed or firewall policy"
            )

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "schema": VERDICT_SCHEMA,
        "repository": REPOSITORY,
        "target_release": TARGET_RELEASE,
        "candidate_commit": candidate_sha,
        "contract_sha256": contract_sha256,
        "qualification_state": "candidate-not-qualified",
        "publishing": False,
        "status": "pass",
        "profile_id": profile["id"],
        "host_id": profile["host_id"],
        "campaign_id": campaign_id,
        "runtime_quarantined": True,
        "snapshot_restore_required": True,
        "package": {
            "filename": package_name,
            "sha256": package_sha256,
            "size": package_size,
            "signer_fingerprint": signer_fingerprint,
        },
        "scenario_ids": [item["id"] for item in scenarios],
        "last_known_good_sha256": baseline["provenance"]["last_known_good_sha256"],
        "firewall_semantic_sha256": baseline["firewall"]["semantic_sha256"],
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _write_new_private(path: Path, document: object) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise NativeFeedEvidenceError("output must be a new absolute path")
    parent = path.parent
    info = parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise NativeFeedEvidenceError("output parent must be one owner-controlled directory")
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
                raise NativeFeedEvidenceError("short write while creating verdict")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise NativeFeedEvidenceError("output already exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser(
        "inspect-deb", help="stream and attest the exact DEB CLI payload"
    )
    inspect_parser.add_argument("--deb-package", type=Path, required=True)
    inspect_parser.add_argument("--output", type=Path, required=True)
    assemble_parser = subparsers.add_parser(
        "assemble", help="recompute canonical evidence from sealed raw observations"
    )
    assemble_parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    assemble_parser.add_argument("--raw-root", type=Path, required=True)
    assemble_parser.add_argument("--candidate-sha", required=True)
    assemble_parser.add_argument("--deb-package", type=Path, required=True)
    assemble_parser.add_argument("--deb-signature", type=Path, required=True)
    assemble_parser.add_argument("--signature-policy", type=Path, required=True)
    assemble_parser.add_argument("--deb-key-id", required=True)
    assemble_parser.add_argument("--deb-signature-date", required=True)
    assemble_parser.add_argument("--node02-ssh-host-key-sha256", required=True)
    assemble_parser.add_argument("--output-evidence", type=Path, required=True)
    assemble_parser.add_argument("--output-verdict", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect-deb":
            _write_new_private(args.output, inspect_deb_payload(args.deb_package))
            print("payload inspection passed")
            return 0
        for path, label in ((args.contract, "contract"), (args.raw_root, "raw root")):
            if not path.is_absolute() or Path(os.path.normpath(path)) != path:
                raise NativeFeedEvidenceError(f"{label} path must be canonical and absolute")
        contract, digest = load_contract(args.contract)
        document = assemble_from_raw(
            args.raw_root,
            candidate_sha=args.candidate_sha,
            package_path=args.deb_package,
            signature_path=args.deb_signature,
            signature_policy=args.signature_policy,
            deb_key_id=args.deb_key_id,
            signature_date=args.deb_signature_date,
            ssh_host_key_sha256=args.node02_ssh_host_key_sha256,
            contract=contract,
            contract_sha256=digest,
        )
        verdict = validate(
            document,
            candidate_sha=args.candidate_sha,
            package_name=document["package"]["filename"],
            package_sha256=document["package"]["sha256"],
            package_size=document["package"]["size"],
            signer_fingerprint=document["package"]["signer_fingerprint"],
            ssh_host_key_sha256=args.node02_ssh_host_key_sha256,
            contract=contract,
            contract_sha256=digest,
        )
        _write_new_private(args.output_evidence, document)
        _write_new_private(args.output_verdict, verdict)
    except (NativeFeedEvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"Native feed evidence: {exc}", file=sys.stderr)
        return 1
    print(
        "Native feed evidence and deterministic verdict written: "
        f"{args.output_evidence}, {args.output_verdict}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
