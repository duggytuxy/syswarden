#!/usr/bin/env python3
"""Offline, fail-closed native package signature verification foundation."""

from __future__ import annotations

import argparse
import datetime as dt
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


class SignatureGateError(RuntimeError):
    pass


SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPENPGP_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
KEY_ID = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
OCI_DIGEST = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$"
)
SAFE_RELATIVE_KEY_PATH = re.compile(
    r"^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$"
)
PACKAGE_NAME = re.compile(r"^syswarden[-_][A-Za-z0-9._+-]+\.(rpm|apk|deb)$")
PACKAGE_SUFFIX = {"rpm": ".rpm", "apk": ".apk", "deb": ".deb"}
MAX_JSON_BYTES = 128 * 1024
MAX_KEY_BYTES = 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_DEB_SIGNATURE_BYTES = 256 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SignatureGateError(message)


def regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{label} must be a singly-linked regular file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
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
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            fail(f"{label} changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
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
        try:
            current = path.lstat()
        except OSError as exc:
            fail(f"cannot re-inspect {label}: {exc}")
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


def decode_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_nonfinite(token: str) -> None:
        fail(f"{label} contains non-finite JSON number {token}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is invalid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def load_json(path: Path, label: str) -> dict[str, Any]:
    return decode_json(regular_bytes(path, MAX_JSON_BYTES, label), label)


def write_json_exclusive(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_JSON_BYTES:
        fail("verification evidence exceeds its size bound")
    parent = path.parent
    try:
        lexical_parent = parent.absolute()
        resolved_parent = parent.resolve(strict=True)
        metadata = resolved_parent.lstat()
    except OSError as exc:
        fail(f"cannot inspect evidence output directory: {exc}")
    mode = stat.S_IMODE(metadata.st_mode)
    owner_controlled = metadata.st_uid == os.geteuid() and mode & 0o022 == 0
    root_sticky = metadata.st_uid == 0 and mode & stat.S_ISVTX != 0
    if (
        lexical_parent != resolved_parent
        or not stat.S_ISDIR(metadata.st_mode)
        or parent.is_symlink()
        or not (owner_controlled or root_sticky)
    ):
        fail("evidence output directory must be a protected real directory")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        fail(f"cannot create verification evidence: {exc}")
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                fail("short write while creating verification evidence")
            written += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
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
            fail("verification evidence changed while being created")
    finally:
        os.close(descriptor)


def parse_day(value: object, label: str) -> dt.date:
    if not isinstance(value, str):
        fail(f"{label} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise SignatureGateError(f"{label} must be an ISO date") from exc


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys are not exact")
    return value


def validate_policy(policy: dict[str, Any], as_of: dt.date) -> None:
    exact_keys(
        policy,
        {"schema_version", "profile", "status", "publishing", "rpm", "apk", "deb"},
        "policy",
    )
    if policy["schema_version"] != 1 or policy["profile"] != "syswarden-native-package-signatures/v4.10.0":
        fail("policy identity is unsupported")
    if policy["status"] not in {"foundation-not-qualified", "qualified"}:
        fail("policy status is unsupported")
    if type(policy["publishing"]) is not bool:
        fail("policy publishing must be boolean")
    rpm = exact_keys(policy["rpm"], {"mechanism", "trusted_keys"}, "rpm policy")
    apk = exact_keys(
        policy["apk"], {"mechanism", "signer_image", "trusted_keys"}, "apk policy"
    )
    deb = exact_keys(
        policy["deb"],
        {
            "channel",
            "decision",
            "mechanism",
            "signature_suffix",
            "trusted_keys",
            "implementation",
        },
        "deb policy",
    )
    if rpm["mechanism"] != "rpm-openpgp" or apk["mechanism"] != "apk-rsa256":
        fail("native package mechanisms are unsupported")
    if (
        apk["signer_image"] is not None
        and (
            not isinstance(apk["signer_image"], str)
            or OCI_DIGEST.fullmatch(apk["signer_image"]) is None
        )
    ):
        fail("APK signer image policy is not a canonical OCI digest reference")
    if policy["status"] == "qualified" and apk["signer_image"] is None:
        fail("qualified policy requires a reviewed APK signer image digest")
    if policy["publishing"] is True and policy["status"] != "qualified":
        fail("publishing approval requires a qualified policy")
    if (
        deb["channel"] != "github-release-assets"
        or deb["decision"] != "detached-package-signature"
        or deb["mechanism"] != "openpgp-detached"
        or deb["signature_suffix"] != ".asc"
        or deb["implementation"] not in {"implemented-not-qualified", "qualified"}
    ):
        fail("DEB signature decision is not exact")
    if policy["publishing"] is True and deb["implementation"] != "qualified":
        fail("publishing approval requires a qualified DEB detached-signature lane")
    global_id_families: dict[str, str] = {}
    global_public_key_digest_families: dict[str, str] = {}
    openpgp_fingerprint_families: dict[str, str] = {}
    for family in ("rpm", "apk", "deb"):
        keys = policy[family]["trusted_keys"]
        if not isinstance(keys, list):
            fail(f"{family} trusted_keys must be an array")
        identities: set[str] = set()
        fingerprints_seen: set[str] = set()
        public_key_digests_seen: set[str] = set()
        for index, raw in enumerate(keys):
            key = exact_keys(
                raw,
                {"id", "public_key", "public_key_sha256", "fingerprint", "valid_from", "valid_until", "revoked", "supersedes"},
                f"{family} key {index}",
            )
            if not isinstance(key["id"], str) or KEY_ID.fullmatch(key["id"]) is None:
                fail(f"{family} key {index} id is invalid")
            if key["id"] in identities:
                fail(f"{family} key identity is duplicated")
            identities.add(key["id"])
            previous_id_family = global_id_families.get(key["id"])
            if previous_id_family is not None:
                fail(
                    "trusted key IDs must be globally unique across RPM, APK and DEB"
                )
            global_id_families[key["id"]] = family
            if (
                not isinstance(key["public_key"], str)
                or SAFE_RELATIVE_KEY_PATH.fullmatch(key["public_key"]) is None
                or Path(key["public_key"]).is_absolute()
                or ".." in Path(key["public_key"]).parts
                or not key["public_key"].startswith("native-package-keys/")
            ):
                fail(f"{family} key {index} path is unsafe")
            if family == "rpm" and Path(key["public_key"]).suffix != ".asc":
                fail("RPM public key filename must use the .asc suffix")
            if not isinstance(key["public_key_sha256"], str) or SHA256.fullmatch(key["public_key_sha256"]) is None:
                fail(f"{family} key {index} public key digest is invalid")
            fingerprint = key["fingerprint"]
            pattern = OPENPGP_FINGERPRINT if family in {"rpm", "deb"} else SHA256
            if not isinstance(fingerprint, str) or pattern.fullmatch(fingerprint) is None:
                fail(f"{family} key {index} fingerprint is invalid")
            if fingerprint in fingerprints_seen:
                fail(f"{family} trusted key fingerprint is duplicated")
            if key["public_key_sha256"] in public_key_digests_seen:
                fail(f"{family} trusted public-key bytes are duplicated")
            fingerprints_seen.add(fingerprint)
            public_key_digests_seen.add(key["public_key_sha256"])
            previous_digest_family = global_public_key_digest_families.get(
                key["public_key_sha256"]
            )
            if previous_digest_family is not None:
                fail(
                    "trusted public-key bytes must be globally unique across RPM, APK and DEB"
                )
            global_public_key_digest_families[key["public_key_sha256"]] = family
            if family in {"rpm", "deb"}:
                previous_fingerprint_family = openpgp_fingerprint_families.get(
                    fingerprint
                )
                if previous_fingerprint_family is not None:
                    fail("RPM and DEB OpenPGP fingerprints must be distinct")
                openpgp_fingerprint_families[fingerprint] = family
            valid_from = parse_day(key["valid_from"], f"{family} key valid_from")
            valid_until = parse_day(key["valid_until"], f"{family} key valid_until")
            if valid_from > valid_until:
                fail(f"{family} key {key['id']} validity interval is inverted")
            if type(key["revoked"]) is not bool:
                fail(f"{family} key {key['id']} revocation state is invalid")
            if not isinstance(key["supersedes"], list) or any(
                not isinstance(item, str) or KEY_ID.fullmatch(item) is None for item in key["supersedes"]
            ):
                fail(f"{family} key {key['id']} rotation lineage is invalid")
            if len(set(key["supersedes"])) != len(key["supersedes"]):
                fail(f"{family} key {key['id']} rotation lineage contains duplicates")
            if key["id"] in key["supersedes"]:
                fail(f"{family} key cannot supersede itself")

        lineage = {
            key["id"]: tuple(key["supersedes"])
            for key in keys
        }
        for identifier, predecessors in lineage.items():
            missing = set(predecessors) - set(lineage)
            if missing:
                fail(f"{family} key {identifier} references unknown rotation predecessors")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(identifier: str) -> None:
            if identifier in visiting:
                fail(f"{family} key rotation lineage contains a cycle")
            if identifier in visited:
                return
            visiting.add(identifier)
            for predecessor in lineage[identifier]:
                visit(predecessor)
            visiting.remove(identifier)
            visited.add(identifier)

        for identifier in lineage:
            visit(identifier)

    if policy["status"] == "qualified" and any(
        not policy[family]["trusted_keys"] for family in ("rpm", "apk", "deb")
    ):
        fail("qualified policy requires reviewed RPM, APK and DEB trusted keys")
    if policy["status"] == "qualified" and deb["implementation"] != "qualified":
        fail("qualified policy requires a qualified DEB detached-signature lane")
    if deb["implementation"] == "qualified" and not deb["trusted_keys"]:
        fail("qualified DEB detached-signature lane requires a reviewed trusted key")


def select_key(
    policy: dict[str, Any], family: str, key_id: str, as_of: dt.date
) -> dict[str, Any]:
    matches = [key for key in policy[family]["trusted_keys"] if key["id"] == key_id]
    if len(matches) != 1:
        fail(f"no unique trusted {family} key matches {key_id}")
    key = matches[0]
    if key["revoked"]:
        fail(f"selected {family} key {key_id} is revoked")
    if not (
        parse_day(key["valid_from"], f"{family} key valid_from")
        <= as_of
        <= parse_day(key["valid_until"], f"{family} key valid_until")
    ):
        fail(f"selected {family} key {key_id} is not valid on the qualification date")
    return key


def select_verification_key(
    policy: dict[str, Any],
    family: str,
    key_id: str,
    as_of: dt.date,
    purpose: str,
    bootstrap_qualification: bool,
) -> dict[str, Any]:
    if not bootstrap_qualification:
        if policy["status"] != "qualified":
            fail("native signature policy is not qualified")
        if policy["deb"]["implementation"] != "qualified":
            fail("DEB detached-signature verification is not qualified")
        if purpose == "publishing" and policy["publishing"] is not True:
            fail("native signature policy is not approved for publishing")
        return select_key(policy, family, key_id, as_of)

    if purpose != "qualification":
        fail("bootstrap qualification is valid only for qualification purpose")
    if (
        policy["status"] != "foundation-not-qualified"
        or policy["publishing"] is not False
        or policy["deb"]["implementation"] != "implemented-not-qualified"
    ):
        fail(
            "bootstrap qualification requires the exact non-publishing "
            "foundation policy"
        )

    selected: dict[str, Any] | None = None
    for candidate_family in ("rpm", "apk", "deb"):
        keys = policy[candidate_family]["trusted_keys"]
        if len(keys) != 1:
            fail(
                "bootstrap qualification requires exactly one trusted key "
                f"for {candidate_family}"
            )
        candidate = select_key(
            policy, candidate_family, keys[0]["id"], as_of
        )
        if candidate_family == family:
            if candidate["id"] != key_id:
                fail(
                    "bootstrap qualification selected key does not match the sole "
                    f"{family} trusted key"
                )
            selected = candidate
    if selected is None:
        fail("bootstrap qualification package family is unsupported")
    return selected


def bind_artifact(
    inventory: dict[str, Any],
    package: Path,
    release: str,
    family: str,
    package_role: str = "standard",
) -> bytes:
    exact_keys(inventory, {"schema_version", "release", "artifacts"}, "release inventory")
    if inventory["schema_version"] != 1 or inventory["release"] != release:
        fail("release inventory identity does not match")
    if not isinstance(release, str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release) is None:
        fail("release is malformed")
    version = release.removeprefix("v")
    if package_role not in {"standard", "rhel-package-owned"}:
        fail("package role is unsupported")
    if package_role == "rhel-package-owned" and family != "rpm":
        fail("RHEL package-owned role is valid only for RPM verification")
    expected_name = {
        "rpm": f"syswarden-{version}-1.x86_64.rpm",
        "apk": f"syswarden_{version}_x86_64.apk",
        "deb": f"syswarden_{version}_amd64.deb",
    }[family]
    if package_role == "rhel-package-owned":
        expected_name = f"syswarden-{version}-1.rhelpo.x86_64.rpm"
    if (
        PACKAGE_NAME.fullmatch(package.name) is None
        or not package.name.endswith(PACKAGE_SUFFIX[family])
        or package.name != expected_name
    ):
        fail("package filename is unsupported")
    data = regular_bytes(package, MAX_PACKAGE_BYTES, "package")
    digest = hashlib.sha256(data).hexdigest()
    artifacts = inventory["artifacts"]
    if not isinstance(artifacts, list):
        fail("release artifacts must be an array")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == package.name]
    if len(matches) != 1:
        fail("package is not uniquely bound to the release inventory")
    artifact = exact_keys(matches[0], {"name", "size", "sha256"}, "release artifact")
    if (
        type(artifact["size"]) is not int
        or artifact["size"] != len(data)
        or not isinstance(artifact["sha256"], str)
        or SHA256.fullmatch(artifact["sha256"]) is None
        or artifact["sha256"] != digest
    ):
        fail("package bytes do not match the release inventory")
    return data


def stage_bound_package(directory: Path, name: str, data: bytes) -> Path:
    destination = directory / name
    try:
        with destination.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        fail(f"cannot stage the bound package: {exc}")
    return destination


def key_path(policy_path: Path, key: dict[str, Any]) -> tuple[Path, bytes]:
    relative = Path(key["public_key"])
    try:
        lexical_policy = policy_path.absolute()
        resolved_policy = policy_path.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve signature policy path: {exc}")
    if lexical_policy != resolved_policy:
        fail("signature policy path must be canonical and contain no symbolic link")
    base = resolved_policy.parent
    current = base
    expected_owner = os.geteuid()
    try:
        policy_metadata = resolved_policy.lstat()
        base_metadata = base.lstat()
    except OSError as exc:
        fail(f"cannot inspect signature policy directory: {exc}")
    if (
        not stat.S_ISREG(policy_metadata.st_mode)
        or policy_metadata.st_nlink != 1
        or policy_metadata.st_uid != expected_owner
        or stat.S_IMODE(policy_metadata.st_mode) & 0o022
    ):
        fail("signature policy file is not owner-controlled")
    if (
        not stat.S_ISDIR(base_metadata.st_mode)
        or stat.S_ISLNK(base_metadata.st_mode)
        or base_metadata.st_uid != expected_owner
        or stat.S_IMODE(base_metadata.st_mode) & 0o022
    ):
        fail("signature policy directory is not owner-controlled")
    for component in relative.parts[:-1]:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            fail(f"cannot inspect public key distribution directory: {exc}")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            fail(
                "public key distribution path must contain only real directories controlled by the owner"
            )
    path = base / relative
    try:
        key_metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect public key: {exc}")
    if (
        key_metadata.st_uid != expected_owner
        or stat.S_IMODE(key_metadata.st_mode) & 0o022
    ):
        fail("public key file is not owner-controlled")
    data = regular_bytes(path, MAX_KEY_BYTES, "public key")
    if hashlib.sha256(data).hexdigest() != key["public_key_sha256"]:
        fail("public key digest does not match policy")
    return path, data


def run(
    command: list[str], label: str, inherited_environment: tuple[str, ...] = ()
) -> str:
    environment = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    for name in inherited_environment:
        value = os.environ.get(name)
        if value is None:
            fail(f"required verifier environment {name} is unavailable")
        environment[name] = value
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"cannot execute {label}: {exc}")
    if result.returncode != 0:
        fail(f"{label} rejected the artifact")
    return result.stdout + result.stderr


def validate_openpgp_signing_identity(
    records: list[list[str]], signature_key_id: str, as_of: dt.date
) -> None:
    matches: list[tuple[list[str], str]] = []
    for index, record in enumerate(records):
        if not record or record[0] not in {"pub", "sub"}:
            continue
        fingerprint = None
        for candidate in records[index + 1 :]:
            if candidate and candidate[0] in {"pub", "sub"}:
                break
            if candidate and candidate[0] == "fpr" and len(candidate) > 9:
                fingerprint = candidate[9]
                break
        if (
            fingerprint is not None
            and OPENPGP_FINGERPRINT.fullmatch(fingerprint) is not None
            and fingerprint.endswith(signature_key_id)
        ):
            matches.append((record, fingerprint))
    if len(matches) != 1:
        fail("RPM signature key ID does not identify one committed OpenPGP key")
    record, _ = matches[0]
    if len(record) <= 11:
        fail("RPM OpenPGP signing-key record is incomplete")
    try:
        bits = int(record[2])
        created = dt.datetime.fromtimestamp(
            int(record[5]), tz=dt.timezone.utc
        ).date()
        expires = (
            dt.datetime.fromtimestamp(int(record[6]), tz=dt.timezone.utc).date()
            if record[6]
            else None
        )
    except (ValueError, OverflowError) as exc:
        raise SignatureGateError("RPM OpenPGP signing-key dates or size are malformed") from exc
    if (
        record[3] not in {"1", "3"}
        or not 3072 <= bits <= 8192
        or "s" not in record[11].lower()
    ):
        fail("RPM signature must use a 3072 to 8192-bit signing-capable RSA key")
    if record[1] in {"d", "e", "i", "r"}:
        fail("RPM OpenPGP signing key is disabled, invalid, expired or revoked")
    if created > as_of or (expires is not None and expires < as_of):
        fail("RPM OpenPGP signing key is not valid on the qualification date")


def validate_rpm_public_key_container(path: Path, data: bytes) -> None:
    if path.suffix != ".asc":
        fail("RPM public key filename must use the .asc suffix")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureGateError("RPM public key must be ASCII armored") from exc
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    private_key_label = "PRIVATE KEY BLOCK"
    secret_key_label = "SECRET KEY BLOCK"
    private_markers = tuple(
        f"-----{boundary} PGP {label}-----"
        for boundary in ("BEGIN", "END")
        for label in (private_key_label, secret_key_label)
    )
    if any(marker in text for marker in private_markers):
        fail("RPM public key must not contain private-key armor")
    if (
        "\r" in text
        or not text.startswith(begin + "\n")
        or not text.endswith(end + "\n")
        or text.count(begin) != 1
        or text.count(end) != 1
        or any(len(line) > 1024 for line in text.splitlines())
    ):
        fail("RPM public key armor is not singular and canonical")


def verify_rpm(policy: dict[str, Any], policy_path: Path, package: Path, key_id: str, rpmkeys: str, gpg: str, as_of: dt.date) -> None:
    key = select_key(policy, "rpm", key_id, as_of)
    public_key_path, public_key_data = key_path(policy_path, key)
    validate_rpm_public_key_container(public_key_path, public_key_data)
    with tempfile.TemporaryDirectory(prefix="syswarden-rpm-verify-") as raw:
        root = Path(raw)
        public_key = stage_bound_package(root, "rpm-public.asc", public_key_data)
        gpg_home = root / "gpg"
        gpg_home.mkdir(mode=0o700)
        listing = run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--homedir",
                str(gpg_home),
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                str(public_key),
            ],
            "OpenPGP key inspection",
        )
        public_records = [line.split(":") for line in listing.splitlines() if line.startswith("pub:")]
        if len(public_records) != 1 or len(public_records[0]) <= 6:
            fail("RPM OpenPGP key has no unique primary identity")
        try:
            primary_bits = int(public_records[0][2])
        except ValueError as exc:
            raise SignatureGateError("RPM OpenPGP key size is malformed") from exc
        if public_records[0][3] not in {"1", "3"} or not 3072 <= primary_bits <= 8192:
            fail("RPM OpenPGP primary key must be a 3072 to 8192-bit signing-capable RSA key")
        if public_records[0][1] in {"d", "e", "i", "r"}:
            fail("RPM OpenPGP primary key is disabled, invalid, expired or revoked")
        if public_records[0][6]:
            try:
                native_expiry = dt.datetime.fromtimestamp(int(public_records[0][6]), tz=dt.timezone.utc).date()
            except (ValueError, OverflowError) as exc:
                raise SignatureGateError("RPM OpenPGP key expiry is malformed") from exc
            if native_expiry < as_of:
                fail("RPM OpenPGP primary key is expired on the qualification date")
        try:
            native_created = dt.datetime.fromtimestamp(
                int(public_records[0][5]), tz=dt.timezone.utc
            ).date()
        except (ValueError, OverflowError) as exc:
            raise SignatureGateError("RPM OpenPGP key creation time is malformed") from exc
        if native_created > as_of:
            fail("RPM OpenPGP primary key was created after the qualification date")
        records = [line.split(":") for line in listing.splitlines()]
        primary_index = next(
            index for index, record in enumerate(records) if record[0] == "pub"
        )
        primary_fingerprint = None
        for record in records[primary_index + 1 :]:
            if record[0] == "fpr" and len(record) > 9:
                primary_fingerprint = record[9]
                break
            if record[0] in {"pub", "sub"}:
                break
        if primary_fingerprint != key["fingerprint"]:
            fail("RPM OpenPGP primary fingerprint does not match policy")
        database = root / "rpmdb"
        database.mkdir(mode=0o700)
        run([rpmkeys, "--dbpath", str(database), "--import", str(public_key)], "RPM key import")
        output = run([rpmkeys, "--dbpath", str(database), "--checksig", "--verbose", str(package)], "RPM native signature verification")
    signature_key_ids = {
        match.upper()
        for match in re.findall(
            r"(?im)^.*\bRSA/SHA256\s+Signature\b[^\n]*\bkey ID ([0-9a-f]{8,40})\b[^\n]*:\s*OK\s*$",
            output,
        )
    }
    if any(marker in output.upper() for marker in ("NOT OK", "NOKEY", "UNSIGNED")) or len(signature_key_ids) != 1:
        fail("RPM native verifier did not emit an RSA/SHA256 signature verdict")
    validate_openpgp_signing_identity(records, signature_key_ids.pop(), as_of)
    if key_path(policy_path, key) != (public_key_path, public_key_data):
        fail("RPM public key changed during native verification")


def verify_apk(
    policy: dict[str, Any],
    policy_path: Path,
    package: Path,
    key_id: str,
    apk: str,
    openssl: str,
    as_of: dt.date,
) -> None:
    key = select_key(policy, "apk", key_id, as_of)
    public_key_path, public_key_data = key_path(policy_path, key)
    if key["fingerprint"] != key["public_key_sha256"]:
        fail("APK key fingerprint must equal its canonical public-key SHA-256")
    public_name = Path(key["public_key"]).name
    if re.fullmatch(r"[A-Za-z0-9._+-]+\.rsa\.pub", public_name) is None:
        fail("APK public key filename is not native-package compatible")
    with tempfile.TemporaryDirectory(prefix="syswarden-apk-keys-") as raw:
        keys = Path(raw)
        trusted = keys / public_name
        public_key = stage_bound_package(keys, public_name, public_key_data)
        if public_key != trusted:
            fail("APK public key staging path changed")
        public_description = run(
            [
                openssl,
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-text_pub",
                "-noout",
            ],
            "APK RSA public key inspection",
        )
        key_size = re.search(
            r"(?m)^Public-Key: \(([0-9]+) bit\)$", public_description
        )
        if key_size is None or not 3072 <= int(key_size.group(1)) <= 8192:
            fail("APK public key must be a 3072 to 8192-bit RSA key")
        run(
            [apk, "verify", "--keys-dir", str(keys), str(package)],
            "APK native signature verification",
            ("SYSWARDEN_APK_SIGNER_IMAGE",)
            if os.environ.get("SYSWARDEN_APK_SIGNER_IMAGE") is not None
            else (),
        )
    if key_path(policy_path, key) != (public_key_path, public_key_data):
        fail("APK public key changed during native verification")


def validate_openpgp_record(
    record: list[str], as_of: dt.date, label: str, require_signing: bool
) -> None:
    if len(record) <= 11:
        fail(f"{label} OpenPGP key record is incomplete")
    try:
        bits = int(record[2])
        created = dt.datetime.fromtimestamp(
            int(record[5]), tz=dt.timezone.utc
        ).date()
        expires = (
            dt.datetime.fromtimestamp(int(record[6]), tz=dt.timezone.utc).date()
            if record[6]
            else None
        )
    except (ValueError, OverflowError) as exc:
        raise SignatureGateError(
            f"{label} OpenPGP key dates or size are malformed"
        ) from exc
    if record[3] not in {"1", "3"} or not 3072 <= bits <= 8192:
        fail(f"{label} OpenPGP key must be a 3072 to 8192-bit RSA key")
    if require_signing and "s" not in record[11].lower():
        fail(f"{label} OpenPGP key is not signing-capable")
    if record[1] in {"d", "e", "i", "r"}:
        fail(f"{label} OpenPGP key is disabled, invalid, expired or revoked")
    if created > as_of or (expires is not None and expires < as_of):
        fail(f"{label} OpenPGP key is not valid on the qualification date")


def validate_deb_openpgp_certificate(
    records: list[list[str]],
    expected_primary_fingerprint: str,
    signing_fingerprint: str,
    as_of: dt.date,
) -> None:
    identities: list[tuple[list[str], str]] = []
    for index, record in enumerate(records):
        if not record or record[0] not in {"pub", "sub"}:
            continue
        fingerprint = None
        for candidate in records[index + 1 :]:
            if candidate and candidate[0] in {"pub", "sub"}:
                break
            if candidate and candidate[0] == "fpr" and len(candidate) > 9:
                fingerprint = candidate[9]
                break
        if fingerprint is None or OPENPGP_FINGERPRINT.fullmatch(fingerprint) is None:
            fail("DEB OpenPGP certificate contains an invalid key fingerprint")
        identities.append((record, fingerprint))
    primary = [item for item in identities if item[0][0] == "pub"]
    if len(primary) != 1 or primary[0][1] != expected_primary_fingerprint:
        fail("DEB OpenPGP primary fingerprint does not match policy")
    validate_openpgp_record(primary[0][0], as_of, "DEB primary", False)
    signers = [item for item in identities if item[1] == signing_fingerprint]
    if len(signers) != 1:
        fail("DEB signature does not identify one key in the committed certificate")
    validate_openpgp_record(signers[0][0], as_of, "DEB signing", True)


def validate_detached_signature_container(data: bytes) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureGateError("DEB detached signature must be ASCII armored") from exc
    begin = "-----BEGIN PGP SIGNATURE-----"
    end = "-----END PGP SIGNATURE-----"
    if (
        "\r" in text
        or not text.startswith(begin + "\n")
        or not text.endswith(end + "\n")
        or text.count(begin) != 1
        or text.count(end) != 1
        or any(len(line) > 1024 for line in text.splitlines())
    ):
        fail("DEB detached signature armor is not singular and canonical")


def validate_deb_public_key_container(path: Path, data: bytes) -> None:
    if path.suffix != ".asc":
        fail("DEB public key filename must use the .asc suffix")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureGateError("DEB public key must be ASCII armored") from exc
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    if (
        "\r" in text
        or not text.startswith(begin + "\n")
        or not text.endswith(end + "\n")
        or text.count(begin) != 1
        or text.count(end) != 1
        or any(len(line) > 1024 for line in text.splitlines())
    ):
        fail("DEB public key armor is not singular and canonical")


def run_gpgv_status(command: list[str]) -> list[tuple[str, list[str]]]:
    environment = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"cannot execute isolated DEB gpgv verification: {exc}")
    if (
        len(result.stdout.encode("utf-8")) > MAX_VERIFIER_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > MAX_VERIFIER_OUTPUT_BYTES
    ):
        fail("isolated DEB gpgv verification output exceeds its bound")
    if result.returncode != 0:
        fail("isolated DEB gpgv verification rejected the signature")
    statuses: list[tuple[str, list[str]]] = []
    for line in result.stdout.splitlines():
        if not line.startswith("[GNUPG:] "):
            fail("DEB gpgv status channel contains non-status output")
        fields = line.removeprefix("[GNUPG:] ").split()
        if not fields:
            fail("DEB gpgv emitted an empty status record")
        statuses.append((fields[0], fields[1:]))
    allowed = {
        "NEWSIG",
        "KEY_CONSIDERED",
        "SIG_ID",
        "GOODSIG",
        "VALIDSIG",
        "TRUST_UNDEFINED",
        "TRUST_MARGINAL",
        "TRUST_FULLY",
        "TRUST_ULTIMATE",
    }
    if not statuses or any(tag not in allowed for tag, _ in statuses):
        fail("DEB gpgv status is incomplete or contains a rejection record")
    return statuses


def one_status(
    statuses: list[tuple[str, list[str]]], tag: str
) -> list[str]:
    matches = [arguments for candidate, arguments in statuses if candidate == tag]
    if len(matches) != 1:
        fail(f"DEB gpgv must emit exactly one {tag} status")
    return matches[0]


def validate_deb_gpgv_status(
    statuses: list[tuple[str, list[str]]], key: dict[str, Any], as_of: dt.date
) -> tuple[str, str]:
    one_status(statuses, "NEWSIG")
    considered = one_status(statuses, "KEY_CONSIDERED")
    signature_id = one_status(statuses, "SIG_ID")
    good = one_status(statuses, "GOODSIG")
    valid = one_status(statuses, "VALIDSIG")
    if len(good) < 1 or not re.fullmatch(r"[0-9A-F]{16,40}", good[0]):
        fail("DEB gpgv GOODSIG identity is malformed")
    if len(valid) < 10:
        fail("DEB gpgv VALIDSIG status is incomplete")
    signing_fingerprint = valid[0]
    primary_fingerprint = valid[9]
    if (
        OPENPGP_FINGERPRINT.fullmatch(signing_fingerprint) is None
        or primary_fingerprint != key["fingerprint"]
        or not signing_fingerprint.endswith(good[0])
    ):
        fail("DEB gpgv signature identity does not match the selected policy key")
    try:
        signed_epoch = int(valid[2])
        expires_epoch = int(valid[3])
        signed_at = dt.datetime.fromtimestamp(
            signed_epoch, tz=dt.timezone.utc
        )
    except (ValueError, OverflowError) as exc:
        raise SignatureGateError("DEB gpgv signature time is malformed") from exc
    if (
        valid[1] != signed_at.date().isoformat()
        or signed_at.date() != as_of
        or expires_epoch < 0
        or (expires_epoch != 0 and expires_epoch < signed_epoch)
        or valid[4] != "4"
        or valid[5] != "0"
        or valid[6] not in {"1", "3"}
        or valid[7] != "8"
        or valid[8] != "00"
    ):
        fail("DEB signature date, algorithm or digest is not qualification-safe")
    if (
        len(considered) != 2
        or considered[0] != key["fingerprint"]
        or considered[1] != "0"
        or len(signature_id) != 3
        or re.fullmatch(r"[A-Za-z0-9+/]{20,64}", signature_id[0]) is None
        or signature_id[1] != valid[1]
        or signature_id[2] != valid[2]
    ):
        fail("DEB gpgv status identities or dates are inconsistent")
    trust = [arguments for tag, arguments in statuses if tag.startswith("TRUST_")]
    if len(trust) > 1:
        fail("DEB gpgv emitted duplicate trust status")
    return signing_fingerprint, signed_at.isoformat().replace("+00:00", "Z")


def verify_deb(
    policy: dict[str, Any],
    policy_path: Path,
    package: Path,
    signature: Path,
    key_id: str,
    gpg: str,
    gpgv: str,
    as_of: dt.date,
) -> tuple[bytes, str]:
    key = select_key(policy, "deb", key_id, as_of)
    public_key_path, public_key_data = key_path(policy_path, key)
    validate_deb_public_key_container(public_key_path, public_key_data)
    signature_data = regular_bytes(
        signature, MAX_DEB_SIGNATURE_BYTES, "DEB detached signature"
    )
    if signature.name != package.name + policy["deb"]["signature_suffix"]:
        fail("DEB detached signature filename is not bound to the package")
    validate_detached_signature_container(signature_data)
    with tempfile.TemporaryDirectory(prefix="syswarden-deb-verify-") as raw:
        root = Path(raw)
        gpg_home = root / "gnupg"
        gpg_home.mkdir(mode=0o700)
        public_key = stage_bound_package(root, "deb-public.asc", public_key_data)
        detached = stage_bound_package(root, signature.name, signature_data)
        listing = run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--homedir",
                str(gpg_home),
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                str(public_key),
            ],
            "DEB OpenPGP key inspection",
        )
        records = [line.split(":") for line in listing.splitlines()]
        keyring = root / "trustedkeys.gpg"
        run(
            [
                gpg,
                "--batch",
                "--yes",
                "--no-options",
                "--homedir",
                str(gpg_home),
                "--output",
                str(keyring),
                "--dearmor",
                str(public_key),
            ],
            "DEB OpenPGP trust-root conversion",
        )
        statuses = run_gpgv_status(
            [
                gpgv,
                "--homedir",
                str(gpg_home),
                "--keyring",
                str(keyring),
                "--status-fd",
                "1",
                "--logger-fd",
                "2",
                "--",
                str(detached),
                str(package),
            ]
        )
        signing_fingerprint, signed_at = validate_deb_gpgv_status(
            statuses, key, as_of
        )
        validate_deb_openpgp_certificate(
            records, key["fingerprint"], signing_fingerprint, as_of
        )
    if regular_bytes(
        signature, MAX_DEB_SIGNATURE_BYTES, "DEB detached signature"
    ) != signature_data:
        fail("DEB detached signature changed during verification")
    if key_path(policy_path, key) != (public_key_path, public_key_data):
        fail("DEB public key changed during native verification")
    return signature_data, signed_at


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=("rpm", "apk", "deb"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--rpmkeys", default="rpmkeys")
    parser.add_argument("--gpg", default="gpg")
    parser.add_argument("--gpgv", default="gpgv")
    parser.add_argument("--apk", default="apk")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--signature", type=Path)
    parser.add_argument(
        "--purpose", choices=("qualification", "publishing"), default="qualification"
    )
    parser.add_argument("--bootstrap-qualification", action="store_true")
    parser.add_argument(
        "--package-role",
        choices=("standard", "rhel-package-owned"),
        default="standard",
    )
    parser.add_argument("--evidence-output", type=Path)
    args = parser.parse_args(argv)
    try:
        as_of = parse_day(args.as_of, "qualification date")
        policy_bytes = regular_bytes(
            args.policy, MAX_JSON_BYTES, "signature policy"
        )
        policy = decode_json(policy_bytes, "signature policy")
        validate_policy(policy, as_of)
        inventory_bytes = regular_bytes(
            args.inventory, MAX_JSON_BYTES, "release inventory"
        )
        package_data = bind_artifact(
            decode_json(inventory_bytes, "release inventory"),
            args.package,
            args.release,
            args.family,
            args.package_role,
        )
        selected_key = select_verification_key(
            policy,
            args.family,
            args.key_id,
            as_of,
            args.purpose,
            args.bootstrap_qualification,
        )
        signature_data: bytes | None = None
        signature_created_at: str | None = None
        with tempfile.TemporaryDirectory(prefix="syswarden-native-package-") as raw:
            bound_package = stage_bound_package(Path(raw), args.package.name, package_data)
            if args.family == "rpm":
                if args.signature is not None:
                    fail("detached signature input is valid only for DEB verification")
                verify_rpm(policy, args.policy, bound_package, args.key_id, args.rpmkeys, args.gpg, as_of)
            elif args.family == "apk":
                if args.signature is not None:
                    fail("detached signature input is valid only for DEB verification")
                verify_apk(
                    policy,
                    args.policy,
                    bound_package,
                    args.key_id,
                    args.apk,
                    args.openssl,
                    as_of,
                )
            else:
                expected_deb_implementation = (
                    "implemented-not-qualified"
                    if args.bootstrap_qualification
                    else "qualified"
                )
                if policy["deb"]["implementation"] != expected_deb_implementation:
                    fail("DEB detached-signature verification is not qualified")
                if args.signature is None:
                    fail("DEB detached signature is required")
                signature_data, signature_created_at = verify_deb(
                    policy,
                    args.policy,
                    bound_package,
                    args.signature,
                    args.key_id,
                    args.gpg,
                    args.gpgv,
                    as_of,
                )
        if (
            regular_bytes(args.policy, MAX_JSON_BYTES, "signature policy")
            != policy_bytes
        ):
            fail("signature policy changed during verification")
        if (
            regular_bytes(args.inventory, MAX_JSON_BYTES, "release inventory")
            != inventory_bytes
        ):
            fail("release inventory changed during verification")
        if regular_bytes(args.package, MAX_PACKAGE_BYTES, "package") != package_data:
            fail("package changed during verification")
        if args.evidence_output is not None:
            evidence: dict[str, Any] = {
                "as_of": as_of.isoformat(),
                "family": args.family,
                "key": {
                    "fingerprint": selected_key["fingerprint"],
                    "id": selected_key["id"],
                    "public_key": selected_key["public_key"],
                    "public_key_sha256": selected_key["public_key_sha256"],
                },
                "mechanism": policy[args.family]["mechanism"],
                "package": {
                    "name": args.package.name,
                    "sha256": hashlib.sha256(package_data).hexdigest(),
                    "size": len(package_data),
                },
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
                "profile": "syswarden-native-package-verification/v4.10.0",
                "purpose": args.purpose,
                "release": args.release,
                "schema_version": 1,
                "status": "verified",
            }
            if signature_data is not None and signature_created_at is not None:
                evidence["signature"] = {
                    "created_at": signature_created_at,
                    "name": args.signature.name,
                    "sha256": hashlib.sha256(signature_data).hexdigest(),
                    "size": len(signature_data),
                }
            write_json_exclusive(
                args.evidence_output,
                evidence,
            )
    except SignatureGateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Native {args.family.upper()} signature and release binding verified offline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
