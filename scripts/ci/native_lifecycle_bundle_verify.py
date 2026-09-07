#!/usr/bin/env python3
"""Revalidate the sealed v4.10.0 native lifecycle verdict."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

try:
    from scripts.ci import native_lifecycle_evidence, native_package_signing_bundle
except ModuleNotFoundError:
    import native_lifecycle_evidence
    import native_package_signing_bundle


def _package_record(value: object, label: str) -> dict[str, object]:
    record = native_package_signing_bundle.exact_keys(
        value, {"name", "sha256", "size"}, label
    )
    name = record["name"]
    digest = record["sha256"]
    size = record["size"]
    if not isinstance(name, str) or not name:
        native_package_signing_bundle.fail(f"{label} name is invalid")
    if (
        not isinstance(digest, str)
        or not native_package_signing_bundle.SHA256.fullmatch(digest)
    ):
        native_package_signing_bundle.fail(f"{label} digest is invalid")
    if (
        type(size) is not int
        or size <= 0
        or size > native_package_signing_bundle.MAX_PACKAGE_BYTES
    ):
        native_package_signing_bundle.fail(f"{label} size is invalid")
    return record


def _signed_package_records(
    provenance: dict[str, object],
) -> dict[str, dict[str, object]]:
    packages = native_package_signing_bundle.exact_keys(
        provenance["packages"], {"signed", "unsigned"}, "package provenance"
    )
    signed = packages["signed"]
    expected_names = set(
        native_package_signing_bundle.package_names(
            native_lifecycle_evidence.TARGET_RELEASE
        ).values()
    )
    if not isinstance(signed, list) or len(signed) != len(expected_names):
        native_package_signing_bundle.fail(
            "signed package provenance inventory is not exact"
        )
    records: dict[str, dict[str, object]] = {}
    observed_names: list[str] = []
    for index, value in enumerate(signed):
        record = _package_record(value, f"signed package record {index}")
        name = str(record["name"])
        if name not in expected_names or name in records:
            native_package_signing_bundle.fail(
                "signed package provenance inventory is not exact"
            )
        records[name] = record
        observed_names.append(name)
    if set(records) != expected_names or observed_names != sorted(expected_names):
        native_package_signing_bundle.fail(
            "signed package provenance inventory is not exact"
        )
    return records


def _signing_key(value: object, family: str) -> dict[str, object]:
    key = native_package_signing_bundle.exact_keys(
        value,
        {"fingerprint", "id", "public_key", "public_key_sha256"},
        f"{family} signing key",
    )
    fingerprint_pattern = (
        native_package_signing_bundle.SHA256
        if family == "apk"
        else native_package_signing_bundle.signature_gate.OPENPGP_FINGERPRINT
    )
    safe_key_path = native_package_signing_bundle.signature_gate.SAFE_RELATIVE_KEY_PATH
    public_key = key["public_key"]
    if (
        not isinstance(key["id"], str)
        or native_package_signing_bundle.KEY_ID.fullmatch(key["id"]) is None
        or not isinstance(public_key, str)
        or safe_key_path.fullmatch(public_key) is None
        or Path(public_key).is_absolute()
        or ".." in Path(public_key).parts
        or not public_key.startswith("native-package-keys/")
        or not isinstance(key["fingerprint"], str)
        or fingerprint_pattern.fullmatch(key["fingerprint"]) is None
        or not isinstance(key["public_key_sha256"], str)
        or native_package_signing_bundle.SHA256.fullmatch(key["public_key_sha256"])
        is None
    ):
        native_package_signing_bundle.fail(f"{family} signing key is malformed")
    if family == "apk" and key["fingerprint"] != key["public_key_sha256"]:
        native_package_signing_bundle.fail(
            "APK key fingerprint and public-key digest differ"
        )
    return key


def _signature_record(value: object, expected_name: str) -> dict[str, object]:
    record = native_package_signing_bundle.exact_keys(
        value,
        {"created_at", "name", "sha256", "size"},
        "DEB detached signature provenance",
    )
    if record["name"] != expected_name or not isinstance(record["created_at"], str):
        native_package_signing_bundle.fail(
            "DEB detached signature provenance is malformed"
        )
    _package_record(
        {key: record[key] for key in ("name", "sha256", "size")},
        "DEB detached signature provenance",
    )
    try:
        created_at = dt.datetime.fromisoformat(
            record["created_at"].replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise native_package_signing_bundle.SigningBundleError(
            "DEB detached signature creation time is invalid"
        ) from exc
    if (
        created_at.tzinfo != dt.timezone.utc
        or created_at.isoformat().replace("+00:00", "Z") != record["created_at"]
    ):
        native_package_signing_bundle.fail(
            "DEB detached signature creation time is not canonical"
        )
    return record


def _verification_document(
    signing_root: Path,
    family: str,
    package: dict[str, object],
    policy_sha256: str,
    provenance_key: dict[str, object],
    provenance_signature: dict[str, object] | None = None,
) -> dict[str, object]:
    path = signing_root / f"{family.upper()}_NATIVE_VERIFICATION.json"
    document = native_package_signing_bundle.load_json(
        path, f"{family} native verification"
    )
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
    native_package_signing_bundle.exact_keys(
        document, expected_keys, f"{family} native verification"
    )
    expected_mechanism = {
        "rpm": "rpm-openpgp",
        "deb": "openpgp-detached",
        "apk": "apk-rsa256",
    }[family]
    if (
        document["schema_version"] != 1
        or document["profile"]
        != native_package_signing_bundle.VERIFICATION_PROFILE
        or document["status"] != "verified"
        or document["purpose"] != "qualification"
        or document["release"] != native_lifecycle_evidence.TARGET_RELEASE
        or document["family"] != family
        or document["mechanism"] != expected_mechanism
        or document["policy_sha256"] != policy_sha256
    ):
        native_package_signing_bundle.fail(
            f"{family} native verification identity is invalid"
        )
    as_of = document["as_of"]
    try:
        parsed_day = dt.date.fromisoformat(as_of) if isinstance(as_of, str) else None
    except ValueError as exc:
        raise native_package_signing_bundle.SigningBundleError(
            f"{family} native verification date is invalid"
        ) from exc
    if parsed_day is None or parsed_day.isoformat() != as_of:
        native_package_signing_bundle.fail(
            f"{family} native verification date is invalid"
        )
    if _package_record(
        document["package"], f"{family} native verification package"
    ) != package:
        native_package_signing_bundle.fail(
            f"{family} native verification package differs from provenance"
        )
    if _signing_key(document["key"], family) != provenance_key:
        native_package_signing_bundle.fail(
            f"{family} native verification key differs from provenance"
        )
    if family == "deb":
        if provenance_signature is None:
            native_package_signing_bundle.fail(
                "DEB provenance signature is unavailable"
            )
        verification_signature = _signature_record(
            document["signature"], str(provenance_signature["name"])
        )
        if verification_signature != provenance_signature:
            native_package_signing_bundle.fail(
                "DEB native verification signature differs from provenance"
            )
    return document


def _validated_signing_inputs(
    signing_root: Path, candidate: str
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, dict[str, object]],
    dict[str, object],
]:
    if native_package_signing_bundle.COMMIT_SHA.fullmatch(candidate) is None:
        native_package_signing_bundle.fail("candidate commit is malformed")
    provenance = native_package_signing_bundle.load_json(
        signing_root / "NATIVE_SIGNING_PROVENANCE.json",
        "native signing provenance",
    )
    native_package_signing_bundle.exact_keys(
        provenance,
        {
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
        },
        "native signing provenance",
    )
    if (
        provenance["schema_version"] != 1
        or provenance["profile"] != native_package_signing_bundle.SCHEMA_PROFILE
        or provenance["status"]
        != native_package_signing_bundle.QUALIFIED_PROVENANCE_STATUS
        or provenance["release_qualified"] is not False
        or provenance["public_release"] is not False
    ):
        native_package_signing_bundle.fail(
            "native signing provenance identity is invalid"
        )
    policy_sha256 = provenance["policy_sha256"]
    if (
        not isinstance(policy_sha256, str)
        or native_package_signing_bundle.SHA256.fullmatch(policy_sha256) is None
        or not isinstance(provenance["repository"], str)
        or native_package_signing_bundle.REPOSITORY.fullmatch(provenance["repository"])
        is None
        or not isinstance(provenance["signer_image"], str)
        or (
            native_package_signing_bundle.OCI_DIGEST.fullmatch(
                provenance["signer_image"]
            )
            is None
        )
    ):
        native_package_signing_bundle.fail(
            "native signing provenance trust binding is malformed"
        )
    source = native_package_signing_bundle.exact_keys(
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
    release_version = native_lifecycle_evidence.TARGET_RELEASE.removeprefix("v")
    expected_unsigned_name = f"syswarden-packages-{release_version}"
    if (
        source["release_sha"] != candidate
        or source["release_tag"] != native_lifecycle_evidence.TARGET_RELEASE
        or source["unsigned_artifact_name"] != expected_unsigned_name
        or not isinstance(source["unsigned_artifact_digest"], str)
        or native_package_signing_bundle.GITHUB_DIGEST.fullmatch(
            source["unsigned_artifact_digest"]
        )
        is None
    ):
        native_package_signing_bundle.fail(
            "unsigned artifact source binding is invalid"
        )
    native_package_signing_bundle.positive_integer(
        source["source_date_epoch"], "source date epoch"
    )
    native_package_signing_bundle.positive_integer(
        source["unsigned_artifact_id"], "unsigned artifact ID"
    )
    native_package_signing_bundle.positive_integer(
        source["unsigned_package_run_id"], "unsigned package run ID"
    )
    signing_run = native_package_signing_bundle.exact_keys(
        provenance["signing_run"],
        {"attempt", "id", "workflow", "workflow_sha"},
        "signing run binding",
    )
    if (
        signing_run["attempt"] != 1
        or signing_run["workflow"] != ".github/workflows/native-package-signing.yml"
        or signing_run["workflow_sha"] != candidate
    ):
        native_package_signing_bundle.fail("signing run binding is invalid")
    native_package_signing_bundle.positive_integer(
        signing_run["id"], "signing run ID"
    )

    package_names = native_package_signing_bundle.package_names(
        native_lifecycle_evidence.TARGET_RELEASE
    )
    packages = _signed_package_records(provenance)
    rpm_signature = native_package_signing_bundle.exact_keys(
        provenance["rpm_signature"],
        {"immutable_header_preserved", "key", "payload_preserved"},
        "RPM signature provenance",
    )
    if (
        rpm_signature["immutable_header_preserved"] is not True
        or rpm_signature["payload_preserved"] is not True
    ):
        native_package_signing_bundle.fail(
            "RPM signature transformation is not proven"
        )
    rpm_key = _signing_key(rpm_signature["key"], "rpm")
    deb_signature = native_package_signing_bundle.exact_keys(
        provenance["deb_signature"],
        {"bytes_unchanged", "detached", "key", "signature"},
        "DEB signature provenance",
    )
    if (
        deb_signature["bytes_unchanged"] is not True
        or deb_signature["detached"] is not True
    ):
        native_package_signing_bundle.fail(
            "DEB detached-signature provenance is inconsistent"
        )
    deb_key = _signing_key(deb_signature["key"], "deb")
    detached_signature = _signature_record(
        deb_signature["signature"],
        native_package_signing_bundle.deb_signature_name(
            native_lifecycle_evidence.TARGET_RELEASE
        ),
    )

    apk_signature = native_package_signing_bundle.exact_keys(
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
    apk_key = _signing_key(apk_signature["key"], "apk")
    expected_signature_entry = ".SIGN.RSA256." + Path(str(apk_key["public_key"])).name
    if (
        apk_signature["exact_unsigned_suffix"] is not True
        or apk_signature["signature_entry"] != expected_signature_entry
        or not isinstance(apk_signature["signature_prefix_sha256"], str)
        or native_package_signing_bundle.SHA256.fullmatch(
            apk_signature["signature_prefix_sha256"]
        )
        is None
        or not isinstance(apk_signature["signature_sha256"], str)
        or native_package_signing_bundle.SHA256.fullmatch(
            apk_signature["signature_sha256"]
        )
        is None
        or type(apk_signature["signature_prefix_size"]) is not int
        or apk_signature["signature_prefix_size"] <= 0
        or apk_signature["signature_prefix_size"]
        > native_package_signing_bundle.MAX_APK_SIGNATURE_PREFIX_BYTES
    ):
        native_package_signing_bundle.fail(
            "APK signature provenance is malformed"
        )

    rpm_verification = _verification_document(
        signing_root,
        "rpm",
        packages[package_names["rpm"]],
        policy_sha256,
        rpm_key,
    )
    deb_verification = _verification_document(
        signing_root,
        "deb",
        packages[package_names["deb"]],
        policy_sha256,
        deb_key,
        detached_signature,
    )
    apk_verification = _verification_document(
        signing_root,
        "apk",
        packages[package_names["apk"]],
        policy_sha256,
        apk_key,
    )
    if len(
        {
            rpm_verification["as_of"],
            deb_verification["as_of"],
            apk_verification["as_of"],
        }
    ) != 1:
        native_package_signing_bundle.fail(
            "native verification dates are inconsistent"
        )
    rhel_package = _validated_rhel_signing_input(
        signing_root,
        candidate,
        rpm_key,
        provenance,
        packages[package_names["rpm"]],
        str(rpm_verification["as_of"]),
    )
    return rpm_key, deb_key, apk_key, packages, rhel_package


def _validated_rhel_signing_input(
    signing_root: Path,
    candidate: str,
    expected_rpm_key: dict[str, object],
    standard_provenance: dict[str, object],
    standard_rpm: dict[str, object],
    expected_as_of: str,
) -> dict[str, object]:
    evidence_root = (
        signing_root.parent
        / native_package_signing_bundle.RHEL_PACKAGE_OWNED_DIRECTORY
        / "evidence"
    )
    provenance = native_package_signing_bundle.load_json(
        evidence_root / "SIGNING_PROVENANCE.json",
        "RHEL package-owned signing provenance",
    )
    native_package_signing_bundle.exact_keys(
        provenance,
        {
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
    if (
        provenance["schema_version"] != 1
        or provenance["profile"]
        != native_package_signing_bundle.RHEL_PACKAGE_OWNED_PROFILE
        or provenance["status"]
        != native_package_signing_bundle.QUALIFIED_PROVENANCE_STATUS
        or provenance["package_role"] != "rhel-package-owned"
        or provenance["public_release"] is not False
        or provenance["release_qualified"] is not False
        or provenance["updater_manifest_included"] is not False
        or provenance["policy_sha256"] != standard_provenance["policy_sha256"]
        or provenance["repository"] != standard_provenance["repository"]
        or provenance["signing_run"] != standard_provenance["signing_run"]
    ):
        native_package_signing_bundle.fail(
            "RHEL package-owned signing provenance identity is invalid"
        )
    expected_name = native_package_signing_bundle.rhel_package_owned_name(
        native_lifecycle_evidence.TARGET_RELEASE
    )
    identity = native_package_signing_bundle.exact_keys(
        provenance["rpm_identity"],
        {"architecture", "filename", "name", "release", "version"},
        "RHEL package-owned RPM identity",
    )
    if identity != {
        "architecture": "x86_64",
        "filename": expected_name,
        "name": "syswarden",
        "release": "1.rhelpo",
        "version": native_lifecycle_evidence.TARGET_RELEASE.removeprefix("v"),
    }:
        native_package_signing_bundle.fail("RHEL package-owned RPM NEVRA is invalid")
    source = native_package_signing_bundle.exact_keys(
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
        "RHEL package-owned unsigned artifact source binding",
    )
    standard_source = standard_provenance["source"]
    if (
        source["release_sha"] != candidate
        or source["release_tag"] != native_lifecycle_evidence.TARGET_RELEASE
        or source["source_date_epoch"] != standard_source["source_date_epoch"]
        or source["unsigned_package_run_id"]
        != standard_source["unsigned_package_run_id"]
        or source["unsigned_artifact_name"]
        != "syswarden-rhel-package-owned-4.10.0"
        or source["unsigned_artifact_id"] == standard_source["unsigned_artifact_id"]
        or source["unsigned_artifact_digest"]
        == standard_source["unsigned_artifact_digest"]
        or not isinstance(source["unsigned_artifact_digest"], str)
        or native_package_signing_bundle.GITHUB_DIGEST.fullmatch(
            source["unsigned_artifact_digest"]
        )
        is None
    ):
        native_package_signing_bundle.fail(
            "RHEL package-owned unsigned artifact source binding is invalid"
        )
    native_package_signing_bundle.positive_integer(
        source["source_date_epoch"], "RHEL package-owned source date epoch"
    )
    native_package_signing_bundle.positive_integer(
        source["unsigned_artifact_id"], "RHEL package-owned unsigned artifact ID"
    )
    native_package_signing_bundle.positive_integer(
        source["unsigned_package_run_id"], "RHEL package-owned package run ID"
    )
    packages = native_package_signing_bundle.exact_keys(
        provenance["packages"],
        {"signed", "unsigned"},
        "RHEL package-owned package provenance",
    )
    signed = _package_record(packages["signed"], "signed RHEL package-owned RPM")
    unsigned = _package_record(
        packages["unsigned"], "unsigned RHEL package-owned RPM"
    )
    if (
        signed["name"] != expected_name
        or unsigned["name"] != expected_name
        or signed == standard_rpm
        or signed["sha256"] == standard_rpm["sha256"]
        or unsigned["sha256"] == signed["sha256"]
    ):
        native_package_signing_bundle.fail(
            "RHEL package-owned package provenance is invalid"
        )
    rpm_signature = native_package_signing_bundle.exact_keys(
        provenance["rpm_signature"],
        {"immutable_header_preserved", "key", "payload_preserved"},
        "RHEL package-owned RPM signature provenance",
    )
    if (
        rpm_signature["immutable_header_preserved"] is not True
        or rpm_signature["payload_preserved"] is not True
        or _signing_key(rpm_signature["key"], "rpm") != expected_rpm_key
    ):
        native_package_signing_bundle.fail(
            "RHEL package-owned RPM signature provenance is invalid"
        )
    verification = _verification_document(
        evidence_root,
        "rpm",
        signed,
        str(provenance["policy_sha256"]),
        expected_rpm_key,
    )
    if verification["as_of"] != expected_as_of:
        native_package_signing_bundle.fail(
            "RHEL package-owned verification date differs from standard RPM"
        )
    return signed


def verify(
    root: Path,
    signing_root: Path,
    candidate: str,
    node02_pin: str,
    node04_pin: str,
    node05_pin: str,
    node03_pin: str,
) -> None:
    archive = root / "RAW_EVIDENCE.tar"
    expected = root / "VERDICT.json"
    rpm_key, deb_key, apk_key, packages, rhel_rpm_package = _validated_signing_inputs(
        signing_root, candidate
    )
    package_names = native_package_signing_bundle.package_names(
        native_lifecycle_evidence.TARGET_RELEASE
    )
    rpm_package = packages[package_names["rpm"]]
    deb_package = packages[package_names["deb"]]
    apk_package = packages[package_names["apk"]]
    with tempfile.TemporaryDirectory(prefix="syswarden-native-lifecycle-") as temporary:
        extracted = Path(temporary)
        with tarfile.open(archive, mode="r:") as stream:
            members = stream.getmembers()
            if not members or len(members) > 192:
                raise SystemExit("native lifecycle archive member count is invalid")
            observation_names = {
                "node02-ubuntu26.04.json",
                "node04-alpine3.24.json",
                "node05-almalinux9.8.json",
                "node05-almalinux9.8-rhelpo.json",
                "node03-almalinux10.2-rhelpo.json",
            }
            seen_members: set[str] = set()
            for member in members:
                name = PurePosixPath(member.name)
                if (
                    not name.parts
                    or name.is_absolute()
                    or any(part in {"", ".", ".."} for part in name.parts)
                ):
                    raise SystemExit("native lifecycle archive path is unsafe")
                canonical_name = name.as_posix()
                if canonical_name in seen_members:
                    raise SystemExit("native lifecycle archive member is duplicated")
                seen_members.add(canonical_name)
                if canonical_name not in observation_names and name.parts[0] != "artifacts":
                    raise SystemExit("native lifecycle archive inventory is not exact")
                if not (member.isdir() or member.isfile()):
                    raise SystemExit("native lifecycle archive type is unsafe")
                target = extracted.joinpath(*name.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if member.size <= 0 or member.size > 1048576:
                    raise SystemExit("native lifecycle archive member size is invalid")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    raise SystemExit("native lifecycle archive member is unreadable")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(source.read())
        node02 = extracted / "node02-ubuntu26.04.json"
        node04 = extracted / "node04-alpine3.24.json"
        node05 = extracted / "node05-almalinux9.8.json"
        node05_rhelpo = extracted / "node05-almalinux9.8-rhelpo.json"
        node03_rhelpo = extracted / "node03-almalinux10.2-rhelpo.json"
        actual = native_lifecycle_evidence.assemble(
            candidate,
            [node02, node04, node05, node05_rhelpo, node03_rhelpo],
            extracted / "artifacts",
            rpm_signer_fingerprint=str(rpm_key["fingerprint"]),
            deb_signer_fingerprint=str(deb_key["fingerprint"]),
            apk_public_key_sha256=str(apk_key["public_key_sha256"]),
            rpm_package_name=str(rpm_package["name"]),
            rpm_package_sha256=str(rpm_package["sha256"]),
            rpm_package_size=int(rpm_package["size"]),
            rhel_rpm_package_name=str(rhel_rpm_package["name"]),
            rhel_rpm_package_sha256=str(rhel_rpm_package["sha256"]),
            rhel_rpm_package_size=int(rhel_rpm_package["size"]),
            deb_package_name=str(deb_package["name"]),
            deb_package_sha256=str(deb_package["sha256"]),
            deb_package_size=int(deb_package["size"]),
            apk_package_name=str(apk_package["name"]),
            apk_package_sha256=str(apk_package["sha256"]),
            apk_package_size=int(apk_package["size"]),
            node02_ssh_host_key_sha256=node02_pin,
            node04_ssh_host_key_sha256=node04_pin,
            node05_ssh_host_key_sha256=node05_pin,
            node03_ssh_host_key_sha256=node03_pin,
        )
        canonical = json.dumps(actual, sort_keys=True, separators=(",", ":")) + "\n"
        if expected.read_text(encoding="utf-8") != canonical:
            raise SystemExit("native lifecycle verdict mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--signing-evidence", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--node02-ssh-host-key-sha256", required=True)
    parser.add_argument("--node04-ssh-host-key-sha256", required=True)
    parser.add_argument("--node05-ssh-host-key-sha256", required=True)
    parser.add_argument("--node03-ssh-host-key-sha256", required=True)
    args = parser.parse_args()
    verify(
        args.bundle,
        args.signing_evidence,
        args.candidate_commit,
        args.node02_ssh_host_key_sha256,
        args.node04_ssh_host_key_sha256,
        args.node05_ssh_host_key_sha256,
        args.node03_ssh_host_key_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
