#!/usr/bin/env python3
"""Qualification-only v5 native evidence, independent of the v4 serializers.

The caller must authenticate the seal digest, release commit, policy digest and
selected keys through its protected workflow. A digest read from the same bundle
is not a trust anchor. The seal binds the builder's package-identity assertions
and RPM preservation proofs; this module does not extract native metadata or
recompute RPM payload proofs. It independently rechecks native signatures.

There is intentionally no CLI, publishing mode, default verifier, or v4 writer.
Injected verifiers are a trusted-code boundary, never a JSON-selected plugin.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import stat
import tempfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

try:
    from scripts.ci import native_package_signature_gate as signatures
    from scripts.ci import native_package_signing_bundle as legacy
except ModuleNotFoundError:
    import native_package_signature_gate as signatures
    import native_package_signing_bundle as legacy


IdentityEvidenceError = signatures.SignatureGateError
PROFILE = "syswarden-native-package-identity-evidence/v5"
SUMMARY_PROFILE = "syswarden-native-package-identity-qualification/v5"
INVENTORY_PROFILE = "syswarden-native-package-inventory/v5"
VERIFICATION_PROFILE = "syswarden-native-package-verification/v5"
RPM_PROOF_PROFILE = "syswarden-rpm-payload-preservation/v5"
SEAL_NAME = "IDENTITY_EVIDENCE.json"
MANIFEST_CHECKSUM_NAME = "MANIFEST_SHA256SUMS"
RELEASE = re.compile(r"v5\.[0-9]{2}\.(?:0|[1-9][0-9]*)\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FAMILIES = ("deb", "rpm", "apk")
PACKAGE_IDENTITIES = ("syswarden", "syswarden-base")
KEY_FIELDS = ("id", "fingerprint", "public_key", "public_key_sha256")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def fail(message: str) -> None:
    raise IdentityEvidenceError(message)


def _equal(actual: object, expected: object, label: str) -> None:
    if not legacy.exact_json_equal(actual, expected):
        fail(f"{label} is not exact")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or signatures.SHA256.fullmatch(value) is None:
        fail(f"{label} must be a SHA-256 digest")
    return value


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Coordinate:
    package_name: str
    family: str
    version: str
    os: str = "linux"
    architecture: str = "amd64"
    package_role: str = "standard"

    @property
    def filename(self) -> str:
        return {
            "deb": f"{self.package_name}_{self.version}_amd64.deb",
            "rpm": f"{self.package_name}-{self.version}-1.x86_64.rpm",
            "apk": f"{self.package_name}_{self.version}_x86_64.apk",
        }[self.family]

    @property
    def verification_name(self) -> str:
        return f"{self.package_name}.{self.family}.NATIVE_VERIFICATION.json"

    @property
    def rpm_proof_name(self) -> str:
        if self.family != "rpm":
            fail("only RPM coordinates have an RPM preservation proof")
        return f"{self.package_name}.rpm.RPM_PAYLOAD_PROOF.json"


def identity_coordinates(release: str) -> tuple[Coordinate, ...]:
    if not isinstance(release, str) or RELEASE.fullmatch(release) is None:
        fail("identity evidence supports canonical v5 standard qualification only")
    patch = release.rsplit(".", 1)[1]
    if len(patch) > 10 or int(patch) > 2147483647:
        fail("identity evidence patch version exceeds the supported bound")
    return tuple(
        Coordinate(name, family, release[1:])
        for name in PACKAGE_IDENTITIES
        for family in FAMILIES
    )


def _file_record(name: str, data: bytes) -> dict[str, Any]:
    return {"name": name, "size": len(data), "sha256": _hash(data)}


def _metadata_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
    )


def _stat_identity(path: Path) -> tuple[int, ...]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise IdentityEvidenceError(f"cannot inspect evidence path: {exc}") from exc
    return _metadata_identity(info)


class _ObservedFiles:
    """Keep only digests and metadata; read at most one bounded package at once."""

    def __init__(self) -> None:
        self.files: dict[Path, tuple[int, tuple[int, ...], dict[str, Any]]] = {}
        self.directories: dict[Path, tuple[set[str], set[str], tuple[int, ...]]] = {}

    def directory(self, root: Path, files: set[str], directories: set[str]) -> None:
        legacy.ensure_protected_directory(root, "identity evidence directory")
        identity = _stat_identity(root)
        expected = files | directories
        observed: set[str] = set()
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if entry.name not in expected or entry.name in observed:
                        fail("identity evidence directory inventory is not exact")
                    observed.add(entry.name)
                    info = entry.stat(follow_symlinks=False)
                    if entry.name in files:
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            fail("identity evidence contains an unsafe file")
                    elif not stat.S_ISDIR(info.st_mode):
                        fail("identity evidence contains an unsafe directory")
        except OSError as exc:
            raise IdentityEvidenceError(f"cannot enumerate identity evidence: {exc}") from exc
        if observed != expected or _stat_identity(root) != identity:
            fail("identity evidence directory changed or inventory is not exact")
        previous = self.directories.get(root)
        current = (files, directories, identity)
        if previous is not None and previous != current:
            fail("identity evidence directory changed during verification")
        self.directories[root] = current

    def read(self, path: Path, maximum: int) -> bytes:
        before = _stat_identity(path)
        if not stat.S_ISREG(before[2]) or before[8] != 1:
            fail("identity evidence must be a singly-linked regular file")
        if before[5] <= 0 or before[5] > maximum:
            fail("identity evidence file exceeds its size bound or is empty")
        # NONBLOCK closes the regular-file-to-FIFO opening race. It has no
        # effect on ordinary regular-file reads. All allocations are bounded.
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise IdentityEvidenceError(f"cannot open identity evidence: {exc}") from exc
        try:
            if _metadata_identity(os.fstat(descriptor)) != before:
                fail("identity evidence changed while opening")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(maximum + 1)
            if (
                len(data) != before[5]
                or len(data) > maximum
                or _metadata_identity(os.fstat(descriptor)) != before
            ):
                fail("identity evidence changed while reading")
        except OSError as exc:
            raise IdentityEvidenceError(f"cannot read identity evidence: {exc}") from exc
        finally:
            os.close(descriptor)
        if _stat_identity(path) != before:
            fail("identity evidence changed while being read")
        record = _file_record(path.name, data)
        previous = self.files.get(path)
        current = (maximum, before, record)
        if previous is not None and previous != current:
            fail("identity evidence changed during verification")
        self.files[path] = current
        return data

    def record(self, path: Path, maximum: int) -> dict[str, Any]:
        data = self.read(path, maximum)
        return _file_record(path.name, data)

    def document(self, path: Path) -> dict[str, Any]:
        return signatures.decode_json(self.read(path, signatures.MAX_JSON_BYTES), path.name)

    def recheck(self) -> None:
        for path, (maximum, _, _) in tuple(self.files.items()):
            self.read(path, maximum)
        for root, (files, directories, _) in tuple(self.directories.items()):
            self.directory(root, files, directories)


def checksum_view(records: list[dict[str, Any]]) -> bytes:
    """Serialize an already validated inventory in canonical filename order."""
    return "".join(
        f"{record['sha256']}  {record['name']}\n"
        for record in sorted(records, key=lambda item: item["name"])
    ).encode("ascii")


def _inventory(
    files: _ObservedFiles, root: Path, release: str,
) -> dict[str, Any]:
    coordinates = identity_coordinates(release)
    files.directory(root, {c.filename for c in coordinates} | {"SHA256SUMS"}, set())
    records = [
        {"coordinate": asdict(c), "file": files.record(root / c.filename, signatures.MAX_PACKAGE_BYTES)}
        for c in coordinates
    ]
    if files.read(root / "SHA256SUMS", legacy.MAX_MANIFEST_BYTES) != checksum_view(
        [record["file"] for record in records]
    ):
        fail("unsigned six-package checksum view is not exact")
    return {
        "schema_version": 2, "profile": INVENTORY_PROFILE,
        "release": release, "artifacts": records,
    }


def build_inventory(root: Path, release: str) -> dict[str, Any]:
    """Read exact unsigned files without creating evidence or asserting trust."""
    files = _ObservedFiles()
    result = _inventory(files, root, release)
    files.recheck()
    return result


@dataclass(frozen=True)
class NativeVerificationRequest:
    coordinate: Coordinate
    package: Path
    package_sha256: str
    signature: Path | None
    signature_sha256: str | None
    policy_path: Path
    policy_sha256: str
    key_id: str
    as_of: dt.date


@dataclass(frozen=True)
class NativeVerificationResult:
    coordinate: Coordinate
    package_sha256: str
    policy_sha256: str
    key_id: str
    signature_sha256: str | None = None
    signature_created_at: str | None = None


NativeVerifier = Callable[[NativeVerificationRequest], NativeVerificationResult]


@dataclass(frozen=True)
class NativeTools:
    """Executables selected by trusted caller code, never by evidence JSON."""

    rpmkeys: str
    gpg: str
    gpgv: str
    apk: str
    openssl: str


def _policy(
    path: Path, expected_digest: str, day: dt.date, key_ids: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _digest(expected_digest, "committed policy digest")
    signatures.exact_keys(key_ids, set(FAMILIES), "caller-selected keys")
    raw = signatures.regular_bytes(path, signatures.MAX_JSON_BYTES, "committed policy")
    if _hash(raw) != expected_digest:
        fail("committed policy digest does not match")
    policy = signatures.decode_json(raw, "committed policy")
    if type(policy.get("schema_version")) is not int:
        fail("committed policy schema version must be an integer")
    signatures.validate_policy(policy, day)
    keys = {}
    for family in FAMILIES:
        identifier = key_ids[family]
        if not isinstance(identifier, str) or signatures.KEY_ID.fullmatch(identifier) is None:
            fail("caller-selected key ID is invalid")
        key = signatures.select_verification_key(policy, family, identifier, day, "qualification", False)
        signatures.key_path(path, key)
        keys[family] = key
    return policy, keys


def native_verifier(tools: NativeTools) -> NativeVerifier:
    """Adapt the existing offline native verifiers; no success is inferred."""
    if type(tools) is not NativeTools or any(
        not isinstance(value, str) or not Path(value).is_absolute()
        for value in asdict(tools).values()
    ):
        fail("native verifier requires explicit absolute executable paths")

    def verify(request: NativeVerificationRequest) -> NativeVerificationResult:
        coordinate = request.coordinate
        if coordinate not in identity_coordinates("v" + coordinate.version):
            fail("native verifier request coordinate is unsupported")
        if request.package.name != coordinate.filename:
            fail("native verifier package filename does not match coordinate")
        raw = signatures.regular_bytes(request.policy_path, signatures.MAX_JSON_BYTES, "committed policy")
        if _hash(raw) != _digest(request.policy_sha256, "committed policy digest"):
            fail("native verifier policy changed")
        policy = signatures.decode_json(raw, "committed policy")
        if type(policy.get("schema_version")) is not int:
            fail("committed policy schema version must be an integer")
        signatures.validate_policy(policy, request.as_of)
        signatures.select_verification_key(
            policy, coordinate.family, request.key_id, request.as_of, "qualification", False,
        )
        observed = _ObservedFiles()
        record = observed.record(request.package, signatures.MAX_PACKAGE_BYTES)
        if record["sha256"] != _digest(request.package_sha256, "bound package digest"):
            fail("native verifier package digest changed")
        created_at = None
        if coordinate.family == "deb":
            if request.signature is None or request.signature.name != coordinate.filename + ".asc":
                fail("DEB native verifier requires the identity-specific signature")
            signature = observed.record(request.signature, signatures.MAX_DEB_SIGNATURE_BYTES)
            if signature["sha256"] != _digest(request.signature_sha256, "bound signature digest"):
                fail("native verifier detached signature digest changed")
            data, created_at = signatures.verify_deb(
                policy, request.policy_path, request.package, request.signature,
                request.key_id, tools.gpg, tools.gpgv, request.as_of,
            )
            if _hash(data) != request.signature_sha256:
                fail("native verifier returned a different detached signature")
        else:
            if request.signature is not None or request.signature_sha256 is not None:
                fail("only DEB supports detached signature records")
            if coordinate.family == "rpm":
                signatures.verify_rpm(
                    policy, request.policy_path, request.package, request.key_id,
                    tools.rpmkeys, tools.gpg, request.as_of,
                )
            else:
                image = os.environ.get("SYSWARDEN_APK_SIGNER_IMAGE")
                if image is not None and image != policy["apk"]["signer_image"]:
                    fail("APK verifier image does not match committed policy")
                signatures.verify_apk(
                    policy, request.policy_path, request.package, request.key_id,
                    tools.apk, tools.openssl, request.as_of,
                )
        observed.recheck()
        if signatures.regular_bytes(request.policy_path, signatures.MAX_JSON_BYTES, "committed policy") != raw:
            fail("native verifier policy changed during verification")
        return NativeVerificationResult(
            coordinate, request.package_sha256, request.policy_sha256,
            request.key_id, request.signature_sha256, created_at,
        )

    return verify


def _timestamp(value: object, day: dt.date) -> str:
    if not isinstance(value, str) or STAMP.fullmatch(value) is None:
        fail("DEB signature creation time is not canonical UTC")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise IdentityEvidenceError("DEB signature creation time is invalid") from exc
    if parsed.date() != day:
        fail("DEB signature creation day does not match qualification")
    return value


def _verification(
    document: dict[str, Any], coordinate: Coordinate, record: dict[str, Any],
    signature: dict[str, Any] | None, release: str, release_sha: str,
    policy_digest: str, day: dt.date, policy: dict[str, Any], key: dict[str, Any],
) -> str | None:
    created_at = None
    expected_signature = None
    if signature is not None:
        part = signatures.exact_keys(document.get("signature"), {"file", "created_at"}, "DEB verification signature")
        created_at = _timestamp(part["created_at"], day)
        expected_signature = {"file": signature, "created_at": created_at}
    _equal(document, {
        "schema_version": 2, "profile": VERIFICATION_PROFILE,
        "purpose": "qualification", "status": "verified", "release": release,
        "release_sha": release_sha, "coordinate": asdict(coordinate),
        "as_of": day.isoformat(), "policy_sha256": policy_digest,
        "mechanism": policy[coordinate.family]["mechanism"],
        "key": {field: key[field] for field in KEY_FIELDS},
        "package": record, "signature": expected_signature,
    }, "identity-specific native verification")
    return created_at


def _rpm_proof(
    document: dict[str, Any], coordinate: Coordinate,
    unsigned: dict[str, Any], signed: dict[str, Any], release: str, release_sha: str,
) -> None:
    if unsigned["sha256"] == signed["sha256"]:
        fail("RPM signature transformation did not change the original package")
    fields = {"file", "immutable_header_sha256", "payload_cpio_sha256"}
    before = signatures.exact_keys(document.get("unsigned"), fields, "unsigned RPM proof")
    after = signatures.exact_keys(document.get("signed"), fields, "signed RPM proof")
    header = _digest(before["immutable_header_sha256"], "RPM immutable header digest")
    payload = _digest(before["payload_cpio_sha256"], "RPM payload digest")
    _equal(document, {
        "schema_version": 2, "profile": RPM_PROOF_PROFILE,
        "purpose": "qualification", "status": "preserved", "release": release,
        "release_sha": release_sha, "coordinate": asdict(coordinate),
        "unsigned": {"file": unsigned, "immutable_header_sha256": header, "payload_cpio_sha256": payload},
        "signed": {"file": signed, "immutable_header_sha256": header, "payload_cpio_sha256": payload},
    }, "identity-specific RPM preservation proof")
    _equal(after["file"], signed, "signed RPM full-file binding")


def _apk_transformation(
    files: _ObservedFiles, path: Path, coordinate: Coordinate,
    unsigned: dict[str, Any], signed: dict[str, Any],
    key: dict[str, Any], source_date_epoch: int,
) -> dict[str, Any]:
    prefix_size = signed["size"] - unsigned["size"]
    if not 0 < prefix_size <= legacy.MAX_APK_SIGNATURE_PREFIX_BYTES:
        fail("APK signature prefix size is unsupported")
    data = files.read(path, signatures.MAX_PACKAGE_BYTES)
    prefix = data[:prefix_size]
    try:
        entry, signature = legacy.validate_apk_signature_archive(
            prefix, key["public_key"], source_date_epoch,
        )
    except zlib.error as exc:
        raise IdentityEvidenceError("APK signature gzip stream is invalid") from exc
    # A view avoids allocating a second package-sized buffer. The original
    # record was computed from the actual, separately observed unsigned file.
    suffix = memoryview(data)[prefix_size:]
    if len(suffix) != unsigned["size"] or hashlib.sha256(suffix).hexdigest() != unsigned["sha256"]:
        fail("APK signing did not preserve the exact unsigned suffix")
    return {
        "coordinate": asdict(coordinate), "unsigned": unsigned, "signed": signed,
        "exact_unsigned_suffix": True, "signature_entry": entry,
        "signature_prefix": {"size": prefix_size, "sha256": _hash(prefix)},
        "signature_sha256": _hash(signature),
        "key": {field: key[field] for field in KEY_FIELDS},
    }


def verify_qualification_bundle(
    root: Path, unsigned_root: Path, *, release: str, release_sha: str,
    expected_seal_sha256: str, policy_path: Path, expected_policy_sha256: str,
    as_of: str, source_date_epoch: int, key_ids: dict[str, str], native_verifier: NativeVerifier,
    purpose: str = "qualification",
) -> dict[str, Any]:
    """Validate sealed files and reverify six signatures with explicit authority.

    RPM payload equality is accepted only as an externally authenticated proof
    bound to the exact original and signed files. This is not native metadata,
    retention, lifecycle, RHEL, updater, or public-release qualification.
    """
    coordinates = identity_coordinates(release)
    if purpose != "qualification":
        fail("v5 publishing remains closed")
    if not callable(native_verifier):
        fail("a trusted native verifier is required")
    if not isinstance(release_sha, str) or COMMIT.fullmatch(release_sha) is None:
        fail("caller-selected release commit is invalid")
    _digest(expected_seal_sha256, "authenticated seal digest")
    day = signatures.parse_day(as_of, "qualification date")
    if day.isoformat() != as_of:
        fail("qualification date must be canonical")
    latest_epoch = int(dt.datetime.combine(day, dt.time.max, dt.timezone.utc).timestamp())
    if type(source_date_epoch) is not int or not 0 < source_date_epoch <= latest_epoch:
        fail("caller-selected source date epoch is invalid or later than qualification")
    policy, keys = _policy(policy_path, expected_policy_sha256, day, key_ids)
    files = _ObservedFiles()
    if files.record(policy_path, signatures.MAX_JSON_BYTES)["sha256"] != expected_policy_sha256:
        fail("committed policy changed before evidence observation")
    for key in keys.values():
        path, _ = signatures.key_path(policy_path, key)
        if files.record(path, signatures.MAX_KEY_BYTES)["sha256"] != key["public_key_sha256"]:
            fail("committed public key changed before evidence observation")
    files.directory(root, {SEAL_NAME, MANIFEST_CHECKSUM_NAME}, {"packages", "evidence"})
    seal_bytes = files.read(root / SEAL_NAME, signatures.MAX_JSON_BYTES)
    if _hash(seal_bytes) != expected_seal_sha256:
        fail("identity evidence seal is not authenticated by the caller")
    seal = signatures.decode_json(seal_bytes, "identity evidence seal")
    unsigned = _inventory(files, unsigned_root, release)
    packages, evidence = root / "packages", root / "evidence"
    detached = {c.filename + ".asc" for c in coordinates if c.family == "deb"}
    files.directory(packages, {c.filename for c in coordinates} | detached | {"SHA256SUMS"}, set())
    files.directory(evidence, {c.verification_name for c in coordinates} | {
        c.rpm_proof_name for c in coordinates if c.family == "rpm"
    }, set())
    signed_records, verification_records, proof_records, signature_records = [], [], [], []
    apk_transformations = []
    verification_results = []
    for index, coordinate in enumerate(coordinates):
        record = files.record(packages / coordinate.filename, signatures.MAX_PACKAGE_BYTES)
        signed_records.append({"coordinate": asdict(coordinate), "file": record})
        original = unsigned["artifacts"][index]["file"]
        signature = None
        if coordinate.family == "deb":
            _equal(record, original, "DEB signing must preserve exact original package bytes")
            signature = files.record(packages / (coordinate.filename + ".asc"), signatures.MAX_DEB_SIGNATURE_BYTES)
            signature_records.append({"coordinate": asdict(coordinate), "file": signature})
        verification_path = evidence / coordinate.verification_name
        verification = files.document(verification_path)
        verification_records.append(files.record(verification_path, signatures.MAX_JSON_BYTES))
        created_at = _verification(
            verification, coordinate, record, signature, release, release_sha,
            expected_policy_sha256, day, policy, keys[coordinate.family],
        )
        if coordinate.family == "rpm":
            proof_path = evidence / coordinate.rpm_proof_name
            _rpm_proof(files.document(proof_path), coordinate, original, record, release, release_sha)
            proof_records.append(files.record(proof_path, signatures.MAX_JSON_BYTES))
        elif coordinate.family == "apk":
            apk_transformations.append(_apk_transformation(
                files, packages / coordinate.filename, coordinate, original, record,
                keys["apk"], source_date_epoch,
            ))
        verification_results.append((coordinate, record, signature, created_at))
    signed_files = [item["file"] for item in signed_records]
    sealed_files = signed_files + [item["file"] for item in signature_records]
    if files.read(packages / "SHA256SUMS", legacy.MAX_MANIFEST_BYTES) != checksum_view(sealed_files):
        fail("signed eight-file checksum view is not exact")
    if files.read(root / MANIFEST_CHECKSUM_NAME, legacy.MAX_MANIFEST_BYTES) != checksum_view(signed_files):
        fail("manifest six-package checksum view is not exact")
    _equal(seal, {
        "schema_version": 2, "profile": PROFILE, "purpose": "qualification",
        "package_role": "standard", "release": release, "release_sha": release_sha,
        "as_of": as_of, "source_date_epoch": source_date_epoch,
        "policy_sha256": expected_policy_sha256,
        "unsigned_inventory": unsigned, "signed_inventory": signed_records,
        "verifications": verification_records, "rpm_proofs": proof_records,
        "deb_signatures": signature_records,
        "apk_transformations": apk_transformations,
        "signed_checksums": files.record(packages / "SHA256SUMS", legacy.MAX_MANIFEST_BYTES),
        "manifest_checksums": files.record(root / MANIFEST_CHECKSUM_NAME, legacy.MAX_MANIFEST_BYTES),
    }, "authenticated identity evidence seal")
    # Validate the entire graph before invoking any verifier. Keep one package
    # staged at a time; native tools only see copies in this private directory.
    for coordinate, record, signature, created_at in verification_results:
        with tempfile.TemporaryDirectory(prefix="syswarden-v5-identity-") as temporary:
            stage = Path(temporary)
            package = signatures.stage_bound_package(
                stage, record["name"], files.read(packages / record["name"], signatures.MAX_PACKAGE_BYTES),
            )
            signature_path = None
            if signature is not None:
                signature_path = signatures.stage_bound_package(
                    stage, signature["name"], files.read(packages / signature["name"], signatures.MAX_DEB_SIGNATURE_BYTES),
                )
            staged = _ObservedFiles()
            _equal(staged.record(package, signatures.MAX_PACKAGE_BYTES), record, "staged package")
            if signature_path is not None:
                _equal(staged.record(signature_path, signatures.MAX_DEB_SIGNATURE_BYTES), signature, "staged signature")
            request = NativeVerificationRequest(
                coordinate, package, record["sha256"], signature_path,
                signature["sha256"] if signature else None, policy_path,
                expected_policy_sha256, keys[coordinate.family]["id"], day,
            )
            result = native_verifier(request)
            expected = NativeVerificationResult(
                coordinate, record["sha256"], expected_policy_sha256,
                request.key_id, request.signature_sha256, created_at,
            )
            if type(result) is not NativeVerificationResult or result != expected:
                fail("native verifier result is not bound to the exact request")
            staged.recheck()
            files.record(packages / record["name"], signatures.MAX_PACKAGE_BYTES)
            if signature is not None:
                files.record(packages / signature["name"], signatures.MAX_DEB_SIGNATURE_BYTES)
    files.recheck()
    return {
        "schema_version": 2, "profile": SUMMARY_PROFILE, "purpose": "qualification",
        "status": "native-signatures-reverified-not-release-qualified",
        "release": release, "release_sha": release_sha,
        "seal_sha256": expected_seal_sha256, "policy_sha256": expected_policy_sha256,
        "as_of": as_of, "source_date_epoch": source_date_epoch,
        "artifacts": signed_records, "deb_signatures": signature_records,
        "apk_transformations": apk_transformations,
        "rpm_preservation": "caller-authenticated-full-file-bound-proofs",
        "native_metadata": "caller-authenticated-build-inventory",
        "publishing": False,
    }


def write_qualification_summary(
    output: Path, root: Path, unsigned_root: Path, **arguments: Any,
) -> dict[str, Any]:
    """No output is created until every file, proof and signature is verified."""
    for input_root in (root, unsigned_root):
        if output.absolute().is_relative_to(input_root.absolute()):
            fail("qualification summary must be outside its sealed inputs")
    result = verify_qualification_bundle(root, unsigned_root, **arguments)
    signatures.write_json_exclusive(output, result)
    return result
