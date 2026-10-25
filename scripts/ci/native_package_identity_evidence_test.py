#!/usr/bin/env python3
"""Schema-2 component tests and a separate real detached-signature adapter test.

Synthetic package bytes and injected callbacks prove binding and refusal only.
They do not qualify package formats, native signatures, or release publication.
"""

from __future__ import annotations

import copy
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_package_identity_evidence as evidence
    from scripts.ci import native_package_signature_gate as signatures
    from scripts.ci import native_package_signing_bundle as legacy
except ModuleNotFoundError:
    import native_package_identity_evidence as evidence
    import native_package_signature_gate as signatures
    import native_package_signing_bundle as legacy


ERRORS = (evidence.IdentityEvidenceError, legacy.SigningBundleError)
RELEASE = "v5.00.0"
RELEASE_SHA = "a" * 40
DAY = "2026-10-25"
CREATED_AT = "2026-10-25T00:00:00Z"
SOURCE_DATE_EPOCH = int(dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc).timestamp())


def record(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"name": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def apk_prefix(public_key: str, epoch: int = SOURCE_DATE_EPOCH, payload: bytes = b"s" * 512) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo(".SIGN.RSA256." + Path(public_key).name)
        entry.size, entry.mode, entry.mtime = len(payload), 0o644, epoch
        entry.pax_headers = {"atime": "0", "ctime": "0"}
        archive.addfile(entry, io.BytesIO(payload))
    return gzip.compress(stream.getvalue(), compresslevel=9, mtime=0)


class IdentityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.unsigned = self.root / "unsigned"
        self.bundle = self.root / "bundle"
        self.packages = self.bundle / "packages"
        self.proofs = self.bundle / "evidence"
        for directory in (self.unsigned, self.bundle, self.packages, self.proofs):
            directory.mkdir(mode=0o700)
        self.coordinates = evidence.identity_coordinates(RELEASE)
        # Public repository trust roots are read-only fixtures. The synthetic
        # callback below supplies no cryptographic qualification for them.
        self.policy_path = Path(signatures.__file__).with_name("native_package_signature_policy_v4100.json")
        self.policy = json.loads(self.policy_path.read_bytes())
        self.policy_digest = record(self.policy_path)["sha256"]
        self.keys = {family: self.policy[family]["trusted_keys"][0] for family in evidence.FAMILIES}
        self.key_ids = {family: key["id"] for family, key in self.keys.items()}
        self.calls = []
        self.expected_signatures = {}
        for coordinate in self.coordinates:
            original = f"synthetic unsigned {coordinate.filename}\n".encode("ascii")
            signed = original if coordinate.family == "deb" else b"synthetic signed\n" + original
            if coordinate.family == "apk":
                original = gzip.compress(original, mtime=0)
                signed = apk_prefix(self.keys["apk"]["public_key"]) + original
            (self.unsigned / coordinate.filename).write_bytes(original)
            (self.packages / coordinate.filename).write_bytes(signed)
            signature = None
            if coordinate.family == "deb":
                detached = f"synthetic signature for {coordinate.filename}\n".encode("ascii")
                path = self.packages / (coordinate.filename + ".asc")
                path.write_bytes(detached)
                signature = {"file": record(path), "created_at": CREATED_AT}
                self.expected_signatures[coordinate.package_name] = detached
            write_json(self.proofs / coordinate.verification_name, {
                "schema_version": 2, "profile": evidence.VERIFICATION_PROFILE,
                "purpose": "qualification", "status": "verified", "release": RELEASE,
                "release_sha": RELEASE_SHA, "coordinate": asdict(coordinate),
                "as_of": DAY, "policy_sha256": self.policy_digest,
                "mechanism": self.policy[coordinate.family]["mechanism"],
                "key": {field: self.keys[coordinate.family][field] for field in evidence.KEY_FIELDS},
                "package": record(self.packages / coordinate.filename), "signature": signature,
            })
            if coordinate.family == "rpm":
                digest = hashlib.sha256(coordinate.package_name.encode("ascii")).hexdigest()
                write_json(self.proofs / coordinate.rpm_proof_name, {
                    "schema_version": 2, "profile": evidence.RPM_PROOF_PROFILE,
                    "purpose": "qualification", "status": "preserved", "release": RELEASE,
                    "release_sha": RELEASE_SHA, "coordinate": asdict(coordinate),
                    "unsigned": {"file": record(self.unsigned / coordinate.filename), "immutable_header_sha256": digest, "payload_cpio_sha256": "b" * 64},
                    "signed": {"file": record(self.packages / coordinate.filename), "immutable_header_sha256": digest, "payload_cpio_sha256": "b" * 64},
                })
        self.refresh_checksums()
        self.reseal()

    def refresh_checksums(self) -> None:
        unsigned = [record(self.unsigned / c.filename) for c in self.coordinates]
        signed = [record(self.packages / c.filename) for c in self.coordinates]
        signatures_ = [record(self.packages / (c.filename + ".asc")) for c in self.coordinates if c.family == "deb"]
        (self.unsigned / "SHA256SUMS").write_bytes(evidence.checksum_view(unsigned))
        (self.packages / "SHA256SUMS").write_bytes(evidence.checksum_view(signed + signatures_))
        (self.bundle / evidence.MANIFEST_CHECKSUM_NAME).write_bytes(evidence.checksum_view(signed))

    def reseal(self, *, apk_transformations: list[dict[str, object]] | None = None) -> None:
        """Re-anchor fixtures to exercise checks even with authenticated bad input."""
        self.seal = {
            "schema_version": 2, "profile": evidence.PROFILE, "purpose": "qualification",
            "package_role": "standard", "release": RELEASE, "release_sha": RELEASE_SHA,
            "as_of": DAY, "source_date_epoch": SOURCE_DATE_EPOCH, "policy_sha256": self.policy_digest,
            "unsigned_inventory": evidence.build_inventory(self.unsigned, RELEASE),
            "signed_inventory": [{"coordinate": asdict(c), "file": record(self.packages / c.filename)} for c in self.coordinates],
            "verifications": [record(self.proofs / c.verification_name) for c in self.coordinates],
            "rpm_proofs": [record(self.proofs / c.rpm_proof_name) for c in self.coordinates if c.family == "rpm"],
            "deb_signatures": [{"coordinate": asdict(c), "file": record(self.packages / (c.filename + ".asc"))} for c in self.coordinates if c.family == "deb"],
            "apk_transformations": apk_transformations if apk_transformations is not None else [
                evidence._apk_transformation(
                    evidence._ObservedFiles(), self.packages / c.filename, c,
                    record(self.unsigned / c.filename), record(self.packages / c.filename),
                    self.keys["apk"], SOURCE_DATE_EPOCH,
                ) for c in self.coordinates if c.family == "apk"
            ],
            "signed_checksums": record(self.packages / "SHA256SUMS"),
            "manifest_checksums": record(self.bundle / evidence.MANIFEST_CHECKSUM_NAME),
        }
        self.write_seal()

    def write_seal(self) -> None:
        write_json(self.bundle / evidence.SEAL_NAME, self.seal)
        self.seal_digest = record(self.bundle / evidence.SEAL_NAME)["sha256"]

    def component_verifier(self, request: evidence.NativeVerificationRequest) -> evidence.NativeVerificationResult:
        self.calls.append(request.coordinate)
        self.assertNotEqual(request.package.parent, self.packages)
        self.assertEqual(request.package.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(record(request.package)["sha256"], request.package_sha256)
        if request.signature is not None:
            if request.signature.read_bytes() != self.expected_signatures[request.coordinate.package_name]:
                raise evidence.IdentityEvidenceError("component signature is bound to another package")
        return evidence.NativeVerificationResult(
            request.coordinate, request.package_sha256, request.policy_sha256,
            request.key_id, request.signature_sha256,
            CREATED_AT if request.signature is not None else None,
        )

    def arguments(self, **changes: object) -> dict[str, object]:
        values = {
            "release": RELEASE, "release_sha": RELEASE_SHA,
            "expected_seal_sha256": self.seal_digest,
            "policy_path": self.policy_path, "expected_policy_sha256": self.policy_digest,
            "as_of": DAY, "source_date_epoch": SOURCE_DATE_EPOCH,
            "key_ids": self.key_ids, "native_verifier": self.component_verifier,
        }
        values.update(changes)
        return values

    def verify(self, **changes: object) -> dict[str, object]:
        return evidence.verify_qualification_bundle(self.bundle, self.unsigned, **self.arguments(**changes))

    def refuse_without_output(self, **changes: object) -> None:
        output = self.root / "summary.json"
        with self.assertRaises(ERRORS):
            evidence.write_qualification_summary(output, self.bundle, self.unsigned, **self.arguments(**changes))
        self.assertFalse(output.exists())

    def test_exact_six_coordinates_in_go_manifest_order(self) -> None:
        self.assertEqual([(c.package_name, c.family) for c in self.coordinates], [
            (name, family) for name in ("syswarden", "syswarden-base") for family in ("deb", "rpm", "apk")
        ])
        for version in ("v5.00.0", "v5.01.0", "v5.00.1", "v5.99.12", "v5.00.2147483647"):
            self.assertEqual(len(evidence.identity_coordinates(version)), 6)
        for version in ("v4.10.4", "v6.00.0", "v5.0.0", "v5.00.00", "5.00.0", "v5.00.0-rc1", "v5.00.0\n", "v5.00.2147483648", "v5.00." + "9" * 5000):
            with self.subTest(version=version), self.assertRaises(evidence.IdentityEvidenceError):
                evidence.identity_coordinates(version)

    def test_component_success_has_six_callbacks_and_no_publication_authority(self) -> None:
        before = {path: (path.read_bytes(), path.stat()) for directory in (self.unsigned, self.packages, self.proofs) for path in directory.iterdir()}
        summary = self.verify()
        self.assertEqual(self.calls, list(self.coordinates))
        self.assertEqual(len(summary["artifacts"]), 6)
        self.assertEqual(len(summary["deb_signatures"]), 2)
        self.assertIs(summary["publishing"], False)
        self.assertEqual(summary["status"], "native-signatures-reverified-not-release-qualified")
        for path, (raw, metadata) in before.items():
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual((path.stat().st_ino, path.stat().st_mode, path.stat().st_mtime_ns), (metadata.st_ino, metadata.st_mode, metadata.st_mtime_ns))
        self.assertEqual(len((self.packages / "SHA256SUMS").read_text().splitlines()), 8)
        self.assertEqual(len((self.bundle / evidence.MANIFEST_CHECKSUM_NAME).read_text().splitlines()), 6)

    def test_no_verifier_or_untrusted_anchors_refuse_before_callback_and_output(self) -> None:
        for changes in (
            {"native_verifier": None}, {"native_verifier": {"status": "verified"}},
            {"expected_seal_sha256": "0" * 64}, {"expected_policy_sha256": "0" * 64},
            {"key_ids": {"deb": "foreign", "rpm": self.key_ids["rpm"], "apk": self.key_ids["apk"]}},
            {"key_ids": {}}, {"purpose": "publishing"}, {"release": "v4.10.4"},
            {"release": "v6.00.0"}, {"release_sha": "b" * 40}, {"as_of": "20261025"},
            {"source_date_epoch": True}, {"source_date_epoch": 0}, {"source_date_epoch": -1},
            {"source_date_epoch": 99999999999},
        ):
            with self.subTest(changes=changes):
                self.refuse_without_output(**changes)
                self.assertEqual(self.calls, [])

    def test_seal_rejects_schema_role_release_and_duplicate_coordinates(self) -> None:
        original = copy.deepcopy(self.seal)
        for mutate in (
            lambda d: d.update(schema_version=1), lambda d: d.update(schema_version=True),
            lambda d: d.update(package_role="rhel-package-owned"),
            lambda d: d.update(purpose="publishing"), lambda d: d.update(release="v5.00.1"),
            lambda d: d["signed_inventory"].__setitem__(3, copy.deepcopy(d["signed_inventory"][0])),
            lambda d: d["unsigned_inventory"]["artifacts"][0]["coordinate"].update(architecture="arm64"),
            lambda d: d["signed_inventory"][0]["file"].update(size=True),
            lambda d: d["verifications"].reverse(),
            lambda d: d["deb_signatures"].pop(),
            lambda d: d.update(verifier="untrusted-plugin"),
        ):
            with self.subTest(mutate=mutate):
                self.seal = copy.deepcopy(original)
                mutate(self.seal)
                self.write_seal()
                self.refuse_without_output()
                self.assertEqual(self.calls, [])

    def test_duplicate_json_keys_refuse_even_with_matching_anchor(self) -> None:
        for path in (self.bundle / evidence.SEAL_NAME, self.proofs / self.coordinates[0].verification_name):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original.replace(b'"schema_version": 2', b'"schema_version": 2, "schema_version": 2', 1))
                if path.name == evidence.SEAL_NAME:
                    self.seal_digest = record(path)["sha256"]
                else:
                    self.reseal()
                self.refuse_without_output()
                self.assertEqual(self.calls, [])
                path.write_bytes(original)
                self.reseal()

    def test_same_key_cross_package_verification_swap_refuses(self) -> None:
        for family in evidence.FAMILIES:
            left, right = [c for c in self.coordinates if c.family == family]
            left_path, right_path = self.proofs / left.verification_name, self.proofs / right.verification_name
            first, second = left_path.read_bytes(), right_path.read_bytes()
            left_path.write_bytes(second)
            right_path.write_bytes(first)
            self.reseal()
            with self.subTest(family=family):
                self.refuse_without_output()
                self.assertEqual(self.calls, [])
            left_path.write_bytes(first)
            right_path.write_bytes(second)
        self.reseal()

    def test_same_key_cross_package_rpm_proof_swap_and_full_file_rebinding_refuse(self) -> None:
        left, right = [c for c in self.coordinates if c.family == "rpm"]
        path = self.proofs / left.rpm_proof_name
        original = path.read_bytes()
        donor = json.loads((self.proofs / right.rpm_proof_name).read_bytes())
        for mutate in (
            lambda d: None,
            lambda d: d.update(coordinate=asdict(left)),
        ):
            document = copy.deepcopy(donor)
            mutate(document)
            write_json(path, document)
            self.reseal()
            self.refuse_without_output()
            self.assertEqual(self.calls, [])
        path.write_bytes(original)
        for side in ("unsigned", "signed"):
            document = json.loads(original)
            document[side]["file"]["sha256"] = "0" * 64
            write_json(path, document)
            self.reseal()
            self.refuse_without_output()
        path.write_bytes(original)

    def test_rpm_proof_requires_same_payload_schema_and_release(self) -> None:
        coordinate = next(c for c in self.coordinates if c.family == "rpm")
        path = self.proofs / coordinate.rpm_proof_name
        original = json.loads(path.read_bytes())
        for mutate in (
            lambda d: d.update(schema_version=1),
            lambda d: d.update(profile=legacy.RPM_PROOF_PROFILE),
            lambda d: d.update(release="v5.00.1"),
            lambda d: d["signed"].update(payload_cpio_sha256="0" * 64),
            lambda d: d["signed"].update(immutable_header_sha256="0" * 64),
            lambda d: d["unsigned"].pop("file"),
        ):
            document = copy.deepcopy(original)
            mutate(document)
            write_json(path, document)
            self.reseal()
            self.refuse_without_output()
            self.assertEqual(self.calls, [])

    def test_rpm_signature_transformation_must_change_both_original_package_identities(self) -> None:
        for coordinate in self.coordinates:
            if coordinate.family != "rpm":
                continue
            with self.subTest(package=coordinate.package_name):
                unsigned_path = self.unsigned / coordinate.filename
                proof_path = self.proofs / coordinate.rpm_proof_name
                original, original_proof = unsigned_path.read_bytes(), proof_path.read_bytes()
                unsigned_path.write_bytes((self.packages / coordinate.filename).read_bytes())
                proof = json.loads(original_proof)
                proof["unsigned"]["file"] = record(unsigned_path)
                write_json(proof_path, proof)
                self.refresh_checksums()
                self.reseal()
                self.refuse_without_output()
                self.assertEqual(self.calls, [])
                unsigned_path.write_bytes(original)
                proof_path.write_bytes(original_proof)
                self.refresh_checksums()
                self.reseal()

    def test_detached_signature_swap_refuses_even_when_provenance_rebound(self) -> None:
        left, right = [c for c in self.coordinates if c.family == "deb"]
        path = self.packages / (left.filename + ".asc")
        path.write_bytes((self.packages / (right.filename + ".asc")).read_bytes())
        # Even a trusted fixture seal cannot turn the wrong signature into a
        # successful native check. The component oracle checks its association.
        verification_path = self.proofs / left.verification_name
        document = json.loads(verification_path.read_bytes())
        document["signature"]["file"] = record(path)
        write_json(verification_path, document)
        self.refresh_checksums()
        self.reseal()
        self.refuse_without_output()
        self.assertEqual(self.calls, [left])

    def test_apk_preservation_rejects_changed_payload_and_unsafe_prefix_before_verifier(self) -> None:
        coordinate = next(c for c in self.coordinates if c.family == "apk")
        path = self.packages / coordinate.filename
        original_signed = path.read_bytes()
        unsigned = (self.unsigned / coordinate.filename).read_bytes()
        prefix = apk_prefix(self.keys["apk"]["public_key"])
        original_proofs = copy.deepcopy(self.seal["apk_transformations"])
        verification_path = self.proofs / coordinate.verification_name
        original_verification = json.loads(verification_path.read_bytes())
        changed_suffix = unsigned[:-1] + bytes([unsigned[-1] ^ 1])
        for signed in (
            prefix + changed_suffix,
            apk_prefix("foreign.rsa.pub") + unsigned,
            apk_prefix(self.keys["apk"]["public_key"], SOURCE_DATE_EPOCH + 1) + unsigned,
            apk_prefix(self.keys["apk"]["public_key"], payload=b"x" * 1025) + unsigned,
            prefix + prefix + unsigned,
            gzip.compress(b"x" * (64 * 1024 + 1), mtime=0) + unsigned,
            b"x" * (legacy.MAX_APK_SIGNATURE_PREFIX_BYTES + 1) + unsigned,
            prefix[:-4] + unsigned,
            unsigned,
        ):
            with self.subTest(size=len(signed), prefix=signed[:16]):
                path.write_bytes(signed)
                verification = copy.deepcopy(original_verification)
                verification["package"] = record(path)
                write_json(verification_path, verification)
                self.refresh_checksums()
                self.reseal(apk_transformations=original_proofs)
                self.refuse_without_output()
                self.assertEqual(self.calls, [])
        path.write_bytes(original_signed)
        write_json(verification_path, original_verification)

    def test_apk_exact_suffix_and_selected_key_records_are_sealed(self) -> None:
        original = copy.deepcopy(self.seal)
        for mutate in (
            lambda d: d["apk_transformations"].reverse(),
            lambda d: d["apk_transformations"][0].update(exact_unsigned_suffix=False),
            lambda d: d["apk_transformations"][0]["key"].update(id="foreign"),
            lambda d: d["apk_transformations"][0]["signature_prefix"].update(sha256="0" * 64),
            lambda d: d.update(source_date_epoch=SOURCE_DATE_EPOCH - 1),
        ):
            self.seal = copy.deepcopy(original)
            mutate(self.seal)
            self.write_seal()
            self.refuse_without_output()
            self.assertEqual(self.calls, [])

    def test_detached_signature_timestamps_must_match_actual_verifier(self) -> None:
        coordinate = self.coordinates[0]
        path = self.proofs / coordinate.verification_name
        original = json.loads(path.read_bytes())
        for timestamp in ("2027-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-09-09", "2026-09-08T00:00:00Z"):
            document = copy.deepcopy(original)
            document["signature"]["created_at"] = timestamp
            write_json(path, document)
            self.reseal()
            self.refuse_without_output()

    def test_entire_graph_is_validated_before_first_native_callback(self) -> None:
        path = self.proofs / self.coordinates[-1].verification_name
        document = json.loads(path.read_bytes())
        document["key"]["id"] = self.key_ids["rpm"]
        write_json(path, document)
        self.reseal()
        self.refuse_without_output()
        self.assertEqual(self.calls, [])

    def test_missing_foreign_extra_hardlink_symlink_and_fifo_inputs_refuse(self) -> None:
        for directory in (self.unsigned, self.packages, self.proofs):
            with self.subTest(directory=directory.name):
                extra = directory / "foreign-file"
                extra.write_bytes(b"foreign\n")
                self.refuse_without_output()
                extra.unlink()
        path = self.packages / self.coordinates[0].filename
        original = path.read_bytes()
        path.unlink()
        self.refuse_without_output()
        donor = self.root / "donor"
        donor.write_bytes(original)
        path.symlink_to(donor)
        self.refuse_without_output()
        path.unlink()
        os.link(donor, path)
        self.refuse_without_output()
        path.unlink()
        os.mkfifo(path)
        self.refuse_without_output()
        path.unlink()
        path.write_bytes(original)
        alias = self.root / "bundle-alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(ERRORS):
            evidence.verify_qualification_bundle(alias, self.unsigned, **self.arguments())
        self.assertEqual(self.calls, [])

    def test_eight_and_six_checksum_views_are_not_interchangeable(self) -> None:
        sealed = self.packages / "SHA256SUMS"
        manifest = self.bundle / evidence.MANIFEST_CHECKSUM_NAME
        old_sealed, old_manifest = sealed.read_bytes(), manifest.read_bytes()
        for path, raw in ((sealed, old_manifest), (manifest, old_sealed), (sealed, old_sealed + old_sealed.splitlines(keepends=True)[0])):
            with self.subTest(path=path.name, size=len(raw)):
                path.write_bytes(raw)
                self.reseal()
                self.refuse_without_output()
                self.assertEqual(self.calls, [])
                sealed.write_bytes(old_sealed)
                manifest.write_bytes(old_manifest)

    def test_wrong_boolean_or_cross_coordinate_callback_result_refuses(self) -> None:
        for transform in (
            lambda result: True, lambda result: {"status": "verified"}, lambda result: None,
            lambda result: replace(result, coordinate=self.coordinates[-1]),
            lambda result: replace(result, package_sha256="0" * 64),
            lambda result: replace(result, key_id="foreign"),
            lambda result: replace(result, policy_sha256="0" * 64),
            lambda result: replace(result, signature_sha256=None),
        ):
            with self.subTest(transform=transform):
                self.refuse_without_output(native_verifier=lambda request: transform(self.component_verifier(request)))

    def test_native_failure_creates_no_output_or_replaces_existing_output(self) -> None:
        def reject(request: evidence.NativeVerificationRequest) -> evidence.NativeVerificationResult:
            raise evidence.IdentityEvidenceError("synthetic verifier refused")
        self.refuse_without_output(native_verifier=reject)
        output = self.root / "summary.json"
        output.write_bytes(b"preserve existing output\n")
        before = output.stat()
        with self.assertRaises(ERRORS):
            evidence.write_qualification_summary(output, self.bundle, self.unsigned, **self.arguments(native_verifier=reject))
        self.assertEqual(output.read_bytes(), b"preserve existing output\n")
        self.assertEqual(output.stat().st_ino, before.st_ino)

    def test_byte_and_inode_changes_during_native_verification_refuse(self) -> None:
        for replace_inode in (False, True):
            for target_kind in ("source", "staged", "evidence", "unsigned"):
                with self.subTest(replace_inode=replace_inode, target=target_kind):
                    changed = False
                    saved = {}
                    def mutate(request: evidence.NativeVerificationRequest) -> evidence.NativeVerificationResult:
                        nonlocal changed
                        result = self.component_verifier(request)
                        if not changed:
                            path = {
                                "source": self.packages / request.coordinate.filename,
                                "staged": request.package,
                                "evidence": self.proofs / request.coordinate.verification_name,
                                "unsigned": self.unsigned / request.coordinate.filename,
                            }[target_kind]
                            raw = path.read_bytes()
                            saved[path] = raw
                            if replace_inode:
                                replacement = path.with_name(path.name + ".replacement")
                                replacement.write_bytes(raw)
                                replacement.replace(path)
                            else:
                                path.write_bytes(raw + b"changed\n")
                            changed = True
                        return result
                    self.refuse_without_output(native_verifier=mutate)
                    for path, raw in saved.items():
                        if path.parent.exists():
                            path.write_bytes(raw)

    def test_successful_output_is_exclusive_and_protected(self) -> None:
        output = self.root / "summary.json"
        summary = evidence.write_qualification_summary(output, self.bundle, self.unsigned, **self.arguments())
        self.assertEqual(json.loads(output.read_bytes()), summary)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        raw, inode = output.read_bytes(), output.stat().st_ino
        with self.assertRaises(ERRORS):
            evidence.write_qualification_summary(output, self.bundle, self.unsigned, **self.arguments())
        self.assertEqual((output.read_bytes(), output.stat().st_ino), (raw, inode))

    def test_output_cannot_modify_sealed_input_inventory(self) -> None:
        for directory in (self.bundle, self.packages, self.unsigned):
            output = directory / "summary.json"
            with self.subTest(directory=directory.name), self.assertRaises(evidence.IdentityEvidenceError):
                evidence.write_qualification_summary(output, self.bundle, self.unsigned, **self.arguments())
            self.assertFalse(output.exists())
        self.assertEqual(self.calls, [])

    def test_reader_refuses_fifo_substitution_at_open_without_blocking(self) -> None:
        path = self.root / "raced-file"
        path.write_bytes(b"initial regular file\n")
        real_open = os.open
        def replace_before_open(target: Path, flags: int) -> int:
            self.assertEqual(target, path)
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            path.unlink()
            os.mkfifo(path)
            return real_open(target, flags)
        with mock.patch.object(evidence.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(evidence.IdentityEvidenceError, "changed while opening"):
                evidence._ObservedFiles().read(path, 1024)

    def test_adapter_requires_explicit_tools_and_checks_request_before_exec(self) -> None:
        with self.assertRaises(evidence.IdentityEvidenceError):
            evidence.native_verifier(evidence.NativeTools("rpmkeys", "gpg", "gpgv", "apk", "openssl"))
        verifier = evidence.native_verifier(evidence.NativeTools(*(["/nonexistent-native-tool"] * 5)))
        request = evidence.NativeVerificationRequest(
            self.coordinates[0], self.packages / self.coordinates[0].filename, "0" * 64,
            None, None, self.policy_path, self.policy_digest, self.key_ids["deb"], dt.date.fromisoformat(DAY),
        )
        with self.assertRaisesRegex(evidence.IdentityEvidenceError, "package digest changed"):
            verifier(request)


@unittest.skipUnless(
    shutil.which("gpg") and shutil.which("gpgv") and shutil.which("gpgconf"),
    "GnuPG tools are required for the real detached-signature adapter fixture",
)
class IdentityEvidenceRealCryptoTests(unittest.TestCase):
    def test_real_deb_adapter_accepts_both_names_and_refuses_same_key_signature_swap(self) -> None:
        # Generate only ephemeral synthetic signing material. This test invokes
        # real GnuPG, never a native package installation or network command.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            keys = root / "native-package-keys"
            keys.mkdir(mode=0o700)
            gpg, gpgv, gpgconf = (shutil.which(name) for name in ("gpg", "gpgv", "gpgconf"))
            environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            timestamp = int(dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc).timestamp())
            command = [gpg, "--batch", "--no-options", "--homedir", str(home), "--pinentry-mode", "loopback", "--passphrase", "", "--faked-system-time", str(timestamp)]
            def run(arguments: list[str]) -> bytes:
                try:
                    return subprocess.run(arguments, check=True, capture_output=True, timeout=60, env=environment).stdout
                except subprocess.CalledProcessError as error:
                    self.fail(f"synthetic GnuPG fixture command failed ({error.returncode}); stderr={error.stderr!r}")
                except subprocess.TimeoutExpired as error:
                    self.fail(f"synthetic GnuPG fixture command timed out; stderr={error.stderr!r}")
            try:
                run(command + ["--quick-generate-key", "SysWarden synthetic test <fixture@example.invalid>", "rsa3072", "sign", "0"])
                listing = run(command + ["--with-colons", "--list-keys"]).decode("ascii")
                fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                public = keys / "deb-fixture.asc"
                public.write_bytes(run(command + ["--armor", "--export", fingerprint]))
                policy_path = root / "policy.json"
                repository_policy = Path(signatures.__file__).with_name("native_package_signature_policy_v4100.json")
                policy = json.loads(repository_policy.read_bytes())
                policy["publishing"] = False
                policy["deb"]["trusted_keys"] = [{
                    "id": "deb-synthetic", "public_key": "native-package-keys/deb-fixture.asc",
                    "public_key_sha256": record(public)["sha256"], "fingerprint": fingerprint,
                    "valid_from": "2026-09-09", "valid_until": "2027-09-09",
                    "revoked": False, "supersedes": [],
                }]
                write_json(policy_path, policy)
                verifier = evidence.native_verifier(evidence.NativeTools("/unused/rpmkeys", gpg, gpgv, "/unused/apk", "/unused/openssl"))
                requests = []
                for coordinate in evidence.identity_coordinates(RELEASE):
                    if coordinate.family != "deb":
                        continue
                    package = root / coordinate.filename
                    package.write_bytes(f"synthetic detached-signature payload for {coordinate.package_name}\n".encode("ascii"))
                    detached = root / (coordinate.filename + ".asc")
                    run(command + ["--armor", "--digest-algo", "SHA256", "--local-user", fingerprint, "--output", str(detached), "--detach-sign", str(package)])
                    request = evidence.NativeVerificationRequest(
                        coordinate, package, record(package)["sha256"], detached,
                        record(detached)["sha256"], policy_path, record(policy_path)["sha256"],
                        "deb-synthetic", dt.date.fromisoformat(DAY),
                    )
                    result = verifier(request)
                    self.assertEqual(result.signature_created_at, CREATED_AT)
                    self.assertEqual(result.coordinate, coordinate)
                    requests.append(request)
                # Rebind the supplied hash too: real cryptography, rather than
                # a stale digest check, must reject the same-key cross-identity swap.
                requests[0].signature.write_bytes(requests[1].signature.read_bytes())
                swapped = replace(requests[0], signature_sha256=record(requests[0].signature)["sha256"])
                with self.assertRaises(evidence.IdentityEvidenceError):
                    verifier(swapped)
            finally:
                active_error = sys.exc_info()[1]
                try:
                    cleanup = subprocess.run([gpgconf, "--homedir", str(home), "--kill", "gpg-agent"], check=False, capture_output=True, timeout=15, env=environment)
                    if cleanup.returncode:
                        raise AssertionError(f"synthetic GnuPG fixture cleanup failed ({cleanup.returncode}); stderr={cleanup.stderr!r}")
                except (OSError, subprocess.TimeoutExpired, AssertionError) as error:
                    if active_error is None:
                        raise
                    active_error.add_note(f"synthetic GnuPG fixture cleanup also failed: {error}")


if __name__ == "__main__":
    unittest.main()
