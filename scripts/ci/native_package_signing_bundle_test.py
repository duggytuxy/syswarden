#!/usr/bin/env python3
"""Adversarial tests for the native package signing evidence bundle."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import tempfile
import tarfile
import unittest
from pathlib import Path

try:
    from scripts.ci import native_package_signing_bundle as bundle
except ModuleNotFoundError:
    import native_package_signing_bundle as bundle


class NativePackageSigningBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.unsigned = self.root / "unsigned"
        self.signed = self.root / "signed"
        self.rhel_unsigned = self.root / "rhel-unsigned"
        self.rhel_signed = self.root / "rhel-signed"
        self.unsigned.mkdir()
        self.signed.mkdir()
        self.rhel_unsigned.mkdir()
        self.rhel_signed.mkdir()
        self.release = "v4.10.0"
        self.release_sha = "1" * 40
        self.names = bundle.package_names(self.release)
        self.unsigned_data = {
            "deb": b"unsigned-deb\n",
            "rpm": b"unsigned-rpm\n",
            "apk": b"\x1f\x8bunsigned-apk\n",
        }
        apk_signature_prefix = self.tar_gzip_single(
            ".SIGN.RSA256.apk-public.rsa.pub", b"s" * 256, 1780000000
        )
        self.signed_data = {
            "deb": self.unsigned_data["deb"],
            "rpm": b"signed-rpm-header\n" + self.unsigned_data["rpm"],
            "apk": apk_signature_prefix + self.unsigned_data["apk"],
        }
        self.write_packages(self.unsigned, self.unsigned_data)
        self.write_packages(self.signed, self.signed_data)
        self.rhel_name = bundle.rhel_package_owned_name(self.release)
        self.rhel_unsigned_data = b"unsigned-rhel-package-owned-rpm\n"
        self.rhel_signed_data = b"signed-rhel-header\n" + self.rhel_unsigned_data
        self.write_rhel_packages(self.rhel_unsigned, self.rhel_unsigned_data)
        self.write_rhel_packages(self.rhel_signed, self.rhel_signed_data)
        self.deb_signature = self.root / bundle.deb_signature_name(self.release)
        self.deb_signature_data = (
            b"-----BEGIN PGP SIGNATURE-----\n\nZmFrZQ==\n"
            b"-----END PGP SIGNATURE-----\n"
        )
        self.deb_signature.write_bytes(self.deb_signature_data)

        self.keys = self.root / "native-package-keys"
        self.keys.mkdir()
        self.rpm_public = self.keys / "rpm-public.asc"
        self.rpm_public.write_bytes(b"rpm-public-key\n")
        self.apk_public = self.keys / "apk-public.rsa.pub"
        self.apk_public.write_bytes(b"apk-public-key\n")
        self.deb_public = self.keys / "deb-public.asc"
        self.deb_public.write_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nZmFrZQ==\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.policy = self.root / "policy.json"
        self.rpm_fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        self.apk_fingerprint = hashlib.sha256(
            self.apk_public.read_bytes()
        ).hexdigest()
        self.deb_fingerprint = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
        self.write_policy()

        self.rpm_proof = self.root / "rpm-proof.json"
        self.rhel_rpm_proof = self.root / "rhel-rpm-proof.json"
        proof_digest = "2" * 64
        self.write_json(
            self.rpm_proof,
            {
                "profile": bundle.RPM_PROOF_PROFILE,
                "schema_version": 1,
                "signed": {
                    "immutable_header_sha256": proof_digest,
                    "payload_cpio_sha256": "3" * 64,
                },
                "status": "preserved",
                "unsigned": {
                    "immutable_header_sha256": proof_digest,
                    "payload_cpio_sha256": "3" * 64,
                },
            },
        )
        self.write_json(
            self.rhel_rpm_proof,
            json.loads(self.rpm_proof.read_text(encoding="utf-8")),
        )
        self.rpm_verification = self.root / "rpm-verification.json"
        self.rhel_rpm_verification = self.root / "rhel-rpm-verification.json"
        self.apk_verification = self.root / "apk-verification.json"
        self.deb_verification = self.root / "deb-verification.json"
        self.write_verification(
            self.rpm_verification,
            "rpm",
            "rpm-2026",
            self.rpm_fingerprint,
            hashlib.sha256(self.rpm_public.read_bytes()).hexdigest(),
        )
        self.write_verification(
            self.rhel_rpm_verification,
            "rpm",
            "rpm-2026",
            self.rpm_fingerprint,
            hashlib.sha256(self.rpm_public.read_bytes()).hexdigest(),
            package_name=self.rhel_name,
            package_data=self.rhel_signed_data,
        )
        self.write_verification(
            self.apk_verification,
            "apk",
            "apk-2026",
            self.apk_fingerprint,
            self.apk_fingerprint,
        )
        self.write_verification(
            self.deb_verification,
            "deb",
            "deb-2026",
            self.deb_fingerprint,
            hashlib.sha256(self.deb_public.read_bytes()).hexdigest(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, document: object) -> None:
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def tar_gzip_single(name: str, data: bytes, mtime: int) -> bytes:
        return NativePackageSigningBundleTests.tar_gzip_members(
            ((name, data),), mtime
        )

    @staticmethod
    def tar_gzip_members(
        members: tuple[tuple[str, bytes], ...], mtime: int
    ) -> bytes:
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            for name, data in members:
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.mtime = mtime
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return gzip.compress(tar_buffer.getvalue(), mtime=0)

    def replace_signed_apk(self, data: bytes) -> None:
        self.signed_data["apk"] = data
        self.write_packages(self.signed, self.signed_data)
        self.write_verification(
            self.apk_verification,
            "apk",
            "apk-2026",
            self.apk_fingerprint,
            self.apk_fingerprint,
        )

    def write_packages(self, directory: Path, content: dict[str, bytes]) -> None:
        named: dict[str, bytes] = {}
        for family, data in content.items():
            name = self.names[family]
            (directory / name).write_bytes(data)
            named[name] = data
        (directory / "SHA256SUMS.txt").write_bytes(bundle.canonical_manifest(named))

    def write_rhel_packages(self, directory: Path, data: bytes) -> None:
        (directory / self.rhel_name).write_bytes(data)
        (directory / "SHA256SUMS.txt").write_bytes(
            bundle.canonical_manifest({self.rhel_name: data})
        )

    def key(
        self, identifier: str, public_path: Path, fingerprint: str
    ) -> dict[str, object]:
        return {
            "fingerprint": fingerprint,
            "id": identifier,
            "public_key": "native-package-keys/" + public_path.name,
            "public_key_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
            "revoked": False,
            "supersedes": [],
            "valid_from": "2026-01-01",
            "valid_until": "2027-01-01",
        }

    def policy_document(self, status: str = "qualified") -> dict[str, object]:
        return {
            "apk": {
                "mechanism": "apk-rsa256",
                "signer_image": "registry.example/syswarden/apk-signer@sha256:" + "5" * 64,
                "trusted_keys": [self.key("apk-2026", self.apk_public, self.apk_fingerprint)],
            },
            "deb": {
                "channel": "github-release-assets",
                "decision": "detached-package-signature",
                "implementation": "qualified",
                "mechanism": "openpgp-detached",
                "signature_suffix": ".asc",
                "trusted_keys": [
                    self.key("deb-2026", self.deb_public, self.deb_fingerprint)
                ],
            },
            "profile": "syswarden-native-package-signatures/v4.10.0",
            "publishing": False,
            "rpm": {
                "mechanism": "rpm-openpgp",
                "trusted_keys": [self.key("rpm-2026", self.rpm_public, self.rpm_fingerprint)],
            },
            "schema_version": 1,
            "status": status,
        }

    def write_policy(self, status: str = "qualified") -> None:
        self.write_json(self.policy, self.policy_document(status))

    def rewrite_verification_evidence(self) -> None:
        self.write_verification(
            self.rpm_verification,
            "rpm",
            "rpm-2026",
            self.rpm_fingerprint,
            hashlib.sha256(self.rpm_public.read_bytes()).hexdigest(),
        )
        self.write_verification(
            self.rhel_rpm_verification,
            "rpm",
            "rpm-2026",
            self.rpm_fingerprint,
            hashlib.sha256(self.rpm_public.read_bytes()).hexdigest(),
            package_name=self.rhel_name,
            package_data=self.rhel_signed_data,
        )
        self.write_verification(
            self.apk_verification,
            "apk",
            "apk-2026",
            self.apk_fingerprint,
            self.apk_fingerprint,
        )
        self.write_verification(
            self.deb_verification,
            "deb",
            "deb-2026",
            self.deb_fingerprint,
            hashlib.sha256(self.deb_public.read_bytes()).hexdigest(),
        )

    def write_bootstrap_policy(self, document: dict[str, object] | None = None) -> None:
        bootstrap = (
            document
            if document is not None
            else self.policy_document("foundation-not-qualified")
        )
        bootstrap["deb"]["implementation"] = "implemented-not-qualified"
        self.write_json(self.policy, bootstrap)
        self.rewrite_verification_evidence()

    def write_verification(
        self,
        path: Path,
        family: str,
        key_id: str,
        fingerprint: str,
        public_key_sha256: str,
        *,
        package_name: str | None = None,
        package_data: bytes | None = None,
    ) -> None:
        policy_sha256 = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        package = package_data if package_data is not None else self.signed_data[family]
        document = {
                "as_of": "2026-09-03",
                "family": family,
                "key": {
                    "fingerprint": fingerprint,
                    "id": key_id,
                    "public_key": {
                        "rpm": "native-package-keys/" + self.rpm_public.name,
                        "apk": "native-package-keys/" + self.apk_public.name,
                        "deb": "native-package-keys/" + self.deb_public.name,
                    }[family],
                    "public_key_sha256": public_key_sha256,
                },
                "mechanism": {
                    "rpm": "rpm-openpgp",
                    "apk": "apk-rsa256",
                    "deb": "openpgp-detached",
                }[family],
                "package": bundle.file_record(package_name or self.names[family], package),
                "policy_sha256": policy_sha256,
                "profile": bundle.VERIFICATION_PROFILE,
                "purpose": "qualification",
                "release": self.release,
                "schema_version": 1,
                "status": "verified",
            }
        if family == "deb":
            document["signature"] = {
                "created_at": "2026-09-03T12:00:00Z",
                **bundle.file_record(
                    self.deb_signature.name, self.deb_signature_data
                ),
            }
        self.write_json(path, document)

    def finalize_arguments(self, output: Path | None = None) -> tuple[str, ...]:
        return (
            "finalize",
            "--release",
            self.release,
            "--release-sha",
            self.release_sha,
            "--repository",
            "duggytuxy/syswarden",
            "--unsigned-packages",
            str(self.unsigned),
            "--signed-packages",
            str(self.signed),
            "--rhel-unsigned-packages",
            str(self.rhel_unsigned),
            "--rhel-signed-packages",
            str(self.rhel_signed),
            "--unsigned-run-id",
            "100",
            "--unsigned-artifact-id",
            "200",
            "--unsigned-artifact-name",
            "syswarden-packages-4.10.0",
            "--unsigned-artifact-digest",
            "sha256:" + "4" * 64,
            "--rhel-unsigned-artifact-id",
            "201",
            "--rhel-unsigned-artifact-name",
            "syswarden-rhel-package-owned-4.10.0",
            "--rhel-unsigned-artifact-digest",
            "sha256:" + "6" * 64,
            "--signing-run-id",
            "300",
            "--signing-run-attempt",
            "1",
            "--signing-workflow-sha",
            self.release_sha,
            "--source-date-epoch",
            "1780000000",
            "--signer-image",
            "registry.example/syswarden/apk-signer@sha256:" + "5" * 64,
            "--policy",
            str(self.policy),
            "--as-of",
            "2026-09-03",
            "--rpm-proof",
            str(self.rpm_proof),
            "--rpm-verification",
            str(self.rpm_verification),
            "--rhel-rpm-proof",
            str(self.rhel_rpm_proof),
            "--rhel-rpm-verification",
            str(self.rhel_rpm_verification),
            "--apk-verification",
            str(self.apk_verification),
            "--deb-signature",
            str(self.deb_signature),
            "--deb-verification",
            str(self.deb_verification),
            "--output",
            str(output or (self.root / "bundle")),
        )

    def test_finalize_and_verify_exact_bundle(self) -> None:
        output = self.root / "bundle"
        self.assertEqual(bundle.main(self.finalize_arguments(output)), 0)
        self.assertEqual(
            bundle.main(
                (
                    "verify",
                    "--bundle",
                    str(output),
                    "--release",
                    self.release,
                    "--release-sha",
                    self.release_sha,
                )
            ),
            0,
        )
        provenance = json.loads(
            (output / "evidence/NATIVE_SIGNING_PROVENANCE.json").read_text()
        )
        self.assertEqual(provenance["status"], bundle.QUALIFIED_PROVENANCE_STATUS)
        self.assertFalse(provenance["public_release"])
        self.assertFalse(provenance["release_qualified"])
        self.assertTrue(provenance["apk_signature"]["exact_unsigned_suffix"])
        self.assertTrue(provenance["rpm_signature"]["payload_preserved"])
        deb_verification = json.loads(
            (output / "evidence/DEB_NATIVE_VERIFICATION.json").read_text()
        )
        self.assertEqual(deb_verification["status"], "verified")
        self.assertEqual(deb_verification["mechanism"], "openpgp-detached")
        self.assertEqual(
            (output / "packages" / self.deb_signature.name).read_bytes(),
            self.deb_signature_data,
        )
        rhel_root = output / bundle.RHEL_PACKAGE_OWNED_DIRECTORY
        self.assertEqual(
            (rhel_root / "packages" / self.rhel_name).read_bytes(),
            self.rhel_signed_data,
        )
        rhel_provenance = json.loads(
            (rhel_root / "evidence/SIGNING_PROVENANCE.json").read_text()
        )
        self.assertEqual(rhel_provenance["rpm_identity"]["release"], "1.rhelpo")
        self.assertFalse(rhel_provenance["updater_manifest_included"])
        self.assertEqual(
            rhel_provenance["rpm_signature"]["key"],
            provenance["rpm_signature"]["key"],
        )

    def test_inventory_is_exact_and_bound(self) -> None:
        output = self.root / "inventory.json"
        self.assertEqual(
            bundle.main(
                (
                    "inventory",
                    "--packages",
                    str(self.unsigned),
                    "--release",
                    self.release,
                    "--output",
                    str(output),
                )
            ),
            0,
        )
        document = json.loads(output.read_text())
        self.assertEqual(document["release"], self.release)
        self.assertEqual(len(document["artifacts"]), 3)
        rhel_output = self.root / "rhel-inventory.json"
        self.assertEqual(
            bundle.main(
                (
                    "rhel-package-owned-inventory",
                    "--packages",
                    str(self.rhel_unsigned),
                    "--release",
                    self.release,
                    "--output",
                    str(rhel_output),
                )
            ),
            0,
        )
        rhel_document = json.loads(rhel_output.read_text())
        self.assertEqual(
            [record["name"] for record in rhel_document["artifacts"]],
            [self.rhel_name],
        )

    def test_rhel_package_owned_tampering_fails_closed(self) -> None:
        self.rhel_signed_data += b"tamper\n"
        self.write_rhel_packages(self.rhel_signed, self.rhel_signed_data)
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_deb_mutation_fails_closed(self) -> None:
        self.signed_data["deb"] = b"signed-deb-is-not-allowed\n"
        self.write_packages(self.signed, self.signed_data)
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_deb_signature_or_verification_tampering_fails_closed(self) -> None:
        self.deb_signature.write_bytes(self.deb_signature_data + b"tamper")
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

        self.deb_signature.write_bytes(self.deb_signature_data)
        document = json.loads(self.deb_verification.read_text(encoding="utf-8"))
        document["signature"]["sha256"] = "0" * 64
        self.write_json(self.deb_verification, document)
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_rpm_payload_or_header_mismatch_fails_closed(self) -> None:
        document = json.loads(self.rpm_proof.read_text())
        document["signed"]["payload_cpio_sha256"] = "9" * 64
        self.write_json(self.rpm_proof, document)
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_apk_non_suffix_transformation_fails_closed(self) -> None:
        self.replace_signed_apk(
            b"\x1f\x8bchanged-apk-content-that-is-longer\n"
        )
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_apk_extra_archive_entry_fails_closed(self) -> None:
        prefix = self.tar_gzip_members(
            (
                (".SIGN.RSA256.apk-public.rsa.pub", b"s" * 256),
                ("private-key-leak", b"secret"),
            ),
            1780000000,
        )
        self.replace_signed_apk(prefix + self.unsigned_data["apk"])
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_apk_signature_entry_for_wrong_key_fails_closed(self) -> None:
        prefix = self.tar_gzip_single(
            ".SIGN.RSA256.wrong-key.rsa.pub", b"s" * 256, 1780000000
        )
        self.replace_signed_apk(prefix + self.unsigned_data["apk"])
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_apk_concatenated_signature_stream_fails_closed(self) -> None:
        valid_prefix = self.tar_gzip_single(
            ".SIGN.RSA256.apk-public.rsa.pub", b"s" * 256, 1780000000
        )
        hidden_stream = gzip.compress(b"secret material", mtime=0)
        self.replace_signed_apk(
            valid_prefix + hidden_stream + self.unsigned_data["apk"]
        )
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_apk_signature_decompression_is_bounded(self) -> None:
        oversized_prefix = gzip.compress(b"0" * (64 * 1024 + 1), mtime=0)
        with self.assertRaisesRegex(
            bundle.SigningBundleError,
            "decompressed size bound|singular and bounded",
        ):
            bundle.validate_apk_signature_archive(
                oversized_prefix,
                "native-package-keys/apk-public.rsa.pub",
                1780000000,
            )

    def test_wrong_verification_digest_fails_closed(self) -> None:
        document = json.loads(self.rpm_verification.read_text())
        document["package"]["sha256"] = "f" * 64
        self.write_json(self.rpm_verification, document)
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_unqualified_policy_fails_closed(self) -> None:
        self.write_bootstrap_policy()
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_explicit_bootstrap_qualification_is_sealed_and_verifiable(self) -> None:
        self.write_bootstrap_policy()
        output = self.root / "bootstrap-bundle"
        arguments = list(self.finalize_arguments(output))
        arguments.append("--bootstrap-qualification")
        self.assertEqual(bundle.main(tuple(arguments)), 0)
        self.assertEqual(
            bundle.main(
                (
                    "verify",
                    "--bundle",
                    str(output),
                    "--release",
                    self.release,
                    "--release-sha",
                    self.release_sha,
                )
            ),
            0,
        )
        provenance = json.loads(
            (output / "evidence/NATIVE_SIGNING_PROVENANCE.json").read_text()
        )
        self.assertEqual(provenance["status"], bundle.BOOTSTRAP_PROVENANCE_STATUS)
        self.assertFalse(provenance["public_release"])
        self.assertFalse(provenance["release_qualified"])

    def test_bootstrap_qualification_policy_boundaries_fail_closed(self) -> None:
        cases = (
            ("qualified", lambda document: None),
            (
                "publishing-enabled",
                lambda document: document.__setitem__("publishing", True),
            ),
            (
                "deb-qualified",
                lambda document: document["deb"].__setitem__(
                    "implementation", "qualified"
                ),
            ),
            (
                "missing-rpm-key",
                lambda document: document["rpm"].__setitem__("trusted_keys", []),
            ),
            (
                "revoked-apk-key",
                lambda document: document["apk"]["trusted_keys"][0].__setitem__(
                    "revoked", True
                ),
            ),
            (
                "expired-deb-key",
                lambda document: document["deb"]["trusted_keys"][0].__setitem__(
                    "valid_until", "2026-09-02"
                ),
            ),
        )
        for index, (name, mutate) in enumerate(cases):
            with self.subTest(name=name):
                document = self.policy_document("foundation-not-qualified")
                document["deb"]["implementation"] = "implemented-not-qualified"
                if name == "qualified":
                    document["status"] = "qualified"
                    document["deb"]["implementation"] = "qualified"
                mutate(document)
                self.write_json(self.policy, document)
                self.rewrite_verification_evidence()
                arguments = list(
                    self.finalize_arguments(self.root / f"bootstrap-rejected-{index}")
                )
                arguments.append("--bootstrap-qualification")
                self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_bootstrap_qualification_cannot_use_publishing_purpose(self) -> None:
        self.write_bootstrap_policy()
        arguments = list(self.finalize_arguments())
        arguments.extend(
            ("--bootstrap-qualification", "--purpose", "publishing")
        )
        self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_bootstrap_qualification_requires_committed_public_key_bytes(self) -> None:
        self.write_bootstrap_policy()
        self.rpm_public.unlink()
        arguments = list(self.finalize_arguments())
        arguments.append("--bootstrap-qualification")
        self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_bootstrap_qualification_requires_exactly_three_policy_keys(self) -> None:
        second_public = self.keys / "rpm-second.asc"
        second_public.write_bytes(b"second-rpm-public-key\n")
        document = self.policy_document("foundation-not-qualified")
        document["rpm"]["trusted_keys"].append(
            self.key("rpm-second", second_public, "A" * 40)
        )
        self.write_bootstrap_policy(document)
        arguments = list(self.finalize_arguments())
        arguments.append("--bootstrap-qualification")
        self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_noncanonical_signer_image_reference_fails_closed(self) -> None:
        arguments = list(self.finalize_arguments())
        image_index = arguments.index(
            "registry.example/syswarden/apk-signer@sha256:" + "5" * 64
        )
        arguments[image_index] = (
            "Registry.Example/syswarden/apk-signer@sha256:" + "5" * 64
        )
        self.assertEqual(bundle.main(tuple(arguments)), 1)

        arguments = list(self.finalize_arguments())
        arguments[image_index] = (
            "registry.example/syswarden/apk-signer@sha256:" + "6" * 64
        )
        self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_extra_input_or_symlink_fails_closed(self) -> None:
        (self.unsigned / "unexpected").write_text("data", encoding="ascii")
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)
        (self.unsigned / "unexpected").unlink()
        rpm = self.signed / self.names["rpm"]
        rpm.unlink()
        rpm.symlink_to(self.unsigned / self.names["rpm"])
        self.assertEqual(bundle.main(self.finalize_arguments()), 1)

    def test_unprotected_output_parent_fails_closed(self) -> None:
        unsafe = self.root / "unsafe-output-parent"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        output = unsafe / "bundle"
        self.assertEqual(bundle.main(self.finalize_arguments(output)), 1)
        self.assertFalse(output.exists())

    def test_sealed_bundle_tampering_fails_closed(self) -> None:
        output = self.root / "bundle"
        self.assertEqual(bundle.main(self.finalize_arguments(output)), 0)
        apk = output / "packages" / self.names["apk"]
        apk.write_bytes(apk.read_bytes() + b"tamper")
        self.assertEqual(
            bundle.main(
                (
                    "verify",
                    "--bundle",
                    str(output),
                    "--release",
                    self.release,
                    "--release-sha",
                    self.release_sha,
                )
            ),
            1,
        )

    def test_sealed_deb_signature_and_evidence_tampering_fail_closed(self) -> None:
        for target in (
            "packages/" + self.deb_signature.name,
            "evidence/DEB_NATIVE_VERIFICATION.json",
        ):
            with self.subTest(target=target):
                output = self.root / ("bundle-" + str(len(list(self.root.glob("bundle-*")))))
                self.assertEqual(bundle.main(self.finalize_arguments(output)), 0)
                path = output / target
                path.write_bytes(path.read_bytes() + b"tamper")
                self.assertEqual(
                    bundle.main(
                        (
                            "verify",
                            "--bundle",
                            str(output),
                            "--release",
                            self.release,
                            "--release-sha",
                            self.release_sha,
                        )
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
