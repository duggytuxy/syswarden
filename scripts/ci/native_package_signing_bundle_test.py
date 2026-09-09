#!/usr/bin/env python3
"""Adversarial tests for the native package signing evidence bundle."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import os
import shutil
import tempfile
import tarfile
import unittest
from argparse import Namespace
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
        self.bootstrap_release_sha = bundle.BOOTSTRAP_RELEASE_SHA
        self.bootstrap_signing_run_id = bundle.BOOTSTRAP_SIGNING_RUN_ID
        self.bootstrap_signed_artifact_id = bundle.BOOTSTRAP_SIGNED_ARTIFACT_ID
        self.bootstrap_signed_artifact_size = bundle.BOOTSTRAP_SIGNED_ARTIFACT_SIZE
        self.bootstrap_signed_artifact_digest = (
            bundle.BOOTSTRAP_SIGNED_ARTIFACT_DIGEST
        )
        self.bootstrap_policy = self.root / "bootstrap-policy.json"
        foundation = self.policy_document("foundation-not-qualified")
        foundation["deb"]["implementation"] = "implemented-not-qualified"
        self.write_json(self.bootstrap_policy, foundation)
        self.original_foundation_policy_sha256 = bundle.FOUNDATION_POLICY_SHA256
        bundle.FOUNDATION_POLICY_SHA256 = hashlib.sha256(
            self.bootstrap_policy.read_bytes()
        ).hexdigest()
        self.write_bootstrap_policy(json.loads(json.dumps(foundation)))
        self.bootstrap_bundle = self.root / "bootstrap-bundle"
        bootstrap_arguments = list(
            self.finalize_arguments(
                self.bootstrap_bundle,
                include_bootstrap=False,
                release_sha=self.bootstrap_release_sha,
                signing_run_id=self.bootstrap_signing_run_id,
            )
        )
        bootstrap_arguments.append("--bootstrap-qualification")
        if bundle.main(tuple(bootstrap_arguments)) != 0:
            raise AssertionError("bootstrap bundle fixture could not be created")
        self.write_policy()
        self.rewrite_verification_evidence()

    def tearDown(self) -> None:
        bundle.FOUNDATION_POLICY_SHA256 = self.original_foundation_policy_sha256
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, document: object) -> None:
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def tar_gzip_single(name: str, data: bytes, mtime: int) -> bytes:
        tar_buffer = io.BytesIO()
        with tarfile.open(
            fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = mtime
            member.size = len(data)
            member.pax_headers = {"atime": "0", "ctime": "0"}
            archive.addfile(member, io.BytesIO(data))
        return gzip.compress(tar_buffer.getvalue(), mtime=0)

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

    def apk_v2_unsigned(self) -> tuple[bytes, bytes]:
        control = self.tar_gzip_members(
            (
                (".PKGINFO", b"pkgname = syswarden\npkgver = 4.10.0-r0\n"),
                (".post-install", b"#!/bin/sh\nexit 0\n"),
            ),
            1780000000,
        )
        data = self.tar_gzip_members(
            (("opt/syswarden/bin/syswarden-cli", b"binary-data\n"),),
            1780000000,
        )
        return control + data, control

    def test_apk_control_signing_layout_preserves_exact_unsigned_suffix(self) -> None:
        unsigned, control = self.apk_v2_unsigned()
        unsigned_path = self.root / "unsigned-layout.apk"
        unsigned_path.write_bytes(unsigned)
        control_path = self.root / "control.tar.gz"
        bundle.apk_control_command(
            Namespace(unsigned_package=unsigned_path, output=control_path)
        )
        self.assertEqual(control_path.read_bytes(), control)

        signature_prefix = self.tar_gzip_single(
            ".SIGN.RSA256.apk-public.rsa.pub", b"s" * 512, 1780000000
        )
        signed_control_path = self.root / "signed-control.tar.gz"
        signed_control_path.write_bytes(signature_prefix + control)
        output = self.root / "signed-layout.apk"
        bundle.apk_assemble_command(
            Namespace(
                unsigned_package=unsigned_path,
                signed_control=signed_control_path,
                public_key_name="apk-public.rsa.pub",
                source_date_epoch=1780000000,
                output=output,
            )
        )
        self.assertEqual(output.read_bytes(), signature_prefix + unsigned)

    def test_apk_whole_package_signing_input_is_rejected(self) -> None:
        unsigned, _ = self.apk_v2_unsigned()
        unsigned_path = self.root / "unsigned-whole.apk"
        unsigned_path.write_bytes(unsigned)
        signature_prefix = self.tar_gzip_single(
            ".SIGN.RSA256.apk-public.rsa.pub", b"s" * 512, 1780000000
        )
        incorrectly_signed = self.root / "incorrectly-signed-control.tar.gz"
        incorrectly_signed.write_bytes(signature_prefix + unsigned)
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "exact unsigned control"
        ):
            bundle.apk_assemble_command(
                Namespace(
                    unsigned_package=unsigned_path,
                    signed_control=incorrectly_signed,
                    public_key_name="apk-public.rsa.pub",
                    source_date_epoch=1780000000,
                    output=self.root / "must-not-exist.apk",
                )
            )

    def test_apk_control_input_rejects_signed_or_single_stream_packages(self) -> None:
        unsigned, control = self.apk_v2_unsigned()
        signature_prefix = self.tar_gzip_single(
            ".SIGN.RSA256.apk-public.rsa.pub", b"s" * 512, 1780000000
        )
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "control archive identity"
        ):
            bundle.unsigned_apk_control_stream(signature_prefix + unsigned)
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "distinct control and data"
        ):
            bundle.unsigned_apk_control_stream(control)

    def test_apk_assembly_rejects_wrong_signature_key_name(self) -> None:
        unsigned, control = self.apk_v2_unsigned()
        unsigned_path = self.root / "unsigned-key-name.apk"
        unsigned_path.write_bytes(unsigned)
        signed_control = self.root / "wrong-key-control.tar.gz"
        signed_control.write_bytes(
            self.tar_gzip_single(
                ".SIGN.RSA256.other.rsa.pub", b"s" * 512, 1780000000
            )
            + control
        )
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "archive entry is invalid"
        ):
            bundle.apk_assemble_command(
                Namespace(
                    unsigned_package=unsigned_path,
                    signed_control=signed_control,
                    public_key_name="apk-public.rsa.pub",
                    source_date_epoch=1780000000,
                    output=self.root / "wrong-key-output.apk",
                )
            )

    def test_apk_assembly_rejects_oversized_signature_prefix(self) -> None:
        unsigned, control = self.apk_v2_unsigned()
        unsigned_path = self.root / "unsigned-prefix-bound.apk"
        unsigned_path.write_bytes(unsigned)
        signed_control = self.root / "oversized-prefix-control.tar.gz"
        signed_control.write_bytes(
            b"x" * (bundle.MAX_APK_SIGNATURE_PREFIX_BYTES + 1) + control
        )
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "compressed size bound"
        ):
            bundle.apk_assemble_command(
                Namespace(
                    unsigned_package=unsigned_path,
                    signed_control=signed_control,
                    public_key_name="apk-public.rsa.pub",
                    source_date_epoch=1780000000,
                    output=self.root / "oversized-prefix-output.apk",
                )
            )

    def test_apk_control_command_rejects_linked_inputs(self) -> None:
        unsigned, _ = self.apk_v2_unsigned()
        source = self.root / "linked-source.apk"
        source.write_bytes(unsigned)
        symbolic = self.root / "symbolic-source.apk"
        symbolic.symlink_to(source)
        with self.assertRaisesRegex(bundle.SigningBundleError, "regular file"):
            bundle.apk_control_command(
                Namespace(
                    unsigned_package=symbolic,
                    output=self.root / "symbolic-output.tar.gz",
                )
            )
        symbolic.unlink()

        hardlink = self.root / "hardlink-source.apk"
        os.link(source, hardlink)
        with self.assertRaisesRegex(bundle.SigningBundleError, "singly-linked"):
            bundle.apk_control_command(
                Namespace(
                    unsigned_package=hardlink,
                    output=self.root / "hardlink-output.tar.gz",
                )
            )

    def test_apk_control_rejects_duplicate_pkginfo(self) -> None:
        duplicated_control = self.tar_gzip_members(
            ((".PKGINFO", b"first\n"), (".PKGINFO", b"second\n")),
            1780000000,
        )
        data = self.tar_gzip_members((("opt/syswarden", b"data\n"),), 1780000000)
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "control archive identity"
        ):
            bundle.unsigned_apk_control_stream(duplicated_control + data)

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

    def finalize_arguments(
        self,
        output: Path | None = None,
        *,
        include_bootstrap: bool = True,
        release_sha: str | None = None,
        signing_run_id: int = 300,
    ) -> tuple[str, ...]:
        selected_release_sha = release_sha or self.release_sha
        arguments = [
            "finalize",
            "--release",
            self.release,
            "--release-sha",
            selected_release_sha,
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
            str(signing_run_id),
            "--signing-run-attempt",
            "1",
            "--signing-workflow-sha",
            selected_release_sha,
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
        ]
        if include_bootstrap:
            arguments.extend(
                (
                    "--bootstrap-bundle",
                    str(self.bootstrap_bundle),
                    "--bootstrap-release-sha",
                    self.bootstrap_release_sha,
                    "--bootstrap-policy",
                    str(self.bootstrap_policy),
                    "--bootstrap-policy-sha256",
                    hashlib.sha256(self.bootstrap_policy.read_bytes()).hexdigest(),
                    "--bootstrap-signing-run-id",
                    str(self.bootstrap_signing_run_id),
                    "--bootstrap-signed-artifact-id",
                    str(self.bootstrap_signed_artifact_id),
                    "--bootstrap-signed-artifact-name",
                    bundle.signed_artifact_name(
                        self.release,
                        bundle.BOOTSTRAP_BUNDLE_MODE,
                        self.bootstrap_signing_run_id,
                        1,
                        self.bootstrap_release_sha,
                    ),
                    "--bootstrap-signed-artifact-size",
                    str(self.bootstrap_signed_artifact_size),
                    "--bootstrap-signed-artifact-digest",
                    self.bootstrap_signed_artifact_digest,
                )
            )
        arguments.extend(("--output", str(output or (self.root / "bundle"))))
        return tuple(arguments)

    @staticmethod
    def replace_argument(
        arguments: tuple[str, ...], option: str, value: str
    ) -> tuple[str, ...]:
        changed = list(arguments)
        changed[changed.index(option) + 1] = value
        return tuple(changed)

    @staticmethod
    def reseal_bundle(root: Path) -> None:
        rhel_root = root / bundle.RHEL_PACKAGE_OWNED_DIRECTORY
        for seal_root in (rhel_root, root):
            members = {}
            for child in sorted(seal_root.rglob("*")):
                if child.is_dir():
                    continue
                relative = child.relative_to(seal_root).as_posix()
                if relative == "SIGNED_ARTIFACT_SHA256SUMS.txt":
                    continue
                members[relative] = child.read_bytes()
            (seal_root / "SIGNED_ARTIFACT_SHA256SUMS.txt").write_bytes(
                bundle.canonical_manifest(members)
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
        reference = provenance["bootstrap_qualification"]
        self.assertEqual(reference["release_sha"], self.bootstrap_release_sha)
        self.assertEqual(reference["signing_run"]["id"], self.bootstrap_signing_run_id)
        self.assertEqual(
            reference["artifact"]["id"], self.bootstrap_signed_artifact_id
        )
        self.assertEqual(
            reference["artifact"]["size"], self.bootstrap_signed_artifact_size
        )
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
        self.assertEqual(rhel_provenance["bootstrap_qualification"], reference)

    def test_phase_a_policy_digest_is_immutable(self) -> None:
        self.assertEqual(
            self.original_foundation_policy_sha256,
            "6b98b3b5bca83b9bc611c3b2e384636b5bbcbecc9e818e0f06104255200b011d",
        )

    def test_reviewed_phase_a_bootstrap_identity_is_immutable(self) -> None:
        self.assertEqual(bundle.BOOTSTRAP_REPOSITORY, "duggytuxy/syswarden")
        self.assertEqual(
            bundle.BOOTSTRAP_RELEASE_SHA,
            "9598861f1be80a651658bf3ca8c10424bd70db6c",
        )
        self.assertEqual(bundle.BOOTSTRAP_SIGNING_RUN_ID, 34292701745)
        self.assertEqual(bundle.BOOTSTRAP_SIGNED_ARTIFACT_ID, 10088398939)
        self.assertEqual(bundle.BOOTSTRAP_SIGNED_ARTIFACT_SIZE, 63065295)
        self.assertEqual(
            bundle.BOOTSTRAP_SIGNED_ARTIFACT_NAME,
            "syswarden-native-signed-packages-4.10.0-34292701745-1-"
            "9598861f1be80a651658bf3ca8c10424bd70db6c",
        )
        self.assertEqual(
            bundle.BOOTSTRAP_SIGNED_ARTIFACT_DIGEST,
            "sha256:a76917630d5d5a90bddcf936d47ec75a987f098c9048bce0d320d1ffda131ad3",
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

    def test_apk_signature_pax_metadata_must_match_pinned_abuild(self) -> None:
        prefix_without_pinned_metadata = self.tar_gzip_members(
            ((".SIGN.RSA256.apk-public.rsa.pub", b"s" * 256),),
            1780000000,
        )
        with self.assertRaisesRegex(
            bundle.SigningBundleError, "archive entry is invalid"
        ):
            bundle.validate_apk_signature_archive(
                prefix_without_pinned_metadata,
                "native-package-keys/apk-public.rsa.pub",
                1780000000,
            )

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
        output = self.root / "bootstrap-bundle-explicit"
        arguments = list(self.finalize_arguments(output, include_bootstrap=False))
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
                    "--mode",
                    "bootstrap",
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

    def test_bundle_verification_is_qualified_only_by_default(self) -> None:
        self.assertEqual(
            bundle.main(
                (
                    "verify",
                    "--bundle",
                    str(self.bootstrap_bundle),
                    "--release",
                    self.release,
                    "--release-sha",
                    self.bootstrap_release_sha,
                )
            ),
            1,
        )
        self.assertEqual(
            bundle.main(
                (
                    "verify",
                    "--bundle",
                    str(self.bootstrap_bundle),
                    "--release",
                    self.release,
                    "--release-sha",
                    self.bootstrap_release_sha,
                    "--mode",
                    "bootstrap",
                )
            ),
            0,
        )

    def test_bundle_provenance_integer_types_fail_closed(self) -> None:
        cases = (
            ("evidence/NATIVE_SIGNING_PROVENANCE.json", "signing-attempt"),
            (
                "rhel-package-owned/evidence/SIGNING_PROVENANCE.json",
                "schema-version",
            ),
        )
        for index, (relative, field) in enumerate(cases):
            with self.subTest(field=field):
                output = self.root / f"provenance-integer-type-{index}"
                shutil.copytree(self.bootstrap_bundle, output)
                path = output / relative
                document = json.loads(path.read_text(encoding="utf-8"))
                if field == "signing-attempt":
                    document["signing_run"]["attempt"] = True
                else:
                    document["schema_version"] = True
                self.write_json(path, document)
                self.reseal_bundle(output)
                self.assertEqual(
                    bundle.main(
                        (
                            "verify",
                            "--bundle",
                            str(output),
                            "--release",
                            self.release,
                            "--release-sha",
                            self.bootstrap_release_sha,
                            "--mode",
                            "bootstrap",
                        )
                    ),
                    1,
                )

    def test_qualified_mode_requires_every_exact_bootstrap_binding(self) -> None:
        bootstrap_options = (
            "--bootstrap-bundle",
            "--bootstrap-release-sha",
            "--bootstrap-policy",
            "--bootstrap-policy-sha256",
            "--bootstrap-signing-run-id",
            "--bootstrap-signed-artifact-id",
            "--bootstrap-signed-artifact-name",
            "--bootstrap-signed-artifact-size",
            "--bootstrap-signed-artifact-digest",
        )
        for index, option in enumerate(bootstrap_options):
            with self.subTest(option=option):
                arguments = list(
                    self.finalize_arguments(self.root / f"missing-bootstrap-{index}")
                )
                position = arguments.index(option)
                del arguments[position : position + 2]
                self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_qualified_mode_rejects_wrong_bootstrap_identities(self) -> None:
        mutations = (
            ("--bootstrap-release-sha", self.release_sha),
            ("--bootstrap-policy-sha256", "0" * 64),
            ("--bootstrap-signing-run-id", "300"),
            ("--bootstrap-signed-artifact-id", "0"),
            (
                "--bootstrap-signed-artifact-id",
                str(self.bootstrap_signed_artifact_id + 1),
            ),
            (
                "--bootstrap-signed-artifact-size",
                str(self.bootstrap_signed_artifact_size + 1),
            ),
            (
                "--bootstrap-signed-artifact-name",
                "syswarden-native-signed-packages-qualified-4.10.0-250-1-"
                + self.bootstrap_release_sha,
            ),
            (
                "--bootstrap-signed-artifact-name",
                "syswarden-native-signed-packages-bootstrap-4.10.0-250-1-"
                + self.bootstrap_release_sha,
            ),
            ("--bootstrap-signed-artifact-digest", "sha256:" + "0" * 63),
            ("--bootstrap-signed-artifact-digest", "sha256:" + "0" * 64),
        )
        for index, (option, value) in enumerate(mutations):
            with self.subTest(option=option):
                arguments = self.finalize_arguments(
                    self.root / f"wrong-bootstrap-{index}"
                )
                arguments = self.replace_argument(arguments, option, value)
                self.assertEqual(bundle.main(arguments), 1)

    def test_sealed_bootstrap_reference_schema_fails_closed(self) -> None:
        output = self.root / "reference-schema"
        self.assertEqual(bundle.main(self.finalize_arguments(output)), 0)
        provenance = json.loads(
            (output / "evidence/NATIVE_SIGNING_PROVENANCE.json").read_text(
                encoding="utf-8"
            )
        )
        reference = provenance["bootstrap_qualification"]
        self.assertEqual(
            bundle.validate_bootstrap_reference(
                reference, self.release, self.release_sha, "duggytuxy/syswarden"
            ),
            reference,
        )
        mutations = (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value.__setitem__("schema_version", True),
            lambda value: value.__setitem__("release_sha", self.release_sha),
            lambda value: value.__setitem__("repository", "other/repository"),
            lambda value: value.__setitem__("policy_sha256", "0" * 64),
            lambda value: value["signing_run"].__setitem__("attempt", 2),
            lambda value: value["signing_run"].__setitem__("attempt", True),
            lambda value: value["signing_run"].__setitem__(
                "workflow_sha", "c" * 40
            ),
            lambda value: value["artifact"].__setitem__("id", 0),
            lambda value: value["artifact"].__setitem__(
                "id", self.bootstrap_signed_artifact_id + 1
            ),
            lambda value: value["artifact"].__setitem__("size", True),
            lambda value: value["artifact"].__setitem__(
                "size", self.bootstrap_signed_artifact_size + 1
            ),
            lambda value: value["artifact"].__setitem__(
                "name", "syswarden-native-signed-packages-qualified"
            ),
            lambda value: value["artifact"].__setitem__(
                "digest", "sha256:" + "0" * 63
            ),
            lambda value: value["artifact"].__setitem__(
                "digest", "sha256:" + "0" * 64
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = json.loads(json.dumps(reference))
                mutate(changed)
                with self.assertRaises(bundle.SigningBundleError):
                    bundle.validate_bootstrap_reference(
                        changed,
                        self.release,
                        self.release_sha,
                        "duggytuxy/syswarden",
                    )

    def test_policy_transition_allows_only_the_reviewed_state_changes(self) -> None:
        qualified = self.policy_document("qualified")
        qualified["publishing"] = True
        self.write_json(self.policy, qualified)
        self.rewrite_verification_evidence()
        self.assertEqual(
            bundle.main(
                self.finalize_arguments(self.root / "qualified-publishing-enabled")
            ),
            0,
        )

        mutations = (
            (
                "schema-version-type",
                lambda document: document.__setitem__("schema_version", True),
            ),
            (
                "key-validity",
                lambda document: document["rpm"]["trusted_keys"][0].__setitem__(
                    "valid_until", "2027-01-02"
                ),
            ),
            (
                "signer-image",
                lambda document: document["apk"].__setitem__(
                    "signer_image",
                    "registry.example/syswarden/apk-signer@sha256:" + "6" * 64,
                ),
            ),
            (
                "deb-signature-suffix",
                lambda document: document["deb"].__setitem__(
                    "signature_suffix", ".sig"
                ),
            ),
        )
        for index, (name, mutate) in enumerate(mutations):
            with self.subTest(name=name):
                document = self.policy_document("qualified")
                mutate(document)
                self.write_json(self.policy, document)
                self.rewrite_verification_evidence()
                self.assertEqual(
                    bundle.main(
                        self.finalize_arguments(
                            self.root / f"transition-rejected-{index}"
                        )
                    ),
                    1,
                )

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
                    self.finalize_arguments(
                        self.root / f"bootstrap-rejected-{index}",
                        include_bootstrap=False,
                    )
                )
                arguments.append("--bootstrap-qualification")
                self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_bootstrap_qualification_cannot_use_publishing_purpose(self) -> None:
        self.write_bootstrap_policy()
        arguments = list(self.finalize_arguments(include_bootstrap=False))
        arguments.extend(
            ("--bootstrap-qualification", "--purpose", "publishing")
        )
        self.assertEqual(bundle.main(tuple(arguments)), 1)

    def test_bootstrap_qualification_requires_committed_public_key_bytes(self) -> None:
        self.write_bootstrap_policy()
        self.rpm_public.unlink()
        arguments = list(self.finalize_arguments(include_bootstrap=False))
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
        arguments = list(self.finalize_arguments(include_bootstrap=False))
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
