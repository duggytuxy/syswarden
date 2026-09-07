#!/usr/bin/env python3
"""Tests for the offline native package signature gate foundation."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

try:
    from scripts.ci import native_package_signature_gate as gate
except ModuleNotFoundError:
    import native_package_signature_gate as gate


class NativePackageSignatureGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.keys = self.root / "native-package-keys"
        self.keys.mkdir()
        self.package = self.root / "syswarden-4.10.0-1.x86_64.rpm"
        self.package.write_bytes(b"signed-rpm-fixture\n")
        self.rpm_key = self.keys / "rpm-public.asc"
        self.rpm_key.write_text(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ncnBtLXB1YmxpYy1rZXk=\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n",
            encoding="ascii",
        )
        self.apk_key = self.keys / "apk-public.rsa.pub"
        self.apk_key.write_bytes(b"apk-public-key-fixture\n")
        self.deb_key = self.keys / "deb-public.asc"
        self.deb_key.write_text(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nZmFrZQ==\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n",
            encoding="ascii",
        )
        self.fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        self.deb_fingerprint = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
        self.policy = self.root / "policy.json"
        self.inventory = self.root / "inventory.json"
        self.rpmkeys = self.tool(
            "rpmkeys",
            "if [ \"$3\" = --import ]; then exit 0; fi\nif [ \"$3\" = --checksig ]; then printf '%s\\n' 'Header V4 RSA/SHA256 Signature, key ID 01234567: OK'; exit 0; fi\nexit 2",
        )
        self.gpg = self.tool(
            "gpg",
            f"printf '%s\\n' 'pub:-:3072:1:0123456789ABCDEF:1767225600:1798761600:::::s:' 'fpr:::::::::{self.fingerprint}:'",
        )
        self.apk = self.tool("apk", "[ \"$1\" = verify ] && exit 0\nexit 2")
        self.openssl = self.tool(
            "openssl", "printf '%s\\n' 'Public-Key: (4096 bit)'"
        )
        self.gpgv = self.tool("gpgv", "exit 2")
        self.write_inventory()
        self.write_policy()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def tool(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="ascii")
        path.chmod(0o700)
        return path

    def key(self, identifier: str, path: Path, fingerprint: str) -> dict[str, object]:
        return {
            "id": identifier,
            "public_key": "native-package-keys/" + path.name,
            "public_key_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "fingerprint": fingerprint,
            "valid_from": "2026-01-01",
            "valid_until": "2027-01-01",
            "revoked": False,
            "supersedes": [],
        }

    def document(self) -> dict[str, object]:
        apk_digest = hashlib.sha256(self.apk_key.read_bytes()).hexdigest()
        return {
            "schema_version": 1,
            "profile": "syswarden-native-package-signatures/v4.10.0",
            "status": "qualified",
            "publishing": False,
            "rpm": {
                "mechanism": "rpm-openpgp",
                "trusted_keys": [self.key("rpm-2026", self.rpm_key, self.fingerprint)],
            },
            "apk": {
                "mechanism": "apk-rsa256",
                "signer_image": "registry.example/syswarden/apk-signer@sha256:" + "5" * 64,
                "trusted_keys": [self.key("apk-2026", self.apk_key, apk_digest)],
            },
            "deb": {
                "channel": "github-release-assets",
                "decision": "detached-package-signature",
                "mechanism": "openpgp-detached",
                "signature_suffix": ".asc",
                "trusted_keys": [
                    self.key("deb-2026", self.deb_key, self.deb_fingerprint)
                ],
                "implementation": "qualified",
            },
        }

    def bootstrap_document(self) -> dict[str, object]:
        document = self.document()
        document["status"] = "foundation-not-qualified"
        document["publishing"] = False
        document["deb"]["implementation"] = "implemented-not-qualified"
        return document

    def write_policy(self, document: dict[str, object] | None = None) -> None:
        self.policy.write_text(json.dumps(document or self.document()), encoding="utf-8")

    def write_inventory(self) -> None:
        data = self.package.read_bytes()
        self.inventory.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "release": "v4.10.0",
                    "artifacts": [
                        {
                            "name": self.package.name,
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def arguments(self, family: str, key_id: str) -> tuple[str, ...]:
        return (
            family,
            "--policy", str(self.policy),
            "--inventory", str(self.inventory),
            "--package", str(self.package),
            "--release", "v4.10.0",
            "--key-id", key_id,
            "--as-of", "2026-09-03",
            "--rpmkeys", str(self.rpmkeys),
            "--gpg", str(self.gpg),
            "--gpgv", str(self.gpgv),
            "--apk", str(self.apk),
            "--openssl", str(self.openssl),
        )

    def deb_arguments(self) -> tuple[str, ...]:
        self.package = self.root / "syswarden_4.10.0_amd64.deb"
        self.package.write_bytes(b"signed-deb-fixture\n")
        self.signature = self.root / (self.package.name + ".asc")
        self.signature.write_text(
            "-----BEGIN PGP SIGNATURE-----\n\nZmFrZQ==\n"
            "-----END PGP SIGNATURE-----\n",
            encoding="ascii",
        )
        self.write_inventory()
        self.gpg = self.tool(
            "gpg-deb",
            f"printf '%s\\n' "
            f"'pub:-:4096:1:76543210FEDCBA98:1767225600:1798761600:::::sc:' "
            f"'fpr:::::::::{self.deb_fingerprint}:'",
        )
        self.gpgv = self.tool(
            "gpgv-deb",
            f"printf '%s\\n' "
            "'[GNUPG:] NEWSIG' "
            f"'[GNUPG:] KEY_CONSIDERED {self.deb_fingerprint} 0' "
            "'[GNUPG:] SIG_ID AAAAAAAAAAAAAAAAAAAA 2026-09-03 1788436800' "
            f"'[GNUPG:] GOODSIG {self.deb_fingerprint[-16:]} Test' "
            f"'[GNUPG:] VALIDSIG {self.deb_fingerprint} 2026-09-03 "
            f"1788436800 0 4 0 1 8 00 {self.deb_fingerprint}' "
            "'[GNUPG:] TRUST_UNDEFINED 0 pgp'",
        )
        return self.arguments("deb", "deb-2026") + (
            "--signature",
            str(self.signature),
        )

    def test_rpm_native_verification_binds_key_package_and_release(self) -> None:
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 0)

    def test_apk_native_verification_binds_key_bytes_and_release(self) -> None:
        self.package = self.root / "syswarden_4.10.0_x86_64.apk"
        self.package.write_bytes(b"signed-apk-fixture\n")
        self.write_inventory()
        self.assertEqual(gate.main(self.arguments("apk", "apk-2026")), 0)

    def test_explicit_bootstrap_qualification_verifies_every_family(self) -> None:
        self.write_policy(self.bootstrap_document())
        self.assertEqual(
            gate.main(
                self.arguments("rpm", "rpm-2026")
                + ("--bootstrap-qualification",)
            ),
            0,
        )

        self.package = self.root / "syswarden_4.10.0_x86_64.apk"
        self.package.write_bytes(b"signed-apk-fixture\n")
        self.write_inventory()
        self.write_policy(self.bootstrap_document())
        self.assertEqual(
            gate.main(
                self.arguments("apk", "apk-2026")
                + ("--bootstrap-qualification",)
            ),
            0,
        )

        arguments = self.deb_arguments()
        self.write_policy(self.bootstrap_document())
        self.assertEqual(
            gate.main(arguments + ("--bootstrap-qualification",)),
            0,
        )

    def test_bootstrap_qualification_policy_boundaries_fail_closed(self) -> None:
        cases = (
            (
                "qualified-policy",
                lambda document: (
                    document.__setitem__("status", "qualified"),
                    document["deb"].__setitem__("implementation", "qualified"),
                ),
            ),
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
        for name, mutate in cases:
            with self.subTest(name=name):
                document = self.bootstrap_document()
                mutate(document)
                self.write_policy(document)
                self.assertEqual(
                    gate.main(
                        self.arguments("rpm", "rpm-2026")
                        + ("--bootstrap-qualification",)
                    ),
                    1,
                )

        second_key = self.keys / "rpm-second.asc"
        second_key.write_text(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ncnBtLXNlY29uZA==\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n",
            encoding="ascii",
        )
        document = self.bootstrap_document()
        document["rpm"]["trusted_keys"].append(
            self.key("rpm-second", second_key, "A" * 40)
        )
        self.write_policy(document)
        self.assertEqual(
            gate.main(
                self.arguments("rpm", "rpm-2026")
                + ("--bootstrap-qualification",)
            ),
            1,
        )

    def test_bootstrap_qualification_rejects_publishing_and_wrong_selection(self) -> None:
        self.write_policy(self.bootstrap_document())
        self.assertEqual(
            gate.main(
                self.arguments("rpm", "rpm-2026")
                + (
                    "--bootstrap-qualification",
                    "--purpose",
                    "publishing",
                )
            ),
            1,
        )
        self.assertEqual(
            gate.main(
                self.arguments("rpm", "rpm-other")
                + ("--bootstrap-qualification",)
            ),
            1,
        )

    def test_normal_mode_rejects_foundation_policy(self) -> None:
        self.write_policy(self.bootstrap_document())
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_repository_foundation_policy_cannot_claim_qualification(self) -> None:
        policy = Path(gate.__file__).with_name("native_package_signature_policy_v4100.json")
        document = gate.load_json(policy, "repository policy")
        gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))
        self.assertEqual(document["status"], "foundation-not-qualified")
        self.assertFalse(document["publishing"])
        self.assertEqual(document["rpm"]["trusted_keys"], [])
        self.assertEqual(document["apk"]["trusted_keys"], [])
        self.assertEqual(document["deb"]["trusted_keys"], [])
        self.assertEqual(
            document["apk"]["signer_image"],
            "docker.io/alpinelinux/build-base@sha256:31d2a020ccd2058e6ab47940428bd0b7dc83e37b66880891f9ed903a12ea668b",
        )

        document["publishing"] = True
        with self.assertRaisesRegex(
            gate.SignatureGateError, "publishing approval requires"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_qualified_policy_requires_a_canonical_committed_signer_image(self) -> None:
        document = self.document()
        document["apk"]["signer_image"] = None
        with self.assertRaisesRegex(
            gate.SignatureGateError, "requires a reviewed APK signer image"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document["apk"]["signer_image"] = "latest"
        with self.assertRaisesRegex(
            gate.SignatureGateError, "canonical OCI digest"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        for family in ("rpm", "apk", "deb"):
            with self.subTest(family=family):
                document = self.document()
                document[family]["trusted_keys"] = []
                with self.assertRaisesRegex(
                    gate.SignatureGateError, "reviewed RPM, APK and DEB trusted keys"
                ):
                    gate.validate_policy(
                        document, gate.parse_day("2026-09-03", "date")
                    )

    def test_expired_revoked_or_self_rotating_key_fails_closed(self) -> None:
        for field, value, message in (
            ("valid_until", "2026-09-02", "not valid"),
            ("revoked", True, "revoked"),
        ):
            with self.subTest(field=field):
                document = self.document()
                document["rpm"]["trusted_keys"][0][field] = value
                self.write_policy(document)
                self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

        document = self.document()
        document["rpm"]["trusted_keys"][0]["supersedes"] = ["rpm-2026"]
        with self.assertRaisesRegex(gate.SignatureGateError, "supersede itself"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_wrong_key_fingerprint_and_key_bytes_fail_closed(self) -> None:
        wrong_fingerprint = copy.deepcopy(self.document())
        wrong_fingerprint["rpm"]["trusted_keys"][0]["fingerprint"] = "F" * 40
        self.write_policy(wrong_fingerprint)
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

        wrong_key = self.document()
        wrong_key["rpm"]["trusted_keys"][0]["public_key_sha256"] = "0" * 64
        self.write_policy(wrong_key)
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_native_openpgp_expiry_revocation_and_future_creation_fail_closed(self) -> None:
        records = (
            ("e", "1767225600", "1798761600"),
            ("r", "1767225600", "1798761600"),
            ("-", "1798848000", "1830384000"),
            ("-", "1767225600", "1788307200"),
        )
        for index, (validity, created, expires) in enumerate(records):
            with self.subTest(validity=validity, created=created, expires=expires):
                self.gpg = self.tool(
                    f"gpg-native-invalid-{index}",
                    f"printf '%s\\n' 'pub:{validity}:3072:1:0123456789ABCDEF:{created}:{expires}:::::s:' "
                    f"'fpr:::::::::{self.fingerprint}:'",
                )
                self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_weak_or_non_rsa_native_keys_fail_closed(self) -> None:
        for index, (bits, algorithm) in enumerate(((2048, 1), (3072, 22))):
            with self.subTest(bits=bits, algorithm=algorithm):
                self.gpg = self.tool(
                    f"gpg-weak-{index}",
                    f"printf '%s\\n' 'pub:-:{bits}:{algorithm}:0123456789ABCDEF:1767225600:1798761600:::::s:' "
                    f"'fpr:::::::::{self.fingerprint}:'",
                )
                self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

        self.package = self.root / "syswarden_4.10.0_x86_64.apk"
        self.package.write_bytes(b"signed-apk-fixture\n")
        self.write_inventory()
        self.openssl = self.tool(
            "openssl-weak", "printf '%s\\n' 'Public-Key: (2048 bit)'"
        )
        self.assertEqual(gate.main(self.arguments("apk", "apk-2026")), 1)

    def test_unsigned_native_verdicts_fail_closed(self) -> None:
        self.rpmkeys = self.tool(
            "rpmkeys-unsigned",
            "if [ \"$3\" = --import ]; then exit 0; fi\n"
            "if [ \"$3\" = --checksig ]; then printf '%s\\n' 'Header SHA256 digest: OK' 'Payload SHA256 digest: OK'; exit 0; fi\n"
            "exit 2",
        )
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

        self.package = self.root / "syswarden_4.10.0_x86_64.apk"
        self.package.write_bytes(b"unsigned-apk-fixture\n")
        self.write_inventory()
        self.apk = self.tool("apk-reject-unsigned", "exit 1")
        self.assertEqual(gate.main(self.arguments("apk", "apk-2026")), 1)

    def test_weak_rpm_signature_digest_fails_closed(self) -> None:
        self.rpmkeys = self.tool(
            "rpmkeys-sha1",
            "if [ \"$3\" = --import ]; then exit 0; fi\n"
            "if [ \"$3\" = --checksig ]; then printf '%s\\n' 'Header V4 RSA/SHA1 Signature, key ID 01234567: OK'; exit 0; fi\n"
            "exit 2",
        )
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_weak_rpm_signing_subkey_fails_closed(self) -> None:
        signing_fingerprint = "A" * 32 + "DEADBEEF"
        self.gpg = self.tool(
            "gpg-weak-signing-subkey",
            f"printf '%s\\n' "
            f"'pub:-:4096:1:0123456789ABCDEF:1767225600:1798761600:::::c:' "
            f"'fpr:::::::::{self.fingerprint}:' "
            f"'sub:-:2048:1:AAAAAAAADEADBEEF:1767225600:1798761600:::::s:' "
            f"'fpr:::::::::{signing_fingerprint}:'",
        )
        self.rpmkeys = self.tool(
            "rpmkeys-weak-signing-subkey",
            "if [ \"$3\" = --import ]; then exit 0; fi\n"
            "if [ \"$3\" = --checksig ]; then printf '%s\\n' 'Header V4 RSA/SHA256 Signature, key ID DEADBEEF: OK'; exit 0; fi\n"
            "exit 2",
        )
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_policy_mutation_during_native_verification_fails_closed(self) -> None:
        self.rpmkeys = self.tool(
            "rpmkeys-policy-race",
            "if [ \"$3\" = --import ]; then exit 0; fi\n"
            f"if [ \"$3\" = --checksig ]; then printf '%s' '{{\"tampered\":true}}' > '{self.policy}'; "
            "printf '%s\\n' 'Header V4 RSA/SHA256 Signature, key ID 01234567: OK'; exit 0; fi\n"
            "exit 2",
        )
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_inventory_mutation_during_deb_verification_fails_closed(self) -> None:
        self.deb_arguments()
        self.gpgv = self.tool(
            "gpgv-inventory-race",
            f"printf '%s\\n' '[GNUPG:] NEWSIG' "
            f"'[GNUPG:] KEY_CONSIDERED {self.deb_fingerprint} 0' "
            "'[GNUPG:] SIG_ID AAAAAAAAAAAAAAAAAAAA 2026-09-03 1788436800' "
            f"'[GNUPG:] GOODSIG {self.deb_fingerprint[-16:]} Test' "
            f"'[GNUPG:] VALIDSIG {self.deb_fingerprint} 2026-09-03 "
            f"1788436800 0 4 0 1 8 00 {self.deb_fingerprint}'; "
            f"printf '%s' '{{\"tampered\":true}}' > '{self.inventory}'",
        )
        arguments = list(self.arguments("deb", "deb-2026")) + [
            "--signature", str(self.signature)
        ]
        self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_rotation_selects_only_the_current_distinct_key(self) -> None:
        old_path = self.keys / "rpm-2025.asc"
        old_path.write_bytes(b"old-rpm-public-key\n")
        document = self.document()
        old = self.key(
            "rpm-2025",
            old_path,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        old["revoked"] = True
        current = document["rpm"]["trusted_keys"][0]
        current["supersedes"] = ["rpm-2025"]
        document["rpm"]["trusted_keys"] = [old, current]
        day = gate.parse_day("2026-09-03", "date")
        gate.validate_policy(document, day)
        self.assertEqual(
            gate.select_key(document, "rpm", "rpm-2026", day)["id"],
            "rpm-2026",
        )
        with self.assertRaisesRegex(gate.SignatureGateError, "revoked"):
            gate.select_key(document, "rpm", "rpm-2025", day)

    def test_duplicate_key_material_or_untrusted_distribution_path_fails(self) -> None:
        document = self.document()
        duplicate = copy.deepcopy(document["rpm"]["trusted_keys"][0])
        duplicate["id"] = "rpm-alias"
        document["rpm"]["trusted_keys"].append(duplicate)
        with self.assertRaisesRegex(gate.SignatureGateError, "fingerprint is duplicated"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document = self.document()
        document["rpm"]["trusted_keys"][0]["public_key"] = "rpm-public.asc"
        with self.assertRaisesRegex(gate.SignatureGateError, "path is unsafe"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_duplicate_public_key_digest_with_distinct_fingerprint_fails(self) -> None:
        document = self.document()
        duplicate = copy.deepcopy(document["rpm"]["trusted_keys"][0])
        duplicate["id"] = "rpm-alias"
        duplicate["fingerprint"] = "A" * 40
        document["rpm"]["trusted_keys"].append(duplicate)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "public-key bytes are duplicated"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_cross_family_key_ids_and_public_key_bytes_fail_closed(self) -> None:
        document = self.document()
        document["apk"]["trusted_keys"][0]["id"] = "rpm-2026"
        with self.assertRaisesRegex(
            gate.SignatureGateError, "IDs must be globally unique"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document = self.document()
        document["deb"]["trusted_keys"][0]["public_key_sha256"] = document[
            "rpm"
        ]["trusted_keys"][0]["public_key_sha256"]
        with self.assertRaisesRegex(
            gate.SignatureGateError,
            "public-key bytes must be globally unique",
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_rpm_and_deb_openpgp_fingerprints_must_be_distinct(self) -> None:
        document = self.document()
        document["deb"]["trusted_keys"][0]["fingerprint"] = document["rpm"][
            "trusted_keys"
        ][0]["fingerprint"]
        with self.assertRaisesRegex(
            gate.SignatureGateError,
            "RPM and DEB OpenPGP fingerprints must be distinct",
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_rpm_public_key_path_and_armor_fail_closed(self) -> None:
        document = self.document()
        document["rpm"]["trusted_keys"][0]["public_key"] = (
            "native-package-keys/rpm-public.gpg"
        )
        with self.assertRaisesRegex(
            gate.SignatureGateError, "RPM public key filename must use the .asc suffix"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        valid = self.rpm_key.read_bytes()
        private_begin = b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----\n"
        private_end = b"-----END PGP " + b"PRIVATE KEY BLOCK-----\n"
        private = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            + private_begin
            + b"ZmFrZQ==\n"
            + private_end
            + b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        for name, data, message in (
            ("non-ascii", b"\xff\n", "must be ASCII armored"),
            ("duplicate-public-block", valid + valid, "not singular and canonical"),
            ("private-key-marker", private, "must not contain private-key armor"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(gate.SignatureGateError, message):
                    gate.validate_rpm_public_key_container(self.rpm_key, data)

    def test_symlinked_public_key_distribution_directory_fails_closed(self) -> None:
        real_keys = self.root / "real-keys"
        real_keys.mkdir()
        real_key = real_keys / self.rpm_key.name
        real_key.write_bytes(self.rpm_key.read_bytes())
        real_apk_key = real_keys / self.apk_key.name
        real_apk_key.write_bytes(self.apk_key.read_bytes())
        real_deb_key = real_keys / self.deb_key.name
        real_deb_key.write_bytes(self.deb_key.read_bytes())
        self.rpm_key.unlink()
        self.apk_key.unlink()
        self.deb_key.unlink()
        self.keys.rmdir()
        self.keys.symlink_to(real_keys, target_is_directory=True)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "only real directories"
        ):
            gate.key_path(
                self.policy,
                self.document()["rpm"]["trusted_keys"][0],
            )

    def test_symlinked_policy_ancestry_and_writable_key_material_fail_closed(self) -> None:
        linked_parent = self.root / "linked-policy-root"
        linked_parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "policy path must be canonical"
        ):
            gate.key_path(
                linked_parent / self.policy.name,
                self.document()["rpm"]["trusted_keys"][0],
            )

        self.keys.chmod(0o775)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "controlled by the owner"
        ):
            gate.key_path(
                self.policy,
                self.document()["rpm"]["trusted_keys"][0],
            )
        self.keys.chmod(0o755)

        self.rpm_key.chmod(0o664)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "key file is not owner-controlled"
        ):
            gate.key_path(
                self.policy,
                self.document()["rpm"]["trusted_keys"][0],
            )

        self.rpm_key.chmod(0o644)
        self.policy.chmod(0o666)
        with self.assertRaisesRegex(
            gate.SignatureGateError, "policy file is not owner-controlled"
        ):
            gate.key_path(
                self.policy,
                self.document()["rpm"]["trusted_keys"][0],
            )

    def test_rotation_unknown_predecessor_and_cycle_fail_closed(self) -> None:
        document = self.document()
        document["rpm"]["trusted_keys"][0]["supersedes"] = ["missing-key"]
        with self.assertRaisesRegex(gate.SignatureGateError, "unknown rotation"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        old_path = self.keys / "rpm-old.asc"
        old_path.write_bytes(b"old-public-key\n")
        document = self.document()
        old = self.key("rpm-old", old_path, "A" * 40)
        old["supersedes"] = ["rpm-2026"]
        document["rpm"]["trusted_keys"][0]["supersedes"] = ["rpm-old"]
        document["rpm"]["trusted_keys"].append(old)
        with self.assertRaisesRegex(gate.SignatureGateError, "contains a cycle"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_package_digest_or_release_mismatch_fails_closed(self) -> None:
        self.package.write_bytes(b"tampered\n")
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)
        self.package.write_bytes(b"signed-rpm-fixture\n")
        arguments = list(self.arguments("rpm", "rpm-2026"))
        arguments[arguments.index("v4.10.0")] = "v4.10.1"
        self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_rollback_package_cannot_be_substituted_for_target_release(self) -> None:
        rollback = self.root / "syswarden-4.04.2-1.x86_64.rpm"
        rollback.write_bytes(self.package.read_bytes())
        self.package = rollback
        self.write_inventory()
        self.assertEqual(gate.main(self.arguments("rpm", "rpm-2026")), 1)

    def test_rollback_filename_is_rejected_for_every_package_family(self) -> None:
        names = {
            "rpm": "syswarden-4.04.2-1.x86_64.rpm",
            "apk": "syswarden_4.04.2_x86_64.apk",
            "deb": "syswarden_4.04.2_amd64.deb",
        }
        for family, name in names.items():
            with self.subTest(family=family):
                package = self.root / name
                package.write_bytes(f"old-{family}\n".encode("ascii"))
                data = package.read_bytes()
                inventory = {
                    "schema_version": 1,
                    "release": "v4.10.0",
                    "artifacts": [
                        {
                            "name": name,
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        }
                    ],
                }
                with self.assertRaisesRegex(
                    gate.SignatureGateError, "filename is unsupported"
                ):
                    gate.bind_artifact(inventory, package, "v4.10.0", family)

    def test_rhel_package_owned_role_accepts_only_the_distinct_rpm_identity(self) -> None:
        profile = self.root / "syswarden-4.10.0-1.rhelpo.x86_64.rpm"
        profile.write_bytes(b"signed-rhel-package-owned-rpm\n")
        data = profile.read_bytes()
        inventory = {
            "schema_version": 1,
            "release": "v4.10.0",
            "artifacts": [
                {
                    "name": profile.name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            ],
        }
        self.assertEqual(
            gate.bind_artifact(
                inventory,
                profile,
                "v4.10.0",
                "rpm",
                "rhel-package-owned",
            ),
            data,
        )
        with self.assertRaisesRegex(gate.SignatureGateError, "filename is unsupported"):
            gate.bind_artifact(inventory, profile, "v4.10.0", "rpm")
        with self.assertRaisesRegex(gate.SignatureGateError, "valid only for RPM"):
            gate.bind_artifact(
                inventory,
                profile,
                "v4.10.0",
                "deb",
                "rhel-package-owned",
            )

    def test_apk_wrong_key_identity_or_key_bytes_fail_closed(self) -> None:
        self.package = self.root / "syswarden_4.10.0_x86_64.apk"
        self.package.write_bytes(b"signed-apk-fixture\n")
        self.write_inventory()
        self.assertEqual(gate.main(self.arguments("apk", "unknown-apk-key")), 1)

        document = self.document()
        document["apk"]["trusted_keys"][0]["public_key_sha256"] = "f" * 64
        document["apk"]["trusted_keys"][0]["fingerprint"] = "f" * 64
        self.write_policy(document)
        self.assertEqual(gate.main(self.arguments("apk", "apk-2026")), 1)

    def test_deb_decision_is_exact_and_foundation_remains_unqualified(self) -> None:
        document = self.document()
        self.assertEqual(document["deb"]["decision"], "detached-package-signature")
        self.assertEqual(document["deb"]["channel"], "github-release-assets")
        document["deb"]["channel"] = "apt-repository"
        with self.assertRaisesRegex(gate.SignatureGateError, "decision is not exact"):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document = self.document()
        document["status"] = "foundation-not-qualified"
        document["deb"]["implementation"] = "implemented-not-qualified"
        document["publishing"] = True
        with self.assertRaisesRegex(
            gate.SignatureGateError, "publishing approval requires"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document = self.document()
        document["deb"]["trusted_keys"] = []
        with self.assertRaisesRegex(
            gate.SignatureGateError, "reviewed RPM, APK and DEB trusted keys"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

        document = self.document()
        document["deb"]["implementation"] = "implemented-not-qualified"
        with self.assertRaisesRegex(
            gate.SignatureGateError, "requires a qualified DEB"
        ):
            gate.validate_policy(document, gate.parse_day("2026-09-03", "date"))

    def test_deb_detached_signature_binds_key_package_release_and_evidence(self) -> None:
        evidence = self.root / "deb-verification.json"
        arguments = self.deb_arguments() + ("--evidence-output", str(evidence))
        self.assertEqual(gate.main(arguments), 0)
        document = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(document["family"], "deb")
        self.assertEqual(document["mechanism"], "openpgp-detached")
        self.assertEqual(document["key"]["fingerprint"], self.deb_fingerprint)
        self.assertEqual(document["signature"]["name"], self.signature.name)
        self.assertEqual(document["signature"]["created_at"], "2026-09-03T12:00:00Z")

    def test_deb_unsigned_bad_or_wrong_key_signature_fails_closed(self) -> None:
        arguments = self.deb_arguments()
        self.signature.write_bytes(b"")
        self.assertEqual(gate.main(arguments), 1)

        self.deb_arguments()
        self.gpgv = self.tool("gpgv-bad", "exit 1")
        arguments = list(self.arguments("deb", "deb-2026")) + ["--signature", str(self.signature)]
        self.assertEqual(gate.main(tuple(arguments)), 1)

        arguments = self.deb_arguments()
        wrong = "A" * 40
        self.gpgv = self.tool(
            "gpgv-wrong",
            f"printf '%s\\n' '[GNUPG:] NEWSIG' "
            f"'[GNUPG:] KEY_CONSIDERED {wrong} 0' "
            "'[GNUPG:] SIG_ID AAAAAAAAAAAAAAAAAAAA 2026-09-03 1788436800' "
            f"'[GNUPG:] GOODSIG {wrong[-16:]} Wrong' "
            f"'[GNUPG:] VALIDSIG {wrong} 2026-09-03 1788436800 0 4 0 1 8 00 {wrong}'",
        )
        arguments = list(self.arguments("deb", "deb-2026")) + ["--signature", str(self.signature)]
        self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_deb_weak_digest_duplicate_status_and_bad_date_fail_closed(self) -> None:
        for name, hash_algorithm, duplicate, day, epoch in (
            ("sha1", "2", False, "2026-09-03", "1788436800"),
            ("duplicate", "8", True, "2026-09-03", "1788436800"),
            ("bad-date", "8", False, "2026-09-02", "1788436800"),
        ):
            with self.subTest(name=name):
                self.deb_arguments()
                valid = (
                    f"[GNUPG:] VALIDSIG {self.deb_fingerprint} {day} {epoch} "
                    f"0 4 0 1 {hash_algorithm} 00 {self.deb_fingerprint}"
                )
                extra = f"printf '%s\\n' '{valid}'; " if duplicate else ""
                self.gpgv = self.tool(
                    f"gpgv-{name}",
                    f"printf '%s\\n' '[GNUPG:] NEWSIG' "
                    f"'[GNUPG:] KEY_CONSIDERED {self.deb_fingerprint} 0' "
                    "'[GNUPG:] SIG_ID AAAAAAAAAAAAAAAAAAAA 2026-09-03 1788436800' "
                    f"'[GNUPG:] GOODSIG {self.deb_fingerprint[-16:]} Test' '{valid}'; "
                    + extra
                    + "exit 0",
                )
                arguments = list(self.arguments("deb", "deb-2026")) + [
                    "--signature", str(self.signature)
                ]
                self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_deb_signature_container_is_singular_and_bounded(self) -> None:
        arguments = self.deb_arguments()
        self.signature.write_bytes(self.signature.read_bytes() * 2)
        self.assertEqual(gate.main(arguments), 1)

        arguments = self.deb_arguments()
        self.signature.write_bytes(b"x" * (gate.MAX_DEB_SIGNATURE_BYTES + 1))
        self.assertEqual(gate.main(arguments), 1)

    def test_deb_native_revoked_or_weak_signing_key_fails_closed(self) -> None:
        for name, validity, bits in (
            ("revoked", "r", 4096),
            ("weak", "-", 2048),
        ):
            with self.subTest(name=name):
                arguments = self.deb_arguments()
                self.gpg = self.tool(
                    f"gpg-deb-{name}",
                    f"printf '%s\\n' "
                    f"'pub:{validity}:{bits}:1:76543210FEDCBA98:1767225600:1798761600:::::sc:' "
                    f"'fpr:::::::::{self.deb_fingerprint}:'",
                )
                arguments = list(self.arguments("deb", "deb-2026")) + [
                    "--signature", str(self.signature)
                ]
                self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_deb_expired_revoked_altered_or_substituted_release_fails_closed(self) -> None:
        arguments = self.deb_arguments()
        document = self.document()
        document["deb"]["trusted_keys"][0]["revoked"] = True
        self.write_policy(document)
        self.assertEqual(gate.main(arguments), 1)

        arguments = self.deb_arguments()
        document = self.document()
        document["deb"]["trusted_keys"][0]["valid_until"] = "2026-09-02"
        self.write_policy(document)
        self.assertEqual(gate.main(arguments), 1)

        self.write_policy()
        arguments = self.deb_arguments()
        self.package.write_bytes(b"altered-deb\n")
        self.assertEqual(gate.main(arguments), 1)

        arguments = list(self.deb_arguments())
        arguments[arguments.index("v4.10.0")] = "v4.10.1"
        self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_duplicate_json_wrong_family_and_unapproved_publishing_fail_closed(self) -> None:
        self.policy.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaisesRegex(gate.SignatureGateError, "duplicate JSON"):
            gate.load_json(self.policy, "policy")

        self.write_policy()
        self.assertEqual(gate.main(self.arguments("apk", "apk-2026")), 1)

        arguments = list(self.arguments("rpm", "rpm-2026"))
        arguments.extend(("--purpose", "publishing"))
        self.assertEqual(gate.main(tuple(arguments)), 1)

    def test_verification_evidence_is_canonical_and_bound(self) -> None:
        evidence = self.root / "rpm-verification.json"
        arguments = self.arguments("rpm", "rpm-2026") + (
            "--evidence-output",
            str(evidence),
        )
        self.assertEqual(gate.main(arguments), 0)
        document = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(document["status"], "verified")
        self.assertEqual(document["release"], "v4.10.0")
        self.assertEqual(document["family"], "rpm")
        self.assertEqual(document["key"]["id"], "rpm-2026")
        self.assertEqual(
            document["key"]["public_key"], "native-package-keys/rpm-public.asc"
        )
        self.assertEqual(
            document["package"]["sha256"],
            hashlib.sha256(self.package.read_bytes()).hexdigest(),
        )
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)

        self.assertEqual(gate.main(arguments), 1)

    def test_verification_evidence_refuses_symlink_output(self) -> None:
        target = self.root / "outside.json"
        evidence = self.root / "rpm-verification.json"
        evidence.symlink_to(target)
        arguments = self.arguments("rpm", "rpm-2026") + (
            "--evidence-output",
            str(evidence),
        )
        self.assertEqual(gate.main(arguments), 1)
        self.assertFalse(target.exists())

    def test_verification_evidence_refuses_unprotected_output_directory(self) -> None:
        unsafe = self.root / "unsafe-output"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        arguments = self.arguments("rpm", "rpm-2026") + (
            "--evidence-output",
            str(unsafe / "rpm-verification.json"),
        )
        self.assertEqual(gate.main(arguments), 1)
        self.assertFalse((unsafe / "rpm-verification.json").exists())


if __name__ == "__main__":
    unittest.main()
