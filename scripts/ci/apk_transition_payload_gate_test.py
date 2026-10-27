#!/usr/bin/env python3
"""Regression tests for the launcher-free APK artifact inventory."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apk_transition_payload_gate as gate
import native_package_signing_bundle as signing_bundle


class APKTransitionPayloadGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sw-apk-transition-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        self.scripts = self.root / "scripts"
        self.stage.mkdir(mode=0o755)
        self.scripts.mkdir()
        self.members = []
        for name, entry in gate.TRANSITION_ENTRIES.items():
            if name == ".":
                continue
            path = self.stage / name
            member = tarfile.TarInfo(name)
            member.mode = entry.mode
            if entry.kind == "directory":
                path.mkdir(mode=entry.mode)
                member.type = tarfile.DIRTYPE
                data = b""
            else:
                if name == gate.package_stage_gate.native_activation_descriptor.DESCRIPTOR_PATH:
                    data = gate.package_stage_gate.native_activation_descriptor.expected_descriptor(self.stage)
                else:
                    data = (name + "\n").encode("ascii")
                path.write_bytes(data)
                path.chmod(entry.mode)
                member.size = len(data)
            self.members.append((member, data))
        self.controls = []
        for name, source in {".PKGINFO": None, **gate.HOOKS}.items():
            data = b"pkgname = syswarden\npkgver = 5.00.0-r0\n" if source is None else b"#!/bin/sh\nexit 0\n"
            member = tarfile.TarInfo(name)
            member.mode = 0o644 if source is None else 0o755
            member.size = len(data)
            self.controls.append((member, data))
            if source is not None:
                path = self.scripts / source
                path.write_bytes(data)
                path.chmod(0o755)
        self.archive = self.root / "candidate.apk"

    @staticmethod
    def tar_bytes(members, ending=True):
        data = bytearray()
        for member, content in members:
            data.extend(member.tobuf(format=tarfile.USTAR_FORMAT))
            data.extend(content)
            data.extend(bytes((-len(content)) % 512))
        if ending:
            data.extend(bytes(1024))
        return bytes(data)

    def write_archive(self, members=None, signature=False):
        wire = b""
        if signature:
            member = tarfile.TarInfo(".SIGN.RSA.fixture.rsa.pub")
            member.mode, member.size = 0o644, 7
            wire += gzip.compress(self.tar_bytes([(member, b"fixture")], False))
        wire += gzip.compress(self.tar_bytes(self.controls, False))
        wire += gzip.compress(self.tar_bytes(self.members if members is None else members))
        self.archive.write_bytes(wire)

    @staticmethod
    def signature_prefix(name, metadata=None):
        # Same bounded public framing as the pinned abuild producer and bundle
        # validator. Inert signature bytes do not assert cryptographic validity.
        member = tarfile.TarInfo(name)
        member.mode, member.size, member.mtime = 0o644, 256, 1780000000
        member.pax_headers = {} if metadata is None else metadata
        wire = member.tobuf(format=tarfile.PAX_FORMAT) + b"s" * 256 + bytes(256)
        return gzip.compress(wire, mtime=0)

    def test_official_rsa256_producer_contract_and_legacy_rsa(self):
        name = ".SIGN.RSA256.apk-public.rsa.pub"
        prefix = self.signature_prefix(name, {"atime": "0", "ctime": "0"})
        # Exercise the exact independent signing-bundle contract, including its
        # selected key basename and mandatory timestamp pair.
        observed_name, signature = signing_bundle.validate_apk_signature_archive(
            prefix, "native-package-keys/apk-public.rsa.pub", 1780000000)
        self.assertEqual((observed_name, signature), (name, b"s" * 256))
        for prefix in (prefix, self.signature_prefix(".SIGN.RSA.legacy.rsa.pub")):
            with self.subTest(prefix_hash=hashlib.sha256(prefix).hexdigest()):
                self.write_archive()
                self.archive.write_bytes(prefix + self.archive.read_bytes())
                observed = gate.validate(self.archive, self.stage, self.scripts)
                self.assertIn("opt/syswarden/bin/syswarden-cli", observed)

    def test_signature_names_and_framing_are_exact(self):
        for name in (".SIGN.RSA512.key.rsa.pub", ".SIGN.DSA.key.rsa.pub", ".SIGN.RSA256x.key",
                     ".SIGN.RSA256.", ".SIGN.RSA.", ".SIGN.RSA256..", ".SIGN.RSA256...",
                     ".SIGN.RSA256.key/name", ".SIGN.RSA256.key/../name", "./.SIGN.RSA256.key",
                     ".SIGN.RSA256.key name", ".SIGN.RSA256.key\\name", ".SIGN.RSA256.keyé"):
            with self.subTest(name=name):
                self.write_archive()
                self.archive.write_bytes(self.signature_prefix(name) + self.archive.read_bytes())
                with self.assertRaises(gate.APKTransitionPayloadError):
                    gate.validate(self.archive, self.stage, self.scripts)
        first = self.signature_prefix(".SIGN.RSA256.apk-public.rsa.pub")
        for other, late in ((first, False), (self.signature_prefix(".SIGN.RSA.legacy.rsa.pub"), False), (b"", True)):
            with self.subTest(other=hashlib.sha256(other).hexdigest(), late=late):
                self.write_archive()
                original = self.archive.read_bytes()
                self.archive.write_bytes(original + first if late else first + other + original)
                with self.assertRaises(gate.APKTransitionPayloadError):
                    gate.validate(self.archive, self.stage, self.scripts)

    def test_signature_timestamps_are_exact_and_signature_only(self):
        name = ".SIGN.RSA256.apk-public.rsa.pub"
        for metadata in ({"atime": "0"}, {"ctime": "0"}, {"atime": "1", "ctime": "0"},
                         {"atime": "0.0", "ctime": "0"}, {"atime": "0", "ctime": "0", "mtime": "0"},
                         {"atime": "0", "ctime": "0", "path": name},
                         {"atime": "0", "ctime": "0", "APK-TOOLS.checksum.SHA1": "0" * 40}):
            with self.subTest(metadata=metadata):
                self.write_archive()
                self.archive.write_bytes(self.signature_prefix(name, metadata) + self.archive.read_bytes())
                with self.assertRaises(gate.APKTransitionPayloadError):
                    gate.validate(self.archive, self.stage, self.scripts)
        for misplaced in (".PKGINFO", "opt/syswarden/bin/syswarden-cli"):
            with self.subTest(misplaced=misplaced):
                self.write_archive()
                self.archive.write_bytes(self.signature_prefix(misplaced, {"atime": "0", "ctime": "0"}) + self.archive.read_bytes())
                with self.assertRaises(gate.APKTransitionPayloadError):
                    gate.validate(self.archive, self.stage, self.scripts)

    def test_reference_descriptor_cannot_claim_unbound_runtime_capability(self):
        self.write_archive()
        descriptor = self.stage / gate.package_stage_gate.native_activation_descriptor.DESCRIPTOR_PATH
        descriptor.write_bytes(descriptor.read_bytes().replace(b"approval-v1", b"approval-v9"))
        with self.assertRaises(gate.package_stage_gate.PackageStageError):
            gate.validate(self.archive, self.stage, self.scripts)

    def test_exact_unsigned_build_and_signed_framing(self):
        for signature in (False, True):
            with self.subTest(signature=signature):
                self.write_archive(signature=signature)
                observed = gate.validate(self.archive, self.stage, self.scripts)
                self.assertIn("opt/syswarden/bin/syswarden-cli", observed)
                self.assertNotIn("usr/local", gate.TRANSITION_ENTRIES)
                self.assertNotIn("usr/local/bin/syswarden", gate.TRANSITION_ENTRIES)

    def test_rejects_launcher_subtree_and_member_substitution(self):
        for change in ("parent", "alias", "duplicate", "dot-alias", "unknown", "owner", "mode", "symlink", "hardlink", "fifo", "sparse-file", "contiguous", "missing", "bytes"):
            with self.subTest(change=change):
                members = [(tarfile.TarInfo.frombuf(m.tobuf(), "utf-8", "strict"), data) for m, data in self.members]
                index = next(i for i, (m, _) in enumerate(members) if m.name == "opt/syswarden/bin/syswarden-cli")
                member, content = members[index]
                if change == "parent":
                    extra = tarfile.TarInfo("usr/local")
                    extra.type, extra.mode = tarfile.DIRTYPE, 0o755
                    members.append((extra, b""))
                elif change in ("alias", "unknown"):
                    member.name = "usr/local/bin/syswarden" if change == "alias" else "opt/syswarden/unknown"
                elif change == "duplicate":
                    members.append(members[index])
                elif change == "dot-alias":
                    member.name = "./" + member.name
                elif change == "owner":
                    member.uid = 1000
                elif change == "mode":
                    member.mode = 0o777
                elif change in ("symlink", "hardlink", "fifo"):
                    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[change]
                    member.linkname = "elsewhere" if change != "fifo" else ""
                elif change in ("sparse-file", "contiguous"):
                    member.type = tarfile.GNUTYPE_SPARSE if change == "sparse-file" else tarfile.CONTTYPE
                elif change == "missing":
                    members.pop(index)
                elif change == "bytes":
                    members[index] = member, bytes([content[0] ^ 1]) + content[1:]
                self.write_archive(members)
                with self.assertRaises(gate.APKTransitionPayloadError):
                    gate.validate(self.archive, self.stage, self.scripts)

    def test_refuses_extended_path_rewriting_and_sparse_framing(self):
        for change in ("pax", "gnu-longname", "sparse"):
            with self.subTest(change=change):
                member = tarfile.TarInfo("metadata")
                member.type = {"pax": tarfile.XHDTYPE, "gnu-longname": tarfile.GNUTYPE_LONGNAME, "sparse": tarfile.GNUTYPE_SPARSE}[change]
                member.mode = 0o644
                data = b"31 path=usr/local/bin/syswarden\n"
                member.size = len(data)
                self.write_archive([(member, data)] + self.members)
                with self.assertRaises((gate.APKTransitionPayloadError, tarfile.TarError)):
                    gate.validate(self.archive, self.stage, self.scripts)

    def test_checks_only_the_supported_apk_checksum_extension(self):
        for correct in (True, False):
            with self.subTest(correct=correct):
                index = next(i for i, (m, _) in enumerate(self.members) if m.name == "opt/syswarden/bin/syswarden-cli")
                checksum = hashlib.sha1(self.members[index][1], usedforsecurity=False).hexdigest() if correct else "0" * 40
                record = b"APK-TOOLS.checksum.SHA1=" + checksum.encode("ascii") + b"\n"
                size = len(record) + 3
                data = str(size).encode("ascii") + b" " + record
                self.assertEqual(size, len(data))
                header = tarfile.TarInfo("PaxHeader")
                header.type, header.mode, header.size = tarfile.XHDTYPE, 0o644, len(data)
                self.write_archive(self.members[:index] + [(header, data)] + self.members[index:])
                if correct:
                    gate.validate(self.archive, self.stage, self.scripts)
                else:
                    with self.assertRaises(gate.APKTransitionPayloadError):
                        gate.validate(self.archive, self.stage, self.scripts)

    def test_refuses_reference_drift_and_archive_bounds(self):
        self.write_archive()
        hook = self.scripts / "postinst.sh"
        hook.write_bytes(b"#!/bin/sh\nexit 1\n")
        with self.assertRaises(gate.APKTransitionPayloadError):
            gate.validate(self.archive, self.stage, self.scripts)
        hook.write_bytes(b"#!/bin/sh\nexit 0\n")
        with mock.patch.object(gate, "MAX_EXPANDED_BYTES", 512):
            with self.assertRaises(gate.APKTransitionPayloadError):
                gate.validate(self.archive, self.stage, self.scripts)
        source = self.root / "artifact-link.apk"
        source.symlink_to(self.archive)
        with self.assertRaises(gate.APKTransitionPayloadError):
            gate.validate(source, self.stage, self.scripts)

    def test_rejects_invalid_tar_header_instead_of_skipping_it(self):
        wire = self.tar_bytes(self.controls, False) + b"x" * 512 + self.tar_bytes(self.members)
        self.archive.write_bytes(gzip.compress(wire))
        with self.assertRaises(tarfile.TarError):
            gate.validate(self.archive, self.stage, self.scripts)

    def test_does_not_change_legacy_or_systemd_stage_contracts(self):
        for entries in (gate.package_stage_gate.LINUX_ENTRIES, gate.package_stage_gate.SYSTEMD_LINUX_ENTRIES):
            self.assertIn("usr/local/bin/syswarden", entries)
            self.assertIn("usr/local/bin/syswarden-tui", entries)


if __name__ == "__main__":
    unittest.main()
