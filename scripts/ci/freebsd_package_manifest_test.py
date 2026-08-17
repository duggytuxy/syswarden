#!/usr/bin/env python3

from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts.ci import freebsd_package_manifest as subject


class FreeBSDPackageManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name) / "syswarden.txz"
        with tarfile.open(self.package, "w:xz") as archive:
            for name, document in (
                ("+COMPACT_MANIFEST", {"name": "syswarden", "version": "4.02.10"}),
                (
                    "+MANIFEST",
                    {
                        "name": "syswarden",
                        "version": "4.02.10",
                        "files": {},
                        "scripts": {"pre-install": "#!/bin/sh\nprintf hook\n"},
                    },
                ),
            ):
                payload = (json.dumps(document) + "\n").encode()
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o600
                self.set_hostile_identity(member)
                archive.addfile(member, io.BytesIO(payload))
            payload = b"binary"
            member = tarfile.TarInfo("/usr/local/syswarden/bin/syswarden-cli")
            member.size = len(payload)
            member.mode = 0o750
            self.set_hostile_identity(member)
            archive.addfile(member, io.BytesIO(payload))

    @staticmethod
    def set_hostile_identity(member: tarfile.TarInfo) -> None:
        member.uid = 1234
        member.gid = 5678
        member.uname = "builder"
        member.gname = "builders"
        member.pax_headers = {
            "uid": "1234",
            "gid": "5678",
            "uname": "builder",
            "gname": "builders",
        }

    def rewrite_package(
        self, mutation: Callable[[tarfile.TarInfo], None]
    ) -> None:
        with tarfile.open(self.package, "r:xz") as source:
            members = source.getmembers()
            payloads = {}
            for member in members:
                if not member.isfile():
                    payloads[member.name] = None
                    continue
                stream = source.extractfile(member)
                self.assertIsNotNone(stream)
                payloads[member.name] = stream.read()
        for member in members:
            mutation(member)
        with tarfile.open(
            self.package, "w:xz", format=tarfile.PAX_FORMAT
        ) as target:
            for member in members:
                payload = payloads[member.name]
                target.addfile(
                    member,
                    io.BytesIO(payload) if payload is not None else None,
                )

    def test_finalize_injects_exact_dependencies_and_preserves_payload(self) -> None:
        subject.finalize(self.package)
        subject.verify(self.package)
        with tarfile.open(self.package, "r:xz") as archive:
            self.assertEqual(
                archive.getnames(),
                [
                    "+COMPACT_MANIFEST",
                    "+MANIFEST",
                    "/usr/local/syswarden/bin/syswarden-cli",
                ],
            )
            payload = archive.extractfile(
                "/usr/local/syswarden/bin/syswarden-cli"
            )
            self.assertIsNotNone(payload)
            self.assertEqual(payload.read(), b"binary")
            for member in archive.getmembers():
                self.assertEqual(
                    (
                        member.uid,
                        member.gid,
                        member.uname,
                        member.gname,
                    ),
                    subject.PACKAGE_MEMBER_IDENTITY,
                )
                self.assertTrue(
                    subject.PAX_IDENTITY_FIELDS.isdisjoint(
                        member.pax_headers
                    )
                )
            for name in subject.MANIFEST_NAMES:
                stream = archive.extractfile(name)
                self.assertIsNotNone(stream)
                document = json.loads(stream.read())
                self.assertEqual(
                    document["deps"], subject.FREEBSD_RUNTIME_DEPENDENCIES
                )
            manifest = json.loads(archive.extractfile("+MANIFEST").read())
            self.assertEqual(
                manifest["scripts"]["pre-install"],
                "#!/bin/sh\nprintf hook\n",
            )

    def test_verify_rejects_owner_and_group_drift_for_every_member(self) -> None:
        subject.finalize(self.package)
        baseline = self.package.read_bytes()
        members = (
            "+COMPACT_MANIFEST",
            "+MANIFEST",
            "/usr/local/syswarden/bin/syswarden-cli",
        )
        mutations = {
            "uid": lambda member: setattr(member, "uid", 1000),
            "gid": lambda member: setattr(member, "gid", 1000),
            "uname": lambda member: setattr(member, "uname", "builder"),
            "gname": lambda member: setattr(member, "gname", "builders"),
        }
        for member_name in members:
            for field, mutate_field in mutations.items():
                with self.subTest(member=member_name, field=field):
                    self.package.write_bytes(baseline)

                    def mutate(member: tarfile.TarInfo) -> None:
                        if member.name == member_name:
                            mutate_field(member)

                    self.rewrite_package(mutate)
                    with self.assertRaisesRegex(
                        subject.FreeBSDManifestError,
                        "unexpected owner metadata",
                    ):
                        subject.verify(self.package)

    def test_finalize_rejects_unreviewed_dependency(self) -> None:
        with tarfile.open(self.package, "r:xz") as archive:
            documents = {
                name: json.loads(archive.extractfile(name).read())
                for name in subject.MANIFEST_NAMES
            }
        documents["+COMPACT_MANIFEST"]["deps"] = {
            "unreviewed": {"origin": "x/y", "version": "1"}
        }
        with tarfile.open(self.package, "w:xz") as archive:
            for name, document in documents.items():
                payload = json.dumps(document).encode()
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        with self.assertRaisesRegex(subject.FreeBSDManifestError, "unexpected"):
            subject.finalize(self.package)


if __name__ == "__main__":
    unittest.main()
