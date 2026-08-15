#!/usr/bin/env python3

from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
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
                ("+MANIFEST", {"name": "syswarden", "version": "4.02.10", "files": {}}),
            ):
                payload = (json.dumps(document) + "\n").encode()
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(payload))
            payload = b"binary"
            member = tarfile.TarInfo("/usr/local/syswarden/bin/syswarden-cli")
            member.size = len(payload)
            member.mode = 0o750
            archive.addfile(member, io.BytesIO(payload))

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
            for name in subject.MANIFEST_NAMES:
                stream = archive.extractfile(name)
                self.assertIsNotNone(stream)
                document = json.loads(stream.read())
                self.assertEqual(
                    document["deps"], subject.FREEBSD_RUNTIME_DEPENDENCIES
                )

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
