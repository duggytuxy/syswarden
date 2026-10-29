#!/usr/bin/env python3
"""Adversarial framing tests, with no native signature or lifecycle claims."""

from __future__ import annotations

import hashlib
import struct
import unittest
from unittest import mock

from scripts.ci import native_rpm_preservation as rpm
from scripts.ci.native_package_identity_evidence_test import rpm_fixture, rpm_header


class RPMPreservationTests(unittest.TestCase):
    def test_signature_region_can_grow_shrink_or_keep_size(self) -> None:
        original = rpm.inspect_content(rpm_fixture("syswarden-base"))
        for value in (b"x", b"replaced", b"s" * 4096):
            with self.subTest(signature_size=len(value)):
                signed = rpm.inspect_content(rpm_fixture("syswarden-base", value))
                rpm.require_preserved(original, signed)
                self.assertEqual(original, signed)
        self.assertEqual(original.compressed_payload_sha256, hashlib.sha256(b"synthetic payload").hexdigest())
        self.assertEqual(original.compressed_payload_size, len(b"synthetic payload"))
        self.assertEqual(original.main_header_sha256, hashlib.sha256(rpm_header(63, b"syswarden-base")).hexdigest())

    def test_content_regions_cannot_change_even_with_identical_sizes(self) -> None:
        wire = rpm_fixture("syswarden")
        original = rpm.inspect_content(wire)
        for offset in (10, len(wire) - len(b"synthetic payload") - 17, len(wire) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(wire)
                changed[offset] ^= 1
                with self.assertRaises(rpm.RPMPreservationError):
                    rpm.require_preserved(original, rpm.inspect_content(bytes(changed)))
        for changed in (wire + b"trailing", wire[:-1], rpm_fixture("another-package")):
            with self.subTest(changed_size=len(changed)), self.assertRaises(rpm.RPMPreservationError):
                rpm.require_preserved(original, rpm.inspect_content(changed))

    def test_every_truncated_framing_prefix_refuses(self) -> None:
        wire = rpm_fixture("syswarden")
        main_end = len(wire) - len(b"synthetic payload")
        for size in range(main_end + 1):
            with self.subTest(size=size), self.assertRaises(rpm.RPMPreservationError):
                rpm.inspect_content(wire[:size])

    def test_input_type_and_total_bound_refuse(self) -> None:
        for value in (None, "rpm", bytearray(rpm_fixture("syswarden")), memoryview(b"rpm")):
            with self.subTest(type=type(value)), self.assertRaises(rpm.RPMPreservationError):
                rpm.inspect_content(value)
        with mock.patch.object(rpm, "MAX_PACKAGE_BYTES", 128), self.assertRaises(rpm.RPMPreservationError):
            rpm.inspect_content(rpm_fixture("syswarden"))
        for args in (({}, {}), (None, None)):
            with self.assertRaises(rpm.RPMPreservationError):
                rpm.require_preserved(*args)

    def test_lead_magic_version_type_and_signature_type_refuse(self) -> None:
        for offset in (0, 4, 5, 6, 78, 79):
            with self.subTest(offset=offset), self.assertRaises(rpm.RPMPreservationError):
                wire = bytearray(rpm_fixture("syswarden"))
                wire[offset] ^= 1
                rpm.inspect_content(bytes(wire))

    def test_signature_and_main_header_bounds_and_regions_refuse(self) -> None:
        base = rpm_fixture("syswarden", b"sig")
        sig_end = 96 + len(rpm_header(62, b"sig"))
        main = (sig_end + 7) & ~7
        for start in (96, main):
            indexes, size = struct.unpack_from(">II", base, start + 8)
            trailer = start + 16 + indexes * 16 + size - 16
            cases = [
                (start, b"badmagic"), (start + 8, struct.pack(">I", 0)),
                (start + 8, struct.pack(">I", rpm.MAX_HEADER_INDEXES + 1)),
                (start + 12, struct.pack(">I", 15)),
                (start + 12, struct.pack(">I", rpm.MAX_HEADER_DATA_BYTES + 1)),
                (start + 12, struct.pack(">I", 0xffffffff)),
                (start + 16, struct.pack(">I", 61)),
                (start + 20, struct.pack(">I", 6)),
                (start + 24, struct.pack(">I", size - 17)),
                (start + 28, struct.pack(">I", 15)),
                (trailer, struct.pack(">I", 61)),
                (trailer + 4, struct.pack(">I", 6)),
                (trailer + 8, struct.pack(">i", -16)),
                (trailer + 12, struct.pack(">I", 15)),
                (start + 32, struct.pack(">I", 62)),
                (start + 36, struct.pack(">I", 10)),
                (start + 40, struct.pack(">I", size - 16)),
                (start + 44, struct.pack(">I", 0)),
                (start + 44, struct.pack(">I", size + 1)),
            ]
            for offset, replacement in cases:
                with self.subTest(start=start, offset=offset, replacement=replacement):
                    changed = bytearray(base)
                    changed[offset:offset + len(replacement)] = replacement
                    with self.assertRaises(rpm.RPMPreservationError):
                        rpm.inspect_content(bytes(changed))
        self.assertGreater(main, sig_end)
        changed = bytearray(base)
        changed[sig_end] = 1
        with self.assertRaisesRegex(rpm.RPMPreservationError, "padding"):
            rpm.inspect_content(bytes(changed))


if __name__ == "__main__":
    unittest.main()
