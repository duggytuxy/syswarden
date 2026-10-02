"""Reject binary differences outside the exact reviewed continuity allowance."""
import struct
import unittest
from scripts.ci import release_ivv_v4101_payload as p


def elf(current=False):
    sha, stamp = (p.NEW_SHA, p.NEW_TIME) if current else (p.OLD_SHA, p.OLD_TIME)
    metadata = b'vcs.revision=' + sha + b'\nvcs.time=' + stamp + b'\nvcs.modified=false\n'
    rows = [('', b''), ('.text', b'unchanged-code'), ('.rodata', metadata),
            ('.go.buildinfo', metadata), ('.note.go.buildid', b'H' * 16 + (b'b' if current else b'a') * 84),
            ('.note.gnu.build-id', b'H' * 16 + (b'b' if current else b'a') * 20)]
    names = b'\0'; indexes = {}
    for name, _ in rows[1:] + [('.shstrtab', b'')]:
        indexes[name] = len(names); names += name.encode() + b'\0'
    rows.append(('.shstrtab', names))
    data = bytearray(64); data[:6] = b'\x7fELF\x02\x01'; table = []
    for name, wire in rows:
        table.append(struct.pack('<IIQQQQIIQQ', indexes.get(name, 0), 1, 0, 0, len(data), len(wire), 0, 0, 1, 0))
        data.extend(wire)
    struct.pack_into('<Q', data, 40, len(data)); struct.pack_into('<HHH', data, 58, 64, len(rows), len(rows) - 1)
    return bytes(data) + b''.join(table)


class PayloadContinuityTests(unittest.TestCase):
    def test_exact_vcs_and_build_notes_only(self):
        for name in ('core', 'tui'):
            p.verify_binary(name, elf(), elf(True))

    def test_runtime_byte_cannot_hide_behind_metadata_allowance(self):
        bad = bytearray(elf(True)); offset, _ = p.sections(bad)['.text']; bad[offset] ^= 1
        with self.assertRaises(p.frozen.PlanError): p.verify_binary('core', elf(), bytes(bad))

    def test_wrong_revision_time_and_note_header_rejected(self):
        for old, new in ((p.NEW_SHA, b'f' * 40), (p.NEW_TIME, b'2026-10-03T07:13:47Z')):
            with self.assertRaises(p.frozen.PlanError):
                p.verify_binary('tui', elf(), elf(True).replace(old, new))
        bad = bytearray(elf(True)); offset, _ = p.sections(bad)['.note.go.buildid']; bad[offset] ^= 1
        with self.assertRaises(p.frozen.PlanError): p.verify_binary('core', elf(), bytes(bad))

    def test_unknown_binary_and_bad_elf_rejected(self):
        with self.assertRaises(p.frozen.PlanError): p.verify_binary('extra', elf(), elf(True))
        with self.assertRaises(p.frozen.PlanError): p.sections(b'not an ELF')

    def test_substituted_packages_and_ar_shapes_rejected(self):
        for a, b in ((b'', b''), (b'synthetic native', b'synthetic product')):
            with self.assertRaises(p.frozen.PlanError): p.verify(a, b)
        for data in (b'', b'!<arch>\n', b'!<arch>\n' + b'x' * 60):
            with self.assertRaises(p.frozen.PlanError): p.ar_members(data)


if __name__ == '__main__': unittest.main()
