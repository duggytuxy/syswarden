"""Recompute the bounded 1ac64-to-8611 DEB payload continuity allowance."""
from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import PurePosixPath
import struct
import tarfile

try:
    from scripts.ci import release_ivv_plan as frozen
except ModuleNotFoundError:
    import release_ivv_plan as frozen

require = frozen.require
NATIVE = '3d4e008d8a73c9733d982bfecaf1760c53daa56780464750567f6911e09dc8c4'
PRODUCT = '97fc84d1273227c0887349534b93c3725299313b72a9c3ce2370c2aec4eee720'
OLD_SHA = b'1ac64bc56ee4b4ea9233713f94f415719b9f5ec0'
NEW_SHA = b'8611c84cb8c245195dd5456bebad13a52b1d7217'
OLD_TIME = b'2026-10-01T22:32:59Z'
NEW_TIME = b'2026-10-02T07:13:47Z'
LIMIT = 128 * 1024 * 1024


def ar_members(wire: bytes) -> dict[str, bytes]:
    require(wire.startswith(b'!<arch>\n') and len(wire) < LIMIT, 'invalid DEB archive')
    offset, result = 8, {}
    while offset < len(wire):
        header = wire[offset:offset + 60]
        require(len(header) == 60 and header[58:] == b'`\n', 'truncated ar header')
        name = header[:16].decode('ascii').strip().removesuffix('/')
        require(name in ('debian-binary', 'control.tar.gz', 'data.tar.gz') and name not in result,
                'unexpected or duplicate DEB member')
        raw_size = header[48:58].strip()
        require(raw_size.isdigit(), 'invalid ar member size')
        size = int(raw_size); offset += 60
        require(0 < size < LIMIT and offset + size <= len(wire), 'oversized ar member')
        result[name] = wire[offset:offset + size]; offset += size
        if offset % 2:
            require(wire[offset:offset + 1] == b'\n', 'invalid ar alignment')
            offset += 1
    require(set(result) == {'debian-binary', 'control.tar.gz', 'data.tar.gz'}
            and result['debian-binary'] == b'2.0\n', 'incomplete DEB inventory')
    return result


def tar_members(wire: bytes) -> dict:
    result = {}
    with tarfile.open(fileobj=io.BytesIO(wire), mode='r:gz') as archive:
        entries = archive.getmembers()
        require(0 < len(entries) < 100 and sum(m.size for m in entries) < LIMIT,
                'invalid expanded package inventory')
        for member in entries:
            name = member.name.removeprefix('./').rstrip('/')
            require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                    and name not in result and (name or member.isdir()), 'unsafe payload path')
            require(member.isfile() or member.isdir() or member.issym(), 'unsafe payload entry')
            data = archive.extractfile(member).read() if member.isfile() else b''
            result[name] = dict(kind=member.type, mode=member.mode, uid=member.uid,
                               gid=member.gid, link=member.linkname, data=data)
    return result


def sections(wire: bytes) -> dict[str, tuple[int, int]]:
    require(len(wire) >= 64 and wire[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian')
    offset = struct.unpack_from('<Q', wire, 40)[0]
    size, count, strings_index = struct.unpack_from('<HHH', wire, 58)
    require(size == 64 and 0 < count < 100 and strings_index < count
            and offset + size * count <= len(wire), 'invalid ELF section table')
    rows = [struct.unpack_from('<IIQQQQIIQQ', wire, offset + i * size) for i in range(count)]
    names_row = rows[strings_index]
    names = wire[names_row[4]:names_row[4] + names_row[5]]
    result = {}
    for row in rows:
        require(row[0] < len(names), 'invalid ELF section name')
        name = names[row[0]:].split(b'\0', 1)[0].decode('ascii')
        require(name not in result, 'duplicate ELF section')
        if row[1] == 8:  # SHT_NOBITS has no bytes in the file.
            continue
        require(row[4] + row[5] <= len(wire), 'ELF section exceeds file')
        result[name] = row[4], row[5]
    return result


def verify_binary(name: str, original: bytes, product: bytes) -> None:
    require(name in ('cli', 'core', 'tui') and len(original) == len(product), 'binary shape changed')
    old_sections, new_sections = sections(original), sections(product)
    require(old_sections == new_sections, 'binary section layout changed')
    a, b = bytearray(original), bytearray(product)
    for section in ('.rodata', '.go.buildinfo'):
        start, length = old_sections[section]
        old = bytes(a[start:start + length]); new = bytes(b[start:start + length])
        for prior, current in ((OLD_SHA, NEW_SHA), (OLD_TIME, NEW_TIME)):
            require(old.count(prior) == new.count(current) == 1, 'unexpected VCS metadata occurrence')
            old = old.replace(prior, current)
        a[start:start + length] = old
    for section in ('.note.go.buildid', '.note.gnu.build-id'):
        start, length = old_sections[section]
        require(length == (100 if section == '.note.go.buildid' else 36), 'unexpected build note')
        # Preserve the note header. Only the digest/identifier payload differs.
        require(a[start:start + 16] == b[start:start + 16], 'build note header changed')
        a[start + 16:start + length] = b[start + 16:start + length]
    if name == 'cli':
        # Reviewed compiler immediates in exactRHELPackageOwnedRPMIdentity and
        # validateInstalledStandardRPMRelease, followed by the three RHEL
        # identity strings. Source impact separately proves only those constants changed.
        locations = {'.text': (6214048, 6655633), '.rodata': (29518, 200827, 457439)}
        for section, offsets in locations.items():
            start, length = old_sections[section]
            for offset in offsets:
                require(offset < length and a[start + offset] == ord('0')
                        and b[start + offset] == ord('1'), 'RHEL identity byte differs from review')
                a[start + offset] = b[start + offset]
    require(a == b, 'binary difference exceeds the reviewed metadata and RHEL identities')


def verify(native: bytes, product: bytes) -> None:
    require(frozen.digest(native) == NATIVE and frozen.digest(product) == PRODUCT,
            'native or product package identity was substituted')
    old_ar, new_ar = ar_members(native), ar_members(product)
    old, new = tar_members(old_ar['data.tar.gz']), tar_members(new_ar['data.tar.gz'])
    require(old.keys() == new.keys(), 'package payload inventory changed')
    binaries = {'opt/syswarden/bin/syswarden-' + n: n for n in ('cli', 'core', 'tui')}
    for path in old:
        x, y = old[path], new[path]
        require({k: v for k, v in x.items() if k != 'data'} ==
                {k: v for k, v in y.items() if k != 'data'}, 'payload metadata changed')
        if path in binaries:
            verify_binary(binaries[path], x['data'], y['data'])
        elif path == 'usr/share/doc/syswarden/changelog.gz':
            a, b = gzip.decompress(x['data']), gzip.decompress(y['data'])
            stamp = b'Thu, 01 Oct 2026 22:32:59 +0000'
            require(a.count(stamp) == 1 and a.replace(stamp, b'Fri, 02 Oct 2026 07:13:47 +0000') == b,
                    'generated FPM changelog differs beyond the source timestamp')
        else:
            require(x['data'] == y['data'], 'unreviewed package payload change')
    ca, cb = tar_members(old_ar['control.tar.gz']), tar_members(new_ar['control.tar.gz'])
    require(ca.keys() == cb.keys(), 'DEB control inventory changed')
    for path in ca:
        if path != 'md5sums':
            require(ca[path] == cb[path], 'DEB control script or metadata changed')
    for control, payload in ((ca, old), (cb, new)):
        rows = {}
        for line in control['md5sums']['data'].decode('ascii').splitlines():
            digest, path = line.split('  ', 1)
            require(path not in rows and path in payload, 'invalid DEB md5 inventory')
            require(hashlib.md5(payload[path]['data'], usedforsecurity=False).hexdigest() == digest,
                    'DEB bookkeeping checksum differs from payload')
            rows[path] = digest
        require(set(rows) == {p for p, r in payload.items() if r['kind'] == tarfile.REGTYPE},
                'DEB bookkeeping inventory incomplete')
