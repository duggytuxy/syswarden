#!/usr/bin/python3
"""Delegate strict native RPM verification to pinned RPM 4 using stdin only.

The host gate remains unchanged. A successful native import publishes one public
key marker in the gate-owned temporary directory. Each checksig call imports that
same key into a fresh isolated RPM database before checking the exact package.
"""
from pathlib import Path
import fcntl
import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile

if sys.flags.optimize:
    raise SystemExit("Native signature verification requires assertions enabled")

os.umask(0o077)
IMAGE = 'sha256:9c045e9162bde53581444d916acf56af7c9cfe26415d1db1c107eeda5610c5d6'
TRUST_ROOT_SHA256 = 'e9c0ffd66f3e6a9addd2b7e347b84e8d92b34d1cc8e4f4f438d02eabe59c3874'
PACKAGES = {
    'syswarden-4.10.0-1.x86_64.rpm': '5d70d52cbaf637630c3eddb63ed1f0175e441ecb32e36b28827e30c3f7abc640',
    'syswarden-4.10.0-1.rhelpo.x86_64.rpm': '21dc2993c109e0e1d3556a46a905f8cf02a2ed9ebc5188550ca6ccbf8f6e873c',
    'syswarden-4.10.1-1.x86_64.rpm': '1dd9d6d5d10a4adeba73d6f6786b2d7611fca32ca80b158adb8e2953bd4fabc8',
    'syswarden-4.10.1-1.rhelpo.x86_64.rpm': 'a50bf06be94671f1dad94099b743ac347f40a978444e4ab4ab1561fe279b8426',
    'syswarden-4.10.2-1.x86_64.rpm': 'ddd8d62f36d37110813bf61338f409fde9e6251514c4f542791609e4dc399d0a',
    'syswarden-4.10.2-1.rhelpo.x86_64.rpm': '4c80b18a455a96c55b13cb1d72e2bfd587e14c05d807d0adc8d89833b810976c',
    'syswarden-4.10.3-1.x86_64.rpm': '1d0076c54d342897ae2f14497330762ed12e45bba0ad263be2635b5510652561',
    'syswarden-4.10.3-1.rhelpo.x86_64.rpm': '34c4333e21902543a9f184eabdf467d81f9721fc7175fdee6231afe8038ac91a',
}
MARKER = 'verified-public-key.asc'


def digest(wire):
    return hashlib.sha256(wire).hexdigest()


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def open_owned_directory(path, prefix):
    assert path.is_absolute() and path.parent == Path('/tmp')
    assert path.name.startswith(prefix) and path.resolve(strict=True) == path
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    meta = os.fstat(descriptor)
    assert stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o700
    assert meta.st_uid == os.geteuid()
    assert (meta.st_dev, meta.st_ino) == (path.lstat().st_dev, path.lstat().st_ino)
    return descriptor


def read_owned(directory, name, maximum):
    assert Path(name).name == name
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600
        assert 0 < before.st_size <= maximum
        wire = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        assert len(wire) == before.st_size and identity(before) == identity(after)
    return wire


args = sys.argv[1:]
assert len(args) in (4, 5) and args[0] == '--dbpath'
db = Path(args[1])
assert db.name == 'rpmdb' and db.is_absolute() and db.resolve(strict=True) == db
parent_fd = open_owned_directory(db.parent, 'syswarden-rpm-verify-')
db_fd = os.open('rpmdb', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
db_meta = os.fstat(db_fd)
assert stat.S_ISDIR(db_meta.st_mode) and stat.S_IMODE(db_meta.st_mode) == 0o700
assert db_meta.st_uid == os.geteuid()
assert (db_meta.st_dev, db_meta.st_ino) == (db.lstat().st_dev, db.lstat().st_ino)
fcntl.flock(db_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

if len(args) == 4:
    assert args[2] == '--import' and Path(args[3]) == db.parent / 'rpm-public.asc'
    assert os.listdir(db_fd) == []
    key = read_owned(parent_fd, 'rpm-public.asc', 65536)
    assert digest(key) == TRUST_ROOT_SHA256
    mode = 'import'
    package_sha = ''
    files = {'key.asc': key}
else:
    assert args[2:4] == ['--checksig', '--verbose']
    assert os.listdir(db_fd) == [MARKER]
    key = read_owned(db_fd, MARKER, 65536)
    assert digest(key) == TRUST_ROOT_SHA256
    package = Path(args[4])
    assert package.name in PACKAGES and package.resolve(strict=True) == package
    package_fd = open_owned_directory(package.parent, 'syswarden-native-package-')
    wire = read_owned(package_fd, package.name, 32 * 1024 * 1024)
    os.close(package_fd)
    package_sha = PACKAGES[package.name]
    assert digest(wire) == package_sha
    mode = 'verify'
    files = {'key.asc': key, 'package.rpm': wire}

buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
    for name, wire in files.items():
        entry = tarfile.TarInfo(name)
        entry.size = len(wire)
        entry.mode = 0o600
        archive.addfile(entry, io.BytesIO(wire))

INNER = r'''
from pathlib import Path
import hashlib, io, os, subprocess, sys, tarfile
os.umask(0o077)
mode, expected_package = sys.argv[1:]
assert mode in ('import', 'verify') and os.geteuid() == 1000
assert subprocess.check_output(['/usr/bin/rpmkeys', '--version'], text=True, timeout=10).strip() == 'RPM version 4.19.1.1'
root = Path('/tmp/verifier'); root.mkdir(mode=0o700)
expected = {'key.asc'} if mode == 'import' else {'key.asc', 'package.rpm'}
data = sys.stdin.buffer.read(34 * 1024 * 1024 + 1)
assert len(data) <= 34 * 1024 * 1024
with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
    members = archive.getmembers()
    assert len(members) == len(expected) and {m.name for m in members} == expected
    for member in members:
        assert member.type == tarfile.REGTYPE and not member.pax_headers and member.mode == 0o600
        assert 0 < member.size <= (65536 if member.name == 'key.asc' else 32 * 1024 * 1024)
        wire = archive.extractfile(member).read(); assert len(wire) == member.size
        expected_sha = 'e9c0ffd66f3e6a9addd2b7e347b84e8d92b34d1cc8e4f4f438d02eabe59c3874' if member.name == 'key.asc' else expected_package
        assert hashlib.sha256(wire).hexdigest() == expected_sha
        with (root / member.name).open('xb') as out: out.write(wire)
db = root / 'rpmdb'; db.mkdir(mode=0o700)
result = subprocess.run(['/usr/bin/rpmkeys', '--dbpath', str(db), '--import', str(root / 'key.asc')], capture_output=True, timeout=15)
sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
if result.returncode or mode == 'import':
    raise SystemExit(result.returncode)
result = subprocess.run(['/usr/bin/rpmkeys', '--dbpath', str(db), '--checksig', '--verbose', str(root / 'package.rpm')], capture_output=True, timeout=15)
sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
'''
command = [
    '/usr/bin/podman', 'run', '--rm', '-i', '--pull=never', '--network=none',
    '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
    '--pids-limit=64', '--memory=256m', '--cpus=1', '--user=1000:1000', '--timeout=45',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,mode=1777,size=80m',
    '--env=LC_ALL=C', '--env=TZ=UTC', '--entrypoint=/usr/bin/python3',
    IMAGE, '-I', '-B', '-c', INNER, mode, package_sha,
]
result = subprocess.run(command, input=buffer.getvalue(), capture_output=True, timeout=55)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
if result.returncode == 0 and mode == 'import':
    assert os.listdir(db_fd) == []
    current = os.stat('rpmdb', dir_fd=parent_fd, follow_symlinks=False)
    assert (current.st_dev, current.st_ino) == (db_meta.st_dev, db_meta.st_ino)
    descriptor = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=db_fd)
    with os.fdopen(descriptor, 'wb') as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(key); out.flush(); os.fsync(out.fileno())
        meta = os.fstat(out.fileno())
        assert stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1 and meta.st_uid == os.geteuid()
    os.fsync(db_fd)
os.close(db_fd)
os.close(parent_fd)
raise SystemExit(result.returncode)
