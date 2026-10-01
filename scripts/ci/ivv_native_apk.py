#!/usr/bin/python3
"""Run native APK verification offline using fixed-name stdin data, no host mounts."""
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

if sys.flags.optimize:
    raise SystemExit("Native signature verification requires assertions enabled")

IMAGE = 'docker.io/alpinelinux/build-base@sha256:31d2a020ccd2058e6ab47940428bd0b7dc83e37b66880891f9ed903a12ea668b'
PUBLIC_CERTIFICATE_FILENAME = 'apk-prod-2026-01.rsa.pub'
assert len(sys.argv) == 5 and sys.argv[1:3] == ['verify', '--keys-dir']
assert os.environ.get('SYSWARDEN_APK_SIGNER_IMAGE') == IMAGE
keys, package = map(Path, sys.argv[3:])
assert keys.is_absolute() and package.is_absolute() and not keys.is_symlink()
assert sorted(p.name for p in keys.iterdir()) == [PUBLIC_CERTIFICATE_FILENAME]
stream = io.BytesIO()
with tarfile.open(fileobj=stream, mode='w') as tar:
    for source, name, limit in ((keys / PUBLIC_CERTIFICATE_FILENAME, PUBLIC_CERTIFICATE_FILENAME, 65536), (package, 'package.apk', 64 * 1024 * 1024)):
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            meta = os.fstat(f.fileno())
            assert stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == os.geteuid()
            assert 0 < meta.st_size < limit
            data = f.read(limit); assert len(data) == meta.st_size
        item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o600
        tar.addfile(item, io.BytesIO(data))
args = ['/usr/bin/podman', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m', '--cpus', '1', '--user', '1000:1000', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,mode=1777,size=80m', '-i', '--entrypoint', '/bin/sh', IMAGE, '-c', 'set -eu; umask 077; mkdir /tmp/verify; tar -xf - -C /tmp/verify; mkdir /tmp/verify/keys; mv /tmp/verify/apk-prod-2026-01.rsa.pub /tmp/verify/keys/; exec /sbin/apk verify --keys-dir /tmp/verify/keys /tmp/verify/package.apk']
result = subprocess.run(args, input=stream.getvalue(), capture_output=True, timeout=55)
sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
