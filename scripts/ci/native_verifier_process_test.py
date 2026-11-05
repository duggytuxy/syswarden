#!/usr/bin/env python3
"""Real-process regression coverage for native verification execution bounds."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_verifier_process as process
    from scripts.ci import native_package_signature_gate as gate
except ModuleNotFoundError:
    import native_verifier_process as process
    import native_package_signature_gate as gate


class NativeVerifierProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = {'PATH': os.environ.get('PATH', ''), 'LC_ALL': 'C'}

    def command(self, source: str) -> list[str]:
        path = self.root / 'verifier.py'
        path.write_text(source, encoding='utf-8')
        return [sys.executable, str(path)]

    def assert_stopped(self, pid: int) -> None:
        until = time.monotonic() + 3
        while time.monotonic() < until:
            try:
                state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == 'Z':
                return
            time.sleep(0.02)
        self.fail('owned verifier descendant is still running')

    def test_exact_channels_stdin_eof_and_nonzero_status(self) -> None:
        result = process.capture(self.command(
            'import os,sys\n'
            'assert sys.stdin.buffer.read() == b""\n'
            'os.write(1,b"first\\r\\nsecond\\xff\\x00")\n'
            'os.write(2,b"logger\\r\\n\\xfe")\n'
            'raise SystemExit(7)\n'
        ), self.environment)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b'first\r\nsecond\xff\x00')
        self.assertEqual(result.stderr, b'logger\r\n\xfe')

    def test_simultaneous_channels_at_exact_limit_do_not_deadlock(self) -> None:
        result = process.capture(self.command(
            'import os,threading\n'
            'def write(fd,byte):\n'
            ' for _ in range(128): os.write(fd,byte*256)\n'
            'a=threading.Thread(target=write,args=(1,b"o"));a.start()\n'
            'write(2,b"e");a.join()\n'
        ), self.environment, channel_limit=32768)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'o' * 32768)
        self.assertEqual(result.stderr, b'e' * 32768)

    def test_each_channel_overflow_is_refused_while_child_still_runs(self) -> None:
        for channel in (1, 2):
            with self.subTest(channel=channel):
                started = time.monotonic()
                with self.assertRaisesRegex(process.VerifierProcessError, 'channel bound'):
                    process.capture(self.command(
                        f'import os\nwhile True: os.write({channel},b"PRIVATE-VERIFIER-TEXT"*1024)\n'
                    ), self.environment, timeout=5, channel_limit=32768)
                self.assertLess(time.monotonic() - started, 4)

    def test_deadline_handles_silence_and_closed_streams(self) -> None:
        for close in (False, True):
            with self.subTest(close=close):
                started = time.monotonic()
                code = 'import os,time\n'
                if close:
                    code += 'os.close(1);os.close(2)\n'
                code += 'time.sleep(60)\n'
                with self.assertRaisesRegex(process.VerifierProcessError, 'deadline'):
                    process.capture(self.command(code), self.environment, timeout=0.2)
                self.assertLess(time.monotonic() - started, 3)

    def test_inherited_pipes_cannot_outlive_deadline(self) -> None:
        pidfile = self.root / 'descendant.pid'
        code = (
            'import os,time\nfrom pathlib import Path\n'
            'pid=os.fork()\n'
            'if pid==0:\n time.sleep(60)\n os._exit(0)\n'
            f'Path({str(pidfile)!r}).write_text(str(pid))\n'
            'os._exit(0)\n'
        )
        with self.assertRaisesRegex(process.VerifierProcessError, 'deadline'):
            process.capture(self.command(code), self.environment, timeout=0.5)
        self.assert_stopped(int(pidfile.read_text()))

    def test_success_reaps_leader_and_stops_private_group_descendants(self) -> None:
        pidfile = self.root / 'descendant.pid'
        code = (
            'import os,time\nfrom pathlib import Path\n'
            'pid=os.fork()\n'
            'if pid==0:\n os.close(1);os.close(2);time.sleep(60)\n os._exit(0)\n'
            f'Path({str(pidfile)!r}).write_text(str(pid))\n'
            'os.write(1,b"verified\\n")\n'
            'os._exit(0)\n'
        )
        result = process.capture(self.command(code), self.environment, timeout=5)
        self.assertEqual((result.returncode, result.stdout), (0, b'verified\n'))
        self.assert_stopped(int(pidfile.read_text()))

    def test_nondefault_child_reaping_refuses_before_launch(self) -> None:
        with mock.patch.object(process.signal, 'getsignal', return_value=process.signal.SIG_IGN), \
                mock.patch.object(process.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(process.VerifierProcessError, 'child-reaping'):
                process.capture([sys.executable, '-V'], self.environment)
            launch.assert_not_called()

    def test_bound_validation_and_launch_failure(self) -> None:
        for options in ({'timeout': 0}, {'timeout': float('nan')}, {'timeout': 61},
                        {'channel_limit': True}, {'channel_limit': 0},
                        {'channel_limit': process.MAX_CHANNEL_BYTES + 1}):
            with self.subTest(options=options), self.assertRaises(process.VerifierProcessError):
                process.capture([sys.executable, '-V'], self.environment, **options)
        for command in ([], [''], [sys.executable, 'bad\x00argument']):
            with self.subTest(command=command), self.assertRaises(process.VerifierProcessError):
                process.capture(command, self.environment)
        with self.assertRaises(process.VerifierProcessError):
            process.capture(['/does/not/exist'], self.environment)
        with self.assertRaises(process.VerifierProcessError):
            process.capture([sys.executable, '-V'], {'INVALID': 'value\x00'})

    def test_native_gate_never_publishes_failed_or_nontext_output(self) -> None:
        for code in ('import sys\nprint("PRIVATE-KEY-CANARY");sys.exit(2)\n',
                     'import os\nos.write(1,b"\\xffPRIVATE-KEY-CANARY")\n'):
            with self.subTest(code=code), self.assertRaises(gate.SignatureGateError) as caught:
                gate.run(self.command(code), 'native fixture')
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_gpgv_status_and_logger_raw_bytes_are_preserved(self) -> None:
        status = b'[GNUPG:] NEWSIG\r\n[GNUPG:] GOODSIG 0123456789ABCDEF Fixture\r\n'
        logger = b'private logger\r\n\xff\n'
        records, actual_status, actual_logger = gate.run_gpgv_status_capture(self.command(
            f'import os\nos.write(1,{status!r});os.write(2,{logger!r})\n'
        ))
        self.assertEqual(records, [('NEWSIG', []), ('GOODSIG', ['0123456789ABCDEF', 'Fixture'])])
        self.assertEqual(actual_status, status)
        self.assertEqual(actual_logger, logger)
        with self.assertRaises(gate.SignatureGateError):
            gate.run_gpgv_status_capture(self.command('import os\nos.write(1,b"[GNUPG:] \\xff")\n'))


if __name__ == '__main__':
    unittest.main()
