"""Safety and failure accounting for isolated native dependency observations."""
import gzip
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_dependency_transition_probe as probe


class NativeDependencyProbeTests(unittest.TestCase):
    def test_group_repository_has_no_packages_and_verified_local_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            paths = probe.group_repository(root, 'rsyslog')
            self.assertEqual(len(paths), 3)
            tree = ET.fromstring((root / 'group-repo/repodata/repomd.xml').read_bytes())
            ns = {'r': 'http://linux.duke.edu/metadata/repo'}
            records = tree.findall('r:data', ns)
            self.assertEqual({item.attrib['type'] for item in records}, {'primary', 'group'})
            for item in records:
                location = item.find('r:location', ns).attrib['href']
                path = root / 'group-repo' / location
                self.assertIn(path, paths)
                packed = path.read_bytes()
                raw = gzip.decompress(packed)
                self.assertEqual(hashlib.sha256(packed).hexdigest(), item.find('r:checksum', ns).text)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item.find('r:open-checksum', ns).text)
                document = ET.fromstring(raw)
                if item.attrib['type'] == 'primary':
                    self.assertEqual(document.attrib['packages'], '0')
                    self.assertEqual(len(document), 0)
                else:
                    self.assertEqual(document.findtext('group/id'), 'sw-lab-group')
                    self.assertEqual(document.findtext('group/packagelist/packagereq'), 'rsyslog')

    def test_group_repository_refuses_arbitrary_scope_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('../rsyslog', '<package/>', 'wireguard-tools', 'rsyslog;id'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    probe.group_repository(root, name)
            self.assertEqual(list(root.iterdir()), [])

    def test_sandbox_inputs_and_boundaries(self):
        for image in ('debian:latest', '-v /:/host', 'a' * 63, 'A' * 64):
            with self.subTest(image=image), self.assertRaises(ValueError):
                probe.sandbox_command('/usr/bin/podman', image, 'deb', 'fresh')
        for format_name, case in (('apk', 'fresh'), ('rpm', 'fresh; rm -rf /')):
            with self.assertRaises(ValueError):
                probe.sandbox_command('/usr/bin/podman', 'a' * 64, format_name, case)
        args = probe.sandbox_command('/usr/bin/podman', 'a' * 64, 'rpm', 'fresh')
        options = args[:args.index('a' * 64)]
        for option, value in (('--network', 'none'), ('--pull', 'never'), ('--cap-drop', 'all'),
                              ('--cap-add', 'SYS_CHROOT'), ('--security-opt', 'no-new-privileges'),
                              ('--cpus', '2'), ('--timeout', '90'), ('--entrypoint', '/bin/sh')):
            self.assertEqual(options[options.index(option) + 1], value)
        for forbidden in ('--privileged', '--mount', '--volume', '-v'):
            self.assertNotIn(forbidden, options)

    def test_root_refused_before_any_command(self):
        with mock.patch.object(probe.os, 'geteuid', return_value=0), mock.patch.object(probe, 'command') as cmd:
            with self.assertRaisesRegex(ValueError, 'unprivileged'):
                probe.run(Path('/unused'), 'a' * 64, 'deb', Path('/unused-output'))
            cmd.assert_not_called()

    def fixture_run(self, root, format_name, case, output, architecture='amd64', native=False, exit_status=0):
        nfpm = root / 'nfpm'; nfpm.write_bytes(b'inert'); nfpm.chmod(0o700)
        retention = None
        if native:
            retention = root / 'retention.test'; retention.write_bytes(b'inert'); retention.chmod(0o700)
        responses = [subprocess.CompletedProcess([], 0, b'true\n'),
                     subprocess.CompletedProcess([], 0, json.dumps([{'Id': 'a' * 64, 'Os': 'linux', 'Architecture': architecture}]).encode()),
                     subprocess.CompletedProcess([], exit_status, output)]
        with mock.patch.object(probe.os, 'geteuid', return_value=1000), \
                mock.patch.object(probe.shutil, 'which', return_value='/usr/bin/podman'), \
                mock.patch.object(probe, 'CASES', (case,)), \
                mock.patch.object(probe, 'NATIVE_CASES', (case,)), \
                mock.patch.object(probe, 'command', side_effect=responses), \
                mock.patch.object(probe, 'fixtures', return_value=b'inert') as build:
            try:
                probe.run(nfpm, 'a' * 64, format_name, root / 'results', retention)
            finally:
                self.builds = build.call_count

    def test_wrong_architecture_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(ValueError, 'AMD64'):
                self.fixture_run(root, 'deb', 'fresh', b'', architecture='unsupported')
            self.assertEqual(self.builds, 0)
            self.assertFalse((root / 'results').exists())

    def test_zero_exit_without_completion_is_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(RuntimeError, 'fresh'):
                self.fixture_run(root, 'deb', 'fresh', b'partial output\n')
            self.assertFalse(json.loads((root / 'results/results.json').read_text())['cases']['fresh']['passed'])

    def test_wrong_observation_cannot_pass(self):
        for format_name, unneeded in (('deb', '1'), ('rpm', '0')):
            with self.subTest(format=format_name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                output = f'OPTIONAL_PRESENT=1\nOPTIONAL_UNNEEDED={unneeded}\nCASE_PASS=single-transaction\n'.encode()
                with self.assertRaisesRegex(RuntimeError, 'single-transaction'):
                    self.fixture_run(root, format_name, 'single-transaction', output)
                result = json.loads((root / 'results/results.json').read_text())['cases']['single-transaction']
                self.assertFalse(result['passed'])
                self.assertEqual(result['exit_status'], 0)

    def test_native_differences_are_preserved(self):
        for format_name, unneeded in (('deb', '0'), ('rpm', '1')):
            with self.subTest(format=format_name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                self.fixture_run(root, format_name, 'single-transaction',
                                 f'OPTIONAL_PRESENT=1\nOPTIONAL_UNNEEDED={unneeded}\nCASE_PASS=single-transaction\n'.encode())
                self.assertTrue(json.loads((root / 'results/results.json').read_text())['cases']['single-transaction']['passed'])

    def test_native_oracle_requires_one_unskipped_success(self):
        marker = b'NATIVE_RETENTION_PASS=/usr/bin/apt-get\n'
        complete = b'CASE_PASS=native-upgrade\n'
        for output, code in ((complete, 0), (marker + marker + complete, 0),
                             (marker + b'--- SKIP: oracle\n' + complete, 0),
                             (marker + complete, 1),
                             (b'NATIVE_RETENTION_PASS=/usr/bin/dnf\n' + complete, 0)):
            with self.subTest(output=output, code=code), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                with self.assertRaisesRegex(RuntimeError, 'native-upgrade'):
                    self.fixture_run(root, 'deb', 'native-upgrade', output, native=True, exit_status=code)
                report = json.loads((root / 'results/results.json').read_text())
                self.assertFalse(report['cases']['native-upgrade']['passed'])

    def test_native_oracle_records_binary_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture_run(root, 'rpm', 'native-upgrade',
                             b'NATIVE_RETENTION_PASS=/usr/bin/dnf\nCASE_PASS=native-upgrade\n', native=True)
            report = json.loads((root / 'results/results.json').read_text())
            self.assertTrue(report['cases']['native-upgrade']['passed'])
            self.assertEqual(report['retention_test_sha256'], probe.hashlib.sha256(b'inert').hexdigest())


if __name__ == '__main__':
    unittest.main()
