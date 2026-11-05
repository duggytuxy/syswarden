"""Safety and failure accounting for isolated native dependency observations."""
import gzip
import hashlib
import io
import json
import os
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock

import native_dependency_transition_probe as probe


class NativeDependencyProbeTests(unittest.TestCase):
    def identity(self, directory=Path('/tmp')):
        helpers = probe.isolation_helpers()
        return helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + '1' * 32, '2' * 32,
                                         directory / 'fresh.cid')

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
                probe.sandbox_command('/usr/bin/podman', image, 'deb', 'fresh', self.identity())
        for format_name, case in (('apk', 'fresh'), ('rpm', 'fresh; rm -rf /')):
            with self.assertRaises(ValueError):
                probe.sandbox_command('/usr/bin/podman', 'a' * 64, format_name, case, self.identity())
        args = probe.sandbox_command('/usr/bin/podman', 'a' * 64, 'rpm', 'fresh', self.identity())
        options = args[:args.index('a' * 64)]
        for option, value in (('--network', 'none'), ('--pull', 'never'), ('--cap-drop', 'all'),
                              ('--cap-add', 'SYS_CHROOT'), ('--security-opt', 'no-new-privileges'),
                              ('--cpus', '2'), ('--timeout', '90'), ('--entrypoint', '/bin/sh')):
            self.assertEqual(options[options.index(option) + 1], value)
        self.assertEqual(args[1], '--remote=false')
        self.assertIn('--image-volume=ignore', options)
        self.assertEqual(options[options.index('--name') + 1], self.identity().name)
        self.assertEqual(options[options.index('--cidfile') + 1], str(self.identity().cidfile))
        self.assertEqual(options[options.index('--label') + 1], probe.isolation_helpers().OWNER_LABEL + '=' + self.identity().token)
        for forbidden in ('--privileged', '--mount', '--volume', '-v', '--rm'):
            self.assertNotIn(forbidden, options)

    def test_root_refused_before_any_command(self):
        with mock.patch.object(probe.os, 'geteuid', return_value=0), mock.patch.object(probe, 'command') as cmd:
            with self.assertRaisesRegex(ValueError, 'unprivileged'):
                probe.run(Path('/unused'), 'a' * 64, 'deb', Path('/unused-output'))
            cmd.assert_not_called()

    def fixture_run(self, root, format_name, case, output, architecture='amd64', native=False, exit_status=0,
                    package_name='syswarden', cleanup=True):
        nfpm = root / 'nfpm'; nfpm.write_bytes(b'inert'); nfpm.chmod(0o700)
        retention = None
        if native:
            retention = root / 'retention.test'; retention.write_bytes(b'inert'); retention.chmod(0o700)
        responses = [subprocess.CompletedProcess([], 0, b'true\n'),
                     subprocess.CompletedProcess([], 0, json.dumps([{'Id': 'a' * 64, 'Os': 'linux', 'Architecture': architecture}]).encode())]
        with mock.patch.object(probe.os, 'geteuid', return_value=1000), \
                mock.patch.object(probe.shutil, 'which', return_value='/usr/bin/podman'), \
                mock.patch.object(probe, 'CASES', (case,)), \
                mock.patch.object(probe, 'NATIVE_CASES', (case,)), \
                mock.patch.object(probe.isolation_helpers(), 'execute_local', side_effect=responses) as local, \
                mock.patch.object(probe, 'run_container', return_value=(subprocess.CompletedProcess([], exit_status, output), {'cleanup': {'verified': cleanup}})), \
                mock.patch.object(probe, 'fixtures', return_value=b'inert') as build:
            try:
                probe.run(nfpm, 'a' * 64, format_name, root / 'results', retention, package_name, case)
            finally:
                self.builds = build.call_count
                self.built_snapshot = build.call_args.args[3] if build.call_args else None
                for call in local.call_args_list:
                    self.assertEqual(call.args[0][1], '--remote=false')

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
        marker = b'NATIVE_RETENTION_PASS=/usr/bin/apt-get\nNATIVE_RETENTION_PACKAGE=syswarden\n'
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
                             b'NATIVE_RETENTION_PASS=/usr/bin/dnf\nNATIVE_RETENTION_PACKAGE=syswarden\nCASE_PASS=native-upgrade\n', native=True)
            report = json.loads((root / 'results/results.json').read_text())
            self.assertTrue(report['cases']['native-upgrade']['passed'])
            self.assertEqual(report['retention_test_sha256'], probe.hashlib.sha256(b'inert').hexdigest())
            self.assertIs(type(self.built_snapshot), probe.RetentionBinarySnapshot)
            self.assertEqual(report['retention_test_sha256'], probe.hashlib.sha256(self.built_snapshot.data).hexdigest())
            self.assertEqual(report['retention_test_size'], len(self.built_snapshot.data))

    def test_selected_name_and_case_are_closed_before_building(self):
        self.assertEqual(probe.selected_cases('deb', False, 'syswarden'), probe.CASES)
        self.assertEqual(probe.selected_cases('rpm', True, 'syswarden-base'), ('native-minimal-upgrade',))
        for name in ('', 'syswarden-base;id', 'syswarden-base@local', '../syswarden'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                probe.selected_cases('deb', True, name)
        for native, case in ((False, None), (True, 'native-upgrade'), (True, 'native-minimal')):
            with self.subTest(native=native, case=case), self.assertRaises(ValueError):
                probe.selected_cases('deb', native, 'syswarden-base', case)
        for format_name, case in (('deb', 'native-group-reason'), ('rpm', 'native-held-dependency'),
                                  ('rpm', 'native-purge')):
            with self.assertRaises(ValueError):
                probe.selected_cases(format_name, True, 'syswarden', case)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(probe, 'command') as command:
            root = Path(d)
            with self.assertRaises(ValueError):
                probe.fixtures(root, root / 'nfpm', 'deb', None, 'syswarden-base')
            self.assertEqual(list(root.iterdir()), [])
            command.assert_not_called()

    def test_minimal_fixtures_are_same_name_payload_with_no_optional_dependencies(self):
        for name in probe.PACKAGE_NAMES:
            for format_name in ('deb', 'rpm'):
                with self.subTest(name=name, format=format_name), tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    retention = root / 'retention.test'
                    retention.write_bytes(b'compiled oracle placeholder')
                    retention.chmod(0o700)
                    snapshot = probe.snapshot_retention_binary(retention)
                    def build(args):
                        Path(args[args.index('--target') + 1]).write_bytes(b'inert package placeholder')
                        return subprocess.CompletedProcess(args, 0, b'')
                    with mock.patch.object(probe, 'command', side_effect=build):
                        archive = probe.fixtures(root, root / 'nfpm', format_name, snapshot, name)
                    for stem, version in (('minimal-1.0.0', '1.0.0'), ('model-2.0.0', '2.0.0')):
                        spec = json.loads((root / (stem + '.json')).read_text())
                        self.assertEqual((spec['name'], spec['version'], spec['arch'], spec['platform']),
                                         (name, version, 'amd64', 'linux'))
                        self.assertEqual(spec['contents'][0]['dst'], '/opt/sw-native-lab/model')
                        self.assertEqual(Path(spec['contents'][0]['src']).read_text(), 'model-' + version + '\n')
                        for forbidden in ('depends', 'recommends', 'suggests', 'scripts', 'provides', 'replaces', 'conflicts'):
                            self.assertNotIn(forbidden, spec)
                    if name == 'syswarden':
                        self.assertEqual(json.loads((root / 'model-1.0.0.json').read_text())['depends'], ['rsyslog'])
                    else:
                        self.assertFalse((root / 'model-1.0.0.json').exists())
                    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                        self.assertIn('minimal-1.0.0.' + format_name, tar.getnames())
                        member = tar.getmember('retention.test')
                        self.assertTrue(member.isreg())
                        self.assertEqual(member.mode, 0o700)
                        self.assertEqual(member.linkname, '')
                        self.assertEqual(tar.extractfile(member).read(), snapshot.data)
                        script = tar.extractfile('cases.sh').read().decode()
                    self.assertIn('SYSWARDEN_NATIVE_RETENTION_PACKAGE="$package_name"', script)
                    self.assertIn("expected_writes=0", script)
                    self.assertIn('assert_model 1.0.0', script)
                    self.assertIn('assert_model 2.0.0', script)
                    self.assertIn('effective_fixture_policy=preserve', script)
                    self.assertIn('apt-mark showauto rsyslog', script)
                    self.assertIn('NATIVE_MINIMAL_UPGRADE=%s', script)
                    self.assertNotIn('sw-lab-model', script)
                    self.assertEqual(subprocess.run(['/bin/sh', '-n'], input=script.encode(),
                                     capture_output=True, timeout=5, check=False).returncode, 0)

    def test_minimal_upgrade_requires_exact_name_and_transaction_marker(self):
        for name in probe.PACKAGE_NAMES:
            marker = ('NATIVE_RETENTION_PASS=/usr/bin/apt-get\nNATIVE_RETENTION_PACKAGE=' + name + '\n').encode()
            transaction = ('NATIVE_MINIMAL_UPGRADE=' + name + '\n').encode()
            complete = b'CASE_PASS=native-minimal-upgrade\n'
            for output, success in ((marker + transaction + complete, True),
                                    (marker + complete, False),
                                    (marker + transaction + transaction + complete, False),
                                    (marker + b'NATIVE_RETENTION_PACKAGE=other\n' + transaction + complete, False),
                                    (marker + transaction + b'NATIVE_MINIMAL_UPGRADE=other\n' + complete, False),
                                    (marker.replace(name.encode(), b'other') + transaction + complete, False)):
                with self.subTest(name=name, output=output), tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    if success:
                        self.fixture_run(root, 'deb', 'native-minimal-upgrade', output, native=True, package_name=name)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'native-minimal-upgrade'):
                            self.fixture_run(root, 'deb', 'native-minimal-upgrade', output, native=True, package_name=name)
                    report = json.loads((root / 'results/results.json').read_text())
                    self.assertEqual(report['package_name'], name)
                    self.assertIs(report['cases']['native-minimal-upgrade']['passed'], success)

    def test_success_without_verified_cleanup_fails_qualification(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(RuntimeError, 'fresh'):
                self.fixture_run(root, 'deb', 'fresh', b'CASE_PASS=fresh\n', cleanup=False)
            report = json.loads((root / 'results/results.json').read_text())['cases']['fresh']
            self.assertEqual(report['exit_status'], 0)
            self.assertFalse(report['passed'])
            self.assertFalse(report['container']['cleanup']['verified'])

    def test_container_run_uses_existing_owned_cleanup_on_success_timeout_and_error(self):
        helpers = probe.isolation_helpers()
        outcomes = (subprocess.CompletedProcess([], 0, b'CASE_PASS=fresh\n'),
                    subprocess.TimeoutExpired('podman', 100, output=b'partial\n'),
                    OSError('launch refused'))
        for outcome, expected_status in zip(outcomes, (0, 124, 125)):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                kwargs = {'side_effect': outcome} if isinstance(outcome, BaseException) else {'return_value': outcome}
                with mock.patch.object(helpers, 'container_exists', return_value=False), \
                        mock.patch.object(helpers, 'execute_local', **kwargs) as execute, \
                        mock.patch.object(helpers, 'cleanup_container', return_value={'verified': True}) as cleanup:
                    result, ownership = probe.run_container('/usr/bin/podman', 'a' * 64, 'deb', 'fresh', root, b'payload')
                self.assertEqual(result.returncode, expected_status)
                self.assertTrue(ownership['absent_before'])
                self.assertTrue(ownership['cleanup']['verified'])
                self.assertEqual(cleanup.call_args.kwargs, {'require_cid': expected_status == 0})
                identity = cleanup.call_args.args[1]
                self.assertTrue(identity.name.startswith(helpers.CONTAINER_PREFIX))
                self.assertEqual(identity.cidfile, root / 'fresh.cid')
                args = execute.call_args.args[0]
                self.assertEqual(args[1], '--remote=false')
                self.assertEqual(args[args.index('--name') + 1], identity.name)
                self.assertEqual(args[args.index('--label') + 1], helpers.OWNER_LABEL + '=' + identity.token)
                self.assertEqual(execute.call_args.kwargs, {'timeout': 100, 'input': b'payload'})
                self.assertEqual(json.loads((root / 'fresh.container.json').read_text()), ownership)

    def test_existing_container_or_cid_never_authorizes_launch_or_cleanup(self):
        helpers = probe.isolation_helpers()
        for existing in ('container', 'cid', 'symlink'):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                if existing == 'cid':
                    (root / 'fresh.cid').write_text('3' * 64)
                elif existing == 'symlink':
                    (root / 'fresh.cid').symlink_to(root / 'missing')
                with mock.patch.object(helpers, 'container_exists', return_value=existing == 'container'), \
                        mock.patch.object(helpers, 'execute_local') as execute, \
                        mock.patch.object(helpers, 'cleanup_container') as cleanup:
                    result, ownership = probe.run_container('/usr/bin/podman', 'a' * 64, 'deb', 'fresh', root, b'payload')
                execute.assert_not_called()
                cleanup.assert_not_called()
                self.assertEqual(result.returncode, 125)
                self.assertFalse(ownership['cleanup']['verified'])
                self.assertFalse(ownership['absent_before'])

    def test_retention_binary_rejects_unsafe_inputs_before_open(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'directory', 'empty', 'oversized', 'not-executable'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                path = root / 'retention.test'
                donor = root / 'donor'
                donor.write_bytes(b'binary')
                donor.chmod(0o700)
                if kind == 'symlink':
                    path.symlink_to(donor)
                elif kind == 'hardlink':
                    os.link(donor, path)
                elif kind == 'fifo':
                    os.mkfifo(path, 0o700)
                elif kind == 'directory':
                    path.mkdir(mode=0o700)
                else:
                    path.write_bytes(b'' if kind == 'empty' else b'binary')
                    path.chmod(0o600 if kind == 'not-executable' else 0o700)
                    if kind == 'oversized':
                        with path.open('r+b') as file:
                            file.truncate(probe.MAX_ORACLE_BYTES + 1)
                with mock.patch.object(probe.os, 'open') as opened, self.assertRaises(ValueError):
                    probe.snapshot_retention_binary(path)
                opened.assert_not_called()

    def test_retention_binary_detects_substitution_at_open_without_blocking(self):
        for kind in ('file', 'fifo', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                path = root / 'retention.test'
                path.write_bytes(b'binary')
                path.chmod(0o700)
                donor = root / 'donor'
                donor.write_bytes(b'binary')
                donor.chmod(0o700)
                real_open = os.open
                def substitute(target, flags):
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    self.assertTrue(flags & os.O_NONBLOCK)
                    path.unlink()
                    if kind == 'file':
                        donor.replace(path)
                    elif kind == 'fifo':
                        os.mkfifo(path, 0o700)
                    else:
                        path.symlink_to(donor)
                    return real_open(target, flags)
                with mock.patch.object(probe.os, 'open', side_effect=substitute), self.assertRaises((ValueError, OSError)):
                    probe.snapshot_retention_binary(path)

    def test_retention_snapshot_rejects_later_source_drift(self):
        for kind in ('bytes', 'inode', 'mode', 'link'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                path = root / 'retention.test'
                path.write_bytes(b'original')
                path.chmod(0o700)
                snapshot = probe.snapshot_retention_binary(path)
                if kind == 'bytes':
                    path.write_bytes(b'modified')
                elif kind == 'inode':
                    replacement = root / 'replacement'
                    replacement.write_bytes(snapshot.data)
                    replacement.chmod(0o700)
                    replacement.replace(path)
                elif kind == 'mode':
                    path.chmod(0o755)
                else:
                    os.link(path, root / 'alias')
                self.assertEqual(snapshot.data, b'original')
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    snapshot.recheck()

    def test_source_drift_during_fixture_build_refuses_before_container_launch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            nfpm = root / 'nfpm'
            nfpm.write_bytes(b'caller-trusted tool')
            nfpm.chmod(0o700)
            path = root / 'retention.test'
            path.write_bytes(b'original oracle')
            path.chmod(0o700)
            observed = {}
            def build(output, tool, format_name, snapshot, package_name):
                observed['bytes'] = snapshot.data
                path.write_bytes(b'changed after snapshot')
                return b'archive placeholder'
            responses = [subprocess.CompletedProcess([], 0, b'true\n'),
                         subprocess.CompletedProcess([], 0, json.dumps([{'Id': 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64'}]).encode())]
            with mock.patch.object(probe.os, 'geteuid', return_value=1000), \
                    mock.patch.object(probe.shutil, 'which', return_value='/usr/bin/podman'), \
                    mock.patch.object(probe.isolation_helpers(), 'execute_local', side_effect=responses), \
                    mock.patch.object(probe, 'fixtures', side_effect=build), \
                    mock.patch.object(probe, 'run_container') as launch:
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    probe.run(nfpm, 'a' * 64, 'deb', root / 'results', path,
                              'syswarden-base', 'native-minimal-upgrade')
                launch.assert_not_called()
            self.assertEqual(observed['bytes'], b'original oracle')

    def test_rpm_minimal_unneeded_requests_line_delimited_results_and_diagnoses_failure(self):
        start = probe.SCRIPT.index('assert_rpm_minimal_unneeded() {')
        end = probe.SCRIPT.index('assert_independent_automatic() {', start)
        helper = probe.SCRIPT[start:end]
        for returned, success in (('sw-lab-optional\nwireguard-tools\n', True),
                                  ('wireguard-tools\nsw-lab-optional\n', True),
                                  ('sw-lab-optionalwireguard-tools', False),
                                  ('wireguard-tools\n', False), ('', False)):
            with self.subTest(returned=returned), tempfile.TemporaryDirectory() as d:
                output = Path(d) / 'unneeded'
                stub = r"""dnf_cmd() {
    test "$#" = 7 || return 70
    test "$1" = -q && test "$2" = repoquery && test "$3" = --unneeded || return 71
    test "$4" = --qf && test "$5" = '%{name}\n' || return 72
    test "$6" = sw-lab-optional && test "$7" = wireguard-tools || return 73
    printf '%s' """ + shlex.quote(returned) + '\n}\n'
                script = 'set -eu\n' + stub + helper + 'assert_rpm_minimal_unneeded ' + shlex.quote(str(output)) + '\n'
                result = subprocess.run(['/bin/sh'], input=script.encode(), capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
                self.assertEqual(output.read_text(), returned)
                self.assertEqual(result.stdout, b'')
                if success:
                    self.assertEqual(result.stderr, b'')
                else:
                    self.assertIn(b'NATIVE_UNNEEDED_ASSERTION_FAILED', result.stderr)


if __name__ == '__main__':
    unittest.main()
