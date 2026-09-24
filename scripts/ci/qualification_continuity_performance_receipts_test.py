#!/usr/bin/env python3
"""Synthetic adversarial fixtures only; these are never native release evidence."""
from __future__ import annotations
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
try:
    from scripts.ci import qualification_continuity_performance_receipts as receipts
except ModuleNotFoundError:
    import qualification_continuity_performance_receipts as receipts


class NativeExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root = Path(self.tmp.name)
        self.environment = self.root / 'environment.json';self.environment.write_text('{"synthetic_test_only":true}\n')
        for key, value in [('SOURCE', hashlib.sha256(b'synthetic-reviewed-source\n').hexdigest()),
                           ('ENVIRONMENT', receipts.sha(self.environment))]:
            patch = mock.patch.object(receipts, key, value);patch.start();self.addCleanup(patch.stop)
        self.sides = [];self.documents = []
        for number, side in enumerate(receipts.SIDES):
            self.sides.append(self.fixture(number, side))

    def fixture(self, number, side):
        directory = self.root / str(number);directory.mkdir();export = directory / 'export';export.mkdir()
        campaign, role = side.rsplit('.', 1);unit = 'syswarden-native-performance-' + side + '-attempt01.service'
        start = datetime(2026, 9, 24, 20, number, tzinfo=timezone.utc)
        stamp = lambda seconds: (start + timedelta(seconds=seconds)).isoformat()
        recorded = start.replace(minute=number - number % 2).strftime('%Y-%m-%dT%H:%M:%SZ')
        binding = {'candidate_commit': receipts.fresh.continuity.RUNTIME, 'campaign_id': campaign,
                   'subject_role': role, 'attempt_id': 'attempt01', 'execution_reviewed': True, 'recorded_at': recorded}
        contract, metrics = receipts.fresh.frozen_tooling()
        sample = {'schema': receipts.fresh.SCHEMA, 'candidate_commit': receipts.fresh.continuity.RUNTIME,
            'campaign_id': campaign, 'subject_role': role, 'recorded_at': recorded, 'contract_id': contract['contract_id'],
            'subject_release': 'v4.04.3' if role == 'baseline' else 'v4.10.0', 'environment_id': receipts.ENVIRONMENT_ID,
            'environment_sha256': receipts.ENVIRONMENT, 'adapter_config_sha256': receipts.CONFIG, 'probe_sha256': receipts.PROBE,
            'adapter_sha256': receipts.fresh.FROZEN['native_performance_adapter.py'], 'frozen_dependencies': receipts.fresh.FROZEN,
            **receipts.fresh.ARTIFACTS[role], 'metrics': {name: {'unit': metrics[name].unit, 'samples':
                [receipts.fresh.SIZES[role][name]] if name in receipts.fresh.probe.SIZE_METRICS else
                [100 + number / 10 + j / 1000 for j in range(10 if name == 'startup_milliseconds' else 1)]}
                for name in receipts.fresh.FRESH}}
        dump = lambda d: (json.dumps(d, sort_keys=True) + '\n').encode()
        props = {'Id': unit, 'MemoryMax': '469762048', 'MemorySwapMax': '134217728', 'TasksMax': '256',
            'CPUQuotaPerSecUSec': '800ms', 'RuntimeMaxUSec': '1h 20min', 'Result': 'success', 'ExecMainStatus': '0',
            'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123', 'ControlGroup': '/system.slice/' + unit}
        events = 'oom 0\noom_kill 0\n';end = {'probe_returncode': 0, 'wrapper_pid': 123, 'observed_at': stamp(3)}
        result_props = dict(props, SubState='exited', MainPID='0', ControlGroup='')
        d = {'START.json': {'bindings': binding, 'started_at': stamp(1)}, 'samples.json': sample,
             'PROBE-EXIT.json': end, 'CGROUP-RELEASE.json': {'probe_returncode': 0, 'counters_captured': True},
             'NATIVE-LIMITS.json': {'observed_at': stamp(2), 'unit_properties': copy.deepcopy(props),
                 'actual_cgroup_files': {'memory.events': events, 'memory.max': '469762048', 'memory.swap.max': '134217728',
                                        'pids.max': '256', 'cpu.max': '80000 100000'}},
             'COMPLETION-CGROUP.json': {'observed_at': stamp(4), 'probe_exit': copy.deepcopy(end),
                 'memory_events': events, 'unit_properties': copy.deepcopy(props)},
             'RESULT.json': {'status': 'actual-native-four-metric-side-complete', 'qualification_gate_passed': False,
                 'candidate_commit': receipts.fresh.continuity.RUNTIME, 'campaign_id': campaign, 'subject_role': role,
                 'sample_sha256': hashlib.sha256(dump(sample)).hexdigest(), 'completion_holder_sha256': receipts.HOLDER,
                 'memory_events_boundary': 'post-probe-before-holder-release', 'memory_events': events,
                 'unit_properties': result_props, 'completed_at': stamp(5)},
             'CLOSED.json': {'unit': unit, 'failure': None, 'product_services_intentionally_preserved': True,
                 'state': 'ActiveState=inactive\nSubState=dead\nMainPID=0\n', 'closed_at': stamp(6)}}
        self.documents.append((d, binding));files = []
        for index, name in enumerate([*d, 'probe.stderr', 'probe.stdout']):
            path = export / (str(index).zfill(4) + '-' + name);path.write_bytes(dump(d[name]) if name in d else b'')
            files.append({'relative_path': 'records/' + side + '.attempt01/' + name, 'local_path': str(path),
                          'bytes': path.stat().st_size, 'sha256': receipts.sha(path)})
        (export / 'INDEX.json').write_bytes(dump({'native_summary': {'status': 'private-performance-side-exported', 'side': side,
            'files': [{k: v for k, v in item.items() if k != 'local_path'} for item in files]}, 'local_files': files}))
        (directory / 'run.source.txt').write_bytes(b'synthetic-reviewed-source\n')
        (directory / 'run.bindings.json').write_bytes(dump(binding));(directory / 'bindings.json').write_bytes(dump(binding))
        (directory / 'run.json').write_bytes(dump({'candidate_commit': receipts.fresh.continuity.RUNTIME,
            'directory': receipts.REMOTE + 'records/' + side + '.attempt01', 'status': 'native-performance-side-complete-awaiting-export'}))
        common = {'remote_returncode': 0, 'two_sessions_closed': True, 'encrypted_recovery_verified': True,
                  'node': 'node02', 'stderr_sha256': receipts.EMPTY}
        (directory / 'run-receipt.json').write_bytes(dump(dict(common, holder_returncode=0, holder_stderr_sha256=receipts.EMPTY,
            source_sha256=receipts.SOURCE, bindings_sha256=receipts.sha(directory / 'bindings.json'),
            capture=str(directory / 'run.json'), capture_sha256=receipts.sha(directory / 'run.json'),
            started_at=stamp(0), completed_at=stamp(7))))
        (directory / 'export-receipt.json').write_bytes(dump(dict(common, capture=str(export / 'INDEX.json'),
            capture_sha256=receipts.sha(export / 'INDEX.json'), checked_at=stamp(8))))
        return dict(run_receipt=directory / 'run-receipt.json', export_receipt=directory / 'export-receipt.json',
                    bindings=directory / 'bindings.json', export_directory=export)

    def check_docs(self, d=None, b=None):
        original, binding = self.documents[0];d = original if d is None else d;b = binding if b is None else b
        prefix = 'records/' + receipts.SIDES[0] + '.attempt01/'
        return receipts.verify_documents({prefix + k: v for k, v in d.items()}, receipts.SIDES[0], b,
                                          original['RESULT.json']['sample_sha256'])

    def test_complete_six_executions_recompute_gate_without_release_acceptance(self):
        result = receipts.verify_all(sides=list(reversed(self.sides)), environment_path=self.environment)
        self.assertEqual(result['performance_gate']['verdict'], 'pass');self.assertFalse(result['release_qualified'])
        self.assertTrue(result['protected_final_validation_required']);self.assertEqual(len(result['executions']), 6)

    def test_missing_or_duplicate_sides_rejected(self):
        for sides in (self.sides[:-1], self.sides[:-1] + [self.sides[0]]):
            with self.assertRaises(receipts.Error):receipts.verify_all(sides=sides, environment_path=self.environment)

    def test_wrong_runtime_role_or_provenance_rejected(self):
        for key, value in [('candidate_commit', receipts.fresh.continuity.BASE), ('probe_sha256', '0' * 64),
                           ('environment_sha256', '0' * 64), ('subject_role', 'candidate')]:
            d = copy.deepcopy(self.documents[0][0]);d['samples.json'][key] = value
            with self.subTest(key=key), self.assertRaises(receipts.Error):self.check_docs(d)

    def test_oom_or_changed_counters_rejected(self):
        for field in ('NATIVE-LIMITS.json', 'COMPLETION-CGROUP.json', 'RESULT.json'):
            d = copy.deepcopy(self.documents[0][0]);target = d[field]
            if field == 'NATIVE-LIMITS.json':target['actual_cgroup_files']['memory.events'] = 'oom 1\noom_kill 0\n'
            else:target['memory_events'] = 'oom 1\noom_kill 0\n'
            with self.subTest(field=field), self.assertRaises(receipts.Error):self.check_docs(d)

    def test_unbounded_wrong_unit_or_dead_holder_rejected(self):
        for field in ('NATIVE-LIMITS.json', 'COMPLETION-CGROUP.json', 'RESULT.json'):
            for key, value in [('MemoryMax', 'infinity'), ('CPUQuotaPerSecUSec', 'infinity'), ('TasksMax', 'infinity'),
                               ('RuntimeMaxUSec', 'infinity'), ('Id', 'foreign.service'), ('MainPID', '999')]:
                d = copy.deepcopy(self.documents[0][0]);d[field]['unit_properties'][key] = value
                with self.subTest(field=field, key=key), self.assertRaises(receipts.Error):self.check_docs(d)

    def test_failed_or_boolean_probe_returncode_rejected(self):
        for value in (1, False):
            d = copy.deepcopy(self.documents[0][0]);d['PROBE-EXIT.json']['probe_returncode'] = value
            d['COMPLETION-CGROUP.json']['probe_exit']['probe_returncode'] = value
            with self.assertRaises(receipts.Error):self.check_docs(d)

    def test_duplicate_properties_and_unclean_closure_rejected(self):
        for state in ('ActiveState=inactive\nSubState=dead\nMainPID=0\nMainPID=0\n',
                      'ActiveState=active\nSubState=running\nMainPID=123\n'):
            d = copy.deepcopy(self.documents[0][0]);d['CLOSED.json']['state'] = state
            with self.assertRaises(receipts.Error):self.check_docs(d)

    def test_wrong_sample_or_holder_digest_rejected(self):
        for key in ('sample_sha256', 'completion_holder_sha256'):
            d = copy.deepcopy(self.documents[0][0]);d['RESULT.json'][key] = '0' * 64
            with self.assertRaises(receipts.Error):self.check_docs(d)

    def test_naive_stale_non_utc_and_reversed_timestamps_rejected(self):
        for value in ('2026-09-24T20:00:06', '2026-09-23T20:00:06Z', '2026-09-24T20:00:06+01:00', '2026-09-24T19:59:06Z'):
            d = copy.deepcopy(self.documents[0][0]);d['CLOSED.json']['closed_at'] = value
            with self.assertRaises(receipts.Error):self.check_docs(d)

    def test_missing_start_or_unreviewed_bindings_rejected(self):
        d = copy.deepcopy(self.documents[0][0]);d.pop('START.json')
        with self.assertRaises(receipts.Error):self.check_docs(d)
        b = copy.deepcopy(self.documents[0][1]);b['execution_reviewed'] = False
        with self.assertRaises(receipts.Error):self.check_docs(b=b)

    def test_native_source_bindings_capture_and_files_cannot_be_edited(self):
        args = self.sides[0];root = args['run_receipt'].parent
        for path in (root / 'run.source.txt', args['bindings'], root / 'run.json', args['export_directory'] / '0001-samples.json'):
            original = path.read_bytes();path.write_bytes(original + b' ')
            with self.subTest(path=path.name), self.assertRaises(receipts.Error):receipts.verify_side(**args)
            path.write_bytes(original)

    def test_extra_files_symlinks_and_nonempty_stderr_rejected(self):
        args = self.sides[0];extra = args['export_directory'] / 'unreviewed.txt';extra.write_text('x')
        with self.assertRaises(receipts.Error):receipts.verify_side(**args)
        extra.unlink();path = args['export_directory'] / '0008-probe.stderr';path.unlink();path.symlink_to(args['bindings'])
        with self.assertRaises((receipts.Error, receipts.fresh.continuity.bundle.SigningBundleError)):receipts.verify_side(**args)
        path.unlink();path.write_text('unexpected stderr')
        with self.assertRaises(receipts.Error):receipts.verify_side(**args)

    def test_recovery_or_transport_failure_rejected(self):
        path = self.sides[0]['export_receipt'];original = receipts.document(path)
        for key, value in [('remote_returncode', 1), ('remote_returncode', False), ('two_sessions_closed', False),
                           ('encrypted_recovery_verified', False), ('node', 'node03')]:
            d = dict(original);d[key] = value;path.write_text(json.dumps(d))
            with self.subTest(key=key), self.assertRaises(receipts.Error):receipts.verify_side(**self.sides[0])
        path.write_text(json.dumps(original))


if __name__ == '__main__':unittest.main()
