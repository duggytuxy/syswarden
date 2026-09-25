#!/usr/bin/env python3
"""Adversarial tests; synthetic fixtures are never native qualification evidence."""
from __future__ import annotations
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
try:
    from scripts.ci import qualification_continuity_performance as fresh
    from scripts.ci import native_performance_probe_test as probe_fixtures
    from scripts.ci import performance_gate_test as gate_fixtures
except ModuleNotFoundError:
    import qualification_continuity_performance as fresh
    import native_performance_probe_test as probe_fixtures
    import performance_gate_test as gate_fixtures


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


class FreshPerformanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.environment = self.root / 'environment.json'; self.environment.write_text('{"host":"unit-test-only"}\n')
        self.contract, self.metrics = fresh.frozen_tooling()
        self.paths = []; self.documents = []
        for index in (1, 2, 3):
            for role in ('baseline', 'candidate'):
                document = {'schema': fresh.SCHEMA, 'candidate_commit': fresh.continuity.RUNTIME,
                    'campaign_id': f'campaign-{index}', 'recorded_at': f'2026-09-24T18:00:0{index}Z',
                    'subject_role': role, 'subject_release': 'v4.04.3' if role == 'baseline' else 'v4.10.0',
                    'contract_id': self.contract['contract_id'], 'environment_id': 'test-host',
                    'environment_sha256': sha(self.environment), 'adapter_sha256': fresh.FROZEN['native_performance_adapter.py'],
                    'adapter_config_sha256': 'd' * 64, 'probe_sha256': sha(Path(fresh.__file__)),
                    'frozen_dependencies': dict(fresh.FROZEN), **fresh.ARTIFACTS[role],
                    'metrics': {name: {'unit': self.metrics[name].unit, 'samples':
                        [fresh.SIZES[role][name]] if name in fresh.probe.SIZE_METRICS else
                        [100.0 + index + n / 1000 for n in range(10 if name == 'startup_milliseconds' else 1)]}
                        for name in fresh.FRESH}}
                self.documents.append(document); self.paths.append(self.root / f'{index}-{role}.json')
        self.write()

    def write(self):
        for path, document in zip(self.paths, self.documents): path.write_text(json.dumps(document) + '\n')

    def evaluate(self, **changes):
        args = dict(sample_paths=self.paths, adapter_config_sha256='d' * 64, environment_id='test-host',
                    environment_path=self.environment, environment_sha256=sha(self.environment),
                    probe_sha256=sha(Path(fresh.__file__)))
        args.update(changes); return fresh.evaluate(**args)

    def test_complete_fresh_gate_is_not_release_acceptance(self):
        result = self.evaluate(sample_paths=list(reversed(self.paths)))
        self.assertEqual(result['verdict'], 'pass'); self.assertEqual(set(result['metrics']), fresh.FRESH)
        self.assertFalse(result['release_qualified']); self.assertTrue(result['native_execution_receipts_required'])
        self.assertTrue(result['protected_final_validation_required']); self.assertFalse(result['historical_samples_relabelled'])
        self.assertEqual(result['metrics']['startup_milliseconds']['candidate']['samples'], 30)
        self.assertEqual(result['metrics']['install_milliseconds']['candidate']['samples'], 3)

    def test_original_probe_contract_and_adapter_are_unchanged(self):
        fresh.frozen_tooling()
        self.assertNotEqual(fresh.SCHEMA, fresh.probe.SAMPLE_SCHEMA)
        policy = copy.deepcopy(fresh.continuity.load_policy()); policy['fresh_required']['performance_metrics'].pop()
        with mock.patch.object(fresh.continuity, 'load_policy', return_value=policy), self.assertRaises(fresh.continuity.ContinuityError): fresh.frozen_tooling()
        with mock.patch.dict(fresh.FROZEN, {'native_performance_probe.py': 'f' * 64}), self.assertRaises(fresh.continuity.ContinuityError): fresh.frozen_tooling()

    def test_old_candidate_schema_artifacts_or_unknown_provenance_fail(self):
        for key, value in [('candidate_commit', fresh.continuity.BASE), ('schema', fresh.probe.SAMPLE_SCHEMA),
            ('binary_sha256', '1' * 64), ('package_sha256', '2' * 64), ('adapter_sha256', '3' * 64),
            ('adapter_config_sha256', '4' * 64), ('probe_sha256', '5' * 64), ('environment_sha256', '6' * 64),
            ('subject_release', 'v4.04.3'), ('subject_role', 'unknown'), ('recorded_at', '2026-09-23T12:00:00Z')]:
            with self.subTest(key=key):
                old = self.documents[1][key]; self.documents[1][key] = value; self.write()
                with self.assertRaises((fresh.continuity.ContinuityError, fresh.gate.PerformanceGateError)): self.evaluate()
                self.documents[1][key] = old
        self.write()

    def test_no_missing_extra_or_duplicate_campaigns(self):
        for paths in (self.paths[:-1], self.paths + [self.paths[0]], self.paths[:-1] + [self.paths[0]]):
            with self.subTest(paths=len(paths)), self.assertRaises(fresh.continuity.ContinuityError): self.evaluate(sample_paths=paths)
        self.documents[3]['campaign_id'] = 'campaign-1'; self.write()
        with self.assertRaises(fresh.continuity.ContinuityError): self.evaluate()

    def test_duplicate_or_mismatched_timestamps_fail(self):
        self.documents[1]['recorded_at'] = '2026-09-24T18:30:00Z'; self.write()
        with self.assertRaises(fresh.continuity.ContinuityError): self.evaluate()
        self.documents[1]['recorded_at'] = self.documents[0]['recorded_at']
        for index in (2, 3): self.documents[index]['recorded_at'] = self.documents[0]['recorded_at']
        self.write()
        with self.assertRaises(fresh.continuity.ContinuityError): self.evaluate()

    def test_cloned_startup_vectors_fail(self):
        for target, source in ((2, 0), (3, 1)):
            self.documents[target]['metrics']['startup_milliseconds'] = copy.deepcopy(self.documents[source]['metrics']['startup_milliseconds'])
        self.write()
        with self.assertRaisesRegex(fresh.continuity.ContinuityError, 'cloned'): self.evaluate()

    def test_size_values_must_match_exact_artifacts(self):
        self.documents[1]['metrics']['package_bytes']['samples'] = [1]; self.write()
        with self.assertRaisesRegex(fresh.continuity.ContinuityError, 'size'): self.evaluate()

    def test_sample_counts_units_and_extra_metrics_fail(self):
        original = copy.deepcopy(self.documents[1]['metrics'])
        mutations = [lambda m: m['startup_milliseconds']['samples'].pop(),
            lambda m: m['install_milliseconds'].update(unit='seconds'),
            lambda m: m.update(idle_cpu_percent={'unit': 'percent', 'samples': [1]}),
            lambda m: m.pop('binary_bytes')]
        for mutate in mutations:
            self.documents[1]['metrics'] = copy.deepcopy(original); mutate(self.documents[1]['metrics']); self.write()
            with self.assertRaises(fresh.continuity.ContinuityError): self.evaluate()

    def test_nan_boolean_zero_negative_samples_fail(self):
        for value in (float('nan'), float('inf'), True, 0, -1, '100'):
            self.documents[1]['metrics']['install_milliseconds']['samples'] = [value]; self.write()
            with self.subTest(value=value), self.assertRaises((fresh.continuity.ContinuityError, fresh.gate.PerformanceGateError)): self.evaluate()

    def test_duplicate_json_fields_and_symlink_inputs_fail(self):
        self.paths[0].write_text(self.paths[0].read_text().replace('{', '{"schema":"duplicate",', 1))
        with self.assertRaises(fresh.continuity.ContinuityError): self.evaluate()
        self.write(); target = self.root / 'link.json'; target.symlink_to(self.paths[0])
        with self.assertRaises(fresh.continuity.bundle.SigningBundleError): self.evaluate(sample_paths=[target, *self.paths[1:]])

    def test_reviewed_input_pins_cannot_be_derived_from_samples(self):
        for key in ('adapter_config_sha256', 'environment_sha256', 'probe_sha256'):
            with self.subTest(key=key), self.assertRaises(fresh.continuity.ContinuityError): self.evaluate(**{key: 'a' * 64})

    def test_same_numerical_decision_as_original_gate(self):
        fixture = gate_fixtures.PerformanceGateTests(); fixture.setUpClass()
        for factor in (1.0, 1.1, 1.100001, 1.3):
            original = fixture.evidence()
            for index in range(3):
                for name in fresh.FRESH:
                    b = self.documents[2 * index]['metrics'][name]['samples']
                    c = self.documents[2 * index + 1]['metrics'][name]['samples']
                    if name not in fresh.probe.SIZE_METRICS: c[:] = [v * factor for v in b]
                    original['metrics'][name]['campaigns'][index].update(baseline=b, candidate=c)
            self.write(); checked = self.evaluate()
            complete = fresh.gate.evaluate(original, fixture.contract, fixture.metrics, {}, fixture.candidate)
            for name in fresh.FRESH:
                for key in ('baseline', 'candidate', 'aggregate_regression_percent', 'regressed_campaigns',
                            'stable_regression', 'accepted', 'waived', 'acceptance'):
                    with self.subTest(factor=factor, name=name, key=key):
                        self.assertEqual(checked['metrics'][name][key], complete['metrics'][name][key])

    def test_single_slow_campaign_is_not_stable_regression(self):
        self.documents[1]['metrics']['install_milliseconds']['samples'] = [10000]; self.write()
        self.assertFalse(self.evaluate()['metrics']['install_milliseconds']['stable_regression'])
        self.documents[3]['metrics']['install_milliseconds']['samples'] = [10000]; self.write()
        self.assertIn('install_milliseconds', self.evaluate()['failed_metrics'])


class FreshCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.adapter, self.binary, self.package = probe_fixtures.NativePerformanceProbeTests().fixture(self.root)
        self.config = self.root / 'config.json'; self.config.write_text('{}\n'); self.config.chmod(0o600)
        self.original_tools = fresh.frozen_tooling()
        self.args = dict(candidate_commit=fresh.continuity.RUNTIME, campaign_id='test-only-1', recorded_at='2026-09-24T18:00:00Z',
            subject_role='candidate', environment_id='test-host', environment_sha256='e' * 64,
            adapter=self.adapter, adapter_sha256=sha(self.adapter), adapter_config=self.config,
            adapter_config_sha256=sha(self.config), binary=self.binary, package=self.package, runs=10, timeout_seconds=10)

    def collect(self, **changes):
        artifacts = {'candidate': {'binary_sha256': sha(self.binary), 'package_sha256': sha(self.package)}}
        sizes = {'candidate': {'binary_bytes': self.binary.stat().st_size, 'package_bytes': self.package.stat().st_size}}
        args = dict(self.args); args.update(changes)
        with mock.patch.object(fresh, 'frozen_tooling', return_value=self.original_tools), \
             mock.patch.dict(fresh.FROZEN, {'native_performance_adapter.py': sha(self.adapter)}), \
             mock.patch.object(fresh, 'ARTIFACTS', artifacts), mock.patch.object(fresh, 'SIZES', sizes):
            return fresh.collect(**args)

    def test_subprocess_requests_only_four_fresh_metrics(self):
        # The child rejects any attempt to replay the seven unaffected metrics.
        body = probe_fixtures.ADAPTER.replace("print(json.dumps(",
            "assert set(names) == ({'startup_milliseconds','install_milliseconds'} if a.iteration == 1 else {'startup_milliseconds'})\nprint(json.dumps(")
        self.adapter.write_text(body); self.args['adapter_sha256'] = sha(self.adapter)
        document = self.collect()
        self.assertEqual(set(document['metrics']), fresh.FRESH)
        self.assertEqual(document['metrics']['startup_milliseconds']['samples'], list(map(float, range(1, 11))))
        self.assertEqual(document['metrics']['install_milliseconds']['samples'], [1.0])
        self.assertEqual(document['metrics']['binary_bytes']['samples'], [12.0])

    def test_old_candidate_bad_count_or_bad_provenance_rejected(self):
        for key, value in [('candidate_commit', fresh.continuity.BASE), ('runs', 9), ('timeout_seconds', 0),
                           ('adapter_sha256', 'f' * 64), ('adapter_config_sha256', 'a' * 64), ('recorded_at', '2026-09-23T12:00:00Z')]:
            with self.subTest(key=key), self.assertRaises((fresh.continuity.ContinuityError, fresh.probe.NativePerformanceProbeError)):
                self.collect(**{key: value})

    def test_adapter_inventing_metrics_is_rejected(self):
        self.adapter.write_text(probe_fixtures.ADAPTER.replace('print(json.dumps(', "names.append('idle_cpu_percent')\nprint(json.dumps("))
        self.args['adapter_sha256'] = sha(self.adapter)
        with self.assertRaises(fresh.probe.NativePerformanceProbeError): self.collect()

    def test_adapter_cannot_change_configuration(self):
        self.adapter.write_text(probe_fixtures.ADAPTER.replace('print(json.dumps(',
            f"open({str(self.config)!r}, 'w').write('changed')\nprint(json.dumps("))
        self.args['adapter_sha256'] = sha(self.adapter)
        with self.assertRaises(fresh.probe.NativePerformanceProbeError): self.collect()


if __name__ == '__main__': unittest.main()
