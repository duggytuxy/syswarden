#!/usr/bin/env python3
"""Adversarial checks for exact historical metric continuity."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import qualification_continuity_metrics as inventory
    from scripts.ci import performance_evidence_test as performance_fixtures
    from scripts.ci import source_allocation_gate_test as allocation_fixtures
except ModuleNotFoundError:
    import qualification_continuity_metrics as inventory
    import performance_evidence_test as performance_fixtures
    import source_allocation_gate_test as allocation_fixtures

c = inventory.continuity


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MetricContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proofs = self.root / "proofs"
        self.proofs.mkdir(mode=0o700)
        self.perf = self.root / "performance"
        self.perf.mkdir(mode=0o700)
        self.policy = copy.deepcopy(c.load_policy())
        self.fixture = performance_fixtures.PerformanceEvidenceTests()
        self.fixture.setUpClass()
        self.fixture.candidate = c.BASE
        self.write(self.perf / "ENVIRONMENT.json", {"host": "test-host"})
        self.samples = []
        campaign_paths = []
        for index in (1, 2, 3):
            identifier = f"campaign-{index}"
            stamp = f"2026-09-{9 + index:02d}T08:00:00Z"
            pair = []
            for role in ("baseline", "candidate"):
                path = self.perf / f"{identifier}-{role}.json"
                self.write(path, self.fixture.sample_document(role, 1.0 + index / 1000, identifier, stamp))
                pair.append(path)
                self.samples.append(path)
            campaign = inventory.campaigns.build_campaign(candidate_commit=c.BASE,
                identifier=identifier, recorded_at=stamp, environment_id="test-host",
                environment_attestation=self.perf / "ENVIRONMENT.json", probe=inventory.performance.DEFAULT_PROBE,
                baseline_samples=pair[0], candidate_samples=pair[1])
            path = self.perf / f"campaign-{index:02d}.json"
            self.write(path, campaign)
            campaign_paths.append(path)
        evidence, report = inventory.campaigns.assemble_evidence(candidate_commit=c.BASE, campaigns=campaign_paths)
        self.write(self.perf / "EVIDENCE.json", evidence)
        self.write(self.perf / "INDEPENDENT-PERFORMANCE-GATE.json", report)
        self.anchor("native-performance.json", {"candidate_commit": c.BASE, "waivers": 0,
                    "gate": {"sha256": sha(self.perf / "INDEPENDENT-PERFORMANCE-GATE.json")}})
        self.anchor("five-native-lifecycles.json", {"candidate_commit": c.BASE})
        self.anchor("source-allocation.json", {"candidate_commit": c.BASE, "native_raw_inputs_unchanged": True})
        self.alloc = allocation_fixtures.BundleFixture(self.root, candidate=c.BASE)
        self.alloc.assemble()
        self.report_sha = sha(self.alloc.root / "REPORT.json")

    def write(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n")

    def anchor(self, name, value):
        path = self.proofs / name
        self.write(path, value)
        self.policy["records"][name] = {"sha256": sha(path), "size": path.stat().st_size}

    def performance(self, samples=None):
        with mock.patch.object(inventory.performance, "reviewed_bindings", return_value={}) as check:
            result = inventory._revalidate_performance(proof_root=self.proofs, policy=self.policy,
                performance_root=self.perf, adapter_config=self.root / "adapter.json",
                sample_paths=self.samples if samples is None else samples)
            check.assert_called_once()
            self.assertEqual(check.call_args.args[:3],
                (self.root / "adapter.json", self.proofs / "five-native-lifecycles.json", c.BASE))
            return result

    def allocation(self):
        with mock.patch.object(inventory, "ALLOCATION_REPORT_SHA256", self.report_sha):
            return inventory._revalidate_allocation(proof_root=self.proofs, policy=self.policy, allocation_root=self.alloc.root)

    def test_six_raw_sample_documents_rebuild_original_performance(self):
        before = {p: p.read_bytes() for p in self.samples}
        result = self.performance(list(reversed(self.samples)))
        self.assertEqual(result["sample_document_count"], 6)
        self.assertEqual(result["observed_candidate"], c.BASE)
        self.assertEqual(result["original_report"]["candidate_commit"], c.BASE)
        self.assertEqual({p: p.read_bytes() for p in self.samples}, before)
        self.assertEqual(len(result["retained_metric_names"]), 7)
        self.assertEqual(set(result["excluded_metric_names"]), inventory.FRESH_METRICS)

    def test_missing_extra_or_duplicate_samples_fail(self):
        for paths in (self.samples[:-1], self.samples + [self.samples[0]], self.samples[:-1] + [self.samples[0]]):
            with self.subTest(count=len(paths)), self.assertRaises(c.ContinuityError): self.performance(paths)

    def test_raw_sample_tampering_fails_even_if_values_are_unchanged(self):
        self.samples[0].write_bytes(self.samples[0].read_bytes() + b" ")
        with self.assertRaises(c.ContinuityError): self.performance()

    def test_campaign_values_cannot_override_actual_samples(self):
        path = self.perf / "campaign-01.json"
        document = json.loads(path.read_bytes())
        document["metrics"]["rss_bytes"]["candidate"][0] += 1
        self.write(path, document)
        with self.assertRaisesRegex(c.ContinuityError, "sample documents"): self.performance()

    def test_report_relabelled_or_reserialized_is_rejected(self):
        path = self.perf / "INDEPENDENT-PERFORMANCE-GATE.json"
        before = path.read_bytes()
        for wire in (before + b" ", before.replace(c.BASE.encode(), c.RUNTIME.encode())):
            path.write_bytes(wire)
            with self.assertRaises(c.ContinuityError): self.performance()

    def test_fresh_metric_requirement_cannot_be_removed(self):
        self.policy["fresh_required"]["performance_metrics"].remove("startup_milliseconds")
        with self.assertRaises(c.ContinuityError): self.performance()

    def test_changed_adapter_binding_is_rejected_by_original_gate(self):
        with mock.patch.object(inventory.performance, "reviewed_bindings", return_value={"expected_adapter_config_sha256": "f" * 64}):
            with self.assertRaises(inventory.performance.PerformanceGateError):
                inventory._revalidate_performance(proof_root=self.proofs, policy=self.policy,
                    performance_root=self.perf, adapter_config=self.root / "adapter.json", sample_paths=self.samples)

    def test_allocation_rebuilds_exact_original_report(self):
        result = self.allocation()
        self.assertEqual(result["observed_candidate"], c.BASE)
        self.assertEqual(result["original_report"]["candidate_commit"], c.BASE)
        self.assertEqual(result["report_sha256"], self.report_sha)

    def test_allocation_raw_tampering_is_rejected(self):
        path = self.alloc.raw_path()
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(inventory.allocation.SourceAllocationGateError): self.allocation()

    def test_allocation_report_change_cannot_be_accepted(self):
        path = self.alloc.root / "REPORT.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(c.ContinuityError): self.allocation()

    def entry(self):
        return inventory.verify_metric_inventory(repository=self.root, proof_root=self.proofs,
            base_bundle=self.root, runtime_bundle=self.root, performance_root=self.perf,
            adapter_config=self.root / "adapter.json", sample_paths=self.samples,
            allocation_root=self.alloc.root, candidate=c.RUNTIME)

    def test_public_entry_rechecks_eligibility_before_reading_measurements(self):
        with mock.patch.object(c, "verify_eligibility", side_effect=c.ContinuityError("ineligible")), \
             mock.patch.object(inventory, "_revalidate_performance") as measure:
            with self.assertRaises(c.ContinuityError): self.entry()
            measure.assert_not_called()

    def test_complete_original_measurements_never_clear_fresh_requirements(self):
        with mock.patch.object(c, "verify_eligibility"), mock.patch.object(c, "load_policy", return_value=self.policy), \
             mock.patch.object(inventory.performance, "reviewed_bindings", return_value={}), \
             mock.patch.object(inventory, "ALLOCATION_REPORT_SHA256", self.report_sha):
            result = self.entry()
        self.assertEqual(set(result["fresh_performance_metrics_still_required"]), inventory.FRESH_METRICS)
        self.assertIs(result["release_qualified"], False)
        self.assertIs(result["native_experiments_replayed"], False)
        self.assertIs(result["historical_evidence_modified"], False)
        self.assertIs(result["protected_final_validation_required"], True)
        self.assertNotIn("verdict", result)


class CompleteMetricEvidenceTests(unittest.TestCase):
    """Synthetic boundary cases; no fixture here is native release evidence."""

    def setUp(self):
        try:
            from scripts.ci import qualification_continuity_performance_receipts as receipts
        except ModuleNotFoundError:
            import qualification_continuity_performance_receipts as receipts
        self.receipts = receipts
        self.contract, names = receipts.fresh.frozen_tooling()
        metrics = {name: {'accepted': True, 'waived': False, 'candidate': {'median': 12}}
                   for name in names}
        self.old = {'schema': inventory.SCHEMA, 'runtime_candidate': c.RUNTIME,
            'continuity_policy_sha256': c.POLICY_SHA256, 'historical_evidence_modified': False,
            'release_qualified': False, 'fresh_performance_metrics_still_required': sorted(inventory.FRESH_METRICS),
            'performance': {'retained_metric_names': sorted(set(names) - inventory.FRESH_METRICS),
                'excluded_metric_names': sorted(inventory.FRESH_METRICS), 'observed_candidate': c.BASE,
                'proposed_acceptance_candidate': c.RUNTIME, 'paired_campaigns': 3, 'sample_document_count': 6,
                'original_report': {'candidate_commit': c.BASE, 'verdict': 'pass', 'failed_metrics': [],
                    'contract_id': self.contract['contract_id'], 'metrics': metrics}},
            'source_allocation': {'observed_candidate': c.BASE, 'proposed_acceptance_candidate': c.RUNTIME,
                'original_report': {'candidate_commit': c.BASE, 'verdict': 'pass', 'failed_metrics': [],
                    'native_package_runtime_measurement': False,
                    'measurement_scope': 'deterministic-source-bound-waap-engine-scan',
                    'campaign_count': 3, 'samples_per_subject': 30}}}
        self.fresh = {'schema': receipts.SCHEMA, 'runtime_candidate': c.RUNTIME,
            'native_execution_receipts_verified': True, 'historical_evidence_modified': False,
            'release_qualified': False,
            'executions': [{'side': side, 'native_execution_verified': True} for side in receipts.SIDES],
            'performance_gate': {'schema': receipts.fresh.REPORT_SCHEMA, 'candidate_commit': c.RUNTIME,
                'verdict': 'pass', 'failed_metrics': [], 'waivers': 0, 'historical_samples_relabelled': False,
                'release_qualified': False, 'contract_id': self.contract['contract_id'],
                'metrics': {name: {'accepted': True, 'waived': False, 'candidate': {'median': 34}}
                            for name in inventory.FRESH_METRICS}}}

    def combine(self):
        return inventory._combine_verified_metrics(self.old, self.fresh)

    def test_metric_origin_stays_explicit_and_observations_are_not_pooled(self):
        before = copy.deepcopy((self.old, self.fresh))
        result = self.combine()
        self.assertEqual(result['measurement_verdict'], 'pass')
        self.assertEqual(result['fresh_performance_metrics_still_required'], [])
        self.assertEqual(len(result['native_metrics']), 11)
        for name, entry in result['native_metrics'].items():
            fresh = name in inventory.FRESH_METRICS
            self.assertEqual(entry['observed_candidate'], c.RUNTIME if fresh else c.BASE)
            self.assertEqual(entry['measurement']['candidate']['median'], 34 if fresh else 12)
        self.assertEqual((self.old, self.fresh), before)
        self.assertFalse(result['release_qualified'])
        self.assertTrue(result['protected_final_validation_required'])
        self.assertFalse(result['samples_pooled_across_candidates'])
        result['native_metrics']['startup_milliseconds']['measurement']['candidate']['median'] = -1
        self.assertEqual((self.old, self.fresh), before)

    def test_historical_install_or_size_cannot_replace_fresh_measurement(self):
        self.old['performance']['original_report']['metrics']['startup_milliseconds']['candidate']['median'] = 0
        self.assertEqual(self.combine()['native_metrics']['startup_milliseconds']['measurement']['candidate']['median'], 34)
        del self.fresh['performance_gate']['metrics']['startup_milliseconds']
        with self.assertRaises(c.ContinuityError): self.combine()

    def test_retained_fresh_boundary_cannot_expand(self):
        self.old['performance']['retained_metric_names'].append('package_bytes')
        with self.assertRaises(c.ContinuityError): self.combine()

    def test_observed_candidates_cannot_be_relabelled_or_reused(self):
        for document, field, candidate in [
                (self.old['performance'], 'observed_candidate', c.RUNTIME),
                (self.old['source_allocation']['original_report'], 'candidate_commit', c.RUNTIME),
                (self.fresh['performance_gate'], 'candidate_commit', c.BASE),
                (self.fresh, 'runtime_candidate', 'f' * 40)]:
            with self.subTest(field=field):
                previous = document[field]; document[field] = candidate
                with self.assertRaises(c.ContinuityError): self.combine()
                document[field] = previous

    def test_failed_or_waived_metric_cannot_be_hidden(self):
        for metric in [self.old['performance']['original_report']['metrics']['rss_bytes'],
                       self.fresh['performance_gate']['metrics']['install_milliseconds']]:
            for field, bad in [('accepted', False), ('waived', True)]:
                previous = metric[field]; metric[field] = bad
                with self.assertRaises(c.ContinuityError): self.combine()
                metric[field] = previous
        for bad in (1, True):
            self.fresh['performance_gate']['waivers'] = bad
            with self.assertRaises(c.ContinuityError): self.combine()

    def test_allocation_channel_must_pass_and_retain_its_source_scope(self):
        allocation = self.old['source_allocation']['original_report']
        for key, bad in [('verdict', 'fail'), ('native_package_runtime_measurement', True),
                         ('measurement_scope', 'native-package-runtime'), ('samples_per_subject', 29)]:
            previous = allocation[key]; allocation[key] = bad
            with self.assertRaises(c.ContinuityError): self.combine()
            allocation[key] = previous

    def test_aggregate_requires_all_six_verified_execution_receipts(self):
        original = copy.deepcopy(self.fresh['executions'])
        for records in (original[:-1], original + original[:1], list(reversed(original))):
            self.fresh['executions'] = records
            with self.assertRaises(c.ContinuityError): self.combine()
        self.fresh['executions'] = original
        self.fresh['native_execution_receipts_verified'] = False
        with self.assertRaises(c.ContinuityError): self.combine()

    def test_combined_result_cannot_claim_release_acceptance(self):
        self.fresh['release_qualified'] = True
        with self.assertRaises(c.ContinuityError): self.combine()

    def test_public_entry_rebuilds_both_channels_and_propagates_failure(self):
        path = Path('/unused-synthetic-test')
        args = {name: path for name in ('repository', 'proof_root', 'base_bundle', 'runtime_bundle',
            'performance_root', 'adapter_config', 'allocation_root', 'fresh_environment')}
        args.update(sample_paths=[path], candidate=c.RUNTIME, fresh_sides=[{'run_receipt': path}])
        with mock.patch.object(inventory, 'verify_metric_inventory', return_value=self.old) as historical, \
                mock.patch.object(self.receipts, 'verify_all', return_value=self.fresh) as native:
            result = inventory.verify_complete_metric_evidence(**args)
            self.assertEqual(result['measurement_verdict'], 'pass')
            historical.assert_called_once_with(**{k: v for k, v in args.items()
                                                  if k not in ('fresh_sides', 'fresh_environment')})
            native.assert_called_once_with(sides=args['fresh_sides'], environment_path=path)
        with mock.patch.object(inventory, 'verify_metric_inventory', side_effect=c.ContinuityError('source changed')), \
                mock.patch.object(self.receipts, 'verify_all') as native:
            with self.assertRaises(c.ContinuityError): inventory.verify_complete_metric_evidence(**args)
            native.assert_not_called()
        with mock.patch.object(inventory, 'verify_metric_inventory', return_value=self.old), \
                mock.patch.object(self.receipts, 'verify_all', side_effect=c.ContinuityError('receipt changed')):
            with self.assertRaises(c.ContinuityError): inventory.verify_complete_metric_evidence(**args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
