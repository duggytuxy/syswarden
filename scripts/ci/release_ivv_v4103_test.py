"""A prior Patch verdict cannot authorize the new signed product."""
import copy
import json
import unittest
from scripts.ci import release_ivv_v4103 as current
from scripts.ci import release_ivv_consumer_test as earlier
from scripts.ci import candidate_update_verify_v4103 as updater
from scripts.ci import release_ivv_v4101_test as capture_tests


class CurrentConsumptionTests(earlier.ConsumptionTests):
    current = current
    updater = updater
    workflow = '.github/workflows/release-ivv-v4103.yml'

    def test_exact_scoped_acceptance(self):
        self.verify(self.report)
        self.assertFalse(self.report['full_qualification_passed'])
        observations = self.report['input_verification']['reviewed_observations']
        self.assertEqual({r['original_candidate'] for r in observations},
                         {current.PRODUCT, current.PREVIOUS_ACCEPTED})
        self.assertIn('retained-harness-failure', {r['relation'] for r in observations})

    def test_prior_product_signature_and_updater_cannot_be_reused(self):
        for section, field, value in (
            ('native_signature_verification', 'product_candidate', current.PREVIOUS_ACCEPTED),
            ('updater_verification', 'producer_run_id', 37033510001),
            ('updater_verification', 'artifact_id', 11237844323),
            ('context', 'workflow', '.github/workflows/release-ivv-v4102.yml'),
        ):
            with self.subTest(section=section, field=field):
                report = copy.deepcopy(self.report)
                report[section][field] = value
                with self.assertRaises(current.frozen.PlanError):
                    self.verify(report)


class CurrentInputTests(unittest.TestCase):
    def test_original_failed_capture_cannot_be_rewritten(self):
        manifest, objects, doc = capture_tests.PrivateCaptureTests().fixture()
        current.verify_capture_bindings(manifest, objects)
        doc['receipt']['rc'] = 0
        objects[manifest['roots'][0]['object_sha256']] = json.dumps(doc).encode()
        with self.assertRaises(current.frozen.PlanError):
            current.verify_capture_bindings(manifest, objects)

    def test_distinct_evidence_identities_and_typed_assertions(self):
        for relation, candidate in [('current-targeted-observation', current.PRODUCT),
                                    ('retained-harness-failure', current.PRODUCT),
                                    ('historical-support-only', current.PREVIOUS_ACCEPTED)]:
            doc = dict(candidate_commit=candidate, checked=True)
            row = dict(id='case', candidate_commit=candidate, relation=relation,
                       object_sha256='a'*64, assertions={'checked':True})
            objects = {'a'*64:json.dumps(doc).encode()}
            result = current.verify_roots(dict(roots=[row]), objects)
            self.assertFalse(result[0]['admitted_as_current_native_pass'])
            with self.assertRaises(current.frozen.PlanError):
                current.verify_roots(dict(roots=[dict(row, candidate_commit='b'*40)]), objects)
            objects['a'*64] = json.dumps(dict(doc, checked=1)).encode()
            with self.assertRaises(current.frozen.PlanError):
                current.verify_roots(dict(roots=[row]), objects)

    def test_plan_binds_fresh_signed_campaign_and_preserves_failures(self):
        plan = current.load_plan()
        manifest = current.load_manifest(plan)
        self.assertEqual(plan['native_tested_candidate'], plan['product_candidate'])
        self.assertEqual(plan['native_file_count'], 305)
        self.assertEqual(len(plan['native_assertions']), 17)
        self.assertFalse(plan['preflight_is_acceptance'])
        self.assertEqual(plan['product_native_signing']['artifact_id'], 11295630713)
        failures = [r for r in manifest['roots'] if r['relation'] == 'retained-harness-failure']
        self.assertEqual(len(failures), 4)
        self.assertTrue(all(r['assertions']['exit'] != 0 for r in failures))
        self.assertEqual(plan['last_public_release']['tag'], 'v4.10.2')
        self.assertNotIn('src/', '\n'.join(plan['publication_source_change_allowlist']))


if __name__ == '__main__':
    unittest.main()
