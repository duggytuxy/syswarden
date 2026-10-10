"""A prior Patch verdict cannot authorize the new signed product."""
import copy
import json
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from scripts.ci import release_ivv_v4104 as current
from scripts.ci import release_ivv_consumer_test as earlier
from scripts.ci import candidate_update_verify_v4104 as updater
from scripts.ci import release_ivv_v4101_test as capture_tests


class CurrentConsumptionTests(earlier.ConsumptionTests):
    current = current
    updater = updater
    workflow = '.github/workflows/release-ivv-v4104.yml'

    def test_exact_scoped_acceptance(self):
        self.verify(self.report)
        self.assertFalse(self.report['full_qualification_passed'])
        observations = self.report['input_verification']['reviewed_observations']
        self.assertEqual({r['original_candidate'] for r in observations},
                         {current.PRODUCT, current.PREVIOUS_ACCEPTED})
        self.assertIn('final-restoration', {r['relation'] for r in observations})

    def test_prior_product_signature_and_updater_cannot_be_reused(self):
        for section, field, value in (
            ('native_signature_verification', 'product_candidate', current.PREVIOUS_ACCEPTED),
            ('updater_verification', 'producer_run_id', 37755322198),
            ('updater_verification', 'artifact_id', 11539873232),
            ('context', 'workflow', '.github/workflows/release-ivv-v4103.yml'),
        ):
            with self.subTest(section=section, field=field):
                report = copy.deepcopy(self.report)
                report[section][field] = value
                with self.assertRaises(current.frozen.PlanError):
                    self.verify(report)


class CurrentInputTests(unittest.TestCase):
    def test_plan_binds_current_packages_and_all_native_groups(self):
        plan = current.load_plan()
        manifest = current.load_manifest(plan)
        self.assertEqual(plan['product_native_signing']['run_id'], 38029436747)
        self.assertEqual(plan['updater_producer']['run_id'], 38029762398)
        self.assertEqual(plan['last_public_release']['tag'], 'v4.10.3')
        self.assertEqual(set(plan['private_evidence_groups']),
                         {'debian', 'alma', 'performance', 'restored-debian', 'restored-alma'})
        self.assertEqual(len(manifest['roots']), 18)
        self.assertFalse(plan['preflight_is_acceptance'])
        self.assertFalse(manifest['private_inputs_uploaded'])
        self.assertFalse(manifest['historical_verdicts_transferred'])
        self.assertNotIn('src/', '\n'.join(plan['publication_source_change_allowlist']))

    def test_native_failure_cannot_be_replaced_by_graph_integrity(self):
        with ExitStack() as stack:
            for name, value in (('load_plan', {'private_input_manifest_sha256': 'a' * 64}),
                                ('load_manifest', {}), ('verify_objects', {}), ('verify_roots', [])):
                stack.enter_context(patch.object(current, name, return_value=value))
            check = stack.enter_context(patch.object(current, 'verify_native_groups',
                side_effect=current.frozen.PlanError('incomplete current native evidence')))
            with self.assertRaisesRegex(current.frozen.PlanError, 'incomplete current native evidence'):
                current.verify_private_inputs(Path('/invented-private-inputs'))
            check.assert_called_once()

    def test_wrong_original_candidate_and_non_boolean_assertion_are_refused(self):
        for relation, candidate in [('current-targeted-observation', current.PRODUCT),
                                    ('historical-support-only', current.PREVIOUS_ACCEPTED)]:
            doc = dict(candidate_commit=candidate, checked=True)
            row = dict(id='case', candidate_commit=candidate, relation=relation,
                       object_sha256='a' * 64, assertions={'checked': True})
            objects = {'a' * 64: json.dumps(doc).encode()}
            current.verify_roots(dict(roots=[row]), objects)
            with self.assertRaises(current.frozen.PlanError):
                current.verify_roots(dict(roots=[dict(row, candidate_commit='b' * 40)]), objects)
            objects['a' * 64] = json.dumps(dict(doc, checked=1)).encode()
            with self.assertRaises(current.frozen.PlanError):
                current.verify_roots(dict(roots=[row]), objects)


if __name__ == '__main__':
    unittest.main()
