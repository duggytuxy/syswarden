"""Known IVV profiles cannot grant acceptance or replace an Upgrade IVVQ gate."""
import copy
import unittest
from scripts.ci import release_ivv_profile as profiles
from scripts.ci import release_assurance_contract as assurance
from scripts.ci import release_ivv_current as previous
from scripts.ci import release_ivv_v4101 as current
from scripts.ci import release_ivv_v4102 as patch2
from scripts.ci import release_ivv_v4103 as patch3
from scripts.ci import release_ivv_consumer as consumer
from scripts.ci import release_ivv_producer as producer


class ProfileTests(unittest.TestCase):
    def test_separate_exact_product_and_workflow(self):
        old, new = profiles.load('v4.10.0'), profiles.load('v4.10.1')
        self.assertEqual(old.product, previous.PRODUCT)
        self.assertEqual(new.product, current.PRODUCT)
        self.assertNotEqual(old.workflow, new.workflow)
        newest = profiles.load('v4.10.2')
        self.assertEqual(newest.product, patch2.PRODUCT)
        self.assertNotEqual(newest.workflow, new.workflow)
        self.assertEqual(previous.PLAN_SHA256, 'fc8147e574f5728147787700fe6c65961eb0be61562e467c8436dd56c9b176ab')
        self.assertEqual(previous.load_plan()['private_input_manifest_sha256'], 'ca7b71603aa2758ee140daaa467d1a8fa39a8d50a7e3b3cbec1107d09f033567')
        self.assertEqual(profiles.load('v4.10.3').product, patch3.PRODUCT)
        self.assertNotEqual(profiles.load('v4.10.3').workflow, newest.workflow)
        self.assertEqual(profiles.load('v4.10.4').product, '0e966d409b6b9d19116597edee1feafad0c83688')
        for release in ('v4.10.5', 'v5.00.0', 'v6.00.0', None):
            with self.assertRaises(previous.frozen.PlanError): profiles.load(release)

    def classification(self, release='v4.10.1', prefix='Patch', track='intermediate-validation'):
        return dict(schema='syswarden-release-track/v1', candidate_commit='a' * 40,
            release=release, previous_version='v4.10.0', transition_commit='9e4c76aa59da3a04746a9b957f962f1b47b6c1b2',
            transition_parent='4ca15287a2ef71658e73ee672db6e1798e526c4c', prefix=prefix, track=track,
            followup_commits=2, qualification_passed=False, publication_authorized=False)

    def test_patch_profile_and_original_upgrade_track(self):
        contract = assurance.from_classification(self.classification(), 'v4.10.1', 'a' * 40)
        self.assertEqual(contract.product_candidate, current.PRODUCT)
        self.assertEqual(contract.assurance, 'IVV')
        for release in ('v5.00.0', 'v6.00.0'):
            row = self.classification(release, 'Upgrade', 'full-qualification')
            row['previous_version'] = 'v4.10.0' if release == 'v5.00.0' else 'v5.10.0'
            self.assertEqual(assurance.from_classification(row, release, 'a' * 40).assurance, 'IVVQ')
            with self.assertRaises(previous.frozen.PlanError):
                assurance.from_classification(dict(row, track='intermediate-validation'), release, 'a' * 40)

    def test_old_native_or_updater_verdict_cannot_move_to_new_profile(self):
        profile = profiles.load('v4.10.1'); inputs = consumer.expected_inputs(current)
        signatures = dict(four_native_signatures_verified=True, purpose='publishing', product_candidate=current.PRODUCT)
        update = dict(product_candidate=current.PRODUCT, producer_run_id=profile.updater.RUN,
            status='current-candidate-manifest-cryptographically-verified', historical_verdicts_transferred=False)
        checks = producer.acceptance_checks(inputs, signatures, update, current, profile.updater)
        self.assertEqual([r['id'] for r in checks], current.load_plan()['required_acceptance_checks'])
        for bad in (dict(signatures, product_candidate=previous.PRODUCT), dict(signatures, purpose='qualification')):
            with self.assertRaises(current.frozen.PlanError):
                producer.acceptance_checks(inputs, bad, update, current, profile.updater)
        with self.assertRaises(current.frozen.PlanError):
            producer.acceptance_checks(inputs, signatures, dict(update, producer_run_id=36842481776), current, profile.updater)
        for mutate in (lambda r:r['reviewed_observations'].pop(),
                       lambda r:r['reviewed_observations'][0].update(admitted_as_current_native_pass=True)):
            bad = copy.deepcopy(inputs); mutate(bad)
            with self.assertRaises(current.frozen.PlanError):
                producer.acceptance_checks(bad, signatures, update, current, profile.updater)


if __name__ == '__main__': unittest.main()
