"""Synthetic tests of private evidence integrity and non-transfer boundaries."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.ci import release_ivv_current as current


class PrivateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'objects').mkdir()
        self.wire = json.dumps(dict(candidate_commit=current.PRODUCT, checked=True,
                                    count=12, rows=[dict(value='retained')])).encode()
        self.digest = current.frozen.digest(self.wire)
        self.path = self.root / 'objects' / self.digest
        self.path.write_bytes(self.wire)
        self.row = dict(path='objects/' + self.digest, sha256=self.digest,
                        size=len(self.wire), references=[])
        self.observation = dict(id='observation', candidate_commit=current.PRODUCT,
            relation='current-targeted-observation', object_sha256=self.digest,
            assertions={'checked': True, 'count': 12, 'rows/0/value': 'retained'})
        self.manifest = dict(objects=[self.row], roots=[self.observation])

    def test_exact_private_inputs_do_not_grant_acceptance(self):
        objects = current.verify_objects(self.root, self.manifest)
        result = current.verify_roots(self.manifest, objects)
        self.assertEqual(result[0]['original_candidate'], current.PRODUCT)
        self.assertIs(result[0]['original_bytes_verified'], True)
        self.assertIs(result[0]['admitted_as_current_native_pass'], False)

    def test_modified_bytes_missing_extra_and_links_rejected(self):
        self.path.write_bytes(b'substituted')
        with self.assertRaises(current.frozen.PlanError): current.verify_objects(self.root, self.manifest)
        self.path.write_bytes(self.wire)
        extra = self.root / 'objects' / ('a' * 64); extra.write_bytes(b'extra')
        with self.assertRaises(current.frozen.PlanError): current.verify_objects(self.root, self.manifest)
        extra.unlink(); self.path.unlink()
        with self.assertRaises(FileNotFoundError): current.verify_objects(self.root, self.manifest)
        other = self.root / 'outside'; other.write_bytes(self.wire); self.path.symlink_to(other)
        with self.assertRaises(current.frozen.PlanError): current.verify_objects(self.root, self.manifest)
        self.path.unlink(); os.link(other, self.path)
        with self.assertRaises(current.frozen.bundle.SigningBundleError):
            current.verify_objects(self.root, self.manifest)

    def test_graph_and_path_substitution_rejected(self):
        for change in [dict(references=['0' * 64]), dict(path='../outside'),
                       dict(size=True), dict(references=[self.digest, self.digest])]:
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest); manifest['objects'][0].update(change)
                with self.assertRaises(current.frozen.PlanError):
                    current.verify_objects(self.root, manifest)
        manifest = copy.deepcopy(self.manifest); manifest['objects'].append(self.row)
        with self.assertRaises(current.frozen.PlanError): current.verify_objects(self.root, manifest)

    def test_historical_candidate_cannot_be_relabelled_current(self):
        for change in [dict(candidate_commit=current.PREVIOUS), dict(relation='historical-support-only'),
                       dict(relation='continuity-review-required')]:
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest); manifest['roots'][0].update(change)
                with self.assertRaises(current.frozen.PlanError):
                    current.verify_roots(manifest, {self.digest: self.wire})

    def test_changed_assertion_type_false_success_or_missing_field_rejected(self):
        for assertion in [{'checked': 1}, {'checked': False}, {'absent': True},
                          {'rows/01/value': 'retained'}, {'rows/1/value': 'retained'},
                          {'count': True}, {}]:
            with self.subTest(assertion=assertion):
                manifest = copy.deepcopy(self.manifest); manifest['roots'][0]['assertions'] = assertion
                with self.assertRaises(current.frozen.PlanError):
                    current.verify_roots(manifest, {self.digest: self.wire})

    def test_duplicate_and_missing_observation_rejected(self):
        manifest = copy.deepcopy(self.manifest); manifest['roots'].append(self.observation)
        with self.assertRaises(current.frozen.PlanError):
            current.verify_roots(manifest, {self.digest: self.wire})
        with self.assertRaises(current.frozen.PlanError): current.verify_roots(self.manifest, {})

    def test_empty_diagnostic_is_exact_and_cannot_be_replaced(self):
        self.path.unlink()
        digest = current.frozen.digest(b''); path = self.root / 'objects' / digest; path.write_bytes(b'')
        manifest = dict(objects=[dict(path='objects/' + digest, sha256=digest, size=0, references=[])])
        self.assertEqual(current.verify_objects(self.root, manifest), {digest: b''})
        path.write_bytes(b'not empty')
        with self.assertRaises(current.frozen.PlanError): current.verify_objects(self.root, manifest)

    def test_current_plan_keeps_original_plan_and_package_identity_separate(self):
        plan = current.load_plan(); manifest = current.load_manifest(plan)
        self.assertEqual(plan['product_candidate'], current.PRODUCT)
        self.assertEqual(current.frozen.load_plan()['product_candidate'], current.PREVIOUS)
        self.assertEqual(len(manifest['roots']), 29)
        self.assertEqual(len(manifest['objects']), 1184)
        self.assertIs(plan['preflight_is_acceptance'], False)


if __name__ == '__main__':
    unittest.main()
