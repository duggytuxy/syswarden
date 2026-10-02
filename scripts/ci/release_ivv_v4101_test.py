"""Retained native results cannot acquire a new candidate or invented success."""
import copy
import json
from pathlib import Path
import unittest
from scripts.ci import release_ivv_v4101 as current
from scripts.ci import release_ivv_consumer_test as old
from scripts.ci import candidate_update_verify_v4101 as updater


class PatchConsumptionTests(old.ConsumptionTests):
    current = current
    updater = updater
    workflow = '.github/workflows/release-ivv-v4101.yml'


class PrivateCaptureTests(unittest.TestCase):
    def fixture(self):
        objects = {}
        rows = []
        def put(wire, references=()):
            digest = current.frozen.digest(wire)
            objects[digest] = wire
            rows.append(dict(sha256=digest, references=list(references)))
            return digest
        source, stdout, stderr = put(b'script'), put(b'{"ok":true}\n'), put(b'')
        receipt = dict(source_sha256=source, stdout_sha256=stdout, stderr_sha256=stderr, rc=1)
        put(json.dumps(receipt).encode(), (source, stdout, stderr))
        doc = dict(receipt=receipt, observations=[dict(ok=True)])
        root = put(json.dumps(doc).encode())
        return dict(objects=rows, roots=[dict(object_sha256=root)]), objects, doc

    def test_exact_receipt_and_nonzero_exit_retained(self):
        manifest, objects, doc = self.fixture()
        current.verify_capture_bindings(manifest, objects)
        self.assertEqual(doc['receipt']['rc'], 1)
        # A log with JSON-looking text is not parsed as an original receipt.
        objects['log'] = b'{"source_sha256" "stdout_sha256" malformed log'
        manifest['objects'].append(dict(sha256='log', references=[]))
        current.verify_capture_bindings(manifest, objects)

    def test_derived_success_or_stdout_substitution_rejected(self):
        for field in ('exit', 'output', 'missing', 'graph'):
            manifest, objects, doc = self.fixture()
            if field == 'exit': doc['receipt']['rc'] = 0
            if field == 'output': doc['observations'] = [dict(ok=False)]
            if field == 'missing': objects.pop(doc['receipt']['stdout_sha256'])
            if field == 'graph':
                for row in manifest['objects']: row['references'] = []
            objects[manifest['roots'][0]['object_sha256']] = json.dumps(doc).encode()
            with self.subTest(field=field), self.assertRaises(current.frozen.PlanError):
                current.verify_capture_bindings(manifest, objects)

    def test_reviewed_plan_cannot_transfer_original_native_candidate(self):
        plan = current.load_plan(); manifest = current.load_manifest(plan)
        self.assertEqual(len(manifest['objects']), 113)
        self.assertEqual(len(manifest['roots']), 12)
        self.assertEqual(plan['required_assurance'], 'IVV')
        row = dict(id='native', candidate_commit=current.PREVIOUS,
                   relation='continuity-review-required', object_sha256='a'*64,
                   assertions={'checked': True})
        wire = json.dumps(dict(candidate_commit=current.PREVIOUS, checked=True)).encode()
        result = current.verify_roots(dict(roots=[row]), {'a'*64: wire})
        self.assertIs(result[0]['admitted_as_current_native_pass'], False)
        for change in (dict(candidate_commit=current.PRODUCT), dict(relation='current-targeted-observation')):
            bad = copy.deepcopy(row); bad.update(change)
            with self.assertRaises(current.frozen.PlanError):
                current.verify_roots(dict(roots=[bad]), {'a'*64: wire})


if __name__ == '__main__': unittest.main()
