"""Private draft lookup never falls back to publishing or ambiguous identities."""
import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.ci import release_draft as gate


class DraftTests(unittest.TestCase):
    def metadata(self):
        return dict(id=17, tag_name='v4.10.2', name='v4.10.2', draft=True, prerelease=False,
            body='Reviewed release notes', assets=[dict(id=29, name='package.deb', size=7,
            digest='sha256:' + hashlib.sha256(b'payload').hexdigest(), state='uploaded')])

    def test_unique_private_draft_resolved_through_id(self):
        calls = []
        def fetch(path):
            calls.append(path)
            return [self.metadata()] if '?' in path else self.metadata()
        self.assertEqual(gate.resolve(gate.REPOSITORY, 'v4.10.2', fetch), self.metadata())
        self.assertEqual(calls, ['repos/' + gate.REPOSITORY + '/releases?per_page=100&page=1',
                               'repos/' + gate.REPOSITORY + '/releases/17'])
        self.assertTrue(all('/tags/' not in path for path in calls))

    def test_inventory_failures_and_duplicate_tags_rejected(self):
        for rows in ([], {}, [self.metadata(), dict(self.metadata(), id=18)],
                     [self.metadata(), self.metadata()], [dict(self.metadata(), id=True)]):
            with self.subTest(rows=rows), self.assertRaises(gate.DraftError):
                gate.resolve(gate.REPOSITORY, 'v4.10.2', lambda _: rows)

    def test_discovery_inspects_later_pages(self):
        page1 = [dict(id=i + 100, tag_name='v1.00.' + str(i)) for i in range(100)]
        def fetch(path):
            if path.endswith('&page=1'): return page1
            if path.endswith('&page=2'): return [self.metadata()]
            return self.metadata()
        self.assertEqual(gate.resolve(gate.REPOSITORY, 'v4.10.2', fetch)['id'], 17)

    def test_mutation_between_list_and_exact_get_rejected(self):
        for delta in (dict(id=18), dict(draft=False), dict(tag_name='v4.10.1'), dict(prerelease=True)):
            def fetch(path):
                return [self.metadata()] if '?' in path else dict(self.metadata(), **delta)
            with self.subTest(delta=delta), self.assertRaises(gate.DraftError):
                gate.resolve(gate.REPOSITORY, 'v4.10.2', fetch)

    def test_unsafe_asset_metadata_rejected(self):
        for delta in (dict(id=True), dict(name='../outside'), dict(name='..'), dict(name='-option'),
                      dict(size=0), dict(size=True), dict(size=gate.MAX_ASSET+1),
                      dict(digest='sha256:bad'), dict(state='new')):
            doc = self.metadata();doc['assets'][0].update(delta)
            with self.subTest(delta=delta), self.assertRaises(gate.DraftError): gate.validate(doc, 'v4.10.2')
        for delta in (dict(name='other.deb'), dict(id=30)):
            doc = self.metadata();doc['assets'].append(dict(doc['assets'][0], **delta))
            with self.assertRaises(gate.DraftError): gate.validate(doc, 'v4.10.2')

    def test_exact_asset_id_and_digest_required(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv);kwargs['stdout'].write(b'payload')
            return subprocess.CompletedProcess(argv, 0)
        with tempfile.TemporaryDirectory() as temp, patch.object(gate.subprocess, 'run', side_effect=run):
            root = Path(temp)
            gate.download(gate.REPOSITORY, self.metadata(), root)
            self.assertEqual((root / 'package.deb').read_bytes(), b'payload')
            self.assertEqual(calls, [['gh','api','--method','GET','-H','Accept: application/octet-stream',
                                     'repos/' + gate.REPOSITORY + '/releases/assets/29']])
            with self.assertRaises(gate.DraftError): gate.download(gate.REPOSITORY, self.metadata(), root)

    def test_wrong_download_symlink_and_existing_destination_rejected(self):
        for wire in (b'wrong!!', b'short'):
            with tempfile.TemporaryDirectory() as temp:
                def run(argv, **kwargs): kwargs['stdout'].write(wire)
                with patch.object(gate.subprocess, 'run', side_effect=run), self.assertRaises(gate.DraftError):
                    gate.download(gate.REPOSITORY, self.metadata(), Path(temp))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);real=root/'real';real.mkdir();link=root/'link';link.symlink_to(real)
            with self.assertRaises(gate.DraftError): gate.download(gate.REPOSITORY, self.metadata(), link)

    def test_json_duplicate_keys_nonfinite_and_wrong_repository_rejected(self):
        for raw in (b'{"id":1,"id":2}', b'{"id":NaN}'):
            with self.assertRaises(gate.DraftError): gate.decode(raw)
        with self.assertRaises(gate.DraftError): gate.resolve('other/repo','v4.10.2')

    def test_workflow_retains_snapshot_and_provenance_boundaries(self):
        wire=(Path(__file__).resolve().parents[2]/'.github/workflows/release-manager.yml').read_text()
        block=wire.split('      - name: Verify Private Draft Assets Before Publication',1)[1].split('      - name:',1)[0]
        self.assertIn('scripts/ci/release_draft.py resolve',block)
        self.assertIn('scripts/ci/release_draft.py download',block)
        self.assertIn('releases/${release_id}',block)
        self.assertNotIn('releases/tags/',block)
        for value in ('snapshot_after', 'snapshot_before', 'scripts/ci/release_gate.py verify',
                      'verify_release_attestations.sh','release_notes.md','RELEASE_SHA256SUMS.txt'):
            self.assertIn(value,block)
        publish=wire.split('          revalidate_exact_draft_snapshot()',1)[1].split('\n          }',1)[0]
        self.assertIn('releases/${EXPECTED_DRAFT_RELEASE_ID}',publish)
        self.assertNotIn('releases/tags/',publish)


if __name__ == '__main__': unittest.main()
