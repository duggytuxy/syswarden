"""Synthetic tests; these do not assert that a native migration was performed."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import release_ivv_updater as gate


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.document = dict(id=gate.ARTIFACT,
            name=f'syswarden-candidate-update-bundle-4.10.0-{gate.RUN}-1-{gate.PRODUCT}',
            size_in_bytes=gate.ARCHIVE_SIZE, digest='sha256:' + gate.ARCHIVE_SHA256,
            expired=False, workflow_run=dict(id=gate.RUN, repository_id=1153695079,
            head_repository_id=1153695079, head_branch='main', head_sha=gate.PRODUCER))

    def test_original_archive_remains_verifiable_after_download_expiry(self):
        for expired in (False, True):
            self.document['expired'] = expired
            gate.verify_artifact_metadata(self.document)

    def test_wrong_identity_size_digest_or_boolean_type_rejected(self):
        for change in (dict(id=True), dict(id=1), dict(name='other'),
                       dict(size_in_bytes=1), dict(digest='sha256:'+'0'*64), dict(expired=0)):
            with self.subTest(change=change), self.assertRaises(gate.ivv.PlanError):
                gate.verify_artifact_metadata(dict(self.document, **change))

    def test_wrong_run_source_branch_and_fork_rejected(self):
        for change in (dict(id=1), dict(head_sha=gate.PRODUCT), dict(head_branch='feature'),
                       dict(repository_id=1), dict(head_repository_id=1)):
            document = copy.deepcopy(self.document)
            document['workflow_run'].update(change)
            with self.subTest(change=change), self.assertRaises(gate.ivv.PlanError):
                gate.verify_artifact_metadata(document)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'archive.zip'
        self.files = {name: ('synthetic ' + name).encode() for name in gate.consumer.FILES}
        self.write_archive()

    def write_archive(self, extra=None, mode=None):
        with zipfile.ZipFile(self.path, 'w') as archive:
            for name, wire in self.files.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                if name == gate.consumer.DESCRIPTOR and mode is not None:
                    info.external_attr = mode << 16
                archive.writestr(info, wire)
            if extra:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr(extra, b'untrusted entry')

    def verify_fixture(self, files=None):
        # Only fixture hashes are substituted. All ZIP/path checks run for real.
        wire = self.path.read_bytes()
        with patch.object(gate, 'ARCHIVE_SHA256', gate.ivv.digest(wire)), \
                patch.object(gate, 'ARCHIVE_SIZE', len(wire)):
            return gate.verify_archive(self.path, self.files if files is None else files)

    def test_complete_original_archive_matches_each_staged_byte(self):
        self.assertEqual(self.verify_fixture(), gate.ivv.digest(self.path.read_bytes()))

    def test_mutated_staging_cannot_be_accepted_by_rewritten_checksums(self):
        files = dict(self.files)
        files[gate.consumer.DESCRIPTOR] = b'forged descriptor'
        with self.assertRaisesRegex(gate.ivv.PlanError, 'staged updater'):
            self.verify_fixture(files)

    def test_unreviewed_archive_bytes_rejected_before_reading_entries(self):
        with self.assertRaisesRegex(gate.ivv.PlanError, 'reviewed GitHub artifact'):
            gate.verify_archive(self.path, self.files)

    def test_extra_traversal_duplicate_or_directory_entry_rejected(self):
        for extra in ('extra.json', '../other', gate.consumer.DESCRIPTOR, 'node01/'):
            self.write_archive(extra=extra)
            with self.subTest(extra=extra), self.assertRaises(gate.ivv.PlanError):
                self.verify_fixture()

    def test_symlink_fifo_device_zip_entries_rejected(self):
        for mode in (stat.S_IFLNK | 0o600, stat.S_IFIFO | 0o600, stat.S_IFCHR | 0o600):
            self.write_archive(mode=mode)
            with self.subTest(mode=mode), self.assertRaises(gate.ivv.PlanError):
                self.verify_fixture()

    def test_symlink_parent_and_hardlinked_archive_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(gate.ivv.PlanError):
            gate.verify_archive(alias / self.path.name, self.files)
        os.link(self.path, self.root / 'hardlink.zip')
        with self.assertRaises(gate.ivv.bundle.SigningBundleError):
            self.verify_fixture()


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'publication'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Synthetic test fixture')
        self.git('config', 'commit.gpgsign', 'false')
        (self.repo / 'runtime.go').write_text('unchanged runtime\n')
        for name in gate.VERIFIER_PATHS:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original verifier fixture\n')
        self.commit('original product')
        self.product = self.git('rev-parse', 'HEAD')
        (self.repo / 'original-tooling.txt').write_text('producer tooling\n')
        self.commit('original producer')
        self.producer_sha = self.git('rev-parse', 'HEAD')
        self.producer = Path(self.temp.name) / 'producer'
        self.git('clone', '--no-hardlinks', str(self.repo), str(self.producer))
        self.plan = dict(product_candidate=self.product,
            publication_source_change_allowlist=['original-tooling.txt'] + sorted(gate.VERIFIER_PATHS))
        self.enterContext(patch.object(gate, 'PRODUCT', self.product))
        self.enterContext(patch.object(gate, 'PRODUCER', self.producer_sha))
        self.enterContext(patch.object(gate.ivv, 'load_plan', return_value=self.plan))
        self.classifier = self.enterContext(patch.object(gate.ivv, 'classify', return_value={'track':'intermediate-validation'}))

    def git(self, *args, cwd=None):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', *args],
            cwd=cwd or self.repo, stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)

    def verify(self):
        return gate.publication_binding(self.repo, self.git('rev-parse', 'HEAD'), self.producer)

    def test_separate_commits_keep_original_verifier_and_product_identity(self):
        path = self.repo / 'scripts/ci/release_ivv_updater.py'
        path.write_text('reviewed consumer extension\n')
        self.commit('publication consumer')
        original = copy.deepcopy(self.plan)
        result = self.verify()
        self.assertEqual(result['product_candidate'], self.product)
        self.assertEqual(result['updater_producer_commit'], self.producer_sha)
        self.assertNotEqual(result['publication_commit'], self.producer_sha)
        self.assertEqual(self.plan, original)

    def test_uncommitted_publication_or_producer_rejected(self):
        for repository in (self.repo, self.producer):
            path = repository / 'runtime.go'
            original = path.read_text()
            path.write_text('dirty input\n')
            with self.subTest(repository=repository), self.assertRaises(gate.ivv.PlanError):
                self.verify()
            path.write_text(original)

    def test_committed_runtime_change_rejected(self):
        (self.repo / 'runtime.go').write_text('changed product\n')
        self.commit('changed runtime')
        with self.assertRaisesRegex(gate.ivv.PlanError, 'frozen product'):
            self.verify()

    def test_verifier_change_in_old_allowlist_still_rejected(self):
        (self.repo / 'scripts/ci/candidate_update_bundle_verify.py').write_text('weakened verifier\n')
        self.commit('changed consumer')
        with self.assertRaisesRegex(gate.ivv.PlanError, 'dependency changed'):
            self.verify()

    def test_wrong_producer_checkout_rejected(self):
        self.git('checkout', '--detach', self.product, cwd=self.producer)
        with self.assertRaisesRegex(gate.ivv.PlanError, 'not checked out'):
            self.verify()

    def test_upgrade_classification_failure_is_not_ignored(self):
        self.classifier.side_effect = gate.ivv.PlanError('Upgrade cannot use IVV')
        with self.assertRaisesRegex(gate.ivv.PlanError, 'Upgrade'):
            self.verify()


class ConsumerExecutionTests(unittest.TestCase):
    def test_fresh_consumer_failure_cannot_accept_a_supplied_receipt(self):
        with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaisesRegex(gate.ivv.PlanError, 'original independent'):
                gate.original_consumer(Path('/producer'), Path('/native'), Path('/updater'))
        argv = run.call_args.args[0]
        self.assertIn('/producer/scripts/ci/candidate_update_bundle_verify.py', argv)
        self.assertEqual(argv[argv.index('--publication-sha') + 1], gate.PRODUCER)
        self.assertNotIn('PYTHONPATH', run.call_args.kwargs['env'])


class VerificationFlowTests(unittest.TestCase):
    """Only the orchestration uses fixtures; signature verification is delegated."""
    def setUp(self):
        self.source = dict(product_candidate=gate.PRODUCT, publication_commit='a'*40)
        self.files = {gate.consumer.DESCRIPTOR:b'synthetic descriptor'}
        self.receipt = dict(schema='syswarden-candidate-update-consumption/v2',
            status='candidate-updater-verified-not-release-validated',
            product_candidate=gate.PRODUCT, publication_commit=gate.PRODUCER,
            producer_run_id=gate.RUN, descriptor_sha256=gate.ivv.digest(self.files[gate.consumer.DESCRIPTOR]),
            intermediate_release_validated=False, qualification_passed=False,
            publication_authorized=False)
        self.enterContext(patch.object(gate,'DESCRIPTOR_SHA256',self.receipt['descriptor_sha256']))
        self.binding=self.enterContext(patch.object(gate,'publication_binding',return_value=self.source))
        self.snapshot=self.enterContext(patch.object(gate.consumer,'snapshot',return_value=self.files))
        self.archive=self.enterContext(patch.object(gate,'verify_archive',return_value=gate.ARCHIVE_SHA256))
        self.enterContext(patch.object(gate.consumer,'command',return_value=b'{"fixture":true}'))
        self.metadata=self.enterContext(patch.object(gate,'verify_artifact_metadata'))
        self.consume=self.enterContext(patch.object(gate,'original_consumer',return_value=self.receipt))

    def verify(self):
        return gate.verify(Path('/publication'),'a'*40,Path('/producer'),
                           Path('/native'),Path('/updater'),Path('/archive.zip'))

    def test_success_is_only_a_prerequisite_and_fresh_consumer_is_required(self):
        result=self.verify()
        self.consume.assert_called_once_with(Path('/producer'),Path('/native'),Path('/updater'))
        for key in ('native_update_accepted','intermediate_release_validated',
                    'qualification_passed','publication_authorized'):
            self.assertIs(result[key],False)
        self.assertEqual(self.binding.call_count,2)
        self.assertEqual(self.snapshot.call_count,2)
        self.assertEqual(self.archive.call_count,2)

    def test_wrong_original_receipt_identity_or_success_claim_is_rejected(self):
        original=dict(self.receipt)
        for change in (dict(product_candidate='0'*40),dict(publication_commit='a'*40),
                       dict(producer_run_id=True),dict(descriptor_sha256='0'*64),
                       dict(schema='supplied-pass'),dict(intermediate_release_validated=True),
                       dict(qualification_passed=True),dict(publication_authorized=True),
                       dict(publication_authorized=0)):
            self.consume.return_value=dict(original,**change)
            with self.subTest(change=change),self.assertRaises(gate.ivv.PlanError):
                self.verify()

    def test_untrusted_artifact_stops_before_fresh_consumer(self):
        self.metadata.side_effect=gate.ivv.PlanError('wrong original artifact')
        with self.assertRaises(gate.ivv.PlanError):self.verify()
        self.consume.assert_not_called()

    def test_changed_source_staging_or_archive_after_verification_is_rejected(self):
        for field in ('source','staging','archive'):
            self.binding.side_effect=None;self.snapshot.side_effect=None;self.archive.side_effect=None
            if field=='source':self.binding.side_effect=[self.source,dict(self.source,publication_commit='b'*40)]
            if field=='staging':self.snapshot.side_effect=[self.files,{gate.consumer.DESCRIPTOR:b'changed'}]
            if field=='archive':self.archive.side_effect=[gate.ARCHIVE_SHA256,'0'*64]
            with self.subTest(field=field),self.assertRaises(gate.ivv.PlanError):self.verify()


if __name__ == '__main__':
    unittest.main()
