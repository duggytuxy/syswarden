"""Real temporary Git histories with explicitly synthetic packages and records."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_ivv_publication as gate


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repository';self.repo.mkdir()
        self.git('init','-q')
        self.git('config','user.name','Synthetic Test')
        self.git('config','user.email','test@example.invalid')
        self.git('config','commit.gpgsign','false')
        for name, wire in {'runtime.go':'original runtime\n','verifier.py':'original verifier\n',
                           'README.md':'original README\n','policy.md':'original policy\n'}.items():
            (self.repo/name).write_text(wire)
        self.commit();self.product=self.git('rev-parse','HEAD')
        (self.repo/'consumer.py').write_text('original independent consumer\n')
        self.commit();self.consumer=self.git('rev-parse','HEAD')
        (self.repo/'README.md').write_text('exact reviewed Discord addition\n')
        (self.repo/'new-helper.py').write_text('reviewed new helper\n')
        self.commit();self.readme=self.git('rev-parse','HEAD:README.md')
        self.plan=dict(product_candidate=self.product,release='v4.10.0',
            publication_source_change_allowlist=['policy.md'],retained_records=[],product_packages=[],
            required_checks=[{'id':'still-required'}])
        self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.packages=self.root/'packages';self.packages.mkdir()
        for target,name,wire in [(self.evidence,'historic.json',json.dumps({'candidate_commit':'b'*40}).encode()),
                                  (self.packages,'candidate.rpm',b'synthetic frozen RPM')]:
            (target/name).write_bytes(wire)
            row=dict(path=name,size=len(wire),sha256=gate.ivv.digest(wire))
            if target==self.evidence:
                row.pop('path');row.update(id='historic',candidate_commit='b'*40,relation='historical-support-only')
                self.plan['retained_records'].append(row)
            else:self.plan['product_packages'].append(row)
        for target,name,value in [(gate,'ORIGINAL_CONSUMER',self.consumer),
                                  (gate,'README_BLOB',self.readme),
                                  (gate,'PINNED_VERIFIERS',frozenset({'verifier.py','consumer.py'})),
                                  (gate,'EXTENSION_PATHS',frozenset({'consumer.py','new-helper.py','README.md'}))]:
            context=patch.object(target,name,value);context.start();self.addCleanup(context.stop)
        context=patch.object(gate.ivv,'load_plan',return_value=self.plan);context.start();self.addCleanup(context.stop)
        context=patch.object(gate.assurance,'derive',side_effect=lambda repo,release,publication:
            gate.assurance.AssuranceContract('intermediate-validation','IVV',release,publication,self.product,
                '.github/workflows/release-ivv.yml','syswarden-release-ivv'))
        context.start();self.addCleanup(context.stop)

    def git(self,*args):
        return subprocess.check_output(['git','-c','core.fsmonitor=false',*args],cwd=self.repo,
            text=True,stderr=subprocess.DEVNULL).strip()

    def commit(self):
        self.git('add','.');self.git('commit','-qm','synthetic fixture')

    def verify(self):
        return gate.preflight(self.repo,self.git('rev-parse','HEAD'),self.evidence,self.packages)

    def test_exact_extension_preserves_original_verifiers_and_historical_identity(self):
        result=self.verify()
        self.assertEqual(result['source_binding']['product_candidate'],self.product)
        self.assertEqual(result['source_binding']['original_consumer_commit'],self.consumer)
        self.assertEqual(result['retained_records'][0]['candidate_commit'],'b'*40)
        self.assertIs(result['retained_records'][0]['admitted_as_current_pass'],False)
        for field in ['native_results_transferred','intermediate_release_validated',
                      'qualification_passed','publication_authorized']:
            self.assertIs(result[field],False)
        self.assertNotIn('README.md',self.plan['publication_source_change_allowlist'])

    def test_runtime_change_and_unknown_build_input_are_rejected(self):
        for name in ['runtime.go','new-build-hook.sh']:
            with self.subTest(name=name):
                original=self.git('rev-parse','HEAD')
                (self.repo/name).write_text('unreviewed product change\n');self.commit()
                with self.assertRaises(gate.ivv.PlanError):self.verify()
                self.git('reset','--hard',original)

    def test_pinned_original_consumer_cannot_change_even_on_admitted_path(self):
        (self.repo/'consumer.py').write_text('bypassed verifier\n');self.commit()
        with self.assertRaisesRegex(gate.ivv.PlanError,'verification dependency changed'):self.verify()

    def test_readme_must_match_exact_reviewed_blob(self):
        (self.repo/'README.md').write_text('additional unreviewed documentation\n');self.commit()
        with self.assertRaisesRegex(gate.ivv.PlanError,'README differs'):self.verify()

    def test_uncommitted_and_hidden_index_changes_are_rejected(self):
        (self.repo/'runtime.go').write_text('dirty runtime\n')
        with self.assertRaises(gate.ivv.PlanError):self.verify()
        self.git('checkout','--','runtime.go')
        self.git('update-index','--assume-unchanged','runtime.go')
        with self.assertRaisesRegex(gate.ivv.PlanError,'hidden index'):self.verify()

    def test_original_consumer_ancestry_is_mandatory(self):
        with patch.object(gate,'ORIGINAL_CONSUMER','e'*40):
            with self.assertRaises(gate.ivv.PlanError):self.verify()

    def test_substituted_signed_package_or_historical_record_is_rejected(self):
        for target in [self.packages/'candidate.rpm',self.evidence/'historic.json']:
            with self.subTest(path=target):
                original=target.read_bytes();target.write_bytes(b'x'*len(original))
                with self.assertRaises(gate.ivv.PlanError):self.verify()
                target.write_bytes(original)

    def test_source_change_during_input_verification_is_rejected(self):
        actual=gate.ivv.verify_inputs
        def changed(*args):
            result=actual(*args)
            (self.repo/'runtime.go').write_text('concurrent mutation\n')
            return result
        with patch.object(gate.ivv,'verify_inputs',side_effect=changed):
            with self.assertRaises(gate.ivv.PlanError):self.verify()


class OriginalUpdaterIntegrationTests(unittest.TestCase):
    """Synthetic control-flow tests; real signature verification is a separate check."""
    def setUp(self):
        self.paths = [Path('/synthetic/' + name) for name in
                      ('publication', 'consumer', 'producer', 'native', 'updater', 'archive')]
        self.publication = 'a' * 40
        self.source = {'publication_commit': self.publication,
                       'product_candidate': gate.original_updater.PRODUCT}
        self.frozen = {'publication_commit': gate.ORIGINAL_CONSUMER,
                       'updater_producer_commit': gate.original_updater.PRODUCER}
        self.receipt = dict(schema='syswarden-intermediate-updater-revalidation/v1',
            status='original-updater-reverified-native-acceptance-pending',
            source_binding=self.frozen, updater_artifact_id=gate.original_updater.ARTIFACT,
            updater_archive_sha256=gate.original_updater.ARCHIVE_SHA256,
            native_update_accepted=False, intermediate_release_validated=False,
            qualification_passed=False, publication_authorized=False)
        self.source_patch = patch.object(gate, 'source_binding', return_value=self.source)
        self.frozen_patch = patch.object(gate.original_updater, 'publication_binding', return_value=self.frozen)
        self.verify_patch = patch.object(gate.original_updater, 'verify', return_value=self.receipt)
        self.source_call = self.source_patch.start();self.addCleanup(self.source_patch.stop)
        self.frozen_call = self.frozen_patch.start();self.addCleanup(self.frozen_patch.stop)
        self.verify_call = self.verify_patch.start();self.addCleanup(self.verify_patch.stop)

    def run_check(self):
        return gate.verify_original_updater(self.paths[0], self.publication, *self.paths[1:])

    def test_executes_original_verifier_once_and_keeps_three_source_identities(self):
        result = self.run_check()
        self.verify_call.assert_called_once_with(self.paths[1], gate.ORIGINAL_CONSUMER, *self.paths[2:])
        self.assertEqual(result['source_binding']['publication_commit'], self.publication)
        self.assertEqual(result['original_consumer_commit'], gate.ORIGINAL_CONSUMER)
        self.assertEqual(result['original_producer_commit'], gate.original_updater.PRODUCER)
        self.assertEqual(result['original_updater_result'], self.receipt)
        for field in ('native_update_accepted', 'intermediate_release_validated',
                      'qualification_passed', 'publication_authorized'):
            self.assertIs(result[field], False)
        self.assertEqual(self.source_call.call_count, 2)
        self.assertEqual(self.frozen_call.call_count, 2)

    def test_verifier_failure_does_not_produce_a_bound_result(self):
        self.verify_call.side_effect = gate.ivv.PlanError('signature rejected')
        with self.assertRaisesRegex(gate.ivv.PlanError, 'signature rejected'):self.run_check()

    def test_original_verifier_result_cannot_claim_acceptance_or_another_artifact(self):
        for field, value in [('native_update_accepted', True), ('intermediate_release_validated', True),
                             ('qualification_passed', True), ('publication_authorized', True),
                             ('schema', 'supplied-pass'), ('status', 'pass'),
                             ('updater_artifact_id', 1), ('updater_archive_sha256', 'f' * 64),
                             ('source_binding', {'publication_commit': self.publication})]:
            with self.subTest(field=field):
                self.verify_call.return_value = dict(self.receipt, **{field: value})
                with self.assertRaisesRegex(gate.ivv.PlanError, 'original updater result differs'):
                    self.run_check()

    def test_publication_mutation_during_verification_is_rejected(self):
        self.source_call.side_effect = [self.source, dict(self.source, publication_commit='b' * 40)]
        with self.assertRaisesRegex(gate.ivv.PlanError, 'publication changed'):self.run_check()

    def test_original_consumer_mutation_during_verification_is_rejected(self):
        self.frozen_call.side_effect = [self.frozen, dict(self.frozen, publication_commit='b' * 40)]
        with self.assertRaisesRegex(gate.ivv.PlanError, 'frozen verifier source changed'):self.run_check()

    def test_cli_rechecks_frozen_inputs_after_signature_verification(self):
        import contextlib
        import io
        import sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for changed in (False, True):
                with self.subTest(changed=changed):
                    output = root / ('output-' + str(changed) + '.json')
                    argv = ['release_ivv_publication.py', '--repository', str(root),
                        '--publication-sha', self.publication, '--evidence-root', str(root),
                        '--package-root', str(root), '--output', str(output)]
                    for option in ('original-consumer-repository', 'original-producer-repository',
                                   'candidate-bundle', 'candidate-archive'):
                        argv.extend(['--' + option, str(root)])
                    initial = {'source_binding': self.source, 'frozen': 'original bytes'}
                    final = dict(initial, frozen='substituted') if changed else dict(initial)
                    with patch.object(sys, 'argv', argv), patch.object(gate, 'preflight',
                            side_effect=[initial, final]) as input_checks, patch.object(gate,
                            'verify_original_updater', return_value={'source_binding': self.source}) as verifier, \
                            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        if changed:
                            with self.assertRaises(SystemExit) as caught:gate.main()
                            self.assertEqual(caught.exception.code, 1)
                            self.assertFalse(output.exists())
                        else:
                            self.assertEqual(gate.main(), 0)
                            self.assertIn('original_updater_reverification', json.loads(output.read_text()))
                        self.assertEqual(input_checks.call_count, 2)
                        verifier.assert_called_once()

    def test_cli_rejects_partial_updater_inputs_before_reading_or_writing(self):
        import sys
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);output = root / 'must-not-exist.json'
            for option in ('original-consumer-repository', 'original-producer-repository',
                           'candidate-bundle', 'candidate-archive'):
                result = subprocess.run([sys.executable, str(Path(gate.__file__)),
                    '--repository', str(root), '--publication-sha', self.publication,
                    '--evidence-root', str(root), '--package-root', str(root),
                    '--output', str(output), '--' + option, str(root)],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 2)
                self.assertIn('requires all four original updater inputs', result.stderr)
                self.assertFalse(output.exists())


if __name__=='__main__':
    unittest.main()
