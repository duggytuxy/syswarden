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


if __name__=='__main__':
    unittest.main()
