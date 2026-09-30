"""Synthetic provenance boundaries for IVV/IVVQ; no native acceptance fixtures."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_assurance_contract as contract


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        plan = contract.ivv.load_plan()
        self.track = dict(schema='syswarden-release-track/v1', candidate_commit=self.sha,
            release='v4.10.0', previous_version=plan['originating_transition']['previous_version'],
            transition_commit=plan['originating_transition']['commit'], transition_parent='b' * 40,
            prefix=plan['originating_transition']['prefix'], track='intermediate-validation',
            followup_commits=4, qualification_passed=False, publication_authorized=False)
        self.ivv = contract.from_classification(self.track, 'v4.10.0', self.sha)
        self.upgrade = dict(self.track, release='v5.00.0', previous_version='v4.10.0',
            prefix='Upgrade', track='full-qualification')

    def test_intermediate_keeps_product_and_publication_distinct(self):
        self.assertEqual(self.ivv.assurance, 'IVV')
        self.assertEqual(self.ivv.product_candidate, contract.PRODUCT_V4100)
        self.assertEqual(self.ivv.publication_commit, self.sha)
        self.assertEqual(self.ivv.workflow_path, '.github/workflows/release-ivv.yml')
        result = self.ivv.as_dict()
        self.assertIs(result['qualification_passed'], False)
        self.assertIs(result['intermediate_release_validated'], False)
        self.assertIs(result['publication_authorized'], False)

    def test_upgrade_always_keeps_full_qualification(self):
        value = contract.from_classification(self.upgrade, 'v5.00.0', self.sha)
        self.assertEqual(value.assurance, 'IVVQ')
        self.assertEqual(value.product_candidate, self.sha)
        self.assertEqual(value.workflow_path, '.github/workflows/release-qualification.yml')
        self.assertEqual(value.artifact_name, 'syswarden-release-qualification')

    def test_rejects_downgrade_foreign_candidate_and_forged_pass(self):
        for change in [dict(track='intermediate-validation'), dict(prefix='Major'),
                       dict(qualification_passed=True), dict(publication_authorized=True),
                       dict(candidate_commit='c'*40), dict(followup_commits=True),
                       dict(followup_commits=-1), dict(skip=True), dict(transition_commit='HEAD')]:
            with self.subTest(change=change), self.assertRaises(contract.ivv.PlanError):
                contract.from_classification(dict(self.upgrade, **change), 'v5.00.0', self.sha)

    def test_future_intermediate_cannot_borrow_frozen_v4100(self):
        with self.assertRaises(contract.ivv.PlanError):
            contract.from_classification(dict(self.track, release='v4.10.1', prefix='Patch'),
                                         'v4.10.1', self.sha)

    def test_current_intermediate_requires_reviewed_original_transition(self):
        for change in [dict(prefix='Minor'), dict(transition_commit='c'*40),
                       dict(previous_version='v4.03.0'), dict(track='full-qualification')]:
            with self.subTest(change=change), self.assertRaises(contract.ivv.PlanError):
                contract.from_classification(dict(self.track, **change), 'v4.10.0', self.sha)

    def run_record(self, selected=None):
        selected = selected or self.ivv
        return dict(id=123, head_sha=selected.publication_commit, head_branch='main',
            event='workflow_dispatch', path=selected.workflow_path, run_attempt=1,
            status='completed', conclusion='success',
            repository=dict(id=contract.REPOSITORY_ID, full_name=contract.REPOSITORY),
            head_repository=dict(id=contract.REPOSITORY_ID, full_name=contract.REPOSITORY),
            actor=dict(id=contract.OWNER_ID, login='duggytuxy'),
            triggering_actor=dict(id=contract.OWNER_ID, login='duggytuxy'))

    def artifact(self):
        return dict(id=234, name=self.ivv.artifact_name, size_in_bytes=300, expired=False,
            digest='sha256:' + 'd'*64, workflow_run=dict(id=123,
                repository_id=contract.REPOSITORY_ID, head_repository_id=contract.REPOSITORY_ID,
                head_sha=self.sha, head_branch='main'))

    def test_unique_completed_producer_and_artifact(self):
        run = self.run_record()
        self.assertEqual(contract.select_unique_run([run], self.ivv, 123), run)
        artifact = self.artifact()
        self.assertEqual(contract.select_artifact([artifact], self.ivv, 123), artifact)

    def test_rejects_wrong_workflow_attempt_branch_or_actor(self):
        for key, value in [('path','.github/workflows/release-qualification.yml'),
                           ('run_attempt',2), ('run_attempt',True), ('head_sha','f'*40),
                           ('head_branch','feature'), ('event','pull_request'),
                           ('status','in_progress'), ('conclusion','failure')]:
            with self.subTest(key=key):
                row = self.run_record();row[key] = value
                with self.assertRaises(contract.ivv.PlanError): contract.verify_run(row,self.ivv,123)
        for key in ['repository','head_repository','actor','triggering_actor']:
            row = self.run_record();row[key]['id'] += 1
            with self.subTest(key=key), self.assertRaises(contract.ivv.PlanError):
                contract.verify_run(row,self.ivv,123)

    def test_same_sha_fork_is_not_a_valid_producer(self):
        row = self.run_record();row['head_repository']['full_name'] = 'attacker/syswarden'
        with self.assertRaises(contract.ivv.PlanError): contract.select_unique_run([row],self.ivv)

    def test_rejects_ambiguous_active_missing_or_requested_other_run(self):
        run = self.run_record()
        for rows in [[], [run,copy.deepcopy(run)],
                     [run,dict(run,id=124,status='in_progress',conclusion=None)]]:
            with self.subTest(rows=rows), self.assertRaises(contract.ivv.PlanError):
                contract.select_unique_run(rows,self.ivv)
        with self.assertRaises(contract.ivv.PlanError): contract.select_unique_run([run],self.ivv,124)
        with self.assertRaises(contract.ivv.PlanError): contract.select_unique_run([run],self.ivv,True)

    def test_unrelated_failed_run_does_not_replace_exact_producer(self):
        row = self.run_record()
        older = dict(row,id=100,head_sha='b'*40,status='completed',conclusion='failure')
        self.assertEqual(contract.select_unique_run([older,row],self.ivv),row)

    def test_rejects_substituted_artifact_and_producer_metadata(self):
        for key,value in [('name','syswarden-release-qualification'),('id',True),('expired',True),
                          ('expired',0),('size_in_bytes',0),('size_in_bytes',True),
                          ('size_in_bytes',129*1024*1024),('digest','missing')]:
            row=self.artifact();row[key]=value
            with self.subTest(key=key),self.assertRaises(contract.ivv.PlanError):
                contract.select_artifact([row],self.ivv,123)
        for key,value in [('id',124),('head_branch','release'),('head_sha','f'*40),
                          ('repository_id',42),('head_repository_id',42)]:
            row=self.artifact();row['workflow_run'][key]=value
            with self.subTest(key=key),self.assertRaises(contract.ivv.PlanError):
                contract.select_artifact([row],self.ivv,123)
        row=self.artifact()
        with self.assertRaises(contract.ivv.PlanError): contract.select_artifact([row,row],self.ivv,123)

    def test_upgrade_cannot_consume_intermediate_producer(self):
        value=contract.from_classification(self.upgrade,'v5.00.0',self.sha)
        with self.assertRaises(contract.ivv.PlanError):
            contract.verify_run(self.run_record(),value,123)
        self.assertEqual(contract.select_unique_run([self.run_record(value)],value)['id'],123)


if __name__ == '__main__':
    unittest.main()
