"""Synthetic IVV acceptance and independent provenance rejection boundaries."""
import copy
from datetime import datetime,timezone,timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from scripts.ci import release_ivv_consumer as consumer

p=consumer.producer
c=consumer.current


class ConsumptionTests(unittest.TestCase):
    current = c
    updater = consumer.updater
    workflow = p.WORKFLOW
    def setUp(self):
        c = self.current
        self.now=datetime(2026,10,1,12,0,tzinfo=timezone.utc)
        self.sha='a'*40;self.run=123
        self.source=dict(product_candidate=c.PRODUCT,publication_commit=self.sha)
        self.files={p.REPORT:b'synthetic',consumer.ATTESTATION:b'synthetic',
                    'native-signing/example':b'synthetic','updater/example':b'synthetic'}
        signatures=dict(schema='syswarden-current-native-signature-revalidation/v1',
            as_of='2026-10-01',checks=[dict(name=n,returncode=0,stdout_sha256='0'*64,stderr_sha256='1'*64)
                for n in ['rhel-inventory','rpm','rhel-rpm','deb','apk']],four_native_signatures_verified=True,
            offline_verification=True,product_candidate=c.PRODUCT,publication_authorized=False,
            purpose='publishing',runtime='rootless-podman-pinned-images-stdin-without-host-mounts')
        update=dict(schema='syswarden-current-candidate-updater-verification/v1',
            status='current-candidate-manifest-cryptographically-verified',product_candidate=c.PRODUCT,
            producer_commit=c.PRODUCT,producer_run_id=self.updater.RUN,
            artifact_id=self.updater.ARTIFACT,artifact_sha256=self.updater.ARCHIVE_SHA256,
            native_update_replayed=False,historical_verdicts_transferred=False,
            intermediate_release_validated=False,qualification_passed=False,publication_authorized=False)
        context=dict(repository=p.REPOSITORY,repository_id=p.REPOSITORY_ID,workflow=self.workflow,
            workflow_ref=p.REPOSITORY+'/'+self.workflow+'@refs/heads/main',publication_commit=self.sha,
            workflow_run_id=self.run,workflow_run_attempt=1,event='workflow_dispatch',
            source_ref='refs/heads/main',runner_environment='self-hosted',environment=p.ENVIRONMENT,owner_id=p.OWNER_ID)
        plan=c.load_plan();inputs=consumer.expected_inputs(c)
        self.report=dict(schema='syswarden-protected-intermediate-ivv/v1',status='ivv-accepted-for-release',
            release=plan['release'],required_assurance='IVV',accepted_at=self.now.isoformat(),context=context,
            source_binding=self.source,plan_sha256=c.PLAN_SHA256,input_verification=inputs,
            native_signature_verification=signatures,updater_verification=update,ci_verification={},
            required_checks=p.acceptance_checks(inputs,signatures,update,c,self.updater),
            product_support_verification=dict(schema='syswarden-original-product-support/v1',
                product_candidate=c.PRODUCT,run_id=plan['product_release_support'][0]['run_id'],
                files=[r['file'] for r in plan['product_release_support']],
                binary_members=plan['product_bundle_members'],original_build_attestation_verified=True,
                publication_authorized=False),
            artifact_files=p.check_inventory({k:v for k,v in self.files.items() if k not in (p.REPORT,consumer.ATTESTATION)}),
            continuity_admitted_under_named_plan=True,historical_verdicts_transferred=False,
            private_raw_inputs_uploaded=False,claim_limits=plan['claim_limits'],
            intermediate_release_validated=True,full_qualification_passed=False,
            publication_authorized=False,release_published=False,post_acceptance_requirements=plan['post_acceptance_requirements'])

    def verify(self,report):
        consumer.verify_report(report,self.files,self.source,self.run,self.now,
                               current=self.current,updater=self.updater,workflow=self.workflow)

    def test_exact_scoped_acceptance(self):
        self.verify(self.report)
        self.assertFalse(self.report['full_qualification_passed'])
        originals={r['original_candidate'] for r in self.report['input_verification']['reviewed_observations']}
        self.assertEqual(len(originals),3)

    def test_missing_checks_transferred_candidates_and_false_pass_rejected(self):
        mutations=[lambda r:r.update(intermediate_release_validated=1),
            lambda r:r.update(full_qualification_passed=True),lambda r:r.update(publication_authorized=True),
            lambda r:r.update(plan_sha256='f'*64),lambda r:r.update(status='preflight-passed'),
            lambda r:r['required_checks'].pop(),lambda r:r['required_checks'][0].update(status='skipped'),
            lambda r:r['input_verification']['reviewed_observations'][0].update(original_candidate='b'*40),
            lambda r:r['input_verification']['reviewed_observations'][0].update(admitted_as_current_native_pass=True),
            lambda r:r['native_signature_verification']['checks'].pop(),
            lambda r:r['native_signature_verification']['checks'][1].update(returncode=True),
            lambda r:r['updater_verification'].update(producer_run_id=36622881503),
            lambda r:r['context'].update(workflow_run_attempt=2)]
        for mutate in mutations:
            bad=copy.deepcopy(self.report);mutate(bad)
            with self.assertRaises(c.frozen.PlanError):self.verify(bad)

    def test_stale_future_naive_acceptance_rejected(self):
        for value in [(self.now-timedelta(hours=25)).isoformat(),
                      (self.now+timedelta(minutes=6)).isoformat(),'2026-10-01T12:00:00']:
            with self.assertRaises(c.frozen.PlanError):self.verify(dict(self.report,accepted_at=value))

    def test_artifact_tamper_and_private_upload_rejected(self):
        self.files['updater/example']=b'tampered'
        with self.assertRaises(c.frozen.PlanError):self.verify(self.report)
        self.files['private/raw.txt']=b'capture'
        self.report['artifact_files']=p.check_inventory({k:v for k,v in self.files.items() if k not in (p.REPORT,consumer.ATTESTATION)})
        with self.assertRaises(c.frozen.PlanError):self.verify(self.report)

    def statement(self):
        return dict(_type='https://in-toto.io/Statement/v1',subject=[dict(name=p.REPORT,digest=dict(sha256='d'*64))],
            predicateType='https://slsa.dev/provenance/v1',predicate=dict(buildDefinition=dict(
                buildType='https://actions.github.io/buildtypes/workflow/v1',externalParameters=dict(workflow=dict(
                    ref='refs/heads/main',repository='https://github.com/'+p.REPOSITORY,path=self.workflow)),
                internalParameters=dict(github=dict(event_name='workflow_dispatch',repository_id=str(p.REPOSITORY_ID),
                    repository_owner_id=str(p.OWNER_ID),runner_environment='self-hosted')),
                resolvedDependencies=[dict(uri=f'git+https://github.com/{p.REPOSITORY}@refs/heads/main',digest=dict(gitCommit=self.sha))]),
                runDetails=dict(builder=dict(id=f'https://github.com/{p.REPOSITORY}/{self.workflow}@refs/heads/main'),
                    metadata=dict(invocationId=f'https://github.com/{p.REPOSITORY}/actions/runs/{self.run}/attempts/1'))))

    def test_verified_slsa_requires_exact_workflow_source_run_and_runner(self):
        def check(stmt):
            wire=json.dumps([dict(verificationResult=dict(statement=stmt,signature=dict(certificate=dict(
                issuer='https://token.actions.githubusercontent.com',
                subjectAlternativeName=f'https://github.com/{p.REPOSITORY}/{self.workflow}@refs/heads/main'))))]).encode()
            consumer.verify_attestation(wire,self.sha,self.run,'d'*64,self.workflow)
        check(self.statement())
        mutations=[lambda s:s['subject'][0]['digest'].update(sha256='e'*64),
            lambda s:s['predicate']['buildDefinition']['resolvedDependencies'][0]['digest'].update(gitCommit='b'*40),
            lambda s:s['predicate']['buildDefinition']['internalParameters']['github'].update(runner_environment='github-hosted'),
            lambda s:s['predicate']['buildDefinition']['externalParameters']['workflow'].update(path='.github/workflows/release-qualification.yml'),
            lambda s:s['predicate']['runDetails']['metadata'].update(invocationId=f'https://github.com/{p.REPOSITORY}/actions/runs/{self.run}/attempts/2')]
        for mutate in mutations:
            statement=self.statement();mutate(statement)
            with self.assertRaises(c.frozen.PlanError):check(statement)

    def test_zip_traversal_link_duplicate_and_missing_report_rejected(self):
        for kind in ['traversal','link','duplicate','missing']:
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w') as archive:
                archive.writestr(p.REPORT,b'{}')
                if kind=='traversal':archive.writestr('../outside',b'x')
                elif kind=='link':
                    item=zipfile.ZipInfo('link');item.external_attr=0o120777<<16;archive.writestr(item,b'outside')
                elif kind=='duplicate':archive.writestr(p.REPORT,b'changed')
            with tempfile.TemporaryDirectory() as tmp,self.assertRaises(c.frozen.PlanError):
                consumer.unpack(buffer.getvalue(),Path(tmp)/'evidence')


if __name__=='__main__': unittest.main()
