#!/usr/bin/env python3
"""Adversarial checks for immutable mixed-candidate proof preparation."""
from __future__ import annotations
import copy, hashlib, json, tempfile, unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import qualification_continuity_capabilities as inventory
    from scripts.ci import native_capability_evidence_test as fixtures
except ModuleNotFoundError:
    import qualification_continuity_capabilities as inventory
    import native_capability_evidence_test as fixtures

c = inventory.continuity
caps = inventory.capabilities


class CapabilityContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.proofs = self.root/'proofs'; self.proofs.mkdir()
        self.fixtures = {}
        self.templates = {}
        for candidate in (c.BASE,c.RUNTIME):
            fixture = fixtures.NativeCapabilityEvidenceTests()
            fixture.candidate = candidate; fixture.setUp()
            self.addCleanup(fixture.doCleanups); self.addCleanup(fixture.tearDown)
            self.fixtures[candidate] = fixture
            fixture.write_json(fixture.evidence_path,fixture.build_evidence())
            self.templates[candidate] = caps.validate_evidence_file(
                candidate_commit=candidate,campaign_path=fixture.campaign,
                evidence_path=fixture.evidence_path,artifact_root=fixture.artifact_root,
                host_attestation_path=fixture.attestation,signing_bundle_path=fixture.signing_bundle,
                validation_time=fixture.validation_time,
            )
        self.policy = c.load_policy(); self.paths = []
        contract,_ = caps.load_contract()
        for profile in contract['host_profiles']:
            name = profile['id']; candidate = c.BASE if name in inventory.HISTORICAL else c.RUNTIME
            verdict = copy.deepcopy(self.templates[candidate])
            verdict.update(profile_id=name,host_id=profile['host_id'],
                evidence_namespace=profile['evidence_namespace'],
                campaign_id=profile['evidence_namespace']+'-continuity-test',
                package_binding=copy.deepcopy(self.fixtures[candidate].package_bindings[name]))
            for field in ('host_attestation_sha256','campaign_sha256','evidence_sha256','evidence_artifact_set_sha256'):
                verdict[field] = hashlib.sha256((name+field).encode()).hexdigest()
            path=self.root/(name+'.json');self.write(path,verdict);self.paths.append(path)
            if name in inventory.HISTORICAL:
                original=self.proofs/('capability-'+name+'.json');original.write_bytes(path.read_bytes())
                self.policy['records'][original.name]={'size':original.stat().st_size,'sha256':hashlib.sha256(original.read_bytes()).hexdigest()}

    def write(self,path,value):path.write_text(json.dumps(value,sort_keys=True)+'\n')

    def verify(self,paths=None):
        return inventory._verify_inventory(
            verdict_paths=self.paths if paths is None else paths,proof_root=self.proofs,
            base_bundle=self.fixtures[c.BASE].signing_bundle,
            runtime_bundle=self.fixtures[c.RUNTIME].signing_bundle,policy=self.policy,
        )

    def test_keeps_original_bytes_candidate_package_and_host(self):
        before={p:p.read_bytes() for p in self.paths}
        result=self.verify(list(reversed(self.paths)))
        self.assertEqual({p:p.read_bytes() for p in self.paths},before)
        self.assertEqual([r['profile_id'] for r in result],[p.stem for p in self.paths])
        for row in result:
            expected=c.BASE if row['profile_id'] in inventory.HISTORICAL else c.RUNTIME
            self.assertEqual(row['observed_candidate'],expected)
            self.assertEqual(row['original_verdict']['candidate_commit'],expected)
            self.assertEqual(row['original_verdict'],json.loads(before[self.root/(row['profile_id']+'.json')]))
            self.assertIn('pending',row['acceptance'])

    def test_old_candidate_cannot_fill_a_missing_fresh_profile(self):
        for name in self.policy['fresh_required']['capability_profiles']:
            path=self.root/(name+'.json');before=path.read_bytes();document=json.loads(before)
            document['candidate_commit']=c.BASE;self.write(path,document)
            with self.subTest(profile=name),self.assertRaises(caps.NativeCapabilityEvidenceError):self.verify()
            path.write_bytes(before)

    def test_relabelled_or_modified_historical_proof_refused(self):
        for name in inventory.HISTORICAL:
            path=self.root/(name+'.json');before=path.read_bytes()
            for key,value in [('candidate_commit',c.RUNTIME),('host_id','node99'),('verdict','fail'),('blockers',['missing']),('campaign_id','different')]:
                document=json.loads(before);document[key]=value;self.write(path,document)
                with self.subTest(profile=name,key=key),self.assertRaises(c.ContinuityError):self.verify()
            path.write_bytes(before+b' ')
            with self.assertRaises(c.ContinuityError):self.verify()
            path.write_bytes(before)

    def test_missing_duplicate_or_unknown_profile_refused(self):
        with self.assertRaises(c.ContinuityError):self.verify(self.paths[:-1])
        with self.assertRaises(c.ContinuityError):self.verify(self.paths[:-1]+[self.paths[0]])
        path=self.paths[0];document=json.loads(path.read_bytes());document['profile_id']='unknown';self.write(path,document)
        with self.assertRaises(c.ContinuityError):self.verify()

    def test_fresh_failure_host_package_and_schema_refused(self):
        path=self.root/'RPM-A10.json';before=path.read_bytes()
        for key,value in [('verdict','fail'),('blockers',['missing']),('host_id','node99'),('schema_version',True),('package_binding',{})]:
            document=json.loads(before);document[key]=value;self.write(path,document)
            with self.subTest(key=key),self.assertRaises(caps.NativeCapabilityEvidenceError):self.verify()
        path.write_bytes(before)

    def test_cross_candidate_duplicate_evidence_and_catalog_mismatch_refused(self):
        historical=json.loads((self.root/'DEB-U2604.json').read_bytes())
        path=self.root/'DEB-13.json';before=path.read_bytes()
        for field in ('host_attestation_sha256','campaign_sha256','evidence_sha256','evidence_artifact_set_sha256'):
            document=json.loads(before);document[field]=historical[field];self.write(path,document)
            with self.subTest(field=field),self.assertRaises(c.ContinuityError):self.verify()
        document=json.loads(before);document['signature_catalog_sha256']='f'*64;self.write(path,document)
        with self.assertRaises(c.ContinuityError):self.verify()

    def test_entry_point_recomputes_eligibility_before_loading_verdicts(self):
        with mock.patch.object(c,'verify_eligibility',side_effect=c.ContinuityError('not eligible')) as check, mock.patch.object(inventory,'_verify_inventory') as collect:
            with self.assertRaises(c.ContinuityError):
                inventory.verify_capability_inventory(repository=self.root,proof_root=self.proofs,
                    base_bundle=self.fixtures[c.BASE].signing_bundle,runtime_bundle=self.fixtures[c.RUNTIME].signing_bundle,
                    verdict_paths=self.paths,candidate=c.RUNTIME)
            check.assert_called_once();collect.assert_not_called()

    def test_complete_inventory_never_grants_final_acceptance(self):
        eligibility={'fresh_required':self.policy['fresh_required']}
        with mock.patch.object(c,'verify_eligibility',return_value=eligibility),mock.patch.object(c,'load_policy',return_value=self.policy):
            result=inventory.verify_capability_inventory(repository=self.root,proof_root=self.proofs,
                base_bundle=self.fixtures[c.BASE].signing_bundle,runtime_bundle=self.fixtures[c.RUNTIME].signing_bundle,
                verdict_paths=self.paths,candidate=c.RUNTIME)
        self.assertFalse(result['release_qualified']);self.assertFalse(result['historical_evidence_modified'])
        self.assertTrue(result['protected_final_validation_required'])
        self.assertEqual(len(result['fresh_rpm_deltas_still_required']),4)
        self.assertNotIn('verdict',result)


class RawCapabilityContinuityTests(unittest.TestCase):
    """Exercise raw-byte enforcement with synthetic native-harness fixtures."""

    def setUp(self):
        self.fixture = fixtures.NativeCapabilityEvidenceTests()
        self.fixture.candidate = c.BASE
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        f = self.fixture
        f.write_json(f.evidence_path, f.build_evidence())
        self.verdict = caps.validate_evidence_file(candidate_commit=c.BASE,
            campaign_path=f.campaign, evidence_path=f.evidence_path, artifact_root=f.artifact_root,
            host_attestation_path=f.attestation, signing_bundle_path=f.signing_bundle,
            validation_time=f.validation_time)
        self.verdict_path = f.root/'verdict.json';f.write_json(self.verdict_path,self.verdict)
        self.proofs=f.root/'proofs';self.proofs.mkdir()
        anchor=self.proofs/'capability-DEB-U2604.json';anchor.write_bytes(self.verdict_path.read_bytes())
        self.policy=copy.deepcopy(c.load_policy())
        self.policy['records'][anchor.name]={'size':anchor.stat().st_size,
            'sha256':hashlib.sha256(anchor.read_bytes()).hexdigest()}
        self.inputs={'verdict_path':self.verdict_path,'campaign_path':f.campaign,
            'evidence_path':f.evidence_path,'artifact_root':f.artifact_root,'host_attestation_path':f.attestation}

    def verify(self):
        return inventory._revalidate_raw_profile(profile='DEB-U2604',inputs=self.inputs,
            proof_root=self.proofs,base_bundle=self.fixture.signing_bundle,
            runtime_bundle=self.fixture.signing_bundle,policy=self.policy)

    def test_recomputes_original_verdict_and_raw_inventory(self):
        before={p:p.read_bytes() for p in self.fixture.artifact_root.rglob('*.json')}
        result=self.verify()
        self.assertEqual(result['original_verdict'],self.verdict)
        self.assertEqual(result['observed_candidate'],c.BASE)
        self.assertTrue(result['raw_artifacts_revalidated'])
        self.assertFalse(result['release_qualified'])
        self.assertGreaterEqual(result['raw_artifact_count'],24)
        self.assertEqual({p:p.read_bytes() for p in before},before)

    def test_passing_summary_cannot_hide_changed_missing_or_symlink_raw(self):
        path=self.fixture.artifact_root/'raw/hips.json';before=path.read_bytes()
        path.write_bytes(before+b' ')
        with self.assertRaises(caps.NativeCapabilityEvidenceError):self.verify()
        path.unlink()
        with self.assertRaises(caps.NativeCapabilityEvidenceError):self.verify()
        alternate=self.fixture.root/'raw-copy.json';alternate.write_bytes(before);path.symlink_to(alternate)
        with self.assertRaises(caps.NativeCapabilityEvidenceError):self.verify()

    def test_historical_verdict_cannot_be_reserialized(self):
        self.verdict_path.write_bytes(self.verdict_path.read_bytes()+b' ')
        with self.assertRaises(c.ContinuityError):self.verify()

    def test_candidate_or_host_cannot_be_relabelled(self):
        for key,bad in [('candidate_commit',c.RUNTIME),('profile_id','DEB-13'),('host_id','node01')]:
            document=copy.deepcopy(self.verdict);document[key]=bad
            self.fixture.write_json(self.verdict_path,document)
            with self.subTest(key=key),self.assertRaises(c.ContinuityError):self.verify()

    def test_attestation_and_campaign_changes_fail(self):
        for path in [self.fixture.attestation,self.fixture.campaign]:
            before=path.read_bytes();path.write_bytes(before+b' ')
            with self.subTest(path=path.name),self.assertRaises((caps.NativeCapabilityEvidenceError,c.ContinuityError)):
                self.verify()
            path.write_bytes(before)

    def test_raw_input_cannot_override_candidate_or_contract(self):
        self.inputs['candidate_commit']=c.RUNTIME
        with self.assertRaises(c.ContinuityError):self.verify()

    def test_partial_historical_inventory_cannot_clear_fresh_profiles(self):
        args=dict(repository=self.fixture.root,proof_root=self.proofs,
            base_bundle=self.fixture.signing_bundle,runtime_bundle=self.fixture.signing_bundle,
            profile_inputs={'DEB-U2604':self.inputs},candidate=c.RUNTIME)
        with self.assertRaises(c.ContinuityError):inventory.verify_historical_raw_capabilities(**args)
        args['profile_inputs']['RPM-A9-RHELPO']=self.inputs
        with self.assertRaises(c.ContinuityError):inventory.verify_capability_raw_inventory(**args)

    def test_historical_entry_revalidates_eligibility_before_any_raw_inputs(self):
        with mock.patch.object(c,'verify_eligibility',side_effect=c.ContinuityError('changed source')), \
             mock.patch.object(inventory,'_revalidate_raw_profile') as raw:
            with self.assertRaises(c.ContinuityError):
                inventory.verify_historical_raw_capabilities(repository=self.fixture.root,
                    proof_root=self.proofs,base_bundle=self.fixture.signing_bundle,
                    runtime_bundle=self.fixture.signing_bundle,
                    profile_inputs={name:self.inputs for name in inventory.HISTORICAL},candidate=c.RUNTIME)
            raw.assert_not_called()

    def test_evidence_mutation_after_validation_is_rejected(self):
        original=caps.validate_evidence_file
        def changed(**kwargs):
            result=original(**kwargs)
            self.fixture.evidence_path.write_bytes(self.fixture.evidence_path.read_bytes()+b' ')
            return result
        with mock.patch.object(caps,'validate_evidence_file',side_effect=changed):
            with self.assertRaises(c.ContinuityError):self.verify()


if __name__=='__main__':unittest.main(verbosity=2)
