"""Fresh signed-product evidence cannot inherit prior acceptance or hide failures."""
import copy
import io
import json
import tarfile
import unittest
from scripts.ci import release_ivv_v4102 as current
from scripts.ci import release_ivv_consumer_test as old
from scripts.ci import candidate_update_verify_v4102 as updater
from scripts.ci import release_ivv_v4101_test as earlier


class PatchConsumptionTests(old.ConsumptionTests):
    current = current
    updater = updater
    workflow = '.github/workflows/release-ivv-v4102.yml'

    def test_exact_scoped_acceptance(self):
        self.verify(self.report)
        self.assertFalse(self.report['full_qualification_passed'])
        originals={r['original_candidate'] for r in self.report['input_verification']['reviewed_observations']}
        self.assertEqual(originals,{current.PRODUCT,current.PREVIOUS_ACCEPTED})
        self.assertIn('retained-harness-failure', {r['relation'] for r in self.report['input_verification']['reviewed_observations']})


class FreshInputsTests(unittest.TestCase):
    def test_failed_capture_cannot_be_replaced_by_success(self):
        manifest,objects,doc=earlier.PrivateCaptureTests().fixture()
        current.verify_capture_bindings(manifest,objects)
        doc['receipt']['rc']=0
        objects[manifest['roots'][0]['object_sha256']]=json.dumps(doc).encode()
        with self.assertRaises(current.frozen.PlanError): current.verify_capture_bindings(manifest,objects)

    def test_historical_and_current_roots_keep_distinct_sources(self):
        for relation,candidate in [('current-targeted-observation',current.PRODUCT),
                                   ('retained-harness-failure',current.PRODUCT),
                                   ('historical-support-only',current.PREVIOUS_ACCEPTED)]:
            doc=dict(candidate_commit=candidate,checked=True)
            row=dict(id='case',candidate_commit=candidate,relation=relation,object_sha256='a'*64,assertions={'checked':True})
            objects={'a'*64:json.dumps(doc).encode()}
            result=current.verify_roots(dict(roots=[row]),objects)
            self.assertFalse(result[0]['admitted_as_current_native_pass'])
            bad=dict(row,candidate_commit='b'*40)
            with self.assertRaises(current.frozen.PlanError):current.verify_roots(dict(roots=[bad]),objects)
            doc['checked']=1;objects['a'*64]=json.dumps(doc).encode()
            with self.assertRaises(current.frozen.PlanError):current.verify_roots(dict(roots=[row]),objects)

    def archive(self, change=None):
        output=io.BytesIO()
        rows=[('root/candidate-bundle/syswarden_4.10.2_amd64.deb',b'package'),
              ('root/syswarden-cli-v4.10.2',b'cli')]
        if change=='missing':rows.pop()
        if change=='duplicate':rows.append(rows[0])
        if change=='traversal':rows.append(('root/../outside',b'bad'))
        if change=='multiple-roots':rows.append(('other/file',b'bad'))
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            for name,data in rows:
                info=tarfile.TarInfo(name);info.size=len(data)
                if change=='symlink':info.type=tarfile.SYMTYPE;info.linkname='outside'
                archive.addfile(info,io.BytesIO(data))
        wire=output.getvalue();digest=current.frozen.digest(wire)
        plan=dict(native_archive_sha256=digest,native_cli_sha256=current.frozen.digest(b'cli'),
                  product_packages=[dict(path='packages/syswarden_4.10.2_amd64.deb',sha256=current.frozen.digest(b'package'))])
        if change=='package':plan['product_packages'][0]['sha256']='f'*64
        if change=='cli':plan['native_cli_sha256']='f'*64
        return plan,{digest:wire}

    def test_native_archive_contains_exact_signed_package_and_cli(self):
        current.verify_native_archive(*self.archive())
        for change in ('package','cli','missing','duplicate','traversal','multiple-roots','symlink'):
            with self.subTest(change=change),self.assertRaises(current.frozen.PlanError):
                current.verify_native_archive(*self.archive(change))

    def test_reviewed_plan_preserves_all_original_failures(self):
        plan=current.load_plan();manifest=current.load_manifest(plan)
        failures=[r for r in manifest['roots'] if r['relation']=='retained-harness-failure']
        self.assertEqual(len(failures),4)
        self.assertTrue(all(r['assertions']['receipt/returncode']==1 for r in failures))
        self.assertEqual(plan['native_tested_candidate'],plan['product_candidate'])
        self.assertFalse(plan['preflight_is_acceptance'])
        self.assertEqual(plan['product_native_signing']['artifact_id'],11237882878)

    def test_restoration_requires_exact_baseline(self):
        baseline=dict(network_config_sha256='a'*64,commands=[dict(rc=0,stdout='same')],
            geo_enabled=True,asn_enabled=True,wireguard_enabled=False,lab_directory_absent=True,
            removal_barrier_absent=True,finalizing_barrier_absent=True)
        roots=[dict(id='entry-readonly',object_sha256='before'),dict(id='final-restored-verification',object_sha256='after')]
        def wire(state):return json.dumps(dict(receipt=dict(returncode=0),observations=[state])).encode()
        objects={'before':wire(baseline),'after':wire(baseline)}
        current.verify_restoration(dict(roots=roots),objects)
        for field in baseline:
            changed=copy.deepcopy(baseline);changed[field]=None;objects['after']=wire(changed)
            with self.subTest(field=field),self.assertRaises(current.frozen.PlanError):
                current.verify_restoration(dict(roots=roots),objects)


if __name__ == '__main__': unittest.main()
