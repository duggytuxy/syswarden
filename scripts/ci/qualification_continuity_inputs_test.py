#!/usr/bin/env python3
"""Adversarial portable-input tests; fixtures are never native release evidence."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
try:
    from scripts.ci import qualification_continuity_inputs as inputs
except ModuleNotFoundError:
    import qualification_continuity_inputs as inputs


class PortablePerformanceInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'data').mkdir(mode=0o700)
        self.rows=[]
        for i in range(6):
            path=self.root/'data'/f'{i}.json';path.write_bytes(f'{{"fixture":{i}}}\n'.encode());path.chmod(0o600)
            self.rows.append({'path':path.relative_to(self.root).as_posix(),'bytes':path.stat().st_size,
                'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'mode':'0o600'})
        arguments={key:'data' for key in inputs.PATH_ARGUMENTS}
        arguments.update(sample_paths=[row['path']for row in self.rows],fresh_sides=[
            {key:('data' if key=='export_directory' else row['path'])for key in inputs.SIDE_ARGUMENTS}
            for row in self.rows])
        self.document={'schema':inputs.SCHEMA,'runtime_candidate':inputs.continuity.RUNTIME,
            'historical_candidate':inputs.continuity.BASE,'arguments':arguments,'files':self.rows}
        self.patcher=mock.patch.object(inputs,'EXPECTED_FILES',6);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.pinpatch=mock.patch.object(inputs,'MANIFEST_SHA256','');self.pinpatch.start();self.addCleanup(self.pinpatch.stop)
        self.write()

    def write(self):
        path=self.root/'MANIFEST.json';path.write_text(json.dumps(self.document,sort_keys=True)+'\n');path.chmod(0o600)
        inputs.MANIFEST_SHA256=hashlib.sha256(path.read_bytes()).hexdigest()

    def read(self):return inputs.read_input_tree(self.root)

    def test_portable_paths_preserve_bytes_and_inventory_identity(self):
        before={p:p.read_bytes() for p in self.root.rglob('*.json')}
        args,identity=self.read()
        self.assertEqual(identity['files'],6)
        self.assertEqual(args['sample_paths'],[self.root/row['path'] for row in self.rows])
        self.assertNotIn('candidate',args);self.assertNotIn('repository',args)
        self.assertEqual(before,{p:p.read_bytes()for p in before})

    def test_manifest_cannot_pin_itself_after_a_change(self):
        path=self.root/'MANIFEST.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_changed_missing_or_extra_file_fails(self):
        path=self.root/'data/0.json';before=path.read_bytes();path.write_bytes(before+b' ')
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()
        path.unlink()
        with self.assertRaises(OSError):self.read()
        path.write_bytes(before);path.chmod(0o600)
        (self.root/'unexpected').write_text('extra')
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_symlink_or_hardlink_files_fail(self):
        import os
        path=self.root/'data/0.json';path.unlink();path.symlink_to(self.root/'data/1.json')
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()
        path.unlink();os.link(self.root/'data/1.json',path)
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_private_modes_and_unexpected_directory_are_enforced(self):
        path=self.root/'data/0.json';path.chmod(0o644)
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()
        path.chmod(0o600);(self.root/'extra').mkdir(mode=0o700)
        with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_relative_paths_cannot_escape_or_use_aliases(self):
        for value in ('../other','/etc/passwd','data/../other','data//0.json','./data/0.json','data\\0.json','data/./0.json'):
            with self.subTest(value=value),self.assertRaises(inputs.continuity.ContinuityError):inputs.relative(value)

    def test_manifest_cannot_select_other_candidates_code_or_contracts(self):
        original=copy.deepcopy(self.document)
        for key in ('runtime_candidate','historical_candidate'):
            self.document=copy.deepcopy(original);self.document[key]='f'*40;self.write()
            with self.assertRaises(inputs.continuity.ContinuityError):self.read()
        for key in ('repository','candidate','contract_path','shell_command'):
            self.document=copy.deepcopy(original);self.document['arguments'][key]='data';self.write()
            with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_duplicate_unordered_or_oversized_records_fail(self):
        original=copy.deepcopy(self.document)
        for mutate in (lambda d:d['files'].__setitem__(1,copy.deepcopy(d['files'][0])),
                       lambda d:d['files'].reverse(),lambda d:d['files'][0].update(bytes=2**40)):
            self.document=copy.deepcopy(original);mutate(self.document);self.write()
            with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_incomplete_duplicate_or_outside_arguments_fail(self):
        original=copy.deepcopy(self.document)
        for mutate in (lambda a:a['sample_paths'].pop(),lambda a:a['fresh_sides'].pop(),
                       lambda a:a['sample_paths'].__setitem__(0,a['sample_paths'][1]),
                       lambda a:a.update(proof_root='not-in-inventory')):
            self.document=copy.deepcopy(original);mutate(self.document['arguments']);self.write()
            with self.assertRaises(inputs.continuity.ContinuityError):self.read()

    def test_inputs_are_verified_before_metrics_and_after_metrics(self):
        expected={'measurement_verdict':'pass','release_qualified':False}
        with mock.patch.object(inputs.metrics,'verify_complete_metric_evidence',return_value=copy.deepcopy(expected)) as gate:
            result=inputs.verify_staged_performance(repository=Path('/reviewed-tooling'),input_root=self.root)
            self.assertEqual(result['measurement_verdict'],'pass')
            self.assertEqual(gate.call_args.kwargs['candidate'],inputs.continuity.RUNTIME)
            self.assertEqual(gate.call_args.kwargs['repository'],Path('/reviewed-tooling'))
        def mutate(**kwargs):
            (self.root/'data/0.json').write_text('changed');return copy.deepcopy(expected)
        with mock.patch.object(inputs.metrics,'verify_complete_metric_evidence',side_effect=mutate):
            with self.assertRaises(inputs.continuity.ContinuityError):
                inputs.verify_staged_performance(repository=Path('/reviewed-tooling'),input_root=self.root)
        with mock.patch.object(inputs.metrics,'verify_complete_metric_evidence') as gate:
            with self.assertRaises(inputs.continuity.ContinuityError):
                inputs.verify_staged_performance(repository=Path('/reviewed-tooling'),input_root=self.root)
            gate.assert_not_called()


if __name__=='__main__':unittest.main()
