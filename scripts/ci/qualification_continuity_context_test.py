#!/usr/bin/env python3
"""Unit tests for protected runtime/tooling identity separation, never native proof."""
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import copy
import unittest
try:
    from scripts.ci import qualification_continuity_context as context
except ModuleNotFoundError:
    import qualification_continuity_context as context


class ToolingContextTests(unittest.TestCase):
    def setUp(self):
        self.tooling = '1' * 40;self.workflow = '.github/workflows/native-release-evidence.yml'
        self.event = {'GITHUB_REPOSITORY': 'duggytuxy/syswarden', 'GITHUB_REPOSITORY_OWNER': 'duggytuxy',
            'GITHUB_ACTOR': 'duggytuxy', 'GITHUB_TRIGGERING_ACTOR': 'duggytuxy', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': self.tooling, 'GITHUB_WORKFLOW_SHA': self.tooling,
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123',
            'GITHUB_WORKFLOW_REF': 'duggytuxy/syswarden/' + self.workflow + '@refs/heads/main'}
        self.changed = 'M\t' + self.workflow + '\nA\tscripts/ci/qualification_continuity_context.py'
        self.head = self.tooling;self.ancestor = context.continuity.RUNTIME;self.dirty = ''
        self.blobs = {'scripts/ci/qualification_continuity_policy_pr257.json': context.continuity.POLICY.read_bytes(),
                      'scripts/ci/native_capability_evidence.py': Path(context.__file__).with_name('native_capability_evidence.py').read_bytes()}
        def git(repository, *args):
            if args == ('rev-parse', 'HEAD'):return self.head
            if args[0] == 'status':return self.dirty
            if args[0] == 'merge-base':return self.ancestor
            if args[0] == 'diff':return self.changed
            if args == ('rev-parse', self.tooling + '^{tree}'):return '2' * 40
            raise AssertionError(args)
        def run(argv, **kwargs):return SimpleNamespace(stdout=self.blobs[argv[-1].split(':', 1)[1]])
        for patch in (mock.patch.object(context.continuity, 'git', side_effect=git),
                      mock.patch.object(context.continuity, 'verify_source'), mock.patch('subprocess.run', side_effect=run)):
            handle = patch.start();self.addCleanup(patch.stop)
            if patch.attribute == 'verify_source':self.verify_source = handle

    def verify(self, **overrides):
        args = dict(repository=Path('/synthetic-test-repository'), runtime_sha=context.continuity.RUNTIME,
                    tooling_sha=self.tooling, workflow=self.workflow, event=self.event)
        args.update(overrides);return context.verify_context(**args)

    def test_runtime_and_tooling_provenance_remain_distinct(self):
        result = self.verify()
        self.assertEqual(result['runtime_candidate'], context.continuity.RUNTIME)
        self.assertEqual(result['tooling_commit'], self.tooling);self.assertFalse(result['release_qualified'])
        self.assertTrue(result['environment_protection_validation_required'])
        self.assertTrue(result['oidc_provenance_validation_required']);self.verify_source.assert_called_once()

    def test_runtime_substitution_and_missing_tooling_rejected(self):
        for args in ({'runtime_sha': context.continuity.BASE}, {'runtime_sha': self.tooling},
                     {'tooling_sha': context.continuity.RUNTIME}, {'tooling_sha': 'main'}, {'tooling_sha': 'A' * 40}):
            with self.subTest(args=args), self.assertRaises(context.continuity.ContinuityError):self.verify(**args)

    def test_spoofed_event_identity_ref_actor_or_attempt_rejected(self):
        for key in self.event:
            event = dict(self.event);event[key] = 'untrusted'
            with self.subTest(key=key), self.assertRaises(context.continuity.ContinuityError):self.verify(event=event)

    def test_runtime_sha_cannot_impersonate_executing_workflow_sha(self):
        for key in ('GITHUB_SHA', 'GITHUB_WORKFLOW_SHA'):
            event = dict(self.event);event[key] = context.continuity.RUNTIME
            with self.assertRaises(context.continuity.ContinuityError):self.verify(event=event)

    def test_checkout_and_ancestry_mismatch_rejected(self):
        self.head = '3' * 40
        with self.assertRaises(context.continuity.ContinuityError):self.verify()
        self.head = self.tooling;self.ancestor = context.continuity.BASE
        with self.assertRaises(context.continuity.ContinuityError):self.verify()

    def test_dirty_checkout_rejected(self):
        self.dirty = '?? scripts/ci/foreign.py'
        with self.assertRaises(context.continuity.ContinuityError):self.verify()

    def test_product_contract_toolchain_or_unrelated_workflow_change_rejected(self):
        for path in ('src/core/syswarden-core/main.go', 'go.mod', 'scripts/ci/performance_contract_v4.10.0.json',
                     'scripts/ci/native_performance_adapter.py', '.github/workflows/native-package-signing.yml', 'build_packages.sh'):
            original = self.changed;self.changed += '\nM\t' + path
            with self.subTest(path=path), self.assertRaises(context.continuity.ContinuityError):self.verify()
            self.changed = original

    def test_deletion_rename_duplicate_or_missing_workflow_rejected(self):
        original = self.changed
        for changed in ('', original.replace('M\t', 'D\t'), original + '\nR100\ta\tb',
                        original + '\nM\t' + self.workflow, 'A\tscripts/ci/qualification_continuity_context.py'):
            self.changed = changed
            with self.subTest(changed=changed), self.assertRaises(context.continuity.ContinuityError):self.verify()

    def test_owner_policy_or_original_validator_mutation_rejected(self):
        for name in self.blobs:
            original = self.blobs[name];self.blobs[name] += b'\n'
            with self.subTest(name=name), self.assertRaises(context.continuity.ContinuityError):self.verify()
            self.blobs[name] = original

    def test_larger_original_runtime_diff_rejected(self):
        self.verify_source.side_effect = context.continuity.ContinuityError('runtime diff exceeds policy')
        with self.assertRaises(context.continuity.ContinuityError):self.verify()


class ProtectedPerformanceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(context.__file__).resolve().parents[2]
        cls.workflow=(cls.root/'.github/workflows/qualification-continuity.yml').read_text()

    def step(self,name):
        return self.workflow.split('      - name: '+name+'\n',1)[1].split('      - name:',1)[0]

    def test_environment_protection_is_identical_to_existing_strict_producer(self):
        original=(self.root/'.github/workflows/native-release-evidence.yml').read_text()
        expected=original.split('      - name: Validate Exact Native Evidence Environment Protection\n',1)[1].split('      - name:',1)[0]
        self.assertEqual(self.step('Validate Exact Performance Environment Protection'),expected)
        self.assertIn('    environment:\n      name: syswarden-release-qualification\n',self.workflow)
        self.assertIn('runs-on: [self-hosted, linux, x64, syswarden-pr257-performance]',self.workflow)

    def test_scope_is_exact_and_upload_contains_only_public_result(self):
        self.assertIn('test "${AUTHORIZATION}" = "VERIFY-PR257-PERFORMANCE-NO-PUBLISH"',self.workflow)
        self.assertNotIn('contents: write',self.workflow)
        self.assertNotIn('secrets.',self.workflow)
        self.assertNotIn('gh release',self.workflow)
        self.assertNotIn('git tag',self.workflow)
        self.assertEqual(self.workflow.count('actions/upload-artifact@'),1)
        self.assertEqual(self.workflow.count('actions/attest-build-provenance@'),1)
        upload=self.step('Upload Public Performance Result Only')
        self.assertIn('path: ${{ steps.performance.outputs.output_root }}/PR257_PERFORMANCE_VERDICT.json',upload)
        self.assertIn("input_root=Path.home()/'.local/share/syswarden/native-release-evidence'/runtime/'pr257-performance'",self.workflow)
        self.assertIn('ref: ${{ github.sha }}',self.workflow)
        self.assertIn('fetch-depth: 0',self.workflow)

    def test_all_workflow_shell_blocks_parse(self):
        import re, subprocess, textwrap
        blocks=re.findall(r'(?m)^        run: \|\n((?:          [^\n]*\n|\n)+)',self.workflow)
        self.assertGreaterEqual(len(blocks),5)
        for block in blocks:
            result=subprocess.run(['bash','-n'],input=textwrap.dedent(block),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def run_public_step(self,passed=True):
        import tempfile, textwrap, os, io
        from contextlib import redirect_stdout
        from scripts.ci import qualification_continuity_inputs as inputs
        block=self.step('Revalidate Private Performance and Distinct Tooling Provenance')
        code=textwrap.dedent(block.split("<<'PY'\n",1)[1].rsplit('          PY\n',1)[0])
        tooling={'tooling_commit':'1'*40,'tooling_tree':'2'*40,
            'workflow':'.github/workflows/qualification-continuity.yml','workflow_run_id':123,
            'workflow_ref':'duggytuxy/syswarden/.github/workflows/qualification-continuity.yml@refs/heads/main'}
        result={'measurement_verdict':'pass' if passed else 'fail','waivers':0,'release_qualified':False,
            'native_metrics':{'metric':{'observed_candidate':context.continuity.BASE}},
            'source_allocation':{'observed_candidate':context.continuity.BASE,
                'original_report':{'native_package_runtime_measurement':False},'acceptance':'pending'},
            'recomputed_result_digests':{'historical_inventory':'a'*64,'fresh_native_executions':'b'*64},
            'historical_inventory':{'private_path':'/private/config','private_capture':'must-not-be-uploaded'}}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(context,'verify_context',return_value=tooling) as check, \
                mock.patch.object(inputs,'verify_staged_performance',return_value=result) as evaluate, \
                mock.patch.dict(os.environ,{'GITHUB_WORKSPACE':'/reviewed/tooling','GITHUB_SHA':'1'*40}), \
                mock.patch('sys.argv',['workflow',temporary]), redirect_stdout(io.StringIO()):
            if not passed:
                with self.assertRaises(context.continuity.ContinuityError):exec(compile(code,'<workflow-test>','exec'),{})
                self.assertFalse(list(Path(temporary).iterdir()));return
            exec(compile(code,'<workflow-test>','exec'),{})
            check.assert_called_once();evaluate.assert_called_once()
            import json
            files=list(Path(temporary).iterdir());self.assertEqual([p.name for p in files],['PR257_PERFORMANCE_VERDICT.json'])
            wire=files[0].read_text();self.assertNotIn('must-not-be-uploaded',wire);self.assertNotIn('/private/config',wire)
            public=json.loads(wire)
            self.assertEqual(public['runtime_commit'],context.continuity.RUNTIME)
            self.assertNotEqual(public['runtime_commit'],public['tooling_commit'])
            self.assertTrue(public['performance_accepted']);self.assertFalse(public['release_qualified'])
            self.assertTrue(public['remaining_release_gates_required']);self.assertFalse(public['private_raw_inputs_uploaded'])

    def test_public_result_keeps_distinct_provenance_without_private_inputs(self):
        self.run_public_step()

    def test_failed_private_revalidation_never_emits_a_public_verdict(self):
        self.run_public_step(passed=False)


if __name__ == '__main__':unittest.main()
