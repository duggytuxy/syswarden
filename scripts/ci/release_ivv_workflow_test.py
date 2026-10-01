"""Publisher trust boundaries and retained full-qualification routing."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def test_producer_cannot_publish_or_upload_private_evidence(self):
        text=(ROOT/'.github/workflows/release-ivv.yml').read_text()
        self.assertIn('runs-on: [self-hosted, linux, x64, syswarden-ivv-proof-verification]',text)
        self.assertIn('name: syswarden-release-qualification',text)
        for excluded in ['contents: write','gh release create','gh release edit','pull_request:',
                         'path: ${{ steps.verify.outputs.private','SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY']:
            self.assertNotIn(excluded,text)
        self.assertIn('subject-path: ${{ steps.verify.outputs.public_root }}/RELEASE_IVV.json',text)
        self.assertIn('path: ${{ steps.verify.outputs.public_root }}/',text)
        self.assertIn('test "${GITHUB_RUN_ATTEMPT}" = "1"',text)
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"',text)

    def test_each_boundary_derives_track_and_consumes_independently(self):
        text=(ROOT/'.github/workflows/release-manager.yml').read_text()
        for name,following in [('coordinate-release','dispatch-release'),
                               ('validate-and-stage','attest-and-publish'),('attest-and-publish',None)]:
            block=text.split('\n  '+name+':',1)[1]
            if following:block=block.split('\n  '+following+':',1)[0]
            self.assertEqual(block.count('python3 scripts/ci/release_assurance_contract.py'),1)
            self.assertEqual(block.count('python3 scripts/ci/release_ivv_consumer.py'),1)
            self.assertIn('if [[ "${REQUIRED_ASSURANCE}" == "IVV" ]]; then',block)
            # Full Upgrade evidence is still resolved and checked in its branch.
            self.assertIn('actions/workflows/release-qualification.yml/runs',block)
            self.assertIn('syswarden-release-qualification',block)
        privileged=text.split('\n  attest-and-publish:',1)[1]
        self.assertIn('--producer-run-id "${QUALIFICATION_RUN_ID}"',privileged)
        self.assertIn('--release-assets "${GITHUB_WORKSPACE}/tmp/release_payload/assets"',privileged)
        self.assertLess(privileged.index('python3 scripts/ci/release_ivv_consumer.py'),
                        privileged.index('      - name: Create Private Draft Release'))
        self.assertIn('Verify Signed Annotated Release Tag',privileged)
        self.assertIn('Require Immutable Release Tag Ruleset Before Publication',privileged)

    def test_shell_blocks_parse_and_actions_are_pinned(self):
        for name in ['release-ivv.yml','release-manager.yml']:
            text=(ROOT/'.github/workflows'/name).read_text()
            for action in re.findall(r'^\s+uses: (.+)$',text,re.M):
                self.assertRegex(action,r'^[^ @]+@[0-9a-f]{40}(?: #.*)?$')
            for body in re.findall(r'        run: \|\n((?:          .*\n|\n)+)',text):
                script='\n'.join(line[10:] if line.startswith('          ') else line for line in body.splitlines())
                result=subprocess.run(['bash','-n'],input=script,text=True,capture_output=True)
                self.assertEqual(result.returncode,0,(name,result.stderr))


if __name__=='__main__':unittest.main()
