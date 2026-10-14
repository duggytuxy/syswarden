"""All three publication boundaries must resolve the reviewed Patch producer."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = '0e966d409b6b9d19116597edee1feafad0c83688'


class PatchWorkflowTests(unittest.TestCase):
    def test_protected_producer_is_read_only_and_exact(self):
        wire = (ROOT/'.github/workflows/release-ivv-v4104.yml').read_text()
        for required in ('VERIFY-V4104-IVV-NO-PUBLISH', '--release v4.10.4',
                         'runs-on: [self-hosted, linux, x64, syswarden-ivv-proof-verification]',
                         'name: syswarden-release-qualification', 'fetch-depth: 0',
                         'persist-credentials: false', 'test "${GITHUB_RUN_ATTEMPT}" = "1"',
                         'test "${GITHUB_REF}" = "refs/heads/main"'):
            self.assertIn(required, wire)
        self.assertIn('git fetch --no-tags --no-recurse-submodules https://github.com/duggytuxy/syswarden.git ' + NATIVE, wire)
        for forbidden in ('contents: write', 'pull_request:', 'gh release ', 'PRIVATE_KEY', 'path: ${{ steps.verify.outputs.private'):
            self.assertNotIn(forbidden, wire)
        self.assertIn('subject-path: ${{ steps.verify.outputs.public_root }}/RELEASE_IVV.json', wire)
        for action in re.findall(r'^\s+uses: (.+)$', wire, re.M):
            self.assertRegex(action, r'^[^ @]+@[0-9a-f]{40}(?: #.*)?$')
        for body in re.findall(r'        run: \|\n((?:          .*\n|\n)+)', wire):
            result = subprocess.run(['bash', '-n'], input=body, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_independent_consumer_selects_reviewed_profile(self):
        wire = (ROOT/'.github/workflows/release-manager.yml').read_text()
        for name, following in [('coordinate-release', 'dispatch-release'),
                                ('validate-and-stage', 'attest-and-publish'), ('attest-and-publish', None)]:
            block = wire.split('\n  ' + name + ':', 1)[1]
            if following: block = block.split('\n  ' + following + ':', 1)[0]
            self.assertEqual(block.count('python3 scripts/ci/release_ivv_consumer.py'), 1)
            self.assertIn('scripts/ci/release_assurance_contract.py', block)
            self.assertIn('actions/workflows/release-qualification.yml/runs', block)
            self.assertLess(block.index('scripts/ci/release_assurance_contract.py'), block.index('python3 scripts/ci/release_ivv_consumer.py'))

    def test_full_qualification_matrix_is_required_only_on_ivvq_track(self):
        wire = (ROOT/'.github/workflows/release-manager.yml').read_text()
        step = wire.split('      - name: Resolve Versioned Qualification Matrix for Coordination\n', 1)[1]
        step = step.split('      - name:', 1)[0]
        self.assertIn("steps.context.outputs.candidate == 'true' && steps.assurance.outputs.assurance == 'IVVQ'", step)
        self.assertIn('--check "${matrix_path}" --expected-target-release "${RELEASE_TAG}"', step)


if __name__ == '__main__': unittest.main()
