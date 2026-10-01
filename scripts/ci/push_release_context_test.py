"""Post-tag pushes must not move tags or inherit a release acceptance verdict."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/push_release_context.sh"


class PushReleaseContextTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("git") or not shutil.which("jq"):
            self.skipTest("git and jq are required")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "README.md").write_text("Initial documentation\n")
        self.git("add", "README.md")
        self.git("commit", "-qm", "Major : prepare v4.10.0")
        self.original = self.git("rev-parse", "HEAD")
        self.output = self.root / "context.json"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       env=self.env, text=True).strip()

    def followup(self):
        (self.repo / "README.md").write_text("Published documentation\n")
        self.git("add", "README.md")
        self.git("commit", "-qm", "Docs : publish the release record")
        return self.git("rev-parse", "HEAD")

    def run_context(self, candidate=None, version="v4.10.0"):
        return subprocess.run(["bash", str(SCRIPT), str(self.repo), version,
                               candidate or self.git("rev-parse", "HEAD"), str(self.output)],
                              env=self.env, text=True, capture_output=True, timeout=10, check=False)

    def assert_context(self, kind, required):
        result = self.run_context()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(self.output.read_text())
        self.assertEqual(value["kind"], kind)
        self.assertEqual(value["candidate_commit"], self.git("rev-parse", "HEAD"))
        self.assertIs(value["release_track_required"], required)
        for field in ["historical_verdicts_transferred", "qualification_passed", "publication_authorized"]:
            self.assertIs(value[field], False)
        self.assertEqual(self.git("status", "--porcelain"), "")
        return value

    def test_untagged_candidate_still_requires_classification(self):
        value = self.assert_context("untagged-candidate", True)
        self.assertEqual(value["existing_tag_commit"], "")
        self.assertEqual(self.git("tag", "--list"), "")

    def test_exact_tagged_head_still_requires_classification(self):
        self.git("tag", "-a", "v4.10.0", "-m", "Published release")
        value = self.assert_context("tagged-head", True)
        self.assertEqual(value["existing_tag_commit"], self.original)

    def test_documentation_followup_preserves_tag_without_transferring_acceptance(self):
        self.git("tag", "-a", "v4.10.0", "-m", "Published release")
        tag_object = self.git("rev-parse", "refs/tags/v4.10.0")
        self.followup()
        value = self.assert_context("post-tag-followup", False)
        self.assertEqual(value["existing_tag_commit"], self.original)
        self.assertEqual(self.git("rev-parse", "refs/tags/v4.10.0"), tag_object)

    def test_unrelated_or_future_tag_is_rejected(self):
        self.followup()
        self.git("tag", "v4.10.0")
        self.git("checkout", "-q", "--detach", self.original)
        result = self.run_context()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not an ancestor", result.stderr)
        self.assertFalse(self.output.exists())

    def test_wrong_candidate_and_malformed_input_are_rejected(self):
        for args in [{"candidate": "f" * 40}, {"candidate": "HEAD"}, {"version": "v4.10.0^"}]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_context(**args).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.write_text("Preserve original evidence")
        self.assertNotEqual(self.run_context().returncode, 0)
        self.assertEqual(self.output.read_text(), "Preserve original evidence")

    def test_post_tag_guard_is_only_used_for_push_classification(self):
        wire = (ROOT / ".github/workflows/auto-versioning.yml").read_text()
        self.assertLess(wire.index('name: "Validate commit version contract"'),
                        wire.index("name: Identify Push Release Context"))
        self.assertEqual(wire.count("if: steps.push-context.outputs.release_track_required == 'true'"), 2)
        self.assertIn("name: syswarden-push-context-${{ github.sha }}", wire)
        self.assertIn("contents: read", wire)
        for name in ["release-manager.yml", "release-qualification.yml"]:
            self.assertNotIn("push_release_context.sh", (ROOT / ".github/workflows" / name).read_text())


if __name__ == "__main__":
    unittest.main()
