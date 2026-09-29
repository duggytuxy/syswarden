"""Release-track recording must preserve provenance without granting acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/record_release_track.sh"


class TrackRecordingTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("jq"):
            self.skipTest("jq is required")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        self.binary = self.root / "bin"
        self.binary.mkdir()
        (self.binary / "git").write_text("#!/bin/sh\nprintf '%s\\n' \"$TEST_HEAD\"\n")
        (self.binary / "git").chmod(0o700)
        (self.repo / "scripts/versioning.sh").write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$TEST_TRACK_JSON\"\n"
        )
        (self.repo / "scripts/versioning.sh").chmod(0o700)
        self.output = self.root / "track.json"
        self.sha = "a" * 40
        self.doc = {
            "schema": "syswarden-release-track/v1",
            "candidate_commit": self.sha,
            "release": "v5.00.0",
            "previous_version": "v4.10.0",
            "transition_commit": "b" * 40,
            "transition_parent": "c" * 40,
            "prefix": "Upgrade",
            "track": "full-qualification",
            "followup_commits": 3,
            "qualification_passed": False,
            "publication_authorized": False,
        }

    def run_script(self, *, candidate=None, head=None):
        env = dict(os.environ, TEST_HEAD=head or self.sha,
                   TEST_TRACK_JSON=json.dumps(self.doc),
                   PATH=str(self.binary) + os.pathsep + os.environ["PATH"])
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.repo), self.doc["release"],
             candidate or self.sha, str(self.output)],
            env=env, text=True, capture_output=True, timeout=10,
            check=False,
        )

    def test_preserves_upgrade_identity_and_false_acceptance(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text()), self.doc)
        self.assertIn("not a test result", result.stdout)
        self.assertEqual(list(self.root.glob("track.json.tmp.*")), [])

    def test_records_all_intermediate_prefixes(self):
        for prefix in ["Patch", "Minor", "Major"]:
            with self.subTest(prefix=prefix):
                self.doc.update(prefix=prefix, track="intermediate-validation", release="v4.10.0")
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.output.unlink()

    def test_rejects_forged_classifications_without_retaining_json(self):
        original = dict(self.doc)
        for mutation in [
            {"track": "intermediate-validation"},
            {"prefix": "Major"},
            {"qualification_passed": True},
            {"publication_authorized": True},
            {"candidate_commit": "d" * 40},
            {"schema": "syswarden-release-qualification"},
            {"transition_commit": "HEAD"},
            {"followup_commits": -1},
        ]:
            with self.subTest(mutation=mutation):
                self.doc = dict(original, **mutation)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output.exists())
                self.assertEqual(list(self.root.glob("track.json.tmp.*")), [])

    def test_rejects_wrong_checkout_and_malformed_candidate(self):
        for args in [{"head": "f" * 40}, {"candidate": "HEAD"}]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_script(**args).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_does_not_replace_an_existing_record(self):
        self.output.write_text("preserve this record")
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.output.read_text(), "preserve this record")


class WorkflowWiringTests(unittest.TestCase):
    def test_all_release_boundaries_record_the_exact_candidate(self):
        for name, count in [("auto-versioning.yml", 1), ("release-qualification.yml", 1),
                            ("release-manager.yml", 3)]:
            with self.subTest(workflow=name):
                wire = (ROOT / ".github/workflows" / name).read_text()
                self.assertEqual(wire.count("bash scripts/ci/record_release_track.sh"), count)
                self.assertEqual(wire.count('"${GITHUB_WORKSPACE}" "${RELEASE_TAG}" "${RELEASE_SHA}" "${track_report}"'), count)
                self.assertEqual(wire.count("Classification only. Required validation, signatures and publication gates remain mandatory."), count)
                self.assertNotIn("skip_qualification", wire)

    def test_classification_has_its_own_non_acceptance_artifact(self):
        wire = (ROOT / ".github/workflows/auto-versioning.yml").read_text()
        self.assertIn("name: syswarden-release-track-${{ github.sha }}", wire)
        self.assertIn("path: ${{ runner.temp }}/syswarden-release-track.json", wire)
        self.assertNotIn("name: syswarden-release-qualification", wire)
        self.assertIn("contents: read", wire)

    def test_recording_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True,
                                text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
