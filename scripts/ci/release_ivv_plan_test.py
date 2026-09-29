"""Regression tests for frozen IVV inputs, provenance and non-acceptance claims."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_ivv_plan as gate


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.packages = self.root / "packages"
        self.evidence.mkdir()
        self.packages.mkdir()
        self.candidate = "a" * 40
        self.wire = json.dumps({"candidate_commit": self.candidate, "verdict": "pass"}).encode()
        (self.evidence / "previous.json").write_bytes(self.wire)
        (self.packages / "candidate.rpm").write_bytes(b"immutable signed package")
        self.plan = {"retained_records": [{
            "id": "previous", "candidate_commit": self.candidate,
            "sha256": gate.digest(self.wire), "size": len(self.wire),
            "relation": "historical-support-only"}], "product_packages": [{
                "path": "candidate.rpm", "sha256": gate.digest(b"immutable signed package"),
                "size": len(b"immutable signed package")}]}

    def verify(self):
        return gate.verify_inputs(self.plan, self.evidence, self.packages)

    def test_exact_bytes_keep_original_provenance_without_promoting_pass(self):
        records, packages = self.verify()
        self.assertEqual(records[0]["candidate_commit"], self.candidate)
        self.assertFalse(records[0]["admitted_as_current_pass"])
        self.assertEqual(packages, self.plan["product_packages"])
        self.assertEqual((self.evidence / "previous.json").read_bytes(), self.wire)

    def test_substituted_package_is_rejected_even_with_same_size(self):
        path = self.packages / "candidate.rpm"
        path.write_bytes(b"x" * path.stat().st_size)
        with self.assertRaisesRegex(gate.PlanError, "reviewed bytes"):
            self.verify()

    def test_rewritten_old_verdict_is_rejected(self):
        (self.evidence / "previous.json").write_text(
            json.dumps({"candidate_commit": "b" * 40, "verdict": "pass"}))
        with self.assertRaises(gate.PlanError):
            self.verify()

    def test_candidate_mismatch_is_rejected_even_if_anchor_is_changed(self):
        wire = json.dumps({"candidate_commit": "b" * 40, "verdict": "pass"}).encode()
        (self.evidence / "previous.json").write_bytes(wire)
        self.plan["retained_records"][0].update(sha256=gate.digest(wire), size=len(wire))
        with self.assertRaisesRegex(gate.PlanError, "relabeled"):
            self.verify()

    def test_missing_evidence_is_not_a_pass(self):
        (self.evidence / "previous.json").unlink()
        with self.assertRaises((OSError, gate.bundle.SigningBundleError)):
            self.verify()

    def test_symlink_hardlink_and_parent_traversal_are_rejected(self):
        path = self.packages / "candidate.rpm"
        saved = self.root / "saved.rpm"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(gate.PlanError):
            self.verify()
        path.unlink()
        os.link(saved, path)
        with self.assertRaises(gate.bundle.SigningBundleError):
            self.verify()
        self.plan["product_packages"][0]["path"] = "../saved.rpm"
        with self.assertRaises(gate.PlanError):
            self.verify()

    def test_symlinked_parent_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.packages, target_is_directory=True)
        with self.assertRaises(gate.PlanError):
            gate.verify_inputs(self.plan, self.evidence, alias)

    def test_strict_json_and_paths(self):
        for wire in [b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'\xff']:
            with self.subTest(wire=wire), self.assertRaises(gate.PlanError):
                gate.strict_json(wire)
        for name in ["/etc/passwd", "../other", "a/../b", "./a", "a//b", "a\\b", "a\nb"]:
            with self.subTest(name=name), self.assertRaises(gate.PlanError):
                gate.relative(name)

    def test_new_output_does_not_overwrite_prior_record(self):
        output = self.root / "result.json"
        gate.write_new(output, {"publication_authorized": False})
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            gate.write_new(output, {"publication_authorized": True})
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


class TrackTests(unittest.TestCase):
    def setUp(self):
        self.publication = "a" * 40
        self.plan = {"release": "v4.10.0", "originating_transition": {
            "commit": "b" * 40, "prefix": "Major", "previous_version": "v4.04.3"}}
        self.track = {"schema": "syswarden-release-track/v1", "candidate_commit": self.publication,
                      "release": "v4.10.0", "previous_version": "v4.04.3", "transition_commit": "b" * 40,
                      "transition_parent": "c" * 40, "prefix": "Major", "track": "intermediate-validation",
                      "followup_commits": 77, "qualification_passed": False, "publication_authorized": False}

    def test_intermediate_prefixes(self):
        for prefix in ["Patch", "Minor", "Major"]:
            with self.subTest(prefix=prefix):
                self.plan["originating_transition"]["prefix"] = prefix
                self.track["prefix"] = prefix
                gate.verify_track(self.track, self.publication, self.plan)

    def test_upgrade_is_never_intermediate_even_after_corrective_followups(self):
        for release in ["v5.00.0", "v6.00.0"]:
            for count in [0, 9]:
                with self.subTest(release=release, count=count):
                    self.plan["release"] = release
                    self.plan["originating_transition"]["prefix"] = "Upgrade"
                    self.track.update(release=release, prefix="Upgrade", followup_commits=count)
                    with self.assertRaises(gate.PlanError):
                        gate.verify_track(self.track, self.publication, self.plan)

    def test_wrong_binding_and_claims_are_rejected(self):
        for change in [{"candidate_commit": "d" * 40}, {"transition_commit": "d" * 40},
                       {"previous_version": "v4.03.3"}, {"prefix": "Patch"},
                       {"track": "full-qualification"}, {"qualification_passed": True},
                       {"publication_authorized": 0}, {"followup_commits": True},
                       {"followup_commits": -1}, {"extra": "unreviewed"}]:
            with self.subTest(change=change), self.assertRaises(gate.PlanError):
                gate.verify_track(dict(self.track, **change), self.publication, self.plan)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / "runtime.go").write_text("frozen runtime\n")
        (self.repo / "policy.md").write_text("original policy\n")
        self.commit()
        self.product = self.git("rev-parse", "HEAD")
        self.plan = {"product_candidate": self.product, "publication_source_change_allowlist": ["policy.md"]}

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.fsmonitor=false", *args],
                                       cwd=self.repo, text=True, stderr=subprocess.DEVNULL).strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def verify(self):
        return gate.verify_source(self.repo, self.git("rev-parse", "HEAD"), self.plan)

    def test_only_explicit_tooling_paths_can_change(self):
        (self.repo / "policy.md").write_text("reviewed IVV policy\n")
        self.commit()
        self.assertEqual(self.verify(), ["policy.md"])

    def test_runtime_change_fails_even_if_policy_changes_too(self):
        (self.repo / "runtime.go").write_text("different runtime\n")
        (self.repo / "policy.md").write_text("new policy\n")
        self.commit()
        with self.assertRaisesRegex(gate.PlanError, "frozen product"):
            self.verify()

    def test_unknown_build_input_addition_is_rejected(self):
        (self.repo / "new-build-hook.sh").write_text("unexpected input\n")
        self.commit()
        with self.assertRaises(gate.PlanError):
            self.verify()

    def test_dirty_checkout_and_wrong_publication_are_rejected(self):
        with self.assertRaises(gate.PlanError):
            gate.verify_source(self.repo, "d" * 40, self.plan)
        (self.repo / "runtime.go").write_text("uncommitted drift\n")
        with self.assertRaisesRegex(gate.PlanError, "clean"):
            self.verify()

    def test_replace_refs_are_rejected(self):
        self.git("update-ref", "refs/replace/" + "d" * 40, self.product)
        with self.assertRaisesRegex(gate.PlanError, "replacement"):
            self.verify()

    def test_assume_unchanged_cannot_hide_modified_executable_inputs(self):
        self.git("update-index", "--assume-unchanged", "runtime.go")
        (self.repo / "runtime.go").write_text("hidden worktree mutation\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(gate.PlanError, "hidden index"):
            self.verify()

    def test_skip_worktree_cannot_hide_modified_inputs(self):
        self.git("update-index", "--skip-worktree", "runtime.go")
        (self.repo / "runtime.go").write_text("hidden sparse mutation\n")
        with self.assertRaisesRegex(gate.PlanError, "hidden index"):
            self.verify()

    def test_no_preflight_success_grants_release_acceptance(self):
        with patch.object(gate, "load_plan", return_value=dict(self.plan, release="v4.10.0", required_checks=[])), \
                patch.object(gate, "classify", return_value={"track": "intermediate-validation"}), \
                patch.object(gate, "verify_inputs", return_value=([], [])):
            report = gate.preflight(self.repo, self.product, self.repo, self.repo)
        for key in ["intermediate_release_validated", "qualification_passed", "publication_authorized"]:
            self.assertIs(report[key], False)
        self.assertEqual(report["product_candidate"], self.product)
        self.assertNotEqual(report["schema"], "syswarden-release-qualification")


class ReviewedPlanTests(unittest.TestCase):
    def test_checked_in_plan_hash_is_current(self):
        plan = gate.load_plan()
        self.assertEqual(len(plan["required_checks"]), 14)
        self.assertEqual(len(plan["product_packages"]), 5)
        self.assertEqual(len(plan["retained_records"]), 7)
        self.assertEqual(len({row["id"] for row in plan["required_checks"]}), 14)
        self.assertIs(plan["preflight_is_acceptance"], False)

    def test_changed_plan_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            plan = copy.deepcopy(gate.load_plan())
            plan["required_checks"] = []
            path.write_text(json.dumps(plan))
            with patch.object(gate, "PLAN", path), self.assertRaisesRegex(gate.PlanError, "reviewed bytes"):
                gate.load_plan()


if __name__ == "__main__":
    unittest.main()
