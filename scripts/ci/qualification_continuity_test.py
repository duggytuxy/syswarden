#!/usr/bin/env python3
"""Adversarial checks for the bounded PR257 continuity eligibility policy."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import qualification_continuity as continuity
except ModuleNotFoundError:
    import qualification_continuity as continuity


class ContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = continuity.load_policy()

    def source_values(self) -> dict[tuple[str, ...], str]:
        p = self.policy
        values = {
            ("merge-base", continuity.BASE, continuity.RUNTIME): continuity.BASE,
            ("rev-parse", continuity.RUNTIME + "^{tree}"): p["runtime_tree"],
            ("rev-parse", p["reviewed_head"] + "^{tree}"): p["runtime_tree"],
            ("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only",
             continuity.BASE, continuity.RUNTIME): "\n".join(x["path"] for x in p["source_changes"]),
        }
        for item in p["source_changes"]:
            for commit, field in ((continuity.BASE, "before_blob"), (continuity.RUNTIME, "after_blob")):
                values[("rev-parse", commit + ":" + item["path"])] = item[field]
        return values

    def test_policy_is_one_exact_transition_without_release_acceptance(self) -> None:
        self.assertEqual(self.policy["release"], "v4.10.0")
        self.assertFalse(self.policy["eligibility_is_release_acceptance"])
        self.assertFalse(self.policy["future_candidate_reuse_allowed"])
        self.assertEqual(len(self.policy["eligible_prior_scopes"]), 5)
        self.assertEqual(set(self.policy["fresh_required"]["performance_metrics"]), {
            "install_milliseconds", "startup_milliseconds", "package_bytes", "binary_bytes"})

    def test_modified_policy_cannot_enable_other_candidate(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["runtime_candidate"] = "a" * 40
        path = self.root / "policy.json"
        path.write_text(json.dumps(policy))
        with mock.patch.object(continuity, "POLICY", path):
            with self.assertRaisesRegex(continuity.ContinuityError, "reviewed policy"):
                continuity.load_policy()

    def test_source_checks_exact_diff_blobs_ancestry_and_reviewed_tree(self) -> None:
        values = self.source_values()
        def fake_git(repository: Path, *args: str) -> str:
            return values[args]
        with mock.patch.object(continuity, "git", side_effect=fake_git):
            continuity.verify_source(self.root, self.policy, continuity.RUNTIME)
            for key in list(values):
                original = values[key]
                values[key] = original + "\nextra.go" if key[0] == "diff" else "f" * 40
                with self.subTest(command=key):
                    with self.assertRaises(continuity.ContinuityError):
                        continuity.verify_source(self.root, self.policy, continuity.RUNTIME)
                values[key] = original

    def test_any_other_runtime_is_rejected_before_git(self) -> None:
        with mock.patch.object(continuity, "git") as git:
            for candidate in (continuity.BASE, "a" * 40, "main", "", continuity.RUNTIME + " "):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(continuity.ContinuityError):
                        continuity.verify_source(self.root, self.policy, candidate)
            git.assert_not_called()

    def test_anchored_file_rejects_tampering_symlink_hardlink_and_wrong_size(self) -> None:
        data = b'{"candidate":"original"}\n'
        anchor = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        path = self.root / "proof.json"
        path.write_bytes(data)
        self.assertEqual(continuity.checked_bytes(path, anchor, "proof"), data)
        path.write_bytes(data.replace(b"original", b"modified"))
        with self.assertRaises(continuity.ContinuityError):
            continuity.checked_bytes(path, anchor, "proof")
        path.write_bytes(data)
        for wrong in (len(data) - 1, True, 0):
            with self.subTest(size=wrong):
                with self.assertRaises(continuity.ContinuityError):
                    continuity.checked_bytes(path, dict(anchor, size=wrong), "proof")
        link = self.root / "symlink"
        link.symlink_to(path)
        with self.assertRaises(continuity.bundle.SigningBundleError):
            continuity.checked_bytes(link, anchor, "proof")
        os.link(path, self.root / "hardlink")
        with self.assertRaises(continuity.bundle.SigningBundleError):
            continuity.checked_bytes(path, anchor, "proof")

    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self) -> None:
        for data in (b'{"pass":true,"pass":false}', b'{"a":NaN}', b'{"a":Infinity}', b'[]'):
            with self.subTest(data=data):
                with self.assertRaises(continuity.ContinuityError):
                    continuity.strict_json(data, "proof")

    def scope_documents(self) -> dict:
        return {
            "native-performance.json": {"candidate_commit": continuity.BASE,
                "status": "independent-current-native-performance-gate-passed"},
            "five-native-lifecycles.json": {"candidate_commit": continuity.BASE,
                "status": "pass", "profile_count": 5},
            "capability-RPM-A9-RHELPO.json": {"candidate_commit": continuity.BASE,
                "verdict": "pass", "blockers": [], "profile_id": "RPM-A9-RHELPO", "host_id": "node05"},
            "capability-DEB-U2604.json": {"candidate_commit": continuity.BASE,
                "verdict": "pass", "blockers": [], "profile_id": "DEB-U2604", "host_id": "node02"},
            "source-allocation.json": {"candidate_commit": continuity.BASE,
                "status": "independent-frozen-source-allocation-gate-passed"},
        }

    def test_eligible_scopes_do_not_relabel_or_mutate_original_proofs(self) -> None:
        documents = self.scope_documents()
        original = copy.deepcopy(documents)
        scopes = continuity.verify_prior_scopes(documents, self.policy)
        self.assertEqual(documents, original)
        for scope in scopes:
            self.assertEqual(scope["observed_candidate"], continuity.BASE)
            self.assertEqual(scope["proposed_acceptance_candidate"], continuity.RUNTIME)
            self.assertEqual(scope["acceptance"],
                             "pending-fresh-affected-gates-and-protected-final-validation")

    def test_failed_relabelled_incomplete_and_different_host_proofs_rejected(self) -> None:
        documents = self.scope_documents()
        for name, original in documents.items():
            mutations = [("candidate_commit", continuity.RUNTIME)]
            if "verdict" in original:
                mutations += [("verdict", "fail")]
            if "host_id" in original:
                mutations += [("host_id", "node03"), ("blockers", ["missing-native-proof"]),
                              ("profile_id", "RPM-A10")]
            if "status" in original:
                mutations += [("status", "incomplete")]
            if "profile_count" in original:
                mutations += [("profile_count", 4)]
            for key, value in mutations:
                changed = copy.deepcopy(documents)
                changed[name][key] = value
                with self.subTest(record=name, field=key):
                    with self.assertRaises(continuity.ContinuityError):
                        continuity.verify_prior_scopes(changed, self.policy)

    def test_changed_package_is_rejected_even_after_valid_bundle_structure(self) -> None:
        root = self.root / "bundle"
        root.mkdir(mode=0o700)
        package = root / "package.rpm"
        package.write_bytes(b"changed payload")
        policy = copy.deepcopy(self.policy)
        policy["packages"] = [{"base": {"path": package.name, "size": package.stat().st_size,
            "sha256": "a" * 64}}]
        with mock.patch.object(continuity.bundle, "verify_bundle"):
            with self.assertRaisesRegex(continuity.ContinuityError, "reviewed anchor"):
                continuity.verify_packages(root, policy, "base")

    def test_eligibility_has_no_acceptance_or_gate_bypass_option(self) -> None:
        import subprocess
        result = subprocess.run(["python3", "-B", str(Path(continuity.__file__)), "--help"],
                                text=True, capture_output=True, check=True)
        for option in ("--allow-old", "--skip", "--approve", "--policy"):
            self.assertNotIn(option, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
