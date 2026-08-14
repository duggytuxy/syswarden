#!/usr/bin/env python3
"""Unit tests for the fail-closed security baseline gate."""

from __future__ import annotations

import collections
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import security_gate


class GosecGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.report = self.root / "report.json"
        self.baseline = self.root / "baseline.json"
        self.scan_name = "linux-example"
        self.tool_version = "v2.28.0"
        self.tool_binary = self.root / "gosec"
        self.base_ref = ""
        self.log = self.root / "gosec.log"
        self.expected_inventory = collections.Counter({"src/example.go": 1})

    def issue(self, line: str = "12") -> dict[str, object]:
        return {
            "rule_id": "G402",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file": str(self.root / "src/example.go"),
            "line": line,
            "details": "TLS setting",
            "code": f"{line}: client := insecureClient()\n",
        }

    def write_report(
        self,
        issues: list[dict[str, object]],
        files: int = 1,
        errors: dict[str, object] | None = None,
    ) -> None:
        self.report.write_text(
            json.dumps(
                {
                    "Stats": {
                        "files": files,
                        "lines": 10,
                        "nosec": 0,
                        "found": len(issues),
                    },
                    "Issues": issues,
                    "Golang errors": errors or {},
                }
            ),
            encoding="utf-8",
        )
        checked_files = max(files, 1)
        self.log.write_text(
            "".join(
                f"[gosec] Checking file: {self.root / 'src/example.go'}\n"
                for _ in range(checked_files)
            ),
            encoding="utf-8",
        )

    def write_baseline(self, issues: list[dict[str, object]]) -> None:
        records = [security_gate.issue_record(item, self.root) for item in issues]
        self.baseline.write_text(
            json.dumps(
                {
                    "schema_version": 3,
                    "baseline_commit": "0" * 40,
                    "gosec_version": self.tool_version,
                    "scans": {
                        self.scan_name: {
                            "module": "src",
                            "goos": "linux",
                            "goarch": "amd64",
                            "cgo_enabled": "0",
                            "issues": records,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def check(self) -> int:
        with (
            mock.patch.object(
                security_gate, "validate_baseline_metadata", return_value=None
            ),
            mock.patch.object(
                security_gate, "gosec_binary_version", return_value=self.tool_version
            ),
            mock.patch.object(
                security_gate,
                "expected_gosec_inventory",
                return_value=self.expected_inventory,
            ),
        ):
            return security_gate.check_gosec(
                self.report,
                self.baseline,
                self.root,
                self.scan_name,
                self.tool_binary,
                self.base_ref,
                "linux",
                "amd64",
                "0",
                "src",
                self.log,
            )

    def test_reviewed_finding_passes_after_line_move(self) -> None:
        self.write_report([self.issue(line="99")])
        self.write_baseline([self.issue(line="12")])
        self.assertEqual(self.check(), 0)

    def test_source_fingerprint_preserves_string_literal_whitespace(self) -> None:
        one_space = self.issue()
        one_space["code"] = '12: value := "a b"\n'
        two_spaces = self.issue()
        two_spaces["code"] = '99: value := "a  b"\n'
        first = security_gate.issue_record(one_space, self.root)["code_sha256"]
        second = security_gate.issue_record(two_spaces, self.root)["code_sha256"]
        self.assertNotEqual(first, second)

    def test_resolved_finding_requires_same_candidate_baseline_reduction(self) -> None:
        self.write_report([])
        self.write_baseline([self.issue()])
        self.assertEqual(self.check(), 1)

    def test_new_finding_fails(self) -> None:
        self.write_report([self.issue()])
        self.write_baseline([])
        self.assertEqual(self.check(), 1)

    def test_duplicate_finding_cannot_be_hidden_by_a_set(self) -> None:
        self.write_report([self.issue("12"), self.issue("13")])
        self.write_baseline([self.issue()])
        self.assertEqual(self.check(), 1)

    def test_identical_gosec_emission_at_same_location_is_deduplicated(self) -> None:
        issue = self.issue()
        self.write_report([issue, dict(issue)])
        self.write_baseline([issue])
        self.assertEqual(self.check(), 0)

    def test_only_exact_physical_duplicates_are_deduplicated(self) -> None:
        issue = self.issue()
        moved = self.issue("13")
        self.assertEqual(
            len(security_gate.unique_report_issues([issue, dict(issue)], self.root)),
            1,
        )
        self.assertEqual(
            len(security_gate.unique_report_issues([issue, moved], self.root)),
            2,
        )

    def test_empty_or_partial_scan_fails(self) -> None:
        self.write_report([], files=0)
        self.write_baseline([])
        with self.assertRaises(ValueError):
            self.check()

    def test_stats_found_must_match_raw_issue_inventory(self) -> None:
        issue = self.issue()
        self.write_report([issue])
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["Stats"]["found"] = 2
        self.report.write_text(json.dumps(report), encoding="utf-8")
        self.write_baseline([issue])
        with self.assertRaisesRegex(ValueError, "raw issue inventory"):
            self.check()

    def test_canonical_gosec_sections_and_types_are_required(self) -> None:
        self.write_report([])
        self.write_baseline([])
        canonical = json.loads(self.report.read_text(encoding="utf-8"))
        mutations = (
            lambda value: value.pop("Golang errors"),
            lambda value: value.__setitem__("Golang errors", []),
            lambda value: value.pop("Issues"),
            lambda value: value.__setitem__("Issues", {}),
            lambda value: value.pop("Stats"),
            lambda value: value.__setitem__("Stats", []),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                report = json.loads(json.dumps(canonical))
                mutate(report)
                self.report.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.check()

    def test_stats_fields_are_present_non_negative_integers(self) -> None:
        self.write_report([])
        self.write_baseline([])
        canonical = json.loads(self.report.read_text(encoding="utf-8"))
        for field in ("files", "lines", "nosec", "found"):
            for value in (None, "0", -1, True):
                with self.subTest(field=field, value=value):
                    report = json.loads(json.dumps(canonical))
                    report["Stats"][field] = value
                    self.report.write_text(json.dumps(report), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "non-negative integer"):
                        self.check()

    def test_gosec_issue_entries_must_be_objects(self) -> None:
        self.write_report([])
        report = json.loads(self.report.read_text(encoding="utf-8"))
        report["Issues"] = ["not-an-object"]
        report["Stats"]["found"] = 1
        self.report.write_text(json.dumps(report), encoding="utf-8")
        self.write_baseline([])
        with self.assertRaisesRegex(ValueError, "issues must be objects"):
            self.check()

    def test_unreviewed_scan_inventory_growth_fails(self) -> None:
        self.write_report([], files=2)
        self.write_baseline([])
        with self.assertRaises(ValueError):
            self.check()

    def test_go_loading_error_fails(self) -> None:
        self.write_report([], errors={"example": "package failed to load"})
        self.write_baseline([])
        self.assertEqual(self.check(), 1)

    def test_fatal_ssa_diagnostic_fails_closed(self) -> None:
        self.log.write_text(
            "Error building the SSA representation of package: package has type errors\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_log(self.log)

    def test_normal_gosec_progress_log_passes(self) -> None:
        self.log.write_text(
            f"[gosec] Checking file: {self.root / 'src/example.go'}\n",
            encoding="utf-8",
        )
        security_gate.validate_gosec_log(self.log)

    def test_log_without_checked_files_fails_closed(self) -> None:
        self.log.write_text("[gosec] Checking package: main\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_log(self.log)

    def test_legitimate_file_removal_needs_no_static_count_baseline(self) -> None:
        remaining = collections.Counter({"src/remaining.go": 1})
        security_gate.validate_gosec_file_inventory(1, remaining, remaining)

    def test_same_count_path_substitution_fails_closed(self) -> None:
        actual = collections.Counter({"src/substitute.go": 1})
        expected = collections.Counter({"src/expected.go": 1})
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_file_inventory(1, actual, expected)

    def test_missing_duplicate_scan_fails_closed(self) -> None:
        actual = collections.Counter({"src/example.go": 1})
        expected = collections.Counter({"src/example.go": 2})
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_file_inventory(1, actual, expected)

    def test_unexpected_duplicate_scan_fails_closed(self) -> None:
        actual = collections.Counter({"src/example.go": 2})
        expected = collections.Counter({"src/example.go": 1})
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_file_inventory(2, actual, expected)

    def test_stats_and_log_inventory_mismatch_fails_closed(self) -> None:
        inventory = collections.Counter({"src/example.go": 1})
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_file_inventory(2, inventory, inventory)

    def test_expected_inventory_matches_go_list_test_multiset(self) -> None:
        module = self.root / "src"
        module.mkdir()
        generated = self.root / "cache" / "testmain.go"
        stream = "".join(
            json.dumps(document)
            for document in (
                {"Dir": str(module), "GoFiles": ["example.go"]},
                {
                    "Dir": str(module),
                    "GoFiles": ["example.go", "example_test.go"],
                },
                {"Dir": str(generated.parent), "GoFiles": [generated.name]},
            )
        )
        with mock.patch.object(
            security_gate.subprocess,
            "run",
            return_value=mock.Mock(stdout=stream, stderr=""),
        ):
            inventory = security_gate.expected_gosec_inventory(
                self.root, "src", "linux", "amd64", "0"
            )
        self.assertEqual(
            inventory,
            collections.Counter(
                {"src/example.go": 2, "src/example_test.go": 1}
            ),
        )

    def test_tool_version_mismatch_fails_closed(self) -> None:
        self.write_report([])
        self.write_baseline([])
        with (
            mock.patch.object(
                security_gate, "validate_baseline_metadata", return_value=None
            ),
            mock.patch.object(
                security_gate, "gosec_binary_version", return_value="v0.0.0"
            ),
            self.assertRaises(ValueError),
        ):
            security_gate.check_gosec(
                self.report,
                self.baseline,
                self.root,
                self.scan_name,
                self.tool_binary,
                self.base_ref,
                "linux",
                "amd64",
                "0",
                "src",
                self.log,
            )

    def test_scan_identity_mismatch_fails_closed(self) -> None:
        self.write_report([])
        self.write_baseline([])
        with (
            mock.patch.object(
                security_gate, "validate_baseline_metadata", return_value=None
            ),
            mock.patch.object(
                security_gate, "gosec_binary_version", return_value=self.tool_version
            ),
        ):
            with self.assertRaises(ValueError):
                security_gate.check_gosec(
                    self.report,
                    self.baseline,
                    self.root,
                    self.scan_name,
                    self.tool_binary,
                    self.base_ref,
                    "freebsd",
                    "amd64",
                    "0",
                    "src",
                    self.log,
                )
            with self.assertRaises(ValueError):
                security_gate.check_gosec(
                    self.report,
                    self.baseline,
                    self.root,
                    self.scan_name,
                    self.tool_binary,
                    self.base_ref,
                    "linux",
                    "amd64",
                    "0",
                    "src/other",
                    self.log,
                )

    def test_baseline_evolution_cannot_add_reviewed_findings(self) -> None:
        previous = {
            "schema_version": 3,
            "baseline_commit": "0" * 40,
            "gosec_version": self.tool_version,
            "scans": {
                self.scan_name: {
                    "module": "src",
                    "goos": "linux",
                    "goarch": "amd64",
                    "cgo_enabled": "0",
                    "issues": [],
                }
            },
        }
        current = json.loads(json.dumps(previous))
        current["scans"][self.scan_name]["issues"] = [
            security_gate.issue_record(self.issue(), self.root)
        ]
        with self.assertRaises(ValueError):
            security_gate.validate_gosec_evolution(current, previous)


class NosecGateTests(unittest.TestCase):
    def inventory(self, content: str):
        return security_gate.nosec_inventory(
            [("src/core/example/example.go", content)]
        )

    def test_existing_legacy_annotation_is_a_subset(self) -> None:
        content = "package example\nvar _ = dangerous() // #nosec\n"
        baseline, _, _ = self.inventory(content)
        current, _, _ = self.inventory(content)
        self.assertFalse(current - baseline)

    def test_new_legacy_annotation_fails_subset_check(self) -> None:
        baseline, _, _ = self.inventory("package example\n")
        current, _, _ = self.inventory(
            "package example\nvar _ = dangerous() // #nosec\n"
        )
        self.assertTrue(current - baseline)

    def test_constant_count_annotation_swap_is_detected(self) -> None:
        baseline, _, _ = self.inventory(
            "package example\nvar _ = oldCall() // #nosec\n"
        )
        current, _, _ = self.inventory(
            "package example\nvar _ = newCall() // #nosec\n"
        )
        self.assertEqual(sum(baseline.values()), sum(current.values()))
        self.assertTrue(current - baseline)

    def test_annotation_fingerprint_preserves_literal_whitespace(self) -> None:
        first, _, _ = self.inventory(
            'package example\nvar _ = dangerous("a b") // #nosec\n'
        )
        second, _, _ = self.inventory(
            'package example\nvar _ = dangerous("a  b") // #nosec\n'
        )
        self.assertNotEqual(first, second)

    def test_rule_and_justification_do_not_consume_legacy_budget(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\n"
            "var _ = reviewed() // #nosec G204 -- arguments are fixed constants\n"
        )
        self.assertEqual(total, 1)
        self.assertEqual(qualified, 1)
        self.assertFalse(legacy)

    def test_string_literal_does_not_hide_generic_directive(self) -> None:
        legacy, total, qualified = self.inventory(
            'package example\nvar _ = dangerous("#nosec G204 -- harmless") // #nosec\n'
        )
        self.assertEqual(total, 1)
        self.assertEqual(qualified, 0)
        self.assertEqual(sum(legacy.values()), 1)

    def test_nosec_prefix_substring_is_a_real_gosec_directive(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\nvar _ = safe() // #nosecurity\n"
        )
        self.assertEqual((total, qualified), (1, 0))
        self.assertEqual(sum(legacy.values()), 1)

    def test_concatenated_nosec_rule_and_justification_is_qualified(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\n"
            "var _ = reviewed() // #nosecG204 -- fixed command and arguments\n"
        )
        self.assertEqual((total, qualified), (1, 1))
        self.assertFalse(legacy)

    def test_concatenated_nosec_suffix_without_rule_is_legacy(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\nvar _ = risky() // #nosecblock\n"
        )
        self.assertEqual((total, qualified), (1, 0))
        self.assertEqual(sum(legacy.values()), 1)

    def test_rule_only_directive_remains_legacy(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\nvar _ = risky() // #nosec G204\n"
        )
        self.assertEqual((total, qualified), (1, 0))
        self.assertEqual(sum(legacy.values()), 1)

    def test_block_comment_directive_is_inventoried(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\nvar _ = risky() /* #nosec G204 */\n"
        )
        self.assertEqual((total, qualified), (1, 0))
        self.assertEqual(sum(legacy.values()), 1)

    def test_multiline_block_comment_directive_is_inventoried(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\n"
            "var _ = risky() /* description\n"
            " #nosec G204 -- fixed command and arguments\n"
            " */\n"
        )
        self.assertEqual((total, qualified), (1, 1))
        self.assertFalse(legacy)

    def test_block_comment_star_prefix_is_not_a_gosec_directive(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\n"
            "var _ = safe() /* description\n"
            " * #nosec G204 -- not recognized by gosec\n"
            " */\n"
        )
        self.assertEqual((total, qualified), (0, 0))
        self.assertFalse(legacy)

    def test_gosec_disable_requires_rules_and_justification(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\n"
            "var _ = risky() //gosec:disable G204 -- arguments are validated\n"
        )
        self.assertEqual((total, qualified), (1, 1))
        self.assertFalse(legacy)

    def test_multiline_raw_string_is_not_parsed_as_comment(self) -> None:
        legacy, total, qualified = self.inventory(
            "package example\nvar raw = `\n// #nosec\n/* #nosec G204 */\n`\n"
        )
        self.assertEqual((total, qualified), (0, 0))
        self.assertFalse(legacy)

    def test_resolved_legacy_directive_requires_baseline_reduction(self) -> None:
        legacy, _, _ = self.inventory(
            "package example\nvar _ = risky() // #nosec\n"
        )
        records = [
            {"file": path, "source_sha256": fingerprint, "count": count}
            for (path, fingerprint), count in legacy.items()
        ]
        baseline = {
            "schema_version": 2,
            "baseline_commit": "0" * 40,
            "legacy": records,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(security_gate, "read_json", return_value=baseline),
            mock.patch.object(
                security_gate, "validate_baseline_metadata", return_value=None
            ),
            mock.patch.object(
                security_gate,
                "current_go_files",
                return_value=[("src/core/example/example.go", "package example\n")],
            ),
        ):
            root = Path(temporary)
            self.assertEqual(
                security_gate.check_nosec(root / "baseline.json", root, ""), 1
            )


class ActFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]

    def test_local_push_fixture_marks_github_only_jobs_as_excluded(self) -> None:
        fixture = self.repository / ".github" / "act" / "push.json"
        event = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertIs(event.get("act"), True)
        self.assertRegex(str(event.get("before", "")), r"^[0-9a-f]{40}$")
        self.assertRegex(str(event.get("after", "")), r"^[0-9a-f]{40}$")
        self.assertTrue(event.get("repository", {}).get("owner", {}).get("login"))
        self.assertTrue(event.get("commits"))

    def test_actrc_loads_the_safe_push_fixture_by_default(self) -> None:
        actrc = self.repository / ".actrc"
        entries = {
            line.strip()
            for line in actrc.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn("--eventpath .github/act/push.json", entries)
        self.assertIn("--concurrent-jobs 1", entries)

    def test_trivy_install_is_checksum_pinned_and_skips_nested_setup(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "TRIVY_ARCHIVE_SHA256: "
            "8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9",
            workflow,
        )
        self.assertIn(
            "https://github.com/aquasecurity/trivy/releases/download/"
            "v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz",
            workflow,
        )
        self.assertEqual(workflow.count("skip-setup-trivy: true"), 2)
        self.assertNotIn("token-setup-trivy:", workflow)

    def test_public_markdown_uses_pinned_markdownlint(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "DavidAnson/markdownlint-cli2-action@"
            "fa0cd0f1a052f54da593c83860f2292982f5d142 # v23.2.0",
            workflow,
        )
        self.assertIn("config: .markdownlint.json", workflow)
        self.assertIn("globs: README.md", workflow)

    def test_bounded_fuzz_campaigns_are_mandatory(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Run bounded parser and network fuzz campaigns", workflow)
        self.assertIn("-fuzztime=5s -parallel=2", workflow)
        for target in (
            "FuzzMigratorParseFromMemory",
            "FuzzIPCIDRPortValidators",
            "FuzzIsValidIP",
            "FuzzHASyncPayloadJSON",
            "FuzzEngineNetworkAndURLInput",
        ):
            self.assertEqual(workflow.count(target), 1)

    def test_baseline_candidate_cli_process_gate_is_mandatory(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Compare frozen and candidate CLI process contracts", workflow)
        self.assertIn("scripts/ci/cli_process_compatibility.py", workflow)
        self.assertIn("--run", workflow)
        self.assertIn(
            '--report "${RUNNER_TEMP}/cli-process-compatibility.json"', workflow
        )

    def test_act_artifact_compatibility_is_scoped_to_act(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        github_pin = (
            "actions/upload-artifact@"
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        )
        act_pin = (
            "actions/upload-artifact@"
            "ea165f8d65b6e75b540449e92b4886f43607fa02"
        )
        self.assertEqual(workflow.count(github_pin), 6)
        self.assertEqual(workflow.count(act_pin), 5)
        self.assertEqual(workflow.count("with Act-compatible protocol"), 5)
        self.assertEqual(
            workflow.count("ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY: '1'"), 5
        )
        self.assertEqual(workflow.count("if: ${{ github.event.act }}\n"), 4)
        self.assertEqual(
            workflow.count("if: ${{ always() && github.event.act }}\n"), 1
        )

    def test_base_ref_selection_is_event_and_act_aware(self) -> None:
        sha = "a" * 40
        zero = "0" * 40
        cases = (
            (sha, False, False, sha),
            (zero, False, False, "HEAD^"),
            ("", False, False, "HEAD^"),
            (sha, True, True, "HEAD"),
            (sha, True, False, "HEAD^"),
        )
        for raw, act, dirty, expected in cases:
            with self.subTest(raw=raw, act=act, dirty=dirty):
                self.assertEqual(
                    security_gate.select_base_ref(raw, act, dirty), expected
                )


class GitleaksContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]

    def test_history_and_worktree_policies_are_separated(self) -> None:
        history = tomllib.loads(
            (self.repository / ".gitleaks-history.toml").read_text(encoding="utf-8")
        )
        worktree = tomllib.loads(
            (self.repository / ".gitleaks.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(history, {"title": history["title"], "extend": {"useDefault": True}})
        rules = worktree.get("rules", [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].get("id"), "generic-api-key")
        allowlists = rules[0].get("allowlists", [])
        self.assertEqual(len(allowlists), 1)
        self.assertEqual(allowlists[0].get("condition"), "AND")
        self.assertEqual(allowlists[0].get("regexTarget"), "match")
        self.assertEqual(
            allowlists[0].get("paths"),
            [r"^src/core/syswarden-cli/cmd/ui/assets/xterm\.js$"],
        )
        self.assertEqual(
            allowlists[0].get("regexes"),
            [r"^t\.FourKeyMap=t\.TwoKeyMap=void $"],
        )

    def test_workflow_uses_pinned_binary_and_explicit_policies(self) -> None:
        workflow = (
            self.repository / ".github" / "workflows" / "security-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("go-version: '1.26.6'", workflow)
        self.assertIn("go install github.com/zricethezav/gitleaks/v8@v8.24.3", workflow)
        self.assertIn('go version -m "${GITLEAKS_BIN}/gitleaks"', workflow)
        self.assertIn(
            "$'\\tmod\\tgithub.com/zricethezav/gitleaks/v8\\tv8.24.3\\t'",
            workflow,
        )
        self.assertIn('"${GITLEAKS}" git \\\n            --config .gitleaks-history.toml', workflow)
        self.assertIn('"${GITLEAKS}" dir \\\n            --config .gitleaks.toml', workflow)


if __name__ == "__main__":
    unittest.main()
