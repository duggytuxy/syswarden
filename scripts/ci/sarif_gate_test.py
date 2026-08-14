#!/usr/bin/env python3
"""Tests for deterministic gosec SARIF normalization."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import sarif_gate


class SarifGateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        source = self.repository / "src" / "core" / "module" / "pkg" / "code.go"
        source.parent.mkdir(parents=True)
        source.write_text("package pkg\n\nfunc example() { dangerous() }\n", encoding="utf-8")

    def report(self, uri: str = "pkg/code.go") -> dict:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gosec",
                            "rules": [
                                {
                                    "id": "G204",
                                    "defaultConfiguration": {"level": "error"},
                                    "help": {
                                        "text": "Subprocess launched\nSeverity: HIGH\nConfidence: HIGH\n"
                                    },
                                    "properties": {"tags": ["security", "HIGH"]},
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "G204",
                            "level": "error",
                            "message": {"text": "Subprocess launched"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {
                                            "startLine": 3,
                                            "startColumn": 18,
                                            "snippet": {"text": "dangerous()"},
                                        },
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }

    def json_report(self, path: str = "pkg/code.go") -> dict:
        return {
            "Issues": [
                {
                    "rule_id": "G204",
                    "file": path,
                    "details": "Subprocess launched",
                    "line": "3",
                    "column": "18",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "code": "3: dangerous()\n",
                }
            ]
        }

    def test_normalizes_module_path_and_adds_stable_fingerprint(self) -> None:
        report = sarif_gate.normalize(
            self.report(), self.json_report(), "src/core/module", self.repository
        )
        result = report["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "src/core/module/pkg/code.go")
        self.assertRegex(result["partialFingerprints"]["syswarden/v1"], r"^[0-9a-f]{64}$")

    def test_fingerprint_survives_real_source_line_movement(self) -> None:
        first = sarif_gate.normalize(
            self.report(), self.json_report(), "src/core/module", self.repository
        )["runs"][0]["results"][0]["partialFingerprints"]["syswarden/v1"]
        source = self.repository / "src" / "core" / "module" / "pkg" / "code.go"
        source.write_text(
            "// unrelated line\n" + source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        moved = self.report()
        moved["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]["startLine"] = 4
        moved_json = self.json_report()
        moved_json["Issues"][0]["line"] = "4"
        moved_json["Issues"][0]["code"] = "4: dangerous()\n"
        second = sarif_gate.normalize(
            moved, moved_json, "src/core/module", self.repository
        )["runs"][0]["results"][0]["partialFingerprints"]["syswarden/v1"]
        self.assertEqual(first, second)

    def test_fingerprint_changes_when_exact_snippet_changes(self) -> None:
        first = sarif_gate.normalize(
            self.report(), self.json_report(), "src/core/module", self.repository
        )["runs"][0]["results"][0]["partialFingerprints"]["syswarden/v1"]
        source = self.repository / "src" / "core" / "module" / "pkg" / "code.go"
        source.write_text(
            source.read_text(encoding="utf-8").replace("dangerous()", "dangerous(1)"),
            encoding="utf-8",
        )
        changed = self.report()
        changed["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]["snippet"]["text"] = "dangerous(1)"
        changed_json = self.json_report()
        changed_json["Issues"][0]["code"] = "3: dangerous(1)\n"
        second = sarif_gate.normalize(
            changed, changed_json, "src/core/module", self.repository
        )["runs"][0]["results"][0]["partialFingerprints"]["syswarden/v1"]
        self.assertNotEqual(first, second)

    def test_rejects_missing_or_escaping_source(self) -> None:
        for uri in ("pkg/missing.go", "../outside.go", "/absolute.go"):
            with self.subTest(uri=uri), self.assertRaises(sarif_gate.SarifError):
                sarif_gate.normalize(
                    self.report(uri), self.json_report(uri), "src/core/module", self.repository
                )

    def test_rejects_sarif_json_inventory_mismatch(self) -> None:
        for json_report in ({"Issues": []}, self.json_report("pkg/missing.go")):
            with self.subTest(json_report=json_report), self.assertRaises(
                sarif_gate.SarifError
            ):
                sarif_gate.normalize(
                    self.report(), json_report, "src/core/module", self.repository
                )

    def test_exact_physical_duplicate_is_removed(self) -> None:
        report = self.report()
        report["runs"][0]["results"].append(
            copy.deepcopy(report["runs"][0]["results"][0])
        )
        normalized = sarif_gate.normalize(
            report, self.json_report(), "src/core/module", self.repository
        )
        self.assertEqual(len(normalized["runs"][0]["results"]), 1)

    def test_empty_gosec_report_without_rule_metadata_is_valid(self) -> None:
        report = self.report()
        report["runs"][0]["results"] = []
        report["runs"][0]["tool"]["driver"].pop("rules")
        normalized = sarif_gate.normalize(
            report, {"Issues": []}, "src/core/module", self.repository
        )
        self.assertEqual(normalized["runs"][0]["results"], [])

    def test_missing_rule_metadata_is_rejected_when_json_has_a_finding(self) -> None:
        report = self.report()
        report["runs"][0]["results"] = []
        report["runs"][0]["tool"]["driver"].pop("rules")
        with self.assertRaises(sarif_gate.SarifError):
            sarif_gate.normalize(
                report, self.json_report(), "src/core/module", self.repository
            )

    def test_empty_report_from_another_tool_is_rejected(self) -> None:
        report = self.report()
        report["runs"][0]["results"] = []
        report["runs"][0]["tool"]["driver"] = {"name": "not-gosec"}
        with self.assertRaises(sarif_gate.SarifError):
            sarif_gate.normalize(
                report, {"Issues": []}, "src/core/module", self.repository
            )

    def test_missing_or_wrong_sarif_version_is_rejected(self) -> None:
        for version in (None, "2.0.0", 2.1):
            with self.subTest(version=version):
                report = self.report()
                if version is None:
                    report.pop("version")
                else:
                    report["version"] = version
                with self.assertRaisesRegex(sarif_gate.SarifError, "version"):
                    sarif_gate.normalize(
                        report, self.json_report(), "src/core/module", self.repository
                    )

    def test_json_issues_must_be_a_present_array(self) -> None:
        for json_report in ({}, {"Issues": None}, {"Issues": {}}):
            with self.subTest(json_report=json_report), self.assertRaisesRegex(
                sarif_gate.SarifError, "present array"
            ):
                sarif_gate.normalize(
                    self.report(), json_report, "src/core/module", self.repository
                )

    def test_same_finding_on_two_lines_is_preserved_with_unique_fingerprints(self) -> None:
        report = self.report()
        second = copy.deepcopy(report["runs"][0]["results"][0])
        second["locations"][0]["physicalLocation"]["region"]["startLine"] = 4
        report["runs"][0]["results"].append(second)
        json_report = self.json_report()
        second_issue = dict(json_report["Issues"][0])
        second_issue["line"] = "4"
        second_issue["code"] = "4: dangerous()\n"
        json_report["Issues"].append(second_issue)
        normalized = sarif_gate.normalize(
            report, json_report, "src/core/module", self.repository
        )
        results = normalized["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(
            len({result["partialFingerprints"]["syswarden/v1"] for result in results}),
            2,
        )

    def test_same_location_with_different_snippet_is_not_hidden(self) -> None:
        report = self.report()
        second = copy.deepcopy(report["runs"][0]["results"][0])
        second["locations"][0]["physicalLocation"]["region"]["snippet"][
            "text"
        ] = "example()"
        report["runs"][0]["results"].append(second)
        with self.assertRaises(sarif_gate.SarifError):
            sarif_gate.normalize(
                report, self.json_report(), "src/core/module", self.repository
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
