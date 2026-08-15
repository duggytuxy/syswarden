#!/usr/bin/env python3
"""Lock required-check workflow names, dependencies and publication scope."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
WORKFLOWS = REPOSITORY / ".github" / "workflows"


def job_block(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job {job_id} is missing")
    return match.group(0)


class RequiredCheckWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.package = (WORKFLOWS / "package.yml").read_text(encoding="utf-8")
        cls.security = (WORKFLOWS / "security-audit.yml").read_text(
            encoding="utf-8"
        )
        cls.scorecard = (WORKFLOWS / "scorecard.yml").read_text(encoding="utf-8")

    def assert_security_publication_result_contract(self, gate: str) -> None:
        required = (
            "EVENT_NAME: ${{ github.event_name }}",
            "ACT_EVENT: ${{ github.event.act == true && 'true' || 'false' }}",
            'expected_publication_result="success"',
            'if [[ "${EVENT_NAME}" == "pull_request" || "${ACT_EVENT}" == "true" ]]; then',
            'expected_publication_result="skipped"',
            'if [[ "${PUBLICATION_RESULT}" != "${expected_publication_result}" ]]; then',
            "expected ${expected_publication_result} for ${EVENT_NAME}",
        )
        for contract in required:
            self.assertIn(contract, gate)

    def test_package_terminal_check_reflects_the_existing_build(self) -> None:
        gate = job_block(self.package, "package")
        self.assertIn("    name: Package\n", gate)
        self.assertEqual(self.package.count("    name: Package\n"), 1)
        self.assertIn("    needs: [build-and-package]\n", gate)
        self.assertIn("    if: ${{ always() }}\n", gate)
        self.assertIn("    permissions: {}\n", gate)
        self.assertIn("BUILD_RESULT: ${{ needs.build-and-package.result }}", gate)
        self.assertIn('[[ "${BUILD_RESULT}" != "success" ]]', gate)
        self.assertNotIn("actions/checkout", gate)
        self.assertEqual(self.package.count("  build-and-package:\n"), 1)

    def test_security_terminal_check_covers_every_required_control(self) -> None:
        gate = job_block(self.security, "security-audit")
        self.assertIn("    name: Security Audit\n", gate)
        self.assertEqual(self.security.count("    name: Security Audit\n"), 1)
        self.assertIn("    if: ${{ always() }}\n", gate)
        self.assertIn("    permissions: {}\n", gate)
        for job_id in (
            "hygiene",
            "gosec",
            "anti-leaks",
            "sast",
            "build-bundle",
            "github-publication",
        ):
            with self.subTest(job_id=job_id):
                self.assertIn(f"      - {job_id}\n", gate)
                self.assertIn(f"needs.{job_id}.result", gate)
        self.assert_security_publication_result_contract(gate)
        self.assertIn(
            "          for result_name in \\\n"
            "            HYGIENE_RESULT \\\n"
            "            GOSEC_RESULT \\\n"
            "            ANTI_LEAKS_RESULT \\\n"
            "            SAST_RESULT \\\n"
            "            BUILD_BUNDLE_RESULT; do\n",
            gate,
        )

    def test_security_publication_scope_rejects_broad_skip_mutations(self) -> None:
        gate = job_block(self.security, "security-audit")
        mutations = (
            gate.replace(
                "EVENT_NAME: ${{ github.event_name }}",
                "EVENT_NAME: pull_request",
                1,
            ),
            gate.replace(
                "ACT_EVENT: ${{ github.event.act == true && 'true' || 'false' }}",
                "ACT_EVENT: true",
                1,
            ),
            gate.replace(
                'if [[ "${EVENT_NAME}" == "pull_request" || "${ACT_EVENT}" == "true" ]]; then',
                "if false; then",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssertionError):
                    self.assert_security_publication_result_contract(mutation)

    def test_security_publication_remains_conditional(self) -> None:
        publication = job_block(self.security, "github-publication")
        self.assertIn("    name: Publish Security Evidence\n", publication)
        self.assertIn(
            "    if: ${{ github.event_name != 'pull_request' && !github.event.act }}\n",
            publication,
        )

    def test_scorecard_pr_analysis_is_read_only_and_never_publishes(self) -> None:
        trigger = self.scorecard.split("\npermissions:", 1)[0]
        self.assertIn(
            '  pull_request:\n    branches: [ "main", "master" ]\n', trigger
        )
        analysis = job_block(self.scorecard, "pull-request-analysis")
        self.assertIn("    if: ${{ github.event_name == 'pull_request' }}\n", analysis)
        self.assertIn("    permissions:\n      contents: read\n", analysis)
        self.assertNotIn("security-events: write", analysis)
        self.assertNotIn("id-token: write", analysis)
        self.assertIn("          publish_results: false\n", analysis)
        self.assertNotIn("upload-sarif", analysis)

    def test_scorecard_publication_is_push_or_schedule_only(self) -> None:
        publication = job_block(self.scorecard, "published-analysis")
        self.assertIn(
            "    if: ${{ github.event_name == 'push' || github.event_name == 'schedule' }}\n",
            publication,
        )
        self.assertIn("      security-events: write\n", publication)
        self.assertIn("      id-token: write\n", publication)
        self.assertIn("          publish_results: true\n", publication)
        self.assertIn("github/codeql-action/upload-sarif@", publication)
        self.assertEqual(self.scorecard.count("publish_results: true"), 1)
        self.assertEqual(self.scorecard.count("publish_results: false"), 1)
        self.assertEqual(self.scorecard.count("github/codeql-action/upload-sarif@"), 1)
        self.assertEqual(self.scorecard.count("security-events: write"), 1)
        self.assertEqual(self.scorecard.count("id-token: write"), 1)

    def test_scorecard_terminal_check_has_the_exact_required_name(self) -> None:
        gate = job_block(self.scorecard, "scorecard")
        self.assertIn("    name: Scorecard supply-chain security\n", gate)
        self.assertEqual(
            self.scorecard.count("    name: Scorecard supply-chain security\n"), 1
        )
        self.assertIn(
            "    needs: [pull-request-analysis, published-analysis]\n", gate
        )
        self.assertIn("    if: ${{ always() }}\n", gate)
        self.assertIn("    permissions: {}\n", gate)
        self.assertIn("PULL_REQUEST_RESULT:", gate)
        self.assertIn("PUBLISHED_RESULT:", gate)


if __name__ == "__main__":
    unittest.main()
