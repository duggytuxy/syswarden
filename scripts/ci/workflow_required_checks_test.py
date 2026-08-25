#!/usr/bin/env python3
"""Lock required-check workflow names, dependencies and publication scope."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
WORKFLOWS = REPOSITORY / ".github" / "workflows"
PLUMBER_ACTION = (
    "getplumber/plumber@7bdbfee1f067431ce13f1b239c76f724ccadd0bf"
    " # v0.4.41"
)
OFFICIAL_LOGO_SHA256 = (
    "616227e08ee7a93e27582976af16664c86d049319f2a8d6774ec5da4c7881895"
)
OFFICIAL_MARK_CONTRACTS = (
    'd="M50 0 L100 20 V60 C100 90 75 110 50 120 C25 110 0 90 0 60 V20 L50 0 Z"',
    'd="M50 15 L85 30 V55 C85 75 65 90 50 100 C35 90 15 75 15 55 V30 L50 15 Z"',
    'd="M35 45 L50 60 L35 75"',
    'x1="55" y1="75" x2="70" y2="75"',
)
EMBEDDED_MARK_PRESENTATION = (
    'fill="#161B22" stroke="url(#officialShieldGradient)" stroke-width="4" filter="url(#officialLogoGlow)"',
    'fill="none" stroke="#00A3FF" stroke-width="1.5" opacity="0.5"',
    'fill="none" stroke="#FFFFFF" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"',
    'stroke="#00A3FF" stroke-width="4" stroke-linecap="round" filter="url(#officialLogoGlow)"',
)
LEGACY_DARK_VISUALS = {
    "syswarden_architecture.svg",
    "syswarden_bunkerweb_integration.svg",
}


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
        cls.compliance = (WORKFLOWS / "compliance.yml").read_text(
            encoding="utf-8"
        )
        cls.dependabot = (REPOSITORY / ".github" / "dependabot.yml").read_text(
            encoding="utf-8"
        )
        cls.package = (WORKFLOWS / "package.yml").read_text(encoding="utf-8")
        cls.plumber_policy = (REPOSITORY / ".plumber.yaml").read_text(
            encoding="utf-8"
        )
        cls.readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        cls.contributing = (REPOSITORY / "CONTRIBUTING.md").read_text(
            encoding="utf-8"
        )
        cls.official_logo_path = REPOSITORY / "assets" / "syswarden_logo.svg"
        cls.official_logo = cls.official_logo_path.read_text(encoding="utf-8")
        cls.brand_visuals = {
            path.name: path.read_text(encoding="utf-8")
            for path in (REPOSITORY / "assets").glob("syswarden_*.svg")
            if path.name != "syswarden_logo.svg"
        }
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

    def assert_plumber_result_contract(self, gate: str) -> None:
        required = (
            "EVENT_NAME: ${{ github.event_name }}",
            "PULL_REQUEST_RESULT: ${{ needs.pull-request-analysis.result }}",
            "PUBLISHED_RESULT: ${{ needs.published-analysis.result }}",
            'case "${EVENT_NAME}" in',
            "pull_request)",
            '[[ "${PULL_REQUEST_RESULT}" == "success" ]]',
            '[[ "${PUBLISHED_RESULT}" == "skipped" ]]',
            "push|schedule)",
            '[[ "${PULL_REQUEST_RESULT}" == "skipped" ]]',
            '[[ "${PUBLISHED_RESULT}" == "success" ]]',
            'echo "ERROR: unsupported Plumber event ${EVENT_NAME}." >&2',
        )
        for contract in required:
            self.assertIn(contract, gate)

    def test_plumber_triggers_cover_premerge_and_weekly_drift(self) -> None:
        trigger = self.compliance.split("\npermissions:", 1)[0]
        self.assertIn("  push:\n    branches: [main]\n    tags: ['v*']\n", trigger)
        self.assertIn("  pull_request:\n    branches: [main]\n", trigger)
        self.assertIn("  schedule:\n    - cron: '30 2 * * 1'\n", trigger)

    def test_plumber_pull_request_analysis_is_read_only_and_strict(self) -> None:
        analysis = job_block(self.compliance, "pull-request-analysis")
        self.assertIn("    if: ${{ github.event_name == 'pull_request' }}\n", analysis)
        self.assertIn("    permissions:\n      contents: read\n", analysis)
        self.assertNotIn("id-token: write", analysis)
        self.assertNotIn("security-events: write", analysis)
        self.assertIn(f"        uses: {PLUMBER_ACTION}\n", analysis)
        self.assertIn("          version: v0.4.41\n", analysis)
        self.assertIn("          min-points: 100\n", analysis)
        self.assertIn("          score-push: false\n", analysis)
        self.assertIn("          upload-sarif: false\n", analysis)
        self.assertIn("          artifact-name: plumber-report\n", analysis)
        self.assertNotIn("threshold:", analysis)

    def test_plumber_publication_is_push_or_schedule_only(self) -> None:
        publication = job_block(self.compliance, "published-analysis")
        self.assertIn(
            "    if: ${{ github.event_name == 'push' || github.event_name == 'schedule' }}\n",
            publication,
        )
        self.assertIn("      contents: read\n", publication)
        self.assertIn("      id-token: write\n", publication)
        self.assertIn("      security-events: write\n", publication)
        self.assertIn(f"        uses: {PLUMBER_ACTION}\n", publication)
        self.assertIn("          version: v0.4.41\n", publication)
        self.assertIn("          min-points: 100\n", publication)
        self.assertIn("          score-push: true\n", publication)
        self.assertIn("          upload-sarif: true\n", publication)
        self.assertIn("          artifact-name: plumber-report\n", publication)
        self.assertNotIn("threshold:", publication)

    def test_plumber_action_and_score_gate_have_no_weaker_path(self) -> None:
        self.assertEqual(self.compliance.count(f"uses: {PLUMBER_ACTION}"), 2)
        self.assertEqual(self.compliance.count("          version: v0.4.41\n"), 2)
        self.assertEqual(self.compliance.count("          min-points: 100\n"), 2)
        self.assertEqual(self.compliance.count("          score-push: false\n"), 1)
        self.assertEqual(self.compliance.count("          score-push: true\n"), 1)
        self.assertNotIn("threshold:", self.compliance)

    def test_readme_publishes_the_official_plumber_score_with_live_badges(self) -> None:
        official_score = "https://score.getplumber.io/github.com/duggytuxy/syswarden"
        self.assertEqual(self.readme.count(f'href="{official_score}"'), 1)
        self.assertEqual(self.readme.count(f'src="{official_score}.svg"'), 1)
        self.assertEqual(self.readme.count('alt="Plumber Score"'), 1)
        for workflow in (
            "package.yml",
            "security-audit.yml",
            "compliance.yml",
            "scorecard.yml",
        ):
            with self.subTest(workflow=workflow):
                workflow_url = (
                    "https://github.com/duggytuxy/syswarden/actions/workflows/"
                    f"{workflow}"
                )
                self.assertEqual(self.readme.count(f'href="{workflow_url}"'), 1)
                self.assertEqual(
                    self.readme.count(
                        "https://img.shields.io/github/actions/workflow/status/"
                        f"duggytuxy/syswarden/{workflow}?branch=main&amp;"
                    ),
                    1,
                )
        self.assertEqual(
            self.readme.count('src="assets/syswarden_hero.svg"'), 1
        )
        self.assertEqual(
            self.readme.count('src="assets/syswarden_architecture.svg"'), 0
        )
        self.assertEqual(
            self.readme.count(
                '</div>\n\n<br>\n\n<div align="center">'
            ),
            1,
        )
        self.assertEqual(
            self.readme.count(
                "[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)]"
                "(https://ko-fi.com/laurentmduggytuxy)"
            ),
            1,
        )

    def test_published_visuals_embed_the_exact_official_syswarden_brand(self) -> None:
        self.assertEqual(
            hashlib.sha256(self.official_logo_path.read_bytes()).hexdigest(),
            OFFICIAL_LOGO_SHA256,
        )
        for contract in OFFICIAL_MARK_CONTRACTS:
            self.assertIn(contract, self.official_logo)
        for name, visual in self.brand_visuals.items():
            with self.subTest(visual=name):
                self.assertEqual(
                    visual.count(
                        'data-brand-source="assets/syswarden_logo.svg"'
                    ),
                    1,
                )
                self.assertIn("<text x=\"160\" y=\"90\"", visual)
                self.assertIn(">SYSWARDEN</text>", visual)
                self.assertIn(">ACTIVE DEFENSE HIDS/HIPS</text>", visual)
                for contract in OFFICIAL_MARK_CONTRACTS:
                    self.assertEqual(visual.count(contract), 1)
                for presentation in EMBEDDED_MARK_PRESENTATION:
                    self.assertEqual(visual.count(presentation), 1)
        self.assertEqual(
            self.brand_visuals["syswarden_bunkerweb_integration.svg"].count(
                'href="#syswardenOfficialMark"'
            ),
            3,
        )
        self.assertNotIn(
            'd="M45 73 L57 85 L82 56"',
            self.brand_visuals["syswarden_hero.svg"],
        )
        self.assertNotIn(
            'd="M36 48L45 57L60 39"',
            self.brand_visuals["syswarden_bunkerweb_integration.svg"],
        )

    def test_new_published_visuals_default_to_the_light_theme(self) -> None:
        visuals = {
            path.name: path.read_text(encoding="utf-8")
            for path in (REPOSITORY / "assets").glob("syswarden_*.svg")
            if path.name != "syswarden_logo.svg"
        }
        hero_name = "syswarden_hero.svg"
        self.assertTrue(LEGACY_DARK_VISUALS.issubset(self.brand_visuals))
        self.assertTrue(LEGACY_DARK_VISUALS.issubset(visuals))
        self.assertIn(hero_name, visuals)
        for name, visual in visuals.items():
            with self.subTest(visual=name):
                if name == hero_name:
                    self.assertNotIn('data-theme=', visual)
                    self.assertNotIn('data-theme-status=', visual)
                elif name in LEGACY_DARK_VISUALS:
                    self.assertIn('data-theme="dark"', visual)
                    self.assertIn('data-theme-status="legacy"', visual)
                else:
                    self.assertIn('data-theme="light"', visual)
                    self.assertNotIn('data-theme-status="legacy"', visual)

        hero = visuals[hero_name]
        self.assertIn(
            '<svg xmlns="http://www.w3.org/2000/svg" width="1600" '
            'height="340" viewBox="0 0 1600 340"',
            hero,
        )
        self.assertEqual(
            hero.count(
                '<rect width="1600" height="340" rx="24" fill="#0b1f33"/>'
            ),
            1,
        )
        self.assertEqual(
            hero.count('<g transform="translate(170 12.5) scale(2.1)">'),
            1,
        )
        self.assertEqual(hero.count('<use href="#syswardenOfficialLogo"/>'), 1)
        self.assertNotIn('id="background"', hero)
        self.assertNotIn('url(#background)', hero)
        self.assertNotIn('id="cardShadow"', hero)
        self.assertNotIn("feDropShadow", hero)
        self.assertNotIn('<stop offset="0" stop-color="#f8fafc"/>', hero)
        self.assertNotIn('<stop offset="1" stop-color="#eef6fb"/>', hero)

        rendered_content = hero.split("</defs>", 1)[1]
        self.assertEqual(rendered_content.count("<rect "), 1)
        self.assertEqual(rendered_content.count("<g "), 1)
        self.assertEqual(rendered_content.count("<use "), 1)
        for decorative_element in ("<circle ", "<ellipse ", "<path ", "<line "):
            self.assertNotIn(decorative_element, rendered_content)

        placement = re.search(
            r'<g transform="translate\((?P<x>[0-9.]+) (?P<y>[0-9.]+)\) '
            r'scale\((?P<scale>[0-9.]+)\)">',
            rendered_content,
        )
        self.assertIsNotNone(placement)
        assert placement is not None
        logo_x = float(placement.group("x"))
        logo_y = float(placement.group("y"))
        logo_scale = float(placement.group("scale"))
        self.assertGreaterEqual(logo_x, 0)
        self.assertGreaterEqual(logo_y, 0)
        self.assertLessEqual(logo_x + (600 * logo_scale), 1600)
        self.assertLessEqual(logo_y + (150 * logo_scale), 340)

        mark_placement = re.search(
            r'<use href="#syswardenOfficialMark" '
            r'transform="translate\((?P<x>[0-9.]+), (?P<y>[0-9.]+)\)"/>',
            hero,
        )
        wordmark = re.search(
            r'<text x="(?P<x>[0-9.]+)" y="90" '
            r'class="official-logo-text">SYSWARDEN</text>',
            hero,
        )
        self.assertIsNotNone(mark_placement)
        self.assertIsNotNone(wordmark)
        assert mark_placement is not None
        assert wordmark is not None
        self.assertLess(
            float(mark_placement.group("x")) + 100,
            float(wordmark.group("x")),
        )

        self.assertEqual(hero.count('fill="#0b1f33"'), 1)
        self.assertEqual(hero.count("fill: #FFFFFF;"), 2)
        self.assertNotIn("fill: #0f2740;", hero)
        self.assertNotIn("fill: #34506b;", hero)

    def test_bunkerweb_visual_routes_and_labels_do_not_reintroduce_overlaps(self) -> None:
        visual = self.brand_visuals["syswarden_bunkerweb_integration.svg"]
        self.assertIn(
            'transform="translate(30 5) scale(0.68)"',
            self.brand_visuals["syswarden_architecture.svg"],
        )
        required = (
            'd="M910 338V418H410V539"',
            '<rect x="930" y="414" width="250" height="24"',
            '<text x="1055" y="431"',
            '<text x="480" y="558"',
            '<text x="480" y="627"',
            '<rect x="988" y="625" width="156" height="24"',
            '<text x="1066" y="642"',
            'd="M428 615H450V878H1375V842"',
            'd="M984 518V444H470V392"',
            'd="M832 659V642H974V622"',
            '<rect width="280" height="44" rx="12"',
            'transform="translate(28 2) scale(0.68)"',
        )
        for contract in required:
            self.assertIn(contract, visual)
        forbidden = (
            'd="M805 338V418H410V539"',
            'd="M805 338V418H250V539"',
            '<rect x="820" y="414" width="260" height="24"',
            'd="M428 615H476V878H1375V842"',
            'd="M984 518V444H470V352"',
            'd="M832 659V642H984V622"',
            '<rect x="630" y="407"',
            '<rect x="1018" y="617"',
        )
        for contract in forbidden:
            self.assertNotIn(contract, visual)
        self.assertIsNone(re.search(r'font-size="(?:[0-9]|10)"', visual))

    def test_visual_contribution_policy_prefers_light_and_forbids_redraws(self) -> None:
        policy = self.contributing.casefold()
        self.assertIn(
            "use `assets/syswarden_logo.svg` as the sole source", policy
        )
        self.assertIn("never redraw, reinterpret or replace", policy)
        self.assertIn("prefer a light theme", policy)
        self.assertIn("readme, wiki or other published visuals", policy)

    def test_plumber_terminal_check_has_the_exact_required_name(self) -> None:
        gate = job_block(self.compliance, "plumber")
        self.assertIn("    name: Plumber Compliance\n", gate)
        self.assertEqual(self.compliance.count("    name: Plumber Compliance\n"), 1)
        self.assertIn(
            "    needs: [pull-request-analysis, published-analysis]\n", gate
        )
        self.assertIn("    if: ${{ always() }}\n", gate)
        self.assertIn("    permissions: {}\n", gate)
        self.assertNotIn("actions/checkout", gate)
        self.assertNotIn("getplumber/plumber@", gate)
        self.assert_plumber_result_contract(gate)

    def test_plumber_terminal_check_rejects_broad_skip_mutations(self) -> None:
        gate = job_block(self.compliance, "plumber")
        mutations = (
            gate.replace(
                "EVENT_NAME: ${{ github.event_name }}",
                "EVENT_NAME: pull_request",
                1,
            ),
            gate.replace(
                '[[ "${PULL_REQUEST_RESULT}" == "success" ]]',
                '[[ "${PULL_REQUEST_RESULT}" != "failure" ]]',
                1,
            ),
            gate.replace(
                '[[ "${PUBLISHED_RESULT}" == "success" ]]',
                '[[ "${PUBLISHED_RESULT}" != "failure" ]]',
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssertionError):
                    self.assert_plumber_result_contract(mutation)

    def test_plumber_policy_extends_default_with_only_reviewed_overrides(self) -> None:
        expected = """extends: plumber:default
version: "2.0"

github:
  controls:
    branchMustBeProtected:
      codeOwnerApprovalRequired: true
    githubActionMustComeFromAuthorizedSources:
      minimumStars: 0
      trustedGithubActions:
        - getplumber/plumber
        - anthropics/claude-code-action
        - docker/setup-qemu-action
        - docker/setup-buildx-action
        - docker/login-action
        - docker/metadata-action
        - docker/build-push-action
        - ossf/scorecard-action
        - anchore/scan-action
        - DavidAnson/markdownlint-cli2-action
        - ruby/setup-ruby
        - gitleaks/gitleaks-action
        - golangci/golangci-lint-action
        - aquasecurity/trivy-action
"""
        self.assertEqual(self.plumber_policy, expected)
        trusted_actions = re.findall(
            r"(?m)^        - ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$",
            self.plumber_policy,
        )
        self.assertEqual(len(trusted_actions), len(set(trusted_actions)))

    def test_dependabot_covers_every_go_module_weekly_once(self) -> None:
        github_actions_entry = (
            '  - package-ecosystem: "github-actions"\n'
            '    directory: "/"\n'
            "    schedule:\n"
            '      interval: "weekly"'
        )
        self.assertEqual(self.dependabot.count(github_actions_entry), 1)
        gomod_entries = re.findall(
            r'(?m)^  - package-ecosystem: "gomod"\n'
            r'    directory: "([^"]+)"\n'
            r"    schedule:\n"
            r'      interval: "weekly"$',
            self.dependabot,
        )
        self.assertEqual(
            gomod_entries,
            [
                "/src/core/syswarden-core",
                "/src/core/syswarden-cli",
                "/src/core/syswarden-tui",
                "/scripts/versionctl",
            ],
        )
        self.assertEqual(len(gomod_entries), len(set(gomod_entries)))
        self.assertEqual(self.dependabot.count("  - package-ecosystem:"), 5)

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
