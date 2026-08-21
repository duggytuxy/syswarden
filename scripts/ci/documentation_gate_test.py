#!/usr/bin/env python3
"""Tests for the SysWarden current-documentation truth gate."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import documentation_gate
import release_gate


REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "docs/reports/PUBLIC_RELEASE_READINESS_REPORT_v4.03.1.md"
ARCHIVE_DIGEST = "a6ebcab7a81769c52147be710622995779cedf9523270cf08cf03e275501cde5"


class DocumentationGateTest(unittest.TestCase):
    def test_repository_truth_gate_passes(self) -> None:
        records, errors = documentation_gate.validate_repository(REPO_ROOT)
        self.assertEqual(errors, [])
        self.assertEqual([record.path for record in records], ["README.md"])

    def test_current_version_and_candidate_status_are_explicit(self) -> None:
        self.assertEqual(documentation_gate.source_version(REPO_ROOT), "v4.03.1")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        self.assertIn("Current source version: **v4.03.1**.", readme)
        self.assertIn("does not claim that v4.03.1 is qualified", readme)
        self.assertIn(
            "does not authorize a tag or publication",
            documentation_gate.normalized(changelog),
        )
        self.assertIn("does not authorize a tag or public Release", report)

    def test_sealed_changelog_reset_pointer_is_exact(self) -> None:
        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        pointer = f"Archived pre-v4.03.0 changelog SHA-256: {ARCHIVE_DIGEST}"
        self.assertTrue(changelog.endswith("\n---\n" + pointer + "\n"))
        self.assertEqual(changelog.count(pointer), 1)
        self.assertEqual(changelog.count("\n---\n" + pointer + "\n"), 1)

    def test_current_public_report_inventory_is_exact(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        surface = contract["active_surface_contract"]
        report_contract = contract["public_report_contract"]
        report_directory = REPO_ROOT / surface["report_directory"]
        actual = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in report_directory.iterdir()
            if path.is_file()
        )
        self.assertEqual(actual, [report_contract["path"]])
        self.assertEqual(
            documentation_gate.validate_active_public_surfaces(
                REPO_ROOT,
                contract,
                documentation_gate.cobra_commands(REPO_ROOT),
                documentation_gate.config_schema(REPO_ROOT),
                contract["forbidden_phrases"],
                "v4.03.1",
            ),
            [],
        )

    def test_public_release_contract_is_six_packages_and_thirteen_assets(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        expected_packages = release_gate.package_names("4.03.1")
        expected_assets = release_gate.expected_release_assets("v4.03.1")
        self.assertEqual(len(expected_packages), 6)
        self.assertEqual(len(expected_assets), 13)
        self.assertEqual(
            set(contract["public_report_contract"]["expected_assets"]),
            expected_assets,
        )
        self.assertEqual(contract["active_surface_contract"]["package_count"], 6)
        self.assertEqual(
            contract["active_surface_contract"]["public_asset_count"], 13
        )

    def test_report_numbered_asset_inventory_matches_release_gate_order(self) -> None:
        report = REPORT.read_text(encoding="utf-8")
        section = report.split("## Exact public release inventory\n", 1)[1].split(
            "\n## ", 1
        )[0]
        listed = []
        for line in section.splitlines():
            if line[:1].isdigit() and "`" in line:
                listed.append(line.split("`", 2)[1])
        contract = documentation_gate.load_contract(REPO_ROOT)
        self.assertEqual(listed, contract["public_report_contract"]["expected_assets"])

    def test_report_asset_mutation_fails_closed(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        changed = json.loads(json.dumps(contract))
        changed["public_report_contract"]["expected_assets"][0] = "unexpected.deb"
        errors = documentation_gate.validate_active_public_surfaces(
            REPO_ROOT,
            changed,
            documentation_gate.cobra_commands(REPO_ROOT),
            documentation_gate.config_schema(REPO_ROOT),
            changed["forbidden_phrases"],
            "v4.03.1",
        )
        self.assertTrue(any("exact release gate" in error for error in errors))

    def test_package_contract_matches_workflow_and_readme(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        package_contract = contract["package_platform_contract"]
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            documentation_gate.validate_package_source_contract(
                REPO_ROOT, package_contract
            ),
            [],
        )
        self.assertEqual(
            documentation_gate.validate_package_documentation(
                readme, "README.md", package_contract
            ),
            [],
        )
        self.assertEqual(len(package_contract["artifacts"]), 6)
        self.assertEqual(
            {entry["family"] for entry in package_contract["artifacts"]},
            {"DEB", "RPM", "APK"},
        )

    def test_package_count_and_architecture_mutations_are_rejected(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        package_contract = contract["package_platform_contract"]
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        wrong_count = readme.replace("two DEB, two RPM", "nine DEB, two RPM")
        errors = documentation_gate.validate_package_documentation(
            wrong_count, "README.md", package_contract
        )
        self.assertTrue(any("artifact count statement changed" in error for error in errors))

        changed = json.loads(json.dumps(package_contract))
        changed["artifacts"][0]["architecture"] = "s390x"
        errors = documentation_gate.validate_package_source_contract(REPO_ROOT, changed)
        self.assertTrue(any("naming/architecture mismatch" in error for error in errors))

    def test_native_tui_and_retired_current_surface_gate(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        normalized_readme = documentation_gate.normalized(readme)
        normalized_report = documentation_gate.normalized(report)
        self.assertIn(
            "runs inside the invoking terminal and opens no listening socket",
            normalized_readme,
        )
        self.assertIn("SysWarden owns no listener", readme)
        self.assertIn("native local TUI", normalized_report)

        contract = documentation_gate.load_contract(REPO_ROOT)
        with mock.patch.object(
            documentation_gate,
            "CURRENT_SURFACE_RETIRED_TERMS",
            ("linux host",),
        ):
            errors = documentation_gate.validate_active_public_surfaces(
                REPO_ROOT,
                contract,
                documentation_gate.cobra_commands(REPO_ROOT),
                documentation_gate.config_schema(REPO_ROOT),
                contract["forbidden_phrases"],
                "v4.03.1",
            )
        self.assertTrue(any("retired platform" in error for error in errors))

    def test_ha_partner_contract_is_unambiguous(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        for text in (readme, report):
            text = documentation_gate.normalized(text)
            self.assertIn("X-SysWarden-HA-Fence-Condition", text)
            self.assertIn("active_drained", text)
            self.assertIn("membership_sha256", text)
            self.assertIn("legacy_writer_inventory_sha256", text)
            self.assertIn("opaque, case-sensitive strings", text)
            self.assertIn("does not recalculate", text)
            self.assertIn("HTTP 428", text)
            self.assertIn("HTTP 400", text)
            self.assertIn("HTTP 412", text)
            self.assertIn("one-hour", text)
            self.assertIn("It is never proof of drain", text)

    def test_ha_delete_semantics_are_explicit(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        for text in (readme, report):
            self.assertIn('DELETE {"bans": [...]}` removes provenance ledger entries only', text)
            self.assertIn('DELETE {"ips": [...]}`', text)
            self.assertIn("durable", text)
            self.assertIn("ownership is never inferred", text.casefold())

    def test_config_saas_and_persistent_list_contract_is_source_bound(self) -> None:
        readme = documentation_gate.normalized(
            (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        )
        report = documentation_gate.normalized(REPORT.read_text(encoding="utf-8"))
        manual = documentation_gate.normalized(
            (REPO_ROOT / "src/core/syswarden-cli/cmd/manual.go").read_text(
                encoding="utf-8"
            )
        )
        for text in (readme, report):
            self.assertIn("schema_version = 1", text)
            self.assertIn("historical input", text)
            self.assertIn("config validate", text)
            self.assertIn("unknown and deprecated", text)
            self.assertIn("config migrate --dry-run", text)
            self.assertIn("zero source or destination writes", text)
            self.assertIn("network.saas.allow_monitors", text)
            self.assertIn("integrations.saas.enabled", text)
            self.assertIn("lock-coordinated atomic pair", text)
            self.assertIn("whitelist", text)
            self.assertIn("--port", text)
            self.assertIn("effective SSH port", text)
            self.assertIn("fails closed", text)
            self.assertIn("revalidates the file identity and type after every rotation", text)
            self.assertIn("parent directory protected against untrusted replacement", text)
            self.assertIn("destination grammars", text)
            self.assertIn("SSH/HA port separation", text)
        for phrase in (
            "schema_version = 1",
            "config validate --path /etc/syswarden/config is read-only",
            "config migrate --dry-run performs zero source or destination writes",
            "network.saas.allow_monitors",
            "required-feed failure retains the previous atomic IPv4/IPv6 pair",
            "whitelist --port scopes the entry to one TCP service",
            "effective SSH port",
            "revalidates exact regular files without following links on every rotation",
            "protect parent directories because rsyslog reopens names itself",
            "destination grammars",
            "configured HA peer port must differ from the configured SSH port",
        ):
            self.assertIn(phrase, manual)

        contract = documentation_gate.load_contract(REPO_ROOT)
        source_assertion_ids = {
            assertion["id"] for assertion in contract["source_assertions"]
        }
        self.assertTrue(
            {
                "cli-config-schema-v1",
                "core-config-schema-v1",
                "config-validate-read-only",
                "config-dry-run-recovery-guard",
                "config-deprecated-saas-alias",
                "saas-official-precedence",
                "saas-disabled-fallback",
                "saas-feed-bounds",
                "saas-https-only",
                "saas-atomic-pair-publication",
                "canonical-persistent-list-parser",
                "ssh-bypass-effective-port",
                "rsyslog-verified-exact-log-match",
                "core-waap-real-regular-log",
                "wireguard-context-validation",
                "cli-ha-ssh-wireguard-port-collision",
                "core-ha-ssh-wireguard-port-collision",
            }.issubset(source_assertion_ids)
        )

    def test_cli_command_inventory_and_exact_add_remove_approvals(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        self.assertEqual(len(commands), 23)
        self.assertIn("ha-fence", commands)
        self.assertIn("tui", commands)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            documentation_gate.validate_command_inventory(
                readme, "Operator commands", commands, "README.md"
            ),
            [],
        )

        contract = documentation_gate.load_contract(REPO_ROOT)
        command_approvals = {
            item["path"]: (item["before"], item["after"])
            for item in contract["approved_cli_public_differences"]
            if item["field"] == "command"
        }
        retired_prefix = "web" + "-"
        self.assertEqual(
            command_approvals["syswarden " + retired_prefix + "token"],
            ("present", None),
        )
        self.assertEqual(
            command_approvals["syswarden " + retired_prefix + "tui"],
            ("present", None),
        )
        for path in (
            "syswarden ha-fence",
            "syswarden ha-fence manifest",
            "syswarden ha-fence manifest create",
            "syswarden ha-fence manifest verify",
            "syswarden ha-fence engage",
            "syswarden ha-fence recover",
            "syswarden ha-fence status",
            "syswarden ha-fence release",
            "syswarden config validate",
            "syswarden config migrate",
        ):
            self.assertEqual(command_approvals[path], (None, "added"))

    def test_cli_public_differences_match_exact_approvals(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        baseline = documentation_gate.baseline_snapshot_command_records(
            REPO_ROOT, contract["cli_baseline"]["version"]
        )
        candidate = documentation_gate.snapshot_command_records(REPO_ROOT)
        actual = {
            (item["path"], item["field"]): (item["before"], item["after"])
            for item in documentation_gate.cli_public_differences(baseline, candidate)
        }
        approved = {
            (item["path"], item["field"]): (item["before"], item["after"])
            for item in contract["approved_cli_public_differences"]
        }
        self.assertEqual(actual, approved)

    def test_manual_inventory_is_top_level_product_commands(self) -> None:
        manual = (REPO_ROOT / "src/core/syswarden-cli/cmd/manual.go").read_text(
            encoding="utf-8"
        )
        manual_commands = set(documentation_gate.MANUAL_COMMAND_RE.findall(manual))
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        self.assertEqual(manual_commands, commands)
        self.assertEqual(len(commands), 23)
        self.assertIn("ha-fence", manual_commands)
        self.assertIn("tui", manual_commands)

    def test_svg_assets_are_safe_self_contained_and_current(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for name in ("syswarden_hero.svg", "syswarden_architecture.svg"):
            path = REPO_ROOT / "assets" / name
            text = path.read_text(encoding="utf-8")
            root = ET.fromstring(text)
            self.assertEqual(root.tag.rsplit("}", 1)[-1], "svg")
            self.assertIn(f'assets/{name}', readme)
            for element in root.iter():
                self.assertNotIn(
                    element.tag.rsplit("}", 1)[-1].casefold(),
                    {"script", "foreignobject"},
                )
                for attribute, value in element.attrib.items():
                    if attribute.rsplit("}", 1)[-1].casefold() in {"href", "src"}:
                        self.assertNotIn(":", value)
            self.assertIn("Linux", text)
            if name == "syswarden_architecture.svg":
                self.assertIn("SysWarden v4.03.1 candidate architecture", text)

    def test_source_assertions_remain_bound_to_runtime(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        self.assertEqual(
            documentation_gate.validate_source_assertions(REPO_ROOT, contract), []
        )
        changed = json.loads(json.dumps(contract))
        changed["source_assertions"][0]["literal"] = "deliberately absent"
        errors = documentation_gate.validate_source_assertions(REPO_ROOT, changed)
        self.assertTrue(any("changed" in error for error in errors))

    def test_unclosed_fence_and_missing_link_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Bad.md"
            text = "# Bad\n\n[missing](missing.md)\n\n```text\nnot closed\n"
            path.write_text(text, encoding="utf-8")
            errors = documentation_gate.validate_markdown(
                path,
                text,
                documentation_gate.cobra_commands(REPO_ROOT),
                documentation_gate.config_schema(REPO_ROOT),
                [],
                "v4.03.1",
                None,
            )
        self.assertTrue(any("unclosed Markdown fence" in error for error in errors))
        self.assertTrue(any("missing local link target" in error for error in errors))

    def test_report_writer_is_machine_readable_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            documentation_gate.write_json_report(
                report_path,
                REPO_ROOT,
                None,
                [],
                ["deliberate failure"],
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["errors"], ["deliberate failure"])

    def test_private_archive_digest_matches_recorded_source(self) -> None:
        archive = (
            REPO_ROOT
            / "output/private-retired-evidence/v4.02.9-v4.02.14/changelog-pre-v4.03.0.md"
        )
        if not archive.is_file():
            self.skipTest("private retirement archive is intentionally outside CI")
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), ARCHIVE_DIGEST)
        manifest = archive.parent / "SHA256SUMS.txt"
        self.assertIn(
            ARCHIVE_DIGEST + "  changelog-pre-v4.03.0.md",
            manifest.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
