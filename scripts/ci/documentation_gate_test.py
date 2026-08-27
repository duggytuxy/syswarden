#!/usr/bin/env python3
"""Tests for the SysWarden current-documentation truth gate."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import documentation_gate
import release_gate


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_CANDIDATE_VERSION = "v4.04.0"
STABLE_PUBLIC_VERSION = "v4.03.3"
REPORT = REPO_ROOT / (
    f"docs/reports/PUBLIC_RELEASE_READINESS_REPORT_{STABLE_PUBLIC_VERSION}.md"
)
ARCHIVE_DIGEST = "a6ebcab7a81769c52147be710622995779cedf9523270cf08cf03e275501cde5"


class DocumentationGateTest(unittest.TestCase):
    def test_repository_truth_gate_passes(self) -> None:
        records, errors = documentation_gate.validate_repository(REPO_ROOT)
        self.assertEqual(errors, [])
        self.assertEqual([record.path for record in records], ["README.md"])

    def test_operational_wiki_contract_is_required_without_network_access(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        wiki_contract = contract["required_wiki_phrases"]
        self.assertEqual(
            documentation_gate.validate_wiki_phrase_contract(wiki_contract), []
        )
        changed = json.loads(json.dumps(wiki_contract))
        changed.pop("RHEL-9-Image-Extensions.md")
        errors = documentation_gate.validate_wiki_phrase_contract(changed)
        self.assertTrue(any("missing required operational wiki pages" in error for error in errors))

    def test_current_version_and_release_status_are_explicit(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        self.assertEqual(
            documentation_gate.source_version(REPO_ROOT), SOURCE_CANDIDATE_VERSION
        )
        self.assertEqual(
            documentation_gate.stable_public_version(contract), STABLE_PUBLIC_VERSION
        )
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        self.assertEqual(
            readme.splitlines().count(
                f"Current source version: **{SOURCE_CANDIDATE_VERSION}**."
            ),
            1,
        )
        self.assertIn(
            "The latest qualified, stable public release is "
            f"[{STABLE_PUBLIC_VERSION}](https://github.com/duggytuxy/syswarden/"
            f"releases/tag/{STABLE_PUBLIC_VERSION}).",
            documentation_gate.normalized(readme),
        )
        self.assertEqual(report.count("## Post-publication record"), 1)
        self.assertLess(
            report.index("## Post-publication record"),
            report.index("## Document status"),
        )
        self.assertIn(
            "The `NO-GO` decision and candidate wording retained below are the "
            "historical pre-publication contract.",
            documentation_gate.normalized(report),
        )
        self.assertIn(
            "does not authorize a tag or publication",
            documentation_gate.normalized(changelog),
        )
        self.assertIn("does not authorize a tag or public Release", report)

    def test_stable_public_version_contract_fails_closed(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        self.assertEqual(
            documentation_gate.stable_public_version(contract), STABLE_PUBLIC_VERSION
        )
        for invalid in (None, "", "4.03.3", "v4.3.3", "v4.03"):
            changed = json.loads(json.dumps(contract))
            if invalid is None:
                changed.pop("stable_public_version")
            else:
                changed["stable_public_version"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(
                documentation_gate.DocumentationGateError
            ):
                documentation_gate.stable_public_version(changed)

    def test_stable_public_version_cannot_lead_the_source_candidate(self) -> None:
        self.assertEqual(
            documentation_gate.validate_public_version_order(
                SOURCE_CANDIDATE_VERSION, STABLE_PUBLIC_VERSION
            ),
            [],
        )
        errors = documentation_gate.validate_public_version_order(
            SOURCE_CANDIDATE_VERSION, "v4.04.1"
        )
        self.assertTrue(any("cannot be newer" in error for error in errors))

    def test_readme_accepts_only_the_candidate_and_bound_stable_versions(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        readme_path = REPO_ROOT / "README.md"
        readme = readme_path.read_text(encoding="utf-8")
        common = (
            readme_path,
            readme,
            documentation_gate.cobra_commands(REPO_ROOT),
            documentation_gate.config_schema(REPO_ROOT),
            contract["forbidden_phrases"],
            SOURCE_CANDIDATE_VERSION,
            None,
        )
        errors = documentation_gate.validate_markdown(
            *common, (STABLE_PUBLIC_VERSION,)
        )
        self.assertFalse(any("non-current version" in error for error in errors))

        errors = documentation_gate.validate_markdown(*common)
        self.assertTrue(
            any(
                f"non-current version {STABLE_PUBLIC_VERSION}" in error
                for error in errors
            )
        )
        self.assertEqual(
            documentation_gate.require_phrases(
                readme,
                contract["required_readme_phrases"],
                SOURCE_CANDIDATE_VERSION,
                "README.md",
                stable_public_version_value=STABLE_PUBLIC_VERSION,
            ),
            [],
        )

    def test_v4032_release_notes_match_the_amd64_only_inventory(self) -> None:
        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        active = changelog.split("\n---\n\n# Release v4.03.1", 1)[0]
        normalized = documentation_gate.normalized(active)
        self.assertIn("three-package reproducibility", normalized)
        self.assertIn("ten-asset publisher gates", normalized)
        self.assertIn("AMD64-only package scope", active)
        self.assertIn("one amd64 DEB", normalized)
        self.assertIn("one x86_64 RPM", normalized)
        self.assertIn("one x86_64 APK", normalized)
        self.assertNotIn("six-package", normalized)
        self.assertNotIn("thirteen-asset", normalized)

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
                SOURCE_CANDIDATE_VERSION,
            ),
            [],
        )

    def test_public_release_contract_is_three_packages_and_ten_assets(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        stable_version = documentation_gate.stable_public_version(contract)
        expected_packages = release_gate.package_names(
            stable_version.removeprefix("v")
        )
        expected_assets = release_gate.expected_release_assets(stable_version)
        self.assertEqual(len(expected_packages), 3)
        self.assertEqual(len(expected_assets), 10)
        self.assertEqual(
            set(contract["public_report_contract"]["expected_assets"]),
            expected_assets,
        )
        self.assertEqual(contract["active_surface_contract"]["package_count"], 3)
        self.assertEqual(
            contract["active_surface_contract"]["public_asset_count"], 10
        )

    def test_optional_image_extension_is_active_and_bounded(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        relative = "extensions/rhel-image/README.md"
        self.assertIn(relative, contract["active_surface_contract"]["documents"])
        extension = (REPO_ROOT / relative).read_text(encoding="utf-8")
        normalized = " ".join(extension.split())
        self.assertIn("optional, additive image-builder extension", normalized)
        self.assertIn("Package scriptlets and triggers are disabled", normalized)
        self.assertIn("does not enter the root, execute a product binary", normalized)
        self.assertIn("nor establishes runtime qualification", normalized)

    def test_local_release_preflight_is_active_and_non_authorizing(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        relative = "docs/maintainers/LOCAL_RELEASE_PREFLIGHT.md"
        self.assertIn(relative, contract["active_surface_contract"]["documents"])
        procedure = (REPO_ROOT / relative).read_text(encoding="utf-8")
        self.assertTrue(procedure.isascii())
        for forbidden in ("\u2011", "\u2013", "\u2014"):
            self.assertNotIn(forbidden, procedure)
        normalized = " ".join(procedure.split())
        self.assertIn("read-only with respect to GitHub and release state", normalized)
        self.assertIn("must not create or update a remote branch, tag", normalized)
        self.assertIn(
            "Only the protected remote sequence may authorize a lot closure, tag or Release",
            normalized,
        )
        self.assertIn(
            "exactly one recognized `Patch :`, `Minor :`, `Major :` or "
            "`Upgrade :` transition",
            normalized,
        )
        self.assertIn(
            "only non-versioning follow-ups that preserve every version target "
            "and `changelog.md` byte-for-byte",
            normalized,
        )
        self.assertIn(
            "The release validator must trace that chain back to the exact transition.",
            normalized,
        )
        self.assertIn(
            "This generic chain contract validates v4.03.3 and later releases.",
            normalized,
        )
        self.assertIn(
            "Earlier immutable releases are revalidated from their published tag, "
            "asset and digest evidence, not replayed through the current release "
            "orchestrator.",
            normalized,
        )
        self.assertIn("complete mandatory pre-push gate", normalized)
        self.assertIn("tracked `.github/act/push.json` fixture is test-only", normalized)
        self.assertIn("Pass `--eventpath \"${SW_EVENT}\"` explicitly", normalized)
        self.assertIn("git clone --no-hardlinks --local", normalized)
        self.assertIn("--workflows .github/workflows/auto-versioning.yml", normalized)
        self.assertIn("--bind", normalized)
        self.assertIn("--pull=true", normalized)
        self.assertNotIn("--pull=false", normalized)
        self.assertIn("Never bind the maintainer's primary worktree", normalized)
        actrc = (REPO_ROOT / ".actrc").read_text(encoding="ascii")
        expected_act_image = (
            "catthehacker/ubuntu:act-24.04@sha256:"
            "b839c14c4410998529ec18f951262bdf87a2b23bc1467304d07b491b9455e074"
        )
        for runner_label in ("ubuntu-24.04", "ubuntu-latest"):
            self.assertEqual(
                [
                    line
                    for line in actrc.splitlines()
                    if line.startswith(f"-P {runner_label}=")
                ],
                [f"-P {runner_label}={expected_act_image}"],
            )
        self.assertNotIn("--pull=false", actrc)
        self.assertIn("Act's sandbox shortcut is not an AppArmor proof", normalized)
        self.assertIn("AppArmor host proof may be marked `REMOTE-ONLY`", normalized)
        self.assertIn(
            "If native AMD64 hardware is unavailable, do not claim complete local qualification.",
            normalized,
        )
        self.assertIn("evidence files are not byte-comparable", normalized)
        self.assertIn("Compare evidence schemas, bindings, inventories", normalized)
        self.assertIn("post-preflight action", normalized)
        self.assertIn("user-approved merge", normalized)
        actual_workflows = {
            path.name for path in (REPO_ROOT / ".github/workflows").glob("*.yml")
        }
        documented_workflows = set(re.findall(r"`([a-z0-9-]+\.yml)`", procedure))
        self.assertEqual(documented_workflows, actual_workflows)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("docs/maintainers/LOCAL_RELEASE_PREFLIGHT.md", readme)

    def test_optional_image_policy_manifest_set_is_exact_and_executable(self) -> None:
        recipes: list[str] = []
        for relative in ("extensions/rhel-image/README.md",):
            errors: list[str] = []
            blocks = documentation_gate.extract_fenced_blocks(
                (REPO_ROOT / relative).read_text(encoding="utf-8"),
                relative,
                errors,
            )
            self.assertEqual(errors, [])
            matches = [
                textwrap.dedent(body)
                for language, body in blocks
                if language == "bash"
                and "EXPECTED_POLICY_MANIFEST_SHA256" in body
            ]
            self.assertEqual(len(matches), 1, relative)
            recipe = matches[0]
            self.assertIn("declare -A EXPECTED_POLICY_SET=()", recipe)
            self.assertIn("declare -A MANIFEST_POLICY_SET=()", recipe)
            self.assertIn(
                'if (( EUID != 0 )) || [[ "${GROUPS[0]}" != 0 ]]; then',
                recipe,
            )
            self.assertNotIn("sudo ", recipe)
            self.assertNotIn("<(printf", recipe)
            recipes.append(recipe)

        marker = '\n(\n  cd "${POLICY_SOURCE}"'
        segments: list[str] = []
        for recipe in recipes:
            start = recipe.index("POLICY_FILES=()")
            end = recipe.index(marker, start)
            segments.append(recipe[start:end])
        self.assertEqual(len(segments), 1)

        expected_files = [
            "ru.ipv4",
            "ru.ipv6",
            "cn.ipv4",
            "cn.ipv6",
            "kp.ipv4",
            "kp.ipv6",
            "ir.ipv4",
            "ir.ipv6",
            "AS123.ipv4",
            "AS123.ipv6",
        ]
        with tempfile.TemporaryDirectory() as directory:
            policy_source = Path(directory)
            manifest = policy_source / "SHA256SUMS"
            prefix = "\n".join(
                (
                    "set -euo pipefail",
                    f"POLICY_SOURCE={shlex.quote(str(policy_source))}",
                    "COUNTRY_CODES=(ru cn kp ir)",
                    "APPROVED_ASNS=(AS123)",
                    "",
                )
            )

            def run_with_manifest(files: list[str]) -> subprocess.CompletedProcess[str]:
                manifest.write_text(
                    "".join(f"{'0' * 64}  {name}\n" for name in files),
                    encoding="ascii",
                )
                return subprocess.run(
                    ["bash", "-c", prefix + segments[0]],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            self.assertEqual(run_with_manifest(expected_files).returncode, 0)
            self.assertNotEqual(run_with_manifest(expected_files[:-1]).returncode, 0)
            self.assertNotEqual(
                run_with_manifest(expected_files + ["extra.ipv4"]).returncode,
                0,
            )
            self.assertNotEqual(
                run_with_manifest(expected_files + [expected_files[0]]).returncode,
                0,
            )

    def test_optional_image_privileged_fences_guard_their_own_root(self) -> None:
        checked = 0
        stage_command = (
            "sudo extensions/rhel-image/stage-syswarden-rhel-image.sh"
        )
        for relative in ("extensions/rhel-image/README.md",):
            errors: list[str] = []
            blocks = documentation_gate.extract_fenced_blocks(
                (REPO_ROOT / relative).read_text(encoding="utf-8"),
                relative,
                errors,
            )
            self.assertEqual(errors, [])
            for language, body in blocks:
                if (
                    language != "bash"
                    or '${IMAGE_ROOT}' not in body
                    or "sudo " not in body
                ):
                    continue
                checked += 1
                recipe = textwrap.dedent(body)
                self.assertTrue(
                    recipe.startswith("set -euo pipefail\n"),
                    relative,
                )
                self.assertIn("IMAGE_ROOT=/srv/image-root\n", recipe, relative)
                self.assertIn(stage_command, recipe, relative)
                self.assertEqual(
                    recipe.index("sudo "),
                    recipe.index(stage_command),
                    relative,
                )
        self.assertGreaterEqual(checked, 3)

    def test_optional_image_configuration_publication_is_exact(self) -> None:
        recipes: list[str] = []
        for relative in ("extensions/rhel-image/README.md",):
            errors: list[str] = []
            blocks = documentation_gate.extract_fenced_blocks(
                (REPO_ROOT / relative).read_text(encoding="utf-8"),
                relative,
                errors,
            )
            self.assertEqual(errors, [])
            matches = [
                textwrap.dedent(body)
                for language, body in blocks
                if language == "bash"
                and 'CONFIG_STAGE="${IMAGE_ROOT}' in body
            ]
            self.assertEqual(len(matches), 1, relative)
            recipe = matches[0]
            self.assertTrue(recipe.startswith("set -euo pipefail\numask 077\n"))
            self.assertIn(
                'if (( EUID != 0 )) || [[ "${GROUPS[0]}" != 0 ]]; then',
                recipe,
            )
            self.assertIn(
                "CONFIG_FILES=(config.toml modules/00-core.toml modules/10-network.toml)",
                recipe,
            )
            self.assertNotIn("sudo ", recipe)
            for command in (
                "/usr/bin/install",
                "/usr/bin/cmp",
                "/usr/bin/mv",
                "/usr/bin/stat",
            ):
                self.assertIn(command, recipe)
            recipes.append(recipe)
        self.assertEqual(len(recipes), 1)

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
            SOURCE_CANDIDATE_VERSION,
        )
        self.assertTrue(any("exact release gate" in error for error in errors))

    def test_stable_version_mutation_breaks_report_assets_and_matrix(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        changed = json.loads(json.dumps(contract))
        changed["stable_public_version"] = SOURCE_CANDIDATE_VERSION
        errors = documentation_gate.validate_active_public_surfaces(
            REPO_ROOT,
            changed,
            documentation_gate.cobra_commands(REPO_ROOT),
            documentation_gate.config_schema(REPO_ROOT),
            changed["forbidden_phrases"],
            SOURCE_CANDIDATE_VERSION,
        )
        self.assertTrue(
            any("report path is not bound" in error for error in errors), errors
        )
        self.assertTrue(any("exact release gate" in error for error in errors), errors)

        matrix_errors = documentation_gate.validate_package_source_contract(
            REPO_ROOT,
            changed["package_platform_contract"],
            SOURCE_CANDIDATE_VERSION,
        )
        self.assertTrue(
            any("package table contract" in error for error in matrix_errors),
            matrix_errors,
        )

    def test_package_contract_matches_workflow_and_wiki_contract(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        package_contract = contract["package_platform_contract"]
        self.assertEqual(
            documentation_gate.validate_package_source_contract(
                REPO_ROOT, package_contract, STABLE_PUBLIC_VERSION
            ),
            [],
        )
        self.assertEqual(
            set(package_contract["inventory_phrases"]),
            {"wiki/Deployment-Tutorial.md"},
        )
        self.assertEqual(
            set(package_contract["tables"]),
            {"wiki/Deployment-Tutorial.md"},
        )
        self.assertEqual(len(package_contract["artifacts"]), 3)
        self.assertEqual(
            {entry["family"] for entry in package_contract["artifacts"]},
            {"DEB", "RPM", "APK"},
        )

    def test_package_count_and_architecture_mutations_are_rejected(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        package_contract = contract["package_platform_contract"]
        label = "wiki/Deployment-Tutorial.md"
        documented_count = package_contract["inventory_phrases"][label]
        wrong_count = documented_count.replace("one DEB, one RPM", "nine DEB, one RPM")
        self.assertNotEqual(wrong_count, documented_count)
        errors = documentation_gate.validate_package_documentation(
            wrong_count, label, package_contract
        )
        self.assertTrue(any("artifact count statement changed" in error for error in errors))

        changed = json.loads(json.dumps(package_contract))
        changed["artifacts"][0]["architecture"] = "s390x"
        errors = documentation_gate.validate_package_source_contract(
            REPO_ROOT, changed, STABLE_PUBLIC_VERSION
        )
        self.assertTrue(any("naming/architecture mismatch" in error for error in errors))

    def test_native_tui_and_retired_current_surface_gate(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        normalized_readme = documentation_gate.normalized(readme)
        normalized_report = documentation_gate.normalized(report)
        self.assertIn(
            "Native local terminal dashboard with no browser service or listening port.",
            normalized_readme,
        )
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
                SOURCE_CANDIDATE_VERSION,
            )
        self.assertTrue(any("retired platform" in error for error in errors))

    def test_ha_partner_contract_is_unambiguous(self) -> None:
        report = REPORT.read_text(encoding="utf-8")
        for text in (report,):
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
        contract = documentation_gate.load_contract(REPO_ROOT)
        wiki_contract = documentation_gate.normalized(
            "\n".join(
                contract["required_wiki_phrases"]["BunkerWeb-Integration.md"]
            )
        )
        for phrase in (
            "X-SysWarden-HA-Fence-Condition",
            "active_drained",
            "opaque, case-sensitive strings",
            "does not recalculate",
            "HTTP 428",
            "HTTP 400",
            "HTTP 412",
            "one-hour",
            "It is never proof of drain",
        ):
            self.assertIn(phrase, wiki_contract)

    def test_ha_delete_semantics_are_explicit(self) -> None:
        report = REPORT.read_text(encoding="utf-8")
        for text in (report,):
            self.assertIn('DELETE {"bans": [...]}` removes provenance ledger entries only', text)
            self.assertIn('DELETE {"ips": [...]}`', text)
            self.assertIn("durable", text)
            self.assertIn("ownership is never inferred", text.casefold())
        contract = documentation_gate.load_contract(REPO_ROOT)
        wiki_contract = documentation_gate.normalized(
            "\n".join(
                contract["required_wiki_phrases"]["BunkerWeb-Integration.md"]
            )
        ).format()
        self.assertIn('DELETE {"bans": [...]}', wiki_contract)
        self.assertIn('DELETE {"ips": [...]}', wiki_contract)

    def test_config_saas_and_persistent_list_contract_is_source_bound(self) -> None:
        report = documentation_gate.normalized(REPORT.read_text(encoding="utf-8"))
        manual = documentation_gate.normalized(
            (REPO_ROOT / "src/core/syswarden-cli/cmd/manual.go").read_text(
                encoding="utf-8"
            )
        )
        for text in (report,):
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
        deployment_contract = documentation_gate.normalized(
            "\n".join(
                contract["required_wiki_phrases"]["Deployment-Tutorial.md"]
            )
        )
        for phrase in (
            "schema_version = 1",
            "historical input",
            "config validate",
            "unknown and deprecated",
            "config migrate --dry-run",
            "zero source or destination writes",
            "network.saas.allow_monitors",
            "integrations.saas.enabled",
            "lock-coordinated atomic pair",
            "--port",
            "effective SSH port",
            "fails closed",
            "revalidates the file identity and type after every rotation",
            "parent directory protected against untrusted replacement",
            "destination grammars",
            "SSH/HA port separation",
        ):
            self.assertIn(phrase, deployment_contract)
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

    def test_migration_and_rhel_wiki_boundaries_are_explicit(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        wiki = contract["required_wiki_phrases"]
        migration = documentation_gate.normalized(
            "\n".join(wiki["Migration-v4.02.8-to-v4.03.2.md"])
        )
        for phrase in (
            "historical v4.02.8 binary predates the signed updater protocol",
            "checksum-verified Linux package",
            "Back up `/etc/syswarden`",
            "verified local console or SSH recovery access",
            "SysWarden package rollback is an explicit package and configuration recovery procedure, not a general host-state reversal.",
        ):
            self.assertIn(phrase, migration)

        current_migration = documentation_gate.normalized(
            "\n".join(wiki["Migration-v4.03.2-to-v4.03.3.md"])
        )
        for phrase in (
            "pending manual release-owner gate",
            "deterministic local TLS fixture",
            "four interval sets",
            "discard ambiguous legacy intervals",
            "unsafe while any ban producer is active",
            "no qualified in-place package downgrade",
            "Uninstall is destructive removal, not rollback.",
        ):
            self.assertIn(phrase, current_migration)

        rhel = documentation_gate.normalized(
            "\n".join(wiki["RHEL-9-Image-Extensions.md"])
        )
        self.assertIn("only currently available RHEL 9+ image extension", rhel)
        self.assertIn(
            "runtime-only, package-owned system-integration extension is not available",
            rhel,
        )
        self.assertIn("Go binaries runtime-only", rhel)
        self.assertIn("RPM owns firewall and systemd configuration", rhel)

    def test_cli_command_inventory_and_exact_add_remove_approvals(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        self.assertEqual(len(commands), 23)
        self.assertIn("ha-fence", commands)
        self.assertIn("tui", commands)

        contract = documentation_gate.load_contract(REPO_ROOT)
        self.assertEqual(
            documentation_gate.validate_wiki_phrase_contract(
                contract["required_wiki_phrases"]
            ),
            [],
        )
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
            if name == "syswarden_hero.svg":
                self.assertIn(f'assets/{name}', readme)
            else:
                self.assertNotIn(f'assets/{name}', readme)
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
                self.assertIn(
                    f"SysWarden {SOURCE_CANDIDATE_VERSION} candidate architecture",
                    text,
                )

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
                "v4.03.2",
                None,
            )
        self.assertTrue(any("unclosed Markdown fence" in error for error in errors))
        self.assertTrue(any("missing local link target" in error for error in errors))

    def test_versioned_wiki_page_link_resolves_without_md_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wiki_root = Path(directory)
            source = wiki_root / "Home.md"
            target = wiki_root / "Migration-v4.02.8-to-v4.03.2.md"
            source.write_text(
                "# Home\n\n[Migration](Migration-v4.02.8-to-v4.03.2)\n",
                encoding="utf-8",
            )
            target.write_text("# Migration\n", encoding="utf-8")
            resolved = documentation_gate.resolve_local_target(
                source,
                "Migration-v4.02.8-to-v4.03.2",
                wiki_root,
            )
        self.assertEqual(resolved, target)

    def test_version_specific_wiki_page_keeps_its_canonical_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wiki_root = Path(directory)
            (wiki_root / "Home.md").write_text(
                "# Home\n\n"
                "> Status: Current\n"
                "> Documentation baseline: v4.03.3\n\n"
                "[Historical migration](Migration-v4.02.8-to-v4.03.2)\n"
                "[Version-specific current migration](Migration-v4.03.2-to-v4.03.3)\n",
                encoding="utf-8",
            )
            (wiki_root / "Migration-v4.02.8-to-v4.03.2.md").write_text(
                "# Historical migration from v4.02.8 to v4.03.2\n\n"
                "> Status: Version-specific\n"
                "> Documentation baseline: v4.03.2\n",
                encoding="utf-8",
            )
            (wiki_root / "Migration-v4.03.2-to-v4.03.3.md").write_text(
                "# Migration from v4.03.2 to v4.03.3\n\n"
                "> Status: Version-specific\n"
                "> Documentation baseline: v4.03.3\n",
                encoding="utf-8",
            )
            errors = documentation_gate.validate_wiki(
                wiki_root,
                documentation_gate.inventory(wiki_root, "test wiki"),
                set(),
                set(),
                [],
                "v4.03.3",
                {},
            )
        self.assertEqual(errors, [])

    def test_current_wiki_page_rejects_a_stale_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wiki_root = Path(directory)
            (wiki_root / "Home.md").write_text(
                "# Home\n\n"
                "> Status: Current\n"
                "> Documentation baseline: v4.03.2\n",
                encoding="utf-8",
            )
            errors = documentation_gate.validate_wiki(
                wiki_root,
                documentation_gate.inventory(wiki_root, "test wiki"),
                set(),
                set(),
                [],
                "v4.03.3",
                {},
            )
        self.assertTrue(
            any(
                "current page baseline v4.03.2 does not match v4.03.3" in error
                for error in errors
            )
        )

    def test_current_wiki_remains_bound_to_the_stable_public_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wiki_root = Path(directory)
            (wiki_root / "Home.md").write_text(
                "# Home\n\n"
                "> Status: Current\n"
                f"> Documentation baseline: {SOURCE_CANDIDATE_VERSION}\n",
                encoding="utf-8",
            )
            errors = documentation_gate.validate_wiki(
                wiki_root,
                documentation_gate.inventory(wiki_root, "test wiki"),
                set(),
                set(),
                [],
                STABLE_PUBLIC_VERSION,
                {},
            )
        self.assertTrue(
            any(
                f"current page baseline {SOURCE_CANDIDATE_VERSION} does not match "
                f"{STABLE_PUBLIC_VERSION}" in error
                for error in errors
            ),
            errors,
        )

    def test_version_specific_page_allows_only_versions_declared_in_heading(self) -> None:
        text = (
            "# Migration from v4.03.2 to v4.03.3\n\n"
            "> Status: Version-specific\n"
            "> Documentation baseline: v4.03.3\n\n"
            "The v4.03.2 source is in scope. v4.03.1 is not declared.\n"
        )
        errors = documentation_gate.validate_markdown(
            Path("Migration-v4.03.2-to-v4.03.3.md"),
            text,
            set(),
            set(),
            [],
            "v4.03.3",
            None,
        )
        self.assertFalse(any("non-current version v4.03.2" in error for error in errors))
        self.assertTrue(any("non-current version v4.03.1" in error for error in errors))

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
