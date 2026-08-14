#!/usr/bin/env python3
"""Tests for the SysWarden documentation truth gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import documentation_gate


REPO_ROOT = Path(__file__).resolve().parents[2]


class DocumentationGateTest(unittest.TestCase):
    def test_repository_documentation_contract(self) -> None:
        records, errors = documentation_gate.validate_repository(REPO_ROOT)
        self.assertEqual(errors, [])
        self.assertEqual([record.path for record in records], ["README.md"])

    def test_readme_code_mismatch_is_rejected(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        version = documentation_gate.source_version(REPO_ROOT)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        changed = readme.replace("0.0.0.0:62027", "127.0.0.1:62027")
        errors = documentation_gate.require_phrases(
            changed,
            contract["required_readme_phrases"],
            version,
            "README.md",
        )
        self.assertTrue(any("default bind" in error for error in errors))

    def test_unknown_command_and_config_key_are_rejected(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        keys = documentation_gate.config_schema(REPO_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Bad.md"
            text = """# Bad example

```bash
sudo syswarden enroll
```

```toml
[core]
invented_key = true
```
"""
            path.write_text(text, encoding="utf-8")
            errors = documentation_gate.validate_markdown(
                path,
                text,
                commands,
                keys,
                [],
                documentation_gate.source_version(REPO_ROOT),
                None,
            )
        self.assertTrue(any("unknown syswarden command: enroll" in error for error in errors))
        self.assertTrue(any("core.invented_key" in error for error in errors))

    def test_cobra_claims_and_non_english_examples_are_rejected(self) -> None:
        records = [
            {
                "path": "syswarden audit",
                "use": "audit",
                "short": "Performs a full Enterprise SYSWARDEN Audit",
                "long": "",
                "example": "syswarden audit # Vérifiez the host",
            }
        ]
        errors = documentation_gate.validate_cobra_public_texts(
            records,
            ["full Enterprise SYSWARDEN Audit"],
        )
        self.assertTrue(any("prohibited unsupported phrase" in error for error in errors))
        self.assertTrue(any("must be written in English" in error for error in errors))

    def test_cobra_use_must_match_the_snapshot_path(self) -> None:
        records = [
            {
                "path": "syswarden audit",
                "use": "check <IP>",
                "short": "Run a local diagnostic",
                "long": "",
                "example": "",
            }
        ]
        errors = documentation_gate.validate_cobra_public_texts(records, [])
        self.assertTrue(any("does not match path" in error for error in errors))

    def test_snapshot_exposes_every_public_cobra_text_field(self) -> None:
        records = documentation_gate.snapshot_command_records(REPO_ROOT)
        self.assertGreaterEqual(len(records), 20)
        for record in records:
            self.assertEqual(
                set(record),
                {"path", "use", "short", "long", "example", "flags", "arg_outcomes"},
            )

    def test_cli_public_differences_require_exact_reviewed_approvals(self) -> None:
        version = documentation_gate.source_version(REPO_ROOT)
        baseline = documentation_gate.baseline_snapshot_command_records(
            REPO_ROOT,
            documentation_gate.load_contract(REPO_ROOT)["cli_baseline"]["version"],
        )
        candidate = documentation_gate.snapshot_command_records(REPO_ROOT)
        changes = documentation_gate.cli_public_differences(baseline, candidate)
        self.assertGreater(len(changes), 0)
        self.assertIn(
            ("syswarden", "long"),
            {(change["path"], change["field"]) for change in changes},
        )

        mutated = json.loads(json.dumps(candidate))
        mutated[0]["short"] = "Unreviewed public claim"
        changed = documentation_gate.cli_public_differences(baseline, mutated)
        self.assertIn(
            ("syswarden", "short"),
            {(change["path"], change["field"]) for change in changed},
        )

    def test_cli_baseline_is_bound_to_version_commit_and_digest(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        version = documentation_gate.source_version(REPO_ROOT)
        self.assertEqual(
            documentation_gate.validate_cli_baseline_metadata(
                REPO_ROOT, contract, version
            ),
            [],
        )
        changed = json.loads(json.dumps(contract))
        changed["cli_baseline"]["sha256"] = "0" * 64
        errors = documentation_gate.validate_cli_baseline_metadata(
            REPO_ROOT, changed, version
        )
        self.assertTrue(any("baseline digest changed" in error for error in errors))
        changed = json.loads(json.dumps(contract))
        changed["cli_baseline"]["source_archive_sha256"] = "0" * 64
        errors = documentation_gate.validate_cli_baseline_metadata(
            REPO_ROOT, changed, version
        )
        self.assertTrue(
            any("baseline source archive changed" in error for error in errors)
        )

    def test_cli_baseline_source_inventory_comes_from_the_baseline_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            snapshot = repository / "testdata/contracts/cli-command-tree-v1.00.0.json"
            baseline_source = (
                repository / "src/core/syswarden-cli/cmd/baseline_only.go"
            )
            snapshot.parent.mkdir(parents=True)
            baseline_source.parent.mkdir(parents=True)
            snapshot.write_text("frozen baseline\n", encoding="utf-8")
            baseline_source.write_text("package cmd\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(
                ["git", "-C", repository, "add", "."], check=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "-c",
                    "user.name=SysWarden Tests",
                    "-c",
                    "user.email=syswarden-tests@example.invalid",
                    "commit",
                    "-qm",
                    "baseline",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", repository, "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            archive = subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "archive",
                    "--format=tar",
                    commit,
                    "src/core/syswarden-cli/cmd/baseline_only.go",
                ],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            contract = {
                "cli_baseline": {
                    "version": "v1.00.0",
                    "commit": commit,
                    "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                    "source_archive_sha256": hashlib.sha256(archive).hexdigest(),
                }
            }

            baseline_source.unlink()
            (baseline_source.parent / "candidate_only.go").write_text(
                "package cmd\n", encoding="utf-8"
            )

            self.assertEqual(
                documentation_gate.validate_cli_baseline_metadata(
                    repository, contract, "v9.99.9"
                ),
                [],
            )

    def test_cli_baseline_rejects_a_commit_without_production_command_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            snapshot = repository / "testdata/contracts/cli-command-tree-v1.00.0.json"
            test_source = repository / "src/core/syswarden-cli/cmd/root_test.go"
            snapshot.parent.mkdir(parents=True)
            test_source.parent.mkdir(parents=True)
            snapshot.write_text("frozen baseline\n", encoding="utf-8")
            test_source.write_text("package cmd\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "-c",
                    "user.name=SysWarden Tests",
                    "-c",
                    "user.email=syswarden-tests@example.invalid",
                    "commit",
                    "-qm",
                    "test-only baseline",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", repository, "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            contract = {
                "cli_baseline": {
                    "version": "v1.00.0",
                    "commit": commit,
                    "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                    "source_archive_sha256": "0" * 64,
                }
            }

            errors = documentation_gate.validate_cli_baseline_metadata(
                repository, contract, "v9.99.9"
            )

        self.assertEqual(errors, ["CLI baseline source inventory is empty"])

    def test_web_token_first_use_side_effects_are_public(self) -> None:
        record = next(
            item
            for item in documentation_gate.snapshot_command_records(REPO_ROOT)
            if item["path"] == "syswarden web-token"
        )
        self.assertIn(
            "without --rotate generates and persists one, then attempts to restart",
            record["long"],
        )
        rotate = next(flag for flag in record["flags"] if flag["name"] == "rotate")
        self.assertEqual(
            rotate["usage"],
            "Persist a replacement token and request a Web-TUI service restart",
        )
        self.assertNotIn("invalidate", rotate["usage"])
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        manual = (
            REPO_ROOT / "src/core/syswarden-cli/cmd/manual.go"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "If no token is configured, `syswarden web-token` generates and persists one",
            readme,
        )
        self.assertIn(
            "running Web-TUI process may continue accepting the previous", readme
        )
        self.assertIn(
            "failure can leave the running Web-TUI on its previous token",
            manual,
        )

    def test_cli_approval_values_are_exact_not_key_only(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        approvals = contract["approved_cli_public_differences"]
        root_long = next(
            item
            for item in approvals
            if item["path"] == "syswarden" and item["field"] == "long"
        )
        self.assertIn("not an inline WAF", root_long["after"])
        changed = json.loads(json.dumps(root_long))
        changed["after"] = "An arbitrary already-approved field value"
        self.assertNotEqual(changed["after"], root_long["after"])

    def test_manual_inventory_is_product_commands_not_cobra_utilities(self) -> None:
        manual = (REPO_ROOT / "src/core/syswarden-cli/cmd/manual.go").read_text(
            encoding="utf-8"
        )
        manual_commands = set(documentation_gate.MANUAL_COMMAND_RE.findall(manual))
        product_commands = documentation_gate.cobra_commands(REPO_ROOT)
        snapshot_commands = documentation_gate.snapshot_commands(REPO_ROOT)
        self.assertEqual(manual_commands, product_commands)
        self.assertTrue({"completion", "help"}.issubset(snapshot_commands))
        self.assertTrue({"completion", "help"}.isdisjoint(manual_commands))

    def test_unclosed_fence_and_missing_link_are_rejected(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        keys = documentation_gate.config_schema(REPO_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Bad.md"
            text = "# Bad\n\n[missing](missing.md)\n\n```text\nnot closed\n"
            path.write_text(text, encoding="utf-8")
            errors = documentation_gate.validate_markdown(
                path,
                text,
                commands,
                keys,
                [],
                documentation_gate.source_version(REPO_ROOT),
                None,
            )
        self.assertTrue(any("unclosed Markdown fence" in error for error in errors))
        self.assertTrue(any("missing local link target" in error for error in errors))

    def test_wiki_inventory_is_dynamic_and_home_must_link_every_page(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        keys = documentation_gate.config_schema(REPO_ROOT)
        version = documentation_gate.source_version(REPO_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            banner = f"> Status: Current\n> Documentation baseline: {version}\n"
            (root / "Home.md").write_text(f"# Home\n\n{banner}\n", encoding="utf-8")
            (root / "Future.md").write_text(f"# Future\n\n{banner}\n", encoding="utf-8")
            records = documentation_gate.inventory(root, "wiki")
            errors = documentation_gate.validate_wiki(
                root, records, commands, keys, [], version, {}
            )
        self.assertEqual({record.path for record in records}, {"Future.md", "Home.md"})
        self.assertTrue(any("does not link to page: Future.md" in error for error in errors))

    def test_missing_command_or_required_wiki_port_is_rejected(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        self.assertEqual(len(commands), 24)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            documentation_gate.validate_command_inventory(
                readme, "Operator commands", commands, "README.md"
            ),
            [],
        )
        without_token = readme.replace("web-token", "token-command")
        errors = documentation_gate.validate_command_inventory(
            without_token, "Operator commands", commands, "README.md"
        )
        self.assertTrue(any("web-token" in error for error in errors))

        with_fictitious_entry = readme.replace(
            "alerts             Stream the alert dashboard.",
            "invented-command   Not a real command.\n"
            "alerts             Stream the alert dashboard.",
        )
        errors = documentation_gate.validate_command_inventory(
            with_fictitious_entry, "Operator commands", commands, "README.md"
        )
        self.assertTrue(any("invented-command" in error for error in errors))

        with_bare_fictitious_entry = readme.replace(
            "alerts             Stream the alert dashboard.",
            "invented-command\nalerts             Stream the alert dashboard.",
        )
        errors = documentation_gate.validate_command_inventory(
            with_bare_fictitious_entry,
            "Operator commands",
            commands,
            "README.md",
        )
        self.assertTrue(any("invented-command" in error for error in errors))

        with_cobra_utility = readme.replace(
            "alerts             Stream the alert dashboard.",
            "help               Cobra help utility, not a product command.\n"
            "alerts             Stream the alert dashboard.",
        )
        errors = documentation_gate.validate_command_inventory(
            with_cobra_utility, "Operator commands", commands, "README.md"
        )
        self.assertTrue(any("help" in error for error in errors))

        contract = documentation_gate.load_contract(REPO_ROOT)
        required = contract["required_wiki_phrases"]["Deployment-Tutorial.md"]
        reviewed_phrases = "\n".join(required)
        changed = reviewed_phrases.replace("62026", "62025")
        errors = documentation_gate.require_phrases(
            changed,
            required,
            documentation_gate.source_version(REPO_ROOT),
            "wiki/Deployment-Tutorial.md",
        )
        self.assertTrue(any("default API port" in error for error in errors))

    def test_package_counts_architectures_and_platform_status_are_exact(self) -> None:
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

        wrong_count = readme.replace("two DEB, two RPM", "nine DEB, two RPM")
        errors = documentation_gate.validate_package_documentation(
            wrong_count, "README.md", package_contract
        )
        self.assertTrue(any("artifact count statement changed" in error for error in errors))

        wrong_architecture = readme.replace(
            "amd64 and arm64 package recipes exist",
            "amd64 and s390x package recipes exist",
            1,
        )
        errors = documentation_gate.validate_package_documentation(
            wrong_architecture, "README.md", package_contract
        )
        self.assertTrue(any("package/platform table differs" in error for error in errors))

        wrong_status = readme.replace(
            "**Known blocker:** the current Linux binaries request the glibc ELF interpreter",
            "Supported: the current Linux binaries request the glibc ELF interpreter",
        )
        errors = documentation_gate.validate_package_documentation(
            wrong_status, "README.md", package_contract
        )
        self.assertTrue(any("package/platform table differs" in error for error in errors))

        changed_contract = json.loads(json.dumps(package_contract))
        changed_contract["artifacts"][0]["architecture"] = "s390x"
        errors = documentation_gate.validate_package_source_contract(
            REPO_ROOT, changed_contract
        )
        self.assertTrue(any("naming/architecture mismatch" in error for error in errors))

    def test_wiki_package_matrix_mutations_are_rejected_without_a_live_checkout(self) -> None:
        package_contract = documentation_gate.load_contract(REPO_ROOT)[
            "package_platform_contract"
        ]
        deployment = """## 1. Target decision

| Package family | Architectures produced by the workflow | Decision for v4.02.8 |
| :--- | :--- | :--- |
| DEB | amd64, arm64 | Laboratory evaluation after inspecting the exact release assets |
| RPM | x86_64, aarch64 | Laboratory evaluation after inspecting the exact release assets |
| APK | x86_64, aarch64 | Do not install: current binaries require glibc, while standard Alpine is musl-based |
| FreeBSD package | amd64 | Do not install: the package uses `/usr/local/syswarden/bin`, but current runtime/service code still references `/opt/syswarden` |

The package workflow is configured to publish two DEB files, two RPM files, two
APK files, one FreeBSD package and `SHA256SUMS.txt`.
"""
        label = "wiki/Deployment-Tutorial.md"
        self.assertEqual(
            documentation_gate.validate_package_documentation(
                deployment, label, package_contract
            ),
            [],
        )
        for changed in (
            deployment.replace("two DEB files", "nine DEB files"),
            deployment.replace("x86_64, aarch64", "x86_64, s390x", 1),
            deployment.replace("Do not install: current binaries require glibc", "Supported"),
        ):
            with self.subTest():
                errors = documentation_gate.validate_package_documentation(
                    changed, label, package_contract
                )
                self.assertNotEqual(errors, [])

    def test_local_documentation_runner_requires_an_explicit_wiki(self) -> None:
        runner = REPO_ROOT / "scripts/ci/validate_documentation.sh"
        result = subprocess.run(
            ["bash", runner],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--wiki-root is required", result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-wiki"
            result = subprocess.run(
                ["bash", runner, "--wiki-root", missing],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("existing non-symlink directory", result.stderr)

        source = runner.read_text(encoding="utf-8")
        for required_invocation in (
            "documentation_gate.py\" check",
            "go test ./config",
            "documentation_gate.py\" inventory",
            "documentation_gate.py\" check-links",
        ):
            self.assertIn(required_invocation, source)

    def test_report_is_machine_readable_and_fail_closed(self) -> None:
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

    def test_external_link_checker_skips_placeholders_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            page = Path(directory) / "Links.md"
            page.write_text(
                "# Links\n\n"
                "[placeholder](https://example.invalid/hook)\n"
                "[public](https://example.com/status)\n",
                encoding="utf-8",
            )
            self.assertEqual(
                documentation_gate.external_links([page]),
                ["https://example.com/status", "https://example.invalid/hook"],
            )
            with mock.patch(
                "documentation_gate.urlopen",
                side_effect=documentation_gate.URLError("offline"),
            ):
                errors = documentation_gate.check_external_links([page], 1.0)
        self.assertEqual(len(errors), 1)
        self.assertIn("https://example.com/status", errors[0])
        self.assertNotIn("example.invalid", errors[0])

    def test_nested_image_and_html_links_are_all_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            page = Path(directory) / "Links.md"
            page.write_text(
                "# Links\n\n"
                "[![Support](https://cdn.example.com/button.svg)]"
                "(https://support.example.com/project)\n\n"
                '<a href="https://status.example.com"><img '
                'src="https://cdn.example.com/status.svg" alt="status"></a>\n',
                encoding="utf-8",
            )
            links = documentation_gate.external_links([page])
        self.assertEqual(
            links,
            [
                "https://cdn.example.com/button.svg",
                "https://cdn.example.com/status.svg",
                "https://status.example.com",
                "https://support.example.com/project",
            ],
        )

    def test_insecure_html_link_is_rejected(self) -> None:
        commands = documentation_gate.cobra_commands(REPO_ROOT)
        keys = documentation_gate.config_schema(REPO_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Bad.md"
            text = '# Bad\n\n<a href="http://example.com">insecure</a>\n'
            path.write_text(text, encoding="utf-8")
            errors = documentation_gate.validate_markdown(
                path,
                text,
                commands,
                keys,
                [],
                documentation_gate.source_version(REPO_ROOT),
                None,
            )
        self.assertTrue(any("absolute HTTPS URL" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
