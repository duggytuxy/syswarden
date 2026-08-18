#!/usr/bin/env python3
"""Tests for the SysWarden documentation truth gate."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import documentation_gate
import freebsd_vm_lab


REPO_ROOT = Path(__file__).resolve().parents[2]


class DocumentationGateTest(unittest.TestCase):
    def test_tracked_files_do_not_contain_forbidden_dash_utf8_bytes(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.split(b"\0")
        # Keep all tracked repository text on plain ASCII hyphens.
        forbidden = {
            b"\xe2\x80\x91": "U+2011",
            b"\xe2\x80\x93": "U+2013",
            b"\xe2\x80\x94": "U+2014",
        }
        offenders = []
        for relative_path in tracked:
            if not relative_path:
                continue
            decoded_path = relative_path.decode("utf-8", errors="surrogateescape")
            content = (REPO_ROOT / decoded_path).read_bytes()
            for sequence, label in forbidden.items():
                if sequence in content:
                    offenders.append(f"{decoded_path}: {label}")
        self.assertEqual(offenders, [])

    def test_v40215_changelog_is_complete_and_preserves_v40214_suffix(self) -> None:
        changelog = (REPO_ROOT / "changelog.md").read_bytes()
        marker = b"# Release v4.02.14\n"
        self.assertEqual(changelog.count(marker), 1)
        suffix = marker + changelog.split(marker, 1)[1]
        self.assertEqual(len(suffix), 157650)
        self.assertEqual(
            hashlib.sha256(suffix).hexdigest(),
            "a6ebcab7a81769c52147be710622995779cedf9523270cf08cf03e275501cde5",
        )

        release_block = changelog.split(b"# Release v4.02.15\n", 1)[1].split(
            b"\n---\n", 1
        )[0].decode("utf-8")
        for phrase in (
            "Protected qualification run `31993252784`",
            "native amd64 and ARM64 package lifecycle shards",
            "FreeBSD and nftables product behavior was therefore not evaluated",
            "Preserve a redacted primary laboratory error when transport cleanup also fails",
            "does not publish that successful result",
            "both `script` TUI probes and all eleven noninteractive `pkg`",
            "exactly 13 explicit `</dev/null` boundaries",
            "All six lifecycle `pkg add -f` and two evidence-bearing `pkg delete -fy`",
            "use bounded FreeBSD `timeout -f`",
            "consuming unread shell source and returning status 2",
            "map HUP, INT and TERM to statuses 129, 130 and 143",
            "Write `root` and `nobody` on separate lines",
            "byte-exact nonsymlink `root:wheel` 0600 state",
            "transactional byte-exact root crontab probe and restoration",
            "restore the original present or absent state even after a primary failure",
            "fail closed on any primary, restoration or restoration-readback error",
            "FreeBSD 14.4 singular `fragment` keyword",
            "rejects the invalid plural `fragments` form",
            "Publish schema v2 before any PF module load or policy mutation",
            "record `initial_kernel_state=module_absent`",
            "state table read through `pfctl -ss`",
            "Persist `mutation_started=true` immediately before applying",
            "Restoration unloads PF only when the snapshot recorded an initially absent module",
            "returns the guest to module and control-device absence",
            "normalized `sshd_config` content is byte-identical",
            "zero backup, temporary-file write, candidate validation, rename",
            "Changed content retains the validated compare-and-swap transaction",
            "Normalize every TXZ member to numeric UID and GID 0 with `root:wheel` names",
            "remove PAX `uid`, `gid`, `uname` and `gname` overrides",
            "reject any numeric or named owner or group drift",
            "No sealed v4.02.14 qualification artifact",
            "final disposable FreeBSD VM evidence",
            "099015d7d7433235b50a2d3cff76782553536af2fe2357dfb5ebf5f999e085",
            "e3ff75d5961092ca1ab0ec752e8dd70d4121f9bf2cbb26957dc339cdd276bf65",
            "harness_status=pass",
            "product_status=fail",
            "release_ready=false",
            "Of 75 checks, 68 passed and seven unexpected checks have status `blocker`.",
            "SW-PKG-FBSD-CANDIDATE-UPGRADE-POSTINSTALL-001",
            "SW-PKG-FBSD-CANDIDATE-REINSTALL-POSTINSTALL-001",
            "SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-POSTINSTALL-001",
            "SW-PKG-FBSD-RCD-ENABLE-001",
            "SW-PKG-FBSD-UPGRADE-RCD-001",
            "SW-PKG-FBSD-PF-MODULE-ABSENT-INSTALL-001",
            "SW-PKG-FBSD-RSYSLOG-001",
            "diagnostics_clean=0",
            "mutation_started=false",
            "base_syslogd_inactive=0",
            "Publication is stopped.",
            "No v4.02.15 tag, public Release, Release signature or public asset is authorized or created.",
            "20 August 2026 at 13:00 CEST",
            "remove FreeBSD support completely",
            "v4.02.15 is an unpublished failed candidate.",
            "Do not install it as a public Release",
            "exactly 14 assets",
            "No PDF and no private `output/` file belongs to a public Release.",
        ):
            self.assertIn(phrase, release_block)

        script = freebsd_vm_lab.REMOTE_LAB_SCRIPT
        self.assertEqual(script.count("</dev/null"), 13)
        self.assertEqual(
            script.count("env TERM=xterm timeout 5 script -q /dev/null"),
            2,
        )
        self.assertEqual(script.count("pkg update -f"), 1)
        self.assertEqual(script.count("pkg install -y"), 1)
        self.assertEqual(script.count("pkg add -f"), 6)
        self.assertEqual(script.count("pkg delete -fy syswarden"), 3)
        self.assertEqual(
            script.count('timeout -f "$command_timeout" pkg add -f'),
            6,
        )
        self.assertEqual(
            script.count("timeout -f 120 pkg delete -fy syswarden"),
            2,
        )
        self.assertEqual(script.count("trap 'final_cleanup \"$?\"' EXIT"), 1)
        for signal, status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            self.assertEqual(script.count(f"trap 'exit {status}' {signal}"), 1)

        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        release_block = changelog.split("# Release v4.02.15\n", 1)[1].split(
            "\n---\n", 1
        )[0]
        report = (
            REPO_ROOT / "docs/reports/LOT1_PUBLIC_SECURITY_REPORT_v4.02.15.md"
        ).read_text(encoding="utf-8")
        for text in (release_block, report):
            self.assertIn("all eleven noninteractive", text)
            self.assertIn("exactly 13", text)
            self.assertIn("six lifecycle", text)
            self.assertIn("two", text)
            self.assertIn("timeout -f", text)
            self.assertIn("both", text)
            self.assertIn("/dev/null", text)
            self.assertIn("129", text)
            self.assertIn("130", text)
            self.assertIn("143", text)
            self.assertIn("`root` and `nobody`", text)
            self.assertIn("root:wheel", text)
            self.assertIn("0600", text)
            self.assertIn("byte-exact", text)
            self.assertIn("singular `fragment`", text)
            self.assertIn("plural `fragments`", text)
            self.assertIn("schema v2", text)
            self.assertIn("initial_kernel_state=module_absent", text)
            self.assertIn("pfctl -ss", text)
            self.assertIn("mutation_started=true", text)
            self.assertIn("initially absent", text)
            self.assertIn("initially present", text)
            self.assertIn("module and control-device absence", text)
            self.assertIn("byte-identical", text)
            self.assertIn("zero backup", text)
            self.assertIn("candidate validation", text)
            self.assertIn("compare-and-swap", text)
            self.assertIn("restoration", text)
            self.assertIn("primary", text)

        self.assertIn(
            "printf '%s\\n' root nobody >/var/cron/allow",
            script,
        )
        self.assertNotIn("'root,nobody' >/var/cron/allow", script)
        self.assertIn(
            "stat -f '%u:%g:%Lp' \"$cron_access_path\"",
            script,
        )
        self.assertIn(
            'validate_root_crontab_round_trip "$work/cron-access-round-trip"',
            script,
        )
        self.assertIn(
            "# Once the probe command has run, restoration is mandatory",
            script,
        )
        self.assertIn(
            'cmp -s "$root_crontab_before" "$root_crontab_restored"',
            script,
        )
        self.assertIn(
            'if [ "$root_crontab_primary_failed" -ne 0 ] ||',
            script,
        )
        self.assertIn(
            '[ "$root_crontab_restore_failed" -ne 0 ]; then',
            script,
        )
        self.assertIn(
            'cmp -s "$removal_cron_expected" "$removal_cron_readback"',
            script,
        )

        singular_fragment_rule = "block drop in quick all fragment"
        plural_fragment_rule = "block drop in quick all fragments"
        for relative_path in (
            "src/core/syswarden-cli/pkg/firewall/firewall_freebsd.go",
            "testdata/firewall/pf-v4.02.8.conf",
        ):
            policy = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn(plural_fragment_rule, policy)
            self.assertEqual(policy.count(singular_fragment_rule), 1)

        pf_restore_source = (
            REPO_ROOT
            / "src/core/syswarden-cli/pkg/firewall/pf_restore_freebsd.go"
        ).read_text(encoding="utf-8")
        for phrase in (
            "pfSnapshotSchemaVersion   = 2",
            'PFInitialKernelModuleAbsent PFInitialKernelState = "module_absent"',
            'States       string             `json:"states"`',
            'MutationStarted    bool                 `json:"mutation_started"`',
            'newPFCTLCommand("-ss")',
        ):
            self.assertIn(phrase, pf_restore_source)

        pf_apply_source = (
            REPO_ROOT
            / "src/core/syswarden-cli/pkg/firewall/firewall_freebsd.go"
        ).read_text(encoding="utf-8")
        transaction_order = [
            pf_apply_source.index(
                "capturePFPolicySnapshotLocked(PFSnapshotExactLive)"
            ),
            pf_apply_source.index("ensurePFKernelReadyForMutationLocked()"),
            pf_apply_source.index('newPFCTLCommand("-nf", "-")'),
            pf_apply_source.index("markPFMutationStartedLocked()"),
            pf_apply_source.index('newPFCTLCommand("-f", "-")'),
        ]
        self.assertEqual(transaction_order, sorted(transaction_order))

        restore_start = pf_restore_source.index(
            "func restorePFPolicyLocked() error {"
        )
        restore_end = pf_restore_source.index(
            "\n}\n\n// RestorePersistedPFPolicy",
            restore_start,
        )
        restore_source = pf_restore_source[restore_start:restore_end]
        self.assertEqual(restore_source.count("unloadPFKernelModule()"), 2)
        self.assertEqual(
            restore_source.count(
                "if snapshot.InitialKernelState == PFInitialKernelModuleAbsent {"
            ),
            3,
        )

        for phrase in (
            'emit PF_INITIAL_MODULE_ABSENT "$initial_pf_module_absent"',
            'select(.schema_version == 2 and .provenance == "exact_live")',
            "PF_ABSENT_SNAPSHOT_MUTATION_STARTED",
            "PF_ABSENT_DELETE_FINAL_MODULE_ABSENT",
            "PF_ABSENT_DELETE_FINAL_DEVICE_ABSENT",
            "PF_FINAL_GUEST_MODULE_ABSENT",
            "PF_FINAL_GUEST_DEVICE_ABSENT",
        ):
            self.assertIn(phrase, script)

        ssh_source = (
            REPO_ROOT / "src/core/syswarden-cli/pkg/system/ssh_freebsd.go"
        ).read_text(encoding="utf-8")
        self.assertRegex(
            ssh_source,
            r"if normalized == originalContent \{\s+return nil\s+\}",
        )
        no_op_guard = ssh_source.index("if normalized == originalContent")
        for side_effect in (
            "freeBSDSSHWritePrivateFile(root, freeBSDSSHBackup",
            "freeBSDSSHWritePrivateFile(root, freeBSDSSHConfigTmp",
            "freeBSDSSHValidate()",
            "freeBSDSSHRename(root, freeBSDSSHConfigTmp",
            "freeBSDSSHSyncDirectory(root)",
            "freeBSDSSHRestart()",
        ):
            self.assertGreater(
                ssh_source.index(side_effect, no_op_guard),
                no_op_guard,
            )

    def test_v40212_historical_changelog_records_exact_nosec_reduction(self) -> None:
        changelog = (REPO_ROOT / "changelog.md").read_text(encoding="utf-8")
        release_block = changelog.split("# Release v4.02.12\n", 1)[1].split(
            "\n---\n", 1
        )[0]
        self.assertIn(
            "Remove only the eight resolved legacy crontab suppressions",
            release_block,
        )

    def test_architecture_diagrams_are_safe_native_svg_and_readme_mermaid_free(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("assets/syswarden_hero.svg", readme)
        self.assertIn("assets/syswarden_architecture.svg", readme)
        self.assertIn("assets/syswarden_bunkerweb_integration.svg", readme)
        self.assertNotIn("```mermaid", readme)

        for relative_path in (
            "assets/syswarden_hero.svg",
            "assets/syswarden_architecture.svg",
            "assets/syswarden_bunkerweb_integration.svg",
        ):
            root = ET.parse(REPO_ROOT / relative_path).getroot()
            self.assertEqual(root.attrib.get("role"), "img")
            labelled_by = root.attrib.get("aria-labelledby", "").split()
            self.assertEqual(labelled_by, ["title", "description"])
            element_names = {
                element.tag.rsplit("}", 1)[-1] for element in root.iter()
            }
            self.assertNotIn("script", element_names)
            self.assertNotIn("foreignObject", element_names)
            for element in root.iter():
                for attribute in element.attrib:
                    self.assertFalse(attribute.lower().startswith("on"))
                    self.assertNotIn(attribute.rsplit("}", 1)[-1], {"href"})

    def test_repository_documentation_contract(self) -> None:
        records, errors = documentation_gate.validate_repository(REPO_ROOT)
        self.assertEqual(errors, [])
        self.assertEqual([record.path for record in records], ["README.md"])

    def test_public_report_contract_is_exact_anonymized_and_preserves_history(self) -> None:
        contract = documentation_gate.load_contract(REPO_ROOT)
        report_contract = contract["public_report_contract"]
        version = documentation_gate.source_version(REPO_ROOT)
        expected_path = f"docs/reports/LOT1_PUBLIC_SECURITY_REPORT_{version}.md"
        self.assertEqual(report_contract["path"], expected_path)

        report_path = REPO_ROOT / report_contract["path"]
        report = report_path.read_text(encoding="utf-8")
        self.assertEqual(
            documentation_gate.require_phrases(
                report,
                report_contract["required_phrases"],
                version,
                report_contract["path"],
            ),
            [],
        )
        report.encode("ascii")
        self.assertNotIn("\u2014", report)
        for phrase in report_contract["forbidden_phrases"]:
            self.assertNotIn(phrase.lower(), report.lower())

        release_assets = re.findall(r"^\d+\. `([^`]+)`[.;]$", report, re.MULTILINE)
        self.assertEqual(release_assets, report_contract["expected_assets"])
        self.assertEqual(len(release_assets), 14)
        self.assertEqual(len(set(release_assets)), 14)

        for preserved in report_contract["preserved_reports"]:
            preserved_path = REPO_ROOT / preserved["path"]
            self.assertEqual(
                hashlib.sha256(preserved_path.read_bytes()).hexdigest(),
                preserved["sha256"],
            )

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
            "restart failure returns nonzero and can leave the running Web-TUI on its previous token",
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
        self.assertTrue(
            {
                "package-capture-pf",
                "package-restore-host-state",
                "package-restore-pf",
            }.isdisjoint(product_commands)
        )
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
            "amd64 and arm64 package contents",
            "amd64 and s390x package contents",
            1,
        )
        errors = documentation_gate.validate_package_documentation(
            wrong_architecture, "README.md", package_contract
        )
        self.assertTrue(any("package/platform table differs" in error for error in errors))

        wrong_status = readme.replace(
            "The exact x86_64 and aarch64 packages must still pass the protected lifecycle run",
            "Release-qualified without the protected lifecycle run",
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

| Package family | Architectures produced by the workflow | Decision for v4.02.15 |
| :--- | :--- | :--- |
| DEB | amd64, arm64 | Package contents and lifecycle contracts validated; exact protected lifecycle still required before release |
| RPM | x86_64, aarch64 | Package contents and lifecycle contracts validated; exact protected lifecycle still required before release |
| APK | x86_64, aarch64 | Dedicated CGO-free static binaries; amd64 executes on standard Alpine musl; exact protected lifecycle still required |
| FreeBSD package | amd64 | ABI 14, native `/usr/local`, rc.d, PF and updater contracts; exact protected VM lifecycle still required |

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
            deployment.replace(
                "Dedicated CGO-free static binaries; amd64 executes on standard Alpine musl; exact protected lifecycle still required",
                "Release-qualified without protected lifecycle",
            ),
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
