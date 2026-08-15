#!/usr/bin/env python3
"""Characterize package lifecycle scripts without mutating a host."""

from __future__ import annotations

import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "package.yml"


class PackageLifecycleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = PACKAGE_WORKFLOW.read_text(encoding="utf-8")

    def script(self, name: str) -> str:
        destination = f"${{PACKAGE_SCRIPTS}}/{name}"
        opener = re.compile(
            rf"^\s*cat\s+<<\s*'(?P<delimiter>[A-Z][A-Z0-9_]*)'\s+>\s+"
            rf'"{re.escape(destination)}"\s*$'
        )
        lines = self.workflow.splitlines()
        bodies: list[str] = []
        for index, line in enumerate(lines):
            match = opener.match(line)
            if match is None:
                continue
            delimiter = match.group("delimiter")
            body: list[str] = []
            for candidate in lines[index + 1 :]:
                if candidate.strip() == delimiter:
                    bodies.append(textwrap.dedent("\n".join(body)))
                    break
                body.append(candidate)
            else:
                self.fail(f"package script {name} has no heredoc terminator")
        self.assertEqual(
            len(bodies),
            1,
            f"package script {name} must have exactly one isolated heredoc",
        )
        return bodies[0]

    def migration_state_machine(self, script_name: str) -> str:
        script = self.script(script_name)
        start = script.index("modular_config_complete() {")
        invocation = "\nmigrate_legacy_configuration\n"
        end = script.index(invocation, start) + len(invocation)
        return script[start:end]

    def test_linux_package_family_and_architecture_matrix(self) -> None:
        required_assets = {
            'syswarden_${VERSION}_amd64.deb',
            'syswarden_${VERSION}_arm64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            "syswarden-${VERSION}-1.aarch64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
            'syswarden_${VERSION}_aarch64.apk',
            "syswarden-${VERSION}.txz",
        }
        for asset in required_assets:
            with self.subTest(asset=asset):
                self.assertIn(asset, self.workflow)

    def test_packaging_workspace_is_isolated_and_fail_closed(self) -> None:
        self.assertIn(
            'PACKAGE_WORKSPACE="$(mktemp -d '
            '"${RUNNER_TEMP%/}/syswarden-package.XXXXXX")"',
            self.workflow,
        )
        for variable, suffix in (
            ("STAGING_AMD64", "staging-amd64"),
            ("STAGING_ARM64", "staging-arm64"),
            ("STAGING_FREEBSD", "staging-freebsd"),
            ("PACKAGE_ASSETS", "assets"),
            ("PACKAGE_SCRIPTS", "scripts"),
            ("PACKAGE_CONFIGS", "configs"),
        ):
            with self.subTest(variable=variable):
                self.assertIn(
                    f'{variable}="${{PACKAGE_WORKSPACE}}/{suffix}"',
                    self.workflow,
                )

        self.assertEqual(
            self.workflow.count("scripts/ci/package_stage_gate.py"),
            3,
        )
        for platform, root in (
            ("linux", "STAGING_AMD64"),
            ("linux", "STAGING_ARM64"),
            ("freebsd", "STAGING_FREEBSD"),
        ):
            with self.subTest(platform=platform, root=root):
                self.assertIn(
                    f'{platform} --root "${{{root}}}"',
                    self.workflow,
                )

        self.assertEqual(
            self.workflow.count("scripts/ci/repository_state.py"),
            2,
        )
        self.assertIn("capture \\\n            --output", self.workflow)
        self.assertIn("verify \\\n            --snapshot", self.workflow)
        capture = self.workflow.index("Capture Candidate Repository State")
        compile_step = self.workflow.index("Compile Universal Script")
        workspace = self.workflow.index("Create Isolated Packaging Workspace")
        first_stage = self.workflow.index("Prepare Staging Environment (AMD64)")
        verify = self.workflow.index("Prove Packaging Did Not Mutate Source")
        upload = self.workflow.index("Upload Package Artifacts")
        self.assertLess(capture, compile_step)
        self.assertLess(compile_step, workspace)
        self.assertLess(workspace, first_stage)
        self.assertLess(first_stage, verify)
        self.assertLess(verify, upload)
        self.assertIn("if: always()", self.workflow[verify:upload])
        self.assertNotIn("package_assets", self.workflow)
        self.assertNotIn("staging_arm64", self.workflow)
        self.assertNotIn("staging_fbsd", self.workflow)

    def test_all_package_outputs_use_the_isolated_asset_directory(self) -> None:
        assets = (
            'syswarden_${VERSION}_amd64.deb',
            'syswarden_${VERSION}_arm64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            "syswarden-${VERSION}-1.aarch64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
            'syswarden_${VERSION}_aarch64.apk',
            "syswarden-${VERSION}.txz",
        )
        for asset in assets:
            with self.subTest(asset=asset):
                self.assertIn(f'"${{PACKAGE_ASSETS}}/{asset}"', self.workflow)
        self.assertIn('cd "${PACKAGE_ASSETS}"', self.workflow)
        self.assertIn('--packages "${PACKAGE_ASSETS}"', self.workflow)
        self.assertIn(
            "name: syswarden-packages-${{ env.VERSION }}",
            self.workflow,
        )
        self.assertIn(
            "path: ${{ steps.package_workspace.outputs.assets }}",
            self.workflow,
        )

    def test_linux_install_and_upgrade_preservation_contract(self) -> None:
        preinstall = self.script("preinst.sh")
        postinstall = self.script("postinst.sh")
        self.assertIn(
            "mv /opt/syswarden/syswarden-auto.conf "
            "/opt/syswarden/syswarden-auto.conf.migration_backup",
            preinstall,
        )
        self.assertIn(
            "[ ! -e /opt/syswarden/syswarden-auto.conf.migration_backup ]",
            preinstall,
        )
        self.assertIn("set -e", preinstall)
        self.assertIn('export SYSWARDEN_PKG_INSTALL=1', postinstall)
        self.assertIn("set -e", postinstall)
        self.assertIn('[ "$1" = "2" ]', postinstall)
        self.assertIn('[ "$1" = "configure" -a -n "$2" ]', postinstall)
        self.assertIn('! modular_config_complete', postinstall)
        self.assertIn('marker=/etc/syswarden/config/.migration-in-progress', postinstall)
        self.assertIn('mv "${source}.migrated" /opt/syswarden/syswarden-auto.conf.bak', postinstall)
        self.assertLess(
            postinstall.index("migrate_legacy_configuration\n"),
            postinstall.index('if [ "$1" = "2" ]'),
        )
        self.assertNotRegex(postinstall, r"migrate-config[^\n]*\|\|\s*true")
        self.assertIn('/opt/syswarden/bin/syswarden-cli install', postinstall)
        self.assertIn('[ -f /etc/alpine-release ]', postinstall)

    def test_linux_remove_and_purge_contract(self) -> None:
        preremove = self.script("prerm.sh")
        self.assertNotIn("/tmp/sw_cron.bak", preremove)
        self.assertIn("mktemp /var/tmp/syswarden-cron.XXXXXX", preremove)
        self.assertIn("umask 077", preremove)
        self.assertIn("trap 'rm -f -- \"$cron_backup\"' 0 1 2 15", preremove)
        postremove = self.script("postrm.sh")
        for state in ('"0"', '"remove"', '"purge"'):
            self.assertIn(f'[ "$1" = {state} ]', preremove)
        for service in (
            "syswarden-core.service",
            "syswarden-firewall.service",
            "syswarden-webtui.service",
        ):
            self.assertIn(service, preremove)
        for table in (
            "netdev syswarden_hw_drop",
            "arp syswarden_arp",
            "inet syswarden",
        ):
            self.assertIn(f"nft delete table {table}", preremove)
        self.assertIn('[ "$1" = "0" ]', postremove)
        self.assertIn('[ "$1" = "purge" ]', postremove)
        self.assertNotIn('[ "$1" = "remove" ]', postremove)
        self.assertIn("rm -rf /opt/syswarden", postremove)
        self.assertIn("rm -rf /etc/syswarden", postremove)

    def test_freebsd_package_lifecycle_contract(self) -> None:
        preinstall = self.script("preinst_fbsd.sh")
        postinstall = self.script("postinst_fbsd.sh")
        preremove = self.script("prerm_fbsd.sh")
        postremove = self.script("postrm_fbsd.sh")
        self.assertIn(
            "mv /usr/local/syswarden/syswarden-auto.conf "
            "/usr/local/syswarden/syswarden-auto.conf.migration_backup",
            preinstall,
        )
        self.assertIn("set -e", preinstall)
        self.assertIn("migrate_legacy_configuration", postinstall)
        self.assertIn(".migration-in-progress", postinstall)
        self.assertIn("/usr/local/bin/syswarden install", postinstall)
        self.assertIn("set -e", postinstall)
        self.assertNotRegex(postinstall, r"migrate-config[^\n]*\|\|\s*true")
        self.assertIn("service syswarden restart || true", postinstall)
        self.assertIn("service syswarden stop || true", preremove)
        self.assertIn("sysrc -x syswarden_enable || true", preremove)
        self.assertIn("rm -rf /usr/local/syswarden", postremove)
        self.assertNotIn("rm -rf /etc/syswarden", postremove)

    def test_package_migration_state_machine_is_retry_safe_and_preserves_modular_bytes(self) -> None:
        platforms = (
            (
                "postinst.sh",
                "/opt/syswarden/bin/syswarden-cli",
                "/opt/syswarden/syswarden-auto.conf.migration_backup",
                "/opt/syswarden/syswarden-auto.conf.bak",
            ),
            (
                "postinst_fbsd.sh",
                "/usr/local/syswarden/bin/syswarden-cli",
                "/usr/local/syswarden/syswarden-auto.conf.migration_backup",
                "/usr/local/syswarden/syswarden-auto.conf.bak",
            ),
        )
        for script_name, cli_path, source_path, backup_path in platforms:
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cli = root / "syswarden-cli"
                calls = root / "calls"
                cli.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' \"$*\" >> {calls}\n"
                    "source_path=\noutput_path=\n"
                    "while [ \"$#\" -gt 0 ]; do\n"
                    "  case \"$1\" in\n"
                    "    --source) source_path=$2; shift 2 ;;\n"
                    "    --output) output_path=$2; shift 2 ;;\n"
                    "    *) shift ;;\n"
                    "  esac\n"
                    "done\n"
                    "mkdir -p \"${output_path}/modules\"\n"
                    "printf 'migrated\\n' > \"${output_path}/modules/40-integrations.toml\"\n"
                    "rm -f \"${output_path}/.migration-in-progress\"\n"
                    "if [ -f \"${source_path}\" ]; then mv \"${source_path}\" \"${source_path}.migrated\"; fi\n",
                    encoding="utf-8",
                )
                cli.chmod(0o700)
                config_root = root / "config"
                source = root / "legacy.migration_backup"
                backup = root / "legacy.bak"
                state_machine = self.migration_state_machine(script_name)
                state_machine = state_machine.replace(cli_path, str(cli))
                state_machine = state_machine.replace(source_path, str(source))
                state_machine = state_machine.replace(backup_path, str(backup))
                state_machine = state_machine.replace("/etc/syswarden/config", str(config_root))

                def run_state_machine() -> subprocess.CompletedProcess[str]:
                    return subprocess.run(
                        ["/bin/sh", "-c", "set -e\n" + state_machine],
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                source.write_text("legacy-fresh\n", encoding="utf-8")
                fresh = run_state_machine()
                self.assertEqual(fresh.returncode, 0, fresh)
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-fresh\n")
                self.assertTrue(calls.exists())

                calls.unlink()
                backup.unlink()
                source.write_text("legacy-existing\n", encoding="utf-8")
                modules = config_root / "modules"
                modules.mkdir(parents=True, exist_ok=True)
                complete_modular_files = {
                    config_root / "config.toml": "master-byte-exact\n",
                    modules / "00-core.toml": "core-byte-exact\n",
                    modules / "10-network.toml": "network-byte-exact\n",
                    modules / "20-security.toml": "security-byte-exact\n",
                    modules / "30-waap.toml": "waap-byte-exact\n",
                    modules / "40-integrations.toml": "integrations-byte-exact\n",
                    modules / "99-user.toml": "user-byte-exact\n",
                }
                for path, content in complete_modular_files.items():
                    path.write_text(content, encoding="utf-8")
                preserved = run_state_machine()
                self.assertEqual(preserved.returncode, 0, preserved)
                self.assertFalse(calls.exists(), "existing modular config unexpectedly reran migration")
                for path, content in complete_modular_files.items():
                    self.assertEqual(path.read_text(encoding="utf-8"), content)
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-existing\n")

                backup.unlink()
                source.write_text("legacy-retry\n", encoding="utf-8")
                (config_root / ".migration-in-progress").write_text("publishing\n", encoding="utf-8")
                retried = run_state_machine()
                self.assertEqual(retried.returncode, 0, retried)
                self.assertTrue(calls.exists(), "transaction marker did not force migration retry")
                self.assertFalse((config_root / ".migration-in-progress").exists())
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-retry\n")

    def test_linux_state_machine_precedes_every_package_family_branch(self) -> None:
        postinstall = self.script("postinst.sh")
        invocation = postinstall.index("migrate_legacy_configuration\n")
        for branch in (
            'if [ "$1" = "2" ]',
            'elif [ "$1" = "1" ]',
            'elif [ -f /etc/alpine-release ]',
        ):
            with self.subTest(branch=branch):
                self.assertLess(invocation, postinstall.index(branch))

    def test_postinstall_propagates_install_failure_without_completion(self) -> None:
        for script_name, install_command in (
            ("postinst.sh", "/opt/syswarden/bin/syswarden-cli install"),
            ("postinst_fbsd.sh", "/usr/local/bin/syswarden install"),
        ):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                postinstall = self.script(script_name)
                self.assertLess(postinstall.index("set -e"), postinstall.index(install_command))
                self.assertNotIn(f"{install_command} || true", postinstall)

                fake_cli = Path(temporary) / "syswarden-cli"
                fake_cli.write_text(
                    "#!/bin/sh\nprintf '[ERROR] configuration preflight failed\\n' >&2\nexit 23\n",
                    encoding="utf-8",
                )
                fake_cli.chmod(0o700)
                probe = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        'set -e\n"$1" install\nprintf "Installation Complete\\n"',
                        "postinstall-probe",
                        str(fake_cli),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(probe.returncode, 23, probe)
                self.assertIn("[ERROR] configuration preflight failed", probe.stderr)
                self.assertNotIn("Installation Complete", probe.stdout)

    def test_no_package_rollback_implementation_is_claimed(self) -> None:
        scripts = "\n".join(
            self.script(name)
            for name in (
                "preinst.sh",
                "postinst.sh",
                "prerm.sh",
                "postrm.sh",
                "preinst_fbsd.sh",
                "postinst_fbsd.sh",
                "prerm_fbsd.sh",
                "postrm_fbsd.sh",
            )
        )
        self.assertNotRegex(scripts.lower(), r"\brollback\b")

    def test_package_artifact_upload_is_github_strict_and_act_compatible(self) -> None:
        github_sha = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        act_sha = "ea165f8d65b6e75b540449e92b4886f43607fa02"
        self.assertEqual(self.workflow.count(f"actions/upload-artifact@{github_sha}"), 1)
        self.assertEqual(self.workflow.count(f"actions/upload-artifact@{act_sha}"), 1)
        self.assertIn("if: ${{ !github.event.act }}", self.workflow)
        self.assertIn("if: ${{ github.event.act }}", self.workflow)
        self.assertIn("ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY: '1'", self.workflow)
        self.assertEqual(self.workflow.count("name: syswarden-packages-${{ env.VERSION }}"), 2)

    def test_apk_metadata_accepts_only_equivalent_numeric_version_components(self) -> None:
        self.assertIn('package_version="$(sed -n \'s/^pkgver = //p\'', self.workflow)
        self.assertIn('pattern = re.compile(r"^[0-9]+(?:\\.[0-9]+){2}$")', self.workflow)
        self.assertIn(
            'normalize = lambda value: tuple(int(part) for part in value.split("."))',
            self.workflow,
        )
        self.assertIn('[[ "${package_architecture}" == "${architecture}" ]]', self.workflow)

    def test_freebsd_runtime_path_divergence_is_explicitly_frozen(self) -> None:
        core_main = (
            REPOSITORY / "src" / "core" / "syswarden-core" / "main.go"
        ).read_text(encoding="utf-8")
        service_source = (
            REPOSITORY
            / "src"
            / "core"
            / "syswarden-cli"
            / "pkg"
            / "system"
            / "service_freebsd.go"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'NewEngine("/opt/syswarden/signatures.json"',
            core_main,
        )
        self.assertIn(
            'STAGING_FREEBSD="${PACKAGE_WORKSPACE}/staging-freebsd"',
            self.workflow,
        )
        self.assertRegex(
            self.workflow,
            r"cp\s+src/core/syswarden-core/signatures\.json\s+\\\s+"
            r'"\$\{STAGING_FREEBSD\}/usr/local/syswarden/"',
        )
        self.assertIn('command="/opt/syswarden/syswarden-core"', service_source)
        for binary in ("syswarden-cli", "syswarden-core", "syswarden-tui"):
            with self.subTest(binary=binary):
                self.assertRegex(
                    self.workflow,
                    rf"cp\s+dist/freebsd/bin/{binary}\s+\\\s+"
                    r'"\$\{STAGING_FREEBSD\}/usr/local/syswarden/bin/"',
                )
        self.assertIn('-C "${STAGING_FREEBSD}" .', self.workflow)


if __name__ == "__main__":
    unittest.main()
