#!/usr/bin/env python3
"""Characterize package lifecycle scripts without mutating a host."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "package.yml"
BUILD_SCRIPT = REPOSITORY / "build.ps1"
LOCAL_BUILD_SCRIPT = REPOSITORY / "build_packages.sh"


def workflow_step_script(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1:
        raise AssertionError(f"expected one shell body for workflow step {step_name}")
    return textwrap.dedent(step.split(run_marker, 1)[1])


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

    def test_package_workflow_shell_steps_fit_github_limit(self) -> None:
        for step_name in (
            "Prepare Linux Maintainer Scripts",
            "Build Debian Package (.deb)",
        ):
            with self.subTest(step=step_name):
                script = workflow_step_script(self.workflow, step_name)
                encoded_size = len(json.dumps(script, ensure_ascii=False))
                self.assertLessEqual(
                    encoded_size,
                    21_000,
                    f"GitHub rejects {step_name!r} above 21,000 encoded characters",
                )

    def local_build_script(self, name: str) -> str:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        opener = re.compile(
            rf"^\s*cat\s+<<\s*'(?P<delimiter>[A-Z][A-Z0-9_]*)'\s+>\s+"
            rf"{re.escape(name)}\s*$"
        )
        lines = source.splitlines()
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
                self.fail(f"local package script {name} has no heredoc terminator")
        self.assertEqual(
            len(bodies),
            1,
            f"local package script {name} must have exactly one isolated heredoc",
        )
        return bodies[0]

    def cron_functions(self, script: str) -> str:
        start = script.index("syswarden_managed_cron_line() {")
        cleanup = script.index("syswarden_cleanup_crontab() {", start)
        end = script.index("\n}\n", cleanup) + len("\n}\n")
        return script[start:end]

    def cron_script_matrix(self) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
        linux_paths = ("/opt/syswarden/bin/syswarden-cli",)
        freebsd_paths = (
            "/usr/local/syswarden/bin/syswarden-cli",
            "/opt/syswarden/bin/syswarden-cli",
        )
        return (
            ("workflow-prerm", self.script("prerm.sh"), linux_paths),
            ("workflow-postrm", self.script("postrm.sh"), linux_paths),
            ("workflow-freebsd-postrm", self.script("postrm_fbsd.sh"), freebsd_paths),
            ("local-build-prerm", self.local_build_script("prerm.sh"), linux_paths),
        )

    def migration_state_machine(self, script_name: str) -> str:
        script = self.script(script_name)
        start = script.index("modular_config_complete() {")
        invocation = "\nmigrate_legacy_configuration\n"
        end = script.index(invocation, start) + len(invocation)
        return script[start:end]

    def secure_directory_function(self, script_name: str) -> str:
        script = self.script(script_name)
        start = script.index("secure_private_directory() {")
        end = script.index("\n}\n", start) + len("\n}\n")
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
            ("STAGING_APK_AMD64", "staging-apk-amd64"),
            ("STAGING_APK_ARM64", "staging-apk-arm64"),
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
            5,
        )
        for platform, root in (
            ("linux", "STAGING_AMD64"),
            ("linux", "STAGING_ARM64"),
            ("linux", "STAGING_APK_AMD64"),
            ("linux", "STAGING_APK_ARM64"),
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
        self.assertIn(
            '{ [ "$1" = "configure" ] && [ -n "${2:-}" ]; }',
            postinstall,
        )
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

    def test_package_preinstall_tightens_directories_and_rejects_links(self) -> None:
        for script_name in ("preinst.sh", "preinst_fbsd.sh"):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                private = root / "private"
                private.mkdir(mode=0o755)
                private.chmod(0o755)
                function = self.secure_directory_function(script_name)
                self.assertIn("find", function)
                self.assertIn("-user", function)
                self.assertIn("-group", function)
                self.assertIn("identity changed while securing", function)

                tightened = subprocess.run(
                    ["/bin/sh", "-c", function + '\nsecure_private_directory "$1"', "probe", str(private)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(tightened.returncode, 0, tightened)
                self.assertEqual(private.stat().st_mode & 0o777, 0o750)

                target = root / "target"
                target.mkdir(mode=0o700)
                link = root / "link"
                link.symlink_to(target, target_is_directory=True)
                rejected = subprocess.run(
                    ["/bin/sh", "-c", function + '\nsecure_private_directory "$1"', "probe", str(link)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(rejected.returncode, 0, rejected)
                self.assertIn("Refusing unsafe SysWarden directory", rejected.stderr)
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_linux_remove_and_purge_contract(self) -> None:
        preremove = self.script("prerm.sh")
        self.assertNotIn("/tmp/sw_cron.bak", preremove)
        self.assertIn("mktemp -d /var/tmp/syswarden-cron.XXXXXX", preremove)
        self.assertIn("umask 077", preremove)
        self.assertIn(
            'cron_backup="${cron_work}/backup"',
            preremove,
        )
        self.assertIn('cron_error="${cron_work}/error"', preremove)
        self.assertIn('cron_filtered="${cron_work}/filtered"', preremove)
        self.assertIn('chmod 0700 "${cron_work}"', preremove)
        self.assertNotIn('${cron_backup}.error', preremove)
        self.assertNotIn('${cron_backup}.filtered', preremove)
        self.assertIn("syswarden_cleanup_crontab", preremove)
        self.assertIn(
            '"*/30 * * * * ${syswarden_cron_cli} ha-sync >/dev/null 2>&1"',
            preremove,
        )
        self.assertIn(
            '"${syswarden_cron_minute} * * * * ${syswarden_cron_cli} update-feeds >/dev/null 2>&1"',
            preremove,
        )
        self.assertIn("/opt/syswarden/bin/syswarden-cli || exit 1", preremove)
        self.assertNotIn(
            "grep -F -v '/opt/syswarden/bin/syswarden-cli'", preremove
        )
        self.assertNotIn("grep -v 'syswarden-cli'", preremove)
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
        self.assertIn('[ "$1" = "remove" ]', postremove)
        self.assertIn("[ -f /etc/alpine-release ]", postremove)
        self.assertIn("rm -rf /opt/syswarden", postremove)
        self.assertIn("rm -rf /etc/syswarden", postremove)
        self.assertIn("cleanup_generated_runtime_artifacts", postremove)
        for generated in (
            "/etc/systemd/system/syswarden-core.service",
            "/etc/systemd/system/syswarden-firewall.service",
            "/etc/systemd/system/syswarden-webtui.service",
            "/etc/init.d/syswarden-core",
            "/etc/init.d/syswarden-firewall",
            "/etc/init.d/syswarden-webtui",
            "/etc/bash_completion.d/syswarden",
            "/etc/rsyslog.d/99-syswarden-siem.conf",
            "/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
        ):
            self.assertIn(generated, postremove)
        self.assertIn("syswarden_cleanup_crontab", postremove)
        self.assertIn("cleanup_generated_runtime_artifacts || exit 1", postremove)
        self.assertNotIn("grep -F -v '/opt/syswarden/bin/syswarden-cli'", postremove)
        self.assertIn("[ -d /run/systemd/system ]", postremove)

    def test_package_cron_filters_are_exact_and_preserve_operator_bytes(self) -> None:
        for name, script, managed_paths in self.cron_script_matrix():
            functions = self.cron_functions(script)
            managed_lines = [
                line
                for path in managed_paths
                for line in (
                    f"*/30 * * * * {path} ha-sync >/dev/null 2>&1",
                    f"17 * * * * {path} update-feeds >/dev/null 2>&1",
                )
            ]
            primary = managed_paths[0]
            survivors = [
                "# operator note mentioning syswarden-cli",
                f"19 4 * * * {primary} update-feeds --operator-option",
                " " + managed_lines[0],
                managed_lines[1] + " ",
                managed_lines[1].replace("17 *", "17  *", 1),
                managed_lines[0].replace("*/30 *", "*/30\t*", 1),
                " \t ",
            ]
            alternate = (
                "23 * * * * /usr/local/syswarden/bin/syswarden-cli "
                "update-feeds >/dev/null 2>&1"
            )
            if "/usr/local/syswarden/bin/syswarden-cli" not in managed_paths:
                survivors.append(alternate)
            input_lines = [survivors[0], *managed_lines, *survivors[1:]]
            if alternate not in input_lines:
                input_lines.append(alternate)
            for final_lf in (False, True):
                with self.subTest(script=name, final_lf=final_lf), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source = root / "input"
                    destination = root / "output"
                    source_bytes = "\n".join(input_lines).encode("utf-8")
                    if final_lf:
                        source_bytes += b"\n"
                    managed_candidates = set(managed_lines)
                    if "/usr/local/syswarden/bin/syswarden-cli" in managed_paths:
                        managed_candidates.add(alternate)
                    expected = b""
                    for index, line in enumerate(input_lines):
                        if line in managed_candidates:
                            continue
                        expected += line.encode("utf-8")
                        if index < len(input_lines) - 1 or final_lf:
                            expected += b"\n"
                    source.write_bytes(source_bytes)
                    result = subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            functions
                            + '\nsyswarden_cron_source="$1"\n'
                            + 'syswarden_cron_destination="$2"\n'
                            + "shift 2\n"
                            + 'syswarden_filter_crontab "${syswarden_cron_source}" '
                            + '"${syswarden_cron_destination}" "$@"',
                            "cron-filter-contract",
                            str(source),
                            str(destination),
                            *managed_paths,
                        ],
                        check=False,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(destination.read_bytes(), expected)

    def test_package_cron_cleanup_distinguishes_absence_and_errors(self) -> None:
        matrix = self.cron_script_matrix()
        reference = self.cron_functions(matrix[0][1])
        for name, script, _paths in matrix[1:]:
            with self.subTest(shared_helper=name):
                self.assertEqual(self.cron_functions(script), reference)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_crontab = fake_bin / "crontab"
            fake_crontab.write_text(
                "#!/bin/sh\n"
                "record_cronie_backup() {\n"
                "  [ \"${CRONTAB_CREATE_BACKUP:-0}\" -eq 1 ] || return 0\n"
                "  [ -n \"${XDG_CACHE_HOME:-}\" ] || return 96\n"
                "  mkdir -p \"${XDG_CACHE_HOME}/crontab\" || return 1\n"
                "  printf 'previous cron\\n' > \"${XDG_CACHE_HOME}/crontab/crontab.bak\" || return 1\n"
                "  printf '%s' \"${XDG_CACHE_HOME}\" > \"${CRONTAB_CACHE_PATH_OUTPUT}\" || return 1\n"
                "}\n"
                "case \"${1:-}\" in\n"
                "  -l)\n"
                "    if [ -e \"${CRONTAB_REMOVED_MARKER}\" ]; then\n"
                "      printf '%s' \"${CRONTAB_VERIFY_STDOUT:-}\"\n"
                "      printf '%s' \"${CRONTAB_VERIFY_STDERR:-}\" >&2\n"
                "      exit \"${CRONTAB_VERIFY_RC:-1}\"\n"
                "    fi\n"
                "    printf '%s' \"${CRONTAB_STDOUT:-}\"\n"
                "    printf '%s' \"${CRONTAB_STDERR:-}\" >&2\n"
                "    exit \"${CRONTAB_READ_RC:-0}\"\n"
                "    ;;\n"
                "  -r)\n"
                "    record_cronie_backup || exit $?\n"
                "    crontab_remove_rc=${CRONTAB_REMOVE_RC:-0}\n"
                "    if [ \"${crontab_remove_rc}\" -eq 0 ]; then\n"
                "      : > \"${CRONTAB_REMOVED_MARKER}\"\n"
                "      if [ \"${CRONTAB_REMOVE_SPOOL:-0}\" -eq 1 ] && "
                "[ -n \"${SYSWARDEN_CRON_ABSENCE_SPOOL:-}\" ]; then\n"
                "        rm -f -- \"${SYSWARDEN_CRON_ABSENCE_SPOOL}\"\n"
                "      fi\n"
                "    fi\n"
                "    exit \"${crontab_remove_rc}\"\n"
                "    ;;\n"
                "  -)\n"
                "    record_cronie_backup || exit $?\n"
                "    cat > \"${CRONTAB_WRITE_OUTPUT}\"\n"
                "    exit \"${CRONTAB_WRITE_RC:-0}\"\n"
                "    ;;\n"
                "  *) exit 97 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_crontab.chmod(0o700)
            fake_cmp = fake_bin / "cmp"
            real_cmp = shutil.which("cmp")
            self.assertIsNotNone(real_cmp)
            fake_cmp.write_text(
                "#!/bin/sh\n"
                "if [ -n \"${CMP_FORCE_RC:-}\" ]; then\n"
                "  exit \"${CMP_FORCE_RC}\"\n"
                "fi\n"
                f'exec "{real_cmp}" "$@"\n',
                encoding="utf-8",
            )
            fake_cmp.chmod(0o700)
            fake_mktemp = fake_bin / "mktemp"
            real_mktemp = shutil.which("mktemp")
            self.assertIsNotNone(real_mktemp)
            fake_mktemp.write_text(
                "#!/bin/sh\n"
                "[ \"$#\" -eq 2 ] || exit 95\n"
                "[ \"$1\" = -d ] || exit 95\n"
                "[ \"$2\" = /var/tmp/syswarden-cron.XXXXXX ] || exit 95\n"
                "[ -n \"${SYSWARDEN_TEST_MKTEMP_ROOT:-}\" ] || exit 94\n"
                f'exec "{real_mktemp}" -d '
                '"${SYSWARDEN_TEST_MKTEMP_ROOT}/syswarden-cron.XXXXXX"\n',
                encoding="utf-8",
            )
            fake_mktemp.chmod(0o700)
            backup = root / "backup"
            error = root / "error"
            filtered = root / "filtered"
            written = root / "written"
            removed = root / "removed"
            command = [
                "/bin/sh",
                "-c",
                reference
                + '\nsyswarden_cleanup_crontab "$1" "$2" "$3" "$4"',
                "cron-cleanup-contract",
                str(backup),
                str(error),
                str(filtered),
                "/opt/syswarden/bin/syswarden-cli",
            ]

            def run_cleanup(**updates: str) -> subprocess.CompletedProcess[bytes]:
                written.unlink(missing_ok=True)
                removed.unlink(missing_ok=True)
                environment = os.environ.copy()
                environment.update(
                    {
                        "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                        "CRONTAB_WRITE_OUTPUT": str(written),
                        "CRONTAB_CACHE_PATH_OUTPUT": str(root / "cache-path"),
                        "CRONTAB_CREATE_BACKUP": "0",
                        "CRONTAB_REMOVED_MARKER": str(removed),
                        "CRONTAB_READ_RC": "0",
                        "CRONTAB_WRITE_RC": "0",
                        "CRONTAB_REMOVE_RC": "0",
                        "CRONTAB_REMOVE_SPOOL": "0",
                        "CRONTAB_STDOUT": "",
                        "CRONTAB_STDERR": "",
                        "CRONTAB_VERIFY_RC": "1",
                        "CRONTAB_VERIFY_STDOUT": "",
                        "CRONTAB_VERIFY_STDERR": "no crontab for root\n",
                        "CMP_FORCE_RC": "",
                        "SYSWARDEN_CRON_ABSENCE_SPOOL": "",
                        "SYSWARDEN_TEST_MKTEMP_ROOT": str(root),
                        **updates,
                    }
                )
                return subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    env=environment,
                )

            for message in (
                "no crontab for root",
                "crontab: no crontab for root",
                "crontab: can't open 'root': No such file or directory",
            ):
                for terminator in ("", "\n"):
                    with self.subTest(absence=message, terminator=repr(terminator)):
                        result = run_cleanup(
                            CRONTAB_READ_RC="1",
                            CRONTAB_STDERR=message + terminator,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertFalse(written.exists())
                        self.assertFalse(removed.exists())

            spool = root / "root-spool"
            spool.write_text("operator cron\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_READ_RC="1",
                CRONTAB_STDERR="crontab: no crontab for root\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists())
            spool.unlink()
            spool.symlink_to(root / "missing-spool-target")
            result = run_cleanup(
                CRONTAB_READ_RC="1",
                CRONTAB_STDERR="crontab: no crontab for root\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists())
            spool.unlink()

            for read_rc, stdout, message in (
                ("1", "", "permission denied\n"),
                ("1", "", "no crontab for root\nextra diagnostic\n"),
                ("1", "", " no crontab for root\n"),
                ("1", "", "no crontab for root \n"),
                ("2", "", "no crontab for root\n"),
                ("1", "partial stdout", "no crontab for root\n"),
            ):
                with self.subTest(read_rc=read_rc, stdout=stdout, read_error=message):
                    result = run_cleanup(
                        CRONTAB_READ_RC=read_rc,
                        CRONTAB_STDOUT=stdout,
                        CRONTAB_STDERR=message,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(written.exists())
                    self.assertFalse(removed.exists())

            managed = (
                "17 * * * * /opt/syswarden/bin/syswarden-cli "
                "update-feeds >/dev/null 2>&1"
            )
            operator = (
                "19 4 * * * /opt/syswarden/bin/syswarden-cli "
                "update-feeds --operator-option"
            )
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n" + operator,
                CRONTAB_STDERR="provider warning must not become cron input\n",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(written.read_bytes(), operator.encode("utf-8"))

            result = run_cleanup(CRONTAB_STDOUT=operator)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(written.exists(), "unchanged operator crontab was rewritten")
            self.assertFalse(removed.exists(), "operator crontab was removed")

            result = run_cleanup(CRONTAB_STDOUT="")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(written.exists(), "explicit empty crontab was rewritten")
            self.assertFalse(removed.exists(), "explicit empty crontab was removed")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CMP_FORCE_RC="2"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists(), "cmp error reached crontab write")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_WRITE_RC="23"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(removed.exists(), "managed-only crontab was not removed")
            self.assertFalse(written.exists(), "managed-only crontab was rewritten empty")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_REMOVE_RC="23"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(removed.exists())
            self.assertFalse(written.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_VERIFY_RC="0"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(removed.exists())
            self.assertFalse(written.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                CRONTAB_VERIFY_RC="2",
                CRONTAB_VERIFY_STDERR="permission denied\n",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(removed.exists())
            self.assertFalse(written.exists())

            spool.write_text(managed + "\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(spool.exists())
            spool.unlink()

            spool.symlink_to(root / "missing-spool-target")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(spool.is_symlink())
            spool.unlink()

            spool.write_text(managed + "\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
                CRONTAB_REMOVE_SPOOL="1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(spool.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n" + operator,
                CRONTAB_WRITE_RC="23",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(removed.exists())

            cache_path_output = root / "cache-path"
            prepared_command = [
                "/bin/sh",
                "-c",
                reference
                + "\numask 077\n"
                + "SYSWARDEN_CRON_ABSENCE_SPOOL=\n"
                + "cron_work=\n"
                + "trap 'syswarden_cleanup_cron_work' 0\n"
                + "trap 'syswarden_cleanup_cron_work; exit 129' 1\n"
                + "trap 'syswarden_cleanup_cron_work; exit 130' 2\n"
                + "trap 'syswarden_cleanup_cron_work; exit 143' 15\n"
                + "syswarden_prepare_cron_work || exit 1\n"
                + 'syswarden_cleanup_crontab "${cron_backup}" '
                + '"${cron_error}" "${cron_filtered}" "$1" || exit 1\n'
                + "syswarden_cleanup_cron_work || exit 1\n"
                + "trap - 0 1 2 15\n",
                "cronie-private-cache-contract",
                "/opt/syswarden/bin/syswarden-cli",
            ]
            for write_rc in ("0", "23"):
                with self.subTest(cronie_write_rc=write_rc):
                    written.unlink(missing_ok=True)
                    cache_path_output.unlink(missing_ok=True)
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                            "CRONTAB_WRITE_OUTPUT": str(written),
                            "CRONTAB_CACHE_PATH_OUTPUT": str(cache_path_output),
                            "CRONTAB_CREATE_BACKUP": "1",
                            "CRONTAB_READ_RC": "0",
                            "CRONTAB_STDOUT": managed + "\n" + operator,
                            "CRONTAB_STDERR": "",
                            "CRONTAB_WRITE_RC": write_rc,
                            "SYSWARDEN_TEST_MKTEMP_ROOT": str(root),
                        }
                    )
                    result = subprocess.run(
                        prepared_command,
                        check=False,
                        capture_output=True,
                        env=environment,
                    )
                    if write_rc == "0":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(written.read_bytes(), operator.encode("utf-8"))
                    else:
                        self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(
                        cache_path_output.exists(),
                        "private Cronie cache setup did not reach crontab: "
                        + result.stderr.decode("utf-8", errors="replace"),
                    )
                    cache_path = Path(
                        cache_path_output.read_text(encoding="utf-8")
                    )
                    self.assertEqual(cache_path.name, "cache")
                    self.assertTrue(cache_path.parent.name.startswith("syswarden-cron."))
                    self.assertFalse(
                        cache_path.parent.exists(),
                        "private Cronie cache work directory remains",
                    )
                    self.assertFalse(
                        (cache_path / "crontab" / "crontab.bak").exists(),
                        "Cronie backup remains outside cleanup",
                    )

    def test_active_local_package_builder_uses_exact_fail_closed_cron_cleanup(self) -> None:
        preremove = self.local_build_script("prerm.sh")
        self.assertIn("syswarden_cleanup_crontab", preremove)
        self.assertIn("/opt/syswarden/bin/syswarden-cli || exit 1", preremove)
        self.assertIn("mktemp -d /var/tmp/syswarden-cron.XXXXXX", preremove)
        self.assertIn("LC_ALL=C crontab -r", preremove)
        self.assertIn(
            'syswarden_read_crontab "${syswarden_cron_backup}" '
            '"${syswarden_cron_error}"',
            preremove,
        )
        self.assertIn('chmod 0700 "${cron_work}"', preremove)
        self.assertNotIn('${cron_backup}.error', preremove)
        self.assertNotIn('${cron_backup}.filtered', preremove)
        self.assertNotIn("grep -v 'syswarden-cli'", preremove)
        self.assertNotIn("grep -F -v '/opt/syswarden/bin/syswarden-cli'", preremove)

    def test_package_cron_signal_handlers_cleanup_and_never_succeed(self) -> None:
        handlers = (
            "trap 'syswarden_cleanup_cron_work' 0",
            "trap 'syswarden_cleanup_cron_work; exit 129' 1",
            "trap 'syswarden_cleanup_cron_work; exit 130' 2",
            "trap 'syswarden_cleanup_cron_work; exit 143' 15",
        )
        matrix = self.cron_script_matrix()
        for name, script, _paths in matrix:
            with self.subTest(handler_contract=name):
                for handler in handlers:
                    self.assertIn(handler, script)
                self.assertIn("mktemp -d", script)
                self.assertIn("syswarden_prepare_cron_work", script)
                self.assertIn('chmod 0700 "${cron_work}"', script)
                self.assertIn('cron_cache="${cron_work}/cache"', script)
                self.assertIn('chmod 0700 "${cron_cache}"', script)
                self.assertIn('XDG_CACHE_HOME="${cron_cache}"', script)
                self.assertIn("export XDG_CACHE_HOME", script)
                self.assertIn("unset XDG_CACHE_HOME", script)
                self.assertIn(
                    "private cron work directory remains after cleanup",
                    script,
                )
                self.assertIn('cron_backup="${cron_work}/backup"', script)
                self.assertIn('cron_error="${cron_work}/error"', script)
                self.assertIn('cron_filtered="${cron_work}/filtered"', script)
                self.assertIn("LC_ALL=C crontab -r", script)
                self.assertIn(
                    "crontab -r returned success but the root crontab is still present",
                    script,
                )
                self.assertNotIn('${cron_backup}.error', script)
                self.assertNotIn('${cron_backup}.filtered', script)
                if name == "workflow-freebsd-postrm":
                    self.assertIn(
                        "SYSWARDEN_CRON_ABSENCE_SPOOL=/var/cron/tabs/root",
                        script,
                    )
                else:
                    self.assertIn("SYSWARDEN_CRON_ABSENCE_SPOOL=\n", script)

        functions = self.cron_functions(matrix[0][1])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "private-cron-work"
            work.mkdir(mode=0o700)
            (work / "backup").write_text("operator cron\n", encoding="utf-8")
            ready = root / "ready"
            code = (
                functions
                + '\ncron_work="$1"\n'
                + "\n".join(handlers)
                + '\nprintf ready > "$2"\n'
                + "while :; do sleep 1; done\n"
            )
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    code,
                    "cron-signal-contract",
                    str(work),
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "signal probe did not become ready")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0, (stdout, stderr))
            self.assertFalse(work.exists(), "signal handler left private cron work")

    def test_linux_postinstall_does_not_treat_systemctl_presence_as_active_systemd(self) -> None:
        postinstall = self.script("postinst.sh")
        self.assertIn("systemd_running()", postinstall)
        self.assertIn("[ -d /run/systemd/system ]", postinstall)
        self.assertIn("systemctl daemon-reload\n", postinstall)
        self.assertIn("/opt/syswarden/bin/syswarden-cli reload\n", postinstall)
        self.assertNotIn("systemctl daemon-reload || true", postinstall)

    def test_linux_packages_declare_every_runtime_dependency(self) -> None:
        for dependency in (
            "wireguard-tools",
            "qrencode",
            "jq",
        ):
            self.assertGreaterEqual(
                self.workflow.count(f'-d "{dependency}"'),
                4,
                dependency,
            )
        for dependency in ("checkpolicy", "policycoreutils-python-utils"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 2)
        for dependency in ("wireguard-tools", "libqrencode-tools", "jq", "openrc"):
            self.assertGreaterEqual(
                self.workflow.count(f"            - {dependency}\n"),
                2,
                dependency,
            )

    def test_apk_fresh_and_upgrade_hooks_share_the_exact_postinstall_contract(self) -> None:
        workflow_postinstall = 'postinstall: "${PACKAGE_SCRIPTS}/postinst.sh"'
        workflow_postupgrade = 'postupgrade: "${PACKAGE_SCRIPTS}/postinst.sh"'
        workflow_apk_hook = (
            "          apk:\n"
            "            scripts:\n"
            '              postupgrade: "${PACKAGE_SCRIPTS}/postinst.sh"\n'
        )
        self.assertEqual(self.workflow.count(workflow_postinstall), 2)
        self.assertEqual(self.workflow.count(workflow_postupgrade), 2)
        self.assertEqual(self.workflow.count(workflow_apk_hook), 2)
        self.assertEqual(self.workflow.count("            - openrc\n"), 2)
        self.assertIn(".post-install$/", self.workflow)
        self.assertIn(".post-upgrade$/", self.workflow)
        self.assertIn("^depend = openrc$", self.workflow)
        self.assertIn('"${postinstall_members[0]}"', self.workflow)
        self.assertIn('"${postupgrade_members[0]}"', self.workflow)

        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(local.count('postinstall: "./postinst.sh"'), 1)
        self.assertEqual(local.count('postupgrade: "./postinst.sh"'), 1)
        self.assertEqual(
            local.count('apk:\n  scripts:\n    postupgrade: "./postinst.sh"\n'),
            1,
        )
        self.assertEqual(local.count("  - openrc\n"), 1)

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
        for command in (
            "service syswarden restart",
            "service syswarden onestatus",
            "service syswardenwebtui restart",
            "service syswardenwebtui onestatus",
        ):
            self.assertIn(command, postinstall)
        self.assertNotRegex(
            postinstall,
            r"service syswarden(?:webtui)? (?:restart|onestatus)\s*\|\|\s*true",
        )
        self.assertIn("/usr/local/syswarden/.postinstall-ok", preinstall)
        self.assertIn("syswarden-freebsd-postinstall-v1", postinstall)
        self.assertLess(
            postinstall.index("/usr/local/bin/syswarden install"),
            postinstall.index("syswarden-freebsd-postinstall-v1"),
        )
        self.assertIn("service syswarden onestop", preremove)
        self.assertIn("service syswarden onestatus", preremove)
        self.assertIn("service syswardenwebtui onestop", preremove)
        self.assertIn("service syswardenwebtui onestatus", preremove)
        self.assertIn("sysrc -x syswarden_enable || true", preremove)
        self.assertIn("set -eu", preremove)
        self.assertIn(
            "/usr/local/syswarden/bin/syswarden-cli package-restore-host-state",
            preremove,
        )
        self.assertIn(
            "/usr/local/syswarden/bin/syswarden-cli package-restore-pf",
            preremove,
        )
        self.assertLess(
            preremove.index("package-restore-host-state"),
            preremove.index("package-restore-pf"),
        )
        self.assertNotIn("pfctl -t", preremove)
        self.assertIn("rm -rf /usr/local/syswarden", postremove)
        self.assertIn("set -eu", postremove)
        self.assertNotIn("rm -rf /etc/syswarden", postremove)
        self.assertIn("syswarden_cleanup_crontab", postremove)
        self.assertIn("/usr/local/syswarden/bin/syswarden-cli", postremove)
        self.assertIn("/opt/syswarden/bin/syswarden-cli", postremove)
        self.assertIn("mktemp -d /var/tmp/syswarden-cron.XXXXXX", postremove)
        self.assertIn(
            "SYSWARDEN_CRON_ABSENCE_SPOOL=/var/cron/tabs/root",
            postremove,
        )
        self.assertIn('chmod 0700 "${cron_work}"', postremove)
        self.assertNotIn('${cron_backup}.error', postremove)
        self.assertNotIn('${cron_backup}.filtered', postremove)
        self.assertIn("/usr/local/etc/rsyslog.d/99-syswarden-siem.conf", postremove)
        self.assertIn("/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf", postremove)
        self.assertNotIn("service rsyslogd restart", postremove)
        self.assertIn("rmdir /var/db/syswarden", postremove)

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
                "/etc/syswarden/config/syswarden-auto.conf.bak",
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

    def test_package_formats_use_their_exact_linux_binary_variants(self) -> None:
        build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("BuildMode = 'pie'", build_script)
        self.assertNotIn("-ldflags=-s -w -d", build_script)
        self.assertIn("validate_linux_pie", self.workflow)
        self.assertIn("validate_static_apk_binary", self.workflow)
        self.assertIn("STAGING_APK_AMD64", self.workflow)
        self.assertIn("STAGING_APK_ARM64", self.workflow)
        self.assertIn('elf_type}" == "EXEC"', self.workflow)
        self.assertIn("CGO_ENABLED=0", self.workflow)
        self.assertIn(
            '"${STAGING_APK_AMD64}/opt/syswarden/bin/syswarden-cli" --help',
            self.workflow,
        )
        self.assertIn(
            "docker.io/library/alpine:3.22@sha256:"
            "7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6",
            self.workflow,
        )
        self.assertIn("/usr/local/bin/syswarden --help", self.workflow)
        for generic_root in ("STAGING_AMD64", "STAGING_ARM64"):
            with self.subTest(generic_root=generic_root):
                self.assertEqual(
                    self.workflow.count(f'-C "${{{generic_root}}}" .'),
                    2,
                )
        for apk_root in ("STAGING_APK_AMD64", "STAGING_APK_ARM64"):
            with self.subTest(apk_root=apk_root):
                self.assertIn(f'- src: "${{{apk_root}}}/opt"', self.workflow)

    def test_freebsd_package_uses_one_native_runtime_prefix(self) -> None:
        core_main = (
            REPOSITORY / "src" / "core" / "syswarden-core" / "main.go"
        ).read_text(encoding="utf-8")
        runtime_paths = (
            REPOSITORY
            / "src"
            / "core"
            / "syswarden-core"
            / "internal"
            / "runtimepaths"
            / "paths.go"
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
            "engine.NewEngine(runtimepaths.Signatures()",
            core_main,
        )
        self.assertIn('freeBSDInstallRoot = "/usr/local/syswarden"', runtime_paths)
        self.assertIn(
            'STAGING_FREEBSD="${PACKAGE_WORKSPACE}/staging-freebsd"',
            self.workflow,
        )
        self.assertRegex(
            self.workflow,
            r"cp\s+src/core/syswarden-core/signatures\.json\s+\\\s+"
            r'"\$\{STAGING_FREEBSD\}/usr/local/syswarden/"',
        )
        self.assertIn('command="/usr/local/syswarden/bin/syswarden-core"', service_source)
        self.assertIn('command="/usr/local/syswarden/bin/syswarden-cli"', service_source)
        self.assertNotIn('command="/opt/syswarden', service_source)
        self.assertIn('--freebsd-osversion 14', self.workflow)
        self.assertIn('.arch == "FreeBSD:14:amd64"', self.workflow)
        self.assertIn(
            "scripts/ci/freebsd_package_manifest.py", self.workflow
        )
        for dependency in (
            "curl",
            "jq",
            "libqrencode",
            "rsyslog",
            "wireguard-tools",
        ):
            with self.subTest(freebsd_dependency=dependency):
                self.assertIn(dependency, self.workflow)
        for script in ("syswarden", "syswardenwebtui"):
            with self.subTest(rc_script=script):
                self.assertIn(
                    f'"${{STAGING_FREEBSD}}/usr/local/etc/rc.d/{script}"',
                    self.workflow,
                )
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
