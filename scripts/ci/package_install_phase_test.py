#!/usr/bin/env python3
"""Test native phase transport without package installation or service commands."""

from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest

from scripts.ci import package_lifecycle_contract_test as contracts


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/ci/package_install_phase.sh"
LOCAL = ROOT / "build_packages.sh"
WORKFLOW = ROOT / ".github/workflows/package.yml"
INSTALL_CALL = 'syswarden_set_native_install_phase postinstall "$@"'
UPGRADE_CALL = 'syswarden_set_native_install_phase postupgrade "$@"'
WRAPPER_MARKER = "# APK upgrade has a fixed selector even when apk-tools supplies no phase environment.\n"


class PackageInstallPhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        contracts.PackageLifecycleContractTests.setUpClass()
        cls.contract = contracts.PackageLifecycleContractTests()

    def run_phase(self, alpine: bool, call: str, arguments: tuple[str, ...], inherited: str) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "alpine-release"
            if alpine:
                marker.write_text("3.24.0\n")
            helper = HELPER.read_text().replace("/etc/alpine-release", str(marker))
            result = subprocess.run(
                ["/bin/sh", "-eu", "-c", helper + "\n" + call +
                 '\n/bin/sh -c \'printf "%s\\n" "$SYSWARDEN_NATIVE_INSTALL_PHASE"\'',
                 "phase-contract", *arguments],
                env={"PATH": os.environ["PATH"], "LC_ALL": "C",
                     "SYSWARDEN_NATIVE_INSTALL_PHASE": inherited,
                     "APK_PACKAGE": "unrelated", "APK_SCRIPT": "post-install",
                     "syswarden_install_hook": "postinstall"},
                capture_output=True, text=True, check=False, timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def test_actual_deb_rpm_arguments_override_inherited_phase(self) -> None:
        cases = (
            (("configure",), "fresh"), (("configure", ""), "fresh"),
            (("configure", "4.10.4"), "upgrade"), (("configure", "1:4.10.4-1+b1"), "upgrade"),
            (("1",), "fresh"), (("2",), "upgrade"), (("23",), "upgrade"),
            (("999999999999999999999999999999",), "upgrade"),
            ((), "unknown"), (("",), "unknown"), (("0",), "unknown"),
            (("01",), "unknown"), (("-1",), "unknown"), (("1x",), "unknown"),
            (("1", "2"), "unknown"), (("configure", "4.10.4", "extra"), "unknown"),
            (("configure", "invalid version"), "unknown"), (("configure", "bad"), "unknown"),
            (("abort-upgrade", "4.10.4"), "unknown"), (("2\n",), "unknown"),
        )
        for inherited in ("fresh", "upgrade", "unknown", "spoofed"):
            for arguments, expected in cases:
                with self.subTest(inherited=inherited, arguments=arguments):
                    self.assertEqual(self.run_phase(False, INSTALL_CALL, arguments, inherited), expected)

    def test_apk_phase_comes_from_separate_fixed_call_not_environment(self) -> None:
        for inherited in ("fresh", "upgrade", "unknown", "spoofed"):
            for arguments in ((), ("5.00.0",), ("5.00.0", "4.10.4")):
                self.assertEqual(self.run_phase(True, INSTALL_CALL, arguments, inherited), "fresh")
                self.assertEqual(self.run_phase(True, UPGRADE_CALL, arguments, inherited), "upgrade")
        for alpine in (False, True):
            for call in ('syswarden_set_native_install_phase', 'syswarden_set_native_install_phase invalid "$@"'):
                self.assertEqual(self.run_phase(alpine, call, (), "fresh"), "unknown")
        self.assertEqual(self.run_phase(False, UPGRADE_CALL, ("1",), "fresh"), "unknown")

    def generated_upgrade(self, source: str, installed: str, directory: Path) -> subprocess.CompletedProcess[str]:
        block = source.split(WRAPPER_MARKER, 1)[1].split("chmod ", 1)[0]
        block = textwrap.dedent(block)
        (directory / "postinst.sh").write_text(installed)
        return subprocess.run(
            ["/bin/bash", "-eu", "-c", 'PACKAGE_SCRIPTS="$1"\n' + block,
             "wrapper-contract", str(directory)],
            cwd=directory, env={"PATH": os.environ["PATH"], "LC_ALL": "C"},
            capture_output=True, text=True, check=False, timeout=5,
        )

    def test_real_local_and_public_wrapper_generation_changes_only_phase(self) -> None:
        outputs = []
        for source, loader in (
            (LOCAL.read_text(), self.contract.local_build_script),
            (WORKFLOW.read_text(), self.contract.script),
        ):
            installed = loader("postinst.sh")
            self.assertEqual(installed.count("\n" + INSTALL_CALL + "\n"), 1)
            self.assertLess(installed.index("\n" + INSTALL_CALL), installed.index("\nsyswarden_preflight_alpine_cronie\n"))
            self.assertIn(HELPER.read_text(), installed)
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = self.generated_upgrade(source, installed, directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                upgraded = (directory / "postupgrade.sh").read_text()
                self.assertEqual(upgraded, installed.replace("\n" + INSTALL_CALL + "\n", "\n" + UPGRADE_CALL + "\n"))
                outputs.append(upgraded)
            for invalid in (installed.replace(INSTALL_CALL, "true"), installed + "\n" + INSTALL_CALL + "\n"):
                with tempfile.TemporaryDirectory() as temporary:
                    result = self.generated_upgrade(source, invalid, Path(temporary))
                    self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs[0], outputs[1])

    def test_packagers_bind_permission_timestamp_and_integrity_to_upgrade_wrapper(self) -> None:
        local, workflow = LOCAL.read_text(), WORKFLOW.read_text()
        self.assertIn('postupgrade: "./postupgrade.sh"', local)
        self.assertIn('postupgrade: "${SELECTED_PACKAGE_SCRIPTS}/postupgrade.sh"', workflow)
        self.assertIn("chmod +x preinst.sh postinst.sh postupgrade.sh postrm.sh prerm.sh", local)
        self.assertRegex(workflow, r'chmod 0755 \\\n(?:.*\\\n)*\s*"\$\{PACKAGE_SCRIPTS\}/postupgrade.sh"')
        self.assertIn("    postupgrade.sh \\\n", local)
        for source in (local, workflow):
            self.assertIn("package_install_phase.sh", source)
        self.assertIn('"${SELECTED_PACKAGE_SCRIPTS}/postupgrade.sh" \\\n              <(tar --extract', workflow)
        self.assertIn('if ! validate_local_apk_install_hooks \\\n', local)
        self.assertIn('scripts/ci/package_install_phase_test.py \\\n', workflow)
        variants = contracts.variant_contracts
        for version in ("4.10.4", "5.00.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                environment = variants.workflow_fixture(Path(temporary), version)
                result = variants.bash(
                    variants.fixture_shell(environment)
                    + variants.workflow_step("Prepare Linux Maintainer Scripts")
                    + variants.workflow_step("Normalize Package Input Timestamps")
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                names = ("",) if version.startswith("4.") else ("syswarden", "syswarden-base")
                for name in names:
                    scripts = Path(environment["PACKAGE_SCRIPTS"]) / name
                    installed = (scripts / "postinst.sh").read_bytes()
                    upgraded = scripts / "postupgrade.sh"
                    self.assertEqual(installed.count(INSTALL_CALL.encode()), 1)
                    self.assertEqual(upgraded.read_bytes(), installed.replace(INSTALL_CALL.encode(), UPGRADE_CALL.encode()))
                    self.assertEqual(upgraded.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(int(upgraded.stat().st_mtime), int(environment["SOURCE_DATE_EPOCH"]))

    def test_local_archive_validation_rejects_fresh_upgrade_missing_and_duplicate_hooks(self) -> None:
        function = "validate_local_apk_install_hooks() {" + LOCAL.read_text().split("validate_local_apk_install_hooks() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "postinst.sh").write_bytes(b"fresh\n")
            (directory / "postupgrade.sh").write_bytes(b"upgrade\n")
            for members, accepted in (
                (((".post-install", b"fresh\n"), (".post-upgrade", b"upgrade\n")), True),
                (((".post-install", b"fresh\n"), (".post-upgrade", b"fresh\n")), False),
                (((".post-install", b"fresh\n"),), False),
                (((".post-install", b"fresh\n"), (".post-upgrade", b"upgrade\n"), ("./.post-upgrade", b"upgrade\n")), False),
            ):
                archive = directory / "fixture.apk"
                with tarfile.open(archive, "w:gz") as output:
                    for name, content in members:
                        member = tarfile.TarInfo(name)
                        member.size = len(content)
                        output.addfile(member, io.BytesIO(content))
                result = subprocess.run(
                    ["/bin/bash", "-eu", "-c", 'PACKAGE_WORKSPACE="$1"\n' + function + '\nvalidate_local_apk_install_hooks "$2"',
                     "archive-contract", str(directory), str(archive)],
                    env={"PATH": os.environ["PATH"], "LC_ALL": "C"},
                    capture_output=True, check=False, timeout=5,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)


if __name__ == "__main__":
    unittest.main()
