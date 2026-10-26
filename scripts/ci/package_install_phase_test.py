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
PREINSTALL_CALL = 'syswarden_set_native_install_phase preinstall "$@"'
PREUPGRADE_CALL = 'syswarden_set_native_install_phase preupgrade "$@"'
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
                self.assertEqual(self.run_phase(True, PREINSTALL_CALL, arguments, inherited), "fresh")
                self.assertEqual(self.run_phase(True, PREUPGRADE_CALL, arguments, inherited), "upgrade")
        for alpine in (False, True):
            for call in ('syswarden_set_native_install_phase', 'syswarden_set_native_install_phase invalid "$@"'):
                self.assertEqual(self.run_phase(alpine, call, (), "fresh"), "unknown")
        self.assertEqual(self.run_phase(False, UPGRADE_CALL, ("1",), "fresh"), "unknown")

    def test_preinstall_deb_rpm_arguments_are_closed_and_do_not_trust_inheritance(self) -> None:
        cases = (
            (("install",), "fresh"), (("install", ""), "fresh"), (("install", "", "5.00.0"), "fresh"),
            (("install", "4.10.4"), "unknown"), (("install", "4.10.4", "5.00.0"), "unknown"),
            (("upgrade", "4.10.4"), "upgrade"), (("upgrade", "4.10.4", "5.00.0"), "upgrade"),
            (("1",), "fresh"), (("2",), "upgrade"), (("23",), "upgrade"),
            ((), "unknown"), (("install", "", "bad version"), "unknown"),
            (("install", "", "bad"), "unknown"), (("install", "", "5.00.0", "extra"), "unknown"),
            (("upgrade",), "unknown"), (("upgrade", ""), "unknown"), (("upgrade", "bad version"), "unknown"),
            (("configure",), "unknown"), (("01",), "unknown"), (("1", "2"), "unknown"),
        )
        for inherited in ("fresh", "upgrade", "spoofed"):
            for arguments, expected in cases:
                with self.subTest(inherited=inherited, arguments=arguments):
                    self.assertEqual(self.run_phase(False, PREINSTALL_CALL, arguments, inherited), expected)

    def generated_upgrade(self, source: str, installed: str, directory: Path, preinstalled: str) -> subprocess.CompletedProcess[str]:
        block = source.split(WRAPPER_MARKER, 1)[1].split("chmod ", 1)[0]
        block = textwrap.dedent(block)
        (directory / "postinst.sh").write_text(installed)
        (directory / "preinst.sh").write_text(preinstalled)
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
            preinstalled = loader("preinst.sh")
            self.assertEqual(installed.count("\n" + INSTALL_CALL + "\n"), 1)
            self.assertLess(installed.index("\n" + INSTALL_CALL), installed.index("\nsyswarden_preflight_alpine_cronie\n"))
            self.assertIn(HELPER.read_text(), installed)
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = self.generated_upgrade(source, installed, directory, preinstalled)
                self.assertEqual(result.returncode, 0, result.stderr)
                upgraded = (directory / "postupgrade.sh").read_text()
                self.assertEqual(upgraded, installed.replace("\n" + INSTALL_CALL + "\n", "\n" + UPGRADE_CALL + "\n"))
                self.assertEqual((directory / "preupgrade.sh").read_text(), preinstalled.replace("\n" + PREINSTALL_CALL + "\n", "\n" + PREUPGRADE_CALL + "\n"))
                outputs.append(upgraded)
            for invalid in (installed.replace(INSTALL_CALL, "true"), installed + "\n" + INSTALL_CALL + "\n"):
                with tempfile.TemporaryDirectory() as temporary:
                    result = self.generated_upgrade(source, invalid, Path(temporary), preinstalled)
                    self.assertNotEqual(result.returncode, 0)
            for invalid in (preinstalled.replace(PREINSTALL_CALL, "true"), preinstalled + "\n" + PREINSTALL_CALL + "\n"):
                with tempfile.TemporaryDirectory() as temporary:
                    result = self.generated_upgrade(source, installed, Path(temporary), invalid)
                    self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs[0], outputs[1])

    def test_packagers_bind_permission_timestamp_and_integrity_to_upgrade_wrapper(self) -> None:
        local, workflow = LOCAL.read_text(), WORKFLOW.read_text()
        self.assertIn('preupgrade: "./preupgrade.sh"', local)
        self.assertIn('preupgrade: "${SELECTED_PACKAGE_SCRIPTS}/preupgrade.sh"', workflow)
        self.assertIn('postupgrade: "./postupgrade.sh"', local)
        self.assertIn('postupgrade: "${SELECTED_PACKAGE_SCRIPTS}/postupgrade.sh"', workflow)
        self.assertIn("chmod +x preinst.sh preupgrade.sh postinst.sh postupgrade.sh postrm.sh prerm.sh", local)
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
                    preinstalled = (scripts / "preinst.sh").read_bytes()
                    preupgraded = scripts / "preupgrade.sh"
                    self.assertEqual(preinstalled.count(PREINSTALL_CALL.encode()), 1)
                    self.assertEqual(preupgraded.read_bytes(), preinstalled.replace(PREINSTALL_CALL.encode(), PREUPGRADE_CALL.encode()))
                    self.assertEqual(preupgraded.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(int(preupgraded.stat().st_mtime), int(environment["SOURCE_DATE_EPOCH"]))

    def test_local_archive_validation_rejects_fresh_upgrade_missing_and_duplicate_hooks(self) -> None:
        function = "validate_local_apk_install_hooks() {" + LOCAL.read_text().split("validate_local_apk_install_hooks() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "preinst.sh").write_bytes(b"pre-fresh\n")
            (directory / "preupgrade.sh").write_bytes(b"pre-upgrade\n")
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
                    for name, content in ((".pre-install", b"pre-fresh\n"), (".pre-upgrade", b"pre-upgrade\n")) + members:
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

class PackageLauncherPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sw-launcher-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.helper = HELPER.read_text().replace("!= 0:0", f"!= {os.getuid()}:{os.getgid()}")
        self.bin = self.root / "usr/local/bin"
        self.bin.mkdir(parents=True, mode=0o755)

    def run_gate(self, phase: str, helper: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-eu", "-c", (helper or self.helper) +
             '\nsyswarden_preflight_launchers "$1" "$2"',
             "launcher-contract", str(self.root), phase],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, text=True, check=False, timeout=5,
        )

    def links(self) -> None:
        for name, target in (("syswarden", "syswarden-cli"), ("syswarden-tui", "syswarden-tui")):
            (self.bin / name).symlink_to("/opt/syswarden/bin/" + target)

    def snapshot(self) -> list[tuple]:
        rows = []
        for path in sorted(self.root.rglob("*")):
            item = path.lstat()
            content = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            rows.append((str(path.relative_to(self.root)), item.st_dev, item.st_ino, item.st_mode,
                         item.st_uid, item.st_gid, item.st_nlink, item.st_size,
                         item.st_mtime_ns, item.st_ctime_ns, content))
        return rows

    def test_absent_before_unpack_and_exact_payload_after_unpack(self) -> None:
        before = self.snapshot()
        self.assertEqual(self.run_gate("before").returncode, 0)
        self.assertNotEqual(self.run_gate("after").returncode, 0)
        self.assertEqual(self.snapshot(), before)
        self.links()
        before = self.snapshot()
        for phase in ("before", "after"):
            result = self.run_gate(phase)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            self.assertEqual(self.snapshot(), before)

    def test_missing_parents_are_not_created(self) -> None:
        self.bin.rmdir()
        self.bin.parent.rmdir()
        self.bin.parent.parent.rmdir()
        before = self.snapshot()
        self.assertEqual(self.run_gate("before").returncode, 0)
        self.assertNotEqual(self.run_gate("after").returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_each_administrator_collision_is_preserved_without_disclosure(self) -> None:
        for name in ("syswarden", "syswarden-tui"):
            for kind in ("wrapper", "directory", "fifo", "redirect", "broken", "newline"):
                with self.subTest(name=name, kind=kind):
                    path = self.bin / name
                    if kind == "wrapper":
                        path.write_bytes(b"PRIVATE-OPERATOR-FIXTURE\n")
                        path.chmod(0o755)
                    elif kind == "directory":
                        path.mkdir()
                    elif kind == "fifo":
                        os.mkfifo(path)
                    else:
                        target = "/opt/syswarden/bin/" + ("syswarden-cli" if name == "syswarden" else name)
                        path.symlink_to(target + "\n" if kind == "newline" else "/PRIVATE-OPERATOR-FIXTURE/" + kind)
                    before = self.snapshot()
                    for phase in ("before", "after"):
                        result = self.run_gate(phase)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("PRIVATE-OPERATOR-FIXTURE", result.stdout + result.stderr)
                        self.assertEqual(self.snapshot(), before)
                    path.rmdir() if kind == "directory" else path.unlink()

    def test_unsafe_parent_and_link_metadata_refuse(self) -> None:
        self.links()
        for parent in (self.root / "usr", self.bin.parent, self.bin):
            previous = parent.stat().st_mode & 0o777
            parent.chmod(0o777)
            before = self.snapshot()
            self.assertNotEqual(self.run_gate("before").returncode, 0)
            self.assertEqual(self.snapshot(), before)
            parent.chmod(previous)
        path = self.bin / "syswarden"
        os.link(path, self.bin / "operator-hardlink", follow_symlinks=False)
        before = self.snapshot()
        self.assertNotEqual(self.run_gate("before").returncode, 0)
        self.assertEqual(self.snapshot(), before)
        (self.bin / "operator-hardlink").unlink()
        helper = self.helper.replace(f"!= {os.getuid()}:{os.getgid()}:1", "!= 4294967294:4294967294:1")
        self.assertNotEqual(self.run_gate("before", helper).returncode, 0)

    def test_symlink_parent_refuses_without_following_it(self) -> None:
        self.bin.rmdir()
        alternate = self.root / "PRIVATE-OPERATOR-FIXTURE"
        alternate.mkdir()
        self.bin.symlink_to(alternate, target_is_directory=True)
        before = self.snapshot()
        result = self.run_gate("before")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PRIVATE-OPERATOR-FIXTURE", result.stdout + result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_actual_generated_hooks_screen_before_payload_and_host_actions(self) -> None:
        contracts.PackageLifecycleContractTests.setUpClass()
        contract = contracts.PackageLifecycleContractTests()
        for loader in (contract.local_build_script, contract.script):
            for hook, phase in (("preinst.sh", "before"), ("postinst.sh", "after")):
                with self.subTest(loader=loader.__name__, hook=hook):
                    source = loader(hook)
                    call = f"\nsyswarden_preflight_launchers / {phase}\n"
                    self.assertEqual(source.count(call), 1)
                    self.assertLess(source.index(call), source.index("\nsyswarden_preflight_install_barriers\n"))
                    self.assertNotIn("ln -sf /opt/syswarden/bin/", source)
                    prefix = source.split(call, 1)[0] + call.replace(" / ", f' "{self.root}" ')
                    prefix = prefix.replace("!= 0:0", f"!= {os.getuid()}:{os.getgid()}")
                    path = self.bin / "syswarden"
                    path.write_bytes(b"PRIVATE-OPERATOR-FIXTURE\n")
                    before = self.snapshot()
                    result = subprocess.run(
                        ["/bin/sh", "-eu", "-c", prefix, "hook-contract", "1"],
                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("command launcher", result.stderr)
                    self.assertEqual(self.snapshot(), before)
                    path.unlink()

    def test_unknown_phase_refuses(self) -> None:
        for phase in ("", "upgrade", "fresh", "after\n"):
            self.assertNotEqual(self.run_gate(phase).returncode, 0)


if __name__ == "__main__":
    unittest.main()
