#!/usr/bin/env python3
"""Exercise actual native hook bodies with inert filesystem and runtime adapters."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import textwrap
import unittest

from scripts.ci import package_lifecycle_contract_test as contracts


ROOT = Path(__file__).resolve().parents[2]
FRESH_BRANCH = 'if [ "${SYSWARDEN_NATIVE_INSTALL_PHASE:-unknown}" = fresh ]; then'
CLI = "/opt/syswarden/bin/syswarden-cli"


class FreshPackageConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        contracts.PackageLifecycleContractTests.setUpClass()
        cls.contract = contracts.PackageLifecycleContractTests()

    def run_hook(self, hook: str, family: str, phase: str, before: bool, *, barrier: str = "0", offline: bool = False, cli_exit: int = 0, launcher_exit: int = 0):
        # Run the complete emitted maintainer body, not only its new branch.
        # All host operations are replaced before executing that body.
        body = hook[hook.rindex("\nset -e\nexport SYSWARDEN_PKG_INSTALL=1") + 1:]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events"
            alpine = root / "alpine-release"
            if family == "apk":
                alpine.write_text("3.24.0\n")
            helper = (ROOT / "scripts/ci/package_install_phase.sh").read_text().replace("/etc/alpine-release", str(alpine))
            stub = root / "cli"
            stub.write_text('#!/bin/sh\nprintf "cli:%s:%s\\n" "$SYSWARDEN_NATIVE_INSTALL_PHASE" "$*" >> "$EVENTS"\nexit "$CLI_EXIT"\n')
            stub.chmod(0o700)
            body = body.replace(CLI, shlex.quote(str(stub))).replace("/etc/alpine-release", str(alpine))
            arguments = {
                ("deb", "fresh", True): ("install",), ("deb", "upgrade", True): ("upgrade", "4.10.4", "5.00.0"),
                ("deb", "fresh", False): ("configure",), ("deb", "upgrade", False): ("configure", "4.10.4"),
                ("rpm", "fresh", True): ("1",), ("rpm", "upgrade", True): ("2",),
                ("rpm", "fresh", False): ("1",), ("rpm", "upgrade", False): ("2",),
                ("apk", "fresh", True): ("5.00.0-r0",), ("apk", "upgrade", True): ("5.00.0-r0", "4.10.4"),
                ("apk", "fresh", False): ("5.00.0-r0",), ("apk", "upgrade", False): ("5.00.0-r0", "4.10.4"),
            }.get((family, phase, before), ("abort-upgrade",))
            definitions = '''
forbidden() { printf 'forbidden:%s\n' "$1" >> "$EVENTS"; return 97; }
for operation in mkdir chmod ln mv rm find stat id sync syswarden_preflight_alpine_cronie syswarden_retire_legacy_webtui syswarden_classify_service_manager syswarden_verify_webtui_retirement syswarden_consume_deferred_purge_marker; do
    eval "$operation() { forbidden '$operation'; }"
done
syswarden_preflight_launchers() { printf 'launchers:%s\n' "$2" >> "$EVENTS"; return "$LAUNCHER_EXIT"; }
syswarden_preflight_wireguard() { printf 'wireguard\n' >> "$EVENTS"; }
syswarden_preflight_systemd_ordering_dropin() { printf 'ordering\n' >> "$EVENTS"; }
syswarden_preflight_systemd_socket_dropin() { printf 'socket\n' >> "$EVENTS"; }
syswarden_preflight_install_barriers() {
    printf 'barriers\n' >> "$EVENTS"
    syswarden_deferred_present="$BARRIER"
    syswarden_finalizing_present=0
}
'''
            result = subprocess.run(
                ["/bin/sh", "-eu", "-c", helper + definitions + body, "fresh-hook-contract", *arguments],
                env={"PATH": os.environ["PATH"], "LC_ALL": "C", "EVENTS": str(events), "BARRIER": barrier,
                     "CLI_EXIT": str(cli_exit), "LAUNCHER_EXIT": str(launcher_exit), "SYSWARDEN_PKG_INSTALL": "1", "SYSWARDEN_NATIVE_INSTALL_PHASE": "fresh",
                     "SYSWARDEN_OFFLINE_QUALIFICATION": "1" if offline else ""},
                capture_output=True, text=True, check=False, timeout=5,
            )
            observed = events.read_text().splitlines() if events.exists() else []
        return result, observed

    def test_whole_fresh_hooks_stage_only_config_without_runtime_or_legacy_work(self) -> None:
        for source, loader in (("local", self.contract.local_build_script), ("workflow", self.contract.script)):
            for before, name in ((True, "preinst.sh"), (False, "postinst.sh")):
                hook = loader(name)
                for family in ("deb", "rpm", "apk"):
                    with self.subTest(source=source, family=family, hook=name):
                        result, events = self.run_hook(hook, family, "fresh", before)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(events, ["launchers:before", "wireguard", "barriers", "ordering", "socket"] if before else ["launchers:after", "barriers", "cli:fresh:install"])
                        result, events = self.run_hook(hook, family, "fresh", before, barrier="1")
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(events, ["launchers:before", "wireguard", "barriers", "ordering", "socket"] if before else ["launchers:after", "barriers"])
                        result, events = self.run_hook(hook, family, "fresh", before, offline=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(events, ["launchers:before", "wireguard", "barriers", "ordering", "socket"] if before else ["launchers:after", "barriers"])
                if not before:
                    result, events = self.run_hook(hook, "apk", "fresh", False, cli_exit=23)
                    self.assertEqual(result.returncode, 23)
                    self.assertEqual(events, ["launchers:after", "barriers", "cli:fresh:install"])
                    self.assertLess(hook.index(FRESH_BRANCH), hook.index("migrate_legacy_configuration\n"))

    def test_fresh_launcher_refusal_precedes_other_work_and_upgrade_is_refused_first(self) -> None:
        for loader in (self.contract.local_build_script, self.contract.script):
            for family in ("deb", "rpm", "apk"):
                for phase in ("fresh", "upgrade"):
                    for before, name, upgraded in ((True, "preinst.sh", "preupgrade.sh"), (False, "postinst.sh", "postupgrade.sh")):
                        hook = loader(upgraded if family == "apk" and phase == "upgrade" else name)
                        with self.subTest(family=family, phase=phase, before=before):
                            result, events = self.run_hook(hook, family, phase, before, launcher_exit=31)
                            self.assertEqual(result.returncode, 31 if phase == "fresh" else 1, result.stderr)
                            self.assertEqual(events, ["launchers:before" if before else "launchers:after"] if phase == "fresh" else [])

    def test_upgrade_and_unknown_hooks_never_enter_fresh_staging(self) -> None:
        for loader in (self.contract.local_build_script, self.contract.script):
            for family in ("deb", "rpm", "apk"):
                for before, name, upgraded in ((True, "preinst.sh", "preupgrade.sh"), (False, "postinst.sh", "postupgrade.sh")):
                    for phase in ("upgrade", "unknown"):
                        if family == "apk" and phase == "unknown":
                            continue  # APK operation is fixed by its exact generated script.
                        hook = loader(upgraded if family == "apk" else name)
                        for offline in (False, True):
                            result, events = self.run_hook(hook, family, phase, before, offline=offline)
                            self.assertEqual(result.returncode, 1, result.stderr)
                            self.assertIn("separately approved coordinated native transaction", result.stderr)
                            self.assertEqual(events, [])

    def test_upgrade_manager_dispositions_remain_unchanged(self) -> None:
        for loader in (self.contract.local_build_script, self.contract.script):
            hook = loader("postinst.sh")
            start = hook.index('if [ "$1" = "2" ]')
            block = textwrap.dedent(hook[start:hook.index("syswarden_verify_webtui_retirement /", start)])
            for manager, accepted, expected in (("ACTIVE", True, "cli\n"), ("OFFLINE", True, ""), ("AMBIGUOUS", False, "")):
                script = 'package_service_manager() { printf systemd; }\nsyswarden_classify_service_manager() { printf "%s" "$MANAGER"; }\n'
                script += block.replace(CLI + " install", "printf 'cli\\n'")
                result = subprocess.run(["/bin/sh", "-eu", "-c", script, "upgrade-contract", "2"],
                                        env={"PATH": os.environ["PATH"], "MANAGER": manager}, capture_output=True, text=True, check=False, timeout=5)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if manager == "ACTIVE":
                    self.assertEqual(result.stdout, expected)
                else:
                    self.assertNotIn("cli\n", result.stdout)

    def test_unqualified_rhel_profile_is_closed_for_v5_only(self) -> None:
        local = (ROOT / "build_packages.sh").read_text()
        start = local.index('if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then\n    case "${VERSION}"')
        guard = local[start:local.index("\nfi", start) + 3]
        for version, enabled, accepted in (("4.10.4", "1", True), ("5.00.0", "1", False), ("5.00.0", "0", True)):
            result = subprocess.run(["/bin/bash", "-eu", "-c", guard],
                                    env={"PATH": os.environ["PATH"], "VERSION": version, "RHEL_PACKAGE_OWNED_PROFILE": enabled},
                                    capture_output=True, text=True, check=False, timeout=5)
            self.assertEqual(result.returncode == 0, accepted, result.stderr)
        workflow = (ROOT / ".github/workflows/package.yml").read_text()
        for name in ("Stage Opt-in RHEL Package-owned RPM Payload", "Build Opt-in RHEL Package-owned Variant (.rpm)",
                     "Validate Opt-in RHEL Package-owned Variant", "Generate Opt-in RHEL Package-owned Checksums"):
            self.assertIn(f"- name: {name}\n        if: startsWith(env.VERSION, '4.')", workflow)
            body = contracts.workflow_step_script(workflow, name)
            result = subprocess.run(["/bin/bash", "-eu", "-c", body],
                                    env={"PATH": os.environ["PATH"], "VERSION": "5.00.0"},
                                    capture_output=True, text=True, check=False, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("generation is unavailable for v5", result.stderr)
        for expression in ("!github.event.act", "github.event.act"):
            self.assertIn("if: ${{ " + expression + " && startsWith(env.VERSION, '4.') }}", workflow)

    def test_workflow_runs_this_contract(self) -> None:
        self.assertIn("scripts/ci/package_fresh_configuration_test.py \\\n", (ROOT / ".github/workflows/package.yml").read_text())


if __name__ == "__main__":
    unittest.main()
