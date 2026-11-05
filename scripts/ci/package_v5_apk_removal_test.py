#!/usr/bin/env python3
"""Version-bound contracts for reviewed Alpine removal fixtures."""

from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_lifecycle_lab as lab


class V5APKRemovalTests(unittest.TestCase):
    def test_recovery_payload_requires_exact_files_modes_links_and_digests(self):
        helper = Path(__file__).with_name("package_v5_apk_removal.sh").read_text()
        for mutation in ("none", "missing", "changed", "mode", "linked", "symlink", "extra", "public-parent", "nonexecutable"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private = root / "private"
                saved = private / ("apk-payload-" + "a" * 64)
                (saved / "bin").mkdir(parents=True)
                private.chmod(0o700)
                saved.chmod(0o750)
                (saved / "bin").chmod(0o750)
                (root / "results").mkdir()
                inventory = []
                for relative in ("bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"):
                    payload = b'#!/bin/sh\n[ "$1" = --help ]\n' if relative.endswith("-cli") else relative.encode()
                    path = saved / relative
                    path.write_bytes(payload)
                    mode = 0o640 if relative == "signatures.json" else 0o750
                    path.chmod(mode)
                    inventory.append(f"/opt/syswarden/{relative}\tfile\t{mode:o}\t0\t0\t{hashlib.sha256(payload).hexdigest()}\n")
                (root / "inventory-candidate").write_text("".join(inventory))
                victim = saved / "bin/syswarden-core"
                if mutation == "missing":
                    victim.unlink()
                elif mutation == "changed":
                    victim.write_bytes(b"changed")
                elif mutation == "mode":
                    victim.chmod(0o755)
                elif mutation == "linked":
                    os.link(victim, root / "hardlink")
                elif mutation == "symlink":
                    victim.rename(root / "original")
                    victim.symlink_to(root / "original")
                elif mutation == "extra":
                    (saved / "unexpected").mkdir()
                elif mutation == "public-parent":
                    private.chmod(0o755)
                elif mutation == "nonexecutable":
                    (saved / "bin/syswarden-cli").chmod(0o640)
                script = helper.replace("/var/backups/syswarden-retired-v1", str(private)).replace("/results", str(root / "results"))
                # Normalize only this test user's UID/GID into the fixture's
                # container-root coordinates. Real native tests use real stat.
                script += f'''
stat() {{ command stat "$@" | sed 's/^{os.getuid()}:{os.getgid()}:/0:0:/'; }}
hash_file() {{ sha256sum "$1" | cut -d ' ' -f 1; }}
PERSIST_ROOT='{root}'
assert_apk_recovery_payload
'''
                result = subprocess.run(["sh", "-eu", "-c", script], capture_output=True, text=True)
                if mutation == "none":
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, mutation)

    def test_recreated_generated_files_and_links_fail_the_restart_inventory(self):
        helper = Path(__file__).with_name("package_v5_apk_removal.sh").read_text()
        function = helper[helper.index("assert_v5_generated_artifacts_absent() {"):]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = function.replace("\n/etc/", f"\n{root}/etc/").replace("\n/run/", f"\n{root}/run/")
            def probe():
                return subprocess.run(["sh", "-eu", "-c", script + "\nassert_v5_generated_artifacts_absent"], capture_output=True)
            self.assertEqual(probe().returncode, 0)
            for relative in ("etc/modprobe.d/syswarden-cis-fs.conf", "etc/rsyslog.d/99-syswarden-antiforging.conf", "etc/init.d/syswarden-firewall"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                for kind in ("file", "dangling-link"):
                    with self.subTest(relative=relative, kind=kind):
                        if kind == "file":
                            path.write_text("recreated\n")
                        else:
                            path.symlink_to(root / "missing")
                        self.assertNotEqual(probe().returncode, 0)
                        path.unlink()

    def test_recovery_checks_are_required_only_for_v5_apk_removal(self):
        for scenario in ("remove", "purge"):
            current = lab.expected_event_checks("apk", scenario, candidate_version="5.00.0")
            old = lab.expected_event_checks("apk", scenario, candidate_version="4.10.4")
            for key in ("reviewed-cron-recovery", "reviewed-list-recovery", "reviewed-ui-config-recovery"):
                self.assertIn(f"{scenario}.{key}", current)
                self.assertNotIn(f"{scenario}.{key}", old)
            self.assertIn(f"{scenario}.{scenario}.generated.completion_exact_removed", current)
            self.assertNotIn(f"{scenario}.{scenario}.generated.completion_residual", current)
            self.assertIn(f"{scenario}.{scenario}.generated.root_crontab_legacy_retired", current)
            self.assertIn(f"{scenario}.{scenario}.state.operator_config_retained", current)
            for family, operation in (("deb", scenario), ("rpm", "remove"), ("apk", "upgrade-rollback")):
                checks = lab.expected_event_checks(family, operation, candidate_version="5.00.0")
                self.assertFalse(any("reviewed-cron-recovery" in x for x in checks))

    def test_current_contract_rejects_old_or_incomplete_recovery_evidence(self):
        for scenario in ("remove", "purge"):
            checks = lab.expected_event_checks("apk", scenario, candidate_version="5.00.0")
            events = [{"check": key, "status": "pass", "detail": "fixture"} for key in checks]
            lab.validate_event_contract(events, "apk", scenario, candidate_version="5.00.0")
            for index, event in enumerate(events):
                with self.subTest(scenario=scenario, missing=event["check"]):
                    with self.assertRaises(lab.LifecycleLabError):
                        lab.validate_event_contract(events[:index] + events[index + 1:], "apk", scenario, candidate_version="5.00.0")
            old_events = [{"check": key, "status": "pass", "detail": "old"} for key in lab.expected_event_checks("apk", scenario, candidate_version="4.10.4")]
            with self.assertRaises(lab.LifecycleLabError):
                lab.validate_event_contract(old_events, "apk", scenario, candidate_version="5.00.0")

    def test_plan_digest_rejects_multiple_malformed_and_absent_plans(self):
        helper = Path(__file__).with_name("package_v5_apk_removal.sh")
        digest = "a" * 64
        cases = ((f"Plan SHA-256: {digest}\n", 0),
                 (f"Plan SHA-256: {digest}\n" * 2, 1),
                 ("Plan SHA-256: not-a-digest\n", 1), ("Dry run only.\n", 1))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan"
            for contents, expected in cases:
                path.write_text(contents)
                result = subprocess.run(["sh", "-c", '. "$1"; fixture_plan_digest "$2"', "fixture", str(helper), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stdout, digest + "\n" if expected == 0 else "")

    def test_removal_restart_is_mandatory_and_never_inferred_from_initial_success(self):
        for scenario in ("remove", "purge"):
            self.assertEqual(lab._scenario_invocations(scenario, reviewed_apk=True), ("initial", "restart-one"))
            self.assertEqual(lab._scenario_invocations(scenario), ("initial",))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for marker in (None, "restart-one\n", "restart-two\n", "complete\nextra\n"):
                    with self.subTest(scenario=scenario, marker=marker):
                        if marker is not None:
                            (root / "restart-state").write_text(marker)
                        with self.assertRaises(lab.LifecycleLabError):
                            lab._final_restart_state(root, scenario, reviewed_apk=True)
                (root / "restart-state").write_text("complete\n")
                self.assertEqual(lab._final_restart_state(root, scenario, reviewed_apk=True), "complete")
                with self.assertRaises(lab.LifecycleLabError):
                    lab._final_restart_state(root, scenario)
            checks = lab.expected_event_checks("apk", scenario, candidate_version="5.00.0")
            for key in ("operator-protection.before", "operator-protection.installed", "operator-protection.removed", "operator-protection.reload", "operator-protection.restart", "restart-one.payload_inventory", "restart-one.no_recreation"):
                self.assertIn(f"{scenario}.{key}", checks)

    def test_profile_paths_do_not_relocate_historical_or_upgrade_fixtures(self):
        helper = Path(__file__).with_name("package_v5_apk_removal.sh")
        for scenario, eligible, expected in (("remove", 0, "/etc/lifecycle-operator/"),
                ("purge", 0, "/etc/lifecycle-operator/"),
                ("remove", 1, "/etc/syswarden/config/"),
                ("upgrade-rollback", 0, "/etc/syswarden/config/")):
            result = subprocess.run(["sh", "-c", '. "$1"; SCENARIO="$2"; eligible="$3"; package_uses_apk_recovery_payload() { return "$eligible"; }; configure_operator_fixture_paths; printf "%s" "$FIXTURE_CONFIG"', "fixture", str(helper), scenario, str(eligible)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected + "lifecycle-operator.conf")


if __name__ == "__main__":
    unittest.main()
