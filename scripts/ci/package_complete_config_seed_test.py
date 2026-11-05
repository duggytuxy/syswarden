#!/usr/bin/env python3
"""Exercise complete removal-policy seeding without host mutation."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
import tomllib
import unittest

try:
    from scripts.ci import package_lifecycle_lab as lab
except ModuleNotFoundError:
    import package_lifecycle_lab as lab


class CompleteRemovalConfigurationTests(unittest.TestCase):
    def test_seed_is_complete_and_refuses_existing_policy(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "config"
            source = lab.complete_removal_configuration_seed().replace(
                "/etc/syswarden/config", str(root)
            )
            invocation = ["/bin/sh", "-eu", "-c", source + "\nseed_complete_removal_configuration"]
            subprocess.run(invocation, check=True, capture_output=True)
            files = sorted(path for path in root.rglob("*") if path.is_file())
            self.assertEqual(len(files), 7)
            self.assertEqual((root / "config.toml").stat().st_mode & 0o777, 0o640)
            for path in files:
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                tomllib.loads(path.read_text())
            core = tomllib.loads((root / "modules/00-core.toml").read_text())["core"]
            self.assertTrue(core["hardening_enabled"])
            self.assertNotIn("install_profile", core)
            user = root / "modules/99-user.toml"
            user.write_text('[user]\nprofile_name = "custom retained operator"\n')
            before = {str(p): hashlib.sha256(p.read_bytes()).digest() for p in files}
            result = subprocess.run(invocation, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).digest() for p in files})

    def test_existing_symlink_cannot_redirect_seed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            destination = root / "untouched"
            destination.mkdir()
            link = root / "config"
            link.symlink_to(destination, target_is_directory=True)
            script = lab.complete_removal_configuration_seed().replace("/etc/syswarden/config", str(link))
            result = subprocess.run(["/bin/sh", "-eu", "-c", script + "\nseed_complete_removal_configuration"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(destination.iterdir()), [])

    def test_complete_seed_precedes_operator_overrides_only_for_removal(self):
        for name in ("scenario_remove", "scenario_purge"):
            body = lab.LIFECYCLE_SCRIPT.split(name + "() {", 1)[1].split("\n}", 1)[0]
            self.assertLess(body.index("seed_complete_removal_configuration"), body.index("seed_state"))
            self.assertLess(body.index("seed_state"), body.index("run_install_step install.candidate"))
        upgrade = lab.LIFECYCLE_SCRIPT.split("scenario_upgrade_rollback_initial() {", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("seed_complete_removal_configuration", upgrade)


if __name__ == "__main__":
    unittest.main()
