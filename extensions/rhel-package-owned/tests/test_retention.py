#!/usr/bin/env python3
"""Run the opt-in RPM shell recovery against private administrator fixtures."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "extensions/rhel-package-owned/scriptlets/postun-recovery.sh"


class RHELConfigurationRetentionTests(unittest.TestCase):
    def test_shared_retention_parser_is_identical_to_standard_packages(self) -> None:
        build = (ROOT / "build_packages.sh").read_text()
        state = (ROOT / "scripts/ci/package_removal_state.sh").read_text()
        guards = build[build.index("syswarden_path_absent() {\n"):build.index("syswarden_remove_exact_product_link() {\n")]
        parser = state[state.index("syswarden_operator_retention_record_has_path() (\n"):state.index("syswarden_assert_external_removal_terminal() {\n")]
        helper = SOURCE.read_text()
        actual = helper.split("# BEGIN shared operator configuration retention\n", 1)[1].split("# END shared operator configuration retention\n", 1)[0]
        self.assertEqual(actual, guards + parser)

    def fixture(self, base: Path, kind: str) -> tuple[Path, Path, list[Path], bytes]:
        # Only fixed product paths are redirected. Host tools and /proc remain
        # real, so file, link, digest, schema and mount guards execute unchanged.
        source = SOURCE.read_text()
        prefixes = ("/var/backups", "/var/lib", "/var/log", "/etc", "/opt", "/usr/lib/systemd", "/usr/libexec", "/usr/share/doc", "/usr/share/bash-completion", "/usr/local/bin", "/var/run", "/run")
        for index, prefix in enumerate(prefixes):
            source = source.replace(prefix, f"@ROOT{index}@")
        for index, prefix in enumerate(prefixes):
            source = source.replace(f"@ROOT{index}@", str(base) + prefix)
        source = source.replace("0:0:", f"{os.getuid()}:{os.getgid()}:")
        config = base / "etc/syswarden"
        for relative in ("config/modules", "lists", "tls"):
            (config / relative).mkdir(parents=True, mode=0o750, exist_ok=True)
        files = [] if kind == "empty" else [config / "config/config.toml", config / "config/modules/75-custom.toml"]
        original = b'[core]\nlog_level = "debug"\n'
        decisions = base / "var/backups/syswarden-retired-v1/operator-configuration"
        decisions.mkdir(parents=True, mode=0o700)
        decisions.parent.chmod(0o700)
        lines = ["SYSWARDEN_OPERATOR_CONFIGURATION_RETENTION_V1", "explicit-operator-retention-at-original-paths"]
        for file in files:
            file.write_bytes(original)
            file.chmod(0o600)
            lines.append("\t".join(("file", str(file), "1", "2", "33152", "0", "0", str(len(original)), "1", "0", "1", "0", hashlib.sha256(original).hexdigest())))
        wire = ("\n".join(lines) + "\n").encode()
        record = decisions / (hashlib.sha256(wire).hexdigest() + ".retention")
        if files:
            record.write_bytes(wire)
            record.chmod(0o600)
        edited = b'# Later administrator edit\n[core]\nlog_level = "info"\n'
        for file in files:
            file.write_bytes(edited)
        if kind == "unknown":
            (config / "config/modules/76-unknown.toml").write_bytes(original)
        elif kind == "list":
            (config / "lists/whitelist.txt").write_bytes(b"192.0.2.1\n")
        elif kind == "modified-record":
            record.write_bytes(wire + b"unexpected\n")
        elif kind == "pending-record":
            (decisions / (record.name + ".new")).write_bytes(b"partial\n")
        elif kind == "record-link":
            os.link(record, base / "outside")
        elif kind == "file-link":
            os.link(files[0], base / "outside")
        elif kind == "symlink":
            files[0].rename(base / "outside")
            files[0].symlink_to(base / "outside")
        elif kind == "mode":
            files[0].chmod(0o666)
        elif kind == "directory-link":
            decisions.parent.rename(base / "outside")
            decisions.parent.symlink_to(base / "outside")
        elif kind == "user-module":
            for file in files:
                file.unlink()
            record.unlink()
            files = [config / "config/modules/99-user.toml"]
            files[0].write_bytes(edited)
            files[0].chmod(0o640)
        installed = base / "usr/libexec/syswarden/rhelpo-postun-recovery-v1"
        installed.parent.mkdir(parents=True)
        installed.write_text(source)
        installed.chmod(0o755)
        state = base / "var/lib/syswarden"
        (state / "ui").mkdir(parents=True, mode=0o750)
        state.chmod(0o750)
        tombstone = state / "removal-in-progress-v1"
        tombstone.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
        tombstone.chmod(0o600)
        marker = base / "var/lib/.syswarden-rhelpo-erase-ready-v1"
        marker.write_bytes(b"SYSWARDEN_RHELPO_ERASE_READY_V1\nnevra=syswarden-4.10.4-1.rhelpo.x86_64\n")
        marker.chmod(0o600)
        return installed, config, files, edited

    def test_readonly_preun_and_postun_preserve_reviewed_files_and_refuse_ambiguity(self) -> None:
        cases = ("reviewed", "empty", "user-module", "unknown", "list", "modified-record", "pending-record", "record-link", "file-link", "symlink", "mode", "directory-link")
        for kind in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="sw-rhel-retention-", dir="/tmp") as temporary:
                base = Path(temporary)
                installed, config, files, edited = self.fixture(base, kind)
                before = [file.stat() for file in files]
                inspected = subprocess.run(("/bin/sh", str(installed), "inspect-configuration-v1"), capture_output=True, timeout=20, check=False)
                success = kind in ("reviewed", "empty", "user-module")
                self.assertEqual(inspected.returncode == 0, success, inspected.stderr)
                self.assertTrue((config / "lists").is_dir(), "inspection mutated the configuration tree")
                helper = base / "var/lib/.syswarden-rhelpo-postun-recovery-v1"
                installed.rename(helper)
                helper.chmod(0o700)
                result = subprocess.run(("/bin/sh", str(helper), "rpm-postun-v1"), capture_output=True, timeout=30, check=False)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertFalse(helper.exists())
                    self.assertFalse((base / "var/lib/syswarden").exists())
                    self.assertFalse((base / "var/lib/.syswarden-rhelpo-erase-ready-v1").exists())
                    self.assertFalse((config / "lists").exists())
                    self.assertEqual(config.exists(), kind != "empty")
                else:
                    self.assertTrue(helper.is_file())
                    self.assertTrue((base / "var/lib/syswarden/removal-in-progress-v1").is_file())
                    self.assertTrue((config / "lists").is_dir())
                for file, identity in zip(files, before):
                    self.assertEqual(file.read_bytes(), edited)
                    self.assertEqual((file.stat().st_ino, file.stat().st_mode), (identity.st_ino, identity.st_mode))


if __name__ == "__main__":
    unittest.main()
