#!/usr/bin/env python3
"""Verify that native finalization cannot adopt unretired directory contents."""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

try:
    from scripts.ci import package_lifecycle_contract_test as lifecycle_contract
except ModuleNotFoundError:
    import package_lifecycle_contract_test as lifecycle_contract


def shell_function(source: str, name: str) -> str:
    start = source.index(name + "() {\n")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class PackageRemovalPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        lifecycle_contract.PackageLifecycleContractTests.setUpClass()
        contract = lifecycle_contract.PackageLifecycleContractTests()
        cls.scripts = {
            "workflow": contract.script("postrm.sh"),
            "local": contract.local_build_script("postrm.sh"),
        }

    def test_finalizer_preserves_unknown_files_links_and_directories(self) -> None:
        # Identity and mount guards have their own lifecycle tests. These
        # private adapters isolate the final file-deletion boundary.
        prefix = """syswarden_path_absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
        syswarden_attest_dedicated_root() { [ -d "$1" ] && [ ! -L "$1" ]; }
        syswarden_refuse_mounted_path_tree() { return 0; }
        """
        for source_name, source in self.scripts.items():
            for kind in ("regular", "hidden", "nested", "symlink", "hardlink", "empty"):
                with self.subTest(source=source_name, kind=kind), tempfile.TemporaryDirectory(prefix="sw-finalize-", dir="/tmp") as temporary:
                    base = Path(temporary)
                    root = base / "product"
                    root.mkdir(mode=0o700)
                    external = base / "administrator"
                    external.write_bytes(b"private administrator sentinel\n")
                    entry = root / "custom.conf"
                    if kind == "hidden":
                        entry = root / ".custom"
                    elif kind == "nested":
                        (root / "custom").mkdir(mode=0o700)
                        entry = root / "custom" / "keep.conf"
                    if kind == "symlink":
                        entry.symlink_to(external)
                    elif kind == "hardlink":
                        os.link(external, entry)
                    elif kind != "empty":
                        entry.write_bytes(external.read_bytes())
                    script = prefix + shell_function(source, "syswarden_remove_dedicated_root") + '\nsyswarden_remove_dedicated_root "$1"\n'
                    result = subprocess.run(("/bin/sh", "-eu", "-c", script, "fixture", str(root)), capture_output=True, timeout=5, check=False)
                    if kind == "empty":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertFalse(root.exists())
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(entry.read_bytes(), b"private administrator sentinel\n")
                    self.assertEqual(external.read_bytes(), b"private administrator sentinel\n")

    def test_operator_configuration_survives_native_finalization_and_retry(self) -> None:
        for source_name, source in self.scripts.items():
            for kind in ("operator", "empty", "unknown", "list", "symlink", "hardlink", "mode"):
                with self.subTest(source=source_name, kind=kind), tempfile.TemporaryDirectory(prefix="sw-operator-retention-", dir="/tmp") as temporary:
                    root = Path(temporary) / "configuration"
                    for relative in ("config/modules", "lists", "tls"):
                        (root / relative).mkdir(parents=True, mode=0o750, exist_ok=True)
                    user = root / "config/modules/99-user.toml"
                    content = b"# Private administrator settings\n[core]\nfirewall_backend = \"keep\"\n"
                    if kind != "empty":
                        user.write_bytes(content)
                        user.chmod(0o640)
                    if kind == "unknown":
                        (root / "config/modules/75-custom.toml").write_bytes(b"keep unknown settings\n")
                    elif kind == "list":
                        (root / "lists/whitelist.txt").write_bytes(b"192.0.2.1\n")
                    elif kind == "symlink":
                        outside = Path(temporary) / "outside"
                        user.rename(outside)
                        user.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(user, Path(temporary) / "outside")
                    elif kind == "mode":
                        user.chmod(0o666)
                    before = user.stat() if user.exists() else None
                    helper = lifecycle_contract.REMOVAL_STATE_HELPER.read_text().replace("/etc/syswarden", str(root))
                    prefix = """syswarden_path_absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
                    syswarden_refuse_mounted_path_tree() { return 0; }
                    """ + shell_function(source, "syswarden_attest_dedicated_root") + "\n"
                    script = (prefix + helper).replace("0:0:", f"{os.getuid()}:{os.getgid()}:")
                    script += "\nsyswarden_finalize_retained_operator_configuration\nsyswarden_assert_retained_operator_configuration\n"
                    result = subprocess.run(("/bin/sh", "-eu", "-c", script), capture_output=True, timeout=10, check=False)
                    if kind in ("empty", "operator"):
                        self.assertEqual(result.returncode, 0, result.stderr)
                        retry = subprocess.run(("/bin/sh", "-eu", "-c", script), capture_output=True, timeout=10, check=False)
                        self.assertEqual(retry.returncode, 0, retry.stderr)
                        self.assertFalse((root / "lists").exists())
                        self.assertFalse((root / "tls").exists())
                        if kind == "empty":
                            self.assertFalse(root.exists())
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue((root / "lists").is_dir())
                        self.assertTrue((root / "tls").is_dir())
                    if kind != "empty":
                        after = user.stat()
                        self.assertEqual(user.read_bytes(), content)
                        self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode))

    def test_deferred_state_refuses_leftovers_and_preserves_its_barrier(self) -> None:
        for source_name, source in self.scripts.items():
            with self.subTest(source=source_name), tempfile.TemporaryDirectory(prefix="sw-state-finalize-", dir="/tmp") as temporary:
                root = Path(temporary)
                barrier = root / "removed-awaiting-purge-v1"
                marker = b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
                barrier.write_bytes(marker)
                unknown = root / "custom.conf"
                unknown.write_bytes(b"retained administrator settings\n")
                function = shell_function(source, "syswarden_empty_removal_state").replace("/var/lib/syswarden", str(root))
                prefix = """syswarden_path_absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
                syswarden_refuse_mounted_path_tree() { return 0; }
                syswarden_attest_removal_marker() { [ -f "$1" ]; }
                """ + "syswarden_active_barrier=" + shlex.quote(str(barrier)) + "\n"
                result = subprocess.run(("/bin/sh", "-eu", "-c", prefix + function + "\nsyswarden_empty_removal_state\n"), capture_output=True, timeout=5, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(unknown.read_bytes(), b"retained administrator settings\n")
                self.assertEqual(barrier.read_bytes(), marker)

    def test_reviewed_custom_configuration_survives_binary_absence_and_later_edits(self) -> None:
        for source_name, source in self.scripts.items():
            for kind in ("reviewed", "modified-record", "pending-record", "extra-file", "unsafe-file", "hardlinked-record", "symlinked-parent"):
                with self.subTest(source=source_name, kind=kind), tempfile.TemporaryDirectory(prefix="sw-reviewed-config-", dir="/tmp") as temporary:
                    base = Path(temporary)
                    root = base / "configuration"
                    backups = base / "backups"
                    decisions = backups / "syswarden-retired-v1/operator-configuration"
                    decisions.mkdir(parents=True, mode=0o700)
                    decisions.parent.chmod(0o700)
                    for relative in ("config/modules", "lists", "tls"):
                        (root / relative).mkdir(parents=True, mode=0o750, exist_ok=True)
                    files = [root / "config/config.toml", root / "config/modules/75-custom.toml"]
                    original = b"[core]\nlog_level = \"debug\"\n"
                    lines = ["SYSWARDEN_OPERATOR_CONFIGURATION_RETENTION_V1", "explicit-operator-retention-at-original-paths"]
                    for file in files:
                        file.write_bytes(original)
                        file.chmod(0o600)
                        lines.append("\t".join(("file", str(file), "1", "2", "33152", "0", "0", str(len(original)), "1", "0", "1", "0", hashlib.sha256(original).hexdigest())))
                    record = ("\n".join(lines) + "\n").encode()
                    decision = decisions / (hashlib.sha256(record).hexdigest() + ".retention")
                    decision.write_bytes(record)
                    decision.chmod(0o600)
                    edited = b"# Later administrator edit\n[core]\nlog_level = \"info\"\n"
                    for file in files:
                        file.write_bytes(edited)
                    if kind == "modified-record":
                        decision.write_bytes(record + b"unexpected\n")
                    elif kind == "pending-record":
                        (decisions / (decision.name + ".new")).write_bytes(b"partial\n")
                    elif kind == "extra-file":
                        (root / "config/modules/76-new.toml").write_bytes(original)
                    elif kind == "unsafe-file":
                        files[0].chmod(0o700)
                    elif kind == "hardlinked-record":
                        os.link(decision, base / "outside")
                    elif kind == "symlinked-parent":
                        relocated = base / "relocated"
                        decisions.parent.rename(relocated)
                        decisions.parent.symlink_to(relocated)
                    before = [file.stat() for file in files]
                    helper = lifecycle_contract.REMOVAL_STATE_HELPER.read_text().replace("/etc/syswarden", str(root)).replace("/var/backups", str(backups))
                    prefix = """syswarden_path_absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
                    syswarden_refuse_mounted_path_tree() { return 0; }
                    """ + shell_function(source, "syswarden_attest_dedicated_root") + "\n"
                    script = (prefix + helper).replace("0:0:", f"{os.getuid()}:{os.getgid()}:")
                    script += "\nsyswarden_finalize_retained_operator_configuration\nsyswarden_assert_retained_operator_configuration\n"
                    result = subprocess.run(("/bin/sh", "-eu", "-c", script), capture_output=True, timeout=10, check=False)
                    if kind == "reviewed":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        retry = subprocess.run(("/bin/sh", "-eu", "-c", script), capture_output=True, timeout=10, check=False)
                        self.assertEqual(retry.returncode, 0, retry.stderr)
                        self.assertFalse((root / "lists").exists())
                        self.assertFalse((root / "tls").exists())
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue((root / "lists").exists())
                        self.assertTrue((root / "tls").exists())
                    for file, identity in zip(files, before):
                        self.assertEqual(file.read_bytes(), edited)
                        self.assertEqual((file.stat().st_ino, file.stat().st_mode), (identity.st_ino, identity.st_mode))


if __name__ == "__main__":
    unittest.main()
