#!/usr/bin/env python3
"""Run the native pre-unpack screen against private historical-state fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/package_wireguard_preflight.sh"


class WireGuardPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for path in ("etc/wireguard/clients", "etc/sysctl.d"):
            self.root.joinpath(path).mkdir(parents=True, mode=0o700)
        self.helper = SCRIPT.read_text(encoding="ascii").replace(
            "!= 0:0", f"!= {os.getuid()}:{os.getgid()}"
        )

    def write(self, path: str, content: str) -> Path:
        target = self.root / path
        target.write_text(content, encoding="ascii")
        target.chmod(0o600)
        return target

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-eu", "-c", self.helper + '\nsyswarden_preflight_wireguard "$1"',
             "preflight", str(self.root)],
            capture_output=True, text=True, timeout=5, check=False,
            env={"PATH": "/usr/bin:/bin"},
        )

    def test_fresh_install_and_unrelated_operator_wg0_pass(self) -> None:
        self.assertEqual(self.run_gate().returncode, 0)
        self.write("etc/wireguard/wg0.conf", "[Interface]\nPrivateKey = PRIVATE_TEST_INPUT\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_historical_claim_refuses_without_touching_config_or_payload(self) -> None:
        config = self.write("etc/wireguard/wg0.conf", "PostUp = nft add table inet syswarden_wg\nPrivateKey = PRIVATE_TEST_INPUT\n")
        payload = self.write("installed-cli", "old-cli\n")
        before = {path: (path.read_bytes(), path.stat()) for path in (config, payload)}
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing package unpack", result.stderr)
        self.assertNotIn("PRIVATE_TEST_INPUT", result.stdout + result.stderr)
        # Inspection can advance atime. Every identity, permission, content and
        # modification field must remain unchanged, including nanoseconds.
        for path, (content, metadata) in before.items():
            self.assertEqual(path.read_bytes(), content)
            current = path.stat()
            for field in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                          "st_size", "st_mtime_ns", "st_ctime_ns"):
                with self.subTest(path=path.name, field=field):
                    self.assertEqual(getattr(current, field), getattr(metadata, field))

    def test_each_unmanifested_artifact_refuses_even_without_wg0(self) -> None:
        for path in ("etc/wireguard/wg-syswarden.conf", "etc/wireguard/clients/admin-pc.conf",
                     "etc/sysctl.d/99-syswarden-wireguard.conf"):
            with self.subTest(path=path):
                artifact = self.write(path, "PRIVATE_TEST_INPUT\n")
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no ownership manifest", result.stderr)
                self.assertNotIn("PRIVATE_TEST_INPUT", result.stderr)
                artifact.unlink()

    def test_existing_manifest_defers_full_verification_to_cli(self) -> None:
        self.write("etc/wireguard/wg-syswarden.conf", "PRIVATE_TEST_INPUT\n")
        self.write("etc/wireguard/.syswarden-ownership-v1.json", "{}\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.write("etc/wireguard/wg0.conf", "PostDown = nft delete table inet syswarden_wg\n")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_pending_migration_blocks_unpack_even_with_a_manifest(self) -> None:
        self.write("etc/wireguard/.syswarden-ownership-v1.json", "{}\n")
        self.write("etc/wireguard/.syswarden-legacy-migration-v1.json", "{}\n")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("migration is pending", result.stderr)

    def test_symlinks_fifo_oversized_and_hardlinked_wg0_refuse(self) -> None:
        path = self.root / "etc/wireguard/wg0.conf"
        target = self.write("outside", "PRIVATE_TEST_INPUT\n")
        path.symlink_to(target)
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.unlink()
        path.symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.unlink()
        os.link(target, path)
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.unlink()
        self.write("etc/wireguard/wg0.conf", "A" * 65537)
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_unsafe_parent_and_manifest_refuse(self) -> None:
        path = self.root / "etc/wireguard/clients"
        path.chmod(0o777)
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.chmod(0o700)
        path.rmdir()
        path.symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_gate().returncode, 0)
        path.unlink()
        manifest = self.root / "etc/wireguard/.syswarden-ownership-v1.json"
        manifest.symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_both_builders_screen_before_other_preinstall_actions(self) -> None:
        for path in (ROOT / "build_packages.sh", ROOT / ".github/workflows/package.yml"):
            with self.subTest(path=path):
                source = path.read_text(encoding="ascii")
                start = source.index("# Pre-Install / Pre-Upgrade script") if path.name.endswith("sh") else source.index('package_systemd_ordering_preflight.sh" >>')
                preinstall = source[start:]
                self.assertLess(preinstall.index("package_wireguard_preflight.sh"), preinstall.index("syswarden_preflight_wireguard /"))
                self.assertLess(preinstall.index("syswarden_preflight_wireguard /"), preinstall.index("syswarden_preflight_alpine_cronie\n"))
                self.assertLess(preinstall.index("syswarden_preflight_wireguard /"), preinstall.index("SYSWARDEN_OFFLINE_QUALIFICATION"))


if __name__ == "__main__":
    unittest.main()
