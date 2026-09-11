#!/usr/bin/env python3
"""Focused contract tests for the package systemd ordering preflight."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("package_systemd_ordering_preflight.sh")
CONTENT = b"[Unit]\nAfter=wg-quick@wg-syswarden.service\n"


class SystemdOrderingPreflightTests(unittest.TestCase):
    artifact_content = CONTENT
    artifact_relative = "syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf"
    helper_name = "syswarden_preflight_systemd_ordering_dropin"
    hash_variable = "syswarden_ordering_sha256"
    contract_file = "package_systemd_wireguard_ordering_contract.json"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "root"
        self.fake_bin = Path(self.temporary.name) / "bin"
        self.root.joinpath("usr/lib/systemd/system").mkdir(parents=True)
        self.root.joinpath("etc").mkdir()
        self.fake_bin.mkdir()
        self.path = self.root / "usr/lib/systemd/system" / self.artifact_relative
        self.directory = self.path.parent
        self._write_package_query_fixtures()
        self.harness = Path(self.temporary.name) / "preflight-harness.sh"
        self.harness.write_text(
            "#!/bin/sh\nset -eu\n"
            + self._isolated_function()
            + "\n" + self.helper_name + "\n",
            encoding="ascii",
        )
        self.harness.chmod(0o700)

    def _isolated_function(self) -> str:
        source = SCRIPT.read_text(encoding="ascii")
        marker = self.helper_name + "() {"
        self.assertEqual(source.count(marker), 1)
        function = source[source.index(marker) :].split("\n}\n", 1)[0] + "\n}\n"
        self.assertEqual(function.count("/etc/alpine-release"), 1)
        self.assertEqual(function.count("/usr"), 6)
        self.assertEqual(function.count("= 0:0"), 3)
        function = function.replace(
            "/etc/alpine-release",
            str(self.root / "etc/alpine-release"),
        )
        function = function.replace("/usr", str(self.root / "usr"))
        function = function.replace(
            "= 0:0",
            f"= {os.getuid()}:{os.getgid()}",
        )
        return function

    def _write_package_query_fixtures(self) -> None:
        dpkg_query = self.fake_bin / "dpkg-query"
        dpkg_query.write_text(
            "#!/bin/sh\n"
            "[ \"$#\" -eq 2 ] && [ \"$1\" = --listfiles ] && "
            "[ \"$2\" = syswarden ] || exit 97\n"
            "[ \"${DPKG_STATUS:-0}\" -eq 0 ] || exit \"${DPKG_STATUS}\"\n"
            "if [ -n \"${MUTATE_PATH:-}\" ]; then "
            "printf '%s' mutation > \"${MUTATE_PATH}\"; fi\n"
            "printf '%s' \"${DPKG_LISTFILES:-}\"\n",
            encoding="ascii",
        )
        dpkg_query.chmod(0o700)
        rpm = self.fake_bin / "rpm"
        rpm.write_text(
            "#!/bin/sh\n"
            "[ \"$#\" -eq 5 ] && [ \"$1\" = --query ] && "
            "[ \"$2\" = --file ] && [ \"$3\" = \"${EXPECTED_PATH}\" ] && "
            "[ \"$4\" = --queryformat ] && [ \"$5\" = '%{NAME}\\n' ] || exit 98\n"
            "[ \"${RPM_STATUS:-0}\" -eq 0 ] || exit \"${RPM_STATUS}\"\n"
            "printf '%s' \"${RPM_OWNER:-}\"\n",
            encoding="ascii",
        )
        rpm.chmod(0o700)

    def _write_exact_artifact(self, content: bytes | None = None) -> None:
        if content is None:
            content = self.artifact_content
        self.directory.mkdir(mode=0o755)
        self.path.write_bytes(content)
        self.path.chmod(0o644)

    def _run(
        self,
        *,
        dpkg_owner: bool = False,
        rpm_owner: bool = False,
        mutate_during_owner_lookup: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.fake_bin}:/usr/bin:/bin",
            "DPKG_LISTFILES": (str(self.path) + "\n") if dpkg_owner else "",
            "RPM_OWNER": "syswarden\n" if rpm_owner else "",
            "EXPECTED_PATH": str(self.path),
            "MUTATE_PATH": str(self.path) if mutate_during_owner_lookup else "",
        }
        return subprocess.run(
            ("/bin/sh", str(self.harness)),
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_absent_artifact_is_accepted_for_first_install(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_helper_contract_matches_repository_source_and_json(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        source = repository_root / "src/init/systemd" / self.artifact_relative
        contract = json.loads(
            (
                repository_root
                / "scripts/ci" / self.contract_file
            ).read_bytes()
        )
        helper = SCRIPT.read_text(encoding="ascii")

        self.assertEqual(source.read_bytes(), self.artifact_content)
        self.assertEqual(
            contract,
            {
                "sha256": hashlib.sha256(self.artifact_content).hexdigest(),
                "size": len(self.artifact_content),
            },
        )
        self.assertIn(f"{self.hash_variable}={contract['sha256']}", helper)
        self.assertIn(f"0:0:644:1:{contract['size']}", helper)

    def test_exact_dpkg_owned_artifact_is_accepted(self) -> None:
        self._write_exact_artifact()
        result = self._run(dpkg_owner=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_rpm_owned_artifact_is_accepted(self) -> None:
        self._write_exact_artifact()
        result = self._run(rpm_owner=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tampered_artifact_is_rejected(self) -> None:
        self._write_exact_artifact(self.artifact_content.replace(b"=", b":", 1))
        result = self._run(dpkg_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("modified existing", result.stderr)

    def test_unexpected_neighbor_is_rejected(self) -> None:
        self._write_exact_artifact()
        neighbor = self.directory / "99-operator.conf"
        neighbor.write_text("[Unit]\nAfter=network.target\n", encoding="ascii")
        neighbor.chmod(0o644)
        result = self._run(dpkg_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("existing unowned systemd drop-in", result.stderr)

    def test_symlinked_artifact_is_rejected(self) -> None:
        self.directory.mkdir(mode=0o755)
        target = Path(self.temporary.name) / "outside.conf"
        target.write_bytes(self.artifact_content)
        target.chmod(0o644)
        self.path.symlink_to(target)
        result = self._run(dpkg_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("unsafe existing", result.stderr)

    def test_symlinked_parent_is_rejected(self) -> None:
        systemd = self.root / "usr/lib/systemd"
        shutil.rmtree(systemd)
        outside = Path(self.temporary.name) / "outside-systemd"
        outside.mkdir()
        systemd.symlink_to(outside, target_is_directory=True)
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("unsafe systemd package parent", result.stderr)

    def test_writable_dropin_directory_is_rejected(self) -> None:
        self._write_exact_artifact()
        self.directory.chmod(0o775)
        result = self._run(dpkg_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("unsafe SysWarden systemd drop-in directory", result.stderr)

    def test_hardlinked_artifact_is_rejected(self) -> None:
        self._write_exact_artifact()
        os.link(self.path, Path(self.temporary.name) / "ordering-alias.conf")
        result = self._run(dpkg_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("unsafe existing", result.stderr)

    def test_owner_lookup_mutation_is_rejected(self) -> None:
        self._write_exact_artifact()
        result = self._run(
            dpkg_owner=True,
            mutate_during_owner_lookup=True,
        )
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("changed during package preflight", result.stderr)

    def test_exact_artifact_without_package_owner_is_rejected(self) -> None:
        self._write_exact_artifact()
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("without one exact package owner", result.stderr)

    def test_dual_package_ownership_is_rejected(self) -> None:
        self._write_exact_artifact()
        result = self._run(dpkg_owner=True, rpm_owner=True)
        self.assertNotEqual(result.returncode, 0, result)
        self.assertIn("without one exact package owner", result.stderr)


class SystemdSocketPreflightTests(SystemdOrderingPreflightTests):
    artifact_content = (
        b"[Service]\n"
        b"# Assign the socket to the verified private rsyslog producer group.\n"
        b"CapabilityBoundingSet=CAP_CHOWN\n"
    )
    artifact_relative = "syswarden-core.service.d/10-syswarden-socket-ownership.conf"
    helper_name = "syswarden_preflight_systemd_socket_dropin"
    hash_variable = "syswarden_socket_sha256"
    contract_file = "package_systemd_socket_capability_contract.json"


if __name__ == "__main__":
    unittest.main()
