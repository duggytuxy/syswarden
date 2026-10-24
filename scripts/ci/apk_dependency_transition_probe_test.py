#!/usr/bin/env python3
"""Safety and failure-accounting tests for the opt-in native APK oracle."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import apk_dependency_transition_probe as probe


class APKDependencyProbeSafetyTests(unittest.TestCase):
    def test_inputs_cannot_change_the_container_execution_boundary(self):
        for image in ("alpine:latest", "-v /:/host", "a" * 63, "A" * 64):
            with self.subTest(image=image), self.assertRaises(ValueError):
                probe.sandbox_command("/usr/bin/podman", image, "fresh")
        with self.assertRaises(ValueError):
            probe.sandbox_command("/usr/bin/podman", "a" * 64, "fresh; apk upgrade")
        arguments = probe.sandbox_command("/usr/bin/podman", "a" * 64, "fresh")
        options = arguments[:arguments.index("a" * 64)]
        for option, value in (("--network", "none"), ("--pull", "never"),
                              ("--cap-drop", "all"), ("--cap-add", "SYS_CHROOT"),
                              ("--security-opt", "no-new-privileges"),
                              ("--cpus", "2"), ("--timeout", "60")):
            self.assertEqual(options[options.index(option) + 1], value)
        self.assertNotIn("--privileged", options)
        self.assertNotIn("--mount", options)
        self.assertNotIn("--volume", options)
        self.assertNotIn("-v", options)

    def test_root_execution_is_rejected_before_any_process(self):
        with mock.patch.object(probe.os, "geteuid", return_value=0), \
                mock.patch.object(probe, "command") as command:
            with self.assertRaisesRegex(ValueError, "unprivileged"):
                probe.run(Path("/not-used"), "a" * 64, Path("/not-created"))
            command.assert_not_called()

    def run_fixture(self, root, inspection, native_result, with_retention=False):
        nfpm = root / "nfpm"
        nfpm.write_bytes(b"fixture packager")
        nfpm.chmod(0o700)
        retention_test = None
        if with_retention:
            retention_test = root / "retention.test"
            retention_test.write_bytes(b"fixture test binary")
            retention_test.chmod(0o700)
        responses = [
            subprocess.CompletedProcess([], 0, b"true\n"),
            subprocess.CompletedProcess([], 0, json.dumps([inspection]).encode()),
            native_result,
        ]
        with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                mock.patch.object(probe, "fixtures", return_value=b"fixtures") as build, \
                mock.patch.object(probe, "command", side_effect=responses) as command:
            try:
                probe.run(nfpm, "a" * 64, root / "results", retention_test)
            finally:
                self.last_build_calls = build.call_count
                self.last_command_calls = command.call_count

    def test_wrong_image_architecture_is_rejected_before_build_or_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "AMD64"):
                self.run_fixture(root, {"Architecture": "unsupported", "Os": "linux", "Id": "a" * 64}, None)
            self.assertFalse((root / "results").exists())
            self.assertEqual(self.last_build_calls, 0)
            self.assertEqual(self.last_command_calls, 2)

    def test_successful_exit_without_completion_marker_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "fresh"):
                self.run_fixture(root, {"Architecture": "amd64", "Os": "linux", "Id": "a" * 64},
                                 subprocess.CompletedProcess([], 0, b"incomplete fixture\n"))
            result = json.loads((root / "results/results.json").read_text())
            self.assertEqual(result["cases"], {"fresh": {"passed": False, "exit_status": 0}})
            self.assertEqual(self.last_command_calls, 3)
            self.assertEqual((root / "results/fresh.log").read_bytes(), b"incomplete fixture\n")

    def test_missing_native_planner_marker_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "fresh"):
                self.run_fixture(root, {"Architecture": "amd64", "Os": "linux", "Id": "a" * 64},
                                 subprocess.CompletedProcess([], 0, b"CASE_PASS=fresh\n"),
                                 with_retention=True)
            result = json.loads((root / "results/results.json").read_text())
            self.assertFalse(result["cases"]["fresh"]["passed"])
            self.assertEqual(result["cases"]["fresh"]["native_planner_passes"], 0)


if __name__ == "__main__":
    unittest.main()
