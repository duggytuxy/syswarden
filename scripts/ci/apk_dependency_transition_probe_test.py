#!/usr/bin/env python3
"""Safety and failure-accounting tests for the opt-in native APK oracle."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import apk_dependency_transition_probe as probe


class APKDependencyProbeSafetyTests(unittest.TestCase):
    def identity(self, root=Path("/tmp")):
        helpers = probe.native.isolation_helpers()
        return helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + "b" * 32, "c" * 32, root / "case.cid")

    def test_inputs_cannot_change_the_container_execution_boundary(self):
        identity = self.identity()
        for image in ("alpine:latest", "-v /:/host", "a" * 63, "A" * 64):
            with self.subTest(image=image), self.assertRaises(ValueError):
                probe.sandbox_command("/usr/bin/podman", image, "fresh", identity)
        for case, name in (("fresh; apk upgrade", "syswarden"), ("fresh", "syswarden-base"),
                           ("native-selected-upgrade", "--root=/tmp")):
            with self.subTest(case=case, name=name), self.assertRaises(ValueError):
                probe.sandbox_command("/usr/bin/podman", "a" * 64, case, identity, name)
        arguments = probe.sandbox_command("/usr/bin/podman", "a" * 64, "fresh", identity)
        options = arguments[:arguments.index("a" * 64)]
        self.assertEqual(arguments[:3], ["/usr/bin/podman", "--remote=false", "run"])
        for option, value in (("--network", "none"), ("--pull", "never"),
                              ("--cap-drop", "all"), ("--cap-add", "SYS_CHROOT"),
                              ("--security-opt", "no-new-privileges"),
                              ("--cpus", "2"), ("--timeout", "60"),
                              ("--name", identity.name), ("--cidfile", str(identity.cidfile))):
            self.assertEqual(options[options.index(option) + 1], value)
        self.assertIn("--image-volume=ignore", options)
        self.assertEqual(options[options.index("--label") + 1],
                         probe.native.isolation_helpers().OWNER_LABEL + "=" + identity.token)
        for forbidden in ("--privileged", "--mount", "--volume", "-v", "--rm"):
            self.assertNotIn(forbidden, options)

    def test_selection_is_closed_and_compatibility_defaults_are_unchanged(self):
        self.assertEqual(probe.selected_cases(False, "syswarden", None), probe.CASES)
        self.assertEqual(probe.selected_cases(True, "syswarden", None), probe.CASES)
        self.assertEqual(probe.selected_cases(True, "syswarden-base", None), probe.NATIVE_CASES)
        for name in probe.PACKAGE_NAMES:
            self.assertEqual(probe.selected_cases(True, name, "native-selected-upgrade"), ("native-selected-upgrade",))
        for enabled, name, case in ((False, "syswarden-base", None), (False, "syswarden", "native-selected-upgrade"),
                                    (True, "syswarden-base", "fresh"), (True, "foreign", None)):
            with self.subTest(name=name, case=case), self.assertRaises(ValueError):
                probe.selected_cases(enabled, name, case)

    def test_root_execution_is_rejected_before_any_process(self):
        helpers = probe.native.isolation_helpers()
        with mock.patch.object(probe.os, "geteuid", return_value=0), \
                mock.patch.object(helpers, "execute_local") as command:
            with self.assertRaisesRegex(ValueError, "unprivileged"):
                probe.run(Path("/not-used"), "a" * 64, Path("/not-created"))
            command.assert_not_called()

    def run_fixture(self, root, inspection, native_result, with_retention=False,
                    package_name="syswarden", case="fresh", cleanup=True):
        nfpm = root / "nfpm"
        nfpm.write_bytes(b"fixture packager")
        nfpm.chmod(0o700)
        binary = None
        if with_retention:
            binary = root / "retention.test"
            binary.write_bytes(b"fixture test binary")
            binary.chmod(0o700)
        responses = [subprocess.CompletedProcess([], 0, b"true\n"),
                     subprocess.CompletedProcess([], 0, json.dumps([inspection]).encode())]
        helpers = probe.native.isolation_helpers()
        with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                mock.patch.object(probe, "fixtures", return_value=b"fixtures") as build, \
                mock.patch.object(helpers, "execute_local", side_effect=responses) as command, \
                mock.patch.object(probe, "run_container", return_value=(native_result, {"cleanup": {"verified": cleanup}})) as run:
            try:
                probe.run(nfpm, "a" * 64, root / "results", binary, package_name, case)
            finally:
                self.last_build_calls = build.call_count
                self.last_command_calls = command.call_count
                self.last_run_calls = run.call_count
                for call in command.call_args_list:
                    self.assertEqual(call.args[0][1], "--remote=false")

    def test_wrong_image_architecture_is_rejected_before_build_or_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "AMD64"):
                self.run_fixture(root, {"Architecture": "unsupported", "Os": "linux", "Id": "a" * 64}, None)
            self.assertFalse((root / "results").exists())
            self.assertEqual((self.last_build_calls, self.last_command_calls, self.last_run_calls), (0, 2, 0))

    def test_successful_exit_without_completion_marker_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "fresh"):
                self.run_fixture(root, {"Architecture": "amd64", "Os": "linux", "Id": "a" * 64},
                                 subprocess.CompletedProcess([], 0, b"incomplete fixture\n"))
            result = json.loads((root / "results/results.json").read_text())
            self.assertEqual(result["cases"], {"fresh": {"passed": False, "exit_status": 0, "cleanup_verified": True}})
            self.assertEqual((root / "results/fresh.log").read_bytes(), b"incomplete fixture\n")

    def test_missing_native_planner_marker_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "fresh"):
                self.run_fixture(root, {"Architecture": "amd64", "Os": "linux", "Id": "a" * 64},
                                 subprocess.CompletedProcess([], 0, b"CASE_PASS=fresh\n"), with_retention=True)
            result = json.loads((root / "results/results.json").read_text())
            self.assertFalse(result["cases"]["fresh"]["passed"])
            self.assertEqual(result["cases"]["fresh"]["native_planner_passes"], 0)

    def test_selected_case_binds_identity_marker_and_verified_cleanup(self):
        for name in probe.PACKAGE_NAMES:
            case = "native-selected-upgrade"
            marker = f"APK_SELECTED_RETENTION_NATIVE_PASS={name}:{case}\nCASE_PASS={case}\n".encode()
            for scenario in ("success", "foreign-name", "duplicate", "expected-plus-foreign", "skip", "cleanup"):
                with self.subTest(name=name, scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                    output = marker
                    if scenario == "foreign-name":
                        output = output.replace(name.encode(), b"foreign")
                    elif scenario == "duplicate":
                        output = marker.splitlines(keepends=True)[0] + marker
                    elif scenario == "expected-plus-foreign":
                        foreign = "syswarden-base" if name == "syswarden" else "syswarden"
                        output = f"APK_SELECTED_RETENTION_NATIVE_PASS={foreign}:{case}\n".encode() + marker
                    elif scenario == "skip":
                        output = b"--- SKIP: native oracle\n" + marker
                    root = Path(temporary)
                    def run():
                        self.run_fixture(root, {"Architecture": "amd64", "Os": "linux", "Id": "a" * 64},
                                         subprocess.CompletedProcess([], 0, output), True, name, case, scenario != "cleanup")
                    if scenario == "success":
                        run()
                    else:
                        with self.assertRaisesRegex(RuntimeError, case):
                            run()
                    record = json.loads((root / "results/results.json").read_text())
                    self.assertEqual(record["cases"][case]["passed"], scenario == "success")
                    self.assertEqual(record["retention_test_sha256"], hashlib.sha256(b"fixture test binary").hexdigest())

    def test_existing_identity_refuses_launch_and_cleanup(self):
        helpers = probe.native.isolation_helpers()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(helpers, "container_exists", return_value=True), \
                    mock.patch.object(helpers, "execute_local") as execute, \
                    mock.patch.object(helpers, "cleanup_container") as cleanup:
                result, ownership = probe.run_container("/usr/bin/podman", "a" * 64, "native-selected-upgrade", root, b"payload", "syswarden-base")
            self.assertEqual(result.returncode, 125)
            self.assertFalse(ownership["absent_before"])
            self.assertFalse(ownership["cleanup"]["verified"])
            execute.assert_not_called()
            cleanup.assert_not_called()

    def test_timeout_retains_output_and_verifies_owned_cleanup(self):
        helpers = probe.native.isolation_helpers()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(helpers, "container_exists", return_value=False), \
                    mock.patch.object(helpers, "execute_local", side_effect=subprocess.TimeoutExpired("podman", 90, output=b"partial\n")), \
                    mock.patch.object(helpers, "cleanup_container", return_value={"verified": True}) as cleanup:
                result, ownership = probe.run_container("/usr/bin/podman", "a" * 64, "native-selected-upgrade", root, b"payload", "syswarden")
            self.assertEqual((result.returncode, result.stdout), (124, b"partial\n"))
            self.assertTrue(ownership["cleanup"]["verified"])
            cleanup.assert_called_once()
            self.assertFalse(cleanup.call_args.kwargs["require_cid"])

    def test_success_requires_retained_container_id_for_cleanup(self):
        helpers = probe.native.isolation_helpers()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(helpers, "container_exists", return_value=False), \
                    mock.patch.object(helpers, "execute_local", return_value=subprocess.CompletedProcess([], 0, b"done\n")), \
                    mock.patch.object(helpers, "cleanup_container", return_value={"verified": False}) as cleanup:
                _, ownership = probe.run_container("/usr/bin/podman", "a" * 64, "native-selected-upgrade", root, b"payload", "syswarden")
            self.assertFalse(ownership["cleanup"]["verified"])
            self.assertTrue(cleanup.call_args.kwargs["require_cid"])

    def test_selected_fixture_binds_exact_binary_and_minimal_dependency_graph(self):
        for name in probe.PACKAGE_NAMES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary = root / "oracle"
                binary.write_bytes(b"exact executable snapshot\n")
                binary.chmod(0o700)
                snapshot = probe.native.snapshot_retention_binary(binary)
                specs = []
                def build(arguments, **kwargs):
                    spec = json.loads(Path(arguments[arguments.index("--config") + 1]).read_text())
                    specs.append(spec)
                    Path(arguments[arguments.index("--target") + 1]).write_bytes(b"inert package")
                    return subprocess.CompletedProcess(arguments, 0, b"built\n")
                with mock.patch.object(probe, "command", side_effect=build):
                    payload = probe.fixtures(root, Path("/fixture/nfpm"), snapshot, name, True)
                with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                    member = archive.getmember("retention.test")
                    self.assertTrue(member.isfile())
                    self.assertEqual(member.mode, 0o700)
                    self.assertEqual(archive.extractfile(member).read(), snapshot.data)
                    self.assertEqual(archive.extractfile(".selected-retention-oracle-v1").read(), b"SYSWARDEN-ISOLATED-APK-RETENTION-V1\n")
                product = [spec for spec in specs if spec["name"] == name]
                self.assertEqual(len(product), 2)
                self.assertEqual([spec.get("depends", []) for spec in product], [["rsyslog"], []] if name == "syswarden" else [[], []])
                for spec in specs:
                    self.assertEqual((spec["arch"], spec["release"], spec["version_schema"]), ("amd64", "0", "none"))
                    self.assertNotIn("scripts", spec)
                self.assertIn("cmp /tmp/unrelated-world.before /tmp/unrelated-world.after", probe.NATIVE_SCRIPT)
                self.assertIn("cmp /tmp/mandatory.before /tmp/mandatory.after-cleanup", probe.NATIVE_SCRIPT)

    def test_binary_symlink_multilink_and_drift_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "oracle"
            binary.write_bytes(b"original")
            binary.chmod(0o700)
            link = root / "link"
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                probe.native.snapshot_retention_binary(link)
            link.unlink()
            link.hardlink_to(binary)
            with self.assertRaises(ValueError):
                probe.native.snapshot_retention_binary(binary)
            link.unlink()
            snapshot = probe.native.snapshot_retention_binary(binary)
            binary.rename(root / "retained-original")
            binary.write_bytes(snapshot.data)
            binary.chmod(0o700)
            with mock.patch.object(probe, "command") as build, self.assertRaisesRegex(ValueError, "identity changed"):
                probe.fixtures(root, Path("/fixture/nfpm"), snapshot, "syswarden-base", True)
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
