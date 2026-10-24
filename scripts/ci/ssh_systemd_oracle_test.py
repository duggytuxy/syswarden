#!/usr/bin/env python3
"""Isolation and cleanup refusals for the explicit native SSH oracle."""

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from scripts.ci import ssh_systemd_oracle as oracle
except ModuleNotFoundError:
    import ssh_systemd_oracle as oracle


IMAGE = "sha256:" + "a" * 64


def image_fixture():
    return {
        "Id": IMAGE, "Os": "linux", "Architecture": "amd64",
        "Config": {"Cmd": ["/sbin/init"], "Entrypoint": None, "Volumes": None},
    }


def container_fixture(output):
    return {
        "Image": IMAGE.removeprefix("sha256:"), "Path": "/sbin/init",
        "Mounts": [
            {"Source": str(output / name), "Destination": "/oracle/" + name,
             "Type": "bind", "RW": False, "Propagation": "rprivate"}
            for name in ("sshpolicy.test", "setup.sh")
        ],
        "HostConfig": {
            "NetworkMode": "none", "PidMode": "private", "CgroupMode": "private",
            "IpcMode": "private", "UTSMode": "private", "Devices": [],
            "Privileged": False, "PortBindings": {}, "PublishAllPorts": False,
            "PidsLimit": 256, "Memory": 1024**3, "NanoCpus": 2 * 10**9,
            "CapAdd": ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"],
            "SecurityOpt": ["no-new-privileges", "label=disable"],
            "Tmpfs": {
                "/run": "rw,nodev,nosuid,exec,size=64m,mode=755,rprivate",
                "/tmp": "rw,nodev,nosuid,exec,size=128m,mode=1777,rprivate,tmpcopyup",
            },
        },
    }


class OracleBoundaryTests(unittest.TestCase):
    def test_recorder_requires_local_podman(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = oracle.Recorder(Path(directory))
            response = subprocess.CompletedProcess([], 0, "true", "")
            with patch.object(oracle.subprocess, "run", return_value=response) as run:
                recorder.run(["podman", "info"])
                self.assertEqual(run.call_args.args[0], ["podman", "--remote=false", "info"])
                with self.assertRaises(ValueError):
                    recorder.run(["ssh", "unrelated-host"])
                self.assertEqual(run.call_count, 1)

    def test_binary_identity(self):
        data = bytearray(64)
        data[:7], data[18:20] = b"\x7fELF\x02\x01\x01", b"\x3e\x00"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(oracle.checked_binary(binary, digest), data)
            with self.assertRaises(ValueError):
                oracle.checked_binary(binary, "b" * 64)
            link = binary.with_name("link")
            link.symlink_to(binary)
            with self.assertRaises(OSError):
                oracle.checked_binary(link, digest)
            for offset in (0, 4, 5, 18):
                changed = bytearray(data)
                changed[offset] = 0
                binary.write_bytes(changed)
                with self.subTest(offset=offset), self.assertRaises(ValueError):
                    oracle.checked_binary(binary, hashlib.sha256(changed).hexdigest())
            with self.assertRaises(ValueError):
                oracle.checked_binary(binary.parent, digest)

    def test_binary_change_during_read_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(b"x" * 64)
            original = binary.stat()
            binary.write_bytes(b"x" * 65)
            changed = binary.stat()
            with patch.object(oracle.os, "fstat", side_effect=[original, changed]):
                with self.assertRaisesRegex(ValueError, "changed"):
                    oracle.checked_binary(binary, hashlib.sha256(b"x" * 65).hexdigest())

    def test_binary_read_atime_is_not_mutation(self):
        data = bytearray(64)
        data[:7], data[18:20] = b"\x7fELF\x02\x01\x01", b"\x3e\x00"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(data)
            before = binary.stat()
            fields = {name: getattr(before, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                "st_size", "st_atime_ns", "st_mtime_ns", "st_ctime_ns")}
            after = SimpleNamespace(**(fields | {"st_atime_ns": before.st_atime_ns + 1}))
            digest = hashlib.sha256(data).hexdigest()
            with patch.object(oracle.os, "fstat", side_effect=[before, after]):
                self.assertEqual(oracle.checked_binary(binary, digest), data)
            for field in fields.keys() - {"st_atime_ns"}:
                changed = SimpleNamespace(**(fields | {field: fields[field] + 1}))
                with self.subTest(field=field), patch.object(oracle.os, "fstat", side_effect=[before, changed]):
                    with self.assertRaisesRegex(ValueError, "changed"):
                        oracle.checked_binary(binary, digest)

    def test_scenarios_require_exact_names(self):
        self.assertEqual(oracle.oracle_case("activation"), ("TestSSHIsolatedSystemdActivationOracle", []))
        for profile in ("forwarding", "cis", "legacy-cis"):
            name, environment = oracle.oracle_case("recovery-" + profile)
            self.assertEqual(name, "TestSSHIsolatedSystemdRecoveryOracle")
            self.assertEqual(environment, ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=" + profile, "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=0"])
        self.assertEqual(oracle.oracle_case("recovery-noop")[1], ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=forwarding", "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=1"])
        for value in ("", "recovery", "other", "activation.*", "recovery-forwarding\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                oracle.oracle_case(value)

    def test_recovery_watchdog_still_attempts_private_export(self):
        responses = [subprocess.TimeoutExpired(["fixture"], 200), subprocess.CompletedProcess([], 0, "private journal", "")]
        with patch.object(oracle.Recorder, "run", side_effect=responses) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                oracle.run_oracle_commands(run, ["podman", "exec", "owned-fixture"], "TestFixture", [], True)
        self.assertEqual(run.call_count, 2)
        self.assertIn("-test.run=^TestSSHIsolatedSystemdJournalExport$", run.call_args_list[1].args[0])
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 15)
        with patch.object(oracle.Recorder, "run", side_effect=[subprocess.TimeoutExpired(["fixture"], 200)]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                oracle.run_oracle_commands(run, [], "TestFixture", [], False)
        self.assertEqual(run.call_count, 1)

    def test_native_pass_and_private_failure_output(self):
        name = "TestSSHIsolatedSystemdRecoveryOracle"
        passed = "--- PASS: " + name + " (1.25s)\n"
        oracle.require_native_pass(subprocess.CompletedProcess([], 0, passed, ""), name)
        cases = [(1, "private-journal-sentinel", "private-journal-sentinel"),
                 (0, "", ""), (0, passed * 2, ""),
                 (0, passed + "    --- SKIP: child (0.00s)\n", ""),
                 (0, passed + "    --- FAIL: child (0.00s)\n", ""),
                 (0, passed.replace(name, name + "Other"), "")]
        for code, stdout, stderr in cases:
            with self.subTest(code=code, stdout=stdout):
                with self.assertRaises(RuntimeError) as caught:
                    oracle.require_native_pass(subprocess.CompletedProcess([], code, stdout, stderr), name)
                self.assertNotIn("private-journal-sentinel", str(caught.exception))

    def test_image_identity_and_entrypoint(self):
        oracle.validate_image(image_fixture(), IMAGE)
        for key, value in (("Id", "b" * 64), ("Os", "other"), ("Architecture", "other")):
            fixture = image_fixture()
            fixture[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                oracle.validate_image(fixture, IMAGE)
        for key, value in (("Cmd", ["sh"]), ("Entrypoint", ["sh"]), ("Volumes", {"/etc": {}})):
            fixture = image_fixture()
            fixture["Config"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                oracle.validate_image(fixture, IMAGE)

    def test_isolation_refusals(self):
        output = Path("/fixture")
        oracle.validate_isolation(container_fixture(output), IMAGE, output)
        mutations = {
            "NetworkMode": "host", "PidMode": "host", "CgroupMode": "host",
            "IpcMode": "host", "UTSMode": "host", "Privileged": True,
            "Devices": ["/dev/example"], "PortBindings": {"22": []}, "PublishAllPorts": True,
            "PidsLimit": 0, "Memory": 0, "NanoCpus": 0,
            "CapAdd": ["CAP_SYS_ADMIN"], "SecurityOpt": [],
            "Tmpfs": {"/run": "rw", "/tmp": "rw"},
        }
        for key, value in mutations.items():
            fixture = container_fixture(output)
            fixture["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                oracle.validate_isolation(fixture, IMAGE, output)
        for key, value in (("RW", True), ("Source", "/etc"), ("Destination", "/etc"),
                           ("Type", "volume"), ("Propagation", "shared")):
            fixture = container_fixture(output)
            fixture["Mounts"][0][key] = value
            with self.subTest(mount=key), self.assertRaises(ValueError):
                oracle.validate_isolation(fixture, IMAGE, output)

    def test_uncertain_create_is_cleaned_and_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "sshpolicy.test").write_bytes(b"synthetic binary")
            (output / "setup.sh").write_bytes(b"synthetic setup")
            calls = []
            def run(argv, **_kwargs):
                calls.append(copy.deepcopy(argv))
                if argv[1] == "info":
                    return subprocess.CompletedProcess(argv, 0, "true", "")
                if argv[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(argv, 0, json.dumps([image_fixture()]), "")
                if argv[1] == "create":
                    raise subprocess.TimeoutExpired(argv, 90)
                if argv[1:3] == ["container", "exists"]:
                    code = 1 if any(c[1] == "rm" for c in calls) else 0
                    return subprocess.CompletedProcess(argv, code, "", "")
                if argv[1] == "rm":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.fail("unexpected command")
            with patch.object(oracle.Recorder, "run", side_effect=run):
                result = oracle.execute(IMAGE, output)
            self.assertEqual(result["status"], "fail")
            self.assertTrue(result["cleanup"]["absent"])
            create = next(c for c in calls if c[1] == "create")
            remove = next(c for c in calls if c[1] == "rm")
            self.assertEqual(create[create.index("--name") + 1], remove[-1])
            self.assertEqual(json.loads((output / "result.json").read_text()), result)

    def test_cleanup_failure_is_not_absence(self):
        for codes in ([125], [0, 125, 0], [0, 0, 125]):
            with self.subTest(codes=codes):
                responses = [subprocess.CompletedProcess([], c, "", "") for c in codes]
                with patch.object(oracle.Recorder, "run", side_effect=responses) as run:
                    self.assertFalse(oracle.cleanup(run, "owned-fixture")["absent"])


if __name__ == "__main__":
    unittest.main()
