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
CID = "b" * 64
NAME = "syswarden-ssh-binder-" + "c" * 32
TOKEN = "d" * 64


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
        self.assertEqual(oracle.oracle_case("access-exchange")[1], ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=forwarding", "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=0", "SYSWARDEN_SSH_ISOLATED_ACCESS_EXCHANGE=1"])
        for step in ("main", "drop-in"):
            name, environment = oracle.oracle_case("recovery-interrupt-" + step)
            self.assertEqual(name, "TestSSHIsolatedSystemdRecoveryOracle")
            self.assertEqual(environment, [
                "SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=forwarding",
                "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=0",
                "SYSWARDEN_SSH_ISOLATED_RECOVERY_INTERRUPT=" + step,
            ])
        for value in ("", "recovery", "other", "activation.*", "recovery-forwarding\n",
                      "recovery-interrupt", "recovery-interrupt-reload", "recovery-interrupt-main\n"):
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

    def test_execute_binds_create_and_all_operations_to_owned_id(self):
        for outcome in ("success", "timeout", "foreign-token", "wrong-returned-id", "occupied-name"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                (output / "sshpolicy.test").write_bytes(b"synthetic binary")
                (output / "setup.sh").write_bytes(b"synthetic setup")
                calls = []
                name, token = None, None

                def run(argv, **_kwargs):
                    nonlocal name, token
                    calls.append(copy.deepcopy(argv))
                    code, stdout, stderr = 0, "", ""
                    if argv[1] == "info":
                        stdout = "true"
                    elif argv[1:3] == ["image", "inspect"]:
                        stdout = json.dumps([image_fixture()])
                    elif argv[1] == "create":
                        name = argv[argv.index("--name") + 1]
                        label = argv[argv.index("--label") + 1]
                        self.assertTrue(label.startswith(oracle.OWNER_LABEL + "="))
                        token = label.split("=", 1)[1]
                        self.assertRegex(token, r"^[0-9a-f]{64}$")
                        self.assertNotIn("--rm", argv)
                        if outcome in ("timeout", "foreign-token"):
                            raise subprocess.TimeoutExpired(argv, 90, output="private-fixture-sentinel")
                        stdout = ("e" * 64 if outcome == "wrong-returned-id" else CID) + "\n"
                    elif argv[1:3] == ["container", "exists"]:
                        created = any(c[1] == "create" for c in calls)
                        removed = any(c[1] == "rm" for c in calls)
                        code = 0 if outcome == "occupied-name" or created and not removed else 1
                    elif argv[1:3] == ["container", "inspect"]:
                        labels = {oracle.OWNER_LABEL: "foreign" if outcome == "foreign-token" else token}
                        stdout = json.dumps([{"Id": CID, "Name": name, "Config": {"Labels": labels}}])
                    elif argv[1] == "inspect":
                        self.assertEqual(argv[-1], CID)
                        stdout = json.dumps([container_fixture(output)])
                    elif argv[1] == "start":
                        self.assertEqual(argv[-1], CID)
                    elif argv[1] == "exec":
                        self.assertEqual(argv[2], CID)
                        if "is-system-running" in argv:
                            stdout = "running"
                        elif "-test.v" in argv:
                            stdout = "--- PASS: TestSSHIsolatedSystemdActivationOracle (1.00s)\n"
                    elif argv[1] == "rm":
                        self.assertEqual(argv, ["podman", "rm", "-f", CID])
                    else:
                        self.fail("unexpected command: " + repr(argv))
                    return subprocess.CompletedProcess(argv, code, stdout, stderr)

                with patch.object(oracle.Recorder, "run", side_effect=run):
                    result = oracle.execute(IMAGE, output)
                self.assertEqual(result["status"], "pass" if outcome == "success" else "fail")
                removed = [c for c in calls if c[1] == "rm"]
                self.assertEqual(len(removed), int(outcome in ("success", "timeout")))
                if outcome in ("success", "timeout"):
                    self.assertTrue(result["cleanup"]["absent"])
                    self.assertEqual(result["cleanup"]["exists"], 1)
                    self.assertEqual(result["cleanup"]["id_exists"], 1)
                elif outcome != "occupied-name":
                    self.assertFalse(result["cleanup"]["absent"])
                else:
                    self.assertFalse(any(c[1] == "create" for c in calls))
                    self.assertNotIn("cleanup", result)
                if outcome != "success":
                    self.assertFalse(any(c[1] in ("start", "exec") for c in calls))
                self.assertNotIn("private-fixture-sentinel", json.dumps(result))
                self.assertEqual(json.loads((output / "result.json").read_text()), result)

    def test_cleanup_refuses_foreign_or_replaced_identity(self):
        original = {"Id": CID, "Name": NAME, "Config": {"Labels": {oracle.OWNER_LABEL: TOKEN}}}
        for scenario in ("wrong-label", "missing-label", "wrong-id", "wrong-name", "short-id",
                         "duplicate-inspection", "malformed", "replacement", "renamed-original"):
            with self.subTest(scenario=scenario):
                calls = []
                inspections = 0

                def run(argv, **_kwargs):
                    nonlocal inspections
                    calls.append(argv)
                    if argv[1:3] == ["container", "exists"]:
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    self.assertEqual(argv[1:3], ["container", "inspect"])
                    inspections += 1
                    item = copy.deepcopy(original)
                    if scenario == "wrong-label" or scenario == "replacement" and inspections == 2:
                        item["Config"]["Labels"][oracle.OWNER_LABEL] = "foreign"
                    elif scenario == "missing-label":
                        item["Config"]["Labels"] = {}
                    elif scenario == "wrong-id":
                        item["Id"] = "e" * 64
                    elif scenario == "short-id":
                        item["Id"] = CID[:12]
                    elif scenario == "wrong-name" or scenario == "renamed-original" and inspections == 2:
                        item["Name"] = "foreign-name"
                    wire = json.dumps([item, item] if scenario == "duplicate-inspection" else [item])
                    if scenario == "malformed":
                        wire = "private-fixture-sentinel"
                    return subprocess.CompletedProcess(argv, 0, wire, "")

                result = oracle.cleanup(run, NAME, TOKEN, CID)
                self.assertFalse(result["absent"])
                self.assertFalse(any(c[1] == "rm" for c in calls))
                self.assertNotIn("private-fixture-sentinel", json.dumps(result))

    def test_cleanup_requires_both_name_and_original_id_absent(self):
        for original_exists in (0, 1, 125):
            responses = [subprocess.CompletedProcess([], code, "", "") for code in (1, original_exists)]
            with self.subTest(original_exists=original_exists), patch.object(oracle.Recorder, "run", side_effect=responses) as run:
                result = oracle.cleanup(run, NAME, TOKEN, CID)
                self.assertEqual(result["absent"], original_exists == 1)
                self.assertEqual([c.args[0][-1] for c in run.call_args_list], [NAME, CID])
        for removal, name_after, id_after in ((0, 1, 1), (125, 1, 1), (0, 0, 1), (0, 1, 0), (0, 125, 1), (0, 1, 125)):
            with self.subTest(removal=removal, name_after=name_after, id_after=id_after):
                ownership = json.dumps([{"Id": CID, "Name": NAME, "Config": {"Labels": {oracle.OWNER_LABEL: TOKEN}}}])
                responses = [subprocess.CompletedProcess([], 0, "", ""),
                             subprocess.CompletedProcess([], 0, ownership, ""),
                             subprocess.CompletedProcess([], 0, ownership, "")]
                responses += [subprocess.CompletedProcess([], code, "", "") for code in (removal, name_after, id_after)]
                with patch.object(oracle.Recorder, "run", side_effect=responses) as run:
                    result = oracle.cleanup(run, NAME, TOKEN, CID)
                self.assertEqual(result["absent"], (removal, name_after, id_after) == (0, 1, 1))
                self.assertEqual(run.call_args_list[1].args[0][-1], NAME)
                self.assertEqual(run.call_args_list[2].args[0][-1], CID)
                self.assertEqual(run.call_args_list[3].args[0], ["podman", "rm", "-f", CID])
                self.assertEqual([c.args[0][-1] for c in run.call_args_list[-2:]], [NAME, CID])

    def test_cleanup_invalid_binding_or_inspection_failure_never_removes(self):
        for name, token, cid in (("foreign", TOKEN, CID), (NAME, "", CID), (NAME, TOKEN, CID[:12])):
            with patch.object(oracle.Recorder, "run") as run:
                self.assertFalse(oracle.cleanup(run, name, token, cid)["absent"])
                run.assert_not_called()
        for codes in ((125,), (0, 125)):
            responses = [subprocess.CompletedProcess([], code, "private-fixture-sentinel", "") for code in codes]
            with patch.object(oracle.Recorder, "run", side_effect=responses) as run:
                result = oracle.cleanup(run, NAME, TOKEN, CID)
                self.assertFalse(result["absent"])
                self.assertFalse(any(c.args[0][1] == "rm" for c in run.call_args_list))
                self.assertNotIn("private-fixture-sentinel", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
