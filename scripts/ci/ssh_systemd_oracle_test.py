#!/usr/bin/env python3
"""Isolation and cleanup refusals for the explicit native SSH oracle."""

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
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
