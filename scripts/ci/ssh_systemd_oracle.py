#!/usr/bin/env python3
"""Explicit isolated production SSH binder oracle; never a host service test."""

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path


OWNER_LABEL = "io.syswarden.ssh-systemd-oracle.owner"


def binary_stamp(value: os.stat_result) -> tuple:
    # Reading a new file may update atime. Pin identity, permissions, size and
    # nanosecond mutation timestamps without treating that read as a mutation.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def checked_binary(path: Path, expected: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None or not path.is_absolute():
        raise ValueError("absolute binary path and exact SHA-256 required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 20 <= before.st_size <= 128 * 1024 * 1024:
            raise ValueError("bounded regular test binary required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(128 * 1024 * 1024 + 1)
            if binary_stamp(os.fstat(fd)) != binary_stamp(before):
                raise ValueError("test binary changed while reading")
    finally:
        os.close(fd)
    if (
        len(data) != before.st_size
        or hashlib.sha256(data).hexdigest() != expected
        or data[:7] != b"\x7fELF\x02\x01\x01"
        or data[18:20] != b"\x3e\x00"
    ):
        raise ValueError("test binary identity or AMD64 ELF format differs")
    return data


def validate_image(inspection: dict, image: str) -> None:
    config = inspection["Config"]
    if (
        inspection["Id"].removeprefix("sha256:") != image.removeprefix("sha256:")
        or inspection["Os"] != "linux"
        or inspection["Architecture"] != "amd64"
        or config["Cmd"] != ["/sbin/init"]
        or config.get("Entrypoint")
        or config.get("Volumes")
    ):
        raise ValueError("unexpected prepared image")


def validate_isolation(inspection: dict, image: str, output: Path) -> None:
    host = inspection["HostConfig"]
    mounts = inspection["Mounts"]
    expected = {
        "/oracle/sshpolicy.test": str(output / "sshpolicy.test"),
        "/oracle/setup.sh": str(output / "setup.sh"),
    }
    if (
        inspection["Image"].removeprefix("sha256:") != image.removeprefix("sha256:")
        or inspection["Path"] != "/sbin/init"
        or host["NetworkMode"] != "none"
        or host["Privileged"] is not False
        or any(host[k] != "private" for k in ("PidMode", "CgroupMode", "IpcMode", "UTSMode"))
        or host["Devices"]
        or host["PortBindings"]
        or host["PublishAllPorts"]
        or host["PidsLimit"] != 256
        or host["Memory"] != 1024**3
        or host["NanoCpus"] != 2 * 10**9
        or set(host["CapAdd"]) != {"CAP_SYS_ADMIN", "CAP_SYS_PTRACE"}
        or set(host["SecurityOpt"]) != {"no-new-privileges", "label=disable"}
        or len(mounts) != 2
        or {m["Destination"]: m["Source"] for m in mounts} != expected
        or any(m["RW"] or m["Type"] != "bind" or m["Propagation"] != "rprivate" for m in mounts)
    ):
        raise ValueError("unexpected container isolation")
    tmpfs = host["Tmpfs"]
    required = {
        "/run": {"rw", "nodev", "nosuid", "exec", "size=64m", "mode=755", "rprivate"},
        "/tmp": {"rw", "nodev", "nosuid", "exec", "size=128m", "mode=1777", "rprivate"},
    }
    if set(tmpfs) != set(required):
        raise ValueError("unexpected temporary mounts")
    for target, options in required.items():
        actual = set(tmpfs[target].split(","))
        if not options <= actual or actual - options - {"tmpcopyup", "notmpcopyup"}:
            raise ValueError("unexpected temporary mount options")


class Recorder:
    def __init__(self, output: Path):
        self.output = output
        self.count = 0

    def run(self, argv: list[str], timeout: int = 90):
        self.count += 1
        if argv[:1] != ["podman"]:
            raise ValueError("only local Podman commands are allowed")
        argv = ["podman", "--remote=false", *argv[1:]]
        record = {"argv": argv}
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
            record.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
            return result
        except subprocess.TimeoutExpired as exc:
            record["error"] = "command timed out"
            for key, value in (("stdout", exc.stdout), ("stderr", exc.stderr)):
                record[key] = value.decode(errors="replace") if isinstance(value, bytes) else value
            raise
        finally:
            (self.output / f"{self.count:02}-command.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )


def must(result) -> str:
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:] + result.stdout[-3000:])
    return result.stdout


def require_native_pass(result, test_name: str) -> None:
    # Exact stdout, including synthetic journal bytes, stays in private command
    # records. Never echo its tail into result.json or the console on failure.
    if result.returncode:
        raise RuntimeError("native SSH oracle failed; inspect the private command records")
    lines = result.stdout.splitlines()
    passes = [line for line in lines if re.fullmatch(r"--- PASS: " + re.escape(test_name) + r" \([0-9.]+s\)", line)]
    if len(passes) != 1 or any(line.lstrip().startswith(("--- SKIP:", "--- FAIL:")) for line in lines):
        raise RuntimeError("exact passing native SSH result without skips is required; inspect the private command records")


def owned_container(run, selector: str, name: str, token: str, cid: str | None) -> str:
    # The token binds this invocation, not every container with a product label.
    # Full inspect identity prevents prefix IDs, aliases and name replacement.
    inspected = run(["podman", "container", "inspect", selector])
    if inspected.returncode:
        raise ValueError("container ownership could not be verified")
    try:
        values = json.loads(inspected.stdout)
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError
        item = values[0]
        actual = item["Id"]
        if (not isinstance(actual, str) or re.fullmatch(r"[0-9a-f]{64}", actual) is None
                or item["Name"] != name
                or item["Config"]["Labels"].get(OWNER_LABEL) != token
                or (cid is not None and actual != cid)):
            raise ValueError
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError("container ownership differs; preserve the container") from exc
    return actual


def cleanup(run, name: str, token: str, cid: str | None) -> dict:
    if (re.fullmatch(r"syswarden-ssh-binder-[0-9a-f]{32}", name) is None
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
            or (cid is not None and re.fullmatch(r"[0-9a-f]{64}", cid) is None)):
        return {"absent": False, "error": "invalid container ownership binding"}
    exists = run(["podman", "container", "exists", name])
    if exists.returncode == 1:
        # A known original ID must also be absent, even if its name was changed.
        original = run(["podman", "container", "exists", cid]) if cid else None
        return {"absent": original is None or original.returncode == 1,
                "exists": 1, "id_exists": original.returncode if original else None}
    if exists.returncode != 0:
        return {"absent": False, "exists": exists.returncode}
    try:
        # An uncertain create may establish its ID only through this exact name
        # and unguessable per-invocation token, never through a generic label scan.
        original = owned_container(run, name, name, token, cid)
        owned_container(run, original, name, token, original)
    except ValueError:
        return {"absent": False, "error": "container ownership unverified; no removal attempted"}
    remove = run(["podman", "rm", "-f", original])
    after_name = run(["podman", "container", "exists", name])
    after_id = run(["podman", "container", "exists", original])
    return {
        "absent": remove.returncode == 0 and after_name.returncode == 1 and after_id.returncode == 1,
        "remove": remove.returncode,
        "exists": after_name.returncode,
        "id_exists": after_id.returncode,
    }


def oracle_case(scenario: str) -> tuple[str, list[str]]:
    if scenario == "activation":
        return "TestSSHIsolatedSystemdActivationOracle", []
    if scenario == "recovery-noop":
        return "TestSSHIsolatedSystemdRecoveryOracle", ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=forwarding", "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=1"]
    if scenario == "access-exchange":
        return "TestSSHIsolatedSystemdRecoveryOracle", ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=forwarding", "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=0", "SYSWARDEN_SSH_ISOLATED_ACCESS_EXCHANGE=1"]
    profiles = {"recovery-forwarding": "forwarding", "recovery-cis": "cis", "recovery-legacy-cis": "legacy-cis"}
    if scenario not in profiles:
        raise ValueError("unqualified native SSH scenario")
    return "TestSSHIsolatedSystemdRecoveryOracle", ["SYSWARDEN_SSH_ISOLATED_RECOVERY_PROFILE=" + profiles[scenario], "SYSWARDEN_SSH_ISOLATED_RECOVERY_NOOP=0"]


def run_oracle_commands(run, prefix: list[str], test_name: str, environment: list[str], recovery: bool):
    base = prefix + ["env", "GOMAXPROCS=2", "SYSWARDEN_SSH_ISOLATED_SYSTEMD_ORACLE_TEST=1"]
    exported = None
    try:
        test = run(base + environment + [
            "/oracle/sshpolicy.test", "-test.run=^" + test_name + "$",
            "-test.v", "-test.timeout=180s",
        ], timeout=200)
    finally:
        if recovery:
            # Go watchdogs need not run t.Cleanup. Attempt a separate bounded
            # read before container removal; command stdout stays private.
            exported = run(base + ["/oracle/sshpolicy.test",
                "-test.run=^TestSSHIsolatedSystemdJournalExport$", "-test.v", "-test.timeout=10s"], timeout=15)
    return test, exported


def execute(image: str, output: Path, scenario: str = "activation") -> dict:
    run = Recorder(output).run
    name = "syswarden-ssh-binder-" + os.urandom(16).hex()
    token = os.urandom(32).hex()
    cid = None
    attempted = False
    result = {"status": "fail", "image": image, "container": name, "scenario": scenario}
    try:
        test_name, environment = oracle_case(scenario)
        result["inputs"] = {
            filename: hashlib.sha256((output / filename).read_bytes()).hexdigest()
            for filename in ("sshpolicy.test", "setup.sh")
        }
        if must(run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"])).strip() != "true":
            raise ValueError("rootless Podman required")
        validate_image(json.loads(must(run(["podman", "image", "inspect", image])))[0], image)
        command = [
            "podman", "create", "--name", name, "--label", OWNER_LABEL + "=" + token,
            "--network=none", "--pid=private", "--ipc=private", "--uts=private", "--cgroupns=private",
            "--cap-add=SYS_ADMIN", "--cap-add=SYS_PTRACE", "--systemd=always",
            "--security-opt=no-new-privileges", "--security-opt=label=disable",
            "--pids-limit=256", "--memory=1g", "--cpus=2", "--platform=linux/amd64",
            "--tmpfs=/run:rw,nodev,nosuid,exec,size=64m,mode=755,notmpcopyup",
            "--tmpfs=/tmp:rw,nodev,nosuid,exec,size=128m,mode=1777",
            "--volume", str(output / "sshpolicy.test") + ":/oracle/sshpolicy.test:ro",
            "--volume", str(output / "setup.sh") + ":/oracle/setup.sh:ro", image,
        ]
        if run(["podman", "container", "exists", name]).returncode != 1:
            raise ValueError("new oracle container name must be absent")
        attempted = True
        created = must(run(command)).strip()
        if re.fullmatch(r"[0-9a-f]{64}", created) is None:
            raise ValueError("create did not return an exact container ID")
        cid = created
        owned_container(run, name, name, token, cid)
        owned_container(run, cid, name, token, cid)
        validate_isolation(json.loads(must(run(["podman", "inspect", cid])))[0], image, output)
        must(run(["podman", "start", cid]))
        for _ in range(30):
            state = run(["podman", "exec", cid, "systemctl", "is-system-running"])
            if state.stdout.strip() in {"running", "degraded"}:
                break
            time.sleep(1)
        else:
            raise RuntimeError("systemd readiness timeout")
        prefix = [
            "podman", "exec", cid, "setpriv", "--bounding-set=-sys_admin",
            "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        ]
        must(run(prefix + ["/bin/sh", "/oracle/setup.sh"]))
        test, exported = run_oracle_commands(run, prefix, test_name, environment, scenario != "activation")
        run(["podman", "exec", cid, "journalctl", "--no-pager", "-u", "ssh.service", "-n", "100"])
        require_native_pass(test, test_name)
        if exported is not None:
            require_native_pass(exported, "TestSSHIsolatedSystemdJournalExport")
        result["status"] = "pass"
    except (Exception, KeyboardInterrupt):
        result["error"] = "native SSH oracle operation failed; inspect the private command records"
    finally:
        if attempted:
            try:
                result["cleanup"] = cleanup(run, name, token, cid)
            except (Exception, KeyboardInterrupt):
                result["cleanup"] = {"absent": False, "error": "cleanup failed; inspect the private command records"}
            if not result["cleanup"]["absent"]:
                result["status"] = "fail"
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--scenario", choices=("activation", "recovery-forwarding", "recovery-cis", "recovery-legacy-cis", "recovery-noop", "access-exchange"), default="activation")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        os.geteuid() == 0
        or platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or re.fullmatch(r"sha256:[0-9a-f]{64}", args.image) is None
        or not args.output.is_absolute()
        or args.output.exists()
        or args.output.is_symlink()
        or any(c in str(args.output.resolve()) for c in ":,\n\r")
    ):
        parser.error("rootless Linux AMD64, exact prepared image and new absolute output required")
    data = checked_binary(args.binary, args.binary_sha256)
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    (output / "sshpolicy.test").write_bytes(data)
    (output / "sshpolicy.test").chmod(0o700)
    (output / "setup.sh").write_bytes(Path(__file__).with_name("ssh_systemd_oracle_setup.sh").read_bytes())
    result = execute(args.image, output, args.scenario)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
