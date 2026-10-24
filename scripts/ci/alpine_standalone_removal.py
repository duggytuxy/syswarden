#!/usr/bin/env python3
"""Explicit, networkless v5 prepared standalone-uninstall native scenario.

Use an existing exact prepared Alpine lifecycle image and a digest-bound APK
as a payload source only. No package transaction, image build or pull occurs.
This report is independent of historical native package lifecycle evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tarfile
import uuid

import package_lifecycle_lab as lab


PROFILE = "alpine-prepared-standalone-uninstall-v1"
SCENARIO = "standalone-uninstall"
MAX_PACKAGE_BYTES = 256 << 20
PAYLOAD_MODES = {
    "opt/syswarden/bin/syswarden-cli": 0o750,
    "opt/syswarden/bin/syswarden-core": 0o750,
    "opt/syswarden/bin/syswarden-tui": 0o750,
    "opt/syswarden/signatures.json": 0o640,
    "usr/share/bash-completion/completions/syswarden": 0o644,
}
PAYLOAD_LINKS = {
    "usr/local/bin/syswarden": "/opt/syswarden/bin/syswarden-cli",
    "usr/local/bin/syswarden-tui": "/opt/syswarden/bin/syswarden-tui",
}
REQUIRED_CHECKS = (
    "architecture", "unregistered.before", "payload.stage", "policy.seed",
    "state.seed", "operator.before", "fixture.activate", "product.active",
    "operator.installed", "runtime.seed", "recovery.review", "uninstall",
    "generated.removed", "absent.removed", "operator.removed", "operator.reload",
    "absent.reloaded", "runtime.restart", "absent.restart", "operator.restart",
)
DISPATCH_BOUNDARY = '\nif [ "${INVOCATION}" = "initial" ]; then\n    if ! probe_execution_architecture; then\n'


class JournalRunner:
    """Keep exact command observations in the new private output directory."""

    def __init__(self, delegate: lab.CommandRunner, path: Path):
        self.delegate = delegate
        self.path = path
        with path.open("x", encoding="utf-8"):
            pass
        path.chmod(0o600)

    def run(self, args, *, timeout, cwd=None):
        entry = {"args": list(args), "timeout_seconds": timeout,
                 "cwd": str(cwd) if cwd is not None else None}
        try:
            result = self.delegate.run(args, timeout=timeout, cwd=cwd)
            entry.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
            return result
        except Exception as exc:
            entry["error"] = str(exc)
            raise
        finally:
            with self.path.open("a", encoding="utf-8") as journal:
                journal.write(json.dumps(entry, sort_keys=True) + "\n")


def build_script() -> str:
    """Reuse helpers only; replace the entire native scenario dispatcher."""
    if lab.LIFECYCLE_SCRIPT.count(DISPATCH_BOUNDARY) != 1:
        raise lab.LifecycleLabError("common lifecycle helper boundary changed")
    definitions = lab.LIFECYCLE_SCRIPT.split(DISPATCH_BOUNDARY)[0]
    fixture = Path(__file__).with_suffix(".sh").read_text(encoding="utf-8")
    return definitions + "\n" + fixture


def validate_events(events: list[dict[str, str]]) -> None:
    expected = [f"{SCENARIO}.{key}" for key in REQUIRED_CHECKS]
    if [item.get("check") for item in events] != expected:
        raise lab.LifecycleLabError("standalone checks are missing, duplicate, unexpected or reordered")
    if any(item.get("status") != "pass" for item in events):
        raise lab.LifecycleLabError("a standalone required check failed")


def inspect_payload(data: bytes) -> tuple[str, dict[str, bytes]]:
    """Read only allowlisted regular payloads; never extract archive paths."""
    selected: dict[str, bytes] = {}
    seen: set[str] = set()
    metadata: bytes | None = None
    member_count, expanded_size = 0, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz", ignore_zeros=True) as archive:
        for member in archive:
            member_count += 1
            expanded_size += member.size
            if member_count > 4096 or expanded_size > 512 << 20:
                raise lab.LifecycleLabError("candidate archive exceeds the bounded payload inventory")
            name = member.name.removeprefix("./")
            if name not in PAYLOAD_MODES and name not in PAYLOAD_LINKS and name != ".PKGINFO":
                continue
            if name in seen:
                raise lab.LifecycleLabError(f"duplicate candidate entry: {name}")
            seen.add(name)
            if member.uid != 0 or member.gid != 0:
                raise lab.LifecycleLabError(f"candidate entry has unexpected ownership: {name}")
            if name in PAYLOAD_LINKS:
                if not member.issym() or member.linkname != PAYLOAD_LINKS[name]:
                    raise lab.LifecycleLabError(f"candidate launcher is not exact: {name}")
                continue
            limit = 64 << 10 if name == ".PKGINFO" else 128 << 20
            if not member.isfile() or not 0 < member.size <= limit:
                raise lab.LifecycleLabError(f"candidate entry is not a bounded regular file: {name}")
            if name in PAYLOAD_MODES and member.mode != PAYLOAD_MODES[name]:
                raise lab.LifecycleLabError(f"candidate payload mode differs: {name}")
            reader = archive.extractfile(member)
            if reader is None:
                raise lab.LifecycleLabError(f"candidate entry cannot be read: {name}")
            content = reader.read(limit + 1)
            if len(content) != member.size:
                raise lab.LifecycleLabError(f"candidate entry is truncated: {name}")
            if name == ".PKGINFO":
                metadata = content
            else:
                selected[name] = content
    if seen != set(PAYLOAD_MODES) | set(PAYLOAD_LINKS) | {".PKGINFO"} or metadata is None:
        raise lab.LifecycleLabError("candidate lacks the exact standalone payload inventory")
    values: dict[str, str] = {}
    for line in metadata.decode("utf-8").splitlines():
        key, separator, value = line.partition(" = ")
        if separator and key in {"pkgname", "pkgver", "arch"}:
            if key in values:
                raise lab.LifecycleLabError("duplicate APK identity metadata")
            values[key] = value
    if values.get("pkgname") != "syswarden" or values.get("arch") != "x86_64":
        raise lab.LifecycleLabError("candidate is not a SysWarden Linux AMD64 APK")
    version = values.get("pkgver", "").removesuffix("-r0")
    if lab.parse_syswarden_version(version) < (5, 0, 0):
        raise lab.LifecycleLabError("standalone profile requires candidate version 5.00.0 or later")
    for name in ("syswarden-cli", "syswarden-core", "syswarden-tui"):
        content = selected[f"opt/syswarden/bin/{name}"]
        if content[:6] != b"\x7fELF\x02\x01" or content[18:20] != b"\x3e\x00":
            raise lab.LifecycleLabError(f"candidate executable is not Linux AMD64 ELF: {name}")
    cli = selected["opt/syswarden/bin/syswarden-cli"]
    for variable, relative in (
        ("standaloneCoreSHA256", "bin/syswarden-core"),
        ("standaloneTUISHA256", "bin/syswarden-tui"),
        ("standaloneSignaturesSHA256", "signatures.json"),
    ):
        digest = hashlib.sha256(selected[f"opt/syswarden/{relative}"]).hexdigest()
        binding = f"syswarden-cli/pkg/system.{variable}={digest}".encode()
        if binding not in cli:
            raise lab.LifecycleLabError(f"candidate CLI lacks exact companion build binding: {variable}")
    # The actual uninstall additionally validates the compiled values, payload
    # bytes and identities. Build metadata alone cannot establish this check.
    return version, selected


def freeze_payload(candidate: Path, expected_sha256: str, destination: Path) -> dict[str, object]:
    before = candidate.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PACKAGE_BYTES:
        raise lab.LifecycleLabError("candidate must be a bounded regular APK, not a symlink")
    data = candidate.read_bytes()
    after = candidate.lstat()
    if len(data) != before.st_size or lab._regular_file_identity(before) != lab._regular_file_identity(after):
        raise lab.LifecycleLabError("candidate changed while reading")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise lab.LifecycleLabError("candidate SHA-256 differs from the explicit input")
    version, payloads = inspect_payload(data)
    payload_root = destination / "payload"
    payload_root.mkdir(mode=0o700)
    inventory, checksums, bindings = [], [], {}
    for relative, content in payloads.items():
        path = payload_root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(PAYLOAD_MODES[relative])
        digest = hashlib.sha256(content).hexdigest()
        bindings[relative] = digest
        checksums.append(f"{digest}  {relative}\n")
        inventory.append(f"/{relative}\tfile\t{PAYLOAD_MODES[relative]:o}\t0\t0\t{digest}\n")
    (destination / "payload.sha256").write_text("".join(checksums))
    (destination / "inventory-candidate").write_text("".join(inventory))
    return {"filename": candidate.name, "sha256": actual, "version": version,
            "payload_sha256": bindings, "source": "APK extraction only; never registered"}


def validate_boots(boots: list[dict[str, object]], spec: lab.PlatformSpec) -> None:
    if [boot.get("invocation") for boot in boots] != ["initial", "restart-one"]:
        raise lab.LifecycleLabError("standalone evidence requires both real boots")
    previous = None
    for boot in boots:
        if boot.get("boot_exit_code") != 0 or boot.get("script_exit_code") != 0:
            raise lab.LifecycleLabError("standalone boot or script failed")
        expected_marker = "restart-one" if previous is None else "complete"
        if boot.get("restart_state") != expected_marker:
            raise lab.LifecycleLabError("standalone restart handoff is incomplete")
        pre = lab._validate_runtime_snapshot_evidence(boot.get("pre_exec"), spec, "absent")
        post = lab._validate_runtime_snapshot_evidence(boot.get("post_exec"), spec, "absent")
        lab._validate_process_security_evidence(boot.get("exec_security"),
            sys_admin_present=frozenset(), sys_ptrace_present=frozenset(), label="standalone execution")
        current = pre["pid1_starttime_ticks"]
        if current != post["pid1_starttime_ticks"] or pre["cron_main_pid"] != post["cron_main_pid"]:
            raise lab.LifecycleLabError("init or cron changed during standalone execution")
        if previous is not None and current == previous:
            raise lab.LifecycleLabError("container restart did not replace PID 1")
        previous = current


def validate_inputs(args: argparse.Namespace) -> None:
    if not args.run_native:
        raise lab.LifecycleLabError("native execution requires explicit --run-native")
    if os.geteuid() == 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise lab.LifecycleLabError("requires an unprivileged Linux AMD64 host")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise lab.LifecycleLabError("image must be an existing exact sha256 image ID")
    if not re.fullmatch(r"[0-9a-f]{64}", args.candidate_sha256):
        raise lab.LifecycleLabError("candidate SHA-256 must be lowercase hexadecimal")
    for path in (args.candidate, args.output):
        if not path.is_absolute() or any(character in str(path) for character in ":\n\r"):
            raise lab.LifecycleLabError("input/output paths must be absolute and safe for bind mounts")
        if path.parent.resolve(strict=True) != path.parent:
            raise lab.LifecycleLabError("input/output parent directories must not contain symlinks")
    if args.output.exists() or args.output.is_symlink():
        raise lab.LifecycleLabError("output must be a new directory")
    if not 30 <= args.timeout <= 1800:
        raise lab.LifecycleLabError("timeout must be between 30 and 1800 seconds")


def run(args: argparse.Namespace, runner: lab.CommandRunner | None = None) -> dict[str, object]:
    validate_inputs(args)
    args.output.mkdir(mode=0o700)
    runner = JournalRunner(runner or lab.CommandRunner(), args.output / "commands.jsonl")
    report: dict[str, object] = {
        "schema_version": 1, "profile": PROFILE, "scenario": SCENARIO,
        "status": "fail", "release_ready": False, "network": "none",
        "scope": "prepared standalone removal only; no install, upgrade or package erase acceptance",
        "image": args.image, "alpine_version": args.alpine_version, "boots": [],
    }
    name = "syswarden-standalone-" + uuid.uuid4().hex[:16]
    create_attempted = False
    try:
        report["podman_version"] = lab.ensure_rootless_podman(runner, args.podman)
        inspected = runner.run((args.podman, "image", "inspect", args.image), timeout=30)
        lab.require_success(inspected, "inspect existing prepared image")
        images = json.loads(inspected.stdout)
        if (len(images) != 1 or images[0].get("Id") != args.image
                or images[0].get("Architecture") != "amd64" or images[0].get("Os") != "linux"
                or images[0].get("Config", {}).get("Cmd") != ["/sbin/openrc-init"]):
            raise lab.LifecycleLabError("image is not the exact prepared Linux AMD64 OpenRC image")
        candidate_root, previous_root, result_root = (args.output / part for part in ("candidate", "empty-previous", "results"))
        for directory in (candidate_root, previous_root, result_root):
            directory.mkdir(mode=0o700)
        candidate = freeze_payload(args.candidate, args.candidate_sha256, candidate_root)
        report["candidate"] = candidate
        script = args.output / "standalone.sh"
        script.write_text(build_script(), encoding="utf-8")
        script.chmod(0o600)
        helper, helper_evidence = lab.snapshot_lifecycle_helper(args.output)
        report["helper"] = helper_evidence
        report["script_sha256"] = lab.sha256_file(script)
        report["source_sha256"] = {
            filename: lab.sha256_file(Path(__file__).with_name(filename))
            for filename in ("alpine_standalone_removal.py", "alpine_standalone_removal.sh", "package_lifecycle_lab.py", "package_v5_apk_removal.sh")
        }
        spec = replace(next(item for item in lab.DEFAULT_PLATFORMS
                            if item.family == "apk" and item.version == args.alpine_version), image=args.image)
        artifact = lab.PackageArtifact(path=args.candidate, version=str(candidate["version"]), sha256=str(candidate["sha256"]))
        pair = lab.PackagePair(artifact, artifact)  # No previous artifact is read or installed.
        create = list(lab.container_run_arguments(args.podman, args.image, name,
                      candidate_root, previous_root, script, helper, result_root, spec, SCENARIO, pair))
        create[2:2] = ["--pull=never", "--cpus=2"]
        create_attempted = True
        lab.require_success(runner.run(create, timeout=60), "create standalone container")
        isolation = lab.inspect_container_isolation(runner, args.podman, name, spec,
                    candidate_root=candidate_root, previous_root=previous_root,
                    script_path=script, helper_path=helper, result_root=result_root)
        report["isolation"] = lab._json_dataclass_evidence(isolation)
        for invocation in ("initial", "restart-one"):
            command = ((args.podman, "start", name) if invocation == "initial" else
                       (args.podman, "restart", "--time", "10", name))
            boot_result = runner.run(command, timeout=60)
            boot: dict[str, object] = {"invocation": invocation, "boot_exit_code": boot_result.returncode}
            report["boots"].append(boot)
            lab.require_success(boot_result, "start or restart standalone container")
            lab.attest_runtime_namespace(runner, args.podman, name, spec)
            pre = lab.attest_runtime_snapshot(runner, args.podman, name, spec, "absent")
            boot["pre_exec"] = lab._json_dataclass_evidence(pre)
            if invocation == "restart-one" and pre.pid1_starttime_ticks == report["boots"][0]["post_exec"]["pid1_starttime_ticks"]:
                raise lab.LifecycleLabError("real restart did not replace PID 1")
            executed = runner.run(lab.lifecycle_exec_arguments(args.podman, name, spec,
                                   "exec /bin/sh /lab/package-lifecycle.sh"), timeout=args.timeout)
            boot["script_exit_code"] = executed.returncode
            security, _ = lab.parse_exec_security_output(executed.stdout, "standalone execution", spec)
            boot["exec_security"] = lab._json_dataclass_evidence(security)
            lab.require_success(executed, "execute standalone scenario")
            marker = (result_root / "restart-state").read_text()
            expected = "restart-one\n" if invocation == "initial" else "complete\n"
            if marker != expected:
                raise lab.LifecycleLabError("standalone scenario did not publish its exact restart handoff")
            boot["restart_state"] = marker.strip()
            lab.attest_runtime_namespace(runner, args.podman, name, spec)
            post = lab.attest_runtime_snapshot(runner, args.podman, name, spec, "absent")
            boot["post_exec"] = lab._json_dataclass_evidence(post)
        report["events"] = lab.parse_events(result_root / "events.tsv")
        validate_events(report["events"])
        validate_boots(report["boots"], spec)
        lab._validate_runtime_isolation_evidence(report["isolation"], spec)
        report["status"] = "pass"
    except (lab.LifecycleLabError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        report["error"] = str(exc)
    finally:
        if create_attempted:
            try:
                removed = runner.run((args.podman, "rm", "--force", name), timeout=30)
                exists = runner.run((args.podman, "container", "exists", name), timeout=30)
                report["cleanup"] = {"remove_exit_code": removed.returncode, "exists_exit_code": exists.returncode}
                if removed.returncode != 0 or exists.returncode != 1:
                    raise lab.LifecycleLabError("standalone container cleanup did not prove absence")
            except (lab.LifecycleLabError, OSError) as exc:
                report["status"] = "fail"
                report["cleanup_error"] = str(exc)
        report["command_journal"] = {"filename": "commands.jsonl", "sha256": lab.sha256_file(runner.path)}
        lab.write_report(args.output / "report.json", report, pretty=True)
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run-native", action="store_true")
    result.add_argument("--candidate", required=True, type=Path)
    result.add_argument("--candidate-sha256", required=True)
    result.add_argument("--image", required=True, help="exact ID of an already prepared lifecycle image")
    result.add_argument("--alpine-version", choices=("3.22", "3.24"), required=True)
    result.add_argument("--output", type=Path, required=True, help="new private output directory")
    result.add_argument("--podman", default="podman")
    result.add_argument("--timeout", type=int, default=600)
    return result


def main() -> int:
    try:
        report = run(parser().parse_args())
    except (lab.LifecycleLabError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in ("profile", "status", "release_ready")}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
