#!/usr/bin/env python3
"""Produce source-bound SysWarden allocation samples from exact Git subjects."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Sequence


REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = REPOSITORY / "scripts" / "ci" / "source_allocation_contract_v4.10.0.json"
DEFAULT_BENCHMARK = REPOSITORY / "scripts" / "ci" / "source_allocation_probe.go"
DEFAULT_FIXTURE = REPOSITORY / "scripts" / "ci" / "fixtures" / "source-allocation" / "waap-event-v1.json"
DEFAULT_CATALOG = REPOSITORY / "scripts" / "ci" / "fixtures" / "source-allocation" / "signatures-v1.json"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PROBE_BYTES = 64 * 1024 * 1024
MAX_TOOLCHAIN_BYTES = 128 * 1024 * 1024
MAX_PROBE_OUTPUT_BYTES = 512 * 1024
MAX_TOOLCHAIN_MEMBERS = 20000
MAX_TOOLCHAIN_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_INPUT_TREE_ENTRIES = 500_000
SYSTEM_BWRAP = Path("/usr/bin/bwrap")
SYSTEM_PYTHON_ENTRY = Path("/usr/bin/python3")
SYSTEM_PYTHON_PATTERN = re.compile(r"^/usr/bin/python3(?:\.[0-9]+)?$")


class AllocationProducerError(ValueError):
    """Raised when source-bound evidence cannot be produced safely."""


def _strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AllocationProducerError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(token: str) -> None:
        raise AllocationProducerError(f"{label} contains non-finite number {token}")

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AllocationProducerError(f"{label} is not one valid UTF-8 JSON document") from exc


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AllocationProducerError(f"{label} keys are not exact")
    return value


def _reject_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.absolute().parts[1:-1]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise AllocationProducerError(f"path contains a symbolic-link ancestor: {path}")


def _read_regular(
    path: Path,
    maximum: int,
    *,
    modes: set[int] | None = None,
    owner: int | set[int] | None = None,
) -> tuple[bytes, os.stat_result]:
    path = path.absolute()
    _reject_symlink_ancestors(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise AllocationProducerError(f"input is not one regular non-symlink file: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise AllocationProducerError(f"input size is outside the accepted bound: {path}")
    if modes is not None and stat.S_IMODE(before.st_mode) not in modes:
        raise AllocationProducerError(f"input mode is unsafe: {path}")
    allowed_owners = {owner} if isinstance(owner, int) else owner
    if allowed_owners is not None and before.st_uid not in allowed_owners:
        raise AllocationProducerError(f"input owner is unsafe: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid, opened.st_nlink)
        if identity != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink):
            raise AllocationProducerError(f"input identity changed before open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AllocationProducerError(f"input exceeded its accepted bound: {path}")
        after = os.fstat(descriptor)
        final_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        initial_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if final_identity != initial_identity or total != opened.st_size:
            raise AllocationProducerError(f"input changed while it was read: {path}")
        return b"".join(chunks), opened
    finally:
        os.close(descriptor)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_new(path: Path, raw: bytes, mode: int) -> None:
    if not raw:
        raise AllocationProducerError(f"refusing to create empty output: {path}")
    path = path.absolute()
    _reject_symlink_ancestors(path)
    parent = path.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise AllocationProducerError(f"output parent is unsafe: {parent}")
    if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise AllocationProducerError(f"output parent owner or mode is unsafe: {parent}")
    directory = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    opened_parent = os.fstat(directory)
    parent_identity = (
        opened_parent.st_dev,
        opened_parent.st_ino,
        opened_parent.st_mode,
        opened_parent.st_uid,
        opened_parent.st_gid,
    )
    if parent_identity != (
        parent_info.st_dev,
        parent_info.st_ino,
        parent_info.st_mode,
        parent_info.st_uid,
        parent_info.st_gid,
    ):
        os.close(directory)
        raise AllocationProducerError(f"output parent changed before open: {parent}")
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            mode,
            dir_fd=directory,
        )
    except Exception:
        os.close(directory)
        raise
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AllocationProducerError(f"short write while creating output: {path}")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        try:
            os.unlink(path.name, dir_fd=directory)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    try:
        os.fsync(directory)
        after_parent = os.fstat(directory)
        if (
            after_parent.st_dev,
            after_parent.st_ino,
            after_parent.st_mode,
            after_parent.st_uid,
            after_parent.st_gid,
        ) != parent_identity:
            raise AllocationProducerError(f"output parent changed after write: {parent}")
    finally:
        os.close(directory)


def _mkdir_new(path: Path) -> None:
    path.mkdir(mode=0o700)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise AllocationProducerError(f"new evidence directory is unsafe: {path}")


def _load_contract(path: Path) -> dict[str, Any]:
    raw, _ = _read_regular(path, MAX_JSON_BYTES, modes={0o600, 0o644}, owner=os.geteuid())
    document = _exact_mapping(
        _strict_json(raw, "allocation contract"),
        {
            "schema_version", "schema_id", "repository", "target_release", "baseline_release",
            "baseline_commit", "architecture", "kernel_machine", "toolchain_version",
            "toolchain_archive_sha256", "workload", "schemas", "campaigns",
            "samples_per_subject_per_campaign", "stable_regression", "metrics",
        },
        "allocation contract",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AllocationProducerError("allocation contract schema version is invalid")
    if document["schema_id"] != "syswarden-source-allocation-contract/v1":
        raise AllocationProducerError("allocation contract schema ID is invalid")
    if document["repository"] != "duggytuxy/syswarden" or document["target_release"] != "v4.10.0":
        raise AllocationProducerError("allocation contract repository or target release is invalid")
    if document["baseline_release"] != "v4.04.3" or document["baseline_commit"] != "381c1f8d91459a9b20605629c725900abd81dee8":
        raise AllocationProducerError("allocation baseline binding is invalid")
    if document["architecture"] != "linux/amd64" or document["kernel_machine"] != "x86_64":
        raise AllocationProducerError("allocation architecture binding is invalid")
    if document["toolchain_version"] != "go1.26.6" or document["toolchain_archive_sha256"] != "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89":
        raise AllocationProducerError("allocation toolchain binding is invalid")
    if document["campaigns"] != ["allocation-campaign-01", "allocation-campaign-02", "allocation-campaign-03"]:
        raise AllocationProducerError("allocation campaign inventory is invalid")
    if type(document["samples_per_subject_per_campaign"]) is not int or document["samples_per_subject_per_campaign"] != 10:
        raise AllocationProducerError("allocation sample quota is invalid")
    return document


def _canonical_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise AllocationProducerError(f"{label} must be a string")
    try:
        parsed = dt.datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise AllocationProducerError(f"{label} is not a canonical UTC timestamp") from exc
    if parsed.strftime(TIMESTAMP_FORMAT) != value:
        raise AllocationProducerError(f"{label} is not canonical")
    return value


def _load_execution_control(path: Path, candidate_commit: str) -> tuple[dict[str, Any], bytes, str]:
    raw, _ = _read_regular(path, MAX_JSON_BYTES, modes={0o600}, owner=os.geteuid())
    document = _exact_mapping(
        _strict_json(raw, "execution control attestation"),
        {
            "schema_version", "schema_id", "candidate_commit", "architecture", "recorded_at",
            "attested_by", "producer_egress_denied", "repository_source_read_only",
            "build_checkouts_producer_writable", "persistent_writes_limited_to_evidence_root",
            "probe_egress_denied", "probe_persistent_filesystem_read_only", "sandbox_kind",
            "sandbox_executable_path", "sandbox_executable_sha256", "python_executable_path",
            "python_executable_sha256", "shell_executable_path", "shell_executable_sha256",
            "outer_unix_socket_canary_passed", "probe_unix_socket_canary_required",
            "runner_threat_model",
        },
        "execution control attestation",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AllocationProducerError("execution control schema version is invalid")
    if document["schema_id"] != "syswarden-allocation-execution-control-attestation/v1":
        raise AllocationProducerError("execution control schema ID is invalid")
    if document["candidate_commit"] != candidate_commit or document["architecture"] != "linux/amd64":
        raise AllocationProducerError("execution control subject binding is invalid")
    _canonical_timestamp(document["recorded_at"], "execution control recorded_at")
    if not isinstance(document["attested_by"], str) or len(document["attested_by"].strip()) < 3:
        raise AllocationProducerError("execution control attester is invalid")
    for key in (
        "producer_egress_denied",
        "repository_source_read_only",
        "build_checkouts_producer_writable",
        "persistent_writes_limited_to_evidence_root",
        "probe_egress_denied",
        "probe_persistent_filesystem_read_only",
    ):
        if type(document[key]) is not bool or document[key] is not True:
            raise AllocationProducerError(f"execution control {key} is not attested")
    if document["sandbox_kind"] != "bubblewrap-minimal-root-unshared-network/v2":
        raise AllocationProducerError("execution control sandbox kind is invalid")
    if document["sandbox_executable_path"] != "/usr/bin/bwrap":
        raise AllocationProducerError("execution control sandbox path is invalid")
    if not isinstance(document["sandbox_executable_sha256"], str) or SHA256_PATTERN.fullmatch(document["sandbox_executable_sha256"]) is None:
        raise AllocationProducerError("execution control sandbox executable SHA-256 is invalid")
    if (
        not isinstance(document["python_executable_path"], str)
        or SYSTEM_PYTHON_PATTERN.fullmatch(document["python_executable_path"]) is None
    ):
        raise AllocationProducerError("execution control Python executable path is invalid")
    if (
        not isinstance(document["python_executable_sha256"], str)
        or SHA256_PATTERN.fullmatch(document["python_executable_sha256"]) is None
    ):
        raise AllocationProducerError("execution control Python executable SHA-256 is invalid")
    if document["shell_executable_path"] != "/usr/bin/bash":
        raise AllocationProducerError("execution control shell executable path is invalid")
    if (
        not isinstance(document["shell_executable_sha256"], str)
        or SHA256_PATTERN.fullmatch(document["shell_executable_sha256"]) is None
    ):
        raise AllocationProducerError("execution control shell executable SHA-256 is invalid")
    for key in (
        "outer_unix_socket_canary_passed",
        "probe_unix_socket_canary_required",
    ):
        if type(document[key]) is not bool or document[key] is not True:
            raise AllocationProducerError(f"execution control {key} is not attested")
    if document["runner_threat_model"] != "protected-dedicated-runner-trusted-launch-environment-no-hostile-same-uid-process/v1":
        raise AllocationProducerError("execution control runner threat model is invalid")
    return document, raw, _sha256(raw)


def _read_system_bwrap(path: Path) -> tuple[bytes, os.stat_result]:
    if path.absolute() != SYSTEM_BWRAP or path != SYSTEM_BWRAP:
        raise AllocationProducerError(
            "probe sandbox must be the canonical /usr/bin/bwrap trust anchor"
        )
    for parent in (Path("/"), Path("/usr"), Path("/usr/bin")):
        info = parent.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AllocationProducerError(
                f"probe sandbox parent is unsafe: {parent}"
            )
    return _read_regular(
        path,
        MAX_PROBE_BYTES,
        modes={0o755, 0o4755},
        owner=0,
    )


def _read_system_python(path: Path) -> tuple[bytes, os.stat_result]:
    for parent in (Path("/"), Path("/usr"), Path("/usr/bin")):
        info = parent.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AllocationProducerError(
                f"system Python parent is unsafe: {parent}"
            )
    entry = SYSTEM_PYTHON_ENTRY.lstat()
    if (
        not (stat.S_ISLNK(entry.st_mode) or stat.S_ISREG(entry.st_mode))
        or entry.st_uid != 0
    ):
        raise AllocationProducerError("system Python entrypoint is unsafe")
    expected = SYSTEM_PYTHON_ENTRY.resolve(strict=True)
    if (
        path != expected
        or not path.is_absolute()
        or SYSTEM_PYTHON_PATTERN.fullmatch(str(path)) is None
    ):
        raise AllocationProducerError(
            "Python executable must be the canonical target of /usr/bin/python3"
        )
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or not os.access(path, os.X_OK)
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise AllocationProducerError("system Python target is unsafe")
    return _read_regular(path, MAX_PROBE_BYTES, owner=0)


def _verify_nested_unix_socket_isolation(
    sandbox_executable: Path,
    sandbox_sha256: str,
    python_executable: Path,
) -> None:
    sandbox_raw, _ = _read_system_bwrap(sandbox_executable)
    if _sha256(sandbox_raw) != sandbox_sha256:
        raise AllocationProducerError(
            "probe sandbox executable changed before the Unix socket canary"
        )
    python_raw, _ = _read_system_python(python_executable)
    canary_root = Path(tempfile.mkdtemp(prefix="syswarden-unix-canary-", dir="/tmp"))
    canary_root.chmod(0o700)
    canary_path = canary_root / "host.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(canary_path))
        listener.listen(1)
        code = (
            "import errno,socket,sys;"
            "client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
            "\ntry: client.connect(sys.argv[1])"
            "\nexcept OSError as error:"
            "\n  raise SystemExit(0 if error.errno == errno.ENOENT else 3)"
            "\nelse: raise SystemExit(4)"
        )
        _command(
            [
                str(SYSTEM_BWRAP),
                "--die-with-parent",
                "--new-session",
                "--unshare-user",
                "--unshare-net",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind-try",
                "/lib64",
                "/lib64",
                "--dir",
                "/run",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/var",
                "--tmpfs",
                "/var/tmp",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--",
                str(python_executable),
                "-I",
                "-c",
                code,
                str(canary_path),
            ],
            timeout=10,
            maximum=64 * 1024,
        )
        current_python, _ = _read_system_python(python_executable)
        if _sha256(current_python) != _sha256(python_raw):
            raise AllocationProducerError(
                "system Python changed during the Unix socket canary"
            )
    finally:
        listener.close()
        try:
            canary_path.unlink()
        except FileNotFoundError:
            pass
        canary_root.rmdir()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _bounded_communicate(
    process: subprocess.Popen[bytes],
    *,
    input_data: bytes | None,
    timeout: int,
    maximum: int,
    label: str,
) -> tuple[bytes, bytes]:
    if maximum < 1 or timeout < 1 or process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise AllocationProducerError(f"{label} capture configuration is invalid")
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_view = memoryview(input_data) if input_data is not None else None
    try:
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr))
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            if input_view is not None and len(input_view):
                selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", None))
            else:
                process.stdin.close()
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AllocationProducerError(f"{label} timed out")
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _ in events:
                stream_name, buffer = key.data
                stream = key.fileobj
                if stream_name == "stdin":
                    try:
                        written = os.write(stream.fileno(), input_view)
                    except BrokenPipeError:
                        written = len(input_view)
                    input_view = input_view[written:]
                    if not input_view:
                        selector.unregister(stream)
                        stream.close()
                    continue
                if not isinstance(buffer, bytearray):
                    raise AllocationProducerError(
                        f"{label} capture stream classification is invalid"
                    )
                read_size = max(1, min(64 * 1024, maximum + 1 - len(buffer)))
                try:
                    chunk = os.read(stream.fileno(), read_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    raise AllocationProducerError(f"{label} output exceeded its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AllocationProducerError(f"{label} timed out")
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise AllocationProducerError(f"{label} timed out") from exc
        return bytes(stdout), bytes(stderr)
    except BaseException:
        _terminate_process_group(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _command(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 120, maximum: int = 8 * 1024 * 1024) -> bytes:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    stdout, stderr = _bounded_communicate(
        process,
        input_data=None,
        timeout=timeout,
        maximum=maximum,
        label=f"command {command[0]}",
    )
    if process.returncode != 0:
        message = stderr.decode("utf-8", "replace").strip()
        raise AllocationProducerError(f"command failed: {command[0]}: {message}")
    return stdout


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _require_disjoint_output(output_root: Path, protected_paths: Sequence[Path]) -> None:
    if not output_root.is_absolute() or output_root.resolve(strict=False) != output_root:
        raise AllocationProducerError("output root must be one canonical absolute path")
    for protected in protected_paths:
        canonical = protected.resolve(strict=True)
        if _paths_overlap(output_root, canonical):
            raise AllocationProducerError(
                f"output root overlaps protected input: {canonical}"
            )


def _attest_regular_tree(root: Path, label: str) -> tuple[int, ...]:
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise AllocationProducerError(f"{label} root is unsafe")
    identity = (
        root_info.st_dev,
        root_info.st_ino,
        root_info.st_mode,
        root_info.st_uid,
        root_info.st_gid,
    )
    pending = [root]
    entries = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_INPUT_TREE_ENTRIES:
                    raise AllocationProducerError(
                        f"{label} exceeds the input tree entry bound"
                    )
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != root_info.st_dev:
                    raise AllocationProducerError(
                        f"{label} contains a nested filesystem: {entry.path}"
                    )
                if info.st_uid != root_info.st_uid or stat.S_IMODE(info.st_mode) & 0o022:
                    raise AllocationProducerError(
                        f"{label} contains an unsafe owner or mode: {entry.path}"
                    )
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(info.st_mode):
                    raise AllocationProducerError(
                        f"{label} contains a symlink or special entry: {entry.path}"
                    )
    after = root.lstat()
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
    ) != identity:
        raise AllocationProducerError(f"{label} root identity changed during scan")
    return identity


def _verify_tree_root(root: Path, identity: tuple[int, ...], label: str) -> None:
    current = root.lstat()
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
    ) != identity:
        raise AllocationProducerError(f"{label} root identity changed")


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    output = _command(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repository), *arguments], env=environment)
    return output.decode("utf-8", "strict").strip()


def _require_candidate_blob(
    repository: Path,
    candidate_commit: str,
    path: Path,
    relative: str,
    *,
    maximum: int,
    modes: set[int],
) -> bytes:
    relative_path = PurePosixPath(relative)
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise AllocationProducerError("candidate input path is invalid")
    expected = repository.joinpath(*relative_path.parts)
    if path.absolute() != expected or path != expected:
        raise AllocationProducerError(
            f"candidate input must use its exact repository path: {relative}"
        )
    raw, _ = _read_regular(
        path,
        maximum,
        modes=modes,
        owner=os.geteuid(),
    )
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    committed = _command(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            "cat-file",
            "blob",
            f"{candidate_commit}:{relative}",
        ],
        env=environment,
        maximum=maximum,
    )
    if not committed or raw != committed:
        raise AllocationProducerError(
            f"candidate input differs from the exact committed blob: {relative}"
        )
    return raw


def _resolve_subjects(repository: Path, candidate_commit: str, baseline_commit: str) -> dict[str, dict[str, str]]:
    if SHA_PATTERN.fullmatch(candidate_commit) is None:
        raise AllocationProducerError("candidate commit must be one lowercase 40-character SHA")
    if _git(repository, "cat-file", "-t", candidate_commit) != "commit" or _git(repository, "cat-file", "-t", baseline_commit) != "commit":
        raise AllocationProducerError("baseline or candidate object is not a commit")
    main_reference = _git(repository, "show-ref", "--verify", "refs/heads/main")
    if main_reference != f"{candidate_commit} refs/heads/main":
        raise AllocationProducerError(
            "refs/heads/main is absent or does not name the exact candidate commit"
        )
    if _git(repository, "rev-parse", "HEAD^{commit}") != candidate_commit:
        raise AllocationProducerError("repository HEAD does not name the exact candidate commit")
    if _git(
        repository,
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise AllocationProducerError(
            "candidate repository contains modified, untracked, or ignored inputs"
        )
    if _git(repository, "rev-parse", "refs/tags/v4.04.3^{commit}") != baseline_commit:
        raise AllocationProducerError("v4.04.3 does not resolve to the frozen baseline commit")
    git_common_dir = Path(
        _git(
            repository,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        )
    )
    forbidden_git_inputs = (
        (git_common_dir / "info" / "grafts", "Git grafts"),
        (git_common_dir / "shallow", "shallow Git history"),
        (git_common_dir / "objects" / "info" / "alternates", "Git object alternates"),
    )
    for path, label in forbidden_git_inputs:
        if path.exists() or path.is_symlink():
            raise AllocationProducerError(f"{label} are forbidden for subject ancestry")
    if _git(repository, "for-each-ref", "--format=%(refname)", "refs/replace"):
        raise AllocationProducerError("Git replacement refs are forbidden")
    try:
        _git(
            repository,
            "merge-base",
            "--is-ancestor",
            baseline_commit,
            candidate_commit,
        )
    except AllocationProducerError as exc:
        raise AllocationProducerError(
            "frozen baseline commit is not an ancestor of the candidate commit"
        ) from exc
    return {
        "baseline": {"release": "v4.04.3", "commit": baseline_commit, "tree": _git(repository, "rev-parse", f"{baseline_commit}^{{tree}}")},
        "candidate": {"release": "v4.10.0", "commit": candidate_commit, "tree": _git(repository, "rev-parse", f"{candidate_commit}^{{tree}}")},
    }


def _clone_subject(repository: Path, destination: Path, commit: str, expected_tree: str) -> None:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    _command(
        ["git", "-c", "core.hooksPath=/dev/null", "clone", "--local", "--no-hardlinks", "--no-checkout", "--", str(repository), str(destination)],
        env=environment,
    )
    _command(["git", "-c", "core.hooksPath=/dev/null", "-C", str(destination), "checkout", "--detach", commit], env=environment)
    if _git(destination, "rev-parse", "HEAD^{commit}") != commit or _git(destination, "rev-parse", "HEAD^{tree}") != expected_tree:
        raise AllocationProducerError("detached subject checkout identity is invalid")
    if _git(destination, "status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching"):
        raise AllocationProducerError("detached subject checkout is not clean")
    modes = _git(destination, "ls-tree", "-r", commit).splitlines()
    if any(line.startswith("120000 ") or line.startswith("160000 ") for line in modes):
        raise AllocationProducerError("subject tree contains a symlink or submodule")
    module = destination / "src" / "core" / "syswarden-core"
    if (module / "vendor").exists():
        raise AllocationProducerError("subject module contains a vendor substitution")


def _go_environment(go_executable: Path, module_cache: Path, cache: Path, temporary: Path) -> dict[str, str]:
    return {
        "PATH": str(go_executable.parent) + os.pathsep + "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOPRIVATE": "",
        "GONOSUMDB": "",
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOMODCACHE": str(module_cache),
        "GOCACHE": str(cache),
        "GOTMPDIR": str(temporary),
    }


def _verify_toolchain_inputs(
    archive: Path, contract: dict[str, Any]
) -> tuple[bytes, str]:
    archive_raw, _ = _read_regular(archive, MAX_TOOLCHAIN_BYTES, modes={0o600}, owner=os.geteuid())
    archive_sha = _sha256(archive_raw)
    if archive_sha != contract["toolchain_archive_sha256"]:
        raise AllocationProducerError("Go toolchain archive SHA-256 mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as stream:
        members = [member for member in stream.getmembers() if member.name == "go/bin/go"]
        if len(members) != 1 or not members[0].isfile():
            raise AllocationProducerError("Go executable is not uniquely bound to the reviewed archive")
        extracted = stream.extractfile(members[0])
        if extracted is None:
            raise AllocationProducerError("Go executable cannot be read from the reviewed archive")
        go_raw = extracted.read(MAX_PROBE_BYTES + 1)
        if not go_raw or len(go_raw) > MAX_PROBE_BYTES or len(go_raw) != members[0].size:
            raise AllocationProducerError("Go executable size in the reviewed archive is invalid")
        go_sha = _sha256(go_raw)
    return archive_raw, go_sha


def _extract_toolchain(
    archive_raw: bytes, destination: Path, expected_go_sha256: str
) -> Path:
    _mkdir_new(destination)
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as stream:
        members = stream.getmembers()
        if not members or len(members) > MAX_TOOLCHAIN_MEMBERS:
            raise AllocationProducerError("Go toolchain archive member count is invalid")
        names: set[str] = set()
        expanded = 0
        validated: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        for member in members:
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or not pure.parts
                or pure.parts[0] != "go"
                or any(part in {"", ".", ".."} for part in pure.parts)
                or member.name in names
            ):
                raise AllocationProducerError("Go toolchain archive path is unsafe")
            names.add(member.name)
            if not (member.isdir() or member.isfile()):
                raise AllocationProducerError(
                    "Go toolchain archive contains a link or special member"
                )
            if member.isfile():
                if member.size < 0 or member.size > MAX_TOOLCHAIN_EXPANDED_BYTES:
                    raise AllocationProducerError(
                        "Go toolchain archive member size is invalid"
                    )
                expanded += member.size
                if expanded > MAX_TOOLCHAIN_EXPANDED_BYTES:
                    raise AllocationProducerError(
                        "Go toolchain archive expanded size is too large"
                    )
            validated.append((member, pure))

        for member, pure in sorted(
            (item for item in validated if item[0].isdir()),
            key=lambda item: len(item[1].parts),
        ):
            target = destination.joinpath(*pure.parts)
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.chmod(0o700)
        for member, pure in (item for item in validated if item[0].isfile()):
            target = destination.joinpath(*pure.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.parent.chmod(0o700)
            source = stream.extractfile(member)
            if source is None:
                raise AllocationProducerError(
                    "Go toolchain archive member cannot be read"
                )
            mode = 0o700 if member.mode & 0o111 else 0o600
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                mode,
            )
            try:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise AllocationProducerError(
                            "Go toolchain archive member ended early"
                        )
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise AllocationProducerError(
                                "Go toolchain extraction produced a short write"
                            )
                        view = view[written:]
                    remaining -= len(chunk)
                if source.read(1):
                    raise AllocationProducerError(
                        "Go toolchain archive member exceeded its declared size"
                    )
            finally:
                os.close(descriptor)

    extracted_go = destination / "go" / "bin" / "go"
    go_raw, _ = _read_regular(
        extracted_go, MAX_PROBE_BYTES, modes={0o700}, owner=os.geteuid()
    )
    if _sha256(go_raw) != expected_go_sha256:
        raise AllocationProducerError(
            "extracted Go executable differs from the reviewed archive binding"
        )
    return extracted_go


def _verify_extracted_toolchain(
    go_executable: Path, contract: dict[str, Any]
) -> str:
    version = _command(
        [str(go_executable), "version"],
        env={
            "PATH": "/usr/bin:/bin",
            "GOTOOLCHAIN": "local",
            "GOENV": "off",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        },
    ).decode().strip()
    expected = f"go version {contract['toolchain_version']} linux/amd64"
    if version != expected:
        raise AllocationProducerError(
            f"Go toolchain version is {version!r}, expected {expected!r}"
        )
    return version


def _decode_json_stream(raw: bytes) -> list[dict[str, Any]]:
    text = raw.decode("utf-8", "strict")
    decoder = json.JSONDecoder()
    offset = 0
    documents: list[dict[str, Any]] = []
    while True:
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            raise AllocationProducerError("Go module graph contains a non-object entry")
        documents.append(value)
    if not documents:
        raise AllocationProducerError("Go module graph is empty")
    return documents


def _module_graph(go_executable: Path, checkout: Path, module_cache: Path, work: Path) -> tuple[list[dict[str, Any]], str]:
    module = checkout / "src" / "core" / "syswarden-core"
    cache = work / "module-graph-cache"
    temporary = work / "module-graph-tmp"
    _mkdir_new(cache)
    _mkdir_new(temporary)
    environment = _go_environment(go_executable, module_cache, cache, temporary)
    edit = _strict_json(_command([str(go_executable), "-C", str(module), "mod", "edit", "-json"], env=environment), "go.mod metadata")
    if not isinstance(edit, dict) or edit.get("Replace") not in (None, []):
        raise AllocationProducerError("subject module contains a replace directive")
    _command([str(go_executable), "-C", str(module), "mod", "verify"], env=environment)
    entries = _decode_json_stream(_command([str(go_executable), "-C", str(module), "list", "-m", "-json", "all"], env=environment))
    canonical: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if "Replace" in entry:
            raise AllocationProducerError("resolved module graph contains a replacement")
        path = entry.get("Path")
        if not isinstance(path, str) or not path or path in seen:
            raise AllocationProducerError("resolved module graph path is invalid or duplicated")
        seen.add(path)
        item = {
            "path": path,
            "version": entry.get("Version", ""),
            "sum": entry.get("Sum", ""),
            "go_mod_sum": entry.get("GoModSum", ""),
            "main": entry.get("Main", False),
        }
        if not isinstance(item["version"], str) or not isinstance(item["sum"], str) or not isinstance(item["go_mod_sum"], str) or type(item["main"]) is not bool:
            raise AllocationProducerError("resolved module graph contains invalid field types")
        canonical.append(item)
    canonical.sort(key=lambda item: item["path"])
    digest = _sha256(_canonical_json(canonical))
    return canonical, digest


def _build_probe(
    role: str,
    go_executable: Path,
    checkout: Path,
    module_cache: Path,
    benchmark_source: Path,
    work: Path,
    output_root: Path,
) -> tuple[str, bytes]:
    module = checkout / "src" / "core" / "syswarden-core"
    builds: list[bytes] = []
    for build_index in (1, 2):
        build_root = work / f"{role}-build-{build_index}"
        _mkdir_new(build_root)
        cache = build_root / "gocache"
        temporary = build_root / "gotmp"
        _mkdir_new(cache)
        _mkdir_new(temporary)
        output = build_root / "probe"
        environment = _go_environment(go_executable, module_cache, cache, temporary)
        _command(
            [str(go_executable), "-C", str(module), "build", "-trimpath", "-buildvcs=false", "-o", str(output), str(benchmark_source)],
            env=environment,
            timeout=300,
        )
        output.chmod(0o700)
        raw, _ = _read_regular(output, MAX_PROBE_BYTES, modes={0o700}, owner=os.geteuid())
        builds.append(raw)
    if builds[0] != builds[1]:
        raise AllocationProducerError(f"{role} probe builds are not byte-identical")
    destination = output_root / f"{role}-probe"
    _write_new(destination, builds[0], 0o700)
    return _sha256(builds[0]), builds[0]


def _environment_document(candidate_commit: str, control: dict[str, Any], control_sha: str) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise AllocationProducerError("source allocation producer requires native Linux x86_64")
    os_release_raw, _ = _read_regular(Path("/etc/os-release").resolve(strict=True), 64 * 1024)
    return {
        "schema_version": 1,
        "schema_id": "syswarden-allocation-environment/v1",
        "repository": "duggytuxy/syswarden",
        "candidate_commit": candidate_commit,
        "recorded_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime(TIMESTAMP_FORMAT),
        "architecture": "linux/amd64",
        "kernel_machine": "x86_64",
        "kernel_release": platform.release(),
        "os_release_sha256": _sha256(os_release_raw),
        "logical_cpu_count": os.cpu_count(),
        "page_size": os.sysconf("SC_PAGE_SIZE"),
        "execution_control_attestation_sha256": control_sha,
        "execution_controls": control,
    }


def _verify_checkout(checkout: Path, commit: str, tree: str) -> None:
    if _git(checkout, "rev-parse", "HEAD^{commit}") != commit or _git(checkout, "rev-parse", "HEAD^{tree}") != tree:
        raise AllocationProducerError("subject checkout identity changed")
    if _git(checkout, "status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching"):
        raise AllocationProducerError("subject checkout changed during allocation production")


def _invoke_probe(
    binary: Path,
    expected_sha: str,
    request: dict[str, Any],
    timeout: int,
    *,
    sandbox_executable: Path | None = None,
    sandbox_sha256: str | None = None,
) -> bytes:
    raw, before = _read_regular(binary, MAX_PROBE_BYTES, modes={0o700}, owner=os.geteuid())
    if _sha256(raw) != expected_sha:
        raise AllocationProducerError("probe binary changed before invocation")
    descriptor = os.open(binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    sandbox_descriptor = -1
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        ):
            raise AllocationProducerError("probe binary identity changed before exec")
        command = [f"/proc/self/fd/{descriptor}"]
        passed_descriptors = [descriptor]
        if sandbox_executable is not None:
            if sandbox_sha256 is None or SHA256_PATTERN.fullmatch(sandbox_sha256) is None:
                raise AllocationProducerError("probe sandbox SHA-256 binding is invalid")
            sandbox_raw, sandbox_info = _read_system_bwrap(sandbox_executable)
            if _sha256(sandbox_raw) != sandbox_sha256:
                raise AllocationProducerError("probe sandbox executable identity mismatch")
            sandbox_descriptor = os.open(
                sandbox_executable,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            opened_sandbox = os.fstat(sandbox_descriptor)
            if (
                opened_sandbox.st_dev,
                opened_sandbox.st_ino,
                opened_sandbox.st_size,
                opened_sandbox.st_mtime_ns,
                opened_sandbox.st_ctime_ns,
            ) != (
                sandbox_info.st_dev,
                sandbox_info.st_ino,
                sandbox_info.st_size,
                sandbox_info.st_mtime_ns,
                sandbox_info.st_ctime_ns,
            ):
                raise AllocationProducerError(
                    "probe sandbox executable changed before invocation"
                )
            command = [
                str(SYSTEM_BWRAP),
                "--die-with-parent",
                "--new-session",
                "--unshare-user",
                "--unshare-net",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--ro-bind",
                str(binary.parent),
                str(binary.parent),
                "--dir",
                "/run",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/var",
                "--tmpfs",
                "/var/tmp",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--chdir",
                "/",
                "--",
                f"/proc/self/fd/{descriptor}",
            ]
        elif sandbox_sha256 is not None:
            raise AllocationProducerError(
                "probe sandbox executable is missing for its SHA-256 binding"
            )
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(passed_descriptors),
            start_new_session=True,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "GOMAXPROCS": "1", "GODEBUG": "", "GOMEMLIMIT": "off"},
        )
        stdout, stderr = _bounded_communicate(
            process,
            input_data=_canonical_json(request),
            timeout=timeout,
            maximum=MAX_PROBE_OUTPUT_BYTES,
            label="allocation probe",
        )
        if process.returncode != 0:
            raise AllocationProducerError(f"allocation probe failed: {stderr.decode('utf-8', 'replace').strip()}")
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            os.killpg(process.pid, signal.SIGKILL)
            raise AllocationProducerError("allocation probe left a persistent descendant process")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
        ):
            raise AllocationProducerError("probe binary changed during invocation")
        if sandbox_descriptor >= 0:
            sandbox_after = os.fstat(sandbox_descriptor)
            if (
                sandbox_after.st_dev,
                sandbox_after.st_ino,
                sandbox_after.st_size,
                sandbox_after.st_mtime_ns,
                sandbox_after.st_ctime_ns,
            ) != (
                opened_sandbox.st_dev,
                opened_sandbox.st_ino,
                opened_sandbox.st_size,
                opened_sandbox.st_mtime_ns,
                opened_sandbox.st_ctime_ns,
            ):
                raise AllocationProducerError(
                    "probe sandbox executable changed during invocation"
                )
    finally:
        if sandbox_descriptor >= 0:
            os.close(sandbox_descriptor)
        os.close(descriptor)
    document = _strict_json(stdout, "raw allocation sample")
    if not isinstance(document, dict) or document.get("sample_id") != request["sample_id"] or document.get("process_nonce") != request["process_nonce"]:
        raise AllocationProducerError("allocation probe did not echo its sample identity")
    if document.get("candidate_commit") != request["candidate_commit"] or document.get("campaign_id") != request["campaign_id"]:
        raise AllocationProducerError("allocation probe did not echo its campaign binding")
    return _canonical_json(document)


def _fresh_campaign_timestamp(previous: str | None) -> str:
    while True:
        current = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime(TIMESTAMP_FORMAT)
        if current != previous:
            return current
        time.sleep(0.05)


def produce(args: argparse.Namespace) -> Path:
    repository = args.repository.resolve(strict=True)
    module_cache = args.module_cache.resolve(strict=True)
    _require_disjoint_output(
        args.output_root,
        (
            repository,
            module_cache,
            args.toolchain_archive,
            args.execution_control_attestation,
        ),
    )
    repository_identity = _attest_regular_tree(repository, "repository")
    module_cache_identity = _attest_regular_tree(module_cache, "module cache")
    contract = _load_contract(args.contract)
    subjects = _resolve_subjects(repository, args.candidate_commit, contract["baseline_commit"])
    for path, relative, maximum, modes in (
        (
            Path(__file__).resolve(),
            "scripts/ci/source_allocation_producer.py",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
        (
            repository / "scripts/ci/source_allocation_sandbox.sh",
            "scripts/ci/source_allocation_sandbox.sh",
            MAX_JSON_BYTES,
            {0o700, 0o755},
        ),
        (
            repository / "scripts/ci/source_allocation_gate.py",
            "scripts/ci/source_allocation_gate.py",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
        (
            args.contract,
            "scripts/ci/source_allocation_contract_v4.10.0.json",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
        (
            args.benchmark_source,
            "scripts/ci/source_allocation_probe.go",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
        (
            args.fixture,
            "scripts/ci/fixtures/source-allocation/waap-event-v1.json",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
        (
            args.signature_catalog,
            "scripts/ci/fixtures/source-allocation/signatures-v1.json",
            MAX_JSON_BYTES,
            {0o600, 0o644},
        ),
    ):
        _require_candidate_blob(
            repository,
            args.candidate_commit,
            path,
            relative,
            maximum=maximum,
            modes=modes,
        )
    control, control_raw, control_sha = _load_execution_control(args.execution_control_attestation, args.candidate_commit)
    running_python = Path(sys.executable).resolve(strict=True)
    python_raw, _ = _read_system_python(running_python)
    if str(running_python) != control["python_executable_path"]:
        raise AllocationProducerError(
            "running Python executable differs from the execution control attestation"
        )
    if _sha256(python_raw) != control["python_executable_sha256"]:
        raise AllocationProducerError(
            "running Python executable digest differs from the execution control attestation"
        )
    sandbox_raw, _ = _read_system_bwrap(args.probe_sandbox_executable)
    sandbox_sha256 = _sha256(sandbox_raw)
    if sandbox_sha256 != control["sandbox_executable_sha256"]:
        raise AllocationProducerError(
            "probe sandbox executable differs from the execution control attestation"
        )
    _verify_nested_unix_socket_isolation(
        args.probe_sandbox_executable,
        sandbox_sha256,
        running_python,
    )
    toolchain_archive_raw, go_sha = _verify_toolchain_inputs(
        args.toolchain_archive, contract
    )

    parent = args.output_root.absolute().parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise AllocationProducerError("output root parent must be an owner-controlled 0700 directory")
    if args.prepared_output_root:
        output_info = args.output_root.lstat()
        if (
            stat.S_ISLNK(output_info.st_mode)
            or not stat.S_ISDIR(output_info.st_mode)
            or output_info.st_uid != os.geteuid()
            or stat.S_IMODE(output_info.st_mode) != 0o700
            or any(args.output_root.iterdir())
        ):
            raise AllocationProducerError(
                "prepared output root must be an empty owner-controlled 0700 directory"
            )
    else:
        if args.output_root.exists() or args.output_root.is_symlink():
            raise AllocationProducerError("output root already exists")
        _mkdir_new(args.output_root)

    benchmark_raw, _ = _read_regular(args.benchmark_source, MAX_JSON_BYTES, modes={0o600, 0o644}, owner=os.geteuid())
    fixture_raw, _ = _read_regular(args.fixture, MAX_JSON_BYTES, modes={0o600, 0o644}, owner=os.geteuid())
    catalog_raw, _ = _read_regular(args.signature_catalog, MAX_JSON_BYTES, modes={0o600, 0o644}, owner=os.geteuid())
    _strict_json(fixture_raw, "allocation fixture")
    _strict_json(catalog_raw, "allocation signature catalog")
    benchmark_path = args.output_root / "benchmark-source.go"
    fixture_path = args.output_root / "fixture.json"
    catalog_path = args.output_root / "signature-catalog.json"
    _write_new(benchmark_path, benchmark_raw, 0o600)
    _write_new(fixture_path, fixture_raw, 0o600)
    _write_new(catalog_path, catalog_raw, 0o600)
    _write_new(args.output_root / "execution-control-attestation.json", control_raw, 0o600)

    environment = _environment_document(args.candidate_commit, control, control_sha)
    environment_raw = _canonical_json(environment)
    environment_sha = _sha256(environment_raw)
    _write_new(args.output_root / "environment.json", environment_raw, 0o600)

    module_cache_info = module_cache.lstat()
    if stat.S_ISLNK(module_cache_info.st_mode) or not stat.S_ISDIR(module_cache_info.st_mode) or module_cache_info.st_uid != os.geteuid() or module_cache_info.st_mode & 0o022:
        raise AllocationProducerError("module cache directory is unsafe")

    with tempfile.TemporaryDirectory(
        prefix=".syswarden-allocation-build-", dir=args.output_root
    ) as temporary_name:
        work = Path(temporary_name)
        work.chmod(0o700)
        extracted_go = _extract_toolchain(
            toolchain_archive_raw, work / "reviewed-toolchain", go_sha
        )
        go_version = _verify_extracted_toolchain(extracted_go, contract)
        checkouts: dict[str, Path] = {}
        subject_attestations: dict[str, Any] = {}
        for role in ("baseline", "candidate"):
            checkout = work / f"{role}-source"
            _clone_subject(repository, checkout, subjects[role]["commit"], subjects[role]["tree"])
            checkouts[role] = checkout
            graph_work = work / f"{role}-graph"
            _mkdir_new(graph_work)
            graph, graph_sha = _module_graph(extracted_go, checkout, module_cache, graph_work)
            probe_sha, _ = _build_probe(role, extracted_go, checkout, module_cache, benchmark_path, work, args.output_root)
            subjects[role]["module_graph_sha256"] = graph_sha
            subjects[role]["probe_binary_sha256"] = probe_sha
            subject_attestations[role] = {
                "release": subjects[role]["release"],
                "commit": subjects[role]["commit"],
                "tree": subjects[role]["tree"],
                "module_graph_sha256": graph_sha,
                "module_graph": graph,
                "probe_binary_sha256": probe_sha,
                "reproducible_build": True,
            }

        build_attestation = {
            "schema_version": 1,
            "schema_id": "syswarden-allocation-build-attestation/v1",
            "repository": contract["repository"],
            "target_release": contract["target_release"],
            "candidate_commit": args.candidate_commit,
            "baseline_release": contract["baseline_release"],
            "baseline_commit": contract["baseline_commit"],
            "environment_sha256": environment_sha,
            "bindings": {
                "benchmark_source_sha256": _sha256(benchmark_raw),
                "fixture_sha256": _sha256(fixture_raw),
                "signature_catalog_sha256": _sha256(catalog_raw),
                "toolchain_version": contract["toolchain_version"],
                "toolchain_archive_sha256": contract["toolchain_archive_sha256"],
                "toolchain_executable_sha256": go_sha,
                "toolchain_version_output": go_version,
                "workload_id": contract["workload"]["id"],
            },
            "build_contract": {
                "gowork": "off",
                "goflags": "-mod=readonly",
                "cgo_enabled": "0",
                "goos": "linux",
                "goarch": "amd64",
                "gotoolchain": "local",
                "goproxy": "off",
                "gosumdb": "off",
                "trimpath": True,
                "buildvcs": False,
                "command": ["go", "-C", "{subject_module}", "build", "-trimpath", "-buildvcs=false", "-o", "{probe_output}", "{benchmark_source}"],
            },
            "subjects": subject_attestations,
        }
        build_raw = _canonical_json(build_attestation)
        build_sha = _sha256(build_raw)
        _write_new(args.output_root / "build-attestation.json", build_raw, 0o600)

        raw_root = args.output_root / "raw"
        _mkdir_new(raw_root)
        previous_timestamp: str | None = None
        seen_nonces: set[str] = set()
        for campaign_id in contract["campaigns"]:
            campaign_root = raw_root / campaign_id
            _mkdir_new(campaign_root)
            campaign_timestamp = _fresh_campaign_timestamp(previous_timestamp)
            previous_timestamp = campaign_timestamp
            invocation_index = 0
            for sample_index in range(1, contract["samples_per_subject_per_campaign"] + 1):
                order = ("baseline", "candidate") if sample_index % 2 else ("candidate", "baseline")
                for role in order:
                    invocation_index += 1
                    nonce = secrets.token_hex(16)
                    if nonce in seen_nonces:
                        raise AllocationProducerError("cryptographic process nonce was reused")
                    seen_nonces.add(nonce)
                    subject = subjects[role]
                    request = {
                        "schema_version": 1,
                        "repository": contract["repository"],
                        "target_release": contract["target_release"],
                        "candidate_commit": args.candidate_commit,
                        "baseline_release": contract["baseline_release"],
                        "baseline_commit": contract["baseline_commit"],
                        "campaign_id": campaign_id,
                        "campaign_recorded_at": campaign_timestamp,
                        "sample_index": sample_index,
                        "invocation_index": invocation_index,
                        "sample_id": f"{campaign_id}-{role}-{sample_index:02d}",
                        "process_nonce": nonce,
                        "subject_role": role,
                        "subject_release": subject["release"],
                        "subject_commit": subject["commit"],
                        "subject_tree": subject["tree"],
                        "probe_binary_sha256": subject["probe_binary_sha256"],
                        "module_graph_sha256": subject["module_graph_sha256"],
                        "environment_sha256": environment_sha,
                        "build_attestation_sha256": build_sha,
                        "benchmark_source_sha256": _sha256(benchmark_raw),
                        "fixture_path": str(fixture_path),
                        "fixture_sha256": _sha256(fixture_raw),
                        "signature_catalog_path": str(catalog_path),
                        "signature_catalog_sha256": _sha256(catalog_raw),
                        "toolchain_version": contract["toolchain_version"],
                        "toolchain_archive_sha256": contract["toolchain_archive_sha256"],
                        "workload_id": contract["workload"]["id"],
                    }
                    raw_sample = _invoke_probe(
                        args.output_root / f"{role}-probe",
                        subject["probe_binary_sha256"],
                        request,
                        args.probe_timeout_seconds,
                        sandbox_executable=args.probe_sandbox_executable,
                        sandbox_sha256=sandbox_sha256,
                    )
                    _write_new(campaign_root / f"{role}-{sample_index:02d}.json", raw_sample, 0o600)
            if invocation_index != 20:
                raise AllocationProducerError("campaign invocation count is invalid")
            for role in ("baseline", "candidate"):
                _verify_checkout(checkouts[role], subjects[role]["commit"], subjects[role]["tree"])
                current, _ = _read_regular(args.output_root / f"{role}-probe", MAX_PROBE_BYTES, modes={0o700}, owner=os.geteuid())
                if _sha256(current) != subjects[role]["probe_binary_sha256"]:
                    raise AllocationProducerError("probe identity changed after campaign")

        for role in ("baseline", "candidate"):
            _verify_checkout(checkouts[role], subjects[role]["commit"], subjects[role]["tree"])
        for path, expected, mode in (
            (benchmark_path, _sha256(benchmark_raw), 0o600),
            (fixture_path, _sha256(fixture_raw), 0o600),
            (catalog_path, _sha256(catalog_raw), 0o600),
            (args.output_root / "execution-control-attestation.json", control_sha, 0o600),
            (args.output_root / "environment.json", environment_sha, 0o600),
            (args.output_root / "build-attestation.json", build_sha, 0o600),
        ):
            current, _ = _read_regular(path, MAX_JSON_BYTES, modes={mode}, owner=os.geteuid())
            if _sha256(current) != expected:
                raise AllocationProducerError(f"bound input changed during production: {path.name}")
    _verify_tree_root(repository, repository_identity, "repository")
    _verify_tree_root(module_cache, module_cache_identity, "module cache")
    return args.output_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--benchmark-source", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--signature-catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--toolchain-archive", type=Path, required=True)
    parser.add_argument("--module-cache", type=Path, required=True)
    parser.add_argument("--execution-control-attestation", type=Path, required=True)
    parser.add_argument("--probe-sandbox-executable", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--prepared-output-root", action="store_true")
    parser.add_argument("--probe-timeout-seconds", type=int, default=30)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.probe_timeout_seconds < 1 or args.probe_timeout_seconds > 120:
        print("ERROR: probe timeout must be between 1 and 120 seconds", file=sys.stderr)
        return 2
    try:
        output = produce(args)
        print(f"Source allocation raw evidence produced at {output}")
        return 0
    except (OSError, AllocationProducerError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
