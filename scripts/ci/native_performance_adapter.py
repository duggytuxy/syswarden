#!/usr/bin/env python3
"""Measure real SysWarden operations on a preconfigured isolated native host."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import stat
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
RESPONSE_SCHEMA_VERSION = 2
MAX_CONFIG_BYTES = 128 * 1024
MAX_CAPTURE_FILE_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_DELTA_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_LINE_BYTES = 512
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 4096
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
METRICS = {
    "idle_cpu_percent",
    "loaded_cpu_percent",
    "rss_bytes",
    "startup_milliseconds",
    "install_milliseconds",
    "event_to_rule_milliseconds",
    "waap_events_per_second",
    "nft_transaction_milliseconds",
    "disk_io_bytes_per_event",
}
EXPECTED_BINARY_PATH = Path("/opt/syswarden/bin/syswarden-core")
COMMAND_NAMES = {
    "install",
    "identity",
    "pid",
    "stop",
    "start",
    "ready",
    "idle_prepare",
    "loaded_workload",
    "loaded_cleanup",
    "event_emit",
    "event_cleanup",
    "nft_apply",
    "nft_verify",
    "nft_cleanup",
}
REQUIRED_COMMAND_PLACEHOLDERS = {
    "install": {"package"},
    "loaded_workload": {"token", "events"},
    "loaded_cleanup": {"token"},
    "event_emit": {"token"},
    "event_cleanup": {"token"},
    "nft_apply": {"token"},
    "nft_verify": {"token"},
    "nft_cleanup": {"token"},
}
PLACEHOLDERS = {
    "package",
    "binary",
    "artifact_commit",
    "candidate_commit",
    "campaign_id",
    "recorded_at",
    "subject_role",
    "subject_release",
    "iteration",
    "token",
    "events",
}


class NativePerformanceAdapterError(ValueError):
    """Raised when a native measurement is incomplete or ambiguous."""


class CaptureNotReady(NativePerformanceAdapterError):
    """Raised when a trusted append-only capture ends in a partial record."""


@dataclass(frozen=True)
class Command:
    path: Path
    sha256: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ProcessSample:
    pid: int
    start_ticks: int
    cpu_ticks: int
    rss_bytes: int
    io_bytes: int


@dataclass(frozen=True)
class CaptureCheckpoint:
    path: Path
    identity: tuple[int, int, int, int, int, int]
    offset: int


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativePerformanceAdapterError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise NativePerformanceAdapterError(f"{label} schema is not exact")
    return value


def _canonical_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise NativePerformanceAdapterError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        raise NativePerformanceAdapterError(f"{label} must be an absolute canonical path")
    return path


def _safe_file(path: Path, label: str, *, executable: bool = False) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise NativePerformanceAdapterError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise NativePerformanceAdapterError(f"{label} must be one regular file: {path}")
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise NativePerformanceAdapterError(f"{label} ownership or mode is unsafe: {path}")
    if executable and not info.st_mode & 0o111:
        raise NativePerformanceAdapterError(f"{label} is not executable: {path}")
    return info


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _hash_file(path: Path, label: str, *, executable: bool = False) -> str:
    before = _safe_file(path, label, executable=executable)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise NativePerformanceAdapterError(f"{label} changed while opening")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(opened):
            raise NativePerformanceAdapterError(f"{label} changed while reading")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_config(descriptor: int, expected_sha256: str) -> dict[str, Any]:
    if descriptor < 3 or SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise NativePerformanceAdapterError("configuration descriptor or SHA-256 is invalid")
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise NativePerformanceAdapterError("configuration descriptor is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in {0, os.geteuid()}
        or info.st_mode & 0o077
        or info.st_size <= 0
        or info.st_size > MAX_CONFIG_BYTES
    ):
        raise NativePerformanceAdapterError("configuration file ownership, mode, or size is unsafe")
    wire = os.pread(descriptor, info.st_size + 1, 0)
    if (
        len(wire) != info.st_size
        or _file_identity(os.fstat(descriptor)) != _file_identity(info)
    ):
        raise NativePerformanceAdapterError("configuration changed while reading")
    if hashlib.sha256(wire).hexdigest() != expected_sha256:
        raise NativePerformanceAdapterError("configuration SHA-256 mismatch")
    try:
        document = json.loads(
            wire,
            object_pairs_hook=_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                NativePerformanceAdapterError(f"invalid JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativePerformanceAdapterError("configuration is not valid JSON") from exc
    return _validate_config(document)


def _positive_int(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        raise NativePerformanceAdapterError(f"{label} is outside bounds")
    return value


def _validate_command(
    value: object,
    label: str,
    required_placeholders: set[str] | frozenset[str] = frozenset(),
) -> Command:
    raw = _exact(value, {"path", "sha256", "arguments"}, label)
    path = _canonical_path(raw["path"], f"{label} path")
    digest = raw["sha256"]
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise NativePerformanceAdapterError(f"{label} SHA-256 is invalid")
    arguments = raw["arguments"]
    if not isinstance(arguments, list) or len(arguments) > MAX_ARGUMENTS:
        raise NativePerformanceAdapterError(f"{label} arguments are outside bounds")
    checked: list[str] = []
    present_placeholders: set[str] = set()
    formatter = string.Formatter()
    for argument in arguments:
        if not isinstance(argument, str) or not argument or len(argument.encode()) > MAX_ARGUMENT_BYTES or "\x00" in argument:
            raise NativePerformanceAdapterError(f"{label} contains an invalid argument")
        for _, field, format_spec, conversion in formatter.parse(argument):
            if field is not None and (field not in PLACEHOLDERS or format_spec or conversion):
                raise NativePerformanceAdapterError(f"{label} contains an invalid placeholder")
            if field is not None:
                present_placeholders.add(field)
        checked.append(argument)
    missing = required_placeholders - present_placeholders
    if missing:
        raise NativePerformanceAdapterError(
            f"{label} is missing required placeholders: {','.join(sorted(missing))}"
        )
    return Command(path=path, sha256=digest, arguments=tuple(checked))


def _validate_subject(value: object, role: str) -> dict[str, Any]:
    raw = _exact(
        value,
        {
            "release",
            "artifact_commit",
            "package_path",
            "package_sha256",
            "binary_path",
            "binary_sha256",
            "identity_stdout",
        },
        f"{role} subject",
    )
    if not isinstance(raw["release"], str) or not raw["release"]:
        raise NativePerformanceAdapterError(f"{role} release is invalid")
    if not isinstance(raw["artifact_commit"], str) or COMMIT_PATTERN.fullmatch(raw["artifact_commit"]) is None:
        raise NativePerformanceAdapterError(f"{role} artifact commit is invalid")
    for name in ("package_sha256", "binary_sha256"):
        if not isinstance(raw[name], str) or SHA256_PATTERN.fullmatch(raw[name]) is None:
            raise NativePerformanceAdapterError(f"{role} {name} is invalid")
    raw["package_path"] = _canonical_path(raw["package_path"], f"{role} package path")
    raw["binary_path"] = _canonical_path(raw["binary_path"], f"{role} binary path")
    if not isinstance(raw["identity_stdout"], str) or not raw["identity_stdout"] or len(raw["identity_stdout"].encode()) > MAX_COMMAND_OUTPUT_BYTES:
        raise NativePerformanceAdapterError(f"{role} identity output is invalid")
    return raw


def _validate_config(value: object) -> dict[str, Any]:
    raw = _exact(
        value,
        {"schema_version", "candidate_commit", "subjects", "captures", "commands", "limits"},
        "configuration",
    )
    if raw["schema_version"] != SCHEMA_VERSION:
        raise NativePerformanceAdapterError("configuration schema version is invalid")
    if not isinstance(raw["candidate_commit"], str) or COMMIT_PATTERN.fullmatch(raw["candidate_commit"]) is None:
        raise NativePerformanceAdapterError("configuration candidate commit is invalid")
    subjects = _exact(raw["subjects"], {"baseline", "candidate"}, "subjects")
    raw["subjects"] = {role: _validate_subject(subjects[role], role) for role in ("baseline", "candidate")}
    if any(
        subject["binary_path"] != EXPECTED_BINARY_PATH
        for subject in raw["subjects"].values()
    ):
        raise NativePerformanceAdapterError(
            "subjects must identify the packaged syswarden-core executable"
        )
    captures = _exact(raw["captures"], {"source_jsonl", "rule_jsonl", "waap_jsonl"}, "captures")
    for name in captures:
        captures[name] = _canonical_path(captures[name], f"capture {name}")
    if len(set(captures.values())) != len(captures):
        raise NativePerformanceAdapterError("capture paths must be pairwise distinct")
    commands = _exact(raw["commands"], COMMAND_NAMES, "commands")
    raw["commands"] = {
        name: _validate_command(
            commands[name],
            f"command {name}",
            REQUIRED_COMMAND_PLACEHOLDERS.get(name, frozenset()),
        )
        for name in COMMAND_NAMES
    }
    limits = _exact(
        raw["limits"],
        {
            "command_timeout_seconds",
            "ready_timeout_milliseconds",
            "event_timeout_milliseconds",
            "nft_timeout_milliseconds",
            "poll_interval_milliseconds",
            "idle_window_milliseconds",
            "waap_events",
        },
        "limits",
    )
    limits["command_timeout_seconds"] = _positive_int(limits["command_timeout_seconds"], "command timeout", 300)
    limits["ready_timeout_milliseconds"] = _positive_int(limits["ready_timeout_milliseconds"], "ready timeout", 300000)
    limits["event_timeout_milliseconds"] = _positive_int(limits["event_timeout_milliseconds"], "event timeout", 300000)
    limits["nft_timeout_milliseconds"] = _positive_int(limits["nft_timeout_milliseconds"], "nft timeout", 300000)
    limits["poll_interval_milliseconds"] = _positive_int(limits["poll_interval_milliseconds"], "poll interval", 1000)
    limits["idle_window_milliseconds"] = _positive_int(limits["idle_window_milliseconds"], "idle window", 300000)
    limits["waap_events"] = _positive_int(limits["waap_events"], "WAAP event count", 10000)
    if limits["poll_interval_milliseconds"] >= min(
        limits["ready_timeout_milliseconds"], limits["event_timeout_milliseconds"], limits["nft_timeout_milliseconds"]
    ):
        raise NativePerformanceAdapterError("poll interval must be below every polling timeout")
    return raw


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise NativePerformanceAdapterError("command process did not terminate") from exc


def _drain(process: subprocess.Popen[bytes], timeout: float, label: str) -> tuple[int, bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        _kill_process(process)
        raise NativePerformanceAdapterError(f"{label} output pipes are unavailable")
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        for stream in buffers:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process(process)
                raise NativePerformanceAdapterError(f"{label} timed out")
            events = selector.select(min(remaining, 0.05))
            if not events:
                continue
            for key, _ in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    selector.unregister(stream)
                    continue
                output = buffers[stream]
                capacity = MAX_COMMAND_OUTPUT_BYTES + 1 - len(output)
                output.extend(chunk[:capacity])
                if len(output) > MAX_COMMAND_OUTPUT_BYTES or len(chunk) > capacity:
                    _kill_process(process)
                    raise NativePerformanceAdapterError(f"{label} output is outside bounds")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process(process)
            raise NativePerformanceAdapterError(f"{label} timed out")
        returncode = process.wait(timeout=remaining)
        return returncode, bytes(buffers[process.stdout]), bytes(buffers[process.stderr])
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _expand(command: Command, bindings: Mapping[str, str]) -> list[str]:
    try:
        arguments = [argument.format_map(bindings) for argument in command.arguments]
    except KeyError as exc:
        raise NativePerformanceAdapterError("command placeholder is unavailable") from exc
    if any(len(argument.encode()) > MAX_ARGUMENT_BYTES or "\x00" in argument for argument in arguments):
        raise NativePerformanceAdapterError("expanded command argument is outside bounds")
    return arguments


def _run(
    command: Command,
    bindings: Mapping[str, str],
    timeout: float,
    label: str,
    *,
    allow_failure: bool = False,
) -> tuple[int, bytes]:
    before = _safe_file(command.path, f"{label} executable", executable=True)
    descriptor = os.open(command.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise NativePerformanceAdapterError(f"{label} executable changed while opening")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(opened) or digest.hexdigest() != command.sha256:
            raise NativePerformanceAdapterError(f"{label} executable identity is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            process = subprocess.Popen(
                [f"/proc/self/fd/{descriptor}", *_expand(command, bindings)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                pass_fds=(descriptor,),
                start_new_session=False,
            )
        except OSError as exc:
            raise NativePerformanceAdapterError(f"{label} could not start") from exc
        returncode, stdout, _ = _drain(process, timeout, label)
        if returncode != 0 and not allow_failure:
            raise NativePerformanceAdapterError(f"{label} failed")
        return returncode, stdout
    finally:
        os.close(descriptor)


def _read_pid(
    command: Command,
    bindings: Mapping[str, str],
    timeout: float,
) -> int:
    try:
        _, wire = _run(command, bindings, timeout, "service PID query")
        text = wire.decode("ascii")
    except UnicodeDecodeError as exc:
        raise NativePerformanceAdapterError("service PID output is unreadable") from exc
    if not text.endswith("\n") or not text[:-1].isdigit():
        raise NativePerformanceAdapterError("service PID output is not canonical")
    pid = int(text[:-1])
    if pid <= 1:
        raise NativePerformanceAdapterError("process PID is invalid")
    return pid


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _process_sample(pid: int, expected_binary_sha256: str) -> ProcessSample:
    try:
        executable = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
        try:
            if _hash_descriptor(executable) != expected_binary_sha256:
                raise NativePerformanceAdapterError("running process binary SHA-256 is invalid")
        finally:
            os.close(executable)
        stat_wire = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        end = stat_wire.rfind(")")
        fields = stat_wire[end + 2 :].split()
        if end < 1 or len(fields) < 22:
            raise ValueError("short stat")
        cpu_ticks = int(fields[11]) + int(fields[12])
        start_ticks = int(fields[19])
        rss_pages = int(fields[21])
        io_values: dict[str, int] = {}
        for line in Path(f"/proc/{pid}/io").read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                io_values[key] = int(value.strip())
        io_bytes = io_values["read_bytes"] + io_values["write_bytes"]
    except (OSError, ValueError, KeyError) as exc:
        raise NativePerformanceAdapterError("running process observation is unavailable") from exc
    if rss_pages <= 0 or cpu_ticks < 0 or start_ticks <= 0 or io_bytes < 0:
        raise NativePerformanceAdapterError("running process observation is invalid")
    return ProcessSample(pid, start_ticks, cpu_ticks, rss_pages * os.sysconf("SC_PAGE_SIZE"), io_bytes)


def _same_process(before: ProcessSample, after: ProcessSample, label: str) -> None:
    if (before.pid, before.start_ticks) != (after.pid, after.start_ticks):
        raise NativePerformanceAdapterError(f"SysWarden process changed during {label}")


def _capture_checkpoint(path: Path) -> CaptureCheckpoint:
    info = _safe_file(path, "capture file")
    if info.st_size > MAX_CAPTURE_FILE_BYTES:
        raise NativePerformanceAdapterError("capture file is outside bounds")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(info):
            raise NativePerformanceAdapterError("capture changed while opening")
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
        )
        if info.st_size and os.pread(descriptor, 1, info.st_size - 1) != b"\n":
            raise NativePerformanceAdapterError("capture file does not end at a JSONL boundary")
    finally:
        os.close(descriptor)
    return CaptureCheckpoint(path, identity, info.st_size)


def _capture_records(checkpoint: CaptureCheckpoint) -> list[dict[str, Any]]:
    info = _safe_file(checkpoint.path, "capture file")
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
    )
    if (
        identity != checkpoint.identity
        or info.st_size < checkpoint.offset
        or info.st_size > MAX_CAPTURE_FILE_BYTES
        or info.st_size - checkpoint.offset > MAX_CAPTURE_DELTA_BYTES
    ):
        raise NativePerformanceAdapterError("capture identity or growth is invalid")
    descriptor = os.open(checkpoint.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
        )
        if (
            opened_identity != checkpoint.identity
            or opened.st_size < info.st_size
            or opened.st_size < checkpoint.offset
            or opened.st_size > MAX_CAPTURE_FILE_BYTES
            or opened.st_size - checkpoint.offset > MAX_CAPTURE_DELTA_BYTES
        ):
            raise NativePerformanceAdapterError("capture changed while opening")
        delta = opened.st_size - checkpoint.offset
        wire = os.pread(descriptor, delta, checkpoint.offset)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
        )
        if after_identity != checkpoint.identity or after.st_size < opened.st_size:
            raise NativePerformanceAdapterError("capture changed while reading")
        if (
            after.st_size == opened.st_size
            and (after.st_mtime_ns, after.st_ctime_ns)
            != (opened.st_mtime_ns, opened.st_ctime_ns)
        ):
            raise NativePerformanceAdapterError("capture was modified without append growth")
    finally:
        os.close(descriptor)
    if len(wire) != delta:
        raise NativePerformanceAdapterError("capture changed while reading")
    if wire and not wire.endswith(b"\n"):
        raise CaptureNotReady("capture ends in a partial JSONL record")
    records: list[dict[str, Any]] = []
    for line in wire.splitlines():
        if not line or len(line) > MAX_CAPTURE_LINE_BYTES:
            raise NativePerformanceAdapterError("capture JSONL line is outside bounds")
        try:
            record = json.loads(line, object_pairs_hook=_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NativePerformanceAdapterError("capture contains invalid JSON") from exc
        record = _exact(record, {"token", "timestamp_ns"}, "capture record")
        if not isinstance(record["token"], str) or len(record["token"]) > 200:
            raise NativePerformanceAdapterError("capture token is invalid")
        if type(record["timestamp_ns"]) is not int or record["timestamp_ns"] <= 0:
            raise NativePerformanceAdapterError("capture timestamp is invalid")
        records.append(record)
    return records


def _require_empty_capture(checkpoint: CaptureCheckpoint, label: str) -> None:
    info = _safe_file(checkpoint.path, label)
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
    )
    if identity != checkpoint.identity:
        raise NativePerformanceAdapterError(
            f"{label} identity changed during cleanup"
        )
    if info.st_size != 0:
        raise NativePerformanceAdapterError(f"{label} was not reset by cleanup")


def _matching(records: list[dict[str, Any]], token: str) -> list[dict[str, Any]]:
    return [record for record in records if record["token"] == token]


def _poll_command(
    command: Command,
    bindings: Mapping[str, str],
    command_timeout: float,
    polling_timeout: float,
    interval: float,
    label: str,
) -> None:
    deadline = time.monotonic() + polling_timeout
    while True:
        returncode, _ = _run(command, bindings, min(command_timeout, max(0.001, deadline - time.monotonic())), label, allow_failure=True)
        if returncode == 0:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativePerformanceAdapterError(f"{label} did not succeed before its deadline")
        time.sleep(min(interval, remaining))


def _positive(value: float, label: str) -> float:
    if not math.isfinite(value) or value <= 0:
        raise NativePerformanceAdapterError(f"{label} observation is not finite and positive")
    return value


def _nonnegative(value: float, label: str) -> float:
    if not math.isfinite(value) or value < 0:
        raise NativePerformanceAdapterError(
            f"{label} observation is not finite and nonnegative"
        )
    return value


def measure(config: dict[str, Any], request: argparse.Namespace) -> dict[str, float]:
    if request.candidate_commit != config["candidate_commit"]:
        raise NativePerformanceAdapterError("candidate commit does not match the configuration")
    if config["subjects"]["baseline"]["artifact_commit"] != request.baseline_commit:
        raise NativePerformanceAdapterError("baseline commit does not match the configuration")
    subject = config["subjects"][request.subject_role]
    if subject["release"] != request.subject_release:
        raise NativePerformanceAdapterError("subject release does not match the configuration")
    if request.subject_role == "candidate" and subject["artifact_commit"] != request.candidate_commit:
        raise NativePerformanceAdapterError("candidate artifact commit does not match the request")
    if Path(request.package_path) != subject["package_path"] or request.package_sha256 != subject["package_sha256"]:
        raise NativePerformanceAdapterError("package binding does not match the configuration")
    if Path(request.binary_path) != subject["binary_path"]:
        raise NativePerformanceAdapterError("binary path does not match the configuration")
    if _hash_file(subject["package_path"], "subject package") != subject["package_sha256"]:
        raise NativePerformanceAdapterError("subject package SHA-256 is invalid")

    metric_names = request.metrics.split(",") if request.metrics else []
    requested = set(metric_names)
    if metric_names != sorted(requested) or requested - METRICS or not requested:
        raise NativePerformanceAdapterError("requested metric inventory is invalid")
    limits = config["limits"]
    commands: dict[str, Command] = config["commands"]
    command_timeout = float(limits["command_timeout_seconds"])
    interval = limits["poll_interval_milliseconds"] / 1000.0
    token = f"{request.campaign_id}.{request.subject_role}.{request.iteration}"
    bindings = {
        "package": str(subject["package_path"]),
        "binary": str(subject["binary_path"]),
        "artifact_commit": subject["artifact_commit"],
        "candidate_commit": request.candidate_commit,
        "campaign_id": request.campaign_id,
        "recorded_at": request.recorded_at,
        "subject_role": request.subject_role,
        "subject_release": request.subject_release,
        "iteration": str(request.iteration),
        "token": token,
        "events": str(limits["waap_events"]),
    }
    observations: dict[str, float] = {}

    if "install_milliseconds" in requested:
        started = time.monotonic_ns()
        _run(commands["install"], bindings, command_timeout, "package installation")
        observations["install_milliseconds"] = _positive((time.monotonic_ns() - started) / 1_000_000.0, "installation")
    if _hash_file(subject["binary_path"], "installed binary", executable=True) != subject["binary_sha256"]:
        raise NativePerformanceAdapterError("installed binary SHA-256 is invalid")
    _, identity_stdout = _run(commands["identity"], bindings, command_timeout, "installed identity")
    if identity_stdout.decode("utf-8", errors="strict") != subject["identity_stdout"]:
        raise NativePerformanceAdapterError("installed package identity output is invalid")

    _run(commands["stop"], bindings, command_timeout, "service stop")
    ready_code, _ = _run(commands["ready"], bindings, command_timeout, "stopped-state check", allow_failure=True)
    if ready_code == 0:
        raise NativePerformanceAdapterError("service remained ready after stop")
    started = time.monotonic_ns()
    _run(commands["start"], bindings, command_timeout, "service start")
    _poll_command(
        commands["ready"], bindings, command_timeout,
        limits["ready_timeout_milliseconds"] / 1000.0, interval, "service readiness",
    )
    startup_ms = (time.monotonic_ns() - started) / 1_000_000.0
    pid = _read_pid(commands["pid"], bindings, command_timeout)
    running = _process_sample(pid, subject["binary_sha256"])
    if "startup_milliseconds" in requested:
        observations["startup_milliseconds"] = _positive(startup_ms, "startup")

    if {"idle_cpu_percent", "rss_bytes"} & requested:
        _run(commands["idle_prepare"], bindings, command_timeout, "idle preparation")
        idle_before = _process_sample(pid, subject["binary_sha256"])
        idle_started = time.monotonic_ns()
        time.sleep(limits["idle_window_milliseconds"] / 1000.0)
        idle_elapsed = (time.monotonic_ns() - idle_started) / 1_000_000_000.0
        idle_after = _process_sample(pid, subject["binary_sha256"])
        _same_process(idle_before, idle_after, "idle window")
        if "idle_cpu_percent" in requested:
            cpu_seconds = (idle_after.cpu_ticks - idle_before.cpu_ticks) / float(os.sysconf("SC_CLK_TCK"))
            observations["idle_cpu_percent"] = _nonnegative(cpu_seconds / idle_elapsed * 100.0, "idle CPU")
        if "rss_bytes" in requested:
            observations["rss_bytes"] = _positive(float(idle_after.rss_bytes), "RSS")

    loaded_metrics = {"loaded_cpu_percent", "waap_events_per_second", "disk_io_bytes_per_event"} & requested
    if loaded_metrics:
        waap_checkpoint = _capture_checkpoint(config["captures"]["waap_jsonl"])
        loaded_before = _process_sample(pid, subject["binary_sha256"])
        loaded_started = time.monotonic_ns()
        try:
            _run(commands["loaded_workload"], bindings, command_timeout, "loaded WAAP workload")
            deadline = time.monotonic() + limits["event_timeout_milliseconds"] / 1000.0
            while True:
                try:
                    admitted = len(
                        _matching(_capture_records(waap_checkpoint), token)
                    )
                except CaptureNotReady:
                    admitted = -1
                if admitted == limits["waap_events"]:
                    loaded_finished = time.monotonic_ns()
                    loaded_after = _process_sample(pid, subject["binary_sha256"])
                    break
                if admitted > limits["waap_events"]:
                    raise NativePerformanceAdapterError(
                        "WAAP admitted-event capture count is ambiguous"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativePerformanceAdapterError(
                        "WAAP admitted-event capture count is incomplete"
                    )
                time.sleep(min(interval, remaining))
        finally:
            _run(commands["loaded_cleanup"], bindings, command_timeout, "loaded workload cleanup")
            _require_empty_capture(
                waap_checkpoint, "WAAP capture"
            )
        loaded_elapsed = (loaded_finished - loaded_started) / 1_000_000_000.0
        _same_process(loaded_before, loaded_after, "loaded window")
        if "loaded_cpu_percent" in requested:
            cpu_seconds = (loaded_after.cpu_ticks - loaded_before.cpu_ticks) / float(os.sysconf("SC_CLK_TCK"))
            observations["loaded_cpu_percent"] = _nonnegative(cpu_seconds / loaded_elapsed * 100.0, "loaded CPU")
        if "waap_events_per_second" in requested:
            observations["waap_events_per_second"] = _positive(admitted / loaded_elapsed, "WAAP throughput")
        if "disk_io_bytes_per_event" in requested:
            observations["disk_io_bytes_per_event"] = _nonnegative((loaded_after.io_bytes - loaded_before.io_bytes) / admitted, "I/O per event")

    if "event_to_rule_milliseconds" in requested:
        source_checkpoint = _capture_checkpoint(config["captures"]["source_jsonl"])
        rule_checkpoint = _capture_checkpoint(config["captures"]["rule_jsonl"])
        try:
            _run(commands["event_emit"], bindings, command_timeout, "event emission")
            deadline = time.monotonic() + limits["event_timeout_milliseconds"] / 1000.0
            while True:
                try:
                    source = _matching(_capture_records(source_checkpoint), token)
                    rule = _matching(_capture_records(rule_checkpoint), token)
                except CaptureNotReady:
                    source = []
                    rule = []
                if source and rule:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativePerformanceAdapterError("event captures did not complete before their deadline")
                time.sleep(min(interval, remaining))
        finally:
            _run(commands["event_cleanup"], bindings, command_timeout, "event cleanup")
            _require_empty_capture(
                source_checkpoint, "source capture"
            )
            _require_empty_capture(
                rule_checkpoint, "rule capture"
            )
        if len(source) != 1 or len(rule) != 1 or rule[0]["timestamp_ns"] <= source[0]["timestamp_ns"]:
            raise NativePerformanceAdapterError("event captures are missing or ambiguous")
        observations["event_to_rule_milliseconds"] = _positive(
            (rule[0]["timestamp_ns"] - source[0]["timestamp_ns"]) / 1_000_000.0,
            "event-to-rule latency",
        )

    if "nft_transaction_milliseconds" in requested:
        started = time.monotonic_ns()
        try:
            _run(commands["nft_apply"], bindings, command_timeout, "nftables transaction")
            _poll_command(
                commands["nft_verify"], bindings, command_timeout,
                limits["nft_timeout_milliseconds"] / 1000.0, interval, "nftables commit verification",
            )
            observations["nft_transaction_milliseconds"] = _positive(
                (time.monotonic_ns() - started) / 1_000_000.0, "nftables transaction"
            )
        finally:
            _run(commands["nft_cleanup"], bindings, command_timeout, "nftables cleanup")

    if _read_pid(commands["pid"], bindings, command_timeout) != pid:
        raise NativePerformanceAdapterError("service PID changed during the iteration")
    final = _process_sample(pid, subject["binary_sha256"])
    _same_process(running, final, "iteration")
    if set(observations) != requested:
        raise NativePerformanceAdapterError("not every requested metric was observed")
    return observations


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-fd", type=int, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    parser.add_argument("--subject-role", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--subject-release", required=True)
    parser.add_argument("--iteration", type=int, required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--package-path", required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--binary-path", required=True)
    args = parser.parse_args(argv)
    if COMMIT_PATTERN.fullmatch(args.candidate_commit) is None:
        parser.error("candidate commit is not canonical")
    if COMMIT_PATTERN.fullmatch(args.baseline_commit) is None:
        parser.error("baseline commit is not canonical")
    if IDENTIFIER_PATTERN.fullmatch(args.campaign_id) is None:
        parser.error("campaign identifier is not canonical")
    if args.iteration <= 0 or args.iteration > 1000:
        parser.error("iteration is outside bounds")
    if SHA256_PATTERN.fullmatch(args.package_sha256) is None:
        parser.error("package SHA-256 is invalid")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    request = _arguments(argv)
    try:
        config = _read_config(request.config_fd, request.config_sha256)
        metrics = measure(config, request)
        response = {
            "schema_version": RESPONSE_SCHEMA_VERSION,
            "candidate_commit": request.candidate_commit,
            "campaign_id": request.campaign_id,
            "recorded_at": request.recorded_at,
            "subject_role": request.subject_role,
            "subject_release": request.subject_release,
            "iteration": request.iteration,
            "metrics": metrics,
        }
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    except (NativePerformanceAdapterError, OSError, UnicodeError) as exc:
        print(f"native performance adapter: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
