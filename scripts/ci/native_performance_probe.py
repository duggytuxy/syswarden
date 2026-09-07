#!/usr/bin/env python3
"""Collect real, candidate-bound native performance samples through a closed adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

try:
    from scripts.ci import performance_gate as gate
except ModuleNotFoundError:
    import performance_gate as gate


MAX_ADAPTER_OUTPUT_BYTES = 64 * 1024
MAX_RUNS = 1000
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SIZE_METRICS = {"binary_bytes", "package_bytes"}
NONNEGATIVE_METRICS = {
    "idle_cpu_percent",
    "loaded_cpu_percent",
    "disk_io_bytes_per_event",
}
SAMPLE_SCHEMA = "syswarden-native-performance-samples/v2"


class NativePerformanceProbeError(ValueError):
    """Raised when a native observation cannot be safely attested."""


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise NativePerformanceProbeError("adapter process group did not terminate") from exc


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_adapter_output(
    process: subprocess.Popen[bytes], timeout_seconds: int, iteration: int
) -> tuple[int, bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise NativePerformanceProbeError("adapter output pipes are unavailable")
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise NativePerformanceProbeError(
                    f"adapter execution timed out at iteration {iteration}"
                )
            events = selector.select(min(remaining, 0.1))
            if not events:
                if process.poll() is not None and _process_group_exists(process.pid):
                    _kill_process_group(process)
                    raise NativePerformanceProbeError(
                        f"adapter left persistent descendants at iteration {iteration}"
                    )
                continue
            for key, _ in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                output = streams[stream]
                remaining_capacity = MAX_ADAPTER_OUTPUT_BYTES + 1 - len(output)
                output.extend(chunk[:remaining_capacity])
                if len(output) > MAX_ADAPTER_OUTPUT_BYTES or len(chunk) > remaining_capacity:
                    _kill_process_group(process)
                    raise NativePerformanceProbeError(
                        f"adapter output is outside bounds at iteration {iteration}"
                    )
            if process.poll() is not None and _process_group_exists(process.pid):
                _kill_process_group(process)
                raise NativePerformanceProbeError(
                    f"adapter left persistent descendants at iteration {iteration}"
                )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            raise NativePerformanceProbeError(
                f"adapter execution timed out at iteration {iteration}"
            )
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            raise NativePerformanceProbeError(
                f"adapter execution timed out at iteration {iteration}"
            ) from exc
        if _process_group_exists(process.pid):
            _kill_process_group(process)
            raise NativePerformanceProbeError(
                f"adapter left persistent descendants at iteration {iteration}"
            )
        return returncode, bytes(streams[process.stdout]), bytes(streams[process.stderr])
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativePerformanceProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _regular(path: Path, *, executable: bool = False) -> os.stat_result:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise NativePerformanceProbeError(f"input must be one regular file: {path}")
    if before.st_uid != os.geteuid() or before.st_mode & 0o022:
        raise NativePerformanceProbeError(f"input ownership or mode is unsafe: {path}")
    if executable and stat.S_IMODE(before.st_mode) != 0o700:
        raise NativePerformanceProbeError(f"adapter mode must be exactly 0700: {path}")
    return before


def _identity(info: os.stat_result) -> tuple[int, ...]:
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


def _sha256(path: Path, expected: os.stat_result | None = None) -> str:
    before = _regular(path)
    if expected is not None and _identity(before) != _identity(expected):
        raise NativePerformanceProbeError(f"input changed during the campaign: {path}")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise NativePerformanceProbeError(f"input changed while opening: {path}")
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(opened):
            raise NativePerformanceProbeError(f"input changed while reading: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _open_attested_adapter(path: Path, expected_sha256: str) -> int:
    before = _regular(path, executable=True)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o022
            or stat.S_IMODE(opened.st_mode) != 0o700
            or _identity(opened) != _identity(before)
        ):
            raise NativePerformanceProbeError("adapter changed while opening")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            _identity(after) != _identity(opened)
            or digest.hexdigest() != expected_sha256
        ):
            raise NativePerformanceProbeError("adapter SHA-256 mismatch or concurrent change")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_attested_config(path: Path, expected_sha256: str) -> int:
    before = _regular(path)
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise NativePerformanceProbeError(f"adapter config mode must be exactly 0600: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise NativePerformanceProbeError("adapter config changed while opening")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if (
            _identity(os.fstat(descriptor)) != _identity(opened)
            or digest.hexdigest() != expected_sha256
        ):
            raise NativePerformanceProbeError(
                "adapter config SHA-256 mismatch or concurrent change"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _observation(value: object, metric: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NativePerformanceProbeError(f"adapter metric {metric} must be numeric")
    number = float(value)
    if not math.isfinite(number) or (
        number < 0 if metric in NONNEGATIVE_METRICS else number <= 0
    ):
        qualifier = "nonnegative" if metric in NONNEGATIVE_METRICS else "positive"
        raise NativePerformanceProbeError(
            f"adapter metric {metric} must be finite and {qualifier}"
        )
    return number


def _invoke_adapter(
    adapter_descriptor: int,
    config_descriptor: int,
    config_sha256: str,
    candidate_commit: str,
    baseline_commit: str,
    campaign_id: str,
    recorded_at: str,
    subject_role: str,
    subject_release: str,
    iteration: int,
    expected_metrics: set[str],
    timeout_seconds: int,
    package: Path,
    package_sha256: str,
    binary: Path,
) -> dict[str, float]:
    command = [
        f"/proc/self/fd/{adapter_descriptor}",
        "--config-fd",
        str(config_descriptor),
        "--config-sha256",
        config_sha256,
        "--candidate-commit",
        candidate_commit,
        "--baseline-commit",
        baseline_commit,
        "--campaign-id",
        campaign_id,
        "--recorded-at",
        recorded_at,
        "--subject-role",
        subject_role,
        "--subject-release",
        subject_release,
        "--iteration",
        str(iteration),
        "--metrics",
        ",".join(sorted(expected_metrics)),
        "--package-path",
        str(package),
        "--package-sha256",
        package_sha256,
        "--binary-path",
        str(binary),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            pass_fds=(adapter_descriptor, config_descriptor),
            start_new_session=True,
        )
    except OSError as exc:
        raise NativePerformanceProbeError(
            f"adapter execution failed at iteration {iteration}"
        ) from exc
    returncode, stdout, stderr = _read_adapter_output(
        process, timeout_seconds, iteration
    )
    if returncode != 0:
        raise NativePerformanceProbeError(f"adapter rejected iteration {iteration}")
    if (
        not stdout
        or len(stdout) > MAX_ADAPTER_OUTPUT_BYTES
        or len(stderr) > MAX_ADAPTER_OUTPUT_BYTES
    ):
        raise NativePerformanceProbeError(f"adapter output is outside bounds at iteration {iteration}")
    try:
        response = json.loads(stdout, object_pairs_hook=_no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(NativePerformanceProbeError(f"invalid JSON number: {value}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativePerformanceProbeError(f"adapter output is invalid JSON at iteration {iteration}") from exc
    if not isinstance(response, dict) or set(response) != {
        "schema_version",
        "candidate_commit",
        "campaign_id",
        "recorded_at",
        "subject_role",
        "subject_release",
        "iteration",
        "metrics",
    }:
        raise NativePerformanceProbeError(f"adapter response schema is not exact at iteration {iteration}")
    if (
        response["schema_version"] != 2
        or response["candidate_commit"] != candidate_commit
        or response["campaign_id"] != campaign_id
        or response["recorded_at"] != recorded_at
        or response["subject_role"] != subject_role
        or response["subject_release"] != subject_release
        or response["iteration"] != iteration
    ):
        raise NativePerformanceProbeError(f"adapter response binding is invalid at iteration {iteration}")
    metrics = response["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != expected_metrics:
        raise NativePerformanceProbeError(f"adapter metric inventory is not exact at iteration {iteration}")
    return {
        name: _observation(metrics[name], name)
        for name in sorted(expected_metrics)
    }


def _write_new_json(path: Path, document: object) -> None:
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise NativePerformanceProbeError("output must have an absolute canonical parent")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        wire = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        os.write(descriptor, wire)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise NativePerformanceProbeError(f"output already exists: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def collect(
    *,
    candidate_commit: str,
    campaign_id: str,
    recorded_at: str,
    subject_role: str,
    adapter: Path,
    adapter_sha256: str,
    adapter_config: Path,
    adapter_config_sha256: str,
    binary: Path,
    package: Path,
    runs: int,
    timeout_seconds: int,
    contract_path: Path = gate.DEFAULT_CONTRACT,
) -> dict[str, Any]:
    if COMMIT_PATTERN.fullmatch(candidate_commit) is None:
        raise NativePerformanceProbeError("candidate commit is not canonical")
    if gate.IDENTIFIER_PATTERN.fullmatch(campaign_id) is None:
        raise NativePerformanceProbeError("campaign identifier is not canonical")
    try:
        gate._canonical_utc_timestamp(recorded_at, "recorded_at")
    except gate.PerformanceGateError as exc:
        raise NativePerformanceProbeError(str(exc)) from exc
    if (
        SHA_PATTERN.fullmatch(adapter_sha256) is None
        or SHA_PATTERN.fullmatch(adapter_config_sha256) is None
    ):
        raise NativePerformanceProbeError(
            "adapter or adapter config SHA-256 is not canonical"
        )
    if runs <= 0 or runs > MAX_RUNS or timeout_seconds <= 0 or timeout_seconds > 3600:
        raise NativePerformanceProbeError("run count or timeout is outside bounds")
    if (
        not adapter.is_absolute()
        or not adapter_config.is_absolute()
        or not binary.is_absolute()
        or not package.is_absolute()
        or Path(os.path.normpath(adapter)) != adapter
        or Path(os.path.normpath(adapter_config)) != adapter_config
        or Path(os.path.normpath(binary)) != binary
        or Path(os.path.normpath(package)) != package
    ):
        raise NativePerformanceProbeError(
            "adapter, config, binary and package paths must be absolute and canonical"
        )
    package_state = _regular(package)
    if package_state.st_size <= 0:
        raise NativePerformanceProbeError("package must be non-empty")
    package_sha256 = _sha256(package, package_state)
    config_state = _regular(adapter_config)
    contract, metrics = gate.load_contract(contract_path)
    subject_releases = {
        "baseline": contract["baseline_release"],
        "candidate": contract["target_release"],
    }
    if subject_role not in subject_releases:
        raise NativePerformanceProbeError("subject role must be baseline or candidate")
    subject_release = subject_releases[subject_role]
    campaign_count = int(contract["minimum_campaigns"])
    per_campaign = {
        name: math.ceil(item.minimum_samples / campaign_count)
        for name, item in metrics.items()
    }
    required_runs = max(per_campaign.values())
    if runs != required_runs:
        raise NativePerformanceProbeError(f"runs must equal {required_runs}")
    dynamic = set(metrics) - SIZE_METRICS
    samples = {name: [] for name in metrics}
    adapter_descriptor = _open_attested_adapter(adapter, adapter_sha256)
    try:
        config_descriptor = _open_attested_config(
            adapter_config, adapter_config_sha256
        )
        try:
            for iteration in range(1, runs + 1):
                requested = {
                    name for name in dynamic if iteration <= per_campaign[name]
                }
                observed = _invoke_adapter(
                    adapter_descriptor,
                    config_descriptor,
                    adapter_config_sha256,
                    candidate_commit,
                    contract["baseline_commit"],
                    campaign_id,
                    recorded_at,
                    subject_role,
                    subject_release,
                    iteration,
                    requested,
                    timeout_seconds,
                    package,
                    package_sha256,
                    binary,
                )
                for name, value in observed.items():
                    samples[name].append(value)
        finally:
            os.close(config_descriptor)
    finally:
        os.close(adapter_descriptor)
    binary_state = _regular(binary)
    if binary_state.st_size <= 0:
        raise NativePerformanceProbeError("installed binary must be non-empty")
    for _ in range(per_campaign["binary_bytes"]):
        samples["binary_bytes"].append(float(binary_state.st_size))
    for _ in range(per_campaign["package_bytes"]):
        samples["package_bytes"].append(float(package_state.st_size))
    if _sha256(adapter_config, config_state) != adapter_config_sha256:
        raise NativePerformanceProbeError("adapter config changed during the campaign")
    return {
        "schema_version": 2,
        "schema_id": SAMPLE_SCHEMA,
        "contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "candidate_commit": candidate_commit,
        "campaign_id": campaign_id,
        "recorded_at": recorded_at,
        "subject_role": subject_role,
        "subject_release": subject_release,
        "adapter_sha256": adapter_sha256,
        "adapter_config_sha256": adapter_config_sha256,
        "binary_sha256": _sha256(binary, binary_state),
        "package_sha256": _sha256(package, package_state),
        "metrics": {
            name: {"unit": metrics[name].unit, "samples": samples[name]}
            for name in metrics
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    parser.add_argument("--subject-role", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--adapter-sha256", required=True)
    parser.add_argument("--adapter-config", type=Path, required=True)
    parser.add_argument("--adapter-config-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--contract", type=Path, default=gate.DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = collect(
            candidate_commit=args.candidate_commit,
            campaign_id=args.campaign_id,
            recorded_at=args.recorded_at,
            subject_role=args.subject_role,
            adapter=args.adapter,
            adapter_sha256=args.adapter_sha256,
            adapter_config=args.adapter_config,
            adapter_config_sha256=args.adapter_config_sha256,
            binary=args.binary,
            package=args.package,
            runs=args.runs,
            timeout_seconds=args.timeout_seconds,
            contract_path=args.contract,
        )
        _write_new_json(args.output, document)
    except (NativePerformanceProbeError, OSError, gate.PerformanceGateError) as exc:
        print(f"native performance probe: {exc}", file=os.sys.stderr)
        return 1
    print(f"Native performance samples written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
