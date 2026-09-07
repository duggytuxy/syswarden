#!/usr/bin/env python3
"""Tests for the fail-closed native performance adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_performance_adapter as adapter
except ModuleNotFoundError:
    import native_performance_adapter as adapter


DRIVER = r"""#!/usr/bin/env python3
import json, os, pathlib, sys, time
action, root = sys.argv[1], pathlib.Path(sys.argv[2])
args = sys.argv[3:]
if action == 'install':
    (root / 'installed').write_text(args[0])
elif action == 'identity':
    sys.stdout.write(args[0] + '\n')
elif action == 'stop':
    (root / 'state').write_text('stopped')
elif action == 'start':
    (root / 'state').write_text('ready')
elif action == 'ready':
    if not (root / 'state').exists() or (root / 'state').read_text() != 'ready':
        sys.exit(1)
elif action == 'pid':
    sys.stdout.write('12345\n')
elif action == 'idle':
    pass
elif action == 'loaded':
    token, count = args[0], int(args[1])
    with (root / 'waap.jsonl').open('a') as stream:
        for _ in range(count):
            stream.write(json.dumps({'token': token, 'timestamp_ns': time.time_ns()}) + '\n')
elif action == 'loaded-cleanup':
    (root / 'waap.jsonl').write_text('')
    (root / 'loaded-cleanup').write_text('done')
elif action == 'event':
    token = args[0]
    source = time.time_ns()
    with (root / 'source.jsonl').open('a') as stream:
        stream.write(json.dumps({'token': token, 'timestamp_ns': source}) + '\n')
    if not (root / 'omit-rule').exists():
        with (root / 'rule.jsonl').open('a') as stream:
            stream.write(json.dumps({'token': token, 'timestamp_ns': source + 1000000}) + '\n')
elif action == 'event-cleanup':
    (root / 'source.jsonl').write_text('')
    (root / 'rule.jsonl').write_text('')
    (root / 'event-cleanup').write_text('done')
elif action == 'nft-apply':
    (root / 'nft').write_text(args[0])
elif action == 'nft-verify':
    if not (root / 'nft').exists() or (root / 'nft').read_text() != args[0]:
        sys.exit(1)
elif action == 'nft-cleanup':
    (root / 'nft').unlink(missing_ok=True)
    (root / 'nft-cleanup').write_text('done')
else:
    sys.exit(2)
"""


class NativePerformanceAdapterTests(unittest.TestCase):
    candidate = "a" * 40

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def fixture(self, root: Path) -> tuple[dict[str, object], Path, Path, Path]:
        driver = root / "driver"
        driver.write_text(DRIVER, encoding="utf-8")
        driver.chmod(0o700)
        package = root / "syswarden.pkg"
        package.write_bytes(b"real-package-artifact")
        package.chmod(0o600)
        binary = root / "syswarden"
        binary.write_bytes(b"real-installed-binary")
        binary.chmod(0o700)
        original_expected_binary = adapter.EXPECTED_BINARY_PATH
        self.addCleanup(
            setattr,
            adapter,
            "EXPECTED_BINARY_PATH",
            original_expected_binary,
        )
        adapter.EXPECTED_BINARY_PATH = binary
        for name in ("source.jsonl", "rule.jsonl", "waap.jsonl"):
            capture = root / name
            capture.write_bytes(b"")
            capture.chmod(0o600)

        command_arguments = {
            "install": ["install", str(root), "{package}"],
            "identity": ["identity", str(root), "{subject_release}"],
            "stop": ["stop", str(root)],
            "start": ["start", str(root)],
            "ready": ["ready", str(root)],
            "pid": ["pid", str(root)],
            "idle_prepare": ["idle", str(root)],
            "loaded_workload": ["loaded", str(root), "{token}", "{events}"],
            "loaded_cleanup": ["loaded-cleanup", str(root), "{token}"],
            "event_emit": ["event", str(root), "{token}"],
            "event_cleanup": ["event-cleanup", str(root), "{token}"],
            "nft_apply": ["nft-apply", str(root), "{token}"],
            "nft_verify": ["nft-verify", str(root), "{token}"],
            "nft_cleanup": ["nft-cleanup", str(root), "{token}"],
        }
        commands = {
            name: {
                "path": str(driver),
                "sha256": self.digest(driver),
                "arguments": arguments,
            }
            for name, arguments in command_arguments.items()
        }
        subject = {
            "release": "v4.10.0",
            "artifact_commit": self.candidate,
            "package_path": str(package),
            "package_sha256": self.digest(package),
            "binary_path": str(binary),
            "binary_sha256": self.digest(binary),
            "identity_stdout": "v4.10.0\n",
        }
        baseline = dict(subject)
        baseline["release"] = "v4.04.3"
        baseline["artifact_commit"] = "381c1f8d91459a9b20605629c725900abd81dee8"
        baseline["identity_stdout"] = "v4.04.3\n"
        config: dict[str, object] = {
            "schema_version": 1,
            "candidate_commit": self.candidate,
            "subjects": {"baseline": baseline, "candidate": subject},
            "captures": {
                "source_jsonl": str(root / "source.jsonl"),
                "rule_jsonl": str(root / "rule.jsonl"),
                "waap_jsonl": str(root / "waap.jsonl"),
            },
            "commands": commands,
            "limits": {
                "command_timeout_seconds": 2,
                "ready_timeout_milliseconds": 100,
                "event_timeout_milliseconds": 100,
                "nft_timeout_milliseconds": 100,
                "poll_interval_milliseconds": 5,
                "idle_window_milliseconds": 10,
                "waap_events": 4,
            },
        }
        return config, driver, package, binary

    def request(self, package: Path, binary: Path, metrics: set[str] | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            candidate_commit=self.candidate,
            baseline_commit="381c1f8d91459a9b20605629c725900abd81dee8",
            campaign_id="campaign-1",
            recorded_at="2026-09-10T08:00:00Z",
            subject_role="candidate",
            subject_release="v4.10.0",
            iteration=1,
            metrics=",".join(sorted(metrics or adapter.METRICS)),
            package_path=str(package),
            package_sha256=self.digest(package),
            binary_path=str(binary),
        )

    def test_configuration_is_digest_bound_private_and_exact(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            config, _, _, _ = self.fixture(root)
            path = root / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                loaded = adapter._read_config(descriptor, self.digest(path))
                self.assertEqual(loaded["candidate_commit"], self.candidate)
                with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "SHA-256 mismatch"):
                    adapter._read_config(descriptor, "b" * 64)
            finally:
                os.close(descriptor)

            path.chmod(0o640)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "unsafe"):
                    adapter._read_config(descriptor, self.digest(path))
            finally:
                os.close(descriptor)

            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "duplicate"):
                    adapter._read_config(descriptor, self.digest(path))
            finally:
                os.close(descriptor)

    def test_configuration_requires_packaged_binary_and_distinct_captures(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            config, _, _, _ = self.fixture(root)

            wrong_binary = json.loads(json.dumps(config))
            wrong_binary["subjects"]["candidate"]["binary_path"] = str(
                root / "different-binary"
            )
            with self.assertRaisesRegex(
                adapter.NativePerformanceAdapterError,
                "packaged syswarden-core executable",
            ):
                adapter._validate_config(wrong_binary)

            aliased_capture = json.loads(json.dumps(config))
            aliased_capture["captures"]["rule_jsonl"] = aliased_capture["captures"][
                "source_jsonl"
            ]
            with self.assertRaisesRegex(
                adapter.NativePerformanceAdapterError,
                "pairwise distinct",
            ):
                adapter._validate_config(aliased_capture)

            for command_name, placeholders in adapter.REQUIRED_COMMAND_PLACEHOLDERS.items():
                for placeholder in placeholders:
                    with self.subTest(command=command_name, placeholder=placeholder):
                        unbound_command = json.loads(json.dumps(config))
                        arguments = unbound_command["commands"][command_name]["arguments"]
                        unbound_command["commands"][command_name]["arguments"] = [
                            argument
                            for argument in arguments
                            if argument != "{" + placeholder + "}"
                        ]
                        with self.assertRaisesRegex(
                            adapter.NativePerformanceAdapterError,
                            "missing required placeholders",
                        ):
                            adapter._validate_config(unbound_command)

    def test_command_is_hash_bound_shell_free_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            config, _, _, _ = self.fixture(root)
            checked = adapter._validate_config(config)
            popen_calls: list[dict[str, object]] = []
            original_popen = adapter.subprocess.Popen

            def recording_popen(*args: object, **kwargs: object) -> object:
                popen_calls.append(kwargs)
                return original_popen(*args, **kwargs)

            with mock.patch.object(
                adapter.subprocess,
                "Popen",
                side_effect=recording_popen,
            ):
                code, stdout = adapter._run(
                    checked["commands"]["identity"],
                    {name: "bound" for name in adapter.PLACEHOLDERS}
                    | {"subject_release": "v4.10.0"},
                    2,
                    "identity",
                )
            self.assertEqual(code, 0)
            self.assertEqual(stdout, b"v4.10.0\n")
            self.assertIs(popen_calls[0]["start_new_session"], False)

            command = checked["commands"]["identity"]
            bad = adapter.Command(command.path, "f" * 64, command.arguments)
            with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "identity is invalid"):
                adapter._run(bad, {name: "x" for name in adapter.PLACEHOLDERS}, 2, "identity")

    def test_real_captures_and_monotonic_proc_deltas_produce_every_metric(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            raw, _, package, binary = self.fixture(root)
            config = adapter._validate_config(raw)
            samples = [
                adapter.ProcessSample(42, 100, 100, 4096, 1000),
                adapter.ProcessSample(42, 100, 100, 4096, 1000),
                adapter.ProcessSample(42, 100, 110, 8192, 1000),
                adapter.ProcessSample(42, 100, 110, 8192, 1000),
                adapter.ProcessSample(42, 100, 130, 8192, 2000),
                adapter.ProcessSample(42, 100, 130, 8192, 2000),
            ]
            with mock.patch.object(adapter, "_process_sample", side_effect=samples):
                observed = adapter.measure(config, self.request(package, binary))
            self.assertEqual(set(observed), adapter.METRICS)
            self.assertTrue(all(value > 0 for value in observed.values()))
            self.assertEqual(observed["rss_bytes"], 8192.0)
            self.assertEqual(observed["disk_io_bytes_per_event"], 250.0)
            self.assertAlmostEqual(observed["event_to_rule_milliseconds"], 1.0)
            self.assertTrue((root / "loaded-cleanup").is_file())
            self.assertTrue((root / "event-cleanup").is_file())
            self.assertTrue((root / "nft-cleanup").is_file())

    def test_missing_capture_fails_and_cleanup_still_runs(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            raw, _, package, binary = self.fixture(root)
            (root / "omit-rule").write_text("yes", encoding="utf-8")
            raw["limits"]["event_timeout_milliseconds"] = 20
            config = adapter._validate_config(raw)
            samples = [
                adapter.ProcessSample(42, 100, 100, 4096, 1000),
                adapter.ProcessSample(42, 100, 100, 4096, 1000),
            ]
            with mock.patch.object(adapter, "_process_sample", side_effect=samples):
                with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "captures did not complete"):
                    adapter.measure(
                        config,
                        self.request(package, binary, {"event_to_rule_milliseconds"}),
                    )
            self.assertTrue((root / "event-cleanup").is_file())

    def test_ten_thousand_event_capture_is_reset_between_iterations(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            raw, _, package, binary = self.fixture(root)
            raw["limits"]["waap_events"] = 10000
            raw["limits"]["event_timeout_milliseconds"] = 2000
            config = adapter._validate_config(raw)
            call = 0

            def process_sample(*_args: object) -> adapter.ProcessSample:
                nonlocal call
                position = call % 4
                call += 1
                if position < 2:
                    return adapter.ProcessSample(42, 100, 100, 4096, 1000)
                return adapter.ProcessSample(42, 100, 110, 4096, 1001000)

            metrics = {
                "loaded_cpu_percent",
                "waap_events_per_second",
                "disk_io_bytes_per_event",
            }
            with mock.patch.object(adapter, "_process_sample", side_effect=process_sample):
                for iteration in (1, 2):
                    request = self.request(package, binary, metrics)
                    request.iteration = iteration
                    observed = adapter.measure(config, request)
                    self.assertEqual(observed["disk_io_bytes_per_event"], 100.0)
                    self.assertEqual((root / "waap.jsonl").stat().st_size, 0)

    def test_ambiguous_capture_and_nonpositive_observation_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            capture = root / "capture.jsonl"
            capture.write_text('{"token":"t","timestamp_ns":1}\n{"token":"t","timestamp_ns":2}\n', encoding="utf-8")
            capture.chmod(0o600)
            checkpoint = adapter.CaptureCheckpoint(
                capture,
                (
                    capture.stat().st_dev,
                    capture.stat().st_ino,
                    capture.stat().st_mode,
                    capture.stat().st_nlink,
                    capture.stat().st_uid,
                    capture.stat().st_gid,
                ),
                0,
            )
            self.assertEqual(len(adapter._matching(adapter._capture_records(checkpoint), "t")), 2)
            with self.assertRaisesRegex(adapter.NativePerformanceAdapterError, "positive"):
                adapter._positive(0.0, "measurement")
            self.assertEqual(adapter._nonnegative(0.0, "zero cost"), 0.0)


if __name__ == "__main__":
    unittest.main()
