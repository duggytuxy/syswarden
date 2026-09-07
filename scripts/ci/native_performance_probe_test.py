#!/usr/bin/env python3
"""Adversarial tests for the native v4.10.0 performance probe."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_performance_probe as probe
except ModuleNotFoundError:
    import native_performance_probe as probe


ADAPTER = """#!/usr/bin/env python3
import argparse, json
p=argparse.ArgumentParser()
p.add_argument('--candidate-commit', required=True)
p.add_argument('--baseline-commit', required=True)
p.add_argument('--campaign-id', required=True)
p.add_argument('--recorded-at', required=True)
p.add_argument('--subject-role', required=True)
p.add_argument('--subject-release', required=True)
p.add_argument('--iteration', required=True, type=int)
p.add_argument('--metrics', required=True)
p.add_argument('--config-fd', required=True)
p.add_argument('--config-sha256', required=True)
p.add_argument('--package-path', required=True)
p.add_argument('--package-sha256', required=True)
p.add_argument('--binary-path', required=True)
a=p.parse_args()
names=a.metrics.split(',') if a.metrics else []
print(json.dumps({'schema_version':2,'candidate_commit':a.candidate_commit,'campaign_id':a.campaign_id,'recorded_at':a.recorded_at,'subject_role':a.subject_role,'subject_release':a.subject_release,'iteration':a.iteration,'metrics':{name:float(a.iteration) for name in names}}))
"""


class NativePerformanceProbeTests(unittest.TestCase):
    candidate = "a" * 40

    def fixture(self, root: Path, body: str | None = None) -> tuple[Path, Path, Path]:
        adapter = root / "adapter"
        adapter.write_text(
            (body if body is not None else ADAPTER),
            encoding="utf-8",
        )
        adapter.chmod(0o700)
        binary = root / "syswarden"
        package = root / "syswarden.pkg"
        binary.write_bytes(b"binary-bytes")
        package.write_bytes(b"package-bytes")
        binary.chmod(0o600)
        package.chmod(0o600)
        return adapter, binary, package

    @staticmethod
    def dynamic_metrics() -> set[str]:
        _, metrics = probe.gate.load_contract()
        return set(metrics) - probe.SIZE_METRICS

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def collect(self, adapter: Path, binary: Path, package: Path, **changes: object) -> dict[str, object]:
        adapter_config = adapter.parent / "adapter-config.json"
        if not adapter_config.exists():
            adapter_config.write_text('{"schema_version":1}\n', encoding="utf-8")
            adapter_config.chmod(0o600)
        arguments: dict[str, object] = {
            "candidate_commit": self.candidate,
            "campaign_id": "campaign-1",
            "recorded_at": "2026-09-10T08:00:00Z",
            "subject_role": "candidate",
            "adapter": adapter,
            "adapter_sha256": self.digest(adapter),
            "adapter_config": adapter_config,
            "adapter_config_sha256": self.digest(adapter_config),
            "binary": binary,
            "package": package,
            "runs": 10,
            "timeout_seconds": 10,
        }
        arguments.update(changes)
        return probe.collect(**arguments)  # type: ignore[arg-type]

    def test_collects_exact_real_sample_shape_and_independent_sizes(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            adapter, binary, package = self.fixture(Path(directory))
            document = self.collect(adapter, binary, package)
            _, contracts = probe.gate.load_contract()
            self.assertEqual(set(document["metrics"]), set(contracts))
            self.assertEqual(document["subject_role"], "candidate")
            self.assertEqual(document["subject_release"], "v4.10.0")
            self.assertEqual(document["schema_version"], 2)
            self.assertEqual(document["adapter_config_sha256"], self.digest(adapter.parent / "adapter-config.json"))
            self.assertEqual(document["campaign_id"], "campaign-1")
            self.assertEqual(document["recorded_at"], "2026-09-10T08:00:00Z")
            self.assertEqual(document["metrics"]["idle_cpu_percent"]["samples"], [float(i) for i in range(1, 11)])
            self.assertEqual(document["metrics"]["loaded_cpu_percent"]["samples"], [float(i) for i in range(1, 11)])
            self.assertEqual(document["metrics"]["install_milliseconds"]["samples"], [1.0])
            self.assertEqual(document["metrics"]["binary_bytes"]["samples"], [12.0])
            self.assertEqual(document["metrics"]["package_bytes"]["samples"], [13.0])

            baseline = self.collect(
                adapter, binary, package, subject_role="baseline"
            )
            self.assertEqual(baseline["subject_release"], "v4.04.3")

    def test_adapter_sha_mode_owner_link_and_path_attestation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter, binary, package = self.fixture(root)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "mismatch"):
                self.collect(adapter, binary, package, adapter_sha256="b" * 64)
            adapter.chmod(0o722)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "unsafe"):
                self.collect(adapter, binary, package)
            adapter.chmod(0o755)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "0700"):
                self.collect(adapter, binary, package)
            adapter.chmod(0o700)
            os.link(adapter, root / "adapter-hardlink")
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "regular"):
                self.collect(adapter, binary, package)

    def test_adapter_path_replacement_between_inspection_and_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter, _, _ = self.fixture(root)
            expected = self.digest(adapter)
            original = probe._regular

            def replace_after_inspection(path: Path, *, executable: bool = False) -> os.stat_result:
                observed = original(path, executable=executable)
                replacement = root / "replacement"
                replacement.write_text(ADAPTER, encoding="utf-8")
                replacement.chmod(0o700)
                os.replace(replacement, path)
                return observed

            with mock.patch.object(probe, "_regular", side_effect=replace_after_inspection):
                with self.assertRaisesRegex(probe.NativePerformanceProbeError, "changed"):
                    probe._open_attested_adapter(adapter, expected)

    def test_response_binding_inventory_duplicates_and_values_are_rejected(self) -> None:
        templates = (
            "#!/bin/sh\nprintf '%%s\\n' '{\"schema_version\":2,\"schema_version\":2}'\n",
            "#!/bin/sh\nprintf '%%s\\n' '{\"schema_version\":2,\"candidate_commit\":\"%s\",\"iteration\":1,\"metrics\":{}}'\n" % self.candidate,
            "#!/bin/sh\nprintf '%%s\\n' '{\"schema_version\":2,\"candidate_commit\":\"%s\",\"iteration\":1,\"metrics\":{\"idle_cpu_percent\":0}}'\n" % self.candidate,
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            for index, body in enumerate(templates):
                case = root / str(index)
                case.mkdir()
                adapter, binary, package = self.fixture(case, body)
                with self.assertRaises(probe.NativePerformanceProbeError):
                    self.collect(adapter, binary, package)

    def test_metric_request_is_canonical_and_response_inventory_is_exact(self) -> None:
        strict_adapter = r"""#!/usr/bin/env python3
import argparse, json, sys
p=argparse.ArgumentParser()
p.add_argument('--candidate-commit', required=True)
p.add_argument('--baseline-commit', required=True)
p.add_argument('--campaign-id', required=True)
p.add_argument('--recorded-at', required=True)
p.add_argument('--subject-role', required=True)
p.add_argument('--subject-release', required=True)
p.add_argument('--iteration', required=True, type=int)
p.add_argument('--metrics', required=True)
p.add_argument('--config-fd', required=True)
p.add_argument('--config-sha256', required=True)
p.add_argument('--package-path', required=True)
p.add_argument('--package-sha256', required=True)
p.add_argument('--binary-path', required=True)
a=p.parse_args()
names=a.metrics.split(',') if a.metrics else []
if names != sorted(set(names)):
    sys.exit(9)
if (a.iteration == 1) != ('install_milliseconds' in names):
    sys.exit(10)
print(json.dumps({'schema_version':2,'candidate_commit':a.candidate_commit,'campaign_id':a.campaign_id,'recorded_at':a.recorded_at,'subject_role':a.subject_role,'subject_release':a.subject_release,'iteration':a.iteration,'metrics':{name:float(a.iteration) for name in names}}))
"""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            adapter, binary, package = self.fixture(Path(directory), strict_adapter)
            document = self.collect(adapter, binary, package)
            self.assertEqual(
                document["metrics"]["install_milliseconds"]["samples"], [1.0]
            )

        for mutation in ("extra", "missing", "campaign"):
            adversarial_adapter = strict_adapter.replace(
                "print(json.dumps(",
                (
                    "names.append('unexpected_metric')\nprint(json.dumps("
                    if mutation == "extra"
                    else "names = names[:-1]\nprint(json.dumps("
                    if mutation == "missing"
                    else "a.campaign_id = 'other-campaign'\nprint(json.dumps("
                ),
            )
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                dir="/tmp"
            ) as directory:
                adapter, binary, package = self.fixture(
                    Path(directory), adversarial_adapter
                )
                with self.assertRaises(probe.NativePerformanceProbeError):
                    self.collect(adapter, binary, package)

    def test_oversized_adapter_output_is_rejected_without_pipe_buffering(self) -> None:
        oversized = """#!/usr/bin/env python3
import sys
sys.stdout.write('x' * 70000)
"""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            adapter, binary, package = self.fixture(Path(directory), oversized)
            with self.assertRaisesRegex(
                probe.NativePerformanceProbeError, "rejected|outside bounds"
            ):
                self.collect(adapter, binary, package)

    def test_workload_file_larger_than_output_limit_is_not_restricted(self) -> None:
        workload_writer = r"""#!/usr/bin/env python3
import argparse, json, os
p=argparse.ArgumentParser()
p.add_argument('--candidate-commit', required=True)
p.add_argument('--baseline-commit', required=True)
p.add_argument('--campaign-id', required=True)
p.add_argument('--recorded-at', required=True)
p.add_argument('--subject-role', required=True)
p.add_argument('--subject-release', required=True)
p.add_argument('--iteration', required=True, type=int)
p.add_argument('--metrics', required=True)
p.add_argument('--config-fd', required=True)
p.add_argument('--config-sha256', required=True)
p.add_argument('--package-path', required=True)
p.add_argument('--package-sha256', required=True)
p.add_argument('--binary-path', required=True)
a=p.parse_args()
with open(os.environ['WORKLOAD_FILE'], 'wb') as stream:
    stream.write(b'w' * 131072)
names=a.metrics.split(',') if a.metrics else []
print(json.dumps({'schema_version':2,'candidate_commit':a.candidate_commit,'campaign_id':a.campaign_id,'recorded_at':a.recorded_at,'subject_role':a.subject_role,'subject_release':a.subject_release,'iteration':a.iteration,'metrics':{name:float(a.iteration) for name in names}}))
"""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter, binary, package = self.fixture(root, workload_writer)
            workload_file = root / "workload.bin"
            original_popen = probe.subprocess.Popen

            def with_workload_file(*args: object, **kwargs: object) -> probe.subprocess.Popen[bytes]:
                environment = dict(kwargs["env"])
                environment["WORKLOAD_FILE"] = str(workload_file)
                kwargs["env"] = environment
                return original_popen(*args, **kwargs)

            with mock.patch.object(
                probe.subprocess, "Popen", side_effect=with_workload_file
            ):
                self.collect(adapter, binary, package)
            self.assertEqual(workload_file.stat().st_size, 131072)

    def test_persistent_adapter_descendant_is_killed_and_rejected(self) -> None:
        persistent = r"""#!/usr/bin/env python3
import argparse, json, os, subprocess
p=argparse.ArgumentParser()
p.add_argument('--candidate-commit', required=True)
p.add_argument('--baseline-commit', required=True)
p.add_argument('--campaign-id', required=True)
p.add_argument('--recorded-at', required=True)
p.add_argument('--subject-role', required=True)
p.add_argument('--subject-release', required=True)
p.add_argument('--iteration', required=True, type=int)
p.add_argument('--metrics', required=True)
p.add_argument('--config-fd', required=True)
p.add_argument('--config-sha256', required=True)
p.add_argument('--package-path', required=True)
p.add_argument('--package-sha256', required=True)
p.add_argument('--binary-path', required=True)
a=p.parse_args()
child=subprocess.Popen(['/usr/bin/sleep','60'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
open(os.environ['PID_FILE'], 'w').write(str(child.pid))
names=a.metrics.split(',') if a.metrics else []
print(json.dumps({'schema_version':2,'candidate_commit':a.candidate_commit,'campaign_id':a.campaign_id,'recorded_at':a.recorded_at,'subject_role':a.subject_role,'subject_release':a.subject_release,'iteration':a.iteration,'metrics':{name:float(a.iteration) for name in names}}))
"""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter, binary, package = self.fixture(root, persistent)
            pid_file = root / "child.pid"
            original_popen = probe.subprocess.Popen

            def with_pid_file(*args: object, **kwargs: object) -> probe.subprocess.Popen[bytes]:
                environment = dict(kwargs["env"])
                environment["PID_FILE"] = str(pid_file)
                kwargs["env"] = environment
                return original_popen(*args, **kwargs)

            with mock.patch.object(probe.subprocess, "Popen", side_effect=with_pid_file):
                with self.assertRaisesRegex(
                    probe.NativePerformanceProbeError, "persistent descendants"
                ):
                    self.collect(adapter, binary, package)
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            for _ in range(50):
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                os.kill(child_pid, signal.SIGKILL)
                self.fail("persistent adapter descendant was not killed")

    def test_candidate_run_bounds_and_new_private_output_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter, binary, package = self.fixture(root)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "equal 10"):
                self.collect(adapter, binary, package, runs=9)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "equal 10"):
                self.collect(adapter, binary, package, runs=11)
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "canonical"):
                self.collect(adapter, binary, package, candidate_commit="main")
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "campaign"):
                self.collect(adapter, binary, package, campaign_id="Bad Campaign")
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "UTC"):
                self.collect(adapter, binary, package, recorded_at="2026-09-10T10:00:00+02:00")
            output = root / "samples.json"
            probe._write_new_json(output, self.collect(adapter, binary, package))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                set(json.loads(output.read_text())["metrics"]),
                set(probe.gate.load_contract()[1]),
            )
            with self.assertRaisesRegex(probe.NativePerformanceProbeError, "already exists"):
                probe._write_new_json(output, {})


if __name__ == "__main__":
    unittest.main()
