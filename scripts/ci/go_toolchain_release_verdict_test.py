#!/usr/bin/env python3
"""Adversarial tests for the Go toolchain release verdict."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/ci/go_toolchain_release_verdict.py"
METADATA = ROOT / "scripts/ci/go_toolchain_evaluation.json"


class GoToolchainReleaseVerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        metadata = json.loads(METADATA.read_text())
        self.sha = "a" * 40
        self.evidence = self.root / "evaluation.json"
        binaries = {
            role: {name: {"bytes": 100, "sha256": "b" * 64, "reproducible": True}
                   for name in ("syswarden-cli", "syswarden-core", "syswarden-tui")}
            for role in ("baseline", "candidate")
        }
        packages = {
            role: {name: {"bytes": 100, "sha256": "d" * 64}
                   for name in ("deb", "rpm", "apk")}
            for role in ("baseline", "candidate")
        }
        def comparison(name: str, value: float, samples: bool = False) -> dict:
            bound = metadata["measurement"]["bounds"][name]
            limit = (
                value * 1.1 + bound["absolute_noise_allowance"]
                if bound["direction"] == "lower"
                else value * 0.9 - bound["absolute_noise_allowance"]
            )
            record = {
                "unit": bound["unit"],
                "direction": bound["direction"],
                "baseline_median": value,
                "candidate_median": value,
                "regression_percent": 0.0,
                "maximum_regression_percent": 10.0,
                "absolute_noise_allowance": bound["absolute_noise_allowance"],
                "candidate_limit": limit,
                "status": "pass",
            }
            if samples:
                record["baseline_samples"] = [value] * 9
                record["candidate_samples"] = [value] * 9
            return record

        measurements = {
            name: comparison(name, 100.0, samples=True)
            for name in (
                "cpu_nanoseconds_per_request",
                "rss_bytes",
                "allocations_per_request",
                "allocated_bytes_per_request",
                "http_requests_per_second",
            )
        }
        size_comparisons = {
            group: {
                "items": {name: comparison(bound, 100.0) for name in names},
                "total": comparison(bound, 300.0),
            }
            for group, bound, names in (
                (
                    "binaries",
                    "binary_bytes",
                    ("syswarden-cli", "syswarden-core", "syswarden-tui"),
                ),
                ("packages", "package_bytes", ("deb", "rpm", "apk")),
            )
        }
        document = {
            "schema_version": 2, "contract_id": "syswarden-go-toolchain-evaluation/v2",
            "candidate_commit": self.sha, "architecture": "linux/amd64",
            "runner": {"os": "Linux", "arch": "X64"},
            "metadata_sha256": hashlib.sha256(METADATA.read_bytes()).hexdigest(),
            "toolchains": metadata["toolchains"],
            "gates": {name: "pass" for name in ("tests", "race", "vet", "stdversion", "fuzz", "goroutineleak", "jsonv2", "jsonv1_rollback", "source_unchanged", "protocol_parity", "performance_bounds", "binary_size_bounds", "package_size_bounds", "toolchain_rollback")},
            "protocols": {role: {name: "pass" for name in metadata["measurement"]["protocols"]} for role in ("baseline", "candidate")},
            "measurements": measurements, "size_comparisons": size_comparisons,
            "binaries": binaries, "packages": packages,
            "rollback": {"schema_version": 1, **metadata["rollback"], "source_byte_exact": True, "builder_pin_verified": True, "baseline_protocol_tests": "pass"},
            "native_qualification": "pending-external-evidence",
            "adoption_decision": "defer-go1.27-keep-go1.26.6",
        }
        self.evidence.write_text(json.dumps(document))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_gate(self, *extra: str) -> subprocess.CompletedProcess[str]:
        output = self.root / "verdict.json"
        arguments = ["python3", str(GATE), "--evidence", str(self.evidence),
            "--metadata", str(METADATA), "--release-sha", self.sha,
            "--release-tag", "v4.10.0", "--pinned-toolchain", "go1.26.6",
            "--repository", "duggytuxy/syswarden", "--run-id", "7",
            "--artifact-id", "8", "--artifact-name", f"syswarden-go127-evaluation-{self.sha}",
            "--artifact-digest", "sha256:" + "c" * 64, "--output", str(output)]
        arguments.extend(extra)
        return subprocess.run(arguments, text=True, capture_output=True)

    def test_deferment_is_explicit_and_bound(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        verdict = json.loads((self.root / "verdict.json").read_text())
        self.assertEqual(verdict["decision"], "defer-go1.27-keep-go1.26.6")
        self.assertEqual(verdict["artifact_id"], 8)

    def test_pending_evidence_with_failed_gate_is_rejected(self) -> None:
        document = json.loads(self.evidence.read_text())
        document["gates"]["race"] = "fail"
        self.evidence.write_text(json.dumps(document))
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_sha_and_artifact_mismatch_are_rejected(self) -> None:
        self.assertNotEqual(self.run_gate("--artifact-name", "wrong").returncode, 0)

    def test_unrelated_pinned_toolchain_is_rejected(self) -> None:
        self.assertNotEqual(self.run_gate("--pinned-toolchain", "go1.28.0").returncode, 0)

    def test_candidate_pin_is_rejected_without_bound_native_evidence(self) -> None:
        self.assertNotEqual(
            self.run_gate("--pinned-toolchain", "go1.27.1").returncode,
            0,
        )

    def test_forged_adoption_and_measurement_are_rejected(self) -> None:
        document = json.loads(self.evidence.read_text())
        document["adoption_decision"] = "adopt-go1.27.1"
        self.evidence.write_text(json.dumps(document))
        self.assertNotEqual(self.run_gate().returncode, 0)
        document["adoption_decision"] = "defer-go1.27-keep-go1.26.6"
        document["measurements"]["rss_bytes"]["candidate_median"] = 1.0
        self.evidence.write_text(json.dumps(document))
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_duplicate_json_key_is_rejected(self) -> None:
        wire = self.evidence.read_text()
        self.evidence.write_text(wire.replace('{"schema_version": 1,', '{"schema_version": 1, "schema_version": 1,'))
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_metadata_nested_mutation_is_rejected(self) -> None:
        metadata = self.root / "metadata.json"
        document = json.loads(METADATA.read_text())
        document["toolchains"]["baseline"]["url"] = "https://example.invalid/go.tar.gz"
        metadata.write_text(json.dumps(document))
        self.assertNotEqual(self.run_gate("--metadata", str(metadata)).returncode, 0)

    def test_output_overwrite_is_rejected(self) -> None:
        (self.root / "verdict.json").write_text("occupied")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_hardlinked_evidence_is_rejected(self) -> None:
        linked = self.root / "linked.json"
        linked.hardlink_to(self.evidence)
        self.assertNotEqual(self.run_gate().returncode, 0)


if __name__ == "__main__":
    unittest.main()
