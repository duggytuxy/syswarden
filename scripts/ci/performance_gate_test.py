#!/usr/bin/env python3
"""Tests for the v4.10.0 performance evidence gate."""

from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import performance_gate as gate
except ModuleNotFoundError:
    import performance_gate as gate


class PerformanceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.metrics = gate.load_contract()
        cls.candidate = "a" * 40

    def evidence(self, factor: float = 1.0) -> dict[str, object]:
        metrics: dict[str, object] = {}
        for name, contract in self.metrics.items():
            campaigns = []
            remaining = contract.minimum_samples
            for index in range(self.contract["minimum_campaigns"]):
                count = max(1, remaining // (self.contract["minimum_campaigns"] - index))
                remaining -= count
                baseline = [100.0 + index + sample / 1000 for sample in range(count)]
                if contract.direction == "lower":
                    candidate = [value * factor for value in baseline]
                else:
                    candidate = [value / factor for value in baseline]
                campaigns.append(
                    {
                        "id": f"campaign-{index + 1}",
                        "recorded_at": f"2026-09-{10 + index:02d}T08:00:00Z",
                        "environment_id": "node02-ubuntu-26.04",
                        "environment_sha256": "b" * 64,
                        "probe_sha256": "c" * 64,
                        "adapter_sha256": "d" * 64,
                        "adapter_config_sha256": "e" * 64,
                        "baseline_samples_sha256": f"{index + 5:x}" * 64,
                        "candidate_samples_sha256": f"{index + 8:x}" * 64,
                        "baseline_binary_sha256": "1" * 64,
                        "candidate_binary_sha256": "2" * 64,
                        "baseline_package_sha256": "3" * 64,
                        "candidate_package_sha256": "4" * 64,
                        "baseline": baseline,
                        "candidate": candidate,
                    }
                )
            metrics[name] = {"unit": contract.unit, "campaigns": campaigns}
        return {
            "schema_version": 2,
            "contract_id": self.contract["contract_id"],
            "target_release": self.contract["target_release"],
            "baseline_release": self.contract["baseline_release"],
            "baseline_commit": self.contract["baseline_commit"],
            "candidate_commit": self.candidate,
            "metrics": metrics,
        }

    def test_complete_evidence_passes_and_reports_distribution(self) -> None:
        report = gate.evaluate(self.evidence(), self.contract, self.metrics, {}, self.candidate)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["failed_metrics"], [])
        self.assertEqual(set(report["metrics"]), set(self.metrics))
        for result in report["metrics"].values():
            self.assertEqual(result["campaign_count"], 3)
            self.assertIn("median", result["baseline"])
            self.assertIn("p95", result["candidate"])
            self.assertFalse(result["stable_regression"])

    def test_report_writer_is_private_independent_of_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            previous_umask = os.umask(0o022)
            try:
                gate._write_report(report, {"verdict": "pass"})
            finally:
                os.umask(previous_umask)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8")),
                {"verdict": "pass"},
            )

    def test_cpu_consumption_metrics_are_lower_is_better(self) -> None:
        self.assertEqual(self.metrics["idle_cpu_percent"].direction, "lower")
        self.assertEqual(self.metrics["loaded_cpu_percent"].direction, "lower")

    def test_real_zero_cost_samples_are_preserved_without_division_by_zero(self) -> None:
        evidence = self.evidence()
        for campaign in evidence["metrics"]["idle_cpu_percent"]["campaigns"]:
            campaign["baseline"] = [0.0] * len(campaign["baseline"])
            campaign["candidate"] = [0.0] * len(campaign["candidate"])
        report = gate.evaluate(
            evidence, self.contract, self.metrics, {}, self.candidate
        )
        self.assertEqual(report["verdict"], "pass")
        self.assertIsNone(
            report["metrics"]["idle_cpu_percent"][
                "aggregate_regression_percent"
            ]
        )
        for campaign in evidence["metrics"]["idle_cpu_percent"]["campaigns"]:
            campaign["candidate"] = [1.0] * len(campaign["candidate"])
        report = gate.evaluate(
            evidence, self.contract, self.metrics, {}, self.candidate
        )
        self.assertIn("idle_cpu_percent", report["failed_metrics"])

    def test_reviewed_probe_adapter_and_config_digests_are_required(self) -> None:
        evidence = self.evidence()
        report = gate.evaluate(
            evidence,
            self.contract,
            self.metrics,
            {},
            self.candidate,
            expected_probe_sha256="c" * 64,
            expected_adapter_sha256="d" * 64,
            expected_adapter_config_sha256="e" * 64,
            expected_baseline_binary_sha256="1" * 64,
            expected_candidate_binary_sha256="2" * 64,
            expected_baseline_package_sha256="3" * 64,
            expected_candidate_package_sha256="4" * 64,
        )
        self.assertEqual(report["verdict"], "pass")
        for key, value in (
            ("expected_probe_sha256", "9" * 64),
            ("expected_adapter_sha256", "8" * 64),
            ("expected_adapter_config_sha256", "7" * 64),
            ("expected_baseline_binary_sha256", "6" * 64),
            ("expected_candidate_binary_sha256", "5" * 64),
            ("expected_baseline_package_sha256", "a" * 64),
            ("expected_candidate_package_sha256", "b" * 64),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                gate.PerformanceGateError, "reviewed input"
            ):
                gate.evaluate(
                    evidence,
                    self.contract,
                    self.metrics,
                    {},
                    self.candidate,
                    **{key: value},
                )

    def test_stable_regression_fails_without_performance_waiver(self) -> None:
        report = gate.evaluate(self.evidence(1.2), self.contract, self.metrics, {}, self.candidate)
        self.assertEqual(report["verdict"], "fail")
        self.assertEqual(set(report["failed_metrics"]), set(self.metrics))
        self.assertTrue(all(item["stable_regression"] for item in report["metrics"].values()))

    def test_one_noisy_campaign_is_not_a_stable_regression(self) -> None:
        evidence = self.evidence()
        name = "loaded_cpu_percent"
        evidence["metrics"][name]["campaigns"][0]["candidate"] = [130.0] * 10
        report = gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)
        self.assertEqual(report["verdict"], "pass")
        self.assertFalse(report["metrics"][name]["stable_regression"])

    def test_waiver_must_be_candidate_bound_complete_and_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "waivers.json"
            waiver = {
                "schema_version": 1,
                "candidate_commit": self.candidate,
                "waivers": {
                    name: {
                        "approved_by": "release-owner",
                        "reason": "Measured size cost is accepted for the bounded candidate.",
                        "evidence": "https://example.invalid/performance-evidence",
                        "expires_on": "2026-09-30",
                    }
                    for name in self.metrics
                },
            }
            path.write_text(json.dumps(waiver), encoding="utf-8")
            loaded = gate._load_waivers(path, self.candidate, gate.dt.date(2026, 9, 3))
            report = gate.evaluate(
                self.evidence(1.2), self.contract, self.metrics, loaded, self.candidate
            )
            self.assertEqual(report["verdict"], "pass")
            self.assertTrue(all(item["waived"] for item in report["metrics"].values()))

            expired = copy.deepcopy(waiver)
            expired["waivers"][next(iter(self.metrics))]["expires_on"] = "2026-09-02"
            path.write_text(json.dumps(expired), encoding="utf-8")
            with self.assertRaisesRegex(gate.PerformanceGateError, "expired"):
                gate._load_waivers(path, self.candidate, gate.dt.date(2026, 9, 3))

    def test_missing_samples_metrics_and_duplicate_json_are_rejected(self) -> None:
        evidence = self.evidence()
        evidence["metrics"]["rss_bytes"]["campaigns"][0]["baseline"] = []
        with self.assertRaisesRegex(gate.PerformanceGateError, "requires at least"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        evidence["metrics"].pop("rss_bytes")
        with self.assertRaisesRegex(gate.PerformanceGateError, "inventory is not exact"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(gate.PerformanceGateError, "duplicate JSON key"):
                gate._load_regular_json(path)

    def test_wrong_binding_nonpositive_nan_and_symlink_are_rejected(self) -> None:
        evidence = self.evidence()
        evidence["candidate_commit"] = "b" * 40
        with self.assertRaisesRegex(gate.PerformanceGateError, "binding is invalid"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        evidence["metrics"]["rss_bytes"]["campaigns"][0]["candidate"][0] = 0
        with self.assertRaisesRegex(gate.PerformanceGateError, "finite and positive"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(gate.PerformanceGateError, "non-finite"):
                gate._load_regular_json(nonfinite)

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(gate.PerformanceGateError, "symbolic link"):
                gate._load_regular_json(link)

    def test_campaign_provenance_and_paired_samples_are_required(self) -> None:
        evidence = self.evidence()
        campaign = evidence["metrics"]["rss_bytes"]["campaigns"][0]
        campaign["environment_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(gate.PerformanceGateError, "environment_sha256"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        campaign = evidence["metrics"]["rss_bytes"]["campaigns"][0]
        campaign["recorded_at"] = "2026-09-10T10:00:00+02:00"
        with self.assertRaisesRegex(gate.PerformanceGateError, "canonical UTC"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        campaign = evidence["metrics"]["rss_bytes"]["campaigns"][0]
        campaign["candidate"].append(1.0)
        with self.assertRaisesRegex(gate.PerformanceGateError, "sample counts differ"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

    def test_campaign_inventory_and_provenance_are_identical_across_metrics(self) -> None:
        evidence = self.evidence()
        evidence["metrics"]["rss_bytes"]["campaigns"][0][
            "candidate_package_sha256"
        ] = "5" * 64
        with self.assertRaisesRegex(
            gate.PerformanceGateError, "provenance differs across metrics"
        ):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

    def test_reviewed_lifecycle_requires_exact_standard_native_profile_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            adapter_config_path = root / "adapter-config.json"
            adapter_config_path.write_text("{}\n", encoding="utf-8")
            adapter_config_path.chmod(0o600)
            lifecycle_path = root / "lifecycle.json"
            lifecycle_path.write_text("{}\n", encoding="utf-8")
            lifecycle_path.chmod(0o600)
            adapter_config = {
                "candidate_commit": self.candidate,
                "subjects": {
                    "baseline": {
                        "release": self.contract["baseline_release"],
                        "artifact_commit": self.contract["baseline_commit"],
                        "binary_path": gate.native_adapter.EXPECTED_BINARY_PATH,
                        "binary_sha256": "1" * 64,
                        "package_sha256": "3" * 64,
                    },
                    "candidate": {
                        "release": self.contract["target_release"],
                        "artifact_commit": self.candidate,
                        "binary_path": gate.native_adapter.EXPECTED_BINARY_PATH,
                        "binary_sha256": "2" * 64,
                        "package_sha256": "4" * 64,
                    },
                },
            }
            lifecycle = {
                "schema": "syswarden-native-package-lifecycle-verdict/v1",
                "repository": "duggytuxy/syswarden",
                "target_release": self.contract["target_release"],
                "candidate_commit": self.candidate,
                "contract_sha256": gate.native_lifecycle.CONTRACT_SHA256,
                "qualification_state": "candidate-not-qualified",
                "publishing": False,
                "status": "pass",
                "profile_count": 3,
                "raw_evidence_count": 87,
                "raw_evidence_inventory_sha256": "5" * 64,
                "profiles": [
                    {
                        "host": {"profile_id": "APK-324"},
                        "packages": [],
                    },
                    {
                        "host": {"profile_id": "DEB-U2604"},
                        "packages": [
                            {
                                "release_tag": self.contract["baseline_release"],
                                "package_sha256": "3" * 64,
                                "producer_commit": self.contract["baseline_commit"],
                                "release_asset_digest_verified": True,
                                "package_payload_verified": True,
                                "verified_before_install": True,
                            },
                            {
                                "release_tag": self.contract["target_release"],
                                "package_sha256": "4" * 64,
                                "producer_commit": self.candidate,
                                "release_asset_digest_verified": True,
                                "package_payload_verified": True,
                                "verified_before_install": True,
                            },
                        ],
                    },
                    {
                        "host": {"profile_id": "RPM-A9"},
                        "packages": [],
                    },
                ],
            }
            with (
                mock.patch.object(
                    gate.native_adapter, "_read_config", return_value=adapter_config
                ),
                mock.patch.object(gate, "_sha256_regular", return_value="6" * 64),
                mock.patch.object(gate, "_load_regular_json", return_value=lifecycle),
            ):
                bindings = gate.reviewed_bindings(
                    adapter_config_path,
                    lifecycle_path,
                    self.candidate,
                    self.contract,
                )
                self.assertEqual(
                    bindings["expected_baseline_package_sha256"], "3" * 64
                )

                for label, mutation in (
                    (
                        "package-owned substitution",
                        lambda item: item["profiles"][2]["host"].__setitem__(
                            "profile_id", "RPM-A9-PACKAGE-OWNED"
                        ),
                    ),
                    (
                        "raw evidence truncation",
                        lambda item: item.__setitem__("raw_evidence_count", 58),
                    ),
                    (
                        "contract substitution",
                        lambda item: item.__setitem__("contract_sha256", "7" * 64),
                    ),
                ):
                    changed = copy.deepcopy(lifecycle)
                    mutation(changed)
                    with self.subTest(case=label), mock.patch.object(
                        gate, "_load_regular_json", return_value=changed
                    ), self.assertRaises(gate.PerformanceGateError):
                        gate.reviewed_bindings(
                            adapter_config_path,
                            lifecycle_path,
                            self.candidate,
                            self.contract,
                        )

    def test_cross_campaign_clones_and_binding_drift_are_rejected(self) -> None:
        evidence = self.evidence()
        for metric in evidence["metrics"].values():
            campaigns = metric["campaigns"]
            campaigns[1]["baseline_samples_sha256"] = campaigns[0]["baseline_samples_sha256"]
        with self.assertRaisesRegex(gate.PerformanceGateError, "reused"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        for metric in evidence["metrics"].values():
            metric["campaigns"][1]["adapter_sha256"] = "9" * 64
        with self.assertRaisesRegex(gate.PerformanceGateError, "binding differs"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        for metric in evidence["metrics"].values():
            metric["campaigns"][1]["adapter_config_sha256"] = "8" * 64
        with self.assertRaisesRegex(gate.PerformanceGateError, "binding differs"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        for metric in evidence["metrics"].values():
            metric["campaigns"][1]["recorded_at"] = metric["campaigns"][0]["recorded_at"]
        with self.assertRaisesRegex(gate.PerformanceGateError, "timestamps"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        metric = evidence["metrics"]["rss_bytes"]
        metric["campaigns"][1]["baseline"] = copy.deepcopy(
            metric["campaigns"][0]["baseline"]
        )
        metric["campaigns"][1]["candidate"] = copy.deepcopy(
            metric["campaigns"][0]["candidate"]
        )
        with self.assertRaisesRegex(gate.PerformanceGateError, "cloned"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        metric = evidence["metrics"]["rss_bytes"]
        metric["campaigns"][0]["baseline"] = [100.0] * 28
        metric["campaigns"][0]["candidate"] = [100.0] * 28
        metric["campaigns"][1]["baseline"] = [101.0]
        metric["campaigns"][1]["candidate"] = [101.0]
        metric["campaigns"][2]["baseline"] = [102.0]
        metric["campaigns"][2]["candidate"] = [102.0]
        with self.assertRaisesRegex(gate.PerformanceGateError, "exactly 10"):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)

        evidence = self.evidence()
        size_metric = evidence["metrics"]["binary_bytes"]
        for campaign in size_metric["campaigns"]:
            campaign["baseline"] = [100.0]
            campaign["candidate"] = [100.0]
        install_metric = evidence["metrics"]["install_milliseconds"]
        for campaign in install_metric["campaigns"]:
            campaign["baseline"] = [100.0]
            campaign["candidate"] = [100.0]
        self.assertEqual(
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)["verdict"],
            "pass",
        )

        evidence = self.evidence()
        evidence["metrics"]["rss_bytes"]["campaigns"][0]["id"] = "campaign-4"
        with self.assertRaisesRegex(
            gate.PerformanceGateError, "inventory differs across metrics"
        ):
            gate.evaluate(evidence, self.contract, self.metrics, {}, self.candidate)


if __name__ == "__main__":
    unittest.main()
