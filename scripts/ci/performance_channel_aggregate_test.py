#!/usr/bin/env python3
"""Tests for the two-channel v4.10.0 performance aggregate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import performance_channel_aggregate as aggregate
    from scripts.ci import performance_gate as native_gate
    from scripts.ci import source_allocation_gate as allocation_gate
except ModuleNotFoundError:
    import performance_channel_aggregate as aggregate
    import performance_gate as native_gate
    import source_allocation_gate as allocation_gate


REPOSITORY = Path(__file__).resolve().parents[2]
CANDIDATE = "a" * 40


def _wire(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


class PerformanceChannelAggregateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        native_contract, _ = native_gate.load_contract()
        cls.native_contract = copy.deepcopy(native_contract)
        cls.native_contract["metrics"].pop("allocations_per_event", None)
        cls.allocation_contract = allocation_gate.load_contract()

    def native_evidence(self) -> dict[str, object]:
        metrics: dict[str, object] = {}
        for name, definition in self.native_contract["metrics"].items():
            campaigns: list[dict[str, object]] = []
            remaining = definition["minimum_samples"]
            for index in range(self.native_contract["minimum_campaigns"]):
                count = max(
                    1,
                    remaining
                    // (self.native_contract["minimum_campaigns"] - index),
                )
                remaining -= count
                baseline = [100.0 + index + sample / 1000 for sample in range(count)]
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
                        "candidate": list(baseline),
                    }
                )
            metrics[name] = {"unit": definition["unit"], "campaigns": campaigns}
        return {
            "schema_version": 2,
            "contract_id": self.native_contract["contract_id"],
            "target_release": "v4.10.0",
            "baseline_release": "v4.04.3",
            "baseline_commit": self.native_contract["baseline_commit"],
            "candidate_commit": CANDIDATE,
            "metrics": metrics,
        }

    def allocation_evidence(self) -> dict[str, object]:
        positions = [
            (campaign, sample)
            for campaign in self.allocation_contract["campaigns"]
            for sample in range(1, 11)
        ]
        values = [
            {
                "campaign_id": campaign,
                "sample_index": sample,
                "raw_numerator": "2048",
                "raw_denominator": "2048",
                "numerator": "1",
                "denominator": "1",
            }
            for campaign, sample in positions
        ]
        metrics = {
            name: {
                "unit": definition["unit"],
                "direction": "lower",
                "baseline": copy.deepcopy(values),
                "candidate": copy.deepcopy(values),
            }
            for name, definition in self.allocation_contract["metrics"].items()
        }
        return {
            "schema_version": 1,
            "schema_id": "syswarden-allocation-evidence/v1",
            "repository": "duggytuxy/syswarden",
            "target_release": "v4.10.0",
            "candidate_commit": CANDIDATE,
            "baseline_release": "v4.04.3",
            "baseline_commit": self.allocation_contract["baseline_commit"],
            "measurement_scope": "deterministic-source-bound-waap-engine-scan",
            "native_package_runtime_measurement": False,
            "bindings": {},
            "subjects": {},
            "campaigns": [],
            "raw_inventory": [],
            "metrics": metrics,
        }

    def documents(self) -> tuple[dict[str, object], ...]:
        native_evidence = self.native_evidence()
        metric_contracts = {
            name: native_gate.MetricContract(
                unit=value["unit"],
                direction=value["direction"],
                minimum_samples=value["minimum_samples"],
            )
            for name, value in self.native_contract["metrics"].items()
        }
        native_report = native_gate.evaluate(
            native_evidence,
            self.native_contract,
            metric_contracts,
            {},
            CANDIDATE,
        )
        allocation_evidence = self.allocation_evidence()
        allocation_evidence_raw = _wire(allocation_evidence)
        allocation_report = allocation_gate.build_report(
            contract=self.allocation_contract,
            candidate_commit=CANDIDATE,
            evidence=allocation_evidence,
            evidence_sha256=hashlib.sha256(allocation_evidence_raw).hexdigest(),
        )
        return (
            native_evidence,
            native_report,
            allocation_evidence,
            allocation_report,
        )

    def call_aggregate(
        self,
        *,
        native_contract: dict[str, object] | None = None,
        native_report_mutation: tuple[str, object] | None = None,
        allocation_report_mutation: tuple[str, object] | None = None,
    ) -> dict[str, object]:
        native_evidence, native_report, allocation_evidence, allocation_report = (
            self.documents()
        )
        if native_report_mutation is not None:
            native_report[native_report_mutation[0]] = native_report_mutation[1]
        if allocation_report_mutation is not None:
            allocation_report[allocation_report_mutation[0]] = (
                allocation_report_mutation[1]
            )
        selected_native = native_contract or self.native_contract
        return aggregate.aggregate(
            selected_native,
            _wire(selected_native),
            self.allocation_contract,
            _wire(self.allocation_contract),
            native_evidence,
            _wire(native_evidence),
            native_report,
            _wire(native_report),
            allocation_evidence,
            _wire(allocation_evidence),
            allocation_report,
            _wire(allocation_report),
            CANDIDATE,
            {
                "expected_probe_sha256": "c" * 64,
                "expected_adapter_sha256": "d" * 64,
                "expected_adapter_config_sha256": "e" * 64,
                "expected_baseline_binary_sha256": "1" * 64,
                "expected_candidate_binary_sha256": "2" * 64,
                "expected_baseline_package_sha256": "3" * 64,
                "expected_candidate_package_sha256": "4" * 64,
            },
        )

    def test_both_independent_passing_channels_are_required(self) -> None:
        result = self.call_aggregate()
        self.assertEqual(result["verdict"], "pass")
        self.assertTrue(result["channels_independent"])
        self.assertTrue(result["neither_channel_substitutes_for_other"])
        self.assertEqual(
            set(result["channels"]),
            {"native_package", "source_bound_allocations"},
        )
        self.assertEqual(result["channels"]["native_package"]["verdict"], "pass")
        self.assertEqual(
            result["channels"]["source_bound_allocations"]["verdict"], "pass"
        )

    def test_native_contract_must_not_retain_synthetic_allocation_metric(self) -> None:
        contract = copy.deepcopy(self.native_contract)
        contract["metrics"]["allocations_per_event"] = {
            "unit": "count",
            "direction": "lower",
            "minimum_samples": 30,
        }
        with self.assertRaisesRegex(
            aggregate.PerformanceAggregateError, "unobservable allocations_per_event"
        ):
            self.call_aggregate(native_contract=contract)

    def test_reports_must_reproduce_exactly_from_evidence(self) -> None:
        with self.assertRaisesRegex(
            aggregate.PerformanceAggregateError, "native performance report"
        ):
            self.call_aggregate(native_report_mutation=("verdict", "fail"))
        with self.assertRaisesRegex(
            aggregate.PerformanceAggregateError, "source allocation report"
        ):
            self.call_aggregate(allocation_report_mutation=("verdict", "fail"))

    def test_source_evidence_digest_is_mandatory(self) -> None:
        with self.assertRaisesRegex(
            aggregate.PerformanceAggregateError, "exact evidence bytes"
        ):
            self.call_aggregate(
                allocation_report_mutation=("evidence_sha256", "0" * 64)
            )

    def test_cli_creates_once_with_private_mode(self) -> None:
        native_evidence, native_report, allocation_evidence, allocation_report = (
            self.documents()
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths = {
                "native_contract": root / "native-contract.json",
                "allocation_contract": root / "allocation-contract.json",
                "native_evidence": root / "native-evidence.json",
                "native_report": root / "native-report.json",
                "allocation_evidence": root / "allocation-evidence.json",
                "allocation_report": root / "allocation-report.json",
                "adapter_config": root / "adapter-config.json",
                "lifecycle_verdict": root / "lifecycle-verdict.json",
            }
            documents = {
                "native_contract": self.native_contract,
                "allocation_contract": self.allocation_contract,
                "native_evidence": native_evidence,
                "native_report": native_report,
                "allocation_evidence": allocation_evidence,
                "allocation_report": allocation_report,
            }
            for name, path in paths.items():
                if name in documents:
                    path.write_bytes(_wire(documents[name]))
                else:
                    path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o644 if name.endswith("contract") else 0o600)
            output = root / "aggregate.json"
            arguments = [
                "--native-contract", str(paths["native_contract"]),
                "--allocation-contract", str(paths["allocation_contract"]),
                "--native-evidence", str(paths["native_evidence"]),
                "--native-report", str(paths["native_report"]),
                "--allocation-evidence", str(paths["allocation_evidence"]),
                "--allocation-report", str(paths["allocation_report"]),
                "--adapter-config", str(paths["adapter_config"]),
                "--native-lifecycle-verdict", str(paths["lifecycle_verdict"]),
                "--candidate-commit", CANDIDATE,
                "--output", str(output),
            ]
            bindings = {
                "expected_probe_sha256": "c" * 64,
                "expected_adapter_sha256": "d" * 64,
                "expected_adapter_config_sha256": "e" * 64,
                "expected_baseline_binary_sha256": "1" * 64,
                "expected_candidate_binary_sha256": "2" * 64,
                "expected_baseline_package_sha256": "3" * 64,
                "expected_candidate_package_sha256": "4" * 64,
            }
            with mock.patch.object(
                aggregate.native_gate, "reviewed_bindings", return_value=bindings
            ):
                self.assertEqual(aggregate.main(arguments), 0)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            with mock.patch.object(
                aggregate.native_gate, "reviewed_bindings", return_value=bindings
            ):
                self.assertEqual(aggregate.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
