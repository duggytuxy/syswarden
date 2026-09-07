#!/usr/bin/env python3
"""Tests for the candidate-bound performance campaign assembler."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    from scripts.ci import performance_evidence as evidence
    from scripts.ci import performance_gate as gate
except ModuleNotFoundError:
    import performance_evidence as evidence
    import performance_gate as gate


class PerformanceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.metrics = gate.load_contract()
        cls.candidate = "a" * 40

    def sample_document(
        self,
        subject_role: str,
        factor: float = 1.0,
        campaign_id: str = "campaign-1",
        recorded_at: str = "2026-09-10T08:00:00Z",
    ) -> dict[str, object]:
        subject_release = (
            self.contract["baseline_release"]
            if subject_role == "baseline"
            else self.contract["target_release"]
        )
        return {
            "schema_version": 2,
            "schema_id": evidence.SAMPLE_CONTRACT_ID,
            "contract_id": self.contract["contract_id"],
            "target_release": self.contract["target_release"],
            "baseline_release": self.contract["baseline_release"],
            "candidate_commit": self.candidate,
            "campaign_id": campaign_id,
            "recorded_at": recorded_at,
            "subject_role": subject_role,
            "subject_release": subject_release,
            "adapter_sha256": "d" * 64,
            "adapter_config_sha256": "e" * 64,
            "binary_sha256": ("1" if subject_role == "baseline" else "2") * 64,
            "package_sha256": ("3" if subject_role == "baseline" else "4") * 64,
            "metrics": {
                name: {
                    "unit": metric.unit,
                    "samples": [
                        factor * (100.0 + index / 1000)
                        for index in range(
                            (metric.minimum_samples + self.contract["minimum_campaigns"] - 1)
                            // self.contract["minimum_campaigns"]
                        )
                    ],
                }
                for name, metric in self.metrics.items()
            },
        }

    def make_campaign(self, root: Path, index: int) -> Path:
        campaign_id = f"campaign-{index}"
        recorded_at = f"2026-09-{9 + index:02d}T08:00:00Z"
        environment = root / f"environment-{index}.json"
        probe = root / f"probe-{index}.sh"
        baseline = root / f"baseline-{index}.json"
        candidate = root / f"candidate-{index}.json"
        environment.write_text('{"host":"node02","kernel":"attested"}\n', encoding="utf-8")
        probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        baseline.write_text(
            json.dumps(
                self.sample_document(
                    "baseline",
                    1.0 + index / 1000,
                    campaign_id,
                    recorded_at,
                )
            ),
            encoding="utf-8",
        )
        candidate.write_text(
            json.dumps(
                self.sample_document(
                    "candidate",
                    1.0 + index / 1000,
                    campaign_id,
                    recorded_at,
                )
            ),
            encoding="utf-8",
        )
        document = evidence.build_campaign(
            candidate_commit=self.candidate,
            identifier=campaign_id,
            recorded_at=recorded_at,
            environment_id="node02-ubuntu-26.04",
            environment_attestation=environment,
            probe=probe,
            baseline_samples=baseline,
            candidate_samples=candidate,
        )
        path = root / f"campaign-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_campaigns_assemble_deterministically_and_pass_gate(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            paths = [self.make_campaign(root, index) for index in (3, 1, 2)]
            document, report = evidence.assemble_evidence(
                candidate_commit=self.candidate, campaigns=paths
            )
            self.assertEqual(report["verdict"], "pass")
            self.assertEqual(
                [item["id"] for item in document["metrics"]["rss_bytes"]["campaigns"]],
                ["campaign-1", "campaign-2", "campaign-3"],
            )
            self.assertEqual(
                document["metrics"]["rss_bytes"]["campaigns"][0]["baseline"],
                document["metrics"]["rss_bytes"]["campaigns"][0]["candidate"],
            )

    def test_sample_inventory_units_and_pairing_are_exact(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            environment = root / "environment"
            probe = root / "probe"
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            environment.write_text("attested\n", encoding="utf-8")
            probe.write_text("probe\n", encoding="utf-8")
            samples = self.sample_document("baseline")
            samples["metrics"].pop("rss_bytes")
            baseline.write_text(json.dumps(samples), encoding="utf-8")
            candidate.write_text(json.dumps(self.sample_document("candidate")), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "inventory"):
                evidence.build_campaign(
                    candidate_commit=self.candidate,
                    identifier="campaign-1",
                    recorded_at="2026-09-10T08:00:00Z",
                    environment_id="node02-ubuntu-26.04",
                    environment_attestation=environment,
                    probe=probe,
                    baseline_samples=baseline,
                    candidate_samples=candidate,
                )

            samples = self.sample_document("baseline")
            samples["metrics"]["rss_bytes"]["samples"].append(1.0)
            baseline.write_text(json.dumps(samples), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "counts differ"):
                evidence.build_campaign(
                    candidate_commit=self.candidate,
                    identifier="campaign-1",
                    recorded_at="2026-09-10T08:00:00Z",
                    environment_id="node02-ubuntu-26.04",
                    environment_attestation=environment,
                    probe=probe,
                    baseline_samples=baseline,
                    candidate_samples=candidate,
                )

            baseline.write_text(
                json.dumps(self.sample_document("candidate")), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                evidence.PerformanceEvidenceError, "subject_role binding"
            ):
                evidence.build_campaign(
                    candidate_commit=self.candidate,
                    identifier="campaign-1",
                    recorded_at="2026-09-10T08:00:00Z",
                    environment_id="node02-ubuntu-26.04",
                    environment_attestation=environment,
                    probe=probe,
                    baseline_samples=baseline,
                    candidate_samples=candidate,
                )

    def test_campaign_binding_duplicate_id_and_tamper_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            paths = [self.make_campaign(root, index) for index in (1, 2, 3)]
            tampered = json.loads(paths[1].read_text(encoding="utf-8"))
            tampered["candidate_commit"] = "b" * 40
            paths[1].write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "binding"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

    def test_sample_campaign_identity_and_timestamp_are_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            environment = root / "environment"
            probe = root / "probe"
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            environment.write_text("attested\n", encoding="utf-8")
            probe.write_text("probe\n", encoding="utf-8")
            baseline.write_text(
                json.dumps(self.sample_document("baseline")), encoding="utf-8"
            )
            candidate.write_text(
                json.dumps(self.sample_document("candidate")), encoding="utf-8"
            )

            with self.assertRaisesRegex(
                evidence.PerformanceEvidenceError, "campaign_id binding"
            ):
                evidence.build_campaign(
                    candidate_commit=self.candidate,
                    identifier="campaign-2",
                    recorded_at="2026-09-10T08:00:00Z",
                    environment_id="node02-ubuntu-26.04",
                    environment_attestation=environment,
                    probe=probe,
                    baseline_samples=baseline,
                    candidate_samples=candidate,
                )

            with self.assertRaisesRegex(
                evidence.PerformanceEvidenceError, "recorded_at binding"
            ):
                evidence.build_campaign(
                    candidate_commit=self.candidate,
                    identifier="campaign-1",
                    recorded_at="2026-09-11T08:00:00Z",
                    environment_id="node02-ubuntu-26.04",
                    environment_attestation=environment,
                    probe=probe,
                    baseline_samples=baseline,
                    candidate_samples=candidate,
                )

    def test_cross_campaign_integrity_rejects_clones_and_binding_drift(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            paths = [self.make_campaign(root, index) for index in (1, 2, 3)]

            cloned = json.loads(paths[1].read_text(encoding="utf-8"))
            source = json.loads(paths[0].read_text(encoding="utf-8"))
            cloned["subjects"]["baseline"]["samples_sha256"] = source["subjects"]["baseline"]["samples_sha256"]
            paths[1].write_text(json.dumps(cloned), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "reused"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths[1] = self.make_campaign(root, 4)
            drifted = json.loads(paths[1].read_text(encoding="utf-8"))
            drifted["subjects"]["adapter_sha256"] = "9" * 64
            paths[1].write_text(json.dumps(drifted), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "binding differs"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths[1] = self.make_campaign(root, 6)
            drifted_config = json.loads(paths[1].read_text(encoding="utf-8"))
            drifted_config["subjects"]["adapter_config_sha256"] = "8" * 64
            paths[1].write_text(json.dumps(drifted_config), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "binding differs"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths[1] = self.make_campaign(root, 5)
            duplicate_time = json.loads(paths[1].read_text(encoding="utf-8"))
            duplicate_time["recorded_at"] = source["recorded_at"]
            paths[1].write_text(json.dumps(duplicate_time), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "timestamps"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths = [self.make_campaign(root, index) for index in (7, 8, 9)]
            first = json.loads(paths[0].read_text(encoding="utf-8"))
            semantic_clone = json.loads(paths[1].read_text(encoding="utf-8"))
            semantic_clone["metrics"]["rss_bytes"] = copy.deepcopy(
                first["metrics"]["rss_bytes"]
            )
            paths[1].write_text(json.dumps(semantic_clone), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "cloned"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths = [self.make_campaign(root, index) for index in (10, 11, 12)]
            uneven = json.loads(paths[0].read_text(encoding="utf-8"))
            uneven["metrics"]["rss_bytes"]["baseline"] = [100.0] * 28
            uneven["metrics"]["rss_bytes"]["candidate"] = [100.0] * 28
            paths[0].write_text(json.dumps(uneven), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "exactly 10"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

            paths = [self.make_campaign(root, index) for index in (13, 14, 15)]
            duplicate = copy.deepcopy(json.loads(paths[1].read_text(encoding="utf-8")))
            duplicate["id"] = "campaign-13"
            paths[1].write_text(json.dumps(duplicate), encoding="utf-8")
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "duplicated"):
                evidence.assemble_evidence(candidate_commit=self.candidate, campaigns=paths)

    def test_output_is_new_canonical_and_symlink_safe(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            output = root / "evidence.json"
            evidence._write_new_json(output, {"status": "bound"})
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"status": "bound"})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "already exist"):
                evidence._write_new_json(output, {})
            output.unlink()
            target = root / "target"
            target.write_text("operator data\n", encoding="utf-8")
            output.symlink_to(target)
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "already exist"):
                evidence._write_new_json(output, {})
            self.assertEqual(target.read_text(encoding="utf-8"), "operator data\n")

    def test_auxiliary_input_symlink_and_hardlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("attestation\n", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "regular file"):
                evidence._sha256_regular_file(link)
            hardlink = root / "hardlink"
            os.link(target, hardlink)
            with self.assertRaisesRegex(evidence.PerformanceEvidenceError, "regular file"):
                evidence._sha256_regular_file(target)


if __name__ == "__main__":
    unittest.main()
