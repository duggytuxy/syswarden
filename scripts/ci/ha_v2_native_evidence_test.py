#!/usr/bin/env python3
"""Adversarial tests for HA v2 native qualification evidence."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import ha_v2_native_evidence as gate
except ModuleNotFoundError:
    import ha_v2_native_evidence as gate


class HAV2NativeEvidenceTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temporary.name)
        (self.bundle / "raw").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def raw(self, name: str) -> str:
        wire = (json.dumps({"capture": name}, sort_keys=True) + "\n").encode()
        (self.bundle / "raw" / name).write_bytes(wire)
        import hashlib
        return hashlib.sha256(wire).hexdigest()

    def evidence(self) -> dict[str, object]:
        fact_sets = {
            "normal-replication-ack-checkpoint": ["replicated", "acknowledged", "checkpoint_equal"],
            "heartbeat-monotonic-receipt-timeout": ["receipt_monotonic", "timeout_fenced"],
            "asymmetric-partition": ["asymmetry_observed", "writer_fenced"],
            "partition-fence-split-brain": ["partition_observed", "dual_writer_prevented", "fence_durable"],
            "rejoin-explicit": ["automatic_rejoin_refused", "operator_rejoin_verified"],
            "crash-wal-recovery": ["crash_injected", "single_restart", "wal_recovered"],
            "crash-head-recovery": ["crash_injected", "single_restart", "head_recovered"],
            "instance-lease-exclusion": ["second_instance_refused", "lease_retained"],
            "rolling-upgrade": ["writer_continuity", "standby_upgraded", "roles_preserved"],
            "rolling-rollback": ["rollback_completed", "state_preserved", "roles_preserved"],
        }
        nodes = []
        for index, role in enumerate(("writer", "standby"), 1):
            nodes.append({
                "node_id": f"node0{index}", "role": role, "architecture": "amd64",
                "candidate_sha": self.sha, "cluster_id": "ha-v2-lab", "epoch": "b" * 64,
                "tls_version": "TLS1.3", "mtls_verified": True,
                "peer_identity_verified": True, "certificate_sha256": str(index) * 64,
                "boot_id_sha256": ("c" if index == 1 else "d") * 64,
                "instance_lease_id": f"lease-node0{index}",
                "attestation_ref": f"raw/node0{index}-attestation.json",
                "attestation_sha256": self.raw(f"node0{index}-attestation.json"),
            })
        scenarios = [{
            "id": scenario, "status": "pass", "observed_at": "2026-09-10T08:10:00Z",
            "evidence_ref": f"raw/{scenario}.json", "evidence_sha256": self.raw(f"{scenario}.json"),
            "facts": {fact: True for fact in facts},
        } for scenario, facts in fact_sets.items()]
        return {
            "schema": gate.EVIDENCE_SCHEMA, "repository": "duggytuxy/syswarden",
            "release_tag": "v4.10.0", "candidate_sha": self.sha,
            "contract_sha256": gate.contract_digest(),
            "campaign": {"id": "ha-v2-native-1", "cluster_id": "ha-v2-lab", "epoch": "b" * 64,
                         "started_at": "2026-09-10T08:00:00Z", "completed_at": "2026-09-10T08:20:00Z",
                         "observation_origin": "real-native-two-node-lab", "synthetic": False},
            "nodes": nodes, "scenarios": scenarios,
            "attestation": {"mechanism": "github-artifact-attestation", "statement_sha256": "1" * 64,
                            "signature_sha256": "2" * 64, "signer_identity": "https://github.com/duggytuxy/syswarden/actions/workflows/ha-v2-native-lab.yml",
                            "verified_by": "release-owner-gate", "verification_status": "verified"},
        }

    def validate(self, document: dict[str, object]) -> dict[str, object]:
        contract, digest = gate.load_contract()
        return gate.validate(document, self.sha, "v4.10.0", contract, digest, self.bundle)

    def test_exact_real_two_node_campaign_passes(self) -> None:
        verdict = self.validate(self.evidence())
        self.assertEqual(verdict["status"], "pass")
        self.assertEqual(verdict["scenario_count"], 10)

    def test_adversarial_mutations_fail_closed(self) -> None:
        mutations = []
        for mutation in (
            lambda d: d.update(candidate_sha="b" * 40),
            lambda d: d["campaign"].update(synthetic=True),
            lambda d: d["nodes"].pop(),
            lambda d: d["nodes"][1].update(role="writer"),
            lambda d: d["nodes"][1].update(tls_version="TLS1.2"),
            lambda d: d["nodes"][1].update(mtls_verified=False),
            lambda d: d["nodes"][1].update(epoch="3" * 64),
            lambda d: d["scenarios"].pop(),
            lambda d: d["scenarios"].append(copy.deepcopy(d["scenarios"][0])),
            lambda d: d["scenarios"][0].update(status="fail"),
            lambda d: d["scenarios"][0].update(observed_at="2026-09-10T09:00:00Z"),
            lambda d: d["scenarios"][0]["facts"].update(unexpected=True),
            lambda d: d["attestation"].update(verification_status="unverified"),
            lambda d: d["attestation"].update(mechanism="self-asserted"),
        ):
            document = self.evidence()
            mutation(document)
            mutations.append(document)
        for document in mutations:
            with self.subTest(document=document), self.assertRaises(gate.EvidenceError):
                self.validate(document)

    def test_cli_rejects_duplicate_keys_and_writes_bound_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            verdict = root / "verdict.json"
            evidence.write_text(json.dumps(self.evidence()) + "\n", encoding="utf-8")
            self.assertEqual(gate.main.__name__, "main")
            document, _ = gate._read(evidence)
            self.assertEqual(self.validate(document)["candidate_sha"], self.sha)
            evidence.write_text('{"schema":1,"schema":2}\n', encoding="utf-8")
            with self.assertRaises(gate.EvidenceError):
                gate._read(evidence)

    def test_raw_symlink_hardlink_and_digest_mutation_are_rejected(self) -> None:
        document = self.evidence()
        referenced = self.bundle / document["scenarios"][0]["evidence_ref"]
        referenced.unlink()
        referenced.symlink_to(self.bundle / "raw" / "normal-replication-ack-checkpoint.json")
        with self.assertRaises(gate.EvidenceError):
            self.validate(document)
        referenced.unlink()

        document = self.evidence()
        referenced = self.bundle / document["scenarios"][0]["evidence_ref"]
        alias = self.bundle / "raw" / "hardlink.json"
        alias.hardlink_to(referenced)
        with self.assertRaises(gate.EvidenceError):
            self.validate(document)

        alias.unlink()
        document = self.evidence()
        document["scenarios"][0]["evidence_sha256"] = "0" * 64
        with self.assertRaises(gate.EvidenceError):
            self.validate(document)

    def test_contract_guardrails_and_scenario_inventory_are_exact(self) -> None:
        original = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        for mutate in (
            lambda d: d["guardrails"].update(synthetic_observations=True),
            lambda d: d["tls"].update(minimum_version="TLS1.2"),
            lambda d: d["required_scenarios"].pop(),
            lambda d: d["limits"].update(maximum_scenario_seconds=0),
        ):
            document = copy.deepcopy(original)
            mutate(document)
            path = self.bundle / "contract.json"
            path.write_text(json.dumps(document) + "\n", encoding="utf-8")
            with self.assertRaises(gate.EvidenceError):
                gate.load_contract(path)

    def test_output_must_be_new_absolute_private_file(self) -> None:
        evidence = self.bundle / "evidence.json"
        evidence.write_text(json.dumps(self.evidence()) + "\n", encoding="utf-8")
        output = self.bundle / "verdict.json"
        output.write_text("occupied\n", encoding="utf-8")
        arguments = ["ha_v2_native_evidence.py", "--bundle", str(self.bundle), "--evidence", str(evidence), "--candidate-sha", self.sha, "--release-tag", "v4.10.0", "--output", str(output)]
        with mock.patch("sys.argv", arguments):
            self.assertEqual(gate.main(), 1)
        output.unlink()
        with mock.patch("sys.argv", arguments):
            self.assertEqual(gate.main(), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
