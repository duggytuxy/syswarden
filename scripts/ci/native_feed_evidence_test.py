#!/usr/bin/env python3
"""Adversarial tests for native NODE02 update-feeds evidence."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import native_feed_evidence as gate
except ModuleNotFoundError:
    import native_feed_evidence as gate


class NativeFeedEvidenceTests(unittest.TestCase):
    candidate = "a" * 40
    package_name = "syswarden_4.10.0_amd64.deb"
    package_sha256 = "b" * 64
    package_size = 15129624
    signer = "A" * 40
    ssh_fingerprint = "SHA256:" + "A" * 43
    validation_time = dt.datetime(2026, 9, 8, 10, 0, tzinfo=dt.timezone.utc)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def script_digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def evidence(self) -> dict[str, object]:
        contract_sha256 = gate.contract_digest()
        feed_sha256 = "d" * 64
        manifest_sha256 = "e" * 64
        firewall_sha256 = "f" * 64
        scenarios = []
        observations = (
            "2026-09-08T08:03:00Z",
            "2026-09-08T08:06:00Z",
            "2026-09-08T08:09:00Z",
        )
        retrievals = (
            "2026-09-08T08:02:00Z",
            "2026-09-08T08:05:00Z",
            "2026-09-08T08:08:00Z",
        )
        for index, expected in enumerate(gate.EXPECTED_SCENARIOS):
            scenarios.append(
                {
                    "id": expected["id"],
                    "sequence": expected["sequence"],
                    "fixture_mode": expected["fixture_mode"],
                    "status": "pass",
                    "observed_at": observations[index],
                    "command_exit_code": 0 if index == 0 else index,
                    "command_log_sha256": str(index + 1) * 64,
                    "audit_sha256": str(index + 4) * 64,
                    "diagnostic": expected["diagnostic"],
                    "diagnostic_occurrences": 1 if index == 0 else 2,
                    "provenance": {
                        "schema": "syswarden.feed-provenance.v1",
                        "state": "current",
                        "freshness": "current",
                        "source_origin": (
                            "https://cinsscore.com,https://lists.blocklist.de"
                        ),
                        "retrieved_at": retrievals[index],
                        "sha256": feed_sha256,
                        "last_known_good_sha256": feed_sha256,
                        "accepted_count": 4,
                        "skipped_count": 0,
                        "rejected_count": 0,
                        "attestation_status": "verified",
                    },
                    "feeds": {
                        "ipv4_sha256": feed_sha256,
                        "ipv4_size": 32,
                        "ipv6_sha256": None,
                        "ipv6_size": 0,
                        "manifest_sha256": manifest_sha256,
                        "snapshot_sha256": feed_sha256,
                        "snapshot_size": 32,
                        "last_known_good_bytes_preserved": True,
                        "six_to_four_absent": True,
                    },
                    "firewall": {
                        "family": "inet",
                        "table": "syswarden",
                        "sets": [
                            "syswarden_blacklist",
                            "syswarden_blacklist6",
                        ],
                        "semantic_sha256": firewall_sha256,
                        "post_update_capture_verified": True,
                        "reapply_completed": True,
                    },
                }
            )
        return {
            "schema": gate.EVIDENCE_SCHEMA,
            "repository": "duggytuxy/syswarden",
            "release_tag": "v4.10.0",
            "candidate_sha": self.candidate,
            "contract_sha256": contract_sha256,
            "campaign": {
                "id": "native-feed-node02-1",
                "started_at": "2026-09-08T08:00:00Z",
                "completed_at": "2026-09-08T08:10:00Z",
                "observation_origin": "real-native-node02-lab-only",
                "runtime_quarantined": True,
                "snapshot_restore_required": True,
                "synthetic": False,
            },
            "host": {
                "profile_id": "DEB-U2604",
                "host_id": "node02",
                "os_id": "ubuntu",
                "os_version": "26.04",
                "architecture": "amd64",
                "package_family": "deb",
                "package_manager": "dpkg",
                "service_manager": "systemd",
                "firewall_backend": "nftables",
                "ssh_host_key_sha256": self.ssh_fingerprint,
            },
            "package": {
                "filename": self.package_name,
                "version": "4.10.0",
                "architecture": "amd64",
                "sha256": self.package_sha256,
                "size": self.package_size,
                "producer_commit": self.candidate,
                "signature_mechanism": "openpgp-detached",
                "signer_fingerprint": self.signer,
                "signature_verified_before_execution": True,
                "signature_sha256": "1" * 64,
                "signature_created_at": "2026-09-08T07:50:00Z",
                "signature_policy_sha256": "2" * 64,
                "signature_inventory_sha256": "3" * 64,
                "installed_record_verified": True,
                "cli_owned_by_package": True,
                "package_database_integrity_verified": True,
                "payload_cli_sha256": "c" * 64,
                "installed_cli_sha256": "c" * 64,
                "dpkg_verify_stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "dpkg_verify_stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "installed_record_sha256": "7" * 64,
                "cli_owner_record_sha256": "8" * 64,
                "package_file_manifest_sha256": "9" * 64,
            },
            "inputs": {
                "lab_script_sha256": self.script_digest(
                    gate.ROOT / "scripts/ci/osint_tls_qualification_lab.sh"
                ),
                "fixture_script_sha256": self.script_digest(
                    gate.ROOT / "scripts/ci/osint_tls_fixture.py"
                ),
                "installed_cli_sha256": "c" * 64,
                "payload_cli_sha256": "c" * 64,
                "raw_manifest_sha256": "6" * 64,
            },
            "transport": {
                "minimum_tls_version": "TLS1.3",
                "fixture_certificate_verified": True,
                "system_trust_store_used": True,
                "proxy_bypass_used": False,
                "product_bypass_used": False,
            },
            "scenarios": scenarios,
        }

    def validate(self, document: dict[str, object]) -> dict[str, object]:
        contract, digest = gate.load_contract()
        return gate.validate(
            document,
            candidate_sha=self.candidate,
            package_name=self.package_name,
            package_sha256=self.package_sha256,
            package_size=self.package_size,
            signer_fingerprint=self.signer,
            ssh_host_key_sha256=self.ssh_fingerprint,
            contract=contract,
            contract_sha256=digest,
            validation_time=self.validation_time,
        )

    def test_exact_node02_campaign_passes_with_deterministic_verdict(self) -> None:
        document = self.evidence()
        first = self.validate(document)
        second = self.validate(copy.deepcopy(document))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["profile_id"], "DEB-U2604")
        self.assertEqual(first["host_id"], "node02")
        self.assertIs(first["runtime_quarantined"], True)
        self.assertIs(first["snapshot_restore_required"], True)
        self.assertEqual(
            first["scenario_ids"],
            [item["id"] for item in gate.EXPECTED_SCENARIOS],
        )
        canonical = json.dumps(
            document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(first["evidence_sha256"], hashlib.sha256(canonical).hexdigest())

    def test_refusal_provenance_does_not_force_new_product_state(self) -> None:
        document = self.evidence()
        document["scenarios"][1]["provenance"].update(
            state="stale", freshness="stale"
        )
        document["scenarios"][2]["provenance"].update(
            state="rejected", freshness="rejected", rejected_count=1
        )
        self.assertEqual(self.validate(document)["status"], "pass")

    def test_ipv6_feed_is_optional_but_preserved_when_present(self) -> None:
        document = self.evidence()
        for scenario in document["scenarios"]:
            scenario["feeds"]["ipv6_sha256"] = "a" * 64
            scenario["feeds"]["ipv6_size"] = 16
        self.assertEqual(self.validate(document)["status"], "pass")

    def test_candidate_host_package_and_transport_tampering_fail_closed(self) -> None:
        mutations = (
            lambda d: d.update(candidate_sha="0" * 40),
            lambda d: d.update(contract_sha256="0" * 64),
            lambda d: d["host"].update(host_id="node03"),
            lambda d: d["host"].update(ssh_host_key_sha256="SHA256:" + "B" * 43),
            lambda d: d["package"].update(filename="syswarden_4.10.0_arm64.deb"),
            lambda d: d["package"].update(signer_fingerprint="B" * 40),
            lambda d: d["package"].update(signature_verified_before_execution=1),
            lambda d: d["package"].update(installed_record_verified=False),
            lambda d: d["package"].update(cli_owned_by_package=False),
            lambda d: d["package"].update(package_database_integrity_verified=False),
            lambda d: d["package"].update(installed_record_sha256="not-a-digest"),
            lambda d: d["inputs"].update(lab_script_sha256="0" * 64),
            lambda d: d["campaign"].update(runtime_quarantined=False),
            lambda d: d["campaign"].update(snapshot_restore_required=False),
            lambda d: d["transport"].update(minimum_tls_version="TLS1.2"),
            lambda d: d["transport"].update(product_bypass_used=True),
            lambda d: d["transport"].update(proxy_bypass_used=0),
        )
        for mutation in mutations:
            document = self.evidence()
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(
                gate.NativeFeedEvidenceError
            ):
                self.validate(document)

    def test_scenario_identity_exit_and_capture_tampering_fail_closed(self) -> None:
        mutations = (
            lambda d: d["scenarios"].reverse(),
            lambda d: d["scenarios"][1].update(id=d["scenarios"][0]["id"]),
            lambda d: d["scenarios"][0].update(sequence=True),
            lambda d: d["scenarios"][0].update(status="fail"),
            lambda d: d["scenarios"][0].update(command_exit_code=1),
            lambda d: d["scenarios"][1].update(command_exit_code=0),
            lambda d: d["scenarios"][1].update(diagnostic="similar diagnostic"),
            lambda d: d["scenarios"][1].update(diagnostic_occurrences=True),
            lambda d: d["scenarios"][1].update(diagnostic_occurrences=1),
            lambda d: d["scenarios"][1].update(observed_at="2026-09-08T07:59:59Z"),
            lambda d: d["scenarios"][1].update(command_log_sha256="bad"),
            lambda d: d["scenarios"][1].update(audit_sha256="bad"),
            lambda d: d["scenarios"][1]["firewall"].update(reapply_completed=False),
            lambda d: d["scenarios"][1]["firewall"].update(
                sets=["syswarden_blacklist"]
            ),
            lambda d: d["scenarios"][1]["feeds"].update(six_to_four_absent=False),
        )
        for mutation in mutations:
            document = self.evidence()
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(
                gate.NativeFeedEvidenceError
            ):
                self.validate(document)

    def test_refusals_must_preserve_lkg_feed_bytes_and_both_nft_sets(self) -> None:
        mutations = (
            lambda d: d["scenarios"][1]["provenance"].update(sha256="a" * 64),
            lambda d: d["scenarios"][1]["provenance"].update(
                last_known_good_sha256="a" * 64
            ),
            lambda d: d["scenarios"][1]["feeds"].update(ipv4_sha256="a" * 64),
            lambda d: d["scenarios"][1]["feeds"].update(ipv4_size=33),
            lambda d: d["scenarios"][1]["feeds"].update(manifest_sha256="a" * 64),
            lambda d: d["scenarios"][1]["feeds"].update(snapshot_sha256="a" * 64),
            lambda d: d["scenarios"][1]["feeds"].update(
                last_known_good_bytes_preserved=False
            ),
            lambda d: d["scenarios"][1]["firewall"].update(
                semantic_sha256="a" * 64
            ),
        )
        for mutation in mutations:
            document = self.evidence()
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(
                gate.NativeFeedEvidenceError
            ):
                self.validate(document)

    def test_provenance_shape_state_and_origin_fail_closed(self) -> None:
        mutations = (
            lambda d: d["scenarios"][0]["provenance"].update(state="degraded-lkg"),
            lambda d: d["scenarios"][0]["provenance"].update(freshness="expired"),
            lambda d: d["scenarios"][0]["provenance"].update(
                source_origin="https://lists.blocklist.de/path"
            ),
            lambda d: d["scenarios"][0]["provenance"].update(
                source_origin="https://lists.blocklist.de,https://cinsscore.com"
            ),
            lambda d: d["scenarios"][0]["provenance"].update(
                attestation_status="self-asserted"
            ),
            lambda d: d["scenarios"][0]["provenance"].update(accepted_count=True),
            lambda d: d["scenarios"][0]["provenance"].update(rejected_count=1),
            lambda d: d["scenarios"][1]["feeds"].update(ipv6_size=False),
        )
        for mutation in mutations:
            document = self.evidence()
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(
                gate.NativeFeedEvidenceError
            ):
                self.validate(document)

    def test_contract_digest_guardrails_and_inventory_are_exact(self) -> None:
        self.assertEqual(gate.contract_digest(), gate.CONTRACT_SHA256)
        original = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        mutations = (
            lambda d: d["profile"].update(host_id="node03"),
            lambda d: d["fixture"]["scenarios"].pop(),
            lambda d: d["fixture"]["scenarios"][0].update(sequence=True),
            lambda d: d["provenance"]["allowed_states"].append("degraded-lkg"),
            lambda d: d["firewall"].update(sets=["syswarden_blacklist"]),
            lambda d: d["guardrails"].update(product_trust_bypass=True),
            lambda d: d["guardrails"].update(product_trust_bypass=0),
            lambda d: d["limits"].update(maximum_campaign_seconds=True),
        )
        for index, mutation in enumerate(mutations):
            document = copy.deepcopy(original)
            mutation(document)
            path = self.root / f"contract-{index}.json"
            path.write_text(json.dumps(document) + "\n", encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(
                gate.NativeFeedEvidenceError
            ):
                gate.load_contract(path)

    def test_strict_json_reader_rejects_duplicates_nonfinite_and_links(self) -> None:
        path = self.root / "evidence.json"
        path.write_text('{"schema":1,"nested":{"x":1,"x":2}}\n', encoding="utf-8")
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "duplicate JSON key"):
            gate._load_json(path, 1024, "test evidence")

        path.write_text('{"value":NaN}\n', encoding="utf-8")
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "non-finite"):
            gate._load_json(path, 1024, "test evidence")

        path.write_bytes(b"{" + b"x" * 1024 + b"}")
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "bounded regular"):
            gate._load_json(path, 1024, "test evidence")

        path.write_text('{}\n', encoding="utf-8")
        alias = self.root / "alias.json"
        os.link(path, alias)
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "bounded regular"):
            gate._load_json(path, 1024, "test evidence")
        alias.unlink()
        path.unlink()
        path.symlink_to(gate.DEFAULT_CONTRACT)
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "bounded regular"):
            gate._load_json(path, 4096, "test evidence")

    def test_cli_writes_new_private_canonical_verdict(self) -> None:
        raw = self.root / "raw"
        raw.mkdir(mode=0o700)
        package = self.root / self.package_name
        signature = self.root / (self.package_name + ".asc")
        policy = self.root / "policy.json"
        for path in (package, signature, policy):
            path.write_bytes(b"test\n")
        evidence_output = self.root / "EVIDENCE.out.json"
        verdict_output = self.root / "VERDICT.json"
        document = self.evidence()
        verdict = self.validate(document)
        arguments = [
            "assemble",
            "--contract",
            str(gate.DEFAULT_CONTRACT),
            "--raw-root",
            str(raw),
            "--candidate-sha",
            self.candidate,
            "--deb-package",
            str(package),
            "--deb-signature",
            str(signature),
            "--signature-policy",
            str(policy),
            "--deb-key-id",
            "deb-2026",
            "--deb-signature-date",
            "2026-09-08",
            "--node02-ssh-host-key-sha256",
            self.ssh_fingerprint,
            "--output-evidence",
            str(evidence_output),
            "--output-verdict",
            str(verdict_output),
        ]
        with mock.patch.object(gate, "assemble_from_raw", return_value=document), mock.patch.object(
            gate, "validate", return_value=verdict
        ):
            self.assertEqual(gate.main(arguments), 0)
            self.assertEqual(gate.main(arguments), 1)
        self.assertEqual(evidence_output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(verdict_output.stat().st_mode & 0o777, 0o600)
        payload = verdict_output.read_bytes()
        self.assertTrue(payload.endswith(b"\n"))
        self.assertNotIn(b" ", payload)

    def test_nft_parser_uses_only_exact_set_elements(self) -> None:
        document = {
            "nftables": [
                {
                    "set": {
                        "family": "inet",
                        "table": "syswarden",
                        "name": "syswarden_blacklist",
                        "type": "ipv4_addr",
                        "comment": "1.0.0.1",
                        "elem": [],
                    }
                }
            ],
            "injected": "1.0.0.1",
        }
        candidate = gate._nft_document(
            gate._canonical_json(document), "syswarden_blacklist", "ipv4_addr"
        )
        self.assertEqual(gate._nft_networks(candidate, 4), set())
        candidate["elem"] = ["1.0.0.1", {"prefix": {"addr": "8.8.8.0", "len": 24}}]
        self.assertEqual(
            {str(item) for item in gate._nft_networks(candidate, 4)},
            {"1.0.0.1/32", "8.8.8.0/24"},
        )
        candidate["elem"] = [{"range": ["1.0.0.1", "1.0.0.2"]}]
        with self.assertRaises(gate.NativeFeedEvidenceError):
            gate._nft_networks(candidate, 4)

    def test_nft_policy_rejects_every_extra_ipv4_element(self) -> None:
        expected = {ipaddress.ip_network("1.0.0.1/32")}
        ipv4 = {
            "family": "inet",
            "table": "syswarden",
            "name": "syswarden_blacklist",
            "type": "ipv4_addr",
            "elem": ["1.0.0.1"],
        }
        ipv6 = {
            "family": "inet",
            "table": "syswarden",
            "name": "syswarden_blacklist6",
            "type": "ipv6_addr",
            "elem": [],
        }
        gate._require_exact_nft_sets(ipv4, ipv6, expected)
        ipv4["elem"].append("8.8.8.8")
        with self.assertRaisesRegex(
            gate.NativeFeedEvidenceError, "exact deterministic feed"
        ):
            gate._require_exact_nft_sets(ipv4, ipv6, expected)

    def test_fixture_final_feed_is_data_shield_union_with_osint(self) -> None:
        expected = gate._expected_fixture_ipv4()
        networks = set(expected.decode("ascii").splitlines())
        self.assertEqual(len(networks), 16)
        for address in gate.tls_fixture.OSINT_COMMON.decode("ascii").splitlines():
            self.assertIn(f"{address}/32", networks)

    def test_raw_bundle_rejects_private_markers_extra_files_and_bad_manifest_bytes(self) -> None:
        contract = {
            "raw_evidence": {
                "manifest": "SHA256SUMS",
                "inventory": ["transport/fixture-key.pem"],
            },
            "limits": {
                "maximum_raw_total_bytes": 4096,
                "maximum_feed_bytes": 4096,
                "maximum_input_bytes": 4096,
            },
        }
        root = self.root / "raw-bundle"
        transport = root / "transport"
        transport.mkdir(mode=0o700, parents=True)
        root.chmod(0o700)
        secret = transport / "fixture-key.pem"
        secret.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
        secret.chmod(0o600)
        manifest = root / "SHA256SUMS"
        manifest.write_bytes(
            f"{hashlib.sha256(secret.read_bytes()).hexdigest()}  transport/fixture-key.pem\n".encode("ascii")
        )
        manifest.chmod(0o600)
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "private key"):
            gate.load_raw_bundle(root, contract)

        secret.write_bytes(b"public fixture\n")
        manifest.write_bytes(
            f"{hashlib.sha256(secret.read_bytes()).hexdigest()}  transport/fixture-key.pem".encode("ascii")
        )
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "manifest bytes"):
            gate.load_raw_bundle(root, contract)
        manifest.write_bytes(
            f"{hashlib.sha256(secret.read_bytes()).hexdigest()}  transport/fixture-key.pem\n".encode("ascii")
        )
        extra = transport / "private.pem"
        extra.write_bytes(b"extra\n")
        extra.chmod(0o600)
        with self.assertRaisesRegex(gate.NativeFeedEvidenceError, "inventory"):
            gate.load_raw_bundle(root, contract)

    def test_deb_payload_inspection_uses_one_private_byte_snapshot(self) -> None:
        package = self.root / self.package_name
        original = b"initial signed package bytes"
        package.write_bytes(original)

        payload = b"candidate cli payload"
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
            member = tarfile.TarInfo("./opt/syswarden/bin/syswarden-cli")
            member.mode = 0o750
            member.uid = 0
            member.gid = 0
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        archive_wire = archive_buffer.getvalue()

        class Process:
            def __init__(self) -> None:
                self.stdout = io.BytesIO(archive_wire)

            @staticmethod
            def wait(timeout: int | None = None) -> int:
                self_timeout = timeout
                del self_timeout
                return 0

            @staticmethod
            def kill() -> None:
                return None

        def popen(arguments: list[str], **kwargs: object) -> Process:
            del kwargs
            snapshot = Path(arguments[2])
            self.assertNotEqual(snapshot, package)
            self.assertEqual(snapshot.read_bytes(), original)
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
            self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)
            package.write_bytes(b"mutated original path")
            return Process()

        with mock.patch.object(gate.subprocess, "Popen", side_effect=popen):
            result = gate.inspect_deb_payload(package)

        self.assertEqual(result["package"]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(result["package"]["size"], len(original))
        self.assertEqual(result["payload"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(package.read_bytes(), b"mutated original path")


if __name__ == "__main__":
    unittest.main()
