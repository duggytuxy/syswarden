#!/usr/bin/env python3
"""Adversarial checks for historical lifecycle continuity without relabelling."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest import mock

try:
    from scripts.ci import qualification_continuity_lifecycle as inventory
    from scripts.ci import native_lifecycle_evidence_test as fixtures
    from scripts.ci import native_capability_evidence_test as package_fixtures
except ModuleNotFoundError:
    import qualification_continuity_lifecycle as inventory
    import native_lifecycle_evidence_test as fixtures
    import native_capability_evidence_test as package_fixtures

c = inventory.continuity


class LifecycleContinuityTests(unittest.TestCase):
    def setUp(self):
        self.package_fixture = package_fixtures.NativeCapabilityEvidenceTests()
        self.package_fixture.candidate = c.BASE
        self.package_fixture.setUp()
        self.addCleanup(self.package_fixture.tearDown)
        self.signing_root = self.package_fixture.signing_bundle
        packages = self.package_fixture.package_bindings
        self.f = fixtures.NativeLifecycleEvidenceTests()
        self.f.candidate = c.BASE
        for prefix, profile in (("rpm", "RPM-A10"), ("deb", "DEB-U2604"),
                                ("apk", "APK-324"), ("rhel_rpm", "RPM-A10-RHELPO")):
            setattr(self.f, prefix + "_package_sha256", packages[profile]["sha256"])
            setattr(self.f, prefix + "_package_size", packages[profile]["size"])
        self.f.rpm_signer = packages["RPM-A10"]["signature"]["key"]["fingerprint"]
        self.f.deb_signer = packages["DEB-U2604"]["signature"]["key"]["fingerprint"]
        self.f.apk_key = packages["APK-324"]["signature"]["key"]["public_key_sha256"]
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.root = self.f.root
        self.proofs = self.root / "proofs"
        self.proofs.mkdir(mode=0o700)
        self.original = self.f.assemble()
        self.path = self.proofs / "five-native-lifecycles.json"
        self.wire = (json.dumps(self.original, sort_keys=True) + "\n").encode()
        self.path.write_bytes(self.wire)
        self.policy = copy.deepcopy(c.load_policy())
        self.policy["records"][self.path.name] = {
            "sha256": hashlib.sha256(self.wire).hexdigest(), "size": len(self.wire),
        }
        self.pins = {host: getattr(self.f, host + "_ssh") for host in inventory.HOSTS}

    def verify(self, **overrides):
        args = dict(proof_root=self.proofs, base_bundle=self.signing_root,
                    observations=self.f.paths, artifact_root=self.f.artifacts,
                    host_keys=self.pins, policy=self.policy)
        args.update(overrides)
        return inventory._revalidate_lifecycle(**args)

    def test_all_raw_evidence_revalidated_without_modifying_original(self):
        before = {p: p.read_bytes() for p in self.f.paths}
        result = self.verify(observations=list(reversed(self.f.paths)))
        self.assertEqual(result["original_verdict"], self.original)
        self.assertEqual(result["observed_candidate"], c.BASE)
        self.assertEqual(result["proposed_acceptance_candidate"], c.RUNTIME)
        self.assertEqual(result["profile_count"], 5)
        self.assertEqual(result["raw_evidence_count"], 145)
        self.assertEqual(self.path.read_bytes(), self.wire)
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_old_verdict_cannot_be_relabelled_or_even_reserialized(self):
        for wire in (self.wire.replace(c.BASE.encode(), c.RUNTIME.encode()), self.wire + b" "):
            with self.subTest(wire_size=len(wire)):
                self.path.write_bytes(wire)
                with self.assertRaises(c.ContinuityError): self.verify()

    def test_missing_or_duplicate_observations_fail(self):
        for paths in (self.f.paths[:-1], self.f.paths[:-1] + [self.f.paths[0]]):
            with self.subTest(paths=paths), self.assertRaises(inventory.lifecycle.LifecycleEvidenceError):
                self.verify(observations=paths)

    def test_tampered_raw_file_is_rejected(self):
        path = next(self.f.artifacts.rglob("*.json"))
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(inventory.lifecycle.LifecycleEvidenceError): self.verify()

    def test_missing_extra_or_reused_host_keys_fail(self):
        for pins in ({k: v for k, v in self.pins.items() if k != "node03"},
                     dict(self.pins, node99=self.pins["node03"]),
                     dict(self.pins, node03=self.pins["node02"])):
            with self.subTest(pins=pins), self.assertRaises(c.ContinuityError):
                self.verify(host_keys=pins)
        with self.assertRaises(inventory.lifecycle.LifecycleEvidenceError):
            self.verify(host_keys=dict(self.pins, node03="SHA256:" + "Z" * 43))

    def test_new_package_cannot_replace_historical_signed_package(self):
        changed = copy.deepcopy(self.package_fixture.package_bindings)
        changed["RPM-A10-RHELPO"]["sha256"] = "f" * 64
        with mock.patch.object(inventory.capabilities, "_load_package_bindings", return_value=changed):
            with self.assertRaises(inventory.lifecycle.LifecycleEvidenceError): self.verify()

    def test_anchored_verdict_requires_actual_recomputed_equality(self):
        different = copy.deepcopy(self.original)
        different["raw_evidence_inventory_sha256"] = "f" * 64
        with mock.patch.object(inventory.lifecycle, "assemble", return_value=different):
            with self.assertRaisesRegex(c.ContinuityError, "anchored original"): self.verify()

    def test_entry_point_requires_freshly_recomputed_eligibility(self):
        with mock.patch.object(c, "verify_eligibility", side_effect=c.ContinuityError("ineligible")) as check, \
             mock.patch.object(inventory, "_revalidate_lifecycle") as collect:
            with self.assertRaises(c.ContinuityError): self.entry()
            check.assert_called_once()
            collect.assert_not_called()

    def entry(self):
        return inventory.verify_lifecycle_inventory(
            repository=self.root, proof_root=self.proofs, base_bundle=self.signing_root,
            runtime_bundle=self.root, observations=self.f.paths, artifact_root=self.f.artifacts,
            host_keys=self.pins, candidate=c.RUNTIME,
        )

    def test_never_qualifies_or_clears_fresh_rpm_requirements(self):
        with mock.patch.object(c, "verify_eligibility", return_value={"fresh_required": self.policy["fresh_required"]}), \
             mock.patch.object(c, "load_policy", return_value=self.policy):
            result = self.entry()
        self.assertEqual(result["fresh_rpm_deltas_still_required"], self.policy["fresh_required"]["rpm_firewalld_profiles"])
        for field in ("release_qualified", "native_experiments_replayed", "historical_evidence_modified"):
            self.assertIs(result[field], False)
        self.assertIs(result["protected_final_validation_required"], True)
        self.assertNotIn("verdict", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
