#!/usr/bin/env python3
"""Revalidate the exact historical lifecycle proofs for PR257 continuity.

This checks existing observations; it never runs native lifecycle experiments.
The original candidate and verdict remain unchanged. Fresh RPM deltas and the
protected final acceptance are still mandatory.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from scripts.ci import qualification_continuity as continuity
    from scripts.ci import native_lifecycle_evidence as lifecycle
    from scripts.ci import native_capability_evidence as capabilities
except ModuleNotFoundError:
    import qualification_continuity as continuity
    import native_lifecycle_evidence as lifecycle
    import native_capability_evidence as capabilities

SCHEMA = "syswarden-pr257-lifecycle-proof-inventory/v1"
HOSTS = frozenset({"node02", "node03", "node04", "node05"})


def _revalidate_lifecycle(
    *, proof_root: Path, base_bundle: Path, observations: Sequence[Path],
    artifact_root: Path, host_keys: Mapping[str, str], policy: dict[str, Any],
) -> dict[str, Any]:
    require = continuity.require
    require(set(host_keys) == HOSTS, "lifecycle requires the four trusted host keys")
    require(all(type(pin) is str for pin in host_keys.values()) and
            len(set(host_keys.values())) == len(HOSTS), "lifecycle host keys must be distinct")
    name = "five-native-lifecycles.json"
    wire = continuity.checked_bytes(proof_root / name, policy["records"][name], name)
    original = continuity.strict_json(wire, name)
    require(original.get("candidate_commit") == continuity.BASE,
            "historical lifecycle candidate was changed")
    contract, _ = capabilities.load_contract()
    packages = capabilities._load_package_bindings(base_bundle, continuity.BASE, contract)
    rpm_key = packages["RPM-A10"]["signature"]["key"]
    deb_key = packages["DEB-U2604"]["signature"]["key"]
    apk_key = packages["APK-324"]["signature"]["key"]
    require(packages["RPM-A10-RHELPO"]["signature"]["key"] == rpm_key,
            "standard and package-owned RPM signing keys differ")
    package_arguments = {}
    for role, profile in (("rpm", "RPM-A10"), ("deb", "DEB-U2604"),
                          ("apk", "APK-324"), ("rhel_rpm", "RPM-A10-RHELPO")):
        package = packages[profile]
        for suffix, field in (("name", "filename"), ("sha256", "sha256"), ("size", "size")):
            package_arguments[f"{role}_package_{suffix}"] = package[field]
    actual = lifecycle.assemble(
        continuity.BASE, observations, artifact_root,
        rpm_signer_fingerprint=rpm_key["fingerprint"],
        deb_signer_fingerprint=deb_key["fingerprint"],
        apk_public_key_sha256=apk_key["public_key_sha256"],
        **package_arguments,
        **{f"{host}_ssh_host_key_sha256": pin for host, pin in host_keys.items()},
    )
    require(actual == original, "recomputed lifecycle differs from the anchored original verdict")
    return {
        "observed_candidate": continuity.BASE,
        "proposed_acceptance_candidate": continuity.RUNTIME,
        "verdict_sha256": continuity.digest(wire), "verdict_size": len(wire),
        "profile_count": actual["profile_count"],
        "raw_evidence_count": actual["raw_evidence_count"],
        "raw_evidence_inventory_sha256": actual["raw_evidence_inventory_sha256"],
        "original_verdict": original,
        "acceptance": "pending-fresh-rpm-deltas-and-protected-final-validation",
    }


def verify_lifecycle_inventory(
    *, repository: Path, proof_root: Path, base_bundle: Path, runtime_bundle: Path,
    observations: Sequence[Path], artifact_root: Path, host_keys: Mapping[str, str],
    candidate: str,
) -> dict[str, Any]:
    eligibility = continuity.verify_eligibility(
        repository=repository, proof_root=proof_root, base_bundle=base_bundle,
        runtime_bundle=runtime_bundle, candidate=candidate,
    )
    historical = _revalidate_lifecycle(
        proof_root=proof_root, base_bundle=base_bundle, observations=observations,
        artifact_root=artifact_root, host_keys=host_keys, policy=continuity.load_policy(),
    )
    return {
        "schema": SCHEMA, "status": "five-lifecycle-proofs-revalidated-final-acceptance-pending",
        "release": "v4.10.0", "runtime_candidate": continuity.RUNTIME,
        "continuity_policy_sha256": continuity.POLICY_SHA256,
        "historical_lifecycle": historical,
        "fresh_rpm_deltas_still_required": eligibility["fresh_required"]["rpm_firewalld_profiles"],
        "native_experiments_replayed": False, "historical_evidence_modified": False,
        "protected_final_validation_required": True, "release_qualified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "proof-root", "base-bundle", "runtime-bundle", "artifact-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--observation", type=Path, action="append", required=True)
    for host in sorted(HOSTS):
        parser.add_argument(f"--{host}-ssh-host-key-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify_lifecycle_inventory(
            repository=args.repository, proof_root=args.proof_root, base_bundle=args.base_bundle,
            runtime_bundle=args.runtime_bundle, observations=args.observation,
            artifact_root=args.artifact_root, candidate=args.candidate,
            host_keys={host: getattr(args, f"{host}_ssh_host_key_sha256") for host in HOSTS},
        )
        continuity.bundle.write_json(args.output, result)
    except (continuity.ContinuityError, continuity.bundle.SigningBundleError,
            lifecycle.LifecycleEvidenceError, capabilities.NativeCapabilityEvidenceError, OSError) as exc:
        parser.exit(1, f"Lifecycle continuity rejected: {exc}\n")
    print("Five original lifecycle proofs revalidated; fresh deltas and final acceptance remain required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
