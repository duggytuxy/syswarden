#!/usr/bin/env python3
"""Verify the six exact PR257 capability proofs without final acceptance.

Historical proof is never rewritten or attributed to the successor runtime.
This inventory remains ineligible for release until fresh affected deltas and
all other mandatory gates pass in the protected qualification workflow.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from scripts.ci import native_capability_evidence as capabilities
    from scripts.ci import qualification_continuity as continuity
except ModuleNotFoundError:
    import native_capability_evidence as capabilities
    import qualification_continuity as continuity


SCHEMA = "syswarden-pr257-capability-proof-inventory/v1"
HISTORICAL = {"DEB-U2604", "RPM-A9-RHELPO"}


def _verify_inventory(
    *, verdict_paths: Sequence[Path], proof_root: Path,
    base_bundle: Path, runtime_bundle: Path, policy: dict[str, Any],
) -> list[dict[str, Any]]:
    """Validate observations after the caller recomputes exact eligibility."""
    require = continuity.require
    contract, contract_wire = capabilities.load_contract()
    contract_sha256 = hashlib.sha256(contract_wire).hexdigest()
    expected = [profile["id"] for profile in contract["host_profiles"]]
    require(len(verdict_paths) == len(expected), "six capability verdicts are required")
    bindings = {
        continuity.BASE: capabilities._load_package_bindings(base_bundle, continuity.BASE, contract),
        continuity.RUNTIME: capabilities._load_package_bindings(runtime_bundle, continuity.RUNTIME, contract),
    }
    maximum = contract["limits"]["maximum_input_bytes"]
    by_profile: dict[str, dict[str, Any]] = {}
    uniqueness = {field: set() for field in (
        "campaign_id", "host_attestation_sha256", "campaign_sha256",
        "evidence_sha256", "evidence_artifact_set_sha256",
    )}
    catalog = None
    for index, path in enumerate(verdict_paths):
        raw, wire = capabilities._load_json(path, maximum, f"PR257 capability verdict {index}")
        profile = raw.get("profile_id")
        require(type(profile) is str and profile in expected, "unknown capability profile")
        require(profile not in by_profile, "duplicate capability profile")
        historical = profile in HISTORICAL
        observed = continuity.BASE if historical else continuity.RUNTIME
        if historical:
            record = f"capability-{profile}.json"
            anchor = policy["records"][record]
            original = continuity.checked_bytes(proof_root / record, anchor, record)
            require(wire == original, "historical capability proof differs from its exact anchor")
        verdict = capabilities._validate_verdict_document(
            raw, candidate_commit=observed, contract=contract,
            contract_sha256=contract_sha256, package_bindings=bindings[observed],
            index=index, seen_profiles=tuple(by_profile),
        )
        for field, seen in uniqueness.items():
            require(verdict[field] not in seen, f"duplicate capability {field}")
            seen.add(verdict[field])
        if catalog is not None:
            require(verdict["signature_catalog_sha256"] == catalog,
                    "capability signature catalogs differ")
        catalog = verdict["signature_catalog_sha256"]
        by_profile[profile] = {
            "profile_id": profile, "host_id": verdict["host_id"],
            "observed_candidate": observed,
            "proposed_acceptance_candidate": continuity.RUNTIME,
            "proof_kind": "anchored-historical-observation" if historical else "fresh-runtime-observation",
            "verdict_sha256": hashlib.sha256(wire).hexdigest(),
            "verdict_size": len(wire), "original_verdict": verdict,
            "acceptance": "pending-fresh-affected-deltas-and-protected-final-validation",
        }
    require(set(by_profile) == set(expected), "capability profile inventory is incomplete")
    require(set(expected) - HISTORICAL == set(policy["fresh_required"]["capability_profiles"]),
            "fresh capability scope differs from exact policy")
    return [by_profile[profile] for profile in expected]


def verify_capability_inventory(
    *, repository: Path, proof_root: Path, base_bundle: Path,
    runtime_bundle: Path, verdict_paths: Sequence[Path], candidate: str,
) -> dict[str, Any]:
    eligibility = continuity.verify_eligibility(
        repository=repository, proof_root=proof_root, base_bundle=base_bundle,
        runtime_bundle=runtime_bundle, candidate=candidate,
    )
    policy = continuity.load_policy()
    profiles = _verify_inventory(
        verdict_paths=verdict_paths, proof_root=proof_root, base_bundle=base_bundle,
        runtime_bundle=runtime_bundle, policy=policy,
    )
    return {
        "schema": SCHEMA, "release": policy["release"],
        "base_candidate": continuity.BASE, "runtime_candidate": continuity.RUNTIME,
        "policy_sha256": continuity.POLICY_SHA256,
        "status": "six-capability-proofs-verified-final-acceptance-pending",
        "profiles": profiles,
        "fresh_rpm_deltas_still_required": eligibility["fresh_required"]["rpm_firewalld_profiles"],
        "protected_final_validation_required": True,
        "historical_evidence_modified": False, "release_qualified": False,
    }


def _revalidate_raw_profile(
    *, profile: str, inputs: Mapping[str, Path], proof_root: Path,
    base_bundle: Path, runtime_bundle: Path, policy: dict[str, Any],
) -> dict[str, Any]:
    """Recompute with the original validator and compare the immutable verdict."""
    require = continuity.require
    contract, _ = capabilities.load_contract()
    expected = {item['id']: item for item in contract['host_profiles']}
    require(profile in expected, 'unknown raw capability profile')
    require(set(inputs) == {'campaign_path', 'evidence_path', 'artifact_root',
                            'host_attestation_path', 'verdict_path'},
            'raw capability input inventory is not exact')
    maximum = contract['limits']['maximum_input_bytes']
    observed = continuity.BASE if profile in HISTORICAL else continuity.RUNTIME
    original, wire = capabilities._load_json(inputs['verdict_path'], maximum, 'original capability verdict')
    require(original['profile_id'] == profile and original['host_id'] == expected[profile]['host_id']
            and original['candidate_commit'] == observed, 'raw capability profile, host or candidate differs')
    if profile in HISTORICAL:
        name = 'capability-' + profile + '.json'
        require(wire == continuity.checked_bytes(proof_root / name, policy['records'][name], name),
                'historical capability verdict differs from its owner-reviewed anchor')
    actual = capabilities.validate_evidence_file(
        candidate_commit=observed, campaign_path=inputs['campaign_path'],
        evidence_path=inputs['evidence_path'], artifact_root=inputs['artifact_root'],
        host_attestation_path=inputs['host_attestation_path'],
        signing_bundle_path=base_bundle if profile in HISTORICAL else runtime_bundle,
    )
    require(actual == original, 'recomputed raw capability proof differs from its original verdict')
    # Pin the second read to the already recomputed result before using its inventory.
    evidence_wire = capabilities._read_regular_bytes(inputs['evidence_path'], maximum)
    require(hashlib.sha256(evidence_wire).hexdigest() == actual['evidence_sha256'],
            'capability evidence changed while collecting its inventory')
    evidence = capabilities._decode_json(evidence_wire, 'revalidated capability evidence')
    raw = [{'reference': name, 'sha256': digest}
           for name, digest in sorted(capabilities._artifact_bindings(evidence))]
    return {'profile_id': profile, 'host_id': actual['host_id'], 'observed_candidate': observed,
            'verdict_sha256': hashlib.sha256(wire).hexdigest(),
            'evidence_sha256': actual['evidence_sha256'],
            'evidence_artifact_set_sha256': actual['evidence_artifact_set_sha256'],
            'raw_artifact_count': len(raw), 'raw_artifacts': raw,
            'original_verdict': original, 'raw_artifacts_revalidated': True,
            'release_qualified': False}


def verify_historical_raw_capabilities(
    *, repository: Path, proof_root: Path, base_bundle: Path, runtime_bundle: Path,
    profile_inputs: Mapping[str, Mapping[str, Path]], candidate: str,
) -> dict[str, Any]:
    """Recheck both retained campaigns without clearing the four missing profiles."""
    continuity.require(set(profile_inputs) == HISTORICAL,
                       'both and only the two historical capability campaigns are required')
    eligibility = continuity.verify_eligibility(repository=repository, proof_root=proof_root,
        base_bundle=base_bundle, runtime_bundle=runtime_bundle, candidate=candidate)
    policy = continuity.load_policy()
    profiles = [_revalidate_raw_profile(profile=name, inputs=profile_inputs[name], proof_root=proof_root,
        base_bundle=base_bundle, runtime_bundle=runtime_bundle, policy=policy) for name in sorted(HISTORICAL)]
    return {'schema': 'syswarden-pr257-historical-capability-raw-inventory/v1',
            'status': 'both-historical-capability-campaigns-revalidated-fresh-profiles-pending',
            'runtime_candidate': continuity.RUNTIME, 'policy_sha256': continuity.POLICY_SHA256,
            'profiles': profiles, 'fresh_capability_profiles_still_required':
                eligibility['fresh_required']['capability_profiles'],
            'fresh_rpm_deltas_still_required': eligibility['fresh_required']['rpm_firewalld_profiles'],
            'native_experiments_replayed': False, 'historical_evidence_modified': False,
            'protected_final_validation_required': True, 'release_qualified': False}


def verify_capability_raw_inventory(
    *, repository: Path, proof_root: Path, base_bundle: Path, runtime_bundle: Path,
    profile_inputs: Mapping[str, Mapping[str, Path]], candidate: str,
) -> dict[str, Any]:
    """Require six complete raw campaigns before emitting the mixed inventory."""
    contract, _ = capabilities.load_contract()
    expected = {item['id'] for item in contract['host_profiles']}
    continuity.require(set(profile_inputs) == expected, 'all six raw capability campaigns are required')
    result = verify_capability_inventory(repository=repository, proof_root=proof_root,
        base_bundle=base_bundle, runtime_bundle=runtime_bundle, candidate=candidate,
        verdict_paths=[profile_inputs[name]['verdict_path'] for name in sorted(expected)])
    policy = continuity.load_policy()
    profiles = [_revalidate_raw_profile(profile=name, inputs=profile_inputs[name], proof_root=proof_root,
        base_bundle=base_bundle, runtime_bundle=runtime_bundle, policy=policy) for name in sorted(expected)]
    # Bind both reads to one identity if the inputs change during revalidation.
    indexed = {item['profile_id']: item for item in result['profiles']}
    continuity.require(all(item['verdict_sha256'] == indexed[item['profile_id']]['verdict_sha256']
        and item['original_verdict'] == indexed[item['profile_id']]['original_verdict'] for item in profiles),
        'capability verdict changed between inventory and raw revalidation')
    result.update(schema='syswarden-pr257-capability-raw-inventory/v1',
                  status='six-capability-raw-campaigns-verified-final-acceptance-pending',
                  raw_profiles=profiles, raw_artifacts_revalidated=True,
                  native_experiments_replayed=False)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--proof-root", type=Path, required=True)
    parser.add_argument("--base-bundle", type=Path, required=True)
    parser.add_argument("--runtime-bundle", type=Path, required=True)
    parser.add_argument("--verdict", type=Path, action="append", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_capability_inventory(
            repository=args.repository, proof_root=args.proof_root,
            base_bundle=args.base_bundle, runtime_bundle=args.runtime_bundle,
            verdict_paths=args.verdict, candidate=args.candidate,
        )
        continuity.bundle.write_json(args.output, result)
    except (continuity.ContinuityError, capabilities.NativeCapabilityEvidenceError,
            continuity.bundle.SigningBundleError, OSError) as exc:
        parser.exit(1, f"PR257 capability inventory rejected: {exc}\n")
    print("Six original capability proofs verified; final acceptance remains pending.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
