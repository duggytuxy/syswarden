#!/usr/bin/env python3
"""Revalidate original PR257 performance and allocation measurements offline.

Only the seven unaffected runtime metrics are eligible for continuity. Fresh
installation, startup and size measurements remain mandatory. This module
neither executes probes nor grants release acceptance.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Sequence

try:
    from scripts.ci import qualification_continuity as continuity
    from scripts.ci import performance_gate as performance
    from scripts.ci import performance_evidence as campaigns
    from scripts.ci import source_allocation_gate as allocation
except ModuleNotFoundError:
    import qualification_continuity as continuity
    import performance_gate as performance
    import performance_evidence as campaigns
    import source_allocation_gate as allocation

SCHEMA = "syswarden-pr257-metric-proof-inventory/v1"
# Exact original report; its evidence digest binds all sixty raw allocation records.
ALLOCATION_REPORT_SHA256 = "9992abd5e9c9f36fd2da73057b1d611dc26afc2181d9710e7b490f98a2511a54"
FRESH_METRICS = frozenset({"install_milliseconds", "startup_milliseconds", "package_bytes", "binary_bytes"})


def _record(proof_root: Path, policy: dict[str, Any], name: str) -> dict[str, Any]:
    return continuity.strict_json(
        continuity.checked_bytes(proof_root / name, policy["records"][name], name), name,
    )


def _hashed_json(path: Path, expected: str, label: str) -> tuple[dict[str, Any], bytes]:
    wire = continuity.bundle.regular_bytes(path, continuity.MAX_RECORD_BYTES, label)
    continuity.require(continuity.digest(wire) == expected, f"{label}: original bytes changed")
    return continuity.strict_json(wire, label), wire


def _revalidate_performance(
    *, proof_root: Path, policy: dict[str, Any], performance_root: Path,
    adapter_config: Path, sample_paths: Sequence[Path],
) -> dict[str, Any]:
    require = continuity.require
    reference = _record(proof_root, policy, "native-performance.json")
    require(reference["candidate_commit"] == continuity.BASE and reference["waivers"] == 0,
            "historical performance identity or waiver policy changed")
    original, wire = _hashed_json(performance_root / "INDEPENDENT-PERFORMANCE-GATE.json",
                                  reference["gate"]["sha256"], "historical performance report")
    contract, metrics = performance.load_contract()
    require(set(policy["fresh_required"]["performance_metrics"]) == FRESH_METRICS,
            "fresh performance requirements differ from the exact policy")
    require(original["verdict"] == "pass" and original["failed_metrics"] == [],
            "historical performance did not pass")
    require(len(sample_paths) == 6, "six original performance sample documents are required")
    samples = {}
    for path in sample_paths:
        digest = performance._sha256_regular(path)
        require(digest not in samples, "duplicate performance sample document")
        samples[digest] = path
    required_samples = set()
    paths = [performance_root / f"campaign-{index:02d}.json" for index in (1, 2, 3)]
    for path in paths:
        document = performance._load_regular_json(path)
        pair = {role: document["subjects"][role]["samples_sha256"] for role in ("baseline", "candidate")}
        require(set(pair.values()) <= samples.keys(), "original performance samples are missing or changed")
        required_samples.update(pair.values())
        rebuilt = campaigns.build_campaign(
            candidate_commit=continuity.BASE, identifier=document["id"],
            recorded_at=document["recorded_at"], environment_id=document["environment_id"],
            environment_attestation=performance_root / "ENVIRONMENT.json", probe=performance.DEFAULT_PROBE,
            baseline_samples=samples[pair["baseline"]], candidate_samples=samples[pair["candidate"]],
        )
        require(rebuilt == document, "performance campaign differs from its original sample documents")
    require(set(samples) == required_samples, "performance sample inventory is not exact")
    evidence, assembled_report = campaigns.assemble_evidence(candidate_commit=continuity.BASE, campaigns=paths)
    require(evidence == performance._load_regular_json(performance_root / "EVIDENCE.json"),
            "performance evidence differs from the reassembled sample documents")
    _record(proof_root, policy, "five-native-lifecycles.json")
    bindings = performance.reviewed_bindings(
        adapter_config, proof_root / "five-native-lifecycles.json", continuity.BASE, contract,
    )
    checked = performance.evaluate(evidence, contract, metrics, {}, continuity.BASE, **bindings)
    require(checked == assembled_report == original,
            "recomputed performance differs from the anchored original report")
    retained = sorted(set(metrics) - FRESH_METRICS)
    require(len(retained) == 7, "unaffected metric inventory is not the exact seven metrics")
    return {
        "observed_candidate": continuity.BASE, "proposed_acceptance_candidate": continuity.RUNTIME,
        "report_sha256": continuity.digest(wire), "original_report": original,
        "retained_metric_names": retained, "excluded_metric_names": sorted(FRESH_METRICS),
        "sample_document_count": len(samples), "paired_campaigns": 3,
        "acceptance": "pending-four-fresh-performance-metrics-and-protected-final-validation",
    }


def _revalidate_allocation(*, proof_root: Path, policy: dict[str, Any], allocation_root: Path) -> dict[str, Any]:
    require = continuity.require
    reference = _record(proof_root, policy, "source-allocation.json")
    require(reference["candidate_commit"] == continuity.BASE and reference["native_raw_inputs_unchanged"] is True,
            "historical allocation identity changed")
    original, wire = _hashed_json(allocation_root / "REPORT.json", ALLOCATION_REPORT_SHA256,
                                  "historical allocation report")
    checked = allocation.validate(
        contract_path=allocation.DEFAULT_CONTRACT, bundle_root=allocation_root,
        candidate_commit=continuity.BASE, evidence_path=allocation_root / "EVIDENCE.json",
        report_path=allocation_root / "REPORT.json",
    )
    require(checked == original and checked["verdict"] == "pass" and checked["failed_metrics"] == [],
            "recomputed allocation differs from the passing original report")
    return {
        "observed_candidate": continuity.BASE, "proposed_acceptance_candidate": continuity.RUNTIME,
        "report_sha256": continuity.digest(wire), "original_report": original,
        "acceptance": "pending-protected-final-validation",
    }


def verify_metric_inventory(
    *, repository: Path, proof_root: Path, base_bundle: Path, runtime_bundle: Path,
    performance_root: Path, adapter_config: Path, sample_paths: Sequence[Path],
    allocation_root: Path, candidate: str,
) -> dict[str, Any]:
    continuity.verify_eligibility(
        repository=repository, proof_root=proof_root, base_bundle=base_bundle,
        runtime_bundle=runtime_bundle, candidate=candidate,
    )
    policy = continuity.load_policy()
    return {
        "schema": SCHEMA, "status": "historical-metric-proofs-revalidated-final-acceptance-pending",
        "runtime_candidate": continuity.RUNTIME, "release": "v4.10.0",
        "continuity_policy_sha256": continuity.POLICY_SHA256,
        "performance": _revalidate_performance(proof_root=proof_root, policy=policy,
            performance_root=performance_root, adapter_config=adapter_config, sample_paths=sample_paths),
        "source_allocation": _revalidate_allocation(proof_root=proof_root, policy=policy,
            allocation_root=allocation_root),
        "fresh_performance_metrics_still_required": sorted(FRESH_METRICS),
        "native_experiments_replayed": False, "historical_evidence_modified": False,
        "protected_final_validation_required": True, "release_qualified": False,
    }


def _combine_verified_metrics(historical: dict[str, Any], native: dict[str, Any]) -> dict[str, Any]:
    """Combine only recomputed verifier results, never caller-supplied verdicts."""
    require = continuity.require
    try:
        from scripts.ci import qualification_continuity_performance_receipts as receipts
    except ModuleNotFoundError:
        import qualification_continuity_performance_receipts as receipts
    contract, metric_contracts = receipts.fresh.frozen_tooling()
    retained = set(metric_contracts) - FRESH_METRICS
    require(len(retained) == 7 and len(metric_contracts) == 11, 'combined metric inventory changed')
    require(historical['schema'] == SCHEMA and historical['runtime_candidate'] == continuity.RUNTIME
            and historical['continuity_policy_sha256'] == continuity.POLICY_SHA256
            and historical['historical_evidence_modified'] is False
            and historical['release_qualified'] is False,
            'historical inventory provenance changed')
    old = historical['performance']
    allocated = historical['source_allocation']
    require(set(old['retained_metric_names']) == retained
            and set(old['excluded_metric_names']) == FRESH_METRICS
            and set(historical['fresh_performance_metrics_still_required']) == FRESH_METRICS,
            'retained and fresh metric boundary changed')
    for channel in (old, allocated):
        require(channel['observed_candidate'] == continuity.BASE
                and channel['proposed_acceptance_candidate'] == continuity.RUNTIME
                and channel['original_report']['candidate_commit'] == continuity.BASE,
                'historical measurements were relabelled')
        require(channel['original_report']['verdict'] == 'pass'
                and channel['original_report']['failed_metrics'] == [],
                'historical measurement channel failed')
    require(old['paired_campaigns'] == 3 and old['sample_document_count'] == 6,
            'historical performance campaigns are incomplete')
    require(native['schema'] == receipts.SCHEMA and native['runtime_candidate'] == continuity.RUNTIME
            and native['native_execution_receipts_verified'] is True
            and native['historical_evidence_modified'] is False and native['release_qualified'] is False,
            'fresh native execution provenance changed')
    executions = native['executions']
    require([item['side'] for item in executions] == list(receipts.SIDES)
            and all(item['native_execution_verified'] is True for item in executions),
            'six verified native execution receipts are mandatory')
    fresh = native['performance_gate']
    require(fresh['schema'] == receipts.fresh.REPORT_SCHEMA
            and fresh['candidate_commit'] == continuity.RUNTIME
            and fresh['verdict'] == 'pass' and fresh['failed_metrics'] == []
            and type(fresh['waivers']) is int and fresh['waivers'] == 0
            and fresh['historical_samples_relabelled'] is False and fresh['release_qualified'] is False,
            'fresh metrics failed or have unreviewed provenance')
    require(set(fresh['metrics']) == FRESH_METRICS
            and set(old['original_report']['metrics']) == set(metric_contracts)
            and old['original_report']['contract_id'] == fresh['contract_id'] == contract['contract_id'],
            'combined metrics do not cover the unchanged numerical contract')
    metrics = {}
    for name in sorted(metric_contracts):
        is_fresh = name in FRESH_METRICS
        value = fresh['metrics'][name] if is_fresh else old['original_report']['metrics'][name]
        require(value['accepted'] is True and value['waived'] is False,
                'an unaccepted or waived metric cannot satisfy the combined evidence')
        metrics[name] = {'observed_candidate': continuity.RUNTIME if is_fresh else continuity.BASE,
                         'evidence_kind': 'fresh-native' if is_fresh else 'exact-pr257-continuity',
                         'measurement': copy.deepcopy(value)}
    allocations = allocated['original_report']
    require(allocations['native_package_runtime_measurement'] is False
            and allocations['measurement_scope'] == 'deterministic-source-bound-waap-engine-scan'
            and allocations['campaign_count'] == 3 and allocations['samples_per_subject'] == 30,
            'allocation measurement scope changed')
    # Bind recomputed results, retaining every original observation and candidate.
    result_digest = lambda d: continuity.digest(json.dumps(d, sort_keys=True, separators=(',', ':'),
                                                         allow_nan=False).encode('utf-8'))
    return {'schema': 'syswarden-pr257-complete-metric-evidence/v1',
            'status': 'required-performance-evidence-revalidated-awaiting-protected-acceptance',
            'runtime_candidate': continuity.RUNTIME, 'historical_candidate': continuity.BASE,
            'continuity_policy_sha256': continuity.POLICY_SHA256,
            'measurement_verdict': 'pass', 'failed_metrics': [], 'waivers': 0,
            'native_metrics': metrics, 'historical_native_metric_names': sorted(retained),
            'fresh_native_metric_names': sorted(FRESH_METRICS),
            'source_allocation': copy.deepcopy(allocated),
            'recomputed_result_digests': {'historical_inventory': result_digest(historical),
                                          'fresh_native_executions': result_digest(native)},
            'historical_inventory': copy.deepcopy(historical), 'fresh_native_executions': copy.deepcopy(native),
            'fresh_performance_metrics_still_required': [], 'native_experiments_replayed': False,
            'historical_evidence_modified': False, 'samples_pooled_across_candidates': False,
            'protected_final_validation_required': True, 'release_qualified': False}


def verify_complete_metric_evidence(
    *, repository: Path, proof_root: Path, base_bundle: Path, runtime_bundle: Path,
    performance_root: Path, adapter_config: Path, sample_paths: Sequence[Path],
    allocation_root: Path, candidate: str, fresh_sides: Sequence[dict[str, Path]],
    fresh_environment: Path,
) -> dict[str, Any]:
    """Rebuild all historical and fresh inputs before combining either channel."""
    try:
        from scripts.ci import qualification_continuity_performance_receipts as receipts
    except ModuleNotFoundError:
        import qualification_continuity_performance_receipts as receipts
    historical = verify_metric_inventory(repository=repository, proof_root=proof_root,
        base_bundle=base_bundle, runtime_bundle=runtime_bundle, performance_root=performance_root,
        adapter_config=adapter_config, sample_paths=sample_paths, allocation_root=allocation_root,
        candidate=candidate)
    native = receipts.verify_all(sides=fresh_sides, environment_path=fresh_environment)
    return _combine_verified_metrics(historical, native)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "proof-root", "base-bundle", "runtime-bundle", "performance-root",
                 "adapter-config", "allocation-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--sample", type=Path, action="append", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    try:
        result = verify_metric_inventory(repository=args.repository, proof_root=args.proof_root,
            base_bundle=args.base_bundle, runtime_bundle=args.runtime_bundle, performance_root=args.performance_root,
            adapter_config=args.adapter_config, sample_paths=args.sample, allocation_root=args.allocation_root,
            candidate=args.candidate)
        continuity.bundle.write_json(args.output, result)
    except (continuity.ContinuityError, continuity.bundle.SigningBundleError,
            performance.PerformanceGateError, campaigns.PerformanceEvidenceError,
            performance.native_adapter.NativePerformanceAdapterError,
            allocation.SourceAllocationGateError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"Metric continuity rejected: {exc}\n")
    print("Original metric proofs revalidated; four fresh metrics and final acceptance remain required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
