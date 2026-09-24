#!/usr/bin/env python3
"""Collect and assess only the four fresh PR257 performance metrics.

This distinct schema never relabels historical samples and cannot qualify a
release. The original eleven-metric probe, adapter and numerical contract stay
byte-identical. A protected final consumer must bind the reviewed configuration,
native environment, execution receipts and this tooling source separately.
"""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
from statistics import median
from typing import Any, Sequence

try:
    from scripts.ci import qualification_continuity as continuity
    from scripts.ci import native_performance_probe as probe
    from scripts.ci import performance_gate as gate
except ModuleNotFoundError:
    import qualification_continuity as continuity
    import native_performance_probe as probe
    import performance_gate as gate

FRESH = frozenset({'install_milliseconds', 'startup_milliseconds', 'package_bytes', 'binary_bytes'})
SCHEMA = 'syswarden-pr257-fresh-performance-samples/v1'
REPORT_SCHEMA = 'syswarden-pr257-fresh-performance-report/v1'
EARLIEST = '2026-09-24T16:06:56Z'
FROZEN = {
    'native_performance_probe.py': '78cfc76846b8e5c0a94f79cf3881aa167f784f5bf5d59fad1775117de40287f0',
    'native_performance_adapter.py': 'a05ae52d0d354c5ab236f2a96d89251e498923ece32c85ecb21cc6f5a1676f70',
    'performance_gate.py': '7e932b8ab8c39f8d5c6ce3c84ca363151a231ac3940f1c2e0ce98055645bc9d6',
    'performance_contract_v4.10.0.json': '5a0f3325b3037a1cf3e95abfa7d1cfa1b952d1a0d0f0e819ec356ef4a9670289',
}
# Exact DEB artifacts from the reviewed native lifecycle and signed successor.
ARTIFACTS = {
    'baseline': {
        'binary_sha256': '62eb100e85c199276347d48ef673636fa64ab43bd65930f0848bdaa12d204583',
        'package_sha256': 'e9ea3252de5668eaa10794333b4cb533a0acedfeac60105b50e512aa915b2612',
    },
    'candidate': {
        'binary_sha256': '94b2c28a76045d73e7a65cf9a5162e07335555c23e45fe3275740d3e48ea2770',
        'package_sha256': '0e8b4eb7d6787deac356f96758a21130c3e66edada2a50d34f980445c1253ac9',
    },
}
SIZES = {
    'baseline': {'package_bytes': 15129624, 'binary_bytes': 11383086},
    'candidate': {'package_bytes': 15894024, 'binary_bytes': 12280110},
}
require = continuity.require


def frozen_tooling() -> tuple[dict[str, Any], dict[str, gate.MetricContract]]:
    root = Path(__file__).resolve().parent
    for name, expected in FROZEN.items():
        require(gate._sha256_regular(root / name) == expected, 'frozen performance dependency changed: ' + name)
    policy = continuity.load_policy()
    require(set(policy['fresh_required']['performance_metrics']) == FRESH, 'fresh metric policy changed')
    return gate.load_contract(root / 'performance_contract_v4.10.0.json')


def canonical_digest(value: str, label: str) -> None:
    require(isinstance(value, str) and gate.SHA256_PATTERN.fullmatch(value) is not None,
            label + ': digest is not canonical')


def timestamp(value: str) -> None:
    gate._canonical_utc_timestamp(value, 'fresh recorded_at')
    require(value >= EARLIEST, 'fresh samples predate the merged runtime')


def collect(*, candidate_commit: str, campaign_id: str, recorded_at: str, subject_role: str,
            environment_id: str, environment_sha256: str, adapter: Path, adapter_sha256: str,
            adapter_config: Path, adapter_config_sha256: str, binary: Path, package: Path,
            runs: int, timeout_seconds: int) -> dict[str, Any]:
    contract, all_metrics = frozen_tooling()
    require(candidate_commit == continuity.RUNTIME, 'fresh collection is limited to the exact PR257 runtime')
    require(subject_role in ARTIFACTS, 'invalid fresh subject role')
    for value in (campaign_id, environment_id):
        require(isinstance(value, str) and gate.IDENTIFIER_PATTERN.fullmatch(value) is not None,
                'invalid fresh campaign or environment identifier')
    timestamp(recorded_at)
    for value in (environment_sha256, adapter_sha256, adapter_config_sha256):
        canonical_digest(value, 'fresh input')
    require(adapter_sha256 == FROZEN['native_performance_adapter.py'], 'adapter is not the frozen native adapter')
    for path in (adapter, adapter_config, binary, package):
        require(path.is_absolute() and Path(os.path.normpath(path)) == path,
                'fresh input paths must be absolute and canonical')
    require(type(runs) is int and runs == 10, 'fresh collection requires exactly ten iterations')
    require(type(timeout_seconds) is int and 0 < timeout_seconds <= 3600, 'invalid adapter time limit')
    metrics = {name: all_metrics[name] for name in sorted(FRESH)}
    counts = {name: math.ceil(item.minimum_samples / contract['minimum_campaigns'])
              for name, item in metrics.items()}
    require(max(counts.values()) == runs, 'contract sample counts changed')
    package_state = probe._regular(package)
    require(package_state.st_size > 0, 'package is empty')
    package_sha256 = probe._sha256(package, package_state)
    require(package_sha256 == ARTIFACTS[subject_role]['package_sha256'], 'package differs from exact reviewed artifact')
    config_state = probe._regular(adapter_config)
    subject_release = contract['baseline_release' if subject_role == 'baseline' else 'target_release']
    samples: dict[str, list[float]] = {name: [] for name in metrics}
    adapter_fd = probe._open_attested_adapter(adapter, adapter_sha256)
    try:
        config_fd = probe._open_attested_config(adapter_config, adapter_config_sha256)
        try:
            for iteration in range(1, runs + 1):
                requested = {name for name in FRESH - probe.SIZE_METRICS if iteration <= counts[name]}
                observed = probe._invoke_adapter(adapter_fd, config_fd, adapter_config_sha256,
                    candidate_commit, contract['baseline_commit'], campaign_id, recorded_at,
                    subject_role, subject_release, iteration, requested, timeout_seconds,
                    package, package_sha256, binary)
                for name, value in observed.items():
                    samples[name].append(value)
        finally:
            os.close(config_fd)
    finally:
        os.close(adapter_fd)
    binary_state = probe._regular(binary)
    binary_sha256 = probe._sha256(binary, binary_state)
    require(binary_sha256 == ARTIFACTS[subject_role]['binary_sha256'], 'installed binary differs from reviewed artifact')
    require(probe._sha256(package, package_state) == package_sha256, 'package changed during collection')
    require(probe._sha256(adapter_config, config_state) == adapter_config_sha256, 'configuration changed during collection')
    for name, size in (('binary_bytes', binary_state.st_size), ('package_bytes', package_state.st_size)):
        require(size == SIZES[subject_role][name], 'size differs from exact reviewed artifact')
        samples[name] = [float(size)] * counts[name]
    return {
        'schema': SCHEMA, 'candidate_commit': candidate_commit, 'campaign_id': campaign_id,
        'recorded_at': recorded_at, 'subject_role': subject_role, 'subject_release': subject_release,
        'contract_id': contract['contract_id'], 'environment_id': environment_id,
        'environment_sha256': environment_sha256, 'adapter_sha256': adapter_sha256,
        'adapter_config_sha256': adapter_config_sha256, 'binary_sha256': binary_sha256,
        'package_sha256': package_sha256, 'probe_sha256': gate._sha256_regular(Path(__file__)),
        'frozen_dependencies': dict(FROZEN),
        'metrics': {name: {'unit': metrics[name].unit, 'samples': samples[name]} for name in metrics},
    }


def evaluate(*, sample_paths: Sequence[Path], adapter_config_sha256: str,
             environment_id: str, environment_path: Path, environment_sha256: str,
             probe_sha256: str) -> dict[str, Any]:
    """Assess six newly collected sides with exact provenance and unchanged budgets.

    Hash arguments are mandatory reviewed input pins, never inferred from the
    sample documents. This report alone does not authenticate remote execution.
    """
    contract, metrics = frozen_tooling()
    for label, value in [('adapter config', adapter_config_sha256), ('environment', environment_sha256),
                         ('probe', probe_sha256)]:
        canonical_digest(value, label)
    require(gate._sha256_regular(Path(__file__)) == probe_sha256, 'reviewed fresh probe changed')
    require(isinstance(environment_id, str) and gate.IDENTIFIER_PATTERN.fullmatch(environment_id) is not None,
            'invalid environment identifier')
    environment = continuity.bundle.regular_bytes(environment_path, continuity.MAX_RECORD_BYTES, 'native environment')
    require(continuity.digest(environment) == environment_sha256, 'reviewed native environment changed')
    continuity.strict_json(environment, 'native environment')
    require(len(sample_paths) == 6, 'exactly three fresh paired campaigns are required')
    documents = {}; hashes = set()
    keys = {'schema', 'candidate_commit', 'campaign_id', 'recorded_at', 'subject_role', 'subject_release',
            'contract_id', 'environment_id', 'environment_sha256', 'adapter_sha256', 'adapter_config_sha256',
            'binary_sha256', 'package_sha256', 'probe_sha256', 'frozen_dependencies', 'metrics'}
    for path in sample_paths:
        wire = continuity.bundle.regular_bytes(path, continuity.MAX_RECORD_BYTES, 'fresh sample')
        sha = continuity.digest(wire)
        require(sha not in hashes, 'fresh sample document is reused')
        hashes.add(sha)
        document = continuity.strict_json(wire, 'fresh sample')
        require(set(document) == keys, 'fresh sample schema is not exact')
        expected = {'schema': SCHEMA, 'candidate_commit': continuity.RUNTIME, 'contract_id': contract['contract_id'],
            'environment_id': environment_id, 'environment_sha256': environment_sha256,
            'adapter_sha256': FROZEN['native_performance_adapter.py'], 'adapter_config_sha256': adapter_config_sha256,
            'probe_sha256': probe_sha256, 'frozen_dependencies': FROZEN}
        require(all(document[k] == v for k, v in expected.items()), 'fresh sample provenance differs from reviewed inputs')
        role = document['subject_role']; identifier = document['campaign_id']
        require(role in ARTIFACTS, 'fresh sample role is invalid')
        require(isinstance(identifier, str) and gate.IDENTIFIER_PATTERN.fullmatch(identifier) is not None,
                'fresh campaign identifier is invalid')
        timestamp(document['recorded_at'])
        require(document['subject_release'] == contract['baseline_release' if role == 'baseline' else 'target_release'],
                'fresh sample release is invalid')
        require(all(document[k] == v for k, v in ARTIFACTS[role].items()), 'fresh artifact binding is invalid')
        require(isinstance(document['metrics'], dict) and set(document['metrics']) == FRESH, 'fresh metric inventory is not exact')
        for name in FRESH:
            item = document['metrics'][name]
            require(isinstance(item, dict) and set(item) == {'unit', 'samples'} and item['unit'] == metrics[name].unit,
                    'fresh metric shape or unit is invalid')
            values = gate._samples(item['samples'], 1, name)
            if name in probe.SIZE_METRICS:
                require(all(value == SIZES[role][name] for value in values), 'fresh size differs from reviewed artifact')
            require(len(values) == math.ceil(metrics[name].minimum_samples / contract['minimum_campaigns']),
                    'fresh metric sample count is invalid')
        pair = documents.setdefault(identifier, {})
        require(role not in pair, 'duplicate fresh campaign side')
        pair[role] = (document, sha)
    require(len(documents) == contract['minimum_campaigns'], 'fresh campaign count is invalid')
    stamps = set(); vectors = set(); campaign_provenance = []
    for identifier, pair in sorted(documents.items()):
        require(set(pair) == {'baseline', 'candidate'}, 'fresh campaign pair is incomplete')
        baseline, candidate = pair['baseline'][0], pair['candidate'][0]
        stamp = baseline['recorded_at']
        require(stamp == candidate['recorded_at'] and stamp not in stamps, 'fresh campaign timestamps differ or repeat')
        stamps.add(stamp)
        vector = tuple(tuple(pair[role][0]['metrics']['startup_milliseconds']['samples']) for role in ('baseline', 'candidate'))
        require(vector not in vectors, 'fresh startup vectors are cloned across campaigns')
        vectors.add(vector)
        campaign_provenance.append({'id': identifier, 'recorded_at': stamp,
            'baseline_samples_sha256': pair['baseline'][1], 'candidate_samples_sha256': pair['candidate'][1]})
    threshold = contract['stable_regression_percent']; results = {}; failures = []
    for name in sorted(FRESH):
        all_values = {'baseline': [], 'candidate': []}; regressed = 0; campaigns = []
        for identifier, pair in sorted(documents.items()):
            values = {role: gate._samples(pair[role][0]['metrics'][name]['samples'], 1, name)
                      for role in all_values}
            for role in all_values:
                all_values[role].extend(values[role])
            bm, cm = median(values['baseline']), median(values['candidate'])
            regressed += int(gate._regressed(bm, cm, metrics[name].direction, threshold))
            campaigns.append({'id': identifier, 'baseline_median': bm, 'candidate_median': cm,
                'regression_percent': gate._regression_percent(bm, cm, metrics[name].direction)})
        bm, cm = median(all_values['baseline']), median(all_values['candidate'])
        failed = gate._regressed(bm, cm, metrics[name].direction, threshold) and regressed >= math.ceil(len(documents) / 2)
        if failed:
            failures.append(name)
        results[name] = {'unit': metrics[name].unit, 'direction': metrics[name].direction,
            **{role: {'samples': len(values), 'minimum': min(values), 'median': median(values),
                      'p95': gate._percentile(values, 0.95), 'maximum': max(values)} for role, values in all_values.items()},
            'aggregate_regression_percent': gate._regression_percent(bm, cm, metrics[name].direction),
            'regressed_campaigns': regressed, 'campaign_count': len(documents), 'campaigns': campaigns,
            'stable_regression': failed, 'accepted': not failed, 'waived': False,
            'acceptance': {'kind': 'stable-relative-regression', 'threshold_percent': threshold}}
    return {'schema': REPORT_SCHEMA, 'candidate_commit': continuity.RUNTIME, 'contract_id': contract['contract_id'],
        'verdict': 'fail' if failures else 'pass', 'failed_metrics': failures, 'metrics': results,
        'campaigns': campaign_provenance, 'environment_id': environment_id, 'environment_sha256': environment_sha256,
        'adapter_config_sha256': adapter_config_sha256, 'probe_sha256': probe_sha256, 'frozen_dependencies': dict(FROZEN),
        'subject_artifacts': ARTIFACTS, 'waivers': 0, 'historical_samples_relabelled': False,
        'native_execution_receipts_required': True, 'protected_final_validation_required': True, 'release_qualified': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    collect_parser = sub.add_parser('collect')
    for name in ('candidate-commit', 'campaign-id', 'recorded-at', 'subject-role', 'environment-id',
                 'environment-sha256', 'adapter-sha256', 'adapter-config-sha256'):
        collect_parser.add_argument('--' + name, required=True)
    for name in ('adapter', 'adapter-config', 'binary', 'package'):
        collect_parser.add_argument('--' + name, type=Path, required=True)
    collect_parser.add_argument('--runs', type=int, default=10)
    collect_parser.add_argument('--timeout-seconds', type=int, default=900)
    evaluate_parser = sub.add_parser('evaluate')
    evaluate_parser.add_argument('--sample', dest='sample_paths', type=Path, action='append', required=True)
    evaluate_parser.add_argument('--environment-path', type=Path, required=True)
    for name in ('adapter-config-sha256', 'environment-id', 'environment-sha256', 'probe-sha256'):
        evaluate_parser.add_argument('--' + name, required=True)
    for command in (collect_parser, evaluate_parser):
        command.add_argument('--output', type=Path, required=True)
    args = vars(parser.parse_args()); action = args.pop('action'); output = args.pop('output')
    try:
        result = collect(**args) if action == 'collect' else evaluate(**args)
        probe._write_new_json(output, result)
    except (continuity.ContinuityError, continuity.bundle.SigningBundleError,
            probe.NativePerformanceProbeError, gate.PerformanceGateError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f'Fresh PR257 performance rejected: {exc}\n')
    return int(result.get('verdict') == 'fail')


if __name__ == '__main__':
    raise SystemExit(main())
