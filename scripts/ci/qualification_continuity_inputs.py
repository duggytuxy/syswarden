#!/usr/bin/env python3
"""Read the one reviewed portable PR257 performance input set, without execution.

All raw captures remain private. The input manifest is pinned independently of
its contents and may not select code, commands, contracts or another candidate.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any

try:
    from scripts.ci import qualification_continuity as continuity
    from scripts.ci import qualification_continuity_metrics as metrics
    from scripts.ci import qualification_continuity_performance_receipts as receipts
except ModuleNotFoundError:
    import qualification_continuity as continuity
    import qualification_continuity_metrics as metrics
    import qualification_continuity_performance_receipts as receipts

MANIFEST_SHA256 = 'af8c9ee6a0b3b24cce419cf7b2a2308b87587dc0b94c4c2d81c30cc0ac38f24d'
EXPECTED_FILES = 290
MAX_TOTAL_BYTES = 512 * 1024 * 1024
SCHEMA = 'syswarden-pr257-performance-protected-inputs/v1'
require = continuity.require
PATH_ARGUMENTS = frozenset({'proof_root', 'base_bundle', 'runtime_bundle',
    'allocation_root', 'performance_root', 'adapter_config', 'fresh_environment'})
SIDE_ARGUMENTS = frozenset({'run_receipt', 'export_receipt', 'bindings', 'export_directory'})


def relative(value: Any) -> str:
    require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
            'invalid private input path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and
            all(part not in ('', '.', '..') for part in path.parts), 'private input path escapes its root')
    return value


def read_input_tree(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    require(root.is_absolute() and root == root.resolve(strict=True), 'private input root is not canonical')
    continuity.bundle.ensure_protected_directory(root, 'private performance inputs')
    raw = receipts.wire(root / 'MANIFEST.json', continuity.MAX_RECORD_BYTES)
    require(continuity.digest(raw) == MANIFEST_SHA256, 'private performance manifest differs from reviewed bytes')
    document = continuity.strict_json(raw, 'private performance manifest')
    require(set(document) == {'schema', 'runtime_candidate', 'historical_candidate', 'arguments', 'files'}
            and document['schema'] == SCHEMA and document['runtime_candidate'] == continuity.RUNTIME
            and document['historical_candidate'] == continuity.BASE, 'private performance manifest identity differs')
    rows = document['files']
    require(type(rows) is list and len(rows) == EXPECTED_FILES, 'private performance file inventory is incomplete')
    seen = set();directories = {''};total = 0;previous = ''
    for item in rows:
        require(type(item) is dict and set(item) == {'path', 'sha256', 'bytes', 'mode'},
                'invalid private performance file record')
        name = relative(item['path'])
        require(name != 'MANIFEST.json' and name not in seen and name > previous,
                'private performance file inventory is duplicated or unordered')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= 128 * 1024 * 1024,
                'private performance file size exceeds its bound')
        require(item['mode'] in ('0o600', '0o700'), 'private input mode is not allowed')
        path = root / name;info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == int(item['mode'], 8), 'private input owner, mode or kind differs')
        data = receipts.wire(path, 128 * 1024 * 1024)
        require(len(data) == item['bytes'] and continuity.digest(data) == item['sha256'],
                'private performance input bytes changed')
        seen.add(name);previous=name;total += len(data)
        require(total <= MAX_TOTAL_BYTES, 'private performance inputs exceed their total bound')
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
    actual = set();actual_directories = {''}
    for directory, children, files in os.walk(root, followlinks=False):
        current = Path(directory)
        continuity.bundle.ensure_protected_directory(current, 'private performance input directory')
        for name in children:
            child=current/name
            require(not child.is_symlink(), 'private input directory is a symlink')
            actual_directories.add(child.relative_to(root).as_posix())
        for name in files:actual.add((current/name).relative_to(root).as_posix())
    require(actual == seen | {'MANIFEST.json'} and actual_directories == directories,
            'private performance tree contains missing or unexpected entries')
    require(continuity.digest(receipts.wire(root / 'MANIFEST.json')) == MANIFEST_SHA256,
            'private performance manifest changed during verification')
    values = document['arguments']
    require(type(values) is dict and set(values) == PATH_ARGUMENTS | {'sample_paths', 'fresh_sides'},
            'private input arguments may not select code, contracts or candidate identity')
    def resolve(value: Any) -> Path:
        name=relative(value)
        require(name in seen or name in directories, 'private input argument is not in the reviewed inventory')
        return root/name
    arguments = {key:resolve(values[key]) for key in PATH_ARGUMENTS}
    require(type(values['sample_paths']) is list and len(values['sample_paths']) == 6,
            'six historical performance samples are mandatory')
    arguments['sample_paths'] = [resolve(value) for value in values['sample_paths']]
    require(len(set(arguments['sample_paths'])) == 6, 'duplicate historical sample argument')
    require(type(values['fresh_sides']) is list and len(values['fresh_sides']) == 6,
            'six fresh native sides are mandatory')
    arguments['fresh_sides'] = []
    for side in values['fresh_sides']:
        require(type(side) is dict and set(side) == SIDE_ARGUMENTS, 'invalid fresh native side arguments')
        arguments['fresh_sides'].append({key:resolve(side[key]) for key in SIDE_ARGUMENTS})
    return arguments, {'manifest_sha256': MANIFEST_SHA256, 'files': len(rows), 'bytes': total}


def verify_staged_performance(*, repository: Path, input_root: Path) -> dict[str, Any]:
    arguments, identity = read_input_tree(input_root)
    result = metrics.verify_complete_metric_evidence(repository=repository, candidate=continuity.RUNTIME, **arguments)
    after_arguments, after_identity = read_input_tree(input_root)
    require(arguments == after_arguments and identity == after_identity, 'private inputs changed during evaluation')
    result['private_input_inventory'] = identity
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--input-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_staged_performance(repository=args.repository, input_root=args.input_root)
        continuity.bundle.write_json(args.output, result)
    except (continuity.ContinuityError, continuity.bundle.SigningBundleError,
            metrics.performance.PerformanceGateError, metrics.campaigns.PerformanceEvidenceError,
            metrics.allocation.SourceAllocationGateError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f'Private performance input rejected: {exc}\n')
    print('Private performance inputs revalidated; protected acceptance remains required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
