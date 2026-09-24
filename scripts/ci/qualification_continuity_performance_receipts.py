#!/usr/bin/env python3
"""Verify the six bounded native executions behind the exact PR257 performance delta.

This is a local evidence verifier. Protected producer provenance and all other
release gates remain mandatory; no result here qualifies or publishes a release.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
import re
import os
import stat

try:
    from scripts.ci import qualification_continuity_performance as fresh
except ModuleNotFoundError:
    import qualification_continuity_performance as fresh

require = fresh.continuity.require
Error = fresh.continuity.ContinuityError
SCHEMA = 'syswarden-pr257-native-performance-executions/v1'
SOURCE = 'dff42232b1cc57dae5edb5e0a6343a4967fb7c10a85de3dcaf00c5b4d09e08f0'
HOLDER = 'dc8b8d923d689eeb824f0423caed4ca27a2286f3794e88e6dec9d78463321710'
CONFIG = '17d9bbb1f361daaf089832438df8d9edb68b66bac68c4221cb56fc41ba649c6a'
ENVIRONMENT = '50057b3cfad05233b7d9dc57e8c673d52b05c3ea81c520dce74a9d01aef1d811'
PROBE = '65f071e456534b43ebcfddb05d6cde0201ea6bbb6beef5d299deda43a556d086'
ENVIRONMENT_ID = 'node02-ubuntu-26.04-four-metrics-380e90dd'
EMPTY = fresh.continuity.digest(b'')
SIDES = tuple(f'380e90dd-node02-four-r1-0{i}.{role}' for i in (1, 2, 3) for role in ('baseline', 'candidate'))
REMOTE = '/root/syswarden-v4100-performance/'


def wire(path: Path, maximum: int = 8 * 1024 * 1024) -> bytes:
    fresh.continuity.bundle.ensure_protected_directory(path.parent, 'native proof directory')
    # Empty native stdout/stderr files are expected evidence, unlike package files.
    before = path.lstat()
    if before.st_size != 0:
        return fresh.continuity.bundle.regular_bytes(path, maximum, 'native execution proof')
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe empty native file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
                (before.st_dev, before.st_ino, 0, before.st_mtime_ns, before.st_ctime_ns) and
                opened.st_nlink == 1 and stat.S_ISREG(opened.st_mode), 'empty native file changed')
        require(os.read(descriptor, 1) == b'', 'empty native file grew')
        require(os.fstat(descriptor) == opened and path.lstat() == before, 'empty native file changed during read')
    finally:
        os.close(descriptor)
    return b''


def document(path: Path) -> dict[str, Any]:
    return fresh.continuity.strict_json(wire(path), 'native execution proof')


def sha(path: Path) -> str:
    return fresh.continuity.digest(wire(path))


def stamp(value: Any) -> datetime:
    require(isinstance(value, str), 'invalid native timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Error('invalid native timestamp') from exc
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
            'native timestamp must be UTC')
    require(datetime(2026, 9, 24, 16, 6, 56, tzinfo=timezone.utc) < parsed <
            datetime(2026, 9, 25, 10, tzinfo=timezone.utc), 'native execution outside authorized interval')
    return parsed


def key_values(text: str, separator: str) -> dict[str, str]:
    require(isinstance(text, str), 'invalid native properties')
    result = {}
    for line in text.splitlines():
        parts = line.split(separator, 1)
        require(len(parts) == 2 and parts[0] not in result, 'duplicate or invalid native property')
        result[parts[0]] = parts[1]
    return result


def verify_documents(records: Mapping[str, dict[str, Any]], side: str,
                     bindings: dict[str, Any], sample_sha256: str) -> dict[str, Any]:
    require(side in SIDES, 'unreviewed native side')
    prefix = 'records/' + side + '.attempt01/'
    required = {'samples.json', 'RESULT.json', 'PROBE-EXIT.json', 'NATIVE-LIMITS.json',
                'COMPLETION-CGROUP.json', 'CGROUP-RELEASE.json', 'CLOSED.json', 'START.json'}
    require(all(prefix + name in records for name in required), 'incomplete native execution records')
    sample, result, end, limits, completion, release, closed, start = (
        records[prefix + name] for name in ('samples.json', 'RESULT.json', 'PROBE-EXIT.json',
        'NATIVE-LIMITS.json', 'COMPLETION-CGROUP.json', 'CGROUP-RELEASE.json', 'CLOSED.json', 'START.json'))
    campaign, role = side.rsplit('.', 1)
    require(bindings['candidate_commit'] == fresh.continuity.RUNTIME and
            bindings['campaign_id'] == campaign and bindings['subject_role'] == role and
            bindings['attempt_id'] == 'attempt01' and bindings['execution_reviewed'] is True,
            'native side bindings differ')
    require(start['bindings'] == bindings, 'native START does not bind the reviewed invocation')
    expected = {'candidate_commit': fresh.continuity.RUNTIME, 'campaign_id': campaign,
                'subject_role': role, 'recorded_at': bindings['recorded_at'], 'schema': fresh.SCHEMA,
                'environment_id': ENVIRONMENT_ID, 'environment_sha256': ENVIRONMENT,
                'adapter_config_sha256': CONFIG, 'probe_sha256': PROBE,
                'adapter_sha256': fresh.FROZEN['native_performance_adapter.py'],
                'frozen_dependencies': fresh.FROZEN, **fresh.ARTIFACTS[role]}
    require(all(sample.get(k) == v for k, v in expected.items()), 'native sample provenance changed')
    require(result['status'] == 'actual-native-four-metric-side-complete' and
            result['qualification_gate_passed'] is False and result['sample_sha256'] == sample_sha256 and
            all(result[k] == expected[k] for k in ('candidate_commit', 'campaign_id', 'subject_role')),
            'native result differs from its sample')
    require(result['completion_holder_sha256'] == HOLDER and
            result['memory_events_boundary'] == 'post-probe-before-holder-release',
            'unreviewed completion holder or observation boundary')
    require(type(end['probe_returncode']) is int and end['probe_returncode'] == 0 and
            type(end['wrapper_pid']) is int and end['wrapper_pid'] > 1 and
            completion['probe_exit'] == end, 'native probe did not complete successfully')
    require(release == {'probe_returncode': 0, 'counters_captured': True} and
            type(release['probe_returncode']) is int and release['counters_captured'] is True,
            'completion holder was released without counters')
    unit = 'syswarden-native-performance-' + side + '-attempt01.service'
    unit_limits = {'MemoryMax': '469762048', 'MemorySwapMax': '134217728',
                   'TasksMax': '256', 'CPUQuotaPerSecUSec': '800ms', 'RuntimeMaxUSec': '1h 20min'}
    for props in (limits['unit_properties'], completion['unit_properties'], result['unit_properties']):
        require(props['Id'] == unit and all(props.get(k) == v for k, v in unit_limits.items()),
                'native unit identity or bounds differ')
        require(props['Result'] == 'success' and props['ExecMainStatus'] == '0', 'native unit failed')
    for props in (limits['unit_properties'], completion['unit_properties']):
        require(props['ActiveState'] == 'active' and props['SubState'] == 'running' and
                props['MainPID'] == str(end['wrapper_pid']) and props['ControlGroup'] == '/system.slice/' + unit,
                'native counters were not captured from the live completion holder')
    actual = limits['actual_cgroup_files']
    require(actual['memory.max'] == unit_limits['MemoryMax'] and actual['memory.swap.max'] == unit_limits['MemorySwapMax']
            and actual['pids.max'] == '256' and actual['cpu.max'] == '80000 100000', 'kernel cgroup bounds differ')
    for events in (actual['memory.events'], completion['memory_events']):
        counters = key_values(events, ' ')
        require(counters.get('oom') == counters.get('oom_kill') == '0', 'native execution encountered OOM')
        require(all(re.fullmatch(r'[0-9]+', v) for v in counters.values()), 'invalid memory counters')
    require(completion['memory_events'] == result['memory_events'], 'completion counters changed after holder release')
    props = result['unit_properties']
    require(props['ActiveState'] == 'active' and props['SubState'] == 'exited' and props['MainPID'] == '0'
            and props['ControlGroup'] == '', 'native wrapper did not exit')
    require(closed['unit'] == unit and closed['failure'] is None and
            closed['product_services_intentionally_preserved'] is True and
            key_values(closed['state'], '=') == {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'},
            'native unit was not closed cleanly')
    times = [stamp(x) for x in (start['started_at'], limits['observed_at'], end['observed_at'],
             completion['observed_at'], result['completed_at'], closed['closed_at'])]
    require(times == sorted(times) and times[0] < times[-1] and stamp(bindings['recorded_at']) <= times[0],
            'native execution timeline is invalid')
    return {'side': side, 'sample_sha256': sample_sha256, 'started_at': start['started_at'],
            'closed_at': closed['closed_at'], 'native_unit': unit, 'native_execution_verified': True}


def verify_side(*, run_receipt: Path, export_receipt: Path, bindings: Path,
                export_directory: Path) -> tuple[dict[str, Any], Path]:
    run, exported, b = document(run_receipt), document(export_receipt), document(bindings)
    for receipt in (run, exported):
        require(type(receipt['remote_returncode']) is int and receipt['remote_returncode'] == 0 and
                receipt['two_sessions_closed'] is True and receipt['encrypted_recovery_verified'] is True and
                receipt['node'] == 'node02' and receipt['stderr_sha256'] == EMPTY,
                'native transport or encrypted recovery incomplete')
    require(run['holder_returncode'] == 0 and type(run['holder_returncode']) is int and
            run['holder_stderr_sha256'] == EMPTY, 'native operator holder failed')
    require(run_receipt.name.endswith('-receipt.json'), 'invalid run receipt name')
    stem = run_receipt.name.removesuffix('-receipt.json')
    source = run_receipt.with_name(stem + '.source.txt')
    capture = run_receipt.with_name(stem + '.json')
    retained_bindings = run_receipt.with_name(stem + '.bindings.json')
    require(sha(source) == run['source_sha256'] == SOURCE and sha(bindings) == sha(retained_bindings) == run['bindings_sha256'],
            'native source or invocation bytes changed')
    require(Path(run['capture']).name == capture.name and sha(capture) == run['capture_sha256'], 'native completion capture changed')
    side = b['campaign_id'] + '.' + b['subject_role'];require(side in SIDES, 'unreviewed native side')
    raw = document(capture)
    require(raw == {'candidate_commit': fresh.continuity.RUNTIME, 'directory': REMOTE + 'records/' + side + '.attempt01',
                    'status': 'native-performance-side-complete-awaiting-export'}, 'native completion capture differs')
    index_path = export_directory / 'INDEX.json'
    require(sha(index_path) == exported['capture_sha256'] and Path(exported['capture']).name == 'INDEX.json', 'export index changed')
    index = document(index_path)
    require(index['native_summary']['status'] == 'private-performance-side-exported' and
            index['native_summary']['side'] == side and 8 <= len(index['local_files']) <= 64, 'export inventory is invalid')
    paths = {};records = {};summary = [];names = {'INDEX.json'};total = 0
    for number, item in enumerate(index['local_files']):
        relative = item['relative_path'];require(isinstance(relative, str) and
            relative.startswith('records/' + side + '.') and '..' not in Path(relative).parts and
            not relative.endswith('FAILURE.json') and relative not in paths, 'unexpected or duplicate native file')
        basename = str(number).zfill(4) + '-' + Path(relative).name
        if basename.endswith('.bin'):basename += '.txt'
        require(Path(item['local_path']).name == basename and basename not in names, 'invalid exported filename')
        path = export_directory / basename;data = wire(path)
        require(type(item['bytes']) is int and item['bytes'] == len(data) and fresh.continuity.digest(data) == item['sha256'],
                'native export bytes changed')
        total += len(data);require(total <= 96 * 1024 * 1024, 'native export exceeds bound')
        names.add(basename);paths[relative] = path;summary.append({k: v for k, v in item.items() if k != 'local_path'})
        if path.suffix == '.json':records[relative] = fresh.continuity.strict_json(data, 'native record')
    require(summary == index['native_summary']['files'] and {p.name for p in export_directory.iterdir()} == names,
            'export files differ from native inventory')
    prefix = 'records/' + side + '.attempt01/'
    require(all(prefix + name in paths and wire(paths[prefix + name]) == b'' for name in ('probe.stderr', 'probe.stdout')),
            'native probe output differs from reviewed protocol')
    require(prefix + 'samples.json' in paths, 'native sample missing')
    sample_path = paths[prefix + 'samples.json']
    result = verify_documents(records, side, b, sha(sample_path))
    require(stamp(run['started_at']) <= stamp(result['started_at']) < stamp(result['closed_at']) <=
            stamp(run['completed_at']) <= stamp(exported['checked_at']), 'transport timeline differs')
    result.update(native_files_verified=len(paths), run_receipt_sha256=sha(run_receipt),
                  export_receipt_sha256=sha(export_receipt), bindings_sha256=sha(bindings), export_index_sha256=sha(index_path))
    return result, sample_path


def verify_all(*, sides: Sequence[Mapping[str, Path]], environment_path: Path) -> dict[str, Any]:
    require(len(sides) == 6, 'all six fresh native sides are mandatory')
    executions = {};samples = []
    for arguments in sides:
        result, sample = verify_side(**arguments)
        require(result['side'] not in executions, 'duplicate native side')
        executions[result['side']] = result;samples.append(sample)
    require(set(executions) == set(SIDES), 'native side inventory is incomplete')
    ordered = [executions[side] for side in SIDES]
    require(all(stamp(a['closed_at']) < stamp(b['started_at']) for a, b in zip(ordered, ordered[1:])),
            'native paired executions overlap or ran out of order')
    gate = fresh.evaluate(sample_paths=samples, adapter_config_sha256=CONFIG, environment_id=ENVIRONMENT_ID,
                          environment_path=environment_path, environment_sha256=ENVIRONMENT, probe_sha256=PROBE)
    return {'schema': SCHEMA, 'runtime_candidate': fresh.continuity.RUNTIME,
            'status': 'six-native-executions-verified', 'executions': ordered, 'performance_gate': gate,
            'native_execution_receipts_verified': True, 'protected_final_validation_required': True,
            'historical_evidence_modified': False, 'release_qualified': False}
