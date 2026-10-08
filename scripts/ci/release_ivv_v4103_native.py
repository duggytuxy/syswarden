"""Verify original signed-product native evidence without extracting private data."""
from __future__ import annotations

import io
import copy
import re
import tarfile

try:
    from scripts.ci import release_ivv_current as common
except ModuleNotFoundError:
    import release_ivv_current as common

frozen = common.frozen
require, equal = common.require, common.equal
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024


def read_archive(wire: bytes) -> dict[str, bytes]:
    require(0 < len(wire) <= 128 * 1024 * 1024, 'invalid private archive size')
    files, total = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(wire), mode='r:gz') as packed:
            for row in packed:
                require(len(files) < 1000 and row.name not in files,
                        'duplicate or excessive native archive members')
                name = frozen.relative(row.name)
                require(name == row.name and row.isfile() and not row.issparse(),
                        'unsafe native archive member')
                require(0 <= row.size <= MAX_FILE, 'oversized native archive member')
                total += row.size
                require(total <= MAX_TOTAL, 'native archive expansion exceeds bound')
                source = packed.extractfile(row)
                require(source is not None, 'missing native archive member')
                with source:
                    data = source.read(MAX_FILE + 1)
                equal(len(data), row.size, 'native archive member length differs')
                files[name] = data
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise frozen.PlanError('invalid private native archive') from exc
    return files


def verify_filesystem_observations(observations: list[dict]) -> None:
    equal(len(observations), 7, 'filesystem observation count differs')
    require(len({row['boot_id'] for row in observations}) >= 4,
            'native observations lack distinct boots')
    renumbered = False
    fields = {'path', 'sha256', 'mode', 'uid', 'gid', 'nlink', 'device', 'inode', 'filesystem_uuid'}
    for observation in observations:
        equal(observation['status'], 'PASS', 'filesystem observation failed')
        rows = observation['artifacts']
        require(type(rows) is list and len(rows) == 3, 'owned artifact count differs')
        require(len({r['expected']['path'] for r in rows}) == 3, 'duplicate owned artifact')
        changed = False
        for row in rows:
            before, after = row['expected'], row['actual']
            equal(set(before), fields, 'unexpected original identity fields')
            equal(set(after), fields, 'unexpected observed identity fields')
            uuid = before['filesystem_uuid']
            require(type(uuid) is str and re.fullmatch('[0-9a-f]{32}', uuid) is not None
                    and uuid != '0' * 32, 'filesystem UUID is missing or invalid')
            for field in fields - {'device'}:
                equal(after[field], before[field], 'owned filesystem identity changed')
            for state in (before, after):
                require(type(state['device']) is int and state['device'] > 0,
                        'invalid native device number')
                equal(state['nlink'], 1, 'owned artifact is not single-link')
                equal(state['uid'], 0, 'owned artifact is not root-owned')
                equal(state['gid'], 0, 'owned artifact has an unexpected group')
            different = before['device'] != after['device']
            equal(row['device_renumbered'], different, 'artifact renumbering claim differs')
            changed = changed or different
        equal(observation['device_renumbered'], changed, 'boot renumbering claim differs')
        renumbered = renumbered or changed
    require(renumbered, 'real device renumbering is required')


def verify_archive(plan: dict, objects: dict[str, bytes]) -> None:
    wire = objects[plan['native_archive_sha256']]
    equal(frozen.digest(wire), plan['native_archive_sha256'], 'native archive was replaced')
    files = read_archive(wire)
    manifest_wire = files['EVIDENCE-MANIFEST.json']
    equal(frozen.digest(manifest_wire), plan['native_manifest_sha256'], 'native manifest differs')
    manifest = frozen.strict_json(manifest_wire)
    equal(manifest['schema'], 'syswarden-private-native-evidence-v1', 'unknown native manifest')
    equal(manifest['candidate'], plan['product_candidate'], 'native campaign was relabeled')
    rows = manifest['files']
    require(type(rows) is list, 'invalid native file inventory')
    equal(len(rows), plan['native_file_count'], 'native evidence count differs')
    equal(len({row['path'] for row in rows}), len(rows), 'duplicate native file anchor')
    equal(set(files), {row['path'] for row in rows} | {'EVIDENCE-MANIFEST.json'},
          'native archive inventory differs')
    for row in rows:
        equal(set(row), {'path', 'bytes', 'sha256'}, 'unexpected native anchor fields')
        data = files[row['path']]
        equal(len(data), row['bytes'], 'native evidence length differs')
        equal(frozen.digest(data), row['sha256'], 'native evidence digest differs')
        equal(objects[row['sha256']], data, 'native evidence is absent from the private graph')
    for name, digest in plan['native_payloads'].items():
        equal(frozen.digest(files[name]), digest, 'native signed payload was replaced')
    for name, assertions in plan['native_assertions'].items():
        doc = frozen.strict_json(files[name])
        for pointer, expected in assertions.items():
            equal(common.at_pointer(doc, pointer), expected, 'native observation assertion differs')
    observations = [frozen.strict_json(data) for name, data in files.items()
                    if name.startswith('filesystem-observations/') and name.endswith('.json')]
    verify_filesystem_observations(observations)
    probes = [frozen.strict_json(data) for name, data in files.items()
              if '/vpn-probe/result-' in '/' + name and name.endswith('.json')]
    equal(len(probes), 11, 'encrypted traffic probe count differs')
    for probe in probes:
        equal(probe['status'], 'PASS', 'encrypted traffic probe failed')
        for key in ('server_and_client_handshake', 'encrypted_bidirectional_transit', 'public_dns_over_vpn_nat'):
            equal(probe[key], True, 'encrypted traffic or NAT observation failed')


def verify_restoration(manifest: dict, objects: dict[str, bytes]) -> None:
    roots = {row['id']: row for row in manifest['roots']}
    def document(name):
        return frozen.strict_json(objects[roots[name]['object_sha256']])
    before, after = document('entry-baseline'), document('final-restored-verification')
    for state in (before, after):
        equal(state['all_passed'], True, 'baseline verification failed')
        equal(state['passed'], 137, 'baseline has incomplete passing controls')
        equal(state['total'], 137, 'baseline control count differs')
        require(len(state['checks']) == 137 and len({r['check'] for r in state['checks']}) == 137,
                'baseline control inventory is not exact')
        require(all(row['passed'] is True for row in state['checks']), 'baseline control failed')
        extra = state['post_restore_checks']
        require(len(extra) == 10 and all(v is True for v in extra.values()),
                'restoration cleanup is incomplete')
    # The default tmpfs size follows available memory at boot. This restoration
    # changed it by four KiB. Keep every mount flag and all other controls exact.
    for state in (before, after):
        state['checks'] = copy.deepcopy(state['checks'])
        row = next(r for r in state['checks'] if r['check'] == 'mount_options_preserved_/tmp')
        parts = row['detail'].split(',')
        size = [p for p in parts if re.fullmatch(r'size=[0-9]+k', p)]
        require(len(size) == 1, 'missing or ambiguous tmpfs size')
        state['tmpfs_size_kib'] = int(size[0][5:-1])
        row['detail'] = ','.join(p for p in parts if p != size[0])
    require(abs(after['tmpfs_size_kib'] - before['tmpfs_size_kib']) <= 4,
            'tmpfs size change exceeds observed boot variance')
    for field in ('checks', 'post_restore_checks', 'deviations'):
        equal(after[field], before[field], 'restored hardening baseline differs')
