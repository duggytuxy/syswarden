"""Bound four independent private removal archives to one signed product."""
from __future__ import annotations

import io
import tarfile

try:
    from scripts.ci import release_ivv_current as common
except ModuleNotFoundError:
    import release_ivv_current as common

frozen = common.frozen
require, equal = common.require, common.equal
CASES = frozenset({'uninstall', 'remove', 'purge', 'remove_then_purge'})
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 1000
PACKET_EXPECTATIONS = {
    f'{family}-{protocol}-{source}': 'allowed' if source == 2 else 'blocked'
    for family in ('ipv4', 'ipv6')
    for protocol in ('icmp', 'tcp', 'udp')
    for source in (2, 3, 4)
}


def read_archive(wire: bytes, *, backup: bool = False) -> dict[str, bytes]:
    require(type(wire) is bytes and 0 < len(wire) <= MAX_ARCHIVE,
            'invalid removal archive size')
    files, total, names = {}, 0, set()
    try:
        with tarfile.open(fileobj=io.BytesIO(wire), mode='r:*') as packed:
            for row in packed:
                require(len(names) < MAX_FILES and row.name not in names,
                        'duplicate or excessive removal archive members')
                equal(frozen.relative(row.name), row.name, 'unsafe removal member path')
                names.add(row.name)
                if backup and row.isdir():
                    equal(row.size, 0, 'nonempty backup directory member')
                    continue
                require(row.isfile() and not row.issparse(), 'nonregular removal member')
                require(0 <= row.size <= MAX_MEMBER, 'oversized removal member')
                total += row.size
                require(total <= MAX_TOTAL, 'removal archive expansion exceeds bound')
                source = packed.extractfile(row)
                require(source is not None, 'missing removal member')
                with source:
                    data = source.read(MAX_MEMBER + 1)
                equal(len(data), row.size, 'removal member length differs')
                files[row.name] = data
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise frozen.PlanError('invalid private removal archive') from exc
    return files


def require_true(doc: dict, keys: tuple[str, ...]) -> None:
    for key in keys:
        equal(doc[key], True, 'required removal observation failed: ' + key)


def verify_case(plan: dict, anchor: dict, objects: dict[str, bytes], *,
                completed_boots: set[str] | None = None) -> dict:
    equal(set(anchor), {'case', 'archive_sha256', 'manifest_name',
                       'manifest_sha256', 'file_count', 'prefix'},
          'unexpected removal anchor fields')
    case = anchor['case']
    require(case in CASES, 'unknown removal lifecycle')
    require(type(anchor['file_count']) is int and 0 < anchor['file_count'] < MAX_FILES,
            'invalid removal file count')
    raw = objects[anchor['archive_sha256']]
    equal(frozen.digest(raw), anchor['archive_sha256'], 'removal archive was replaced')
    files = read_archive(raw)
    manifest_wire = files[anchor['manifest_name']]
    equal(frozen.digest(manifest_wire), anchor['manifest_sha256'], 'removal manifest differs')
    equal(objects[anchor['manifest_sha256']], manifest_wire, 'removal manifest missing from private graph')
    manifest = frozen.strict_json(manifest_wire)
    require(type(manifest) is dict, 'invalid removal manifest')
    equal(len(manifest), anchor['file_count'], 'removal member count differs')
    equal(set(files), set(manifest) | {anchor['manifest_name']}, 'removal inventory differs')
    for name, row in manifest.items():
        equal(set(row), {'size', 'sha256'}, 'unexpected removal identity fields')
        equal(len(files[name]), row['size'], 'removal member size differs')
        equal(frozen.digest(files[name]), row['sha256'], 'removal member digest differs')
        equal(objects[row['sha256']], files[name], 'removal member missing from private graph')
    product = plan['product_candidate']
    raw_case = 'remove' if case == 'remove_then_purge' else case
    suffix = 'remove-only-remove' if case == 'remove' else raw_case
    prefix = 'case-signed' + product[:8] + '-' + suffix + '/'
    equal(anchor['prefix'], prefix, 'removal lifecycle archive was relabeled')

    def document(name):
        return frozen.strict_json(files[prefix + name])

    def array(name):
        rows = frozen.strict_json(b'{"rows":' + files[prefix + name] + b'}')['rows']
        require(type(rows) is list, 'required evidence array is not a list')
        return rows

    baseline = document('administrator-baseline.json')
    require(type(baseline) is dict and len(baseline) == 213,
            'administrator baseline inventory differs')
    for name, row in baseline.items():
        require(type(name) is str and
                name.startswith(('/etc/', '/usr/local/libexec/', '/var/spool/cron/')),
                'unexpected administrator baseline path')
        equal(frozen.relative(name[1:]), name[1:], 'unsafe administrator baseline path')
        require(type(row['regular']) is bool, 'invalid administrator baseline file type')
        equal(set(row), {'uid', 'gid', 'inode', 'mode', 'regular'} |
              ({'sha256'} if row['regular'] else {'target'} if 'target' in row else set()),
              'unexpected administrator baseline fields')
        if 'target' in row:
            require(type(row['target']) is str and bool(row['target']),
                    'administrator symlink target is missing')
    equal(sum(row['regular'] for row in baseline.values()), 199,
          'administrator regular file count differs')
    equal(sum('target' in row for row in baseline.values()), 1,
          'administrator symlink count differs')

    package = next(row['sha256'] for row in plan['product_packages']
                   if row['path'] == 'packages/syswarden_4.10.3_amd64.deb')
    result = document('result.json')
    equal(result['case'], raw_case, 'different removal entry point')
    equal(result['candidate_package_sha256'], package, 'different native package')
    equal(result['install_returncode'], 0, 'native installation failed')
    equal(result['removal_returncode'], 0, 'native removal failed')
    require_true(result, ('unrelated_root_cron_preserved', 'ui_snapshots_absent',
        'generated_lists_absent', 'created_log_directory_absent',
        'empty_runtime_history_absent', 'empty_runtime_history_backup_complete',
        'pristine_default_templates_absent', 'operator_override_preserved',
        'firewall_active_metadata_absent', 'operator_traffic_preserved',
        'operator_file_preserved', 'operator_rules_preserved',
        'checked_scope_removal_complete', 'fresh_single_candidate_campaign'))
    identity = document('installed-payload-identity.json')
    equal(identity['cli_sha256'], plan['native_payloads']['candidate/opt/syswarden/bin/syswarden-cli'],
          'different installed native executable')
    equal(identity['signed_package_sha256'], package, 'different signed package identity')
    equal(identity['producer_run_id'], plan['product_native_signing']['run_id'],
          'different native signing producer')
    require_true(identity, ('exact_identity_verified',))
    equal(document(raw_case+'-after-configuration-retention.json')['returncode'], 0,
          'removal retry failed')
    retention = document('operator-configuration-retention-verdict.json')
    require_true(retention, ('original_paths_preserved',))
    equal(retention['later_edit_and_deferred_purge_verified'], case == 'remove_then_purge',
          'deferred purge cannot replace independent removal')
    deferred = prefix+'purge-after-remove-and-administrator-edit.json'
    if case == 'remove_then_purge':
        equal(document('purge-after-remove-and-administrator-edit.json')['returncode'], 0,
              'purge after administrator edit failed')
    else:
        require(deferred not in files, 'independent removal contains deferred purge')
    recovery = document('iptables-recovery-verdict.json')
    require_true(recovery, ('original_handle_delta_verified', 'unconfirmed_apply_refused',
        'read_only_inspection_verified', 'repeat_application_verified',
        'exact_administrator_state_preserved'))
    equal(recovery['plan']['retained_rule_count'], 3, 'administrator iptables rules differ')
    equal(recovery['plan']['deletes_shared_table'], False, 'shared table deletion requested')
    equal([row['handle'] for row in recovery['plan']['targets']],
          array('iptables-capture/independent-added-handles.json'),
          'historical deletion targets differ from the independent origin capture')
    require(recovery['plan']['targets'], 'historical removal target set is empty')
    origin = document('iptables-capture/review.json')
    equal(origin['schema'], 'syswarden-historical-iptables-inputs-v1', 'unexpected origin schema')
    equal(origin['generation'], 'v4.02.8', 'historical origin generation differs')
    for row in origin['evidence']:
        equal(frozen.digest(files[prefix+'iptables-capture/'+frozen.relative(row['file'])]),
              row['sha256'], 'historical origin evidence differs')
    for name in ('inspect-legacy-iptables', 'retire-legacy-iptables', 'retry-retire-legacy-iptables'):
        equal(document(name+'.json')['returncode'], 0, 'historical iptables recovery failed')
    require(document('refuse-unconfirmed-iptables.json')['returncode'] != 0,
            'historical iptables deletion did not require confirmation')
    require_true(document('fail2ban-recovery-verdict.json'),
                 ('unrelated_configurations_preserved', 'unrelated_ban_preserved_after_reload',
                  'target_absent_after_reload', 'repeat_application_verified'))
    for name in ('ssh-historical-normalization-verdict.json',
                 'ssh-candidate-normalization-verdict.json'):
        require_true(document(name), ('effective_policy_identical',))
    packets, boots = 0, []
    for phase in ('pre-reboot', 'post-reboot'):
        proof = document(phase+'-persistence-verdict.json')
        equal(proof['phase'], phase, 'different persistence phase')
        require_true(proof, ('fresh_single_candidate_campaign', 'baseline_files_preserved',
            'hardened_loader_preserved', 'original_ssh_jail_active'))
        equal(proof['real_reboot_verified'], phase == 'post-reboot', 'reboot evidence differs')
        equal(proof['boot_before'] != proof['boot_current'], phase == 'post-reboot',
              'real reboot is missing')
        boots.append(proof['boot_current'])
        require_true(document(phase+'-ordering-verdict.json'), ('current_boot_has_no_ordering_cycle',))
        for stage in ('initial', 'shared-reload-0', 'shared-reload-1', 'after-service-reload'):
            traffic = document(phase+'-'+stage+'-traffic.json')
            require_true(traffic, ('all_passed',))
            equal(set(traffic['cases']), set(PACKET_EXPECTATIONS), 'incomplete packet case set')
            for name, row in traffic['cases'].items():
                equal(row['expected'], PACKET_EXPECTATIONS[name], 'incorrect expected packet outcome')
                equal(row['observed'], PACKET_EXPECTATIONS[name], 'packet outcome differs')
                require(not row['server_errors'], 'packet probe encountered server errors')
            packets += 18
        equal(len(proof['after_two_shared_reloads']), 2, 'missing independent shared reload')
        observations = [proof['initial'], *proof['after_two_shared_reloads'],
                        proof['after_service_reload']]
        for observation in observations:
            require_true(observation, ('cron_records_preserved', 'cron_original_inode_retained',
                'operator_module_hash_preserved', 'unrelated_fail2ban_ban_active',
                'exact_receiver_rules_preserved', 'active_product_paths_absent',
                'private_originals_unchanged'))
            ipt = observation['iptables_independent_preservation']
            require_true(ipt, ('exact_administrator_kernel_structure',
                              'exact_administrator_save_rules', 'historical_handles_absent'))
            equal(ipt['same_boot_handles_compared'], phase == 'pre-reboot',
                  'incorrect rule identity comparison across reboot')
            equal(ipt['independent_ipv4_output_packets'],
                  {'127.0.0.6': 'blocked', '127.0.0.7': 'allowed'},
                  'administrator protection is ineffective')
            if phase == 'post-reboot':
                require_true(observation, ('cron_reboot_job_executed',))
    equal(len(set(boots)), 2, 'missing distinct native boots')
    if completed_boots is not None:
        require(boots[1] not in completed_boots, 'independent removal reused a completed boot')
        completed_boots.add(boots[1])
    equal(packets, 144, 'incomplete native packet verification')
    groups = array('legacy-retention-verification.json')
    equal(len(groups), 3, 'incomplete private retention groups')
    equal({row['kind'] for row in groups}, {'lists', 'logs', 'ui'}, 'private retention scope differs')
    originals = read_archive(files[prefix+'private-retirement-backups.tar.gz'], backup=True)
    verified_originals = set()
    for group in groups:
        require_true(group, ('retry_verified',))
        marker = '/legacy-'+group['kind']+'-'+group['plan_sha256']+'-'
        for name, row in group['originals_retained'].items():
            frozen.relative(name)
            matches = [path for path in originals if path.rsplit('/', 1)[-1] == name and marker in path]
            equal(len(matches), 1, 'missing or ambiguous private original')
            require(matches[0] not in verified_originals, 'private original counted twice')
            verified_originals.add(matches[0])
            equal(frozen.digest(originals[matches[0]]), row['sha256'], 'private original bytes differ')
    require(len(verified_originals) >= 12, 'incomplete private original backup verification')
    return dict(case=case, packet_cases=packets, real_reboot_verified=True,
                archive_sha256=anchor['archive_sha256'], private_originals=len(verified_originals))


def verify_removal_archives(plan: dict, objects: dict[str, bytes]) -> list[dict]:
    anchors = plan['removal_archives']
    require(type(anchors) is list and len(anchors) == 4, 'four removal archives are required')
    equal({row['case'] for row in anchors}, set(CASES), 'missing independent removal lifecycle')
    equal(len({row['archive_sha256'] for row in anchors}), 4, 'removal archive reused')
    completed_boots: set[str] = set()
    return [verify_case(plan, row, objects, completed_boots=completed_boots) for row in anchors]
