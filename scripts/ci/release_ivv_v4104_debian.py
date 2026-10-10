"""Verify the signed migration and four independent Debian removal observations."""
from __future__ import annotations

try:
    from scripts.ci import release_ivv_v4104_evidence as proof
except ModuleNotFoundError:
    import release_ivv_v4104_evidence as proof

equal, require, frozen = proof.equal, proof.require, proof.frozen
BINARIES = {
    'syswarden-cli': 'afed7f087f63af4b9d0fbcaae48c8f134e1dbc7884a4654fef836d992f4a99ff',
    'syswarden-core': 'a3eb5b4a9de365b5f7173645afbf55c471083408a15c67ad39a2aa3239514d0a',
    'syswarden-tui': '2bf7a4eaef528f4f7bb7ebbc56932ec430cd07654854f3b2ab02d1c5e3df6282',
}
SERVICES = ('ssh.service', 'nftables.service', 'fail2ban.service')
REMOVAL_PATHS = {
    'remove': ('removed-reload-evidence-final', 'removed-reboot-evidence-final',
               'removed-verify03-evidence-verified'),
    'deferred-purge': ('purged-reload02-evidence-final', 'purged-reboot-evidence-final',
                       'purged-verify01-evidence-verified'),
    'purge': ('direct-purged-reload-evidence-final', 'direct-purged-reboot-evidence-final',
              'direct-purged-verify02-evidence-final'),
    'uninstall': ('standalone-removed-r2-reload-evidence-final',
                  'standalone-removed-r2-reboot-evidence-final',
                  'standalone-removed-r2-verify02-evidence-final'),
}


def administrator_filter(wire: bytes) -> list[dict]:
    """Ignore counters and two known dynamic meter contents, never rule semantics."""
    output = []
    for row in frozen.strict_json(wire)['nftables']:
        require(type(row) is dict and len(row) == 1, 'malformed nftables observation')
        kind, value = next(iter(row.items()))
        if type(value) is not dict or value.get('family') != 'inet':
            continue
        if not ((kind == 'table' and value.get('name') == 'filter') or
                value.get('table') == 'filter'):
            continue
        value = dict(value)
        value.pop('handle', None)
        if kind == 'set' and value.get('name') in ('ssh4', 'ssh6'):
            equal(value.get('flags'), ['timeout', 'dynamic'], 'meter is not dynamic')
            value.pop('elem', None)
        if kind == 'rule':
            value['expr'] = [{'counter': None} if 'counter' in item else item
                             for item in value['expr']]
        output.append({kind: value})
    require(output, 'administrator filter is absent')
    return output


def no_product_tables(wire: bytes) -> None:
    for row in frozen.strict_json(wire)['nftables']:
        table = row.get('table')
        if table:
            require(not table['name'].startswith('syswarden'),
                    'product firewall table remains after removal')


def require_status(group: proof.Group, directory: str, status: str) -> dict:
    doc = group.observation(directory)
    equal(doc['status'], status, 'required Debian scenario did not complete')
    equal(doc['product_sha'], proof.PRODUCT, 'Debian scenario product differs')
    return doc


def retained_configuration(doc: dict) -> None:
    equal(len(doc['operator_config_preserved']), 3, 'operator configuration is missing')
    retained = doc['retained_lists']
    equal(len(retained['files']), 10, 'inactive legacy inventory differs')
    equal(retained['original_inodes_and_bytes_preserved'], True,
          'inactive legacy bytes or identity changed')


def verify_migration(group: proof.Group) -> None:
    guards = 'migration-guards-evidence-initial'
    doc = require_status(group, guards, 'PASS_INSTALLED_STABLE_UPDATER_NEGATIVE_GUARDS')
    for name in ('invalid-signature', 'changed-package'):
        group.command(guards, doc, name, 1)
    equal(group.data(guards + '/services-before.stdout'),
          group.data(guards + '/services-after.stdout'), 'negative update changed services')
    migration = 'migration-upgrade-evidence-initial'
    doc = require_status(group, migration, 'PASS_SIGNED_STABLE_TO_CANDIDATE_MIGRATION_INITIAL')
    equal(doc['previous_version'], 'v4.10.3', 'wrong Debian migration source')
    equal(doc['target_version'], 'v4.10.4', 'wrong Debian migration target')
    equal(doc['before']['package'], 'install ok installed 4.10.3', 'old package not installed')
    equal(doc['after']['package'], 'install ok installed 4.10.4', 'target package not configured')
    equal(doc['after']['binaries'], BINARIES, 'signed executable identity differs')
    equal(doc['before']['files'], doc['after']['files'], 'migration changed protected files')
    equal(len(doc['after']['files']), 200, 'migration protected inventory differs')
    equal(doc['after']['barrier'], False, 'migration left a removal barrier')
    group.command(migration, doc, 'signed-upgrade', 0)
    group.command(migration, doc, 'online-feed-refresh', 0)
    equal(group.command(migration, doc, 'dpkg-audit-after', 0), b'', 'dpkg audit failed')
    boots = []
    for directory, phase in [('candidate-reload-evidence-verified', 'reload'),
                             ('candidate-verify-reboot-evidence-verified', 'verify-reboot')]:
        result = group.observation(directory, 'result.json')
        equal(result['status'], 'PASS_CANDIDATE_' + phase.upper().replace('-', '_'),
              'candidate reload or reboot was not verified')
        equal(result['product_sha'], proof.PRODUCT, 'reload checked another candidate')
        equal(result['protected_files_unchanged'], 200, 'reload lost protected files')
        equal(result['administrator_forward_chain_unchanged'], True, 'forward policy changed')
        for unit in (*SERVICES, 'syswarden-core.service', 'wg-quick@wg-syswarden.service'):
            equal(group.command(directory, result, 'service-' + unit, 0), b'active\n',
                  'required service did not survive migration')
        equal(group.command(directory, result, 'audit', 0), b'', 'dpkg audit is not clean')
        boots.append(result['boot_id'])
    require(boots[0] != boots[1], 'migration reboot was not observed')


def verify_removal(group: proof.Group) -> None:
    refusal = 'apt-remove01-evidence-initial'
    doc = require_status(group, refusal, 'NATIVE_REMOVAL_REFUSED_REQUIRES_REVIEW')
    group.command(refusal, doc, 'native-uninstall-refusal', 1)
    group.command(refusal, doc, 'apt-remove', 100, ['apt-get'])
    baseline = administrator_filter(group.data(refusal + '/before-ruleset.stdout'))
    remove = 'legacy-retention01-evidence-verified'
    doc = require_status(group, remove,
        'PASS_NATIVE_APT_REMOVE_WITH_VERIFIED_LEGACY_RETENTION_RELOAD_REBOOT_PENDING')
    retained_configuration(doc)
    group.command(remove, doc, 'wrong-review-refused', 1)
    for command in ('legacy-lists-apply', 'legacy-lists-retry', 'operator-config-apply',
                    'apt-remove-retry'):
        group.command(remove, doc, command, 0)
    deferred = 'deferred-purge01-evidence-verified'
    doc = require_status(group, deferred, 'PASS_DEFERRED_NATIVE_PURGE')
    retained_configuration(doc)
    edit = doc['administrator_edit']
    equal(edit['inode_replaced'], True, 'deferred purge did not test a later replacement')
    require(edit['before_sha256'] != edit['after_sha256'], 'deferred edit bytes did not change')
    group.command(deferred, doc, 'apt-purge', 0, ['apt-get'])
    direct = 'direct-purge02-evidence-final'
    doc = require_status(group, direct, 'FAILED_REQUIRES_INSPECTION')
    equal(doc['error'], "AssertionError('Inspect direct purge evidence: apt-direct-purge-initial')",
          'original direct purge harness failure was replaced')
    group.command(direct, doc, 'apt-direct-purge-initial', 0, ['apt-get'])
    standalone = 'standalone02-uninstall-evidence-final'
    doc = require_status(group, standalone, 'PASS_STANDALONE_UNINSTALL')
    retained_configuration(doc)
    group.command(standalone, doc, 'standalone-uninstall', 0,
                  ['/usr/local/bin/syswarden', 'uninstall'])
    completed_boots = set()
    for case, directories in REMOVAL_PATHS.items():
        boot_ids = []
        for directory, phase in zip(directories, ('reload', 'reboot', 'verify')):
            doc = group.observation(directory, 'result.json')
            prefix = 'REMOVED' if case == 'remove' else 'PURGED'
            equal(doc['status'], 'PASS_' + prefix + '_' + phase.upper(),
                  'separate removal phase is incomplete')
            equal(doc['phase'], phase, 'removal phase was relabeled')
            equal(doc['protected_files'], 188, 'administrator inventory differs')
            equal(doc['package_payload_checked'], 12, 'payload absence check is incomplete')
            equal(doc['operator_files_retained'], 3, 'administrator configurations were removed')
            equal(doc['inactive_legacy_files_retained'], 10, 'private recovery backup differs')
            package = group.command(directory, doc, 'package', 0 if case == 'remove' else 1,
                                    ['dpkg-query', '-W'])
            equal(package, b'deinstall ok config-files 4.10.4' if case == 'remove' else b'',
                  'unexpected package-manager residual state')
            equal(group.command(directory, doc, 'dpkg-audit', 0), b'', 'dpkg remains inconsistent')
            for unit in SERVICES:
                equal(group.command(directory, doc, 'active-' + unit, 0), b'active\n',
                      'unrelated protection was stopped')
            rules = group.command(directory, doc, 'ruleset', 0, ['nft', '-a', '-j', 'list', 'ruleset'])
            no_product_tables(rules)
            equal(administrator_filter(rules), baseline, 'administrator firewall policy changed')
            boot_ids.append(doc['boot_id'])
        equal(boot_ids[0], boot_ids[1], 'reboot request started on another boot')
        require(boot_ids[1] != boot_ids[2] and boot_ids[2] not in completed_boots,
                'independent removal reboot evidence was reused')
        completed_boots.add(boot_ids[2])


def verify_reinstall(group: proof.Group) -> None:
    directory = 'reinstall01-evidence-verified'
    doc = require_status(group, directory, 'PASS_NATIVE_REINSTALL_AFTER_PURGE_AND_SAME_VERSION')
    equal(doc['administrator_files'], 190, 'reinstall protected inventory differs')
    group.command(directory, doc, 'package-before', 1, ['dpkg-query'])
    for command in ('native-install-after-purge', 'native-same-version-reinstall'):
        group.command(directory, doc, command, 0, ['apt-get'])
    for phase in ('installed', 'reinstalled'):
        equal(group.command(directory, doc, phase + '-package', 0),
              b'install ok installed 4.10.4', 'native reinstall remains incomplete')
        equal(group.command(directory, doc, phase + '-audit', 0), b'',
              'native reinstall left an inconsistent package database')
        for service in (*SERVICES, 'syswarden-core.service', 'wg-quick@wg-syswarden.service'):
            equal(group.command(directory, doc, phase + '-' + service, 0), b'active\n',
                  'reinstall lost product or administrator service')
    for phase in ('after_install', 'after_reinstall'):
        equal(doc[phase]['protected_files'], 190, 'reinstall changed protected files')


def verify_vpn(group: proof.Group) -> None:
    """Bind the exact probe and its observed four directional packet counters."""
    source = group.data('wireguard-transit-remote-r2.py')
    equal(frozen.digest(source),
          'b27fe0a3c12ed0812a8af4fab5d814cfe34da9138f73ff8e034ac01c94994130', 'unreviewed encrypted transit probe')
    migration = group.document('migration-upgrade-evidence-initial/state.json')
    clients = [row['sha256'] for path, row in migration['before']['files'].items()
               if path.endswith('/clients/admin-pc.conf')]
    require(len(clients) == 1, 'original client binding is ambiguous')
    starts = []
    for phase in ('before', 'after'):
        directory = 'wireguard-transit-' + phase + '-reboot-r2-evidence-verified'
        doc = group.observation(directory, 'result.json')
        equal(doc['status'], 'PASS_NATIVE_ENCRYPTED_TRANSIT_AND_NAT', 'VPN probe failed')
        equal(doc['original_client_sha256'], clients[0], 'VPN client continuity differs')
        for field in ('encrypted_transit', 'public_dns_over_nat', 'original_client_unchanged',
                      'administrator_forward_chain_restored_exactly', 'fixture_removed',
                      'management_ipv4_routes_preserved'):
            equal(doc[field], True, 'VPN probe or fixture cleanup is incomplete')
        equal(doc['forward_policy'], 'drop', 'probe weakened administrator forward policy')
        rows = doc['test_rule_counters']
        equal(len(rows), 4, 'probe direction coverage is incomplete')
        equal({row['comment'].rsplit('-', 2)[-2] + '-' + row['comment'].rsplit('-', 1)[-1]
               for row in rows}, {'0-out', '0-return', '1-out', '1-return'},
              'probe duplicated a direction')
        for row in rows:
            counters = [item['counter'] for item in row['expr'] if 'counter' in item]
            require(len(counters) == 1 and type(counters[0]['packets']) is int and
                    counters[0]['packets'] > 0 and counters[0]['bytes'] > 0,
                    'probe has no observed traffic in one direction')
        require(doc['started_utc'] < doc['completed_utc'], 'invalid VPN observation interval')
        starts.append(doc['started_utc'])
    require(starts[0] < starts[1], 'VPN observation ordering differs')
