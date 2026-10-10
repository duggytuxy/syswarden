"""Check current signed RPM lifecycles, packet traces and real renewal windows."""
from __future__ import annotations

from collections import Counter, defaultdict
import re

try:
    from scripts.ci import release_ivv_v4104_evidence as proof
    from scripts.ci import release_ivv_v4104_debian as debian
except ModuleNotFoundError:
    import release_ivv_v4104_evidence as proof
    import release_ivv_v4104_debian as debian

equal, require = proof.equal, proof.require
HELPER = 'b4773497827abdaa6d9ab0ea23e5a05a71c316d590380b55b6cd0a7044887bb8'
REBOOTS = {
    'removed-reboot01': 'PASS_CURRENT_SIGNED_RPM_REMOVAL_REBOOT_AND_IPV6_RENEWAL',
    'standalone-removed-reboot01': 'PASS_CURRENT_SIGNED_STANDALONE_REMOVAL_REBOOT_AND_IPV6_RENEWAL',
    'upgraded-reboot01': 'PASS_CURRENT_SIGNED_RPM_REBOOT_AND_IPV6_RENEWAL',
    'upgraded-removed-reboot01': 'PASS_CURRENT_SIGNED_DEPENDENCY_RETRY_REMOVAL_REBOOT_AND_IPV6_RENEWAL',
    'opt-in-removed-reboot01': 'PASS_CURRENT_SIGNED_OPT_IN_POSTUN_RECOVERY_REBOOT_AND_IPV6_RENEWAL',
}


def scenario(group: proof.Group, directory: str, status: str,
             commands: dict[str, int]) -> dict:
    doc = group.observation(directory)
    equal(doc['status'], status, 'required RPM observation differs')
    equal(doc['product_sha'], proof.PRODUCT, 'RPM observation product differs')
    for name, code in commands.items():
        group.command(directory, doc, name, code)
    return doc


def packet_counts(wire: bytes) -> dict:
    traces = defaultdict(list)
    for line in wire.decode('utf-8').splitlines():
        match = re.match(r'trace id ([0-9a-f]+) ', line)
        if match:
            traces[match.group(1)].append(line)
    counts = Counter()
    for rows in traces.values():
        if not all(any(f'{family} {table} ipv6-control-plane ' in line and
                       '(verdict accept)' in line for line in rows)
                   for family, table in [('netdev', 'syswarden_hw_drop'), ('inet', 'syswarden')]):
            continue
        for label, packet in [('dhcp', 'udp dport 546'),
                              ('router_advertisement', 'icmpv6 type nd-router-advert'),
                              ('neighbour_discovery', 'icmpv6 type nd-neighbor')]:
            if any('packet:' in line and packet in line for line in rows):
                counts[label] += 1
    require(all(counts[label] > 0 for label in
                ('dhcp', 'router_advertisement', 'neighbour_discovery')),
            'real IPv6 packets did not traverse both product hooks')
    return dict(counts)


def verify_protocol(group: proof.Group) -> None:
    directory = 'protocol-upgrade01-evidence-01'
    doc = scenario(group, directory, 'OBSERVED_PENDING_TRACE_VALIDATION',
                   {'product-reload': 0, 'feed-update': 0, 'firewalld-reload': 0,
                    'diagnostic-remove': 0, 'diagnostic-absent-after': 1})
    equal(doc['renewal_after_all_reloads'], True, 'renewal occurred before reloads')
    equal(doc['diagnostic_cleanup'], 'PASS', 'temporary diagnostic rules remain')
    counts = packet_counts(group.data(directory + '/trace.log'))
    verdict = group.document('protocol-upgrade-verdict.json')
    equal(verdict['real_packets_accepted_in_both_product_hooks'], counts,
          'packet counters do not match the original trace')
    require(b'DHCPRENEW' in group.data(directory + '/router-after.log'),
            'actual DHCP renewal is absent')
    times = []
    for index in range(14):
        wire = group.command(directory, doc, 'renewal-' + str(index), 0)
        observed = proof.frozen.strict_json(wire)
        equal(observed['management_routes_preserved'], True, 'management routes changed')
        equal(observed['services'], ['active'] * 3, 'unrelated service stopped')
        equal(observed['selinux'], 'Enforcing', 'SELinux protection was weakened')
        times.append(observed['monotonic_seconds'])
    require(all(b > a for a, b in zip(times, times[1:])) and times[-1] - times[0] >= 130,
            'IPv6 renewal observation window was shortened')


def verify_standard(group: proof.Group) -> None:
    doc = scenario(group, 'standard-clean-evidence-verified',
        'PASS_NATIVE_INSTALL_INITIAL_OBSERVATIONS', {'dnf-install': 0, 'rpm-after': 0})
    equal(doc['administrator_before'], doc['administrator_after'],
          'standard install changed administrator authority')
    equal(len(doc['administrator_after']), 3, 'administrator fixture coverage differs')
    doc = scenario(group, 'standard-upgrade01-evidence-verified',
        'SIGNED_UPGRADE_INSTALLED_REQUIRES_PROTOCOL_REACQUISITION',
        {'dnf-upgrade': 0, 'current-rpm': 0, 'network-after': 0})
    equal(doc['binaries'], debian.BINARIES, 'RPM upgrade executable identity differs')
    equal(doc['changed_existing_files'], [], 'upgrade changed protected files')
    equal(doc['native_pipeline_completed'], True, 'native upgrade pipeline is incomplete')
    scenario(group, 'standard-native-removal01-evidence-initial',
        'FAILED_REQUIRES_INSPECTION', {'standalone-authority-guard': 1, 'dnf-remove': 1})
    doc = scenario(group, 'inactive-config-recovery01-evidence-verified',
        'PASS_CURRENT_SIGNED_INACTIVE_BACKUP_RECOVERY_AND_NATIVE_ERASE',
        {'wrong-review-refused': 1, 'inactive-backup-apply': 0,
         'inactive-backup-exact-retry': 0, 'dnf-retry': 0, 'rpm-after': 1})
    equal(doc['backup_unchanged_after_erase'], True, 'inactive configuration backup changed')
    equal(doc['rpm_registered_after'], False, 'native erase retained package registration')
    for phase in ('install', 'uninstall'):
        scenario(group, 'standalone02-' + phase + '-evidence-verified',
            'PASS_CURRENT_SIGNED_PAYLOAD_STANDALONE_' + phase.upper(),
            {'rpm-absent-before': 1, 'standalone-' + phase: 0, 'rpm-absent-after': 1})
    scenario(group, 'fence-guards02-evidence-verified',
        'PASS_SIGNED_PAUSED_MUTATOR_REFUSAL_AND_INTERRUPTION_BARRIER',
        {'concurrent-removal': 1, 'barrier-reload': 1, 'barrier-update-feeds': 1})
    doc = scenario(group, 'upgraded-retention02-evidence-verified',
        'PASS_CURRENT_SIGNED_UPGRADED_RPM_RETENTION_AND_NATIVE_ERASE',
        {'dependency-absent-before': 1, 'dnf-remove-retry': 0,
         'wireguard-dependency-still-absent': 1, 'rpm-absent': 1,
         'firewalld-reload': 0, 'network-after': 0})
    equal(doc['signed_retry_without_dependency_reinstallation'], True,
          'removal retry relied on restoring the missing dependency')
    equal(set(doc['retained']), {'retain-legacy-lists', 'retain-legacy-config',
          'retain-legacy-logs', 'retain-legacy-ui'}, 'legacy retention coverage differs')


def verify_optional(group: proof.Group) -> None:
    scenario(group, 'rhelpo-current02-evidence-initial', 'FAILED_REQUIRES_INSPECTION',
        {'dnf-install': 0, 'rpm-identity': 0, 'explicit-start': 1})
    scenario(group, 'rhelpo-current03-evidence-initial', 'FAILED_REQUIRES_INSPECTION',
        {'rpm-payload-before-start': 0, 'explicit-start': 0, 'feed-refresh': 0})
    installed = scenario(group, 'rhelpo-current04-evidence-verified',
        'PASS_CURRENT_OPT_IN_RPM_INSTALL_AND_EXPLICIT_START',
        {'rpm-payload': 0, 'services-active': 0, 'network-after': 0})
    equal(installed['transaction_did_not_start_product'], True,
          'optional package activated itself during installation')
    scenario(group, 'rhelpo-removal02-evidence-verified',
        'READY_FOR_REVIEWED_OPT_IN_OPERATOR_RETENTION',
        {'native-erase-before-runtime-retirement': 1, 'rpm-payload-after-preun-refusal': 0,
         'explicit-runtime-uninstall': 1})
    original = 'rhelpo-removal03-evidence-original'
    doc = scenario(group, original, 'FAILED_REQUIRES_INSPECTION',
        {'operator-wrong-digest': 1, 'operator-retention-apply': 0,
         'operator-retention-repeat': 0, 'signed-uninstall-retry': 0,
         'signed-uninstall-idempotent-retry': 0, 'rpm-payload-after-runtime-uninstall': 0,
         'native-preun-unreviewed-configuration': 1, 'rpm-payload-after-configuration-refusal': 0,
         'native-erase-interrupted-postun': 0, 'rpm-absent-after-postun': 1,
         'signed-helper-recovery': 0, 'rpm-final-absence': 1})
    equal(doc['error'], "AssertionError('/etc/firewalld/zones/trusted.xml.old')",
          'original generated-history assertion was replaced')
    equal(doc['postun_fault']['signed_payload_unchanged'], True, 'fault changed signed payload')
    equal(doc['signed_helper_sha256'], HELPER, 'different helper recovered POSTUN failure')
    logs = group.data(original + '/native-erase-interrupted-postun.stdout') + group.data(
        original + '/native-erase-interrupted-postun.stderr')
    require(b'scriptlet failed' in logs, 'successful package-manager status hid POSTUN failure')
    final = 'rhelpo-removal04-evidence-verified'
    doc = scenario(group, final,
        'PASS_SIGNED_OPT_IN_RETRY_PREUN_REFUSAL_POSTUN_RECOVERY_AND_ADMIN_EDIT',
        {'firewalld-code-integrity': 0, 'rpm-absence': 1, 'network': 0, 'services': 0})
    for key in ('original_failure_preserved', 'active_firewalld_policy_exactly_restored',
                'generated_history_not_loaded', 'original_inactive_history_preserved_in_evidence'):
        equal(doc[key], True, 'optional removal verification is incomplete: ' + key)
    equal(doc['signed_helper_sha256'], HELPER, 'recovery helper binding changed')
    equal(len(doc['operator_configurations']), 5, 'later administrator configuration was lost')
    equal(set(doc['generated_zone_history']), {'/etc/firewalld/zones/trusted.xml.old'},
          'unexpected shared-service file changed')
    for mode in ('runtime', 'permanent'):
        equal(group.data(final + '/firewalld-' + mode + '.stdout'),
              group.data('rhelpo-current02-evidence-initial/firewalld-' + mode + '-before.stdout'),
              'active or persistent administrator zone policy changed')
    equal(group.data(final + '/selinux.stdout'), b'Enforcing\n', 'SELinux is not enforcing')


def verify_reboots(group: proof.Group) -> None:
    completed = set()
    for directory, status in REBOOTS.items():
        doc = group.reboot(directory, status)
        require(doc['after_boot'] not in completed, 'separate native reboot proof was reused')
        completed.add(doc['after_boot'])
        for index in range(14):
            observed = group.document(directory + '/renewal-' + str(index) + '.stdout')
            equal(observed['management_routes_preserved'], True, 'reboot changed management routes')
            equal(observed['services'], ['active'] * 3, 'reboot stopped unrelated services')
            equal(observed['selinux'], 'Enforcing', 'reboot weakened SELinux')
            if directory == 'upgraded-reboot01':
                equal(observed['syswarden_installed'], True, 'upgrade payload did not survive reboot')
                equal(observed['product_binary_provenance'], 'PASS', 'post-boot payload differs')
                equal(observed['ipv6_first_dispatch_both_hooks'], True, 'IPv6 dispatch changed at boot')
            else:
                equal(observed['product_absent'], True, 'removed product returned at boot')
                equal(observed['firewalld_policy_restored'], True, 'firewalld policy did not survive')
                equal(observed['broad_product_residual_scan'], 'PASS', 'product residuals remain')
                equal(observed['retained_configuration_files'],
                      5 if directory == 'opt-in-removed-reboot01' else 4,
                      'acknowledged administrator configurations differ')
