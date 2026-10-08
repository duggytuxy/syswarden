"""Synthetic adversarial tests for the independent removal evidence consumer."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import unittest

from scripts.ci import release_ivv_v4103_removal as gate


def wire(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def pack(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def rebind(anchor, files):
    """Recompute integrity to exercise semantic rejection independently."""
    anchor, files = copy.deepcopy(anchor), dict(files)
    manifest = {name: dict(size=len(data), sha256=digest(data))
                for name, data in files.items() if name != anchor['manifest_name']}
    files[anchor['manifest_name']] = wire(manifest)
    raw = pack(files)
    anchor.update(archive_sha256=digest(raw), file_count=len(manifest),
                  manifest_sha256=digest(files[anchor['manifest_name']]))
    return anchor, {digest(data): data for data in [raw, *files.values()]}


PLAN = dict(product_candidate='a' * 40,
            product_packages=[dict(path='packages/syswarden_4.10.3_amd64.deb', sha256='b' * 64)],
            native_payloads={'candidate/opt/syswarden/bin/syswarden-cli': 'c' * 64},
            product_native_signing={'run_id': 12345})


def fixture(case):
    """Build invented observations without using operational evidence."""
    raw_case = 'remove' if case == 'remove_then_purge' else case
    suffix = 'remove-only-remove' if case == 'remove' else raw_case
    prefix = 'case-signedaaaaaaaa-' + suffix + '/'
    files = {}

    def document(name, value):
        files[prefix + name] = wire(value)

    result = dict(case=raw_case, candidate_package_sha256='b' * 64,
                  install_returncode=0, removal_returncode=0)
    for field in ('unrelated_root_cron_preserved', 'ui_snapshots_absent',
                  'generated_lists_absent', 'created_log_directory_absent',
                  'empty_runtime_history_absent', 'empty_runtime_history_backup_complete',
                  'pristine_default_templates_absent', 'operator_override_preserved',
                  'firewall_active_metadata_absent', 'operator_traffic_preserved',
                  'operator_file_preserved', 'operator_rules_preserved',
                  'checked_scope_removal_complete', 'fresh_single_candidate_campaign'):
        result[field] = True
    document('result.json', result)
    document('administrator-baseline.json', {
        '/etc/synthetic-administrator/config-' + str(index):
        dict(uid=0, gid=0, inode=index + 1, mode=384, regular=index < 199,
             **({'sha256': 'd' * 64} if index < 199 else
                {'target': '/etc/synthetic-target'} if index == 212 else {}))
        for index in range(213)})
    document('installed-payload-identity.json', dict(cli_sha256='c' * 64,
        signed_package_sha256='b' * 64, producer_run_id=12345, exact_identity_verified=True))
    document(raw_case + '-after-configuration-retention.json', dict(returncode=0))
    document('operator-configuration-retention-verdict.json', dict(original_paths_preserved=True,
        later_edit_and_deferred_purge_verified=case == 'remove_then_purge'))
    if case == 'remove_then_purge':
        document('purge-after-remove-and-administrator-edit.json', dict(returncode=0))
    document('iptables-recovery-verdict.json', dict(original_handle_delta_verified=True,
        unconfirmed_apply_refused=True, read_only_inspection_verified=True,
        repeat_application_verified=True, exact_administrator_state_preserved=True,
        plan=dict(retained_rule_count=3, deletes_shared_table=False, targets=[dict(handle=41)])))
    document('iptables-capture/independent-added-handles.json', [41])
    files[prefix + 'iptables-capture/origin.txt'] = b'Invented historical origin fixture\n'
    document('iptables-capture/review.json', dict(schema='syswarden-historical-iptables-inputs-v1',
        generation='v4.02.8', evidence=[dict(file='origin.txt',
        sha256=digest(files[prefix + 'iptables-capture/origin.txt']))]))
    for action in ('inspect-legacy-iptables', 'retire-legacy-iptables', 'retry-retire-legacy-iptables'):
        document(action + '.json', dict(returncode=0))
    document('refuse-unconfirmed-iptables.json', dict(returncode=1))
    document('fail2ban-recovery-verdict.json', dict(unrelated_configurations_preserved=True,
        unrelated_ban_preserved_after_reload=True, target_absent_after_reload=True,
        repeat_application_verified=True))
    for stage in ('historical', 'candidate'):
        document('ssh-' + stage + '-normalization-verdict.json', dict(effective_policy_identical=True))
    for phase in ('pre-reboot', 'post-reboot'):
        observation = dict(cron_records_preserved=True, cron_original_inode_retained=True,
            operator_module_hash_preserved=True, unrelated_fail2ban_ban_active=True,
            exact_receiver_rules_preserved=True, active_product_paths_absent=True,
            private_originals_unchanged=True, cron_reboot_job_executed=True,
            iptables_independent_preservation=dict(exact_administrator_kernel_structure=True,
                exact_administrator_save_rules=True, historical_handles_absent=True,
                same_boot_handles_compared=phase == 'pre-reboot',
                independent_ipv4_output_packets={'127.0.0.6': 'blocked', '127.0.0.7': 'allowed'}))
        document(phase + '-persistence-verdict.json', dict(phase=phase,
            fresh_single_candidate_campaign=True, baseline_files_preserved=True,
            hardened_loader_preserved=True, original_ssh_jail_active=True,
            real_reboot_verified=phase == 'post-reboot', boot_before=case + '-synthetic-boot-one',
            boot_current=case + ('-synthetic-boot-two' if phase == 'post-reboot' else '-synthetic-boot-one'),
            initial=observation, after_two_shared_reloads=[observation, observation],
            after_service_reload=observation))
        document(phase + '-ordering-verdict.json', dict(current_boot_has_no_ordering_cycle=True))
        for stage in ('initial', 'shared-reload-0', 'shared-reload-1', 'after-service-reload'):
            cases = {}
            for family in ('ipv4', 'ipv6'):
                for protocol in ('icmp', 'tcp', 'udp'):
                    for source, outcome in ((2, 'allowed'), (3, 'blocked'), (4, 'blocked')):
                        cases[f'{family}-{protocol}-{source}'] = dict(expected=outcome,
                            observed=outcome, server_errors=[])
            document(phase + '-' + stage + '-traffic.json', dict(all_passed=True, cases=cases))
    originals, groups = {}, []
    for kind in ('lists', 'logs', 'ui'):
        group = dict(kind=kind, retry_verified=True, plan_sha256=digest(kind.encode()), originals_retained={})
        for index in range(4):
            name = kind + '-' + str(index)
            data = ('Invented private original ' + name).encode()
            originals['backups/legacy-' + kind + '-' + group['plan_sha256'] + '-1/' + name] = data
            group['originals_retained'][name] = dict(sha256=digest(data))
        groups.append(group)
    document('legacy-retention-verification.json', groups)
    files[prefix + 'private-retirement-backups.tar.gz'] = pack(originals)
    anchor = dict(case=case, prefix=prefix, manifest_name='MANIFEST.json')
    anchor, objects = rebind(anchor, files)
    return anchor, objects, files


class RemovalEvidenceTests(unittest.TestCase):
    def test_four_distinct_entry_points(self):
        anchors, objects = [], {}
        for case in ('uninstall', 'remove', 'purge', 'remove_then_purge'):
            anchor, graph, _ = fixture(case)
            anchors.append(anchor)
            objects.update(graph)
        result = gate.verify_removal_archives(dict(PLAN, removal_archives=anchors), objects)
        self.assertEqual(sum(row['packet_cases'] for row in result), 576)
        self.assertEqual({row['case'] for row in result}, set(gate.CASES))

    def test_recomputed_hashes_do_not_hide_semantic_failures(self):
        mutations = (
            ('administrator-baseline.json', lambda d: d.pop(next(iter(d)))),
            ('result.json', lambda d: d.update(checked_scope_removal_complete=False)),
            ('installed-payload-identity.json', lambda d: d.update(producer_run_id=54321)),
            ('pre-reboot-initial-traffic.json', lambda d: d['cases']['ipv4-tcp-3'].update(expected='allowed', observed='allowed')),
            ('post-reboot-persistence-verdict.json', lambda d: d.update(boot_current=d['boot_before'])),
            ('operator-configuration-retention-verdict.json', lambda d: d.update(later_edit_and_deferred_purge_verified=False)),
            ('iptables-recovery-verdict.json', lambda d: d['plan'].update(deletes_shared_table=True)),
            ('iptables-capture/independent-added-handles.json', lambda d: d.append(42)),
            ('fail2ban-recovery-verdict.json', lambda d: d.update(unrelated_ban_preserved_after_reload=False)),
            ('post-reboot-persistence-verdict.json', lambda d: d['after_service_reload'].update(private_originals_unchanged=False)),
        )
        for name, mutate in mutations:
            with self.subTest(member=name):
                anchor, _, files = fixture('remove_then_purge')
                path = anchor['prefix'] + name
                doc = json.loads(files[path]); mutate(doc); files[path] = wire(doc)
                anchor, objects = rebind(anchor, files)
                with self.assertRaises(gate.frozen.PlanError):
                    gate.verify_case(PLAN, anchor, objects)

    def test_missing_or_reused_lifecycle_is_rejected(self):
        anchor, objects, _ = fixture('remove')
        for anchors in ([anchor], [dict(anchor, case=case) for case in gate.CASES]):
            with self.assertRaises(gate.frozen.PlanError):
                gate.verify_removal_archives(dict(PLAN, removal_archives=anchors), objects)

    def test_distinct_archives_cannot_reuse_one_completed_boot(self):
        anchors, objects = [], {}
        for case in ('uninstall', 'remove', 'purge', 'remove_then_purge'):
            anchor, _, files = fixture(case)
            name = anchor['prefix'] + 'post-reboot-persistence-verdict.json'
            proof = json.loads(files[name]); proof['boot_current'] = 'reused-completed-boot'
            files[name] = wire(proof)
            anchor, graph = rebind(anchor, files)
            anchors.append(anchor); objects.update(graph)
        with self.assertRaises(gate.frozen.PlanError):
            gate.verify_removal_archives(dict(PLAN, removal_archives=anchors), objects)

    def test_archive_and_private_original_replacement_is_rejected(self):
        anchor, objects, files = fixture('purge')
        objects[anchor['archive_sha256']] = b'replaced'
        with self.assertRaises(gate.frozen.PlanError):
            gate.verify_case(PLAN, anchor, objects)
        files[anchor['prefix'] + 'private-retirement-backups.tar.gz'] = pack({'unrelated': b'other'})
        anchor, objects = rebind(anchor, files)
        with self.assertRaises(gate.frozen.PlanError):
            gate.verify_case(PLAN, anchor, objects)

    def test_unsafe_or_excessive_members_are_rejected(self):
        for files in ({'../outside': b'x'}, {'/outside': b'x'}, {str(i): b'' for i in range(1001)}):
            with self.assertRaises(gate.frozen.PlanError):
                gate.read_archive(pack(files))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = 'outside'
            archive.addfile(member)
        with self.assertRaises(gate.frozen.PlanError):
            gate.read_archive(output.getvalue())


if __name__ == '__main__':
    unittest.main()
