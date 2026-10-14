"""Reject misleading success labels and policy loss in Debian IVV evidence."""
import copy
import json
import unittest

from scripts.ci import release_ivv_v4104_debian as subject


def rules(policy='drop', meter=None, extra=None):
    rows = [{'table': {'family': 'inet', 'name': 'filter', 'handle': 1}},
            {'chain': {'family': 'inet', 'table': 'filter', 'name': 'forward',
                       'hook': 'forward', 'policy': policy, 'handle': 2}},
            {'set': {'family': 'inet', 'table': 'filter', 'name': 'ssh4',
                     'flags': ['timeout', 'dynamic'], 'elem': meter or []}},
            {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'forward',
                      'expr': [{'counter': {'packets': 10, 'bytes': 500}}, {'drop': None}]}}]
    if extra:
        rows.append(extra)
    return json.dumps({'nftables': rows}).encode()


class ObservationGroup:
    """Synthetic observations, with raw byte binding tested by the evidence reader."""

    def __init__(self):
        retained = dict(operator_config_preserved={'one': {}, 'two': {}, 'three': {}},
            retained_lists=dict(files=list(range(10)), original_inodes_and_bytes_preserved=True))
        names = {
            'apt-remove01-evidence-initial': 'NATIVE_REMOVAL_REFUSED_REQUIRES_REVIEW',
            'legacy-retention01-evidence-verified':
                'PASS_NATIVE_APT_REMOVE_WITH_VERIFIED_LEGACY_RETENTION_RELOAD_REBOOT_PENDING',
            'deferred-purge01-evidence-verified': 'PASS_DEFERRED_NATIVE_PURGE',
            'direct-purge02-evidence-final': 'FAILED_REQUIRES_INSPECTION',
            'standalone02-uninstall-evidence-final': 'PASS_STANDALONE_UNINSTALL',
        }
        self.docs = {name: dict(status=status, product_sha=subject.proof.PRODUCT,
                               **copy.deepcopy(retained)) for name, status in names.items()}
        self.docs['deferred-purge01-evidence-verified']['administrator_edit'] = dict(
            inode_replaced=True, before_sha256='a' * 64, after_sha256='b' * 64)
        self.docs['direct-purge02-evidence-final']['error'] = (
            "AssertionError('Inspect direct purge evidence: apt-direct-purge-initial')")
        self.streams = {}
        for case, directories in subject.REMOVAL_PATHS.items():
            for directory, phase in zip(directories, ('reload', 'reboot', 'verify')):
                self.docs[directory] = dict(status='PASS_' +
                    ('REMOVED' if case == 'remove' else 'PURGED') + '_' + phase.upper(),
                    phase=phase, protected_files=188, package_payload_checked=12,
                    operator_files_retained=3, inactive_legacy_files_retained=10,
                    boot_id=case + ('-after' if phase == 'verify' else '-before'))
                self.streams[directory, 'package'] = (
                    b'deinstall ok config-files 4.10.4' if case == 'remove' else b'')
                self.streams[directory, 'dpkg-audit'] = b''
                self.streams[directory, 'ruleset'] = rules()
                for unit in subject.SERVICES:
                    self.streams[directory, 'active-' + unit] = b'active\n'

    def observation(self, directory, filename='state.json'):
        return self.docs[directory]

    def data(self, name):
        return rules()

    def command(self, directory, doc, name, code, prefix=None):
        return self.streams.get((directory, name), b'')


class DebianTests(unittest.TestCase):
    def test_reinstallation_requires_consistent_package_and_live_protection(self):
        directory = 'reinstall01-evidence-verified'
        group = ObservationGroup()
        group.docs[directory] = dict(
            status='PASS_NATIVE_REINSTALL_AFTER_PURGE_AND_SAME_VERSION',
            product_sha=subject.proof.PRODUCT, administrator_files=190,
            after_install={'protected_files': 190}, after_reinstall={'protected_files': 190})
        for phase in ('installed', 'reinstalled'):
            group.streams[directory, phase + '-package'] = b'install ok installed 4.10.4'
            group.streams[directory, phase + '-audit'] = b''
            for service in (*subject.SERVICES, 'syswarden-core.service', 'wg-quick@wg-syswarden.service'):
                group.streams[directory, phase + '-' + service] = b'active\n'
        subject.verify_reinstall(group)
        for name, value in [('reinstalled-package', b'install ok half-configured 4.10.4'),
                            ('installed-audit', b'Package configuration is incomplete'),
                            ('reinstalled-fail2ban.service', b'inactive\n'),
                            ('installed-wg-quick@wg-syswarden.service', b'failed\n')]:
            changed = copy.deepcopy(group)
            changed.streams[directory, name] = value
            with self.subTest(name=name), self.assertRaises(subject.frozen.PlanError):
                subject.verify_reinstall(changed)

    def test_filter_normalization_preserves_security_semantics(self):
        self.assertEqual(subject.administrator_filter(rules(meter=['test-a'])),
                         subject.administrator_filter(rules(meter=['test-b'])))
        self.assertNotEqual(subject.administrator_filter(rules()),
                            subject.administrator_filter(rules(policy='accept')))
        wrong = json.loads(rules())
        wrong['nftables'][2]['set']['flags'] = ['constant']
        with self.assertRaises(subject.frozen.PlanError):
            subject.administrator_filter(json.dumps(wrong).encode())

    def test_four_separate_observations_and_retained_original_failure(self):
        subject.verify_removal(ObservationGroup())

    def test_success_labels_do_not_override_lost_protection_or_residuals(self):
        last = subject.REMOVAL_PATHS['purge'][2]
        mutations = [
            lambda g: g.streams.update({(last, 'ruleset'): rules(policy='accept')}),
            lambda g: g.streams.update({(last, 'ruleset'): rules(extra={
                'table': {'family': 'inet', 'name': 'syswarden_wg'}})}),
            lambda g: g.streams.update({(last, 'dpkg-audit'): b'half-configured\n'}),
            lambda g: g.streams.update({(last, 'active-fail2ban.service'): b'inactive\n'}),
            lambda g: g.docs[last].update(protected_files=187),
            lambda g: g.docs[last].update(operator_files_retained=0),
            lambda g: g.docs[last].update(boot_id='remove-after'),
            lambda g: g.docs[last].update(boot_id='purge-before'),
            lambda g: g.docs['direct-purge02-evidence-final'].update(status='PASS'),
            lambda g: g.docs['deferred-purge01-evidence-verified']['administrator_edit'].update(
                inode_replaced=False),
            lambda g: g.docs['standalone02-uninstall-evidence-final'].update(product_sha='1' * 40),
        ]
        for index, mutate in enumerate(mutations):
            group = ObservationGroup()
            mutate(group)
            with self.subTest(mutation=index), self.assertRaises(subject.frozen.PlanError):
                subject.verify_removal(group)


if __name__ == '__main__':
    unittest.main()
