"""Require actual packet acceptance and preserved protection after every reboot."""
import copy
import unittest

from scripts.ci import release_ivv_v4104_alma as subject


def trace():
    lines = []
    packets = ['udp dport 546', 'icmpv6 type nd-router-advert', 'icmpv6 type nd-neighbor-solicit']
    for number, packet in enumerate(packets):
        prefix = 'trace id ' + format(number + 1, 'x') + ' '
        lines.append(prefix + 'netdev diagnostic ingress packet: ' + packet)
        for family, table in [('netdev', 'syswarden_hw_drop'), ('inet', 'syswarden')]:
            lines.append(prefix + family + ' ' + table + ' ipv6-control-plane rule (verdict accept)')
    return '\n'.join(lines).encode()


class RebootGroup:
    def __init__(self):
        self.verdicts = {name: dict(after_boot=name + '-new') for name in subject.REBOOTS}
        self.observations = {}
        for name in subject.REBOOTS:
            for index in range(14):
                doc = dict(management_routes_preserved=True, services=['active'] * 3,
                    selinux='Enforcing', administrator_policy_preserved=True)
                if name == 'upgraded-reboot01':
                    doc.update(syswarden_installed=True, product_binary_provenance='PASS',
                               ipv6_first_dispatch_both_hooks=True)
                else:
                    doc.update(product_absent=True, firewalld_policy_restored=True,
                        broad_product_residual_scan='PASS',
                        retained_configuration_files=5 if name.startswith('opt-in') else 4)
                self.observations[name + '/renewal-' + str(index) + '.stdout'] = doc

    def reboot(self, directory, status):
        return self.verdicts[directory]

    def document(self, name):
        return self.observations[name]


class AlmaTests(unittest.TestCase):
    def test_packets_must_match_both_hooks_under_one_trace_identity(self):
        self.assertEqual(subject.packet_counts(trace()), {
            'dhcp': 1, 'router_advertisement': 1, 'neighbour_discovery': 1})
        for changed in (
            trace().replace(b'inet syswarden ', b'inet administrator '),
            trace().replace(b'(verdict accept)', b'(verdict continue)'),
            trace().replace(b'packet:', b'rule:'),
            trace().replace(b'trace id 1 inet', b'trace id ff inet'),
            trace().replace(b'udp dport 546', b'udp sport 546'),
        ):
            with self.subTest(trace=changed), self.assertRaises(subject.proof.frozen.PlanError):
                subject.packet_counts(changed)

    def test_five_distinct_reboots_and_protection(self):
        subject.verify_reboots(RebootGroup())

    def test_failure_at_any_renewal_sample_is_not_hidden_by_final_pass(self):
        mutations = [('selinux', 'Permissive'), ('management_routes_preserved', False),
                     ('services', ['active', 'inactive', 'active']), ('product_absent', False),
                     ('firewalld_policy_restored', False), ('broad_product_residual_scan', 'FAILED'),
                     ('retained_configuration_files', 0)]
        for field, value in mutations:
            group = RebootGroup()
            group.observations['opt-in-removed-reboot01/renewal-7.stdout'][field] = value
            with self.subTest(field=field), self.assertRaises(subject.proof.frozen.PlanError):
                subject.verify_reboots(group)
        group = RebootGroup()
        group.verdicts['opt-in-removed-reboot01'] = copy.deepcopy(group.verdicts['removed-reboot01'])
        with self.assertRaises(subject.proof.frozen.PlanError):
            subject.verify_reboots(group)


if __name__ == '__main__':
    unittest.main()
