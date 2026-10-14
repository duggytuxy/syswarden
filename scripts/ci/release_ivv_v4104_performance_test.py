"""Reject replay shortcuts, incomplete measurements and misleading rate metrics."""
import copy
import unittest

from scripts.ci import release_ivv_v4104_performance as subject


class PerformanceTests(unittest.TestCase):
    def sample(self):
        return dict(role='candidate', round=0, family=6, responses=2000,
                    samples_us=[12.5] * 2000, request_rtt_seconds=0.025,
                    elapsed_seconds=0.1, requests_per_second=20000.0, p95_us=12.5)

    def test_elapsed_capacity_and_raw_latency_are_independent(self):
        subject.trial(self.sample(), 'candidate', 0, 6)
        changes = [('responses', 1999), ('samples_us', [12.5] * 1999),
                   ('samples_us', [True] * 2000), ('requests_per_second', 80000.0),
                   ('p95_us', 10.0), ('elapsed_seconds', 21.0), ('family', 4)]
        for key, value in changes:
            row = self.sample()
            row[key] = value
            with self.subTest(field=key), self.assertRaises(subject.frozen.PlanError):
                subject.trial(row, 'candidate', 0, 6)

    def test_replay_preserves_membership_and_rule_order(self):
        original = {'nftables': [
            {'table': {'family': 'netdev', 'name': 'syswarden_hw_drop', 'handle': 9}},
            {'chain': {'family': 'netdev', 'table': 'syswarden_hw_drop', 'name': 'ingress',
                       'hook': 'ingress', 'dev': 'original0', 'handle': 8}},
            {'set': {'family': 'netdev', 'table': 'syswarden_hw_drop',
                     'name': 'syswarden_blacklist', 'elem': ['203.0.113.1'], 'handle': 7}},
            {'rule': {'family': 'netdev', 'table': 'syswarden_hw_drop', 'chain': 'ingress',
                      'expr': [{'counter': {'bytes': 900, 'packets': 10}}, {'drop': None}], 'handle': 6}},
            {'table': {'family': 'inet', 'name': 'administrator', 'handle': 5}},
        ]}
        before = copy.deepcopy(original)
        replay = subject.replay(original)
        self.assertEqual(original, before)
        self.assertEqual(len(replay['nftables']), 4)
        self.assertEqual(replay['nftables'][1]['add']['chain']['dev'], 'swp4104rx')
        self.assertEqual(replay['nftables'][2]['add']['set']['elem'], ['203.0.113.1'])
        self.assertEqual(replay['nftables'][3]['add']['rule']['expr'],
                         [{'counter': {'bytes': 0, 'packets': 0}}, {'drop': None}])

    def test_benchmark_cannot_hide_inside_a_whitelist_or_blocklist(self):
        for member in ['198.18.0.2', {'prefix': {'addr': '2001:db8:4104::', 'len': 64}},
                       {'range': ['198.18.0.1', '198.18.0.20']}]:
            policy = {'nftables': [{'add': {'set': {
                'name': 'syswarden_whitelist', 'elem': [member]}}}]}
            with self.subTest(member=member), self.assertRaises(subject.frozen.PlanError):
                subject.peers_not_exempted(policy)


if __name__ == '__main__':
    unittest.main()
