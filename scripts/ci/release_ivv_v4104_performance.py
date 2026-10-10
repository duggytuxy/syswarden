"""Recompute the bounded kernel comparison from exact policies and raw samples."""
from __future__ import annotations

from collections import defaultdict
import ipaddress
import re
import statistics

try:
    from scripts.ci import release_ivv_v4104_evidence as proof
except ModuleNotFoundError:
    import release_ivv_v4104_evidence as proof

equal, require, frozen = proof.equal, proof.require, proof.frozen
HOOKS = {('netdev', 'syswarden_hw_drop'), ('inet', 'syswarden')}
PEERS = ('198.18.0.2', '2001:db8:4104::2')


def replay(source: dict) -> dict:
    def clean(value):
        if type(value) is list:
            return [clean(item) for item in value]
        if type(value) is dict:
            return {key: ({'packets': 0, 'bytes': 0} if key == 'counter' else clean(item))
                    for key, item in value.items() if key != 'handle'}
        return value
    rows = []
    for row in source['nftables']:
        require(type(row) is dict and len(row) == 1, 'invalid source policy row')
        kind, value = next(iter(row.items()))
        if type(value) is not dict:
            continue
        table = value.get('name') if kind == 'table' else value.get('table')
        if (value.get('family'), table) not in HOOKS:
            continue
        value = clean(value)
        if kind == 'chain' and value.get('hook') == 'ingress':
            value['dev'] = 'swp4104rx'
        rows.append({'add': {kind: value}})
    require(rows, 'captured product policy is absent')
    return {'nftables': rows}


def trial(doc: dict, role: str, index: int, family: int) -> None:
    equal([doc['role'], doc['round'], doc['family']], [role, index, family],
          'performance sample was assigned to another round')
    equal(doc['responses'], 2000, 'performance requests were lost')
    values = doc['samples_us']
    require(type(values) is list and len(values) == 2000 and
            all(type(value) in (int, float) and value > 0 for value in values),
            'raw positive latency samples are incomplete')
    require(0 < doc['request_rtt_seconds'] <= doc['elapsed_seconds'] < 20,
            'performance elapsed-time bound failed')
    require(abs(doc['requests_per_second'] - 2000 / doc['elapsed_seconds']) < 1e-9,
            'capacity was computed from an incorrect duration')
    equal(doc['p95_us'], sorted(values)[1899], 'p95 differs from raw measurements')


def ordinary_rules(document: dict) -> list:
    return [value for row in document['nftables'] for kind, value in row['add'].items()
            if kind == 'rule' and value['chain'] != 'ipv6-control-plane' and
            value['expr'] != [{'jump': {'target': 'ipv6-control-plane'}}]]


def peers_not_exempted(document: dict) -> None:
    for row in document['nftables']:
        item = row['add'].get('set')
        if not item or item['name'] not in ('syswarden_whitelist', 'syswarden_whitelist6',
            'syswarden_blacklist', 'syswarden_blacklist6', 'banned_ips', 'banned_ips6'):
            continue
        for member in item.get('elem', []):
            if type(member) is str:
                network = ipaddress.ip_network(member, strict=False)
            elif 'prefix' in member:
                network = ipaddress.ip_network(str(member['prefix']['addr']) + '/' +
                                                str(member['prefix']['len']), strict=False)
            elif set(member) == {'range'}:
                low, high = map(ipaddress.ip_address, member['range'])
                require(low.version == high.version and low <= high, 'invalid address range')
                require(all(peer.version != low.version or not low <= peer <= high
                            for peer in map(ipaddress.ip_address, PEERS)), 'test peer is exempted')
                continue
            else:
                raise frozen.PlanError('unsupported captured set member')
            require(all(ipaddress.ip_address(peer) not in network for peer in PEERS),
                    'test peer is exempted or blocked by a captured list')


def verify(group: proof.Group, debian: proof.Group) -> None:
    collection = group.document('evidence-05/COLLECTION.json')
    equal(collection['status'], 'PASS_BOUNDED_KERNEL_POLICY_COMPARISON', 'performance run failed')
    require(type(collection['files']) is list and len(collection['files']) == 49,
            'performance inventory differs')
    seen = set()
    for row in collection['files']:
        name = proof.relative(row['name'])
        require(name not in seen, 'duplicate performance capture')
        seen.add(name)
        data = group.data('evidence-05/' + name)
        equal(len(data), row['size'], 'performance capture length differs')
        equal(frozen.digest(data), row['sha256'], 'performance capture was substituted')
    prefix = 'evidence-05/observations/'
    result = group.document(prefix + 'RESULT.json')
    equal(result['status'], collection['status'], 'performance status was relabeled')
    for key in ('fixture_removed', 'host_policy_preserved', 'host_routes_preserved'):
        equal(result[key], True, 'performance fixture altered the host')
    protocol = group.document('PROTOCOL.json')
    equal(protocol['predeclared_limits'], dict(required_successful_responses_fraction=1.0,
        minimum_median_candidate_capacity_ratio=0.75, maximum_candidate_p95_latency_ratio=1.3,
        additional_latency_tolerance_us=25), 'performance limits changed after measurement')
    policies, samples = {}, []
    for role, phase in [('baseline', 'before'), ('candidate', 'after')]:
        source = debian.data('migration-upgrade-evidence-initial/nft-' + phase + '.stdout')
        policy = group.data(role + '.json')
        expected = protocol['variants'][role]
        equal(frozen.digest(source), expected['source_sha256'], 'source kernel policy differs')
        equal(frozen.digest(policy), expected['replay_sha256'], 'replayed policy differs')
        policies[role] = frozen.strict_json(policy)
        equal(replay(frozen.strict_json(source)), policies[role],
              'performance replay changed policy semantics or set membership')
        peers_not_exempted(policies[role])
        for index in range(6):
            for family in (4, 6):
                row = group.document(prefix + f'round-{index}-{role}-ipv{family}.json')
                trial(row, role, index, family)
                samples.append(row)
        traces = defaultdict(list)
        for line in group.data(prefix + role + '-trace.log').decode().splitlines():
            match = re.match(r'trace id ([a-f0-9]+) ', line)
            if match:
                traces[match[1]].append(line)
        for marker in ('ip saddr ' + PEERS[0], 'ip6 saddr ' + PEERS[1]):
            require(any(any(marker in line and 'packet:' in line for line in rows) and
                all(any(f'{family} {table} ' in line and
                    ('(verdict accept)' in line or 'policy accept' in line) for line in rows)
                    for family, table in HOOKS) for rows in traces.values()),
                'measured traffic did not traverse both kernel hooks')
        after = group.document(prefix + role + '-trace-after.json')
        counters = [term['counter']['packets'] for entry in after['nftables'] if 'rule' in entry
                    and entry['rule']['table'] == 'ivv4104_perf_trace'
                    for term in entry['rule']['expr'] if 'counter' in term]
        equal(counters, [50], 'independent ingress packet count differs')
    equal(ordinary_rules(policies['baseline']), ordinary_rules(policies['candidate']),
          'comparison changed non-IPv6 rule order or semantics')
    verdict = group.document('VERDICT.json')
    equal(verdict['product_sha'], proof.PRODUCT, 'performance product was relabeled')
    equal(verdict['release_acceptance'], False, 'bounded performance is not release acceptance')
    equal(verdict['measured_requests'], 48000, 'request accounting differs')
    for family in (4, 6):
        rates, latency = {}, {}
        for role in ('baseline', 'candidate'):
            rows = [row for row in samples if row['family'] == family and row['role'] == role]
            rates[role] = statistics.median(row['requests_per_second'] for row in rows)
            latency[role] = statistics.median(row['p95_us'] for row in rows)
        ratio = rates['candidate'] / rates['baseline']
        require(ratio >= 0.75 and latency['candidate'] <= latency['baseline'] * 1.3 + 25,
                'bounded performance regression exceeds predeclared limits')
        equal(verdict['comparisons'][str(family)], dict(capacity_ratio=ratio,
            median_p95_us=latency, median_requests_per_second=rates), 'reported metrics differ')
