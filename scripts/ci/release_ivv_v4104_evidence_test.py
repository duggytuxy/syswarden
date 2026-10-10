"""Private IVV inventories must reject missing, substituted and relabeled proof."""
import copy
import json
import unittest

from scripts.ci import release_ivv_v4104_evidence as proof


def wire(value):
    return json.dumps(value, sort_keys=True).encode()


def group(files):
    objects = {proof.frozen.digest(data): data for data in files.values()}
    descriptor = dict(schema='syswarden-private-ivv-evidence-group/v1',
        product_candidate=proof.PRODUCT, files=[dict(name=name, size=len(data),
        sha256=proof.frozen.digest(data)) for name, data in sorted(files.items())])
    return descriptor, objects


class EvidenceTests(unittest.TestCase):
    def native_case(self):
        stdout, stderr = b'installed\n', b''
        state = dict(status='PASS', product_sha=proof.PRODUCT, release_acceptance=False,
            events=[dict(name='package', argv=['rpm', '-q', 'syswarden'], returncode=0,
                stdout_sha256=proof.frozen.digest(stdout),
                stderr_sha256=proof.frozen.digest(stderr))])
        files = {'case/state.json': wire(state), 'case/package.stdout': stdout,
                 'case/package.stderr': stderr}
        collection = dict(state='PASS', release_acceptance=False, bytes=sum(map(len, files.values())),
            files=[dict(name=name.split('/', 1)[1], size=len(data), sha256=proof.frozen.digest(data))
                   for name, data in files.items()])
        files['case/COLLECTION.json'] = wire(collection)
        return files

    def test_complete_command_capture(self):
        verified = proof.Group(*group(self.native_case()))
        doc = verified.observation('case')
        self.assertEqual(verified.command('case', doc, 'package', 0, ['rpm', '-q']), b'installed\n')
        with self.assertRaises(proof.frozen.PlanError):
            verified.command('case', doc, 'package', 0, ['dpkg'])

    def test_missing_or_substituted_stream(self):
        for operation in ('missing', 'replace'):
            files = self.native_case()
            if operation == 'missing': del files['case/package.stdout']
            else: files['case/package.stdout'] = b'other package\n'
            with self.subTest(operation=operation), self.assertRaises(proof.frozen.PlanError):
                proof.Group(*group(files)).observation('case')

    def test_separate_command_inventory_is_bound_and_checked(self):
        for wrong in (False, True):
            files = self.native_case()
            state = json.loads(files.pop('case/state.json'))
            events = state.pop('events')
            if wrong:
                events[0]['returncode'] = False
            files['case/result.json'] = wire(state)
            files['case/commands.json'] = wire(events)
            del files['case/COLLECTION.json']
            collection = dict(state='PASS', release_acceptance=False,
                files=[dict(name=name.split('/', 1)[1], size=len(data),
                            sha256=proof.frozen.digest(data)) for name, data in files.items()])
            files['case/COLLECTION.json'] = wire(collection)
            if wrong:
                with self.assertRaises(proof.frozen.PlanError):
                    proof.Group(*group(files)).observation('case', 'result.json')
            else:
                verified = proof.Group(*group(files))
                doc = verified.observation('case', 'result.json')
                self.assertEqual(verified.command('case', doc, 'package', 0), b'installed\n')

    def test_reviewed_object_anchor_cannot_change(self):
        descriptor, objects = group(self.native_case())
        objects[descriptor['files'][0]['sha256']] = b'substituted'
        with self.assertRaises(proof.frozen.PlanError): proof.Group(descriptor, objects)

    def test_paths_duplicates_types_and_product_transplants(self):
        descriptor, objects = group(self.native_case())
        mutations = [
            lambda d: d.update(product_candidate='0a0fa7e7669fe61c36b6ed84e27a42d71cc7063e'),
            lambda d: d['files'].append(copy.deepcopy(d['files'][0])),
            lambda d: d['files'][0].update(size=True),
            lambda d: d['files'][0].update(name='../outside'),
            lambda d: d['files'][0].update(name='/outside'),
            lambda d: d['files'][0].update(name='case//file'),
            lambda d: d['files'][0].update(name='case/./file'),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(descriptor); mutate(changed)
            with self.subTest(index=index), self.assertRaises(proof.frozen.PlanError):
                proof.Group(changed, objects)

    def test_boolean_exit_status_and_relabeling_are_not_passes(self):
        for change in ('boolean', 'product', 'acceptance', 'status', 'duplicate'):
            files = self.native_case(); state = json.loads(files['case/state.json'])
            if change == 'boolean': state['events'][0]['returncode'] = False
            elif change == 'product': state['product_sha'] = '1' * 40
            elif change == 'acceptance': state['release_acceptance'] = True
            elif change == 'status': state['status'] = 'RELABELED'
            else: state['events'].append(copy.deepcopy(state['events'][0]))
            files['case/state.json'] = wire(state)
            collection = json.loads(files['case/COLLECTION.json'])
            for row in collection['files']:
                data = files['case/' + row['name']]
                row.update(size=len(data), sha256=proof.frozen.digest(data))
            collection['bytes'] = sum(row['size'] for row in collection['files'])
            files['case/COLLECTION.json'] = wire(collection)
            with self.subTest(change=change), self.assertRaises(proof.frozen.PlanError):
                proof.Group(*group(files)).observation('case')

    def reboot_case(self):
        files = {}
        for index in range(14):
            files['reboot/renewal-' + str(index) + '.stdout'] = wire(dict(boot_id='second',
                administrator_policy_preserved=True, router_logs={'router': 'DHCPRENEW observed'}))
        doc = dict(status='PASS_REBOOT', product_sha=proof.PRODUCT, release_acceptance=False,
            before_boot='first', after_boot='second', minimum_post_boot_observation_seconds=140,
            administrator_policy_preserved=True, files=[dict(name=name.split('/', 1)[1],
                size=len(data), sha256=proof.frozen.digest(data)) for name, data in files.items()])
        files['reboot/VERDICT.json'] = wire(doc)
        return files

    def test_actual_reboot_and_complete_renewal_window(self):
        proof.Group(*group(self.reboot_case())).reboot('reboot', 'PASS_REBOOT')
        for key, value in [('after_boot', 'first'), ('minimum_post_boot_observation_seconds', 10),
                           ('administrator_policy_preserved', False), ('release_acceptance', True)]:
            files = self.reboot_case(); doc = json.loads(files['reboot/VERDICT.json'])
            doc[key] = value; files['reboot/VERDICT.json'] = wire(doc)
            with self.subTest(field=key), self.assertRaises(proof.frozen.PlanError):
                proof.Group(*group(files)).reboot('reboot', 'PASS_REBOOT')

    def test_dhcp_state_label_cannot_replace_real_renewal(self):
        files = self.reboot_case()
        name = 'reboot/renewal-13.stdout'
        observed = json.loads(files[name]); observed['router_logs'] = {'router': 'DHCPREQUEST only'}
        files[name] = wire(observed)
        doc = json.loads(files['reboot/VERDICT.json'])
        for row in doc['files']:
            if row['name'] == 'renewal-13.stdout':
                row.update(size=len(files[name]), sha256=proof.frozen.digest(files[name]))
        files['reboot/VERDICT.json'] = wire(doc)
        with self.assertRaises(proof.frozen.PlanError):
            proof.Group(*group(files)).reboot('reboot', 'PASS_REBOOT')


if __name__ == '__main__':
    unittest.main()
