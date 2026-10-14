"""Read bounded private evidence groups without publishing their contents."""
from __future__ import annotations

from pathlib import PurePosixPath

try:
    from scripts.ci import release_ivv_current as common
except ModuleNotFoundError:
    import release_ivv_current as common

frozen = common.frozen
require, equal = common.require, common.equal
PRODUCT = '0e966d409b6b9d19116597edee1feafad0c83688'
MAX_GROUP_BYTES = 256 * 1024 * 1024


def relative(name: str) -> str:
    require(type(name) is str and name and '\\' not in name,
            'invalid private evidence name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and
            all(part not in ('', '.', '..') for part in path.parts),
            'unsafe private evidence name')
    return name


class Group:
    """Immutable bytes anchored by a reviewed group digest and exact inventory."""

    def __init__(self, descriptor: dict, objects: dict[str, bytes]):
        equal(set(descriptor), {'schema', 'product_candidate', 'files'},
              'unexpected private evidence group fields')
        equal(descriptor['schema'], 'syswarden-private-ivv-evidence-group/v1',
              'unknown private evidence group')
        equal(descriptor['product_candidate'], PRODUCT, 'wrong native product')
        rows = descriptor['files']
        require(type(rows) is list and 0 < len(rows) <= 3000,
                'invalid private evidence group size')
        self.files: dict[str, bytes] = {}
        total = 0
        for row in rows:
            equal(set(row), {'name', 'sha256', 'size'}, 'unexpected evidence anchor')
            name = relative(row['name'])
            require(name not in self.files, 'duplicate private evidence name')
            require(type(row['size']) is int and 0 <= row['size'] <= 128 * 1024 * 1024,
                    'invalid private evidence size')
            digest = row['sha256']
            require(type(digest) is str and frozen.SHA256.fullmatch(digest) is not None
                    and digest in objects, 'missing private evidence object')
            wire = objects[digest]
            require(type(wire) is bytes and len(wire) == row['size'] and
                    frozen.digest(wire) == digest, 'private evidence bytes differ')
            total += len(wire)
            require(total <= MAX_GROUP_BYTES, 'private evidence group exceeds bound')
            self.files[name] = wire

    def data(self, name: str) -> bytes:
        require(relative(name) in self.files, 'required private evidence is absent')
        return self.files[name]

    def document(self, name: str) -> dict:
        doc = frozen.strict_json(self.data(name))
        require(type(doc) is dict, 'private observation must be an object')
        return doc

    def collection(self, directory: str) -> dict:
        """Recheck every copied stream, not just the collection's status label."""
        name = relative(directory) + '/COLLECTION.json'
        doc = self.document(name)
        equal(doc['release_acceptance'], False, 'private collection claims acceptance')
        rows = doc['files']
        require(type(rows) is list and 0 < len(rows) <= 250,
                'invalid private collection inventory')
        seen, total = set(), 0
        for row in rows:
            entry = relative(row['name'])
            require(entry not in seen, 'duplicate private collection member')
            seen.add(entry)
            wire = self.data(directory + '/' + entry)
            require(type(row['size']) is int and row['size'] >= 0,
                    'invalid copied evidence size')
            equal(len(wire), row['size'], 'copied evidence size differs')
            equal(frozen.digest(wire), row['sha256'], 'copied evidence digest differs')
            total += len(wire)
        if 'bytes' in doc:
            equal(total, doc['bytes'], 'private collection byte count differs')
        prefix = directory + '/'
        present = {name[len(prefix):] for name in self.files if name.startswith(prefix)}
        equal(present - {'COLLECTION.json', 'collection.stderr'}, seen,
              'private collection contains unaccounted evidence')
        return doc

    def observation(self, directory: str, filename: str = 'state.json') -> dict:
        collection = self.collection(directory)
        doc = self.document(directory + '/' + filename)
        equal(doc['status'], collection['state'], 'collection state was relabeled')
        if 'product_sha' in doc:
            equal(doc['product_sha'], PRODUCT, 'native observation product differs')
        equal(doc['release_acceptance'], False, 'native observation claims acceptance')
        events = doc.get('events', [])
        command_path = directory + '/commands.json'
        if command_path in self.files:
            captures = frozen.strict_json(b'{"events":' + self.data(command_path) + b'}')['events']
            if 'events' in doc:
                equal(captures, events, 'command inventories disagree')
            else:
                events = captures
        require(type(events) is list and len(events) <= 250, 'invalid event inventory')
        names = set()
        for row in events:
            name = relative(row['name'])
            require('/' not in name and name not in names, 'ambiguous command capture')
            names.add(name)
            require(type(row['returncode']) is int, 'invalid native exit status')
            args = row.get('argv', row.get('args'))
            require(type(args) is list and args and all(type(arg) is str for arg in args),
                    'invalid native command identity')
            for suffix in ('stdout', 'stderr'):
                equal(frozen.digest(self.data(directory + '/' + name + '.' + suffix)),
                      row[suffix + '_sha256'], 'native command stream was substituted')
        return {**doc, 'events': events}

    def command(self, directory: str, doc: dict, name: str, code: int,
                prefix: list[str] | None = None) -> bytes:
        rows = [row for row in doc['events'] if row['name'] == name]
        require(len(rows) == 1, 'required native command missing or duplicated')
        row = rows[0]
        equal(row['returncode'], code, 'native command exit status differs')
        args = row.get('argv', row.get('args'))
        if prefix is not None:
            equal(args[:len(prefix)], prefix, 'native command identity differs')
        wire = self.data(directory + '/' + name + '.stdout')
        equal(frozen.digest(wire), row['stdout_sha256'], 'native command output differs')
        return wire

    def reboot(self, directory: str, expected_status: str) -> dict:
        doc = self.document(relative(directory) + '/VERDICT.json')
        equal(doc['status'], expected_status, 'native reboot verification failed')
        equal(doc['product_sha'], PRODUCT, 'native reboot product differs')
        equal(doc['release_acceptance'], False, 'native reboot claims acceptance')
        require(type(doc['before_boot']) is str and type(doc['after_boot']) is str and
                doc['before_boot'] != doc['after_boot'], 'distinct boots are required')
        equal(doc['minimum_post_boot_observation_seconds'], 140,
              'IPv6 renewal observation was shortened')
        equal(doc['administrator_policy_preserved'], True, 'administrator policy changed')
        rows = doc['files']
        require(type(rows) is list and rows, 'native reboot capture is absent')
        names = set()
        for row in rows:
            name = relative(row['name'])
            require('/' not in name and name not in names, 'ambiguous reboot capture')
            names.add(name)
            wire = self.data(directory + '/' + name)
            equal(len(wire), row['size'], 'reboot capture size differs')
            equal(frozen.digest(wire), row['sha256'], 'reboot capture was substituted')
        for index in range(14):
            observation = self.document(directory + '/renewal-' + str(index) + '.stdout')
            equal(observation['boot_id'], doc['after_boot'], 'renewal changed boots')
            equal(observation['administrator_policy_preserved'], True,
                  'renewal lost administrator policy')
        final = self.document(directory + '/renewal-13.stdout')
        require(any('DHCPRENEW' in log for log in final['router_logs'].values()),
                'actual post-boot DHCP renewal is absent')
        return doc
