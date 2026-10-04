"""Native evidence must preserve owned identity, actual traffic and raw bytes."""
import copy
import io
import json
import tarfile
import unittest
from unittest.mock import patch
from scripts.ci import release_ivv_v4103_native as gate


def wire(document):
    return json.dumps(document).encode()


def filesystem_observations():
    observations = []
    for boot in range(7):
        artifacts = []
        for number in range(3):
            before = dict(path='/generated/'+str(number), sha256='a'*64, mode=384,
                uid=0, gid=0, nlink=1, device=2048, inode=number+1, filesystem_uuid='b'*32)
            after = dict(before, device=2064 if boot == 6 else 2048)
            artifacts.append(dict(expected=before, actual=after, device_renumbered=boot == 6))
        observations.append(dict(status='PASS', boot_id=str(boot), artifacts=artifacts,
                                 device_renumbered=boot == 6))
    return observations


class NativeIdentityTests(unittest.TestCase):
    def test_real_renumbering_preserves_all_other_identity_fields(self):
        gate.verify_filesystem_observations(filesystem_observations())
        mutations = [
            lambda rows: rows.pop(),
            lambda rows: [r.update(boot_id='same') for r in rows],
            lambda rows: rows[-1].update(device_renumbered=False),
            lambda rows: rows[-1]['artifacts'][0].update(device_renumbered=1),
        ]
        for field in ('path','sha256','mode','uid','gid','nlink','inode','filesystem_uuid'):
            mutations.append(lambda rows, field=field: rows[-1]['artifacts'][0]['actual'].update({field:None}))
        for mutate in mutations:
            rows = filesystem_observations(); mutate(rows)
            with self.assertRaises(gate.frozen.PlanError):
                gate.verify_filesystem_observations(rows)

    def test_unchanged_devices_cannot_claim_renumbering(self):
        rows = filesystem_observations()
        for row in rows:
            row['device_renumbered'] = False
            for artifact in row['artifacts']:
                artifact['actual']['device'] = artifact['expected']['device']
                artifact['device_renumbered'] = False
        with self.assertRaises(gate.frozen.PlanError):
            gate.verify_filesystem_observations(rows)

    def test_matching_invalid_uuid_is_not_ownership_proof(self):
        for value in ('0'*32, 'unknown', 42):
            rows = filesystem_observations()
            for field in ('expected','actual'):
                rows[0]['artifacts'][0][field]['filesystem_uuid'] = value
            with self.assertRaises(gate.frozen.PlanError):
                gate.verify_filesystem_observations(rows)


class NativeArchiveTests(unittest.TestCase):
    def pack(self, files, extra=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as packed:
            for name, data in files.items():
                row = tarfile.TarInfo(name); row.size = len(data)
                packed.addfile(row, io.BytesIO(data))
            if extra:
                row = tarfile.TarInfo(extra[0]); row.type = extra[1]; row.linkname = 'outside'
                packed.addfile(row, io.BytesIO(b''))
        return output.getvalue()

    def fixture(self):
        files = {'candidate.deb':b'authentic', 'required.json':wire(dict(status='PASS'))}
        for i, row in enumerate(filesystem_observations()):
            files[f'filesystem-observations/{i}.json'] = wire(row)
            files[f'case{i}/vpn-probe/result-proof.json'] = wire(dict(status='PASS',
                server_and_client_handshake=True, encrypted_bidirectional_transit=True, public_dns_over_vpn_nat=True))
        manifest = dict(schema='syswarden-private-native-evidence-v1', candidate='a'*40,
            files=[dict(path=name,bytes=len(data),sha256=gate.frozen.digest(data)) for name,data in files.items()])
        files['EVIDENCE-MANIFEST.json'] = wire(manifest)
        archive = self.pack(files); digest = gate.frozen.digest(archive)
        plan = dict(native_archive_sha256=digest, native_manifest_sha256=gate.frozen.digest(files['EVIDENCE-MANIFEST.json']),
            product_candidate='a'*40, native_file_count=len(manifest['files']),
            native_payloads={'candidate.deb':gate.frozen.digest(b'authentic')},
            native_assertions={'required.json':{'status':'PASS'}})
        objects = {gate.frozen.digest(data):data for data in files.values()}
        objects[digest] = archive
        return plan, objects, files

    def test_exact_archive_verifies_every_member_and_signed_payload(self):
        plan, objects, _ = self.fixture()
        gate.verify_archive(plan, objects)
        for mutate in (
            lambda p,o: p['native_payloads'].update({'candidate.deb':'0'*64}),
            lambda p,o: p.update(native_file_count=p['native_file_count']-1),
            lambda p,o: p.update(product_candidate='b'*40),
            lambda p,o: p['native_assertions']['required.json'].update(status='FAIL'),
            lambda p,o: o.update({gate.frozen.digest(b'authentic'):b'substituted'}),
        ):
            p,o = copy.deepcopy(plan),copy.deepcopy(objects); mutate(p,o)
            with self.assertRaises(gate.frozen.PlanError): gate.verify_archive(p,o)

    def test_extra_duplicate_traversal_and_link_members_rejected(self):
        _,_,files = self.fixture()
        for name, kind in [('candidate.deb',tarfile.REGTYPE),('../outside',tarfile.REGTYPE),
                           ('link',tarfile.SYMTYPE),('link',tarfile.LNKTYPE),('/absolute',tarfile.REGTYPE)]:
            with self.subTest(name=name,kind=kind), self.assertRaises(gate.frozen.PlanError):
                gate.read_archive(self.pack(files,(name,kind)))
        with patch.object(gate,'MAX_TOTAL',1), self.assertRaises(gate.frozen.PlanError):
            gate.read_archive(self.pack(files))
        with self.assertRaises(gate.frozen.PlanError): gate.read_archive(b'not an archive')


class RestorationTests(unittest.TestCase):
    def fixture(self):
        checks = [dict(check='control'+str(i),passed=True) for i in range(136)]
        checks.append(dict(check='mount_options_preserved_/tmp',passed=True,
                           detail='rw,nosuid,nodev,size=2007976k,nr_inodes=1048576,inode64'))
        before = dict(all_passed=True,passed=137,total=137,checks=checks,
                      post_restore_checks={str(i):True for i in range(7)},deviations=['unchanged'])
        after = copy.deepcopy(before)
        after['checks'][-1]['detail'] = after['checks'][-1]['detail'].replace('2007976','2007972')
        return before, after

    def verify(self,before,after):
        roots = [dict(id=name,object_sha256=name) for name in ('entry-baseline','final-restored-verification')]
        gate.verify_restoration(dict(roots=roots),{'entry-baseline':wire(before),'final-restored-verification':wire(after)})

    def test_only_observed_tmpfs_memory_variance_is_accepted(self):
        before,after = self.fixture(); self.verify(before,after)
        for mutate in (
            lambda d:d['checks'][0].update(passed=False),
            lambda d:d['checks'][-1].update(detail=d['checks'][-1]['detail'].replace('nodev,','')),
            lambda d:d['checks'][-1].update(detail=d['checks'][-1]['detail'].replace('2007972','2007960')),
            lambda d:d['post_restore_checks'].update({'0':False}),
            lambda d:d.update(passed=True),
        ):
            changed=copy.deepcopy(after);mutate(changed)
            with self.assertRaises(gate.frozen.PlanError): self.verify(before,changed)


if __name__ == '__main__':
    unittest.main()
