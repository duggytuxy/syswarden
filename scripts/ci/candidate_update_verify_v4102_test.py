import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.ci import candidate_update_verify_v4102 as gate


class CurrentUpdaterProvenanceTests(unittest.TestCase):
    def metadata(self):
        owner = dict(login='duggytuxy', id=61513268)
        repository = dict(id=1153695079, full_name=gate.REPOSITORY)
        run = dict(id=gate.RUN, head_sha=gate.PRODUCT, head_branch='main',
                   event='workflow_dispatch', path=gate.WORKFLOW, run_attempt=1,
                   status='completed', conclusion='success', actor=owner,
                   triggering_actor=copy.deepcopy(owner), repository=repository,
                   head_repository=copy.deepcopy(repository))
        artifact = dict(id=gate.ARTIFACT, size_in_bytes=gate.ARCHIVE_SIZE,
            name=f'syswarden-candidate-update-bundle-4.10.2-{gate.RUN}-1-{gate.PRODUCT}',
            digest='sha256:' + gate.ARCHIVE_SHA256, expired=False,
            workflow_run=dict(id=gate.RUN, repository_id=1153695079, head_repository_id=1153695079,
                              head_branch='main', head_sha=gate.PRODUCT))
        return run, artifact

    def test_exact_new_producer(self):
        gate.verify_metadata(*self.metadata())

    def test_historical_producer_fork_retry_and_wrong_workflow_rejected(self):
        cases = [('id', 36622881503), ('head_sha', 'f334beaddc5c6005f40d79c7bab4e43598bfc5ed'),
                 ('run_attempt', 2), ('run_attempt', True), ('head_branch', 'feature'),
                 ('event', 'push'), ('path', '.github/workflows/native-package-signing.yml'),
                 ('status', 'in_progress'), ('conclusion', 'failure')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                run, artifact = self.metadata(); run[key] = value
                with self.assertRaises(gate.ivv.PlanError): gate.verify_metadata(run, artifact)
        for key in ('actor', 'triggering_actor', 'repository', 'head_repository'):
            with self.subTest(identity=key):
                run, artifact = self.metadata(); run[key]['id'] += 1
                with self.assertRaises(gate.ivv.PlanError): gate.verify_metadata(run, artifact)

    def test_artifact_transplants_and_invalid_types_rejected(self):
        cases = [('id', 11059596903), ('name', 'other'), ('size_in_bytes', 0),
                 ('digest', 'sha256:' + '0'*64), ('expired', 0)]
        for key, value in cases:
            with self.subTest(key=key):
                run, artifact = self.metadata(); artifact[key] = value
                with self.assertRaises(gate.ivv.PlanError): gate.verify_metadata(run, artifact)
        for key in ('id', 'repository_id', 'head_repository_id', 'head_sha', 'head_branch'):
            with self.subTest(binding=key):
                run, artifact = self.metadata(); artifact['workflow_run'][key] = 'substitute'
                with self.assertRaises(gate.ivv.PlanError): gate.verify_metadata(run, artifact)

    def test_expired_current_artifact_rejected(self):
        run, artifact = self.metadata(); artifact['expired'] = True
        with self.assertRaises(gate.ivv.PlanError): gate.verify_metadata(run, artifact)

    def test_archive_and_staged_files_must_agree(self):
        files = {name: name.encode() for name in gate.FILES}
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as packed:
            for name, content in files.items(): packed.writestr(name, content)
        wire = data.getvalue()
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'artifact.zip'; archive.write_bytes(wire)
            with patch.object(gate, 'ARCHIVE_SHA256', gate.ivv.digest(wire)), \
                 patch.object(gate, 'ARCHIVE_SIZE', len(wire)):
                gate.verify_archive(archive, files)
                wrong = dict(files); wrong[gate.original.MANIFEST] = b'substituted'
                with self.assertRaises(gate.ivv.PlanError): gate.verify_archive(archive, wrong)
                archive.write_bytes(wire[:-1] + bytes([wire[-1] ^ 1]))
                with self.assertRaises(gate.ivv.PlanError): gate.verify_archive(archive, files)

    def test_symlink_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / 'original.zip'; real.write_bytes(b'bytes')
            link = Path(temporary) / 'substitute.zip'; link.symlink_to(real)
            with self.assertRaises(gate.ivv.PlanError): gate.verify_archive(link, {})

    def test_changed_trust_root_cannot_redefine_manifest_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in gate.PINNED_HELPERS:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'original reviewed bytes')
            with patch.object(gate.ivv, 'git', return_value=''), \
                 patch('subprocess.check_output', return_value=b'original reviewed bytes'):
                gate.verify_helpers(root)
                trust = root / 'src/core/syswarden-cli/pkg/system/release_trust_roots.json'
                trust.write_bytes(b'substituted attacker key')
                with self.assertRaises(gate.ivv.PlanError): gate.verify_helpers(root)


if __name__ == '__main__':
    unittest.main()
