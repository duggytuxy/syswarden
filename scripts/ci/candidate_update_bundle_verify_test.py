"""Synthetic, non-native tests for independent v2 updater consumption."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import candidate_update_bundle_verify as gate


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        self.native = self.root / 'native'
        for name in ['bundle/node01', 'bundle/verification', 'native/packages', 'native/rhel-package-owned/packages']:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.product, self.publication, self.run = 'a' * 40, 'b' * 40, 123
        anchors = []
        for name in ['packages/' + gate.DEB, 'packages/' + gate.DEB + '.asc',
                     'packages/syswarden-4.10.0-1.x86_64.rpm', 'packages/syswarden_4.10.0_x86_64.apk',
                     'rhel-package-owned/packages/syswarden-4.10.0-1.rhelpo.x86_64.rpm']:
            payload = ('synthetic package fixture ' + name).encode()
            (self.native / name).write_bytes(payload)
            anchors.append(dict(path=name, size=len(payload), sha256=gate.ivv.digest(payload)))
        self.source = dict(release='v4.10.0', product_candidate=self.product,
                           publication_commit=self.publication, frozen_package_bytes=anchors,
                           native_signing=dict(run_id=456, artifact_id=789,
                                               artifact_name='fixture-artifact', artifact_digest='sha256:' + 'c' * 64))
        self.files = {
            'node01/' + gate.DEB: (self.native / 'packages' / gate.DEB).read_bytes(),
            'verification/' + gate.DEB + '.asc': (self.native / 'packages' / (gate.DEB + '.asc')).read_bytes(),
            gate.MANIFEST: b'{"key_id":"unit-key"}\n', gate.SIGNATURE: b'unit-signature\n',
            gate.ATTESTATION: b'unit-Sigstore-bundle, never a real signature\n',
        }
        packages = sorted([dict(name=Path(row['path']).name, sha256=row['sha256'], size=row['size'])
                           for row in anchors if row['path'].startswith('packages/') and not row['path'].endswith('.asc')],
                          key=lambda row: row['name'])
        self.descriptor = {
            'schema_version': 2, 'profile': 'syswarden-candidate-update-bundle/v2',
            'status': 'candidate-signed-not-release-qualified', 'repository': gate.REPOSITORY,
            'release_tag': 'v4.10.0', 'release_sha': self.product, 'public_release': False, 'release_qualified': False,
            'producer': dict(workflow=gate.WORKFLOW, workflow_sha=self.publication, run_id=self.run,
                             run_attempt=1, runner_environment='github-hosted'),
            'source': dict(native_signing_workflow='.github/workflows/native-package-signing.yml',
                           native_signing_run_id=456, native_signing_artifact_id=789,
                           native_signing_artifact_name='fixture-artifact', native_signing_artifact_digest='sha256:' + 'c' * 64),
            'packages': packages,
            'manifest': dict(key_id='unit-key', document=gate.record(self.files, gate.MANIFEST),
                             signature=gate.record(self.files, gate.SIGNATURE)),
            'node01_bundle': dict(identity=f'github:{gate.REPOSITORY}:candidate-update:v4.10.0:{self.product}:{self.run}:1',
                                 directory='node01', exact_file_count=3,
                                 files=sorted([gate.record(self.files, name) for name in [gate.MANIFEST, gate.SIGNATURE, 'node01/' + gate.DEB]],
                                              key=lambda row: row['path'])),
            'detached_deb_signature': gate.record(self.files, 'verification/' + gate.DEB + '.asc'),
            'attestation': dict(mechanism='github-artifact-attestation', predicate_type='https://slsa.dev/provenance/v1',
                                subject=gate.DESCRIPTOR, bundle_path=gate.ATTESTATION),
            'source_binding': self.source,
        }
        self.write_descriptor()
        self.run_record = dict(id=self.run, head_sha=self.publication, head_branch='main', event='workflow_dispatch',
                               path=gate.WORKFLOW, run_attempt=1, status='completed', conclusion='success',
                               actor=dict(login='duggytuxy'), triggering_actor=dict(login='duggytuxy'))
        self.statement = {
            'subject': [dict(name=gate.DESCRIPTOR, digest=dict(sha256=gate.ivv.digest(self.files[gate.DESCRIPTOR])))],
            'predicateType': 'https://slsa.dev/provenance/v1',
            'predicate': {
                'buildDefinition': {
                    'buildType': 'https://actions.github.io/buildtypes/workflow/v1',
                    'externalParameters': dict(workflow=dict(ref='refs/heads/main', repository='https://github.com/' + gate.REPOSITORY,
                                                             path=gate.WORKFLOW)),
                    'internalParameters': dict(github=dict(event_name='workflow_dispatch', repository_id='1153695079',
                                                          repository_owner_id='61513268', runner_environment='github-hosted')),
                    'resolvedDependencies': [dict(uri=f'git+https://github.com/{gate.REPOSITORY}@refs/heads/main',
                                                  digest=dict(gitCommit=self.publication))],
                },
                'runDetails': dict(builder=dict(id=f'https://github.com/{gate.REPOSITORY}/{gate.WORKFLOW}@refs/heads/main'),
                                   metadata=dict(invocationId=f'https://github.com/{gate.REPOSITORY}/actions/runs/{self.run}/attempts/1')),
            },
        }
        self.enterContext(patch.object(gate.binding, 'source_binding', return_value=self.source))
        self.binding_check = self.enterContext(patch.object(gate.binding, 'verify_binding', return_value=self.source))
        self.native_check = self.enterContext(patch.object(gate.ivv.bundle, 'verify_bundle'))
        self.commands = []
        def run(argv, repository):
            self.commands.append(argv)
            if argv[:2] == ['gh', 'api']:
                return json.dumps(self.run_record).encode()
            if argv[:3] == ['gh', 'attestation', 'verify']:
                return json.dumps([dict(verificationResult=dict(statement=self.statement))]).encode()
            if argv[:2] == ['go', 'run']:
                return b''
            raise AssertionError('unexpected verification command')
        self.command = self.enterContext(patch.object(gate, 'command', side_effect=run))

    def write_descriptor(self):
        self.files[gate.DESCRIPTOR] = json.dumps(self.descriptor).encode()
        self.flush()

    def flush(self):
        self.files[gate.CHECKSUMS] = ''.join(f'{gate.ivv.digest(self.files[name])}  {name}\n'
                                          for name in sorted(gate.FILES - {gate.CHECKSUMS})).encode()
        for name, wire in self.files.items():
            (self.bundle / name).write_bytes(wire)

    def verify(self):
        return gate.verify(self.root, self.publication, self.product, self.native, self.bundle, self.run)

    def test_valid_v2_requires_crypto_source_native_bundle_and_keeps_no_release_claim(self):
        receipt = self.verify()
        self.assertFalse(receipt['qualification_passed'])
        self.assertFalse(receipt['publication_authorized'])
        self.assertFalse(receipt['intermediate_release_validated'])
        self.native_check.assert_called_once_with(self.native, 'v4.10.0', self.product)
        self.assertEqual(self.binding_check.call_count, 2)
        self.assertEqual(len(self.commands), 3)
        crypto = self.commands[1]
        self.assertEqual(crypto[crypto.index('--signer-digest') + 1], self.publication)
        self.assertEqual(crypto[crypto.index('--source-digest') + 1], self.publication)
        self.assertIn('--deny-self-hosted-runners', crypto)
        self.assertIn('./scripts/ci/update_manifest.go', self.commands[2])

    def test_old_schema_wrong_product_and_forged_pass_are_rejected(self):
        original = copy.deepcopy(self.descriptor)
        for changes in [dict(schema_version=1), dict(profile='syswarden-candidate-update-bundle/v1'),
                        dict(release_sha=self.publication), dict(public_release=True), dict(release_qualified=True),
                        dict(source_binding={}), dict(release_qualified=0), dict(extra='field')]:
            with self.subTest(changes=changes):
                self.descriptor = dict(original, **changes)
                self.write_descriptor()
                with self.assertRaises(gate.ivv.PlanError):
                    self.verify()
        self.assertEqual(self.commands, [])

    def test_substituted_package_rejected_with_recomputed_bundle_checksums(self):
        self.files['node01/' + gate.DEB] = b'substituted signed package\n'
        self.flush()
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()
        self.assertEqual(self.commands, [])

    def test_producer_run_failed_retried_or_untrusted_rejected(self):
        original = dict(self.run_record)
        for change in [dict(head_sha=self.product), dict(head_branch='feature'), dict(event='pull_request'),
                       dict(run_attempt=2), dict(conclusion='failure'), dict(status='in_progress'),
                       dict(actor={'login': 'other'}), dict(triggering_actor={'login': 'other'})]:
            with self.subTest(change=change), self.assertRaises(gate.ivv.PlanError):
                self.run_record = dict(original, **change)
                self.verify()

    def test_untrusted_sigstore_subject_run_and_source_are_rejected(self):
        original = copy.deepcopy(self.statement)
        mutations = [
            lambda s: s['subject'][0]['digest'].update(sha256='0' * 64),
            lambda s: s['subject'].append(s['subject'][0]),
            lambda s: s.update(predicateType='untrusted'),
            lambda s: s['predicate']['buildDefinition']['internalParameters']['github'].update(runner_environment='self-hosted'),
            lambda s: s['predicate']['buildDefinition']['externalParameters']['workflow'].update(path='other.yml'),
            lambda s: s['predicate']['buildDefinition']['resolvedDependencies'][0]['digest'].update(gitCommit=self.product),
            lambda s: s['predicate']['runDetails']['metadata'].update(invocationId='other-run'),
        ]
        for mutate in mutations:
            self.statement = copy.deepcopy(original)
            mutate(self.statement)
            with self.subTest(statement=self.statement), self.assertRaises(gate.ivv.PlanError):
                self.verify()

    def test_failed_crypto_is_not_a_passing_receipt(self):
        def fail(argv, repository):
            if argv[:2] == ['gh', 'api']:
                return json.dumps(self.run_record).encode()
            raise gate.ivv.PlanError('cryptographic verification rejected')
        self.command.side_effect = fail
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()

    def test_special_links_extra_and_missing_inputs_rejected(self):
        path = self.bundle / gate.SIGNATURE
        saved = self.root / 'saved'
        saved.write_bytes(path.read_bytes())
        path.unlink()
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()
        path.symlink_to(saved)
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()
        path.unlink()
        os.link(saved, path)
        with self.assertRaises(gate.ivv.bundle.SigningBundleError):
            self.verify()
        path.unlink()
        path.write_bytes(saved.read_bytes())
        (self.bundle / 'extra').write_bytes(b'unknown')
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()

    def test_bundle_change_during_verification_is_rejected(self):
        original = self.command.side_effect
        def race(argv, repository):
            result = original(argv, repository)
            if argv[:2] == ['go', 'run']:
                self.files[gate.ATTESTATION] += b'changed'
                self.flush()
            return result
        self.command.side_effect = race
        with self.assertRaises(gate.ivv.PlanError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
