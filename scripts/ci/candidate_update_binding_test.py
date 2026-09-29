"""Adversarial product/producer binding with real Git and file bytes."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import candidate_update_binding as gate


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.packages = self.root / 'packages'
        self.packages.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Synthetic test fixture')
        (self.repo / 'runtime').write_bytes(b'frozen runtime\n')
        self.product = self.commit('Major : fixture')
        (self.repo / 'tooling').write_bytes(b'reviewed publication tool\n')
        self.publication = self.commit('CI : fixture')
        self.payload = b'synthetic package fixture, never native evidence\n'
        (self.packages / 'package.deb').write_bytes(self.payload)
        self.plan = dict(gate.ivv.load_plan())
        self.plan.update(product_candidate=self.product,
                         publication_source_change_allowlist=['tooling'],
                         product_packages=[dict(path='package.deb', size=len(self.payload),
                                                sha256=gate.ivv.digest(self.payload))])
        self.track = dict(schema='syswarden-release-track/v1', candidate_commit=self.publication,
                          release='v4.10.0', previous_version='v4.04.3',
                          transition_commit=self.plan['originating_transition']['commit'],
                          transition_parent='c' * 40, prefix='Major', track='intermediate-validation',
                          followup_commits=1, qualification_passed=False, publication_authorized=False)
        # Version arithmetic has its own actual Go tests. Exercise its validator
        # here while using a minimal real Git repository for source tampering.
        def classify(repo, publication, plan):
            gate.ivv.verify_track(self.track, publication, plan)
            return self.track
        self.enterContext(patch.object(gate.ivv, 'load_plan', return_value=self.plan))
        self.enterContext(patch.object(gate.ivv, 'classify', side_effect=classify))

    def git(self, *args):
        result = subprocess.run(['git', '-c', 'core.fsmonitor=false', *args], cwd=self.repo,
                                check=True, text=True, capture_output=True)
        return result.stdout.strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def create(self):
        return gate.source_binding(self.repo, self.publication, self.product)

    def verify(self, document):
        return gate.verify_binding(document, self.repo, self.publication, self.product, self.packages)

    def test_separate_exact_product_and_producer_preserve_bytes_and_nonacceptance(self):
        document = self.create()
        self.assertEqual(self.verify(document), document)
        self.assertEqual(document['product_candidate'], self.product)
        self.assertEqual(document['publication_commit'], self.publication)
        self.assertNotEqual(self.product, self.publication)
        self.assertEqual((self.packages / 'package.deb').read_bytes(), self.payload)
        self.assertIs(document['intermediate_release_validated'], False)
        self.assertIs(document['qualification_passed'], False)
        self.assertIs(document['publication_authorized'], False)

    def test_wrong_product_and_identical_commit_mode_rejected(self):
        for product, publication in [('a' * 40, self.publication), (self.product, self.product)]:
            with self.subTest(product=product), self.assertRaises(gate.ivv.PlanError):
                gate.source_binding(self.repo, publication, product)

    def test_wrong_publication_rejected(self):
        with self.assertRaises(gate.ivv.PlanError):
            gate.source_binding(self.repo, 'd' * 40, self.product)

    def test_forged_binding_fields_and_acceptance_rejected(self):
        original = self.create()
        changes = [dict(product_candidate='a' * 40), dict(publication_commit='b' * 40),
                   dict(plan_sha256='0' * 64), dict(frozen_package_bytes=[]),
                   dict(source_changes=[]), dict(qualification_passed=True),
                   dict(intermediate_release_validated=True), dict(publication_authorized=True),
                   dict(extra='not reviewed'), dict(qualification_passed=0)]
        for update in changes:
            with self.subTest(update=update), self.assertRaises(gate.ivv.PlanError):
                self.verify(dict(original, **update))

    def test_upgrade_cannot_use_retained_product_exception(self):
        self.track.update(prefix='Upgrade', track='full-qualification')
        with self.assertRaises(gate.ivv.PlanError):
            self.create()

    def test_runtime_change_after_binding_rejected(self):
        document = self.create()
        (self.repo / 'runtime').write_bytes(b'changed runtime\n')
        with self.assertRaises(gate.ivv.PlanError):
            self.verify(document)
        self.publication = self.commit('Patch : runtime change')
        self.track['candidate_commit'] = self.publication
        with self.assertRaises(gate.ivv.PlanError):
            self.create()

    def test_wrong_and_hidden_index_bytes_rejected(self):
        self.git('update-index', '--assume-unchanged', 'runtime')
        (self.repo / 'runtime').write_bytes(b'hidden runtime mutation\n')
        with self.assertRaises(gate.ivv.PlanError):
            self.create()

    def test_package_substitution_missing_and_links_rejected(self):
        document = self.create()
        path = self.packages / 'package.deb'
        path.write_bytes(b'x' * len(self.payload))
        with self.assertRaises(gate.ivv.PlanError):
            self.verify(document)
        path.unlink()
        with self.assertRaises(OSError):
            self.verify(document)
        outside = self.root / 'saved.deb'
        outside.write_bytes(self.payload)
        path.symlink_to(outside)
        with self.assertRaises(gate.ivv.PlanError):
            self.verify(document)
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(gate.ivv.bundle.SigningBundleError):
            self.verify(document)

    def test_source_race_during_package_read_is_rejected(self):
        document = self.create()
        original = gate.ivv.read_anchored
        def mutate(*args):
            result = original(*args)
            (self.repo / 'runtime').write_bytes(b'concurrent mutation\n')
            return result
        with patch.object(gate.ivv, 'read_anchored', side_effect=mutate):
            with self.assertRaises(gate.ivv.PlanError):
                self.verify(document)

    def test_binding_has_no_new_native_or_qualification_verdict(self):
        document = self.create()
        self.assertNotIn('verdict', document)
        self.assertNotIn('retained_records', document)
        self.assertNotIn('native_checks', document)
        self.assertNotIn('signatures_verified', document)
        self.assertEqual(document['frozen_package_bytes'], self.plan['product_packages'])


if __name__ == '__main__':
    unittest.main()
