#!/usr/bin/env python3
"""Revalidate frozen IVV inputs from a later, narrowly admitted tooling checkout.

The original producer plan and independent updater consumer remain unchanged.
This source/input preflight cannot grant release acceptance.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import subprocess
import zipfile

try:
    from scripts.ci import release_ivv_plan as ivv
    from scripts.ci import release_ivv_updater as original_updater
    from scripts.ci import release_assurance_contract as assurance
except ModuleNotFoundError:
    import release_ivv_plan as ivv
    import release_ivv_updater as original_updater
    import release_assurance_contract as assurance

ORIGINAL_CONSUMER = '3e66ea186f5b1ae5eb851859aa72d2440157bf17'
README_BLOB = '109bf22a21267c80e4b0af9d6e11d2e5f41ab6d4'
EXTENSION_PATHS = frozenset({
    *original_updater.EXTENSION_PATHS,
    'README.md',
    'scripts/ci/release_assurance_contract.py',
    'scripts/ci/release_assurance_contract_test.py',
    'scripts/ci/release_ivv_publication.py',
    'scripts/ci/release_ivv_publication_test.py',
    'docs/qualification/INTERMEDIATE_PUBLICATION_BINDING_V4.10.0.md',
})
PINNED_VERIFIERS = frozenset({
    *original_updater.VERIFIER_PATHS,
    'scripts/ci/release_ivv_updater.py',
})


def source_binding(repository: Path, publication: str) -> dict:
    plan = ivv.load_plan()
    extended = copy.deepcopy(plan)
    extended['publication_source_change_allowlist'] = sorted(
        set(plan['publication_source_change_allowlist']) | EXTENSION_PATHS)
    changes = ivv.verify_source(repository, publication, extended)
    ivv.require(ivv.git(repository, 'merge-base', ORIGINAL_CONSUMER, publication) == ORIGINAL_CONSUMER,
                'publication must descend from the merged original updater consumer')
    blobs = {}
    for name in sorted(PINNED_VERIFIERS):
        before = ivv.git(repository, 'rev-parse', f'{ORIGINAL_CONSUMER}:{name}')
        after = ivv.git(repository, 'rev-parse', f'{publication}:{name}')
        assurance.equal(before, after, 'original verification dependency changed: ' + name)
        blobs[name] = after
    assurance.equal(ivv.git(repository, 'rev-parse', f'{publication}:README.md'), README_BLOB,
                    'README differs from the exact reviewed PR277 addition')
    contract = assurance.derive(repository, plan['release'], publication)
    ivv.require(contract.assurance == 'IVV' and contract.product_candidate == plan['product_candidate'],
                'wrong assurance track or frozen product')
    return dict(schema='syswarden-intermediate-publication-binding/v1',
        product_candidate=plan['product_candidate'], publication_commit=publication,
        original_consumer_commit=ORIGINAL_CONSUMER, original_plan_sha256=ivv.PLAN_SHA256,
        required_producer=contract.as_dict(), source_changes=changes,
        original_verifier_git_blobs=blobs, reviewed_readme_blob=README_BLOB,
        frozen_product_sources_unchanged=True, intermediate_release_validated=False,
        qualification_passed=False, publication_authorized=False)


def preflight(repository: Path, publication: str, evidence_root: Path, package_root: Path) -> dict:
    source = source_binding(repository, publication)
    plan = ivv.load_plan()
    records, packages = ivv.verify_inputs(plan, evidence_root, package_root)
    assurance.equal(source_binding(repository, publication), source,
                    'publication changed during immutable input verification')
    assurance.equal(ivv.load_plan(), plan, 'original plan changed during verification')
    return dict(schema='syswarden-intermediate-publication-preflight/v1',
        source_binding=source, retained_records=records, frozen_package_bytes=packages,
        required_checks=plan['required_checks'],
        scope='Source and immutable byte continuity only. Fresh signatures, CI, native evidence and protected acceptance remain separate.',
        native_results_transferred=False, intermediate_release_validated=False,
        qualification_passed=False, publication_authorized=False)


def verify_original_updater(repository: Path, publication: str, frozen_consumer: Path,
                            producer: Path, native: Path, updater: Path, archive: Path) -> dict:
    """Execute the unchanged verifier; never accept a supplied success receipt.

    Its original consumer checkout remains at ORIGINAL_CONSUMER. The separately
    checked publication checkout may contain the reviewed additions above.
    """
    source = source_binding(repository, publication)
    frozen_source = original_updater.publication_binding(frozen_consumer, ORIGINAL_CONSUMER, producer)
    # source_binding pins this imported verification module and all its original
    # dependencies. verify() actually invokes the producer-era signature consumer.
    receipt = original_updater.verify(frozen_consumer, ORIGINAL_CONSUMER, producer,
                                      native, updater, archive)
    expected = dict(schema='syswarden-intermediate-updater-revalidation/v1',
        status='original-updater-reverified-native-acceptance-pending',
        source_binding=frozen_source, updater_artifact_id=original_updater.ARTIFACT,
        updater_archive_sha256=original_updater.ARCHIVE_SHA256,
        native_update_accepted=False, intermediate_release_validated=False,
        qualification_passed=False, publication_authorized=False)
    for key, value in expected.items():
        assurance.equal(receipt[key], value, 'original updater result differs: ' + key)
    assurance.equal(source_binding(repository, publication), source,
                    'publication changed during original updater verification')
    assurance.equal(original_updater.publication_binding(frozen_consumer, ORIGINAL_CONSUMER, producer),
                    frozen_source, 'frozen verifier source changed during verification')
    return dict(schema='syswarden-publication-updater-binding/v1',
        source_binding=source, original_consumer_commit=ORIGINAL_CONSUMER,
        original_producer_commit=original_updater.PRODUCER,
        original_updater_result=receipt, native_update_accepted=False,
        intermediate_release_validated=False, qualification_passed=False,
        publication_authorized=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'evidence-root', 'package-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-sha', required=True)
    for name in ('original-consumer-repository', 'original-producer-repository',
                 'candidate-bundle', 'candidate-archive'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    updater_inputs = (args.original_consumer_repository, args.original_producer_repository,
                      args.candidate_bundle, args.candidate_archive)
    if any(value is not None for value in updater_inputs) and not all(
            value is not None for value in updater_inputs):
        parser.error('original updater verification requires all four original updater inputs')
    try:
        result = preflight(args.repository, args.publication_sha, args.evidence_root, args.package_root)
        if all(value is not None for value in updater_inputs):
            updater_result = verify_original_updater(
                args.repository, args.publication_sha, args.original_consumer_repository,
                args.original_producer_repository, args.package_root,
                args.candidate_bundle, args.candidate_archive)
            assurance.equal(updater_result['source_binding'], result['source_binding'],
                            'publication changed between input and updater verification')
            assurance.equal(preflight(args.repository, args.publication_sha,
                                      args.evidence_root, args.package_root), result,
                            'frozen inputs changed during original updater verification')
            result['original_updater_reverification'] = updater_result
        ivv.write_new(args.output, result)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError,
            zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Publication input continuity rejected: {exc}\n')
    print('Frozen product inputs retained; protected IVV acceptance remains mandatory.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
