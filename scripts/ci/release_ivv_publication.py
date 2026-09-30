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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'evidence-root', 'package-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-sha', required=True)
    args = parser.parse_args()
    try:
        result = preflight(args.repository, args.publication_sha, args.evidence_root, args.package_root)
        ivv.write_new(args.output, result)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError,
            subprocess.SubprocessError) as exc:
        parser.exit(1, f'Publication input continuity rejected: {exc}\n')
    print('Frozen product inputs retained; protected IVV acceptance remains mandatory.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
