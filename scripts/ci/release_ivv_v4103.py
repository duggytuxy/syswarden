#!/usr/bin/env python3
"""Bind fresh native observations to the exact signed v4.10.3 product.

Only the protected producer can admit the complete intermediate acceptance.
This verifier retains original failures and never transfers historical verdicts.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

try:
    from scripts.ci import release_ivv_current as historical
    from scripts.ci import release_ivv_v4101 as captures
    from scripts.ci import release_ivv_plan as frozen
    from scripts.ci import release_ivv_v4102 as previous
    from scripts.ci import release_ivv_v4103_native as native
    from scripts.ci import release_ivv_v4103_removal as removal
except ModuleNotFoundError:
    import release_ivv_current as historical
    import release_ivv_v4101 as captures
    import release_ivv_plan as frozen
    import release_ivv_v4102 as previous
    import release_ivv_v4103_native as native
    import release_ivv_v4103_removal as removal

PLAN = Path(__file__).with_name('release_ivv_v4103_plan.json')
INPUTS = Path(__file__).with_name('release_ivv_v4103_inputs.json')
IMPACT = Path(__file__).with_name('release_ivv_v4103_impact.json')
PLAN_SHA256 = 'ccbea1c1ab1ef9f4a6bcda5027ae93371b63d301a6bd5806367a7f9f096ab52f'
PRODUCT = '0a0fa7e7669fe61c36b6ed84e27a42d71cc7063e'
PREVIOUS_ACCEPTED = '94d97f07cb5a054669dd66d6efd28ba55db5d173'
MAX_OBJECT = 128 * 1024 * 1024
RELATIONS = frozenset({'current-targeted-observation', 'final-restoration',
    'retained-harness-failure', 'historical-support-only', 'source-review',
    'payload-review', 'product-ci', 'cryptographic-prerequisite'})
require = frozen.require
equal = captures.equal
verify_objects = historical.verify_objects
at_pointer = historical.at_pointer
verify_capture_bindings = captures.verify_capture_bindings


def load_plan() -> dict:
    wire = frozen.bundle.regular_bytes(PLAN, frozen.MAX_JSON, 'current IVV plan')
    equal(frozen.digest(wire), PLAN_SHA256, 'current plan differs from reviewed bytes')
    plan = frozen.strict_json(wire)
    require(plan['schema'] == 'syswarden-current-intermediate-ivv-plan/v1' and
            plan['release'] == 'v4.10.3' and plan['required_assurance'] == 'IVV' and
            plan['product_candidate'] == PRODUCT and plan['native_tested_candidate'] == PRODUCT and
            plan['preflight_is_acceptance'] is False, 'unsupported current IVV plan')
    equal(plan['historical_plan_sha256'], previous.PLAN_SHA256, 'historical plan was replaced')
    previous.load_plan()
    return plan


def load_manifest(plan: dict) -> dict:
    wire = frozen.bundle.regular_bytes(INPUTS, frozen.MAX_JSON, 'reviewed private input manifest')
    equal(frozen.digest(wire), plan['private_input_manifest_sha256'], 'unreviewed private input inventory')
    manifest = frozen.strict_json(wire)
    equal(set(manifest), {'schema', 'product_candidate', 'roots', 'objects',
                         'private_inputs_uploaded', 'historical_verdicts_transferred', 'acceptance'},
          'unexpected private manifest fields')
    require(manifest['schema'] == 'syswarden-private-ivv-input-manifest/v1' and
            manifest['product_candidate'] == PRODUCT and manifest['private_inputs_uploaded'] is False and
            manifest['historical_verdicts_transferred'] is False and manifest['acceptance'] is False,
            'input inventory cannot claim acceptance or transfer verdicts')
    equal(sorted(row['id'] for row in manifest['roots']), plan['required_input_ids'],
          'required reviewed observation missing')
    return manifest


def verify_roots(manifest: dict, objects: dict[str, bytes]) -> list[dict]:
    roots = manifest['roots']
    require(type(roots) is list and 0 < len(roots) <= 1000, 'invalid reviewed root count')
    require(len({row['id'] for row in roots}) == len(roots), 'duplicate reviewed observation')
    reviewed = []
    for row in roots:
        equal(set(row), {'id', 'candidate_commit', 'relation', 'object_sha256', 'assertions'},
              'unexpected reviewed observation fields')
        require(row['relation'] in RELATIONS, 'invalid evidence relation')
        candidate = PREVIOUS_ACCEPTED if row['relation'] == 'historical-support-only' else PRODUCT
        equal(row['candidate_commit'], candidate, 'original observation candidate differs')
        require(row['object_sha256'] in objects, 'reviewed observation is absent')
        doc = frozen.strict_json(objects[row['object_sha256']])
        for field in ('candidate_commit', 'candidate_sha', 'candidate', 'product_candidate'):
            if field in doc:
                equal(doc[field], candidate, 'original candidate binding differs')
        require(type(row['assertions']) is dict and row['assertions'], 'empty reviewed assertions')
        for pointer, value in row['assertions'].items():
            equal(at_pointer(doc, pointer), value, 'reviewed observation assertion differs: ' + row['id'])
        reviewed.append(dict(id=row['id'], original_candidate=candidate, relation=row['relation'],
            input_sha256=row['object_sha256'], original_bytes_verified=True,
            admitted_as_current_native_pass=False))
    return reviewed


def verify_native_archive(plan: dict, objects: dict[str, bytes]) -> None:
    native.verify_archive(plan, objects)


def verify_restoration(manifest: dict, objects: dict[str, bytes]) -> None:
    native.verify_restoration(manifest, objects)


def verify_private_inputs(root: Path) -> dict:
    plan = load_plan()
    manifest = load_manifest(plan)
    objects = verify_objects(root, manifest)
    observations = verify_roots(manifest, objects)
    verify_capture_bindings(manifest, objects)
    verify_native_archive(plan, objects)
    removal.verify_removal_archives(plan, objects)
    verify_restoration(manifest, objects)
    equal(verify_objects(root, manifest), objects, 'private inputs changed during verification')
    equal(load_plan(), plan, 'plan changed during verification')
    equal(load_manifest(plan), manifest, 'manifest changed during verification')
    return dict(schema='syswarden-reviewed-ivv-input-verification/v1', product_candidate=PRODUCT,
        plan_sha256=PLAN_SHA256, input_manifest_sha256=plan['private_input_manifest_sha256'],
        object_count=len(objects), reviewed_observations=observations, private_raw_inputs_uploaded=False,
        historical_verdicts_transferred=False, intermediate_release_validated=False,
        qualification_passed=False, publication_authorized=False)


def verify_source_impact(repository: Path, plan: dict) -> None:
    wire = frozen.bundle.regular_bytes(IMPACT, frozen.MAX_JSON, 'reviewed patch impact')
    equal(frozen.digest(wire), plan['impact_sha256'], 'unreviewed source-impact record')
    impact = frozen.strict_json(wire)
    equal(impact['product_candidate'], PRODUCT, 'wrong source-impact product')
    equal(impact['native_tested_candidate'], PRODUCT, 'native product was relabeled')
    last = plan['last_public_release']['commit']
    equal(set(impact['comparison_trees']), {last, PRODUCT}, 'source comparison incomplete')
    for commit, tree in impact['comparison_trees'].items():
        equal(frozen.git(repository, 'rev-parse', commit + '^{tree}'), tree, 'reviewed tree differs')
    def blob(commit, path, missing=False):
        frozen.relative(path)
        result = subprocess.run(['git', '--no-replace-objects', 'show', commit + ':' + path],
                                cwd=repository, capture_output=True, timeout=30)
        if missing:
            require(result.returncode != 0, 'unexpected source object')
            return None
        require(result.returncode == 0 and len(result.stdout) <= MAX_OBJECT, 'source object absent or oversized')
        return frozen.digest(result.stdout)
    paths = frozen.git(repository, 'diff', '--name-only', last, PRODUCT).splitlines()
    equal(paths, [row['path'] for row in impact['source_differences_from_public_release']], 'unreviewed source delta')
    for row in impact['source_differences_from_public_release']:
        for commit, field in ((last, 'original_sha256'), (PRODUCT, 'product_sha256')):
            equal(blob(commit, row['path'], row[field] is None), row[field], 'source-impact bytes differ')
    equal(impact['source_differences_from_native_tested_candidate'], [], 'native product source changed')
    paths = [p for p in frozen.git(repository, 'ls-tree', '-r', '--name-only', PRODUCT).splitlines()
             if p.startswith('src/') and p.endswith(('.go', 'go.mod', 'go.sum')) and not p.endswith('_test.go')]
    closure = impact['native_source_closure']
    equal(paths, [row['path'] for row in closure['complete_module_inputs']], 'module closure incomplete')
    equal(closure['all_module_inputs_byte_identical'], True, 'native runtime differs')
    for row in closure['complete_module_inputs']:
        digest = blob(PRODUCT, row['path'])
        equal(row, dict(path=row['path'], native_sha256=digest, product_sha256=digest, byte_identical=True),
              'native module input changed')


def source_binding(repository: Path, publication: str) -> dict:
    plan = load_plan()
    changed = frozen.verify_source(repository, publication, plan)
    verify_source_impact(repository, plan)
    track = frozen.classify(repository, publication, plan)
    return dict(product_candidate=PRODUCT, publication_commit=publication, plan_sha256=PLAN_SHA256,
        classification=track, source_changes=changed, frozen_package_bytes=plan['product_packages'],
        impact_sha256=plan['impact_sha256'])


def verify_package_inputs(native: Path) -> list[dict]:
    plan = load_plan()
    for row in plan['product_packages']:
        frozen.read_anchored(native, row, MAX_OBJECT)
    return plan['product_packages']
