#!/usr/bin/env python3
"""Validate reviewed current IVV inputs while preserving historical identities.

This module grants no protected acceptance. The protected producer must also
reverify signatures, updater provenance and publication CI. Publisher consumers
must authenticate that producer independently.
"""
from __future__ import annotations

from pathlib import Path

try:
    from scripts.ci import release_ivv_current as previous
    from scripts.ci import release_ivv_plan as frozen
except ModuleNotFoundError:
    import release_ivv_current as previous
    import release_ivv_plan as frozen

PLAN = Path(__file__).with_name('release_ivv_v4101_plan.json')
INPUTS = Path(__file__).with_name('release_ivv_v4101_inputs.json')
IMPACT = Path(__file__).with_name('release_ivv_v4101_impact.json')
verify_objects = previous.verify_objects
at_pointer = previous.at_pointer
PLAN_SHA256 = '039e36f6f19cbd826df726b09a6e0bcc4352ca2981bd58d9daf84c03af0cc227'
PRODUCT = '8611c84cb8c245195dd5456bebad13a52b1d7217'
PREVIOUS = '1ac64bc56ee4b4ea9233713f94f415719b9f5ec0'
PREVIOUS_ACCEPTED = '8c3405758a9b369924f466d12652e99d3a84dc56'
MAX_OBJECT = 128 * 1024 * 1024
RELATIONS = frozenset({'current-targeted-observation', 'final-restoration',
    'continuity-review-required', 'historical-support-only', 'source-review',
    'payload-review', 'product-ci', 'cryptographic-prerequisite'})
require = frozen.require
equal = lambda a, b, message: require(frozen.bundle.exact_json_equal(a, b), message)


def load_plan() -> dict:
    wire = frozen.bundle.regular_bytes(PLAN, frozen.MAX_JSON, 'current IVV plan')
    equal(frozen.digest(wire), PLAN_SHA256, 'current plan differs from reviewed bytes')
    plan = frozen.strict_json(wire)
    require(plan['schema'] == 'syswarden-current-intermediate-ivv-plan/v1' and
            plan['release'] == 'v4.10.1' and plan['required_assurance'] == 'IVV' and
            plan['product_candidate'] == PRODUCT and plan['previous_product_candidate'] == PREVIOUS and
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
        require(row['relation'] in RELATIONS and type(row['candidate_commit']) is str and
                frozen.SHA.fullmatch(row['candidate_commit']) is not None, 'invalid evidence relation')
        require(row['object_sha256'] in objects, 'reviewed observation is absent')
        doc = frozen.strict_json(objects[row['object_sha256']])
        if row['relation'] in ('current-targeted-observation', 'product-ci', 'source-review',
                               'payload-review', 'cryptographic-prerequisite'):
            equal(row['candidate_commit'], PRODUCT, 'current observation binds another candidate')
        if row['relation'] == 'continuity-review-required':
            equal(row['candidate_commit'], PREVIOUS, 'historical native observation relabeled')
        if row['relation'] == 'historical-support-only':
            equal(row['candidate_commit'], PREVIOUS_ACCEPTED,
                  'historical measurement relabeled')
        if row['relation'] == 'final-restoration':
            equal(row['candidate_commit'], PREVIOUS, 'restoration campaign relabeled')
        for field in ('candidate_commit', 'candidate_sha', 'candidate', 'product_candidate'):
            if field in doc:
                equal(doc[field], row['candidate_commit'], 'original candidate binding differs')
        require(type(row['assertions']) is dict and row['assertions'], 'empty reviewed assertions')
        for pointer, value in row['assertions'].items():
            equal(at_pointer(doc, pointer), value, 'reviewed observation assertion differs: ' + row['id'])
        reviewed.append(dict(id=row['id'], original_candidate=row['candidate_commit'],
                             relation=row['relation'], input_sha256=row['object_sha256'],
                             original_bytes_verified=True, admitted_as_current_native_pass=False))
    return reviewed


def verify_private_inputs(root: Path) -> dict:
    plan = load_plan()
    manifest = load_manifest(plan)
    objects = verify_objects(root, manifest)
    observations = verify_roots(manifest, objects)
    verify_capture_bindings(manifest, objects)
    try:
        from scripts.ci import release_ivv_v4101_payload as payload
    except ModuleNotFoundError:
        import release_ivv_v4101_payload as payload
    payload.verify(objects[payload.NATIVE], objects[payload.PRODUCT])
    # Read again after the assertions to reject changing evidence paths.
    equal(verify_objects(root, manifest), objects, 'private inputs changed during verification')
    equal(load_plan(), plan, 'plan changed during verification')
    equal(load_manifest(plan), manifest, 'manifest changed during verification')
    return dict(schema='syswarden-reviewed-ivv-input-verification/v1',
                product_candidate=PRODUCT, plan_sha256=PLAN_SHA256,
                input_manifest_sha256=plan['private_input_manifest_sha256'],
                object_count=len(objects), reviewed_observations=observations,
                private_raw_inputs_uploaded=False, historical_verdicts_transferred=False,
                intermediate_release_validated=False, qualification_passed=False,
                publication_authorized=False)


def source_binding(repository: Path, publication: str) -> dict:
    plan = load_plan()
    changed = frozen.verify_source(repository, publication, plan)
    verify_source_impact(repository, plan)
    track = frozen.classify(repository, publication, plan)
    return dict(product_candidate=PRODUCT, publication_commit=publication,
                plan_sha256=PLAN_SHA256, classification=track,
                source_changes=changed, frozen_package_bytes=plan['product_packages'],
                impact_sha256=plan['impact_sha256'])


def verify_package_inputs(native: Path) -> list[dict]:
    plan = load_plan()
    for row in plan['product_packages']:
        frozen.read_anchored(native, row, MAX_OBJECT)
    return plan['product_packages']


def verify_capture_bindings(manifest: dict, objects: dict[str, bytes]) -> None:
    """Derived assertions must preserve the exact original receipt and output."""
    # Only graph nodes with all three capture references can be receipts.
    # Logs and scripts may contain receipt-like strings; never parse those as
    # an original receipt merely because a substring happened to match.
    original_receipts = []
    fields = ('source_sha256', 'stdout_sha256', 'stderr_sha256')
    for row in manifest['objects']:
        if len(row['references']) < 3:
            continue
        try:
            doc = frozen.strict_json(objects[row['sha256']])
        except frozen.PlanError:
            continue
        if type(doc) is dict and all(field in doc for field in fields):
            require(all(doc[field] in row['references'] for field in fields),
                    'original receipt is not bound to its capture graph')
            original_receipts.append(doc)
    def capture(doc):
        if 'receipt' not in doc:
            return
        receipt = doc['receipt']
        require(type(receipt) is dict, 'missing original capture receipt')
        for field in fields:
            require(receipt[field] in objects, 'original capture bytes absent')
        require(any(frozen.bundle.exact_json_equal(r, receipt) for r in original_receipts),
                'derived capture has no exact original receipt')
        output = objects[receipt['stdout_sha256']]
        try:
            observations = [frozen.strict_json(output)]
        except frozen.PlanError:
            observations = [frozen.strict_json(line) for line in output.splitlines() if line.strip()]
        equal(doc['observations'], observations, 'derived observation differs from original stdout')
    for row in manifest['roots']:
        doc = frozen.strict_json(objects[row['object_sha256']])
        capture(doc)
        for value in doc.values():
            if type(value) is dict:
                capture(value)


def verify_source_impact(repository: Path, plan: dict) -> None:
    import subprocess
    raw = frozen.bundle.regular_bytes(IMPACT, frozen.MAX_JSON, 'reviewed patch impact')
    equal(frozen.digest(raw), plan['impact_sha256'], 'unreviewed source-impact record')
    impact = frozen.strict_json(raw)
    equal(impact['product_candidate'], PRODUCT, 'wrong source-impact product')
    equal(impact['native_tested_candidate'], PREVIOUS, 'native observation was relabeled')
    equal(set(impact['comparison_trees']),
          {plan['last_public_release']['commit'], PREVIOUS, PRODUCT},
          'source comparison omits a required tree')
    for commit, tree in impact['comparison_trees'].items():
        equal(frozen.git(repository, 'rev-parse', commit + '^{tree}'), tree,
              'reviewed source tree differs, including modes and object types')
    def blob(commit, path):
        frozen.relative(path)
        result = subprocess.run(['git', '--no-replace-objects', 'show', commit + ':' + path],
                                cwd=repository, capture_output=True, timeout=30)
        require(result.returncode == 0 and len(result.stdout) <= MAX_OBJECT,
                'source object is missing or oversized')
        return result.stdout
    for name, base in (
        ('source_differences_from_public_release', plan['last_public_release']['commit']),
        ('source_differences_from_native_tested_candidate', PREVIOUS)):
        expected = impact[name]
        paths = frozen.git(repository, 'diff', '--name-only', base, PRODUCT).splitlines()
        equal(paths, [row['path'] for row in expected], 'unreviewed source delta')
        for row in expected:
            equal(frozen.digest(blob(PRODUCT, row['path'])), row['product_sha256'],
                  'product source differs from impact review')
            if row['original_sha256'] is not None:
                equal(frozen.digest(blob(base, row['path'])), row['original_sha256'],
                      'original source differs from impact review')
    closure = impact['native_source_closure']
    paths = [p for p in frozen.git(repository, 'ls-tree', '-r', '--name-only', PRODUCT).splitlines()
             if p.startswith('src/') and p.endswith(('.go', 'go.mod', 'go.sum'))
             and not p.endswith('_test.go')]
    equal(paths, [r['path'] for r in closure['complete_module_inputs']], 'module closure incomplete')
    for row in closure['complete_module_inputs']:
        a, b = blob(PREVIOUS, row['path']), blob(PRODUCT, row['path'])
        equal(frozen.digest(a), row['native_sha256'], 'native module input changed')
        equal(frozen.digest(b), row['product_sha256'], 'product module input changed')
        if a != b:
            permitted = closure['permitted_version_constant_files']
            require(row['path'] in permitted, 'unreviewed runtime source change')
            equal(a.count(b'4.10.0'), permitted[row['path']], 'version substitution scope differs')
            equal(a.replace(b'4.10.0', b'4.10.1'), b, 'runtime difference exceeds reviewed identities')
