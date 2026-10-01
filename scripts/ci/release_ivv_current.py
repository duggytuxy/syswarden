#!/usr/bin/env python3
"""Validate reviewed current IVV inputs while preserving historical identities.

This module grants no protected acceptance. The protected producer must also
reverify signatures, updater provenance and publication CI. Publisher consumers
must authenticate that producer independently.
"""
from __future__ import annotations

from pathlib import Path
import os
import stat

try:
    from scripts.ci import release_ivv_plan as frozen
except ModuleNotFoundError:
    import release_ivv_plan as frozen

PLAN = Path(__file__).with_name('release_ivv_current_v4.10.0.json')
INPUTS = Path(__file__).with_name('release_ivv_current_inputs.json')
PLAN_SHA256 = 'fc8147e574f5728147787700fe6c65961eb0be61562e467c8436dd56c9b176ab'
PRODUCT = '8c3405758a9b369924f466d12652e99d3a84dc56'
PREVIOUS = 'f334beaddc5c6005f40d79c7bab4e43598bfc5ed'
MAX_OBJECT = 128 * 1024 * 1024
RELATIONS = frozenset({'current-targeted-observation', 'final-restoration',
    'continuity-review-required', 'historical-support-only', 'source-review',
    'payload-review', 'product-ci', 'cryptographic-prerequisite'})
require = frozen.require
equal = lambda a, b, message: require(frozen.bundle.exact_json_equal(a, b), message)


def read_object(path: Path, size: int) -> bytes:
    if size:
        return frozen.bundle.regular_bytes(path, MAX_OBJECT, 'private evidence object')
    # Empty diagnostic logs are valid historical inputs. Keep the original
    # nonempty package reader unchanged and bind this case to an empty file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 0,
                'empty diagnostic is not an empty single-link regular file')
        require(os.read(fd, 1) == b'', 'empty diagnostic contains bytes')
        after = os.fstat(fd)
        current = path.lstat()
        for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            require(getattr(before, field) == getattr(after, field) == getattr(current, field),
                    'empty diagnostic changed while reading')
        return b''
    finally:
        os.close(fd)


def load_plan() -> dict:
    wire = frozen.bundle.regular_bytes(PLAN, frozen.MAX_JSON, 'current IVV plan')
    equal(frozen.digest(wire), PLAN_SHA256, 'current plan differs from reviewed bytes')
    plan = frozen.strict_json(wire)
    require(plan['schema'] == 'syswarden-current-intermediate-ivv-plan/v1' and
            plan['release'] == 'v4.10.0' and plan['required_assurance'] == 'IVV' and
            plan['product_candidate'] == PRODUCT and plan['previous_product_candidate'] == PREVIOUS and
            plan['preflight_is_acceptance'] is False, 'unsupported current IVV plan')
    equal(plan['historical_plan_sha256'], frozen.PLAN_SHA256, 'historical plan was replaced')
    frozen.load_plan()
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


def verify_objects(root: Path, manifest: dict) -> dict[str, bytes]:
    require(root.is_absolute() and root == root.resolve(strict=True), 'unsafe private evidence root')
    directory = root / 'objects'
    require(directory.is_dir() and directory == directory.resolve(strict=True), 'unsafe object directory')
    rows = manifest['objects']
    require(type(rows) is list and 0 < len(rows) <= 10000, 'invalid object count')
    objects = {}
    for row in rows:
        equal(set(row), {'path', 'sha256', 'size', 'references'}, 'unexpected object anchor fields')
        digest = row['sha256']
        require(type(digest) is str and frozen.SHA256.fullmatch(digest) is not None,
                'invalid evidence digest')
        require(row['path'] == 'objects/' + digest and digest not in objects,
                'duplicate or unsafe evidence object path')
        require(type(row['size']) is int and 0 <= row['size'] <= MAX_OBJECT, 'invalid evidence size')
        require(type(row['references']) is list and
                len(set(row['references'])) == len(row['references']), 'duplicate graph edge')
        path = root / row['path']
        require(path == path.resolve(strict=True), 'symbolic link in private object path')
        wire = read_object(path, row['size'])
        require(len(wire) == row['size'] and frozen.digest(wire) == digest, 'private evidence bytes changed')
        objects[digest] = wire
    equal({path.name for path in directory.iterdir()}, set(objects), 'missing or extra private object')
    require(all(set(row['references']) <= set(objects) for row in rows), 'referenced private proof missing')
    return objects


def at_pointer(document, pointer: str):
    require(type(pointer) is str and pointer and not pointer.startswith('/'), 'invalid assertion pointer')
    value = document
    for part in pointer.split('/'):
        if type(value) is list:
            require(part.isdecimal() and str(int(part)) == part and int(part) < len(value),
                    'invalid list assertion pointer')
            value = value[int(part)]
        else:
            require(type(value) is dict and part in value, 'required observation field missing')
            value = value[part]
    return value


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
            equal(row['candidate_commit'], '24c3c6e1548b8db0ccf64c37a33e05b351be5a18',
                  'historical measurement relabeled')
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
    track = frozen.classify(repository, publication, plan)
    return dict(product_candidate=PRODUCT, publication_commit=publication,
                plan_sha256=PLAN_SHA256, classification=track,
                source_changes=changed, frozen_package_bytes=plan['product_packages'])


def verify_package_inputs(native: Path) -> list[dict]:
    plan = load_plan()
    for row in plan['product_packages']:
        frozen.read_anchored(native, row, MAX_OBJECT)
    return plan['product_packages']
