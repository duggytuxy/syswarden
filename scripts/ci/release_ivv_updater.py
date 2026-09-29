#!/usr/bin/env python3
"""Reverify the frozen IVV updater from a later publication checkout.

The original producer checkout stays separate and clean. Its original consumer
rechecks Sigstore, Ed25519, GitHub run identity and the frozen product bytes.
This prerequisite is neither native update acceptance nor release acceptance.
"""
from __future__ import annotations

import argparse
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile

try:
    from scripts.ci import candidate_update_bundle_verify as consumer
except ModuleNotFoundError:
    import candidate_update_bundle_verify as consumer

ivv = consumer.ivv
PRODUCER = '2b35616c686210886c71d0e207f0ded2ccf256a4'
PRODUCT = 'f334beaddc5c6005f40d79c7bab4e43598bfc5ed'
RUN = 36622881503
ARTIFACT = 11059596903
ARCHIVE_SHA256 = '7c178ebcd5d2cabe7bc1f316b6c5b94bd5a67e7497c0491fe29db0f39a8b48be'
ARCHIVE_SIZE = 15919756
DESCRIPTOR_SHA256 = '1122675a316f749d5d37fcba0933e68102eb368973df67881d9d1cf9e3fc5e17'
EXTENSION_PATHS = frozenset({
    'scripts/ci/release_ivv_updater.py',
    'scripts/ci/release_ivv_updater_test.py',
    'docs/qualification/INTERMEDIATE_UPDATER_CONSUMPTION_V4.10.0.md',
})
VERIFIER_PATHS = frozenset({
    'scripts/ci/candidate_update_bundle_verify.py',
    'scripts/ci/candidate_update_binding.py',
    'scripts/ci/release_ivv_plan.py',
    'scripts/ci/release_ivv_plan_v4.10.0.json',
    'scripts/ci/native_package_signing_bundle.py',
    'scripts/ci/native_package_signature_gate.py',
    'scripts/ci/update_manifest.go',
    'scripts/versioning.sh',
    'scripts/versionctl/command.go',
    'scripts/versionctl/release_track.go',
})


def equal(actual, expected, message):
    ivv.require(ivv.bundle.exact_json_equal(actual, expected), message)


def publication_binding(repository: Path, publication: str, producer: Path) -> dict:
    plan = ivv.load_plan()
    ivv.require(plan['product_candidate'] == PRODUCT, 'unreviewed product candidate')
    # Do not alter the producer's historical plan or recompute its descriptor
    # against today's source. The narrowly reviewed extension concerns only
    # this consumer; future publication changes need their own explicit review.
    ivv.verify_source(producer, PRODUCER, plan)
    ivv.classify(producer, PRODUCER, plan)
    extended = copy.deepcopy(plan)
    extended['publication_source_change_allowlist'] = sorted(
        set(plan['publication_source_change_allowlist']) | EXTENSION_PATHS)
    changes = ivv.verify_source(repository, publication, extended)
    track = ivv.classify(repository, publication, plan)
    ivv.require(ivv.git(repository, 'merge-base', PRODUCER, publication) == PRODUCER,
                'publication does not descend from the original updater producer')
    pinned = {}
    for name in sorted(VERIFIER_PATHS):
        original = ivv.git(producer, 'rev-parse', f'{PRODUCER}:{name}')
        current = ivv.git(repository, 'rev-parse', f'{publication}:{name}')
        ivv.require(original == current, 'updater verification dependency changed: ' + name)
        pinned[name] = original
    return dict(product_candidate=PRODUCT, updater_producer_commit=PRODUCER,
                publication_commit=publication, original_plan_sha256=ivv.PLAN_SHA256,
                classification=track, source_changes=changes,
                verifier_git_blobs=pinned)


def verify_artifact_metadata(document: dict) -> None:
    expected = dict(id=ARTIFACT,
        name=f'syswarden-candidate-update-bundle-4.10.0-{RUN}-1-{PRODUCT}',
        size_in_bytes=ARCHIVE_SIZE, digest='sha256:' + ARCHIVE_SHA256)
    for key, value in expected.items():
        equal(document[key], value, 'wrong original updater artifact ' + key)
    ivv.require(type(document['expired']) is bool, 'invalid artifact expiry metadata')
    # Expiry affects redownload availability, not signatures of retained bytes.
    for key, value in dict(id=RUN, repository_id=1153695079,
            head_repository_id=1153695079, head_branch='main', head_sha=PRODUCER).items():
        equal(document['workflow_run'][key], value, 'wrong original artifact producer ' + key)


def verify_archive(archive: Path, files: dict[str, bytes]) -> str:
    ivv.require(archive.is_absolute() and archive == archive.resolve(strict=True),
                'updater archive path is not canonical')
    wire = ivv.bundle.regular_bytes(archive, 128 * 1024 * 1024, 'original updater archive')
    ivv.require(len(wire) == ARCHIVE_SIZE and ivv.digest(wire) == ARCHIVE_SHA256,
                'updater archive is not the originally reviewed GitHub artifact')
    with zipfile.ZipFile(io.BytesIO(wire)) as packed:
        rows = packed.infolist()
        ivv.require(len(rows) == len(consumer.FILES) and
                    {row.filename for row in rows} == consumer.FILES,
                    'updater archive inventory is not exact')
        ivv.require(sum(row.file_size for row in rows) < 128 * 1024 * 1024,
                    'updater archive expands beyond its bound')
        for row in rows:
            mode = row.external_attr >> 16
            ivv.require(not row.is_dir() and not row.flag_bits & 1 and
                        stat.S_IFMT(mode) in (0, stat.S_IFREG), 'unsafe updater archive entry')
            ivv.require(packed.read(row) == files[row.filename],
                        'staged updater file differs from original GitHub archive')
    return ivv.digest(wire)


def original_consumer(producer: Path, native: Path, updater: Path) -> dict:
    # Execute the actual, unchanged producer-era consumer in its checkout.
    # Its fresh output cannot be replaced by a supplied pass receipt.
    with tempfile.TemporaryDirectory(prefix='syswarden-ivv-updater-') as temporary:
        output = Path(temporary) / 'consumer.json'
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)
        result = subprocess.run([sys.executable, '-E', '-s',
            str(producer / 'scripts/ci/candidate_update_bundle_verify.py'),
            '--repository', str(producer), '--publication-sha', PRODUCER,
            '--product-sha', PRODUCT, '--producer-run-id', str(RUN),
            '--native-bundle', str(native), '--candidate-bundle', str(updater),
            '--output', str(output)], cwd=producer, env=environment,
            capture_output=True, timeout=600)
        ivv.require(result.returncode == 0, 'original independent updater consumer rejected inputs')
        return ivv.strict_json(ivv.bundle.regular_bytes(output, ivv.MAX_JSON, 'fresh updater receipt'))


def verify(repository: Path, publication: str, producer: Path,
           native: Path, updater: Path, archive: Path) -> dict:
    source = publication_binding(repository, publication, producer)
    files = consumer.snapshot(updater)
    equal(ivv.digest(files[consumer.DESCRIPTOR]), DESCRIPTOR_SHA256, 'wrong original updater descriptor')
    archive_digest = verify_archive(archive, files)
    metadata_wire = consumer.command(['gh', 'api', '--method', 'GET',
        f'repos/{consumer.REPOSITORY}/actions/artifacts/{ARTIFACT}'], producer)
    verify_artifact_metadata(ivv.strict_json(metadata_wire))
    receipt = original_consumer(producer, native, updater)
    for key, value in dict(schema='syswarden-candidate-update-consumption/v2',
            status='candidate-updater-verified-not-release-validated',
            product_candidate=PRODUCT, publication_commit=PRODUCER,
            producer_run_id=RUN, descriptor_sha256=DESCRIPTOR_SHA256,
            intermediate_release_validated=False, qualification_passed=False,
            publication_authorized=False).items():
        equal(receipt[key], value, 'fresh consumer receipt mismatch: ' + key)
    equal(publication_binding(repository, publication, producer), source,
          'publication source changed during updater verification')
    equal(consumer.snapshot(updater), files, 'updater changed during verification')
    equal(verify_archive(archive, files), archive_digest, 'original archive changed during verification')
    return dict(schema='syswarden-intermediate-updater-revalidation/v1',
        status='original-updater-reverified-native-acceptance-pending',
        source_binding=source, updater_artifact_id=ARTIFACT,
        updater_archive_sha256=archive_digest, artifact_metadata_sha256=ivv.digest(metadata_wire),
        original_consumer_receipt=receipt, native_update_accepted=False,
        intermediate_release_validated=False, qualification_passed=False,
        publication_authorized=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('repository', 'producer-repository', 'native-bundle', 'candidate-bundle', 'archive', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    parser.add_argument('--publication-sha', required=True)
    args = parser.parse_args()
    try:
        result = verify(args.repository, args.publication_sha, args.producer_repository,
                        args.native_bundle, args.candidate_bundle, args.archive)
        ivv.write_new(args.output, result)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError,
            zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Original IVV updater rejected: {exc}\n')
    print('Original updater reverified; native update and release acceptance remain separate.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
