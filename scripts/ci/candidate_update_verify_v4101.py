#!/usr/bin/env python3
"""Verify the exact signed v4.10.1 updater without transferring an older verdict."""
from __future__ import annotations

import argparse
import io
from pathlib import Path
import stat
import tempfile
import zipfile

try:
    from scripts.ci import candidate_update_bundle_verify as original
except ModuleNotFoundError:
    import candidate_update_bundle_verify as original

ivv = original.ivv
PRODUCT = '8611c84cb8c245195dd5456bebad13a52b1d7217'
RUN = 36980486519
ARTIFACT = 11215198424
ARCHIVE_SHA256 = 'ab1b30eb724acd50683d3af108d2902bc6fdbdb7dc4c4e96882d455e1868228a'
ARCHIVE_SIZE = 15919670
NATIVE_RUN = 36978920291
NATIVE_ARTIFACT = 11214948349
NATIVE_DIGEST = 'sha256:6c761b88b1b13d762f5cc7c2ef4e51e59e48422a431dfa877978c6420e11d0b6'
REPOSITORY = original.REPOSITORY
WORKFLOW = original.WORKFLOW
DEB = 'syswarden_4.10.1_amd64.deb'
FILES = {original.DESCRIPTOR, original.ATTESTATION, original.MANIFEST, original.SIGNATURE,
         'node01/' + DEB, 'verification/' + DEB + '.asc', original.CHECKSUMS}
PACKAGES = {
    'syswarden-4.10.1-1.x86_64.rpm': '1dd9d6d5d10a4adeba73d6f6786b2d7611fca32ca80b158adb8e2953bd4fabc8',
    'syswarden_4.10.1_amd64.deb': '97fc84d1273227c0887349534b93c3725299313b72a9c3ce2370c2aec4eee720',
    'syswarden_4.10.1_x86_64.apk': '708bb718e8edc240f98c86ababe34a385ff2ec7b69122abc64e124391fb55cee',
}
PINNED_HELPERS = (
    'scripts/ci/candidate_update_bundle_verify.py',
    'scripts/ci/candidate_update_binding.py',
    'scripts/ci/release_ivv_plan.py',
    'scripts/ci/release_ivv_plan_v4.10.0.json',
    'scripts/ci/native_package_signing_bundle.py',
    'scripts/ci/native_package_signature_gate.py',
    'scripts/ci/update_manifest.go',
    'src/core/syswarden-cli/pkg/system/release_trust_roots.json',
)
equal = original.equal


def snapshot(root: Path) -> dict[str, bytes]:
    ivv.require(root.is_absolute() and root == root.resolve(strict=True), 'unsafe updater root')
    entries = list(root.rglob('*'))
    ivv.require(len(entries) == len(FILES) + 2, 'unexpected updater entry count')
    files = {}
    directories = set()
    for entry in entries:
        ivv.require(not entry.is_symlink(), 'symbolic link in updater bundle')
        name = entry.relative_to(root).as_posix()
        if entry.is_dir():
            directories.add(name)
        else:
            ivv.require(name in FILES, 'unexpected updater file')
            files[name] = ivv.bundle.regular_bytes(entry, 128 * 1024 * 1024, name)
    ivv.require(set(files) == FILES and directories == {'node01', 'verification'},
                'updater inventory is not exact')
    expected = ''.join(f'{ivv.digest(files[name])}  {name}\n'
                       for name in sorted(FILES - {original.CHECKSUMS})).encode()
    ivv.require(files[original.CHECKSUMS] == expected, 'updater checksums are not canonical or correct')
    return files


def verify_helpers(repository: Path) -> None:
    """A later tooling checkout cannot silently weaken shared verifiers."""
    ivv.require(repository.is_absolute() and repository == repository.resolve(strict=True),
                'noncanonical repository')
    ivv.require(not ivv.git(repository, 'for-each-ref', 'refs/replace'), 'replacement refs forbidden')
    import subprocess
    for name in PINNED_HELPERS:
        expected = subprocess.check_output(['git', '--no-replace-objects', 'show',
                                           PRODUCT + ':' + name], cwd=repository)
        ivv.require(repository / name == (repository / name).resolve(strict=True),
                    'symbolic link in shared verifier path')
        actual = ivv.bundle.regular_bytes(repository / name, 4 * 1024 * 1024, name)
        equal(ivv.digest(actual), ivv.digest(expected), 'shared frozen verifier changed: ' + name)


def verify_metadata(run: dict, artifact: dict) -> None:
    for key, value in dict(id=RUN, head_sha=PRODUCT, head_branch='main', event='workflow_dispatch',
            path=WORKFLOW, run_attempt=1, status='completed', conclusion='success').items():
        equal(run[key], value, 'new updater producer mismatch: ' + key)
    for key in ('actor', 'triggering_actor'):
        equal(run[key]['login'], 'duggytuxy', 'wrong producer owner')
        equal(run[key]['id'], 61513268, 'wrong producer owner ID')
    for key in ('repository', 'head_repository'):
        equal(run[key]['id'], 1153695079, 'wrong producer repository ID')
        equal(run[key]['full_name'], REPOSITORY, 'wrong producer repository')
    for key, value in dict(id=ARTIFACT, size_in_bytes=ARCHIVE_SIZE,
            name=f'syswarden-candidate-update-bundle-4.10.1-{RUN}-1-{PRODUCT}',
            digest='sha256:' + ARCHIVE_SHA256).items():
        equal(artifact[key], value, 'new updater artifact mismatch: ' + key)
    ivv.require(artifact['expired'] is False, 'current updater artifact expired')
    for key, value in dict(id=RUN, repository_id=1153695079, head_repository_id=1153695079,
                          head_branch='main', head_sha=PRODUCT).items():
        equal(artifact['workflow_run'][key], value, 'artifact producer mismatch: ' + key)


def verify_archive(archive: Path, files: dict[str, bytes]) -> None:
    ivv.require(archive.is_absolute() and archive == archive.resolve(strict=True), 'unsafe archive path')
    wire = ivv.bundle.regular_bytes(archive, 128 * 1024 * 1024, 'new updater archive')
    equal(len(wire), ARCHIVE_SIZE, 'archive size differs')
    equal(ivv.digest(wire), ARCHIVE_SHA256, 'archive digest differs')
    with zipfile.ZipFile(io.BytesIO(wire)) as packed:
        rows = packed.infolist()
        ivv.require(len(rows) == len(FILES) and
                    {r.filename for r in rows} == FILES, 'archive inventory differs')
        ivv.require(sum(r.file_size for r in rows) < 128 * 1024 * 1024, 'archive too large')
        for row in rows:
            ivv.require(not row.is_dir() and not row.flag_bits & 1 and
                        stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG), 'unsafe ZIP entry')
            equal(packed.read(row), files[row.filename], 'staged bytes differ from original archive')


def verify_descriptor(files: dict[str, bytes], native: Path) -> dict:
    descriptor = ivv.strict_json(files[original.DESCRIPTOR])
    packages = []
    for name, digest in sorted(PACKAGES.items()):
        wire = ivv.bundle.regular_bytes(native / 'packages' / name, 128 * 1024 * 1024, name)
        equal(ivv.digest(wire), digest, 'wrong current product package')
        packages.append(dict(name=name, sha256=digest, size=len(wire)))
    equal(files['node01/' + DEB],
          (native / 'packages' / DEB).read_bytes(), 'substituted updater DEB')
    equal(files['verification/' + DEB + '.asc'],
          ivv.bundle.regular_bytes(native / 'packages' / (DEB + '.asc'),
                                   ivv.MAX_JSON, 'native DEB signature'), 'substituted DEB signature')
    manifest = ivv.strict_json(files[original.MANIFEST])
    rec = lambda name: original.record(files, name)
    expected = dict(schema_version=1, profile='syswarden-candidate-update-bundle/v1',
        status='candidate-signed-not-release-qualified', repository=REPOSITORY,
        release_tag='v4.10.1', release_sha=PRODUCT, public_release=False, release_qualified=False,
        producer=dict(workflow=WORKFLOW, workflow_sha=PRODUCT, run_id=RUN,
                      run_attempt=1, runner_environment='github-hosted'),
        source=dict(native_signing_workflow='.github/workflows/native-package-signing.yml',
                    native_signing_run_id=NATIVE_RUN, native_signing_artifact_id=NATIVE_ARTIFACT,
                    native_signing_artifact_name=f'syswarden-native-signed-packages-qualified-4.10.1-{NATIVE_RUN}-1-{PRODUCT}',
                    native_signing_artifact_digest=NATIVE_DIGEST),
        packages=packages,
        manifest=dict(key_id=manifest['key_id'], document=rec(original.MANIFEST),
                      signature=rec(original.SIGNATURE)),
        node01_bundle=dict(identity=f'github:{REPOSITORY}:candidate-update:v4.10.1:{PRODUCT}:{RUN}:1',
                           directory='node01', exact_file_count=3,
                           files=sorted([rec(p) for p in (original.MANIFEST, original.SIGNATURE,
                                                        'node01/' + DEB)], key=lambda x:x['path'])),
        detached_deb_signature=rec('verification/' + DEB + '.asc'),
        attestation=dict(mechanism='github-artifact-attestation',
                         predicate_type='https://slsa.dev/provenance/v1',
                         subject=original.DESCRIPTOR, bundle_path=original.ATTESTATION))
    equal(descriptor, expected, 'descriptor is not the exact current v1 updater')
    return descriptor


def verify(repository: Path, native: Path, root: Path, archive: Path) -> dict:
    verify_helpers(repository)
    ivv.bundle.verify_bundle(native, 'v4.10.1', PRODUCT)
    files = snapshot(root)
    verify_archive(archive, files)
    descriptor = verify_descriptor(files, native)
    run_wire = original.command(['gh', 'api', f'repos/{REPOSITORY}/actions/runs/{RUN}'], repository)
    artifact_wire = original.command(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{ARTIFACT}'], repository)
    verify_metadata(ivv.strict_json(run_wire), ivv.strict_json(artifact_wire))
    attested = original.command(['gh', 'attestation', 'verify', str(root / original.DESCRIPTOR),
        '--bundle', str(root / original.ATTESTATION), '--repo', REPOSITORY,
        '--signer-workflow', REPOSITORY + '/' + WORKFLOW, '--signer-digest', PRODUCT,
        '--source-digest', PRODUCT, '--source-ref', 'refs/heads/main',
        '--deny-self-hosted-runners', '--format', 'json'], repository)
    original.verify_attestation_result(attested, PRODUCT, RUN, ivv.digest(files[original.DESCRIPTOR]))
    with tempfile.TemporaryDirectory(prefix='syswarden-current-updater-') as temporary:
        packages = Path(temporary)
        payloads = {}
        for name in PACKAGES:
            payloads[name] = ivv.bundle.regular_bytes(native / 'packages' / name,
                                                     128 * 1024 * 1024, name)
            ivv.bundle.write_exclusive(packages / name, payloads[name])
        ivv.bundle.write_exclusive(packages / 'SHA256SUMS.txt', ivv.bundle.canonical_manifest(payloads))
        original.command(['go', 'run', './scripts/ci/update_manifest.go', 'verify',
            '--repository', str(repository), '--tag', 'v4.10.1', '--packages', str(packages),
            '--manifest', str(root / original.MANIFEST), '--signature', str(root / original.SIGNATURE)], repository)
    verify_helpers(repository)
    equal(verify_descriptor(files, native), descriptor, 'native inputs changed during verification')
    equal(snapshot(root), files, 'updater changed during verification')
    verify_archive(archive, files)
    return dict(schema='syswarden-current-candidate-updater-verification/v1',
        status='current-candidate-manifest-cryptographically-verified',
        product_candidate=PRODUCT, producer_commit=PRODUCT, producer_run_id=RUN,
        artifact_id=ARTIFACT, artifact_sha256=ARCHIVE_SHA256,
        descriptor_sha256=ivv.digest(files[original.DESCRIPTOR]),
        manifest_sha256=ivv.digest(files[original.MANIFEST]),
        manifest_signature_sha256=ivv.digest(files[original.SIGNATURE]),
        attestation_verification_sha256=ivv.digest(attested),
        run_metadata_sha256=ivv.digest(run_wire), artifact_metadata_sha256=ivv.digest(artifact_wire),
        packages=descriptor['packages'], native_update_replayed=False,
        historical_verdicts_transferred=False, intermediate_release_validated=False,
        qualification_passed=False, publication_authorized=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'native-bundle', 'candidate-bundle', 'archive', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.repository, args.native_bundle, args.candidate_bundle, args.archive)
        ivv.write_new(args.output, result)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError,
            zipfile.BadZipFile) as exc:
        parser.exit(1, f'Current updater rejected: {exc}\n')
    print('New updater cryptographically verified; no release acceptance granted.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
