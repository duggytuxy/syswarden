#!/usr/bin/env python3
"""Verify the exact signed v4.10.2 updater without transferring an older verdict."""
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
PRODUCT = '94d97f07cb5a054669dd66d6efd28ba55db5d173'
RUN = 37033510001
ARTIFACT = 11237844323
ARCHIVE_SHA256 = 'e0e233a82a1f011026022758ba79951783dedf95661e4ee8ce96ac0f3c61f236'
ARCHIVE_SIZE = 15945332
NATIVE_RUN = 37030270841
NATIVE_ARTIFACT = 11237882878
NATIVE_DIGEST = 'sha256:825aac83e41320bbb8607f91adbfea9a12f3da6e6b116e62c45c9509e2252bf3'
REPOSITORY = original.REPOSITORY
WORKFLOW = original.WORKFLOW
DEB = 'syswarden_4.10.2_amd64.deb'
FILES = {original.DESCRIPTOR, original.ATTESTATION, original.MANIFEST, original.SIGNATURE,
         'node01/' + DEB, 'verification/' + DEB + '.asc', original.CHECKSUMS}
PACKAGES = {'syswarden-4.10.2-1.x86_64.rpm': 'ddd8d62f36d37110813bf61338f409fde9e6251514c4f542791609e4dc399d0a', 'syswarden_4.10.2_amd64.deb': '0e71d9856e6838a3feeea369c514c6ed55676d249b1b3fe213b086cd942e5980', 'syswarden_4.10.2_x86_64.apk': '6a74053f1d0fe4e054a5d6868d899dbc97cdce21d19b828ad8e0c2f2897165ae'}
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
            name=f'syswarden-candidate-update-bundle-4.10.2-{RUN}-1-{PRODUCT}',
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
        release_tag='v4.10.2', release_sha=PRODUCT, public_release=False, release_qualified=False,
        producer=dict(workflow=WORKFLOW, workflow_sha=PRODUCT, run_id=RUN,
                      run_attempt=1, runner_environment='github-hosted'),
        source=dict(native_signing_workflow='.github/workflows/native-package-signing.yml',
                    native_signing_run_id=NATIVE_RUN, native_signing_artifact_id=NATIVE_ARTIFACT,
                    native_signing_artifact_name=f'syswarden-native-signed-packages-qualified-4.10.2-{NATIVE_RUN}-1-{PRODUCT}',
                    native_signing_artifact_digest=NATIVE_DIGEST),
        packages=packages,
        manifest=dict(key_id=manifest['key_id'], document=rec(original.MANIFEST),
                      signature=rec(original.SIGNATURE)),
        node01_bundle=dict(identity=f'github:{REPOSITORY}:candidate-update:v4.10.2:{PRODUCT}:{RUN}:1',
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
    ivv.bundle.verify_bundle(native, 'v4.10.2', PRODUCT)
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
            '--repository', str(repository), '--tag', 'v4.10.2', '--packages', str(packages),
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
