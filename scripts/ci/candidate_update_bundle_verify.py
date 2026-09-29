#!/usr/bin/env python3
"""Independently verify an IVV candidate updater v2; never authorize publication."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

try:
    from scripts.ci import candidate_update_binding as binding
except ModuleNotFoundError:
    import candidate_update_binding as binding

ivv = binding.ivv
REPOSITORY = 'duggytuxy/syswarden'
WORKFLOW = '.github/workflows/candidate-update-bundle.yml'
DESCRIPTOR = 'CANDIDATE_UPDATE_BUNDLE.json'
ATTESTATION = 'verification/producer-attestation.jsonl'
MANIFEST = 'node01/syswarden-update-manifest-v1.json'
SIGNATURE = MANIFEST + '.sig'
DEB = 'syswarden_4.10.0_amd64.deb'
CHECKSUMS = 'CANDIDATE_UPDATE_SHA256SUMS.txt'
FILES = {DESCRIPTOR, ATTESTATION, MANIFEST, SIGNATURE, 'node01/' + DEB,
         'verification/' + DEB + '.asc', CHECKSUMS}


def equal(actual, expected, label):
    ivv.require(ivv.bundle.exact_json_equal(actual, expected), label)


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
                       for name in sorted(FILES - {CHECKSUMS})).encode()
    ivv.require(files[CHECKSUMS] == expected, 'updater checksums are not canonical or correct')
    return files


def record(files: dict[str, bytes], name: str) -> dict:
    wire = files[name]
    return dict(path=name, size=len(wire), sha256=ivv.digest(wire))


def descriptor_check(files: dict[str, bytes], source: dict, run: int) -> dict:
    ivv.require(type(run) is int and run > 0, 'invalid producer run ID')
    descriptor = ivv.strict_json(files[DESCRIPTOR])
    manifest = ivv.strict_json(files[MANIFEST])
    anchors = {row['path']: row for row in source['frozen_package_bytes']}
    packages = sorted([dict(name=Path(row['path']).name, sha256=row['sha256'], size=row['size'])
                       for row in anchors.values()
                       if row['path'].startswith('packages/') and not row['path'].endswith('.asc')],
                      key=lambda row: row['name'])
    for path, original in [('node01/' + DEB, 'packages/' + DEB),
                           ('verification/' + DEB + '.asc', 'packages/' + DEB + '.asc')]:
        equal(record(files, path), dict(anchors[original], path=path), 'updater package/signature was substituted')
    native = source['native_signing']
    expected = {
        'schema_version': 2, 'profile': 'syswarden-candidate-update-bundle/v2',
        'status': 'candidate-signed-not-release-qualified', 'repository': REPOSITORY,
        'release_tag': source['release'], 'release_sha': source['product_candidate'],
        'public_release': False, 'release_qualified': False,
        'producer': dict(workflow=WORKFLOW, workflow_sha=source['publication_commit'],
                         run_id=run, run_attempt=1, runner_environment='github-hosted'),
        'source': dict(native_signing_workflow='.github/workflows/native-package-signing.yml',
                       native_signing_run_id=native['run_id'], native_signing_artifact_id=native['artifact_id'],
                       native_signing_artifact_name=native['artifact_name'],
                       native_signing_artifact_digest=native['artifact_digest']),
        'packages': packages,
        'manifest': dict(key_id=manifest['key_id'], document=record(files, MANIFEST),
                         signature=record(files, SIGNATURE)),
        'node01_bundle': dict(identity=f"github:{REPOSITORY}:candidate-update:{source['release']}:{source['product_candidate']}:{run}:1",
                             directory='node01', exact_file_count=3,
                             files=sorted([record(files, name) for name in [MANIFEST, SIGNATURE, 'node01/' + DEB]],
                                          key=lambda row: row['path'])),
        'detached_deb_signature': record(files, 'verification/' + DEB + '.asc'),
        'attestation': dict(mechanism='github-artifact-attestation', predicate_type='https://slsa.dev/provenance/v1',
                            subject=DESCRIPTOR, bundle_path=ATTESTATION),
        'source_binding': source,
    }
    equal(descriptor, expected, 'candidate updater descriptor is not the exact v2 producer/product binding')
    return descriptor


def verify_attestation_result(wire: bytes, publication: str, run: int, digest: str) -> None:
    # Reuse strict decoding for nested keys and reject non-finite/duplicate input.
    rows = ivv.strict_json(b'{"results":' + wire + b'}')['results']
    ivv.require(type(rows) is list and len(rows) == 1, 'exactly one verified producer statement is required')
    statement = rows[0]['verificationResult']['statement']
    equal(statement['subject'], [dict(name=DESCRIPTOR, digest=dict(sha256=digest))], 'attested subject differs')
    ivv.require(statement['predicateType'] == 'https://slsa.dev/provenance/v1', 'wrong provenance predicate')
    predicate = statement['predicate']
    build = predicate['buildDefinition']
    ivv.require(build['buildType'] == 'https://actions.github.io/buildtypes/workflow/v1', 'wrong producer build type')
    equal(build['externalParameters']['workflow'],
          dict(ref='refs/heads/main', repository='https://github.com/' + REPOSITORY, path=WORKFLOW),
          'wrong attested workflow')
    github = build['internalParameters']['github']
    for key, expected in dict(event_name='workflow_dispatch', repository_id='1153695079',
                              repository_owner_id='61513268', runner_environment='github-hosted').items():
        equal(github[key], expected, 'wrong attested producer context')
    equal(build['resolvedDependencies'], [dict(uri=f'git+https://github.com/{REPOSITORY}@refs/heads/main',
                                               digest=dict(gitCommit=publication))], 'wrong producer source commit')
    equal(predicate['runDetails']['builder']['id'],
          f'https://github.com/{REPOSITORY}/{WORKFLOW}@refs/heads/main', 'wrong producer builder')
    equal(predicate['runDetails']['metadata']['invocationId'],
          f'https://github.com/{REPOSITORY}/actions/runs/{run}/attempts/1', 'wrong producer run or attempt')


def command(argv: list[str], repository: Path) -> bytes:
    environment = dict(os.environ, GOFLAGS='-mod=readonly', PYTHONDONTWRITEBYTECODE='1')
    environment.pop('SYSWARDEN_UPDATE_ED25519_PRIVATE_KEY', None)
    try:
        result = subprocess.run(argv, cwd=repository, env=environment, capture_output=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ivv.PlanError('cannot run independent updater verification') from exc
    ivv.require(result.returncode == 0, 'independent updater verification command failed')
    ivv.require(len(result.stdout) <= 4 * 1024 * 1024, 'verification response is too large')
    return result.stdout


def verify(repository: Path, publication: str, product: str, native: Path,
           root: Path, run: int) -> dict:
    source = binding.source_binding(repository, publication, product)
    binding.verify_binding(source, repository, publication, product, native)
    ivv.bundle.verify_bundle(native, source['release'], product)
    files = snapshot(root)
    descriptor_check(files, source, run)
    run_wire = command(['gh', 'api', '--method', 'GET', f'repos/{REPOSITORY}/actions/runs/{run}'], repository)
    observed = ivv.strict_json(run_wire)
    for key, expected in dict(id=run, head_sha=publication, head_branch='main', event='workflow_dispatch',
                              path=WORKFLOW, run_attempt=1, status='completed', conclusion='success').items():
        equal(observed[key], expected, 'producer run is not one successful exact-main attempt')
    equal(observed['actor']['login'], 'duggytuxy', 'producer actor is not the owner')
    equal(observed['triggering_actor']['login'], 'duggytuxy', 'producer triggering actor is not the owner')
    attestation_wire = command([
        'gh', 'attestation', 'verify', str(root / DESCRIPTOR), '--bundle', str(root / ATTESTATION),
        '--repo', REPOSITORY, '--signer-workflow', REPOSITORY + '/' + WORKFLOW,
        '--signer-digest', publication, '--source-digest', publication, '--source-ref', 'refs/heads/main',
        '--deny-self-hosted-runners', '--format', 'json'], repository)
    verify_attestation_result(attestation_wire, publication, run, ivv.digest(files[DESCRIPTOR]))
    # The updater manifest verifier expects the three standard packages. Keep
    # the complete four-variant signed bundle untouched and use private copies.
    with tempfile.TemporaryDirectory(prefix='syswarden-updater-verify-') as temporary:
        packages = Path(temporary)
        payloads = {}
        for row in source['frozen_package_bytes']:
            if row['path'].startswith('packages/') and not row['path'].endswith('.asc'):
                payloads[Path(row['path']).name] = ivv.read_anchored(native, row, 128 * 1024 * 1024)
        for name, wire in payloads.items():
            ivv.bundle.write_exclusive(packages / name, wire)
        ivv.bundle.write_exclusive(packages / 'SHA256SUMS.txt', ivv.bundle.canonical_manifest(payloads))
        command(['go', 'run', './scripts/ci/update_manifest.go', 'verify', '--repository', str(repository),
                 '--tag', source['release'], '--packages', str(packages), '--manifest', str(root / MANIFEST),
                 '--signature', str(root / SIGNATURE)], repository)
    binding.verify_binding(source, repository, publication, product, native)
    ivv.require(snapshot(root) == files, 'candidate updater changed during verification')
    return dict(schema='syswarden-candidate-update-consumption/v2',
                status='candidate-updater-verified-not-release-validated',
                product_candidate=product, publication_commit=publication, producer_run_id=run,
                descriptor_sha256=ivv.digest(files[DESCRIPTOR]),
                producer_attestation_sha256=ivv.digest(files[ATTESTATION]),
                run_metadata_sha256=ivv.digest(run_wire), source_binding=source,
                manifest_sha256=ivv.digest(files[MANIFEST]), manifest_signature_sha256=ivv.digest(files[SIGNATURE]),
                native_package_signatures='previously-protected-and-frozen-bytes-reverified',
                intermediate_release_validated=False, qualification_passed=False, publication_authorized=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['repository', 'native-bundle', 'candidate-bundle', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-sha', required=True)
    parser.add_argument('--product-sha', required=True)
    parser.add_argument('--producer-run-id', type=int, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.repository, args.publication_sha, args.product_sha,
                        args.native_bundle, args.candidate_bundle, args.producer_run_id)
        ivv.write_new(args.output, result)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError, IndexError) as exc:
        parser.exit(1, f'Candidate updater rejected: {exc}\n')
    print('Candidate updater v2 independently verified; no release acceptance or publication.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
