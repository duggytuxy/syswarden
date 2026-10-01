#!/usr/bin/env python3
"""Independently consume one protected IVV result at each publisher boundary."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import io
import os
from pathlib import Path
import stat
import subprocess
import zipfile

try:
    from scripts.ci import release_ivv_current as current
    from scripts.ci import release_assurance_contract as assurance
    from scripts.ci import release_ivv_producer as producer
except ModuleNotFoundError:
    import release_ivv_current as current
    import release_assurance_contract as assurance
    import release_ivv_producer as producer

frozen = current.frozen
updater = producer.updater
require, equal = current.require, current.equal
REPOSITORY = producer.REPOSITORY
ATTESTATION = 'RELEASE_IVV.intoto.jsonl'
MAX_ARCHIVE = 128 * 1024 * 1024


def pages(repository: Path, path: str, field: str, *args: str) -> list:
    wire = updater.original.command(['gh', 'api', '--paginate', '--slurp', '--method', 'GET',
        'repos/' + REPOSITORY + '/' + path, '-f', 'per_page=100', *args], repository)
    documents = frozen.strict_json(b'{"pages":' + wire + b'}')['pages']
    require(type(documents) is list and 0 < len(documents) <= 100, 'invalid API pagination')
    rows = []
    for doc in documents:
        require(type(doc[field]) is list, 'invalid API page')
        rows.extend(doc[field])
    equal(documents[0]['total_count'], len(rows), 'incomplete producer inventory')
    require(all(doc['total_count'] == len(rows) for doc in documents), 'inventory changed during pagination')
    return rows


def select(repository: Path, contract, requested: int | None) -> tuple[dict, dict]:
    runs = pages(repository, 'actions/workflows/' + Path(contract.workflow_path).name + '/runs',
        'workflow_runs', '-f', 'event=workflow_dispatch', '-f', 'branch=main',
        '-f', 'head_sha=' + contract.publication_commit)
    run = assurance.select_unique_run(runs, contract, requested)
    assurance.verify_run(producer.api(repository, 'actions/runs/' + str(run['id'])), contract, run['id'])
    rows = pages(repository, 'actions/runs/' + str(run['id']) + '/artifacts', 'artifacts')
    # List responses omit workflow_run; fetch the exact matching artifact independently.
    matches = [r for r in rows if r.get('name') == contract.artifact_name]
    require(len(matches) == 1, 'exactly one assurance artifact required')
    artifact = producer.api(repository, 'actions/artifacts/' + str(matches[0]['id']))
    selected = assurance.select_artifact([artifact], contract, run['id'])
    for name in ('id', 'name', 'digest', 'size_in_bytes', 'expired'):
        equal(selected[name], matches[0][name], 'artifact metadata changed while resolving')
    return run, selected


def download(repository: Path, artifact: dict, destination: Path) -> bytes:
    require(not destination.exists() and not destination.is_symlink(), 'archive output exists')
    require(destination.parent == destination.parent.resolve(strict=True), 'unsafe archive parent')
    # Bound the download before parsing. GitHub metadata is authenticated again below.
    with destination.open('xb') as output:
        result = subprocess.run(['gh', 'api', '--method', 'GET',
            f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"], cwd=repository,
            stdout=output, stderr=subprocess.PIPE, timeout=240)
    require(result.returncode == 0, 'cannot download original protected artifact')
    wire = frozen.bundle.regular_bytes(destination, MAX_ARCHIVE, 'protected artifact archive')
    equal(len(wire), artifact['size_in_bytes'], 'archive size differs from API')
    equal('sha256:' + frozen.digest(wire), artifact['digest'], 'archive differs from API digest')
    return wire


def unpack(wire: bytes, destination: Path) -> dict[str, bytes]:
    require(not destination.exists() and not destination.is_symlink(), 'artifact output exists')
    require(destination.parent == destination.parent.resolve(strict=True), 'unsafe artifact parent')
    destination.mkdir(mode=0o700)
    files = {}
    with zipfile.ZipFile(io.BytesIO(wire)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) < 1000 and sum(r.file_size for r in entries) <= MAX_ARCHIVE,
                'invalid expanded artifact inventory')
        for row in entries:
            name = frozen.relative(row.filename)
            require(name == row.filename and row.filename not in files,
                    'noncanonical or duplicate ZIP entry')
            require(not row.is_dir() and not row.flag_bits & 1 and
                    stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG), 'unsafe ZIP entry')
            data = archive.read(row)
            require(len(data) == row.file_size, 'truncated artifact entry')
            path = destination / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            frozen.bundle.write_exclusive(path, data)
            files[row.filename] = data
    require(producer.REPORT in files and ATTESTATION in files, 'protected report or attestation absent')
    return files


def verify_attestation(wire: bytes, publication: str, run: int, digest: str) -> None:
    rows = frozen.strict_json(b'{"results":' + wire + b'}')['results']
    require(type(rows) is list and len(rows) == 1, 'one verified protected statement required')
    statement = rows[0]['verificationResult']['statement']
    cert = rows[0]['verificationResult']['signature']['certificate']
    equal(cert['issuer'], 'https://token.actions.githubusercontent.com', 'wrong protected OIDC issuer')
    equal(cert['subjectAlternativeName'],
          f'https://github.com/{REPOSITORY}/{producer.WORKFLOW}@refs/heads/main',
          'wrong protected certificate identity')
    equal(statement['_type'], 'https://in-toto.io/Statement/v1', 'wrong statement type')
    equal(statement['subject'], [dict(name=producer.REPORT, digest=dict(sha256=digest))],
          'protected subject differs')
    equal(statement['predicateType'], 'https://slsa.dev/provenance/v1', 'wrong provenance type')
    predicate = statement['predicate']; build = predicate['buildDefinition']
    equal(build['buildType'], 'https://actions.github.io/buildtypes/workflow/v1', 'wrong build type')
    equal(build['externalParameters']['workflow'], dict(ref='refs/heads/main',
          repository='https://github.com/' + REPOSITORY, path=producer.WORKFLOW), 'wrong protected workflow')
    github = build['internalParameters']['github']
    for key, value in dict(event_name='workflow_dispatch', repository_id=str(producer.REPOSITORY_ID),
        repository_owner_id=str(producer.OWNER_ID), runner_environment='self-hosted').items():
        equal(github[key], value, 'wrong protected attestation context: ' + key)
    equal(build['resolvedDependencies'], [dict(uri=f'git+https://github.com/{REPOSITORY}@refs/heads/main',
          digest=dict(gitCommit=publication))], 'wrong protected source')
    equal(predicate['runDetails']['builder']['id'],
          f'https://github.com/{REPOSITORY}/{producer.WORKFLOW}@refs/heads/main', 'wrong protected builder')
    equal(predicate['runDetails']['metadata']['invocationId'],
          f'https://github.com/{REPOSITORY}/actions/runs/{run}/attempts/1', 'wrong protected run or retry')


def expected_inputs() -> dict:
    plan = current.load_plan(); manifest = current.load_manifest(plan)
    rows = [dict(id=r['id'], original_candidate=r['candidate_commit'], relation=r['relation'],
                 input_sha256=r['object_sha256'], original_bytes_verified=True,
                 admitted_as_current_native_pass=False) for r in manifest['roots']]
    return dict(schema='syswarden-reviewed-ivv-input-verification/v1',
        product_candidate=current.PRODUCT, plan_sha256=current.PLAN_SHA256,
        input_manifest_sha256=plan['private_input_manifest_sha256'],
        object_count=len(manifest['objects']), reviewed_observations=rows,
        private_raw_inputs_uploaded=False, historical_verdicts_transferred=False,
        intermediate_release_validated=False, qualification_passed=False, publication_authorized=False)


def verify_report(report: dict, files: dict[str, bytes], source: dict, run: int,
                  now: datetime | None = None) -> None:
    plan = current.load_plan(); publication = source['publication_commit']
    expected_context = dict(repository=REPOSITORY, repository_id=producer.REPOSITORY_ID,
        workflow=producer.WORKFLOW, workflow_ref=REPOSITORY + '/' + producer.WORKFLOW + '@refs/heads/main',
        publication_commit=publication, workflow_run_id=run, workflow_run_attempt=1,
        event='workflow_dispatch', source_ref='refs/heads/main', runner_environment='self-hosted',
        environment=producer.ENVIRONMENT, owner_id=producer.OWNER_ID)
    fixed = dict(schema='syswarden-protected-intermediate-ivv/v1',status='ivv-accepted-for-release',
        release='v4.10.0',required_assurance='IVV',context=expected_context,source_binding=source,
        plan_sha256=current.PLAN_SHA256,input_verification=expected_inputs(),
        continuity_admitted_under_named_plan=True,historical_verdicts_transferred=False,
        private_raw_inputs_uploaded=False,claim_limits=plan['claim_limits'],
        intermediate_release_validated=True,full_qualification_passed=False,
        publication_authorized=False,release_published=False,
        post_acceptance_requirements=plan['post_acceptance_requirements'])
    equal(set(report), set(fixed) | {'accepted_at','native_signature_verification','updater_verification',
          'ci_verification','required_checks','artifact_files','product_support_verification'}, 'unexpected protected report fields')
    for key, value in fixed.items(): equal(report[key], value, 'protected acceptance differs: ' + key)
    accepted = datetime.fromisoformat(report['accepted_at'])
    require(accepted.tzinfo is not None and accepted.utcoffset() == timedelta(0), 'acceptance is not UTC')
    now = now or datetime.now(timezone.utc)
    require(timedelta(minutes=-5) <= now-accepted <= timedelta(hours=24), 'protected acceptance is stale or in the future')
    signatures = report['native_signature_verification']
    equal(set(signatures), {'schema','as_of','checks','four_native_signatures_verified','offline_verification',
          'product_candidate','publication_authorized','purpose','runtime'}, 'unexpected signature receipt fields')
    for key,value in dict(schema='syswarden-current-native-signature-revalidation/v1',
        product_candidate=current.PRODUCT,purpose='publishing',four_native_signatures_verified=True,
        offline_verification=True,publication_authorized=False,
        runtime='rootless-podman-pinned-images-stdin-without-host-mounts',as_of=now.date().isoformat()).items():
        equal(signatures[key],value,'native publication signature check differs: '+key)
    equal([r['name'] for r in signatures['checks']],['rhel-inventory','rpm','rhel-rpm','deb','apk'],
          'a native signature check is absent')
    for row in signatures['checks']:
        equal(set(row), {'name','returncode','stdout_sha256','stderr_sha256'}, 'invalid native check')
        equal(row['returncode'],0,'native signature failed')
        require(all(type(row[k]) is str and frozen.SHA256.fullmatch(row[k]) for k in
                    ('stdout_sha256','stderr_sha256')), 'invalid native check digest')
    update = report['updater_verification']
    for key,value in dict(schema='syswarden-current-candidate-updater-verification/v1',
        status='current-candidate-manifest-cryptographically-verified',product_candidate=current.PRODUCT,
        producer_commit=current.PRODUCT,producer_run_id=updater.RUN,artifact_id=updater.ARTIFACT,
        artifact_sha256=updater.ARCHIVE_SHA256,native_update_replayed=False,
        historical_verdicts_transferred=False,intermediate_release_validated=False,
        qualification_passed=False,publication_authorized=False).items():
        equal(update[key],value,'updater acceptance differs: '+key)
    equal(report['required_checks'], producer.acceptance_checks(expected_inputs(),signatures,update),
          'a required IVV check or its original evidence binding is missing')
    payload = {k:v for k,v in files.items() if k not in (producer.REPORT, ATTESTATION)}
    equal(report['artifact_files'],producer.check_inventory(payload),'public artifact changed after acceptance')
    require(payload and all(n.startswith(('native-signing/','updater/','product-support/')) for n in payload),
            'private or unexpected files in public artifact')
    equal(report['product_support_verification'],dict(schema='syswarden-original-product-support/v1',
        product_candidate=current.PRODUCT,run_id=producer.support.RUN,
        files=[r['file'] for r in plan['product_release_support']],
        binary_members=plan['product_bundle_members'],original_build_attestation_verified=True,
        publication_authorized=False),'original binary/SBOM support differs')


def materialize(native: Path, update: Path, support: Path, output: Path) -> None:
    require(not output.exists() and not output.is_symlink(), 'prepared layout exists')
    output.mkdir(mode=0o700)
    payloads = {}
    for row in current.verify_package_inputs(native):
        if row['path'].startswith('packages/') and not row['path'].endswith('.asc'):
            payloads[Path(row['path']).name] = frozen.read_anchored(native,row,MAX_ARCHIVE)
    producer.copy_files(payloads,output/'packages/candidate')
    frozen.bundle.write_exclusive(output/'packages/candidate/SHA256SUMS.txt',
                                   frozen.bundle.canonical_manifest(payloads))
    producer.copy_files(producer.file_snapshot(native),output/'native-signing')
    producer.copy_files({Path(name).name:(update/name).read_bytes()
                       for name in (updater.original.MANIFEST,updater.original.SIGNATURE)},output/'update')
    for row in current.load_plan()['product_release_support']:
        producer.copy_files({row['file']['path']: frozen.read_anchored(support,row['file'],MAX_ARCHIVE)},
                            output/row['name'])


def verify_assets(assets: Path, native: Path, update: Path, support: Path) -> None:
    for row in current.verify_package_inputs(native):
        equal(frozen.bundle.regular_bytes(assets/Path(row['path']).name,MAX_ARCHIVE,'release asset'),
              frozen.read_anchored(native,row,MAX_ARCHIVE),'publication substituted a tested package')
    for name in (updater.original.MANIFEST,updater.original.SIGNATURE):
        equal(frozen.bundle.regular_bytes(assets/Path(name).name,MAX_ARCHIVE,'release manifest'),
              (update/name).read_bytes(),'publication substituted the signed updater')
    for row in current.load_plan()['product_release_support']:
        equal(frozen.read_anchored(assets,row['file'],MAX_ARCHIVE),
              frozen.read_anchored(support,row['file'],MAX_ARCHIVE),'publication substituted original binary/SBOM')


def consume(repository: Path, publication: str, release: str, requested: int | None,
            work: Path, assets: Path | None = None) -> dict:
    contract = assurance.derive(repository,release,publication)
    equal(contract.assurance,'IVV','the intermediate consumer cannot replace an Upgrade gate')
    source = current.source_binding(repository,publication)
    run, artifact = select(repository,contract,requested)
    require(work.is_absolute() and work.parent == work.parent.resolve(strict=True) and not work.exists(),
            'independent consumer workspace must be new')
    work.mkdir(mode=0o700)
    archive_wire = download(repository,artifact,work/'artifact.zip')
    root=work/'evidence';files=unpack(archive_wire,root)
    attested = updater.original.command(['gh','attestation','verify',str(root/producer.REPORT),
        '--bundle',str(root/ATTESTATION),'--repo',REPOSITORY,
        '--signer-workflow',REPOSITORY+'/'+producer.WORKFLOW,'--signer-digest',publication,
        '--source-digest',publication,'--source-ref','refs/heads/main','--format','json'],repository)
    verify_attestation(attested,publication,run['id'],frozen.digest(files[producer.REPORT]))
    report=frozen.strict_json(files[producer.REPORT]);verify_report(report,files,source,run['id'])
    equal(producer.ci_verification(repository,publication),report['ci_verification'],'required CI changed')
    producer.verify_environment(producer.api(repository,'environments/'+producer.ENVIRONMENT),
        producer.api(repository,'environments/'+producer.ENVIRONMENT+'/deployment-branch-policies','-f','per_page=100'))
    native=root/'native-signing';update=root/'updater'
    current.verify_package_inputs(native)
    frozen.bundle.verify_bundle(native,release,current.PRODUCT)
    update_artifact=producer.api(repository,'actions/artifacts/'+str(updater.ARTIFACT))
    download(repository,update_artifact,work/'updater-original.zip')
    checked_update=updater.verify(repository,native,update,work/'updater-original.zip')
    # API/verification output hashes can change as GitHub updates metadata. Package and
    # cryptographic identities cannot, and were independently recomputed above.
    for key in ('descriptor_sha256','manifest_sha256','manifest_signature_sha256','packages'):
        equal(checked_update[key],report['updater_verification'][key],'updater identity changed')
    support=root/'product-support'
    equal(producer.support.verify(repository,support),report['product_support_verification'],
          'original binary/SBOM could not be independently verified')
    if assets is not None: verify_assets(assets,native,update,support)
    materialize(native,update,support,work/'verified')
    equal(producer.file_snapshot(root),files,'artifact changed during independent consumption')
    repeated_run,repeated_artifact=select(repository,contract,run['id'])
    equal(repeated_artifact,artifact,'original protected artifact metadata changed')
    equal(current.source_binding(repository,publication),source,'publication source changed')
    result=dict(schema='syswarden-independent-ivv-consumption/v1',status='protected-ivv-verified',
        required_assurance='IVV',release=release,publication_commit=publication,
        product_candidate=current.PRODUCT,producer_run_id=run['id'],artifact_id=artifact['id'],
        artifact_digest=artifact['digest'],report_sha256=frozen.digest(files[producer.REPORT]),
        plan_sha256=current.PLAN_SHA256,updater_independently_verified=True,
        tested_package_bytes_retained=True,release_assets_compared=assets is not None,
        full_qualification_passed=False,publication_authorized=False)
    frozen.write_new(work/'CONSUMPTION.json',result)
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,required=True)
    parser.add_argument('--publication-sha',required=True)
    parser.add_argument('--release',required=True)
    parser.add_argument('--producer-run-id',type=int)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--release-assets',type=Path)
    args=parser.parse_args()
    try:
        consume(args.repository,args.publication_sha,args.release,args.producer_run_id,args.work,args.release_assets)
    except (frozen.PlanError,frozen.bundle.SigningBundleError,OSError,KeyError,TypeError,ValueError,
            zipfile.BadZipFile,subprocess.SubprocessError) as exc:
        parser.exit(1,f'Independent protected IVV consumption rejected: {exc}\n')
    print('Protected intermediate IVV independently verified. Publication gates remain required.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
