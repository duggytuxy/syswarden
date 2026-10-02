#!/usr/bin/env python3
"""Protected IVV production from exact private observations and signed packages."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import stat
import zipfile

try:
    from scripts.ci import release_ivv_current as current
    from scripts.ci import current_candidate_update_verify as updater
    from scripts.ci import release_ivv_native_signatures as native_signatures
    from scripts.ci import release_ivv_support as support
    from scripts.ci import release_ivv_profile as profiles
except ModuleNotFoundError:
    import release_ivv_current as current
    import current_candidate_update_verify as updater
    import release_ivv_native_signatures as native_signatures
    import release_ivv_support as support
    import release_ivv_profile as profiles

frozen = current.frozen
require, equal = current.require, current.equal
REPOSITORY = 'duggytuxy/syswarden'
OWNER_ID = 61513268
REPOSITORY_ID = 1153695079
WORKFLOW = '.github/workflows/release-ivv.yml'
REPORT = 'RELEASE_IVV.json'
ENVIRONMENT = 'syswarden-release-qualification'
CI_WORKFLOWS = ('auto-versioning.yml', 'package.yml', 'security-audit.yml', 'compliance.yml', 'scorecard.yml')


def api(repository: Path, path: str, *args: str) -> dict:
    wire = updater.original.command(['gh', 'api', '--method', 'GET',
                                     'repos/' + REPOSITORY + '/' + path, *args], repository)
    return frozen.strict_json(wire)


def verify_context(event: dict, publication: str, workflow: str = WORKFLOW) -> dict:
    require(type(publication) is str and frozen.SHA.fullmatch(publication), 'exact publication commit required')
    expected = dict(GITHUB_REPOSITORY=REPOSITORY, GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
        GITHUB_REPOSITORY_OWNER='duggytuxy', GITHUB_REPOSITORY_OWNER_ID=str(OWNER_ID),
        GITHUB_ACTOR='duggytuxy', GITHUB_TRIGGERING_ACTOR='duggytuxy',
        GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/main',
        GITHUB_SHA=publication, GITHUB_WORKFLOW_SHA=publication, GITHUB_RUN_ATTEMPT='1',
        GITHUB_WORKFLOW_REF=REPOSITORY + '/' + workflow + '@refs/heads/main',
        RUNNER_ENVIRONMENT='self-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64')
    for key, value in expected.items(): equal(event.get(key), value, 'wrong protected producer context: ' + key)
    run = event.get('GITHUB_RUN_ID', '')
    require(type(run) is str and run.isdecimal() and int(run) > 0 and str(int(run)) == run,
            'invalid protected producer run')
    return dict(repository=REPOSITORY, repository_id=REPOSITORY_ID, workflow=workflow,
                workflow_ref=expected['GITHUB_WORKFLOW_REF'], publication_commit=publication,
                workflow_run_id=int(run), workflow_run_attempt=1, event='workflow_dispatch',
                source_ref='refs/heads/main', runner_environment='self-hosted',
                environment=ENVIRONMENT, owner_id=OWNER_ID)


def verify_environment(document: dict, branches: dict) -> None:
    equal(document['name'], ENVIRONMENT, 'wrong protected environment')
    require(document['can_admins_bypass'] is False, 'administrator bypass is forbidden')
    equal(document['deployment_branch_policy'],
          dict(protected_branches=False, custom_branch_policies=True), 'wrong environment branch policy')
    rules = document['protection_rules']
    require(type(rules) is list and len(rules) == 2, 'unexpected environment protection rules')
    reviewer = [r for r in rules if r['type'] == 'required_reviewers']
    require(len(reviewer) == 1 and len([r for r in rules if r['type'] == 'branch_policy']) == 1,
            'reviewer or branch protection missing')
    require(reviewer[0]['prevent_self_review'] is False, 'owner cannot approve this environment')
    entries = reviewer[0]['reviewers']
    require(type(entries) is list and len(entries) == 1, 'exactly the owner must be a required reviewer')
    equal(entries[0]['type'], 'User', 'reviewer is not an individual owner')
    equal(entries[0]['reviewer']['login'], 'duggytuxy', 'wrong environment reviewer')
    equal(entries[0]['reviewer']['id'], OWNER_ID, 'wrong reviewer ID')
    equal(branches['total_count'], 1, 'unexpected protected branch count')
    require(type(branches['branch_policies']) is list and len(branches['branch_policies']) == 1,
            'unexpected environment branch inventory')
    equal(branches['branch_policies'][0]['name'], 'main', 'protected producer requires main')
    equal(branches['branch_policies'][0]['type'], 'branch', 'tags cannot run the IVV producer')


def check_run(row: dict, sha: str, path: str, event='push', branch='main') -> dict:
    require(type(row['id']) is int and row['id'] > 0, 'invalid CI run ID')
    for key, value in dict(head_sha=sha, path=path, event=event, head_branch=branch,
                           status='completed', conclusion='success', run_attempt=1).items():
        equal(row[key], value, 'required CI run differs: ' + key)
    for field in ('repository', 'head_repository'):
        equal(row[field]['id'], REPOSITORY_ID, 'foreign CI repository')
        equal(row[field]['full_name'], REPOSITORY, 'foreign CI repository name')
    return {key:row[key] for key in ('id', 'head_sha', 'path', 'event', 'head_branch',
                                    'status', 'conclusion', 'run_attempt')}


def ci_verification(repository: Path, publication: str, current=current) -> dict:
    product = []
    for expected in current.load_plan()['product_ci']:
        row = api(repository, 'actions/runs/' + str(expected['run_id']))
        equal(row['id'], expected['run_id'], 'substituted product CI run')
        product.append(check_run(row, current.PRODUCT, expected['workflow']))
    publishing = []
    for workflow in CI_WORKFLOWS:
        response = api(repository, 'actions/workflows/' + workflow + '/runs', '-f', 'event=push',
                       '-f', 'branch=main', '-f', 'head_sha=' + publication, '-f', 'per_page=100')
        rows = response['workflow_runs']
        require(type(rows) is list and type(response['total_count']) is int and
                response['total_count'] == len(rows) and len(rows) == 1,
                'exactly one publication CI run is required: ' + workflow)
        publishing.append(check_run(rows[0], publication, '.github/workflows/' + workflow))
    return dict(product=product, publication=publishing)


def file_snapshot(root: Path) -> dict[str, bytes]:
    require(root.is_absolute() and root == root.resolve(strict=True), 'unsafe public bundle root')
    files = {}
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'symbolic link in public bundle')
        if path.is_dir(): continue
        name = path.relative_to(root).as_posix()
        frozen.relative(name)
        files[name] = frozen.bundle.regular_bytes(path, 128 * 1024 * 1024, 'public bundle input')
    require(files and len(files) < 1000, 'invalid public bundle inventory')
    return files


def check_native_archive(archive: Path, native: Path, current=current) -> None:
    require(archive.is_absolute() and archive == archive.resolve(strict=True), 'unsafe native archive')
    wire = frozen.bundle.regular_bytes(archive, 128 * 1024 * 1024, 'original native archive')
    equal('sha256:' + frozen.digest(wire), current.load_plan()['product_native_signing']['artifact_digest'],
          'original native signing artifact was substituted')
    files = file_snapshot(native)
    with zipfile.ZipFile(io.BytesIO(wire)) as packed:
        rows = packed.infolist()
        require(len(rows) == len(files) and {r.filename for r in rows} == set(files),
                'original native archive inventory differs')
        require(sum(r.file_size for r in rows) <= 128 * 1024 * 1024, 'native archive expands beyond bound')
        for row in rows:
            require(not row.is_dir() and not row.flag_bits & 1 and
                    stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG), 'unsafe native ZIP entry')
            equal(packed.read(row), files[row.filename], 'native file differs from original artifact')


def copy_files(files: dict[str, bytes], destination: Path) -> None:
    for name, wire in files.items():
        path = destination / frozen.relative(name)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        frozen.bundle.write_exclusive(path, wire)


def check_inventory(files: dict[str, bytes]) -> list[dict]:
    return [dict(path=name, size=len(wire), sha256=frozen.digest(wire))
            for name, wire in sorted(files.items())]


def acceptance_checks(input_result: dict, signatures: dict, update: dict,
                      current=current, updater=updater) -> list[dict]:
    """Admission is scoped IVV, never a replacement historical native verdict."""
    plan = current.load_plan()
    equal(input_result['product_candidate'], current.PRODUCT, 'input candidate differs')
    equal(input_result['plan_sha256'], current.PLAN_SHA256, 'input plan differs')
    equal(sorted(r['id'] for r in input_result['reviewed_observations']), plan['required_input_ids'],
          'required native observation absent')
    require(all(r['original_bytes_verified'] is True and r['admitted_as_current_native_pass'] is False
                for r in input_result['reviewed_observations']), 'historical verdict was transferred')
    require(signatures['four_native_signatures_verified'] is True and signatures['purpose'] == 'publishing'
            and signatures['product_candidate'] == current.PRODUCT, 'native signatures are not reverified')
    require(update['product_candidate'] == current.PRODUCT and update['producer_run_id'] == updater.RUN
            and update['status'] == 'current-candidate-manifest-cryptographically-verified'
            and update['historical_verdicts_transferred'] is False, 'new updater is not authenticated')
    observations = {r['id']: r for r in input_result['reviewed_observations']}
    equal(set(plan['acceptance_basis']), set(plan['required_acceptance_checks']),
          'acceptance traceability map is incomplete')
    rows = []
    for name in plan['required_acceptance_checks']:
        references = [observations[identifier] for identifier in plan['acceptance_basis'][name]]
        require(references or name == 'native-signatures', 'acceptance check has no evidence')
        rows.append(dict(id=name, status='pass', assurance='IVV', plan_sha256=current.PLAN_SHA256,
                         reviewed_inputs=references,
                         fresh_native_signature_check=name == 'native-signatures',
                         fresh_manifest_signature_check=name == 'offline-update'))
    return rows


def produce(repository: Path, publication: str, private: Path, native: Path,
            native_archive: Path, update_root: Path, update_archive: Path, work: Path,
            *, current=current, updater=updater, workflow: str = WORKFLOW) -> dict:
    context = verify_context(dict(os.environ), publication, workflow)
    source = current.source_binding(repository, publication)
    environment = api(repository, 'environments/' + ENVIRONMENT)
    branches = api(repository, 'environments/' + ENVIRONMENT + '/deployment-branch-policies', '-f', 'per_page=100')
    verify_environment(environment, branches)
    require(work.is_absolute() and work.parent == work.parent.resolve(strict=True) and not work.exists(),
            'producer workspace must be new')
    work.mkdir(mode=0o700)
    inputs = current.verify_private_inputs(private)
    ci = ci_verification(repository, publication, current)
    current.verify_package_inputs(native)
    check_native_archive(native_archive, native, current)
    signatures = native_signatures.verify(repository, native, work / 'native-verification', current)
    update = updater.verify(repository, native, update_root, update_archive)
    support_root, support_result = support.fetch(repository, work / 'product-support', current)
    checks = acceptance_checks(inputs, signatures, update, current, updater)
    public = work / 'public'; public.mkdir(mode=0o700)
    native_files = file_snapshot(native)
    copy_files(native_files, public / 'native-signing')
    snapshot = getattr(updater, 'snapshot', updater.original.snapshot)
    updater_files = snapshot(update_root)
    # These are public package/provenance files, never the private native captures.
    copy_files(updater_files, public / 'updater')
    copy_files(file_snapshot(support_root), public / 'product-support')
    inventory = check_inventory(file_snapshot(public))
    require(current.source_binding(repository, publication) == source, 'publication source changed')
    equal(current.verify_private_inputs(private), inputs, 'reviewed private inputs changed')
    equal(file_snapshot(native), native_files, 'native input changed after verification')
    equal(snapshot(update_root), updater_files, 'updater changed after verification')
    equal(ci_verification(repository, publication, current), ci, 'required CI changed during verification')
    verify_environment(api(repository, 'environments/' + ENVIRONMENT),
                       api(repository, 'environments/' + ENVIRONMENT + '/deployment-branch-policies', '-f', 'per_page=100'))
    report = dict(schema='syswarden-protected-intermediate-ivv/v1',
        status='ivv-accepted-for-release', release=current.load_plan()['release'], required_assurance='IVV',
        accepted_at=datetime.now(timezone.utc).isoformat(), context=context, source_binding=source,
        plan_sha256=current.PLAN_SHA256, input_verification=inputs,
        native_signature_verification=signatures, updater_verification=update,
        product_support_verification=support_result,
        ci_verification=ci, required_checks=checks, artifact_files=inventory,
        continuity_admitted_under_named_plan=True, historical_verdicts_transferred=False,
        private_raw_inputs_uploaded=False, claim_limits=current.load_plan()['claim_limits'],
        intermediate_release_validated=True, full_qualification_passed=False,
        publication_authorized=False, release_published=False,
        post_acceptance_requirements=current.load_plan()['post_acceptance_requirements'])
    frozen.write_new(public / REPORT, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'private-inputs', 'native-bundle', 'native-archive',
                 'candidate-bundle', 'candidate-archive', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-sha', required=True)
    parser.add_argument('--release', choices=tuple(profiles.REVIEWED), default='v4.10.0')
    args = parser.parse_args()
    try:
        profile = profiles.load(args.release)
        produce(args.repository, args.publication_sha, args.private_inputs, args.native_bundle,
                args.native_archive, args.candidate_bundle, args.candidate_archive, args.work,
                current=profile.current, updater=profile.updater, workflow=profile.workflow)
    except (frozen.PlanError, frozen.bundle.SigningBundleError, OSError, KeyError, TypeError,
            zipfile.BadZipFile) as exc:
        parser.exit(1, f'Protected intermediate acceptance rejected: {exc}\n')
    print('Protected intermediate IVV accepted. Independent publication and authenticity gates remain required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
