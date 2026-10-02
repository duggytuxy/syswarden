#!/usr/bin/env python3
"""Select and bind the required release producer, never grant acceptance.

All publisher boundaries must derive this contract from Git classification.
A successful metadata check is a provenance prerequisite, not an IVV/IVVQ pass.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys

try:
    from scripts.ci import release_ivv_plan as ivv
    from scripts.ci import release_ivv_current as current
    from scripts.ci import release_ivv_profile as profiles
except ModuleNotFoundError:
    import release_ivv_plan as ivv
    import release_ivv_current as current
    import release_ivv_profile as profiles

REPOSITORY = 'duggytuxy/syswarden'
REPOSITORY_ID = 1153695079
OWNER_ID = 61513268
PRODUCT_V4100 = '8c3405758a9b369924f466d12652e99d3a84dc56'
VERSION = re.compile(r'v(?:0|[1-9][0-9]*)\.[0-9]{2}\.(?:0|[1-9][0-9]*)')
TRACK_KEYS = frozenset({'schema', 'candidate_commit', 'release', 'previous_version',
    'transition_commit', 'transition_parent', 'prefix', 'track', 'followup_commits',
    'qualification_passed', 'publication_authorized'})


def require(condition: bool, message: str) -> None:
    ivv.require(condition, message)


def equal(actual, expected, message: str) -> None:
    require(ivv.bundle.exact_json_equal(actual, expected), message)


def sha(value) -> bool:
    return type(value) is str and ivv.SHA.fullmatch(value) is not None


@dataclass(frozen=True)
class AssuranceContract:
    track: str
    assurance: str
    release: str
    publication_commit: str
    product_candidate: str
    workflow_path: str
    artifact_name: str

    def as_dict(self) -> dict:
        return dict(schema='syswarden-release-assurance-contract/v1',
            track=self.track, assurance=self.assurance, release=self.release,
            publication_commit=self.publication_commit, product_candidate=self.product_candidate,
            workflow_path=self.workflow_path, artifact_name=self.artifact_name,
            qualification_passed=False, intermediate_release_validated=False,
            publication_authorized=False)


def from_classification(document: dict, release: str, publication: str) -> AssuranceContract:
    """Validate classification structure; caller must also prove its Git origin."""
    require(type(document) is dict and set(document) == TRACK_KEYS, 'unexpected classification fields')
    require(type(release) is str and VERSION.fullmatch(release) is not None and sha(publication),
            'exact release and publication commit required')
    require(document['schema'] == 'syswarden-release-track/v1' and
            document['candidate_commit'] == publication and document['release'] == release,
            'classification identity differs')
    require(type(document['previous_version']) is str and
            VERSION.fullmatch(document['previous_version']) is not None and
            sha(document['transition_commit']) and sha(document['transition_parent']),
            'invalid original transition')
    require(type(document['followup_commits']) is int and document['followup_commits'] >= 0,
            'invalid follow-up count')
    require(document['qualification_passed'] is False and document['publication_authorized'] is False,
            'classification cannot grant acceptance')
    if document['prefix'] == 'Upgrade':
        require(document['track'] == 'full-qualification', 'Upgrade cannot select IVV')
        return AssuranceContract('full-qualification', 'IVVQ', release, publication, publication,
            '.github/workflows/release-qualification.yml', 'syswarden-release-qualification')
    require(document['prefix'] in ('Patch', 'Minor', 'Major') and
            document['track'] == 'intermediate-validation', 'invalid intermediate classification')
    # A future intermediate release needs its own reviewed product plan.
    # Do not silently borrow the frozen v4.10.0 product or evidence.
    profile = profiles.load(release)
    plan = profile.current.load_plan()
    ivv.verify_track(document, publication, plan)
    equal(plan['product_candidate'], profile.product, 'unreviewed frozen product')
    return AssuranceContract('intermediate-validation', 'IVV', release, publication, profile.product,
        profile.workflow, 'syswarden-release-ivv')


def derive(repository: Path, release: str, publication: str) -> AssuranceContract:
    require(repository.is_absolute() and repository == repository.resolve(strict=True),
            'repository must be canonical')
    require(sha(publication), 'full publication SHA required')
    require(ivv.git(repository, 'rev-parse', 'HEAD') == publication, 'wrong checkout')
    require(ivv.git(repository, 'rev-parse', '--is-shallow-repository') == 'false', 'full history required')
    require(not ivv.git(repository, 'for-each-ref', 'refs/replace'), 'Git replacement refs forbidden')
    grafts = Path(ivv.git(repository, 'rev-parse', '--git-path', 'info/grafts'))
    if not grafts.is_absolute():
        grafts = repository / grafts
    require(not grafts.exists(), 'Git grafts forbidden')
    require(not ivv.git(repository, 'status', '--porcelain', '--untracked-files=normal'),
            'clean publication checkout required')
    require(all(line.startswith('H ') for line in ivv.git(repository, 'ls-files', '-v').splitlines()),
            'hidden index changes forbidden')
    result = subprocess.run([str(repository / 'scripts/versioning.sh'), 'release-track',
        '--repo', str(repository), '--tag', release], cwd=repository,
        capture_output=True, timeout=180, check=True)
    require(len(result.stdout) < ivv.MAX_JSON, 'classification too large')
    contract = from_classification(ivv.strict_json(result.stdout), release, publication)
    require(ivv.git(repository, 'rev-parse', 'HEAD') == publication and
            not ivv.git(repository, 'status', '--porcelain', '--untracked-files=normal'),
            'publication changed during classification')
    return contract


def verify_run(run: dict, contract: AssuranceContract, run_id: int) -> None:
    require(type(run_id) is int and run_id > 0, 'invalid producer run ID')
    for key, value in dict(id=run_id, head_sha=contract.publication_commit, head_branch='main',
            event='workflow_dispatch', path=contract.workflow_path, run_attempt=1,
            status='completed', conclusion='success').items():
        equal(run[key], value, 'wrong required producer run: ' + key)
    for key in ('repository', 'head_repository'):
        equal(run[key]['id'], REPOSITORY_ID, 'producer belongs to a different repository')
        equal(run[key]['full_name'], REPOSITORY, 'producer repository name differs')
    for key in ('actor', 'triggering_actor'):
        equal(run[key]['id'], OWNER_ID, 'producer must be dispatched by the repository owner')
        equal(run[key]['login'], 'duggytuxy', 'unexpected producer owner')


def select_unique_run(runs: list, contract: AssuranceContract, requested: int | None = None) -> dict:
    require(type(runs) is list and len(runs) <= 10000 and all(type(row) is dict for row in runs), 'invalid workflow run inventory')
    scoped = [run for run in runs if run.get('head_sha') == contract.publication_commit
              and run.get('head_branch') == 'main' and run.get('event') == 'workflow_dispatch']
    require(all(run['status'] == 'completed' for run in scoped), 'a matching producer is still active')
    passed = [run for run in scoped if run.get('conclusion') == 'success']
    require(len(passed) == 1, 'exactly one successful required producer is mandatory')
    run = passed[0]
    verify_run(run, contract, run['id'])
    if requested is not None:
        require(type(requested) is int and requested > 0, 'invalid requested run ID')
        equal(run['id'], requested, 'requested run is not the unique protected producer')
    return run


def select_artifact(artifacts: list, contract: AssuranceContract, run_id: int) -> dict:
    require(type(run_id) is int and run_id > 0, 'invalid producer run ID')
    require(type(artifacts) is list and len(artifacts) <= 10000 and all(type(row) is dict for row in artifacts), 'invalid artifact inventory')
    matches = [row for row in artifacts if row.get('name') == contract.artifact_name]
    require(len(matches) == 1, 'exactly one required assurance artifact is mandatory')
    artifact = matches[0]
    require(type(artifact['id']) is int and artifact['id'] > 0, 'invalid artifact ID')
    require(artifact['expired'] is False and type(artifact['size_in_bytes']) is int and
            0 < artifact['size_in_bytes'] <= 128 * 1024 * 1024, 'artifact expired, empty or oversized')
    require(type(artifact['digest']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']),
            'artifact digest missing or malformed')
    for key, value in dict(id=run_id, repository_id=REPOSITORY_ID, head_repository_id=REPOSITORY_ID,
            head_branch='main', head_sha=contract.publication_commit).items():
        equal(artifact['workflow_run'][key], value, 'artifact producer binding differs: ' + key)
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--publication-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = derive(args.repository, args.release, args.publication_sha)
        ivv.write_new(args.output, contract.as_dict())
    except (ivv.PlanError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Required release producer rejected: {exc}\n')
    print('Required producer selected from Git; report, provenance and acceptance still required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
