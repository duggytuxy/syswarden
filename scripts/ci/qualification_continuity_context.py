#!/usr/bin/env python3
"""Keep the exact PR257 runtime separate from its reviewed qualification tooling.

Call only from a protected workflow, using GitHub-provided event context. This
validates identities and the tooling-only Git diff, not environment protection,
OIDC attestations, native results or final release acceptance.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Mapping
try:
    from scripts.ci import qualification_continuity as continuity
except ModuleNotFoundError:
    import qualification_continuity as continuity

SCHEMA = 'syswarden-pr257-tooling-context/v1'
REPOSITORY = 'duggytuxy/syswarden'
WORKFLOWS = frozenset({'.github/workflows/native-release-evidence.yml',
                       '.github/workflows/release-qualification.yml', '.github/workflows/release-manager.yml',
                       '.github/workflows/qualification-continuity.yml'})
MODULES = ('qualification_continuity', 'qualification_continuity_capabilities',
           'qualification_continuity_lifecycle', 'qualification_continuity_metrics',
           'qualification_continuity_performance', 'qualification_continuity_performance_receipts',
           'qualification_continuity_context', 'qualification_continuity_inputs')
ALLOWED_PATHS = WORKFLOWS | frozenset('scripts/ci/' + name + suffix for name in MODULES
                                      for suffix in ('.py', '_test.py')) | frozenset({
    'scripts/ci/qualification_continuity_policy_pr257.json', 'scripts/ci/native_capability_evidence.py',
    'docs/maintainers/LOCAL_RELEASE_PREFLIGHT.md'})
CAPABILITY_REFACTOR_SHA256 = '589eef1bb83ad33a5224d39c96e217df4af7fef4bd3b12505d96408667c97109'


def verify_context(*, repository: Path, runtime_sha: str, tooling_sha: str,
                   workflow: str, event: Mapping[str, str]) -> dict[str, Any]:
    require = continuity.require
    require(runtime_sha == continuity.RUNTIME, 'tooling separation is limited to exact PR257 runtime')
    require(isinstance(tooling_sha, str) and re.fullmatch('[0-9a-f]{40}', tooling_sha) is not None
            and tooling_sha != runtime_sha, 'a distinct full tooling commit is mandatory')
    require(workflow in WORKFLOWS, 'unreviewed qualification workflow')
    expected = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_OWNER': 'duggytuxy',
                'GITHUB_ACTOR': 'duggytuxy', 'GITHUB_TRIGGERING_ACTOR': 'duggytuxy',
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                'GITHUB_SHA': tooling_sha, 'GITHUB_WORKFLOW_SHA': tooling_sha, 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_WORKFLOW_REF': REPOSITORY + '/' + workflow + '@refs/heads/main'}
    require(all(event.get(key) == value for key, value in expected.items()), 'protected tooling event identity differs')
    run_id = event.get('GITHUB_RUN_ID', '')
    require(isinstance(run_id, str) and re.fullmatch('[1-9][0-9]*', run_id) is not None, 'invalid workflow run id')
    git = lambda *args: continuity.git(repository, *args)
    policy = continuity.load_policy()
    continuity.verify_source(repository, policy, runtime_sha)
    require(git('rev-parse', 'HEAD') == tooling_sha, 'checkout does not match executing tooling commit')
    require(git('status', '--porcelain=v1', '--untracked-files=normal') == '', 'qualification tooling checkout is dirty')
    require(git('merge-base', runtime_sha, tooling_sha) == runtime_sha, 'tooling is not a descendant of the frozen runtime')
    changes = git('diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-status', runtime_sha, tooling_sha)
    paths = []
    for line in changes.splitlines():
        fields = line.split('\t')
        require(len(fields) == 2 and fields[0] in ('A', 'M') and fields[1] in ALLOWED_PATHS,
                'tooling revision changes unreviewed files or deletes prior files')
        require(fields[1] not in paths, 'duplicate tooling diff path')
        paths.append(fields[1])
    require(paths and workflow in paths and 'scripts/ci/qualification_continuity_context.py' in paths,
            'tooling revision does not contain its context guard and executing workflow')
    # The policy's identity remains the owner-reviewed policy even after tooling changes.
    # Read blobs through git cat-file in bytes; git() strips text and is unsuitable for hashes.
    import subprocess
    def blob_sha(path: str) -> str:
        try:
            result = subprocess.run(['git', '-c', 'core.fsmonitor=false', '--no-replace-objects',
                'cat-file', 'blob', tooling_sha + ':' + path], cwd=repository, capture_output=True,
                timeout=30, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise continuity.ContinuityError('cannot verify frozen tooling blob') from exc
        return continuity.digest(result.stdout)
    require(blob_sha('scripts/ci/qualification_continuity_policy_pr257.json') == continuity.POLICY_SHA256,
            'tooling revision changed the owner-reviewed continuity policy')
    require(blob_sha('scripts/ci/native_capability_evidence.py') == CAPABILITY_REFACTOR_SHA256,
            'capability validator differs from the reviewed behavior-preserving extraction')
    return {'schema': SCHEMA, 'repository': REPOSITORY, 'release': 'v4.10.0',
            'runtime_candidate': runtime_sha, 'tooling_commit': tooling_sha,
            'tooling_tree': git('rev-parse', tooling_sha + '^{tree}'), 'workflow': workflow,
            'workflow_run_id': int(run_id), 'workflow_run_attempt': 1, 'workflow_ref': expected['GITHUB_WORKFLOW_REF'],
            'continuity_policy_sha256': continuity.POLICY_SHA256, 'tooling_changed_paths': sorted(paths),
            'runtime_diff_revalidated': True, 'runtime_artifacts_require_runtime_sha': True,
            'tooling_attestations_require_tooling_sha': True, 'environment_protection_validation_required': True,
            'oidc_provenance_validation_required': True, 'release_qualified': False}
