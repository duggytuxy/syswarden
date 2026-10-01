"""Original product bundle provenance must not follow a later publication build."""
import copy
import json
import unittest
from scripts.ci import release_ivv_support as support


class ProductSupportTests(unittest.TestCase):
    def result(self):
        row=support.current.load_plan()['product_release_support'][0]['file']
        workflow=support.WORKFLOW;repo=support.REPO
        statement=dict(_type='https://in-toto.io/Statement/v1',
            subject=[dict(name=row['path'],digest=dict(sha256=row['sha256']))],
            predicateType='https://slsa.dev/provenance/v1',predicate=dict(buildDefinition=dict(
                buildType='https://actions.github.io/buildtypes/workflow/v1',
                externalParameters=dict(workflow=dict(path=workflow,ref='refs/heads/main',repository='https://github.com/'+repo)),
                internalParameters=dict(github=dict(event_name='push',repository_id='1153695079',
                    repository_owner_id='61513268',runner_environment='github-hosted')),
                resolvedDependencies=[dict(uri=f'git+https://github.com/{repo}@refs/heads/main',
                    digest=dict(gitCommit=support.current.PRODUCT))]),runDetails=dict(
                    builder=dict(id=f'https://github.com/{repo}/{workflow}@refs/heads/main'),
                    metadata=dict(invocationId=f'https://github.com/{repo}/actions/runs/{support.RUN}/attempts/1'))))
        return dict(statement=statement,signature=dict(certificate=dict(issuer='https://token.actions.githubusercontent.com',
            subjectAlternativeName=f'https://github.com/{repo}/{workflow}@refs/heads/main')))

    def test_exact_product_provenance_and_rejections(self):
        def check(result):
            support.verify_statement(json.dumps([dict(verificationResult=result)]).encode())
        check(self.result())
        mutations=[lambda r:r['signature']['certificate'].update(issuer='https://github.com/login/oauth'),
            lambda r:r['signature']['certificate'].update(subjectAlternativeName='https://github.com/other/repo/workflow'),
            lambda r:r['statement']['subject'][0]['digest'].update(sha256='f'*64),
            lambda r:r['statement']['predicate']['buildDefinition']['resolvedDependencies'][0]['digest'].update(gitCommit='f'*40),
            lambda r:r['statement']['predicate']['buildDefinition']['internalParameters']['github'].update(runner_environment='self-hosted'),
            lambda r:r['statement']['predicate']['runDetails']['metadata'].update(invocationId=f'https://github.com/{support.REPO}/actions/runs/{support.RUN}/attempts/2')]
        for mutate in mutations:
            result=copy.deepcopy(self.result());mutate(result)
            with self.assertRaises(support.frozen.PlanError):check(result)


if __name__=='__main__':unittest.main()
