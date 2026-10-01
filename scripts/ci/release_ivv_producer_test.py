"""Protected producer provenance, environment and non-transfer regressions."""
import copy
import unittest
from scripts.ci import release_ivv_producer as producer


class ProtectedProducerTests(unittest.TestCase):
    def context(self):
        sha='a'*40
        return sha, dict(GITHUB_REPOSITORY='duggytuxy/syswarden',GITHUB_REPOSITORY_ID='1153695079',
            GITHUB_REPOSITORY_OWNER='duggytuxy',GITHUB_REPOSITORY_OWNER_ID='61513268',
            GITHUB_ACTOR='duggytuxy',GITHUB_TRIGGERING_ACTOR='duggytuxy',
            GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/main',
            GITHUB_SHA=sha,GITHUB_WORKFLOW_SHA=sha,GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='123',
            GITHUB_WORKFLOW_REF='duggytuxy/syswarden/.github/workflows/release-ivv.yml@refs/heads/main',
            RUNNER_ENVIRONMENT='self-hosted',RUNNER_OS='Linux',RUNNER_ARCH='X64')

    def test_exact_owner_context(self):
        sha,env=self.context()
        self.assertEqual(producer.verify_context(env,sha)['workflow_run_id'],123)
        for key,value in [('GITHUB_SHA','b'*40),('GITHUB_WORKFLOW_SHA','b'*40),
            ('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_ID','0123'),('GITHUB_ACTOR','other'),
            ('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/tags/v4.10.0'),
            ('RUNNER_ENVIRONMENT','github-hosted'),('GITHUB_REPOSITORY_ID','12')]:
            with self.subTest(key=key),self.assertRaises(producer.frozen.PlanError):
                producer.verify_context(dict(env,**{key:value}),sha)

    def test_exact_environment_rejects_bypass_or_extra_access(self):
        env=dict(name=producer.ENVIRONMENT,can_admins_bypass=False,
            deployment_branch_policy=dict(protected_branches=False,custom_branch_policies=True),
            protection_rules=[dict(type='branch_policy'),dict(type='required_reviewers',
                prevent_self_review=False,reviewers=[dict(type='User',reviewer=dict(login='duggytuxy',id=61513268))])])
        branches=dict(total_count=1,branch_policies=[dict(name='main',type='branch')])
        producer.verify_environment(env,branches)
        mutations=[lambda x:x.update(can_admins_bypass=True),
            lambda x:x['protection_rules'][1]['reviewers'][0]['reviewer'].update(id=1),
            lambda x:x['protection_rules'][1]['reviewers'].append(dict(type='Team')),
            lambda x:x['protection_rules'].append(dict(type='wait_timer'))]
        for mutate in mutations:
            bad=copy.deepcopy(env);mutate(bad)
            with self.assertRaises(producer.frozen.PlanError): producer.verify_environment(bad,branches)
        for change in [dict(total_count=True),dict(total_count=2),
                       dict(branch_policies=[dict(name='*',type='branch')]),
                       dict(branch_policies=[dict(name='main',type='tag')])]:
            with self.assertRaises(producer.frozen.PlanError):
                producer.verify_environment(env,dict(branches,**change))

    def test_ci_fork_retry_boolean_and_failure_rejected(self):
        row=dict(id=123,head_sha='a'*40,path='.github/workflows/package.yml',event='push',
            head_branch='main',status='completed',conclusion='success',run_attempt=1,
            repository=dict(id=1153695079,full_name='duggytuxy/syswarden'),
            head_repository=dict(id=1153695079,full_name='duggytuxy/syswarden'))
        producer.check_run(row,'a'*40,'.github/workflows/package.yml')
        for change in [dict(id=True),dict(run_attempt=True),dict(run_attempt=2),dict(conclusion='failure'),
            dict(event='pull_request'),dict(head_repository=dict(id=1,full_name='duggytuxy/syswarden'))]:
            with self.assertRaises(producer.frozen.PlanError):
                producer.check_run(dict(row,**change),'a'*40,'.github/workflows/package.yml')


if __name__=='__main__': unittest.main()
