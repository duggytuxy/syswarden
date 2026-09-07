#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".gitlab-ci.yml"

PLUMBER_VERSION = "0.4.55"
PLUMBER_COMPONENT_COMMIT = "37b44609c34b3094dad6cf0dedf218e77a8fbc70"
PLUMBER_IMAGE_DIGEST = "28d08dda9b93e1163080e95c679b82b2181f4e910a1269124edd85d1cd058e93"


class GitLabPlumberWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_pipeline_is_gitlab_only_and_closed_by_default(self) -> None:
        self.assertIn("if: '$GITLAB_CI != \"true\"'", self.workflow)
        self.assertRegex(
            self.workflow,
            r"if: '\$GITLAB_CI != \"true\"'\n\s+when: never",
        )
        self.assertIn("    - when: never", self.workflow)

    def test_external_inputs_are_immutable_and_use_internal_mirrors(self) -> None:
        component = (
            "$CI_SERVER_FQDN/infrastructure/ci-components/plumber/plumber@"
            + PLUMBER_COMPONENT_COMMIT
        )
        image = (
            "$CI_REGISTRY_IMAGE/plumber@sha256:"
            + PLUMBER_IMAGE_DIGEST
        )
        self.assertIn(component, self.workflow)
        self.assertIn(image, self.workflow)
        self.assertIn(f"Plumber v{PLUMBER_VERSION}", self.workflow)
        self.assertNotRegex(
            self.workflow,
            r"(?:component:|image:)\s+https?://",
        )

    def test_untrusted_fork_merge_requests_do_not_execute(self) -> None:
        self.assertRegex(
            self.workflow,
            re.compile(
                r"if: '\$CI_PIPELINE_SOURCE == \"merge_request_event\" "
                r"&& \$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == \$CI_PROJECT_ID'"
                r"[\s\S]+?if: '\$CI_PIPELINE_SOURCE == \"merge_request_event\"'"
                r"\n\s+when: never"
            ),
        )

    def test_compliance_gate_cannot_publish_or_soft_fail(self) -> None:
        required = {
            '      min_points: "100"',
            "      score_push: false",
            "      mr_comment: false",
            "      badge: false",
            "      fail_warnings: true",
            "      allow_failure: false",
        }
        for setting in required:
            with self.subTest(setting=setting):
                self.assertIn(setting, self.workflow)


if __name__ == "__main__":
    unittest.main()
