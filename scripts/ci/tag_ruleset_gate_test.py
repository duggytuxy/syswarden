#!/usr/bin/env python3
"""Adversarial tests for the immutable release-tag ruleset gate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import tag_ruleset_gate


class TagRulesetGateTests(unittest.TestCase):
    ruleset_id = 42

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def valid_document(self) -> dict[str, object]:
        return {
            "id": self.ruleset_id,
            "name": tag_ruleset_gate.RULESET_NAME,
            "target": "tag",
            "source_type": "Repository",
            "source": "syswarden/syswarden",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [{"type": "deletion"}, {"type": "update"}],
            "node_id": "RRS_lACkVXNlcgQB",
            "_links": {
                "self": {
                    "href": "https://api.github.com/repos/syswarden/syswarden/rulesets/42"
                },
                "html": {
                    "href": "https://github.com/syswarden/syswarden/rules/42"
                },
            },
            "created_at": "2026-08-14T10:20:30Z",
            "updated_at": "2026-08-14T10:20:30Z",
        }

    def validate(self, document: dict[str, object] | None = None) -> None:
        tag_ruleset_gate.validate_ruleset(
            document or self.valid_document(), self.ruleset_id
        )

    def write_document(self, document: dict[str, object] | None = None) -> Path:
        path = self.root / "ruleset.json"
        path.write_text(json.dumps(document or self.valid_document()), encoding="utf-8")
        return path

    def assert_invalid(self, document: dict[str, object]) -> None:
        with self.assertRaises(tag_ruleset_gate.RulesetGateError):
            self.validate(document)

    def test_accepts_only_the_exact_immutable_tag_contract(self) -> None:
        self.validate()
        reversed_rules = self.valid_document()
        reversed_rules["rules"] = list(reversed(reversed_rules["rules"]))
        self.validate(reversed_rules)

    def test_rejects_wrong_id_name_target_or_enforcement(self) -> None:
        mutations = {
            "id": 43,
            "name": "syswarden-release-tags-almost-immutable",
            "target": "branch",
            "enforcement": "evaluate",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                document = self.valid_document()
                document[key] = value
                self.assert_invalid(document)

    def test_rejects_missing_hidden_or_nonempty_bypass_actors(self) -> None:
        for bypass in (None, {}, [{"actor_type": "RepositoryRole"}]):
            with self.subTest(bypass=bypass):
                document = self.valid_document()
                if bypass is None:
                    del document["bypass_actors"]
                else:
                    document["bypass_actors"] = bypass
                self.assert_invalid(document)

    def test_rejects_broad_or_excluded_ref_conditions(self) -> None:
        mutations = (
            {"include": ["~ALL"], "exclude": []},
            {"include": ["refs/tags/v*", "refs/tags/test*"], "exclude": []},
            {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v4*"]},
            {"include": "refs/tags/v*", "exclude": []},
        )
        for ref_name in mutations:
            with self.subTest(ref_name=ref_name):
                document = self.valid_document()
                document["conditions"] = {"ref_name": ref_name}
                self.assert_invalid(document)

    def test_rejects_missing_duplicate_or_unknown_rules(self) -> None:
        mutations = (
            [{"type": "update"}],
            [{"type": "update"}, {"type": "update"}, {"type": "deletion"}],
            [{"type": "update"}, {"type": "deletion"}, {"type": "creation"}],
            [{"type": "update"}, {"type": "deletion"}, "invalid"],
        )
        for rules in mutations:
            with self.subTest(rules=rules):
                document = self.valid_document()
                document["rules"] = rules
                self.assert_invalid(document)

    def test_rejects_unknown_fields_at_every_contract_level(self) -> None:
        documents = []

        top = self.valid_document()
        top["current_user_can_bypass"] = False
        documents.append(top)

        conditions = self.valid_document()
        conditions["conditions"]["repository_name"] = {"include": [], "exclude": []}
        documents.append(conditions)

        ref_name = self.valid_document()
        ref_name["conditions"]["ref_name"]["protected"] = True
        documents.append(ref_name)

        rule = self.valid_document()
        rule["rules"][0]["parameters"] = {}
        documents.append(rule)

        links = self.valid_document()
        links["_links"]["self"]["templated"] = False
        documents.append(links)

        for index, document in enumerate(documents):
            with self.subTest(index=index):
                self.assert_invalid(document)

    def test_rejects_wrong_metadata_types_and_non_https_links(self) -> None:
        mutations = {
            "id": True,
            "source_type": [],
            "source": "",
            "node_id": None,
            "created_at": "2026-08-14T10:20:30+00:00",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                document = self.valid_document()
                document[key] = value
                self.assert_invalid(document)
        document = self.valid_document()
        document["_links"]["self"]["href"] = "http://api.github.com/rulesets/42"
        self.assert_invalid(document)

    def test_strict_parser_rejects_duplicate_keys_and_nonfinite_values(self) -> None:
        payloads = (
            b'{"id": 42, "id": 43}',
            b'{"conditions": {"ref_name": {"include": [], "include": []}}}',
            b'{"id": NaN}',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(tag_ruleset_gate.RulesetGateError):
                    tag_ruleset_gate.parse_ruleset(payload)

    def test_rejects_non_object_root_missing_and_unknown_top_level_keys(self) -> None:
        with self.assertRaises(tag_ruleset_gate.RulesetGateError):
            tag_ruleset_gate.parse_ruleset(b"[]")
        missing = self.valid_document()
        del missing["updated_at"]
        self.assert_invalid(missing)

    def test_file_reader_rejects_symlink_empty_and_oversized_input(self) -> None:
        target = self.write_document()
        link = self.root / "ruleset-link.json"
        link.symlink_to(target)
        with self.assertRaises(tag_ruleset_gate.RulesetGateError):
            tag_ruleset_gate.read_ruleset(link)

        empty = self.root / "empty.json"
        empty.write_bytes(b"")
        with self.assertRaises(tag_ruleset_gate.RulesetGateError):
            tag_ruleset_gate.read_ruleset(empty)

        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * (tag_ruleset_gate.MAX_RULESET_BYTES + 1))
        with self.assertRaises(tag_ruleset_gate.RulesetGateError):
            tag_ruleset_gate.read_ruleset(oversized)

    def test_cli_fails_closed_and_reports_success(self) -> None:
        path = self.write_document()
        self.assertEqual(
            tag_ruleset_gate.main(
                ["--ruleset", str(path), "--expected-id", str(self.ruleset_id)]
            ),
            0,
        )
        invalid = copy.deepcopy(self.valid_document())
        invalid["enforcement"] = "disabled"
        path.write_text(json.dumps(invalid), encoding="utf-8")
        self.assertEqual(
            tag_ruleset_gate.main(
                ["--ruleset", str(path), "--expected-id", str(self.ruleset_id)]
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
