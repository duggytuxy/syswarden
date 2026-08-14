#!/usr/bin/env python3
"""Validate the exact GitHub ruleset required to keep release tags immutable."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


RULESET_NAME = "syswarden-release-tags-immutable"
EXPECTED_INCLUDE = ["refs/tags/v*"]
EXPECTED_RULE_TYPES = frozenset({"update", "deletion"})
MAX_RULESET_BYTES = 1024 * 1024
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)

TOP_LEVEL_KEYS = frozenset(
    {
        "_links",
        "bypass_actors",
        "conditions",
        "created_at",
        "enforcement",
        "id",
        "name",
        "node_id",
        "rules",
        "source",
        "source_type",
        "target",
        "updated_at",
    }
)


class RulesetGateError(ValueError):
    """Raised when the external release-tag ruleset is not exact and safe."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RulesetGateError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RulesetGateError(f"non-finite JSON value is forbidden: {value}")


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RulesetGateError(f"{label} must be a JSON object")
    actual = frozenset(value)
    if actual != expected:
        raise RulesetGateError(
            f"{label} keys mismatch; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RulesetGateError(f"{label} must be a non-empty string")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RulesetGateError(f"{label} must be a positive integer")
    return value


def _validate_timestamp(value: Any, label: str) -> None:
    timestamp = _nonempty_string(value, label)
    if TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise RulesetGateError(f"{label} must be a UTC GitHub timestamp")


def parse_ruleset(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RulesetGateError(f"invalid ruleset JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise RulesetGateError("ruleset JSON root must be an object")
    return document


def read_ruleset(path: Path) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RulesetGateError(f"cannot inspect ruleset response {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise RulesetGateError("ruleset response must be a regular file, not a link or device")
    if before.st_size <= 0 or before.st_size > MAX_RULESET_BYTES:
        raise RulesetGateError(
            f"ruleset response size must be between 1 and {MAX_RULESET_BYTES} bytes"
        )
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise RulesetGateError(f"cannot read ruleset response {path}: {exc}") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_after != identity_before or len(payload) != before.st_size:
        raise RulesetGateError("ruleset response changed while it was being read")
    return parse_ruleset(payload)


def validate_ruleset(document: dict[str, Any], expected_id: int) -> None:
    ruleset = _exact_keys(document, TOP_LEVEL_KEYS, "ruleset")
    if _positive_integer(ruleset["id"], "ruleset.id") != expected_id:
        raise RulesetGateError("ruleset.id does not match the uniquely selected list entry")
    if ruleset["name"] != RULESET_NAME:
        raise RulesetGateError(f"ruleset.name must equal {RULESET_NAME!r}")
    if ruleset["target"] != "tag":
        raise RulesetGateError("ruleset.target must equal 'tag'")
    if ruleset["enforcement"] != "active":
        raise RulesetGateError("ruleset.enforcement must equal 'active'")
    if ruleset["bypass_actors"] != []:
        raise RulesetGateError("ruleset.bypass_actors must be an explicit empty array")

    _nonempty_string(ruleset["source_type"], "ruleset.source_type")
    _nonempty_string(ruleset["source"], "ruleset.source")
    _nonempty_string(ruleset["node_id"], "ruleset.node_id")
    _validate_timestamp(ruleset["created_at"], "ruleset.created_at")
    _validate_timestamp(ruleset["updated_at"], "ruleset.updated_at")

    conditions = _exact_keys(
        ruleset["conditions"], frozenset({"ref_name"}), "ruleset.conditions"
    )
    ref_name = _exact_keys(
        conditions["ref_name"],
        frozenset({"exclude", "include"}),
        "ruleset.conditions.ref_name",
    )
    if ref_name["include"] != EXPECTED_INCLUDE:
        raise RulesetGateError(
            f"ruleset.conditions.ref_name.include must equal {EXPECTED_INCLUDE!r}"
        )
    if ref_name["exclude"] != []:
        raise RulesetGateError(
            "ruleset.conditions.ref_name.exclude must be an explicit empty array"
        )

    rules = ruleset["rules"]
    if not isinstance(rules, list):
        raise RulesetGateError("ruleset.rules must be an array")
    seen: set[str] = set()
    for index, rule_value in enumerate(rules):
        rule = _exact_keys(
            rule_value, frozenset({"type"}), f"ruleset.rules[{index}]"
        )
        rule_type = _nonempty_string(rule["type"], f"ruleset.rules[{index}].type")
        if rule_type not in EXPECTED_RULE_TYPES:
            raise RulesetGateError(f"unknown release-tag rule type: {rule_type!r}")
        if rule_type in seen:
            raise RulesetGateError(f"duplicate release-tag rule type: {rule_type!r}")
        seen.add(rule_type)
    if seen != EXPECTED_RULE_TYPES:
        raise RulesetGateError(
            f"ruleset.rules must contain exactly {sorted(EXPECTED_RULE_TYPES)}"
        )

    links = _exact_keys(
        ruleset["_links"], frozenset({"html", "self"}), "ruleset._links"
    )
    for link_name in ("self", "html"):
        link = _exact_keys(
            links[link_name], frozenset({"href"}), f"ruleset._links.{link_name}"
        )
        href = _nonempty_string(link["href"], f"ruleset._links.{link_name}.href")
        if not href.startswith("https://"):
            raise RulesetGateError(
                f"ruleset._links.{link_name}.href must be an HTTPS URL"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ruleset", type=Path, required=True)
    parser.add_argument("--expected-id", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        expected_id = _positive_integer(args.expected_id, "--expected-id")
        validate_ruleset(read_ruleset(args.ruleset), expected_id)
    except RulesetGateError as exc:
        print(f"immutable release-tag ruleset invalid: {exc}", file=sys.stderr)
        return 2
    print(
        f"Validated active immutable release-tag ruleset {RULESET_NAME} "
        f"with ID {expected_id}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
