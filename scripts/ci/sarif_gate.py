#!/usr/bin/env python3
"""Normalize and validate SysWarden gosec SARIF paths and fingerprints."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from collections import Counter
from typing import Any


class SarifError(ValueError):
    """Raised when a SARIF report violates the repository contract."""


SOURCE_LINE = re.compile(r"^\s*(\d+):\s?(.*)$")
CONFIDENCE = re.compile(r"(?m)^Confidence:\s+(HIGH|MEDIUM|LOW)\s*$")


def json_issue_snippet(issue: dict[str, Any]) -> str:
    code = str(issue.get("code", "")).replace("\r\n", "\n")
    target_line = str(issue.get("line", ""))
    for raw_line in code.splitlines():
        match = SOURCE_LINE.fullmatch(raw_line)
        if match is not None and match.group(1) == target_line:
            snippet = match.group(2).strip()
            if snippet:
                return snippet
    raise SarifError(
        f"gosec JSON code has no source snippet for line {target_line!r}"
    )


def sarif_rule_metadata(
    run: dict[str, Any], *, allow_missing_for_empty_results: bool = False
) -> dict[str, tuple[str, str, str]]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict) or driver.get("name") != "gosec":
        raise SarifError("SARIF tool driver must be gosec")
    rules = driver.get("rules") if isinstance(driver, dict) else None
    if rules is None and allow_missing_for_empty_results:
        return {}
    if not isinstance(rules, list):
        raise SarifError("gosec SARIF run has no tool rule metadata")
    metadata: dict[str, tuple[str, str, str]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise SarifError("gosec SARIF rule metadata must be objects")
        rule_id = str(rule.get("id", ""))
        properties = rule.get("properties")
        tags = properties.get("tags") if isinstance(properties, dict) else None
        severity = ""
        if isinstance(tags, list):
            severity = next(
                (str(tag) for tag in tags if str(tag) in {"HIGH", "MEDIUM", "LOW"}),
                "",
            )
        help_block = rule.get("help")
        help_text = str(help_block.get("text", "")) if isinstance(help_block, dict) else ""
        confidence_match = CONFIDENCE.search(help_text)
        configuration = rule.get("defaultConfiguration")
        level = str(configuration.get("level", "")) if isinstance(configuration, dict) else ""
        if not rule_id or not severity or confidence_match is None or not level:
            raise SarifError(f"incomplete gosec SARIF rule metadata for {rule_id!r}")
        if rule_id in metadata:
            raise SarifError(f"duplicate gosec SARIF rule metadata for {rule_id}")
        metadata[rule_id] = (severity, confidence_match.group(1), level)
    return metadata


def json_issue_key(
    issue: dict[str, Any], module: str, repository: Path
) -> tuple[str, str, str, str, str, str, str, str]:
    raw_path = Path(str(issue.get("file", "")))
    if raw_path.is_absolute():
        try:
            path = raw_path.resolve().relative_to(repository.resolve()).as_posix()
        except ValueError as exc:
            raise SarifError(f"gosec JSON path escapes repository: {raw_path}") from exc
    else:
        path = (Path(module) / raw_path).as_posix()
    return (
        str(issue.get("rule_id", "")),
        path,
        str(issue.get("details", "")),
        str(issue.get("line", "")),
        str(issue.get("column", "")),
        str(issue.get("severity", "")),
        str(issue.get("confidence", "")),
        json_issue_snippet(issue),
    )


def normalize(
    report: dict[str, Any], json_report: dict[str, Any], module: str, repository: Path
) -> dict[str, Any]:
    if report.get("version") != "2.1.0":
        raise SarifError("gosec SARIF version must be 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise SarifError("gosec SARIF must contain exactly one run")
    results = runs[0].get("results")
    if not isinstance(results, list):
        raise SarifError("gosec SARIF run must contain a results array")
    if "Issues" not in json_report or not isinstance(json_report["Issues"], list):
        raise SarifError("gosec JSON report Issues must be a present array")
    issues = json_report["Issues"]
    rule_metadata = sarif_rule_metadata(
        runs[0], allow_missing_for_empty_results=not results and not issues
    )
    module_path = Path(module).as_posix().strip("/")
    if not module_path or not (repository / module_path).is_dir():
        raise SarifError(f"invalid gosec module path: {module!r}")
    sarif_inventory: Counter[tuple[str, str, str, str, str, str, str, str]] = Counter()
    fingerprint_candidates: list[
        tuple[dict[str, Any], tuple[str, ...], int, int]
    ] = []
    normalized_results: list[dict[str, Any]] = []
    exact_results: set[tuple[str, str, str, str, str, str, str, str]] = set()
    for result in results:
        rule_id = str(result.get("ruleId", ""))
        locations = result.get("locations")
        if not rule_id or not isinstance(locations, list) or len(locations) != 1:
            raise SarifError("each gosec result must contain exactly one ruleId and location")
        metadata = rule_metadata.get(rule_id)
        if metadata is None:
            raise SarifError(f"gosec SARIF result has no rule metadata: {rule_id}")
        severity, confidence, expected_level = metadata
        if str(result.get("level", "")) != expected_level:
            raise SarifError(f"gosec SARIF result level disagrees with rule {rule_id}")
        fingerprint_parts: list[str] = [rule_id]
        for location in locations:
            physical = location.get("physicalLocation")
            if not isinstance(physical, dict):
                raise SarifError("gosec result has no physicalLocation")
            artifact = physical.get("artifactLocation")
            if not isinstance(artifact, dict):
                raise SarifError("gosec result has no artifactLocation")
            raw_uri = str(artifact.get("uri", ""))
            candidate = Path(raw_uri)
            if not raw_uri or candidate.is_absolute() or ".." in candidate.parts:
                raise SarifError(f"unsafe gosec SARIF URI: {raw_uri!r}")
            normalized_uri = (Path(module_path) / candidate).as_posix()
            source_path = (repository / normalized_uri).resolve()
            try:
                source_path.relative_to(repository.resolve())
            except ValueError as exc:
                raise SarifError(f"gosec URI escapes repository: {raw_uri!r}") from exc
            if not source_path.is_file():
                raise SarifError(f"gosec SARIF source does not exist: {normalized_uri}")
            artifact["uri"] = normalized_uri
            artifact.pop("uriBaseId", None)
            region = physical.get("region") or {}
            snippet = str(region.get("snippet", {}).get("text", ""))
            if not snippet:
                raise SarifError("gosec SARIF location has no source snippet")
            try:
                source = source_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise SarifError(
                    f"gosec SARIF source is not valid UTF-8: {normalized_uri}"
                ) from exc
            if snippet not in source:
                raise SarifError(
                    f"gosec SARIF snippet does not occur in source: {normalized_uri}"
                )
            fingerprint_parts.extend(
                [
                    normalized_uri,
                    str(result.get("message", {}).get("text", "")),
                    snippet,
                ]
            )
            result_identity = (
                rule_id,
                normalized_uri,
                str(result.get("message", {}).get("text", "")),
                str(region.get("startLine", "")),
                str(region.get("startColumn", "")),
                severity,
                confidence,
                snippet,
            )
            if result_identity in exact_results:
                break
            exact_results.add(result_identity)
            sarif_inventory[
                (
                    rule_id,
                    normalized_uri,
                    str(result.get("message", {}).get("text", "")),
                    str(region.get("startLine", "")),
                    str(region.get("startColumn", "")),
                    severity,
                    confidence,
                    snippet,
                )
            ] += 1
        else:
            try:
                start_line = int(region.get("startLine", 0))
                start_column = int(region.get("startColumn", 0))
            except (TypeError, ValueError) as exc:
                raise SarifError("gosec SARIF location has invalid coordinates") from exc
            if start_line <= 0 or start_column <= 0:
                raise SarifError("gosec SARIF location must have positive coordinates")
            fingerprint_candidates.append(
                (result, tuple(fingerprint_parts), start_line, start_column)
            )
    groups: dict[tuple[str, ...], list[tuple[dict[str, Any], int, int]]] = {}
    for result, key, line, column in fingerprint_candidates:
        groups.setdefault(key, []).append((result, line, column))
    for key in sorted(groups):
        ordered = sorted(groups[key], key=lambda item: (item[1], item[2]))
        for ordinal, (result, _, _) in enumerate(ordered):
            digest = hashlib.sha256(
                "\0".join((*key, str(ordinal))).encode()
            ).hexdigest()
            fingerprints = result.setdefault("partialFingerprints", {})
            if not isinstance(fingerprints, dict):
                raise SarifError("partialFingerprints must be an object")
            fingerprints["syswarden/v1"] = digest
            normalized_results.append(result)
    runs[0]["results"] = normalized_results
    json_inventory = Counter(
        set(json_issue_key(issue, module_path, repository) for issue in issues)
    )
    if sarif_inventory != json_inventory:
        raise SarifError(
            "gosec SARIF inventory does not match the validated JSON report: "
            f"sarif={sum(sarif_inventory.values())}, json={sum(json_inventory.values())}"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--json-report", type=Path, required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        json_report = json.loads(args.json_report.read_text(encoding="utf-8"))
        if not isinstance(report, dict) or not isinstance(json_report, dict):
            raise SarifError("SARIF and gosec JSON reports must be JSON objects")
        normalized = normalize(
            report, json_report, args.module, args.repository.resolve()
        )
        args.report.write_text(
            json.dumps(normalized, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, SarifError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
