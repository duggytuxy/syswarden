#!/usr/bin/env python3
"""Fail closed when security scans are partial or exceed reviewed debt."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


QUALIFIED_NOSEC_BODY = re.compile(
    r"^\s*G\d{3}(?:[\s,]+G\d{3})*\s+--+\s+\S.*$", re.DOTALL
)
SOURCE_LINE_PREFIX = re.compile(r"^\s*\d+:\s?", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
GOSEC_MODULE_LINE = re.compile(
    r"^\s*mod\s+github\.com/securego/gosec/v2\s+(v[^\s]+)\s+", re.MULTILINE
)
GOSEC_FATAL_LOG = re.compile(
    r"(?i)(error building the ssa representation|package has type errors|failed to build package|panic:)"
)
GOSEC_CHECKING_FILE = re.compile(r"Checking file:\s+(.+?)\s*$", re.MULTILINE)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid JSON from {path}: {exc}") from exc


def relative_path(raw_path: str, repository: Path) -> str:
    candidate = Path(raw_path)
    try:
        return candidate.resolve().relative_to(repository.resolve()).as_posix()
    except (OSError, ValueError):
        normalized = candidate.as_posix()
        marker = "/src/"
        if marker in normalized:
            return "src/" + normalized.split(marker, 1)[1]
        return normalized.lstrip("./")


def normalized_source(code: str) -> str:
    without_line_numbers = SOURCE_LINE_PREFIX.sub("", code)
    return without_line_numbers.replace("\r\n", "\n").rstrip("\r\n")


def issue_record(issue: dict[str, Any], repository: Path) -> dict[str, str]:
    code = normalized_source(str(issue.get("code", "")))
    return {
        "rule_id": str(issue.get("rule_id", "")),
        "severity": str(issue.get("severity", "")),
        "confidence": str(issue.get("confidence", "")),
        "file": relative_path(str(issue.get("file", "")), repository),
        "details": str(issue.get("details", "")),
        "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
    }


def issue_key(record: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(record.get("rule_id", "")),
        str(record.get("severity", "")),
        str(record.get("confidence", "")),
        str(record.get("file", "")),
        str(record.get("details", "")),
        str(record.get("code_sha256", "")),
    )


def unique_report_issues(issues: list[dict[str, Any]], repository: Path) -> list[dict[str, Any]]:
    """Drop only byte-identical gosec emissions for the same physical location."""
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for issue in issues:
        identity = (
            str(issue.get("rule_id", "")),
            str(issue.get("severity", "")),
            str(issue.get("confidence", "")),
            relative_path(str(issue.get("file", "")), repository),
            str(issue.get("line", "")),
            str(issue.get("column", "")),
            str(issue.get("details", "")),
            normalized_source(str(issue.get("code", ""))),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(issue)
    return unique


def gosec_report_schema(
    report: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Return the canonical gosec sections after strict schema validation."""
    if "Golang errors" not in report or not isinstance(report["Golang errors"], dict):
        raise ValueError("gosec report 'Golang errors' must be a present object")
    if "Issues" not in report or not isinstance(report["Issues"], list):
        raise ValueError("gosec report 'Issues' must be a present array")
    issues = report["Issues"]
    if any(not isinstance(issue, dict) for issue in issues):
        raise ValueError("gosec report issues must be objects")
    if "Stats" not in report or not isinstance(report["Stats"], dict):
        raise ValueError("gosec report 'Stats' must be a present object")
    raw_stats = report["Stats"]
    stats: dict[str, int] = {}
    for field in ("files", "lines", "nosec", "found"):
        value = raw_stats.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"gosec Stats.{field} must be a present non-negative integer"
            )
        stats[field] = value
    if stats["found"] != len(issues):
        raise ValueError(
            "gosec Stats.found disagrees with the raw issue inventory: "
            f"found={stats['found']}, issues={len(issues)}"
        )
    return report["Golang errors"], issues, stats


def read_gosec_log(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot read gosec diagnostic log {path}: {exc}") from exc
    match = GOSEC_FATAL_LOG.search(content)
    if match is not None:
        raise ValueError(
            f"gosec diagnostic log reports a partial scan: {match.group(0)}"
        )
    if GOSEC_CHECKING_FILE.search(content) is None:
        raise ValueError("gosec diagnostic log contains no checked-file inventory")
    return content


def validate_gosec_log(path: Path) -> None:
    read_gosec_log(path)


def gosec_log_inventory(
    path: Path, repository: Path, module: str
) -> collections.Counter[str]:
    content = read_gosec_log(path)
    repository_root = repository.resolve()
    module_root = (repository_root / module).resolve()
    try:
        module_root.relative_to(repository_root)
    except ValueError as exc:
        raise ValueError(f"gosec module escapes repository: {module}") from exc

    inventory: collections.Counter[str] = collections.Counter()
    for match in GOSEC_CHECKING_FILE.finditer(content):
        candidate = Path(match.group(1).strip())
        if not candidate.is_absolute():
            candidate = module_root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(module_root)
            relative = resolved.relative_to(repository_root).as_posix()
        except ValueError as exc:
            raise ValueError(
                f"gosec checked a file outside module {module}: {candidate}"
            ) from exc
        inventory[relative] += 1
    if not inventory:
        raise ValueError("gosec diagnostic log contains an empty checked-file inventory")
    return inventory


def decode_json_stream(content: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    position = 0
    documents: list[dict[str, Any]] = []
    while position < len(content):
        while position < len(content) and content[position].isspace():
            position += 1
        if position >= len(content):
            break
        try:
            document, position = decoder.raw_decode(content, position)
        except json.JSONDecodeError as exc:
            raise ValueError(f"go list returned an invalid JSON stream: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError("go list JSON stream must contain only objects")
        documents.append(document)
    if not documents:
        raise ValueError("go list returned an empty package inventory")
    return documents


def expected_gosec_inventory(
    repository: Path,
    module: str,
    goos: str,
    goarch: str,
    cgo_enabled: str,
) -> collections.Counter[str]:
    repository_root = repository.resolve()
    module_root = (repository_root / module).resolve()
    try:
        module_root.relative_to(repository_root)
    except ValueError as exc:
        raise ValueError(f"gosec module escapes repository: {module}") from exc

    environment = os.environ.copy()
    environment.update(
        {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": cgo_enabled}
    )
    if module == "scripts/versionctl":
        environment["GOWORK"] = "off"
    target = "." if module == "scripts/versionctl" else "./..."
    try:
        process = subprocess.run(
            ["go", "list", "-mod=readonly", "-json", "-test", target],
            cwd=module_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "")
        raise ValueError(
            f"cannot resolve the expected Go file inventory for {module}: {stderr or exc}"
        ) from exc

    inventory: collections.Counter[str] = collections.Counter()
    for package in decode_json_stream(process.stdout):
        directory = Path(str(package.get("Dir", "")))
        if not directory.is_absolute():
            raise ValueError("go list package has no absolute Dir")
        for field in ("GoFiles", "CgoFiles"):
            files = package.get(field, [])
            if not isinstance(files, list):
                raise ValueError(f"go list package field {field} must be an array")
            for raw_file in files:
                candidate = Path(str(raw_file))
                if not candidate.is_absolute():
                    candidate = directory / candidate
                resolved = candidate.resolve()
                try:
                    resolved.relative_to(module_root)
                except ValueError:
                    # `go list -test` also emits generated test-main files from GOCACHE.
                    continue
                relative = resolved.relative_to(repository_root).as_posix()
                inventory[relative] += 1
    if not inventory:
        raise ValueError(f"go list found no scannable Go files for {module}")
    return inventory


def validate_gosec_file_inventory(
    reported_files: int,
    actual: collections.Counter[str],
    expected: collections.Counter[str],
) -> None:
    if reported_files != sum(actual.values()):
        raise ValueError(
            "gosec Stats.files disagrees with its checked-file log: "
            f"stats={reported_files}, log={sum(actual.values())}"
        )
    if actual == expected:
        return
    missing = expected - actual
    unexpected = actual - expected
    details: list[str] = []
    if missing:
        details.append(
            "missing=" + ",".join(f"{count}x {path}" for path, count in sorted(missing.items()))
        )
    if unexpected:
        details.append(
            "unexpected="
            + ",".join(f"{count}x {path}" for path, count in sorted(unexpected.items()))
        )
    raise ValueError("gosec checked-file inventory mismatch: " + "; ".join(details))


def load_scan(baseline: dict[str, Any], scan_name: str, tool_version: str) -> dict[str, Any]:
    expected_version = str(baseline.get("gosec_version", ""))
    if expected_version != tool_version:
        raise ValueError(
            f"gosec version {tool_version!r} does not match baseline {expected_version!r}"
        )
    scans = baseline.get("scans")
    if not isinstance(scans, dict) or not isinstance(scans.get(scan_name), dict):
        raise ValueError(f"gosec baseline has no scan named {scan_name!r}")
    return scans[scan_name]


def validate_baseline_metadata(
    baseline: dict[str, Any],
    repository: Path,
    baseline_path: Path,
    base_ref: str,
    schema_version: int,
) -> dict[str, Any] | None:
    if baseline.get("schema_version") != schema_version:
        raise ValueError(
            f"security baseline schema_version must be exactly {schema_version}"
        )
    commit = str(baseline.get("baseline_commit", ""))
    if not FULL_SHA.fullmatch(commit):
        raise ValueError("security baseline must contain a full 40-character commit SHA")
    git_output(repository, "cat-file", "-e", f"{commit}^{{commit}}")
    if base_ref and set(base_ref) != {"0"}:
        if not FULL_SHA.fullmatch(base_ref):
            raise ValueError("security baseline base-ref must be a full 40-character SHA")
        relative_baseline = baseline_path.resolve().relative_to(repository.resolve()).as_posix()
        try:
            previous = git_output(
                repository, "show", f"{base_ref}:{relative_baseline}"
            )
        except ValueError:
            if commit != base_ref:
                raise ValueError(
                    "a newly introduced security baseline must be anchored to the validated base-ref"
                )
            return None
        try:
            parsed = json.loads(previous)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"security baseline at {base_ref}:{relative_baseline} is invalid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ValueError("previous security baseline must be a JSON object")
        return parsed
    return None


def issue_counter(scan: dict[str, Any]) -> collections.Counter[tuple[str, str, str, str, str, str]]:
    issues = scan.get("issues", [])
    if not isinstance(issues, list):
        raise ValueError("gosec baseline scan issues must be an array")
    result: collections.Counter[tuple[str, str, str, str, str, str]] = collections.Counter()
    for item in issues:
        count = int(item.get("count", 1))
        if count <= 0:
            raise ValueError("gosec baseline issue counts must be positive")
        result[issue_key(item)] += count
    return result


def validate_gosec_evolution(current: dict[str, Any], previous: dict[str, Any] | None) -> None:
    if previous is None:
        return
    for field in ("schema_version", "baseline_commit", "gosec_version"):
        if current.get(field) != previous.get(field):
            raise ValueError(f"gosec baseline field {field!r} cannot change")
    current_scans = current.get("scans")
    previous_scans = previous.get("scans")
    if not isinstance(current_scans, dict) or not isinstance(previous_scans, dict):
        raise ValueError("gosec baselines must contain scan objects")
    if set(current_scans) != set(previous_scans):
        raise ValueError("gosec baseline scan inventory cannot change after introduction")
    for name, old_scan in previous_scans.items():
        new_scan = current_scans[name]
        for field in ("goos", "goarch", "cgo_enabled", "module"):
            if new_scan.get(field) != old_scan.get(field):
                raise ValueError(f"gosec scan {name!r} field {field!r} cannot change")
        added = issue_counter(new_scan) - issue_counter(old_scan)
        if added:
            raise ValueError(
                f"gosec scan {name!r} baseline may only remove reviewed findings"
            )


def baseline_scan(
    baseline: dict[str, Any] | None, scan_name: str
) -> dict[str, Any] | None:
    if baseline is None:
        return None
    scans = baseline.get("scans")
    if not isinstance(scans, dict) or not isinstance(scans.get(scan_name), dict):
        raise ValueError(f"previous gosec baseline has no scan named {scan_name!r}")
    return scans[scan_name]


def gosec_binary_version(binary: Path) -> str:
    try:
        process = subprocess.run(
            ["go", "version", "-m", str(binary)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "")
        raise ValueError(f"cannot inspect gosec binary {binary}: {stderr or exc}") from exc
    match = GOSEC_MODULE_LINE.search(process.stdout)
    if match is None:
        raise ValueError(
            f"binary {binary} does not declare github.com/securego/gosec/v2 build metadata"
        )
    return match.group(1)


def check_gosec(
    report_path: Path,
    baseline_path: Path,
    repository: Path,
    scan_name: str,
    tool_binary: Path,
    base_ref: str,
    expected_goos: str,
    expected_goarch: str,
    expected_cgo_enabled: str,
    expected_module: str,
    diagnostic_log: Path | None = None,
) -> int:
    report = read_json(report_path)
    if diagnostic_log is not None:
        validate_gosec_log(diagnostic_log)
    baseline = read_json(baseline_path)
    if not isinstance(report, dict) or not isinstance(baseline, dict):
        raise ValueError("gosec report and baseline must be JSON objects")
    previous_baseline = validate_baseline_metadata(
        baseline, repository, baseline_path, base_ref, 3
    )
    validate_gosec_evolution(baseline, previous_baseline)
    tool_version = gosec_binary_version(tool_binary)
    scan = load_scan(baseline, scan_name, tool_version)
    baseline_goos = str(scan.get("goos", ""))
    baseline_goarch = str(scan.get("goarch", ""))
    baseline_cgo_enabled = str(scan.get("cgo_enabled", ""))
    baseline_module = str(scan.get("module", ""))
    if baseline_goos != expected_goos:
        raise ValueError(
            f"gosec scan {scan_name!r} expects GOOS {baseline_goos!r}, "
            f"not {expected_goos!r}"
        )
    if baseline_goarch != expected_goarch:
        raise ValueError(
            f"gosec scan {scan_name!r} expects GOARCH {baseline_goarch!r}, "
            f"not {expected_goarch!r}"
        )
    if baseline_cgo_enabled != expected_cgo_enabled:
        raise ValueError(
            f"gosec scan {scan_name!r} expects CGO_ENABLED {baseline_cgo_enabled!r}, "
            f"not {expected_cgo_enabled!r}"
        )
    if baseline_module != expected_module:
        raise ValueError(
            f"gosec scan {scan_name!r} expects module {baseline_module!r}, "
            f"not {expected_module!r}"
        )

    errors, current_issues, stats = gosec_report_schema(report)
    if errors:
        print(f"ERROR: gosec reported Go loading errors: {errors}", file=sys.stderr)
        return 1

    files = stats["files"]
    lines = stats["lines"]
    if lines <= 0:
        print(
            "ERROR: gosec produced an empty or partial scan: "
            f"files={files}, lines={lines}",
            file=sys.stderr,
        )
        return 1
    if diagnostic_log is None:
        raise ValueError("gosec validation requires a diagnostic log")
    actual_inventory = gosec_log_inventory(
        diagnostic_log, repository, baseline_module
    )
    expected_inventory = expected_gosec_inventory(
        repository,
        baseline_module,
        baseline_goos,
        baseline_goarch,
        baseline_cgo_enabled,
    )
    validate_gosec_file_inventory(files, actual_inventory, expected_inventory)

    current_records = [
        issue_record(item, repository)
        for item in unique_report_issues(current_issues, repository)
    ]
    module = baseline_module
    outside_module = [item["file"] for item in current_records if not item["file"].startswith(module + "/")]
    if outside_module:
        print(
            f"ERROR: gosec scan {scan_name!r} contains paths outside {module}: {outside_module}",
            file=sys.stderr,
        )
        return 1

    allowed = issue_counter(scan)
    current = collections.Counter(issue_key(item) for item in current_records)
    unexpected = current - allowed
    previous_scan = baseline_scan(previous_baseline, scan_name)
    reintroduced: collections.Counter[tuple[str, str, str, str, str, str]] = collections.Counter()
    if previous_scan is not None:
        reintroduced = current - issue_counter(previous_scan)
    resolved = allowed - current

    print(
        "gosec scan summary: "
        f"scan={scan_name}, files={files}, lines={lines}, "
        f"findings={sum(current.values())}, "
        f"reviewed_baseline={sum((current & allowed).values())}, "
        f"resolved={sum(resolved.values())}"
    )

    if unexpected or reintroduced:
        print("ERROR: unreviewed gosec findings detected:", file=sys.stderr)
        for key, count in sorted((unexpected | reintroduced).items()):
            rule_id, severity, confidence, path, details, code_hash = key
            print(
                f"  - {count}x {rule_id} {severity}/{confidence} {path}: "
                f"{details} [code_sha256={code_hash}]",
                file=sys.stderr,
            )
        return 1

    if resolved:
        print(
            "ERROR: resolved gosec findings must be removed from the reviewed baseline "
            "in the same candidate so they cannot be reintroduced later.",
            file=sys.stderr,
        )
        return 1

    return 0


def annotation_fingerprint(path: str, line: str) -> tuple[str, str]:
    normalized = line.rstrip("\r\n")
    return path, hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def go_comments(content: str) -> Iterable[tuple[str, str, str]]:
    index = 0
    length = len(content)
    while index < length:
        char = content[index]
        if char in {'"', "'"}:
            quote = char
            index += 1
            while index < length:
                if content[index] == "\\":
                    index += 2
                    continue
                if content[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char == "`":
            index += 1
            while index < length and content[index] != "`":
                index += 1
            index += index < length
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "/":
            start = index
            end = content.find("\n", index + 2)
            if end < 0:
                end = length
            line_start = content.rfind("\n", 0, start) + 1
            yield content[index + 2 : end], content[line_start:end], "line"
            index = end
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "*":
            start = index
            close = content.find("*/", index + 2)
            end = length if close < 0 else close + 2
            line_start = content.rfind("\n", 0, start) + 1
            line_end = content.find("\n", end)
            if line_end < 0:
                line_end = length
            body_end = length if close < 0 else close
            yield content[index + 2 : body_end], content[line_start:line_end], "block"
            index = end
            continue
        index += 1


def nosec_directive_bodies(comment: str, kind: str) -> list[str]:
    """Mirror gosec's prefix-based #nosec and //gosec:disable recognition."""
    directives: list[str] = []
    for line in comment.splitlines() or [comment]:
        candidate = line.strip()
        if candidate.startswith("#nosec"):
            directives.append(candidate[len("#nosec") :])
            # gosec's findNoSecTag returns the first tag in a comment group.
            break
    if kind == "line" and comment.startswith("gosec:disable"):
        body = comment[len("gosec:disable") :]
        if not body or body.startswith(" "):
            directives.append(body)
    return directives


def nosec_inventory(files: Iterable[tuple[str, str]]) -> tuple[collections.Counter[tuple[str, str]], int, int]:
    legacy: collections.Counter[tuple[str, str]] = collections.Counter()
    total = 0
    qualified = 0
    for path, content in files:
        for comment, source, kind in go_comments(content):
            for body in nosec_directive_bodies(comment, kind):
                total += 1
                if QUALIFIED_NOSEC_BODY.fullmatch(body) is not None:
                    qualified += 1
                else:
                    legacy[annotation_fingerprint(path, source)] += 1
    return legacy, total, qualified


def current_go_files(repository: Path) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for root in (repository / "src" / "core", repository / "scripts" / "versionctl"):
        for path in sorted(root.rglob("*.go")):
            files.append(
                (path.relative_to(repository).as_posix(), path.read_text(encoding="utf-8"))
            )
    return files


def git_output(repository: Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "")
        raise ValueError(f"git {' '.join(arguments)} failed: {stderr or exc}") from exc
    return process.stdout


def select_base_ref(raw_ref: str, act: bool, dirty: bool) -> str:
    if act:
        return "HEAD" if dirty else "HEAD^"
    if FULL_SHA.fullmatch(raw_ref) and set(raw_ref) != {"0"}:
        return raw_ref
    return "HEAD^"


def resolve_base_ref(repository: Path, raw_ref: str, act_value: str) -> str:
    act = act_value.strip().lower() in {"1", "true", "yes", "on"}
    dirty = bool(git_output(repository, "status", "--porcelain=v1", "--untracked-files=all"))
    selected = select_base_ref(raw_ref, act, dirty)
    resolved = git_output(
        repository, "rev-parse", "--verify", f"{selected}^{{commit}}"
    ).strip()
    if not FULL_SHA.fullmatch(resolved):
        raise ValueError(f"resolved security baseline is not a full commit SHA: {resolved!r}")
    return resolved


def baseline_go_files(repository: Path, commit: str) -> list[tuple[str, str]]:
    paths = git_output(
        repository,
        "ls-tree",
        "-r",
        "--name-only",
        commit,
        "--",
        "src/core",
        "scripts/versionctl",
    ).splitlines()
    files: list[tuple[str, str]] = []
    for path in paths:
        if path.endswith(".go"):
            files.append((path, git_output(repository, "show", f"{commit}:{path}")))
    if not files:
        raise ValueError(f"baseline commit {commit} contains no Go files under src/core")
    return files


def nosec_counter(baseline: dict[str, Any]) -> collections.Counter[tuple[str, str]]:
    records = baseline.get("legacy")
    if not isinstance(records, list):
        raise ValueError("nosec baseline must contain a legacy inventory array")
    result: collections.Counter[tuple[str, str]] = collections.Counter()
    for item in records:
        path = str(item.get("file", ""))
        fingerprint = str(item.get("source_sha256", ""))
        count = int(item.get("count", 1))
        if not path or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or count <= 0:
            raise ValueError("nosec baseline contains an invalid legacy inventory record")
        result[(path, fingerprint)] += count
    return result


def validate_nosec_evolution(
    current: dict[str, Any], previous: dict[str, Any] | None
) -> None:
    if previous is None:
        return
    for field in ("schema_version", "baseline_commit"):
        if current.get(field) != previous.get(field):
            raise ValueError(f"nosec baseline field {field!r} cannot change")
    if nosec_counter(current) - nosec_counter(previous):
        raise ValueError("nosec baseline may only remove reviewed legacy suppressions")


def check_nosec(baseline_path: Path, repository: Path, base_ref: str) -> int:
    baseline = read_json(baseline_path)
    if not isinstance(baseline, dict):
        raise ValueError("nosec baseline must be a JSON object")
    previous_baseline = validate_baseline_metadata(
        baseline, repository, baseline_path, base_ref, 2
    )
    validate_nosec_evolution(baseline, previous_baseline)
    allowed = nosec_counter(baseline)
    baseline_total = sum(allowed.values())
    current, total, qualified = nosec_inventory(current_go_files(repository))
    unexpected = current - allowed
    reintroduced: collections.Counter[tuple[str, str]] = collections.Counter()
    if base_ref and set(base_ref) != {"0"}:
        base_inventory, _, _ = nosec_inventory(baseline_go_files(repository, base_ref))
        reintroduced = current - base_inventory
    resolved = allowed - current

    print(
        "#nosec inventory: "
        f"total={total}, qualified_with_rule_and_justification={qualified}, "
        f"legacy={sum(current.values())}, baseline_legacy={baseline_total}, "
        f"resolved_or_qualified={sum(resolved.values())}"
    )

    if unexpected or reintroduced:
        print(
            "ERROR: new or moved unqualified #nosec annotations detected. "
            "Use '#nosec GXXX -- reviewed justification'.",
            file=sys.stderr,
        )
        for (path, fingerprint), count in sorted((unexpected | reintroduced).items()):
            print(f"  - {count}x {path} [{fingerprint}]", file=sys.stderr)
        return 1

    if resolved:
        print(
            "ERROR: removed or qualified suppressions must be removed from the legacy "
            "baseline in the same candidate.",
            file=sys.stderr,
        )
        return 1

    return 0


def render_gosec(report_path: Path, repository: Path) -> int:
    report = read_json(report_path)
    if not isinstance(report, dict):
        raise ValueError("gosec report must be a JSON object")
    issues = report.get("Issues", [])
    if not isinstance(issues, list):
        raise ValueError("gosec report 'Issues' must be an array")
    records = [
        issue_record(item, repository)
        for item in unique_report_issues(issues, repository)
    ]
    counts = collections.Counter(issue_key(item) for item in records)
    rendered: list[dict[str, Any]] = []
    for key, count in sorted(counts.items()):
        rule_id, severity, confidence, path, details, code_hash = key
        record: dict[str, Any] = {
            "rule_id": rule_id,
            "severity": severity,
            "confidence": confidence,
            "file": path,
            "details": details,
            "code_sha256": code_hash,
        }
        if count > 1:
            record["count"] = count
        rendered.append(record)
    print(json.dumps(rendered, indent=2, sort_keys=True))
    return 0


def render_nosec(repository: Path, commit: str) -> int:
    if not FULL_SHA.fullmatch(commit):
        raise ValueError("render-nosec commit must be a full 40-character SHA")
    inventory, _, _ = nosec_inventory(baseline_go_files(repository, commit))
    records: list[dict[str, Any]] = []
    for (path, fingerprint), count in sorted(inventory.items()):
        record: dict[str, Any] = {"file": path, "source_sha256": fingerprint}
        if count > 1:
            record["count"] = count
        records.append(record)
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="repository root (defaults to the current directory)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    gosec_parser = subparsers.add_parser("gosec", help="validate a gosec JSON report")
    gosec_parser.add_argument("--report", type=Path, required=True)
    gosec_parser.add_argument("--baseline", type=Path, required=True)
    gosec_parser.add_argument("--scan", required=True)
    gosec_parser.add_argument("--tool-binary", type=Path, required=True)
    gosec_parser.add_argument("--base-ref", default="")
    gosec_parser.add_argument("--goos", required=True)
    gosec_parser.add_argument("--goarch", required=True)
    gosec_parser.add_argument("--cgo-enabled", choices=("0", "1"), required=True)
    gosec_parser.add_argument("--module", required=True)
    gosec_parser.add_argument("--diagnostic-log", type=Path, required=True)

    gosec_log_parser = subparsers.add_parser(
        "gosec-log", help="reject fatal gosec diagnostics"
    )
    gosec_log_parser.add_argument("--log", type=Path, required=True)

    nosec_parser = subparsers.add_parser("nosec", help="validate #nosec debt")
    nosec_parser.add_argument("--baseline", type=Path, required=True)
    nosec_parser.add_argument("--base-ref", default="")

    render_parser = subparsers.add_parser(
        "render-gosec", help="render stable gosec issue fingerprints for review"
    )
    render_parser.add_argument("--report", type=Path, required=True)

    render_nosec_parser = subparsers.add_parser(
        "render-nosec", help="render stable legacy suppression fingerprints"
    )
    render_nosec_parser.add_argument("--commit", required=True)
    base_ref_parser = subparsers.add_parser(
        "base-ref", help="resolve the event-aware comparison commit"
    )
    base_ref_parser.add_argument("--raw", default="")
    base_ref_parser.add_argument("--act", default="false")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repository = args.repository.resolve()
    try:
        if args.command == "gosec":
            return check_gosec(
                args.report,
                args.baseline,
                repository,
                args.scan,
                args.tool_binary,
                args.base_ref,
                args.goos,
                args.goarch,
                args.cgo_enabled,
                args.module,
                args.diagnostic_log,
            )
        if args.command == "gosec-log":
            validate_gosec_log(args.log)
            return 0
        if args.command == "nosec":
            return check_nosec(args.baseline, repository, args.base_ref)
        if args.command == "render-gosec":
            return render_gosec(args.report, repository)
        if args.command == "base-ref":
            print(resolve_base_ref(repository, args.raw, args.act))
            return 0
        return render_nosec(repository, args.commit)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
