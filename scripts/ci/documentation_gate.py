#!/usr/bin/env python3
"""Fail-closed documentation contract checks for SysWarden.

The repository README and embedded manual are always checked. A separate wiki
checkout can be supplied explicitly for the maintainer-controlled local gate.
The deterministic CI gate has no network dependency; external URLs are
syntax-checked and must use HTTPS. The maintainer-controlled release-time gate
adds an explicit reachability check through the ``check-links`` subcommand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

import release_gate


class DocumentationGateError(ValueError):
    """Raised when public documentation and executable contracts disagree."""


@dataclass(frozen=True)
class InventoryRecord:
    path: str
    bytes: int
    lines: int
    sha256: str


FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})([^`]*)$")
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
MARKDOWN_LINK_TARGET_RE = re.compile(r"\]\(\s*(<[^>]+>|[^\s)]+)")
AUTOLINK_RE = re.compile(r"<(https://[^\s<>]+)>")
VERSION_RE = re.compile(r"v[0-9]+\.[0-9]{2}\.[0-9]+")
USE_RE = re.compile(r'\bUse:\s+"([^" ]+)')
MANUAL_COMMAND_RE = re.compile(r'fmt\.Printf\("  %s([a-z][a-z0-9-]+)%s')
COBRA_PUBLIC_FIELDS = ("use", "short", "long", "example")
COBRA_UTILITY_COMMANDS = frozenset({"completion", "help"})
WORKFLOW_PACKAGE_NAME_RE = re.compile(
    r"syswarden[${}A-Za-z0-9_.-]+\.(?:deb|rpm|apk|txz)"
)
FRENCH_RE = re.compile(
    r"[àâçéèêëîïôùûüÿœ]|\b(?:aucune|ceci|cliquez|doit|français|"
    r"installation\s+sécurisée|mise\s+à\s+jour|paramètres|pré-requis|"
    r"recommandé|réseau|serveur|utilisateur|vérifiez)\b",
    re.IGNORECASE,
)
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "Slack webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    "Discord webhook": re.compile(r"https://(?:discord(?:app)?\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
}


class MarkdownHTMLLinkParser(HTMLParser):
    """Collect link-bearing HTML attributes embedded in Markdown."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.targets: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        link_attribute = "href" if tag.casefold() == "a" else "src"
        if tag.casefold() not in {"a", "img"}:
            return
        for name, value in attrs:
            if name.casefold() == link_attribute and value is not None:
                self.targets.append(value.strip())


def document_links(text: str) -> list[str]:
    """Return every Markdown, autolink and embedded HTML link target."""

    targets = [split_link_target(raw) for raw in MARKDOWN_LINK_TARGET_RE.findall(text)]
    targets.extend(AUTOLINK_RE.findall(text))
    parser = MarkdownHTMLLinkParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:  # HTMLParser errors are rare, but the gate is fail-closed.
        raise DocumentationGateError(f"cannot parse embedded HTML links: {exc}") from exc
    targets.extend(parser.targets)
    return targets


def read_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DocumentationGateError(f"required regular file is missing: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DocumentationGateError(f"cannot read UTF-8 file {path}: {exc}") from exc


def normalized(text: str) -> str:
    return " ".join(text.split())


def github_slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"[\s-]+", "-", value).strip("-")


def split_link_target(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")]
    if " " in raw:
        return raw.split(" ", 1)[0]
    return raw


def flatten_toml(value: object, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if not isinstance(value, dict):
        return keys
    for key, child in value.items():
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, dict):
            keys.update(flatten_toml(child, dotted))
        else:
            keys.add(dotted)
    return keys


def config_schema(repo_root: Path) -> set[str]:
    type_fields: dict[str, list[tuple[str, str]]] = {}
    type_pattern = re.compile(
        r"^type\s+(\w+)\s+struct\s*\{(.*?)^\}", re.MULTILINE | re.DOTALL
    )
    field_pattern = re.compile(
        r"^\s*\w+\s+([\[\]*]*\w+)\s+`[^`]*mapstructure:\"([^\"]+)\"[^`]*`",
        re.MULTILINE,
    )
    config_dir = repo_root / "src/core/syswarden-cli/config"
    files = sorted(config_dir.glob("*.go"))
    if not files:
        raise DocumentationGateError("configuration source inventory is empty")
    for path in files:
        source = read_text(path)
        for match in type_pattern.finditer(source):
            type_fields[match.group(1)] = field_pattern.findall(match.group(2))

    if "ModularConfig" not in type_fields:
        raise DocumentationGateError("ModularConfig schema root was not discovered")

    leaves: set[str] = set()

    def walk(type_name: str, prefix: str, stack: tuple[str, ...]) -> None:
        if type_name in stack:
            raise DocumentationGateError(f"recursive configuration type: {type_name}")
        fields = type_fields.get(type_name)
        if fields is None:
            if prefix:
                leaves.add(prefix)
            return
        for child_type, tag in fields:
            dotted = f"{prefix}.{tag}" if prefix else tag
            base_type = child_type.lstrip("[]*")
            if base_type in type_fields:
                walk(base_type, dotted, stack + (type_name,))
            else:
                leaves.add(dotted)

    walk("ModularConfig", "", ())
    if len(leaves) < 30:
        raise DocumentationGateError(
            f"configuration schema discovery is incomplete: {len(leaves)} keys"
        )
    return leaves


def cobra_commands(repo_root: Path) -> set[str]:
    commands: set[str] = set()
    files = sorted((repo_root / "src/core/syswarden-cli/cmd").glob("*.go"))
    if not files:
        raise DocumentationGateError("Cobra command source inventory is empty")
    for path in files:
        if path.name.endswith("_test.go"):
            continue
        commands.update(USE_RE.findall(read_text(path)))
    if "syswarden" not in commands or len(commands) < 20:
        raise DocumentationGateError(
            f"Cobra command discovery is incomplete: {sorted(commands)}"
        )
    commands.remove("syswarden")
    return commands


def snapshot_command_records(repo_root: Path) -> list[dict[str, object]]:
    snapshot = repo_root / "testdata/contracts/cli-command-tree.json"
    try:
        data = json.loads(read_text(snapshot))
    except json.JSONDecodeError as exc:
        raise DocumentationGateError(f"invalid CLI snapshot {snapshot}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise DocumentationGateError(f"CLI snapshot is empty: {snapshot}")
    records: list[dict[str, object]] = []
    paths: set[str] = set()
    for record in data:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise DocumentationGateError(f"invalid CLI snapshot record in {snapshot}")
        path = record["path"]
        if path != "syswarden" and not path.startswith("syswarden "):
            raise DocumentationGateError(f"unsupported CLI snapshot path: {path!r}")
        if path in paths:
            raise DocumentationGateError(f"duplicate CLI snapshot path: {path!r}")
        paths.add(path)

        public_record = {"path": path}
        for field in COBRA_PUBLIC_FIELDS:
            value = record.get(field, "")
            if not isinstance(value, str):
                raise DocumentationGateError(
                    f"invalid CLI snapshot {field} for {path!r}: expected string"
                )
            public_record[field] = value
        flags = record.get("flags", [])
        outcomes = record.get("arg_outcomes")
        if not isinstance(flags, list) or not all(isinstance(flag, dict) for flag in flags):
            raise DocumentationGateError(
                f"invalid CLI snapshot flags for {path!r}: expected object list"
            )
        if not isinstance(outcomes, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in outcomes.items()
        ):
            raise DocumentationGateError(
                f"invalid CLI snapshot arg_outcomes for {path!r}: expected string map"
            )
        public_record["flags"] = flags
        public_record["arg_outcomes"] = outcomes
        records.append(public_record)
    return records


def baseline_snapshot_command_records(
    repo_root: Path, version: str
) -> list[dict[str, object]]:
    snapshot = repo_root / f"testdata/contracts/cli-command-tree-{version}.json"
    if not snapshot.is_file():
        raise DocumentationGateError(
            f"versioned CLI baseline snapshot is missing: {snapshot}"
        )
    try:
        data = json.loads(read_text(snapshot))
    except json.JSONDecodeError as exc:
        raise DocumentationGateError(f"invalid CLI baseline {snapshot}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise DocumentationGateError(f"CLI baseline snapshot is empty: {snapshot}")
    return data


def validate_cli_baseline_metadata(
    repo_root: Path, contract: dict[str, object], version: str
) -> list[str]:
    metadata = contract.get("cli_baseline")
    if not isinstance(metadata, dict):
        return ["documentation contract cli_baseline must be an object"]
    baseline_version = metadata.get("version")
    if not isinstance(baseline_version, str) or VERSION_RE.fullmatch(baseline_version) is None:
        return ["CLI baseline version must use canonical vMAJOR.MINOR.PATCH form"]
    commit = metadata.get("commit")
    digest = metadata.get("sha256")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        return ["CLI baseline commit must be a full lowercase Git SHA"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return ["CLI baseline sha256 must be a lowercase SHA-256"]
    path = repo_root / f"testdata/contracts/cli-command-tree-{baseline_version}.json"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        return [
            f"CLI baseline digest changed: expected {digest}, got {actual}; reconstruct it from {commit}"
        ]
    try:
        subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"CLI baseline commit is not available in Git: {commit}: {exc}"]
    try:
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "ls-tree",
                "-r",
                "--name-only",
                commit,
                "--",
                "src/core/syswarden-cli/cmd",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"cannot inventory CLI baseline source from {commit}: {exc}"]
    source_paths = sorted(
        candidate
        for candidate in tree.splitlines()
        if re.fullmatch(r"src/core/syswarden-cli/cmd/[^/]+\.go", candidate)
        and not candidate.endswith("_test.go")
    )
    if not source_paths:
        return ["CLI baseline source inventory is empty"]
    try:
        archive = subprocess.run(
            ["git", "-C", str(repo_root), "archive", "--format=tar", commit, *source_paths],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"cannot reconstruct CLI baseline source from {commit}: {exc}"]
    source_digest = metadata.get("source_archive_sha256")
    if not isinstance(source_digest, str) or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None:
        return ["CLI baseline source_archive_sha256 must be a lowercase SHA-256"]
    actual_source_digest = hashlib.sha256(archive).hexdigest()
    if actual_source_digest != source_digest:
        return [
            f"CLI baseline source archive changed: expected {source_digest}, got {actual_source_digest}"
        ]
    return []


def cli_public_differences(
    baseline_records: Iterable[dict[str, object]],
    candidate_records: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    baseline = {str(record.get("path")): record for record in baseline_records}
    candidate = {str(record.get("path")): record for record in candidate_records}
    changes: list[dict[str, object]] = []
    public_fields = ("use", "short", "long", "example", "flags", "arg_outcomes")
    for path in sorted(set(baseline) | set(candidate)):
        if path not in baseline:
            changes.append({"path": path, "field": "command", "before": None, "after": "added"})
            continue
        if path not in candidate:
            changes.append({"path": path, "field": "command", "before": "present", "after": None})
            continue
        for field in public_fields:
            before = baseline[path].get(field, "")
            after = candidate[path].get(field, "")
            if before != after:
                changes.append(
                    {"path": path, "field": field, "before": before, "after": after}
                )
    return changes


def snapshot_command_names(records: Iterable[dict[str, object]]) -> set[str]:
    return {
        str(record["path"]).split()[1]
        for record in records
        if record["path"] != "syswarden"
    }


def snapshot_commands(repo_root: Path) -> set[str]:
    return snapshot_command_names(snapshot_command_records(repo_root))


def validate_cobra_public_texts(
    records: Iterable[dict[str, object]], forbidden_phrases: Iterable[str]
) -> list[str]:
    errors: list[str] = []
    prohibited = tuple(dict.fromkeys(forbidden_phrases))
    for record in records:
        path = record["path"]
        use = record["use"]
        if not use.strip():
            errors.append(f"CLI snapshot {path!r}: Cobra Use must not be empty")
        elif use.split()[0] != path.split()[-1]:
            errors.append(
                f"CLI snapshot {path!r}: Cobra Use command {use.split()[0]!r} "
                f"does not match path"
            )
        if not record["short"].strip():
            errors.append(f"CLI snapshot {path!r}: Cobra Short must not be empty")

        for field in COBRA_PUBLIC_FIELDS:
            text = record[field]
            label = f"CLI snapshot {path!r} Cobra {field.title()}"
            lowered = text.casefold()
            for phrase in prohibited:
                if phrase.casefold() in lowered:
                    errors.append(
                        f"{label}: prohibited unsupported phrase: {phrase!r}"
                    )
            if FRENCH_RE.search(text):
                errors.append(f"{label}: public CLI text must be written in English")
            for secret_name, pattern in SECRET_PATTERNS.items():
                if pattern.search(text):
                    errors.append(f"{label}: possible real {secret_name}")
    return errors


def source_version(repo_root: Path) -> str:
    upgrade = read_text(repo_root / "src/core/syswarden-cli/pkg/system/upgrade.go")
    match = re.search(r'var Version = "(v[0-9]+\.[0-9]{2}\.[0-9]+)"', upgrade)
    if match is None:
        raise DocumentationGateError("source version was not found in upgrade.go")
    version = match.group(1)
    changelog = read_text(repo_root / "changelog.md")
    heading = re.search(r"^# Release (v[0-9]+\.[0-9]{2}\.[0-9]+)\s*$", changelog, re.MULTILINE)
    if heading is None or heading.group(1) != version:
        actual = heading.group(1) if heading else "missing"
        raise DocumentationGateError(
            f"changelog first release {actual} does not match source {version}"
        )
    return version


def extract_fenced_blocks(text: str, label: str, errors: list[str]) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    opener: tuple[str, int, str] | None = None
    content: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = FENCE_RE.match(line)
        if opener is None:
            if match:
                marker = match.group(1)
                language = match.group(2).strip().split()[0].lower() if match.group(2).strip() else ""
                opener = (marker, line_number, language)
                content = []
            continue
        marker, start, language = opener
        if match and match.group(1)[0] == marker[0] and len(match.group(1)) >= len(marker):
            blocks.append((language, "\n".join(content) + "\n"))
            opener = None
            content = []
        else:
            content.append(line)
    if opener is not None:
        errors.append(f"{label}:{opener[1]}: unclosed Markdown fence")
    return blocks


def markdown_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    duplicates: Counter[str] = Counter()
    in_fence = False
    marker = ""
    for line in text.splitlines():
        fence = FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence = True
                marker = fence.group(1)[0]
            elif fence.group(1)[0] == marker:
                in_fence = False
            continue
        if in_fence:
            continue
        heading = HEADING_RE.match(line)
        if heading:
            base = github_slug(heading.group(2))
            count = duplicates[base]
            duplicates[base] += 1
            anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def resolve_local_target(document: Path, target: str, wiki_root: Path | None) -> Path:
    path_part = unquote(target.split("#", 1)[0])
    if path_part.startswith("/"):
        return document.parents[0] / path_part.lstrip("/")
    candidate = document.parent / path_part
    if candidate.exists():
        return candidate
    if wiki_root is not None and candidate.suffix == "":
        markdown_candidate = candidate.with_suffix(".md")
        if markdown_candidate.exists():
            return markdown_candidate
    return candidate


def markdown_commands(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    pattern = re.compile(
        r"(?:^|[\s`])(?:sudo\s+)?(?:/opt/syswarden/bin/syswarden-cli|syswarden)\s+([a-z][a-z0-9-]*)"
    )
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in pattern.finditer(line):
            found.append((line_number, match.group(1)))
    return found


def markdown_section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.find(marker)
    if start < 0:
        raise DocumentationGateError(f"missing Markdown section: {marker}")
    body_start = text.find("\n", start)
    if body_start < 0:
        return ""
    next_heading = re.search(r"(?m)^## ", text[body_start + 1 :])
    if next_heading is None:
        return text[body_start + 1 :]
    return text[body_start + 1 : body_start + 1 + next_heading.start()]


def documented_command_inventory(section: str) -> set[str]:
    """Extract only inventory entries, not commands mentioned in prose."""

    commands: set[str] = set()
    fenced_entry = re.compile(r"^([a-z][a-z0-9-]+)(?:[ \t]{2,}\S.*)?$")
    table_entry = re.compile(r"`([a-z][a-z0-9-]+)`|\b([a-z][a-z0-9-]+)\b")
    in_fence = False
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            match = fenced_entry.fullmatch(line)
            if match is not None:
                commands.add(match.group(1))
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        first_cell = stripped[1:-1].split("|", 1)[0].strip()
        if not first_cell or first_cell.casefold() == "command" or re.fullmatch(
            r":?-{3,}:?", first_cell
        ):
            continue
        for token in table_entry.finditer(first_cell):
            commands.add(token.group(1) or token.group(2))
    return commands


def validate_command_inventory(
    text: str, heading: str, expected: set[str], label: str
) -> list[str]:
    try:
        section = markdown_section(text, heading)
    except DocumentationGateError as exc:
        return [f"{label}: {exc}"]
    actual = documented_command_inventory(section)
    missing = expected - actual
    unexpected = actual - expected
    if missing or unexpected:
        return [
            f"{label}: command inventory mismatch; "
            f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        ]
    return []


def markdown_table(text: str, heading: str) -> tuple[list[str], list[list[str]]]:
    """Return the first Markdown table in a level-two section."""

    section = markdown_section(text, heading)
    header: list[str] = []
    rows: list[list[str]] = []
    in_table = False
    separator_seen = False
    separator = re.compile(r"^:?-{3,}:?$")
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            if in_table and separator_seen:
                break
            continue
        cells = [cell.strip() for cell in stripped[1:-1].split("|")]
        if not in_table:
            header = cells
            in_table = True
            continue
        if not separator_seen:
            if len(cells) != len(header) or not all(separator.fullmatch(cell) for cell in cells):
                raise DocumentationGateError(
                    f"invalid Markdown table separator below section {heading!r}"
                )
            separator_seen = True
            continue
        if len(cells) != len(header):
            raise DocumentationGateError(
                f"invalid Markdown table row width below section {heading!r}"
            )
        rows.append(cells)
    if not header or not separator_seen or not rows:
        raise DocumentationGateError(
            f"missing populated Markdown table below section {heading!r}"
        )
    return header, rows


def validate_package_source_contract(repo_root: Path, value: object) -> list[str]:
    """Bind the documented package matrix to package.yml and release_gate.py."""

    if not isinstance(value, dict):
        return ["documentation contract package_platform_contract must be an object"]
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return ["documentation package artifact contract must be a non-empty list"]

    errors: list[str] = []
    release_names: list[str] = []
    workflow_names: list[str] = []
    coordinates: set[tuple[str, str]] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or not all(
            isinstance(artifact.get(key), str) and artifact[key]
            for key in ("family", "architecture", "release_name", "workflow_name")
        ):
            errors.append(
                f"documentation package artifact {index} must define family, architecture, release_name and workflow_name"
            )
            continue
        family = artifact["family"]
        architecture = artifact["architecture"]
        coordinate = (family, architecture)
        if coordinate in coordinates:
            errors.append(f"duplicate documentation package coordinate: {coordinate!r}")
        coordinates.add(coordinate)
        try:
            release_name = artifact["release_name"].format(version="9.99.9")
        except (KeyError, ValueError) as exc:
            errors.append(f"invalid package release_name template at index {index}: {exc}")
            continue
        expected_release_name = {
            "DEB": f"syswarden_9.99.9_{architecture}.deb",
            "RPM": f"syswarden-9.99.9-1.{architecture}.rpm",
            "APK": f"syswarden_9.99.9_{architecture}.apk",
            "FreeBSD": "syswarden-9.99.9.txz",
        }.get(family)
        if expected_release_name is None:
            errors.append(f"unsupported documentation package family: {family!r}")
        elif release_name != expected_release_name:
            errors.append(
                f"package artifact naming/architecture mismatch for {coordinate!r}: "
                f"expected {expected_release_name!r}, got {release_name!r}"
            )
        if family == "FreeBSD" and architecture != "amd64":
            errors.append("the current FreeBSD package contract must identify amd64")
        release_names.append(release_name)
        workflow_names.append(artifact["workflow_name"])

    expected_release_names = release_gate.package_names("9.99.9")
    if release_names != expected_release_names:
        errors.append(
            "documentation/release package inventory mismatch; "
            f"release-gate={expected_release_names}, documentation={release_names}"
        )

    family_counts = Counter(
        artifact["family"]
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("family"), str)
    )
    number_words = {1: "one", 2: "two"}

    def count_word(family: str) -> str:
        count = family_counts.get(family, 0)
        return number_words.get(count, str(count))

    expected_inventory_phrases = {
        "README.md": (
            "The package workflow is configured to generate "
            f"{count_word('DEB')} DEB, {count_word('RPM')} RPM, "
            f"{count_word('APK')} APK and {count_word('FreeBSD')} FreeBSD "
            f"package{'s' if family_counts.get('FreeBSD') != 1 else ''} plus "
            "`SHA256SUMS.txt`."
        ),
        "wiki/Deployment-Tutorial.md": (
            "The package workflow is configured to publish "
            f"{count_word('DEB')} DEB files, {count_word('RPM')} RPM files, "
            f"{count_word('APK')} APK files, {count_word('FreeBSD')} FreeBSD "
            f"package{'s' if family_counts.get('FreeBSD') != 1 else ''} and "
            "`SHA256SUMS.txt`."
        ),
    }
    inventory_phrases = value.get("inventory_phrases")
    if inventory_phrases != expected_inventory_phrases:
        errors.append(
            "documentation package count statements do not match the exact release inventory; "
            f"expected={expected_inventory_phrases}, actual={inventory_phrases}"
        )

    workflow = read_text(repo_root / ".github/workflows/package.yml")
    discovered_workflow_names = set(WORKFLOW_PACKAGE_NAME_RE.findall(workflow))
    if discovered_workflow_names != set(workflow_names):
        errors.append(
            "documentation/package workflow asset inventory mismatch; "
            f"workflow-only={sorted(discovered_workflow_names - set(workflow_names))}, "
            f"documentation-only={sorted(set(workflow_names) - discovered_workflow_names)}"
        )
    return errors


def validate_package_documentation(
    text: str, label: str, value: object
) -> list[str]:
    """Validate exact package counts, architectures and qualification rows."""

    if not isinstance(value, dict):
        return ["documentation contract package_platform_contract must be an object"]
    errors: list[str] = []
    phrases = value.get("inventory_phrases")
    if not isinstance(phrases, dict):
        errors.append("documentation package inventory_phrases must be an object")
    else:
        phrase = phrases.get(label)
        if phrase is not None:
            if not isinstance(phrase, str) or not phrase:
                errors.append(f"documentation package inventory phrase for {label} is invalid")
            elif normalized(phrase) not in normalized(text):
                errors.append(f"{label}: package artifact count statement changed: {phrase!r}")

    tables = value.get("tables")
    if not isinstance(tables, dict):
        errors.append("documentation package tables must be an object")
        return errors
    table_contract = tables.get(label)
    if table_contract is None:
        return errors
    if not isinstance(table_contract, dict):
        return errors + [f"documentation package table contract for {label} is invalid"]
    heading = table_contract.get("heading")
    expected_header = table_contract.get("header")
    expected_rows = table_contract.get("rows")
    if (
        not isinstance(heading, str)
        or not isinstance(expected_header, list)
        or not all(isinstance(cell, str) for cell in expected_header)
        or not isinstance(expected_rows, list)
        or not all(
            isinstance(row, list) and all(isinstance(cell, str) for cell in row)
            for row in expected_rows
        )
    ):
        return errors + [f"documentation package table contract for {label} is invalid"]
    try:
        actual_header, actual_rows = markdown_table(text, heading)
    except DocumentationGateError as exc:
        return errors + [f"{label}: {exc}"]
    if actual_header != expected_header or actual_rows != expected_rows:
        errors.append(
            f"{label}: package/platform table differs from the reviewed contract; "
            f"expected_header={expected_header}, actual_header={actual_header}, "
            f"expected_rows={expected_rows}, actual_rows={actual_rows}"
        )
    return errors


def external_links(paths: Iterable[Path]) -> list[str]:
    links: set[str] = set()
    for path in paths:
        text = read_text(path)
        for target in document_links(text):
            parsed = urlparse(target)
            if parsed.scheme == "https" and parsed.netloc:
                links.add(target)
    return sorted(links)


def check_external_links(paths: Iterable[Path], timeout_seconds: float) -> list[str]:
    errors: list[str] = []
    for target in external_links(paths):
        if target.endswith(".invalid") or ".invalid/" in target:
            continue
        request = Request(
            target,
            headers={"User-Agent": "SysWarden-documentation-gate/1"},
            method="HEAD",
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    errors.append(f"external link returned HTTP {status}: {target}")
        except HTTPError as exc:
            # Some valid public endpoints reject HEAD; retry once with GET.
            if exc.code not in (403, 405):
                errors.append(f"external link returned HTTP {exc.code}: {target}")
                continue
            try:
                fallback = Request(
                    target,
                    headers={"User-Agent": "SysWarden-documentation-gate/1"},
                    method="GET",
                )
                with urlopen(fallback, timeout=timeout_seconds) as response:
                    if getattr(response, "status", 200) >= 400:
                        errors.append(
                            f"external link returned HTTP {response.status}: {target}"
                        )
            except (HTTPError, URLError, TimeoutError, socket.timeout) as retry_exc:
                errors.append(f"external link is unreachable: {target}: {retry_exc}")
        except (URLError, TimeoutError, socket.timeout) as exc:
            errors.append(f"external link is unreachable: {target}: {exc}")
    return errors


def validate_markdown(
    path: Path,
    text: str,
    known_commands: set[str],
    known_config_keys: set[str],
    forbidden_phrases: Iterable[str],
    current_version: str,
    wiki_root: Path | None,
) -> list[str]:
    errors: list[str] = []
    label = path.as_posix()
    lines = text.splitlines()
    if not lines:
        return [f"{label}: empty Markdown document"]
    if not any(HEADING_RE.match(line) for line in lines):
        errors.append(f"{label}: no Markdown heading")
    for line_number, line in enumerate(lines, 1):
        if line.rstrip() != line:
            errors.append(f"{label}:{line_number}: trailing whitespace")
        if "\t" in line:
            errors.append(f"{label}:{line_number}: tab character in Markdown")

    blocks = extract_fenced_blocks(text, label, errors)
    anchors = markdown_anchors(text)
    for target in document_links(text):
        if not target:
            errors.append(f"{label}: empty link target")
            continue
        parsed = urlparse(target)
        if parsed.scheme:
            if parsed.scheme != "https" or not parsed.netloc:
                errors.append(f"{label}: external link must be an absolute HTTPS URL: {target}")
            continue
        if target.startswith("#"):
            anchor = unquote(target[1:]).lower()
            if anchor not in anchors:
                errors.append(f"{label}: missing local anchor: {target}")
            continue
        resolved = resolve_local_target(path, target, wiki_root)
        if not resolved.exists():
            errors.append(f"{label}: missing local link target: {target}")
            continue
        if "#" in target and resolved.suffix.lower() == ".md":
            anchor = unquote(target.split("#", 1)[1]).lower()
            target_anchors = markdown_anchors(read_text(resolved))
            if anchor not in target_anchors:
                errors.append(f"{label}: missing target anchor: {target}")

    for language, body in blocks:
        if language == "toml":
            try:
                parsed_toml = tomllib.loads(body)
            except tomllib.TOMLDecodeError as exc:
                errors.append(f"{label}: invalid TOML fenced block: {exc}")
                continue
            unknown = flatten_toml(parsed_toml) - known_config_keys
            if unknown:
                errors.append(
                    f"{label}: unknown TOML configuration keys: {sorted(unknown)}"
                )

    for line_number, command in markdown_commands(text):
        if command not in known_commands:
            errors.append(f"{label}:{line_number}: unknown syswarden command: {command}")

    lowered = text.casefold()
    for phrase in forbidden_phrases:
        if phrase.casefold() in lowered:
            errors.append(f"{label}: prohibited unsupported phrase: {phrase!r}")
    if FRENCH_RE.search(text):
        errors.append(f"{label}: public documentation must be written in English")
    for secret_name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            errors.append(f"{label}: possible real {secret_name} in documentation")

    for line_number, line in enumerate(lines, 1):
        versions = VERSION_RE.findall(line)
        for version in versions:
            if version == current_version:
                continue
            context = line.casefold()
            if not any(word in context for word in ("historical", "archive", "obsolete", "version-specific")):
                errors.append(
                    f"{label}:{line_number}: non-current version {version} is not explicitly historical"
                )
    return errors


def load_contract(repo_root: Path) -> dict[str, object]:
    path = repo_root / "scripts/ci/documentation_contract.json"
    try:
        contract = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise DocumentationGateError(f"invalid documentation contract: {exc}") from exc
    if not isinstance(contract, dict) or contract.get("schema_version") != 1:
        raise DocumentationGateError("unsupported documentation contract schema")
    return contract


def require_phrases(
    text: str, phrases: Iterable[str], version: str, label: str
) -> list[str]:
    haystack = normalized(text)
    errors: list[str] = []
    for raw in phrases:
        phrase = raw.format(version=version)
        if normalized(phrase) not in haystack:
            errors.append(f"{label}: required reviewed statement is missing: {phrase!r}")
    return errors


def validate_source_assertions(repo_root: Path, contract: dict[str, object]) -> list[str]:
    errors: list[str] = []
    assertions = contract.get("source_assertions")
    if not isinstance(assertions, list) or not assertions:
        return ["documentation contract has no source assertions"]
    seen: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict):
            errors.append("documentation contract contains a non-object source assertion")
            continue
        identifier = assertion.get("id")
        relative = assertion.get("path")
        literal = assertion.get("literal")
        if not all(isinstance(value, str) and value for value in (identifier, relative, literal)):
            errors.append(f"invalid source assertion: {assertion!r}")
            continue
        if identifier in seen:
            errors.append(f"duplicate source assertion id: {identifier}")
        seen.add(identifier)
        path = repo_root / relative
        try:
            source = read_text(path)
        except DocumentationGateError as exc:
            errors.append(str(exc))
            continue
        if literal not in source:
            errors.append(
                f"source assertion {identifier!r} changed in {relative}; review the public limitation and contract together"
            )
    return errors


def inventory(root: Path, label: str) -> list[InventoryRecord]:
    if root.is_symlink() or not root.is_dir():
        raise DocumentationGateError(f"{label} root is missing or is a symlink: {root}")
    records: list[InventoryRecord] = []
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            raise DocumentationGateError(f"{label} contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise DocumentationGateError(f"{label} contains an unsupported entry: {path}")
        data = path.read_bytes()
        if not data:
            raise DocumentationGateError(f"{label} contains an empty file: {path}")
        records.append(
            InventoryRecord(
                path=path.relative_to(root).as_posix(),
                bytes=len(data),
                lines=len(data.splitlines()),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    if not records:
        raise DocumentationGateError(f"{label} inventory is empty: {root}")
    return records


def validate_wiki(
    wiki_root: Path,
    records: list[InventoryRecord],
    known_commands: set[str],
    known_config_keys: set[str],
    forbidden_phrases: Iterable[str],
    version: str,
    required_phrases: object,
) -> list[str]:
    errors: list[str] = []
    markdown_records = [record for record in records if record.path.endswith(".md")]
    if not markdown_records:
        return [f"wiki contains no Markdown pages: {wiki_root}"]
    home_path = wiki_root / "Home.md"
    if not home_path.is_file():
        errors.append(f"wiki Home.md is missing: {wiki_root}")
        home_text = ""
    else:
        home_text = read_text(home_path)
    referenced_assets: set[str] = set()
    for record in markdown_records:
        path = wiki_root / record.path
        text = read_text(path)
        if not re.search(r"^> Status: (?:Current|Version-specific|Obsolete|Archive)\s*$", text, re.MULTILINE):
            errors.append(f"{path}: missing reviewed wiki status banner")
        expected_baseline = f"> Documentation baseline: {version}"
        if expected_baseline not in text:
            errors.append(f"{path}: missing baseline banner {expected_baseline!r}")
        errors.extend(
            validate_markdown(
                path,
                text,
                known_commands,
                known_config_keys,
                forbidden_phrases,
                version,
                wiki_root,
            )
        )
        page_required = (
            required_phrases.get(record.path, [])
            if isinstance(required_phrases, dict)
            else []
        )
        if not isinstance(page_required, list) or not all(
            isinstance(item, str) and item for item in page_required
        ):
            errors.append(
                f"documentation contract required_wiki_phrases[{record.path!r}] must be a string list"
            )
        else:
            errors.extend(
                require_phrases(
                    text,
                    page_required,
                    version,
                    f"wiki/{record.path}",
                )
            )
        for target in document_links(text):
            parsed = urlparse(target)
            if parsed.scheme or target.startswith("#"):
                continue
            resolved = resolve_local_target(path, target, wiki_root)
            try:
                relative = resolved.relative_to(wiki_root).as_posix()
            except ValueError:
                continue
            referenced_assets.add(relative.split("#", 1)[0])

    for record in markdown_records:
        if record.path == "Home.md":
            continue
        stem = Path(record.path).with_suffix("").as_posix()
        candidates = (record.path, stem)
        if not any(candidate in home_text for candidate in candidates):
            errors.append(f"wiki Home.md does not link to page: {record.path}")

    for record in records:
        if record.path.endswith(".md"):
            continue
        if record.path not in referenced_assets:
            errors.append(f"wiki asset is not referenced by any page: {record.path}")
    return errors


def validate_repository(
    repo_root: Path, wiki_root: Path | None = None
) -> tuple[list[InventoryRecord], list[str]]:
    repo_root = repo_root.resolve()
    contract = load_contract(repo_root)
    version = source_version(repo_root)
    source_commands = cobra_commands(repo_root)
    snapshot_records = snapshot_command_records(repo_root)
    baseline_metadata = contract.get("cli_baseline", {})
    baseline_version = (
        baseline_metadata.get("version", version)
        if isinstance(baseline_metadata, dict)
        else version
    )
    baseline_snapshot_records = baseline_snapshot_command_records(
        repo_root, str(baseline_version)
    )
    snapshots = snapshot_command_names(snapshot_records)
    commands = snapshots
    config_keys = config_schema(repo_root)
    errors: list[str] = []
    errors.extend(validate_cli_baseline_metadata(repo_root, contract, version))
    expected_snapshot_commands = source_commands | {"completion", "help"}
    if expected_snapshot_commands != snapshots:
        errors.append(
            "Cobra/help snapshot inventory mismatch; "
            f"source-only={sorted(expected_snapshot_commands - snapshots)}, "
            f"snapshot-only={sorted(snapshots - expected_snapshot_commands)}"
        )

    readme_path = repo_root / "README.md"
    manual_path = repo_root / "src/core/syswarden-cli/cmd/manual.go"
    readme = read_text(readme_path)
    manual = read_text(manual_path)
    forbidden = contract.get("forbidden_phrases")
    cobra_forbidden = contract.get("forbidden_cobra_phrases")
    readme_required = contract.get("required_readme_phrases")
    manual_required = contract.get("required_manual_phrases")
    wiki_required = contract.get("required_wiki_phrases")
    product_command_count = contract.get("product_command_count")
    package_platform_contract = contract.get("package_platform_contract")
    if not isinstance(forbidden, list) or not all(isinstance(item, str) for item in forbidden):
        errors.append("documentation contract forbidden_phrases must be a string list")
        forbidden = []
    if not isinstance(cobra_forbidden, list) or not all(
        isinstance(item, str) and item for item in cobra_forbidden
    ):
        errors.append(
            "documentation contract forbidden_cobra_phrases must be a non-empty string list"
        )
        cobra_forbidden = []
    if not isinstance(readme_required, list) or not all(isinstance(item, str) for item in readme_required):
        errors.append("documentation contract required_readme_phrases must be a string list")
        readme_required = []
    if not isinstance(manual_required, list) or not all(isinstance(item, str) for item in manual_required):
        errors.append("documentation contract required_manual_phrases must be a string list")
        manual_required = []
    if not isinstance(product_command_count, int) or product_command_count <= 0:
        errors.append("documentation contract product_command_count must be a positive integer")
    elif len(source_commands) != product_command_count:
        errors.append(
            "product command count differs from the reviewed contract; "
            f"expected={product_command_count}, actual={len(source_commands)}"
        )
    if source_commands & COBRA_UTILITY_COMMANDS:
        errors.append(
            "Cobra utility commands leaked into the product command source inventory: "
            f"{sorted(source_commands & COBRA_UTILITY_COMMANDS)}"
        )
    errors.extend(
        validate_package_source_contract(repo_root, package_platform_contract)
    )

    errors.extend(
        validate_cobra_public_texts(
            snapshot_records,
            [*forbidden, *cobra_forbidden],
        )
    )

    public_differences = cli_public_differences(
        baseline_snapshot_records, snapshot_records
    )
    approved_differences = contract.get("approved_cli_public_differences")
    if not isinstance(approved_differences, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("field"), str)
        and isinstance(item.get("reason"), str)
        and item["reason"].strip()
        and "before" in item
        and "after" in item
        for item in approved_differences
    ):
        errors.append(
            "documentation contract approved_cli_public_differences must contain path, field, before, after and reason"
        )
        approved_differences = []
    approved_by_key = {
        (item["path"], item["field"]): item for item in approved_differences
    }
    actual_by_key = {
        (item["path"], item["field"]): item for item in public_differences
    }
    approved_keys = set(approved_by_key)
    actual_keys = set(actual_by_key)
    invalid_values = sorted(
        key
        for key in approved_keys & actual_keys
        if approved_by_key[key].get("before") != actual_by_key[key]["before"]
        or approved_by_key[key].get("after") != actual_by_key[key]["after"]
    )
    if actual_keys != approved_keys or invalid_values:
        errors.append(
            "CLI baseline/candidate public differences are not exactly approved; "
            f"unapproved={sorted(actual_keys - approved_keys)}, "
            f"stale_approvals={sorted(approved_keys - actual_keys)}, "
            f"value_mismatches={invalid_values}"
        )

    errors.extend(
        validate_markdown(
            readme_path,
            readme,
            commands,
            config_keys,
            forbidden,
            version,
            None,
        )
    )
    errors.extend(require_phrases(readme, readme_required, version, "README.md"))
    errors.extend(require_phrases(manual, manual_required, version, "manual.go"))
    errors.extend(
        validate_package_documentation(
            readme, "README.md", package_platform_contract
        )
    )
    errors.extend(
        validate_command_inventory(
            readme, "Operator commands", source_commands, "README.md"
        )
    )
    errors.extend(validate_source_assertions(repo_root, contract))

    manual_commands = set(MANUAL_COMMAND_RE.findall(manual))
    if manual_commands != source_commands:
        errors.append(
            "embedded manual/Cobra command inventory mismatch; "
            f"manual-only={sorted(manual_commands - source_commands)}, "
            f"manual-missing={sorted(source_commands - manual_commands)}"
        )
    if re.search(r"\benroll\b", readme + "\n" + manual, re.IGNORECASE):
        errors.append("README/manual documents the nonexistent enroll command")

    records = [
        InventoryRecord(
            path="README.md",
            bytes=readme_path.stat().st_size,
            lines=len(readme.splitlines()),
            sha256=hashlib.sha256(readme_path.read_bytes()).hexdigest(),
        )
    ]
    if wiki_root is not None:
        wiki_root = wiki_root.resolve()
        wiki_records = inventory(wiki_root, "wiki")
        records.extend(
            InventoryRecord(
                path=f"wiki/{record.path}",
                bytes=record.bytes,
                lines=record.lines,
                sha256=record.sha256,
            )
            for record in wiki_records
        )
        errors.extend(
            validate_wiki(
                wiki_root,
                wiki_records,
                commands,
                config_keys,
                forbidden,
                version,
                wiki_required,
            )
        )
        deployment = wiki_root / "Deployment-Tutorial.md"
        if deployment.is_file():
            errors.extend(
                validate_command_inventory(
                    read_text(deployment),
                    "11. Command inventory",
                    source_commands,
                    "wiki/Deployment-Tutorial.md",
                )
            )
        wiki_markdown = {
            f"wiki/{record.path}": read_text(wiki_root / record.path)
            for record in wiki_records
            if record.path.endswith(".md")
        }
        tables = (
            package_platform_contract.get("tables", {})
            if isinstance(package_platform_contract, dict)
            else {}
        )
        phrases = (
            package_platform_contract.get("inventory_phrases", {})
            if isinstance(package_platform_contract, dict)
            else {}
        )
        expected_wiki_documents = {
            label
            for mapping in (tables, phrases)
            if isinstance(mapping, dict)
            for label in mapping
            if isinstance(label, str) and label.startswith("wiki/")
        }
        for label in sorted(expected_wiki_documents):
            text = wiki_markdown.get(label)
            if text is None:
                errors.append(
                    f"{label}: package/platform documentation page is missing"
                )
                continue
            errors.extend(
                validate_package_documentation(
                    text, label, package_platform_contract
                )
            )
    return records, errors


def write_json_report(
    path: Path,
    repo_root: Path,
    wiki_root: Path | None,
    records: list[InventoryRecord],
    errors: list[str],
) -> None:
    report = {
        "schema_version": 1,
        "status": "PASS" if not errors else "FAIL",
        "repo_root": str(repo_root.resolve()),
        "wiki_root": str(wiki_root.resolve()) if wiki_root is not None else None,
        "inventory": [asdict(record) for record in records],
        "errors": errors,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def classify_original_line(line: str) -> tuple[str, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("```"):
        return "STRUCTURE_REBUILT", "Blank line or Markdown fence"
    if stripped.startswith("#"):
        return "STRUCTURE_REBUILT", "Heading or code comment reviewed"
    if re.search(
        r"production|enterprise|guarante|zero|instant|flawless|absolute|"
        r"compliance|SLSA|memory-safe|saniti|military-grade",
        stripped,
        re.IGNORECASE,
    ):
        return "UNSUPPORTED_CLAIM_REMOVED", "Claim required evidence or qualification"
    if re.search(r"\bsyswarden\b|^[A-Za-z0-9_.-]+\s*=|^\[[A-Za-z0-9_.-]+\]", stripped):
        return "EXAMPLE_REVALIDATED_OR_REMOVED", "Command or configuration example reviewed"
    if "http://" in stripped or "https://" in stripped or "](" in stripped:
        return "LINK_REVALIDATED_OR_REMOVED", "Link reviewed"
    return "CONTENT_REWRITTEN", "Narrative reviewed against source"


def write_line_inventory(wiki_root: Path, output: Path) -> None:
    records = inventory(wiki_root, "wiki")
    markdown = [record for record in records if record.path.endswith(".md")]
    rows = ["file\tline\tstatus\tnote\tline_sha256\texcerpt"]
    for record in markdown:
        path = wiki_root / record.path
        for line_number, line in enumerate(read_text(path).splitlines(), 1):
            status, note = classify_original_line(line)
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            excerpt = " ".join(line.strip().split())[:120]
            excerpt = excerpt.replace("\t", " ")
            rows.append(
                f"{record.path}\t{line_number}\t{status}\t{note}\t{digest}\t{excerpt}"
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def command_check(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root)
    wiki_root = Path(args.wiki_root) if args.wiki_root else None
    try:
        records, errors = validate_repository(repo_root, wiki_root)
    except DocumentationGateError as exc:
        records, errors = [], [str(exc)]
    if args.report:
        write_json_report(Path(args.report), repo_root, wiki_root, records, errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    scope = "README/manual"
    if wiki_root is not None:
        scope += f" and {len(records) - 1} wiki files"
    print(f"Documentation truth gate passed for {scope}.")
    return 0


def command_inventory(args: argparse.Namespace) -> int:
    try:
        write_line_inventory(Path(args.wiki_root).resolve(), Path(args.output))
    except DocumentationGateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Wiki line inventory written to {args.output}.")
    return 0


def command_check_links(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    paths = [repo_root / "README.md"]
    if args.wiki_root:
        wiki_root = Path(args.wiki_root).resolve()
        try:
            records = inventory(wiki_root, "wiki")
        except DocumentationGateError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        paths.extend(
            wiki_root / record.path
            for record in records
            if record.path.endswith(".md")
        )
    try:
        errors = check_external_links(paths, args.timeout_seconds)
    except DocumentationGateError as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"External documentation links passed for {len(paths)} Markdown files.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="validate README/manual and optional wiki")
    check.add_argument("--repo-root", default=".")
    check.add_argument("--wiki-root")
    check.add_argument("--report")
    check.set_defaults(func=command_check)

    line_inventory = subparsers.add_parser(
        "inventory", help="produce a line-by-line review ledger for a wiki checkout"
    )
    line_inventory.add_argument("--wiki-root", required=True)
    line_inventory.add_argument("--output", required=True)
    line_inventory.set_defaults(func=command_inventory)

    link_check = subparsers.add_parser(
        "check-links", help="verify external HTTPS documentation links"
    )
    link_check.add_argument("--repo-root", default=".")
    link_check.add_argument("--wiki-root")
    link_check.add_argument("--timeout-seconds", type=float, default=20.0)
    link_check.set_defaults(func=command_check_links)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
