#!/usr/bin/env python3
"""Capture and verify the non-ignored SysWarden repository state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


class RepositoryStateError(ValueError):
    """Raised when repository state cannot be captured or does not match."""


def git_bytes(repository: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", b"")
        detail = stderr.decode("utf-8", errors="replace") if stderr else str(exc)
        raise RepositoryStateError(
            f"git {' '.join(arguments)} failed: {detail}"
        ) from exc
    return process.stdout


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def path_record(repository: Path, relative: str) -> dict[str, Any]:
    path = repository / relative
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"path": relative, "type": "missing"}
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISREG(metadata.st_mode):
        return {
            "path": relative,
            "type": "file",
            "mode": mode,
            "size": metadata.st_size,
            "sha256": digest_file(path),
        }
    if stat.S_ISLNK(metadata.st_mode):
        return {
            "path": relative,
            "type": "symlink",
            "mode": mode,
            "target": os.readlink(path),
        }
    raise RepositoryStateError(f"unsupported repository entry type: {relative}")


def capture(repository: Path) -> dict[str, Any]:
    repository = repository.resolve()
    git_dir = git_bytes(repository, "rev-parse", "--git-dir").strip()
    if not git_dir:
        raise RepositoryStateError(f"not a Git repository: {repository}")
    raw_paths = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    )
    paths = sorted(
        item.decode("utf-8", errors="surrogateescape")
        for item in raw_paths.split(b"\0")
        if item
    )
    return {
        "schema_version": 1,
        "index_sha256": hashlib.sha256(
            git_bytes(repository, "ls-files", "--stage", "-z")
        ).hexdigest(),
        "entries": [path_record(repository, path) for path in paths],
    }


def write_snapshot(repository: Path, output: Path) -> None:
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RepositoryStateError(f"snapshot output is not a regular file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(capture(repository), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def verify_snapshot(repository: Path, snapshot: Path) -> None:
    try:
        expected = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RepositoryStateError(f"cannot read state snapshot {snapshot}: {exc}") from exc
    actual = capture(repository)
    if actual != expected:
        expected_entries = {
            item["path"]: item for item in expected.get("entries", [])
        }
        actual_entries = {item["path"]: item for item in actual["entries"]}
        changed = sorted(
            path
            for path in set(expected_entries) | set(actual_entries)
            if expected_entries.get(path) != actual_entries.get(path)
        )
        if actual.get("index_sha256") != expected.get("index_sha256"):
            changed.insert(0, "<git-index>")
        raise RepositoryStateError(
            "repository state changed during validation: " + ", ".join(changed)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--snapshot", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "capture":
            write_snapshot(args.repository, args.output)
            print(f"Repository state captured in {args.output}")
        else:
            verify_snapshot(args.repository, args.snapshot)
            print("Repository state is unchanged")
    except RepositoryStateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
