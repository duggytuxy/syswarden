#!/usr/bin/env python3
"""Resolve a unique private draft and download assets through exact REST IDs.

The tag lookup endpoint describes published releases. Draft discovery uses the
release list, followed by a numeric identity lookup. This helper never publishes
or changes a release and does not replace provenance or snapshot verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPOSITORY = 'duggytuxy/syswarden'
MAX_JSON = 8 * 1024 * 1024
MAX_ASSET = 128 * 1024 * 1024


class DraftError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise DraftError(message)


def positive(value) -> bool:
    return type(value) is int and value > 0


def decode(wire: bytes):
    require(len(wire) <= MAX_JSON, 'release metadata exceeds bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate release metadata key')
            result[key] = value
        return result
    def invalid(_):
        raise DraftError('non-finite release metadata value')
    return json.loads(wire.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)


def get(path: str):
    result = subprocess.run(['gh', 'api', '--method', 'GET', path], check=True,
                            capture_output=True, timeout=120)
    return decode(result.stdout)


def validate(metadata: dict, tag: str, release_id: int | None = None) -> None:
    require(type(metadata) is dict and positive(metadata.get('id')), 'invalid release identity')
    require(release_id is None or metadata['id'] == release_id, 'release identity changed')
    require(metadata.get('tag_name') == tag and metadata.get('name') == tag and
            metadata.get('draft') is True and metadata.get('prerelease') is False,
            'release is not the exact private draft')
    require(type(metadata.get('body')) is str, 'draft notes are absent')
    assets = metadata.get('assets')
    require(type(assets) is list and 0 < len(assets) <= 100, 'invalid draft asset count')
    names, ids = set(), set()
    for asset in assets:
        require(type(asset) is dict and positive(asset.get('id')), 'invalid asset identity')
        name = asset.get('name')
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) is not None,
                'unsafe asset name')
        require(name not in names and asset['id'] not in ids, 'duplicate draft asset')
        names.add(name)
        ids.add(asset['id'])
        require(positive(asset.get('size')) and asset['size'] <= MAX_ASSET and
                type(asset.get('digest')) is str and
                re.fullmatch(r'sha256:[0-9a-f]{64}', asset['digest']) is not None and
                asset.get('state') == 'uploaded', 'invalid draft asset metadata')


def resolve(repository: str, tag: str, fetch=get) -> dict:
    require(repository == REPOSITORY, 'unexpected release repository')
    require(type(tag) is str and re.fullmatch(r'v[0-9]+\.[0-9]{2}\.[0-9]+', tag) is not None,
            'invalid release tag')
    matches, seen = [], set()
    for page in range(1, 101):
        rows = fetch(f'repos/{repository}/releases?per_page=100&page={page}')
        require(type(rows) is list and len(rows) <= 100, 'invalid release inventory')
        for row in rows:
            require(type(row) is dict and positive(row.get('id')), 'invalid listed release identity')
            require(row['id'] not in seen, 'duplicate release identity across pages')
            seen.add(row['id'])
            if row.get('tag_name') == tag:
                matches.append(row)
        if len(rows) < 100:
            break
    else:
        raise DraftError('release inventory exceeds pagination bound')
    require(len(matches) == 1, 'exactly one release must match the requested tag')
    listed = matches[0]
    validate(listed, tag)
    exact = fetch(f'repos/{repository}/releases/{listed["id"]}')
    validate(exact, tag, listed['id'])
    return exact


def download(repository: str, metadata: dict, destination: Path) -> None:
    require(repository == REPOSITORY, 'unexpected release repository')
    validate(metadata, metadata.get('tag_name'))
    require(destination.is_absolute() and destination == destination.resolve(strict=True) and
            destination.is_dir() and not any(destination.iterdir()), 'asset destination must be canonical and empty')
    for asset in metadata['assets']:
        path = destination / asset['name']
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            subprocess.run(['gh', 'api', '--method', 'GET', '-H', 'Accept: application/octet-stream',
                f'repos/{repository}/releases/assets/{asset["id"]}'], check=True,
                stdout=output, stderr=subprocess.PIPE, timeout=180)
        require(path.stat().st_size == asset['size'], 'downloaded asset size differs')
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        require('sha256:' + digest.hexdigest() == asset['digest'], 'downloaded asset digest differs')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    find = sub.add_parser('resolve')
    find.add_argument('--tag', required=True)
    files = sub.add_parser('download')
    files.add_argument('--metadata', type=Path, required=True)
    files.add_argument('--destination', type=Path, required=True)
    for command in (find, files):
        command.add_argument('--repository', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'resolve':
            print(json.dumps(resolve(args.repository, args.tag), separators=(',', ':')))
        else:
            require(args.metadata.is_file() and not args.metadata.is_symlink() and
                    args.metadata.stat().st_size <= MAX_JSON, 'invalid metadata file')
            download(args.repository, decode(args.metadata.read_bytes()), args.destination.absolute())
    except (DraftError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Private draft verification failed: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
