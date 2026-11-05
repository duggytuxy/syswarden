#!/usr/bin/env python3
"""Bind exact generated-package Go test results to the observed artifact bytes.

This gate rejects missing, skipped, duplicated and foreign cases. It attests a
producer/consumer identity check only, never signatures or native installation.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from pathlib import Path
from typing import Any

try:
    from scripts.ci import native_package_signature_gate as files
except ModuleNotFoundError:
    import native_package_signature_gate as files

TEST = "TestGeneratedNativePackageIdentity"
PACKAGE = "syswarden-cli/pkg/system"
MAX_REPORT_BYTES = 4 * 1024 * 1024
RELEASE = re.compile(r"v[45]\.[0-9]{2}\.(?:0|[1-9][0-9]{0,9})\Z")
RECORD = re.compile(r"package=(syswarden(?:-base)?) format=(deb|rpm|apk) release=(v[45]\.[0-9]{2}\.[0-9]+) sha256=([0-9a-f]{64})\n?\Z")


def expected_cases(release: str) -> dict[str, tuple[str, str, str]]:
    if not isinstance(release, str) or RELEASE.fullmatch(release) is None or int(release.rsplit(".", 1)[1]) > 2147483647:
        raise ValueError("generated header gate requires a canonical v4 or v5 release")
    names = ("syswarden", "syswarden-base") if release.startswith("v5.") else ("syswarden",)
    version = release[1:]
    result = {}
    for name in names:
        for family in ("deb", "rpm", "apk"):
            filename = {"deb": f"{name}_{version}_amd64.deb", "rpm": f"{name}-{version}-1.x86_64.rpm", "apk": f"{name}_{version}_x86_64.apk"}[family]
            result[f"{TEST}/{name}/{family}"] = (name, family, filename)
    return result


def validate_events(raw: bytes, release: str) -> dict[str, str]:
    expected = expected_cases(release)
    if not raw or len(raw) > MAX_REPORT_BYTES or not raw.endswith(b"\n"):
        raise ValueError("generated header report is empty, incomplete or excessive")
    states = {name: "absent" for name in (TEST, *expected)}
    digests: dict[str, str] = {}
    package_state = "absent"
    for line in raw.splitlines():
        if not line or len(line) > 65536:
            raise ValueError("generated header event is empty or excessive")
        event = files.decode_json(line, "generated header event")
        if event.get("Package") != PACKAGE or event.get("Action") not in {"start", "run", "output", "pass"}:
            raise ValueError("generated header event is foreign, failed, skipped or unsupported")
        action, test = event["Action"], event.get("Test")
        if test is not None and (not isinstance(test, str) or test not in states):
            raise ValueError("generated header case is outside the expected inventory")
        if action == "start":
            if test is not None or package_state != "absent":
                raise ValueError("generated header package start is duplicated")
            package_state = "running"
        elif action == "run":
            if package_state != "running" or test is None or states[test] != "absent":
                raise ValueError("generated header test run is missing or duplicated")
            states[test] = "running"
        elif action == "pass":
            if package_state != "running":
                raise ValueError("generated header pass is out of sequence")
            if test is None:
                if any(state != "passed" for state in states.values()):
                    raise ValueError("generated header package passed without complete cases")
                package_state = "passed"
            else:
                if states[test] != "running" or (test in expected and test not in digests):
                    raise ValueError("generated header test passed without exact evidence")
                states[test] = "passed"
        else:
            output = event.get("Output")
            if not isinstance(output, str) or package_state != "running":
                raise ValueError("generated header output is malformed or out of sequence")
            marker = "verified generated header: "
            if marker in output:
                if test not in expected or states[test] != "running" or test in digests:
                    raise ValueError("generated header identity record is misplaced or duplicated")
                match = RECORD.fullmatch(output.split(marker, 1)[1])
                if match is None or match.group(1, 2) != expected[test][:2] or match[3] != release:
                    raise ValueError("generated header identity record differs from selection")
                digests[test] = match[4]
    if package_state != "passed" or any(state != "passed" for state in states.values()) or set(digests) != set(expected):
        raise ValueError("generated header report is incomplete")
    return {expected[name][2]: digests[name] for name in expected}


def verify(report: Path, packages: Path, release: str) -> dict[str, Any]:
    metadata = packages.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("generated package root must be a real directory")
    raw = files.regular_bytes(report, MAX_REPORT_BYTES, "generated header report")
    digests = validate_events(raw, release)
    artifacts = []
    for filename, expected in digests.items():
        data = files.regular_bytes(packages / filename, files.MAX_PACKAGE_BYTES, "generated package")
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("generated package bytes differ from tested header")
        artifacts.append({"filename": filename, "sha256": expected, "size": len(data)})
    current = packages.lstat()
    if not stat.S_ISDIR(current.st_mode) or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError("generated package root changed")
    if files.regular_bytes(report, MAX_REPORT_BYTES, "generated header report") != raw:
        raise ValueError("generated header report changed")
    return {"schema_version": 1, "release": release, "status": "generated-native-identity-verified", "artifacts": artifacts,
            "signature_acceptance": False, "native_installation_acceptance": False, "release_acceptance": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--packages", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    try:
        summary = verify(args.report, args.packages, args.release)
        files.write_json_exclusive(args.summary, summary)
    except (ValueError, OSError, files.SignatureGateError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Verified {len(summary['artifacts'])} generated native package identities; installation and signatures are separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
