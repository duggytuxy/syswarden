"""Reject incomplete or skipped evidence from the mandatory cross-UID gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT_TEST = "TestLocalUnprivilegedBoundary"
PACKAGE = "syswarden-core/journal"
MAX_REPORT_BYTES = 4 * 1024 * 1024


def required_tests() -> set[str]:
    cases = {ROOT_TEST}
    cases.add(f"{ROOT_TEST}/launch-configuration")
    for case in ("valid", "nil", "closed", "writable-fd", "wrong-owner", "wrong-group", "mode", "special-mode", "hardlink", "acl", "directory", "fifo", "empty", "oversized", "corrupt", "wrong-digest", "uppercase-digest", "service-identity"):
        cases.add(f"{ROOT_TEST}/launch-configuration/{case}")
    for resource in ("policy", "custody", "anchor", "segment", "checkpoint"):
        for attack in ("read", "overwrite", "append", "truncate", "unlink", "rename", "hardlink", "chmod", "chown"):
            cases.add(f"{ROOT_TEST}/{resource}/{attack}")
    for resource in ("policy", "custody", "anchor", "journal"):
        for attack in ("create", "symlink", "replace-directory"):
            cases.add(f"{ROOT_TEST}/{resource}/{attack}")
    for operation in ("resume", "commit", "inspect-recovery", "apply-recovery", "inspect-policy", "apply-policy"):
        cases.add(f"{ROOT_TEST}/ungranted-peer/{operation}")
    for attack in ("unlink", "rename", "hardlink", "chmod", "chown", "create", "symlink", "replace-directory"):
        cases.add(f"{ROOT_TEST}/endpoint-{attack}")
    for operation in ("resume", "commit", "inspect-recovery", "apply-recovery", "inspect-policy", "apply-policy"):
        cases.add(f"{ROOT_TEST}/endpoint-ungranted-{operation}")
    for attack in ("read", "overwrite", "append", "truncate", "unlink", "rename", "hardlink", "chmod", "chown"):
        cases.add(f"{ROOT_TEST}/endpoint-owner-{attack}")
    cases.add(f"{ROOT_TEST}/process-endpoint-crash-preservation")
    cases.add(f"{ROOT_TEST}/process-endpoint-recovery-denied")
    cases.add(f"{ROOT_TEST}/process-endpoint-reviewed-restart")
    for case in ("private-socket", "endpoint-outside-group", "client-rejects-impostor", "endpoint-uid-quota", "endpoint-uid-rate", "authorized-operation-after-attacks"):
        cases.add(f"{ROOT_TEST}/{case}")
    for case in ("service-start", "client-resume", "client-private-storage", "client-process-interference", "client-no-administration", "stranger-private-storage", "client-commit", "client-replay-refused", "service-stop", "service-restart", "client-resume-after-restart", "service-final-stop"):
        cases.add(f"{ROOT_TEST}/process-{case}")
    for operation in ("resume", "commit", "inspect-recovery", "apply-recovery", "inspect-policy", "apply-policy"):
        cases.add(f"{ROOT_TEST}/process-stranger-{operation}")
    return cases


def verify(data: bytes) -> int:
    if not data or len(data) > MAX_REPORT_BYTES:
        raise ValueError("empty or oversized cross-UID report")
    required = required_tests()
    started: set[str] = set()
    passed: set[str] = set()
    package_started = False
    package_passed = False
    for line in data.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict) or event.get("Package") != PACKAGE or package_passed:
            raise ValueError("invalid report envelope or data after package completion")
        action, test = event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            raise ValueError("cross-UID evidence contains a skip or failure")
        if action == "output":
            continue
        if test is None:
            if action == "start" and not package_started:
                package_started = True
            elif action == "pass" and package_started and passed == required:
                package_passed = True
            else:
                raise ValueError("invalid or incomplete package completion")
        elif not package_started or test not in required:
            raise ValueError("unexpected test identity")
        elif action == "run" and test not in started:
            started.add(test)
        elif action == "pass" and test in started and test not in passed:
            passed.add(test)
        else:
            raise ValueError("duplicate or invalid test transition")
    if not package_passed or started != required or passed != required:
        raise ValueError("missing mandatory cross-UID evidence")
    return len(required) - 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    with args.report.open("rb") as stream:
        count = verify(stream.read(MAX_REPORT_BYTES + 1))
    print(f"Verified {count} cross-UID component cases with no skipped evidence.")


if __name__ == "__main__":
    main()
