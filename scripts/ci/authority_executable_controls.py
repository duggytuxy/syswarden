"""Reject incomplete evidence from the standalone authority executable gate."""

from __future__ import annotations

import argparse
from pathlib import Path

from unprivileged_controls import MAX_REPORT_BYTES, PACKAGE, verify_tests

ROOT_TEST = "TestAuthorityExecutableBoundary"


def required_tests() -> set[str]:
    return {ROOT_TEST} | {f"{ROOT_TEST}/{name}" for name in (
        "verified-binary", "missing-descriptors", "wrong-digest", "wrong-identity",
        "swapped-directories", "read-only-readiness", "missing-no-new-privileges",
        "real-root-identity", "unexpected-group", "ambient-capability",
        "start", "kernel-identity",
        "client-resume", "client-private-storage", "client-process-interference",
        "client-no-administration", "stranger-resume-denied", "client-commit",
        "client-replay-denied", "sigterm-clean-drain", "restart",
        "client-resume-after-restart", "sigint-clean-drain",
        "sigkill-preserves-evidence", "stale-restart-refused",
    )}


def verify(data: bytes) -> int:
    return verify_tests(data, required_tests())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    with args.report.open("rb") as stream:
        count = verify(stream.read(MAX_REPORT_BYTES + 1))
    print(f"Verified {count} standalone executable cases with no skipped evidence.")


if __name__ == "__main__":
    main()
