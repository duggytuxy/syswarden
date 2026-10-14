"""Reject incomplete evidence from the standalone authority executable gate."""

from __future__ import annotations

import argparse
from pathlib import Path

from unprivileged_controls import MAX_REPORT_BYTES, PACKAGE, verify_tests

ROOT_TEST = "TestAuthorityExecutableBoundary"


def required_tests() -> set[str]:
    cases = {ROOT_TEST} | {f"{ROOT_TEST}/{name}" for name in (
        "bootstrap-lifecycle", "launcher-bounding-set", "verified-launcher", "launcher-not-root", "launcher-wrong-launch-digest", "launcher-wrong-image-digest", "launcher-missing-image", "launcher-unsealed-image",
        "verified-bootstrap", "bootstrap-inheritance", "wrong-image-digest", "unsealed-image", "missing-image", "bootstrap-root",
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
    cases.add(f"{ROOT_TEST}/executable-snapshot")
    for name in ("valid-sealed", "source-replaced", "source-modified", "nil", "closed",
                 "writable-fd", "path-fd", "wrong-owner", "wrong-group", "mode", "special-mode",
                 "hardlink", "acl", "file-capability", "directory", "fifo", "empty",
                 "oversized", "wrong-digest", "uppercase-digest", "malformed-digest"):
        cases.add(f"{ROOT_TEST}/executable-snapshot/{name}")
    return cases


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
