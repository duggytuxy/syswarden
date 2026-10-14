"""Reject incomplete evidence from the standalone authority executable gate."""

from __future__ import annotations

import argparse
from pathlib import Path

from unprivileged_controls import MAX_REPORT_BYTES, PACKAGE, verify_tests

ROOT_TEST = "TestAuthorityExecutableBoundary"


def required_tests() -> set[str]:
    cases = {ROOT_TEST} | {f"{ROOT_TEST}/{name}" for name in (
        "elf-actual-profiles", "launcher-elf-script", "launcher-elf-machine", "launcher-elf-writable-code", "launcher-elf-stack", "launcher-elf-table", "launcher-elf-entry", "launcher-elf-interpreter", "bootstrap-elf-script",
        "supervisor-disconnected", "supervisor-full", "resource-limits", "launcher-low-descriptor-limit", "bootstrap-low-descriptor-limit", "direct-low-descriptor-limit",
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
    cases.add(f"{ROOT_TEST}/prepared-inputs")
    cases.add(f"{ROOT_TEST}/launch-inputs")
    for name in ("valid-held", "nil", "closed", "path-fd", "parent-file", "parent-mode", "parent-owner", "parent-group", "parent-acl", "parent-default-acl", "launch-symlink", "image-symlink", "launch-hardlink", "image-hardlink", "launch-fifo", "image-fifo", "launch-missing", "image-missing", "launch-malformed", "launch-mode", "image-mode", "image-invalid-elf", "wrong-launch-digest", "wrong-image-digest", "malformed-digest", "entry-replacement"):
        cases.add(f"{ROOT_TEST}/launch-inputs/{name}")
    cases.add(f"{ROOT_TEST}/launch-snapshot")
    for name in ("valid-sealed", "source-replaced", "source-modified", "source-unlinked", "nil", "closed", "writable-fd", "path-fd", "wrong-digest", "malformed-digest", "malformed-record", "unsealed", "missing-write", "missing-grow", "missing-shrink", "missing-seal", "missing-exec", "anonymous-mode", "anonymous-owner", "anonymous-group", "anonymous-writable"):
        cases.add(f"{ROOT_TEST}/launch-snapshot/{name}")
    for name in ("launcher-unsealed-launch", "launcher-executable-launch", "bootstrap-unsealed-launch", "bootstrap-executable-launch"):
        cases.add(f"{ROOT_TEST}/{name}")
    cases.add(f"{ROOT_TEST}/runtime-inputs")
    cases.add(f"{ROOT_TEST}/prepared-runtime")
    for name in ("valid-held", "entry-replacement", "nil-state-parent", "nil-endpoint-parent", "closed-state-parent", "closed-endpoint-parent", "path-state-parent", "path-endpoint-parent", "swapped-parents", "same-parents", "nil-launch", "closed-launch", "wrong-launch-digest"):
        cases.add(f"{ROOT_TEST}/runtime-inputs/{name}")
    for target in ("state-parent", "endpoint-parent", "state", "endpoint"):
        for mutation in ("owner", "group", "mode", "acl", "default-acl"):
            cases.add(f"{ROOT_TEST}/runtime-inputs/{target}-{mutation}")
    for target in ("state", "endpoint"):
        for mutation in ("symlink", "fifo", "file", "missing"):
            cases.add(f"{ROOT_TEST}/runtime-inputs/{target}-{mutation}")
    cases.add(f"{ROOT_TEST}/launch-bundle")
    cases.add(f"{ROOT_TEST}/prepared-bundle")
    for name in ("valid-held", "nil-inputs", "nil-state", "nil-endpoint", "closed-inputs", "closed-state", "closed-endpoint", "wrong-launch-digest", "wrong-image-digest", "invalid-image", "state-owner", "endpoint-owner", "state-missing", "endpoint-missing", "swapped-parents", "repeated-runtime-refusal"):
        cases.add(f"{ROOT_TEST}/launch-bundle/{name}")
    cases.add(f"{ROOT_TEST}/readiness-monitor")
    for name in ("ready", "ready-then-eof", "eof", "wrong-byte", "extra-byte", "canceled", "deadline", "nil-context", "nil-channel", "zero-channel", "closed-channel", "closed-reader", "blocking-reader", "writer-as-reader", "regular-reader", "unsealed-reader", "second-wait", "close-failure", "earlier-close-failure", "cancel-during-wait"):
        cases.add(f"{ROOT_TEST}/readiness-monitor/{name}")
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
