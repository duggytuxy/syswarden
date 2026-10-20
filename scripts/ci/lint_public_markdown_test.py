#!/usr/bin/env python3
"""Exercise the verified Markdown bundle runner without network or Node."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("lint_public_markdown.sh")


class MarkdownRunnerTests(unittest.TestCase):
    def test_download_verification_precedes_execution_and_failures_propagate(self) -> None:
        content = b"deliberate bundled-linter fixture\n"
        for scenario in ("valid", "digest", "download", "node-version", "lint"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script = SCRIPT.read_text(encoding="utf-8")
                # Change only the test copy's expected digest for a local fixture.
                script, count = re.subn(
                    r"'[0-9a-f]{64}'",
                    f"'{hashlib.sha256(content).hexdigest()}'",
                    script,
                )
                self.assertEqual(count, 1)
                (root / "runner.sh").write_text(script, encoding="utf-8")
                binary = root / "bin"
                binary.mkdir()
                (root / "bundle").write_bytes(content if scenario != "digest" else b"changed\n")
                gh = binary / "gh"
                gh.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' fetched > \"$TEST_ROOT/fetched\"\n"
                    "base64 \"$TEST_ROOT/bundle\"\n"
                    'test "$TEST_SCENARIO" != download\n',
                    encoding="utf-8",
                )
                gh.chmod(0o700)
                node = binary / "node"
                node.write_text(
                    "#!/bin/sh\n"
                    'if [ "$1" = --version ]; then\n'
                    '  if [ "$TEST_SCENARIO" = node-version ]; then echo v22.0.0; else echo v24.19.0; fi\n'
                    "  exit 0\n"
                    "fi\n"
                    'test "$INPUT_CONFIG" = .markdownlint.json || exit 91\n'
                    'test "$INPUT_GLOBS" = README.md || exit 92\n'
                    'test -z "$INPUT_FIX" || exit 93\n'
                    'test -z "${GH_TOKEN:-}${GH_ENTERPRISE_TOKEN:-}${GITHUB_TOKEN:-}" || exit 94\n'
                    "printf '%s\\n' executed > \"$TEST_ROOT/executed\"\n"
                    'test "$TEST_SCENARIO" != lint\n',
                    encoding="utf-8",
                )
                node.chmod(0o700)
                result = subprocess.run(
                    ["bash", str(root / "runner.sh")],
                    cwd=root,
                    env={
                        **os.environ,
                        "PATH": f"{binary}:/usr/bin:/bin",
                        "RUNNER_TEMP": str(root),
                        "TEST_ROOT": str(root),
                        "TEST_SCENARIO": scenario,
                        "GH_TOKEN": "deliberate-fixture-token",
                        "GH_ENTERPRISE_TOKEN": "deliberate-fixture-token",
                        "GITHUB_TOKEN": "deliberate-fixture-token",
                    },
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, scenario == "valid", result.stderr)
                self.assertEqual((root / "executed").exists(), scenario in ("valid", "lint"))
                self.assertEqual((root / "fetched").exists(), scenario != "node-version")
                self.assertEqual(list(root.glob("syswarden-markdown.*")), [])


if __name__ == "__main__":
    unittest.main()
