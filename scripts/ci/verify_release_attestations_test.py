#!/usr/bin/env python3
"""Tests for exact release-asset provenance verification."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class VerifyReleaseAttestationsTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.log = self.root / "gh.log"
        self.state = self.root / "gh.state"
        self.script = (
            Path(__file__).resolve().parent / "verify_release_attestations.sh"
        )
        self.write_executable(
            "gh",
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\0' "$@" >> "${FAKE_GH_LOG}"
count=0
if [[ -f "${FAKE_GH_STATE}" ]]; then
  read -r count < "${FAKE_GH_STATE}"
fi
count=$((count + 1))
printf '%s\\n' "${count}" > "${FAKE_GH_STATE}"
if (( count <= FAKE_GH_FAILURES )); then
  exit 1
fi
""",
        )
        self.write_executable("sleep", "#!/usr/bin/env bash\nexit 0\n")

    def write_executable(self, name: str, content: str) -> None:
        path = self.bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)

    def run_script(
        self, failures: int = 0, sha: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "FAKE_GH_LOG": str(self.log),
                "FAKE_GH_STATE": str(self.state),
                "FAKE_GH_FAILURES": str(failures),
            }
        )
        return subprocess.run(
            [
                "bash",
                str(self.script),
                str(self.assets),
                "owner/repository",
                "owner/repository/.github/workflows/release-manager.yml",
                sha or self.sha,
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def logged_calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        arguments = self.log.read_bytes().split(b"\0")
        arguments = [item.decode() for item in arguments if item]
        call_size = 10
        self.assertEqual(len(arguments) % call_size, 0, arguments)
        return [
            arguments[index : index + call_size]
            for index in range(0, len(arguments), call_size)
        ]

    def test_every_exact_asset_is_verified_with_strict_identity(self) -> None:
        for name in ("z-last.bin", "a-first.bin"):
            (self.assets / name).write_bytes(name.encode())
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.logged_calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            [Path(call[2]).name for call in calls],
            ["a-first.bin", "z-last.bin"],
        )
        for call in calls:
            self.assertEqual(call[0:2], ["attestation", "verify"])
            self.assertIn("--repo", call)
            self.assertIn("owner/repository", call)
            self.assertIn("--signer-workflow", call)
            self.assertIn(
                "owner/repository/.github/workflows/release-manager.yml", call
            )
            self.assertIn("--source-digest", call)
            self.assertIn(self.sha, call)
            self.assertIn("--deny-self-hosted-runners", call)

    def test_transient_failure_is_retried(self) -> None:
        (self.assets / "asset.bin").write_bytes(b"asset")
        result = self.run_script(failures=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.logged_calls()), 3)

    def test_five_failures_block_release(self) -> None:
        (self.assets / "asset.bin").write_bytes(b"asset")
        result = self.run_script(failures=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.logged_calls()), 5)
        self.assertIn("build provenance verification failed", result.stderr)

    def test_empty_asset_directory_and_invalid_sha_fail_closed(self) -> None:
        empty = self.run_script()
        self.assertNotEqual(empty.returncode, 0)
        self.assertIn("no release assets", empty.stderr)
        (self.assets / "asset.bin").write_bytes(b"asset")
        invalid = self.run_script(sha="not-a-sha")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("full lowercase Git commit SHA", invalid.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
