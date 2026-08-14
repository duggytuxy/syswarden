#!/usr/bin/env python3
"""Tests for exact repository state capture and verification."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import repository_state


class RepositoryStateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        subprocess.run(["git", "init", "-q", self.repository], check=True)
        (self.repository / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        (self.repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", self.repository, "add", ".gitignore", "tracked.txt"],
            check=True,
        )
        self.snapshot = self.repository.parent / f"{self.repository.name}.state.json"
        repository_state.write_snapshot(self.repository, self.snapshot)

    def test_unchanged_repository_passes(self) -> None:
        repository_state.verify_snapshot(self.repository, self.snapshot)

    def test_tracked_content_change_fails(self) -> None:
        (self.repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaises(repository_state.RepositoryStateError):
            repository_state.verify_snapshot(self.repository, self.snapshot)

    def test_untracked_file_change_fails(self) -> None:
        (self.repository / "candidate.txt").write_text("new\n", encoding="utf-8")
        with self.assertRaises(repository_state.RepositoryStateError):
            repository_state.verify_snapshot(self.repository, self.snapshot)

    def test_index_change_fails(self) -> None:
        (self.repository / "staged.txt").write_text("new\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", self.repository, "add", "staged.txt"], check=True
        )
        with self.assertRaises(repository_state.RepositoryStateError):
            repository_state.verify_snapshot(self.repository, self.snapshot)

    def test_mode_change_fails(self) -> None:
        os.chmod(self.repository / "tracked.txt", 0o755)
        with self.assertRaises(repository_state.RepositoryStateError):
            repository_state.verify_snapshot(self.repository, self.snapshot)

    def test_ignored_build_output_is_ignored(self) -> None:
        output = self.repository / "ignored" / "binary"
        output.parent.mkdir()
        output.write_bytes(b"artifact")
        repository_state.verify_snapshot(self.repository, self.snapshot)


if __name__ == "__main__":
    unittest.main(verbosity=2)
