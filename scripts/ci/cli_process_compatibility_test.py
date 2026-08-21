#!/usr/bin/env python3
"""Unit tests for the isolated CLI baseline/candidate process gate."""

from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cli_process_compatibility as gate


def record(
    path: str,
    *,
    use: str | None = None,
    short: str = "description",
    long: str = "",
    flags: list[dict[str, object]] | None = None,
    outcomes: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "path": path,
        "use": use if use is not None else path.split()[-1],
        "short": short,
        "long": long,
        "example": "",
        "flags": flags or [],
        "arg_outcomes": outcomes
        or {str(count): "ok" for count in range(5)},
    }


class CLIProcessCompatibilityTest(unittest.TestCase):
    def test_public_differences_require_exact_non_stale_approvals(self) -> None:
        baseline = [record("syswarden", long="old boundary")]
        candidate = [record("syswarden", long="new boundary")]
        changes = gate.public_differences(baseline, candidate)
        approvals = [
            {
                "path": "syswarden",
                "field": "long",
                "reason": "Bound the public claim.",
                "before": "old boundary",
                "after": "new boundary",
            }
        ]
        self.assertEqual(
            gate.classify_public_differences(changes, approvals),
            [{**changes[0], "reason": "Bound the public claim."}],
        )

        changed_approval = [{**approvals[0], "after": "different"}]
        with self.assertRaisesRegex(gate.CompatibilityError, "values do not match"):
            gate.classify_public_differences(changes, changed_approval)
        with self.assertRaisesRegex(gate.CompatibilityError, "unapproved"):
            gate.classify_public_differences(changes, [])
        with self.assertRaisesRegex(gate.CompatibilityError, "stale"):
            gate.classify_public_differences([], approvals)

    def test_safe_case_matrix_never_executes_valid_product_arguments(self) -> None:
        rejected = {
            "0": "requires at least 1 arg(s), only received 0",
            "1": "ok",
            "2": "ok",
            "3": "ok",
            "4": "ok",
        }
        completion_rejected = {
            "0": "ok",
            "1": 'unknown command "arg-1"',
            "2": 'unknown command "arg-1"',
            "3": 'unknown command "arg-1"',
            "4": 'unknown command "arg-1"',
        }
        cases = gate.make_process_cases(
            [
                record("syswarden"),
                record("syswarden block", use="block <IP>...", outcomes=rejected),
                record("syswarden completion", outcomes=completion_rejected),
                record("syswarden completion bash", outcomes=completion_rejected),
            ]
        )
        arity = [case for case in cases if case.case_id.startswith("arity:")]
        self.assertEqual([case.case_id for case in arity], ["arity:syswarden block:0"])
        self.assertEqual(arity[0].argv, ("block",))
        self.assertNotIn("ok", {case.expected_error for case in arity})
        self.assertEqual(
            {case.path for case in cases if case.category == "help"},
            {
                "syswarden",
                "syswarden block",
                "syswarden completion",
                "syswarden completion bash",
            },
        )

    def test_command_set_transition_requires_exact_approved_additions_and_removals(self) -> None:
        baseline = {
            "syswarden": record("syswarden"),
            "syswarden retired": record("syswarden retired"),
        }
        candidate = {
            "syswarden": record("syswarden"),
            "syswarden replacement": record("syswarden replacement"),
        }
        approvals = [
            {
                "path": "syswarden retired",
                "field": "command",
                "before": "present",
                "after": None,
                "reason": "Retire network exposure.",
            },
            {
                "path": "syswarden replacement",
                "field": "command",
                "before": None,
                "after": "added",
                "reason": "Add local administration.",
            },
        ]
        self.assertEqual(
            gate.approved_common_command_paths(baseline, candidate, approvals),
            {"syswarden"},
        )
        with self.assertRaisesRegex(gate.CompatibilityError, "do not match"):
            gate.approved_common_command_paths(baseline, candidate, approvals[:1])

    def test_help_change_is_reduced_only_to_approved_public_text(self) -> None:
        baseline = {
            "syswarden": record("syswarden", long="old root"),
            "syswarden audit": record("syswarden audit", short="old audit"),
        }
        candidate = {
            "syswarden": record("syswarden", long="new root"),
            "syswarden audit": record("syswarden audit", short="new audit"),
        }
        changes = [
            {
                "path": "syswarden",
                "field": "long",
                "before": "old root",
                "after": "new root",
                "reason": "truth",
            },
            {
                "path": "syswarden audit",
                "field": "short",
                "before": "old audit",
                "after": "new audit",
                "reason": "truth",
            },
        ]
        case = gate.ProcessCase(
            "help:syswarden", "help", "syswarden", ("--help",)
        )
        before = gate.ProcessResult(0, "old root\n  audit  old audit\n", "")
        after = gate.ProcessResult(0, "new root\n  audit  new audit\n", "")
        classification = gate.classify_process_result(
            case, before, after, baseline, candidate, changes, []
        )
        self.assertEqual(
            classification["streams"]["stdout"], "approved-public-fields"
        )

        unexpected = gate.ProcessResult(0, after.stdout + "extra\n", "")
        with self.assertRaisesRegex(gate.CompatibilityError, "unapproved"):
            gate.classify_process_result(
                case, before, unexpected, baseline, candidate, changes, []
            )

    def test_process_approval_requires_exact_before_and_after(self) -> None:
        baseline = {"syswarden": record("syswarden")}
        candidate = {"syswarden": record("syswarden")}
        case = gate.ProcessCase("root", "root", "syswarden", ())
        before = gate.ProcessResult(0, "old\n", "")
        after = gate.ProcessResult(0, "new\n", "")
        approval = [
            {
                "case": "root",
                "stream": "stdout",
                "reason": "Replace unsupported wording.",
                "before": "old\n",
                "after": "new\n",
            }
        ]
        classification = gate.classify_process_result(
            case, before, after, baseline, candidate, [], approval
        )
        self.assertEqual(
            classification["streams"]["stdout"], "exact-process-approval"
        )
        with self.assertRaisesRegex(gate.CompatibilityError, "values do not match"):
            gate.classify_process_result(
                case,
                before,
                after,
                baseline,
                candidate,
                [],
                [{**approval[0], "after": "unexpected\n"}],
            )

    def test_exact_process_approval_precedes_flag_canonicalization(self) -> None:
        baseline = {
            "syswarden whitelist": record(
                "syswarden whitelist",
                flags=[{"name": "help", "usage": "help"}],
            )
        }
        candidate = {
            "syswarden whitelist": record(
                "syswarden whitelist",
                flags=[
                    {"name": "help", "usage": "help"},
                    {"name": "port", "usage": "service port"},
                ],
            )
        }
        case = gate.ProcessCase(
            "help:syswarden whitelist",
            "help",
            "syswarden whitelist",
            ("whitelist", "--help"),
        )
        before = gate.ProcessResult(0, "old help\n", "")
        after = gate.ProcessResult(0, "new help with --port\n", "")
        approval = [
            {
                "case": case.case_id,
                "stream": "stdout",
                "reason": "Approve the exact flag transition.",
                "before": before.stdout,
                "after": after.stdout,
            }
        ]
        classification = gate.classify_process_result(
            case,
            before,
            after,
            baseline,
            candidate,
            [
                {
                    "path": case.path,
                    "field": "flags",
                    "reason": "Add the service-scoped flag.",
                    "before": baseline[case.path]["flags"],
                    "after": candidate[case.path]["flags"],
                }
            ],
            approval,
        )
        self.assertEqual(
            classification["streams"]["stdout"], "exact-process-approval"
        )

    def test_stale_process_approval_is_rejected(self) -> None:
        case = gate.ProcessCase("root", "root", "syswarden", ())
        same = gate.ProcessResult(0, "same\n", "")
        with self.assertRaisesRegex(gate.CompatibilityError, "stale"):
            gate.validate_process_approval_inventory(
                [case],
                {"root": (same, same)},
                [
                    {
                        "case": "root",
                        "stream": "stdout",
                        "reason": "stale",
                        "before": "old\n",
                        "after": "new\n",
                    }
                ],
            )

    def test_snapshot_validation_is_fail_closed(self) -> None:
        valid = record("syswarden")
        self.assertEqual(gate.validate_snapshot([valid], "fixture"), [valid])
        with self.assertRaisesRegex(gate.CompatibilityError, "duplicate"):
            gate.validate_snapshot([valid, valid], "fixture")
        invalid = {**valid, "arg_outcomes": {"0": "ok"}}
        with self.assertRaisesRegex(gate.CompatibilityError, "exactly counts"):
            gate.validate_snapshot([invalid], "fixture")

    def test_archive_extraction_rejects_traversal_and_links(self) -> None:
        for name, member_type in (("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                member = tarfile.TarInfo(name)
                member.type = member_type
                if member_type == tarfile.REGTYPE:
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"x"))
                else:
                    member.linkname = "target"
                    archive.addfile(member)
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "extract"
                with self.assertRaises(gate.CompatibilityError):
                    gate.safe_extract_tar(stream.getvalue(), destination)

    def test_candidate_copy_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "go.mod").write_text("module fixture\n", encoding="utf-8")
            (source / "link").symlink_to("go.mod")
            with self.assertRaisesRegex(gate.CompatibilityError, "symlink"):
                gate.copy_candidate_module(source, root / "copy")

    def test_scoped_state_changes_only_for_gate_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "src/core/syswarden-cli"
            contracts = root / "testdata/contracts"
            scripts = root / "scripts/ci"
            cli.mkdir(parents=True)
            contracts.mkdir(parents=True)
            scripts.mkdir(parents=True)
            (cli / "go.mod").write_text("module fixture\n", encoding="utf-8")
            (contracts / "cli.json").write_text("[]\n", encoding="utf-8")
            (scripts / "documentation_contract.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (scripts / "cli_process_compatibility.py").write_text(
                "# fixture\n", encoding="utf-8"
            )
            first = gate.scoped_repository_state(root)
            (scripts / "unrelated_lab.py").write_text("# parallel\n", encoding="utf-8")
            self.assertEqual(gate.scoped_repository_state(root), first)
            (cli / "go.mod").write_text("module changed\n", encoding="utf-8")
            self.assertNotEqual(gate.scoped_repository_state(root), first)

    def test_report_path_inside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(gate.output_path_is_in_repo(root, root / "report.json"))
            self.assertFalse(
                gate.output_path_is_in_repo(root, root.parent / "outside-report.json")
            )

    def test_process_execution_requires_explicit_acknowledgement(self) -> None:
        with mock.patch.object(gate, "run_gate") as run_gate:
            self.assertEqual(gate.main([]), 1)
        run_gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
