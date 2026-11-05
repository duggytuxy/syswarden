"""Adversarial report binding tests; synthetic bytes are not native packages."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.ci import generated_package_header_gate as gate


def events(release: str = "v5.00.0", payload: bytes = b"synthetic report-binding fixture") -> list[dict]:
    def event(action: str, test: str | None = None, output: str | None = None) -> dict:
        result = {"Package": gate.PACKAGE, "Action": action}
        if test is not None:
            result["Test"] = test
        if output is not None:
            result["Output"] = output
        return result
    result = [event("start"), event("run", gate.TEST)]
    for name, (package, family, _) in gate.expected_cases(release).items():
        result.extend([event("run", name), event("output", name, f"    fixture_test.go:1: verified generated header: package={package} format={family} release={release} sha256={hashlib.sha256(payload).hexdigest()}\n"), event("pass", name)])
    return result + [event("pass", gate.TEST), event("pass")]


def wire(rows: list[dict]) -> bytes:
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class GeneratedHeaderGateTests(unittest.TestCase):
    def test_exact_v4_and_v5_inventories(self) -> None:
        for release, count in (("v4.10.4", 3), ("v5.00.0", 6), ("v5.12.2147483647", 6)):
            with self.subTest(release=release):
                self.assertEqual(len(gate.validate_events(wire(events(release)), release)), count)

    def test_release_refusal(self) -> None:
        for release in ("5.00.0", "v5.0.0", "v5.00.01", "v6.00.0", "v5.00.2147483648", "v5.00.0\n", None):
            with self.subTest(release=release), self.assertRaises(ValueError):
                gate.expected_cases(release)

    def test_missing_duplicated_or_failed_events_refused(self) -> None:
        original = events()
        for index in range(len(original)):
            for mode in ("remove", "duplicate", "failure", "skip"):
                with self.subTest(index=index, mode=mode):
                    rows = copy.deepcopy(original)
                    if mode == "remove": rows.pop(index)
                    elif mode == "duplicate": rows.insert(index, copy.deepcopy(rows[index]))
                    else: rows[index]["Action"] = "fail" if mode == "failure" else "skip"
                    with self.assertRaises(ValueError): gate.validate_events(wire(rows), "v5.00.0")

    def test_identity_record_changes_refused(self) -> None:
        changes = {"name": ("package=syswarden ", "package=syswarden-base "), "format": ("format=deb", "format=rpm"), "version": ("release=v5.00.0", "release=v5.00.1"), "hash": ("sha256=", "sha256=x"), "suffix": ("\n", " trailing\n")}
        for name, (before, after) in changes.items():
            with self.subTest(change=name):
                rows = events(); rows[3]["Output"] = rows[3]["Output"].replace(before, after)
                with self.assertRaises(ValueError): gate.validate_events(wire(rows), "v5.00.0")

    def test_foreign_or_misplaced_output_refused(self) -> None:
        for field, value in (("Package", "foreign"), ("Test", "TestOther"), ("Test", gate.TEST), ("Output", None), ("Action", "build-fail")):
            with self.subTest(field=field, value=value):
                rows = events(); rows[3][field] = value
                with self.assertRaises(ValueError): gate.validate_events(wire(rows), "v5.00.0")

    def test_empty_partial_malformed_or_excessive_report_refused(self) -> None:
        samples = (b"", b"{}", wire(events())[:-1], b"[]\n", b"null\n", b'{"Action":"start","Action":"pass"}\n', b"{}\n" * (gate.MAX_REPORT_BYTES // 3 + 1), b" " * 65537 + b"\n")
        for sample in samples:
            with self.subTest(size=len(sample)), self.assertRaises((ValueError, gate.files.SignatureGateError)):
                gate.validate_events(sample, "v5.00.0")

    def test_no_tests_and_skipped_optional_test_are_not_success(self) -> None:
        for rows in ([{"Package": gate.PACKAGE, "Action": "start"}, {"Package": gate.PACKAGE, "Action": "pass"}], [{"Package": gate.PACKAGE, "Action": "start"}, {"Package": gate.PACKAGE, "Action": "skip", "Test": gate.TEST}]):
            with self.assertRaises(ValueError): gate.validate_events(wire(rows), "v5.00.0")

    def fixture(self, root: Path) -> tuple[Path, Path]:
        packages = root / "packages"; packages.mkdir()
        for _, _, name in gate.expected_cases("v5.00.0").values():
            (packages / name).write_bytes(b"synthetic report-binding fixture")
        report = root / "report.jsonl"; report.write_bytes(wire(events()))
        return report, packages

    def test_summary_is_bound_and_never_accepts_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, packages = self.fixture(Path(temporary))
            summary = gate.verify(report, packages, "v5.00.0")
            self.assertEqual(len(summary["artifacts"]), 6)
            for key in ("signature_acceptance", "native_installation_acceptance", "release_acceptance"):
                self.assertIs(summary[key], False)

    def test_missing_changed_linked_or_oversized_artifact_refused(self) -> None:
        for mode in ("missing", "changed", "linked", "oversized"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); report, packages = self.fixture(root)
                target = next(packages.iterdir())
                if mode == "missing": target.unlink()
                elif mode == "changed": target.write_bytes(b"changed")
                elif mode == "linked":
                    original = root / "original"; target.rename(original); target.symlink_to(original)
                else:
                    with target.open("wb") as handle: handle.truncate(gate.files.MAX_PACKAGE_BYTES + 1)
                with self.assertRaises((ValueError, OSError, gate.files.SignatureGateError)):
                    gate.verify(report, packages, "v5.00.0")

    def test_linked_root_and_changed_report_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report, packages = self.fixture(root)
            linked = root / "link"; linked.symlink_to(packages)
            with self.assertRaises(ValueError): gate.verify(report, linked, "v5.00.0")
            original = gate.files.regular_bytes
            reads = 0
            def changed(path: Path, maximum: int, label: str) -> bytes:
                nonlocal reads
                raw = original(path, maximum, label)
                if path == report:
                    reads += 1
                    if reads == 2: return raw + b"changed"
                return raw
            with mock.patch.object(gate.files, "regular_bytes", side_effect=changed), self.assertRaises(ValueError):
                gate.verify(report, packages, "v5.00.0")

    def test_workflow_requires_the_actual_reader_before_upload(self) -> None:
        source = (Path(__file__).resolve().parents[2] / ".github/workflows/package.yml").read_text()
        title = "      - name: Verify Generated Package Identities with Updater Parser"
        step = source.split(title, 1)[1].split("      - name:", 1)[0]
        for expected in ('SYSWARDEN_GENERATED_PACKAGE_DIRECTORY="${PACKAGE_ASSETS}"', 'SYSWARDEN_GENERATED_PACKAGE_VERSION="${RELEASE_TAG}"', "-run '^TestGeneratedNativePackageIdentity$'", 'generated_package_header_gate.py', '--report "${PACKAGE_WORKSPACE}/generated-header-tests.jsonl"', '--packages "${PACKAGE_ASSETS}" --release "${RELEASE_TAG}"', '-buildvcs=false -p=2 -count=1 -timeout=3m -json ./pkg/system'):
            self.assertIn(expected, step)
        self.assertNotIn("continue-on-error", step)
        self.assertLess(source.index("      - name: Validate Exact Package Artifact"), source.index(title))
        self.assertLess(source.index(title), source.index("      - name: Upload Package Artifacts"))
        self.assertIn("scripts/ci/generated_package_header_gate_test.py", source)


if __name__ == "__main__":
    unittest.main()
