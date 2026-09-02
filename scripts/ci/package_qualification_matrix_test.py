#!/usr/bin/env python3
"""Test the frozen SysWarden AMD64 package qualification matrix contract."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

try:
    from scripts.ci import package_qualification_matrix as matrix
except ModuleNotFoundError:  # Direct execution from scripts/ci.
    import package_qualification_matrix as matrix


class PackageQualificationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.canonical = matrix.load_matrix()

    def document(self) -> dict[str, object]:
        return copy.deepcopy(self.canonical)

    def assert_invalid(self, document: object, message: str) -> None:
        with self.assertRaisesRegex(matrix.QualificationMatrixError, message):
            matrix.validate_document(document)

    def write_payload(self, root: Path, payload: bytes) -> Path:
        path = root / "matrix.json"
        path.write_bytes(payload)
        return path

    def test_repository_matrix_is_the_exact_frozen_contract(self) -> None:
        document = self.canonical
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["target_release"], "v4.04.2")
        self.assertEqual(document["architecture"], matrix.EXPECTED_ARCHITECTURE)
        self.assertEqual(
            tuple(cell["id"] for cell in document["cells"]),
            tuple(contract.identifier for contract in matrix.EXPECTED_CELLS),
        )
        self.assertEqual(
            tuple(cell["image"] for cell in document["cells"]),
            tuple(contract.image for contract in matrix.EXPECTED_CELLS),
        )
        self.assertEqual(
            tuple(tuple(cell["container_scenarios"]) for cell in document["cells"]),
            tuple(contract.container_scenarios for contract in matrix.EXPECTED_CELLS),
        )
        self.assertEqual(
            tuple(tuple(cell["required_checks"]) for cell in document["cells"]),
            tuple(contract.required_checks for contract in matrix.EXPECTED_CELLS),
        )
        self.assertEqual(
            tuple(
                (cell["real_host"]["mode"], cell["real_host"]["reboot_count"])
                for cell in document["cells"]
            ),
            tuple(
                (contract.real_host_mode, contract.reboot_count)
                for contract in matrix.EXPECTED_CELLS
            ),
        )

    def test_cli_checks_repository_matrix_by_default_and_by_explicit_path(self) -> None:
        for arguments in (
            (),
            ("--check", str(matrix.DEFAULT_MATRIX)),
            ("--expected-target-release", "v4.04.2"),
        ):
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = matrix.main(arguments)
                self.assertEqual(result, 0, stderr.getvalue())
                self.assertEqual(stderr.getvalue(), "")
                self.assertIn("8 AMD64 cells for v4.04.2", stdout.getvalue())
                self.assertRegex(stdout.getvalue(), r"sha256=[0-9a-f]{64}\n$")

    def test_cli_rejects_a_target_release_mismatch(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = matrix.main(("--expected-target-release", "v4.04.0"))
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("target_release", stderr.getvalue())

    def test_snapshot_binds_validated_document_to_exact_file_sha256(self) -> None:
        document, digest = matrix.load_matrix_snapshot()
        expected = hashlib.sha256(matrix.DEFAULT_MATRIX.read_bytes()).hexdigest()
        self.assertEqual(document, self.canonical)
        self.assertEqual(matrix.load_matrix(), document)
        self.assertEqual(digest, expected)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_top_level_schema_is_closed(self) -> None:
        missing = self.document()
        missing.pop("budgets")
        self.assert_invalid(missing, "keys are not exact")
        unexpected = self.document()
        unexpected["waiver"] = True
        self.assert_invalid(unexpected, "keys are not exact")
        self.assert_invalid([], "matrix must be an object")

    def test_schema_identity_and_target_release_are_exact(self) -> None:
        for field, value, message in (
            ("schema_version", 2, "schema_version"),
            ("schema_version", True, "schema_version"),
            ("schema_version", 1.0, "schema_version"),
            ("schema_version", "1", "schema_version"),
            ("schema_version", None, "schema_version"),
            ("matrix_id", "syswarden-package-qualification/v2", "matrix_id"),
            ("target_release", "v4.04.0", "target_release"),
        ):
            with self.subTest(field=field, value=value):
                changed = self.document()
                changed[field] = value
                self.assert_invalid(changed, message)

    def test_architecture_contract_is_closed_and_amd64_only(self) -> None:
        for key, value in (
            ("oci_platform", "linux/" + "arm64"),
            ("kernel", "aarch" + "64"),
            ("deb", "arm" + "64"),
            ("rpm", "aarch" + "64"),
            ("apk", "arm" + "64"),
        ):
            with self.subTest(key=key):
                changed = self.document()
                changed["architecture"][key] = value
                self.assert_invalid(changed, "retired architecture token")
        changed = self.document()
        changed["architecture"]["extra"] = "amd64"
        self.assert_invalid(changed, "architecture keys are not exact")

    def test_active_arm_tokens_are_rejected_recursively_and_case_insensitively(self) -> None:
        for value in ("arm" + "64", "aarch" + "64", "LiNuX/ARM" + "64"):
            with self.subTest(value=value):
                changed = self.document()
                changed["cells"][0]["required_checks"][0] = value
                self.assert_invalid(changed, "retired architecture token")
        changed = self.document()
        changed["cells"][0]["arm" + "64"] = "disabled"
        self.assert_invalid(changed, "retired architecture token")

    def test_candidate_source_is_same_commit_single_run_and_forbids_local_rebuild(self) -> None:
        mutations = {
            "workflow": "other.yml",
            "successful_run_count": 2,
            "commit_binding": "floating-branch",
            "local_rebuild_allowed": True,
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                changed = self.document()
                changed["package_sources"]["candidate"][key] = value
                self.assert_invalid(changed, "candidate does not match")
        for key, value in (
            ("successful_run_count", True),
            ("local_rebuild_allowed", 0),
        ):
            with self.subTest(key=key, wrong_type=value):
                changed = self.document()
                changed["package_sources"]["candidate"][key] = value
                self.assert_invalid(changed, "candidate does not match")
        changed = self.document()
        changed["package_sources"]["candidate"]["retry"] = True
        self.assert_invalid(changed, "candidate keys are not exact")

    def test_baseline_source_is_exact_public_v4033_identity(self) -> None:
        mutations = {
            "release": "v4.03.2",
            "commit": "0" * 40,
            "release_id": 377680979,
            "release_state": "prerelease",
            "asset_selection": "filename",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                changed = self.document()
                changed["package_sources"]["baseline"][key] = value
                self.assert_invalid(changed, "baseline identity does not match")
        for value in (True, 377680978.0, "377680978", None):
            with self.subTest(release_id=value):
                changed = self.document()
                changed["package_sources"]["baseline"]["release_id"] = value
                self.assert_invalid(changed, "baseline identity does not match")
        changed = self.document()
        changed["package_sources"]["baseline"]["unexpected"] = True
        self.assert_invalid(changed, "baseline keys are not exact")

    def test_baseline_assets_are_exact_ordered_and_strictly_typed(self) -> None:
        assets = self.canonical["package_sources"]["baseline"]["assets"]
        self.assertEqual(
            tuple(
                (
                    asset["name"],
                    asset["id"],
                    asset["size"],
                    asset["architecture"],
                    asset["sha256"],
                )
                for asset in assets
            ),
            tuple(
                (
                    asset.name,
                    asset.identifier,
                    asset.size,
                    asset.architecture,
                    asset.sha256,
                )
                for asset in matrix.EXPECTED_BASELINE_ASSETS
            ),
        )
        missing = self.document()
        missing["package_sources"]["baseline"]["assets"].pop()
        self.assert_invalid(missing, "exactly four entries")
        reordered = self.document()
        reordered["package_sources"]["baseline"]["assets"].reverse()
        self.assert_invalid(reordered, r"assets\[0\] does not match")
        for field, value in (
            ("name", "renamed.deb"),
            ("id", 532015728),
            ("size", 284),
            ("architecture", "x86_64"),
            ("sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                changed = self.document()
                changed["package_sources"]["baseline"]["assets"][0][field] = value
                self.assert_invalid(changed, r"assets\[0\] does not match")
        for field, value in (
            ("id", True),
            ("id", 532015727.0),
            ("id", "532015727"),
            ("id", None),
            ("size", True),
            ("size", 283.0),
            ("size", "283"),
            ("size", None),
        ):
            with self.subTest(field=field, value=value):
                changed = self.document()
                changed["package_sources"]["baseline"]["assets"][0][field] = value
                self.assert_invalid(changed, r"assets\[0\] does not match")
        changed = self.document()
        changed["package_sources"]["baseline"]["assets"][0]["extra"] = 1
        self.assert_invalid(changed, r"assets\[0\] keys are not exact")

    def test_artifact_inventory_is_exact_ordered_amd64_inventory(self) -> None:
        for inventory in (
            list(matrix.EXPECTED_ARTIFACT_INVENTORY[:-1]),
            list(reversed(matrix.EXPECTED_ARTIFACT_INVENTORY)),
            [*matrix.EXPECTED_ARTIFACT_INVENTORY, "extra"],
            ["deb:" + "arm64", *matrix.EXPECTED_ARTIFACT_INVENTORY[1:]],
        ):
            with self.subTest(inventory=inventory):
                changed = self.document()
                changed["package_sources"]["artifact_inventory"] = inventory
                message = (
                    "retired architecture token"
                    if any("arm64" in item for item in inventory)
                    else "frozen order"
                )
                self.assert_invalid(changed, message)

    def test_budgets_are_closed_exact_positive_integers(self) -> None:
        changed = self.document()
        changed["budgets"].pop("updater_install_seconds")
        self.assert_invalid(changed, "budgets keys are not exact")
        changed = self.document()
        changed["budgets"]["extra"] = 1
        self.assert_invalid(changed, "budgets keys are not exact")
        for value in (True, 0, -1, 600.0, 601):
            with self.subTest(value=value):
                changed = self.document()
                changed["budgets"]["lifecycle_scenario_seconds"] = value
                self.assert_invalid(changed, "frozen positive integer 600")
        changed = self.document()
        changed["budgets"]["kernel_lab"]["memory_mib"] = 1024
        self.assert_invalid(changed, "frozen positive integer 512")
        changed = self.document()
        changed["budgets"]["kernel_lab"]["unknown"] = 1
        self.assert_invalid(changed, "kernel_lab keys are not exact")

    def test_required_evidence_is_dynamic_exact_and_ordered(self) -> None:
        for evidence in (
            list(matrix.EXPECTED_EVIDENCE[:-1]),
            list(reversed(matrix.EXPECTED_EVIDENCE)),
            [*matrix.EXPECTED_EVIDENCE, "operator-waiver"],
        ):
            with self.subTest(evidence=evidence):
                changed = self.document()
                changed["required_evidence"] = evidence
                self.assert_invalid(changed, "required_evidence does not match")
        flattened = json.dumps(self.canonical).casefold()
        self.assertNotIn("node01", flattened)
        self.assertNotIn("node02", flattened)
        self.assertNotIn("node03", flattened)
        self.assertNotIn("node04", flattened)

    def test_cell_set_and_order_are_exact(self) -> None:
        missing = self.document()
        missing["cells"].pop()
        self.assert_invalid(missing, "exactly 8 entries")
        extra = self.document()
        extra["cells"].append(copy.deepcopy(extra["cells"][-1]))
        self.assert_invalid(extra, "exactly 8 entries")
        reordered = self.document()
        reordered["cells"][0], reordered["cells"][1] = (
            reordered["cells"][1],
            reordered["cells"][0],
        )
        self.assert_invalid(reordered, "must equal the frozen value")

    def test_cell_schema_and_identity_are_closed(self) -> None:
        changed = self.document()
        changed["cells"][0].pop("family")
        self.assert_invalid(changed, r"cells\[0\] keys are not exact")
        changed = self.document()
        changed["cells"][0]["waiver"] = False
        self.assert_invalid(changed, r"cells\[0\] keys are not exact")
        for field, value in (
            ("id", "DEB-OTHER"),
            ("distribution", "other"),
            ("version", "latest"),
            ("family", "rpm"),
        ):
            with self.subTest(field=field):
                changed = self.document()
                changed["cells"][0][field] = value
                self.assert_invalid(changed, f"cells\\[0\\].{field}")

    def test_oci_images_require_exact_official_tag_and_digest(self) -> None:
        original = self.canonical["cells"][0]["image"]
        digest = original.rsplit("@sha256:", 1)[1]
        mutations = (
            original.split("@", 1)[0],
            original.replace("docker.io/library/debian", "example.invalid/debian"),
            original.replace(":13-slim@", ":latest@"),
            original.replace(digest, digest.upper()),
            original[:-1] + ("0" if original[-1] != "0" else "1"),
            original.replace("@sha256:", "@sha512:"),
        )
        for image in mutations:
            with self.subTest(image=image):
                changed = self.document()
                changed["cells"][0]["image"] = image
                self.assert_invalid(
                    changed,
                    "tag-and-sha256|official repository|readable tag|OCI digest",
                )

    def test_container_scenarios_are_exact_and_ordered_for_every_cell(self) -> None:
        for index, contract in enumerate(matrix.EXPECTED_CELLS):
            for scenarios in (
                list(contract.container_scenarios[:-1]),
                list(reversed(contract.container_scenarios)),
                [*contract.container_scenarios, "waived"],
            ):
                with self.subTest(cell=contract.identifier, scenarios=scenarios):
                    changed = self.document()
                    changed["cells"][index]["container_scenarios"] = scenarios
                    self.assert_invalid(changed, "container_scenarios does not match")

    def test_required_checks_are_exact_and_never_encode_reboots(self) -> None:
        for index, contract in enumerate(matrix.EXPECTED_CELLS):
            for checks in (
                list(contract.required_checks[:-1]),
                list(reversed(contract.required_checks)),
                [*contract.required_checks, "waived"],
            ):
                with self.subTest(cell=contract.identifier, checks=checks):
                    changed = self.document()
                    changed["cells"][index]["required_checks"] = checks
                    self.assert_invalid(changed, "required_checks does not match")
            self.assertFalse(
                any("reboot" in check for check in contract.required_checks),
                contract.identifier,
            )

    def test_real_host_modes_and_reboot_counts_are_closed_and_exact(self) -> None:
        expected = (
            ("required", 2),
            ("none", 0),
            ("required", 2),
            ("conditional", 1),
            ("none", 0),
            ("required", 2),
            ("none", 0),
            ("required", 2),
        )
        self.assertEqual(
            tuple(
                (cell["real_host"]["mode"], cell["real_host"]["reboot_count"])
                for cell in self.canonical["cells"]
            ),
            expected,
        )
        for mode, count in (
            ("none", 1),
            ("conditional", 0),
            ("conditional", 2),
            ("required", 0),
            ("required", 1),
        ):
            with self.subTest(mode=mode, count=count):
                changed = self.document()
                changed["cells"][0]["real_host"] = {
                    "mode": mode,
                    "reboot_count": count,
                }
                self.assert_invalid(changed, "invalid combination|frozen obligation")
        for value in (True, 2.0, "2", None, -1):
            with self.subTest(reboot_count=value):
                changed = self.document()
                changed["cells"][0]["real_host"]["reboot_count"] = value
                self.assert_invalid(changed, "non-negative integer")
        changed = self.document()
        changed["cells"][0]["real_host"]["mode"] = "optional"
        self.assert_invalid(changed, "mode is unsupported")
        changed = self.document()
        changed["cells"][0]["real_host"]["identity"] = "host"
        self.assert_invalid(changed, "real_host keys are not exact")

    def test_duplicate_keys_non_finite_values_and_trailing_json_are_rejected(self) -> None:
        payloads = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
            b'{}\n{}\n',
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as raw:
                path = self.write_payload(Path(raw), payload)
                with self.assertRaises(matrix.QualificationMatrixError):
                    matrix.load_matrix(path)

    def test_non_utf8_empty_and_oversized_files_are_rejected(self) -> None:
        payloads = (
            b"\xff",
            b"",
            b"{" + b" " * matrix.MAX_MATRIX_BYTES + b"}",
        )
        for payload in payloads:
            with self.subTest(size=len(payload)), tempfile.TemporaryDirectory() as raw:
                path = self.write_payload(Path(raw), payload)
                with self.assertRaises(matrix.QualificationMatrixError):
                    matrix.load_matrix(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_symlink_matrix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.json"
            target.write_text(json.dumps(self.canonical), encoding="utf-8")
            link = root / "matrix.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                matrix.QualificationMatrixError, "non-symlink"
            ):
                matrix.load_matrix(link)

    def test_cli_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            invalid = Path(raw) / "invalid.json"
            invalid.write_text("{}\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = matrix.main(("--check", str(invalid)))
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertTrue(stderr.getvalue().startswith("ERROR: "))


if __name__ == "__main__":
    unittest.main()
