#!/usr/bin/env python3
"""Tests for the exact signed FreeBSD updater VM probe."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import freebsd_updater_vm_probe as subject
import freebsd_vm_lab as vm_lab


def fixture(path: Path, content: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def passing_evidence() -> dict[str, str]:
    return {
        "MARKER_MATCH": "1",
        "LAB_LOCK_ACQUIRED": "1",
        "INPUT_SHA_MATCH": "1",
        "PREVIOUS_SHA256": hashlib.sha256(b"previous").hexdigest(),
        "CANDIDATE_SHA256": hashlib.sha256(b"candidate").hexdigest(),
        "TEST_BINARY_SHA256": hashlib.sha256(b"ELF").hexdigest(),
        "MANIFEST_SHA256": hashlib.sha256(b"{}\n").hexdigest(),
        "SIGNATURE_SHA256": hashlib.sha256(b"signature\n").hexdigest(),
        "LAB_BASELINE_CLEAN": "1",
        "INITIAL_PACKAGE_ABSENT": "1",
        "PREVIOUS_INSTALL_RC": "0",
        "PREVIOUS_VERSION": "4.02.8",
        "SOURCE_SHA": "b" * 40,
        "UPDATER_RC": "0",
        "UPDATER_RESULT_SHA256": "a" * 64,
        "UPDATER_RESULT_EXACT": "1",
        "UPDATER_RESULT_LINE": f"--- PASS: {subject.TEST_NAME} (1.23s)",
        "CANDIDATE_VERSION": "4.02.12",
        "CORE_ENABLED": "YES",
        "WEB_ENABLED": "YES",
        "CORE_STATUS_RC": "0",
        "WEB_STATUS_RC": "0",
        "CLEANUP_RC": "0",
        "PACKAGE_ABSENT": "1",
        "PF_BASELINE_STATUS": "Disabled",
        "PF_BASELINE_EMPTY": "1",
        "PF_FINAL_STATUS": "Disabled",
        "PF_FINAL_EMPTY": "1",
        "PF_FILTER_MATCH": "1",
        "PF_NAT_MATCH": "1",
        "PF_TABLES_MATCH": "1",
        "PF_SYSWARDEN_ABSENT": "1",
        "PF_METADATA_ABSENT": "1",
        "RUNTIME_PATHS_ABSENT": "1",
        "SERVICE_PROCESSES_ABSENT": "1",
        "PID_FILES_ABSENT": "1",
        "WEB_SOCKET_MATCH": "1",
        "SYSRC_FLAGS_ABSENT": "1",
        "SYSRC_INVENTORY_MATCH": "1",
        "MANAGED_CRON_ABSENT": "1",
        "RSYSLOG_FILES_ABSENT": "1",
        "OPERATOR_STATE_PRESERVED": "1",
        "HARNESS_RESET_COMPLETE": "1",
        "LAB_LOCK_RELEASED": "1",
        "REMOTE_WORKSPACE_REMOVED": "1",
    }


class FreeBSDUpdaterVMProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate_path = fixture(self.root / "syswarden-4.02.12.txz", b"candidate")
        self.previous_path = fixture(self.root / "syswarden-4.02.8.txz", b"previous")
        self.manifest = fixture(self.root / "syswarden-update-manifest-v1.json", b"{}\n")
        self.signature = fixture(self.root / "syswarden-update-manifest-v1.json.sig", b"signature\n")
        self.test_binary = fixture(self.root / subject.TEST_BINARY_NAME, b"ELF", 0o700)
        self.candidate = vm_lab.PackageArtifact(
            self.candidate_path, "4.02.12", hashlib.sha256(b"candidate").hexdigest()
        )
        self.previous = vm_lab.PackageArtifact(
            self.previous_path, "4.02.8", hashlib.sha256(b"previous").hexdigest()
        )
        self.release_sha = "b" * 40
        self.digests = {
            "candidate": self.candidate.sha256,
            "previous": self.previous.sha256,
            "manifest": hashlib.sha256(b"{}\n").hexdigest(),
            "signature": hashlib.sha256(b"signature\n").hexdigest(),
            "test_binary": hashlib.sha256(b"ELF").hexdigest(),
        }

    def report(self, evidence: dict[str, str] | None = None) -> dict[str, object]:
        return subject.build_report(
            evidence or passing_evidence(),
            self.candidate,
            self.previous,
            self.manifest,
            self.signature,
            self.test_binary,
            self.digests,
            self.release_sha,
        )

    def test_accepts_exact_transition_and_inputs(self) -> None:
        report = self.report()
        self.assertTrue(report["release_ready"])
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(report["inputs"]["candidate"]["version"], "4.02.12")
        self.assertEqual(report["inputs"]["previous"]["version"], "4.02.8")

    def test_each_material_observation_is_fail_closed(self) -> None:
        mutations = {
            "MARKER_MATCH": "0",
            "LAB_LOCK_ACQUIRED": "0",
            "LAB_LOCK_RELEASED": "0",
            "REMOTE_WORKSPACE_REMOVED": "0",
            "INPUT_SHA_MATCH": "0",
            "PREVIOUS_SHA256": "0" * 64,
            "CANDIDATE_SHA256": "0" * 64,
            "TEST_BINARY_SHA256": "0" * 64,
            "MANIFEST_SHA256": "0" * 64,
            "SIGNATURE_SHA256": "0" * 64,
            "LAB_BASELINE_CLEAN": "0",
            "INITIAL_PACKAGE_ABSENT": "0",
            "PREVIOUS_INSTALL_RC": "1",
            "PREVIOUS_VERSION": "4.02.9",
            "SOURCE_SHA": "c" * 40,
            "UPDATER_RC": "1",
            "UPDATER_RESULT_SHA256": "invalid",
            "UPDATER_RESULT_EXACT": "0",
            "UPDATER_RESULT_LINE": "PASS",
            "CANDIDATE_VERSION": "4.02.9",
            "CORE_ENABLED": "NO",
            "WEB_ENABLED": "NO",
            "CORE_STATUS_RC": "1",
            "WEB_STATUS_RC": "1",
            "CLEANUP_RC": "1",
            "PACKAGE_ABSENT": "0",
            "PF_BASELINE_STATUS": "invalid",
            "PF_BASELINE_EMPTY": "0",
            "PF_FINAL_STATUS": "Enabled",
            "PF_FINAL_EMPTY": "0",
            "PF_FILTER_MATCH": "0",
            "PF_NAT_MATCH": "0",
            "PF_TABLES_MATCH": "0",
            "PF_SYSWARDEN_ABSENT": "0",
            "PF_METADATA_ABSENT": "0",
            "RUNTIME_PATHS_ABSENT": "0",
            "SERVICE_PROCESSES_ABSENT": "0",
            "PID_FILES_ABSENT": "0",
            "WEB_SOCKET_MATCH": "0",
            "SYSRC_FLAGS_ABSENT": "0",
            "SYSRC_INVENTORY_MATCH": "0",
            "MANAGED_CRON_ABSENT": "0",
            "RSYSLOG_FILES_ABSENT": "0",
            "OPERATOR_STATE_PRESERVED": "0",
            "HARNESS_RESET_COMPLETE": "0",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                evidence = passing_evidence()
                evidence[key] = value
                report = self.report(evidence)
                self.assertFalse(report["release_ready"])
                self.assertEqual(report["blocker_ids"], ["SW-UPD-FBSD-001"])

    def test_rejects_unsafe_or_oversized_inputs(self) -> None:
        symlink = self.root / "manifest-link"
        symlink.symlink_to(self.manifest)
        with self.assertRaises(vm_lab.FreeBSDVMLabError):
            subject.require_probe_file(symlink, "manifest", 1024)
        oversized = fixture(self.root / "oversized", b"12345")
        with self.assertRaises(subject.FreeBSDUpdaterProbeError):
            subject.require_probe_file(oversized, "manifest", 4)
        non_executable = fixture(self.root / "not-executable", b"ELF", 0o600)
        with self.assertRaises(subject.FreeBSDUpdaterProbeError):
            subject.validate_test_binary(non_executable, self.release_sha)
        fake_executable = fixture(self.root / "fake-executable", b"not an ELF", 0o700)
        with self.assertRaises(subject.FreeBSDUpdaterProbeError):
            subject.validate_test_binary(fake_executable, self.release_sha)
        with self.assertRaises(subject.FreeBSDUpdaterProbeError):
            subject.validate_release_sha("B" * 40)

    def test_go_build_metadata_is_exact(self) -> None:
        valid = "\n".join(
            (
                "binary: go1.26.6",
                "\tpath\tsyswarden-cli/pkg/system.test",
                "\tmod\tsyswarden-cli\t(devel)\t",
                "\tbuild\t-buildmode=exe",
                "\tbuild\t-compiler=gc",
                "\tbuild\t-ldflags=-X=syswarden-cli/pkg/system."
                f"freeBSDUpdaterQualificationSourceSHA={self.release_sha}",
                "\tbuild\tCGO_ENABLED=0",
                "\tbuild\tGOARCH=amd64",
                "\tbuild\tGOOS=freebsd",
                "\tbuild\tGOAMD64=v1",
                "\tbuild\tvcs=git",
                "\tbuild\tvcs.modified=false",
                f"\tbuild\tvcs.revision={self.release_sha}",
                "\tbuild\tvcs.time=2026-08-15T09:45:52Z",
            )
        )
        subject.validate_go_build_metadata(valid, self.release_sha)
        for mutation in (
            valid.replace("go1.26.6", "go1.26.5"),
            valid.replace("GOOS=freebsd", "GOOS=linux"),
            valid.replace("GOARCH=amd64", "GOARCH=arm64"),
            valid.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            valid.replace("GOAMD64=v1", "GOAMD64=v3"),
            valid.replace("syswarden-cli/pkg/system.test", "attacker.test"),
            valid.replace("\tmod\tsyswarden-cli\t(devel)\t", "\tmod\tsyswarden-cli\tv1.0.0\t"),
            valid.replace("vcs.modified=false", "vcs.modified=true"),
            valid.replace("vcs.time=2026-08-15T09:45:52Z", "vcs.time=2026-99-15T09:45:52Z"),
            valid.replace(self.release_sha, "c" * 40, 1),
            valid + "\n\tbuild\tGOOS=freebsd",
            valid + "\n\tbuild\t-tags=unsafe",
            valid + "\n\tdep\tattacker.example\tv1.0.0",
        ):
            with self.subTest(mutation=mutation[-40:]):
                with self.assertRaises(subject.FreeBSDUpdaterProbeError):
                    subject.validate_go_build_metadata(mutation, self.release_sha)

    def test_remote_script_binds_real_commands_and_state_order(self) -> None:
        script = subject.REMOTE_PROBE_SCRIPT
        required = (
            'pkg add -f "$sealed/$previous_name"',
            'SYSWARDEN_FREEBSD_UPDATER_MANIFEST="$sealed/$manifest_name"',
            'SYSWARDEN_FREEBSD_UPDATER_SOURCE_SHA="$source_sha"',
            'mkfifo "$work/updater-output.pipe"',
            'test_name="${15}"',
            f'[ "$test_name" != "{subject.TEST_NAME}" ]',
            '-test.run "^${test_name}$"',
            'pkg query \'%v\' syswarden',
            'service syswarden onestatus',
            'service syswardenwebtui onestatus',
            'pkg delete -fy syswarden',
            'lock_path=/var/run/syswarden-lot0-lab.lock',
            'cp -P "$work/$fixture" "$sealed/$fixture"',
            'pfctl -a \'*\' -sr >"$work/pf-filter-before"',
            'pkg query -a \'%n\' >"$work/pkg-names-before"',
            'sysrc -a >"$work/sysrc-before"',
            'cron_root_before="$(capture_cron_root_state)"',
            'operator_config_before="$(capture_operator_file_state',
            'emit PF_FILTER_MATCH',
            "'^/usr/local/syswarden/bin/syswarden-cli web-tui($| )'",
            "'^/opt/syswarden/bin/syswarden-cli web-tui($| )'",
            "emit OPERATOR_STATE_PRESERVED",
            "emit SYSRC_INVENTORY_MATCH",
            "emit HARNESS_RESET_COMPLETE",
        )
        for fragment in required:
            self.assertIn(fragment, script)
        self.assertLess(
            script.index("observed_previous="),
            script.index("SYSWARDEN_FREEBSD_UPDATER_E2E=1"),
        )
        self.assertLess(
            script.index("emit UPDATER_RC"), script.index("emit CANDIDATE_VERSION")
        )
        self.assertLess(
            script.index('cp -P "$work/$fixture"'),
            script.index("observed_previous_sha="),
        )
        self.assertLess(
            script.index("emit OPERATOR_STATE_PRESERVED"),
            script.index("rm -rf \\\n    /usr/local/syswarden"),
        )
        reset_index = script.index("emit HARNESS_RESET_COMPLETE")
        self.assertLess(
            reset_index,
            script.index("package_cleanup_authorized=0", reset_index),
        )
        self.assertNotIn("updater-test.log", script)
        self.assertLess(script.index('case "$remote_nonce"'), script.index("trap cleanup_workspace"))
        self.assertLess(script.index("trap cleanup_workspace"), script.index("marker="))
        self.assertLess(script.index("emit INITIAL_PACKAGE_ABSENT"), script.index("package_cleanup_authorized=1"))
        prepare = subject.REMOTE_ROOT_PREPARE_SCRIPT
        self.assertIn('mkdir "$lock_path"', prepare)
        self.assertIn('chown 0:0 "$work"', prepare)
        self.assertIn('chmod 733 "$work"', prepare)
        self.assertLess(prepare.index('mkdir "$lock_path"'), prepare.index('mkdir "$work"'))

    def test_requires_canonical_transferred_names(self) -> None:
        self.assertEqual(subject.MANIFEST_NAME, self.manifest.name)
        self.assertEqual(subject.SIGNATURE_NAME, self.signature.name)
        self.assertEqual(subject.TEST_BINARY_NAME, self.test_binary.name)

    def test_test_binary_is_validated_and_hashed_from_a_private_snapshot(self) -> None:
        original_bytes = self.test_binary.read_bytes()
        with mock.patch.object(subject, "validate_test_binary", side_effect=lambda path, _sha: path):
            with subject.validated_test_binary_snapshot(self.test_binary, self.release_sha) as result:
                snapshot, snapshot_digest = result
                self.assertNotEqual(snapshot, self.test_binary)
                self.assertEqual(snapshot.name, subject.TEST_BINARY_NAME)
                self.assertEqual(snapshot_digest, hashlib.sha256(original_bytes).hexdigest())
                self.test_binary.write_bytes(b"replacement")
                self.assertEqual(snapshot.read_bytes(), original_bytes)

    def test_evidence_parser_requires_exact_inventory(self) -> None:
        lines = []
        for key, value in passing_evidence().items():
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            lines.append(f"SWL0\t{key}\t{encoded}")
        parsed = vm_lab.parse_markers("\n".join(lines) + "\n", subject.EVIDENCE_KEYS)
        self.assertEqual(parsed, passing_evidence())
        with self.assertRaises(vm_lab.FreeBSDVMLabError):
            vm_lab.parse_markers("\n".join(lines[:-1]) + "\n", subject.EVIDENCE_KEYS)

    def test_sealed_report_recomputes_exactly(self) -> None:
        report_path = self.root / "freebsd-updater-raw.json"
        report_path.write_text(json.dumps(self.report(), sort_keys=True) + "\n", encoding="utf-8")
        report_path.chmod(0o600)
        arguments = SimpleNamespace(
            release_sha=self.release_sha,
            packages_dir=self.root / "candidate",
            previous_packages_dir=self.root / "previous",
            manifest=self.manifest,
            signature=self.signature,
            test_binary=self.test_binary,
            report=report_path,
        )
        with mock.patch.object(
            subject.vm_lab,
            "discover_package_pair",
            return_value=(self.candidate, self.previous),
        ), mock.patch.object(
            subject,
            "validated_test_binary_snapshot",
        ) as snapshot:
            snapshot.return_value.__enter__.return_value = (
                self.test_binary,
                self.digests["test_binary"],
            )
            subject.verify_probe_report(arguments)

            invalid = self.report()
            invalid["release_ready"] = 1
            report_path.write_text(json.dumps(invalid, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(subject.FreeBSDUpdaterProbeError):
                subject.verify_probe_report(arguments)

        report_path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        with self.assertRaises(subject.FreeBSDUpdaterProbeError):
            subject.read_probe_report(report_path)


if __name__ == "__main__":
    unittest.main()
