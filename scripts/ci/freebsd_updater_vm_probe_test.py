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


TOKEN = "0" * 32


def marker_output(values: dict[str, str]) -> str:
    return "".join(
        f"SWL0\t{key}\t{base64.b64encode(value.encode('utf-8')).decode('ascii')}\n"
        for key, value in values.items()
    )


def carries_script(input_text: str | None, script: str) -> bool:
    return bool(input_text and input_text.endswith(script + "\n"))


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
        "CANDIDATE_VERSION": "4.02.15",
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


class UpdaterSequencedRunner(vm_lab.CommandRunner):
    def __init__(
        self,
        cleanup_outcomes: list[int | BaseException],
        *,
        remote_returncode: int = 0,
        remote_evidence: dict[str, str] | None = None,
        remote_stdout: str | None = None,
        copy_returncode: int = 0,
    ) -> None:
        self.cleanup_outcomes = list(cleanup_outcomes)
        self.remote_returncode = remote_returncode
        self.remote_evidence = remote_evidence
        self.remote_stdout = remote_stdout
        self.copy_returncode = copy_returncode
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def run(
        self,
        args: tuple[str, ...],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> vm_lab.CommandResult:
        del timeout
        command = tuple(args)
        self.calls.append((command, input_text))
        if carries_script(input_text, vm_lab.PROBE_SCRIPT):
            return vm_lab.CommandResult(
                command,
                0,
                marker_output(
                    {
                        "MARKER_MATCH": "1",
                        "MARKER_SAFE": "1",
                        "OS_NAME": "FreeBSD",
                        "OS_RELEASE": "14.4-RELEASE-p2",
                        "MACHINE": "amd64",
                        "SUDO_READY": "1",
                        "BASE64_READY": "1",
                    }
                ),
                "",
            )
        if carries_script(input_text, subject.REMOTE_PROBE_SCRIPT):
            stdout = self.remote_stdout
            if stdout is None:
                stdout = marker_output(
                    passing_evidence()
                    if self.remote_evidence is None
                    else self.remote_evidence
                )
            return vm_lab.CommandResult(
                command,
                self.remote_returncode,
                stdout,
                f"untrusted updater stderr {TOKEN}",
            )
        if carries_script(input_text, subject.REMOTE_ROOT_CLEANUP_SCRIPT):
            if not self.cleanup_outcomes:
                raise AssertionError("unexpected updater cleanup attempt")
            outcome = self.cleanup_outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return vm_lab.CommandResult(
                command,
                outcome,
                f"untrusted cleanup stdout {TOKEN}",
                f"untrusted cleanup stderr {TOKEN}",
            )
        if command[0] == "scp" and self.copy_returncode != 0:
            return vm_lab.CommandResult(
                command,
                self.copy_returncode,
                f"untrusted copy stdout {TOKEN}",
                f"untrusted copy stderr {TOKEN}",
            )
        return vm_lab.CommandResult(command, 0, "", "")


class FreeBSDUpdaterVMProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate_path = fixture(self.root / "syswarden-4.02.15.txz", b"candidate")
        self.previous_path = fixture(self.root / "syswarden-4.02.8.txz", b"previous")
        self.manifest = fixture(self.root / "syswarden-update-manifest-v1.json", b"{}\n")
        self.signature = fixture(self.root / "syswarden-update-manifest-v1.json.sig", b"signature\n")
        self.test_binary = fixture(self.root / subject.TEST_BINARY_NAME, b"ELF", 0o700)
        self.marker_token_file = fixture(
            self.root / "marker-token", (TOKEN + "\n").encode("ascii"), 0o600
        )
        self.candidate = vm_lab.PackageArtifact(
            self.candidate_path, "4.02.15", hashlib.sha256(b"candidate").hexdigest()
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

    def run_snapshot(
        self, runner: UpdaterSequencedRunner
    ) -> dict[str, object]:
        args = SimpleNamespace(
            ssh="ssh",
            scp="scp",
            ssh_host="127.0.0.1",
            ssh_port=2222,
            ssh_user="syswarden",
            identity_file=self.root / "id_ed25519",
            known_hosts_file=self.root / "known_hosts",
            vm_marker_token=None,
            vm_marker_token_file=self.marker_token_file,
            command_timeout=600,
            release_sha=self.release_sha,
            packages_dir=self.root / "candidate",
            previous_packages_dir=self.root / "previous",
            manifest=self.manifest,
            signature=self.signature,
            test_binary=self.test_binary,
        )
        with (
            mock.patch.object(
                vm_lab,
                "validate_transport_program",
                side_effect=lambda program, _label: program,
            ),
            mock.patch.object(
                vm_lab,
                "validate_transport_inputs",
                return_value=(
                    "127.0.0.1",
                    args.identity_file,
                    args.known_hosts_file,
                ),
            ),
            mock.patch.object(
                vm_lab,
                "discover_package_pair",
                return_value=(self.candidate, self.previous),
            ),
            mock.patch.object(
                subject,
                "validate_test_binary",
                return_value=self.test_binary,
            ),
            mock.patch.object(vm_lab.time, "sleep"),
        ):
            return subject._run_probe_from_snapshot(
                args,
                self.digests["test_binary"],
                runner=runner,
            )

    def test_accepts_exact_transition_and_inputs(self) -> None:
        report = self.report()
        self.assertTrue(report["release_ready"])
        self.assertEqual(report["blocker_ids"], [])
        self.assertEqual(report["inputs"]["candidate"]["version"], "4.02.15")
        self.assertEqual(report["inputs"]["previous"]["version"], "4.02.8")

    def test_updater_in_band_cleanup_proof_skips_external_cleanup(self) -> None:
        runner = UpdaterSequencedRunner([])
        report = self.run_snapshot(runner)
        self.assertTrue(report["release_ready"])
        cleanup_calls = [
            call
            for call in runner.calls
            if carries_script(call[1], subject.REMOTE_ROOT_CLEANUP_SCRIPT)
        ]
        self.assertEqual(cleanup_calls, [])

    def test_updater_invalid_cleanup_markers_clean_and_fail(self) -> None:
        for marker_mode in (
            "missing_workspace",
            "false_workspace",
            "false_lock",
        ):
            with self.subTest(marker_mode=marker_mode):
                evidence = passing_evidence()
                if marker_mode == "missing_workspace":
                    evidence.pop("REMOTE_WORKSPACE_REMOVED")
                elif marker_mode == "false_workspace":
                    evidence["REMOTE_WORKSPACE_REMOVED"] = "0"
                else:
                    evidence["LAB_LOCK_RELEASED"] = "0"
                runner = UpdaterSequencedRunner(
                    [vm_lab.FreeBSDVMLabError(f"transport timeout {TOKEN}"), 0],
                    remote_evidence=evidence,
                )
                with self.assertRaises(vm_lab.FreeBSDVMLabError) as raised:
                    self.run_snapshot(runner)
                message = str(raised.exception)
                expected = (
                    "markers differ"
                    if marker_mode == "missing_workspace"
                    else "remote cleanup markers did not prove"
                )
                self.assertIn(expected, message)
                self.assertNotIn(TOKEN, message)
                self.assertEqual(
                    sum(
                        carries_script(
                            input_text, subject.REMOTE_ROOT_CLEANUP_SCRIPT
                        )
                        for _, input_text in runner.calls
                    ),
                    2,
                )

    def test_updater_malformed_output_cleans_and_redacts(self) -> None:
        runner = UpdaterSequencedRunner(
            [0],
            remote_stdout=f"malformed updater output {TOKEN}\n",
        )
        with self.assertRaisesRegex(
            vm_lab.FreeBSDVMLabError,
            "invalid VM evidence line",
        ) as raised:
            self.run_snapshot(runner)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(
            sum(
                carries_script(input_text, subject.REMOTE_ROOT_CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            1,
        )

    def test_updater_cleanup_exhaustion_is_redacted_and_fail_closed(self) -> None:
        evidence = passing_evidence()
        evidence["REMOTE_WORKSPACE_REMOVED"] = "0"
        runner = UpdaterSequencedRunner(
            [255, 255, 255], remote_evidence=evidence
        )
        with self.assertRaisesRegex(
            vm_lab.FreeBSDVMLabError,
            "not proven after 3 attempts",
        ) as raised:
            self.run_snapshot(runner)
        message = str(raised.exception)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("untrusted cleanup", message)
        self.assertEqual(message.count("exit_255"), 3)
        self.assertNotIn(
            TOKEN,
            json.dumps(subject.error_report(raised.exception), sort_keys=True),
        )

    def test_updater_primary_transport_error_is_preserved_and_redacted(self) -> None:
        runner = UpdaterSequencedRunner([255, 0], remote_returncode=9)
        with self.assertRaisesRegex(
            vm_lab.FreeBSDVMLabError,
            "signed-updater transition probe failed with exit code 9",
        ) as raised:
            self.run_snapshot(runner)
        message = str(raised.exception)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("untrusted updater", message)
        self.assertNotIn("cleanup", message)
        self.assertEqual(
            sum(
                carries_script(input_text, subject.REMOTE_ROOT_CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            2,
        )

    def test_updater_copy_error_is_preserved_and_cleanup_retries(self) -> None:
        runner = UpdaterSequencedRunner(
            [255, 0],
            copy_returncode=1,
        )
        with self.assertRaisesRegex(
            vm_lab.FreeBSDVMLabError,
            "copy .* failed with exit code 1",
        ) as raised:
            self.run_snapshot(runner)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(
            sum(
                carries_script(input_text, subject.REMOTE_ROOT_CLEANUP_SCRIPT)
                for _, input_text in runner.calls
            ),
            2,
        )

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
            'emit LAB_LOCK_RELEASED "$lock_released"',
            'emit REMOTE_WORKSPACE_REMOVED "$workspace_removed"',
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
        workspace_remove = script.rindex('rm -rf "$work"')
        workspace_marker = script.rindex(
            'emit REMOTE_WORKSPACE_REMOVED "$workspace_removed"'
        )
        self.assertLess(workspace_remove, workspace_marker)

    def test_tmp_sticky_bit_uses_freebsd_high_and_low_mode_fields(self) -> None:
        corrected = (
            '[ "$(stat -f \'%HT|%u|%g|%Mp|%Lp\' /tmp)" '
            "= 'Directory|0|0|1|777' ]"
        )
        truncated = (
            '[ "$(stat -f \'%HT|%u|%g|%Lp\' /tmp)" '
            "= 'Directory|0|0|1777' ]"
        )

        def assert_contract(script: str) -> None:
            self.assertEqual(script.count(corrected), 1)
            self.assertNotIn(truncated, script)

        script = subject.REMOTE_ROOT_PREPARE_SCRIPT
        assert_contract(script)
        with self.assertRaises(AssertionError):
            assert_contract(script.replace(corrected, truncated, 1))

    def test_external_cleanup_is_idempotent_but_rejects_partial_state(self) -> None:
        script = subject.REMOTE_ROOT_CLEANUP_SCRIPT
        already_clean = (
            'if [ "$work_exists:$lock_exists" = "0:0" ]; then\n'
            "    exit 0\n"
            "fi"
        )
        partial_rejection = (
            'if [ "$work_exists:$lock_exists" != "1:1" ]; then\n'
            "    exit 92\n"
            "fi"
        )
        final_proof = (
            '[ ! -e "$work" ] && [ ! -L "$work" ]\n'
            '[ ! -e "$lock_path" ] && [ ! -L "$lock_path" ]'
        )

        def assert_contract(candidate: str) -> None:
            self.assertEqual(candidate.count(already_clean), 1)
            self.assertEqual(candidate.count(partial_rejection), 1)
            self.assertEqual(candidate.count(final_proof), 1)
            self.assertLess(
                candidate.index(already_clean), candidate.index(partial_rejection)
            )
            self.assertLess(
                candidate.index(partial_rejection),
                candidate.index('rm -rf "$work"'),
            )

        assert_contract(script)
        with self.assertRaises(AssertionError):
            assert_contract(script.replace(partial_rejection, ":", 1))

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
