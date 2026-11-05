#!/usr/bin/env python3
"""Small isolated tests for the opt-in prepared standalone removal contract."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alpine_standalone_removal as standalone
import package_lifecycle_lab as lab


def candidate_bytes(mutation="none"):
    elf = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\0"
    payloads = {name: (elf + name.encode() if "/bin/" in name else name.encode())
                for name in standalone.PAYLOAD_MODES}
    cli = "opt/syswarden/bin/syswarden-cli"
    for variable, relative in (("standaloneCoreSHA256", "bin/syswarden-core"),
                               ("standaloneTUISHA256", "bin/syswarden-tui"),
                               ("standaloneSignaturesSHA256", "signatures.json")):
        digest = hashlib.sha256(payloads[f"opt/syswarden/{relative}"]).hexdigest()
        if mutation != "unbound":
            payloads[cli] += f" syswarden-cli/pkg/system.{variable}={digest}".encode()
    if mutation == "modified-companion":
        payloads["opt/syswarden/bin/syswarden-core"] += b"changed"
    if mutation == "arm":
        payloads[cli] = payloads[cli][:18] + b"\xb7\0" + payloads[cli][20:]
    contents = io.BytesIO()
    with tarfile.open(fileobj=contents, mode="w:gz") as archive:
        metadata = b"pkgname = syswarden\npkgver = 5.00.0-r0\narch = x86_64\n"
        if mutation == "normalized-version":
            metadata = metadata.replace(b"5.00.0-r0", b"5.0.0")
        elif mutation == "malformed-version":
            metadata = metadata.replace(b"5.00.0-r0", b"5.000.0")
        entries = [(".PKGINFO", metadata, 0o644), *[(name, data, standalone.PAYLOAD_MODES[name]) for name, data in payloads.items()]]
        if mutation == "duplicate":
            entries.append(entries[1])
        for name, data, mode in entries:
            if mutation == "missing" and name == cli:
                continue
            member = tarfile.TarInfo("./" + name)
            member.mode, member.size = mode, len(data)
            if name == cli and mutation == "mode":
                member.mode = 0o777
            if name == cli and mutation == "owner":
                member.uid = 1000
            if name == cli and mutation == "hardlink":
                member.type, member.linkname, member.size = tarfile.LNKTYPE, "other", 0
            archive.addfile(member, io.BytesIO(data))
        for name, target in standalone.PAYLOAD_LINKS.items():
            member = tarfile.TarInfo(name)
            member.type, member.linkname = tarfile.SYMTYPE, target
            archive.addfile(member)
    return contents.getvalue()


class StandaloneRemovalTests(unittest.TestCase):
    def test_podman_inspect_identity_requires_exact_image_with_optional_algorithm(self):
        expected = "sha256:" + "a" * 64
        image = {"Id": expected, "Architecture": "amd64", "Os": "linux", "Config": {"Cmd": ["/sbin/openrc-init"]}}
        standalone.validate_prepared_image([image], expected)
        standalone.validate_prepared_image([{**image, "Id": expected.removeprefix("sha256:")}], expected)
        for changed in (None, {}, [], [image, image], [{**image, "Id": "b" * 64}],
                        [{**image, "Id": "a" * 12}], [{**image, "Config": None}],
                        [{**image, "Config": {"Cmd": ["/bin/sh"]}}], [{**image, "Os": "other"}]):
            with self.subTest(changed=changed), self.assertRaises(lab.LifecycleLabError):
                standalone.validate_prepared_image(changed, expected)

    def test_payload_requires_exact_identity_bindings_and_architecture(self):
        version, payloads = standalone.inspect_payload(candidate_bytes())
        self.assertEqual(version, "5.00.0")
        self.assertEqual(set(payloads), set(standalone.PAYLOAD_MODES))
        self.assertEqual(standalone.inspect_payload(candidate_bytes("normalized-version"))[0], "5.00.0")
        for mutation in ("unbound", "modified-companion", "arm", "duplicate", "missing", "mode", "owner", "hardlink", "malformed-version"):
            with self.subTest(mutation=mutation), self.assertRaises(lab.LifecycleLabError):
                standalone.inspect_payload(candidate_bytes(mutation))

    def test_candidate_digest_is_required_before_any_payload_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.apk"
            candidate.write_bytes(candidate_bytes())
            destination = root / "snapshot"
            destination.mkdir()
            with self.assertRaises(lab.LifecycleLabError):
                standalone.freeze_payload(candidate, "0" * 64, destination)
            self.assertEqual(list(destination.iterdir()), [])
            evidence = standalone.freeze_payload(candidate, lab.sha256_file(candidate), destination)
            self.assertEqual(evidence["sha256"], lab.sha256_file(candidate))
            self.assertEqual(set(evidence["payload_sha256"]), set(standalone.PAYLOAD_MODES))

    def test_every_ordered_step_is_required_and_native_contracts_do_not_change(self):
        original = deepcopy(lab.EXPECTED_SCENARIOS)
        events = [{"check": f"{standalone.SCENARIO}.{key}", "status": "pass"} for key in standalone.REQUIRED_CHECKS]
        standalone.validate_events(events)
        for index in range(len(events)):
            for changed in (events[:index] + events[index + 1:], events[:index] + [events[index]] + events[index:],
                            [*events[:index], {**events[index], "status": "fail"}, *events[index + 1:]]):
                with self.assertRaises(lab.LifecycleLabError):
                    standalone.validate_events(changed)
        with self.assertRaises(lab.LifecycleLabError):
            standalone.validate_events(list(reversed(events)))
        script = standalone.build_script()
        self.assertIn("standalone_initial", script)
        self.assertNotIn("initial) scenario_remove", script)
        self.assertEqual(lab.EXPECTED_SCENARIOS, original)
        result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_initialization_opt_ins_cannot_reach_uninstall(self):
        helper = Path(standalone.__file__).with_suffix(".sh").read_text()
        uninstall = helper.split("uninstall_standalone() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("env -i", uninstall)
        self.assertIn("/opt/syswarden/bin/syswarden-cli uninstall", uninstall)
        self.assertNotIn("SYSWARDEN_PKG_INSTALL", uninstall)
        self.assertNotIn("SYSWARDEN_OFFLINE_QUALIFICATION", uninstall)
        self.assertNotIn("apk del", helper)
        self.assertNotIn("apk add", helper)

    def test_nested_assertion_failure_cannot_be_hidden_by_zero_exit(self):
        helper = Path(standalone.__file__).with_suffix(".sh").read_text()
        functions = helper[helper.index("record() {"):helper.index("assert_unregistered() {")]
        with tempfile.TemporaryDirectory() as directory:
            script = functions.replace("/results", directory) + f'''
FAILURES=0
RESULT_FILE='{directory}/events.tsv'
COMMAND_LOG='{directory}/commands.log'
nested() {{ record fail nested 'failure'; return 0; }}
required_step must-fail nested
'''
            result = subprocess.run(["sh", "-u", "-c", script], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((Path(directory) / "events.tsv").read_text().startswith("fail\t"))

    def test_v5_telemetry_wait_uses_current_schema_and_candidate_core(self):
        helper = Path(standalone.__file__).with_suffix(".sh").read_text()
        function = helper[helper.index("wait_for_standalone_telemetry() {"):helper.index("uninstall_standalone() {")]
        selector = lab.LIFECYCLE_SCRIPT.split("live_telemetry_contract_for_version() {", 1)[1].split("\n}\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = "a" * 64
            (root / "inventory-candidate").write_text(f"/opt/syswarden/bin/syswarden-core\tfile\t750\t0\t0\t{digest}\n")
            for actual_digest, accepted in ((digest, True), ("b" * 64, False)):
                script = "live_telemetry_contract_for_version() {" + selector + "\n}\n" + function + f'''
EXPECTED_CANDIDATE_VERSION=5.00.0
PERSIST_ROOT='{root}'
attest_installed_core_process() {{ core_runtime_pid=123; core_runtime_identity=identity; core_runtime_sha256='{actual_digest}'; }}
live_telemetry_schema_valid() {{ [ "$2" = kpi-feed-v1 ]; }}
sleep() {{ return 1; }}
wait_for_standalone_telemetry
'''
                result = subprocess.run(["sh", "-eu", "-c", script], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_real_restart_and_both_successful_invocations_are_mandatory(self):
        spec = next(item for item in lab.DEFAULT_PLATFORMS if item.cell_id == "APK-322")
        def snapshot(pid):
            return {"pid1_starttime_ticks": pid, "cron_main_pid": 2}
        boots = [{"invocation": invocation, "boot_exit_code": 0, "script_exit_code": 0,
                  "restart_state": marker, "pre_exec": snapshot(pid), "post_exec": snapshot(pid), "exec_security": {}}
                 for invocation, marker, pid in (("initial", "restart-one", 10), ("restart-one", "complete", 20))]
        # The existing laboratory owns detailed namespace/security validation.
        # Isolate this runner's additional orchestration requirements here.
        with patch.object(lab, "_validate_runtime_snapshot_evidence", side_effect=lambda value, *_: value), \
             patch.object(lab, "_validate_process_security_evidence"):
            standalone.validate_boots(boots, spec)
            for mutation in ("missing", "same-pid", "script-failed", "boot-failed", "missing-marker", "pid-changed-during-script"):
                changed = deepcopy(boots)
                if mutation == "missing":
                    changed.pop()
                elif mutation == "same-pid":
                    changed[1]["pre_exec"] = changed[1]["post_exec"] = snapshot(10)
                elif mutation == "script-failed":
                    changed[1]["script_exit_code"] = 1
                elif mutation == "boot-failed":
                    changed[1]["boot_exit_code"] = 1
                elif mutation == "missing-marker":
                    changed[1]["restart_state"] = "restart-one"
                else:
                    changed[1]["post_exec"] = snapshot(21)
                with self.subTest(mutation=mutation), self.assertRaises(lab.LifecycleLabError):
                    standalone.validate_boots(changed, spec)

    def test_retained_standalone_tree_requires_content_metadata_and_backup_identity(self):
        helper = Path(standalone.__file__).with_suffix(".sh").read_text()
        function = helper[helper.index("assert_standalone_recovery() {"):helper.index("assert_retained_data() {")]
        for mutation in ("none", "changed", "missing", "mode", "hardlink", "symlink", "extra-directory", "wrong-name", "public-parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private = root / "private"
                saved = private / "pending"
                (saved / "bin").mkdir(parents=True)
                private.chmod(0o700)
                saved.chmod(0o750)
                (saved / "bin").chmod(0o750)
                (root / "results").mkdir()
                digest, inventory = hashlib.sha256(), []
                for relative in ("bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"):
                    content = b'#!/bin/sh\n[ "$1" = --help ]\n' if relative.endswith("-cli") else relative.encode()
                    path = saved / relative
                    path.write_bytes(content)
                    mode = 0o640 if relative == "signatures.json" else 0o750
                    path.chmod(mode)
                    checksum = hashlib.sha256(content).hexdigest()
                    digest.update(f"{relative}\0{checksum}\n".encode())
                    inventory.append(f"/opt/syswarden/{relative}\tfile\t{mode:o}\t0\t0\t{checksum}\n")
                identity = saved.stat()
                final = private / f"standalone-payload-{digest.hexdigest()}-{identity.st_dev:x}-{identity.st_ino:x}"
                saved.rename(final)
                saved = final
                (root / "inventory-candidate").write_text("".join(inventory))
                victim = saved / "bin/syswarden-core"
                if mutation == "changed":
                    victim.write_bytes(b"changed")
                elif mutation == "missing":
                    victim.unlink()
                elif mutation == "mode":
                    victim.chmod(0o755)
                elif mutation == "hardlink":
                    os.link(victim, root / "hardlink")
                elif mutation == "symlink":
                    victim.rename(root / "original")
                    victim.symlink_to(root / "original")
                elif mutation == "extra-directory":
                    (saved / "extra").mkdir()
                elif mutation == "wrong-name":
                    saved.rename(private / (saved.name + "-wrong"))
                elif mutation == "public-parent":
                    private.chmod(0o755)
                script = function.replace("/var/backups/syswarden-retired-v1", str(private)).replace("/results", str(root / "results"))
                script += f'''
stat() {{ command stat "$@" | sed 's/^{os.getuid()}:{os.getgid()}:/0:0:/'; }}
hash_file() {{ sha256sum "$1" | cut -d ' ' -f 1; }}
PERSIST_ROOT='{root}'
assert_standalone_recovery
'''
                result = subprocess.run(["sh", "-eu", "-c", script], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mutation == "none", result.stderr)

    def test_native_execution_requires_opt_in_before_any_command(self):
        with tempfile.TemporaryDirectory() as directory:
            args = standalone.parser().parse_args(["--candidate", f"{directory}/candidate.apk",
                "--candidate-sha256", "a" * 64, "--image", "sha256:" + "b" * 64,
                "--alpine-version", "3.22", "--output", f"{directory}/output"])
            with patch.object(lab.CommandRunner, "run") as run:
                with self.assertRaises(lab.LifecycleLabError):
                    standalone.run(args)
                run.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_absent_registration_requires_exact_native_exit_and_output(self):
        helper = Path(standalone.__file__).with_suffix(".sh").read_text()
        function = helper[helper.index("assert_unregistered() {"):helper.index("native_inventory() {")]
        with tempfile.TemporaryDirectory() as directory:
            for exit_code, output, accepted in ((1, "", True), (0, "", False), (2, "", False), (1, "query failure", False)):
                script = function.replace("/results", directory) + f'''
apk() {{ printf '%s' '{output}'; return {exit_code}; }}
assert_unregistered
'''
                result = subprocess.run(["sh", "-eu", "-c", script], capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)

    def test_journal_retains_exact_failed_command_observations(self):
        class Delegate:
            def run(self, args, *, timeout, cwd):
                return lab.CommandResult(tuple(args), 17, "stdout\n", "stderr\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commands.jsonl"
            runner = standalone.JournalRunner(Delegate(), path)
            observed = runner.run(("podman", "start", "fixture"), timeout=60)
            self.assertEqual(observed.returncode, 17)
            entry = json.loads(path.read_text())
            self.assertEqual(entry["args"], ["podman", "start", "fixture"])
            self.assertEqual((entry["exit_code"], entry["stdout"], entry["stderr"]), (17, "stdout\n", "stderr\n"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
