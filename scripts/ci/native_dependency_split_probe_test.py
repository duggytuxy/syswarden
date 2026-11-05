"""Failure accounting and fixture scope for the native identity split laboratory."""
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import native_dependency_split_probe as probe


def container_identity(root):
    return probe.ContainerIdentity(probe.CONTAINER_PREFIX + "b" * 32, "c" * 32, root / "case.cid")


def inspected_container(identity, **overrides):
    value = {"Id": "d" * 64, "Name": identity.name,
             "Config": {"Labels": {probe.OWNER_LABEL: identity.token}}}
    value.update(overrides)
    return subprocess.CompletedProcess([], 0, json.dumps([value]).encode())


def result_output(case="compatibility-upgrade", **overrides):
    fields = {"optional_present": "1", "sentinels": "preserved", "transaction_exit": "0",
              "product_version": "2.0.0", "base_version": "2.0.0", "legacy_payload": "absent",
              "shared_base_payload": "absent", "disjoint_base_payload": "intact", "runtime_owner": "absent",
              "unrelated_cleanup": "verified", "script_refusal": "0", "legacy_unchanged": "0"}
    fields.update(overrides)
    return ("".join(f"SW_SPLIT_RESULT {key}={value}\n" for key, value in fields.items())
            + f"SW_SPLIT_COMPLETE={case}\n").encode()


class NativeDependencySplitTests(unittest.TestCase):
    def test_byte_comparison_preserves_newline_and_missing_file_failures(self):
        helper = "same_bytes() {" + probe.SCRIPT.split("same_bytes() {", 1)[1].split("\n}", 1)[0] + "\n}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left, right = root / "left", root / "right"
            left.write_bytes(b"fixture\n")
            for content in (b"fixture\n", b"fixture", b"fixture\n\n", b"other\n", None):
                if content is None:
                    right.unlink()
                else:
                    right.write_bytes(content)
                result = subprocess.run(["/bin/sh", "-c", helper + '\nsame_bytes "$1" "$2"',
                                         "probe", str(left), str(right)], capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, content == b"fixture\n")

    def test_shell_syntax_without_executing_fixture(self):
        result = subprocess.run(["/bin/sh", "-n"], input=probe.SCRIPT.encode(), capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_fixtures_keep_legacy_root_and_distinct_minimal_identity(self):
        for format_name in ("deb", "rpm", "apk"):
            with self.subTest(format=format_name), tempfile.TemporaryDirectory() as temporary:
                specs = dict(probe.fixture_specs(Path(temporary), format_name))
                self.assertEqual(len(specs), 9)
                for spec in specs.values():
                    self.assertEqual((spec["arch"], spec["platform"]), ("amd64", "linux"))
                    for forbidden in ("conflicts", "replaces", "provides", "obsoletes"):
                        self.assertNotIn(forbidden, spec)
                    self.assertTrue(spec["name"].startswith("sw-lab-"))
                for stem in ("base-disjoint-2.0.0", "base-shared-2.0.0"):
                    self.assertEqual(specs[stem]["name"], "sw-lab-base")
                    self.assertNotIn("depends", specs[stem])
                    self.assertNotIn("scripts", specs[stem])
                legacy = specs["legacy-1.0.0"]
                compatibility = specs["compatibility-2.0.0"]
                self.assertEqual(legacy["name"], compatibility["name"])
                self.assertEqual(legacy["depends"], ["sw-lab-optional"])
                self.assertEqual(compatibility["depends"], [probe.requirement("sw-lab-base", "2.0.0", format_name), "sw-lab-optional"])
                old_path = legacy["contents"][0]["dst"]
                self.assertNotEqual(old_path, specs["base-disjoint-2.0.0"]["contents"][0]["dst"])
                self.assertEqual(old_path, specs["base-shared-2.0.0"]["contents"][0]["dst"])
                self.assertIn(probe.requirement("sw-lab-unavailable", "1.0.0", format_name), specs["solver-refused-3.0.0"]["depends"])
                refused = specs["script-refused-4.0.0"]
                scripts = refused["apk"]["scripts"] if format_name == "apk" else refused["scripts"]
                self.assertEqual(set(scripts), {"preupgrade" if format_name == "apk" else "preinstall"})

    def test_sandbox_is_offline_bounded_and_format_specific(self):
        identity = container_identity(Path("/fixture"))
        args = probe.sandbox_command("/usr/bin/podman", "a" * 64, "apk", "compatibility-upgrade", identity)
        self.assertEqual(args[:3], ["/usr/bin/podman", "--remote=false", "run"])
        options = args[:args.index("a" * 64)]
        for key, value in (("--pull", "never"), ("--network", "none"), ("--cap-drop", "all"),
                           ("--cap-add", "SYS_CHROOT"), ("--security-opt", "no-new-privileges"),
                           ("--cpus", "2"), ("--memory", "512m"), ("--timeout", "90"),
                           ("--name", identity.name), ("--cidfile", str(identity.cidfile)),
                           ("--label", probe.OWNER_LABEL + "=" + identity.token)):
            self.assertEqual(options[options.index(key) + 1], value)
        self.assertIn("--image-volume=ignore", options)
        for denied in ("--privileged", "--mount", "--volume", "-v", "--rm"):
            self.assertNotIn(denied, options)
        for image, format_name, case in (("alpine:latest", "apk", "fresh-base"),
                                         ("a" * 64, "apk", "compatibility-held"),
                                         ("a" * 64, "rpm", "compatibility-pinned"),
                                         ("a" * 64, "unknown", "fresh-base")):
            with self.assertRaises(ValueError):
                probe.sandbox_command("podman", image, format_name, case, identity)

    def test_podman_execution_explicitly_disables_remote_engine(self):
        args = probe.podman_command("/usr/bin/podman", "info", "--format", "{{.Host.Security.Rootless}}")
        with mock.patch.object(probe.subprocess, "run", return_value=subprocess.CompletedProcess(args, 0, b"true")) as run:
            probe.execute_local(args)
            self.assertEqual(run.call_args.args[0][1], "--remote=false")
            self.assertEqual(run.call_args.kwargs["timeout"], 15)
            with self.assertRaisesRegex(ValueError, "local Podman"):
                probe.execute_local(["podman", "info"])
            self.assertEqual(run.call_count, 1)

    def test_automatic_cleanup_requires_name_and_exact_id_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = container_identity(Path(temporary))
            identity.cidfile.write_text("d" * 64 + "\n")
            with mock.patch.object(probe, "execute_local", side_effect=[subprocess.CompletedProcess([], 1, b"")] * 2) as execute:
                result = probe.cleanup_container("podman", identity, require_cid=True)
            self.assertTrue(result["verified"])
            self.assertTrue(result["name_absent"])
            self.assertTrue(result["id_absent"])
            self.assertFalse(result["removal_attempted"])
            self.assertEqual([call.args[0][-1] for call in execute.call_args_list], [identity.name, "d" * 64])
            self.assertTrue(all(call.args[0][1] == "--remote=false" for call in execute.call_args_list))

    def test_cleanup_removes_only_verified_full_id_and_rechecks_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = container_identity(Path(temporary))
            identity.cidfile.write_text("d" * 64 + "\n")
            responses = [subprocess.CompletedProcess([], 0, b""), inspected_container(identity),
                         subprocess.CompletedProcess([], 0, b"removed\n"),
                         subprocess.CompletedProcess([], 1, b""), subprocess.CompletedProcess([], 1, b"")]
            with mock.patch.object(probe, "execute_local", side_effect=responses) as execute:
                result = probe.cleanup_container("podman", identity, require_cid=True)
            self.assertTrue(result["verified"])
            self.assertTrue(result["ownership_verified"])
            self.assertEqual(execute.call_args_list[2].args[0], ["podman", "--remote=false", "rm", "--force", "--time", "5", "d" * 64])
            self.assertTrue(all(call.args[0][1] == "--remote=false" for call in execute.call_args_list))

    def test_unknown_ownership_never_authorizes_removal(self):
        for mismatch in ("label", "name", "id", "ambiguous", "timeout"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                identity = container_identity(Path(temporary))
                identity.cidfile.write_text("d" * 64 + "\n")
                changes = {"label": {"Config": {"Labels": {}}}, "name": {"Name": "unrelated"},
                           "id": {"Id": "e" * 64}}
                inspection = inspected_container(identity, **changes.get(mismatch, {}))
                if mismatch == "ambiguous":
                    inspection = subprocess.CompletedProcess([], 0, b"[]")
                if mismatch == "timeout":
                    inspection = subprocess.TimeoutExpired("inspect", 15)
                with mock.patch.object(probe, "execute_local", side_effect=[subprocess.CompletedProcess([], 0, b""), inspection]) as execute:
                    result = probe.cleanup_container("podman", identity, require_cid=True)
                self.assertFalse(result["verified"])
                self.assertFalse(result["removal_attempted"])
                self.assertFalse(any(call.args[0][2] == "rm" for call in execute.call_args_list))

    def test_missing_cid_or_surviving_container_cannot_pass_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = container_identity(Path(temporary))
            with mock.patch.object(probe, "execute_local", return_value=subprocess.CompletedProcess([], 1, b"")):
                self.assertFalse(probe.cleanup_container("podman", identity, require_cid=True)["verified"])
            identity.cidfile.write_text("d" * 64)
            responses = [subprocess.CompletedProcess([], 0, b""), inspected_container(identity),
                         subprocess.CompletedProcess([], 0, b""), subprocess.CompletedProcess([], 0, b""),
                         subprocess.CompletedProcess([], 0, b"")]
            with mock.patch.object(probe, "execute_local", side_effect=responses):
                self.assertFalse(probe.cleanup_container("podman", identity, require_cid=True)["verified"])

    def test_preexisting_container_is_neither_run_nor_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = container_identity(root)
            with mock.patch.object(probe, "container_identity", return_value=identity), \
                    mock.patch.object(probe, "execute_local", return_value=subprocess.CompletedProcess([], 0, b"")) as execute:
                result, ownership = probe.run_container("podman", "a" * 64, "apk", "compatibility-upgrade", root, b"inert")
            self.assertEqual(result.returncode, 125)
            self.assertFalse(ownership["absent_before"])
            self.assertFalse(ownership["cleanup"]["removal_attempted"])
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(execute.call_args.args[0][2:4], ["container", "exists"])

    def test_run_timeout_still_cleans_owned_container_and_records_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = container_identity(root)
            responses = [subprocess.CompletedProcess([], 1, b""), None,
                         subprocess.CompletedProcess([], 0, b""), inspected_container(identity),
                         subprocess.CompletedProcess([], 0, b""), subprocess.CompletedProcess([], 1, b""),
                         subprocess.CompletedProcess([], 1, b"")]
            def execute(args, **kwargs):
                response = responses.pop(0)
                self.assertEqual(args[1], "--remote=false")
                if response is None:
                    self.assertEqual(args[2], "run")
                    self.assertEqual(kwargs["timeout"], 100)
                    identity.cidfile.write_text("d" * 64 + "\n")
                    raise subprocess.TimeoutExpired("run", 100, output=b"partial native output\n")
                return response
            with mock.patch.object(probe, "container_identity", return_value=identity), \
                    mock.patch.object(probe, "execute_local", side_effect=execute):
                result, ownership = probe.run_container("podman", "a" * 64, "apk", "compatibility-upgrade", root, b"inert")
            self.assertEqual(result.returncode, 124)
            self.assertTrue(ownership["cleanup"]["verified"])
            self.assertTrue(ownership["cleanup"]["removal_attempted"])
            self.assertEqual(json.loads((root / "compatibility-upgrade.container.json").read_text()), ownership)

    def test_qualification_rejects_incomplete_duplicate_and_unsafe_observations(self):
        good = result_output()
        self.assertTrue(probe.observations("compatibility-upgrade", good, 0)["synthetic_contract_passed"])
        for output, status in ((good, 1), (b"", 0), (good + b"SW_SPLIT_COMPLETE=compatibility-upgrade\n", 0),
                               (good.replace(b"SW_SPLIT_RESULT base_version=2.0.0\n", b""), 0),
                               (b"SW_SPLIT_RESULT base_version=2.0.0\n" + good, 0),
                               (result_output(optional_present="0"), 0),
                               (result_output(runtime_owner="legacy"), 0),
                               (result_output(unrelated_cleanup="not-run"), 0),
                               (result_output(transaction_exit="256"), 0),
                               (result_output(unknown="1"), 0)):
            with self.subTest(output=output, status=status), self.assertRaises(ValueError):
                probe.observations("compatibility-upgrade", output, status)

    def test_fresh_and_solver_refusal_require_their_distinct_states(self):
        fresh = result_output("fresh-base", optional_present="0", sentinels="not-applicable",
                              product_version="absent", unrelated_cleanup="not-run")
        self.assertTrue(probe.observations("fresh-base", fresh, 0)["synthetic_contract_passed"])
        refusal = result_output("solver-refusal", transaction_exit="1", product_version="1.0.0", base_version="absent",
                                legacy_payload="intact", shared_base_payload="changed", disjoint_base_payload="absent",
                                runtime_owner="legacy", unrelated_cleanup="not-run", legacy_unchanged="1")
        self.assertTrue(probe.observations("solver-refusal", refusal, 0)["synthetic_contract_passed"])
        with self.assertRaises(ValueError):
            probe.observations("solver-refusal", refusal.replace(b"transaction_exit=1", b"transaction_exit=0"), 0)
        with self.assertRaises(ValueError):
            probe.observations("solver-refusal", refusal.replace(b"legacy_unchanged=1", b"legacy_unchanged=0"), 0)

    def test_characterization_never_claims_rollback_or_product_acceptance(self):
        examples = (
            ("shared-handoff", {"shared_base_payload": "intact", "legacy_payload": "changed", "runtime_owner": "base"}, "shared-handoff-observed"),
            ("unprepared-shared-base", {"transaction_exit": "1", "product_version": "1.0.0", "legacy_payload": "intact",
                                       "shared_base_payload": "changed", "runtime_owner": "legacy", "legacy_unchanged": "1"}, "partial-registration-old-payload-preserved"),
            ("script-refusal", {"transaction_exit": "1", "product_version": "4.0.0", "script_refusal": "1"}, "partial-or-unsafe-transition"),
            ("unprepared-shared-base", {"product_version": "1.0.0", "legacy_payload": "changed", "runtime_owner": "base"}, "partial-or-unsafe-transition"),
        )
        for case, fields, outcome in examples:
            with self.subTest(case=case, outcome=outcome):
                result = probe.observations(case, result_output(case, **fields), 0)
                self.assertEqual(result["outcome"], outcome)
                self.assertFalse(result["synthetic_contract_passed"])
                self.assertFalse(result["product_accepted"])
                self.assertTrue(result["observation_complete"])

    def test_root_refusal_precedes_commands(self):
        with mock.patch.object(probe.os, "geteuid", return_value=0), mock.patch.object(probe.native, "command") as command:
            with self.assertRaisesRegex(ValueError, "unprivileged"):
                probe.run(Path("/unused"), "a" * 64, "apk", Path("/unused-output"))
            command.assert_not_called()

    def test_architecture_refusal_precedes_fixture_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nfpm = root / "nfpm"
            nfpm.write_bytes(b"fixture")
            nfpm.chmod(0o700)
            responses = [subprocess.CompletedProcess([], 0, b"true\n"), subprocess.CompletedProcess([], 0,
                         json.dumps([{"Os": "linux", "Architecture": "unsupported", "Id": "a" * 64}]).encode())]
            with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                    mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                    mock.patch.object(probe, "execute_local", side_effect=responses) as execute, \
                    mock.patch.object(probe, "fixtures") as fixtures:
                with self.assertRaisesRegex(ValueError, "AMD64"):
                    probe.run(nfpm, "a" * 64, "apk", root / "results")
                fixtures.assert_not_called()
                self.assertFalse((root / "results").exists())
                self.assertTrue(all(call.args[0][1] == "--remote=false" for call in execute.call_args_list))

    def test_subset_and_timeout_cannot_claim_complete_qualification(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                nfpm = root / "nfpm"
                nfpm.write_bytes(b"fixture")
                nfpm.chmod(0o700)
                responses = [subprocess.CompletedProcess([], 0, b"true\n"), subprocess.CompletedProcess([], 0,
                             json.dumps([{"Os": "linux", "Architecture": "amd64", "Id": "a" * 64}]).encode())]
                native_result = subprocess.CompletedProcess([], 124, b"incomplete\n") if timeout else subprocess.CompletedProcess([], 0, result_output())
                with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                        mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                        mock.patch.object(probe, "execute_local", side_effect=responses), \
                        mock.patch.object(probe, "run_container", return_value=(native_result, {"cleanup": {"verified": True}})), \
                        mock.patch.object(probe, "fixtures", return_value=b"inert"):
                    if timeout:
                        with self.assertRaisesRegex(RuntimeError, "compatibility-upgrade"):
                            probe.run(nfpm, "a" * 64, "apk", root / "results", ("compatibility-upgrade",))
                    else:
                        probe.run(nfpm, "a" * 64, "apk", root / "results", ("compatibility-upgrade",))
                report = json.loads((root / "results/results.json").read_text())
                self.assertFalse(report["product_accepted"])
                self.assertFalse(report["shared_payload_qualified"])
                self.assertFalse(report["synthetic_disjoint_contract_passed"])
                self.assertEqual(report["selected_observations_complete"], not timeout)

    def test_unresolved_cleanup_overrides_success_and_stops_later_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nfpm = root / "nfpm"
            nfpm.write_bytes(b"fixture")
            nfpm.chmod(0o700)
            responses = [subprocess.CompletedProcess([], 0, b"true\n"), subprocess.CompletedProcess([], 0,
                         json.dumps([{"Os": "linux", "Architecture": "amd64", "Id": "a" * 64}]).encode())]
            with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                    mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                    mock.patch.object(probe, "execute_local", side_effect=responses), \
                    mock.patch.object(probe, "run_container", return_value=(subprocess.CompletedProcess([], 0, result_output()),
                                      {"cleanup": {"verified": False}})) as run, \
                    mock.patch.object(probe, "fixtures", return_value=b"inert"):
                with self.assertRaisesRegex(RuntimeError, "compatibility-upgrade"):
                    probe.run(nfpm, "a" * 64, "apk", root / "results", ("compatibility-upgrade", "fresh-base"))
                self.assertEqual(run.call_count, 1)
            report = json.loads((root / "results/results.json").read_text())
            self.assertFalse(report["cases"]["compatibility-upgrade"]["synthetic_contract_passed"])
            self.assertFalse(report["selected_observations_complete"])
            self.assertFalse(report["synthetic_disjoint_contract_passed"])

    def test_archive_contains_only_built_inert_artifacts_and_fixture_script(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def build(args):
                Path(args[args.index("--target") + 1]).write_bytes(b"inert package")
                return subprocess.CompletedProcess(args, 0, b"built\n")
            with mock.patch.object(probe.native, "command", side_effect=build):
                payload = probe.fixtures(root, Path("/fixture/nfpm"), "apk")
            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                names = archive.getnames()
                self.assertEqual(len(names), 10)
                self.assertIn("cases.sh", names)
                self.assertTrue(all(name == "cases.sh" or name.endswith(".apk") for name in names))
                self.assertTrue(all(not name.startswith("/") and ".." not in name for name in names))


if __name__ == "__main__":
    unittest.main()
