#!/usr/bin/env python3
"""Tests for the source-bound allocation producer and Go probe."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts.ci import source_allocation_producer as producer
except ImportError:
    import source_allocation_producer as producer


class SourceAllocationProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, raw: bytes, mode: int = 0o600) -> Path:
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def test_contract_is_exact_and_source_bound(self) -> None:
        contract = producer._load_contract(producer.DEFAULT_CONTRACT)
        self.assertEqual(contract["workload"]["entrypoint"], "syswarden-core/engine.Engine.Scan")
        self.assertEqual(contract["workload"]["goroutines_before"], 2)
        self.assertEqual(contract["workload"]["goroutines_after"], 2)
        self.assertEqual(contract["campaigns"], [
            "allocation-campaign-01",
            "allocation-campaign-02",
            "allocation-campaign-03",
        ])
        self.assertEqual(set(contract["metrics"]), {
            "waap_detection_allocations_per_admitted_event",
            "waap_detection_allocated_bytes_per_admitted_event",
        })

    def test_strict_json_rejects_duplicate_nested_key(self) -> None:
        with self.assertRaises(producer.AllocationProducerError):
            producer._strict_json(b'{"outer":{"value":1,"value":2}}', "fixture")

    def test_write_new_is_create_once_and_owner_only(self) -> None:
        output = self.root / "evidence.json"
        producer._write_new(output, b"{}\n", 0o600)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            producer._write_new(output, b"{}\n", 0o600)

    def test_output_root_must_not_overlap_any_protected_input(self) -> None:
        protected = self.root / "protected"
        protected.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "overlaps protected input",
        ):
            producer._require_disjoint_output(
                protected / "evidence",
                (protected,),
            )
        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "overlaps protected input",
        ):
            producer._require_disjoint_output(
                self.root / "future-parent",
                (self.root,),
            )

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets")
    def test_input_tree_attestation_rejects_unix_socket(self) -> None:
        tree = self.root / "tree"
        tree.mkdir(mode=0o700)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                listener.bind(str(tree / "fsmonitor.sock"))
            except PermissionError:
                self.skipTest("the local sandbox forbids creating Unix sockets")
            with self.assertRaisesRegex(
                producer.AllocationProducerError,
                "symlink or special entry",
            ):
                producer._attest_regular_tree(tree, "test tree")
        finally:
            listener.close()

    def test_input_tree_attestation_rejects_fifo(self) -> None:
        tree = self.root / "fifo-tree"
        tree.mkdir(mode=0o700)
        os.mkfifo(tree / "unexpected.fifo", 0o600)
        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "symlink or special entry",
        ):
            producer._attest_regular_tree(tree, "test tree")

    def test_command_output_is_bounded_while_the_child_is_running(self) -> None:
        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "output exceeded its bound",
        ):
            producer._command(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os; os.write(1, b'x' * 131072)",
                ],
                timeout=10,
                maximum=1024,
            )

    def test_candidate_must_descend_from_the_frozen_baseline(self) -> None:
        candidate = "1" * 40
        baseline = "2" * 40

        def git_result(_repository: Path, *arguments: str) -> str:
            if arguments[:2] == ("cat-file", "-t"):
                return "commit"
            if arguments == ("show-ref", "--verify", "refs/heads/main"):
                return f"{candidate} refs/heads/main"
            if arguments == ("rev-parse", "HEAD^{commit}"):
                return candidate
            if arguments and arguments[0] == "status":
                return ""
            if arguments == ("rev-parse", "refs/tags/v4.04.3^{commit}"):
                return baseline
            if arguments == (
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ):
                return str(self.root / "git-common")
            if arguments == (
                "for-each-ref",
                "--format=%(refname)",
                "refs/replace",
            ):
                return ""
            if arguments and arguments[0] == "merge-base":
                raise producer.AllocationProducerError("not an ancestor")
            raise AssertionError(arguments)

        with mock.patch.object(producer, "_git", side_effect=git_result):
            with self.assertRaisesRegex(
                producer.AllocationProducerError,
                "not an ancestor",
            ):
                producer._resolve_subjects(self.root, candidate, baseline)

    def test_git_grafts_are_rejected_before_ancestry(self) -> None:
        candidate = "1" * 40
        baseline = "2" * 40
        common = self.root / "git-common"
        (common / "info").mkdir(parents=True, mode=0o700)
        (common / "info" / "grafts").write_text(
            f"{candidate} {baseline}\n",
            encoding="ascii",
        )

        def git_result(_repository: Path, *arguments: str) -> str:
            if arguments[:2] == ("cat-file", "-t"):
                return "commit"
            if arguments == ("show-ref", "--verify", "refs/heads/main"):
                return f"{candidate} refs/heads/main"
            if arguments == ("rev-parse", "HEAD^{commit}"):
                return candidate
            if arguments and arguments[0] == "status":
                return ""
            if arguments == ("rev-parse", "refs/tags/v4.04.3^{commit}"):
                return baseline
            if arguments == (
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ):
                return str(common)
            raise AssertionError(arguments)

        with mock.patch.object(producer, "_git", side_effect=git_result):
            with self.assertRaisesRegex(
                producer.AllocationProducerError,
                "Git grafts are forbidden",
            ):
                producer._resolve_subjects(self.root, candidate, baseline)

    def test_read_regular_rejects_hardlink_and_symlink(self) -> None:
        source = self.write("source.json", b"{}\n")
        hardlink = self.root / "hardlink.json"
        os.link(source, hardlink)
        with self.assertRaises(producer.AllocationProducerError):
            producer._read_regular(source, 1024, modes={0o600}, owner=os.geteuid())
        symlink = self.root / "symlink.json"
        symlink.symlink_to(source)
        with self.assertRaises(producer.AllocationProducerError):
            producer._read_regular(symlink, 1024, modes={0o600}, owner=os.geteuid())

    def execution_control(self, candidate: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "schema_id": "syswarden-allocation-execution-control-attestation/v1",
            "candidate_commit": candidate,
            "architecture": "linux/amd64",
            "recorded_at": "2026-09-10T08:00:00Z",
            "attested_by": "protected-runner",
            "producer_egress_denied": True,
            "repository_source_read_only": True,
            "build_checkouts_producer_writable": True,
            "persistent_writes_limited_to_evidence_root": True,
            "probe_egress_denied": True,
            "probe_persistent_filesystem_read_only": True,
            "sandbox_kind": "bubblewrap-minimal-root-unshared-network/v2",
            "sandbox_executable_path": "/usr/bin/bwrap",
            "sandbox_executable_sha256": "a" * 64,
            "python_executable_path": "/usr/bin/python3.14",
            "python_executable_sha256": "b" * 64,
            "shell_executable_path": "/usr/bin/bash",
            "shell_executable_sha256": "c" * 64,
            "outer_unix_socket_canary_passed": True,
            "probe_unix_socket_canary_required": True,
            "runner_threat_model": "protected-dedicated-runner-trusted-launch-environment-no-hostile-same-uid-process/v1",
        }

    def test_execution_control_requires_external_fail_closed_attestation(self) -> None:
        candidate = "1" * 40
        document = self.execution_control(candidate)
        path = self.write("control.json", producer._canonical_json(document))
        parsed, raw, digest = producer._load_execution_control(path, candidate)
        self.assertEqual(parsed, document)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        document["producer_egress_denied"] = False
        path.unlink()
        path = self.write("control.json", producer._canonical_json(document))
        with self.assertRaises(producer.AllocationProducerError):
            producer._load_execution_control(path, candidate)

    def test_producer_rejects_a_caller_selected_sandbox(self) -> None:
        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "canonical /usr/bin/bwrap trust anchor",
        ):
            producer._read_system_bwrap(Path("/bin/true"))

    def test_producer_rejects_a_substituted_python_target(self) -> None:
        substituted = self.write("python3", b"not python\n", mode=0o700)
        original_lstat = Path.lstat

        def trusted_system_lstat(path: Path, *args: object, **kwargs: object) -> object:
            info = original_lstat(path, *args, **kwargs)
            if path in {
                Path("/"),
                Path("/usr"),
                Path("/usr/bin"),
                producer.SYSTEM_PYTHON_ENTRY,
            }:
                trusted = mock.Mock()
                for attribute in (
                    "st_mode",
                    "st_ino",
                    "st_dev",
                    "st_nlink",
                    "st_gid",
                    "st_size",
                ):
                    setattr(trusted, attribute, getattr(info, attribute))
                trusted.st_uid = 0
                return trusted
            return info

        with self.assertRaisesRegex(
            producer.AllocationProducerError,
            "canonical target of /usr/bin/python3",
        ), mock.patch.object(Path, "lstat", new=trusted_system_lstat):
            producer._read_system_python(substituted)

    def test_candidate_inputs_must_equal_the_exact_committed_blob(self) -> None:
        repository = self.root / "repository"
        input_path = repository / "scripts" / "ci" / "input.json"
        input_path.parent.mkdir(parents=True, mode=0o700)
        input_path.write_bytes(b"changed\n")
        input_path.chmod(0o600)
        with mock.patch.object(producer, "_command", return_value=b"committed\n"):
            with self.assertRaisesRegex(
                producer.AllocationProducerError,
                "differs from the exact committed blob",
            ):
                producer._require_candidate_blob(
                    repository,
                    "1" * 40,
                    input_path,
                    "scripts/ci/input.json",
                    maximum=1024,
                    modes={0o600},
                )

    def test_toolchain_is_extracted_from_the_verified_archive_bytes(self) -> None:
        local_go = Path(shutil.which("go") or "")
        if not local_go.is_file():
            self.skipTest("Go is unavailable")
        go_bytes = local_go.read_bytes()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
            directory = tarfile.TarInfo("go/bin")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            stream.addfile(directory)
            binary = tarfile.TarInfo("go/bin/go")
            binary.size = len(go_bytes)
            binary.mode = 0o755
            stream.addfile(binary, io.BytesIO(go_bytes))
        archive_bytes = buffer.getvalue()
        archive = self.write("toolchain.tar.gz", archive_bytes)
        contract = {
            "toolchain_archive_sha256": hashlib.sha256(archive_bytes).hexdigest()
        }
        verified_archive, executable_sha = producer._verify_toolchain_inputs(
            archive, contract
        )
        self.assertEqual(verified_archive, archive_bytes)
        extracted_go = producer._extract_toolchain(
            verified_archive, self.root / "extracted", executable_sha
        )
        self.assertEqual(extracted_go.read_bytes(), go_bytes)
        self.assertEqual(extracted_go.stat().st_mode & 0o777, 0o700)

    def test_toolchain_extraction_rejects_links_and_home_is_not_redefined(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
            link = tarfile.TarInfo("go/bin/go")
            link.type = tarfile.SYMTYPE
            link.linkname = "/usr/bin/go"
            stream.addfile(link)
        with self.assertRaisesRegex(producer.AllocationProducerError, "link or special"):
            producer._extract_toolchain(
                buffer.getvalue(), self.root / "unsafe-extracted", "0" * 64
            )
        environment = producer._go_environment(
            Path("/toolchain/go/bin/go"),
            self.root,
            self.root,
            self.root,
        )
        self.assertNotIn("HOME", environment)
        self.assertNotIn('"HOME"', producer.Path(producer.__file__).read_text())

    def test_qualifying_launcher_requires_nested_network_and_filesystem_isolation(self) -> None:
        launcher = producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        completed = subprocess.run(
            ["bash", "-n", str(launcher)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        source = launcher.read_text(encoding="utf-8")
        for requirement in (
            "--unshare-user",
            "--unshare-net",
            "--ro-bind /usr /usr",
            "--tmpfs /tmp",
            '--bind "${output_root}" "${output_root}"',
            "--prepared-output-root",
            "--probe-sandbox-executable",
            "sandbox_executable='/usr/bin/bwrap'",
            "source_allocation_gate.py",
            "validate-raw",
            "outer_unix_socket_canary_passed",
            "probe_unix_socket_canary_required",
        ):
            self.assertIn(requirement, source)
        producer_source = Path(producer.__file__).read_text(encoding="utf-8")
        self.assertIn('"refs/heads/main"', producer_source)
        self.assertIn('"--ignored=matching"', producer_source)
        self.assertNotIn('f"/proc/self/fd/{sandbox_descriptor}"', producer_source)
        self.assertNotIn('install -m 0700 -- "${sandbox_executable}"', source)
        self.assertNotIn("[--sandbox-executable", source)
        self.assertNotIn("--share-net", source)
        self.assertNotIn("--ro-bind / /", source)
        self.assertNotIn("--setenv HOME", source)
        self.assertNotIn("command -v python3", source)
        self.assertIn("python_entry='/usr/bin/python3'", source)
        self.assertTrue(source.startswith("#!/usr/bin/bash -p\n"))
        self.assertEqual(source.count('"${python_executable}" -I'), 6)
        self.assertIn("unset BASH_ENV ENV", source)
        post_gate = source.index('"${gate}" validate-raw')
        final_python_check = source.index("verify_system_python", post_gate)
        success = source.index(
            "Source allocation bundle produced and validated", post_gate
        )
        self.assertLess(post_gate, final_python_check)
        self.assertLess(final_python_check, success)

    @unittest.skipUnless(platform.system() == "Linux", "Linux bubblewrap canary")
    def test_nested_probe_unix_socket_canary_is_enforced_when_system_tools_are_trusted(self) -> None:
        sandbox = producer.SYSTEM_BWRAP
        python_entry = producer.SYSTEM_PYTHON_ENTRY
        if not sandbox.is_file() or sandbox.stat().st_uid != 0:
            self.skipTest("canonical root-owned /usr/bin/bwrap is unavailable")
        python_target = python_entry.resolve(strict=True)
        if python_target.stat().st_uid != 0:
            self.skipTest("canonical root-owned /usr/bin/python3 target is unavailable")
        sandbox_sha = hashlib.sha256(sandbox.read_bytes()).hexdigest()
        producer._verify_nested_unix_socket_isolation(
            sandbox,
            sandbox_sha,
            python_target,
        )

    @unittest.skipUnless(platform.system() == "Linux", "Linux launcher")
    def test_qualifying_launcher_ignores_python_path_injection(self) -> None:
        injected = self.root / "injected"
        injected.mkdir(mode=0o700)
        marker = self.root / "path-python-executed"
        fake_python = injected / "python3"
        fake_python.write_text(
            f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 91\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o700)
        archive = self.write("path-toolchain.tar.gz", b"not opened")
        module_cache = self.root / "path-module-cache"
        module_cache.mkdir(mode=0o700)
        launcher = producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        environment = os.environ.copy()
        environment["PATH"] = f"{injected}:/usr/bin:/bin"
        completed = subprocess.run(
            [
                str(launcher),
                "--repository",
                str(producer.REPOSITORY),
                "--candidate-commit",
                "1" * 40,
                "--toolchain-archive",
                str(archive),
                "--module-cache",
                str(module_cache),
                "--output-root",
                str(self.root / "path-evidence"),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 91)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(platform.system() == "Linux", "Linux launcher")
    def test_qualifying_launcher_ignores_shell_and_python_environment_injection(self) -> None:
        injected = self.root / "environment-injection"
        injected.mkdir(mode=0o700)
        bash_marker = self.root / "bash-env-executed"
        python_marker = self.root / "python-path-executed"
        bash_env = injected / "bash-env.sh"
        bash_env.write_text(
            f"/usr/bin/touch {bash_marker}\n",
            encoding="utf-8",
        )
        bash_env.chmod(0o600)
        sitecustomize = injected / "sitecustomize.py"
        sitecustomize.write_text(
            f"from pathlib import Path\nPath({str(python_marker)!r}).touch()\n",
            encoding="utf-8",
        )
        sitecustomize.chmod(0o600)
        archive = self.write("environment-toolchain.tar.gz", b"not opened")
        module_cache = self.root / "environment-module-cache"
        module_cache.mkdir(mode=0o700)
        launcher = producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        environment = os.environ.copy()
        environment.update(
            {
                "BASH_ENV": str(bash_env),
                "PYTHONPATH": str(injected),
                "PYTHONHOME": str(injected / "fake-python-home"),
            }
        )
        completed = subprocess.run(
            [
                str(launcher),
                "--repository",
                str(producer.REPOSITORY),
                "--candidate-commit",
                "1" * 40,
                "--toolchain-archive",
                str(archive),
                "--module-cache",
                str(module_cache),
                "--output-root",
                str(self.root / "environment-evidence"),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(bash_marker.exists())
        self.assertFalse(python_marker.exists())

    @unittest.skipUnless(platform.system() == "Linux", "Linux bubblewrap launcher")
    def test_qualifying_launcher_fails_closed_for_foreign_owned_bubblewrap(self) -> None:
        sandbox = Path("/usr/bin/bwrap")
        if not sandbox.is_file():
            self.skipTest("/usr/bin/bwrap is unavailable")
        if sandbox.stat().st_uid in {0, os.geteuid()}:
            self.skipTest("/usr/bin/bwrap is controlled by root or the current owner")

        archive = self.write("toolchain.tar.gz", b"not opened before sandbox validation")
        module_cache = self.root / "module-cache"
        module_cache.mkdir(mode=0o700)
        launcher = producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        completed = subprocess.run(
            [
                str(launcher),
                "--repository",
                str(producer.REPOSITORY),
                "--candidate-commit",
                "1" * 40,
                "--toolchain-archive",
                str(archive),
                "--module-cache",
                str(module_cache),
                "--output-root",
                str(self.root / "evidence"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("owner is unsafe", completed.stderr.decode("utf-8", "replace"))
        self.assertFalse((self.root / "evidence").exists())

    def test_qualifying_launcher_rejects_a_caller_selected_noop_sandbox(self) -> None:
        launcher = producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        completed = subprocess.run(
            [str(launcher), "--sandbox-executable", "/bin/true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Usage:", completed.stderr.decode("utf-8", "replace"))

    def test_launcher_post_validation_rejects_a_noop_sandbox(self) -> None:
        system_noop = Path("/usr/bin/true")
        if (
            not system_noop.is_file()
            or system_noop.resolve() != system_noop
            or system_noop.stat().st_uid != 0
        ):
            self.skipTest("canonical root-owned /usr/bin/true is unavailable")
        source_launcher = (
            producer.REPOSITORY / "scripts" / "ci" / "source_allocation_sandbox.sh"
        )
        mutated = source_launcher.read_text(encoding="utf-8").replace(
            "sandbox_executable='/usr/bin/bwrap'",
            "sandbox_executable='/usr/bin/true'",
        )
        launcher = self.write("no-op-sandbox-launcher.sh", mutated.encode(), mode=0o700)
        archive = self.write("no-op-toolchain.tar.gz", b"not reached")
        module_cache = self.root / "no-op-module-cache"
        module_cache.mkdir(mode=0o700)
        output = self.root / "no-op-evidence"
        completed = subprocess.run(
            [
                str(launcher),
                "--repository",
                str(producer.REPOSITORY),
                "--candidate-commit",
                "1" * 40,
                "--toolchain-archive",
                str(archive),
                "--module-cache",
                str(module_cache),
                "--output-root",
                str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(
            "produced and validated under enforced controls",
            completed.stdout.decode("utf-8", "replace"),
        )
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])

    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux AMD64 probe")
    def test_probe_builds_outside_subject_tree_and_emits_exact_raw_counters(self) -> None:
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go is unavailable")
        core = producer.REPOSITORY / "src" / "core" / "syswarden-core"
        version_environment = os.environ.copy()
        version_environment["GOTOOLCHAIN"] = "local"
        version = subprocess.check_output([go, "version"], text=True, env=version_environment).strip()
        if version != "go version go1.26.6 linux/amd64":
            auto_environment = os.environ.copy()
            auto_environment["GOTOOLCHAIN"] = "auto"
            goroot = subprocess.check_output(
                [go, "-C", str(core), "env", "GOROOT"],
                text=True,
                env=auto_environment,
            ).strip()
            candidate_go = str(Path(goroot) / "bin" / "go")
            if not Path(candidate_go).is_file():
                self.skipTest(f"exact Go 1.26.6 toolchain is unavailable: {version}")
            candidate_version = subprocess.check_output(
                [candidate_go, "version"], text=True, env=version_environment
            ).strip()
            if candidate_version != "go version go1.26.6 linux/amd64":
                self.skipTest(
                    f"exact Go 1.26.6 toolchain is unavailable: {candidate_version}"
                )
            go = candidate_go
        probe = self.root / "candidate-probe"
        cache = self.root / "gocache"
        temporary = self.root / "gotmp"
        cache.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        environment = os.environ.copy()
        environment.update({
            "GOWORK": "off",
            "GOFLAGS": "-mod=readonly",
            "GOCACHE": str(cache),
            "GOTMPDIR": str(temporary),
            "CGO_ENABLED": "0",
            "GOOS": "linux",
            "GOARCH": "amd64",
            "GOTOOLCHAIN": "local",
        })
        completed = subprocess.run(
            [go, "-C", str(core), "build", "-trimpath", "-buildvcs=false", "-o", str(probe), str(producer.DEFAULT_BENCHMARK)],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr.decode("utf-8", "replace"))
        probe.chmod(0o700)
        fixture = self.root / "fixture.json"
        catalog = self.root / "signature-catalog.json"
        fixture.write_bytes(producer.DEFAULT_FIXTURE.read_bytes())
        catalog.write_bytes(producer.DEFAULT_CATALOG.read_bytes())
        fixture.chmod(0o600)
        catalog.chmod(0o600)
        probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
        fixture_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
        catalog_sha = hashlib.sha256(catalog.read_bytes()).hexdigest()
        candidate = subprocess.check_output(["git", "-C", str(producer.REPOSITORY), "rev-parse", "HEAD"], text=True).strip()
        tree = subprocess.check_output(["git", "-C", str(producer.REPOSITORY), "rev-parse", "HEAD^{tree}"], text=True).strip()
        request = {
            "schema_version": 1,
            "repository": "duggytuxy/syswarden",
            "target_release": "v4.10.0",
            "candidate_commit": candidate,
            "baseline_release": "v4.04.3",
            "baseline_commit": "381c1f8d91459a9b20605629c725900abd81dee8",
            "campaign_id": "allocation-campaign-01",
            "campaign_recorded_at": "2026-09-10T08:00:00Z",
            "sample_index": 1,
            "invocation_index": 2,
            "sample_id": "allocation-campaign-01-candidate-01",
            "process_nonce": "0123456789abcdef0123456789abcdef",
            "subject_role": "candidate",
            "subject_release": "v4.10.0",
            "subject_commit": candidate,
            "subject_tree": tree,
            "probe_binary_sha256": probe_sha,
            "module_graph_sha256": "1" * 64,
            "environment_sha256": "2" * 64,
            "build_attestation_sha256": "3" * 64,
            "benchmark_source_sha256": hashlib.sha256(producer.DEFAULT_BENCHMARK.read_bytes()).hexdigest(),
            "fixture_path": str(fixture),
            "fixture_sha256": fixture_sha,
            "signature_catalog_path": str(catalog),
            "signature_catalog_sha256": catalog_sha,
            "toolchain_version": "go1.26.6",
            "toolchain_archive_sha256": "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89",
            "workload_id": "syswarden-waap-engine-scan-allocation-workload/v1",
        }
        raw = producer._invoke_probe(probe, probe_sha, request, 30)
        document = json.loads(raw)
        self.assertEqual(document["workload"]["warmup_events"], 256)
        self.assertEqual(document["workload"]["requested_events"], 2048)
        self.assertEqual(document["workload"]["admitted_events"], 2048)
        self.assertEqual(document["workload"]["rejected_events"], 0)
        self.assertEqual(document["workload"]["goroutines_before"], 2)
        self.assertEqual(document["workload"]["goroutines_after"], 2)
        counters = document["counters"]
        malloc_delta = int(counters["mallocs_after"]) - int(counters["mallocs_before"])
        byte_delta = int(counters["total_alloc_bytes_after"]) - int(counters["total_alloc_bytes_before"])
        self.assertEqual(malloc_delta == 0, byte_delta == 0)
        self.assertEqual(counters["gc_cycles_before"], counters["gc_cycles_after"])


if __name__ == "__main__":
    unittest.main()
