#!/usr/bin/env python3
"""Contract tests for the isolated Go 1.27 evaluation lane."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
METADATA = REPOSITORY / "scripts" / "ci" / "go_toolchain_evaluation.json"
WORKFLOW = REPOSITORY / ".github" / "workflows" / "go-127-evaluation.yml"
EVALUATOR = REPOSITORY / "scripts" / "ci" / "go_toolchain_evaluation.py"
ROLLBACK = REPOSITORY / "scripts" / "ci" / "go_toolchain_rollback.py"
PROBE = REPOSITORY / "scripts" / "ci" / "go127_protocol_probe.go"


def literal_run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*\|\s*$", lines[index])
        if match is None:
            index += 1
            continue
        indentation = len(match.group(1))
        body: list[str] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
                break
            body.append(candidate)
            index += 1
        blocks.append("\n".join(body))
    return blocks


class GoToolchainEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = json.loads(METADATA.read_text(encoding="utf-8"))
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.run_blocks = literal_run_blocks(cls.workflow)

    def test_metadata_is_closed_and_exact(self) -> None:
        self.assertEqual(
            set(self.metadata),
            {
                "schema_version",
                "architecture",
                "release_toolchain_unchanged",
                "measurement",
                "rollback",
                "toolchains",
            },
        )
        self.assertEqual(self.metadata["schema_version"], 2)
        self.assertEqual(self.metadata["architecture"], "linux/amd64")
        self.assertIs(self.metadata["release_toolchain_unchanged"], True)
        expected = {
            "baseline": (
                "go1.26.6",
                66890545,
                "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89",
            ),
            "candidate": (
                "go1.27.1",
                70553950,
                "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
            ),
        }
        self.assertEqual(set(self.metadata["toolchains"]), set(expected))
        for role, (version, size, sha256) in expected.items():
            with self.subTest(role=role):
                record = self.metadata["toolchains"][role]
                self.assertEqual(
                    set(record), {"version", "filename", "url", "size", "sha256"}
                )
                filename = f"{version}.linux-amd64.tar.gz"
                self.assertEqual(record["version"], version)
                self.assertEqual(record["filename"], filename)
                self.assertEqual(record["url"], f"https://go.dev/dl/{filename}")
                self.assertEqual(record["size"], size)
                self.assertEqual(record["sha256"], sha256)
                self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")

        measurement = self.metadata["measurement"]
        self.assertEqual(measurement["samples_per_toolchain"], 9)
        self.assertEqual(measurement["operations_per_sample"], 2048)
        self.assertEqual(
            set(measurement["protocols"]),
            {
                "http1_keepalive",
                "tls13",
                "bounded_response_headers",
                "strict_json",
                "ed25519_manifest",
            },
        )
        self.assertEqual(
            set(measurement["bounds"]),
            {
                "cpu_nanoseconds_per_request",
                "rss_bytes",
                "allocations_per_request",
                "allocated_bytes_per_request",
                "http_requests_per_second",
                "binary_bytes",
                "package_bytes",
            },
        )
        for name, bound in measurement["bounds"].items():
            with self.subTest(bound=name):
                self.assertEqual(bound["maximum_regression_percent"], 10.0)
                self.assertGreaterEqual(bound["absolute_noise_allowance"], 0.0)
        self.assertEqual(
            measurement["binaries"],
            ["syswarden-cli", "syswarden-core", "syswarden-tui"],
        )
        self.assertEqual(measurement["packages"], ["deb", "rpm", "apk"])
        self.assertEqual(self.metadata["rollback"]["from"], "go1.27.1")
        self.assertEqual(self.metadata["rollback"]["to"], "go1.26.6")
        self.assertEqual(len(self.metadata["rollback"]["directive_files"]), 5)
        self.assertEqual(self.metadata["rollback"]["builder_file"], "build_packages.sh")
        self.assertEqual(len(self.metadata["rollback"]["required_files"]), 6)
        self.assertEqual(
            self.metadata["rollback"]["required_files"],
            [*self.metadata["rollback"]["directive_files"], "build_packages.sh"],
        )

    def test_workflow_is_manual_read_only_and_non_publishing(self) -> None:
        trigger = self.workflow.split("\npermissions:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:\n", trigger)
        self.assertNotIn("pull_request", trigger)
        self.assertNotIn("push:", trigger)
        self.assertIn("permissions:\n  contents: read\n", self.workflow)
        for forbidden in (
            "id-token: write",
            "contents: write",
            "packages: write",
            "secrets.",
            "gh release",
            "softprops/action-gh-release",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.workflow.lower())
        self.assertEqual(self.workflow.count("actions/upload-artifact@"), 1)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            self.workflow,
        )
        self.assertIn("retention-days: 30", self.workflow)
        self.assertIn("compression-level: 0", self.workflow)

    def test_workflow_verifies_downloads_and_preserves_release_toolchain(self) -> None:
        self.assertIn(
            'test "$(jq -er \'.schema_version\' "${metadata}")" = "2"',
            self.workflow,
        )
        stale_schema_check = (
            'test "$(jq -er \'.schema_version\' "${metadata}")" = "' + "1" + '"'
        )
        self.assertNotIn(stale_schema_check, self.workflow)
        required = (
            "--proto '=https'",
            "--proto-redir '=https'",
            "--max-redirs 3",
            "--connect-timeout 15",
            "--max-time 300",
            "sha256sum --check --strict",
            "GOTOOLCHAIN=local",
            "go127_goroutineleak_probe_test.go",
            "for experiment in jsonv2 nojsonv2",
            'GOEXPERIMENT="${experiment}"',
            "go127-${experiment}.ok",
            "go127-jsonv2.ok",
            "go127-nojsonv2.ok",
            "test -race -mod=readonly",
            "vet -mod=readonly",
            "-fuzztime=100000x",
            "FuzzCompileOperatorTransportPolicyClosed",
            "FuzzSelect",
            "cmp --silent",
            "go127-binary-records.tsv",
            "go127-package-records.tsv",
            "go127-protocol-records.jsonl",
            "go127_protocol_probe.go",
            "go_toolchain_evaluation.py",
            "go_toolchain_rollback.py",
            'test "${#required_files[@]}" -eq 6',
            "builder_pin_verified: true",
            "package builder was not restored to exact Go 1.26.6 anchors",
            '"defer-go1.27-keep-go1.26.6"',
            '.native_qualification == "pending-external-evidence"',
            '.gates.toolchain_rollback == "pass"',
            '.gates.package_size_bounds == "pass"',
            '.gates.performance_bounds == "pass"',
            "syswarden-go127-evaluation-${{ github.sha }}",
            "repository_state.py verify",
            "--snapshot",
        )
        for contract in required:
            with self.subTest(contract=contract):
                self.assertIn(contract, self.workflow)
        self.assertNotIn("go-version: '1.27", self.workflow)
        self.assertIsNone(re.search(r"(?m)^\s*go\s+1\.27", self.workflow))

    def test_every_literal_run_block_parses_as_bash(self) -> None:
        self.assertTrue(self.run_blocks)
        for index, block in enumerate(self.run_blocks):
            result = subprocess.run(
                ["bash", "-n"],
                input=textwrap.dedent(block),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"run block {index} is not valid bash: {result.stderr}",
            )

    def test_firewall_sandbox_is_enforced_before_functional_tests(self) -> None:
        sandbox_name = "Prepare enforced firewall test sandbox"
        self.assertLess(
            self.workflow.index(sandbox_name),
            self.workflow.index("Run Go 1.27 functional, race and vet gates"),
        )
        preparation = self.workflow.split(sandbox_name, 1)[1].split(
            "      - name: Run Go 1.27 functional, race and vet gates", 1
        )[0]
        audit = (REPOSITORY / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        start = '          test "$(bwrap --version)"'
        end = '            echo "ERROR: Bubblewrap child retained usable capabilities."'
        approved = audit[audit.index(start):audit.index(end)]
        self.assertIn(approved, preparation)
        self.assertIn("rpm bubblewrap=0.9.0-1ubuntu0.1", self.workflow)
        self.assertIn('GOTOOLCHAIN=local CI=true "${CANDIDATE_GO}"', preparation)
        self.assertIn(
            "^Test(NftablesRulesGolden|BubblewrapFirewallGoldenTemporaryDirectoryContract)_SW_QA_001$",
            preparation,
        )
        for bypass in ("sysctl -w", "aa-disable", "aa-complain", "|| true"):
            self.assertNotIn(bypass, preparation)

    def test_package_comparison_prepares_clean_exact_experimental_commit(self) -> None:
        block = next(
            block for block in self.run_blocks
            if 'records="${RUNNER_TEMP}/go127-package-records.tsv"' in block
        )
        preparation = block.split('            PATH="$(dirname "${tool}"):', 1)[0]
        preparation = textwrap.dedent(preparation) + "\ndone\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            runner = root / "runner"
            runner.mkdir()
            builder = source / "build_packages.sh"
            original = "# go1.26.6 go1.26.6\n# Go 1.26.6 Go 1.26.6 Go 1.26.6\n"
            builder.write_text(original, encoding="utf-8")
            (source / "product-source.txt").write_text("unchanged product\n", encoding="utf-8")

            def git(directory: Path, *arguments: str) -> str:
                return subprocess.check_output(
                    ["git", "-c", "core.fsmonitor=false", "-C", str(directory), *arguments],
                    text=True, stderr=subprocess.PIPE,
                ).strip()

            git(source, "init", "--quiet")
            git(source, "add", "build_packages.sh", "product-source.txt")
            git(source, "-c", "user.name=Evaluation test", "-c",
                "user.email=evaluation-test@syswarden.invalid", "-c",
                "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture source")
            original_commit = git(source, "rev-parse", "HEAD")
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", preparation],
                env={
                    **os.environ,
                    "GITHUB_WORKSPACE": str(source), "RUNNER_TEMP": str(runner),
                    "CANDIDATE_COMMIT": original_commit,
                    "BASELINE_GO": "/unused/baseline/go", "CANDIDATE_GO": "/unused/candidate/go",
                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                    "GIT_CONFIG_VALUE_0": "false",
                },
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            baseline = runner / "go127-package-baseline"
            candidate = runner / "go127-package-candidate"
            for checkout in (source, baseline, candidate):
                self.assertEqual(git(checkout, "status", "--porcelain"), "")
                self.assertEqual((checkout / "product-source.txt").read_text(), "unchanged product\n")
            self.assertEqual(git(source, "rev-parse", "HEAD"), original_commit)
            self.assertEqual(git(baseline, "rev-parse", "HEAD"), original_commit)
            self.assertEqual(git(candidate, "rev-parse", "HEAD^"), original_commit)
            self.assertEqual(git(candidate, "diff", "--name-only", "HEAD^", "HEAD"), "build_packages.sh")
            self.assertEqual(
                git(candidate, "show", "-s", "--format=%cI", "HEAD"),
                git(source, "show", "-s", "--format=%cI", "HEAD"),
            )
            self.assertEqual(builder.read_text(), original)
            self.assertEqual(
                (candidate / "build_packages.sh").read_text(),
                original.replace("go1.26.6", "go1.27.1").replace("Go 1.26.6", "Go 1.27.1"),
            )
            self.assertEqual(result.stdout.count("Package comparison source:"), 2)


class GoToolchainEvaluationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        metadata = json.loads(METADATA.read_text(encoding="utf-8"))
        self.measurements = self.root / "measurements.jsonl"
        protocols = {name: "pass" for name in metadata["measurement"]["protocols"]}
        records = []
        for role in ("baseline", "candidate"):
            factor = 1.02 if role == "candidate" else 1.0
            for sample in range(1, 10):
                records.append(
                    {
                        "schema_version": 1,
                        "role": role,
                        "sample": sample,
                        "operations": 2048,
                        "protocols": protocols,
                        "metrics": {
                            "cpu_nanoseconds_per_request": 100000.0 * factor,
                            "rss_bytes": 20000000.0 * factor,
                            "allocations_per_request": 100.0 * factor,
                            "allocated_bytes_per_request": 4096.0 * factor,
                            "http_requests_per_second": 10000.0 / factor,
                        },
                    }
                )
        self.measurements.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )
        self.binaries = self.root / "binaries.tsv"
        self.packages = self.root / "packages.tsv"
        self.binaries.write_text(
            "".join(
                f"{role}\t{name}\t{1000 if role == 'baseline' else 1050}\t{'a' * 64}\n"
                for role in ("baseline", "candidate")
                for name in ("syswarden-cli", "syswarden-core", "syswarden-tui")
            ),
            encoding="utf-8",
        )
        self.packages.write_text(
            "".join(
                f"{role}\t{name}\t{2000 if role == 'baseline' else 2100}\t{'b' * 64}\n"
                for role in ("baseline", "candidate")
                for name in ("deb", "rpm", "apk")
            ),
            encoding="utf-8",
        )
        self.rollback = self.root / "rollback.json"
        self.rollback.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    **metadata["rollback"],
                    "source_byte_exact": True,
                    "builder_pin_verified": True,
                    "baseline_protocol_tests": "pass",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_evaluator(self) -> subprocess.CompletedProcess[str]:
        output = self.root / "evaluation.json"
        output.unlink(missing_ok=True)
        return subprocess.run(
            [
                "python3",
                str(EVALUATOR),
                "--metadata",
                str(METADATA),
                "--measurements",
                str(self.measurements),
                "--binaries",
                str(self.binaries),
                "--packages",
                str(self.packages),
                "--rollback",
                str(self.rollback),
                "--candidate-commit",
                "c" * 40,
                "--runner-os",
                "Linux",
                "--runner-arch",
                "X64",
                "--output",
                str(output),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_evaluator_seals_bounded_deferment(self) -> None:
        result = self.run_evaluator()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.root / "evaluation.json").read_text())
        self.assertEqual(evidence["contract_id"], "syswarden-go-toolchain-evaluation/v2")
        self.assertEqual(evidence["adoption_decision"], "defer-go1.27-keep-go1.26.6")
        self.assertEqual(evidence["native_qualification"], "pending-external-evidence")
        self.assertTrue(all(value == "pass" for value in evidence["gates"].values()))

    def test_evaluator_rejects_performance_regression(self) -> None:
        records = [json.loads(line) for line in self.measurements.read_text().splitlines()]
        for record in records:
            if record["role"] == "candidate":
                record["metrics"]["cpu_nanoseconds_per_request"] = 200000.0
        self.measurements.write_text("".join(json.dumps(item) + "\n" for item in records))
        self.assertNotEqual(self.run_evaluator().returncode, 0)

    def test_evaluator_rejects_one_protocol_failure(self) -> None:
        records = [json.loads(line) for line in self.measurements.read_text().splitlines()]
        records[-1]["protocols"]["tls13"] = "fail"
        self.measurements.write_text("".join(json.dumps(item) + "\n" for item in records))
        self.assertNotEqual(self.run_evaluator().returncode, 0)

    def test_evaluator_rejects_package_size_regression(self) -> None:
        self.packages.write_text(
            self.packages.read_text().replace(
                "candidate\trpm\t2100", "candidate\trpm\t2400"
            )
        )
        self.assertNotEqual(self.run_evaluator().returncode, 0)

    def test_evaluator_rejects_missing_sample_and_duplicate_key(self) -> None:
        lines = self.measurements.read_text().splitlines()
        self.measurements.write_text("\n".join(lines[:-1]) + "\n")
        self.assertNotEqual(self.run_evaluator().returncode, 0)
        self.measurements.write_text(
            "".join(line + "\n" for line in lines).replace(
                '"schema_version": 1,',
                '"schema_version": 1, "schema_version": 1,',
                1,
            )
        )
        self.assertNotEqual(self.run_evaluator().returncode, 0)


class GoToolchainRollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        rollback = json.loads(METADATA.read_text())["rollback"]
        self.required = rollback["required_files"]
        self.builder = rollback["builder_file"]
        self.builder_candidate = (
            b'GO_TOOLCHAIN_ROOT="$(GOTOOLCHAIN=go1.27.1 GOPROXY=off go env GOROOT)"\n'
            b'go1.27.1\n'
            b'Go 1.27.1\nGo 1.27.1\nGo 1.27.1\n'
        )
        for relative in self.required:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                self.builder_candidate
                if relative == self.builder
                else b"module example.invalid/test\n\ngo 1.27.1\n"
            )
            path.chmod(0o644)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_rollback(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(ROLLBACK),
                "--repository",
                str(self.root),
                "--from-toolchain",
                "go1.27.1",
                "--to-toolchain",
                "go1.26.6",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_exact_rollback_restores_every_required_directive(self) -> None:
        result = self.run_rollback()
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative in self.required:
            wire = (self.root / relative).read_bytes()
            if relative == self.builder:
                self.assertEqual(wire.count(b"go1.26.6"), 2)
                self.assertEqual(wire.count(b"Go 1.26.6"), 3)
                self.assertNotIn(b"1.27.1", wire)
            else:
                self.assertEqual(wire, b"module example.invalid/test\n\ngo 1.26.6\n")

    def test_rollback_rejects_wrong_version_and_symbolic_link(self) -> None:
        first = self.root / self.required[0]
        first.write_bytes(first.read_bytes().replace(b"1.27.1", b"1.27.0"))
        self.assertNotEqual(self.run_rollback().returncode, 0)
        first.write_bytes(b"module example.invalid/test\n\ngo 1.27.1\n")
        linked = self.root / "linked"
        first.rename(linked)
        first.symlink_to(linked)
        self.assertNotEqual(self.run_rollback().returncode, 0)

    def test_rollback_preflight_prevents_partial_source_change(self) -> None:
        last = self.root / self.required[-1]
        last.write_bytes(last.read_bytes().replace(b"1.27.1", b"1.27.0"))
        self.assertNotEqual(self.run_rollback().returncode, 0)
        for relative in self.required[:-1]:
            self.assertIn(b"go 1.27.1\n", (self.root / relative).read_bytes())

    def test_repository_builder_roundtrip_is_byte_exact(self) -> None:
        pristine: dict[str, bytes] = {}
        for relative in self.required:
            source = REPOSITORY / relative
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o644 if relative != self.builder else 0o755)
            pristine[relative] = destination.read_bytes()
            if relative == self.builder:
                destination.write_bytes(
                    pristine[relative]
                    .replace(b"go1.26.6", b"go1.27.1")
                    .replace(b"Go 1.26.6", b"Go 1.27.1")
                )
            else:
                destination.write_bytes(
                    pristine[relative].replace(b"go 1.26.6\n", b"go 1.27.1\n")
                )
        result = self.run_rollback()
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative, expected in pristine.items():
            self.assertEqual((self.root / relative).read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
