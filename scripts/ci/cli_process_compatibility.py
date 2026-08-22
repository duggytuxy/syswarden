#!/usr/bin/env python3
"""Compare the frozen v4.02.8 CLI process contract with the candidate.

The gate reconstructs the baseline from its immutable Git commit and copies the
current CLI module into an isolated temporary workspace.  It never executes a
successful host-mutating subcommand: the process matrix is limited to root
startup, Cobra help, an unknown command, and argument counts that Cobra rejects
before a command handler can run.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


BASELINE_VERSION = "v4.02.8"
BASELINE_COMMIT = "371d353e871fedb410b08f0618a1ae6aa2f7fedc"
PUBLIC_FIELDS = ("use", "short", "long", "example", "flags", "arg_outcomes")
SNAPSHOT_PROBE_NAME = "zz_lot0_cli_process_probe_test.go"


class CompatibilityError(ValueError):
    """Raised when the CLI compatibility proof cannot be completed safely."""


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProcessCase:
    case_id: str
    category: str
    path: str
    argv: tuple[str, ...]
    expected_error: str = ""


SNAPSHOT_PROBE = r'''package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type lot0ProcessCommandContract struct {
	Path        string                       `json:"path"`
	Use         string                       `json:"use"`
	Short       string                       `json:"short"`
	Long        string                       `json:"long,omitempty"`
	Example     string                       `json:"example,omitempty"`
	Flags       []lot0ProcessFlagContract    `json:"flags,omitempty"`
	ArgOutcomes map[string]string            `json:"arg_outcomes"`
}

type lot0ProcessFlagContract struct {
	Name       string `json:"name"`
	Shorthand  string `json:"shorthand,omitempty"`
	Type       string `json:"type"`
	Default    string `json:"default"`
	NoOption   string `json:"no_option,omitempty"`
	Usage      string `json:"usage"`
	Persistent bool   `json:"persistent,omitempty"`
}

func TestLot0CLIProcessSnapshotProbe(t *testing.T) {
	output := os.Getenv("SYSWARDEN_CLI_PROCESS_SNAPSHOT")
	if output == "" {
		t.Fatal("SYSWARDEN_CLI_PROCESS_SNAPSHOT is required")
	}
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	var contracts []lot0ProcessCommandContract
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		if command != rootCmd && command.Hidden { return }
		command.InitDefaultHelpFlag()
		contract := lot0ProcessCommandContract{
			Path: command.CommandPath(), Use: command.Use, Short: command.Short,
			Long: command.Long, Example: command.Example,
			ArgOutcomes: make(map[string]string),
		}
		seen := make(map[string]bool)
		appendFlags := func(flags *pflag.FlagSet, persistent bool) {
			flags.VisitAll(func(flag *pflag.Flag) {
				if seen[flag.Name] { return }
				seen[flag.Name] = true
				contract.Flags = append(contract.Flags, lot0ProcessFlagContract{
					Name: flag.Name, Shorthand: flag.Shorthand, Type: flag.Value.Type(),
					Default: flag.DefValue, NoOption: flag.NoOptDefVal,
					Usage: flag.Usage, Persistent: persistent,
				})
			})
		}
		appendFlags(command.LocalNonPersistentFlags(), false)
		appendFlags(command.PersistentFlags(), true)
		appendFlags(command.InheritedFlags(), true)
		sort.Slice(contract.Flags, func(i, j int) bool {
			return contract.Flags[i].Name < contract.Flags[j].Name
		})
		for count := 0; count <= 4; count++ {
			outcome := "ok"
			if command.Args != nil {
				args := make([]string, count)
				for index := range args { args[index] = fmt.Sprintf("arg-%d", index+1) }
				if err := command.Args(command, args); err != nil { outcome = err.Error() }
			}
			contract.ArgOutcomes[fmt.Sprintf("%d", count)] = outcome
		}
		contracts = append(contracts, contract)
		children := command.Commands()
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children { walk(child) }
	}
	walk(rootCmd)
	encoded, err := json.MarshalIndent(contracts, "", "  ")
	if err != nil { t.Fatal(err) }
	encoded = append(encoded, '\n')
	if err := os.WriteFile(output, encoded, 0600); err != nil { t.Fatal(err) }
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"required regular JSON file is missing: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"cannot read JSON file {path}: {exc}") from exc


def run_checked(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    binary: bool = False,
) -> str | bytes:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=not binary,
        )
    except OSError as exc:
        raise CompatibilityError(f"cannot execute {argv[0]!r}: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace") if binary else exc.stderr
        stdout = exc.stdout.decode("utf-8", "replace") if binary else exc.stdout
        raise CompatibilityError(
            f"command failed ({exc.returncode}): {' '.join(argv)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from exc
    return completed.stdout


def readonly_git_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def git_output(repo_root: Path, *args: str, binary: bool = False) -> str | bytes:
    return run_checked(
        ["git", "-c", "core.fsmonitor=false", "-C", str(repo_root), *args],
        cwd=repo_root,
        env=readonly_git_env(),
        binary=binary,
    )


def git_state(repo_root: Path) -> dict[str, str]:
    head = str(git_output(repo_root, "rev-parse", "HEAD")).strip()
    status = bytes(
        git_output(
            repo_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            binary=True,
        )
    )
    index = repo_root / ".git/index"
    if not index.is_file():
        raise CompatibilityError(f"Git index is missing: {index}")
    try:
        index_rows = str(
            git_output(repo_root, "ls-files", "--stage", "--eol")
        ).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CompatibilityError(f"Git index inventory is not valid UTF-8: {exc}") from exc
    return {
        "head": head,
        "status_sha256": sha256_bytes(status),
        "index_manifest_sha256": sha256_bytes(index_rows),
    }


def scoped_repository_state(repo_root: Path) -> dict[str, str]:
    """Hash every in-scope input while allowing unrelated parallel lab output."""

    roots = [
        repo_root / "src/core/syswarden-cli",
        repo_root / "testdata/contracts",
    ]
    files = [
        repo_root / "scripts/ci/documentation_contract.json",
        repo_root / "scripts/ci/cli_process_compatibility.py",
    ]
    inventory: list[dict[str, object]] = []
    for root in roots:
        _, records = source_manifest(root)
        prefix = root.relative_to(repo_root).as_posix()
        inventory.extend(
            {**record, "path": f"{prefix}/{record['path']}"} for record in records
        )
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise CompatibilityError(f"required regular gate input is missing: {path}")
        content = path.read_bytes()
        inventory.append(
            {
                "path": path.relative_to(repo_root).as_posix(),
                "bytes": len(content),
                "sha256": sha256_bytes(content),
            }
        )
    inventory.sort(key=lambda item: str(item["path"]))
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return {"manifest_sha256": sha256_bytes(encoded), "file_count": str(len(inventory))}


def validate_snapshot(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise CompatibilityError(f"{label} must be a non-empty JSON array")
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise CompatibilityError(f"{label}[{index}] must be an object")
        path = raw.get("path")
        if not isinstance(path, str) or (
            path != "syswarden" and not path.startswith("syswarden ")
        ):
            raise CompatibilityError(f"{label}[{index}] has invalid path: {path!r}")
        if path in seen:
            raise CompatibilityError(f"{label} contains duplicate path: {path!r}")
        seen.add(path)
        record: dict[str, object] = {"path": path}
        for field in ("use", "short", "long", "example"):
            item = raw.get(field, "")
            if not isinstance(item, str):
                raise CompatibilityError(f"{label} {path!r} field {field!r} is not text")
            record[field] = item
        flags = raw.get("flags", [])
        if not isinstance(flags, list) or not all(isinstance(flag, dict) for flag in flags):
            raise CompatibilityError(f"{label} {path!r} flags must be an object array")
        outcomes = raw.get("arg_outcomes")
        if not isinstance(outcomes, dict) or set(outcomes) != {"0", "1", "2", "3", "4"}:
            raise CompatibilityError(
                f"{label} {path!r} arg_outcomes must contain exactly counts 0 through 4"
            )
        if not all(isinstance(outcome, str) and outcome for outcome in outcomes.values()):
            raise CompatibilityError(f"{label} {path!r} has invalid argument outcomes")
        record["flags"] = flags
        record["arg_outcomes"] = outcomes
        records.append(record)
    if "syswarden" not in seen:
        raise CompatibilityError(f"{label} does not contain the root command")
    return records


def public_differences(
    baseline: Iterable[dict[str, object]], candidate: Iterable[dict[str, object]]
) -> list[dict[str, object]]:
    before = {str(record["path"]): record for record in baseline}
    after = {str(record["path"]): record for record in candidate}
    changes: list[dict[str, object]] = []
    for path in sorted(set(before) | set(after)):
        if path not in before:
            changes.append({"path": path, "field": "command", "before": None, "after": "added"})
            continue
        if path not in after:
            changes.append({"path": path, "field": "command", "before": "present", "after": None})
            continue
        for field in PUBLIC_FIELDS:
            old = before[path].get(field, "")
            new = after[path].get(field, "")
            if old != new:
                changes.append({"path": path, "field": field, "before": old, "after": new})
    return changes


def classify_public_differences(
    changes: Sequence[dict[str, object]], approvals: object
) -> list[dict[str, object]]:
    if not isinstance(approvals, list):
        raise CompatibilityError("approved_cli_public_differences must be an array")
    expected: dict[tuple[str, str], dict[str, object]] = {}
    for index, approval in enumerate(approvals):
        if not isinstance(approval, dict):
            raise CompatibilityError(f"CLI approval {index} must be an object")
        path, field = approval.get("path"), approval.get("field")
        reason = approval.get("reason")
        if not isinstance(path, str) or not isinstance(field, str):
            raise CompatibilityError(f"CLI approval {index} needs text path and field")
        if field not in PUBLIC_FIELDS and field != "command":
            raise CompatibilityError(f"CLI approval {index} has unsupported field {field!r}")
        if not isinstance(reason, str) or not reason.strip():
            raise CompatibilityError(f"CLI approval {index} needs a non-empty reason")
        if "before" not in approval or "after" not in approval:
            raise CompatibilityError(f"CLI approval {index} needs exact before and after values")
        key = (path, field)
        if key in expected:
            raise CompatibilityError(f"duplicate CLI approval: {path!r} {field!r}")
        expected[key] = approval

    classified: list[dict[str, object]] = []
    actual_keys: set[tuple[str, str]] = set()
    for change in changes:
        key = (str(change["path"]), str(change["field"]))
        actual_keys.add(key)
        approval = expected.get(key)
        if approval is None:
            raise CompatibilityError(
                f"unapproved CLI public difference: {key[0]!r} {key[1]!r}"
            )
        if approval["before"] != change["before"] or approval["after"] != change["after"]:
            raise CompatibilityError(
                f"CLI approval values do not match {key[0]!r} {key[1]!r}; "
                f"approved before={approval['before']!r}, after={approval['after']!r}; "
                f"actual before={change['before']!r}, after={change['after']!r}"
            )
        classified.append({**change, "reason": approval["reason"]})

    stale = sorted(set(expected) - actual_keys)
    if stale:
        raise CompatibilityError(f"stale CLI public approvals without a difference: {stale}")
    return classified


def safe_extract_tar(archive: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for member in bundle.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise CompatibilityError(f"unsafe path in Git archive: {member.name!r}")
                if not (member.isdir() or member.isfile()):
                    raise CompatibilityError(
                        f"unsupported non-regular member in Git archive: {member.name!r}"
                    )
                target = (root / Path(*path.parts)).resolve()
                if root != target and root not in target.parents:
                    raise CompatibilityError(f"Git archive escapes workspace: {member.name!r}")
            bundle.extractall(destination, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise CompatibilityError(f"cannot extract baseline Git archive: {exc}") from exc


def source_manifest(root: Path) -> tuple[str, list[dict[str, object]]]:
    if root.is_symlink() or not root.is_dir():
        raise CompatibilityError(f"CLI module is not a regular directory: {root}")
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise CompatibilityError(f"CLI source contains unsupported symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise CompatibilityError(f"CLI source contains non-regular entry: {relative}")
        content = path.read_bytes()
        records.append(
            {"path": relative, "bytes": len(content), "sha256": sha256_bytes(content)}
        )
    if not records:
        raise CompatibilityError(f"CLI source inventory is empty: {root}")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded), records


def copy_candidate_module(source: Path, destination: Path) -> tuple[str, int]:
    before_digest, before_records = source_manifest(source)
    try:
        shutil.copytree(source, destination, symlinks=True)
    except OSError as exc:
        raise CompatibilityError(f"cannot copy candidate CLI module: {exc}") from exc
    copied_digest, copied_records = source_manifest(destination)
    after_digest, after_records = source_manifest(source)
    if not (
        before_digest == copied_digest == after_digest
        and before_records == copied_records == after_records
    ):
        raise CompatibilityError("candidate CLI source changed while its isolated copy was created")
    return copied_digest, len(copied_records)


def baseline_command_source_digest(repo_root: Path, commit: str) -> str:
    tree = str(
        git_output(
            repo_root,
            "ls-tree",
            "-r",
            "--name-only",
            commit,
            "--",
            "src/core/syswarden-cli/cmd",
        )
    )
    paths = sorted(
        path
        for path in tree.splitlines()
        if re.fullmatch(r"src/core/syswarden-cli/cmd/[^/]+\.go", path)
        and not path.endswith("_test.go")
    )
    if not paths:
        raise CompatibilityError("baseline production command source inventory is empty")
    archive = bytes(
        git_output(
            repo_root,
            "archive",
            "--format=tar",
            commit,
            *paths,
            binary=True,
        )
    )
    return sha256_bytes(archive)


def verify_baseline_contract(
    repo_root: Path, contract: object
) -> tuple[Path, list[dict[str, object]], dict[str, str]]:
    if not isinstance(contract, dict) or not isinstance(contract.get("cli_baseline"), dict):
        raise CompatibilityError("documentation contract cli_baseline must be an object")
    metadata = contract["cli_baseline"]
    assert isinstance(metadata, dict)
    if metadata.get("version") != BASELINE_VERSION:
        raise CompatibilityError(
            f"CLI baseline version must remain {BASELINE_VERSION}, got {metadata.get('version')!r}"
        )
    if metadata.get("commit") != BASELINE_COMMIT:
        raise CompatibilityError(
            f"CLI baseline commit must remain {BASELINE_COMMIT}, got {metadata.get('commit')!r}"
        )
    resolved = str(git_output(repo_root, "rev-parse", f"{BASELINE_COMMIT}^{{commit}}")).strip()
    if resolved != BASELINE_COMMIT:
        raise CompatibilityError(
            f"baseline commit resolved to {resolved!r}, expected {BASELINE_COMMIT!r}"
        )
    version_source = str(
        git_output(
            repo_root,
            "show",
            f"{BASELINE_COMMIT}:src/core/syswarden-cli/pkg/system/upgrade.go",
        )
    )
    version = re.search(r'var Version = "(v[0-9]+\.[0-9]{2}\.[0-9]+)"', version_source)
    if version is None or version.group(1) != BASELINE_VERSION:
        raise CompatibilityError("baseline commit does not declare the frozen v4.02.8 version")

    snapshot_path = repo_root / f"testdata/contracts/cli-command-tree-{BASELINE_VERSION}.json"
    snapshot_bytes = snapshot_path.read_bytes()
    expected_snapshot_digest = metadata.get("sha256")
    actual_snapshot_digest = sha256_bytes(snapshot_bytes)
    if expected_snapshot_digest != actual_snapshot_digest:
        raise CompatibilityError(
            f"baseline snapshot digest mismatch: expected {expected_snapshot_digest!r}, "
            f"got {actual_snapshot_digest}"
        )
    source_digest = baseline_command_source_digest(repo_root, BASELINE_COMMIT)
    if metadata.get("source_archive_sha256") != source_digest:
        raise CompatibilityError(
            "baseline command-source archive digest does not match the documentation contract"
        )
    records = validate_snapshot(read_json(snapshot_path), "baseline CLI snapshot")
    return snapshot_path, records, {
        "version": BASELINE_VERSION,
        "commit": BASELINE_COMMIT,
        "snapshot_sha256": actual_snapshot_digest,
        "command_source_archive_sha256": source_digest,
    }


def isolated_go_env(cache: Path) -> dict[str, str]:
    cache.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(
        {
            "GOCACHE": str(cache),
            "GOFLAGS": "-mod=readonly",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }
    )
    return env


def reconstruct_snapshot(module: Path, env: dict[str, str], output: Path) -> bytes:
    probe = module / "cmd" / SNAPSHOT_PROBE_NAME
    if probe.exists():
        raise CompatibilityError(f"temporary snapshot probe path already exists: {probe}")
    probe.write_text(SNAPSHOT_PROBE, encoding="utf-8")
    probe.chmod(0o600)
    probe_env = env.copy()
    probe_env["SYSWARDEN_CLI_PROCESS_SNAPSHOT"] = str(output)
    run_checked(
        [
            "go",
            "test",
            "-mod=readonly",
            "-count=1",
            "-run=^TestLot0CLIProcessSnapshotProbe$",
            "./cmd",
        ],
        cwd=module,
        env=probe_env,
    )
    if not output.is_file():
        raise CompatibilityError(f"snapshot probe did not create its output: {output}")
    return output.read_bytes()


def build_binary(module: Path, env: dict[str, str], output: Path) -> str:
    run_checked(
        [
            "go",
            "build",
            "-mod=readonly",
            "-buildvcs=false",
            "-trimpath",
            "-o",
            str(output),
            ".",
        ],
        cwd=module,
        env=env,
    )
    if output.is_symlink() or not output.is_file():
        raise CompatibilityError(f"Go build did not produce a regular binary: {output}")
    return sha256_bytes(output.read_bytes())


def make_process_cases(records: Sequence[dict[str, object]]) -> list[ProcessCase]:
    cases = [
        ProcessCase("root", "root", "syswarden", ()),
        ProcessCase("unknown-command", "argument-validation", "syswarden", ("does-not-exist",), "unknown command"),
    ]
    for record in records:
        path = str(record["path"])
        prefix = tuple(path.split()[1:])
        cases.append(
            ProcessCase(
                f"help:{path}",
                "help",
                path,
                prefix + ("--help",),
            )
        )
        # Only top-level product commands enter the rejected-arity matrix. Cobra's
        # generated completion/help command tree has dispatch semantics that are
        # not represented by calling Command.Args directly, and successful
        # utility execution is not an argument-validation proof.
        if len(path.split()) != 2 or path.split()[1] in {"completion", "help"}:
            continue
        outcomes = record["arg_outcomes"]
        assert isinstance(outcomes, dict)
        for count in range(5):
            outcome = str(outcomes[str(count)])
            if outcome == "ok":
                continue
            args = prefix + tuple(f"arg-{index}" for index in range(1, count + 1))
            cases.append(
                ProcessCase(
                    f"arity:{path}:{count}",
                    "argument-validation",
                    path,
                    args,
                    outcome,
                )
            )
    identifiers = [case.case_id for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise CompatibilityError("generated CLI process case identifiers are not unique")
    return cases


def approved_common_command_paths(
    baseline: Mapping[str, dict[str, object]],
    candidate: Mapping[str, dict[str, object]],
    approved_changes: Sequence[dict[str, object]],
) -> set[str]:
    approved_removed = {
        str(change["path"])
        for change in approved_changes
        if change.get("field") == "command"
        and change.get("before") == "present"
        and change.get("after") is None
    }
    approved_added = {
        str(change["path"])
        for change in approved_changes
        if change.get("field") == "command"
        and change.get("before") is None
        and change.get("after") == "added"
    }
    actual_removed = set(baseline) - set(candidate)
    actual_added = set(candidate) - set(baseline)
    if actual_removed != approved_removed or actual_added != approved_added:
        raise CompatibilityError(
            "approved CLI command additions/removals do not match the exact snapshot transition"
        )
    if "syswarden" not in baseline or "syswarden" not in candidate:
        raise CompatibilityError("the root command cannot be added or removed")
    return set(baseline) & set(candidate)


def run_process(binary: Path, case: ProcessCase, cwd: Path) -> ProcessResult:
    try:
        completed = subprocess.run(
            [str(binary), *case.argv],
            cwd=cwd,
            env=os.environ.copy(),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise CompatibilityError(f"cannot execute safe case {case.case_id!r}: {exc}") from exc
    return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


def validate_case_result(case: ProcessCase, result: ProcessResult, side: str) -> None:
    if case.category in {"root", "help"}:
        if result.exit_code != 0:
            raise CompatibilityError(
                f"{side} {case.case_id} exited {result.exit_code}, expected 0; "
                f"stderr={result.stderr!r}"
            )
        if result.stderr:
            raise CompatibilityError(
                f"{side} {case.case_id} unexpectedly wrote stderr: {result.stderr!r}"
            )
        if not result.stdout:
            raise CompatibilityError(f"{side} {case.case_id} produced empty stdout")
        return
    if result.exit_code != 1:
        raise CompatibilityError(
            f"{side} {case.case_id} exited {result.exit_code}, expected 1"
        )
    if result.stdout:
        raise CompatibilityError(
            f"{side} {case.case_id} unexpectedly wrote stdout: {result.stdout!r}"
        )
    if case.expected_error not in result.stderr:
        raise CompatibilityError(
            f"{side} {case.case_id} stderr omits {case.expected_error!r}: {result.stderr!r}"
        )


def records_by_path(records: Iterable[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(record["path"]): record for record in records}


def add_replacement(
    replacements: list[tuple[str, str, str]],
    old: object,
    new: object,
    token: str,
) -> None:
    if not isinstance(old, str) or not isinstance(new, str) or not old or not new:
        return
    replacements.append((old, new, token))


def case_replacements(
    case: ProcessCase,
    baseline: Mapping[str, dict[str, object]],
    candidate: Mapping[str, dict[str, object]],
    approved_changes: Sequence[dict[str, object]],
) -> list[tuple[str, str, str]]:
    changes = {(str(item["path"]), str(item["field"])): item for item in approved_changes}
    replacements: list[tuple[str, str, str]] = []

    relevant_paths = {case.path}
    if case.category == "help" and case.path == "syswarden":
        relevant_paths.update(
            path for path in baseline if len(path.split()) == 2
        )
    for path in sorted(relevant_paths):
        if path not in baseline or path not in candidate:
            continue
        before, after = baseline[path], candidate[path]
        description_changed = (path, "long") in changes or (path, "short") in changes
        if case.category == "help" and path == case.path and description_changed:
            add_replacement(
                replacements,
                before.get("long") or before.get("short"),
                after.get("long") or after.get("short"),
                f"{{{{description:{path}}}}}",
            )
        if case.category == "help" and case.path == "syswarden" and path != "syswarden":
            if (path, "short") in changes:
                add_replacement(
                    replacements,
                    before.get("short"),
                    after.get("short"),
                    f"{{{{short:{path}}}}}",
                )
        for field in ("use", "example"):
            if (path, field) in changes and path == case.path:
                add_replacement(
                    replacements,
                    before.get(field),
                    after.get(field),
                    f"{{{{{field}:{path}}}}}",
                )
        if (path, "flags") in changes and path == case.path:
            before_flags = {
                str(flag.get("name")): flag
                for flag in before["flags"]
                if isinstance(flag, dict)
            }
            after_flags = {
                str(flag.get("name")): flag
                for flag in after["flags"]
                if isinstance(flag, dict)
            }
            if set(before_flags) != set(after_flags):
                raise CompatibilityError(
                    f"cannot safely canonicalize added or removed flags for {path!r}"
                )
            for name in sorted(before_flags):
                for field in ("usage", "default", "shorthand", "type", "no_option"):
                    old = before_flags[name].get(field, "")
                    new = after_flags[name].get(field, "")
                    if old != new:
                        add_replacement(
                            replacements,
                            old,
                            new,
                            f"{{{{flag:{path}:{name}:{field}}}}}",
                        )
    return replacements


def canonicalize_pair(
    before: str, after: str, replacements: Sequence[tuple[str, str, str]]
) -> tuple[str, str]:
    old_values: dict[str, str] = {}
    new_values: dict[str, str] = {}
    for old, new, token in replacements:
        if old in old_values and old_values[old] != token:
            raise CompatibilityError(f"ambiguous baseline public text replacement: {old!r}")
        if new in new_values and new_values[new] != token:
            raise CompatibilityError(f"ambiguous candidate public text replacement: {new!r}")
        old_values[old] = token
        new_values[new] = token
    for value in sorted(old_values, key=len, reverse=True):
        before = before.replace(value, old_values[value])
    for value in sorted(new_values, key=len, reverse=True):
        after = after.replace(value, new_values[value])
    return before, after


def classify_process_result(
    case: ProcessCase,
    before: ProcessResult,
    after: ProcessResult,
    baseline_records: Mapping[str, dict[str, object]],
    candidate_records: Mapping[str, dict[str, object]],
    approved_public_changes: Sequence[dict[str, object]],
    process_approvals: object,
) -> dict[str, object]:
    exact = {"exit_code": before.exit_code == after.exit_code}
    if not exact["exit_code"]:
        raise CompatibilityError(f"unapproved exit-code difference in {case.case_id!r}")

    replacements: list[tuple[str, str, str]] | None = None
    classified_streams: dict[str, str] = {}
    if not isinstance(process_approvals, list):
        raise CompatibilityError("approved_cli_process_differences must be an array")
    approvals: dict[tuple[str, str], dict[str, object]] = {}
    for index, approval in enumerate(process_approvals):
        if not isinstance(approval, dict):
            raise CompatibilityError(f"CLI process approval {index} must be an object")
        key = (str(approval.get("case")), str(approval.get("stream")))
        if key in approvals:
            raise CompatibilityError(f"duplicate CLI process approval: {key}")
        if key[1] not in {"stdout", "stderr"}:
            raise CompatibilityError(f"unsupported CLI process approval stream: {key[1]!r}")
        if not isinstance(approval.get("reason"), str) or not str(approval["reason"]).strip():
            raise CompatibilityError(f"CLI process approval {index} needs a reason")
        if not isinstance(approval.get("before"), str) or not isinstance(approval.get("after"), str):
            raise CompatibilityError(f"CLI process approval {index} needs exact text values")
        approvals[key] = approval

    for stream in ("stdout", "stderr"):
        old = getattr(before, stream)
        new = getattr(after, stream)
        if old == new:
            classified_streams[stream] = "unchanged"
            continue
        approval = approvals.get((case.case_id, stream))
        if approval is not None:
            if approval["before"] != old or approval["after"] != new:
                raise CompatibilityError(
                    f"CLI process approval values do not match {case.case_id!r} {stream}"
                )
            classified_streams[stream] = "exact-process-approval"
            continue
        if replacements is None:
            replacements = case_replacements(
                case, baseline_records, candidate_records, approved_public_changes
            )
        canonical_old, canonical_new = canonicalize_pair(old, new, replacements)
        if canonical_old != canonical_new:
            raise CompatibilityError(
                f"unapproved CLI process difference in {case.case_id!r} {stream}; "
                "the output cannot be reduced to exact approved Cobra field changes"
            )
        classified_streams[stream] = "approved-public-fields"
    return {
        "changed": before != after,
        "exit_code": "unchanged",
        "streams": classified_streams,
    }


def validate_process_approval_inventory(
    cases: Sequence[ProcessCase],
    results: Mapping[str, tuple[ProcessResult, ProcessResult]],
    approvals: object,
) -> None:
    if not isinstance(approvals, list):
        raise CompatibilityError("approved_cli_process_differences must be an array")
    case_ids = {case.case_id for case in cases}
    used: set[tuple[str, str]] = set()
    for approval in approvals:
        if not isinstance(approval, dict):
            raise CompatibilityError("CLI process approval must be an object")
        case_id, stream = approval.get("case"), approval.get("stream")
        if not isinstance(case_id, str) or case_id not in case_ids:
            raise CompatibilityError(f"CLI process approval references unknown case: {case_id!r}")
        if stream not in {"stdout", "stderr"}:
            raise CompatibilityError(f"CLI process approval has invalid stream: {stream!r}")
        key = (case_id, stream)
        if key in used:
            raise CompatibilityError(f"duplicate CLI process approval: {key}")
        used.add(key)
        before, after = results[case_id]
        if getattr(before, stream) == getattr(after, stream):
            raise CompatibilityError(f"stale CLI process approval without a difference: {key}")
    actual = {
        (case_id, stream)
        for case_id, (before, after) in results.items()
        for stream in ("stdout", "stderr")
        if getattr(before, stream) != getattr(after, stream)
    }
    unconsumed = used - actual
    if unconsumed:
        raise CompatibilityError(f"stale CLI process approvals: {sorted(unconsumed)}")


def output_path_is_in_repo(repo_root: Path, output: Path) -> bool:
    root = repo_root.resolve()
    resolved = output.expanduser().resolve()
    return resolved == root or root in resolved.parents


def run_gate(repo_root: Path) -> dict[str, object]:
    repo_root = repo_root.resolve()
    contract_path = repo_root / "scripts/ci/documentation_contract.json"
    contract = read_json(contract_path)
    if not isinstance(contract, dict):
        raise CompatibilityError("documentation contract must be an object")
    baseline_snapshot_path, baseline_stored, baseline_provenance = verify_baseline_contract(
        repo_root, contract
    )
    candidate_snapshot_path = repo_root / "testdata/contracts/cli-command-tree.json"
    candidate_stored = validate_snapshot(
        read_json(candidate_snapshot_path), "candidate CLI snapshot"
    )
    changes = public_differences(baseline_stored, candidate_stored)
    approved_changes = classify_public_differences(
        changes, contract.get("approved_cli_public_differences")
    )
    process_approvals = contract.get("approved_cli_process_differences")

    initial_git_state = git_state(repo_root)
    initial_scoped_state = scoped_repository_state(repo_root)
    candidate_source = repo_root / "src/core/syswarden-cli"
    with tempfile.TemporaryDirectory(prefix="syswarden-cli-compat-") as temporary:
        workspace = Path(temporary)
        baseline_archive = bytes(
            git_output(
                repo_root,
                "archive",
                "--format=tar",
                BASELINE_COMMIT,
                "--",
                "src/core/syswarden-cli",
                binary=True,
            )
        )
        safe_extract_tar(baseline_archive, workspace / "baseline")
        baseline_module = workspace / "baseline/src/core/syswarden-cli"
        candidate_module = workspace / "candidate/src/core/syswarden-cli"
        candidate_digest, candidate_files = copy_candidate_module(
            candidate_source, candidate_module
        )

        baseline_env = isolated_go_env(workspace / "go-cache-baseline")
        candidate_env = isolated_go_env(workspace / "go-cache-candidate")
        go_version = str(run_checked(["go", "version"], cwd=workspace)).strip()

        baseline_rebuilt_bytes = reconstruct_snapshot(
            baseline_module, baseline_env, workspace / "baseline-snapshot.json"
        )
        candidate_rebuilt_bytes = reconstruct_snapshot(
            candidate_module, candidate_env, workspace / "candidate-snapshot.json"
        )
        if baseline_rebuilt_bytes != baseline_snapshot_path.read_bytes():
            raise CompatibilityError(
                "baseline snapshot is not the exact reconstruction of the frozen Git source"
            )
        if candidate_rebuilt_bytes != candidate_snapshot_path.read_bytes():
            raise CompatibilityError(
                "candidate snapshot is not the exact reconstruction of the copied candidate source"
            )

        baseline_binary = workspace / "syswarden-baseline"
        candidate_binary = workspace / "syswarden-candidate"
        baseline_binary_digest = build_binary(
            baseline_module, baseline_env, baseline_binary
        )
        candidate_binary_digest = build_binary(
            candidate_module, candidate_env, candidate_binary
        )

        baseline_map = records_by_path(baseline_stored)
        candidate_map = records_by_path(candidate_stored)
        common_paths = approved_common_command_paths(
            baseline_map, candidate_map, approved_changes
        )
        cases = [
            case
            for case in make_process_cases(baseline_stored)
            if case.path in common_paths
        ]

        results: dict[str, tuple[ProcessResult, ProcessResult]] = {}
        case_reports: list[dict[str, object]] = []
        execution_cwd = workspace / "process-cwd"
        execution_cwd.mkdir(mode=0o700)
        for case in cases:
            before = run_process(baseline_binary, case, execution_cwd)
            after = run_process(candidate_binary, case, execution_cwd)
            validate_case_result(case, before, "baseline")
            validate_case_result(case, after, "candidate")
            results[case.case_id] = (before, after)
            classification = classify_process_result(
                case,
                before,
                after,
                baseline_map,
                candidate_map,
                approved_changes,
                process_approvals,
            )
            case_reports.append(
                {
                    "id": case.case_id,
                    "category": case.category,
                    "path": case.path,
                    "argv": list(case.argv),
                    "expected_error": case.expected_error,
                    "baseline": asdict(before),
                    "candidate": asdict(after),
                    "classification": classification,
                }
            )
        validate_process_approval_inventory(cases, results, process_approvals)

        candidate_digest_after, candidate_records_after = source_manifest(candidate_source)
        if candidate_digest_after != candidate_digest or len(candidate_records_after) != candidate_files:
            raise CompatibilityError("candidate CLI source changed during the process comparison")
        final_git_state = git_state(repo_root)
        final_scoped_state = scoped_repository_state(repo_root)
        if final_git_state["head"] != initial_git_state["head"]:
            raise CompatibilityError(
                "Git HEAD changed while the read-only compatibility gate ran"
            )
        if (
            final_git_state["index_manifest_sha256"]
            != initial_git_state["index_manifest_sha256"]
        ):
            raise CompatibilityError(
                "Git index changed while the read-only compatibility gate ran"
            )
        if final_scoped_state != initial_scoped_state:
            raise CompatibilityError(
                "an in-scope CLI, snapshot, contract, or gate input changed during comparison"
            )

        category_counts: dict[str, int] = {}
        for case in cases:
            category_counts[case.category] = category_counts.get(case.category, 0) + 1
        return {
            "schema_version": 1,
            "status": "pass",
            "baseline": {
                **baseline_provenance,
                "module_archive_sha256": sha256_bytes(baseline_archive),
                "reconstructed_snapshot_sha256": sha256_bytes(baseline_rebuilt_bytes),
                "binary_sha256": baseline_binary_digest,
            },
            "candidate": {
                "source_manifest_sha256": candidate_digest,
                "source_file_count": candidate_files,
                "stored_snapshot_sha256": sha256_bytes(candidate_snapshot_path.read_bytes()),
                "reconstructed_snapshot_sha256": sha256_bytes(candidate_rebuilt_bytes),
                "binary_sha256": candidate_binary_digest,
            },
            "build": {
                "go_version": go_version,
                "mode": "-mod=readonly",
                "trimpath": True,
                "buildvcs": False,
                "workspace": "temporary-and-removed",
            },
            "public_differences": approved_changes,
            "process_cases": case_reports,
            "summary": {
                "process_case_count": len(cases),
                "categories": category_counts,
                "changed_process_case_count": sum(
                    1 for report in case_reports if report["classification"]["changed"]
                ),
                "approved_public_difference_count": len(approved_changes),
            },
            "repository_state": {
                "head": initial_git_state["head"],
                "index_manifest_sha256": initial_git_state[
                    "index_manifest_sha256"
                ],
                "scoped_input_manifest_sha256": initial_scoped_state["manifest_sha256"],
                "scoped_input_file_count": int(initial_scoped_state["file_count"]),
                "worktree_status_sha256_before": initial_git_state["status_sha256"],
                "worktree_status_sha256_after": final_git_state["status_sha256"],
                "parallel_out_of_scope_changes_observed": (
                    final_git_state["status_sha256"] != initial_git_state["status_sha256"]
                ),
            },
            "limitations": [
                "Only root startup, Cobra help, unknown-command handling, and argument counts rejected before command handlers are executed are compared.",
                "Successful install, uninstall, update, reload, firewall, service, network, TUI, migration, synchronization, and retired-feature cleanup paths are intentionally not executed on the host.",
                "This process gate does not replace privileged package lifecycle, kernel firewall, or mixed-version HA/TUI laboratories.",
            ],
        }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="SysWarden repository root",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="optional JSON report path outside the repository (stdout when omitted)",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="acknowledge and run the safe baseline/candidate process matrix",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if not args.run:
            raise CompatibilityError(
                "refusing to execute processes without the explicit --run acknowledgement"
            )
        if args.report is not None and output_path_is_in_repo(args.repo_root, args.report):
            raise CompatibilityError(
                "the compatibility report must be written outside the repository"
            )
        report = run_gate(args.repo_root)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.report is None:
            sys.stdout.write(encoded)
        else:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(encoded, encoding="utf-8")
            print(
                f"CLI process compatibility: PASS ({report['summary']['process_case_count']} cases); "
                f"report={args.report}"
            )
        return 0
    except (CompatibilityError, OSError) as exc:
        print(f"CLI process compatibility: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
