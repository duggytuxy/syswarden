#!/usr/bin/env python3
"""Prove honeyport rules and the real native manager in an isolated namespace.

This laboratory never applies rules to the host namespace. It also proves that
the historical 236379 regression is rejected before any ruleset mutation, then
runs the compiled NftablesManager against the namespace's kernel netlink API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Sequence


SCHEMA_VERSION = 3
FINDING_ID = "SW-FW-004"
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACT_IMAGE_RE = re.compile(
    r"^-P ubuntu-24\.04=([^\s]+@sha256:[0-9a-f]{64})$"
)
MARKER_RE = re.compile(r"^([A-Z_]+)=(.*)$")
SOURCE_BINDING_PATHS = (
    ".actrc",
    "src/core/syswarden-cli/config/config_loader.go",
    "src/core/syswarden-cli/pkg/firewall/firewall_linux.go",
    "src/core/syswarden-cli/pkg/firewall/firewall_linux_golden_test.go",
    "src/core/syswarden-cli/pkg/firewall/honeyports.go",
    "src/core/syswarden-core/firewall/manager_kernel_integration_linux_test.go",
    "src/core/syswarden-core/firewall/manager_linux.go",
    "testdata/firewall/nftables-v4.02.8.nft",
)


class NftablesLabError(RuntimeError):
    """Raised when isolated evidence cannot be trusted."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(self, args: Sequence[str], *, timeout: int) -> CommandResult:
        try:
            process = subprocess.run(
                list(args),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise NftablesLabError(
                f"command timed out after {timeout}s: {args[0]}"
            ) from exc
        return CommandResult(process.returncode, process.stdout, process.stderr)


def _git(repo_root: Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repo_root),
                *arguments,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NftablesLabError(f"cannot inspect Git repository: {exc}") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        raise NftablesLabError(
            f"Git {' '.join(arguments)} failed: {detail}"
        )
    return process.stdout.strip()


def inspect_repository_binding(repo_root: Path) -> dict[str, object]:
    """Return the exact clean Git commit/tree used by the laboratory."""

    reported_root = Path(_git(repo_root, "rev-parse", "--show-toplevel")).absolute()
    if reported_root != repo_root:
        raise NftablesLabError(
            f"repository root mismatch: expected {repo_root}, Git reports {reported_root}"
        )
    commit_sha = _git(repo_root, "rev-parse", "--verify", "HEAD^{commit}")
    tree_sha = _git(repo_root, "rev-parse", "--verify", "HEAD^{tree}")
    if GIT_SHA_RE.fullmatch(commit_sha) is None:
        raise NftablesLabError(f"Git returned an invalid commit SHA: {commit_sha!r}")
    if GIT_SHA_RE.fullmatch(tree_sha) is None:
        raise NftablesLabError(f"Git returned an invalid tree SHA: {tree_sha!r}")
    status = _git(
        repo_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        raise NftablesLabError(
            "nftables kernel lab requires a clean Git worktree so its compiled "
            "manager is exactly bound to HEAD"
        )
    return {
        "schema_version": 1,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "worktree_clean": True,
    }


def _git_archive_bytes(repo_root: Path, commit_sha: str) -> bytes:
    """Return the deterministic tar stream for an already resolved commit."""

    try:
        process = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repo_root),
                "archive",
                "--format=tar",
                commit_sha,
            ),
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NftablesLabError(f"cannot archive Git commit {commit_sha}: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise NftablesLabError(f"cannot archive Git commit {commit_sha}: {detail}")
    if not process.stdout:
        raise NftablesLabError(f"Git archive for {commit_sha} is empty")
    return process.stdout


def _extract_git_archive(archive_path: Path, snapshot_root: Path) -> None:
    """Extract regular Git files without accepting links or special entries."""

    snapshot_root.mkdir(mode=0o700)
    seen: set[str] = set()
    file_modes: dict[Path, int] = {}
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                raw_parts = member.name.rstrip("/").split("/")
                pure = PurePosixPath(member.name.rstrip("/"))
                if (
                    not member.name
                    or pure.is_absolute()
                    or not raw_parts
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or pure.as_posix() in seen
                ):
                    raise NftablesLabError(
                        f"Git archive contains an unsafe or duplicate path: {member.name!r}"
                    )
                seen.add(pure.as_posix())
                target = snapshot_root.joinpath(*pure.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    metadata = target.lstat()
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                        raise NftablesLabError(
                            f"Git archive directory collided with a non-directory: {member.name}"
                        )
                    continue
                if not member.isfile():
                    raise NftablesLabError(
                        f"Git archive contains a link or special entry: {member.name}"
                    )
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise NftablesLabError(
                        f"cannot read regular Git archive entry: {member.name}"
                    )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(target, flags, 0o600)
                    try:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            view = memoryview(chunk)
                            while view:
                                written = os.write(descriptor, view)
                                view = view[written:]
                    finally:
                        os.close(descriptor)
                finally:
                    source.close()
                if target.stat().st_size != member.size:
                    raise NftablesLabError(
                        f"Git archive entry size changed during extraction: {member.name}"
                    )
                file_modes[target] = 0o500 if member.mode & 0o111 else 0o400
    except (OSError, tarfile.TarError) as exc:
        raise NftablesLabError(f"cannot securely extract Git archive: {exc}") from exc
    if not seen:
        raise NftablesLabError("Git archive does not contain any entries")
    for path, mode in file_modes.items():
        path.chmod(mode)
    directories = [snapshot_root]
    directories.extend(path for path in snapshot_root.rglob("*") if path.is_dir())
    for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        directory.chmod(0o500)


def _thaw_snapshot(snapshot_root: Path) -> None:
    """Restore directory traversal/write permission so TemporaryDirectory can clean up."""

    if not snapshot_root.exists():
        return
    snapshot_root.chmod(0o700)
    for directory, names, _files in os.walk(snapshot_root):
        Path(directory).chmod(0o700)
        for name in names:
            child = Path(directory) / name
            if child.is_dir() and not child.is_symlink():
                child.chmod(0o700)


def _stable_regular_bytes(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise NftablesLabError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise NftablesLabError(f"{label} must be a regular non-symlink file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as exc:
        raise NftablesLabError(f"cannot read stable {label} {path}: {exc}") from exc
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise NftablesLabError(f"{label} changed while it was being read: {path}")
    payload = b"".join(chunks)
    if len(payload) != opened.st_size:
        raise NftablesLabError(f"{label} size changed while it was being read: {path}")
    return payload, opened


def _source_snapshot_evidence(
    snapshot_root: Path,
    archive_path: Path,
    repository_binding: dict[str, object],
) -> dict[str, object]:
    archive_payload, _archive_metadata = _stable_regular_bytes(
        archive_path, "Git archive"
    )
    critical_files: list[dict[str, object]] = []
    for relative in SOURCE_BINDING_PATHS:
        payload, _metadata = _stable_regular_bytes(
            snapshot_root / relative, f"source snapshot file {relative}"
        )
        critical_files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
        )
    entries = [snapshot_root]
    entries.extend(snapshot_root.rglob("*"))
    for entry in entries:
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            raise NftablesLabError(f"source snapshot contains an unsafe entry: {entry}")
        if stat.S_IMODE(metadata.st_mode) & 0o222:
            raise NftablesLabError(f"source snapshot entry is writable: {entry}")
    return {
        "schema_version": 1,
        "format": "git-archive-tar-v1",
        "commit_sha": repository_binding["commit_sha"],
        "tree_sha": repository_binding["tree_sha"],
        "archive_sha256": hashlib.sha256(archive_payload).hexdigest(),
        "archive_size_bytes": len(archive_payload),
        "critical_files": critical_files,
        "read_only": True,
        "revalidated_after_container": False,
    }


def _manager_binary_identity(path: Path) -> dict[str, object]:
    payload, metadata = _stable_regular_bytes(path, "NftablesManager kernel test binary")
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        mode != 0o500
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or not payload
    ):
        raise NftablesLabError(
            "NftablesManager kernel test binary must be non-empty, owner-bound, and mode 0500"
        )
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": "0500",
        "size_bytes": metadata.st_size,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
        "regular_file": True,
        "symlink": False,
    }


def require_regular_file(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise NftablesLabError(f"cannot inspect {label} {absolute}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NftablesLabError(f"{label} must be a real regular file: {absolute}")
    return absolute


def pinned_act_image(repo_root: Path) -> str:
    actrc = require_regular_file(repo_root / ".actrc", "Act configuration")
    matches = []
    for raw in actrc.read_text(encoding="utf-8").splitlines():
        match = ACT_IMAGE_RE.fullmatch(raw.strip())
        if match is not None:
            matches.append(match.group(1))
    if len(matches) != 1:
        raise NftablesLabError(
            "Act configuration must contain exactly one digest-pinned ubuntu-24.04 image"
        )
    return matches[0]


def verify_corrected_source_contract(repo_root: Path, golden: Path) -> str:
    text = golden.read_text(encoding="utf-8")
    if text.count("tcp dport { 236379 }") != 2:
        raise NftablesLabError(
            "the frozen baseline no longer contains exactly two historical 236379 honeyport rules"
        )
    loader = require_regular_file(
        repo_root / "src/core/syswarden-cli/config/config_loader.go",
        "configuration loader",
    ).read_text(encoding="utf-8")
    generator = require_regular_file(
        repo_root / "src/core/syswarden-cli/pkg/firewall/firewall_linux.go",
        "Linux firewall generator",
    ).read_text(encoding="utf-8")
    serializer = require_regular_file(
        repo_root / "src/core/syswarden-cli/pkg/firewall/honeyports.go",
        "honeyport serializer",
    ).read_text(encoding="utf-8")
    if 'strings.Join(m.Security.Honeyports, " ")' not in loader:
        raise NftablesLabError("the compatible honeyport loader contract changed")
    if 'canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)' not in generator:
        raise NftablesLabError("the Linux generator does not use the validated serializer")
    if 'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")' in generator:
        raise NftablesLabError("the concatenating honeyport implementation is still present")
    if 'strings.Join(canonical, ", ")' not in serializer:
        raise NftablesLabError("the honeyport serializer does not preserve item separators")
    candidate = text.replace("tcp dport { 236379 }", "tcp dport { 23, 6379 }")
    candidate = candidate.replace(
        "flags timeout;", "flags interval,timeout;"
    )
    candidate = candidate.replace(
        'type filter hook ingress devices = { "eth-test0", "eth-test1" }',
        'type filter hook ingress device "lo"',
    )
    if candidate.count("tcp dport { 23, 6379 }") != 2 or "236379" in candidate:
        raise NftablesLabError("the corrected candidate does not contain two distinct honeyports")
    return candidate


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-4000:]
        raise NftablesLabError(
            f"{description} failed with exit code {result.returncode}: {detail}"
        )


def normalize_amd64(value: str) -> str | None:
    normalized = value.strip().casefold()
    if normalized in {"amd64", "x86_64"}:
        return "amd64"
    return None


def ensure_local_native_engine(
    runner: CommandRunner, podman: str, image: str, pull_policy: str
) -> dict[str, object]:
    inspected_engine = runner.run(
        (podman, "info", "--format", "json"), timeout=30
    )
    require_success(inspected_engine, "Podman local native endpoint probe")
    try:
        document = json.loads(inspected_engine.stdout)
    except json.JSONDecodeError as exc:
        raise NftablesLabError("Podman endpoint probe is not valid JSON") from exc
    host = document.get("host") if isinstance(document, dict) else None
    security = host.get("security") if isinstance(host, dict) else None
    local_os = platform.system().strip().casefold()
    local_architecture = normalize_amd64(platform.machine())
    server_architecture = normalize_amd64(str(host.get("arch", ""))) if isinstance(host, dict) else None
    server_kernel = host.get("kernel") if isinstance(host, dict) else None
    if (
        not isinstance(host, dict)
        or not isinstance(security, dict)
        or security.get("rootless") is not True
        or host.get("serviceIsRemote") is not False
        or host.get("os") != "linux"
        or local_os != "linux"
        or local_architecture != "amd64"
        or server_architecture != "amd64"
        or type(server_kernel) is not str
        or not server_kernel
    ):
        raise NftablesLabError(
            "nftables kernel lab requires a local non-remote rootless Linux AMD64 "
            "Podman server on a native Linux AMD64 host"
        )
    version = runner.run(
        (podman, "version", "--format", "{{.Client.Version}}"), timeout=30
    )
    require_success(version, "Podman version probe")
    client_version = version.stdout.strip()
    if not client_version:
        raise NftablesLabError("Podman client version probe returned an empty value")
    exists = runner.run((podman, "image", "exists", image), timeout=30)
    if exists.returncode != 0:
        if pull_policy == "never":
            raise NftablesLabError(f"required pinned image is not local: {image}")
        pulled = runner.run((podman, "pull", image), timeout=600)
        require_success(pulled, "pull pinned Act image")
    inspected = runner.run(
        (podman, "image", "inspect", "--format", "{{.Digest}}", image),
        timeout=30,
    )
    require_success(inspected, "inspect pinned Act image")
    expected = image.rsplit("@", 1)[1]
    if inspected.stdout.strip() != expected:
        raise NftablesLabError(
            f"Act image digest mismatch: expected {expected}, found {inspected.stdout.strip()}"
        )
    return {
        "client_version": client_version,
        "rootless": True,
        "service_is_remote": False,
        "local_os": "linux",
        "local_architecture": "amd64",
        "server_os": "linux",
        "server_architecture": "amd64",
        "server_kernel": server_kernel,
    }


def prove_current_generator_contract(
    runner: CommandRunner, repo_root: Path
) -> None:
    result = runner.run(
        (
            "env",
            "GOENV=off",
            "GOWORK=off",
            "GOFLAGS=-buildvcs=false",
            "go",
            "-C",
            str(repo_root / "src/core/syswarden-cli"),
            "test",
            "-mod=readonly",
            "-count=1",
            "-run=^TestNftablesRulesGolden_SW_QA_001$",
            "-v",
            "./pkg/firewall",
        ),
        timeout=240,
    )
    require_success(result, "current Linux firewall generator contract")
    combined = result.stdout + "\n" + result.stderr
    if (
        "--- PASS: TestNftablesRulesGolden_SW_QA_001" not in combined
        or "--- SKIP: TestNftablesRulesGolden_SW_QA_001" in combined
    ):
        raise NftablesLabError(
            "current Linux firewall generator contract did not execute to PASS"
        )


def build_manager_kernel_test_binary(
    runner: CommandRunner, repo_root: Path, destination: Path
) -> Path:
    result = runner.run(
        (
            "env",
            "GOENV=off",
            "GOWORK=off",
            "GOFLAGS=-buildvcs=false",
            "CGO_ENABLED=0",
            "go",
            "-C",
            str(repo_root / "src/core/syswarden-core"),
            "test",
            "-mod=readonly",
            "-c",
            "-o",
            str(destination),
            "./firewall",
        ),
        timeout=300,
    )
    require_success(result, "compile real NftablesManager kernel test")
    binary = require_regular_file(destination, "NftablesManager kernel test binary")
    binary.chmod(0o500)
    _manager_binary_identity(binary)
    return binary


CONTAINER_SCRIPT = r'''
set +e
printf 'NETNS=%s\n' "$(readlink /proc/self/ns/net)"
printf 'KERNEL_VERSION=%s\n' "$(uname -r)"
printf 'KERNEL_MACHINE=%s\n' "$(uname -m)"
printf 'NFT_VERSION=%s\n' "$(nft --version)"
nft -c -f /fixture/syswarden.nft >/tmp/legacy.out 2>/tmp/legacy.err
printf 'LEGACY_CHECK_RC=%s\n' "$?"
nft -j list ruleset >/tmp/before.json 2>/tmp/list-before.err
printf 'LEGACY_LIST_RC=%s\n' "$?"
python3 -c 'import json; d=json.load(open("/tmp/before.json")); print("LEGACY_OBJECTS="+str(len(d["nftables"])-1))'
nft -f /fixture/honeyports-candidate.nft >/tmp/candidate.out 2>/tmp/candidate.err
printf 'CANDIDATE_APPLY_RC=%s\n' "$?"
nft -j list ruleset >/tmp/after.json 2>/tmp/list-after.err
printf 'CANDIDATE_LIST_RC=%s\n' "$?"
python3 -c 'import json; d=json.load(open("/tmp/after.json")); print("CANDIDATE_OBJECTS="+str(len(d["nftables"])-1))'
lab_netns="$(readlink /proc/self/ns/net)"
SYSWARDEN_NFTABLES_KERNEL_LAB=isolated-rootless-netns-v1 \
SYSWARDEN_NFTABLES_KERNEL_LAB_NETNS="$lab_netns" \
/fixture/syswarden-core-firewall.test \
    -test.run '^TestNftablesManagerKernelIntervals_SW_FW_004$' \
    -test.count=1 -test.v >/tmp/manager.out 2>/tmp/manager.err
manager_rc=$?
printf 'MANAGER_KERNEL_RC=%s\n' "$manager_rc"
if [ "$manager_rc" -eq 0 ] && \
   grep -Fq -- '--- PASS: TestNftablesManagerKernelIntervals_SW_FW_004' /tmp/manager.out && \
   ! grep -Fq -- '--- SKIP: TestNftablesManagerKernelIntervals_SW_FW_004' /tmp/manager.out; then
    printf 'MANAGER_KERNEL_PASS=1\n'
else
    printf 'MANAGER_KERNEL_PASS=0\n'
fi
if grep -Fq -- 'SYSWARDEN_MANAGER_KERNEL_RAW_INTERVALS_OK' /tmp/manager.out; then
    printf 'MANAGER_RAW_INTERVALS_OK=1\n'
else
    printf 'MANAGER_RAW_INTERVALS_OK=0\n'
fi
nft flush ruleset >/tmp/flush.out 2>/tmp/flush.err
printf 'CLEANUP_RC=%s\n' "$?"
printf '%s\n' 'ERROR_BEGIN'
cat /tmp/legacy.err
cat /tmp/candidate.err
if [ "$manager_rc" -ne 0 ]; then
    cat /tmp/manager.out
    cat /tmp/manager.err
fi
printf '%s\n' 'ERROR_END'
exit 0
'''.strip()


def container_arguments(
    podman: str,
    image: str,
    golden: Path,
    normalized: Path,
    manager_test_binary: Path,
) -> tuple[str, ...]:
    return (
        podman,
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--platform=linux/amd64",
        "--read-only",
        "--cap-drop=all",
        "--cap-add=NET_ADMIN",
        "--security-opt=label=disable",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=512m",
        "--tmpfs=/tmp:rw,nodev,nosuid,noexec,size=64m,mode=1777",
        "--volume",
        f"{golden}:/fixture/syswarden.nft:ro",
        "--volume",
        f"{normalized}:/fixture/honeyports-candidate.nft:ro",
        "--volume",
        f"{manager_test_binary}:/fixture/syswarden-core-firewall.test:ro",
        image,
        "bash",
        "-c",
        CONTAINER_SCRIPT,
    )


def parse_container_output(stdout: str) -> tuple[dict[str, str], str]:
    markers: dict[str, str] = {}
    error_lines: list[str] = []
    in_error = False
    for line in stdout.splitlines():
        if line == "ERROR_BEGIN":
            in_error = True
            continue
        if line == "ERROR_END":
            in_error = False
            continue
        if in_error:
            error_lines.append(line)
            continue
        match = MARKER_RE.fullmatch(line)
        if match is not None:
            if match.group(1) in markers:
                raise NftablesLabError(
                    f"duplicate container evidence marker: {match.group(1)}"
                )
            markers[match.group(1)] = match.group(2)
    expected = {
        "NETNS",
        "KERNEL_VERSION",
        "KERNEL_MACHINE",
        "NFT_VERSION",
        "LEGACY_CHECK_RC",
        "LEGACY_LIST_RC",
        "LEGACY_OBJECTS",
        "CANDIDATE_APPLY_RC",
        "CANDIDATE_LIST_RC",
        "CANDIDATE_OBJECTS",
        "MANAGER_KERNEL_RC",
        "MANAGER_KERNEL_PASS",
        "MANAGER_RAW_INTERVALS_OK",
        "CLEANUP_RC",
    }
    if set(markers) != expected:
        raise NftablesLabError(
            f"container evidence markers differ: expected {sorted(expected)}, "
            f"found {sorted(markers)}"
        )
    return markers, "\n".join(error_lines)


def run_lab(
    repo_root: Path,
    podman: str,
    pull_policy: str,
    *,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    root = repo_root.expanduser().absolute()
    if not root.is_dir() or root.is_symlink():
        raise NftablesLabError(f"repository root must be a real directory: {root}")
    repository_binding = inspect_repository_binding(root)
    active_runner = runner or CommandRunner()
    host_netns = os.readlink("/proc/self/ns/net")
    with tempfile.TemporaryDirectory(prefix="syswarden-nftables-kernel-") as raw:
        temporary_root = Path(raw)
        archive_path = temporary_root / "source.tar"
        snapshot_root = temporary_root / "source"
        try:
            archive_payload = _git_archive_bytes(
                root, str(repository_binding["commit_sha"])
            )
            archive_path.write_bytes(archive_payload)
            archive_path.chmod(0o400)
            _extract_git_archive(archive_path, snapshot_root)
            source_snapshot = _source_snapshot_evidence(
                snapshot_root, archive_path, repository_binding
            )
            image = pinned_act_image(snapshot_root)
            golden = require_regular_file(
                snapshot_root / "testdata/firewall/nftables-v4.02.8.nft",
                "nftables golden",
            )
            normalized_text = verify_corrected_source_contract(
                snapshot_root, golden
            )
            prove_current_generator_contract(active_runner, snapshot_root)
            engine_evidence = ensure_local_native_engine(
                active_runner, podman, image, pull_policy
            )
            normalized = temporary_root / "honeyports-normalized.nft"
            normalized.write_text(normalized_text, encoding="utf-8")
            normalized.chmod(0o400)
            manager_test_binary = build_manager_kernel_test_binary(
                active_runner,
                snapshot_root,
                temporary_root / "syswarden-core-firewall.test",
            )
            manager_binary_before = _manager_binary_identity(manager_test_binary)
            result = active_runner.run(
                container_arguments(
                    podman,
                    image,
                    golden,
                    normalized,
                    manager_test_binary,
                ),
                timeout=240,
            )
            manager_binary_after = _manager_binary_identity(manager_test_binary)
            if manager_binary_before != manager_binary_after:
                raise NftablesLabError(
                    "NftablesManager kernel test binary changed during container execution"
                )
            source_snapshot_after = _source_snapshot_evidence(
                snapshot_root, archive_path, repository_binding
            )
            if source_snapshot != source_snapshot_after:
                raise NftablesLabError(
                    "immutable Git source snapshot changed during laboratory execution"
                )
            source_snapshot["revalidated_after_container"] = True
            manager_test_binary_evidence = {
                "schema_version": 1,
                "source_archive_sha256": source_snapshot["archive_sha256"],
                "before": manager_binary_before,
                "after": manager_binary_after,
                "identical": True,
            }
        finally:
            _thaw_snapshot(snapshot_root)
    require_success(result, "isolated nftables kernel probe")
    markers, kernel_error = parse_container_output(result.stdout)
    container_architecture = normalize_amd64(markers["KERNEL_MACHINE"])
    conditions = {
        "local_native_podman_server": (
            engine_evidence["rootless"] is True
            and engine_evidence["service_is_remote"] is False
            and engine_evidence["local_os"] == "linux"
            and engine_evidence["server_os"] == "linux"
            and engine_evidence["local_architecture"] == "amd64"
            and engine_evidence["server_architecture"] == "amd64"
        ),
        "container_kernel_matches_server": (
            container_architecture == engine_evidence["server_architecture"]
            and markers["KERNEL_VERSION"] == engine_evidence["server_kernel"]
        ),
        "immutable_git_source_revalidated": source_snapshot[
            "revalidated_after_container"
        ]
        is True,
        "manager_test_binary_revalidated": (
            manager_test_binary_evidence["identical"] is True
            and manager_test_binary_evidence["before"]
            == manager_test_binary_evidence["after"]
        ),
        "separate_network_namespace": markers["NETNS"] != host_netns,
        "historical_concatenation_rejected_before_mutation": (
            markers["LEGACY_CHECK_RC"] == "1"
            and markers["LEGACY_LIST_RC"] == "0"
            and markers["LEGACY_OBJECTS"] == "0"
        ),
        "kernel_reported_invalid_port": "Service out of range" in kernel_error,
        "corrected_ruleset_applied": (
            markers["CANDIDATE_APPLY_RC"] == "0"
            and markers["CANDIDATE_LIST_RC"] == "0"
            and int(markers["CANDIDATE_OBJECTS"]) > 0
        ),
        "current_generator_contract_passed": True,
        "native_manager_interval_contract_passed": (
            markers["MANAGER_KERNEL_RC"] == "0"
            and markers["MANAGER_KERNEL_PASS"] == "1"
            and markers["MANAGER_RAW_INTERVALS_OK"] == "1"
        ),
        "isolated_ruleset_cleanup_succeeded": markers["CLEANUP_RC"] == "0",
    }
    if not all(conditions.values()):
        raise NftablesLabError(
            "nftables evidence does not prove the corrected honeyport contract: "
            + json.dumps(conditions, sort_keys=True)
            + "; isolated manager output: "
            + kernel_error[-4000:]
        )
    if inspect_repository_binding(root) != repository_binding:
        raise NftablesLabError(
            "Git repository binding changed while the nftables kernel lab was running"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "pass",
        "product_status": "pass",
        "release_ready": True,
        "finding_id": FINDING_ID,
        "repository_binding": repository_binding,
        "source_snapshot": source_snapshot,
        "manager_test_binary": manager_test_binary_evidence,
        "summary": (
            "The corrected generator keeps honeyports 23 and 6379 distinct, the isolated "
            "kernel applies the candidate, the historical 236379 form is rejected, and "
            "the real NftablesManager proves exact interval boundaries in inet and netdev."
        ),
        "engine": {
            "name": "podman",
            **engine_evidence,
            "container_architecture": container_architecture,
            "container_kernel": markers["KERNEL_VERSION"],
            "image": image,
            "network": "none",
            "nftables": markers["NFT_VERSION"],
        },
        "network_namespaces": {"host": host_netns, "container": markers["NETNS"]},
        "conditions": conditions,
        "kernel_error": kernel_error[-4000:],
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    destination = path.expanduser().absolute()
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise NftablesLabError(f"report parent must be a real directory: {parent}")
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise NftablesLabError(
            f"report destination must be absent or a regular file: {destination}"
        )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=parent
    )
    os.close(descriptor)
    temporary = Path(raw_temporary)
    try:
        temporary.write_text(payload, encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--pull-policy", choices=("never", "missing"), default="never")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_lab(args.repo_root, args.podman, args.pull_policy)
        return_code = 0
    except (NftablesLabError, OSError) as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "harness_status": "fail",
            "product_status": "unknown",
            "release_ready": False,
            "error": str(exc),
        }
        return_code = 1
    if args.output is not None:
        write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
