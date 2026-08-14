#!/usr/bin/env python3
"""Characterize the v4.02.8 nftables golden in an isolated kernel namespace.

This laboratory never applies rules to the host namespace.  It records the
known honeyport serialization defect as a release blocker until the Lot 1
transactional firewall work intentionally replaces this contract.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = 1
FINDING_ID = "SW-FW-004"
ACT_IMAGE_RE = re.compile(
    r"^-P ubuntu-24\.04=([^\s]+@sha256:[0-9a-f]{64})$"
)
MARKER_RE = re.compile(r"^([A-Z_]+)=(.*)$")


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


def verify_known_source_contract(repo_root: Path, golden: Path) -> str:
    text = golden.read_text(encoding="utf-8")
    if text.count("tcp dport { 236379 }") != 2:
        raise NftablesLabError(
            "the frozen golden no longer contains exactly two known 236379 honeyport rules; "
            "review and replace this characterization intentionally"
        )
    loader = require_regular_file(
        repo_root / "src/core/syswarden-cli/config/config_loader.go",
        "configuration loader",
    ).read_text(encoding="utf-8")
    generator = require_regular_file(
        repo_root / "src/core/syswarden-cli/pkg/firewall/firewall_linux.go",
        "Linux firewall generator",
    ).read_text(encoding="utf-8")
    if 'strings.Join(m.Security.Honeyports, " ")' not in loader:
        raise NftablesLabError("the known honeyport loader source contract changed")
    if 'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")' not in generator:
        raise NftablesLabError("the known honeyport generator source contract changed")
    return text.replace("tcp dport { 236379 }", "tcp dport { 23, 6379 }")


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-4000:]
        raise NftablesLabError(
            f"{description} failed with exit code {result.returncode}: {detail}"
        )


def ensure_rootless_engine(
    runner: CommandRunner, podman: str, image: str, pull_policy: str
) -> str:
    rootless = runner.run(
        (podman, "info", "--format", "{{.Host.Security.Rootless}}"), timeout=30
    )
    require_success(rootless, "Podman rootless probe")
    if rootless.stdout.strip().lower() != "true":
        raise NftablesLabError("nftables kernel lab requires rootless Podman")
    version = runner.run(
        (podman, "version", "--format", "{{.Client.Version}}"), timeout=30
    )
    require_success(version, "Podman version probe")
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
    return version.stdout.strip()


CONTAINER_SCRIPT = r'''
set +e
printf 'NETNS=%s\n' "$(readlink /proc/self/ns/net)"
printf 'NFT_VERSION=%s\n' "$(nft --version)"
nft -f /fixture/syswarden.nft >/tmp/exact.out 2>/tmp/exact.err
printf 'EXACT_APPLY_RC=%s\n' "$?"
nft -j list ruleset >/tmp/after.json 2>/tmp/list.err
printf 'EXACT_LIST_RC=%s\n' "$?"
python3 -c 'import json; d=json.load(open("/tmp/after.json")); print("EXACT_OBJECTS="+str(len(d["nftables"])-1))'
nft -c -f /fixture/honeyports-normalized.nft >/tmp/normalized.out 2>/tmp/normalized.err
printf 'NORMALIZED_CHECK_RC=%s\n' "$?"
nft flush ruleset >/tmp/flush.out 2>/tmp/flush.err
printf 'CLEANUP_RC=%s\n' "$?"
printf '%s\n' 'ERROR_BEGIN'
cat /tmp/exact.err
printf '%s\n' 'ERROR_END'
exit 0
'''.strip()


def container_arguments(
    podman: str, image: str, golden: Path, normalized: Path
) -> tuple[str, ...]:
    return (
        podman,
        "run",
        "--rm",
        "--network=none",
        "--cap-add=NET_ADMIN",
        "--security-opt=label=disable",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=512m",
        "--volume",
        f"{golden}:/fixture/syswarden.nft:ro",
        "--volume",
        f"{normalized}:/fixture/honeyports-normalized.nft:ro",
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
        "NFT_VERSION",
        "EXACT_APPLY_RC",
        "EXACT_LIST_RC",
        "EXACT_OBJECTS",
        "NORMALIZED_CHECK_RC",
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
    image = pinned_act_image(root)
    golden = require_regular_file(
        root / "testdata/firewall/nftables-v4.02.8.nft", "nftables golden"
    )
    normalized_text = verify_known_source_contract(root, golden)
    active_runner = runner or CommandRunner()
    engine_version = ensure_rootless_engine(
        active_runner, podman, image, pull_policy
    )
    host_netns = os.readlink("/proc/self/ns/net")
    with tempfile.TemporaryDirectory(prefix="syswarden-nftables-kernel-") as raw:
        normalized = Path(raw) / "honeyports-normalized.nft"
        normalized.write_text(normalized_text, encoding="utf-8")
        normalized.chmod(0o600)
        result = active_runner.run(
            container_arguments(podman, image, golden, normalized), timeout=180
        )
    require_success(result, "isolated nftables kernel probe")
    markers, kernel_error = parse_container_output(result.stdout)
    conditions = {
        "separate_network_namespace": markers["NETNS"] != host_netns,
        "exact_ruleset_rejected": markers["EXACT_APPLY_RC"] == "1",
        "exact_ruleset_left_no_objects": (
            markers["EXACT_LIST_RC"] == "0" and markers["EXACT_OBJECTS"] == "0"
        ),
        "kernel_reported_invalid_port": "Service out of range" in kernel_error,
        "honeyport_only_normalization_passed_syntax_check": (
            markers["NORMALIZED_CHECK_RC"] == "0"
        ),
        "isolated_ruleset_cleanup_succeeded": markers["CLEANUP_RC"] == "0",
    }
    if not all(conditions.values()):
        raise NftablesLabError(
            "nftables evidence no longer matches the reviewed baseline blocker: "
            + json.dumps(conditions, sort_keys=True)
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "pass",
        "product_status": "known_blocker",
        "release_ready": False,
        "finding_id": FINDING_ID,
        "summary": (
            "The v4.02.8 generator serializes honeyports 23 and 6379 as the "
            "out-of-range port 236379; the isolated kernel rejects the exact ruleset."
        ),
        "engine": {
            "name": "podman",
            "version": engine_version,
            "rootless": True,
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
