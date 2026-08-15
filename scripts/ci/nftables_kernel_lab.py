#!/usr/bin/env python3
"""Prove the corrected honeyport rules in an isolated nftables namespace.

This laboratory never applies rules to the host namespace. It also proves that
the historical 236379 regression is rejected before any ruleset mutation.
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


def prove_current_generator_contract(
    runner: CommandRunner, repo_root: Path
) -> None:
    result = runner.run(
        (
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


CONTAINER_SCRIPT = r'''
set +e
printf 'NETNS=%s\n' "$(readlink /proc/self/ns/net)"
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
nft add element inet syswarden banned_ips '{ 198.51.100.0-198.51.100.255 timeout 3600s expires 3599s }' >/tmp/dynamic.out 2>/tmp/dynamic.err && \
nft add element inet syswarden banned_ips6 '{ 2001:db8::-2001:db8::ffff:ffff:ffff:ffff timeout 3600s expires 3599s }' >>/tmp/dynamic.out 2>>/tmp/dynamic.err && \
nft add element netdev syswarden_hw_drop banned_ips '{ 198.51.100.0-198.51.100.255 timeout 3600s expires 3599s }' >>/tmp/dynamic.out 2>>/tmp/dynamic.err && \
nft add element netdev syswarden_hw_drop banned_ips6 '{ 2001:db8::-2001:db8::ffff:ffff:ffff:ffff timeout 3600s expires 3599s }' >>/tmp/dynamic.out 2>>/tmp/dynamic.err
printf 'DYNAMIC_ADD_RC=%s\n' "$?"
nft -j list ruleset >/tmp/dynamic.json 2>/tmp/dynamic-list.err
printf 'DYNAMIC_LIST_RC=%s\n' "$?"
python3 -c 'import json; d=json.load(open("/tmp/dynamic.json")); w={("inet","syswarden","banned_ips"),("inet","syswarden","banned_ips6"),("netdev","syswarden_hw_drop","banned_ips"),("netdev","syswarden_hw_drop","banned_ips6")}; o=[x.get("element") or x.get("set") for x in d["nftables"]]; f={(x.get("family"),x.get("table"),x.get("name")) for x in o if isinstance(x,dict) and "\"timeout\"" in json.dumps(x.get("elem",[])) and "\"expires\"" in json.dumps(x.get("elem",[]))}; print("DYNAMIC_TIMEOUT_OK="+str(int(f==w)))'
nft flush ruleset >/tmp/flush.out 2>/tmp/flush.err
printf 'CLEANUP_RC=%s\n' "$?"
printf '%s\n' 'ERROR_BEGIN'
cat /tmp/legacy.err
cat /tmp/candidate.err
cat /tmp/dynamic.err
cat /tmp/dynamic-list.err
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
        f"{normalized}:/fixture/honeyports-candidate.nft:ro",
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
        "LEGACY_CHECK_RC",
        "LEGACY_LIST_RC",
        "LEGACY_OBJECTS",
        "CANDIDATE_APPLY_RC",
        "CANDIDATE_LIST_RC",
        "CANDIDATE_OBJECTS",
        "DYNAMIC_ADD_RC",
        "DYNAMIC_LIST_RC",
        "DYNAMIC_TIMEOUT_OK",
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
    normalized_text = verify_corrected_source_contract(root, golden)
    active_runner = runner or CommandRunner()
    prove_current_generator_contract(active_runner, root)
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
        "dynamic_timeout_replication_applied": (
            markers["DYNAMIC_ADD_RC"] == "0"
            and markers["DYNAMIC_LIST_RC"] == "0"
            and markers["DYNAMIC_TIMEOUT_OK"] == "1"
        ),
        "isolated_ruleset_cleanup_succeeded": markers["CLEANUP_RC"] == "0",
    }
    if not all(conditions.values()):
        raise NftablesLabError(
            "nftables evidence does not prove the corrected honeyport contract: "
            + json.dumps(conditions, sort_keys=True)
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "pass",
        "product_status": "pass",
        "release_ready": True,
        "finding_id": FINDING_ID,
        "summary": (
            "The corrected generator keeps honeyports 23 and 6379 distinct, the isolated "
            "kernel applies the candidate, and the historical 236379 form is rejected."
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
