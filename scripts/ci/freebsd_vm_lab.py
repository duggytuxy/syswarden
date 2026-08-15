#!/usr/bin/env python3
"""Exercise two SysWarden FreeBSD packages in an explicitly disposable VM.

The harness only connects to an SSH endpoint on the local loopback interface.
It requires an explicit private key, a pinned known-hosts file, and a marker
inside the guest.  Package and PF mutations happen as root inside that marked
FreeBSD VM; this process never invokes a host firewall command.  The lifecycle
is previous install, candidate upgrade, candidate reinstall, previous rollback,
and native FreeBSD removal (``pkg delete`` has no separate purge operation).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = 2
VM_MARKER_PATH = "/var/run/syswarden-lot0-disposable.marker"
PACKAGE_PATTERN = re.compile(
    r"^syswarden-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\.txz$"
)
TOKEN_PATTERN = re.compile(r"^[A-Fa-f0-9]{32,128}$")
USER_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
REMOTE_ROOT_PATTERN = re.compile(r"^/tmp/syswarden-freebsd-lot0-[a-f0-9]{32}$")
MARKER_LINE_PATTERN = re.compile(r"^SWL0\t([A-Z0-9_]+)\t([A-Za-z0-9+/=]*)$")
MAX_EVIDENCE_BYTES = 256_000

EXPECTED_SIGNATURE_RULE_COUNT = 78
EXPECTED_ENGINE_SIGNATURE_COUNT = 194
EXPECTED_FREEBSD_PACKAGE_ABI = "FreeBSD:14:amd64"
KNOWN_LEGACY_FREEBSD_PACKAGE_ABI = "FreeBSD:13:amd64"
EXPECTED_NATIVE_ELF_ARCH = "amd64"
CANONICAL_BLOCKER_IDS = frozenset({"SW-BSD-001"})
KNOWN_FREEBSD_CORE_COMMAND = "/opt/syswarden/syswarden-core"
KNOWN_FREEBSD_WEB_COMMAND = "/opt/syswarden/bin/syswarden-cli"
EXPECTED_FAILED_CHECK_BLOCKERS = {
    "SW-PKG-FBSD-PREVIOUS-INSTALL-ABI-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREVIOUS-INSTALL-ELF-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREVIOUS-INSTALL-SIGNATURES-001": "SW-BSD-001",
    "SW-PKG-FBSD-CANDIDATE-UPGRADE-ABI-001": "SW-BSD-001",
    "SW-PKG-FBSD-CANDIDATE-REINSTALL-ABI-001": "SW-BSD-001",
    "SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-001": "SW-BSD-001",
    "SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-ABI-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-ABI-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-ELF-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-SIGNATURES-001": "SW-BSD-001",
    "SW-PKG-FBSD-PREFIX-001": "SW-BSD-001",
    "SW-PKG-FBSD-RCD-CORE-001": "SW-BSD-001",
    "SW-PKG-FBSD-RCD-WEB-001": "SW-BSD-001",
    "SW-PKG-FBSD-RCD-CORE-PATH-001": "SW-BSD-001",
    "SW-PKG-FBSD-RCD-WEB-PATH-001": "SW-BSD-001",
    "SW-PKG-FBSD-RCD-ENABLE-001": "SW-BSD-001",
    "SW-PKG-FBSD-START-CORE-001": "SW-BSD-001",
    "SW-PKG-FBSD-RESTART-CORE-001": "SW-BSD-001",
    "SW-PKG-FBSD-START-WEB-001": "SW-BSD-001",
    "SW-PKG-FBSD-RESTART-WEB-001": "SW-BSD-001",
}
ABI_CHECK_PHASES = {
    "SW-PKG-FBSD-PREVIOUS-INSTALL-ABI-001": "PREVIOUS_INSTALL",
    "SW-PKG-FBSD-CANDIDATE-UPGRADE-ABI-001": "CANDIDATE_UPGRADE",
    "SW-PKG-FBSD-CANDIDATE-REINSTALL-ABI-001": "CANDIDATE_REINSTALL",
    "SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-ABI-001": (
        "CANDIDATE_RESTART_IDEMPOTENCE"
    ),
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-ABI-001": "PREVIOUS_ROLLBACK",
}
PREVIOUS_MIXED_ELF_CHECK_PHASES = {
    "SW-PKG-FBSD-PREVIOUS-INSTALL-ELF-001": "PREVIOUS_INSTALL",
    "SW-PKG-FBSD-PREVIOUS-INSTALL-SIGNATURES-001": "PREVIOUS_INSTALL",
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-ELF-001": "PREVIOUS_ROLLBACK",
    "SW-PKG-FBSD-PREVIOUS-ROLLBACK-SIGNATURES-001": "PREVIOUS_ROLLBACK",
}
USER_CONFIG_STATE = "syswarden-freebsd-user-config-state-v1\n"
USER_DATA_STATE = "syswarden-freebsd-user-data-state-v1\n"
USER_CONFIG_SHA256 = hashlib.sha256(USER_CONFIG_STATE.encode("utf-8")).hexdigest()
USER_DATA_SHA256 = hashlib.sha256(USER_DATA_STATE.encode("utf-8")).hexdigest()
ANCHOR_NAME_PATTERN = re.compile(r"^syswarden_lot0_[a-f0-9]{32}$")
METADATA_INVENTORY_ROOTS = (
    "/usr/local/syswarden",
    "/usr/local/bin/syswarden",
    "/usr/local/bin/syswarden-tui",
    "/usr/local/etc/rc.d/syswarden",
    "/usr/local/etc/rc.d/syswardenwebtui",
    "/etc/syswarden",
    "/var/lib/syswarden",
    "/opt/syswarden",
)

LIFECYCLE_PHASES = (
    "PREVIOUS_INSTALL",
    "CANDIDATE_UPGRADE",
    "CANDIDATE_REINSTALL",
    "CANDIDATE_RESTART_IDEMPOTENCE",
    "PREVIOUS_ROLLBACK",
)
PHASE_EVIDENCE_SUFFIXES = frozenset(
    {
        "OPERATION_RC",
        "PKG_INSTALLED",
        "PKG_NAME",
        "PKG_VERSION",
        "PKG_ARCH",
        "PKG_INVENTORY",
        "ELF_CLI_ARCH",
        "ELF_CORE_ARCH",
        "ELF_TUI_ARCH",
        "USER_STATE_INVENTORY",
        "USER_CONFIG_SHA256",
        "USER_DATA_SHA256",
        "SIGNATURE_RULE_COUNT",
        "SIGNATURE_ENGINE_COUNT",
        "SIGNATURE_PROBE_RC",
        "SIGNATURE_LOAD_ERROR",
        "SIGNATURE_STATE_BEFORE",
        "SIGNATURE_STATE_AFTER",
        "SIGNATURE_STATE_RESTORED",
    }
)

EXPECTED_PACKAGE_INVENTORY = frozenset(
    {
        "/usr/local/syswarden/bin/syswarden-cli",
        "/usr/local/syswarden/bin/syswarden-core",
        "/usr/local/syswarden/bin/syswarden-tui",
        "/usr/local/syswarden/signatures.json",
    }
)
EXPECTED_USER_STATE_INVENTORY = frozenset(
    {
        "/etc/syswarden/config/lifecycle-user.conf",
        "/var/lib/syswarden/lifecycle-user.state",
    }
)

PROBE_KEYS = frozenset(
    {
        "MARKER_MATCH",
        "MARKER_SAFE",
        "OS_NAME",
        "OS_RELEASE",
        "MACHINE",
        "SUDO_READY",
        "BASE64_READY",
    }
)

BASE_EVIDENCE_KEYS = frozenset(
    {
        "ROOT_UID",
        "MARKER_MATCH",
        "MARKER_SAFE",
        "OS_NAME",
        "OS_RELEASE",
        "MACHINE",
        "PKG_TOOL_READY",
        "PF_TOOL_READY",
        "TIMEOUT_TOOL_READY",
        "FILE_TOOL_READY",
        "PRECLEAN",
        "PREVIOUS_PACKAGE_SHA256",
        "CANDIDATE_PACKAGE_SHA256",
        "PF_BASELINE_READY",
        "PF_BASELINE_CLEAN",
        "PF_BASELINE_STATUS",
        "PF_FINAL_STATUS",
        "PF_SNAPSHOT_SHA256",
        "PF_FIXTURE_SHA256",
        "PF_FIXTURE_SHA_MATCH",
        "PF_ANCHOR_NAME",
        "LAB_LOCK_ACQUIRED",
        "LAB_LOCK_RELEASED",
        "RESTART_BASELINE_INVENTORY",
        "RESTART_ONE_INVENTORY",
        "RESTART_TWO_INVENTORY",
        "MODE_CLI",
        "MODE_CORE",
        "MODE_TUI",
        "MODE_SIGNATURES",
        "LINK_CLI",
        "LINK_TUI",
        "CLI_DIRECT_RC",
        "CLI_LINK_RC",
        "SIGNATURE_PACKAGE_PATH",
        "SIGNATURE_RUNTIME_PATH",
        "RC_CORE_PRESENT",
        "RC_WEB_PRESENT",
        "RC_CORE_MODE",
        "RC_WEB_MODE",
        "RC_CORE_COMMAND",
        "RC_WEB_COMMAND",
        "RC_CORE_ENABLED",
        "RC_WEB_ENABLED",
        "RC_CORE_START_RC",
        "RC_CORE_STATUS_RC",
        "RC_CORE_RESTART_ONE_RC",
        "RC_CORE_RESTART_ONE_STATUS_RC",
        "RC_CORE_RESTART_TWO_RC",
        "RC_CORE_RESTART_TWO_STATUS_RC",
        "RC_WEB_START_RC",
        "RC_WEB_STATUS_RC",
        "RC_WEB_RESTART_ONE_RC",
        "RC_WEB_RESTART_ONE_STATUS_RC",
        "RC_WEB_RESTART_TWO_RC",
        "RC_WEB_RESTART_TWO_STATUS_RC",
        "PF_INTERFACE",
        "PF_FIXTURE_SYNTAX_RC",
        "PF_FIXTURE_APPLY_RC",
        "PF_FIXTURE_RULE_COUNT",
        "PF_ANCHOR_CLEAN",
        "PF_HONEYPORT_SOURCE_BAD",
        "PF_HONEYPORT_EXACT_VALUE",
        "PF_HONEYPORT_SYNTAX_RC",
        "REMOVE_RC",
        "REMOVE_PACKAGE_ABSENT",
        "REMOVE_PKG_INVENTORY",
        "REMOVE_PAYLOAD_ABSENT",
        "REMOVE_LINKS_ABSENT",
        "REMOVE_RC_CORE_ABSENT",
        "REMOVE_RC_WEB_ABSENT",
        "REMOVE_CORE_FLAG_ABSENT",
        "REMOVE_WEB_FLAG_ABSENT",
        "REMOVE_USER_STATE_INVENTORY",
        "REMOVE_USER_CONFIG_SHA256",
        "REMOVE_USER_DATA_SHA256",
        "LAB_CLEANUP_OK",
        "PF_BASELINE_RESTORED",
    }
)
EVIDENCE_KEYS = BASE_EVIDENCE_KEYS | frozenset(
    f"{phase}_{suffix}"
    for phase in LIFECYCLE_PHASES
    for suffix in PHASE_EVIDENCE_SUFFIXES
)


class FreeBSDVMLabError(RuntimeError):
    """Raised when the VM evidence cannot be trusted."""


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PackageArtifact:
    path: Path
    version: str
    sha256: str


@dataclass(frozen=True)
class ProductAssets:
    repository: Path
    pf_fixture: Path
    pf_fixture_sha256: str
    honeyport_source_bad: bool


class CommandRunner:
    """Run local transport commands without a shell."""

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int,
        input_text: str | None = None,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                list(args),
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise FreeBSDVMLabError(
                f"transport command timed out after {timeout}s: {args[0]}"
            ) from exc
        return CommandResult(
            tuple(args), completed.returncode, completed.stdout, completed.stderr
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_real_directory(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise FreeBSDVMLabError(f"cannot inspect {label} {absolute}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise FreeBSDVMLabError(f"{label} must be a real directory: {absolute}")
    return absolute


def require_regular_file(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise FreeBSDVMLabError(f"cannot inspect {label} {absolute}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise FreeBSDVMLabError(
            f"{label} must be a real regular file: {absolute}"
        )
    return absolute


def validate_loopback(host: str) -> str:
    if host == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise FreeBSDVMLabError(
            "SSH host must be localhost or a literal loopback address"
        ) from exc
    if not address.is_loopback:
        raise FreeBSDVMLabError(
            "SSH host must be localhost or a literal loopback address"
        )
    return host


def validate_transport_inputs(
    host: str,
    port: int,
    user: str,
    identity_file: Path,
    known_hosts_file: Path,
    marker_token: str,
) -> tuple[str, Path, Path]:
    validated_host = validate_loopback(host)
    if port < 1 or port > 65535:
        raise FreeBSDVMLabError("SSH port must be between 1 and 65535")
    if USER_PATTERN.fullmatch(user) is None:
        raise FreeBSDVMLabError(f"invalid SSH user: {user!r}")
    if TOKEN_PATTERN.fullmatch(marker_token) is None:
        raise FreeBSDVMLabError(
            "VM marker token must contain 32 to 128 hexadecimal characters"
        )
    identity = require_regular_file(identity_file, "SSH identity")
    identity_mode = stat.S_IMODE(identity.stat().st_mode)
    if identity_mode & 0o077:
        raise FreeBSDVMLabError(
            f"SSH identity must not be group/world accessible: {identity}"
        )
    known_hosts = require_regular_file(known_hosts_file, "SSH known-hosts file")
    if known_hosts.stat().st_size == 0:
        raise FreeBSDVMLabError("SSH known-hosts file must not be empty")
    return validated_host, identity, known_hosts


def resolve_marker_token(args: argparse.Namespace) -> str:
    """Load the VM marker secret without putting it in transport arguments."""

    direct_token = getattr(args, "vm_marker_token", None)
    token_file_value = getattr(args, "vm_marker_token_file", None)
    if direct_token:
        raise FreeBSDVMLabError(
            "direct VM marker tokens are disabled; use --vm-marker-token-file"
        )
    if not token_file_value:
        raise FreeBSDVMLabError("--vm-marker-token-file is required")
    token_file = require_regular_file(
        Path(token_file_value), "VM marker token file"
    )
    token_mode = stat.S_IMODE(token_file.stat().st_mode)
    if token_mode & 0o077:
        raise FreeBSDVMLabError(
            "VM marker token file must not be group/world accessible"
        )
    if token_file.stat().st_size > 130:
        raise FreeBSDVMLabError("VM marker token file is unexpectedly large")
    raw_token = token_file.read_text(encoding="ascii")
    if raw_token.endswith("\n"):
        raw_token = raw_token[:-1]
    if "\n" in raw_token or "\r" in raw_token:
        raise FreeBSDVMLabError(
            "VM marker token file must contain exactly one token"
        )
    token = raw_token
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise FreeBSDVMLabError(
            "VM marker token must contain 32 to 128 hexadecimal characters"
        )
    return token


def script_stdin_with_token(script: str, marker_token: str) -> str:
    """Transmit the marker secret in SSH stdin, never in SSH argv."""

    if TOKEN_PATTERN.fullmatch(marker_token) is None:
        raise FreeBSDVMLabError("refusing to transmit an invalid VM marker token")
    # Hex-only validation makes this assignment inert shell data.  Tracing is
    # never enabled by either script, so the secret cannot enter remote logs.
    return f"token={marker_token}\n{script}\n"


def validate_transport_program(program: str, expected_name: str) -> str:
    if not program or Path(program).name != expected_name:
        raise FreeBSDVMLabError(
            f"{expected_name} transport must name the {expected_name} executable"
        )
    return program


def read_checksum(checksum_file: Path, package_name: str) -> str:
    manifest = require_regular_file(checksum_file, "package checksum manifest")
    matches: list[str] = []
    for line_number, raw_line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?([^/\s]+)", line)
        if match is None:
            raise FreeBSDVMLabError(
                f"invalid SHA256SUMS entry at {manifest}:{line_number}"
            )
        if match.group(2) == package_name:
            matches.append(match.group(1))
    if len(matches) != 1:
        raise FreeBSDVMLabError(
            f"expected exactly one checksum for {package_name}, found {len(matches)}"
        )
    return matches[0]


def discover_package(packages_dir: Path) -> PackageArtifact:
    directory = require_real_directory(packages_dir, "FreeBSD package directory")
    candidates: list[tuple[Path, re.Match[str]]] = []
    for child in sorted(directory.iterdir(), key=lambda item: item.name):
        match = PACKAGE_PATTERN.fullmatch(child.name)
        if match is None:
            continue
        package = require_regular_file(child, "FreeBSD package")
        if package.stat().st_size == 0:
            raise FreeBSDVMLabError(f"FreeBSD package is empty: {package}")
        candidates.append((package, match))
    if len(candidates) != 1:
        raise FreeBSDVMLabError(
            "expected exactly one syswarden-<version>.txz package in "
            f"{directory}, found {len(candidates)}"
        )
    package, match = candidates[0]
    expected = read_checksum(directory / "SHA256SUMS.txt", package.name)
    actual = sha256_file(package)
    if actual != expected:
        raise FreeBSDVMLabError(
            f"checksum mismatch for {package}: expected {expected}, found {actual}"
        )
    return PackageArtifact(package, match.group("version"), actual)


def version_tuple(version: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", version)
    if match is None:
        raise FreeBSDVMLabError(f"invalid package version: {version!r}")
    return tuple(int(part) for part in match.groups())


def discover_package_pair(
    candidate_packages_dir: Path, previous_packages_dir: Path
) -> tuple[PackageArtifact, PackageArtifact]:
    candidate_root = require_real_directory(
        candidate_packages_dir, "candidate FreeBSD package directory"
    )
    previous_root = require_real_directory(
        previous_packages_dir, "previous FreeBSD package directory"
    )
    try:
        same_directory = candidate_root.samefile(previous_root)
    except OSError as exc:
        raise FreeBSDVMLabError(
            f"cannot compare candidate and previous package directories: {exc}"
        ) from exc
    if same_directory:
        raise FreeBSDVMLabError(
            "candidate and previous FreeBSD package directories must be distinct"
        )

    candidate = discover_package(candidate_root)
    previous = discover_package(previous_root)
    if candidate.path.name == previous.path.name or candidate.version == previous.version:
        raise FreeBSDVMLabError(
            "candidate and previous FreeBSD package versions must be distinct"
        )
    if candidate.sha256 == previous.sha256:
        raise FreeBSDVMLabError(
            "candidate and previous FreeBSD package checksums must be distinct"
        )
    if version_tuple(previous.version) >= version_tuple(candidate.version):
        raise FreeBSDVMLabError(
            "previous FreeBSD package version must be older than the candidate"
        )
    return candidate, previous


def inspect_product_assets(repo_root: Path) -> ProductAssets:
    repository = require_real_directory(repo_root, "repository root")
    fixture = require_regular_file(
        repository / "testdata/firewall/pf-v4.02.8.conf", "FreeBSD PF fixture"
    )
    fixture_text = fixture.read_text(encoding="utf-8")
    if fixture_text.count("vtnet-test0") < 1:
        raise FreeBSDVMLabError(
            "FreeBSD PF fixture no longer exposes its isolated test interface"
        )
    source = require_regular_file(
        repository
        / "src/core/syswarden-cli/pkg/firewall/firewall_freebsd.go",
        "FreeBSD firewall source",
    )
    source_text = source.read_text(encoding="utf-8")
    source_bad = (
        'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")'
        in source_text
    )
    if not source_bad and "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)" not in source_text:
        raise FreeBSDVMLabError(
            "FreeBSD firewall source does not use the reviewed honeyport serializer"
        )
    return ProductAssets(repository, fixture, sha256_file(fixture), source_bad)


def ssh_arguments(
    ssh: str,
    host: str,
    port: int,
    user: str,
    identity: Path,
    known_hosts: Path,
) -> tuple[str, ...]:
    destination_host = f"[{host}]" if ":" in host else host
    address_family = "inet6" if ":" in host else "inet"
    return (
        ssh,
        "-F",
        "/dev/null",
        "-T",
        "-p",
        str(port),
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        f"HostName={host}",
        "-o",
        f"AddressFamily={address_family}",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=3",
        f"{user}@{destination_host}",
    )


def scp_arguments(
    scp: str,
    host: str,
    port: int,
    user: str,
    identity: Path,
    known_hosts: Path,
    source: Path,
    destination: str,
) -> tuple[str, ...]:
    if REMOTE_ROOT_PATTERN.fullmatch(str(Path(destination).parent)) is None:
        raise FreeBSDVMLabError(f"unsafe remote copy destination: {destination}")
    destination_host = f"[{host}]" if ":" in host else host
    address_family = "inet6" if ":" in host else "inet"
    return (
        scp,
        "-F",
        "/dev/null",
        "-P",
        str(port),
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        f"HostName={host}",
        "-o",
        f"AddressFamily={address_family}",
        "-o",
        "CanonicalizeHostname=no",
        str(source),
        f"{user}@{destination_host}:{destination}",
    )


PROBE_SCRIPT = r'''
set +e
token="${token:?VM marker token was not supplied through stdin}"
emit() {
    encoded="$(printf '%s' "$2" | /usr/bin/base64 | tr -d '\n')"
    printf 'SWL0\t%s\t%s\n' "$1" "$encoded"
}
marker="$(sudo -n /bin/cat /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
marker_match=0
if [ "$marker" = "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}" ]; then
    marker_match=1
fi
emit MARKER_MATCH "$marker_match"
marker_owner="$(sudo -n /usr/bin/stat -f '%u' /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
marker_mode="$(sudo -n /usr/bin/stat -f '%Lp' /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
marker_safe=0
if sudo -n /bin/test -f /var/run/syswarden-lot0-disposable.marker && \
   ! sudo -n /bin/test -L /var/run/syswarden-lot0-disposable.marker && \
   [ "$marker_owner" = "0" ]; then
    case "$marker_mode" in
        600|640|644) marker_safe=1 ;;
    esac
fi
emit MARKER_SAFE "$marker_safe"
emit OS_NAME "$(uname -s 2>/dev/null)"
emit OS_RELEASE "$(freebsd-version -u 2>/dev/null)"
emit MACHINE "$(uname -m 2>/dev/null)"
sudo_ready=0
if sudo -n /usr/bin/true >/dev/null 2>&1; then
    sudo_ready=1
fi
emit SUDO_READY "$sudo_ready"
base64_ready=0
if command -v base64 >/dev/null 2>&1; then
    base64_ready=1
fi
emit BASE64_READY "$base64_ready"
exit 0
'''.strip()


PREPARE_SCRIPT = r'''
set -eu
work="$1"
case "$work" in
    /tmp/syswarden-freebsd-lot0-[a-f0-9][a-f0-9]*) ;;
    *) exit 90 ;;
esac
[ ! -e "$work" ]
umask 077
mkdir "$work"
chmod 700 "$work"
'''.strip()


REMOTE_LAB_SCRIPT = r'''
set +e
umask 077
export LC_ALL=C
token="${token:?VM marker token was not supplied through stdin}"

work="$1"
previous_package_name="$2"
previous_expected_sha="$3"
previous_expected_version="$4"
candidate_package_name="$5"
candidate_expected_sha="$6"
candidate_expected_version="$7"
source_bad="$8"
pf_expected_sha="$9"
anchor_nonce="${10}"
command_timeout="${11}"
anchor="syswarden_lot0_${anchor_nonce}"
lock_path=/var/run/syswarden-lot0-lab.lock
lock_acquired=0
vm_cleanup_authorized=0
pf_cleanup_authorized=0
baseline_status=

emit() {
    encoded="$(printf '%s' "$2" | /usr/bin/base64 | tr -d '\n')"
    printf 'SWL0\t%s\t%s\n' "$1" "$encoded"
}
boolean() {
    if "$@"; then printf 1; else printf 0; fi
}
quiet_boolean() {
    if "$@" >/dev/null 2>&1; then printf 1; else printf 0; fi
}
cleanup_vm() {
    if [ "$vm_cleanup_authorized" -ne 1 ]; then
        return 0
    fi
    service syswardenwebtui onestop >/dev/null 2>&1 || true
    service syswarden onestop >/dev/null 2>&1 || true
    env ASSUME_ALWAYS_YES=yes pkg delete -fy syswarden >/dev/null 2>&1 || true
    if [ "$pf_cleanup_authorized" -eq 1 ]; then
        pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
        if [ "$baseline_status" = "Disabled" ]; then
            pfctl -d >/dev/null 2>&1 || true
        fi
        pfctl -F all >/dev/null 2>&1 || true
    fi
    sysrc -x syswarden_enable >/dev/null 2>&1 || true
    sysrc -x syswardenwebtui_enable >/dev/null 2>&1 || true
    rm -f /usr/local/bin/syswarden /usr/local/bin/syswarden-tui
    rm -f /usr/local/etc/rc.d/syswarden /usr/local/etc/rc.d/syswardenwebtui
    rm -rf /usr/local/syswarden /opt/syswarden /etc/syswarden /var/lib/syswarden
}
# shellcheck disable=SC2317 # Invoked indirectly by the final signal/exit trap.
final_cleanup() {
    cleanup_exit_status="$1"
    trap - EXIT HUP INT TERM
    cleanup_vm
    rm -rf "$work"
    if [ "$lock_acquired" -eq 1 ]; then
        rmdir "$lock_path" >/dev/null 2>&1 || true
    fi
    exit "$cleanup_exit_status"
}
mode_of() {
    stat -f '%Lp' "$1" 2>/dev/null || true
}
elf_arch_of() {
    elf_path="$1"
    if [ ! -f "$elf_path" ] || [ -L "$elf_path" ]; then
        printf invalid
        return
    fi
    elf_description="$(file -b "$elf_path" 2>/dev/null || true)"
    case "$elf_description" in
        ELF*64-bit*LSB*x86-64*) printf amd64 ;;
        ELF*64-bit*LSB*ARM*aarch64*) printf arm64 ;;
        *) printf invalid ;;
    esac
}
flag_value() {
    sysrc -n "$1" 2>/dev/null || true
}
user_state_inventory() {
    for path in \
        /etc/syswarden/config/lifecycle-user.conf \
        /var/lib/syswarden/lifecycle-user.state; do
        if [ -f "$path" ] && [ ! -L "$path" ]; then
            printf '%s\n' "$path"
        fi
    done | LC_ALL=C sort
}
full_state_inventory() {
    {
        for root in \
            /usr/local/syswarden \
            /usr/local/bin/syswarden \
            /usr/local/bin/syswarden-tui \
            /usr/local/etc/rc.d/syswarden \
            /usr/local/etc/rc.d/syswardenwebtui \
            /etc/syswarden \
            /var/lib/syswarden \
            /opt/syswarden; do
            if [ -d "$root" ] && [ ! -L "$root" ]; then
                find "$root" -print 2>/dev/null
            elif [ -e "$root" ] || [ -L "$root" ]; then
                printf '%s\n' "$root"
            fi
        done
    } | LC_ALL=C sort -u | while IFS= read -r path; do
        kind="$(stat -f '%HT' "$path" 2>/dev/null || true)"
        mode="$(stat -f '%Lp' "$path" 2>/dev/null || true)"
        uid="$(stat -f '%u' "$path" 2>/dev/null || true)"
        gid="$(stat -f '%g' "$path" 2>/dev/null || true)"
        target=-
        if [ -L "$path" ]; then
            target="$(readlink "$path" 2>/dev/null || true)"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$path" "$kind" "$mode" "$uid" "$gid" "$target"
    done
}
signature_state() {
    path="$1"
    if [ -L "$path" ]; then
        target="$(readlink "$path" 2>/dev/null || true)"
        target_sha="$(printf '%s' "$target" | sha256 -q 2>/dev/null || true)"
        printf 'symlink:%s:%s:%s:%s' \
            "$target_sha" \
            "$(stat -f '%Lp' "$path" 2>/dev/null || true)" \
            "$(stat -f '%u' "$path" 2>/dev/null || true)" \
            "$(stat -f '%g' "$path" 2>/dev/null || true)"
    elif [ -f "$path" ]; then
        printf 'file:%s:%s:%s:%s' \
            "$(sha256 -q "$path" 2>/dev/null || true)" \
            "$(stat -f '%Lp' "$path" 2>/dev/null || true)" \
            "$(stat -f '%u' "$path" 2>/dev/null || true)" \
            "$(stat -f '%g' "$path" 2>/dev/null || true)"
    elif [ ! -e "$path" ]; then
        printf absent
    else
        printf 'other:%s:%s:%s:%s' \
            "$(stat -f '%HT' "$path" 2>/dev/null || true)" \
            "$(stat -f '%Lp' "$path" 2>/dev/null || true)" \
            "$(stat -f '%u' "$path" 2>/dev/null || true)" \
            "$(stat -f '%g' "$path" 2>/dev/null || true)"
    fi
}
probe_signatures() {
    phase="$1"
    signature_file=/usr/local/syswarden/signatures.json
    signature_log="$work/signature-${phase}.log"
    runtime_signature=/opt/syswarden/signatures.json
    (
        runtime_parent=/opt/syswarden
        runtime_parent_existed=0
        [ -d "$runtime_parent" ] && runtime_parent_existed=1
        runtime_signature_kind="absent"
        runtime_signature_target=
        runtime_signature_mode=
        runtime_signature_uid=
        runtime_signature_gid=
        runtime_signature_backup="$work/runtime-signature-${phase}.save"
        runtime_signature_backup_ready=1
        runtime_signature_mutated=0
        if [ -L "$runtime_signature" ]; then
            runtime_signature_kind="symlink"
            runtime_signature_target="$(readlink "$runtime_signature" 2>/dev/null || true)"
            runtime_signature_mode="$(stat -f '%Lp' "$runtime_signature" 2>/dev/null || true)"
            runtime_signature_uid="$(stat -f '%u' "$runtime_signature" 2>/dev/null || true)"
            runtime_signature_gid="$(stat -f '%g' "$runtime_signature" 2>/dev/null || true)"
        elif [ -f "$runtime_signature" ]; then
            runtime_signature_kind="file"
            runtime_signature_mode="$(stat -f '%Lp' "$runtime_signature" 2>/dev/null || true)"
            runtime_signature_uid="$(stat -f '%u' "$runtime_signature" 2>/dev/null || true)"
            runtime_signature_gid="$(stat -f '%g' "$runtime_signature" 2>/dev/null || true)"
            cp -p "$runtime_signature" "$runtime_signature_backup" || \
                runtime_signature_backup_ready=0
        elif [ -e "$runtime_signature" ]; then
            runtime_signature_kind="other"
        fi
        signature_before="$(signature_state "$runtime_signature")"
        restore_signature_state() {
            if [ "$runtime_signature_mutated" -eq 0 ]; then
                return 0
            fi
            case "$runtime_signature_kind" in
                absent)
                    rm -rf "$runtime_signature"
                    if [ "$runtime_parent_existed" -eq 0 ]; then
                        rmdir "$runtime_parent" >/dev/null 2>&1 || true
                    fi
                    ;;
                file)
                    rm -rf "$runtime_signature"
                    cp -p "$runtime_signature_backup" "$runtime_signature" || return 1
                    chown "${runtime_signature_uid}:${runtime_signature_gid}" \
                        "$runtime_signature" || return 1
                    chmod "$runtime_signature_mode" "$runtime_signature" || return 1
                    ;;
                symlink)
                    rm -rf "$runtime_signature"
                    ln -s "$runtime_signature_target" "$runtime_signature" || return 1
                    chown -h "${runtime_signature_uid}:${runtime_signature_gid}" \
                        "$runtime_signature" || return 1
                    chmod -h "$runtime_signature_mode" "$runtime_signature" || return 1
                    ;;
                other)
                    ;;
            esac
            return 0
        }

        # Install restoration before the first mutation of the runtime path.
        trap 'restore_signature_state >/dev/null 2>&1' EXIT
        trap 'exit 97' HUP INT TERM

        signature_rules="$(grep -Ec '^[[:space:]]*"id"[[:space:]]*:' "$signature_file" 2>/dev/null || true)"
        signature_probe_rc=125
        signature_engine_count=
        signature_load_error=1
        service syswardenwebtui onestop >/dev/null 2>&1 || true
        service syswarden onestop >/dev/null 2>&1 || true
        rm -f /var/run/syswarden.sock
        if [ "$runtime_signature_kind" != other ] && \
           [ "$runtime_signature_backup_ready" -eq 1 ] && \
           [ -f "$signature_file" ] && [ ! -L "$signature_file" ]; then
            if mkdir -p "$runtime_parent"; then
                runtime_signature_mutated=1
                rm -rf "$runtime_signature"
            fi
            if [ "$runtime_signature_mutated" -eq 1 ] && \
               cp "$signature_file" "$runtime_signature"; then
                timeout 8 /usr/local/syswarden/bin/syswarden-core \
                    >"$signature_log" 2>&1
                signature_probe_rc=$?
                signature_engine_count="$(sed -n 's/.*Loaded \([0-9][0-9]*\) threat signatures.*/\1/p' "$signature_log" | tail -n 1)"
                signature_load_error=0
                if grep -q 'Failed to initialize threat engine' \
                    "$signature_log" 2>/dev/null; then
                    signature_load_error=1
                fi
            fi
        fi
        rm -f /var/run/syswarden.sock
        restore_signature_state
        signature_restore_rc=$?
        signature_after="$(signature_state "$runtime_signature")"
        signature_restored=0
        if [ "$signature_restore_rc" -eq 0 ] && \
           [ "$signature_before" = "$signature_after" ]; then
            signature_restored=1
            trap - EXIT
        fi
        trap - HUP INT TERM

        emit "${phase}_SIGNATURE_RULE_COUNT" "$signature_rules"
        emit "${phase}_SIGNATURE_ENGINE_COUNT" "$signature_engine_count"
        emit "${phase}_SIGNATURE_PROBE_RC" "$signature_probe_rc"
        emit "${phase}_SIGNATURE_LOAD_ERROR" "$signature_load_error"
        emit "${phase}_SIGNATURE_STATE_BEFORE" "$signature_before"
        emit "${phase}_SIGNATURE_STATE_AFTER" "$signature_after"
        emit "${phase}_SIGNATURE_STATE_RESTORED" "$signature_restored"
    )
}
capture_installed_phase() {
    phase="$1"
    operation_rc="$2"
    emit "${phase}_OPERATION_RC" "$operation_rc"
    emit "${phase}_PKG_INSTALLED" "$(quiet_boolean pkg info -e syswarden)"
    emit "${phase}_PKG_NAME" "$(pkg query '%n' syswarden 2>/dev/null || true)"
    emit "${phase}_PKG_VERSION" "$(pkg query '%v' syswarden 2>/dev/null || true)"
    emit "${phase}_PKG_ARCH" "$(pkg query '%q' syswarden 2>/dev/null || true)"
    emit "${phase}_PKG_INVENTORY" "$(pkg query '%Fp' syswarden 2>/dev/null | LC_ALL=C sort || true)"
    emit "${phase}_ELF_CLI_ARCH" "$(elf_arch_of /usr/local/syswarden/bin/syswarden-cli)"
    emit "${phase}_ELF_CORE_ARCH" "$(elf_arch_of /usr/local/syswarden/bin/syswarden-core)"
    emit "${phase}_ELF_TUI_ARCH" "$(elf_arch_of /usr/local/syswarden/bin/syswarden-tui)"
    emit "${phase}_USER_STATE_INVENTORY" "$(user_state_inventory)"
    emit "${phase}_USER_CONFIG_SHA256" "$(sha256 -q /etc/syswarden/config/lifecycle-user.conf 2>/dev/null || true)"
    emit "${phase}_USER_DATA_SHA256" "$(sha256 -q /var/lib/syswarden/lifecycle-user.state 2>/dev/null || true)"
    probe_signatures "$phase"
}

emit ROOT_UID "$(id -u)"
marker="$(cat /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
emit MARKER_MATCH "$(boolean test "$marker" = "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}")"
marker_owner="$(stat -f '%u' /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
marker_mode="$(stat -f '%Lp' /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
marker_safe=0
if [ -f /var/run/syswarden-lot0-disposable.marker ] && \
   [ ! -L /var/run/syswarden-lot0-disposable.marker ] && \
   [ "$marker_owner" = "0" ]; then
    case "$marker_mode" in
        600|640|644) marker_safe=1 ;;
    esac
fi
emit MARKER_SAFE "$marker_safe"
emit OS_NAME "$(uname -s 2>/dev/null)"
emit OS_RELEASE "$(freebsd-version -u 2>/dev/null)"
emit MACHINE "$(uname -m 2>/dev/null)"
emit PKG_TOOL_READY "$(quiet_boolean command -v pkg)"
emit PF_TOOL_READY "$(quiet_boolean command -v pfctl)"
emit TIMEOUT_TOOL_READY "$(quiet_boolean command -v timeout)"
emit FILE_TOOL_READY "$(quiet_boolean command -v file)"

safe_work=0
case "$work" in
    /tmp/syswarden-freebsd-lot0-[a-f0-9][a-f0-9]*) safe_work=1 ;;
esac
case "$source_bad" in
    0|1) ;;
    *) exit 91 ;;
esac
case "$pf_expected_sha" in
    ''|*[!a-f0-9]*) exit 91 ;;
esac
case "$anchor_nonce" in
    ''|*[!a-f0-9]*) exit 91 ;;
esac
if [ "$safe_work" -ne 1 ] || [ "$(id -u)" -ne 0 ] || \
   [ "$marker" != "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}" ] || \
   [ "$marker_safe" -ne 1 ] || \
   [ "$(uname -s 2>/dev/null)" != "FreeBSD" ] || \
   [ "$(uname -m 2>/dev/null)" != "amd64" ] || \
   [ "${#pf_expected_sha}" -ne 64 ] || \
   [ "${#anchor_nonce}" -ne 32 ] || \
   [ "$previous_package_name" != "syswarden-${previous_expected_version}.txz" ] || \
   [ "$candidate_package_name" != "syswarden-${candidate_expected_version}.txz" ] || \
   [ "$previous_package_name" = "$candidate_package_name" ] || \
   [ "$previous_expected_sha" = "$candidate_expected_sha" ] || \
   [ "$previous_expected_version" = "$candidate_expected_version" ]; then
    exit 91
fi
trap 'final_cleanup "$?"' EXIT HUP INT TERM

for required_input in \
    "$work/$previous_package_name" \
    "$work/$candidate_package_name" \
    "$work/pf-v4.02.8.conf"; do
    if [ ! -f "$required_input" ] || [ -L "$required_input" ]; then
        exit 91
    fi
done
chown -R 0:0 "$work" || exit 91
chmod 700 "$work" || exit 91
chmod 600 \
    "$work/$previous_package_name" \
    "$work/$candidate_package_name" \
    "$work/pf-v4.02.8.conf" || exit 91

preclean=1
pkg info -e syswarden >/dev/null 2>&1 && preclean=0
for path in \
    /usr/local/syswarden /opt/syswarden /usr/local/bin/syswarden \
    /usr/local/bin/syswarden-tui /usr/local/etc/rc.d/syswarden \
    /usr/local/etc/rc.d/syswardenwebtui /etc/syswarden \
    /var/lib/syswarden; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        preclean=0
    fi
done
emit PRECLEAN "$preclean"
if [ "$preclean" -ne 1 ]; then
    exit 92
fi

previous_actual_sha="$(sha256 -q "$work/$previous_package_name" 2>/dev/null)"
candidate_actual_sha="$(sha256 -q "$work/$candidate_package_name" 2>/dev/null)"
pf_actual_sha="$(sha256 -q "$work/pf-v4.02.8.conf" 2>/dev/null)"
emit PREVIOUS_PACKAGE_SHA256 "$previous_actual_sha"
emit CANDIDATE_PACKAGE_SHA256 "$candidate_actual_sha"
emit PF_FIXTURE_SHA256 "$pf_actual_sha"
pf_fixture_sha_match=0
if [ "$pf_actual_sha" = "$pf_expected_sha" ]; then
    pf_fixture_sha_match=1
fi
emit PF_FIXTURE_SHA_MATCH "$pf_fixture_sha_match"
if [ "$previous_actual_sha" != "$previous_expected_sha" ] || \
   [ "$candidate_actual_sha" != "$candidate_expected_sha" ] || \
   [ "$pf_fixture_sha_match" -ne 1 ]; then
    exit 93
fi

emit PF_ANCHOR_NAME "$anchor"
if ! mkdir "$lock_path" 2>/dev/null; then
    emit LAB_LOCK_ACQUIRED 0
    exit 96
fi
lock_acquired=1
chmod 700 "$lock_path" || exit 96
emit LAB_LOCK_ACQUIRED 1

kldload pf >"$work/kldload.log" 2>&1 || true
pfctl -s info >"$work/pf-info-before" 2>&1
pf_ready=$?
emit PF_BASELINE_READY "$(test "$pf_ready" -eq 0 && printf 1 || printf 0)"
if [ "$pf_ready" -ne 0 ]; then
    exit 94
fi
pfctl -sr >"$work/pf-filter-before" 2>&1
filter_rc=$?
pfctl -sn >"$work/pf-nat-before" 2>&1
nat_rc=$?
pfctl -s Tables >"$work/pf-tables-before" 2>&1
tables_rc=$?
baseline_clean=0
if [ "$filter_rc" -eq 0 ] && [ "$nat_rc" -eq 0 ] && \
   [ "$tables_rc" -eq 0 ] && [ ! -s "$work/pf-filter-before" ] && \
   [ ! -s "$work/pf-nat-before" ] && [ ! -s "$work/pf-tables-before" ]; then
    baseline_clean=1
fi
emit PF_BASELINE_CLEAN "$baseline_clean"
baseline_status="$(awk '/^Status:/{print $2; exit}' "$work/pf-info-before")"
emit PF_BASELINE_STATUS "$baseline_status"
snapshot_sha="$(cat "$work/pf-filter-before" "$work/pf-nat-before" "$work/pf-tables-before" | sha256 -q)"
emit PF_SNAPSHOT_SHA256 "$snapshot_sha"
if [ "$baseline_clean" -ne 1 ] || [ "$baseline_status" != "Disabled" ]; then
    exit 95
fi
vm_cleanup_authorized=1
pf_cleanup_authorized=1

mkdir -p /etc/syswarden/config /var/lib/syswarden
printf '%s\n' 'syswarden-freebsd-user-config-state-v1' \
    >/etc/syswarden/config/lifecycle-user.conf
printf '%s\n' 'syswarden-freebsd-user-data-state-v1' \
    >/var/lib/syswarden/lifecycle-user.state

env ASSUME_ALWAYS_YES=yes SYSWARDEN_PKG_INSTALL=1 \
    timeout "$command_timeout" pkg add -f "$work/$previous_package_name" \
    >"$work/previous-install.log" 2>&1
previous_install_rc=$?
capture_installed_phase PREVIOUS_INSTALL "$previous_install_rc"

env ASSUME_ALWAYS_YES=yes SYSWARDEN_PKG_INSTALL=1 \
    timeout "$command_timeout" pkg add -f "$work/$candidate_package_name" \
    >"$work/candidate-upgrade.log" 2>&1
candidate_upgrade_rc=$?
capture_installed_phase CANDIDATE_UPGRADE "$candidate_upgrade_rc"

env ASSUME_ALWAYS_YES=yes SYSWARDEN_PKG_INSTALL=1 \
    timeout "$command_timeout" pkg add -f "$work/$candidate_package_name" \
    >"$work/candidate-reinstall.log" 2>&1
candidate_reinstall_rc=$?
capture_installed_phase CANDIDATE_REINSTALL "$candidate_reinstall_rc"

emit MODE_CLI "$(mode_of /usr/local/syswarden/bin/syswarden-cli)"
emit MODE_CORE "$(mode_of /usr/local/syswarden/bin/syswarden-core)"
emit MODE_TUI "$(mode_of /usr/local/syswarden/bin/syswarden-tui)"
emit MODE_SIGNATURES "$(mode_of /usr/local/syswarden/signatures.json)"
emit LINK_CLI "$(readlink /usr/local/bin/syswarden 2>/dev/null || true)"
emit LINK_TUI "$(readlink /usr/local/bin/syswarden-tui 2>/dev/null || true)"

timeout 20 /usr/local/syswarden/bin/syswarden-cli --help \
    >"$work/cli-direct.log" 2>&1
emit CLI_DIRECT_RC "$?"
timeout 20 /usr/local/bin/syswarden --help >"$work/cli-link.log" 2>&1
emit CLI_LINK_RC "$?"
emit SIGNATURE_PACKAGE_PATH "$(boolean test -f /usr/local/syswarden/signatures.json)"
emit SIGNATURE_RUNTIME_PATH "$(boolean test -f /opt/syswarden/signatures.json)"

emit RC_CORE_PRESENT "$(boolean test -f /usr/local/etc/rc.d/syswarden)"
emit RC_WEB_PRESENT "$(boolean test -f /usr/local/etc/rc.d/syswardenwebtui)"
emit RC_CORE_MODE "$(mode_of /usr/local/etc/rc.d/syswarden)"
emit RC_WEB_MODE "$(mode_of /usr/local/etc/rc.d/syswardenwebtui)"
emit RC_CORE_COMMAND "$(awk -F= '/^command=/{gsub(/\"/,"",$2); print $2; exit}' /usr/local/etc/rc.d/syswarden 2>/dev/null)"
emit RC_WEB_COMMAND "$(awk -F= '/^command=/{gsub(/\"/,"",$2); print $2; exit}' /usr/local/etc/rc.d/syswardenwebtui 2>/dev/null)"
emit RC_CORE_ENABLED "$(flag_value syswarden_enable)"
emit RC_WEB_ENABLED "$(flag_value syswardenwebtui_enable)"

timeout 20 service syswarden onestart >"$work/core-start.log" 2>&1
core_start_rc=$?
emit RC_CORE_START_RC "$core_start_rc"
service syswarden onestatus >"$work/core-status.log" 2>&1
core_status_rc=$?
emit RC_CORE_STATUS_RC "$core_status_rc"
timeout 20 service syswardenwebtui onestart >"$work/web-start.log" 2>&1
web_start_rc=$?
emit RC_WEB_START_RC "$web_start_rc"
service syswardenwebtui onestatus >"$work/web-status.log" 2>&1
web_status_rc=$?
emit RC_WEB_STATUS_RC "$web_status_rc"

emit RESTART_BASELINE_INVENTORY "$(full_state_inventory)"

timeout 20 service syswarden onerestart >"$work/core-restart-one.log" 2>&1
core_restart_one_rc=$?
emit RC_CORE_RESTART_ONE_RC "$core_restart_one_rc"
service syswarden onestatus >"$work/core-restart-one-status.log" 2>&1
core_restart_one_status_rc=$?
emit RC_CORE_RESTART_ONE_STATUS_RC "$core_restart_one_status_rc"
timeout 20 service syswardenwebtui onerestart >"$work/web-restart-one.log" 2>&1
web_restart_one_rc=$?
emit RC_WEB_RESTART_ONE_RC "$web_restart_one_rc"
service syswardenwebtui onestatus >"$work/web-restart-one-status.log" 2>&1
web_restart_one_status_rc=$?
emit RC_WEB_RESTART_ONE_STATUS_RC "$web_restart_one_status_rc"

emit RESTART_ONE_INVENTORY "$(full_state_inventory)"

timeout 20 service syswarden onerestart >"$work/core-restart-two.log" 2>&1
core_restart_two_rc=$?
emit RC_CORE_RESTART_TWO_RC "$core_restart_two_rc"
service syswarden onestatus >"$work/core-restart-two-status.log" 2>&1
core_restart_two_status_rc=$?
emit RC_CORE_RESTART_TWO_STATUS_RC "$core_restart_two_status_rc"
timeout 20 service syswardenwebtui onerestart >"$work/web-restart-two.log" 2>&1
web_restart_two_rc=$?
emit RC_WEB_RESTART_TWO_RC "$web_restart_two_rc"
service syswardenwebtui onestatus >"$work/web-restart-two-status.log" 2>&1
web_restart_two_status_rc=$?
emit RC_WEB_RESTART_TWO_STATUS_RC "$web_restart_two_status_rc"

emit RESTART_TWO_INVENTORY "$(full_state_inventory)"

service syswardenwebtui onestop >/dev/null 2>&1 || true
service syswarden onestop >/dev/null 2>&1 || true
restart_idempotence_rc=0
for restart_rc in \
    "$core_start_rc" "$core_status_rc" \
    "$core_restart_one_rc" "$core_restart_one_status_rc" \
    "$core_restart_two_rc" "$core_restart_two_status_rc" \
    "$web_start_rc" "$web_status_rc" \
    "$web_restart_one_rc" "$web_restart_one_status_rc" \
    "$web_restart_two_rc" "$web_restart_two_status_rc"; do
    if [ "$restart_rc" -ne 0 ]; then
        restart_idempotence_rc=1
    fi
done
capture_installed_phase CANDIDATE_RESTART_IDEMPOTENCE "$restart_idempotence_rc"

interface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
case "$interface" in
    ''|*[!A-Za-z0-9_.-]*) interface="INVALID" ;;
esac
emit PF_INTERFACE "$interface"
mkdir -p "$work/lists"
for name in \
    syswarden_whitelist.ipv4 syswarden_whitelist.ipv6 \
    syswarden_blacklist.ipv4 syswarden_threatintel.ipv4 \
    syswarden_blacklist.ipv6 syswarden_threatintel.ipv6; do
    : >"$work/lists/$name"
done
if [ "$interface" != "INVALID" ]; then
    # Revalidate immediately before deriving and applying the PF input.  The
    # copied fixture has already been made root-owned and non-writable by the
    # transport account.
    if [ "$(sha256 -q "$work/pf-v4.02.8.conf" 2>/dev/null)" != \
         "$pf_expected_sha" ]; then
        exit 93
    fi
    sed -e "s/vtnet-test0/$interface/g" \
        -e "s#/etc/syswarden/lists/#$work/lists/#g" \
        "$work/pf-v4.02.8.conf" >"$work/pf-lab.conf"
    pfctl -n -a "$anchor" -f "$work/pf-lab.conf" >"$work/pf-syntax.log" 2>&1
    pf_syntax_rc=$?
    emit PF_FIXTURE_SYNTAX_RC "$pf_syntax_rc"
    if [ "$pf_syntax_rc" -eq 0 ]; then
        pfctl -a "$anchor" -f "$work/pf-lab.conf" >"$work/pf-apply.log" 2>&1
        pf_apply_rc=$?
    else
        pf_apply_rc=125
    fi
    emit PF_FIXTURE_APPLY_RC "$pf_apply_rc"
    emit PF_FIXTURE_RULE_COUNT "$(pfctl -a "$anchor" -sr 2>/dev/null | awk 'NF{n++} END{print n+0}')"
    pfctl -a "$anchor" -F all >/dev/null 2>&1
    anchor_cleanup_rc=$?
    anchor_lines="$(pfctl -a "$anchor" -sr 2>/dev/null | awk 'NF{n++} END{print n+0}')"
    emit PF_ANCHOR_CLEAN "$(test "$anchor_cleanup_rc" -eq 0 -a "$anchor_lines" -eq 0 && printf 1 || printf 0)"
    if [ "$source_bad" -eq 1 ]; then
        honeyports='23 6379'
        honeyport_exact_value="$(printf '%s' "$honeyports" | tr -d ' ')"
    else
        honeyport_exact_value='23, 6379'
    fi
    printf 'block drop in log quick on %s proto tcp to any port { %s }\n' \
        "$interface" "$honeyport_exact_value" \
        >"$work/pf-honeyport.conf"
    emit PF_HONEYPORT_EXACT_VALUE "$honeyport_exact_value"
    pfctl -n -a "$anchor" -f "$work/pf-honeyport.conf" >"$work/pf-honeyport.log" 2>&1
    emit PF_HONEYPORT_SYNTAX_RC "$?"
else
    emit PF_FIXTURE_SYNTAX_RC 125
    emit PF_FIXTURE_APPLY_RC 125
    emit PF_FIXTURE_RULE_COUNT 0
    emit PF_ANCHOR_CLEAN 0
    emit PF_HONEYPORT_EXACT_VALUE ""
    emit PF_HONEYPORT_SYNTAX_RC not_run
fi
emit PF_HONEYPORT_SOURCE_BAD "$source_bad"

env ASSUME_ALWAYS_YES=yes SYSWARDEN_PKG_INSTALL=1 \
    timeout "$command_timeout" pkg add -f "$work/$previous_package_name" \
    >"$work/previous-rollback.log" 2>&1
previous_rollback_rc=$?
capture_installed_phase PREVIOUS_ROLLBACK "$previous_rollback_rc"

env ASSUME_ALWAYS_YES=yes timeout 120 pkg delete -fy syswarden \
    >"$work/pkg-delete.log" 2>&1
emit REMOVE_RC "$?"
remove_package_absent=0
if ! pkg info -e syswarden >/dev/null 2>&1; then
    remove_package_absent=1
fi
emit REMOVE_PACKAGE_ABSENT "$remove_package_absent"
emit REMOVE_PKG_INVENTORY "$(pkg query '%Fp' syswarden 2>/dev/null | LC_ALL=C sort || true)"
payload_absent=1
for path in /usr/local/syswarden/bin/syswarden-cli \
    /usr/local/syswarden/bin/syswarden-core \
    /usr/local/syswarden/bin/syswarden-tui \
    /usr/local/syswarden/signatures.json; do
    [ -e "$path" ] && payload_absent=0
done
emit REMOVE_PAYLOAD_ABSENT "$payload_absent"
links_absent=1
if [ -e /usr/local/bin/syswarden ] || [ -L /usr/local/bin/syswarden ]; then
    links_absent=0
fi
if [ -e /usr/local/bin/syswarden-tui ] || [ -L /usr/local/bin/syswarden-tui ]; then
    links_absent=0
fi
emit REMOVE_LINKS_ABSENT "$links_absent"
emit REMOVE_RC_CORE_ABSENT "$(boolean test ! -e /usr/local/etc/rc.d/syswarden)"
emit REMOVE_RC_WEB_ABSENT "$(boolean test ! -e /usr/local/etc/rc.d/syswardenwebtui)"
remove_core_flag_absent=0
if ! sysrc -n syswarden_enable >/dev/null 2>&1; then
    remove_core_flag_absent=1
fi
emit REMOVE_CORE_FLAG_ABSENT "$remove_core_flag_absent"
remove_web_flag_absent=0
if ! sysrc -n syswardenwebtui_enable >/dev/null 2>&1; then
    remove_web_flag_absent=1
fi
emit REMOVE_WEB_FLAG_ABSENT "$remove_web_flag_absent"
emit REMOVE_USER_STATE_INVENTORY "$(user_state_inventory)"
emit REMOVE_USER_CONFIG_SHA256 "$(sha256 -q /etc/syswarden/config/lifecycle-user.conf 2>/dev/null || true)"
emit REMOVE_USER_DATA_SHA256 "$(sha256 -q /var/lib/syswarden/lifecycle-user.state 2>/dev/null || true)"

cleanup_vm
cleanup_ok=1
pkg info -e syswarden >/dev/null 2>&1 && cleanup_ok=0
for path in /usr/local/syswarden /opt/syswarden /usr/local/bin/syswarden \
    /usr/local/bin/syswarden-tui /usr/local/etc/rc.d/syswarden \
    /usr/local/etc/rc.d/syswardenwebtui /etc/syswarden \
    /var/lib/syswarden; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        cleanup_ok=0
    fi
done
emit LAB_CLEANUP_OK "$cleanup_ok"
pfctl -sr >"$work/pf-filter-after" 2>&1
filter_after_rc=$?
pfctl -sn >"$work/pf-nat-after" 2>&1
nat_after_rc=$?
pfctl -s Tables >"$work/pf-tables-after" 2>&1
tables_after_rc=$?
pfctl -s info >"$work/pf-info-after" 2>&1
info_after_rc=$?
final_status="$(awk '/^Status:/{print $2; exit}' "$work/pf-info-after")"
emit PF_FINAL_STATUS "$final_status"
restored=0
if [ "$filter_after_rc" -eq 0 ] && [ "$nat_after_rc" -eq 0 ] && \
   [ "$tables_after_rc" -eq 0 ] && [ "$info_after_rc" -eq 0 ] && \
   [ "$baseline_status" = "Disabled" ] && [ "$final_status" = "Disabled" ] && \
   cmp -s "$work/pf-filter-before" "$work/pf-filter-after" && \
   cmp -s "$work/pf-nat-before" "$work/pf-nat-after" && \
   cmp -s "$work/pf-tables-before" "$work/pf-tables-after"; then
    restored=1
fi
emit PF_BASELINE_RESTORED "$restored"
lock_released=0
if rmdir "$lock_path" 2>/dev/null; then
    lock_released=1
    lock_acquired=0
fi
emit LAB_LOCK_RELEASED "$lock_released"
if [ "$lock_released" -ne 1 ]; then
    exit 96
fi
rm -rf "$work"
if [ -e "$work" ]; then
    exit 96
fi
trap - EXIT HUP INT TERM
exit 0
'''.strip()


def parse_markers(output: str, expected: frozenset[str]) -> dict[str, str]:
    if len(output.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise FreeBSDVMLabError("VM evidence output exceeds the bounded limit")
    markers: dict[str, str] = {}
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        match = MARKER_LINE_PATTERN.fullmatch(raw_line)
        if match is None:
            raise FreeBSDVMLabError(f"invalid VM evidence line: {raw_line[:120]!r}")
        key, encoded = match.groups()
        if key in markers:
            raise FreeBSDVMLabError(f"duplicate VM evidence marker: {key}")
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise FreeBSDVMLabError(f"invalid base64 evidence for {key}") from exc
        markers[key] = decoded
    if set(markers) != expected:
        raise FreeBSDVMLabError(
            f"VM evidence markers differ: expected {sorted(expected)}, "
            f"found {sorted(markers)}"
        )
    return markers


def require_transport_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-4000:]
        raise FreeBSDVMLabError(
            f"{description} failed with exit code {result.returncode}: {detail}"
        )


def validate_probe(markers: dict[str, str]) -> None:
    conditions = {
        "disposable VM marker": markers["MARKER_MATCH"] == "1",
        "root-owned VM marker": markers["MARKER_SAFE"] == "1",
        "FreeBSD operating system": markers["OS_NAME"] == "FreeBSD",
        "FreeBSD 14.4 userland": markers["OS_RELEASE"].startswith(
            "14.4-RELEASE"
        ),
        "amd64 machine": markers["MACHINE"] == "amd64",
        "passwordless sudo": markers["SUDO_READY"] == "1",
        "base64 utility": markers["BASE64_READY"] == "1",
    }
    failures = [name for name, passed in conditions.items() if not passed]
    if failures:
        raise FreeBSDVMLabError(
            "FreeBSD VM prerequisite check failed: " + ", ".join(failures)
        )


def check(
    check_id: str,
    category: str,
    passed: bool,
    expected: object,
    observed: object,
    detail: str,
) -> dict[str, object]:
    return {
        "id": check_id,
        "category": category,
        "status": "pass" if passed else "blocker",
        "expected": expected,
        "observed": observed,
        "detail": detail,
    }


def evidence_inventory(value: str) -> frozenset[str]:
    return frozenset(line for line in value.splitlines() if line)


def metadata_inventory(value: str) -> frozenset[str] | None:
    """Parse a complete scoped path/type/mode/uid/gid/link inventory."""

    records: set[str] = set()
    paths: set[str] = set()
    for line in value.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 6:
            return None
        path, kind, mode, uid, gid, target = fields
        if (
            not path.startswith("/")
            or not any(
                path == root or path.startswith(root + "/")
                for root in METADATA_INVENTORY_ROOTS
            )
            or path in paths
            or not kind
            or re.fullmatch(r"[0-7]{3,6}", mode) is None
            or not uid.isdigit()
            or not gid.isdigit()
        ):
            return None
        if kind.casefold() == "symbolic link":
            if not target or target == "-":
                return None
        elif target != "-":
            return None
        paths.add(path)
        records.add(line)
    return frozenset(records) if records else None


def valid_signature_state(value: str) -> bool:
    if value == "absent":
        return True
    return (
        re.fullmatch(
            r"(?:file|symlink):[0-9a-f]{64}:[0-7]{3,6}:[0-9]+:[0-9]+",
            value,
        )
        is not None
    )


def phase_observation(evidence: dict[str, str], phase: str) -> dict[str, object]:
    return {
        "operation_return_code": evidence[f"{phase}_OPERATION_RC"],
        "package": {
            "installed": evidence[f"{phase}_PKG_INSTALLED"] == "1",
            "name": evidence[f"{phase}_PKG_NAME"],
            "version": evidence[f"{phase}_PKG_VERSION"],
            "architecture": evidence[f"{phase}_PKG_ARCH"],
            "elf_architectures": {
                "cli": evidence[f"{phase}_ELF_CLI_ARCH"],
                "core": evidence[f"{phase}_ELF_CORE_ARCH"],
                "tui": evidence[f"{phase}_ELF_TUI_ARCH"],
            },
            "inventory": sorted(
                evidence_inventory(evidence[f"{phase}_PKG_INVENTORY"])
            ),
        },
        "user_state": {
            "inventory": sorted(
                evidence_inventory(evidence[f"{phase}_USER_STATE_INVENTORY"])
            ),
            "config_sha256": evidence[f"{phase}_USER_CONFIG_SHA256"],
            "data_sha256": evidence[f"{phase}_USER_DATA_SHA256"],
        },
        "signatures": {
            "rule_definitions": evidence[f"{phase}_SIGNATURE_RULE_COUNT"],
            "engine_loaded": evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"],
            "probe_return_code": evidence[f"{phase}_SIGNATURE_PROBE_RC"],
            "loader_error": evidence[f"{phase}_SIGNATURE_LOAD_ERROR"] == "1",
            "runtime_state_before": evidence[f"{phase}_SIGNATURE_STATE_BEFORE"],
            "runtime_state_after": evidence[f"{phase}_SIGNATURE_STATE_AFTER"],
            "runtime_state_restored": evidence[
                f"{phase}_SIGNATURE_STATE_RESTORED"
            ]
            == "1",
        },
    }


def phase_checks(
    evidence: dict[str, str],
    phase: str,
    expected_version: str,
    check_prefix: str,
) -> list[dict[str, object]]:
    inventory = evidence_inventory(evidence[f"{phase}_PKG_INVENTORY"])
    user_inventory = evidence_inventory(evidence[f"{phase}_USER_STATE_INVENTORY"])
    lifecycle_observed = {
        "return_code": evidence[f"{phase}_OPERATION_RC"],
        "installed": evidence[f"{phase}_PKG_INSTALLED"],
        "name": evidence[f"{phase}_PKG_NAME"],
        "version": evidence[f"{phase}_PKG_VERSION"],
        "architecture": evidence[f"{phase}_PKG_ARCH"],
    }
    elf_observed = {
        "cli": evidence[f"{phase}_ELF_CLI_ARCH"],
        "core": evidence[f"{phase}_ELF_CORE_ARCH"],
        "tui": evidence[f"{phase}_ELF_TUI_ARCH"],
    }
    signature_observed = {
        "rule_definitions": evidence[f"{phase}_SIGNATURE_RULE_COUNT"],
        "engine_loaded": evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"],
        "probe_return_code": evidence[f"{phase}_SIGNATURE_PROBE_RC"],
        "loader_error": evidence[f"{phase}_SIGNATURE_LOAD_ERROR"],
        "runtime_state_before": evidence[f"{phase}_SIGNATURE_STATE_BEFORE"],
        "runtime_state_after": evidence[f"{phase}_SIGNATURE_STATE_AFTER"],
        "runtime_state_restored": evidence[
            f"{phase}_SIGNATURE_STATE_RESTORED"
        ],
    }
    return [
        check(
            f"SW-PKG-FBSD-{check_prefix}-001",
            "lifecycle",
            evidence[f"{phase}_OPERATION_RC"] == "0"
            and evidence[f"{phase}_PKG_INSTALLED"] == "1"
            and evidence[f"{phase}_PKG_NAME"] == "syswarden"
            and evidence[f"{phase}_PKG_VERSION"] == expected_version,
            {
                "return_code": 0,
                "installed": True,
                "name": "syswarden",
                "version": expected_version,
                "architecture": "validated by the separate exact ABI check",
            },
            lifecycle_observed,
            "The native package database must identify the expected package after this lifecycle transition.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-ABI-001",
            "architecture",
            evidence[f"{phase}_PKG_ARCH"] == EXPECTED_FREEBSD_PACKAGE_ABI,
            EXPECTED_FREEBSD_PACKAGE_ABI,
            evidence[f"{phase}_PKG_ARCH"],
            "Every package phase must declare the exact ABI of the FreeBSD 14 amd64 qualification guest.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-ELF-001",
            "architecture",
            set(elf_observed.values()) == {EXPECTED_NATIVE_ELF_ARCH},
            {
                "cli": EXPECTED_NATIVE_ELF_ARCH,
                "core": EXPECTED_NATIVE_ELF_ARCH,
                "tui": EXPECTED_NATIVE_ELF_ARCH,
            },
            elf_observed,
            "The CLI, core, and TUI must each be native amd64 ELF executables at every installed phase.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-INVENTORY-001",
            "lifecycle",
            inventory == EXPECTED_PACKAGE_INVENTORY,
            sorted(EXPECTED_PACKAGE_INVENTORY),
            sorted(inventory),
            "Every installed phase must retain the exact four-file package inventory.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-STATE-001",
            "lifecycle",
            user_inventory == EXPECTED_USER_STATE_INVENTORY
            and evidence[f"{phase}_USER_CONFIG_SHA256"] == USER_CONFIG_SHA256
            and evidence[f"{phase}_USER_DATA_SHA256"] == USER_DATA_SHA256,
            {
                "inventory": sorted(EXPECTED_USER_STATE_INVENTORY),
                "config_sha256": USER_CONFIG_SHA256,
                "data_sha256": USER_DATA_SHA256,
            },
            {
                "inventory": sorted(user_inventory),
                "config_sha256": evidence[f"{phase}_USER_CONFIG_SHA256"],
                "data_sha256": evidence[f"{phase}_USER_DATA_SHA256"],
            },
            "Operator-owned configuration and data must survive every install, upgrade, reinstall, and rollback phase byte-for-byte.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-SIGNATURES-001",
            "signatures",
            evidence[f"{phase}_SIGNATURE_RULE_COUNT"]
            == str(EXPECTED_SIGNATURE_RULE_COUNT)
            and evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"]
            == str(EXPECTED_ENGINE_SIGNATURE_COUNT)
            and evidence[f"{phase}_SIGNATURE_PROBE_RC"] == "124"
            and evidence[f"{phase}_SIGNATURE_LOAD_ERROR"] == "0",
            {
                "rule_definitions": EXPECTED_SIGNATURE_RULE_COUNT,
                "engine_loaded": EXPECTED_ENGINE_SIGNATURE_COUNT,
                "probe_return_code": 124,
                "loader_error": False,
            },
            signature_observed,
            "The packaged database must contain all 78 rule definitions and the real core loader must compile all 194 effective signatures and remain alive for the bounded probe.",
        ),
        check(
            f"SW-PKG-FBSD-{check_prefix}-SIGNATURE-RESTORE-001",
            "signatures",
            valid_signature_state(evidence[f"{phase}_SIGNATURE_STATE_BEFORE"])
            and evidence[f"{phase}_SIGNATURE_STATE_BEFORE"]
            == evidence[f"{phase}_SIGNATURE_STATE_AFTER"]
            and evidence[f"{phase}_SIGNATURE_STATE_RESTORED"] == "1",
            "identical type/bytes/mode/uid/gid, including exact absence",
            {
                "before": evidence[f"{phase}_SIGNATURE_STATE_BEFORE"],
                "after": evidence[f"{phase}_SIGNATURE_STATE_AFTER"],
                "restored": evidence[f"{phase}_SIGNATURE_STATE_RESTORED"],
            },
            "The bounded loader probe must restore the runtime signature path exactly, even when interrupted.",
        ),
    ]


def product_checks(
    evidence: dict[str, str],
    candidate: PackageArtifact,
    previous: PackageArtifact,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for phase, expected_version, check_prefix in (
        ("PREVIOUS_INSTALL", previous.version, "PREVIOUS-INSTALL"),
        ("CANDIDATE_UPGRADE", candidate.version, "CANDIDATE-UPGRADE"),
        ("CANDIDATE_REINSTALL", candidate.version, "CANDIDATE-REINSTALL"),
        (
            "CANDIDATE_RESTART_IDEMPOTENCE",
            candidate.version,
            "CANDIDATE-RESTART-IDEMPOTENCE",
        ),
        ("PREVIOUS_ROLLBACK", previous.version, "PREVIOUS-ROLLBACK"),
    ):
        checks.extend(phase_checks(evidence, phase, expected_version, check_prefix))

    pf_rule_count = (
        int(evidence["PF_FIXTURE_RULE_COUNT"])
        if evidence["PF_FIXTURE_RULE_COUNT"].isdigit()
        else 0
    )
    restart_baseline_inventory = metadata_inventory(
        evidence["RESTART_BASELINE_INVENTORY"]
    )
    restart_one_inventory = metadata_inventory(evidence["RESTART_ONE_INVENTORY"])
    restart_two_inventory = metadata_inventory(evidence["RESTART_TWO_INVENTORY"])
    restart_inventory_observed = {
        "baseline": (
            sorted(restart_baseline_inventory)
            if restart_baseline_inventory is not None
            else None
        ),
        "after_first_restart": (
            sorted(restart_one_inventory)
            if restart_one_inventory is not None
            else None
        ),
        "after_second_restart": (
            sorted(restart_two_inventory)
            if restart_two_inventory is not None
            else None
        ),
    }
    remove_user_inventory = evidence_inventory(evidence["REMOVE_USER_STATE_INVENTORY"])
    checks.extend(
        [
            check("SW-PKG-FBSD-MODE-CLI-001", "package", evidence["MODE_CLI"] == "750", "750", evidence["MODE_CLI"], "The CLI must retain the staged executable mode."),
            check("SW-PKG-FBSD-MODE-CORE-001", "package", evidence["MODE_CORE"] == "750", "750", evidence["MODE_CORE"], "The core must retain the staged executable mode."),
            check("SW-PKG-FBSD-MODE-TUI-001", "package", evidence["MODE_TUI"] == "750", "750", evidence["MODE_TUI"], "The TUI must retain the staged executable mode."),
            check("SW-PKG-FBSD-MODE-SIG-001", "package", evidence["MODE_SIGNATURES"] == "640", "640", evidence["MODE_SIGNATURES"], "The signature database must not be world-readable."),
            check("SW-PKG-FBSD-LINK-CLI-001", "package", evidence["LINK_CLI"] == "/usr/local/syswarden/bin/syswarden-cli", "/usr/local/syswarden/bin/syswarden-cli", evidence["LINK_CLI"], "The public CLI symlink must target the packaged binary."),
            check("SW-PKG-FBSD-LINK-TUI-001", "package", evidence["LINK_TUI"] == "/usr/local/syswarden/bin/syswarden-tui", "/usr/local/syswarden/bin/syswarden-tui", evidence["LINK_TUI"], "The public TUI symlink must target the packaged binary."),
            check("SW-PKG-FBSD-EXEC-DIRECT-001", "runtime", evidence["CLI_DIRECT_RC"] == "0", 0, evidence["CLI_DIRECT_RC"], "The candidate CLI must execute natively after reinstall."),
            check("SW-PKG-FBSD-EXEC-LINK-001", "runtime", evidence["CLI_LINK_RC"] == "0", 0, evidence["CLI_LINK_RC"], "The candidate public entry point must execute natively after reinstall."),
            check("SW-PKG-FBSD-SIG-PACKAGED-001", "runtime", evidence["SIGNATURE_PACKAGE_PATH"] == "1", True, evidence["SIGNATURE_PACKAGE_PATH"] == "1", "The candidate package must install its signature database."),
            check("SW-PKG-FBSD-PREFIX-001", "runtime", evidence["SIGNATURE_RUNTIME_PATH"] == "1", "/opt/syswarden/signatures.json exists without laboratory assistance", evidence["SIGNATURE_RUNTIME_PATH"] == "1", "The compatibility-copy signature probe does not excuse the package/runtime prefix mismatch; this check is captured before the temporary probe path is created."),
            check("SW-PKG-FBSD-RCD-CORE-001", "rc.d", evidence["RC_CORE_PRESENT"] == "1" and evidence["RC_CORE_MODE"] == "755", "core rc.d script exists with mode 755", {"present": evidence["RC_CORE_PRESENT"], "mode": evidence["RC_CORE_MODE"]}, "Candidate reinstallation must create a runnable core service script."),
            check("SW-PKG-FBSD-RCD-WEB-001", "rc.d", evidence["RC_WEB_PRESENT"] == "1" and evidence["RC_WEB_MODE"] == "755", "web rc.d script exists with mode 755", {"present": evidence["RC_WEB_PRESENT"], "mode": evidence["RC_WEB_MODE"]}, "Candidate reinstallation must create a runnable Web-TUI service script."),
            check("SW-PKG-FBSD-RCD-CORE-PATH-001", "rc.d", evidence["RC_CORE_COMMAND"] == "/usr/local/syswarden/bin/syswarden-core", "/usr/local/syswarden/bin/syswarden-core", evidence["RC_CORE_COMMAND"], "The core service command must reference the packaged path."),
            check("SW-PKG-FBSD-RCD-WEB-PATH-001", "rc.d", evidence["RC_WEB_COMMAND"] == "/usr/local/syswarden/bin/syswarden-cli", "/usr/local/syswarden/bin/syswarden-cli", evidence["RC_WEB_COMMAND"], "The Web-TUI service command must reference the packaged path."),
            check("SW-PKG-FBSD-RCD-ENABLE-001", "rc.d", evidence["RC_CORE_ENABLED"] == "YES" and evidence["RC_WEB_ENABLED"] == "YES", "both services enabled", {"core": evidence["RC_CORE_ENABLED"], "web": evidence["RC_WEB_ENABLED"]}, "Both generated rc.d services must be enabled."),
            check("SW-PKG-FBSD-START-CORE-001", "startup", evidence["RC_CORE_START_RC"] == "0" and evidence["RC_CORE_STATUS_RC"] == "0", "core starts and reports running", {"start": evidence["RC_CORE_START_RC"], "status": evidence["RC_CORE_STATUS_RC"]}, "The candidate core must start through rc.d."),
            check("SW-PKG-FBSD-RESTART-CORE-001", "startup", all(evidence[key] == "0" for key in ("RC_CORE_RESTART_ONE_RC", "RC_CORE_RESTART_ONE_STATUS_RC", "RC_CORE_RESTART_TWO_RC", "RC_CORE_RESTART_TWO_STATUS_RC")), "two consecutive core restarts succeed and report running", {key: evidence[key] for key in ("RC_CORE_RESTART_ONE_RC", "RC_CORE_RESTART_ONE_STATUS_RC", "RC_CORE_RESTART_TWO_RC", "RC_CORE_RESTART_TWO_STATUS_RC")}, "A second consecutive restart is the bounded rc.d idempotence check."),
            check("SW-PKG-FBSD-START-WEB-001", "startup", evidence["RC_WEB_START_RC"] == "0" and evidence["RC_WEB_STATUS_RC"] == "0", "Web-TUI starts and reports running", {"start": evidence["RC_WEB_START_RC"], "status": evidence["RC_WEB_STATUS_RC"]}, "The candidate Web-TUI must start through rc.d."),
            check("SW-PKG-FBSD-RESTART-WEB-001", "startup", all(evidence[key] == "0" for key in ("RC_WEB_RESTART_ONE_RC", "RC_WEB_RESTART_ONE_STATUS_RC", "RC_WEB_RESTART_TWO_RC", "RC_WEB_RESTART_TWO_STATUS_RC")), "two consecutive Web-TUI restarts succeed and report running", {key: evidence[key] for key in ("RC_WEB_RESTART_ONE_RC", "RC_WEB_RESTART_ONE_STATUS_RC", "RC_WEB_RESTART_TWO_RC", "RC_WEB_RESTART_TWO_STATUS_RC")}, "A second consecutive restart is the bounded rc.d idempotence check."),
            check(
                "SW-PKG-FBSD-RESTART-METADATA-001",
                "startup",
                restart_baseline_inventory is not None
                and restart_baseline_inventory == restart_one_inventory
                and restart_baseline_inventory == restart_two_inventory,
                "identical complete scoped path/type/mode/uid/gid/link inventory after both restarts",
                restart_inventory_observed,
                "Both consecutive restart cycles must preserve the complete scoped filesystem inventory and metadata.",
            ),
            check("SW-PF-FBSD-FIXTURE-SYNTAX-001", "pf", evidence["PF_FIXTURE_SYNTAX_RC"] == "0", 0, evidence["PF_FIXTURE_SYNTAX_RC"], "The frozen FreeBSD PF policy must pass the native kernel parser."),
            check("SW-PF-FBSD-FIXTURE-APPLY-001", "pf", evidence["PF_FIXTURE_APPLY_RC"] == "0" and pf_rule_count > 0, "isolated anchor contains rules", {"return_code": evidence["PF_FIXTURE_APPLY_RC"], "rules": evidence["PF_FIXTURE_RULE_COUNT"]}, "The policy is loaded only into a unique, unattached VM anchor."),
            check("SW-PF-FBSD-HONEYPORT-001", "pf", evidence["PF_HONEYPORT_SOURCE_BAD"] == "0" and evidence["PF_HONEYPORT_EXACT_VALUE"] == "23, 6379" and evidence["PF_HONEYPORT_SYNTAX_RC"] == "0", "the exact { 23, 6379 } rule passes the native PF parser", {"source_concatenates_ports": evidence["PF_HONEYPORT_SOURCE_BAD"] == "1", "exact_port_value": evidence["PF_HONEYPORT_EXACT_VALUE"], "native_syntax_return_code": evidence["PF_HONEYPORT_SYNTAX_RC"]}, "The corrected source must keep both configured honeyports distinct and prove the exact rule with pfctl -n."),
            check("SW-PKG-FBSD-REMOVE-001", "cleanup", evidence["REMOVE_RC"] == "0" and evidence["REMOVE_PACKAGE_ABSENT"] == "1" and evidence["REMOVE_PKG_INVENTORY"] == "" and evidence["REMOVE_PAYLOAD_ABSENT"] == "1" and evidence["REMOVE_LINKS_ABSENT"] == "1", "pkg delete removes registration, inventory, payload and public links", {"return_code": evidence["REMOVE_RC"], "package_absent": evidence["REMOVE_PACKAGE_ABSENT"], "inventory": sorted(evidence_inventory(evidence["REMOVE_PKG_INVENTORY"])), "payload_absent": evidence["REMOVE_PAYLOAD_ABSENT"], "links_absent": evidence["REMOVE_LINKS_ABSENT"]}, "FreeBSD exposes native removal through pkg delete and has no separate purge operation."),
            check("SW-PKG-FBSD-REMOVE-STATE-001", "cleanup", remove_user_inventory == EXPECTED_USER_STATE_INVENTORY and evidence["REMOVE_USER_CONFIG_SHA256"] == USER_CONFIG_SHA256 and evidence["REMOVE_USER_DATA_SHA256"] == USER_DATA_SHA256, {"semantics": "pkg delete preserves unowned operator state; no separate purge", "inventory": sorted(EXPECTED_USER_STATE_INVENTORY), "config_sha256": USER_CONFIG_SHA256, "data_sha256": USER_DATA_SHA256}, {"inventory": sorted(remove_user_inventory), "config_sha256": evidence["REMOVE_USER_CONFIG_SHA256"], "data_sha256": evidence["REMOVE_USER_DATA_SHA256"]}, "Native FreeBSD removal must preserve unowned operator configuration and data byte-for-byte; laboratory cleanup happens only after this evidence is emitted."),
            check("SW-PKG-FBSD-RCD-CLEANUP-001", "cleanup", all(evidence[key] == "1" for key in ("REMOVE_RC_CORE_ABSENT", "REMOVE_RC_WEB_ABSENT", "REMOVE_CORE_FLAG_ABSENT", "REMOVE_WEB_FLAG_ABSENT")), "rc.d scripts and enable flags removed", {key: evidence[key] for key in ("REMOVE_RC_CORE_ABSENT", "REMOVE_RC_WEB_ABSENT", "REMOVE_CORE_FLAG_ABSENT", "REMOVE_WEB_FLAG_ABSENT")}, "Package removal must not leave startup artifacts behind."),
        ]
    )
    return checks


def harness_conditions(evidence: dict[str, str]) -> dict[str, bool]:
    return {
        "root inside guest": evidence["ROOT_UID"] == "0",
        "disposable VM marker revalidated": evidence["MARKER_MATCH"] == "1",
        "root-owned VM marker revalidated": evidence["MARKER_SAFE"] == "1",
        "FreeBSD 14.4 amd64 revalidated": evidence["OS_NAME"] == "FreeBSD" and evidence["OS_RELEASE"].startswith("14.4-RELEASE") and evidence["MACHINE"] == "amd64",
        "native tools available": all(evidence[key] == "1" for key in ("PKG_TOOL_READY", "PF_TOOL_READY", "TIMEOUT_TOOL_READY", "FILE_TOOL_READY")),
        "clean disposable snapshot": evidence["PRECLEAN"] == "1" and evidence["PF_BASELINE_READY"] == "1" and evidence["PF_BASELINE_CLEAN"] == "1" and evidence["PF_BASELINE_STATUS"] == "Disabled",
        "verified previous package transfer": bool(
            re.fullmatch(r"[0-9a-f]{64}", evidence["PREVIOUS_PACKAGE_SHA256"])
        ),
        "verified candidate package transfer": bool(
            re.fullmatch(r"[0-9a-f]{64}", evidence["CANDIDATE_PACKAGE_SHA256"])
        ),
        "verified PF fixture transfer": evidence["PF_FIXTURE_SHA_MATCH"] == "1"
        and bool(re.fullmatch(r"[0-9a-f]{64}", evidence["PF_FIXTURE_SHA256"])),
        "exclusive guest lock": evidence["LAB_LOCK_ACQUIRED"] == "1"
        and evidence["LAB_LOCK_RELEASED"] == "1",
        "unique validated PF anchor": ANCHOR_NAME_PATTERN.fullmatch(
            evidence["PF_ANCHOR_NAME"]
        )
        is not None,
        "PF anchor removed": evidence["PF_ANCHOR_CLEAN"] == "1",
        "lab filesystem cleanup": evidence["LAB_CLEANUP_OK"] == "1",
        "PF snapshot restored": evidence["PF_BASELINE_RESTORED"] == "1"
        and evidence["PF_FINAL_STATUS"] == "Disabled",
    }


def classify_failed_checks(
    checks: Sequence[dict[str, object]],
    evidence: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Separate approved roadmap blockers from every unexpected failure."""

    guest_is_expected = (
        evidence["OS_NAME"] == "FreeBSD"
        and evidence["OS_RELEASE"].startswith("14.4-RELEASE")
        and evidence["MACHINE"] == "amd64"
    )
    exact_prefix_mismatch = (
        evidence["SIGNATURE_PACKAGE_PATH"] == "1"
        and evidence["SIGNATURE_RUNTIME_PATH"] == "0"
    )
    exact_missing_rcd = all(
        (
            evidence["RC_CORE_PRESENT"] == "0",
            evidence["RC_WEB_PRESENT"] == "0",
            evidence["RC_CORE_MODE"] == "",
            evidence["RC_WEB_MODE"] == "",
            evidence["RC_CORE_COMMAND"] == "",
            evidence["RC_WEB_COMMAND"] == "",
            evidence["RC_CORE_ENABLED"] == "",
            evidence["RC_WEB_ENABLED"] == "",
            all(
                evidence[key] == "1"
                for key in (
                    "RC_CORE_START_RC",
                    "RC_CORE_STATUS_RC",
                    "RC_CORE_RESTART_ONE_RC",
                    "RC_CORE_RESTART_ONE_STATUS_RC",
                    "RC_CORE_RESTART_TWO_RC",
                    "RC_CORE_RESTART_TWO_STATUS_RC",
                    "RC_WEB_START_RC",
                    "RC_WEB_STATUS_RC",
                    "RC_WEB_RESTART_ONE_RC",
                    "RC_WEB_RESTART_ONE_STATUS_RC",
                    "RC_WEB_RESTART_TWO_RC",
                    "RC_WEB_RESTART_TWO_STATUS_RC",
                )
            ),
            evidence["CANDIDATE_RESTART_IDEMPOTENCE_OPERATION_RC"] == "1",
        )
    )
    exact_legacy_rcd_prefix = (
        evidence["RC_CORE_COMMAND"] == KNOWN_FREEBSD_CORE_COMMAND
        and evidence["RC_WEB_COMMAND"] == KNOWN_FREEBSD_WEB_COMMAND
    )
    rcd_absence_ids = {
        "SW-PKG-FBSD-CANDIDATE-RESTART-IDEMPOTENCE-001",
        "SW-PKG-FBSD-RCD-CORE-001",
        "SW-PKG-FBSD-RCD-WEB-001",
        "SW-PKG-FBSD-RCD-ENABLE-001",
    }
    rcd_path_ids = {
        "SW-PKG-FBSD-RCD-CORE-PATH-001",
        "SW-PKG-FBSD-RCD-WEB-PATH-001",
    }
    rcd_runtime_ids = {
        "SW-PKG-FBSD-START-CORE-001",
        "SW-PKG-FBSD-RESTART-CORE-001",
        "SW-PKG-FBSD-START-WEB-001",
        "SW-PKG-FBSD-RESTART-WEB-001",
    }

    def exact_expected_blocker(check_id: str) -> str | None:
        mapped = EXPECTED_FAILED_CHECK_BLOCKERS.get(check_id)
        if mapped is None or not guest_is_expected:
            return None
        if check_id in ABI_CHECK_PHASES:
            phase = ABI_CHECK_PHASES[check_id]
            if (
                evidence[f"{phase}_PKG_ARCH"]
                == KNOWN_LEGACY_FREEBSD_PACKAGE_ABI
            ):
                return mapped
            return None
        if check_id in PREVIOUS_MIXED_ELF_CHECK_PHASES:
            phase = PREVIOUS_MIXED_ELF_CHECK_PHASES[check_id]
            exact_mixed_elf = (
                evidence[f"{phase}_ELF_CLI_ARCH"] == "amd64"
                and evidence[f"{phase}_ELF_CORE_ARCH"] == "arm64"
                and evidence[f"{phase}_ELF_TUI_ARCH"] == "arm64"
            )
            if not exact_mixed_elf:
                return None
            if check_id.endswith("-SIGNATURES-001"):
                exact_exec_format_consequence = (
                    evidence[f"{phase}_SIGNATURE_RULE_COUNT"]
                    == str(EXPECTED_SIGNATURE_RULE_COUNT)
                    and evidence[f"{phase}_SIGNATURE_ENGINE_COUNT"] == ""
                    and evidence[f"{phase}_SIGNATURE_PROBE_RC"] == "2"
                    and evidence[f"{phase}_SIGNATURE_LOAD_ERROR"] == "0"
                    and evidence[f"{phase}_SIGNATURE_STATE_RESTORED"] == "1"
                    and valid_signature_state(
                        evidence[f"{phase}_SIGNATURE_STATE_BEFORE"]
                    )
                    and evidence[f"{phase}_SIGNATURE_STATE_BEFORE"]
                    == evidence[f"{phase}_SIGNATURE_STATE_AFTER"]
                )
                return mapped if exact_exec_format_consequence else None
            return mapped
        if check_id == "SW-PKG-FBSD-PREFIX-001":
            return mapped if exact_prefix_mismatch else None
        if check_id in rcd_absence_ids:
            return mapped if exact_missing_rcd else None
        if check_id in rcd_path_ids:
            if exact_missing_rcd or exact_legacy_rcd_prefix:
                return mapped
            return None
        if check_id in rcd_runtime_ids:
            if exact_missing_rcd:
                return mapped
            if exact_legacy_rcd_prefix:
                relevant_values = (
                    evidence[key]
                    for key in (
                        "RC_CORE_START_RC",
                        "RC_CORE_STATUS_RC",
                        "RC_CORE_RESTART_ONE_RC",
                        "RC_CORE_RESTART_ONE_STATUS_RC",
                        "RC_CORE_RESTART_TWO_RC",
                        "RC_CORE_RESTART_TWO_STATUS_RC",
                        "RC_WEB_START_RC",
                        "RC_WEB_STATUS_RC",
                        "RC_WEB_RESTART_ONE_RC",
                        "RC_WEB_RESTART_ONE_STATUS_RC",
                        "RC_WEB_RESTART_TWO_RC",
                        "RC_WEB_RESTART_TWO_STATUS_RC",
                    )
                )
                return mapped if all(value == "1" for value in relevant_values) else None
            return None
        return None

    failed_check_ids = [
        str(item["id"]) for item in checks if item.get("status") != "pass"
    ]
    classified = {
        check_id: exact_expected_blocker(check_id) for check_id in failed_check_ids
    }
    blocker_ids = sorted({value for value in classified.values() if value})
    if not set(blocker_ids).issubset(CANONICAL_BLOCKER_IDS):
        raise FreeBSDVMLabError("non-canonical expected blocker classification")
    unexpected_failed_check_ids = sorted(
        check_id
        for check_id in failed_check_ids
        if classified[check_id] is None
    )
    return blocker_ids, unexpected_failed_check_ids


def build_report(
    evidence: dict[str, str],
    candidate: PackageArtifact,
    previous: PackageArtifact,
    assets: ProductAssets,
    host: str,
    port: int,
    expected_anchor_name: str | None = None,
) -> dict[str, object]:
    conditions = harness_conditions(evidence)
    if evidence["PREVIOUS_PACKAGE_SHA256"] != previous.sha256:
        conditions["verified previous package transfer"] = False
    if evidence["CANDIDATE_PACKAGE_SHA256"] != candidate.sha256:
        conditions["verified candidate package transfer"] = False
    if evidence["PF_FIXTURE_SHA256"] != assets.pf_fixture_sha256:
        conditions["verified PF fixture transfer"] = False
    if (
        expected_anchor_name is not None
        and evidence["PF_ANCHOR_NAME"] != expected_anchor_name
    ):
        conditions["unique validated PF anchor"] = False
    harness_status = "pass" if all(conditions.values()) else "fail"
    checks = product_checks(evidence, candidate, previous)
    blocker_ids, unexpected_failed_check_ids = classify_failed_checks(checks, evidence)
    failed = any(item["status"] != "pass" for item in checks)
    if not checks or unexpected_failed_check_ids:
        product_status = "fail"
    elif failed:
        product_status = "known_blocker"
    else:
        product_status = "pass"
    release_ready = harness_status == "pass" and product_status == "pass"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": harness_status,
        "product_status": product_status,
        "release_ready": release_ready,
        "blocker_ids": blocker_ids,
        "unexpected_failed_check_ids": unexpected_failed_check_ids,
        "scope": {
            "guest": "explicitly marked disposable FreeBSD VM",
            "ssh_endpoint": f"{host}:{port}",
            "ssh_scope": "local loopback only",
            "host_firewall_mutation": False,
            "pf_scope": "unique unattached anchor plus disposable-VM package behavior",
            "guest_lock": "atomic root-owned /var/run lock held through PF restoration",
            "pf_snapshot": "empty guest ruleset and exact Disabled status captured before mutation and restored after cleanup",
            "lifecycle": "previous install -> candidate upgrade -> candidate reinstall -> previous rollback -> pkg delete",
            "remove_purge_semantics": "FreeBSD pkg has no separate purge operation; pkg delete must remove package-owned artifacts and preserve unowned operator state",
            "signature_probe": "each installed phase temporarily presents the packaged database at the core's hard-coded runtime path, requires exactly 78 rule definitions and a real loader report of 194 effective signatures, then trap-restores and verifies exact type/bytes/mode/uid/gid or absence",
            "restart_inventory": "complete scoped path/type/mode/uid/gid/link inventory must remain identical after both restart cycles",
            "vm_disposition": "discard or externally revert the disposable VM snapshot after the lab; the installer intentionally mutates guest state beyond package and PF paths",
        },
        "environment": {
            "os": evidence["OS_NAME"],
            "release": evidence["OS_RELEASE"],
            "machine": evidence["MACHINE"],
            "pf_interface": evidence["PF_INTERFACE"],
            "pf_initial_status": evidence["PF_BASELINE_STATUS"],
            "pf_final_status": evidence["PF_FINAL_STATUS"],
            "pf_snapshot_sha256": evidence["PF_SNAPSHOT_SHA256"],
            "pf_anchor": evidence["PF_ANCHOR_NAME"],
        },
        "inputs": {
            "candidate": {
                "package": candidate.path.name,
                "version": candidate.version,
                "sha256": candidate.sha256,
            },
            "previous": {
                "package": previous.path.name,
                "version": previous.version,
                "sha256": previous.sha256,
            },
            "pf_fixture": str(assets.pf_fixture.relative_to(assets.repository)),
            "pf_fixture_sha256": assets.pf_fixture_sha256,
            "pf_fixture_guest_sha256": evidence["PF_FIXTURE_SHA256"],
        },
        "restart_metadata_inventories": {
            "baseline": sorted(
                metadata_inventory(evidence["RESTART_BASELINE_INVENTORY"]) or ()
            ),
            "after_first_restart": sorted(
                metadata_inventory(evidence["RESTART_ONE_INVENTORY"]) or ()
            ),
            "after_second_restart": sorted(
                metadata_inventory(evidence["RESTART_TWO_INVENTORY"]) or ()
            ),
        },
        "lifecycle_phases": {
            "previous_install": phase_observation(evidence, "PREVIOUS_INSTALL"),
            "candidate_upgrade": phase_observation(evidence, "CANDIDATE_UPGRADE"),
            "candidate_reinstall": phase_observation(evidence, "CANDIDATE_REINSTALL"),
            "candidate_restart_idempotence": phase_observation(
                evidence, "CANDIDATE_RESTART_IDEMPOTENCE"
            ),
            "previous_rollback": phase_observation(evidence, "PREVIOUS_ROLLBACK"),
            "remove": {
                "operation_return_code": evidence["REMOVE_RC"],
                "package_absent": evidence["REMOVE_PACKAGE_ABSENT"] == "1",
                "package_inventory": sorted(
                    evidence_inventory(evidence["REMOVE_PKG_INVENTORY"])
                ),
                "user_state": {
                    "inventory": sorted(
                        evidence_inventory(evidence["REMOVE_USER_STATE_INVENTORY"])
                    ),
                    "config_sha256": evidence["REMOVE_USER_CONFIG_SHA256"],
                    "data_sha256": evidence["REMOVE_USER_DATA_SHA256"],
                },
                "semantics": "pkg delete; no separate FreeBSD purge operation",
            },
        },
        "harness_conditions": conditions,
        "checks": checks,
    }


def run_lab(
    args: argparse.Namespace, *, runner: CommandRunner | None = None
) -> dict[str, object]:
    ssh_program = validate_transport_program(args.ssh, "ssh")
    scp_program = validate_transport_program(args.scp, "scp")
    marker_token = resolve_marker_token(args)
    host, identity, known_hosts = validate_transport_inputs(
        args.ssh_host,
        args.ssh_port,
        args.ssh_user,
        args.identity_file,
        args.known_hosts_file,
        marker_token,
    )
    if args.command_timeout < 60 or args.command_timeout > 1800:
        raise FreeBSDVMLabError("command timeout must be between 60 and 1800 seconds")
    candidate, previous = discover_package_pair(
        args.packages_dir, args.previous_packages_dir
    )
    assets = inspect_product_assets(args.repo_root)
    active_runner = runner or CommandRunner()
    ssh_base = ssh_arguments(
        ssh_program, host, args.ssh_port, args.ssh_user, identity, known_hosts
    )

    probe = active_runner.run(
        ssh_base + ("/bin/sh", "-s", "--"),
        timeout=45,
        input_text=script_stdin_with_token(PROBE_SCRIPT, marker_token),
    )
    require_transport_success(probe, "FreeBSD VM prerequisite probe")
    validate_probe(parse_markers(probe.stdout, PROBE_KEYS))

    remote_root = f"/tmp/syswarden-freebsd-lot0-{uuid.uuid4().hex}"
    anchor_nonce = uuid.uuid4().hex
    expected_anchor_name = f"syswarden_lot0_{anchor_nonce}"
    prepared = active_runner.run(
        ssh_base + ("/bin/sh", "-s", "--", remote_root),
        timeout=30,
        input_text=PREPARE_SCRIPT,
    )
    require_transport_success(prepared, "prepare disposable VM workspace")

    for source, name in (
        (previous.path, previous.path.name),
        (candidate.path, candidate.path.name),
        (assets.pf_fixture, assets.pf_fixture.name),
    ):
        copied = active_runner.run(
            scp_arguments(
                scp_program,
                host,
                args.ssh_port,
                args.ssh_user,
                identity,
                known_hosts,
                source,
                f"{remote_root}/{name}",
            ),
            timeout=120,
        )
        require_transport_success(copied, f"copy {name} into disposable VM")

    remote = active_runner.run(
        ssh_base
        + (
            "sudo",
            "-n",
            "/bin/sh",
            "-s",
            "--",
            remote_root,
            previous.path.name,
            previous.sha256,
            previous.version,
            candidate.path.name,
            candidate.sha256,
            candidate.version,
            "1" if assets.honeyport_source_bad else "0",
            assets.pf_fixture_sha256,
            anchor_nonce,
            str(args.command_timeout),
        ),
        timeout=(args.command_timeout * 4) + 360,
        input_text=script_stdin_with_token(REMOTE_LAB_SCRIPT, marker_token),
    )
    require_transport_success(remote, "FreeBSD package/PF laboratory")
    evidence = parse_markers(remote.stdout, EVIDENCE_KEYS)
    return build_report(
        evidence,
        candidate,
        previous,
        assets,
        host,
        args.ssh_port,
        expected_anchor_name,
    )


def write_report(path: Path, report: dict[str, object], pretty: bool) -> None:
    destination = path.expanduser().absolute()
    parent = require_real_directory(destination.parent, "report parent directory")
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FreeBSDVMLabError(
            f"cannot inspect report destination {destination}: {exc}"
        ) from exc
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise FreeBSDVMLabError(
                f"report destination must be absent or a regular file: {destination}"
            )
    serialized = json.dumps(
        report, indent=2 if pretty else None, sort_keys=True
    ) + "\n"
    temporary = parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    try:
        temporary.write_text(serialized, encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def error_report(exc: Exception) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "fail",
        "product_status": "not_evaluated",
        "release_ready": False,
        "blocker_ids": [],
        "unexpected_failed_check_ids": [],
        "error": str(exc),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--packages-dir",
        type=Path,
        required=True,
        help="directory containing the checksummed candidate FreeBSD package",
    )
    parser.add_argument(
        "--previous-packages-dir",
        type=Path,
        required=True,
        help="distinct directory containing the checksummed previous FreeBSD package",
    )
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--known-hosts-file", type=Path, required=True)
    parser.add_argument(
        "--vm-marker-token-file",
        type=Path,
        required=True,
        help="0600 file containing the disposable-VM marker token (preferred)",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--scp", default="scp")
    parser.add_argument("--command-timeout", type=int, default=600)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = run_lab(args)
    except (FreeBSDVMLabError, OSError, ValueError) as exc:
        report = error_report(exc)
        try:
            write_report(args.output, report, args.pretty)
        except (FreeBSDVMLabError, OSError):
            print(json.dumps(report, sort_keys=True), file=sys.stderr)
        return 2
    write_report(args.output, report, args.pretty)
    if report["harness_status"] != "pass":
        return 2
    return 0 if report["release_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
