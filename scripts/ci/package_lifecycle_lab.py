#!/usr/bin/env python3
"""Run fail-closed SysWarden package lifecycle tests in rootless Podman.

The lab prepares disposable Debian, Ubuntu, Fedora, AlmaLinux, and Alpine images
from immutable official-image references for amd64 and arm64. Package operations
then run without network access. Package directories are mounted read-only. No
host service, firewall, device, container-engine socket, or non-lab writable path
is exposed to a test container.
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
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = 3
LOG_TAIL_LIMIT = 12_000
MAX_VERSION_COMPONENT = 2_147_483_647
VERSION_SCHEME = "canonical_syswarden_numeric_v1"
VERSION_RELATION = "previous < candidate"
ARM64_BINFMT_REGISTRATION = Path("/proc/sys/fs/binfmt_misc/qemu-aarch64")
IMAGE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$"
)
SYSWARDEN_VERSION_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.([0-9]{2})\.(0|[1-9][0-9]*)$"
)
ARTIFACT_VERSION_PATTERNS = (
    re.compile(
        r"^syswarden_(?P<version>[0-9][0-9.]*)_(?:amd64|arm64)\.deb$"
    ),
    re.compile(
        r"^syswarden-(?P<version>[0-9][0-9.]*)-1\.(?:x86_64|aarch64)\.rpm$"
    ),
    re.compile(
        r"^syswarden_(?P<version>[0-9][0-9.]*)_(?:x86_64|aarch64)\.apk$"
    ),
)


class LifecycleLabError(RuntimeError):
    """Raised when the lifecycle lab cannot produce trustworthy evidence."""


@dataclass(frozen=True)
class PlatformSpec:
    name: str
    distribution: str
    family: str
    architecture: str
    package_architecture: str
    podman_platform: str
    uname_architecture: str
    official_repository: str
    image: str
    package_pattern: str
    bootstrap_command: str
    scenarios: tuple[str, ...]
    purge_semantics: str


ARCHITECTURE_LABELS = {
    "amd64": "amd64/x86_64",
    "arm64": "arm64/aarch64",
}

EXPECTED_PACKAGE_ARCHITECTURES = {
    ("deb", "amd64"): "amd64",
    ("deb", "arm64"): "arm64",
    ("rpm", "amd64"): "x86_64",
    ("rpm", "arm64"): "aarch64",
    ("apk", "amd64"): "x86_64",
    ("apk", "arm64"): "aarch64",
}

EXPECTED_PACKAGE_PATTERNS = {
    ("deb", "amd64"): r"^syswarden_[0-9][0-9.]*_amd64\.deb$",
    ("deb", "arm64"): r"^syswarden_[0-9][0-9.]*_arm64\.deb$",
    ("rpm", "amd64"): r"^syswarden-[0-9][0-9.]*-1\.x86_64\.rpm$",
    ("rpm", "arm64"): r"^syswarden-[0-9][0-9.]*-1\.aarch64\.rpm$",
    ("apk", "amd64"): r"^syswarden_[0-9][0-9.]*_x86_64\.apk$",
    ("apk", "arm64"): r"^syswarden_[0-9][0-9.]*_aarch64\.apk$",
}

EXPECTED_SCENARIOS = {
    "deb": ("upgrade-rollback", "remove", "purge"),
    "rpm": ("upgrade-rollback", "remove"),
    "apk": ("upgrade-rollback", "remove", "purge"),
}

OFFICIAL_REPOSITORIES = {
    "debian": "docker.io/library/debian",
    "ubuntu": "docker.io/library/ubuntu",
    "fedora": "docker.io/library/fedora",
    "almalinux": "docker.io/library/almalinux",
    "alpine": "docker.io/library/alpine",
}

DEB_BOOTSTRAP = (
    "apt-get update && "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y "
    "--no-install-recommends nftables ipset curl wget rsyslog cron "
    "bash-completion wireguard-tools qrencode jq unattended-upgrades "
    "apt-listchanges procps e2fsprogs socat binutils file && "
    "if [ -f /etc/dpkg/dpkg.cfg.d/docker ]; then "
    "sed -i '\\|^path-exclude /usr/share/doc/\\*$|d' "
    "/etc/dpkg/dpkg.cfg.d/docker; fi && "
    "rm -rf /var/lib/apt/lists/*"
)
RPM_BOOTSTRAP = (
    "if grep -Eq '^ID=\"?almalinux\"?$' /etc/os-release; then "
    "dnf -y install epel-release; fi && "
    "dnf -y install nftables ipset curl-minimal wget rsyslog cronie "
    "bash-completion wireguard-tools qrencode jq checkpolicy "
    "policycoreutils-python-utils dnf-automatic procps-ng e2fsprogs socat binutils "
    "cpio diffutils file && dnf clean all"
)
APK_BOOTSTRAP = (
    "apk add --no-cache nftables openrc curl wget rsyslog rsyslog-uxsock "
    "bash-completion wireguard-tools libqrencode-tools jq procps-ng "
    "e2fsprogs-extra socat binutils file"
)
DEB_PURGE_SEMANTICS = (
    "remove preserves generated /etc and /var state; purge removes generated "
    "/etc state while the current package leaves /var data"
)
RPM_PURGE_SEMANTICS = (
    "RPM has no distinct purge operation; erase runs the package's destructive "
    "final-removal script"
)
APK_PURGE_SEMANTICS = (
    "apk --purge only purges package-managed configuration; the current package "
    "does not own generated /etc or /var state"
)


DEFAULT_PLATFORMS = (
    PlatformSpec(
        name="Debian",
        distribution="debian",
        family="deb",
        architecture="amd64",
        package_architecture="amd64",
        podman_platform="linux/amd64",
        uname_architecture="x86_64",
        official_repository=OFFICIAL_REPOSITORIES["debian"],
        image=(
            "docker.io/library/debian:stable-slim@sha256:"
            "0ef0f77425e6677ead26f893cb61707f7fc44467a480625d8974feb7ab2085fe"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_amd64\.deb$",
        bootstrap_command=DEB_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=DEB_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Debian",
        distribution="debian",
        family="deb",
        architecture="arm64",
        package_architecture="arm64",
        podman_platform="linux/arm64",
        uname_architecture="aarch64",
        official_repository=OFFICIAL_REPOSITORIES["debian"],
        image=(
            "docker.io/library/debian:stable-slim@sha256:"
            "9d047d46b340f5f97430c9a8ea63de328bf6223fb5dacdd5d24be2eadf54a0cf"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_arm64\.deb$",
        bootstrap_command=DEB_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=DEB_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Ubuntu",
        distribution="ubuntu",
        family="deb",
        architecture="amd64",
        package_architecture="amd64",
        podman_platform="linux/amd64",
        uname_architecture="x86_64",
        official_repository=OFFICIAL_REPOSITORIES["ubuntu"],
        image=(
            "docker.io/library/ubuntu:24.04@sha256:"
            "019e8eb29a85e74d64925745884f2ec79aa27e3feab36353d24656f4d6b89467"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_amd64\.deb$",
        bootstrap_command=DEB_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=DEB_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Ubuntu",
        distribution="ubuntu",
        family="deb",
        architecture="arm64",
        package_architecture="arm64",
        podman_platform="linux/arm64",
        uname_architecture="aarch64",
        official_repository=OFFICIAL_REPOSITORIES["ubuntu"],
        image=(
            "docker.io/library/ubuntu:24.04@sha256:"
            "b17516cd982bf06bdd5d5600253d12a8de017b9eb831cc052b532a0363d294f9"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_arm64\.deb$",
        bootstrap_command=DEB_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=DEB_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Fedora",
        distribution="fedora",
        family="rpm",
        architecture="amd64",
        package_architecture="x86_64",
        podman_platform="linux/amd64",
        uname_architecture="x86_64",
        official_repository=OFFICIAL_REPOSITORIES["fedora"],
        image=(
            "docker.io/library/fedora:44@sha256:"
            "89f61a124414261868224666aa7fb8df1b78397a53623774bdfb105d1612b48b"
        ),
        package_pattern=r"^syswarden-[0-9][0-9.]*-1\.x86_64\.rpm$",
        bootstrap_command=RPM_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove"),
        purge_semantics=RPM_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Fedora",
        distribution="fedora",
        family="rpm",
        architecture="arm64",
        package_architecture="aarch64",
        podman_platform="linux/arm64",
        uname_architecture="aarch64",
        official_repository=OFFICIAL_REPOSITORIES["fedora"],
        image=(
            "docker.io/library/fedora:44@sha256:"
            "a471bd8bf8e7e99812fd2f29fc950685d860b3d528b9f090443dbc1a0d2bad62"
        ),
        package_pattern=r"^syswarden-[0-9][0-9.]*-1\.aarch64\.rpm$",
        bootstrap_command=RPM_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove"),
        purge_semantics=RPM_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="AlmaLinux",
        distribution="almalinux",
        family="rpm",
        architecture="amd64",
        package_architecture="x86_64",
        podman_platform="linux/amd64",
        uname_architecture="x86_64",
        official_repository=OFFICIAL_REPOSITORIES["almalinux"],
        image=(
            "docker.io/library/almalinux:9@sha256:"
            "28db580abb508f7ccbc0ac6d53e1d8da9d42a26c77fa3dcc26ac2726673fbe3e"
        ),
        package_pattern=r"^syswarden-[0-9][0-9.]*-1\.x86_64\.rpm$",
        bootstrap_command=RPM_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove"),
        purge_semantics=RPM_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="AlmaLinux",
        distribution="almalinux",
        family="rpm",
        architecture="arm64",
        package_architecture="aarch64",
        podman_platform="linux/arm64",
        uname_architecture="aarch64",
        official_repository=OFFICIAL_REPOSITORIES["almalinux"],
        image=(
            "docker.io/library/almalinux:9@sha256:"
            "2c999b3bd705fad8b115741d9036ae2499148ba162752f09f2f4ab62b0c07320"
        ),
        package_pattern=r"^syswarden-[0-9][0-9.]*-1\.aarch64\.rpm$",
        bootstrap_command=RPM_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove"),
        purge_semantics=RPM_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Alpine",
        distribution="alpine",
        family="apk",
        architecture="amd64",
        package_architecture="x86_64",
        podman_platform="linux/amd64",
        uname_architecture="x86_64",
        official_repository=OFFICIAL_REPOSITORIES["alpine"],
        image=(
            "docker.io/library/alpine:3.22@sha256:"
            "7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_x86_64\.apk$",
        bootstrap_command=APK_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=APK_PURGE_SEMANTICS,
    ),
    PlatformSpec(
        name="Alpine",
        distribution="alpine",
        family="apk",
        architecture="arm64",
        package_architecture="aarch64",
        podman_platform="linux/arm64",
        uname_architecture="aarch64",
        official_repository=OFFICIAL_REPOSITORIES["alpine"],
        image=(
            "docker.io/library/alpine:3.22@sha256:"
            "2c9d26f410d032d5b1525aa8a873e238b05b90c4ae8618743d4311f0cc827e37"
        ),
        package_pattern=r"^syswarden_[0-9][0-9.]*_aarch64\.apk$",
        bootstrap_command=APK_BOOTSTRAP,
        scenarios=("upgrade-rollback", "remove", "purge"),
        purge_semantics=APK_PURGE_SEMANTICS,
    ),
)

REQUIRED_PLATFORM_COORDINATES = frozenset(
    (spec.distribution, spec.architecture) for spec in DEFAULT_PLATFORMS
)
REQUIRED_PACKAGE_COORDINATES = frozenset(
    f"{spec.family}:{spec.package_architecture}" for spec in DEFAULT_PLATFORMS
)
PACKAGE_COORDINATE_PATTERNS = {
    f"{spec.family}:{spec.package_architecture}": spec.package_pattern
    for spec in DEFAULT_PLATFORMS
}
REQUIRED_FAMILIES = ("deb", "rpm", "apk")
NATIVE_AGGREGATE_HOST = "native-shards:amd64,arm64"
QUALIFICATION_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "release_sha",
        "release_tag",
        "previous_tag",
        "workflow_run_id",
        "workflow_run_attempt",
        "candidate_run_id",
        "candidate_artifact_id",
        "candidate_artifact_name",
        "previous_release_id",
        "candidate_manifest_sha256",
        "previous_manifest_sha256",
    }
)
NATIVE_SHARD_KEYS = frozenset({"schema_version", "architecture"})
NATIVE_SHARDS_KEYS = frozenset({"schema_version", "mode", "reports"})
NATIVE_SHARD_RECORD_KEYS = frozenset(
    {
        "architecture",
        "host_architecture",
        "report_sha256",
        "engine_name",
        "engine_version",
    }
)

OPERATOR_STATE_KEYS = (
    "config",
    "token",
    "list",
    "list_ipv6",
    "data",
    "certificate",
)

PACKAGE_PAYLOAD_PATHS = (
    "/opt/syswarden/bin/syswarden-cli",
    "/opt/syswarden/bin/syswarden-core",
    "/opt/syswarden/bin/syswarden-tui",
    "/opt/syswarden/signatures.json",
    "/usr/local/bin/syswarden",
    "/usr/local/bin/syswarden-tui",
)
FORWARD_ONLY_APK_CANDIDATE_VERSION = "4.03.0"
FORWARD_ONLY_APK_PREVIOUS_VERSION = "4.02.8"
FORWARD_ONLY_APK_PREVIOUS = {
    "x86_64": {
        "filename": "syswarden_4.02.8_x86_64.apk",
        "sha256": "c0869bcb6f9adc1e4ca191ae5f5ed7962c9c89fb2bac9a4d52c0c246b09036d4",
    },
    "aarch64": {
        "filename": "syswarden_4.02.8_aarch64.apk",
        "sha256": "80a16b099d299db4053249f7bcb3d7c234ee662ad1e10e7081ae92553d13d275",
    },
}
DEB_PACKAGE_PATHS = frozenset(
    (*PACKAGE_PAYLOAD_PATHS,)
    + (
        "/opt",
        "/opt/syswarden",
        "/opt/syswarden/bin",
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/usr/share",
        "/usr/share/doc",
        "/usr/share/doc/syswarden",
        "/usr/share/doc/syswarden/changelog.gz",
    )
)
APK_PACKAGE_PATHS = frozenset(PACKAGE_PAYLOAD_PATHS)
RPM_BUILD_ID_DIRECTORY_PATTERN = re.compile(r"^/usr/lib/\.build-id/[0-9a-f]{2}$")
RPM_BUILD_ID_LINK_PATTERN = re.compile(
    r"^/usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38}$"
)


def _state_event_checks(scenario: str, label: str) -> tuple[str, ...]:
    return tuple(
        f"{scenario}.{label}.state.{key}.{attribute}"
        for key in OPERATOR_STATE_KEYS
        for attribute in ("type", "hash", "mode", "owner")
    )


def _installed_phase_event_checks(scenario: str, label: str) -> tuple[str, ...]:
    return (
        f"{scenario}.{label}.version",
        f"{scenario}.{label}.inventory.manager",
        f"{scenario}.{label}.inventory.filesystem",
        f"{scenario}.{label}.executable",
        f"{scenario}.{label}.elf_contract",
        f"{scenario}.{label}.postinstall_contract",
    )


def _generated_cleanup_event_checks(scenario: str, label: str) -> tuple[str, ...]:
    return tuple(
        f"{scenario}.{label}.generated.{key}"
        for key in (
            "systemd_core",
            "systemd_firewall",
            "systemd_webtui",
            "openrc_core",
            "openrc_firewall",
            "openrc_webtui",
            "systemd_core_enablement",
            "systemd_firewall_enablement",
            "openrc_core_enablement",
            "openrc_firewall_enablement",
            "completion",
            "rsyslog_siem",
            "rsyslog_waf_bridge",
            "cron_reference",
            "cron_unrelated",
        )
    )


def expected_inventory_phase_labels(scenario: str) -> tuple[str, ...]:
    if scenario == "upgrade-rollback":
        return (
            "previous",
            "candidate",
            "reinstall",
            "restart-one",
            "restart-two",
            "rollback",
            "recovery",
        )
    if scenario in {"remove", "purge"}:
        return ("fresh",)
    raise LifecycleLabError(f"unsupported inventory scenario: {scenario!r}")


def _preparation_event_checks(scenario: str) -> tuple[str, ...]:
    return (
        f"{scenario}.platform.uname",
        f"{scenario}.extract.previous",
        f"{scenario}.extract.candidate",
        f"{scenario}.metadata.previous.sha256",
        f"{scenario}.metadata.candidate.sha256",
        f"{scenario}.metadata.previous.version",
        f"{scenario}.metadata.candidate.version",
        f"{scenario}.metadata.previous.architecture",
        f"{scenario}.metadata.candidate.architecture",
        f"{scenario}.metadata.previous.manager_manifest",
        f"{scenario}.metadata.previous.payload_inventory",
        f"{scenario}.metadata.candidate.manager_manifest",
        f"{scenario}.metadata.candidate.payload_inventory",
        f"{scenario}.metadata.candidate.runtime_dependencies",
    )


def expected_event_checks(family: str, scenario: str) -> tuple[str, ...]:
    """Return the exact ordered evidence contract for one lifecycle scenario."""

    if family not in EXPECTED_SCENARIOS or scenario not in EXPECTED_SCENARIOS[family]:
        raise LifecycleLabError(
            f"unsupported lifecycle evidence coordinate: {family}/{scenario}"
        )

    checks = list(_preparation_event_checks(scenario))

    def installed(command: str, label: str) -> None:
        checks.append(f"{scenario}.{command}")
        checks.append(f"{scenario}.{command}.maintainer_script")
        checks.extend(_installed_phase_event_checks(scenario, label))
        checks.extend(_state_event_checks(scenario, label))

    if scenario == "upgrade-rollback":
        installed("install.previous", "previous")
        installed("upgrade.candidate", "candidate")
        installed("reinstall.candidate", "reinstall")
        checks.extend(_installed_phase_event_checks(scenario, "restart-one"))
        checks.extend(_state_event_checks(scenario, "restart-one"))
        checks.extend(_installed_phase_event_checks(scenario, "restart-two"))
        checks.extend(_state_event_checks(scenario, "restart-two"))
        installed("rollback.previous", "rollback")
        installed("recovery.candidate", "recovery")
        return tuple(checks)

    installed("install.candidate", "fresh")
    removal_label = "final-removal" if family == "rpm" else scenario
    checks.extend(
        (
            f"{scenario}.{removal_label}",
            f"{scenario}.{removal_label}.database",
            f"{scenario}.{removal_label}.payload_inventory",
        )
    )
    checks.append(f"{scenario}.{removal_label}.service_manager_calls")
    checks.extend(_generated_cleanup_event_checks(scenario, removal_label))
    if family in {"apk"} or (family == "deb" and scenario == "remove"):
        checks.extend(_state_event_checks(scenario, removal_label))
    elif family == "deb":
        checks.extend(
            f"{scenario}.{removal_label}.state.{key}"
            for key in ("config", "token", "list", "list_ipv6", "certificate")
        )
        for key in ("data",):
            checks.extend(
                f"{scenario}.{removal_label}.state.{key}.{attribute}"
                for attribute in ("type", "hash", "mode", "owner")
            )
    elif family == "rpm":
        checks.extend(
            f"{scenario}.{removal_label}.state.{key}"
            for key in ("config", "token", "list", "list_ipv6", "certificate")
        )
        for key in ("data",):
            checks.extend(
                f"{scenario}.{removal_label}.state.{key}.{attribute}"
                for attribute in ("type", "hash", "mode", "owner")
            )
        checks.append(f"{scenario}.{removal_label}.purge-equivalent")
    return tuple(checks)


@dataclass(frozen=True)
class PackageArtifact:
    path: Path
    version: str
    sha256: str


@dataclass(frozen=True)
class PackagePair:
    candidate: PackageArtifact
    previous: PackageArtifact


def is_forward_only_apk_pair(spec: PlatformSpec, pair: PackagePair) -> bool:
    if spec.family != "apk":
        return False
    expected = FORWARD_ONLY_APK_PREVIOUS[spec.package_architecture]
    return (
        pair.candidate.version == FORWARD_ONLY_APK_CANDIDATE_VERSION
        and pair.candidate.path.name
        == f"syswarden_{FORWARD_ONLY_APK_CANDIDATE_VERSION}_{spec.package_architecture}.apk"
        and pair.previous.version == FORWARD_ONLY_APK_PREVIOUS_VERSION
        and pair.previous.path.name == expected["filename"]
        and pair.previous.sha256 == expected["sha256"]
    )


def validate_forward_only_apk_pair(spec: PlatformSpec, pair: PackagePair) -> bool:
    if spec.family != "apk":
        return False
    expected = FORWARD_ONLY_APK_PREVIOUS[spec.package_architecture]
    historical_binding_touched = (
        pair.previous.version == FORWARD_ONLY_APK_PREVIOUS_VERSION
        or pair.previous.path.name == expected["filename"]
        or pair.previous.sha256 == expected["sha256"]
    )
    forward_only = is_forward_only_apk_pair(spec, pair)
    if historical_binding_touched and not forward_only:
        raise LifecycleLabError(
            "historical APK transition must be the exact byte-bound "
            "v4.02.8 -> v4.03.0 contract for "
            f"{spec.package_architecture}"
        )
    return forward_only


@dataclass(frozen=True)
class EmulatorArtifact:
    path: Path
    sha256: str


@dataclass(frozen=True)
class BinfmtRegistration:
    path: Path
    sha256: str
    interpreter: str
    flags: str


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    """Execute commands without a shell and capture bounded evidence."""

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int,
        cwd: Path | None = None,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                list(args),
                cwd=cwd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr
            raise LifecycleLabError(
                f"command timed out after {timeout}s: {args[0]}"
            ) from exc
        return CommandResult(
            args=tuple(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_syswarden_version(version: str) -> tuple[int, int, int]:
    """Parse the canonical package form of a SysWarden source version."""

    match = SYSWARDEN_VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise LifecycleLabError(
            f"invalid SysWarden package version {version!r}; expected canonical "
            "MAJOR.MINOR.PATCH with a two-digit minor"
        )
    numeric = tuple(int(part) for part in match.groups())
    if numeric[0] > MAX_VERSION_COMPONENT or numeric[2] > MAX_VERSION_COMPONENT:
        raise LifecycleLabError(
            f"SysWarden package version component exceeds {MAX_VERSION_COMPONENT}: "
            f"{version!r}"
        )
    canonical = f"{numeric[0]}.{numeric[1]:02d}.{numeric[2]}"
    if canonical != version:
        raise LifecycleLabError(
            f"non-canonical SysWarden package version {version!r}; expected "
            f"{canonical!r}"
        )
    return numeric


def artifact_version(package_name: str) -> str:
    matches = [
        match
        for pattern in ARTIFACT_VERSION_PATTERNS
        if (match := pattern.fullmatch(package_name)) is not None
    ]
    if len(matches) != 1:
        raise LifecycleLabError(
            f"cannot extract an unambiguous SysWarden version from {package_name!r}"
        )
    version = matches[0].group("version")
    parse_syswarden_version(version)
    return version


def require_real_directory(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot inspect {label} {absolute}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LifecycleLabError(f"{label} must be a real directory: {absolute}")
    return absolute


def validate_arm64_emulator(path: Path | None) -> EmulatorArtifact | None:
    """Validate the exact interpreter expected by the host binfmt registration."""

    if path is None:
        return None
    absolute = path.expanduser().absolute()
    if ":" in str(absolute) or "\n" in str(absolute):
        raise LifecycleLabError(
            f"arm64 emulator path is unsafe for a read-only bind mount: {absolute}"
        )
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise LifecycleLabError(
            f"cannot inspect arm64 emulator {absolute}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LifecycleLabError(
            f"arm64 emulator must be a regular non-symlink file: {absolute}"
        )
    if metadata.st_size == 0:
        raise LifecycleLabError(f"arm64 emulator is empty: {absolute}")
    if metadata.st_mode & 0o111 == 0 or not os.access(absolute, os.X_OK):
        raise LifecycleLabError(f"arm64 emulator is not executable: {absolute}")
    return EmulatorArtifact(path=absolute, sha256=sha256_file(absolute))


def validate_arm64_binfmt(
    emulator: EmulatorArtifact,
    registration_path: Path = ARM64_BINFMT_REGISTRATION,
) -> BinfmtRegistration:
    """Require an enabled, persistent binfmt registration for the exact emulator."""

    absolute = registration_path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
        content = absolute.read_bytes()
    except OSError as exc:
        raise LifecycleLabError(
            f"cannot inspect arm64 binfmt registration {absolute}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LifecycleLabError(
            f"arm64 binfmt registration must be a regular non-symlink file: {absolute}"
        )
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LifecycleLabError(
            f"arm64 binfmt registration is not UTF-8: {absolute}"
        ) from exc
    if not lines or lines[0] != "enabled":
        raise LifecycleLabError("arm64 binfmt registration is not enabled")
    interpreter_lines = [
        line.removeprefix("interpreter ")
        for line in lines
        if line.startswith("interpreter ")
    ]
    flags_lines = [
        line.removeprefix("flags: ")
        for line in lines
        if line.startswith("flags: ")
    ]
    if interpreter_lines != [str(emulator.path)]:
        raise LifecycleLabError(
            "arm64 binfmt interpreter does not exactly match --arm64-emulator"
        )
    if len(flags_lines) != 1 or re.fullmatch(r"[A-Z]+", flags_lines[0]) is None:
        raise LifecycleLabError("arm64 binfmt flags are absent or malformed")
    if "F" not in flags_lines[0]:
        raise LifecycleLabError(
            "arm64 binfmt registration lacks the persistent interpreter flag F"
        )
    return BinfmtRegistration(
        path=absolute,
        sha256=hashlib.sha256(content).hexdigest(),
        interpreter=interpreter_lines[0],
        flags=flags_lines[0],
    )


def read_checksum(checksum_file: Path, package_name: str) -> str:
    try:
        metadata = checksum_file.lstat()
    except OSError as exc:
        raise LifecycleLabError(
            f"missing checksum manifest {checksum_file}: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LifecycleLabError(
            f"checksum manifest must be a regular file: {checksum_file}"
        )

    matches: list[str] = []
    for line_number, raw_line in enumerate(
        checksum_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?([^/\s]+)", line)
        if match is None:
            raise LifecycleLabError(
                f"invalid SHA256SUMS entry at {checksum_file}:{line_number}"
            )
        if match.group(2) == package_name:
            matches.append(match.group(1))
    if len(matches) != 1:
        raise LifecycleLabError(
            f"expected exactly one checksum for {package_name}, found {len(matches)}"
        )
    return matches[0]


def discover_artifact(directory: Path, pattern: str) -> PackageArtifact:
    matcher = re.compile(pattern)
    candidates: list[Path] = []
    try:
        children = sorted(directory.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise LifecycleLabError(f"cannot enumerate package directory {directory}: {exc}") from exc
    for child in children:
        if matcher.fullmatch(child.name):
            metadata = child.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise LifecycleLabError(
                    f"package artifact must be a regular file: {child}"
                )
            if metadata.st_size == 0:
                raise LifecycleLabError(f"package artifact is empty: {child}")
            candidates.append(child)
    if len(candidates) != 1:
        raise LifecycleLabError(
            f"expected exactly one package matching {pattern!r} in {directory}, "
            f"found {len(candidates)}"
        )
    package = candidates[0]
    expected = read_checksum(directory / "SHA256SUMS.txt", package.name)
    actual = sha256_file(package)
    if actual != expected:
        raise LifecycleLabError(
            f"checksum mismatch for {package}: expected {expected}, found {actual}"
        )
    return PackageArtifact(package, artifact_version(package.name), actual)


def validate_image_reference(image: str) -> None:
    if IMAGE_PATTERN.fullmatch(image) is None:
        raise LifecycleLabError(
            "container image references must include an immutable sha256 digest: "
            f"{image!r}"
        )


def image_repository(image: str) -> str:
    """Return the repository portion of a validated tag-and-digest reference."""

    validate_image_reference(image)
    tagged = image.rsplit("@", 1)[0]
    return tagged.rsplit(":", 1)[0]


def package_coordinate(spec: PlatformSpec) -> str:
    return f"{spec.family}:{spec.package_architecture}"


def platform_coordinate(spec: PlatformSpec) -> tuple[str, str]:
    return spec.distribution, spec.architecture


def platform_slug(spec: PlatformSpec) -> str:
    slug = f"{spec.distribution}-{spec.architecture}"
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug) is None:
        raise LifecycleLabError(f"unsafe platform coordinate: {slug!r}")
    return slug


def validate_platforms(platforms: Sequence[PlatformSpec]) -> None:
    if not platforms:
        raise LifecycleLabError("package lifecycle platform matrix is empty")
    seen: set[tuple[str, str]] = set()
    for spec in platforms:
        coordinate = platform_coordinate(spec)
        if coordinate in seen:
            raise LifecycleLabError(f"duplicate package lifecycle platform: {coordinate}")
        seen.add(coordinate)
        if spec.distribution not in OFFICIAL_REPOSITORIES:
            raise LifecycleLabError(
                f"unsupported package lifecycle distribution: {spec.distribution!r}"
            )
        if spec.name.casefold() != (
            "almalinux" if spec.distribution == "almalinux" else spec.distribution
        ).casefold():
            raise LifecycleLabError(
                f"platform name/distribution mismatch: {spec.name!r}/{spec.distribution!r}"
            )
        if spec.architecture not in ARCHITECTURE_LABELS:
            raise LifecycleLabError(
                f"unsupported package lifecycle architecture: {spec.architecture!r}"
            )
        expected_platform = f"linux/{spec.architecture}"
        if spec.podman_platform != expected_platform:
            raise LifecycleLabError(
                f"Podman platform mismatch for {coordinate}: expected {expected_platform!r}, "
                f"found {spec.podman_platform!r}"
            )
        expected_uname = "x86_64" if spec.architecture == "amd64" else "aarch64"
        if spec.uname_architecture != expected_uname:
            raise LifecycleLabError(
                f"uname architecture mismatch for {coordinate}: expected {expected_uname!r}"
            )
        expected_package_architecture = EXPECTED_PACKAGE_ARCHITECTURES.get(
            (spec.family, spec.architecture)
        )
        if expected_package_architecture is None:
            raise LifecycleLabError(
                f"unsupported family/architecture coordinate: {spec.family}/{spec.architecture}"
            )
        if spec.package_architecture != expected_package_architecture:
            raise LifecycleLabError(
                f"package architecture mismatch for {coordinate}: expected "
                f"{expected_package_architecture!r}, found {spec.package_architecture!r}"
            )
        expected_pattern = EXPECTED_PACKAGE_PATTERNS[(spec.family, spec.architecture)]
        if spec.package_pattern != expected_pattern:
            raise LifecycleLabError(
                f"package filename contract mismatch for {coordinate}: expected "
                f"{expected_pattern!r}, found {spec.package_pattern!r}"
            )
        if spec.scenarios != EXPECTED_SCENARIOS[spec.family]:
            raise LifecycleLabError(
                f"lifecycle scenario contract mismatch for {coordinate}: expected "
                f"{EXPECTED_SCENARIOS[spec.family]!r}, found {spec.scenarios!r}"
            )
        expected_repository = OFFICIAL_REPOSITORIES[spec.distribution]
        if spec.official_repository != expected_repository:
            raise LifecycleLabError(
                f"official repository declaration mismatch for {coordinate}: "
                f"expected {expected_repository!r}"
            )
        if image_repository(spec.image) != expected_repository:
            raise LifecycleLabError(
                f"platform {coordinate} must use official image repository "
                f"{expected_repository!r}"
            )
        if not spec.bootstrap_command.strip() or "\n" in spec.bootstrap_command:
            raise LifecycleLabError(f"invalid bootstrap command for {coordinate}")
        if not spec.purge_semantics.strip():
            raise LifecycleLabError(f"missing purge semantics for {coordinate}")
        platform_slug(spec)


def build_package_version_contract(
    pairs: dict[str, PackagePair],
) -> dict[str, object]:
    if not pairs:
        raise LifecycleLabError("package version coordinate set is empty")

    coordinates: list[dict[str, object]] = []
    candidate_versions: set[str] = set()
    previous_versions: set[str] = set()
    for coordinate, pair in sorted(pairs.items()):
        if coordinate not in REQUIRED_PACKAGE_COORDINATES:
            raise LifecycleLabError(
                f"unsupported package version coordinate {coordinate!r}"
            )
        coordinate_pattern = PACKAGE_COORDINATE_PATTERNS[coordinate]
        if (
            re.fullmatch(coordinate_pattern, pair.candidate.path.name) is None
            or re.fullmatch(coordinate_pattern, pair.previous.path.name) is None
        ):
            raise LifecycleLabError(
                f"package filenames do not match version coordinate {coordinate}"
            )
        try:
            family, package_architecture = coordinate.split(":", 1)
        except ValueError as exc:
            raise LifecycleLabError(
                f"invalid package coordinate {coordinate!r}"
            ) from exc
        candidate_numeric = parse_syswarden_version(pair.candidate.version)
        previous_numeric = parse_syswarden_version(pair.previous.version)
        candidate_versions.add(pair.candidate.version)
        previous_versions.add(pair.previous.version)
        coordinates.append(
            {
                "coordinate": coordinate,
                "family": family,
                "package_architecture": package_architecture,
                "previous_version": pair.previous.version,
                "candidate_version": pair.candidate.version,
                "previous_numeric": list(previous_numeric),
                "candidate_numeric": list(candidate_numeric),
            }
        )

    if len(previous_versions) != 1:
        raise LifecycleLabError(
            "previous package versions are inconsistent across artifacts: "
            + ", ".join(sorted(previous_versions))
        )
    if len(candidate_versions) != 1:
        raise LifecycleLabError(
            "candidate package versions are inconsistent across artifacts: "
            + ", ".join(sorted(candidate_versions))
        )

    previous_version = next(iter(previous_versions))
    candidate_version = next(iter(candidate_versions))
    previous_numeric = parse_syswarden_version(previous_version)
    candidate_numeric = parse_syswarden_version(candidate_version)
    if previous_version == candidate_version:
        raise LifecycleLabError(
            "previous and candidate package versions must be distinct; two builds "
            f"of {candidate_version} cannot prove upgrade or rollback behavior"
        )
    if previous_numeric >= candidate_numeric:
        raise LifecycleLabError(
            "previous package version must be numerically older than the candidate: "
            f"{previous_version} is not older than {candidate_version}"
        )

    return {
        "scheme": VERSION_SCHEME,
        "relation": VERSION_RELATION,
        "previous_version": previous_version,
        "candidate_version": candidate_version,
        "previous_numeric": list(previous_numeric),
        "candidate_numeric": list(candidate_numeric),
        "coordinates": coordinates,
    }


def validate_inputs(
    packages_dir: Path,
    previous_packages_dir: Path,
    platforms: Sequence[PlatformSpec],
) -> tuple[Path, Path, dict[str, PackagePair]]:
    validate_platforms(platforms)
    candidate_root = require_real_directory(packages_dir, "candidate package directory")
    previous_root = require_real_directory(
        previous_packages_dir, "previous package directory"
    )
    if candidate_root == previous_root:
        raise LifecycleLabError(
            "candidate and previous package directories must be distinct"
        )

    pairs: dict[str, PackagePair] = {}
    for spec in platforms:
        coordinate = package_coordinate(spec)
        if coordinate not in pairs:
            pair = PackagePair(
                candidate=discover_artifact(candidate_root, spec.package_pattern),
                previous=discover_artifact(previous_root, spec.package_pattern),
            )
            if pair.candidate.sha256 == pair.previous.sha256:
                raise LifecycleLabError(
                    f"candidate and previous package bytes are identical for {coordinate}"
                )
            pairs[coordinate] = pair
    build_package_version_contract(pairs)
    for spec in platforms:
        validate_forward_only_apk_pair(spec, pairs[package_coordinate(spec)])
    return candidate_root, previous_root, pairs


def build_containerfile(spec: PlatformSpec) -> str:
    validate_image_reference(spec.image)
    return (
        f"FROM {spec.image}\n"
        "ENV LANG=C.UTF-8 LC_ALL=C.UTF-8\n"
        f"RUN {spec.bootstrap_command}\n"
    )


LIFECYCLE_SCRIPT = r'''#!/bin/sh
# ShellCheck cannot infer function calls passed through run_step.
# shellcheck disable=SC2317
set -u

RESULT_FILE="/results/events.tsv"
COMMAND_LOG="/results/commands.log"
RESTART_STATE_FILE="/results/restart-state"
OPERATOR_STATE_FILE="/results/operator-state"
OPERATOR_CRON_FILE="/results/operator-cron-lines"
FAILURES=0
PREFIX="${SCENARIO}"
INVOCATION="initial"

if [ "${SCENARIO}" = "upgrade-rollback" ] && [ -f "${RESTART_STATE_FILE}" ]; then
    INVOCATION="$(sed -n '1p' "${RESTART_STATE_FILE}")"
    printf 'CONTAINER RESTART %s\n' "${INVOCATION}" >> "${COMMAND_LOG}"
else
    : > "${RESULT_FILE}"
    : > "${COMMAND_LOG}"
    rm -f "${RESTART_STATE_FILE}" "${OPERATOR_STATE_FILE}" "${OPERATOR_CRON_FILE}"
fi

record() {
    record_status="$1"
    record_check="$2"
    record_detail="$3"
    printf '%s\t%s\t%s\n' "${record_status}" "${record_check}" "${record_detail}" >> "${RESULT_FILE}"
    if [ "${record_status}" = "fail" ]; then
        FAILURES=$((FAILURES + 1))
    fi
}

if [ "${INVOCATION}" != "initial" ]; then
    FAILURES="$(awk -F '\t' '$1 == "fail" { count++ } END { print count + 0 }' "${RESULT_FILE}")"
fi

run_step() {
    check="$1"
    shift
    printf 'COMMAND %s\n' "${check}" >> "${COMMAND_LOG}"
    if "$@" >> "${COMMAND_LOG}" 2>&1; then
        record pass "${PREFIX}.${check}" "command completed"
        return 0
    else
        rc=$?
        record fail "${PREFIX}.${check}" "command failed with exit code ${rc}"
        return "${rc}"
    fi
}

run_install_step() {
    check="$1"
    package="$2"
    diagnostic="/tmp/syswarden-maintainer-${check}"
    printf 'COMMAND %s\n' "${check}" >> "${COMMAND_LOG}"
    if install_package "${package}" "${check}" > "${diagnostic}" 2>&1; then
        command_rc=0
        record pass "${PREFIX}.${check}" "command completed"
    else
        command_rc=$?
        record fail "${PREFIX}.${check}" "command failed with exit code ${command_rc}"
    fi
    cat "${diagnostic}" >> "${COMMAND_LOG}"
    if grep -Eq '(^|[[:space:]])panic:|fatal error:|SIGSEGV|segmentation violation' "${diagnostic}"; then
        if [ "${command_rc}" -eq 0 ]; then
            record fail "${PREFIX}.${check}.maintainer_script" "package manager returned success after maintainer script emitted a Go panic"
        else
            record fail "${PREFIX}.${check}.maintainer_script" "maintainer script emitted a Go panic and package manager returned exit code ${command_rc}"
        fi
    else
        record pass "${PREFIX}.${check}.maintainer_script" "maintainer script emitted no Go panic or fatal runtime diagnostic"
    fi
    rm -f "${diagnostic}"
    return "${command_rc}"
}

check_equal() {
    check="$1"
    expected="$2"
    actual="$3"
    if [ "${actual}" = "${expected}" ]; then
        record pass "${PREFIX}.${check}" "matched expected value ${expected}"
    else
        record fail "${PREFIX}.${check}" "expected ${expected}; found ${actual}"
    fi
}

check_absent() {
    check="$1"
    path="$2"
    if [ ! -e "${path}" ] && [ ! -L "${path}" ]; then
        record pass "${PREFIX}.${check}" "path is absent"
    else
        record fail "${PREFIX}.${check}" "path remains: ${path}"
    fi
}

extract_package() {
    package="$1"
    destination="$2"
    rm -rf "${destination}"
    mkdir -p "${destination}"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --extract "${package}" "${destination}"
            ;;
        rpm)
            archive="${destination}/payload.cpio"
            rpm2cpio "${package}" > "${archive}" || return 1
            (cd "${destination}" && cpio -idm --quiet < payload.cpio) || return 1
            rm -f "${archive}"
            ;;
        apk)
            tar -xf "${package}" -C "${destination}"
            ;;
        *)
            return 2
            ;;
    esac
    return 0
}

normalize_apk_version() {
    raw="$1"
    case "${raw}" in
        *-r*)
            release="${raw##*-r}"
            case "${release}" in
                ''|*[!0-9]*) return 1 ;;
            esac
            raw="${raw%-r*}"
            ;;
    esac
    printf '%s\n' "${raw}" | awk -F. '
        NF != 3 { exit 1 }
        $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ { exit 1 }
        ($2 + 0) > 99 { exit 1 }
        { printf "%d.%02d.%d\n", $1 + 0, $2 + 0, $3 + 0 }
    '
}

package_version() {
    package="$1"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --field "${package}" Version
            ;;
        rpm)
            rpm -qp --queryformat '%{VERSION}' "${package}"
            ;;
        apk)
            metadata="$(mktemp -d /tmp/syswarden-apk-metadata.XXXXXX)"
            if ! tar -xf "${package}" -C "${metadata}" .PKGINFO; then
                rm -rf "${metadata}"
                return 1
            fi
            raw_version="$(sed -n 's/^pkgver = //p' "${metadata}/.PKGINFO")"
            rm -rf "${metadata}"
            normalize_apk_version "${raw_version}"
            ;;
    esac
}

package_architecture() {
    package="$1"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --field "${package}" Architecture
            ;;
        rpm)
            rpm -qp --queryformat '%{ARCH}' "${package}"
            ;;
        apk)
            metadata="$(mktemp -d /tmp/syswarden-apk-architecture.XXXXXX)"
            if ! tar -xf "${package}" -C "${metadata}" .PKGINFO; then
                rm -rf "${metadata}"
                return 1
            fi
            sed -n 's/^arch = //p' "${metadata}/.PKGINFO"
            rm -rf "${metadata}"
            ;;
    esac
}

expected_runtime_dependencies() {
    case "${PACKAGE_FAMILY}" in
        deb)
            printf '%s\n' apt-listchanges bash-completion cron curl e2fsprogs ipset jq nftables procps qrencode rsyslog unattended-upgrades wget wireguard-tools
            ;;
        rpm)
            printf '%s\n' bash-completion checkpolicy cronie curl dnf-automatic e2fsprogs ipset jq nftables policycoreutils-python-utils procps-ng qrencode rsyslog wget wireguard-tools
            ;;
        apk)
            printf '%s\n' bash-completion curl e2fsprogs-extra jq libqrencode-tools nftables openrc procps-ng rsyslog rsyslog-uxsock wget wireguard-tools
            ;;
        *)
            return 2
            ;;
    esac | LC_ALL=C sort
}

package_runtime_dependencies() {
    package="$1"
    destination="$2"
    raw="${destination}.raw"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --field "${package}" Depends 2>/dev/null | tr ',' '\n' | \
                sed -E 's/^[[:space:]]*//; s/[[:space:]]*\([^)]*\)//; s/[[:space:]]*$//' \
                > "${raw}" || return 1
            ;;
        rpm)
            rpm -qp --requires "${package}" 2>/dev/null | \
                sed -E 's/[[:space:]].*$//' | \
                grep -E '^[A-Za-z0-9][A-Za-z0-9+_.-]*$' > "${raw}" || true
            ;;
        apk)
            metadata="$(mktemp -d /tmp/syswarden-apk-dependencies.XXXXXX)"
            if ! tar -xf "${package}" -C "${metadata}" .PKGINFO; then
                rm -rf "${metadata}"
                return 1
            fi
            sed -n 's/^depend = //p' "${metadata}/.PKGINFO" | \
                sed -E 's/[<>=~].*$//' | \
                grep -E '^[A-Za-z0-9][A-Za-z0-9+_.-]*$' > "${raw}" || true
            rm -rf "${metadata}"
            ;;
        *)
            return 2
            ;;
    esac
    LC_ALL=C sort -u "${raw}" > "${destination}"
    rm -f "${raw}"
    [ -s "${destination}" ]
}

installed_version() {
    case "${PACKAGE_FAMILY}" in
        deb)
            status="$(dpkg-query --show --showformat='${Status}' syswarden 2>/dev/null)" || return 1
            [ "${status}" = "install ok installed" ] || return 1
            dpkg-query --show --showformat='${Version}' syswarden
            ;;
        rpm)
            rpm -q --queryformat '%{VERSION}' syswarden
            ;;
        apk)
            apk info --installed syswarden > /dev/null 2>&1 || return 1
            raw_version="$(apk --no-network list --installed syswarden 2>/dev/null \
                | awk 'NR == 1 { sub(/^syswarden-/, "", $1); print $1 }')"
            normalize_apk_version "${raw_version}"
            ;;
    esac
}

is_exact_forward_only_apk_rollback() {
    check="$1"
    package="$2"
    [ "${check}" = "rollback.previous" ] || return 1
    [ "${FORWARD_ONLY_APK_TRANSITION}" = "1" ] || return 1
    [ "${package}" = "${PREVIOUS_PACKAGE}" ] || return 1
    [ "${EXPECTED_PREVIOUS_VERSION}" = "4.02.8" ] || return 1
    [ "$(hash_file "${package}" 2>/dev/null || true)" = "${EXPECTED_PREVIOUS_SHA256}" ]
}

install_package() {
    package="$1"
    check="${2:-}"
    case "${PACKAGE_FAMILY}" in
        deb)
            DEBIAN_FRONTEND=noninteractive dpkg --install "${package}"
            ;;
        rpm)
            rpm -Uvh --replacepkgs --oldpackage "${package}"
            ;;
        apk)
            if [ "${check}" = "rollback.previous" ] && \
               [ "${FORWARD_ONLY_APK_TRANSITION}" = "1" ]; then
                is_exact_forward_only_apk_rollback "${check}" "${package}" || return 1
                apk add --allow-untrusted --no-network --force-overwrite \
                    --force-old-apk "${package}"
            else
                apk add --allow-untrusted --no-network --force-overwrite "${package}"
            fi
            ;;
    esac
}

remove_package() {
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg --remove syswarden
            ;;
        rpm)
            rpm -e syswarden
            ;;
        apk)
            apk del syswarden
            ;;
    esac
}

purge_package() {
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg --purge syswarden
            ;;
        apk)
            apk del --purge syswarden
            ;;
        *)
            return 2
            ;;
    esac
}

hash_file() {
    sha256sum "$1" | awk '{print $1}'
}

file_mode() {
    stat -c '%a' "$1"
}

normalize_manifest() {
    source_file="$1"
    destination="$2"
    unsorted="${destination}.unsorted"
    : > "${unsorted}"
    while IFS= read -r raw_path || [ -n "${raw_path}" ]; do
        case "${raw_path}" in
            ''|*' contains:') continue ;;
        esac
        if [ "${PACKAGE_FAMILY}" = "apk" ]; then
            case "${raw_path}" in
                */|.PKGINFO|.INSTALL|.SIGN.*|.pre-*|.post-*|.trigger) continue ;;
            esac
        fi
        path="${raw_path#./}"
        path="${path%/}"
        case "${path}" in
            ''|'.'|'/'|'/.') continue ;;
        esac
        case "${path}" in
            /*) ;;
            *) path="/${path}" ;;
        esac
        case "${path}" in
            *'/../'*|'/..'|*'/..'|*'/./'*)
                rm -f "${unsorted}"
                return 1
                ;;
        esac
        if printf '%s' "${path}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
            rm -f "${unsorted}"
            return 1
        fi
        printf '%s\n' "${path}" >> "${unsorted}"
    done < "${source_file}"
    LC_ALL=C sort "${unsorted}" > "${destination}"
    rm -f "${unsorted}"
    [ -s "${destination}" ] || return 1
    if uniq -d "${destination}" | grep -q .; then
        return 1
    fi
}

package_manager_manifest() {
    package="$1"
    destination="$2"
    raw="${destination}.raw"
    archive="${destination}.archive"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --fsys-tarfile "${package}" > "${archive}" || return 1
            tar -tf "${archive}" > "${raw}" || return 1
            rm -f "${archive}"
            ;;
        rpm)
            rpm -qpl "${package}" > "${raw}" || return 1
            ;;
        apk)
            tar -tf "${package}" > "${raw}" || return 1
            ;;
        *)
            return 2
            ;;
    esac
    normalize_manifest "${raw}" "${destination}"
    rc=$?
    rm -f "${raw}" "${archive}"
    return "${rc}"
}

installed_manager_manifest() {
    destination="$1"
    raw="${destination}.raw"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-query --listfiles syswarden > "${raw}" || return 1
            ;;
        rpm)
            rpm -ql syswarden > "${raw}" || return 1
            ;;
        apk)
            apk info --contents syswarden > "${raw}" || return 1
            ;;
        *)
            return 2
            ;;
    esac
    normalize_manifest "${raw}" "${destination}"
    rc=$?
    rm -f "${raw}"
    return "${rc}"
}

read_inventory_metadata() {
    metadata="$(stat -c '%a %u %g' "$1" 2>/dev/null || true)"
    INVENTORY_MODE="${metadata%% *}"
    metadata_tail="${metadata#* }"
    if [ "${metadata_tail}" = "${metadata}" ]; then
        INVENTORY_UID=''
        INVENTORY_GID=''
        return 1
    fi
    INVENTORY_UID="${metadata_tail%% *}"
    INVENTORY_GID="${metadata_tail#* }"
    [ -n "${INVENTORY_MODE}" ] && [ -n "${INVENTORY_UID}" ] && [ -n "${INVENTORY_GID}" ]
}

inventory_entry() {
    path="$1"
    root="$2"
    relative="${path#/}"
    entry="${root%/}/${relative}"
    if [ -L "${entry}" ]; then
        read_inventory_metadata "${entry}" || true
        printf '%s\tsymlink\t%s\t%s\t%s\t%s\n' "${path}" "${INVENTORY_MODE}" "${INVENTORY_UID}" "${INVENTORY_GID}" "$(readlink "${entry}" 2>/dev/null || true)"
    elif [ -f "${entry}" ]; then
        read_inventory_metadata "${entry}" || true
        printf '%s\tfile\t%s\t%s\t%s\t%s\n' "${path}" "${INVENTORY_MODE}" "${INVENTORY_UID}" "${INVENTORY_GID}" "$(hash_file "${entry}" 2>/dev/null || true)"
    elif [ -d "${entry}" ]; then
        read_inventory_metadata "${entry}" || true
        printf '%s\tdirectory\t%s\t%s\t%s\t-\n' "${path}" "${INVENTORY_MODE}" "${INVENTORY_UID}" "${INVENTORY_GID}"
    elif [ -e "${entry}" ]; then
        read_inventory_metadata "${entry}" || true
        printf '%s\tunsupported\t%s\t%s\t%s\t-\n' "${path}" "${INVENTORY_MODE}" "${INVENTORY_UID}" "${INVENTORY_GID}"
        return 1
    else
        printf '%s\tmissing\t-\t-\t-\t-\n' "${path}"
        return 1
    fi
}

build_filesystem_inventory() {
    manifest="$1"
    root="$2"
    destination="$3"
    inventory_status=0
    : > "${destination}"
    while IFS= read -r path; do
        if ! inventory_entry "${path}" "${root}" >> "${destination}"; then
            inventory_status=1
        fi
    done < "${manifest}"
    return "${inventory_status}"
}

required_manifest_path() {
    manifest="$1"
    path="$2"
    [ "$(grep -Fxc "${path}" "${manifest}" 2>/dev/null || true)" = "1" ]
}

validate_manifest_contract() {
    manifest="$1"
    for required in \
        /opt/syswarden/bin/syswarden-cli \
        /opt/syswarden/bin/syswarden-core \
        /opt/syswarden/bin/syswarden-tui \
        /opt/syswarden/signatures.json \
        /usr/local/bin/syswarden \
        /usr/local/bin/syswarden-tui
    do
        required_manifest_path "${manifest}" "${required}" || return 1
    done

    case "${PACKAGE_FAMILY}" in
        deb)
            allowed='^/(opt|opt/syswarden|opt/syswarden/bin|usr|usr/local|usr/local/bin|usr/share|usr/share/doc|usr/share/doc/syswarden|usr/share/doc/syswarden/changelog\.gz|opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
            [ "$(wc -l < "${manifest}" | tr -d ' ')" = "16" ] || return 1
            grep -Ev "${allowed}" "${manifest}" | grep -q . && return 1
            ;;
        apk)
            allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
            [ "$(wc -l < "${manifest}" | tr -d ' ')" = "6" ] || return 1
            grep -Ev "${allowed}" "${manifest}" | grep -q . && return 1
            ;;
        rpm)
            allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/lib/\.build-id|usr/lib/\.build-id/[0-9a-f]{2}|usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38})$'
            grep -Ev "${allowed}" "${manifest}" | grep -q . && return 1
            required_manifest_path "${manifest}" /usr/lib/.build-id || return 1
            awk '
                /^\/usr\/lib\/\.build-id\/[0-9a-f]{2}$/ {
                    directories[$0]++
                    next
                }
                /^\/usr\/lib\/\.build-id\/[0-9a-f]{2}\/[0-9a-f]{38}$/ {
                    links++
                    parent = $0
                    sub(/\/[0-9a-f]{38}$/, "", parent)
                    required_directories[parent] = 1
                    next
                }
                END {
                    if (links != 3) {
                        exit 1
                    }
                    for (directory in directories) {
                        if (directories[directory] != 1 ||
                            !(directory in required_directories)) {
                            exit 1
                        }
                    }
                    for (directory in required_directories) {
                        if (directories[directory] != 1) {
                            exit 1
                        }
                    }
                }
            ' "${manifest}" || return 1
            ;;
    esac
    return 0
}

inventory_has_exact_entry() {
    inventory="$1"
    path="$2"
    kind="$3"
    mode="$4"
    value="$5"
    awk -F '\t' -v path="${path}" -v kind="${kind}" -v mode="${mode}" -v value="${value}" '
        $1 == path && $2 == kind && $3 == mode && $4 == "0" && $5 == "0" && $6 == value { count++ }
        END { exit count == 1 ? 0 : 1 }
    ' "${inventory}"
}

validate_inventory_contract() {
    inventory="$1"
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-cli file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-cli" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-core file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-core" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-tui file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-tui" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/signatures.json file 640 "$(awk -F '\t' '$1 == "/opt/syswarden/signatures.json" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /usr/local/bin/syswarden symlink 777 /opt/syswarden/bin/syswarden-cli || return 1
    inventory_has_exact_entry "${inventory}" /usr/local/bin/syswarden-tui symlink 777 /opt/syswarden/bin/syswarden-tui || return 1
    if awk -F '\t' '$2 == "missing" || $2 == "unsupported" { found = 1 } END { exit found ? 0 : 1 }' "${inventory}"; then
        return 1
    fi
    if awk -F '\t' '$2 == "file" && (length($6) != 64 || $6 ~ /[^0-9a-f]/) { exit 1 }' "${inventory}"; then
        :
    else
        return 1
    fi
    if [ "${PACKAGE_FAMILY}" = "deb" ]; then
        for directory in /opt /opt/syswarden /opt/syswarden/bin /usr /usr/local /usr/local/bin /usr/share /usr/share/doc /usr/share/doc/syswarden; do
            inventory_has_exact_entry "${inventory}" "${directory}" directory 755 - || return 1
        done
        changelog_hash="$(awk -F '\t' '$1 == "/usr/share/doc/syswarden/changelog.gz" { print $6 }' "${inventory}")"
        inventory_has_exact_entry "${inventory}" /usr/share/doc/syswarden/changelog.gz file 644 "${changelog_hash}" || return 1
    fi
    if [ "${PACKAGE_FAMILY}" = "rpm" ]; then
        awk -F '\t' '
            $1 == "/usr/lib/.build-id" && ($2 != "directory" || $3 != "755" || $4 != "0" || $5 != "0") { exit 1 }
            $1 ~ /^\/usr\/lib\/\.build-id\/[0-9a-f]{2}$/ && ($2 != "directory" || $3 != "755" || $4 != "0" || $5 != "0") { exit 1 }
            $1 ~ /^\/usr\/lib\/\.build-id\/[0-9a-f]{2}\/[0-9a-f]{38}$/ && ($2 != "symlink" || $3 != "777" || $4 != "0" || $5 != "0" || $6 !~ /^\.\.\/\.\.\/\.\.\/\.\.\/opt\/syswarden\/bin\/syswarden-(cli|core|tui)$/) { exit 1 }
        ' "${inventory}" || return 1
    fi
    return 0
}

verify_package_artifact() {
    label="$1"
    package="$2"
    expected_root="$3"
    manifest="/tmp/manifest-${label}"
    inventory="/tmp/inventory-${label}"
    if package_manager_manifest "${package}" "${manifest}" && validate_manifest_contract "${manifest}"; then
        record pass "${PREFIX}.metadata.${label}.manager_manifest" "exact native package manifest sha256=$(hash_file "${manifest}")"
    else
        record fail "${PREFIX}.metadata.${label}.manager_manifest" "native package manifest violates its exact family contract"
    fi
    if build_filesystem_inventory "${manifest}" "${expected_root}" "${inventory}" && validate_inventory_contract "${inventory}"; then
        record pass "${PREFIX}.metadata.${label}.payload_inventory" "complete payload inventory sha256=$(hash_file "${inventory}")"
    else
        record fail "${PREFIX}.metadata.${label}.payload_inventory" "payload type, mode, owner, link, or content inventory mismatch"
    fi
    if [ "${label}" = "candidate" ]; then
        dependencies="/tmp/dependencies-${label}"
        expected_dependencies="/tmp/dependencies-${label}.expected"
        expected_runtime_dependencies > "${expected_dependencies}"
        if package_runtime_dependencies "${package}" "${dependencies}" && \
           cmp -s "${expected_dependencies}" "${dependencies}"; then
            record pass "${PREFIX}.metadata.${label}.runtime_dependencies" "exact runtime dependency inventory sha256=$(hash_file "${dependencies}")"
        else
            diff -u "${expected_dependencies}" "${dependencies}" >> "${COMMAND_LOG}" 2>&1 || true
            record fail "${PREFIX}.metadata.${label}.runtime_dependencies" "runtime dependency inventory differs from the reviewed family contract"
        fi
    fi
}

probe_forward_only_apk_payload() {
    label="$1"
    actual_version="$(installed_version 2>/dev/null || true)"
    check_equal "${label}.version" "${EXPECTED_PREVIOUS_VERSION}" "${actual_version}"
    verify_installed_inventory "${label}" previous

    /opt/syswarden/bin/syswarden-cli --help \
        > /tmp/syswarden-historical-help.out 2>&1
    historical_rc=$?
    if [ "${historical_rc}" -eq 127 ]; then
        record pass "${PREFIX}.${label}.executable" "historical glibc loader refusal matched exit code 127"
    else
        record fail "${PREFIX}.${label}.executable" "historical failure class changed; expected loader exit 127, found ${historical_rc}"
    fi

    case "${EXPECTED_PACKAGE_ARCHITECTURE}" in
        x86_64)
            expected_interp=/lib64/ld-linux-x86-64.so.2
            expected_machine='Advanced Micro Devices X86-64'
            ;;
        aarch64)
            expected_interp=/lib/ld-linux-aarch64.so.1
            expected_machine='AArch64'
            ;;
        *)
            expected_interp=invalid
            expected_machine=invalid
            ;;
    esac
    historical_elf_ok=1
    for binary in \
        /opt/syswarden/bin/syswarden-cli \
        /opt/syswarden/bin/syswarden-core \
        /opt/syswarden/bin/syswarden-tui; do
        elf_type="$(readelf --file-header "${binary}" 2>/dev/null | sed -n 's/^[[:space:]]*Type:[[:space:]]*\([^[:space:]]*\).*/\1/p')"
        machine="$(readelf --file-header "${binary}" 2>/dev/null | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
        interpreter="$(readelf --program-headers "${binary}" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p')"
        [ "${elf_type}" = "DYN" ] || historical_elf_ok=0
        [ "${machine}" = "${expected_machine}" ] || historical_elf_ok=0
        [ "${interpreter}" = "${expected_interp}" ] || historical_elf_ok=0
    done
    if [ "${historical_elf_ok}" -eq 1 ]; then
        record pass "${PREFIX}.${label}.elf_contract" "historical payload matched DYN plus exact glibc PT_INTERP failure class"
    else
        record fail "${PREFIX}.${label}.elf_contract" "historical APK ELF failure class does not match the byte-bound contract"
    fi
    record pass "${PREFIX}.${label}.postinstall_contract" "exact byte-bound v4.02.8 historical postinstall failure input recorded before candidate recovery"
}

legacy_webtui_runtime_absent() {
    legacy_root="${1%/}"
    for retired_path in \
        /etc/systemd/system/syswarden-webtui.service \
        /etc/systemd/system/syswarden-webtui.service.syswarden-retiring \
        /etc/systemd/system/syswarden-webtui.service.d \
        /etc/systemd/system/multi-user.target.wants/syswarden-webtui.service \
        /run/systemd/system/syswarden-webtui.service \
        /run/systemd/system/syswarden-webtui.service.d \
        /etc/init.d/syswarden-webtui \
        /etc/conf.d/syswarden-webtui \
        /etc/runlevels/default/syswarden-webtui \
        /run/syswarden-webtui.pid; do
        [ ! -e "${legacy_root}${retired_path}" ] && \
            [ ! -L "${legacy_root}${retired_path}" ] || return 1
    done
}

install_service_manager_sentinels() {
    manager_path_state=/tmp/syswarden-manager-original-path
    if [ -f "${manager_path_state}" ] && [ ! -L "${manager_path_state}" ] && \
       [ "$(stat -c '%u:%g:%a' "${manager_path_state}" 2>/dev/null || true)" = 0:0:600 ]; then
        SYSWARDEN_MANAGER_ORIGINAL_PATH="$(cat "${manager_path_state}")" || return 1
    else
        [ ! -e "${manager_path_state}" ] && [ ! -L "${manager_path_state}" ] || return 1
        SYSWARDEN_MANAGER_ORIGINAL_PATH="${SYSWARDEN_MANAGER_ORIGINAL_PATH:-${PATH}}"
        (umask 077 && printf '%s\n' "${SYSWARDEN_MANAGER_ORIGINAL_PATH}" > "${manager_path_state}") || return 1
    fi
    export SYSWARDEN_MANAGER_ORIGINAL_PATH
    mkdir -p /tmp/syswarden-manager-bin
    : > /tmp/syswarden-service-manager-calls
    for manager_command in systemctl rc-service rc-update service; do
        cat > "/tmp/syswarden-manager-bin/${manager_command}" <<'SYSWARDEN_MANAGER_SENTINEL'
#!/bin/sh
printf '%s\n' "${0##*/} $*" >> /tmp/syswarden-service-manager-calls
exit 97
SYSWARDEN_MANAGER_SENTINEL
        chmod 0755 "/tmp/syswarden-manager-bin/${manager_command}"
    done
    PATH="/tmp/syswarden-manager-bin:${SYSWARDEN_MANAGER_ORIGINAL_PATH}"
    export PATH
}

remove_service_manager_sentinels() {
    manager_path_state=/tmp/syswarden-manager-original-path
    if [ -f "${manager_path_state}" ] && [ ! -L "${manager_path_state}" ] && \
       [ "$(stat -c '%u:%g:%a' "${manager_path_state}" 2>/dev/null || true)" = 0:0:600 ]; then
        SYSWARDEN_MANAGER_ORIGINAL_PATH="$(cat "${manager_path_state}")" || return 1
    fi
    PATH="${SYSWARDEN_MANAGER_ORIGINAL_PATH:-${PATH}}"
    export PATH
    rm -rf /tmp/syswarden-manager-bin
}

probe_postinstall_contract() {
    label="$1"
    postinstall_ok=1
    actual_version="$(installed_version 2>/dev/null || true)"
    for path in \
        /etc/syswarden/config/config.toml \
        /etc/syswarden/config/modules/00-core.toml \
        /etc/syswarden/config/modules/10-network.toml \
        /etc/syswarden/config/modules/20-security.toml \
        /etc/syswarden/config/modules/30-waap.toml \
        /etc/syswarden/config/modules/40-integrations.toml \
        /etc/syswarden/config/modules/99-user.toml; do
        [ -f "${path}" ] && [ ! -L "${path}" ] || postinstall_ok=0
    done
    if [ ! -s /etc/bash_completion.d/syswarden ] || [ -L /etc/bash_completion.d/syswarden ]; then
        postinstall_ok=0
    fi
    if cron_state="$(LC_ALL=C crontab -l 2>/tmp/syswarden-postinstall-cron.error)"; then
        feed_cron_count="$(printf '%s\n' "${cron_state}" | awk '
            $1 ~ /^([1-9]|[1-5][0-9])$/ &&
                $0 == $1 " * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1" { count++ }
            END { print count + 0 }
        ')"
        [ "${feed_cron_count}" -eq 1 ] || postinstall_ok=0
    else
        postinstall_ok=0
    fi
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            service_contract='systemd'
            for specification in \
                '/etc/systemd/system/syswarden-core.service|/opt/syswarden/bin/syswarden-core' \
                '/etc/systemd/system/syswarden-firewall.service|/opt/syswarden/bin/syswarden-cli reload --no-restart'; do
                path="${specification%%|*}"
                fragment="${specification#*|}"
                [ -f "${path}" ] && [ ! -L "${path}" ] && \
                    [ "$(file_mode "${path}" 2>/dev/null || true)" = "600" ] && \
                    grep -Fq "${fragment}" "${path}" || postinstall_ok=0
            done
            for specification in \
                '/etc/systemd/system/multi-user.target.wants/syswarden-core.service|../syswarden-core.service' \
                '/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service|../syswarden-firewall.service'; do
                path="${specification%%|*}"
                target="${specification#*|}"
                [ -L "${path}" ] && [ "$(readlink "${path}")" = "${target}" ] || postinstall_ok=0
            done
            ;;
        apk)
            service_contract='openrc'
            for specification in \
                '/etc/init.d/syswarden-core|/opt/syswarden/bin/syswarden-core' \
                '/etc/init.d/syswarden-firewall|/opt/syswarden/bin/syswarden-cli reload --no-restart'; do
                path="${specification%%|*}"
                fragment="${specification#*|}"
                [ -f "${path}" ] && [ ! -L "${path}" ] && \
                    [ "$(file_mode "${path}" 2>/dev/null || true)" = "755" ] && \
                    grep -Fq "${fragment}" "${path}" || postinstall_ok=0
            done
            for specification in \
                '/etc/runlevels/default/syswarden-core|/etc/init.d/syswarden-core' \
                '/etc/runlevels/default/syswarden-firewall|/etc/init.d/syswarden-firewall'; do
                path="${specification%%|*}"
                target="${specification#*|}"
                [ -L "${path}" ] && [ "$(readlink "${path}")" = "${target}" ] || postinstall_ok=0
            done
            ;;
        *)
            service_contract='invalid'
            postinstall_ok=0
            ;;
    esac
    if [ -s /tmp/syswarden-service-manager-calls ]; then
        postinstall_ok=0
    fi
    if [ "${actual_version}" = "${EXPECTED_CANDIDATE_VERSION}" ]; then
        legacy_webtui_runtime_absent / || postinstall_ok=0
        if grep -Fq 'webtui_password' \
            /etc/syswarden/config/config.toml /etc/syswarden/config/modules/*.toml \
            2>/dev/null; then
            postinstall_ok=0
        fi
        for retired_secret in \
            lot0-lifecycle-retired-token \
            lot0-lifecycle-live-retired-token; do
            if grep -Fq "${retired_secret}" "${COMMAND_LOG}" \
                /tmp/syswarden-legacy-webtui-process.log 2>/dev/null; then
                postinstall_ok=0
            fi
        done
        if [ -f /tmp/syswarden-legacy-webtui-process.pid ]; then
            legacy_webtui_pid="$(cat /tmp/syswarden-legacy-webtui-process.pid)"
            if [ -r "/proc/${legacy_webtui_pid}/cmdline" ] && \
               od -An -tx1 -v "/proc/${legacy_webtui_pid}/cmdline" 2>/dev/null | \
                   tr -d '[:space:]' | grep -Fq '007765622d74756900'; then
                postinstall_ok=0
                kill -KILL "${legacy_webtui_pid}" 2>/dev/null || true
            fi
            wait "${legacy_webtui_pid}" 2>/dev/null || true
            rm -f /tmp/syswarden-legacy-webtui-process.pid
        fi
        if [ -f /tmp/syswarden-legacy-saas-seeded ]; then
            legacy_saas_v4=/etc/syswarden/lists/syswarden_saas_monitors.ipv4
            legacy_saas_v6=/etc/syswarden/lists/syswarden_saas_monitors.ipv6
            legacy_saas_pair=/etc/syswarden/lists/syswarden_saas_monitors.pair
            [ -f "${legacy_saas_v4}" ] && [ ! -L "${legacy_saas_v4}" ] && \
                [ "$(file_mode "${legacy_saas_v4}" 2>/dev/null || true)" = 600 ] && \
                [ "$(stat -c '%u:%g' "${legacy_saas_v4}" 2>/dev/null || true)" = 0:0 ] && \
                [ "$(hash_file "${legacy_saas_v4}" 2>/dev/null || true)" = \
                    daf3972b7d1f162ae7c9b5da4a53efed5ab9cb8fb4a2385139931c37287f440c ] || postinstall_ok=0
            [ -f "${legacy_saas_v6}" ] && [ ! -L "${legacy_saas_v6}" ] && \
                [ ! -s "${legacy_saas_v6}" ] && \
                [ "$(file_mode "${legacy_saas_v6}" 2>/dev/null || true)" = 600 ] && \
                [ "$(stat -c '%u:%g' "${legacy_saas_v6}" 2>/dev/null || true)" = 0:0 ] || postinstall_ok=0
            [ -f "${legacy_saas_pair}" ] && [ ! -L "${legacy_saas_pair}" ] && \
                [ "$(file_mode "${legacy_saas_pair}" 2>/dev/null || true)" = 600 ] && \
                [ "$(stat -c '%u:%g' "${legacy_saas_pair}" 2>/dev/null || true)" = 0:0 ] || postinstall_ok=0
            expected_saas_pair=/tmp/syswarden-expected-saas-pair
            printf '%s\n' \
                'syswarden-saas-pair-v1' \
                'ipv4_sha256=daf3972b7d1f162ae7c9b5da4a53efed5ab9cb8fb4a2385139931c37287f440c' \
                'ipv6_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
                > "${expected_saas_pair}"
            cmp -s "${expected_saas_pair}" "${legacy_saas_pair}" || postinstall_ok=0
        fi
        [ -x /opt/syswarden/bin/syswarden-tui ] || postinstall_ok=0
        [ -L /usr/local/bin/syswarden-tui ] || postinstall_ok=0
        [ "$(readlink /usr/local/bin/syswarden-tui 2>/dev/null || true)" = /opt/syswarden/bin/syswarden-tui ] || postinstall_ok=0
        if nft list table inet syswarden > /tmp/syswarden-candidate-nftables 2>/dev/null; then
            if grep -Eq 'tcp dport (\{[^}]*[ ,])?62027([ ,}]|$)' /tmp/syswarden-candidate-nftables; then
                postinstall_ok=0
            fi
        else
            postinstall_ok=0
        fi
        if [ -f /tmp/syswarden-operator-62027.pid ]; then
            operator_listener_pid="$(cat /tmp/syswarden-operator-62027.pid)"
            if kill -0 "${operator_listener_pid}" 2>/dev/null; then
                operator_probe="$(printf '%s' 'syswarden-operator-62027' | \
                    socat -T 2 - TCP:127.0.0.1:62027 2>/dev/null || true)"
                [ "${operator_probe}" = 'syswarden-operator-62027' ] || postinstall_ok=0
            else
                postinstall_ok=0
                rm -f /tmp/syswarden-operator-62027.pid
            fi
        else
            postinstall_ok=0
        fi
    elif [ "${actual_version}" = "${EXPECTED_PREVIOUS_VERSION}" ]; then
        case "${PACKAGE_FAMILY}" in
            deb|rpm)
                [ -f /etc/systemd/system/syswarden-webtui.service ] && \
                    grep -Fq '/opt/syswarden/bin/syswarden-cli web-tui' \
                        /etc/systemd/system/syswarden-webtui.service || postinstall_ok=0
                ;;
            apk)
                [ -f /etc/init.d/syswarden-webtui ] && \
                    grep -Fq 'command_args="web-tui"' /etc/init.d/syswarden-webtui || postinstall_ok=0
                ;;
        esac
    else
        postinstall_ok=0
    fi
    if [ "${postinstall_ok}" -eq 1 ]; then
        record pass "${PREFIX}.${label}.postinstall_contract" "modular config, native TUI, ${service_contract} services, completion, feed cron, and browser-service retirement match the installed version"
    else
        record fail "${PREFIX}.${label}.postinstall_contract" "postinstall output contract is incomplete"
    fi
}

verify_installed_inventory() {
    label="$1"
    expected_label="$2"
    expected_manifest="/tmp/manifest-${expected_label}"
    expected_inventory="/tmp/inventory-${expected_label}"
    actual_manifest="/tmp/manifest-installed-${label}"
    actual_inventory="/tmp/inventory-installed-${label}"
    mkdir -p /results/inventories
    if installed_manager_manifest "${actual_manifest}" && cmp -s "${expected_manifest}" "${actual_manifest}"; then
        cp "${actual_manifest}" "/results/inventories/${PREFIX}-${label}-manager.tsv"
        record pass "${PREFIX}.${label}.inventory.manager" "exact native installed manifest sha256=$(hash_file "${actual_manifest}")"
    else
        diff -u "${expected_manifest}" "${actual_manifest}" >> "${COMMAND_LOG}" 2>&1 || true
        record fail "${PREFIX}.${label}.inventory.manager" "installed native manifest differs from the package manifest"
    fi
    if build_filesystem_inventory "${expected_manifest}" / "${actual_inventory}" && validate_inventory_contract "${actual_inventory}" && cmp -s "${expected_inventory}" "${actual_inventory}"; then
        cp "${actual_inventory}" "/results/inventories/${PREFIX}-${label}-filesystem.tsv"
        record pass "${PREFIX}.${label}.inventory.filesystem" "exact type/mode/owner/link/content inventory sha256=$(hash_file "${actual_inventory}")"
    else
        diff -u "${expected_inventory}" "${actual_inventory}" >> "${COMMAND_LOG}" 2>&1 || true
        record fail "${PREFIX}.${label}.inventory.filesystem" "installed type, mode, owner, link, or content inventory differs"
    fi
}

probe_payload() {
    label="$1"
    expected_label="$2"
    expected_version="$3"

    actual_version="$(installed_version 2>/dev/null || true)"
    check_equal "${label}.version" "${expected_version}" "${actual_version}"
    verify_installed_inventory "${label}" "${expected_label}"

    if /opt/syswarden/bin/syswarden-cli --help > /tmp/syswarden-help.out 2>&1; then
        if grep -q '^Usage:' /tmp/syswarden-help.out; then
            record pass "${PREFIX}.${label}.executable" "CLI executed and emitted help"
        else
            record fail "${PREFIX}.${label}.executable" "CLI exited zero without its help contract"
        fi
    else
        rc=$?
        record fail "${PREFIX}.${label}.executable" "CLI execution failed with exit code ${rc}"
    fi

    case "${EXPECTED_PACKAGE_ARCHITECTURE}" in
        amd64|x86_64) expected_machine='Advanced Micro Devices X86-64' ;;
        arm64|aarch64) expected_machine='AArch64' ;;
        *) expected_machine=invalid ;;
    esac
    elf_contract_ok=1
    for binary in \
        /opt/syswarden/bin/syswarden-cli \
        /opt/syswarden/bin/syswarden-core \
        /opt/syswarden/bin/syswarden-tui; do
        elf_type="$(readelf --file-header "${binary}" 2>/dev/null | sed -n 's/^[[:space:]]*Type:[[:space:]]*\([^[:space:]]*\).*/\1/p')"
        machine="$(readelf --file-header "${binary}" 2>/dev/null | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
        has_interp=0
        if readelf --program-headers "${binary}" 2>/dev/null | grep -q '[[:space:]]INTERP[[:space:]]'; then
            has_interp=1
        fi
        description="$(file -b "${binary}" 2>/dev/null || true)"
        [ "${machine}" = "${expected_machine}" ] || elf_contract_ok=0
        case "${PACKAGE_FAMILY}" in
            apk)
                [ "${elf_type}" = "EXEC" ] || elf_contract_ok=0
                [ "${has_interp}" -eq 0 ] || elf_contract_ok=0
                printf '%s' "${description}" | grep -Fq 'statically linked' || elf_contract_ok=0
                ;;
            deb|rpm)
                [ "${elf_type}" = "DYN" ] || elf_contract_ok=0
                [ "${has_interp}" -eq 1 ] || elf_contract_ok=0
                ;;
            *)
                elf_contract_ok=0
                ;;
        esac
    done
    if [ "${elf_contract_ok}" -eq 1 ]; then
        record pass "${PREFIX}.${label}.elf_contract" "all payload binaries match the exact package-family ELF contract"
    else
        record fail "${PREFIX}.${label}.elf_contract" "payload binaries violate the exact package-family ELF contract"
    fi
    probe_postinstall_contract "${label}"
}

seed_state() {
    mkdir -p /etc/syswarden/config/modules /etc/syswarden/lists /etc/syswarden/tls
    mkdir -p /var/lib/syswarden/ui
    printf '%s\n' 'operator-setting=preserve-exactly' > /etc/syswarden/config/lifecycle-operator.conf
    printf '%s\n' \
        '[network]' 'interfaces = "lo"' '' \
        '[user]' 'profile_name = "lifecycle-operator"' \
        > /etc/syswarden/config/modules/99-user.toml
    printf '%s\n' '198.51.100.42' > /etc/syswarden/lists/syswarden_blacklist.ipv4
    printf '%s\n' '2001:db8::42' > /etc/syswarden/lists/syswarden_blacklist.ipv6
    printf '%s\n' '{"schema":1,"sentinel":"preserve-exactly"}' > /var/lib/syswarden/ui/data.json
    printf '%s\n' '-----BEGIN CERTIFICATE-----' 'lot0-lifecycle-certificate' '-----END CERTIFICATE-----' > /etc/syswarden/tls/operator.pem
    chmod 0640 /etc/syswarden/config/lifecycle-operator.conf
    chmod 0640 /etc/syswarden/config/modules/99-user.toml
    chmod 0600 /etc/syswarden/lists/syswarden_blacklist.ipv4
    chmod 0600 /etc/syswarden/lists/syswarden_blacklist.ipv6
    chmod 0600 /var/lib/syswarden/ui/data.json
    chmod 0600 /etc/syswarden/tls/operator.pem

    STATE_CONFIG_HASH="$(hash_file /etc/syswarden/config/lifecycle-operator.conf)"
    STATE_TOKEN_HASH="$(hash_file /etc/syswarden/config/modules/99-user.toml)"
    STATE_LIST_HASH="$(hash_file /etc/syswarden/lists/syswarden_blacklist.ipv4)"
    STATE_LIST_IPV6_HASH="$(hash_file /etc/syswarden/lists/syswarden_blacklist.ipv6)"
    STATE_DATA_HASH="$(hash_file /var/lib/syswarden/ui/data.json)"
    STATE_CERT_HASH="$(hash_file /etc/syswarden/tls/operator.pem)"
    {
        printf 'STATE_CONFIG_HASH=%s\n' "${STATE_CONFIG_HASH}"
        printf 'STATE_TOKEN_HASH=%s\n' "${STATE_TOKEN_HASH}"
        printf 'STATE_LIST_HASH=%s\n' "${STATE_LIST_HASH}"
        printf 'STATE_LIST_IPV6_HASH=%s\n' "${STATE_LIST_IPV6_HASH}"
        printf 'STATE_DATA_HASH=%s\n' "${STATE_DATA_HASH}"
        printf 'STATE_CERT_HASH=%s\n' "${STATE_CERT_HASH}"
    } > "${OPERATOR_STATE_FILE}"
    chmod 0600 "${OPERATOR_STATE_FILE}"
}

seed_legacy_webtui_upgrade_state() {
    legacy_module=/etc/syswarden/config/modules/98-legacy-webtui.toml
    printf '%s\n' \
        '# Historical browser credential seeded for bounded upgrade cleanup' \
        '[user]' \
        'webtui_password = "lot0-lifecycle-retired-token"' \
        'profile_name = "preserve-after-browser-retirement"' \
        > "${legacy_module}" || return 1
    chmod 0640 "${legacy_module}" || return 1
    mkdir -p /run
    printf '%s\n' 4194303 > /run/syswarden-webtui.pid || return 1
    chmod 0600 /run/syswarden-webtui.pid || return 1
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            mkdir -p /etc/systemd/system/multi-user.target.wants /run/systemd
            cat > /etc/systemd/system/syswarden-webtui.service <<'SYSWARDEN_SYSTEMD_WEBTUI'
[Unit]
Description=SYSWARDEN Web-TUI (WebTTY)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/syswarden/bin/syswarden-cli web-tui
Restart=on-failure
RestartSec=5s

# Security Hardening
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SYSWARDEN_SYSTEMD_WEBTUI
            chmod 0600 /etc/systemd/system/syswarden-webtui.service || return 1
            ln -sf ../syswarden-webtui.service \
                /etc/systemd/system/multi-user.target.wants/syswarden-webtui.service || return 1
            ;;
        apk)
            [ -d /run ] && [ ! -L /run ] || return 1
            [ ! -e /run/openrc ] && [ ! -L /run/openrc ] || return 1
            rm -f /run/syswarden-webtui.pid
            printf '%s\n' 4194303 > /run/syswarden-webtui.pid || return 1
            mkdir -p /etc/init.d /etc/runlevels/default
            cat > /etc/init.d/syswarden-webtui <<'SYSWARDEN_OPENRC_WEBTUI'
#!/sbin/openrc-run

name="syswarden-webtui"
description="SYSWARDEN Web-TUI (WebTTY)"
command="/opt/syswarden/bin/syswarden-cli"
command_args="web-tui"
command_background=true
pidfile="/run/syswarden-webtui.pid"
retry="TERM/5/KILL/5"

depend() {
	need net
}
SYSWARDEN_OPENRC_WEBTUI
            chmod 0755 /etc/init.d/syswarden-webtui || return 1
            ln -sf /etc/init.d/syswarden-webtui /etc/runlevels/default/syswarden-webtui || return 1
            ;;
    esac

    nft delete table inet syswarden >/dev/null 2>&1 || true
    nft -f - <<'SYSWARDEN_LEGACY_62027_NFT' || return 1
table inet syswarden {
	chain stateful_protect {
		type filter hook input priority -10; policy accept;
		tcp dport 62027 accept comment "syswarden legacy Web-TUI"
	}
}
SYSWARDEN_LEGACY_62027_NFT

    socat TCP-LISTEN:62027,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat \
        >/tmp/syswarden-operator-62027.log 2>&1 &
    operator_listener_pid=$!
    printf '%s\n' "${operator_listener_pid}" > /tmp/syswarden-operator-62027.pid
    operator_listener_ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [ "$(printf '%s' 'syswarden-operator-62027' | \
            socat -T 1 - TCP:127.0.0.1:62027 2>/dev/null || true)" = \
            'syswarden-operator-62027' ]; then
            operator_listener_ready=1
            break
        fi
        kill -0 "${operator_listener_pid}" 2>/dev/null || break
        sleep 0.1
    done
    [ "${operator_listener_ready}" -eq 1 ] || return 1
}

seed_legacy_saas_monitor_state() {
    legacy_saas_v4=/etc/syswarden/lists/syswarden_saas_monitors.ipv4
    legacy_saas_v6=/etc/syswarden/lists/syswarden_saas_monitors.ipv6
    legacy_saas_pair=/etc/syswarden/lists/syswarden_saas_monitors.pair
    mkdir -p /etc/syswarden/lists || return 1
    printf '%s\n%s' '192.0.2.10' '198.51.100.0/24' > "${legacy_saas_v4}" || return 1
    chmod 0600 "${legacy_saas_v4}" || return 1
    chown 0:0 "${legacy_saas_v4}" || return 1
    rm -f "${legacy_saas_v6}" "${legacy_saas_pair}" || return 1
    : > /tmp/syswarden-legacy-saas-seeded
}

seed_live_legacy_webtui_process() {
    case "${PACKAGE_FAMILY}" in
        deb|rpm) ;;
        *) return 0 ;;
    esac
    /opt/syswarden/bin/syswarden-cli web-tui \
        --bind=127.0.0.1:62028 --token=lot0-lifecycle-live-retired-token \
        >/tmp/syswarden-legacy-webtui-process.log 2>&1 &
    legacy_webtui_pid=$!
    printf '%s\n' "${legacy_webtui_pid}" > /tmp/syswarden-legacy-webtui-process.pid
    legacy_webtui_ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        legacy_webtui_status="$(curl --insecure --silent --output /dev/null \
            --write-out '%{http_code}' https://127.0.0.1:62028/ 2>/dev/null || true)"
        if [ "${legacy_webtui_status}" = 401 ]; then
            legacy_webtui_ready=1
            break
        fi
        kill -0 "${legacy_webtui_pid}" 2>/dev/null || break
        sleep 0.1
    done
    if [ "${legacy_webtui_ready}" -ne 1 ]; then
        kill -KILL "${legacy_webtui_pid}" 2>/dev/null || true
        wait "${legacy_webtui_pid}" 2>/dev/null || true
        return 1
    fi
}

load_state_contract() {
    [ -f "${OPERATOR_STATE_FILE}" ] || return 1
    STATE_CONFIG_HASH="$(sed -n 's/^STATE_CONFIG_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_TOKEN_HASH="$(sed -n 's/^STATE_TOKEN_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_LIST_HASH="$(sed -n 's/^STATE_LIST_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_LIST_IPV6_HASH="$(sed -n 's/^STATE_LIST_IPV6_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_DATA_HASH="$(sed -n 's/^STATE_DATA_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_CERT_HASH="$(sed -n 's/^STATE_CERT_HASH=//p' "${OPERATOR_STATE_FILE}")"
    for expected_hash in \
        "${STATE_CONFIG_HASH}" "${STATE_TOKEN_HASH}" "${STATE_LIST_HASH}" \
        "${STATE_LIST_IPV6_HASH}" "${STATE_DATA_HASH}" "${STATE_CERT_HASH}"
    do
        case "${expected_hash}" in
            *[!0-9a-f]*|'') return 1 ;;
        esac
        [ "${#expected_hash}" = "64" ] || return 1
    done
}

assert_preserved() {
    label="$1"
    key="$2"
    path="$3"
    expected_hash="$4"
    expected_mode="$5"
    if [ -f "${path}" ] && [ ! -L "${path}" ]; then
        actual_type=regular
        actual_hash="$(hash_file "${path}" 2>/dev/null || true)"
        actual_mode="$(file_mode "${path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${path}" 2>/dev/null || true)"
    elif [ -L "${path}" ]; then
        actual_type=symlink
        actual_hash='-'
        actual_mode="$(file_mode "${path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${path}" 2>/dev/null || true)"
    elif [ -e "${path}" ]; then
        actual_type=unsupported
        actual_hash='-'
        actual_mode="$(file_mode "${path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${path}" 2>/dev/null || true)"
    else
        actual_type=missing
        actual_hash='-'
        actual_mode='-'
        actual_owner='-'
    fi
    check_equal "${label}.state.${key}.type" regular "${actual_type}"
    check_equal "${label}.state.${key}.hash" "${expected_hash}" "${actual_hash}"
    check_equal "${label}.state.${key}.mode" "${expected_mode}" "${actual_mode}"
    check_equal "${label}.state.${key}.owner" 0:0 "${actual_owner}"
}

assert_all_state_preserved() {
    label="$1"
    assert_preserved "${label}" config /etc/syswarden/config/lifecycle-operator.conf "${STATE_CONFIG_HASH}" 640
    assert_preserved "${label}" token /etc/syswarden/config/modules/99-user.toml "${STATE_TOKEN_HASH}" 640
    assert_preserved "${label}" list /etc/syswarden/lists/syswarden_blacklist.ipv4 "${STATE_LIST_HASH}" 600
    assert_preserved "${label}" list_ipv6 /etc/syswarden/lists/syswarden_blacklist.ipv6 "${STATE_LIST_IPV6_HASH}" 600
    assert_preserved "${label}" data /var/lib/syswarden/ui/data.json "${STATE_DATA_HASH}" 600
    assert_preserved "${label}" certificate /etc/syswarden/tls/operator.pem "${STATE_CERT_HASH}" 600
}

assert_package_absent() {
    label="$1"
    expected_label="$2"
    if installed_version > /dev/null 2>&1; then
        record fail "${PREFIX}.${label}.database" "package remains installed"
    else
        record pass "${PREFIX}.${label}.database" "package is absent from package database"
    fi
    remaining="/tmp/remaining-${label}"
    : > "${remaining}"
    while IFS="$(printf '\t')" read -r path kind _rest; do
        if [ "${kind}" != "directory" ] && { [ -e "${path}" ] || [ -L "${path}" ]; }; then
            printf '%s\n' "${path}" >> "${remaining}"
        fi
    done < "/tmp/inventory-${expected_label}"
    if [ -s "${remaining}" ]; then
        record fail "${PREFIX}.${label}.payload_inventory" "package-owned files or links remain: $(tr '\n' ' ' < "${remaining}")"
    else
        record pass "${PREFIX}.${label}.payload_inventory" "all package-owned files and links are absent"
    fi
}

seed_generated_runtime_artifacts() {
    mkdir -p /etc/rsyslog.d
    for path in \
        /etc/rsyslog.d/99-syswarden-siem.conf \
        /etc/rsyslog.d/99-syswarden-waf-bridge.conf; do
        printf '%s\n' 'syswarden-lifecycle-generated-artifact' > "${path}"
    done
    LC_ALL=C crontab -l > /tmp/syswarden-existing-cron 2>/tmp/syswarden-existing-cron.error || return 1
    {
        printf '%s\n' '# operator note mentioning syswarden-cli'
        printf '%s\n' '19 4 * * * /opt/syswarden/bin/syswarden-cli update-feeds --operator-option'
        printf '%s\n' ' */30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1'
        printf '%s \n' '17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1'
        printf '%s\n' '17  * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1'
        printf '*/30\t* * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1\n'
        printf '%s\n' '23 * * * * /srv/operator/bin/syswarden-cli update-feeds >/dev/null 2>&1'
        printf ' \t \n'
    } > "${OPERATOR_CRON_FILE}"
    {
        cat /tmp/syswarden-existing-cron
        cat "${OPERATOR_CRON_FILE}"
    } | crontab -
}

assert_generated_runtime_artifacts_absent() {
    label="$1"
    if [ -s /tmp/syswarden-service-manager-calls ]; then
        record fail "${PREFIX}.${label}.service_manager_calls" "offline removal invoked a service manager: $(tr '\n' ' ' < /tmp/syswarden-service-manager-calls)"
    else
        record pass "${PREFIX}.${label}.service_manager_calls" "offline removal invoked no service manager"
    fi
    check_absent "${label}.generated.systemd_core" /etc/systemd/system/syswarden-core.service
    check_absent "${label}.generated.systemd_firewall" /etc/systemd/system/syswarden-firewall.service
    check_absent "${label}.generated.systemd_webtui" /etc/systemd/system/syswarden-webtui.service
    check_absent "${label}.generated.openrc_core" /etc/init.d/syswarden-core
    check_absent "${label}.generated.openrc_firewall" /etc/init.d/syswarden-firewall
    check_absent "${label}.generated.openrc_webtui" /etc/init.d/syswarden-webtui
    check_absent "${label}.generated.systemd_core_enablement" /etc/systemd/system/multi-user.target.wants/syswarden-core.service
    check_absent "${label}.generated.systemd_firewall_enablement" /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service
    check_absent "${label}.generated.openrc_core_enablement" /etc/runlevels/default/syswarden-core
    check_absent "${label}.generated.openrc_firewall_enablement" /etc/runlevels/default/syswarden-firewall
    check_absent "${label}.generated.completion" /etc/bash_completion.d/syswarden
    check_absent "${label}.generated.rsyslog_siem" /etc/rsyslog.d/99-syswarden-siem.conf
    check_absent "${label}.generated.rsyslog_waf_bridge" /etc/rsyslog.d/99-syswarden-waf-bridge.conf
    if ! cron_state="$(LC_ALL=C crontab -l 2>/tmp/syswarden-remove-cron.error)"; then
        record fail "${PREFIX}.${label}.generated.cron_reference" "root crontab could not be read after removal"
        record fail "${PREFIX}.${label}.generated.cron_unrelated" "operator cron preservation could not be verified"
        return
    fi
    managed_cron="$(printf '%s\n' "${cron_state}" | awk '
        $0 == "*/30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1" { print }
        $1 ~ /^([1-9]|[1-5][0-9])$/ &&
            $0 == $1 " * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1" { print }
    ')"
    if [ -n "${managed_cron}" ]; then
        record fail "${PREFIX}.${label}.generated.cron_reference" "dead SysWarden cron reference remains"
    else
        record pass "${PREFIX}.${label}.generated.cron_reference" "SysWarden cron references are absent"
    fi
    operator_cron_ok=1
    while IFS= read -r operator_cron_line || [ -n "${operator_cron_line}" ]; do
        if ! printf '%s\n' "${cron_state}" | grep -F -x -q "${operator_cron_line}"; then
            operator_cron_ok=0
        fi
    done < "${OPERATOR_CRON_FILE}"
    if [ "${operator_cron_ok}" -eq 1 ]; then
        record pass "${PREFIX}.${label}.generated.cron_unrelated" "unrelated cron entry is preserved"
    else
        record fail "${PREFIX}.${label}.generated.cron_unrelated" "unrelated cron entry was removed"
    fi
}

prepare_expected_payloads() {
    if ! run_step extract.previous extract_package "${PREVIOUS_PACKAGE}" /tmp/expected-previous; then
        return 1
    fi
    if ! run_step extract.candidate extract_package "${CANDIDATE_PACKAGE}" /tmp/expected-candidate; then
        return 1
    fi
    check_equal metadata.previous.sha256 "${EXPECTED_PREVIOUS_SHA256}" "$(hash_file "${PREVIOUS_PACKAGE}" 2>/dev/null || true)"
    check_equal metadata.candidate.sha256 "${EXPECTED_CANDIDATE_SHA256}" "$(hash_file "${CANDIDATE_PACKAGE}" 2>/dev/null || true)"
    if [ "$(hash_file "${PREVIOUS_PACKAGE}" 2>/dev/null || true)" != "${EXPECTED_PREVIOUS_SHA256}" ] || \
       [ "$(hash_file "${CANDIDATE_PACKAGE}" 2>/dev/null || true)" != "${EXPECTED_CANDIDATE_SHA256}" ]; then
        return 1
    fi
    PREVIOUS_VERSION="$(package_version "${PREVIOUS_PACKAGE}" 2>/dev/null || true)"
    CANDIDATE_VERSION="$(package_version "${CANDIDATE_PACKAGE}" 2>/dev/null || true)"
    if [ -z "${PREVIOUS_VERSION}" ]; then
        record fail "${PREFIX}.metadata.previous.version" "version is empty"
        return 1
    fi
    if [ -z "${CANDIDATE_VERSION}" ]; then
        record fail "${PREFIX}.metadata.candidate.version" "version is empty"
        return 1
    fi
    check_equal metadata.previous.version "${EXPECTED_PREVIOUS_VERSION}" "${PREVIOUS_VERSION}"
    check_equal metadata.candidate.version "${EXPECTED_CANDIDATE_VERSION}" "${CANDIDATE_VERSION}"
    if [ "${PREVIOUS_VERSION}" != "${EXPECTED_PREVIOUS_VERSION}" ] || \
       [ "${CANDIDATE_VERSION}" != "${EXPECTED_CANDIDATE_VERSION}" ]; then
        return 1
    fi
    PREVIOUS_ARCHITECTURE="$(package_architecture "${PREVIOUS_PACKAGE}" 2>/dev/null || true)"
    CANDIDATE_ARCHITECTURE="$(package_architecture "${CANDIDATE_PACKAGE}" 2>/dev/null || true)"
    check_equal metadata.previous.architecture "${EXPECTED_PACKAGE_ARCHITECTURE}" "${PREVIOUS_ARCHITECTURE}"
    check_equal metadata.candidate.architecture "${EXPECTED_PACKAGE_ARCHITECTURE}" "${CANDIDATE_ARCHITECTURE}"
    if [ "${PREVIOUS_ARCHITECTURE}" != "${EXPECTED_PACKAGE_ARCHITECTURE}" ] || \
       [ "${CANDIDATE_ARCHITECTURE}" != "${EXPECTED_PACKAGE_ARCHITECTURE}" ]; then
        return 1
    fi
    verify_package_artifact previous "${PREVIOUS_PACKAGE}" /tmp/expected-previous
    verify_package_artifact candidate "${CANDIDATE_PACKAGE}" /tmp/expected-candidate
    return 0
}

probe_execution_architecture() {
    actual="$(uname -m 2>/dev/null || true)"
    check_equal platform.uname "${EXPECTED_UNAME_ARCHITECTURE}" "${actual}"
    [ "${actual}" = "${EXPECTED_UNAME_ARCHITECTURE}" ]
}

scenario_upgrade_rollback_initial() {
    prepare_expected_payloads || return
    run_install_step install.previous "${PREVIOUS_PACKAGE}" || return
    if [ "${FORWARD_ONLY_APK_TRANSITION}" = "1" ]; then
        probe_forward_only_apk_payload previous
    else
        probe_payload previous previous "${PREVIOUS_VERSION}"
    fi
    seed_state
    assert_all_state_preserved previous
    seed_legacy_webtui_upgrade_state || return
    seed_live_legacy_webtui_process || return
    seed_legacy_saas_monitor_state || return

    install_service_manager_sentinels || return
    run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload candidate candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved candidate

    run_install_step reinstall.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload reinstall candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved reinstall

    printf '%s\n' restart-one > "${RESTART_STATE_FILE}"
}

scenario_upgrade_rollback_restart_one() {
    load_state_contract || return
    install_service_manager_sentinels || return
    probe_payload restart-one candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved restart-one
    printf '%s\n' restart-two > "${RESTART_STATE_FILE}"
}

scenario_upgrade_rollback_restart_two() {
    load_state_contract || return
    install_service_manager_sentinels || return
    probe_payload restart-two candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved restart-two
    remove_service_manager_sentinels
    run_install_step rollback.previous "${PREVIOUS_PACKAGE}" || return
    if [ "${FORWARD_ONLY_APK_TRANSITION}" = "1" ]; then
        probe_forward_only_apk_payload rollback
    else
        probe_payload rollback previous "${EXPECTED_PREVIOUS_VERSION}"
    fi
    assert_all_state_preserved rollback
    install_service_manager_sentinels || return
    run_install_step recovery.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload recovery candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved recovery
    printf '%s\n' complete > "${RESTART_STATE_FILE}"
}

scenario_remove() {
    prepare_expected_payloads || return
    seed_state
    install_service_manager_sentinels || return
    run_install_step install.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload fresh candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved fresh
    seed_generated_runtime_artifacts || return
    case "${PACKAGE_FAMILY}" in
        deb|apk)
            run_step remove remove_package || return
            assert_package_absent remove candidate
            assert_generated_runtime_artifacts_absent remove
            assert_all_state_preserved remove
            ;;
        rpm)
            run_step final-removal remove_package || return
            assert_package_absent final-removal candidate
            assert_generated_runtime_artifacts_absent final-removal
            check_absent final-removal.state.config /etc/syswarden/config/lifecycle-operator.conf
            check_absent final-removal.state.token /etc/syswarden/config/modules/99-user.toml
            check_absent final-removal.state.list /etc/syswarden/lists/syswarden_blacklist.ipv4
            check_absent final-removal.state.list_ipv6 /etc/syswarden/lists/syswarden_blacklist.ipv6
            check_absent final-removal.state.certificate /etc/syswarden/tls/operator.pem
            assert_preserved final-removal data /var/lib/syswarden/ui/data.json "${STATE_DATA_HASH}" 600
            if ! installed_version >/dev/null 2>&1 && [ ! -s /tmp/remaining-final-removal ]; then
                record pass "${PREFIX}.final-removal.purge-equivalent" "RPM final erase completed its verified purge-equivalent semantics"
            else
                record fail "${PREFIX}.final-removal.purge-equivalent" "RPM final erase did not complete its purge-equivalent semantics"
            fi
            ;;
    esac
}

scenario_purge() {
    prepare_expected_payloads || return
    seed_state
    install_service_manager_sentinels || return
    run_install_step install.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload fresh candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved fresh
    seed_generated_runtime_artifacts || return
    run_step purge purge_package || return
    assert_package_absent purge candidate
    assert_generated_runtime_artifacts_absent purge
    case "${PACKAGE_FAMILY}" in
        deb)
            check_absent purge.state.config /etc/syswarden/config/lifecycle-operator.conf
            check_absent purge.state.token /etc/syswarden/config/modules/99-user.toml
            check_absent purge.state.list /etc/syswarden/lists/syswarden_blacklist.ipv4
            check_absent purge.state.list_ipv6 /etc/syswarden/lists/syswarden_blacklist.ipv6
            check_absent purge.state.certificate /etc/syswarden/tls/operator.pem
            assert_preserved purge data /var/lib/syswarden/ui/data.json "${STATE_DATA_HASH}" 600
            ;;
        apk)
            assert_all_state_preserved purge
            ;;
    esac
}

if [ "${INVOCATION}" = "initial" ]; then
    if ! probe_execution_architecture; then
        exit 1
    fi
fi

case "${SCENARIO}" in
    upgrade-rollback)
        case "${INVOCATION}" in
            initial) scenario_upgrade_rollback_initial ;;
            restart-one) scenario_upgrade_rollback_restart_one ;;
            restart-two) scenario_upgrade_rollback_restart_two ;;
            *) exit 1 ;;
        esac
        ;;
    remove)
        scenario_remove
        ;;
    purge)
        scenario_purge
        ;;
    *)
        record fail "scenario" "unsupported scenario ${SCENARIO}"
        ;;
esac

if [ "${FAILURES}" -ne 0 ]; then
    exit 1
fi
exit 0
'''


def parse_events(path: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LifecycleLabError(f"cannot read lifecycle event file {path}: {exc}") from exc
    events: list[dict[str, str]] = []
    for line_number, line in enumerate(lines, start=1):
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] not in {"pass", "fail", "info"}:
            raise LifecycleLabError(
                f"invalid lifecycle event at {path}:{line_number}"
            )
        events.append(
            {"status": fields[0], "check": fields[1], "detail": fields[2]}
        )
    if not events:
        raise LifecycleLabError(f"lifecycle event file is empty: {path}")
    return events


def validate_event_contract(
    events: Sequence[dict[str, str]], family: str, scenario: str
) -> None:
    """Reject missing, duplicated, reordered, synthetic, or informational evidence."""

    expected = expected_event_checks(family, scenario)
    observed: list[str] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise LifecycleLabError(
                f"lifecycle event {index} for {family}/{scenario} is not an object"
            )
        status = event.get("status")
        check = event.get("check")
        detail = event.get("detail")
        if status not in {"pass", "fail"}:
            raise LifecycleLabError(
                f"lifecycle event {index} for {family}/{scenario} has a non-verdict status"
            )
        if not isinstance(check, str) or not isinstance(detail, str) or not detail:
            raise LifecycleLabError(
                f"lifecycle event {index} for {family}/{scenario} is incomplete"
            )
        observed.append(check)
    if tuple(observed) != expected:
        expected_set = set(expected)
        observed_set = set(observed)
        missing = [check for check in expected if check not in observed_set]
        unexpected = [check for check in observed if check not in expected_set]
        duplicated = sorted(
            check for check in observed_set if observed.count(check) > 1
        )
        raise LifecycleLabError(
            f"lifecycle event contract mismatch for {family}/{scenario}; "
            f"missing={missing!r}, unexpected={unexpected!r}, "
            f"duplicated={duplicated!r}, ordered_match=False"
        )


def _validate_manager_paths(family: str, paths: list[str]) -> None:
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise LifecycleLabError(
            "native package-manager inventory must be sorted and duplicate-free"
        )
    if any(
        not path.startswith("/")
        or path in {"/", "/."}
        or ".." in Path(path).parts
        or any(ord(character) < 32 for character in path)
        for path in paths
    ):
        raise LifecycleLabError(
            "native package-manager inventory contains an unsafe path"
        )
    observed = set(paths)
    if family == "deb":
        if observed != DEB_PACKAGE_PATHS:
            raise LifecycleLabError("DEB native package inventory is not exact")
        return
    if family == "apk":
        if observed != APK_PACKAGE_PATHS:
            raise LifecycleLabError("APK native package inventory is not exact")
        return
    if family != "rpm":
        raise LifecycleLabError(f"unsupported inventory family: {family!r}")
    build_directories = {
        path for path in paths if RPM_BUILD_ID_DIRECTORY_PATTERN.fullmatch(path)
    }
    build_links = {
        path for path in paths if RPM_BUILD_ID_LINK_PATTERN.fullmatch(path)
    }
    required_build_directories = {
        path.rsplit("/", 1)[0] for path in build_links
    }
    expected = (
        set(PACKAGE_PAYLOAD_PATHS)
        | {"/usr/lib/.build-id"}
        | required_build_directories
        | build_links
    )
    if (
        observed != expected
        or len(build_links) != 3
        or build_directories != required_build_directories
    ):
        raise LifecycleLabError("RPM native package inventory is not exact")


def validate_inventory_snapshot(
    family: str,
    manager_paths: list[str],
    filesystem: list[dict[str, object]],
) -> None:
    """Validate the full native path list and every filesystem metadata entry."""

    _validate_manager_paths(family, manager_paths)
    if len(filesystem) != len(manager_paths):
        raise LifecycleLabError(
            "filesystem inventory does not cover every native package path"
        )
    observed_paths: list[str] = []
    entries: dict[str, dict[str, object]] = {}
    for entry in filesystem:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "type",
            "mode",
            "uid",
            "gid",
            "value",
        }:
            raise LifecycleLabError("filesystem inventory entry has invalid fields")
        path = entry.get("path")
        if not isinstance(path, str) or path in entries:
            raise LifecycleLabError(
                "filesystem inventory contains an invalid or duplicate path"
            )
        if (
            not isinstance(entry.get("type"), str)
            or not isinstance(entry.get("mode"), str)
            or type(entry.get("uid")) is not int
            or type(entry.get("gid")) is not int
            or not isinstance(entry.get("value"), str)
        ):
            raise LifecycleLabError(
                "filesystem inventory metadata has invalid scalar types"
            )
        if entry["uid"] != 0 or entry["gid"] != 0:
            raise LifecycleLabError(
                f"package inventory owner is not root:root at {path}"
            )
        observed_paths.append(path)
        entries[path] = entry
    if observed_paths != manager_paths:
        raise LifecycleLabError(
            "filesystem inventory order differs from the native package inventory"
        )

    file_modes = {
        "/opt/syswarden/bin/syswarden-cli": "750",
        "/opt/syswarden/bin/syswarden-core": "750",
        "/opt/syswarden/bin/syswarden-tui": "750",
        "/opt/syswarden/signatures.json": "640",
    }
    for path, mode in file_modes.items():
        entry = entries[path]
        if (
            entry["type"] != "file"
            or entry["mode"] != mode
            or re.fullmatch(r"[0-9a-f]{64}", str(entry["value"])) is None
        ):
            raise LifecycleLabError(
                f"package file type/mode/digest contract failed at {path}"
            )
    link_targets = {
        "/usr/local/bin/syswarden": "/opt/syswarden/bin/syswarden-cli",
        "/usr/local/bin/syswarden-tui": "/opt/syswarden/bin/syswarden-tui",
    }
    for path, target in link_targets.items():
        entry = entries[path]
        if (
            entry["type"] != "symlink"
            or entry["mode"] != "777"
            or entry["value"] != target
        ):
            raise LifecycleLabError(
                f"package public-link contract failed at {path}"
            )
    if family == "deb":
        for path in DEB_PACKAGE_PATHS - set(PACKAGE_PAYLOAD_PATHS) - {
            "/usr/share/doc/syswarden/changelog.gz"
        }:
            entry = entries[path]
            if (
                entry["type"] != "directory"
                or entry["mode"] != "755"
                or entry["value"] != "-"
            ):
                raise LifecycleLabError(
                    f"DEB directory metadata contract failed at {path}"
                )
        changelog = entries["/usr/share/doc/syswarden/changelog.gz"]
        if (
            changelog["type"] != "file"
            or changelog["mode"] != "644"
            or re.fullmatch(r"[0-9a-f]{64}", str(changelog["value"])) is None
        ):
            raise LifecycleLabError("DEB generated changelog inventory is invalid")
    if family == "rpm":
        build_id_targets: set[str] = set()
        for path, entry in entries.items():
            if path == "/usr/lib/.build-id" or RPM_BUILD_ID_DIRECTORY_PATTERN.fullmatch(
                path
            ):
                if (
                    entry["type"] != "directory"
                    or entry["mode"] != "755"
                    or entry["value"] != "-"
                ):
                    raise LifecycleLabError(
                        f"RPM build-id directory metadata failed at {path}"
                    )
            elif RPM_BUILD_ID_LINK_PATTERN.fullmatch(path):
                if entry["type"] != "symlink" or entry["mode"] != "777":
                    raise LifecycleLabError(
                        f"RPM build-id link metadata failed at {path}"
                    )
                build_id_targets.add(str(entry["value"]))
        if build_id_targets != {
            "../../../../opt/syswarden/bin/syswarden-cli",
            "../../../../opt/syswarden/bin/syswarden-core",
            "../../../../opt/syswarden/bin/syswarden-tui",
        }:
            raise LifecycleLabError("RPM build-id link targets are not exact")


def parse_scenario_inventory_evidence(
    result_root: Path, family: str, scenario: str
) -> dict[str, object]:
    inventory_root = result_root / "inventories"
    try:
        root_metadata = inventory_root.lstat()
    except OSError as exc:
        raise LifecycleLabError(
            f"missing scenario inventory evidence at {inventory_root}: {exc}"
        ) from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise LifecycleLabError(
            f"scenario inventory evidence must be a real directory: {inventory_root}"
        )
    labels = expected_inventory_phase_labels(scenario)
    expected_names = {
        f"{scenario}-{label}-{kind}.tsv"
        for label in labels
        for kind in ("manager", "filesystem")
    }
    actual_names = {path.name for path in inventory_root.iterdir()}
    if actual_names != expected_names:
        raise LifecycleLabError(
            f"scenario inventory evidence file set is not exact for {family}/{scenario}"
        )

    evidence: dict[str, object] = {}
    for label in labels:
        manager_file = inventory_root / f"{scenario}-{label}-manager.tsv"
        filesystem_file = inventory_root / f"{scenario}-{label}-filesystem.tsv"
        for path in (manager_file, filesystem_file):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise LifecycleLabError(
                    f"scenario inventory evidence must be a regular file: {path}"
                )
        manager_paths = manager_file.read_text(encoding="utf-8").splitlines()
        filesystem: list[dict[str, object]] = []
        for line_number, line in enumerate(
            filesystem_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            fields = line.split("\t")
            if len(fields) != 6:
                raise LifecycleLabError(
                    f"invalid filesystem inventory at {filesystem_file}:{line_number}"
                )
            path, kind, mode, uid, gid, value = fields
            if not uid.isdecimal() or not gid.isdecimal():
                raise LifecycleLabError(
                    f"invalid inventory owner at {filesystem_file}:{line_number}"
                )
            filesystem.append(
                {
                    "path": path,
                    "type": kind,
                    "mode": mode,
                    "uid": int(uid),
                    "gid": int(gid),
                    "value": value,
                }
            )
        validate_inventory_snapshot(family, manager_paths, filesystem)
        evidence[label] = {
            "manager_paths": manager_paths,
            "filesystem": filesystem,
        }
    return evidence


def validate_scenario_inventory_evidence(
    evidence: object, family: str, scenario: str
) -> None:
    labels = expected_inventory_phase_labels(scenario)
    if not isinstance(evidence, dict) or set(evidence) != set(labels):
        raise LifecycleLabError(
            f"scenario inventory phase set is not exact for {family}/{scenario}"
        )
    for label in labels:
        phase = evidence.get(label)
        if not isinstance(phase, dict) or set(phase) != {
            "manager_paths",
            "filesystem",
        }:
            raise LifecycleLabError(
                f"scenario inventory phase is invalid for {family}/{scenario}/{label}"
            )
        manager_paths = phase.get("manager_paths")
        filesystem = phase.get("filesystem")
        if (
            not isinstance(manager_paths, list)
            or any(not isinstance(path, str) for path in manager_paths)
            or not isinstance(filesystem, list)
            or any(not isinstance(entry, dict) for entry in filesystem)
        ):
            raise LifecycleLabError(
                f"scenario inventory phase values are invalid for {family}/{scenario}/{label}"
            )
        validate_inventory_snapshot(family, manager_paths, filesystem)


def command_log_tail(result: CommandResult, command_log: Path | None = None) -> str:
    sections = []
    if command_log is not None and command_log.is_file():
        sections.append(command_log.read_text(encoding="utf-8", errors="replace"))
    if result.stdout:
        sections.append("PODMAN STDOUT\n" + result.stdout)
    if result.stderr:
        sections.append("PODMAN STDERR\n" + result.stderr)
    return "\n".join(sections)[-LOG_TAIL_LIMIT:]


def require_success(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        detail = command_log_tail(result)
        raise LifecycleLabError(
            f"{description} failed with exit code {result.returncode}: {detail}"
        )


def ensure_rootless_podman(runner: CommandRunner, podman: str) -> str:
    version = runner.run(
        (podman, "version", "--format", "{{.Client.Version}}"), timeout=30
    )
    require_success(version, "Podman version probe")
    rootless = runner.run(
        (podman, "info", "--format", "{{.Host.Security.Rootless}}"), timeout=30
    )
    require_success(rootless, "Podman rootless probe")
    if rootless.stdout.strip().lower() != "true":
        raise LifecycleLabError("package lifecycle lab requires rootless Podman")
    return version.stdout.strip()


def ensure_image(
    runner: CommandRunner,
    podman: str,
    spec: PlatformSpec,
    pull_policy: str,
) -> None:
    image = spec.image
    validate_image_reference(image)
    exists = runner.run((podman, "image", "exists", image), timeout=30)
    should_pull = pull_policy == "always" or (
        pull_policy == "missing" and exists.returncode != 0
    )
    if pull_policy == "never" and exists.returncode != 0:
        raise LifecycleLabError(f"required pinned image is not local: {image}")
    if should_pull:
        pulled = runner.run(
            (podman, "pull", "--platform", spec.podman_platform, image),
            timeout=600,
        )
        require_success(pulled, f"pull pinned image {image}")

    inspected = runner.run(
        (
            podman,
            "image",
            "inspect",
            "--format",
            "{{.Digest}}\t{{.Os}}/{{.Architecture}}",
            image,
        ),
        timeout=30,
    )
    require_success(inspected, f"inspect pinned image {image}")
    expected_digest = image.rsplit("@", 1)[1]
    fields = inspected.stdout.strip().split("\t")
    if len(fields) != 2:
        raise LifecycleLabError(
            f"invalid image inspection evidence for {image}: {inspected.stdout!r}"
        )
    actual_digest, actual_platform = fields
    if actual_digest != expected_digest:
        raise LifecycleLabError(
            f"image digest mismatch for {image}: found {actual_digest}"
        )
    if actual_platform != spec.podman_platform:
        raise LifecycleLabError(
            f"image architecture mismatch for {image}: expected "
            f"{spec.podman_platform}, found {actual_platform}"
        )


def architecture_probe_arguments(
    podman: str,
    spec: PlatformSpec,
) -> tuple[str, ...]:
    """Build a networkless, read-only execution probe for native/binfmt support."""

    arguments = [
        podman,
        "run",
        "--rm",
        "--network=none",
        "--platform",
        spec.podman_platform,
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--security-opt=label=disable",
        "--pids-limit=64",
        "--memory=128m",
        "--tmpfs=/tmp:rw,nodev,nosuid,size=16m",
    ]
    arguments.extend((spec.image, "/bin/uname", "-m"))
    return tuple(arguments)


def normalize_host_architecture(value: str) -> str | None:
    normalized = value.strip().casefold()
    if normalized in {"amd64", "x86_64"}:
        return "amd64"
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    return None


def required_coordinates_for_architecture(
    architecture: str,
) -> frozenset[tuple[str, str]]:
    if architecture not in ARCHITECTURE_LABELS:
        raise LifecycleLabError(
            f"unsupported package lifecycle architecture shard {architecture!r}"
        )
    return frozenset(
        coordinate
        for coordinate in REQUIRED_PLATFORM_COORDINATES
        if coordinate[1] == architecture
    )


def probe_platform_execution(
    runner: CommandRunner,
    podman: str,
    spec: PlatformSpec,
    host_architecture: str,
    emulator: EmulatorArtifact | None = None,
    binfmt: BinfmtRegistration | None = None,
    binfmt_error: str | None = None,
) -> dict[str, object]:
    """Prove that the requested architecture can execute, including emulation."""

    normalized_host = normalize_host_architecture(host_architecture)
    cross_arm64 = spec.architecture == "arm64" and normalized_host != "arm64"
    if cross_arm64 and emulator is None:
        return {
            "status": "unavailable",
            "execution_mode": "explicit_emulator_required",
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "reason": (
                "cross-architecture arm64 execution requires an explicit, "
                "validated --arm64-emulator and its exact persistent binfmt "
                "registration; implicit emulation is forbidden"
            ),
        }
    if cross_arm64 and binfmt is None:
        return {
            "status": "unavailable",
            "execution_mode": "host_binfmt_required",
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "reason": binfmt_error or "validated arm64 binfmt registration is absent",
        }
    active_emulator = emulator if cross_arm64 else None
    active_binfmt = binfmt if cross_arm64 else None
    execution_mode = "host_binfmt_qemu_aarch64" if active_binfmt else "native"
    emulator_evidence = (
        {
            "path": str(active_emulator.path),
            "sha256": active_emulator.sha256,
            "role": "host binfmt interpreter",
        }
        if active_emulator is not None
        else None
    )
    binfmt_evidence = (
        {
            "path": str(active_binfmt.path),
            "sha256": active_binfmt.sha256,
            "interpreter": active_binfmt.interpreter,
            "flags": active_binfmt.flags,
        }
        if active_binfmt is not None
        else None
    )
    args = architecture_probe_arguments(podman, spec)
    try:
        result = runner.run(args, timeout=60)
    except LifecycleLabError as exc:
        return {
            "status": "unavailable",
            "execution_mode": execution_mode,
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "reason": str(exc),
            "emulator": emulator_evidence,
            "binfmt": binfmt_evidence,
        }
    actual_uname = result.stdout.strip()
    if result.returncode != 0 or actual_uname != spec.uname_architecture:
        return {
            "status": "unavailable",
            "execution_mode": execution_mode,
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "actual_uname": actual_uname,
            "container_exit_code": result.returncode,
            "reason": (
                "the pinned image did not execute with the requested architecture; "
                "native execution or explicitly configured binfmt/emulation is required"
            ),
            "log_tail": command_log_tail(result),
            "emulator": emulator_evidence,
            "binfmt": binfmt_evidence,
        }
    return {
        "status": "available",
        "execution_mode": execution_mode,
        "podman_platform": spec.podman_platform,
        "expected_uname": spec.uname_architecture,
        "actual_uname": actual_uname,
        "container_exit_code": result.returncode,
        "network": "disabled",
        "filesystem": "read-only with bounded /tmp tmpfs",
        "emulator": emulator_evidence,
        "binfmt": binfmt_evidence,
    }


def container_run_arguments(
    podman: str,
    image: str,
    name: str,
    candidate_root: Path,
    previous_root: Path,
    script_path: Path,
    result_root: Path,
    spec: PlatformSpec,
    scenario: str,
    pair: PackagePair,
) -> tuple[str, ...]:
    arguments = [
        podman,
        "create",
        "--name",
        name,
        "--network=none",
        "--cap-add",
        "NET_ADMIN",
        "--platform",
        spec.podman_platform,
        "--security-opt=no-new-privileges",
        "--security-opt=label=disable",
        "--pids-limit=512",
        "--memory=1g",
        "--tmpfs=/run:rw,nodev,nosuid,size=64m",
        "--volume",
        f"{candidate_root}:/candidate:ro",
        "--volume",
        f"{previous_root}:/previous:ro",
        "--volume",
        f"{script_path}:/lab/package-lifecycle.sh:ro",
        "--volume",
        f"{result_root}:/results:rw",
        "--env",
        f"PACKAGE_FAMILY={spec.family}",
        "--env",
        f"EXPECTED_PACKAGE_ARCHITECTURE={spec.package_architecture}",
        "--env",
        f"EXPECTED_UNAME_ARCHITECTURE={spec.uname_architecture}",
        "--env",
        f"EXPECTED_CANDIDATE_VERSION={pair.candidate.version}",
        "--env",
        f"EXPECTED_PREVIOUS_VERSION={pair.previous.version}",
        "--env",
        f"EXPECTED_CANDIDATE_SHA256={pair.candidate.sha256}",
        "--env",
        f"EXPECTED_PREVIOUS_SHA256={pair.previous.sha256}",
        "--env",
        "FORWARD_ONLY_APK_TRANSITION="
        + ("1" if is_forward_only_apk_pair(spec, pair) else "0"),
        "--env",
        f"SCENARIO={scenario}",
        "--env",
        f"CANDIDATE_PACKAGE=/candidate/{pair.candidate.path.name}",
        "--env",
        f"PREVIOUS_PACKAGE=/previous/{pair.previous.path.name}",
    ]
    arguments.extend((image, "/bin/sh", "/lab/package-lifecycle.sh"))
    return tuple(arguments)


def run_platform(
    runner: CommandRunner,
    podman: str,
    spec: PlatformSpec,
    pair: PackagePair,
    candidate_root: Path,
    previous_root: Path,
    workspace: Path,
    pull_policy: str,
    timeout: int,
    host_architecture: str,
    arm64_emulator: EmulatorArtifact | None = None,
    arm64_binfmt: BinfmtRegistration | None = None,
    arm64_binfmt_error: str | None = None,
) -> dict[str, object]:
    slug = platform_slug(spec)
    use_emulator = (
        spec.architecture == "arm64"
        and normalize_host_architecture(host_architecture) != "arm64"
        and arm64_emulator is not None
        and arm64_binfmt is not None
    )
    active_emulator = arm64_emulator if use_emulator else None
    platform_result: dict[str, object] = {
        "name": spec.name,
        "distribution": spec.distribution,
        "family": spec.family,
        "architecture": ARCHITECTURE_LABELS[spec.architecture],
        "architecture_id": spec.architecture,
        "package_architecture": spec.package_architecture,
        "podman_platform": spec.podman_platform,
        "image": spec.image,
        "purge_semantics": spec.purge_semantics,
        "candidate_version": pair.candidate.version,
        "previous_version": pair.previous.version,
        "candidate": {
            "filename": pair.candidate.path.name,
            "version": pair.candidate.version,
            "sha256": pair.candidate.sha256,
        },
        "previous": {
            "filename": pair.previous.path.name,
            "version": pair.previous.version,
            "sha256": pair.previous.sha256,
        },
        "package_bytes_differ": pair.candidate.sha256 != pair.previous.sha256,
        "bootstrap_execution": (
            "podman_platform_with_validated_host_binfmt"
            if active_emulator is not None
            else "native_container_build"
        ),
        "lifecycle_network": "disabled",
        "restart_contract": (
            "upgrade-rollback performs two consecutive container restarts and "
            "revalidates native and filesystem inventories plus operator state"
        ),
        "scenarios": [],
    }
    image_tag = f"localhost/syswarden-lifecycle-{slug}-{uuid.uuid4().hex}"
    context = workspace / f"build-{slug}"
    context.mkdir(mode=0o700)
    containerfile = context / "Containerfile"
    containerfile.write_text(build_containerfile(spec), encoding="utf-8")
    containerfile.chmod(0o600)

    try:
        ensure_image(runner, podman, spec, pull_policy)
        architecture_probe = probe_platform_execution(
            runner,
            podman,
            spec,
            host_architecture,
            arm64_emulator,
            arm64_binfmt,
            arm64_binfmt_error,
        )
        platform_result["architecture_probe"] = architecture_probe
        if architecture_probe["status"] != "available":
            platform_result["status"] = "incomplete"
            platform_result["error"] = architecture_probe["reason"]
            return platform_result
        build = runner.run(
            (
                podman,
                "build",
                "--pull=never",
                "--layers=false",
                "--platform",
                spec.podman_platform,
                "--tag",
                image_tag,
                "--file",
                str(containerfile),
                str(context),
            ),
            timeout=900,
        )
        require_success(build, f"bootstrap {spec.name} lifecycle image")

        script_path = workspace / "package-lifecycle.sh"
        for scenario in spec.scenarios:
            result_root = workspace / f"result-{slug}-{scenario}"
            result_root.mkdir(mode=0o700)
            container_name = (
                f"syswarden-lifecycle-{slug}-{uuid.uuid4().hex[:12]}"
            )
            run_args = container_run_arguments(
                podman,
                image_tag,
                container_name,
                candidate_root,
                previous_root,
                script_path,
                result_root,
                spec,
                scenario,
                pair,
            )
            try:
                created = runner.run(run_args, timeout=60)
                require_success(created, f"create {spec.name} {scenario} container")
                required_starts = 3 if scenario == "upgrade-rollback" else 1
                starts: list[CommandResult] = []
                for _invocation in range(required_starts):
                    started = runner.run(
                        (podman, "start", "--attach", container_name),
                        timeout=timeout,
                    )
                    starts.append(started)
                    if started.returncode != 0:
                        restart_state = result_root / "restart-state"
                        may_continue_complete_failure_evidence = (
                            scenario == "upgrade-rollback"
                            and restart_state.is_file()
                            and restart_state.read_text(encoding="utf-8").strip()
                            in {"restart-one", "restart-two"}
                        )
                        if not may_continue_complete_failure_evidence:
                            break
            finally:
                runner.run((podman, "rm", "--force", container_name), timeout=30)

            event_file = result_root / "events.tsv"
            command_log = result_root / "commands.log"
            try:
                events = parse_events(event_file)
                validate_event_contract(events, spec.family, scenario)
                inventory_evidence = parse_scenario_inventory_evidence(
                    result_root, spec.family, scenario
                )
            except LifecycleLabError as exc:
                inventory_evidence = {}
                events = [
                    {
                        "status": "fail",
                        "check": f"{scenario}.evidence",
                        "detail": str(exc),
                    }
                ]
            failed = [event for event in events if event["status"] == "fail"]
            start_exit_codes = [item.returncode for item in starts]
            scenario_status = (
                "pass"
                if len(starts) == required_starts
                and all(code == 0 for code in start_exit_codes)
                and not failed
                else "fail"
            )
            last_start = starts[-1] if starts else created
            platform_result["scenarios"].append(
                {
                    "name": scenario,
                    "status": scenario_status,
                    "container_exit_code": last_start.returncode,
                    "container_start_exit_codes": start_exit_codes,
                    "container_restart_count": max(0, len(starts) - 1),
                    "events": events,
                    "inventory_evidence": inventory_evidence,
                    "log_tail": command_log_tail(last_start, command_log),
                }
            )
    except LifecycleLabError as exc:
        platform_result["status"] = "fail"
        platform_result["error"] = str(exc)
        return platform_result
    finally:
        runner.run((podman, "image", "rm", "--force", image_tag), timeout=120)

    scenarios = platform_result["scenarios"]
    platform_result["status"] = (
        "pass"
        if scenarios and all(item["status"] == "pass" for item in scenarios)
        else "fail"
    )
    return platform_result


def coverage_status(
    results: Sequence[dict[str, object]], expected_count: int
) -> str:
    if any(result.get("status") == "fail" for result in results):
        return "fail"
    if len(results) != expected_count or any(
        result.get("status") == "incomplete" for result in results
    ):
        return "incomplete"
    if results and all(result.get("status") == "pass" for result in results):
        return "pass"
    return "incomplete"


def forward_only_apk_report_contract(
    platform_result: dict[str, object],
) -> tuple[bool, list[str]]:
    if platform_result.get("family") != "apk":
        return False, []
    package_architecture = platform_result.get("package_architecture")
    if package_architecture not in FORWARD_ONLY_APK_PREVIOUS:
        return False, ["forward-only-apk-architecture-invalid"]
    previous = platform_result.get("previous")
    candidate = platform_result.get("candidate")
    if not isinstance(previous, dict) or not isinstance(candidate, dict):
        return False, ["forward-only-apk-artifact-binding-absent"]
    expected = FORWARD_ONLY_APK_PREVIOUS[package_architecture]
    historical_binding_touched = (
        previous.get("version") == FORWARD_ONLY_APK_PREVIOUS_VERSION
        or previous.get("filename") == expected["filename"]
        or previous.get("sha256") == expected["sha256"]
    )
    exact = (
        historical_binding_touched
        and previous
        == {
            "filename": expected["filename"],
            "version": FORWARD_ONLY_APK_PREVIOUS_VERSION,
            "sha256": expected["sha256"],
        }
        and candidate.get("version") == FORWARD_ONLY_APK_CANDIDATE_VERSION
        and candidate.get("filename")
        == f"syswarden_{FORWARD_ONLY_APK_CANDIDATE_VERSION}_{package_architecture}.apk"
        and platform_result.get("previous_version")
        == FORWARD_ONLY_APK_PREVIOUS_VERSION
        and platform_result.get("candidate_version")
        == FORWARD_ONLY_APK_CANDIDATE_VERSION
    )
    if historical_binding_touched and not exact:
        return False, ["forward-only-apk-binding-not-exact"]
    return exact, []


def validate_forward_only_apk_events(
    platform_result: dict[str, object], scenario_result: dict[str, object]
) -> list[str]:
    exact, problems = forward_only_apk_report_contract(platform_result)
    if problems or not exact or scenario_result.get("name") != "upgrade-rollback":
        return problems
    expected_details = {
        "upgrade-rollback.previous.executable": (
            "historical glibc loader refusal matched exit code 127"
        ),
        "upgrade-rollback.previous.elf_contract": (
            "historical payload matched DYN plus exact glibc PT_INTERP failure class"
        ),
        "upgrade-rollback.rollback.executable": (
            "historical glibc loader refusal matched exit code 127"
        ),
        "upgrade-rollback.rollback.elf_contract": (
            "historical payload matched DYN plus exact glibc PT_INTERP failure class"
        ),
        "upgrade-rollback.recovery.candidate": "command completed",
        "upgrade-rollback.recovery.candidate.maintainer_script": (
            "maintainer script emitted no Go panic or fatal runtime diagnostic"
        ),
    }
    events = scenario_result.get("events")
    if not isinstance(events, list):
        return ["forward-only-apk-events-absent"]
    by_check = {
        item.get("check"): item
        for item in events
        if isinstance(item, dict) and isinstance(item.get("check"), str)
    }
    return [
        f"forward-only-apk-evidence-mismatch:{check}"
        for check, detail in expected_details.items()
        if by_check.get(check)
        != {"status": "pass", "check": check, "detail": detail}
    ]


def classify_lifecycle_evidence(
    results: Sequence[dict[str, object]],
    *,
    required_platform_coordinates: frozenset[tuple[str, str]] = REQUIRED_PLATFORM_COORDINATES,
) -> dict[str, object]:
    """Recompute release readiness without a generic product waiver."""

    if (
        not required_platform_coordinates
        or not required_platform_coordinates.issubset(REQUIRED_PLATFORM_COORDINATES)
    ):
        raise LifecycleLabError("required platform coordinate contract is invalid")

    structural_failures: list[str] = []
    results_by_coordinate = {
        (str(result.get("distribution")), str(result.get("architecture_id"))): result
        for result in results
    }
    if len(results_by_coordinate) != len(results):
        structural_failures.append("matrix:duplicate-platform-coordinate")
    for distribution, architecture in sorted(
        set(results_by_coordinate) - required_platform_coordinates
    ):
        structural_failures.append(
            f"matrix:unexpected-platform-coordinate:{distribution}/{architecture}"
        )
    observed_failures: dict[str, str] = {}
    coordinate_classification: list[dict[str, object]] = []

    for distribution, architecture in sorted(required_platform_coordinates):
        coordinate_name = f"{distribution}/{architecture}"
        platform_result = results_by_coordinate.get((distribution, architecture))
        coordinate_structural: list[str] = []
        coordinate_failures: dict[str, str] = {}
        if platform_result is None:
            coordinate_structural.append(f"{coordinate_name}:platform-result-missing")
            family = next(
                spec.family
                for spec in DEFAULT_PLATFORMS
                if platform_coordinate(spec) == (distribution, architecture)
            )
        else:
            family = str(platform_result.get("family"))
            _, binding_problems = forward_only_apk_report_contract(platform_result)
            coordinate_structural.extend(
                f"{coordinate_name}:{problem}" for problem in binding_problems
            )
            scenarios = platform_result.get("scenarios")
            if not isinstance(scenarios, list) or [
                item.get("name") if isinstance(item, dict) else None
                for item in scenarios
            ] != list(EXPECTED_SCENARIOS.get(family, ())):
                coordinate_structural.append(
                    f"{coordinate_name}:scenario-contract-incomplete"
                )
                scenarios = [] if not isinstance(scenarios, list) else scenarios
            for scenario_result in scenarios:
                if not isinstance(scenario_result, dict):
                    coordinate_structural.append(
                        f"{coordinate_name}:scenario-result-invalid"
                    )
                    continue
                scenario_name = scenario_result.get("name")
                if not isinstance(scenario_name, str):
                    coordinate_structural.append(
                        f"{coordinate_name}:scenario-name-invalid"
                    )
                    continue
                required_starts = 3 if scenario_name == "upgrade-rollback" else 1
                start_codes = scenario_result.get("container_start_exit_codes")
                if (
                    not isinstance(start_codes, list)
                    or len(start_codes) != required_starts
                    or any(type(code) is not int for code in start_codes)
                    or scenario_result.get("container_restart_count")
                    != required_starts - 1
                ):
                    coordinate_structural.append(
                        f"{coordinate_name}:{scenario_name}:restart-evidence-incomplete"
                    )
                events = scenario_result.get("events")
                try:
                    if not isinstance(events, list):
                        raise LifecycleLabError("scenario event list is absent")
                    validate_event_contract(events, family, scenario_name)
                except LifecycleLabError:
                    coordinate_structural.append(
                        f"{coordinate_name}:{scenario_name}:event-contract-invalid"
                    )
                    continue
                coordinate_structural.extend(
                    f"{coordinate_name}:{scenario_name}:{problem}"
                    for problem in validate_forward_only_apk_events(
                        platform_result, scenario_result
                    )
                )
                try:
                    validate_scenario_inventory_evidence(
                        scenario_result.get("inventory_evidence"),
                        family,
                        scenario_name,
                    )
                except LifecycleLabError:
                    coordinate_structural.append(
                        f"{coordinate_name}:{scenario_name}:inventory-evidence-invalid"
                    )
                scenario_failed_events = [
                    event for event in events if event["status"] == "fail"
                ]
                if isinstance(start_codes, list) and len(start_codes) == required_starts:
                    if scenario_result.get("container_exit_code") != start_codes[-1]:
                        coordinate_structural.append(
                            f"{coordinate_name}:{scenario_name}:container-exit-inconsistent"
                        )
                    if not scenario_failed_events and any(
                        code != 0 for code in start_codes
                    ):
                        coordinate_structural.append(
                            f"{coordinate_name}:{scenario_name}:unexpected-container-exit"
                        )
                    if scenario_failed_events and start_codes[-1] == 0:
                        coordinate_structural.append(
                            f"{coordinate_name}:{scenario_name}:failure-exit-inconsistent"
                        )
                    derived_scenario_status = (
                        "pass"
                        if not scenario_failed_events
                        and all(code == 0 for code in start_codes)
                        else "fail"
                    )
                    if scenario_result.get("status") != derived_scenario_status:
                        coordinate_structural.append(
                            f"{coordinate_name}:{scenario_name}:scenario-status-inconsistent"
                        )
                for event in events:
                    if event["status"] == "fail":
                        identifier = f"{coordinate_name}:{event['check']}"
                        coordinate_failures[identifier] = event["detail"]
            if isinstance(scenarios, list) and scenarios:
                derived_platform_status = (
                    "pass"
                    if all(
                        isinstance(item, dict) and item.get("status") == "pass"
                        for item in scenarios
                    )
                    else "fail"
                )
                if platform_result.get("status") != derived_platform_status:
                    coordinate_structural.append(
                        f"{coordinate_name}:platform-status-inconsistent"
                    )

        structural_failures.extend(coordinate_structural)
        observed_failures.update(coordinate_failures)
        if not coordinate_structural and not coordinate_failures:
            coordinate_status = "pass"
        else:
            coordinate_status = "incomplete"
        coordinate_classification.append(
            {
                "distribution": distribution,
                "architecture_id": architecture,
                "family": family,
                "status": coordinate_status,
                "blocker_ids": [],
            }
        )
    unexpected_failed_checks = sorted(
        set(structural_failures) | set(observed_failures)
    )
    every_check_passed = not unexpected_failed_checks and not observed_failures
    harness_complete = (
        every_check_passed
        and len(results_by_coordinate) == len(required_platform_coordinates)
    )
    release_ready = harness_complete and every_check_passed
    return {
        "harness_complete": harness_complete,
        "release_ready": release_ready,
        "blocker_ids": [],
        "unexpected_failed_checks": unexpected_failed_checks,
        "coordinate_classification": coordinate_classification,
    }


def validate_report_version_contract(
    report: dict[str, object],
    *,
    required_platform_coordinates: frozenset[tuple[str, str]] = REQUIRED_PLATFORM_COORDINATES,
) -> None:
    """Reject a report whose artifact-version evidence is incomplete or mutable."""

    schema_version = report.get("schema_version")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise LifecycleLabError(
            f"package lifecycle report schema must be {SCHEMA_VERSION}"
        )
    contract = report.get("package_version_contract")
    if not isinstance(contract, dict):
        raise LifecycleLabError("package lifecycle report lacks a version contract")
    if contract.get("scheme") != VERSION_SCHEME:
        raise LifecycleLabError("package lifecycle report has an invalid version scheme")
    if contract.get("relation") != VERSION_RELATION:
        raise LifecycleLabError("package lifecycle report has an invalid version relation")

    previous_version = contract.get("previous_version")
    candidate_version = contract.get("candidate_version")
    if not isinstance(previous_version, str) or not isinstance(candidate_version, str):
        raise LifecycleLabError("package lifecycle report versions must be strings")
    previous_numeric = parse_syswarden_version(previous_version)
    candidate_numeric = parse_syswarden_version(candidate_version)
    if previous_version == candidate_version or previous_numeric >= candidate_numeric:
        raise LifecycleLabError(
            "package lifecycle report does not prove previous < candidate"
        )
    reported_previous_numeric = contract.get("previous_numeric")
    if (
        not isinstance(reported_previous_numeric, list)
        or any(type(part) is not int for part in reported_previous_numeric)
        or reported_previous_numeric != list(previous_numeric)
    ):
        raise LifecycleLabError(
            "package lifecycle report previous numeric version is inconsistent"
        )
    reported_candidate_numeric = contract.get("candidate_numeric")
    if (
        not isinstance(reported_candidate_numeric, list)
        or any(type(part) is not int for part in reported_candidate_numeric)
        or reported_candidate_numeric != list(candidate_numeric)
    ):
        raise LifecycleLabError(
            "package lifecycle report candidate numeric version is inconsistent"
        )

    platforms = report.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise LifecycleLabError("package lifecycle report has no platform results")
    expected_coordinates: set[str] = set()
    for platform_result in platforms:
        if not isinstance(platform_result, dict):
            raise LifecycleLabError("package lifecycle platform result must be an object")
        family = platform_result.get("family")
        package_architecture = platform_result.get("package_architecture")
        if not isinstance(family, str) or not isinstance(package_architecture, str):
            raise LifecycleLabError(
                "package lifecycle platform result lacks its package coordinate"
            )
        if family not in EXPECTED_SCENARIOS:
            raise LifecycleLabError(
                "package lifecycle platform result has an unsupported family"
            )
        scenarios = platform_result.get("scenarios")
        if platform_result.get("status") == "pass":
            if not isinstance(scenarios, list) or [
                item.get("name") if isinstance(item, dict) else None
                for item in scenarios
            ] != list(EXPECTED_SCENARIOS[family]):
                raise LifecycleLabError(
                    "passing package lifecycle platform has an incomplete or "
                    "reordered scenario contract"
                )
            for scenario_result in scenarios:
                if not isinstance(scenario_result, dict):
                    raise LifecycleLabError(
                        "package lifecycle scenario result must be an object"
                    )
                scenario_name = scenario_result["name"]
                required_starts = 3 if scenario_name == "upgrade-rollback" else 1
                if (
                    scenario_result.get("status") != "pass"
                    or scenario_result.get("container_start_exit_codes")
                    != [0] * required_starts
                    or scenario_result.get("container_restart_count")
                    != required_starts - 1
                    or scenario_result.get("container_exit_code") != 0
                ):
                    raise LifecycleLabError(
                        "passing package lifecycle scenario lacks its exact "
                        "container restart evidence"
                    )
                scenario_events = scenario_result.get("events")
                if not isinstance(scenario_events, list):
                    raise LifecycleLabError(
                        "package lifecycle scenario lacks event evidence"
                    )
                validate_event_contract(scenario_events, family, scenario_name)
        expected_coordinates.add(f"{family}:{package_architecture}")
        candidate = platform_result.get("candidate")
        previous = platform_result.get("previous")
        if not isinstance(candidate, dict) or not isinstance(previous, dict):
            raise LifecycleLabError(
                "package lifecycle platform result lacks artifact evidence"
            )
        candidate_filename = candidate.get("filename")
        previous_filename = previous.get("filename")
        coordinate = f"{family}:{package_architecture}"
        coordinate_pattern = PACKAGE_COORDINATE_PATTERNS.get(coordinate)
        if (
            coordinate_pattern is None
            or not isinstance(candidate_filename, str)
            or re.fullmatch(coordinate_pattern, candidate_filename) is None
            or artifact_version(candidate_filename) != candidate_version
            or not isinstance(previous_filename, str)
            or re.fullmatch(coordinate_pattern, previous_filename) is None
            or artifact_version(previous_filename) != previous_version
        ):
            raise LifecycleLabError(
                "package lifecycle platform filename/version evidence is inconsistent"
            )
        if (
            platform_result.get("candidate_version") != candidate_version
            or candidate.get("version") != candidate_version
        ):
            raise LifecycleLabError(
                "package lifecycle platform candidate version is inconsistent"
            )
        if (
            platform_result.get("previous_version") != previous_version
            or previous.get("version") != previous_version
        ):
            raise LifecycleLabError(
                "package lifecycle platform previous version is inconsistent"
            )
    engine = report.get("engine")
    if not isinstance(engine, dict):
        raise LifecycleLabError("package lifecycle report lacks engine evidence")
    emulator_report = engine.get("arm64_emulator")
    if emulator_report is not None:
        if (
            not isinstance(emulator_report, dict)
            or not isinstance(emulator_report.get("path"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(emulator_report.get("sha256"))
            )
            or emulator_report.get("regular_file") is not True
            or emulator_report.get("executable") is not True
            or emulator_report.get("symlink") is not False
            or emulator_report.get("role") != "host binfmt interpreter"
        ):
            raise LifecycleLabError(
                "package lifecycle report has invalid arm64 emulator evidence"
            )
    binfmt_report = engine.get("arm64_binfmt")
    if binfmt_report is not None:
        if (
            not isinstance(binfmt_report, dict)
            or not isinstance(binfmt_report.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(binfmt_report.get("sha256")))
            or not isinstance(binfmt_report.get("interpreter"), str)
            or not isinstance(binfmt_report.get("flags"), str)
            or "F" not in str(binfmt_report.get("flags"))
            or not isinstance(emulator_report, dict)
            or binfmt_report.get("interpreter") != emulator_report.get("path")
        ):
            raise LifecycleLabError(
                "package lifecycle report has invalid arm64 binfmt evidence"
            )
    for platform_result in platforms:
        architecture_probe = platform_result.get("architecture_probe")
        if not isinstance(architecture_probe, dict):
            continue
        if architecture_probe.get("execution_mode") != "host_binfmt_qemu_aarch64":
            continue
        probe_emulator = architecture_probe.get("emulator")
        probe_binfmt = architecture_probe.get("binfmt")
        if (
            not isinstance(emulator_report, dict)
            or not isinstance(probe_emulator, dict)
            or not isinstance(binfmt_report, dict)
            or not isinstance(probe_binfmt, dict)
            or probe_emulator.get("path") != emulator_report.get("path")
            or probe_emulator.get("sha256") != emulator_report.get("sha256")
            or probe_emulator.get("role") != "host binfmt interpreter"
            or probe_binfmt != binfmt_report
        ):
            raise LifecycleLabError(
                "package lifecycle arm64 probe/binfmt evidence is inconsistent"
            )
    if not expected_coordinates.issubset(REQUIRED_PACKAGE_COORDINATES):
        raise LifecycleLabError(
            "package lifecycle report contains an unsupported package coordinate"
        )

    coordinates = contract.get("coordinates")
    if not isinstance(coordinates, list) or not coordinates:
        raise LifecycleLabError(
            "package lifecycle report version coordinates are empty"
        )
    observed_coordinates: set[str] = set()
    for coordinate_result in coordinates:
        if not isinstance(coordinate_result, dict):
            raise LifecycleLabError(
                "package lifecycle report version coordinate must be an object"
            )
        coordinate = coordinate_result.get("coordinate")
        family = coordinate_result.get("family")
        package_architecture = coordinate_result.get("package_architecture")
        if (
            not isinstance(coordinate, str)
            or not isinstance(family, str)
            or not isinstance(package_architecture, str)
            or coordinate != f"{family}:{package_architecture}"
            or coordinate in observed_coordinates
        ):
            raise LifecycleLabError(
                "package lifecycle report contains an invalid or duplicate version coordinate"
            )
        observed_coordinates.add(coordinate)
        coordinate_previous_numeric = coordinate_result.get("previous_numeric")
        coordinate_candidate_numeric = coordinate_result.get("candidate_numeric")
        if (
            coordinate_result.get("previous_version") != previous_version
            or coordinate_result.get("candidate_version") != candidate_version
            or not isinstance(coordinate_previous_numeric, list)
            or any(type(part) is not int for part in coordinate_previous_numeric)
            or coordinate_previous_numeric != list(previous_numeric)
            or not isinstance(coordinate_candidate_numeric, list)
            or any(type(part) is not int for part in coordinate_candidate_numeric)
            or coordinate_candidate_numeric != list(candidate_numeric)
        ):
            raise LifecycleLabError(
                f"package lifecycle report version mismatch at {coordinate}"
            )
    if observed_coordinates != expected_coordinates:
        raise LifecycleLabError(
            "package lifecycle report version coordinates do not cover its platforms"
        )
    classification = classify_lifecycle_evidence(
        platforms,
        required_platform_coordinates=required_platform_coordinates,
    )
    for key in (
        "harness_complete",
        "release_ready",
        "blocker_ids",
        "unexpected_failed_checks",
    ):
        if report.get(key) != classification[key]:
            raise LifecycleLabError(
                f"package lifecycle report {key} classification is inconsistent"
            )
    scope = report.get("scope")
    if (
        not isinstance(scope, dict)
        or scope.get("coordinate_classification")
        != classification["coordinate_classification"]
        or scope.get("container_lab_complete")
        != (report.get("status") == "pass")
    ):
        raise LifecycleLabError(
            "package lifecycle report coordinate classification is inconsistent"
        )
    if (report.get("status") == "pass") != classification["release_ready"]:
        raise LifecycleLabError(
            "package lifecycle report status/release classification is inconsistent"
        )


def _positive_identifier(value: object, label: str) -> int:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return int(value)
    raise LifecycleLabError(f"{label} must be a positive canonical integer")


def _manifest_sha256(root: Path, label: str) -> str:
    path = root / "SHA256SUMS.txt"
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LifecycleLabError(f"{label} must be a regular non-symlink file")
    return sha256_file(path)


def validate_qualification_binding(
    value: object,
    *,
    expected: dict[str, object] | None = None,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != QUALIFICATION_BINDING_KEYS:
        raise LifecycleLabError("qualification binding schema is not exact")
    binding = dict(value)
    if type(binding["schema_version"]) is not int or binding["schema_version"] != 1:
        raise LifecycleLabError("qualification binding schema version must be 1")
    repository = binding["repository"]
    if not isinstance(repository, str) or re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ) is None:
        raise LifecycleLabError("qualification repository is not canonical")
    release_sha = binding["release_sha"]
    if not isinstance(release_sha, str) or re.fullmatch(
        r"[0-9a-f]{40}", release_sha
    ) is None:
        raise LifecycleLabError("qualification release SHA is not canonical")
    for key in ("release_tag", "previous_tag"):
        tag = binding[key]
        if not isinstance(tag, str) or re.fullmatch(
            r"v[0-9]+\.[0-9]{2}\.[0-9]+", tag
        ) is None:
            raise LifecycleLabError(f"qualification {key} is not canonical")
    if binding["release_tag"] == binding["previous_tag"]:
        raise LifecycleLabError("qualification release and previous tags must differ")
    artifact_name = binding["candidate_artifact_name"]
    if not isinstance(artifact_name, str) or artifact_name != (
        "syswarden-packages-" + str(binding["release_tag"]).removeprefix("v")
    ):
        raise LifecycleLabError("qualification candidate artifact name is invalid")
    for key in (
        "workflow_run_id",
        "workflow_run_attempt",
        "candidate_run_id",
        "candidate_artifact_id",
        "previous_release_id",
    ):
        if type(binding[key]) is not int or binding[key] <= 0:
            raise LifecycleLabError(
                f"qualification {key} must be a positive JSON integer"
            )
    for key in ("candidate_manifest_sha256", "previous_manifest_sha256"):
        digest = binding[key]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LifecycleLabError(f"qualification {key} is not a SHA-256 digest")
    if expected is not None and binding != expected:
        raise LifecycleLabError("qualification binding differs from the expected inputs")
    return binding


def build_qualification_binding(
    args: argparse.Namespace,
    candidate_root: Path,
    previous_root: Path,
    version_contract: dict[str, object],
) -> dict[str, object]:
    binding = {
        "schema_version": 1,
        "repository": getattr(args, "qualification_repository", None),
        "release_sha": getattr(args, "qualification_release_sha", None),
        "release_tag": getattr(args, "qualification_release_tag", None),
        "previous_tag": getattr(args, "qualification_previous_tag", None),
        "workflow_run_id": _positive_identifier(
            getattr(args, "qualification_workflow_run_id", None),
            "qualification workflow_run_id",
        ),
        "workflow_run_attempt": _positive_identifier(
            getattr(args, "qualification_workflow_run_attempt", None),
            "qualification workflow_run_attempt",
        ),
        "candidate_run_id": _positive_identifier(
            getattr(args, "qualification_candidate_run_id", None),
            "qualification candidate_run_id",
        ),
        "candidate_artifact_id": _positive_identifier(
            getattr(args, "qualification_candidate_artifact_id", None),
            "qualification candidate_artifact_id",
        ),
        "candidate_artifact_name": getattr(
            args, "qualification_candidate_artifact_name", None
        ),
        "previous_release_id": _positive_identifier(
            getattr(args, "qualification_previous_release_id", None),
            "qualification previous_release_id",
        ),
        "candidate_manifest_sha256": _manifest_sha256(
            candidate_root, "candidate checksum manifest"
        ),
        "previous_manifest_sha256": _manifest_sha256(
            previous_root, "previous checksum manifest"
        ),
    }
    validated = validate_qualification_binding(binding)
    if validated["release_tag"] != "v" + str(version_contract["candidate_version"]):
        raise LifecycleLabError(
            "qualification release tag differs from candidate package versions"
        )
    if validated["previous_tag"] != "v" + str(version_contract["previous_version"]):
        raise LifecycleLabError(
            "qualification previous tag differs from previous package versions"
        )
    return validated


def run_lab(
    args: argparse.Namespace,
    *,
    runner: CommandRunner | None = None,
    platforms: Sequence[PlatformSpec] = DEFAULT_PLATFORMS,
    host_architecture: str | None = None,
) -> dict[str, object]:
    active_runner = runner or CommandRunner()
    architecture_shard = getattr(args, "architecture_shard", None)
    required_platform_coordinates = (
        required_coordinates_for_architecture(architecture_shard)
        if architecture_shard is not None
        else REQUIRED_PLATFORM_COORDINATES
    )
    observed_platform_coordinates = frozenset(
        platform_coordinate(spec) for spec in platforms
    )
    if architecture_shard is not None and (
        observed_platform_coordinates != required_platform_coordinates
        or len(platforms) != len(required_platform_coordinates)
    ):
        raise LifecycleLabError(
            f"{architecture_shard} shard must contain its exact five platform coordinates"
        )
    candidate_root, previous_root, pairs = validate_inputs(
        args.packages_dir, args.previous_packages_dir, platforms
    )
    actual_host_architecture = host_architecture or platform.machine()
    normalized_host = normalize_host_architecture(actual_host_architecture)
    if architecture_shard is not None and normalized_host != architecture_shard:
        raise LifecycleLabError(
            f"{architecture_shard} shard requires a native {architecture_shard} host"
        )
    if architecture_shard is not None and getattr(args, "arm64_emulator", None) is not None:
        raise LifecycleLabError("native architecture shards forbid ARM64 emulation")
    arm64_emulator = validate_arm64_emulator(
        getattr(args, "arm64_emulator", None)
    )
    arm64_binfmt: BinfmtRegistration | None = None
    arm64_binfmt_error: str | None = None
    if (
        normalize_host_architecture(actual_host_architecture) != "arm64"
        and arm64_emulator is not None
    ):
        registration_path = getattr(
            args, "_arm64_binfmt_registration", ARM64_BINFMT_REGISTRATION
        )
        try:
            arm64_binfmt = validate_arm64_binfmt(
                arm64_emulator, registration_path
            )
        except LifecycleLabError as exc:
            arm64_binfmt_error = str(exc)
    podman_version = ensure_rootless_podman(active_runner, args.podman)

    with tempfile.TemporaryDirectory(prefix="syswarden-package-lifecycle-") as raw:
        workspace = Path(raw)
        script_path = workspace / "package-lifecycle.sh"
        script_path.write_text(LIFECYCLE_SCRIPT, encoding="utf-8")
        script_path.chmod(0o500)

        platform_results = [
            run_platform(
                active_runner,
                args.podman,
                spec,
                pairs[package_coordinate(spec)],
                candidate_root,
                previous_root,
                workspace,
                args.pull_policy,
                args.scenario_timeout,
                actual_host_architecture,
                arm64_emulator,
                arm64_binfmt,
                arm64_binfmt_error,
            )
            for spec in platforms
        ]

    if arm64_emulator is not None:
        final_emulator = validate_arm64_emulator(arm64_emulator.path)
        if final_emulator is None or final_emulator.sha256 != arm64_emulator.sha256:
            raise LifecycleLabError(
                "arm64 emulator changed while lifecycle evidence was being collected"
            )
    if arm64_binfmt is not None and arm64_emulator is not None:
        final_binfmt = validate_arm64_binfmt(
            arm64_emulator, arm64_binfmt.path
        )
        if final_binfmt != arm64_binfmt:
            raise LifecycleLabError(
                "arm64 binfmt registration changed while lifecycle evidence was "
                "being collected"
            )

    results_by_coordinate = {
        (str(result["distribution"]), str(result["architecture_id"])): result
        for result in platform_results
    }
    missing_coordinates = sorted(
        required_platform_coordinates - set(results_by_coordinate)
    )
    architecture_coverage: list[dict[str, object]] = []
    for architecture in sorted({item[1] for item in required_platform_coordinates}):
        expected = sorted(
            coordinate
            for coordinate in required_platform_coordinates
            if coordinate[1] == architecture
        )
        present = [
            results_by_coordinate[coordinate]
            for coordinate in expected
            if coordinate in results_by_coordinate
        ]
        status = coverage_status(present, len(expected))
        architecture_coverage.append(
            {
                "architecture": ARCHITECTURE_LABELS[architecture],
                "architecture_id": architecture,
                "status": status,
                "required_distributions": [item[0] for item in expected],
                "completed_distributions": sorted(
                    str(result["distribution"])
                    for result in present
                    if result["status"] == "pass"
                ),
                "incomplete_or_failed_distributions": sorted(
                    str(result["distribution"])
                    for result in present
                    if result["status"] != "pass"
                ),
            }
        )

    family_architecture_coverage: list[dict[str, object]] = []
    for architecture in sorted({item[1] for item in required_platform_coordinates}):
        for family in REQUIRED_FAMILIES:
            expected_specs = [
                spec
                for spec in DEFAULT_PLATFORMS
                if spec.architecture == architecture
                and spec.family == family
                and platform_coordinate(spec) in required_platform_coordinates
            ]
            present = [
                results_by_coordinate[platform_coordinate(spec)]
                for spec in expected_specs
                if platform_coordinate(spec) in results_by_coordinate
            ]
            family_architecture_coverage.append(
                {
                    "family": family,
                    "architecture": ARCHITECTURE_LABELS[architecture],
                    "architecture_id": architecture,
                    "status": coverage_status(present, len(expected_specs)),
                    "required_distributions": [
                        spec.distribution for spec in expected_specs
                    ],
                    "completed_distributions": sorted(
                        str(result["distribution"])
                        for result in present
                        if result["status"] == "pass"
                    ),
                }
            )

    if any(result["status"] == "fail" for result in platform_results):
        container_status = "fail"
    elif missing_coordinates or any(
        result["status"] == "incomplete" for result in platform_results
    ):
        container_status = "incomplete"
    elif set(results_by_coordinate) != required_platform_coordinates:
        container_status = "incomplete"
    elif platform_results and all(
        result["status"] == "pass" for result in platform_results
    ):
        container_status = "pass"
    else:
        container_status = "incomplete"

    completed_architectures = [
        item["architecture"]
        for item in architecture_coverage
        if item["status"] == "pass"
    ]
    incomplete_architectures = [
        {
            "architecture": item["architecture"],
            "status": item["status"],
            "reason": "not every required distribution completed every lifecycle scenario",
        }
        for item in architecture_coverage
        if item["status"] != "pass"
    ]
    classification = classify_lifecycle_evidence(
        platform_results,
        required_platform_coordinates=required_platform_coordinates,
    )
    version_contract = build_package_version_contract(pairs)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": container_status,
        "harness_complete": classification["harness_complete"],
        "release_ready": classification["release_ready"],
        "blocker_ids": classification["blocker_ids"],
        "unexpected_failed_checks": classification[
            "unexpected_failed_checks"
        ],
        "package_version_contract": version_contract,
        "scope": {
            "container_lab_complete": container_status == "pass",
            "coordinate_classification": classification[
                "coordinate_classification"
            ],
            "host_architecture": actual_host_architecture,
            "network_during_image_bootstrap": "rootless Podman default",
            "network_during_package_operations": "disabled",
            "host_mutation": "bounded to rootless Podman storage and a temporary workdir",
            "architectures_completed": completed_architectures,
            "architectures_incomplete_or_failed": incomplete_architectures,
            "architecture_coverage": architecture_coverage,
            "family_architecture_coverage": family_architecture_coverage,
            "required_platform_coordinates": [
                {"distribution": distribution, "architecture": architecture}
                for distribution, architecture in sorted(required_platform_coordinates)
            ],
            "missing_platform_coordinates": [
                {"distribution": distribution, "architecture": architecture}
                for distribution, architecture in missing_coordinates
            ],
            "arm64_coverage_policy": (
                "qualification shards require native execution on matching amd64 "
                "and arm64 hosts and forbid emulation"
                if architecture_shard is not None
                else (
                    "arm64/aarch64 is complete only after each DEB, RPM, and APK "
                    "distribution variant executes natively or through a validated "
                    "persistent host binfmt registration whose interpreter exactly "
                    "matches the checksum-recorded --arm64-emulator"
                )
            ),
            "rollback_model": (
                "external package-manager downgrade to the separately supplied, "
                "checksum-verified previous artifact; this is not a SysWarden "
                "product rollback feature"
            ),
        },
        "engine": {
            "name": "podman",
            "version": podman_version,
            "rootless": True,
            "arm64_emulator": (
                {
                    "path": str(arm64_emulator.path),
                    "sha256": arm64_emulator.sha256,
                    "regular_file": True,
                    "executable": True,
                    "symlink": False,
                    "role": "host binfmt interpreter",
                }
                if arm64_emulator is not None
                else None
            ),
            "arm64_binfmt": (
                {
                    "path": str(arm64_binfmt.path),
                    "sha256": arm64_binfmt.sha256,
                    "interpreter": arm64_binfmt.interpreter,
                    "flags": arm64_binfmt.flags,
                }
                if arm64_binfmt is not None
                else None
            ),
        },
        "package_roots": {
            "candidate": str(candidate_root),
            "previous": str(previous_root),
            "mount_mode": "read-only",
        },
        "platforms": platform_results,
    }
    if architecture_shard is not None:
        report["qualification_binding"] = build_qualification_binding(
            args,
            candidate_root,
            previous_root,
            version_contract,
        )
        report["native_shard"] = {
            "schema_version": 1,
            "architecture": architecture_shard,
        }
    validate_report_version_contract(
        report,
        required_platform_coordinates=required_platform_coordinates,
    )
    return report


def validate_native_shard_report(
    report: dict[str, object],
    *,
    architecture: str,
    expected_binding: dict[str, object],
) -> None:
    expected_top_keys = {
        "schema_version",
        "generated_at",
        "status",
        "harness_complete",
        "release_ready",
        "blocker_ids",
        "unexpected_failed_checks",
        "package_version_contract",
        "scope",
        "engine",
        "package_roots",
        "platforms",
        "qualification_binding",
        "native_shard",
    }
    if set(report) != expected_top_keys:
        raise LifecycleLabError("native shard report top-level schema is not exact")
    required_coordinates = required_coordinates_for_architecture(architecture)
    validate_qualification_binding(
        report.get("qualification_binding"), expected=expected_binding
    )
    native_shard = report.get("native_shard")
    if (
        not isinstance(native_shard, dict)
        or set(native_shard) != NATIVE_SHARD_KEYS
        or type(native_shard.get("schema_version")) is not int
        or native_shard.get("schema_version") != 1
        or native_shard.get("architecture") != architecture
    ):
        raise LifecycleLabError("native shard identity is invalid")
    scope = report.get("scope")
    if not isinstance(scope, dict) or normalize_host_architecture(
        str(scope.get("host_architecture", ""))
    ) != architecture:
        raise LifecycleLabError("native shard host architecture is inconsistent")
    expected_coordinates_json = [
        {"distribution": distribution, "architecture": item_architecture}
        for distribution, item_architecture in sorted(required_coordinates)
    ]
    if (
        scope.get("required_platform_coordinates") != expected_coordinates_json
        or scope.get("missing_platform_coordinates") != []
    ):
        raise LifecycleLabError("native shard platform coordinate scope is not exact")
    architecture_coverage = scope.get("architecture_coverage")
    family_coverage = scope.get("family_architecture_coverage")
    if (
        not isinstance(architecture_coverage, list)
        or len(architecture_coverage) != 1
        or not isinstance(architecture_coverage[0], dict)
        or architecture_coverage[0].get("architecture_id") != architecture
        or not isinstance(family_coverage, list)
        or len(family_coverage) != len(REQUIRED_FAMILIES)
        or {
            (item.get("family"), item.get("architecture_id"))
            for item in family_coverage
            if isinstance(item, dict)
        }
        != {(family, architecture) for family in REQUIRED_FAMILIES}
    ):
        raise LifecycleLabError("native shard coverage summary is not exact")
    engine = report.get("engine")
    if (
        not isinstance(engine, dict)
        or set(engine)
        != {"name", "version", "rootless", "arm64_emulator", "arm64_binfmt"}
        or engine.get("name") != "podman"
        or not isinstance(engine.get("version"), str)
        or not engine.get("version")
        or engine.get("rootless") is not True
        or engine.get("arm64_emulator") is not None
        or engine.get("arm64_binfmt") is not None
    ):
        raise LifecycleLabError("native shard engine evidence is invalid")
    roots = report.get("package_roots")
    if (
        not isinstance(roots, dict)
        or set(roots) != {"candidate", "previous", "mount_mode"}
        or roots.get("mount_mode") != "read-only"
        or not isinstance(roots.get("candidate"), str)
        or not Path(roots["candidate"]).is_absolute()
        or not isinstance(roots.get("previous"), str)
        or not Path(roots["previous"]).is_absolute()
        or roots["candidate"] == roots["previous"]
    ):
        raise LifecycleLabError("native shard package roots are invalid")
    platforms = report.get("platforms")
    if not isinstance(platforms, list) or len(platforms) != len(required_coordinates):
        raise LifecycleLabError("native shard platform inventory is incomplete")
    specs = {
        platform_coordinate(spec): spec
        for spec in DEFAULT_PLATFORMS
        if spec.architecture == architecture
    }
    seen: set[tuple[str, str]] = set()
    observed_order: list[tuple[str, str]] = []
    for platform_result in platforms:
        if not isinstance(platform_result, dict):
            raise LifecycleLabError("native shard platform result is invalid")
        coordinate = (
            str(platform_result.get("distribution")),
            str(platform_result.get("architecture_id")),
        )
        if coordinate in seen or coordinate not in required_coordinates:
            raise LifecycleLabError(
                "native shard platform coordinate is duplicate or unsupported"
            )
        seen.add(coordinate)
        observed_order.append(coordinate)
        spec = specs[coordinate]
        expected_platform_metadata = {
            "family": spec.family,
            "architecture": ARCHITECTURE_LABELS[spec.architecture],
            "package_architecture": spec.package_architecture,
            "podman_platform": spec.podman_platform,
            "image": spec.image,
            "lifecycle_network": "disabled",
            "bootstrap_execution": "native_container_build",
        }
        if any(
            platform_result.get(key) != value
            for key, value in expected_platform_metadata.items()
        ):
            raise LifecycleLabError(
                f"native shard platform metadata is invalid at {coordinate}"
            )
        probe = platform_result.get("architecture_probe")
        if (
            not isinstance(probe, dict)
            or set(probe)
            != {
                "status",
                "execution_mode",
                "podman_platform",
                "expected_uname",
                "actual_uname",
                "container_exit_code",
                "network",
                "filesystem",
                "emulator",
                "binfmt",
            }
            or probe.get("status") != "available"
            or probe.get("execution_mode") != "native"
            or probe.get("podman_platform") != spec.podman_platform
            or probe.get("expected_uname") != spec.uname_architecture
            or probe.get("actual_uname") != spec.uname_architecture
            or type(probe.get("container_exit_code")) is not int
            or probe.get("container_exit_code") != 0
            or probe.get("network") != "disabled"
            or probe.get("filesystem") != "read-only with bounded /tmp tmpfs"
            or probe.get("emulator") is not None
            or probe.get("binfmt") is not None
        ):
            raise LifecycleLabError(
                f"native shard execution evidence is invalid at {coordinate}"
            )
    if seen != required_coordinates:
        raise LifecycleLabError("native shard platform coordinate set is incomplete")
    expected_order = [
        platform_coordinate(spec)
        for spec in DEFAULT_PLATFORMS
        if spec.architecture == architecture
    ]
    if observed_order != expected_order:
        raise LifecycleLabError("native shard platform coordinate order is not canonical")
    validate_report_version_contract(
        report,
        required_platform_coordinates=required_coordinates,
    )


def _read_native_shard(
    path: Path,
    label: str,
) -> tuple[dict[str, object], str, tuple[int, int]]:
    absolute = path.expanduser().absolute()
    try:
        before = absolute.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LifecycleLabError(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > 64 * 1024 * 1024:
        raise LifecycleLabError(f"{label} size is invalid")
    try:
        payload = absolute.read_bytes()
        after = absolute.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot read {label}: {exc}") from exc
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(payload) != before.st_size
    ):
        raise LifecycleLabError(f"{label} changed while it was read")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise LifecycleLabError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        report = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleLabError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise LifecycleLabError(f"{label} root must be an object")
    return (
        report,
        hashlib.sha256(payload).hexdigest(),
        (before.st_dev, before.st_ino),
    )


def _aggregate_matrix_summary(
    platform_results: Sequence[dict[str, object]],
) -> tuple[str, dict[str, object], dict[str, object]]:
    results_by_coordinate = {
        (str(result.get("distribution")), str(result.get("architecture_id"))): result
        for result in platform_results
    }
    if len(results_by_coordinate) != len(platform_results):
        raise LifecycleLabError("native shard aggregate contains duplicate coordinates")
    if set(results_by_coordinate) != REQUIRED_PLATFORM_COORDINATES:
        raise LifecycleLabError("native shard aggregate platform matrix is not exact")
    architecture_coverage: list[dict[str, object]] = []
    family_architecture_coverage: list[dict[str, object]] = []
    for architecture in ARCHITECTURE_LABELS:
        expected = sorted(
            coordinate
            for coordinate in REQUIRED_PLATFORM_COORDINATES
            if coordinate[1] == architecture
        )
        present = [results_by_coordinate[coordinate] for coordinate in expected]
        architecture_coverage.append(
            {
                "architecture": ARCHITECTURE_LABELS[architecture],
                "architecture_id": architecture,
                "status": coverage_status(present, len(expected)),
                "required_distributions": [item[0] for item in expected],
                "completed_distributions": sorted(
                    str(result["distribution"])
                    for result in present
                    if result["status"] == "pass"
                ),
                "incomplete_or_failed_distributions": sorted(
                    str(result["distribution"])
                    for result in present
                    if result["status"] != "pass"
                ),
            }
        )
        for family in REQUIRED_FAMILIES:
            specs = [
                spec
                for spec in DEFAULT_PLATFORMS
                if spec.architecture == architecture and spec.family == family
            ]
            family_results = [
                results_by_coordinate[platform_coordinate(spec)] for spec in specs
            ]
            family_architecture_coverage.append(
                {
                    "family": family,
                    "architecture": ARCHITECTURE_LABELS[architecture],
                    "architecture_id": architecture,
                    "status": coverage_status(family_results, len(specs)),
                    "required_distributions": [spec.distribution for spec in specs],
                    "completed_distributions": sorted(
                        str(result["distribution"])
                        for result in family_results
                        if result["status"] == "pass"
                    ),
                }
            )
    if any(result.get("status") == "fail" for result in platform_results):
        status = "fail"
    elif any(result.get("status") != "pass" for result in platform_results):
        status = "incomplete"
    else:
        status = "pass"
    classification = classify_lifecycle_evidence(platform_results)
    scope = {
        "container_lab_complete": status == "pass",
        "coordinate_classification": classification["coordinate_classification"],
        "host_architecture": NATIVE_AGGREGATE_HOST,
        "network_during_image_bootstrap": (
            "rootless Podman default on each native architecture shard"
        ),
        "network_during_package_operations": "disabled",
        "host_mutation": (
            "bounded to rootless Podman storage and temporary workdirs on each "
            "native architecture runner"
        ),
        "architectures_completed": [
            item["architecture"]
            for item in architecture_coverage
            if item["status"] == "pass"
        ],
        "architectures_incomplete_or_failed": [
            {
                "architecture": item["architecture"],
                "status": item["status"],
                "reason": (
                    "not every required distribution completed every lifecycle scenario"
                ),
            }
            for item in architecture_coverage
            if item["status"] != "pass"
        ],
        "architecture_coverage": architecture_coverage,
        "family_architecture_coverage": family_architecture_coverage,
        "required_platform_coordinates": [
            {"distribution": distribution, "architecture": architecture}
            for distribution, architecture in sorted(REQUIRED_PLATFORM_COORDINATES)
        ],
        "missing_platform_coordinates": [],
        "arm64_coverage_policy": (
            "arm64/aarch64 qualification requires the native ubuntu-24.04-arm "
            "shard; emulation and binfmt execution are forbidden"
        ),
        "rollback_model": (
            "external package-manager downgrade to the separately supplied, "
            "checksum-verified previous artifact; this is not a SysWarden "
            "product rollback feature"
        ),
    }
    return status, classification, scope


def aggregate_native_shard_reports(args: argparse.Namespace) -> dict[str, object]:
    candidate_root, previous_root, pairs = validate_inputs(
        args.packages_dir,
        args.previous_packages_dir,
        DEFAULT_PLATFORMS,
    )
    version_contract = build_package_version_contract(pairs)
    expected_binding = build_qualification_binding(
        args,
        candidate_root,
        previous_root,
        version_contract,
    )
    paths = {
        "amd64": args.aggregate_amd64_report,
        "arm64": args.aggregate_arm64_report,
    }
    shard_reports: dict[str, dict[str, object]] = {}
    shard_digests: dict[str, str] = {}
    identities: set[tuple[int, int]] = set()
    for architecture in ("amd64", "arm64"):
        report, digest, identity = _read_native_shard(
            paths[architecture], f"{architecture} native shard report"
        )
        if identity in identities:
            raise LifecycleLabError("native shard reports must have distinct inodes")
        identities.add(identity)
        validate_native_shard_report(
            report,
            architecture=architecture,
            expected_binding=expected_binding,
        )
        shard_reports[architecture] = report
        shard_digests[architecture] = digest

    expected_contract_coordinates = {
        str(item["coordinate"]): item
        for item in version_contract["coordinates"]
        if isinstance(item, dict)
    }
    platform_results: list[dict[str, object]] = []
    observed_package_coordinates: set[str] = set()
    for architecture in ("amd64", "arm64"):
        shard = shard_reports[architecture]
        shard_contract = shard["package_version_contract"]
        if not isinstance(shard_contract, dict):
            raise LifecycleLabError("native shard version contract is invalid")
        for key in (
            "scheme",
            "relation",
            "previous_version",
            "candidate_version",
            "previous_numeric",
            "candidate_numeric",
        ):
            if shard_contract.get(key) != version_contract[key]:
                raise LifecycleLabError(
                    f"{architecture} shard version contract differs at {key}"
                )
        coordinates = shard_contract.get("coordinates")
        if not isinstance(coordinates, list):
            raise LifecycleLabError("native shard package coordinates are invalid")
        for item in coordinates:
            if not isinstance(item, dict):
                raise LifecycleLabError("native shard package coordinate is invalid")
            coordinate = str(item.get("coordinate"))
            if (
                coordinate in observed_package_coordinates
                or expected_contract_coordinates.get(coordinate) != item
            ):
                raise LifecycleLabError(
                    "native shard package coordinate is duplicate or mismatched"
                )
            observed_package_coordinates.add(coordinate)
        platforms = shard.get("platforms")
        if not isinstance(platforms, list):
            raise LifecycleLabError("native shard platform list is invalid")
        for platform_result in platforms:
            if not isinstance(platform_result, dict):
                raise LifecycleLabError("native shard platform result is invalid")
            coordinate = f"{platform_result.get('family')}:{platform_result.get('package_architecture')}"
            pair = pairs.get(coordinate)
            if pair is None:
                raise LifecycleLabError("native shard references an unknown package coordinate")
            if platform_result.get("candidate") != {
                "filename": pair.candidate.path.name,
                "version": pair.candidate.version,
                "sha256": pair.candidate.sha256,
            } or platform_result.get("previous") != {
                "filename": pair.previous.path.name,
                "version": pair.previous.version,
                "sha256": pair.previous.sha256,
            }:
                raise LifecycleLabError(
                    "native shard artifact evidence differs from current package bytes"
                )
            platform_results.append(platform_result)
    if observed_package_coordinates != set(expected_contract_coordinates):
        raise LifecycleLabError("native shard package coordinate union is incomplete")

    status, classification, scope = _aggregate_matrix_summary(platform_results)
    native_records = []
    for architecture in ("amd64", "arm64"):
        shard = shard_reports[architecture]
        shard_scope = shard["scope"]
        shard_engine = shard["engine"]
        if not isinstance(shard_scope, dict) or not isinstance(shard_engine, dict):
            raise LifecycleLabError("native shard metadata is invalid")
        native_records.append(
            {
                "architecture": architecture,
                "host_architecture": normalize_host_architecture(
                    str(shard_scope["host_architecture"])
                ),
                "report_sha256": shard_digests[architecture],
                "engine_name": shard_engine["name"],
                "engine_version": shard_engine["version"],
            }
        )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": status,
        "harness_complete": classification["harness_complete"],
        "release_ready": classification["release_ready"],
        "blocker_ids": classification["blocker_ids"],
        "unexpected_failed_checks": classification["unexpected_failed_checks"],
        "package_version_contract": version_contract,
        "scope": scope,
        "engine": {
            "name": "podman",
            "version": ";".join(
                f"{item['architecture']}={item['engine_version']}"
                for item in native_records
            ),
            "rootless": True,
            "arm64_emulator": None,
            "arm64_binfmt": None,
        },
        "package_roots": {
            "candidate": str(candidate_root),
            "previous": str(previous_root),
            "mount_mode": "read-only",
        },
        "platforms": platform_results,
        "qualification_binding": expected_binding,
        "native_shards": {
            "schema_version": 1,
            "mode": "native_architecture_shards_v1",
            "reports": native_records,
        },
    }
    validate_report_version_contract(report)
    return report


def write_report(path: Path, report: dict[str, object], pretty: bool) -> None:
    destination = path.expanduser().absolute()
    parent = require_real_directory(destination.parent, "report parent directory")
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise LifecycleLabError(f"cannot inspect report destination {destination}: {exc}") from exc
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LifecycleLabError(
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages-dir", type=Path, required=True)
    parser.add_argument("--previous-packages-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--architecture-shard", choices=("amd64", "arm64"))
    parser.add_argument("--aggregate-amd64-report", type=Path)
    parser.add_argument("--aggregate-arm64-report", type=Path)
    parser.add_argument("--qualification-repository")
    parser.add_argument("--qualification-release-sha")
    parser.add_argument("--qualification-release-tag")
    parser.add_argument("--qualification-previous-tag")
    parser.add_argument("--qualification-workflow-run-id")
    parser.add_argument("--qualification-workflow-run-attempt")
    parser.add_argument("--qualification-candidate-run-id")
    parser.add_argument("--qualification-candidate-artifact-id")
    parser.add_argument("--qualification-candidate-artifact-name")
    parser.add_argument("--qualification-previous-release-id")
    parser.add_argument(
        "--arm64-emulator",
        type=Path,
        help=(
            "exact qemu-aarch64-static interpreter registered by enabled host "
            "binfmt_misc with persistent flag F on a non-arm64 host"
        ),
    )
    parser.add_argument(
        "--pull-policy", choices=("never", "missing", "always"), default="missing"
    )
    parser.add_argument("--scenario-timeout", type=int, default=600)
    defaults = {
        platform_coordinate(spec): spec.image for spec in DEFAULT_PLATFORMS
    }
    parser.add_argument(
        "--debian-image",
        "--debian-amd64-image",
        dest="debian_amd64_image",
        default=defaults[("debian", "amd64")],
    )
    parser.add_argument(
        "--debian-arm64-image", default=defaults[("debian", "arm64")]
    )
    parser.add_argument(
        "--ubuntu-amd64-image", default=defaults[("ubuntu", "amd64")]
    )
    parser.add_argument(
        "--ubuntu-arm64-image", default=defaults[("ubuntu", "arm64")]
    )
    parser.add_argument(
        "--fedora-image",
        "--fedora-amd64-image",
        dest="fedora_amd64_image",
        default=defaults[("fedora", "amd64")],
    )
    parser.add_argument(
        "--fedora-arm64-image", default=defaults[("fedora", "arm64")]
    )
    parser.add_argument(
        "--almalinux-amd64-image", default=defaults[("almalinux", "amd64")]
    )
    parser.add_argument(
        "--almalinux-arm64-image", default=defaults[("almalinux", "arm64")]
    )
    parser.add_argument(
        "--alpine-image",
        "--alpine-amd64-image",
        dest="alpine_amd64_image",
        default=defaults[("alpine", "amd64")],
    )
    parser.add_argument(
        "--alpine-arm64-image", default=defaults[("alpine", "arm64")]
    )
    return parser


def configured_platforms(args: argparse.Namespace) -> tuple[PlatformSpec, ...]:
    images = {
        ("debian", "amd64"): args.debian_amd64_image,
        ("debian", "arm64"): args.debian_arm64_image,
        ("ubuntu", "amd64"): args.ubuntu_amd64_image,
        ("ubuntu", "arm64"): args.ubuntu_arm64_image,
        ("fedora", "amd64"): args.fedora_amd64_image,
        ("fedora", "arm64"): args.fedora_arm64_image,
        ("almalinux", "amd64"): args.almalinux_amd64_image,
        ("almalinux", "arm64"): args.almalinux_arm64_image,
        ("alpine", "amd64"): args.alpine_amd64_image,
        ("alpine", "arm64"): args.alpine_arm64_image,
    }
    return tuple(
        PlatformSpec(
            **{
                **asdict(spec),
                "image": images[platform_coordinate(spec)],
            }
        )
        for spec in DEFAULT_PLATFORMS
        if args.architecture_shard is None
        or spec.architecture == args.architecture_shard
    )


def error_report(exc: Exception) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "fail",
        "harness_complete": False,
        "release_ready": False,
        "blocker_ids": [],
        "unexpected_failed_checks": [f"harness:{exc}"],
        "error": str(exc),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    aggregate_requested = (
        args.aggregate_amd64_report is not None
        or args.aggregate_arm64_report is not None
    )
    if aggregate_requested and (
        args.aggregate_amd64_report is None
        or args.aggregate_arm64_report is None
        or args.architecture_shard is not None
        or args.arm64_emulator is not None
    ):
        report = error_report(
            LifecycleLabError(
                "aggregation requires exactly both shard reports and forbids shard/emulator options"
            )
        )
    elif args.scenario_timeout < 30:
        report = error_report(
            LifecycleLabError("--scenario-timeout must be at least 30 seconds")
        )
    else:
        try:
            if aggregate_requested:
                report = aggregate_native_shard_reports(args)
            else:
                report = run_lab(args, platforms=configured_platforms(args))
        except (LifecycleLabError, OSError) as exc:
            report = error_report(exc)

    serialized = json.dumps(
        report, indent=2 if args.pretty else None, sort_keys=True
    ) + "\n"
    if args.output is not None:
        try:
            write_report(args.output, report, args.pretty)
        except LifecycleLabError as exc:
            report = error_report(exc)
            serialized = json.dumps(
                report, indent=2 if args.pretty else None, sort_keys=True
            ) + "\n"
    sys.stdout.write(serialized)
    return 0 if report.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
