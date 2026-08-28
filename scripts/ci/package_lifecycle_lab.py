#!/usr/bin/env python3
"""Run fail-closed SysWarden package lifecycle tests in rootless Podman.

The lab prepares disposable Debian, Ubuntu, Fedora, AlmaLinux, and Alpine images
from immutable official-image references for amd64. Package operations
then run without network access. Package directories are mounted read-only. No
host service, firewall, device, container-engine socket, or non-lab writable path
is exposed to a test container.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

try:
    from scripts.ci import package_qualification_matrix as qualification_matrix
except ModuleNotFoundError:  # Direct execution from scripts/ci.
    import package_qualification_matrix as qualification_matrix


SCHEMA_VERSION = 5
LOG_TAIL_LIMIT = 12_000
NAMESPACE_DIAGNOSTIC_PREFIX_BYTES = 256
MAX_VERSION_COMPONENT = 2_147_483_647
SYS_ADMIN_CAPABILITY_BIT = 21
SYS_PTRACE_CAPABILITY_BIT = 19
SYSTEMD_MANAGER_CAPABILITY_FIELDS = frozenset(
    {"permitted", "effective", "bounding"}
)
EXEC_SECURITY_MARKER = "SYSWARDEN_EXEC_SECURITY_V1"
NAMESPACE_FAILURE_MARKER = "SYSWARDEN_NAMESPACE_FAILURE_V1"
SNAPSHOT_FAILURE_MARKER = "SYSWARDEN_SNAPSHOT_FAILURE_V1"
SEED_FAILURE_MARKER = "SYSWARDEN_LIFECYCLE_SEED_FAILURE_V1"
FEDORA_CRON_DROPIN_PATH = (
    "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
)
SYSTEMD_EXEC_LAUNCHER = (
    "/usr/bin/setpriv",
    "--bounding-set=-sys_admin",
    "--inh-caps=-sys_admin",
    "--ambient-caps=-sys_admin",
    "--no-new-privs",
    "/bin/sh",
    "-ceu",
)
VERSION_SCHEME = "canonical_syswarden_numeric_v1"
VERSION_RELATION = "previous < candidate"
IMAGE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$"
)
SYSWARDEN_VERSION_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.([0-9]{2})\.(0|[1-9][0-9]*)$"
)
ARTIFACT_VERSION_PATTERNS = (
    re.compile(r"^syswarden_(?P<version>[0-9][0-9.]*)_amd64\.deb$"),
    re.compile(r"^syswarden-(?P<version>[0-9][0-9.]*)-1\.x86_64\.rpm$"),
    re.compile(r"^syswarden_(?P<version>[0-9][0-9.]*)_x86_64\.apk$"),
)


class LifecycleLabError(RuntimeError):
    """Raised when the lifecycle lab cannot produce trustworthy evidence."""


@dataclass(frozen=True)
class PlatformSpec:
    cell_id: str
    version: str
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
}

EXPECTED_PACKAGE_ARCHITECTURES = {
    ("deb", "amd64"): "amd64",
    ("rpm", "amd64"): "x86_64",
    ("apk", "amd64"): "x86_64",
}

EXPECTED_PACKAGE_PATTERNS = {
    ("deb", "amd64"): r"^syswarden_[0-9][0-9.]*_amd64\.deb$",
    ("rpm", "amd64"): r"^syswarden-[0-9][0-9.]*-1\.x86_64\.rpm$",
    ("apk", "amd64"): r"^syswarden_[0-9][0-9.]*_x86_64\.apk$",
}

EXPECTED_SCENARIOS = {
    "deb": ("upgrade-rollback", "remove", "purge"),
    "rpm": ("upgrade-rollback", "remove"),
    "apk": ("upgrade-rollback", "remove", "purge"),
}

ACTIVE_RESTART_CONTRACT = (
    "upgrade-rollback performs two consecutive container restarts from "
    "a non-copy-up /run tmpfs and revalidates native and filesystem "
    "inventories plus operator state"
)
AVAILABLE_ARCHITECTURE_PROBE_KEYS = frozenset(
    {
        "status",
        "execution_mode",
        "podman_platform",
        "expected_uname",
        "actual_uname",
        "expected_distribution",
        "actual_distribution",
        "expected_distribution_version",
        "actual_distribution_version",
        "container_exit_code",
        "network",
        "filesystem",
    }
)

OFFICIAL_REPOSITORIES = {
    "debian": "docker.io/library/debian",
    "ubuntu": "docker.io/library/ubuntu",
    "fedora": "docker.io/library/fedora",
    "almalinux": "docker.io/library/almalinux",
    "alpine": "docker.io/library/alpine",
}

EXACT_OS_RELEASE_VERSION_DISTRIBUTIONS = frozenset(
    {"debian", "ubuntu", "fedora"}
)
OS_RELEASE_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")

DEB_BOOTSTRAP = (
    "apt-get update && "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y "
    "--no-install-recommends systemd systemd-sysv dbus iproute2 nftables ipset curl wget rsyslog cron "
    "bash-completion wireguard-tools qrencode jq unattended-upgrades util-linux "
    "apt-listchanges procps e2fsprogs socat binutils file && "
    "if [ -f /etc/dpkg/dpkg.cfg.d/docker ]; then "
    "sed -i '\\|^path-exclude /usr/share/doc/\\*$|d' "
    "/etc/dpkg/dpkg.cfg.d/docker; fi && "
    "rm -rf /var/lib/apt/lists/*"
)
RPM_BOOTSTRAP = (
    "dnf -y install systemd iproute nftables ipset curl-minimal wget rsyslog cronie "
    "bash-completion wireguard-tools jq checkpolicy "
    "policycoreutils-python-utils dnf-automatic procps-ng e2fsprogs socat binutils "
    "cpio diffutils file util-linux && dnf clean all"
)
RPM_COMMON_IMAGE_DEPENDENCY_GUARD = (
    "RUN ! rpm -q qrencode >/dev/null 2>&1 && "
    "! rpm -q epel-release >/dev/null 2>&1\n"
)
HISTORICAL_RPM_TRANSITION_VERSION = "4.03.2"
HISTORICAL_RPM_TRANSITION_BOOTSTRAPS = {
    "fedora": (
        "dnf -y install qrencode && "
        "rpm -q qrencode >/dev/null && "
        "! rpm -q epel-release >/dev/null 2>&1 && dnf clean all"
    ),
    "almalinux": (
        "dnf -y install epel-release && "
        "dnf -y install qrencode && "
        "rpm -q epel-release >/dev/null && "
        "rpm -q qrencode >/dev/null && dnf clean all"
    ),
}
APK_BOOTSTRAP = (
    "apk add --no-cache openrc openrc-init && "
    "apk add --no-cache iproute2 nftables cronie cronie-openrc curl wget rsyslog rsyslog-uxsock "
    "bash-completion wireguard-tools libqrencode-tools jq procps-ng "
    "e2fsprogs-extra shadow socat binutils file && test -x /usr/bin/gpasswd"
)
DEB_PURGE_SEMANTICS = (
    "remove preserves generated /etc, /var/lib, and /var/log state behind an "
    "exact deferred-purge marker; a later purge removes every dedicated product root"
)
RPM_PURGE_SEMANTICS = (
    "RPM has no distinct purge operation; erase runs the package's destructive "
    "final-removal script"
)
APK_PURGE_SEMANTICS = (
    "APK final removal runs post-deinstall and removes the dedicated opt, etc, "
    "data, and log roots; apk --purge adds no broader product cleanup"
)
LAB_NETWORK_HELPER = """#!/bin/sh
set -eu
if ! ip link show dev eth0 >/dev/null 2>&1; then
    ip link add eth0 type dummy
fi
ip link set dev eth0 up
ip -d link show dev eth0 | grep -Eq '(^|[[:space:]])dummy([[:space:]]|$)'
"""
SYSTEMD_LAB_NETWORK_UNIT = """[Unit]
Description=Isolated SysWarden lifecycle lab network provider
After=local-fs.target
Before=network.target network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/syswarden-lab-network
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
ALPINE_LAB_NETWORK_PROVIDER = """#!/sbin/openrc-run
name="syswarden-lab-net"
description="Isolated SysWarden lifecycle lab network provider"

depend() {
    provide net
}

start() {
    ebegin "Attesting isolated lifecycle dummy interface"
    /usr/local/libexec/syswarden-lab-network || return 1
    eend 0
}

stop() {
    return 0
}
"""
ALPINE_RSYSLOG_READINESS_PROVIDER = """#!/sbin/openrc-run
name="syswarden-lab-rsyslog-ready"
description="Ensure rsyslog is active in the isolated SysWarden lifecycle lab"

depend() {
    need syswarden-lab-net
    after rsyslog
}

start() {
    ebegin "Attesting isolated lifecycle rsyslog service"
    if ! rc-service rsyslog status >/dev/null 2>&1; then
        if ! rc-service rsyslog start; then
            eend 1
            return 1
        fi
    fi
    if ! rc-service rsyslog status >/dev/null 2>&1; then
        eend 1
        return 1
    fi
    eend 0
}

stop() {
    return 0
}
"""
ALPINE_OPENRC_VERSION = "0.62.6-r0"
ALPINE_OPENRC_SYS_ATTESTATION_HEX = (
    "504f444d414e0a"
)
ALPINE_RC_CONF_PRE_SHA256 = (
    "87799a1b4fa5e3941276e695e8525fcd2c1a08f551d02d1c0b1bdfdd67a71dce"
)
ALPINE_RC_CONF_APPEND_BASE64 = (
    "CnJjX3N5cz0icG9kbWFuIgpyY19jZ3JvdXBfbW9kZT0ibGVnYWN5Igo="
)
ALPINE_RC_CONF_APPEND_SHA256 = (
    "6f9f3c8182fa0f7e1cde659cfda5b3a19f917ab222ee8d26ac87c5575b78c768"
)
ALPINE_RC_CONF_POST_SHA256 = (
    "6653be4e72083b79317918a08493ad54671441f83b646555f56c30117a0c0b8f"
)
ALPINE_HOSTNAME_INIT_PRE_SHA256 = (
    "29d467628434f1a56b37c0042463ee0253a12ce8743e42f65e9dcbc4ed34ff20"
)
ALPINE_HOSTNAME_INIT_POST_SHA256 = (
    "11eb8ad952a72d82a63987faf51f8d0248acd765f8327f117436b45a378f4f91"
)
FEDORA_LAB_MASK_TARGETS = (
    "systemd-oomd.service",
    "systemd-oomd.socket",
    "systemd-resolved-monitor.socket",
    "systemd-resolved-varlink.socket",
    "systemd-resolved.service",
)
FEDORA_LAB_MASKED_UNITS = tuple(
    sorted(
        (
            "dbus-org.freedesktop.oom1.service",
            "dbus-org.freedesktop.resolve1.service",
            *FEDORA_LAB_MASK_TARGETS,
        )
    )
)
# A delegated rootless cgroup namespace may expose its own cgroup2 mount as rw.
# The caller separately proves the non-host-root ID map, private cgroup namespace,
# exact non-SYS_ADMIN capabilities, and NoNewPrivs. The Alpine runtime additionally
# pins legacy OpenRC cgroup mode and rejects every openrc.* cgroup residue.
ALPINE_CGROUP_MOUNTINFO_AWK = (
    '$5 == "/sys/fs/cgroup" { '
    "count++; separator = 0; "
    "for (field_number = 7; field_number <= NF; field_number++) "
    'if ($field_number == "-") { separator = field_number; break } '
    'if ($4 != "/" || !separator || $(separator + 1) != "cgroup2") bad = 1; '
    'split($6, options, ","); readonly = 0; readwrite = 0; '
    "nosuid = 0; nodev = 0; noexec = 0; "
    "for (option in options) { "
    'if (options[option] == "ro") readonly++; '
    'else if (options[option] == "rw") readwrite++; '
    'else if (options[option] == "nosuid") nosuid++; '
    'else if (options[option] == "nodev") nodev++; '
    'else if (options[option] == "noexec") noexec++ '
    "} "
    "if (readonly + readwrite != 1 || nosuid != 1 || nodev != 1 || "
    "noexec != 1) bad = 1; "
    'access = readonly == 1 ? "ro" : "rw" '
    "} END { if (count != 1 || bad) exit 1; print access }"
)
NAMESPACE_ATTESTATION_HELPERS = f"""set -eu
syswarden_namespace_hex_prefix() {{
    LC_ALL=C dd bs={NAMESPACE_DIAGNOSTIC_PREFIX_BYTES} count=1 2>/dev/null | \\
        od -An -v -tx1 | tr -d ' \\n'
}}
syswarden_namespace_fail() {{
    syswarden_namespace_predicate="$1"
    syswarden_namespace_status="$2"
    syswarden_namespace_actual="$3"
    syswarden_namespace_expected="$4"
    case "${{syswarden_namespace_predicate}}" in
        NS[0-9][0-9]_*) ;;
        *) exit 97 ;;
    esac
    case "${{syswarden_namespace_status}}" in
        ''|*[!0-9]*) exit 97 ;;
    esac
    [ "${{syswarden_namespace_status}}" -le 255 ] || exit 97
    syswarden_namespace_actual_bytes="$(
        printf '%s' "${{syswarden_namespace_actual}}" | LC_ALL=C wc -c | tr -d ' '
    )" || exit 97
    syswarden_namespace_expected_bytes="$(
        printf '%s' "${{syswarden_namespace_expected}}" | LC_ALL=C wc -c | tr -d ' '
    )" || exit 97
    syswarden_namespace_actual_hex_prefix="$(
        printf '%s' "${{syswarden_namespace_actual}}" | syswarden_namespace_hex_prefix
    )" || exit 97
    syswarden_namespace_expected_hex_prefix="$(
        printf '%s' "${{syswarden_namespace_expected}}" | syswarden_namespace_hex_prefix
    )" || exit 97
    printf '%s\\tpredicate=%s\\trc=%s\\tactual_bytes=%s\\tactual_hex_prefix=%s\\texpected_bytes=%s\\texpected_hex_prefix=%s\\n' \\
        '{NAMESPACE_FAILURE_MARKER}' "${{syswarden_namespace_predicate}}" \\
        "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual_bytes}}" \\
        "${{syswarden_namespace_actual_hex_prefix}}" \\
        "${{syswarden_namespace_expected_bytes}}" \\
        "${{syswarden_namespace_expected_hex_prefix}}" >&2
    exit 1
}}
syswarden_namespace_expect_equal() {{
    syswarden_namespace_predicate="$1"
    syswarden_namespace_status="$2"
    syswarden_namespace_actual="$3"
    syswarden_namespace_expected="$4"
    if [ "${{syswarden_namespace_status}}" -ne 0 ] || \\
       [ "${{syswarden_namespace_actual}}" != "${{syswarden_namespace_expected}}" ]; then
        syswarden_namespace_fail "${{syswarden_namespace_predicate}}" \\
            "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" \\
            "${{syswarden_namespace_expected}}"
    fi
}}
syswarden_namespace_expect_integer() {{
    syswarden_namespace_predicate="$1"
    syswarden_namespace_status="$2"
    syswarden_namespace_actual="$3"
    syswarden_namespace_expected="$4"
    if [ "${{syswarden_namespace_status}}" -ne 0 ]; then
        syswarden_namespace_fail "${{syswarden_namespace_predicate}}" \\
            "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" \\
            "${{syswarden_namespace_expected}}"
    fi
    if ! [ "${{syswarden_namespace_actual}}" -eq \\
           "${{syswarden_namespace_expected}}" ] 2>/dev/null; then
        syswarden_namespace_fail "${{syswarden_namespace_predicate}}" \\
            "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" \\
            "${{syswarden_namespace_expected}}"
    fi
}}
syswarden_namespace_expect_status() {{
    syswarden_namespace_predicate="$1"
    syswarden_namespace_status="$2"
    syswarden_namespace_actual="$3"
    if [ "${{syswarden_namespace_status}}" -ne 0 ]; then
        syswarden_namespace_fail "${{syswarden_namespace_predicate}}" \\
            "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" ''
    fi
}}
syswarden_namespace_file_record() {{
    syswarden_namespace_record_path="$1"
    syswarden_namespace_record_bytes="$(
        LC_ALL=C wc -c < "${{syswarden_namespace_record_path}}" 2>&1
    )" || {{
        syswarden_namespace_record_status=$?
        printf 'wc=%s' "${{syswarden_namespace_record_bytes}}"
        return "${{syswarden_namespace_record_status}}"
    }}
    syswarden_namespace_record_od="$(
        LC_ALL=C od -An -N {NAMESPACE_DIAGNOSTIC_PREFIX_BYTES} -v -tx1 \\
            "${{syswarden_namespace_record_path}}" 2>&1
    )" || {{
        syswarden_namespace_record_status=$?
        printf 'od=%s' "${{syswarden_namespace_record_od}}"
        return "${{syswarden_namespace_record_status}}"
    }}
    syswarden_namespace_record_hex="$(
        printf '%s' "${{syswarden_namespace_record_od}}" | tr -d ' \\n'
    )" || {{
        syswarden_namespace_record_status=$?
        printf 'tr=%s' "${{syswarden_namespace_record_hex}}"
        return "${{syswarden_namespace_record_status}}"
    }}
    printf 'bytes=%s;hex=%s' "${{syswarden_namespace_record_bytes}}" \\
        "${{syswarden_namespace_record_hex}}"
}}
"""


QUALIFICATION_MATRIX_PATH = qualification_matrix.DEFAULT_MATRIX
QUALIFICATION_MATRIX_DOCUMENT, QUALIFICATION_MATRIX_SHA256 = (
    qualification_matrix.load_matrix_snapshot(QUALIFICATION_MATRIX_PATH)
)
QUALIFICATION_MATRIX_ID = str(QUALIFICATION_MATRIX_DOCUMENT["matrix_id"])

_PLATFORM_NAMES = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "fedora": "Fedora",
    "almalinux": "AlmaLinux",
    "alpine": "Alpine",
}
_BOOTSTRAP_COMMANDS = {
    "deb": DEB_BOOTSTRAP,
    "rpm": RPM_BOOTSTRAP,
    "apk": APK_BOOTSTRAP,
}
_PURGE_SEMANTICS = {
    "deb": DEB_PURGE_SEMANTICS,
    "rpm": RPM_PURGE_SEMANTICS,
    "apk": APK_PURGE_SEMANTICS,
}


def _platform_from_matrix_cell(cell: dict[str, object]) -> PlatformSpec:
    distribution = str(cell["distribution"])
    family = str(cell["family"])
    architecture = "amd64"
    return PlatformSpec(
        cell_id=str(cell["id"]),
        version=str(cell["version"]),
        name=_PLATFORM_NAMES[distribution],
        distribution=distribution,
        family=family,
        architecture=architecture,
        package_architecture=EXPECTED_PACKAGE_ARCHITECTURES[
            (family, architecture)
        ],
        podman_platform=str(
            QUALIFICATION_MATRIX_DOCUMENT["architecture"]["oci_platform"]
        ),
        uname_architecture=str(
            QUALIFICATION_MATRIX_DOCUMENT["architecture"]["kernel"]
        ),
        official_repository=OFFICIAL_REPOSITORIES[distribution],
        image=str(cell["image"]),
        package_pattern=EXPECTED_PACKAGE_PATTERNS[(family, architecture)],
        bootstrap_command=_BOOTSTRAP_COMMANDS[family],
        scenarios=tuple(str(item) for item in cell["container_scenarios"]),
        purge_semantics=_PURGE_SEMANTICS[family],
    )


DEFAULT_PLATFORMS = tuple(
    _platform_from_matrix_cell(cell)
    for cell in QUALIFICATION_MATRIX_DOCUMENT["cells"]
)
if len(DEFAULT_PLATFORMS) != 8:
    raise LifecycleLabError("frozen qualification matrix must contain exactly 8 cells")

REQUIRED_PLATFORM_COORDINATES = frozenset(
    (spec.cell_id, spec.architecture) for spec in DEFAULT_PLATFORMS
)
REQUIRED_PLATFORM_COORDINATE_ORDER = tuple(
    (spec.cell_id, spec.architecture) for spec in DEFAULT_PLATFORMS
)
REQUIRED_PACKAGE_COORDINATES = frozenset(
    f"{spec.family}:{spec.package_architecture}" for spec in DEFAULT_PLATFORMS
)
PACKAGE_COORDINATE_PATTERNS = {
    f"{spec.family}:{spec.package_architecture}": spec.package_pattern
    for spec in DEFAULT_PLATFORMS
}
REQUIRED_FAMILIES = ("deb", "rpm", "apk")
NATIVE_AGGREGATE_HOST = "native-shards:amd64"
QUALIFICATION_MATRIX_KEYS = frozenset({"matrix_id", "sha256"})
SCOPE_KEYS = frozenset(
    {
        "evidence_kind",
        "coverage_kind",
        "real_host_evidence_included",
        "required_checks_complete",
        "covered_scenarios",
        "container_lab_complete",
        "coordinate_classification",
        "host_architecture",
        "network_during_image_bootstrap",
        "network_during_package_operations",
        "host_mutation",
        "architectures_completed",
        "architectures_incomplete_or_failed",
        "architecture_coverage",
        "family_architecture_coverage",
        "required_platform_coordinates",
        "missing_platform_coordinates",
        "architecture_coverage_policy",
        "rollback_model",
    }
)
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


def qualification_matrix_binding(path: Path) -> dict[str, str]:
    """Load and byte-bind the exact frozen matrix used by this lab run."""

    try:
        document, digest = qualification_matrix.load_matrix_snapshot(path)
    except qualification_matrix.QualificationMatrixError as exc:
        raise LifecycleLabError(f"qualification matrix is invalid: {exc}") from exc
    if document != QUALIFICATION_MATRIX_DOCUMENT:
        raise LifecycleLabError(
            "qualification matrix differs from the frozen lifecycle contract"
        )
    if digest != QUALIFICATION_MATRIX_SHA256:
        raise LifecycleLabError(
            "qualification matrix bytes differ from the frozen lifecycle contract"
        )
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise LifecycleLabError("qualification matrix SHA-256 is invalid")
    return {"matrix_id": QUALIFICATION_MATRIX_ID, "sha256": digest}


def validate_qualification_matrix_binding(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != QUALIFICATION_MATRIX_KEYS
        or value.get("matrix_id") != QUALIFICATION_MATRIX_ID
        or not isinstance(value.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
        or value.get("sha256") != QUALIFICATION_MATRIX_SHA256
    ):
        raise LifecycleLabError("qualification matrix report binding is invalid")
    return {"matrix_id": str(value["matrix_id"]), "sha256": str(value["sha256"])}


def qualification_matrix_container_scenarios() -> list[dict[str, object]]:
    return [
        {"cell_id": spec.cell_id, "scenarios": list(spec.scenarios)}
        for spec in DEFAULT_PLATFORMS
    ]

OPERATOR_STATE_KEYS = (
    "config",
    "token",
    "list",
    "list_ipv6",
    "operator_data",
    "certificate",
)
LIVE_TELEMETRY_STATE_KEY = "telemetry"
LIVE_TELEMETRY_STATE_ATTRIBUTES = (
    "type",
    "mode",
    "owner",
    "json",
    "schema",
)

BASH_COMPLETION_PATH = "/usr/share/bash-completion/completions/syswarden"
GEOIP_DATA_LICENSE_PATH = "/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt"
GEOIP_DATA_LICENSE_FIRST_VERSION = "4.04.0"
GEOIP_DATA_LICENSE_SHA256 = (
    "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"
)
PROJECT_LICENSE_PATH = "/usr/share/doc/syswarden/LICENSE.txt"
PROJECT_LICENSE_SHA256 = (
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
)
PROJECT_LICENSE_EXPRESSION = "GPL-3.0-or-later"
LEGACY_BASH_COMPLETION_PATH = "/etc/bash_completion.d/syswarden"
LEGACY_BASH_COMPLETION_VERSION = "4.03.2"
LEGACY_BASH_COMPLETION_SIZE = 16_339
LEGACY_BASH_COMPLETION_SHA256 = (
    "c23c9f6c54b91105e9ecd8ad4431a9a11ad26ba3437bcd20ec2cef1a96e51d21"
)
LEGACY_PACKAGE_PAYLOAD_PATHS = (
    "/opt/syswarden/bin/syswarden-cli",
    "/opt/syswarden/bin/syswarden-core",
    "/opt/syswarden/bin/syswarden-tui",
    "/opt/syswarden/signatures.json",
    "/usr/local/bin/syswarden",
    "/usr/local/bin/syswarden-tui",
)
PACKAGE_PAYLOAD_PATHS = (
    *LEGACY_PACKAGE_PAYLOAD_PATHS,
    BASH_COMPLETION_PATH,
)
LICENSED_PACKAGE_PAYLOAD_PATHS = (
    *PACKAGE_PAYLOAD_PATHS,
    GEOIP_DATA_LICENSE_PATH,
    PROJECT_LICENSE_PATH,
)
FORWARD_ONLY_APK_CANDIDATE_VERSION = "4.03.2"
FORWARD_ONLY_APK_PREVIOUS_VERSION = "4.02.8"
FORWARD_ONLY_APK_PREVIOUS = {
    "x86_64": {
        "filename": "syswarden_4.02.8_x86_64.apk",
        "sha256": "c0869bcb6f9adc1e4ca191ae5f5ed7962c9c89fb2bac9a4d52c0c246b09036d4",
    },
}
HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION = "4.03.3"
HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION = "4.03.2"
HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS = {
    "filename": "syswarden_4.03.2_amd64.deb",
    "sha256": "e499370fbed0e40968a6377f4e3cd9a8718993352deccc181a4fb43333289019",
}
HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL = (
    "exact byte-bound v4.03.2 Ubuntu DEB postinstall race recovered by one "
    "bounded dpkg reconfiguration"
)
LEGACY_DEB_PACKAGE_PATHS = frozenset(
    (*LEGACY_PACKAGE_PAYLOAD_PATHS,)
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
DEB_PACKAGE_PATHS = frozenset(
    (*LEGACY_DEB_PACKAGE_PATHS,)
    + (
        BASH_COMPLETION_PATH,
        "/usr/share/bash-completion",
        "/usr/share/bash-completion/completions",
    )
)
LICENSED_DEB_PACKAGE_PATHS = frozenset(
    (*DEB_PACKAGE_PATHS, GEOIP_DATA_LICENSE_PATH, PROJECT_LICENSE_PATH)
)
LEGACY_APK_PACKAGE_PATHS = frozenset(LEGACY_PACKAGE_PAYLOAD_PATHS)
APK_PACKAGE_PATHS = frozenset(PACKAGE_PAYLOAD_PATHS)
LICENSED_APK_PACKAGE_PATHS = frozenset(
    LICENSED_PACKAGE_PAYLOAD_PATHS
)
RPM_BUILD_ID_DIRECTORY_PATTERN = re.compile(r"^/usr/lib/\.build-id/[0-9a-f]{2}$")
RPM_BUILD_ID_LINK_PATTERN = re.compile(
    r"^/usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38}$"
)


def _state_event_checks(scenario: str, label: str) -> tuple[str, ...]:
    operator_checks = tuple(
        f"{scenario}.{label}.state.{key}.{attribute}"
        for key in OPERATOR_STATE_KEYS
        for attribute in ("type", "hash", "mode", "owner")
    )
    telemetry_checks = tuple(
        f"{scenario}.{label}.state.{LIVE_TELEMETRY_STATE_KEY}.{attribute}"
        for attribute in LIVE_TELEMETRY_STATE_ATTRIBUTES
    )
    return operator_checks + telemetry_checks


def _installed_phase_event_checks(scenario: str, label: str) -> tuple[str, ...]:
    return (
        f"{scenario}.{label}.version",
        f"{scenario}.{label}.inventory.manager",
        f"{scenario}.{label}.inventory.filesystem",
        f"{scenario}.{label}.executable",
        f"{scenario}.{label}.elf_contract",
        f"{scenario}.{label}.postinstall_contract",
    )


def _generated_cleanup_event_checks(
    scenario: str,
    label: str,
    *,
    exact_rsyslog: bool = False,
) -> tuple[str, ...]:
    keys = [
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
        "runtime_socket",
        "runtime_lock",
        "rsyslog_antiforging_exact_removed",
        "rsyslog_selinux_provenance_removed",
        "completion_residual",
    ]
    if exact_rsyslog:
        keys.extend(
            (
                "rsyslog_siem_exact_removed",
                "rsyslog_waf_bridge_exact_removed",
                "rsyslog_provenance_removed",
                "rsyslog_configuration_valid",
                "rsyslog_reactivated",
            )
        )
    else:
        keys.extend(
            (
                "rsyslog_siem_residual",
                "rsyslog_waf_bridge_residual",
                "rsyslog_provenance_residual",
            )
        )
    keys.extend(
        (
            "cron_d_owned",
            "cron_d_pending",
            "root_crontab_bytes",
            "root_crontab_legacy_residual",
        )
    )
    return tuple(f"{scenario}.{label}.generated.{key}" for key in keys)


def _generated_rsyslog_pre_removal_event_checks(
    scenario: str,
    label: str,
) -> tuple[str, ...]:
    return tuple(
        f"{scenario}.{label}.generated.{key}"
        for key in (
            "rsyslog_siem_exact_generated",
            "rsyslog_waf_bridge_exact_generated",
            "rsyslog_provenance_exact",
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
    if scenario == "remove":
        return ("fresh",)
    if scenario == "purge":
        return ("fresh",)
    raise LifecycleLabError(f"unsupported inventory scenario: {scenario!r}")


def _preparation_event_checks(
    scenario: str,
    *,
    candidate_version: str | None = None,
) -> tuple[str, ...]:
    checks = [
        f"{scenario}.platform.uname",
        f"{scenario}.extract.previous",
        f"{scenario}.extract.candidate",
        f"{scenario}.metadata.previous.sha256",
        f"{scenario}.metadata.candidate.sha256",
        f"{scenario}.metadata.previous.version",
        f"{scenario}.metadata.candidate.version",
        f"{scenario}.metadata.previous.architecture",
        f"{scenario}.metadata.candidate.architecture",
    ]
    if candidate_version is not None and _uses_geoip_data_license_payload(
        "candidate", candidate_version
    ):
        checks.append(f"{scenario}.metadata.candidate.license")
    checks.extend(
        (
            f"{scenario}.metadata.previous.manager_manifest",
            f"{scenario}.metadata.previous.payload_inventory",
            f"{scenario}.metadata.candidate.manager_manifest",
            f"{scenario}.metadata.candidate.payload_inventory",
            f"{scenario}.metadata.candidate.runtime_dependencies",
        )
    )
    return tuple(checks)


def expected_event_checks(
    family: str,
    scenario: str,
    *,
    candidate_version: str | None = None,
) -> tuple[str, ...]:
    """Return the exact ordered evidence contract for one lifecycle scenario."""

    if family not in EXPECTED_SCENARIOS or scenario not in EXPECTED_SCENARIOS[family]:
        raise LifecycleLabError(
            f"unsupported lifecycle evidence coordinate: {family}/{scenario}"
        )

    checks = list(
        _preparation_event_checks(
            scenario,
            candidate_version=candidate_version,
        )
    )

    def installed(
        command: str,
        label: str,
        before_phase_checks: tuple[str, ...] = (),
    ) -> None:
        checks.append(f"{scenario}.{command}")
        checks.append(f"{scenario}.{command}.maintainer_script")
        checks.extend(before_phase_checks)
        checks.extend(_installed_phase_event_checks(scenario, label))
        checks.extend(_state_event_checks(scenario, label))

    def deb_removed(label: str) -> None:
        checks.extend(
            _generated_rsyslog_pre_removal_event_checks(
                scenario,
                label,
            )
        )
        checks.extend(
            (
                f"{scenario}.{label}",
                f"{scenario}.{label}.database",
                f"{scenario}.{label}.payload_inventory",
                f"{scenario}.{label}.service_manager_calls",
            )
        )
        checks.extend(
            _generated_cleanup_event_checks(
                scenario,
                label,
                exact_rsyslog=True,
            )
        )
        checks.extend(_state_event_checks(scenario, label))
        checks.extend(
            f"{scenario}.{label}.state.log.{attribute}"
            for attribute in ("type", "hash", "mode", "owner")
        )
        checks.extend(
            f"{scenario}.{label}.state.deferred_purge_marker.{attribute}"
            for attribute in ("type", "hash", "mode", "owner", "links")
        )

    if scenario == "upgrade-rollback":
        checks.append(f"{scenario}.preinstall.networkless_config")
        installed(
            "install.previous",
            "previous",
            (f"{scenario}.previous.networkless_config_preserved",),
        )
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

    if family == "deb" and scenario == "remove":
        deb_removed("remove")
        installed(
            "reinstall-after-remove.candidate",
            "reinstall-after-remove",
        )
        checks.extend(
            f"{scenario}.reinstall-after-remove.state.log.{attribute}"
            for attribute in ("type", "hash", "mode", "owner")
        )
        checks.append(
            f"{scenario}.reinstall-after-remove.state.deferred_purge_marker"
        )
        deb_removed("remove-before-purge")
        checks.extend(
            (
                f"{scenario}.purge-after-remove",
                f"{scenario}.purge-after-remove.database",
                f"{scenario}.purge-after-remove.payload_inventory",
            )
        )
        checks.extend(
            f"{scenario}.purge-after-remove.state.{key}"
            for key in (
                "opt_root",
                "config_root",
                "data_root",
                "log_root",
            )
        )
        return tuple(checks)

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
    if family in {"deb", "rpm", "apk"}:
        checks.extend(
            f"{scenario}.{removal_label}.state.{key}"
            for key in ("opt_root", "config_root", "data_root", "log_root")
        )
    if family == "rpm":
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
            "v4.02.8 -> v4.03.2 contract for "
            f"{spec.package_architecture}"
        )
    return forward_only


def is_historical_ubuntu_deb_recovery_pair(
    spec: PlatformSpec, pair: PackagePair
) -> bool:
    expected = HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS
    return (
        spec.family == "deb"
        and spec.distribution == "ubuntu"
        and spec.architecture == "amd64"
        and spec.package_architecture == "amd64"
        and pair.candidate.version
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
        and pair.candidate.path.name
        == f"syswarden_{HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION}_amd64.deb"
        and pair.previous.version
        == HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION
        and pair.previous.path.name == expected["filename"]
        and pair.previous.sha256 == expected["sha256"]
    )


def validate_historical_ubuntu_deb_recovery_pair(
    spec: PlatformSpec, pair: PackagePair
) -> bool:
    if not (
        spec.family == "deb"
        and spec.distribution == "ubuntu"
        and spec.architecture == "amd64"
        and spec.package_architecture == "amd64"
    ):
        return False
    expected = HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS
    historical_binding_touched = (
        pair.candidate.version
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
        or pair.candidate.path.name
        == f"syswarden_{HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION}_amd64.deb"
        or pair.previous.version
        == HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION
        or pair.previous.path.name == expected["filename"]
        or pair.previous.sha256 == expected["sha256"]
    )
    exact = is_historical_ubuntu_deb_recovery_pair(spec, pair)
    if historical_binding_touched and not exact:
        raise LifecycleLabError(
            "historical Ubuntu DEB recovery must be the exact byte-bound "
            "v4.03.2 -> v4.03.3 amd64 contract"
        )
    return exact


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProcessSecurityEvidence:
    cap_inheritable: str
    cap_permitted: str
    cap_effective: str
    cap_bounding: str
    cap_ambient: str
    no_new_privileges: bool


@dataclass(frozen=True)
class IDMapRange:
    inside_id: int
    outside_id: int
    length: int


@dataclass(frozen=True)
class SetprivEvidence:
    path: str
    file_identity: str
    sha256: str
    package_name: str
    package_version: str
    package_architecture: str


@dataclass(frozen=True)
class ProductServicesEvidence:
    expectation: str
    core_load_state: str
    core_fragment_path: str | None
    core_enabled_state: str
    core_active_state: str
    core_main_pid: int | None
    core_executable_path: str | None
    core_executable_identity: str | None
    core_pidfile_identity: str | None
    core_process_security: ProcessSecurityEvidence | None
    firewall_load_state: str
    firewall_fragment_path: str | None
    firewall_enabled_state: str
    firewall_active_state: str
    firewall_main_pid: int | None


@dataclass(frozen=True)
class RuntimeSnapshot:
    capture_count: int
    pid1_comm: str
    pid1_exe: str
    pid1_starttime_ticks: int
    pid1_process_security: ProcessSecurityEvidence
    attestation_process_security: ProcessSecurityEvidence
    pid1_uid_map: tuple[IDMapRange, ...]
    pid1_gid_map: tuple[IDMapRange, ...]
    setpriv: SetprivEvidence | None
    manager_state: str
    manager_runtime: str
    cron_enabled: bool
    cron_active: bool
    cron_main_pid: int
    cron_executable_path: str
    cron_executable_identity: str
    cron_fragment_path: str
    cron_fragment_identity: str
    cron_dropin_paths: tuple[str, ...]
    cron_package_name: str
    cron_package_version: str
    cron_package_architecture: str
    cron_fragment_package_name: str
    cron_fragment_package_version: str
    cron_fragment_package_architecture: str
    rsyslog_enabled: bool
    rsyslog_active: bool
    rsyslog_main_pid: int
    dummy_interface: str
    product_services: ProductServicesEvidence


@dataclass(frozen=True)
class RuntimeMountEvidence:
    role: str
    destination: str
    read_only: bool


@dataclass(frozen=True)
class RuntimeIsolationEvidence:
    privileged: bool
    network_mode: str
    pid_mode: str
    ipc_mode: str
    uts_mode: str
    userns_mode: str
    cgroup_mode: str
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    lifecycle_exec_launcher: tuple[str, ...]
    devices: tuple[str, ...]
    security_opts: tuple[str, ...]
    stop_signal: str
    tmpfs: dict[str, tuple[str, ...]]
    mounts: tuple[RuntimeMountEvidence, ...]


@dataclass(frozen=True)
class RuntimeRestartEvidence:
    performed: bool
    command_exit_code: int | None
    previous_pid1_starttime_ticks: int | None
    distinct: bool | None


@dataclass(frozen=True)
class RuntimeBootEvidence:
    invocation: str
    boot_command_exit_code: int
    restart: RuntimeRestartEvidence
    pre_exec: RuntimeSnapshot
    lifecycle_exec_security: ProcessSecurityEvidence
    script_exec_exit_code: int
    restart_state: str | None
    post_exec: RuntimeSnapshot


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


def require_private_directory(path: Path, label: str) -> Path:
    absolute = require_real_directory(path, label)
    try:
        resolved = absolute.resolve(strict=True)
        metadata = absolute.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot resolve {label} {absolute}: {exc}") from exc
    if resolved != absolute:
        raise LifecycleLabError(
            f"{label} must not contain symlinked path components: {absolute}"
        )
    if metadata.st_uid != os.geteuid():
        raise LifecycleLabError(
            f"{label} must be owned by effective uid {os.geteuid()}: {absolute}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise LifecycleLabError(f"{label} must have mode 0700: {absolute}")
    return absolute


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
    return spec.cell_id, spec.architecture


def platform_slug(spec: PlatformSpec) -> str:
    slug = f"{spec.cell_id.casefold()}-{spec.architecture}"
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug) is None:
        raise LifecycleLabError(f"unsafe platform coordinate: {slug!r}")
    return slug


def expected_cron_executable(spec: PlatformSpec) -> str:
    if spec.family == "deb":
        return "/usr/sbin/cron"
    if spec.distribution == "fedora":
        if spec.family != "rpm":
            raise LifecycleLabError("Fedora cron executable requires the RPM family")
        return "/usr/bin/crond"
    return "/usr/sbin/crond"


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
        expected_spec = next(
            (
                item
                for item in DEFAULT_PLATFORMS
                if platform_coordinate(item) == coordinate
            ),
            None,
        )
        if expected_spec is None:
            raise LifecycleLabError(
                f"unsupported package lifecycle matrix cell: {coordinate!r}"
            )
        if spec.version != expected_spec.version:
            raise LifecycleLabError(
                f"matrix cell version mismatch for {coordinate}: expected "
                f"{expected_spec.version!r}, found {spec.version!r}"
            )
        expected_platform = f"linux/{spec.architecture}"
        if spec.podman_platform != expected_platform:
            raise LifecycleLabError(
                f"Podman platform mismatch for {coordinate}: expected {expected_platform!r}, "
                f"found {spec.podman_platform!r}"
            )
        expected_uname = "x86_64"
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
        if spec.image != expected_spec.image:
            raise LifecycleLabError(
                f"frozen image identity mismatch for {coordinate}: expected "
                f"{expected_spec.image!r}, found {spec.image!r}"
            )
        if not spec.bootstrap_command.strip() or "\n" in spec.bootstrap_command:
            raise LifecycleLabError(f"invalid bootstrap command for {coordinate}")
        if not spec.purge_semantics.strip():
            raise LifecycleLabError(f"missing purge semantics for {coordinate}")
        if spec != expected_spec:
            raise LifecycleLabError(
                f"matrix cell runtime contract differs from the frozen "
                f"definition for {coordinate}"
            )
        if spec != expected_spec:
            raise LifecycleLabError(
                f"platform specification differs from frozen matrix cell {coordinate}"
            )
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
        pair = pairs[package_coordinate(spec)]
        validate_forward_only_apk_pair(spec, pair)
        validate_historical_ubuntu_deb_recovery_pair(spec, pair)
    return candidate_root, previous_root, pairs


def historical_transition_bootstrap(
    spec: PlatformSpec, previous_version: str
) -> str:
    parse_syswarden_version(previous_version)
    if spec.family != "rpm" or previous_version != HISTORICAL_RPM_TRANSITION_VERSION:
        return ""
    command = HISTORICAL_RPM_TRANSITION_BOOTSTRAPS.get(spec.distribution)
    if command is None:
        raise LifecycleLabError(
            "unsupported RPM distribution for the exact v4.03.2 transition "
            f"bootstrap: {spec.distribution!r}"
        )
    return f"RUN {command}\n"


def build_containerfile(spec: PlatformSpec) -> str:
    validate_image_reference(spec.image)
    helper_encoded = base64.b64encode(LAB_NETWORK_HELPER.encode("utf-8")).decode(
        "ascii"
    )
    helper_step = (
        "RUN install -d -m 0755 /usr/local/libexec && "
        f"printf '%s' {shlex.quote(helper_encoded)} | base64 -d > "
        "/usr/local/libexec/syswarden-lab-network && "
        "chmod 0755 /usr/local/libexec/syswarden-lab-network\n"
    )
    if spec.family == "deb":
        unit_encoded = base64.b64encode(
            SYSTEMD_LAB_NETWORK_UNIT.encode("utf-8")
        ).decode("ascii")
        init_contract = (
            helper_step
            + f"RUN printf '%s' {shlex.quote(unit_encoded)} | base64 -d > "
            "/etc/systemd/system/syswarden-lab-network.service && "
            "chmod 0644 /etc/systemd/system/syswarden-lab-network.service\n"
            "RUN systemctl enable syswarden-lab-network.service cron.service "
            "rsyslog.service\n"
            "STOPSIGNAL SIGRTMIN+3\n"
            'CMD ["/sbin/init"]\n'
        )
    elif spec.family == "rpm":
        unit_encoded = base64.b64encode(
            SYSTEMD_LAB_NETWORK_UNIT.encode("utf-8")
        ).decode("ascii")
        fedora_masks = ""
        if spec.distribution == "fedora":
            fedora_masks = "RUN systemctl mask " + " ".join(
                FEDORA_LAB_MASK_TARGETS
            ) + "\n"
        init_contract = (
            helper_step
            + f"RUN printf '%s' {shlex.quote(unit_encoded)} | base64 -d > "
            "/etc/systemd/system/syswarden-lab-network.service && "
            "chmod 0644 /etc/systemd/system/syswarden-lab-network.service\n"
            "RUN systemctl enable syswarden-lab-network.service crond.service "
            "rsyslog.service\n"
            + fedora_masks
            + "STOPSIGNAL SIGRTMIN+3\n"
            + 'CMD ["/sbin/init"]\n'
        )
    elif spec.family == "apk":
        try:
            rc_conf_append = base64.b64decode(
                ALPINE_RC_CONF_APPEND_BASE64, validate=True
            )
        except (ValueError, TypeError) as exc:
            raise LifecycleLabError(
                "Alpine OpenRC configuration payload is not canonical base64"
            ) from exc
        if (
            rc_conf_append
            != b'\nrc_sys="podman"\nrc_cgroup_mode="legacy"\n'
            or hashlib.sha256(rc_conf_append).hexdigest()
            != ALPINE_RC_CONF_APPEND_SHA256
        ):
            raise LifecycleLabError(
                "Alpine OpenRC configuration payload is not exact"
            )
        provider_encoded = base64.b64encode(
            ALPINE_LAB_NETWORK_PROVIDER.encode("utf-8")
        ).decode("ascii")
        rsyslog_readiness_encoded = base64.b64encode(
            ALPINE_RSYSLOG_READINESS_PROVIDER.encode("utf-8")
        ).decode("ascii")
        init_contract = (
            "RUN apk info -e 'openrc="
            + ALPINE_OPENRC_VERSION
            + "' && "
            "test -f /etc/rc.conf && test ! -L /etc/rc.conf && "
            "test \"$(sha256sum /etc/rc.conf | awk '{ print $1 }')\" = "
            + ALPINE_RC_CONF_PRE_SHA256
            + " && "
            "test \"$(awk '/^[[:space:]]*rc_sys[[:space:]]*=/ { count++ } END { print count + 0 }' /etc/rc.conf)\" -eq 0 && "
            "test \"$(awk '/^[[:space:]]*rc_cgroup_mode[[:space:]]*=/ { count++ } END { print count + 0 }' /etc/rc.conf)\" -eq 0 && "
            "printf '%s' "
            + ALPINE_RC_CONF_APPEND_BASE64
            + " | base64 -d >> /etc/rc.conf && "
            "test \"$(sha256sum /etc/rc.conf | awk '{ print $1 }')\" = "
            + ALPINE_RC_CONF_POST_SHA256
            + " && "
            "test \"$(grep -Fxc 'rc_sys=\"podman\"' /etc/rc.conf)\" -eq 1 && "
            "test \"$(grep -Fxc 'rc_cgroup_mode=\"legacy\"' /etc/rc.conf)\" -eq 1 && "
            "test -f /etc/init.d/hostname && test ! -L /etc/init.d/hostname && "
            "test \"$(sha256sum /etc/init.d/hostname | awk '{ print $1 }')\" = "
            + ALPINE_HOSTNAME_INIT_PRE_SHA256
            + " && "
            "test \"$(grep -Ec '^[[:space:]]*keyword -prefix -lxc -docker$' /etc/init.d/hostname)\" -eq 1 && "
            "sed -i 's/^\\([[:space:]]*keyword -prefix -lxc -docker\\)$/\\1 -podman/' /etc/init.d/hostname && "
            "test \"$(sha256sum /etc/init.d/hostname | awk '{ print $1 }')\" = "
            + ALPINE_HOSTNAME_INIT_POST_SHA256
            + "\n"
            + helper_step
            + f"RUN printf '%s' {shlex.quote(provider_encoded)} | base64 -d > "
            "/etc/init.d/syswarden-lab-net && "
            "chmod 0755 /etc/init.d/syswarden-lab-net\n"
            + f"RUN printf '%s' {shlex.quote(rsyslog_readiness_encoded)} | base64 -d > "
            "/etc/init.d/syswarden-lab-rsyslog-ready && "
            "chmod 0755 /etc/init.d/syswarden-lab-rsyslog-ready\n"
            "RUN rc-update add syswarden-lab-net default && "
            "rc-update add cronie default && rc-update add rsyslog default && "
            "rc-update add syswarden-lab-rsyslog-ready default && "
            "rc-update -u\n"
            "STOPSIGNAL SIGINT\n"
            'CMD ["/sbin/openrc-init"]\n'
        )
    else:
        raise LifecycleLabError(
            f"unsupported package family for real-init image: {spec.family!r}"
        )
    return (
        f"FROM {spec.image}\n"
        "ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 container=podman\n"
        f"RUN {spec.bootstrap_command}\n"
        + (RPM_COMMON_IMAGE_DEPENDENCY_GUARD if spec.family == "rpm" else "")
        + init_contract
    )


def build_historical_transition_containerfile(
    spec: PlatformSpec,
    previous_version: str,
    common_image: str,
) -> str | None:
    if re.fullmatch(
        r"localhost/syswarden-lifecycle-[a-z0-9-]+-[0-9a-f]{32}",
        common_image,
    ) is None:
        raise LifecycleLabError(
            f"unsafe common lifecycle image reference: {common_image!r}"
        )
    transition_bootstrap = historical_transition_bootstrap(spec, previous_version)
    if not transition_bootstrap:
        return None
    return f"FROM {common_image}\n{transition_bootstrap}"


LIFECYCLE_SCRIPT = r'''#!/bin/sh
# ShellCheck cannot infer function calls passed through run_step.
# shellcheck disable=SC2317
set -u

[ -r /lab/package-webtui-retirement.sh ] || exit 90
# shellcheck source=package_webtui_retirement.sh
. /lab/package-webtui-retirement.sh

[ -r /etc/os-release ] || exit 92
case "${EXPECTED_DISTRIBUTION_VERSION}" in
    ''|*[!0-9.]*|.*|*..*|*.) exit 92 ;;
esac
ACTUAL_DISTRIBUTION_ID="$(
    . /etc/os-release
    printf '%s' "${ID-}"
)" || exit 92
ACTUAL_DISTRIBUTION_VERSION="$(
    . /etc/os-release
    printf '%s' "${VERSION_ID-}"
)" || exit 92
[ "${ACTUAL_DISTRIBUTION_ID}" = "${EXPECTED_DISTRIBUTION}" ] || exit 92
case "${ACTUAL_DISTRIBUTION_VERSION}" in
    ''|*[!0-9.]*|.*|*..*|*.) exit 92 ;;
esac
case "${EXPECTED_DISTRIBUTION}" in
    debian|ubuntu|fedora)
        [ "${ACTUAL_DISTRIBUTION_VERSION}" = "${EXPECTED_DISTRIBUTION_VERSION}" ] || exit 92
        ;;
    almalinux)
        [ "${ACTUAL_DISTRIBUTION_VERSION%%.*}" = "${EXPECTED_DISTRIBUTION_VERSION}" ] || exit 92
        ;;
    alpine)
        actual_distribution_tail="${ACTUAL_DISTRIBUTION_VERSION#*.}"
        actual_distribution_major_minor="${ACTUAL_DISTRIBUTION_VERSION%%.*}.${actual_distribution_tail%%.*}"
        [ "${actual_distribution_major_minor}" = "${EXPECTED_DISTRIBUTION_VERSION}" ] || exit 92
        ;;
    *) exit 92 ;;
esac

RESULT_FILE="/results/events.tsv"
COMMAND_LOG="/results/commands.log"
RESTART_STATE_FILE="/results/restart-state"
OPERATOR_STATE_FILE="/results/operator-state"
OPERATOR_CRON_FILE="/results/operator-cron-lines"
PERSIST_ROOT="/results/runtime-state"
FAILURES=0
PREFIX="${SCENARIO}"
INVOCATION="initial"

if [ "${SCENARIO}" = "upgrade-rollback" ] && [ -f "${RESTART_STATE_FILE}" ]; then
    INVOCATION="$(sed -n '1p' "${RESTART_STATE_FILE}")"
    printf 'CONTAINER RESTART %s\n' "${INVOCATION}" >> "${COMMAND_LOG}"
else
    : > "${RESULT_FILE}"
    : > "${COMMAND_LOG}"
    rm -rf "${PERSIST_ROOT}"
    mkdir -m 0700 "${PERSIST_ROOT}" || exit 91
    rm -f "${RESTART_STATE_FILE}" "${OPERATOR_STATE_FILE}" "${OPERATOR_CRON_FILE}"
fi
[ -d "${PERSIST_ROOT}" ] && [ ! -L "${PERSIST_ROOT}" ] || exit 91

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

is_exact_historical_ubuntu_deb_recovery() {
    syswarden_historical_check="$1"
    syswarden_historical_package="$2"
    [ "${PACKAGE_FAMILY}" = deb ] || return 1
    [ "${SCENARIO}" = upgrade-rollback ] || return 1
    [ "${EXPECTED_DISTRIBUTION}" = ubuntu ] || return 1
    [ "${EXPECTED_PACKAGE_ARCHITECTURE}" = amd64 ] || return 1
    [ "${HISTORICAL_UBUNTU_DEB_RECOVERY}" = 1 ] || return 1
    [ "${FORWARD_ONLY_APK_TRANSITION}" = 0 ] || return 1
    [ "${syswarden_historical_check}" = rollback.previous ] || return 1
    [ "${syswarden_historical_package}" = "${PREVIOUS_PACKAGE}" ] || return 1
    [ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ] || return 1
    [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.3 ] || return 1
    [ "${PREVIOUS_PACKAGE##*/}" = syswarden_4.03.2_amd64.deb ] || return 1
    [ "${CANDIDATE_PACKAGE##*/}" = syswarden_4.03.3_amd64.deb ] || return 1
    [ -f "${PREVIOUS_PACKAGE}" ] && [ ! -L "${PREVIOUS_PACKAGE}" ] || return 1
    [ -f "${CANDIDATE_PACKAGE}" ] && [ ! -L "${CANDIDATE_PACKAGE}" ] || return 1
    [ "${EXPECTED_PREVIOUS_SHA256}" = e499370fbed0e40968a6377f4e3cd9a8718993352deccc181a4fb43333289019 ] || return 1
    [ "$(hash_file "${PREVIOUS_PACKAGE}" 2>/dev/null || true)" = "${EXPECTED_PREVIOUS_SHA256}" ] || return 1
    [ "$(hash_file "${CANDIDATE_PACKAGE}" 2>/dev/null || true)" = "${EXPECTED_CANDIDATE_SHA256}" ]
}

historical_ubuntu_deb_diagnostic_is_exact() {
    syswarden_historical_diagnostic="$1"
    [ -f "${syswarden_historical_diagnostic}" ] && \
        [ ! -L "${syswarden_historical_diagnostic}" ] || return 1
    [ "$(LC_ALL=C grep -Fxc -- \
        '[SYSWARDEN] v4.03.2 native installation complete.' \
        "${syswarden_historical_diagnostic}" 2>/dev/null || true)" = 1 ] || return 1
    [ "$(LC_ALL=C grep -Fxc -- \
        'dpkg: error processing package syswarden (--install):' \
        "${syswarden_historical_diagnostic}" 2>/dev/null || true)" = 1 ] || return 1
    [ "$(LC_ALL=C grep -Fxc -- \
        ' installed syswarden package post-installation script subprocess returned error exit status 1' \
        "${syswarden_historical_diagnostic}" 2>/dev/null || true)" = 1 ] || return 1
    ! grep -Eq '(^|[[:space:]])panic:|fatal error:|SIGSEGV|segmentation violation' \
        "${syswarden_historical_diagnostic}"
}

historical_ubuntu_deb_package_state() {
    LC_ALL=C dpkg-query --show \
        '--showformat=${db:Status-Abbrev}|${Status}|${Version}|${Architecture}' \
        syswarden 2>/dev/null
}

historical_ubuntu_deb_cli_payload_is_exact() {
    syswarden_historical_cli=/opt/syswarden/bin/syswarden-cli
    syswarden_historical_expected_cli="${PERSIST_ROOT}/expected-previous/opt/syswarden/bin/syswarden-cli"
    [ -f "${syswarden_historical_cli}" ] && \
        [ ! -L "${syswarden_historical_cli}" ] && \
        [ -x "${syswarden_historical_cli}" ] || return 1
    [ -f "${syswarden_historical_expected_cli}" ] && \
        [ ! -L "${syswarden_historical_expected_cli}" ] || return 1
    [ "$(stat -c '%f:%u:%g:%a:%h' "${syswarden_historical_cli}" 2>/dev/null || true)" = \
        81e8:0:0:750:1 ] || return 1
    syswarden_historical_expected_cli_sha="$({
        hash_file "${syswarden_historical_expected_cli}" 2>/dev/null || true
    })"
    [ -n "${syswarden_historical_expected_cli_sha}" ] || return 1
    [ "$(hash_file "${syswarden_historical_cli}" 2>/dev/null || true)" = \
        "${syswarden_historical_expected_cli_sha}" ]
}

# Return 0 only for an empty exact CLI inventory, 1 while the exact installed
# CLI inode is stable and running, and 2 if that exact identity becomes
# unreadable without the process disappearing.
historical_ubuntu_deb_cli_process_inventory_empty() {
    syswarden_historical_proc_root="$1"
    syswarden_historical_cli="$2"
    [ -d "${syswarden_historical_proc_root}" ] && \
        [ ! -L "${syswarden_historical_proc_root}" ] || return 2
    syswarden_historical_expected_identity="$(
        stat -L -c '%d:%i' "${syswarden_historical_cli}" 2>/dev/null
    )" || return 2
    for syswarden_historical_proc in "${syswarden_historical_proc_root}"/[0-9]*; do
        [ -d "${syswarden_historical_proc}" ] || continue
        syswarden_historical_identity_before="$(
            stat -L -c '%d:%i' "${syswarden_historical_proc}/exe" 2>/dev/null || true
        )"
        [ "${syswarden_historical_identity_before}" = \
            "${syswarden_historical_expected_identity}" ] || continue
        syswarden_historical_start_before="$(
            syswarden_webtui_process_starttime \
                "${syswarden_historical_proc}/stat" 2>/dev/null || true
        )"
        if [ -z "${syswarden_historical_start_before}" ]; then
            [ ! -d "${syswarden_historical_proc}" ] && continue
            return 2
        fi
        syswarden_historical_identity_after="$(
            stat -L -c '%d:%i' "${syswarden_historical_proc}/exe" 2>/dev/null || true
        )"
        syswarden_historical_start_after="$(
            syswarden_webtui_process_starttime \
                "${syswarden_historical_proc}/stat" 2>/dev/null || true
        )"
        if [ -z "${syswarden_historical_identity_after}" ] || \
           [ -z "${syswarden_historical_start_after}" ]; then
            [ ! -d "${syswarden_historical_proc}" ] && continue
            return 2
        fi
        if [ "${syswarden_historical_identity_after}" != \
             "${syswarden_historical_expected_identity}" ]; then
            continue
        fi
        return 1
    done
    return 0
}

historical_ubuntu_deb_wait_for_cli_quiescence() {
    syswarden_historical_proc_root="$1"
    syswarden_historical_cli="$2"
    syswarden_historical_wait_attempt=0
    syswarden_historical_clean_scans=0
    while [ "${syswarden_historical_wait_attempt}" -lt 20 ]; do
        if historical_ubuntu_deb_cli_process_inventory_empty \
            "${syswarden_historical_proc_root}" "${syswarden_historical_cli}"; then
            syswarden_historical_clean_scans=$((syswarden_historical_clean_scans + 1))
            [ "${syswarden_historical_clean_scans}" -lt 2 ] || return 0
        else
            syswarden_historical_inventory_status=$?
            case "${syswarden_historical_inventory_status}" in
                1|2) ;;
                *) return 1 ;;
            esac
            syswarden_historical_clean_scans=0
        fi
        syswarden_historical_wait_attempt=$((syswarden_historical_wait_attempt + 1))
        sleep 0.05 || return 1
    done
    return 1
}

recover_exact_historical_ubuntu_deb_postinstall() {
    syswarden_historical_check="$1"
    syswarden_historical_package="$2"
    syswarden_historical_diagnostic="$3"
    is_exact_historical_ubuntu_deb_recovery \
        "${syswarden_historical_check}" "${syswarden_historical_package}" || return 1
    historical_ubuntu_deb_diagnostic_is_exact \
        "${syswarden_historical_diagnostic}" || return 1
    [ "$(historical_ubuntu_deb_package_state 2>/dev/null || true)" = \
        'iF |install ok half-configured|4.03.2|amd64' ] || return 1
    historical_ubuntu_deb_cli_payload_is_exact || return 1
    historical_ubuntu_deb_wait_for_cli_quiescence \
        /proc /opt/syswarden/bin/syswarden-cli || return 1
    syswarden_verify_webtui_retirement / || return 1
    printf '%s\n' \
        'HISTORICAL v4.03.2 POSTINSTALL RECOVERY: one exact dpkg reconfiguration' \
        >> "${syswarden_historical_diagnostic}" || return 1
    DEBIAN_FRONTEND=noninteractive dpkg --configure syswarden \
        >> "${syswarden_historical_diagnostic}" 2>&1 || return 1
    [ "$(historical_ubuntu_deb_package_state 2>/dev/null || true)" = \
        'ii |install ok installed|4.03.2|amd64' ] || return 1
    historical_ubuntu_deb_cli_payload_is_exact || return 1
    syswarden_verify_webtui_retirement /
}

run_install_step() {
    check="$1"
    package="$2"
    diagnostic="/tmp/syswarden-maintainer-${check}"
    printf 'COMMAND %s\n' "${check}" >> "${COMMAND_LOG}"
    if install_package "${package}" "${check}" > "${diagnostic}" 2>&1; then
        command_rc=0
        command_detail="command completed"
    else
        command_rc=$?
        if [ "${command_rc}" -eq 1 ] && \
           [ "${HISTORICAL_UBUNTU_DEB_RECOVERY:-0}" = 1 ] && \
           recover_exact_historical_ubuntu_deb_postinstall \
               "${check}" "${package}" "${diagnostic}"; then
            command_rc=0
            command_detail="exact byte-bound v4.03.2 Ubuntu DEB postinstall race recovered by one bounded dpkg reconfiguration"
        else
            command_detail="command failed with exit code ${command_rc}"
        fi
    fi
    if [ "${command_rc}" -eq 0 ]; then
        record pass "${PREFIX}.${check}" "${command_detail}"
    else
        record fail "${PREFIX}.${check}" "${command_detail}"
    fi
    sed 's/^\([[:space:]]*Password:[[:space:]]*\)[0-9a-f]\{32\}$/\1[REDACTED]/' \
        "${diagnostic}" >> "${COMMAND_LOG}"
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

package_license() {
    package="$1"
    case "${PACKAGE_FAMILY}" in
        deb)
            dpkg-deb --field "${package}" License
            ;;
        rpm)
            rpm -qp --queryformat '%{LICENSE}' "${package}"
            ;;
        apk)
            members="$(tar --list --file "${package}")" || return 1
            member_count="$(
                printf '%s\n' "${members}" | \
                    awk '$0 == ".PKGINFO" { count++ } END { print count + 0 }'
            )" || return 1
            [ "${member_count}" -eq 1 ] || return 1
            metadata="$(tar --extract --to-stdout --file "${package}" .PKGINFO)" || \
                return 1
            license_count="$(
                printf '%s\n' "${metadata}" | \
                    awk '$0 ~ /^license = / { count++ } END { print count + 0 }'
            )" || return 1
            [ "${license_count}" -eq 1 ] || return 1
            printf '%s\n' "${metadata}" | sed -n 's/^license = //p'
            ;;
        *)
            return 2
            ;;
    esac
}

expected_runtime_dependencies() {
    case "${PACKAGE_FAMILY}" in
        deb)
            printf '%s\n' apt-listchanges bash-completion cron curl e2fsprogs ipset jq nftables procps qrencode rsyslog unattended-upgrades wget wireguard-tools
            ;;
        rpm)
            printf '%s\n' bash-completion checkpolicy cronie curl dnf-automatic e2fsprogs ipset jq nftables policycoreutils-python-utils procps-ng rsyslog wget wireguard-tools
            ;;
        apk)
            printf '%s\n' bash-completion cronie cronie-openrc curl e2fsprogs-extra jq libqrencode-tools nftables openrc procps-ng rsyslog rsyslog-uxsock shadow wget wireguard-tools
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

package_uses_legacy_completion_payload() {
    artifact_role="$1"
    case "${artifact_role}" in
        candidate)
            if [ "${PACKAGE_FAMILY}" = apk ] && \
               [ "${FORWARD_ONLY_APK_TRANSITION}" = 1 ] && \
               [ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ] && \
               [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ]; then
                return 0
            fi
            return 1
            ;;
        previous)
            if [ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ]; then
                return 0
            fi
            if [ "${PACKAGE_FAMILY}" = apk ] && \
               [ "${FORWARD_ONLY_APK_TRANSITION}" = 1 ] && \
               [ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ] && \
               [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ]; then
                return 0
            fi
            return 1
            ;;
        *)
            return 2
            ;;
    esac
}

package_uses_geoip_data_license_payload() {
    artifact_role="$1"
    case "${artifact_role}" in
        candidate) artifact_version="${EXPECTED_CANDIDATE_VERSION}" ;;
        previous) artifact_version="${EXPECTED_PREVIOUS_VERSION}" ;;
        *) return 2 ;;
    esac
    artifact_major="${artifact_version%%.*}"
    artifact_remainder="${artifact_version#*.}"
    artifact_minor="${artifact_remainder%%.*}"
    case "${artifact_major}:${artifact_minor}" in
        *[!0-9:]*|:*) return 2 ;;
    esac
    [ "${artifact_major}" -gt 4 ] || {
        [ "${artifact_major}" -eq 4 ] && [ "${artifact_minor}" -ge 4 ]
    }
}

validate_manifest_contract() {
    manifest="$1"
    artifact_role="$2"
    case "${artifact_role}" in candidate|previous) ;; *) return 1 ;; esac
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
    legacy_completion_payload=0
    if package_uses_legacy_completion_payload "${artifact_role}"; then
        legacy_completion_payload=1
        required_manifest_path "${manifest}" \
            /usr/share/bash-completion/completions/syswarden && return 1
    else
        legacy_completion_rc=$?
        [ "${legacy_completion_rc}" -eq 1 ] || return 1
        required_manifest_path "${manifest}" \
            /usr/share/bash-completion/completions/syswarden || return 1
    fi
    geoip_data_license_payload=0
    if package_uses_geoip_data_license_payload "${artifact_role}"; then
        geoip_data_license_payload=1
        required_manifest_path "${manifest}" \
            /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt || return 1
        required_manifest_path "${manifest}" \
            /usr/share/doc/syswarden/LICENSE.txt || return 1
    else
        geoip_data_license_rc=$?
        [ "${geoip_data_license_rc}" -eq 1 ] || return 1
        required_manifest_path "${manifest}" \
            /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt && return 1
        required_manifest_path "${manifest}" \
            /usr/share/doc/syswarden/LICENSE.txt && return 1
    fi

    case "${PACKAGE_FAMILY}" in
        deb)
            if [ "${legacy_completion_payload}" -eq 1 ]; then
                allowed='^/(opt|opt/syswarden|opt/syswarden/bin|usr|usr/local|usr/local/bin|usr/share|usr/share/doc|usr/share/doc/syswarden|usr/share/doc/syswarden/changelog\.gz|opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
                expected_manifest_count=16
            elif [ "${geoip_data_license_payload}" -eq 1 ]; then
                allowed='^/(opt|opt/syswarden|opt/syswarden/bin|usr|usr/local|usr/local/bin|usr/share|usr/share/bash-completion|usr/share/bash-completion/completions|usr/share/bash-completion/completions/syswarden|usr/share/doc|usr/share/doc/syswarden|usr/share/doc/syswarden/(changelog\.gz|GEOIP-DATA-LICENSE\.txt|LICENSE\.txt)|opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
                expected_manifest_count=21
            else
                allowed='^/(opt|opt/syswarden|opt/syswarden/bin|usr|usr/local|usr/local/bin|usr/share|usr/share/bash-completion|usr/share/bash-completion/completions|usr/share/bash-completion/completions/syswarden|usr/share/doc|usr/share/doc/syswarden|usr/share/doc/syswarden/changelog\.gz|opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
                expected_manifest_count=19
            fi
            [ "$(wc -l < "${manifest}" | tr -d ' ')" = \
                "${expected_manifest_count}" ] || return 1
            grep -Ev "${allowed}" "${manifest}" | grep -q . && return 1
            ;;
        apk)
            if [ "${legacy_completion_payload}" -eq 1 ]; then
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?)$'
                expected_manifest_count=6
            elif [ "${geoip_data_license_payload}" -eq 1 ]; then
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/share/bash-completion/completions/syswarden|usr/share/doc/syswarden/(GEOIP-DATA-LICENSE|LICENSE)\.txt)$'
                expected_manifest_count=9
            else
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/share/bash-completion/completions/syswarden)$'
                expected_manifest_count=7
            fi
            [ "$(wc -l < "${manifest}" | tr -d ' ')" = \
                "${expected_manifest_count}" ] || return 1
            grep -Ev "${allowed}" "${manifest}" | grep -q . && return 1
            ;;
        rpm)
            if [ "${legacy_completion_payload}" -eq 1 ]; then
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/lib/\.build-id|usr/lib/\.build-id/[0-9a-f]{2}|usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38})$'
            elif [ "${geoip_data_license_payload}" -eq 1 ]; then
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/share/bash-completion/completions/syswarden|usr/share/doc/syswarden/(GEOIP-DATA-LICENSE|LICENSE)\.txt|usr/lib/\.build-id|usr/lib/\.build-id/[0-9a-f]{2}|usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38})$'
            else
                allowed='^/(opt/syswarden/bin/syswarden-(cli|core|tui)|opt/syswarden/signatures\.json|usr/local/bin/syswarden(-tui)?|usr/share/bash-completion/completions/syswarden|usr/lib/\.build-id|usr/lib/\.build-id/[0-9a-f]{2}|usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38})$'
            fi
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
    artifact_role="$2"
    case "${artifact_role}" in candidate|previous) ;; *) return 1 ;; esac
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-cli file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-cli" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-core file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-core" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/bin/syswarden-tui file 750 "$(awk -F '\t' '$1 == "/opt/syswarden/bin/syswarden-tui" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /opt/syswarden/signatures.json file 640 "$(awk -F '\t' '$1 == "/opt/syswarden/signatures.json" { print $6 }' "${inventory}")" || return 1
    inventory_has_exact_entry "${inventory}" /usr/local/bin/syswarden symlink 777 /opt/syswarden/bin/syswarden-cli || return 1
    inventory_has_exact_entry "${inventory}" /usr/local/bin/syswarden-tui symlink 777 /opt/syswarden/bin/syswarden-tui || return 1
    legacy_completion_payload=0
    if package_uses_legacy_completion_payload "${artifact_role}"; then
        legacy_completion_payload=1
        grep -Fq '/usr/share/bash-completion/completions/syswarden' \
            "${inventory}" && return 1
    else
        legacy_completion_rc=$?
        [ "${legacy_completion_rc}" -eq 1 ] || return 1
        completion_hash="$(awk -F '\t' '$1 == "/usr/share/bash-completion/completions/syswarden" { print $6 }' "${inventory}")"
        inventory_has_exact_entry "${inventory}" /usr/share/bash-completion/completions/syswarden file 644 "${completion_hash}" || return 1
    fi
    if package_uses_geoip_data_license_payload "${artifact_role}"; then
        inventory_has_exact_entry "${inventory}" \
            /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt file 644 \
            a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499 || return 1
        inventory_has_exact_entry "${inventory}" \
            /usr/share/doc/syswarden/LICENSE.txt file 644 \
            3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 || return 1
    else
        geoip_data_license_rc=$?
        [ "${geoip_data_license_rc}" -eq 1 ] || return 1
    fi
    if awk -F '\t' '$2 == "missing" || $2 == "unsupported" { found = 1 } END { exit found ? 0 : 1 }' "${inventory}"; then
        return 1
    fi
    if awk -F '\t' '$2 == "file" && (length($6) != 64 || $6 ~ /[^0-9a-f]/) { exit 1 }' "${inventory}"; then
        :
    else
        return 1
    fi
    if [ "${PACKAGE_FAMILY}" = "deb" ]; then
        required_directories='/opt /opt/syswarden /opt/syswarden/bin /usr /usr/local /usr/local/bin /usr/share /usr/share/doc /usr/share/doc/syswarden'
        if [ "${legacy_completion_payload}" -eq 0 ]; then
            required_directories="${required_directories} /usr/share/bash-completion /usr/share/bash-completion/completions"
        fi
        for directory in ${required_directories}; do
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
    manifest="${PERSIST_ROOT}/manifest-${label}"
    inventory="${PERSIST_ROOT}/inventory-${label}"
    if package_manager_manifest "${package}" "${manifest}" && \
       validate_manifest_contract "${manifest}" "${label}"; then
        record pass "${PREFIX}.metadata.${label}.manager_manifest" "exact native package manifest sha256=$(hash_file "${manifest}")"
    else
        record fail "${PREFIX}.metadata.${label}.manager_manifest" "native package manifest violates its exact family contract"
    fi
    if build_filesystem_inventory "${manifest}" "${expected_root}" "${inventory}" && \
       validate_inventory_contract "${inventory}" "${label}"; then
        record pass "${PREFIX}.metadata.${label}.payload_inventory" "complete payload inventory sha256=$(hash_file "${inventory}")"
    else
        record fail "${PREFIX}.metadata.${label}.payload_inventory" "payload type, mode, owner, link, or content inventory mismatch"
    fi
    if [ "${label}" = "candidate" ]; then
        dependencies="${PERSIST_ROOT}/dependencies-${label}"
        expected_dependencies="${PERSIST_ROOT}/dependencies-${label}.expected"
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

    if [ "${EXPECTED_PACKAGE_ARCHITECTURE}" = x86_64 ]; then
        expected_interp=/lib64/ld-linux-x86-64.so.2
        expected_machine='Advanced Micro Devices X86-64'
    else
        expected_interp=invalid
        expected_machine=invalid
    fi
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

v4032_to_v4033_upgrade_selected() {
    v4032_to_v4033_transition_selected && \
        [ "$(installed_version 2>/dev/null || true)" = 4.03.2 ]
}

attest_v4032_previous_webtui_retirement() {
    previous_webtui_root="${1:-/}"
    previous_webtui_root="${previous_webtui_root%/}"
    previous_webtui_proc_root="${2:-${previous_webtui_root}/proc}"
    previous_webtui_executable="${previous_webtui_root}/opt/syswarden/bin/syswarden-cli"

    v4032_to_v4033_upgrade_selected || return 1
    legacy_webtui_runtime_absent "${previous_webtui_root}" || return 1
    syswarden_verify_no_exact_webtui_process \
        "${previous_webtui_root}" "${previous_webtui_proc_root}" \
        "${previous_webtui_executable}" || return 1
    previous_webtui_ss_stderr="$(
        mktemp /tmp/syswarden-previous-webtui-ss.XXXXXX
    )" || return 1
    for previous_webtui_port in 62027 62028; do
        : > "${previous_webtui_ss_stderr}" || {
            rm -f "${previous_webtui_ss_stderr}"
            return 1
        }
        previous_webtui_ss_output="$(
            ss -H -ltn "sport = :${previous_webtui_port}" \
                2>"${previous_webtui_ss_stderr}"
        )"
        previous_webtui_ss_status=$?
        if [ "${previous_webtui_ss_status}" -ne 0 ] || \
           [ -s "${previous_webtui_ss_stderr}" ] || \
           [ -n "${previous_webtui_ss_output}" ]; then
            rm -f "${previous_webtui_ss_stderr}"
            return 1
        fi
    done
    rm -f "${previous_webtui_ss_stderr}" || return 1
}

alpine_apk_owner_version() {
    syswarden_owner_path="$1"
    syswarden_owner_package="$2"
    syswarden_owner_output="$(LC_ALL=C apk info --who-owns "${syswarden_owner_path}")" || return 1
    printf '%s\n' "${syswarden_owner_output}" | LC_ALL=C awk \
        -v path="${syswarden_owner_path}" \
        -v package="${syswarden_owner_package}" '
        BEGIN { prefix = path " is owned by " package "-" }
        {
            records++
            if (records != 1 || index($0, prefix) != 1) {
                invalid = 1
            }
            version = substr($0, length(prefix) + 1)
            if (version !~ /^[0-9][A-Za-z0-9._+~:-]*$/) {
                invalid = 1
            }
        }
        END {
            if (records != 1 || invalid) {
                exit 1
            }
            print version
        }
    '
}

validate_alpine_cronie_runlevels() {
    syswarden_runlevel_mode="$1"
    LC_ALL=C awk -v mode="${syswarden_runlevel_mode}" '
        $1 == "cronie" {
            records++
            if (NF != 3 || $2 != "|" || $3 != "default") {
                invalid = 1
            }
        }
        END {
            if (invalid || mode == "required" && records != 1 ||
                mode == "preparable" && records > 1 ||
                mode != "required" && mode != "preparable") {
                exit 1
            }
        }
    '
}

capture_alpine_crond_package_snapshot() {
    LC_ALL=C apk info --installed cronie || return 1
    LC_ALL=C apk info --installed cronie-openrc || return 1
    syswarden_crond_path="$(command -v crond)" || return 1
    case "${syswarden_crond_path}" in
        /*) ;;
        *) return 1 ;;
    esac
    case "${syswarden_crond_path}" in
        *[[:space:]]*) return 1 ;;
    esac
    syswarden_crond_target="$(readlink -f "${syswarden_crond_path}")" || return 1
    case "${syswarden_crond_target}" in
        /*) ;;
        *) return 1 ;;
    esac
    case "${syswarden_crond_target}" in
        *[[:space:]]*) return 1 ;;
    esac
    [ "${syswarden_crond_target##*/}" = crond ] || return 1
    syswarden_crond_version="$(alpine_apk_owner_version "${syswarden_crond_target}" cronie)" || return 1
    # Alpine names the OpenRC service "cronie" even though its daemon is crond.
    syswarden_init_version="$(alpine_apk_owner_version /etc/init.d/cronie cronie-openrc)" || return 1
    [ "${syswarden_crond_version}" = "${syswarden_init_version}" ] || return 1
    printf '%s\n' \
        "crond_path=${syswarden_crond_path}" \
        "crond_target=${syswarden_crond_target}" \
        "cronie_version=${syswarden_crond_version}" \
        "openrc_service=cronie" \
        "init_path=/etc/init.d/cronie" \
        "cronie_openrc_version=${syswarden_init_version}"
}

capture_alpine_crond_provider_snapshot() {
    syswarden_package_snapshot="$(capture_alpine_crond_package_snapshot)" || return 1
    LC_ALL=C rc-service --exists cronie || return 1
    syswarden_status_snapshot="$(LC_ALL=C rc-service cronie status 2>&1)" || return 1
    syswarden_runlevel_snapshot="$(LC_ALL=C rc-update show)" || return 1
    printf '%s\n' "${syswarden_runlevel_snapshot}" | validate_alpine_cronie_runlevels required || return 1
    printf '%s\n' \
        "${syswarden_package_snapshot}" \
        "status_begin" \
        "${syswarden_status_snapshot}" \
        "status_end" \
        "runlevels_begin" \
        "${syswarden_runlevel_snapshot}" \
        "runlevels_end"
}

attest_alpine_crond_provider() {
    [ "${PACKAGE_FAMILY}" = apk ] || return 0
    syswarden_provider_first="$(capture_alpine_crond_provider_snapshot)" || return 1
    syswarden_provider_second="$(capture_alpine_crond_provider_snapshot)" || return 1
    [ "${syswarden_provider_first}" = "${syswarden_provider_second}" ] || return 1
}

prepare_service_runtime_fixture() {
    case "${PACKAGE_FAMILY}" in
        deb|rpm) syswarden_runtime_manager=systemd ;;
        apk) syswarden_runtime_manager=openrc ;;
        *) return 1 ;;
    esac
    [ "$(syswarden_classify_service_manager / "${syswarden_runtime_manager}")" = ACTIVE ] || return 1
    case "${PACKAGE_FAMILY}" in
        deb)
            [ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || return 1
            case "$(readlink /proc/1/exe 2>/dev/null || true)" in
                /usr/lib/systemd/systemd|/lib/systemd/systemd) ;;
                *) return 1 ;;
            esac
            [ "$(systemctl is-system-running 2>/dev/null || true)" = running ] || return 1
            [ "$(systemctl is-enabled cron.service 2>/dev/null || true)" = enabled ] || return 1
            [ "$(systemctl is-active cron.service 2>/dev/null || true)" = active ] || return 1
            ;;
        rpm)
            [ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] || return 1
            case "$(readlink /proc/1/exe 2>/dev/null || true)" in
                /usr/lib/systemd/systemd|/lib/systemd/systemd) ;;
                *) return 1 ;;
            esac
            [ "$(systemctl is-system-running 2>/dev/null || true)" = running ] || return 1
            [ "$(systemctl is-enabled crond.service 2>/dev/null || true)" = enabled ] || return 1
            [ "$(systemctl is-active crond.service 2>/dev/null || true)" = active ] || return 1
            ;;
        apk)
            [ "$(cat /proc/1/comm 2>/dev/null || true)" = openrc-init ] || return 1
            [ "$(readlink /proc/1/exe 2>/dev/null || true)" = /sbin/openrc-init ] || return 1
            [ "$(rc-status --runlevel 2>/dev/null || true)" = default ] || return 1
            attest_alpine_crond_provider || return 1
            ;;
    esac
}

# The exact historical AlmaLinux v4.02.8 RPM ignores a failed rsyslog restart.
# In a rootless cgroup that restart can strand a live daemon in failed state.
# This transition-only lab fixture refuses manual stop before that old scriptlet,
# while candidate reload and all active-state assertions remain fully enforced.
rootless_podman_id_map() {
    awk '
        NF != 3 || $1 !~ /^(0|[1-9][0-9]*)$/ ||
            $2 !~ /^(0|[1-9][0-9]*)$/ ||
            $3 !~ /^[1-9][0-9]*$/ { invalid = 1; next }
        NR == 1 {
            if ($1 != 0 || $2 == 0 || $3 != 1) invalid = 1
            next_inside = 1
            next
        }
        {
            if ($1 != next_inside || $2 == 0) invalid = 1
            next_inside += $3
        }
        END { exit (invalid || NR < 2) ? 1 : 0 }
    ' "$1"
}

attest_rootless_podman_systemd_runtime() {
    syswarden_transition_proc_root="${1:-/proc}"
    [ "${container:-}" = podman ] || return 1
    [ "$(cat "${syswarden_transition_proc_root}/1/comm" 2>/dev/null || true)" = systemd ] || return 1
    rootless_podman_id_map "${syswarden_transition_proc_root}/1/uid_map" || return 1
    rootless_podman_id_map "${syswarden_transition_proc_root}/1/gid_map" || return 1
    [ "$(syswarden_classify_service_manager / systemd)" = ACTIVE ]
}

alma_v4028_rpm_transition_selected() {
    [ "${PACKAGE_FAMILY}:${SCENARIO}:${EXPECTED_DISTRIBUTION}" = \
        rpm:upgrade-rollback:almalinux ] && \
        [ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ] && \
        [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ]
}

attest_alma_v4028_previous_rpm_artifact() {
    [ -f "${PREVIOUS_PACKAGE}" ] && [ ! -L "${PREVIOUS_PACKAGE}" ] || return 1
    [ "${PREVIOUS_PACKAGE##*/}" = \
        "syswarden-4.02.8-1.${EXPECTED_PACKAGE_ARCHITECTURE}.rpm" ] || return 1
    [ "$(hash_file "${PREVIOUS_PACKAGE}" 2>/dev/null || true)" = "${EXPECTED_PREVIOUS_SHA256}" ] || return 1
    syswarden_transition_previous_record="$(
        rpm -qp --queryformat '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}' \
            "${PREVIOUS_PACKAGE}" 2>/dev/null
    )" || return 1
    [ "${syswarden_transition_previous_record}" = \
        "syswarden|0|4.02.8|1|${EXPECTED_PACKAGE_ARCHITECTURE}" ]
}

attest_alma_v4028_rsyslog_process() {
    syswarden_transition_expected_pid="$1"
    syswarden_transition_proc_root="${2:-/proc}"
    case "${syswarden_transition_expected_pid}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${syswarden_transition_expected_pid}" -gt 1 ] || return 1
    kill -0 "${syswarden_transition_expected_pid}" 2>/dev/null || return 1
    [ "$(cat "${syswarden_transition_proc_root}/${syswarden_transition_expected_pid}/comm" 2>/dev/null || true)" = rsyslogd ] || return 1
    [ "$(readlink "${syswarden_transition_proc_root}/${syswarden_transition_expected_pid}/exe" 2>/dev/null || true)" = /usr/sbin/rsyslogd ]
}

attest_alma_v4028_rpm_rsyslog_fixture() {
    alma_v4028_rpm_transition_selected || return 0
    syswarden_transition_proc_root="$1"
    syswarden_transition_systemd_root="$2"
    syswarden_transition_owner="$3"
    syswarden_transition_rsyslogd="$4"
    syswarden_transition_dropin_dir="${syswarden_transition_systemd_root}/rsyslog.service.d"
    syswarden_transition_dropin="${syswarden_transition_dropin_dir}/90-syswarden-lifecycle-v4028.conf"
    syswarden_transition_expected_pid="${syswarden_transition_rsyslog_pid_before:-}"

    attest_rootless_podman_systemd_runtime "${syswarden_transition_proc_root}" || return 1
    attest_alma_v4028_previous_rpm_artifact || return 1
    case "${syswarden_transition_rsyslogd}" in /*) ;; *) return 1 ;; esac
    [ -x "${syswarden_transition_rsyslogd}" ] && \
        [ ! -L "${syswarden_transition_rsyslogd}" ] || return 1
    "${syswarden_transition_rsyslogd}" -N1 -f /etc/rsyslog.conf \
        >/dev/null 2>&1 || return 1
    [ -d "${syswarden_transition_systemd_root}" ] && \
        [ ! -L "${syswarden_transition_systemd_root}" ] && \
        [ "$(stat -c '%u:%g:%a' "${syswarden_transition_systemd_root}" 2>/dev/null || true)" = \
            "${syswarden_transition_owner}:755" ] || return 1
    [ -d "${syswarden_transition_dropin_dir}" ] && \
        [ ! -L "${syswarden_transition_dropin_dir}" ] && \
        [ "$(stat -c '%u:%g:%a' "${syswarden_transition_dropin_dir}" 2>/dev/null || true)" = \
            "${syswarden_transition_owner}:755" ] || return 1
    [ -f "${syswarden_transition_dropin}" ] && \
        [ ! -L "${syswarden_transition_dropin}" ] && \
        [ "$(stat -c '%u:%g:%a' "${syswarden_transition_dropin}" 2>/dev/null || true)" = \
            "${syswarden_transition_owner}:644" ] && \
        [ "$(hash_file "${syswarden_transition_dropin}" 2>/dev/null || true)" = \
            896e27cd6a65891cd2184253fcfba7e691f0d46047f41d08ee11be81a7d06098 ] || return 1
    [ "$(systemctl show -p RefuseManualStop --value rsyslog.service 2>/dev/null || true)" = yes ] || return 1
    [ "$(systemctl is-enabled rsyslog.service 2>/dev/null || true)" = enabled ] || return 1
    [ "$(systemctl is-active rsyslog.service 2>/dev/null || true)" = active ] || return 1
    [ "$(systemctl show -p MainPID --value rsyslog.service 2>/dev/null || true)" = \
        "${syswarden_transition_expected_pid}" ] || return 1
    attest_alma_v4028_rsyslog_process \
        "${syswarden_transition_expected_pid}" "${syswarden_transition_proc_root}"
}

prepare_alma_v4028_rpm_rsyslog_fixture() {
    alma_v4028_rpm_transition_selected || return 0
    syswarden_transition_proc_root="$1"
    syswarden_transition_systemd_root="$2"
    syswarden_transition_owner="$3"
    syswarden_transition_rsyslogd="$4"
    syswarden_transition_dropin_dir="${syswarden_transition_systemd_root}/rsyslog.service.d"
    syswarden_transition_dropin="${syswarden_transition_dropin_dir}/90-syswarden-lifecycle-v4028.conf"
    syswarden_transition_expected_pid="${syswarden_transition_rsyslog_pid_before:-}"

    attest_rootless_podman_systemd_runtime "${syswarden_transition_proc_root}" || return 1
    attest_alma_v4028_previous_rpm_artifact || return 1
    case "${syswarden_transition_rsyslogd}" in /*) ;; *) return 1 ;; esac
    [ -x "${syswarden_transition_rsyslogd}" ] && \
        [ ! -L "${syswarden_transition_rsyslogd}" ] || return 1
    "${syswarden_transition_rsyslogd}" -N1 -f /etc/rsyslog.conf \
        >/dev/null 2>&1 || return 1
    [ "$(systemctl show -p RefuseManualStop --value rsyslog.service 2>/dev/null || true)" = no ] || return 1
    [ "$(systemctl is-enabled rsyslog.service 2>/dev/null || true)" = enabled ] || return 1
    [ "$(systemctl is-active rsyslog.service 2>/dev/null || true)" = active ] || return 1
    [ "$(systemctl show -p MainPID --value rsyslog.service 2>/dev/null || true)" = \
        "${syswarden_transition_expected_pid}" ] || return 1
    attest_alma_v4028_rsyslog_process \
        "${syswarden_transition_expected_pid}" "${syswarden_transition_proc_root}" || return 1
    [ -d "${syswarden_transition_systemd_root}" ] && \
        [ ! -L "${syswarden_transition_systemd_root}" ] && \
        [ "$(stat -c '%u:%g:%a' "${syswarden_transition_systemd_root}" 2>/dev/null || true)" = \
            "${syswarden_transition_owner}:755" ] || return 1
    [ ! -e "${syswarden_transition_dropin}" ] && [ ! -L "${syswarden_transition_dropin}" ] || return 1
    if [ -e "${syswarden_transition_dropin_dir}" ] || [ -L "${syswarden_transition_dropin_dir}" ]; then
        return 1
    fi
    mkdir -m 0755 "${syswarden_transition_dropin_dir}" || return 1
    (umask 077 && printf '%s\n' '[Unit]' 'RefuseManualStop=yes' > "${syswarden_transition_dropin}") || return 1
    chmod 0644 "${syswarden_transition_dropin}" || return 1
    [ "$(stat -c '%u:%g:%a' "${syswarden_transition_dropin_dir}" 2>/dev/null || true)" = \
        "${syswarden_transition_owner}:755" ] || return 1
    [ "$(stat -c '%u:%g:%a' "${syswarden_transition_dropin}" 2>/dev/null || true)" = \
        "${syswarden_transition_owner}:644" ] || return 1
    [ "$(hash_file "${syswarden_transition_dropin}" 2>/dev/null || true)" = \
        896e27cd6a65891cd2184253fcfba7e691f0d46047f41d08ee11be81a7d06098 ] || return 1
    systemctl daemon-reload >/dev/null 2>&1 || return 1
    attest_alma_v4028_rpm_rsyslog_fixture \
        "${syswarden_transition_proc_root}" "${syswarden_transition_systemd_root}" \
        "${syswarden_transition_owner}" "${syswarden_transition_rsyslogd}" || return 1
    printf 'TRANSITION alma-v4028-rpm-rsyslog fixture=refuse-manual-stop pid=%s\n' \
        "${syswarden_transition_expected_pid}" >> "${COMMAND_LOG}"
}

attest_alma_v4028_rpm_rsyslog_after_previous() {
    alma_v4028_rpm_transition_selected || return 0
    syswarden_transition_installed_record="$(
        rpm -q --queryformat '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}' \
            syswarden 2>/dev/null
    )" || return 1
    [ "${syswarden_transition_installed_record}" = \
        "syswarden|0|4.02.8|1|${EXPECTED_PACKAGE_ARCHITECTURE}" ] || return 1
    [ "$(installed_version 2>/dev/null || true)" = 4.02.8 ] || return 1
    attest_alma_v4028_rpm_rsyslog_fixture "$@" || return 1
    printf 'TRANSITION alma-v4028-rpm-rsyslog postinstall=active pid=%s\n' \
        "${syswarden_transition_rsyslog_pid_before}" >> "${COMMAND_LOG}"
}

prepare_package_transition() {
    prepare_service_runtime_fixture || return 1
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            [ "$(systemctl is-enabled rsyslog.service 2>/dev/null || true)" = enabled ] || return 1
            [ "$(systemctl is-active rsyslog.service 2>/dev/null || true)" = active ] || return 1
            syswarden_transition_rsyslog_pid_before="$(
                systemctl show -p MainPID --value rsyslog.service 2>/dev/null || true
            )"
            case "${syswarden_transition_rsyslog_pid_before}" in
                ''|*[!0-9]*) return 1 ;;
            esac
            [ "${syswarden_transition_rsyslog_pid_before}" -gt 1 ] || return 1
            kill -0 "${syswarden_transition_rsyslog_pid_before}" 2>/dev/null || return 1
            systemctl reset-failed rsyslog.service >/dev/null 2>&1 || return 1
            [ "$(systemctl is-enabled rsyslog.service 2>/dev/null || true)" = enabled ] || return 1
            [ "$(systemctl is-active rsyslog.service 2>/dev/null || true)" = active ] || return 1
            syswarden_transition_rsyslog_pid_after="$(
                systemctl show -p MainPID --value rsyslog.service 2>/dev/null || true
            )"
            [ "${syswarden_transition_rsyslog_pid_after}" = "${syswarden_transition_rsyslog_pid_before}" ] || return 1
            kill -0 "${syswarden_transition_rsyslog_pid_after}" 2>/dev/null || return 1
            [ "$(syswarden_classify_service_manager / systemd)" = ACTIVE ] || return 1
            ;;
        apk) ;;
        *) return 1 ;;
    esac
}

v4028_to_v4032_transition_selected() {
    [ "${SCENARIO}" = upgrade-rollback ] && \
        [ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ] && \
        [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ]
}

v4032_to_v4033_transition_selected() {
    [ "${SCENARIO}" = upgrade-rollback ] && \
        [ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ] && \
        [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.3 ]
}

expected_systemd_enablement_prefix() {
    label="$1"
    case "${SCENARIO}:${label}" in
        upgrade-rollback:previous|upgrade-rollback:candidate|upgrade-rollback:reinstall|\
        upgrade-rollback:restart-one|upgrade-rollback:restart-two|upgrade-rollback:rollback|\
        upgrade-rollback:recovery)
            if v4028_to_v4032_transition_selected; then
                printf '%s\n' /etc/systemd/system
            elif v4032_to_v4033_transition_selected; then
                printf '%s\n' ..
            else
                return 1
            fi
            ;;
        remove:fresh|remove:reinstall-after-remove|purge:fresh)
            printf '%s\n' ..
            ;;
        *)
            return 1
            ;;
    esac
}

operator_listener_preservation_required() {
    label="$1"
    case "${SCENARIO}:${label}" in
        upgrade-rollback:candidate|upgrade-rollback:reinstall)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

candidate_nft_runtime_required() {
    label="$1"
    case "${SCENARIO}:${label}" in
        upgrade-rollback:candidate|upgrade-rollback:reinstall|\
        upgrade-rollback:recovery|remove:fresh|remove:reinstall-after-remove|purge:fresh)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

operator_listener_process_identity() {
    operator_identity_pid="$1"
    case "${operator_identity_pid}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${operator_identity_pid}" -gt 1 ] || return 1
    operator_identity_start_time="$(awk '{ print $22 }' \
        "/proc/${operator_identity_pid}/stat" 2>/dev/null)" || return 1
    case "${operator_identity_start_time}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    operator_identity_executable="$(readlink \
        "/proc/${operator_identity_pid}/exe" 2>/dev/null)" || return 1
    case "${operator_identity_executable}" in
        /*) ;;
        *) return 1 ;;
    esac
    case "${operator_identity_executable}" in
        *' (deleted)') return 1 ;;
    esac
    operator_identity_executable_stat="$(stat -Lc '%d:%i:%f:%u:%g' \
        "/proc/${operator_identity_pid}/exe" 2>/dev/null)" || return 1
    [ -n "${operator_identity_executable_stat}" ] || return 1
    printf '%s|%s|%s\n' \
        "${operator_identity_start_time}" \
        "${operator_identity_executable}" \
        "${operator_identity_executable_stat}"
}

operator_listener_socket_identity() {
    operator_socket_pid="$1"
    case "${operator_socket_pid}" in ''|*[!0-9]*) return 1 ;; esac
    operator_socket_inode="$(awk '
        $2 == "0100007F:F24B" && $4 == "0A" { print $10 }
    ' /proc/net/tcp)" || return 1
    case "${operator_socket_inode}" in ''|*[!0-9]*|*' '*) return 1 ;; esac
    operator_socket_fd=
    operator_socket_matches=0
    for operator_socket_candidate in "/proc/${operator_socket_pid}/fd"/*; do
        [ -L "${operator_socket_candidate}" ] || continue
        if [ "$(readlink "${operator_socket_candidate}" 2>/dev/null || true)" = "socket:[${operator_socket_inode}]" ]; then
            operator_socket_fd="${operator_socket_candidate##*/}"
            operator_socket_matches=$((operator_socket_matches + 1))
        fi
    done
    [ "${operator_socket_matches}" -eq 1 ] || return 1
    case "${operator_socket_fd}" in ''|*[!0-9]*) return 1 ;; esac
    operator_socket_ss="$(ss -H -ltnp 'sport = :62027' 2>/dev/null || true)" || return 1
    [ "$(printf '%s\n' "${operator_socket_ss}" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] || return 1
    printf '%s\n' "${operator_socket_ss}" | grep -Eq "pid=${operator_socket_pid},fd=${operator_socket_fd}([,)])" || return 1
    printf '%s|%s\n' "${operator_socket_inode}" "${operator_socket_fd}"
}

operator_listener_matches_seeded_proof() {
    operator_proof_pid="$1"
    operator_proof_process_identity="$2"
    operator_proof_pidfile_identity="$3"
    operator_proof_socket_identity="$4"
    [ -n "${SEEDED_OPERATOR_LISTENER_PID:-}" ] && \
        [ -n "${SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY:-}" ] && \
        [ -n "${SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY:-}" ] && \
        [ -n "${SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY:-}" ] && \
        [ "${operator_proof_pid}" = "${SEEDED_OPERATOR_LISTENER_PID}" ] && \
        [ "${operator_proof_process_identity}" = \
            "${SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY}" ] && \
        [ "${operator_proof_pidfile_identity}" = \
            "${SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY}" ] && \
        [ "${operator_proof_socket_identity}" = \
            "${SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY}" ]
}

probe_seeded_operator_listener_preservation() {
    label="$1"
    if ! operator_listener_preservation_required "${label}"; then
        return 0
    fi
    operator_listener_pid_path="${PERSIST_ROOT}/operator-62027.pid"
    [ -f "${operator_listener_pid_path}" ] && \
        [ ! -L "${operator_listener_pid_path}" ] && \
        [ "$(stat -c '%u:%g:%a' "${operator_listener_pid_path}" 2>/dev/null || true)" = 0:0:600 ] || return 1
    [ "$(wc -c < "${operator_listener_pid_path}" | tr -d ' ')" -le 32 ] || return 1
    operator_listener_pid="$(cat "${operator_listener_pid_path}")" || return 1
    case "${operator_listener_pid}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${operator_listener_pid}" -gt 1 ] || return 1
    operator_listener_process_identity_before="$(operator_listener_process_identity \
        "${operator_listener_pid}")" || return 1
    operator_listener_pidfile_identity_before="$(stat -c '%d:%i:%s:%u:%g:%a' \
        "${operator_listener_pid_path}" 2>/dev/null)" || return 1
    operator_listener_socket_identity_before="$(operator_listener_socket_identity \
        "${operator_listener_pid}")" || return 1
    operator_listener_matches_seeded_proof \
        "${operator_listener_pid}" \
        "${operator_listener_process_identity_before}" \
        "${operator_listener_pidfile_identity_before}" \
        "${operator_listener_socket_identity_before}" || return 1
    kill -0 "${operator_listener_pid}" 2>/dev/null || return 1
    operator_probe="$(printf '%s' 'syswarden-operator-62027' | \
        socat -T 2 - TCP4:127.0.0.1:62027 2>/dev/null || true)"
    [ "${operator_probe}" = 'syswarden-operator-62027' ] || return 1
    operator_listener_pid_after="$(cat "${operator_listener_pid_path}" 2>/dev/null)" || return 1
    operator_listener_process_identity_after="$(operator_listener_process_identity \
        "${operator_listener_pid_after}")" || return 1
    operator_listener_pidfile_identity_after="$(stat -c '%d:%i:%s:%u:%g:%a' \
        "${operator_listener_pid_path}" 2>/dev/null)" || return 1
    operator_listener_socket_identity_after="$(operator_listener_socket_identity \
        "${operator_listener_pid_after}")" || return 1
    operator_listener_matches_seeded_proof \
        "${operator_listener_pid_after}" \
        "${operator_listener_process_identity_after}" \
        "${operator_listener_pidfile_identity_after}" \
        "${operator_listener_socket_identity_after}" && \
        [ "$(stat -c '%u:%g:%a' "${operator_listener_pid_path}" 2>/dev/null || true)" = 0:0:600 ] && \
        kill -0 "${operator_listener_pid_after}" 2>/dev/null
}

attest_installed_core_process() {
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            [ "$(systemctl show syswarden-core.service -p LoadState --value 2>/dev/null || true)" = loaded ] || return 1
            [ "$(systemctl show syswarden-core.service -p FragmentPath --value 2>/dev/null || true)" = /etc/systemd/system/syswarden-core.service ] || return 1
            [ "$(systemctl show syswarden-core.service -p UnitFileState --value 2>/dev/null || true)" = enabled ] || return 1
            [ "$(systemctl show syswarden-core.service -p ActiveState --value 2>/dev/null || true)" = active ] || return 1
            core_runtime_pid="$(systemctl show syswarden-core.service -p MainPID --value 2>/dev/null || true)" || return 1
            ;;
        apk)
            [ -f /etc/init.d/syswarden-core ] && [ ! -L /etc/init.d/syswarden-core ] || return 1
            [ -L /etc/runlevels/default/syswarden-core ] && [ "$(readlink /etc/runlevels/default/syswarden-core)" = /etc/init.d/syswarden-core ] || return 1
            rc-service syswarden-core status >/dev/null 2>&1 || return 1
            [ -f /run/syswarden-core.pid ] && [ ! -L /run/syswarden-core.pid ] || return 1
            [ "$(stat -c '%u:%g:%a' /run/syswarden-core.pid 2>/dev/null || true)" = 0:0:644 ] || return 1
            [ "$(wc -c < /run/syswarden-core.pid | tr -d ' ')" -le 32 ] || return 1
            core_runtime_pid="$(cat /run/syswarden-core.pid 2>/dev/null || true)" || return 1
            [ "$(pgrep -x syswarden-core 2>/dev/null || true)" = "${core_runtime_pid}" ] || return 1
            ;;
        *) return 1 ;;
    esac
    case "${core_runtime_pid}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${core_runtime_pid}" -gt 1 ] && kill -0 "${core_runtime_pid}" 2>/dev/null || return 1
    core_runtime_path="$(readlink "/proc/${core_runtime_pid}/exe" 2>/dev/null || true)" || return 1
    [ "${core_runtime_path}" = /opt/syswarden/bin/syswarden-core ] || return 1
    core_runtime_identity="$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${core_runtime_pid}/exe" 2>/dev/null || true)" || return 1
    core_installed_identity="$(stat -Lc '%d:%i:%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)" || return 1
    [ "$(stat -Lc '%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)" = 81e8:0:0 ] || return 1
    core_runtime_sha256="$(sha256sum "/proc/${core_runtime_pid}/exe" 2>/dev/null | awk '{ print $1 }')" || return 1
    core_installed_sha256="$(sha256sum /opt/syswarden/bin/syswarden-core 2>/dev/null | awk '{ print $1 }')" || return 1
    case "${core_installed_sha256}" in *[!0-9a-f]*|'') return 1 ;; esac
    [ "${#core_installed_sha256}" -eq 64 ] && \
        [ -n "${core_runtime_identity}" ] && \
        [ "${core_runtime_identity}" = "${core_installed_identity}" ] && \
        [ "${core_runtime_sha256}" = "${core_installed_sha256}" ] || return 1
    [ "$(readlink "/proc/${core_runtime_pid}/exe" 2>/dev/null || true)" = "${core_runtime_path}" ] && \
        [ "$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${core_runtime_pid}/exe" 2>/dev/null || true)" = "${core_runtime_identity}" ] && \
        [ "$(stat -Lc '%d:%i:%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)" = "${core_installed_identity}" ] && \
        [ "$(sha256sum "/proc/${core_runtime_pid}/exe" 2>/dev/null | awk '{ print $1 }')" = "${core_runtime_sha256}" ] && \
    [ "$(sha256sum /opt/syswarden/bin/syswarden-core 2>/dev/null | awk '{ print $1 }')" = "${core_installed_sha256}" ]
}

legacy_bash_completion_is_exact() {
    legacy_completion=/etc/bash_completion.d/syswarden
    [ -f "${legacy_completion}" ] && \
        [ ! -L "${legacy_completion}" ] && \
        [ "$(stat -c '%u:%g:%a:%h:%s' \
            "${legacy_completion}" 2>/dev/null || true)" = \
            0:0:644:1:16339 ] && \
        [ "$(hash_file "${legacy_completion}" 2>/dev/null || true)" = \
            c23c9f6c54b91105e9ecd8ad4431a9a11ad26ba3437bcd20ec2cef1a96e51d21 ]
}

package_owned_bash_completion_is_exact() {
    package_completion=/usr/share/bash-completion/completions/syswarden
    [ -s "${package_completion}" ] && \
        [ ! -L "${package_completion}" ] && \
        [ "$(stat -c '%u:%g:%a:%h' \
            "${package_completion}" 2>/dev/null || true)" = 0:0:644:1 ]
}

probe_postinstall_contract() {
    label="$1"
    postinstall_ok=1
    postinstall_failure_codes=
    mark_postinstall_failure() {
        postinstall_ok=0
        postinstall_failure_code="$1"
        case " ${postinstall_failure_codes} " in
            *" ${postinstall_failure_code} "*) ;;
            *) postinstall_failure_codes="${postinstall_failure_codes} ${postinstall_failure_code}" ;;
        esac
    }
    actual_version="$(installed_version 2>/dev/null || true)"
    for path in \
        /etc/syswarden/config/config.toml \
        /etc/syswarden/config/modules/00-core.toml \
        /etc/syswarden/config/modules/10-network.toml \
        /etc/syswarden/config/modules/20-security.toml \
        /etc/syswarden/config/modules/30-waap.toml \
        /etc/syswarden/config/modules/40-integrations.toml \
        /etc/syswarden/config/modules/99-user.toml; do
        [ -f "${path}" ] && [ ! -L "${path}" ] || mark_postinstall_failure modular-config
    done
    if { [ "${actual_version}" = "${EXPECTED_PREVIOUS_VERSION}" ] && \
         [ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ]; } || \
       { [ "${PACKAGE_FAMILY}" = apk ] && \
         [ "${FORWARD_ONLY_APK_TRANSITION}" = 1 ] && \
         [ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ] && \
         [ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ] && \
         [ "${actual_version}" = "${EXPECTED_CANDIDATE_VERSION}" ]; }; then
        legacy_bash_completion_is_exact || \
            mark_postinstall_failure completion-legacy
        if [ -e /usr/share/bash-completion/completions/syswarden ] || \
           [ -L /usr/share/bash-completion/completions/syswarden ]; then
            mark_postinstall_failure completion-package-owned-residual
        fi
    elif [ "${actual_version}" = "${EXPECTED_CANDIDATE_VERSION}" ] || \
         [ "${actual_version}" = "${EXPECTED_PREVIOUS_VERSION}" ]; then
        package_owned_bash_completion_is_exact || \
            mark_postinstall_failure completion-package-owned
        if legacy_bash_completion_is_exact; then
            mark_postinstall_failure completion-legacy-residual
        fi
    else
        mark_postinstall_failure completion-version
    fi
    feed_cron_count=0
    if [ -f /etc/cron.d/syswarden ] && [ ! -L /etc/cron.d/syswarden ] && \
       [ "$(stat -c '%u:%g:%a:%h' /etc/cron.d/syswarden 2>/dev/null || true)" = 0:0:644:1 ]; then
        feed_cron_count="$(awk '
            $1 ~ /^([1-9]|[1-5][0-9])$/ &&
                $0 == $1 " * * * * root /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1" { count++ }
            END { print count + 0 }
        ' /etc/cron.d/syswarden)"
    elif cron_state="$(LC_ALL=C crontab -l 2>/tmp/syswarden-postinstall-cron.error)"; then
        feed_cron_count="$(printf '%s\n' "${cron_state}" | awk '
            $1 ~ /^([1-9]|[1-5][0-9])$/ &&
                $0 == $1 " * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1" { count++ }
            END { print count + 0 }
        ')"
    fi
    [ "${feed_cron_count}" -eq 1 ] || mark_postinstall_failure feed-cron
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            service_contract='systemd'
            systemd_enablement_prefix="$(expected_systemd_enablement_prefix "${label}" 2>/dev/null || true)"
            [ -n "${systemd_enablement_prefix}" ] || mark_postinstall_failure systemd-prefix
            for specification in \
                '/etc/systemd/system/syswarden-core.service|/opt/syswarden/bin/syswarden-core' \
                '/etc/systemd/system/syswarden-firewall.service|/opt/syswarden/bin/syswarden-cli reload --no-restart'; do
                path="${specification%%|*}"
                fragment="${specification#*|}"
                [ -f "${path}" ] && [ ! -L "${path}" ] && \
                    [ "$(file_mode "${path}" 2>/dev/null || true)" = "600" ] && \
                    grep -Fq "${fragment}" "${path}" || mark_postinstall_failure systemd-unit
            done
            for specification in \
                "/etc/systemd/system/multi-user.target.wants/syswarden-core.service|${systemd_enablement_prefix}/syswarden-core.service" \
                "/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service|${systemd_enablement_prefix}/syswarden-firewall.service"; do
                path="${specification%%|*}"
                target="${specification#*|}"
                [ -L "${path}" ] && [ "$(readlink "${path}")" = "${target}" ] || mark_postinstall_failure systemd-enablement
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
                    grep -Fq "${fragment}" "${path}" || mark_postinstall_failure openrc-unit
            done
            for specification in \
                '/etc/runlevels/default/syswarden-core|/etc/init.d/syswarden-core' \
                '/etc/runlevels/default/syswarden-firewall|/etc/init.d/syswarden-firewall'; do
                path="${specification%%|*}"
                target="${specification#*|}"
                [ -L "${path}" ] && [ "$(readlink "${path}")" = "${target}" ] || mark_postinstall_failure openrc-enablement
            done
            ;;
        *)
            service_contract='invalid'
            mark_postinstall_failure package-family
            ;;
    esac
    prepare_service_runtime_fixture || mark_postinstall_failure service-manager-runtime
    postinstall_core_digest=
    if [ "${actual_version}" = "${EXPECTED_CANDIDATE_VERSION}" ]; then
        if attest_installed_core_process; then
            postinstall_core_digest="${core_installed_sha256}"
        else
            mark_postinstall_failure core-process-identity
        fi
        legacy_webtui_runtime_absent / || mark_postinstall_failure legacy-webtui-runtime
        if grep -Fq 'webtui_password' \
            /etc/syswarden/config/config.toml /etc/syswarden/config/modules/*.toml \
            2>/dev/null; then
            mark_postinstall_failure legacy-webtui-config
        fi
        for retired_secret in \
            lot0-lifecycle-retired-token \
            lot0-lifecycle-live-retired-token; do
            if grep -Fq "${retired_secret}" "${COMMAND_LOG}" \
                /tmp/syswarden-legacy-webtui-process.log 2>/dev/null; then
                mark_postinstall_failure retired-secret-log
            fi
        done
        if [ -f "${PERSIST_ROOT}/legacy-webtui-process.pid" ]; then
            legacy_webtui_pid="$(cat "${PERSIST_ROOT}/legacy-webtui-process.pid")"
            if [ -r "/proc/${legacy_webtui_pid}/cmdline" ] && \
               od -An -tx1 -v "/proc/${legacy_webtui_pid}/cmdline" 2>/dev/null | \
                   tr -d '[:space:]' | grep -Fq '007765622d74756900'; then
                mark_postinstall_failure legacy-webtui-process
                kill -KILL "${legacy_webtui_pid}" 2>/dev/null || true
            fi
            wait "${legacy_webtui_pid}" 2>/dev/null || true
            rm -f "${PERSIST_ROOT}/legacy-webtui-process.pid"
        fi
        if [ -f "${PERSIST_ROOT}/legacy-saas-seeded" ]; then
            legacy_saas_v4=/etc/syswarden/lists/syswarden_saas_monitors.ipv4
            legacy_saas_v6=/etc/syswarden/lists/syswarden_saas_monitors.ipv6
            legacy_saas_pair=/etc/syswarden/lists/syswarden_saas_monitors.pair
            [ -f "${legacy_saas_v4}" ] && [ ! -L "${legacy_saas_v4}" ] && \
                [ "$(file_mode "${legacy_saas_v4}" 2>/dev/null || true)" = 600 ] && \
                [ "$(stat -c '%u:%g' "${legacy_saas_v4}" 2>/dev/null || true)" = 0:0 ] && \
                [ "$(hash_file "${legacy_saas_v4}" 2>/dev/null || true)" = \
                    7337141ed136cb92b166db379d6bd2ceba3ddf64cef41583e469485e0048dedc ] || mark_postinstall_failure legacy-saas-ipv4
            [ -f "${legacy_saas_v6}" ] && [ ! -L "${legacy_saas_v6}" ] && \
                [ ! -s "${legacy_saas_v6}" ] && \
                [ "$(file_mode "${legacy_saas_v6}" 2>/dev/null || true)" = 600 ] && \
                    [ "$(stat -c '%u:%g' "${legacy_saas_v6}" 2>/dev/null || true)" = 0:0 ] || mark_postinstall_failure legacy-saas-ipv6
            [ -f "${legacy_saas_pair}" ] && [ ! -L "${legacy_saas_pair}" ] && \
                [ "$(file_mode "${legacy_saas_pair}" 2>/dev/null || true)" = 600 ] && \
                    [ "$(stat -c '%u:%g' "${legacy_saas_pair}" 2>/dev/null || true)" = 0:0 ] || mark_postinstall_failure legacy-saas-manifest
            expected_saas_pair=/tmp/syswarden-expected-saas-pair
            printf '%s\n' \
                'syswarden-saas-pair-v1' \
                'ipv4_sha256=7337141ed136cb92b166db379d6bd2ceba3ddf64cef41583e469485e0048dedc' \
                'ipv6_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
                > "${expected_saas_pair}"
            cmp -s "${expected_saas_pair}" "${legacy_saas_pair}" || mark_postinstall_failure legacy-saas-manifest
        fi
        [ -x /opt/syswarden/bin/syswarden-tui ] || mark_postinstall_failure tui-binary
        [ -L /usr/local/bin/syswarden-tui ] || mark_postinstall_failure tui-link
        [ "$(readlink /usr/local/bin/syswarden-tui 2>/dev/null || true)" = /opt/syswarden/bin/syswarden-tui ] || mark_postinstall_failure tui-link
        if candidate_nft_runtime_required "${label}"; then
            if nft list table inet syswarden > /tmp/syswarden-candidate-nftables 2>/dev/null; then
                if grep -Eq 'tcp dport (\{[^}]*[ ,])?62027([ ,}]|$)' /tmp/syswarden-candidate-nftables; then
                    mark_postinstall_failure nft-runtime
                fi
            else
                mark_postinstall_failure nft-runtime
            fi
        fi
        probe_seeded_operator_listener_preservation "${label}" || mark_postinstall_failure operator-listener
    elif [ "${actual_version}" = "${EXPECTED_PREVIOUS_VERSION}" ]; then
        if v4032_to_v4033_upgrade_selected; then
            attest_v4032_previous_webtui_retirement || \
                mark_postinstall_failure previous-webtui-retirement
        else
            case "${PACKAGE_FAMILY}" in
                deb|rpm)
                    [ -f /etc/systemd/system/syswarden-webtui.service ] && \
                        grep -Fq '/opt/syswarden/bin/syswarden-cli web-tui' \
                            /etc/systemd/system/syswarden-webtui.service || mark_postinstall_failure previous-webtui
                    ;;
                apk)
                    [ -f /etc/init.d/syswarden-webtui ] && \
                        grep -Fq 'command_args="web-tui"' /etc/init.d/syswarden-webtui || mark_postinstall_failure previous-webtui
                    ;;
            esac
        fi
    else
        mark_postinstall_failure installed-version
    fi
    if [ "${postinstall_ok}" -eq 1 ]; then
        if [ -n "${postinstall_core_digest}" ]; then
            record pass "${PREFIX}.${label}.postinstall_contract" "modular config, native TUI, ${service_contract} services, completion, feed cron, browser-service retirement, and core process sha256=${postinstall_core_digest} match the installed version"
        else
            record pass "${PREFIX}.${label}.postinstall_contract" "modular config, native TUI, ${service_contract} services, completion, feed cron, and browser-service retirement match the installed version"
        fi
    else
        postinstall_failure_codes="$(printf '%s' "${postinstall_failure_codes}" | sed 's/^ *//; s/  */,/g')"
        record fail "${PREFIX}.${label}.postinstall_contract" "postinstall output contract is incomplete: ${postinstall_failure_codes:-unclassified}"
    fi
}

verify_installed_inventory() {
    label="$1"
    expected_label="$2"
    publish_evidence="${3:-1}"
    expected_manifest="${PERSIST_ROOT}/manifest-${expected_label}"
    expected_inventory="${PERSIST_ROOT}/inventory-${expected_label}"
    actual_manifest="/tmp/manifest-installed-${label}"
    actual_inventory="/tmp/inventory-installed-${label}"
    mkdir -p /results/inventories
    if installed_manager_manifest "${actual_manifest}" && cmp -s "${expected_manifest}" "${actual_manifest}"; then
        if [ "${publish_evidence}" = 1 ]; then
            cp "${actual_manifest}" "/results/inventories/${PREFIX}-${label}-manager.tsv"
        fi
        record pass "${PREFIX}.${label}.inventory.manager" "exact native installed manifest sha256=$(hash_file "${actual_manifest}")"
    else
        diff -u "${expected_manifest}" "${actual_manifest}" >> "${COMMAND_LOG}" 2>&1 || true
        record fail "${PREFIX}.${label}.inventory.manager" "installed native manifest differs from the package manifest"
    fi
    if build_filesystem_inventory "${expected_manifest}" / "${actual_inventory}" && \
       validate_inventory_contract "${actual_inventory}" "${expected_label}" && \
       cmp -s "${expected_inventory}" "${actual_inventory}"; then
        if [ "${publish_evidence}" = 1 ]; then
            cp "${actual_inventory}" "/results/inventories/${PREFIX}-${label}-filesystem.tsv"
        fi
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
    publish_inventory="${4:-1}"

    actual_version="$(installed_version 2>/dev/null || true)"
    check_equal "${label}.version" "${expected_version}" "${actual_version}"
    verify_installed_inventory "${label}" "${expected_label}" "${publish_inventory}"

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

write_preinstall_networkless_config() {
    preinstall_networkless_config="$1"
    printf '%s\n' \
        '# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".' \
        '[network.blocklists]' \
        'list_choice = "4"' \
        'custom_url = ""' \
        'custom_url_ipv6 = ""' \
        'custom_hash = ""' \
        'custom_hash_ipv6 = ""' \
        'use_spamhaus = false' \
        '' > "${preinstall_networkless_config}"
}

seed_and_attest_preinstall_networkless_config() {
    preinstall_networkless_path=/etc/syswarden/config/modules/99-user.toml
    for preinstall_networkless_directory in \
        /etc/syswarden \
        /etc/syswarden/config \
        /etc/syswarden/config/modules; do
        if [ -e "${preinstall_networkless_directory}" ] || \
           [ -L "${preinstall_networkless_directory}" ]; then
            if [ ! -d "${preinstall_networkless_directory}" ] || \
               [ -L "${preinstall_networkless_directory}" ] || \
               [ "$(stat -c '%u:%g' \
                   "${preinstall_networkless_directory}" 2>/dev/null || true)" != 0:0 ]; then
                record fail "${PREFIX}.preinstall.networkless_config" \
                    "refusing a non-directory, symlinked, or non-root-owned configuration ancestor"
                return 1
            fi
        fi
    done
    if [ -e "${preinstall_networkless_path}" ] || \
       [ -L "${preinstall_networkless_path}" ]; then
        record fail "${PREFIX}.preinstall.networkless_config" \
            "refusing to replace a pre-existing networkless configuration path"
        return 1
    fi
    mkdir -p /etc/syswarden/config/modules || return 1
    for preinstall_networkless_directory in \
        /etc/syswarden \
        /etc/syswarden/config \
        /etc/syswarden/config/modules; do
        if [ ! -d "${preinstall_networkless_directory}" ] || \
           [ -L "${preinstall_networkless_directory}" ] || \
           [ "$(stat -c '%u:%g' \
               "${preinstall_networkless_directory}" 2>/dev/null || true)" != 0:0 ]; then
            record fail "${PREFIX}.preinstall.networkless_config" \
                "configuration ancestors failed their real root-owned directory attestation"
            return 1
        fi
    done
    if [ -e "${preinstall_networkless_path}" ] || \
       [ -L "${preinstall_networkless_path}" ]; then
        record fail "${PREFIX}.preinstall.networkless_config" \
            "networkless configuration path appeared before publication"
        return 1
    fi
    write_preinstall_networkless_config "${preinstall_networkless_path}" || return 1
    chmod 0640 "${preinstall_networkless_path}" || return 1
    preinstall_networkless_identity="$(
        stat -c '%u:%g:%a:%h' "${preinstall_networkless_path}" 2>/dev/null || true
    )"
    preinstall_networkless_hash="$(
        hash_file "${preinstall_networkless_path}" 2>/dev/null || true
    )"
    if [ -f "${preinstall_networkless_path}" ] && \
       [ ! -L "${preinstall_networkless_path}" ] && \
       [ "${preinstall_networkless_identity}" = 0:0:640:1 ] && \
       [ "${preinstall_networkless_hash}" = \
         e0a6d764d1786c3661c6f25fa7b688bd8c8922d8fd0a00135925ae982f274d68 ]; then
        record pass "${PREFIX}.preinstall.networkless_config" \
            "exact option-4 networkless configuration is installed before the previous package"
        return 0
    fi
    record fail "${PREFIX}.preinstall.networkless_config" \
        "option-4 networkless configuration failed its exact pre-install attestation"
    return 1
}

attest_preinstall_networkless_config_after_previous() {
    preinstall_networkless_path=/etc/syswarden/config/modules/99-user.toml
    preinstall_networkless_identity="$(
        stat -c '%u:%g:%a:%h' "${preinstall_networkless_path}" 2>/dev/null || true
    )"
    preinstall_networkless_hash="$(
        hash_file "${preinstall_networkless_path}" 2>/dev/null || true
    )"
    if [ -f "${preinstall_networkless_path}" ] && \
       [ ! -L "${preinstall_networkless_path}" ] && \
       [ "${preinstall_networkless_identity}" = 0:0:640:1 ] && \
       [ "${preinstall_networkless_hash}" = \
         e0a6d764d1786c3661c6f25fa7b688bd8c8922d8fd0a00135925ae982f274d68 ]; then
        record pass "${PREFIX}.previous.networkless_config_preserved" \
            "the previous package preserved the exact option-4 networkless configuration"
        return 0
    fi
    record fail "${PREFIX}.previous.networkless_config_preserved" \
        "the previous package changed the exact option-4 networkless configuration"
    return 1
}

write_seeded_operator_token() {
    seeded_operator_token="$1"
    {
        printf '%s\n' '[network]' 'interfaces = "lo"' ''
        if [ "${SCENARIO}" = upgrade-rollback ]; then
            printf '%s\n' '[network.saas]' 'allow_monitors = true' ''
        fi
        printf '%s\n' \
            '# Lifecycle-only network-isolation override; production defaults remain list_choice = "1".' \
            '[network.blocklists]' \
            'list_choice = "4"' \
            'custom_url = ""' \
            'custom_url_ipv6 = ""' \
            'custom_hash = ""' \
            'custom_hash_ipv6 = ""' \
            'use_spamhaus = false' \
            ''
        if [ "${PACKAGE_FAMILY:-}" = deb ] && \
           { [ "${SCENARIO}" = remove ] || [ "${SCENARIO}" = purge ]; }; then
            printf '%s\n' \
                '[integrations.siem]' \
                'enabled = true' \
                'ip = "127.0.0.1"' \
                'port = "5514"' \
                'protocol = "udp"' \
                'tls_ca = ""' \
                ''
        fi
        printf '%s\n' '[user]' 'profile_name = "lifecycle-operator"'
    } > "${seeded_operator_token}"
}

seed_state() {
    mkdir -p /etc/syswarden/config/modules /etc/syswarden/lists /etc/syswarden/tls
    mkdir -p /var/lib/syswarden/ui
    printf '%s\n' 'operator-setting=preserve-exactly' > /etc/syswarden/config/lifecycle-operator.conf
    write_seeded_operator_token /etc/syswarden/config/modules/99-user.toml
    printf '%s\n' '198.51.100.42' > /etc/syswarden/lists/syswarden_blacklist.ipv4
    printf '%s\n' '2001:db8::42' > /etc/syswarden/lists/syswarden_blacklist.ipv6
    printf '%s\n' '{"schema":1,"sentinel":"lifecycle-operator-preserve-exactly"}' > /var/lib/syswarden/ui/lifecycle-operator.json
    printf '%s\n' '{"timestamp":"1970-01-01T00:00:00Z","github_stars":"","github_release":"","profile_name":"lifecycle-operator","system":{"hostname":"lifecycle-fixture","uptime":"","load_average":"","ram_used_mb":0,"ram_total_mb":0,"disk_used_mb":0,"disk_total_mb":0,"cores":"0","arch":"unknown","os":"unknown","cpu_model":"","server_ip":"127.0.0.1","services":[],"ports":[]},"layer3":{"global_blocked":0,"geoip_blocked":0,"asn_blocked":0,"l7_banned":0,"zero_trust_mode":false},"waf":{"total_banned":0,"total_detected":0,"active_signatures":0,"signatures_data":[],"targeted_ports":[],"banned_ips":[],"top_attackers":[],"risk_radar":[],"sparkline_24h":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"allowed_events":[]},"whitelist":{"active_ips":0,"ips":[]}}' > /var/lib/syswarden/ui/data.json
    printf '%s\n' '-----BEGIN CERTIFICATE-----' 'lot0-lifecycle-certificate' '-----END CERTIFICATE-----' > /etc/syswarden/tls/operator.pem
    chmod 0640 /etc/syswarden/config/lifecycle-operator.conf
    chmod 0640 /etc/syswarden/config/modules/99-user.toml
    chmod 0600 /etc/syswarden/lists/syswarden_blacklist.ipv4
    chmod 0600 /etc/syswarden/lists/syswarden_blacklist.ipv6
    chmod 0600 /var/lib/syswarden/ui/lifecycle-operator.json
    chmod 0600 /var/lib/syswarden/ui/data.json
    chmod 0600 /etc/syswarden/tls/operator.pem

    STATE_CONFIG_HASH="$(hash_file /etc/syswarden/config/lifecycle-operator.conf)"
    STATE_TOKEN_HASH="$(hash_file /etc/syswarden/config/modules/99-user.toml)"
    STATE_LIST_HASH="$(hash_file /etc/syswarden/lists/syswarden_blacklist.ipv4)"
    STATE_LIST_IPV6_HASH="$(hash_file /etc/syswarden/lists/syswarden_blacklist.ipv6)"
    STATE_OPERATOR_DATA_HASH="$(hash_file /var/lib/syswarden/ui/lifecycle-operator.json)"
    STATE_CERT_HASH="$(hash_file /etc/syswarden/tls/operator.pem)"
    {
        printf 'STATE_CONFIG_HASH=%s\n' "${STATE_CONFIG_HASH}"
        printf 'STATE_TOKEN_HASH=%s\n' "${STATE_TOKEN_HASH}"
        printf 'STATE_LIST_HASH=%s\n' "${STATE_LIST_HASH}"
        printf 'STATE_LIST_IPV6_HASH=%s\n' "${STATE_LIST_IPV6_HASH}"
        printf 'STATE_OPERATOR_DATA_HASH=%s\n' "${STATE_OPERATOR_DATA_HASH}"
        printf 'STATE_CERT_HASH=%s\n' "${STATE_CERT_HASH}"
    } > "${OPERATOR_STATE_FILE}"
    chmod 0600 "${OPERATOR_STATE_FILE}"
}

seed_deb_removal_log() {
    [ "${PACKAGE_FAMILY}" = deb ] || return 1
    mkdir -p /var/log/syswarden || return 1
    printf '%s\n' 'operator-log=preserve-until-explicit-purge' > \
        /var/log/syswarden/lifecycle-operator.log || return 1
    chmod 0600 /var/log/syswarden/lifecycle-operator.log || return 1
    STATE_LOG_HASH="$(hash_file /var/log/syswarden/lifecycle-operator.log)" || return 1
    [ -n "${STATE_LOG_HASH}" ]
}

attest_openrc_webtui_pidfile_before_manager() {
    openrc_webtui_pidfile="$1"
    openrc_webtui_proc_root="${2:-/proc}"
    if [ ! -e "${openrc_webtui_pidfile}" ] && [ ! -L "${openrc_webtui_pidfile}" ]; then
        SYSWARDEN_OPENRC_WEBTUI_PIDFILE_STATE=absent
        SYSWARDEN_OPENRC_WEBTUI_PID=
        return 0
    fi
    [ -f "${openrc_webtui_pidfile}" ] && [ ! -L "${openrc_webtui_pidfile}" ] || return 1
    openrc_webtui_pidfile_before="$(stat -c '%d:%i:%f:%u:%g:%s:%Y' \
        "${openrc_webtui_pidfile}" 2>/dev/null || true)"
    openrc_webtui_pidfile_mode="$(stat -c '%a' "${openrc_webtui_pidfile}" 2>/dev/null || true)"
    [ "$(stat -c '%u:%g' "${openrc_webtui_pidfile}" 2>/dev/null || true)" = 0:0 ] || return 1
    case "${openrc_webtui_pidfile_mode}" in 600|640|644) ;; *) return 1 ;; esac
    openrc_webtui_pidfile_size="$(wc -c < "${openrc_webtui_pidfile}" | tr -d ' ')"
    case "${openrc_webtui_pidfile_size}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${openrc_webtui_pidfile_size}" -gt 1 ] && \
        [ "${openrc_webtui_pidfile_size}" -le 32 ] || return 1
    openrc_webtui_pid="$(cat "${openrc_webtui_pidfile}" 2>/dev/null || true)"
    case "${openrc_webtui_pid}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${openrc_webtui_pid}" -gt 1 ] || return 1
    printf '%s\n' "${openrc_webtui_pid}" | \
        cmp -s - "${openrc_webtui_pidfile}" || return 1
    openrc_webtui_pidfile_after="$(stat -c '%d:%i:%f:%u:%g:%s:%Y' \
        "${openrc_webtui_pidfile}" 2>/dev/null || true)"
    [ -n "${openrc_webtui_pidfile_before}" ] && \
        [ "${openrc_webtui_pidfile_before}" = "${openrc_webtui_pidfile_after}" ] || return 1
    openrc_webtui_process_root="${openrc_webtui_proc_root}/${openrc_webtui_pid}"
    [ "$(readlink "${openrc_webtui_process_root}/exe" 2>/dev/null || true)" = \
        /opt/syswarden/bin/syswarden-cli ] || return 1
    syswarden_webtui_cmdline_matches "${openrc_webtui_process_root}" || return 1
    SYSWARDEN_OPENRC_WEBTUI_PIDFILE_STATE=present
    SYSWARDEN_OPENRC_WEBTUI_PID="${openrc_webtui_pid}"
}

write_exclusive_root_pidfile() {
    exclusive_pidfile="$1"
    exclusive_pid="$2"
    exclusive_directory="${exclusive_pidfile%/*}"
    [ -d "${exclusive_directory}" ] && [ ! -L "${exclusive_directory}" ] || return 1
    [ ! -e "${exclusive_pidfile}" ] && [ ! -L "${exclusive_pidfile}" ] || return 1
    exclusive_temporary="$(mktemp "${exclusive_directory}/.syswarden-pid.XXXXXX")" || return 1
    if ! [ -f "${exclusive_temporary}" ] || [ -L "${exclusive_temporary}" ] || \
       [ "$(stat -c '%u:%g:%a' "${exclusive_temporary}" 2>/dev/null || true)" != 0:0:600 ] || \
       ! printf '%s\n' "${exclusive_pid}" > "${exclusive_temporary}" || \
       ! ln "${exclusive_temporary}" "${exclusive_pidfile}"; then
        rm -f "${exclusive_temporary}"
        return 1
    fi
    exclusive_identity="$(stat -c '%d:%i:%s:%u:%g:%a' \
        "${exclusive_temporary}" 2>/dev/null || true)"
    if ! rm -f "${exclusive_temporary}" || \
       [ "$(stat -c '%d:%i:%s:%u:%g:%a' "${exclusive_pidfile}" 2>/dev/null || true)" != \
           "${exclusive_identity}" ] || \
       ! printf '%s\n' "${exclusive_pid}" | cmp -s - "${exclusive_pidfile}"; then
        rm -f "${exclusive_temporary}" "${exclusive_pidfile}"
        return 1
    fi
}

quiesce_previous_webtui_runtime() {
    prepare_service_runtime_fixture || return 1
    if v4032_to_v4033_upgrade_selected; then
        attest_v4032_previous_webtui_retirement || return 1
        return 0
    fi
    case "${PACKAGE_FAMILY}" in
        deb|rpm)
            previous_webtui_unit=/etc/systemd/system/syswarden-webtui.service
            previous_webtui_enablement=/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service
            if [ ! -e "${previous_webtui_unit}" ] && [ ! -L "${previous_webtui_unit}" ]; then
                return 1
            fi
            [ -f "${previous_webtui_unit}" ] && [ ! -L "${previous_webtui_unit}" ] && \
                [ "$(stat -c '%u:%g:%a' "${previous_webtui_unit}" 2>/dev/null || true)" = 0:0:600 ] || return 1
            syswarden_read_exact_webtui_unit "${previous_webtui_unit}" systemd || return 1
            syswarden_validate_exact_webtui_enablement "${previous_webtui_enablement}" systemd || return 1
            syswarden_attest_systemd_webtui_runtime / || return 1
            previous_webtui_state="$(syswarden_read_systemd_webtui_property ActiveState)" || return 1
            case "${previous_webtui_state}" in
                active)
                    previous_webtui_pid="$(syswarden_read_systemd_webtui_property MainPID)" || return 1
                    case "${previous_webtui_pid}" in ''|*[!0-9]*) return 1 ;; esac
                    [ "${previous_webtui_pid}" -gt 1 ] || return 1
                    [ "$(readlink "/proc/${previous_webtui_pid}/exe" 2>/dev/null || true)" = /opt/syswarden/bin/syswarden-cli ] || return 1
                    systemctl stop syswarden-webtui.service || return 1
                    if kill -0 "${previous_webtui_pid}" 2>/dev/null; then return 1; fi
                    ;;
                inactive) ;;
                *) return 1 ;;
            esac
            [ "$(syswarden_read_systemd_webtui_property ActiveState)" = inactive ] || return 1
            [ ! -e /run/syswarden-webtui.pid ] && [ ! -L /run/syswarden-webtui.pid ] || return 1
            syswarden_read_exact_webtui_unit "${previous_webtui_unit}" systemd || return 1
            syswarden_validate_exact_webtui_enablement "${previous_webtui_enablement}" systemd || return 1
            ;;
        apk)
            previous_webtui_unit=/etc/init.d/syswarden-webtui
            previous_webtui_enablement=/etc/runlevels/default/syswarden-webtui
            if [ ! -e "${previous_webtui_unit}" ] && [ ! -L "${previous_webtui_unit}" ]; then
                [ "${FORWARD_ONLY_APK_TRANSITION}" = 1 ] || return 1
                for path in "${previous_webtui_enablement}" /run/syswarden-webtui.pid; do
                    [ ! -e "${path}" ] && [ ! -L "${path}" ] || return 1
                done
            else
                [ -f "${previous_webtui_unit}" ] && [ ! -L "${previous_webtui_unit}" ] && \
                    [ "$(stat -c '%u:%g:%a' "${previous_webtui_unit}" 2>/dev/null || true)" = 0:0:755 ] || return 1
                syswarden_read_exact_webtui_unit "${previous_webtui_unit}" openrc || return 1
                syswarden_validate_exact_webtui_enablement "${previous_webtui_enablement}" openrc || return 1
                syswarden_openrc_runtime_available / || return 1
                attest_openrc_webtui_pidfile_before_manager \
                    /run/syswarden-webtui.pid /proc || return 1
                if rc-service syswarden-webtui status >/dev/null 2>&1; then
                    previous_webtui_status=0
                else
                    previous_webtui_status=$?
                fi
                case "${SYSWARDEN_OPENRC_WEBTUI_PIDFILE_STATE}:${previous_webtui_status}" in
                    present:0)
                        rc-service syswarden-webtui stop || return 1
                        if kill -0 "${SYSWARDEN_OPENRC_WEBTUI_PID}" 2>/dev/null; then
                            return 1
                        fi
                        ;;
                    absent:3) ;;
                    *) return 1 ;;
                esac
                if rc-service syswarden-webtui status >/dev/null 2>&1; then
                    return 1
                else
                    [ "$?" -eq 3 ] || return 1
                fi
                [ ! -e /run/syswarden-webtui.pid ] && [ ! -L /run/syswarden-webtui.pid ] || return 1
                syswarden_read_exact_webtui_unit "${previous_webtui_unit}" openrc || return 1
                syswarden_validate_exact_webtui_enablement "${previous_webtui_enablement}" openrc || return 1
            fi
            ;;
        *) return 1 ;;
    esac
    syswarden_verify_no_exact_webtui_process / || return 1
    [ -z "$(ss -H -ltn 'sport = :62027' 2>/dev/null || true)" ] || return 1
}

lifecycle_seed_hex_prefix() {
    LC_ALL=C od -An -v -tx1 | tr -d ' \n' | cut -c1-512
}

record_lifecycle_seed_failure() {
    lifecycle_seed_predicate="$1"
    lifecycle_seed_status="$2"
    lifecycle_seed_actual="$3"
    lifecycle_seed_expected="$4"
    lifecycle_seed_log="$5"
    case "${lifecycle_seed_predicate}" in
        LS0[1-9]_*) ;;
        *) return 97 ;;
    esac
    case "${lifecycle_seed_status}" in
        ''|*[!0-9]*) return 97 ;;
    esac
    [ "${lifecycle_seed_status}" -le 255 ] || return 97
    case "${lifecycle_seed_log}" in
        /tmp/syswarden-operator-62027.log|\
        /tmp/syswarden-legacy-webtui-process.log) ;;
        *) return 97 ;;
    esac
    lifecycle_seed_actual_bytes="$(
        printf '%s' "${lifecycle_seed_actual}" | LC_ALL=C wc -c | tr -d ' '
    )" || return 97
    lifecycle_seed_expected_bytes="$(
        printf '%s' "${lifecycle_seed_expected}" | LC_ALL=C wc -c | tr -d ' '
    )" || return 97
    case "${lifecycle_seed_actual_bytes}:${lifecycle_seed_expected_bytes}" in
        *[!0-9:]*) return 97 ;;
    esac
    [ "${lifecycle_seed_actual_bytes}" -le 256 ] && \
        [ "${lifecycle_seed_expected_bytes}" -le 256 ] || return 97
    lifecycle_seed_actual_hex="$(
        printf '%s' "${lifecycle_seed_actual}" | lifecycle_seed_hex_prefix
    )" || return 97
    lifecycle_seed_expected_hex="$(
        printf '%s' "${lifecycle_seed_expected}" | lifecycle_seed_hex_prefix
    )" || return 97
    lifecycle_seed_log_bytes=0
    lifecycle_seed_log_hex=
    [ -f "${COMMAND_LOG}" ] && [ ! -L "${COMMAND_LOG}" ] || return 97
    lifecycle_seed_command_owner="$(
        stat -c '%u:%g' "${COMMAND_LOG}" 2>/dev/null || true
    )"
    [ -n "${lifecycle_seed_command_owner}" ] || return 97
    if [ -e "${lifecycle_seed_log}" ] || [ -L "${lifecycle_seed_log}" ]; then
        [ -f "${lifecycle_seed_log}" ] && [ ! -L "${lifecycle_seed_log}" ] && \
            [ "$(stat -c '%u:%g' "${lifecycle_seed_log}" 2>/dev/null || true)" = \
                "${lifecycle_seed_command_owner}" ] || return 97
        lifecycle_seed_log_bytes="$(
            LC_ALL=C wc -c < "${lifecycle_seed_log}" | tr -d ' '
        )" || return 97
        case "${lifecycle_seed_log_bytes}" in
            ''|*[!0-9]*) return 97 ;;
        esac
        [ "${lifecycle_seed_log_bytes}" -le 1048576 ] || return 97
        lifecycle_seed_log_hex="$(
            LC_ALL=C head -c 256 "${lifecycle_seed_log}" | lifecycle_seed_hex_prefix
        )" || return 97
    fi
    printf '%s\tpredicate=%s\trc=%s\tactual_bytes=%s\tactual_hex_prefix=%s\texpected_bytes=%s\texpected_hex_prefix=%s\tlog_bytes=%s\tlog_hex_prefix=%s\n' \
        'SYSWARDEN_LIFECYCLE_SEED_FAILURE_V1' \
        "${lifecycle_seed_predicate}" "${lifecycle_seed_status}" \
        "${lifecycle_seed_actual_bytes}" "${lifecycle_seed_actual_hex}" \
        "${lifecycle_seed_expected_bytes}" "${lifecycle_seed_expected_hex}" \
        "${lifecycle_seed_log_bytes}" "${lifecycle_seed_log_hex}" \
        >> "${COMMAND_LOG}"
}

stop_lifecycle_seed_process() {
    lifecycle_seed_pid="$1"
    case "${lifecycle_seed_pid}" in ''|*[!0-9]*) return 97 ;; esac
    [ "${lifecycle_seed_pid}" -gt 1 ] || return 97
    if kill -0 "${lifecycle_seed_pid}" 2>/dev/null; then
        kill -KILL "${lifecycle_seed_pid}" 2>/dev/null || return 97
    fi
    wait "${lifecycle_seed_pid}" 2>/dev/null || true
}

seed_legacy_webtui_upgrade_state() {
    quiesce_previous_webtui_runtime || return 1
    legacy_module=/etc/syswarden/config/modules/98-legacy-webtui.toml
    printf '%s\n' \
        '# Historical browser credential seeded for bounded upgrade cleanup' \
        '[user]' \
        'webtui_password = "lot0-lifecycle-retired-token"' \
        'profile_name = "preserve-after-browser-retirement"' \
        > "${legacy_module}" || return 1
    chmod 0640 "${legacy_module}" || return 1
    mkdir -p /run
    [ ! -e /run/syswarden-webtui.pid ] && [ ! -L /run/syswarden-webtui.pid ] || return 1
    write_exclusive_root_pidfile /run/syswarden-webtui.pid 4194303 || return 1
    [ -f /run/syswarden-webtui.pid ] && [ ! -L /run/syswarden-webtui.pid ] && \
        [ "$(stat -c '%u:%g:%a' /run/syswarden-webtui.pid 2>/dev/null || true)" = 0:0:600 ] || return 1
    seeded_webtui_pidfile_identity="$(stat -c '%d:%i' \
        /run/syswarden-webtui.pid 2>/dev/null || true)"
    [ -n "${seeded_webtui_pidfile_identity}" ] || return 1
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
            systemctl daemon-reload || return 1
            ;;
        apk)
            [ -d /run ] && [ ! -L /run ] || return 1
            prepare_service_runtime_fixture || return 1
            chmod 0644 /run/syswarden-webtui.pid || return 1
            [ -f /run/syswarden-webtui.pid ] && [ ! -L /run/syswarden-webtui.pid ] && \
                [ "$(stat -c '%d:%i' /run/syswarden-webtui.pid 2>/dev/null || true)" = \
                    "${seeded_webtui_pidfile_identity}" ] && \
                [ "$(stat -c '%u:%g:%a' /run/syswarden-webtui.pid 2>/dev/null || true)" = 0:0:644 ] && \
                printf '%s\n' 4194303 | cmp -s - /run/syswarden-webtui.pid || return 1
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

    socat TCP4-LISTEN:62027,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat \
        >/tmp/syswarden-operator-62027.log 2>&1 &
    operator_listener_pid=$!
    (umask 077 && printf '%s\n' "${operator_listener_pid}" > "${PERSIST_ROOT}/operator-62027.pid") || {
        kill -KILL "${operator_listener_pid}" 2>/dev/null || true
        wait "${operator_listener_pid}" 2>/dev/null || true
        return 1
    }
    operator_listener_ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [ "$(printf '%s' 'syswarden-operator-62027' | \
            socat -T 1 - TCP4:127.0.0.1:62027 2>/dev/null || true)" = \
            'syswarden-operator-62027' ]; then
            operator_listener_ready=1
            break
        fi
        kill -0 "${operator_listener_pid}" 2>/dev/null || break
        sleep 0.1
    done
    if [ "${operator_listener_ready}" -ne 1 ]; then
        operator_listener_alive=0
        kill -0 "${operator_listener_pid}" 2>/dev/null && operator_listener_alive=1
        record_lifecycle_seed_failure LS01_OPERATOR_LISTENER_READY 1 \
            "ready=${operator_listener_ready}|alive=${operator_listener_alive}" \
            'ready=1|alive=1' /tmp/syswarden-operator-62027.log
        operator_listener_diagnostic_rc=$?
        stop_lifecycle_seed_process "${operator_listener_pid}" || return 97
        [ "${operator_listener_diagnostic_rc}" -eq 0 ] || \
            return "${operator_listener_diagnostic_rc}"
        return 1
    fi
    operator_listener_expected_executable="$(command -v socat 2>/dev/null || true)"
    operator_listener_expected_executable="$(readlink -f \
        "${operator_listener_expected_executable}" 2>/dev/null || true)"
    operator_listener_seeded_executable="$(readlink \
        "/proc/${operator_listener_pid}/exe" 2>/dev/null || true)"
    if [ -z "${operator_listener_expected_executable}" ] || \
       [ "${operator_listener_seeded_executable}" != \
           "${operator_listener_expected_executable}" ]; then
        record_lifecycle_seed_failure LS02_OPERATOR_EXECUTABLE_PATH 1 \
            "${operator_listener_seeded_executable}" \
            "${operator_listener_expected_executable}" \
            /tmp/syswarden-operator-62027.log
        operator_listener_diagnostic_rc=$?
        stop_lifecycle_seed_process "${operator_listener_pid}" || return 97
        [ "${operator_listener_diagnostic_rc}" -eq 0 ] || \
            return "${operator_listener_diagnostic_rc}"
        return 1
    fi
    SEEDED_OPERATOR_LISTENER_PID="${operator_listener_pid}"
    if ! SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY="$(
        operator_listener_process_identity "${operator_listener_pid}"
    )"; then
        record_lifecycle_seed_failure LS03_OPERATOR_PROCESS_IDENTITY 1 \
            unavailable canonical-process-identity \
            /tmp/syswarden-operator-62027.log
        operator_listener_diagnostic_rc=$?
        stop_lifecycle_seed_process "${operator_listener_pid}" || return 97
        [ "${operator_listener_diagnostic_rc}" -eq 0 ] || \
            return "${operator_listener_diagnostic_rc}"
        return 1
    fi
    if ! SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY="$(
        stat -c '%d:%i:%s:%u:%g:%a' \
            "${PERSIST_ROOT}/operator-62027.pid" 2>/dev/null
    )"; then
        record_lifecycle_seed_failure LS04_OPERATOR_PIDFILE_IDENTITY 1 \
            unavailable canonical-pidfile-identity \
            /tmp/syswarden-operator-62027.log
        operator_listener_diagnostic_rc=$?
        stop_lifecycle_seed_process "${operator_listener_pid}" || return 97
        [ "${operator_listener_diagnostic_rc}" -eq 0 ] || \
            return "${operator_listener_diagnostic_rc}"
        return 1
    fi
    if ! SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY="$(
        operator_listener_socket_identity "${operator_listener_pid}"
    )"; then
        record_lifecycle_seed_failure LS05_OPERATOR_SOCKET_IDENTITY 1 \
            unavailable canonical-socket-identity \
            /tmp/syswarden-operator-62027.log
        operator_listener_diagnostic_rc=$?
        stop_lifecycle_seed_process "${operator_listener_pid}" || return 97
        [ "${operator_listener_diagnostic_rc}" -eq 0 ] || \
            return "${operator_listener_diagnostic_rc}"
        return 1
    fi
    [ -n "${SEEDED_OPERATOR_LISTENER_PROCESS_IDENTITY}" ] && \
        [ -n "${SEEDED_OPERATOR_LISTENER_PIDFILE_IDENTITY}" ] && \
        [ -n "${SEEDED_OPERATOR_LISTENER_SOCKET_IDENTITY}" ] || return 1
}

seed_legacy_saas_monitor_state() {
    legacy_saas_v4=/etc/syswarden/lists/syswarden_saas_monitors.ipv4
    legacy_saas_v6=/etc/syswarden/lists/syswarden_saas_monitors.ipv6
    legacy_saas_pair=/etc/syswarden/lists/syswarden_saas_monitors.pair
    mkdir -p /etc/syswarden/lists || return 1
    printf '%s\n%s' '8.8.8.8' '1.1.1.0/24' > "${legacy_saas_v4}" || return 1
    chmod 0600 "${legacy_saas_v4}" || return 1
    chown 0:0 "${legacy_saas_v4}" || return 1
    rm -f "${legacy_saas_v6}" "${legacy_saas_pair}" || return 1
    : > "${PERSIST_ROOT}/legacy-saas-seeded"
}

seed_live_legacy_webtui_process() {
    case "${PACKAGE_FAMILY}" in
        deb|rpm) ;;
        *) return 0 ;;
    esac
    if v4032_to_v4033_upgrade_selected; then
        return 0
    fi
    /opt/syswarden/bin/syswarden-cli web-tui \
        --bind=127.0.0.1:62028 --token=lot0-lifecycle-live-retired-token \
        >/tmp/syswarden-legacy-webtui-process.log 2>&1 &
    legacy_webtui_pid=$!
    printf '%s\n' "${legacy_webtui_pid}" > "${PERSIST_ROOT}/legacy-webtui-process.pid"
    legacy_webtui_ready=0
    legacy_webtui_status=000
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
        legacy_webtui_alive=0
        kill -0 "${legacy_webtui_pid}" 2>/dev/null && legacy_webtui_alive=1
        record_lifecycle_seed_failure LS06_LIVE_WEBTUI_READY 1 \
            "ready=${legacy_webtui_ready}|alive=${legacy_webtui_alive}|http=${legacy_webtui_status}" \
            'ready=1|alive=1|http=401' \
            /tmp/syswarden-legacy-webtui-process.log
        legacy_webtui_diagnostic_rc=$?
        stop_lifecycle_seed_process "${legacy_webtui_pid}" || return 97
        [ "${legacy_webtui_diagnostic_rc}" -eq 0 ] || \
            return "${legacy_webtui_diagnostic_rc}"
        return 1
    fi
}

load_state_contract() {
    [ -f "${OPERATOR_STATE_FILE}" ] || return 1
    STATE_CONFIG_HASH="$(sed -n 's/^STATE_CONFIG_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_TOKEN_HASH="$(sed -n 's/^STATE_TOKEN_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_LIST_HASH="$(sed -n 's/^STATE_LIST_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_LIST_IPV6_HASH="$(sed -n 's/^STATE_LIST_IPV6_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_OPERATOR_DATA_HASH="$(sed -n 's/^STATE_OPERATOR_DATA_HASH=//p' "${OPERATOR_STATE_FILE}")"
    STATE_CERT_HASH="$(sed -n 's/^STATE_CERT_HASH=//p' "${OPERATOR_STATE_FILE}")"
    for expected_hash in \
        "${STATE_CONFIG_HASH}" "${STATE_TOKEN_HASH}" "${STATE_LIST_HASH}" \
        "${STATE_LIST_IPV6_HASH}" "${STATE_OPERATOR_DATA_HASH}" "${STATE_CERT_HASH}"
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

live_telemetry_schema_valid() {
    live_telemetry_path="$1"
    [ -f "${live_telemetry_path}" ] && [ ! -L "${live_telemetry_path}" ] || return 1
    live_telemetry_size="$(wc -c < "${live_telemetry_path}" 2>/dev/null | tr -d ' ')" || return 1
    case "${live_telemetry_size}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${live_telemetry_size}" -gt 0 ] && [ "${live_telemetry_size}" -le 8388608 ] || return 1
    jq -e '
        def integer: type == "number" and (floor == .);
        type == "object" and
        (keys == ["github_release", "github_stars", "layer3", "profile_name", "system", "timestamp", "waf", "whitelist"]) and
        (has("ha") | not) and
        (.timestamp | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
        (.github_stars | type == "string") and
        (.github_release | type == "string") and
        (.profile_name | type == "string") and
        (.system |
            type == "object" and
            (keys == ["arch", "cores", "cpu_model", "disk_total_mb", "disk_used_mb", "hostname", "load_average", "os", "ports", "ram_total_mb", "ram_used_mb", "server_ip", "services", "uptime"]) and
            (.hostname | type == "string") and
            (.uptime | type == "string") and
            (.load_average | type == "string") and
            (.ram_used_mb | integer) and
            (.ram_total_mb | integer) and
            (.disk_used_mb | integer) and
            (.disk_total_mb | integer) and
            (.cores | type == "string") and
            (.arch | type == "string") and
            (.os | type == "string") and
            (.cpu_model | type == "string") and
            (.server_ip | type == "string") and
            (.services | type == "array" and all(.[];
                type == "object" and
                (keys == ["name", "path", "status"]) and
                (.name | type == "string") and
                (.path | type == "string") and
                (.status | type == "string"))) and
            (.ports | type == "array" and all(.[];
                type == "object" and
                (keys == ["ip", "port", "protocol", "state"]) and
                (.ip | type == "string") and
                (.state | type == "string") and
                (.port | type == "string") and
                (.protocol | type == "string")))) and
        (.layer3 |
            type == "object" and
            (keys == ["asn_blocked", "geoip_blocked", "global_blocked", "l7_banned", "zero_trust_mode"]) and
            (.global_blocked | integer) and
            (.geoip_blocked | integer) and
            (.asn_blocked | integer) and
            (.l7_banned | integer) and
            (.zero_trust_mode | type == "boolean")) and
        (.waf |
            type == "object" and
            (keys == ["active_signatures", "allowed_events", "banned_ips", "risk_radar", "signatures_data", "sparkline_24h", "targeted_ports", "top_attackers", "total_banned", "total_detected"]) and
            (.total_banned | integer) and
            (.total_detected | integer) and
            (.active_signatures | integer) and
            (.signatures_data | type == "array" and all(.[];
                type == "object" and
                (keys == ["count", "mitre", "name"]) and
                (.name | type == "string") and
                (.count | integer) and
                (.mitre | type == "string"))) and
            (.targeted_ports | . == null or
                (type == "array" and all(.[];
                    type == "object" and
                    (keys == ["hits", "port", "service", "unique_ips"]) and
                    (.port | type == "string") and
                    (.service | type == "string") and
                    (.hits | integer) and
                    (.unique_ips | integer)))) and
            (.banned_ips | type == "array" and all(.[];
                type == "object" and
                (keys == ["action", "ip", "jail", "mitre", "payload", "timestamp"]) and
                (.timestamp | type == "string") and
                (.ip | type == "string") and
                (.jail | type == "string") and
                (.payload | type == "string") and
                (.mitre | type == "string") and
                (.action | type == "string"))) and
            (.top_attackers | type == "array" and all(.[];
                type == "object" and
                (keys == ["asn", "country", "hits", "ip", "last_seen", "org", "port", "severity", "threat"]) and
                (.ip | type == "string") and
                (.severity | type == "string") and
                (.port | type == "string") and
                (.country | type == "string") and
                (.asn | type == "string") and
                (.threat | type == "string") and
                (.org | type == "string") and
                (.hits | integer) and
                (.last_seen | type == "string"))) and
            (.risk_radar | . == null or (type == "array" and all(.[]; integer))) and
            (.sparkline_24h | type == "array" and length == 24 and all(.[]; integer)) and
            (.allowed_events | . == null or
                (type == "array" and all(.[];
                    type == "object" and
                    (keys == ["ip", "payload", "service", "timestamp"]) and
                    (.timestamp | type == "string") and
                    (.ip | type == "string") and
                    (.service | type == "string") and
                    (.payload | type == "string"))))) and
        (.whitelist |
            type == "object" and
            (keys == ["active_ips", "ips"]) and
            (.active_ips | integer) and
            (.ips | type == "array" and all(.[]; type == "string")))
    ' "${live_telemetry_path}" >/dev/null 2>&1
}

assert_live_telemetry_data() {
    label="$1"
    live_telemetry_path="${2:-/var/lib/syswarden/ui/data.json}"
    if [ -f "${live_telemetry_path}" ] && [ ! -L "${live_telemetry_path}" ]; then
        actual_type=regular
        actual_mode="$(file_mode "${live_telemetry_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${live_telemetry_path}" 2>/dev/null || true)"
        actual_json=invalid
        actual_schema=invalid
        live_telemetry_size="$(wc -c < "${live_telemetry_path}" 2>/dev/null | tr -d ' ')" || live_telemetry_size=invalid
        case "${live_telemetry_size}" in
            ''|*[!0-9]*) ;;
            *)
                if [ "${live_telemetry_size}" -gt 0 ] && \
                   [ "${live_telemetry_size}" -le 8388608 ] && \
                   jq -e . "${live_telemetry_path}" >/dev/null 2>&1; then
                    actual_json=valid
                fi
                ;;
        esac
        if live_telemetry_schema_valid "${live_telemetry_path}"; then
            actual_schema=dashboard-data-v1
        fi
    elif [ -L "${live_telemetry_path}" ]; then
        actual_type=symlink
        actual_mode="$(file_mode "${live_telemetry_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${live_telemetry_path}" 2>/dev/null || true)"
        actual_json=invalid
        actual_schema=invalid
    elif [ -e "${live_telemetry_path}" ]; then
        actual_type=unsupported
        actual_mode="$(file_mode "${live_telemetry_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${live_telemetry_path}" 2>/dev/null || true)"
        actual_json=invalid
        actual_schema=invalid
    else
        actual_type=missing
        actual_mode=-
        actual_owner=-
        actual_json=invalid
        actual_schema=invalid
    fi
    check_equal "${label}.state.telemetry.type" regular "${actual_type}"
    check_equal "${label}.state.telemetry.mode" 600 "${actual_mode}"
    check_equal "${label}.state.telemetry.owner" 0:0 "${actual_owner}"
    check_equal "${label}.state.telemetry.json" valid "${actual_json}"
    check_equal "${label}.state.telemetry.schema" dashboard-data-v1 "${actual_schema}"
}

sanitize_historical_rollback_token() {
    rollback_token_source="$1"
    rollback_token_sanitized="$2"
    rollback_token_secret_file="$3"
    [ ! -e "${rollback_token_sanitized}" ] && \
        [ ! -L "${rollback_token_sanitized}" ] && \
        [ ! -e "${rollback_token_secret_file}" ] && \
        [ ! -L "${rollback_token_secret_file}" ] || return 1
    (umask 077 && : > "${rollback_token_sanitized}" && \
        : > "${rollback_token_secret_file}") || return 1
    rollback_token_last_octet="$(tail -c 1 "${rollback_token_source}" | \
        od -An -tu1 -v | tr -d '[:space:]')" || return 1
    [ -n "${rollback_token_last_octet}" ] && \
        [ "${rollback_token_last_octet}" != 10 ] || return 1
    LC_ALL=C awk -v secret_file="${rollback_token_secret_file}" '
        BEGIN {
            in_user = 0
            credentials = 0
            have_buffer = 0
            after_credential = 0
        }
        {
            if (after_credential) {
                exit 42
            }
            if (index($0, "webtui_password") != 0) {
                if (!in_user || !have_buffer || buffered != "" ||
                    $0 !~ /^webtui_password = "[0-9a-f]+"$/) {
                    exit 42
                }
                secret = substr($0, 20, length($0) - 20)
                if (length(secret) != 32 || secret ~ /[^0-9a-f]/) {
                    exit 42
                }
                credentials++
                print secret > secret_file
                have_buffer = 0
                after_credential = 1
                next
            }
            if (have_buffer) {
                print buffered
            }
            buffered = $0
            have_buffer = 1
            if ($0 ~ /^\[/) {
                in_user = ($0 == "[user]")
            }
        }
        END {
            if (credentials != 1 || !after_credential) {
                exit 43
            }
        }
    ' "${rollback_token_source}" > "${rollback_token_sanitized}"
}

assert_historical_rollback_token() {
    label="$1"
    token_path=/etc/syswarden/config/modules/99-user.toml
    sanitized=/tmp/syswarden-rollback-token-sanitized
    secret_file=/tmp/syswarden-rollback-token-secret
    rm -f "${sanitized}" "${secret_file}"
    if [ -f "${token_path}" ] && [ ! -L "${token_path}" ]; then
        actual_type=regular
        actual_mode="$(file_mode "${token_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${token_path}" 2>/dev/null || true)"
    elif [ -L "${token_path}" ]; then
        actual_type=symlink
        actual_mode="$(file_mode "${token_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${token_path}" 2>/dev/null || true)"
    elif [ -e "${token_path}" ]; then
        actual_type=unsupported
        actual_mode="$(file_mode "${token_path}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${token_path}" 2>/dev/null || true)"
    else
        actual_type=missing
        actual_mode=-
        actual_owner=-
    fi
    sanitized_hash=invalid
    if [ "${actual_type}" = regular ] && [ "${actual_mode}" = 640 ] && \
       [ "${actual_owner}" = 0:0 ] && \
       [ "$(wc -c < "${token_path}" | tr -d ' ')" -le 8388608 ] && \
       sanitize_historical_rollback_token \
           "${token_path}" "${sanitized}" "${secret_file}"; then
        rollback_secret="$(cat "${secret_file}" 2>/dev/null || true)"
        if [ "${#rollback_secret}" -eq 32 ] && \
           ! grep -Fq "${rollback_secret}" "${COMMAND_LOG}" 2>/dev/null; then
            sanitized_hash="$(hash_file "${sanitized}" 2>/dev/null || true)"
        fi
    fi
    check_equal "${label}.state.token.type" regular "${actual_type}"
    check_equal "${label}.state.token.hash" "${STATE_TOKEN_HASH}" "${sanitized_hash}"
    check_equal "${label}.state.token.mode" 640 "${actual_mode}"
    check_equal "${label}.state.token.owner" 0:0 "${actual_owner}"
    rm -f "${sanitized}" "${secret_file}"
}

expected_upgrade_rollback_token_contract() {
    label="$1"
    [ "${SCENARIO}:${label}" = upgrade-rollback:rollback ] || return 1
    case "${PACKAGE_FAMILY}" in
        deb|rpm) ;;
        *) return 1 ;;
    esac
    if v4028_to_v4032_transition_selected; then
        printf '%s\n' historical-webtui-credential
    elif v4032_to_v4033_transition_selected; then
        printf '%s\n' byte-exact
    else
        return 1
    fi
}

record_unsupported_rollback_token_contract() {
    label="$1"
    check_equal "${label}.state.token.type" regular unsupported-transition
    check_equal "${label}.state.token.hash" "${STATE_TOKEN_HASH}" unsupported-transition
    check_equal "${label}.state.token.mode" 640 unsupported-transition
    check_equal "${label}.state.token.owner" 0:0 unsupported-transition
}

assert_all_state_preserved() {
    label="$1"
    assert_preserved "${label}" config /etc/syswarden/config/lifecycle-operator.conf "${STATE_CONFIG_HASH}" 640
    if [ "${SCENARIO}:${label}:${PACKAGE_FAMILY}" = upgrade-rollback:rollback:deb ] || \
       [ "${SCENARIO}:${label}:${PACKAGE_FAMILY}" = upgrade-rollback:rollback:rpm ]; then
        rollback_token_contract="$(
            expected_upgrade_rollback_token_contract "${label}" 2>/dev/null || true
        )"
        case "${rollback_token_contract}" in
            historical-webtui-credential)
                assert_historical_rollback_token "${label}"
                ;;
            byte-exact)
                assert_preserved "${label}" token /etc/syswarden/config/modules/99-user.toml "${STATE_TOKEN_HASH}" 640
                ;;
            *)
                record_unsupported_rollback_token_contract "${label}"
                ;;
        esac
    else
        assert_preserved "${label}" token /etc/syswarden/config/modules/99-user.toml "${STATE_TOKEN_HASH}" 640
    fi
    assert_preserved "${label}" list /etc/syswarden/lists/syswarden_blacklist.ipv4 "${STATE_LIST_HASH}" 600
    assert_preserved "${label}" list_ipv6 /etc/syswarden/lists/syswarden_blacklist.ipv6 "${STATE_LIST_IPV6_HASH}" 600
    assert_preserved "${label}" operator_data /var/lib/syswarden/ui/lifecycle-operator.json "${STATE_OPERATOR_DATA_HASH}" 600
    assert_preserved "${label}" certificate /etc/syswarden/tls/operator.pem "${STATE_CERT_HASH}" 600
    assert_live_telemetry_data "${label}"
}

assert_deb_removal_log_preserved() {
    label="$1"
    [ "${PACKAGE_FAMILY}" = deb ] || return 1
    assert_preserved \
        "${label}" log \
        /var/log/syswarden/lifecycle-operator.log \
        "${STATE_LOG_HASH}" 600
}

assert_deferred_purge_marker() {
    label="$1"
    marker=/var/lib/syswarden/removed-awaiting-purge-v1
    expected_hash=e1a0bbd8e3d90884bdaf9306233e6c2cfb5ab752c3065939139119982fed4514
    if [ -f "${marker}" ] && [ ! -L "${marker}" ]; then
        actual_type=regular
        actual_hash="$(hash_file "${marker}" 2>/dev/null || true)"
        actual_mode="$(file_mode "${marker}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${marker}" 2>/dev/null || true)"
        actual_links="$(stat -c '%h' "${marker}" 2>/dev/null || true)"
    elif [ -L "${marker}" ]; then
        actual_type=symlink
        actual_hash=invalid
        actual_mode="$(file_mode "${marker}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${marker}" 2>/dev/null || true)"
        actual_links="$(stat -c '%h' "${marker}" 2>/dev/null || true)"
    elif [ -e "${marker}" ]; then
        actual_type=unsupported
        actual_hash=invalid
        actual_mode="$(file_mode "${marker}" 2>/dev/null || true)"
        actual_owner="$(stat -c '%u:%g' "${marker}" 2>/dev/null || true)"
        actual_links="$(stat -c '%h' "${marker}" 2>/dev/null || true)"
    else
        actual_type=missing
        actual_hash=missing
        actual_mode=-
        actual_owner=-
        actual_links=-
    fi
    check_equal "${label}.state.deferred_purge_marker.type" regular "${actual_type}"
    check_equal "${label}.state.deferred_purge_marker.hash" "${expected_hash}" "${actual_hash}"
    check_equal "${label}.state.deferred_purge_marker.mode" 600 "${actual_mode}"
    check_equal "${label}.state.deferred_purge_marker.owner" 0:0 "${actual_owner}"
    check_equal "${label}.state.deferred_purge_marker.links" 1 "${actual_links}"
}

assert_dedicated_roots_absent() {
    label="$1"
    check_absent "${label}.state.opt_root" /opt/syswarden
    check_absent "${label}.state.config_root" /etc/syswarden
    check_absent "${label}.state.data_root" /var/lib/syswarden
    check_absent "${label}.state.log_root" /var/log/syswarden
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
    done < "${PERSIST_ROOT}/inventory-${expected_label}"
    if [ -s "${remaining}" ]; then
        record fail "${PREFIX}.${label}.payload_inventory" "package-owned files or links remain: $(tr '\n' ' ' < "${remaining}")"
    else
        record pass "${PREFIX}.${label}.payload_inventory" "all package-owned files and links are absent"
    fi
}

rsyslog_exec_reload_succeeded() {
    reload_records="$1"
    [ -n "${reload_records}" ] || return 1
    printf '%s\n' "${reload_records}" | LC_ALL=C awk '
        BEGIN { count = 0 }
        {
            count++
            if ($0 !~ /^[{] path=\/[^;]+ ; argv\[\]=[^;]+ ; ignore_errors=(yes|no) ; start_time=\[[^]]+\] ; stop_time=\[[^]]+\] ; pid=[0-9]+ ; code=exited ; status=0(\/SUCCESS)? [}]$/) {
                exit 1
            }
            if (index($0, "start_time=[n/a]") ||
                index($0, "stop_time=[n/a]")) {
                exit 1
            }
            pid = $0
            sub(/^.* ; pid=/, "", pid)
            sub(/ ; code=.*$/, "", pid)
            if (pid !~ /^[0-9]+$/ || pid + 0 <= 1) {
                exit 1
            }
        }
        END { if (count < 1) exit 1 }
    '
}

rsyslog_reactivation_mode() {
    reload_before="$1"
    reload_after="$2"
    main_pid_before="$3"
    main_pid_after="$4"
    active_enter_before="$5"
    active_enter_after="$6"
    for reactivation_number in \
        "${main_pid_before}" \
        "${main_pid_after}" \
        "${active_enter_before}" \
        "${active_enter_after}"; do
        case "${reactivation_number}" in
            ''|*[!0-9]*) return 1 ;;
        esac
    done
    [ "${main_pid_before}" -gt 1 ] && \
        [ "${main_pid_after}" -gt 1 ] && \
        [ "${active_enter_before}" -gt 0 ] && \
        [ "${active_enter_after}" -gt 0 ] || return 1

    if [ -n "${reload_before}" ] && \
       [ -n "${reload_after}" ] && \
       [ "${reload_after}" != "${reload_before}" ] && \
       rsyslog_exec_reload_succeeded "${reload_after}" && \
       [ "${main_pid_after}" -eq "${main_pid_before}" ]; then
        printf '%s\n' reload
        return 0
    fi
    if [ "${main_pid_after}" -ne "${main_pid_before}" ] && \
       [ "${active_enter_after}" -gt "${active_enter_before}" ]; then
        printf '%s\n' restart
        return 0
    fi
    return 1
}

attest_owned_cron_seed_state() {
    syswarden_owned_cron_path="$1"
    syswarden_owned_cron_evidence_label="$2"
    case "${PACKAGE_FAMILY}:${SCENARIO}:${syswarden_owned_cron_evidence_label}" in
        deb:remove:remove-before-purge)
            [ ! -e "${syswarden_owned_cron_path}" ] && \
                [ ! -L "${syswarden_owned_cron_path}" ] || return 1
            ;;
        *)
            [ -f "${syswarden_owned_cron_path}" ] && \
                [ ! -L "${syswarden_owned_cron_path}" ] || return 1
            ;;
    esac
}

seed_generated_runtime_artifacts() {
    rsyslog_contract="${1:-ambiguous-rsyslog}"
    evidence_label="${2:-}"
    mkdir -p /etc/rsyslog.d
    case "${rsyslog_contract}" in
        exact-rsyslog)
            [ "${PACKAGE_FAMILY}" = deb ] || return 1
            [ -n "${evidence_label}" ] || return 1
            for path in \
                /etc/rsyslog.d/99-syswarden-siem.conf \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf \
                /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1; do
                [ -f "${path}" ] && [ ! -L "${path}" ] || return 1
                [ "$(stat -c '%u:%g:%a:%h' "${path}" 2>/dev/null || true)" = 0:0:600:1 ] || return 1
            done
            [ "$(grep -F -x -c '*.* @127.0.0.1:5514' \
                /etc/rsyslog.d/99-syswarden-siem.conf || true)" = 1 ] || return 1
            for forbidden_fragment in \
                'imfile' \
                '/var/log/syswarden/waf.json' \
                'syswarden-waf-json' \
                'Facility="local7"'; do
                ! grep -F -q "${forbidden_fragment}" \
                    /etc/rsyslog.d/99-syswarden-siem.conf || return 1
            done
            [ "$(grep -F -x -c 'module(load="imfile")' \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true)" = 1 ] || return 1
            [ "$(grep -F -x -c 'input(type="imfile"' \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true)" = 1 ] || return 1
            waf_telemetry_input_block="$(
                sed -n \
                    '/^input(type="imfile"$/,/^[[:space:]]*Facility="local7")[[:space:]]*$/p' \
                    /etc/rsyslog.d/99-syswarden-waf-bridge.conf
            )" || return 1
            [ -n "${waf_telemetry_input_block}" ] || return 1
            for telemetry_fragment in \
                'File="/var/log/syswarden/waf.json"' \
                'Tag="syswarden-waf-json"' \
                'Facility="local7"'; do
                [ "$(printf '%s\n' "${waf_telemetry_input_block}" | \
                    grep -F -c "${telemetry_fragment}" || true)" = 1 ] || return 1
            done
            ! printf '%s\n' "${waf_telemetry_input_block}" | \
                grep -F -q 'ruleset="waf_bridge"' || return 1
            for fragment in \
                'module(load="omuxsock")' \
                '$OMUxSockSocket /var/run/syswarden.sock' \
                'input(type="imfile" File="/var/log/nginx/*.log" Tag="syswarden-waf" ruleset="waf_bridge")' \
                'input(type="imfile" File="/var/log/auth.log" Tag="syswarden-waf" ruleset="waf_bridge")' \
                '*.* :omuxsock:;SYSWARDENRaw'; do
                grep -F -q "${fragment}" \
                    /etc/rsyslog.d/99-syswarden-waf-bridge.conf || return 1
            done
            /usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf >> \
                "${COMMAND_LOG}" 2>&1 || return 1
            hash_file /etc/rsyslog.d/99-syswarden-siem.conf > \
                /tmp/syswarden-rsyslog-siem-before || return 1
            hash_file /etc/rsyslog.d/99-syswarden-waf-bridge.conf > \
                /tmp/syswarden-rsyslog-waf-before || return 1
            wc -c < /etc/rsyslog.d/99-syswarden-siem.conf | tr -d '[:space:]' > \
                /tmp/syswarden-rsyslog-siem-size || return 1
            wc -c < /etc/rsyslog.d/99-syswarden-waf-bridge.conf | tr -d '[:space:]' > \
                /tmp/syswarden-rsyslog-waf-size || return 1
            [ "$(sed -n '1p' /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1)" = \
                syswarden-rsyslog-provenance-v1 ] || return 1
            [ "$(wc -l < /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1 | tr -d '[:space:]')" = 3 ] || return 1
            grep -F -x -q "$(printf '%s\t%s\t%s' \
                99-syswarden-siem.conf \
                "$(cat /tmp/syswarden-rsyslog-siem-size)" \
                "$(cat /tmp/syswarden-rsyslog-siem-before)")" \
                /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1 || return 1
            grep -F -x -q "$(printf '%s\t%s\t%s' \
                99-syswarden-waf-bridge.conf \
                "$(cat /tmp/syswarden-rsyslog-waf-size)" \
                "$(cat /tmp/syswarden-rsyslog-waf-before)")" \
                /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1 || return 1
            LC_ALL=C systemctl show rsyslog.service -p ExecReload --value > \
                /tmp/syswarden-rsyslog-reload-before || return 1
            LC_ALL=C systemctl show rsyslog.service -p MainPID --value > \
                /tmp/syswarden-rsyslog-pid-before || return 1
            LC_ALL=C systemctl show rsyslog.service \
                -p ActiveEnterTimestampMonotonic --value > \
                /tmp/syswarden-rsyslog-active-enter-before || return 1
            rsyslog_pid_before="$(cat /tmp/syswarden-rsyslog-pid-before)"
            rsyslog_active_enter_before="$(
                cat /tmp/syswarden-rsyslog-active-enter-before
            )"
            case "${rsyslog_pid_before}" in ''|*[!0-9]*) return 1 ;; esac
            case "${rsyslog_active_enter_before}" in
                ''|*[!0-9]*) return 1 ;;
            esac
            [ "${rsyslog_pid_before}" -gt 1 ] && \
                [ "${rsyslog_active_enter_before}" -gt 0 ] && \
                kill -0 "${rsyslog_pid_before}" 2>/dev/null || return 1
            record pass \
                "${PREFIX}.${evidence_label}.generated.rsyslog_siem_exact_generated" \
                "SIEM-enabled rsyslog bytes are product-generated and provenance-bound sha256=$(cat /tmp/syswarden-rsyslog-siem-before)"
            record pass \
                "${PREFIX}.${evidence_label}.generated.rsyslog_waf_bridge_exact_generated" \
                "WAF rsyslog bytes are product-generated and provenance-bound sha256=$(cat /tmp/syswarden-rsyslog-waf-before)"
            record pass \
                "${PREFIX}.${evidence_label}.generated.rsyslog_provenance_exact" \
                "canonical product provenance binds exactly the generated SIEM and WAF artifacts"
            ;;
        ambiguous-rsyslog)
            rsyslog_provenance=/etc/rsyslog.d/.syswarden-rsyslog-provenance-v1
            [ -f "${rsyslog_provenance}" ] && \
                [ ! -L "${rsyslog_provenance}" ] && \
                [ "$(stat -c '%u:%g:%a:%h' \
                    "${rsyslog_provenance}" 2>/dev/null || true)" = \
                    0:0:600:1 ] || return 1
            hash_file "${rsyslog_provenance}" > \
                /tmp/syswarden-rsyslog-provenance-before || return 1
            printf '%s\n' '# operator-owned ambiguous SIEM bridge preserved by the lifecycle lab' > \
                /etc/rsyslog.d/99-syswarden-siem.conf || return 1
            printf '%s\n' '# operator-owned ambiguous WAF bridge preserved by the lifecycle lab' > \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf || return 1
            chmod 0600 \
                /etc/rsyslog.d/99-syswarden-siem.conf \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf || return 1
            hash_file /etc/rsyslog.d/99-syswarden-siem.conf > \
                /tmp/syswarden-rsyslog-siem-before || return 1
            hash_file /etc/rsyslog.d/99-syswarden-waf-bridge.conf > \
                /tmp/syswarden-rsyslog-waf-before || return 1
            ;;
        *) return 1 ;;
    esac

    mkdir -p /etc/bash_completion.d || return 1
    if [ ! -f /tmp/syswarden-completion-before ]; then
        printf '%s\n' '# operator-owned ambiguous SysWarden completion' > \
            /etc/bash_completion.d/syswarden || return 1
        chmod 0644 /etc/bash_completion.d/syswarden || return 1
        hash_file /etc/bash_completion.d/syswarden > \
            /tmp/syswarden-completion-before || return 1
    elif [ ! -f /etc/bash_completion.d/syswarden ] || \
         [ -L /etc/bash_completion.d/syswarden ] || \
         [ "$(hash_file /etc/bash_completion.d/syswarden 2>/dev/null || true)" != \
             "$(cat /tmp/syswarden-completion-before)" ]; then
        return 1
    fi

    if [ ! -f /tmp/syswarden-root-cron-before ]; then
        if LC_ALL=C crontab -l > /tmp/syswarden-existing-cron 2>/tmp/syswarden-existing-cron.error; then
            :
        elif [ ! -s /tmp/syswarden-existing-cron ] && grep -E -x -q \
            "(no crontab for root|crontab: no crontab for root|crontab: can't open 'root': No such file or directory)" \
            /tmp/syswarden-existing-cron.error; then
            : > /tmp/syswarden-existing-cron
        else
            return 1
        fi
        {
            printf '%s\n' '17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1'
            printf '%s\n' '# operator note mentioning syswarden-cli'
            printf '%s\n' '23 * * * * /srv/operator/bin/syswarden-cli update-feeds >/dev/null 2>&1'
            printf ' \t \n'
        } > "${OPERATOR_CRON_FILE}"
        {
            cat /tmp/syswarden-existing-cron
            cat "${OPERATOR_CRON_FILE}"
        } > /tmp/syswarden-root-cron-before
        crontab - < /tmp/syswarden-root-cron-before || return 1
    fi
    LC_ALL=C crontab -l > /tmp/syswarden-root-cron-confirmed 2>/tmp/syswarden-root-cron-confirmed.error || return 1
    cmp -s /tmp/syswarden-root-cron-before /tmp/syswarden-root-cron-confirmed || return 1
    attest_owned_cron_seed_state \
        /etc/cron.d/syswarden "${evidence_label}" || return 1
    printf '%s' '# Managed by' > /etc/cron.d/.syswarden.pending-v1 || return 1
    chmod 0600 /etc/cron.d/.syswarden.pending-v1 || return 1
}

assert_generated_runtime_artifact_contract() {
    label="$1"
    rsyslog_contract="${2:-ambiguous-rsyslog}"
    if prepare_service_runtime_fixture; then
        record pass "${PREFIX}.${label}.service_manager_calls" "real init, active service manager, and enabled cron provider remain attestable"
    else
        record fail "${PREFIX}.${label}.service_manager_calls" "real init, active service manager, or enabled cron provider became unavailable"
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
    check_absent "${label}.generated.runtime_socket" /run/syswarden.sock
    check_absent "${label}.generated.runtime_lock" /run/syswarden-firewall.lock
    check_absent "${label}.generated.rsyslog_antiforging_exact_removed" \
        /etc/rsyslog.d/99-syswarden-antiforging.conf
    check_absent "${label}.generated.rsyslog_selinux_provenance_removed" \
        /etc/rsyslog.d/.syswarden-rsyslog-selinux-provenance-v1
    if [ -f /etc/bash_completion.d/syswarden ] && [ ! -L /etc/bash_completion.d/syswarden ] && \
       [ "$(hash_file /etc/bash_completion.d/syswarden 2>/dev/null || true)" = "$(cat /tmp/syswarden-completion-before)" ]; then
        record pass "${PREFIX}.${label}.generated.completion_residual" "ambiguous shell completion is preserved for manual recovery"
    else
        record fail "${PREFIX}.${label}.generated.completion_residual" "ambiguous shell completion changed during removal"
    fi
    case "${rsyslog_contract}" in
        exact-rsyslog)
            check_absent "${label}.generated.rsyslog_siem_exact_removed" \
                /etc/rsyslog.d/99-syswarden-siem.conf
            check_absent "${label}.generated.rsyslog_waf_bridge_exact_removed" \
                /etc/rsyslog.d/99-syswarden-waf-bridge.conf
            check_absent "${label}.generated.rsyslog_provenance_removed" \
                /etc/rsyslog.d/.syswarden-rsyslog-provenance-v1
            if /usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf >> "${COMMAND_LOG}" 2>&1; then
                record pass "${PREFIX}.${label}.generated.rsyslog_configuration_valid" \
                    "complete rsyslog configuration validates after exact generated bridge removal"
            else
                record fail "${PREFIX}.${label}.generated.rsyslog_configuration_valid" \
                    "complete rsyslog configuration is invalid after exact generated bridge removal"
            fi
            rsyslog_reload_before="$(cat /tmp/syswarden-rsyslog-reload-before 2>/dev/null || true)"
            rsyslog_reload_after="$(LC_ALL=C systemctl show rsyslog.service -p ExecReload --value 2>/dev/null || true)"
            rsyslog_pid_before="$(cat /tmp/syswarden-rsyslog-pid-before 2>/dev/null || true)"
            rsyslog_active_enter_before="$(cat /tmp/syswarden-rsyslog-active-enter-before 2>/dev/null || true)"
            rsyslog_pid_after="$(LC_ALL=C systemctl show rsyslog.service -p MainPID --value 2>/dev/null || true)"
            rsyslog_active_enter_after="$(LC_ALL=C systemctl show rsyslog.service -p ActiveEnterTimestampMonotonic --value 2>/dev/null || true)"
            case "${rsyslog_pid_after}" in ''|*[!0-9]*) rsyslog_pid_after=0 ;; esac
            rsyslog_reactivation_proof="$(rsyslog_reactivation_mode \
                "${rsyslog_reload_before}" "${rsyslog_reload_after}" \
                "${rsyslog_pid_before}" "${rsyslog_pid_after}" \
                "${rsyslog_active_enter_before}" \
                "${rsyslog_active_enter_after}" 2>/dev/null || true)"
            if { [ "${rsyslog_reactivation_proof}" = reload ] || \
                 [ "${rsyslog_reactivation_proof}" = restart ]; } && \
               [ "$(systemctl is-active rsyslog.service 2>/dev/null || true)" = active ] && \
               [ "${rsyslog_pid_after}" -gt 1 ] && \
               kill -0 "${rsyslog_pid_after}" 2>/dev/null; then
                record pass "${PREFIX}.${label}.generated.rsyslog_reactivated" \
                    "rsyslog completed a successful ${rsyslog_reactivation_proof} activation and remains active after exact cleanup"
            else
                record fail "${PREFIX}.${label}.generated.rsyslog_reactivated" \
                    "rsyslog lacks portable evidence of a successful reload or restart fallback after exact cleanup"
            fi
            ;;
        ambiguous-rsyslog)
            if [ -f /etc/rsyslog.d/99-syswarden-siem.conf ] && [ ! -L /etc/rsyslog.d/99-syswarden-siem.conf ] && \
               [ "$(hash_file /etc/rsyslog.d/99-syswarden-siem.conf 2>/dev/null || true)" = "$(cat /tmp/syswarden-rsyslog-siem-before)" ]; then
                record pass "${PREFIX}.${label}.generated.rsyslog_siem_residual" "ambiguous rsyslog SIEM bridge is preserved for manual recovery"
            else
                record fail "${PREFIX}.${label}.generated.rsyslog_siem_residual" "ambiguous rsyslog SIEM bridge changed during removal"
            fi
            if [ -f /etc/rsyslog.d/99-syswarden-waf-bridge.conf ] && [ ! -L /etc/rsyslog.d/99-syswarden-waf-bridge.conf ] && \
               [ "$(hash_file /etc/rsyslog.d/99-syswarden-waf-bridge.conf 2>/dev/null || true)" = "$(cat /tmp/syswarden-rsyslog-waf-before)" ]; then
                record pass "${PREFIX}.${label}.generated.rsyslog_waf_bridge_residual" "ambiguous rsyslog WAF bridge is preserved for manual recovery"
            else
                record fail "${PREFIX}.${label}.generated.rsyslog_waf_bridge_residual" "ambiguous rsyslog WAF bridge changed during removal"
            fi
            rsyslog_provenance=/etc/rsyslog.d/.syswarden-rsyslog-provenance-v1
            if [ -f "${rsyslog_provenance}" ] && \
               [ ! -L "${rsyslog_provenance}" ] && \
               [ "$(stat -c '%u:%g:%a:%h' \
                   "${rsyslog_provenance}" 2>/dev/null || true)" = \
                   0:0:600:1 ] && \
               [ "$(hash_file "${rsyslog_provenance}" 2>/dev/null || true)" = \
                   "$(cat /tmp/syswarden-rsyslog-provenance-before)" ]; then
                record pass \
                    "${PREFIX}.${label}.generated.rsyslog_provenance_residual" \
                    "ambiguous rsyslog provenance is preserved byte-exact for manual recovery"
            else
                record fail \
                    "${PREFIX}.${label}.generated.rsyslog_provenance_residual" \
                    "ambiguous rsyslog provenance changed during removal"
            fi
            ;;
        *) return 1 ;;
    esac
    check_absent "${label}.generated.cron_d_owned" /etc/cron.d/syswarden
    check_absent "${label}.generated.cron_d_pending" /etc/cron.d/.syswarden.pending-v1
    if ! LC_ALL=C crontab -l > /tmp/syswarden-root-cron-after 2>/tmp/syswarden-remove-cron.error; then
        record fail "${PREFIX}.${label}.generated.root_crontab_bytes" "root crontab could not be read after removal"
        record fail "${PREFIX}.${label}.generated.root_crontab_legacy_residual" "legacy residual could not be verified"
        return
    fi
    cron_state="$(cat /tmp/syswarden-root-cron-after)"
    if cmp -s /tmp/syswarden-root-cron-before /tmp/syswarden-root-cron-after; then
        record pass "${PREFIX}.${label}.generated.root_crontab_bytes" "operator-controlled root crontab bytes are preserved exactly"
    else
        record fail "${PREFIX}.${label}.generated.root_crontab_bytes" "operator-controlled root crontab bytes changed"
    fi
    legacy_count="$(printf '%s\n' "${cron_state}" | grep -F -x -c \
        '17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1' || true)"
    if [ "${legacy_count}" -eq 1 ] && [ ! -e /opt/syswarden/bin/syswarden-cli ] && [ ! -L /opt/syswarden/bin/syswarden-cli ]; then
        record pass "${PREFIX}.${label}.generated.root_crontab_legacy_residual" "one exact inert legacy record remains as a bounded residual"
    else
        record fail "${PREFIX}.${label}.generated.root_crontab_legacy_residual" "bounded inert legacy residual contract is not satisfied"
    fi
}

prepare_expected_payloads() {
    if ! run_step extract.previous extract_package "${PREVIOUS_PACKAGE}" "${PERSIST_ROOT}/expected-previous"; then
        return 1
    fi
    if ! run_step extract.candidate extract_package "${CANDIDATE_PACKAGE}" "${PERSIST_ROOT}/expected-candidate"; then
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
    if package_uses_geoip_data_license_payload candidate; then
        if ! CANDIDATE_LICENSE="$(
            package_license "${CANDIDATE_PACKAGE}" 2>> "${COMMAND_LOG}"
        )"; then
            record fail "${PREFIX}.metadata.candidate.license" \
                "native package license metadata could not be read exactly"
            return 1
        fi
        check_equal metadata.candidate.license GPL-3.0-or-later "${CANDIDATE_LICENSE}"
        [ "${CANDIDATE_LICENSE}" = GPL-3.0-or-later ] || return 1
    else
        license_contract_rc=$?
        [ "${license_contract_rc}" -eq 1 ] || return 1
    fi
    verify_package_artifact previous "${PREVIOUS_PACKAGE}" "${PERSIST_ROOT}/expected-previous"
    verify_package_artifact candidate "${CANDIDATE_PACKAGE}" "${PERSIST_ROOT}/expected-candidate"
    return 0
}

probe_execution_architecture() {
    actual="$(uname -m 2>/dev/null || true)"
    check_equal platform.uname "${EXPECTED_UNAME_ARCHITECTURE}" "${actual}"
    [ "${actual}" = "${EXPECTED_UNAME_ARCHITECTURE}" ]
}

scenario_upgrade_rollback_initial() {
    prepare_expected_payloads || return
    seed_and_attest_preinstall_networkless_config || return
    prepare_package_transition || return
    prepare_alma_v4028_rpm_rsyslog_fixture \
        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return
    run_install_step install.previous "${PREVIOUS_PACKAGE}" || return
    attest_preinstall_networkless_config_after_previous || return
    attest_alma_v4028_rpm_rsyslog_after_previous \
        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return
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

    prepare_package_transition || return
    run_install_step upgrade.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload candidate candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved candidate

    prepare_package_transition || return
    run_install_step reinstall.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload reinstall candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved reinstall

    printf '%s\n' restart-one > "${RESTART_STATE_FILE}"
}

scenario_upgrade_rollback_restart_one() {
    load_state_contract || return
    prepare_service_runtime_fixture || return
    probe_payload restart-one candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved restart-one
    printf '%s\n' restart-two > "${RESTART_STATE_FILE}"
}

scenario_upgrade_rollback_restart_two() {
    load_state_contract || return
    prepare_service_runtime_fixture || return
    probe_payload restart-two candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved restart-two
    prepare_package_transition || return
    attest_alma_v4028_rpm_rsyslog_fixture \
        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return
    run_install_step rollback.previous "${PREVIOUS_PACKAGE}" || return
    attest_alma_v4028_rpm_rsyslog_after_previous \
        /proc /etc/systemd/system 0:0 /usr/sbin/rsyslogd || return
    if [ "${FORWARD_ONLY_APK_TRANSITION}" = "1" ]; then
        probe_forward_only_apk_payload rollback
    else
        probe_payload rollback previous "${EXPECTED_PREVIOUS_VERSION}"
    fi
    assert_all_state_preserved rollback
    prepare_package_transition || return
    run_install_step recovery.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload recovery candidate "${EXPECTED_CANDIDATE_VERSION}"
    assert_all_state_preserved recovery
    printf '%s\n' complete > "${RESTART_STATE_FILE}"
}

scenario_remove() {
    prepare_expected_payloads || return
    seed_state
    if [ "${PACKAGE_FAMILY}" = deb ]; then
        seed_deb_removal_log || return
    fi
    prepare_package_transition || return
    run_install_step install.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload fresh candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved fresh
    case "${PACKAGE_FAMILY}" in
        deb)
            prepare_package_transition || return
            seed_generated_runtime_artifacts exact-rsyslog remove || return
            run_step remove remove_package || return
            assert_package_absent remove candidate
            assert_generated_runtime_artifact_contract remove exact-rsyslog
            assert_all_state_preserved remove
            assert_deb_removal_log_preserved remove
            assert_deferred_purge_marker remove

            prepare_package_transition || return
            run_install_step reinstall-after-remove.candidate \
                "${CANDIDATE_PACKAGE}" || return
            probe_payload reinstall-after-remove candidate "${CANDIDATE_VERSION}" 0
            assert_all_state_preserved reinstall-after-remove
            assert_deb_removal_log_preserved reinstall-after-remove
            check_absent \
                reinstall-after-remove.state.deferred_purge_marker \
                /var/lib/syswarden/removed-awaiting-purge-v1

            prepare_package_transition || return
            seed_generated_runtime_artifacts \
                exact-rsyslog remove-before-purge || return
            run_step remove-before-purge remove_package || return
            assert_package_absent remove-before-purge candidate
            assert_generated_runtime_artifact_contract \
                remove-before-purge exact-rsyslog
            assert_all_state_preserved remove-before-purge
            assert_deb_removal_log_preserved remove-before-purge
            assert_deferred_purge_marker remove-before-purge

            run_step purge-after-remove purge_package || return
            assert_package_absent purge-after-remove candidate
            assert_dedicated_roots_absent purge-after-remove
            ;;
        apk)
            seed_generated_runtime_artifacts || return
            run_step remove remove_package || return
            assert_package_absent remove candidate
            assert_generated_runtime_artifact_contract remove
            assert_dedicated_roots_absent remove
            ;;
        rpm)
            seed_generated_runtime_artifacts || return
            run_step final-removal remove_package || return
            assert_package_absent final-removal candidate
            assert_generated_runtime_artifact_contract final-removal
            assert_dedicated_roots_absent final-removal
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
    if [ "${PACKAGE_FAMILY}" = deb ]; then
        seed_deb_removal_log || return
    fi
    prepare_package_transition || return
    run_install_step install.candidate "${CANDIDATE_PACKAGE}" || return
    probe_payload fresh candidate "${CANDIDATE_VERSION}"
    assert_all_state_preserved fresh
    seed_generated_runtime_artifacts || return
    run_step purge purge_package || return
    assert_package_absent purge candidate
    assert_generated_runtime_artifact_contract purge
    case "${PACKAGE_FAMILY}" in
        deb)
            assert_dedicated_roots_absent purge
            ;;
        apk)
            assert_dedicated_roots_absent purge
            ;;
    esac
}

if [ "${INVOCATION}" = "initial" ]; then
    if ! probe_execution_architecture; then
        exit 1
    fi
fi

scenario_rc=0
case "${SCENARIO}" in
    upgrade-rollback)
        case "${INVOCATION}" in
            initial) scenario_upgrade_rollback_initial || scenario_rc=$? ;;
            restart-one) scenario_upgrade_rollback_restart_one || scenario_rc=$? ;;
            restart-two) scenario_upgrade_rollback_restart_two || scenario_rc=$? ;;
            *) scenario_rc=1 ;;
        esac
        ;;
    remove)
        scenario_remove || scenario_rc=$?
        ;;
    purge)
        scenario_purge || scenario_rc=$?
        ;;
    *)
        record fail "scenario" "unsupported scenario ${SCENARIO}"
        scenario_rc=1
        ;;
esac

if [ "${scenario_rc}" -ne 0 ]; then
    if [ "${FAILURES}" -eq 0 ]; then
        record fail "scenario.execution" "scenario returned exit code ${scenario_rc}"
    fi
    exit "${scenario_rc}"
fi
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
    events: Sequence[dict[str, str]],
    family: str,
    scenario: str,
    *,
    candidate_version: str | None = None,
) -> None:
    """Reject missing, duplicated, reordered, synthetic, or informational evidence."""

    expected = expected_event_checks(
        family,
        scenario,
        candidate_version=candidate_version,
    )
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


def _inventory_role_for_phase(label: str) -> str:
    if label in {"previous", "rollback"}:
        return "previous"
    if label in {
        "candidate",
        "reinstall",
        "restart-one",
        "restart-two",
        "recovery",
        "fresh",
    }:
        return "candidate"
    raise LifecycleLabError(f"unsupported inventory phase: {label!r}")


def _uses_legacy_completion_payload(
    family: str,
    role: str,
    version: str,
    candidate_version: str,
    *,
    forward_only_apk: bool = False,
) -> bool:
    if role not in {"previous", "candidate"}:
        raise LifecycleLabError(f"unsupported package artifact role: {role!r}")
    parse_syswarden_version(version)
    parse_syswarden_version(candidate_version)
    if forward_only_apk:
        if (
            family != "apk"
            or candidate_version != FORWARD_ONLY_APK_CANDIDATE_VERSION
        ):
            raise LifecycleLabError(
                "forward-only APK completion contract is not byte-bound"
            )
        expected_version = (
            FORWARD_ONLY_APK_PREVIOUS_VERSION
            if role == "previous"
            else FORWARD_ONLY_APK_CANDIDATE_VERSION
        )
        if version != expected_version:
            raise LifecycleLabError(
                "forward-only APK completion role/version is inconsistent"
            )
        return True
    if role != "previous":
        return False
    if version == LEGACY_BASH_COMPLETION_VERSION:
        return True
    return False


def _uses_geoip_data_license_payload(
    role: str,
    version: str,
) -> bool:
    if role not in {"previous", "candidate"}:
        raise LifecycleLabError(f"unsupported package artifact role: {role!r}")
    return parse_syswarden_version(version) >= parse_syswarden_version(
        GEOIP_DATA_LICENSE_FIRST_VERSION
    )


def _validate_manager_paths(
    family: str,
    paths: list[str],
    *,
    role: str,
    version: str,
    candidate_version: str,
    forward_only_apk: bool = False,
) -> None:
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
    legacy_completion = _uses_legacy_completion_payload(
        family,
        role,
        version,
        candidate_version,
        forward_only_apk=forward_only_apk,
    )
    license_payloads = _uses_geoip_data_license_payload(role, version)
    expected_payload_paths = set(
        LEGACY_PACKAGE_PAYLOAD_PATHS
        if legacy_completion
        else (
            LICENSED_PACKAGE_PAYLOAD_PATHS
            if license_payloads
            else PACKAGE_PAYLOAD_PATHS
        )
    )
    if family == "deb":
        expected = (
            LEGACY_DEB_PACKAGE_PATHS
            if legacy_completion
            else (
                LICENSED_DEB_PACKAGE_PATHS
                if license_payloads
                else DEB_PACKAGE_PATHS
            )
        )
        if observed != expected:
            raise LifecycleLabError("DEB native package inventory is not exact")
        return
    if family == "apk":
        expected = (
            LEGACY_APK_PACKAGE_PATHS
            if legacy_completion
            else (
                LICENSED_APK_PACKAGE_PATHS
                if license_payloads
                else APK_PACKAGE_PATHS
            )
        )
        if observed != expected:
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
        expected_payload_paths
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
    *,
    role: str,
    version: str,
    candidate_version: str,
    forward_only_apk: bool = False,
) -> None:
    """Validate the full native path list and every filesystem metadata entry."""

    _validate_manager_paths(
        family,
        manager_paths,
        role=role,
        version=version,
        candidate_version=candidate_version,
        forward_only_apk=forward_only_apk,
    )
    legacy_completion = _uses_legacy_completion_payload(
        family,
        role,
        version,
        candidate_version,
        forward_only_apk=forward_only_apk,
    )
    license_payloads = _uses_geoip_data_license_payload(role, version)
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
    if not legacy_completion:
        file_modes[BASH_COMPLETION_PATH] = "644"
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
    if license_payloads:
        attribution = entries[GEOIP_DATA_LICENSE_PATH]
        if (
            attribution["type"] != "file"
            or attribution["mode"] != "644"
            or attribution["value"] != GEOIP_DATA_LICENSE_SHA256
        ):
            raise LifecycleLabError(
                "GeoIP data license payload is not the pinned intact source"
            )
        project_license = entries[PROJECT_LICENSE_PATH]
        if (
            project_license["type"] != "file"
            or project_license["mode"] != "644"
            or project_license["value"] != PROJECT_LICENSE_SHA256
        ):
            raise LifecycleLabError(
                "project license payload is not the pinned intact source"
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
        expected_paths = (
            LEGACY_DEB_PACKAGE_PATHS
            if legacy_completion
            else (
                LICENSED_DEB_PACKAGE_PATHS
                if license_payloads
                else DEB_PACKAGE_PATHS
            )
        )
        expected_payload_paths = set(
            LEGACY_PACKAGE_PAYLOAD_PATHS
            if legacy_completion
            else (
                LICENSED_PACKAGE_PAYLOAD_PATHS
                if license_payloads
                else PACKAGE_PAYLOAD_PATHS
            )
        )
        for path in expected_paths - expected_payload_paths - {
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
    result_root: Path,
    family: str,
    scenario: str,
    *,
    previous_version: str,
    candidate_version: str,
) -> dict[str, object]:
    forward_only_apk = (
        family == "apk"
        and previous_version == FORWARD_ONLY_APK_PREVIOUS_VERSION
        and candidate_version == FORWARD_ONLY_APK_CANDIDATE_VERSION
    )
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
        role = _inventory_role_for_phase(label)
        role_version = (
            previous_version if role == "previous" else candidate_version
        )
        validate_inventory_snapshot(
            family,
            manager_paths,
            filesystem,
            role=role,
            version=role_version,
            candidate_version=candidate_version,
            forward_only_apk=forward_only_apk,
        )
        evidence[label] = {
            "manager_paths": manager_paths,
            "filesystem": filesystem,
        }
    return evidence


def validate_scenario_inventory_evidence(
    evidence: object,
    family: str,
    scenario: str,
    *,
    previous_version: str,
    candidate_version: str,
) -> None:
    forward_only_apk = (
        family == "apk"
        and previous_version == FORWARD_ONLY_APK_PREVIOUS_VERSION
        and candidate_version == FORWARD_ONLY_APK_CANDIDATE_VERSION
    )
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
        role = _inventory_role_for_phase(label)
        role_version = (
            previous_version if role == "previous" else candidate_version
        )
        validate_inventory_snapshot(
            family,
            manager_paths,
            filesystem,
            role=role,
            version=role_version,
            candidate_version=candidate_version,
            forward_only_apk=forward_only_apk,
        )


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


def inspect_rootless_podman_cgroups(
    runner: CommandRunner, podman: str, expected_host_architecture: str
) -> dict[str, object]:
    inspected = runner.run(
        (podman, "info", "--format", "json"),
        timeout=30,
    )
    require_success(inspected, "Podman cgroup probe")
    try:
        document = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise LifecycleLabError("Podman cgroup probe is not valid JSON") from exc
    host = document.get("host") if isinstance(document, dict) else None
    if not isinstance(host, dict):
        raise LifecycleLabError("Podman cgroup probe omits host evidence")
    security = host.get("security")
    controllers = host.get("cgroupControllers")
    host_architecture = normalize_host_architecture(str(host.get("arch", "")))
    expected_architecture = normalize_host_architecture(expected_host_architecture)
    if (
        not isinstance(security, dict)
        or security.get("rootless") is not True
        or host.get("cgroupVersion") != "v2"
        or host.get("cgroupManager") != "systemd"
        or not isinstance(controllers, list)
        or any(not isinstance(item, str) for item in controllers)
        or len(set(controllers)) != len(controllers)
        or not {"cpu", "io", "memory", "pids"}.issubset(controllers)
        or host.get("serviceIsRemote") is not False
        or host.get("os") != "linux"
        or host_architecture is None
        or expected_architecture is None
        or host_architecture != expected_architecture
    ):
        raise LifecycleLabError(
            "package lifecycle lab requires native rootless Podman with systemd "
            "cgroup v2 delegation and the cpu/io/memory/pids controllers"
        )
    effective_uid = os.geteuid()
    effective_gid = os.getegid()
    id_mappings = host.get("idMappings")
    if (
        effective_uid <= 0
        or effective_gid <= 0
        or not isinstance(id_mappings, dict)
        or set(id_mappings) != {"uidmap", "gidmap"}
    ):
        raise LifecycleLabError(
            "Podman rootless identity mapping evidence is incomplete"
        )

    def parse_engine_map(
        raw: object, label: str, effective_id: int
    ) -> list[dict[str, int]]:
        if not isinstance(raw, list):
            raise LifecycleLabError(f"Podman {label} is not an array")
        rendered: list[str] = []
        for record in raw:
            if (
                not isinstance(record, dict)
                or set(record) != {"container_id", "host_id", "size"}
                or any(
                    type(record.get(key)) is not int
                    for key in ("container_id", "host_id", "size")
                )
            ):
                raise LifecycleLabError(f"Podman {label} schema is not exact")
            rendered.append(
                f"{record['container_id']}:{record['host_id']}:{record['size']}"
            )
        parsed = _parse_id_map(",".join(rendered), f"Podman {label}")
        if parsed[0].outside_id != effective_id:
            raise LifecycleLabError(
                f"Podman {label} does not bind container root to the effective ID"
            )
        return [asdict(item) for item in parsed]

    uid_map = parse_engine_map(
        id_mappings.get("uidmap"), "uid_map", effective_uid
    )
    gid_map = parse_engine_map(
        id_mappings.get("gidmap"), "gid_map", effective_gid
    )
    return {
        "cgroups_version": "v2",
        "cgroup_manager": "systemd",
        "cgroup_delegation": "rootless-systemd-v2",
        "cgroup_controllers": sorted(controllers),
        "host_architecture": host_architecture,
        "service_is_remote": False,
        "effective_uid": effective_uid,
        "effective_gid": effective_gid,
        "uid_map": uid_map,
        "gid_map": gid_map,
    }


def _regular_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable_regular_file(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise LifecycleLabError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LifecycleLabError(f"{label} must be a regular non-symlink file")
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
        raise LifecycleLabError(f"cannot read {label}: {exc}") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or _regular_file_identity(before) != _regular_file_identity(opened)
        or _regular_file_identity(opened) != _regular_file_identity(after)
    ):
        raise LifecycleLabError(f"{label} changed while it was being read")
    data = b"".join(chunks)
    if len(data) != after.st_size:
        raise LifecycleLabError(f"{label} byte count differs from its metadata")
    return data, after


def snapshot_lifecycle_helper(workspace: Path) -> tuple[Path, dict[str, object]]:
    source = Path(__file__).resolve().with_name("package_webtui_retirement.sh")
    data, source_metadata = _read_stable_regular_file(
        source, "package lifecycle helper source"
    )
    digest = hashlib.sha256(data).hexdigest()
    snapshot = workspace / "package-webtui-retirement.sh"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(snapshot, flags, 0o600)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(descriptor, data[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise LifecycleLabError(f"cannot freeze package lifecycle helper: {exc}") from exc
    frozen_data, frozen_metadata = _read_stable_regular_file(
        snapshot, "frozen package lifecycle helper"
    )
    if (
        frozen_data != data
        or stat.S_IMODE(frozen_metadata.st_mode) != 0o600
        or hashlib.sha256(frozen_data).hexdigest() != digest
    ):
        raise LifecycleLabError("frozen package lifecycle helper differs from source")
    return snapshot, {
        "source": str(source),
        "sha256": digest,
        "size_bytes": len(data),
        "source_regular_file": True,
        "source_symlink": False,
        "snapshot_mode": "0600",
        "snapshot_regular_file": True,
        "snapshot_symlink": False,
        "source_identity": list(_regular_file_identity(source_metadata)),
        "snapshot_identity": list(_regular_file_identity(frozen_metadata)),
    }


def revalidate_lifecycle_helper(
    snapshot: Path, expected: dict[str, object]
) -> dict[str, object]:
    source = Path(str(expected.get("source", "")))
    source_data, source_metadata = _read_stable_regular_file(
        source, "package lifecycle helper source"
    )
    frozen_data, frozen_metadata = _read_stable_regular_file(
        snapshot, "frozen package lifecycle helper"
    )
    digest = str(expected.get("sha256", ""))
    if (
        hashlib.sha256(source_data).hexdigest() != digest
        or hashlib.sha256(frozen_data).hexdigest() != digest
        or source_data != frozen_data
        or len(source_data) != expected.get("size_bytes")
        or list(_regular_file_identity(source_metadata))
        != expected.get("source_identity")
        or list(_regular_file_identity(frozen_metadata))
        != expected.get("snapshot_identity")
        or stat.S_IMODE(frozen_metadata.st_mode) != 0o600
    ):
        raise LifecycleLabError(
            "package lifecycle helper changed while evidence was collected"
        )
    return {
        "source": str(source),
        "sha256": digest,
        "size_bytes": len(source_data),
        "source_regular_file": True,
        "source_symlink": False,
        "snapshot_mode": "0600",
        "snapshot_regular_file": True,
        "snapshot_symlink": False,
        "frozen_copy": True,
        "revalidated_before_report": True,
    }


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


def distribution_version_matches(
    distribution: str,
    expected_version: str,
    actual_version: str,
) -> bool:
    """Match an os-release VERSION_ID against the frozen distribution line.

    Debian, Ubuntu, and Fedora matrix cells identify an exact VERSION_ID.
    AlmaLinux tags identify a major release line, while Alpine tags identify a
    major.minor release line.  Both line-based forms still reject malformed
    values and adjacent lines; the immutable image digest remains exact.
    """

    if (
        OS_RELEASE_VERSION_PATTERN.fullmatch(expected_version) is None
        or OS_RELEASE_VERSION_PATTERN.fullmatch(actual_version) is None
    ):
        return False
    expected_components = expected_version.split(".")
    actual_components = actual_version.split(".")
    if distribution in EXACT_OS_RELEASE_VERSION_DISTRIBUTIONS:
        return actual_version == expected_version
    if distribution == "almalinux":
        return (
            len(expected_components) == 1
            and actual_components[0] == expected_components[0]
        )
    if distribution == "alpine":
        return (
            len(expected_components) == 2
            and len(actual_components) >= 2
            and actual_components[:2] == expected_components
        )
    return False


def architecture_probe_arguments(
    podman: str,
    spec: PlatformSpec,
) -> tuple[str, ...]:
    """Build a networkless, read-only native AMD64 execution probe."""

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
        "--env",
        f"EXPECTED_DISTRIBUTION={spec.distribution}",
        "--env",
        f"EXPECTED_DISTRIBUTION_VERSION={spec.version}",
    ]
    probe = (
        "set -eu\n"
        ". /etc/os-release\n"
        "actual_uname=\"$(uname -m)\"\n"
        "actual_distribution=\"${ID-}\"\n"
        "actual_version=\"${VERSION_ID-}\"\n"
        "printf '%s\\t%s\\t%s\\n' \"${actual_uname}\" "
        "\"${actual_distribution}\" \"${actual_version}\"\n"
        "[ \"${actual_distribution}\" = \"${EXPECTED_DISTRIBUTION}\" ]\n"
        "case \"${actual_version}\" in "
        "''|*[!0-9.]*|.*|*..*|*.) exit 1 ;; esac\n"
        "[ -n \"${actual_version}\" ]\n"
        "case \"${EXPECTED_DISTRIBUTION}\" in\n"
        "  debian|ubuntu|fedora) "
        "[ \"${actual_version}\" = \"${EXPECTED_DISTRIBUTION_VERSION}\" ] ;;\n"
        "  almalinux) "
        "[ \"${actual_version%%.*}\" = \"${EXPECTED_DISTRIBUTION_VERSION}\" ] ;;\n"
        "  alpine)\n"
        "    actual_tail=\"${actual_version#*.}\"\n"
        "    actual_major_minor=\"${actual_version%%.*}.${actual_tail%%.*}\"\n"
        "    [ \"${actual_major_minor}\" = \"${EXPECTED_DISTRIBUTION_VERSION}\" ] ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
    )
    arguments.extend((spec.image, "/bin/sh", "-ceu", probe))
    return tuple(arguments)


def normalize_host_architecture(value: str) -> str | None:
    normalized = value.strip().casefold()
    if normalized in {"amd64", "x86_64"}:
        return "amd64"
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
) -> dict[str, object]:
    """Prove that the requested AMD64 architecture executes natively."""

    normalized_host = normalize_host_architecture(host_architecture)
    if normalized_host != "amd64":
        return {
            "status": "unavailable",
            "execution_mode": "native_amd64_required",
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "reason": "package lifecycle qualification requires a native AMD64 host",
        }
    args = architecture_probe_arguments(podman, spec)
    try:
        result = runner.run(args, timeout=60)
    except LifecycleLabError as exc:
        return {
            "status": "unavailable",
            "execution_mode": "native",
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "reason": str(exc),
        }
    fields = result.stdout.rstrip("\n").split("\t")
    actual_uname = fields[0] if len(fields) == 3 else ""
    actual_distribution = fields[1] if len(fields) == 3 else ""
    actual_distribution_version = fields[2] if len(fields) == 3 else ""
    if (
        result.returncode != 0
        or len(fields) != 3
        or actual_uname != spec.uname_architecture
        or actual_distribution != spec.distribution
        or not distribution_version_matches(
            spec.distribution,
            spec.version,
            actual_distribution_version,
        )
    ):
        return {
            "status": "unavailable",
            "execution_mode": "native",
            "podman_platform": spec.podman_platform,
            "expected_uname": spec.uname_architecture,
            "actual_uname": actual_uname,
            "expected_distribution": spec.distribution,
            "actual_distribution": actual_distribution,
            "expected_distribution_version": spec.version,
            "actual_distribution_version": actual_distribution_version,
            "container_exit_code": result.returncode,
            "reason": (
                "the pinned image did not prove the requested native architecture "
                "and closed /etc/os-release ID and VERSION_ID identity"
            ),
            "log_tail": command_log_tail(result),
        }
    return {
        "status": "available",
        "execution_mode": "native",
        "podman_platform": spec.podman_platform,
        "expected_uname": spec.uname_architecture,
        "actual_uname": actual_uname,
        "expected_distribution": spec.distribution,
        "actual_distribution": actual_distribution,
        "expected_distribution_version": spec.version,
        "actual_distribution_version": actual_distribution_version,
        "container_exit_code": result.returncode,
        "network": "disabled",
        "filesystem": "read-only with bounded /tmp tmpfs",
    }


def validate_available_architecture_probe(
    value: object, spec: PlatformSpec
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != AVAILABLE_ARCHITECTURE_PROBE_KEYS
        or value.get("status") != "available"
        or value.get("execution_mode") != "native"
        or value.get("podman_platform") != spec.podman_platform
        or value.get("expected_uname") != spec.uname_architecture
        or value.get("actual_uname") != spec.uname_architecture
        or value.get("expected_distribution") != spec.distribution
        or value.get("actual_distribution") != spec.distribution
        or value.get("expected_distribution_version") != spec.version
        or not isinstance(value.get("actual_distribution_version"), str)
        or not distribution_version_matches(
            spec.distribution,
            spec.version,
            value["actual_distribution_version"],
        )
        or type(value.get("container_exit_code")) is not int
        or value.get("container_exit_code") != 0
        or value.get("network") != "disabled"
        or value.get("filesystem") != "read-only with bounded /tmp tmpfs"
    ):
        raise LifecycleLabError(
            f"architecture and distribution-version evidence is invalid for "
            f"{platform_coordinate(spec)}"
        )
    return value


def _capability_has_bit(value: str, bit: int) -> bool:
    if re.fullmatch(r"[0-9a-f]{16}", value) is None:
        raise LifecycleLabError("process capability mask is not canonical")
    return bool(int(value, 16) & (1 << bit))


def _validate_process_security(
    value: ProcessSecurityEvidence,
    *,
    sys_admin_present: frozenset[str],
    sys_ptrace_present: frozenset[str],
    label: str,
) -> ProcessSecurityEvidence:
    capabilities = {
        "inheritable": value.cap_inheritable,
        "permitted": value.cap_permitted,
        "effective": value.cap_effective,
        "bounding": value.cap_bounding,
        "ambient": value.cap_ambient,
    }
    if value.no_new_privileges is not True:
        raise LifecycleLabError(f"{label} does not prove NoNewPrivs=1")
    for capability_name, bit, expected_fields in (
        ("SYS_ADMIN", SYS_ADMIN_CAPABILITY_BIT, sys_admin_present),
        ("SYS_PTRACE", SYS_PTRACE_CAPABILITY_BIT, sys_ptrace_present),
    ):
        for name, encoded in capabilities.items():
            observed = _capability_has_bit(encoded, bit)
            if observed is not (name in expected_fields):
                raise LifecycleLabError(
                    f"{label} {capability_name} {name} capability state is not exact"
                )
    return value


def _process_security_from_fields(
    fields: Sequence[str],
    *,
    sys_admin_present: frozenset[str],
    sys_ptrace_present: frozenset[str],
    label: str,
) -> ProcessSecurityEvidence:
    if len(fields) != 6 or fields[5] not in {"0", "1"}:
        raise LifecycleLabError(f"{label} process security field count is not exact")
    evidence = ProcessSecurityEvidence(
        cap_inheritable=fields[0],
        cap_permitted=fields[1],
        cap_effective=fields[2],
        cap_bounding=fields[3],
        cap_ambient=fields[4],
        no_new_privileges=fields[5] == "1",
    )
    return _validate_process_security(
        evidence,
        sys_admin_present=sys_admin_present,
        sys_ptrace_present=sys_ptrace_present,
        label=label,
    )


def _parse_id_map(value: str, label: str) -> tuple[IDMapRange, ...]:
    records: list[IDMapRange] = []
    for raw in value.split(","):
        match = re.fullmatch(
            r"(0|[1-9][0-9]*):(0|[1-9][0-9]*):(0|[1-9][0-9]*)", raw
        )
        if match is None:
            raise LifecycleLabError(f"{label} is not canonical")
        inside, outside, length = (int(item) for item in match.groups())
        if length <= 0 or max(inside, outside, length) > 4_294_967_295:
            raise LifecycleLabError(f"{label} contains an invalid range")
        if inside + length > 4_294_967_296 or outside + length > 4_294_967_296:
            raise LifecycleLabError(f"{label} range overflows the ID space")
        records.append(IDMapRange(inside, outside, length))
    if len(records) != 2:
        raise LifecycleLabError(f"{label} must contain the exact rootless map shape")
    first, subordinate = records
    first_outside_end = first.outside_id + first.length
    subordinate_outside_end = subordinate.outside_id + subordinate.length
    if (
        first.inside_id != 0
        or first.outside_id == 0
        or first.length != 1
        or subordinate.inside_id != 1
        or subordinate.outside_id == 0
        or subordinate.length != 65_536
        or first.outside_id == subordinate.outside_id
        or max(first.outside_id, subordinate.outside_id)
        < min(first_outside_end, subordinate_outside_end)
    ):
        raise LifecycleLabError(f"{label} does not exclude host root exactly")
    return tuple(records)


def _exec_security_guard_script(spec: PlatformSpec) -> str:
    expect_sys_ptrace = "1" if spec.family != "apk" else "0"
    return f"""syswarden_read_status_value() {{
    syswarden_status_pid="$1"
    syswarden_status_key="$2"
    awk -v wanted="${{syswarden_status_key}}:" '
        $1 == wanted {{
            if (found || NF != 2) exit 1
            value = $2
            found = 1
        }}
        END {{
            if (!found) exit 1
            print value
        }}
    ' "/proc/${{syswarden_status_pid}}/status"
}}
syswarden_capability_has_sys_admin() {{
    syswarden_capability_value="$1"
    printf '%s\\n' "${{syswarden_capability_value}}" | LC_ALL=C grep -Eq '^[0-9a-f]{{16}}$' || return 2
    [ $((0x${{syswarden_capability_value}} & 0x00200000)) -ne 0 ]
}}
syswarden_capability_has_sys_ptrace() {{
    syswarden_capability_value="$1"
    printf '%s\\n' "${{syswarden_capability_value}}" | LC_ALL=C grep -Eq '^[0-9a-f]{{16}}$' || return 2
    [ $((0x${{syswarden_capability_value}} & 0x00080000)) -ne 0 ]
}}
syswarden_exec_cap_inh="$(syswarden_read_status_value "$$" CapInh)" || exit 90
syswarden_exec_cap_prm="$(syswarden_read_status_value "$$" CapPrm)" || exit 90
syswarden_exec_cap_eff="$(syswarden_read_status_value "$$" CapEff)" || exit 90
syswarden_exec_cap_bnd="$(syswarden_read_status_value "$$" CapBnd)" || exit 90
syswarden_exec_cap_amb="$(syswarden_read_status_value "$$" CapAmb)" || exit 90
syswarden_exec_nnp="$(syswarden_read_status_value "$$" NoNewPrivs)" || exit 90
for syswarden_capability_value in \\
    "${{syswarden_exec_cap_inh}}" \\
    "${{syswarden_exec_cap_prm}}" \\
    "${{syswarden_exec_cap_eff}}" \\
    "${{syswarden_exec_cap_bnd}}" \\
    "${{syswarden_exec_cap_amb}}"; do
    if syswarden_capability_has_sys_admin "${{syswarden_capability_value}}"; then
        exit 90
    else
        syswarden_capability_status=$?
        [ "${{syswarden_capability_status}}" -eq 1 ] || exit 90
    fi
done
syswarden_expect_sys_ptrace={expect_sys_ptrace}
if [ "${{syswarden_expect_sys_ptrace}}" = 1 ]; then
    for syswarden_capability_value in \
        "${{syswarden_exec_cap_prm}}" \
        "${{syswarden_exec_cap_eff}}" \
        "${{syswarden_exec_cap_bnd}}"; do
        syswarden_capability_has_sys_ptrace "${{syswarden_capability_value}}" || exit 90
    done
    for syswarden_capability_value in \
        "${{syswarden_exec_cap_inh}}" \
        "${{syswarden_exec_cap_amb}}"; do
        if syswarden_capability_has_sys_ptrace "${{syswarden_capability_value}}"; then
            exit 90
        else
            syswarden_capability_status=$?
            [ "${{syswarden_capability_status}}" -eq 1 ] || exit 90
        fi
    done
else
    for syswarden_capability_value in \
        "${{syswarden_exec_cap_inh}}" \
        "${{syswarden_exec_cap_prm}}" \
        "${{syswarden_exec_cap_eff}}" \
        "${{syswarden_exec_cap_bnd}}" \
        "${{syswarden_exec_cap_amb}}"; do
        if syswarden_capability_has_sys_ptrace "${{syswarden_capability_value}}"; then
            exit 90
        else
            syswarden_capability_status=$?
            [ "${{syswarden_capability_status}}" -eq 1 ] || exit 90
        fi
    done
fi
[ "${{syswarden_exec_nnp}}" = 1 ] || exit 90
printf '{EXEC_SECURITY_MARKER}\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \\
    "${{syswarden_exec_cap_inh}}" "${{syswarden_exec_cap_prm}}" \\
    "${{syswarden_exec_cap_eff}}" "${{syswarden_exec_cap_bnd}}" \\
    "${{syswarden_exec_cap_amb}}" "${{syswarden_exec_nnp}}"
"""


def lifecycle_exec_arguments(
    podman: str,
    name: str,
    spec: PlatformSpec,
    script: str,
) -> tuple[str, ...]:
    arguments = [podman, "exec", name]
    if spec.family == "apk":
        arguments.extend(("/bin/sh", "-ceu"))
    else:
        arguments.extend(SYSTEMD_EXEC_LAUNCHER)
    arguments.append(_exec_security_guard_script(spec) + script)
    return tuple(arguments)


def parse_exec_security_output(
    output: str, label: str, spec: PlatformSpec
) -> tuple[ProcessSecurityEvidence, str]:
    first_line, separator, remainder = output.partition("\n")
    if not separator:
        raise LifecycleLabError(f"{label} omitted the exec security marker")
    marker_fields = first_line.split("\t")
    if (
        len(marker_fields) != 7
        or marker_fields[0] != EXEC_SECURITY_MARKER
        or any(
            line == EXEC_SECURITY_MARKER
            or line.startswith(EXEC_SECURITY_MARKER + "\t")
            for line in remainder.splitlines()
        )
    ):
        raise LifecycleLabError(f"{label} exec security marker is not unique and exact")
    security = _process_security_from_fields(
        marker_fields[1:],
        sys_admin_present=frozenset(),
        sys_ptrace_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if spec.family != "apk"
            else frozenset()
        ),
        label=label,
    )
    return security, remainder


def container_run_arguments(
    podman: str,
    image: str,
    name: str,
    candidate_root: Path,
    previous_root: Path,
    script_path: Path,
    helper_path: Path,
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
        "--pid=private",
        "--cgroupns=private",
        "--ipc=private",
        "--uts=private",
        "--cap-add=NET_ADMIN",
        "--platform",
        spec.podman_platform,
        "--security-opt=no-new-privileges",
        "--security-opt=label=disable",
        "--pids-limit=512",
        "--memory=1g",
        "--tmpfs=/run:rw,nodev,nosuid,exec,size=64m,mode=755,notmpcopyup",
        "--tmpfs=/tmp:rw,nodev,nosuid,exec,size=256m,mode=1777",
        "--volume",
        f"{candidate_root}:/candidate:ro",
        "--volume",
        f"{previous_root}:/previous:ro",
        "--volume",
        f"{script_path}:/lab/package-lifecycle.sh:ro",
        "--volume",
        f"{helper_path}:/lab/package-webtui-retirement.sh:ro",
        "--volume",
        f"{result_root}:/results:rw",
        "--env",
        f"PACKAGE_FAMILY={spec.family}",
        "--env",
        f"EXPECTED_PACKAGE_ARCHITECTURE={spec.package_architecture}",
        "--env",
        f"EXPECTED_UNAME_ARCHITECTURE={spec.uname_architecture}",
        "--env",
        f"EXPECTED_DISTRIBUTION={spec.distribution}",
        "--env",
        f"EXPECTED_DISTRIBUTION_VERSION={spec.version}",
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
        "HISTORICAL_UBUNTU_DEB_RECOVERY="
        + (
            "1"
            if is_historical_ubuntu_deb_recovery_pair(spec, pair)
            else "0"
        ),
        "--env",
        f"SCENARIO={scenario}",
        "--env",
        f"CANDIDATE_PACKAGE=/candidate/{pair.candidate.path.name}",
        "--env",
        f"PREVIOUS_PACKAGE=/previous/{pair.previous.path.name}",
    ]
    if spec.family == "apk":
        arguments.extend(("--cap-add=SYS_BOOT", "--stop-signal=SIGINT"))
    else:
        arguments.extend(
            (
                "--cap-add=SYS_ADMIN",
                "--cap-add=SYS_PTRACE",
                "--systemd=always",
                "--stop-signal=SIGRTMIN+3",
            )
        )
    arguments.append(image)
    return tuple(arguments)


def runtime_namespace_script(spec: PlatformSpec) -> str:
    helper_sha256 = hashlib.sha256(LAB_NETWORK_HELPER.encode("utf-8")).hexdigest()
    common = NAMESPACE_ATTESTATION_HELPERS + f"""syswarden_namespace_status=0
syswarden_namespace_actual="$(sha256sum /usr/local/libexec/syswarden-lab-network | awk '{{ print $1 }}')" || syswarden_namespace_status=$?
syswarden_namespace_expect_equal NS01_HELPER_SHA "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" "{helper_sha256}"
syswarden_namespace_status=0
syswarden_namespace_actual="$(stat -c '%u:%g:%a' /usr/local/libexec/syswarden-lab-network 2>&1)" || syswarden_namespace_status=$?
syswarden_namespace_expect_equal NS02_HELPER_STAT "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}" 0:0:755
syswarden_namespace_status=0
syswarden_namespace_actual="$(ip link show dev eth0 2>&1)" || syswarden_namespace_status=$?
syswarden_namespace_expect_status NS03_ETH0_LINK "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}"
syswarden_namespace_status=0
syswarden_namespace_actual="$(ip -d link show dev eth0 2>&1)" || syswarden_namespace_status=$?
if [ "${{syswarden_namespace_status}}" -eq 0 ]; then
    printf '%s\\n' "${{syswarden_namespace_actual}}" | grep -Eq '(^|[[:space:]])dummy([[:space:]]|$)' || syswarden_namespace_status=$?
fi
syswarden_namespace_expect_status NS04_ETH0_DUMMY "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}"
syswarden_namespace_status=0
syswarden_namespace_actual="$(ip link show dev eth0 2>&1)" || syswarden_namespace_status=$?
syswarden_namespace_expect_status NS05_ETH0_UP_SOURCE "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}"
syswarden_namespace_status=0
printf '%s\\n' "${{syswarden_namespace_actual}}" | grep -Fq UP || syswarden_namespace_status=$?
syswarden_namespace_expect_status NS06_ETH0_UP "${{syswarden_namespace_status}}" "${{syswarden_namespace_actual}}"
"""
    if spec.family != "apk":
        unit_sha256 = hashlib.sha256(
            SYSTEMD_LAB_NETWORK_UNIT.encode("utf-8")
        ).hexdigest()
        systemd_runtime = (
            common
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(sha256sum /etc/systemd/system/syswarden-lab-network.service | awk '{ print $1 }')\" || syswarden_namespace_status=$?\n"
            + f"syswarden_namespace_expect_equal NS07_UNIT_SHA \"${{syswarden_namespace_status}}\" \"${{syswarden_namespace_actual}}\" \"{unit_sha256}\"\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(stat -c '%u:%g:%a' /etc/systemd/system/syswarden-lab-network.service 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_expect_equal NS08_UNIT_STAT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 0:0:644\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(systemctl is-enabled syswarden-lab-network.service 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_expect_equal NS09_NET_ENABLED \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" enabled\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(systemctl is-active syswarden-lab-network.service 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_expect_equal NS10_NET_ACTIVE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" active\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(systemctl is-enabled rsyslog.service 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_expect_equal NS11_RSYSLOG_ENABLED \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" enabled\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(systemctl is-active rsyslog.service 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_expect_equal NS12_RSYSLOG_ACTIVE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" active\n"
            + "syswarden_namespace_status=0\n"
            + "syswarden_namespace_actual=\"$(systemctl --failed --no-legend --plain 2>&1)\" || syswarden_namespace_status=$?\n"
            + "syswarden_namespace_failed_count=\"$(printf '%s\\n' \"${syswarden_namespace_actual}\" | awk 'NF { count++ } END { print count + 0 }')\" || syswarden_namespace_status=$?\n"
            + "if [ \"${syswarden_namespace_status}\" -ne 0 ] || [ \"${syswarden_namespace_failed_count}\" -ne 0 ]; then\n"
            + "    syswarden_namespace_fail NS13_FAILED_UNITS \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" ''\n"
            + "fi\n"
        )
        if spec.distribution == "fedora":
            expected_masks = "\n".join(FEDORA_LAB_MASKED_UNITS)
            systemd_runtime += (
                "syswarden_namespace_status=0\n"
                "syswarden_namespace_actual=\"$(systemctl list-unit-files --state=masked "
                "--no-legend --plain 2>&1)\" || syswarden_namespace_status=$?\n"
                "if [ \"${syswarden_namespace_status}\" -eq 0 ]; then\n"
                "    actual_masks=\"$(printf '%s\\n' \"${syswarden_namespace_actual}\" | awk 'NF { print $1 }' | LC_ALL=C sort)\" || syswarden_namespace_status=$?\n"
                "else\n"
                "    actual_masks=\"${syswarden_namespace_actual}\"\n"
                "fi\n"
                f"syswarden_namespace_expect_equal NS14_FEDORA_MASKS \"${{syswarden_namespace_status}}\" \"${{actual_masks}}\" \"{expected_masks}\"\n"
            )
        return systemd_runtime
    provider_sha256 = hashlib.sha256(
        ALPINE_LAB_NETWORK_PROVIDER.encode("utf-8")
    ).hexdigest()
    return (
        common
        + "syswarden_apk_info_actual=\"$(\n"
        + "    syswarden_apk_info_status=0\n"
        + f"    apk info -e 'openrc={ALPINE_OPENRC_VERSION}' 2>&1 || syswarden_apk_info_status=$?\n"
        + "    printf 'syswarden-apk-info-rc=%s' \"${syswarden_apk_info_status}\"\n"
        + ")\"\n"
        + "syswarden_apk_info_expected=\"$(printf 'openrc\\nsyswarden-apk-info-rc=0')\"\n"
        + "syswarden_namespace_expect_equal NS15_OPENRC_PACKAGE 0 \"${syswarden_apk_info_actual}\" \"${syswarden_apk_info_expected}\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(sha256sum /etc/init.d/syswarden-lab-net 2>&1)\" || syswarden_namespace_status=$?\n"
        + f"syswarden_namespace_expect_equal NS16_APK_PROVIDER_SHA \"${{syswarden_namespace_status}}\" \"${{syswarden_namespace_actual}}\" \"{provider_sha256}  /etc/init.d/syswarden-lab-net\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(stat -c '%F:%u:%g:%a' /etc/init.d/syswarden-lab-net 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_equal NS17_APK_PROVIDER_STAT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 'regular file:0:0:755'\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(stat -c '%F:%u:%g:%a' /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_equal NS18_APK_RC_CONF_STAT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 'regular file:0:0:644'\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(sha256sum /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + f"syswarden_namespace_expect_equal NS19_APK_RC_CONF_SHA \"${{syswarden_namespace_status}}\" \"${{syswarden_namespace_actual}}\" \"{ALPINE_RC_CONF_POST_SHA256}  /etc/rc.conf\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(grep -Fxc 'rc_sys=\"podman\"' /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS20_APK_RC_SYS_LINE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(grep -Fxc 'rc_cgroup_mode=\"legacy\"' /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS21_APK_RC_CGROUP_LINE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(awk '/^[[:space:]]*rc_sys[[:space:]]*=/ { count++ } END { print count + 0 }' /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS22_APK_RC_SYS_COUNT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(awk '/^[[:space:]]*rc_cgroup_mode[[:space:]]*=/ { count++ } END { print count + 0 }' /etc/rc.conf 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS23_APK_RC_CGROUP_COUNT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_openrc_file=\"$(mktemp /tmp/syswarden-openrc-sys.XXXXXX 2>&1)\" || syswarden_namespace_status=$?\n"
        + "if [ \"${syswarden_namespace_status}\" -eq 0 ]; then\n"
        + "    openrc --sys > \"${syswarden_namespace_openrc_file}\" 2>&1 || syswarden_namespace_status=$?\n"
        + "    syswarden_namespace_record_status=0\n"
        + "    syswarden_namespace_actual=\"$(syswarden_namespace_file_record \"${syswarden_namespace_openrc_file}\")\" || syswarden_namespace_record_status=$?\n"
        + "    if [ \"${syswarden_namespace_status}\" -eq 0 ]; then\n"
        + "        syswarden_namespace_status=\"${syswarden_namespace_record_status}\"\n"
        + "    fi\n"
        + "    syswarden_namespace_cleanup_status=0\n"
        + "    syswarden_namespace_cleanup=\"$(rm -f \"${syswarden_namespace_openrc_file}\" 2>&1)\" || syswarden_namespace_cleanup_status=$?\n"
        + "    if [ \"${syswarden_namespace_cleanup_status}\" -ne 0 ]; then\n"
        + "        syswarden_namespace_actual=\"${syswarden_namespace_actual};cleanup=${syswarden_namespace_cleanup}\"\n"
        + "        if [ \"${syswarden_namespace_status}\" -eq 0 ]; then\n"
        + "            syswarden_namespace_status=\"${syswarden_namespace_cleanup_status}\"\n"
        + "        fi\n"
        + "    fi\n"
        + "else\n"
        + "    syswarden_namespace_actual=\"mktemp=${syswarden_namespace_openrc_file}\"\n"
        + "fi\n"
        + f"syswarden_namespace_expect_equal NS24_APK_OPENRC_SYS \"${{syswarden_namespace_status}}\" \"${{syswarden_namespace_actual}}\" 'bytes=7;hex={ALPINE_OPENRC_SYS_ATTESTATION_HEX}'\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(stat -c '%F:%u:%g:%a' /etc/init.d/hostname 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_equal NS25_APK_HOSTNAME_STAT \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 'regular file:0:0:755'\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(sha256sum /etc/init.d/hostname 2>&1)\" || syswarden_namespace_status=$?\n"
        + f"syswarden_namespace_expect_equal NS26_APK_HOSTNAME_SHA \"${{syswarden_namespace_status}}\" \"${{syswarden_namespace_actual}}\" \"{ALPINE_HOSTNAME_INIT_POST_SHA256}  /etc/init.d/hostname\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(grep -Ec '^[[:space:]]*keyword -prefix -lxc -docker -podman$' /etc/init.d/hostname 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS27_APK_HOSTNAME_KEYWORD \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_pid1_environment=\"$(tr '\\000' '\\n' < /proc/1/environ 2>&1)\" || syswarden_namespace_status=$?\n"
        + "if [ \"${syswarden_namespace_status}\" -eq 0 ]; then\n"
        + "    syswarden_namespace_actual=\"$(printf '%s\\n' \"${syswarden_namespace_pid1_environment}\" | grep -Fxc 'container=podman')\" || syswarden_namespace_status=$?\n"
        + "else\n"
        + "    syswarden_namespace_actual=\"${syswarden_namespace_pid1_environment}\"\n"
        + "fi\n"
        + "syswarden_namespace_expect_integer NS28_APK_PID1_ENV \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(awk "
        + shlex.quote(ALPINE_CGROUP_MOUNTINFO_AWK)
        + " /proc/self/mountinfo 2>&1)\" || syswarden_namespace_status=$?\n"
        + "case \"${syswarden_namespace_actual}\" in\n"
        + "    ro|rw) syswarden_namespace_cgroup_access=\"${syswarden_namespace_actual}\"; syswarden_namespace_cgroup_contract=delegated-cgroup2 ;;\n"
        + "    *) syswarden_namespace_cgroup_contract=\"${syswarden_namespace_actual}\" ;;\n"
        + "esac\n"
        + "syswarden_namespace_expect_equal NS29_APK_CGROUP_MOUNT \"${syswarden_namespace_status}\" \"${syswarden_namespace_cgroup_contract}\" delegated-cgroup2\n"
        + "syswarden_namespace_cgroup_boundary() {\n"
        + "    syswarden_namespace_cgroup_access=\"$1\"\n"
        + "    syswarden_namespace_children_status=0\n"
        + "    syswarden_namespace_children=\"$(find /sys/fs/cgroup -mindepth 1 -maxdepth 1 '(' -type d -o -type l ')' -print 2>&1)\" || syswarden_namespace_children_status=$?\n"
        + "    if [ \"${syswarden_namespace_children_status}\" -ne 0 ]; then\n"
        + "        printf 'find=%s' \"${syswarden_namespace_children}\"\n"
        + "        return \"${syswarden_namespace_children_status}\"\n"
        + "    fi\n"
        + "    if [ -n \"${syswarden_namespace_children}\" ]; then\n"
        + "        printf 'children=%s' \"${syswarden_namespace_children}\"\n"
        + "        return 1\n"
        + "    fi\n"
        + "    if [ \"${syswarden_namespace_cgroup_access}\" = ro ]; then\n"
        + "        printf 'ro;children='\n"
        + "        return 0\n"
        + "    fi\n"
        + "    syswarden_namespace_cgroup_status=0\n"
        + "    syswarden_namespace_cgroup=\"$(cat /proc/self/cgroup 2>&1)\" || syswarden_namespace_cgroup_status=$?\n"
        + "    if [ \"${syswarden_namespace_cgroup_status}\" -ne 0 ]; then\n"
        + "        printf 'cgroup=%s' \"${syswarden_namespace_cgroup}\"\n"
        + "        return \"${syswarden_namespace_cgroup_status}\"\n"
        + "    fi\n"
        + "    syswarden_namespace_memory_status=0\n"
        + "    syswarden_namespace_memory=\"$(cat /sys/fs/cgroup/memory.max 2>&1)\" || syswarden_namespace_memory_status=$?\n"
        + "    if [ \"${syswarden_namespace_memory_status}\" -ne 0 ]; then\n"
        + "        printf 'memory.max=%s' \"${syswarden_namespace_memory}\"\n"
        + "        return \"${syswarden_namespace_memory_status}\"\n"
        + "    fi\n"
        + "    syswarden_namespace_pids_status=0\n"
        + "    syswarden_namespace_pids=\"$(cat /sys/fs/cgroup/pids.max 2>&1)\" || syswarden_namespace_pids_status=$?\n"
        + "    if [ \"${syswarden_namespace_pids_status}\" -ne 0 ]; then\n"
        + "        printf 'pids.max=%s' \"${syswarden_namespace_pids}\"\n"
        + "        return \"${syswarden_namespace_pids_status}\"\n"
        + "    fi\n"
        + "    printf 'rw;cgroup=%s;memory.max=%s;pids.max=%s;children=' \\\n"
        + "        \"${syswarden_namespace_cgroup}\" \"${syswarden_namespace_memory}\" \\\n"
        + "        \"${syswarden_namespace_pids}\"\n"
        + "}\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(syswarden_namespace_cgroup_boundary \"${syswarden_namespace_cgroup_access}\")\" || syswarden_namespace_status=$?\n"
        + "case \"${syswarden_namespace_cgroup_access}\" in\n"
        + "    ro) syswarden_namespace_expected='ro;children=' ;;\n"
        + "    rw) syswarden_namespace_expected='rw;cgroup=0::/;memory.max=1073741824;pids.max=512;children=' ;;\n"
        + "    *) syswarden_namespace_expected=delegated-cgroup2 ;;\n"
        + "esac\n"
        + "syswarden_namespace_expect_equal NS30_APK_CGROUP_BOUNDARY \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" \"${syswarden_namespace_expected}\"\n"
        + "syswarden_namespace_runlevel_count() {\n"
        + "    syswarden_namespace_service=\"$1\"\n"
        + "    syswarden_namespace_runlevel_status=0\n"
        + "    syswarden_namespace_runlevels=\"$(rc-update show -v 2>&1)\" || syswarden_namespace_runlevel_status=$?\n"
        + "    if [ \"${syswarden_namespace_runlevel_status}\" -ne 0 ]; then\n"
        + "        printf '%s' \"${syswarden_namespace_runlevels}\"\n"
        + "        return \"${syswarden_namespace_runlevel_status}\"\n"
        + "    fi\n"
        + "    printf '%s\\n' \"${syswarden_namespace_runlevels}\" | awk -v wanted=\"${syswarden_namespace_service}\" '$1 == wanted && $2 == \"|\" && $3 == \"default\" { count++ } END { print count + 0 }'\n"
        + "}\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(syswarden_namespace_runlevel_count syswarden-lab-net)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS31_APK_NET_RUNLEVEL \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(syswarden_namespace_runlevel_count cronie)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS32_APK_CRON_RUNLEVEL \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(syswarden_namespace_runlevel_count rsyslog)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_integer NS33_APK_RSYSLOG_RUNLEVEL \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\" 1\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(rc-service syswarden-lab-net status 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_status NS34_APK_NET_ACTIVE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(rc-service cronie status 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_status NS35_APK_CRON_ACTIVE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\"\n"
        + "syswarden_namespace_status=0\n"
        + "syswarden_namespace_actual=\"$(rc-service rsyslog status 2>&1)\" || syswarden_namespace_status=$?\n"
        + "syswarden_namespace_expect_status NS36_APK_RSYSLOG_ACTIVE \"${syswarden_namespace_status}\" \"${syswarden_namespace_actual}\"\n"
    )


def attest_runtime_namespace(
    runner: CommandRunner,
    podman: str,
    name: str,
    spec: PlatformSpec,
    *,
    attempts: int = 30,
) -> ProcessSecurityEvidence:
    last_result: CommandResult | None = None
    for attempt in range(attempts):
        prepared = runner.run(
            lifecycle_exec_arguments(
                podman, name, spec, runtime_namespace_script(spec)
            ),
            timeout=60,
        )
        last_result = prepared
        if prepared.returncode == 0:
            security, remainder = parse_exec_security_output(
                prepared.stdout, f"{spec.name} namespace attestation", spec
            )
            if remainder:
                raise LifecycleLabError(
                    f"{spec.name} namespace attestation emitted unexpected output"
                )
            return security
        if attempt + 1 < attempts:
            time.sleep(1)
    assert last_result is not None
    raise LifecycleLabError(
        f"attest isolated runtime namespace for {spec.name} failed after "
        f"{attempts} bounded attempts: {command_log_tail(last_result)}"
    )


def runtime_snapshot_script(spec: PlatformSpec, product_state: str) -> str:
    if product_state not in {"active", "absent", "unasserted"}:
        raise LifecycleLabError(
            f"unsupported product service expectation: {product_state!r}"
        )
    manager = "openrc" if spec.family == "apk" else "systemd"
    cron_executable = expected_cron_executable(spec)
    if spec.family == "deb":
        cron_service = "cron.service"
        cron_fragment = "/usr/lib/systemd/system/cron.service"
    elif spec.family == "rpm":
        cron_service = "crond.service"
        cron_fragment = "/usr/lib/systemd/system/crond.service"
    else:
        cron_service = "cronie"
        cron_fragment = "/etc/init.d/cronie"
    cron_fragment_mode_hex = "81ed" if spec.family == "apk" else "81a4"
    expected_cron_dropin = (
        FEDORA_CRON_DROPIN_PATH if spec.distribution == "fedora" else ""
    )
    return f"""set -eu
syswarden_expected_manager='{manager}'
syswarden_package_family='{spec.family}'
syswarden_expected_product_state='{product_state}'
. /lab/package-webtui-retirement.sh
syswarden_snapshot_hex_prefix() {{
    LC_ALL=C od -An -v -tx1 | tr -d ' \n' | cut -c1-512
}}
syswarden_snapshot_fail() {{
    syswarden_snapshot_predicate="$1"
    syswarden_snapshot_status="$2"
    syswarden_snapshot_actual="$3"
    syswarden_snapshot_expected="$4"
    case "${{syswarden_snapshot_predicate}}" in
        RS[0-9][0-9]_*) ;;
        *) exit 97 ;;
    esac
    case "${{syswarden_snapshot_status}}" in
        ''|*[!0-9]*) exit 97 ;;
    esac
    [ "${{syswarden_snapshot_status}}" -le 255 ] || exit 97
    syswarden_snapshot_actual_bytes="$(
        printf '%s' "${{syswarden_snapshot_actual}}" | LC_ALL=C wc -c | tr -d ' '
    )" || exit 97
    syswarden_snapshot_expected_bytes="$(
        printf '%s' "${{syswarden_snapshot_expected}}" | LC_ALL=C wc -c | tr -d ' '
    )" || exit 97
    syswarden_snapshot_actual_hex_prefix="$(
        printf '%s' "${{syswarden_snapshot_actual}}" | syswarden_snapshot_hex_prefix
    )" || exit 97
    syswarden_snapshot_expected_hex_prefix="$(
        printf '%s' "${{syswarden_snapshot_expected}}" | syswarden_snapshot_hex_prefix
    )" || exit 97
    printf '%s\tpredicate=%s\trc=%s\tactual_bytes=%s\tactual_hex_prefix=%s\texpected_bytes=%s\texpected_hex_prefix=%s\n' \
        '{SNAPSHOT_FAILURE_MARKER}' "${{syswarden_snapshot_predicate}}" \
        "${{syswarden_snapshot_status}}" "${{syswarden_snapshot_actual_bytes}}" \
        "${{syswarden_snapshot_actual_hex_prefix}}" \
        "${{syswarden_snapshot_expected_bytes}}" \
        "${{syswarden_snapshot_expected_hex_prefix}}" >&2
}}
attest_no_syswarden_core_runtime() {{
    core_proc_root="$1"
    core_pidfile="$2"
    [ ! -e "${{core_pidfile}}" ] && [ ! -L "${{core_pidfile}}" ] || return 79
    for core_process_root in "${{core_proc_root}}"/[0-9]*; do
        [ -d "${{core_process_root}}" ] || continue
        core_process_comm="$(cat "${{core_process_root}}/comm" 2>/dev/null || true)"
        core_process_exe="$(readlink "${{core_process_root}}/exe" 2>/dev/null || true)"
        if [ "${{core_process_comm}}" = syswarden-core ]; then
            return 79
        fi
        case "${{core_process_exe}}" in
            /opt/syswarden/bin/syswarden-core|\
            '/opt/syswarden/bin/syswarden-core (deleted)') return 79 ;;
        esac
    done
}}
canonical_id_map() {{
    awk '
        NF != 3 || $1 !~ /^(0|[1-9][0-9]*)$/ ||
            $2 !~ /^(0|[1-9][0-9]*)$/ ||
            $3 !~ /^(0|[1-9][0-9]*)$/ {{ exit 1 }}
        {{
            printf "%s%s:%s:%s", (count ? "," : ""), $1, $2, $3
            count++
        }}
        END {{
            if (!count) exit 1
            print ""
        }}
    ' "$1"
}}
capture_snapshot() {{
    pid1_comm="$(cat /proc/1/comm)"
    pid1_exe="$(readlink /proc/1/exe)"
    pid1_starttime="$(awk '{{ print $22 }}' /proc/1/stat)"
    case "${{pid1_starttime}}" in ''|*[!0-9]*) return 71 ;; esac
    pid1_cap_inh="$(syswarden_read_status_value 1 CapInh)" || return 83
    pid1_cap_prm="$(syswarden_read_status_value 1 CapPrm)" || return 83
    pid1_cap_eff="$(syswarden_read_status_value 1 CapEff)" || return 83
    pid1_cap_bnd="$(syswarden_read_status_value 1 CapBnd)" || return 83
    pid1_cap_amb="$(syswarden_read_status_value 1 CapAmb)" || return 83
    pid1_nnp="$(syswarden_read_status_value 1 NoNewPrivs)" || return 83
    [ "${{pid1_nnp}}" = 1 ] || return 83
    pid1_uid_map="$(canonical_id_map /proc/1/uid_map)" || return 83
    pid1_gid_map="$(canonical_id_map /proc/1/gid_map)" || return 83
    [ "${{pid1_uid_map%%,*}}" = "0:{os.geteuid()}:1" ] || return 83
    [ "${{pid1_gid_map%%,*}}" = "0:{os.getegid()}:1" ] || return 83
    if [ "${{syswarden_expected_manager}}" = systemd ]; then
        for pid1_capability in \
            "${{pid1_cap_prm}}" "${{pid1_cap_eff}}" "${{pid1_cap_bnd}}"; do
            syswarden_capability_has_sys_admin "${{pid1_capability}}" || return 83
            syswarden_capability_has_sys_ptrace "${{pid1_capability}}" || return 83
        done
        for pid1_capability in "${{pid1_cap_inh}}" "${{pid1_cap_amb}}"; do
            if syswarden_capability_has_sys_admin "${{pid1_capability}}"; then
                return 83
            else
                pid1_capability_status=$?
                [ "${{pid1_capability_status}}" -eq 1 ] || return 83
            fi
            if syswarden_capability_has_sys_ptrace "${{pid1_capability}}"; then
                return 83
            else
                pid1_capability_status=$?
                [ "${{pid1_capability_status}}" -eq 1 ] || return 83
            fi
        done
    else
        for pid1_capability in \
            "${{pid1_cap_inh}}" "${{pid1_cap_prm}}" \
            "${{pid1_cap_eff}}" "${{pid1_cap_bnd}}" \
            "${{pid1_cap_amb}}"; do
            if syswarden_capability_has_sys_admin "${{pid1_capability}}"; then
                return 83
            else
                pid1_capability_status=$?
                [ "${{pid1_capability_status}}" -eq 1 ] || return 83
            fi
            if syswarden_capability_has_sys_ptrace "${{pid1_capability}}"; then
                return 83
            else
                pid1_capability_status=$?
                [ "${{pid1_capability_status}}" -eq 1 ] || return 83
            fi
        done
    fi
    if [ "${{syswarden_expected_manager}}" = systemd ]; then
        setpriv_path=/usr/bin/setpriv
        [ -f "${{setpriv_path}}" ] && [ ! -L "${{setpriv_path}}" ] || return 84
        setpriv_identity="$(stat -Lc '%d:%i:%f:%u:%g' "${{setpriv_path}}" 2>/dev/null || true)"
        case "${{setpriv_identity}}" in *:81ed:0:0) ;; *) return 84 ;; esac
        setpriv_sha256="$(sha256sum "${{setpriv_path}}" 2>/dev/null | awk '{{ print $1 }}')"
        case "${{setpriv_sha256}}" in *[!0-9a-f]*|'') return 84 ;; esac
        [ "${{#setpriv_sha256}}" -eq 64 ] || return 84
        case "${{syswarden_package_family}}" in
            deb)
                [ "$(dpkg-query -S "${{setpriv_path}}" 2>/dev/null || true)" = \
                    "util-linux: ${{setpriv_path}}" ] || return 84
                setpriv_package_name=util-linux
                setpriv_package_version="$(dpkg-query -W -f='${{Version}}' util-linux 2>/dev/null || true)"
                setpriv_package_architecture="$(dpkg-query -W -f='${{Architecture}}' util-linux 2>/dev/null || true)"
                ;;
            rpm)
                setpriv_package_record="$(rpm -qf --qf '%{{NAME}}\t%{{EVR}}\t%{{ARCH}}' "${{setpriv_path}}" 2>/dev/null || true)"
                [ "$(printf '%s\n' "${{setpriv_package_record}}" | awk -F '\t' 'NF == 3 {{ print $1 }}')" = util-linux ] || return 84
                setpriv_package_name=util-linux
                setpriv_package_version="$(printf '%s\n' "${{setpriv_package_record}}" | cut -f2)"
                setpriv_package_architecture="$(printf '%s\n' "${{setpriv_package_record}}" | cut -f3)"
                ;;
        esac
        case "${{setpriv_package_version}}" in ''|*[!A-Za-z0-9.+:~_-]*) return 84 ;; esac
        [ "${{#setpriv_package_version}}" -le 128 ] || return 84
        [ "${{setpriv_package_architecture}}" = "{spec.package_architecture}" ] || return 84
        [ "$(stat -Lc '%d:%i:%f:%u:%g' "${{setpriv_path}}" 2>/dev/null || true)" = \
            "${{setpriv_identity}}" ] || return 84
        [ "$(sha256sum "${{setpriv_path}}" 2>/dev/null | awk '{{ print $1 }}')" = \
            "${{setpriv_sha256}}" ] || return 84
    else
        setpriv_path=-
        setpriv_identity=-
        setpriv_sha256=-
        setpriv_package_name=-
        setpriv_package_version=-
        setpriv_package_architecture=-
    fi
    manager_state="$(syswarden_classify_service_manager / "${{syswarden_expected_manager}}")"
    [ "${{manager_state}}" = ACTIVE ] || return 72
    ip link show dev eth0 >/dev/null 2>&1 || return 73
    ip -d link show dev eth0 | grep -Eq '(^|[[:space:]])dummy([[:space:]]|$)' || return 73
    ip link show dev eth0 | grep -Fq 'UP' || return 73
    if [ "${{syswarden_expected_manager}}" = systemd ]; then
        case "${{pid1_exe}}" in /usr/lib/systemd/systemd|/lib/systemd/systemd) ;; *) return 74 ;; esac
        [ "${{pid1_comm}}" = systemd ] || return 74
        manager_runtime="$(systemctl is-system-running 2>/dev/null || true)"
        [ "${{manager_runtime}}" = running ] || return 75
        cron_enabled="$(systemctl is-enabled {cron_service} 2>/dev/null || true)"
        cron_active="$(systemctl is-active {cron_service} 2>/dev/null || true)"
        cron_pid="$(systemctl show -p MainPID --value {cron_service} 2>/dev/null || true)"
        rsyslog_enabled="$(systemctl is-enabled rsyslog.service 2>/dev/null || true)"
        rsyslog_active="$(systemctl is-active rsyslog.service 2>/dev/null || true)"
        rsyslog_pid="$(systemctl show -p MainPID --value rsyslog.service 2>/dev/null || true)"
        [ "${{cron_enabled}}" = enabled ] && [ "${{cron_active}}" = active ] || return 76
        [ "${{rsyslog_enabled}}" = enabled ] && [ "${{rsyslog_active}}" = active ] || return 76
    else
        [ "${{pid1_comm}}" = openrc-init ] && [ "${{pid1_exe}}" = /sbin/openrc-init ] || return 74
        manager_runtime="$(rc-status --runlevel 2>/dev/null || true)"
        [ "${{manager_runtime}}" = default ] || return 75
        [ "$(rc-update show -v | awk '$1 == "cronie" && $2 == "|" && $3 == "default" {{ count++ }} END {{ print count + 0 }}')" -eq 1 ] || return 76
        [ "$(rc-update show -v | awk '$1 == "rsyslog" && $2 == "|" && $3 == "default" {{ count++ }} END {{ print count + 0 }}')" -eq 1 ] || return 76
        rc-service cronie status >/dev/null 2>&1 || return 76
        rc-service rsyslog status >/dev/null 2>&1 || return 76
        cron_enabled=enabled
        cron_active=active
        rsyslog_enabled=enabled
        rsyslog_active=active
        cron_pid="$(pgrep -x crond 2>/dev/null || true)"
        rsyslog_pid="$(pgrep -x rsyslogd 2>/dev/null || true)"
        [ "$(printf '%s\n' "${{cron_pid}}" | awk 'NF {{ count++ }} END {{ print count + 0 }}')" -eq 1 ] || return 76
        [ "$(printf '%s\n' "${{rsyslog_pid}}" | awk 'NF {{ count++ }} END {{ print count + 0 }}')" -eq 1 ] || return 76
    fi
    case "${{cron_pid}}:${{rsyslog_pid}}" in *[!0-9:]*) return 77 ;; esac
    [ "${{cron_pid}}" -gt 1 ] && [ "${{rsyslog_pid}}" -gt 1 ] || return 77
    kill -0 "${{cron_pid}}" 2>/dev/null && kill -0 "${{rsyslog_pid}}" 2>/dev/null || return 77
    cron_executable_path="$(readlink "/proc/${{cron_pid}}/exe" 2>/dev/null || true)"
    if [ "${{cron_executable_path}}" != "{cron_executable}" ]; then
        syswarden_snapshot_fail RS07_CRON_EXECUTABLE_PATH 82 \
            "${{cron_executable_path}}" "{cron_executable}"
        return 82
    fi
    cron_process_identity="$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${{cron_pid}}/exe" 2>/dev/null || true)"
    cron_installed_identity="$(stat -Lc '%d:%i:%f:%u:%g' "{cron_executable}" 2>/dev/null || true)"
    cron_process_sha256="$(sha256sum "/proc/${{cron_pid}}/exe" 2>/dev/null | awk '{{ print $1 }}')"
    cron_installed_sha256="$(sha256sum "{cron_executable}" 2>/dev/null | awk '{{ print $1 }}')"
    [ -n "${{cron_process_identity}}" ] && \
        [ "${{cron_process_identity}}" = "${{cron_installed_identity}}" ] && \
        [ "${{cron_process_sha256}}" = "${{cron_installed_sha256}}" ] || return 82
    case "${{cron_installed_sha256}}" in *[!0-9a-f]*|'') return 82 ;; esac
    [ "${{#cron_installed_sha256}}" -eq 64 ] || return 82
    [ "${{cron_installed_identity#*:*:}}" != "${{cron_installed_identity}}" ] || return 82
    [ "$(stat -Lc '%f:%u:%g' "{cron_executable}" 2>/dev/null || true)" = 81ed:0:0 ] || return 82
    if [ "${{syswarden_expected_manager}}" = systemd ]; then
        cron_fragment_path="$(systemctl show {cron_service} -p FragmentPath --value 2>/dev/null || true)"
        case "${{syswarden_package_family}}:${{cron_fragment_path}}" in
            deb:/lib/systemd/system/cron.service|deb:/usr/lib/systemd/system/cron.service|\
            rpm:/usr/lib/systemd/system/crond.service) ;;
            *) return 82 ;;
        esac
        cron_dropin_value="$(systemctl show {cron_service} -p DropInPaths --value 2>/dev/null || true)"
        if [ "${{cron_dropin_value}}" != "{expected_cron_dropin}" ]; then
            syswarden_snapshot_fail RS01_CRON_DROPIN_PATHS 82 \
                "${{cron_dropin_value}}" "{expected_cron_dropin}"
            return 82
        fi
    else
        cron_fragment_path="{cron_fragment}"
        [ -f "${{cron_fragment_path}}" ] && [ ! -L "${{cron_fragment_path}}" ] || return 82
        cron_dropin_value=
    fi
    cron_dropin_output=-
    cron_dropin_attestation=-
    if [ -n "${{cron_dropin_value}}" ]; then
        cron_dropin_path="${{cron_dropin_value}}"
        cron_dropin_lstat="$(stat -c '%d:%i:%f:%u:%g' "${{cron_dropin_path}}" 2>/dev/null || true)"
        cron_dropin_stat="$(stat -Lc '%d:%i:%f:%u:%g' "${{cron_dropin_path}}" 2>/dev/null || true)"
        cron_dropin_sha256="$(sha256sum "${{cron_dropin_path}}" 2>/dev/null | awk '{{ print $1 }}')"
        cron_dropin_file_state="$(stat -c '%f:%u:%g' "${{cron_dropin_path}}" 2>/dev/null || true)"
        if [ ! -f "${{cron_dropin_path}}" ] || [ -L "${{cron_dropin_path}}" ] || \
           [ "${{cron_dropin_file_state}}" != 81a4:0:0 ] || \
           [ -z "${{cron_dropin_lstat}}" ] || [ -z "${{cron_dropin_stat}}" ]; then
            syswarden_snapshot_fail RS02_CRON_DROPIN_FILE 82 \
                "${{cron_dropin_file_state}}" 81a4:0:0
            return 82
        fi
        case "${{cron_dropin_sha256}}" in *[!0-9a-f]*|'')
            syswarden_snapshot_fail RS03_CRON_DROPIN_SHA256 82 \
                "${{cron_dropin_sha256}}" sha256-lowercase-hex
            return 82
            ;;
        esac
        if [ "${{#cron_dropin_sha256}}" -ne 64 ]; then
            syswarden_snapshot_fail RS03_CRON_DROPIN_SHA256 82 \
                "${{cron_dropin_sha256}}" sha256-lowercase-hex
            return 82
        fi
        cron_dropin_package_status=0
        cron_dropin_package_record="$(
            rpm -qf --qf '%{{NAME}}\t%{{EVR}}\t%{{ARCH}}\t%{{FILEDIGESTALGO}}\n' \
                "${{cron_dropin_path}}" 2>/dev/null
        )" || cron_dropin_package_status=$?
        if [ "${{cron_dropin_package_status}}" -ne 0 ]; then
            syswarden_snapshot_fail RS04_CRON_DROPIN_PACKAGE 82 \
                "rc=${{cron_dropin_package_status}}|${{cron_dropin_package_record}}" \
                'rc=0|systemd<TAB>EVR<TAB>{spec.package_architecture}<TAB>8'
            return 82
        fi
        if ! printf '%s\n' "${{cron_dropin_package_record}}" | awk -F '\t' \
            -v expected_arch='{spec.package_architecture}' '
                NF != 4 {{ bad = 1 }}
                $1 != "systemd" || $2 !~ /^[A-Za-z0-9.+:~_-]+$/ ||
                    length($2) > 128 || $3 != expected_arch || $4 != "8" {{ bad = 1 }}
                {{ count++ }}
                END {{ exit !(count == 1 && !bad) }}
            '; then
            syswarden_snapshot_fail RS04_CRON_DROPIN_PACKAGE 82 \
                "${{cron_dropin_package_record}}" \
                'systemd<TAB>EVR<TAB>{spec.package_architecture}<TAB>8'
            return 82
        fi
        cron_dropin_package_version="$(printf '%s\n' "${{cron_dropin_package_record}}" | cut -f2)"
        cron_dropin_metadata_status=0
        cron_dropin_metadata_record="$(
            rpm -qf --qf '[%{{FILENAMES}}\t%{{FILEDIGESTS}}\n]' \
                "${{cron_dropin_path}}" 2>/dev/null
        )" || cron_dropin_metadata_status=$?
        if [ "${{cron_dropin_metadata_status}}" -ne 0 ]; then
            syswarden_snapshot_fail RS05_CRON_DROPIN_RPM_DIGEST 82 \
                "rc=${{cron_dropin_metadata_status}}|${{cron_dropin_metadata_record}}" \
                'rc=0|PATH<TAB>SHA256'
            return 82
        fi
        cron_dropin_metadata_sha256="$(
            printf '%s\n' "${{cron_dropin_metadata_record}}" |
                awk -F '\t' -v wanted="${{cron_dropin_path}}" '
                    $1 == wanted {{ count++; digest = $2 }}
                    END {{ if (count != 1) exit 1; print digest }}
                '
        )" || cron_dropin_metadata_sha256=
        if [ "${{cron_dropin_metadata_sha256}}" != "${{cron_dropin_sha256}}" ]; then
            syswarden_snapshot_fail RS05_CRON_DROPIN_RPM_DIGEST 82 \
                "${{cron_dropin_sha256}}" "${{cron_dropin_metadata_sha256}}"
            return 82
        fi
        cron_dropin_after="$(
            stat -c '%d:%i:%f:%u:%g' "${{cron_dropin_path}}" 2>/dev/null || true
        )|$(
            stat -Lc '%d:%i:%f:%u:%g' "${{cron_dropin_path}}" 2>/dev/null || true
        )|$(sha256sum "${{cron_dropin_path}}" 2>/dev/null | awk '{{ print $1 }}')"
        if [ "${{cron_dropin_after}}" != \
             "${{cron_dropin_lstat}}|${{cron_dropin_stat}}|${{cron_dropin_sha256}}" ]; then
            syswarden_snapshot_fail RS06_CRON_DROPIN_DRIFT 82 \
                "${{cron_dropin_after}}" \
                "${{cron_dropin_lstat}}|${{cron_dropin_stat}}|${{cron_dropin_sha256}}"
            return 82
        fi
        cron_dropin_output="${{cron_dropin_path}}"
        cron_dropin_attestation="${{cron_dropin_stat}}|${{cron_dropin_sha256}}|systemd|${{cron_dropin_package_version}}|{spec.package_architecture}|8"
    fi
    [ -f "${{cron_fragment_path}}" ] && [ ! -L "${{cron_fragment_path}}" ] && \
        [ "$(stat -c '%f:%u:%g' "${{cron_fragment_path}}" 2>/dev/null || true)" = {cron_fragment_mode_hex}:0:0 ] || return 82
    cron_fragment_stat="$(stat -Lc '%d:%i:%f:%u:%g' "${{cron_fragment_path}}" 2>/dev/null || true)"
    cron_fragment_sha256="$(sha256sum "${{cron_fragment_path}}" 2>/dev/null | awk '{{ print $1 }}')"
    case "${{cron_fragment_sha256}}" in *[!0-9a-f]*|'') return 82 ;; esac
    [ "${{#cron_fragment_sha256}}" -eq 64 ] || return 82
    case "${{syswarden_package_family}}" in
        deb)
            [ "$(dpkg-query -S "{cron_executable}" 2>/dev/null || true)" = "cron: {cron_executable}" ] || return 82
            cron_package_name=cron
            cron_package_version="$(dpkg-query -W -f='${{Version}}' cron 2>/dev/null || true)"
            cron_package_architecture="$(dpkg-query -W -f='${{Architecture}}' cron 2>/dev/null || true)"
            cron_fragment_owner_count=0
            for cron_fragment_owner_path in /lib/systemd/system/cron.service /usr/lib/systemd/system/cron.service; do
                if [ "$(dpkg-query -S "${{cron_fragment_owner_path}}" 2>/dev/null || true)" = "cron: ${{cron_fragment_owner_path}}" ] && \
                   [ "$(stat -Lc '%d:%i:%f:%u:%g' "${{cron_fragment_owner_path}}" 2>/dev/null || true)" = "${{cron_fragment_stat}}" ]; then
                    cron_fragment_owner_count=$((cron_fragment_owner_count + 1))
                fi
            done
            [ "${{cron_fragment_owner_count}}" -eq 1 ] || return 82
            cron_fragment_package_name=cron
            cron_fragment_package_version="${{cron_package_version}}"
            cron_fragment_package_architecture="${{cron_package_architecture}}"
            ;;
        rpm)
            cron_package_name="$(rpm -qf --qf '%{{NAME}}' "{cron_executable}" 2>/dev/null || true)"
            cron_package_version="$(rpm -qf --qf '%{{EVR}}' "{cron_executable}" 2>/dev/null || true)"
            cron_package_architecture="$(rpm -qf --qf '%{{ARCH}}' "{cron_executable}" 2>/dev/null || true)"
            [ "${{cron_package_name}}" = cronie ] || return 82
            cron_fragment_package_name="$(rpm -qf --qf '%{{NAME}}' "${{cron_fragment_path}}" 2>/dev/null || true)"
            cron_fragment_package_version="$(rpm -qf --qf '%{{EVR}}' "${{cron_fragment_path}}" 2>/dev/null || true)"
            cron_fragment_package_architecture="$(rpm -qf --qf '%{{ARCH}}' "${{cron_fragment_path}}" 2>/dev/null || true)"
            [ "${{cron_fragment_package_name}}:${{cron_fragment_package_version}}:${{cron_fragment_package_architecture}}" = \
                "${{cron_package_name}}:${{cron_package_version}}:${{cron_package_architecture}}" ] || return 82
            ;;
        apk)
            apk_installed_db=/lib/apk/db/installed
            [ -f "${{apk_installed_db}}" ] && [ ! -L "${{apk_installed_db}}" ] && \
                [ "$(stat -c '%u:%g' "${{apk_installed_db}}" 2>/dev/null || true)" = 0:0 ] && \
                [ "$(wc -c < "${{apk_installed_db}}" | tr -d ' ')" -le 16777216 ] || return 82
            apk_installed_record() {{
                awk -v wanted="$1" '
                    function flush() {{
                        if (package == wanted) {{
                            count++
                            if (pcount != 1 || vcount != 1 || acount != 1) bad = 1
                            result = package "\t" version "\t" architecture
                        }}
                        package = version = architecture = ""
                        pcount = vcount = acount = 0
                    }}
                    /^$/ {{ flush(); next }}
                    /^P:/ {{ package = substr($0, 3); pcount++; next }}
                    /^V:/ {{ version = substr($0, 3); vcount++; next }}
                    /^A:/ {{ architecture = substr($0, 3); acount++; next }}
                    END {{ flush(); if (count != 1 || bad) exit 1; print result }}
                ' "${{apk_installed_db}}"
            }}
            cron_package_record="$(apk_installed_record cronie)" || return 82
            cron_fragment_package_record="$(apk_installed_record cronie-openrc)" || return 82
            [ "$(printf '%s\n' "${{cron_package_record}}" | awk -F '\t' 'NF == 3 {{ print $1 }}')" = cronie ] || return 82
            cron_package_name=cronie
            cron_package_version="$(printf '%s\n' "${{cron_package_record}}" | cut -f2)"
            cron_package_architecture="$(printf '%s\n' "${{cron_package_record}}" | cut -f3)"
            cron_fragment_package_name=cronie-openrc
            cron_fragment_package_version="$(printf '%s\n' "${{cron_fragment_package_record}}" | cut -f2)"
            cron_fragment_package_architecture="$(printf '%s\n' "${{cron_fragment_package_record}}" | cut -f3)"
            cron_package_owner="$(apk info --who-owns "{cron_executable}" 2>/dev/null || true)"
            [ "${{cron_package_owner}}" = "{cron_executable} is owned by cronie-${{cron_package_version}}" ] || return 82
            cron_fragment_package_owner="$(apk info --who-owns "${{cron_fragment_path}}" 2>/dev/null || true)"
            [ "${{cron_fragment_package_owner}}" = "${{cron_fragment_path}} is owned by cronie-openrc-${{cron_fragment_package_version}}" ] || return 82
            [ "${{cron_package_version}}" = "${{cron_fragment_package_version}}" ] || return 82
            [ "${{cron_package_architecture}}" = "$(apk --print-arch 2>/dev/null || true)" ] || return 82
            ;;
    esac
    [ "${{cron_package_architecture}}" = "{spec.package_architecture}" ] || return 82
    case "${{cron_package_version}}" in ''|*[!A-Za-z0-9.+:~_-]*) return 82 ;; esac
    [ "${{#cron_package_version}}" -le 128 ] || return 82
    [ "${{cron_fragment_package_architecture}}" = "${{cron_package_architecture}}" ] || return 82
    cron_fragment_identity="${{cron_fragment_stat}}|${{cron_fragment_sha256}}"
    [ "$(readlink "/proc/${{cron_pid}}/exe" 2>/dev/null || true)" = "${{cron_executable_path}}" ] || return 82
    [ "$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${{cron_pid}}/exe" 2>/dev/null || true)" = "${{cron_process_identity}}" ] || return 82
    [ "$(stat -Lc '%d:%i:%f:%u:%g' "{cron_executable}" 2>/dev/null || true)" = "${{cron_installed_identity}}" ] || return 82
    [ "$(sha256sum "/proc/${{cron_pid}}/exe" 2>/dev/null | awk '{{ print $1 }}')" = "${{cron_process_sha256}}" ] || return 82
    [ "$(sha256sum "{cron_executable}" 2>/dev/null | awk '{{ print $1 }}')" = "${{cron_installed_sha256}}" ] || return 82
    [ "$(stat -Lc '%d:%i:%f:%u:%g' "${{cron_fragment_path}}" 2>/dev/null || true)" = "${{cron_fragment_stat}}" ] || return 82
    [ "$(sha256sum "${{cron_fragment_path}}" 2>/dev/null | awk '{{ print $1 }}')" = "${{cron_fragment_sha256}}" ] || return 82
    cron_executable_identity="${{cron_installed_identity}}|${{cron_installed_sha256}}"
    if [ "${{syswarden_expected_product_state}}" = active ]; then
        if [ "${{syswarden_expected_manager}}" = systemd ]; then
            core_load="$(systemctl show syswarden-core.service -p LoadState --value 2>/dev/null || true)"
            core_fragment="$(systemctl show syswarden-core.service -p FragmentPath --value 2>/dev/null || true)"
            core_active="$(systemctl show syswarden-core.service -p ActiveState --value 2>/dev/null || true)"
            core_enabled="$(systemctl show syswarden-core.service -p UnitFileState --value 2>/dev/null || true)"
            core_pid="$(systemctl show syswarden-core.service -p MainPID --value 2>/dev/null || true)"
            firewall_load="$(systemctl show syswarden-firewall.service -p LoadState --value 2>/dev/null || true)"
            firewall_fragment="$(systemctl show syswarden-firewall.service -p FragmentPath --value 2>/dev/null || true)"
            firewall_active="$(systemctl show syswarden-firewall.service -p ActiveState --value 2>/dev/null || true)"
            firewall_enabled="$(systemctl show syswarden-firewall.service -p UnitFileState --value 2>/dev/null || true)"
            firewall_pid="$(systemctl show syswarden-firewall.service -p MainPID --value 2>/dev/null || true)"
            [ "${{core_load}}:${{core_fragment}}:${{core_active}}:${{core_enabled}}" = \
                'loaded:/etc/systemd/system/syswarden-core.service:active:enabled' ] || return 78
            [ "${{firewall_load}}:${{firewall_fragment}}:${{firewall_active}}:${{firewall_enabled}}" = \
                'loaded:/etc/systemd/system/syswarden-firewall.service:active:enabled' ] || return 78
            [ "${{core_pid}}" -gt 1 ] && [ "${{firewall_pid}}" -eq 0 ] || return 78
            kill -0 "${{core_pid}}" 2>/dev/null || return 78
        else
            for service in syswarden-core syswarden-firewall; do
                [ -f "/etc/init.d/${{service}}" ] && [ ! -L "/etc/init.d/${{service}}" ] || return 78
                [ -L "/etc/runlevels/default/${{service}}" ] && [ "$(readlink "/etc/runlevels/default/${{service}}")" = "/etc/init.d/${{service}}" ] || return 78
                rc-service "${{service}}" status >/dev/null 2>&1 || return 78
            done
            core_pid="$(pgrep -x syswarden-core 2>/dev/null || true)"
            [ "$(printf '%s\n' "${{core_pid}}" | awk 'NF {{ count++ }} END {{ print count + 0 }}')" -eq 1 ] || return 78
            [ "${{core_pid}}" -gt 1 ] && kill -0 "${{core_pid}}" 2>/dev/null || return 78
            core_load=loaded
            core_fragment=/etc/init.d/syswarden-core
            core_enabled=enabled
            core_active=active
            firewall_load=loaded
            firewall_fragment=/etc/init.d/syswarden-firewall
            firewall_enabled=enabled
            firewall_active=active
            firewall_pid=0
        fi
        core_cap_inh="$(syswarden_read_status_value "${{core_pid}}" CapInh)" || return 85
        core_cap_prm="$(syswarden_read_status_value "${{core_pid}}" CapPrm)" || return 85
        core_cap_eff="$(syswarden_read_status_value "${{core_pid}}" CapEff)" || return 85
        core_cap_bnd="$(syswarden_read_status_value "${{core_pid}}" CapBnd)" || return 85
        core_cap_amb="$(syswarden_read_status_value "${{core_pid}}" CapAmb)" || return 85
        core_nnp="$(syswarden_read_status_value "${{core_pid}}" NoNewPrivs)" || return 85
        [ "${{core_nnp}}" = 1 ] || return 85
        for core_capability in \
            "${{core_cap_inh}}" "${{core_cap_prm}}" \
            "${{core_cap_eff}}" "${{core_cap_bnd}}" \
            "${{core_cap_amb}}"; do
            if syswarden_capability_has_sys_admin "${{core_capability}}"; then
                return 85
            else
                core_capability_status=$?
                [ "${{core_capability_status}}" -eq 1 ] || return 85
            fi
            if syswarden_capability_has_sys_ptrace "${{core_capability}}"; then
                return 85
            else
                core_capability_status=$?
                [ "${{core_capability_status}}" -eq 1 ] || return 85
            fi
        done
        core_executable_path="$(readlink "/proc/${{core_pid}}/exe" 2>/dev/null || true)"
        [ "${{core_executable_path}}" = /opt/syswarden/bin/syswarden-core ] || return 81
        core_process_identity="$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${{core_pid}}/exe" 2>/dev/null || true)"
        core_installed_identity="$(stat -Lc '%d:%i:%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)"
        [ "$(stat -Lc '%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)" = 81e8:0:0 ] || return 81
        core_process_sha256="$(sha256sum "/proc/${{core_pid}}/exe" 2>/dev/null | awk '{{ print $1 }}')"
        core_installed_sha256="$(sha256sum /opt/syswarden/bin/syswarden-core 2>/dev/null | awk '{{ print $1 }}')"
        [ -n "${{core_process_identity}}" ] && \
            [ "${{core_process_identity}}" = "${{core_installed_identity}}" ] && \
            [ "${{core_process_sha256}}" = "${{core_installed_sha256}}" ] || return 81
        case "${{core_installed_sha256}}" in *[!0-9a-f]*|'') return 81 ;; esac
        [ "${{#core_installed_sha256}}" -eq 64 ] || return 81
        [ "$(readlink "/proc/${{core_pid}}/exe" 2>/dev/null || true)" = "${{core_executable_path}}" ] || return 81
        [ "$(stat -Lc '%d:%i:%f:%u:%g' "/proc/${{core_pid}}/exe" 2>/dev/null || true)" = "${{core_process_identity}}" ] || return 81
        [ "$(stat -Lc '%d:%i:%f:%u:%g' /opt/syswarden/bin/syswarden-core 2>/dev/null || true)" = "${{core_installed_identity}}" ] || return 81
        [ "$(sha256sum "/proc/${{core_pid}}/exe" 2>/dev/null | awk '{{ print $1 }}')" = "${{core_process_sha256}}" ] || return 81
        [ "$(sha256sum /opt/syswarden/bin/syswarden-core 2>/dev/null | awk '{{ print $1 }}')" = "${{core_installed_sha256}}" ] || return 81
        core_executable_identity="${{core_installed_identity}}|${{core_installed_sha256}}"
        if [ "${{syswarden_expected_manager}}" = openrc ]; then
            [ -f /run/syswarden-core.pid ] && [ ! -L /run/syswarden-core.pid ] || return 81
            [ "$(stat -c '%u:%g:%a' /run/syswarden-core.pid 2>/dev/null || true)" = 0:0:644 ] || return 81
            [ "$(wc -c < /run/syswarden-core.pid | tr -d ' ')" -le 32 ] || return 81
            [ "$(cat /run/syswarden-core.pid 2>/dev/null || true)" = "${{core_pid}}" ] || return 81
            core_pidfile_identity="$(stat -c '%d:%i:%s:%u:%g:%a' /run/syswarden-core.pid 2>/dev/null || true)"
            [ -n "${{core_pidfile_identity}}" ] || return 81
        else
            core_pidfile_identity=-
        fi
    elif [ "${{syswarden_expected_product_state}}" = absent ]; then
        attest_no_syswarden_core_runtime /proc /run/syswarden-core.pid || return 79
        for path in \
            /etc/systemd/system/syswarden-core.service \
            /etc/systemd/system/syswarden-firewall.service \
            /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
            /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
            /etc/init.d/syswarden-core \
            /etc/init.d/syswarden-firewall \
            /etc/runlevels/default/syswarden-core \
            /etc/runlevels/default/syswarden-firewall; do
            [ ! -e "${{path}}" ] && [ ! -L "${{path}}" ] || return 79
        done
        if [ "${{syswarden_expected_manager}}" = systemd ]; then
            systemctl is-active --quiet syswarden-core.service && return 79
            systemctl is-active --quiet syswarden-firewall.service && return 79
            systemctl is-enabled --quiet syswarden-core.service && return 79
            systemctl is-enabled --quiet syswarden-firewall.service && return 79
        else
            rc-service syswarden-core status >/dev/null 2>&1 && return 79
            rc-service syswarden-firewall status >/dev/null 2>&1 && return 79
        fi
        core_load=absent
        core_fragment=-
        core_enabled=disabled
        core_active=inactive
        core_pid=-
        core_executable_path=-
        core_executable_identity=-
        core_pidfile_identity=-
        core_cap_inh=-
        core_cap_prm=-
        core_cap_eff=-
        core_cap_bnd=-
        core_cap_amb=-
        core_nnp=-
        firewall_load=absent
        firewall_fragment=-
        firewall_enabled=disabled
        firewall_active=inactive
        firewall_pid=-
    else
        core_load=unasserted
        core_fragment=-
        core_enabled=unasserted
        core_active=unasserted
        core_pid=-
        core_executable_path=-
        core_executable_identity=-
        core_pidfile_identity=-
        core_cap_inh=-
        core_cap_prm=-
        core_cap_eff=-
        core_cap_bnd=-
        core_cap_amb=-
        core_nnp=-
        firewall_load=unasserted
        firewall_fragment=-
        firewall_enabled=unasserted
        firewall_active=unasserted
        firewall_pid=-
    fi
    printf '%s\t' \
        "${{pid1_comm}}" "${{pid1_exe}}" "${{pid1_starttime}}" \
        "${{pid1_cap_inh}}" "${{pid1_cap_prm}}" "${{pid1_cap_eff}}" \
        "${{pid1_cap_bnd}}" "${{pid1_cap_amb}}" "${{pid1_nnp}}" \
        "${{pid1_uid_map}}" "${{pid1_gid_map}}" \
        "${{setpriv_path}}" "${{setpriv_identity}}" "${{setpriv_sha256}}" \
        "${{setpriv_package_name}}" "${{setpriv_package_version}}" \
        "${{setpriv_package_architecture}}" "${{manager_state}}" \
        "${{manager_runtime}}" "${{cron_enabled}}" "${{cron_active}}" "${{cron_pid}}" \
        "${{cron_executable_path}}" "${{cron_executable_identity}}" "${{cron_fragment_path}}" \
        "${{cron_fragment_identity}}" "${{cron_dropin_output}}" \
        "${{cron_dropin_attestation}}" \
        "${{cron_package_name}}" "${{cron_package_version}}" "${{cron_package_architecture}}" \
        "${{cron_fragment_package_name}}" "${{cron_fragment_package_version}}" \
        "${{cron_fragment_package_architecture}}" \
        "${{rsyslog_enabled}}" "${{rsyslog_active}}" "${{rsyslog_pid}}" eth0:dummy:up \
        "${{syswarden_expected_product_state}}" "${{core_load}}" "${{core_fragment}}" "${{core_enabled}}" \
        "${{core_active}}" "${{core_pid}}" "${{core_executable_path}}" \
        "${{core_executable_identity}}" "${{core_pidfile_identity}}" \
        "${{core_cap_inh}}" "${{core_cap_prm}}" "${{core_cap_eff}}" \
        "${{core_cap_bnd}}" "${{core_cap_amb}}" "${{core_nnp}}" \
        "${{firewall_load}}" "${{firewall_fragment}}" \
        "${{firewall_enabled}}" "${{firewall_active}}" "${{firewall_pid}}"
    printf '%s\n' "{cron_service}"
}}
first="$(capture_snapshot)"
second="$(capture_snapshot)"
[ "${{first}}" = "${{second}}" ] || exit 80
printf '%s\n' "${{first}}"
"""


def parse_runtime_snapshot(
    output: str,
    spec: PlatformSpec,
    product_state: str,
    attestation_process_security: ProcessSecurityEvidence,
) -> RuntimeSnapshot:
    lines = output.splitlines()
    if len(lines) != 1:
        raise LifecycleLabError("runtime attestation did not emit exactly one record")
    fields = lines[0].split("\t")
    if len(fields) != 59:
        raise LifecycleLabError("runtime attestation field count is not exact")
    (
        pid1_comm,
        pid1_exe,
        starttime,
        pid1_cap_inh,
        pid1_cap_prm,
        pid1_cap_eff,
        pid1_cap_bnd,
        pid1_cap_amb,
        pid1_nnp,
        pid1_uid_map_raw,
        pid1_gid_map_raw,
        setpriv_path,
        setpriv_identity,
        setpriv_sha256,
        setpriv_package_name,
        setpriv_package_version,
        setpriv_package_architecture,
        manager_state,
        manager_runtime,
        cron_enabled,
        cron_active,
        cron_pid,
        cron_executable_path,
        cron_executable_identity,
        cron_fragment_path,
        cron_fragment_identity,
        cron_dropin_paths,
        cron_dropin_attestation,
        cron_package_name,
        cron_package_version,
        cron_package_architecture,
        cron_fragment_package_name,
        cron_fragment_package_version,
        cron_fragment_package_architecture,
        rsyslog_enabled,
        rsyslog_active,
        rsyslog_pid,
        dummy_interface,
        actual_product_state,
        core_load,
        core_fragment,
        core_enabled_state,
        core_active_state,
        core_pid,
        core_executable_path,
        core_executable_identity,
        core_pidfile_identity,
        core_cap_inh,
        core_cap_prm,
        core_cap_eff,
        core_cap_bnd,
        core_cap_amb,
        core_nnp,
        firewall_load,
        firewall_fragment,
        firewall_enabled_state,
        firewall_active_state,
        firewall_pid,
        cron_service,
    ) = fields
    expected_manager = "openrc" if spec.family == "apk" else "systemd"
    pid1_process_security = _process_security_from_fields(
        (
            pid1_cap_inh,
            pid1_cap_prm,
            pid1_cap_eff,
            pid1_cap_bnd,
            pid1_cap_amb,
            pid1_nnp,
        ),
        sys_admin_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if expected_manager == "systemd"
            else frozenset()
        ),
        sys_ptrace_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if expected_manager == "systemd"
            else frozenset()
        ),
        label=f"{spec.name} PID1",
    )
    pid1_uid_map = _parse_id_map(pid1_uid_map_raw, f"{spec.name} PID1 uid_map")
    pid1_gid_map = _parse_id_map(pid1_gid_map_raw, f"{spec.name} PID1 gid_map")
    if expected_manager == "systemd":
        if (
            setpriv_path != "/usr/bin/setpriv"
            or re.fullmatch(r"[0-9]+:[0-9]+:81ed:0:0", setpriv_identity)
            is None
            or re.fullmatch(r"[0-9a-f]{64}", setpriv_sha256) is None
            or setpriv_package_name != "util-linux"
            or re.fullmatch(
                r"[A-Za-z0-9.+:~_-]{1,128}", setpriv_package_version
            )
            is None
            or setpriv_package_architecture != spec.package_architecture
        ):
            raise LifecycleLabError("setpriv provenance evidence is not exact")
        setpriv = SetprivEvidence(
            path=setpriv_path,
            file_identity=setpriv_identity,
            sha256=setpriv_sha256,
            package_name=setpriv_package_name,
            package_version=setpriv_package_version,
            package_architecture=setpriv_package_architecture,
        )
    else:
        if {
            setpriv_path,
            setpriv_identity,
            setpriv_sha256,
            setpriv_package_name,
            setpriv_package_version,
            setpriv_package_architecture,
        } != {"-"}:
            raise LifecycleLabError("OpenRC snapshot carries setpriv provenance")
        setpriv = None
    expected_init = "openrc-init" if spec.family == "apk" else "systemd"
    expected_cron = (
        "cronie"
        if spec.family == "apk"
        else "cron.service" if spec.family == "deb" else "crond.service"
    )
    expected_cron_executable_path = expected_cron_executable(spec)
    expected_cron_fragments = (
        {"/etc/init.d/cronie"}
        if spec.family == "apk"
        else (
            {
                "/lib/systemd/system/cron.service",
                "/usr/lib/systemd/system/cron.service",
            }
            if spec.family == "deb"
            else {"/usr/lib/systemd/system/crond.service"}
        )
    )
    expected_cron_package = "cron" if spec.family == "deb" else "cronie"
    expected_cron_fragment_mode = "81ed" if spec.family == "apk" else "81a4"
    expected_cron_dropin_paths = (
        (FEDORA_CRON_DROPIN_PATH,) if spec.distribution == "fedora" else ()
    )
    expected_cron_dropin_value = (
        FEDORA_CRON_DROPIN_PATH if expected_cron_dropin_paths else "-"
    )
    if spec.distribution == "fedora":
        if re.fullmatch(
            rf"[0-9]+:[0-9]+:81a4:0:0\|[0-9a-f]{{64}}\|systemd\|"
            rf"[A-Za-z0-9.+:~_-]{{1,128}}\|"
            rf"{re.escape(spec.package_architecture)}\|8",
            cron_dropin_attestation,
        ) is None:
            raise LifecycleLabError("Fedora cron drop-in provenance is not exact")
    elif cron_dropin_attestation != "-":
        raise LifecycleLabError("non-Fedora snapshot carries cron drop-in provenance")
    if (
        pid1_comm != expected_init
        or manager_state != "ACTIVE"
        or manager_runtime != ("default" if expected_manager == "openrc" else "running")
        or cron_enabled != "enabled"
        or cron_active != "active"
        or cron_executable_path != expected_cron_executable_path
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81ed:0:0\|[0-9a-f]{64}",
            cron_executable_identity,
        )
        is None
        or cron_fragment_path not in expected_cron_fragments
        or re.fullmatch(
            rf"[0-9]+:[0-9]+:{expected_cron_fragment_mode}:0:0\|[0-9a-f]{{64}}",
            cron_fragment_identity,
        )
        is None
        or cron_dropin_paths != expected_cron_dropin_value
        or cron_package_name != expected_cron_package
        or re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", cron_package_version)
        is None
        or cron_package_architecture != spec.package_architecture
        or cron_fragment_package_name
        != ("cronie-openrc" if spec.family == "apk" else expected_cron_package)
        or cron_fragment_package_version != cron_package_version
        or cron_fragment_package_architecture != cron_package_architecture
        or rsyslog_enabled != "enabled"
        or rsyslog_active != "active"
        or dummy_interface != "eth0:dummy:up"
        or actual_product_state != product_state
        or cron_service != expected_cron
    ):
        raise LifecycleLabError("runtime attestation values differ from the ACTIVE contract")
    if expected_manager == "openrc":
        if pid1_exe != "/sbin/openrc-init":
            raise LifecycleLabError("OpenRC PID1 executable is not exact")
    elif pid1_exe not in {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}:
        raise LifecycleLabError("systemd PID1 executable is not exact")
    numeric = (starttime, cron_pid, rsyslog_pid)
    if any(not value.isdecimal() or int(value) <= 1 for value in numeric):
        raise LifecycleLabError("runtime PID/starttime evidence is invalid")
    for label, value in (("core", core_pid), ("firewall", firewall_pid)):
        if value != "-" and not value.isdecimal():
            raise LifecycleLabError(f"runtime {label} PID is not canonical")
    parsed_core: int | None = None if core_pid == "-" else int(core_pid)
    parsed_firewall: int | None = None if firewall_pid == "-" else int(firewall_pid)
    if product_state == "active":
        core_process_security = _process_security_from_fields(
            (
                core_cap_inh,
                core_cap_prm,
                core_cap_eff,
                core_cap_bnd,
                core_cap_amb,
                core_nnp,
            ),
            sys_admin_present=frozenset(),
            sys_ptrace_present=frozenset(),
            label=f"{spec.name} syswarden-core",
        )
    else:
        if {
            core_cap_inh,
            core_cap_prm,
            core_cap_eff,
            core_cap_bnd,
            core_cap_amb,
            core_nnp,
        } != {"-"}:
            raise LifecycleLabError("inactive core carries process security evidence")
        core_process_security = None
    expected_core_fragment = (
        "/etc/init.d/syswarden-core"
        if expected_manager == "openrc"
        else "/etc/systemd/system/syswarden-core.service"
    )
    expected_firewall_fragment = (
        "/etc/init.d/syswarden-firewall"
        if expected_manager == "openrc"
        else "/etc/systemd/system/syswarden-firewall.service"
    )
    if product_state == "active" and (
        core_load != "loaded"
        or core_fragment != expected_core_fragment
        or core_enabled_state != "enabled"
        or core_active_state != "active"
        or parsed_core is None
        or parsed_core <= 1
        or core_executable_path != "/opt/syswarden/bin/syswarden-core"
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81e8:0:0\|[0-9a-f]{64}",
            core_executable_identity,
        )
        is None
        or (
            expected_manager == "openrc"
            and re.fullmatch(
                r"[0-9]+:[0-9]+:[0-9]+:0:0:644", core_pidfile_identity
            )
            is None
        )
        or (expected_manager == "systemd" and core_pidfile_identity != "-")
        or firewall_load != "loaded"
        or firewall_fragment != expected_firewall_fragment
        or firewall_enabled_state != "enabled"
        or firewall_active_state != "active"
        or parsed_firewall is None
        or parsed_firewall != 0
    ):
        raise LifecycleLabError("active product service PID evidence is invalid")
    if product_state == "absent" and (
        core_load != "absent"
        or core_fragment != "-"
        or core_enabled_state != "disabled"
        or core_active_state != "inactive"
        or parsed_core is not None
        or core_executable_path != "-"
        or core_executable_identity != "-"
        or core_pidfile_identity != "-"
        or firewall_load != "absent"
        or firewall_fragment != "-"
        or firewall_enabled_state != "disabled"
        or firewall_active_state != "inactive"
        or parsed_firewall is not None
    ):
        raise LifecycleLabError("absent product service evidence carries PIDs")
    if product_state == "unasserted" and (
        core_load != "unasserted"
        or core_fragment != "-"
        or core_enabled_state != "unasserted"
        or core_active_state != "unasserted"
        or parsed_core is not None
        or core_executable_path != "-"
        or core_executable_identity != "-"
        or core_pidfile_identity != "-"
        or firewall_load != "unasserted"
        or firewall_fragment != "-"
        or firewall_enabled_state != "unasserted"
        or firewall_active_state != "unasserted"
        or parsed_firewall is not None
    ):
        raise LifecycleLabError("unasserted product service evidence carries PIDs")
    return RuntimeSnapshot(
        capture_count=2,
        pid1_comm=pid1_comm,
        pid1_exe=pid1_exe,
        pid1_starttime_ticks=int(starttime),
        pid1_process_security=pid1_process_security,
        attestation_process_security=attestation_process_security,
        pid1_uid_map=pid1_uid_map,
        pid1_gid_map=pid1_gid_map,
        setpriv=setpriv,
        manager_state=manager_state,
        manager_runtime=manager_runtime,
        cron_enabled=True,
        cron_active=True,
        cron_main_pid=int(cron_pid),
        cron_executable_path=cron_executable_path,
        cron_executable_identity=cron_executable_identity,
        cron_fragment_path=cron_fragment_path,
        cron_fragment_identity=cron_fragment_identity,
        cron_dropin_paths=expected_cron_dropin_paths,
        cron_package_name=cron_package_name,
        cron_package_version=cron_package_version,
        cron_package_architecture=cron_package_architecture,
        cron_fragment_package_name=cron_fragment_package_name,
        cron_fragment_package_version=cron_fragment_package_version,
        cron_fragment_package_architecture=cron_fragment_package_architecture,
        rsyslog_enabled=True,
        rsyslog_active=True,
        rsyslog_main_pid=int(rsyslog_pid),
        dummy_interface=dummy_interface,
        product_services=ProductServicesEvidence(
            expectation=actual_product_state,
            core_load_state=core_load,
            core_fragment_path=None if core_fragment == "-" else core_fragment,
            core_enabled_state=core_enabled_state,
            core_active_state=core_active_state,
            core_main_pid=parsed_core,
            core_executable_path=(
                None if core_executable_path == "-" else core_executable_path
            ),
            core_executable_identity=(
                None
                if core_executable_identity == "-"
                else core_executable_identity
            ),
            core_pidfile_identity=(
                None if core_pidfile_identity == "-" else core_pidfile_identity
            ),
            core_process_security=core_process_security,
            firewall_load_state=firewall_load,
            firewall_fragment_path=(
                None if firewall_fragment == "-" else firewall_fragment
            ),
            firewall_enabled_state=firewall_enabled_state,
            firewall_active_state=firewall_active_state,
            firewall_main_pid=parsed_firewall,
        ),
    )


def attest_runtime_snapshot(
    runner: CommandRunner,
    podman: str,
    name: str,
    spec: PlatformSpec,
    product_state: str,
    *,
    attempts: int = 30,
) -> RuntimeSnapshot:
    last_result: CommandResult | None = None
    for attempt in range(attempts):
        result = runner.run(
            lifecycle_exec_arguments(
                podman, name, spec, runtime_snapshot_script(spec, product_state)
            ),
            timeout=30,
        )
        last_result = result
        if result.returncode == 0:
            security, snapshot_output = parse_exec_security_output(
                result.stdout, f"{spec.name} runtime snapshot", spec
            )
            return parse_runtime_snapshot(
                snapshot_output, spec, product_state, security
            )
        if attempt + 1 < attempts:
            time.sleep(1)
    assert last_result is not None
    raise LifecycleLabError(
        "ACTIVE runtime attestation failed after bounded retries: "
        + command_log_tail(last_result)
    )


def _canonical_tmpfs_options(
    raw: object,
    *,
    expected_mode: str,
    expected_size: str,
    allow_tmpcopyup: bool,
) -> tuple[str, ...]:
    if not isinstance(raw, str):
        raise LifecycleLabError("container tmpfs options are not strings")
    tokens = set(raw.split(","))
    size_aliases = {
        expected_size,
        "size=" + str(int(expected_size.removeprefix("size=").removesuffix("m")) * 1024 * 1024),
    }
    observed_sizes = {token for token in tokens if token.startswith("size=")}
    if len(observed_sizes) != 1 or not observed_sizes.issubset(size_aliases):
        raise LifecycleLabError("container tmpfs size differs from the exact contract")
    tokens -= observed_sizes
    required = {"rw", "nodev", "nosuid", "exec", f"mode={expected_mode}"}
    allowed = required | {"rprivate"}
    if allow_tmpcopyup:
        allowed.add("tmpcopyup")
    elif "tmpcopyup" in tokens:
        raise LifecycleLabError("container /run tmpfs copy-up is not disabled")
    if not required.issubset(tokens) or not tokens.issubset(allowed):
        raise LifecycleLabError("container tmpfs options differ from the exact contract")
    return tuple(sorted(required | {expected_size}))


def inspect_container_isolation(
    runner: CommandRunner,
    podman: str,
    name: str,
    spec: PlatformSpec,
    *,
    candidate_root: Path,
    previous_root: Path,
    script_path: Path,
    helper_path: Path,
    result_root: Path,
) -> RuntimeIsolationEvidence:
    inspected = runner.run((podman, "inspect", name), timeout=30)
    require_success(inspected, f"inspect {spec.name} lifecycle container")
    try:
        documents = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise LifecycleLabError("container inspection is not valid JSON") from exc
    if (
        not isinstance(documents, list)
        or len(documents) != 1
        or not isinstance(documents[0], dict)
    ):
        raise LifecycleLabError("container inspection must contain exactly one object")
    document = documents[0]
    host = document.get("HostConfig")
    config = document.get("Config")
    mounts = document.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        raise LifecycleLabError("container inspection omits isolation objects")
    expected_caps = (
        {"CAP_NET_ADMIN", "CAP_SYS_BOOT"}
        if spec.family == "apk"
        else {"CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"}
    )
    cap_add = host.get("CapAdd")
    cap_drop = host.get("CapDrop")
    devices = host.get("Devices")
    security_opts = host.get("SecurityOpt")
    if (
        host.get("Privileged") is not False
        or host.get("NetworkMode") != "none"
        or host.get("PidMode") != "private"
        or host.get("IpcMode") != "private"
        or host.get("UTSMode") != "private"
        or host.get("CgroupMode") != "private"
        or host.get("UsernsMode") not in {"", None}
        or not isinstance(cap_add, list)
        or len(cap_add) != len(expected_caps)
        or set(cap_add) != expected_caps
        or not isinstance(cap_drop, list)
        or cap_drop
        or not isinstance(devices, list)
        or devices
        or not isinstance(security_opts, list)
        or set(security_opts) != {"label=disable", "no-new-privileges"}
    ):
        raise LifecycleLabError("container namespace/capability isolation is not exact")
    memory_limit = host.get("Memory")
    pids_limit = host.get("PidsLimit")
    if (
        type(memory_limit) is not int
        or memory_limit != 1_073_741_824
        or type(pids_limit) is not int
        or pids_limit != 512
    ):
        raise LifecycleLabError("container memory/PID limits are not exact")
    expected_stop = "SIGINT" if spec.family == "apk" else "SIGRTMIN+3"
    if config.get("StopSignal") != expected_stop:
        raise LifecycleLabError("container stop signal differs from the init contract")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/run", "/tmp"}:
        raise LifecycleLabError("container internal tmpfs inventory is not exact")
    canonical_tmpfs = {
        "/run": _canonical_tmpfs_options(
            tmpfs["/run"],
            expected_mode="755",
            expected_size="size=64m",
            allow_tmpcopyup=False,
        ),
        "/tmp": _canonical_tmpfs_options(
            tmpfs["/tmp"],
            expected_mode="1777",
            expected_size="size=256m",
            allow_tmpcopyup=True,
        ),
    }
    expected_mounts = {
        "/candidate": ("candidate", str(candidate_root), True),
        "/previous": ("previous", str(previous_root), True),
        "/lab/package-lifecycle.sh": ("script", str(script_path), True),
        "/lab/package-webtui-retirement.sh": ("helper", str(helper_path), True),
        "/results": ("results", str(result_root), False),
    }
    observed: dict[str, RuntimeMountEvidence] = {}
    for item in mounts:
        if not isinstance(item, dict):
            raise LifecycleLabError("container mount record is invalid")
        if item.get("Type") == "tmpfs":
            if item.get("Destination") not in {"/run", "/tmp"}:
                raise LifecycleLabError("container exposes an unexpected tmpfs")
            continue
        destination = item.get("Destination")
        if item.get("Type") != "bind" or destination not in expected_mounts:
            raise LifecycleLabError("container exposes an unexpected host mount")
        role, expected_source, read_only = expected_mounts[str(destination)]
        if (
            item.get("Source") != expected_source
            or item.get("RW") is not (not read_only)
            or destination in observed
        ):
            raise LifecycleLabError("container bind mount differs from the exact contract")
        observed[str(destination)] = RuntimeMountEvidence(
            role=role,
            destination=str(destination),
            read_only=read_only,
        )
    if set(observed) != set(expected_mounts):
        raise LifecycleLabError("container bind mount inventory is incomplete")
    return RuntimeIsolationEvidence(
        privileged=False,
        network_mode="none",
        pid_mode="private",
        ipc_mode="private",
        uts_mode="private",
        userns_mode="rootless-default",
        cgroup_mode="private",
        cap_add=tuple(sorted(expected_caps)),
        cap_drop=(),
        lifecycle_exec_launcher=(
            ("/bin/sh", "-ceu")
            if spec.family == "apk"
            else SYSTEMD_EXEC_LAUNCHER
        ),
        devices=(),
        security_opts=tuple(sorted({"label=disable", "no-new-privileges"})),
        stop_signal=expected_stop,
        tmpfs=canonical_tmpfs,
        mounts=tuple(observed[path] for path in expected_mounts),
    )


def _json_dataclass_evidence(value: object) -> dict[str, object]:
    rendered = json.loads(json.dumps(asdict(value), sort_keys=True))
    if not isinstance(rendered, dict):
        raise LifecycleLabError("runtime evidence did not serialize as an object")
    return rendered


def _scenario_invocations(scenario: str) -> tuple[str, ...]:
    if scenario == "upgrade-rollback":
        return ("initial", "restart-one", "restart-two")
    if scenario in {"remove", "purge"}:
        return ("initial",)
    raise LifecycleLabError(f"unsupported lifecycle scenario {scenario!r}")


def _restart_state_allows_continuation(result_root: Path) -> bool:
    restart_state = result_root / "restart-state"
    try:
        metadata = restart_state.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return False
        return restart_state.read_text(encoding="utf-8").strip() in {
            "restart-one",
            "restart-two",
        }
    except OSError:
        return False


def _observed_restart_state(result_root: Path, scenario: str) -> str | None:
    restart_state = result_root / "restart-state"
    try:
        metadata = restart_state.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LifecycleLabError("cannot inspect restart-state evidence") from exc
    try:
        value = restart_state.read_text(encoding="utf-8")
    except OSError as exc:
        raise LifecycleLabError("cannot read restart-state evidence") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or value not in {"restart-one\n", "restart-two\n", "complete\n"}
    ):
        raise LifecycleLabError(f"{scenario} restart-state evidence is not exact")
    return value.strip()


def _final_restart_state(result_root: Path, scenario: str) -> str | None:
    value = _observed_restart_state(result_root, scenario)
    if scenario != "upgrade-rollback":
        if value is not None:
            raise LifecycleLabError(
                f"{scenario} unexpectedly produced restart-state evidence"
            )
        return None
    if value is None:
        raise LifecycleLabError(
            "upgrade-rollback lacks final restart-state evidence"
        )
    if value != "complete":
        raise LifecycleLabError(
            "upgrade-rollback final restart-state evidence is not exact"
        )
    return "complete"


def run_platform(
    runner: CommandRunner,
    podman: str,
    spec: PlatformSpec,
    pair: PackagePair,
    candidate_root: Path,
    previous_root: Path,
    workspace: Path,
    helper_path: Path,
    pull_policy: str,
    timeout: int,
    host_architecture: str,
) -> dict[str, object]:
    slug = platform_slug(spec)
    platform_result: dict[str, object] = {
        "cell_id": spec.cell_id,
        "version": spec.version,
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
        "bootstrap_execution": "native_container_build",
        "lifecycle_network": "disabled",
        "runtime_mode": "active-real-init",
        "restart_contract": ACTIVE_RESTART_CONTRACT,
        "scenarios": [],
    }
    image_tag = f"localhost/syswarden-lifecycle-{slug}-{uuid.uuid4().hex}"
    historical_image_tag = f"{image_tag}-historical-upgrade"
    context = workspace / f"build-{slug}"
    context.mkdir(mode=0o700)
    containerfile = context / "Containerfile"
    containerfile.write_text(build_containerfile(spec), encoding="utf-8")
    containerfile.chmod(0o600)
    historical_containerfile_text = (
        build_historical_transition_containerfile(
            spec,
            pair.previous.version,
            image_tag,
        )
        if "upgrade-rollback" in spec.scenarios
        else None
    )
    historical_context: Path | None = None
    historical_containerfile: Path | None = None
    image_tags = [image_tag]
    if historical_containerfile_text is not None:
        historical_context = workspace / f"build-{slug}-historical-upgrade"
        historical_context.mkdir(mode=0o700)
        historical_containerfile = historical_context / "Containerfile"
        historical_containerfile.write_text(
            historical_containerfile_text, encoding="utf-8"
        )
        historical_containerfile.chmod(0o600)
        image_tags.append(historical_image_tag)
    image_cleanup_failed = False

    try:
        ensure_image(runner, podman, spec, pull_policy)
        architecture_probe = probe_platform_execution(
            runner,
            podman,
            spec,
            host_architecture,
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
        if historical_containerfile is not None and historical_context is not None:
            historical_build = runner.run(
                (
                    podman,
                    "build",
                    "--pull=never",
                    "--layers=false",
                    "--platform",
                    spec.podman_platform,
                    "--tag",
                    historical_image_tag,
                    "--file",
                    str(historical_containerfile),
                    str(historical_context),
                ),
                timeout=900,
            )
            require_success(
                historical_build,
                f"bootstrap {spec.name} historical upgrade lifecycle image",
            )

        script_path = workspace / "package-lifecycle.sh"
        for scenario in spec.scenarios:
            result_root = workspace / f"result-{slug}-{scenario}"
            result_root.mkdir(mode=0o700)
            container_name = (
                f"syswarden-lifecycle-{slug}-{uuid.uuid4().hex[:12]}"
            )
            run_args = container_run_arguments(
                podman,
                (
                    historical_image_tag
                    if scenario == "upgrade-rollback"
                    and historical_containerfile is not None
                    else image_tag
                ),
                container_name,
                candidate_root,
                previous_root,
                script_path,
                helper_path,
                result_root,
                spec,
                scenario,
                pair,
            )
            created = runner.run(run_args, timeout=60)
            last_command = created
            isolation: RuntimeIsolationEvidence | None = None
            boot_evidence: list[dict[str, object]] = []
            executed_exit_codes: list[int] = []
            orchestration_error: str | None = None
            try:
                if created.returncode != 0:
                    raise LifecycleLabError(
                        f"create {spec.name} {scenario} container failed with "
                        f"exit code {created.returncode}: {command_log_tail(created)}"
                    )
                isolation = inspect_container_isolation(
                    runner,
                    podman,
                    container_name,
                    spec,
                    candidate_root=candidate_root,
                    previous_root=previous_root,
                    script_path=script_path,
                    helper_path=helper_path,
                    result_root=result_root,
                )
                previous_starttime: int | None = None
                for invocation in _scenario_invocations(scenario):
                    if invocation == "initial":
                        boot_result = runner.run(
                            (podman, "start", container_name), timeout=60
                        )
                        restart = RuntimeRestartEvidence(
                            performed=False,
                            command_exit_code=None,
                            previous_pid1_starttime_ticks=None,
                            distinct=None,
                        )
                    else:
                        boot_result = runner.run(
                            (podman, "restart", "--time", "10", container_name),
                            timeout=60,
                        )
                        restart = RuntimeRestartEvidence(
                            performed=True,
                            command_exit_code=boot_result.returncode,
                            previous_pid1_starttime_ticks=previous_starttime,
                            distinct=None,
                        )
                    last_command = boot_result
                    boot_record: dict[str, object] = {
                        "invocation": invocation,
                        "boot_command_exit_code": boot_result.returncode,
                        "restart": _json_dataclass_evidence(restart),
                        "pre_exec": None,
                        "lifecycle_exec_security": None,
                        "script_exec_exit_code": None,
                        "restart_state": None,
                        "post_exec": None,
                    }
                    boot_evidence.append(boot_record)
                    require_success(
                        boot_result,
                        f"{invocation} boot for {spec.name} {scenario}",
                    )
                    attest_runtime_namespace(runner, podman, container_name, spec)
                    pre_state = "absent" if invocation == "initial" else "active"
                    pre_exec = attest_runtime_snapshot(
                        runner, podman, container_name, spec, pre_state
                    )
                    boot_record["pre_exec"] = _json_dataclass_evidence(pre_exec)
                    if invocation != "initial":
                        if previous_starttime is None:
                            raise LifecycleLabError(
                                "restart lacks the previous PID1 starttime"
                            )
                        distinct = pre_exec.pid1_starttime_ticks != previous_starttime
                        if not distinct:
                            raise LifecycleLabError(
                                "real container restart did not replace PID1"
                            )
                        restart = RuntimeRestartEvidence(
                            performed=True,
                            command_exit_code=boot_result.returncode,
                            previous_pid1_starttime_ticks=previous_starttime,
                            distinct=True,
                        )
                        boot_record["restart"] = _json_dataclass_evidence(restart)
                    executed = runner.run(
                        lifecycle_exec_arguments(
                            podman,
                            container_name,
                            spec,
                            "exec /bin/sh /lab/package-lifecycle.sh",
                        ),
                        timeout=timeout,
                    )
                    last_command = executed
                    lifecycle_exec_security, _ = parse_exec_security_output(
                        executed.stdout,
                        f"{spec.name} {scenario} {invocation} lifecycle exec",
                        spec,
                    )
                    boot_record["lifecycle_exec_security"] = (
                        _json_dataclass_evidence(lifecycle_exec_security)
                    )
                    executed_exit_codes.append(executed.returncode)
                    boot_record["script_exec_exit_code"] = executed.returncode
                    observed_restart_state = _observed_restart_state(
                        result_root, scenario
                    )
                    boot_record["restart_state"] = observed_restart_state
                    if scenario != "upgrade-rollback" and observed_restart_state is not None:
                        raise LifecycleLabError(
                            f"{scenario} unexpectedly produced restart-state evidence"
                        )
                    attest_runtime_namespace(
                        runner, podman, container_name, spec
                    )
                    post_state = (
                        "active"
                        if executed.returncode == 0 and scenario == "upgrade-rollback"
                        else "absent"
                        if executed.returncode == 0
                        else "unasserted"
                    )
                    post_exec = attest_runtime_snapshot(
                        runner, podman, container_name, spec, post_state
                    )
                    boot_record["post_exec"] = _json_dataclass_evidence(post_exec)
                    if (
                        pre_exec.pid1_starttime_ticks
                        != post_exec.pid1_starttime_ticks
                    ):
                        raise LifecycleLabError(
                            "PID1 changed during a lifecycle script execution"
                        )
                    if pre_exec.cron_main_pid != post_exec.cron_main_pid:
                        raise LifecycleLabError(
                            "cron provider changed during a lifecycle script execution"
                        )
                    previous_starttime = post_exec.pid1_starttime_ticks
                    if executed.returncode != 0 and not (
                        scenario == "upgrade-rollback"
                        and _restart_state_allows_continuation(result_root)
                    ):
                        break
            except LifecycleLabError as exc:
                orchestration_error = str(exc)
            finally:
                cleanup_result = runner.run(
                    (podman, "rm", "--force", container_name), timeout=30
                )
                cleanup_exists = runner.run(
                    (podman, "container", "exists", container_name), timeout=30
                )
                cleanup_evidence = {
                    "remove_exit_code": cleanup_result.returncode,
                    "exists_probe_exit_code": cleanup_exists.returncode,
                    "absent_after_cleanup": cleanup_exists.returncode == 1,
                }
                if cleanup_result.returncode != 0 or cleanup_exists.returncode != 1:
                    cleanup_error = (
                        "container cleanup did not attest exact object absence: "
                        f"rm={cleanup_result.returncode}, "
                        f"exists={cleanup_exists.returncode}"
                    )
                    orchestration_error = (
                        f"{orchestration_error}; {cleanup_error}"
                        if orchestration_error is not None
                        else cleanup_error
                    )

            event_file = result_root / "events.tsv"
            command_log = result_root / "commands.log"
            try:
                events = parse_events(event_file)
                validate_event_contract(
                    events,
                    spec.family,
                    scenario,
                    candidate_version=pair.candidate.version,
                )
                inventory_evidence = parse_scenario_inventory_evidence(
                    result_root,
                    spec.family,
                    scenario,
                    previous_version=pair.previous.version,
                    candidate_version=pair.candidate.version,
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
            try:
                restart_state = _final_restart_state(result_root, scenario)
            except LifecycleLabError as exc:
                restart_state = None
                orchestration_error = (
                    f"{orchestration_error}; {exc}"
                    if orchestration_error is not None
                    else str(exc)
                )
            required_boots = len(_scenario_invocations(scenario))
            scenario_status = (
                "pass"
                if created.returncode == 0
                and orchestration_error is None
                and isolation is not None
                and len(boot_evidence) == required_boots
                and len(executed_exit_codes) == required_boots
                and all(code == 0 for code in executed_exit_codes)
                and all(item.get("post_exec") is not None for item in boot_evidence)
                and not failed
                else "fail"
            )
            platform_result["scenarios"].append(
                {
                    "name": scenario,
                    "status": scenario_status,
                    "runtime_mode": "active-real-init",
                    "container_create_exit_code": created.returncode,
                    "lifecycle_exec_exit_codes": executed_exit_codes,
                    "restart_state": restart_state,
                    "boots": boot_evidence,
                    "isolation": (
                        _json_dataclass_evidence(isolation)
                        if isolation is not None
                        else None
                    ),
                    "cleanup": cleanup_evidence,
                    "orchestration_error": orchestration_error,
                    "events": events,
                    "inventory_evidence": inventory_evidence,
                    "log_tail": command_log_tail(last_command, command_log),
                }
            )
    except LifecycleLabError as exc:
        platform_result["status"] = "fail"
        platform_result["error"] = str(exc)
        return platform_result
    finally:
        cleanup_results: list[tuple[int, int]] = []
        for cleanup_tag in reversed(image_tags):
            image_cleanup = runner.run(
                (podman, "image", "rm", "--force", cleanup_tag), timeout=120
            )
            image_exists = runner.run(
                (podman, "image", "exists", cleanup_tag), timeout=30
            )
            cleanup_results.append(
                (image_cleanup.returncode, image_exists.returncode)
            )
        cleanup_remove_exit = next(
            (remove for remove, _ in cleanup_results if remove != 0), 0
        )
        cleanup_exists_exit = next(
            (exists for _, exists in cleanup_results if exists != 1), 1
        )
        cleanup_absent = all(
            remove == 0 and exists == 1
            for remove, exists in cleanup_results
        )
        platform_result["bootstrap_image_cleanup"] = {
            "remove_exit_code": cleanup_remove_exit,
            "exists_probe_exit_code": cleanup_exists_exit,
            "absent_after_cleanup": cleanup_absent,
        }
        if not cleanup_absent:
            image_cleanup_failed = True
            cleanup_error = (
                "bootstrap image cleanup did not attest exact object absence: "
                f"rm={cleanup_remove_exit}, exists={cleanup_exists_exit}"
            )
            existing_error = platform_result.get("error")
            platform_result["error"] = (
                f"{existing_error}; {cleanup_error}"
                if isinstance(existing_error, str) and existing_error
                else cleanup_error
            )
            platform_result["status"] = "fail"

    scenarios = platform_result["scenarios"]
    platform_result["status"] = (
        "pass"
        if not image_cleanup_failed
        and scenarios
        and all(item["status"] == "pass" for item in scenarios)
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


def historical_ubuntu_deb_recovery_report_contract(
    platform_result: dict[str, object],
) -> tuple[bool, list[str]]:
    if not (
        platform_result.get("family") == "deb"
        and platform_result.get("distribution") == "ubuntu"
        and platform_result.get("architecture_id") == "amd64"
        and platform_result.get("package_architecture") == "amd64"
    ):
        return False, []
    previous = platform_result.get("previous")
    candidate = platform_result.get("candidate")
    if not isinstance(previous, dict) or not isinstance(candidate, dict):
        return False, ["historical-ubuntu-deb-artifact-binding-absent"]
    expected = HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS
    candidate_filename = (
        f"syswarden_{HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION}_amd64.deb"
    )
    historical_binding_touched = (
        previous.get("version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION
        or previous.get("filename") == expected["filename"]
        or previous.get("sha256") == expected["sha256"]
        or candidate.get("version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
        or candidate.get("filename") == candidate_filename
        or platform_result.get("previous_version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION
        or platform_result.get("candidate_version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
    )
    candidate_sha256 = candidate.get("sha256")
    exact = (
        historical_binding_touched
        and previous
        == {
            "filename": expected["filename"],
            "version": HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION,
            "sha256": expected["sha256"],
        }
        and candidate.get("filename") == candidate_filename
        and candidate.get("version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
        and isinstance(candidate_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is not None
        and platform_result.get("previous_version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_PREVIOUS_VERSION
        and platform_result.get("candidate_version")
        == HISTORICAL_UBUNTU_DEB_RECOVERY_CANDIDATE_VERSION
    )
    if historical_binding_touched and not exact:
        return False, ["historical-ubuntu-deb-binding-not-exact"]
    return exact, []


def validate_historical_ubuntu_deb_recovery_events(
    platform_result: dict[str, object], scenario_result: dict[str, object]
) -> list[str]:
    exact, problems = historical_ubuntu_deb_recovery_report_contract(
        platform_result
    )
    if scenario_result.get("name") != "upgrade-rollback":
        return problems
    events = scenario_result.get("events")
    if not isinstance(events, list):
        return problems + ["historical-ubuntu-deb-events-absent"]
    by_check = {
        item.get("check"): item
        for item in events
        if isinstance(item, dict) and isinstance(item.get("check"), str)
    }
    rollback_check = "upgrade-rollback.rollback.previous"
    rollback = by_check.get(rollback_check)
    recovery_used = (
        isinstance(rollback, dict)
        and rollback.get("detail") == HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL
    )
    if exact and (
        not isinstance(rollback, dict)
        or rollback.get("status") != "pass"
        or rollback.get("detail")
        not in {"command completed", HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL}
    ):
        problems.append("historical-ubuntu-deb-rollback-detail-invalid")
    if not recovery_used:
        return problems
    if not exact:
        return problems + ["historical-ubuntu-deb-recovery-binding-not-exact"]
    expected_details = {
        rollback_check: HISTORICAL_UBUNTU_DEB_RECOVERY_DETAIL,
        "upgrade-rollback.rollback.previous.maintainer_script": (
            "maintainer script emitted no Go panic or fatal runtime diagnostic"
        ),
        "upgrade-rollback.recovery.candidate": "command completed",
        "upgrade-rollback.recovery.candidate.maintainer_script": (
            "maintainer script emitted no Go panic or fatal runtime diagnostic"
        ),
    }
    return [
        f"historical-ubuntu-deb-evidence-mismatch:{check}"
        for check, detail in expected_details.items()
        if by_check.get(check)
        != {"status": "pass", "check": check, "detail": detail}
    ]


def _platform_spec_from_result(platform_result: dict[str, object]) -> PlatformSpec:
    matches = [
        spec
        for spec in DEFAULT_PLATFORMS
        if spec.cell_id == platform_result.get("cell_id")
        and spec.version == platform_result.get("version")
        and spec.distribution == platform_result.get("distribution")
        and spec.architecture == platform_result.get("architecture_id")
        and spec.family == platform_result.get("family")
    ]
    if len(matches) != 1:
        raise LifecycleLabError("runtime platform identity is not exact")
    return matches[0]


PROCESS_SECURITY_KEYS = {
    "cap_inheritable",
    "cap_permitted",
    "cap_effective",
    "cap_bounding",
    "cap_ambient",
    "no_new_privileges",
}
ID_MAP_RANGE_KEYS = {"inside_id", "outside_id", "length"}
SETPRIV_EVIDENCE_KEYS = {
    "path",
    "file_identity",
    "sha256",
    "package_name",
    "package_version",
    "package_architecture",
}


def _validate_process_security_evidence(
    value: object,
    *,
    sys_admin_present: frozenset[str],
    sys_ptrace_present: frozenset[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != PROCESS_SECURITY_KEYS:
        raise LifecycleLabError(f"{label} process security schema is not exact")
    if type(value.get("no_new_privileges")) is not bool:
        raise LifecycleLabError(f"{label} NoNewPrivs type is not exact")
    evidence = ProcessSecurityEvidence(
        cap_inheritable=str(value.get("cap_inheritable")),
        cap_permitted=str(value.get("cap_permitted")),
        cap_effective=str(value.get("cap_effective")),
        cap_bounding=str(value.get("cap_bounding")),
        cap_ambient=str(value.get("cap_ambient")),
        no_new_privileges=bool(value.get("no_new_privileges")),
    )
    _validate_process_security(
        evidence,
        sys_admin_present=sys_admin_present,
        sys_ptrace_present=sys_ptrace_present,
        label=label,
    )
    return value


def _validate_id_map_evidence(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise LifecycleLabError(f"{label} must be an array")
    rendered: list[str] = []
    for record in value:
        if not isinstance(record, dict) or set(record) != ID_MAP_RANGE_KEYS:
            raise LifecycleLabError(f"{label} range schema is not exact")
        if any(type(record.get(key)) is not int for key in ID_MAP_RANGE_KEYS):
            raise LifecycleLabError(f"{label} range types are not exact")
        rendered.append(
            f"{record['inside_id']}:{record['outside_id']}:{record['length']}"
        )
    _parse_id_map(",".join(rendered), label)
    return value


def _validate_setpriv_evidence(
    value: object, spec: PlatformSpec, label: str
) -> dict[str, object] | None:
    if spec.family == "apk":
        if value is not None:
            raise LifecycleLabError(f"{label} OpenRC snapshot carries setpriv")
        return None
    if not isinstance(value, dict) or set(value) != SETPRIV_EVIDENCE_KEYS:
        raise LifecycleLabError(f"{label} setpriv schema is not exact")
    if (
        value.get("path") != "/usr/bin/setpriv"
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81ed:0:0", str(value.get("file_identity"))
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
        or value.get("package_name") != "util-linux"
        or re.fullmatch(
            r"[A-Za-z0-9.+:~_-]{1,128}", str(value.get("package_version"))
        )
        is None
        or value.get("package_architecture") != spec.package_architecture
    ):
        raise LifecycleLabError(f"{label} setpriv provenance is not exact")
    return value


def _validate_product_services_evidence(
    value: object, spec: PlatformSpec, expectation: str
) -> None:
    keys = {
        "expectation",
        "core_load_state",
        "core_fragment_path",
        "core_enabled_state",
        "core_active_state",
        "core_main_pid",
        "core_executable_path",
        "core_executable_identity",
        "core_pidfile_identity",
        "core_process_security",
        "firewall_load_state",
        "firewall_fragment_path",
        "firewall_enabled_state",
        "firewall_active_state",
        "firewall_main_pid",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleLabError("product service runtime evidence schema is not exact")
    if value.get("expectation") != expectation:
        raise LifecycleLabError("product service runtime expectation is inconsistent")
    if expectation == "active":
        core_fragment = (
            "/etc/init.d/syswarden-core"
            if spec.family == "apk"
            else "/etc/systemd/system/syswarden-core.service"
        )
        firewall_fragment = (
            "/etc/init.d/syswarden-firewall"
            if spec.family == "apk"
            else "/etc/systemd/system/syswarden-firewall.service"
        )
        expected = {
            "core_load_state": "loaded",
            "core_fragment_path": core_fragment,
            "core_enabled_state": "enabled",
            "core_active_state": "active",
            "firewall_load_state": "loaded",
            "firewall_fragment_path": firewall_fragment,
            "firewall_enabled_state": "enabled",
            "firewall_active_state": "active",
            "firewall_main_pid": 0,
        }
        if any(value.get(key) != item for key, item in expected.items()):
            raise LifecycleLabError("active product service evidence is not exact")
        core_pid = value.get("core_main_pid")
        if type(core_pid) is not int or core_pid <= 1:
            raise LifecycleLabError("active core service PID evidence is invalid")
        if (
            value.get("core_executable_path")
            != "/opt/syswarden/bin/syswarden-core"
            or not isinstance(value.get("core_executable_identity"), str)
            or re.fullmatch(
                r"[0-9]+:[0-9]+:81e8:0:0\|[0-9a-f]{64}",
                str(value.get("core_executable_identity")),
            )
            is None
            or (
                spec.family == "apk"
                and re.fullmatch(
                    r"[0-9]+:[0-9]+:[0-9]+:0:0:644",
                    str(value.get("core_pidfile_identity")),
                )
                is None
            )
            or (
                spec.family != "apk"
                and value.get("core_pidfile_identity") is not None
            )
        ):
            raise LifecycleLabError("active core executable identity is invalid")
        _validate_process_security_evidence(
            value.get("core_process_security"),
            sys_admin_present=frozenset(),
            sys_ptrace_present=frozenset(),
            label="active syswarden-core",
        )
        return
    if expectation != "absent":
        raise LifecycleLabError("passing runtime evidence cannot be unasserted")
    expected_absent = {
        "core_load_state": "absent",
        "core_fragment_path": None,
        "core_enabled_state": "disabled",
        "core_active_state": "inactive",
        "core_main_pid": None,
        "core_executable_path": None,
        "core_executable_identity": None,
        "core_pidfile_identity": None,
        "core_process_security": None,
        "firewall_load_state": "absent",
        "firewall_fragment_path": None,
        "firewall_enabled_state": "disabled",
        "firewall_active_state": "inactive",
        "firewall_main_pid": None,
    }
    if any(value.get(key) != item for key, item in expected_absent.items()):
        raise LifecycleLabError("absent product service evidence is not exact")


def _validate_runtime_snapshot_evidence(
    value: object,
    spec: PlatformSpec,
    expectation: str,
    *,
    expected_uid_map: list[dict[str, object]] | None = None,
    expected_gid_map: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    keys = {
        "capture_count",
        "pid1_comm",
        "pid1_exe",
        "pid1_starttime_ticks",
        "pid1_process_security",
        "attestation_process_security",
        "pid1_uid_map",
        "pid1_gid_map",
        "setpriv",
        "manager_state",
        "manager_runtime",
        "cron_enabled",
        "cron_active",
        "cron_main_pid",
        "cron_executable_path",
        "cron_executable_identity",
        "cron_fragment_path",
        "cron_fragment_identity",
        "cron_dropin_paths",
        "cron_package_name",
        "cron_package_version",
        "cron_package_architecture",
        "cron_fragment_package_name",
        "cron_fragment_package_version",
        "cron_fragment_package_architecture",
        "rsyslog_enabled",
        "rsyslog_active",
        "rsyslog_main_pid",
        "dummy_interface",
        "product_services",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleLabError("runtime snapshot schema is not exact")
    manager = "openrc" if spec.family == "apk" else "systemd"
    _validate_process_security_evidence(
        value.get("pid1_process_security"),
        sys_admin_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if manager == "systemd"
            else frozenset()
        ),
        sys_ptrace_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if manager == "systemd"
            else frozenset()
        ),
        label="runtime PID1",
    )
    _validate_process_security_evidence(
        value.get("attestation_process_security"),
        sys_admin_present=frozenset(),
        sys_ptrace_present=(
            SYSTEMD_MANAGER_CAPABILITY_FIELDS
            if manager == "systemd"
            else frozenset()
        ),
        label="runtime attestation exec",
    )
    uid_map = _validate_id_map_evidence(
        value.get("pid1_uid_map"), "runtime PID1 uid_map"
    )
    gid_map = _validate_id_map_evidence(
        value.get("pid1_gid_map"), "runtime PID1 gid_map"
    )
    if (
        (expected_uid_map is not None and uid_map != expected_uid_map)
        or (expected_gid_map is not None and gid_map != expected_gid_map)
    ):
        raise LifecycleLabError(
            "runtime PID1 identity maps differ from the native Podman engine"
        )
    _validate_setpriv_evidence(value.get("setpriv"), spec, "runtime snapshot")
    init_comm = "openrc-init" if spec.family == "apk" else "systemd"
    init_executables = (
        {"/sbin/openrc-init"}
        if spec.family == "apk"
        else {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}
    )
    expected_cron_executable_path = expected_cron_executable(spec)
    expected_cron_fragments = (
        {"/etc/init.d/cronie"}
        if spec.family == "apk"
        else (
            {
                "/lib/systemd/system/cron.service",
                "/usr/lib/systemd/system/cron.service",
            }
            if spec.family == "deb"
            else {"/usr/lib/systemd/system/crond.service"}
        )
    )
    expected_cron_fragment_mode = "81ed" if spec.family == "apk" else "81a4"
    expected_cron_dropin_paths = (
        [FEDORA_CRON_DROPIN_PATH] if spec.distribution == "fedora" else []
    )
    if (
        value.get("capture_count") != 2
        or value.get("pid1_comm") != init_comm
        or value.get("pid1_exe") not in init_executables
        or value.get("manager_state") != "ACTIVE"
        or value.get("manager_runtime")
        != ("default" if manager == "openrc" else "running")
        or value.get("cron_enabled") is not True
        or value.get("cron_active") is not True
        or value.get("cron_executable_path") != expected_cron_executable_path
        or not isinstance(value.get("cron_executable_identity"), str)
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81ed:0:0\|[0-9a-f]{64}",
            str(value.get("cron_executable_identity")),
        )
        is None
        or value.get("cron_fragment_path") not in expected_cron_fragments
        or not isinstance(value.get("cron_fragment_identity"), str)
        or re.fullmatch(
            rf"[0-9]+:[0-9]+:{expected_cron_fragment_mode}:0:0\|[0-9a-f]{{64}}",
            str(value.get("cron_fragment_identity")),
        )
        is None
        or value.get("cron_dropin_paths") != expected_cron_dropin_paths
        or value.get("cron_package_name")
        != ("cron" if spec.family == "deb" else "cronie")
        or not isinstance(value.get("cron_package_version"), str)
        or re.fullmatch(
            r"[A-Za-z0-9.+:~_-]{1,128}",
            str(value.get("cron_package_version")),
        )
        is None
        or value.get("cron_package_architecture") != spec.package_architecture
        or value.get("cron_fragment_package_name")
        != ("cronie-openrc" if spec.family == "apk" else (
            "cron" if spec.family == "deb" else "cronie"
        ))
        or value.get("cron_fragment_package_version")
        != value.get("cron_package_version")
        or value.get("cron_fragment_package_architecture")
        != value.get("cron_package_architecture")
        or value.get("rsyslog_enabled") is not True
        or value.get("rsyslog_active") is not True
        or value.get("dummy_interface") != "eth0:dummy:up"
    ):
        raise LifecycleLabError("runtime snapshot ACTIVE values are not exact")
    for key in (
        "pid1_starttime_ticks",
        "cron_main_pid",
        "rsyslog_main_pid",
    ):
        if type(value.get(key)) is not int or int(value[key]) <= 1:
            raise LifecycleLabError(f"runtime snapshot {key} is invalid")
    _validate_product_services_evidence(
        value.get("product_services"), spec, expectation
    )
    return value


def _validate_runtime_isolation_evidence(
    value: object, spec: PlatformSpec
) -> None:
    keys = {
        "privileged",
        "network_mode",
        "pid_mode",
        "ipc_mode",
        "uts_mode",
        "userns_mode",
        "cgroup_mode",
        "cap_add",
        "cap_drop",
        "lifecycle_exec_launcher",
        "devices",
        "security_opts",
        "stop_signal",
        "tmpfs",
        "mounts",
    }
    expected_caps = (
        ["CAP_NET_ADMIN", "CAP_SYS_BOOT"]
        if spec.family == "apk"
        else ["CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
    )
    expected_launcher = (
        ["/bin/sh", "-ceu"]
        if spec.family == "apk"
        else list(SYSTEMD_EXEC_LAUNCHER)
    )
    expected_tmpfs = {
        "/run": sorted(
            {"rw", "nodev", "nosuid", "exec", "mode=755", "size=64m"}
        ),
        "/tmp": sorted(
            {"rw", "nodev", "nosuid", "exec", "mode=1777", "size=256m"}
        ),
    }
    expected_mounts = [
        {"role": "candidate", "destination": "/candidate", "read_only": True},
        {"role": "previous", "destination": "/previous", "read_only": True},
        {
            "role": "script",
            "destination": "/lab/package-lifecycle.sh",
            "read_only": True,
        },
        {
            "role": "helper",
            "destination": "/lab/package-webtui-retirement.sh",
            "read_only": True,
        },
        {"role": "results", "destination": "/results", "read_only": False},
    ]
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value.get("privileged") is not False
        or value.get("network_mode") != "none"
        or value.get("pid_mode") != "private"
        or value.get("ipc_mode") != "private"
        or value.get("uts_mode") != "private"
        or value.get("userns_mode") != "rootless-default"
        or value.get("cgroup_mode") != "private"
        or value.get("cap_add") != expected_caps
        or value.get("cap_drop") != []
        or value.get("lifecycle_exec_launcher") != expected_launcher
        or value.get("devices") != []
        or value.get("security_opts")
        != ["label=disable", "no-new-privileges"]
        or value.get("stop_signal")
        != ("SIGINT" if spec.family == "apk" else "SIGRTMIN+3")
        or value.get("tmpfs") != expected_tmpfs
        or value.get("mounts") != expected_mounts
    ):
        raise LifecycleLabError("ACTIVE container isolation evidence is not exact")


def _inventory_core_digest(
    scenario_result: dict[str, object], phase_label: str
) -> str:
    inventories = scenario_result.get("inventory_evidence")
    phase = inventories.get(phase_label) if isinstance(inventories, dict) else None
    filesystem = phase.get("filesystem") if isinstance(phase, dict) else None
    matches = [
        entry.get("value")
        for entry in filesystem
        if isinstance(entry, dict)
        and entry.get("path") == "/opt/syswarden/bin/syswarden-core"
        and entry.get("type") == "file"
        and entry.get("mode") == "750"
        and entry.get("uid") == 0
        and entry.get("gid") == 0
    ] if isinstance(filesystem, list) else []
    if (
        len(matches) != 1
        or re.fullmatch(r"[0-9a-f]{64}", str(matches[0])) is None
    ):
        raise LifecycleLabError("core inventory digest binding is absent")
    return str(matches[0])


def _validate_postinstall_core_digest_events(
    scenario_result: dict[str, object], scenario: str
) -> dict[str, str]:
    labels = (
        ("candidate", "reinstall", "restart-one", "restart-two", "recovery")
        if scenario == "upgrade-rollback"
        else ("fresh",)
    )
    events = scenario_result.get("events")
    if not isinstance(events, list):
        raise LifecycleLabError("core process event binding is absent")
    by_check = {
        item.get("check"): item
        for item in events
        if isinstance(item, dict) and isinstance(item.get("check"), str)
    }
    bindings: dict[str, str] = {}
    for label in labels:
        digest = _inventory_core_digest(scenario_result, label)
        event = by_check.get(f"{scenario}.{label}.postinstall_contract")
        detail = event.get("detail") if isinstance(event, dict) else None
        if (
            event is None
            or event.get("status") != "pass"
            or not isinstance(detail, str)
            or not detail.endswith(
                f"core process sha256={digest} match the installed version"
            )
        ):
            raise LifecycleLabError(
                f"core process bytes are not bound to inventory phase {label}"
            )
        bindings[label] = digest
    return bindings


def _snapshot_core_digest(snapshot: dict[str, object]) -> str:
    services = snapshot.get("product_services")
    identity = (
        services.get("core_executable_identity")
        if isinstance(services, dict)
        else None
    )
    if (
        not isinstance(identity, str)
        or re.fullmatch(r"[0-9]+:[0-9]+:81e8:0:0\|[0-9a-f]{64}", identity)
        is None
    ):
        raise LifecycleLabError("active core snapshot lacks byte identity")
    return identity.rsplit("|", 1)[1]


def validate_passing_active_scenario_runtime(
    platform_result: dict[str, object],
    scenario_result: dict[str, object],
    *,
    expected_uid_map: list[dict[str, object]] | None = None,
    expected_gid_map: list[dict[str, object]] | None = None,
) -> None:
    scenario = scenario_result.get("name")
    if not isinstance(scenario, str):
        raise LifecycleLabError("runtime scenario name is invalid")
    spec = _platform_spec_from_result(platform_result)
    keys = {
        "name",
        "status",
        "runtime_mode",
        "container_create_exit_code",
        "lifecycle_exec_exit_codes",
        "restart_state",
        "boots",
        "isolation",
        "cleanup",
        "orchestration_error",
        "events",
        "inventory_evidence",
        "log_tail",
    }
    invocations = _scenario_invocations(scenario)
    expected_restart_states = (
        ("restart-one", "restart-two", "complete")
        if scenario == "upgrade-rollback"
        else (None,)
    )
    boots = scenario_result.get("boots")
    cleanup = scenario_result.get("cleanup")
    if (
        set(scenario_result) != keys
        or scenario_result.get("runtime_mode") != "active-real-init"
        or scenario_result.get("container_create_exit_code") != 0
        or scenario_result.get("lifecycle_exec_exit_codes")
        != [0] * len(invocations)
        or scenario_result.get("restart_state")
        != ("complete" if scenario == "upgrade-rollback" else None)
        or scenario_result.get("orchestration_error") is not None
        or not isinstance(cleanup, dict)
        or set(cleanup)
        != {"remove_exit_code", "exists_probe_exit_code", "absent_after_cleanup"}
        or cleanup.get("remove_exit_code") != 0
        or cleanup.get("exists_probe_exit_code") != 1
        or cleanup.get("absent_after_cleanup") is not True
        or not isinstance(scenario_result.get("log_tail"), str)
        or not isinstance(boots, list)
        or len(boots) != len(invocations)
    ):
        raise LifecycleLabError("passing ACTIVE scenario schema is not exact")
    _validate_runtime_isolation_evidence(scenario_result.get("isolation"), spec)
    core_bindings = _validate_postinstall_core_digest_events(
        scenario_result, scenario
    )
    previous_starttime: int | None = None
    previous_cron_binding: tuple[object, ...] | None = None
    previous_boundary_binding: tuple[object, ...] | None = None
    for index, (invocation, expected_restart_state) in enumerate(
        zip(invocations, expected_restart_states, strict=True)
    ):
        boot = boots[index]
        boot_keys = {
            "invocation",
            "boot_command_exit_code",
            "restart",
            "pre_exec",
            "lifecycle_exec_security",
            "script_exec_exit_code",
            "restart_state",
            "post_exec",
        }
        if (
            not isinstance(boot, dict)
            or set(boot) != boot_keys
            or boot.get("invocation") != invocation
            or boot.get("boot_command_exit_code") != 0
            or boot.get("script_exec_exit_code") != 0
            or boot.get("restart_state") != expected_restart_state
        ):
            raise LifecycleLabError("ACTIVE boot evidence is not exact")
        _validate_process_security_evidence(
            boot.get("lifecycle_exec_security"),
            sys_admin_present=frozenset(),
            sys_ptrace_present=(
                SYSTEMD_MANAGER_CAPABILITY_FIELDS
                if spec.family != "apk"
                else frozenset()
            ),
            label=f"{scenario} {invocation} lifecycle exec",
        )
        restart = boot.get("restart")
        restart_keys = {
            "performed",
            "command_exit_code",
            "previous_pid1_starttime_ticks",
            "distinct",
        }
        if not isinstance(restart, dict) or set(restart) != restart_keys:
            raise LifecycleLabError("ACTIVE restart evidence schema is not exact")
        if index == 0:
            if restart != {
                "performed": False,
                "command_exit_code": None,
                "previous_pid1_starttime_ticks": None,
                "distinct": None,
            }:
                raise LifecycleLabError("initial boot restart evidence is not null")
        elif restart != {
            "performed": True,
            "command_exit_code": 0,
            "previous_pid1_starttime_ticks": previous_starttime,
            "distinct": True,
        }:
            raise LifecycleLabError("real restart evidence is not exact")
        pre_expectation = "absent" if index == 0 else "active"
        post_expectation = "active" if scenario == "upgrade-rollback" else "absent"
        pre = _validate_runtime_snapshot_evidence(
            boot.get("pre_exec"),
            spec,
            pre_expectation,
            expected_uid_map=expected_uid_map,
            expected_gid_map=expected_gid_map,
        )
        post = _validate_runtime_snapshot_evidence(
            boot.get("post_exec"),
            spec,
            post_expectation,
            expected_uid_map=expected_uid_map,
            expected_gid_map=expected_gid_map,
        )
        boundary_keys = (
            "pid1_process_security",
            "attestation_process_security",
            "pid1_uid_map",
            "pid1_gid_map",
            "setpriv",
        )
        pre_boundary = tuple(pre[key] for key in boundary_keys)
        post_boundary = tuple(post[key] for key in boundary_keys)
        if (
            pre_boundary != post_boundary
            or boot.get("lifecycle_exec_security")
            != pre["attestation_process_security"]
            or (
                previous_boundary_binding is not None
                and pre_boundary != previous_boundary_binding
            )
        ):
            raise LifecycleLabError(
                "runtime capability/userns boundary changed across lifecycle execution"
            )
        if scenario == "upgrade-rollback":
            post_phase = ("reinstall", "restart-one", "recovery")[index]
            if _snapshot_core_digest(post) != core_bindings[post_phase]:
                raise LifecycleLabError(
                    "post-exec core process bytes differ from inventory"
                )
            if index > 0:
                pre_phase = ("reinstall", "restart-one")[index - 1]
                if _snapshot_core_digest(pre) != core_bindings[pre_phase]:
                    raise LifecycleLabError(
                        "pre-exec core process bytes differ from inventory"
                    )
        if (
            pre["pid1_starttime_ticks"] != post["pid1_starttime_ticks"]
            or pre["cron_main_pid"] != post["cron_main_pid"]
        ):
            raise LifecycleLabError(
                "PID1 or cron changed during lifecycle script execution"
            )
        pre_cron_binding = tuple(
            pre[key]
            for key in (
                "cron_executable_path",
                "cron_executable_identity",
                "cron_fragment_path",
                "cron_fragment_identity",
                "cron_dropin_paths",
                "cron_package_name",
                "cron_package_version",
                "cron_package_architecture",
                "cron_fragment_package_name",
                "cron_fragment_package_version",
                "cron_fragment_package_architecture",
            )
        )
        post_cron_binding = tuple(
            post[key]
            for key in (
                "cron_executable_path",
                "cron_executable_identity",
                "cron_fragment_path",
                "cron_fragment_identity",
                "cron_dropin_paths",
                "cron_package_name",
                "cron_package_version",
                "cron_package_architecture",
                "cron_fragment_package_name",
                "cron_fragment_package_version",
                "cron_fragment_package_architecture",
            )
        )
        if pre_cron_binding != post_cron_binding or (
            previous_cron_binding is not None
            and pre_cron_binding != previous_cron_binding
        ):
            raise LifecycleLabError("cron provider identity changed across evidence")
        if index > 0 and pre["pid1_starttime_ticks"] == previous_starttime:
            raise LifecycleLabError("PID1 starttime did not change across restart")
        previous_starttime = int(post["pid1_starttime_ticks"])
        previous_cron_binding = post_cron_binding
        previous_boundary_binding = post_boundary


def classify_lifecycle_evidence(
    results: Sequence[dict[str, object]],
    *,
    required_platform_coordinates: frozenset[tuple[str, str]] = REQUIRED_PLATFORM_COORDINATES,
) -> dict[str, object]:
    """Recompute compatibility verdicts for container scenarios only."""

    if (
        not required_platform_coordinates
        or not required_platform_coordinates.issubset(REQUIRED_PLATFORM_COORDINATES)
    ):
        raise LifecycleLabError("required platform coordinate contract is invalid")

    structural_failures: list[str] = []
    results_by_coordinate = {
        (str(result.get("cell_id")), str(result.get("architecture_id"))): result
        for result in results
    }
    if len(results_by_coordinate) != len(results):
        structural_failures.append("matrix:duplicate-platform-coordinate")
    for cell_id, architecture in sorted(
        set(results_by_coordinate) - required_platform_coordinates
    ):
        structural_failures.append(
            f"matrix:unexpected-platform-coordinate:{cell_id}/{architecture}"
        )
    observed_failures: dict[str, str] = {}
    coordinate_classification: list[dict[str, object]] = []

    required_coordinate_order = [
        coordinate
        for coordinate in REQUIRED_PLATFORM_COORDINATE_ORDER
        if coordinate in required_platform_coordinates
    ]
    for cell_id, architecture in required_coordinate_order:
        coordinate_name = f"{cell_id}/{architecture}"
        platform_result = results_by_coordinate.get((cell_id, architecture))
        coordinate_structural: list[str] = []
        coordinate_failures: dict[str, str] = {}
        expected_spec = next(
            spec
            for spec in DEFAULT_PLATFORMS
            if platform_coordinate(spec) == (cell_id, architecture)
        )
        if platform_result is None:
            coordinate_structural.append(f"{coordinate_name}:platform-result-missing")
            family = expected_spec.family
        else:
            family = str(platform_result.get("family"))
            if any(
                platform_result.get(key) != value
                for key, value in {
                    "cell_id": expected_spec.cell_id,
                    "version": expected_spec.version,
                    "distribution": expected_spec.distribution,
                    "family": expected_spec.family,
                }.items()
            ):
                coordinate_structural.append(
                    f"{coordinate_name}:matrix-cell-identity-invalid"
                )
            if platform_result.get("runtime_mode") != "active-real-init":
                coordinate_structural.append(
                    f"{coordinate_name}:runtime-mode-not-active-real-init"
                )
            if platform_result.get("restart_contract") != ACTIVE_RESTART_CONTRACT:
                coordinate_structural.append(
                    f"{coordinate_name}:restart-contract-invalid"
                )
            image_cleanup = platform_result.get("bootstrap_image_cleanup")
            if (
                not isinstance(image_cleanup, dict)
                or set(image_cleanup)
                != {
                    "remove_exit_code",
                    "exists_probe_exit_code",
                    "absent_after_cleanup",
                }
                or image_cleanup.get("remove_exit_code") != 0
                or image_cleanup.get("exists_probe_exit_code") != 1
                or image_cleanup.get("absent_after_cleanup") is not True
            ):
                coordinate_structural.append(
                    f"{coordinate_name}:bootstrap-image-cleanup-invalid"
                )
            _, binding_problems = forward_only_apk_report_contract(platform_result)
            coordinate_structural.extend(
                f"{coordinate_name}:{problem}" for problem in binding_problems
            )
            _, binding_problems = historical_ubuntu_deb_recovery_report_contract(
                platform_result
            )
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
                runtime_valid = True
                try:
                    validate_passing_active_scenario_runtime(
                        platform_result, scenario_result
                    )
                except LifecycleLabError:
                    runtime_valid = False
                    coordinate_structural.append(
                        f"{coordinate_name}:{scenario_name}:active-runtime-evidence-invalid"
                    )
                events = scenario_result.get("events")
                try:
                    if not isinstance(events, list):
                        raise LifecycleLabError("scenario event list is absent")
                    validate_event_contract(
                        events,
                        family,
                        scenario_name,
                        candidate_version=str(
                            platform_result.get("candidate_version", "")
                        ),
                    )
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
                coordinate_structural.extend(
                    f"{coordinate_name}:{scenario_name}:{problem}"
                    for problem in validate_historical_ubuntu_deb_recovery_events(
                        platform_result, scenario_result
                    )
                )
                try:
                    validate_scenario_inventory_evidence(
                        scenario_result.get("inventory_evidence"),
                        family,
                        scenario_name,
                        previous_version=str(
                            platform_result.get("previous_version", "")
                        ),
                        candidate_version=str(
                            platform_result.get("candidate_version", "")
                        ),
                    )
                except LifecycleLabError:
                    coordinate_structural.append(
                        f"{coordinate_name}:{scenario_name}:inventory-evidence-invalid"
                    )
                scenario_failed_events = [
                    event for event in events if event["status"] == "fail"
                ]
                derived_scenario_status = (
                    "pass"
                    if runtime_valid and not scenario_failed_events
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
                "cell_id": cell_id,
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


def validate_lifecycle_helper_evidence(value: object) -> dict[str, object]:
    keys = {
        "source",
        "sha256",
        "size_bytes",
        "source_regular_file",
        "source_symlink",
        "snapshot_mode",
        "snapshot_regular_file",
        "snapshot_symlink",
        "frozen_copy",
        "revalidated_before_report",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleLabError("lifecycle helper evidence schema is not exact")
    source = value.get("source")
    current_helper = Path(__file__).resolve().with_name(
        "package_webtui_retirement.sh"
    )
    current_helper_bytes, _ = _read_stable_regular_file(
        current_helper, "current package lifecycle helper"
    )
    current_helper_sha256 = hashlib.sha256(current_helper_bytes).hexdigest()
    if (
        not isinstance(source, str)
        or not source
        or (
            source != "native-shards-byte-bound"
            and (
                not Path(source).is_absolute()
                or Path(source).name != "package_webtui_retirement.sh"
            )
        )
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
        or value.get("sha256") != current_helper_sha256
        or type(value.get("size_bytes")) is not int
        or int(value["size_bytes"]) <= 0
        or value.get("size_bytes") != len(current_helper_bytes)
        or value.get("source_regular_file") is not True
        or value.get("source_symlink") is not False
        or value.get("snapshot_mode") != "0600"
        or value.get("snapshot_regular_file") is not True
        or value.get("snapshot_symlink") is not False
        or value.get("frozen_copy") is not True
        or value.get("revalidated_before_report") is not True
    ):
        raise LifecycleLabError("lifecycle helper evidence values are invalid")
    return value


def validate_runtime_engine_evidence(value: object) -> dict[str, object]:
    keys = {
        "name",
        "version",
        "rootless",
        "cgroups_version",
        "cgroup_manager",
        "cgroup_delegation",
        "cgroup_controllers",
        "host_architecture",
        "service_is_remote",
        "effective_uid",
        "effective_gid",
        "uid_map",
        "gid_map",
        "lifecycle_helper",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise LifecycleLabError("package lifecycle engine schema is not exact")
    controllers = value.get("cgroup_controllers")
    host_architecture = value.get("host_architecture")
    if (
        value.get("name") != "podman"
        or not isinstance(value.get("version"), str)
        or not value.get("version")
        or value.get("rootless") is not True
        or value.get("cgroups_version") != "v2"
        or value.get("cgroup_manager") != "systemd"
        or value.get("cgroup_delegation")
        not in {"rootless-systemd-v2", "native-shards-rootless-systemd-v2"}
        or not isinstance(controllers, list)
        or any(not isinstance(item, str) for item in controllers)
        or controllers != sorted(set(controllers))
        or not {"cpu", "io", "memory", "pids"}.issubset(controllers)
        or host_architecture not in {"amd64", "native-shards"}
        or value.get("service_is_remote") is not False
    ):
        raise LifecycleLabError("package lifecycle engine values are invalid")
    if host_architecture == "native-shards":
        if any(
            value.get(key) is not None
            for key in ("effective_uid", "effective_gid", "uid_map", "gid_map")
        ):
            raise LifecycleLabError(
                "aggregate engine fabricates a common rootless identity map"
            )
    else:
        effective_uid = value.get("effective_uid")
        effective_gid = value.get("effective_gid")
        if (
            type(effective_uid) is not int
            or int(effective_uid) <= 0
            or type(effective_gid) is not int
            or int(effective_gid) <= 0
        ):
            raise LifecycleLabError(
                "native engine effective rootless IDs are invalid"
            )
        uid_map = _validate_id_map_evidence(
            value.get("uid_map"), "native engine uid_map"
        )
        gid_map = _validate_id_map_evidence(
            value.get("gid_map"), "native engine gid_map"
        )
        if (
            uid_map[0]["outside_id"] != effective_uid
            or gid_map[0]["outside_id"] != effective_gid
        ):
            raise LifecycleLabError(
                "native engine maps do not bind the effective rootless IDs"
            )
    validate_lifecycle_helper_evidence(value.get("lifecycle_helper"))
    return value


def validate_aggregate_engine_binding(
    report: dict[str, object], engine: dict[str, object]
) -> dict[str, tuple[list[dict[str, object]], list[dict[str, object]]]]:
    native_shards = report.get("native_shards")
    if native_shards is None:
        return {}
    if (
        not isinstance(native_shards, dict)
        or set(native_shards) != {"schema_version", "mode", "reports"}
        or native_shards.get("schema_version") != 1
        or native_shards.get("mode") != "native_architecture_shards_v1"
    ):
        raise LifecycleLabError("aggregate native shard schema is not exact")
    records = native_shards.get("reports")
    record_keys = {
        "architecture",
        "host_architecture",
        "report_sha256",
        "engine_name",
        "engine_version",
        "rootless",
        "cgroups_version",
        "cgroup_manager",
        "cgroup_delegation",
        "cgroup_controllers",
        "engine_host_architecture",
        "service_is_remote",
        "effective_uid",
        "effective_gid",
        "uid_map",
        "gid_map",
        "lifecycle_helper",
    }
    if (
        not isinstance(records, list)
        or len(records) != 1
        or [item.get("architecture") if isinstance(item, dict) else None for item in records]
        != ["amd64"]
    ):
        raise LifecycleLabError("aggregate native shard records are not exact")
    helper_binding: tuple[object, ...] | None = None
    controller_intersection: set[str] | None = None
    identity_maps: dict[
        str, tuple[list[dict[str, object]], list[dict[str, object]]]
    ] = {}
    for record in records:
        assert isinstance(record, dict)
        architecture = record["architecture"]
        helper = validate_lifecycle_helper_evidence(record.get("lifecycle_helper"))
        binding = tuple(helper[key] for key in sorted(set(helper) - {"source"}))
        if helper_binding is None:
            helper_binding = binding
        elif binding != helper_binding:
            raise LifecycleLabError("aggregate shard helper bindings differ")
        controllers = record.get("cgroup_controllers")
        effective_uid = record.get("effective_uid")
        effective_gid = record.get("effective_gid")
        uid_map = _validate_id_map_evidence(
            record.get("uid_map"), f"{architecture} shard uid_map"
        )
        gid_map = _validate_id_map_evidence(
            record.get("gid_map"), f"{architecture} shard gid_map"
        )
        if (
            set(record) != record_keys
            or record.get("host_architecture") != architecture
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("report_sha256")))
            is None
            or record.get("engine_name") != "podman"
            or not isinstance(record.get("engine_version"), str)
            or not record.get("engine_version")
            or record.get("rootless") is not True
            or record.get("cgroups_version") != "v2"
            or record.get("cgroup_manager") != "systemd"
            or record.get("cgroup_delegation") != "rootless-systemd-v2"
            or not isinstance(controllers, list)
            or controllers != sorted(set(controllers))
            or not {"cpu", "io", "memory", "pids"}.issubset(controllers)
            or record.get("engine_host_architecture") != architecture
            or record.get("service_is_remote") is not False
            or type(effective_uid) is not int
            or int(effective_uid) <= 0
            or type(effective_gid) is not int
            or int(effective_gid) <= 0
            or uid_map[0]["outside_id"] != effective_uid
            or gid_map[0]["outside_id"] != effective_gid
        ):
            raise LifecycleLabError("aggregate native shard engine record is invalid")
        identity_maps[str(architecture)] = (uid_map, gid_map)
        controller_intersection = (
            set(controllers)
            if controller_intersection is None
            else controller_intersection & set(controllers)
        )
    assert helper_binding is not None and controller_intersection is not None
    aggregate_helper = validate_lifecycle_helper_evidence(
        engine.get("lifecycle_helper")
    )
    aggregate_binding = tuple(
        aggregate_helper[key]
        for key in sorted(set(aggregate_helper) - {"source"})
    )
    if (
        engine.get("host_architecture") != "native-shards"
        or engine.get("cgroup_delegation")
        != "native-shards-rootless-systemd-v2"
        or engine.get("cgroup_controllers") != sorted(controller_intersection)
        or engine.get("version")
        != ";".join(
            f"{item['architecture']}={item['engine_version']}" for item in records
        )
        or aggregate_helper.get("source") != "native-shards-byte-bound"
        or aggregate_binding != helper_binding
    ):
        raise LifecycleLabError("aggregate engine dilutes native shard evidence")
    return identity_maps


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
    validate_qualification_matrix_binding(report.get("qualification_matrix"))
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

    engine = validate_runtime_engine_evidence(report.get("engine"))
    aggregate_identity_maps = validate_aggregate_engine_binding(report, engine)

    platforms = report.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise LifecycleLabError("package lifecycle report has no platform results")
    expected_coordinates: set[str] = set()
    for platform_result in platforms:
        if not isinstance(platform_result, dict):
            raise LifecycleLabError("package lifecycle platform result must be an object")
        spec = _platform_spec_from_result(platform_result)
        expected_platform_metadata = {
            "cell_id": spec.cell_id,
            "version": spec.version,
            "distribution": spec.distribution,
            "family": spec.family,
            "architecture": ARCHITECTURE_LABELS[spec.architecture],
            "architecture_id": spec.architecture,
            "package_architecture": spec.package_architecture,
            "podman_platform": spec.podman_platform,
            "image": spec.image,
        }
        if any(
            platform_result.get(key) != value
            for key, value in expected_platform_metadata.items()
        ):
            raise LifecycleLabError(
                f"package lifecycle matrix-cell evidence is invalid at "
                f"{platform_coordinate(spec)}"
            )
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
        if aggregate_identity_maps:
            identity_binding = aggregate_identity_maps.get(
                str(platform_result.get("architecture_id"))
            )
            if identity_binding is None:
                raise LifecycleLabError(
                    "aggregate platform lacks its native shard identity map"
                )
            expected_uid_map, expected_gid_map = identity_binding
        else:
            native_uid_map = engine.get("uid_map")
            native_gid_map = engine.get("gid_map")
            if not isinstance(native_uid_map, list) or not isinstance(
                native_gid_map, list
            ):
                raise LifecycleLabError(
                    "native report lacks engine identity maps"
                )
            expected_uid_map = native_uid_map
            expected_gid_map = native_gid_map
        scenarios = platform_result.get("scenarios")
        if platform_result.get("status") == "pass":
            validate_available_architecture_probe(
                platform_result.get("architecture_probe"), spec
            )
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
                if scenario_result.get("status") != "pass":
                    raise LifecycleLabError(
                        "passing package lifecycle platform contains a failed scenario"
                    )
                validate_passing_active_scenario_runtime(
                    platform_result,
                    scenario_result,
                    expected_uid_map=expected_uid_map,
                    expected_gid_map=expected_gid_map,
                )
                scenario_events = scenario_result.get("events")
                if not isinstance(scenario_events, list):
                    raise LifecycleLabError(
                        "package lifecycle scenario lacks event evidence"
                    )
                validate_event_contract(
                    scenario_events,
                    family,
                    scenario_name,
                    candidate_version=candidate_version,
                )
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
        or set(scope) != SCOPE_KEYS
        or scope.get("evidence_kind") != "container-lifecycle"
        or scope.get("coverage_kind") != "container_scenarios_only"
        or scope.get("real_host_evidence_included") is not False
        or scope.get("required_checks_complete") is not False
        or scope.get("covered_scenarios")
        != qualification_matrix_container_scenarios()
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
    matrix_path = Path(
        getattr(args, "qualification_matrix", QUALIFICATION_MATRIX_PATH)
    )
    matrix_binding = qualification_matrix_binding(matrix_path)
    architecture_shard = getattr(args, "architecture_shard", None)
    required_platform_coordinates = (
        required_coordinates_for_architecture(architecture_shard)
        if architecture_shard is not None
        else REQUIRED_PLATFORM_COORDINATES
    )
    observed_platform_coordinates = frozenset(
        platform_coordinate(spec) for spec in platforms
    )
    observed_platform_coordinate_order = tuple(
        platform_coordinate(spec) for spec in platforms
    )
    required_platform_coordinate_order = tuple(
        coordinate
        for coordinate in REQUIRED_PLATFORM_COORDINATE_ORDER
        if coordinate in required_platform_coordinates
    )
    if architecture_shard is not None and (
        observed_platform_coordinates != required_platform_coordinates
        or len(platforms) != len(required_platform_coordinates)
        or observed_platform_coordinate_order != required_platform_coordinate_order
    ):
        raise LifecycleLabError(
            f"{architecture_shard} shard must contain its exact eight matrix cells "
            f"in canonical order"
        )
    candidate_root, previous_root, pairs = validate_inputs(
        args.packages_dir, args.previous_packages_dir, platforms
    )
    package_tmp_dir = getattr(args, "package_tmp_dir", None)
    if package_tmp_dir is None:
        raise LifecycleLabError("--package-tmp-dir is required outside aggregate mode")
    package_tmp_root = require_private_directory(
        package_tmp_dir, "package lifecycle temporary directory"
    )
    actual_host_architecture = host_architecture or platform.machine()
    normalized_host = normalize_host_architecture(actual_host_architecture)
    if architecture_shard is not None and normalized_host != architecture_shard:
        raise LifecycleLabError(
            f"{architecture_shard} shard requires a native {architecture_shard} host"
        )
    podman_version = ensure_rootless_podman(active_runner, args.podman)
    cgroup_evidence = inspect_rootless_podman_cgroups(
        active_runner, args.podman, actual_host_architecture
    )

    with tempfile.TemporaryDirectory(
        prefix="syswarden-package-lifecycle-", dir=package_tmp_root
    ) as raw:
        workspace = Path(raw)
        script_path = workspace / "package-lifecycle.sh"
        script_path.write_text(LIFECYCLE_SCRIPT, encoding="utf-8")
        script_path.chmod(0o500)
        helper_path, helper_evidence = snapshot_lifecycle_helper(workspace)

        platform_results = [
            run_platform(
                active_runner,
                args.podman,
                spec,
                pairs[package_coordinate(spec)],
                candidate_root,
                previous_root,
                workspace,
                helper_path,
                args.pull_policy,
                args.scenario_timeout,
                actual_host_architecture,
            )
            for spec in platforms
        ]
        helper_evidence = revalidate_lifecycle_helper(
            helper_path, helper_evidence
        )

    results_by_coordinate = {
        (str(result["cell_id"]), str(result["architecture_id"])): result
        for result in platform_results
    }
    required_coordinate_order = [
        coordinate
        for coordinate in REQUIRED_PLATFORM_COORDINATE_ORDER
        if coordinate in required_platform_coordinates
    ]
    missing_coordinates = [
        coordinate
        for coordinate in required_coordinate_order
        if coordinate not in results_by_coordinate
    ]
    architecture_coverage: list[dict[str, object]] = []
    for architecture in sorted({item[1] for item in required_platform_coordinates}):
        expected = [
            coordinate
            for coordinate in required_coordinate_order
            if coordinate[1] == architecture
        ]
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
                "required_cells": [item[0] for item in expected],
                "completed_cells": [
                    cell_id
                    for cell_id, item_architecture in expected
                    if results_by_coordinate.get((cell_id, item_architecture), {}).get(
                        "status"
                    )
                    == "pass"
                ],
                "incomplete_or_failed_cells": [
                    cell_id
                    for cell_id, item_architecture in expected
                    if results_by_coordinate.get((cell_id, item_architecture), {}).get(
                        "status"
                    )
                    != "pass"
                ],
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
                    "required_cells": [spec.cell_id for spec in expected_specs],
                    "completed_cells": [
                        spec.cell_id
                        for spec in expected_specs
                        if results_by_coordinate.get(platform_coordinate(spec), {}).get(
                            "status"
                        )
                        == "pass"
                    ],
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
            "reason": "not every required matrix cell completed every lifecycle scenario",
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
        "qualification_matrix": matrix_binding,
        "package_version_contract": version_contract,
        "scope": {
            "evidence_kind": "container-lifecycle",
            "coverage_kind": "container_scenarios_only",
            "real_host_evidence_included": False,
            "required_checks_complete": False,
            "covered_scenarios": qualification_matrix_container_scenarios(),
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
                {"cell_id": cell_id, "architecture": architecture}
                for cell_id, architecture in required_coordinate_order
            ],
            "missing_platform_coordinates": [
                {"cell_id": cell_id, "architecture": architecture}
                for cell_id, architecture in missing_coordinates
            ],
            "architecture_coverage_policy": (
                "container lifecycle qualification requires every declared "
                "container_scenario in the exact eight-cell AMD64 matrix on a "
                "native AMD64 host; it does not close real-host, updater, or "
                "reboot obligations"
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
            "cgroups_version": cgroup_evidence["cgroups_version"],
            "cgroup_manager": cgroup_evidence["cgroup_manager"],
            "cgroup_delegation": cgroup_evidence["cgroup_delegation"],
            "cgroup_controllers": cgroup_evidence["cgroup_controllers"],
            "host_architecture": cgroup_evidence["host_architecture"],
            "service_is_remote": cgroup_evidence["service_is_remote"],
            "effective_uid": cgroup_evidence["effective_uid"],
            "effective_gid": cgroup_evidence["effective_gid"],
            "uid_map": cgroup_evidence["uid_map"],
            "gid_map": cgroup_evidence["gid_map"],
            "lifecycle_helper": helper_evidence,
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
        "qualification_matrix",
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
    validate_qualification_matrix_binding(report.get("qualification_matrix"))
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
        {"cell_id": cell_id, "architecture": item_architecture}
        for cell_id, item_architecture in REQUIRED_PLATFORM_COORDINATE_ORDER
        if (cell_id, item_architecture) in required_coordinates
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
    engine = validate_runtime_engine_evidence(report.get("engine"))
    if (
        engine.get("host_architecture") != architecture
        or engine.get("cgroup_delegation") != "rootless-systemd-v2"
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
            str(platform_result.get("cell_id")),
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
            "cell_id": spec.cell_id,
            "version": spec.version,
            "distribution": spec.distribution,
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
        validate_available_architecture_probe(
            platform_result.get("architecture_probe"), spec
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
        (str(result.get("cell_id")), str(result.get("architecture_id"))): result
        for result in platform_results
    }
    if len(results_by_coordinate) != len(platform_results):
        raise LifecycleLabError("native shard aggregate contains duplicate coordinates")
    if set(results_by_coordinate) != REQUIRED_PLATFORM_COORDINATES:
        raise LifecycleLabError("native shard aggregate platform matrix is not exact")
    architecture_coverage: list[dict[str, object]] = []
    family_architecture_coverage: list[dict[str, object]] = []
    for architecture in ARCHITECTURE_LABELS:
        expected = [
            coordinate
            for coordinate in REQUIRED_PLATFORM_COORDINATE_ORDER
            if coordinate[1] == architecture
        ]
        present = [results_by_coordinate[coordinate] for coordinate in expected]
        architecture_coverage.append(
            {
                "architecture": ARCHITECTURE_LABELS[architecture],
                "architecture_id": architecture,
                "status": coverage_status(present, len(expected)),
                "required_cells": [item[0] for item in expected],
                "completed_cells": [
                    cell_id
                    for cell_id, item_architecture in expected
                    if results_by_coordinate[(cell_id, item_architecture)]["status"]
                    == "pass"
                ],
                "incomplete_or_failed_cells": [
                    cell_id
                    for cell_id, item_architecture in expected
                    if results_by_coordinate[(cell_id, item_architecture)]["status"]
                    != "pass"
                ],
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
                    "required_cells": [spec.cell_id for spec in specs],
                    "completed_cells": [
                        spec.cell_id
                        for spec in specs
                        if results_by_coordinate[platform_coordinate(spec)]["status"]
                        == "pass"
                    ],
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
        "evidence_kind": "container-lifecycle",
        "coverage_kind": "container_scenarios_only",
        "real_host_evidence_included": False,
        "required_checks_complete": False,
        "covered_scenarios": qualification_matrix_container_scenarios(),
        "container_lab_complete": status == "pass",
        "coordinate_classification": classification["coordinate_classification"],
        "host_architecture": NATIVE_AGGREGATE_HOST,
        "network_during_image_bootstrap": "rootless Podman default on the native AMD64 shard",
        "network_during_package_operations": "disabled",
        "host_mutation": (
            "bounded to rootless Podman storage and temporary workdirs on the "
            "native AMD64 runner"
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
                    "not every required matrix cell completed every lifecycle scenario"
                ),
            }
            for item in architecture_coverage
            if item["status"] != "pass"
        ],
        "architecture_coverage": architecture_coverage,
        "family_architecture_coverage": family_architecture_coverage,
        "required_platform_coordinates": [
            {"cell_id": cell_id, "architecture": architecture}
            for cell_id, architecture in REQUIRED_PLATFORM_COORDINATE_ORDER
        ],
        "missing_platform_coordinates": [],
        "architecture_coverage_policy": (
            "container lifecycle qualification requires every declared "
            "container_scenario in the exact eight-cell AMD64 matrix on the "
            "native AMD64 shard; it does not close real-host, updater, or "
            "reboot obligations"
        ),
        "rollback_model": (
            "external package-manager downgrade to the separately supplied, "
            "checksum-verified previous artifact; this is not a SysWarden "
            "product rollback feature"
        ),
    }
    return status, classification, scope


def aggregate_native_shard_reports(args: argparse.Namespace) -> dict[str, object]:
    matrix_path = Path(
        getattr(args, "qualification_matrix", QUALIFICATION_MATRIX_PATH)
    )
    matrix_binding = qualification_matrix_binding(matrix_path)
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
    paths = {"amd64": args.aggregate_amd64_report}
    shard_reports: dict[str, dict[str, object]] = {}
    shard_digests: dict[str, str] = {}
    identities: set[tuple[int, int]] = set()
    for architecture in ("amd64",):
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
        if report.get("qualification_matrix") != matrix_binding:
            raise LifecycleLabError(
                "native shard qualification matrix differs from aggregate inputs"
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
    for architecture in ("amd64",):
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
    common_helper_binding: tuple[object, ...] | None = None
    aggregate_controllers: set[str] | None = None
    for architecture in ("amd64",):
        shard = shard_reports[architecture]
        shard_scope = shard["scope"]
        shard_engine = shard["engine"]
        if not isinstance(shard_scope, dict):
            raise LifecycleLabError("native shard metadata is invalid")
        shard_engine = validate_runtime_engine_evidence(shard_engine)
        shard_helper = validate_lifecycle_helper_evidence(
            shard_engine["lifecycle_helper"]
        )
        helper_binding = tuple(
            shard_helper[key]
            for key in sorted(set(shard_helper) - {"source"})
        )
        if common_helper_binding is None:
            common_helper_binding = helper_binding
        elif helper_binding != common_helper_binding:
            raise LifecycleLabError(
                "native shards used different frozen lifecycle helper bytes"
            )
        controllers = set(shard_engine["cgroup_controllers"])
        aggregate_controllers = (
            controllers
            if aggregate_controllers is None
            else aggregate_controllers & controllers
        )
        native_records.append(
            {
                "architecture": architecture,
                "host_architecture": normalize_host_architecture(
                    str(shard_scope["host_architecture"])
                ),
                "report_sha256": shard_digests[architecture],
                "engine_name": shard_engine["name"],
                "engine_version": shard_engine["version"],
                "rootless": shard_engine["rootless"],
                "cgroups_version": shard_engine["cgroups_version"],
                "cgroup_manager": shard_engine["cgroup_manager"],
                "cgroup_delegation": shard_engine["cgroup_delegation"],
                "cgroup_controllers": shard_engine["cgroup_controllers"],
                "engine_host_architecture": shard_engine["host_architecture"],
                "service_is_remote": shard_engine["service_is_remote"],
                "effective_uid": shard_engine["effective_uid"],
                "effective_gid": shard_engine["effective_gid"],
                "uid_map": shard_engine["uid_map"],
                "gid_map": shard_engine["gid_map"],
                "lifecycle_helper": shard_helper,
            }
        )
    assert aggregate_controllers is not None
    first_helper = native_records[0]["lifecycle_helper"]
    assert isinstance(first_helper, dict)
    aggregate_helper = {
        **first_helper,
        "source": "native-shards-byte-bound",
    }
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": status,
        "harness_complete": classification["harness_complete"],
        "release_ready": classification["release_ready"],
        "blocker_ids": classification["blocker_ids"],
        "unexpected_failed_checks": classification["unexpected_failed_checks"],
        "qualification_matrix": matrix_binding,
        "package_version_contract": version_contract,
        "scope": scope,
        "engine": {
            "name": "podman",
            "version": ";".join(
                f"{item['architecture']}={item['engine_version']}"
                for item in native_records
            ),
            "rootless": True,
            "cgroups_version": "v2",
            "cgroup_manager": "systemd",
            "cgroup_delegation": "native-shards-rootless-systemd-v2",
            "cgroup_controllers": sorted(aggregate_controllers),
            "host_architecture": "native-shards",
            "service_is_remote": False,
            "effective_uid": None,
            "effective_gid": None,
            "uid_map": None,
            "gid_map": None,
            "lifecycle_helper": aggregate_helper,
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
    parser.add_argument("--architecture-shard", choices=("amd64",))
    parser.add_argument("--aggregate-amd64-report", type=Path)
    parser.add_argument(
        "--qualification-matrix",
        type=Path,
        default=QUALIFICATION_MATRIX_PATH,
    )
    parser.add_argument("--package-tmp-dir", type=Path)
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
        "--pull-policy", choices=("never", "missing", "always"), default="missing"
    )
    parser.add_argument("--scenario-timeout", type=int, default=600)
    defaults = {spec.cell_id: spec.image for spec in DEFAULT_PLATFORMS}
    parser.add_argument(
        "--debian-image",
        "--debian-amd64-image",
        "--debian-13-image",
        dest="deb_13_image",
        default=defaults["DEB-13"],
    )
    parser.add_argument(
        "--ubuntu-amd64-image",
        "--ubuntu-2404-image",
        dest="deb_u2404_image",
        default=defaults["DEB-U2404"],
    )
    parser.add_argument(
        "--ubuntu-2604-image",
        dest="deb_u2604_image",
        default=defaults["DEB-U2604"],
    )
    parser.add_argument(
        "--fedora-image",
        "--fedora-amd64-image",
        "--fedora-44-image",
        dest="rpm_f44_image",
        default=defaults["RPM-F44"],
    )
    parser.add_argument(
        "--almalinux-amd64-image",
        "--almalinux-9-image",
        dest="rpm_a9_image",
        default=defaults["RPM-A9"],
    )
    parser.add_argument(
        "--almalinux-10-image",
        dest="rpm_a10_image",
        default=defaults["RPM-A10"],
    )
    parser.add_argument(
        "--alpine-image",
        "--alpine-amd64-image",
        "--alpine-322-image",
        dest="apk_322_image",
        default=defaults["APK-322"],
    )
    parser.add_argument(
        "--alpine-324-image",
        dest="apk_324_image",
        default=defaults["APK-324"],
    )
    return parser


def configured_platforms(args: argparse.Namespace) -> tuple[PlatformSpec, ...]:
    images = {
        "DEB-13": args.deb_13_image,
        "DEB-U2404": args.deb_u2404_image,
        "DEB-U2604": args.deb_u2604_image,
        "RPM-F44": args.rpm_f44_image,
        "RPM-A9": args.rpm_a9_image,
        "RPM-A10": args.rpm_a10_image,
        "APK-322": args.apk_322_image,
        "APK-324": args.apk_324_image,
    }
    return tuple(
        PlatformSpec(
            **{
                **asdict(spec),
                "image": images[spec.cell_id],
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
        "qualification_matrix": {
            "matrix_id": QUALIFICATION_MATRIX_ID,
            "sha256": QUALIFICATION_MATRIX_SHA256,
        },
        "error": str(exc),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    aggregate_requested = args.aggregate_amd64_report is not None
    if aggregate_requested and (
        args.architecture_shard is not None
    ):
        report = error_report(
            LifecycleLabError(
                "aggregation requires the exact AMD64 shard report and forbids shard mode"
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
