#!/usr/bin/env python3
"""Strictly bind raw SysWarden runtime-lab reports to release evidence.

The native package shards carry an explicit qualification-run binding so their
cross-run aggregation is independently reproducible. This adapter validates all
exact schemas and shard digests, independently re-verifies the Git checkout and
both package sets, derives decisions from nested evidence, and emits the two
canonical envelopes consumed by ``release_qualification_gate.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Sequence

import package_lifecycle_lab as package_lab
import release_qualification_gate as gate


OUTPUT_NAMES = {
    "nft": "nftables-bound.json",
    "package": "package-lifecycle-bound.json",
}
RAW_NAMES = {
    "nft": "nftables-raw.json",
    "package": "package-lifecycle-raw.json",
}
# Laboratories run sequentially, so raw timestamps cannot be byte-identical.
# The CLI skew applies to the normalized envelopes; independently bound the raw
# collection window and stamp all envelopes with the earliest raw timestamp.
RAW_REPORT_MAX_SKEW_SECONDS = 3600
RAW_TOP_KEYS = {
    "nft": frozenset(
        {
            "schema_version",
            "generated_at",
            "harness_status",
            "product_status",
            "release_ready",
            "finding_id",
            "repository_binding",
            "source_snapshot",
            "manager_test_binary",
            "summary",
            "engine",
            "network_namespaces",
            "conditions",
            "kernel_error",
        }
    ),
    "package": frozenset(
        {
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
            "native_shards",
        }
    ),
}
NFT_SOURCE_BINDING_PATHS = (
    ".actrc",
    "src/core/syswarden-cli/config/config_loader.go",
    "src/core/syswarden-cli/pkg/firewall/firewall_linux.go",
    "src/core/syswarden-cli/pkg/firewall/firewall_linux_golden_test.go",
    "src/core/syswarden-cli/pkg/firewall/honeyports.go",
    "src/core/syswarden-core/firewall/manager_kernel_integration_linux_test.go",
    "src/core/syswarden-core/firewall/manager_linux.go",
    "testdata/firewall/nftables-v4.02.8.nft",
)
NFT_BINARY_IDENTITY_KEYS = frozenset(
    {
        "sha256",
        "device",
        "inode",
        "mode",
        "size_bytes",
        "uid",
        "gid",
        "mtime_ns",
        "ctime_ns",
        "regular_file",
        "symlink",
    }
)


class AdapterError(gate.EvidenceError):
    """Raised when raw evidence cannot be safely normalized."""


@dataclass(frozen=True)
class RawReport:
    label: str
    snapshot: gate.FileSnapshot
    document: dict[str, Any]
    generated_at: datetime


@dataclass(frozen=True)
class ValidatedInputs:
    binding: gate.RepositoryBinding
    candidate: gate.PackageManifest
    previous: gate.PackageManifest
    raws: dict[str, RawReport]
    package_shards: dict[str, RawReport]
    envelopes: dict[str, dict[str, Any]]


def _fail(message: str) -> None:
    raise AdapterError(message)


def _exact_keys(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    expected = frozenset(keys)
    actual = frozenset(value)
    if actual != expected:
        _fail(
            f"{label} schema keys differ; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _string(value: Any, label: str, *, empty: bool = False) -> str:
    if type(value) is not str or (not empty and not value):
        _fail(f"{label} must be {'a string' if empty else 'a non-empty string'}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        _fail(f"{label} must be an integer")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        _fail(f"{label} must be an array")
    return value


def _string_list(
    value: Any,
    label: str,
    *,
    sorted_unique: bool = False,
    allow_empty_items: bool = False,
) -> list[str]:
    result = _list(value, label)
    if any(
        type(item) is not str or (not allow_empty_items and not item)
        for item in result
    ):
        _fail(f"{label} must contain only valid strings")
    if sorted_unique and result != sorted(set(result)):
        _fail(f"{label} must be sorted and unique")
    return result


def _sha256(value: Any, label: str) -> str:
    result = _string(value, label)
    if gate.SHA256_RE.fullmatch(result) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return result


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _git_blob_bytes(binding: gate.RepositoryBinding, relative: str) -> bytes:
    try:
        process = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(binding.root),
                "show",
                f"{binding.commit_sha}:{relative}",
            ),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(f"cannot read Git blob {relative}: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        _fail(f"cannot read Git blob {relative}: {detail}")
    return process.stdout


def _git_archive_bytes(binding: gate.RepositoryBinding) -> bytes:
    try:
        process = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(binding.root),
                "archive",
                "--format=tar",
                binding.commit_sha,
            ),
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(
            f"cannot independently archive Git commit {binding.commit_sha}: {exc}"
        ) from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        _fail(
            f"cannot independently archive Git commit {binding.commit_sha}: {detail}"
        )
    if not process.stdout:
        _fail("independent Git archive is empty")
    return process.stdout


def _validate_nft_source_snapshot(
    value: Any, binding: gate.RepositoryBinding
) -> dict[str, Any]:
    snapshot = _exact_keys(
        value,
        {
            "schema_version",
            "format",
            "commit_sha",
            "tree_sha",
            "archive_sha256",
            "archive_size_bytes",
            "critical_files",
            "read_only",
            "revalidated_after_container",
        },
        "nft.source_snapshot",
    )
    archive = _git_archive_bytes(binding)
    if (
        _integer(snapshot["schema_version"], "nft.source_snapshot.schema_version")
        != 1
        or snapshot["format"] != "git-archive-tar-v1"
        or snapshot["commit_sha"] != binding.commit_sha
        or snapshot["tree_sha"] != binding.tree_sha
        or _sha256(
            snapshot["archive_sha256"], "nft.source_snapshot.archive_sha256"
        )
        != hashlib.sha256(archive).hexdigest()
        or _integer(
            snapshot["archive_size_bytes"],
            "nft.source_snapshot.archive_size_bytes",
        )
        != len(archive)
        or _boolean(snapshot["read_only"], "nft.source_snapshot.read_only")
        is not True
        or _boolean(
            snapshot["revalidated_after_container"],
            "nft.source_snapshot.revalidated_after_container",
        )
        is not True
    ):
        _fail("nft source snapshot is not an immutable archive of the exact Git commit")
    records = _list(snapshot["critical_files"], "nft.source_snapshot.critical_files")
    if len(records) != len(NFT_SOURCE_BINDING_PATHS):
        _fail("nft source snapshot critical-file count differs")
    for index, relative in enumerate(NFT_SOURCE_BINDING_PATHS):
        record = _exact_keys(
            records[index],
            {"path", "sha256", "size_bytes"},
            f"nft.source_snapshot.critical_files[{index}]",
        )
        payload = _git_blob_bytes(binding, relative)
        if (
            record["path"] != relative
            or _sha256(
                record["sha256"],
                f"nft.source_snapshot.critical_files[{index}].sha256",
            )
            != hashlib.sha256(payload).hexdigest()
            or _integer(
                record["size_bytes"],
                f"nft.source_snapshot.critical_files[{index}].size_bytes",
            )
            != len(payload)
        ):
            _fail(f"nft source snapshot does not bind exact Git blob {relative}")
    return snapshot


def _validate_nft_binary_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact_keys(value, NFT_BINARY_IDENTITY_KEYS, label)
    _sha256(identity["sha256"], f"{label}.sha256")
    if (
        _integer(identity["device"], f"{label}.device") < 0
        or _integer(identity["inode"], f"{label}.inode") <= 0
        or identity["mode"] != "0500"
        or _integer(identity["size_bytes"], f"{label}.size_bytes") <= 0
        or _integer(identity["uid"], f"{label}.uid") < 0
        or _integer(identity["gid"], f"{label}.gid") < 0
        or _integer(identity["mtime_ns"], f"{label}.mtime_ns") <= 0
        or _integer(identity["ctime_ns"], f"{label}.ctime_ns") <= 0
        or _boolean(identity["regular_file"], f"{label}.regular_file") is not True
        or _boolean(identity["symlink"], f"{label}.symlink") is not False
    ):
        _fail(f"{label} does not prove a non-empty immutable regular executable")
    return identity


def _validate_nft_manager_binary(
    value: Any, source_snapshot: dict[str, Any]
) -> dict[str, Any]:
    binary = _exact_keys(
        value,
        {"schema_version", "source_archive_sha256", "before", "after", "identical"},
        "nft.manager_test_binary",
    )
    before = _validate_nft_binary_identity(
        binary["before"], "nft.manager_test_binary.before"
    )
    after = _validate_nft_binary_identity(
        binary["after"], "nft.manager_test_binary.after"
    )
    if (
        _integer(binary["schema_version"], "nft.manager_test_binary.schema_version")
        != 1
        or _sha256(
            binary["source_archive_sha256"],
            "nft.manager_test_binary.source_archive_sha256",
        )
        != source_snapshot["archive_sha256"]
        or _boolean(binary["identical"], "nft.manager_test_binary.identical")
        is not True
        or before != after
    ):
        _fail("nft manager test binary changed or is not bound to the source archive")
    return binary


def _load_raw(
    path: Path,
    label: str,
    repo: Path,
    now: datetime,
    max_age_seconds: int,
) -> RawReport:
    snapshot = gate.read_snapshot(path, f"{label} raw report")
    if _inside(snapshot.path, repo):
        _fail(f"{label} raw report must be outside the repository")
    document = gate.strict_json(snapshot.payload, f"{label} raw report")
    generated_at = gate.parse_timestamp(document.get("generated_at"), f"{label}.generated_at")
    if generated_at > now + timedelta(seconds=gate.FUTURE_SKEW_SECONDS):
        _fail(f"{label} raw report timestamp is too far in the future")
    if now - generated_at > timedelta(seconds=max_age_seconds):
        _fail(f"{label} raw report is stale")
    return RawReport(label, snapshot, document, generated_at)


def _validate_nft(document: dict[str, Any], binding: gate.RepositoryBinding) -> dict[str, Any]:
    _exact_keys(document, RAW_TOP_KEYS["nft"], "nft raw report")
    if _integer(document["schema_version"], "nft.schema_version") != 3:
        _fail("nft raw report schema version must be 3")
    repository_binding = _exact_keys(
        document["repository_binding"],
        {"schema_version", "commit_sha", "tree_sha", "worktree_clean"},
        "nft.repository_binding",
    )
    if (
        _integer(
            repository_binding["schema_version"],
            "nft.repository_binding.schema_version",
        )
        != 1
        or repository_binding["commit_sha"] != binding.commit_sha
        or repository_binding["tree_sha"] != binding.tree_sha
        or _boolean(
            repository_binding["worktree_clean"],
            "nft.repository_binding.worktree_clean",
        )
        is not True
    ):
        _fail("nft raw report is not bound to the exact clean Git commit and tree")
    source_snapshot = _validate_nft_source_snapshot(
        document["source_snapshot"], binding
    )
    _validate_nft_manager_binary(
        document["manager_test_binary"], source_snapshot
    )
    engine = _exact_keys(
        document["engine"],
        {
            "name",
            "client_version",
            "rootless",
            "service_is_remote",
            "local_os",
            "local_architecture",
            "server_os",
            "server_architecture",
            "server_kernel",
            "container_architecture",
            "container_kernel",
            "image",
            "network",
            "nftables",
        },
        "nft.engine",
    )
    for key in (
        "name",
        "client_version",
        "local_os",
        "local_architecture",
        "server_os",
        "server_architecture",
        "server_kernel",
        "container_architecture",
        "container_kernel",
        "image",
        "network",
        "nftables",
    ):
        _string(engine[key], f"nft.engine.{key}")
    if (
        engine["name"] != "podman"
        or _boolean(engine["rootless"], "nft.engine.rootless") is not True
        or _boolean(
            engine["service_is_remote"], "nft.engine.service_is_remote"
        )
        is not False
        or engine["local_os"] != "linux"
        or engine["server_os"] != "linux"
        or engine["local_architecture"] != "amd64"
        or engine["server_architecture"] != "amd64"
        or engine["container_architecture"] != "amd64"
        or engine["container_kernel"] != engine["server_kernel"]
        or engine["network"] != "none"
        or re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", engine["image"]) is None
    ):
        _fail("nft engine is not a local native Linux AMD64 server-bound endpoint")
    namespaces = _exact_keys(
        document["network_namespaces"], {"host", "container"}, "nft.network_namespaces"
    )
    host_namespace = _string(namespaces["host"], "nft.network_namespaces.host")
    lab_namespace = _string(namespaces["container"], "nft.network_namespaces.container")
    if host_namespace == lab_namespace:
        _fail("nft laboratory namespace is not distinct from the host namespace")
    condition_keys = {
        "local_native_podman_server",
        "container_kernel_matches_server",
        "immutable_git_source_revalidated",
        "manager_test_binary_revalidated",
        "separate_network_namespace",
        "historical_concatenation_rejected_before_mutation",
        "kernel_reported_invalid_port",
        "corrected_ruleset_applied",
        "current_generator_contract_passed",
        "native_manager_interval_contract_passed",
        "isolated_ruleset_cleanup_succeeded",
    }
    conditions = _exact_keys(document["conditions"], condition_keys, "nft.conditions")
    if any(_boolean(value, f"nft.conditions.{key}") is not True for key, value in conditions.items()):
        _fail("nft raw report no longer proves the corrected kernel contract")
    if "Service out of range" not in _string(document["kernel_error"], "nft.kernel_error"):
        _fail("nft kernel error does not prove the reviewed invalid-port rejection")
    _string(document["summary"], "nft.summary")
    derived_harness = (
        all(conditions.values())
        and engine["rootless"] is True
        and engine["service_is_remote"] is False
        and engine["container_kernel"] == engine["server_kernel"]
    )
    if (
        document["harness_status"] != ("pass" if derived_harness else "fail")
        or document["product_status"] != "pass"
        or _boolean(document["release_ready"], "nft.release_ready") is not True
        or document["finding_id"] != "SW-FW-004"
    ):
        _fail("nft top-level classification is inconsistent with nested evidence")

    # Bind the characterization to the reviewed source and pinned Act image in HEAD.
    golden = gate._blob(binding.root, "testdata/firewall/nftables-v4.02.8.nft")
    loader = gate._blob(binding.root, "src/core/syswarden-cli/config/config_loader.go")
    generator = gate._blob(
        binding.root, "src/core/syswarden-cli/pkg/firewall/firewall_linux.go"
    )
    serializer = gate._blob(
        binding.root, "src/core/syswarden-cli/pkg/firewall/honeyports.go"
    )
    if (
        golden.count("tcp dport { 236379 }") != 2
        or 'strings.Join(m.Security.Honeyports, " ")' not in loader
        or "canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)" not in generator
        or 'strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")' in generator
        or 'strings.Join(canonical, ", ")' not in serializer
    ):
        _fail("nft raw characterization does not match the expected Git source contract")
    act_images = re.findall(
        r"(?m)^\s*-P ubuntu-24\.04=([^\s]+@sha256:[0-9a-f]{64})\s*$",
        gate._blob(binding.root, ".actrc"),
    )
    if act_images != [engine["image"]]:
        _fail("nft engine image does not match the digest-pinned Act image in Git")
    return {
        "harness_complete": derived_harness,
        "release_ready": True,
        "blocker_ids": [],
        "conditions": {
            "network_namespace_isolated": conditions["separate_network_namespace"],
            "host_namespace_untouched": (
                engine["rootless"] is True
                and engine["service_is_remote"] is False
                and engine["network"] == "none"
                and host_namespace != lab_namespace
            ),
            "kernel_apply_executed": conditions["corrected_ruleset_applied"],
            "cleanup_complete": conditions["isolated_ruleset_cleanup_succeeded"],
        },
        "network_namespaces": {"host": host_namespace, "laboratory": lab_namespace},
    }


PACKAGE_CONTRACT_KEYS = frozenset(
    {
        "scheme",
        "relation",
        "previous_version",
        "candidate_version",
        "previous_numeric",
        "candidate_numeric",
        "coordinates",
    }
)
PACKAGE_CONTRACT_COORDINATE_KEYS = frozenset(
    {
        "coordinate",
        "family",
        "package_architecture",
        "previous_version",
        "candidate_version",
        "previous_numeric",
        "candidate_numeric",
    }
)
PACKAGE_SCOPE_KEYS = frozenset(
    {
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
PACKAGE_QUALIFICATION_BINDING_KEYS = frozenset(
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
PACKAGE_NATIVE_SHARDS_KEYS = frozenset({"schema_version", "mode", "reports"})
PACKAGE_NATIVE_SHARD_RECORD_KEYS = frozenset(
    {
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
)
PACKAGE_ENGINE_KEYS = frozenset(
    {
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
)
LIFECYCLE_HELPER_KEYS = frozenset(
    {
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
)
PACKAGE_NATIVE_SHARD_NAMES = {
    "amd64": "package-lifecycle-amd64.json",
}
PACKAGE_NATIVE_AGGREGATE_HOST = "native-shards:amd64"
PACKAGE_PLATFORM_KEYS = frozenset(
    {
        "name",
        "distribution",
        "family",
        "architecture",
        "architecture_id",
        "package_architecture",
        "podman_platform",
        "image",
        "purge_semantics",
        "candidate_version",
        "previous_version",
        "candidate",
        "previous",
        "package_bytes_differ",
        "bootstrap_execution",
        "lifecycle_network",
        "runtime_mode",
        "restart_contract",
        "scenarios",
        "architecture_probe",
        "bootstrap_image_cleanup",
        "status",
    }
)
PACKAGE_SCENARIO_KEYS = frozenset(
    {
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
)
RUNTIME_BOOT_KEYS = frozenset(
    {
        "invocation",
        "boot_command_exit_code",
        "restart",
        "pre_exec",
        "lifecycle_exec_security",
        "script_exec_exit_code",
        "restart_state",
        "post_exec",
    }
)
RUNTIME_RESTART_KEYS = frozenset(
    {
        "performed",
        "command_exit_code",
        "previous_pid1_starttime_ticks",
        "distinct",
    }
)
RUNTIME_SNAPSHOT_KEYS = frozenset(
    {
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
)
PRODUCT_SERVICES_KEYS = frozenset(
    {
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
)
RUNTIME_ISOLATION_KEYS = frozenset(
    {
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
)
RUNTIME_MOUNT_KEYS = frozenset({"role", "destination", "read_only"})
RUNTIME_CLEANUP_KEYS = frozenset(
    {"remove_exit_code", "exists_probe_exit_code", "absent_after_cleanup"}
)
PROCESS_SECURITY_KEYS = frozenset(
    {
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
        "no_new_privileges",
    }
)
ID_MAP_RANGE_KEYS = frozenset({"inside_id", "outside_id", "length"})
SETPRIV_KEYS = frozenset(
    {
        "path",
        "file_identity",
        "sha256",
        "package_name",
        "package_version",
        "package_architecture",
    }
)
SYS_ADMIN_CAPABILITY_BIT = 21
SYS_PTRACE_CAPABILITY_BIT = 19
SYSTEMD_MANAGER_CAPABILITY_KEYS = frozenset(
    {"cap_permitted", "cap_effective", "cap_bounding"}
)
SYSTEMD_LIFECYCLE_EXEC_LAUNCHER = (
    "/usr/bin/setpriv",
    "--bounding-set=-sys_admin",
    "--inh-caps=-sys_admin",
    "--ambient-caps=-sys_admin",
    "--no-new-privs",
    "/bin/sh",
    "-ceu",
)
OPENRC_LIFECYCLE_EXEC_LAUNCHER = ("/bin/sh", "-ceu")
LIFECYCLE_CLAIM_KEYS = (
    "active_service_manager",
    "active_postinstall",
    "legacy_runtime_retirement",
    "fresh_install",
    "upgrade",
    "reinstall",
    "rollback",
    "remove",
    "purge",
    "second_restart",
)


def _package_versions(document: dict[str, Any], expected_version: str) -> tuple[str, str]:
    _exact_keys(document, RAW_TOP_KEYS["package"], "package raw report")
    if _integer(document["schema_version"], "package.schema_version") != 4:
        _fail("package raw report schema version must be 4")
    contract = _exact_keys(
        document["package_version_contract"], PACKAGE_CONTRACT_KEYS, "package.version_contract"
    )
    previous = _string(contract["previous_version"], "package.previous_version")
    candidate = _string(contract["candidate_version"], "package.candidate_version")
    if "v" + candidate != expected_version:
        _fail("package raw candidate version does not match the expected Git version")
    try:
        if gate.version_tuple("v" + previous) >= gate.version_tuple("v" + candidate):
            _fail("package raw report does not prove previous < candidate")
    except gate.EvidenceError as exc:
        raise AdapterError(str(exc)) from exc
    return previous, candidate


def _validate_package_qualification_binding(
    value: Any,
) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        PACKAGE_QUALIFICATION_BINDING_KEYS,
        "package.qualification_binding",
    )
    if _integer(binding["schema_version"], "package.qualification_binding.schema_version") != 1:
        _fail("package qualification binding schema version must be 1")
    for key in (
        "repository",
        "release_sha",
        "release_tag",
        "previous_tag",
        "candidate_artifact_name",
    ):
        _string(binding[key], f"package.qualification_binding.{key}")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", binding["repository"]) is None:
        _fail("package qualification repository is not canonical")
    if gate.SHA_RE.fullmatch(binding["release_sha"]) is None:
        _fail("package qualification release SHA is not canonical")
    for key in ("release_tag", "previous_tag"):
        if gate.VERSION_RE.fullmatch(binding[key]) is None:
            _fail(f"package qualification {key} is not canonical")
    if binding["release_tag"] == binding["previous_tag"]:
        _fail("package qualification release and previous tags must differ")
    for key in (
        "workflow_run_id",
        "workflow_run_attempt",
        "candidate_run_id",
        "candidate_artifact_id",
        "previous_release_id",
    ):
        if _integer(binding[key], f"package.qualification_binding.{key}") <= 0:
            _fail(f"package qualification {key} must be positive")
    for key in ("candidate_manifest_sha256", "previous_manifest_sha256"):
        _sha256(binding[key], f"package.qualification_binding.{key}")
    return binding


def _validate_lifecycle_helper(
    value: Any,
    label: str,
    *,
    aggregate: bool,
) -> dict[str, Any]:
    helper = _exact_keys(value, LIFECYCLE_HELPER_KEYS, label)
    source = _string(helper["source"], f"{label}.source")
    if aggregate:
        if source != "native-shards-byte-bound":
            _fail(f"{label}.source is not bound to the native shards")
    elif not Path(source).is_absolute() or Path(source).name != (
        "package_webtui_retirement.sh"
    ):
        _fail(f"{label}.source is not the absolute lifecycle helper path")
    _sha256(helper["sha256"], f"{label}.sha256")
    if _integer(helper["size_bytes"], f"{label}.size_bytes") <= 0:
        _fail(f"{label}.size_bytes must be positive")
    expected = {
        "source_regular_file": True,
        "source_symlink": False,
        "snapshot_regular_file": True,
        "snapshot_symlink": False,
        "frozen_copy": True,
        "revalidated_before_report": True,
    }
    if (
        helper["snapshot_mode"] != "0600"
        or any(
            _boolean(helper[key], f"{label}.{key}") is not expected_value
            for key, expected_value in expected.items()
        )
    ):
        _fail(f"{label} does not prove a frozen regular-file helper snapshot")
    return helper


def _validate_cgroup_controllers(value: Any, label: str) -> list[str]:
    controllers = _string_list(value, label, sorted_unique=True)
    if not {"cpu", "io", "memory", "pids"}.issubset(controllers):
        _fail(f"{label} lacks required cgroup v2 controllers")
    return controllers


def _validate_package_engine(
    value: Any,
    label: str,
    *,
    architecture: str,
) -> dict[str, Any]:
    engine = _exact_keys(value, PACKAGE_ENGINE_KEYS, label)
    expected_delegation = (
        "native-shards-rootless-systemd-v2"
        if architecture == "native-shards"
        else "rootless-systemd-v2"
    )
    if (
        engine["name"] != "podman"
        or not _string(engine["version"], f"{label}.version")
        or _boolean(engine["rootless"], f"{label}.rootless") is not True
        or engine["cgroups_version"] != "v2"
        or engine["cgroup_manager"] != "systemd"
        or engine["cgroup_delegation"] != expected_delegation
        or engine["host_architecture"] != architecture
        or _boolean(
            engine["service_is_remote"], f"{label}.service_is_remote"
        )
        is not False
    ):
        _fail(f"{label} lacks exact native rootless cgroup v2 evidence")
    _validate_cgroup_controllers(
        engine["cgroup_controllers"], f"{label}.cgroup_controllers"
    )
    identity_keys = ("effective_uid", "effective_gid", "uid_map", "gid_map")
    if architecture == "native-shards":
        if any(engine[key] is not None for key in identity_keys):
            _fail(f"{label} fabricates a common native rootless identity map")
    else:
        effective_uid = _integer(engine["effective_uid"], f"{label}.effective_uid")
        effective_gid = _integer(engine["effective_gid"], f"{label}.effective_gid")
        uid_map = _validate_id_map(engine["uid_map"], f"{label}.uid_map")
        gid_map = _validate_id_map(engine["gid_map"], f"{label}.gid_map")
        if (
            effective_uid <= 0
            or effective_gid <= 0
            or uid_map[0]["outside_id"] != effective_uid
            or gid_map[0]["outside_id"] != effective_gid
        ):
            _fail(f"{label} does not bind its effective rootless IDs to its maps")
    _validate_lifecycle_helper(
        engine["lifecycle_helper"],
        f"{label}.lifecycle_helper",
        aggregate=architecture == "native-shards",
    )
    return engine


def _validate_package_native_shards(value: Any) -> dict[str, dict[str, Any]]:
    native_shards = _exact_keys(
        value,
        PACKAGE_NATIVE_SHARDS_KEYS,
        "package.native_shards",
    )
    if _integer(native_shards["schema_version"], "package.native_shards.schema_version") != 1:
        _fail("package native shard schema version must be 1")
    if native_shards["mode"] != "native_architecture_shards_v1":
        _fail("package native shard mode is invalid")
    reports = _list(native_shards["reports"], "package.native_shards.reports")
    if len(reports) != 1:
        _fail("package native shard inventory must contain exactly one report")
    by_architecture: dict[str, dict[str, Any]] = {}
    architecture_order: list[str] = []
    helper_binding: tuple[Any, ...] | None = None
    for index, value in enumerate(reports):
        report = _exact_keys(
            value,
            PACKAGE_NATIVE_SHARD_RECORD_KEYS,
            f"package.native_shards.reports[{index}]",
        )
        architecture = _string(
            report["architecture"],
            f"package.native_shards.reports[{index}].architecture",
        )
        for key in (
            "host_architecture",
            "engine_name",
            "engine_version",
            "cgroups_version",
            "cgroup_manager",
            "cgroup_delegation",
            "engine_host_architecture",
        ):
            _string(
                report[key],
                f"package.native_shards.reports[{index}].{key}",
            )
        _sha256(
            report["report_sha256"],
            f"package.native_shards.reports[{index}].report_sha256",
        )
        if architecture in by_architecture or architecture != "amd64":
            _fail("package native shard architecture is duplicate or unsupported")
        controllers = _validate_cgroup_controllers(
            report["cgroup_controllers"],
            f"package.native_shards.reports[{index}].cgroup_controllers",
        )
        effective_uid = _integer(
            report["effective_uid"],
            f"package.native_shards.reports[{index}].effective_uid",
        )
        effective_gid = _integer(
            report["effective_gid"],
            f"package.native_shards.reports[{index}].effective_gid",
        )
        uid_map = _validate_id_map(
            report["uid_map"],
            f"package.native_shards.reports[{index}].uid_map",
        )
        gid_map = _validate_id_map(
            report["gid_map"],
            f"package.native_shards.reports[{index}].gid_map",
        )
        helper = _validate_lifecycle_helper(
            report["lifecycle_helper"],
            f"package.native_shards.reports[{index}].lifecycle_helper",
            aggregate=False,
        )
        binding = tuple(
            helper[key] for key in sorted(LIFECYCLE_HELPER_KEYS - {"source"})
        )
        if helper_binding is None:
            helper_binding = binding
        elif helper_binding != binding:
            _fail("package native shards used different lifecycle helper bytes")
        if (
            report["host_architecture"] != architecture
            or report["engine_name"] != "podman"
            or report["rootless"] is not True
            or report["cgroups_version"] != "v2"
            or report["cgroup_manager"] != "systemd"
            or report["cgroup_delegation"] != "rootless-systemd-v2"
            or report["engine_host_architecture"] != architecture
            or report["service_is_remote"] is not False
            or not {"cpu", "io", "memory", "pids"}.issubset(controllers)
            or effective_uid <= 0
            or effective_gid <= 0
            or uid_map[0]["outside_id"] != effective_uid
            or gid_map[0]["outside_id"] != effective_gid
        ):
            _fail("package native shard host or engine identity is invalid")
        by_architecture[architecture] = report
        architecture_order.append(architecture)
    if set(by_architecture) != {"amd64"}:
        _fail("package native shard architecture inventory is incomplete")
    if architecture_order != ["amd64"]:
        _fail("package native shard inventory order must contain AMD64 only")
    return by_architecture


def _validate_package_shard_binding(
    document: dict[str, Any],
    package_shards: dict[str, RawReport],
    expected_binding: dict[str, Any],
) -> None:
    binding = _validate_package_qualification_binding(
        document["qualification_binding"]
    )
    if binding != expected_binding:
        _fail("package qualification binding differs from the exact workflow inputs")
    records = _validate_package_native_shards(document["native_shards"])
    if set(package_shards) != {"amd64"}:
        _fail("package native shard file inventory is incomplete")
    for architecture in ("amd64",):
        raw = package_shards[architecture]
        record = records[architecture]
        if raw.snapshot.path.name != PACKAGE_NATIVE_SHARD_NAMES[architecture]:
            _fail(f"package {architecture} shard basename is invalid")
        if raw.snapshot.sha256 != record["report_sha256"]:
            _fail(f"package {architecture} shard digest differs from the aggregate")
        try:
            package_lab.validate_native_shard_report(
                raw.document,
                architecture=architecture,
                expected_binding=expected_binding,
            )
        except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
            raise AdapterError(
                f"invalid package {architecture} native shard evidence: {exc}"
            ) from exc
        engine = _validate_package_engine(
            raw.document["engine"],
            f"package.{architecture}.engine",
            architecture=architecture,
        )
        scope = raw.document["scope"]
        shard_helper = _validate_lifecycle_helper(
            engine["lifecycle_helper"],
            f"package.{architecture}.engine.lifecycle_helper",
            aggregate=False,
        )
        if record != {
            "architecture": architecture,
            "host_architecture": package_lab.normalize_host_architecture(
                scope["host_architecture"]
            ),
            "report_sha256": raw.snapshot.sha256,
            "engine_name": engine["name"],
            "engine_version": engine["version"],
            "rootless": engine["rootless"],
            "cgroups_version": engine["cgroups_version"],
            "cgroup_manager": engine["cgroup_manager"],
            "cgroup_delegation": engine["cgroup_delegation"],
            "cgroup_controllers": engine["cgroup_controllers"],
            "engine_host_architecture": engine["host_architecture"],
            "service_is_remote": engine["service_is_remote"],
            "effective_uid": engine["effective_uid"],
            "effective_gid": engine["effective_gid"],
            "uid_map": engine["uid_map"],
            "gid_map": engine["gid_map"],
            "lifecycle_helper": shard_helper,
        }:
            _fail(f"package {architecture} shard metadata differs from its report")
    shard_platforms = [
        platform
        for architecture in ("amd64",)
        for platform in package_shards[architecture].document["platforms"]
    ]
    if document.get("platforms") != shard_platforms:
        _fail("package aggregate platform evidence differs from its native shards")
    try:
        aggregate_status, aggregate_classification, aggregate_scope = (
            package_lab._aggregate_matrix_summary(shard_platforms)
        )
    except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError(
            f"invalid package native shard aggregate evidence: {exc}"
        ) from exc
    if (
        document.get("status") != aggregate_status
        or document.get("harness_complete")
        != aggregate_classification["harness_complete"]
        or document.get("release_ready")
        != aggregate_classification["release_ready"]
        or document.get("blocker_ids") != aggregate_classification["blocker_ids"]
        or document.get("unexpected_failed_checks")
        != aggregate_classification["unexpected_failed_checks"]
        or document.get("scope") != aggregate_scope
    ):
        _fail("package aggregate summary differs from its native shards")

    shard_contracts = [
        package_shards[architecture].document["package_version_contract"]
        for architecture in ("amd64",)
    ]
    expected_contract = {
        key: shard_contracts[0][key]
        for key in (
            "scheme",
            "relation",
            "previous_version",
            "candidate_version",
            "previous_numeric",
            "candidate_numeric",
        )
    }
    expected_contract["coordinates"] = sorted(
        [
            coordinate
            for contract in shard_contracts
            for coordinate in contract["coordinates"]
        ],
        key=lambda coordinate: coordinate["coordinate"],
    )
    if document.get("package_version_contract") != expected_contract:
        _fail("package aggregate version contract differs from its native shards")
    expected_engine_version = ";".join(
        f"{architecture}={records[architecture]['engine_version']}"
        for architecture in ("amd64",)
    )
    engine = document.get("engine")
    if not isinstance(engine, dict) or engine.get("version") != expected_engine_version:
        _fail("package aggregate engine version differs from native shard reports")


def _nullable_integer(value: Any, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _validate_cleanup_evidence(value: Any, label: str) -> dict[str, Any]:
    cleanup = _exact_keys(value, RUNTIME_CLEANUP_KEYS, label)
    if (
        _integer(cleanup["remove_exit_code"], f"{label}.remove_exit_code") != 0
        or _integer(
            cleanup["exists_probe_exit_code"],
            f"{label}.exists_probe_exit_code",
        )
        != 1
        or _boolean(
            cleanup["absent_after_cleanup"], f"{label}.absent_after_cleanup"
        )
        is not True
    ):
        _fail(f"{label} does not prove exact object removal")
    return cleanup


def _capability_has_sys_admin(value: Any, label: str) -> bool:
    encoded = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{16}", encoded) is None:
        _fail(f"{label} must be a canonical 64-bit capability mask")
    return bool(int(encoded, 16) & (1 << SYS_ADMIN_CAPABILITY_BIT))


def _capability_has_sys_ptrace(value: Any, label: str) -> bool:
    encoded = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{16}", encoded) is None:
        _fail(f"{label} must be a canonical 64-bit capability mask")
    return bool(int(encoded, 16) & (1 << SYS_PTRACE_CAPABILITY_BIT))


def _validate_process_security(
    value: Any,
    label: str,
    *,
    sys_admin_present: frozenset[str],
    sys_ptrace_present: frozenset[str],
) -> dict[str, Any]:
    security = _exact_keys(value, PROCESS_SECURITY_KEYS, label)
    capability_keys = (
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
    )
    for capability_name, detector, expected_keys in (
        ("SYS_ADMIN", _capability_has_sys_admin, sys_admin_present),
        ("SYS_PTRACE", _capability_has_sys_ptrace, sys_ptrace_present),
    ):
        for key in capability_keys:
            observed = detector(security[key], f"{label}.{key}")
            if observed is not (key in expected_keys):
                _fail(f"{label}.{key} has an unexpected {capability_name} state")
    if (
        _boolean(
            security["no_new_privileges"],
            f"{label}.no_new_privileges",
        )
        is not True
    ):
        _fail(f"{label} does not prove NoNewPrivs=1")
    return security


def _validate_id_map(value: Any, label: str) -> list[dict[str, Any]]:
    records = _list(value, label)
    if len(records) != 2:
        _fail(f"{label} must contain the exact two-range rootless map")
    parsed: list[dict[str, Any]] = []
    for index, raw in enumerate(records):
        record = _exact_keys(raw, ID_MAP_RANGE_KEYS, f"{label}[{index}]")
        parsed_record = {
            key: _integer(record[key], f"{label}[{index}].{key}")
            for key in ID_MAP_RANGE_KEYS
        }
        inside = parsed_record["inside_id"]
        outside = parsed_record["outside_id"]
        length = parsed_record["length"]
        if (
            min(inside, outside) < 0
            or length <= 0
            or max(inside, outside, length) > 4_294_967_295
            or inside + length > 4_294_967_296
            or outside + length > 4_294_967_296
        ):
            _fail(f"{label}[{index}] contains an invalid ID range")
        parsed.append(parsed_record)
    first, subordinate = parsed
    subordinate_start = subordinate["outside_id"]
    subordinate_end = subordinate_start + subordinate["length"]
    if (
        first["inside_id"] != 0
        or first["outside_id"] == 0
        or first["length"] != 1
        or subordinate["inside_id"] != 1
        or subordinate_start == 0
        or subordinate["length"] != 65_536
        or subordinate_start
        <= first["outside_id"]
        < subordinate_end
    ):
        _fail(f"{label} is not the exact default rootless map shape")
    return records


def _validate_setpriv(
    value: Any,
    spec: package_lab.PlatformSpec,
    label: str,
) -> dict[str, Any] | None:
    if spec.family == "apk":
        if value is not None:
            _fail(f"{label} must be null for OpenRC")
        return None
    provenance = _exact_keys(value, SETPRIV_KEYS, label)
    for key in (
        "path",
        "file_identity",
        "package_name",
        "package_version",
        "package_architecture",
    ):
        _string(provenance[key], f"{label}.{key}")
    _sha256(provenance["sha256"], f"{label}.sha256")
    if (
        provenance["path"] != "/usr/bin/setpriv"
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81ed:0:0",
            provenance["file_identity"],
        )
        is None
        or provenance["package_name"] != "util-linux"
        or re.fullmatch(
            r"[A-Za-z0-9.+:~_-]{1,128}",
            provenance["package_version"],
        )
        is None
        or provenance["package_architecture"] != spec.package_architecture
    ):
        _fail(f"{label} does not prove exact packaged setpriv provenance")
    return provenance


def _validate_product_services(
    value: Any,
    spec: package_lab.PlatformSpec,
    expectation: str,
    label: str,
) -> dict[str, Any]:
    services = _exact_keys(value, PRODUCT_SERVICES_KEYS, label)
    for key in (
        "expectation",
        "core_load_state",
        "core_enabled_state",
        "core_active_state",
        "firewall_load_state",
        "firewall_enabled_state",
        "firewall_active_state",
    ):
        _string(services[key], f"{label}.{key}")
    for key in (
        "core_fragment_path",
        "core_executable_path",
        "core_executable_identity",
        "core_pidfile_identity",
        "firewall_fragment_path",
    ):
        if services[key] is not None:
            _string(services[key], f"{label}.{key}")
    core_pid = _nullable_integer(services["core_main_pid"], f"{label}.core_main_pid")
    firewall_pid = _nullable_integer(
        services["firewall_main_pid"], f"{label}.firewall_main_pid"
    )
    if services["expectation"] != expectation:
        _fail(f"{label}.expectation differs from the runtime phase")
    manager = "openrc" if spec.family == "apk" else "systemd"
    core_fragment = (
        "/etc/init.d/syswarden-core"
        if manager == "openrc"
        else "/etc/systemd/system/syswarden-core.service"
    )
    firewall_fragment = (
        "/etc/init.d/syswarden-firewall"
        if manager == "openrc"
        else "/etc/systemd/system/syswarden-firewall.service"
    )
    if expectation == "active":
        _validate_process_security(
            services["core_process_security"],
            f"{label}.core_process_security",
            sys_admin_present=frozenset(),
            sys_ptrace_present=frozenset(),
        )
        expected = {
            "core_load_state": "loaded",
            "core_fragment_path": core_fragment,
            "core_enabled_state": "enabled",
            "core_active_state": "active",
            "core_executable_path": "/opt/syswarden/bin/syswarden-core",
            "firewall_load_state": "loaded",
            "firewall_fragment_path": firewall_fragment,
            "firewall_enabled_state": "enabled",
            "firewall_active_state": "active",
        }
        if (
            any(services[key] != expected_value for key, expected_value in expected.items())
            or core_pid is None
            or core_pid <= 1
            or firewall_pid != 0
            or re.fullmatch(
                r"[0-9]+:[0-9]+:81e8:0:0\|[0-9a-f]{64}",
                str(services["core_executable_identity"]),
            )
            is None
            or (
                spec.family == "apk"
                and re.fullmatch(
                    r"[0-9]+:[0-9]+:[0-9]+:0:0:644",
                    str(services["core_pidfile_identity"]),
                )
                is None
            )
            or (
                spec.family != "apk"
                and services["core_pidfile_identity"] is not None
            )
        ):
            _fail(f"{label} does not prove active product services")
    elif expectation == "absent":
        if services["core_process_security"] is not None:
            _fail(f"{label}.core_process_security must be null when core is absent")
        expected = {
            "core_load_state": "absent",
            "core_fragment_path": None,
            "core_enabled_state": "disabled",
            "core_active_state": "inactive",
            "core_executable_path": None,
            "core_executable_identity": None,
            "core_pidfile_identity": None,
            "firewall_load_state": "absent",
            "firewall_fragment_path": None,
            "firewall_enabled_state": "disabled",
            "firewall_active_state": "inactive",
        }
        if (
            any(services[key] != expected_value for key, expected_value in expected.items())
            or core_pid is not None
            or firewall_pid is not None
        ):
            _fail(f"{label} does not prove absent product services")
    else:
        _fail(f"{label} carries an unsupported product-service expectation")
    return services


def _validate_runtime_snapshot(
    value: Any,
    spec: package_lab.PlatformSpec,
    expectation: str,
    label: str,
    *,
    expected_uid_map: list[dict[str, Any]] | None = None,
    expected_gid_map: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    snapshot = _exact_keys(value, RUNTIME_SNAPSHOT_KEYS, label)
    if _integer(snapshot["capture_count"], f"{label}.capture_count") != 2:
        _fail(f"{label} must prove two byte-identical runtime captures")
    for key in (
        "pid1_comm",
        "pid1_exe",
        "manager_state",
        "manager_runtime",
        "cron_executable_path",
        "cron_executable_identity",
        "cron_fragment_path",
        "cron_fragment_identity",
        "cron_package_name",
        "cron_package_version",
        "cron_package_architecture",
        "cron_fragment_package_name",
        "cron_fragment_package_version",
        "cron_fragment_package_architecture",
        "dummy_interface",
    ):
        _string(snapshot[key], f"{label}.{key}")
    starttime = _integer(
        snapshot["pid1_starttime_ticks"], f"{label}.pid1_starttime_ticks"
    )
    cron_pid = _integer(snapshot["cron_main_pid"], f"{label}.cron_main_pid")
    rsyslog_pid = _integer(
        snapshot["rsyslog_main_pid"], f"{label}.rsyslog_main_pid"
    )
    for key in (
        "cron_enabled",
        "cron_active",
        "rsyslog_enabled",
        "rsyslog_active",
    ):
        if _boolean(snapshot[key], f"{label}.{key}") is not True:
            _fail(f"{label}.{key} must be true")
    manager = "openrc" if spec.family == "apk" else "systemd"
    pid1_systemd_capabilities = (
        SYSTEMD_MANAGER_CAPABILITY_KEYS
        if manager == "systemd"
        else frozenset()
    )
    _validate_process_security(
        snapshot["pid1_process_security"],
        f"{label}.pid1_process_security",
        sys_admin_present=pid1_systemd_capabilities,
        sys_ptrace_present=pid1_systemd_capabilities,
    )
    _validate_process_security(
        snapshot["attestation_process_security"],
        f"{label}.attestation_process_security",
        sys_admin_present=frozenset(),
        sys_ptrace_present=pid1_systemd_capabilities,
    )
    uid_map = _validate_id_map(snapshot["pid1_uid_map"], f"{label}.pid1_uid_map")
    gid_map = _validate_id_map(snapshot["pid1_gid_map"], f"{label}.pid1_gid_map")
    if (expected_uid_map is None) is not (expected_gid_map is None):
        _fail(f"{label} rootless map binding is internally incomplete")
    if expected_uid_map is not None and (
        uid_map != expected_uid_map or gid_map != expected_gid_map
    ):
        _fail(f"{label} rootless maps differ from the native engine shard")
    _validate_setpriv(snapshot["setpriv"], spec, f"{label}.setpriv")
    expected_pid1 = "openrc-init" if manager == "openrc" else "systemd"
    expected_runtime = "default" if manager == "openrc" else "running"
    valid_executable = (
        snapshot["pid1_exe"] == "/sbin/openrc-init"
        if manager == "openrc"
        else snapshot["pid1_exe"]
        in {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}
    )
    expected_cron_executable = package_lab.expected_cron_executable(spec)
    expected_cron_fragments = (
        {"/etc/init.d/cronie"}
        if spec.family == "apk"
        else {
            "/lib/systemd/system/cron.service",
            "/usr/lib/systemd/system/cron.service",
        }
        if spec.family == "deb"
        else {"/usr/lib/systemd/system/crond.service"}
    )
    expected_cron_fragment_mode = "81ed" if spec.family == "apk" else "81a4"
    expected_cron_dropin_paths = (
        [package_lab.FEDORA_CRON_DROPIN_PATH]
        if spec.distribution == "fedora"
        else []
    )
    expected_cron_package = "cron" if spec.family == "deb" else "cronie"
    expected_fragment_package = (
        "cronie-openrc" if spec.family == "apk" else expected_cron_package
    )
    if (
        snapshot["manager_state"] != "ACTIVE"
        or snapshot["pid1_comm"] != expected_pid1
        or not valid_executable
        or snapshot["manager_runtime"] != expected_runtime
        or snapshot["cron_executable_path"] != expected_cron_executable
        or re.fullmatch(
            r"[0-9]+:[0-9]+:81ed:0:0\|[0-9a-f]{64}",
            snapshot["cron_executable_identity"],
        )
        is None
        or snapshot["cron_fragment_path"] not in expected_cron_fragments
        or re.fullmatch(
            rf"[0-9]+:[0-9]+:{expected_cron_fragment_mode}:0:0\|[0-9a-f]{{64}}",
            snapshot["cron_fragment_identity"],
        )
        is None
        or snapshot["cron_dropin_paths"] != expected_cron_dropin_paths
        or snapshot["cron_package_name"] != expected_cron_package
        or re.fullmatch(
            r"[A-Za-z0-9.+:~_-]{1,128}", snapshot["cron_package_version"]
        )
        is None
        or snapshot["cron_package_architecture"] != spec.package_architecture
        or snapshot["cron_fragment_package_name"] != expected_fragment_package
        or snapshot["cron_fragment_package_version"]
        != snapshot["cron_package_version"]
        or snapshot["cron_fragment_package_architecture"]
        != spec.package_architecture
        or snapshot["dummy_interface"] != "eth0:dummy:up"
        or min(starttime, cron_pid, rsyslog_pid) <= 1
    ):
        _fail(f"{label} does not prove an ACTIVE real-init runtime")
    _validate_product_services(
        snapshot["product_services"], spec, expectation, f"{label}.product_services"
    )
    return snapshot


def _validate_runtime_isolation(
    value: Any,
    spec: package_lab.PlatformSpec,
    label: str,
) -> dict[str, Any]:
    isolation = _exact_keys(value, RUNTIME_ISOLATION_KEYS, label)
    expected_caps = (
        ["CAP_NET_ADMIN", "CAP_SYS_BOOT"]
        if spec.family == "apk"
        else ["CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
    )
    expected_launcher = (
        OPENRC_LIFECYCLE_EXEC_LAUNCHER
        if spec.family == "apk"
        else SYSTEMD_LIFECYCLE_EXEC_LAUNCHER
    )
    expected_stop = "SIGINT" if spec.family == "apk" else "SIGRTMIN+3"
    scalar_contract = {
        "network_mode": "none",
        "pid_mode": "private",
        "ipc_mode": "private",
        "uts_mode": "private",
        "userns_mode": "rootless-default",
        "cgroup_mode": "private",
        "cap_add": expected_caps,
        "cap_drop": [],
        "lifecycle_exec_launcher": list(expected_launcher),
        "devices": [],
        "security_opts": ["label=disable", "no-new-privileges"],
        "stop_signal": expected_stop,
    }
    if (
        _boolean(isolation["privileged"], f"{label}.privileged") is not False
        or any(
            isolation[key] != expected
            for key, expected in scalar_contract.items()
        )
    ):
        _fail(f"{label} namespace, capability, or device isolation is not exact")
    tmpfs = _exact_keys(isolation["tmpfs"], {"/run", "/tmp"}, f"{label}.tmpfs")
    expected_tmpfs = {
        "/run": ["exec", "mode=755", "nodev", "nosuid", "rw", "size=64m"],
        "/tmp": ["exec", "mode=1777", "nodev", "nosuid", "rw", "size=256m"],
    }
    if tmpfs != expected_tmpfs:
        _fail(f"{label}.tmpfs differs from the bounded runtime contract")
    mounts = _list(isolation["mounts"], f"{label}.mounts")
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
    for index, mount in enumerate(mounts):
        mount = _exact_keys(
            mount, RUNTIME_MOUNT_KEYS, f"{label}.mounts[{index}]"
        )
        _boolean(mount["read_only"], f"{label}.mounts[{index}].read_only")
    if mounts != expected_mounts:
        _fail(f"{label}.mounts exposes an unexpected or writable host path")
    return isolation


def _validate_runtime_boots(
    value: Any,
    spec: package_lab.PlatformSpec,
    scenario: str,
    label: str,
    *,
    expected_uid_map: list[dict[str, Any]] | None = None,
    expected_gid_map: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    boots = _list(value, label)
    invocations = (
        ("initial", "restart-one", "restart-two")
        if scenario == "upgrade-rollback"
        else ("initial",)
    )
    if len(boots) != len(invocations):
        _fail(f"{label} does not contain the exact boot/restart count")
    previous_post_starttime: int | None = None
    previous_cron_provenance: tuple[Any, ...] | None = None
    previous_rootless_provenance: tuple[Any, ...] | None = None
    expected_restart_states = (
        ("restart-one", "restart-two", "complete")
        if scenario == "upgrade-rollback"
        else (None,)
    )
    for index, (boot_value, invocation, restart_state) in enumerate(
        zip(boots, invocations, expected_restart_states, strict=True)
    ):
        boot_label = f"{label}[{index}]"
        boot = _exact_keys(boot_value, RUNTIME_BOOT_KEYS, boot_label)
        if (
            boot["invocation"] != invocation
            or _integer(
                boot["boot_command_exit_code"],
                f"{boot_label}.boot_command_exit_code",
            )
            != 0
            or _integer(
                boot["script_exec_exit_code"],
                f"{boot_label}.script_exec_exit_code",
            )
            != 0
            or boot["restart_state"] != restart_state
        ):
            _fail(f"{boot_label} invocation or exit evidence is not exact")
        lifecycle_exec_security = _validate_process_security(
            boot["lifecycle_exec_security"],
            f"{boot_label}.lifecycle_exec_security",
            sys_admin_present=frozenset(),
            sys_ptrace_present=(
                SYSTEMD_MANAGER_CAPABILITY_KEYS
                if spec.family != "apk"
                else frozenset()
            ),
        )
        restart = _exact_keys(
            boot["restart"], RUNTIME_RESTART_KEYS, f"{boot_label}.restart"
        )
        if invocation == "initial":
            if (
                _boolean(
                    restart["performed"], f"{boot_label}.restart.performed"
                )
                is not False
                or restart["command_exit_code"] is not None
                or restart["previous_pid1_starttime_ticks"] is not None
                or restart["distinct"] is not None
            ):
                _fail(f"{boot_label} initial boot carries forged restart evidence")
        else:
            if (
                restart["performed"] is not True
                or _integer(
                    restart["command_exit_code"],
                    f"{boot_label}.restart.command_exit_code",
                )
                != 0
                or _integer(
                    restart["previous_pid1_starttime_ticks"],
                    f"{boot_label}.restart.previous_pid1_starttime_ticks",
                )
                != previous_post_starttime
                or restart["distinct"] is not True
            ):
                _fail(f"{boot_label} does not prove a real distinct PID1 restart")
        pre_expectation = "absent" if invocation == "initial" else "active"
        post_expectation = "active" if scenario == "upgrade-rollback" else "absent"
        pre = _validate_runtime_snapshot(
            boot["pre_exec"],
            spec,
            pre_expectation,
            f"{boot_label}.pre_exec",
            expected_uid_map=expected_uid_map,
            expected_gid_map=expected_gid_map,
        )
        post = _validate_runtime_snapshot(
            boot["post_exec"],
            spec,
            post_expectation,
            f"{boot_label}.post_exec",
            expected_uid_map=expected_uid_map,
            expected_gid_map=expected_gid_map,
        )
        cron_provenance_keys = (
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
        pre_cron_provenance = tuple(pre[key] for key in cron_provenance_keys)
        post_cron_provenance = tuple(post[key] for key in cron_provenance_keys)
        rootless_provenance_keys = (
            "pid1_process_security",
            "attestation_process_security",
            "pid1_uid_map",
            "pid1_gid_map",
            "setpriv",
        )
        pre_rootless_provenance = tuple(
            pre[key] for key in rootless_provenance_keys
        )
        post_rootless_provenance = tuple(
            post[key] for key in rootless_provenance_keys
        )
        if (
            pre["pid1_starttime_ticks"] != post["pid1_starttime_ticks"]
            or pre["cron_main_pid"] != post["cron_main_pid"]
            or pre_cron_provenance != post_cron_provenance
            or pre_rootless_provenance != post_rootless_provenance
            or lifecycle_exec_security != pre["attestation_process_security"]
            or (
                previous_cron_provenance is not None
                and pre_cron_provenance != previous_cron_provenance
            )
            or (
                previous_rootless_provenance is not None
                and pre_rootless_provenance != previous_rootless_provenance
            )
            or (
                invocation != "initial"
                and pre["pid1_starttime_ticks"] == previous_post_starttime
            )
        ):
            _fail(f"{boot_label} process continuity/restart evidence is inconsistent")
        previous_post_starttime = post["pid1_starttime_ticks"]
        previous_cron_provenance = post_cron_provenance
        previous_rootless_provenance = post_rootless_provenance
    return boots


def _validate_runtime_scenario(
    value: Any,
    spec: package_lab.PlatformSpec,
    scenario: str,
    label: str,
    *,
    expected_uid_map: list[dict[str, Any]] | None = None,
    expected_gid_map: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = _exact_keys(value, PACKAGE_SCENARIO_KEYS, label)
    required_boots = 3 if scenario == "upgrade-rollback" else 1
    exec_exit_codes = _list(
        result["lifecycle_exec_exit_codes"], f"{label}.lifecycle_exec_exit_codes"
    )
    if (
        result["name"] != scenario
        or result["status"] != "pass"
        or result["runtime_mode"] != "active-real-init"
        or _integer(
            result["container_create_exit_code"],
            f"{label}.container_create_exit_code",
        )
        != 0
        or len(exec_exit_codes) != required_boots
        or any(
            _integer(code, f"{label}.lifecycle_exec_exit_codes[{index}]") != 0
            for index, code in enumerate(exec_exit_codes)
        )
        or result["restart_state"]
        != ("complete" if scenario == "upgrade-rollback" else None)
        or result["orchestration_error"] is not None
    ):
        _fail(f"{label} does not prove the ACTIVE lifecycle scenario")
    _validate_runtime_isolation(result["isolation"], spec, f"{label}.isolation")
    _validate_runtime_boots(
        result["boots"],
        spec,
        scenario,
        f"{label}.boots",
        expected_uid_map=expected_uid_map,
        expected_gid_map=expected_gid_map,
    )
    _validate_cleanup_evidence(result["cleanup"], f"{label}.cleanup")
    events = _list(result["events"], f"{label}.events")
    for event_index, event_value in enumerate(events):
        event = _exact_keys(
            event_value,
            {"status", "check", "detail"},
            f"{label}.events[{event_index}]",
        )
        if event["status"] != "pass":
            _fail(f"{label} contains a non-passing lifecycle event")
        _string(event["check"], f"{label}.events[{event_index}].check")
        _string(
            event["detail"], f"{label}.events[{event_index}].detail", empty=True
        )
    try:
        package_lab.validate_event_contract(events, spec.family, scenario)
    except package_lab.LifecycleLabError as exc:
        raise AdapterError(f"{label} event contract is invalid: {exc}") from exc
    _string(result["log_tail"], f"{label}.log_tail", empty=True)
    return result


def _passing_event(scenario: dict[str, Any], check: str) -> bool:
    return any(
        event.get("status") == "pass" and event.get("check") == check
        for event in scenario["events"]
        if isinstance(event, dict)
    )


def _derive_runtime_boundary_prerequisites(
    platform: dict[str, Any],
    spec: package_lab.PlatformSpec,
) -> tuple[bool, bool]:
    manager_complete = True
    lifecycle_and_core_complete = True
    active_core_count = 0
    pid1_systemd_capabilities = (
        frozenset()
        if spec.family == "apk"
        else SYSTEMD_MANAGER_CAPABILITY_KEYS
    )
    for scenario_index, scenario in enumerate(platform["scenarios"]):
        label = f"derived.scenarios[{scenario_index}]"
        try:
            _validate_runtime_isolation(scenario["isolation"], spec, f"{label}.isolation")
        except (AdapterError, KeyError, TypeError):
            manager_complete = False
            lifecycle_and_core_complete = False
        for boot_index, boot in enumerate(scenario["boots"]):
            boot_label = f"{label}.boots[{boot_index}]"
            try:
                lifecycle_security = _validate_process_security(
                    boot["lifecycle_exec_security"],
                    f"{boot_label}.lifecycle_exec_security",
                    sys_admin_present=frozenset(),
                    sys_ptrace_present=pid1_systemd_capabilities,
                )
            except (AdapterError, KeyError, TypeError):
                lifecycle_and_core_complete = False
                lifecycle_security = None
            for phase in ("pre_exec", "post_exec"):
                try:
                    snapshot = boot[phase]
                except (KeyError, TypeError):
                    manager_complete = False
                    lifecycle_and_core_complete = False
                    continue
                try:
                    _validate_process_security(
                        snapshot["pid1_process_security"],
                        f"{boot_label}.{phase}.pid1_process_security",
                        sys_admin_present=pid1_systemd_capabilities,
                        sys_ptrace_present=pid1_systemd_capabilities,
                    )
                    _validate_id_map(
                        snapshot["pid1_uid_map"],
                        f"{boot_label}.{phase}.pid1_uid_map",
                    )
                    _validate_id_map(
                        snapshot["pid1_gid_map"],
                        f"{boot_label}.{phase}.pid1_gid_map",
                    )
                except (AdapterError, KeyError, TypeError):
                    manager_complete = False
                try:
                    attestation_security = _validate_process_security(
                        snapshot["attestation_process_security"],
                        f"{boot_label}.{phase}.attestation_process_security",
                        sys_admin_present=frozenset(),
                        sys_ptrace_present=pid1_systemd_capabilities,
                    )
                    _validate_setpriv(
                        snapshot["setpriv"],
                        spec,
                        f"{boot_label}.{phase}.setpriv",
                    )
                    if (
                        lifecycle_security is not None
                        and attestation_security != lifecycle_security
                    ):
                        lifecycle_and_core_complete = False
                    core_security = snapshot["product_services"][
                        "core_process_security"
                    ]
                    core_expected = (
                        snapshot["product_services"]["expectation"] == "active"
                    )
                    if core_expected:
                        if core_security is None:
                            lifecycle_and_core_complete = False
                        else:
                            active_core_count += 1
                            _validate_process_security(
                                core_security,
                                f"{boot_label}.{phase}.core_process_security",
                                sys_admin_present=frozenset(),
                                sys_ptrace_present=frozenset(),
                            )
                    elif core_security is not None:
                        lifecycle_and_core_complete = False
                except (AdapterError, KeyError, TypeError):
                    lifecycle_and_core_complete = False
    return manager_complete, lifecycle_and_core_complete and active_core_count > 0


def _derive_platform_lifecycle_claims(
    platform: dict[str, Any], spec: package_lab.PlatformSpec
) -> dict[str, bool]:
    scenarios = {item["name"]: item for item in platform["scenarios"]}
    upgrade = scenarios["upgrade-rollback"]
    remove = scenarios["remove"]
    purge = scenarios.get("purge")
    installed_postinstall_checks = [
        "upgrade-rollback.candidate.postinstall_contract",
        "upgrade-rollback.reinstall.postinstall_contract",
        "upgrade-rollback.restart-one.postinstall_contract",
        "upgrade-rollback.restart-two.postinstall_contract",
        "upgrade-rollback.recovery.postinstall_contract",
        "remove.fresh.postinstall_contract",
    ]
    if purge is not None:
        installed_postinstall_checks.append("purge.fresh.postinstall_contract")
    installed_scenarios = {
        check: upgrade if check.startswith("upgrade-rollback.") else remove
        if check.startswith("remove.")
        else purge
        for check in installed_postinstall_checks
    }
    runtime_snapshots = [
        boot[phase]
        for scenario in platform["scenarios"]
        for boot in scenario["boots"]
        for phase in ("pre_exec", "post_exec")
    ]
    cron_provenance = {
        (
            snapshot["cron_executable_path"],
            snapshot["cron_executable_identity"],
            snapshot["cron_fragment_path"],
            snapshot["cron_fragment_identity"],
            tuple(snapshot["cron_dropin_paths"]),
            snapshot["cron_package_name"],
            snapshot["cron_package_version"],
            snapshot["cron_package_architecture"],
            snapshot["cron_fragment_package_name"],
            snapshot["cron_fragment_package_version"],
            snapshot["cron_fragment_package_architecture"],
        )
        for snapshot in runtime_snapshots
    }
    removal_check = (
        "remove.final-removal.purge-equivalent"
        if spec.family == "rpm"
        else "remove.remove"
    )
    purge_claim = (
        _passing_event(remove, "remove.final-removal.purge-equivalent")
        if spec.family == "rpm"
        else purge is not None
        and _passing_event(purge, "purge.purge")
        and purge["boots"][-1]["post_exec"]["product_services"]["expectation"]
        == "absent"
    )
    upgrade_boots = upgrade["boots"]
    manager_boundary, postinstall_boundary = _derive_runtime_boundary_prerequisites(
        platform, spec
    )
    return {
        "active_service_manager": all(
            snapshot["manager_state"] == "ACTIVE"
            and snapshot["capture_count"] == 2
            for snapshot in runtime_snapshots
        )
        and len(cron_provenance) == 1
        and manager_boundary,
        "active_postinstall": all(
            scenario is not None and _passing_event(scenario, check)
            for check, scenario in installed_scenarios.items()
        )
        and postinstall_boundary,
        "legacy_runtime_retirement": all(
            scenario is not None
            and any(
                event.get("status") == "pass"
                and event.get("check") == check
                and "browser-service retirement" in str(event.get("detail", ""))
                for event in scenario["events"]
            )
            for check, scenario in installed_scenarios.items()
        ),
        "fresh_install": _passing_event(remove, "remove.install.candidate")
        and _passing_event(remove, "remove.fresh.postinstall_contract"),
        "upgrade": _passing_event(upgrade, "upgrade-rollback.upgrade.candidate")
        and _passing_event(
            upgrade, "upgrade-rollback.upgrade.candidate.maintainer_script"
        )
        and _passing_event(upgrade, "upgrade-rollback.candidate.postinstall_contract"),
        "reinstall": _passing_event(upgrade, "upgrade-rollback.reinstall.candidate")
        and _passing_event(
            upgrade, "upgrade-rollback.reinstall.candidate.maintainer_script"
        )
        and _passing_event(upgrade, "upgrade-rollback.reinstall.postinstall_contract"),
        "rollback": _passing_event(upgrade, "upgrade-rollback.rollback.previous")
        and _passing_event(
            upgrade, "upgrade-rollback.rollback.previous.maintainer_script"
        )
        and _passing_event(upgrade, "upgrade-rollback.rollback.postinstall_contract")
        and _passing_event(upgrade, "upgrade-rollback.recovery.candidate")
        and _passing_event(upgrade, "upgrade-rollback.recovery.postinstall_contract"),
        "remove": _passing_event(remove, removal_check)
        and remove["boots"][-1]["post_exec"]["product_services"]["expectation"]
        == "absent",
        "purge": bool(purge_claim),
        "second_restart": upgrade["restart_state"] == "complete"
        and [boot["invocation"] for boot in upgrade_boots]
        == ["initial", "restart-one", "restart-two"]
        and [boot["restart_state"] for boot in upgrade_boots]
        == ["restart-one", "restart-two", "complete"]
        and all(
            boot["restart"]["performed"] is True
            and boot["restart"]["distinct"] is True
            for boot in upgrade_boots[1:]
        ),
    }


def _validate_package_schema(document: dict[str, Any]) -> None:
    _validate_package_qualification_binding(document["qualification_binding"])
    native_records = _validate_package_native_shards(document["native_shards"])
    contract = _exact_keys(
        document["package_version_contract"], PACKAGE_CONTRACT_KEYS, "package.version_contract"
    )
    for key in ("scheme", "relation", "previous_version", "candidate_version"):
        _string(contract[key], f"package.version_contract.{key}")
    for key in ("previous_numeric", "candidate_numeric"):
        numbers = _list(contract[key], f"package.version_contract.{key}")
        if len(numbers) != 3 or any(type(item) is not int or item < 0 for item in numbers):
            _fail(f"package.version_contract.{key} must contain three non-negative integers")
    coordinates = _list(contract["coordinates"], "package.version_contract.coordinates")
    if len(coordinates) != 3:
        _fail("package version contract must contain exactly three package coordinates")
    for index, item in enumerate(coordinates):
        coordinate = _exact_keys(
            item, PACKAGE_CONTRACT_COORDINATE_KEYS, f"package.version_contract.coordinates[{index}]"
        )
        for key in ("coordinate", "family", "package_architecture", "previous_version", "candidate_version"):
            _string(coordinate[key], f"package.version_contract.coordinates[{index}].{key}")
        for key in ("previous_numeric", "candidate_numeric"):
            values = _list(coordinate[key], f"package.version_contract.coordinates[{index}].{key}")
            if len(values) != 3 or any(type(value) is not int for value in values):
                _fail("package coordinate numeric version is invalid")

    scope = _exact_keys(document["scope"], PACKAGE_SCOPE_KEYS, "package.scope")
    _boolean(scope["container_lab_complete"], "package.scope.container_lab_complete")
    for key in (
        "host_architecture",
        "network_during_image_bootstrap",
        "network_during_package_operations",
        "host_mutation",
        "architecture_coverage_policy",
        "rollback_model",
    ):
        _string(scope[key], f"package.scope.{key}")
    normalized_host_architecture = package_lab.normalize_host_architecture(
        scope["host_architecture"]
    )
    native_aggregate = scope["host_architecture"] == PACKAGE_NATIVE_AGGREGATE_HOST
    if not native_aggregate or normalized_host_architecture is not None:
        _fail("package report must identify the exact AMD64 native shard model")
    if scope["network_during_package_operations"] != "disabled":
        _fail("package operations were not network-isolated")
    classification = _list(scope["coordinate_classification"], "package.scope.coordinate_classification")
    if len(classification) != 5:
        _fail("package coordinate classification must contain exactly five coordinates")
    for index, item in enumerate(classification):
        entry = _exact_keys(
            item,
            {"distribution", "architecture_id", "family", "status", "blocker_ids"},
            f"package.scope.coordinate_classification[{index}]",
        )
        for key in ("distribution", "architecture_id", "family", "status"):
            _string(entry[key], f"package.scope.coordinate_classification[{index}].{key}")
        _string_list(entry["blocker_ids"], f"package.scope.coordinate_classification[{index}].blocker_ids", sorted_unique=True)
    for key in ("architectures_completed",):
        _string_list(scope[key], f"package.scope.{key}")
    incomplete = _list(scope["architectures_incomplete_or_failed"], "package.scope.architectures_incomplete_or_failed")
    for index, item in enumerate(incomplete):
        entry = _exact_keys(item, {"architecture", "status", "reason"}, f"package.scope.architectures_incomplete_or_failed[{index}]")
        for key in entry:
            _string(entry[key], f"package.scope.architectures_incomplete_or_failed[{index}].{key}")
    architecture_coverage = _list(scope["architecture_coverage"], "package.scope.architecture_coverage")
    if len(architecture_coverage) != 1:
        _fail("package architecture coverage must contain AMD64 only")
    for index, item in enumerate(architecture_coverage):
        entry = _exact_keys(item, {"architecture", "architecture_id", "status", "required_distributions", "completed_distributions", "incomplete_or_failed_distributions"}, f"package.scope.architecture_coverage[{index}]")
        for key in ("architecture", "architecture_id", "status"):
            _string(entry[key], f"package.scope.architecture_coverage[{index}].{key}")
        for key in ("required_distributions", "completed_distributions", "incomplete_or_failed_distributions"):
            _string_list(entry[key], f"package.scope.architecture_coverage[{index}].{key}")
    family_coverage = _list(scope["family_architecture_coverage"], "package.scope.family_architecture_coverage")
    if len(family_coverage) != 3:
        _fail("package family/architecture coverage must contain three coordinates")
    for index, item in enumerate(family_coverage):
        entry = _exact_keys(item, {"family", "architecture", "architecture_id", "status", "required_distributions", "completed_distributions"}, f"package.scope.family_architecture_coverage[{index}]")
        for key in ("family", "architecture", "architecture_id", "status"):
            _string(entry[key], f"package.scope.family_architecture_coverage[{index}].{key}")
        for key in ("required_distributions", "completed_distributions"):
            _string_list(entry[key], f"package.scope.family_architecture_coverage[{index}].{key}")
    for key in ("required_platform_coordinates", "missing_platform_coordinates"):
        entries = _list(scope[key], f"package.scope.{key}")
        for index, item in enumerate(entries):
            entry = _exact_keys(item, {"distribution", "architecture"}, f"package.scope.{key}[{index}]")
            _string(entry["distribution"], f"package.scope.{key}[{index}].distribution")
            _string(entry["architecture"], f"package.scope.{key}[{index}].architecture")

    engine = _validate_package_engine(
        document["engine"], "package.engine", architecture="native-shards"
    )
    expected_engine_version = ";".join(
        f"{architecture}={native_records[architecture]['engine_version']}"
        for architecture in ("amd64",)
    )
    controller_intersection = sorted(
        set(native_records["amd64"]["cgroup_controllers"])
    )
    helper_keys = sorted(LIFECYCLE_HELPER_KEYS - {"source"})
    aggregate_helper_binding = tuple(
        engine["lifecycle_helper"][key] for key in helper_keys
    )
    shard_helper_binding = tuple(
        native_records["amd64"]["lifecycle_helper"][key]
        for key in helper_keys
    )
    if (
        engine["version"] != expected_engine_version
        or engine["cgroup_controllers"] != controller_intersection
        or aggregate_helper_binding != shard_helper_binding
    ):
        _fail("package aggregate engine dilutes native shard evidence")

    roots = _exact_keys(document["package_roots"], {"candidate", "previous", "mount_mode"}, "package.package_roots")
    _string(roots["candidate"], "package.package_roots.candidate")
    _string(roots["previous"], "package.package_roots.previous")
    if roots["mount_mode"] != "read-only":
        _fail("package roots were not mounted read-only")

    platforms = _list(document["platforms"], "package.platforms")
    if len(platforms) != 5:
        _fail("package report must contain exactly five platform results")
    seen: set[tuple[str, str]] = set()
    specs = {(item.distribution, item.architecture): item for item in package_lab.DEFAULT_PLATFORMS}
    for index, item in enumerate(platforms):
        platform = _exact_keys(item, PACKAGE_PLATFORM_KEYS, f"package.platforms[{index}]")
        for key in ("name", "distribution", "family", "architecture", "architecture_id", "package_architecture", "podman_platform", "image", "purge_semantics", "candidate_version", "previous_version", "bootstrap_execution", "lifecycle_network", "runtime_mode", "restart_contract", "status"):
            _string(platform[key], f"package.platforms[{index}].{key}")
        coordinate = (platform["distribution"], platform["architecture_id"])
        if coordinate in seen or coordinate not in specs:
            _fail(f"package platform coordinate is duplicate or unsupported: {coordinate}")
        seen.add(coordinate)
        spec = specs[coordinate]
        expected = {
            "name": spec.name,
            "family": spec.family,
            "architecture": package_lab.ARCHITECTURE_LABELS[spec.architecture],
            "package_architecture": spec.package_architecture,
            "podman_platform": spec.podman_platform,
            "image": spec.image,
            "purge_semantics": spec.purge_semantics,
        }
        if any(platform[key] != value for key, value in expected.items()):
            _fail(f"package platform metadata differs from the pinned matrix at {coordinate}")
        if (
            platform["lifecycle_network"] != "disabled"
            or platform["runtime_mode"] != "active-real-init"
            or platform["restart_contract"] != package_lab.ACTIVE_RESTART_CONTRACT
            or _boolean(
                platform["package_bytes_differ"],
                f"package.platforms[{index}].package_bytes_differ",
            )
            is not True
        ):
            _fail(f"package lifecycle isolation/byte distinction is invalid at {coordinate}")
        _validate_cleanup_evidence(
            platform["bootstrap_image_cleanup"],
            f"package.platforms[{index}].bootstrap_image_cleanup",
        )
        for artifact_key in ("candidate", "previous"):
            artifact = _exact_keys(platform[artifact_key], {"filename", "version", "sha256"}, f"package.platforms[{index}].{artifact_key}")
            _string(artifact["filename"], f"package.platforms[{index}].{artifact_key}.filename")
            _string(artifact["version"], f"package.platforms[{index}].{artifact_key}.version")
            _sha256(artifact["sha256"], f"package.platforms[{index}].{artifact_key}.sha256")
        probe = _exact_keys(platform["architecture_probe"], {"status", "execution_mode", "podman_platform", "expected_uname", "actual_uname", "container_exit_code", "network", "filesystem"}, f"package.platforms[{index}].architecture_probe")
        for key in ("status", "execution_mode", "podman_platform", "expected_uname", "actual_uname", "network", "filesystem"):
            _string(probe[key], f"package.platforms[{index}].architecture_probe.{key}")
        if (
            probe["status"] != "available"
            or probe["network"] != "disabled"
            or _integer(
                probe["container_exit_code"],
                f"package.platforms[{index}].architecture_probe.container_exit_code",
            )
            != 0
            or probe["podman_platform"] != spec.podman_platform
            or probe["expected_uname"] != spec.uname_architecture
            or probe["actual_uname"] != spec.uname_architecture
            or probe["execution_mode"] != "native"
            or platform["bootstrap_execution"] != "native_container_build"
        ):
            _fail(f"package architecture execution probe is incomplete at {coordinate}")
        scenarios = _list(platform["scenarios"], f"package.platforms[{index}].scenarios")
        expected_scenarios = package_lab.EXPECTED_SCENARIOS[spec.family]
        if [
            item.get("name") if isinstance(item, dict) else None
            for item in scenarios
        ] != list(expected_scenarios):
            _fail(f"package scenario inventory is not exact at {coordinate}")
        for scenario_index, scenario_value in enumerate(scenarios):
            scenario_label = (
                f"package.platforms[{index}].scenarios[{scenario_index}]"
            )
            scenario = _validate_runtime_scenario(
                scenario_value,
                spec,
                expected_scenarios[scenario_index],
                scenario_label,
                expected_uid_map=native_records[spec.architecture]["uid_map"],
                expected_gid_map=native_records[spec.architecture]["gid_map"],
            )
            inventory = _exact_keys(
                scenario["inventory_evidence"],
                set(package_lab.expected_inventory_phase_labels(scenario["name"])),
                "package scenario inventory evidence",
            )
            for phase_name, phase_value in inventory.items():
                phase = _exact_keys(phase_value, {"manager_paths", "filesystem"}, f"package inventory {phase_name}")
                _string_list(phase["manager_paths"], f"package inventory {phase_name}.manager_paths")
                filesystem = _list(phase["filesystem"], f"package inventory {phase_name}.filesystem")
                for entry_index, entry_value in enumerate(filesystem):
                    entry = _exact_keys(entry_value, {"path", "type", "mode", "uid", "gid", "value"}, f"package inventory {phase_name}.filesystem[{entry_index}]")
                    for key in ("path", "type", "mode", "value"):
                        _string(entry[key], f"package inventory filesystem.{key}", empty=key == "value")
                    for key in ("uid", "gid"):
                        _integer(entry[key], f"package inventory filesystem.{key}")
    if seen != package_lab.REQUIRED_PLATFORM_COORDINATES:
        _fail("package platform matrix is incomplete")


def _validate_package(
    document: dict[str, Any],
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
    package_shards: dict[str, RawReport],
    expected_qualification_binding: dict[str, Any],
) -> dict[str, Any]:
    _validate_package_schema(document)
    _validate_package_shard_binding(
        document,
        package_shards,
        expected_qualification_binding,
    )
    try:
        package_lab.validate_report_version_contract(document)
        classification = package_lab.classify_lifecycle_evidence(document["platforms"])
    except (package_lab.LifecycleLabError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError(f"invalid package lifecycle evidence: {exc}") from exc
    for key in ("harness_complete", "release_ready"):
        _boolean(document[key], f"package.{key}")
    blockers = _string_list(document["blocker_ids"], "package.blocker_ids", sorted_unique=True)
    unexpected = _string_list(document["unexpected_failed_checks"], "package.unexpected_failed_checks", sorted_unique=True)
    for key in ("harness_complete", "release_ready", "blocker_ids", "unexpected_failed_checks"):
        if document[key] != classification[key]:
            _fail(f"package.{key} is not derived from lifecycle evidence")
    if classification["harness_complete"] is not True or unexpected:
        _fail("package lifecycle harness is incomplete or contains unexpected failures")
    if blockers:
        _fail("package lifecycle evidence may not carry a generic product waiver")
    expected_status = "pass" if classification["release_ready"] else "fail"
    if document["status"] != expected_status:
        _fail("package status is inconsistent with recomputed lifecycle evidence")
    # These paths are provenance only.  Durable artifacts are intentionally
    # extracted elsewhere; basenames and independently verified digests below
    # are the relocation-safe package binding.
    roots = document["package_roots"]
    raw_candidate_root = Path(roots["candidate"])
    raw_previous_root = Path(roots["previous"])
    if (
        not raw_candidate_root.is_absolute()
        or not raw_previous_root.is_absolute()
        or raw_candidate_root == raw_previous_root
    ):
        _fail("package raw roots must record two distinct absolute laboratory paths")
    contract = document["package_version_contract"]
    candidate_version = contract["candidate_version"]
    previous_version = contract["previous_version"]
    if "v" + candidate_version != binding.version:
        _fail("package candidate version does not match the Git binding")
    for index, platform in enumerate(document["platforms"]):
        for side, manifest, version in (
            ("candidate", candidate, candidate_version),
            ("previous", previous, previous_version),
        ):
            artifact = platform[side]
            if (
                artifact["filename"] not in manifest.checksums
                or artifact["sha256"] != manifest.checksums[artifact["filename"]]
                or artifact["version"] != version
                or platform[f"{side}_version"] != version
            ):
                _fail(f"package platform artifact binding is invalid at index {index}/{side}")
        if platform["candidate"]["sha256"] == platform["previous"]["sha256"]:
            _fail("package previous and candidate bytes are identical")
    specs = {
        (item.distribution, item.architecture): item
        for item in package_lab.DEFAULT_PLATFORMS
    }
    coordinate_claims = [
        _derive_platform_lifecycle_claims(
            platform,
            specs[(platform["distribution"], platform["architecture_id"])],
        )
        for platform in document["platforms"]
    ]
    derived_claims = {
        claim: all(coordinate[claim] for coordinate in coordinate_claims)
        for claim in LIFECYCLE_CLAIM_KEYS
    }
    if not all(derived_claims.values()):
        missing = sorted(
            claim for claim, complete in derived_claims.items() if not complete
        )
        _fail(f"package ACTIVE lifecycle claims are incomplete: {missing}")
    runtime_modes = {platform["runtime_mode"] for platform in document["platforms"]}
    if runtime_modes != {"active-real-init"}:
        _fail("package lifecycle evidence is not exclusively ACTIVE real-init")
    coordinates = [
        {
            "platform": item["distribution"],
            "architecture": item["architecture_id"],
            "status": item["status"],
        }
        for item in classification["coordinate_classification"]
    ]
    lifecycle = {
        "previous_version": "v" + previous_version,
        "candidate_version": "v" + candidate_version,
        "runtime_mode": next(iter(runtime_modes)),
        **derived_claims,
        "previous_package_checksums": {
            name: digest
            for name, digest in previous.checksums.items()
        },
    }
    return {
        "harness_complete": classification["harness_complete"],
        "release_ready": classification["release_ready"],
        "blocker_ids": blockers,
        "coordinates": coordinates,
        "lifecycle": lifecycle,
    }


def _package_identity_set(*manifests: gate.PackageManifest) -> set[tuple[int, int]]:
    return {(item.device, item.inode) for manifest in manifests for item in manifest.snapshots}


def _revalidate_all(
    binding: gate.RepositoryBinding,
    candidate: gate.PackageManifest,
    previous: gate.PackageManifest,
    raws: dict[str, RawReport],
    package_shards: dict[str, RawReport],
) -> None:
    for raw in (*raws.values(), *package_shards.values()):
        gate.revalidate(raw.snapshot, f"{raw.label} raw report")
    for manifest, label in ((candidate, "candidate package evidence"), (previous, "previous package evidence")):
        for snapshot in manifest.snapshots:
            gate.revalidate(snapshot, label)
    current_candidate = gate.verify_packages(candidate.directory, binding)
    previous_deb = next(
        name for name in previous.checksums if name.endswith("_amd64.deb")
    )
    previous_version = "v" + previous_deb.removeprefix("syswarden_").removesuffix(
        "_amd64.deb"
    )
    current_previous = gate.verify_packages(
        previous.directory,
        gate.RepositoryBinding(
            binding.root,
            binding.commit_sha,
            binding.tree_sha,
            previous_version,
        ),
    )
    if current_candidate != candidate or current_previous != previous:
        _fail("package directory inventory changed after validation")
    current = gate.verify_repository(binding.root, binding.commit_sha, binding.version)
    if current != binding:
        _fail("Git binding changed during adapter validation")


def build_expected(args: argparse.Namespace, *, now: datetime | None = None) -> ValidatedInputs:
    if args.max_age_seconds < 60 or args.max_age_seconds > gate.MAX_EVIDENCE_AGE:
        _fail(f"max evidence age must be between 60 and {gate.MAX_EVIDENCE_AGE} seconds")
    if args.max_report_skew_seconds < 0 or args.max_report_skew_seconds > 3600:
        _fail("max report skew must be between 0 and 3600 seconds")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    binding = gate.verify_repository(args.repo_root, args.expected_sha, args.expected_version)
    candidate = gate.verify_packages(args.candidate_packages_dir, binding)
    raw_paths = {"nft": args.nft_raw, "package": args.package_raw}
    raws = {key: _load_raw(path, key, binding.root, current, args.max_age_seconds) for key, path in raw_paths.items()}
    package_shard_paths = {"amd64": args.package_amd64_shard}
    package_shards = {
        architecture: _load_raw(
            path,
            f"package-{architecture}-shard",
            binding.root,
            current,
            args.max_age_seconds,
        )
        for architecture, path in package_shard_paths.items()
    }
    for key, raw in raws.items():
        if raw.snapshot.path.name != RAW_NAMES[key]:
            _fail(f"{key} raw basename must be exactly {RAW_NAMES[key]!r}")
    all_raws = [*raws.values(), *package_shards.values()]
    if (
        len({(item.snapshot.device, item.snapshot.inode) for item in all_raws}) != 3
        or len({item.snapshot.path for item in all_raws}) != 3
        or len({item.snapshot.path.name for item in all_raws}) != 3
    ):
        _fail("the raw reports and native shards must have distinct files, inodes, paths, and basenames")
    timestamps = [item.generated_at for item in raws.values()]
    if max(timestamps) - min(timestamps) > timedelta(seconds=RAW_REPORT_MAX_SKEW_SECONDS):
        _fail("raw report timestamps exceed the bounded laboratory collection window")
    previous_version, _ = _package_versions(raws["package"].document, binding.version)
    previous_binding = gate.RepositoryBinding(binding.root, binding.commit_sha, binding.tree_sha, "v" + previous_version)
    previous = gate.verify_packages(args.previous_packages_dir, previous_binding)
    expected_qualification_binding = {
        "schema_version": 1,
        "repository": args.expected_repository,
        "release_sha": binding.commit_sha,
        "release_tag": binding.version,
        "previous_tag": previous_binding.version,
        "workflow_run_id": args.expected_workflow_run_id,
        "workflow_run_attempt": args.expected_workflow_run_attempt,
        "candidate_run_id": args.expected_candidate_run_id,
        "candidate_artifact_id": args.expected_candidate_artifact_id,
        "candidate_artifact_name": args.expected_candidate_artifact_name,
        "previous_release_id": args.expected_previous_release_id,
        "candidate_manifest_sha256": candidate.sha256,
        "previous_manifest_sha256": previous.sha256,
    }
    _validate_package_qualification_binding(expected_qualification_binding)
    if args.expected_candidate_artifact_name != (
        "syswarden-packages-" + binding.version.removeprefix("v")
    ):
        _fail("candidate package artifact name does not match the release version")
    candidate_dir_stat = candidate.directory.stat()
    previous_dir_stat = previous.directory.stat()
    if candidate.directory == previous.directory or (
        candidate_dir_stat.st_dev,
        candidate_dir_stat.st_ino,
    ) == (previous_dir_stat.st_dev, previous_dir_stat.st_ino):
        _fail("candidate and previous package directories must be distinct")
    identities = _package_identity_set(candidate, previous)
    if len(identities) != len(candidate.snapshots) + len(previous.snapshots):
        _fail("candidate and previous package evidence must not share files/inodes")
    raw_identities = {
        (item.snapshot.device, item.snapshot.inode) for item in all_raws
    }
    if raw_identities & identities:
        _fail("raw reports must not alias candidate or previous package evidence")
    if (
        candidate.directory.name != "candidate"
        or previous.directory.name != "previous"
        or candidate.directory.parent.name != "packages"
        or previous.directory.parent != candidate.directory.parent
    ):
        _fail("package directories do not match packages/{candidate,previous}")
    artifact_root = candidate.directory.parent.parent
    if any(
        raw.snapshot.path.parent.name != "raw"
        or raw.snapshot.path.parent.parent != artifact_root
        for raw in all_raws
    ):
        _fail("raw reports and package directories do not share the exact artifact layout")
    for old_name, new_name in zip(gate.package_names("v" + previous_version), gate.package_names(binding.version)):
        if previous.checksums[old_name] == candidate.checksums[new_name]:
            _fail(f"previous and candidate package bytes are identical: {old_name}/{new_name}")
    nft = _validate_nft(raws["nft"].document, binding)
    package = _validate_package(
        raws["package"].document,
        binding,
        candidate,
        previous,
        package_shards,
        expected_qualification_binding,
    )
    generated_at = min(timestamps).isoformat()
    bindings = {
        "commit_sha": binding.commit_sha,
        "tree_sha": binding.tree_sha,
        "version": binding.version,
        "tag": binding.version,
        "package_manifest_sha256": candidate.sha256,
        "package_checksums": candidate.checksums,
    }
    envelopes = {
        "nft": gate.build_bound_report(kind="nftables_kernel", generated_at=generated_at, raw_report_sha256=raws["nft"].snapshot.sha256, bindings=bindings, **nft),
        "package": gate.build_bound_report(kind="linux_package_lifecycle", generated_at=generated_at, raw_report_sha256=raws["package"].snapshot.sha256, bindings=bindings, **package),
    }
    _revalidate_all(binding, candidate, previous, raws, package_shards)
    return ValidatedInputs(
        binding,
        candidate,
        previous,
        raws,
        package_shards,
        envelopes,
    )


def _destination_paths(args: argparse.Namespace) -> dict[str, Path]:
    if args.command == "build":
        return {"nft": args.nft_output, "package": args.package_output}
    return {"nft": args.nft_envelope, "package": args.package_envelope}


def _validate_destinations(paths: dict[str, Path], state: ValidatedInputs, *, must_exist: bool) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    protected = {
        (item.snapshot.device, item.snapshot.inode)
        for item in (*state.raws.values(), *state.package_shards.values())
    } | _package_identity_set(state.candidate, state.previous)
    existing: set[tuple[int, int]] = set()
    for key, path in paths.items():
        if path.name != OUTPUT_NAMES[key]:
            _fail(f"{key} envelope basename must be exactly {OUTPUT_NAMES[key]!r}")
        absolute = gate._absolute_without_symlinks(path, f"{key} envelope", leaf_may_absent=not must_exist)
        artifact_root = state.candidate.directory.parent.parent
        if absolute.parent.name != "bound" or absolute.parent.parent != artifact_root:
            _fail(f"{key} envelope does not match the exact bound/ artifact layout")
        if _inside(absolute, state.binding.root) or _inside(absolute, state.candidate.directory) or _inside(absolute, state.previous.directory):
            _fail(f"{key} envelope must be outside the repository and package directories")
        resolved[key] = absolute
        if absolute.exists():
            metadata = absolute.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                _fail(f"{key} envelope must be a regular non-symlink file")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in protected or identity in existing:
                _fail(f"{key} envelope aliases raw/package/other envelope evidence")
            existing.add(identity)
        elif must_exist:
            _fail(f"{key} envelope does not exist")
    if len(set(resolved.values())) != 2:
        _fail("the two envelope paths must be distinct")
    return resolved


def run_build(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    destinations = _validate_destinations(_destination_paths(args), state, must_exist=False)
    for key, destination in destinations.items():
        gate.write_atomic(destination, state.envelopes[key], state.binding.root)
    snapshots = {key: gate.read_snapshot(path, f"{key} generated envelope") for key, path in destinations.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 2:
        _fail("generated envelopes do not have distinct inodes")
    for key, snapshot in snapshots.items():
        if snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope atomic write was not byte-exact")
    _revalidate_all(
        state.binding,
        state.candidate,
        state.previous,
        state.raws,
        state.package_shards,
    )
    return state.envelopes


def run_verify(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    state = build_expected(args)
    paths = _validate_destinations(_destination_paths(args), state, must_exist=True)
    snapshots = {key: gate.read_snapshot(path, f"{key} envelope") for key, path in paths.items()}
    if len({(item.device, item.inode) for item in snapshots.values()}) != 2:
        _fail("the two envelopes must have distinct inodes")
    for key, snapshot in snapshots.items():
        document = gate.strict_json(snapshot.payload, f"{key} envelope")
        if document != state.envelopes[key] or snapshot.payload != _canonical(state.envelopes[key]):
            _fail(f"{key} envelope is not the byte-exact canonical recomputation")
    for key, snapshot in snapshots.items():
        gate.revalidate(snapshot, f"{key} envelope")
    _revalidate_all(
        state.binding,
        state.candidate,
        state.previous,
        state.raws,
        state.package_shards,
    )
    return state.envelopes


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--candidate-packages-dir", type=Path, required=True)
    parser.add_argument("--previous-packages-dir", type=Path, required=True)
    parser.add_argument("--nft-raw", type=Path, required=True)
    parser.add_argument("--package-raw", type=Path, required=True)
    parser.add_argument("--package-amd64-shard", type=Path, required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-workflow-run-id", type=int, required=True)
    parser.add_argument("--expected-workflow-run-attempt", type=int, required=True)
    parser.add_argument("--expected-candidate-run-id", type=int, required=True)
    parser.add_argument("--expected-candidate-artifact-id", type=int, required=True)
    parser.add_argument("--expected-candidate-artifact-name", required=True)
    parser.add_argument("--expected-previous-release-id", type=int, required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    parser.add_argument("--max-report-skew-seconds", type=int, default=300)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build bound qualification envelopes")
    _common_arguments(build)
    build.add_argument("--nft-output", type=Path, required=True)
    build.add_argument("--package-output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify byte-exact bound envelopes")
    _common_arguments(verify)
    verify.add_argument("--nft-envelope", type=Path, required=True)
    verify.add_argument("--package-envelope", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        envelopes = run_build(args) if args.command == "build" else run_verify(args)
    except (gate.EvidenceError, package_lab.LifecycleLabError, OSError, ValueError) as exc:
        print(f"release qualification adapter invalid: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(envelopes, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
