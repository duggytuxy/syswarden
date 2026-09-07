#!/usr/bin/env python3
"""Validate real, attested, candidate-bound HA v2 native observations."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "scripts/ci/ha_v2_native_contract_v4.10.0.json"
EVIDENCE_SCHEMA = "syswarden-ha-v2-native-evidence/v1"
VERDICT_SCHEMA = "syswarden-ha-v2-native-verdict/v1"
CONTRACT_SHA256 = "159f1e64aa2622c3f9181c0b3c3e7ee9b7275da1188c57779a478d62380f72a3"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
UTC = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class EvidenceError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path, maximum: int = 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise EvidenceError(f"input must be one regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        wire = b""
        while len(wire) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(wire)))
            if not chunk:
                break
            wire += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise EvidenceError(f"input changed while reading: {path}")
    if not wire or len(wire) > maximum:
        raise EvidenceError(f"input size is outside bounds: {path}")
    try:
        value = json.loads(wire.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON: {path}") from exc
    if type(value) is not dict:
        raise EvidenceError(f"JSON root must be an object: {path}")
    return value, wire


def _exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise EvidenceError(f"{label} keys are not exact")


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise EvidenceError(f"invalid {label}")
    return value


def load_contract(path: Path = DEFAULT_CONTRACT) -> tuple[dict[str, Any], str]:
    document, wire = _read(path)
    _exact(document, {"schema_version", "contract_id", "target_release", "architecture", "node_count", "roles", "tls", "required_scenarios", "guardrails", "limits"}, "contract")
    if document["schema_version"] != 1 or document["target_release"] != "v4.10.0":
        raise EvidenceError("unsupported HA v2 contract")
    if document["architecture"] != "amd64" or document["node_count"] != 2:
        raise EvidenceError("HA v2 contract must require two AMD64 nodes")
    if document["roles"] != ["standby", "writer"]:
        raise EvidenceError("HA v2 roles are not exact")
    _exact(document["tls"], {"minimum_version", "mutual_authentication", "identity_binding"}, "contract TLS")
    if document["tls"] != {"minimum_version": "TLS1.3", "mutual_authentication": True, "identity_binding": ["cluster_id", "epoch", "node_id", "peer_certificate_sha256"]}:
        raise EvidenceError("HA v2 TLS contract is not exact")
    _exact(document["guardrails"], {"observations", "synthetic_observations", "attestation_required", "single_restart_recovery", "automatic_rejoin"}, "contract guardrails")
    if document["guardrails"] != {"observations": "real-native-two-node-lab-only", "synthetic_observations": False, "attestation_required": True, "single_restart_recovery": True, "automatic_rejoin": False}:
        raise EvidenceError("HA v2 guardrails are not exact")
    _exact(document["limits"], {"maximum_input_bytes", "maximum_clock_skew_seconds", "maximum_scenario_seconds"}, "contract limits")
    for key in document["limits"]:
        if type(document["limits"][key]) is not int or document["limits"][key] <= 0:
            raise EvidenceError("HA v2 contract limit is invalid")
    required = document["required_scenarios"]
    if type(required) is not list or len(required) != 10 or len(set(required)) != 10 or any(type(item) is not str for item in required):
        raise EvidenceError("HA v2 scenario contract is not exact")
    digest = hashlib.sha256(wire).hexdigest()
    if path == DEFAULT_CONTRACT and digest != CONTRACT_SHA256:
        raise EvidenceError("committed HA v2 contract digest mismatch")
    return document, digest


def contract_digest(path: Path = DEFAULT_CONTRACT) -> str:
    return load_contract(path)[1]


def _verify_reference(bundle: Path, reference: str, digest: str) -> None:
    path = bundle / reference
    try:
        resolved_bundle = bundle.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EvidenceError(f"missing raw evidence: {reference}") from exc
    if resolved.parent != resolved_bundle / "raw":
        raise EvidenceError(f"unsafe raw evidence reference: {reference}")
    document, wire = _read(path)
    del document
    if not wire or len(wire) > 1024 * 1024 or hashlib.sha256(wire).hexdigest() != digest:
        raise EvidenceError(f"raw evidence digest mismatch: {reference}")


def _timestamp(value: Any, label: str) -> dt.datetime:
    _string(value, UTC, label)
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def validate(document: dict[str, Any], candidate_sha: str, release_tag: str, contract: dict[str, Any], contract_sha256: str, bundle: Path) -> dict[str, Any]:
    _string(candidate_sha, SHA1, "candidate SHA")
    if release_tag != "v4.10.0":
        raise EvidenceError("unsupported release tag")
    _exact(document, {"schema", "repository", "release_tag", "candidate_sha", "contract_sha256", "campaign", "nodes", "scenarios", "attestation"}, "evidence")
    if document["schema"] != EVIDENCE_SCHEMA or document["repository"] != "duggytuxy/syswarden":
        raise EvidenceError("evidence identity mismatch")
    if document["release_tag"] != release_tag or document["candidate_sha"] != candidate_sha:
        raise EvidenceError("candidate binding mismatch")
    if document["contract_sha256"] != contract_sha256:
        raise EvidenceError("contract digest mismatch")

    campaign = document["campaign"]
    if type(campaign) is not dict:
        raise EvidenceError("campaign must be an object")
    _exact(campaign, {"id", "cluster_id", "epoch", "started_at", "completed_at", "observation_origin", "synthetic"}, "campaign")
    _string(campaign["id"], IDENTIFIER, "campaign id")
    _string(campaign["cluster_id"], IDENTIFIER, "cluster id")
    _string(campaign["epoch"], SHA256, "cluster epoch")
    started = _timestamp(campaign["started_at"], "campaign start")
    completed = _timestamp(campaign["completed_at"], "campaign completion")
    if completed <= started or (completed - started).total_seconds() > contract["limits"]["maximum_scenario_seconds"]:
        raise EvidenceError("campaign time bounds are invalid")
    if campaign["observation_origin"] != "real-native-two-node-lab" or campaign["synthetic"] is not False:
        raise EvidenceError("synthetic or non-native observations are forbidden")

    nodes = document["nodes"]
    if type(nodes) is not list or len(nodes) != 2:
        raise EvidenceError("exactly two nodes are required")
    node_ids: set[str] = set()
    roles: set[str] = set()
    certificates: set[str] = set()
    leases: set[str] = set()
    for node in nodes:
        if type(node) is not dict:
            raise EvidenceError("node must be an object")
        _exact(node, {"node_id", "role", "architecture", "candidate_sha", "cluster_id", "epoch", "tls_version", "mtls_verified", "peer_identity_verified", "certificate_sha256", "boot_id_sha256", "instance_lease_id", "attestation_ref", "attestation_sha256"}, "node")
        node_ids.add(_string(node["node_id"], IDENTIFIER, "node id"))
        roles.add(node["role"])
        certificates.add(_string(node["certificate_sha256"], SHA256, "certificate digest"))
        leases.add(_string(node["instance_lease_id"], IDENTIFIER, "instance lease"))
        for key in ("boot_id_sha256", "attestation_sha256"):
            _string(node[key], SHA256, key)
        if node["architecture"] != "amd64" or node["candidate_sha"] != candidate_sha:
            raise EvidenceError("node candidate or architecture mismatch")
        if node["cluster_id"] != campaign["cluster_id"] or node["epoch"] != campaign["epoch"]:
            raise EvidenceError("node cluster or epoch mismatch")
        if node["tls_version"] != "TLS1.3" or node["mtls_verified"] is not True or node["peer_identity_verified"] is not True:
            raise EvidenceError("TLS 1.3 mutual identity proof is required")
        _string(node["attestation_ref"], re.compile(r"^raw/[a-z0-9._-]+\.json$"), "attestation reference")
        _verify_reference(bundle, node["attestation_ref"], node["attestation_sha256"])
    if len(node_ids) != 2 or roles != {"writer", "standby"} or len(certificates) != 2 or len(leases) != 2:
        raise EvidenceError("node identities, roles, certificates, or leases are ambiguous")

    required = set(contract["required_scenarios"])
    scenarios = document["scenarios"]
    if type(scenarios) is not list or len(scenarios) != len(required):
        raise EvidenceError("scenario inventory is not exact")
    seen: set[str] = set()
    for scenario in scenarios:
        if type(scenario) is not dict:
            raise EvidenceError("scenario must be an object")
        _exact(scenario, {"id", "status", "observed_at", "evidence_ref", "evidence_sha256", "facts"}, "scenario")
        scenario_id = scenario["id"]
        if scenario_id not in required or scenario_id in seen:
            raise EvidenceError("unknown or duplicate scenario")
        seen.add(scenario_id)
        if scenario["status"] != "pass":
            raise EvidenceError(f"scenario did not pass: {scenario_id}")
        observed = _timestamp(scenario["observed_at"], "scenario timestamp")
        skew = contract["limits"]["maximum_clock_skew_seconds"]
        if observed < started - dt.timedelta(seconds=skew) or observed > completed + dt.timedelta(seconds=skew):
            raise EvidenceError("scenario timestamp is outside campaign bounds")
        _string(scenario["evidence_ref"], re.compile(r"^raw/[a-z0-9._-]+\.json$"), "scenario reference")
        _string(scenario["evidence_sha256"], SHA256, "scenario digest")
        _verify_reference(bundle, scenario["evidence_ref"], scenario["evidence_sha256"])
        facts = scenario["facts"]
        if type(facts) is not dict or not facts or any(value is not True for value in facts.values()):
            raise EvidenceError(f"scenario facts must be explicit true observations: {scenario_id}")
    if seen != required:
        raise EvidenceError("required HA v2 scenarios are incomplete")

    required_facts = {
        "normal-replication-ack-checkpoint": {"replicated", "acknowledged", "checkpoint_equal"},
        "heartbeat-monotonic-receipt-timeout": {"receipt_monotonic", "timeout_fenced"},
        "asymmetric-partition": {"asymmetry_observed", "writer_fenced"},
        "partition-fence-split-brain": {"partition_observed", "dual_writer_prevented", "fence_durable"},
        "rejoin-explicit": {"automatic_rejoin_refused", "operator_rejoin_verified"},
        "crash-wal-recovery": {"crash_injected", "single_restart", "wal_recovered"},
        "crash-head-recovery": {"crash_injected", "single_restart", "head_recovered"},
        "instance-lease-exclusion": {"second_instance_refused", "lease_retained"},
        "rolling-upgrade": {"writer_continuity", "standby_upgraded", "roles_preserved"},
        "rolling-rollback": {"rollback_completed", "state_preserved", "roles_preserved"},
    }
    by_id = {item["id"]: item for item in scenarios}
    for scenario_id, facts in required_facts.items():
        if set(by_id[scenario_id]["facts"]) != facts:
            raise EvidenceError(f"facts are not exact for scenario: {scenario_id}")

    attestation = document["attestation"]
    if type(attestation) is not dict:
        raise EvidenceError("attestation must be an object")
    _exact(attestation, {"mechanism", "statement_sha256", "signature_sha256", "signer_identity", "verified_by", "verification_status"}, "attestation")
    if attestation["mechanism"] not in {"github-artifact-attestation", "sigstore-bundle"}:
        raise EvidenceError("unsupported attestation mechanism")
    for key in ("statement_sha256", "signature_sha256"):
        _string(attestation[key], SHA256, key)
    _string(attestation["signer_identity"], re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,255}$"), "signer identity")
    if attestation["verified_by"] != "release-owner-gate" or attestation["verification_status"] != "verified":
        raise EvidenceError("evidence attestation was not externally verified")
    return {"schema": VERDICT_SCHEMA, "status": "pass", "repository": document["repository"], "release_tag": release_tag, "candidate_sha": candidate_sha, "contract_sha256": contract_sha256, "campaign_id": campaign["id"], "node_ids": sorted(node_ids), "scenario_count": len(seen), "evidence_sha256": hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        document, _ = _read(args.evidence)
        contract, digest = load_contract(args.contract)
        verdict = validate(document, args.candidate_sha, args.release_tag, contract, digest, args.bundle)
        encoded = json.dumps(verdict, sort_keys=True, separators=(",", ":")) + "\n"
        if args.output:
            if not args.output.is_absolute() or args.output.exists() or args.output.is_symlink():
                raise EvidenceError("output must be a new absolute path")
            parent = args.output.parent
            parent_info = parent.lstat()
            if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
                raise EvidenceError("output parent must be a real directory")
            descriptor, temporary = tempfile.mkstemp(prefix=".ha-v2-verdict-", dir=parent)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                descriptor = -1
                os.link(temporary, args.output, follow_symlinks=False)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                Path(temporary).unlink(missing_ok=True)
        else:
            sys.stdout.write(encoded)
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
