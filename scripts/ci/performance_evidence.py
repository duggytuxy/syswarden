#!/usr/bin/env python3
"""Build candidate-bound SysWarden performance campaign evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Sequence

try:
    from scripts.ci import performance_gate as gate
except ModuleNotFoundError:
    import performance_gate as gate


CAMPAIGN_CONTRACT_ID = "syswarden-performance-campaign/v2"
SAMPLE_CONTRACT_ID = "syswarden-native-performance-samples/v2"
MAX_AUXILIARY_BYTES = 1024 * 1024
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class PerformanceEvidenceError(ValueError):
    """Raised when campaign evidence is incomplete or ambiguous."""


def _read_regular_bytes(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise PerformanceEvidenceError(f"cannot inspect input: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PerformanceEvidenceError(f"input must be one regular file: {path}")
    if before.st_size <= 0 or before.st_size > maximum:
        raise PerformanceEvidenceError(f"input size is outside bounds: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if identity != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise PerformanceEvidenceError(f"input changed while opening: {path}")
        wire = b""
        while len(wire) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(wire)))
            if not chunk:
                break
            wire += chunk
        after = os.fstat(descriptor)
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise PerformanceEvidenceError(f"input changed while reading: {path}")
    finally:
        os.close(descriptor)
    if len(wire) != before.st_size or len(wire) > maximum:
        raise PerformanceEvidenceError(f"input changed while reading: {path}")
    return wire


def _sha256_regular_file(path: Path) -> str:
    return hashlib.sha256(_read_regular_bytes(path, MAX_AUXILIARY_BYTES)).hexdigest()


def _load_sample_set(
    path: Path,
    metric_contracts: dict[str, gate.MetricContract],
    contract: dict[str, Any],
    candidate_commit: str,
    campaign_id: str,
    recorded_at: str,
    subject_role: str,
) -> tuple[dict[str, list[float]], dict[str, str]]:
    raw = gate._exact_mapping(
        gate._load_regular_json(path),
        {
            "schema_version",
            "schema_id",
            "contract_id",
            "target_release",
            "baseline_release",
            "candidate_commit",
            "campaign_id",
            "recorded_at",
            "subject_role",
            "subject_release",
            "adapter_sha256",
            "adapter_config_sha256",
            "binary_sha256",
            "package_sha256",
            "metrics",
        },
        f"{subject_role} sample document",
    )
    expected_release = (
        contract["baseline_release"]
        if subject_role == "baseline"
        else contract["target_release"]
    )
    expected = {
        "schema_version": 2,
        "schema_id": SAMPLE_CONTRACT_ID,
        "contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "candidate_commit": candidate_commit,
        "campaign_id": campaign_id,
        "recorded_at": recorded_at,
        "subject_role": subject_role,
        "subject_release": expected_release,
    }
    for key, value in expected.items():
        if raw[key] != value:
            raise PerformanceEvidenceError(
                f"{subject_role} sample {key} binding is invalid"
            )
    for key in (
        "adapter_sha256",
        "adapter_config_sha256",
        "binary_sha256",
        "package_sha256",
    ):
        if gate.SHA256_PATTERN.fullmatch(str(raw[key])) is None:
            raise PerformanceEvidenceError(
                f"{subject_role} sample {key} is invalid"
            )
    raw_metrics = raw["metrics"]
    if not isinstance(raw_metrics, dict) or set(raw_metrics) != set(metric_contracts):
        raise PerformanceEvidenceError("sample metric inventory is not exact")
    result: dict[str, list[float]] = {}
    for name, contract in metric_contracts.items():
        item = gate._exact_mapping(
            raw_metrics[name], {"unit", "samples"}, f"sample metric {name}"
        )
        if item["unit"] != contract.unit:
            raise PerformanceEvidenceError(f"sample metric unit mismatch: {name}")
        result[name] = gate._samples(
            item["samples"],
            1,
            f"sample metric {name}",
            allow_zero=name in gate.NONNEGATIVE_METRICS,
        )
    provenance = {
        "release": raw["subject_release"],
        "adapter_sha256": raw["adapter_sha256"],
        "adapter_config_sha256": raw["adapter_config_sha256"],
        "binary_sha256": raw["binary_sha256"],
        "package_sha256": raw["package_sha256"],
        "samples_sha256": hashlib.sha256(_read_regular_bytes(path, gate.MAX_INPUT_BYTES)).hexdigest(),
    }
    return result, provenance


def build_campaign(
    *,
    candidate_commit: str,
    identifier: str,
    recorded_at: str,
    environment_id: str,
    environment_attestation: Path,
    probe: Path,
    baseline_samples: Path,
    candidate_samples: Path,
    contract_path: Path = gate.DEFAULT_CONTRACT,
) -> dict[str, Any]:
    contract, metric_contracts = gate.load_contract(contract_path)
    if SHA_PATTERN.fullmatch(candidate_commit) is None:
        raise PerformanceEvidenceError("candidate commit is not canonical")
    if gate.IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise PerformanceEvidenceError("campaign identifier is not canonical")
    if gate.IDENTIFIER_PATTERN.fullmatch(environment_id) is None:
        raise PerformanceEvidenceError("environment identifier is not canonical")
    gate._canonical_utc_timestamp(recorded_at, "recorded_at")
    baseline, baseline_provenance = _load_sample_set(
        baseline_samples,
        metric_contracts,
        contract,
        candidate_commit,
        identifier,
        recorded_at,
        "baseline",
    )
    candidate, candidate_provenance = _load_sample_set(
        candidate_samples,
        metric_contracts,
        contract,
        candidate_commit,
        identifier,
        recorded_at,
        "candidate",
    )
    if baseline_provenance["adapter_sha256"] != candidate_provenance["adapter_sha256"]:
        raise PerformanceEvidenceError("paired sample adapters differ")
    if (
        baseline_provenance["adapter_config_sha256"]
        != candidate_provenance["adapter_config_sha256"]
    ):
        raise PerformanceEvidenceError("paired sample adapter configs differ")
    metrics: dict[str, Any] = {}
    for name, metric_contract in metric_contracts.items():
        if len(baseline[name]) != len(candidate[name]):
            raise PerformanceEvidenceError(
                f"paired sample counts differ for metric {name}"
            )
        metrics[name] = {
            "unit": metric_contract.unit,
            "baseline": baseline[name],
            "candidate": candidate[name],
        }
    return {
        "schema_version": 2,
        "contract_id": CAMPAIGN_CONTRACT_ID,
        "performance_contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "baseline_commit": contract["baseline_commit"],
        "candidate_commit": candidate_commit,
        "id": identifier,
        "recorded_at": recorded_at,
        "environment_id": environment_id,
        "environment_sha256": _sha256_regular_file(environment_attestation),
        "probe_sha256": _sha256_regular_file(probe),
        "subjects": {
            "adapter_sha256": baseline_provenance["adapter_sha256"],
            "adapter_config_sha256": baseline_provenance[
                "adapter_config_sha256"
            ],
            "baseline": {
                key: baseline_provenance[key]
                for key in ("release", "binary_sha256", "package_sha256", "samples_sha256")
            },
            "candidate": {
                key: candidate_provenance[key]
                for key in ("release", "binary_sha256", "package_sha256", "samples_sha256")
            },
        },
        "metrics": metrics,
    }


def _validate_campaign(
    raw: object,
    contract: dict[str, Any],
    metric_contracts: dict[str, gate.MetricContract],
    candidate_commit: str,
) -> dict[str, Any]:
    document = gate._exact_mapping(
        raw,
        {
            "schema_version",
            "contract_id",
            "performance_contract_id",
            "target_release",
            "baseline_release",
            "baseline_commit",
            "candidate_commit",
            "id",
            "recorded_at",
            "environment_id",
            "environment_sha256",
            "probe_sha256",
            "subjects",
            "metrics",
        },
        "campaign",
    )
    expected = {
        "schema_version": 2,
        "contract_id": CAMPAIGN_CONTRACT_ID,
        "performance_contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "baseline_commit": contract["baseline_commit"],
        "candidate_commit": candidate_commit,
    }
    for key, value in expected.items():
        if document[key] != value:
            raise PerformanceEvidenceError(f"campaign {key} binding is invalid")
    if gate.IDENTIFIER_PATTERN.fullmatch(str(document["id"])) is None:
        raise PerformanceEvidenceError("campaign identifier is not canonical")
    if gate.IDENTIFIER_PATTERN.fullmatch(str(document["environment_id"])) is None:
        raise PerformanceEvidenceError("campaign environment is not canonical")
    gate._canonical_utc_timestamp(document["recorded_at"], "campaign recorded_at")
    for key in ("environment_sha256", "probe_sha256"):
        if gate.SHA256_PATTERN.fullmatch(str(document[key])) is None:
            raise PerformanceEvidenceError(f"campaign {key} is invalid")
    subjects = gate._exact_mapping(
        document["subjects"],
        {"adapter_sha256", "adapter_config_sha256", "baseline", "candidate"},
        "campaign subjects",
    )
    if gate.SHA256_PATTERN.fullmatch(str(subjects["adapter_sha256"])) is None:
        raise PerformanceEvidenceError("campaign adapter digest is invalid")
    if (
        gate.SHA256_PATTERN.fullmatch(str(subjects["adapter_config_sha256"]))
        is None
    ):
        raise PerformanceEvidenceError("campaign adapter config digest is invalid")
    for role, release in (
        ("baseline", contract["baseline_release"]),
        ("candidate", contract["target_release"]),
    ):
        subject = gate._exact_mapping(
            subjects[role],
            {"release", "binary_sha256", "package_sha256", "samples_sha256"},
            f"campaign {role} subject",
        )
        if subject["release"] != release:
            raise PerformanceEvidenceError(f"campaign {role} release is invalid")
        for key in ("binary_sha256", "package_sha256", "samples_sha256"):
            if gate.SHA256_PATTERN.fullmatch(str(subject[key])) is None:
                raise PerformanceEvidenceError(
                    f"campaign {role} {key} is invalid"
                )
    raw_metrics = document["metrics"]
    if not isinstance(raw_metrics, dict) or set(raw_metrics) != set(metric_contracts):
        raise PerformanceEvidenceError("campaign metric inventory is not exact")
    for name, metric_contract in metric_contracts.items():
        item = gate._exact_mapping(
            raw_metrics[name], {"unit", "baseline", "candidate"}, f"campaign metric {name}"
        )
        if item["unit"] != metric_contract.unit:
            raise PerformanceEvidenceError(f"campaign metric unit mismatch: {name}")
        baseline = gate._samples(
            item["baseline"],
            1,
            f"{name}/baseline",
            allow_zero=name in gate.NONNEGATIVE_METRICS,
        )
        candidate = gate._samples(
            item["candidate"],
            1,
            f"{name}/candidate",
            allow_zero=name in gate.NONNEGATIVE_METRICS,
        )
        if len(baseline) != len(candidate):
            raise PerformanceEvidenceError(f"paired sample counts differ for metric {name}")
        required_per_campaign = math.ceil(
            metric_contract.minimum_samples / contract["minimum_campaigns"]
        )
        if len(baseline) != required_per_campaign:
            raise PerformanceEvidenceError(
                f"campaign metric {name} requires exactly {required_per_campaign} samples per side"
            )
    return document


def assemble_evidence(
    *,
    candidate_commit: str,
    campaigns: Sequence[Path],
    contract_path: Path = gate.DEFAULT_CONTRACT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract, metric_contracts = gate.load_contract(contract_path)
    if SHA_PATTERN.fullmatch(candidate_commit) is None:
        raise PerformanceEvidenceError("candidate commit is not canonical")
    if len(campaigns) < contract["minimum_campaigns"]:
        raise PerformanceEvidenceError("not enough campaign files")
    validated = [
        _validate_campaign(
            gate._load_regular_json(path), contract, metric_contracts, candidate_commit
        )
        for path in campaigns
    ]
    validated.sort(key=lambda item: item["id"])
    identifiers = [item["id"] for item in validated]
    if len(identifiers) != len(set(identifiers)):
        raise PerformanceEvidenceError("campaign identifiers are duplicated")
    timestamps = [item["recorded_at"] for item in validated]
    if len(timestamps) != len(set(timestamps)):
        raise PerformanceEvidenceError("campaign timestamps are duplicated")

    reference = validated[0]
    shared_binding = (
        reference["environment_id"],
        reference["environment_sha256"],
        reference["probe_sha256"],
        reference["subjects"]["adapter_sha256"],
        reference["subjects"]["adapter_config_sha256"],
        reference["subjects"]["baseline"]["binary_sha256"],
        reference["subjects"]["candidate"]["binary_sha256"],
        reference["subjects"]["baseline"]["package_sha256"],
        reference["subjects"]["candidate"]["package_sha256"],
    )
    sample_documents: set[str] = set()
    dynamic_sample_pairs: dict[
        str, set[tuple[tuple[float, ...], tuple[float, ...]]]
    ] = {
        name: set()
        for name, metric in metric_contracts.items()
        if name not in gate.STATIC_SIZE_METRICS
        and math.ceil(metric.minimum_samples / contract["minimum_campaigns"]) > 1
    }
    for campaign in validated:
        binding = (
            campaign["environment_id"],
            campaign["environment_sha256"],
            campaign["probe_sha256"],
            campaign["subjects"]["adapter_sha256"],
            campaign["subjects"]["adapter_config_sha256"],
            campaign["subjects"]["baseline"]["binary_sha256"],
            campaign["subjects"]["candidate"]["binary_sha256"],
            campaign["subjects"]["baseline"]["package_sha256"],
            campaign["subjects"]["candidate"]["package_sha256"],
        )
        if binding != shared_binding:
            raise PerformanceEvidenceError(
                "campaign environment, probe, adapter, or artifact binding differs"
            )
        baseline_samples = campaign["subjects"]["baseline"]["samples_sha256"]
        candidate_samples = campaign["subjects"]["candidate"]["samples_sha256"]
        if baseline_samples == candidate_samples:
            raise PerformanceEvidenceError("paired sample documents are identical")
        for digest in (baseline_samples, candidate_samples):
            if digest in sample_documents:
                raise PerformanceEvidenceError(
                    "sample document is reused across campaigns"
                )
            sample_documents.add(digest)
        for name in dynamic_sample_pairs:
            item = campaign["metrics"][name]
            sample_pair = (
                tuple(float(value) for value in item["baseline"]),
                tuple(float(value) for value in item["candidate"]),
            )
            has_zero_vector = any(
                all(value == 0 for value in values) for values in sample_pair
            )
            if sample_pair in dynamic_sample_pairs[name] and not has_zero_vector:
                raise PerformanceEvidenceError(
                    f"dynamic sample vectors are cloned across campaigns: {name}"
                )
            dynamic_sample_pairs[name].add(sample_pair)
    metrics: dict[str, Any] = {}
    for name, metric_contract in metric_contracts.items():
        metrics[name] = {
            "unit": metric_contract.unit,
            "campaigns": [
                {
                    "id": campaign["id"],
                    "recorded_at": campaign["recorded_at"],
                    "environment_id": campaign["environment_id"],
                    "environment_sha256": campaign["environment_sha256"],
                    "probe_sha256": campaign["probe_sha256"],
                    "adapter_sha256": campaign["subjects"]["adapter_sha256"],
                    "adapter_config_sha256": campaign["subjects"][
                        "adapter_config_sha256"
                    ],
                    "baseline_samples_sha256": campaign["subjects"]["baseline"]["samples_sha256"],
                    "candidate_samples_sha256": campaign["subjects"]["candidate"]["samples_sha256"],
                    "baseline_binary_sha256": campaign["subjects"]["baseline"]["binary_sha256"],
                    "candidate_binary_sha256": campaign["subjects"]["candidate"]["binary_sha256"],
                    "baseline_package_sha256": campaign["subjects"]["baseline"]["package_sha256"],
                    "candidate_package_sha256": campaign["subjects"]["candidate"]["package_sha256"],
                    "baseline": campaign["metrics"][name]["baseline"],
                    "candidate": campaign["metrics"][name]["candidate"],
                }
                for campaign in validated
            ],
        }
    evidence = {
        "schema_version": 2,
        "contract_id": contract["contract_id"],
        "target_release": contract["target_release"],
        "baseline_release": contract["baseline_release"],
        "baseline_commit": contract["baseline_commit"],
        "candidate_commit": candidate_commit,
        "metrics": metrics,
    }
    report = gate.evaluate(evidence, contract, metric_contracts, {}, candidate_commit)
    return evidence, report


def _write_new_json(path: Path, document: object) -> None:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise PerformanceEvidenceError("output path must be absolute and canonical")
    parent = path.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise PerformanceEvidenceError("output parent must be a real directory")
    if path.exists() or path.is_symlink():
        raise PerformanceEvidenceError("output must not already exist")
    wire = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".syswarden-performance-", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(wire)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        directory_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    campaign = subparsers.add_parser("campaign", help="build one paired campaign")
    campaign.add_argument("--candidate-commit", required=True)
    campaign.add_argument("--id", required=True)
    campaign.add_argument("--recorded-at", required=True)
    campaign.add_argument("--environment-id", required=True)
    campaign.add_argument("--environment-attestation", type=Path, required=True)
    campaign.add_argument("--probe", type=Path, required=True)
    campaign.add_argument("--baseline-samples", type=Path, required=True)
    campaign.add_argument("--candidate-samples", type=Path, required=True)
    campaign.add_argument("--contract", type=Path, default=gate.DEFAULT_CONTRACT)
    campaign.add_argument("--output", type=Path, required=True)
    assemble = subparsers.add_parser("assemble", help="assemble paired campaigns")
    assemble.add_argument("--candidate-commit", required=True)
    assemble.add_argument("--campaign", type=Path, action="append", required=True)
    assemble.add_argument("--contract", type=Path, default=gate.DEFAULT_CONTRACT)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "campaign":
            document = build_campaign(
                candidate_commit=arguments.candidate_commit,
                identifier=arguments.id,
                recorded_at=arguments.recorded_at,
                environment_id=arguments.environment_id,
                environment_attestation=arguments.environment_attestation,
                probe=arguments.probe,
                baseline_samples=arguments.baseline_samples,
                candidate_samples=arguments.candidate_samples,
                contract_path=arguments.contract,
            )
            _write_new_json(arguments.output, document)
            return 0
        evidence, report = assemble_evidence(
            candidate_commit=arguments.candidate_commit,
            campaigns=arguments.campaign,
            contract_path=arguments.contract,
        )
        _write_new_json(arguments.output, evidence)
        if arguments.report is not None:
            _write_new_json(arguments.report, report)
        return 0 if report["verdict"] == "pass" else 1
    except (OSError, gate.PerformanceGateError, PerformanceEvidenceError) as exc:
        print(f"performance evidence: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
