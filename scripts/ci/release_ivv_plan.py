#!/usr/bin/env python3
"""Verify the reviewed IVV plan and frozen product inputs, never release acceptance.

The publication commit may add reviewed release tooling while all product inputs
and signed package bytes remain anchored to their original product candidate.
Historical observations are inventoried, not promoted to current test verdicts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any

try:
    from scripts.ci import native_package_signing_bundle as bundle
except ModuleNotFoundError:
    import native_package_signing_bundle as bundle

PLAN = Path(__file__).with_name("release_ivv_plan_v4.10.0.json")
PLAN_SHA256 = "0aa14136104664baacedf5966bad16e1b4a4ce73b1662e9548e603bcea1bec2a"
SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_JSON = 4 * 1024 * 1024


class PlanError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def digest(wire: bytes) -> str:
    return hashlib.sha256(wire).hexdigest()


def strict_json(wire: bytes) -> dict[str, Any]:
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value

    def nonfinite(_):
        raise PlanError("non-finite JSON value")

    try:
        value = json.loads(wire.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=nonfinite)
    except (UnicodeDecodeError, ValueError) as exc:
        raise PlanError("invalid JSON document") from exc
    require(type(value) is dict, "JSON root must be an object")
    return value


def relative(value: str) -> str:
    require(type(value) is str and value and "\\" not in value and
            all(ord(c) >= 32 and ord(c) != 127 for c in value), "unsafe relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and
            all(part not in (".", "..") for part in path.parts), "path escapes root")
    return value


def read_anchored(root: Path, row: dict[str, Any], maximum: int) -> bytes:
    name = relative(row["path"])
    require(root.is_absolute() and root == root.resolve(strict=True), "noncanonical input root")
    path = root / name
    require(path == path.resolve(strict=True), "symbolic link in input path")
    require(type(row["size"]) is int and 0 < row["size"] <= maximum and
            type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]) is not None,
            "invalid reviewed input anchor")
    wire = bundle.regular_bytes(path, maximum, name)
    require(len(wire) == row["size"] and digest(wire) == row["sha256"],
            f"input differs from reviewed bytes: {name}")
    return wire


def load_plan() -> dict[str, Any]:
    wire = bundle.regular_bytes(PLAN, MAX_JSON, "reviewed IVV plan")
    require(digest(wire) == PLAN_SHA256, "IVV plan differs from reviewed bytes")
    plan = strict_json(wire)
    require(plan["schema"] == "syswarden-intermediate-ivv-plan/v1" and
            plan["release"] == "v4.10.0" and plan["required_assurance"] == "IVV" and
            plan["preflight_is_acceptance"] is False, "unsupported IVV plan")
    return plan


def git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=/dev/null", *arguments],
            cwd=repository, text=True, capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlanError("cannot verify Git source identity") from exc
    return result.stdout.strip()


def verify_source(repository: Path, publication: str, plan: dict[str, Any]) -> list[str]:
    require(SHA.fullmatch(publication) is not None, "publication must be an exact commit")
    require(repository.is_absolute() and repository == repository.resolve(strict=True),
            "repository path is not canonical")
    require(git(repository, "rev-parse", "HEAD") == publication, "publication is not checked out")
    require(git(repository, "rev-parse", "--is-shallow-repository") == "false",
            "complete version history is required")
    require(not git(repository, "for-each-ref", "refs/replace"), "Git replacement refs are forbidden")
    grafts = Path(git(repository, "rev-parse", "--git-path", "info/grafts"))
    if not grafts.is_absolute():
        grafts = repository / grafts
    require(not grafts.exists(), "Git grafts are forbidden")
    require(not git(repository, "status", "--porcelain", "--untracked-files=normal"),
            "preflight requires a clean checked-out publication commit")
    require(all(line.startswith("H ") for line in git(repository, "ls-files", "-v").splitlines()),
            "hidden index changes or sparse checkout are forbidden")
    product = plan["product_candidate"]
    require(git(repository, "merge-base", product, publication) == product,
            "publication does not descend from frozen product")
    allowed = plan["publication_source_change_allowlist"]
    require(len(allowed) == len(set(allowed)), "duplicate source allowlist entry")
    for name in allowed:
        relative(name)
    changed = git(repository, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                  "--name-only", product, publication).splitlines()
    require(set(changed) <= set(allowed), "publication changes a frozen product/build input")
    # Paths outside the exact reviewed allowlist cannot change, including files
    # not anticipated when defining a list of known product directories.
    return changed


def verify_track(track: dict[str, Any], publication: str, plan: dict[str, Any]) -> None:
    expected = {"schema", "candidate_commit", "release", "previous_version",
                "transition_commit", "transition_parent", "prefix", "track",
                "followup_commits", "qualification_passed", "publication_authorized"}
    require(set(track) == expected, "unexpected version classification fields")
    origin = plan["originating_transition"]
    require(track["schema"] == "syswarden-release-track/v1" and
            track["candidate_commit"] == publication and track["release"] == plan["release"] and
            track["transition_commit"] == origin["commit"] and
            track["previous_version"] == origin["previous_version"] and
            track["prefix"] == origin["prefix"] and track["prefix"] in ("Patch", "Minor", "Major") and
            track["track"] == "intermediate-validation" and
            SHA.fullmatch(track["transition_parent"]) is not None and
            type(track["followup_commits"]) is int and track["followup_commits"] >= 0 and
            track["qualification_passed"] is False and track["publication_authorized"] is False,
            "IVV plan does not match the original version transition")


def classify(repository: Path, publication: str, plan: dict[str, Any]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(repository / "scripts/versioning.sh"), "release-track", "--repo",
             str(repository), "--tag", plan["release"]], cwd=repository,
            capture_output=True, check=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlanError("validated version classification failed") from exc
    track = strict_json(result.stdout)
    verify_track(track, publication, plan)
    return track


def verify_inputs(plan: dict[str, Any], evidence_root: Path,
                  package_root: Path) -> tuple[list[dict], list[dict]]:
    records = []
    for row in plan["retained_records"]:
        anchor = dict(row, path=relative(row["id"] + ".json"))
        wire = read_anchored(evidence_root, anchor, MAX_JSON)
        original = strict_json(wire)
        recorded_candidate = original.get("candidate_commit", original.get("candidate_sha"))
        # Some independently verified receipts name the source differently.
        # Their exact reviewed hash remains mandatory; no field is rewritten.
        if recorded_candidate is not None:
            require(recorded_candidate == row["candidate_commit"], "historical candidate was relabeled")
        records.append(dict(row, admitted_as_current_pass=False))
    packages = []
    for row in plan["product_packages"]:
        read_anchored(package_root, row, 128 * 1024 * 1024)
        packages.append(dict(row))
    return records, packages


def preflight(repository: Path, publication: str, evidence_root: Path,
              package_root: Path) -> dict[str, Any]:
    plan = load_plan()
    changed = verify_source(repository, publication, plan)
    track = classify(repository, publication, plan)
    records, packages = verify_inputs(plan, evidence_root, package_root)
    require(load_plan() == plan and verify_source(repository, publication, plan) == changed,
            "source or reviewed plan changed during verification")
    return {
        "schema": "syswarden-intermediate-ivv-preflight/v1",
        "release": plan["release"], "plan_sha256": PLAN_SHA256,
        "product_candidate": plan["product_candidate"], "publication_commit": publication,
        "classification": track, "source_changes": changed,
        "retained_records": records, "frozen_package_bytes": packages,
        "required_checks": plan["required_checks"],
        "scope": "Plan and immutable input verification only; not cryptographic signature revalidation or protected release acceptance.",
        "intermediate_release_validated": False, "qualification_passed": False,
        "publication_authorized": False,
    }


def write_new(path: Path, result: dict[str, Any]) -> None:
    parent = path.parent
    require(parent.is_absolute() and parent == parent.resolve(strict=True),
            "output parent is not canonical")
    wire = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(wire)
        output.flush()
        os.fsync(output.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--publication-sha", required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = preflight(args.repository, args.publication_sha,
                           args.evidence_root, args.package_root)
        write_new(args.output, result)
    except (PlanError, bundle.SigningBundleError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"IVV preflight rejected: {exc}\n")
    print("IVV plan and frozen inputs verified. Required checks and protected acceptance remain pending.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
