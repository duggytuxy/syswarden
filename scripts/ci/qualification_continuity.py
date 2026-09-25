#!/usr/bin/env python3
"""Check eligibility for the exact PR257 transition, never release acceptance.

Historical observations retain their candidate, package, host and timestamps.
This check intentionally cannot emit a passing release or capability verdict.
Final consumers must additionally verify fresh affected and unfinished gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

try:
    from scripts.ci import native_package_signing_bundle as bundle
except ModuleNotFoundError:
    import native_package_signing_bundle as bundle


class ContinuityError(ValueError):
    pass


BASE = "cd09e754852c2d7831222bb8ed8c620d9ffd4ec0"
RUNTIME = "380e90dd29b7db77f6914d5a4978740e33df2770"
POLICY = Path(__file__).with_name("qualification_continuity_policy_pr257.json")
POLICY_SHA256 = "a4d0564867eb292e5e96e639998085c1c34e4d2cd702a0e230e4480a8ebf39fa"
MAX_RECORD_BYTES = 4 * 1024 * 1024
ELIGIBILITY_SCHEMA = "syswarden-pr257-continuity-eligibility/v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContinuityError(message)


def digest(wire: bytes) -> str:
    return hashlib.sha256(wire).hexdigest()


def strict_json(wire: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label}: duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(token: str) -> None:
        raise ContinuityError(f"{label}: non-finite JSON value {token}")

    try:
        value = json.loads(wire.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=nonfinite)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ContinuityError(f"{label}: invalid JSON") from exc
    require(type(value) is dict, f"{label}: expected JSON object")
    return value


def checked_bytes(path: Path, expected: dict[str, Any], label: str,
                  maximum: int = MAX_RECORD_BYTES) -> bytes:
    require(set(expected) == {"sha256", "size"}, f"{label}: invalid anchor")
    require(type(expected["size"]) is int and 0 < expected["size"] <= maximum,
            f"{label}: invalid anchored size")
    wire = bundle.regular_bytes(path, maximum, label)
    require(len(wire) == expected["size"] and digest(wire) == expected["sha256"],
            f"{label}: bytes differ from reviewed anchor")
    return wire


def load_policy() -> dict[str, Any]:
    wire = bundle.regular_bytes(POLICY, MAX_RECORD_BYTES, "PR257 policy")
    require(digest(wire) == POLICY_SHA256, "PR257 policy differs from reviewed policy")
    policy = strict_json(wire, "PR257 policy")
    require(policy["base_candidate"] == BASE and policy["runtime_candidate"] == RUNTIME,
            "PR257 policy candidate identity is invalid")
    require(policy["eligibility_is_release_acceptance"] is False and
            policy["future_candidate_reuse_allowed"] is False,
            "PR257 policy cannot authorize general reuse or release acceptance")
    return policy


def git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
             "--no-replace-objects", *args], cwd=repository, capture_output=True,
            text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContinuityError("cannot verify exact Git objects") from exc
    return result.stdout.strip()


def verify_source(repository: Path, policy: dict[str, Any], runtime: str) -> None:
    require(runtime == RUNTIME, "continuity is limited to the exact PR257 runtime")
    require(git(repository, "merge-base", BASE, runtime) == BASE,
            "runtime is not a descendant of the exact prior candidate")
    require(git(repository, "rev-parse", runtime + "^{tree}") == policy["runtime_tree"],
            "runtime tree differs from reviewed tree")
    require(git(repository, "rev-parse", policy["reviewed_head"] + "^{tree}") ==
            policy["runtime_tree"], "merged runtime differs from reviewed PR head")
    changes = policy["source_changes"]
    expected = {item["path"] for item in changes}
    actual = git(repository, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                 "--name-only", BASE, runtime).splitlines()
    require(len(actual) == len(expected) and set(actual) == expected,
            "source diff exceeds the exact two reviewed files")
    for change in changes:
        for candidate, field in ((BASE, "before_blob"), (runtime, "after_blob")):
            require(git(repository, "rev-parse", candidate + ":" + change["path"]) ==
                    change[field], "source blob differs from reviewed correction")


def verify_packages(root: Path, policy: dict[str, Any], role: str) -> list[dict[str, Any]]:
    candidate = BASE if role == "base" else RUNTIME
    bundle.ensure_protected_directory(root, f"{role} bundle")
    bundle.verify_bundle(root, policy["release"], candidate)
    records = []
    for pair in policy["packages"]:
        package = pair[role]
        relative = Path(package["path"])
        require(not relative.is_absolute() and ".." not in relative.parts,
                "package path escapes bundle")
        path = root / relative
        require(path.absolute() == path.resolve(strict=True), "package path contains symlink")
        checked_bytes(path, {k: package[k] for k in ("sha256", "size")},
                      f"{role} {relative}", bundle.MAX_PACKAGE_BYTES)
        records.append(dict(package))
    return records


def verify_prior_scopes(documents: dict[str, dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    scopes = []
    for scope, binding in sorted(policy["eligible_prior_scopes"].items()):
        record = binding["record"]
        document = documents[record]
        require(document.get("candidate_commit") == BASE,
                f"{scope}: original observed candidate was changed")
        if scope.startswith("capability-"):
            require(document.get("verdict") == "pass" and document.get("blockers") == [],
                    f"{scope}: prior capability is not complete and passing")
            profile = scope.removeprefix("capability-")
            expected_host = {"RPM-A9-RHELPO": "node05", "DEB-U2604": "node02"}[profile]
            require(document.get("profile_id") == profile and document.get("host_id") == expected_host,
                    f"{scope}: prior host or package profile changed")
        elif scope == "five-native-lifecycles":
            require(document.get("status") == "pass" and document.get("profile_count") == 5,
                    "prior lifecycle verdict is not complete and passing")
        elif scope == "native-performance":
            require(document.get("status") == "independent-current-native-performance-gate-passed",
                    "prior performance verification did not pass")
        elif scope == "source-allocation":
            require(document.get("status") == "independent-frozen-source-allocation-gate-passed",
                    "prior allocation verification did not pass")
        else:
            raise ContinuityError("unreviewed prior scope")
        scopes.append({
            "scope": scope, "record": record,
            "record_sha256": policy["records"][record]["sha256"],
            "observed_candidate": BASE, "proposed_acceptance_candidate": RUNTIME,
            "acceptance": "pending-fresh-affected-gates-and-protected-final-validation",
        })
    return scopes


def verify_eligibility(*, repository: Path, proof_root: Path, base_bundle: Path,
                       runtime_bundle: Path, candidate: str) -> dict[str, Any]:
    policy = load_policy()
    verify_source(repository, policy, candidate)
    bundle.ensure_protected_directory(proof_root, "continuity input directory")
    require({p.name for p in proof_root.iterdir()} == set(policy["records"]),
            "continuity input inventory is not exact")
    documents = {}
    for name, anchor in policy["records"].items():
        wire = checked_bytes(proof_root / name, anchor, name)
        if name.endswith(".json"):
            documents[name] = strict_json(wire, name)
    require(documents["owner-approval.json"].get("status") == "owner-approved",
            "exact transition lacks owner approval")
    for role, candidate_sha in (("base", BASE), ("runtime", RUNTIME)):
        signature = documents[f"{role}-native-signatures.json"]
        require(signature.get("candidate_sha") == candidate_sha and
                signature.get("status") == "qualified-bundle-and-four-native-signatures-verified" and
                len(signature.get("checks", [])) == 6 and
                all(type(check.get("returncode")) is int and check["returncode"] == 0
                    for check in signature["checks"]),
                f"{role}: native signature verification is incomplete")
    scopes = verify_prior_scopes(documents, policy)
    packages = {
        "base": verify_packages(base_bundle, policy, "base"),
        "runtime": verify_packages(runtime_bundle, policy, "runtime"),
    }
    return {
        "schema": ELIGIBILITY_SCHEMA, "release": policy["release"],
        "base_candidate": BASE, "runtime_candidate": RUNTIME,
        "policy_sha256": POLICY_SHA256,
        "validator_sha256": digest(bundle.regular_bytes(Path(__file__), MAX_RECORD_BYTES,
                                                       "continuity validator")),
        "status": "exact-transition-eligible-final-acceptance-pending",
        "records": policy["records"], "packages": packages, "prior_scopes": scopes,
        "fresh_required": policy["fresh_required"],
        "historical_evidence_modified": False, "release_qualified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--proof-root", type=Path, required=True)
    parser.add_argument("--base-bundle", type=Path, required=True)
    parser.add_argument("--runtime-bundle", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_eligibility(repository=args.repository, proof_root=args.proof_root,
                                    base_bundle=args.base_bundle, runtime_bundle=args.runtime_bundle,
                                    candidate=args.candidate)
        bundle.write_json(args.output, result)
    except (ContinuityError, bundle.SigningBundleError, OSError) as exc:
        parser.exit(1, f"Continuity eligibility rejected: {exc}\n")
    print("Exact PR257 transition eligible; fresh gates and final acceptance remain required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
