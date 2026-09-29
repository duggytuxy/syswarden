#!/usr/bin/env python3
"""Bind a protected updater producer to the frozen IVV product, without accepting a release.

The producer checkout and attestation identify the publication/tooling commit.
The manifest packages retain their original product commit and native signatures.
This relation is available only for the pinned v4.10.0 IVV plan.
"""
from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scripts.ci import release_ivv_plan as ivv
except ModuleNotFoundError:
    import release_ivv_plan as ivv


def source_binding(repository: Path, publication: str, product: str) -> dict:
    plan = ivv.load_plan()
    ivv.require(product == plan["product_candidate"], "updater product is not the frozen IVV candidate")
    ivv.require(publication != product, "separate binding requires distinct producer and product commits")
    changed = ivv.verify_source(repository, publication, plan)
    track = ivv.classify(repository, publication, plan)
    return {
        "schema": "syswarden-candidate-update-source-binding/v1",
        "release": plan["release"],
        "product_candidate": product,
        "publication_commit": publication,
        "plan_sha256": ivv.PLAN_SHA256,
        "native_signing": plan["product_native_signing"],
        "classification": track,
        "source_changes": changed,
        "frozen_package_bytes": plan["product_packages"],
        "intermediate_release_validated": False,
        "qualification_passed": False,
        "publication_authorized": False,
    }


def verify_binding(document: dict, repository: Path, publication: str,
                   product: str, packages: Path) -> dict:
    expected = source_binding(repository, publication, product)
    ivv.require(ivv.bundle.exact_json_equal(document, expected), "candidate updater source binding differs from recomputed inputs")
    for row in expected["frozen_package_bytes"]:
        ivv.read_anchored(packages, row, 128 * 1024 * 1024)
    ivv.require(source_binding(repository, publication, product) == expected,
                "source changed while verifying candidate updater inputs")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--publication-sha", required=True)
    parser.add_argument("--product-sha", required=True)
    parser.add_argument("--native-run-id", type=int, required=True)
    parser.add_argument("--native-artifact-id", type=int, required=True)
    parser.add_argument("--packages", type=Path)
    parser.add_argument("--binding", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        native = ivv.load_plan()["product_native_signing"]
        ivv.require(args.native_run_id == native["run_id"] and
                    args.native_artifact_id == native["artifact_id"],
                    "native signing input is not the reviewed immutable artifact")
        ivv.require((args.binding is None) == (args.packages is None),
                    "package revalidation requires the original binding")
        ivv.require((args.binding is None) != (args.output is None),
                    "create a new binding or verify the existing one")
        if args.binding is None:
            result = source_binding(args.repository, args.publication_sha, args.product_sha)
            ivv.write_new(args.output, result)
        else:
            parent = args.binding.parent
            ivv.require(parent.is_absolute() and parent == parent.resolve(strict=True),
                        "binding parent is not canonical")
            document = ivv.strict_json(ivv.bundle.regular_bytes(
                args.binding, ivv.MAX_JSON, "candidate source binding"))
            verify_binding(document, args.repository, args.publication_sha,
                           args.product_sha, args.packages)
    except (ivv.PlanError, ivv.bundle.SigningBundleError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"Candidate source binding rejected: {exc}\n")
    print("Candidate product/producer binding verified; no release acceptance or publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
