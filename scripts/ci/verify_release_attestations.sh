#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: $0 <asset-directory> <owner/repository> <signer-workflow> <source-sha>" >&2
  exit 2
fi

readonly asset_directory="$1"
readonly repository="$2"
readonly signer_workflow="$3"
readonly source_sha="$4"

if [[ ! "${source_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: source SHA must be a full lowercase Git commit SHA." >&2
  exit 1
fi

if [[ ! -d "${asset_directory}" ]]; then
  echo "ERROR: release asset directory is missing: ${asset_directory}" >&2
  exit 1
fi

mapfile -d '' -t assets < <(
  find "${asset_directory}" -mindepth 1 -maxdepth 1 -type f -print0 | sort -z
)
if [[ "${#assets[@]}" -eq 0 ]]; then
  echo "ERROR: no release assets are available for attestation verification." >&2
  exit 1
fi

for asset in "${assets[@]}"; do
  verified=false
  for attempt in 1 2 3 4 5; do
    if gh attestation verify "${asset}" \
      --repo "${repository}" \
      --signer-workflow "${signer_workflow}" \
      --source-digest "${source_sha}" \
      --deny-self-hosted-runners; then
      verified=true
      break
    fi
    if [[ "${attempt}" -lt 5 ]]; then
      sleep "$((attempt * 5))"
    fi
  done
  if [[ "${verified}" != "true" ]]; then
    echo "ERROR: build provenance verification failed for ${asset}." >&2
    exit 1
  fi
done

echo "Build provenance verified for ${#assets[@]} exact release assets."
