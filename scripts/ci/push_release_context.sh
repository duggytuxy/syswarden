#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: $0 <repository> <source-version> <candidate-sha> <output-json>" >&2
  exit 2
fi
readonly repository="$1" release_tag="$2" candidate_sha="$3" output="$4"
if [[ ! "${candidate_sha}" =~ ^[0-9a-f]{40}$ ||
      ! "${release_tag}" =~ ^v[0-9]+\.[0-9]{2}\.[0-9]+$ ]]; then
  echo "ERROR: exact candidate SHA and canonical source version are required." >&2
  exit 1
fi
if [[ "$(git -C "${repository}" rev-parse --verify 'HEAD^{commit}')" != "${candidate_sha}" ]]; then
  echo "ERROR: candidate SHA does not equal the checked-out commit." >&2
  exit 1
fi
if [[ -e "${output}" || -L "${output}" ]]; then
  echo "ERROR: push context output already exists." >&2
  exit 1
fi

# Run only after validate-commit. This describes a push, never release acceptance.
kind="untagged-candidate"
tag_commit=""
required=true
if git -C "${repository}" show-ref --verify --quiet "refs/tags/${release_tag}"; then
  tag_commit="$(git -C "${repository}" rev-parse --verify "refs/tags/${release_tag}^{commit}")"
  if [[ "${tag_commit}" == "${candidate_sha}" ]]; then
    kind="tagged-head"
  elif git -C "${repository}" merge-base --is-ancestor "${tag_commit}" "${candidate_sha}"; then
    kind="post-tag-followup"
    required=false
  else
    echo "ERROR: existing version tag is not an ancestor of the checked-out commit." >&2
    exit 1
  fi
else
  status="$?"
  if [[ "${status}" -ne 1 ]]; then
    echo "ERROR: unable to determine the existing version tag." >&2
    exit 1
  fi
fi

umask 077
temporary="$(mktemp "${output}.tmp.XXXXXX")"
trap 'rm -f -- "${temporary}"' EXIT
jq -n --arg candidate "${candidate_sha}" --arg release "${release_tag}" \
  --arg tag_commit "${tag_commit}" --arg kind "${kind}" --argjson required "${required}" '
  {schema: "syswarden-push-release-context/v1", candidate_commit: $candidate,
   source_version: $release, existing_tag_commit: $tag_commit, kind: $kind,
   release_track_required: $required, historical_verdicts_transferred: false,
   qualification_passed: false, publication_authorized: false}
' > "${temporary}"
mv -- "${temporary}" "${output}"
echo "Push context: ${kind}; release-track classification required: ${required}"
