#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: $0 <repository> <release-tag> <candidate-sha> <output-json>" >&2
  exit 2
fi
readonly repository="$1" release_tag="$2" candidate_sha="$3" output="$4"
if [[ ! "${candidate_sha}" =~ ^[0-9a-f]{40}$ ||
      ! "${release_tag}" =~ ^v[0-9]+\.[0-9]{2}\.[0-9]+$ ]]; then
  echo "ERROR: exact candidate SHA and canonical release tag are required." >&2
  exit 1
fi
if [[ "$(git -C "${repository}" rev-parse --verify 'HEAD^{commit}')" != "${candidate_sha}" ]]; then
  echo "ERROR: candidate SHA does not equal the checked-out commit." >&2
  exit 1
fi
if [[ -e "${output}" || -L "${output}" ]]; then
  echo "ERROR: classification output already exists." >&2
  exit 1
fi
umask 077
temporary="$(mktemp "${output}.tmp.XXXXXX")"
trap 'rm -f -- "${temporary}"' EXIT
"${repository}/scripts/versioning.sh" release-track --repo "${repository}" --tag "${release_tag}" > "${temporary}"
jq -e --arg sha "${candidate_sha}" --arg tag "${release_tag}" '
  .schema == "syswarden-release-track/v1" and
  .candidate_commit == $sha and .release == $tag and
  (.transition_commit | test("^[0-9a-f]{40}$")) and
  (.transition_parent | test("^[0-9a-f]{40}$")) and
  (.followup_commits | type == "number" and . >= 0 and floor == .) and
  .qualification_passed == false and .publication_authorized == false and
  ((.prefix == "Upgrade" and .track == "full-qualification") or
   ((.prefix == "Patch" or .prefix == "Minor" or .prefix == "Major") and
    .track == "intermediate-validation"))
' "${temporary}" >/dev/null
mv -- "${temporary}" "${output}"
echo "Release validation track: $(jq -r '.track' "${output}")"
echo "Originating transition: $(jq -r '.transition_commit + " (" + .prefix + ")"' "${output}")"
echo "Track classification is not a test result or publication authorization."
