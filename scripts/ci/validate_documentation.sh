#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly REPO_ROOT

usage() {
  cat <<'EOF'
Usage: validate_documentation.sh --wiki-root PATH [--artifacts-dir PATH] [--timeout-seconds SECONDS]

Run the maintainer-controlled documentation gate against an explicit local
SysWarden wiki checkout. The GitHub workflow deliberately does not assume that
the separate wiki repository is available beside the source checkout.
EOF
}

wiki_root=""
artifacts_dir=""
timeout_seconds="20"

while (($# > 0)); do
  case "$1" in
    --wiki-root)
      (($# >= 2)) || {
        echo "ERROR: --wiki-root requires a path." >&2
        exit 2
      }
      wiki_root="$2"
      shift 2
      ;;
    --artifacts-dir)
      (($# >= 2)) || {
        echo "ERROR: --artifacts-dir requires a path." >&2
        exit 2
      }
      artifacts_dir="$2"
      shift 2
      ;;
    --timeout-seconds)
      (($# >= 2)) || {
        echo "ERROR: --timeout-seconds requires a value." >&2
        exit 2
      }
      timeout_seconds="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unsupported argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${wiki_root}" ]]; then
  echo "ERROR: --wiki-root is required; the gate must not silently omit the separate wiki checkout." >&2
  usage >&2
  exit 2
fi
if [[ ! -d "${wiki_root}" || -L "${wiki_root}" ]]; then
  echo "ERROR: wiki root must be an existing non-symlink directory: ${wiki_root}" >&2
  exit 2
fi
wiki_root="$(cd -- "${wiki_root}" && pwd -P)"

if [[ -z "${artifacts_dir}" ]]; then
  artifacts_dir="$(mktemp -d "${TMPDIR:-/tmp}/syswarden-documentation.XXXXXX")"
else
  if [[ -e "${artifacts_dir}" && (! -d "${artifacts_dir}" || -L "${artifacts_dir}") ]]; then
    echo "ERROR: artifacts directory must be a non-symlink directory: ${artifacts_dir}" >&2
    exit 2
  fi
  install -d -m 0750 "${artifacts_dir}"
fi
artifacts_dir="$(cd -- "${artifacts_dir}" && pwd -P)"
for reserved_name in \
  documentation-truth-report.json \
  wiki-line-inventory.tsv \
  go-build-cache \
  go-tmp; do
  if [[ -e "${artifacts_dir}/${reserved_name}" || -L "${artifacts_dir}/${reserved_name}" ]]; then
    echo "ERROR: reserved evidence path already exists: ${artifacts_dir}/${reserved_name}" >&2
    exit 2
  fi
done
install -d -m 0700 \
  "${artifacts_dir}/go-build-cache" \
  "${artifacts_dir}/go-tmp"

PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/documentation_gate.py" check \
  --repo-root "${REPO_ROOT}" \
  --wiki-root "${wiki_root}" \
  --report "${artifacts_dir}/documentation-truth-report.json"

(
  cd -- "${REPO_ROOT}/src/core/syswarden-cli"
  SYSWARDEN_WIKI_ROOT="${wiki_root}" \
    GOCACHE="${artifacts_dir}/go-build-cache" \
    GOTMPDIR="${artifacts_dir}/go-tmp" \
    go test ./config \
      -run '^TestPublicTOMLSnippetsLoadWithApplicationParser_SW_DOC_001$' \
      -count=1
)

PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/documentation_gate.py" inventory \
  --wiki-root "${wiki_root}" \
  --output "${artifacts_dir}/wiki-line-inventory.tsv"

PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/documentation_gate.py" check-links \
  --repo-root "${REPO_ROOT}" \
  --wiki-root "${wiki_root}" \
  --timeout-seconds "${timeout_seconds}"

printf 'Documentation validation passed. Evidence: %s\n' "${artifacts_dir}"
