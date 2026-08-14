#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERSIONCTL_BINARY="$(mktemp /tmp/syswarden-versionctl.XXXXXX)"
trap 'rm -f -- "${VERSIONCTL_BINARY}"' EXIT

(
  cd "${SCRIPT_DIR}/versionctl"
  GOWORK=off go build -o "${VERSIONCTL_BINARY}" .
)

"${VERSIONCTL_BINARY}" "$@"
