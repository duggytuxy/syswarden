#!/usr/bin/env bash
# Run the upstream bundled linter only after verifying its exact bytes.
set -euo pipefail

test "$(node --version)" = "v24.19.0"
markdown_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/syswarden-markdown.XXXXXXXX")"
trap 'rm -rf -- "${markdown_dir}"' EXIT
bundle="${markdown_dir}/index.mjs"

# This object is dist/index.mjs from the pinned v23.2.0 action commit
# fa0cd0f1a052f54da593c83860f2292982f5d142. Decode the Git blob to preserve
# control bytes; a failed download or a non-base64 response must stop here.
gh api --hostname github.com \
  repos/DavidAnson/markdownlint-cli2-action/git/blobs/8ea700050c9eaec3565888b9943c0002fcb2dae8 \
  --jq .content | base64 --decode > "${bundle}"
printf '%s  %s\n' \
  'd086e03cc18f78fcd4d1e46c2d2b4f47c6a2d07eec38a1c16763c8c664c51ead' \
  "${bundle}" | sha256sum --check --strict

unset GH_TOKEN GH_ENTERPRISE_TOKEN GITHUB_TOKEN
INPUT_CONFIG=.markdownlint.json INPUT_GLOBS=README.md \
  INPUT_CONFIGPOINTER='' INPUT_FIX='' INPUT_SEPARATOR='' node "${bundle}"
