#!/usr/bin/env bash
set -euo pipefail

# Official release: https://github.com/PowerShell/PowerShell/releases/tag/v7.6.4
readonly PWSH_VERSION="7.6.4"
readonly PWSH_ARCHIVE="powershell-${PWSH_VERSION}-linux-x64.tar.gz"
readonly PWSH_SHA256="4471b5a36bfe86ec7af8525d36bb1cacba0128e7aac22d05cc064bc00e604721"
readonly PWSH_URL="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/${PWSH_ARCHIVE}"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: the pinned PowerShell bootstrap supports Linux x86_64 runners only." >&2
  exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP must identify the runner temporary directory}"
: "${GITHUB_PATH:?GITHUB_PATH must identify the GitHub Actions PATH file}"

archive="$(mktemp "${RUNNER_TEMP}/syswarden-powershell-${PWSH_VERSION}.XXXXXX.tar.gz")"
install_dir="$(mktemp -d "${RUNNER_TEMP}/syswarden-powershell-${PWSH_VERSION}.XXXXXX")"

curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  --output "${archive}" \
  "${PWSH_URL}"
printf '%s  %s\n' "${PWSH_SHA256}" "${archive}" | sha256sum --check --strict
tar --extract --gzip --file "${archive}" --directory "${install_dir}"
chmod 0755 "${install_dir}/pwsh"

actual_version="$(
  "${install_dir}/pwsh" -NoLogo -NoProfile -NonInteractive \
    -Command "\$PSVersionTable.PSVersion.ToString()"
)"
if [[ "${actual_version}" != "${PWSH_VERSION}" ]]; then
  echo "ERROR: expected PowerShell ${PWSH_VERSION}, got ${actual_version}." >&2
  exit 1
fi

printf '%s\n' "${install_dir}" >> "${GITHUB_PATH}"
echo "PowerShell ${actual_version} verified from the official SHA-256 pinned archive."
