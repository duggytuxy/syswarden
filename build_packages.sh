#!/bin/bash
# SysWarden Local Builder & Packager for Beta Testers
# Supported OS: Debian/Ubuntu & RHEL/CentOS/AlmaLinux
# This script compiles the Native Go binaries and generates .deb, .rpm, and .apk packages locally.

set -euo pipefail
umask 077

RHEL_PACKAGE_OWNED_PROFILE=0
case "$#:$*" in
    0:) ;;
    1:--rhel-package-owned-profile)
        RHEL_PACKAGE_OWNED_PROFILE=1
        ;;
    *)
        echo "Usage: $0 [--rhel-package-owned-profile]" >&2
        exit 2
        ;;
esac

echo "[*] Initializing SysWarden Local Package Builder..."

REPOSITORY_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
cd "${REPOSITORY_ROOT}"
for git_environment_variable in \
    GIT_DIR \
    GIT_WORK_TREE \
    GIT_COMMON_DIR \
    GIT_INDEX_FILE \
    GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_ATTR_SOURCE \
    GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_NAMESPACE \
    GIT_REPLACE_REF_BASE \
    GIT_SHALLOW_FILE \
    GIT_GRAFT_FILE \
    GIT_QUARANTINE_PATH \
    GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS \
    GIT_CONFIG_GLOBAL \
    GIT_CONFIG_SYSTEM \
    GIT_EXEC_PATH; do
    if [[ -v "${git_environment_variable}" ]]; then
        echo "[-] Refusing inherited Git repository influence: ${git_environment_variable}" >&2
        exit 1
    fi
done
export GIT_NO_REPLACE_OBJECTS=1
PACKAGE_WORKSPACE="$(mktemp -d /tmp/syswarden-local-package.XXXXXX)"
chmod 0700 "${PACKAGE_WORKSPACE}"
SOURCE_ROOT="${PACKAGE_WORKSPACE}/source"
SOURCE_ARCHIVE="${PACKAGE_WORKSPACE}/source.tar"
PACKAGE_REPOSITORY_STATE="${PACKAGE_WORKSPACE}/repository-state.json"
LOCAL_PACKAGE_OUTPUT="${REPOSITORY_ROOT}/dist/packages"
PACKAGE_STATE_CAPTURED=0
PACKAGE_STATE_VERIFIED=0

cleanup_package_workspace() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "${PACKAGE_STATE_CAPTURED}" -eq 1 ] && [ "${PACKAGE_STATE_VERIFIED}" -eq 0 ]; then
        if ! PYTHONDONTWRITEBYTECODE=1 python3 \
            "${REPOSITORY_ROOT}/scripts/ci/repository_state.py" \
            --repository "${REPOSITORY_ROOT}" verify \
            --snapshot "${PACKAGE_REPOSITORY_STATE}"; then
            status=1
        fi
    fi
    module_cache="${PACKAGE_WORKSPACE}/go-module-cache"
    if [ -e "${module_cache}" ] || [ -L "${module_cache}" ]; then
        if [ -L "${module_cache}" ] || [ ! -d "${module_cache}" ]; then
            echo "[-] Refusing unsafe local Go module cache cleanup." >&2
            status=1
        elif ! find "${module_cache}" -type d -exec chmod u+w -- {} +; then
            echo "[-] Unable to make the private Go module cache removable." >&2
            status=1
        fi
    fi
    case "${PACKAGE_WORKSPACE}" in
        /tmp/syswarden-local-package.*)
            rm -rf -- "${PACKAGE_WORKSPACE}" || status=1
            ;;
        *)
            echo "[-] Refusing to remove an unexpected package workspace." >&2
            status=1
            ;;
    esac
    exit "${status}"
}
trap cleanup_package_workspace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for required_command in python3 git go fpm nfpm readelf file ar rpm rpm2cpio cpio tar touch date sed sha256sum flock; do
    command -v "${required_command}" >/dev/null 2>&1 || {
        echo "[-] Required pinned build tool is unavailable: ${required_command}" >&2
        exit 1
    }
done

PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/repository_state.py" \
    --repository "${REPOSITORY_ROOT}" capture \
    --output "${PACKAGE_REPOSITORY_STATE}"
PACKAGE_STATE_CAPTURED=1
secure_builder_directory() {
    directory="$1"
    if [ -L "${directory}" ] || { [ -e "${directory}" ] && [ ! -d "${directory}" ]; }; then
        echo "[-] Refusing an unsafe local builder directory: ${directory}" >&2
        return 1
    fi
    if [ ! -d "${directory}" ]; then
        mkdir "${directory}" || return 1
    fi
    expected_user="$(id -un)"
    expected_group="$(id -gn)"
    if [ "$(find "${directory}" -prune -user "${expected_user}" -group "${expected_group}" -print)" != "${directory}" ]; then
        echo "[-] Refusing a local builder directory owned by another account: ${directory}" >&2
        return 1
    fi
    chmod 0700 "${directory}" || return 1
    if [ -L "${directory}" ] || [ ! -d "${directory}" ] || \
       [ "$(find "${directory}" -prune -user "${expected_user}" -group "${expected_group}" -print)" != "${directory}" ]; then
        echo "[-] Local builder directory identity changed while securing it: ${directory}" >&2
        return 1
    fi
}
secure_builder_directory "${REPOSITORY_ROOT}/dist"
secure_builder_directory "${LOCAL_PACKAGE_OUTPUT}"

# 1. Detect OS and attest the pinned build toolchain.
if [ -f /etc/debian_version ]; then
    echo "[*] Debian/Ubuntu detected."
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    echo "[*] RHEL/CentOS/Fedora/AlmaLinux detected."
else
    echo "[-] Unsupported OS for local package building."
    exit 1
fi

GO_TOOLCHAIN_ROOT="$(GOENV=off GOFLAGS='' GOWORK=off GOEXPERIMENT='' GOAMD64=v1 \
    GOCACHEPROG='' \
    GOTOOLCHAIN=go1.26.6 GOPROXY=off go env GOROOT)" || {
    echo "[-] Go 1.26.6 is not already installed; refusing an implicit toolchain download." >&2
    exit 1
}
GO_BIN="${GO_TOOLCHAIN_ROOT}/bin/go"
if [ ! -x "${GO_BIN}" ] || [ -L "${GO_BIN}" ]; then
    echo "[-] Go 1.26.6 executable is not a regular trusted toolchain file." >&2
    exit 1
fi
[ "$(GOTOOLCHAIN=local "${GO_BIN}" version)" = "go version go1.26.6 linux/amd64" ] || {
    echo "[-] Local package builds require exactly Go 1.26.6 for linux/amd64." >&2
    exit 1
}
[ "$(fpm --version)" = "1.17.0" ] || {
    echo "[-] Local package builds require exactly FPM 1.17.0." >&2
    exit 1
}
NFPM_BIN="$(command -v nfpm)"
if [ ! -f "${NFPM_BIN}" ] || [ ! -x "${NFPM_BIN}" ] || [ -L "${NFPM_BIN}" ]; then
    echo "[-] nfpm must be an existing regular executable, not a symlink." >&2
    exit 1
fi
if ! GOTOOLCHAIN=local "${GO_BIN}" version -m "${NFPM_BIN}" | LC_ALL=C awk '
    $1 == "mod" && $2 == "github.com/goreleaser/nfpm/v2" && $3 == "v2.47.0" { matches++ }
    END { exit matches == 1 ? 0 : 1 }
'; then
    echo "[-] Local package builds require exactly nfpm v2.47.0." >&2
    exit 1
fi

export GOTOOLCHAIN=local
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0
export GOFLAGS=-mod=readonly
export GOWORK=off
export GOENV=off
export GOAMD64=v1
export GOEXPERIMENT=
export GOCACHEPROG=
export GOCACHE="${PACKAGE_WORKSPACE}/go-build-cache"
export GOTMPDIR="${PACKAGE_WORKSPACE}/go-tmp"
export GOMODCACHE="${PACKAGE_WORKSPACE}/go-module-cache"
export GOPATH="${PACKAGE_WORKSPACE}/go-path"
mkdir -p \
    "${GOCACHE}" \
    "${GOTMPDIR}" \
    "${GOMODCACHE}" \
    "${GOPATH}" \
    "${PACKAGE_WORKSPACE}/dist/bin" \
    "${PACKAGE_WORKSPACE}/dist/bin-apk"
chmod 0700 \
    "${GOCACHE}" \
    "${GOTMPDIR}" \
    "${GOMODCACHE}" \
    "${GOPATH}" \
    "${PACKAGE_WORKSPACE}/dist" \
    "${PACKAGE_WORKSPACE}/dist/bin" \
    "${PACKAGE_WORKSPACE}/dist/bin-apk"
REPOSITORY_TOPLEVEL="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" rev-parse --show-toplevel)"
if [ "$(CDPATH='' cd -- "${REPOSITORY_TOPLEVEL}" && pwd -P)" != "${REPOSITORY_ROOT}" ]; then
    echo "[-] Git repository root does not match the builder location." >&2
    exit 1
fi
SOURCE_DATE_EPOCH="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" log -1 --format=%ct HEAD)"
case "${SOURCE_DATE_EPOCH}" in
    ''|0|*[!0-9]*)
        echo "[-] Unable to derive a reproducible source timestamp." >&2
        exit 1
        ;;
esac
SOURCE_COMMIT="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" rev-parse --verify 'HEAD^{commit}')"
if ! printf '%s\n' "${SOURCE_COMMIT}" | grep -Eq '^[0-9a-f]{40}$'; then
    echo "[-] Unable to derive the exact source commit." >&2
    exit 1
fi
SOURCE_VCS_TIME="$(date --utc --date="@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')" || {
    echo "[-] Unable to derive the exact source commit time." >&2
    exit 1
}
SOURCE_GIT_DIR="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" rev-parse --absolute-git-dir)"
case "${SOURCE_GIT_DIR}" in
    /*) ;;
    *)
        echo "[-] Git returned a non-absolute repository directory." >&2
        exit 1
        ;;
esac
if [ -L "${SOURCE_GIT_DIR}" ] || [ ! -d "${SOURCE_GIT_DIR}" ]; then
    echo "[-] Refusing an unsafe Git repository directory." >&2
    exit 1
fi
SOURCE_GIT_COMMON_DIR="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" \
    rev-parse --path-format=absolute --git-common-dir)"
case "${SOURCE_GIT_COMMON_DIR}" in
    /*) ;;
    *)
        echo "[-] Git returned a non-absolute common repository directory." >&2
        exit 1
        ;;
esac
if [ -L "${SOURCE_GIT_COMMON_DIR}" ] || [ ! -d "${SOURCE_GIT_COMMON_DIR}" ]; then
    echo "[-] Refusing an unsafe common Git repository directory." >&2
    exit 1
fi
if ! SOURCE_STATUS="$(git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" status --porcelain=v1 --untracked-files=normal)"; then
    echo "[-] Unable to verify the source repository state." >&2
    exit 1
fi
if [ -n "${SOURCE_STATUS}" ]; then
    echo "[-] Local release package builds require a clean exact commit." >&2
    exit 1
fi

install -d -m 0700 "${SOURCE_ROOT}"
git -c core.fsmonitor=false -C "${REPOSITORY_ROOT}" archive \
    --format=tar --output="${SOURCE_ARCHIVE}" "${SOURCE_COMMIT}"
tar --extract --file="${SOURCE_ARCHIVE}" --directory="${SOURCE_ROOT}" \
    --no-same-owner --no-same-permissions
rm -f -- "${SOURCE_ARCHIVE}"
if [ -e "${SOURCE_ROOT}/.git" ] || [ -L "${SOURCE_ROOT}/.git" ]; then
    echo "[-] Refusing a materialized source tree containing Git control data." >&2
    exit 1
fi
if ! MATERIALIZED_STATUS="$(
    GIT_COMMON_DIR="${SOURCE_GIT_COMMON_DIR}" \
        GIT_DIR="${SOURCE_GIT_DIR}" GIT_WORK_TREE="${SOURCE_ROOT}" \
        GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor \
        GIT_CONFIG_VALUE_0=false \
        git status --porcelain=v1 --untracked-files=all
)"; then
    echo "[-] Unable to verify the materialized exact source commit." >&2
    exit 1
fi
if [ -n "${MATERIALIZED_STATUS}" ]; then
    echo "[-] Materialized source does not match the exact source commit." >&2
    exit 1
fi
mkdir -- "${SOURCE_ROOT}/.git"
chmod 0500 "${SOURCE_ROOT}/.git"
if [ -L "${SOURCE_ROOT}/.git" ] || [ ! -d "${SOURCE_ROOT}/.git" ] || \
   [ -n "$(find "${SOURCE_ROOT}/.git" -mindepth 1 -print -quit)" ]; then
    echo "[-] Refusing an unsafe VCS discovery sentinel." >&2
    exit 1
fi
export SOURCE_DATE_EPOCH
export LC_ALL=C
export LANG=C
export TZ=UTC

# Extract the version through the repository-wide version contract.
SOURCE_TAG="$(PATH="${GO_TOOLCHAIN_ROOT}/bin:${PATH}" \
    GIT_COMMON_DIR="${SOURCE_GIT_COMMON_DIR}" \
    GIT_DIR="${SOURCE_GIT_DIR}" GIT_WORK_TREE="${SOURCE_ROOT}" \
    "${SOURCE_ROOT}/scripts/versioning.sh" inspect --repo "${SOURCE_ROOT}")"
case "${SOURCE_TAG}" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "[-] The source version contract did not return a release tag." >&2
        exit 1
        ;;
esac
VERSION="${SOURCE_TAG#v}"
RPM_PACKAGE_RELEASE="1"
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
    RPM_PACKAGE_RELEASE="1.rhelpo"
fi
RPM_PACKAGE_FILENAME="syswarden-${VERSION}-${RPM_PACKAGE_RELEASE}.x86_64.rpm"
echo "[+] Detected SysWarden Version: v${VERSION}"

# 2. Compile Go Binaries
echo "[*] Compiling SysWarden Native Go Modules..."
for module in syswarden-cli syswarden-core syswarden-tui; do
    echo " -> Downloading locked ${module} modules..."
    "${GO_BIN}" -C "${SOURCE_ROOT}/src/core/${module}" mod download
    "${GO_BIN}" -C "${SOURCE_ROOT}/src/core/${module}" mod verify
    echo " -> Compiling ${module}..."
    GIT_COMMON_DIR="${SOURCE_GIT_COMMON_DIR}" \
        GIT_DIR="${SOURCE_GIT_DIR}" GIT_WORK_TREE="${SOURCE_ROOT}" \
        GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor \
        GIT_CONFIG_VALUE_0=false GOWORK="${SOURCE_ROOT}/go.work" \
        "${GO_BIN}" -C "${SOURCE_ROOT}" build \
        -buildvcs=true -mod=readonly -trimpath -buildmode=pie -ldflags="-s -w" \
        -o "${PACKAGE_WORKSPACE}/dist/bin/${module}" "./src/core/${module}"
    echo " -> Compiling static Alpine ${module}..."
    GIT_COMMON_DIR="${SOURCE_GIT_COMMON_DIR}" \
        GIT_DIR="${SOURCE_GIT_DIR}" GIT_WORK_TREE="${SOURCE_ROOT}" \
        GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor \
        GIT_CONFIG_VALUE_0=false GOWORK="${SOURCE_ROOT}/go.work" \
        "${GO_BIN}" -C "${SOURCE_ROOT}" build \
        -buildvcs=true -mod=readonly -trimpath -ldflags="-s -w" \
        -o "${PACKAGE_WORKSPACE}/dist/bin-apk/${module}" "./src/core/${module}"
done

validate_trimpath_binary() {
    artifact="$1"
    "${GO_BIN}" version -m "${artifact}" | grep -Eq \
        '^[[:space:]]*build[[:space:]]+-trimpath=true$' || {
        echo "[-] Binary does not attest path-independent compilation: ${artifact}" >&2
        return 1
    }
}

validate_vcs_binary() {
    artifact="$1"
    if ! "${GO_BIN}" version -m "${artifact}" | LC_ALL=C awk \
        -v revision="${SOURCE_COMMIT}" \
        -v commit_time="${SOURCE_VCS_TIME}" '
        $1 == "build" && $2 == "vcs=git" { vcs_git++ }
        $1 == "build" && $2 == "vcs.revision=" revision { vcs_revision++ }
        $1 == "build" && $2 == "vcs.time=" commit_time { vcs_time++ }
        $1 == "build" && $2 == "vcs.modified=false" { vcs_clean++ }
        $1 == "build" && $2 ~ /^vcs(\.|=)/ { vcs_total++ }
        END {
            exit vcs_git == 1 && vcs_revision == 1 && vcs_time == 1 &&
                 vcs_clean == 1 && vcs_total == 4 ? 0 : 1
        }
    '; then
        echo "[-] Binary VCS provenance does not match the clean exact source commit: ${artifact}" >&2
        return 1
    fi
}

validate_amd64_level_binary() {
    artifact="$1"
    "${GO_BIN}" version -m "${artifact}" | grep -Eq \
        '^[[:space:]]*build[[:space:]]+GOAMD64=v1$' || {
        echo "[-] Binary does not attest the baseline AMD64 feature level: ${artifact}" >&2
        return 1
    }
}

for artifact in \
    "${PACKAGE_WORKSPACE}"/dist/bin/* \
    "${PACKAGE_WORKSPACE}"/dist/bin-apk/*; do
    validate_trimpath_binary "${artifact}"
    validate_vcs_binary "${artifact}"
    validate_amd64_level_binary "${artifact}"
done

echo "[+] Linux Compilation successful."

# 3. Prepare Staging Environment
echo "[*] Preparing File Hierarchy for Packaging..."
cd "${PACKAGE_WORKSPACE}"
install -d -m 0755 \
    staging \
    staging/opt \
    staging/opt/syswarden \
    staging/opt/syswarden/bin \
    staging/usr \
    staging/usr/lib \
    staging/usr/lib/systemd \
    staging/usr/lib/systemd/system \
    staging/usr/lib/systemd/system/syswarden-firewall.service.d \
    staging/usr/local \
    staging/usr/local/bin \
    staging/usr/share \
    staging/usr/share/bash-completion \
    staging/usr/share/bash-completion/completions \
    staging/usr/share/doc \
    staging/usr/share/doc/syswarden \
    staging-apk \
    staging-apk/opt \
    staging-apk/opt/syswarden \
    staging-apk/opt/syswarden/bin \
    staging-apk/usr \
    staging-apk/usr/local \
    staging-apk/usr/local/bin \
    staging-apk/usr/share \
    staging-apk/usr/share/bash-completion \
    staging-apk/usr/share/bash-completion/completions \
    staging-apk/usr/share/doc \
    staging-apk/usr/share/doc/syswarden

# Copy files
cp "${SOURCE_ROOT}/src/core/syswarden-core/signatures.json" staging/opt/syswarden/
cp dist/bin/syswarden-cli dist/bin/syswarden-core dist/bin/syswarden-tui staging/opt/syswarden/bin/
ln -s /opt/syswarden/bin/syswarden-cli staging/usr/local/bin/syswarden
ln -s /opt/syswarden/bin/syswarden-tui staging/usr/local/bin/syswarden-tui
staging/opt/syswarden/bin/syswarden-cli completion bash > \
    staging/usr/share/bash-completion/completions/syswarden
install -m 0644 \
    "${SOURCE_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    staging/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt
install -m 0644 \
    "${SOURCE_ROOT}/LICENSE" \
    staging/usr/share/doc/syswarden/LICENSE.txt
install -m 0644 \
    "${SOURCE_ROOT}/src/init/systemd/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf" \
    staging/usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf
cp "${SOURCE_ROOT}/src/core/syswarden-core/signatures.json" staging-apk/opt/syswarden/
cp dist/bin-apk/syswarden-cli dist/bin-apk/syswarden-core dist/bin-apk/syswarden-tui staging-apk/opt/syswarden/bin/
ln -s /opt/syswarden/bin/syswarden-cli staging-apk/usr/local/bin/syswarden
ln -s /opt/syswarden/bin/syswarden-tui staging-apk/usr/local/bin/syswarden-tui
staging-apk/opt/syswarden/bin/syswarden-cli completion bash > \
    staging-apk/usr/share/bash-completion/completions/syswarden
install -m 0644 \
    "${SOURCE_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    staging-apk/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt
install -m 0644 \
    "${SOURCE_ROOT}/LICENSE" \
    staging-apk/usr/share/doc/syswarden/LICENSE.txt

# Permissions
chmod 750 staging/opt/syswarden/bin/*
chmod 640 staging/opt/syswarden/signatures.json
chmod 644 staging/usr/share/bash-completion/completions/syswarden
chmod 750 staging-apk/opt/syswarden/bin/*
chmod 640 staging-apk/opt/syswarden/signatures.json
chmod 644 staging-apk/usr/share/bash-completion/completions/syswarden
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_ROOT}/scripts/ci/package_stage_gate.py" \
    linux --root staging \
    --service-manager systemd \
    --systemd-ordering-contract \
    "${SOURCE_ROOT}/scripts/ci/package_systemd_wireguard_ordering_contract.json" \
    --systemd-ordering-source \
    "${SOURCE_ROOT}/src/init/systemd/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf" \
    --completion-contract "${SOURCE_ROOT}/scripts/ci/package_completion_contract.json" \
    --geoip-data-license-contract \
    "${SOURCE_ROOT}/scripts/ci/package_geoip_data_license_contract.json" \
    --geoip-data-license-source \
    "${SOURCE_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    --project-license-contract \
    "${SOURCE_ROOT}/scripts/ci/package_project_license_contract.json" \
    --project-license-source "${SOURCE_ROOT}/LICENSE"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_ROOT}/scripts/ci/package_stage_gate.py" \
    linux --root staging-apk \
    --service-manager openrc \
    --completion-contract "${SOURCE_ROOT}/scripts/ci/package_completion_contract.json" \
    --geoip-data-license-contract \
    "${SOURCE_ROOT}/scripts/ci/package_geoip_data_license_contract.json" \
    --geoip-data-license-source \
    "${SOURCE_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    --project-license-contract \
    "${SOURCE_ROOT}/scripts/ci/package_project_license_contract.json" \
    --project-license-source "${SOURCE_ROOT}/LICENSE"

validate_static_apk_binary() {
    artifact="$1"
    expected_machine="$2"
    elf_type="$(readelf --file-header "${artifact}" | sed -n 's/^[[:space:]]*Type:[[:space:]]*\([^[:space:]]*\).*/\1/p')"
    machine="$(readelf --file-header "${artifact}" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
    [ "${elf_type}" = "EXEC" ] || {
        echo "[-] Alpine artifact is not a static ET_EXEC binary: ${artifact}" >&2
        return 1
    }
    [ "${machine}" = "${expected_machine}" ] || {
        echo "[-] Alpine artifact has unexpected machine ${machine}: ${artifact}" >&2
        return 1
    }
    if readelf --program-headers "${artifact}" | grep -q '[[:space:]]INTERP[[:space:]]'; then
        echo "[-] Alpine artifact contains a dynamic PT_INTERP loader: ${artifact}" >&2
        return 1
    fi
    file "${artifact}" | grep -Fq 'statically linked' || {
        echo "[-] Alpine artifact is not statically linked: ${artifact}" >&2
        return 1
    }
    "${GO_BIN}" version -m "${artifact}" | grep -Eq '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0$' || {
        echo "[-] Alpine artifact was not built with CGO_ENABLED=0: ${artifact}" >&2
        return 1
    }
}

for artifact in staging-apk/opt/syswarden/bin/*; do
    validate_static_apk_binary "${artifact}" 'Advanced Micro Devices X86-64'
done
staging-apk/opt/syswarden/bin/syswarden-cli --help >/dev/null

prepare_rpm_build_id_links() {
    local rpm_root="$1"
    shift
    [ "$#" -eq 3 ] || {
        echo "[-] RPM build-id preparation requires exactly three binaries." >&2
        return 1
    }
    local rpm_build_id_root="${rpm_root%/}/usr/lib/.build-id"
    install -d -m 0755 "${rpm_build_id_root}"
    declare -A rpm_build_ids=()
    local rpm_binary rpm_notes rpm_build_id rpm_build_id_prefix
    local rpm_build_id_suffix rpm_build_id_directory rpm_build_id_link
    for rpm_binary in "$@"; do
        rpm_notes="$(LC_ALL=C readelf --notes "${rpm_binary}")" || return 1
        rpm_build_id="$(
            printf '%s\n' "${rpm_notes}" |
                sed -n 's/^[[:space:]]*Build ID:[[:space:]]*\([0-9a-f][0-9a-f]*\)[[:space:]]*$/\1/p'
        )" || return 1
        if [[ ! "${rpm_build_id}" =~ ^[0-9a-f]{40}$ ]]; then
            echo "[-] RPM binary lacks one exact 40-hex GNU build-id: ${rpm_binary}" >&2
            return 1
        fi
        if [ -n "${rpm_build_ids[${rpm_build_id}]+present}" ]; then
            echo "[-] RPM binaries share a GNU build-id: ${rpm_build_id}" >&2
            return 1
        fi
        rpm_build_ids["${rpm_build_id}"]="${rpm_binary}"
        rpm_build_id_prefix="${rpm_build_id:0:2}"
        rpm_build_id_suffix="${rpm_build_id:2}"
        rpm_build_id_directory="${rpm_build_id_root}/${rpm_build_id_prefix}"
        rpm_build_id_link="${rpm_build_id_directory}/${rpm_build_id_suffix}"
        install -d -m 0755 "${rpm_build_id_directory}"
        [ ! -e "${rpm_build_id_link}" ] && [ ! -L "${rpm_build_id_link}" ] || {
            echo "[-] Refusing an existing RPM build-id path: ${rpm_build_id_link}" >&2
            return 1
        }
        ln -s \
            "../../../../opt/syswarden/bin/$(basename -- "${rpm_binary}")" \
            "${rpm_build_id_link}"
    done
    [ "${#rpm_build_ids[@]}" -eq 3 ]
}

install -d -m 0755 staging-rpm
cp -a staging/. staging-rpm/
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 0 ]; then
    prepare_rpm_build_id_links \
        staging-rpm \
        staging-rpm/opt/syswarden/bin/syswarden-cli \
        staging-rpm/opt/syswarden/bin/syswarden-core \
        staging-rpm/opt/syswarden/bin/syswarden-tui
fi

RHEL_PROFILE_STAGE=""
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
    RHEL_PROFILE_STAGE="${PACKAGE_WORKSPACE}/rhel-package-owned-profile"
    PYTHONDONTWRITEBYTECODE=1 python3 \
        "${REPOSITORY_ROOT}/extensions/rhel-package-owned/stage.py" \
        --enable-rhel-package-owned-profile \
        --shared-base-payload "${PACKAGE_WORKSPACE}/staging-rpm" \
        --output "${RHEL_PROFILE_STAGE}"
    rhel_profile_build_id_tree="${PACKAGE_WORKSPACE}/staging-rpm/usr/lib/.build-id"
    [ ! -e "${rhel_profile_build_id_tree}" ] && [ ! -L "${rhel_profile_build_id_tree}" ] || {
        echo "[-] RHEL package-owned staging unexpectedly contains a build-id tree." >&2
        exit 1
    }
    for profile_path in \
        usr/lib/systemd/system/syswarden-core.service \
        usr/lib/systemd/system/syswarden-firewall.service \
        usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset \
        usr/share/doc/syswarden/rhel-package-owned-profile.json; do
        if [ -e "staging-rpm/${profile_path}" ] || [ -L "staging-rpm/${profile_path}" ]; then
            echo "[-] Refusing an RPM profile payload collision: ${profile_path}" >&2
            exit 1
        fi
    done
    cp -a "${RHEL_PROFILE_STAGE}/payload/." staging-rpm/
fi

# Pre-Install / Pre-Upgrade script
cat "${SOURCE_ROOT}/scripts/ci/package_webtui_retirement.sh" > preinst.sh
cat "${SOURCE_ROOT}/scripts/ci/package_deferred_purge_postinstall.sh" >> preinst.sh
cat "${SOURCE_ROOT}/scripts/ci/package_alpine_cronie_preflight.sh" >> preinst.sh
cat "${SOURCE_ROOT}/scripts/ci/package_systemd_ordering_preflight.sh" >> preinst.sh
cat << 'EOF' >> preinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
syswarden_preflight_alpine_cronie
syswarden_preflight_install_barriers
syswarden_preflight_systemd_ordering_dropin
if [ "${SYSWARDEN_OFFLINE_QUALIFICATION:-}" = 1 ]; then
    if [ "${syswarden_deferred_present:-0}" -ne 0 ] || \
       [ "${syswarden_finalizing_present:-0}" -ne 0 ]; then
        printf '%s\n' 'Offline qualification requires an installation state without deferred removal barriers.' >&2
        exit 1
    fi
    printf '%s\n' 'SysWarden offline qualification staging: pre-install host mutation deferred.'
    exit 0
fi
secure_private_directory() {
    path="$1"
    if [ -L "${path}" ] || { [ -e "${path}" ] && [ ! -d "${path}" ]; }; then
        echo "Refusing unsafe SysWarden directory: ${path}" >&2
        exit 1
    fi
    if [ ! -d "${path}" ]; then
        (umask 027 && mkdir -p "${path}")
    fi
    expected_user="$(id -un)"
    expected_group="$(id -gn)"
    if [ "$(find "${path}" -prune -user "${expected_user}" -group "${expected_group}" -print)" != "${path}" ]; then
        echo "Refusing non-owner-controlled SysWarden directory: ${path}" >&2
        exit 1
    fi
    chmod go-w,o-rwx "${path}"
    if [ -L "${path}" ] || [ ! -d "${path}" ] || \
       [ "$(find "${path}" -prune -user "${expected_user}" -group "${expected_group}" -print)" != "${path}" ]; then
        echo "SysWarden directory identity changed while securing it: ${path}" >&2
        exit 1
    fi
}
for directory in \
    /etc/syswarden \
    /etc/syswarden/config \
    /etc/syswarden/config/modules \
    /etc/syswarden/lists \
    /etc/syswarden/tls \
    /var/lib/syswarden \
    /var/lib/syswarden/ui; do
    secure_private_directory "${directory}"
done
for legacy_config_path in \
    /opt/syswarden/syswarden-auto.conf \
    /opt/syswarden/syswarden-auto.conf.migration_backup \
    /opt/syswarden/syswarden-auto.conf.migration_backup.migrated \
    /opt/syswarden/syswarden-auto.conf.bak; do
    if [ -L "${legacy_config_path}" ]; then
        echo "Refusing a symlinked legacy configuration path: ${legacy_config_path}" >&2
        exit 1
    fi
done
syswarden_retire_legacy_webtui / || exit 1
if [ -f /opt/syswarden/syswarden-auto.conf ] && \
   [ ! -e /opt/syswarden/syswarden-auto.conf.migration_backup ] && \
   [ ! -e /opt/syswarden/syswarden-auto.conf.migration_backup.migrated ]; then
    mv /opt/syswarden/syswarden-auto.conf /opt/syswarden/syswarden-auto.conf.migration_backup
fi
EOF

# Global Execution Symlink handled via postinst script
cat "${SOURCE_ROOT}/scripts/ci/package_webtui_retirement.sh" > postinst.sh
cat "${SOURCE_ROOT}/scripts/ci/package_deferred_purge_postinstall.sh" >> postinst.sh
cat "${SOURCE_ROOT}/scripts/ci/package_alpine_cronie_preflight.sh" >> postinst.sh
cat << 'EOF' >> postinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
syswarden_preflight_alpine_cronie
syswarden_preflight_install_barriers
if [ "${SYSWARDEN_OFFLINE_QUALIFICATION:-}" = 1 ]; then
    if [ "${syswarden_deferred_present:-0}" -ne 0 ] || \
       [ "${syswarden_finalizing_present:-0}" -ne 0 ]; then
        printf '%s\n' 'Offline qualification requires an installation state without deferred removal barriers.' >&2
        exit 1
    fi
    printf '%s\n' 'SysWarden offline qualification staging: post-install host mutation deferred.'
    exit 0
fi
ln -sf /opt/syswarden/bin/syswarden-cli /usr/local/bin/syswarden
ln -sf /opt/syswarden/bin/syswarden-tui /usr/local/bin/syswarden-tui

package_service_manager() {
    if [ -f /etc/alpine-release ]; then
        printf '%s\n' openrc
    else
        printf '%s\n' systemd
    fi
}

modular_config_complete() {
    for file in \
        /etc/syswarden/config/config.toml \
        /etc/syswarden/config/modules/00-core.toml \
        /etc/syswarden/config/modules/10-network.toml \
        /etc/syswarden/config/modules/20-security.toml \
        /etc/syswarden/config/modules/30-waap.toml \
        /etc/syswarden/config/modules/40-integrations.toml \
        /etc/syswarden/config/modules/99-user.toml; do
        [ -f "${file}" ] || return 1
    done
    return 0
}
migrate_legacy_configuration() {
    source=/opt/syswarden/syswarden-auto.conf.migration_backup
    marker=/etc/syswarden/config/.migration-in-progress
    archive=/opt/syswarden/syswarden-auto.conf.bak
    if [ -f "${marker}" ]; then
        /opt/syswarden/bin/syswarden-cli migrate-config --source "${source}" --output /etc/syswarden/config
    elif [ -f "${source}" ] && ! modular_config_complete; then
        /opt/syswarden/bin/syswarden-cli migrate-config --source "${source}" --output /etc/syswarden/config
    fi
    if [ -f "${source}.migrated" ]; then
        [ ! -e "${archive}" ] && [ ! -L "${archive}" ] || {
            echo "Refusing to overwrite an existing legacy configuration archive" >&2
            return 1
        }
        mv "${source}.migrated" "${archive}"
    elif [ -f "${source}" ] && [ ! -f "${marker}" ] && modular_config_complete; then
        [ ! -e "${archive}" ] && [ ! -L "${archive}" ] || {
            echo "Refusing to overwrite an existing legacy configuration archive" >&2
            return 1
        }
        mv "${source}" "${archive}"
    fi
}
migrate_legacy_configuration

if [ "$1" = "2" ] || [ "$1" = "1" ] || [ "$1" = "configure" ] || [ -f /etc/alpine-release ]; then
    manager="$(package_service_manager)"
    manager_state="$(syswarden_classify_service_manager / "${manager}")"
    case "${manager_state}" in
        ACTIVE)
            /opt/syswarden/bin/syswarden-cli install
            [ "$(syswarden_classify_service_manager / "${manager}")" = ACTIVE ] || {
                echo "Service-manager runtime changed during package installation" >&2
                exit 1
            }
            ;;
        OFFLINE)
            echo "Service-manager runtime is offline; host configuration is deferred until an explicit online install."
            ;;
        *)
            echo "Refusing an ambiguous service-manager runtime" >&2
            exit 1
            ;;
    esac
fi
syswarden_verify_webtui_retirement /
syswarden_consume_deferred_purge_marker
EOF

cat "${SOURCE_ROOT}/scripts/ci/package_webtui_retirement.sh" > postrm.sh
cat "${SOURCE_ROOT}/scripts/ci/package_removal_state.sh" >> postrm.sh
cat << 'EOF' >> postrm.sh
export SYSWARDEN_PKG_INSTALL=1

syswarden_refresh_systemd_after_rpm_payload_transition() {
    [ "${1:-}" = 1 ] || return 0
    [ ! -f /etc/alpine-release ] || return 1
    syswarden_postremove_manager_state="$(
        syswarden_classify_service_manager / systemd isolated
    )" || return 1
    case "${syswarden_postremove_manager_state}" in
        ACTIVE)
            command -v systemctl >/dev/null 2>&1 || return 1
            systemctl daemon-reload || return 1
            [ "$(syswarden_classify_service_manager / systemd isolated)" = ACTIVE ] || return 1
            ;;
        OFFLINE) ;;
        *)
            printf '%s\n' 'Refusing an ambiguous systemd runtime after an RPM payload transition.' >&2
            return 1
            ;;
    esac
}

cleanup_generated_runtime_artifacts() {
    syswarden_verify_legacy_webtui_runtime_absent / || return 1
    printf '%s\n' 'Preserving root crontab and every modified or ambiguous legacy host artifact for manual recovery.' >&2
}

syswarden_path_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

syswarden_refuse_mounted_path_tree() {
    syswarden_mount_root="$1"
    [ -r /proc/self/mountinfo ] || {
        printf 'Refusing removal without readable mount topology: %s\n' "${syswarden_mount_root}" >&2
        return 1
    }
    if ! awk -v root="${syswarden_mount_root}" '
        {
            mountpoint = $5
            gsub(/\\040/, " ", mountpoint)
            gsub(/\\011/, "\t", mountpoint)
            gsub(/\\012/, "\n", mountpoint)
            gsub(/\\134/, "\\", mountpoint)
            if (mountpoint == root || index(mountpoint, root "/") == 1) {
                exit 42
            }
        }
    ' /proc/self/mountinfo; then
        printf 'Refusing removal across a mounted product path: %s\n' "${syswarden_mount_root}" >&2
        return 1
    fi
}

syswarden_attest_dedicated_root() {
    syswarden_root_path="$1"
    syswarden_path_absent "${syswarden_root_path}" && return 0
    [ ! -L "${syswarden_root_path}" ] && [ -d "${syswarden_root_path}" ] || {
        printf 'Refusing unsafe dedicated product root: %s\n' "${syswarden_root_path}" >&2
        return 1
    }
    case "$(stat -c '%u:%g:%a' "${syswarden_root_path}")" in
        0:0:700|0:0:750|0:0:755) ;;
        *) printf 'Refusing unsafe dedicated product root metadata: %s\n' "${syswarden_root_path}" >&2; return 1 ;;
    esac
}

syswarden_remove_exact_product_link() {
    syswarden_link_path="$1"
    syswarden_link_target="$2"
    syswarden_path_absent "${syswarden_link_path}" && return 0
    [ -L "${syswarden_link_path}" ] || {
        printf 'Refusing non-symlink product launcher: %s\n' "${syswarden_link_path}" >&2
        return 1
    }
    [ "$(stat -c '%u:%g:%h' "${syswarden_link_path}")" = '0:0:1' ] || return 1
    [ "$(readlink "${syswarden_link_path}")" = "${syswarden_link_target}" ] || {
        printf 'Refusing unexpected product launcher target: %s\n' "${syswarden_link_path}" >&2
        return 1
    }
    [ "$(readlink "${syswarden_link_path}")" = "${syswarden_link_target}" ] || return 1
    rm -f -- "${syswarden_link_path}" || return 1
    syswarden_path_absent "${syswarden_link_path}"
}

syswarden_remove_exact_runtime_socket() {
    syswarden_socket_path="$1"
    syswarden_path_absent "${syswarden_socket_path}" && return 0
    [ ! -L "${syswarden_socket_path}" ] && [ -S "${syswarden_socket_path}" ] || {
        printf 'Refusing non-attributable product socket: %s\n' "${syswarden_socket_path}" >&2
        return 1
    }
    [ "$(stat -c '%u:%g:%h' "${syswarden_socket_path}")" = '0:0:1' ] || return 1
    [ ! -L "${syswarden_socket_path}" ] && [ -S "${syswarden_socket_path}" ] || return 1
    rm -f -- "${syswarden_socket_path}" || return 1
    syswarden_path_absent "${syswarden_socket_path}"
}

syswarden_remove_dedicated_root() {
    syswarden_root_path="$1"
    syswarden_path_absent "${syswarden_root_path}" && return 0
    syswarden_attest_dedicated_root "${syswarden_root_path}" || return 1
    syswarden_refuse_mounted_path_tree "${syswarden_root_path}" || return 1
    syswarden_attest_dedicated_root "${syswarden_root_path}" || return 1
    rm -rf -- "${syswarden_root_path}" || return 1
    syswarden_path_absent "${syswarden_root_path}"
}

if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    cleanup_generated_runtime_artifacts || exit 1
    syswarden_remove_exact_product_link /usr/local/bin/syswarden /opt/syswarden/bin/syswarden-cli || exit 1
    syswarden_remove_exact_product_link /usr/local/bin/syswarden-tui /opt/syswarden/bin/syswarden-tui || exit 1
    syswarden_remove_exact_runtime_socket /run/syswarden.sock || exit 1
    if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || [ "$1" = "purge" ]; then
        syswarden_select_removal_barrier
        syswarden_barrier_status=$?
        if [ "${syswarden_barrier_status}" -eq 2 ]; then
            syswarden_resume_unmarked_terminal_state || exit 1
            exit 0
        fi
        [ "${syswarden_barrier_status}" -eq 0 ] || exit 1
        if [ "${syswarden_barrier_kind}" = finalizing ]; then
            syswarden_resume_external_finalization || exit 1
            exit 0
        fi
        for syswarden_purge_root in \
            /opt/syswarden \
            /etc/syswarden \
            /var/log/syswarden \
            /var/lib/syswarden; do
            syswarden_attest_dedicated_root "${syswarden_purge_root}" || exit 1
            syswarden_refuse_mounted_path_tree "${syswarden_purge_root}" || exit 1
        done
        syswarden_attest_removal_marker "${syswarden_active_barrier}" || exit 1
        syswarden_remove_dedicated_root /opt/syswarden || exit 1
        syswarden_remove_dedicated_root /etc/syswarden || exit 1
        syswarden_remove_dedicated_root /var/log/syswarden || exit 1
        syswarden_empty_removal_state || exit 1
        syswarden_finalize_removal_state_root || exit 1
    else
        syswarden_transition_to_deferred_purge || exit 1
    fi
fi
syswarden_refresh_systemd_after_rpm_payload_transition "${1:-}" || exit 1
EOF

cat "${SOURCE_ROOT}/scripts/ci/package_webtui_retirement.sh" > prerm.sh
cat << 'EOF' >> prerm.sh
export SYSWARDEN_PKG_INSTALL=1
case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in
::0|::remove|::purge) ;;
::*grade|::reinstall|::deconfigure) exit;;
syswarden:pre-deinstall:*|::*.*.*) case "$1" in *[!0-9.]*) exit 1;;esac;printf %s "$1"|grep -Eq '^[1-9][0-9]*(\.(0|[1-9][0-9]*)){2}$'||exit;[ -n "${APK_SCRIPT:-}" ]||[ -f /etc/alpine-release ]||exit;;
::*) [ "$1" -gt 0 ] 2>/dev/null&&exit;exit 1;;
*) exit 1;;
esac
/opt/syswarden/bin/syswarden-cli prepare-package-removal || exit 1
syswarden_retire_legacy_webtui / || exit 1
printf '%s\n' 'Root crontab bytes and ambiguous legacy host artifacts were preserved for manual recovery.' >&2
EOF

chmod +x preinst.sh postinst.sh postrm.sh prerm.sh

RPM_SCRIPTS="${PACKAGE_WORKSPACE}/rpm-scripts"
install -d -m 0700 "${RPM_SCRIPTS}"
# rpmbuild expands RPM macros inside scriptlets. Double each percent only in
# the private RPM inputs so final scriptlets stay byte-exact.
prepare_rpm_scriptlet() {
    local source="$1"
    local destination="$2"
    if [ -L "${source}" ] || [ ! -f "${source}" ]; then
        echo "[-] RPM scriptlet source is not a regular file: ${source}" >&2
        return 1
    fi
    LC_ALL=C sed 's/%/%%/g' -- "${source}" > "${destination}"
    chmod 0700 "${destination}"
    if [ -L "${destination}" ] || [ ! -f "${destination}" ]; then
        echo "[-] RPM scriptlet input is not a regular file: ${destination}" >&2
        return 1
    fi
}
RPM_EXPECTED_PREIN="${PACKAGE_WORKSPACE}/preinst.sh"
RPM_EXPECTED_POSTIN="${PACKAGE_WORKSPACE}/postinst.sh"
RPM_EXPECTED_PREUN="${PACKAGE_WORKSPACE}/prerm.sh"
RPM_EXPECTED_POSTUN="${PACKAGE_WORKSPACE}/postrm.sh"
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
    RPM_EXPECTED_PREIN="${RHEL_PROFILE_STAGE}/rpm-scriptlets/pre-install.sh"
    RPM_EXPECTED_POSTIN="${RHEL_PROFILE_STAGE}/rpm-scriptlets/post-install.sh"
    RPM_EXPECTED_PREUN="${RHEL_PROFILE_STAGE}/rpm-scriptlets/pre-uninstall.sh"
    RPM_EXPECTED_POSTUN="${RHEL_PROFILE_STAGE}/rpm-scriptlets/post-uninstall.sh"
fi
prepare_rpm_scriptlet "${RPM_EXPECTED_PREIN}" "${RPM_SCRIPTS}/preinst.sh"
prepare_rpm_scriptlet "${RPM_EXPECTED_POSTIN}" "${RPM_SCRIPTS}/postinst.sh"
prepare_rpm_scriptlet "${RPM_EXPECTED_PREUN}" "${RPM_SCRIPTS}/prerm.sh"
prepare_rpm_scriptlet "${RPM_EXPECTED_POSTUN}" "${RPM_SCRIPTS}/postrm.sh"

prepare_rpm_changelog() {
    local destination="$1"
    local package_release="$2"
    local changelog_date
    local changelog_day
    changelog_day="$(date --utc --date="@${SOURCE_DATE_EPOCH}" '+%Y-%m-%d')" || return 1
    changelog_date="$(date --utc --date="@${SOURCE_DATE_EPOCH}" '+%a %b %e %Y')" || return 1
    RPM_CHANGELOG_EPOCH="$(date --utc --date="${changelog_day} 12:00:00" '+%s')" || return 1
    case "${RPM_CHANGELOG_EPOCH}" in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    printf '* %s SysWarden Engineering - %s-%s\n- Package created with FPM\n' \
        "${changelog_date}" "${VERSION}" "${package_release}" > "${destination}"
    chmod 0600 "${destination}"
}
normalize_package_mtimes() {
    local target
    for target in "$@"; do
        if [ ! -e "${target}" ] && [ ! -L "${target}" ]; then
            echo "ERROR: package timestamp target is missing: ${target}" >&2
            return 1
        fi
        find "${target}" -depth -exec \
            touch -h --date="@${SOURCE_DATE_EPOCH}" -- {} +
    done
}
RPM_CHANGELOG="${PACKAGE_WORKSPACE}/rpm-changelog"
prepare_rpm_changelog "${RPM_CHANGELOG}" "${RPM_PACKAGE_RELEASE}"
normalize_package_mtimes \
    staging \
    staging-rpm \
    staging-apk \
    preinst.sh \
    postinst.sh \
    prerm.sh \
    postrm.sh \
    "${RPM_SCRIPTS}" \
    "${RPM_CHANGELOG}"

# 4. Generate Packages
echo "[*] Generating .deb and .rpm packages via FPM..."

RPM_PROFILE_DEPENDENCIES=()
RPM_PROFILE_FPM_OPTIONS=()
RPM_BUILD_ID_FPM_OPTIONS=(--directories /usr/lib/.build-id)
RPM_BUILD_ID_DEFINE_OPTIONS=()
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
    RPM_PROFILE_DEPENDENCIES=(-d "systemd")
    RPM_BUILD_ID_FPM_OPTIONS=()
    RPM_BUILD_ID_DEFINE_OPTIONS=(--rpm-rpmbuild-define "_build_id_links none")
    RPM_PROFILE_FPM_OPTIONS=(
        --rpm-digest sha256
        --directories /etc/syswarden
        --directories /etc/syswarden/config
        --directories /etc/syswarden/config/modules
        --directories /etc/syswarden/lists
        --directories /etc/syswarden/tls
        --directories /var/lib/syswarden
        --directories /var/lib/syswarden/ui
        --directories /var/log/syswarden
        --rpm-attr "0750,root,root:/etc/syswarden"
        --rpm-attr "0750,root,root:/etc/syswarden/config"
        --rpm-attr "0750,root,root:/etc/syswarden/config/modules"
        --rpm-attr "0750,root,root:/etc/syswarden/lists"
        --rpm-attr "0750,root,root:/etc/syswarden/tls"
        --rpm-attr "0750,root,root:/var/lib/syswarden"
        --rpm-attr "0750,root,root:/var/lib/syswarden/ui"
        --rpm-attr "0750,root,root:/var/log/syswarden"
        --rpm-attr "0755,root,root:/usr/share/doc/syswarden"
    )
fi

# Generate DEB
(
    # FPM creates the generated Debian changelog under the active umask.
    # Scope 022 to this public package payload while the private workspace
    # and every other intermediate remain protected by the global 077.
    umask 022
    fpm -f -s dir -t deb \
        -n syswarden \
        -v "${VERSION}" \
        --vendor "SysWarden Security" \
        --maintainer "SysWarden Engineering" \
        --description "SysWarden Host-based Security Orchestrator for Linux" \
        --url "https://github.com/duggytuxy/syswarden" \
        --license "GPL-3.0-or-later" \
        --source-date-epoch-default "${SOURCE_DATE_EPOCH}" \
        -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "cron" -d "bash-completion" \
        -d "wireguard-tools" -d "qrencode" -d "jq" -d "unattended-upgrades" -d "apt-listchanges" -d "procps" -d "e2fsprogs" \
        --before-install preinst.sh \
        --after-install postinst.sh \
        --before-remove prerm.sh \
        --after-remove postrm.sh \
        -p "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb" \
        -C staging .
)

# Generate RPM
(
    # FPM recreates explicitly owned RPM directories under the active umask.
    # Match the workflow's public 0755 build-id directories in this bounded
    # package subprocess while retaining 077 everywhere else.
    umask 022
    fpm -f -s dir -t rpm \
        -n syswarden \
        -v "${VERSION}" \
        --iteration "${RPM_PACKAGE_RELEASE}" \
        --vendor "SysWarden Security" \
        --maintainer "SysWarden Engineering" \
        --description "SysWarden Host-based Security Orchestrator for Linux" \
        --url "https://github.com/duggytuxy/syswarden" \
        --license "GPL-3.0-or-later" \
        --source-date-epoch-default "${SOURCE_DATE_EPOCH}" \
        --rpm-changelog "${RPM_CHANGELOG}" \
        -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "cronie" -d "bash-completion" \
        -d "wireguard-tools" -d "jq" -d "checkpolicy" -d "policycoreutils-python-utils" \
        -d "dnf-automatic" -d "procps-ng" -d "e2fsprogs" \
        "${RPM_PROFILE_DEPENDENCIES[@]}" \
        "${RPM_PROFILE_FPM_OPTIONS[@]}" \
        --before-install "${RPM_SCRIPTS}/preinst.sh" \
        --after-install "${RPM_SCRIPTS}/postinst.sh" \
        --before-remove "${RPM_SCRIPTS}/prerm.sh" \
        --after-remove "${RPM_SCRIPTS}/postrm.sh" \
        --rpm-digest sha256 \
        "${RPM_BUILD_ID_DEFINE_OPTIONS[@]}" \
        --rpm-rpmbuild-define "_binary_filedigest_algorithm 8" \
        --rpm-rpmbuild-define "_source_filedigest_algorithm 8" \
        --rpm-rpmbuild-define "use_source_date_epoch_as_buildtime 1" \
        --rpm-rpmbuild-define "clamp_mtime_to_source_date_epoch 1" \
        --rpm-rpmbuild-define "_buildhost syswarden-build.invalid" \
        "${RPM_BUILD_ID_FPM_OPTIONS[@]}" \
        --directories /usr/share/doc/syswarden \
        -p "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" \
        -C staging-rpm .
)

# Generate Alpine APK via nfpm
echo "[*] Generating .apk package via nfpm..."
cat << EOF > nfpm_alpine_amd64.yaml
name: "syswarden"
arch: "amd64"
platform: "linux"
version: "${VERSION}"
maintainer: "SysWarden Engineering"
description: "SysWarden Host-based Security Orchestrator for Alpine Linux"
vendor: "SysWarden Security"
homepage: "https://github.com/duggytuxy/syswarden"
license: "GPL-3.0-or-later"
depends:
  - nftables
  - openrc
  - cronie
  - cronie-openrc
  - curl
  - wget
  - rsyslog
  - rsyslog-uxsock
  - bash-completion
  - wireguard-tools
  - libqrencode-tools
  - jq
  - procps-ng
  - e2fsprogs-extra
  - shadow
contents:
  - src: "./staging-apk/opt"
    dst: "/opt"
  - src: "./staging-apk/usr"
    dst: "/usr"
scripts:
  preinstall: "./preinst.sh"
  postinstall: "./postinst.sh"
  preremove: "./prerm.sh"
  postremove: "./postrm.sh"
apk:
  scripts:
    preupgrade: "./preinst.sh"
    postupgrade: "./postinst.sh"
EOF
"${NFPM_BIN}" pkg \
    --config nfpm_alpine_amd64.yaml \
    --packager apk \
    --target "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_x86_64.apk"

PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_ROOT}/scripts/ci/package_systemd_ordering_artifact_gate.py" \
    --format stage \
    --root staging \
    --source \
    "${SOURCE_ROOT}/src/init/systemd/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf" \
    --contract "${SOURCE_ROOT}/scripts/ci/package_systemd_wireguard_ordering_contract.json"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_ROOT}/scripts/ci/package_systemd_ordering_artifact_gate.py" \
    --format deb \
    --package "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb" \
    --source \
    "${SOURCE_ROOT}/src/init/systemd/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf" \
    --contract "${SOURCE_ROOT}/scripts/ci/package_systemd_wireguard_ordering_contract.json"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_ROOT}/scripts/ci/package_systemd_ordering_artifact_gate.py" \
    --format rpm \
    --package "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" \
    --source \
    "${SOURCE_ROOT}/src/init/systemd/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf" \
    --contract "${SOURCE_ROOT}/scripts/ci/package_systemd_wireguard_ordering_contract.json"

validate_local_deb_changelog() {
    local deb_path="$1"
    local deb_data_members deb_changelog_metadata
    deb_data_members="$(ar t "${deb_path}" | awk '$0 == "data.tar.gz" { print }')" || return 1
    [ "${deb_data_members}" = data.tar.gz ] || return 1
    deb_changelog_metadata="$(
        ar p "${deb_path}" data.tar.gz |
            LC_ALL=C tar -tzvf - ./usr/share/doc/syswarden/changelog.gz
    )" || return 1
    if ! printf '%s\n' "${deb_changelog_metadata}" | awk '
        NR == 1 && NF == 6 &&
        $1 == "-rw-r--r--" && $2 == "0/0" &&
        $3 ~ /^[1-9][0-9]*$/ &&
        $6 == "./usr/share/doc/syswarden/changelog.gz" { valid = 1 }
        END { exit !(NR == 1 && valid == 1) }
    '; then
        echo "[-] Debian changelog is not one root-owned 0644 regular file." >&2
        return 1
    fi
}

validate_local_deb_license() {
    local deb_path="$1"
    local license_lines
    license_lines="$(
        ar p "${deb_path}" control.tar.gz |
            LC_ALL=C tar -xOzf - ./control |
            LC_ALL=C awk -F ': ' '$1 == "License" { print $2 }'
    )" || return 1
    [ "${license_lines}" = GPL-3.0-or-later ]
}

validate_local_deb_homepage() {
    local deb_path="$1"
    local homepage_lines
    homepage_lines="$(
        ar p "${deb_path}" control.tar.gz |
            LC_ALL=C tar -xOzf - ./control |
            LC_ALL=C awk -F ': ' '$1 == "Homepage" { print $2 }'
    )" || return 1
    [ "${homepage_lines}" = https://github.com/duggytuxy/syswarden ]
}

validate_local_apk_license() {
    local apk_path="$1"
    local metadata
    metadata="$(LC_ALL=C tar -xOzf "${apk_path}" .PKGINFO)" || return 1
    [ "$(grep -Fxc 'license = GPL-3.0-or-later' <<< "${metadata}")" -eq 1 ]
}

validate_local_apk_homepage() {
    local apk_path="$1"
    local metadata
    metadata="$(LC_ALL=C tar -xOzf "${apk_path}" .PKGINFO)" || return 1
    [ "$(grep -Fxc 'url = https://github.com/duggytuxy/syswarden' <<< "${metadata}")" -eq 1 ]
}

validate_local_rpm_scriptlet() {
    local rpm_path="$1"
    local tag="$2"
    local expected_path="$3"
    local actual
    local expected
    local interpreter
    actual="$(rpm -qp --qf "%{${tag}}" "${rpm_path}")" || return 1
    expected="$(cat "${expected_path}")" || return 1
    interpreter="$(rpm -qp --qf "%{${tag}PROG}" "${rpm_path}")" || return 1
    [ -n "${actual}" ] && \
        [ "${actual}" = "${expected}" ] && \
        [ "${interpreter}" = /bin/sh ]
}

validate_local_rpm_build_ids() {
    local rpm_path="$1"
    declare -A rpm_build_id_directories=()
    declare -A rpm_build_id_prefixes=()
    declare -A rpm_build_id_targets=()
    local rpm_build_id_root_count=0
    local rpm_inventory rpm_pathname rpm_permissions rpm_owner rpm_target rpm_prefix
    [ "$(rpm -qp --qf '%{BUILDTIME}' "${rpm_path}")" = "${SOURCE_DATE_EPOCH}" ] || return 1
    [ "$(rpm -qp --qf '%{BUILDHOST}' "${rpm_path}")" = syswarden-build.invalid ] || return 1
    [ "$(rpm -qp --qf '%{CHANGELOGTIME}' "${rpm_path}")" = "${RPM_CHANGELOG_EPOCH}" ] || return 1
    [ "$(rpm -qp --qf '%{LICENSE}' "${rpm_path}")" = GPL-3.0-or-later ] || return 1
    [ "$(rpm -qp --qf '%{URL}' "${rpm_path}")" = https://github.com/duggytuxy/syswarden ] || return 1
    validate_local_rpm_scriptlet "${rpm_path}" PREIN "${RPM_EXPECTED_PREIN}" || return 1
    validate_local_rpm_scriptlet "${rpm_path}" POSTIN "${RPM_EXPECTED_POSTIN}" || return 1
    validate_local_rpm_scriptlet "${rpm_path}" PREUN "${RPM_EXPECTED_PREUN}" || return 1
    validate_local_rpm_scriptlet "${rpm_path}" POSTUN "${RPM_EXPECTED_POSTUN}" || return 1
    rpm_inventory="$(
        rpm -qp --qf \
            '[%{FILENAMES}\t%{FILEMODES:perms}\t%{FILEUSERNAME}:%{FILEGROUPNAME}\t%{FILELINKTOS}\n]' \
            "${rpm_path}"
    )" || return 1
    if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
        while IFS=$'\t' read -r rpm_pathname _; do
            case "${rpm_pathname}" in
                /usr/lib/.build-id|/usr/lib/.build-id/*) return 1 ;;
            esac
        done <<< "${rpm_inventory}"
        return 0
    fi
    while IFS=$'\t' read -r rpm_pathname rpm_permissions rpm_owner rpm_target; do
        case "${rpm_pathname}" in
            /usr/lib/.build-id)
                [ "${rpm_permissions}" = drwxr-xr-x ] && \
                    [ "${rpm_owner}" = root:root ] && \
                    [ -z "${rpm_target}" ] || return 1
                rpm_build_id_root_count=$((rpm_build_id_root_count + 1))
                ;;
            /usr/lib/.build-id/*)
                if [[ "${rpm_pathname}" =~ ^/usr/lib/\.build-id/([0-9a-f]{2})$ ]]; then
                    rpm_prefix="${BASH_REMATCH[1]}"
                    [ "${rpm_permissions}" = drwxr-xr-x ] && \
                        [ "${rpm_owner}" = root:root ] && \
                        [ -z "${rpm_target}" ] || return 1
                    [ -z "${rpm_build_id_directories[${rpm_prefix}]+present}" ] || return 1
                    rpm_build_id_directories["${rpm_prefix}"]=1
                elif [[ "${rpm_pathname}" =~ ^/usr/lib/\.build-id/([0-9a-f]{2})/([0-9a-f]{38})$ ]]; then
                    rpm_prefix="${BASH_REMATCH[1]}"
                    [ "${rpm_permissions}" = lrwxrwxrwx ] && \
                        [ "${rpm_owner}" = root:root ] || return 1
                    case "${rpm_target}" in
                        ../../../../opt/syswarden/bin/syswarden-cli|\
                        ../../../../opt/syswarden/bin/syswarden-core|\
                        ../../../../opt/syswarden/bin/syswarden-tui) ;;
                        *) return 1 ;;
                    esac
                    [ -z "${rpm_build_id_targets[${rpm_target}]+present}" ] || return 1
                    rpm_build_id_targets["${rpm_target}"]=1
                    rpm_build_id_prefixes["${rpm_prefix}"]=1
                else
                    return 1
                fi
                ;;
        esac
    done <<< "${rpm_inventory}"
    [ "${rpm_build_id_root_count}" -eq 1 ] && \
        [ "${#rpm_build_id_targets[@]}" -eq 3 ] && \
        [ "${#rpm_build_id_directories[@]}" -eq "${#rpm_build_id_prefixes[@]}" ] || return 1
    for rpm_prefix in "${!rpm_build_id_prefixes[@]}"; do
        [ -n "${rpm_build_id_directories[${rpm_prefix}]+present}" ] || return 1
    done
}

if ! validate_local_deb_changelog \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb"; then
    echo "[-] Local Debian archive validation failed." >&2
    exit 1
fi
if ! validate_local_deb_license \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb"; then
    echo "[-] Local Debian license metadata validation failed." >&2
    exit 1
fi
if ! validate_local_deb_homepage \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb"; then
    echo "[-] Local Debian homepage metadata validation failed." >&2
    exit 1
fi
if ! validate_local_rpm_build_ids \
    "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}"; then
    echo "[-] Local RPM build-id validation failed." >&2
    rpm -qp --qf \
        '[%{FILENAMES}\t%{FILEMODES:perms}\t%{FILEUSERNAME}:%{FILEGROUPNAME}\t%{FILELINKTOS}\n]' \
        "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" >&2 || true
    exit 1
fi
if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then
    RPM_PROFILE_SHA256="$(
        sha256sum "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" |
            awk 'NF == 2 && $1 ~ /^[0-9a-f]{64}$/ { print $1 }'
    )"
    if [[ ! "${RPM_PROFILE_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "[-] Unable to bind the RHEL package-owned RPM digest." >&2
        exit 1
    fi
    PYTHONDONTWRITEBYTECODE=1 python3 \
        "${REPOSITORY_ROOT}/extensions/rhel-package-owned/verify-rpm.py" \
        --rpm "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" \
        --sha256 "${RPM_PROFILE_SHA256}"
fi
if ! validate_local_apk_license \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_x86_64.apk"; then
    echo "[-] Local Alpine license metadata validation failed." >&2
    exit 1
fi
if ! validate_local_apk_homepage \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_x86_64.apk"; then
    echo "[-] Local Alpine homepage metadata validation failed." >&2
    exit 1
fi

publish_local_package() {
    source_path="$1"
    filename="$(basename -- "${source_path}")"
    destination="${LOCAL_PACKAGE_OUTPUT}/${filename}"
    if [ -L "${destination}" ] || { [ -e "${destination}" ] && [ ! -f "${destination}" ]; }; then
        echo "[-] Refusing an unsafe local package destination: ${destination}" >&2
        return 1
    fi
    temporary="$(mktemp "${LOCAL_PACKAGE_OUTPUT}/.${filename}.XXXXXX")"
    if ! cp -- "${source_path}" "${temporary}" || \
       ! chmod 0644 "${temporary}" || \
       ! sync -f "${temporary}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    expected_user="$(id -un)"
    expected_group="$(id -gn)"
    if [ -L "${temporary}" ] || [ ! -f "${temporary}" ] || \
       [ "$(find "${temporary}" -prune -user "${expected_user}" \
           -group "${expected_group}" -links 1 -perm 0644 -print)" != "${temporary}" ]; then
        echo "[-] Refusing an unsafe staged local package: ${temporary}" >&2
        rm -f -- "${temporary}"
        return 1
    fi
    if ! mv -fT -- "${temporary}" "${destination}" || \
       ! sync -f "${LOCAL_PACKAGE_OUTPUT}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    if [ -L "${destination}" ] || [ ! -f "${destination}" ] || \
       [ "$(find "${destination}" -prune -user "${expected_user}" \
           -group "${expected_group}" -links 1 -perm 0644 -print)" != "${destination}" ] || \
       ! cmp -s -- "${source_path}" "${destination}"; then
        echo "[-] Local package publication verification failed: ${destination}" >&2
        return 1
    fi
}

publish_local_checksums() {
    local destination expected_group expected_user filename manifest temporary
    local -a filenames=(
        "syswarden_${VERSION}_amd64.deb"
        "${RPM_PACKAGE_FILENAME}"
        "syswarden_${VERSION}_x86_64.apk"
    )
    destination="${LOCAL_PACKAGE_OUTPUT}/SHA256SUMS.txt"
    manifest="${PACKAGE_WORKSPACE}/SHA256SUMS.txt"
    if [ -e "${manifest}" ] || [ -L "${manifest}" ]; then
        echo "[-] Refusing an occupied private checksum path: ${manifest}" >&2
        return 1
    fi
    expected_user="$(id -un)"
    expected_group="$(id -gn)"
    for filename in "${filenames[@]}"; do
        if [ -L "${PACKAGE_WORKSPACE}/${filename}" ] || \
           [ ! -f "${PACKAGE_WORKSPACE}/${filename}" ] || \
           [ "$(find "${PACKAGE_WORKSPACE}/${filename}" -prune \
               -user "${expected_user}" -group "${expected_group}" \
               -links 1 -perm 0644 -print)" != "${PACKAGE_WORKSPACE}/${filename}" ]; then
            echo "[-] Refusing an unsafe private package for checksumming: ${filename}" >&2
            return 1
        fi
    done
    temporary="$(mktemp "${PACKAGE_WORKSPACE}/.SHA256SUMS.txt.XXXXXX")" || return 1
    if ! (
        cd "${PACKAGE_WORKSPACE}" || exit 1
        sha256sum -- "${filenames[@]}"
    ) >"${temporary}" || \
       ! chmod 0644 "${temporary}" || \
       ! sync -f "${temporary}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    if [ -L "${temporary}" ] || [ ! -f "${temporary}" ] || \
       [ "$(find "${temporary}" -prune -user "${expected_user}" \
           -group "${expected_group}" -links 1 -perm 0644 -print)" != "${temporary}" ]; then
        echo "[-] Refusing an unsafe staged local checksum file: ${temporary}" >&2
        rm -f -- "${temporary}"
        return 1
    fi
    if ! (
        cd "${PACKAGE_WORKSPACE}" || exit 1
        [ "$(wc -l < "$(basename -- "${temporary}")")" -eq "${#filenames[@]}" ] || exit 1
        for filename in "${filenames[@]}"; do
            [ "$(awk -v expected="${filename}" \
                '$2 == expected { count++ } END { print count + 0 }' \
                "$(basename -- "${temporary}")")" -eq 1 ] || exit 1
        done
        sha256sum --check --strict "$(basename -- "${temporary}")"
    ); then
        echo "[-] Private checksum manifest validation failed." >&2
        rm -f -- "${temporary}"
        return 1
    fi
    if ! mv -fT -- "${temporary}" "${manifest}" || \
       ! sync -f "${manifest}"; then
        rm -f -- "${temporary}" "${manifest}"
        return 1
    fi
    if ! publish_local_package "${manifest}"; then
        if ! rm -f -- "${destination}" || \
           ! sync -f "${LOCAL_PACKAGE_OUTPUT}"; then
            echo "[-] Unable to invalidate the failed local checksum publication." >&2
        fi
        return 1
    fi
    if ! (
        cd "${LOCAL_PACKAGE_OUTPUT}" || exit 1
        [ "$(wc -l < SHA256SUMS.txt)" -eq "${#filenames[@]}" ] || exit 1
        for filename in "${filenames[@]}"; do
            [ "$(awk -v expected="${filename}" \
                '$2 == expected { count++ } END { print count + 0 }' \
                SHA256SUMS.txt)" -eq 1 ] || exit 1
        done
        sha256sum --check --strict SHA256SUMS.txt
    ); then
        echo "[-] Local checksum publication verification failed: ${destination}" >&2
        if ! rm -f -- "${destination}" || \
           ! sync -f "${LOCAL_PACKAGE_OUTPUT}"; then
            echo "[-] Unable to invalidate the failed local checksum publication." >&2
        fi
        return 1
    fi
}

publish_local_artifacts() (
    local checksum_destination expected_group expected_user publication_lock_fd
    checksum_destination="${LOCAL_PACKAGE_OUTPUT}/SHA256SUMS.txt"
    if [ -L "${LOCAL_PACKAGE_OUTPUT}" ] || [ ! -d "${LOCAL_PACKAGE_OUTPUT}" ]; then
        echo "[-] Refusing an unsafe local package output directory." >&2
        return 1
    fi
    if ! exec {publication_lock_fd}<"${LOCAL_PACKAGE_OUTPUT}" || \
       ! flock --exclusive "${publication_lock_fd}"; then
        echo "[-] Unable to lock the local package output directory." >&2
        return 1
    fi
    if [ -L "${checksum_destination}" ] || \
       { [ -e "${checksum_destination}" ] && [ ! -f "${checksum_destination}" ]; }; then
        echo "[-] Refusing an unsafe local checksum destination: ${checksum_destination}" >&2
        return 1
    fi
    if ! rm -f -- "${checksum_destination}" || \
       ! sync -f "${LOCAL_PACKAGE_OUTPUT}"; then
        echo "[-] Unable to invalidate the previous local checksum manifest." >&2
        return 1
    fi

    expected_user="$(id -un)"
    expected_group="$(id -gn)"
    for artifact in \
        "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb" \
        "${PACKAGE_WORKSPACE}/${RPM_PACKAGE_FILENAME}" \
        "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_x86_64.apk"; do
        if [ ! -f "${artifact}" ] || [ -L "${artifact}" ] || \
           [ "$(find "${artifact}" -prune -user "${expected_user}" \
               -group "${expected_group}" -links 1 -print)" != "${artifact}" ]; then
            echo "[-] Expected package artifact is missing or unsafe: ${artifact}" >&2
            return 1
        fi
        chmod 0644 "${artifact}" || return 1
        publish_local_package "${artifact}" || return 1
    done
    publish_local_checksums || return 1
)

cd "${REPOSITORY_ROOT}"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/repository_state.py" \
    --repository "${REPOSITORY_ROOT}" verify \
    --snapshot "${PACKAGE_REPOSITORY_STATE}"
PACKAGE_STATE_VERIFIED=1

publish_local_artifacts

echo "[SUCCESS] Packages have been generated in ${LOCAL_PACKAGE_OUTPUT}."
ls -lh \
    "${LOCAL_PACKAGE_OUTPUT}/syswarden_${VERSION}_amd64.deb" \
    "${LOCAL_PACKAGE_OUTPUT}/${RPM_PACKAGE_FILENAME}" \
    "${LOCAL_PACKAGE_OUTPUT}/syswarden_${VERSION}_x86_64.apk"
