#!/bin/bash
# SysWarden Local Builder & Packager for Beta Testers
# Supported OS: Debian/Ubuntu & RHEL/CentOS/AlmaLinux
# This script compiles the Native Go binaries and generates .deb, .rpm, and .apk packages locally.

set -euo pipefail
umask 077
echo "[*] Initializing SysWarden Local Package Builder..."

REPOSITORY_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
cd "${REPOSITORY_ROOT}"
PACKAGE_WORKSPACE="$(mktemp -d /tmp/syswarden-local-package.XXXXXX)"
chmod 0700 "${PACKAGE_WORKSPACE}"
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

for required_command in python3 git go fpm nfpm readelf file ar rpm tar touch date sed; do
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

GO_TOOLCHAIN_ROOT="$(GOTOOLCHAIN=go1.26.6 GOPROXY=off go env GOROOT)" || {
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
export GOCACHE="${PACKAGE_WORKSPACE}/go-build-cache"
export GOTMPDIR="${PACKAGE_WORKSPACE}/go-tmp"
export GOMODCACHE="${PACKAGE_WORKSPACE}/go-module-cache"
mkdir -p \
    "${GOCACHE}" \
    "${GOTMPDIR}" \
    "${GOMODCACHE}" \
    "${PACKAGE_WORKSPACE}/dist/bin" \
    "${PACKAGE_WORKSPACE}/dist/bin-apk"
chmod 0700 \
    "${GOCACHE}" \
    "${GOTMPDIR}" \
    "${GOMODCACHE}" \
    "${PACKAGE_WORKSPACE}/dist" \
    "${PACKAGE_WORKSPACE}/dist/bin" \
    "${PACKAGE_WORKSPACE}/dist/bin-apk"
SOURCE_DATE_EPOCH="$(git -C "${REPOSITORY_ROOT}" log -1 --format=%ct HEAD)"
case "${SOURCE_DATE_EPOCH}" in
    ''|0|*[!0-9]*)
        echo "[-] Unable to derive a reproducible source timestamp." >&2
        exit 1
        ;;
esac
export SOURCE_DATE_EPOCH
export LC_ALL=C
export LANG=C
export TZ=UTC

# Extract the version through the repository-wide version contract.
SOURCE_TAG="$(PATH="${GO_TOOLCHAIN_ROOT}/bin:${PATH}" \
    "${REPOSITORY_ROOT}/scripts/versioning.sh" inspect --repo "${REPOSITORY_ROOT}")"
case "${SOURCE_TAG}" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "[-] The source version contract did not return a release tag." >&2
        exit 1
        ;;
esac
VERSION="${SOURCE_TAG#v}"
echo "[+] Detected SysWarden Version: v${VERSION}"

# 2. Compile Go Binaries
echo "[*] Compiling SysWarden Native Go Modules..."
for module in syswarden-cli syswarden-core syswarden-tui; do
    echo " -> Downloading locked ${module} modules..."
    "${GO_BIN}" -C "${REPOSITORY_ROOT}/src/core/${module}" mod download
    echo " -> Compiling ${module}..."
    "${GO_BIN}" -C "${REPOSITORY_ROOT}/src/core/${module}" build \
        -mod=readonly -buildmode=pie -ldflags="-s -w" \
        -o "${PACKAGE_WORKSPACE}/dist/bin/${module}" .
    echo " -> Compiling static Alpine ${module}..."
    "${GO_BIN}" -C "${REPOSITORY_ROOT}/src/core/${module}" build \
        -mod=readonly -ldflags="-s -w" \
        -o "${PACKAGE_WORKSPACE}/dist/bin-apk/${module}" .
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
cp "${REPOSITORY_ROOT}/src/core/syswarden-core/signatures.json" staging/opt/syswarden/
cp dist/bin/syswarden-cli dist/bin/syswarden-core dist/bin/syswarden-tui staging/opt/syswarden/bin/
ln -s /opt/syswarden/bin/syswarden-cli staging/usr/local/bin/syswarden
ln -s /opt/syswarden/bin/syswarden-tui staging/usr/local/bin/syswarden-tui
staging/opt/syswarden/bin/syswarden-cli completion bash > \
    staging/usr/share/bash-completion/completions/syswarden
install -m 0644 \
    "${REPOSITORY_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    staging/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt
cp "${REPOSITORY_ROOT}/src/core/syswarden-core/signatures.json" staging-apk/opt/syswarden/
cp dist/bin-apk/syswarden-cli dist/bin-apk/syswarden-core dist/bin-apk/syswarden-tui staging-apk/opt/syswarden/bin/
ln -s /opt/syswarden/bin/syswarden-cli staging-apk/usr/local/bin/syswarden
ln -s /opt/syswarden/bin/syswarden-tui staging-apk/usr/local/bin/syswarden-tui
staging-apk/opt/syswarden/bin/syswarden-cli completion bash > \
    staging-apk/usr/share/bash-completion/completions/syswarden
install -m 0644 \
    "${REPOSITORY_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt" \
    staging-apk/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt

# Permissions
chmod 750 staging/opt/syswarden/bin/*
chmod 640 staging/opt/syswarden/signatures.json
chmod 644 staging/usr/share/bash-completion/completions/syswarden
chmod 750 staging-apk/opt/syswarden/bin/*
chmod 640 staging-apk/opt/syswarden/signatures.json
chmod 644 staging-apk/usr/share/bash-completion/completions/syswarden
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/package_stage_gate.py" \
    linux --root staging \
    --completion-contract "${REPOSITORY_ROOT}/scripts/ci/package_completion_contract.json" \
    --geoip-data-license-contract \
    "${REPOSITORY_ROOT}/scripts/ci/package_geoip_data_license_contract.json" \
    --geoip-data-license-source \
    "${REPOSITORY_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/package_stage_gate.py" \
    linux --root staging-apk \
    --completion-contract "${REPOSITORY_ROOT}/scripts/ci/package_completion_contract.json" \
    --geoip-data-license-contract \
    "${REPOSITORY_ROOT}/scripts/ci/package_geoip_data_license_contract.json" \
    --geoip-data-license-source \
    "${REPOSITORY_ROOT}/src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt"

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
prepare_rpm_build_id_links \
    staging-rpm \
    staging-rpm/opt/syswarden/bin/syswarden-cli \
    staging-rpm/opt/syswarden/bin/syswarden-core \
    staging-rpm/opt/syswarden/bin/syswarden-tui

# Pre-Install / Pre-Upgrade script
cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > preinst.sh
cat "${REPOSITORY_ROOT}/scripts/ci/package_deferred_purge_postinstall.sh" >> preinst.sh
cat "${REPOSITORY_ROOT}/scripts/ci/package_alpine_cronie_preflight.sh" >> preinst.sh
cat << 'EOF' >> preinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
syswarden_preflight_alpine_cronie
syswarden_preflight_install_barriers
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
cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > postinst.sh
cat "${REPOSITORY_ROOT}/scripts/ci/package_deferred_purge_postinstall.sh" >> postinst.sh
cat "${REPOSITORY_ROOT}/scripts/ci/package_alpine_cronie_preflight.sh" >> postinst.sh
cat << 'EOF' >> postinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
syswarden_preflight_alpine_cronie
syswarden_preflight_install_barriers
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

cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > postrm.sh
cat "${REPOSITORY_ROOT}/scripts/ci/package_removal_state.sh" >> postrm.sh
cat << 'EOF' >> postrm.sh
export SYSWARDEN_PKG_INSTALL=1

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
EOF

cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > prerm.sh
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
for script_name in preinst.sh postinst.sh prerm.sh postrm.sh; do
    prepare_rpm_scriptlet \
        "${PACKAGE_WORKSPACE}/${script_name}" \
        "${RPM_SCRIPTS}/${script_name}"
done

prepare_rpm_changelog() {
    local destination="$1"
    local changelog_date
    local changelog_day
    changelog_day="$(date --utc --date="@${SOURCE_DATE_EPOCH}" '+%Y-%m-%d')" || return 1
    changelog_date="$(date --utc --date="@${SOURCE_DATE_EPOCH}" '+%a %b %e %Y')" || return 1
    RPM_CHANGELOG_EPOCH="$(date --utc --date="${changelog_day} 12:00:00" '+%s')" || return 1
    case "${RPM_CHANGELOG_EPOCH}" in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    printf '* %s SysWarden Engineering - %s-1\n- Package created with FPM\n' \
        "${changelog_date}" "${VERSION}" > "${destination}"
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
prepare_rpm_changelog "${RPM_CHANGELOG}"
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
        --vendor "SysWarden Security" \
        --maintainer "SysWarden Engineering" \
        --description "SysWarden Host-based Security Orchestrator for Linux" \
        --source-date-epoch-default "${SOURCE_DATE_EPOCH}" \
        --rpm-changelog "${RPM_CHANGELOG}" \
        -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "cronie" -d "bash-completion" \
        -d "wireguard-tools" -d "jq" -d "checkpolicy" -d "policycoreutils-python-utils" \
        -d "dnf-automatic" -d "procps-ng" -d "e2fsprogs" \
        --before-install "${RPM_SCRIPTS}/preinst.sh" \
        --after-install "${RPM_SCRIPTS}/postinst.sh" \
        --before-remove "${RPM_SCRIPTS}/prerm.sh" \
        --after-remove "${RPM_SCRIPTS}/postrm.sh" \
        --rpm-rpmbuild-define "_build_id_links none" \
        --rpm-rpmbuild-define "use_source_date_epoch_as_buildtime 1" \
        --rpm-rpmbuild-define "clamp_mtime_to_source_date_epoch 1" \
        --rpm-rpmbuild-define "_buildhost syswarden-build.invalid" \
        --directories /usr/lib/.build-id \
        -p "${PACKAGE_WORKSPACE}/syswarden-${VERSION}-1.x86_64.rpm" \
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
    validate_local_rpm_scriptlet "${rpm_path}" PREIN preinst.sh || return 1
    validate_local_rpm_scriptlet "${rpm_path}" POSTIN postinst.sh || return 1
    validate_local_rpm_scriptlet "${rpm_path}" PREUN prerm.sh || return 1
    validate_local_rpm_scriptlet "${rpm_path}" POSTUN postrm.sh || return 1
    rpm_inventory="$(
        rpm -qp --qf \
            '[%{FILENAMES}\t%{FILEMODES:perms}\t%{FILEUSERNAME}:%{FILEGROUPNAME}\t%{FILELINKTOS}\n]' \
            "${rpm_path}"
    )" || return 1
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
if ! validate_local_rpm_build_ids \
    "${PACKAGE_WORKSPACE}/syswarden-${VERSION}-1.x86_64.rpm"; then
    echo "[-] Local RPM build-id validation failed." >&2
    rpm -qp --qf \
        '[%{FILENAMES}\t%{FILEMODES:perms}\t%{FILEUSERNAME}:%{FILEGROUPNAME}\t%{FILELINKTOS}\n]' \
        "${PACKAGE_WORKSPACE}/syswarden-${VERSION}-1.x86_64.rpm" >&2 || true
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
    mv -f -- "${temporary}" "${destination}"
    sync -f "${LOCAL_PACKAGE_OUTPUT}"
    if [ -L "${destination}" ] || [ ! -f "${destination}" ] || \
       [ "$(find "${destination}" -prune -user "${expected_user}" \
           -group "${expected_group}" -links 1 -perm 0644 -print)" != "${destination}" ] || \
       ! cmp -s -- "${source_path}" "${destination}"; then
        echo "[-] Local package publication verification failed: ${destination}" >&2
        return 1
    fi
}

for artifact in \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb" \
    "${PACKAGE_WORKSPACE}/syswarden-${VERSION}-1.x86_64.rpm" \
    "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_x86_64.apk"; do
    if [ ! -f "${artifact}" ] || [ -L "${artifact}" ]; then
        echo "[-] Expected package artifact is missing or unsafe: ${artifact}" >&2
        exit 1
    fi
    chmod 0644 "${artifact}"
    publish_local_package "${artifact}"
done

cd "${REPOSITORY_ROOT}"
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/repository_state.py" \
    --repository "${REPOSITORY_ROOT}" verify \
    --snapshot "${PACKAGE_REPOSITORY_STATE}"
PACKAGE_STATE_VERIFIED=1

echo "[SUCCESS] Packages have been generated in ${LOCAL_PACKAGE_OUTPUT}."
ls -lh \
    "${LOCAL_PACKAGE_OUTPUT}/syswarden_${VERSION}_amd64.deb" \
    "${LOCAL_PACKAGE_OUTPUT}/syswarden-${VERSION}-1.x86_64.rpm" \
    "${LOCAL_PACKAGE_OUTPUT}/syswarden_${VERSION}_x86_64.apk"
