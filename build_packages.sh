#!/bin/bash
# SysWarden Local Builder & Packager for Beta Testers
# Supported OS: Debian/Ubuntu & RHEL/CentOS/AlmaLinux
# This script compiles the Native Go binaries and generates the .deb / .rpm packages locally.

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

for required_command in python3 git go fpm nfpm; do
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
mkdir -p "${GOCACHE}" "${GOTMPDIR}" "${GOMODCACHE}" "${PACKAGE_WORKSPACE}/dist/bin"
chmod 0700 "${GOCACHE}" "${GOTMPDIR}" "${GOMODCACHE}" "${PACKAGE_WORKSPACE}/dist" "${PACKAGE_WORKSPACE}/dist/bin"
SOURCE_DATE_EPOCH="$(git -C "${REPOSITORY_ROOT}" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
case "${SOURCE_DATE_EPOCH}" in
    ''|*[!0-9]*)
        echo "[-] Unable to derive a reproducible source timestamp." >&2
        exit 1
        ;;
esac

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
    staging/usr/local/bin

# Copy files
cp "${REPOSITORY_ROOT}/src/core/syswarden-core/signatures.json" staging/opt/syswarden/
cp dist/bin/syswarden-cli dist/bin/syswarden-core dist/bin/syswarden-tui staging/opt/syswarden/bin/
ln -s /opt/syswarden/bin/syswarden-cli staging/usr/local/bin/syswarden
ln -s /opt/syswarden/bin/syswarden-tui staging/usr/local/bin/syswarden-tui

# Permissions
chmod 750 staging/opt/syswarden/bin/*
chmod 640 staging/opt/syswarden/signatures.json
PYTHONDONTWRITEBYTECODE=1 python3 \
    "${REPOSITORY_ROOT}/scripts/ci/package_stage_gate.py" \
    linux --root staging

# Pre-Install / Pre-Upgrade script
cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > preinst.sh
cat << 'EOF' >> preinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
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
cat << 'EOF' >> postinst.sh
set -e
export SYSWARDEN_PKG_INSTALL=1
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

mkdir -p /etc/bash_completion.d
/opt/syswarden/bin/syswarden-cli completion bash > /etc/bash_completion.d/syswarden 2>/dev/null || true

if [ -f /etc/debian_version ] && [ -f /root/.bashrc ]; then
    if ! grep -qE "^[[:space:]]*\.[[:space:]]+/etc/bash_completion" /root/.bashrc; then
        echo "" >> /root/.bashrc
        echo "# SysWarden Auto-Completion Hook" >> /root/.bashrc
        echo "if [ -f /etc/bash_completion ] && ! shopt -oq posix; then" >> /root/.bashrc
        echo "    . /etc/bash_completion" >> /root/.bashrc
        echo "fi" >> /root/.bashrc
    fi
fi

if [ "$1" = "2" ] || [ "$1" = "1" ] || [ "$1" = "configure" ] || [ -f /etc/alpine-release ]; then
    manager="$(package_service_manager)"
    manager_state="$(syswarden_classify_service_manager / "${manager}")"
    [ "${manager_state}" != AMBIGUOUS ] || {
        echo "Refusing an ambiguous service-manager runtime" >&2
        exit 1
    }
    /opt/syswarden/bin/syswarden-cli install
    manager_state="$(syswarden_classify_service_manager / "${manager}")"
    case "${manager_state}" in
        ACTIVE)
            /opt/syswarden/bin/syswarden-cli reload
            ;;
        OFFLINE)
            /opt/syswarden/bin/syswarden-cli reload --no-restart
            ;;
        *)
            echo "Service-manager runtime changed during package installation" >&2
            exit 1
            ;;
    esac
fi
syswarden_verify_webtui_retirement /
EOF

cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > postrm.sh
cat << 'EOF' >> postrm.sh
export SYSWARDEN_PKG_INSTALL=1
syswarden_managed_cron_line() {
    syswarden_cron_candidate="$1"
    shift
    syswarden_cron_minute="$(printf '%s\n' "${syswarden_cron_candidate}" | awk 'NR == 1 { print $1; exit }')"
    for syswarden_cron_cli do
        if [ "${syswarden_cron_candidate}" = "*/30 * * * * ${syswarden_cron_cli} ha-sync >/dev/null 2>&1" ]; then
            return 0
        fi
        case "${syswarden_cron_minute}" in
            [1-9]|[1-5][0-9])
                if [ "${syswarden_cron_candidate}" = "${syswarden_cron_minute} * * * * ${syswarden_cron_cli} update-feeds >/dev/null 2>&1" ]; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}
syswarden_filter_crontab() {
    syswarden_cron_input="$1"
    syswarden_cron_output="$2"
    shift 2
    {
        while :; do
            syswarden_cron_candidate=
            if IFS= read -r syswarden_cron_candidate; then
                syswarden_cron_terminated=1
            else
                syswarden_cron_terminated=0
                [ -n "${syswarden_cron_candidate}" ] || break
            fi
            if ! syswarden_managed_cron_line "${syswarden_cron_candidate}" "$@"; then
                if [ "${syswarden_cron_terminated}" -eq 1 ]; then
                    printf '%s\n' "${syswarden_cron_candidate}" || return 1
                else
                    printf '%s' "${syswarden_cron_candidate}" || return 1
                fi
            fi
        done
    } < "${syswarden_cron_input}" > "${syswarden_cron_output}"
}
syswarden_read_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_present=0
    if LC_ALL=C crontab -l > "${syswarden_cron_backup}" 2> "${syswarden_cron_error}"; then
        syswarden_cron_present=1
        return 0
    else
        syswarden_cron_rc=$?
    fi
    [ "${syswarden_cron_rc}" -eq 1 ] || {
        printf 'crontab -l failed with exit %s\n' "${syswarden_cron_rc}" >&2
        return 1
    }
    [ ! -s "${syswarden_cron_backup}" ] || {
        printf '%s\n' 'crontab -l emitted partial stdout while reporting absence' >&2
        return 1
    }
    syswarden_cron_message="$(cat "${syswarden_cron_error}")"
    syswarden_cron_lines="$(LC_ALL=C awk 'END { print NR + 0 }' "${syswarden_cron_error}")"
    case "${syswarden_cron_lines}:${syswarden_cron_message}" in
        "1:no crontab for root"|\
        "1:crontab: no crontab for root"|\
        "1:crontab: can't open 'root': No such file or directory")
            if [ -n "${SYSWARDEN_CRON_ABSENCE_SPOOL:-}" ] && \
               { [ -e "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ] || [ -L "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ]; }; then
                printf '%s\n' 'crontab reported absence while the configured spool path still exists' >&2
                return 1
            fi
            : > "${syswarden_cron_backup}"
            return 0
            ;;
    esac
    printf '%s\n' "${syswarden_cron_message}" >&2
    return 1
}
syswarden_cleanup_cron_work() {
    [ -n "${cron_work:-}" ] || return 0
    syswarden_cron_cleanup_target="${cron_work}"
    if [ "${XDG_CACHE_HOME:-}" = "${syswarden_cron_cleanup_target}/cache" ]; then
        unset XDG_CACHE_HOME
    fi
    cron_cache=
    rm -rf -- "${syswarden_cron_cleanup_target}" || return 1
    if [ -e "${syswarden_cron_cleanup_target}" ] || [ -L "${syswarden_cron_cleanup_target}" ]; then
        printf '%s\n' 'private cron work directory remains after cleanup' >&2
        return 1
    fi
    cron_work=
}
syswarden_prepare_cron_work() {
    cron_work="$(mktemp -d /var/tmp/syswarden-cron.XXXXXX)" || return 1
    chmod 0700 "${cron_work}" || return 1
    cron_cache="${cron_work}/cache"
    mkdir "${cron_cache}" || return 1
    chmod 0700 "${cron_cache}" || return 1
    XDG_CACHE_HOME="${cron_cache}"
    export XDG_CACHE_HOME
    cron_backup="${cron_work}/backup"
    cron_error="${cron_work}/error"
    cron_filtered="${cron_work}/filtered"
}
syswarden_cleanup_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_filtered="$3"
    shift 3
    syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
    [ "${syswarden_cron_present}" -eq 1 ] || return 0
    syswarden_filter_crontab "${syswarden_cron_backup}" "${syswarden_cron_filtered}" "$@" || return 1
    if cmp -s "${syswarden_cron_backup}" "${syswarden_cron_filtered}"; then
        return 0
    else
        syswarden_cron_cmp_rc=$?
    fi
    [ "${syswarden_cron_cmp_rc}" -eq 1 ] || return 1
    if [ ! -s "${syswarden_cron_filtered}" ]; then
        LC_ALL=C crontab -r || return 1
        syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
        [ "${syswarden_cron_present}" -eq 0 ] || {
            printf '%s\n' 'crontab -r returned success but the root crontab is still present' >&2
            return 1
        }
        return 0
    fi
    crontab - < "${syswarden_cron_filtered}" || return 1
}

cleanup_generated_runtime_artifacts() {
    if [ -f /etc/alpine-release ]; then manager=openrc; else manager=systemd; fi
    manager_state="$(syswarden_classify_service_manager / "${manager}")"
    [ "${manager_state}" != AMBIGUOUS ] || return 1
    syswarden_remove_exact_product_services "${manager}" || return 1
    rm -f \
        /etc/bash_completion.d/syswarden \
        /etc/rsyslog.d/99-syswarden-siem.conf \
        /etc/rsyslog.d/99-syswarden-waf-bridge.conf
    if command -v crontab >/dev/null 2>&1; then
        umask 077
        SYSWARDEN_CRON_ABSENCE_SPOOL=
        cron_work=
        trap 'syswarden_cleanup_cron_work' 0
        trap 'syswarden_cleanup_cron_work; exit 129' 1
        trap 'syswarden_cleanup_cron_work; exit 130' 2
        trap 'syswarden_cleanup_cron_work; exit 143' 15
        syswarden_prepare_cron_work || return 1
        syswarden_cleanup_crontab \
            "${cron_backup}" "${cron_error}" "${cron_filtered}" \
            /opt/syswarden/bin/syswarden-cli || return 1
        syswarden_cleanup_cron_work || return 1
        trap - 0 1 2 15
    fi
    case "${manager_state}" in
        ACTIVE)
            if [ "${manager}" = systemd ]; then
                systemctl daemon-reload
                systemctl try-restart rsyslog.service
            else
                if rc-service rsyslog status >/dev/null 2>&1; then
                    rc-service rsyslog restart
                else
                    manager_status=$?
                    [ "${manager_status}" -eq 3 ] || return 1
                fi
            fi
            ;;
        OFFLINE) : ;;
        *) return 1 ;;
    esac
}

if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    cleanup_generated_runtime_artifacts || exit 1
    rm -f /usr/local/bin/syswarden
    rm -f /usr/local/bin/syswarden-tui
fi
if [ "$1" = "0" ] || [ "$1" = "purge" ]; then
    rm -rf /opt/syswarden
    rm -rf /etc/syswarden
fi
EOF

cat "${REPOSITORY_ROOT}/scripts/ci/package_webtui_retirement.sh" > prerm.sh
cat << 'EOF' >> prerm.sh
export SYSWARDEN_PKG_INSTALL=1
syswarden_retire_legacy_webtui / || exit 1
syswarden_managed_cron_line() {
    syswarden_cron_candidate="$1"
    shift
    syswarden_cron_minute="$(printf '%s\n' "${syswarden_cron_candidate}" | awk 'NR == 1 { print $1; exit }')"
    for syswarden_cron_cli do
        if [ "${syswarden_cron_candidate}" = "*/30 * * * * ${syswarden_cron_cli} ha-sync >/dev/null 2>&1" ]; then
            return 0
        fi
        case "${syswarden_cron_minute}" in
            [1-9]|[1-5][0-9])
                if [ "${syswarden_cron_candidate}" = "${syswarden_cron_minute} * * * * ${syswarden_cron_cli} update-feeds >/dev/null 2>&1" ]; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}
syswarden_filter_crontab() {
    syswarden_cron_input="$1"
    syswarden_cron_output="$2"
    shift 2
    {
        while :; do
            syswarden_cron_candidate=
            if IFS= read -r syswarden_cron_candidate; then
                syswarden_cron_terminated=1
            else
                syswarden_cron_terminated=0
                [ -n "${syswarden_cron_candidate}" ] || break
            fi
            if ! syswarden_managed_cron_line "${syswarden_cron_candidate}" "$@"; then
                if [ "${syswarden_cron_terminated}" -eq 1 ]; then
                    printf '%s\n' "${syswarden_cron_candidate}" || return 1
                else
                    printf '%s' "${syswarden_cron_candidate}" || return 1
                fi
            fi
        done
    } < "${syswarden_cron_input}" > "${syswarden_cron_output}"
}
syswarden_read_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_present=0
    if LC_ALL=C crontab -l > "${syswarden_cron_backup}" 2> "${syswarden_cron_error}"; then
        syswarden_cron_present=1
        return 0
    else
        syswarden_cron_rc=$?
    fi
    [ "${syswarden_cron_rc}" -eq 1 ] || {
        printf 'crontab -l failed with exit %s\n' "${syswarden_cron_rc}" >&2
        return 1
    }
    [ ! -s "${syswarden_cron_backup}" ] || {
        printf '%s\n' 'crontab -l emitted partial stdout while reporting absence' >&2
        return 1
    }
    syswarden_cron_message="$(cat "${syswarden_cron_error}")"
    syswarden_cron_lines="$(LC_ALL=C awk 'END { print NR + 0 }' "${syswarden_cron_error}")"
    case "${syswarden_cron_lines}:${syswarden_cron_message}" in
        "1:no crontab for root"|\
        "1:crontab: no crontab for root"|\
        "1:crontab: can't open 'root': No such file or directory")
            if [ -n "${SYSWARDEN_CRON_ABSENCE_SPOOL:-}" ] && \
               { [ -e "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ] || [ -L "${SYSWARDEN_CRON_ABSENCE_SPOOL}" ]; }; then
                printf '%s\n' 'crontab reported absence while the configured spool path still exists' >&2
                return 1
            fi
            : > "${syswarden_cron_backup}"
            return 0
            ;;
    esac
    printf '%s\n' "${syswarden_cron_message}" >&2
    return 1
}
syswarden_cleanup_cron_work() {
    [ -n "${cron_work:-}" ] || return 0
    syswarden_cron_cleanup_target="${cron_work}"
    if [ "${XDG_CACHE_HOME:-}" = "${syswarden_cron_cleanup_target}/cache" ]; then
        unset XDG_CACHE_HOME
    fi
    cron_cache=
    rm -rf -- "${syswarden_cron_cleanup_target}" || return 1
    if [ -e "${syswarden_cron_cleanup_target}" ] || [ -L "${syswarden_cron_cleanup_target}" ]; then
        printf '%s\n' 'private cron work directory remains after cleanup' >&2
        return 1
    fi
    cron_work=
}
syswarden_prepare_cron_work() {
    cron_work="$(mktemp -d /var/tmp/syswarden-cron.XXXXXX)" || return 1
    chmod 0700 "${cron_work}" || return 1
    cron_cache="${cron_work}/cache"
    mkdir "${cron_cache}" || return 1
    chmod 0700 "${cron_cache}" || return 1
    XDG_CACHE_HOME="${cron_cache}"
    export XDG_CACHE_HOME
    cron_backup="${cron_work}/backup"
    cron_error="${cron_work}/error"
    cron_filtered="${cron_work}/filtered"
}
syswarden_cleanup_crontab() {
    syswarden_cron_backup="$1"
    syswarden_cron_error="$2"
    syswarden_cron_filtered="$3"
    shift 3
    syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
    [ "${syswarden_cron_present}" -eq 1 ] || return 0
    syswarden_filter_crontab "${syswarden_cron_backup}" "${syswarden_cron_filtered}" "$@" || return 1
    if cmp -s "${syswarden_cron_backup}" "${syswarden_cron_filtered}"; then
        return 0
    else
        syswarden_cron_cmp_rc=$?
    fi
    [ "${syswarden_cron_cmp_rc}" -eq 1 ] || return 1
    if [ ! -s "${syswarden_cron_filtered}" ]; then
        LC_ALL=C crontab -r || return 1
        syswarden_read_crontab "${syswarden_cron_backup}" "${syswarden_cron_error}" || return 1
        [ "${syswarden_cron_present}" -eq 0 ] || {
            printf '%s\n' 'crontab -r returned success but the root crontab is still present' >&2
            return 1
        }
        return 0
    fi
    crontab - < "${syswarden_cron_filtered}" || return 1
}

# RPM Uninstall ($1 = 0) or DEB Uninstall/Purge
if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if [ -f /etc/alpine-release ]; then manager=openrc; else manager=systemd; fi
    manager_state="$(syswarden_classify_service_manager / "${manager}")"
    case "${manager_state}" in
        ACTIVE)
            if [ "${manager}" = systemd ]; then
                systemctl stop syswarden-core.service
                systemctl disable syswarden-core.service
                systemctl stop syswarden-firewall.service
                systemctl disable syswarden-firewall.service
                systemctl restart rsyslog
            else
                rc-service syswarden-core stop
                rc-update del syswarden-core default
                rc-service syswarden-firewall stop
                rc-update del syswarden-firewall default
                rc-service rsyslog restart
            fi
            ;;
        OFFLINE) : ;;
        *) exit 1 ;;
    esac
    syswarden_remove_exact_product_services "${manager}" || exit 1
    nft delete table netdev syswarden_hw_drop || true
    nft delete table arp syswarden_arp || true
    nft delete table inet syswarden || true
    umask 077
    SYSWARDEN_CRON_ABSENCE_SPOOL=
    cron_work=
    trap 'syswarden_cleanup_cron_work' 0
    trap 'syswarden_cleanup_cron_work; exit 129' 1
    trap 'syswarden_cleanup_cron_work; exit 130' 2
    trap 'syswarden_cleanup_cron_work; exit 143' 15
    syswarden_prepare_cron_work || {
        echo "Unable to create the private cron backup" >&2
        exit 1
    }
    syswarden_cleanup_crontab \
        "${cron_backup}" "${cron_error}" "${cron_filtered}" \
        /opt/syswarden/bin/syswarden-cli || exit 1
    syswarden_cleanup_cron_work || exit 1
    trap - 0 1 2 15
    rm -f /etc/rsyslog.d/99-syswarden-siem.conf || true
    rm -f /etc/rsyslog.d/99-syswarden-waf-bridge.conf || true
fi
EOF

chmod +x preinst.sh postinst.sh postrm.sh prerm.sh

# 4. Generate Packages
echo "[*] Generating .deb and .rpm packages via FPM..."

# Generate DEB
fpm -f -s dir -t deb \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for Linux" \
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "cron" -d "bash-completion" \
    -d "wireguard-tools" -d "qrencode" -d "jq" -d "unattended-upgrades" -d "apt-listchanges" -d "procps" -d "e2fsprogs" \
    --before-install preinst.sh \
    --after-install postinst.sh \
    --before-remove prerm.sh \
    --after-remove postrm.sh \
    -p "${PACKAGE_WORKSPACE}/syswarden_${VERSION}_amd64.deb" \
    -C staging .

# Generate RPM
fpm -f -s dir -t rpm \
    -n syswarden \
    -v "${VERSION}" \
    --vendor "SysWarden Security" \
    --maintainer "SysWarden Engineering" \
    --description "SysWarden Host-based Security Orchestrator for Linux" \
    -d "nftables" -d "ipset" -d "curl" -d "wget" -d "rsyslog" -d "cronie" -d "bash-completion" \
    -d "wireguard-tools" -d "qrencode" -d "jq" -d "checkpolicy" -d "policycoreutils-python-utils" \
    -d "dnf-automatic" -d "procps-ng" -d "e2fsprogs" \
    --before-install preinst.sh \
    --after-install postinst.sh \
    --before-remove prerm.sh \
    --after-remove postrm.sh \
    -p "${PACKAGE_WORKSPACE}/syswarden-${VERSION}-1.x86_64.rpm" \
    -C staging .

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
contents:
  - src: "./staging/opt"
    dst: "/opt"
  - src: "./staging/usr"
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
