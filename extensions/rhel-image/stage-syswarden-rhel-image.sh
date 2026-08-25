#!/bin/bash
# Stage a fresh SysWarden RPM into an offline RHEL-family 9+ image root.

set -Eeuo pipefail
umask 077
export LC_ALL=C

PROGRAM_NAME="${0##*/}"
IMAGE_ROOT=""
RPM_SOURCE=""
EXPECTED_SHA256=""
STAGING_DIRECTORY=""
STAGING_RPM=""
TRANSACTION_JOURNAL_PATH=""
TRANSACTION_JOURNAL_CONTENT=""
RECOVERY_MODE=0
PACKAGE_PRESENT=0
RHEL_FAMILY_MAJOR=""
TARGET_RPM_DBPATH=""
PREFLIGHT_ROOT_ONLY=0
ROOT_IDENTITY_READY=0
declare -a IMAGE_ROOT_ANCESTOR_PATHS=()
declare -a IMAGE_ROOT_ANCESTOR_IDENTITIES=()
declare -a RPM_SOURCE_ANCESTOR_PATHS=()
declare -a RPM_SOURCE_ANCESTOR_IDENTITIES=()

usage() {
    printf '%s\n' \
        'Usage:' \
        '  stage-syswarden-rhel-image.sh --preflight-root --root /absolute/offline/installroot' \
        '' \
        "  stage-syswarden-rhel-image.sh \\" \
        "    --root /absolute/offline/installroot \\" \
        "    --rpm /absolute/local/syswarden.rpm \\" \
        '    --sha256 64_HEX_DIGEST' \
        '' \
        'This optional extension accepts only a fresh, unmounted RHEL-family 9+' \
        'filesystem tree. It never handles an upgrade and never runs package scripts or' \
        'SysWarden code while staging the image. The root-only preflight is read-only and' \
        'does not require an RPM or installed image dependencies. It does require an' \
        'extracted RHEL-family 9+ root shape with exact os-release metadata.'
}

fail() {
    printf '%s: %s\n' "${PROGRAM_NAME}" "$*" >&2
    exit 1
}

cleanup_staging_directory() {
    local status=$?
    trap - EXIT HUP INT TERM

    # Once the root identity has been captured, cleanup is allowed only through
    # that same protected ancestor chain. A renamed parent or root therefore
    # leaves a recoverable in-image snapshot instead of redirecting cleanup.
    if ((ROOT_IDENTITY_READY == 1 && ${#IMAGE_ROOT_ANCESTOR_PATHS[@]} > 0)); then
        assert_root_identity
        assert_offline_unmounted_root
    fi

    if [[ -n "${STAGING_RPM}" && -e "${STAGING_RPM}" ]]; then
        case "${STAGING_RPM}" in
            "${IMAGE_ROOT}"/.syswarden-image-stage.*/package.*.rpm)
                assert_root_identity
                rm -f -- "${STAGING_RPM}" || status=1
                ;;
            *)
                printf '%s: refusing unexpected temporary RPM cleanup: %s\n' \
                    "${PROGRAM_NAME}" "${STAGING_RPM}" >&2
                status=1
                ;;
        esac
    fi
    if [[ -n "${STAGING_DIRECTORY}" && -d "${STAGING_DIRECTORY}" ]]; then
        case "${STAGING_DIRECTORY}" in
            "${IMAGE_ROOT}"/.syswarden-image-stage.*)
                assert_root_identity
                rmdir -- "${STAGING_DIRECTORY}" 2>/dev/null || {
                    printf '%s: temporary staging directory is not empty: %s\n' \
                        "${PROGRAM_NAME}" "${STAGING_DIRECTORY}" >&2
                    status=1
                }
                ;;
            *)
                printf '%s: refusing unexpected temporary directory cleanup: %s\n' \
                    "${PROGRAM_NAME}" "${STAGING_DIRECTORY}" >&2
                status=1
                ;;
        esac
    fi
    exit "${status}"
}

trap cleanup_staging_directory EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_option_value() {
    local option=$1
    local value=${2-}
    [[ -n "${value}" && "${value}" != --* ]] || fail "${option} requires a value"
}

while (($# > 0)); do
    case "$1" in
        --root)
            require_option_value "$1" "${2-}"
            [[ -z "${IMAGE_ROOT}" ]] || fail "--root may be specified only once"
            IMAGE_ROOT=$2
            shift 2
            ;;
        --rpm)
            require_option_value "$1" "${2-}"
            [[ -z "${RPM_SOURCE}" ]] || fail "--rpm may be specified only once"
            RPM_SOURCE=$2
            shift 2
            ;;
        --sha256)
            require_option_value "$1" "${2-}"
            [[ -z "${EXPECTED_SHA256}" ]] || fail "--sha256 may be specified only once"
            EXPECTED_SHA256=$2
            shift 2
            ;;
        --preflight-root)
            ((PREFLIGHT_ROOT_ONLY == 0)) || fail "--preflight-root may be specified only once"
            PREFLIGHT_ROOT_ONLY=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --*)
            fail "unknown option: $1"
            ;;
        *)
            fail "unexpected positional argument: $1"
            ;;
    esac
done

[[ -n "${IMAGE_ROOT}" ]] || fail "--root is required"
if ((PREFLIGHT_ROOT_ONLY == 1)); then
    [[ -z "${RPM_SOURCE}" && -z "${EXPECTED_SHA256}" ]] || \
        fail "--preflight-root is mutually exclusive with --rpm and --sha256"
else
    [[ -n "${RPM_SOURCE}" ]] || fail "--rpm is required"
    [[ -n "${EXPECTED_SHA256}" ]] || fail "--sha256 is required"
fi
if ((EUID != 0)) || [[ "${GROUPS[0]}" != 0 ]]; then
    fail "image staging must run as root with primary group root"
fi

TOOL_DIRECTORY=/usr/bin
RPM_RCFILE=/usr/lib/rpm/rpmrc
RPM_MACROS_FILE=/usr/lib/rpm/macros
TEST_TOOL_OVERRIDE=0
if [[ -n "${SYSWARDEN_IMAGE_TEST_TOOL_DIR:-}" ]]; then
    [[ "$(/usr/bin/readlink /proc/self/ns/user)" != "$(/usr/bin/readlink /proc/1/ns/user)" ]] || \
        fail "test tool override is allowed only inside a separate user namespace"
    TOOL_DIRECTORY="$(/usr/bin/realpath -e -- "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}")" || \
        fail "test tool directory does not exist"
    [[ "${TOOL_DIRECTORY}" == "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}" ]] || \
        fail "test tool directory must be canonical"
    RPM_RCFILE="${TOOL_DIRECTORY}/rpmrc"
    RPM_MACROS_FILE="${TOOL_DIRECTORY}/rpm-macros"
    TEST_TOOL_OVERRIDE=1
fi

unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH \
    PERL5LIB RUBYLIB RPM_CONFIGDIR RPM_ETCCONFIGDIR RPMRC RPM_MACROS RPM_DBPATH RPM_ROOT RPM_TARGET
PATH="${TOOL_DIRECTORY}"
export PATH

bootstrap_attest_path() {
    local label=$1
    local path=$2
    local expected_kind=$3
    local kind uid gid mode numeric_mode

    [[ ! -L "${path}" ]] || fail "${label} may not be a symlink: ${path}"
    IFS='|' read -r kind uid gid mode < <(/usr/bin/stat -c '%F|%u|%g|%a' -- "${path}") || \
        fail "cannot inspect ${label}: ${path}"
    [[ "${kind}" == "${expected_kind}" ]] || fail "${label} has an unexpected type: ${path}"
    [[ "${uid}" == 0 && "${gid}" == 0 ]] || fail "${label} is not root owned: ${path}"
    [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail "${label} mode is invalid: ${path}"
    numeric_mode=$((8#${mode}))
    (( (numeric_mode & 0022) == 0 )) || fail "${label} is group/world writable: ${path}"
}

if ((TEST_TOOL_OVERRIDE == 0)); then
    bootstrap_attest_path "tool parent directory" / directory
    bootstrap_attest_path "tool parent directory" /usr directory
    bootstrap_attest_path "tool directory" /usr/bin directory
    if ((PREFLIGHT_ROOT_ONLY == 0)); then
        bootstrap_attest_path "RPM configuration parent" /usr/lib directory
        bootstrap_attest_path "RPM configuration parent" /usr/lib/rpm directory
    fi
else
    bootstrap_attest_path "test tool directory" "${TOOL_DIRECTORY}" directory
fi
if ((PREFLIGHT_ROOT_ONLY == 0)); then
    bootstrap_attest_path "RPM configuration" "${RPM_RCFILE}" "regular file"
    bootstrap_attest_path "RPM macro configuration" "${RPM_MACROS_FILE}" "regular file"
    REQUIRED_TOOLS=(
        realpath stat sha256sum findmnt rpm find grep cp mktemp mkdir chmod ln readlink rm rmdir
    )
else
    REQUIRED_TOOLS=(realpath stat findmnt readlink)
fi
for required_tool in "${REQUIRED_TOOLS[@]}"; do
    tool_path="$(command -v "${required_tool}")" || fail "required tool is unavailable: ${required_tool}"
    [[ "${tool_path}" == "${TOOL_DIRECTORY}/${required_tool}" ]] || \
        fail "required tool resolved outside the trusted directory: ${required_tool}"
    bootstrap_attest_path "required tool" "${tool_path}" "regular file"
    [[ -x "${tool_path}" ]] || fail "required tool is not executable: ${tool_path}"
done

RPM_COMMAND=()
if ((PREFLIGHT_ROOT_ONLY == 0)); then
    RPM_COMMAND=(rpm --noplugins --rcfile "${RPM_RCFILE}" --macros "${RPM_MACROS_FILE}")

    # This also proves that the local RPM implementation accepts the option before
    # any image write occurs. RPM implementations without plugin isolation fail
    # closed instead of silently ignoring the requested boundary.
    "${RPM_COMMAND[@]}" --version >/dev/null 2>&1 || \
        fail "the local rpm tool does not support required --noplugins isolation"
fi

validate_argument_path_text() {
    local label=$1
    local path=$2
    [[ "${path}" == /* ]] || fail "${label} must be an absolute path"
    case "${path}" in
        *[[:space:]]*) fail "${label} may not contain whitespace" ;;
    esac
}

assert_no_symlink_components() {
    local label=$1
    local path=$2
    local current=""
    local component
    local -a components=()

    IFS='/' read -r -a components <<< "${path#/}"
    for component in "${components[@]}"; do
        [[ -n "${component}" ]] || continue
        current="${current}/${component}"
        [[ ! -L "${current}" ]] || fail "${label} contains a symlink component: ${current}"
    done
}

canonical_existing_path() {
    local label=$1
    local path=$2
    local canonical

    validate_argument_path_text "${label}" "${path}"
    assert_no_symlink_components "${label}" "${path}"
    canonical="$(realpath -e -- "${path}")" || fail "${label} does not exist: ${path}"
    [[ "${path}" == "${canonical}" ]] || \
        fail "${label} must be an exact canonical path: ${path}"
    printf '%s\n' "${canonical}"
}

path_identity() {
    stat -c '%d:%i:%u:%g:%a:%F' -- "$1"
}

inspect_protected_ancestor() {
    local label=$1
    local path=$2
    local kind uid gid mode device inode numeric_mode

    [[ ! -L "${path}" ]] || fail "${label} may not be a symlink: ${path}"
    IFS='|' read -r kind uid gid mode device inode < <(
        stat -c '%F|%u|%g|%a|%d|%i' -- "${path}"
    ) || fail "cannot inspect ${label}: ${path}"
    [[ "${kind}" == directory ]] || fail "${label} is not a directory: ${path}"
    [[ "${uid}" == 0 && "${gid}" == 0 ]] || fail "${label} is not root owned: ${path}"
    [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail "${label} has an unreadable mode: ${path}"
    [[ "${device}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ ]] || \
        fail "${label} has an unreadable identity: ${path}"
    numeric_mode=$((8#${mode}))
    (( (numeric_mode & 0022) == 0 )) || fail "${label} is group/world writable: ${path}"
    printf '%s:%s\n' "${device}" "${inode}"
}

capture_protected_ancestor_chain() {
    local label=$1
    local path=$2
    local chain_kind=$3
    local current=/ component identity
    local -a components=() captured_paths=() captured_identities=()

    IFS='/' read -r -a components <<< "${path#/}"
    ((${#components[@]} <= 128)) || fail "${label} has too many ancestor components"

    identity="$(inspect_protected_ancestor "${label} ancestor" /)" || \
        fail "cannot capture ${label} ancestor identity: /"
    captured_paths+=(/)
    captured_identities+=("${identity}")
    for component in "${components[@]}"; do
        [[ -n "${component}" && "${component}" != . && "${component}" != .. ]] || \
            fail "${label} contains an unsafe ancestor component"
        if [[ "${current}" == / ]]; then
            current="/${component}"
        else
            current="${current}/${component}"
        fi
        identity="$(inspect_protected_ancestor "${label} ancestor" "${current}")" || \
            fail "cannot capture ${label} ancestor identity: ${current}"
        captured_paths+=("${current}")
        captured_identities+=("${identity}")
    done
    case "${chain_kind}" in
        image_root)
            IMAGE_ROOT_ANCESTOR_PATHS=("${captured_paths[@]}")
            IMAGE_ROOT_ANCESTOR_IDENTITIES=("${captured_identities[@]}")
            ;;
        rpm_source)
            RPM_SOURCE_ANCESTOR_PATHS=("${captured_paths[@]}")
            RPM_SOURCE_ANCESTOR_IDENTITIES=("${captured_identities[@]}")
            ;;
        *) fail "unknown protected ancestor chain: ${chain_kind}" ;;
    esac
}

reattest_protected_ancestor_chain() {
    local label=$1
    local chain_kind=$2
    local index identity
    local -a paths_ref=() identities_ref=()

    case "${chain_kind}" in
        image_root)
            paths_ref=("${IMAGE_ROOT_ANCESTOR_PATHS[@]}")
            identities_ref=("${IMAGE_ROOT_ANCESTOR_IDENTITIES[@]}")
            ;;
        rpm_source)
            paths_ref=("${RPM_SOURCE_ANCESTOR_PATHS[@]}")
            identities_ref=("${RPM_SOURCE_ANCESTOR_IDENTITIES[@]}")
            ;;
        *) fail "unknown protected ancestor chain: ${chain_kind}" ;;
    esac

    ((${#paths_ref[@]} > 0 && ${#paths_ref[@]} == ${#identities_ref[@]})) || \
        fail "${label} ancestor identity snapshot is unavailable"
    for index in "${!paths_ref[@]}"; do
        identity="$(inspect_protected_ancestor "${label} ancestor" "${paths_ref[index]}")" || \
            fail "cannot re-attest ${label} ancestor: ${paths_ref[index]}"
        [[ "${identity}" == "${identities_ref[index]}" ]] || \
            fail "${label} ancestor identity changed during staging: ${paths_ref[index]}"
    done
}

assert_secure_owned_directory() {
    local label=$1
    local path=$2
    local kind uid gid mode numeric_mode

    [[ ! -L "${path}" ]] || fail "${label} may not be a symlink: ${path}"
    IFS='|' read -r kind uid gid mode < <(stat -c '%F|%u|%g|%a' -- "${path}") || \
        fail "cannot inspect ${label}: ${path}"
    [[ "${kind}" == directory ]] || fail "${label} is not a directory: ${path}"
    [[ "${uid}" == 0 && "${gid}" == 0 ]] || \
        fail "${label} is not root owned: ${path}"
    [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail "${label} has an unreadable mode: ${path}"
    numeric_mode=$((8#${mode}))
    (( (numeric_mode & 0022) == 0 )) || fail "${label} is group/world writable: ${path}"
    (( (numeric_mode & 0700) == 0700 )) || fail "${label} is not owner controlled: ${path}"
}

assert_secure_owned_regular_file() {
    local label=$1
    local path=$2
    local required_mode=${3-}
    local kind uid gid mode numeric_mode

    [[ ! -L "${path}" ]] || fail "${label} may not be a symlink: ${path}"
    IFS='|' read -r kind uid gid mode < <(stat -c '%F|%u|%g|%a' -- "${path}") || \
        fail "cannot inspect ${label}: ${path}"
    [[ "${kind}" == "regular file" ]] || fail "${label} is not a regular file: ${path}"
    [[ "${uid}" == 0 && "${gid}" == 0 ]] || \
        fail "${label} is not root owned: ${path}"
    [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail "${label} has an unreadable mode: ${path}"
    numeric_mode=$((8#${mode}))
    (( (numeric_mode & 0022) == 0 )) || fail "${label} is group/world writable: ${path}"
    (( (numeric_mode & 0400) == 0400 )) || fail "${label} is not owner readable: ${path}"
    if [[ -n "${required_mode}" ]]; then
        [[ "${mode}" == "${required_mode}" ]] || \
            fail "${label} has mode ${mode}; expected ${required_mode}: ${path}"
    fi
}

assert_owned_exact_symlink() {
    local label=$1
    local path=$2
    local expected_target=$3
    local kind uid gid

    [[ -L "${path}" ]] || fail "${label} is not a symlink: ${path}"
    IFS='|' read -r kind uid gid < <(stat -c '%F|%u|%g' -- "${path}") || \
        fail "cannot inspect ${label}: ${path}"
    [[ "${kind}" == "symbolic link" ]] || fail "${label} has an unexpected type: ${path}"
    [[ "${uid}" == 0 && "${gid}" == 0 ]] || fail "${label} is not root owned: ${path}"
    [[ "$(readlink -- "${path}")" == "${expected_target}" ]] || \
        fail "${label} has an unexpected target: ${path}"
}

attest_offline_crond_provider() {
    local fragment=/usr/lib/systemd/system/crond.service
    local daemon=/usr/sbin/crond
    local enablement=/etc/systemd/system/multi-user.target.wants/crond.service
    local fragment_host="${IMAGE_ROOT}${fragment}"
    local daemon_host="${IMAGE_ROOT}${daemon}"
    local enablement_host="${IMAGE_ROOT}${enablement}"
    local target fragment_owner daemon_owner kind uid gid

    assert_secure_existing_directory_chain "Cronie unit parent" "usr/lib/systemd/system"
    assert_secure_existing_directory_chain "Cronie daemon parent" "usr/sbin"
    assert_secure_existing_directory_chain \
        "Cronie enablement parent" "etc/systemd/system/multi-user.target.wants"
    assert_secure_owned_regular_file "Cronie systemd unit" "${fragment_host}"
    assert_secure_owned_regular_file "Cronie daemon" "${daemon_host}"
    [[ -x "${daemon_host}" ]] || fail "Cronie daemon is not executable: ${daemon_host}"

    [[ -L "${enablement_host}" ]] || \
        fail "offline image requires enabled crond.service: ${enablement_host}"
    IFS='|' read -r kind uid gid < <(stat -c '%F|%u|%g' -- "${enablement_host}") || \
        fail "cannot inspect Cronie enablement: ${enablement_host}"
    [[ "${kind}" == "symbolic link" && "${uid}" == 0 && "${gid}" == 0 ]] || \
        fail "Cronie enablement is not a root-owned symlink: ${enablement_host}"
    target="$(readlink -- "${enablement_host}")" || \
        fail "cannot read Cronie enablement target: ${enablement_host}"
    case "${target}" in
        /usr/lib/systemd/system/crond.service|\
        ../../../../usr/lib/systemd/system/crond.service) : ;;
        *) fail "Cronie enablement does not target the packaged crond.service unit" ;;
    esac

    fragment_owner="$(run_rooted_rpm --queryfile --queryformat \
        '%{NAME}|%{EVR}\n' -- "${fragment}")" || \
        fail "cannot attest Cronie unit RPM ownership"
    daemon_owner="$(run_rooted_rpm --queryfile --queryformat \
        '%{NAME}|%{EVR}\n' -- "${daemon}")" || \
        fail "cannot attest Cronie daemon RPM ownership"
    [[ "${fragment_owner}" =~ ^cronie\|[A-Za-z0-9.+:~_-]+$ ]] || \
        fail "Cronie unit RPM ownership is ambiguous"
    [[ "${daemon_owner}" == "${fragment_owner}" ]] || \
        fail "Cronie unit and daemon RPM provenance disagree"
}

assert_secure_existing_directory_chain() {
    local label=$1
    local relative=$2
    local current="${IMAGE_ROOT}"
    local component
    local -a components=()

    [[ "${relative}" != /* ]] || fail "${label} must be image relative"
    IFS='/' read -r -a components <<< "${relative}"
    for component in "${components[@]}"; do
        [[ -n "${component}" && "${component}" != . && "${component}" != .. ]] || \
            fail "${label} contains an unsafe path component: ${relative}"
        current="${current}/${component}"
        if [[ -e "${current}" || -L "${current}" ]]; then
            [[ ! -L "${current}" ]] || fail "${label} contains a symlink: ${current}"
            assert_secure_owned_directory "${label}" "${current}"
        else
            break
        fi
    done
}

attest_rpm_database_paths() {
    local database_host_path entry link_count
    local -a database_entries=()

    if ((10#${RHEL_FAMILY_MAJOR} == 9)); then
        TARGET_RPM_DBPATH=/var/lib/rpm
        if [[ -e "${IMAGE_ROOT}/usr/lib/sysimage/rpm" || \
              -L "${IMAGE_ROOT}/usr/lib/sysimage/rpm" ]]; then
            fail "RHEL-family 9 image has an ambiguous relocated RPM database path"
        fi
        assert_secure_existing_directory_chain "RPM database path" "var/lib/rpm"
    else
        TARGET_RPM_DBPATH=/usr/lib/sysimage/rpm
        assert_secure_existing_directory_chain "RPM database path" "usr/lib/sysimage/rpm"
        assert_secure_existing_directory_chain "RPM compatibility path" "var/lib"
        [[ -e "${IMAGE_ROOT}/var/lib/rpm" || -L "${IMAGE_ROOT}/var/lib/rpm" ]] || \
            fail "RHEL-family 10+ image lacks the RPM compatibility database link"
        assert_owned_exact_symlink "RPM compatibility database link" \
            "${IMAGE_ROOT}/var/lib/rpm" ../../usr/lib/sysimage/rpm
    fi

    database_host_path="${IMAGE_ROOT}${TARGET_RPM_DBPATH}"
    [[ -d "${database_host_path}" && ! -L "${database_host_path}" ]] || \
        fail "image RPM database is not a regular directory: ${database_host_path}"
    assert_secure_owned_directory "RPM database directory" "${database_host_path}"

    shopt -s nullglob dotglob
    database_entries=("${database_host_path}"/*)
    shopt -u nullglob dotglob
    for entry in "${database_entries[@]}"; do
        [[ ! -L "${entry}" ]] || fail "image RPM database contains a symlink: ${entry}"
        assert_secure_owned_regular_file "RPM database file" "${entry}"
        link_count="$(stat -c '%h' -- "${entry}")" || \
            fail "cannot inspect RPM database file link count: ${entry}"
        [[ "${link_count}" == 1 ]] || \
            fail "image RPM database file must not be hard-linked: ${entry}"
    done

}

IMAGE_ROOT="$(canonical_existing_path "image root" "${IMAGE_ROOT}")"
[[ "${IMAGE_ROOT}" != / ]] || fail "image root '/' is never accepted"
capture_protected_ancestor_chain \
    "image root" "${IMAGE_ROOT}" image_root
assert_secure_owned_directory "image root" "${IMAGE_ROOT}"
ROOT_IDENTITY="$(path_identity "${IMAGE_ROOT}")" || fail "cannot capture image root identity"

if ((PREFLIGHT_ROOT_ONLY == 0)); then
    RPM_SOURCE="$(canonical_existing_path "RPM source" "${RPM_SOURCE}")"
    [[ "${RPM_SOURCE}" != "${IMAGE_ROOT}"/* ]] || fail "RPM source must be outside the image root"
    assert_secure_owned_regular_file "RPM source" "${RPM_SOURCE}"
    RPM_SOURCE_PARENT=${RPM_SOURCE%/*}
    [[ -n "${RPM_SOURCE_PARENT}" ]] || RPM_SOURCE_PARENT=/
    capture_protected_ancestor_chain \
        "RPM source parent" "${RPM_SOURCE_PARENT}" rpm_source
    assert_secure_owned_directory "RPM source parent" "${RPM_SOURCE_PARENT}"
    (( $(stat -c '%s' -- "${RPM_SOURCE}") > 0 )) || fail "RPM source is empty"

    [[ ${#EXPECTED_SHA256} -eq 64 ]] || \
        fail "--sha256 must contain exactly 64 hexadecimal characters"
    [[ "${EXPECTED_SHA256}" != *[!0-9A-Fa-f]* ]] || fail "--sha256 is not hexadecimal"
    EXPECTED_SHA256="${EXPECTED_SHA256,,}"
    RPM_SOURCE_IDENTITY="$(path_identity "${RPM_SOURCE}")" || fail "cannot capture RPM identity"
fi

assert_root_identity() {
    reattest_protected_ancestor_chain \
        "image root" image_root
    [[ "$(path_identity "${IMAGE_ROOT}")" == "${ROOT_IDENTITY}" ]] || \
        fail "image root identity changed during staging"
    assert_no_symlink_components "image root" "${IMAGE_ROOT}"
    assert_secure_owned_directory "image root" "${IMAGE_ROOT}"
}

assert_rpm_source_identity() {
    reattest_protected_ancestor_chain \
        "RPM source parent" rpm_source
    [[ "$(path_identity "${RPM_SOURCE}")" == "${RPM_SOURCE_IDENTITY}" ]] || \
        fail "RPM source identity changed during staging"
    assert_no_symlink_components "RPM source" "${RPM_SOURCE}"
    assert_secure_owned_regular_file "RPM source" "${RPM_SOURCE}"
}

assert_offline_unmounted_root() {
    local mount_targets target

    mount_targets="$(findmnt --raw --noheadings --output TARGET)" || \
        fail "cannot enumerate builder mount targets"
    while IFS= read -r target; do
        [[ -n "${target}" ]] || continue
        case "${target}" in
            "${IMAGE_ROOT}"|"${IMAGE_ROOT}"/*)
                fail "image root or a descendant is mounted: ${target}"
                ;;
        esac
    done <<< "${mount_targets}"

    for runtime_path in \
        run/systemd/system \
        run/openrc \
        proc/1 \
        sys/kernel; do
        if [[ -e "${IMAGE_ROOT}/${runtime_path}" || -L "${IMAGE_ROOT}/${runtime_path}" ]]; then
            fail "image root contains a live or ambiguous runtime path: /${runtime_path}"
        fi
    done
}

ROOT_IDENTITY_READY=1

decode_os_release_value() {
    local raw=$1
    local kind=$2
    local value

    if [[ "${raw}" == \"*\" && ${#raw} -ge 2 ]]; then
        value="${raw:1:${#raw}-2}"
    elif [[ "${raw}" == \'*\' && ${#raw} -ge 2 ]]; then
        value="${raw:1:${#raw}-2}"
    else
        value="${raw}"
    fi
    case "${kind}" in
        id)
            [[ "${value}" =~ ^[a-z0-9._-]+$ ]] || return 1
            ;;
        id_like)
            [[ -z "${value}" || "${value}" =~ ^[a-z0-9._-]+([[:space:]][a-z0-9._-]+)*$ ]] || return 1
            ;;
        version)
            [[ "${value}" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
            ;;
        *) return 1 ;;
    esac
    printf '%s\n' "${value}"
}

attest_rhel_family() {
    local os_release=""
    local line key raw value token
    local image_id="" image_id_like="" image_version=""
    local id_count=0 id_like_count=0 version_count=0 family_match=0
    local major

    if [[ -e "${IMAGE_ROOT}/usr/lib/os-release" || -L "${IMAGE_ROOT}/usr/lib/os-release" ]]; then
        os_release="${IMAGE_ROOT}/usr/lib/os-release"
    elif [[ -e "${IMAGE_ROOT}/etc/os-release" || -L "${IMAGE_ROOT}/etc/os-release" ]]; then
        os_release="${IMAGE_ROOT}/etc/os-release"
    else
        fail "image root has no os-release metadata"
    fi
    assert_no_symlink_components "os-release metadata" "${os_release}"
    assert_secure_owned_regular_file "os-release metadata" "${os_release}"
    (( $(stat -c '%s' -- "${os_release}") <= 65536 )) || fail "os-release metadata is too large"

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        [[ "${line}" == *=* ]] || continue
        key=${line%%=*}
        raw=${line#*=}
        case "${key}" in
            ID)
                ((id_count += 1))
                ((id_count == 1)) || fail "os-release contains duplicate ID"
                value="$(decode_os_release_value "${raw}" id)" || fail "os-release contains an unsafe ID"
                image_id=${value}
                ;;
            ID_LIKE)
                ((id_like_count += 1))
                ((id_like_count == 1)) || fail "os-release contains duplicate ID_LIKE"
                value="$(decode_os_release_value "${raw}" id_like)" || fail "os-release contains an unsafe ID_LIKE"
                image_id_like=${value}
                ;;
            VERSION_ID)
                ((version_count += 1))
                ((version_count == 1)) || fail "os-release contains duplicate VERSION_ID"
                value="$(decode_os_release_value "${raw}" version)" || fail "os-release contains an unsafe VERSION_ID"
                image_version=${value}
                ;;
        esac
    done < "${os_release}"

    ((id_count == 1 && version_count == 1)) || fail "os-release must define one ID and one VERSION_ID"
    case "${image_id}" in
        rhel|centos|rocky|almalinux|ol) family_match=1 ;;
    esac
    for token in ${image_id_like}; do
        case "${token}" in
            rhel|centos) family_match=1 ;;
        esac
    done
    ((family_match == 1)) || fail "image is not in the supported RHEL family"

    major=${image_version%%.*}
    [[ "${major}" =~ ^[1-9][0-9]*$ ]] || fail "RHEL-family major version is invalid: ${image_version}"
    ((10#${major} >= 9)) || fail "RHEL-family major version 9 or newer is required"
    printf '%s\n' "${major}"
}

attest_preflight_root_shape() {
    local relative path

    # These fixed paths distinguish an extracted operating-system root from a
    # protected host directory such as /etc, /usr, or /var. The check is
    # intentionally bounded and read-only so it is safe before any image
    # builder invokes a package-manager or service-manager --root operation.
    for relative in etc usr usr/lib var var/lib; do
        path="${IMAGE_ROOT}/${relative}"
        [[ -d "${path}" && ! -L "${path}" ]] || \
            fail "image root lacks required extracted-root directory: /${relative}"
        assert_secure_owned_directory "extracted-root directory" "${path}"
    done
    path="${IMAGE_ROOT}/usr/lib/os-release"
    [[ -e "${path}" && ! -L "${path}" ]] || \
        fail "image root requires exact /usr/lib/os-release metadata"
    assert_no_symlink_components "preflight os-release metadata" "${path}"
    assert_secure_owned_regular_file "preflight os-release metadata" "${path}"
}

if ((PREFLIGHT_ROOT_ONLY == 1)); then
    assert_root_identity
    assert_offline_unmounted_root
    attest_preflight_root_shape
    RHEL_FAMILY_MAJOR="$(attest_rhel_family)"
    assert_root_identity
    assert_offline_unmounted_root
    printf 'Offline RHEL-family %s image root preflight passed: %s\n' \
        "${RHEL_FAMILY_MAJOR}" "${IMAGE_ROOT}"
    exit 0
fi

scan_cron_tree() {
    local scan_root=$1
    local current entry file_size scan_output scan_status
    local -a pending=("${scan_root}") children=()

    while ((${#pending[@]} > 0)); do
        current=${pending[-1]}
        unset 'pending[-1]'

        [[ ! -L "${current}" ]] || fail "refusing symlinked cron state: ${current}"
        if [[ -d "${current}" ]]; then
            children=()
            shopt -s nullglob dotglob
            children=("${current}"/*)
            shopt -u nullglob dotglob
            for entry in "${children[@]}"; do
                pending+=("${entry}")
            done
            continue
        fi
        [[ -f "${current}" ]] || fail "refusing non-regular cron state: ${current}"
        file_size="$(stat -c '%s' -- "${current}")" || \
            fail "cannot inspect cron state size: ${current}"
        [[ "${file_size}" =~ ^[0-9]+$ ]] || fail "cron state size is invalid: ${current}"
        ((file_size <= 1048576)) || fail "cron state file is too large to inspect: ${current}"

        set +e
        scan_output="$(grep -I -i -l -m 1 -- 'syswarden' "${current}" 2>/dev/null)"
        scan_status=$?
        set -e
        case "${scan_status}" in
            0) fail "fresh-image staging refuses existing SysWarden cron state: ${scan_output}" ;;
            1) : ;;
            *) fail "cannot inspect existing cron state: ${current}" ;;
        esac
    done
}

cleanup_orphaned_pretransaction_snapshots() {
    local directory entry base entry_base
    local -a directories=() entries=()

    assert_root_identity
    assert_offline_unmounted_root
    shopt -s nullglob dotglob
    directories=("${IMAGE_ROOT}"/.syswarden-image-stage.*)
    shopt -u nullglob dotglob
    for directory in "${directories[@]}"; do
        base=${directory##*/}
        [[ "${base}" =~ ^[.]syswarden-image-stage[.][A-Za-z0-9]{10}$ ]] || \
            fail "fresh-image cleanup refuses malformed snapshot state: ${directory}"
        assert_secure_owned_directory "orphaned RPM snapshot directory" "${directory}"
        [[ "$(stat -c '%a' -- "${directory}")" == 700 ]] || \
            fail "orphaned RPM snapshot directory has an unsafe mode: ${directory}"
        shopt -s nullglob dotglob
        entries=("${directory}"/*)
        shopt -u nullglob dotglob
        for entry in "${entries[@]}"; do
            entry_base=${entry##*/}
            if [[ ! "${entry_base}" =~ ^package[.][A-Za-z0-9]{10}[.]rpm$ && \
                  ! "${entry_base}" =~ ^journal[.][A-Za-z0-9]{10}$ ]]; then
                fail "fresh-image cleanup refuses unexpected snapshot content: ${entry}"
            fi
            assert_secure_owned_regular_file "orphaned transaction artifact" "${entry}" 600
            assert_root_identity
            assert_offline_unmounted_root
            rm -f -- "${entry}"
        done
        assert_root_identity
        assert_offline_unmounted_root
        rmdir -- "${directory}" || \
            fail "cannot retire an orphaned pre-transaction snapshot directory: ${directory}"
    done
}

assert_syswarden_state_boundary() {
    local matches match scan_path

    assert_root_identity
    assert_offline_unmounted_root
    matches="$(find -P "${IMAGE_ROOT}" -xdev -mindepth 1 -iname '*syswarden*' -print)" || \
        fail "cannot scan the image for existing SysWarden paths"
    if ((RECOVERY_MODE == 0)); then
        [[ -z "${matches}" ]] || \
            fail "fresh-image staging refuses existing SysWarden path: ${matches%%$'\n'*}"
    else
        while IFS= read -r match; do
            [[ -n "${match}" ]] || continue
            case "${match}" in
                "${IMAGE_ROOT}"/.syswarden-image-stage.*)
                    [[ "${match%/*}" == "${IMAGE_ROOT}" && \
                        "${match##*/}" =~ ^[.]syswarden-image-stage[.][A-Za-z0-9]{10}$ ]] || \
                        fail "transaction recovery refuses malformed snapshot state: ${match}"
                    continue
                    ;;
            esac
            case "${match}" in
                "${TRANSACTION_JOURNAL_PATH}"|\
                "${IMAGE_ROOT}/opt/syswarden"|\
                "${IMAGE_ROOT}/opt/syswarden/bin"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-core"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-tui"|\
                "${IMAGE_ROOT}/opt/syswarden/signatures.json"|\
                "${IMAGE_ROOT}/usr/local/bin/syswarden"|\
                "${IMAGE_ROOT}/usr/local/bin/syswarden-tui"|\
                "${IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service"|\
                "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service"|\
                "${IMAGE_ROOT}/var/lib/syswarden"|\
                "${IMAGE_ROOT}/var/lib/syswarden/image"|\
                "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending")
                    :
                    ;;
                "${IMAGE_ROOT}/etc/systemd/system/.syswarden-image-firstboot.service."*)
                    [[ "${match##*/}" =~ ^[.]syswarden-image-firstboot[.]service[.][A-Za-z0-9]{10}$ ]] || \
                        fail "transaction recovery refuses malformed publication state: ${match}"
                    ;;
                *)
                    fail "transaction recovery refuses unexpected SysWarden state: ${match}"
                    ;;
            esac
        done <<< "${matches}"
    fi

    for scan_path in \
        "${IMAGE_ROOT}/etc/crontab" \
        "${IMAGE_ROOT}/etc/cron.d" \
        "${IMAGE_ROOT}/var/spool/cron" \
        "${IMAGE_ROOT}/var/spool/cron/crontabs"; do
        [[ -e "${scan_path}" || -L "${scan_path}" ]] || continue
        scan_cron_tree "${scan_path}"
    done
}

assert_root_identity
assert_offline_unmounted_root
RHEL_FAMILY_MAJOR="$(attest_rhel_family)"
TRANSACTION_JOURNAL_PATH="${IMAGE_ROOT}/.syswarden-image-transaction"
if [[ -e "${TRANSACTION_JOURNAL_PATH}" || -L "${TRANSACTION_JOURNAL_PATH}" ]]; then
    assert_no_symlink_components "transaction journal" "${TRANSACTION_JOURNAL_PATH}"
    assert_secure_owned_regular_file "transaction journal" "${TRANSACTION_JOURNAL_PATH}" 600
    RECOVERY_MODE=1
fi
if ((RECOVERY_MODE == 0)); then
    cleanup_orphaned_pretransaction_snapshots
fi
assert_syswarden_state_boundary

# A usable image must already contain systemd and the utility used to retire
# the marker. They are inspected as files only and are never executed here.
assert_no_symlink_components "systemd executable" "${IMAGE_ROOT}/usr/lib/systemd/systemd"
assert_secure_owned_regular_file "systemd executable" "${IMAGE_ROOT}/usr/lib/systemd/systemd"
[[ -x "${IMAGE_ROOT}/usr/lib/systemd/systemd" ]] || fail "image systemd executable is not executable"
assert_no_symlink_components "marker removal utility" "${IMAGE_ROOT}/usr/bin/rm"
assert_secure_owned_regular_file "marker removal utility" "${IMAGE_ROOT}/usr/bin/rm"
[[ -x "${IMAGE_ROOT}/usr/bin/rm" ]] || fail "image marker removal utility is not executable"

assert_root_identity
assert_offline_unmounted_root
attest_rpm_database_paths
ROOTED_RPM_COMMAND=("${RPM_COMMAND[@]}" --root "${IMAGE_ROOT}" --dbpath "${TARGET_RPM_DBPATH}")

assert_image_transaction_boundary() {
    assert_root_identity
    assert_offline_unmounted_root
}

run_rooted_rpm() {
    assert_image_transaction_boundary
    "${ROOTED_RPM_COMMAND[@]}" "$@"
}

run_snapshot_rpm() {
    assert_image_transaction_boundary
    "${RPM_COMMAND[@]}" "$@"
}

INSTALLED_INVENTORY="$(run_rooted_rpm --query --all \
    --queryformat '%{NAME}|%{ARCH}\n')" || fail "cannot read the image RPM database"
[[ -n "${INSTALLED_INVENTORY}" ]] || fail "image RPM database has no installed packages"
SYSWARDEN_PACKAGE_COUNT=0
while IFS='|' read -r installed_name installed_arch; do
    [[ -n "${installed_name}" && -n "${installed_arch}" ]] || fail "image RPM inventory is malformed"
    if [[ "${installed_name}" == syswarden ]]; then
        ((SYSWARDEN_PACKAGE_COUNT += 1))
        ((RECOVERY_MODE == 1)) || fail "fresh-image staging refuses an installed SysWarden package"
        PACKAGE_PRESENT=1
    fi
done <<< "${INSTALLED_INVENTORY}"
((SYSWARDEN_PACKAGE_COUNT <= 1)) || fail "transaction recovery found multiple installed SysWarden packages"

assert_image_transaction_boundary

assert_rpm_source_identity
STAGING_DIRECTORY="$(mktemp -d "${IMAGE_ROOT}/.syswarden-image-stage.XXXXXXXXXX")" || \
    fail "cannot create a private RPM snapshot directory inside the image root"
assert_image_transaction_boundary
chmod 0700 -- "${STAGING_DIRECTORY}"
assert_secure_owned_directory "RPM snapshot directory" "${STAGING_DIRECTORY}"
assert_image_transaction_boundary
STAGING_RPM="$(mktemp "${STAGING_DIRECTORY}/package.XXXXXXXXXX.rpm")" || \
    fail "cannot create a private RPM snapshot inside the image root"
assert_image_transaction_boundary
assert_rpm_source_identity
cp -- "${RPM_SOURCE}" "${STAGING_RPM}"
assert_image_transaction_boundary
chmod 0600 -- "${STAGING_RPM}"
assert_secure_owned_regular_file "RPM snapshot" "${STAGING_RPM}" 600

assert_rpm_source_identity
assert_image_transaction_boundary
ACTUAL_SHA256="$(sha256sum -- "${STAGING_RPM}")" || fail "cannot hash the private RPM snapshot"
ACTUAL_SHA256=${ACTUAL_SHA256%% *}
[[ "${ACTUAL_SHA256}" == "${EXPECTED_SHA256}" ]] || fail "RPM SHA-256 does not match --sha256"

RPM_METADATA="$(run_snapshot_rpm --query --package \
    --queryformat '%{NAME}\n%{ARCH}\n%{VERSION}\n%{RELEASE}\n' "${STAGING_RPM}")" || \
    fail "cannot read local RPM metadata"
mapfile -t RPM_FIELDS <<< "${RPM_METADATA}"
[[ ${#RPM_FIELDS[@]} -eq 4 ]] || fail "local RPM identity metadata is malformed"
RPM_NAME=${RPM_FIELDS[0]}
RPM_ARCH=${RPM_FIELDS[1]}
RPM_VERSION=${RPM_FIELDS[2]}
RPM_RELEASE=${RPM_FIELDS[3]}
[[ "${RPM_NAME}" == syswarden ]] || fail "local RPM package name is not syswarden"
case "${RPM_ARCH}" in
    x86_64) : ;;
    *) fail "unsupported SysWarden RPM architecture: ${RPM_ARCH}" ;;
esac
[[ -n "${RPM_VERSION}" && -n "${RPM_RELEASE}" ]] || fail "local RPM version or release is empty"

attest_exact_rpm_payload_inventory() {
    local inventory path mode target extra prefix
    local cli_seen=0 core_seen=0 tui_seen=0 signatures_seen=0
    local command_seen=0 tui_command_seen=0 build_root_seen=0 build_link_count=0
    local -A seen_paths=() build_directories=() build_targets=() build_link_prefixes=()

    inventory="$(run_snapshot_rpm --query --package \
        --queryformat '[%{FILENAMES}|%{FILEMODES:octal}|%{FILELINKTOS}\n]' \
        "${STAGING_RPM}")" || fail "cannot read the local RPM file inventory"
    [[ -n "${inventory}" ]] || fail "local RPM file inventory is empty"

    while IFS='|' read -r path mode target extra; do
        [[ -n "${path}" && -n "${mode}" && -z "${extra}" ]] || \
            fail "local RPM file inventory is malformed"
        [[ -z "${seen_paths[${path}]+present}" ]] || fail "local RPM repeats payload path: ${path}"
        seen_paths["${path}"]=1
        case "${path}" in
            /opt/syswarden/bin/syswarden-cli)
                [[ "${mode}" =~ ^0*100750$ && -z "${target}" ]] || fail "unsafe CLI payload metadata"
                cli_seen=1
                ;;
            /opt/syswarden/bin/syswarden-core)
                [[ "${mode}" =~ ^0*100750$ && -z "${target}" ]] || fail "unsafe core payload metadata"
                core_seen=1
                ;;
            /opt/syswarden/bin/syswarden-tui)
                [[ "${mode}" =~ ^0*100750$ && -z "${target}" ]] || fail "unsafe TUI payload metadata"
                tui_seen=1
                ;;
            /opt/syswarden/signatures.json)
                [[ "${mode}" =~ ^0*100640$ && -z "${target}" ]] || fail "unsafe signatures payload metadata"
                signatures_seen=1
                ;;
            /usr/local/bin/syswarden)
                [[ "${mode}" =~ ^0*120777$ && "${target}" == /opt/syswarden/bin/syswarden-cli ]] || \
                    fail "unsafe CLI command-link metadata"
                command_seen=1
                ;;
            /usr/local/bin/syswarden-tui)
                [[ "${mode}" =~ ^0*120777$ && "${target}" == /opt/syswarden/bin/syswarden-tui ]] || \
                    fail "unsafe TUI command-link metadata"
                tui_command_seen=1
                ;;
            /usr/lib/.build-id)
                [[ "${mode}" =~ ^0*40755$ && -z "${target}" ]] || fail "unsafe build-id root metadata"
                build_root_seen=1
                ;;
            /usr/lib/.build-id/*)
                if [[ "${path}" =~ ^/usr/lib/[.]build-id/([0-9a-f]{2})$ ]]; then
                    prefix=${BASH_REMATCH[1]}
                    [[ "${mode}" =~ ^0*40755$ && -z "${target}" ]] || \
                        fail "unsafe build-id directory metadata: ${path}"
                    build_directories["${prefix}"]=1
                elif [[ "${path}" =~ ^/usr/lib/[.]build-id/([0-9a-f]{2})/([0-9a-f]{38})$ ]]; then
                    prefix=${BASH_REMATCH[1]}
                    [[ "${mode}" =~ ^0*120777$ ]] || fail "unsafe build-id link mode: ${path}"
                    case "${target}" in
                        ../../../../opt/syswarden/bin/syswarden-cli|\
                        ../../../../opt/syswarden/bin/syswarden-core|\
                        ../../../../opt/syswarden/bin/syswarden-tui) : ;;
                        *) fail "unsafe build-id link target: ${path}" ;;
                    esac
                    [[ -z "${build_targets[${target}]+present}" ]] || \
                        fail "local RPM repeats a build-id target: ${target}"
                    build_targets["${target}"]=1
                    build_link_prefixes["${prefix}"]=1
                    ((build_link_count += 1))
                else
                    fail "local RPM contains an unexpected build-id path: ${path}"
                fi
                ;;
            *)
                fail "local RPM contains an unexpected payload path: ${path}"
                ;;
        esac
    done <<< "${inventory}"

    ((cli_seen == 1 && core_seen == 1 && tui_seen == 1 && signatures_seen == 1)) || \
        fail "local RPM is missing an exact product payload file"
    ((command_seen == 1 && tui_command_seen == 1 && build_root_seen == 1)) || \
        fail "local RPM is missing an exact command or build-id path"
    ((build_link_count == 3)) || fail "local RPM must contain exactly three build-id links"
    for target in \
        ../../../../opt/syswarden/bin/syswarden-cli \
        ../../../../opt/syswarden/bin/syswarden-core \
        ../../../../opt/syswarden/bin/syswarden-tui; do
        [[ -n "${build_targets[${target}]+present}" ]] || fail "local RPM is missing build-id target: ${target}"
    done
    for prefix in "${!build_link_prefixes[@]}"; do
        [[ -n "${build_directories[${prefix}]+present}" ]] || \
            fail "local RPM omits build-id parent directory: ${prefix}"
    done

    assert_secure_existing_directory_chain "RPM payload parent" "opt/syswarden/bin"
    assert_secure_existing_directory_chain "RPM command-link parent" "usr/local/bin"
    assert_secure_existing_directory_chain "RPM build-id parent" "usr/lib/.build-id"
    for prefix in "${!build_link_prefixes[@]}"; do
        assert_secure_existing_directory_chain "RPM build-id prefix parent" "usr/lib/.build-id/${prefix}"
    done
    assert_secure_existing_directory_chain \
        "first-boot unit parent" "etc/systemd/system/multi-user.target.wants"
    assert_secure_existing_directory_chain \
        "first-boot marker parent" "var/lib/syswarden/image"
}

attest_exact_rpm_payload_inventory

ARCH_PRESENT=0
while IFS='|' read -r installed_name installed_arch; do
    [[ "${installed_arch}" == "${RPM_ARCH}" ]] && ARCH_PRESENT=1
done <<< "${INSTALLED_INVENTORY}"
((ARCH_PRESENT == 1)) || fail "local RPM architecture is absent from the image RPM inventory: ${RPM_ARCH}"

RPM_REQUIREMENTS="$(run_snapshot_rpm --query --package --requires "${STAGING_RPM}")" || \
    fail "cannot read local RPM dependencies"
[[ -n "${RPM_REQUIREMENTS}" ]] || fail "local RPM dependency metadata is empty"
while IFS= read -r requirement; do
    [[ -n "${requirement}" ]] || fail "local RPM contains an empty dependency"
    [[ "${requirement}" != *$'\r'* && "${requirement}" != *$'\t'* ]] || \
        fail "local RPM contains an unsafe dependency expression"
    case "${requirement}" in
        rpmlib\(*) continue ;;
    esac
    run_rooted_rpm --query --whatprovides -- "${requirement}" \
        >/dev/null || fail "image is missing required RPM capability: ${requirement}"
done <<< "${RPM_REQUIREMENTS}"

# This is an offline file, package, and enablement proof only. It never claims
# a live daemon or invokes a service manager inside the image root. The normal
# first-boot CLI transaction performs the separate runtime attestation.
attest_offline_crond_provider

TRANSACTION_JOURNAL_CONTENT="format=1
sha256=${EXPECTED_SHA256}
name=${RPM_NAME}
arch=${RPM_ARCH}
version=${RPM_VERSION}
release=${RPM_RELEASE}
"

cleanup_abandoned_snapshot_directories() {
    local directory entry base entry_base
    local -a directories=() entries=()

    assert_image_transaction_boundary
    shopt -s nullglob dotglob
    directories=("${IMAGE_ROOT}"/.syswarden-image-stage.*)
    shopt -u nullglob dotglob
    for directory in "${directories[@]}"; do
        [[ "${directory}" != "${STAGING_DIRECTORY}" ]] || continue
        base=${directory##*/}
        [[ "${base}" =~ ^[.]syswarden-image-stage[.][A-Za-z0-9]{10}$ ]] || \
            fail "transaction recovery refuses malformed snapshot directory: ${directory}"
        assert_secure_owned_directory "abandoned RPM snapshot directory" "${directory}"
        [[ "$(stat -c '%a' -- "${directory}")" == 700 ]] || \
            fail "abandoned RPM snapshot directory has an unsafe mode: ${directory}"
        shopt -s nullglob dotglob
        entries=("${directory}"/*)
        shopt -u nullglob dotglob
        for entry in "${entries[@]}"; do
            entry_base=${entry##*/}
            if [[ ! "${entry_base}" =~ ^package[.][A-Za-z0-9]{10}[.]rpm$ && \
                  ! "${entry_base}" =~ ^journal[.][A-Za-z0-9]{10}$ ]]; then
                fail "transaction recovery refuses unexpected snapshot content: ${entry}"
            fi
            assert_secure_owned_regular_file "abandoned transaction artifact" "${entry}" 600
            assert_image_transaction_boundary
            rm -f -- "${entry}"
        done
        assert_image_transaction_boundary
        rmdir -- "${directory}" || fail "cannot retire an abandoned snapshot directory: ${directory}"
    done
}

cleanup_recovery_publication_temporaries() {
    local temporary base mode
    local -a temporaries=()

    assert_image_transaction_boundary
    shopt -s nullglob
    temporaries=(
        "${IMAGE_ROOT}/etc/systemd/system"/.syswarden-image-firstboot.service.*
        "${IMAGE_ROOT}/var/lib/syswarden/image"/.firstboot.pending.*
    )
    shopt -u nullglob
    for temporary in "${temporaries[@]}"; do
        base=${temporary##*/}
        case "${temporary}" in
            "${IMAGE_ROOT}/etc/systemd/system/"*)
                [[ "${base}" =~ ^[.]syswarden-image-firstboot[.]service[.][A-Za-z0-9]{10}$ ]] || \
                    fail "transaction recovery refuses malformed unit temporary: ${temporary}"
                assert_secure_owned_regular_file \
                    "first-boot unit publication temporary" "${temporary}"
                mode="$(stat -c '%a' -- "${temporary}")"
                [[ "${mode}" == 600 || "${mode}" == 644 ]] || \
                    fail "first-boot unit publication temporary has unsafe mode: ${temporary}"
                ;;
            "${IMAGE_ROOT}/var/lib/syswarden/image/"*)
                [[ "${base}" =~ ^[.]firstboot[.]pending[.][A-Za-z0-9]{10}$ ]] || \
                    fail "transaction recovery refuses malformed marker temporary: ${temporary}"
                assert_secure_owned_regular_file \
                    "first-boot marker publication temporary" "${temporary}" 600
                ;;
            *)
                fail "transaction recovery refuses publication temporary outside its boundary: ${temporary}"
                ;;
        esac
        assert_image_transaction_boundary
        rm -f -- "${temporary}"
    done
}

assert_recovery_tree_shape() {
    local path entries

    if [[ -e "${IMAGE_ROOT}/opt/syswarden" || -L "${IMAGE_ROOT}/opt/syswarden" ]]; then
        [[ ! -L "${IMAGE_ROOT}/opt/syswarden" ]] || fail "transaction recovery refuses symlinked payload state"
        entries="$(find -P "${IMAGE_ROOT}/opt/syswarden" -mindepth 1 -print)" || \
            fail "cannot inspect recovery payload state"
        while IFS= read -r path; do
            [[ -n "${path}" ]] || continue
            case "${path}" in
                "${IMAGE_ROOT}/opt/syswarden/bin"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-core"|\
                "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-tui"|\
                "${IMAGE_ROOT}/opt/syswarden/signatures.json") : ;;
                *) fail "transaction recovery refuses unexpected payload state: ${path}" ;;
            esac
        done <<< "${entries}"
    fi

    if [[ -e "${IMAGE_ROOT}/var/lib/syswarden" || -L "${IMAGE_ROOT}/var/lib/syswarden" ]]; then
        [[ ! -L "${IMAGE_ROOT}/var/lib/syswarden" ]] || fail "transaction recovery refuses symlinked image state"
        entries="$(find -P "${IMAGE_ROOT}/var/lib/syswarden" -mindepth 1 -print)" || \
            fail "cannot inspect recovery image state"
        while IFS= read -r path; do
            [[ -n "${path}" ]] || continue
            case "${path}" in
                "${IMAGE_ROOT}/var/lib/syswarden/image"|\
                "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending") : ;;
                *) fail "transaction recovery refuses unexpected image state: ${path}" ;;
            esac
        done <<< "${entries}"
    fi
}

if ((RECOVERY_MODE == 1)); then
    assert_image_transaction_boundary
    [[ "$(<"${TRANSACTION_JOURNAL_PATH}")" == "${TRANSACTION_JOURNAL_CONTENT%$'\n'}" ]] || \
        fail "transaction journal does not match the supplied RPM identity and SHA-256"
    cleanup_recovery_publication_temporaries
    cleanup_abandoned_snapshot_directories
    assert_recovery_tree_shape
    if ((PACKAGE_PRESENT == 0)); then
        for inconsistent_path in \
            "${IMAGE_ROOT}/opt/syswarden" \
            "${IMAGE_ROOT}/usr/local/bin/syswarden" \
            "${IMAGE_ROOT}/usr/local/bin/syswarden-tui" \
            "${IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service" \
            "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" \
            "${IMAGE_ROOT}/var/lib/syswarden"; do
            [[ ! -e "${inconsistent_path}" && ! -L "${inconsistent_path}" ]] || \
                fail "transaction journal has no package but image state is already present: ${inconsistent_path}"
        done
    fi
else
    assert_image_transaction_boundary
    journal_temporary="$(mktemp "${STAGING_DIRECTORY}/journal.XXXXXXXXXX")" || \
        fail "cannot create a private transaction journal"
    assert_image_transaction_boundary
    printf '%s' "${TRANSACTION_JOURNAL_CONTENT}" > "${journal_temporary}"
    assert_image_transaction_boundary
    chmod 0600 -- "${journal_temporary}"
    assert_secure_owned_regular_file "temporary transaction journal" "${journal_temporary}" 600
    assert_image_transaction_boundary
    if ! ln -- "${journal_temporary}" "${TRANSACTION_JOURNAL_PATH}"; then
        assert_image_transaction_boundary
        rm -f -- "${journal_temporary}"
        fail "cannot publish the transaction journal without replacement"
    fi
    assert_image_transaction_boundary
    rm -f -- "${journal_temporary}"
    assert_secure_owned_regular_file "transaction journal" "${TRANSACTION_JOURNAL_PATH}" 600
    [[ "$(<"${TRANSACTION_JOURNAL_PATH}")" == "${TRANSACTION_JOURNAL_CONTENT%$'\n'}" ]] || \
        fail "transaction journal changed while publishing"
fi

assert_image_transaction_boundary

# The test transaction and the real transaction use the same hard boundary:
# one local package, no plugins, no package scripts, and no triggers. No
# dependency package is installed by this extension.
if ((PACKAGE_PRESENT == 0)); then
    run_rooted_rpm --install --test --noscripts --notriggers -- "${STAGING_RPM}" || \
        fail "local RPM test transaction failed"
    run_rooted_rpm --install --noscripts --notriggers -- "${STAGING_RPM}" || \
        fail "local RPM installation into the image root failed"
fi

INSTALLED_METADATA="$(run_rooted_rpm --query \
    --queryformat '%{NAME}\n%{ARCH}\n%{VERSION}\n%{RELEASE}\n' syswarden)" || \
    fail "installed SysWarden RPM identity is unavailable"
[[ "${INSTALLED_METADATA}" == "${RPM_METADATA}" ]] || fail "installed RPM identity differs from the local artifact"
run_rooted_rpm --verify --noscript syswarden || \
    fail "installed SysWarden RPM payload verification failed"

assert_secure_owned_directory "installed payload directory" "${IMAGE_ROOT}/opt/syswarden"
assert_secure_owned_directory "installed payload binary directory" "${IMAGE_ROOT}/opt/syswarden/bin"
for payload_binary in syswarden-cli syswarden-core syswarden-tui; do
    assert_no_symlink_components "installed payload" "${IMAGE_ROOT}/opt/syswarden/bin/${payload_binary}"
    assert_secure_owned_regular_file "installed payload" \
        "${IMAGE_ROOT}/opt/syswarden/bin/${payload_binary}" 750
    [[ -x "${IMAGE_ROOT}/opt/syswarden/bin/${payload_binary}" ]] || \
        fail "installed payload is not executable: ${payload_binary}"
done
assert_no_symlink_components "installed signatures" "${IMAGE_ROOT}/opt/syswarden/signatures.json"
assert_secure_owned_regular_file "installed signatures" \
    "${IMAGE_ROOT}/opt/syswarden/signatures.json" 640

assert_secure_owned_directory "installed command link directory" "${IMAGE_ROOT}/usr/local/bin"
for payload_link in syswarden syswarden-tui; do
    link_path="${IMAGE_ROOT}/usr/local/bin/${payload_link}"
    expected_target="/opt/syswarden/bin/syswarden-cli"
    [[ "${payload_link}" == syswarden-tui ]] && expected_target="/opt/syswarden/bin/syswarden-tui"
    assert_owned_exact_symlink "installed payload link" "${link_path}" "${expected_target}"
done

assert_root_identity
assert_offline_unmounted_root

ensure_secure_directory_chain() {
    local relative=$1
    local final_mode=$2
    local current="${IMAGE_ROOT}"
    local component path mode
    local -a components=()

    assert_image_transaction_boundary
    [[ "${relative}" != /* && "${relative}" != *..* ]] || fail "unsafe image-relative directory: ${relative}"
    IFS='/' read -r -a components <<< "${relative}"
    for component in "${components[@]}"; do
        [[ -n "${component}" && "${component}" != . && "${component}" != .. ]] || \
            fail "unsafe image-relative directory component: ${relative}"
        current="${current}/${component}"
        if [[ -e "${current}" || -L "${current}" ]]; then
            [[ ! -L "${current}" ]] || fail "refusing symlinked image directory: ${current}"
            assert_secure_owned_directory "image directory" "${current}"
        else
            mode=0755
            [[ "${current}" == "${IMAGE_ROOT}/${relative}" ]] && mode=${final_mode}
            assert_image_transaction_boundary
            mkdir -m "${mode}" -- "${current}"
            assert_secure_owned_directory "created image directory" "${current}"
        fi
    done
}

publish_exact_regular_file() {
    local destination=$1
    local mode=$2
    local content=$3
    local parent base temporary

    assert_image_transaction_boundary
    [[ "${destination}" == "${IMAGE_ROOT}"/* ]] || fail "publication path escapes the image root"
    parent=${destination%/*}
    base=${destination##*/}
    assert_secure_owned_directory "publication directory" "${parent}"
    if [[ -e "${destination}" || -L "${destination}" ]]; then
        assert_secure_owned_regular_file "existing extension artifact" "${destination}" "${mode}"
        [[ "$(<"${destination}")" == "${content%$'\n'}" ]] || \
            fail "refusing modified existing extension artifact: ${destination}"
        return 0
    fi
    assert_image_transaction_boundary
    temporary="$(mktemp "${parent}/.${base}.XXXXXXXXXX")" || \
        fail "cannot create temporary extension artifact: ${destination}"
    assert_image_transaction_boundary
    printf '%s' "${content}" > "${temporary}"
    assert_image_transaction_boundary
    chmod "${mode}" -- "${temporary}"
    assert_secure_owned_regular_file "temporary extension artifact" "${temporary}" "${mode}"
    assert_image_transaction_boundary
    if ! ln -- "${temporary}" "${destination}"; then
        assert_image_transaction_boundary
        rm -f -- "${temporary}"
        fail "cannot publish extension artifact without replacement: ${destination}"
    fi
    assert_image_transaction_boundary
    rm -f -- "${temporary}"
    assert_secure_owned_regular_file "published extension artifact" "${destination}" "${mode}"
    [[ "$(<"${destination}")" == "${content%$'\n'}" ]] || \
        fail "published extension artifact changed while verifying: ${destination}"
}

ensure_secure_directory_chain "etc/systemd/system" 0755
ensure_secure_directory_chain "etc/systemd/system/multi-user.target.wants" 0755
ensure_secure_directory_chain "var/lib/syswarden" 0750
ensure_secure_directory_chain "var/lib/syswarden/image" 0700

FIRSTBOOT_UNIT_PATH="${IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service"
FIRSTBOOT_LINK_PATH="${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service"
FIRSTBOOT_MARKER_PATH="${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending"

FIRSTBOOT_UNIT_CONTENT='[Unit]
Description=Initialize SysWarden from an offline RHEL image
ConditionPathExists=/var/lib/syswarden/image/firstboot.pending
Requires=crond.service
After=network-online.target firewalld.service crond.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=SYSWARDEN_PKG_INSTALL=1
ExecStart=/opt/syswarden/bin/syswarden-cli install
ExecStart=/opt/syswarden/bin/syswarden-cli reload
ExecStartPost=/usr/bin/rm -f /var/lib/syswarden/image/firstboot.pending
TimeoutStartSec=30min

[Install]
WantedBy=multi-user.target
'
FIRSTBOOT_MARKER_CONTENT="format=1
package=${RPM_NAME}-${RPM_VERSION}-${RPM_RELEASE}.${RPM_ARCH}
sha256=${EXPECTED_SHA256}
"

# The enablement link is published last. Any earlier failure therefore leaves
# an inert image rather than a partially enabled first-boot action.
publish_exact_regular_file "${FIRSTBOOT_MARKER_PATH}" 600 "${FIRSTBOOT_MARKER_CONTENT}"
publish_exact_regular_file "${FIRSTBOOT_UNIT_PATH}" 644 "${FIRSTBOOT_UNIT_CONTENT}"
if [[ -e "${FIRSTBOOT_LINK_PATH}" || -L "${FIRSTBOOT_LINK_PATH}" ]]; then
    assert_owned_exact_symlink "first-boot enablement" \
        "${FIRSTBOOT_LINK_PATH}" ../syswarden-image-firstboot.service
else
    assert_image_transaction_boundary
    ln -s -- ../syswarden-image-firstboot.service "${FIRSTBOOT_LINK_PATH}"
fi
assert_owned_exact_symlink "first-boot enablement" \
    "${FIRSTBOOT_LINK_PATH}" ../syswarden-image-firstboot.service

assert_image_transaction_boundary

assert_secure_owned_regular_file "transaction journal" "${TRANSACTION_JOURNAL_PATH}" 600
[[ "$(<"${TRANSACTION_JOURNAL_PATH}")" == "${TRANSACTION_JOURNAL_CONTENT%$'\n'}" ]] || \
    fail "transaction journal changed before completion"
rm -f -- "${TRANSACTION_JOURNAL_PATH}"
[[ ! -e "${TRANSACTION_JOURNAL_PATH}" && ! -L "${TRANSACTION_JOURNAL_PATH}" ]] || \
    fail "transaction journal remains after completion"

printf 'Staged SysWarden %s-%s.%s into %s\n' \
    "${RPM_VERSION}" "${RPM_RELEASE}" "${RPM_ARCH}" "${IMAGE_ROOT}"
printf 'First boot will run the package-mode install and reload workflow.\n'
printf 'No package script, product binary, service manager, firewall tool, or kernel policy tool ran during staging.\n'
