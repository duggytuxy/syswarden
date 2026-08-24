#!/bin/bash

set -Eeuo pipefail
umask 077
export LC_ALL=C

TEST_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
EXTENSION_DIRECTORY="$(CDPATH='' cd -- "${TEST_DIRECTORY}/.." && pwd -P)"
STAGE_SCRIPT="${EXTENSION_DIRECTORY}/stage-syswarden-rhel-image.sh"

if [[ "${SYSWARDEN_IMAGE_TEST_USERNS:-0}" != 1 ]]; then
    command -v unshare >/dev/null 2>&1 || {
        printf 'Tests require unshare user-namespace support.\n' >&2
        exit 1
    }
    exec env SYSWARDEN_IMAGE_TEST_USERNS=1 unshare --user --map-root-user -- "$0" "$@"
fi
((EUID == 0)) || {
    printf 'The isolated test user namespace did not map the caller to root.\n' >&2
    exit 1
}
[[ "$(readlink /proc/self/ns/user)" != "$(readlink /proc/1/ns/user)" ]] || {
    printf 'Tests require a user namespace separate from PID 1.\n' >&2
    exit 1
}

TEST_WORKSPACE="$(mktemp -d /tmp/syswarden-rhel-image-tests.XXXXXXXXXX)"
FAKE_BIN="${TEST_WORKSPACE}/fake-bin"
PASSED=0
FAILED=0

cleanup_tests() {
    local status=$?
    trap - EXIT HUP INT TERM
    case "${TEST_WORKSPACE}" in
        /tmp/syswarden-rhel-image-tests.*)
            rm -rf -- "${TEST_WORKSPACE}"
            ;;
        *)
            printf 'Refusing unexpected test cleanup: %s\n' "${TEST_WORKSPACE}" >&2
            status=1
            ;;
    esac
    exit "${status}"
}

trap cleanup_tests EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 -- "${FAKE_BIN}"

for copied_tool in realpath stat sha256sum find grep cp mktemp mkdir chmod ln readlink rm rmdir; do
    cp -- "/usr/bin/${copied_tool}" "${FAKE_BIN}/${copied_tool}"
    chmod 0700 "${FAKE_BIN}/${copied_tool}"
done
printf '%s\n' '# isolated fake RPM configuration' > "${FAKE_BIN}/rpmrc"
printf '%s\n' '# isolated fake RPM macros' > "${FAKE_BIN}/rpm-macros"
chmod 0600 "${FAKE_BIN}/rpmrc" "${FAKE_BIN}/rpm-macros"

cp -- "${FAKE_BIN}/ln" "${FAKE_BIN}/ln.real"
cat > "${FAKE_BIN}/ln" <<'EOF'
#!/bin/bash
set -euo pipefail
destination=${!#}
if [[ "${FAKE_KILL_PARENT_DURING_MARKER_PUBLISH:-0}" == 1 && \
      "${destination}" == "${FAKE_IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending" ]]; then
    kill -KILL "${PPID}"
    exit 137
fi
if [[ "${FAKE_KILL_PARENT_DURING_UNIT_PUBLISH:-0}" == 1 && \
      "${destination}" == "${FAKE_IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service" ]]; then
    kill -KILL "${PPID}"
    exit 137
fi
exec "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/ln.real" "$@"
EOF
chmod 0700 "${FAKE_BIN}/ln" "${FAKE_BIN}/ln.real"

cp -- "${FAKE_BIN}/stat" "${FAKE_BIN}/stat.real"
cat > "${FAKE_BIN}/stat" <<'EOF'
#!/bin/bash
set -euo pipefail
path=${!#}
format=""
previous=""
for argument in "$@"; do
    if [[ "${previous}" == -c ]]; then
        format=${argument}
        break
    fi
    previous=${argument}
done
if [[ -n "${FAKE_STAT_WRONG_OWNER_PATH:-}" && "${path}" == "${FAKE_STAT_WRONG_OWNER_PATH}" ]]; then
    case "${format}" in
        '%F|%u|%g|%a')
            IFS='|' read -r kind _ _ mode < <(
                "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/stat.real" -c '%F|%u|%g|%a' -- "${path}"
            )
            printf '%s|1|1|%s\n' "${kind}" "${mode}"
            exit 0
            ;;
        '%F|%u|%g|%a|%d|%i')
            IFS='|' read -r kind _ _ mode device inode < <(
                "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/stat.real" \
                    -c '%F|%u|%g|%a|%d|%i' -- "${path}"
            )
            printf '%s|1|1|%s|%s|%s\n' "${kind}" "${mode}" "${device}" "${inode}"
            exit 0
            ;;
    esac
fi
if [[ "${FAKE_TRUST_USERNS_ANCESTORS:-0}" == 1 && \
      ("${path}" == / || "${path}" == /tmp) && \
      "${format}" == '%F|%u|%g|%a|%d|%i' ]]; then
    IFS='|' read -r kind _ _ mode device inode < <(
        "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/stat.real" \
            -c '%F|%u|%g|%a|%d|%i' -- "${path}"
    )
    [[ "${path}" != /tmp ]] || mode=755
    printf '%s|0|0|%s|%s|%s\n' "${kind}" "${mode}" "${device}" "${inode}"
    exit 0
fi
exec "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/stat.real" "$@"
EOF
chmod 0700 "${FAKE_BIN}/stat" "${FAKE_BIN}/stat.real"

cat > "${FAKE_BIN}/findmnt" <<'EOF'
#!/bin/sh
set -eu
if [ "${FAKE_FINDMNT_FAIL:-0}" = 1 ]; then
    exit 2
fi
if [ -n "${FAKE_MOUNT_TARGETS:-}" ]; then
    printf '%s\n' "${FAKE_MOUNT_TARGETS}"
fi
EOF
chmod 0700 "${FAKE_BIN}/findmnt"

cat > "${FAKE_BIN}/rpm" <<'EOF'
#!/bin/bash
set -euo pipefail

for forbidden_environment in \
    RPM_CONFIGDIR RPM_ETCCONFIGDIR RPMRC RPM_MACROS RPM_DBPATH RPM_ROOT RPM_TARGET; do
    if [[ -v "${forbidden_environment}" ]]; then
        printf 'unsanitized RPM environment: %s\n' "${forbidden_environment}" >&2
        exit 90
    fi
done

has_argument() {
    local wanted=$1
    shift
    local argument
    for argument in "$@"; do
        [[ "${argument}" == "${wanted}" ]] && return 0
    done
    return 1
}

has_argument_containing() {
    local needle=$1
    shift
    local argument
    for argument in "$@"; do
        [[ "${argument}" == *"${needle}"* ]] && return 0
    done
    return 1
}

argument_after() {
    local wanted=$1
    shift
    local previous="" argument
    for argument in "$@"; do
        if [[ "${previous}" == "${wanted}" ]]; then
            printf '%s\n' "${argument}"
            return 0
        fi
        previous=${argument}
    done
    return 1
}

perform_requested_image_swap() {
    [[ "${FAKE_SWAP_IMAGE_PATH_AFTER_REQUIRES:-0}" == 1 ]] || return 0
    [[ -n "${FAKE_SWAP_PATH:-}" && -n "${FAKE_SWAP_BACKUP:-}" && \
       -n "${FAKE_SWAP_TARGET:-}" ]] || exit 83
    (
        /usr/bin/mv -- "${FAKE_SWAP_PATH}" "${FAKE_SWAP_BACKUP}"
        /usr/bin/ln -s -- "${FAKE_SWAP_TARGET}" "${FAKE_SWAP_PATH}"
    ) &
    attacker_pid=$!
    wait "${attacker_pid}"
}

printf '%s' 'rpm' >> "${FAKE_RPM_LOG}"
for argument in "$@"; do
    printf ' <%s>' "${argument}" >> "${FAKE_RPM_LOG}"
done
printf '\n' >> "${FAKE_RPM_LOG}"

has_argument --noplugins "$@" || {
    printf 'missing --noplugins\n' >&2
    exit 91
}
[[ "$(argument_after --rcfile "$@")" == "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/rpmrc" ]] || {
    printf 'unexpected or missing --rcfile\n' >&2
    exit 89
}
[[ "$(argument_after --macros "$@")" == "${SYSWARDEN_IMAGE_TEST_TOOL_DIR}/rpm-macros" ]] || {
    printf 'unexpected or missing --macros\n' >&2
    exit 88
}
if [[ "${FAKE_NO_NOPLUGINS:-0}" == 1 ]]; then
    printf 'unknown option --noplugins\n' >&2
    exit 92
fi
if has_argument --root "$@"; then
    [[ "$(argument_after --root "$@")" == "${FAKE_IMAGE_ROOT}" ]] || exit 87
    [[ "$(argument_after --dbpath "$@")" == "${FAKE_TARGET_DBPATH}" ]] || {
        printf 'rooted RPM call has the wrong explicit target dbpath\n' >&2
        exit 86
    }
elif has_argument --dbpath "$@"; then
    printf 'unrooted RPM call unexpectedly has a dbpath\n' >&2
    exit 85
fi
if has_argument --version "$@"; then
    printf 'RPM version fake\n'
    exit 0
fi

if has_argument --eval "$@"; then
    printf 'builder RPM dbpath evaluation is forbidden in this test\n' >&2
    exit 84
fi

if has_argument --requires "$@"; then
    printf '%s\n' '/bin/sh' 'nftables' 'cronie' 'rpmlib(CompressedFileNames) <= 3.0.4-1'
    perform_requested_image_swap
    exit 0
fi

if has_argument --queryfile "$@"; then
    queried_path=${!#}
    case "${queried_path}" in
        /usr/lib/systemd/system/crond.service)
            printf 'cronie|%s\n' "${FAKE_CRONIE_FRAGMENT_EVR:-1.7.2-1.el9}"
            ;;
        /usr/sbin/crond)
            printf 'cronie|%s\n' "${FAKE_CRONIE_DAEMON_EVR:-1.7.2-1.el9}"
            ;;
        *)
            exit 1
            ;;
    esac
    exit 0
fi

if has_argument --package "$@" && has_argument_containing FILENAMES "$@"; then
    printf '%s\n' \
        '/opt/syswarden/bin/syswarden-cli|100750|' \
        '/opt/syswarden/bin/syswarden-core|100750|' \
        '/opt/syswarden/bin/syswarden-tui|100750|' \
        '/opt/syswarden/signatures.json|100640|' \
        '/usr/lib/.build-id|40755|' \
        '/usr/lib/.build-id/11|40755|' \
        '/usr/lib/.build-id/11/11111111111111111111111111111111111111|120777|../../../../opt/syswarden/bin/syswarden-cli' \
        '/usr/lib/.build-id/22|40755|' \
        '/usr/lib/.build-id/22/22222222222222222222222222222222222222|120777|../../../../opt/syswarden/bin/syswarden-core' \
        '/usr/lib/.build-id/33|40755|' \
        '/usr/lib/.build-id/33/33333333333333333333333333333333333333|120777|../../../../opt/syswarden/bin/syswarden-tui' \
        '/usr/local/bin/syswarden|120777|/opt/syswarden/bin/syswarden-cli' \
        '/usr/local/bin/syswarden-tui|120777|/opt/syswarden/bin/syswarden-tui'
    if [[ "${FAKE_EXTRA_PAYLOAD_PATH:-0}" == 1 ]]; then
        printf '%s\n' '/etc/cron.d/syswarden|100644|'
    fi
    exit 0
fi

if has_argument --package "$@" && has_argument --queryformat "$@"; then
    if [[ "${FAKE_KILL_PARENT_DURING_METADATA:-0}" == 1 ]]; then
        kill -KILL "${PPID}"
    fi
    printf '%s\n' \
        "${FAKE_RPM_NAME:-syswarden}" \
        "${FAKE_RPM_ARCH:-x86_64}" \
        "${FAKE_RPM_VERSION:-4.03.2}" \
        "${FAKE_RPM_RELEASE:-1}"
    exit 0
fi

if has_argument --all "$@"; then
    printf '%s\n' 'basesystem|x86_64' 'bash|x86_64' 'nftables|x86_64'
    if [[ "${FAKE_PREINSTALLED:-0}" == 1 || \
        -f "${FAKE_IMAGE_ROOT}${FAKE_TARGET_DBPATH}/fake-installed" ]]; then
        printf '%s\n' 'syswarden|x86_64'
    fi
    exit 0
fi

if has_argument --whatprovides "$@"; then
    requirement=${!#}
    if [[ -n "${FAKE_MISSING_REQUIREMENT:-}" && \
        "${requirement}" == "${FAKE_MISSING_REQUIREMENT}" ]]; then
        exit 1
    fi
    printf 'fake-provider-1.x86_64\n'
    exit 0
fi

if has_argument --install "$@"; then
    for forbidden in --nodeps --force --replacepkgs --replacefiles --ignorearch; do
        has_argument "${forbidden}" "$@" && {
            printf 'unsafe RPM option: %s\n' "${forbidden}" >&2
            exit 93
        }
    done
    has_argument --noscripts "$@" || exit 94
    has_argument --notriggers "$@" || exit 95
    root=""
    previous=""
    for argument in "$@"; do
        if [[ "${previous}" == --root ]]; then
            root=${argument}
        fi
        previous=${argument}
    done
    [[ "${root}" == "${FAKE_IMAGE_ROOT}" ]] || exit 96
    package_path=${!#}
    [[ "${package_path}" == "${root}"/.syswarden-image-stage.*/package.*.rpm ]] || exit 97
    if has_argument --test "$@"; then
        [[ "${FAKE_FAIL_TEST_TRANSACTION:-0}" != 1 ]] || exit 98
        exit 0
    fi

    mkdir -p \
        "${root}/opt/syswarden/bin" \
        "${root}/usr/local/bin" \
        "${root}${FAKE_TARGET_DBPATH}"
    for binary in syswarden-cli syswarden-core syswarden-tui; do
        printf 'fake verified payload: %s\n' "${binary}" > "${root}/opt/syswarden/bin/${binary}"
        chmod 0750 "${root}/opt/syswarden/bin/${binary}"
    done
    printf '%s\n' '[]' > "${root}/opt/syswarden/signatures.json"
    chmod 0640 "${root}/opt/syswarden/signatures.json"
    ln -s /opt/syswarden/bin/syswarden-cli "${root}/usr/local/bin/syswarden"
    ln -s /opt/syswarden/bin/syswarden-tui "${root}/usr/local/bin/syswarden-tui"
    printf '%s\n' installed > "${root}${FAKE_TARGET_DBPATH}/fake-installed"
    if [[ "${FAKE_BAD_PAYLOAD_MODE:-0}" == 1 ]]; then
        chmod 0755 "${root}/opt/syswarden/bin/syswarden-cli"
    fi
    if [[ "${FAKE_KILL_PARENT_AFTER_INSTALL:-0}" == 1 ]]; then
        kill -KILL "${PPID}"
    fi
    exit 0
fi

if has_argument --verify "$@"; then
    has_argument --noscript "$@" || exit 99
    [[ "${FAKE_FAIL_VERIFY:-0}" != 1 ]] || exit 100
    exit 0
fi

if has_argument --query "$@" && [[ "${!#}" == syswarden ]]; then
    [[ -f "${FAKE_IMAGE_ROOT}${FAKE_TARGET_DBPATH}/fake-installed" ]] || exit 1
    printf '%s\n' \
        "${FAKE_RPM_NAME:-syswarden}" \
        "${FAKE_RPM_ARCH:-x86_64}" \
        "${FAKE_RPM_VERSION:-4.03.2}" \
        "${FAKE_RPM_RELEASE:-1}"
    exit 0
fi

printf 'unexpected fake rpm invocation\n' >&2
exit 101
EOF
chmod 0700 "${FAKE_BIN}/rpm"

cat > "${FAKE_BIN}/forbidden-command" <<'EOF'
#!/bin/sh
printf 'forbidden image-time command invoked: %s\n' "${0##*/}" >&2
exit 111
EOF
chmod 0700 "${FAKE_BIN}/forbidden-command"

for forbidden_tool in \
    dnf chroot systemctl systemd-run service \
    firewall-cmd ufw nft iptables ip6tables \
    ps pgrep pkill killall crontab rsyslogd \
    sysctl modprobe; do
    ln -s forbidden-command "${FAKE_BIN}/${forbidden_tool}"
done

new_fixture() {
    CASE_DIRECTORY="$(mktemp -d "${TEST_WORKSPACE}/case.XXXXXXXXXX")"
    IMAGE_PARENT="${CASE_DIRECTORY}/image-parent"
    IMAGE_ROOT="${IMAGE_PARENT}/root"
    INPUT_DIRECTORY="${CASE_DIRECTORY}/input"
    INPUT_RPM="${INPUT_DIRECTORY}/package.rpm"
    OUTSIDE_PROBE="${CASE_DIRECTORY}/outside-probe"
    RPM_LOG="${CASE_DIRECTORY}/rpm.calls"
    STDOUT_FILE="${CASE_DIRECTORY}/stdout"
    STDERR_FILE="${CASE_DIRECTORY}/stderr"

    mkdir -m 0700 "${IMAGE_PARENT}"
    mkdir -m 0755 "${IMAGE_ROOT}"
    mkdir -p \
        "${IMAGE_ROOT}/usr/lib/systemd" \
        "${IMAGE_ROOT}/usr/lib/systemd/system" \
        "${IMAGE_ROOT}/usr/bin" \
        "${IMAGE_ROOT}/usr/sbin" \
        "${IMAGE_ROOT}/usr/local" \
        "${IMAGE_ROOT}/etc" \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants" \
        "${IMAGE_ROOT}/var/lib/rpm"
    chmod 0755 \
        "${IMAGE_ROOT}/usr" \
        "${IMAGE_ROOT}/usr/lib" \
        "${IMAGE_ROOT}/usr/lib/systemd" \
        "${IMAGE_ROOT}/usr/lib/systemd/system" \
        "${IMAGE_ROOT}/usr/bin" \
        "${IMAGE_ROOT}/usr/sbin" \
        "${IMAGE_ROOT}/usr/local" \
        "${IMAGE_ROOT}/etc" \
        "${IMAGE_ROOT}/etc/systemd" \
        "${IMAGE_ROOT}/etc/systemd/system" \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants" \
        "${IMAGE_ROOT}/var" \
        "${IMAGE_ROOT}/var/lib" \
        "${IMAGE_ROOT}/var/lib/rpm"
    printf '%s\n' \
        'ID="rocky"' \
        'ID_LIKE="rhel centos fedora"' \
        'VERSION_ID="9.4"' > "${IMAGE_ROOT}/usr/lib/os-release"
    chmod 0644 "${IMAGE_ROOT}/usr/lib/os-release"
    printf '#!/bin/sh\nexit 0\n' > "${IMAGE_ROOT}/usr/lib/systemd/systemd"
    printf '#!/bin/sh\nexit 0\n' > "${IMAGE_ROOT}/usr/bin/rm"
    printf '%s\n' '[Unit]' 'Description=Cronie daemon' > \
        "${IMAGE_ROOT}/usr/lib/systemd/system/crond.service"
    printf '#!/bin/sh\nexit 0\n' > "${IMAGE_ROOT}/usr/sbin/crond"
    chmod 0644 "${IMAGE_ROOT}/usr/lib/systemd/system/crond.service"
    chmod 0755 \
        "${IMAGE_ROOT}/usr/lib/systemd/systemd" \
        "${IMAGE_ROOT}/usr/bin/rm" \
        "${IMAGE_ROOT}/usr/sbin/crond"
    ln -s ../../../../usr/lib/systemd/system/crond.service \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"

    mkdir -m 0700 "${INPUT_DIRECTORY}" "${OUTSIDE_PROBE}"
    printf '%s\n' 'fake local SysWarden RPM bytes' > "${INPUT_RPM}"
    chmod 0644 "${INPUT_RPM}"
    INPUT_SHA256="$(sha256sum "${INPUT_RPM}")"
    INPUT_SHA256=${INPUT_SHA256%% *}
    printf '%s\n' 'must remain unchanged' > "${OUTSIDE_PROBE}/sentinel"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"

    RUN_ROOT=${IMAGE_ROOT}
    RUN_RPM=${INPUT_RPM}
    RUN_SHA256=${INPUT_SHA256}
    RUN_TARGET_DBPATH=/var/lib/rpm
    PREFLIGHT_INCLUDE_RPM_ARGS=0
}

configure_rhel10_rpm_database_layout() {
    printf '%s\n' \
        'ID="rocky"' \
        'ID_LIKE="rhel centos fedora"' \
        'VERSION_ID="10.0"' > "${IMAGE_ROOT}/usr/lib/os-release"
    rmdir "${IMAGE_ROOT}/var/lib/rpm"
    mkdir -p "${IMAGE_ROOT}/usr/lib/sysimage/rpm"
    chmod 0755 \
        "${IMAGE_ROOT}/usr/lib/sysimage" \
        "${IMAGE_ROOT}/usr/lib/sysimage/rpm"
    ln -s ../../usr/lib/sysimage/rpm "${IMAGE_ROOT}/var/lib/rpm"
    RUN_TARGET_DBPATH=/usr/lib/sysimage/rpm
}

run_stage() {
    local -a extra_environment=("$@")
    set +e
    (
        env \
            PATH="${FAKE_BIN}:/usr/bin:/bin" \
            TMPDIR="${OUTSIDE_PROBE}" \
            SYSWARDEN_IMAGE_TEST_TOOL_DIR="${FAKE_BIN}" \
            RPM_CONFIGDIR="${OUTSIDE_PROBE}/hostile-rpm-config" \
            RPM_ETCCONFIGDIR="${OUTSIDE_PROBE}/hostile-rpm-etc" \
            RPMRC="${OUTSIDE_PROBE}/hostile-rpmrc" \
            RPM_MACROS="${OUTSIDE_PROBE}/hostile-macros" \
            RPM_DBPATH="${OUTSIDE_PROBE}/hostile-rpmdb" \
            RPM_ROOT="${OUTSIDE_PROBE}/hostile-root" \
            RPM_TARGET="hostile-target" \
            FAKE_IMAGE_ROOT="${IMAGE_ROOT}" \
            FAKE_TARGET_DBPATH="${RUN_TARGET_DBPATH}" \
            FAKE_RPM_LOG="${RPM_LOG}" \
            FAKE_MOUNT_TARGETS="" \
            FAKE_TRUST_USERNS_ANCESTORS=1 \
            "${extra_environment[@]}" \
            "${STAGE_SCRIPT}" \
            --root "${RUN_ROOT}" \
            --rpm "${RUN_RPM}" \
            --sha256 "${RUN_SHA256}"
    ) > "${STDOUT_FILE}" 2> "${STDERR_FILE}"
    LAST_STATUS=$?
    set -e
}

run_root_preflight() {
    local -a extra_environment=("$@")
    local -a stage_arguments=(--preflight-root --root "${RUN_ROOT}")
    if ((PREFLIGHT_INCLUDE_RPM_ARGS == 1)); then
        stage_arguments+=(--rpm "${RUN_RPM}" --sha256 "${RUN_SHA256}")
    fi
    set +e
    (
        env \
            PATH="${FAKE_BIN}:/usr/bin:/bin" \
            TMPDIR="${OUTSIDE_PROBE}" \
            SYSWARDEN_IMAGE_TEST_TOOL_DIR="${FAKE_BIN}" \
            RPM_CONFIGDIR="${OUTSIDE_PROBE}/hostile-rpm-config" \
            RPM_ETCCONFIGDIR="${OUTSIDE_PROBE}/hostile-rpm-etc" \
            RPMRC="${OUTSIDE_PROBE}/hostile-rpmrc" \
            RPM_MACROS="${OUTSIDE_PROBE}/hostile-macros" \
            RPM_DBPATH="${OUTSIDE_PROBE}/hostile-rpmdb" \
            RPM_ROOT="${OUTSIDE_PROBE}/hostile-root" \
            RPM_TARGET="hostile-target" \
            FAKE_MOUNT_TARGETS="" \
            FAKE_TRUST_USERNS_ANCESTORS=1 \
            "${extra_environment[@]}" \
            "${STAGE_SCRIPT}" "${stage_arguments[@]}"
    ) > "${STDOUT_FILE}" 2> "${STDERR_FILE}"
    LAST_STATUS=$?
    set -e
}

require_success() {
    if ((LAST_STATUS != 0)); then
        printf 'Expected success, got %d\n' "${LAST_STATUS}" >&2
        sed -n '1,160p' "${STDERR_FILE}" >&2
        return 1
    fi
}

require_failure() {
    if ((LAST_STATUS == 0)); then
        printf 'Expected failure, got success\n' >&2
        sed -n '1,160p' "${STDOUT_FILE}" >&2
        return 1
    fi
}

assert_outside_unchanged() {
    local after
    after="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    [[ "${after}" == "${OUTSIDE_BEFORE}" ]] || {
        printf 'A write escaped into TMPDIR/outside probe\n' >&2
        return 1
    }
}

test_static_staging_contract() {
    local forbidden_pattern install_count

    bash -n "${STAGE_SCRIPT}" "${BASH_SOURCE[0]}"
    for forbidden_pattern in \
        '(^|[^[:alnum:]_-])dnf([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])chroot([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])systemctl([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])systemd-run([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])firewall-cmd([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])ufw([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])iptables([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])ip6tables([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])nft([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])pgrep([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])pkill([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])killall([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])rsyslogd([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])sysctl([^[:alnum:]_-]|$)' \
        '(^|[^[:alnum:]_-])modprobe([^[:alnum:]_-]|$)' \
        'grep[[:space:]]+-[^[:space:]]*R' \
        'SYSWARDEN_CORE_FIREWALL_BACKEND'; do
        if grep -Eq -- "${forbidden_pattern}" "${STAGE_SCRIPT}"; then
            printf 'Forbidden staging-time construct matched: %s\n' "${forbidden_pattern}" >&2
            return 1
        fi
    done
    for forbidden_option in \
        --nodeps --force --replacepkgs --replacefiles --ignorearch; do
        if grep -Fq -- "${forbidden_option}" "${STAGE_SCRIPT}"; then
            printf 'Forbidden RPM option matched: %s\n' "${forbidden_option}" >&2
            return 1
        fi
    done
    install_count="$(grep -o -- '--install' "${STAGE_SCRIPT}" | wc -l)"
    [[ "${install_count}" == 2 ]]
    # These are literal source-code contracts, not test-shell expansions.
    # shellcheck disable=SC2016
    grep -Fq -- '--install --test --noscripts --notriggers -- "${STAGING_RPM}"' \
        "${STAGE_SCRIPT}"
    # shellcheck disable=SC2016
    grep -Fq -- '--install --noscripts --notriggers -- "${STAGING_RPM}"' \
        "${STAGE_SCRIPT}"
    grep -Fq -- '--verify --noscript syswarden' "${STAGE_SCRIPT}"
    # shellcheck disable=SC2016
    grep -Fq -- '--dbpath "${TARGET_RPM_DBPATH}"' "${STAGE_SCRIPT}"
    if grep -Fq -- '--eval' "${STAGE_SCRIPT}"; then
        return 1
    fi
    grep -Fq 'Environment=SYSWARDEN_PKG_INSTALL=1' "${STAGE_SCRIPT}"
    if grep -Eq 'Environment=.*FIREWALL_BACKEND' "${STAGE_SCRIPT}"; then
        return 1
    fi
}

test_root_only_preflight_is_read_only_and_independent() {
    local image_before image_after

    new_fixture
    rm -f -- \
        "${IMAGE_ROOT}/usr/lib/systemd/systemd" \
        "${IMAGE_ROOT}/usr/lib/systemd/system/crond.service" \
        "${IMAGE_ROOT}/usr/bin/rm" \
        "${IMAGE_ROOT}/usr/sbin/crond" \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"
    rmdir -- "${IMAGE_ROOT}/var/lib/rpm"
    image_before="$(find -P "${IMAGE_ROOT}" -printf '%P|%y|%m|%s\n' | sort)"
    run_root_preflight
    require_success
    grep -Fq 'image root preflight passed' "${STDOUT_FILE}"
    image_after="$(find -P "${IMAGE_ROOT}" -printf '%P|%y|%m|%s\n' | sort)"
    [[ "${image_after}" == "${image_before}" ]]
    [[ ! -e "${RPM_LOG}" ]]
    assert_outside_unchanged

    new_fixture
    RUN_ROOT="${IMAGE_ROOT}/etc"
    run_root_preflight
    require_failure
    grep -Fq 'lacks required extracted-root directory' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    rm -f -- "${IMAGE_ROOT}/usr/lib/os-release"
    run_root_preflight
    require_failure
    grep -Fq 'requires exact /usr/lib/os-release metadata' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    printf '%s\n' 'ID="rocky"' 'ID_LIKE="rhel centos"' 'VERSION_ID="8.10"' \
        > "${IMAGE_ROOT}/usr/lib/os-release"
    run_root_preflight
    require_failure
    grep -Fq 'major version 9 or newer is required' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    PREFLIGHT_INCLUDE_RPM_ARGS=1
    run_root_preflight
    require_failure
    grep -Fq 'mutually exclusive with --rpm and --sha256' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    RUN_ROOT=/
    run_root_preflight
    require_failure
    grep -Fq "image root '/' is never accepted" "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    ln -s "${IMAGE_ROOT}" "${CASE_DIRECTORY}/root-link"
    RUN_ROOT="${CASE_DIRECTORY}/root-link"
    run_root_preflight
    require_failure
    grep -Fq 'symlink component' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    run_root_preflight "FAKE_MOUNT_TARGETS=${IMAGE_ROOT}/run"
    require_failure
    grep -Fq 'image root or a descendant is mounted' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]

    new_fixture
    mkdir -p "${IMAGE_ROOT}/run/systemd/system"
    run_root_preflight
    require_failure
    grep -Fq 'live or ambiguous runtime path' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]
}

test_full_ancestor_contract_rejects_writable_and_nonroot_parents() {
    new_fixture
    chmod 0777 "${CASE_DIRECTORY}"
    run_root_preflight
    require_failure
    grep -Fq 'image root ancestor is group/world writable' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]
    assert_outside_unchanged

    new_fixture
    run_root_preflight "FAKE_STAT_WRONG_OWNER_PATH=${CASE_DIRECTORY}"
    require_failure
    grep -Fq 'image root ancestor is not root owned' "${STDERR_FILE}"
    [[ ! -e "${RPM_LOG}" ]]
    assert_outside_unchanged
}

assert_no_install_or_publication_after_swap() {
    if [[ -e "${RPM_LOG}" ]] && grep -Fq '<--install>' "${RPM_LOG}"; then
        printf 'An RPM install call crossed the swapped-root boundary\n' >&2
        return 1
    fi
    if find -P "${CASE_DIRECTORY}" -xdev \
        \( -name .syswarden-image-transaction \
           -o -name firstboot.pending \
           -o -name syswarden-image-firstboot.service \) \
        -print -quit | grep -q .; then
        printf 'An extension publication crossed the swapped-root boundary\n' >&2
        return 1
    fi
    assert_outside_unchanged
}

test_concurrent_parent_and_root_swap_fail_before_install_or_publication() {
    local swap_backup swap_target

    new_fixture
    swap_backup="${IMAGE_ROOT}.attacker-original"
    swap_target="${OUTSIDE_PROBE}/root-redirect"
    mkdir -m 0700 -- "${swap_target}"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage \
        FAKE_SWAP_IMAGE_PATH_AFTER_REQUIRES=1 \
        "FAKE_SWAP_PATH=${IMAGE_ROOT}" \
        "FAKE_SWAP_BACKUP=${swap_backup}" \
        "FAKE_SWAP_TARGET=${swap_target}"
    require_failure
    grep -Eq 'image root ancestor may not be a symlink|image root identity changed' \
        "${STDERR_FILE}" || {
        sed -n '1,160p' "${STDERR_FILE}" >&2
        return 1
    }
    [[ -d "${swap_backup}" && -L "${IMAGE_ROOT}" ]] || {
        printf 'Root swap did not leave the expected fail-closed shape\n' >&2
        return 1
    }
    assert_no_install_or_publication_after_swap

    new_fixture
    swap_backup="${IMAGE_PARENT}.attacker-original"
    swap_target="${OUTSIDE_PROBE}/parent-redirect"
    mkdir -m 0700 -- "${swap_target}"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage \
        FAKE_SWAP_IMAGE_PATH_AFTER_REQUIRES=1 \
        "FAKE_SWAP_PATH=${IMAGE_PARENT}" \
        "FAKE_SWAP_BACKUP=${swap_backup}" \
        "FAKE_SWAP_TARGET=${swap_target}"
    require_failure
    grep -Eq 'image root ancestor may not be a symlink|image root identity changed' \
        "${STDERR_FILE}" || {
        sed -n '1,160p' "${STDERR_FILE}" >&2
        return 1
    }
    [[ -d "${swap_backup}" && -L "${IMAGE_PARENT}" ]] || {
        printf 'Parent swap did not leave the expected fail-closed shape\n' >&2
        return 1
    }
    assert_no_install_or_publication_after_swap
}

test_success_contract_and_ancestor_mount() {
    new_fixture
    run_stage "FAKE_MOUNT_TARGETS=${IMAGE_ROOT%/*}"
    require_success

    unit="${IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service"
    marker="${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending"
    link="${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service"
    [[ -f "${unit}" && ! -L "${unit}" && "$(stat -c '%a' "${unit}")" == 644 ]]
    [[ -f "${marker}" && ! -L "${marker}" && "$(stat -c '%a' "${marker}")" == 600 ]]
    [[ -L "${link}" && "$(readlink "${link}")" == ../syswarden-image-firstboot.service ]]
    grep -Fxq 'ConditionPathExists=/var/lib/syswarden/image/firstboot.pending' "${unit}"
    grep -Fxq 'Requires=crond.service' "${unit}"
    grep -Fxq 'After=network-online.target firewalld.service crond.service' "${unit}"
    grep -Fxq 'Environment=SYSWARDEN_PKG_INSTALL=1' "${unit}"
    if grep -Fq 'SYSWARDEN_CORE_FIREWALL_BACKEND' "${unit}"; then
        return 1
    fi
    if grep -Eq '^(Before|After|Wants|Requires)=.*syswarden-(core|firewall)' "${unit}"; then
        return 1
    fi

    install_line=$(grep -nFx 'ExecStart=/opt/syswarden/bin/syswarden-cli install' "${unit}" | cut -d: -f1)
    reload_line=$(grep -nFx 'ExecStart=/opt/syswarden/bin/syswarden-cli reload' "${unit}" | cut -d: -f1)
    marker_line=$(grep -nFx 'ExecStartPost=/usr/bin/rm -f /var/lib/syswarden/image/firstboot.pending' "${unit}" | cut -d: -f1)
    ((install_line < reload_line && reload_line < marker_line))

    grep -Fq '<--install> <--test> <--noscripts> <--notriggers>' "${RPM_LOG}"
    grep -Fq '<--install> <--noscripts> <--notriggers>' "${RPM_LOG}"
    grep -Fq '<--verify> <--noscript> <syswarden>' "${RPM_LOG}"
    if grep -Eq '<--(nodeps|force|replacepkgs|replacefiles|ignorearch)>' "${RPM_LOG}"; then
        return 1
    fi
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/syswarden-core.service" ]]
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/syswarden-firewall.service" ]]
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    if compgen -G "${IMAGE_ROOT}/.syswarden-image-stage.*" >/dev/null; then
        return 1
    fi
    assert_outside_unchanged
}

test_offline_crond_provider_is_exact_and_enabled() {
    new_fixture
    rm "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"
    run_stage
    require_failure
    grep -Fq 'offline image requires enabled crond.service' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]

    new_fixture
    rm "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"
    ln -s /etc/systemd/system/operator-crond.service \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"
    run_stage
    require_failure
    grep -Fq 'does not target the packaged crond.service unit' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]

    new_fixture
    run_stage FAKE_CRONIE_DAEMON_EVR=1.7.2-2.el9
    require_failure
    grep -Fq 'Cronie unit and daemon RPM provenance disagree' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
}

test_exact_mount_is_rejected() {
    new_fixture
    run_stage "FAKE_MOUNT_TARGETS=${IMAGE_ROOT}"
    require_failure
    grep -Fq 'image root or a descendant is mounted' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
    assert_outside_unchanged
}

test_descendant_bind_mount_is_rejected() {
    new_fixture
    run_stage "FAKE_MOUNT_TARGETS=${IMAGE_ROOT}/run"
    require_failure
    grep -Fq 'image root or a descendant is mounted' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
}

test_live_runtime_is_rejected() {
    new_fixture
    mkdir -p "${IMAGE_ROOT}/run/systemd/system"
    run_stage
    require_failure
    grep -Fq 'live or ambiguous runtime path' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
}

test_root_and_rpm_symlinks_are_rejected() {
    new_fixture
    real_root=${IMAGE_ROOT}
    ln -s "${real_root}" "${CASE_DIRECTORY}/root-link"
    RUN_ROOT="${CASE_DIRECTORY}/root-link"
    run_stage
    require_failure
    grep -Fq 'symlink component' "${STDERR_FILE}"

    new_fixture
    ln -s "${INPUT_RPM}" "${INPUT_DIRECTORY}/package-link.rpm"
    RUN_RPM="${INPUT_DIRECTORY}/package-link.rpm"
    run_stage
    require_failure
    grep -Fq 'symlink component' "${STDERR_FILE}"
}

test_unsafe_modes_are_rejected() {
    new_fixture
    chmod 0666 "${INPUT_RPM}"
    run_stage
    require_failure
    grep -Fq 'group/world writable' "${STDERR_FILE}"

    new_fixture
    chmod 0777 "${IMAGE_ROOT}"
    run_stage
    require_failure
    grep -Fq 'group/world writable' "${STDERR_FILE}"

    new_fixture
    run_stage "FAKE_STAT_WRONG_OWNER_PATH=${INPUT_RPM}"
    require_failure
    grep -Fq 'RPM source is not root owned' "${STDERR_FILE}"
}

test_os_family_and_major_are_rejected() {
    new_fixture
    printf '%s\n' 'ID="debian"' 'ID_LIKE="debian"' 'VERSION_ID="13"' \
        > "${IMAGE_ROOT}/usr/lib/os-release"
    run_stage
    require_failure
    grep -Fq 'not in the supported RHEL family' "${STDERR_FILE}"

    new_fixture
    printf '%s\n' 'ID="rocky"' 'ID_LIKE="rhel centos"' 'VERSION_ID="8.10"' \
        > "${IMAGE_ROOT}/usr/lib/os-release"
    run_stage
    require_failure
    grep -Fq 'major version 9 or newer is required' "${STDERR_FILE}"
}

test_target_rpm_database_layout_is_explicit_and_versioned() {
    new_fixture
    run_stage
    require_success
    grep -Fq "<--root> <${IMAGE_ROOT}> <--dbpath> </var/lib/rpm>" "${RPM_LOG}"
    if grep -Fq '<--eval>' "${RPM_LOG}"; then
        return 1
    fi

    new_fixture
    configure_rhel10_rpm_database_layout
    run_stage
    require_success
    grep -Fq "<--root> <${IMAGE_ROOT}> <--dbpath> </usr/lib/sysimage/rpm>" "${RPM_LOG}"
    if grep -Fq '<--eval>' "${RPM_LOG}"; then
        return 1
    fi

    new_fixture
    mkdir -p "${IMAGE_ROOT}/usr/lib/sysimage/rpm"
    run_stage
    require_failure
    grep -Fq 'RHEL-family 9 image has an ambiguous relocated RPM database path' \
        "${STDERR_FILE}"

    new_fixture
    configure_rhel10_rpm_database_layout
    rm "${IMAGE_ROOT}/var/lib/rpm"
    mkdir "${IMAGE_ROOT}/var/lib/rpm"
    run_stage
    require_failure
    grep -Fq 'RPM compatibility database link is not a symlink' "${STDERR_FILE}"
}

test_existing_state_and_package_are_rejected() {
    new_fixture
    mkdir -p "${IMAGE_ROOT}/etc/syswarden"
    run_stage
    require_failure
    grep -Fq 'fresh-image staging refuses existing SysWarden path' "${STDERR_FILE}"

    new_fixture
    run_stage FAKE_PREINSTALLED=1
    require_failure
    grep -Fq 'fresh-image staging refuses an installed SysWarden package' "${STDERR_FILE}"
}

test_cron_scan_refuses_nested_symlinks_and_special_files() {
    new_fixture
    mkdir -p "${IMAGE_ROOT}/etc/cron.d"
    ln -s "${OUTSIDE_PROBE}/sentinel" "${IMAGE_ROOT}/etc/cron.d/redirect"
    run_stage
    require_failure
    grep -Fq 'refusing symlinked cron state' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged

    new_fixture
    mkdir -p "${IMAGE_ROOT}/etc/cron.d"
    mkfifo "${IMAGE_ROOT}/etc/cron.d/untrusted-fifo"
    run_stage
    require_failure
    grep -Fq 'refusing non-regular cron state' "${STDERR_FILE}"
    if [[ -e "${RPM_LOG}" ]] && grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
}

test_hash_and_dependency_fail_closed() {
    new_fixture
    RUN_SHA256="${INPUT_SHA256%?}0"
    [[ "${RUN_SHA256}" != "${INPUT_SHA256}" ]] || RUN_SHA256="${INPUT_SHA256%?}1"
    run_stage
    require_failure
    grep -Fq 'RPM SHA-256 does not match' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]

    new_fixture
    run_stage FAKE_MISSING_REQUIREMENT=nftables
    require_failure
    grep -Fq 'missing required RPM capability: nftables' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
}

test_rpm_plugin_isolation_fails_cleanly() {
    new_fixture
    run_stage FAKE_NO_NOPLUGINS=1
    require_failure
    grep -Fq 'does not support required --noplugins isolation' "${STDERR_FILE}"
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]
}

test_tool_boundary_rejects_unsafe_override_and_ignores_ambient_path() {
    new_fixture
    hostile_path="${CASE_DIRECTORY}/hostile-path"
    mkdir -m 0700 "${hostile_path}"
    printf '%s\n' '#!/bin/sh' \
        "printf invoked > '${OUTSIDE_PROBE}/ambient-rpm-ran'" \
        'exit 127' > "${hostile_path}/rpm"
    chmod 0700 "${hostile_path}/rpm"
    run_stage "PATH=${hostile_path}:${FAKE_BIN}:/usr/bin:/bin"
    require_success
    [[ ! -e "${OUTSIDE_PROBE}/ambient-rpm-ran" ]]

    new_fixture
    unsafe_tools="${CASE_DIRECTORY}/unsafe-tools"
    cp -a -- "${FAKE_BIN}" "${unsafe_tools}"
    chmod 0722 "${unsafe_tools}/rpm"
    run_stage "SYSWARDEN_IMAGE_TEST_TOOL_DIR=${unsafe_tools}"
    require_failure
    grep -Fq 'required tool is group/world writable' "${STDERR_FILE}"
    if [[ -e "${RPM_LOG}" ]] && grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
}

test_payload_mode_is_reverified() {
    new_fixture
    run_stage FAKE_BAD_PAYLOAD_MODE=1
    require_failure
    grep -Fq 'expected 750' "${STDERR_FILE}"
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/syswarden-image-firstboot.service" ]]
}

test_post_install_failure_resumes_without_reinstall() {
    new_fixture
    run_stage FAKE_FAIL_VERIFY=1
    require_failure
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    [[ -f "${IMAGE_ROOT}/var/lib/rpm/fake-installed" ]]
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]

    run_stage
    require_success
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    [[ -f "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending" ]]
    [[ -L "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]
    install_calls=$(grep -c '<--install>' "${RPM_LOG}")
    [[ "${install_calls}" == 2 ]]
}

test_pretransaction_interruption_retires_only_exact_snapshot() {
    new_fixture
    run_stage FAKE_KILL_PARENT_DURING_METADATA=1
    require_failure
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    compgen -G "${IMAGE_ROOT}/.syswarden-image-stage.*" >/dev/null
    [[ ! -e "${IMAGE_ROOT}/opt/syswarden" ]]

    run_stage
    require_success
    if compgen -G "${IMAGE_ROOT}/.syswarden-image-stage.*" >/dev/null; then
        return 1
    fi
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    install_calls=$(grep -c '<--install>' "${RPM_LOG}")
    [[ "${install_calls}" == 2 ]]
}

test_abrupt_interruption_resumes_and_retires_snapshot() {
    new_fixture
    run_stage FAKE_KILL_PARENT_AFTER_INSTALL=1
    require_failure
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    [[ -f "${IMAGE_ROOT}/var/lib/rpm/fake-installed" ]]
    compgen -G "${IMAGE_ROOT}/.syswarden-image-stage.*" >/dev/null

    run_stage
    require_success
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    if compgen -G "${IMAGE_ROOT}/.syswarden-image-stage.*" >/dev/null; then
        return 1
    fi
    [[ -f "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending" ]]
    install_calls=$(grep -c '<--install>' "${RPM_LOG}")
    [[ "${install_calls}" == 2 ]]
}

test_publication_interruptions_resume_without_reinstall() {
    new_fixture
    run_stage FAKE_KILL_PARENT_DURING_MARKER_PUBLISH=1
    require_failure
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    compgen -G "${IMAGE_ROOT}/var/lib/syswarden/image/.firstboot.pending.*" >/dev/null
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]

    run_stage
    require_success
    if compgen -G "${IMAGE_ROOT}/var/lib/syswarden/image/.firstboot.pending.*" >/dev/null; then
        return 1
    fi
    [[ -f "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending" ]]
    [[ -L "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]
    install_calls=$(grep -c '<--install>' "${RPM_LOG}")
    [[ "${install_calls}" == 2 ]]

    new_fixture
    run_stage FAKE_KILL_PARENT_DURING_UNIT_PUBLISH=1
    require_failure
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
    [[ -f "${IMAGE_ROOT}/var/lib/syswarden/image/firstboot.pending" ]]
    compgen -G "${IMAGE_ROOT}/etc/systemd/system/.syswarden-image-firstboot.service.*" >/dev/null
    [[ ! -e "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]

    run_stage
    require_success
    if compgen -G "${IMAGE_ROOT}/etc/systemd/system/.syswarden-image-firstboot.service.*" >/dev/null; then
        return 1
    fi
    [[ -L "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service" ]]
    install_calls=$(grep -c '<--install>' "${RPM_LOG}")
    [[ "${install_calls}" == 2 ]]
}

test_modified_recovery_state_fails_closed() {
    new_fixture
    run_stage FAKE_FAIL_VERIFY=1
    require_failure
    printf '%s\n' tampered > "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"
    chmod 0755 "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"
    run_stage
    require_failure
    grep -Eq 'verification failed|expected 750' "${STDERR_FILE}"
    [[ -f "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
}

test_destination_symlink_never_writes_outside_root() {
    new_fixture
    mkdir -m 0700 "${OUTSIDE_PROBE}/redirect"
    rm -- "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/crond.service"
    rmdir -- \
        "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants" \
        "${IMAGE_ROOT}/etc/systemd/system" \
        "${IMAGE_ROOT}/etc/systemd"
    rmdir -- "${IMAGE_ROOT}/etc"
    ln -s "${OUTSIDE_PROBE}/redirect" "${IMAGE_ROOT}/etc"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Eq 'first-boot unit parent contains a symlink|symlinked image directory' \
        "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged
    [[ ! -e "${OUTSIDE_PROBE}/redirect/systemd" ]]

    new_fixture
    mkdir -m 0700 "${OUTSIDE_PROBE}/snapshot-redirect"
    printf '%s\n' 'outside snapshot content' \
        > "${OUTSIDE_PROBE}/snapshot-redirect/package.AAAAAAAAAA.rpm"
    ln -s "${OUTSIDE_PROBE}/snapshot-redirect" \
        "${IMAGE_ROOT}/.syswarden-image-stage.AAAAAAAAAA"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Fq 'orphaned RPM snapshot directory may not be a symlink' "${STDERR_FILE}"
    assert_outside_unchanged
    [[ -f "${OUTSIDE_PROBE}/snapshot-redirect/package.AAAAAAAAAA.rpm" ]]
}

test_payload_parent_symlinks_fail_before_rpm_install() {
    new_fixture
    mkdir -m 0700 "${OUTSIDE_PROBE}/opt-redirect"
    ln -s "${OUTSIDE_PROBE}/opt-redirect" "${IMAGE_ROOT}/opt"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Fq 'RPM payload parent contains a symlink' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged
    [[ ! -e "${OUTSIDE_PROBE}/opt-redirect/syswarden" ]]

    new_fixture
    mkdir -m 0700 "${OUTSIDE_PROBE}/command-redirect"
    ln -s "${OUTSIDE_PROBE}/command-redirect" "${IMAGE_ROOT}/usr/local/bin"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Fq 'RPM command-link parent contains a symlink' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged
    [[ ! -e "${OUTSIDE_PROBE}/command-redirect/syswarden" ]]
}

test_rpm_database_redirect_and_payload_inventory_fail_closed() {
    new_fixture
    mkdir -m 0700 "${OUTSIDE_PROBE}/rpmdb-redirect"
    rmdir "${IMAGE_ROOT}/var/lib/rpm"
    ln -s "${OUTSIDE_PROBE}/rpmdb-redirect" "${IMAGE_ROOT}/var/lib/rpm"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Eq 'RPM database path contains a symlink|RPM database is not a regular directory' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged

    new_fixture
    printf '%s\n' 'outside rpm database inode' > "${OUTSIDE_PROBE}/rpmdb-hardlink-target"
    ln "${OUTSIDE_PROBE}/rpmdb-hardlink-target" \
        "${IMAGE_ROOT}/var/lib/rpm/rpmdb.sqlite"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Fq 'RPM database file must not be hard-linked' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged

    new_fixture
    configure_rhel10_rpm_database_layout
    mkdir -m 0700 "${OUTSIDE_PROBE}/rpmdb10-redirect"
    rmdir "${IMAGE_ROOT}/usr/lib/sysimage/rpm"
    ln -s "${OUTSIDE_PROBE}/rpmdb10-redirect" \
        "${IMAGE_ROOT}/usr/lib/sysimage/rpm"
    OUTSIDE_BEFORE="$(find "${OUTSIDE_PROBE}" -mindepth 1 -printf '%P|%y|%m|%s\n' | sort)"
    run_stage
    require_failure
    grep -Eq 'RPM database path contains a symlink|RPM database is not a regular directory' \
        "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    assert_outside_unchanged

    new_fixture
    run_stage FAKE_EXTRA_PAYLOAD_PATH=1
    require_failure
    grep -Fq 'unexpected payload path' "${STDERR_FILE}"
    if grep -Fq '<--install>' "${RPM_LOG}"; then
        return 1
    fi
    [[ ! -e "${IMAGE_ROOT}/.syswarden-image-transaction" ]]
}

run_test() {
    local name=$1
    local function_name=$2
    local status
    set +e
    (set -e; "${function_name}")
    status=$?
    set -e
    if ((status == 0)); then
        printf 'ok - %s\n' "${name}"
        ((PASSED += 1))
    else
        printf 'not ok - %s\n' "${name}" >&2
        ((FAILED += 1))
    fi
}

bash -n "${STAGE_SCRIPT}"

run_test 'static no-execution and exact RPM transaction contract' test_static_staging_contract
run_test 'read-only root preflight and argument boundary' test_root_only_preflight_is_read_only_and_independent
run_test 'full protected image-root ancestor contract' test_full_ancestor_contract_rejects_writable_and_nonroot_parents
run_test 'concurrent parent and root swap fail closed' test_concurrent_parent_and_root_swap_fail_before_install_or_publication
run_test 'success contract, first-boot order, and ancestor mount' test_success_contract_and_ancestor_mount
run_test 'exact image-root mount refusal' test_exact_mount_is_rejected
run_test 'descendant bind-mount refusal' test_descendant_bind_mount_is_rejected
run_test 'live runtime refusal' test_live_runtime_is_rejected
run_test 'symlink input refusal' test_root_and_rpm_symlinks_are_rejected
run_test 'unsafe mode refusal' test_unsafe_modes_are_rejected
run_test 'RHEL-family and version boundary' test_os_family_and_major_are_rejected
run_test 'versioned target RPM database layout and explicit dbpath' test_target_rpm_database_layout_is_explicit_and_versioned
run_test 'fresh-image-only package and state boundary' test_existing_state_and_package_are_rejected
run_test 'bounded cron scan rejects nested links and special files' test_cron_scan_refuses_nested_symlinks_and_special_files
run_test 'SHA-256 and dependency boundary' test_hash_and_dependency_fail_closed
run_test 'offline Cronie provider and first-boot boundary' test_offline_crond_provider_is_exact_and_enabled
run_test 'RPM plugin isolation support boundary' test_rpm_plugin_isolation_fails_cleanly
run_test 'trusted tool and sanitized RPM environment boundary' test_tool_boundary_rejects_unsafe_override_and_ignores_ambient_path
run_test 'installed payload mode re-attestation' test_payload_mode_is_reverified
run_test 'journaled post-install resume without reinstall' test_post_install_failure_resumes_without_reinstall
run_test 'pre-transaction interruption retires only exact snapshot' test_pretransaction_interruption_retires_only_exact_snapshot
run_test 'abrupt interruption resume and snapshot retirement' test_abrupt_interruption_resumes_and_retires_snapshot
run_test 'publication interruptions resume without reinstall' test_publication_interruptions_resume_without_reinstall
run_test 'modified recovery state fails closed' test_modified_recovery_state_fails_closed
run_test 'destination symlink cannot redirect a write' test_destination_symlink_never_writes_outside_root
run_test 'payload parent symlinks fail before RPM install' test_payload_parent_symlinks_fail_before_rpm_install
run_test 'RPM database redirect and payload allowlist boundary' test_rpm_database_redirect_and_payload_inventory_fail_closed

printf '%d passed, %d failed\n' "${PASSED}" "${FAILED}"
((FAILED == 0))
