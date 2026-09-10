#!/bin/bash

set -euo pipefail
umask 077
export LC_ALL=C

TEST_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
EXTENSION_DIRECTORY="$(CDPATH='' cd -- "${TEST_DIRECTORY}/.." && pwd -P)"
TEST_WORKSPACE="$(mktemp -d /tmp/syswarden-rhel-profile-rpm-test.XXXXXXXXXX)"
PROFILE_STAGE="${TEST_WORKSPACE}/profile"
PACKAGE_DIRECTORY="${TEST_WORKSPACE}/package"
PACKAGE_PATH="${PACKAGE_DIRECTORY}/syswarden-4.10.0-1.rhelpo.x86_64.rpm"
STANDARD_PACKAGE_PATH="${PACKAGE_DIRECTORY}/syswarden-4.04.3-1.x86_64.rpm"
RPM_SCRIPTLETS="${TEST_WORKSPACE}/rpm-scriptlets"
IMAGE_ROOT="${TEST_WORKSPACE}/image-root"
CHROOT_ROOT="${TEST_WORKSPACE}/rpm-chroot"
CLEAN_CHROOT_ROOT="${TEST_WORKSPACE}/clean-rpm-chroot"
STANDARD_STAGE="${TEST_WORKSPACE}/standard-stage"

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    case "${TEST_WORKSPACE}" in
        /tmp/syswarden-rhel-profile-rpm-test.*)
            if [ "${RPM_ROOT_MODE:-}" = user-namespace ]; then
                for root in "${CHROOT_ROOT}" "${CLEAN_CHROOT_ROOT}"; do
                    if [ -d "${root}/usr/lib" ] && [ ! -L "${root}/usr/lib" ]; then
                        chmod u+w -- "${root}/usr/lib" || status=1
                    fi
                done
            fi
            if [ "${RPM_ROOT_MODE:-}" = sudo ]; then
                for root in "${CHROOT_ROOT}" "${CLEAN_CHROOT_ROOT}"; do
                    if [ -d "${root}" ]; then
                        sudo -n rm -rf -- "${root}" || status=1
                    fi
                done
            fi
            rm -rf -- "${TEST_WORKSPACE}"
            ;;
        *)
            printf '%s\n' 'Refusing unexpected RPM profile test cleanup path.' >&2
            status=1
            ;;
    esac
    exit "${status}"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(fpm --version)" == 1.17.0 ]]
rpm --version >/dev/null
systemctl --version >/dev/null
systemd-analyze --version >/dev/null
unshare --version >/dev/null

RPM_ROOT_MODE=user-namespace
RPM_ROOT_COMMAND=(unshare -Ur rpm)
if ! unshare -Ur true >/dev/null 2>&1; then
    command -v sudo >/dev/null
    sudo -n true
    RPM_ROOT_MODE=sudo
    RPM_ROOT_COMMAND=(sudo -n rpm)
fi

chroot_admin() {
    if [ "${RPM_ROOT_MODE}" = sudo ]; then
        sudo -n "$@"
        return
    fi
    "$@"
}

python3 "${EXTENSION_DIRECTORY}/stage.py" \
    --enable-rhel-package-owned-profile \
    --output "${PROFILE_STAGE}"
mkdir -m 0700 "${PACKAGE_DIRECTORY}" "${RPM_SCRIPTLETS}"

prepare_rpm_scriptlet() {
    local source="$1"
    local destination="$2"
    [[ -f "${source}" && ! -L "${source}" ]]
    LC_ALL=C sed 's/%/%%/g' -- "${source}" > "${destination}"
    chmod 0700 "${destination}"
    [[ -f "${destination}" && ! -L "${destination}" ]]
    cmp -s \
        <(LC_ALL=C sed 's/%%/%/g' -- "${destination}") \
        "${source}"
}

for scriptlet in pre-install post-install pre-uninstall post-uninstall; do
    prepare_rpm_scriptlet \
        "${PROFILE_STAGE}/rpm-scriptlets/${scriptlet}.sh" \
        "${RPM_SCRIPTLETS}/${scriptlet}.sh"
done
grep -R -F -q '%s' "${PROFILE_STAGE}/rpm-scriptlets"
grep -R -F -q '%%s' "${RPM_SCRIPTLETS}"

install -d -m 0755 \
    "${IMAGE_ROOT}/usr/lib/systemd/system" \
    "${IMAGE_ROOT}/usr/lib/systemd/system-preset" \
    "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants" \
    "${IMAGE_ROOT}/opt/syswarden/bin"
cp "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-core.service" \
    "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-firewall.service" \
    "${IMAGE_ROOT}/usr/lib/systemd/system/"
cp "${PROFILE_STAGE}/payload/usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset" \
    "${IMAGE_ROOT}/usr/lib/systemd/system-preset/"
printf '%s\n' '[Unit]' 'Description=Offline target fixture' > \
    "${IMAGE_ROOT}/usr/lib/systemd/system/multi-user.target"
for dependency_unit in \
    network.target \
    network-online.target \
    rsyslog.service \
    cron.service \
    crond.service; do
    printf '%s\n' '[Unit]' 'Description=Offline dependency fixture' > \
        "${IMAGE_ROOT}/usr/lib/systemd/system/${dependency_unit}"
done
printf '%s\n' '[Unit]' 'Description=firewalld fixture' '[Install]' 'WantedBy=multi-user.target' > \
    "${IMAGE_ROOT}/usr/lib/systemd/system/firewalld.service"
printf '%s\n' '[Unit]' 'Description=nftables fixture' '[Install]' 'WantedBy=multi-user.target' > \
    "${IMAGE_ROOT}/usr/lib/systemd/system/nftables.service"
ln -s /usr/lib/systemd/system/firewalld.service \
    "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/firewalld.service"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-core"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"
chmod 0755 \
    "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-core" \
    "${IMAGE_ROOT}/opt/syswarden/bin/syswarden-cli"
printf '%s\n' 'ID=rhel' 'VERSION_ID=9' > "${IMAGE_ROOT}/etc/os-release"
SYSTEMD_VERIFY_STATUS=0
SYSTEMD_VERIFY_OUTPUT="$(
    systemd-analyze \
        --root="${IMAGE_ROOT}" \
        --man=no \
        --generators=no \
        --recursive-errors=no \
        verify \
        syswarden-core.service \
        syswarden-firewall.service 2>&1
)" || SYSTEMD_VERIFY_STATUS=$?
if [ "${SYSTEMD_VERIFY_STATUS}" -ne 0 ]; then
    SYSTEMD_VERIFY_LINES="$(printf '%s\n' "${SYSTEMD_VERIFY_OUTPUT}" | awk 'NF { count++ } END { print count + 0 }')"
    if [ "${SYSTEMD_VERIFY_LINES}" -ne 2 ] || \
       [ "$(printf '%s\n' "${SYSTEMD_VERIFY_OUTPUT}" | grep -Fxc \
           'Failed to turn off SO_PASSRIGHTS on user lookup socket, ignoring: Operation not permitted')" -ne 1 ] || \
       [ "$(printf '%s\n' "${SYSTEMD_VERIFY_OUTPUT}" | grep -Fxc \
           'Failed to enable SO_PASSCRED on handoff timestamp socket: Operation not permitted')" -ne 1 ]; then
        printf '%s\n' "${SYSTEMD_VERIFY_OUTPUT}" >&2
        exit 1
    fi
    printf '%s\n' 'systemd-analyze runtime verification skipped because the sandbox blocks credential sockets.'
fi
systemctl --root="${IMAGE_ROOT}" preset \
    syswarden-firewall.service syswarden-core.service >/dev/null
[[ "$(readlink "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/firewalld.service")" == \
    /usr/lib/systemd/system/firewalld.service ]]
[[ "$(readlink "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service")" == \
    /usr/lib/systemd/system/syswarden-firewall.service ]]
[[ "$(readlink "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service")" == \
    /usr/lib/systemd/system/syswarden-core.service ]]
[[ ! -e "${IMAGE_ROOT}/etc/systemd/system/multi-user.target.wants/nftables.service" ]]

assemble_profile_rpm() {
    local version="$1"
    local destination="$2"
    fpm -f -s dir -t rpm \
        -n syswarden \
        -v "${version}" \
        --iteration 1.rhelpo \
        --architecture x86_64 \
        -d nftables \
        -d systemd \
        --rpm-digest sha256 \
        --directories /etc/syswarden \
        --directories /etc/syswarden/config \
        --directories /etc/syswarden/config/modules \
        --directories /etc/syswarden/lists \
        --directories /etc/syswarden/tls \
        --directories /var/lib/syswarden \
        --directories /var/lib/syswarden/ui \
        --directories /var/log/syswarden \
        --directories /usr/lib/systemd/system/syswarden-firewall.service.d \
        --rpm-attr "0755,root,root:/usr/lib/systemd/system/syswarden-firewall.service.d" \
        --rpm-attr "0750,root,root:/etc/syswarden" \
        --rpm-attr "0750,root,root:/etc/syswarden/config" \
        --rpm-attr "0750,root,root:/etc/syswarden/config/modules" \
        --rpm-attr "0750,root,root:/etc/syswarden/lists" \
        --rpm-attr "0750,root,root:/etc/syswarden/tls" \
        --rpm-attr "0750,root,root:/var/lib/syswarden" \
        --rpm-attr "0750,root,root:/var/lib/syswarden/ui" \
        --rpm-attr "0750,root,root:/var/log/syswarden" \
        --rpm-attr "0755,root,root:/usr/share/doc/syswarden" \
        --before-install "${RPM_SCRIPTLETS}/pre-install.sh" \
        --after-install "${RPM_SCRIPTLETS}/post-install.sh" \
        --before-remove "${RPM_SCRIPTLETS}/pre-uninstall.sh" \
        --after-remove "${RPM_SCRIPTLETS}/post-uninstall.sh" \
        --rpm-rpmbuild-define "_build_id_links none" \
        --directories /usr/share/doc/syswarden \
        -p "${destination}" \
        -C "${PROFILE_STAGE}/payload" .
}

# The extension RPM is assembled here with the minimal shape of the real shared
# SysWarden payload so final-erase checks exercise /opt rather than a profile-only
# package that could hide residual runtime files.
install -d -m 0755 \
    "${PROFILE_STAGE}/payload/opt/syswarden/bin" \
    "${PROFILE_STAGE}/payload/usr/local/bin" \
    "${PROFILE_STAGE}/payload/usr/share/bash-completion/completions"
for binary in syswarden-cli syswarden-core syswarden-tui; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "${PROFILE_STAGE}/payload/opt/syswarden/bin/${binary}"
    chmod 0750 "${PROFILE_STAGE}/payload/opt/syswarden/bin/${binary}"
done
printf '%s\n' '{"fixture":true}' > "${PROFILE_STAGE}/payload/opt/syswarden/signatures.json"
chmod 0640 "${PROFILE_STAGE}/payload/opt/syswarden/signatures.json"
ln -s /opt/syswarden/bin/syswarden-cli "${PROFILE_STAGE}/payload/usr/local/bin/syswarden"
ln -s /opt/syswarden/bin/syswarden-tui "${PROFILE_STAGE}/payload/usr/local/bin/syswarden-tui"
printf '%s\n' '# fixture completion' > \
    "${PROFILE_STAGE}/payload/usr/share/bash-completion/completions/syswarden"
chmod 0644 "${PROFILE_STAGE}/payload/usr/share/bash-completion/completions/syswarden"
install -m 0644 LICENSE "${PROFILE_STAGE}/payload/usr/share/doc/syswarden/LICENSE.txt"
install -m 0644 src/core/syswarden-cli/pkg/geoip/LICENSE-CC0-1.0.txt \
    "${PROFILE_STAGE}/payload/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt"

assemble_profile_rpm 4.10.0 "${PACKAGE_PATH}"

install -d -m 0755 \
    "${STANDARD_STAGE}/usr/share/syswarden-standard-fixture" \
    "${STANDARD_STAGE}/opt/syswarden/bin" \
    "${STANDARD_STAGE}/usr/local/bin"
install -m 0644 \
    "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-core.service" \
    "${STANDARD_STAGE}/usr/share/syswarden-standard-fixture/syswarden-core.service"
install -m 0644 \
    "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-firewall.service" \
    "${STANDARD_STAGE}/usr/share/syswarden-standard-fixture/syswarden-firewall.service"
for binary in syswarden-cli syswarden-core syswarden-tui; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "${STANDARD_STAGE}/opt/syswarden/bin/${binary}"
    chmod 0750 "${STANDARD_STAGE}/opt/syswarden/bin/${binary}"
done
printf '%s\n' '{"fixture":true}' > "${STANDARD_STAGE}/opt/syswarden/signatures.json"
chmod 0640 "${STANDARD_STAGE}/opt/syswarden/signatures.json"
ln -s /opt/syswarden/bin/syswarden-cli "${STANDARD_STAGE}/usr/local/bin/syswarden"
ln -s /opt/syswarden/bin/syswarden-tui "${STANDARD_STAGE}/usr/local/bin/syswarden-tui"
STANDARD_POST_INSTALL="${TEST_WORKSPACE}/standard-post-install.sh"
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '/usr/bin/install -d -m 0755 /etc/systemd/system/multi-user.target.wants' \
    '/usr/bin/install -d -m 0750 /etc/syswarden /etc/syswarden/config /etc/syswarden/config/modules /etc/syswarden/lists /etc/syswarden/tls /var/lib/syswarden /var/lib/syswarden/ui /var/log/syswarden' \
    '/usr/bin/install -m 0600 /usr/share/syswarden-standard-fixture/syswarden-core.service /etc/systemd/system/syswarden-core.service' \
    '/usr/bin/install -m 0600 /usr/share/syswarden-standard-fixture/syswarden-firewall.service /etc/systemd/system/syswarden-firewall.service' \
    '/usr/bin/rm -f -- /etc/systemd/system/multi-user.target.wants/syswarden-core.service /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service' \
    '/usr/bin/ln -s -- ../syswarden-core.service /etc/systemd/system/multi-user.target.wants/syswarden-core.service' \
    '/usr/bin/ln -s -- ../syswarden-firewall.service /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service' \
    'exit 0' > "${STANDARD_POST_INSTALL}"
chmod 0700 "${STANDARD_POST_INSTALL}"
fpm -f -s dir -t rpm \
    -n syswarden \
    -v 4.04.3 \
    --iteration 1 \
    --architecture x86_64 \
    --after-install "${STANDARD_POST_INSTALL}" \
    -p "${STANDARD_PACKAGE_PATH}" \
    -C "${STANDARD_STAGE}" .

PACKAGE_SHA256="$(sha256sum "${PACKAGE_PATH}" | awk 'NF == 2 { print $1 }')"
[[ "${PACKAGE_SHA256}" =~ ^[0-9a-f]{64}$ ]]
python3 "${EXTENSION_DIRECTORY}/verify-rpm.py" \
    --rpm "${PACKAGE_PATH}" \
    --sha256 "${PACKAGE_SHA256}"

UNREVIEWED_SCRIPT_TAGS=(
    PREINFLAGS POSTINFLAGS PREUNFLAGS POSTUNFLAGS
    PRETRANS PRETRANSFLAGS PRETRANSPROG
    POSTTRANS POSTTRANSFLAGS POSTTRANSPROG
    PREUNTRANS PREUNTRANSFLAGS PREUNTRANSPROG
    POSTUNTRANS POSTUNTRANSFLAGS POSTUNTRANSPROG
    VERIFYSCRIPT VERIFYSCRIPTFLAGS VERIFYSCRIPTPROG
    TRIGGERCONDS TRIGGERFLAGS TRIGGERINDEX TRIGGERNAME
    TRIGGERSCRIPTFLAGS TRIGGERSCRIPTPROG TRIGGERSCRIPTS
    TRIGGERTYPE TRIGGERVERSION
    FILETRIGGERCONDS FILETRIGGERFLAGS FILETRIGGERINDEX FILETRIGGERNAME
    FILETRIGGERPRIORITIES FILETRIGGERSCRIPTFLAGS FILETRIGGERSCRIPTPROG
    FILETRIGGERSCRIPTS FILETRIGGERTYPE FILETRIGGERVERSION
    TRANSFILETRIGGERCONDS TRANSFILETRIGGERFLAGS TRANSFILETRIGGERINDEX
    TRANSFILETRIGGERNAME TRANSFILETRIGGERPRIORITIES
    TRANSFILETRIGGERSCRIPTFLAGS TRANSFILETRIGGERSCRIPTPROG
    TRANSFILETRIGGERSCRIPTS TRANSFILETRIGGERTYPE TRANSFILETRIGGERVERSION
    POLICIES POLICYFLAGS POLICYNAMES POLICYTYPES POLICYTYPESINDEXES SYSUSERS
)
for tag in "${UNREVIEWED_SCRIPT_TAGS[@]}"; do
    tag_state="$(rpm --noplugins --query --package \
        --queryformat "%|${tag}?{present}:{absent}|" \
        "${PACKAGE_PATH}")"
    if [[ "${tag_state}" != absent ]]; then
        printf 'RHEL package-owned RPM contains unreviewed tag %s.\n' "${tag}" >&2
        exit 1
    fi
done
rpm_payload_paths="$(rpm --noplugins --query --package \
    --queryformat '[%{FILENAMES}\n]' "${PACKAGE_PATH}")"
if grep -Eq '^/usr/lib/[.]build-id($|/)' <<< "${rpm_payload_paths}"; then
    printf '%s\n' 'RHEL package-owned RPM unexpectedly contains build-id links.' >&2
    exit 1
fi

if python3 "${EXTENSION_DIRECTORY}/verify-rpm.py" \
    --rpm "${PACKAGE_PATH}" \
    --sha256 0000000000000000000000000000000000000000000000000000000000000000 \
    >/dev/null 2>&1; then
    printf '%s\n' 'RPM profile verifier accepted an incorrect package digest.' >&2
    exit 1
fi

# Exercise the exact RPM scriptlets through two offline chroots. Every command
# used by a scriptlet is the real host binary with its real dynamic libraries;
# only systemctl is replaced because no systemd manager runs in the chroot.
install_chroot_executable() {
    local root="$1"
    local executable="$2"
    [[ "${executable}" == /* && -x "${executable}" ]]
    install -D -m 0755 "${executable}" "${root}${executable}"
    while IFS= read -r library; do
        [[ "${library}" == /* && -f "${library}" ]]
        install -D -m 0755 "${library}" "${root}${library}"
    done < <(
        ldd "${executable}" | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }'
    )
}

initialize_rpm_chroot() {
    local root="$1"
    install -d -m 0755 \
        "${root}/bin" \
        "${root}/dev" \
        "${root}/etc/rpm" \
        "${root}/run" \
        "${root}/tmp" \
        "${root}/usr/bin" \
        "${root}/usr/lib/sysimage/rpm" \
        "${root}/var/lib/syswarden-scriptlet-test"
    install_chroot_executable "${root}" /bin/bash
    ln -s bash "${root}/bin/sh"
    for executable in \
        /usr/bin/awk \
        /usr/bin/dirname \
        /usr/bin/head \
        /usr/bin/install \
        /usr/bin/ln \
        /usr/bin/mktemp \
        /usr/bin/mv \
        /usr/bin/readlink \
        /usr/bin/rm \
        /usr/bin/rmdir \
        /usr/bin/rpm \
        /usr/bin/sha256sum \
        /usr/bin/stat \
        /usr/bin/sync \
        /usr/bin/timeout; do
        install_chroot_executable "${root}" "${executable}"
    done
    mv "${root}/usr/bin/rmdir" "${root}/usr/bin/rmdir.real"
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'flag=/var/lib/syswarden-scriptlet-test/fail-rmdir-once' \
        'if [ -f "$flag" ]; then /usr/bin/rm -f -- "$flag"; exit 70; fi' \
        'exec /usr/bin/rmdir.real "$@"' > "${root}/usr/bin/rmdir"
    chmod 0755 "${root}/usr/bin/rmdir"
    mv "${root}/usr/bin/rm" "${root}/usr/bin/rm.real"
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'flag=/var/lib/syswarden-scriptlet-test/fail-helper-remove-once' \
        'if [ -f "$flag" ]; then' \
        '    for argument in "$@"; do' \
        '        if [ "$argument" = /var/lib/.syswarden-rhelpo-postun-recovery-v1 ]; then' \
        '            /usr/bin/rm.real -f -- "$flag"' \
        '            exit 71' \
        '        fi' \
        '    done' \
        'fi' \
        'exec /usr/bin/rm.real "$@"' > "${root}/usr/bin/rm"
    chmod 0755 "${root}/usr/bin/rm"
    mv "${root}/usr/bin/sync" "${root}/usr/bin/sync.real"
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'flag=/var/lib/syswarden-scriptlet-test/fail-global-sync-once' \
        'if [ "$#" -eq 0 ] && [ -f "$flag" ]; then' \
        '    /usr/bin/rm.real -f -- "$flag"' \
        '    exit 72' \
        'fi' \
        'final_flag=/var/lib/syswarden-scriptlet-test/fail-final-sync-once' \
        'if [ "$*" = "-f -- /var/lib" ] && [ -f "$final_flag" ] &&' \
        '   [ ! -e /var/lib/.syswarden-rhelpo-erase-ready-v1 ] &&' \
        '   [ ! -e /var/lib/.syswarden-rhelpo-postun-recovery-v1 ]; then' \
        '    /usr/bin/rm.real -f -- "$final_flag"' \
        '    exit 73' \
        'fi' \
        'exec /usr/bin/sync.real "$@"' > "${root}/usr/bin/sync"
    chmod 0755 "${root}/usr/bin/sync"
    cp -a /usr/lib/rpm "${root}/usr/lib/"
    # Debian-family RPM uses a per-root database by default, while RHEL-family
    # RPM uses /usr/lib/sysimage/rpm. Scriptlets query the database from inside
    # this RHEL qualification chroot, so pin its test-only macro to the same
    # path already passed to the outer RPM transaction.
    printf '%s\n' '%_dbpath /usr/lib/sysimage/rpm' > "${root}/etc/rpm/macros"
    chmod 0644 "${root}/etc/rpm/macros"
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'printf "%s\n" "$*" >> /var/lib/syswarden-scriptlet-test/systemctl.log' \
        'if [ "${1:-}" = preset ]; then' \
        '    /usr/bin/install -d -m 0755 /etc/systemd/system/multi-user.target.wants' \
        '    /usr/bin/rm -f -- /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service /etc/systemd/system/multi-user.target.wants/syswarden-core.service' \
        '    /usr/bin/ln -s -- /usr/lib/systemd/system/syswarden-firewall.service /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service' \
        '    preset_mode=' \
        '    if [ -f /var/lib/syswarden-scriptlet-test/preset-mode ]; then IFS= read -r preset_mode < /var/lib/syswarden-scriptlet-test/preset-mode; fi' \
        '    [ "$preset_mode" != fail ] || exit 1' \
        '    [ "$preset_mode" != partial-success ] || exit 0' \
        '    /usr/bin/ln -s -- /usr/lib/systemd/system/syswarden-core.service /etc/systemd/system/multi-user.target.wants/syswarden-core.service' \
        '    : > /var/lib/syswarden-scriptlet-test/preset-applied' \
        'elif [ "${1:-}" = show ]; then' \
        '    property=${2#--property=}' \
        '    case "$property" in' \
        '        ActiveState)' \
        '            value=inactive' \
        '            if [ -f /var/lib/syswarden-scriptlet-test/active-state ]; then IFS= read -r value < /var/lib/syswarden-scriptlet-test/active-state; fi' \
        '            printf "%s\n" "$value"' \
        '            ;;' \
        '        Job)' \
        '            value=' \
        '            if [ -f /var/lib/syswarden-scriptlet-test/job ]; then IFS= read -r value < /var/lib/syswarden-scriptlet-test/job || :; fi' \
        '            printf "%s\n" "$value"' \
        '            ;;' \
        '        *) exit 1 ;;' \
        '    esac' \
        'fi' \
        'exit 0' > "${root}/usr/bin/systemctl"
    chmod 0755 "${root}/usr/bin/systemctl"
    : > "${root}/dev/null"
    chmod 0666 "${root}/dev/null"
    if [ "${RPM_ROOT_MODE}" = sudo ]; then
        # Keep the outer workspace owned by the invoking user for cleanup, but
        # make every chroot entry match the root-owned RHEL filesystem it models.
        chroot_admin find "${root}" -mindepth 1 \
            -exec chown -h 0:0 -- '{}' +
        [[ "$(chroot_admin stat -c '%u:%g' -- "${root}/etc")" == 0:0 ]]
    fi
}

initialize_rpm_chroot "${CLEAN_CHROOT_ROOT}"
initialize_rpm_chroot "${CHROOT_ROOT}"

rpm_at_root() {
    local root="$1"
    shift
    "${RPM_ROOT_COMMAND[@]}" --root "${root}" --dbpath /usr/lib/sysimage/rpm \
        --noplugins "$@"
}

run_in_chroot() {
    local root="$1"
    shift
    if [ "${RPM_ROOT_MODE}" = sudo ]; then
        sudo -n chroot "${root}" "$@"
        return
    fi
    unshare -Ur chroot "${root}" "$@"
}

chroot_path_is_regular() {
    local root="$1"
    local path="$2"
    chroot_admin test -f "${root}${path}" &&
        ! chroot_admin test -L "${root}${path}"
}

chroot_path_is_directory() {
    local root="$1"
    local path="$2"
    chroot_admin test -d "${root}${path}" &&
        ! chroot_admin test -L "${root}${path}"
}

assert_chroot_path_absent() {
    local root="$1"
    local path="$2"
    if chroot_admin test -e "${root}${path}" || \
       chroot_admin test -L "${root}${path}"; then
        printf 'Unexpected chroot residue remains: %s\n' "${path}" >&2
        return 1
    fi
}

assert_exact_chroot_regular_file() {
    local root="$1"
    local path="$2"
    local mode="$3"
    local size="$4"
    local expected_digest="$5"
    local label="$6"
    local metadata
    local actual_digest
    if ! chroot_path_is_regular "${root}" "${path}"; then
        printf '%s is not a regular non-symlink file: %s\n' "${label}" "${path}" >&2
        return 1
    fi
    if ! metadata="$(run_in_chroot "${root}" /usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "${path}")"; then
        printf 'Cannot attest %s metadata: %s\n' "${label}" "${path}" >&2
        return 1
    fi
    if [[ "${metadata}" != "0:0:${mode}:1:${size}" ]]; then
        printf 'Unexpected %s metadata for %s: %s\n' "${label}" "${path}" "${metadata}" >&2
        return 1
    fi
    if ! actual_digest="$(run_in_chroot "${root}" /usr/bin/sha256sum -- "${path}" |
        awk 'NF == 2 { print $1 }')"; then
        printf 'Cannot attest %s content: %s\n' "${label}" "${path}" >&2
        return 1
    fi
    if [[ "${actual_digest}" != "${expected_digest}" ]]; then
        printf 'Unexpected %s digest for %s: %s\n' "${label}" "${path}" "${actual_digest}" >&2
        return 1
    fi
}

assert_exact_preset_marker() {
    assert_exact_chroot_regular_file "$1" \
        /var/lib/.syswarden-rhelpo-preset-pending-v1 \
        600 35 \
        862ed0191cbc87e5d7379296af67f418b0f27dec63738fa3a7ff9a9e67b1ce82 \
        'RHEL package-owned preset recovery marker'
}

assert_exact_erase_ready_marker() {
    assert_exact_chroot_regular_file "$1" \
        /var/lib/.syswarden-rhelpo-erase-ready-v1 \
        600 71 \
        3c429337c31a5c397da09b2976dc6cb759d0ae44f986dc19aa4e25f47a2970c8 \
        'RHEL package-owned erase-ready marker'
}

assert_exact_removal_tombstone() {
    assert_exact_chroot_regular_file "$1" \
        /var/lib/syswarden/removal-in-progress-v1 \
        600 39 \
        e1a0bbd8e3d90884bdaf9306233e6c2cfb5ab752c3065939139119982fed4514 \
        'SysWarden removal tombstone'
}

assert_exact_postun_recovery_helper() {
    assert_exact_chroot_regular_file "$1" \
        /var/lib/.syswarden-rhelpo-postun-recovery-v1 \
        700 9843 \
        64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c \
        'RHEL package-owned post-uninstall recovery helper'
}

assert_exact_initial_enablement() {
    local root="$1"
    local unit
    local link
    for unit in syswarden-firewall.service syswarden-core.service; do
        link="/etc/systemd/system/multi-user.target.wants/${unit}"
        chroot_admin test -L "${root}${link}" || {
            printf 'Expected vendor enablement symlink is absent: %s\n' "${link}" >&2
            return 1
        }
        [[ "$(run_in_chroot "${root}" /usr/bin/stat -c '%u:%g:%h' -- "${link}")" == \
            0:0:1 ]] || {
            printf 'Vendor enablement symlink metadata is not exact: %s\n' "${link}" >&2
            return 1
        }
        [[ "$(run_in_chroot "${root}" /usr/bin/readlink -- "${link}")" == \
            "/usr/lib/systemd/system/${unit}" ]] || {
            printf 'Vendor enablement symlink target is not exact: %s\n' "${link}" >&2
            return 1
        }
    done
}

assert_exact_preset_invocation_count() {
    local root="$1"
    local expected_count="$2"
    local log=/var/lib/syswarden-scriptlet-test/systemctl.log
    local metadata
    if ! chroot_path_is_regular "${root}" "${log}"; then
        printf 'systemctl test log is not a regular non-symlink file: %s\n' "${log}" >&2
        return 1
    fi
    metadata="$(run_in_chroot "${root}" /usr/bin/stat -Lc '%u:%g:%a:%h' -- "${log}")"
    [[ "${metadata}" == 0:0:600:1 ]] || {
        printf 'systemctl test log metadata is not exact: %s\n' "${metadata}" >&2
        return 1
    }
    # shellcheck disable=SC2016
    if ! run_in_chroot "${root}" /usr/bin/awk -v expected_count="${expected_count}" '
        $0 == "preset syswarden-firewall.service syswarden-core.service" { exact++ }
        { total++ }
        END { exit !(exact == expected_count && total == expected_count) }
    ' "${log}"; then
        printf 'systemctl test log does not contain exactly %s preset invocation(s).\n' \
            "${expected_count}" >&2
        return 1
    fi
}

run_exact_postun_recovery() {
    local root="$1"
    local helper=/var/lib/.syswarden-rhelpo-postun-recovery-v1
    assert_exact_postun_recovery_helper "${root}" || return 1
    run_in_chroot "${root}" /bin/sh "${helper}"
}

assert_exact_postun_recovery_state() {
    local root="$1"
    assert_exact_postun_recovery_helper "${root}"
    assert_exact_erase_ready_marker "${root}"
    assert_exact_removal_tombstone "${root}"
}

assert_package_identity() {
    local root="$1"
    local expected="$2"
    local actual
    actual="$(rpm_at_root "${root}" --query \
        --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' syswarden)"
    [[ "${actual}" == "${expected}" ]]
    [[ "$(rpm_at_root "${root}" --query --queryformat '%{EPOCHNUM}' syswarden)" == 0 ]]
}

assert_standard_units_unowned() {
    local root="$1"
    local unit
    for unit in syswarden-core.service syswarden-firewall.service; do
        if rpm_at_root "${root}" --query --file "/etc/systemd/system/${unit}" >/dev/null 2>&1; then
            printf 'Production-realistic legacy unit unexpectedly became RPM-owned: %s\n' "${unit}" >&2
            exit 1
        fi
    done
}

expect_rhel_upgrade_refusal() {
    local root="$1"
    local reason="$2"
    if rpm_at_root "${root}" --upgrade --nodeps --nosignature --nodigest --nocontexts \
        "${PACKAGE_PATH}" >/dev/null 2>&1; then
        printf 'RHEL package-owned migration accepted %s.\n' "${reason}" >&2
        exit 1
    fi
    assert_package_identity "${root}" syswarden-4.04.3-1.x86_64
}

assert_rhel_authority() {
    local root="$1"
    assert_chroot_path_absent "${root}" /etc/systemd/system/syswarden-core.service
    assert_chroot_path_absent "${root}" /etc/systemd/system/syswarden-firewall.service
    chroot_path_is_regular "${root}" /usr/lib/systemd/system/syswarden-core.service
    chroot_path_is_regular "${root}" /usr/lib/systemd/system/syswarden-firewall.service
    for unit in syswarden-core.service syswarden-firewall.service; do
        local link="/etc/systemd/system/multi-user.target.wants/${unit}"
        if chroot_admin test -e "${root}${link}" || \
           chroot_admin test -L "${root}${link}"; then
            [[ "$(chroot_admin readlink "${root}${link}")" == \
                "/usr/lib/systemd/system/${unit}" ]]
        fi
    done
}

assert_standard_authority() {
    local root="$1"
    chroot_path_is_regular "${root}" /etc/systemd/system/syswarden-core.service
    chroot_path_is_regular "${root}" /etc/systemd/system/syswarden-firewall.service
    [[ "$(chroot_admin stat -c '%a' "${root}/etc/systemd/system/syswarden-core.service")" == \
        600 ]]
    [[ "$(chroot_admin stat -c '%a' "${root}/etc/systemd/system/syswarden-firewall.service")" == \
        600 ]]
    [[ "$(chroot_admin readlink "${root}/etc/systemd/system/multi-user.target.wants/syswarden-core.service")" == \
        ../syswarden-core.service ]]
    [[ "$(chroot_admin readlink "${root}/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service")" == \
        ../syswarden-firewall.service ]]
    assert_chroot_path_absent "${root}" /usr/lib/systemd/system/syswarden-core.service
    assert_chroot_path_absent "${root}" /usr/lib/systemd/system/syswarden-firewall.service
}

prepare_exact_erase_state() {
    local root="$1"
    chroot_admin rm -f -- \
        "${root}/etc/systemd/system/multi-user.target.wants/syswarden-core.service" \
        "${root}/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service"
    for directory in \
        "${root}/etc/syswarden/config/modules" \
        "${root}/etc/syswarden/lists" \
        "${root}/etc/syswarden/tls" \
        "${root}/var/lib/syswarden/ui" \
        "${root}/var/log/syswarden"; do
        chroot_admin find "${directory}" -mindepth 1 -maxdepth 1 -exec rm -rf -- '{}' +
    done
    chroot_admin find "${root}/etc/syswarden/config" -mindepth 1 -maxdepth 1 \
        ! -name modules -exec rm -rf -- '{}' +
    chroot_admin find "${root}/etc/syswarden" -mindepth 1 -maxdepth 1 \
        ! -name config ! -name lists ! -name tls -exec rm -rf -- '{}' +
    chroot_admin find "${root}/var/lib/syswarden" -mindepth 1 -maxdepth 1 \
        ! -name ui ! -name removal-in-progress-v1 -exec rm -rf -- '{}' +
    chroot_admin find "${root}/opt/syswarden/bin" -mindepth 1 -maxdepth 1 \
        ! -name syswarden-cli ! -name syswarden-core ! -name syswarden-tui \
        -exec rm -rf -- '{}' +
    chroot_admin find "${root}/opt/syswarden" -mindepth 1 -maxdepth 1 \
        ! -name bin ! -name signatures.json -exec rm -rf -- '{}' +
    printf '%s' 'SYSWARDEN_REMOVAL_V1
state=in-progress
' > "${TEST_WORKSPACE}/removal-in-progress-v1"
    printf '%s' 'SYSWARDEN_RHELPO_ERASE_READY_V1
nevra=syswarden-4.10.0-1.rhelpo.x86_64
' > "${TEST_WORKSPACE}/rhelpo-erase-ready-v1"
    chroot_admin install -m 0600 -- \
        "${TEST_WORKSPACE}/removal-in-progress-v1" \
        "${root}/var/lib/syswarden/removal-in-progress-v1"
    chroot_admin install -m 0600 -- \
        "${TEST_WORKSPACE}/rhelpo-erase-ready-v1" \
        "${root}/var/lib/.syswarden-rhelpo-erase-ready-v1"
}

assert_final_absence() {
    local root="$1"
    if rpm_at_root "${root}" --query syswarden >/dev/null 2>&1; then
        printf '%s\n' 'Offline RPM removal retained the package database record.' >&2
        exit 1
    fi
    for removed_path in \
        usr/lib/systemd/system/syswarden-core.service \
        usr/lib/systemd/system/syswarden-firewall.service \
        usr/lib/systemd/system/syswarden-firewall.service.d \
        usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf \
        usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset \
        usr/libexec/syswarden/rhelpo-postun-recovery-v1 \
        usr/libexec/syswarden \
        usr/share/doc/syswarden/rhel-package-owned-profile.json \
        usr/share/doc/syswarden \
        usr/share/bash-completion/completions/syswarden \
        opt/syswarden \
        usr/local/bin/syswarden \
        usr/local/bin/syswarden-tui \
        etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
        etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration \
        etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration \
        etc/syswarden \
        var/lib/syswarden \
        var/lib/syswarden/removal-in-progress-v1.new \
        var/lib/.syswarden-removal-finalizing-v1 \
        var/lib/.syswarden-removal-finalizing-v1.new \
        var/lib/.syswarden-rhelpo-erase-ready-v1 \
        var/lib/.syswarden-rhelpo-erase-ready-v1.new \
        var/lib/.syswarden-rhelpo-preset-pending-v1 \
        var/lib/.syswarden-rhelpo-preset-pending-v1.new \
        var/lib/.syswarden-rhelpo-postun-recovery-v1 \
        var/lib/.syswarden-rhelpo-postun-recovery-v1.new \
        var/log/syswarden; do
        assert_chroot_path_absent "${root}" "/${removed_path}" || {
            printf 'Offline RPM removal retained package-owned state: /%s\n' \
                "${removed_path}" >&2
            exit 1
        }
    done
}

reset_after_test_noscripts_erase() {
    local root="$1"
    local directory
    for directory in \
        usr/lib/systemd/system/syswarden-firewall.service.d \
        usr/libexec/syswarden \
        usr/share/doc/syswarden \
        opt/syswarden/bin \
        opt/syswarden \
        etc/syswarden/config/modules \
        etc/syswarden/config \
        etc/syswarden/lists \
        etc/syswarden/tls \
        etc/syswarden \
        var/lib/syswarden/ui \
        var/lib/syswarden \
        var/log/syswarden; do
        if chroot_admin test -e "${root}/${directory}" || \
           chroot_admin test -L "${root}/${directory}"; then
            chroot_path_is_directory "${root}" "/${directory}"
            chroot_admin rmdir -- "${root}/${directory}"
        fi
    done
}

for root in "${CLEAN_CHROOT_ROOT}" "${CHROOT_ROOT}"; do
    [[ "$(run_in_chroot "${root}" /usr/bin/rpm --eval '%{_dbpath}')" == \
        /usr/lib/sysimage/rpm ]]
    rpm_at_root "${root}" --initdb
    # Match the native RHEL parent after creating the fixture RPM database.
    chroot_admin chmod 0555 -- "${root}/usr/lib"
done

expect_clean_install_refusal() {
    local reason="$1"
    if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
        "${PACKAGE_PATH}" >/dev/null 2>&1; then
        printf 'RHEL package-owned clean installation accepted %s.\n' "${reason}" >&2
        exit 1
    fi
    if rpm_at_root "${CLEAN_CHROOT_ROOT}" --query syswarden >/dev/null 2>&1; then
        printf 'Refused clean installation retained the RPM database record for %s.\n' "${reason}" >&2
        exit 1
    fi
}

for unsafe_library_mode in 0550 0750 0775; do
    chroot_admin chmod "${unsafe_library_mode}" -- "${CLEAN_CHROOT_ROOT}/usr/lib"
    expect_clean_install_refusal "unsupported shared /usr/lib mode ${unsafe_library_mode}"
done
chroot_admin chmod 0555 -- "${CLEAN_CHROOT_ROOT}/usr/lib"

# RPM follows directory symlinks while extracting its payload. The PREIN must
# reject every reserved payload-root redirection before any package bytes land.
for payload_root in \
    etc/syswarden \
    var/lib/syswarden \
    var/log/syswarden \
    opt/syswarden \
    usr/share/doc/syswarden \
    usr/libexec/syswarden; do
    escape_name="$(tr '/' '-' <<< "${payload_root}")"
    escape_directory="${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/escape-${escape_name}"
    payload_path="${CLEAN_CHROOT_ROOT}/${payload_root}"
    chroot_admin install -d -m 0755 -- "$(dirname -- "${payload_path}")" "${escape_directory}"
    printf '%s\n' "sentinel-${payload_root}" > "${TEST_WORKSPACE}/payload-root-sentinel"
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/payload-root-sentinel" \
        "${escape_directory}/sentinel"
    relative_escape="$(realpath --relative-to="$(dirname -- "${payload_path}")" "${escape_directory}")"
    chroot_admin ln -s -- "${relative_escape}" "${payload_path}"
    expect_clean_install_refusal "a symlinked /${payload_root} payload root"
    chroot_admin cmp -s \
        "${TEST_WORKSPACE}/payload-root-sentinel" "${escape_directory}/sentinel"
    [[ "$(chroot_admin find "${escape_directory}" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]]
    chroot_admin rm -f -- "${payload_path}"
    chroot_admin rm -f -- "${escape_directory}/sentinel"
    chroot_admin rmdir -- "${escape_directory}"
done

# A real, correctly-owned dedicated directory can still contain unrelated data.
# Clean installation must not claim any such root and later make it removable.
for dedicated_root_and_mode in \
    etc/syswarden:0750 \
    var/lib/syswarden:0750 \
    var/log/syswarden:0750 \
    opt/syswarden:0755 \
    usr/lib/systemd/system/syswarden-firewall.service.d:0755 \
    usr/libexec/syswarden:0755 \
    usr/share/doc/syswarden:0755; do
    dedicated_root="${dedicated_root_and_mode%:*}"
    dedicated_mode="${dedicated_root_and_mode##*:}"
    dedicated_path="${CLEAN_CHROOT_ROOT}/${dedicated_root}"
    chroot_admin install -d -m "${dedicated_mode}" -- "${dedicated_path}"
    printf 'dedicated-sentinel-%s\n' "${dedicated_root}" > "${TEST_WORKSPACE}/dedicated-sentinel"
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/dedicated-sentinel" \
        "${dedicated_path}/sentinel"
    expect_clean_install_refusal "a pre-existing dedicated /${dedicated_root} directory"
    chroot_admin cmp -s \
        "${TEST_WORKSPACE}/dedicated-sentinel" "${dedicated_path}/sentinel"
    chroot_admin rm -f -- "${dedicated_path}/sentinel"
    chroot_admin rmdir -- "${dedicated_path}"
done

# `/etc/systemd` is an ancestor rather than a package leaf, but POSTIN mutates
# below it. It must be protected before the transaction just like payload roots.
systemd_escape="${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/escape-etc-systemd"
chroot_admin install -d -m 0755 -- "${CLEAN_CHROOT_ROOT}/etc" "${systemd_escape}"
printf '%s\n' systemd-sentinel > "${TEST_WORKSPACE}/systemd-sentinel"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/systemd-sentinel" \
    "${systemd_escape}/sentinel"
systemd_escape_relative="$(realpath --relative-to="${CLEAN_CHROOT_ROOT}/etc" "${systemd_escape}")"
chroot_admin ln -s -- "${systemd_escape_relative}" "${CLEAN_CHROOT_ROOT}/etc/systemd"
expect_clean_install_refusal 'a symlinked /etc/systemd ancestor'
chroot_admin cmp -s "${TEST_WORKSPACE}/systemd-sentinel" "${systemd_escape}/sentinel"
[[ "$(chroot_admin find "${systemd_escape}" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]]
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/etc/systemd"
chroot_admin rm -f -- "${systemd_escape}/sentinel"
chroot_admin rmdir -- "${systemd_escape}"

chroot_admin install -d -m 0777 -- "${CLEAN_CHROOT_ROOT}/etc/systemd"
expect_clean_install_refusal 'modified /etc/systemd ancestry metadata'
chroot_admin rmdir -- "${CLEAN_CHROOT_ROOT}/etc/systemd"

wants_escape="${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/escape-systemd-wants"
chroot_admin install -d -m 0755 -- \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system" "${wants_escape}"
printf '%s\n' wants-sentinel > "${TEST_WORKSPACE}/wants-sentinel"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/wants-sentinel" "${wants_escape}/sentinel"
wants_escape_relative="$(realpath --relative-to="${CLEAN_CHROOT_ROOT}/etc/systemd/system" \
    "${wants_escape}")"
chroot_admin ln -s -- "${wants_escape_relative}" \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants"
expect_clean_install_refusal 'a symlinked systemd wants directory'
chroot_admin cmp -s "${TEST_WORKSPACE}/wants-sentinel" "${wants_escape}/sentinel"
[[ "$(chroot_admin find "${wants_escape}" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]]
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants"
chroot_admin rm -f -- "${wants_escape}/sentinel"
chroot_admin rmdir -- "${wants_escape}"

# Even byte-compatible leaf collisions are unowned on a clean install and must
# not be overwritten merely because their mode and owner look plausible.
chroot_admin install -d -m 0755 -- \
    "${CLEAN_CHROOT_ROOT}/usr/share/bash-completion/completions"
printf '%s\n' '# unowned completion' > "${TEST_WORKSPACE}/unowned-completion"
chroot_admin install -m 0644 -- "${TEST_WORKSPACE}/unowned-completion" \
    "${CLEAN_CHROOT_ROOT}/usr/share/bash-completion/completions/syswarden"
expect_clean_install_refusal 'an unowned regular payload collision'
chroot_admin cmp -s "${TEST_WORKSPACE}/unowned-completion" \
    "${CLEAN_CHROOT_ROOT}/usr/share/bash-completion/completions/syswarden"
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/usr/share/bash-completion/completions/syswarden"

chroot_admin install -d -m 0755 -- "${CLEAN_CHROOT_ROOT}/usr/local/bin"
chroot_admin ln -s -- /opt/syswarden/bin/syswarden-cli \
    "${CLEAN_CHROOT_ROOT}/usr/local/bin/syswarden"
expect_clean_install_refusal 'an unowned symlink payload collision'
[[ "$(chroot_admin readlink "${CLEAN_CHROOT_ROOT}/usr/local/bin/syswarden")" == \
    /opt/syswarden/bin/syswarden-cli ]]
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/usr/local/bin/syswarden"

# Clean RHEL package-owned install and final purge. A direct rpm erase must be
# refused until the exact CLI-produced barriers and empty skeleton exist.
chroot_admin install -d -m 0750 "${CLEAN_CHROOT_ROOT}/var/lib/syswarden"
printf '%s\n' 'blocked' > "${TEST_WORKSPACE}/blocked"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/blocked" \
    "${CLEAN_CHROOT_ROOT}/var/lib/syswarden/removal-in-progress-v1"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted an active removal barrier.' >&2
    exit 1
fi
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/syswarden/removal-in-progress-v1"
for removal_barrier in \
    var/lib/syswarden/removal-in-progress-v1.new \
    var/lib/.syswarden-removal-finalizing-v1.new \
    var/lib/.syswarden-rhelpo-erase-ready-v1.new \
    var/lib/.syswarden-rhelpo-postun-recovery-v1 \
    var/lib/.syswarden-rhelpo-postun-recovery-v1.new; do
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/blocked" \
        "${CLEAN_CHROOT_ROOT}/${removal_barrier}"
    if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
        "${PACKAGE_PATH}" >/dev/null 2>&1; then
        printf 'RHEL package-owned RPM accepted removal recovery state: /%s\n' \
            "${removal_barrier}" >&2
        exit 1
    fi
    chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/${removal_barrier}"
done
chroot_admin rmdir -- "${CLEAN_CHROOT_ROOT}/var/lib/syswarden"
chroot_admin install -d -m 0755 "${CLEAN_CHROOT_ROOT}/etc/systemd/system"
chroot_admin ln -s -- /tmp/attacker \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
chroot_admin ln -s -- /tmp/attacker \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/syswarden-firewall.service"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted clean-install priority unit overrides.' >&2
    exit 1
fi
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/syswarden-core.service" \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/syswarden-firewall.service"
chroot_admin install -d -m 0755 \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants"
chroot_admin ln -s -- /tmp/attacker \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted clean-install pre-existing enablement.' >&2
    exit 1
fi
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service"
chroot_admin ln -s -- /usr/lib/systemd/system/syswarden-core.service \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted interrupted migration during clean installation.' >&2
    exit 1
fi
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 > "${TEST_WORKSPACE}/preset-pending.new"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending.new" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted preset recovery state during clean installation.' >&2
    exit 1
fi
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
for preset_mode in fail partial-success; do
    printf '%s\n' "${preset_mode}" > "${TEST_WORKSPACE}/preset-mode"
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-mode" \
        "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-mode"
    chroot_admin rm -f -- \
        "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log"
    rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
        "${PACKAGE_PATH}" >/dev/null 2>&1 || :
    # RPM releases expose failed POSTIN scriptlets through different CLI
    # statuses. Qualify the exact recoverable state instead of treating that
    # transport status as proof.
    assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
    for link in \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service; do
        assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" "${link}"
    done
    assert_exact_preset_marker "${CLEAN_CHROOT_ROOT}"
    assert_exact_preset_invocation_count "${CLEAN_CHROOT_ROOT}" 1
    chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-mode"
    rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
        "${PACKAGE_PATH}"
    assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
    assert_exact_initial_enablement "${CLEAN_CHROOT_ROOT}"
    assert_exact_preset_invocation_count "${CLEAN_CHROOT_ROOT}" 2
    for marker in \
        /var/lib/.syswarden-rhelpo-preset-pending-v1 \
        /var/lib/.syswarden-rhelpo-preset-pending-v1.new; do
        assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" "${marker}"
    done
    rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase --noscripts syswarden
    chroot_admin rm -f -- \
        "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service" \
        "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service"
    reset_after_test_noscripts_erase "${CLEAN_CHROOT_ROOT}"
done
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-mode"
printf '%s\n' fail > "${TEST_WORKSPACE}/fail-global-sync-once"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/fail-global-sync-once" \
    "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/fail-global-sync-once"
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log"
rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1 || :
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
assert_exact_preset_marker "${CLEAN_CHROOT_ROOT}"
assert_exact_initial_enablement "${CLEAN_CHROOT_ROOT}"
assert_exact_preset_invocation_count "${CLEAN_CHROOT_ROOT}" 1
rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
assert_exact_initial_enablement "${CLEAN_CHROOT_ROOT}"
assert_exact_preset_invocation_count "${CLEAN_CHROOT_ROOT}" 2
for marker in \
    /var/lib/.syswarden-rhelpo-preset-pending-v1 \
    /var/lib/.syswarden-rhelpo-preset-pending-v1.new; do
    assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" "${marker}"
done
rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase --noscripts syswarden
chroot_admin rm -f -- \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service" \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service"
reset_after_test_noscripts_erase "${CLEAN_CHROOT_ROOT}"

rpm_at_root "${CLEAN_CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
operator_recovery_helper="${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-postun-recovery-v1"
chroot_admin install -m 0700 -- \
    "${PROFILE_STAGE}/payload/usr/libexec/syswarden/rhelpo-postun-recovery-v1" \
    "${operator_recovery_helper}"
if run_exact_postun_recovery "${CLEAN_CHROOT_ROOT}" >/dev/null 2>&1; then
    printf '%s\n' 'Operator recovery accepted a still-installed SysWarden RPM.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
if run_in_chroot "${CLEAN_CHROOT_ROOT}" /bin/sh \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1 invalid-mode >/dev/null 2>&1; then
    printf '%s\n' 'Post-uninstall recovery accepted an invalid internal mode argument.' >&2
    exit 1
fi
chroot_path_is_regular "${CLEAN_CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1
chroot_admin rm -f -- "${operator_recovery_helper}"
chroot_admin ln -- "${CLEAN_CHROOT_ROOT}/opt/syswarden/bin/syswarden-cli" \
    "${CLEAN_CHROOT_ROOT}/opt/syswarden/bin/syswarden-cli.hardlink"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a hard-linked shared payload leaf.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/opt/syswarden/bin/syswarden-cli.hardlink"
chroot_admin ln -s -- /usr/lib/systemd/system/syswarden-core.service \
    "${CLEAN_CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" \
    /etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration
printf '%s' 'tampered' > "${TEST_WORKSPACE}/preset-pending-invalid-prefix"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending-invalid-prefix" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a substituted partial preset marker.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 | head -c 11 > \
    "${TEST_WORKSPACE}/preset-pending-prefix"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending-prefix" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a partial final preset marker.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending-prefix" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-preset-pending-v1.new
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending.new" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
rpm_at_root "${CLEAN_CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CLEAN_CHROOT_ROOT}"
assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-preset-pending-v1
assert_chroot_path_absent "${CLEAN_CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-preset-pending-v1.new
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased without the CLI authorization barriers.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
outside_sentinel="${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/outside-sentinel"
printf '%s\n' 'outside must survive' > "${TEST_WORKSPACE}/outside-sentinel"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/outside-sentinel" "${outside_sentinel}"
chroot_admin ln -s -- "${outside_sentinel}" "${CLEAN_CHROOT_ROOT}/opt/syswarden/untrusted-link"
chroot_admin ln -- "${outside_sentinel}" "${CLEAN_CHROOT_ROOT}/opt/syswarden/untrusted-hardlink"
chroot_admin mkfifo -m 0600 "${CLEAN_CHROOT_ROOT}/opt/syswarden/untrusted-fifo"
prepare_exact_erase_state "${CLEAN_CHROOT_ROOT}"
prepare_exact_erase_state "${CLEAN_CHROOT_ROOT}"
chroot_admin cmp -s "${TEST_WORKSPACE}/outside-sentinel" "${outside_sentinel}"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/blocked" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-removal-finalizing-v1"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased with a finalizing barrier.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-removal-finalizing-v1"
printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 > "${TEST_WORKSPACE}/preset-pending.new"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending.new" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased with interrupted preset recovery state.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
chroot_admin install -d -m 0755 "${CLEAN_CHROOT_ROOT}/run/systemd/system"
for service_state in failed activating unknown; do
    printf '%s\n' "${service_state}" > "${TEST_WORKSPACE}/active-state"
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/active-state" \
        "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/active-state"
    if rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
        printf 'RHEL package-owned RPM erased while service state was %s.\n' "${service_state}" >&2
        exit 1
    fi
    assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
done
printf '%s\n' inactive > "${TEST_WORKSPACE}/active-state"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/active-state" \
    "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/active-state"
printf '%s\n' '123 queued' > "${TEST_WORKSPACE}/job"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/job" \
    "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/job"
if rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased with a queued systemd job.' >&2
    exit 1
fi
assert_package_identity "${CLEAN_CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${CLEAN_CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/job"
chroot_admin install -m 0700 -- \
    "${PROFILE_STAGE}/payload/usr/libexec/syswarden/rhelpo-postun-recovery-v1" \
    "${CLEAN_CHROOT_ROOT}/var/lib/.syswarden-rhelpo-postun-recovery-v1.new"
rpm_at_root "${CLEAN_CHROOT_ROOT}" --erase syswarden
assert_final_absence "${CLEAN_CHROOT_ROOT}"

# Contract cycle: exact standard v4.04.3, migration to RHELPO v4.10.0,
# rollback to standard, reupgrade to RHELPO, then adversarial and final purge.
rpm_at_root "${CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${STANDARD_PACKAGE_PATH}"
assert_package_identity "${CHROOT_ROOT}" syswarden-4.04.3-1.x86_64
assert_standard_authority "${CHROOT_ROOT}"
assert_standard_units_unowned "${CHROOT_ROOT}"
for unit in syswarden-core.service syswarden-firewall.service; do
    chroot_admin chmod 0644 -- "${CHROOT_ROOT}/etc/systemd/system/${unit}"
    [[ "$(run_in_chroot "${CHROOT_ROOT}" /usr/bin/stat -Lc '%u:%g:%a:%h' -- \
        "/etc/systemd/system/${unit}")" == 0:0:644:1 ]]
done
printf '%s\n' '[network]' 'whitelist_ips = ["192.0.2.10/32"]' > "${TEST_WORKSPACE}/99-user.toml"
chroot_admin install -m 0640 -- "${TEST_WORKSPACE}/99-user.toml" \
    "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml"
OPERATOR_CONFIG_SHA256="$(chroot_admin sha256sum \
    "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" | awk 'NF == 2 { print $1 }')"

chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/preset-pending.new" \
    "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"
expect_rhel_upgrade_refusal "${CHROOT_ROOT}" 'preset recovery state owned by no RHEL package-owned install'
chroot_admin rm -f -- "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-preset-pending-v1.new"

for unsafe_legacy_mode in 0640 0664 0755 1644 2644 4644; do
    chroot_admin chmod "${unsafe_legacy_mode}" -- \
        "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
    [[ "$(run_in_chroot "${CHROOT_ROOT}" /usr/bin/stat -Lc '%a' -- \
        /etc/systemd/system/syswarden-core.service)" == "${unsafe_legacy_mode#0}" ]]
    expect_rhel_upgrade_refusal "${CHROOT_ROOT}" \
        "an exact legacy unit with unsupported mode ${unsafe_legacy_mode}"
    chroot_admin chmod 0644 -- "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
done

chroot_admin ln -- "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service.hardlink"
expect_rhel_upgrade_refusal "${CHROOT_ROOT}" 'a hard-linked legacy unit'
chroot_admin rm -f -- "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service.hardlink"

chroot_admin rm -f -- "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
chroot_admin ln -s -- /tmp/attacker "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
expect_rhel_upgrade_refusal "${CHROOT_ROOT}" 'a symlinked legacy unit'
chroot_admin rm -f -- "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
chroot_admin install -m 0644 -- \
    "${CHROOT_ROOT}/usr/share/syswarden-standard-fixture/syswarden-core.service" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"

printf '%s\n' 'substituted' > "${TEST_WORKSPACE}/substituted-unit"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/substituted-unit" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-firewall.service"
expect_rhel_upgrade_refusal "${CHROOT_ROOT}" 'a byte-substituted legacy unit'
chroot_admin install -m 0644 -- \
    "${CHROOT_ROOT}/usr/share/syswarden-standard-fixture/syswarden-firewall.service" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-firewall.service"

chroot_admin ln -s -- /usr/lib/systemd/system/syswarden-core.service \
    "${CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
expect_rhel_upgrade_refusal "${CHROOT_ROOT}" 'interrupted migration owned by the standard package'
chroot_admin rm -f -- \
    "${CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"

rpm_at_root "${CHROOT_ROOT}" --upgrade --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
assert_rhel_authority "${CHROOT_ROOT}"
[[ "$(chroot_admin sha256sum "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" |
    awk 'NF == 2 { print $1 }')" == "${OPERATOR_CONFIG_SHA256}" ]]
chroot_admin ln -s -- /usr/lib/systemd/system/syswarden-core.service \
    "${CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
rpm_at_root "${CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CHROOT_ROOT}"
assert_chroot_path_absent "${CHROOT_ROOT}" \
    /etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration

# A retry after an interrupted POSTIN may see exact legacy units even though
# the installed identity is already RHELPO. It must complete deterministically.
chroot_admin install -m 0600 -- \
    "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-core.service" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-core.service"
chroot_admin install -m 0600 -- \
    "${PROFILE_STAGE}/payload/usr/lib/systemd/system/syswarden-firewall.service" \
    "${CHROOT_ROOT}/etc/systemd/system/syswarden-firewall.service"
rpm_at_root "${CHROOT_ROOT}" --upgrade --replacepkgs --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CHROOT_ROOT}"

rpm_at_root "${CHROOT_ROOT}" --upgrade --oldpackage --nodeps --nosignature --nodigest --nocontexts \
    "${STANDARD_PACKAGE_PATH}"
assert_package_identity "${CHROOT_ROOT}" syswarden-4.04.3-1.x86_64
assert_standard_authority "${CHROOT_ROOT}"
assert_standard_units_unowned "${CHROOT_ROOT}"
[[ "$(chroot_admin sha256sum "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" |
    awk 'NF == 2 { print $1 }')" == "${OPERATOR_CONFIG_SHA256}" ]]

rpm_at_root "${CHROOT_ROOT}" --upgrade --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
assert_rhel_authority "${CHROOT_ROOT}"
[[ "$(chroot_admin sha256sum "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" |
    awk 'NF == 2 { print $1 }')" == "${OPERATOR_CONFIG_SHA256}" ]]

prepare_exact_erase_state "${CHROOT_ROOT}"
for substituted_leaf in \
    usr/local/bin/syswarden \
    usr/local/bin/syswarden-tui \
    usr/share/bash-completion/completions/syswarden; do
    leaf_path="${CHROOT_ROOT}/${substituted_leaf}"
    chroot_admin rm -f -- "${leaf_path}"
    chroot_admin install -d -m 0755 -- "${leaf_path}"
    chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/blocked" "${leaf_path}/residue"
    if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
        printf 'RHEL package-owned RPM erased with substituted payload leaf /%s.\n' \
            "${substituted_leaf}" >&2
        exit 1
    fi
    assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
    chroot_admin rm -f -- "${leaf_path}/residue"
    chroot_admin rmdir -- "${leaf_path}"
    case "${substituted_leaf}" in
        usr/local/bin/syswarden)
            chroot_admin ln -s -- /opt/syswarden/bin/syswarden-cli "${leaf_path}"
            ;;
        usr/local/bin/syswarden-tui)
            chroot_admin ln -s -- /opt/syswarden/bin/syswarden-tui "${leaf_path}"
            ;;
        usr/share/bash-completion/completions/syswarden)
            chroot_admin install -m 0644 -- \
                "${PROFILE_STAGE}/payload/usr/share/bash-completion/completions/syswarden" \
                "${leaf_path}"
            ;;
        *)
            printf 'No exact payload restoration is defined for /%s.\n' \
                "${substituted_leaf}" >&2
            exit 1
            ;;
    esac
done
chroot_admin ln -s -- /usr/lib/systemd/system/syswarden-core.service \
    "${CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased with interrupted enablement migration.' >&2
    exit 1
fi
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- \
    "${CHROOT_ROOT}/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration"
printf '%s\n' 'unexpected' | chroot_admin tee \
    "${CHROOT_ROOT}/usr/lib/systemd/system/syswarden-firewall.service.d/unexpected.conf" >/dev/null
if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM erased with an unexpected drop-in.' >&2
    exit 1
fi
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- \
    "${CHROOT_ROOT}/usr/lib/systemd/system/syswarden-firewall.service.d/unexpected.conf"
prepare_exact_erase_state "${CHROOT_ROOT}"
postun_helper_source="${CHROOT_ROOT}/usr/libexec/syswarden/rhelpo-postun-recovery-v1"
postun_helper_temporary="${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-postun-recovery-v1.new"
chroot_admin ln -s -- /usr/libexec/syswarden/rhelpo-postun-recovery-v1 \
    "${postun_helper_temporary}"
if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a symlinked recovery-helper temporary.' >&2
    exit 1
fi
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${postun_helper_temporary}"
chroot_admin ln -- "${postun_helper_source}" "${postun_helper_temporary}"
if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a hard-linked recovery-helper temporary.' >&2
    exit 1
fi
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${postun_helper_temporary}"
chroot_admin install -m 0700 -- "${TEST_WORKSPACE}/blocked" "${postun_helper_temporary}"
if rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a substituted recovery-helper temporary.' >&2
    exit 1
fi
assert_package_identity "${CHROOT_ROOT}" syswarden-4.10.0-1.rhelpo.x86_64
chroot_admin rm -f -- "${postun_helper_temporary}"
head -c 257 -- "${PROFILE_STAGE}/payload/usr/libexec/syswarden/rhelpo-postun-recovery-v1" > \
    "${TEST_WORKSPACE}/postun-recovery-prefix"
chroot_admin install -m 0700 -- "${TEST_WORKSPACE}/postun-recovery-prefix" \
    "${postun_helper_temporary}"
printf '%s\n' fail > "${TEST_WORKSPACE}/fail-rmdir-once"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/fail-rmdir-once" \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/fail-rmdir-once"
rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1 || \
    :
if rpm_at_root "${CHROOT_ROOT}" --query syswarden >/dev/null 2>&1; then
    printf '%s\n' 'Injected post-uninstall failure retained the package database record.' >&2
    exit 1
fi
# RPM 4.x and RPM 6 expose a failed POSTUN through different CLI statuses.
# The package database transition and exact durable recovery artifacts are the
# portable contract that operators rely on after either implementation.
assert_exact_postun_recovery_state "${CHROOT_ROOT}"
printf '%s\n' tampered | chroot_admin tee -a \
    "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-postun-recovery-v1" >/dev/null
if run_exact_postun_recovery "${CHROOT_ROOT}" >/dev/null 2>&1; then
    printf '%s\n' 'Operator recovery accepted a substituted durable helper.' >&2
    exit 1
fi
chroot_admin install -m 0700 -- \
    "${PROFILE_STAGE}/payload/usr/libexec/syswarden/rhelpo-postun-recovery-v1" \
    "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-postun-recovery-v1"
chroot_admin rm -f -- "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-erase-ready-v1"
if run_exact_postun_recovery "${CHROOT_ROOT}" >/dev/null 2>&1; then
    printf '%s\n' 'Operator recovery accepted a missing erase-ready barrier.' >&2
    exit 1
fi
chroot_path_is_regular "${CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1
chroot_path_is_regular "${CHROOT_ROOT}" /var/lib/syswarden/removal-in-progress-v1
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/rhelpo-erase-ready-v1" \
    "${CHROOT_ROOT}/var/lib/.syswarden-rhelpo-erase-ready-v1"
chroot_admin install -d -m 0755 "${CHROOT_ROOT}/etc/cron.d"
printf '%s\n' residue > "${TEST_WORKSPACE}/standalone-residue"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/standalone-residue" \
    "${CHROOT_ROOT}/etc/cron.d/syswarden"
if run_exact_postun_recovery "${CHROOT_ROOT}" >/dev/null 2>&1; then
    printf '%s\n' 'Post-uninstall recovery consumed authorization with standalone residue.' >&2
    exit 1
fi
chroot_path_is_regular "${CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1
chroot_path_is_regular "${CHROOT_ROOT}" /var/lib/.syswarden-rhelpo-erase-ready-v1
chroot_admin rm -f -- "${CHROOT_ROOT}/etc/cron.d/syswarden"
printf '%s\n' fail > "${TEST_WORKSPACE}/fail-global-sync-once"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/fail-global-sync-once" \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/fail-global-sync-once"
if run_exact_postun_recovery "${CHROOT_ROOT}" >/dev/null 2>&1; then
    printf '%s\n' 'Injected post-uninstall durability barrier failure unexpectedly succeeded.' >&2
    exit 1
fi
chroot_path_is_regular "${CHROOT_ROOT}" \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1
chroot_path_is_regular "${CHROOT_ROOT}" /var/lib/.syswarden-rhelpo-erase-ready-v1
run_exact_postun_recovery "${CHROOT_ROOT}"
assert_final_absence "${CHROOT_ROOT}"

rpm_at_root "${CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CHROOT_ROOT}"
prepare_exact_erase_state "${CHROOT_ROOT}"
printf '%s\n' fail > "${TEST_WORKSPACE}/fail-helper-remove-once"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/fail-helper-remove-once" \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/fail-helper-remove-once"
rpm_at_root "${CHROOT_ROOT}" --erase syswarden >/dev/null 2>&1 || :
if rpm_at_root "${CHROOT_ROOT}" --query syswarden >/dev/null 2>&1; then
    printf '%s\n' 'Injected late recovery failure retained the package database record.' >&2
    exit 1
fi
assert_exact_postun_recovery_helper "${CHROOT_ROOT}"
for removed_recovery_path in \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1.new \
    /var/lib/.syswarden-rhelpo-erase-ready-v1 \
    /var/lib/.syswarden-rhelpo-erase-ready-v1.new \
    /var/lib/syswarden/removal-in-progress-v1 \
    /var/lib/syswarden/removal-in-progress-v1.new; do
    assert_chroot_path_absent "${CHROOT_ROOT}" "${removed_recovery_path}"
done
if rpm_at_root "${CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}" >/dev/null 2>&1; then
    printf '%s\n' 'RHEL package-owned RPM accepted a stale post-uninstall recovery helper.' >&2
    exit 1
fi
printf '%s\n' fail > "${TEST_WORKSPACE}/fail-final-sync-once"
chroot_admin install -m 0600 -- "${TEST_WORKSPACE}/fail-final-sync-once" \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/fail-final-sync-once"
run_exact_postun_recovery "${CHROOT_ROOT}"
assert_final_absence "${CHROOT_ROOT}"
rpm_at_root "${CHROOT_ROOT}" --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
assert_rhel_authority "${CHROOT_ROOT}"
prepare_exact_erase_state "${CHROOT_ROOT}"
rpm_at_root "${CHROOT_ROOT}" --erase syswarden
assert_final_absence "${CHROOT_ROOT}"

for root in "${CLEAN_CHROOT_ROOT}" "${CHROOT_ROOT}"; do
    [[ "$(run_in_chroot "${root}" /usr/bin/stat -Lc '%u:%g:%a' -- /usr/lib)" == 0:0:555 ]]
done
printf '%s\n' 'RHEL package-owned RPM assembly contract passed.'
