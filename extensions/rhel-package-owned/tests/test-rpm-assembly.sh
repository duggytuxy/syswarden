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
UPGRADE_PACKAGE_PATH="${PACKAGE_DIRECTORY}/syswarden-4.10.1-1.rhelpo.x86_64.rpm"
RPM_SCRIPTLETS="${TEST_WORKSPACE}/rpm-scriptlets"
IMAGE_ROOT="${TEST_WORKSPACE}/image-root"
CHROOT_ROOT="${TEST_WORKSPACE}/rpm-chroot"

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    case "${TEST_WORKSPACE}" in
        /tmp/syswarden-rhel-profile-rpm-test.*)
            if [ "${RPM_ROOT_MODE:-}" = sudo ] && [ -d "${CHROOT_ROOT}" ]; then
                sudo -n rm -rf -- "${CHROOT_ROOT}" || status=1
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
        --rpm-attr "0750,root,root:/etc/syswarden" \
        --rpm-attr "0750,root,root:/etc/syswarden/config" \
        --rpm-attr "0750,root,root:/etc/syswarden/config/modules" \
        --rpm-attr "0750,root,root:/etc/syswarden/lists" \
        --rpm-attr "0750,root,root:/etc/syswarden/tls" \
        --rpm-attr "0750,root,root:/var/lib/syswarden" \
        --rpm-attr "0750,root,root:/var/lib/syswarden/ui" \
        --rpm-attr "0750,root,root:/var/log/syswarden" \
        --before-install "${RPM_SCRIPTLETS}/pre-install.sh" \
        --after-install "${RPM_SCRIPTLETS}/post-install.sh" \
        --before-remove "${RPM_SCRIPTLETS}/pre-uninstall.sh" \
        --after-remove "${RPM_SCRIPTLETS}/post-uninstall.sh" \
        -p "${destination}" \
        -C "${PROFILE_STAGE}/payload" .
}

assemble_profile_rpm 4.10.0 "${PACKAGE_PATH}"
assemble_profile_rpm 4.10.1 "${UPGRADE_PACKAGE_PATH}"

PACKAGE_SHA256="$(sha256sum "${PACKAGE_PATH}" | awk 'NF == 2 { print $1 }')"
[[ "${PACKAGE_SHA256}" =~ ^[0-9a-f]{64}$ ]]
python3 "${EXTENSION_DIRECTORY}/verify-rpm.py" \
    --rpm "${PACKAGE_PATH}" \
    --sha256 "${PACKAGE_SHA256}"

if python3 "${EXTENSION_DIRECTORY}/verify-rpm.py" \
    --rpm "${PACKAGE_PATH}" \
    --sha256 0000000000000000000000000000000000000000000000000000000000000000 \
    >/dev/null 2>&1; then
    printf '%s\n' 'RPM profile verifier accepted an incorrect package digest.' >&2
    exit 1
fi

# Exercise the exact RPM scriptlets through an offline chroot with no running
# systemd manager. The fake systemctl records package intent without starting a
# service. This models a mock-backed image root and proves that an upgrade does
# not recreate an enablement decision removed by the image administrator.
install -d -m 0755 \
    "${CHROOT_ROOT}/bin" \
    "${CHROOT_ROOT}/dev" \
    "${CHROOT_ROOT}/run" \
    "${CHROOT_ROOT}/tmp" \
    "${CHROOT_ROOT}/usr/bin" \
    "${CHROOT_ROOT}/var/lib/rpm" \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test"
install -m 0755 /bin/bash "${CHROOT_ROOT}/bin/bash"
ln -s bash "${CHROOT_ROOT}/bin/sh"
while IFS= read -r library; do
    [[ "${library}" == /* && -f "${library}" ]]
    install -D -m 0755 "${library}" "${CHROOT_ROOT}${library}"
done < <(
    ldd /bin/bash | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }'
)
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'printf "%s\n" "$*" >> /var/lib/syswarden-scriptlet-test/systemctl.log' \
    'if [ "${1:-}" = preset ]; then' \
    '    : > /var/lib/syswarden-scriptlet-test/preset-applied' \
    'fi' \
    'exit 0' > "${CHROOT_ROOT}/usr/bin/systemctl"
chmod 0755 "${CHROOT_ROOT}/usr/bin/systemctl"
: > "${CHROOT_ROOT}/dev/null"
chmod 0666 "${CHROOT_ROOT}/dev/null"

"${RPM_ROOT_COMMAND[@]}" --root "${CHROOT_ROOT}" --dbpath /var/lib/rpm \
    --noplugins --initdb
"${RPM_ROOT_COMMAND[@]}" --root "${CHROOT_ROOT}" --dbpath /var/lib/rpm \
    --noplugins --install --nodeps --nosignature --nodigest --nocontexts \
    "${PACKAGE_PATH}"
[[ ! -d "${CHROOT_ROOT}/run/systemd/system" ]]
[[ -f "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-applied" ]]
[[ "$(chroot_admin cat "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log")" == \
    'preset syswarden-firewall.service syswarden-core.service' ]]
rm -f -- "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-applied"
printf '%s\n' 'administrator-disabled' > \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/administrator-choice"
printf '%s\n' \
    '[network]' \
    'whitelist_ips = ["192.0.2.10/32"]' > "${TEST_WORKSPACE}/99-user.toml"
chroot_admin install -m 0640 -- \
    "${TEST_WORKSPACE}/99-user.toml" \
    "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml"
OPERATOR_CONFIG_SHA256="$(
    chroot_admin sha256sum "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" |
        awk 'NF == 2 { print $1 }'
)"

"${RPM_ROOT_COMMAND[@]}" --root "${CHROOT_ROOT}" --dbpath /var/lib/rpm \
    --noplugins --upgrade --nodeps --nosignature --nodigest --nocontexts \
    "${UPGRADE_PACKAGE_PATH}"
[[ ! -e "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/preset-applied" ]]
[[ "$(cat "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/administrator-choice")" == \
    'administrator-disabled' ]]
[[ "$(
    chroot_admin sha256sum "${CHROOT_ROOT}/etc/syswarden/config/modules/99-user.toml" |
        awk 'NF == 2 { print $1 }'
)" == "${OPERATOR_CONFIG_SHA256}" ]]
[[ "$(chroot_admin cat "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log")" == \
    'preset syswarden-firewall.service syswarden-core.service' ]]

"${RPM_ROOT_COMMAND[@]}" --root "${CHROOT_ROOT}" --dbpath /var/lib/rpm \
    --noplugins --erase syswarden
[[ "$(chroot_admin tail -n 1 "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log")" == \
    'disable syswarden-core.service syswarden-firewall.service' ]]
if chroot_admin grep -Fq 'stop ' \
    "${CHROOT_ROOT}/var/lib/syswarden-scriptlet-test/systemctl.log"; then
    printf '%s\n' 'Offline RPM removal attempted to stop a service without a running systemd manager.' >&2
    exit 1
fi

printf '%s\n' 'RHEL package-owned RPM assembly contract passed.'
