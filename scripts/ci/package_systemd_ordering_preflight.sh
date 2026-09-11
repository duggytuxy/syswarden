#!/bin/sh

syswarden_preflight_systemd_ordering_dropin() {
    [ ! -f /etc/alpine-release ] || return 0

    syswarden_ordering_path=/usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf
    syswarden_ordering_directory=/usr/lib/systemd/system/syswarden-firewall.service.d
    syswarden_ordering_sha256=8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483

    for syswarden_ordering_parent in \
        /usr \
        /usr/lib \
        /usr/lib/systemd \
        /usr/lib/systemd/system; do
        if [ ! -d "${syswarden_ordering_parent}" ] || \
            [ -L "${syswarden_ordering_parent}" ] || \
            [ "$(stat -c '%u:%g' "${syswarden_ordering_parent}" 2>/dev/null)" != 0:0 ] || \
            [ -n "$(find "${syswarden_ordering_parent}" -maxdepth 0 -perm /0022 -print -quit 2>/dev/null)" ]; then
            printf 'Refusing unsafe systemd package parent: %s\n' \
                "${syswarden_ordering_parent}" >&2
            return 1
        fi
    done

    if [ -e "${syswarden_ordering_directory}" ] || [ -L "${syswarden_ordering_directory}" ]; then
        if [ ! -d "${syswarden_ordering_directory}" ] || \
            [ -L "${syswarden_ordering_directory}" ] || \
            [ "$(stat -c '%u:%g' "${syswarden_ordering_directory}" 2>/dev/null)" != 0:0 ] || \
            [ -n "$(find "${syswarden_ordering_directory}" -maxdepth 0 -perm /0022 -print -quit 2>/dev/null)" ]; then
            printf 'Refusing unsafe SysWarden systemd drop-in directory: %s\n' \
                "${syswarden_ordering_directory}" >&2
            return 1
        fi
        syswarden_ordering_unexpected="$({
            find "${syswarden_ordering_directory}" -mindepth 1 -maxdepth 1 \
                ! -path "${syswarden_ordering_path}" -print -quit
        } 2>/dev/null)" || return 1
        [ -z "${syswarden_ordering_unexpected}" ] || {
            printf 'Refusing an existing unowned systemd drop-in: %s\n' \
                "${syswarden_ordering_unexpected}" >&2
            return 1
        }
    fi

    if [ ! -e "${syswarden_ordering_path}" ] && [ ! -L "${syswarden_ordering_path}" ]; then
        return 0
    fi
    if [ ! -f "${syswarden_ordering_path}" ] || \
        [ -L "${syswarden_ordering_path}" ] || \
        [ "$(stat -c '%u:%g:%a:%h:%s' "${syswarden_ordering_path}" 2>/dev/null)" != 0:0:644:1:43 ]; then
        printf 'Refusing unsafe existing SysWarden systemd ordering drop-in.\n' >&2
        return 1
    fi
    syswarden_ordering_identity_before="$(
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_ordering_path}"
    )" || return 1
    [ "$(sha256sum "${syswarden_ordering_path}" | awk '{ print $1 }')" = \
        "${syswarden_ordering_sha256}" ] || {
        printf 'Refusing modified existing SysWarden systemd ordering drop-in.\n' >&2
        return 1
    }

    syswarden_ordering_authorities=0
    if command -v dpkg-query >/dev/null 2>&1; then
        syswarden_ordering_dpkg_files="$(dpkg-query --listfiles syswarden 2>/dev/null)" || \
            syswarden_ordering_dpkg_files=
        if [ -n "${syswarden_ordering_dpkg_files}" ] && \
            [ "$(printf '%s\n' "${syswarden_ordering_dpkg_files}" | \
                awk -v path="${syswarden_ordering_path}" '$0 == path { count++ } END { print count + 0 }')" -eq 1 ]; then
            syswarden_ordering_authorities=$((syswarden_ordering_authorities + 1))
        fi
    fi
    if command -v rpm >/dev/null 2>&1; then
        syswarden_ordering_rpm_owner="$(
            rpm --query --file "${syswarden_ordering_path}" \
                --queryformat '%{NAME}\n' 2>/dev/null
        )" || syswarden_ordering_rpm_owner=
        if [ "${syswarden_ordering_rpm_owner}" = syswarden ]; then
            syswarden_ordering_authorities=$((syswarden_ordering_authorities + 1))
        fi
    fi
    [ "${syswarden_ordering_authorities}" -eq 1 ] || {
        printf 'Refusing an existing SysWarden systemd ordering drop-in without one exact package owner.\n' >&2
        return 1
    }

    if [ "$(stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_ordering_path}" 2>/dev/null)" != \
        "${syswarden_ordering_identity_before}" ] || \
        [ "$(sha256sum "${syswarden_ordering_path}" | awk '{ print $1 }')" != \
            "${syswarden_ordering_sha256}" ]; then
        printf 'SysWarden systemd ordering drop-in changed during package preflight.\n' >&2
        return 1
    fi
}

syswarden_preflight_systemd_socket_dropin() {
    [ ! -f /etc/alpine-release ] || return 0

    syswarden_socket_path=/usr/lib/systemd/system/syswarden-core.service.d/10-syswarden-socket-ownership.conf
    syswarden_socket_directory=/usr/lib/systemd/system/syswarden-core.service.d
    syswarden_socket_sha256=b1b4cc3937ea7464f6d86a40024ea7b7e8dc0dd12e4d0aa7a8b58f6dd0254186

    for syswarden_socket_parent in \
        /usr \
        /usr/lib \
        /usr/lib/systemd \
        /usr/lib/systemd/system; do
        if [ ! -d "${syswarden_socket_parent}" ] || \
            [ -L "${syswarden_socket_parent}" ] || \
            [ "$(stat -c '%u:%g' "${syswarden_socket_parent}" 2>/dev/null)" != 0:0 ] || \
            [ -n "$(find "${syswarden_socket_parent}" -maxdepth 0 -perm /0022 -print -quit 2>/dev/null)" ]; then
            printf 'Refusing unsafe systemd package parent: %s\n' \
                "${syswarden_socket_parent}" >&2
            return 1
        fi
    done

    if [ -e "${syswarden_socket_directory}" ] || [ -L "${syswarden_socket_directory}" ]; then
        if [ ! -d "${syswarden_socket_directory}" ] || \
            [ -L "${syswarden_socket_directory}" ] || \
            [ "$(stat -c '%u:%g' "${syswarden_socket_directory}" 2>/dev/null)" != 0:0 ] || \
            [ -n "$(find "${syswarden_socket_directory}" -maxdepth 0 -perm /0022 -print -quit 2>/dev/null)" ]; then
            printf 'Refusing unsafe SysWarden systemd drop-in directory: %s\n' \
                "${syswarden_socket_directory}" >&2
            return 1
        fi
        syswarden_socket_unexpected="$({
            find "${syswarden_socket_directory}" -mindepth 1 -maxdepth 1 \
                ! -path "${syswarden_socket_path}" -print -quit
        } 2>/dev/null)" || return 1
        [ -z "${syswarden_socket_unexpected}" ] || {
            printf 'Refusing an existing unowned systemd drop-in: %s\n' \
                "${syswarden_socket_unexpected}" >&2
            return 1
        }
    fi

    if [ ! -e "${syswarden_socket_path}" ] && [ ! -L "${syswarden_socket_path}" ]; then
        return 0
    fi
    if [ ! -f "${syswarden_socket_path}" ] || \
        [ -L "${syswarden_socket_path}" ] || \
        [ "$(stat -c '%u:%g:%a:%h:%s' "${syswarden_socket_path}" 2>/dev/null)" != 0:0:644:1:110 ]; then
        printf 'Refusing unsafe existing SysWarden systemd socket capability drop-in.\n' >&2
        return 1
    fi
    syswarden_socket_identity_before="$(
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_socket_path}"
    )" || return 1
    [ "$(sha256sum "${syswarden_socket_path}" | awk '{ print $1 }')" = \
        "${syswarden_socket_sha256}" ] || {
        printf 'Refusing modified existing SysWarden systemd socket capability drop-in.\n' >&2
        return 1
    }

    syswarden_socket_authorities=0
    if command -v dpkg-query >/dev/null 2>&1; then
        syswarden_socket_dpkg_files="$(dpkg-query --listfiles syswarden 2>/dev/null)" || \
            syswarden_socket_dpkg_files=
        if [ -n "${syswarden_socket_dpkg_files}" ] && \
            [ "$(printf '%s\n' "${syswarden_socket_dpkg_files}" | \
                awk -v path="${syswarden_socket_path}" '$0 == path { count++ } END { print count + 0 }')" -eq 1 ]; then
            syswarden_socket_authorities=$((syswarden_socket_authorities + 1))
        fi
    fi
    if command -v rpm >/dev/null 2>&1; then
        syswarden_socket_rpm_owner="$(
            rpm --query --file "${syswarden_socket_path}" \
                --queryformat '%{NAME}\n' 2>/dev/null
        )" || syswarden_socket_rpm_owner=
        if [ "${syswarden_socket_rpm_owner}" = syswarden ]; then
            syswarden_socket_authorities=$((syswarden_socket_authorities + 1))
        fi
    fi
    [ "${syswarden_socket_authorities}" -eq 1 ] || {
        printf 'Refusing an existing SysWarden systemd socket capability drop-in without one exact package owner.\n' >&2
        return 1
    }

    if [ "$(stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_socket_path}" 2>/dev/null)" != \
        "${syswarden_socket_identity_before}" ] || \
        [ "$(sha256sum "${syswarden_socket_path}" | awk '{ print $1 }')" != \
            "${syswarden_socket_sha256}" ]; then
        printf 'SysWarden systemd socket capability drop-in changed during package preflight.\n' >&2
        return 1
    fi
}
