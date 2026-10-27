#!/bin/sh

# Package phase only adds a conservative lifecycle guard. It does not authorize
# replacement of existing service files, masks, enablement or runtime state.
syswarden_set_native_install_phase() {
    SYSWARDEN_NATIVE_INSTALL_PHASE=unknown
    if [ "$#" -gt 0 ]; then
        syswarden_install_hook="$1"
        shift
        if [ -f /etc/alpine-release ]; then
            # APK 2 does not reliably expose APK_SCRIPT. These selectors are
            # fixed in the separate generated install and upgrade scripts.
            case "${syswarden_install_hook}" in
                preinstall|postinstall) SYSWARDEN_NATIVE_INSTALL_PHASE=fresh ;;
                preupgrade|postupgrade) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
            esac
        elif [ "${syswarden_install_hook}" = preinstall ]; then
            case "${1:-}" in
                install)
                    # dpkg install has no previous version on a fresh system.
                    # A retained old version is never interpreted as fresh.
                    if [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && [ -z "$2" ]; }; then
                        SYSWARDEN_NATIVE_INSTALL_PHASE=fresh
                    elif [ "$#" -eq 3 ] && [ -z "$2" ]; then
                        case "$3" in
                            *[!0-9A-Za-z.+:~-]*) ;;
                            [0-9]*) SYSWARDEN_NATIVE_INSTALL_PHASE=fresh ;;
                        esac
                    fi
                    ;;
                upgrade)
                    if [ "$#" -ge 2 ] && [ "$#" -le 3 ]; then
                        case "$2" in
                            *[!0-9A-Za-z.+:~-]*) ;;
                            [0-9]*) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
                        esac
                    fi
                    ;;
                ''|0*|*[!0-9]*) ;;
                *)
                    if [ "$#" -eq 1 ]; then
                        case "$1" in
                            1) SYSWARDEN_NATIVE_INSTALL_PHASE=fresh ;;
                            *) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
                        esac
                    fi
                    ;;
            esac
        elif [ "${syswarden_install_hook}" = postinstall ]; then
            case "${1:-}" in
                configure)
                    if [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && [ -z "$2" ]; }; then
                        SYSWARDEN_NATIVE_INSTALL_PHASE=fresh
                    elif [ "$#" -eq 2 ]; then
                        case "$2" in
                            *[!0-9A-Za-z.+:~-]*) ;;
                            [0-9]*) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
                        esac
                    fi
                    ;;
                ''|0*|*[!0-9]*) ;;
                *)
                    if [ "$#" -eq 1 ]; then
                        case "$1" in
                            1) SYSWARDEN_NATIVE_INSTALL_PHASE=fresh ;;
                            *) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
                        esac
                    fi
                    ;;
            esac
        fi
    fi
    export SYSWARDEN_NATIVE_INSTALL_PHASE
}

# The generated hook computes its phase from native arguments immediately
# before this gate. Inherited phase, qualification or package flags cannot
# authorize an upgrade. This refuses hook effects only; APK may have already
# evaluated or changed dependencies before invoking its package script.
syswarden_require_fresh_native_install() {
    if [ "${SYSWARDEN_NATIVE_INSTALL_PHASE:-unknown}" = fresh ]; then
        return 0
    fi
    printf '%s\n' 'Non-fresh native installation is refused before SysWarden hook effects. A separately approved coordinated native transaction is required.' >&2
    return 1
}

# Screen payload aliases before unpack and verify them after unpack. The package
# must not replace an administrator wrapper or redirect through a shared symlink.
# This read-only check assumes no concurrent privileged filesystem replacement.
syswarden_preflight_launchers() {
    [ "$#" -eq 2 ] || return 1
    syswarden_launcher_root="${1%/}"
    syswarden_launcher_phase="$2"
    case "${syswarden_launcher_phase}" in
        before|after) ;;
        *) return 1 ;;
    esac
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    for syswarden_launcher_parent in / /usr /usr/local /usr/local/bin; do
        syswarden_launcher_path="${syswarden_launcher_root}${syswarden_launcher_parent}"
        if [ -L "${syswarden_launcher_path}" ] || \
           { [ -e "${syswarden_launcher_path}" ] && [ ! -d "${syswarden_launcher_path}" ]; }; then
            printf '%s\n' 'Refusing package installation: unsafe command-launcher parent.' >&2
            return 1
        fi
        if [ -d "${syswarden_launcher_path}" ]; then
            syswarden_launcher_owner="$(stat -c '%u:%g' "${syswarden_launcher_path}")" || return 1
            syswarden_launcher_mode="$(stat -c '%a' "${syswarden_launcher_path}")" || return 1
            if [ "${syswarden_launcher_owner}" != 0:0 ] || \
               [ "$((0${syswarden_launcher_mode} & 0022))" -ne 0 ]; then
                printf '%s\n' 'Refusing package installation: command-launcher parent is not protected.' >&2
                return 1
            fi
        elif [ "${syswarden_launcher_phase}" = after ]; then
            printf '%s\n' 'Refusing package configuration: command-launcher parent is missing.' >&2
            return 1
        fi
    done
    for syswarden_launcher_name in syswarden syswarden-tui; do
        syswarden_launcher_path="${syswarden_launcher_root}/usr/local/bin/${syswarden_launcher_name}"
        case "${syswarden_launcher_name}" in
            syswarden) syswarden_launcher_target=/opt/syswarden/bin/syswarden-cli ;;
            syswarden-tui) syswarden_launcher_target=/opt/syswarden/bin/syswarden-tui ;;
        esac
        if [ ! -e "${syswarden_launcher_path}" ] && [ ! -L "${syswarden_launcher_path}" ]; then
            [ "${syswarden_launcher_phase}" = before ] && continue
            printf '%s\n' 'Refusing package configuration: command launcher is missing.' >&2
            return 1
        fi
        if [ ! -L "${syswarden_launcher_path}" ] || \
           [ "$(stat -c '%u:%g:%h' "${syswarden_launcher_path}")" != 0:0:1 ] || \
           [ "$(stat -c '%s' "${syswarden_launcher_path}")" -ne "${#syswarden_launcher_target}" ] || \
           [ "$(readlink "${syswarden_launcher_path}")" != "${syswarden_launcher_target}" ]; then
            printf '%s\n' 'Refusing package installation: preserve the existing administrator command launcher and resolve its collision before retrying.' >&2
            return 1
        fi
    done
}
