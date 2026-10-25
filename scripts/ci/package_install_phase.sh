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
                postinstall) SYSWARDEN_NATIVE_INSTALL_PHASE=fresh ;;
                postupgrade) SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade ;;
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
