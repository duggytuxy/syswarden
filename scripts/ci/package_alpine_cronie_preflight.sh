#!/bin/sh

# apk-tools executes package scripts before it commits the installed-package
# database. SysWarden therefore requires the Alpine cron provider to be a
# previously committed and operational host prerequisite. This check runs
# before any SysWarden installation state is created.
syswarden_validate_alpine_cronie_runlevels() {
    awk -F '|' '
        BEGIN { found = 0 }
        {
            service = $1
            levels = $2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", service)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", levels)
            if (service == "cronie") {
                if (NF != 2 || found != 0 || levels != "default") exit 1
                found = 1
            }
            if (service == "crond" && (NF != 2 || levels != "")) exit 1
        }
        END { if (found != 1) exit 1 }
    '
}

syswarden_preflight_alpine_cronie() {
    [ -f /etc/alpine-release ] || return 0

    syswarden_alpine_manager_state="$(
        syswarden_classify_service_manager / openrc
    )" || return 1
    case "${syswarden_alpine_manager_state}" in
        OFFLINE)
            return 0
            ;;
        ACTIVE) ;;
        *)
            printf '%s\n' 'Refusing Alpine installation with an ambiguous OpenRC runtime.' >&2
            return 1
            ;;
    esac

    for syswarden_alpine_command in apk rc-service rc-update; do
        command -v "${syswarden_alpine_command}" >/dev/null 2>&1 || {
            printf '%s\n' "Alpine installation requires ${syswarden_alpine_command}." >&2
            return 1
        }
    done
    for syswarden_alpine_package in cronie cronie-openrc; do
        apk info --installed "${syswarden_alpine_package}" >/dev/null 2>&1 || {
            printf '%s\n' "Alpine installation requires ${syswarden_alpine_package} to be installed in a completed apk transaction before SysWarden." >&2
            return 1
        }
    done
    if ! rc-service --exists cronie >/dev/null 2>&1 || \
       ! rc-service cronie status >/dev/null 2>&1; then
        printf '%s\n' 'Alpine installation requires the Cronie OpenRC service to be active before SysWarden.' >&2
        return 1
    fi

    syswarden_alpine_runlevels="$(rc-update show -v 2>/dev/null)" || {
        printf '%s\n' 'Unable to inspect Alpine OpenRC runlevels before SysWarden installation.' >&2
        return 1
    }
    printf '%s\n' "${syswarden_alpine_runlevels}" | \
        syswarden_validate_alpine_cronie_runlevels || {
        printf '%s\n' 'Alpine installation requires Cronie in the default OpenRC runlevel only, with BusyBox crond absent from every runlevel.' >&2
        return 1
    }
    if rc-service --exists crond >/dev/null 2>&1 && \
       rc-service crond status >/dev/null 2>&1; then
        printf '%s\n' 'Alpine installation requires the BusyBox crond service to be inactive before SysWarden.' >&2
        return 1
    fi
}
