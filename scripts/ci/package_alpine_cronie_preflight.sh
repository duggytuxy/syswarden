#!/bin/sh

# apk-tools 3.0 can continue a transaction after a failed pre-install hook and
# leave the package marked broken. Fresh installs therefore defer activation
# with a successful hook when their Cronie dependency is not ready yet. The
# post-install hook repeats the read-only check later in the fresh transaction,
# when dependencies can already be visible, and exits before any SysWarden
# configuration when activation still is not safe. Upgrade hooks fail before
# SysWarden configuration, but apk-tools 3.0 can still commit their payload and
# mark the package broken; fail-closed activation does not reverse that package
# transaction.
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

syswarden_alpine_apk_phase() {
    case "${APK_PACKAGE:-}:${APK_SCRIPT:-}" in
        syswarden:pre-install|syswarden:post-install)
            printf '%s\n' fresh
            ;;
        syswarden:pre-upgrade|syswarden:post-upgrade)
            printf '%s\n' upgrade
            ;;
        :)
            # Preserve strict behavior for direct/legacy script invocation.
            printf '%s\n' strict
            ;;
        *)
            printf 'Refusing unexpected Alpine package hook context: %s:%s\n' \
                "${APK_PACKAGE:-<unset>}" "${APK_SCRIPT:-<unset>}" >&2
            return 1
            ;;
    esac
}

syswarden_print_alpine_cronie_activation() {
    cat >&2 <<'EOF'
SysWarden activation is deferred until the current apk transaction is committed.
After apk completes successfully, prepare the single Cronie provider and activate SysWarden:
/bin/sh -eu <<'SYSWARDEN_ACTIVATE'
syswarden_parse_openrc_runlevels() {
    awk -F '|' '
        {
            service = $1
            levels = $2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", service)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", levels)
            if (service != "crond" && service != "cronie") next
            if (NF != 2 || ++service_lines[service] != 1) exit 1
            count = split(levels, item, /[[:space:]]+/)
            for (position = 1; position <= count; position++) {
                level = item[position]
                if (level == "") continue
                if (level !~ /^[A-Za-z0-9][A-Za-z0-9_.-]*$/) exit 1
                key = service SUBSEP level
                if (seen[key]++ != 0) continue
                if (++total[service] > 32) exit 1
                print service "|" level
            }
        }
        END { if (service_lines["cronie"] != 1) exit 1 }
    '
}
syswarden_remove_openrc_runlevels() {
    syswarden_service="$1"
    syswarden_enabled_runlevels="$2"
    case "${syswarden_service}" in
        crond|cronie) ;;
        *) return 1 ;;
    esac
    [ -n "${syswarden_enabled_runlevels}" ] || return 0
    printf '%s\n' "${syswarden_enabled_runlevels}" |
        while IFS= read -r syswarden_runlevel; do
            case "${syswarden_runlevel}" in
                ''|*[!A-Za-z0-9_.-]*) exit 1 ;;
            esac
            rc-update del "${syswarden_service}" "${syswarden_runlevel}"
        done
}
syswarden_attest_single_cronie_provider() {
    syswarden_runlevel_inventory="$(rc-update show -v)" || return 1
    printf '%s\n' "${syswarden_runlevel_inventory}" | awk -F '|' '
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
syswarden_openrc_service_state() {
    syswarden_service="$1"
    case "${syswarden_service}" in
        crond|cronie) ;;
        *) return 1 ;;
    esac
    if ! rc-service --exists "${syswarden_service}" >/dev/null 2>&1; then
        printf '%s\n' missing
        return 0
    fi
    syswarden_service_status=0
    rc-service "${syswarden_service}" status >/dev/null 2>&1 || \
        syswarden_service_status=$?
    case "${syswarden_service_status}" in
        0) printf '%s\n' active ;;
        3) printf '%s\n' inactive ;;
        *) return 1 ;;
    esac
}
syswarden_runlevel_inventory="$(rc-update show -v)"
syswarden_normalized_runlevels="$(
    printf '%s\n' "${syswarden_runlevel_inventory}" |
        syswarden_parse_openrc_runlevels
)"
syswarden_crond_runlevels="$(
    printf '%s\n' "${syswarden_normalized_runlevels}" |
        awk -F '|' '$1 == "crond" { print $2 }'
)"
syswarden_cronie_runlevels="$(
    printf '%s\n' "${syswarden_normalized_runlevels}" |
        awk -F '|' '$1 == "cronie" { print $2 }'
)"
syswarden_cronie_state="$(syswarden_openrc_service_state cronie)"
[ "${syswarden_cronie_state}" != missing ]
syswarden_crond_state="$(syswarden_openrc_service_state crond)"
if [ "${syswarden_crond_state}" = active ]; then
    rc-service crond stop
fi
syswarden_remove_openrc_runlevels crond "${syswarden_crond_runlevels}"
syswarden_remove_openrc_runlevels cronie "${syswarden_cronie_runlevels}"
rc-update add cronie default
if [ "${syswarden_cronie_state}" = inactive ]; then
    rc-service cronie start
fi
syswarden_crond_state="$(syswarden_openrc_service_state crond)"
if [ "${syswarden_crond_state}" = active ]; then
    printf '%s\n' 'BusyBox crond is still active after the requested stop.' >&2
    exit 1
fi
[ "$(syswarden_openrc_service_state cronie)" = active ]
syswarden_attest_single_cronie_provider
SYSWARDEN_PKG_INSTALL=1 /opt/syswarden/bin/syswarden-cli install
SYSWARDEN_ACTIVATE
EOF
}

syswarden_defer_or_reject_alpine_cronie() {
    syswarden_alpine_reason="$1"
    if [ "${syswarden_alpine_apk_phase}" = fresh ]; then
        printf '%s\n' "${syswarden_alpine_reason}" >&2
        syswarden_print_alpine_cronie_activation
        # Exit the maintainer script, rather than returning to its caller, so
        # no install barrier, migration, symlink, configuration, or service
        # mutation can run in this hook. apk still commits the package-owned
        # payload, which already includes both global launcher symlinks.
        exit 0
    fi
    printf '%s\n' "${syswarden_alpine_reason}" >&2
    return 1
}

syswarden_preflight_alpine_cronie() {
    [ -f /etc/alpine-release ] || return 0

    syswarden_alpine_apk_phase="$(syswarden_alpine_apk_phase)" || return 1

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
            syswarden_defer_or_reject_alpine_cronie \
                "Alpine installation requires ${syswarden_alpine_package} from a completed apk transaction before SysWarden activation."
        }
    done
    if ! rc-service --exists cronie >/dev/null 2>&1 || \
       ! rc-service cronie status >/dev/null 2>&1; then
        syswarden_defer_or_reject_alpine_cronie \
            'Alpine installation requires the Cronie OpenRC service to be active before SysWarden activation.'
    fi

    syswarden_alpine_runlevels="$(rc-update show -v 2>/dev/null)" || {
        printf '%s\n' 'Unable to inspect Alpine OpenRC runlevels before SysWarden installation.' >&2
        return 1
    }
    printf '%s\n' "${syswarden_alpine_runlevels}" | \
        syswarden_validate_alpine_cronie_runlevels || {
        syswarden_defer_or_reject_alpine_cronie \
            'Alpine installation requires Cronie in the default OpenRC runlevel only, with BusyBox crond absent from every runlevel.'
    }
    if rc-service --exists crond >/dev/null 2>&1 && \
       rc-service crond status >/dev/null 2>&1; then
        syswarden_defer_or_reject_alpine_cronie \
            'Alpine installation requires the BusyBox crond service to be inactive before SysWarden activation.'
    fi
}
