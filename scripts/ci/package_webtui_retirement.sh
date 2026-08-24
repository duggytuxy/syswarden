#!/bin/sh

# One-release package compatibility helper. This code retires only the exact
# legacy browser service and credential owned by SysWarden.

syswarden_normalize_webtui_root() {
    syswarden_webtui_root_input="$1"
    case "${syswarden_webtui_root_input}" in
        ''|/)
            SYSWARDEN_NORMALIZED_WEBTUI_ROOT=
            ;;
        /*)
            case "${syswarden_webtui_root_input}" in
                *//*|*/./*|*/../*|*/.|*/..) return 1 ;;
            esac
            SYSWARDEN_NORMALIZED_WEBTUI_ROOT="${syswarden_webtui_root_input%/}"
            [ -n "${SYSWARDEN_NORMALIZED_WEBTUI_ROOT}" ] || return 1
            ;;
        *)
            return 1
            ;;
    esac
    syswarden_webtui_root_path="${SYSWARDEN_NORMALIZED_WEBTUI_ROOT:-/}"
    [ ! -L "${syswarden_webtui_root_path}" ] && [ -d "${syswarden_webtui_root_path}" ]
}

syswarden_webtui_root_identity() {
    [ "$#" -eq 1 ] && [ -n "$1" ] || return 1
    [ ! -L "$1" ] && [ -d "$1" ] || return 1
    stat -c '%d:%i:%u:%g:%a' "$1" 2>/dev/null
}

syswarden_safe_runtime_object() {
    syswarden_runtime_object="$1"
    syswarden_runtime_kind="$2"
    syswarden_runtime_owner="$3"
    [ ! -L "${syswarden_runtime_object}" ] || return 1
    case "${syswarden_runtime_kind}" in
        directory) [ -d "${syswarden_runtime_object}" ] || return 1 ;;
        file) [ -f "${syswarden_runtime_object}" ] || return 1 ;;
        *) return 1 ;;
    esac
    syswarden_runtime_metadata="$(stat -c '%u:%g:%a' "${syswarden_runtime_object}" 2>/dev/null)" || return 1
    case "${syswarden_runtime_metadata}" in
        "${syswarden_runtime_owner}":*) ;;
        *) return 1 ;;
    esac
    syswarden_runtime_mode="${syswarden_runtime_metadata##*:}"
    case "${syswarden_runtime_mode}" in
        *[2367][0-7]|*[0-7][2367]) return 1 ;;
    esac
}

syswarden_attest_openrc_runtime() {
    syswarden_openrc_root="$1"
    syswarden_openrc_runtime="$2"
    syswarden_openrc_owner="$3"
    syswarden_openrc_softlevel="${syswarden_openrc_runtime}/softlevel"
    syswarden_openrc_comm="${syswarden_openrc_root}/proc/1/comm"
    [ ! -L "${syswarden_openrc_runtime}" ] && [ -d "${syswarden_openrc_runtime}" ] || return 1
    syswarden_openrc_runtime_metadata="$(
        stat -c '%u:%g:%a' "${syswarden_openrc_runtime}" 2>/dev/null
    )" || return 1
    case "${syswarden_openrc_runtime_metadata}" in
        "${syswarden_openrc_owner}":755|"${syswarden_openrc_owner}":775) ;;
        *) return 1 ;;
    esac
    syswarden_openrc_runtime_before="$(
        stat -c '%d:%i:%f:%u:%g:%a:%s:%Y:%Z' "${syswarden_openrc_runtime}" 2>/dev/null
    )" || return 1
    syswarden_safe_runtime_object "${syswarden_openrc_softlevel}" file "${syswarden_openrc_owner}" || return 1
    syswarden_openrc_softlevel_before="$(stat -c '%d:%i:%u:%g:%a:%s:%Y:%Z' "${syswarden_openrc_softlevel}" 2>/dev/null)" || return 1
    syswarden_openrc_softlevel_digest_before="$(
        sha256sum "${syswarden_openrc_softlevel}" 2>/dev/null | awk '{ print $1 }'
    )" || return 1
    case "${syswarden_openrc_softlevel_digest_before}" in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "${#syswarden_openrc_softlevel_digest_before}" -eq 64 ] || return 1
    syswarden_openrc_softlevel_size="$(wc -c < "${syswarden_openrc_softlevel}" | tr -d ' ')" || return 1
    case "${syswarden_openrc_softlevel_size}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${syswarden_openrc_softlevel_size}" -le 64 ] || return 1
    syswarden_openrc_level="$(sed -n '1p' "${syswarden_openrc_softlevel}" 2>/dev/null)" || return 1
    [ -n "${syswarden_openrc_level}" ] || return 1
    case "${syswarden_openrc_level}" in *[!A-Za-z0-9_.-]*) return 1 ;; esac
    case "${syswarden_openrc_softlevel_size}" in
        "${#syswarden_openrc_level}") ;;
        "$((${#syswarden_openrc_level} + 1))")
            syswarden_openrc_softlevel_tail="$(
                tail -c 1 "${syswarden_openrc_softlevel}" 2>/dev/null |
                    od -An -tx1 | tr -d ' \n'
            )" || return 1
            [ "${syswarden_openrc_softlevel_tail}" = 0a ] || return 1
            ;;
        *) return 1 ;;
    esac
    syswarden_safe_runtime_object "${syswarden_openrc_softlevel}" file "${syswarden_openrc_owner}" || return 1
    [ "$(stat -c '%d:%i:%u:%g:%a:%s:%Y:%Z' "${syswarden_openrc_softlevel}" 2>/dev/null)" = \
        "${syswarden_openrc_softlevel_before}" ] || return 1
    [ "$(sha256sum "${syswarden_openrc_softlevel}" 2>/dev/null | awk '{ print $1 }')" = \
        "${syswarden_openrc_softlevel_digest_before}" ] || return 1
    syswarden_safe_runtime_object "${syswarden_openrc_comm}" file "${syswarden_openrc_owner}" || return 1
    [ "$(wc -c < "${syswarden_openrc_comm}" | tr -d ' ')" -le 32 ] || return 1
    syswarden_openrc_identity="$(cat "${syswarden_openrc_comm}" 2>/dev/null)" || return 1
    case "${syswarden_openrc_identity}" in init|openrc-init) ;; *) return 1 ;; esac
    [ "$(wc -c < "${syswarden_openrc_comm}" | tr -d ' ')" -eq "$((${#syswarden_openrc_identity} + 1))" ] || return 1
    syswarden_safe_runtime_object "${syswarden_openrc_comm}" file "${syswarden_openrc_owner}" || return 1
    [ "$(stat -c '%d:%i:%f:%u:%g:%a:%s:%Y:%Z' "${syswarden_openrc_runtime}" 2>/dev/null)" = \
        "${syswarden_openrc_runtime_before}" ] || return 1
    [ "$(stat -c '%u:%g:%a' "${syswarden_openrc_runtime}" 2>/dev/null)" = \
        "${syswarden_openrc_runtime_metadata}" ] || return 1
    return 0
}

syswarden_attest_systemd_runtime() {
    syswarden_systemd_root="$1"
    syswarden_systemd_owner="$2"
    syswarden_systemd_comm="${syswarden_systemd_root}/proc/1/comm"
    syswarden_systemd_exe="${syswarden_systemd_root}/proc/1/exe"
    syswarden_safe_runtime_object "${syswarden_systemd_comm}" file "${syswarden_systemd_owner}" || return 1
    [ "$(wc -c < "${syswarden_systemd_comm}" | tr -d ' ')" -eq 8 ] || return 1
    [ "$(cat "${syswarden_systemd_comm}" 2>/dev/null)" = systemd ] || return 1
    syswarden_safe_runtime_object "${syswarden_systemd_comm}" file "${syswarden_systemd_owner}" || return 1
    [ -L "${syswarden_systemd_exe}" ] || return 1
    syswarden_systemd_exe_before="$(stat -c '%d:%i:%u:%g' "${syswarden_systemd_exe}" 2>/dev/null)" || return 1
    case "${syswarden_systemd_exe_before}" in *:"${syswarden_systemd_owner}") ;; *) return 1 ;; esac
    syswarden_systemd_target="$(readlink "${syswarden_systemd_exe}" 2>/dev/null)" || return 1
    case "${syswarden_systemd_target}" in /usr/lib/systemd/systemd|/lib/systemd/systemd) ;; *) return 1 ;; esac
    [ "$(stat -c '%d:%i:%u:%g' "${syswarden_systemd_exe}" 2>/dev/null)" = "${syswarden_systemd_exe_before}" ] || return 1
    [ "$(readlink "${syswarden_systemd_exe}" 2>/dev/null)" = "${syswarden_systemd_target}" ] || return 1
}

# Print ACTIVE, OFFLINE, or AMBIGUOUS. OFFLINE is possible only inside an
# explicitly marked package transaction with both manager runtimes absent.
syswarden_classify_service_manager() {
    syswarden_manager_root="${1%/}"
    syswarden_manager_kind="$2"
    syswarden_manager_scope="${3:-strict}"
    syswarden_manager_run="${syswarden_manager_root}/run"
    [ -n "${syswarden_manager_root}" ] || syswarden_manager_root=/
    syswarden_manager_owner="$(stat -c '%u:%g' "${syswarden_manager_root}" 2>/dev/null)" || {
        printf '%s\n' AMBIGUOUS
        return 0
    }
    if ! syswarden_safe_runtime_object "${syswarden_manager_run}" directory "${syswarden_manager_owner}"; then
        printf '%s\n' AMBIGUOUS
        return 0
    fi
    case "${syswarden_manager_kind}" in
        systemd)
            syswarden_manager_expected="${syswarden_manager_run}/systemd/system"
            syswarden_manager_competing="${syswarden_manager_run}/openrc"
            ;;
        openrc)
            syswarden_manager_expected="${syswarden_manager_run}/openrc"
            syswarden_manager_competing="${syswarden_manager_run}/systemd/system"
            ;;
        *)
            printf '%s\n' AMBIGUOUS
            return 0
            ;;
    esac
    syswarden_manager_systemd_parent="${syswarden_manager_run}/systemd"
    if { [ -e "${syswarden_manager_systemd_parent}" ] || [ -L "${syswarden_manager_systemd_parent}" ]; } && \
       ! syswarden_safe_runtime_object "${syswarden_manager_systemd_parent}" directory "${syswarden_manager_owner}"; then
        printf '%s\n' AMBIGUOUS
        return 0
    fi
    for syswarden_manager_path in "${syswarden_manager_expected}" "${syswarden_manager_competing}"; do
        if [ "${syswarden_manager_kind}" = openrc ] && \
           [ "${syswarden_manager_path}" = "${syswarden_manager_expected}" ]; then
            if [ -L "${syswarden_manager_path}" ] || \
               { [ -e "${syswarden_manager_path}" ] && [ ! -d "${syswarden_manager_path}" ]; }; then
                printf '%s\n' AMBIGUOUS
                return 0
            fi
            continue
        fi
        if { [ -e "${syswarden_manager_path}" ] || [ -L "${syswarden_manager_path}" ]; } && \
           ! syswarden_safe_runtime_object "${syswarden_manager_path}" directory "${syswarden_manager_owner}"; then
            printf '%s\n' AMBIGUOUS
            return 0
        fi
    done
    if [ -d "${syswarden_manager_competing}" ] && [ "${syswarden_manager_scope}" != isolated ]; then
        printf '%s\n' AMBIGUOUS
    elif [ -d "${syswarden_manager_expected}" ]; then
        if [ "${syswarden_manager_kind}" = openrc ] && \
           ! syswarden_attest_openrc_runtime "${syswarden_manager_root}" "${syswarden_manager_expected}" "${syswarden_manager_owner}"; then
            printf '%s\n' AMBIGUOUS
        elif [ "${syswarden_manager_kind}" = systemd ] && \
             ! syswarden_attest_systemd_runtime "${syswarden_manager_root}" "${syswarden_manager_owner}"; then
            printf '%s\n' AMBIGUOUS
        else
            printf '%s\n' ACTIVE
        fi
    elif [ "${SYSWARDEN_PKG_INSTALL:-}" = 1 ]; then
        printf '%s\n' OFFLINE
    else
        printf '%s\n' AMBIGUOUS
    fi
}

syswarden_require_offline_service_manager() {
    [ "$(syswarden_classify_service_manager "$1" "$2" "${3:-strict}")" = OFFLINE ] || {
        printf '%s\n' 'Service-manager runtime changed during offline retirement' >&2
        return 1
    }
}

syswarden_package_runtime_is_offline() {
    syswarden_offline_root="$1"
    [ "${SYSWARDEN_PKG_INSTALL:-}" = 1 ] || return 1
    [ "$(syswarden_classify_service_manager "${syswarden_offline_root}" systemd isolated)" = OFFLINE ] || return 1
    [ "$(syswarden_classify_service_manager "${syswarden_offline_root}" openrc isolated)" = OFFLINE ] || return 1
}

syswarden_remove_exact_service_enablement() {
    syswarden_service_link="$1"
    shift
    [ -e "${syswarden_service_link}" ] || [ -L "${syswarden_service_link}" ] || return 0
    [ -L "${syswarden_service_link}" ] || {
        printf 'Refusing modified SysWarden service enablement: %s\n' "${syswarden_service_link}" >&2
        return 1
    }
    syswarden_service_actual_target="$(readlink "${syswarden_service_link}" 2>/dev/null || true)"
    syswarden_service_target_allowed=0
    for syswarden_service_target in "$@"; do
        if [ "${syswarden_service_actual_target}" = "${syswarden_service_target}" ]; then
            syswarden_service_target_allowed=1
            break
        fi
    done
    if [ "${syswarden_service_target_allowed}" -ne 1 ]; then
        printf 'Refusing modified SysWarden service enablement: %s\n' "${syswarden_service_link}" >&2
        return 1
    fi
    rm -f -- "${syswarden_service_link}" || return 1
    sync -f "$(dirname "${syswarden_service_link}")" || return 1
}

syswarden_remove_exact_service_file() {
    syswarden_service_file="$1"
    syswarden_service_hash="$2"
    syswarden_service_mode="$3"
    [ -e "${syswarden_service_file}" ] || [ -L "${syswarden_service_file}" ] || return 0
    if [ -L "${syswarden_service_file}" ] || [ ! -f "${syswarden_service_file}" ] || \
       [ "$(stat -c '%u:%g:%a' "${syswarden_service_file}" 2>/dev/null || true)" != "0:0:${syswarden_service_mode}" ] || \
       [ "$(sha256sum "${syswarden_service_file}" 2>/dev/null | awk '{ print $1 }')" != "${syswarden_service_hash}" ]; then
        printf 'Refusing modified SysWarden service file: %s\n' "${syswarden_service_file}" >&2
        return 1
    fi
    rm -f -- "${syswarden_service_file}" || return 1
    sync -f "$(dirname "${syswarden_service_file}")" || return 1
}

syswarden_remove_exact_product_services() {
    syswarden_service_manager="$1"
    case "${syswarden_service_manager}" in
        systemd)
            syswarden_remove_exact_service_enablement \
                /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
                ../syswarden-core.service \
                /etc/systemd/system/syswarden-core.service || return 1
            syswarden_remove_exact_service_enablement \
                /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
                ../syswarden-firewall.service \
                /etc/systemd/system/syswarden-firewall.service || return 1
            syswarden_remove_exact_service_file \
                /etc/systemd/system/syswarden-core.service \
                8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd 600 || return 1
            syswarden_remove_exact_service_file \
                /etc/systemd/system/syswarden-firewall.service \
                989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1 600 || return 1
            ;;
        openrc)
            syswarden_remove_exact_service_enablement \
                /etc/runlevels/default/syswarden-core /etc/init.d/syswarden-core || return 1
            syswarden_remove_exact_service_enablement \
                /etc/runlevels/default/syswarden-firewall /etc/init.d/syswarden-firewall || return 1
            syswarden_remove_exact_service_file \
                /etc/init.d/syswarden-core \
                99adff6d6bcb6c5f0fad472e11668d3f8f4e19136c3b3ce473493101db136558 755 || return 1
            syswarden_remove_exact_service_file \
                /etc/init.d/syswarden-firewall \
                d8c57c59dae9493523275026acb2a5c599bd4949ff8993add6760e725f89a5ba 755 || return 1
            ;;
        *) return 1 ;;
    esac
}

syswarden_retire_stale_webtui_pid() {
    syswarden_retire_root="$1"
    syswarden_retire_pid_path="${syswarden_retire_root}/run/syswarden-webtui.pid"
    if [ -L "${syswarden_retire_pid_path}" ]; then
        printf '%s\n' 'Refusing a symlinked legacy Web-TUI PID file' >&2
        return 1
    fi
    [ -e "${syswarden_retire_pid_path}" ] || return 0
    if [ ! -f "${syswarden_retire_pid_path}" ] || \
       [ "$(wc -c < "${syswarden_retire_pid_path}" | tr -d ' ')" -gt 32 ]; then
        printf '%s\n' 'Refusing an invalid legacy Web-TUI PID file' >&2
        return 1
    fi
    syswarden_retire_pid="$(cat "${syswarden_retire_pid_path}")"
    case "${syswarden_retire_pid}" in
        ''|*[!0-9]*)
            printf '%s\n' 'Refusing invalid legacy Web-TUI PID content' >&2
            return 1
            ;;
    esac
    if kill -0 "${syswarden_retire_pid}" 2>/dev/null; then
        # A stale PID can be reused by an unrelated process. The executable and
        # argv scan is the authority: never signal a process solely from this
        # historical PID file, and remove the stale owned file only after the
        # exact process inventory is proven empty.
        if ! syswarden_verify_no_exact_webtui_process "${syswarden_retire_root}"; then
            printf '%s\n' 'An exact legacy Web-TUI process remains live after service retirement' >&2
            return 1
        fi
    fi
    rm -f -- "${syswarden_retire_pid_path}" || return 1
    if [ -e "${syswarden_retire_pid_path}" ] || [ -L "${syswarden_retire_pid_path}" ]; then
        printf '%s\n' 'Legacy Web-TUI PID file remains after retirement' >&2
        return 1
    fi
}

syswarden_retire_offline_webtui_pid() {
    syswarden_retire_pid_path="${1}/run/syswarden-webtui.pid"
    [ ! -L "${syswarden_retire_pid_path}" ] || {
        printf '%s\n' 'Refusing a symlinked legacy Web-TUI PID file' >&2
        return 1
    }
    [ -e "${syswarden_retire_pid_path}" ] || return 0
    [ -f "${syswarden_retire_pid_path}" ] || return 1
    [ "$(wc -c < "${syswarden_retire_pid_path}" | tr -d ' ')" -le 32 ] || return 1
    syswarden_retire_pid="$(cat "${syswarden_retire_pid_path}")"
    case "${syswarden_retire_pid}" in ''|*[!0-9]*) return 1 ;; esac
    rm -f -- "${syswarden_retire_pid_path}" || return 1
    [ ! -e "${syswarden_retire_pid_path}" ] && [ ! -L "${syswarden_retire_pid_path}" ]
}

syswarden_validate_exact_webtui_enablement() {
    syswarden_retire_enablement="$1"
    syswarden_retire_enablement_kind="$2"
    [ -e "${syswarden_retire_enablement}" ] || [ -L "${syswarden_retire_enablement}" ] || return 0
    if [ ! -L "${syswarden_retire_enablement}" ]; then
        printf 'Refusing a non-symlink legacy Web-TUI enablement path: %s\n' "${syswarden_retire_enablement}" >&2
        return 1
    fi
    syswarden_retire_enablement_target="$(readlink "${syswarden_retire_enablement}" 2>/dev/null || true)"
    case "${syswarden_retire_enablement_kind}:${syswarden_retire_enablement_target}" in
        systemd:../syswarden-webtui.service|\
        systemd:/etc/systemd/system/syswarden-webtui.service|\
        openrc:/etc/init.d/syswarden-webtui|\
        openrc:../../init.d/syswarden-webtui)
            ;;
        *)
            printf 'Refusing a modified legacy Web-TUI enablement link: %s\n' "${syswarden_retire_enablement}" >&2
            return 1
            ;;
    esac
}

syswarden_remove_exact_webtui_enablement() {
    syswarden_retire_enablement="$1"
    syswarden_retire_enablement_kind="$2"
    syswarden_validate_exact_webtui_enablement \
        "${syswarden_retire_enablement}" "${syswarden_retire_enablement_kind}" || return 1
    [ -e "${syswarden_retire_enablement}" ] || [ -L "${syswarden_retire_enablement}" ] || return 0
    rm -f -- "${syswarden_retire_enablement}" || return 1
    if [ -e "${syswarden_retire_enablement}" ] || [ -L "${syswarden_retire_enablement}" ]; then
        printf 'Legacy Web-TUI enablement remains after retirement: %s\n' "${syswarden_retire_enablement}" >&2
        return 1
    fi
    sync -f "$(dirname "${syswarden_retire_enablement}")" || return 1
}

# Return 0 only for an attestable live OpenRC runtime, 1 only when the runtime
# is provably absent, and 2 for an unsafe or ambiguous runtime surface.
syswarden_openrc_runtime_available() {
    syswarden_retire_root="$1"
    syswarden_retire_root_identity="${syswarden_retire_root:-/}"
    syswarden_retire_run="${syswarden_retire_root}/run"
    syswarden_retire_runtime="${syswarden_retire_run}/openrc"
    syswarden_retire_owner="$(stat -c '%u:%g' "${syswarden_retire_root_identity}" 2>/dev/null)" || return 2
    if ! syswarden_safe_runtime_object "${syswarden_retire_run}" directory "${syswarden_retire_owner}"; then
        printf '%s\n' 'Refusing an unsafe OpenRC runtime parent' >&2
        return 2
    fi
    if [ ! -e "${syswarden_retire_runtime}" ] && [ ! -L "${syswarden_retire_runtime}" ]; then
        return 1
    fi
    if ! syswarden_attest_openrc_runtime \
        "${syswarden_retire_root}" "${syswarden_retire_runtime}" "${syswarden_retire_owner}"; then
        printf '%s\n' 'Refusing an ambiguous OpenRC runtime directory' >&2
        return 2
    fi
    return 0
}

syswarden_read_exact_webtui_unit() {
    syswarden_retire_unit_path="$1"
    syswarden_retire_unit_kind="$2"
    if [ -L "${syswarden_retire_unit_path}" ] || [ ! -f "${syswarden_retire_unit_path}" ]; then
        printf 'Refusing an unsafe legacy Web-TUI unit path: %s\n' "${syswarden_retire_unit_path}" >&2
        return 1
    fi
    if [ "$(wc -c < "${syswarden_retire_unit_path}" | tr -d ' ')" -gt 65536 ]; then
        printf 'Legacy Web-TUI unit exceeds the cleanup limit: %s\n' "${syswarden_retire_unit_path}" >&2
        return 1
    fi
    syswarden_retire_expected="$(mktemp "${syswarden_retire_unit_path}.expected.XXXXXX")" || return 1
    case "${syswarden_retire_unit_kind}" in
        systemd)
            printf '%s\n' \
                '[Unit]' \
                'Description=SYSWARDEN Web-TUI (WebTTY)' \
                'After=network-online.target' \
                'Wants=network-online.target' \
                '' \
                '[Service]' \
                'Type=simple' \
                'User=root' \
                'ExecStart=/opt/syswarden/bin/syswarden-cli web-tui' \
                'Restart=on-failure' \
                'RestartSec=5s' \
                '' \
                '# Security Hardening' \
                'ProtectSystem=full' \
                'ProtectHome=yes' \
                'NoNewPrivileges=true' \
                'PrivateTmp=true' \
                '' \
                '[Install]' \
                'WantedBy=multi-user.target' > "${syswarden_retire_expected}" || return 1
            ;;
        openrc)
            printf '%s\n' \
                '#!/sbin/openrc-run' \
                '' \
                'name="syswarden-webtui"' \
                'description="SYSWARDEN Web-TUI (WebTTY)"' \
                'command="/opt/syswarden/bin/syswarden-cli"' \
                'command_args="web-tui"' \
                'command_background=true' \
                'pidfile="/run/syswarden-webtui.pid"' \
                'retry="TERM/5/KILL/5"' \
                '' \
                'depend() {' \
                '	need net' \
                '}' > "${syswarden_retire_expected}" || return 1
            ;;
        *)
            rm -f -- "${syswarden_retire_expected}"
            return 1
            ;;
    esac
    if ! cmp -s "${syswarden_retire_expected}" "${syswarden_retire_unit_path}"; then
        rm -f -- "${syswarden_retire_expected}"
        printf 'Refusing a modified legacy Web-TUI unit: %s\n' "${syswarden_retire_unit_path}" >&2
        return 1
    fi
    rm -f -- "${syswarden_retire_expected}" || return 1
}

syswarden_assert_no_webtui_manager_overrides() {
    syswarden_retire_root="$1"
    syswarden_retire_manager="$2"
    case "${syswarden_retire_manager}" in
        systemd)
            set -- \
                "${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service.d" \
                "${syswarden_retire_root}/run/systemd/system/syswarden-webtui.service" \
                "${syswarden_retire_root}/run/systemd/system/syswarden-webtui.service.d"
            ;;
        openrc)
            set -- "${syswarden_retire_root}/etc/conf.d/syswarden-webtui"
            ;;
        *)
            printf '%s\n' 'Refusing an unknown legacy Web-TUI service manager' >&2
            return 1
            ;;
    esac
    for syswarden_retire_override in "$@"; do
        if [ -e "${syswarden_retire_override}" ] || [ -L "${syswarden_retire_override}" ]; then
            printf 'Refusing a legacy Web-TUI manager override: %s\n' "${syswarden_retire_override}" >&2
            return 1
        fi
    done
}

syswarden_read_systemd_webtui_property() {
    syswarden_retire_property="$1"
    syswarden_retire_property_file="$(mktemp /tmp/syswarden-webtui-systemd.XXXXXX)" || return 1
    if ! LC_ALL=C systemctl show syswarden-webtui.service \
        "--property=${syswarden_retire_property}" --value > "${syswarden_retire_property_file}"; then
        rm -f -- "${syswarden_retire_property_file}"
        printf 'Unable to attest the loaded legacy Web-TUI %s\n' "${syswarden_retire_property}" >&2
        return 1
    fi
    if [ -L "${syswarden_retire_property_file}" ] || \
       [ ! -f "${syswarden_retire_property_file}" ] || \
       [ "$(wc -c < "${syswarden_retire_property_file}" | tr -d ' ')" -gt 4096 ] || \
       ! awk 'END { exit NR == 1 ? 0 : 1 }' "${syswarden_retire_property_file}"; then
        rm -f -- "${syswarden_retire_property_file}"
        printf 'Refusing an ambiguous loaded legacy Web-TUI %s\n' "${syswarden_retire_property}" >&2
        return 1
    fi
    cat "${syswarden_retire_property_file}"
    syswarden_retire_property_status=$?
    rm -f -- "${syswarden_retire_property_file}" || return 1
    return "${syswarden_retire_property_status}"
}

syswarden_attest_boundary_owned_parent_chain() {
    syswarden_chain_boundary="$1"
    syswarden_chain_path="$2"
    syswarden_chain_owner="$3"
    syswarden_chain_parent="$(dirname "${syswarden_chain_path}")" || return 1
    while :; do
        [ ! -L "${syswarden_chain_parent}" ] && [ -d "${syswarden_chain_parent}" ] || return 1
        syswarden_chain_metadata="$(stat -c '%u:%g:%a' "${syswarden_chain_parent}" 2>/dev/null)" || return 1
        case "${syswarden_chain_metadata}" in "${syswarden_chain_owner}":*) ;; *) return 1 ;; esac
        syswarden_chain_mode="${syswarden_chain_metadata##*:}"
        case "${syswarden_chain_mode}" in *[2367][0-7]|*[0-7][2367]) return 1 ;; esac
        [ "${syswarden_chain_parent}" != "${syswarden_chain_boundary}" ] || return 0
        syswarden_chain_next="$(dirname "${syswarden_chain_parent}")" || return 1
        [ "${syswarden_chain_next}" != "${syswarden_chain_parent}" ] || return 1
        syswarden_chain_parent="${syswarden_chain_next}"
    done
}

syswarden_attest_approved_systemd_service_dropins() {
    syswarden_retire_root="$1"
    syswarden_retire_dropins="$2"
    [ -n "${syswarden_retire_dropins}" ] || return 0
    syswarden_retire_approved_dropin="${syswarden_retire_root}/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
    if [ "${syswarden_retire_dropins}" != "${syswarden_retire_approved_dropin}" ]; then
        printf '%s\n' 'Refusing a loaded legacy Web-TUI unit with unapproved drop-ins' >&2
        return 1
    fi
    syswarden_retire_boundary="${syswarden_retire_root:-/}"
    syswarden_retire_boundary_owner="$(stat -c '%u:%g' "${syswarden_retire_boundary}" 2>/dev/null)" || return 1
    syswarden_attest_boundary_owned_parent_chain "${syswarden_retire_boundary}" \
        "${syswarden_retire_approved_dropin}" "${syswarden_retire_boundary_owner}" || {
        printf '%s\n' 'Refusing an unsafe approved systemd drop-in parent chain' >&2
        return 1
    }
    if [ -L "${syswarden_retire_approved_dropin}" ] || [ ! -f "${syswarden_retire_approved_dropin}" ] || \
       [ "$(stat -c '%u:%g:%a:%h:%s' "${syswarden_retire_approved_dropin}" 2>/dev/null || true)" != \
         "${syswarden_retire_boundary_owner}:644:1:596" ]; then
        printf '%s\n' 'Refusing approved systemd drop-in with inexact metadata' >&2
        return 1
    fi
    syswarden_retire_dropin_before="$({
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        stat -Lc '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        sha256sum "${syswarden_retire_approved_dropin}" | awk '{ print $1 }'
    } 2>/dev/null)" || return 1
    syswarden_retire_expected_dropin_sha=ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37
    [ "$(printf '%s\n' "${syswarden_retire_dropin_before}" | sed -n '3p')" = \
        "${syswarden_retire_expected_dropin_sha}" ] || {
        printf '%s\n' 'Refusing approved systemd drop-in with inexact bytes' >&2
        return 1
    }
    syswarden_retire_rpm_path="$(command -v rpm 2>/dev/null)" || return 1
    syswarden_retire_rpm="$(readlink -f -- "${syswarden_retire_rpm_path}" 2>/dev/null)" || return 1
    syswarden_retire_expected_rpm="${syswarden_retire_root}/usr/bin/rpm"
    if [ "${syswarden_retire_rpm}" != "${syswarden_retire_expected_rpm}" ] || \
       [ -L "${syswarden_retire_rpm}" ] || [ ! -f "${syswarden_retire_rpm}" ] || \
       [ "$(stat -c '%u:%g:%a:%h' "${syswarden_retire_rpm}" 2>/dev/null || true)" != \
         "${syswarden_retire_boundary_owner}:755:1" ] || \
       ! syswarden_attest_boundary_owned_parent_chain "${syswarden_retire_boundary}" \
            "${syswarden_retire_rpm}" "${syswarden_retire_boundary_owner}"; then
        printf '%s\n' 'Refusing an untrusted RPM executable for approved systemd drop-in attestation' >&2
        return 1
    fi
    syswarden_retire_rpm_before="$({
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_rpm}" &&
        stat -Lc '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_rpm}"
    } 2>/dev/null)" || return 1
    syswarden_retire_owner_one="$(mktemp /tmp/syswarden-webtui-rpm-owner.XXXXXX)" || return 1
    syswarden_retire_files_one="$(mktemp /tmp/syswarden-webtui-rpm-files.XXXXXX)" || {
        rm -f -- "${syswarden_retire_owner_one}"
        return 1
    }
    syswarden_retire_digests_one="$(mktemp /tmp/syswarden-webtui-rpm-digests.XXXXXX)" || {
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}"
        return 1
    }
    syswarden_retire_owner_two="$(mktemp /tmp/syswarden-webtui-rpm-owner.XXXXXX)" || {
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" "${syswarden_retire_digests_one}"
        return 1
    }
    syswarden_retire_files_two="$(mktemp /tmp/syswarden-webtui-rpm-files.XXXXXX)" || {
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}"
        return 1
    }
    syswarden_retire_digests_two="$(mktemp /tmp/syswarden-webtui-rpm-digests.XXXXXX)" || {
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" "${syswarden_retire_files_two}"
        return 1
    }
    for syswarden_retire_metadata_file in \
        "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
        "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
        "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"; do
        if [ -L "${syswarden_retire_metadata_file}" ] || [ ! -f "${syswarden_retire_metadata_file}" ] || \
           [ "$(stat -c '%u:%g:%a:%h' "${syswarden_retire_metadata_file}" 2>/dev/null || true)" != \
             "${syswarden_retire_boundary_owner}:600:1" ]; then
            rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
                "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
                "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
            printf '%s\n' 'Refusing unsafe temporary RPM metadata evidence' >&2
            return 1
        fi
    done
    if ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '%{NAME}\t%{EVR}\t%{ARCH}\t%{FILEDIGESTALGO}\n' > "${syswarden_retire_owner_one}" || \
       ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '[%{FILENAMES}\n]' > "${syswarden_retire_files_one}" || \
       ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '[%{FILEDIGESTS}\n]' > "${syswarden_retire_digests_one}"; then
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
            "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
        printf '%s\n' 'Unable to attest approved systemd drop-in RPM metadata' >&2
        return 1
    fi
    syswarden_retire_machine="$(uname -m 2>/dev/null)" || syswarden_retire_machine=
    case "${syswarden_retire_machine}" in x86_64|aarch64) ;; *) syswarden_retire_machine=invalid ;; esac
    if [ -L "${syswarden_retire_owner_one}" ] || [ ! -f "${syswarden_retire_owner_one}" ] || \
       [ "$(wc -c < "${syswarden_retire_owner_one}" | tr -d ' ')" -gt 4096 ] || \
       ! awk -F '\t' -v expected_arch="${syswarden_retire_machine}" '
            NF != 4 { bad = 1 }
            $1 != "systemd" || $2 !~ /^[A-Za-z0-9.+:~_-]+$/ || length($2) > 128 ||
                $3 != expected_arch || $4 != "8" { bad = 1 }
            { count++ }
            END { exit !(count == 1 && !bad) }
        ' "${syswarden_retire_owner_one}" || \
       [ "$(wc -c < "${syswarden_retire_files_one}" | tr -d ' ')" -gt 65536 ] || \
       [ "$(wc -c < "${syswarden_retire_digests_one}" | tr -d ' ')" -gt 65536 ] || \
       ! awk -v wanted="${syswarden_retire_approved_dropin}" \
           -v expected_digest="${syswarden_retire_expected_dropin_sha}" '
            FILENAME == ARGV[1] { digests[FNR] = $0; digest_count = FNR; next }
            { file_count = FNR; if ($0 == wanted) { matches++; if (digests[FNR] != expected_digest) bad = 1 } }
            END { exit !(digest_count == file_count && file_count > 0 && matches == 1 && !bad) }
        ' "${syswarden_retire_digests_one}" "${syswarden_retire_files_one}"; then
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
            "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
        printf '%s\n' 'Refusing unproven approved systemd drop-in RPM metadata' >&2
        return 1
    fi
    syswarden_retire_dropin_after="$({
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        stat -Lc '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        sha256sum "${syswarden_retire_approved_dropin}" | awk '{ print $1 }'
    } 2>/dev/null)" || syswarden_retire_dropin_after=
    if [ "${syswarden_retire_dropin_after}" != "${syswarden_retire_dropin_before}" ] || \
       ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '%{NAME}\t%{EVR}\t%{ARCH}\t%{FILEDIGESTALGO}\n' > "${syswarden_retire_owner_two}" || \
       ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '[%{FILENAMES}\n]' > "${syswarden_retire_files_two}" || \
       ! LC_ALL=C "${syswarden_retire_rpm}" --query --file "${syswarden_retire_approved_dropin}" \
        --queryformat '[%{FILEDIGESTS}\n]' > "${syswarden_retire_digests_two}" || \
       ! cmp -s "${syswarden_retire_owner_one}" "${syswarden_retire_owner_two}" || \
       ! cmp -s "${syswarden_retire_files_one}" "${syswarden_retire_files_two}" || \
       ! cmp -s "${syswarden_retire_digests_one}" "${syswarden_retire_digests_two}"; then
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
            "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
        printf '%s\n' 'Approved systemd drop-in or RPM metadata changed during attestation' >&2
        return 1
    fi
    syswarden_retire_dropin_final="$({
        stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        stat -Lc '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_approved_dropin}" &&
        sha256sum "${syswarden_retire_approved_dropin}" | awk '{ print $1 }'
    } 2>/dev/null)" || syswarden_retire_dropin_final=
    if [ "${syswarden_retire_dropin_final}" != "${syswarden_retire_dropin_before}" ] || \
       ! syswarden_attest_boundary_owned_parent_chain "${syswarden_retire_boundary}" \
            "${syswarden_retire_approved_dropin}" "${syswarden_retire_boundary_owner}" || \
       [ "$({
            stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_rpm}" &&
            stat -Lc '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "${syswarden_retire_rpm}"
          } 2>/dev/null)" != "${syswarden_retire_rpm_before}" ] || \
       ! syswarden_attest_boundary_owned_parent_chain "${syswarden_retire_boundary}" \
            "${syswarden_retire_rpm}" "${syswarden_retire_boundary_owner}"; then
        rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
            "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
            "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
        printf '%s\n' 'Approved systemd drop-in changed after RPM metadata reattestation' >&2
        return 1
    fi
    for syswarden_retire_metadata_file in \
        "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
        "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
        "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"; do
        [ ! -L "${syswarden_retire_metadata_file}" ] && [ -f "${syswarden_retire_metadata_file}" ] && \
            [ "$(stat -c '%u:%g:%a:%h' "${syswarden_retire_metadata_file}" 2>/dev/null || true)" = \
              "${syswarden_retire_boundary_owner}:600:1" ] || {
            rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
                "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
                "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}"
            return 1
        }
    done
    rm -f -- "${syswarden_retire_owner_one}" "${syswarden_retire_files_one}" \
        "${syswarden_retire_digests_one}" "${syswarden_retire_owner_two}" \
        "${syswarden_retire_files_two}" "${syswarden_retire_digests_two}" || return 1
}

syswarden_attest_systemd_webtui_runtime() {
    if ! syswarden_normalize_webtui_root "$1"; then
        printf '%s\n' 'Refusing an unsafe legacy Web-TUI retirement root' >&2
        return 1
    fi
    syswarden_retire_root="${SYSWARDEN_NORMALIZED_WEBTUI_ROOT}"
    syswarden_systemd_attest_root="${syswarden_retire_root:-/}"
    syswarden_systemd_attest_root_before="$(
        syswarden_webtui_root_identity "${syswarden_systemd_attest_root}"
    )" || {
        printf '%s\n' 'Unable to attest the legacy Web-TUI retirement root' >&2
        return 1
    }
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    syswarden_retire_load_state="$(syswarden_read_systemd_webtui_property LoadState)" || return 1
    if [ "${syswarden_retire_load_state}" != loaded ]; then
        printf '%s\n' 'Refusing a legacy Web-TUI unit that is not loaded normally' >&2
        return 1
    fi
    syswarden_retire_fragment="$(syswarden_read_systemd_webtui_property FragmentPath)" || return 1
    if [ "${syswarden_retire_fragment}" != "${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service" ]; then
        printf '%s\n' 'Refusing a legacy Web-TUI unit loaded from an unexpected fragment' >&2
        return 1
    fi
    syswarden_retire_dropins="$(syswarden_read_systemd_webtui_property DropInPaths)" || return 1
    syswarden_attest_approved_systemd_service_dropins \
        "${syswarden_retire_root}" "${syswarden_retire_dropins}" || return 1
    syswarden_retire_execstart="$(syswarden_read_systemd_webtui_property ExecStart)" || return 1
    if ! printf '%s\n' "${syswarden_retire_execstart}" | LC_ALL=C awk '
        /^[{] path=\/opt\/syswarden\/bin\/syswarden-cli ; argv\[\]=\/opt\/syswarden\/bin\/syswarden-cli web-tui ; ignore_errors=(yes|no) ; start_time=[^;]* ; stop_time=[^;]* ; pid=[0-9]+ ; code=[^;]* ; status=[^;]* [}]$/ {
            exact = 1
        }
        END { exit NR == 1 && exact ? 0 : 1 }
    '; then
        printf '%s\n' 'Refusing an unexpected loaded legacy Web-TUI ExecStart' >&2
        return 1
    fi
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    if [ "$(syswarden_webtui_root_identity "${syswarden_systemd_attest_root}" 2>/dev/null || true)" != \
         "${syswarden_systemd_attest_root_before}" ]; then
        printf '%s\n' 'Legacy Web-TUI retirement root changed during systemd attestation' >&2
        return 1
    fi
}

syswarden_retire_cached_systemd_webtui() {
    syswarden_retire_root="$1"
    syswarden_retire_wants="$2"
    command -v systemctl >/dev/null 2>&1 || {
        printf '%s\n' 'systemctl is required to inspect the cached legacy Web-TUI unit' >&2
        return 1
    }
    syswarden_retire_load_state="$(syswarden_read_systemd_webtui_property LoadState)" || return 1
    case "${syswarden_retire_load_state}" in
        not-found)
            syswarden_retire_active_state="$(syswarden_read_systemd_webtui_property ActiveState)" || return 1
            if [ "${syswarden_retire_active_state}" != inactive ]; then
                printf '%s\n' 'Refusing a non-inactive legacy Web-TUI service without an attestable loaded unit' >&2
                return 1
            fi
            syswarden_remove_exact_webtui_enablement "${syswarden_retire_wants}" systemd
            return $?
            ;;
        loaded)
            syswarden_attest_systemd_webtui_runtime "${syswarden_retire_root}" || return 1
            ;;
        *)
            printf '%s\n' 'Refusing an ambiguous cached legacy Web-TUI load state' >&2
            return 1
            ;;
    esac
    syswarden_attest_systemd_webtui_runtime "${syswarden_retire_root}" || return 1
    systemctl stop syswarden-webtui.service || return 1
    syswarden_retire_active_state="$(syswarden_read_systemd_webtui_property ActiveState)" || return 1
    case "${syswarden_retire_active_state}" in
        inactive|failed) ;;
        *)
            printf '%s\n' 'Cached legacy Web-TUI service remains live after synchronous stop' >&2
            return 1
            ;;
    esac
    syswarden_remove_exact_webtui_enablement "${syswarden_retire_wants}" systemd || return 1
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    systemctl daemon-reload || return 1
    syswarden_retire_load_state="$(syswarden_read_systemd_webtui_property LoadState)" || return 1
    if [ "${syswarden_retire_load_state}" != not-found ]; then
        printf '%s\n' 'Cached legacy Web-TUI unit remains loaded after daemon reload' >&2
        return 1
    fi
    syswarden_retire_active_state="$(syswarden_read_systemd_webtui_property ActiveState)" || return 1
    if [ "${syswarden_retire_active_state}" != inactive ]; then
        printf '%s\n' 'Legacy Web-TUI service resurrected after daemon reload' >&2
        return 1
    fi
    return 0
}

syswarden_retire_systemd_webtui() {
    syswarden_retire_root="$1"
    syswarden_retire_unit="${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service"
    syswarden_retire_wants="${syswarden_retire_root}/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
    syswarden_retire_pending="${syswarden_retire_unit}.syswarden-retiring"
    if [ ! -e "${syswarden_retire_unit}" ] && [ ! -L "${syswarden_retire_unit}" ] && \
       [ ! -e "${syswarden_retire_pending}" ] && [ ! -L "${syswarden_retire_pending}" ] && \
       [ ! -e "${syswarden_retire_wants}" ] && [ ! -L "${syswarden_retire_wants}" ] && \
       [ ! -e "${syswarden_retire_root}/run/systemd/system" ] && \
       [ ! -L "${syswarden_retire_root}/run/systemd/system" ]; then
        return 0
    fi
    syswarden_retire_systemd_state="$(syswarden_classify_service_manager "${syswarden_retire_root}" systemd isolated)"
    [ "${syswarden_retire_systemd_state}" != AMBIGUOUS ] || {
        printf '%s\n' 'Refusing an ambiguous systemd runtime' >&2
        return 1
    }
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    if [ -e "${syswarden_retire_pending}" ] || [ -L "${syswarden_retire_pending}" ]; then
        if [ -e "${syswarden_retire_unit}" ] || [ -L "${syswarden_retire_unit}" ]; then
            printf '%s\n' 'Both active and pending legacy Web-TUI units exist' >&2
            return 1
        fi
        syswarden_read_exact_webtui_unit "${syswarden_retire_pending}" systemd || return 1
        mv -f -- "${syswarden_retire_pending}" "${syswarden_retire_unit}" || return 1
    fi
    if [ ! -e "${syswarden_retire_unit}" ] && [ ! -L "${syswarden_retire_unit}" ]; then
        if [ "${syswarden_retire_systemd_state}" = ACTIVE ]; then
            syswarden_retire_cached_systemd_webtui \
                "${syswarden_retire_root}" "${syswarden_retire_wants}"
            return $?
        fi
        syswarden_require_offline_service_manager "${syswarden_retire_root}" systemd isolated || return 1
        syswarden_remove_exact_webtui_enablement "${syswarden_retire_wants}" systemd
        syswarden_retire_status=$?
        [ "${syswarden_retire_status}" -eq 0 ] || return "${syswarden_retire_status}"
        syswarden_require_offline_service_manager "${syswarden_retire_root}" systemd isolated
        return $?
    fi
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" systemd || return 1
    if [ "${syswarden_retire_systemd_state}" = OFFLINE ]; then
        syswarden_require_offline_service_manager "${syswarden_retire_root}" systemd isolated || return 1
        syswarden_remove_exact_webtui_enablement "${syswarden_retire_wants}" systemd || return 1
        syswarden_require_offline_service_manager "${syswarden_retire_root}" systemd isolated || return 1
        syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" systemd || return 1
        rm -f -- "${syswarden_retire_unit}" || return 1
        sync -f "$(dirname "${syswarden_retire_unit}")" || return 1
        syswarden_require_offline_service_manager "${syswarden_retire_root}" systemd isolated || return 1
        return 0
    fi
    command -v systemctl >/dev/null 2>&1 || {
        printf '%s\n' 'systemctl is required to retire the legacy Web-TUI unit' >&2
        return 1
    }
    syswarden_attest_systemd_webtui_runtime "${syswarden_retire_root}" || return 1
        if systemctl is-active --quiet syswarden-webtui.service; then
            syswarden_attest_systemd_webtui_runtime "${syswarden_retire_root}" || return 1
            systemctl stop syswarden-webtui.service || return 1
        else
            syswarden_retire_status=$?
            case "${syswarden_retire_status}" in
                3|4) ;;
                *)
                    printf 'Unable to prove legacy Web-TUI inactivity: systemctl exit %s\n' "${syswarden_retire_status}" >&2
                    return 1
                    ;;
            esac
        fi
        if systemctl is-active --quiet syswarden-webtui.service; then
            printf '%s\n' 'Legacy Web-TUI service remains active after stop' >&2
            return 1
        else
            syswarden_retire_status=$?
            case "${syswarden_retire_status}" in
                3|4) ;;
                *)
                    printf 'Unable to verify legacy Web-TUI stop: systemctl exit %s\n' "${syswarden_retire_status}" >&2
                    return 1
                    ;;
            esac
        fi
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    if [ -e "${syswarden_retire_wants}" ] || [ -L "${syswarden_retire_wants}" ]; then
        systemctl disable syswarden-webtui.service || return 1
    fi
    syswarden_remove_exact_webtui_enablement "${syswarden_retire_wants}" systemd || return 1
    mv -f -- "${syswarden_retire_unit}" "${syswarden_retire_pending}" || return 1
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" systemd || return 1
    if ! systemctl daemon-reload; then
        mv -f -- "${syswarden_retire_pending}" "${syswarden_retire_unit}" || return 1
        sync -f "$(dirname "${syswarden_retire_unit}")" || return 1
        return 1
    fi
    rm -f -- "${syswarden_retire_pending}" || return 1
    sync -f "$(dirname "${syswarden_retire_unit}")" || return 1
    if [ -e "${syswarden_retire_unit}" ] || [ -L "${syswarden_retire_unit}" ] || \
       [ -e "${syswarden_retire_pending}" ] || [ -L "${syswarden_retire_pending}" ]; then
        printf '%s\n' 'Legacy Web-TUI systemd unit remains after retirement' >&2
        return 1
    fi
}

syswarden_retire_openrc_webtui() {
    syswarden_retire_root="$1"
    syswarden_retire_unit="${syswarden_retire_root}/etc/init.d/syswarden-webtui"
    syswarden_retire_runlevel="${syswarden_retire_root}/etc/runlevels/default/syswarden-webtui"
    if [ ! -e "${syswarden_retire_unit}" ] && [ ! -L "${syswarden_retire_unit}" ] && \
       [ ! -e "${syswarden_retire_runlevel}" ] && [ ! -L "${syswarden_retire_runlevel}" ] && \
       [ ! -e "${syswarden_retire_root}/etc/conf.d/syswarden-webtui" ] && \
       [ ! -L "${syswarden_retire_root}/etc/conf.d/syswarden-webtui" ] && \
       [ ! -e "${syswarden_retire_root}/run/openrc" ] && \
       [ ! -L "${syswarden_retire_root}/run/openrc" ]; then
        return 0
    fi
    syswarden_retire_openrc_state="$(syswarden_classify_service_manager "${syswarden_retire_root}" openrc isolated)"
    [ "${syswarden_retire_openrc_state}" != AMBIGUOUS ] || {
        printf '%s\n' 'Refusing an ambiguous OpenRC runtime' >&2
        return 1
    }
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" openrc || return 1
    if [ ! -e "${syswarden_retire_unit}" ] && [ ! -L "${syswarden_retire_unit}" ]; then
        if [ "${syswarden_retire_openrc_state}" = OFFLINE ]; then
            syswarden_require_offline_service_manager "${syswarden_retire_root}" openrc isolated || return 1
        fi
        syswarden_remove_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc
        syswarden_retire_status=$?
        [ "${syswarden_retire_status}" -eq 0 ] || return "${syswarden_retire_status}"
        if [ "${syswarden_retire_openrc_state}" = OFFLINE ]; then
            syswarden_require_offline_service_manager "${syswarden_retire_root}" openrc isolated || return 1
        fi
        return 0
    fi
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
    syswarden_validate_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
    if [ "${syswarden_retire_openrc_state}" = OFFLINE ]; then
        # OpenRC cannot hold a cached service when its runtime is absent. Keep
        # the exact on-disk unit and enablement as the only removal authority;
        # the caller's exact /proc inventory remains the process authority.
        syswarden_require_offline_service_manager "${syswarden_retire_root}" openrc isolated || return 1
        syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" openrc || return 1
        syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
        syswarden_remove_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
        syswarden_require_offline_service_manager "${syswarden_retire_root}" openrc isolated || return 1
        syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
        rm -f -- "${syswarden_retire_unit}" || return 1
        sync -f "$(dirname "${syswarden_retire_unit}")" || return 1
        if [ -e "${syswarden_retire_unit}" ] || [ -L "${syswarden_retire_unit}" ]; then
            printf '%s\n' 'Legacy Web-TUI OpenRC unit remains after offline retirement' >&2
            return 1
        fi
        syswarden_require_offline_service_manager "${syswarden_retire_root}" openrc isolated || return 1
        return 0
    fi
    if ! command -v rc-service >/dev/null 2>&1 || ! command -v rc-update >/dev/null 2>&1; then
        printf '%s\n' 'OpenRC tools are required to retire the legacy Web-TUI service' >&2
        return 1
    fi
    syswarden_openrc_runtime_available "${syswarden_retire_root}" || return 1
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
    syswarden_validate_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
    if rc-service syswarden-webtui status >/dev/null 2>&1; then
        syswarden_openrc_runtime_available "${syswarden_retire_root}" || return 1
        syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" openrc || return 1
        syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
        syswarden_validate_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
        rc-service syswarden-webtui stop || return 1
    else
        syswarden_retire_status=$?
        [ "${syswarden_retire_status}" -eq 3 ] || {
            printf 'Unable to prove legacy Web-TUI inactivity: rc-service exit %s\n' "${syswarden_retire_status}" >&2
            return 1
        }
    fi
    syswarden_openrc_runtime_available "${syswarden_retire_root}" || return 1
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
    syswarden_validate_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
    if rc-service syswarden-webtui status >/dev/null 2>&1; then
        printf '%s\n' 'Legacy Web-TUI OpenRC service remains active after stop' >&2
        return 1
    else
        syswarden_retire_status=$?
        [ "${syswarden_retire_status}" -eq 3 ] || {
            printf 'Unable to verify legacy Web-TUI stop: rc-service exit %s\n' "${syswarden_retire_status}" >&2
            return 1
        }
    fi
    syswarden_openrc_runtime_available "${syswarden_retire_root}" || return 1
    syswarden_assert_no_webtui_manager_overrides "${syswarden_retire_root}" openrc || return 1
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
    syswarden_validate_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
    if [ -e "${syswarden_retire_runlevel}" ] || [ -L "${syswarden_retire_runlevel}" ]; then
        rc-update del syswarden-webtui default || return 1
        sync -f "$(dirname "${syswarden_retire_runlevel}")" || return 1
    fi
    syswarden_remove_exact_webtui_enablement "${syswarden_retire_runlevel}" openrc || return 1
    syswarden_read_exact_webtui_unit "${syswarden_retire_unit}" openrc || return 1
    rm -f -- "${syswarden_retire_unit}" || return 1
    sync -f "$(dirname "${syswarden_retire_unit}")" || return 1
    if [ -e "${syswarden_retire_unit}" ] || [ -L "${syswarden_retire_unit}" ]; then
        printf '%s\n' 'Legacy Web-TUI OpenRC unit remains after retirement' >&2
        return 1
    fi
}

syswarden_webtui_process_starttime() {
    syswarden_retire_stat_path="$1"
    sed 's/^.*) //' "${syswarden_retire_stat_path}" 2>/dev/null | \
        awk 'NF >= 20 { print $20; found = 1 } END { exit found ? 0 : 1 }'
}

# Return 0 when argv[1] is exactly web-tui, 1 for another subcommand, and 2
# when the NUL-delimited command line cannot be bounded and decoded safely.
syswarden_webtui_cmdline_matches() {
    syswarden_retire_process_root="$1"
    syswarden_retire_cmdline="$(mktemp /tmp/syswarden-webtui-cmdline.XXXXXX)" || return 2
    if ! dd if="${syswarden_retire_process_root}/cmdline" of="${syswarden_retire_cmdline}" \
        bs=65537 count=1 2>/dev/null; then
        rm -f -- "${syswarden_retire_cmdline}"
        [ -d "${syswarden_retire_process_root}" ] || return 1
        return 2
    fi
    syswarden_retire_cmdline_size="$(wc -c < "${syswarden_retire_cmdline}" | tr -d ' ')"
    if [ "${syswarden_retire_cmdline_size}" -gt 65536 ]; then
        rm -f -- "${syswarden_retire_cmdline}"
        return 2
    fi
    syswarden_retire_cmdline_hex="$(od -An -tx1 -v "${syswarden_retire_cmdline}" | tr -d '[:space:]')"
    rm -f -- "${syswarden_retire_cmdline}" || return 2
    case "${syswarden_retire_cmdline_hex}" in
        *00*) syswarden_retire_after_argv0="${syswarden_retire_cmdline_hex#*00}" ;;
        *) return 2 ;;
    esac
    case "${syswarden_retire_after_argv0}" in
        7765622d74756900*) return 0 ;;
        *) return 1 ;;
    esac
}

# Return 0 for an exact process match, 1 for a different or vanished process,
# and 2 when a process using the attested executable cannot be inspected.
syswarden_webtui_process_matches() {
    syswarden_retire_pid="$1"
    syswarden_retire_proc_root="$2"
    syswarden_retire_executable="$3"
    syswarden_retire_expected_identity="$4"
    syswarden_retire_process_root="${syswarden_retire_proc_root}/${syswarden_retire_pid}"
    syswarden_retire_process_identity="$(stat -L -c '%d:%i' "${syswarden_retire_process_root}/exe" 2>/dev/null || true)"
    [ -n "${syswarden_retire_process_identity}" ] || return 1
    [ "${syswarden_retire_process_identity}" = "${syswarden_retire_expected_identity}" ] || return 1
    syswarden_retire_starttime="$(syswarden_webtui_process_starttime "${syswarden_retire_process_root}/stat" 2>/dev/null || true)"
    if [ -z "${syswarden_retire_starttime}" ]; then
        [ ! -d "${syswarden_retire_process_root}" ] && return 1
        return 2
    fi
    if syswarden_webtui_cmdline_matches "${syswarden_retire_process_root}"; then
        syswarden_retire_argv_match=1
    else
        syswarden_retire_cmdline_status=$?
        [ "${syswarden_retire_cmdline_status}" -ne 2 ] || return 2
        syswarden_retire_argv_match=0
    fi
    syswarden_retire_after_identity="$(stat -L -c '%d:%i' "${syswarden_retire_process_root}/exe" 2>/dev/null || true)"
    syswarden_retire_after_starttime="$(syswarden_webtui_process_starttime "${syswarden_retire_process_root}/stat" 2>/dev/null || true)"
    if [ "${syswarden_retire_after_identity}" != "${syswarden_retire_process_identity}" ] || \
       [ "${syswarden_retire_after_starttime}" != "${syswarden_retire_starttime}" ]; then
        return 1
    fi
    [ "${syswarden_retire_argv_match}" -eq 1 ] || return 1
    SYSWARDEN_MATCHED_WEBTUI_STARTTIME="${syswarden_retire_starttime}"
    return 0
}

syswarden_find_exact_webtui_processes() {
    syswarden_retire_root="$1"
    syswarden_retire_proc_root="${2:-/proc}"
    syswarden_retire_executable="${3:-${syswarden_retire_root}/opt/syswarden/bin/syswarden-cli}"
    SYSWARDEN_MATCHED_WEBTUI_PROCESSES=
    for syswarden_retire_proc in "${syswarden_retire_proc_root}"/[0-9]*; do
        [ -d "${syswarden_retire_proc}" ] || continue
        syswarden_retire_exe_link="$(readlink "${syswarden_retire_proc}/exe" 2>/dev/null || true)"
        [ "${syswarden_retire_exe_link}" = "${syswarden_retire_executable} (deleted)" ] || continue
        if syswarden_webtui_cmdline_matches "${syswarden_retire_proc}"; then
            printf '%s\n' 'A deleted legacy Web-TUI executable is still live and cannot be identity-attested' >&2
            return 2
        else
            syswarden_retire_cmdline_status=$?
            [ "${syswarden_retire_cmdline_status}" -ne 2 ] || return 2
        fi
    done
    if [ -L "${syswarden_retire_executable}" ]; then
        printf '%s\n' 'Refusing a symlinked SysWarden CLI while proving Web-TUI retirement' >&2
        return 2
    fi
    if [ -e "${syswarden_retire_executable}" ] && [ ! -f "${syswarden_retire_executable}" ]; then
        printf '%s\n' 'Refusing a non-regular SysWarden CLI while proving Web-TUI retirement' >&2
        return 2
    fi
    if [ ! -f "${syswarden_retire_executable}" ]; then
        return 0
    fi
    syswarden_retire_expected_identity="$(stat -L -c '%d:%i' "${syswarden_retire_executable}")" || return 2
    for syswarden_retire_proc in "${syswarden_retire_proc_root}"/[0-9]*; do
        [ -d "${syswarden_retire_proc}" ] || continue
        syswarden_retire_pid="${syswarden_retire_proc##*/}"
        case "${syswarden_retire_pid}" in
            ''|*[!0-9]*) continue ;;
        esac
        if syswarden_webtui_process_matches \
            "${syswarden_retire_pid}" "${syswarden_retire_proc_root}" \
            "${syswarden_retire_executable}" "${syswarden_retire_expected_identity}"; then
            SYSWARDEN_MATCHED_WEBTUI_PROCESSES="${SYSWARDEN_MATCHED_WEBTUI_PROCESSES} ${syswarden_retire_pid}:${SYSWARDEN_MATCHED_WEBTUI_STARTTIME}"
        else
            syswarden_retire_match_status=$?
            [ "${syswarden_retire_match_status}" -ne 2 ] || return 2
        fi
    done
    return 0
}

syswarden_verify_no_exact_webtui_process() {
    syswarden_find_exact_webtui_processes "$@" || return 1
    [ -z "${SYSWARDEN_MATCHED_WEBTUI_PROCESSES}" ]
}

syswarden_retire_exact_webtui_processes() {
    syswarden_retire_root="$1"
    syswarden_retire_proc_root="${2:-/proc}"
    syswarden_retire_executable="${3:-${syswarden_retire_root}/opt/syswarden/bin/syswarden-cli}"
    syswarden_find_exact_webtui_processes \
        "${syswarden_retire_root}" "${syswarden_retire_proc_root}" "${syswarden_retire_executable}" || return 1
    syswarden_retire_processes="${SYSWARDEN_MATCHED_WEBTUI_PROCESSES}"
    syswarden_retire_expected_identity="$(stat -L -c '%d:%i' "${syswarden_retire_executable}" 2>/dev/null || true)"
    for syswarden_retire_process in ${syswarden_retire_processes}; do
        syswarden_retire_pid="$(
            printf '%s\n' "${syswarden_retire_process}" |
                LC_ALL=C awk -F ':' 'NR == 1 { print $1; exit }'
        )" || return 1
        syswarden_retire_starttime="${syswarden_retire_process#*:}"
        if syswarden_webtui_process_matches \
            "${syswarden_retire_pid}" "${syswarden_retire_proc_root}" \
            "${syswarden_retire_executable}" "${syswarden_retire_expected_identity}"; then
            [ "${SYSWARDEN_MATCHED_WEBTUI_STARTTIME}" = "${syswarden_retire_starttime}" ] || continue
            kill -TERM "${syswarden_retire_pid}" || return 1
        else
            syswarden_retire_match_status=$?
            [ "${syswarden_retire_match_status}" -ne 2 ] || return 1
            continue
        fi
        syswarden_retire_wait=0
        while [ "${syswarden_retire_wait}" -lt 20 ]; do
            if syswarden_webtui_process_matches \
                "${syswarden_retire_pid}" "${syswarden_retire_proc_root}" \
                "${syswarden_retire_executable}" "${syswarden_retire_expected_identity}"; then
                [ "${SYSWARDEN_MATCHED_WEBTUI_STARTTIME}" = "${syswarden_retire_starttime}" ] || break
            else
                syswarden_retire_match_status=$?
                [ "${syswarden_retire_match_status}" -ne 2 ] || return 1
                break
            fi
            sleep 0.1
            syswarden_retire_wait=$((syswarden_retire_wait + 1))
        done
        if syswarden_webtui_process_matches \
            "${syswarden_retire_pid}" "${syswarden_retire_proc_root}" \
            "${syswarden_retire_executable}" "${syswarden_retire_expected_identity}" && \
           [ "${SYSWARDEN_MATCHED_WEBTUI_STARTTIME}" = "${syswarden_retire_starttime}" ]; then
            kill -KILL "${syswarden_retire_pid}" || return 1
        fi
    done
    syswarden_verify_no_exact_webtui_process \
        "${syswarden_retire_root}" "${syswarden_retire_proc_root}" "${syswarden_retire_executable}" || {
        printf '%s\n' 'An exact legacy Web-TUI process remains after bounded retirement' >&2
        return 1
    }
}

syswarden_clean_webtui_config_file() {
    syswarden_retire_config="$1"
    if [ -L "${syswarden_retire_config}" ] || [ ! -f "${syswarden_retire_config}" ]; then
        printf 'Refusing an unsafe configuration file during Web-TUI retirement: %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    if [ "$(wc -c < "${syswarden_retire_config}" | tr -d ' ')" -gt 8388608 ]; then
        printf 'Configuration file exceeds the Web-TUI cleanup limit: %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    syswarden_retire_identity="$(stat -c '%d:%i' "${syswarden_retire_config}")" || return 1
    syswarden_retire_mode="$(stat -c '%a' "${syswarden_retire_config}")" || return 1
    syswarden_retire_owner="$(stat -c '%u:%g' "${syswarden_retire_config}")" || return 1
    syswarden_retire_size="$(wc -c < "${syswarden_retire_config}" | tr -d '[:space:]')" || return 1
    case "${syswarden_retire_size}" in
        ''|*[!0-9]*)
            printf 'Unable to determine configuration size during Web-TUI retirement: %s\n' "${syswarden_retire_config}" >&2
            return 1
            ;;
    esac
    syswarden_retire_final_newline=0
    if [ "${syswarden_retire_size}" -gt 0 ]; then
        syswarden_retire_last_octet="$(tail -c 1 "${syswarden_retire_config}" | od -An -tu1 -v | tr -d '[:space:]')" || return 1
        case "${syswarden_retire_last_octet}" in
            10) syswarden_retire_final_newline=1 ;;
            ''|*[!0-9]*)
                printf 'Unable to inspect configuration termination during Web-TUI retirement: %s\n' "${syswarden_retire_config}" >&2
                return 1
                ;;
        esac
    fi
    syswarden_retire_temp="$(mktemp "${syswarden_retire_config}.webtui-retire.XXXXXX")" || return 1
    if ! LC_ALL=C awk -v final_newline="${syswarden_retire_final_newline}" '
        BEGIN { in_user = 0; have_output = 0 }
        /^[[:space:]]*\[/ {
            in_user = ($0 ~ /^[[:space:]]*\[[[:space:]]*(user|"user"|\047user\047)[[:space:]]*\][[:space:]]*(#.*)?$/)
        }
        {
            user_key = "(webtui_password|\"webtui_password\"|\047webtui_password\047)"
            table_assignment = "^[[:space:]]*" user_key "[[:space:]]*="
            dotted_assignment = "^[[:space:]]*(user|\"user\"|\047user\047)[[:space:]]*\\.[[:space:]]*" user_key "[[:space:]]*="
            if ((in_user && $0 ~ table_assignment) || $0 ~ dotted_assignment) {
                value = $0
                if (in_user) {
                    sub(table_assignment, "", value)
                } else {
                    sub(dotted_assignment, "", value)
                }
                if (value ~ /^[[:space:]]*"[^"]*"[[:space:]]*(#.*)?$/ ||
                    value ~ /^[[:space:]]*\047[^\047]*\047[[:space:]]*(#.*)?$/) {
                    next
                }
                exit 42
            }
            if (have_output) {
                print buffered
            }
            buffered = $0
            have_output = 1
        }
        END {
            if (have_output) {
                printf "%s", buffered
                if (final_newline) {
                    printf "%s", ORS
                }
            }
        }
    ' "${syswarden_retire_config}" > "${syswarden_retire_temp}"; then
        rm -f -- "${syswarden_retire_temp}"
        printf 'Unable to safely remove the legacy Web-TUI credential from %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    if grep -Fq 'webtui_password' "${syswarden_retire_temp}"; then
        rm -f -- "${syswarden_retire_temp}"
        printf 'Ambiguous legacy Web-TUI credential syntax remains in %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    if cmp -s "${syswarden_retire_config}" "${syswarden_retire_temp}"; then
        rm -f -- "${syswarden_retire_temp}"
        sync -f "$(dirname "${syswarden_retire_config}")" || return 1
        return 0
    fi
    if [ -L "${syswarden_retire_config}" ] || \
       [ "$(stat -c '%d:%i' "${syswarden_retire_config}" 2>/dev/null || true)" != "${syswarden_retire_identity}" ]; then
        rm -f -- "${syswarden_retire_temp}"
        printf 'Configuration file changed during Web-TUI retirement: %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    chown "${syswarden_retire_owner}" "${syswarden_retire_temp}" || {
        rm -f -- "${syswarden_retire_temp}"
        return 1
    }
    chmod "${syswarden_retire_mode}" "${syswarden_retire_temp}" || {
        rm -f -- "${syswarden_retire_temp}"
        return 1
    }
    syswarden_retire_digest="$(sha256sum "${syswarden_retire_temp}" | awk '{ print $1 }')" || {
        rm -f -- "${syswarden_retire_temp}"
        return 1
    }
    sync -f "${syswarden_retire_temp}" || {
        rm -f -- "${syswarden_retire_temp}"
        return 1
    }
    mv -f -- "${syswarden_retire_temp}" "${syswarden_retire_config}" || return 1
    if [ -L "${syswarden_retire_config}" ] || [ ! -f "${syswarden_retire_config}" ] || \
       [ "$(stat -c '%u:%g' "${syswarden_retire_config}" 2>/dev/null || true)" != "${syswarden_retire_owner}" ] || \
       [ "$(stat -c '%a' "${syswarden_retire_config}" 2>/dev/null || true)" != "${syswarden_retire_mode}" ] || \
       [ "$(sha256sum "${syswarden_retire_config}" 2>/dev/null | awk '{ print $1 }')" != "${syswarden_retire_digest}" ]; then
        printf 'Unable to verify the retired configuration publication: %s\n' "${syswarden_retire_config}" >&2
        return 1
    fi
    sync -f "$(dirname "${syswarden_retire_config}")" || return 1
}

syswarden_retire_webtui_configuration() {
    syswarden_retire_root="$1"
    syswarden_retire_config_root="${syswarden_retire_root}/etc/syswarden/config"
    [ -e "${syswarden_retire_config_root}" ] || [ -L "${syswarden_retire_config_root}" ] || return 0
    if [ -L "${syswarden_retire_config_root}" ] || [ ! -d "${syswarden_retire_config_root}" ]; then
        printf '%s\n' 'Refusing an unsafe configuration root during Web-TUI retirement' >&2
        return 1
    fi
    syswarden_retire_config_parent="${syswarden_retire_root}/etc/syswarden"
    if [ -L "${syswarden_retire_config_parent}" ] || [ ! -d "${syswarden_retire_config_parent}" ]; then
        printf '%s\n' 'Refusing an unsafe configuration parent during Web-TUI retirement' >&2
        return 1
    fi
    syswarden_retire_modules="${syswarden_retire_config_root}/modules"
    if [ -L "${syswarden_retire_modules}" ] || { [ -e "${syswarden_retire_modules}" ] && [ ! -d "${syswarden_retire_modules}" ]; }; then
        printf '%s\n' 'Refusing an unsafe modules directory during Web-TUI retirement' >&2
        return 1
    fi
    syswarden_retire_count=0
    for syswarden_retire_config in \
        "${syswarden_retire_config_root}/config.toml" \
        "${syswarden_retire_modules}"/*.toml; do
        [ -e "${syswarden_retire_config}" ] || [ -L "${syswarden_retire_config}" ] || continue
        syswarden_retire_count=$((syswarden_retire_count + 1))
        [ "${syswarden_retire_count}" -le 1024 ] || {
            printf '%s\n' 'Configuration inventory exceeds the Web-TUI cleanup limit' >&2
            return 1
        }
        syswarden_clean_webtui_config_file "${syswarden_retire_config}" || return 1
    done
}

syswarden_retire_legacy_webtui() {
    if [ "$#" -ne 1 ] || [ -z "$1" ] || ! syswarden_normalize_webtui_root "$1"; then
        printf '%s\n' 'Refusing an unsafe legacy Web-TUI retirement root' >&2
        return 1
    fi
    syswarden_retire_root="${SYSWARDEN_NORMALIZED_WEBTUI_ROOT}"
    syswarden_retire_systemd_webtui "${syswarden_retire_root}" || return 1
    syswarden_retire_openrc_webtui "${syswarden_retire_root}" || return 1
    if syswarden_package_runtime_is_offline "${syswarden_retire_root}"; then
        syswarden_retire_offline_webtui_pid "${syswarden_retire_root}" || return 1
    else
        syswarden_retire_exact_webtui_processes "${syswarden_retire_root}" || return 1
        syswarden_retire_stale_webtui_pid "${syswarden_retire_root}" || return 1
    fi
    syswarden_retire_webtui_configuration "${syswarden_retire_root}" || return 1
}

syswarden_verify_legacy_webtui_runtime_absent() {
    if [ "$#" -ne 1 ] || [ -z "$1" ] || ! syswarden_normalize_webtui_root "$1"; then
        printf '%s\n' 'Refusing an unsafe legacy Web-TUI verification root' >&2
        return 1
    fi
    syswarden_retire_root="${SYSWARDEN_NORMALIZED_WEBTUI_ROOT}"
    for syswarden_retire_path in \
        "${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service" \
        "${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service.syswarden-retiring" \
        "${syswarden_retire_root}/etc/systemd/system/syswarden-webtui.service.d" \
        "${syswarden_retire_root}/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service" \
        "${syswarden_retire_root}/run/systemd/system/syswarden-webtui.service" \
        "${syswarden_retire_root}/run/systemd/system/syswarden-webtui.service.d" \
        "${syswarden_retire_root}/etc/init.d/syswarden-webtui" \
        "${syswarden_retire_root}/etc/conf.d/syswarden-webtui" \
        "${syswarden_retire_root}/etc/runlevels/default/syswarden-webtui" \
        "${syswarden_retire_root}/run/syswarden-webtui.pid"; do
        if [ -e "${syswarden_retire_path}" ] || [ -L "${syswarden_retire_path}" ]; then
            printf 'Retired Web-TUI runtime path remains: %s\n' "${syswarden_retire_path}" >&2
            return 1
        fi
    done
    if ! syswarden_package_runtime_is_offline "${syswarden_retire_root}"; then
        syswarden_verify_no_exact_webtui_process "${syswarden_retire_root}" || return 1
    fi
}

syswarden_verify_webtui_retirement() {
    syswarden_verify_legacy_webtui_runtime_absent "$@" || return 1
    if ! syswarden_normalize_webtui_root "$1"; then
        printf '%s\n' 'Refusing an unsafe legacy Web-TUI verification root' >&2
        return 1
    fi
    syswarden_retire_root="${SYSWARDEN_NORMALIZED_WEBTUI_ROOT}"
    [ -x "${syswarden_retire_root}/opt/syswarden/bin/syswarden-tui" ] || {
        printf '%s\n' 'Native SysWarden TUI payload is missing after installation' >&2
        return 1
    }
    [ -L "${syswarden_retire_root}/usr/local/bin/syswarden-tui" ] || {
        printf '%s\n' 'Native SysWarden TUI launcher is missing after installation' >&2
        return 1
    }
    [ "$(readlink "${syswarden_retire_root}/usr/local/bin/syswarden-tui")" = /opt/syswarden/bin/syswarden-tui ] || {
        printf '%s\n' 'Native SysWarden TUI launcher has an unexpected target' >&2
        return 1
    }
}
