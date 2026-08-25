# shellcheck shell=sh

syswarden_install_path_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

syswarden_attest_install_marker_file() {
    syswarden_install_marker="$1"
    [ ! -L "${syswarden_install_marker}" ] && [ -f "${syswarden_install_marker}" ] || return 1
    [ "$(stat -c '%u:%g:%a:%h' "${syswarden_install_marker}")" = '0:0:600:1' ] || return 1
    [ "$(LC_ALL=C wc -c < "${syswarden_install_marker}" | tr -d '[:space:]')" = '39' ] || return 1
    printf 'SYSWARDEN_REMOVAL_V1\nstate=in-progress\n' | \
        cmp - "${syswarden_install_marker}" >/dev/null 2>&1
}

syswarden_attest_deferred_purge_marker() {
    syswarden_state_root=/var/lib/syswarden
    syswarden_deferred_marker=${syswarden_state_root}/removed-awaiting-purge-v1
    [ ! -L "${syswarden_state_root}" ] && [ -d "${syswarden_state_root}" ] || return 1
    case "$(stat -c '%u:%g:%a' "${syswarden_state_root}")" in
        0:0:700|0:0:750|0:0:755) ;;
        *) return 1 ;;
    esac
    syswarden_attest_install_marker_file "${syswarden_deferred_marker}"
}

syswarden_attest_finalizing_purge_marker() {
    syswarden_finalizing_marker=/var/lib/.syswarden-removal-finalizing-v1
    [ ! -L /var/lib ] && [ -d /var/lib ] || return 1
    case "$(stat -c '%u:%g:%a' /var/lib)" in
        0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755) ;;
        *) return 1 ;;
    esac
    syswarden_attest_install_marker_file "${syswarden_finalizing_marker}"
}

syswarden_preflight_install_barriers() {
    syswarden_active_marker=/var/lib/syswarden/removal-in-progress-v1
    syswarden_deferred_marker=/var/lib/syswarden/removed-awaiting-purge-v1
    syswarden_finalizing_marker=/var/lib/.syswarden-removal-finalizing-v1
    if ! syswarden_install_path_absent "${syswarden_active_marker}"; then
        printf '%s\n' 'Refusing installation with an active package-removal barrier.' >&2
        return 1
    fi
    syswarden_deferred_present=0
    syswarden_finalizing_present=0
    syswarden_install_path_absent "${syswarden_deferred_marker}" || syswarden_deferred_present=1
    syswarden_install_path_absent "${syswarden_finalizing_marker}" || syswarden_finalizing_present=1
    [ "${syswarden_deferred_present}" -eq 0 ] && \
        [ "${syswarden_finalizing_present}" -eq 0 ] && return 0
    if [ "${syswarden_deferred_present}" -eq 1 ] && \
       [ "${syswarden_finalizing_present}" -eq 1 ]; then
        printf '%s\n' 'Refusing installation with simultaneous deferred and final package-removal barriers.' >&2
        return 1
    fi
    if [ "${syswarden_deferred_present}" -eq 1 ]; then
        syswarden_attest_deferred_purge_marker || {
            printf '%s\n' 'Refusing an ambiguous deferred package-removal barrier.' >&2
            return 1
        }
    elif [ "${syswarden_finalizing_present}" -eq 1 ]; then
        syswarden_attest_finalizing_purge_marker || {
            printf '%s\n' 'Refusing an ambiguous final package-removal barrier.' >&2
            return 1
        }
    fi
}

syswarden_consume_deferred_purge_marker() {
    syswarden_preflight_install_barriers || return 1
    [ "${syswarden_deferred_present}" -eq 0 ] && \
        [ "${syswarden_finalizing_present}" -eq 0 ] && return 0
    if [ "${syswarden_deferred_present}" -eq 1 ]; then
        syswarden_install_barrier=${syswarden_deferred_marker}
        syswarden_attest_deferred_purge_marker || return 1
    else
        syswarden_install_barrier=${syswarden_finalizing_marker}
        syswarden_attest_finalizing_purge_marker || return 1
    fi
    rm -f -- "${syswarden_install_barrier}" || return 1
    sync || return 1
    syswarden_install_path_absent "${syswarden_install_barrier}"
}
