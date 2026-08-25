# shellcheck shell=sh

syswarden_attest_state_root() {
    [ ! -L /var/lib/syswarden ] && [ -d /var/lib/syswarden ] || return 1
    case "$(stat -c '%u:%g:%a' /var/lib/syswarden)" in
        0:0:700|0:0:750|0:0:755) ;;
        *) return 1 ;;
    esac
}

syswarden_attest_marker_file() {
    syswarden_marker_path="$1"
    [ ! -L "${syswarden_marker_path}" ] && [ -f "${syswarden_marker_path}" ] || return 1
    [ "$(stat -c '%u:%g:%a:%h' "${syswarden_marker_path}")" = '0:0:600:1' ] || return 1
    [ "$(LC_ALL=C wc -c < "${syswarden_marker_path}" | tr -d '[:space:]')" = '39' ] || return 1
    printf 'SYSWARDEN_REMOVAL_V1\nstate=in-progress\n' | \
        cmp - "${syswarden_marker_path}" >/dev/null 2>&1
}

syswarden_attest_removal_marker() {
    syswarden_attest_state_root || return 1
    syswarden_attest_marker_file "$1"
}

syswarden_attest_removal_tombstone() {
    syswarden_attest_removal_marker /var/lib/syswarden/removal-in-progress-v1
}

syswarden_attest_deferred_purge_marker() {
    syswarden_attest_removal_marker /var/lib/syswarden/removed-awaiting-purge-v1
}

syswarden_attest_finalizing_marker() {
    [ ! -L /var/lib ] && [ -d /var/lib ] || return 1
    case "$(stat -c '%u:%g:%a' /var/lib)" in
        0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755) ;;
        *) return 1 ;;
    esac
    syswarden_attest_marker_file /var/lib/.syswarden-removal-finalizing-v1
}

syswarden_assert_product_binaries_absent() {
    for syswarden_binary in \
        /opt/syswarden/bin/syswarden-cli \
        /opt/syswarden/bin/syswarden-core \
        /opt/syswarden/bin/syswarden-tui; do
        syswarden_path_absent "${syswarden_binary}" || {
            printf 'Refusing removal finalization while a product binary remains: %s\n' "${syswarden_binary}" >&2
            return 1
        }
    done
}

syswarden_select_removal_barrier() {
    syswarden_active_tombstone=/var/lib/syswarden/removal-in-progress-v1
    syswarden_deferred_tombstone=/var/lib/syswarden/removed-awaiting-purge-v1
    syswarden_finalizing_tombstone=/var/lib/.syswarden-removal-finalizing-v1
    syswarden_barrier_count=0
    syswarden_active_barrier=
    syswarden_barrier_kind=
    syswarden_active_present=0
    syswarden_deferred_present=0
    syswarden_finalizing_present=0
    if ! syswarden_path_absent "${syswarden_active_tombstone}"; then
        syswarden_attest_removal_tombstone || {
            printf '%s\n' 'Refusing an ambiguous active package-removal barrier.' >&2
            return 1
        }
        syswarden_active_barrier=${syswarden_active_tombstone}
        syswarden_barrier_kind=active
        syswarden_active_present=1
        syswarden_barrier_count=$((syswarden_barrier_count + 1))
    fi
    if ! syswarden_path_absent "${syswarden_deferred_tombstone}"; then
        syswarden_attest_deferred_purge_marker || {
            printf '%s\n' 'Refusing an ambiguous deferred package-removal barrier.' >&2
            return 1
        }
        syswarden_active_barrier=${syswarden_deferred_tombstone}
        syswarden_barrier_kind=deferred
        syswarden_deferred_present=1
        syswarden_barrier_count=$((syswarden_barrier_count + 1))
    fi
    if ! syswarden_path_absent "${syswarden_finalizing_tombstone}"; then
        syswarden_attest_finalizing_marker || {
            printf '%s\n' 'Refusing an ambiguous final package-removal barrier.' >&2
            return 1
        }
        syswarden_active_barrier=${syswarden_finalizing_tombstone}
        syswarden_barrier_kind=finalizing
        syswarden_finalizing_present=1
        syswarden_barrier_count=$((syswarden_barrier_count + 1))
    fi
    [ "${syswarden_barrier_count}" -eq 0 ] && return 2
    if [ "${syswarden_finalizing_present}" -eq 0 ] && \
       [ "${syswarden_active_present}" -eq 1 ] && \
       [ "${syswarden_deferred_present}" -eq 1 ]; then
        syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
        syswarden_attest_removal_tombstone || return 1
        syswarden_attest_deferred_purge_marker || return 1
        rm -f -- "${syswarden_deferred_tombstone}" || return 1
        sync || return 1
        syswarden_path_absent "${syswarden_deferred_tombstone}" || return 1
        syswarden_attest_removal_tombstone || return 1
        syswarden_active_barrier=${syswarden_active_tombstone}
        syswarden_barrier_kind=active
        syswarden_barrier_count=1
    fi
    if [ "${syswarden_deferred_present}" -eq 0 ] && \
       [ "${syswarden_active_present}" -eq 1 ] && \
       [ "${syswarden_finalizing_present}" -eq 1 ]; then
        syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
        syswarden_attest_removal_tombstone || return 1
        syswarden_attest_finalizing_marker || return 1
        rm -f -- "${syswarden_finalizing_tombstone}" || return 1
        sync || return 1
        syswarden_path_absent "${syswarden_finalizing_tombstone}" || return 1
        syswarden_attest_removal_tombstone || return 1
        syswarden_active_barrier=${syswarden_active_tombstone}
        syswarden_barrier_kind=active
        syswarden_barrier_count=1
    fi
    [ "${syswarden_barrier_count}" -eq 1 ] || {
        printf '%s\n' 'Refusing simultaneous package-removal barriers.' >&2
        return 1
    }
}

syswarden_transition_to_deferred_purge() {
    syswarden_active_tombstone=/var/lib/syswarden/removal-in-progress-v1
    syswarden_deferred_tombstone=/var/lib/syswarden/removed-awaiting-purge-v1
    syswarden_assert_product_binaries_absent || return 1
    syswarden_select_removal_barrier || return 1
    [ "${syswarden_barrier_kind}" = deferred ] && return 0
    [ "${syswarden_barrier_kind}" = active ] || return 1
    syswarden_path_absent "${syswarden_deferred_tombstone}" || return 1
    syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
    syswarden_state_identity="$(stat -c '%d:%i' /var/lib/syswarden)" || return 1
    mv -- "${syswarden_active_tombstone}" "${syswarden_deferred_tombstone}" || return 1
    sync || return 1
    [ "$(stat -c '%d:%i' /var/lib/syswarden)" = "${syswarden_state_identity}" ] || return 1
    syswarden_path_absent "${syswarden_active_tombstone}" || return 1
    syswarden_attest_deferred_purge_marker
}

syswarden_empty_removal_state() {
    syswarden_state_root=/var/lib/syswarden
    syswarden_attest_removal_marker "${syswarden_active_barrier}" || return 1
    syswarden_refuse_mounted_path_tree "${syswarden_state_root}" || return 1
    for syswarden_state_entry in \
        "${syswarden_state_root}"/* \
        "${syswarden_state_root}"/.[!.]* \
        "${syswarden_state_root}"/..?*; do
        syswarden_path_absent "${syswarden_state_entry}" && continue
        [ "${syswarden_state_entry}" = "${syswarden_active_barrier}" ] && continue
        syswarden_refuse_mounted_path_tree "${syswarden_state_root}" || return 1
        rm -rf -- "${syswarden_state_entry}" || return 1
    done
    syswarden_attest_removal_marker "${syswarden_active_barrier}" || return 1
    syswarden_state_count=0
    for syswarden_state_entry in \
        "${syswarden_state_root}"/* \
        "${syswarden_state_root}"/.[!.]* \
        "${syswarden_state_root}"/..?*; do
        syswarden_path_absent "${syswarden_state_entry}" && continue
        [ "${syswarden_state_entry}" = "${syswarden_active_barrier}" ] || return 1
        syswarden_state_count=$((syswarden_state_count + 1))
    done
    [ "${syswarden_state_count}" -eq 1 ]
}

syswarden_assert_external_removal_terminal() {
    syswarden_assert_product_binaries_absent || return 1
    for syswarden_terminal_path in \
        /opt/syswarden \
        /etc/syswarden \
        /var/log/syswarden \
        /usr/local/bin/syswarden \
        /usr/local/bin/syswarden-tui \
        /usr/share/bash-completion/completions/syswarden \
        /run/syswarden.sock; do
        syswarden_path_absent "${syswarden_terminal_path}" || return 1
    done
}

syswarden_state_root_is_empty() {
    syswarden_attest_state_root || return 1
    syswarden_state_count=0
    for syswarden_state_entry in \
        /var/lib/syswarden/* \
        /var/lib/syswarden/.[!.]* \
        /var/lib/syswarden/..?*; do
        syswarden_path_absent "${syswarden_state_entry}" && continue
        syswarden_state_count=$((syswarden_state_count + 1))
    done
    [ "${syswarden_state_count}" -eq 0 ]
}

syswarden_finalize_removal_state_root() {
    syswarden_finalizing_barrier=/var/lib/.syswarden-removal-finalizing-v1
    syswarden_assert_external_removal_terminal || return 1
    syswarden_attest_removal_marker "${syswarden_active_barrier}" || return 1
    syswarden_empty_removal_state || return 1
    syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
    syswarden_state_identity="$(stat -c '%d:%i' /var/lib/syswarden)" || return 1
    syswarden_path_absent "${syswarden_finalizing_barrier}" || return 1
    mv -- "${syswarden_active_barrier}" "${syswarden_finalizing_barrier}" || return 1
    syswarden_active_barrier=${syswarden_finalizing_barrier}
    sync || return 1
    syswarden_attest_finalizing_marker || return 1
    syswarden_state_root_is_empty || return 1
    [ "$(stat -c '%d:%i' /var/lib/syswarden)" = "${syswarden_state_identity}" ] || return 1
    rmdir -- /var/lib/syswarden || return 1
    syswarden_path_absent /var/lib/syswarden || return 1
    sync || return 1
    syswarden_attest_finalizing_marker || return 1
    rm -f -- "${syswarden_finalizing_barrier}" || return 1
    sync || return 1
    syswarden_path_absent "${syswarden_active_barrier}" || return 1
}

syswarden_resume_external_finalization() {
    syswarden_finalizing_barrier=/var/lib/.syswarden-removal-finalizing-v1
    syswarden_assert_external_removal_terminal || return 1
    syswarden_attest_finalizing_marker || return 1
    if ! syswarden_path_absent /var/lib/syswarden; then
        syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
        syswarden_state_root_is_empty || return 1
        rmdir -- /var/lib/syswarden || return 1
        syswarden_path_absent /var/lib/syswarden || return 1
        sync || return 1
    fi
    syswarden_attest_finalizing_marker || return 1
    rm -f -- "${syswarden_finalizing_barrier}" || return 1
    sync || return 1
    syswarden_path_absent "${syswarden_finalizing_barrier}"
}

syswarden_resume_unmarked_terminal_state() {
    syswarden_assert_external_removal_terminal || return 1
    syswarden_path_absent /var/lib/syswarden && return 0
    syswarden_refuse_mounted_path_tree /var/lib/syswarden || return 1
    syswarden_state_root_is_empty || return 1
    syswarden_state_identity="$(stat -c '%d:%i' /var/lib/syswarden)" || return 1
    syswarden_state_root_is_empty || return 1
    [ "$(stat -c '%d:%i' /var/lib/syswarden)" = "${syswarden_state_identity}" ] || return 1
    rmdir -- /var/lib/syswarden || return 1
    sync || return 1
    syswarden_path_absent /var/lib/syswarden
}
