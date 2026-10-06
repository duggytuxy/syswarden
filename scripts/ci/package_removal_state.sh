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
        printf '%s\n' 'Refusing finalization while unretired state remains. Preserve the removal evidence and complete verified file retirement.' >&2
        return 1
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

# 99-user.toml is the documented administrator-owned surface. Retention of
# that file gives no deletion authority over adjacent or unknown entries.
# Subshells keep recursive inventory variables local on every supported shell.
syswarden_attest_retained_config_tree() (
    config_path="$1"
    config_logical="$2"
    syswarden_path_absent "${config_path}" && exit 0
    syswarden_attest_dedicated_root "${config_path}" || exit 1
    syswarden_refuse_mounted_path_tree "${config_path}" || exit 1
    for config_entry in "${config_path}"/* "${config_path}"/.[!.]* "${config_path}"/..?*; do
        syswarden_path_absent "${config_entry}" && continue
        config_name=${config_entry##*/}
        case "${config_logical}/${config_name}" in
            /etc/syswarden/config|/etc/syswarden/lists|/etc/syswarden/tls|/etc/syswarden/config/modules)
                syswarden_attest_retained_config_tree "${config_entry}" "${config_logical}/${config_name}" || exit 1 ;;
            /etc/syswarden/config/modules/99-user.toml)
                [ ! -L "${config_entry}" ] && [ -f "${config_entry}" ] || exit 1
                case "$(stat -c '%u:%g:%a:%h' "${config_entry}")" in
                    0:0:600:1|0:0:640:1) ;;
                    *) exit 1 ;;
                esac ;;
            *)
                printf 'Unretired configuration entry remains: %s\n' "${config_entry}" >&2
                exit 1 ;;
        esac
    done
)

syswarden_finalize_retained_config_tree() (
    config_path="$1"
    config_logical="$2"
    syswarden_path_absent "${config_path}" && exit 0
    syswarden_attest_retained_config_tree "${config_path}" "${config_logical}" || exit 1
    config_identity=$(stat -c '%d:%i:%u:%g:%a' "${config_path}") || exit 1
    for config_entry in "${config_path}"/* "${config_path}"/.[!.]* "${config_path}"/..?*; do
        syswarden_path_absent "${config_entry}" && continue
        config_name=${config_entry##*/}
        case "${config_logical}/${config_name}" in
            /etc/syswarden/config/modules/99-user.toml) ;;
            *) syswarden_finalize_retained_config_tree "${config_entry}" "${config_logical}/${config_name}" || exit 1 ;;
        esac
    done
    syswarden_attest_retained_config_tree "${config_path}" "${config_logical}" || exit 1
    [ "$(stat -c '%d:%i:%u:%g:%a' "${config_path}")" = "${config_identity}" ] || exit 1
    for config_entry in "${config_path}"/* "${config_path}"/.[!.]* "${config_path}"/..?*; do
        syswarden_path_absent "${config_entry}" || exit 0
    done
    # rmdir cannot remove or follow a concurrent file, link or nonempty tree.
    rmdir -- "${config_path}" || exit 1
    sync || exit 1
    syswarden_path_absent "${config_path}"
)

syswarden_assert_retained_operator_configuration() (
    syswarden_path_absent /etc/syswarden && exit 0
    syswarden_attest_retained_config_tree /etc/syswarden /etc/syswarden || exit 1
    for config_path in /etc/syswarden /etc/syswarden/config /etc/syswarden/config/modules; do
        config_count=0
        for config_entry in "${config_path}"/* "${config_path}"/.[!.]* "${config_path}"/..?*; do
            syswarden_path_absent "${config_entry}" && continue
            case "${config_entry}" in
                /etc/syswarden/config|/etc/syswarden/config/modules|/etc/syswarden/config/modules/99-user.toml) ;;
                *) exit 1 ;;
            esac
            config_count=$((config_count + 1))
        done
        [ "${config_count}" -eq 1 ] || exit 1
    done
)

syswarden_finalize_retained_operator_configuration() {
    syswarden_attest_retained_config_tree /etc/syswarden /etc/syswarden || return 1
    syswarden_finalize_retained_config_tree /etc/syswarden /etc/syswarden || return 1
    syswarden_assert_retained_operator_configuration
}

syswarden_assert_external_removal_terminal() {
    syswarden_assert_product_binaries_absent || return 1
    syswarden_assert_retained_operator_configuration || return 1
    for syswarden_terminal_path in \
        /opt/syswarden \
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
