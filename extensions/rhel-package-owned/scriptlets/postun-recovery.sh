#!/bin/sh
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

helper=/var/lib/.syswarden-rhelpo-postun-recovery-v1
marker=/var/lib/.syswarden-rhelpo-erase-ready-v1
tombstone=/var/lib/syswarden/removal-in-progress-v1

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

exact_regular() {
    path="$1"
    mode="$2"
    size="$3"
    digest="$4"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RHEL package-owned recovery file: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")" = "0:0:${mode}:1:${size}" ] || \
        fail "Refusing modified RHEL package-owned recovery metadata: $path"
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$digest" ] || \
        fail "Refusing modified RHEL package-owned recovery content: $path"
}

exact_directory() {
    path="$1"
    mode="$2"
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe residual RPM directory: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = "0:0:${mode}" ] || \
        fail "Refusing modified residual RPM directory metadata: $path"
}

remove_empty_directory() {
    path="$1"
    mode="$2"
    if absent "$path"; then
        return 0
    fi
    exact_directory "$path" "$mode"
    /usr/bin/rmdir -- "$path"
    absent "$path" || fail "Residual RPM directory remains after recovery: $path"
}

# BEGIN shared operator configuration retention
syswarden_path_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

syswarden_refuse_mounted_path_tree() {
    syswarden_mount_root="$1"
    [ -r /proc/self/mountinfo ] || {
        printf 'Refusing removal without readable mount topology: %s\n' "${syswarden_mount_root}" >&2
        return 1
    }
    if ! awk -v root="${syswarden_mount_root}" '
        {
            mountpoint = $5
            gsub(/\\040/, " ", mountpoint)
            gsub(/\\011/, "\t", mountpoint)
            gsub(/\\012/, "\n", mountpoint)
            gsub(/\\134/, "\\", mountpoint)
            if (mountpoint == root || index(mountpoint, root "/") == 1) {
                exit 42
            }
        }
    ' /proc/self/mountinfo; then
        printf 'Refusing removal across a mounted product path: %s\n' "${syswarden_mount_root}" >&2
        return 1
    fi
}

syswarden_attest_dedicated_root() {
    syswarden_root_path="$1"
    syswarden_path_absent "${syswarden_root_path}" && return 0
    [ ! -L "${syswarden_root_path}" ] && [ -d "${syswarden_root_path}" ] || {
        printf 'Refusing unsafe dedicated product root: %s\n' "${syswarden_root_path}" >&2
        return 1
    }
    case "$(stat -c '%u:%g:%a' "${syswarden_root_path}")" in
        0:0:700|0:0:750|0:0:755) ;;
        *) printf 'Refusing unsafe dedicated product root metadata: %s\n' "${syswarden_root_path}" >&2; return 1 ;;
    esac
}

syswarden_operator_retention_record_has_path() (
    retention_record="$1"
    retention_target="$2"
    [ ! -L "${retention_record}" ] && [ -f "${retention_record}" ] || exit 1
    case "$(stat -c '%u:%g:%a:%h' "${retention_record}")" in 0:0:600:1) ;; *) exit 1 ;; esac
    retention_size=$(stat -c '%s' "${retention_record}") || exit 1
    [ "${retention_size}" -gt 0 ] && [ "${retention_size}" -le 65536 ] || exit 1
    retention_identity=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${retention_record}") || exit 1
    exec 3<"${retention_record}" || exit 1
    [ "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%y:%z' /proc/self/fd/3)" = "${retention_identity}" ] || exit 1
    retention_hash=$(sha256sum /proc/self/fd/3) || exit 1
    retention_hash=${retention_hash%% *}
    [ "${retention_record##*/}" = "${retention_hash}.retention" ] || exit 1
    retention_last=$(tail -c 1 /proc/self/fd/3) || exit 1
    [ -z "${retention_last}" ] || exit 1
    LC_ALL=C awk -F '\t' -v target="${retention_target}" '
        function bounded(value, maximum) {
            return value ~ /^(0|[1-9][0-9]*)$/ &&
                (length(value) < length(maximum) ||
                (length(value) == length(maximum) && "x" value <= "x" maximum))
        }
        NR == 1 { if ($0 != "SYSWARDEN_OPERATOR_CONFIGURATION_RETENTION_V1") bad = 1; next }
        NR == 2 { if ($0 != "explicit-operator-retention-at-original-paths") bad = 1; next }
        {
            path = $2
            prefix = "/etc/syswarden/config/modules/"
            name = substr(path, length(prefix) + 1)
            allowed = path == "/etc/syswarden/config/config.toml" ||
                (index(path, prefix) == 1 && length(name) >= 6 && length(name) <= 128 &&
                name ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*[.]toml$/)
            if (NF != 13 || $1 != "file" || !allowed || NR > 130 ||
                (previous != "" && "x" previous >= "x" path) ||
                !bounded($3, "18446744073709551615") || !bounded($4, "18446744073709551615") || $4 == "0" ||
                ($5 != "33152" && $5 != "33184") || $6 != "0" || $7 != "0" ||
                !bounded($8, "262144") || !bounded($9, "9223372036854775807") ||
                !bounded($10, "999999999") || !bounded($11, "9223372036854775807") ||
                !bounded($12, "999999999") || length($13) != 64 || $13 !~ /^[0-9a-f]+$/) bad = 1
            previous = path
            if (path == target) found = 1
        }
        END { if (bad || NR < 3) exit 1; if (!found) exit 2 }
    ' /proc/self/fd/3
    retention_status=$?
    [ "$(stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' "${retention_record}")" = "${retention_identity}" ] || exit 1
    [ "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%y:%z' /proc/self/fd/3)" = "${retention_identity}" ] || exit 1
    exit "${retention_status}"
)

syswarden_operator_configuration_retained() (
    [ "$1" = /etc/syswarden/config/modules/99-user.toml ] && exit 0
    retention_directory=/var/backups/syswarden-retired-v1/operator-configuration
    retention_seen=0
    retention_found=0
    for retention_parent in /var/backups /var/backups/syswarden-retired-v1 "${retention_directory}"; do
        syswarden_path_absent "${retention_parent}" && exit 1
        syswarden_attest_dedicated_root "${retention_parent}" || exit 1
        syswarden_refuse_mounted_path_tree "${retention_parent}" || exit 1
        if [ "${retention_parent}" != /var/backups ]; then
            [ "$(stat -c '%a' "${retention_parent}")" = 700 ] || exit 1
        fi
    done
    retention_directory_identity=$(stat -c '%d:%i:%u:%g:%a:%y:%z' "${retention_directory}") || exit 1
    for retention_record in "${retention_directory}"/* "${retention_directory}"/.[!.]* "${retention_directory}"/..?*; do
        syswarden_path_absent "${retention_record}" && continue
        retention_seen=$((retention_seen + 1))
        [ "${retention_seen}" -le 128 ] || exit 1
        retention_status=0
        syswarden_operator_retention_record_has_path "${retention_record}" "$1" || retention_status=$?
        case "${retention_status}" in 0) retention_found=1 ;; 2) ;; *) exit 1 ;; esac
    done
    [ "$(stat -c '%d:%i:%u:%g:%a:%y:%z' "${retention_directory}")" = "${retention_directory_identity}" ] || exit 1
    [ "${retention_found}" -eq 1 ]
)

# The documented operator module and explicitly reviewed additional files are
# retained. Neither gives deletion authority over adjacent or unknown entries.
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
            *)
                if ! syswarden_operator_configuration_retained "${config_logical}/${config_name}"; then
                    printf 'Unretired configuration entry remains: %s\n' "${config_entry}" >&2
                    exit 1
                fi
                [ ! -L "${config_entry}" ] && [ -f "${config_entry}" ] || exit 1
                case "$(stat -c '%u:%g:%a:%h' "${config_entry}")" in
                    0:0:600:1|0:0:640:1) ;;
                    *) exit 1 ;;
                esac ;;
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
        if ! syswarden_operator_configuration_retained "${config_logical}/${config_name}"; then
            syswarden_finalize_retained_config_tree "${config_entry}" "${config_logical}/${config_name}" || exit 1
        fi
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
    syswarden_assert_nonempty_retained_config_tree /etc/syswarden
)

syswarden_assert_nonempty_retained_config_tree() (
    config_path="$1"
    config_count=0
    for config_entry in "${config_path}"/* "${config_path}"/.[!.]* "${config_path}"/..?*; do
        syswarden_path_absent "${config_entry}" && continue
        case "${config_entry}" in
            /etc/syswarden/config|/etc/syswarden/config/modules)
                syswarden_assert_nonempty_retained_config_tree "${config_entry}" || exit 1 ;;
            *) syswarden_operator_configuration_retained "${config_entry}" || exit 1 ;;
        esac
        config_count=$((config_count + 1))
    done
    [ "${config_count}" -gt 0 ]
)

syswarden_finalize_retained_operator_configuration() {
    syswarden_attest_retained_config_tree /etc/syswarden /etc/syswarden || return 1
    syswarden_finalize_retained_config_tree /etc/syswarden /etc/syswarden || return 1
    syswarden_assert_retained_operator_configuration
}

# END shared operator configuration retention

assert_terminal_directories_absent() {
    syswarden_assert_retained_operator_configuration || fail 'Unreviewed configuration remains after RPM erase.'
    for path in \
        /usr/lib/systemd/system/syswarden-firewall.service.d \
        /usr/libexec/syswarden \
        /usr/share/doc/syswarden \
        /opt/syswarden \
        /var/lib/syswarden \
        /var/log/syswarden; do
        absent "$path" || fail "Refusing recovery without its authorization marker while residue remains: $path"
    done
}

assert_rpm_payload_absent() {
    for path in \
        /usr/lib/systemd/system/syswarden-core.service \
        /usr/lib/systemd/system/syswarden-firewall.service \
        /usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf \
        /usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset \
        /usr/libexec/syswarden/rhelpo-postun-recovery-v1 \
        /usr/share/doc/syswarden/rhel-package-owned-profile.json \
        /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt \
        /usr/share/doc/syswarden/LICENSE.txt \
        /opt/syswarden/bin/syswarden-cli \
        /opt/syswarden/bin/syswarden-core \
        /opt/syswarden/bin/syswarden-tui \
        /opt/syswarden/signatures.json \
        /usr/local/bin/syswarden \
        /usr/local/bin/syswarden-tui \
        /usr/share/bash-completion/completions/syswarden \
        /etc/systemd/system/syswarden-core.service \
        /etc/systemd/system/syswarden-firewall.service \
        /etc/systemd/system/syswarden-webtui.service \
        /etc/systemd/system/syswarden-webtui.service.syswarden-retiring \
        /etc/systemd/system/syswarden-webtui.service.d \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration \
        /etc/systemd/system/multi-user.target.wants/syswarden-webtui.service \
        /run/systemd/system/syswarden-webtui.service \
        /run/systemd/system/syswarden-webtui.service.d \
        /etc/init.d/syswarden-core \
        /etc/init.d/syswarden-firewall \
        /etc/init.d/syswarden-webtui \
        /etc/conf.d/syswarden-webtui \
        /etc/runlevels/default/syswarden-core \
        /etc/runlevels/default/syswarden-firewall \
        /etc/runlevels/default/syswarden-webtui \
        /etc/cron.d/syswarden \
        /etc/rsyslog.d/99-syswarden-waf-bridge.conf \
        /etc/init.d/wg-quick.wg-syswarden \
        /etc/runlevels/default/wg-quick.wg-syswarden \
        /etc/wireguard/wg-syswarden.conf \
        /run/syswarden.sock \
        /var/run/syswarden.sock \
        /run/syswarden-control.sock \
        /var/run/syswarden-control.sock \
        /run/syswarden-core.pid \
        /run/syswarden-firewall.lock \
        /run/syswarden-webtui.pid \
        /var/lib/.syswarden-removal-finalizing-v1 \
        /var/lib/.syswarden-removal-finalizing-v1.new \
        /var/lib/syswarden/removal-in-progress-v1.new \
        /var/lib/.syswarden-rhelpo-preset-pending-v1 \
        /var/lib/.syswarden-rhelpo-preset-pending-v1.new \
        /var/lib/.syswarden-rhelpo-erase-ready-v1.new \
        /var/lib/.syswarden-rhelpo-postun-recovery-v1.new; do
        absent "$path" || fail "Refusing finalization while RPM payload or transient state remains: $path"
    done
}

# PREUN calls this read-only mode only after digest and RPM ownership checks.
# It never invokes a product binary or publishes an erase authorization.
if [ "$#" -eq 1 ] && [ "$1" = inspect-configuration-v1 ]; then
    [ "$0" = /usr/libexec/syswarden/rhelpo-postun-recovery-v1 ] || fail 'Configuration inspection helper path is not exact.'
    [ -f "$0" ] && [ ! -L "$0" ] || fail 'Configuration inspection helper is not a regular file.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$0")" = '0:0:755:1' ] || fail 'Configuration inspection helper metadata is not exact.'
    syswarden_attest_retained_config_tree /etc/syswarden /etc/syswarden || fail 'Unreviewed configuration remains before RPM erase.'
    exit 0
fi

recovery_mode=operator
if [ "$#" -eq 1 ] && [ "$1" = rpm-postun-v1 ]; then
    recovery_mode=rpm-postun
elif [ "$#" -ne 0 ]; then
    fail 'RHEL package-owned post-uninstall recovery arguments are invalid.'
fi
[ "$0" = "$helper" ] || fail 'RHEL package-owned post-uninstall recovery path is not exact.'
[ -f "$helper" ] && [ ! -L "$helper" ] || fail 'RHEL package-owned post-uninstall recovery helper is absent.'
[ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$helper")" = '0:0:700:1' ] || \
    fail 'RHEL package-owned post-uninstall recovery helper metadata is not exact.'

if [ "$recovery_mode" = operator ]; then
    rpm_stdout="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-postun-rpm-out.XXXXXXXXXX)" || \
        fail 'Cannot allocate the RPM database stdout attestation file.'
    rpm_stderr="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-postun-rpm-err.XXXXXXXXXX)" || {
        /usr/bin/rm -f -- "$rpm_stdout"
        fail 'Cannot allocate the RPM database stderr attestation file.'
    }
    cleanup_rpm_query() {
        /usr/bin/rm -f -- "$rpm_stdout" "$rpm_stderr"
    }
    trap cleanup_rpm_query 0 1 2 3 15
    set +e
    LC_ALL=C /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query syswarden \
        >"$rpm_stdout" 2>"$rpm_stderr"
    rpm_status=$?
    set -e
    [ "$rpm_status" -eq 1 ] || fail 'RPM query did not prove that the SysWarden package is absent.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$rpm_stdout")" = '0:0:600:1:35' ] || \
        fail 'RPM absence stdout is not canonical and bounded.'
    [ "$(/usr/bin/sha256sum -- "$rpm_stdout" | /usr/bin/awk '{print $1}')" = \
        68e70994030d3c56dbe9c32e18e4efd90389d75a20d8a28cfade11218a847634 ] || \
        fail 'RPM absence response is not exact.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$rpm_stderr")" = '0:0:600:1:0' ] || \
        fail 'RPM absence stderr is not exactly empty.'
    cleanup_rpm_query
    trap - 0 1 2 3 15
fi

assert_rpm_payload_absent
syswarden_attest_retained_config_tree /etc/syswarden /etc/syswarden || fail 'Unreviewed configuration blocks post-uninstall recovery.'

if absent "$marker"; then
    absent "$tombstone" || fail 'Removal tombstone remains without its erase-ready marker.'
    assert_terminal_directories_absent
    /usr/bin/rm -f -- "$helper"
    absent "$helper" || fail 'Post-uninstall recovery helper remains after terminal cleanup.'
    /usr/bin/sync -f -- /var/lib || exit 0
    exit 0
fi

exact_regular "$marker" 600 71 \
    93066cdc965c4d5469a5e4d75f2e7fad16845a113381a78d5c422832cda85d8c

if ! absent /var/lib/syswarden; then
    exact_directory /var/lib/syswarden 750
    state_children=0
    for entry in /var/lib/syswarden/.[!.]* /var/lib/syswarden/..?* /var/lib/syswarden/*; do
        absent "$entry" && continue
        case "$entry" in
            /var/lib/syswarden/ui)
                exact_directory "$entry" 750
                for ui_entry in "$entry"/.[!.]* "$entry"/..?* "$entry"/*; do
                    absent "$ui_entry" || fail "Refusing non-empty UI state during post-uninstall recovery: $ui_entry"
                done
                state_children=$((state_children + 1))
                ;;
            "$tombstone")
                state_children=$((state_children + 1))
                ;;
            *)
                fail "Refusing unexpected state during post-uninstall recovery: $entry"
                ;;
        esac
    done
    [ "$state_children" -le 2 ] || fail 'Post-uninstall recovery state inventory is not exact.'
fi
if ! absent "$tombstone"; then
    exact_regular "$tombstone" 600 39 \
        e1a0bbd8e3d90884bdaf9306233e6c2cfb5ab752c3065939139119982fed4514
fi

remove_empty_directory /usr/lib/systemd/system/syswarden-firewall.service.d 755
remove_empty_directory /usr/libexec/syswarden 755
remove_empty_directory /usr/share/doc/syswarden 755
remove_empty_directory /opt/syswarden/bin 755
remove_empty_directory /opt/syswarden 755
syswarden_finalize_retained_operator_configuration || fail 'Cannot finalize retained operator configuration.'
remove_empty_directory /var/lib/syswarden/ui 750
remove_empty_directory /var/log/syswarden 750

if ! absent "$tombstone"; then
    exact_regular "$tombstone" 600 39 \
        e1a0bbd8e3d90884bdaf9306233e6c2cfb5ab752c3065939139119982fed4514
    /usr/bin/rm -f -- "$tombstone"
    absent "$tombstone" || fail 'Removal tombstone remains after post-uninstall recovery.'
fi
remove_empty_directory /var/lib/syswarden 750

if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || \
        fail 'systemd daemon reload failed during post-uninstall recovery.'
fi

syswarden_assert_retained_operator_configuration || fail 'Configuration changed before removal finalization.'
/usr/bin/timeout 30 /usr/bin/sync || fail 'Cannot make post-uninstall cleanup durable.'

exact_regular "$marker" 600 71 \
    93066cdc965c4d5469a5e4d75f2e7fad16845a113381a78d5c422832cda85d8c
/usr/bin/rm -f -- "$marker"
absent "$marker" || fail 'Erase-ready marker remains after post-uninstall recovery.'
/usr/bin/sync -f -- /var/lib
/usr/bin/rm -f -- "$helper"
absent "$helper" || fail 'Post-uninstall recovery helper remains after cleanup.'
/usr/bin/sync -f -- /var/lib || exit 0

exit 0
