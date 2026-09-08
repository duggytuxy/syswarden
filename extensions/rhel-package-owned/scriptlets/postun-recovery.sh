#!/bin/sh
set -eu
umask 077

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

assert_terminal_directories_absent() {
    for path in \
        /usr/lib/systemd/system/syswarden-firewall.service.d \
        /usr/libexec/syswarden \
        /usr/share/doc/syswarden \
        /opt/syswarden \
        /etc/syswarden \
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

if absent "$marker"; then
    absent "$tombstone" || fail 'Removal tombstone remains without its erase-ready marker.'
    assert_terminal_directories_absent
    /usr/bin/rm -f -- "$helper"
    absent "$helper" || fail 'Post-uninstall recovery helper remains after terminal cleanup.'
    /usr/bin/sync -f -- /var/lib || exit 0
    exit 0
fi

exact_regular "$marker" 600 71 \
    3c429337c31a5c397da09b2976dc6cb759d0ae44f986dc19aa4e25f47a2970c8

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
remove_empty_directory /etc/syswarden/config/modules 750
remove_empty_directory /etc/syswarden/config 750
remove_empty_directory /etc/syswarden/lists 750
remove_empty_directory /etc/syswarden/tls 750
remove_empty_directory /etc/syswarden 750
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

/usr/bin/timeout 30 /usr/bin/sync || fail 'Cannot make post-uninstall cleanup durable.'

exact_regular "$marker" 600 71 \
    3c429337c31a5c397da09b2976dc6cb759d0ae44f986dc19aa4e25f47a2970c8
/usr/bin/rm -f -- "$marker"
absent "$marker" || fail 'Erase-ready marker remains after post-uninstall recovery.'
/usr/bin/sync -f -- /var/lib
/usr/bin/rm -f -- "$helper"
absent "$helper" || fail 'Post-uninstall recovery helper remains after cleanup.'
/usr/bin/sync -f -- /var/lib || exit 0

exit 0
