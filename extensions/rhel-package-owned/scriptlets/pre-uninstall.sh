#!/bin/sh
set -eu
umask 077

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM pre-uninstall transaction state.' >&2
        exit 1
        ;;
esac

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

exact_empty_directory() {
    path="$1"
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RHEL package-owned directory: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = '0:0:750' ] || \
        fail "Refusing modified RHEL package-owned directory metadata: $path"
    for entry in "$path"/.[!.]* "$path"/..?* "$path"/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        fail "Refusing RPM erase while runtime state remains: $entry"
    done
}

exact_payload_file() {
    path="$1"
    digest="$2"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RHEL package-owned payload: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")" = '0:0:644:1' ] || \
        fail "Refusing modified RHEL package-owned payload metadata: $path"
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$digest" ] || \
        fail "Refusing modified RHEL package-owned payload content: $path"
    owner_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-preun.XXXXXXXXXX)" || \
        fail 'Cannot allocate the RPM ownership attestation file.'
    cleanup_owner() {
        /usr/bin/rm -f -- "$owner_file"
    }
    trap cleanup_owner 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query --file "$path" \
        --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
        >"$owner_file" 2>/dev/null; then
        cleanup_owner
        trap - 0 1 2 3 15
        fail "RPM ownership query failed for RHEL package-owned payload: $path"
    fi
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$owner_file")" = '0:0:600:1:35' ] || \
        fail "RPM ownership output is not canonical and bounded: $path"
    [ "$(/usr/bin/sha256sum -- "$owner_file" | /usr/bin/awk '{print $1}')" = \
        a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247 ] || \
        fail "Refusing payload without exact RHEL package ownership: $path"
    cleanup_owner
    trap - 0 1 2 3 15
}

exact_owned_payload_file() {
    path="$1"
    mode="$2"
    digest="${3:-}"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RPM-owned product payload: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")" = "0:0:${mode}:1" ] || \
        fail "Refusing modified RPM-owned product payload metadata: $path"
    if [ -n "$digest" ]; then
        [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$digest" ] || \
            fail "Refusing modified RPM-owned product payload content: $path"
    fi
    owner_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-preun-product.XXXXXXXXXX)" || \
        fail 'Cannot allocate the product RPM ownership attestation file.'
    cleanup_owner() {
        /usr/bin/rm -f -- "$owner_file"
    }
    trap cleanup_owner 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query --file "$path" \
        --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
        >"$owner_file" 2>/dev/null; then
        cleanup_owner
        trap - 0 1 2 3 15
        fail "RPM ownership query failed for product payload: $path"
    fi
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$owner_file")" = '0:0:600:1:35' ] || \
        fail "RPM ownership output is not canonical and bounded: $path"
    [ "$(/usr/bin/sha256sum -- "$owner_file" | /usr/bin/awk '{print $1}')" = \
        a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247 ] || \
        fail "Refusing product payload without exact RHEL package ownership: $path"
    cleanup_owner
    trap - 0 1 2 3 15
}

exact_recovery_helper() {
    path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe post-uninstall recovery helper: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")" = '0:0:700:1:9843' ] || \
        fail "Refusing modified post-uninstall recovery helper metadata: $path"
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = \
        64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c ] || \
        fail "Refusing modified post-uninstall recovery helper content: $path"
}

remove_recoverable_recovery_helper_prefix() {
    path="$1"
    source="$2"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe partial post-uninstall recovery helper: $path"
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")"
    case "$metadata" in
        0:0:700:1:*) ;;
        *) fail "Refusing modified partial post-uninstall recovery helper metadata: $path" ;;
    esac
    size="${metadata##*:}"
    case "$size" in
        ''|*[!0-9]*) fail "Refusing malformed partial post-uninstall recovery helper size: $path" ;;
    esac
    [ "$size" -lt 9843 ] || fail "Refusing non-partial post-uninstall recovery helper: $path"
    actual_digest="$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')"
    expected_digest="$(/usr/bin/head -c "$size" -- "$source" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
    [ "$actual_digest" = "$expected_digest" ] || \
        fail "Refusing modified partial post-uninstall recovery helper content: $path"
    /usr/bin/rm -f -- "$path"
    [ ! -e "$path" ] && [ ! -L "$path" ] || \
        fail "Partial post-uninstall recovery helper remains after bounded recovery: $path"
    /usr/bin/sync -f -- /var/lib
}

publish_recovery_helper() {
    source=/usr/libexec/syswarden/rhelpo-postun-recovery-v1
    destination=/var/lib/.syswarden-rhelpo-postun-recovery-v1
    temporary="${destination}.new"
    if [ -e "$temporary" ] || [ -L "$temporary" ]; then
        temporary_metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$temporary")"
        if [ "$temporary_metadata" != '0:0:700:1:9843' ]; then
            remove_recoverable_recovery_helper_prefix "$temporary" "$source"
        fi
    fi
    if [ -e "$temporary" ] || [ -L "$temporary" ]; then
        exact_recovery_helper "$temporary"
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            exact_recovery_helper "$destination"
            /usr/bin/rm -f -- "$temporary"
        else
            /usr/bin/sync -f -- "$temporary"
            /usr/bin/mv -T -- "$temporary" "$destination"
        fi
    fi
    if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
        /usr/bin/install -m 0700 -- "$source" "$temporary"
        exact_recovery_helper "$temporary"
        /usr/bin/sync -f -- "$temporary"
        /usr/bin/mv -T -- "$temporary" "$destination"
    fi
    exact_recovery_helper "$destination"
    [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || \
        fail 'Post-uninstall recovery helper publication left a temporary file.'
    /usr/bin/sync -f -- "$destination"
    /usr/bin/sync -f -- /var/lib
}

exact_product_directory() {
    path="$1"
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RPM-owned product directory: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = '0:0:755' ] || \
        fail "Refusing modified RPM-owned product directory metadata: $path"
}

exact_owned_payload_symlink() {
    path="$1"
    target="$2"
    [ -L "$path" ] || fail "Refusing missing or non-symlink RPM-owned product link: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$path")" = '0:0:777:1' ] || \
        fail "Refusing modified RPM-owned product link metadata: $path"
    [ "$(/usr/bin/readlink -- "$path")" = "$target" ] || \
        fail "Refusing modified RPM-owned product link target: $path"
    owner_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-preun-link.XXXXXXXXXX)" || \
        fail 'Cannot allocate the product-link RPM ownership attestation file.'
    cleanup_owner() {
        /usr/bin/rm -f -- "$owner_file"
    }
    trap cleanup_owner 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query --file "$path" \
        --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
        >"$owner_file" 2>/dev/null; then
        cleanup_owner
        trap - 0 1 2 3 15
        fail "RPM ownership query failed for product link: $path"
    fi
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$owner_file")" = '0:0:600:1:35' ] || \
        fail "RPM ownership output is not canonical and bounded: $path"
    [ "$(/usr/bin/sha256sum -- "$owner_file" | /usr/bin/awk '{print $1}')" = \
        a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247 ] || \
        fail "Refusing product link without exact RHEL package ownership: $path"
    cleanup_owner
    trap - 0 1 2 3 15
}

attest_systemd_value() {
    unit="$1"
    property="$2"
    expected_size="$3"
    expected_digest="$4"
    state_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-systemd.XXXXXXXXXX)" || \
        fail 'Cannot allocate the systemd state attestation file.'
    cleanup_state() {
        /usr/bin/rm -f -- "$state_file"
    }
    trap cleanup_state 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/systemctl show \
        --property="$property" --value "$unit" >"$state_file" 2>/dev/null; then
        cleanup_state
        trap - 0 1 2 3 15
        fail "Cannot query exact $property for SysWarden service: $unit"
    fi
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$state_file")" = \
        "0:0:600:1:${expected_size}" ] || \
        fail "Systemd $property output is not canonical and bounded: $unit"
    [ "$(/usr/bin/sha256sum -- "$state_file" | /usr/bin/awk '{print $1}')" = "$expected_digest" ] || \
        fail "Refusing non-quiescent systemd $property before RPM erase: $unit"
    cleanup_state
    trap - 0 1 2 3 15
}

if [ "$1" -eq 0 ]; then
    [ -x /usr/bin/rpm ] && [ -x /usr/bin/timeout ] && [ -x /usr/bin/mktemp ] && \
        [ -x /usr/bin/head ] && \
        [ -x /usr/bin/install ] && [ -x /usr/bin/mv ] && [ -x /usr/bin/sync ] || \
        fail 'RPM ownership attestation is unavailable before final erase.'
    for parent_and_mode in \
        /etc:755 \
        /etc/systemd:755 \
        /etc/systemd/system:755 \
        /etc/systemd/system/multi-user.target.wants:755 \
        /etc/syswarden:750 \
        /etc/syswarden/config:750 \
        /etc/syswarden/config/modules:750 \
        /etc/syswarden/lists:750 \
        /etc/syswarden/tls:750 \
        /var:755 \
        /var/lib:755 \
        /var/lib/syswarden:750 \
        /var/lib/syswarden/ui:750 \
        /var/log:755 \
        /var/log/syswarden:750 \
        /opt:755 \
        /opt/syswarden:755 \
        /opt/syswarden/bin:755 \
        /usr:755 \
        /usr/lib:755 \
        /usr/lib/systemd:755 \
        /usr/lib/systemd/system:755 \
        /usr/lib/systemd/system/syswarden-firewall.service.d:755 \
        /usr/lib/systemd/system-preset:755 \
        /usr/libexec:755 \
        /usr/libexec/syswarden:755 \
        /usr/local:755 \
        /usr/local/bin:755 \
        /usr/share:755 \
        /usr/share/bash-completion:755 \
        /usr/share/bash-completion/completions:755 \
        /usr/share/doc:755 \
        /usr/share/doc/syswarden:755; do
        parent_path="${parent_and_mode%:*}"
        parent_mode="${parent_and_mode##*:}"
        [ -d "$parent_path" ] && [ ! -L "$parent_path" ] || \
            fail "Refusing unsafe RPM payload ancestry before erase: $parent_path"
        [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$parent_path")" = "0:0:${parent_mode}" ] || \
            fail "Refusing modified RPM payload ancestry before erase: $parent_path"
    done
    for preset_marker in \
        /var/lib/.syswarden-rhelpo-preset-pending-v1 \
        /var/lib/.syswarden-rhelpo-preset-pending-v1.new \
        /var/lib/.syswarden-rhelpo-erase-ready-v1.new \
        /var/lib/.syswarden-removal-finalizing-v1 \
        /var/lib/.syswarden-removal-finalizing-v1.new \
        /var/lib/syswarden/removal-in-progress-v1.new \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration; do
        [ ! -e "$preset_marker" ] && [ ! -L "$preset_marker" ] || \
            fail "Refusing RPM erase while preset recovery remains pending: $preset_marker"
    done
    marker=/var/lib/.syswarden-rhelpo-erase-ready-v1
    [ -f "$marker" ] && [ ! -L "$marker" ] || \
        fail 'Run syswarden uninstall before erasing the RHEL package-owned RPM.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$marker")" = '0:0:600:1' ] || \
        fail 'Refusing modified RHEL package-owned erase authorization metadata.'
    [ "$(/usr/bin/sha256sum -- "$marker" | /usr/bin/awk '{print $1}')" = \
        3c429337c31a5c397da09b2976dc6cb759d0ae44f986dc19aa4e25f47a2970c8 ] || \
        fail 'Refusing modified RHEL package-owned erase authorization content.'
    tombstone=/var/lib/syswarden/removal-in-progress-v1
    [ -f "$tombstone" ] && [ ! -L "$tombstone" ] || \
        fail 'Refusing RPM erase without the durable SysWarden removal barrier.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$tombstone")" = '0:0:600:1:39' ] || \
        fail 'Refusing modified SysWarden removal barrier metadata.'
    [ "$(/usr/bin/sha256sum -- "$tombstone" | /usr/bin/awk '{print $1}')" = \
        e1a0bbd8e3d90884bdaf9306233e6c2cfb5ab752c3065939139119982fed4514 ] || \
        fail 'Refusing modified SysWarden removal barrier content.'

    dropin_directory=/usr/lib/systemd/system/syswarden-firewall.service.d
    [ -d "$dropin_directory" ] && [ ! -L "$dropin_directory" ] || \
        fail 'Refusing unsafe SysWarden systemd drop-in directory before RPM erase.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$dropin_directory")" = '0:0:755' ] || \
        fail 'Refusing modified SysWarden systemd drop-in directory metadata.'
    dropin_children=0
    for entry in "$dropin_directory"/.[!.]* "$dropin_directory"/..?* "$dropin_directory"/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        [ "$entry" = "$dropin_directory/10-syswarden-wireguard-ordering.conf" ] || \
            fail "Refusing unexpected SysWarden systemd drop-in entry: $entry"
        dropin_children=$((dropin_children + 1))
    done
    [ "$dropin_children" -eq 1 ] || fail 'Required SysWarden systemd drop-in is absent.'
    exact_payload_file /usr/lib/systemd/system/syswarden-core.service \
        8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd
    exact_payload_file /usr/lib/systemd/system/syswarden-firewall.service \
        989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
    exact_payload_file "$dropin_directory/10-syswarden-wireguard-ordering.conf" \
        8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483
    exact_payload_file /usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset \
        0f6e058dc43d09ed101799ee444015918d28127186c9f0cbc78231906b955354
    exact_payload_file /usr/share/doc/syswarden/rhel-package-owned-profile.json \
        06b0aa821553e322f58641767ac96385c1ad5210bf4d074d735d4bfe06365ac5
    exact_owned_payload_file /usr/share/bash-completion/completions/syswarden 644
    exact_owned_payload_symlink /usr/local/bin/syswarden /opt/syswarden/bin/syswarden-cli
    exact_owned_payload_symlink /usr/local/bin/syswarden-tui /opt/syswarden/bin/syswarden-tui

    exact_product_directory /usr/share/doc/syswarden
    documentation_children=0
    for entry in /usr/share/doc/syswarden/.[!.]* /usr/share/doc/syswarden/..?* /usr/share/doc/syswarden/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in
            /usr/share/doc/syswarden/rhel-package-owned-profile.json)
                documentation_children=$((documentation_children + 1))
                ;;
            /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt|/usr/share/doc/syswarden/LICENSE.txt)
                exact_owned_payload_file "$entry" 644
                documentation_children=$((documentation_children + 1))
                ;;
            *) fail "Refusing unexpected SysWarden documentation entry before RPM erase: $entry" ;;
        esac
    done
    [ "$documentation_children" -eq 3 ] || fail 'RPM-owned documentation inventory is incomplete.'

    exact_product_directory /usr/libexec/syswarden
    recovery_children=0
    for entry in /usr/libexec/syswarden/.[!.]* /usr/libexec/syswarden/..?* /usr/libexec/syswarden/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        [ "$entry" = /usr/libexec/syswarden/rhelpo-postun-recovery-v1 ] || \
            fail "Refusing unexpected RHEL package-owned helper payload: $entry"
        exact_owned_payload_file "$entry" 755 \
            64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c
        recovery_children=$((recovery_children + 1))
    done
    [ "$recovery_children" -eq 1 ] || fail 'RPM-owned recovery helper inventory is incomplete.'

    exact_product_directory /opt/syswarden
    exact_product_directory /opt/syswarden/bin
    product_binary_children=0
    for entry in /opt/syswarden/bin/.[!.]* /opt/syswarden/bin/..?* /opt/syswarden/bin/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in
            /opt/syswarden/bin/syswarden-cli|/opt/syswarden/bin/syswarden-core|/opt/syswarden/bin/syswarden-tui)
                exact_owned_payload_file "$entry" 750
                product_binary_children=$((product_binary_children + 1))
                ;;
            *) fail "Refusing unexpected product binary entry before RPM erase: $entry" ;;
        esac
    done
    [ "$product_binary_children" -eq 3 ] || fail 'RPM-owned product binary inventory is incomplete.'
    product_children=0
    for entry in /opt/syswarden/.[!.]* /opt/syswarden/..?* /opt/syswarden/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in
            /opt/syswarden/bin)
                product_children=$((product_children + 1))
                ;;
            /opt/syswarden/signatures.json)
                exact_owned_payload_file "$entry" 640
                product_children=$((product_children + 1))
                ;;
            *) fail "Refusing unexpected product entry before RPM erase: $entry" ;;
        esac
    done
    [ "$product_children" -eq 2 ] || fail 'RPM-owned product inventory is incomplete.'

    exact_empty_directory /etc/syswarden/config/modules
    exact_empty_directory /etc/syswarden/lists
    exact_empty_directory /etc/syswarden/tls
    exact_empty_directory /var/lib/syswarden/ui
    exact_empty_directory /var/log/syswarden
    for path in /etc/syswarden/config /etc/syswarden /var/lib/syswarden; do
        [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RHEL package-owned directory: $path"
        [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = '0:0:750' ] || \
            fail "Refusing modified RHEL package-owned directory metadata: $path"
    done
    config_children=0
    for entry in /etc/syswarden/config/.[!.]* /etc/syswarden/config/..?* /etc/syswarden/config/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        [ "$entry" = /etc/syswarden/config/modules ] || fail 'Refusing RPM erase while configuration state remains.'
        config_children=$((config_children + 1))
    done
    [ "$config_children" -eq 1 ] || fail 'RHEL package-owned modules directory is absent.'
    product_children=0
    for entry in /etc/syswarden/.[!.]* /etc/syswarden/..?* /etc/syswarden/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in
            /etc/syswarden/config|/etc/syswarden/lists|/etc/syswarden/tls)
                product_children=$((product_children + 1))
                ;;
            *)
                fail 'Refusing RPM erase while product configuration remains.'
                ;;
        esac
    done
    [ "$product_children" -eq 3 ] || fail 'RHEL package-owned configuration skeleton is incomplete.'
    state_children=0
    for entry in /var/lib/syswarden/.[!.]* /var/lib/syswarden/..?* /var/lib/syswarden/*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in
            /var/lib/syswarden/ui|/var/lib/syswarden/removal-in-progress-v1)
                state_children=$((state_children + 1))
                ;;
            *)
                fail 'Refusing RPM erase while product state remains.'
                ;;
        esac
    done
    [ "$state_children" -eq 2 ] || fail 'RHEL package-owned state skeleton or removal barrier is absent.'
    for link in \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service; do
        [ ! -e "$link" ] && [ ! -L "$link" ] || fail "Refusing RPM erase while enablement remains: $link"
    done

    if [ -d /run/systemd/system ]; then
        [ -x /usr/bin/systemctl ] || fail 'Cannot attest inactive SysWarden services before RPM erase.'
        for unit in syswarden-core.service syswarden-firewall.service; do
            attest_systemd_value "$unit" ActiveState 9 \
                cb6f82a52d11c260ee6936511d22d5a7db55f8e7c5afe9f03ea847350ce860c5
            attest_systemd_value "$unit" Job 1 \
                01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
        done
    fi

    publish_recovery_helper

fi

exit 0
