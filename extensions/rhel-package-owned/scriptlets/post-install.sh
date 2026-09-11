#!/bin/sh
set -eu
umask 077

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM post-install transaction state.' >&2
        exit 1
        ;;
esac

if [ "$1" -lt 1 ]; then
    printf '%s\n' 'Refusing an invalid RPM post-install transaction count.' >&2
    exit 1
fi

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

attest_installed_rhelpo_identity() {
    [ -x /usr/bin/rpm ] && [ -x /usr/bin/timeout ] && [ -x /usr/bin/mktemp ] || \
        fail 'RPM identity attestation is unavailable during interrupted migration recovery.'
    identity_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-postin.XXXXXXXXXX)" || \
        fail 'Cannot allocate the RPM identity attestation file.'
    cleanup_identity() {
        /usr/bin/rm -f -- "$identity_file"
    }
    trap cleanup_identity 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query \
        --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
        syswarden >"$identity_file" 2>/dev/null; then
        cleanup_identity
        trap - 0 1 2 3 15
        fail 'RPM identity query failed during interrupted migration recovery.'
    fi
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$identity_file")" = '0:0:600:1:35' ] || \
        fail 'RPM identity output is not canonical and bounded during interrupted migration recovery.'
    [ "$(/usr/bin/sha256sum -- "$identity_file" | /usr/bin/awk '{print $1}')" = \
        a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247 ] || \
        fail 'Installed RPM identity does not authorize interrupted migration recovery.'
    cleanup_identity
    trap - 0 1 2 3 15
}

exact_file() {
    path="$1"
    mode="$2"
    digest="$3"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RHEL package-owned file: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")" = "0:0:${mode}:1" ] || \
        fail "Refusing modified RHEL package-owned file metadata: $path"
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$digest" ] || \
        fail "Refusing modified RHEL package-owned file content: $path"
}

exact_legacy_source_unit() {
    path="$1"
    shift
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        fail "Refusing unsafe legacy SysWarden unit: $path"
    fi
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")"
    case "$metadata" in
        0:0:600:1|0:0:644:1) ;;
        *) fail "Refusing modified legacy SysWarden unit metadata: $path" ;;
    esac
    actual_digest="$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')"
    for digest in "$@"; do
        [ "$actual_digest" = "$digest" ] && return 0
    done
    fail "Refusing modified legacy SysWarden unit content: $path"
}

exact_directory() {
    path="$1"
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe systemd directory: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = '0:0:755' ] || \
        fail "Refusing modified systemd directory metadata: $path"
}

exact_directory_if_present() {
    path="$1"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    exact_directory "$path"
}

exact_vendor_enablement() {
    path="$1"
    target="$2"
    [ -L "$path" ] || fail "Required SysWarden enablement is absent: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$path")" = '0:0:1' ] || \
        fail "Refusing modified SysWarden enablement metadata: $path"
    [ "$(/usr/bin/readlink -- "$path")" = "$target" ] || \
        fail "Refusing unexpected SysWarden enablement target: $path"
}

vendor_enablement_is_exact() {
    path="$1"
    target="$2"
    [ -L "$path" ] && \
        [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$path")" = '0:0:1' ] && \
        [ "$(/usr/bin/readlink -- "$path")" = "$target" ]
}

remove_exact_vendor_enablement_if_present() {
    path="$1"
    target="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    exact_vendor_enablement "$path" "$target"
    /usr/bin/rm -f -- "$path"
    [ ! -e "$path" ] && [ ! -L "$path" ] || \
        fail "SysWarden enablement rollback did not persist: $path"
}

exact_preset_marker() {
    path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || fail 'Refusing unsafe preset-recovery marker.'
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")" = '0:0:600:1:35' ] || \
        fail 'Refusing modified preset-recovery marker metadata.'
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = \
        862ed0191cbc87e5d7379296af67f418b0f27dec63738fa3a7ff9a9e67b1ce82 ] || \
        fail 'Refusing modified preset-recovery marker content.'
}

remove_recoverable_preset_prefix() {
    path="$1"
    [ -x /usr/bin/head ] || fail 'Preset-recovery prefix repair is unavailable.'
    [ -f "$path" ] && [ ! -L "$path" ] || fail 'Refusing unsafe partial preset-recovery marker.'
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")"
    case "$metadata" in
        0:0:600:1:*) ;;
        *) fail 'Refusing modified partial preset-recovery marker metadata.' ;;
    esac
    size="${metadata##*:}"
    case "$size" in
        ''|*[!0-9]*) fail 'Refusing malformed partial preset-recovery marker size.' ;;
    esac
    [ "$size" -lt 35 ] || fail 'Refusing non-partial preset-recovery marker.'
    actual_digest="$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')"
    expected_digest="$(printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 | \
        /usr/bin/head -c "$size" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
    [ "$actual_digest" = "$expected_digest" ] || \
        fail 'Refusing modified partial preset-recovery marker content.'
    /usr/bin/rm -f -- "$path"
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail 'Partial preset-recovery marker remains.'
    /usr/bin/sync -f -- /var/lib
}

publish_preset_marker() {
    marker="$1"
    temporary="${marker}.new"
    if [ -e "$temporary" ] || [ -L "$temporary" ]; then
        temporary_metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$temporary")"
        if [ "$temporary_metadata" != '0:0:600:1:35' ]; then
            remove_recoverable_preset_prefix "$temporary"
        fi
    fi
    if [ -e "$temporary" ] || [ -L "$temporary" ]; then
        exact_preset_marker "$temporary"
        if [ -e "$marker" ] || [ -L "$marker" ]; then
            exact_preset_marker "$marker"
            /usr/bin/rm -f -- "$temporary"
            /usr/bin/sync -f -- /var/lib
        else
            /usr/bin/sync -f -- "$temporary"
            /usr/bin/mv -T -- "$temporary" "$marker"
            /usr/bin/sync -f -- /var/lib
        fi
    fi
    if [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
        printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 > "$temporary"
        exact_preset_marker "$temporary"
        /usr/bin/sync -f -- "$temporary"
        /usr/bin/mv -T -- "$temporary" "$marker"
        /usr/bin/sync -f -- /var/lib
    fi
    exact_preset_marker "$marker"
}

migrate_enablement() {
    migration_path="$1"
    migration_legacy_target="$2"
    migration_vendor_target="$3"
    migration_temporary="${migration_path}.syswarden-rhelpo-migration"
    migration_directory="$(/usr/bin/dirname -- "$migration_path")"
    [ -x /usr/bin/sync ] || fail 'Enablement migration durability support is unavailable.'
    if [ -e "$migration_temporary" ] || [ -L "$migration_temporary" ]; then
        [ -L "$migration_temporary" ] || fail "Refusing unsafe interrupted enablement migration: $migration_temporary"
        [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$migration_temporary")" = '0:0:1' ] || \
            fail "Refusing modified interrupted enablement migration: $migration_temporary"
        [ "$(/usr/bin/readlink -- "$migration_temporary")" = "$migration_vendor_target" ] || \
            fail "Refusing unexpected interrupted enablement target: $migration_temporary"
        /usr/bin/rm -f -- "$migration_temporary"
        [ ! -e "$migration_temporary" ] && [ ! -L "$migration_temporary" ] || \
            fail "Interrupted enablement migration remains: $migration_temporary"
        /usr/bin/sync -f -- "$migration_directory"
    fi
    if [ ! -e "$migration_path" ] && [ ! -L "$migration_path" ]; then
        return 0
    fi
    [ -L "$migration_path" ] || fail "Refusing non-symlink SysWarden enablement: $migration_path"
    migration_target="$(/usr/bin/readlink -- "$migration_path")"
    if [ "$migration_target" = "$migration_vendor_target" ]; then
        return 0
    fi
    [ "$migration_target" = "$migration_legacy_target" ] || \
        fail "Refusing unexpected SysWarden enablement target: $migration_path"
    exact_directory "$migration_directory"
    /usr/bin/ln -s -- "$migration_vendor_target" "$migration_temporary"
    [ -L "$migration_temporary" ] && \
        [ "$(/usr/bin/readlink -- "$migration_temporary")" = "$migration_vendor_target" ] || \
        fail "Enablement migration temporary is not exact: $migration_temporary"
    /usr/bin/sync -f -- "$migration_directory"
    /usr/bin/mv -T -- "$migration_temporary" "$migration_path"
    [ "$(/usr/bin/readlink -- "$migration_path")" = "$migration_vendor_target" ] || \
        fail "RHEL package-owned enablement migration did not persist: $migration_path"
    /usr/bin/sync -f -- "$migration_directory"
}

exact_file /usr/lib/systemd/system/syswarden-core.service 644 \
    cfc30f12ea66548dce4322d2cde38a62cbc257d93be3e82218434a848051dbd7
exact_file /usr/lib/systemd/system/syswarden-firewall.service 644 \
    989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
exact_file /usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf 644 \
    8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483
exact_file /usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset 644 \
    0f6e058dc43d09ed101799ee444015918d28127186c9f0cbc78231906b955354
exact_file /usr/share/doc/syswarden/rhel-package-owned-profile.json 644 \
    06b0aa821553e322f58641767ac96385c1ad5210bf4d074d735d4bfe06365ac5

exact_directory /etc/systemd/system
exact_directory_if_present /etc/systemd/system/multi-user.target.wants

if [ "$1" -gt 1 ]; then
    core_present=0
    firewall_present=0
    if [ -e /etc/systemd/system/syswarden-core.service ] || \
       [ -L /etc/systemd/system/syswarden-core.service ]; then
        core_present=1
    fi
    if [ -e /etc/systemd/system/syswarden-firewall.service ] || \
       [ -L /etc/systemd/system/syswarden-firewall.service ]; then
        firewall_present=1
    fi
    if [ "$core_present" -ne "$firewall_present" ]; then
        attest_installed_rhelpo_identity
    fi
    if [ "$core_present" -eq 1 ]; then
        exact_legacy_source_unit /etc/systemd/system/syswarden-core.service \
            8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd \
            cfc30f12ea66548dce4322d2cde38a62cbc257d93be3e82218434a848051dbd7
    fi
    if [ "$firewall_present" -eq 1 ]; then
        exact_legacy_source_unit /etc/systemd/system/syswarden-firewall.service \
            989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
    fi
    if [ "$core_present" -eq 1 ]; then
        exact_legacy_source_unit /etc/systemd/system/syswarden-core.service \
            8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd \
            cfc30f12ea66548dce4322d2cde38a62cbc257d93be3e82218434a848051dbd7
        /usr/bin/rm -f -- /etc/systemd/system/syswarden-core.service
        [ ! -e /etc/systemd/system/syswarden-core.service ] && \
            [ ! -L /etc/systemd/system/syswarden-core.service ] || \
            fail 'Legacy core unit remains after RHEL package-owned migration.'
        /usr/bin/sync -f -- /etc/systemd/system
    fi
    if [ "$firewall_present" -eq 1 ]; then
        exact_legacy_source_unit /etc/systemd/system/syswarden-firewall.service \
            989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
        /usr/bin/rm -f -- /etc/systemd/system/syswarden-firewall.service
        [ ! -e /etc/systemd/system/syswarden-firewall.service ] && \
            [ ! -L /etc/systemd/system/syswarden-firewall.service ] || \
            fail 'Legacy firewall unit remains after RHEL package-owned migration.'
        /usr/bin/sync -f -- /etc/systemd/system
    fi
fi

migrate_enablement \
    /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
    ../syswarden-core.service \
    /usr/lib/systemd/system/syswarden-core.service
migrate_enablement \
    /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
    ../syswarden-firewall.service \
    /usr/lib/systemd/system/syswarden-firewall.service

for priority_unit in \
    /etc/systemd/system/syswarden-core.service \
    /etc/systemd/system/syswarden-firewall.service; do
    [ ! -e "$priority_unit" ] && [ ! -L "$priority_unit" ] || \
        fail "Priority SysWarden unit remains after RHEL package-owned installation: $priority_unit"
done
exact_directory /etc/systemd/system
exact_directory_if_present /etc/systemd/system/multi-user.target.wants

preset_marker=/var/lib/.syswarden-rhelpo-preset-pending-v1
preset_required=0
if [ "$1" -eq 1 ]; then
    publish_preset_marker "$preset_marker"
    preset_required=1
elif [ -e "$preset_marker" ] || [ -L "$preset_marker" ] || \
     [ -e "${preset_marker}.new" ] || [ -L "${preset_marker}.new" ]; then
    publish_preset_marker "$preset_marker"
    preset_required=1
fi

if [ "$preset_required" -eq 1 ]; then
    [ -x /usr/bin/systemctl ] && [ -x /usr/bin/sync ] && [ -x /usr/bin/timeout ] || \
        fail 'Durable systemd preset application is unavailable.'
    for link in \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service; do
        remove_exact_vendor_enablement_if_present "$link" \
            "/usr/lib/systemd/system$(printf '%s' "$link" | /usr/bin/awk -F/ '{print "/" $NF}')"
    done
    if ! /usr/bin/systemctl preset \
        syswarden-firewall.service \
        syswarden-core.service >/dev/null 2>&1; then
        exact_directory /etc/systemd/system
        exact_directory_if_present /etc/systemd/system/multi-user.target.wants
        remove_exact_vendor_enablement_if_present \
            /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
            /usr/lib/systemd/system/syswarden-firewall.service
        remove_exact_vendor_enablement_if_present \
            /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
            /usr/lib/systemd/system/syswarden-core.service
        fail 'RHEL package-owned systemd preset application failed.'
    fi
    exact_directory /etc/systemd/system
    exact_directory /etc/systemd/system/multi-user.target.wants
    if ! vendor_enablement_is_exact \
            /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
            /usr/lib/systemd/system/syswarden-firewall.service || \
       ! vendor_enablement_is_exact \
            /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
            /usr/lib/systemd/system/syswarden-core.service; then
        remove_exact_vendor_enablement_if_present \
            /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
            /usr/lib/systemd/system/syswarden-firewall.service
        remove_exact_vendor_enablement_if_present \
            /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
            /usr/lib/systemd/system/syswarden-core.service
        fail 'RHEL package-owned preset did not create both exact enablement links.'
    fi
    /usr/bin/timeout 30 /usr/bin/sync || \
        fail 'Cannot make exact systemd preset enablement durable.'
    exact_directory /etc/systemd/system
    exact_directory /etc/systemd/system/multi-user.target.wants
    exact_vendor_enablement \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
        /usr/lib/systemd/system/syswarden-firewall.service
    exact_vendor_enablement \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /usr/lib/systemd/system/syswarden-core.service
    exact_preset_marker "$preset_marker"
    /usr/bin/rm -f -- "$preset_marker"
    [ ! -e "$preset_marker" ] && [ ! -L "$preset_marker" ] || \
        fail 'Preset-recovery marker remains after exact preset application.'
    /usr/bin/sync -f -- /var/lib
fi

if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || \
        fail 'systemd daemon reload failed after RHEL package-owned installation.'
fi

exit 0
