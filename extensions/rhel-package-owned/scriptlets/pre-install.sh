#!/bin/sh
set -eu
umask 077

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM pre-install transaction state.' >&2
        exit 1
        ;;
esac

if [ "$1" -lt 1 ]; then
    printf '%s\n' 'Refusing an invalid RPM pre-install transaction count.' >&2
    exit 1
fi

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

exact_legacy_source_unit() {
    path="$1"
    digest="$2"
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        fail "Refusing unsafe legacy SysWarden unit: $path"
    fi
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")"
    case "$metadata" in
        0:0:600:1|0:0:644:1) ;;
        *) fail "Refusing modified legacy SysWarden unit metadata: $path" ;;
    esac
    [ "$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')" = "$digest" ] || \
        fail "Refusing modified legacy SysWarden unit content: $path"
}

exact_enablement() {
    path="$1"
    legacy_target="$2"
    vendor_target="$3"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ -L "$path" ] || fail "Refusing non-symlink SysWarden enablement: $path"
    target="$(/usr/bin/readlink -- "$path")"
    [ "$target" = "$legacy_target" ] || [ "$target" = "$vendor_target" ] || \
        fail "Refusing unexpected SysWarden enablement target: $path"
}

exact_systemd_directory() {
    path="$1"
    required="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        [ "$required" -eq 0 ] || fail "Required systemd directory is absent: $path"
        return 0
    fi
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe systemd directory: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")" = '0:0:755' ] || \
        fail "Refusing modified systemd directory metadata: $path"
}

exact_existing_directory() {
    path="$1"
    mode="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ -d "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe RPM payload directory: $path"
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a' -- "$path")"
    # RHEL filesystem packages ship this shared parent read-only.
    if [ "$path" = /usr/lib ] && [ "$mode" = 755 ] && [ "$metadata" = '0:0:555' ]; then
        return 0
    fi
    [ "$metadata" = "0:0:${mode}" ] || \
        fail "Refusing modified RPM payload directory metadata: $path"
}

exact_existing_product_directory() {
    path="$1"
    mode="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ "$transaction_count" -gt 1 ] || \
        fail "Refusing pre-existing dedicated SysWarden directory during clean installation: $path"
    exact_existing_directory "$path" "$mode"
}

exact_existing_regular() {
    path="$1"
    mode="$2"
    ownership="$3"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ "$transaction_count" -gt 1 ] || \
        fail "Refusing pre-existing RPM payload file during clean installation: $path"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Refusing unsafe existing RPM payload file: $path"
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$path")" = "0:0:${mode}:1" ] || \
        fail "Refusing modified existing RPM payload metadata: $path"
    attest_payload_owner "$path" "$ownership"
}

exact_existing_symlink() {
    path="$1"
    target="$2"
    ownership="$3"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ "$transaction_count" -gt 1 ] || \
        fail "Refusing pre-existing RPM payload link during clean installation: $path"
    [ -L "$path" ] || fail "Refusing non-symlink existing RPM payload link: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$path")" = '0:0:777:1' ] || \
        fail "Refusing modified existing RPM payload link metadata: $path"
    [ "$(/usr/bin/readlink -- "$path")" = "$target" ] || \
        fail "Refusing unexpected existing RPM payload link target: $path"
    attest_payload_owner "$path" "$ownership"
}

exact_migration_temporary() {
    path="$1"
    target="$2"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ "$1" != '' ] || fail 'Interrupted enablement migration path is unavailable.'
    [ -L "$path" ] || fail "Refusing unsafe interrupted enablement migration: $path"
    [ "$(/usr/bin/stat -c '%u:%g:%h' -- "$path")" = '0:0:1' ] || \
        fail "Refusing modified interrupted enablement migration: $path"
    [ "$(/usr/bin/readlink -- "$path")" = "$target" ] || \
        fail "Refusing unexpected interrupted enablement target: $path"
    [ "$transaction_count" -gt 1 ] || \
        fail 'Refusing interrupted enablement migration during clean installation.'
    attest_installed_identity 35 a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247
}

attest_installed_identity() {
    expected_size="$1"
    expected_digest="$2"
    alternate_size="${3:-}"
    alternate_digest="${4:-}"
    [ -x /usr/bin/rpm ] && [ -x /usr/bin/timeout ] && [ -x /usr/bin/mktemp ] || \
        fail 'RPM identity attestation is unavailable during RHEL package-owned migration.'
    identity_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-prein.XXXXXXXXXX)" || \
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
        fail 'RPM identity query failed during RHEL package-owned migration.'
    fi
    identity_metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$identity_file")"
    identity_digest="$(/usr/bin/sha256sum -- "$identity_file" | /usr/bin/awk '{print $1}')"
    if [ "$identity_metadata" != "0:0:600:1:${expected_size}" ] || \
       [ "$identity_digest" != "$expected_digest" ]; then
        [ -n "$alternate_size" ] && [ -n "$alternate_digest" ] && \
            [ "$identity_metadata" = "0:0:600:1:${alternate_size}" ] && \
            [ "$identity_digest" = "$alternate_digest" ] || \
            fail 'Installed RPM identity does not match the authorized migration source.'
    fi
    cleanup_identity
    trap - 0 1 2 3 15
}

attest_payload_owner() {
    owned_path="$1"
    ownership="$2"
    owner_file="$(/usr/bin/mktemp /tmp/syswarden-rhelpo-prein-owner.XXXXXXXXXX)" || \
        fail 'Cannot allocate the RPM payload ownership attestation file.'
    cleanup_owner() {
        /usr/bin/rm -f -- "$owner_file"
    }
    trap cleanup_owner 0 1 2 3 15
    if ! /usr/bin/timeout 15 /usr/bin/rpm --noplugins --query --file "$owned_path" \
        --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
        >"$owner_file" 2>/dev/null; then
        cleanup_owner
        trap - 0 1 2 3 15
        fail "RPM ownership query failed for existing payload: $owned_path"
    fi
    owner_metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$owner_file")"
    owner_digest="$(/usr/bin/sha256sum -- "$owner_file" | /usr/bin/awk '{print $1}')"
    owner_is_rhelpo=0
    if [ "$owner_metadata" = '0:0:600:1:35' ] && \
       [ "$owner_digest" = a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247 ]; then
        owner_is_rhelpo=1
    fi
    owner_is_standard=0
    if [ "$owner_metadata" = '0:0:600:1:28' ] && \
       [ "$owner_digest" = c3dd1e8df980ad039e7ba1c3c7a82625048df88a5636bdb039da6cc1c06de7c9 ]; then
        owner_is_standard=1
    fi
    cleanup_owner
    trap - 0 1 2 3 15
    case "$ownership" in
        shared)
            [ "$owner_is_rhelpo" -eq 1 ] || [ "$owner_is_standard" -eq 1 ] || \
                fail "Existing shared payload lacks an authorized RPM owner: $owned_path"
            ;;
        rhelpo)
            [ "$owner_is_rhelpo" -eq 1 ] || \
                fail "Existing RHEL package-owned payload lacks its exact RPM owner: $owned_path"
            ;;
        *) fail "Internal payload ownership class is invalid: $owned_path" ;;
    esac
}

transaction_count="$1"

for directory_and_mode in \
    /etc:755 \
    /etc/systemd:755 \
    /etc/systemd/system:755 \
    /etc/systemd/system/multi-user.target.wants:755 \
    /var:755 \
    /var/lib:755 \
    /var/log:755 \
    /opt:755 \
    /usr:755 \
    /usr/lib:755 \
    /usr/lib/systemd:755 \
    /usr/lib/systemd/system:755 \
    /usr/lib/systemd/system-preset:755 \
    /usr/libexec:755 \
    /usr/local:755 \
    /usr/local/bin:755 \
    /usr/share:755 \
    /usr/share/bash-completion:755 \
    /usr/share/bash-completion/completions:755 \
    /usr/share/doc:755; do
    exact_existing_directory \
        "${directory_and_mode%:*}" "${directory_and_mode##*:}"
done

for directory_and_mode in \
    /etc/syswarden:750 \
    /etc/syswarden/config:750 \
    /etc/syswarden/config/modules:750 \
    /etc/syswarden/lists:750 \
    /etc/syswarden/tls:750 \
    /var/lib/syswarden:750 \
    /var/lib/syswarden/ui:750 \
    /var/log/syswarden:750 \
    /opt/syswarden:755 \
    /opt/syswarden/bin:755 \
    /usr/lib/systemd/system/syswarden-firewall.service.d:755 \
    /usr/libexec/syswarden:755 \
    /usr/share/doc/syswarden:755; do
    exact_existing_product_directory \
        "${directory_and_mode%:*}" "${directory_and_mode##*:}"
done

for regular_mode_and_owner in \
    /opt/syswarden/bin/syswarden-cli:750:shared \
    /opt/syswarden/bin/syswarden-core:750:shared \
    /opt/syswarden/bin/syswarden-tui:750:shared \
    /opt/syswarden/signatures.json:640:shared \
    /usr/lib/systemd/system/syswarden-core.service:644:rhelpo \
    /usr/lib/systemd/system/syswarden-firewall.service:644:rhelpo \
    /usr/lib/systemd/system/syswarden-firewall.service.d/10-syswarden-wireguard-ordering.conf:644:shared \
    /usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset:644:rhelpo \
    /usr/libexec/syswarden/rhelpo-postun-recovery-v1:755:rhelpo \
    /usr/share/bash-completion/completions/syswarden:644:shared \
    /usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt:644:shared \
    /usr/share/doc/syswarden/LICENSE.txt:644:shared \
    /usr/share/doc/syswarden/rhel-package-owned-profile.json:644:rhelpo; do
    regular_path="${regular_mode_and_owner%%:*}"
    regular_mode_and_owner="${regular_mode_and_owner#*:}"
    regular_mode="${regular_mode_and_owner%%:*}"
    regular_owner="${regular_mode_and_owner##*:}"
    exact_existing_regular "$regular_path" "$regular_mode" "$regular_owner"
done
exact_existing_symlink /usr/local/bin/syswarden /opt/syswarden/bin/syswarden-cli shared
exact_existing_symlink /usr/local/bin/syswarden-tui /opt/syswarden/bin/syswarden-tui shared

attest_preset_recovery_candidate() {
    path="$1"
    [ -x /usr/bin/head ] || fail 'Preset-recovery prefix attestation is unavailable.'
    [ -f "$path" ] && [ ! -L "$path" ] || \
        fail "Refusing unsafe RHEL package-owned preset-recovery state: $path"
    metadata="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$path")"
    case "$metadata" in
        0:0:600:1:*) ;;
        *) fail "Refusing modified RHEL package-owned preset-recovery metadata: $path" ;;
    esac
    size="${metadata##*:}"
    case "$size" in
        ''|*[!0-9]*) fail "Refusing malformed RHEL package-owned preset-recovery size: $path" ;;
    esac
    [ "$size" -le 35 ] || fail "Refusing oversized RHEL package-owned preset-recovery state: $path"
    actual_digest="$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')"
    expected_digest="$(printf '%s\n' SYSWARDEN_RHELPO_PRESET_PENDING_V1 | \
        /usr/bin/head -c "$size" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
    [ "$actual_digest" = "$expected_digest" ] || \
        fail "Refusing modified RHEL package-owned preset-recovery content: $path"
}

for barrier in \
    /var/lib/syswarden/removal-in-progress-v1 \
    /var/lib/syswarden/removal-in-progress-v1.new \
    /var/lib/syswarden/removed-awaiting-purge-v1 \
    /var/lib/.syswarden-removal-finalizing-v1 \
    /var/lib/.syswarden-removal-finalizing-v1.new \
    /var/lib/.syswarden-rhelpo-erase-ready-v1 \
    /var/lib/.syswarden-rhelpo-erase-ready-v1.new \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1 \
    /var/lib/.syswarden-rhelpo-postun-recovery-v1.new; do
    if [ -e "$barrier" ] || [ -L "$barrier" ]; then
        fail "Refusing install while a SysWarden removal barrier remains: $barrier"
    fi
done

preset_marker=/var/lib/.syswarden-rhelpo-preset-pending-v1
preset_temporary="${preset_marker}.new"
preset_recovery=0
for preset_candidate in "$preset_marker" "$preset_temporary"; do
    if [ ! -e "$preset_candidate" ] && [ ! -L "$preset_candidate" ]; then
        continue
    fi
    [ "$1" -gt 1 ] || fail 'Refusing preset-recovery state during clean installation.'
    attest_preset_recovery_candidate "$preset_candidate"
    if [ "$preset_candidate" = "$preset_marker" ]; then
        [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$preset_candidate")" = \
            '0:0:600:1:35' ] || \
            fail 'Refusing partial final RHEL package-owned preset-recovery marker.'
    fi
    preset_recovery=1
done
if [ "$preset_recovery" -eq 1 ]; then
    attest_installed_identity 35 a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247
fi

exact_systemd_directory /etc/systemd/system 1
exact_systemd_directory /etc/systemd/system/multi-user.target.wants 0

exact_migration_temporary \
    /etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration \
    /usr/lib/systemd/system/syswarden-core.service
exact_migration_temporary \
    /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration \
    /usr/lib/systemd/system/syswarden-firewall.service

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
if [ "$1" -gt 1 ]; then
    if [ "$core_present" -eq 1 ] && [ "$firewall_present" -eq 1 ]; then
        attest_installed_identity \
            28 c3dd1e8df980ad039e7ba1c3c7a82625048df88a5636bdb039da6cc1c06de7c9 \
            35 a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247
        exact_legacy_source_unit /etc/systemd/system/syswarden-core.service \
            8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd
        exact_legacy_source_unit /etc/systemd/system/syswarden-firewall.service \
            989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
    elif [ "$core_present" -eq 0 ] && [ "$firewall_present" -eq 0 ]; then
        attest_installed_identity 35 a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247
    else
        attest_installed_identity 35 a62c66b7e1f03e6da14b42a39fe6cc4c4af3cf518ed78efa025d958dd85d1247
        if [ "$core_present" -eq 1 ]; then
            exact_legacy_source_unit /etc/systemd/system/syswarden-core.service \
                8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd
        fi
        if [ "$firewall_present" -eq 1 ]; then
            exact_legacy_source_unit /etc/systemd/system/syswarden-firewall.service \
                989be4b60c43bba830333ef30949376e57658222a48947194395393794e328c1
        fi
    fi
    exact_enablement \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        ../syswarden-core.service \
        /usr/lib/systemd/system/syswarden-core.service
    exact_enablement \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service \
        ../syswarden-firewall.service \
        /usr/lib/systemd/system/syswarden-firewall.service
else
    [ "$core_present" -eq 0 ] && [ "$firewall_present" -eq 0 ] || \
        fail 'Refusing pre-existing priority SysWarden units during clean RHEL package-owned installation.'
    for link in \
        /etc/systemd/system/multi-user.target.wants/syswarden-core.service \
        /etc/systemd/system/multi-user.target.wants/syswarden-firewall.service; do
        [ ! -e "$link" ] && [ ! -L "$link" ] || \
            fail "Refusing pre-existing SysWarden enablement during clean installation: $link"
    done
fi

exit 0
