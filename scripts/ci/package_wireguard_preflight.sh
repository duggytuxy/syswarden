#!/bin/sh
# Read-only historical-state screening before a native package replaces payload.
# This is not an ownership verifier. The CLI repeats full runtime and manifest
# verification before configuration. Never invoke the installed legacy CLI here.

syswarden_preflight_wireguard() {
    syswarden_wg_root="${1%/}"
    for syswarden_wg_parent in /etc /etc/wireguard /etc/wireguard/clients /etc/sysctl.d; do
        syswarden_wg_path="${syswarden_wg_root}${syswarden_wg_parent}"
        if [ -L "${syswarden_wg_path}" ] || \
           { [ -e "${syswarden_wg_path}" ] && [ ! -d "${syswarden_wg_path}" ]; }; then
            printf '%s\n' 'Refusing package unpack: unsafe WireGuard configuration parent.' >&2
            return 1
        fi
        if [ -d "${syswarden_wg_path}" ]; then
            syswarden_wg_owner="$(stat -c '%u:%g' "${syswarden_wg_path}")" || return 1
            syswarden_wg_mode="$(stat -c '%a' "${syswarden_wg_path}")" || return 1
            if [ "${syswarden_wg_owner}" != 0:0 ] || \
               [ "$((0${syswarden_wg_mode} & 0022))" -ne 0 ]; then
                printf '%s\n' 'Refusing package unpack: WireGuard configuration parent is not protected.' >&2
                return 1
            fi
        fi
    done
    syswarden_wg_path="${syswarden_wg_root}/etc/wireguard/.syswarden-legacy-migration-v1.json"
    if [ -e "${syswarden_wg_path}" ] || [ -L "${syswarden_wg_path}" ]; then
        printf '%s\n' 'Refusing package unpack: historical WireGuard migration is pending. Resume its exact reviewed plan with the verified candidate recovery CLI before retrying.' >&2
        return 1
    fi
    syswarden_wg_path="${syswarden_wg_root}/etc/wireguard/wg0.conf"
    if [ -e "${syswarden_wg_path}" ] || [ -L "${syswarden_wg_path}" ]; then
        if [ -L "${syswarden_wg_path}" ] || [ ! -f "${syswarden_wg_path}" ] || \
           [ "$(stat -c '%u:%g:%a:%h' "${syswarden_wg_path}")" != 0:0:600:1 ]; then
            printf '%s\n' 'Refusing package unpack: historical WireGuard configuration cannot be safely inspected.' >&2
            return 1
        fi
        syswarden_wg_size="$(stat -c '%s' "${syswarden_wg_path}")" || return 1
        if [ "${syswarden_wg_size}" -gt 65536 ]; then
            printf '%s\n' 'Refusing package unpack: historical WireGuard configuration exceeds the inspection limit.' >&2
            return 1
        fi
        # No configuration bytes enter diagnostics. A read error also refuses.
        if LC_ALL=C grep -qF syswarden_wg "${syswarden_wg_path}"; then
            printf '%s\n' 'Refusing package unpack: historical wg0 claims the SysWarden nftables namespace. Use the verified candidate recovery CLI outside the installed payload to inspect recover-wireguard --retire-legacy-wg0. Preserve configuration, keys, manifests and removal barriers; see https://syswarden.io/docs/.' >&2
            return 1
        else
            syswarden_wg_grep_status=$?
            [ "${syswarden_wg_grep_status}" -eq 1 ] || return 1
        fi
    fi
    syswarden_wg_manifest="${syswarden_wg_root}/etc/wireguard/.syswarden-ownership-v1.json"
    if [ -L "${syswarden_wg_manifest}" ] || \
       { [ -e "${syswarden_wg_manifest}" ] && [ ! -f "${syswarden_wg_manifest}" ]; }; then
        printf '%s\n' 'Refusing package unpack: unsafe WireGuard ownership manifest.' >&2
        return 1
    fi
    if [ ! -f "${syswarden_wg_manifest}" ]; then
        for syswarden_wg_artifact in \
            /etc/wireguard/wg-syswarden.conf \
            /etc/wireguard/clients/admin-pc.conf \
            /etc/sysctl.d/99-syswarden-wireguard.conf; do
            syswarden_wg_path="${syswarden_wg_root}${syswarden_wg_artifact}"
            if [ -e "${syswarden_wg_path}" ] || [ -L "${syswarden_wg_path}" ]; then
                printf '%s\n' 'Refusing package unpack: historical WireGuard artifacts have no ownership manifest. Inspect their verified migration with the candidate recovery CLI outside the installed payload. Do not delete configuration or create a manifest manually; see https://syswarden.io/docs/.' >&2
                return 1
            fi
        done
    fi
}
