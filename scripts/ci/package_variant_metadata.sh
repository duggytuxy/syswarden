#!/bin/bash
# Local builder metadata only. The public release inventory is unchanged.
# Both identities carry the complete payload; neither replaces the other.

syswarden_select_local_package_variant() {
    if [ "$#" -ne 1 ]; then
        printf '%s\n' 'Exactly one local package variant is required.' >&2
        return 2
    fi
    case "$1" in
        compatibility)
            PACKAGE_NAME=syswarden
            # Library output consumed by the sourcing local builder.
            # shellcheck disable=SC2034
            PACKAGE_CONFLICT=syswarden-base
            DEB_PACKAGE_DEPENDENCIES=(
                nftables ipset curl wget rsyslog cron bash-completion
                wireguard-tools qrencode jq unattended-upgrades apt-listchanges procps e2fsprogs
            )
            RPM_PACKAGE_DEPENDENCIES=(
                nftables ipset curl wget rsyslog cronie bash-completion
                wireguard-tools jq checkpolicy policycoreutils-python-utils dnf-automatic procps-ng e2fsprogs
            )
            APK_PACKAGE_DEPENDENCIES=(
                nftables openrc cronie cronie-openrc curl wget rsyslog rsyslog-uxsock
                bash-completion wireguard-tools libqrencode-tools jq procps-ng e2fsprogs-extra shadow
            )
            ;;
        minimal)
            PACKAGE_NAME=syswarden-base
            # Library output consumed by the sourcing local builder.
            # shellcheck disable=SC2034
            PACKAGE_CONFLICT=syswarden
            # Match the manual baseDependencyArguments contract. Native
            # install/update/removal qualification remains separate work.
            DEB_PACKAGE_DEPENDENCIES=(bash-completion cron curl jq nftables procps wget)
            RPM_PACKAGE_DEPENDENCIES=(bash-completion cronie curl jq nftables procps-ng wget)
            APK_PACKAGE_DEPENDENCIES=(
                bash-completion cronie cronie-openrc curl jq nftables openrc procps-ng shadow wget
            )
            ;;
        *)
            printf '%s\n' 'Unsupported local package variant.' >&2
            return 2
            ;;
    esac

    DEB_PACKAGE_FPM_DEPENDENCIES=()
    RPM_PACKAGE_FPM_DEPENDENCIES=()
    local dependency
    for dependency in "${DEB_PACKAGE_DEPENDENCIES[@]}"; do
        DEB_PACKAGE_FPM_DEPENDENCIES+=(-d "${dependency}")
    done
    for dependency in "${RPM_PACKAGE_DEPENDENCIES[@]}"; do
        RPM_PACKAGE_FPM_DEPENDENCIES+=(-d "${dependency}")
    done
    # Library output consumed by the sourcing local builder.
    # shellcheck disable=SC2034
    APK_PACKAGE_DEPENDENCIES_YAML="$(printf '  - %s\n' "${APK_PACKAGE_DEPENDENCIES[@]}")"
}

# Bind only APK hook context selectors. Product paths and runtime payload names
# stay unchanged, and no runtime environment variable selects the package name.
syswarden_render_local_package_hook() {
    [ "$#" -eq 1 ] || return 2
    case "${PACKAGE_NAME:-}" in
        syswarden)
            cat -- "$1"
            ;;
        syswarden-base)
            sed \
                -e 's/syswarden:pre-install/syswarden-base:pre-install/g' \
                -e 's/syswarden:post-install/syswarden-base:post-install/g' \
                -e 's/syswarden:pre-upgrade/syswarden-base:pre-upgrade/g' \
                -e 's/syswarden:post-upgrade/syswarden-base:post-upgrade/g' \
                -e 's/syswarden:pre-deinstall/syswarden-base:pre-deinstall/g' \
                -- "$1"
            ;;
        *) return 2 ;;
    esac
}
