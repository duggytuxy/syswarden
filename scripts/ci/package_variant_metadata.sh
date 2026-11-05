#!/bin/bash
# Metadata for local builds and unsigned v4/v5 workflow artifacts.
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
    # nfpm's APK backend ignores its generic Conflicts field. APK expresses
    # conflicts as negative dependencies; quote ! so YAML cannot treat it as a tag.
    APK_PACKAGE_DEPENDENCIES_YAML="$(printf '  - %s\n' "${APK_PACKAGE_DEPENDENCIES[@]}"; printf '  - "!%s"\n' "${PACKAGE_CONFLICT}")"
}

# Generation is deliberately closed to the qualified source-version families.
# This selector does not authorize native signing or release acceptance.
syswarden_select_workflow_package_variants() {
    WORKFLOW_PACKAGE_VARIANTS=()
    if [ "$#" -ne 1 ] || [[ ! "$1" =~ ^[45]\.[0-9]{2}\.(0|[1-9][0-9]{0,9})$ ]] ||
        (( 10#${1##*.} > 2147483647 )); then
        printf '%s\n' 'Unsigned package generation requires a canonical v4 or v5 source version.' >&2
        return 2
    fi
    WORKFLOW_PACKAGE_VARIANTS=(compatibility)
    if [[ "$1" == 5.* ]]; then
        WORKFLOW_PACKAGE_VARIANTS+=(minimal)
    fi
}

# These library outputs are consumed by the sourcing workflow build blocks.
# shellcheck disable=SC2034
syswarden_select_workflow_package_variant() {
    [ "$#" -eq 2 ] || return 2
    syswarden_select_workflow_package_variants "$1" || return
    if [ "$2" != compatibility ] && { [[ "$1" != 5.* ]] || [ "$2" != minimal ]; }; then
        printf '%s\n' 'Package identity is outside the unsigned source-version inventory.' >&2
        return 2
    fi
    syswarden_select_local_package_variant "$2" || return
    PACKAGE_FPM_CONFLICTS=()
    PACKAGE_SCRIPT_SUBDIRECTORY=
    PACKAGE_CONFIG_SUFFIX=
    APK_PACKAGE_CONFLICTS_YAML=
    APK_PACKAGE_RELEASE_YAML=
    if [[ "$1" == 5.* ]]; then
        PACKAGE_FPM_CONFLICTS=(--conflicts "${PACKAGE_CONFLICT}")
        PACKAGE_SCRIPT_SUBDIRECTORY="/${PACKAGE_NAME}"
        PACKAGE_CONFIG_SUFFIX="-${PACKAGE_NAME}"
        # Candidate headers must carry the exact native revision expected by
        # the authenticated updater. Historical hosted v4 retains no revision.
        APK_PACKAGE_RELEASE_YAML=$'\nrelease: "0"'
        APK_PACKAGE_CONFLICTS_YAML="$(printf '\nconflicts:\n  - "%s"' "${PACKAGE_CONFLICT}")"
    else
        # Preserve historical v4 metadata and maintainer-script paths exactly.
        PACKAGE_CONFLICT=
        APK_PACKAGE_DEPENDENCIES_YAML="$(printf '  - %s\n' "${APK_PACKAGE_DEPENDENCIES[@]}")"
    fi
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
