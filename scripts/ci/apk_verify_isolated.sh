#!/bin/sh
set -eu

if [ "$#" -ne 4 ] || [ "$1" != "verify" ] || [ "$2" != "--keys-dir" ]; then
    printf '%s\n' 'ERROR: isolated APK verifier received unsupported arguments.' >&2
    exit 64
fi

keys_dir="$3"
package="$4"
image="${SYSWARDEN_APK_SIGNER_IMAGE:-}"

if ! printf '%s\n' "${image}" | grep -Eq \
    '^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$'; then
    printf '%s\n' 'ERROR: APK signer image is not pinned by a SHA-256 digest.' >&2
    exit 65
fi

case "${keys_dir}:${package}" in
    /*:/*) ;;
    *)
        printf '%s\n' 'ERROR: isolated APK verifier paths must be absolute.' >&2
        exit 66
        ;;
esac

if [ ! -d "${keys_dir}" ] || [ -L "${keys_dir}" ] || \
   [ ! -f "${package}" ] || [ -L "${package}" ]; then
    printf '%s\n' 'ERROR: isolated APK verifier input is unsafe.' >&2
    exit 67
fi

keys_real="$(realpath -e -- "${keys_dir}")"
package_real="$(realpath -e -- "${package}")"
uid="$(id -u)"
gid="$(id -g)"

exec docker run --rm \
    --pull never \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 256m \
    --cpus 1 \
    --user "${uid}:${gid}" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m \
    --mount "type=bind,src=${keys_real},dst=/run/syswarden-keys,readonly" \
    --mount "type=bind,src=${package_real},dst=/run/syswarden-package.apk,readonly" \
    --entrypoint /sbin/apk \
    "${image}" \
    verify --keys-dir /run/syswarden-keys /run/syswarden-package.apk
