#!/bin/sh
set -eu

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM post-uninstall transaction state.' >&2
        exit 1
        ;;
esac

if [ "$1" -eq 0 ]; then
    helper=/var/lib/.syswarden-rhelpo-postun-recovery-v1
    [ -f "$helper" ] && [ ! -L "$helper" ] || {
        printf '%s\n' 'RHEL package-owned post-uninstall recovery helper is absent.' >&2
        exit 1
    }
    [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%s' -- "$helper")" = '0:0:700:1:9843' ] || {
        printf '%s\n' 'RHEL package-owned post-uninstall recovery helper metadata is not exact.' >&2
        exit 1
    }
    [ "$(/usr/bin/sha256sum -- "$helper" | /usr/bin/awk '{print $1}')" = \
        64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c ] || {
        printf '%s\n' 'RHEL package-owned post-uninstall recovery helper content is not exact.' >&2
        exit 1
    }
    exec /bin/sh "$helper" rpm-postun-v1
fi

exit 0
