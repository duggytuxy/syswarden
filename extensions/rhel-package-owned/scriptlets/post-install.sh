#!/bin/sh
set -eu

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

if [ "$1" -eq 1 ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl preset \
        syswarden-firewall.service \
        syswarden-core.service >/dev/null 2>&1 || :
fi

if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

exit 0
