#!/bin/sh
set -eu

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM pre-uninstall transaction state.' >&2
        exit 1
        ;;
esac

if [ "$1" -eq 0 ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl disable \
        syswarden-core.service \
        syswarden-firewall.service >/dev/null 2>&1 || :
    if [ -d /run/systemd/system ]; then
        /usr/bin/systemctl stop \
            syswarden-core.service \
            syswarden-firewall.service >/dev/null 2>&1 || :
    fi
fi

exit 0
