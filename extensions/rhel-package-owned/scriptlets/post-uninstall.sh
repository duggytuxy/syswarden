#!/bin/sh
set -eu

case "${1:-}" in
    ''|*[!0-9]*)
        printf '%s\n' 'Refusing an invalid RPM post-uninstall transaction state.' >&2
        exit 1
        ;;
esac

if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -eq 0 ]; then
        /usr/bin/systemctl reset-failed \
            syswarden-core.service \
            syswarden-firewall.service >/dev/null 2>&1 || :
    fi
fi

exit 0
