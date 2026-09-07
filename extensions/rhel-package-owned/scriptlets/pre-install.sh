#!/bin/sh
set -eu

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

exit 0
