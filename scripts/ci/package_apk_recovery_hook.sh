#!/bin/sh
# APK package script failures do not veto removal. Preserve a verified private
# recovery payload before any native transaction can remove its executables.
# Fresh launcher completion consumes only previously staged intent after APK
# commits its database. Neither operation activates host policy.
case "${1:-}" in
    pre-commit)
        exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
            /opt/syswarden/bin/syswarden-cli prepare-package-removal --retain-apk-payload
        ;;
    post-commit)
        # Native erase may remove the CLI before this hook. Absence grants no
        # completion and clears no pending launcher or removal evidence.
        [ ! -L /opt/syswarden/bin/syswarden-cli ] || exit 1
        [ -e /opt/syswarden/bin/syswarden-cli ] || exit 0
        exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
            /opt/syswarden/bin/syswarden-cli internal-apk-launchers --complete-fresh
        ;;
    *) exit 1 ;;
esac
