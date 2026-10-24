#!/bin/sh
# APK package script failures do not veto removal. Preserve a verified private
# recovery payload before any native transaction can remove its executables.
# This hook does not inspect or change the transaction plan or host policy.
case "${1:-}" in
    pre-commit)
        exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
            /opt/syswarden/bin/syswarden-cli prepare-package-removal --retain-apk-payload
        ;;
    post-commit) exit 0 ;;
    *) exit 1 ;;
esac
