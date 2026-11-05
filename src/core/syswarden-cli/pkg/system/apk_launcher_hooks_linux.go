//go:build linux

package system

const apkRecoveryHookSource = `#!/bin/sh
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
`

// APKRecoveryHookSHA256 identifies reviewed hook bytes, not transaction approval.
func APKRecoveryHookSHA256() string { return apkTransitionDigest([]byte(apkRecoveryHookSource)) }

// APKTransitionUpgradeHookSHA256 permits only the fixed native dispatcher.
// Its protected active reference and live execution authority are separately
// authenticated by the transition coordinator and retained helper.
func APKTransitionUpgradeHookSHA256(phase string) string {
	if phase != "pre-upgrade" && phase != "post-upgrade" {
		return ""
	}
	return apkTransitionDigest([]byte("#!/bin/sh\nset -eu\nexec /var/backups/syswarden-apk-transitions-v1/active-hook " + phase + "\n"))
}
