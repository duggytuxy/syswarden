//go:build !freebsd

package main

import (
	"os"
	"os/exec"
)

const haLegacyConfigFile = "/opt/syswarden/syswarden-auto.conf"

func actionEnvironment(target string) []string {
	return append(os.Environ(), "SYSWARDEN_TARGET="+target)
}

func runUnblockAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `if [ -e /opt/syswarden/bin/syswarden ]; then exec /opt/syswarden/bin/syswarden unblock "$SYSWARDEN_TARGET"; else exec syswarden unblock "$SYSWARDEN_TARGET"; fi`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}

func runWhitelistAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `if [ -e /opt/syswarden/bin/syswarden ]; then exec /opt/syswarden/bin/syswarden whitelist "$SYSWARDEN_TARGET"; else exec syswarden whitelist "$SYSWARDEN_TARGET"; fi`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}

func runBlockAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `if [ -e /opt/syswarden/bin/syswarden ]; then exec /opt/syswarden/bin/syswarden block "$SYSWARDEN_TARGET"; else exec syswarden block "$SYSWARDEN_TARGET"; fi`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}
