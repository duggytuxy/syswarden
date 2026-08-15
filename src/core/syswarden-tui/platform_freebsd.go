//go:build freebsd

package main

import (
	"os"
	"os/exec"
)

const haLegacyConfigFile = "/usr/local/syswarden/syswarden-auto.conf"

func actionEnvironment(target string) []string {
	return append(os.Environ(), "SYSWARDEN_TARGET="+target)
}

func runUnblockAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `exec /usr/local/syswarden/bin/syswarden-cli unblock "$SYSWARDEN_TARGET"`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}

func runWhitelistAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `exec /usr/local/syswarden/bin/syswarden-cli whitelist "$SYSWARDEN_TARGET"`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}

func runBlockAction(target string) error {
	cmd := exec.Command("/bin/sh", "-c", `exec /usr/local/syswarden/bin/syswarden-cli block "$SYSWARDEN_TARGET"`)
	cmd.Env = actionEnvironment(target)
	return cmd.Run()
}
