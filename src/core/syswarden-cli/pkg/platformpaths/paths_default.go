//go:build !freebsd

package platformpaths

import (
	"os"
	"os/exec"
)

const (
	InstallRoot  = "/opt/syswarden"
	CLI          = InstallRoot + "/bin/syswarden-cli"
	TUI          = InstallRoot + "/bin/syswarden-tui"
	LegacyConfig = InstallRoot + "/syswarden-auto.conf"
)

var managedCronCLIPaths = [...]string{CLI}

// TUICommand returns the packaged Linux TUI command.
func TUICommand() *exec.Cmd {
	return exec.Command("/opt/syswarden/bin/syswarden-tui")
}

func whitelistCommand(target string) *exec.Cmd {
	cmd := exec.Command(
		"/bin/sh",
		"-c",
		`/opt/syswarden/bin/syswarden-cli whitelist "$SYSWARDEN_PEER"`,
	)
	cmd.Env = append(os.Environ(), "SYSWARDEN_PEER="+target)
	return cmd
}
