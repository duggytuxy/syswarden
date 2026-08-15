//go:build freebsd

package platformpaths

import (
	"os"
	"os/exec"
)

const (
	InstallRoot  = "/usr/local/syswarden"
	CLI          = InstallRoot + "/bin/syswarden-cli"
	TUI          = InstallRoot + "/bin/syswarden-tui"
	LegacyConfig = InstallRoot + "/syswarden-auto.conf"
)

var managedCronCLIPaths = [...]string{CLI, "/opt/syswarden/bin/syswarden-cli"}

// TUICommand returns the packaged FreeBSD TUI command.
func TUICommand() *exec.Cmd {
	return exec.Command("/usr/local/syswarden/bin/syswarden-tui")
}

func whitelistCommand(target string) *exec.Cmd {
	cmd := exec.Command(
		"/bin/sh",
		"-c",
		`/usr/local/syswarden/bin/syswarden-cli whitelist "$SYSWARDEN_PEER"`,
	)
	cmd.Env = append(os.Environ(), "SYSWARDEN_PEER="+target)
	return cmd
}
