//go:build linux

package platformpaths

import "os/exec"

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

func whitelistCommand(target, port string) *exec.Cmd {
	return exec.Command(CLI, "whitelist", target, "--port", port)
}
