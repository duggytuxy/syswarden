//go:build linux

package cmd

import (
	"golang.org/x/sys/unix"
	"os"
)

//nolint:unused // Used in tui.go, but linter struggles with OS-specific files
func flushStdin() {
	_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
