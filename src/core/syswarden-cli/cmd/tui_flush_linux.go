//go:build linux

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

//nolint:unused // Used in tui.go, but linter struggles with OS-specific files
func flushStdin() {
	_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
