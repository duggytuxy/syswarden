//go:build linux

package cmd

import (
	"golang.org/x/sys/unix"
	"os"
)

func flushStdin() {
	_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
