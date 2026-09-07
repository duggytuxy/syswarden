//go:build unix

package network

import (
	"io/fs"
	"syscall"
)

func feedFileLinkCount(info fs.FileInfo) (uint64, bool) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(status.Nlink), true
}
