//go:build linux

package logger

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"syswarden-core/fileorigin"
)

// Existing logs remain usable without acquiring removal authority. Only the
// process that exclusively created the inode records its product origin.
func openAppendProductLog(path, kind string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600) // #nosec G304 -- Internal log destination; exclusive creation and no-follow flags protect the leaf.
	if errors.Is(err, os.ErrExist) {
		return reopenTelemetryLog(path)
	}
	if err != nil {
		return nil, err
	}
	if err := fileorigin.MarkCreatedLog(file, kind); err != nil {
		// Logging remains available on filesystems without extended attributes.
		// Removal must preserve this unmarked file for explicit recovery.
		log.Printf("[Logger] Product log origin could not be recorded; preserve this log during removal: %v", err)
	}
	return file, nil
}

func OpenCoreProcessLog(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("core process log path is empty")
	}
	return openAppendProductLog(path, fileorigin.CoreLog)
}
