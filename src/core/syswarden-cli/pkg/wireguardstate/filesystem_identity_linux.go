//go:build linux

package wireguardstate

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FS_IOC_GETFSUUID reads the external filesystem UUID through the already
// pinned descriptor. Unlike st_dev, this identity survives block-device
// renumbering. Linux uses a 17-byte fsuuid2 structure. Reuse the architecture's
// read-direction bits from FS_IOC_GETFLAGS, including MIPS and PowerPC layouts.
// See Linux v6.12 include/uapi/linux/fs.h and fs/ioctl.c.
const filesystemUUIDIOCTL = (unix.FS_IOC_GETFLAGS & 0xe0000000) | (17 << 16) | (0x15 << 8)

// CaptureFilesystemUUID returns a persistent identity for an already pinned
// file. An empty result means that only strict device matching is available.
func CaptureFilesystemUUID(file *os.File) (string, error) {
	if file == nil {
		return "", fmt.Errorf("cannot attest a missing pinned filesystem descriptor")
	}
	uuid, err := readFilesystemUUID(int(file.Fd()))
	runtime.KeepAlive(file)
	return uuid, err
}

// ValidFilesystemUUID accepts a canonical UUID or absent legacy evidence.
func ValidFilesystemUUID(value string) bool { return validFilesystemUUID(value) }

// MatchesRecordedArtifact verifies every recorded field. Only the device number
// may differ when both identities carry the exact same persistent UUID.
func MatchesRecordedArtifact(actual, expected Artifact) bool { return sameArtifact(actual, expected) }

// MatchesRecordedServiceLink applies the same persistent filesystem checks to
// an owned OpenRC service link captured through its pinned parent directory.
func MatchesRecordedServiceLink(actual, expected SymlinkArtifact) bool {
	return sameSymlinkArtifact(actual, expected)
}

func readFilesystemUUID(fd int) (string, error) {
	var response [17]byte
	// #nosec G103 -- the constant read-only ioctl writes exactly the fixed 17-byte UAPI response
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), filesystemUUIDIOCTL,
		uintptr(unsafe.Pointer(&response[0])))
	if errno != 0 {
		// An unsupported kernel or filesystem retains strict legacy device
		// matching. A recorded UUID is never discarded during verification.
		if errors.Is(errno, unix.ENOTTY) || errors.Is(errno, unix.EOPNOTSUPP) || errors.Is(errno, unix.ENOSYS) {
			return "", nil
		}
		return "", fmt.Errorf("read pinned filesystem UUID: %w", errno)
	}
	if response[0] != 16 {
		return "", fmt.Errorf("pinned filesystem UUID has unsupported length %d", response[0])
	}
	uuid := hex.EncodeToString(response[1:])
	if !validFilesystemUUID(uuid) || uuid == "" {
		return "", fmt.Errorf("pinned filesystem UUID is invalid")
	}
	return uuid, nil
}

func validFilesystemUUID(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value &&
		value != "00000000000000000000000000000000"
}

// sameFilesystemIdentity accepts device renumbering only when both records
// carry the same persistent UUID. Legacy records still require the exact device.
// The first operand is the newly captured identity; the second is its record.
func sameFilesystemIdentity(actualDevice uint64, actualUUID string, expectedDevice uint64, expectedUUID string) bool {
	if !validFilesystemUUID(actualUUID) || !validFilesystemUUID(expectedUUID) {
		return false
	}
	if expectedUUID == "" {
		return actualDevice == expectedDevice
	}
	return actualUUID == expectedUUID
}
