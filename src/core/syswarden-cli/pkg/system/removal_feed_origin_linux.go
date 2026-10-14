//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const generatedFeedOriginAttribute = "user.syswarden.feed-origin-v1"

// MaximumGeneratedFeedBytes is shared by publication and retirement so every
// accepted generated feed can also be retained without truncating its bytes.
const MaximumGeneratedFeedBytes = 32 << 20

// MaximumGeneratedFeedSnapshots bounds each address family's generations.
const MaximumGeneratedFeedSnapshots = 8

// Two address families, each with one compatibility file, one provenance
// commit and at most eight snapshots, matching the bounded feed publisher.
const maximumGeneratedFeedArtifacts = 2 * (2 + MaximumGeneratedFeedSnapshots)

func validateGeneratedFeedInventory(names []string) error {
	for _, family := range []string{"ipv4", "ipv6"} {
		count := 0
		for _, name := range names {
			if strings.HasPrefix(name, ".syswarden_threatintel."+family+".syswarden-snapshot-") {
				count++
			}
		}
		if count > MaximumGeneratedFeedSnapshots {
			return fmt.Errorf("generated %s feed snapshot inventory exceeds its bound", family)
		}
	}
	return nil
}

// IsGeneratedFeedArtifactName only bounds candidate names. It never proves
// ownership, which also requires an exact writer-created inode marker.
func IsGeneratedFeedArtifactName(name string) bool {
	for _, family := range []string{"ipv4", "ipv6"} {
		base := "syswarden_threatintel." + family
		if name == base || name == base+".provenance.json" {
			return true
		}
		if digest, found := strings.CutPrefix(name, "."+base+".syswarden-snapshot-"); found {
			decoded, err := hex.DecodeString(digest)
			return err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
		}
	}
	return false
}

func generatedFeedOriginRecord(file *os.File, name string, digest [sha256.Size]byte) ([]byte, error) {
	if file == nil || !IsGeneratedFeedArtifactName(name) {
		return nil, fmt.Errorf("invalid generated feed origin request")
	}
	return generatedDataOriginRecord(file, name, digest, "SYSWARDEN_FEED_ARTIFACT_ORIGIN_V1")
}

// MarkCreatedFeedArtifact marks exclusive writer creation only. An existing
// unmarked file must never gain ownership merely through a feed refresh.
func MarkCreatedFeedArtifact(file *os.File, name string, content []byte) error {
	record, err := generatedFeedOriginRecord(file, name, sha256.Sum256(content))
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(len(content)) {
		return fmt.Errorf("generated feed size differs from its writer input")
	}
	if err := unix.Fsetxattr(int(file.Fd()), generatedFeedOriginAttribute, record, unix.XATTR_CREATE); err != nil {
		return err
	}
	return file.Sync()
}

// HasGeneratedFeedArtifactOrigin rejects altered or copied markers. An old
// unmarked generation remains unowned and requires explicit private retention.
func HasGeneratedFeedArtifactOrigin(file *os.File, name string, digest [sha256.Size]byte) (bool, error) {
	if file == nil || !IsGeneratedFeedArtifactName(name) {
		return false, fmt.Errorf("invalid generated feed origin request")
	}
	var marker [512]byte
	size, err := unix.Fgetxattr(int(file.Fd()), generatedFeedOriginAttribute, marker[:])
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expected, err := generatedFeedOriginRecord(file, name, digest)
	if err != nil {
		return false, err
	}
	if string(marker[:size]) != string(expected) {
		return false, fmt.Errorf("generated feed origin does not bind this inode and content")
	}
	return true, nil
}
