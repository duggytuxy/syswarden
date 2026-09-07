package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	feedSnapshotMarker         = ".syswarden-snapshot-"
	maximumFeedSnapshotEntries = 8
)

// FeedProvenanceStatus is the bounded public view of an active feed snapshot.
// SourceIdentity is deliberately omitted because it is an internal correlation
// value rather than an operator-facing source identifier.
type FeedProvenanceStatus struct {
	SchemaVersion     string `json:"schema_version"`
	FeedName          string `json:"feed_name"`
	SourceOrigin      string `json:"source_origin"`
	RetrievedAt       string `json:"retrieved_at"`
	Freshness         string `json:"freshness"`
	AgeSeconds        *int64 `json:"age_seconds,omitempty"`
	LicenseIdentifier string `json:"license_identifier"`
	EvidenceQuality   string `json:"evidence_quality"`
	ByteSize          int64  `json:"byte_size"`
	SHA256            string `json:"sha256"`
	AcceptedCount     int    `json:"accepted_count"`
	SkippedCount      int    `json:"skipped_count"`
	RejectedCount     int    `json:"rejected_count"`
	State             string `json:"state"`
}

var feedPublicationHook = func(string) error { return nil }

func feedSnapshotPrefix(target feedFileTarget) string {
	return "." + target.name + feedSnapshotMarker
}

func feedSnapshotTarget(target feedFileTarget, digest string) (feedFileTarget, error) {
	if digest != strings.ToLower(digest) || !approvedSHA256.MatchString(digest) {
		return feedFileTarget{}, fmt.Errorf("feed snapshot digest is not canonical SHA-256")
	}
	name := feedSnapshotPrefix(target) + digest
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return feedFileTarget{}, fmt.Errorf("feed snapshot name is invalid")
	}
	return feedFileTarget{directory: target.directory, name: name}, nil
}

func trustedOwnerOnlyFeed(identity feedFileIdentity, label string) error {
	if identity.info == nil || !identity.info.Mode().IsRegular() || identity.info.Mode() != 0600 ||
		!identity.ownerKnown || identity.uid != os.Geteuid() || identity.gid != os.Getegid() {
		return fmt.Errorf("%s has untrusted mode or owner", label)
	}
	links, ok := feedFileLinkCount(identity.info)
	if !ok || links != 1 {
		return fmt.Errorf("%s has an untrusted link count", label)
	}
	return nil
}

func readProvenanceDocumentInDirectory(directory *os.Root, target feedFileTarget) (feedProvenance, feedFileIdentity, error) {
	metadataTarget := provenanceTarget(target)
	content, identity, err := readFeedFileSnapshotInDirectory(directory, metadataTarget)
	if err != nil {
		return feedProvenance{}, feedFileIdentity{}, err
	}
	if err := trustedOwnerOnlyFeed(identity, "feed provenance file"); err != nil {
		return feedProvenance{}, feedFileIdentity{}, err
	}
	metadata, err := decodeFeedProvenance(content, target)
	if err != nil {
		return feedProvenance{}, feedFileIdentity{}, err
	}
	return metadata, identity, nil
}

func readAttestedFeedInDirectory(directory *os.Root, target feedFileTarget) ([]byte, feedProvenance, error) {
	metadata, metadataIdentity, err := readProvenanceDocumentInDirectory(directory, target)
	if err != nil {
		return nil, feedProvenance{}, err
	}
	snapshotTarget, err := feedSnapshotTarget(target, metadata.SHA256)
	if err != nil {
		return nil, feedProvenance{}, err
	}
	content, snapshotIdentity, err := readFeedFileSnapshotInDirectory(directory, snapshotTarget)
	if err != nil {
		// A missing provenance file means the optional feed was never committed.
		// A provenance commit whose selected generation is missing is corruption,
		// not an optional absence, and must remain visible to consumers.
		return nil, feedProvenance{}, fmt.Errorf("read active feed snapshot: %v", err)
	}
	if err := trustedOwnerOnlyFeed(snapshotIdentity, "active feed snapshot"); err != nil {
		return nil, feedProvenance{}, err
	}
	digest := sha256.Sum256(content)
	if metadata.ByteSize != int64(len(content)) || metadata.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, feedProvenance{}, fmt.Errorf("feed provenance does not bind the active snapshot")
	}
	if err := verifyFeedDestination(directory, provenanceTarget(target), metadataIdentity, true); err != nil {
		return nil, feedProvenance{}, fmt.Errorf("feed provenance changed while reading: %w", err)
	}
	if err := verifyFeedDestination(directory, snapshotTarget, snapshotIdentity, true); err != nil {
		return nil, feedProvenance{}, fmt.Errorf("active feed snapshot changed while reading: %w", err)
	}
	return content, metadata, nil
}

func verifyCompatibilityFeedInDirectory(directory *os.Root, target feedFileTarget, content []byte) error {
	visible, identity, err := readFeedFileSnapshotInDirectory(directory, target)
	if err != nil {
		return err
	}
	if err := trustedOwnerOnlyFeed(identity, "feed compatibility file"); err != nil {
		return err
	}
	if !bytesEqual(visible, content) {
		return fmt.Errorf("feed compatibility file does not match the active attested snapshot")
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	leftDigest := sha256.Sum256(left)
	rightDigest := sha256.Sum256(right)
	return leftDigest == rightDigest
}

func marshalFeedProvenance(metadata feedProvenance, target feedFileTarget) ([]byte, error) {
	if err := validateFeedProvenance(metadata, target); err != nil {
		return nil, err
	}
	content, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	content = append(content, '\n')
	if len(content) > maximumFeedProvenanceBytes {
		return nil, fmt.Errorf("feed provenance exceeds the publication limit")
	}
	return content, nil
}

func ensureFeedSnapshotInDirectory(directory *os.Root, target feedFileTarget, content []byte) (feedFileTarget, error) {
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	snapshotTarget, err := feedSnapshotTarget(target, digestText)
	if err != nil {
		return feedFileTarget{}, err
	}
	identity, exists, err := inspectFeedDestination(directory, snapshotTarget)
	if err != nil {
		return feedFileTarget{}, fmt.Errorf("inspect feed snapshot: %w", err)
	}
	if exists {
		if err := trustedOwnerOnlyFeed(identity, "existing feed snapshot"); err != nil {
			return feedFileTarget{}, err
		}
		if identity.digest != digest || identity.info.Size() != int64(len(content)) {
			return feedFileTarget{}, fmt.Errorf("existing feed snapshot content mismatch")
		}
		return snapshotTarget, nil
	}
	if err := writeFeedFileInDirectoryBeforeRename(directory, snapshotTarget, content, nil); err != nil {
		return feedFileTarget{}, fmt.Errorf("publish feed snapshot: %w", err)
	}
	identity, exists, err = inspectFeedDestination(directory, snapshotTarget)
	if err != nil || !exists {
		return feedFileTarget{}, fmt.Errorf("reattest published feed snapshot: %w", err)
	}
	if err := trustedOwnerOnlyFeed(identity, "published feed snapshot"); err != nil {
		return feedFileTarget{}, err
	}
	if identity.digest != digest || identity.info.Size() != int64(len(content)) {
		return feedFileTarget{}, fmt.Errorf("published feed snapshot content mismatch")
	}
	return snapshotTarget, nil
}

func cleanupFeedSnapshotsInDirectory(directory *os.Root, target feedFileTarget, keep ...string) error {
	keepSet := make(map[string]struct{}, len(keep))
	for _, digest := range keep {
		if digest == "" {
			continue
		}
		snapshot, err := feedSnapshotTarget(target, digest)
		if err != nil {
			return err
		}
		keepSet[snapshot.name] = struct{}{}
	}
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open feed directory for snapshot enumeration: %w", err)
	}
	entries, readErr := directoryFile.ReadDir(-1)
	closeErr := directoryFile.Close()
	if readErr != nil {
		return fmt.Errorf("enumerate feed snapshots: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close feed snapshot enumeration: %w", closeErr)
	}
	prefix := feedSnapshotPrefix(target)
	matched := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		matched++
		if matched > maximumFeedSnapshotEntries {
			return fmt.Errorf("feed snapshot inventory exceeds %d entries", maximumFeedSnapshotEntries)
		}
		digest := strings.TrimPrefix(entry.Name(), prefix)
		if _, err := feedSnapshotTarget(target, digest); err != nil {
			return fmt.Errorf("feed snapshot inventory contains an invalid name")
		}
		identity, exists, err := inspectFeedDestination(directory, feedFileTarget{directory: target.directory, name: entry.Name()})
		if err != nil || !exists {
			return fmt.Errorf("inspect historical feed snapshot: %w", err)
		}
		if err := trustedOwnerOnlyFeed(identity, "historical feed snapshot"); err != nil {
			return err
		}
		if _, retained := keepSet[entry.Name()]; retained {
			continue
		}
		if err := directory.Remove(entry.Name()); err != nil {
			return fmt.Errorf("remove historical feed snapshot: %w", err)
		}
	}
	return syncFeedDirectory(directory)
}

func writeProvenanceCommitInDirectory(directory *os.Root, target feedFileTarget, metadata feedProvenance) error {
	content, err := marshalFeedProvenance(metadata, target)
	if err != nil {
		return err
	}
	metadataTarget := provenanceTarget(target)
	existing, exists, err := inspectFeedDestination(directory, metadataTarget)
	if err != nil {
		return fmt.Errorf("inspect existing feed provenance: %w", err)
	}
	if exists {
		if err := trustedOwnerOnlyFeed(existing, "existing feed provenance"); err != nil {
			return err
		}
		existingContent, _, readErr := readFeedFileSnapshotInDirectory(directory, metadataTarget)
		if readErr != nil {
			return fmt.Errorf("read existing feed provenance: %w", readErr)
		}
		if _, decodeErr := decodeFeedProvenance(existingContent, target); decodeErr != nil {
			return fmt.Errorf("existing feed provenance is invalid: %w", decodeErr)
		}
		return writeFeedFileInDirectoryExpected(directory, metadataTarget, content, &existing, nil)
	}
	return writeFeedFileInDirectoryBeforeRename(directory, metadataTarget, content, nil)
}

func publishAttestedFeedInDirectory(
	directory *os.Root,
	target feedFileTarget,
	content []byte,
	metadata feedProvenance,
	visibleIdentity feedFileIdentity,
	visibleExists bool,
) error {
	if int64(len(content)) != metadata.ByteSize {
		return fmt.Errorf("feed provenance byte count does not match candidate")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != metadata.SHA256 {
		return fmt.Errorf("feed provenance digest does not match candidate")
	}
	currentDigest := ""
	if _, current, err := readAttestedFeedInDirectory(directory, target); err == nil {
		currentDigest = current.SHA256
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("validate active feed snapshot before publication: %w", err)
	}
	if _, err := ensureFeedSnapshotInDirectory(directory, target, content); err != nil {
		return err
	}
	if err := cleanupFeedSnapshotsInDirectory(directory, target, currentDigest, metadata.SHA256); err != nil {
		return err
	}
	if err := feedPublicationHook("snapshot-durable"); err != nil {
		return err
	}
	if visibleExists {
		if err := writeFeedFileInDirectoryExpected(directory, target, content, &visibleIdentity, nil); err != nil {
			return fmt.Errorf("publish feed compatibility file: %w", err)
		}
	} else if err := writeFeedFileInDirectoryBeforeRename(directory, target, content, nil); err != nil {
		return fmt.Errorf("publish feed compatibility file: %w", err)
	}
	if err := feedPublicationHook("compatibility-durable"); err != nil {
		return err
	}
	if err := writeProvenanceCommitInDirectory(directory, target, metadata); err != nil {
		return fmt.Errorf("commit feed provenance: %w", err)
	}
	return nil
}

// ReadAttestedFeedFile returns only bytes selected by an owner-only, strict
// provenance commit. The mutable compatibility file is never used as policy
// input, so an interrupted two-name update or direct substitution cannot widen
// policy.
func ReadAttestedFeedFile(path string) ([]byte, FeedProvenanceStatus, error) {
	suffix := filepath.Ext(path)
	target, err := approvedFeedFileForPath(path, suffix)
	if err != nil {
		return nil, FeedProvenanceStatus{}, err
	}
	directory, err := openFeedDirectory(target, suffix, false)
	if err != nil {
		return nil, FeedProvenanceStatus{}, err
	}
	defer func() { _ = directory.Close() }()
	content, metadata, err := readAttestedFeedInDirectory(directory, target)
	if err != nil {
		return nil, FeedProvenanceStatus{}, err
	}
	status, err := publicFeedProvenanceStatus(metadata)
	if err != nil {
		return nil, FeedProvenanceStatus{}, err
	}
	return content, status, nil
}

func publicFeedProvenanceStatus(metadata feedProvenance) (FeedProvenanceStatus, error) {
	freshness := string(metadata.State)
	var ageSeconds *int64
	if metadata.RetrievedAt != "" {
		retrievedAt, parseErr := time.Parse(time.RFC3339, metadata.RetrievedAt)
		if parseErr != nil {
			return FeedProvenanceStatus{}, fmt.Errorf("parse attested feed retrieval time: %w", parseErr)
		}
		age := feedProvenanceNow().UTC().Sub(retrievedAt)
		if age < 0 {
			age = 0
		}
		seconds := int64(age / time.Second)
		ageSeconds = &seconds
		if metadata.State == feedStateCurrent && age > maximumCurrentFeedAge {
			freshness = "expired"
		}
	}
	return FeedProvenanceStatus{
		SchemaVersion:     metadata.SchemaVersion,
		FeedName:          metadata.FeedName,
		SourceOrigin:      metadata.SourceURL,
		RetrievedAt:       metadata.RetrievedAt,
		Freshness:         freshness,
		AgeSeconds:        ageSeconds,
		LicenseIdentifier: metadata.LicenseIdentifier,
		EvidenceQuality:   metadata.EvidenceQuality,
		ByteSize:          metadata.ByteSize,
		SHA256:            metadata.SHA256,
		AcceptedCount:     metadata.AcceptedCount,
		SkippedCount:      metadata.SkippedCount,
		RejectedCount:     metadata.RejectedCount,
		State:             string(metadata.State),
	}, nil
}

// WriteFeedProvenanceAudit emits one bounded observation per managed threat
// feed. It reports durable metadata only and never claims that kernel policy was
// reloaded from the snapshot.
func WriteFeedProvenanceAudit(writer io.Writer) {
	if writer == nil {
		return
	}
	for _, path := range []string{
		"/etc/syswarden/lists/syswarden_threatintel.ipv4",
		"/etc/syswarden/lists/syswarden_threatintel.ipv6",
	} {
		_, status, err := ReadAttestedFeedFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			_, _ = fmt.Fprintf(writer, "  [INFO] Threat feed %s has no active attested snapshot.\n", filepath.Base(path))
			continue
		}
		if err != nil {
			_, _ = fmt.Fprintf(writer, "  [FAIL] Threat feed %s attestation failed: %v\n", filepath.Base(path), err)
			continue
		}
		ageSeconds := int64(-1)
		if status.AgeSeconds != nil {
			ageSeconds = *status.AgeSeconds
		}
		_, _ = fmt.Fprintf(
			writer,
			"  [OBSERVED] Threat feed %s state=%s freshness=%s age_seconds=%d evidence=%s source_origin=%s retrieved_at=%s sha256=%s accepted=%d skipped=%d rejected=%d license=%s.\n",
			status.FeedName,
			status.State,
			status.Freshness,
			ageSeconds,
			status.EvidenceQuality,
			status.SourceOrigin,
			status.RetrievedAt,
			status.SHA256,
			status.AcceptedCount,
			status.SkippedCount,
			status.RejectedCount,
			status.LicenseIdentifier,
		)
	}
}
