//go:build linux

package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	feedProvenanceSchemaV1       = "syswarden.feed-provenance.v1"
	maximumFeedProvenanceBytes   = int64(64 * 1024)
	maximumFeedSnapshotBytes     = int64(32 * 1024 * 1024)
	maximumFeedEntries           = 250000
	maximumFeedSources           = 16
	maximumFeedLicenseBytes      = 128
	maximumCurrentFeedAge        = 2 * time.Hour
	maximumFeedClockSkew         = 5 * time.Minute
	feedSnapshotGenerationMarker = ".syswarden-snapshot-"
)

var threatFeedNow = time.Now

// ThreatFeedStatus is a display-only view of the exact snapshot selected by a
// feed provenance commit. It never influences severity or firewall policy.
// Source identities are deliberately excluded because they may correlate a
// private configured URL.
type ThreatFeedStatus struct {
	FeedName          string   `json:"feed_name"`
	AddressFamily     string   `json:"address_family"`
	State             string   `json:"state"`
	Freshness         string   `json:"freshness"`
	Attestation       string   `json:"attestation"`
	SourceOrigins     []string `json:"source_origins"`
	RetrievedAt       string   `json:"retrieved_at,omitempty"`
	AgeSeconds        *int64   `json:"age_seconds,omitempty"`
	LicenseIdentifier string   `json:"license_identifier,omitempty"`
	EvidenceQuality   string   `json:"evidence_quality,omitempty"`
	SHA256            string   `json:"sha256,omitempty"`
	AcceptedCount     int      `json:"accepted_count"`
	SkippedCount      int      `json:"skipped_count"`
	RejectedCount     int      `json:"rejected_count"`
}

type feedProvenanceProjection struct {
	SchemaVersion       string `json:"schema_version"`
	FeedName            string `json:"feed_name"`
	SourceURL           string `json:"source_url"`
	SourceIdentity      string `json:"source_identity"`
	AuthoritySHA256     string `json:"authority_sha256,omitempty"`
	RetrievedAt         string `json:"retrieved_at"`
	LicenseIdentifier   string `json:"license_identifier"`
	EvidenceQuality     string `json:"evidence_quality"`
	ByteSize            int64  `json:"byte_size"`
	SHA256              string `json:"sha256"`
	AcceptedCount       int    `json:"accepted_count"`
	SkippedCount        int    `json:"skipped_count"`
	RejectedCount       int    `json:"rejected_count"`
	State               string `json:"state"`
	LastKnownGoodSHA256 string `json:"last_known_good_sha256"`
}

type feedProjectionIdentity struct {
	info  fs.FileInfo
	mode  fs.FileMode
	uid   uint32
	gid   uint32
	nlink uint64
	size  int64
	mtime time.Time
}

func unavailableThreatFeedStatus(feedName, family, attestation string) ThreatFeedStatus {
	return ThreatFeedStatus{
		FeedName:      feedName,
		AddressFamily: family,
		State:         "unavailable",
		Freshness:     "unavailable",
		Attestation:   attestation,
		SourceOrigins: []string{},
	}
}

func collectThreatFeedStatuses(listDirectory string, now time.Time) []ThreatFeedStatus {
	feeds := []struct {
		name   string
		family string
	}{
		{name: "syswarden_threatintel.ipv4", family: "ipv4"},
		{name: "syswarden_threatintel.ipv6", family: "ipv6"},
	}
	statuses := make([]ThreatFeedStatus, 0, len(feeds))
	for _, feed := range feeds {
		status, err := readThreatFeedStatus(listDirectory, feed.name, feed.family, now)
		if err != nil {
			attestation := "rejected"
			if errors.Is(err, fs.ErrNotExist) {
				attestation = "missing"
			}
			status = unavailableThreatFeedStatus(feed.name, feed.family, attestation)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func readThreatFeedStatus(listDirectory, feedName, family string, now time.Time) (ThreatFeedStatus, error) {
	if filepath.Clean(listDirectory) != listDirectory || !filepath.IsAbs(listDirectory) {
		return ThreatFeedStatus{}, fmt.Errorf("feed directory is not absolute and canonical")
	}
	if (family != "ipv4" && family != "ipv6") || feedName != "syswarden_threatintel."+family {
		return ThreatFeedStatus{}, fmt.Errorf("feed identity is not approved")
	}
	directory, err := openThreatFeedProjectionDirectory(listDirectory)
	if err != nil {
		return ThreatFeedStatus{}, err
	}
	defer directory.Close()
	lock, err := directory.Open(".")
	if err != nil {
		return ThreatFeedStatus{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return ThreatFeedStatus{}, err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	provenanceName := feedName + ".provenance.json"
	provenanceWire, provenanceIdentity, err := readOwnedFeedProjectionFile(directory, provenanceName, maximumFeedProvenanceBytes)
	if err != nil {
		return ThreatFeedStatus{}, err
	}
	metadata, origins, retrievedAt, err := decodeFeedProvenanceProjection(provenanceWire, feedName, now)
	if err != nil {
		return ThreatFeedStatus{}, err
	}
	snapshotName := "." + feedName + feedSnapshotGenerationMarker + metadata.SHA256
	snapshot, snapshotIdentity, err := readOwnedFeedProjectionFile(directory, snapshotName, maximumFeedSnapshotBytes)
	if err != nil {
		return ThreatFeedStatus{}, fmt.Errorf("active feed snapshot: %v", err)
	}
	digest := sha256.Sum256(snapshot)
	if metadata.ByteSize != int64(len(snapshot)) || metadata.SHA256 != hex.EncodeToString(digest[:]) {
		return ThreatFeedStatus{}, fmt.Errorf("feed provenance does not bind the active snapshot")
	}
	if bytes.Count(snapshot, []byte{'\n'}) != metadata.AcceptedCount || len(snapshot) == 0 || snapshot[len(snapshot)-1] != '\n' {
		return ThreatFeedStatus{}, fmt.Errorf("active feed snapshot count is inconsistent")
	}
	if err := reattestFeedProjectionFile(directory, provenanceName, provenanceIdentity); err != nil {
		return ThreatFeedStatus{}, fmt.Errorf("feed provenance changed while reading: %w", err)
	}
	if err := reattestFeedProjectionFile(directory, snapshotName, snapshotIdentity); err != nil {
		return ThreatFeedStatus{}, fmt.Errorf("active feed snapshot changed while reading: %w", err)
	}

	freshness := metadata.State
	var ageSeconds *int64
	if !retrievedAt.IsZero() {
		age := now.UTC().Sub(retrievedAt)
		if age < 0 {
			age = 0
		}
		seconds := int64(age / time.Second)
		ageSeconds = &seconds
		if metadata.State == "current" && age > maximumCurrentFeedAge {
			freshness = "expired"
		}
	}
	return ThreatFeedStatus{
		FeedName:          metadata.FeedName,
		AddressFamily:     family,
		State:             metadata.State,
		Freshness:         freshness,
		Attestation:       "verified",
		SourceOrigins:     origins,
		RetrievedAt:       metadata.RetrievedAt,
		AgeSeconds:        ageSeconds,
		LicenseIdentifier: metadata.LicenseIdentifier,
		EvidenceQuality:   metadata.EvidenceQuality,
		SHA256:            metadata.SHA256,
		AcceptedCount:     metadata.AcceptedCount,
		SkippedCount:      metadata.SkippedCount,
		RejectedCount:     metadata.RejectedCount,
	}, nil
}

func openThreatFeedProjectionDirectory(path string) (*os.Root, error) {
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for feed projection: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "/"), "/") {
		if component == "" {
			continue
		}
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, fmt.Errorf("feed directory component is not a real directory")
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("feed directory component changed while opening")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func readOwnedFeedProjectionFile(directory *os.Root, name string, maximumBytes int64) ([]byte, feedProjectionIdentity, error) {
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return nil, feedProjectionIdentity{}, fmt.Errorf("feed projection name is invalid")
	}
	before, err := directory.Lstat(name)
	if err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	identity, err := feedProjectionIdentityFromInfo(before, maximumBytes)
	if err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	file, err := directory.Open(name)
	if err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	openedIdentity, err := feedProjectionIdentityFromInfo(opened, maximumBytes)
	if err != nil || !sameFeedProjectionIdentity(identity, openedIdentity) || !os.SameFile(before, opened) {
		return nil, feedProjectionIdentity{}, fmt.Errorf("feed projection changed while opening")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	if int64(len(wire)) > maximumBytes {
		return nil, feedProjectionIdentity{}, fmt.Errorf("feed projection exceeds its size limit")
	}
	if err := reattestFeedProjectionFile(directory, name, identity); err != nil {
		return nil, feedProjectionIdentity{}, err
	}
	return wire, identity, nil
}

func feedProjectionIdentityFromInfo(info fs.FileInfo, maximumBytes int64) (feedProjectionIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode() != 0600 || int64(stat.Uid) != int64(os.Geteuid()) ||
		int64(stat.Gid) != int64(os.Getegid()) || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maximumBytes {
		return feedProjectionIdentity{}, fmt.Errorf("feed projection file has an unsafe identity")
	}
	return feedProjectionIdentity{
		info: info, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, nlink: uint64(stat.Nlink),
		size: info.Size(), mtime: info.ModTime(),
	}, nil
}

func sameFeedProjectionIdentity(left, right feedProjectionIdentity) bool {
	return os.SameFile(left.info, right.info) && left.mode == right.mode && left.uid == right.uid &&
		left.gid == right.gid && left.nlink == right.nlink && left.size == right.size && left.mtime.Equal(right.mtime)
}

func reattestFeedProjectionFile(directory *os.Root, name string, expected feedProjectionIdentity) error {
	current, err := directory.Lstat(name)
	if err != nil {
		return err
	}
	identity, err := feedProjectionIdentityFromInfo(current, expected.size)
	if err != nil || !sameFeedProjectionIdentity(expected, identity) {
		return fmt.Errorf("feed projection identity changed")
	}
	return nil
}

func decodeFeedProvenanceProjection(wire []byte, feedName string, now time.Time) (feedProvenanceProjection, []string, time.Time, error) {
	if len(wire) == 0 || int64(len(wire)) > maximumFeedProvenanceBytes {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance size is invalid")
	}
	if err := rejectDuplicateJSONKeys(wire); err != nil {
		return feedProvenanceProjection{}, nil, time.Time{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var metadata feedProvenanceProjection
	if err := decoder.Decode(&metadata); err != nil {
		return feedProvenanceProjection{}, nil, time.Time{}, err
	}
	if err := requireFeedProjectionJSONEOF(decoder); err != nil {
		return feedProvenanceProjection{}, nil, time.Time{}, err
	}
	if metadata.SchemaVersion != feedProvenanceSchemaV1 || metadata.FeedName != feedName {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance identity mismatch")
	}
	origins := strings.Split(metadata.SourceURL, ",")
	identities := strings.Split(metadata.SourceIdentity, ",")
	if len(origins) == 0 || len(origins) > maximumFeedSources || len(origins) != len(identities) || !sort.StringsAreSorted(origins) {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance source inventory is invalid")
	}
	seenOrigins := make(map[string]struct{}, len(origins))
	seenIdentities := make(map[string]struct{}, len(identities))
	for index, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
			parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != origin ||
			strings.ContainsAny(parsed.Host, ", \t\r\n") {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance source origin is invalid")
		}
		if _, duplicate := seenOrigins[origin]; duplicate {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance source inventory contains duplicates")
		}
		seenOrigins[origin] = struct{}{}
		identity := identities[index]
		if !strings.HasPrefix(identity, "sha256:") || !isLowerSHA256(strings.TrimPrefix(identity, "sha256:")) {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance source identity is invalid")
		}
		if _, duplicate := seenIdentities[identity]; duplicate {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance source inventory contains duplicates")
		}
		seenIdentities[identity] = struct{}{}
	}
	var retrievedAt time.Time
	switch metadata.EvidenceQuality {
	case "source-validated", "operator-pinned-sha256", "https-origin-quorum", "https-origin-intersection", "authenticated-source-union", "https-unverified-narrowing":
		parsed, err := time.Parse(time.RFC3339, metadata.RetrievedAt)
		if err != nil || parsed.UTC().Format(time.RFC3339) != metadata.RetrievedAt || parsed.After(now.UTC().Add(maximumFeedClockSkew)) {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance retrieval time is invalid")
		}
		retrievedAt = parsed
	case "legacy-local-validation":
		if metadata.RetrievedAt != "" || metadata.State != "stale" {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("legacy feed provenance state is invalid")
		}
	default:
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance evidence quality is invalid")
	}
	if metadata.LicenseIdentifier != strings.TrimSpace(metadata.LicenseIdentifier) || len(metadata.LicenseIdentifier) == 0 ||
		len(metadata.LicenseIdentifier) > maximumFeedLicenseBytes || strings.IndexFunc(metadata.LicenseIdentifier, func(value rune) bool {
		return unicode.IsControl(value) || !unicode.IsPrint(value)
	}) >= 0 {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance license identifier is invalid")
	}
	if metadata.ByteSize <= 0 || metadata.ByteSize > maximumFeedSnapshotBytes || metadata.AcceptedCount <= 0 ||
		metadata.AcceptedCount > maximumFeedEntries || metadata.SkippedCount < 0 || metadata.SkippedCount > maximumFeedEntries ||
		metadata.RejectedCount < 0 || metadata.RejectedCount > maximumFeedEntries || !isLowerSHA256(metadata.SHA256) ||
		!isLowerSHA256(metadata.LastKnownGoodSHA256) || metadata.SHA256 != metadata.LastKnownGoodSHA256 {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance bounds or digest are invalid")
	}
	if metadata.AuthoritySHA256 != "" &&
		(!isLowerSHA256(metadata.AuthoritySHA256) || metadata.EvidenceQuality != "operator-pinned-sha256" || len(origins) != 1) {
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance authority digest is invalid")
	}
	switch metadata.State {
	case "current":
		if metadata.RejectedCount != 0 {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("current feed provenance has rejected entries")
		}
	case "stale", "unavailable":
		if metadata.State == "unavailable" && metadata.RejectedCount != 0 {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("unavailable feed provenance has rejected entries")
		}
	case "rejected":
		if metadata.RejectedCount == 0 {
			return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("rejected feed provenance has no rejected entries")
		}
	default:
		return feedProvenanceProjection{}, nil, time.Time{}, fmt.Errorf("feed provenance state is invalid")
	}
	return metadata, origins, retrievedAt, nil
}

func requireFeedProjectionJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("feed provenance has trailing JSON")
		}
		return err
	}
	return nil
}

func isLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
