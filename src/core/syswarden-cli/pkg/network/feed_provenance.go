package network

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
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	feedProvenanceSchemaVersion    = "syswarden.feed-provenance.v1"
	maximumFeedProvenanceBytes     = 64 * 1024
	maximumFeedSources             = 16
	maximumFeedLicenseBytes        = 128
	maximumCurrentFeedAge          = 2 * time.Hour
	maximumFeedClockSkew           = 5 * time.Minute
	feedLicenseNotAttested         = "not-attested"
	feedEvidenceSourceValidated    = "source-validated"
	feedEvidencePinnedDigest       = "operator-pinned-sha256"
	feedEvidenceOriginQuorum       = "https-origin-quorum"
	feedEvidenceIntersection       = "https-origin-intersection"
	feedEvidenceAuthenticatedUnion = "authenticated-source-union"
	feedEvidenceRestrictedHTTPS    = "https-unverified-narrowing"
	feedEvidenceLegacyLocal        = "legacy-local-validation"
)

type feedFreshnessState string

const (
	feedStateCurrent     feedFreshnessState = "current"
	feedStateStale       feedFreshnessState = "stale"
	feedStateUnavailable feedFreshnessState = "unavailable"
	feedStateRejected    feedFreshnessState = "rejected"
)

type feedProvenance struct {
	SchemaVersion       string             `json:"schema_version"`
	FeedName            string             `json:"feed_name"`
	SourceURL           string             `json:"source_url"`
	SourceIdentity      string             `json:"source_identity"`
	AuthoritySHA256     string             `json:"authority_sha256,omitempty"`
	RetrievedAt         string             `json:"retrieved_at"`
	LicenseIdentifier   string             `json:"license_identifier"`
	EvidenceQuality     string             `json:"evidence_quality"`
	ByteSize            int64              `json:"byte_size"`
	SHA256              string             `json:"sha256"`
	AcceptedCount       int                `json:"accepted_count"`
	SkippedCount        int                `json:"skipped_count"`
	RejectedCount       int                `json:"rejected_count"`
	State               feedFreshnessState `json:"state"`
	LastKnownGoodSHA256 string             `json:"last_known_good_sha256"`
}

var feedProvenanceNow = time.Now

func provenanceTarget(target feedFileTarget) feedFileTarget {
	return feedFileTarget{directory: target.directory, name: target.name + ".provenance.json"}
}

func sanitizedFeedSource(raw string) (string, string, error) {
	parsed, err := validateHTTPSFeedURL(raw)
	if err != nil {
		return "", "", err
	}
	// Query strings, fragments, user information and paths may contain private
	// access material. The durable URL identifies the HTTPS origin only; the
	// digest binds the exact configured source without disclosing it.
	origin := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
	identity := sha256.Sum256([]byte(raw))
	return origin, "sha256:" + hex.EncodeToString(identity[:]), nil
}

func newCurrentFeedProvenance(target feedFileTarget, rawURL, license string, candidate canonicalCIDRFeed) (feedProvenance, error) {
	return newCurrentFeedProvenanceFromSources(target, []string{rawURL}, license, candidate)
}

func newCurrentFeedProvenanceFromSources(target feedFileTarget, rawURLs []string, license string, candidate canonicalCIDRFeed) (feedProvenance, error) {
	if len(rawURLs) == 0 || len(rawURLs) > maximumFeedSources {
		return feedProvenance{}, fmt.Errorf("feed provenance source count is outside accepted bounds")
	}
	type sourceEvidence struct {
		origin   string
		identity string
	}
	evidence := make([]sourceEvidence, 0, len(rawURLs))
	for _, rawURL := range rawURLs {
		sourceURL, identity, err := sanitizedFeedSource(rawURL)
		if err != nil {
			return feedProvenance{}, err
		}
		evidence = append(evidence, sourceEvidence{origin: sourceURL, identity: identity})
	}
	sort.Slice(evidence, func(left, right int) bool {
		if evidence[left].origin != evidence[right].origin {
			return evidence[left].origin < evidence[right].origin
		}
		return evidence[left].identity < evidence[right].identity
	})
	sourceURLs := make([]string, 0, len(evidence))
	identities := make([]string, 0, len(evidence))
	seenIdentities := make(map[string]struct{}, len(evidence))
	for index, item := range evidence {
		if index > 0 && item.origin == evidence[index-1].origin {
			return feedProvenance{}, fmt.Errorf("feed provenance sources must be unique")
		}
		if _, duplicate := seenIdentities[item.identity]; duplicate {
			return feedProvenance{}, fmt.Errorf("feed provenance sources must be unique")
		}
		seenIdentities[item.identity] = struct{}{}
		sourceURLs = append(sourceURLs, item.origin)
		identities = append(identities, item.identity)
	}
	license = strings.TrimSpace(license)
	if license == "" {
		license = feedLicenseNotAttested
	}
	digest := sha256.Sum256(candidate.content)
	digestText := hex.EncodeToString(digest[:])
	return feedProvenance{
		SchemaVersion:       feedProvenanceSchemaVersion,
		FeedName:            target.name,
		SourceURL:           strings.Join(sourceURLs, ","),
		SourceIdentity:      strings.Join(identities, ","),
		RetrievedAt:         feedProvenanceNow().UTC().Format(time.RFC3339),
		LicenseIdentifier:   license,
		EvidenceQuality:     feedEvidenceSourceValidated,
		ByteSize:            int64(len(candidate.content)),
		SHA256:              digestText,
		AcceptedCount:       len(candidate.prefixes),
		SkippedCount:        candidate.ignoredNonPublicEntries,
		State:               feedStateCurrent,
		LastKnownGoodSHA256: digestText,
	}, nil
}

func mergeAuthenticatedFeedSources(current *feedProvenance, previous feedProvenance) error {
	if current == nil {
		return errors.New("current feed provenance is unavailable")
	}
	type sourceEvidence struct {
		origin   string
		identity string
	}
	pairs := make([]sourceEvidence, 0, maximumFeedSources)
	appendSources := func(metadata feedProvenance) error {
		origins := strings.Split(metadata.SourceURL, ",")
		identities := strings.Split(metadata.SourceIdentity, ",")
		if len(origins) != len(identities) {
			return errors.New("feed provenance source inventory is misaligned")
		}
		for index := range origins {
			pairs = append(pairs, sourceEvidence{origin: origins[index], identity: identities[index]})
		}
		return nil
	}
	if err := appendSources(previous); err != nil {
		return err
	}
	if err := appendSources(*current); err != nil {
		return err
	}
	sort.Slice(pairs, func(left, right int) bool {
		if pairs[left].origin != pairs[right].origin {
			return pairs[left].origin < pairs[right].origin
		}
		return pairs[left].identity < pairs[right].identity
	})
	origins := make([]string, 0, len(pairs))
	identities := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if len(origins) > 0 && origins[len(origins)-1] == pair.origin {
			if identities[len(identities)-1] == pair.identity {
				continue
			}
			return errors.New("one feed source origin has conflicting exact identities")
		}
		origins = append(origins, pair.origin)
		identities = append(identities, pair.identity)
	}
	if len(origins) == 0 || len(origins) > maximumFeedSources {
		return errors.New("authenticated union source count is outside accepted bounds")
	}
	current.SourceURL = strings.Join(origins, ",")
	current.SourceIdentity = strings.Join(identities, ",")
	current.AuthoritySHA256 = ""
	current.LicenseIdentifier = feedLicenseNotAttested
	return nil
}

func validateFeedProvenance(metadata feedProvenance, target feedFileTarget) error {
	if metadata.SchemaVersion != feedProvenanceSchemaVersion || metadata.FeedName != target.name {
		return fmt.Errorf("feed provenance identity mismatch")
	}
	suffix := filepath.Ext(target.name)
	if err := validateFeedFileTarget(target, suffix); err != nil {
		return fmt.Errorf("feed provenance target: %w", err)
	}
	sources := strings.Split(metadata.SourceURL, ",")
	identities := strings.Split(metadata.SourceIdentity, ",")
	if len(sources) == 0 || len(sources) > maximumFeedSources || len(sources) != len(identities) ||
		!sort.StringsAreSorted(sources) {
		return fmt.Errorf("feed provenance source inventory is invalid")
	}
	seenIdentities := make(map[string]struct{}, len(identities))
	for index := range sources {
		if index > 0 && sources[index] == sources[index-1] {
			return fmt.Errorf("feed provenance source inventory contains duplicates")
		}
		parsed, err := validateHTTPSFeedURL(sources[index])
		if err != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
			strings.ContainsAny(parsed.Host, ", \t\r\n") ||
			(&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String() != sources[index] {
			return fmt.Errorf("feed provenance source origin is invalid")
		}
		if !strings.HasPrefix(identities[index], "sha256:") ||
			!approvedSHA256.MatchString(strings.TrimPrefix(identities[index], "sha256:")) ||
			identities[index] != strings.ToLower(identities[index]) {
			return fmt.Errorf("feed provenance source identity is invalid")
		}
		if _, duplicate := seenIdentities[identities[index]]; duplicate {
			return fmt.Errorf("feed provenance source inventory contains duplicates")
		}
		seenIdentities[identities[index]] = struct{}{}
	}
	switch metadata.EvidenceQuality {
	case feedEvidenceSourceValidated, feedEvidencePinnedDigest, feedEvidenceOriginQuorum, feedEvidenceIntersection,
		feedEvidenceAuthenticatedUnion, feedEvidenceRestrictedHTTPS:
		retrievedAt, err := time.Parse(time.RFC3339, metadata.RetrievedAt)
		if err != nil {
			return fmt.Errorf("feed provenance retrieval time: %w", err)
		}
		if retrievedAt.UTC().Format(time.RFC3339) != metadata.RetrievedAt {
			return fmt.Errorf("feed provenance retrieval time is not canonical UTC")
		}
		if retrievedAt.After(feedProvenanceNow().UTC().Add(maximumFeedClockSkew)) {
			return fmt.Errorf("feed provenance retrieval time exceeds the clock-skew allowance")
		}
	case feedEvidenceLegacyLocal:
		if metadata.RetrievedAt != "" || metadata.State != feedStateStale {
			return fmt.Errorf("legacy feed provenance must retain an unknown retrieval time and stale state")
		}
	default:
		return fmt.Errorf("feed provenance evidence quality is invalid")
	}
	if metadata.LicenseIdentifier != strings.TrimSpace(metadata.LicenseIdentifier) ||
		len(metadata.LicenseIdentifier) == 0 || len(metadata.LicenseIdentifier) > maximumFeedLicenseBytes ||
		strings.IndexFunc(metadata.LicenseIdentifier, func(value rune) bool {
			return unicode.IsControl(value) || !unicode.IsPrint(value)
		}) >= 0 {
		return fmt.Errorf("feed provenance license identifier is invalid")
	}
	if metadata.ByteSize <= 0 || metadata.ByteSize > maximumPublishedBytes || metadata.AcceptedCount <= 0 ||
		metadata.AcceptedCount > maximumCanonicalFeedEntries || metadata.SkippedCount > maximumCanonicalFeedEntries ||
		metadata.AcceptedCount < 0 || metadata.SkippedCount < 0 || metadata.RejectedCount < 0 {
		return fmt.Errorf("feed provenance counters are outside accepted bounds")
	}
	if !approvedSHA256.MatchString(metadata.SHA256) || !approvedSHA256.MatchString(metadata.LastKnownGoodSHA256) ||
		metadata.SHA256 != strings.ToLower(metadata.SHA256) ||
		metadata.LastKnownGoodSHA256 != strings.ToLower(metadata.LastKnownGoodSHA256) {
		return fmt.Errorf("feed provenance digest is invalid")
	}
	switch metadata.State {
	case feedStateCurrent, feedStateStale, feedStateUnavailable, feedStateRejected:
	default:
		return fmt.Errorf("feed provenance state is invalid: %q", metadata.State)
	}
	if metadata.SHA256 != metadata.LastKnownGoodSHA256 {
		return fmt.Errorf("feed provenance is not bound to its last-known-good digest")
	}
	if metadata.AuthoritySHA256 != "" {
		if metadata.AuthoritySHA256 != strings.ToLower(metadata.AuthoritySHA256) ||
			!approvedSHA256.MatchString(metadata.AuthoritySHA256) ||
			metadata.EvidenceQuality != feedEvidencePinnedDigest || len(sources) != 1 {
			return fmt.Errorf("feed provenance authority digest is invalid")
		}
	}
	if (metadata.State == feedStateCurrent && metadata.RejectedCount != 0) ||
		(metadata.State == feedStateRejected && metadata.RejectedCount == 0) ||
		metadata.State == feedStateUnavailable && metadata.RejectedCount != 0 {
		return fmt.Errorf("feed provenance state counters are inconsistent")
	}
	return nil
}

func rejectDuplicateJSONNames(decoder *json.Decoder) error {
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return fmt.Errorf("JSON object name is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON field %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func decodeFeedProvenance(content []byte, target feedFileTarget) (feedProvenance, error) {
	if len(content) == 0 || len(content) > maximumFeedProvenanceBytes {
		return feedProvenance{}, fmt.Errorf("feed provenance size is invalid")
	}
	duplicateDecoder := json.NewDecoder(bytes.NewReader(content))
	if err := rejectDuplicateJSONNames(duplicateDecoder); err != nil {
		return feedProvenance{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var metadata feedProvenance
	if err := decoder.Decode(&metadata); err != nil {
		return feedProvenance{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return feedProvenance{}, fmt.Errorf("feed provenance has trailing data")
	}
	if err := validateFeedProvenance(metadata, target); err != nil {
		return feedProvenance{}, err
	}
	return metadata, nil
}

func publishFeedProvenance(target feedFileTarget, suffix string, metadata feedProvenance) error {
	if err := validateFeedFileTarget(target, suffix); err != nil {
		return err
	}
	if err := validateFeedProvenance(metadata, target); err != nil {
		return err
	}
	directory, err := openFeedDirectory(target, suffix, true)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	feedContent, feedIdentity, err := readFeedFileSnapshotInDirectory(directory, target)
	if err != nil {
		return fmt.Errorf("read feed compatibility file: %w", err)
	}
	if err := trustedOwnerOnlyFeed(feedIdentity, "feed compatibility file"); err != nil {
		return err
	}
	digest := sha256.Sum256(feedContent)
	if metadata.ByteSize != int64(len(feedContent)) || metadata.SHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("feed provenance does not bind the compatibility file")
	}
	if _, err := ensureFeedSnapshotInDirectory(directory, target, feedContent); err != nil {
		return err
	}
	currentDigest := ""
	if _, current, activeErr := readAttestedFeedInDirectory(directory, target); activeErr == nil {
		currentDigest = current.SHA256
	} else if !errors.Is(activeErr, fs.ErrNotExist) {
		return fmt.Errorf("validate active feed snapshot before provenance publication: %w", activeErr)
	}
	if err := cleanupFeedSnapshotsInDirectory(directory, target, currentDigest, metadata.SHA256); err != nil {
		return err
	}
	if err := feedPublicationHook("snapshot-durable"); err != nil {
		return err
	}
	if err := feedPublicationHook("compatibility-durable"); err != nil {
		return err
	}
	return writeProvenanceCommitInDirectory(directory, target, metadata)
}

func readFeedProvenance(target feedFileTarget, suffix string) (feedProvenance, error) {
	directory, err := openFeedDirectory(target, suffix, false)
	if err != nil {
		return feedProvenance{}, err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return feedProvenance{}, err
	}
	defer unlockFeedDirectory(lockFile)
	feedContent, metadata, err := readAttestedFeedInDirectory(directory, target)
	if err != nil {
		return feedProvenance{}, err
	}
	if err := verifyCompatibilityFeedInDirectory(directory, target, feedContent); err != nil {
		return feedProvenance{}, err
	}
	return metadata, nil
}

func markFeedProvenanceState(target feedFileTarget, suffix string, state feedFreshnessState, rejectedCount int) error {
	if state == feedStateCurrent || rejectedCount < 0 || (state == feedStateRejected && rejectedCount == 0) ||
		state == feedStateUnavailable && rejectedCount != 0 {
		return fmt.Errorf("invalid feed provenance state transition")
	}
	directory, err := openFeedDirectory(target, suffix, false)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	lockFile, err := lockFeedDirectory(directory)
	if err != nil {
		return err
	}
	defer unlockFeedDirectory(lockFile)
	_, metadata, err := readAttestedFeedInDirectory(directory, target)
	if err != nil {
		return err
	}
	metadata.State = state
	metadata.RejectedCount = rejectedCount
	return writeProvenanceCommitInDirectory(directory, target, metadata)
}
