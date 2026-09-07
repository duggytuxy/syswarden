package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func provenanceTestTarget(t *testing.T) feedFileTarget {
	t.Helper()
	return feedFileTarget{directory: t.TempDir(), name: "test_feed.ipv4"}
}

func TestFeedProvenanceRoundTripBindsLastKnownGood_SW_FEED_001(t *testing.T) {
	target := provenanceTestTarget(t)
	policy := testIPv4FeedPolicy(1)
	policy.skipNonPublicEntries = true
	candidate, err := canonicalizeCIDRFeed([]byte("8.8.8.8\n192.0.2.1\n1.1.1.1\n"), policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFeedFileAt(target, ".ipv4", candidate.content); err != nil {
		t.Fatal(err)
	}
	fixedTime := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	previousNow := feedProvenanceNow
	feedProvenanceNow = func() time.Time { return fixedTime }
	t.Cleanup(func() { feedProvenanceNow = previousNow })
	metadata, err := newCurrentFeedProvenance(target, "https://feeds.example.test/private/path?token=secret", "CC-BY-4.0", candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishFeedProvenance(target, ".ipv4", metadata); err != nil {
		t.Fatal(err)
	}

	got, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != feedStateCurrent || got.AcceptedCount != 2 || got.SkippedCount != 1 ||
		got.LicenseIdentifier != "CC-BY-4.0" || got.RetrievedAt != fixedTime.Format(time.RFC3339) {
		t.Fatalf("unexpected provenance: %#v", got)
	}
	if got.SourceURL != "https://feeds.example.test" || strings.Contains(got.SourceURL, "secret") || strings.Contains(got.SourceURL, "private") {
		t.Fatalf("source URL was not sanitized: %q", got.SourceURL)
	}
	digest := sha256.Sum256(candidate.content)
	if got.SHA256 != hex.EncodeToString(digest[:]) || got.LastKnownGoodSHA256 != got.SHA256 {
		t.Fatalf("last-known-good binding is invalid: %#v", got)
	}
	if err := markFeedProvenanceState(target, ".ipv4", feedStateStale, 3); err != nil {
		t.Fatal(err)
	}
	stale, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if stale.State != feedStateStale || stale.RejectedCount != 3 || stale.LastKnownGoodSHA256 != got.LastKnownGoodSHA256 {
		t.Fatalf("stale provenance lost its last-known-good binding: %#v", stale)
	}
}

func TestMergedDataShieldAndOSINTProvenanceReportsAuthenticatedUnion(t *testing.T) {
	target := provenanceTestTarget(t)
	validation := testIPv4FeedPolicy(1)
	dataShield := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.8.8/32"))
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		dataShield,
		validation,
		feedPublicationPolicy{verified: true},
		[]string{"https://shield-one.example/feed", "https://shield-two.example/feed"},
		"",
	); err != nil {
		t.Fatal(err)
	}
	osint := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "1.1.1.1/32"))
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		osint,
		validation,
		feedPublicationPolicy{mergePrevious: true},
		[]string{"https://osint-one.example/list", "https://osint-two.example/list"},
		"",
	); err != nil {
		t.Fatal(err)
	}
	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	content, metadata, err := readAttestedFeedInDirectory(directory, target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "1.1.1.1/32\n8.8.8.8/32\n" || metadata.AcceptedCount != 2 {
		t.Fatalf("authenticated union content/status = %q %#v", content, metadata)
	}
	wantOrigins := strings.Join([]string{
		"https://osint-one.example",
		"https://osint-two.example",
		"https://shield-one.example",
		"https://shield-two.example",
	}, ",")
	if metadata.SourceURL != wantOrigins || metadata.EvidenceQuality != feedEvidenceAuthenticatedUnion {
		t.Fatalf("authenticated union provenance = %#v", metadata)
	}
	if metadata.EvidenceQuality == feedEvidenceIntersection {
		t.Fatal("union content was falsely classified as a source intersection")
	}
}

func TestAuthenticatedUnionRefusesLegacyContentWithoutSourceProvenance(t *testing.T) {
	target := provenanceTestTarget(t)
	legacy := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.8.8/32"))
	if err := writeFeedFileAt(target, ".ipv4", legacy.content); err != nil {
		t.Fatal(err)
	}
	err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "1.1.1.1/32")),
		testIPv4FeedPolicy(1),
		feedPublicationPolicy{mergePrevious: true},
		[]string{"https://osint-one.example/list", "https://osint-two.example/list"},
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "without authenticated source provenance") {
		t.Fatalf("legacy merge error = %v", err)
	}
}

func TestFeedProvenanceStrictJSONRejectsDuplicateUnknownAndTrailing_SW_FEED_002(t *testing.T) {
	target := feedFileTarget{directory: "/tmp", name: "strict.ipv4"}
	valid := `{"schema_version":"syswarden.feed-provenance.v1","feed_name":"strict.ipv4","source_url":"https://example.test","source_identity":"sha256:` + strings.Repeat("b", 64) + `","retrieved_at":"2026-09-03T12:00:00Z","license_identifier":"not-attested","evidence_quality":"source-validated","byte_size":8,"sha256":"` + strings.Repeat("a", 64) + `","accepted_count":1,"skipped_count":0,"rejected_count":0,"state":"current","last_known_good_sha256":"` + strings.Repeat("a", 64) + `"}`
	testCases := map[string]string{
		"duplicate": strings.Replace(valid, `"feed_name":"strict.ipv4"`, `"feed_name":"strict.ipv4","feed_name":"strict.ipv4"`, 1),
		"unknown":   strings.Replace(valid, `"byte_size":8`, `"unexpected":true,"byte_size":8`, 1),
		"trailing":  valid + `{}`,
	}
	for name, content := range testCases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFeedProvenance([]byte(content), target); err == nil {
				t.Fatal("malformed provenance was accepted")
			}
		})
	}
}

func TestFeedProvenanceRejectsNonCanonicalOriginsTimesLicensesAndStates_SW_FEED_005(t *testing.T) {
	target := feedFileTarget{directory: "/tmp", name: "strict.ipv4"}
	fixedTime := time.Date(2026, time.September, 3, 13, 0, 0, 0, time.UTC)
	previousNow := feedProvenanceNow
	feedProvenanceNow = func() time.Time { return fixedTime }
	t.Cleanup(func() { feedProvenanceNow = previousNow })
	base := feedProvenance{
		SchemaVersion:       feedProvenanceSchemaVersion,
		FeedName:            target.name,
		SourceURL:           "https://example.test",
		SourceIdentity:      "sha256:" + strings.Repeat("a", 64),
		RetrievedAt:         "2026-09-03T12:00:00Z",
		LicenseIdentifier:   feedLicenseNotAttested,
		EvidenceQuality:     feedEvidenceSourceValidated,
		ByteSize:            8,
		SHA256:              strings.Repeat("b", 64),
		AcceptedCount:       1,
		State:               feedStateCurrent,
		LastKnownGoodSHA256: strings.Repeat("b", 64),
	}
	tests := map[string]func(*feedProvenance){
		"source path":       func(value *feedProvenance) { value.SourceURL += "/private" },
		"source identity":   func(value *feedProvenance) { value.SourceIdentity = "sha256:short" },
		"noncanonical time": func(value *feedProvenance) { value.RetrievedAt = "2026-09-03T14:00:00+02:00" },
		"future time": func(value *feedProvenance) {
			value.RetrievedAt = fixedTime.Add(maximumFeedClockSkew + time.Second).Format(time.RFC3339)
		},
		"license control":          func(value *feedProvenance) { value.LicenseIdentifier = "bad\nlicense" },
		"unavailable rejection":    func(value *feedProvenance) { value.State, value.RejectedCount = feedStateUnavailable, 1 },
		"rejected without count":   func(value *feedProvenance) { value.State = feedStateRejected },
		"last-known-good mismatch": func(value *feedProvenance) { value.LastKnownGoodSHA256 = strings.Repeat("c", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := validateFeedProvenance(candidate, target); err == nil {
				t.Fatal("invalid provenance was accepted")
			}
		})
	}
}

func TestAttestedFeedStatusExpiresWithoutReclassifyingDurableState_SW_FEED_010(t *testing.T) {
	target := provenanceTestTarget(t)
	candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.8.8/32"))
	publicationTime := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	currentTime := publicationTime
	previousNow := feedProvenanceNow
	feedProvenanceNow = func() time.Time { return currentTime }
	t.Cleanup(func() { feedProvenanceNow = previousNow })
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		candidate,
		testIPv4FeedPolicy(1),
		feedPublicationPolicy{verified: true},
		[]string{"https://example.test/feed"},
		"test-only",
	); err != nil {
		t.Fatal(err)
	}

	metadata, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := publicFeedProvenanceStatus(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != string(feedStateCurrent) || fresh.Freshness != string(feedStateCurrent) ||
		fresh.AgeSeconds == nil || *fresh.AgeSeconds != 0 {
		t.Fatalf("unexpected fresh status: %#v", fresh)
	}

	currentTime = publicationTime.Add(maximumCurrentFeedAge + time.Second)
	expired, err := publicFeedProvenanceStatus(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != string(feedStateCurrent) || expired.Freshness != "expired" ||
		expired.AgeSeconds == nil || *expired.AgeSeconds != int64((maximumCurrentFeedAge+time.Second)/time.Second) {
		t.Fatalf("unexpected expired status: %#v", expired)
	}
}

func TestVerifiedGeneralFeedPublishesProvenance_SW_FEED_004(t *testing.T) {
	server := newTLSCIDRServer(t, "8.8.8.8\n1.1.1.1\n")
	target := provenanceTestTarget(t)
	downloaded := []byte("8.8.8.8\n1.1.1.1\n")
	digest := sha256.Sum256(downloaded)
	if err := secureDownloadWithClient(t.Context(), server.Client(), server.URL, target, ".ipv4", hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	metadata, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != feedStateCurrent || metadata.AcceptedCount != 2 {
		t.Fatalf("unexpected published provenance: %#v", metadata)
	}
	lastKnownGood := metadata.LastKnownGoodSHA256
	invalid := newTLSCIDRServer(t, "not-a-prefix\n")
	invalidBytes := []byte("not-a-prefix\n")
	invalidDigest := sha256.Sum256(invalidBytes)
	if err := secureDownloadWithClient(t.Context(), invalid.Client(), invalid.URL, target, ".ipv4", hex.EncodeToString(invalidDigest[:])); err == nil {
		t.Fatal("invalid feed was accepted")
	}
	rejected, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.State != feedStateRejected || rejected.RejectedCount != 1 || rejected.LastKnownGoodSHA256 != lastKnownGood {
		t.Fatalf("rejected update lost last-known-good provenance: %#v", rejected)
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := secureDownloadWithClient(cancelled, server.Client(), server.URL, target, ".ipv4", hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("cancelled update was accepted")
	}
	unavailable, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.State != feedStateUnavailable || unavailable.LastKnownGoodSHA256 != lastKnownGood {
		t.Fatalf("unavailable update lost last-known-good provenance: %#v", unavailable)
	}
}

func TestFeedProvenanceFailsClosedOnModeSymlinkAndDigestDrift_SW_FEED_003(t *testing.T) {
	newFixture := func(t *testing.T) (feedFileTarget, feedProvenance) {
		t.Helper()
		target := provenanceTestTarget(t)
		candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.8.8/32"))
		if err := writeFeedFileAt(target, ".ipv4", candidate.content); err != nil {
			t.Fatal(err)
		}
		metadata, err := newCurrentFeedProvenance(target, "https://example.test/feed", "", candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := publishFeedProvenance(target, ".ipv4", metadata); err != nil {
			t.Fatal(err)
		}
		return target, metadata
	}

	t.Run("mode", func(t *testing.T) {
		target, metadata := newFixture(t)
		if err := os.Chmod(filepath.Join(target.directory, provenanceTarget(target).name), 0644); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates an unsafe provenance mode
			t.Fatal(err)
		}
		if _, err := readFeedProvenance(target, ".ipv4"); err == nil || !strings.Contains(err.Error(), "mode or owner") {
			t.Fatalf("mode error = %v", err)
		}
		if err := publishFeedProvenance(target, ".ipv4", metadata); err == nil || !strings.Contains(err.Error(), "untrusted mode or owner") {
			t.Fatalf("unsafe replacement error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target, _ := newFixture(t)
		path := filepath.Join(target.directory, provenanceTarget(target).name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(target.directory, target.name), path); err != nil {
			t.Fatal(err)
		}
		if _, err := readFeedProvenance(target, ".ipv4"); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink error = %v", err)
		}
	})

	t.Run("digest drift", func(t *testing.T) {
		target, _ := newFixture(t)
		changed := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "1.1.1.1/32"))
		if err := writeFeedFileAt(target, ".ipv4", changed.content); err != nil {
			t.Fatal(err)
		}
		if _, err := readFeedProvenance(target, ".ipv4"); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("digest binding error = %v", err)
		}
	})
}

func TestAttestedFeedPublicationRecoversAfterInterruptedCompatibilityCutover_SW_FEED_006(t *testing.T) {
	target := provenanceTestTarget(t)
	validation := testIPv4FeedPolicy(1)
	publication := feedPublicationPolicy{verified: true}
	first := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.8.8/32"))
	second := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "1.1.1.1/32"))
	if err := publishCanonicalFeedWithProvenanceAt(
		target, ".ipv4", first, validation, publication, []string{"https://one.example.test/feed"}, "test-only",
	); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected interruption before provenance commit")
	previousHook := feedPublicationHook
	feedPublicationHook = func(point string) error {
		if point == "compatibility-durable" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { feedPublicationHook = previousHook })
	if err := publishCanonicalFeedWithProvenanceAt(
		target, ".ipv4", second, validation, publication, []string{"https://two.example.test/feed"}, "test-only",
	); !errors.Is(err, injected) {
		t.Fatalf("interrupted publication error = %v", err)
	}

	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	active, metadata, err := readAttestedFeedInDirectory(directory, target)
	_ = directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != string(first.content) || metadata.State != feedStateCurrent {
		t.Fatalf("interrupted publication selected %q with %#v", active, metadata)
	}
	if _, err := readFeedProvenance(target, ".ipv4"); err == nil || !strings.Contains(err.Error(), "compatibility file") {
		t.Fatalf("compatibility drift was not reported: %v", err)
	}

	feedPublicationHook = func(string) error { return nil }
	if err := publishCanonicalFeedWithProvenanceAt(
		target, ".ipv4", second, validation, publication, []string{"https://two.example.test/feed"}, "test-only",
	); err != nil {
		t.Fatal(err)
	}
	metadata, err = readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256(first.content)
	if metadata.SHA256 == hex.EncodeToString(firstDigest[:]) {
		t.Fatal("recovery retained the old generation")
	}
}

func TestFirstAttestedFeedPublicationDoesNotActivateBeforeCommit_SW_FEED_007(t *testing.T) {
	target := provenanceTestTarget(t)
	candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "8.8.4.4/32"))
	injected := errors.New("injected interruption before first commit")
	previousHook := feedPublicationHook
	feedPublicationHook = func(point string) error {
		if point == "compatibility-durable" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { feedPublicationHook = previousHook })
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		candidate,
		testIPv4FeedPolicy(1),
		feedPublicationPolicy{verified: true},
		[]string{"https://example.test/feed"},
		"test-only",
	); !errors.Is(err, injected) {
		t.Fatalf("interrupted publication error = %v", err)
	}
	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, _, err := readAttestedFeedInDirectory(directory, target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted first snapshot was accepted: %v", err)
	}
}

func TestAttestedFeedIgnoresCompatibilitySubstitutionAndRejectsGenerationSubstitution_SW_FEED_008(t *testing.T) {
	target := provenanceTestTarget(t)
	candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "9.9.9.9/32"))
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		candidate,
		testIPv4FeedPolicy(1),
		feedPublicationPolicy{verified: true},
		[]string{"https://example.test/feed"},
		"test-only",
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.directory, target.name), []byte("1.1.1.1/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	active, metadata, err := readAttestedFeedInDirectory(directory, target)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	if string(active) != string(candidate.content) {
		_ = directory.Close()
		t.Fatalf("compatibility substitution became active: %q", active)
	}
	snapshotTarget, err := feedSnapshotTarget(target, metadata.SHA256)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	_ = directory.Close()
	if err := os.WriteFile(filepath.Join(target.directory, snapshotTarget.name), []byte("1.1.1.1/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err = openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, _, err := readAttestedFeedInDirectory(directory, target); err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatalf("generation substitution error = %v", err)
	}
}

func TestAttestedFeedRejectsSymlinkedGeneration_SW_FEED_009(t *testing.T) {
	target := provenanceTestTarget(t)
	candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, "4.2.2.2/32"))
	if err := publishCanonicalFeedWithProvenanceAt(
		target,
		".ipv4",
		candidate,
		testIPv4FeedPolicy(1),
		feedPublicationPolicy{verified: true},
		[]string{"https://example.test/feed"},
		"test-only",
	); err != nil {
		t.Fatal(err)
	}
	metadata, err := readFeedProvenance(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	snapshotTarget, err := feedSnapshotTarget(target, metadata.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(target.directory, snapshotTarget.name)
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target.directory, target.name), snapshotPath); err != nil {
		t.Fatal(err)
	}
	directory, err := openFeedDirectory(target, ".ipv4", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, _, err := readAttestedFeedInDirectory(directory, target); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked generation error = %v", err)
	}
}

func mustParseFeedPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
