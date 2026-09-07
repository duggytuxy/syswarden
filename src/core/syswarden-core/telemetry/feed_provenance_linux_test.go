//go:build linux

package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeThreatFeedProjectionFixture(t *testing.T, directory, feedName, source, state string, retrievedAt time.Time) feedProvenanceProjection {
	t.Helper()
	digest := sha256.Sum256([]byte(source))
	digestText := hex.EncodeToString(digest[:])
	metadata := feedProvenanceProjection{
		SchemaVersion:       feedProvenanceSchemaV1,
		FeedName:            feedName,
		SourceURL:           "https://feed.example.test",
		SourceIdentity:      "sha256:" + strings.Repeat("b", 64),
		RetrievedAt:         retrievedAt.UTC().Format(time.RFC3339),
		LicenseIdentifier:   "CC-BY-4.0",
		EvidenceQuality:     "source-validated",
		ByteSize:            int64(len(source)),
		SHA256:              digestText,
		AcceptedCount:       strings.Count(source, "\n"),
		State:               state,
		LastKnownGoodSHA256: digestText,
	}
	if state == "rejected" {
		metadata.RejectedCount = 1
	}
	if err := os.WriteFile(filepath.Join(directory, "."+feedName+feedSnapshotGenerationMarker+digestText), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, feedName+".provenance.json"), append(wire, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestThreatFeedProjectionExposesVerifiedFreshnessWithoutSourceIdentity_SW_FEED_011(t *testing.T) {
	directory := t.TempDir()
	retrievedAt := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	writeThreatFeedProjectionFixture(t, directory, "syswarden_threatintel.ipv4", "1.1.1.1/32\n8.8.8.8/32\n", "current", retrievedAt)

	status, err := readThreatFeedStatus(directory, "syswarden_threatintel.ipv4", "ipv4", retrievedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if status.Attestation != "verified" || status.State != "current" || status.Freshness != "current" ||
		status.AgeSeconds == nil || *status.AgeSeconds != 3600 || status.AcceptedCount != 2 {
		t.Fatalf("unexpected threat-feed status: %#v", status)
	}
	if len(status.SourceOrigins) != 1 || status.SourceOrigins[0] != "https://feed.example.test" {
		t.Fatalf("source origins = %#v", status.SourceOrigins)
	}
	wire, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "source_identity") || strings.Contains(string(wire), strings.Repeat("b", 64)) {
		t.Fatalf("display projection exposed a private source identity: %s", wire)
	}

	expired, err := readThreatFeedStatus(directory, "syswarden_threatintel.ipv4", "ipv4", retrievedAt.Add(maximumCurrentFeedAge+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != "current" || expired.Freshness != "expired" || expired.Attestation != "verified" {
		t.Fatalf("expired status = %#v", expired)
	}
}

func TestThreatFeedProjectionAcceptsPinnedCustomAuthorityWithoutExposingIt_SW_FEED_017(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	metadata := writeThreatFeedProjectionFixture(
		t,
		directory,
		"syswarden_threatintel.ipv4",
		"1.1.1.1/32\n",
		"current",
		now,
	)
	metadata.EvidenceQuality = "operator-pinned-sha256"
	metadata.AuthoritySHA256 = strings.Repeat("a", 64)
	writeThreatFeedProvenanceFixture(t, directory, metadata)

	status, err := readThreatFeedStatus(directory, metadata.FeedName, "ipv4", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Attestation != "verified" || status.EvidenceQuality != metadata.EvidenceQuality {
		t.Fatalf("pinned custom feed status = %#v", status)
	}
	wire, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "authority_sha256") || strings.Contains(string(wire), metadata.AuthoritySHA256) {
		t.Fatalf("display projection exposed a private authority digest: %s", wire)
	}
}

func TestThreatFeedProjectionAcceptsAuthenticatedSourceUnion_SW_FEED_018(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	metadata := writeThreatFeedProjectionFixture(
		t,
		directory,
		"syswarden_threatintel.ipv4",
		"1.1.1.1/32\n8.8.8.8/32\n",
		"current",
		now,
	)
	metadata.SourceURL = "https://feed-one.example.test,https://feed-two.example.test"
	metadata.SourceIdentity = "sha256:" + strings.Repeat("a", 64) + ",sha256:" + strings.Repeat("b", 64)
	metadata.EvidenceQuality = "authenticated-source-union"
	metadata.LicenseIdentifier = "not-attested"
	writeThreatFeedProvenanceFixture(t, directory, metadata)

	status, err := readThreatFeedStatus(directory, metadata.FeedName, "ipv4", now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Attestation != "verified" || status.EvidenceQuality != metadata.EvidenceQuality ||
		len(status.SourceOrigins) != 2 {
		t.Fatalf("authenticated source union status = %#v", status)
	}
}

func TestThreatFeedProjectionRejectsInvalidAuthorityBinding_SW_FEED_019(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*feedProvenanceProjection)
	}{
		{name: "non canonical digest", mutate: func(metadata *feedProvenanceProjection) {
			metadata.AuthoritySHA256 = strings.Repeat("A", 64)
		}},
		{name: "non pinned quality", mutate: func(metadata *feedProvenanceProjection) {
			metadata.AuthoritySHA256 = strings.Repeat("a", 64)
			metadata.EvidenceQuality = "source-validated"
		}},
		{name: "multiple sources", mutate: func(metadata *feedProvenanceProjection) {
			metadata.AuthoritySHA256 = strings.Repeat("a", 64)
			metadata.SourceURL = "https://feed-one.example.test,https://feed-two.example.test"
			metadata.SourceIdentity = "sha256:" + strings.Repeat("a", 64) + ",sha256:" + strings.Repeat("b", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			metadata := writeThreatFeedProjectionFixture(
				t,
				directory,
				"syswarden_threatintel.ipv4",
				"1.1.1.1/32\n",
				"current",
				now,
			)
			metadata.EvidenceQuality = "operator-pinned-sha256"
			test.mutate(&metadata)
			writeThreatFeedProvenanceFixture(t, directory, metadata)
			if _, err := readThreatFeedStatus(directory, metadata.FeedName, "ipv4", now); err == nil {
				t.Fatal("invalid feed authority binding was accepted")
			}
		})
	}
}

func writeThreatFeedProvenanceFixture(t *testing.T, directory string, metadata feedProvenanceProjection) {
	t.Helper()
	wire, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, metadata.FeedName+".provenance.json"), append(wire, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestThreatFeedProjectionUsesAttestedGenerationNotMutableCompatibilityFile_SW_FEED_012(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	previousNow := threatFeedNow
	threatFeedNow = func() time.Time { return now }
	defer func() { threatFeedNow = previousNow }()
	writeThreatFeedProjectionFixture(t, directory, "syswarden_threatintel.ipv4", "1.1.1.1/32\n8.8.8.8/32\n", "current", now)
	if err := os.WriteFile(filepath.Join(directory, "syswarden_threatintel.ipv4"), []byte("203.0.113.0/24\n203.0.114.0/24\n203.0.115.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeTelemetryLines(t, filepath.Join(directory, "syswarden_blacklist.ipv4"), 3)

	stats := collectLayer3Stats(directory, nil)
	if stats.GlobalBlocked != 5 || stats.L7Banned != 3 {
		t.Fatalf("Layer 3 counters trusted mutable compatibility bytes: %#v", stats)
	}
	if len(stats.ThreatFeeds) != 2 || stats.ThreatFeeds[0].Attestation != "verified" || stats.ThreatFeeds[1].Attestation != "missing" {
		t.Fatalf("Layer 3 feed evidence = %#v", stats.ThreatFeeds)
	}
}

func TestThreatFeedProjectionRejectsMalformedOrSubstitutedEvidence_SW_FEED_013(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(t *testing.T, directory string, metadata feedProvenanceProjection)
	}{
		{
			name: "duplicate JSON field",
			mutate: func(t *testing.T, directory string, _ feedProvenanceProjection) {
				t.Helper()
				path := filepath.Join(directory, "syswarden_threatintel.ipv4.provenance.json")
				wire, err := os.ReadFile(path) // #nosec G304 -- path is a fixed provenance filename beneath t.TempDir
				if err != nil {
					t.Fatal(err)
				}
				wire = []byte(strings.Replace(string(wire), `"feed_name":`, `"feed_name":"syswarden_threatintel.ipv4","feed_name":`, 1))
				if err := os.WriteFile(path, wire, 0600); err != nil { // #nosec G703 -- path is a fixed provenance filename beneath t.TempDir
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown JSON field",
			mutate: func(t *testing.T, directory string, _ feedProvenanceProjection) {
				t.Helper()
				path := filepath.Join(directory, "syswarden_threatintel.ipv4.provenance.json")
				wire, err := os.ReadFile(path) // #nosec G304 -- path is a fixed provenance filename beneath t.TempDir
				if err != nil {
					t.Fatal(err)
				}
				wire = []byte(strings.Replace(string(wire), "{", `{"extra":true,`, 1))
				if err := os.WriteFile(path, wire, 0600); err != nil { // #nosec G703 -- path is a fixed provenance filename beneath t.TempDir
					t.Fatal(err)
				}
			},
		},
		{
			name: "snapshot digest drift",
			mutate: func(t *testing.T, directory string, metadata feedProvenanceProjection) {
				t.Helper()
				path := filepath.Join(directory, ".syswarden_threatintel.ipv4"+feedSnapshotGenerationMarker+metadata.SHA256)
				if err := os.WriteFile(path, []byte("9.9.9.9/32\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard-linked provenance",
			mutate: func(t *testing.T, directory string, _ feedProvenanceProjection) {
				t.Helper()
				path := filepath.Join(directory, "syswarden_threatintel.ipv4.provenance.json")
				if err := os.Link(path, filepath.Join(directory, "unexpected-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "world-readable provenance",
			mutate: func(t *testing.T, directory string, _ feedProvenanceProjection) {
				t.Helper()
				if err := os.Chmod(filepath.Join(directory, "syswarden_threatintel.ipv4.provenance.json"), 0644); err != nil { // #nosec G302 -- this adversarial fixture deliberately makes provenance world-readable
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing selected generation",
			mutate: func(t *testing.T, directory string, metadata feedProvenanceProjection) {
				t.Helper()
				if err := os.Remove(filepath.Join(directory, ".syswarden_threatintel.ipv4"+feedSnapshotGenerationMarker+metadata.SHA256)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symbolic-link provenance",
			mutate: func(t *testing.T, directory string, _ feedProvenanceProjection) {
				t.Helper()
				path := filepath.Join(directory, "syswarden_threatintel.ipv4.provenance.json")
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(path)+".real", path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			metadata := writeThreatFeedProjectionFixture(t, directory, "syswarden_threatintel.ipv4", "1.1.1.1/32\n", "current", now)
			test.mutate(t, directory, metadata)
			if _, err := readThreatFeedStatus(directory, "syswarden_threatintel.ipv4", "ipv4", now); err == nil {
				t.Fatal("unsafe feed evidence was accepted")
			}
			statuses := collectThreatFeedStatuses(directory, now)
			if statuses[0].Attestation != "rejected" || statuses[0].AcceptedCount != 0 {
				t.Fatalf("rejected projection = %#v", statuses[0])
			}
		})
	}
}

func TestThreatFeedProjectionRejectsAProvenanceTimestampBeyondClockSkew_SW_FEED_016(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	writeThreatFeedProjectionFixture(
		t,
		directory,
		"syswarden_threatintel.ipv4",
		"1.1.1.1/32\n",
		"current",
		now.Add(maximumFeedClockSkew+time.Second),
	)
	if _, err := readThreatFeedStatus(directory, "syswarden_threatintel.ipv4", "ipv4", now); err == nil {
		t.Fatal("future feed provenance timestamp was accepted")
	}
}

func TestThreatFeedProjectionPreservesExplicitDegradedStates_SW_FEED_014(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	for _, state := range []string{"stale", "unavailable", "rejected"} {
		t.Run(state, func(t *testing.T) {
			directory := t.TempDir()
			writeThreatFeedProjectionFixture(t, directory, "syswarden_threatintel.ipv4", "1.1.1.1/32\n", state, now)
			status, err := readThreatFeedStatus(directory, "syswarden_threatintel.ipv4", "ipv4", now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if status.State != state || status.Freshness != state || status.Attestation != "verified" || status.AcceptedCount != 1 {
				t.Fatalf("degraded feed status = %#v", status)
			}
		})
	}
}
