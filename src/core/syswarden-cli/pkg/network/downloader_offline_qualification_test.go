package network

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"syswarden-cli/pkg/system"
	"testing"
)

func offlineQualificationSources(rawURLs []string) (string, string) {
	type sourcePair struct {
		origin   string
		identity string
	}
	pairs := make([]sourcePair, 0, len(rawURLs))
	for _, rawURL := range rawURLs {
		origin, identity, err := sanitizedFeedSource(rawURL)
		if err != nil {
			panic(err)
		}
		pairs = append(pairs, sourcePair{origin: origin, identity: identity})
	}
	sort.Slice(pairs, func(left, right int) bool { return pairs[left].origin < pairs[right].origin })
	origins := make([]string, 0, len(pairs))
	identities := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		origins = append(origins, pair.origin)
		identities = append(identities, pair.identity)
	}
	return strings.Join(origins, ","), strings.Join(identities, ",")
}

func offlineQualificationStatus(path string, content []byte) offlineQualificationFeedEvidence {
	digest := sha256.Sum256(content)
	evidence := offlineQualificationFeedEvidence{
		status: FeedProvenanceStatus{
			FeedName:      filepath.Base(path),
			ByteSize:      int64(len(content)),
			SHA256:        hex.EncodeToString(digest[:]),
			AcceptedCount: 1,
			State:         "current",
		},
	}
	sources := osintThreatIntelSources()
	quality := feedEvidenceIntersection
	if strings.HasSuffix(path, ".ipv4") {
		mirrors := system.ThreatIntelMirrors("1")
		if len(mirrors) < 2 {
			panic("built-in Data-Shield source inventory is incomplete")
		}
		sources = mirrors[:2]
		quality = feedEvidenceOriginQuorum
	}
	origins, identities := offlineQualificationSources(sources)
	evidence.status.SourceOrigin = origins
	evidence.status.EvidenceQuality = quality
	evidence.sourceIdentity = identities
	return evidence
}

func dataShieldOfflineQualificationStatus(path string, content []byte, listChoice string) offlineQualificationFeedEvidence {
	evidence := offlineQualificationStatus(path, content)
	mirrors := system.ThreatIntelMirrors(listChoice)
	if len(mirrors) < 2 {
		panic("built-in Data-Shield source inventory is incomplete")
	}
	origins, identities := offlineQualificationSources(mirrors[:2])
	evidence.status.SourceOrigin = origins
	evidence.status.EvidenceQuality = feedEvidenceOriginQuorum
	evidence.sourceIdentity = identities
	return evidence
}

func customOfflineQualificationStatus(path string, content []byte, rawURL, authoritySHA256 string) offlineQualificationFeedEvidence {
	evidence := offlineQualificationStatus(path, content)
	origin, identity, err := sanitizedFeedSource(rawURL)
	if err != nil {
		panic(err)
	}
	evidence.status.SourceOrigin = origin
	evidence.status.EvidenceQuality = feedEvidencePinnedDigest
	evidence.sourceIdentity = identity
	evidence.authoritySHA256 = authoritySHA256
	return evidence
}

func TestOfflineQualificationFeedsReuseAttestedLastKnownGoodWithoutFetcher(t *testing.T) {
	reads := 0
	reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		reads++
		if strings.HasSuffix(path, ".ipv6") {
			return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
		}
		content := []byte("1.1.1.1/32\n")
		return content, offlineQualificationStatus(path, content), nil
	}
	if err := attestOfflineQualificationFeedsWith(
		"https://codeberg.org/", "", "", "", "1", "be", "fr", false, reader,
	); err != nil {
		t.Fatalf("offline last-known-good attestation failed: %v", err)
	}
	if reads != 2 {
		t.Fatalf("offline feed reads = %d, want 2", reads)
	}
}

func TestOfflineQualificationFeedsFailClosedOnMissingOrInvalidRequiredSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		reader offlineQualificationFeedReader
	}{
		{
			name: "missing required IPv4",
			reader: func(string) ([]byte, offlineQualificationFeedEvidence, error) {
				return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
			},
		},
		{
			name: "nonpublic IPv4",
			reader: func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
				content := []byte("192.0.2.1/32\n")
				return content, offlineQualificationStatus(path, content), nil
			},
		},
		{
			name: "provenance digest mismatch",
			reader: func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
				content := []byte("1.1.1.1/32\n")
				status := offlineQualificationStatus(path, content)
				status.status.SHA256 = strings.Repeat("0", sha256.Size*2)
				return content, status, nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := attestOfflineQualificationFeedsWith(
				"https://codeberg.org/", "", "", "", "1", "", "", false, test.reader,
			)
			if err == nil {
				t.Fatal("offline qualification accepted an invalid required feed")
			}
		})
	}
}

func TestOfflineQualificationFeedsRequireAbsenceInExplicitNoFeedModes(t *testing.T) {
	reader := func(string) ([]byte, offlineQualificationFeedEvidence, error) {
		return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
	}
	for _, selection := range []struct {
		name       string
		listChoice string
		lanMode    bool
	}{
		{name: "disabled", listChoice: "4"},
		{name: "lan", listChoice: "1", lanMode: true},
	} {
		t.Run(selection.name, func(t *testing.T) {
			if err := attestOfflineQualificationFeedsWith(
				"https://codeberg.org/", "", "", "", selection.listChoice, "", "", selection.lanMode, reader,
			); err != nil {
				t.Fatalf("explicit no-feed selection failed: %v", err)
			}
		})
	}
}

func TestOfflineQualificationFeedsRejectActiveSnapshotInNoFeedMode(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		if strings.HasSuffix(path, ".ipv4") {
			return content, offlineQualificationStatus(path, content), nil
		}
		return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
	}
	for _, selection := range []struct {
		name       string
		listChoice string
		lanMode    bool
	}{
		{name: "disabled", listChoice: "4"},
		{name: "lan", listChoice: "1", lanMode: true},
	} {
		t.Run(selection.name, func(t *testing.T) {
			err := attestOfflineQualificationFeedsWith(
				"https://codeberg.org/", "", "", "", selection.listChoice, "", "", selection.lanMode, reader,
			)
			if err == nil || !strings.Contains(err.Error(), "refuses active threat intelligence snapshot") {
				t.Fatalf("active no-feed snapshot error = %v", err)
			}
		})
	}
}

func TestOfflineQualificationFeedLifecycleRemovesUnselectedSnapshotsBeforeAttestation(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	reads := 0
	active := map[string]bool{
		"syswarden_threatintel.ipv4": true,
		"syswarden_threatintel.ipv6": true,
	}
	reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		reads++
		if !active[filepath.Base(path)] {
			return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
		}
		return content, offlineQualificationStatus(path, content), nil
	}
	remover := func(targets ...feedFileTarget) error {
		for _, target := range targets {
			delete(active, target.name)
		}
		return nil
	}

	if err := attestOfflineQualificationFeedsLifecycleWith(
		"https://codeberg.org/", "", "", "", "1", "", "", true, reader, remover,
	); err != nil {
		t.Fatalf("LAN cleanup and attestation failed: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("LAN cleanup left active snapshots: %#v", active)
	}
	if reads != 2 {
		t.Fatalf("injected feed reader calls = %d, want 2", reads)
	}
}

func TestUnselectedThreatIntelTargetsCoverSelectionTransitions(t *testing.T) {
	tests := []struct {
		name, ipv4URL, ipv6URL, choice string
		lan                            bool
		want                           []string
	}{
		{name: "lan", choice: "1", lan: true, want: []string{"syswarden_threatintel.ipv4", "syswarden_threatintel.ipv6"}},
		{name: "none", choice: "4", want: []string{"syswarden_threatintel.ipv4", "syswarden_threatintel.ipv6"}},
		{name: "custom v4 only", choice: "3", ipv4URL: "https://feeds.example/v4", want: []string{"syswarden_threatintel.ipv6"}},
		{name: "custom v6 only", choice: "3", ipv6URL: "https://feeds.example/v6", want: []string{"syswarden_threatintel.ipv4"}},
		{name: "custom dual stack", choice: "3", ipv4URL: "https://feeds.example/v4", ipv6URL: "https://feeds.example/v6"},
		{name: "managed", choice: "1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets := unselectedThreatIntelTargets(test.ipv4URL, test.ipv6URL, test.choice, test.lan)
			got := make([]string, 0, len(targets))
			for _, target := range targets {
				got = append(got, target.name)
			}
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("removal targets = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestOfflineQualificationCustomFeedsBindConfiguredSourceAndDigest(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	digest := sha256.Sum256(content)
	digestText := hex.EncodeToString(digest[:])
	configuredURL := "https://feeds.example.test/custom.ipv4"
	baseReader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		if strings.HasSuffix(path, ".ipv6") {
			return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
		}
		evidence := customOfflineQualificationStatus(path, content, configuredURL, digestText)
		return content, evidence, nil
	}
	if err := attestOfflineQualificationFeedsWith(
		configuredURL, "", digestText, "", "3", "", "", false, baseReader,
	); err != nil {
		t.Fatalf("matching custom feed rejected: %v", err)
	}

	for _, test := range []struct {
		name       string
		url        string
		digest     string
		mutateRead func(offlineQualificationFeedEvidence) offlineQualificationFeedEvidence
	}{
		{name: "changed URL", url: "https://other.example.test/custom.ipv4", digest: digestText},
		{name: "changed pin", url: configuredURL, digest: strings.Repeat("b", sha256.Size*2)},
		{
			name: "untrusted provenance class", url: configuredURL, digest: digestText,
			mutateRead: func(evidence offlineQualificationFeedEvidence) offlineQualificationFeedEvidence {
				evidence.status.EvidenceQuality = feedEvidenceSourceValidated
				return evidence
			},
		},
		{
			name: "substituted authority digest", url: configuredURL, digest: digestText,
			mutateRead: func(evidence offlineQualificationFeedEvidence) offlineQualificationFeedEvidence {
				evidence.authoritySHA256 = strings.Repeat("c", sha256.Size*2)
				return evidence
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := baseReader
			if test.mutateRead != nil {
				reader = func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
					body, evidence, readErr := baseReader(path)
					if readErr == nil {
						evidence = test.mutateRead(evidence)
					}
					return body, evidence, readErr
				}
			}
			err := attestOfflineQualificationFeedsWith(
				test.url, "", test.digest, "", "3", "", "", false, reader,
			)
			if err == nil || !strings.Contains(err.Error(), "does not match its configured source and pinned digest") {
				t.Fatalf("mismatched custom feed error = %v", err)
			}
		})
	}
}

func TestOfflineQualificationCustomFeedAcceptsRawAuthorityHashSeparateFromCanonicalSnapshot(t *testing.T) {
	raw := []byte("# operator source\n8.8.8.8/32\n1.1.1.1/32\n")
	rawDigest := sha256.Sum256(raw)
	rawDigestText := hex.EncodeToString(rawDigest[:])
	canonical := []byte("1.1.1.1/32\n8.8.8.8/32\n")
	configuredURL := "https://feeds.example.test/noncanonical.ipv4"
	reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		if strings.HasSuffix(path, ".ipv6") {
			return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
		}
		evidence := customOfflineQualificationStatus(path, canonical, configuredURL, rawDigestText)
		evidence.status.AcceptedCount = 2
		return canonical, evidence, nil
	}
	if err := attestOfflineQualificationFeedsWith(
		configuredURL, "", rawDigestText, "", "3", "", "", false, reader,
	); err != nil {
		t.Fatalf("raw authority digest separate from canonical snapshot was rejected: %v", err)
	}
}

func TestManagedSelectionRetiresCustomIPv6BeforeZeroOrFreshOSINTPublication(t *testing.T) {
	customURL := "https://feeds.example.test/custom.ipv6"
	customContent := []byte("2606:4700:4700::1111/128\n")
	customDigest := sha256.Sum256(customContent)
	customDigestText := hex.EncodeToString(customDigest[:])
	ipv4Content := []byte("1.1.1.1/32\n")
	for _, test := range []struct {
		name         string
		publishFresh bool
	}{
		{name: "zero OSINT IPv6 intersection"},
		{name: "nonzero OSINT IPv6 intersection", publishFresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			active := map[string]offlineQualificationFeedEvidence{
				"syswarden_threatintel.ipv4": offlineQualificationStatus("syswarden_threatintel.ipv4", ipv4Content),
				"syswarden_threatintel.ipv6": customOfflineQualificationStatus(
					"syswarden_threatintel.ipv6", customContent, customURL, customDigestText,
				),
			}
			reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
				evidence, ok := active[filepath.Base(path)]
				if !ok {
					return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
				}
				if strings.HasSuffix(path, ".ipv6") {
					return customContent, evidence, nil
				}
				return ipv4Content, evidence, nil
			}
			var removed []string
			remover := func(targets ...feedFileTarget) error {
				for _, target := range targets {
					removed = append(removed, target.name)
					delete(active, target.name)
				}
				return nil
			}
			retired, err := reconcileThreatIntelSelectionWith(
				"https://codeberg.org/", "", "", "", "1", false, reader, remover,
			)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(retired, ",") != "syswarden_threatintel.ipv6" {
				t.Fatalf("retired feeds = %#v", retired)
			}
			if _, exists := active["syswarden_threatintel.ipv6"]; exists {
				t.Fatal("custom IPv6 snapshot survived the switch to managed feeds")
			}
			if !strings.Contains(strings.Join(removed, ","), "syswarden_threatintel.ipv6") {
				t.Fatalf("removed targets = %#v", removed)
			}
			if test.publishFresh {
				fresh := offlineQualificationStatus("syswarden_threatintel.ipv6", customContent)
				if err := validateManagedThreatIntelEvidence(fresh, "1", 6); err != nil {
					t.Fatalf("fresh OSINT IPv6 evidence rejected: %v", err)
				}
			}
		})
	}
}

func TestManagedSelectionRetiresCustomOrWrongDataShieldIPv4(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	digest := sha256.Sum256(content)
	custom := customOfflineQualificationStatus(
		"syswarden_threatintel.ipv4", content, "https://feeds.example.test/custom.ipv4", hex.EncodeToString(digest[:]),
	)
	standard := dataShieldOfflineQualificationStatus("syswarden_threatintel.ipv4", content, "1")
	for _, test := range []struct {
		name       string
		selection  string
		evidence   offlineQualificationFeedEvidence
		wantRetire bool
	}{
		{name: "custom to standard", selection: "1", evidence: custom, wantRetire: true},
		{name: "standard to critical", selection: "2", evidence: standard, wantRetire: true},
		{name: "matching standard", selection: "1", evidence: standard},
	} {
		t.Run(test.name, func(t *testing.T) {
			removed := false
			reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
				if strings.HasSuffix(path, ".ipv6") {
					return nil, offlineQualificationFeedEvidence{}, fs.ErrNotExist
				}
				return content, test.evidence, nil
			}
			remover := func(targets ...feedFileTarget) error {
				for _, target := range targets {
					if target.name == "syswarden_threatintel.ipv4" {
						removed = true
					}
				}
				return nil
			}
			retired, err := reconcileThreatIntelSelectionWith(
				"https://codeberg.org/", "", "", "", test.selection, false, reader, remover,
			)
			if err != nil {
				t.Fatal(err)
			}
			if removed != test.wantRetire || (len(retired) != 0) != test.wantRetire {
				t.Fatalf("removed=%t retired=%#v wantRetire=%t", removed, retired, test.wantRetire)
			}
		})
	}
}

func TestManagedSelectionKeepsTwoCompatibleFeedsWithoutRemoval(t *testing.T) {
	ipv4Content := []byte("1.1.1.1/32\n")
	ipv6Content := []byte("2606:4700:4700::1111/128\n")
	reader := func(path string) ([]byte, offlineQualificationFeedEvidence, error) {
		if strings.HasSuffix(path, ".ipv6") {
			return ipv6Content, offlineQualificationStatus(path, ipv6Content), nil
		}
		return ipv4Content, offlineQualificationStatus(path, ipv4Content), nil
	}
	removeCalls := 0
	retired, err := reconcileThreatIntelSelectionWith(
		"https://codeberg.org/", "", "", "", "1", false,
		reader,
		func(...feedFileTarget) error {
			removeCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 || removeCalls != 0 {
		t.Fatalf("compatible feeds retired=%#v removeCalls=%d", retired, removeCalls)
	}
}

func TestOfflineManagedAttestationRejectsCustomEvidenceForBothFamilies(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(map[int]string{4: "IPv4", 6: "IPv6"}[family], func(t *testing.T) {
			content := []byte("1.1.1.1/32\n")
			path := "/etc/syswarden/lists/syswarden_threatintel.ipv4"
			url := "https://feeds.example.test/custom.ipv4"
			if family == 6 {
				content = []byte("2606:4700:4700::1111/128\n")
				path = "/etc/syswarden/lists/syswarden_threatintel.ipv6"
				url = "https://feeds.example.test/custom.ipv6"
			}
			digest := sha256.Sum256(content)
			evidence := customOfflineQualificationStatus(path, content, url, hex.EncodeToString(digest[:]))
			if err := validateManagedThreatIntelEvidence(evidence, "1", family); err == nil {
				t.Fatal("managed qualification accepted custom pinned provenance")
			}
		})
	}
}

func TestManagedIPv4RequiresSelectedDataShieldContribution(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	makeEvidence := func(quality string, rawURLs []string) offlineQualificationFeedEvidence {
		evidence := offlineQualificationStatus("syswarden_threatintel.ipv4", content)
		origins, identities := offlineQualificationSources(rawURLs)
		evidence.status.SourceOrigin = origins
		evidence.status.EvidenceQuality = quality
		evidence.sourceIdentity = identities
		return evidence
	}
	osint := osintThreatIntelSources()
	standardMirrors := system.ThreatIntelMirrors("1")
	if len(standardMirrors) < 2 {
		t.Fatal("standard Data-Shield source inventory is incomplete")
	}
	for _, test := range []struct {
		name       string
		selection  string
		evidence   offlineQualificationFeedEvidence
		wantReject bool
	}{
		{
			name:      "OSINT-only intersection under standard",
			selection: "1", evidence: makeEvidence(feedEvidenceIntersection, osint), wantReject: true,
		},
		{
			name:      "OSINT-only union under critical",
			selection: "2", evidence: makeEvidence(feedEvidenceAuthenticatedUnion, osint), wantReject: true,
		},
		{
			name:      "standard Data-Shield and OSINT union under critical",
			selection: "2",
			evidence: makeEvidence(
				feedEvidenceAuthenticatedUnion,
				append(append([]string(nil), standardMirrors[:2]...), osint...),
			),
			wantReject: true,
		},
		{
			name:      "standard Data-Shield quorum",
			selection: "1", evidence: makeEvidence(feedEvidenceOriginQuorum, standardMirrors[:2]),
		},
		{
			name:      "standard Data-Shield and OSINT union",
			selection: "1",
			evidence: makeEvidence(
				feedEvidenceAuthenticatedUnion,
				append(append([]string(nil), standardMirrors[:2]...), osint...),
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateManagedThreatIntelEvidence(test.evidence, test.selection, 4)
			if (err != nil) != test.wantReject {
				t.Fatalf("managed IPv4 evidence error = %v, wantReject=%t", err, test.wantReject)
			}
		})
	}
}
