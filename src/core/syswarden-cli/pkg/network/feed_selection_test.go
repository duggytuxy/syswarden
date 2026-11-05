package network

import (
	"syswarden-cli/pkg/system"
	"testing"
)

func TestStandardOnlySelectionDoesNotInheritSupplementalAuthorities(t *testing.T) {
	base := ThreatIntelSelection{ListChoice: "1"}
	if !base.IncludesFamily(4) || base.IncludesFamily(6) {
		t.Fatal("standard selection inferred supplemental IPv6")
	}
	base.OSINTEnabled = true
	if !base.IncludesFamily(4) || base.IncludesFamily(6) {
		t.Fatal("historical OSINT flag reactivated the retired supplement")
	}
	base.OSINTEnabled = false
	base.LANMode = true
	if base.IncludesFamily(4) || base.IncludesFamily(6) {
		t.Fatal("LAN selection requested internet feeds")
	}
	base = ThreatIntelSelection{ListChoice: "3", CustomURLIPv6: "https://feeds.example.test/list6", CustomHashIPv6: "unused-in-selection"}
	if base.IncludesFamily(4) || !base.IncludesFamily(6) {
		t.Fatal("custom family selection changed")
	}
}

func TestStandardOnlyRejectsPreviousMergedOSINTUntilRebuilt(t *testing.T) {
	content := []byte("1.1.1.1/32\n")
	evidence := offlineQualificationStatus("/etc/syswarden/lists/syswarden_threatintel.ipv4", content)
	if err := validateManagedThreatIntelEvidence(evidence, "1", 4, false); err != nil {
		t.Fatal(err)
	}
	sources := append(append([]string(nil), system.ThreatIntelMirrors("1")...), retiredOSINTFixtureSources()...)
	evidence.status.SourceOrigin, evidence.sourceIdentity = offlineQualificationSources(sources)
	evidence.status.EvidenceQuality = feedEvidenceAuthenticatedUnion
	if err := validateManagedThreatIntelEvidence(evidence, "1", 4, true); err == nil {
		t.Fatal("historical union accepted with legacy OSINT selection")
	}
	if err := validateManagedThreatIntelEvidence(evidence, "1", 4, false); err == nil {
		t.Fatal("unselected OSINT survived runtime consumption")
	}
	ipv6 := offlineQualificationStatus("/etc/syswarden/lists/syswarden_threatintel.ipv6", []byte("2606:4700::/32\n"))
	if err := validateManagedThreatIntelEvidence(ipv6, "1", 6, false); err == nil {
		t.Fatal("OSINT IPv6 accepted without opt-in")
	}
}

func TestUnselectedFeedRefusesBeforeFilesystemRead(t *testing.T) {
	for _, path := range []string{"/etc/syswarden/lists/syswarden_threatintel.ipv6", "/tmp/unselected.ipv4"} {
		if _, _, err := ReadSelectedThreatIntelFeed(path, ThreatIntelSelection{ListChoice: "1"}); err == nil {
			t.Fatal("unselected feed read", path)
		}
	}
}

func TestBothManagedListsExcludeRetiredSourcesRegardlessOfLegacySelection(t *testing.T) {
	for _, choice := range []string{"1", "2"} {
		for _, legacyEnabled := range []bool{false, true} {
			selection := ThreatIntelSelection{ListChoice: choice, OSINTEnabled: legacyEnabled}
			if !selection.IncludesFamily(4) || selection.IncludesFamily(6) {
				t.Fatalf("managed list %s inherited retired supplemental family", choice)
			}
			content := []byte("1.1.1.1/32\n")
			evidence := dataShieldOfflineQualificationStatus("syswarden_threatintel.ipv4", content, choice)
			if err := validateManagedThreatIntelEvidence(evidence, choice, 4, legacyEnabled); err != nil {
				t.Fatal("matching Data-Shield quorum rejected", err)
			}
			for _, retired := range retiredOSINTFixtureSources() {
				origins := append(append([]string(nil), system.ThreatIntelMirrors(choice)[:2]...), retired)
				evidence.status.SourceOrigin, evidence.sourceIdentity = offlineQualificationSources(origins)
				for _, quality := range []string{feedEvidenceOriginQuorum, feedEvidenceAuthenticatedUnion} {
					evidence.status.EvidenceQuality = quality
					if err := validateManagedThreatIntelEvidence(evidence, choice, 4, legacyEnabled); err == nil {
						t.Fatalf("list %s accepted retired source under quality %s", choice, quality)
					}
				}
			}
		}
	}
}

func TestRetiredSupplementEntryPointCannotPublish(t *testing.T) {
	v4, _ := osintLifecycleTargets(t, true)
	before := osintLifecycleSnapshot(t, v4.directory)
	if err := DownloadOSINT(t.Context(), v4.directory+"/feed"); err == nil {
		t.Fatal("retired supplement reported a successful refresh")
	}
	after := osintLifecycleSnapshot(t, v4.directory)
	if len(before) != len(after) {
		t.Fatal("retired entry point changed the inventory")
	}
	for name, value := range before {
		if after[name] != value {
			t.Fatal("retired entry point changed existing bytes or metadata", name)
		}
	}
}
