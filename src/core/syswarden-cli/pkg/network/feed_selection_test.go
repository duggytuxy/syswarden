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
	if !base.IncludesFamily(4) || !base.IncludesFamily(6) {
		t.Fatal("explicit OSINT selection lost a family")
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
	sources := append(append([]string(nil), system.ThreatIntelMirrors("1")...), osintThreatIntelSources()...)
	evidence.status.SourceOrigin, evidence.sourceIdentity = offlineQualificationSources(sources)
	evidence.status.EvidenceQuality = feedEvidenceAuthenticatedUnion
	if err := validateManagedThreatIntelEvidence(evidence, "1", 4, true); err != nil {
		t.Fatal(err)
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
