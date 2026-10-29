package network

import (
	"fmt"
	"path/filepath"
)

// ThreatIntelSelection binds runtime consumption to the configured authorities,
// independently of whether the hourly updater has run since a TOML change.
type ThreatIntelSelection struct {
	ListChoice     string
	CustomURL      string
	CustomURLIPv6  string
	CustomHash     string
	CustomHashIPv6 string
	// OSINTEnabled is decoded for historical configuration compatibility only.
	// It cannot authorize a retired source for managed lists.
	OSINTEnabled bool
	LANMode      bool
}

// ReadSelectedThreatIntelFeed validates the bytes and their source identity in
// the same protected feed snapshot before allowing firewall consumption.
func ReadSelectedThreatIntelFeed(path string, selection ThreatIntelSelection) ([]byte, FeedProvenanceStatus, error) {
	family := 0
	for _, selected := range selectedThreatIntelFeeds(selection.CustomURL, selection.CustomURLIPv6, selection.ListChoice, selection.LANMode, selection.OSINTEnabled) {
		if selected.path == path {
			family = selected.family
			break
		}
	}
	if family == 0 {
		return nil, FeedProvenanceStatus{}, fmt.Errorf("threat feed %s is not selected", filepath.Base(path))
	}
	content, evidence, err := readOfflineQualificationFeed(path)
	if err != nil {
		return nil, evidence.status, err
	}
	if err := validateThreatIntelEvidenceForSelection(evidence, selection.ListChoice, family, selection.CustomURL, selection.CustomURLIPv6, selection.CustomHash, selection.CustomHashIPv6, selection.OSINTEnabled); err != nil {
		return nil, evidence.status, err
	}
	return content, evidence.status, nil
}

// IncludesFamily does not infer an IPv6 authority from the IPv4 standard list.
func (s ThreatIntelSelection) IncludesFamily(family int) bool {
	for _, selected := range selectedThreatIntelFeeds(s.CustomURL, s.CustomURLIPv6, s.ListChoice, s.LANMode, s.OSINTEnabled) {
		if selected.family == family {
			return true
		}
	}
	return false
}
