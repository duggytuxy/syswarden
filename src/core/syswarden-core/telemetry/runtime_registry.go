package telemetry

import "sort"

// Administrative runtime claims need no attack record to appear in the active
// registry. This projection never contributes to physical-hit or risk metrics.
func appendActiveRuntimeRegistryEntries(entries []BannedIP, view runtimeEnforcementView) []BannedIP {
	if !view.linked || !view.complete || view.truncated || len(entries) >= 50 {
		return entries
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Action == "BANNED" && entry.EnforcementState == "active" {
			seen[entry.IP] = true
		}
	}
	addresses := make([]string, 0, len(view.byIP))
	for address, state := range view.byIP {
		if state == "active" && !seen[address] {
			addresses = append(addresses, address)
		}
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		if len(entries) >= 50 {
			break
		}
		entries = append(entries, BannedIP{
			Timestamp: view.capturedAt, IP: address, Jail: "native-runtime", Mitre: "-",
			Payload: "Active firewall block reported by native runtime.",
			Action:  "BANNED", EnforcementState: "active",
		})
	}
	return entries
}
