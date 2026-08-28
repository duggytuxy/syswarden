//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"syswarden-cli/pkg/geoip"
)

const maximumAuthenticatedGeoIPPrefixesPerFamily = 300000

// deniedAuthenticatedGeoIPPrefixes contains address space that must never be
// attributed to a country in an active firewall set. The embedded snapshot is
// bound to the binary, and the firewall independently revalidates its data
// before mutating kernel policy. Official signed releases authenticate the
// binary and therefore the exact snapshot bytes.
var deniedAuthenticatedGeoIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3ffe::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func configuredAuthenticatedGeoIPPopulations(
	rawCountries string,
	ipv4SetName string,
	ipv6SetName string,
) (nftSetPopulation, nftSetPopulation, error) {
	selectedCountries := authenticatedGeoIPCountryInput(rawCountries)
	if selectedCountries == "" {
		return nftSetPopulation{name: ipv4SetName, entries: []string{}}, nftSetPopulation{name: ipv6SetName, entries: []string{}}, nil
	}
	selection, err := geoip.Select(selectedCountries)
	if err != nil {
		return nftSetPopulation{name: ipv4SetName}, nftSetPopulation{name: ipv6SetName}, fmt.Errorf("select authenticated GeoIP snapshot: %w", err)
	}
	return populateAuthenticatedGeoIPSelection(selection, ipv4SetName, ipv6SetName)
}

func authenticatedGeoIPCountryInput(raw string) string {
	fields := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	selected := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.EqualFold(field, "none") {
			continue
		}
		selected = append(selected, field)
	}
	return strings.Join(selected, " ")
}

func populateAuthenticatedGeoIPSelection(
	selection geoip.Selection,
	ipv4SetName string,
	ipv6SetName string,
) (nftSetPopulation, nftSetPopulation, error) {
	ipv4 := nftSetPopulation{name: ipv4SetName}
	ipv6 := nftSetPopulation{name: ipv6SetName}
	expectedSnapshotID := geoip.SnapshotID()
	if expectedSnapshotID == "" {
		return ipv4, ipv6, fmt.Errorf("embedded GeoIP snapshot has no identity")
	}
	if selection.SnapshotID == "" {
		return ipv4, ipv6, fmt.Errorf("authenticated GeoIP selection has no snapshot identity")
	}
	if selection.SnapshotID != expectedSnapshotID {
		return ipv4, ipv6, fmt.Errorf("authenticated GeoIP selection identity %q does not match embedded snapshot %q", selection.SnapshotID, expectedSnapshotID)
	}
	expectedSelection, err := geoip.Select(strings.Join(selection.Countries, " "))
	if err != nil {
		return ipv4, ipv6, fmt.Errorf("reselect authenticated GeoIP countries from embedded snapshot: %w", err)
	}
	if expectedSelection.SnapshotID != expectedSnapshotID {
		return ipv4, ipv6, fmt.Errorf("reselected GeoIP identity %q does not match embedded snapshot %q", expectedSelection.SnapshotID, expectedSnapshotID)
	}
	if !slices.Equal(selection.Countries, expectedSelection.Countries) {
		return ipv4, ipv6, fmt.Errorf("authenticated GeoIP country list is not the normalized embedded selection")
	}
	if !slices.Equal(selection.IPv4, expectedSelection.IPv4) {
		return ipv4, ipv6, fmt.Errorf("authenticated GeoIP IPv4 prefix list does not match the embedded country selection")
	}
	if !slices.Equal(selection.IPv6, expectedSelection.IPv6) {
		return ipv4, ipv6, fmt.Errorf("authenticated GeoIP IPv6 prefix list does not match the embedded country selection")
	}
	var errs []error
	var ipv4Err, ipv6Err error
	ipv4.entries, ipv4Err = canonicalAuthenticatedGeoIPPrefixes(selection.IPv4, false, ipv4SetName)
	ipv6.entries, ipv6Err = canonicalAuthenticatedGeoIPPrefixes(selection.IPv6, true, ipv6SetName)
	errs = append(errs, ipv4Err, ipv6Err)
	return ipv4, ipv6, errors.Join(errs...)
}

func canonicalAuthenticatedGeoIPPrefixes(raw []string, wantIPv6 bool, setName string) ([]string, error) {
	if !nftSetNameRE.MatchString(setName) {
		return nil, fmt.Errorf("invalid nftables set name %q", setName)
	}
	if len(raw) > maximumAuthenticatedGeoIPPrefixesPerFamily {
		return nil, fmt.Errorf("%s: authenticated GeoIP selection exceeds %d prefixes", setName, maximumAuthenticatedGeoIPPrefixesPerFamily)
	}
	prefixes := make([]netip.Prefix, 0, len(raw))
	seen := make(map[netip.Prefix]struct{}, len(raw))
	var errs []error
	for index, value := range raw {
		prefix, err := canonicalAuthenticatedGeoIPPrefix(value, wantIPv6)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: authenticated prefix %d: %w", setName, index+1, err))
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			errs = append(errs, fmt.Errorf("%s: authenticated prefix %d duplicates %s", setName, index+1, prefix))
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(left, right int) bool {
		return prefixes[left].Compare(prefixes[right]) < 0
	})
	var furthest nftAddressInterval
	var furthestPrefix netip.Prefix
	for index, prefix := range prefixes {
		current, err := nftIntervalForEntry(prefix.String())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: derive authenticated interval: %w", setName, err))
			continue
		}
		if index > 0 && current.start.Compare(furthest.end) <= 0 {
			errs = append(errs, fmt.Errorf("%s: authenticated prefixes %s and %s overlap", setName, furthestPrefix, prefix))
		}
		if index == 0 || current.end.Compare(furthest.end) > 0 {
			furthest = current
			furthestPrefix = prefix
		}
	}
	entries := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		entries = append(entries, prefix.String())
	}
	normalized, err := normalizeNFTIntervals(setName, entries)
	if err != nil {
		errs = append(errs, err)
	} else {
		entries = normalized
	}
	return entries, errors.Join(errs...)
}

func canonicalAuthenticatedGeoIPPrefix(value string, wantIPv6 bool) (netip.Prefix, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return netip.Prefix{}, fmt.Errorf("invalid canonical GeoIP prefix %q", value)
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid GeoIP CIDR %q", value)
	}
	if prefix != prefix.Masked() || value != prefix.String() {
		return netip.Prefix{}, fmt.Errorf("non-canonical GeoIP CIDR %q", value)
	}
	if wantIPv6 == prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("GeoIP CIDR %q has the wrong address family", value)
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("GeoIP CIDR %q is an unbounded /0", value)
	}
	if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || overlapsAnyNetwork(prefix, deniedAuthenticatedGeoIPPrefixes) {
		return netip.Prefix{}, fmt.Errorf("GeoIP CIDR %q overlaps non-public or special-use space", value)
	}
	return prefix, nil
}

func mergeNFTAddressPopulations(setName string, populations ...nftSetPopulation) (nftSetPopulation, error) {
	merged := nftSetPopulation{name: setName}
	if !nftSetNameRE.MatchString(setName) {
		return merged, fmt.Errorf("invalid nftables set name %q", setName)
	}
	var intervals []nftAddressInterval
	for _, population := range populations {
		if population.kind != nftAddressPopulation {
			return merged, fmt.Errorf("%s: cannot merge non-address population %s", setName, population.name)
		}
		for _, entry := range population.entries {
			interval, err := nftPopulationInterval(entry)
			if err != nil {
				return merged, fmt.Errorf("%s: merge %s entry %q: %w", setName, population.name, entry, err)
			}
			wantIPv6 := strings.HasSuffix(setName, "6")
			if wantIPv6 == interval.start.Is4() || interval.start.Is4() != interval.end.Is4() {
				return merged, fmt.Errorf("%s: merge %s entry %q has the wrong address family", setName, population.name, entry)
			}
			intervals = append(intervals, interval)
		}
	}
	merged.entries = normalizeNFTAddressIntervals(intervals)
	return merged, nil
}

func nftPopulationInterval(value string) (nftAddressInterval, error) {
	if interval, err := nftIntervalForEntry(value); err == nil {
		return interval, nil
	}
	canonical, err := canonicalNFTIntervalExpression(value)
	if err != nil {
		return nftAddressInterval{}, err
	}
	parts := strings.Split(canonical, "-")
	if len(parts) != 2 {
		return nftAddressInterval{}, fmt.Errorf("invalid normalized nftables interval %q", value)
	}
	start, startErr := netip.ParseAddr(parts[0])
	end, endErr := netip.ParseAddr(parts[1])
	if startErr != nil || endErr != nil {
		return nftAddressInterval{}, fmt.Errorf("invalid normalized nftables interval %q", value)
	}
	return nftAddressInterval{text: canonical, start: start, end: end}, nil
}

func normalizeNFTAddressIntervals(intervals []nftAddressInterval) []string {
	sort.Slice(intervals, func(left, right int) bool {
		comparison := intervals[left].start.Compare(intervals[right].start)
		if comparison == 0 {
			return intervals[left].end.Compare(intervals[right].end) < 0
		}
		return comparison < 0
	})
	if len(intervals) == 0 {
		return []string{}
	}
	merged := []nftAddressInterval{intervals[0]}
	for index := 1; index < len(intervals); index++ {
		current := intervals[index]
		previous := &merged[len(merged)-1]
		overlaps := current.start.Compare(previous.end) <= 0
		adjacent := false
		if next := previous.end.Next(); next.IsValid() {
			adjacent = current.start == next
		}
		if overlaps || adjacent {
			if current.end.Compare(previous.end) > 0 {
				previous.end = current.end
				previous.text = ""
			}
			continue
		}
		merged = append(merged, current)
	}
	result := make([]string, 0, len(merged))
	for _, interval := range merged {
		if interval.text != "" {
			result = append(result, interval.text)
		} else if interval.start == interval.end {
			result = append(result, interval.start.String())
		} else {
			result = append(result, interval.start.String()+"-"+interval.end.String())
		}
	}
	return result
}
