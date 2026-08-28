//go:build linux

package firewall

import (
	"strings"
	"testing"
)

func TestStrictAllowRejectsEmptyMergedPopulationBeforeMutation_SW_GEO_001(t *testing.T) {
	err := validateStrictAllowPopulations(
		true,
		nftSetPopulation{name: "syswarden_zt_allowed", entries: []string{}},
		nftSetPopulation{name: "syswarden_zt_allowed6", entries: []string{}},
	)
	if err == nil || !strings.Contains(err.Error(), "empty for both IPv4 and IPv6") {
		t.Fatalf("empty strict allow populations error = %v", err)
	}
}

func TestStrictAllowRejectsSupportedCountryWithNoAddressAllocation_SW_GEO_001(t *testing.T) {
	geo4, geo6, err := configuredAuthenticatedGeoIPPopulations(
		"bv",
		"syswarden_zt_allowed",
		"syswarden_zt_allowed6",
	)
	if err != nil {
		t.Fatalf("select supported empty-allocation country: %v", err)
	}
	merged4, err := mergeNFTAddressPopulations(
		"syswarden_zt_allowed",
		nftSetPopulation{name: "syswarden_zt_allowed", entries: []string{}},
		geo4,
	)
	if err != nil {
		t.Fatalf("merge empty IPv4 authorities: %v", err)
	}
	merged6, err := mergeNFTAddressPopulations(
		"syswarden_zt_allowed6",
		nftSetPopulation{name: "syswarden_zt_allowed6", entries: []string{}},
		geo6,
	)
	if err != nil {
		t.Fatalf("merge empty IPv6 authorities: %v", err)
	}
	if err := validateStrictAllowPopulations(true, merged4, merged6); err == nil {
		t.Fatal("strict allow accepted a supported country with no IPv4 or IPv6 allocation")
	}
}

func TestStrictAllowAcceptsOnePopulatedFamily_SW_GEO_001(t *testing.T) {
	tests := []struct {
		name string
		ipv4 nftSetPopulation
		ipv6 nftSetPopulation
	}{
		{
			name: "IPv4 only",
			ipv4: nftSetPopulation{name: "syswarden_zt_allowed", entries: []string{"175.45.176.0/22"}},
			ipv6: nftSetPopulation{name: "syswarden_zt_allowed6", entries: []string{}},
		},
		{
			name: "IPv6 only",
			ipv4: nftSetPopulation{name: "syswarden_zt_allowed", entries: []string{}},
			ipv6: nftSetPopulation{name: "syswarden_zt_allowed6", entries: []string{"2606:4700:4700::/48"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStrictAllowPopulations(true, test.ipv4, test.ipv6); err != nil {
				t.Fatalf("one-family strict allow population was rejected: %v", err)
			}
		})
	}
}

func TestStrictAllowDisabledAcceptsEmptyPopulations_SW_GEO_001(t *testing.T) {
	if err := validateStrictAllowPopulations(
		false,
		nftSetPopulation{name: "syswarden_zt_allowed"},
		nftSetPopulation{name: "syswarden_zt_allowed6"},
	); err != nil {
		t.Fatalf("disabled strict allow rejected empty populations: %v", err)
	}
}

func TestStrictAllowLegacySentinelsAreNotTreatedAsConfigured_SW_GEO_001(t *testing.T) {
	for _, test := range []struct {
		countries string
		asns      string
	}{
		{countries: " \t, , "},
		{asns: " \t, , "},
		{countries: "none"},
		{asns: "none"},
		{asns: "auto"},
		{countries: "none", asns: "none, auto"},
	} {
		if hasConfiguredStrictAllowSelection(test.countries, test.asns) {
			t.Fatalf("legacy sentinels were treated as strict allow policy: countries=%q asns=%q", test.countries, test.asns)
		}
	}
	if !hasConfiguredStrictAllowSelection("kp", "") || !hasConfiguredStrictAllowSelection("", "AS64500") {
		t.Fatal("real GeoIP or ASN strict allow selection was not detected")
	}
}

func TestStrictAllowRenderedPolicyUsesNormalizedConfiguration_SW_GEO_001(t *testing.T) {
	render := func(candidate strictAllowConfiguration) string {
		t.Helper()
		var rules strings.Builder
		appendStrictAllowInputRules(
			&rules,
			candidate.configured,
			[]string{"10.0.0.0/8"},
			[]string{"fd00::/8"},
		)
		appendStrictAllowForwardRules(&rules, candidate.configured)
		return rules.String()
	}

	for _, test := range []struct {
		name      string
		countries string
		asns      string
	}{
		{name: "whitespace and commas", countries: " \t, , ", asns: " ,\n "},
		{name: "legacy none", countries: "none", asns: "none"},
		{name: "legacy auto ASN", asns: "auto"},
		{name: "mixed legacy sentinels", countries: "none, NONE", asns: "auto none, AUTO"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := normalizeStrictAllowConfiguration(test.countries, test.asns)
			if candidate.configured || candidate.countries != "" || candidate.asns != "" {
				t.Fatalf("normalized strict allow configuration = %#v, want disabled and empty", candidate)
			}
			if got := render(candidate); got != "" {
				t.Fatalf("disabled strict allow rendered policy rules:\n%s", got)
			}
		})
	}

	real := normalizeStrictAllowConfiguration("none, kp", "auto, AS64500")
	if !real.configured || real.countries != "kp" || real.asns != "AS64500" {
		t.Fatalf("normalized real strict allow configuration = %#v", real)
	}
	rules := render(real)
	for _, required := range []string{
		"ip saddr { 10.0.0.0/8 } accept",
		"ip6 saddr { fd00::/8 } accept",
		"ip saddr != @syswarden_zt_allowed drop",
		"ip6 saddr != @syswarden_zt_allowed6 drop",
		"ip saddr != @syswarden_zt_allowed counter drop",
		"ip6 saddr != @syswarden_zt_allowed6 counter drop",
	} {
		if !strings.Contains(rules, required) {
			t.Fatalf("enabled strict allow policy omitted %q:\n%s", required, rules)
		}
	}
}
