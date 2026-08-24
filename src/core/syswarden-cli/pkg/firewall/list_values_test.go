package firewall

import "testing"

func TestCanonicalListEntryGrammar_SW_LIST_001(t *testing.T) {
	tests := []struct {
		input    string
		want     string
		wantIPv4 bool
		wantPort string
		valid    bool
	}{
		{input: "192.0.2.0/24", want: "192.0.2.0/24", wantIPv4: true, valid: true},
		{input: "2001:0db8::1", want: "2001:db8::1", valid: true},
		{input: "192.0.2.10:00443", want: "192.0.2.10", wantIPv4: true, wantPort: "443", valid: true},
		{input: "[2001:db8::10]:2222", want: "2001:db8::10", wantPort: "2222", valid: true},
		{input: "192.0.2.0/24:443", want: "192.0.2.0/24", wantIPv4: true, wantPort: "443", valid: true},
		{input: "[2001:db8:1::/64]:443", want: "2001:db8:1::/64", wantPort: "443", valid: true},
		{input: "2001:db8::1:22", want: "2001:db8::1:22", valid: true},
		{input: "192.0.2.129/24"},
		{input: "192.0.2.129/24:443"},
		{input: "[2001:db8:1::1/64]:443"},
		{input: "[2001:db8::10]"},
		{input: "[fe80::1%eth0]:22"},
		{input: "[::ffff:192.0.2.1]:22"},
		{input: "192.0.2.1:0"},
		{input: "192.0.2.1:65536"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			entry, err := parseCanonicalListEntry(test.input, true)
			if (err == nil) != test.valid {
				t.Fatalf("parseCanonicalListEntry(%q) error = %v, valid = %t", test.input, err, test.valid)
			}
			if err != nil {
				return
			}
			if entry.network != test.want || entry.isIPv4 != test.wantIPv4 || entry.port != test.wantPort {
				t.Fatalf("entry = %#v, want network=%q ipv4=%t port=%q", entry, test.want, test.wantIPv4, test.wantPort)
			}
		})
	}
}

func TestCanonicalListEntryRejectsUnsafeNetworks_SW_SEC_M1(t *testing.T) {
	tests := []string{
		"0.0.0.0/0",
		"::/0",
		"8.0.0.0/8",
		"8.8.0.0/16",
		"2606:4700::/48",
		"10.20.0.0/16",
		"fd00::/48",
		"0.0.0.0",
		"::",
		"127.0.0.1",
		"169.254.10.20",
		"100.64.0.1",
		"198.18.0.1",
		"224.0.0.1",
		"255.255.255.255",
		"::1",
		"fe80::1",
		"ff02::1",
		"64:ff9b::1",
		"2001::1",
		"2002::1",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if entry, err := parseCanonicalListEntry(value, true); err == nil {
				t.Fatalf("parseCanonicalListEntry(%q) = %#v, want rejection", value, entry)
			}
		})
	}
}

func TestCanonicalListEntryPreservesBoundedPublicPrivateAndPortEntries_SW_SEC_M1(t *testing.T) {
	tests := map[string]string{
		"8.8.8.8":                   "8.8.8.8",
		"8.8.8.0/24":                "8.8.8.0/24",
		"8.8.8.128/25":              "8.8.8.128/25",
		"2606:4700:4700::1":         "2606:4700:4700::1",
		"2606:4700:4700::/64":       "2606:4700:4700::/64",
		"10.20.30.40":               "10.20.30.40",
		"10.20.30.0/24":             "10.20.30.0/24",
		"fd00:1234::/64":            "fd00:1234::/64",
		"8.8.8.8:00443":             "8.8.8.8:443",
		"[2606:4700:4700::1]:00443": "[2606:4700:4700::1]:443",
	}
	for input, want := range tests {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			entry, err := parseCanonicalListEntry(input, true)
			if err != nil {
				t.Fatalf("parseCanonicalListEntry(%q) error = %v", input, err)
			}
			if entry.String() != want {
				t.Fatalf("parseCanonicalListEntry(%q) = %q, want %q", input, entry.String(), want)
			}
		})
	}
}

func TestCanonicalListEntryAllowsBoundedDocumentationNetworks_SW_SEC_M1(t *testing.T) {
	// Documentation networks remain valid for operator-authored lab policy and
	// deterministic fixtures. They receive the same prefix floor as live space.
	for input, want := range map[string]string{
		"192.0.2.0/24":               "192.0.2.0/24",
		"198.51.100.8":               "198.51.100.8",
		"203.0.113.128/25":           "203.0.113.128/25",
		"[2001:db8:1234::/64]:00443": "[2001:db8:1234::/64]:443",
		"3fff:abc::/64":              "3fff:abc::/64",
	} {
		entry, err := parseCanonicalListEntry(input, true)
		if err != nil {
			t.Fatalf("parseCanonicalListEntry(%q) error = %v", input, err)
		}
		if entry.String() != want {
			t.Fatalf("parseCanonicalListEntry(%q) = %q, want %q", input, entry.String(), want)
		}
	}
	for _, broad := range []string{"192.0.0.0/16", "2001:db8::/32", "3fff::/20"} {
		if entry, err := parseCanonicalListEntry(broad, true); err == nil {
			t.Fatalf("parseCanonicalListEntry(%q) = %#v, want prefix-floor rejection", broad, entry)
		}
	}
}

func TestExactListAndRulesetLookup_SW_LIST_001(t *testing.T) {
	target, err := parseCanonicalListEntry("192.0.2.1", false)
	if err != nil {
		t.Fatal(err)
	}
	if listContentContainsNetwork([]byte("192.0.2.10\n198.51.100.192/26\n"), target) {
		t.Fatal("list lookup accepted a substring match")
	}
	if !listContentContainsNetwork([]byte("192.0.2.10\n192.0.2.1:2222\n"), target) {
		t.Fatal("list lookup missed an exact address with a port")
	}
	if nftRulesetContainsExactNetwork([]byte("ip saddr 192.0.2.10 accept"), target) {
		t.Fatal("ruleset lookup accepted a substring match")
	}
	if !nftRulesetContainsExactNetwork([]byte("add element inet syswarden fixture { 192.0.2.1 }"), target) {
		t.Fatal("ruleset lookup missed an exact address token")
	}
}

func TestDiagnosticLookupFindsLegacyUnsafeNetworks_SW2_M1(t *testing.T) {
	target, err := parseCanonicalRecoveryListEntry("0.0.0.0/0", false)
	if err != nil {
		t.Fatal(err)
	}
	if !listContentContainsNetwork([]byte("# legacy policy\n0.0.0.0/0\n"), target) {
		t.Fatal("list lookup missed a legacy unsafe network")
	}
	if !nftRulesetContainsExactNetwork([]byte("add element inet syswarden fixture { 0.0.0.0/0 }"), target) {
		t.Fatal("ruleset lookup missed a legacy unsafe network")
	}
}

func TestCanonicalRemovalPreservesUnrelatedEntries_SW_LIST_001(t *testing.T) {
	content := []byte("# operator entry\n192.0.2.1:22\n192.0.2.10\n198.51.100.129/24\n")
	updated, found, changed := removeListEntriesForIP(content, "192.0.2.1")
	if !found || !changed {
		t.Fatal("exact removal did not find the port-qualified address")
	}
	want := "# operator entry\n192.0.2.10\n"
	if string(updated) != want {
		t.Fatalf("updated list = %q, want %q", updated, want)
	}
}

func TestNewSSHBypassPortMustMatchEffectivePort_SW_LIST_002(t *testing.T) {
	tests := []struct {
		name          string
		network       string
		requestedPort string
		effectivePort string
		want          string
		wantError     bool
	}{
		{name: "equal IPv4 port", network: "192.0.2.1", requestedPort: "02222", effectivePort: "2222", want: "192.0.2.1:2222"},
		{name: "equal IPv6 port", network: "2001:db8::1", requestedPort: "2222", effectivePort: "2222", want: "[2001:db8::1]:2222"},
		{name: "legacy no port", network: "2001:db8::1", effectivePort: "22", want: "2001:db8::1"},
		{name: "mismatched port", network: "192.0.2.1", requestedPort: "2222", effectivePort: "22", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, err := newCanonicalSSHBypassEntry(test.network, test.requestedPort, test.effectivePort)
			if (err != nil) != test.wantError {
				t.Fatalf("newCanonicalSSHBypassEntry() error = %v, wantError=%t", err, test.wantError)
			}
			if err == nil && entry.String() != test.want {
				t.Fatalf("entry = %q, want %q", entry.String(), test.want)
			}
		})
	}
}
