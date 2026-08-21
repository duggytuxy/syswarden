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
		{input: "192.0.2.129/24", want: "192.0.2.0/24", wantIPv4: true, valid: true},
		{input: "2001:0db8::1", want: "2001:db8::1", valid: true},
		{input: "192.0.2.10:00443", want: "192.0.2.10", wantIPv4: true, wantPort: "443", valid: true},
		{input: "[2001:db8::10]:2222", want: "2001:db8::10", wantPort: "2222", valid: true},
		{input: "192.0.2.129/24:443", want: "192.0.2.0/24", wantIPv4: true, wantPort: "443", valid: true},
		{input: "[2001:db8:1::1/64]:443", want: "2001:db8:1::/64", wantPort: "443", valid: true},
		{input: "2001:db8::1:22", want: "2001:db8::1:22", valid: true},
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

func TestCanonicalRemovalPreservesUnrelatedEntries_SW_LIST_001(t *testing.T) {
	content := []byte("# operator entry\n192.0.2.1:22\n192.0.2.10\n198.51.100.129/24\n")
	updated, found := removeListEntriesForIP(content, "192.0.2.1")
	if !found {
		t.Fatal("exact removal did not find the port-qualified address")
	}
	want := "# operator entry\n192.0.2.10\n198.51.100.129/24\n"
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
