package main

import "testing"

func TestParseVersion(t *testing.T) {
	t.Parallel()
	valid := map[string]Version{
		"v4.02.8":  {Major: 4, Minor: 2, Patch: 8},
		"v4.02.10": {Major: 4, Minor: 2, Patch: 10},
		"v12.99.0": {Major: 12, Minor: 99, Patch: 0},
		"v0.00.0":  {},
	}
	for raw, expected := range valid {
		raw, expected := raw, expected
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			actual, err := parseVersion(raw)
			if err != nil {
				t.Fatalf("parseVersion(%q): %v", raw, err)
			}
			if actual != expected || actual.String() != raw {
				t.Fatalf("parseVersion(%q) = %#v (%s), want %#v", raw, actual, actual, expected)
			}
		})
	}

	for _, raw := range []string{"", "4.02.8", "v4.2.8", "v4.002.8", "v04.02.8", "v4.02.08", "v4.02", "v4.02.8.1", "v4.-2.8", "v4.02.-1", " v4.02.8", "v4.02.8 ", "V4.02.8", "v2147483648.02.8"} {
		raw := raw
		t.Run("invalid_"+raw, func(t *testing.T) {
			t.Parallel()
			if _, err := parseVersion(raw); err == nil {
				t.Fatalf("parseVersion(%q) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestNextVersionContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		current string
		bump    BumpType
		want    string
	}{
		{current: "v4.02.8", bump: BumpPatch, want: "v4.02.9"},
		{current: "v4.02.9", bump: BumpPatch, want: "v4.02.10"},
		{current: "v4.02.8", bump: BumpMinor, want: "v4.03.0"},
		{current: "v4.09.7", bump: BumpMinor, want: "v4.10.0"},
		{current: "v4.02.8", bump: BumpMajor, want: "v4.10.0"},
		{current: "v4.12.3", bump: BumpMajor, want: "v4.20.0"},
		{current: "v4.99.9", bump: BumpUpgrade, want: "v5.00.0"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.current+"_"+string(test.bump), func(t *testing.T) {
			t.Parallel()
			current, err := parseVersion(test.current)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := nextVersion(current, test.bump)
			if err != nil {
				t.Fatalf("nextVersion: %v", err)
			}
			if actual.String() != test.want {
				t.Fatalf("nextVersion(%s, %s) = %s, want %s", current, test.bump, actual, test.want)
			}
		})
	}

	current, _ := parseVersion("v4.99.9")
	for _, bump := range []BumpType{BumpMinor, BumpMajor} {
		if _, err := nextVersion(current, bump); err == nil {
			t.Fatalf("nextVersion(%s, %s) should reject minor overflow", current, bump)
		}
	}
	if _, err := nextVersion(current, "Unknown"); err == nil {
		t.Fatal("nextVersion should reject an unknown bump type")
	}
	if _, err := nextVersion(Version{Major: 4, Minor: 2, Patch: 2147483647}, BumpPatch); err == nil {
		t.Fatal("nextVersion should reject patch overflow")
	}
	if _, err := nextVersion(Version{Major: 2147483647, Minor: 99, Patch: 9}, BumpUpgrade); err == nil {
		t.Fatal("nextVersion should reject major overflow")
	}
}

func TestParseCommitMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		message    string
		bump       BumpType
		recognized bool
		wantError  bool
	}{
		{name: "patch canonical", message: "Patch : fix validation", bump: BumpPatch, recognized: true},
		{name: "minor compact", message: "Minor: add feature", bump: BumpMinor, recognized: true},
		{name: "major multiline", message: "Major : harden API\n\nLong body", bump: BumpMajor, recognized: true},
		{name: "upgrade CRLF", message: "Upgrade : new generation\r\nBody", bump: BumpUpgrade, recognized: true},
		{name: "ordinary", message: "Docs : clarify support", recognized: false},
		{name: "wrong case", message: "patch : fix", recognized: false},
		{name: "prefix not at start", message: "Revert Patch : fix", recognized: false},
		{name: "empty canonical", message: "Patch :   ", wantError: true},
		{name: "empty compact", message: "Minor:", wantError: true},
		{name: "prefix only", message: "Upgrade", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bump, recognized, err := parseCommitMessage(test.message)
			if (err != nil) != test.wantError {
				t.Fatalf("parseCommitMessage error = %v, wantError %v", err, test.wantError)
			}
			if bump != test.bump || recognized != test.recognized {
				t.Fatalf("parseCommitMessage = (%q, %v), want (%q, %v)", bump, recognized, test.bump, test.recognized)
			}
		})
	}
}
