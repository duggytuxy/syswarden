package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsValidIPCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input  string
		valid  bool
		isIPv4 bool
	}{
		{input: "192.0.2.1", valid: true, isIPv4: true},
		{input: "2001:db8::1", valid: true},
		{input: "192.0.2.0/24", valid: true, isIPv4: true},
		{input: "2001:db8::/32", valid: true},
		{input: "192.0.2.10:443"},
		{input: "[2001:db8::10]:443"},
		{input: "192.0.2.10 # operator comment"},
		{input: "192.0.2.1/33"},
		{input: "999.0.2.1"},
		{input: "example.com"},
		{input: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			valid, isIPv4 := IsValidIP(test.input)
			if valid != test.valid || isIPv4 != test.isIPv4 {
				t.Fatalf("IsValidIP(%q) = (%t, %t), want (%t, %t)", test.input, valid, isIPv4, test.valid, test.isIPv4)
			}
		})
	}
}

func TestRemoveFromFileCanonicalizationContract_SW_LIST_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list")
	content := "# operator comment\n 192.0.2.10 \n\n198.51.100.1\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- the contract intentionally models an existing operator-created world-readable list
		t.Fatal(err)
	}
	if err := removeFromFile(path, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	want := "# operator comment\n198.51.100.1\n"
	if string(got) != want {
		t.Fatalf("removeFromFile() output = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// os.WriteFile keeps the pre-existing mode. This records that an existing
	// operator-created list is not silently chmod'ed during an entry removal.
	if info.Mode().Perm() != 0644 {
		t.Fatalf("removeFromFile() mode = %#o, want preserved mode 0644", info.Mode().Perm())
	}
	if strings.Contains(string(got), "192.0.2.10") {
		t.Fatal("removed address remains in the list")
	}
}
