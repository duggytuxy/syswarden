package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func readBoundedRegularTestFile(directory, name string) ([]byte, error) {
	if name == "" || name == "." || filepath.Base(name) != name {
		return nil, fmt.Errorf("test file name %q is not a basename", name)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open test root: %w", err)
	}
	defer root.Close()

	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("lstat test file: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("test file %q is not regular", name)
	}
	content, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}
	after, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("revalidate test file: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("test file %q changed during read", name)
	}
	return content, nil
}

func TestRemoveExactLegacyMetadataWhitelistLinePreservesAllOtherBytes_SW_SEC_M1(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		changed bool
	}{
		{
			name:    "beginning",
			input:   legacyMetadataWhitelistIPv4 + "\n8.8.8.8\n",
			want:    "8.8.8.8\n",
			changed: true,
		},
		{
			name:    "middle",
			input:   "# operator comment\n" + legacyMetadataWhitelistIPv4 + "\n10.0.0.1\n",
			want:    "# operator comment\n10.0.0.1\n",
			changed: true,
		},
		{
			name:    "terminal EOF without LF",
			input:   "8.8.8.8\n" + legacyMetadataWhitelistIPv4,
			want:    "8.8.8.8\n",
			changed: true,
		},
		{
			name:    "duplicates",
			input:   legacyMetadataWhitelistIPv4 + "\n\n" + legacyMetadataWhitelistIPv4 + "\n10.0.0.1\n" + legacyMetadataWhitelistIPv4,
			want:    "\n10.0.0.1\n",
			changed: true,
		},
		{
			name: "lookalikes remain byte exact",
			input: " 169.254.169.254\n" +
				"169.254.169.254 \n" +
				"169.254.169.254:443\n" +
				"169.254.169.254/32\n" +
				"# 169.254.169.254\n" +
				"169.254.169.254\r\n" +
				"169.254.169.25\n",
			want: " 169.254.169.254\n" +
				"169.254.169.254 \n" +
				"169.254.169.254:443\n" +
				"169.254.169.254/32\n" +
				"# 169.254.169.254\n" +
				"169.254.169.254\r\n" +
				"169.254.169.25\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, changed := removeExactListLine([]byte(test.input), legacyMetadataWhitelistIPv4)
			if changed != test.changed {
				t.Fatalf("changed = %t, want %t", changed, test.changed)
			}
			if string(got) != test.want {
				t.Fatalf("output = %q, want byte-exact %q", got, test.want)
			}
		})
	}
}

func TestLegacyMetadataWhitelistUpgradeRetirementIsBoundedAndIdempotent_SW_SEC_M1(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "whitelist.ipv4"}
	path := filepath.Join(directory, target.name)
	fixture := []byte("# preserved operator record\n" +
		legacyMetadataWhitelistIPv4 + "\n" +
		"8.8.8.8\n" +
		" " + legacyMetadataWhitelistIPv4 + " \n" +
		legacyMetadataWhitelistIPv4)
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwner := before.Sys().(*syscall.Stat_t)

	changed, err := retireLegacyMetadataWhitelistEntryAt(target)
	if err != nil || !changed {
		t.Fatalf("legacy retirement = (%t, %v), want (true, nil)", changed, err)
	}
	want := "# preserved operator record\n8.8.8.8\n " + legacyMetadataWhitelistIPv4 + " \n"
	content, err := readBoundedRegularTestFile(directory, target.name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("retired whitelist = %q, want byte-exact %q", content, want)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterOwner := after.Sys().(*syscall.Stat_t)
	if after.Mode().Perm() != 0600 {
		t.Fatalf("retired whitelist mode = %#o, want 0600", after.Mode().Perm())
	}
	if beforeOwner.Uid != afterOwner.Uid || beforeOwner.Gid != afterOwner.Gid {
		t.Fatalf("retired whitelist owner = %d:%d, want %d:%d", afterOwner.Uid, afterOwner.Gid, beforeOwner.Uid, beforeOwner.Gid)
	}

	changed, err = retireLegacyMetadataWhitelistEntryAt(target)
	if err != nil || changed {
		t.Fatalf("idempotent retirement = (%t, %v), want (false, nil)", changed, err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(after, second) {
		t.Fatal("idempotent retirement replaced an unchanged whitelist")
	}
}

func TestLegacyMetadataWhitelistRetirementRejectsSymlink_SW_SEC_M1(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "whitelist.ipv4"}
	outside := filepath.Join(directory, "outside")
	fixture := []byte(legacyMetadataWhitelistIPv4 + "\nkeep\n")
	if err := os.WriteFile(outside, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("outside", filepath.Join(directory, target.name)); err != nil {
		t.Fatal(err)
	}
	changed, err := retireLegacyMetadataWhitelistEntryAt(target)
	if err == nil || changed {
		t.Fatalf("symlink retirement = (%t, %v), want (false, error)", changed, err)
	}
	content, readErr := readBoundedRegularTestFile(directory, "outside")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(content, fixture) {
		t.Fatalf("symlink target changed: %q", content)
	}
}

func TestLegacyMetadataWhitelistRetirementRejectsPublicationRace_SW_SEC_M1(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "whitelist.ipv4"}
	path := filepath.Join(directory, target.name)
	if err := os.WriteFile(path, []byte(legacyMetadataWhitelistIPv4+"\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	peerUpdate := []byte("# concurrent operator update\n8.8.4.4\n")
	changed, err := retireLegacyMetadataWhitelistEntryAtBeforeRename(target, func() error {
		return os.WriteFile(path, peerUpdate, 0600)
	})
	if err == nil || changed {
		t.Fatalf("racing retirement = (%t, %v), want (false, error)", changed, err)
	}
	if !strings.Contains(err.Error(), "changed before publication") {
		t.Fatalf("racing retirement error = %v", err)
	}
	content, readErr := readBoundedRegularTestFile(directory, target.name)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(content, peerUpdate) {
		t.Fatalf("racing retirement replaced peer update: %q", content)
	}
	entries, readDirErr := os.ReadDir(directory)
	if readDirErr != nil {
		t.Fatal(readDirErr)
	}
	if len(entries) != 1 || entries[0].Name() != target.name {
		t.Fatalf("racing retirement left staging residue: %#v", entries)
	}
}

func TestWhitelistCandidateProducersExcludeMetadataAndCanonicalize_SW_SEC_M1(t *testing.T) {
	autoIPv4, autoIPv6 := automaticWhitelistCandidates(
		"198.51.100.9",
		true,
		[]string{"8.8.8.8", legacyMetadataWhitelistIPv4, "10.0.0.1", "8.8.8.8"},
		[]string{"2001:0db8::1", legacyMetadataWhitelistIPv4, "203.0.113.10"},
	)
	if want := []string{"198.51.100.9", "8.8.8.8", "10.0.0.1", "203.0.113.10"}; !reflect.DeepEqual(autoIPv4, want) {
		t.Fatalf("automatic IPv4 candidates = %#v, want %#v", autoIPv4, want)
	}
	if want := []string{"2001:db8::1"}; !reflect.DeepEqual(autoIPv6, want) {
		t.Fatalf("automatic IPv6 candidates = %#v, want %#v", autoIPv6, want)
	}

	infra := whitelistInfraIPv4Candidates(
		"198.51.100.9",
		[]string{"8.8.4.4", legacyMetadataWhitelistIPv4},
		[]string{"10.0.0.1", legacyMetadataWhitelistIPv4, "8.8.4.4"},
	)
	if want := []string{"198.51.100.9", "8.8.4.4", "10.0.0.1"}; !reflect.DeepEqual(infra, want) {
		t.Fatalf("infrastructure IPv4 candidates = %#v, want %#v", infra, want)
	}
	for _, candidates := range [][]string{autoIPv4, autoIPv6, infra} {
		for _, candidate := range candidates {
			if candidate == legacyMetadataWhitelistIPv4 {
				t.Fatalf("producer retained legacy metadata candidate in %#v", candidates)
			}
		}
	}
}

func TestLegacyMetadataRemainsRejectedByStrictFirewallListParser_SW_SEC_M1(t *testing.T) {
	if canonical, isIPv4, err := canonicalFirewallListNetwork(legacyMetadataWhitelistIPv4); err == nil {
		t.Fatalf("strict parser accepted metadata address as (%q, %t)", canonical, isIPv4)
	}
	if valid, isIPv4 := IsValidIP(legacyMetadataWhitelistIPv4); valid || isIPv4 {
		t.Fatalf("IsValidIP(metadata) = (%t, %t), want (false, false)", valid, isIPv4)
	}
}

func TestWhitelistInfraAppliesPoliciesWhenOnlyLegacyMetadataWasRetired_SW_SEC_M1(t *testing.T) {
	calls := 0
	apply := func() error {
		calls++
		return nil
	}
	if err := applyWhitelistInfraChanges(false, true, apply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("ApplyPolicies calls = %d, want 1", calls)
	}

	sentinel := errors.New("synthetic apply failure")
	if err := applyWhitelistInfraChanges(false, true, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("ApplyPolicies failure = %v, want sentinel", err)
	}
	if err := applyWhitelistInfraChanges(false, false, apply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("unchanged path ApplyPolicies calls = %d, want 1", calls)
	}
}
