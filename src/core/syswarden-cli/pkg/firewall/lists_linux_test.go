//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestPopulateSetListGrammarContract_SW_LIST_001(t *testing.T) {
	root := t.TempDir()
	listPath := filepath.Join(root, "mixed.list")
	content := `# Full-line comments are ignored.

192.0.2.10
198.51.100.0/24
2001:db8::10
2001:db8:1::/48
192.0.2.11:443
192.0.2.12 # inline comments are not part of the accepted grammar
invalid.example
`
	if err := os.WriteFile(listPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := populateSet(context.Background(), []nftListSource{{path: listPath, required: true}}, "fixture_set")
	if err == nil {
		t.Fatal("mixed-family and malformed entries must be rejected instead of silently filtered")
	}

	ipv4Path := filepath.Join(root, "fixture.ipv4")
	if err := os.WriteFile(ipv4Path, []byte("192.0.2.10\n198.51.100.0/24\n192.0.2.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	population, err := populateSet(context.Background(), []nftListSource{{path: ipv4Path, required: true}}, "fixture_set")
	if err != nil {
		t.Fatalf("populateSet() rejected a valid IPv4 list: %v", err)
	}
	want := []string{"192.0.2.10", "198.51.100.0/24"}
	if !reflect.DeepEqual(population.entries, want) {
		t.Fatalf("parsed entries = %#v, want %#v", population.entries, want)
	}
}

func TestPopulateSetNormalizesAutoMergeIntervals_SW_FW_002(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{name: "overlapping prefix and address", content: "192.0.2.0/24\n192.0.2.42\n", want: []string{"192.0.2.0/24"}},
		{name: "adjacent addresses", content: "198.51.100.1\n198.51.100.2\n", want: []string{"198.51.100.1-198.51.100.2"}},
		{name: "nested interval after another nested entry", content: "203.0.113.0/24\n203.0.113.1\n203.0.113.128/25\n", want: []string{"203.0.113.0/24"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ambiguous.ipv4")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			population, err := populateSet(
				context.Background(),
				[]nftListSource{{path: path, required: true}},
				"syswarden_blacklist",
			)
			if err != nil {
				t.Fatalf("populateSet() rejected a normalizable union: %v", err)
			}
			if !reflect.DeepEqual(population.entries, test.want) {
				t.Fatalf("normalized entries = %#v, want %#v", population.entries, test.want)
			}
		})
	}
}

func TestPopulateWhitelistPortSets_SW_LIST_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.ipv4")
	content := "192.0.2.1\n192.0.2.129/24:443\n192.0.2.0/24:0443\n192.0.2.42:443\n198.51.100.1:2222\n198.51.100.2:2222\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	addresses, ports, err := populateWhitelistSets(
		context.Background(),
		[]nftListSource{{path: path, required: true}},
		"syswarden_whitelist",
		"syswarden_whitelist_ports",
	)
	if err != nil {
		t.Fatalf("populateWhitelistSets() rejected valid entries: %v", err)
	}
	if want := []string{"192.0.2.1"}; !reflect.DeepEqual(addresses.entries, want) {
		t.Fatalf("address entries = %#v, want %#v", addresses.entries, want)
	}
	wantPorts := []string{"192.0.2.0/24 . 443", "198.51.100.1-198.51.100.2 . 2222"}
	if !reflect.DeepEqual(ports.entries, wantPorts) {
		t.Fatalf("port entries = %#v, want %#v", ports.entries, wantPorts)
	}
	if ports.kind != nftAddressPortPopulation {
		t.Fatalf("port population kind = %d", ports.kind)
	}
}

func TestPopulateWhitelistPortSetsNormalizesIPv6Overlap_SW_LIST_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.ipv6")
	content := "[2001:db8::/64]:443\n[2001:db8::10]:443\n[2001:db8:1::1]:8443\n[2001:db8:1::2]:8443\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	addresses, ports, err := populateWhitelistSets(
		context.Background(),
		[]nftListSource{{path: path, required: true}},
		"syswarden_whitelist6",
		"syswarden_whitelist_ports6",
	)
	if err != nil {
		t.Fatalf("populateWhitelistSets() rejected valid IPv6 overlap: %v", err)
	}
	if len(addresses.entries) != 0 {
		t.Fatalf("port-qualified IPv6 entries leaked into address set: %#v", addresses.entries)
	}
	want := []string{"2001:db8:1::1-2001:db8:1::2 . 8443", "2001:db8::/64 . 443"}
	if !reflect.DeepEqual(ports.entries, want) {
		t.Fatalf("normalized IPv6 port entries = %#v, want %#v", ports.entries, want)
	}
}

func TestPopulateHistoricalSSHBypassSets_SW_LIST_002(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_whitelist.txt")
	content := "192.0.2.129/24:2222\n192.0.2.0/24\n[2001:db8::10]:2222\n2001:db8::10\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err := populateSSHBypassSets(context.Background(), nftListSource{path: path}, "2222")
	if err != nil {
		t.Fatalf("populateSSHBypassSets() rejected valid historical entries: %v", err)
	}
	if want := []string{"192.0.2.0/24"}; !reflect.DeepEqual(ipv4.entries, want) {
		t.Fatalf("IPv4 SSH bypass = %#v, want %#v", ipv4.entries, want)
	}
	if want := []string{"2001:db8::10"}; !reflect.DeepEqual(ipv6.entries, want) {
		t.Fatalf("IPv6 SSH bypass = %#v, want %#v", ipv6.entries, want)
	}
	if !ipv4.inetOnly || !ipv6.inetOnly {
		t.Fatal("SSH bypass populations must remain scoped to the inet table")
	}

	if err := os.WriteFile(path, []byte("192.0.2.1\ninvalid.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = populateSSHBypassSets(context.Background(), nftListSource{path: path}, "2222")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid historical list error = %v", err)
	}
}

func TestHistoricalSSHBypassPortChangeFailsClosed_SW_LIST_002(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_whitelist.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1:2222\n[2001:db8::1]:2222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err := populateSSHBypassSets(context.Background(), nftListSource{path: path}, "2222")
	if err != nil || len(ipv4.entries) != 1 || len(ipv6.entries) != 1 {
		t.Fatalf("matching effective port was rejected: IPv4=%#v IPv6=%#v error=%v", ipv4.entries, ipv6.entries, err)
	}
	ipv4, ipv6, err = populateSSHBypassSets(context.Background(), nftListSource{path: path}, "22")
	if err == nil || !strings.Contains(err.Error(), "does not match the effective SSH port 22") {
		t.Fatalf("changed SSH port error = %v", err)
	}
	if len(ipv4.entries) != 0 || len(ipv6.entries) != 0 {
		t.Fatalf("mismatched qualified entries reached the candidate: IPv4=%#v IPv6=%#v", ipv4.entries, ipv6.entries)
	}

	if err := os.WriteFile(path, []byte("192.0.2.1\n2001:db8::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ipv4, ipv6, err = populateSSHBypassSets(context.Background(), nftListSource{path: path}, "22")
	if err != nil || len(ipv4.entries) != 1 || len(ipv6.entries) != 1 {
		t.Fatalf("unqualified legacy entries did not follow the effective SSH port: IPv4=%#v IPv6=%#v error=%v", ipv4.entries, ipv6.entries, err)
	}
}

func TestAddressPortAndSSHPopulationRendering_SW_LIST_001(t *testing.T) {
	rules, err := buildPopulationRules([]nftSetPopulation{
		{name: "syswarden_whitelist_ports", kind: nftAddressPortPopulation, entries: []string{"192.0.2.0-192.0.2.255 . 443"}},
		{name: "syswarden_ssh_bypass", inetOnly: true, entries: []string{"192.0.2.1"}},
	})
	if err != nil {
		t.Fatalf("buildPopulationRules() error: %v", err)
	}
	for _, fragment := range []string{
		"add element netdev syswarden_hw_drop syswarden_whitelist_ports { 192.0.2.0-192.0.2.255 . 443 }",
		"add element inet syswarden syswarden_whitelist_ports { 192.0.2.0-192.0.2.255 . 443 }",
		"add element inet syswarden syswarden_ssh_bypass { 192.0.2.1 }",
	} {
		if !strings.Contains(rules, fragment) {
			t.Fatalf("population rules missing %q:\n%s", fragment, rules)
		}
	}
	if strings.Contains(rules, "netdev syswarden_hw_drop syswarden_ssh_bypass") {
		t.Fatalf("SSH bypass leaked into the netdev table:\n%s", rules)
	}
	if _, err := canonicalNFTAddressPortExpression("192.0.2.1 . 22; drop table inet syswarden"); err == nil {
		t.Fatal("address and port renderer accepted an injected service")
	}
}

func TestNftListSnapshotCoordinatesAtomicPairPublication_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	reader, err := lockNftListSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if reader == nil {
		t.Fatal("existing list directory did not produce a snapshot lock")
	}
	defer unlockNftListSnapshot(reader)

	writerRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer writerRoot.Close()
	writer, err := writerRoot.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	err = syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(writer.Fd()), syscall.LOCK_UN)
		t.Fatal("exclusive pair publication lock bypassed the shared firewall snapshot")
	}
	if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		t.Fatalf("nonblocking publication lock error = %v", err)
	}
}

func TestSaaSMonitorSourcesRespectExplicitFalse_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	for _, allowed := range []bool{false, true} {
		ipv4, ipv6 := whitelistNftSources(directory, allowed)
		wantLength := 1
		if allowed {
			wantLength = 2
		}
		if len(ipv4) != wantLength || len(ipv6) != wantLength {
			t.Fatalf("allowSaaSMonitors=%t produced %d IPv4 and %d IPv6 sources, want %d each", allowed, len(ipv4), len(ipv6), wantLength)
		}
		for _, sources := range [][]nftListSource{ipv4, ipv6} {
			for _, source := range sources {
				if !allowed && strings.Contains(source.path, "saas_monitors") {
					t.Fatalf("explicit false retained stale SaaS source %s", source.path)
				}
			}
		}
	}
}

func TestValidateSaaSListPairFailsClosedOnPartialOrMismatchedState_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	present, err := validateSaaSListPair(directory)
	if err != nil || present {
		t.Fatalf("absent pair = (%t, %v), want (false, nil)", present, err)
	}
	ipv4 := []byte("192.0.2.1\n")
	ipv6 := []byte("2001:db8::1\n")
	if err := os.WriteFile(filepath.Join(directory, "syswarden_saas_monitors.ipv4"), ipv4, 0600); err != nil {
		t.Fatal(err)
	}
	if present, err = validateSaaSListPair(directory); err == nil || present {
		t.Fatalf("partial pair = (%t, %v), want fail-closed error", present, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "syswarden_saas_monitors.ipv6"), ipv6, 0600); err != nil {
		t.Fatal(err)
	}
	ipv4Digest := sha256.Sum256(ipv4)
	ipv6Digest := sha256.Sum256(ipv6)
	manifest := fmt.Sprintf("%s\nipv4_sha256=%x\nipv6_sha256=%x\n", saasPairManifestV1, ipv4Digest, ipv6Digest)
	if err := os.WriteFile(filepath.Join(directory, saasPairManifestFile), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = validateSaaSListPair(directory)
	if err != nil || !present {
		t.Fatalf("valid pair = (%t, %v), want (true, nil)", present, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "syswarden_saas_monitors.ipv6"), []byte("2001:db8::2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if present, err = validateSaaSListPair(directory); err == nil || present {
		t.Fatalf("mismatched pair = (%t, %v), want fail-closed error", present, err)
	}
}

func TestAdoptLegacySaaSIPv4OnlyPairDuringPackageUpgrade_SW_SAAS_001(t *testing.T) {
	directory := t.TempDir()
	ipv4Path := filepath.Join(directory, "syswarden_saas_monitors.ipv4")
	ipv6Path := filepath.Join(directory, "syswarden_saas_monitors.ipv6")
	manifestPath := filepath.Join(directory, saasPairManifestFile)
	ipv4 := []byte("192.0.2.10\n198.51.100.0/24")
	if err := os.WriteFile(ipv4Path, ipv4, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(saasLegacyAdoptionEnvironment, "")
	adopted, err := maybeAdoptLegacySaaSListPair(directory, true)
	if err != nil || adopted {
		t.Fatalf("non-package SaaS adoption = (%t, %v), want (false, nil)", adopted, err)
	}
	t.Setenv(saasLegacyAdoptionEnvironment, "1")

	adopted, err = maybeAdoptLegacySaaSListPair(directory, false)
	if err != nil || adopted {
		t.Fatalf("explicit SaaS false adoption = (%t, %v), want (false, nil)", adopted, err)
	}
	for _, path := range []string{ipv6Path, manifestPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("explicit false created %s: %v", path, err)
		}
	}

	adopted, err = maybeAdoptLegacySaaSListPair(directory, true)
	if err != nil || !adopted {
		t.Fatalf("legacy SaaS adoption = (%t, %v), want (true, nil)", adopted, err)
	}
	adoptionRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer adoptionRoot.Close()
	if content, err := adoptionRoot.ReadFile(filepath.Base(ipv4Path)); err != nil || string(content) != string(ipv4) {
		t.Fatalf("adoption changed legacy IPv4 bytes: %q, %v", content, err)
	}
	if content, err := adoptionRoot.ReadFile(filepath.Base(ipv6Path)); err != nil || len(content) != 0 {
		t.Fatalf("adopted IPv6 half = %q, %v, want empty", content, err)
	}
	wantManifest := renderSaaSPairManifest(ipv4, nil)
	if content, err := adoptionRoot.ReadFile(filepath.Base(manifestPath)); err != nil || string(content) != string(wantManifest) {
		t.Fatalf("adopted manifest = %q, %v, want %q", content, err, wantManifest)
	}
	for _, path := range []string{ipv4Path, ipv6Path, manifestPath} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("adopted component %s mode = %v", path, info.Mode())
		}
	}
	if present, err := validateSaaSListPair(directory); err != nil || !present {
		t.Fatalf("adopted pair validation = (%t, %v), want (true, nil)", present, err)
	}
	if adopted, err := maybeAdoptLegacySaaSListPair(directory, true); err != nil || adopted {
		t.Fatalf("idempotent adoption = (%t, %v), want (false, nil)", adopted, err)
	}
}

func TestAdoptLegacySaaSListRejectsUnsafeOrNonCanonicalState_SW_SAAS_001(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "non-canonical prefix",
			setup: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, "syswarden_saas_monitors.ipv4"), []byte("192.0.2.129/24"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe mode",
			setup: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, "syswarden_saas_monitors.ipv4"), []byte("192.0.2.1"), 0644); err != nil { // #nosec G306 -- deliberately permissive fixture verifies fail-closed legacy adoption
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink component",
			setup: func(t *testing.T, directory string) {
				t.Helper()
				victim := filepath.Join(directory, "victim")
				if err := os.WriteFile(victim, []byte("192.0.2.1"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(directory, "syswarden_saas_monitors.ipv4")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			test.setup(t, directory)
			if adopted, err := adoptLegacySaaSListPair(directory); err == nil || adopted {
				t.Fatalf("unsafe adoption = (%t, %v), want fail-closed error", adopted, err)
			}
			for _, name := range []string{"syswarden_saas_monitors.ipv6", saasPairManifestFile} {
				if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed adoption created %s: %v", name, err)
				}
			}
		})
	}
}
