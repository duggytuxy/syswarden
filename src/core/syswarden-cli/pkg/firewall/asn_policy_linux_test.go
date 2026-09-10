//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func writeASNPolicyFixture(t *testing.T, directory, base, ipv4, ipv6 string) {
	t.Helper()
	for suffix, content := range map[string]string{
		".ipv4":       ipv4,
		".ipv6":       ipv6,
		".policy-pin": fmt.Sprintf("%slist_base=%s\nipv4_sha256=%x\nipv6_sha256=%x\n", asnPolicyPinHeader, base, sha256.Sum256([]byte(ipv4)), sha256.Sum256([]byte(ipv6))),
	} {
		if err := os.WriteFile(filepath.Join(directory, base+suffix), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExplicitASNPolicyPinsPreserveBroadRoutes(t *testing.T) {
	directory := t.TempDir()
	base := "allowed_AS16276"
	ipv4 := "51.38.0.0/16\n51.38.0.0/24\n"
	ipv6 := "2607:5300::/32\n2607:5300:600::/40\n"
	writeASNPolicyFixture(t, directory, base, ipv4, ipv6)
	v4, v6, err := configuredASNNftSources(directory, "AS16276", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		sources   []nftListSource
		set, want string
	}{
		{v4, "syswarden_zt_allowed", "51.38.0.0-51.38.255.255"},
		{v6, "syswarden_zt_allowed6", "2607:5300::/32"},
	} {
		got, err := populateSet(context.Background(), test.sources, test.set)
		if err != nil || !reflect.DeepEqual(got.entries, []string{test.want}) {
			t.Fatalf("pinned population = %#v, %v", got.entries, err)
		}
	}
	// The same files remain subject to the generic floor outside configured ASN
	// selection; an adjacent pin cannot authorize a generic allow or block list.
	if _, err := populateSet(context.Background(), []nftListSource{{path: filepath.Join(directory, base+".ipv6"), required: true}}, "syswarden_blacklist6"); err == nil || !strings.Contains(err.Error(), "broader than /64") {
		t.Fatalf("generic list floor changed: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, base+".policy-pin")); err != nil {
		t.Fatal(err)
	}
	_, v6, err = configuredASNNftSources(directory, "AS16276", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := populateSet(context.Background(), v6, "syswarden_zt_allowed6"); err == nil || !strings.Contains(err.Error(), "broader than /64") {
		t.Fatalf("unpinned configured ASN bypassed the floor: %v", err)
	}
}

func TestASNPolicyPinsRejectChangedPairAndPurpose(t *testing.T) {
	for _, mutation := range []string{"ipv4", "ipv6", "missing-ipv6", "wrong-purpose", "uppercase-digest", "extra-line", "duplicate-field", "partial-pin"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			base := "allowed_AS16276"
			writeASNPolicyFixture(t, dir, base, "51.38.0.0/16\n", "2607:5300::/32\n")
			pin := filepath.Join(dir, base+".policy-pin")
			content, err := os.ReadFile(pin)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "ipv4", "ipv6":
				if err := os.WriteFile(filepath.Join(dir, base+"."+mutation), []byte("8.8.8.0/24\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-ipv6":
				if err := os.Remove(filepath.Join(dir, base+".ipv6")); err != nil {
					t.Fatal(err)
				}
			case "wrong-purpose":
				content = []byte(strings.Replace(string(content), "list_base=allowed_AS16276", "list_base=AS16276", 1))
			case "uppercase-digest":
				content = []byte(strings.ToUpper(string(content)))
			case "extra-line":
				content = append(content, '\n')
			case "duplicate-field":
				content = append(content, []byte("ipv4_sha256="+strings.Repeat("0", 64)+"\n")...)
			case "partial-pin":
				content = []byte(asnPolicyPinHeader)
			}
			if err := os.WriteFile(pin, content, 0600); err != nil {
				t.Fatal(err)
			}
			if v4, v6, err := configuredASNNftSources(dir, "AS16276", true); err == nil || len(v4)+len(v6) != 0 {
				t.Fatalf("invalid pair produced sources: %#v %#v %v", v4, v6, err)
			}
		})
	}
}

func TestASNPolicyPinsRecheckBytesAtPopulation(t *testing.T) {
	dir := t.TempDir()
	base := "AS16276"
	writeASNPolicyFixture(t, dir, base, "51.38.0.0/16\n", "2607:5300::/32\n")
	v4, _, err := configuredASNNftSources(dir, "AS16276", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".ipv4"), []byte("51.39.0.0/16\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := populateSet(context.Background(), v4, "syswarden_asn")
	if err == nil || len(got.entries) != 0 || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed bytes accepted: %#v %v", got, err)
	}
}

func TestASNPolicyPinsRejectUnsafeFilesystem(t *testing.T) {
	for _, suffix := range []string{".policy-pin", ".ipv4", ".ipv6"} {
		for _, mutation := range []string{"symlink", "hardlink", "fifo", "mode", "directory"} {
			t.Run(suffix+"/"+mutation, func(t *testing.T) {
				dir := t.TempDir()
				base := "allowed_AS16276"
				writeASNPolicyFixture(t, dir, base, "51.38.0.0/16\n", "2607:5300::/32\n")
				path := filepath.Join(dir, base+suffix)
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				var err error
				switch mutation {
				case "symlink":
					err = os.Symlink(path+".original", path)
				case "hardlink":
					err = os.Link(path+".original", path)
				case "fifo":
					err = syscall.Mkfifo(path, 0600)
				case "directory":
					err = os.Mkdir(path, 0700)
				case "mode":
					err = os.Rename(path+".original", path)
					if err == nil {
						err = os.Chmod(path, 0644)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := configuredASNNftSources(dir, "AS16276", true); err == nil {
					t.Fatal("unsafe file accepted")
				}
			})
		}
	}
}

func TestPinnedASNStillRejectsUnsafeNetworks(t *testing.T) {
	for _, route := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "169.254.0.0/16", "192.0.2.0/24", "2001:db8::/32", "fc00::/7", "ff00::/8", "::ffff:8.8.8.0/120", "51.38.0.1/16", "51.38.0.0/16:443", "8.8.8.8"} {
		t.Run(route, func(t *testing.T) {
			if _, _, err := canonicalPinnedASNNetwork(route, strings.Contains(route, ":")); err == nil {
				t.Fatalf("unsafe route accepted: %s", route)
			}
		})
	}
	if _, _, err := canonicalPinnedASNNetwork("2607:5300::/32", false); err == nil {
		t.Fatal("wrong family accepted")
	}
}

func TestASNPolicyPinsEnforceBoundsAndTrustSeparation(t *testing.T) {
	dir := t.TempDir()
	base := "allowed_AS16276"
	writeASNPolicyFixture(t, dir, base, strings.Repeat("51.38.0.0/16\n", maximumPinnedASNPrefixes+1), "2607:5300::/32\n")
	v4, _, err := configuredASNNftSources(dir, "AS16276", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := populateSet(context.Background(), v4, "syswarden_zt_allowed"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unbounded route count: %v", err)
	}
	v4[0].attested = true
	if _, err := readNFTListSource(v4[0]); err == nil || !strings.Contains(err.Error(), "cannot replace") {
		t.Fatalf("ASN pin replaced threat-feed attestation: %v", err)
	}
	writeASNPolicyFixture(t, dir, base, strings.Repeat(" ", maximumPinnedASNBytes+1), "2607:5300::/32\n")
	if _, _, err := configuredASNNftSources(dir, "AS16276", true); err == nil {
		t.Fatal("oversized approved list accepted")
	}
}

func TestASNPolicyPinsRejectSymlinkedOrWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	writeASNPolicyFixture(t, dir, "allowed_AS16276", "51.38.0.0/16\n", "2607:5300::/32\n")
	link := filepath.Join(t.TempDir(), "lists")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configuredASNNftSources(link, "AS16276", true); err == nil {
		t.Fatal("symlinked list directory accepted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configuredASNNftSources(dir, "AS16276", true); err == nil {
		t.Fatal("writable list directory accepted")
	}
}
