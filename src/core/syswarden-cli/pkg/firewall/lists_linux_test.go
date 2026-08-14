//go:build linux

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPopulateSetListGrammarContract_SW_LIST_001(t *testing.T) {
	root := t.TempDir()
	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolDir, 0750); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "nft.log")
	fakeNft := filepath.Join(toolDir, "nft")
	fakeCommand := `#!/bin/sh
printf 'ARGS:%s\n' "$*" >> "$SYSWARDEN_NFT_TEST_LOG"
/bin/cat >> "$SYSWARDEN_NFT_TEST_LOG"
`
	if err := os.WriteFile(fakeNft, []byte(fakeCommand), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fakeNft, 0700); err != nil { // #nosec G302 -- the owner-only fake nft command must be executable during this test
		t.Fatal(err)
	}
	t.Setenv("PATH", toolDir)
	t.Setenv("SYSWARDEN_NFT_TEST_LOG", logPath)

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

	populateSet(context.Background(), []string{listPath}, "fixture_set")
	populateSet(context.Background(), []string{listPath}, "fixture_set6")
	got, err := os.ReadFile(logPath) // #nosec G304 -- logPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	want := `ARGS:-f -
add element netdev syswarden_hw_drop fixture_set {` + " " + `
192.0.2.10,
198.51.100.0/24
 }
ARGS:-f -
add element inet syswarden fixture_set { 192.0.2.10, 198.51.100.0/24 }
ARGS:-f -
add element netdev syswarden_hw_drop fixture_set6 {` + " " + `
2001:db8::10,
2001:db8:1::/48
 }
ARGS:-f -
add element inet syswarden fixture_set6 { 2001:db8::10, 2001:db8:1::/48 }
`
	if string(got) != want {
		t.Fatalf("list-to-nft contract changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}
