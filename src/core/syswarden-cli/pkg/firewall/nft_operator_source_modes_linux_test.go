//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"testing"
)

func TestNFTOperatorPreservationKeepsSupportedConfigurationModes(t *testing.T) {
	for _, mode := range []fs.FileMode{0600, 0640} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			ctx := context.Background()
			initial, _ := fixtureNFTOperatorPreservation(t)
			path := nftOperatorConfigurationPath[1:]
			if err := initial.host.root.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			before, err := initial.host.root.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			content, err := initial.host.read(nftOperatorConfigurationPath)
			if err != nil {
				t.Fatal(err)
			}
			inspection, err := inspectNFTOperatorPreservationUsing(ctx, initial.host, initial.dependencies)
			if err != nil {
				t.Fatalf("supported configuration mode %04o refused: %v", mode, err)
			}
			approveNFTOperatorFixture(t, inspection)
			if err := inspection.authorize(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := initial.host.root.Stat(path)
			if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != mode {
				t.Fatal("preservation changed the administrator file identity or mode", err)
			}
			current, err := initial.host.read(nftOperatorConfigurationPath)
			if err != nil || !bytes.Equal(content, current) {
				t.Fatal("preservation changed the administrator source", err)
			}
			changed := fs.FileMode(0600)
			if mode == 0600 {
				changed = 0640
			}
			if err := initial.host.root.Chmod(path, changed); err != nil {
				t.Fatal(err)
			}
			if err := inspection.authorize(ctx); err == nil {
				t.Fatal("mode drift after review was accepted")
			}
		})
	}
}

func TestNFTOperatorPreservationDoesNotBroadenReceiverOrWriterModes(t *testing.T) {
	for _, kind := range []string{"receiver", "product-source", "public-configuration"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			initial, _ := fixtureNFTOperatorPreservation(t)
			path, mode := nftOperatorReceiverPath(initial.model), fs.FileMode(0640)
			if kind == "product-source" {
				path = legacyNFTIncludePath
			}
			if kind == "public-configuration" {
				path, mode = nftOperatorConfigurationPath, 0644
			}
			if err := initial.host.root.Chmod(path[1:], mode); err != nil {
				t.Fatal(err)
			}
			inspection, err := inspectNFTOperatorPreservationUsing(ctx, initial.host, initial.dependencies)
			if err == nil {
				_, err = inspection.plan(ctx)
			}
			if err == nil {
				t.Fatal("unsupported source mode accepted", kind)
			}
		})
	}
}
