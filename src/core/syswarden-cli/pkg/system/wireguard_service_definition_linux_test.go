//go:build linux

package system

import (
	"crypto/sha1" // #nosec G505 -- test fixture mirrors APK v2 Q1 records
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openRCWireGuardFixture(t *testing.T) (openRCWireGuardDefinitionPaths, string, string, string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"lib/apk/db", "etc/init.d"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
			t.Fatal(err)
		}
	}
	scriptPath := filepath.Join(root, "etc/init.d/wg-quick")
	script := []byte("#!/sbin/openrc-run\ncommand=/usr/bin/wg-quick\n")
	if err := os.WriteFile(scriptPath, script, 0755); err != nil {
		t.Fatal(err)
	}
	checksum := sha1.Sum(script) // #nosec G401 -- fixture mirrors APK package metadata
	database := strings.Join([]string{
		"C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"P:wireguard-tools-openrc",
		"V:1.0-r0",
		"F:etc/init.d",
		"R:wg-quick",
		"a:0:0:755",
		"Z:Q1" + base64.StdEncoding.EncodeToString(checksum[:]),
		"",
		"C:Q1BBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		"P:unrelated-package",
		"V:1.0-r0",
		"",
	}, "\n")
	databasePath := filepath.Join(root, "lib/apk/db/installed")
	if err := os.WriteFile(databasePath, []byte(database), 0644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(root, "etc/init.d/wg-quick.wg-syswarden")
	if err := os.Symlink("/etc/init.d/wg-quick", linkPath); err != nil {
		t.Fatal(err)
	}
	return openRCWireGuardDefinitionPaths{
		root: root, expectedUID: uint32(os.Geteuid()), expectedGID: uint32(os.Getegid()),
	}, databasePath, scriptPath, linkPath
}

func TestAttestOpenRCWireGuardDefinitionRequiresExactAPKProof_SW2_FWBACKEND_001(t *testing.T) {
	paths, _, _, _ := openRCWireGuardFixture(t)
	if err := attestOpenRCWireGuardDefinitionWith(paths); err != nil {
		t.Fatal(err)
	}
}

func TestAttestOpenRCWireGuardDefinitionRejectsAdversarialEvidence_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, string, string)
	}{
		{
			name: "modified script",
			mutate: func(t *testing.T, _, script, _ string) {
				if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong script mode",
			mutate: func(t *testing.T, _, script, _ string) {
				if err := os.Chmod(script, 0775); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate package record",
			mutate: func(t *testing.T, database, _, _ string) {
				content, err := os.ReadFile(database)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(database, append(content, content...), 0644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ambiguous file tuple",
			mutate: func(t *testing.T, database, _, _ string) {
				content, err := os.ReadFile(database)
				if err != nil {
					t.Fatal(err)
				}
				content = []byte(strings.Replace(
					string(content),
					"R:wg-quick\na:0:0:755",
					"R:wg-quick\na:0:0:755\nR:wg-quick\na:0:0:755",
					1,
				))
				if err := os.WriteFile(database, content, 0644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "writable package database",
			mutate: func(t *testing.T, database, _, _ string) {
				if err := os.Chmod(database, 0664); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "lookalike service target",
			mutate: func(t *testing.T, _, _, link string) {
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/init.d/wg-quick.backup", link); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "script symlink",
			mutate: func(t *testing.T, _, script, _ string) {
				backup := script + ".owned"
				if err := os.Rename(script, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup, script); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths, database, script, link := openRCWireGuardFixture(t)
			test.mutate(t, database, script, link)
			if err := attestOpenRCWireGuardDefinitionWith(paths); err == nil {
				t.Fatal("unsafe OpenRC WireGuard definition was accepted")
			}
		})
	}
}

func TestAPKOpenRCWireGuardChecksumRejectsNonCanonicalQ1_SW2_FWBACKEND_001(t *testing.T) {
	for _, replacement := range []string{
		"a:1:0:755",
		"Z:Q2AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"Z:Q1not-base64",
	} {
		t.Run(replacement[:1], func(t *testing.T) {
			record := strings.Join([]string{
				"P:wireguard-tools-openrc",
				"F:etc/init.d",
				"R:wg-quick",
				"a:0:0:755",
				"Z:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"",
			}, "\n")
			if strings.HasPrefix(replacement, "a:") {
				record = strings.Replace(record, "a:0:0:755", replacement, 1)
			} else {
				record = strings.Replace(record, "Z:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=", replacement, 1)
			}
			if _, err := apkOpenRCWireGuardChecksum([]byte(record)); err == nil {
				t.Fatalf("accepted noncanonical tuple %q", replacement)
			}
		})
	}
}
