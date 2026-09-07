package firewall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCompleteBlocklistRemovalStopsBeforeHASyncWhenFirewallApplyFails(t *testing.T) {
	applyErr := errors.New("nft verification failed")
	var output bytes.Buffer
	var calls []string

	err := completeBlocklistRemoval(
		"198.51.100.7",
		&output,
		func(ip string) error {
			if ip != "198.51.100.7" {
				t.Fatalf("firewall removal target = %q", ip)
			}
			calls = append(calls, "apply")
			return applyErr
		},
		func(ips []string) error {
			calls = append(calls, "sync:"+strings.Join(ips, ","))
			return errors.New("HA synchronization must not run")
		},
	)

	if !errors.Is(err, applyErr) {
		t.Fatalf("completeBlocklistRemoval() error = %v, want apply failure", err)
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
	wantCalls := []string{"apply"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("operation calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestCompleteBlocklistRemovalReportsSuccessOnlyAfterVerificationAndHASync(t *testing.T) {
	var output bytes.Buffer
	var calls []string

	err := completeBlocklistRemoval(
		"2001:db8::7",
		&output,
		func(ip string) error {
			if ip != "2001:db8::7" {
				t.Fatalf("firewall removal target = %q", ip)
			}
			if output.Len() != 0 {
				t.Fatal("success was reported before firewall verification")
			}
			calls = append(calls, "apply")
			return nil
		},
		func(ips []string) error {
			if output.Len() != 0 {
				t.Fatal("success was reported before HA synchronization")
			}
			calls = append(calls, "sync:"+strings.Join(ips, ","))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("completeBlocklistRemoval() error = %v", err)
	}
	wantCalls := []string{"apply", "sync:2001:db8::7"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("operation calls = %#v, want %#v", calls, wantCalls)
	}
	if got := output.String(); got != "[SUCCESS] IP 2001:db8::7 removed from blocklist.\n" {
		t.Fatalf("success output = %q", got)
	}
}

func TestPortScopedWhitelistPreservesGlobalBlocksAndRollsBackAbsentFile(t *testing.T) {
	directory := t.TempDir()
	whitelist := approvedListFile{directory: directory, name: "whitelist"}
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	originalBlocklist := []byte("51.195.135.163\n8.8.8.8\n")
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), originalBlocklist, 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("51.195.135.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	applyErr := errors.New("nft verification failed")
	var output bytes.Buffer
	normalCalls := 0
	unbanCalls := 0

	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error {
			normalCalls++
			if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || !bytes.Equal(got, originalBlocklist) { // #nosec G304 -- path is a fixed test list beneath t.TempDir
				t.Fatalf("port-scoped whitelist changed global blocklist: content=%q error=%v", got, readErr)
			}
			if got, readErr := os.ReadFile(filepath.Join(directory, whitelist.name)); readErr != nil || string(got) != "51.195.135.163:443\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
				t.Fatalf("port-scoped candidate content=%q error=%v", got, readErr)
			}
			return applyErr
		},
		func(string) error {
			unbanCalls++
			return errors.New("global dynamic unban must not run")
		},
	)

	if !errors.Is(err, applyErr) {
		t.Fatalf("addToWhitelistAt() error = %v, want apply failure", err)
	}
	if normalCalls != 1 || unbanCalls != 0 {
		t.Fatalf("apply calls normal/unban = %d/%d, want 1/0", normalCalls, unbanCalls)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || !bytes.Equal(got, originalBlocklist) { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("global blocklist after rollback=%q error=%v", got, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, whitelist.name)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction-created whitelist was not removed: %v", statErr)
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
}

func TestGlobalWhitelistRestoresPresentFilesWhenDynamicUnbanFails(t *testing.T) {
	directory := t.TempDir()
	whitelist := approvedListFile{directory: directory, name: "whitelist"}
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	originalWhitelist := []byte("1.1.1.1\n")
	originalBlocklist := []byte("# retained exactly\n51.195.135.163\n8.8.8.8\n")
	if err := os.WriteFile(filepath.Join(directory, whitelist.name), originalWhitelist, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), originalBlocklist, 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("51.195.135.163", "")
	if err != nil {
		t.Fatal(err)
	}
	applyErr := errors.New("nft verification failed")
	var output bytes.Buffer

	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error { return errors.New("plain apply must not run") },
		func(network string) error {
			if network != entry.network {
				t.Fatalf("dynamic unban target = %q", network)
			}
			return applyErr
		},
	)
	if !errors.Is(err, applyErr) {
		t.Fatalf("addToWhitelistAt() error = %v, want apply failure", err)
	}
	for _, state := range []struct {
		target approvedListFile
		want   []byte
	}{{whitelist, originalWhitelist}, {blocklist, originalBlocklist}} {
		got, readErr := os.ReadFile(filepath.Join(directory, state.target.name)) // #nosec G304 -- path is a fixed test list beneath t.TempDir
		if readErr != nil || !bytes.Equal(got, state.want) {
			t.Fatalf("restored %s=%q error=%v, want %q", state.target.name, got, readErr, state.want)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
}

func TestWhitelistRollbackRefusesConcurrentPersistentChange(t *testing.T) {
	directory := t.TempDir()
	whitelist := approvedListFile{directory: directory, name: "whitelist"}
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	original := []byte("8.8.8.8\n")
	concurrent := []byte("8.8.8.8\n9.9.9.9\n")
	if err := os.WriteFile(filepath.Join(directory, whitelist.name), original, 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("51.195.135.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error {
			if writeErr := os.WriteFile(filepath.Join(directory, whitelist.name), concurrent, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			return errors.New("apply failed")
		},
		func(string) error { return errors.New("global dynamic unban must not run") },
	)
	if err == nil || !strings.Contains(err.Error(), "refuse to overwrite list target changed before rollback") {
		t.Fatalf("concurrent rollback error = %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(directory, whitelist.name)) // #nosec G304 -- path is a fixed test list beneath t.TempDir
	if readErr != nil || !bytes.Equal(got, concurrent) {
		t.Fatalf("concurrent content was overwritten: content=%q error=%v", got, readErr)
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
}

func TestRemoveFromBlocklistRollsBackApplyFailureAndKeepsLocalCommitOnHAFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		applyFail bool
		haFail    bool
		present   bool
	}{
		{name: "apply failure with prior file", applyFail: true, present: true},
		{name: "apply failure with absent file", applyFail: true},
		{name: "HA failure with prior file", haFail: true, present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := approvedListFile{directory: directory, name: "blocklist"}
			original := []byte("# exact bytes\ninvalid legacy entry\n51.195.135.163\n8.8.8.8\n")
			if test.present {
				if err := os.WriteFile(filepath.Join(directory, target.name), original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			applyCalls := 0
			syncCalls := 0
			err := removeFromBlocklistAt(
				"51.195.135.163",
				target,
				[]approvedListFile{target},
				&output,
				func(network string) error {
					applyCalls++
					if network != "51.195.135.163" {
						t.Fatalf("dynamic unban target = %q", network)
					}
					if test.applyFail {
						return errors.New("apply failed")
					}
					return nil
				},
				func(networks []string) error {
					syncCalls++
					if !reflect.DeepEqual(networks, []string{"51.195.135.163"}) {
						t.Fatalf("HA unban targets = %#v", networks)
					}
					if test.haFail {
						return errors.New("HA failed")
					}
					return nil
				},
			)
			if err == nil {
				t.Fatal("failure unexpectedly succeeded")
			}
			if applyCalls != 1 || syncCalls != boolInt(!test.applyFail) {
				t.Fatalf("apply/sync calls = %d/%d", applyCalls, syncCalls)
			}
			path := filepath.Join(directory, target.name)
			if test.present {
				want := original
				if test.haFail {
					want = []byte("# exact bytes\n8.8.8.8\n")
					if !strings.Contains(err.Error(), "local firewall and persistent blocklist changes are committed") {
						t.Fatalf("HA failure did not report local commit: %v", err)
					}
				}
				got, readErr := os.ReadFile(path) // #nosec G304 -- path is a fixed test list beneath t.TempDir
				if readErr != nil || !bytes.Equal(got, want) {
					t.Fatalf("blocklist after failure=%q error=%v, want %q", got, readErr, want)
				}
			} else if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("absent blocklist state changed: %v", statErr)
			}
			if output.Len() != 0 {
				t.Fatalf("failure emitted a false-success message: %q", output.String())
			}
		})
	}
}

func TestRemoveFromBlocklistRollbackRefusesConcurrentPersistentChange(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "blocklist"}
	if err := os.WriteFile(filepath.Join(directory, target.name), []byte("51.195.135.163\n"), 0600); err != nil {
		t.Fatal(err)
	}
	concurrent := []byte("9.9.9.9\n")
	var output bytes.Buffer
	err := removeFromBlocklistAt(
		"51.195.135.163",
		target,
		nil,
		&output,
		func(string) error {
			if writeErr := os.WriteFile(filepath.Join(directory, target.name), concurrent, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			return errors.New("apply failed")
		},
		func([]string) error { return errors.New("HA must not run") },
	)
	if err == nil || !strings.Contains(err.Error(), "refuse to overwrite list target changed before rollback") {
		t.Fatalf("concurrent rollback error = %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(directory, target.name)) // #nosec G304 -- path is a fixed test list beneath t.TempDir
	if readErr != nil || !bytes.Equal(got, concurrent) {
		t.Fatalf("concurrent content was overwritten: content=%q error=%v", got, readErr)
	}
	if output.Len() != 0 {
		t.Fatalf("failure emitted a false-success message: %q", output.String())
	}
}

func TestTransactionalListSnapshotsRejectSymlinksAndOversizedFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		victim := filepath.Join(directory, "victim")
		original := []byte("8.8.8.8\n")
		if err := os.WriteFile(victim, original, 0600); err != nil {
			t.Fatal(err)
		}
		target := approvedListFile{directory: directory, name: "whitelist"}
		if err := os.Symlink(victim, filepath.Join(directory, target.name)); err != nil {
			t.Fatal(err)
		}
		mutation, err := addToListFileTransactionally(target, "51.195.135.163")
		if err == nil || mutation.changed {
			t.Fatalf("symlink mutation = %#v, error = %v", mutation, err)
		}
		got, readErr := os.ReadFile(victim) // #nosec G304 -- victim is a fixed test file beneath t.TempDir
		if readErr != nil || !bytes.Equal(got, original) {
			t.Fatalf("symlink victim changed: content=%q error=%v", got, readErr)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		directory := t.TempDir()
		target := approvedListFile{directory: directory, name: "blocklist"}
		path := filepath.Join(directory, target.name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- path is a fixed test list beneath t.TempDir
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maximumTransactionalListSnapshotBytes + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		mutation, err := removeFromListFileTransactionally(target, "51.195.135.163")
		if err == nil || mutation.changed || !strings.Contains(err.Error(), "snapshot limit") {
			t.Fatalf("oversized mutation = %#v, error = %v", mutation, err)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Size() != maximumTransactionalListSnapshotBytes+1 {
			t.Fatalf("oversized target changed: size=%d", info.Size())
		}
	})
}

func TestTransactionalListRollbackRejectsSameDigestReplacement(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "whitelist"}
	path := filepath.Join(directory, target.name)
	if err := os.WriteFile(path, []byte("8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mutation, err := addToListFileTransactionally(target, "51.195.135.163")
	if err != nil || !mutation.changed {
		t.Fatalf("transactional mutation = %#v, error = %v", mutation, err)
	}
	candidate, err := os.ReadFile(path) // #nosec G304 -- path is a fixed test list beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, candidate, 0600); err != nil { // #nosec G703 -- replacement is a fixed test filename beneath t.TempDir
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	err = rollbackTransactionalListMutation(mutation)
	if err == nil || !strings.Contains(err.Error(), "refuse to overwrite") {
		t.Fatalf("same-digest replacement rollback error = %v", err)
	}
	currentInfo, statErr := os.Stat(path)
	got, readErr := os.ReadFile(path) // #nosec G304 -- path is a fixed test list beneath t.TempDir
	if statErr != nil || readErr != nil || !os.SameFile(replacementInfo, currentInfo) || !bytes.Equal(got, candidate) {
		t.Fatalf("same-digest replacement was overwritten: content=%q stat=%v read=%v", got, statErr, readErr)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
