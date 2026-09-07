//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertCommittedPersistentListError(t *testing.T, err, cause error) {
	t.Helper()
	if err == nil || !errors.Is(err, cause) {
		t.Fatalf("committed list mutation error = %v, want wrapped cause %v", err, cause)
	}
	for _, fragment := range []string{
		"local firewall and persistent list changes are committed",
		"post-commit reconciliation is incomplete",
		"compatibility wrapper reconciliation is incomplete",
		"0123456789abcdef",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("committed list mutation error %q omitted %q", err, fragment)
		}
	}
}

func TestCommittedWrapperErrorKeepsGlobalWhitelistFilesAlignedWithFirewall_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	whitelist := approvedListFile{directory: directory, name: "whitelist"}
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	if err := os.WriteFile(filepath.Join(directory, whitelist.name), []byte("1.1.1.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), []byte("# retained exactly\n51.195.135.163\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("51.195.135.163", "")
	if err != nil {
		t.Fatal(err)
	}
	wrapperErr := errors.New("compatibility wrapper failed")
	var output bytes.Buffer
	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error { return errors.New("port-scoped apply must not run") },
		func(string) error { return committedWrapperReconciliationError("0123456789abcdef", wrapperErr) },
	)
	assertCommittedPersistentListError(t, err, wrapperErr)
	if got, readErr := os.ReadFile(filepath.Join(directory, whitelist.name)); readErr != nil || string(got) != "1.1.1.1\n51.195.135.163\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("committed global whitelist = %q error=%v", got, readErr)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || string(got) != "# retained exactly\n8.8.8.8\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("committed global blocklist = %q error=%v", got, readErr)
	}
	if output.Len() != 0 {
		t.Fatalf("committed wrapper warning emitted false success: %q", output.String())
	}
}

func TestCommittedWrapperErrorKeepsPortScopedWhitelistAlignedWithFirewall_SW_FW_001(t *testing.T) {
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
	wrapperErr := errors.New("compatibility wrapper failed")
	var output bytes.Buffer
	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error { return committedWrapperReconciliationError("0123456789abcdef", wrapperErr) },
		func(string) error { return errors.New("global dynamic unban must not run") },
	)
	assertCommittedPersistentListError(t, err, wrapperErr)
	if got, readErr := os.ReadFile(filepath.Join(directory, whitelist.name)); readErr != nil || string(got) != "51.195.135.163:443\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("committed port-scoped whitelist = %q error=%v", got, readErr)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || !bytes.Equal(got, originalBlocklist) { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("port-scoped whitelist changed global blocklist: content=%q error=%v", got, readErr)
	}
	if output.Len() != 0 {
		t.Fatalf("committed wrapper warning emitted false success: %q", output.String())
	}
}

func TestCommittedWrapperErrorKeepsUnblockFileAlignedWithFirewall_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), []byte("# retained exactly\n51.195.135.163\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	wrapperErr := errors.New("compatibility wrapper failed")
	var output bytes.Buffer
	haCalls := 0
	err := removeFromBlocklistAt(
		"51.195.135.163",
		blocklist,
		[]approvedListFile{blocklist},
		&output,
		func(string) error { return committedWrapperReconciliationError("0123456789abcdef", wrapperErr) },
		func([]string) error {
			haCalls++
			return errors.New("HA synchronization must not run")
		},
	)
	assertCommittedPersistentListError(t, err, wrapperErr)
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || string(got) != "# retained exactly\n8.8.8.8\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("committed unblock list = %q error=%v", got, readErr)
	}
	if haCalls != 0 {
		t.Fatalf("HA synchronization calls after incomplete wrapper reconciliation = %d", haCalls)
	}
	if output.Len() != 0 {
		t.Fatalf("committed wrapper warning emitted false success: %q", output.String())
	}
}

func TestCommittedPersistedPhaseErrorKeepsWhitelistFilesAlignedWithFirewall_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	whitelist := approvedListFile{directory: directory, name: "whitelist"}
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	if err := os.WriteFile(filepath.Join(directory, whitelist.name), []byte("1.1.1.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), []byte("51.195.135.163\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := newCanonicalListEntry("51.195.135.163", "")
	if err != nil {
		t.Fatal(err)
	}
	phaseErr := errors.New("persisted journal phase durability is uncertain")
	var output bytes.Buffer
	err = addToWhitelistAt(
		entry,
		whitelist,
		blocklist,
		&output,
		func() error { return errors.New("port-scoped apply must not run") },
		func(string) error { return markCommittedFirewallPolicyError(phaseErr) },
	)
	if err == nil || !errors.Is(err, phaseErr) ||
		!strings.Contains(err.Error(), "local firewall and persistent list changes are committed") ||
		!strings.Contains(err.Error(), "post-commit reconciliation is incomplete") ||
		strings.Contains(err.Error(), "compatibility wrapper") {
		t.Fatalf("committed persisted-phase whitelist result = %v", err)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, whitelist.name)); readErr != nil || string(got) != "1.1.1.1\n51.195.135.163\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("persisted-phase whitelist = %q error=%v", got, readErr)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || string(got) != "8.8.8.8\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("persisted-phase blocklist = %q error=%v", got, readErr)
	}
	if output.Len() != 0 {
		t.Fatalf("persisted-phase warning emitted false success: %q", output.String())
	}
}

func TestCommittedJournalCleanupErrorKeepsUnblockFileAlignedWithFirewall_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	blocklist := approvedListFile{directory: directory, name: "blocklist"}
	if err := os.WriteFile(filepath.Join(directory, blocklist.name), []byte("51.195.135.163\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("recovery journal cleanup is incomplete and will be retried")
	var output bytes.Buffer
	haCalls := 0
	err := removeFromBlocklistAt(
		"51.195.135.163",
		blocklist,
		[]approvedListFile{blocklist},
		&output,
		func(string) error { return markCommittedFirewallPolicyError(cleanupErr) },
		func([]string) error {
			haCalls++
			return errors.New("HA synchronization must not run")
		},
	)
	if err == nil || !errors.Is(err, cleanupErr) ||
		!strings.Contains(err.Error(), "local firewall and persistent list changes are committed") ||
		!strings.Contains(err.Error(), "post-commit reconciliation is incomplete") ||
		strings.Contains(err.Error(), "compatibility wrapper") {
		t.Fatalf("committed journal-cleanup unblock result = %v", err)
	}
	if got, readErr := os.ReadFile(filepath.Join(directory, blocklist.name)); readErr != nil || string(got) != "8.8.8.8\n" { // #nosec G304 -- path is a fixed test list beneath t.TempDir
		t.Fatalf("journal-cleanup unblock list = %q error=%v", got, readErr)
	}
	if haCalls != 0 {
		t.Fatalf("HA synchronization calls after committed journal cleanup error = %d", haCalls)
	}
	if output.Len() != 0 {
		t.Fatalf("journal-cleanup warning emitted false success: %q", output.String())
	}
}
