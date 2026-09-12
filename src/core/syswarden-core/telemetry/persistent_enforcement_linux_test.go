//go:build linux

package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writePersistentEnforcementTestFile(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPersistentEnforcementView(t *testing.T, rawEntries ...string) persistentEnforcementView {
	t.Helper()
	view := persistentEnforcementView{attested: true, entries: []persistentEnforcementEntry{}}
	seen := make(map[string]struct{}, len(rawEntries))
	for _, raw := range rawEntries {
		entry, identity, err := canonicalPersistentEnforcementEntry(raw, strings.Contains(raw, ":"))
		if err != nil {
			t.Fatalf("invalid test enforcement entry %q: %v", raw, err)
		}
		if _, duplicate := seen[identity]; duplicate {
			t.Fatalf("duplicate test enforcement entry %q", raw)
		}
		seen[identity] = struct{}{}
		view.entries = append(view.entries, entry)
	}
	return view
}

func TestPersistentEnforcementSnapshotAttestsAddressesCIDRsAndAbsence_SW_GRC_017(t *testing.T) {
	directory := t.TempDir()
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.10\n198.51.100.0/24\n")
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv6File, "2001:db8::/48\n")

	view, err := collectPersistentEnforcementView(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !view.attested || view.entryCount() != 3 {
		t.Fatalf("unexpected persistent enforcement snapshot: %#v", view)
	}
	for _, address := range []string{"192.0.2.10", "198.51.100.42", "2001:db8::1234"} {
		if !view.contains(address) {
			t.Fatalf("attested snapshot does not contain %s", address)
		}
	}
	for _, address := range []string{"192.0.2.11", "203.0.113.1", "2001:db9::1", "::ffff:192.0.2.10"} {
		if view.contains(address) {
			t.Fatalf("attested snapshot unexpectedly contains %s", address)
		}
	}

	emptyDirectory := t.TempDir()
	writePersistentEnforcementTestFile(t, emptyDirectory, persistentEnforcementIPv4File, "")
	writePersistentEnforcementTestFile(t, emptyDirectory, persistentEnforcementIPv6File, "")
	empty, err := collectPersistentEnforcementView(emptyDirectory)
	if err != nil {
		t.Fatalf("present empty files under the shared lock must form an empty attested snapshot: %v", err)
	}
	if !empty.attested || empty.entryCount() != 0 || empty.contains("192.0.2.10") {
		t.Fatalf("present empty files were not represented as an empty attested snapshot: %#v", empty)
	}
}

func TestPersistentEnforcementSnapshotDoesNotTreatMissingEvidenceAsZero_SW_GRC_018(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		present []string
	}{
		{name: "both missing"},
		{name: "IPv6 missing", present: []string{persistentEnforcementIPv4File}},
		{name: "IPv4 missing", present: []string{persistentEnforcementIPv6File}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range fixture.present {
				writePersistentEnforcementTestFile(t, directory, name, "")
			}
			view, err := collectPersistentEnforcementView(directory)
			if err == nil || view.attested || view.entryCount() != 0 {
				t.Fatalf("missing evidence produced an attested zero: view=%#v err=%v", view, err)
			}
		})
	}
}

func TestPersistentEnforcementSnapshotRejectsUnsafeFilesAndContent_SW_GRC_018(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"mode": func(t *testing.T, directory string) {
			path := writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
			if err := os.Chmod(path, 0640); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates an unsafe enforcement file mode
				t.Fatal(err)
			}
		},
		"symbolic link": func(t *testing.T, directory string) {
			target := writePersistentEnforcementTestFile(t, directory, "target", "192.0.2.1\n")
			if err := os.Symlink(target, filepath.Join(directory, persistentEnforcementIPv4File)); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, directory string) {
			target := writePersistentEnforcementTestFile(t, directory, "target", "192.0.2.1\n")
			if err := os.Link(target, filepath.Join(directory, persistentEnforcementIPv4File)); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(t *testing.T, directory string) {
			path := writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "")
			if err := os.Truncate(path, maximumPersistentEnforcementBytes+1); err != nil {
				t.Fatal(err)
			}
		},
		"wrong family": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "2001:db8::1\n")
		},
		"non canonical CIDR": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.42/24\n")
		},
		"duplicate address": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n192.0.2.1\n")
		},
		"semantic duplicate": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n192.0.2.1/32\n")
		},
		"empty line": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n\n198.51.100.1\n")
		},
		"newline instead of an empty list": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "\n")
		},
		"surrounding whitespace": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, " 192.0.2.1\n")
		},
		"missing final newline": func(t *testing.T, directory string) {
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1")
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			prepare(t, directory)
			view, err := collectPersistentEnforcementView(directory)
			if err == nil || view.attested || view.entryCount() != 0 || view.contains("192.0.2.1") {
				t.Fatalf("unsafe persistent enforcement evidence was accepted: view=%#v err=%v", view, err)
			}
		})
	}
}

func TestPersistentEnforcementSnapshotRejectsUnsafeDirectoryPaths_SW_GRC_019(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"relative/path",
		realDirectory + string(filepath.Separator) + ".",
		linkedDirectory,
	} {
		if view, err := collectPersistentEnforcementView(path); err == nil || view.attested {
			t.Fatalf("unsafe directory path %q was accepted: view=%#v err=%v", path, view, err)
		}
	}
}

func TestPersistentEnforcementSnapshotAttestsDirectoryOwnershipAndMode_SW_GRC_019(t *testing.T) {
	for _, mode := range []os.FileMode{0720, 0702, 0770, 0707} {
		t.Run(mode.String(), func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "lists")
			if err := os.Mkdir(directory, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, mode); err != nil {
				t.Fatal(err)
			}
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "")
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv6File, "")
			if view, err := collectPersistentEnforcementView(directory); err == nil || view.attested {
				t.Fatalf("writable directory mode %04o was accepted: view=%#v err=%v", mode.Perm(), view, err)
			}
		})
	}
}

func TestPersistentEnforcementSnapshotRejectsIdentityChanges_SW_GRC_020(t *testing.T) {
	t.Run("replacement after open", func(t *testing.T) {
		directory := t.TempDir()
		path := writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
		mutated := false
		hook := func(stage, name string) {
			if mutated || stage != "opened" || name != persistentEnforcementIPv4File {
				return
			}
			mutated = true
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "198.51.100.1\n")
		}
		view, err := collectPersistentEnforcementViewWithHook(directory, hook)
		if err == nil || view.attested {
			t.Fatalf("replacement race was accepted: view=%#v err=%v", view, err)
		}
	})

	t.Run("same inode mutation during read", func(t *testing.T) {
		directory := t.TempDir()
		path := writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
		mutated := false
		hook := func(stage, name string) {
			if mutated || stage != "read" || name != persistentEnforcementIPv4File {
				return
			}
			mutated = true
			if err := os.WriteFile(path, []byte("198.0.2.1\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		view, err := collectPersistentEnforcementViewWithHook(directory, hook)
		if err == nil || view.attested {
			t.Fatalf("in-place mutation race was accepted: view=%#v err=%v", view, err)
		}
	})

	t.Run("file appears after attested absence", func(t *testing.T) {
		directory := t.TempDir()
		mutated := false
		hook := func(stage, name string) {
			if mutated || stage != "missing" || name != persistentEnforcementIPv4File {
				return
			}
			mutated = true
			writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
		}
		view, err := collectPersistentEnforcementViewWithHook(directory, hook)
		if err == nil || view.attested {
			t.Fatalf("raced file creation was accepted: view=%#v err=%v", view, err)
		}
	})
}

func TestPersistentEnforcementSnapshotUsesWriterDirectoryLock_SW_GRC_021(t *testing.T) {
	directory := t.TempDir()
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv6File, "")
	lock, err := os.Open(directory) // #nosec G304 -- directory is created by t.TempDir and opened only to hold its advisory lock
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	type result struct {
		view persistentEnforcementView
		err  error
	}
	done := make(chan result, 1)
	go func() {
		view, readErr := collectPersistentEnforcementView(directory)
		done <- result{view: view, err: readErr}
	}()
	select {
	case got := <-done:
		t.Fatalf("reader bypassed the writer-compatible directory lock: %#v", got)
	case <-time.After(75 * time.Millisecond):
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || !got.view.attested || !got.view.contains("192.0.2.1") {
			t.Fatalf("reader failed after writer lock release: view=%#v err=%v", got.view, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not resume after writer lock release")
	}
}

func TestPersistentEnforcementUnsafeEvidenceCannotOverclaimRuntimeOrGRC_SW_GRC_022(t *testing.T) {
	runtimeView := runtimeEnforcementView{
		linked: true, complete: true, byIP: map[string]string{},
	}
	unsafeView := persistentEnforcementView{}
	if state := resolveRuntimeEnforcementState("192.0.2.10", runtimeView, unsafeView, nil); state != "unknown" {
		t.Fatalf("unsafe persistent evidence produced an exact absence claim: %q", state)
	}
	safeEmpty := persistentEnforcementView{attested: true, entries: []persistentEnforcementEntry{}}
	if state := resolveRuntimeEnforcementState("192.0.2.10", runtimeView, safeEmpty, nil); state != "absent" {
		t.Fatalf("attested empty snapshot did not produce exact absence: %q", state)
	}
	safeCIDR := testPersistentEnforcementView(t, "192.0.2.0/24")
	if state := resolveRuntimeEnforcementState("192.0.2.10", runtimeView, safeCIDR, nil); state != "active" {
		t.Fatalf("attested CIDR membership did not produce active state: %q", state)
	}
	runtimeView.byIP["192.0.2.10"] = "active"
	if state := resolveRuntimeEnforcementState("192.0.2.10", runtimeView, unsafeView, nil); state != "active" {
		t.Fatalf("independent exact HA evidence was discarded: %q", state)
	}
	evidence := kpiEvidenceState{
		catalogAvailable: true, journalScanComplete: true, persistentEnforcementUnsafe: true,
	}
	if evidence.quality() != kpiEvidenceQualityDegraded {
		t.Fatal("unsafe persistent enforcement evidence did not degrade GRC evidence quality")
	}
}

func TestPersistentEnforcementSnapshotRejectsWrongOwnershipWhenPrivileged_SW_GRC_023(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	directory := t.TempDir()
	path := writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "192.0.2.1\n")
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if view, err := collectPersistentEnforcementView(directory); err == nil || view.attested {
		t.Fatalf("wrong ownership was accepted: view=%#v err=%v", view, err)
	}
}

func TestPersistentEnforcementSnapshotRejectsWrongDirectoryOwnershipWhenPrivileged_SW_GRC_024(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing directory ownership requires root")
	}
	directory := filepath.Join(t.TempDir(), "lists")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv4File, "")
	writePersistentEnforcementTestFile(t, directory, persistentEnforcementIPv6File, "")
	if err := os.Chown(directory, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chown(directory, os.Geteuid(), os.Getegid()); err != nil {
			t.Errorf("restore directory ownership: %v", err)
		}
	}()
	if view, err := collectPersistentEnforcementView(directory); err == nil || view.attested {
		t.Fatalf("wrong directory ownership was accepted: view=%#v err=%v", view, err)
	}
}
