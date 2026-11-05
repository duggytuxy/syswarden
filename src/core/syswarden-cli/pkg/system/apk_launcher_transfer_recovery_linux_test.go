//go:build linux

package system

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPKLauncherTransferRecordedGateQuarantineCompositeRemoval(t *testing.T) {
	for _, sharedParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-created-parents", true: "shared-created-parent"}[sharedParent], func(t *testing.T) {
			type retainedFile struct {
				content []byte
				info    os.FileInfo
			}
			preserved := make(map[string]retainedFile)
			retain := func(path string) {
				t.Helper()
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				preserved[path] = retainedFile{freshAPKAtomicRead(t, path), info}
			}
			sentinel := "usr/administrator-sentinel"
			if sharedParent {
				sentinel = "usr/local/bin/administrator-sentinel"
			}
			var aliases [2]os.FileInfo
			var sourceDirectory string
			var sourceNames []os.DirEntry
			f, factory, record := apkTerminalGateCrashFixtureWithSetup(t, func(candidate *authenticatedAPKCandidate, services *apkTransitionServices) {
				apkTransferFixtureSource(t, candidate, services, true)
				freshAPKFixtureWrite(t, services.hostRoot, sentinel, []byte("preserve administrator behavior\n"), 0755)
				retain(filepath.Join(services.hostRoot, sentinel))
				source, _ := freshAPKAtomicReference(t, services.hostRoot)
				sourceDirectory = filepath.Join(services.hostRoot, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+source.PlanSHA256)
				var err error
				sourceNames, err = os.ReadDir(sourceDirectory)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range sourceNames {
					retain(filepath.Join(sourceDirectory, name.Name()))
				}
				for i, path := range apkLauncherPaths {
					aliases[i], err = os.Lstat(filepath.Join(services.hostRoot, path))
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			host := f.services.hostRoot
			for _, name := range []string{"original-runtime.json", "original-runtime/bin/syswarden-cli", "original-runtime/bin/syswarden-core", "original-runtime/bin/syswarden-tui", "original-runtime/signatures.json", "native-result.json", "native-output.txt", "resources-closed.json", "native-handoff.json", "native-post-commit-database.txt", "post-attestation.json", "observed-host-snapshot.json", "launcher-prepared.json", "launcher-custody.json"} {
				retain(filepath.Join(f.review.Directory, name))
			}
			retain(filepath.Join(host, "lib/apk/db/installed"))
			quarantine := filepath.Join(host, apkTransitionGateDirectory, record.Quarantine)
			before, err := os.Lstat(quarantine)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := apkLauncherIdentity(before)
			if err != nil || !sameAPKLauncherMovedIdentity(record.Original.Identity, identity) {
				t.Fatal("interruption did not retain the original renamed gate", err)
			}
			quarantineBytes := freshAPKAtomicRead(t, quarantine)
			for i, path := range apkLauncherPaths {
				info, err := os.Lstat(filepath.Join(host, path))
				if err != nil || !os.SameFile(aliases[i], info) {
					t.Fatal("interrupted upgrade replaced source-owned alias", err)
				}
			}
			if err := preflightAPKLauncherRemovalAt(t.Context(), host); err == nil {
				t.Fatal("unclosed quarantine authorized transferred launcher removal")
			}
			if _, err := captureAPKNativeHooks(t.Context(), host); err == nil {
				t.Fatal("ordinary execution capture accepted terminal quarantine")
			}
			authority, err := inspectAPKTerminalFixture(t.Context(), f, factory)
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(quarantine)
			if err != nil || !os.SameFile(before, after) || !bytes.Equal(quarantineBytes, freshAPKAtomicRead(t, quarantine)) {
				t.Fatal("read-only reconstruction mutated recorded quarantine", err)
			}
			if _, err := os.Lstat(filepath.Join(f.review.Directory, "terminal-closed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("read-only reconstruction published successful closure", err)
			}
			if err := finalizeAPKTransitionWith(t.Context(), f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{quarantine, filepath.Join(host, apkTransitionGateDirectory, apkTransitionGateName), filepath.Join(f.services.root, "active-hook")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovered terminal retained gate debt", err)
				}
			}
			if err := preflightAPKLauncherRemovalAt(t.Context(), host); err != nil {
				t.Fatal("successful recovered closure did not authorize composite removal", err)
			}
			freshAPKFixtureBarrier(t, host)
			if err := retireAPKLaunchersForRemovalAt(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			removal, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(removal.attestTerminal(), removal.close()); err != nil {
				t.Fatal(err)
			}
			for _, path := range apkLauncherPaths {
				if _, err := os.Lstat(filepath.Join(host, path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovered transferred alias remains", err)
				}
			}
			for _, path := range []string{"usr/local/bin", "usr/local"} {
				_, err := os.Lstat(filepath.Join(host, path))
				if sharedParent && err != nil || !sharedParent && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("created parent ownership boundary failed", path, err)
				}
			}
			for path, expected := range preserved {
				info, err := os.Lstat(path)
				if err != nil || !os.SameFile(expected.info, info) || !bytes.Equal(expected.content, freshAPKAtomicRead(t, path)) {
					t.Fatal("recovery changed administrator, source, or native outcome evidence", path, err)
				}
			}
			names, err := os.ReadDir(sourceDirectory)
			if err != nil || len(names) != len(sourceNames) {
				t.Fatal("recovery changed original fresh source inventory", err)
			}
			if f.calls != 1 {
				t.Fatal("terminal reconstruction replayed native execution")
			}
		})
	}
}
