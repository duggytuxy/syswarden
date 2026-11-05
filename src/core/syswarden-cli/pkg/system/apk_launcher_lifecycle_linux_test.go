//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func freshAPKFixtureWrite(t *testing.T, root, path string, content []byte, mode os.FileMode) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- test-owned native payload directory fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil { // #nosec G306,G703 -- reviewed fixture-relative names under t.TempDir; exact native payload modes
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- deliberate fixture metadata
		t.Fatal(err)
	}
}

func freshAPKFixture(t *testing.T, parents bool) string {
	t.Helper()
	root := t.TempDir()
	for path, mode := range apkLauncherPayloadModes {
		if mode&syscall.S_IFMT == syscall.S_IFDIR {
			if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil { // #nosec G301 -- exact test-owned native directory fixture
				t.Fatal(err)
			}
			continue
		}
		freshAPKFixtureWrite(t, root, path, []byte("fixture:"+path+"\n"), os.FileMode(mode&0777))
	}
	cli, _ := os.ReadFile(filepath.Join(root, qualificationPackageCLIPath)) // #nosec G304 -- test-owned fixture path
	core, _ := os.ReadFile(filepath.Join(root, nativeActivationCorePath))   // #nosec G304 -- test-owned fixture path
	descriptor, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(apkTransitionDigest(cli), apkTransitionDigest(core)))
	if err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureWrite(t, root, nativeActivationDescriptorPath, descriptor, 0644)
	freshAPKFixtureWrite(t, root, "etc/apk/commit_hooks.d/syswarden-recovery", []byte(apkRecoveryHookSource), 0755)
	freshAPKFixtureWrite(t, root, "lib/apk/db/installed", []byte("P:base\nV:1.0-r0\nA:x86_64\n\n"), 0644)
	freshAPKFixtureWrite(t, root, "etc/alpine-release", []byte("3.22.0\n"), 0644)
	if err := os.MkdirAll(filepath.Join(root, "var"), 0755); err != nil {
		t.Fatal(err)
	} // #nosec G301 -- test-owned native parent
	if parents {
		if err := os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0755); err != nil {
			t.Fatal(err)
		} // #nosec G301 -- inherited shared parent fixture
	}
	return root
}

func freshAPKFixtureCommit(t *testing.T, root string, sha256Files bool) {
	t.Helper()
	anchor, err := openAPKLauncherLifecycleAnchor(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := captureAPKLauncherPayload(context.Background(), anchor)
	if closeErr := anchor.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]apkLauncherPayloadFile{}
	for _, file := range files {
		byPath[file.Path] = file
	}
	var dirs []string
	for path, mode := range apkLauncherPayloadModes {
		if mode&syscall.S_IFMT == syscall.S_IFDIR {
			dirs = append(dirs, path)
		}
	}
	sort.Strings(dirs)
	var record strings.Builder
	fmt.Fprintf(&record, "P:syswarden\nV:%s-r0\nA:x86_64\nC:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", strings.TrimPrefix(Version, "v"))
	if sha256Files {
		record.WriteString("f:S\n")
	}
	for _, directory := range dirs {
		fmt.Fprintf(&record, "F:%s\n", directory)
		var names []string
		for path := range byPath {
			if filepath.Dir(path) == directory {
				names = append(names, path)
			}
		}
		sort.Strings(names)
		for _, path := range names {
			file := byPath[path]
			fmt.Fprintf(&record, "R:%s\na:0:0:%o\n", filepath.Base(path), apkLauncherPayloadModes[path]&0777)
			checksum := file.NativeSHA1
			if sha256Files {
				checksum = file.NativeSHA256160
			}
			fmt.Fprintf(&record, "Z:%s\n", checksum)
		}
	}
	freshAPKFixtureWrite(t, root, "lib/apk/db/installed", []byte("P:base\nV:1.0-r0\nA:x86_64\n\n"+record.String()+"\n"), 0644)
}

func freshAPKFixtureBarrier(t *testing.T, root string) {
	t.Helper()
	freshAPKFixtureWrite(t, root, strings.TrimPrefix(RemovalTombstonePath, "/"), []byte(RemovalTombstoneRecord), 0600)
}

func TestFreshAPKLauncherLifecycleCreatesOnlyAbsentAndRetiresExact(t *testing.T) {
	for _, parents := range []bool{false, true} {
		for _, sha256Files := range []bool{false, true} {
			t.Run(fmt.Sprintf("parents_%t_sha256_%t", parents, sha256Files), func(t *testing.T) {
				root := freshAPKFixture(t, parents)
				if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(root, apkLauncherPaths[0])); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("staging created alias: %v", err)
				}
				if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err == nil {
					t.Fatal("accepted uncommitted native state")
				}
				freshAPKFixtureCommit(t, root, sha256Files)
				if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err != nil {
					t.Fatal(err)
				}
				for i, path := range apkLauncherPaths {
					target, err := os.Readlink(filepath.Join(root, path))
					if err != nil || target != apkLauncherTargets[i] {
						t.Fatalf("alias %s: %q %v", path, target, err)
					}
				}
				if err := preflightAPKLauncherRemovalAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
				if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err == nil {
					t.Fatal("retired without barrier")
				}
				freshAPKFixtureBarrier(t, root)
				if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err != nil {
					t.Fatal(err)
				}
				h, err := inspectAPKLauncherLifecycleRemovalAt(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(h.attestTerminal(), h.close()); err != nil {
					t.Fatal(err)
				}
				for _, path := range apkLauncherPaths {
					if _, err := os.Lstat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("alias remains: %v", err)
					}
				}
				_, err = os.Lstat(filepath.Join(root, "usr/local"))
				if parents && err != nil || !parents && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("shared parent preservation: %v", err)
				}
			})
		}
	}
}

func TestFreshAPKLauncherPreservesInheritedWithoutAdoptingBehavior(t *testing.T) {
	for _, kind := range []string{"wrapper", "direct-product-link", "indirect-link"} {
		t.Run(kind, func(t *testing.T) {
			root := freshAPKFixture(t, true)
			path := filepath.Join(root, apkLauncherPaths[0])
			if kind == "wrapper" {
				freshAPKFixtureWrite(t, root, apkLauncherPaths[0], []byte("#!/bin/sh\nexec /opt/syswarden/bin/syswarden-cli \"$@\"\n"), 0755)
			} else {
				target := "/opt/syswarden/bin/syswarden-cli"
				if kind == "indirect-link" {
					target = "/usr/local/bin/admin-tool"
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureCommit(t, root, false)
			if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("inherited alias replaced")
			}
			freshAPKFixtureBarrier(t, root)
			if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err == nil || !strings.Contains(err.Error(), "behavior is unresolved") {
				t.Fatalf("opaque behavior was adopted: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, qualificationPackageCLIPath)); err != nil {
				t.Fatal("product target removed")
			}
		})
	}
}

func TestFreshAPKLauncherLateDriftRetainsRecoveryDebt(t *testing.T) {
	for _, target := range []string{"first-created-alias", "inherited-alias", "cli", "tui", "pending-reference", "pending-reference-unlink"} {
		t.Run(target, func(t *testing.T) {
			root := freshAPKFixture(t, true)
			if target == "inherited-alias" {
				freshAPKFixtureWrite(t, root, apkLauncherPaths[0], []byte("administrator\n"), 0755)
			}
			if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureCommit(t, root, false)
			changed := false
			fault := func(phase string) error {
				if changed || phase != "after-"+apkLauncherCreationName(1) {
					return nil
				}
				changed = true
				switch target {
				case "first-created-alias":
					if err := os.Remove(filepath.Join(root, apkLauncherPaths[0])); err != nil {
						return err
					}
					return os.Symlink("/administrator", filepath.Join(root, apkLauncherPaths[0]))
				case "inherited-alias":
					freshAPKFixtureWrite(t, root, apkLauncherPaths[0], []byte("changed administrator\n"), 0755)
				case "cli":
					freshAPKFixtureWrite(t, root, qualificationPackageCLIPath, []byte("changed runtime\n"), 0750)
				case "tui":
					freshAPKFixtureWrite(t, root, "opt/syswarden/bin/syswarden-tui", []byte("changed runtime\n"), 0750)
				case "pending-reference", "pending-reference-unlink":
					path := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "pending.json")
					raw, err := os.ReadFile(path) // #nosec G304 -- fixed pending.json under t.TempDir before deliberate inode replacement
					if err != nil {
						return err
					}
					before, err := os.Lstat(path)
					if err != nil {
						return err
					}
					if target == "pending-reference-unlink" {
						err = os.Remove(path)
					} else {
						// Retaining the original makes this replacement distinct even
						// without the production descriptor's inode-reuse protection.
						err = os.Rename(path, path+".held")
					}
					if err != nil {
						return err
					}
					if err := os.WriteFile(path, raw, 0600); err != nil { // #nosec G703 -- fixed pending.json under t.TempDir; deliberate same-byte inode replacement
						return err
					}
					after, err := os.Lstat(path)
					if err != nil {
						return err
					}
					if os.SameFile(before, after) {
						t.Fatal("pending reference replacement reused the original inode")
					}
				}
				return nil
			}
			err := completeFreshAPKLaunchersAt(context.Background(), root, fault)
			if err == nil {
				t.Fatal("late drift accepted")
			}
			if strings.HasPrefix(target, "pending-reference") && !strings.Contains(err.Error(), "pending reference identity changed") {
				t.Fatalf("pending replacement did not reach the identity guard: %v", err)
			}
			if !changed {
				t.Fatal("late mutation seam not reached")
			}
			if _, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "pending.json")); err != nil {
				t.Fatal("recovery intent lost")
			}
			if err := preflightAPKLauncherRemovalAt(context.Background(), root); err == nil {
				t.Fatal("pending debt accepted")
			}
		})
	}
}

func TestFreshAPKLauncherNativeProofRefusesChangedRegistration(t *testing.T) {
	for _, target := range []string{"checksum", "mode", "owner", "extra", "missing", "unhealthy", "version", "other-package-alias"} {
		t.Run(target, func(t *testing.T) {
			root := freshAPKFixture(t, true)
			if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureCommit(t, root, false)
			path := filepath.Join(root, "lib/apk/db/installed")
			raw, err := os.ReadFile(path) // #nosec G304 -- fixed native database fixture under t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			s := string(raw)
			switch target {
			case "checksum":
				s = strings.Replace(s, "Z:Q1", "Z:Q2", 1)
			case "mode":
				s = strings.Replace(s, "a:0:0:750", "a:0:0:755", 1)
			case "owner":
				s = strings.Replace(s, "a:0:0:750", "a:1:0:750", 1)
			case "extra":
				s = strings.TrimRight(s, "\n") + "\nR:unrecognized\n\n"
			case "missing":
				s = strings.Replace(s, "F:opt\n", "", 1)
			case "unhealthy":
				s = strings.Replace(s, "P:syswarden\n", "P:syswarden\nf:f\n", 1)
			case "version":
				s = strings.Replace(s, "V:"+strings.TrimPrefix(Version, "v")+"-r0", "V:4.00.0-r0", 1)
			case "other-package-alias":
				s += "P:other\nV:1-r0\nF:usr/local/bin\nR:syswarden\n\n"
			}
			freshAPKFixtureWrite(t, root, "lib/apk/db/installed", []byte(s), 0644)
			if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err == nil {
				t.Fatal("invalid committed native proof accepted")
			}
			if _, err := os.Lstat(filepath.Join(root, apkLauncherPaths[0])); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("alias mutated before valid native proof")
			}
		})
	}
}

func TestFreshAPKLauncherMissingLineageAndPartialCreationAreRecovery(t *testing.T) {
	root := freshAPKFixture(t, false)
	if err := preflightAPKLauncherRemovalAt(context.Background(), root); err == nil {
		t.Fatal("historical absence inferred ownership")
	}
	if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureCommit(t, root, false)
	injected := errors.New("injected parent publication failure")
	if err := completeFreshAPKLaunchersAt(context.Background(), root, func(phase string) error {
		if phase == "after-created-parent-2.json" {
			return injected
		}
		return nil
	}); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err == nil {
		t.Fatal("uncertain partial creation adopted")
	}
	if err := preflightAPKLauncherRemovalAt(context.Background(), root); err == nil {
		t.Fatal("partial ownership accepted")
	}
}

func TestFreshAPKLauncherCreatedParentBecomesShared(t *testing.T) {
	root := freshAPKFixture(t, false)
	if err := stageFreshAPKLaunchersAt(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureCommit(t, root, false)
	if err := completeFreshAPKLaunchersAt(context.Background(), root, nil); err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureWrite(t, root, "usr/local/bin/admin", []byte("preserve\n"), 0755)
	freshAPKFixtureBarrier(t, root)
	if err := retireAPKLaunchersForRemovalAt(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "usr/local/bin/admin")) // #nosec G304 -- fixed preservation fixture under t.TempDir
	if err != nil || !bytes.Equal(raw, []byte("preserve\n")) {
		t.Fatal("shared administrator entry lost")
	}
}

func TestFreshAPKLauncherHooksMatchProducerBytes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", "..", ".."))
	for path, want := range map[string]string{
		"package_apk_recovery_hook.sh": APKRecoveryHookSHA256(),
		"package_apk_preupgrade.sh":    APKTransitionUpgradeHookSHA256("pre-upgrade"),
		"package_apk_postupgrade.sh":   APKTransitionUpgradeHookSHA256("post-upgrade"),
	} {
		raw, err := os.ReadFile(filepath.Join(root, "scripts", "ci", path))
		if err != nil {
			t.Fatal(err)
		} // #nosec G304 -- repository test vector with fixed reviewed names
		if apkTransitionDigest(raw) != want {
			t.Fatalf("producer hook differs: %s", path)
		}
	}
	if APKTransitionUpgradeHookSHA256("post-install") != "" {
		t.Fatal("unsupported hook accepted")
	}
}
