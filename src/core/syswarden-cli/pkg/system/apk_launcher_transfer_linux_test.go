//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func apkTransferFixtureCandidate(t *testing.T, candidate *authenticatedAPKCandidate) {
	t.Helper()
	version := "v5.01.0"
	controls := apkTransitionFixtureControls()
	for i := range controls {
		if controls[i].header.Name == ".PKGINFO" {
			controls[i].content = bytes.ReplaceAll(controls[i].content, []byte("5.00.0"), []byte("5.01.0"))
			controls[i].header.Size = int64(len(controls[i].content))
		}
	}
	data := apkTransitionFixtureArchiveWithControls(t, apkTransitionFixtureMembers(), controls, true)
	manifest := testUpdateManifest(t, version, data)
	raw := testMarshalManifest(t, manifest)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	filename, err := packageFilename(version, packageFormatAPK, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := createSecureWorkspace(t.TempDir(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := createSecureExclusiveFile(workspace, filename, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	candidate.target.filename = filename
	artifact, err := manifest.artifactFor(candidate.target)
	if err != nil {
		t.Fatal(err)
	}
	candidate.version, candidate.artifact, candidate.file, candidate.path = version, artifact, file, file.Name()
	candidate.manifest, candidate.signature = raw, testSignManifest(private, raw)
	candidate.keys = map[string]ed25519.PublicKey{testReleaseKeyID: public}
}

func apkTransferFixtureSource(t *testing.T, candidate *authenticatedAPKCandidate, services *apkTransitionServices, createdParents bool) {
	t.Helper()
	root := services.hostRoot
	for _, path := range apkLauncherPaths {
		if err := os.Remove(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	if createdParents {
		for _, path := range []string{"usr/local/bin", "usr/local"} {
			if err := os.Remove(filepath.Join(root, path)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for path, mode := range apkLauncherPayloadModes {
		if mode&syscall.S_IFMT == syscall.S_IFDIR {
			if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
				t.Fatal(err)
			} // #nosec G301 -- exact native fixture directories
			if err := os.Chmod(filepath.Join(root, path), 0755); err != nil {
				t.Fatal(err)
			} // #nosec G302 -- exact native fixture directory metadata
			continue
		}
		if strings.HasPrefix(path, "opt/syswarden/bin/") {
			continue
		}
		contents := []byte("fresh source fixture: " + path + "\n")
		if path == "etc/apk/commit_hooks.d/syswarden-recovery" {
			contents = []byte(apkRecoveryHookSource)
		}
		if path == nativeActivationDescriptorPath {
			cli := freshAPKAtomicRead(t, filepath.Join(root, qualificationPackageCLIPath))
			core := freshAPKAtomicRead(t, filepath.Join(root, nativeActivationCorePath))
			var err error
			contents, err = canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(apkTransitionDigest(cli), apkTransitionDigest(core)))
			if err != nil {
				t.Fatal(err)
			}
		}
		freshAPKFixtureWrite(t, root, path, contents, os.FileMode(mode&0777))
	}
	extras := strings.SplitN(apkRetentionFixtureDatabase(), "\n\n", 2)[1]
	freshAPKFixtureWrite(t, root, "lib/apk/db/installed", []byte(extras), 0600)
	freshAPKFixtureWrite(t, root, "etc/alpine-release", []byte("3.22.0\n"), 0644)
	if err := stageFreshAPKLaunchersAt(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	freshAPKFixtureCommit(t, root, true)
	database := freshAPKAtomicRead(t, filepath.Join(root, "lib/apk/db/installed"))
	database = bytes.TrimPrefix(database, []byte("P:base\nV:1.0-r0\nA:x86_64\n\n"))
	database = bytes.Replace(database, []byte("P:syswarden\n"), []byte("P:syswarden\nD:nftables wireguard-tools rsyslog\n"), 1)
	freshAPKFixtureWrite(t, root, "lib/apk/db/installed", append(database, []byte(extras)...), 0600)
	if err := completeFreshAPKLaunchersAt(t.Context(), root, nil); err != nil {
		t.Fatal(err)
	}
	originalCLI := apkTransitionDigest(freshAPKAtomicRead(t, filepath.Join(root, qualificationPackageCLIPath)))
	candidate.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
		return installedQualificationEvidence{version: Version, cliSHA256: originalCLI}, nil
	}
	apkTransferFixtureCandidate(t, candidate)
}

func TestAPKLauncherTransferFreshUpgradeCompleteLauncherRemoval(t *testing.T) {
	for _, createdParents := range []bool{false, true} {
		t.Run(map[bool]string{false: "inherited-parents", true: "created-parents"}[createdParents], func(t *testing.T) {
			var sourceReference apkLauncherLifecycleReference
			var sourceBytes map[string][]byte
			var aliasInfo [2]os.FileInfo
			fixture, factory := apkTerminalCompleteFixtureWithSetup(t, func(candidate *authenticatedAPKCandidate, services *apkTransitionServices) {
				apkTransferFixtureSource(t, candidate, services, createdParents)
				sourceReference, _ = freshAPKAtomicReference(t, services.hostRoot)
				directory := filepath.Join(services.hostRoot, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+sourceReference.PlanSHA256)
				names, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				sourceBytes = make(map[string][]byte)
				for _, name := range names {
					sourceBytes[name.Name()] = freshAPKAtomicRead(t, filepath.Join(directory, name.Name()))
				}
				for i, path := range apkLauncherPaths {
					aliasInfo[i], err = os.Lstat(filepath.Join(services.hostRoot, path))
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			if err := finalizeAPKTransitionWith(t.Context(), fixture.review.PlanSHA256, fixture.candidate.keys, fixture.candidate.attestInstalled, fixture.services, factory); err != nil {
				t.Fatal(err)
			}
			current, _ := freshAPKAtomicReference(t, fixture.services.hostRoot)
			if current.Kind != "execution" || current.PlanSHA256 != fixture.review.PlanSHA256 {
				t.Fatal("execution did not advance exact source lineage")
			}
			for i, path := range apkLauncherPaths {
				info, err := os.Lstat(filepath.Join(fixture.services.hostRoot, path))
				if err != nil || !os.SameFile(info, aliasInfo[i]) {
					t.Fatal("upgrade replaced transferred alias identity")
				}
			}
			custody, err := inspectAPKLaunchersForRemovalAt(t.Context(), fixture.services.hostRoot, current.PlanSHA256, current.ReceiptSHA256)
			if err != nil {
				t.Fatal(err)
			}
			terminalErr := custody.AttestTerminal()
			if err := custody.Close(); err != nil {
				t.Fatal(err)
			}
			if terminalErr == nil || !strings.Contains(terminalErr.Error(), "complete lifecycle source authority") {
				t.Fatalf("custody attested transferred aliases as terminal: %v", terminalErr)
			}
			lineage, err := captureAPKLauncherLineageProposal(t.Context(), fixture.services.hostRoot)
			if err != nil {
				t.Fatal(err)
			}
			original, err := captureAPKLauncherCustodyAt(t.Context(), fixture.services.hostRoot)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := captureAPKLauncherOwnershipTransfer(t.Context(), fixture.services.hostRoot, lineage, original); err == nil {
				t.Fatal("partial synthetic native payload was accepted as a repeated ownership source")
			}
			if err := preflightAPKLauncherRemovalAt(t.Context(), fixture.services.hostRoot); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureBarrier(t, fixture.services.hostRoot)
			if err := retireAPKLaunchersForRemovalAt(t.Context(), fixture.services.hostRoot); err != nil {
				t.Fatal(err)
			}
			h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), fixture.services.hostRoot)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(h.attestTerminal(), h.close()); err != nil {
				t.Fatal(err)
			}
			for _, path := range apkLauncherPaths {
				if _, err := os.Lstat(filepath.Join(fixture.services.hostRoot, path)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("transferred alias remains")
				}
			}
			_, err = os.Lstat(filepath.Join(fixture.services.hostRoot, "usr/local"))
			if createdParents && !errors.Is(err, os.ErrNotExist) || !createdParents && err != nil {
				t.Fatal("transferred parent ownership boundary failed", err)
			}
			directory := filepath.Join(fixture.services.hostRoot, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+sourceReference.PlanSHA256)
			for name, before := range sourceBytes {
				if !bytes.Equal(before, freshAPKAtomicRead(t, filepath.Join(directory, name))) {
					t.Fatal("original source proof was rewritten")
				}
			}
			if fixture.calls != 1 {
				t.Fatal("ownership transfer replayed native execution")
			}
		})
	}
}

func TestAPKLauncherTransferCaptureRefusesChangedSource(t *testing.T) {
	for _, mutation := range []string{"none", "native-absent", "native-version", "alias-inode", "source-proof", "other-package-alias"} {
		t.Run(mutation, func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, false)
			lineage, err := captureAPKLauncherLineageProposal(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			original, err := captureAPKLauncherCustodyAt(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "native-absent":
				freshAPKAtomicForgetNative(t, root)
			case "native-version":
				path := filepath.Join(root, "lib/apk/db/installed")
				freshAPKFixtureWrite(t, root, "lib/apk/db/installed", bytes.Replace(freshAPKAtomicRead(t, path), []byte(strings.TrimPrefix(Version, "v")+"-r0"), []byte("99.00.0-r0"), 1), 0644)
			case "alias-inode":
				path := filepath.Join(root, apkLauncherPaths[0])
				if err := os.Rename(path, path+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(apkLauncherTargets[0], path); err != nil {
					t.Fatal(err)
				}
			case "source-proof":
				reference, _ := freshAPKAtomicReference(t, root)
				path := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+reference.PlanSHA256, apkLauncherCreationName(0))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "other-package-alias":
				path := filepath.Join(root, "lib/apk/db/installed")
				freshAPKFixtureWrite(t, root, "lib/apk/db/installed", append(freshAPKAtomicRead(t, path), []byte("P:other\nV:1-r0\nF:usr/local/bin\nR:syswarden\n\n")...), 0644)
			}
			proposal, err := captureAPKLauncherOwnershipTransfer(t.Context(), root, lineage, original)
			if mutation == "none" {
				if err != nil || proposal == nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("changed source accepted")
			}
		})
	}
}

func TestAPKLauncherTransferRefusesAdministratorOrMixedSource(t *testing.T) {
	for _, kind := range []string{"mixed", "administrator"} {
		t.Run(kind, func(t *testing.T) {
			root := freshAPKFixture(t, true)
			freshAPKFixtureWrite(t, root, apkLauncherPaths[0], []byte("#!/bin/sh\nexec /administrator/tool\n"), 0755)
			if kind == "administrator" {
				if err := os.Symlink("/administrator/tool", filepath.Join(root, apkLauncherPaths[1])); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(filepath.Join(root, apkLauncherPaths[0]))
			if err != nil {
				t.Fatal(err)
			}
			if err := stageFreshAPKLaunchersAt(t.Context(), root); err != nil {
				t.Fatal(err)
			}
			freshAPKFixtureCommit(t, root, false)
			if err := completeFreshAPKLaunchersAt(t.Context(), root, nil); err != nil {
				t.Fatal(err)
			}
			lineage, err := captureAPKLauncherLineageProposal(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			original, err := captureAPKLauncherCustodyAt(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := captureAPKLauncherOwnershipTransfer(t.Context(), root, lineage, original); err == nil {
				t.Fatal("administrator ownership was transferred")
			}
			after, err := os.Lstat(filepath.Join(root, apkLauncherPaths[0]))
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("administrator launcher was changed")
			}
		})
	}
}

func TestAPKLauncherTransferRejectsSameByteSourceSubstitution(t *testing.T) {
	for _, name := range []string{"receipt.json", "intent.json", apkLauncherCreationName(0)} {
		t.Run(name, func(t *testing.T) {
			root := freshAPKAtomicInstalled(t, false)
			lineage, err := captureAPKLauncherLineageProposal(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			original, err := captureAPKLauncherCustodyAt(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			proposal, err := captureAPKLauncherOwnershipTransfer(t.Context(), root, lineage, original)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+proposal.Reference.PlanSHA256, name)
			raw := freshAPKAtomicRead(t, path)
			if err := os.Rename(path, filepath.Join(root, "held-original-proof")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			} // #nosec G306 -- deliberate same-byte proof substitution
			source, err := openAPKLauncherTransferSource(t.Context(), root, proposal, "", "")
			if source != nil {
				_ = source.close()
			}
			if err == nil || !strings.Contains(err.Error(), "source ownership evidence changed") {
				t.Fatalf("source inode substitution was not rejected by identity: %v", err)
			}
		})
	}
}

func TestAPKLauncherTransferRemovalRecoveryAndPreservation(t *testing.T) {
	for _, kind := range []string{"alias-interruption", "parent-interruption", "shared-parent", "administrator-alias", "source-substitution"} {
		t.Run(kind, func(t *testing.T) {
			var source apkLauncherLifecycleReference
			fixture, factory := apkTerminalCompleteFixtureWithSetup(t, func(candidate *authenticatedAPKCandidate, services *apkTransitionServices) {
				apkTransferFixtureSource(t, candidate, services, true)
				source, _ = freshAPKAtomicReference(t, services.hostRoot)
			})
			if err := finalizeAPKTransitionWith(t.Context(), fixture.review.PlanSHA256, fixture.candidate.keys, fixture.candidate.attestInstalled, fixture.services, factory); err != nil {
				t.Fatal(err)
			}
			root := fixture.services.hostRoot
			if kind == "administrator-alias" {
				path := filepath.Join(root, apkLauncherPaths[0])
				if err := os.Rename(path, path+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/administrator/tool", path); err != nil {
					t.Fatal(err)
				}
				if err := preflightAPKLauncherRemovalAt(t.Context(), root); err == nil {
					t.Fatal("administrator replacement was adopted")
				}
				target, err := os.Readlink(path)
				if err != nil || target != "/administrator/tool" {
					t.Fatal("administrator replacement was changed")
				}
				return
			}
			if kind == "source-substitution" {
				path := filepath.Join(root, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+source.PlanSHA256, apkLauncherCreationName(0))
				raw := freshAPKAtomicRead(t, path)
				if err := os.Rename(path, filepath.Join(root, "held-source-proof")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				} // #nosec G306 -- deliberate immutable proof replacement
				if err := preflightAPKLauncherRemovalAt(t.Context(), root); err == nil {
					t.Fatal("substituted transfer proof was accepted for removal")
				}
				if _, err := os.Lstat(filepath.Join(root, apkLauncherPaths[0])); err != nil {
					t.Fatal("refusal removed a launcher")
				}
				return
			}
			if kind == "shared-parent" {
				freshAPKFixtureWrite(t, root, "usr/local/bin/administrator", []byte("preserve\n"), 0755)
			}
			freshAPKFixtureBarrier(t, root)
			if kind == "alias-interruption" || kind == "parent-interruption" {
				h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), root)
				if err != nil {
					t.Fatal(err)
				}
				path := apkLauncherPaths[0]
				if kind == "parent-interruption" {
					path = apkLauncherParents[3]
				}
				injected := errors.New("interrupted transferred quarantine")
				h.store.fault = func(phase string) error {
					if phase == "after-quarantine-"+path {
						return injected
					}
					return nil
				}
				if err := errors.Join(h.retire(), h.close()); !errors.Is(err, injected) {
					t.Fatalf("transfer quarantine fault not reached: %v", err)
				}
			}
			if err := retireAPKLaunchersForRemovalAt(t.Context(), root); err != nil {
				t.Fatal(err)
			}
			h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(h.attestTerminal(), h.close()); err != nil {
				t.Fatal(err)
			}
			if kind == "shared-parent" && string(freshAPKAtomicRead(t, filepath.Join(root, "usr/local/bin/administrator"))) != "preserve\n" {
				t.Fatal("shared parent content was lost")
			}
		})
	}
}
