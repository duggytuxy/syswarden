//go:build linux

package system

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type apkTransitionFixtureMember struct {
	header  tar.Header
	content []byte
}

func apkTransitionFixtureMembers() []apkTransitionFixtureMember {
	var entries []apkTransitionFixtureMember
	for _, name := range []string{"opt", "opt/syswarden", "opt/syswarden/bin", "usr", "usr/share", "usr/share/bash-completion", "usr/share/bash-completion/completions", "usr/share/doc", "usr/share/doc/syswarden", "etc", "etc/apk", "etc/apk/commit_hooks.d"} {
		entries = append(entries, apkTransitionFixtureMember{header: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}})
	}
	for name, mode := range map[string]int64{
		"opt/syswarden/bin/syswarden-cli": 0750, "opt/syswarden/bin/syswarden-core": 0750, "opt/syswarden/bin/syswarden-tui": 0750,
		"opt/syswarden/signatures.json": 0640, "usr/share/bash-completion/completions/syswarden": 0644,
		"usr/share/doc/syswarden/LICENSE.txt": 0644, "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt": 0644,
		"etc/apk/commit_hooks.d/syswarden-recovery": 0755,
	} {
		data := []byte("public inert fixture: " + name + "\n")
		entries = append(entries, apkTransitionFixtureMember{header: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data))}, content: data})
	}
	return entries
}

func apkTransitionFixtureControls() []apkTransitionFixtureMember {
	data := nativeHeaderTestAPKInfo("syswarden")
	entries := []apkTransitionFixtureMember{{header: tar.Header{Name: ".PKGINFO", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}, content: data}}
	for _, name := range []string{".pre-install", ".post-install", ".pre-upgrade", ".post-upgrade", ".pre-deinstall", ".post-deinstall"} {
		data := []byte("#!/bin/sh\nexit 0\n")
		entries = append(entries, apkTransitionFixtureMember{header: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(data))}, content: data})
	}
	return entries
}

func apkTransitionFixtureTar(t *testing.T, entries []apkTransitionFixtureMember) []byte {
	t.Helper()
	var data bytes.Buffer
	archive := tar.NewWriter(&data)
	for _, entry := range entries {
		if err := archive.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func apkTransitionFixtureArchive(t *testing.T, entries []apkTransitionFixtureMember, signed bool, rewrite ...func([]byte) []byte) []byte {
	t.Helper()
	return apkTransitionFixtureArchiveWithControls(t, entries, apkTransitionFixtureControls(), signed, rewrite...)
}

func apkTransitionFixtureArchiveWithControls(t *testing.T, entries, controls []apkTransitionFixtureMember, signed bool, rewrite ...func([]byte) []byte) []byte {
	t.Helper()
	data := apkTransitionFixtureTar(t, entries)
	for _, change := range rewrite {
		data = change(data)
	}
	var result []byte
	if signed {
		result = nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".SIGN.RSA.public-fixture.pub", data: []byte("inert native signature, verifier injected")}))
	}
	result = append(result, nativeHeaderTestGzip(t, apkTransitionFixtureTar(t, controls))...)
	return append(result, nativeHeaderTestGzip(t, data)...)
}

func apkTransitionFixture(t *testing.T) (authenticatedAPKCandidate, apkTransitionServices, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := apkTransitionFixtureArchive(t, apkTransitionFixtureMembers(), true)
	version := "v5.00.0"
	manifest := testUpdateManifest(t, version, data)
	manifestBytes := testMarshalManifest(t, manifest)
	filename, err := packageFilename(version, packageFormatAPK, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	target := packageTarget{packageName: "syswarden", os: "linux", architecture: "amd64", format: packageFormatAPK, filename: filename, installer: "/sbin/apk"}
	artifact, err := manifest.artifactFor(target)
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
	candidate := authenticatedAPKCandidate{target: target, version: version, artifact: artifact, file: file, path: file.Name(), manifest: manifestBytes,
		signature: testSignManifest(private, manifestBytes), cliSHA256: apkTransitionDigest([]byte("public inert fixture: opt/syswarden/bin/syswarden-cli\n")),
		uid: os.Geteuid(), keys: map[string]ed25519.PublicKey{testReleaseKeyID: public},
		attestInstalled: func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
			return installedQualificationEvidence{version: "v4.10.4", cliSHA256: strings.Repeat("a", 64)}, nil
		}}
	host := t.TempDir()
	for _, name := range []string{"usr/local/bin", "etc/apk", "lib/apk/db", "etc/syswarden/config/modules"} {
		if err := os.MkdirAll(filepath.Join(host, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string][]byte{"etc/apk/world": []byte("syswarden\n"), "lib/apk/db/installed": []byte(apkRetentionFixtureDatabase()),
		"etc/syswarden/config/syswarden.toml":       []byte("# Original opaque configuration evidence\n"),
		"etc/syswarden/config/modules/99-user.toml": []byte("# Original operator bytes\n"), "usr/local/bin/syswarden": []byte("administrator bytes\n")} {
		if err := os.WriteFile(filepath.Join(host, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/opt/administrator-tool", filepath.Join(host, "usr/local/bin/syswarden-tui")); err != nil {
		t.Fatal(err)
	}
	services := apkTransitionServices{root: filepath.Join(t.TempDir(), filepath.Base(apkTransitionRoot)), hostRoot: host,
		verifyNative: func(context.Context, authenticatedAPKCandidate) error { return nil },
		policy: func(context.Context) (apkTransitionPolicyBinding, error) {
			return apkTransitionPolicyBinding{strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)}, nil
		}}
	return candidate, services, data
}

func TestAPKTransitionPreparationPreservesOriginalEvidenceAndNeverInstalls(t *testing.T) {
	candidate, services, data := apkTransitionFixture(t)
	before, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
	if err != nil {
		t.Fatal(err)
	}
	err = prepareAPKTransition(t.Context(), candidate, services)
	var review *APKTransitionApprovalRequiredError
	if !errors.As(err, &review) {
		t.Fatalf("expected retained review, got %v", err)
	}
	if !validSHA256(review.PlanSHA256) || review.Directory != filepath.Join(services.root, review.PlanSHA256) {
		t.Fatal("unbound review identity")
	}
	saved, err := os.ReadFile(filepath.Join(review.Directory, candidate.artifact.Filename))
	if err != nil || !bytes.Equal(saved, data) {
		t.Fatal("candidate bytes were not retained", err)
	}
	planBytes, err := os.ReadFile(filepath.Join(review.Directory, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan apkTransitionPlan
	if err := decodeAPKTransitionJSON(planBytes, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.NativeExecutionAuthorized || plan.ProductAccepted || !reflect.DeepEqual(plan.RetainedDependencyNames, []string{"rsyslog", "wireguard-tools"}) {
		t.Fatalf("incorrect preparation meaning: %#v", plan)
	}
	if apkTransitionDigest(planBytes) != review.PlanSHA256 {
		t.Fatal("plan digest did not bind exact bytes")
	}
	for count := 0; count < 2; count++ {
		if err := approvePreparedAPKTransition(t.Context(), review.PlanSHA256, candidate.keys, candidate.attestInstalled, services); !errors.Is(err, errAPKTransitionExecutionUnavailable) {
			t.Fatalf("review may never install or report completion: %v", err)
		}
	}
	after, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preparation or review changed original host evidence", err)
	}
	reviewBytes, err := os.ReadFile(filepath.Join(review.Directory, "approval.json"))
	if err != nil || !bytes.Contains(reviewBytes, []byte(`"native_execution_authorized":false`)) {
		t.Fatal("review falsely authorized native execution", err)
	}
}

func TestAPKTransitionFailuresRetainAuthenticatedCandidateWithoutOriginalMutation(t *testing.T) {
	for _, kind := range []string{"native-signature", "runtime-approval", "snapshot-drift", "cancellation", "candidate-cli-mismatch", "missing-cli-digest", "downgrade"} {
		t.Run(kind, func(t *testing.T) {
			candidate, services, data := apkTransitionFixture(t)
			before, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sentinel := errors.New("synthetic refusal")
			switch kind {
			case "native-signature":
				services.verifyNative = func(context.Context, authenticatedAPKCandidate) error { return sentinel }
			case "runtime-approval":
				services.policy = func(context.Context) (apkTransitionPolicyBinding, error) {
					return apkTransitionPolicyBinding{}, sentinel
				}
			case "snapshot-drift":
				calls := 0
				original := services.policy
				services.policy = func(ctx context.Context) (apkTransitionPolicyBinding, error) {
					binding, err := original(ctx)
					calls++
					if calls == 2 {
						binding.ApprovalSHA256 = strings.Repeat("e", 64)
					}
					return binding, err
				}
			case "cancellation":
				services.verifyNative = func(context.Context, authenticatedAPKCandidate) error { cancel(); return nil }
			case "candidate-cli-mismatch":
				candidate.cliSHA256 = strings.Repeat("f", 64)
			case "missing-cli-digest":
				candidate.cliSHA256 = ""
			case "downgrade":
				candidate.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
					return installedQualificationEvidence{version: "v6.00.0", cliSHA256: strings.Repeat("a", 64)}, nil
				}
			}
			err = prepareAPKTransition(ctx, candidate, services)
			var review *APKTransitionApprovalRequiredError
			if err == nil || errors.As(err, &review) {
				t.Fatalf("failed evidence became a reviewable plan: %v", err)
			}
			entries, readErr := os.ReadDir(services.root)
			if readErr != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".pending-") {
				t.Fatalf("failed custody lost: %v %v", entries, readErr)
			}
			directory := filepath.Join(services.root, entries[0].Name())
			preserved, readErr := os.ReadFile(filepath.Join(directory, candidate.artifact.Filename)) // #nosec G304 -- both directory and candidate name come from this test's isolated generated fixture
			if readErr != nil || !bytes.Equal(preserved, data) {
				t.Fatal("failed candidate was discarded or altered", readErr)
			}
			if _, err := os.Stat(filepath.Join(directory, "failure.json")); err != nil {
				t.Fatal("failure state missing", err)
			}
			after, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("refusal mutated original host evidence", err)
			}
		})
	}
}

func TestAPKTransitionApprovalCannotAdoptNewStateOrUnknownPlan(t *testing.T) {
	for _, kind := range []string{"unknown-plan", "alias", "config", "world", "candidate", "receipt", "runtime-approval", "native-error", "extra-file"} {
		t.Run(kind, func(t *testing.T) {
			candidate, services, _ := apkTransitionFixture(t)
			var review *APKTransitionApprovalRequiredError
			if err := prepareAPKTransition(t.Context(), candidate, services); !errors.As(err, &review) {
				t.Fatal(err)
			}
			digest := review.PlanSHA256
			var mutate string
			switch kind {
			case "unknown-plan":
				digest = strings.Repeat("0", 64)
			case "alias":
				mutate = filepath.Join(services.hostRoot, "usr/local/bin/syswarden")
			case "config":
				mutate = filepath.Join(services.hostRoot, "etc/syswarden/config/modules/99-user.toml")
			case "world":
				mutate = filepath.Join(services.hostRoot, "etc/apk/world")
			case "candidate":
				mutate = filepath.Join(review.Directory, candidate.artifact.Filename)
			case "receipt":
				mutate = filepath.Join(review.Directory, "plan.json")
			case "runtime-approval":
				services.policy = func(context.Context) (apkTransitionPolicyBinding, error) {
					return apkTransitionPolicyBinding{}, errors.New("approval absent")
				}
			case "native-error":
				services.verifyNative = func(context.Context, authenticatedAPKCandidate) error { return errors.New("native signature changed") }
			case "extra-file":
				mutate = filepath.Join(review.Directory, "unreviewed.json")
			}
			if mutate != "" {
				if err := os.WriteFile(mutate, []byte("independent changed bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := approvePreparedAPKTransition(t.Context(), digest, candidate.keys, candidate.attestInstalled, services)
			if err == nil || errors.Is(err, errAPKTransitionExecutionUnavailable) {
				t.Fatalf("changed/unknown review accepted: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(review.Directory, "approval.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unreviewed state gained approval", err)
			}
			if mutate != "" {
				content, err := os.ReadFile(mutate) // #nosec G304 -- closed cases select only files created under this test's temporary host or custody root
				if err != nil || string(content) != "independent changed bytes" {
					t.Fatal("review rewrote evidence", err)
				}
			}
		})
	}
}

func TestAPKTransitionInventoryRejectsAliasesUnknownOwnershipAndAmbiguousFrames(t *testing.T) {
	for _, kind := range []string{"valid", "usr-local", "alias", "duplicate", "dot-alias", "symlink", "hardlink", "foreign-owner", "wrong-mode", "missing", "pax-path", "gnu-long-name", "native-checksum", "unsigned"} {
		t.Run(kind, func(t *testing.T) {
			entries := apkTransitionFixtureMembers()
			signed := true
			index := 0
			for i, entry := range entries {
				if entry.header.Name == "opt/syswarden/bin/syswarden-cli" {
					index = i
				}
			}
			switch kind {
			case "usr-local":
				entries = append(entries, apkTransitionFixtureMember{header: tar.Header{Name: "usr/local", Typeflag: tar.TypeDir, Mode: 0755}})
			case "alias":
				entries = append(entries, apkTransitionFixtureMember{header: tar.Header{Name: "usr/local/bin/syswarden", Typeflag: tar.TypeReg, Mode: 0750, Size: 1}, content: []byte("x")})
			case "duplicate":
				entries = append(entries, entries[index])
			case "dot-alias":
				entries[index].header.Name = "./" + entries[index].header.Name
			case "symlink", "hardlink":
				entries[index].header.Typeflag = tar.TypeSymlink
				if kind == "hardlink" {
					entries[index].header.Typeflag = tar.TypeLink
				}
				entries[index].header.Linkname = "other"
				entries[index].header.Size = 0
				entries[index].content = nil
			case "foreign-owner":
				entries[index].header.Uid = 123
			case "wrong-mode":
				entries[index].header.Mode = 0777
			case "missing":
				entries = append(entries[:index], entries[index+1:]...)
			case "pax-path", "gnu-long-name":
				entries[index].header.Name = strings.Repeat("x", 120)
				entries[index].header.Format = tar.FormatPAX
				if kind == "gnu-long-name" {
					entries[index].header.Format = tar.FormatGNU
				}
			case "native-checksum":
				entries[index].header.PAXRecords = map[string]string{"APK-TOOLS.checksum.SHA1": strings.Repeat("0", 40)}
			case "unsigned":
				signed = false
			}
			var rewrites []func([]byte) []byte
			if kind == "pax-path" || kind == "gnu-long-name" {
				rewrites = append(rewrites, func(data []byte) []byte { return rewriteAPKTransitionExtendedName(t, data, kind) })
			}
			file := openQualificationPayloadFixture(t, "candidate.apk", apkTransitionFixtureArchive(t, entries, signed, rewrites...))
			if _, err := file.Seek(3, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			inventory, _, err := readAPKTransitionInventory(t.Context(), file)
			if kind == "valid" {
				if err != nil || len(inventory) != 28 {
					t.Fatalf("valid inventory: %d %v", len(inventory), err)
				}
			} else if err == nil {
				t.Fatal("ambiguous inventory accepted")
			}
			if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
				t.Fatal("candidate descriptor position changed", err)
			}
		})
	}
}

// Rewrite a real generated extended-name record so the normalized tar.Header
// names an otherwise allowed path. The original base header still names x...x.
func rewriteAPKTransitionExtendedName(t *testing.T, data []byte, kind string) []byte {
	t.Helper()
	name := "opt/syswarden/bin/syswarden-cli"
	for offset := 0; offset+1024 <= len(data); offset += 512 {
		typeflag := data[offset+156]
		if typeflag != tar.TypeXHeader && typeflag != tar.TypeGNULongName {
			continue
		}
		var record []byte
		if kind == "gnu-long-name" {
			if typeflag != tar.TypeGNULongName {
				continue
			}
			record = append([]byte(name), 0)
		} else {
			if typeflag != tar.TypeXHeader {
				continue
			}
			size := len(name) + 10
			for {
				record = []byte(fmt.Sprintf("%d path=%s\n", size, name))
				if len(record) == size {
					break
				}
				size = len(record)
			}
		}
		copy(data[offset+124:offset+136], []byte(fmt.Sprintf("%011o\x00", len(record))))
		for index := offset + 148; index < offset+156; index++ {
			data[index] = ' '
		}
		checksum := 0
		for _, value := range data[offset : offset+512] {
			checksum += int(value)
		}
		copy(data[offset+148:offset+156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
		clear(data[offset+512 : offset+1024])
		copy(data[offset+512:offset+1024], record)
		reader := tar.NewReader(bytes.NewReader(data))
		found := false
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("extended-name fixture is malformed: %v", err)
			}
			if header.Name == name {
				found = true
			}
		}
		if !found {
			t.Fatal("extended-name fixture did not normalize to the allowed payload path")
		}
		return data
	}
	t.Fatal("fixture did not emit requested extended-name record")
	return nil
}

func TestAPKTransitionInventoryRequiresEveryLifecycleControlAndExactModes(t *testing.T) {
	for index, entry := range apkTransitionFixtureControls() {
		for _, mutation := range []string{"missing", "mode"} {
			t.Run(entry.header.Name+"/"+mutation, func(t *testing.T) {
				controls := apkTransitionFixtureControls()
				if mutation == "missing" {
					controls = append(controls[:index], controls[index+1:]...)
				} else {
					controls[index].header.Mode = 0600
				}
				file := openQualificationPayloadFixture(t, "candidate.apk", apkTransitionFixtureArchiveWithControls(t, apkTransitionFixtureMembers(), controls, true))
				if _, _, err := readAPKTransitionInventory(t.Context(), file); err == nil {
					t.Fatal("incomplete or mispermissioned lifecycle accepted")
				}
			})
		}
	}
}

func TestAPKTransitionCustodyFaultPreservesCompleteOriginalStage(t *testing.T) {
	for _, fault := range []string{"copy-enospc", "copy-cancel", "publish-enospc"} {
		t.Run(fault, func(t *testing.T) {
			candidate, services, original := apkTransitionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if fault == "publish-enospc" {
				services.publish = func(*pinnedServiceDirectory, string, string) error { return syscall.ENOSPC }
			} else {
				services.copyCandidate = func(ctx context.Context, directory *pinnedServiceDirectory, candidate authenticatedAPKCandidate) error {
					if err := writeAPKTransitionBytes(directory, candidate.artifact.Filename, []byte("partial")); err != nil {
						return err
					}
					if fault == "copy-cancel" {
						cancel()
						return ctx.Err()
					}
					return syscall.ENOSPC
				}
			}
			u := &updater{effectiveUID: candidate.uid, trustedKeys: candidate.keys, attestInstalled: candidate.attestInstalled, attestTimeout: time.Second,
				prepareAPKTransition: func(ctx context.Context, candidate authenticatedAPKCandidate) error {
					return prepareAPKTransition(ctx, candidate, services)
				}}
			err := u.preflightAPKTransition(ctx, candidate.target, candidate.version, candidate.artifact, candidate.file, candidate.path, candidate.manifest, candidate.signature, candidate.cliSHA256, false)
			var retained *APKTransitionRetainedMaterialError
			if !errors.As(err, &retained) || !retained.CandidateVerified || !retained.OriginalStageSynchronized || retained.PackagePath != candidate.path || !retainAPKTransitionWorkspace(err, filepath.Dir(candidate.path)) {
				t.Fatalf("complete stage was not bound for retention: %v", err)
			}
			if retainAPKTransitionWorkspace(err, filepath.Join(filepath.Dir(candidate.path), "different")) {
				t.Fatal("retention escaped its exact workspace")
			}
			saved, err := os.ReadFile(candidate.path)
			if err != nil || !bytes.Equal(saved, original) {
				t.Fatal("complete original stage changed", err)
			}
			entries, err := os.ReadDir(services.root)
			if err != nil || len(entries) != 1 {
				t.Fatal("pending fault evidence missing", err)
			}
			pending, err := os.ReadFile(filepath.Join(services.root, entries[0].Name(), candidate.artifact.Filename))
			if err != nil {
				t.Fatal(err)
			}
			if fault != "publish-enospc" && string(pending) != "partial" {
				t.Fatal("partial-copy fault was not exercised")
			}
		})
	}
}

func TestAPKTransitionGateIsConsumedByOnlineAndOfflineRegardlessOfVersion(t *testing.T) {
	for _, version := range []string{"v4.10.0", "v5.00.0"} {
		for _, offline := range []bool{false, true} {
			for _, outcome := range []string{"unclassified", "refusal", "cancel", "copy-failure", "copy-cancel"} {
				t.Run(fmt.Sprintf("%s/offline=%t/%s", version, offline, outcome), func(t *testing.T) {
					fixture := newVersionedQualificationFixture(t, version)
					manifest := testMarshalManifest(t, fixture.manifest)
					signature := testSignManifest(fixture.privateKey, manifest)
					filename, err := packageFilename(version, packageFormatAPK, "amd64")
					if err != nil {
						t.Fatal(err)
					}
					var installs, network atomic.Int32
					var u *updater
					var output *bytes.Buffer
					if offline {
						deb, _ := packageFilename(version, packageFormatDEB, "amd64")
						if err := os.Remove(filepath.Join(fixture.bundle, deb)); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(fixture.bundle, filename), fixture.payload, 0600); err != nil {
							t.Fatal(err)
						}
						u, output, _ = qualificationTestUpdater(t, fixture, "v4.04.2", &network, &installs)
						u.currentVersion = version
					} else {
						client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
							switch request.URL.Path {
							case "/latest":
								return testHTTPResponse(200, []byte(`{"tag_name":"`+version+`"}`)), nil
							case "/download/" + version + "/" + updateManifestAssetName:
								return testHTTPResponse(200, manifest), nil
							case "/download/" + version + "/" + updateManifestSignatureAssetName:
								return testHTTPResponse(200, signature), nil
							case "/download/" + version + "/" + filename:
								return testHTTPResponse(200, fixture.payload), nil
							default:
								return nil, errors.New("unexpected network request")
							}
						})
						u = testUpdater(client, t.TempDir(), "amd64", map[string]ed25519.PublicKey{testReleaseKeyID: fixture.publicKey}, func(context.Context, string, ...string) error { installs.Add(1); return nil })
						output = &bytes.Buffer{}
						u.stdout = output
					}
					u.lookPath = testAllPackageFrontends
					u.preflightNativeIdentity = func(context.Context) (nativeUpdateIdentity, error) {
						return testCompatibilityUpdateIdentity("apk"), nil
					}
					u.installPackage = func(context.Context, packageTarget, string, func(context.Context) error) error {
						installs.Add(1)
						return nil
					}
					u.activateCandidate = func(context.Context, installedQualificationEvidence) error {
						t.Fatal("refused candidate was activated")
						return nil
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					calls := 0
					u.prepareAPKTransition = nil
					if outcome != "unclassified" {
						u.prepareAPKTransition = func(bounded context.Context, candidate authenticatedAPKCandidate) error {
							calls++
							if _, ok := bounded.Deadline(); !ok {
								t.Fatal("preparation is unbounded")
							}
							if candidate.version != version || candidate.offline != offline || candidate.target.packageName != "syswarden" || !bytes.Equal(candidate.manifest, manifest) || !bytes.Equal(candidate.signature, signature) {
								t.Fatal("preparation lost authenticated selection")
							}
							if err := verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid); err != nil {
								t.Fatal(err)
							}
							if outcome == "cancel" {
								cancel()
								return nil
							}
							if outcome == "copy-failure" || outcome == "copy-cancel" {
								_, services, _ := apkTransitionFixture(t)
								services.copyCandidate = func(ctx context.Context, directory *pinnedServiceDirectory, incoming authenticatedAPKCandidate) error {
									if err := writeAPKTransitionBytes(directory, incoming.artifact.Filename, []byte("partial")); err != nil {
										return err
									}
									if outcome == "copy-cancel" {
										cancel()
										return ctx.Err()
									}
									return syscall.ENOSPC
								}
								return prepareAPKTransition(bounded, candidate, services)
							}
							return errors.New("candidate requires retained-plan review")
						}
					}
					if offline {
						err = u.runQualificationBundle(ctx, fixture.bundle, version)
					} else {
						err = u.run(ctx)
					}
					if err == nil || installs.Load() != 0 || bytes.Contains(output.Bytes(), []byte("[SUCCESS]")) {
						t.Fatalf("APK preflight bypass: err=%v installs=%d output=%s", err, installs.Load(), output.String())
					}
					var retained *APKTransitionRetainedMaterialError
					if !errors.As(err, &retained) || !retained.CandidateVerified || !retained.OriginalStageSynchronized {
						t.Fatalf("failed APK stage was not explicitly retained: %v", err)
					}
					preserved, readErr := os.ReadFile(retained.PackagePath)
					if readErr != nil || !bytes.Equal(preserved, fixture.payload) {
						t.Fatal("updater cleanup deleted the complete authenticated candidate", readErr)
					}
					metadata, statErr := os.Lstat(retained.Workspace)
					if statErr != nil || metadata.Mode() != os.ModeDir|0700 {
						t.Fatal("retained updater stage is not private", statErr)
					}
					if outcome != "unclassified" && calls != 1 {
						t.Fatalf("gate not consumed exactly once: %d %v", calls, err)
					}
					if offline && network.Load() != 0 {
						t.Fatal("offline preparation attempted network discovery")
					}
				})
			}
		}
	}
}

func TestAPKTransitionProductionConstructorsRequirePreparation(t *testing.T) {
	for _, constructor := range []func() (*updater, error){newProductionUpdater, newQualificationUpdater} {
		u, err := constructor()
		if err != nil {
			t.Fatal(err)
		}
		if u.prepareAPKTransition == nil {
			t.Fatal("production APK preparation is absent")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := approvePreparedAPKTransition(ctx, "", nil, nil, apkTransitionServices{}); err == nil {
		t.Fatal("approval accepted missing authority")
	}
}
