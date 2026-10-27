//go:build linux

package system

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func nativeActivationTestDescriptor(t *testing.T, cli, core []byte) []byte {
	t.Helper()
	cliHash, coreHash := sha256.Sum256(cli), sha256.Sum256(core)
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(hex.EncodeToString(cliHash[:]), hex.EncodeToString(coreHash[:])))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nativeActivationTestPayload(t *testing.T) []qualificationTarFixtureEntry {
	t.Helper()
	cli, core := []byte("synthetic CLI, never executed\n"), []byte("synthetic core, never executed\n")
	return []qualificationTarFixtureEntry{
		{name: qualificationPackageCLIPath, payload: cli, mode: 0750},
		{name: nativeActivationCorePath, payload: core, mode: 0750},
		{name: nativeActivationDescriptorPath, payload: nativeActivationTestDescriptor(t, cli, core), mode: 0644},
	}
}

func nativeActivationTestClassify(t *testing.T, format string, entries []qualificationTarFixtureEntry) (NativeActivationCandidate, error) {
	t.Helper()
	data := qualificationTarGzipFixture(t, entries)
	var converter qualificationRPMPayloadConverter
	switch format {
	case packageFormatDEB:
		data = qualificationDEBFixture(t, "data.tar.gz", data)
	case packageFormatAPK:
		control := nativeHeaderTestGzip(t, nativeHeaderTestTar(t, true, nativeHeaderTestEntry{name: ".PKGINFO", data: nativeHeaderTestAPKInfo("syswarden")}))
		data = append(control, data...)
	case packageFormatRPM:
		cpioEntries := make([]qualificationCPIOFixtureEntry, 0, len(entries))
		for _, entry := range entries {
			if entry.mode < 0 || entry.uid < 0 || entry.gid < 0 {
				t.Fatal("negative native activation fixture metadata")
				return NativeActivationCandidate{}, nil
			}
			mode := uint64(0100000) | uint64(entry.mode)
			if entry.typeflag == tar.TypeSymlink {
				mode = 0120000 | uint64(entry.mode)
			}
			cpioEntries = append(cpioEntries, qualificationCPIOFixtureEntry{name: entry.name, payload: entry.payload, mode: mode, uid: uint64(entry.uid), gid: uint64(entry.gid), nlink: 1})
		}
		cpio := qualificationCPIOFixture(t, cpioEntries)
		converter = func(_ context.Context, _ *os.File, output io.Writer) error { _, err := output.Write(cpio); return err }
		data = []byte("authenticated RPM descriptor fixture, conversion is injected")
	}
	file := openQualificationPayloadFixture(t, "candidate", data)
	if _, err := file.Seek(1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	candidate, err := attestNativeActivationCandidateWith(t.Context(), packageTarget{format: format}, file, converter)
	if offset, seekErr := file.Seek(0, io.SeekCurrent); seekErr != nil || offset != 1 {
		t.Fatalf("classification moved caller descriptor: %d %v", offset, seekErr)
	}
	return candidate, err
}

func TestNativeActivationCandidateBindsBothBinariesAndContract(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		t.Run(format, func(t *testing.T) {
			entries := nativeActivationTestPayload(t)
			candidate, err := nativeActivationTestClassify(t, format, entries)
			if err != nil {
				t.Fatal(err)
			}
			want, err := parseNativeActivationDescriptor(entries[2].payload)
			if err != nil {
				t.Fatal(err)
			}
			if candidate != want || candidate.SHA256() == "" {
				t.Fatalf("candidate mismatch: %+v", candidate.Review())
			}
			review := candidate.Review()
			review.CoreSHA256 = strings.Repeat("0", 64)
			if candidate.Review().CoreSHA256 == review.CoreSHA256 {
				t.Fatal("review changed captured value")
			}
		})
	}
	if (NativeActivationCandidate{}).SHA256() != "" {
		t.Fatal("zero value granted capability")
	}
}

func TestNativeActivationCandidateRejectsUnsafeOrUnboundPayload(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"missing-descriptor", "missing-core", "wrong-core", "duplicate-cli", "duplicate-descriptor", "foreign-owner", "writable-core", "symlink-core", "aliased-core", "unknown-contract", "noncanonical", "extra-field", "oversized-descriptor"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				entries := nativeActivationTestPayload(t)
				switch name {
				case "missing-descriptor":
					entries = entries[:2]
				case "missing-core":
					entries = append(entries[:1], entries[2:]...)
				case "wrong-core":
					entries[1].payload = []byte("other core")
				case "duplicate-cli":
					entries = append(entries, entries[0])
				case "duplicate-descriptor":
					entries = append(entries, entries[2])
				case "foreign-owner":
					entries[1].uid = 1000
				case "writable-core":
					entries[1].mode = 0770
				case "symlink-core":
					entries[1].typeflag = tar.TypeSymlink
					entries[1].linkname = "other"
					entries[1].payload = nil
				case "aliased-core":
					entries[1].name = "opt/syswarden/bin/../bin/syswarden-core"
				case "unknown-contract":
					entries[2].payload = bytes.ReplaceAll(entries[2].payload, []byte("approval-v1"), []byte("approval-v9"))
				case "noncanonical":
					entries[2].payload = append([]byte(" "), entries[2].payload...)
				case "extra-field":
					entries[2].payload = bytes.Replace(entries[2].payload, []byte("}\n"), []byte(",\"authorization\":true}\n"), 1)
				case "oversized-descriptor":
					entries[2].payload = bytes.Repeat([]byte("x"), 4097)
				}
				if candidate, err := nativeActivationTestClassify(t, format, entries); err == nil || candidate.SHA256() != "" {
					t.Fatalf("unsafe candidate accepted: %+v %v", candidate.Review(), err)
				}
			})
		}
	}
}

func TestNativeActivationCandidateCanonicalContractLiterals(t *testing.T) {
	// Independent source checks prevent the runtime/parser contract from silently
	// changing while the capability descriptor continues to declare old support.
	raw, err := os.ReadFile("../../config/activation_contract_linux.go") // #nosec G304 -- fixed public source contract, never an operator path
	if err != nil {
		t.Fatal(err)
	}
	for _, literal := range []string{"syswarden-activation-approval-v1", "syswarden-toml-source-v1", "toml-only-reject-modular-environment-v1"} {
		if !bytes.Contains(raw, []byte("\""+literal+"\"")) {
			t.Fatalf("source no longer defines descriptor contract %s", literal)
		}
	}
}

func TestNativeActivationCandidateCanceledAndUnavailableInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []context.Context{nil, ctx, t.Context()} {
		if got, err := attestNativeActivationCandidate(input, packageTarget{format: packageFormatDEB}, nil); err == nil || got.SHA256() != "" {
			t.Fatal("unavailable input accepted")
		}
	}
	if err := (NativeActivationCandidate{}).VerifyInstalled(t.Context()); err == nil {
		t.Fatal("zero value verified installed runtime")
	}
}

func TestNativeActivationCandidateInstalledBytesAndMetadata(t *testing.T) {
	for _, outcome := range []string{"valid", "changed-cli", "changed-core", "changed-descriptor", "missing-descriptor", "symlink-core", "writable-parent", "writable-descriptor", "linked-cli", "fifo-core"} {
		t.Run(outcome, func(t *testing.T) {
			root := t.TempDir()
			entries := nativeActivationTestPayload(t)
			for _, entry := range entries {
				name := filepath.Join(root, entry.name)
				mode := os.FileMode(entry.mode & 07777)
				if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil { // #nosec G301 -- fixture models exact protected native ancestry
					t.Fatal(err)
				}
				if err := os.WriteFile(name, entry.payload, mode); err != nil { // #nosec G304 G306 -- test-owned fixture models exact native payload bytes and modes
					t.Fatal(err)
				}
				if err := os.Chmod(name, mode); err != nil { // #nosec G302 -- exact native payload permission fixture
					t.Fatal(err)
				}
			}
			candidate, err := parseNativeActivationDescriptor(entries[2].payload)
			if err != nil {
				t.Fatal(err)
			}
			core := filepath.Join(root, nativeActivationCorePath)
			switch outcome {
			case "changed-cli", "changed-core", "changed-descriptor":
				index := map[string]int{"changed-cli": 0, "changed-core": 1, "changed-descriptor": 2}[outcome]
				if err := os.WriteFile(filepath.Join(root, entries[index].name), []byte("changed"), 0600); err != nil { // #nosec G304 -- deliberate mutation of the test-owned runtime fixture
					t.Fatal(err)
				}
			case "missing-descriptor":
				if err := os.Remove(filepath.Join(root, nativeActivationDescriptorPath)); err != nil {
					t.Fatal(err)
				}
			case "symlink-core":
				if err := os.Remove(core); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("syswarden-cli", core); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(filepath.Dir(core), 0775); err != nil { // #nosec G302 -- deliberate unsafe ancestry rejection fixture
					t.Fatal(err)
				}
			case "writable-descriptor":
				if err := os.Chmod(filepath.Join(root, nativeActivationDescriptorPath), 0664); err != nil { // #nosec G302 -- deliberate unsafe descriptor rejection fixture
					t.Fatal(err)
				}
			case "linked-cli":
				if err := os.Link(filepath.Join(root, qualificationPackageCLIPath), filepath.Join(root, "extra-link")); err != nil {
					t.Fatal(err)
				}
			case "fifo-core":
				if err := os.Remove(core); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(core, 0750); err != nil {
					t.Fatal(err)
				}
			}
			uid := uint32(os.Getuid()) // #nosec G115 -- operating system UID of test-owned fixtures is nonnegative and represented by uint32
			gid := uint32(os.Getgid()) // #nosec G115 -- operating system GID of test-owned fixtures is nonnegative and represented by uint32
			err = candidate.verifyInstalledAt(t.Context(), root, uid, gid)
			if (err == nil) != (outcome == "valid") {
				t.Fatalf("installed verification outcome %s: %v", outcome, err)
			}
		})
	}
}
