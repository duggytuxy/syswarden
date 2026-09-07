package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const testQualificationCandidate = "v4.10.0"

type qualificationFixture struct {
	bundle     string
	payload    []byte
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	manifest   updateManifest
}

func newQualificationFixture(t *testing.T) qualificationFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated v4.10.0 qualification package")
	manifest := testUpdateManifest(t, testQualificationCandidate, payload)
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	manifestBytes := testMarshalManifest(t, manifest)
	files := map[string][]byte{
		updateManifestAssetName:          manifestBytes,
		updateManifestSignatureAssetName: testSignManifest(privateKey, manifestBytes),
		"syswarden_4.10.0_amd64.deb":     payload,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(bundle, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return qualificationFixture{
		bundle: bundle, payload: payload, publicKey: publicKey, privateKey: privateKey, manifest: manifest,
	}
}

func qualificationTestUpdater(
	t *testing.T,
	fixture qualificationFixture,
	installedVersion string,
	networkCalls *atomic.Int32,
	installCalls *atomic.Int32,
) (*updater, *bytes.Buffer, string) {
	t.Helper()
	tempBase := t.TempDir()
	output := new(bytes.Buffer)
	var attestationCalls atomic.Int32
	u := &updater{
		// A hostile client is deliberately present. The offline path must never
		// reach it, even though the candidate CLI itself is network-capable.
		client: staticHTTPClient(func(*http.Request) (*http.Response, error) {
			networkCalls.Add(1)
			return nil, fmt.Errorf("offline qualification attempted network access")
		}),
		latestURL:       "https://network-must-not-be-used.invalid/latest",
		downloadBaseURL: "https://network-must-not-be-used.invalid/download",
		// This models the extracted candidate CLI. Its compiled version is the
		// target, while the separately attested installed host is older.
		currentVersion: testQualificationCandidate,
		goos:           "linux",
		goarch:         "amd64",
		tempBase:       tempBase,
		trustedKeys:    map[string]ed25519.PublicKey{testReleaseKeyID: fixture.publicKey},
		lookPath: func(name string) (string, error) {
			switch name {
			case "apt-get":
				return "/usr/bin/apt-get", nil
			case "systemctl":
				return "/usr/bin/systemctl", nil
			default:
				return "", os.ErrNotExist
			}
		},
		runCommand: func(_ context.Context, name string, arguments ...string) error {
			if name != "/usr/bin/dpkg" {
				return nil
			}
			installCalls.Add(1)
			if len(arguments) != 2 || arguments[0] != "--install" {
				t.Fatalf("installer arguments = %#v", arguments)
			}
			content, err := os.ReadFile(arguments[1])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(content, fixture.payload) {
				t.Fatalf("installer package = %q", content)
			}
			return nil
		},
		effectiveUID:   os.Geteuid(),
		stdout:         output,
		installTimeout: time.Second,
		attestTimeout:  time.Second,
		attestInstalled: func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
			version := installedVersion
			if attestationCalls.Add(1) > 1 {
				version = testQualificationCandidate
			}
			return installedQualificationEvidence{
				version: version, cliSHA256: strings.Repeat("a", sha256.Size*2),
			}, nil
		},
		attestDependencies: func(context.Context, packageTarget) error { return nil },
		attestCandidateCLI: func(context.Context, packageTarget, *os.File) (string, error) {
			return strings.Repeat("a", sha256.Size*2), nil
		},
		activateCandidate: func(context.Context, installedQualificationEvidence) error { return nil },
	}
	return u, output, tempBase
}

func TestQualificationBundleAcceptsCandidateCLIOnOlderAttestedHostWithoutNetwork(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, output, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)

	if err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate); err != nil {
		t.Fatalf("runQualificationBundle() error = %v", err)
	}
	if networkCalls.Load() != 0 {
		t.Fatalf("offline qualification made %d network calls", networkCalls.Load())
	}
	if installCalls.Load() != 1 {
		t.Fatalf("installer calls = %d, want 1", installCalls.Load())
	}
	for _, expected := range []string{
		"network discovery and fallback are disabled",
		qualificationChannelDisclosure,
		"Installed Version    : v4.04.2",
		"Installed CLI SHA-256: " + strings.Repeat("a", sha256.Size*2),
		"Installed Candidate Version    : v4.10.0",
		"Installed Candidate CLI SHA-256: " + strings.Repeat("a", sha256.Size*2),
		"Candidate Version : v4.10.0",
		fixture.manifest.Artifacts[0].SHA256,
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("qualification output lacks %q:\n%s", expected, output.String())
		}
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationBundleRejectsSameOrOlderCandidateThanAttestedHost(t *testing.T) {
	for _, installedVersion := range []string{"v4.10.0", "v4.11.0"} {
		t.Run(installedVersion, func(t *testing.T) {
			fixture := newQualificationFixture(t)
			var networkCalls atomic.Int32
			var installCalls atomic.Int32
			u, _, tempBase := qualificationTestUpdater(t, fixture, installedVersion, &networkCalls, &installCalls)
			err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
			if err == nil || !strings.Contains(err.Error(), "strictly newer than attested installed version") {
				t.Fatalf("runQualificationBundle() error = %v", err)
			}
			if networkCalls.Load() != 0 || installCalls.Load() != 0 {
				t.Fatalf("network=%d installs=%d after version refusal", networkCalls.Load(), installCalls.Load())
			}
			assertEmptyDirectory(t, tempBase)
		})
	}
}

func TestQualificationCandidateRejectsUnsignedEra(t *testing.T) {
	if err := validateQualificationCandidateVersion("v4.02.8"); err == nil || !strings.Contains(err.Error(), "predates") {
		t.Fatalf("unsigned-era candidate validation error = %v", err)
	}
}

func TestQualificationBundleRejectsUnsignedTamperedOrAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture qualificationFixture)
	}{
		{
			name: "tampered signature",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				path := filepath.Join(fixture.bundle, updateManifestSignatureAssetName)
				content, err := os.ReadFile(path) // #nosec G304 -- path is a fixed release asset name beneath the test-owned bundle
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, testTamperedSignature(t, content), 0600); err != nil { // #nosec G703 -- path is a fixed release asset name beneath the test-owned bundle
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered package",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(fixture.bundle, "syswarden_4.10.0_amd64.deb"),
					bytes.Repeat([]byte{'X'}, len(fixture.payload)),
					0600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unexpected extra file",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fixture.bundle, "unexpected"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "manifest hard link",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				if err := os.Link(
					filepath.Join(fixture.bundle, updateManifestAssetName),
					filepath.Join(t.TempDir(), "manifest-link"),
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "signature wrong mode",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				if err := os.Chmod(filepath.Join(fixture.bundle, updateManifestSignatureAssetName), 0640); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates an unsafe signature mode
					t.Fatal(err)
				}
			},
		},
		{
			name: "bundle wrong mode",
			mutate: func(t *testing.T, fixture qualificationFixture) {
				t.Helper()
				if err := os.Chmod(fixture.bundle, 0750); err != nil { // #nosec G302 -- this adversarial fixture deliberately removes the required private directory mode
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newQualificationFixture(t)
			test.mutate(t, fixture)
			var networkCalls atomic.Int32
			var installCalls atomic.Int32
			u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
			if err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate); err == nil {
				t.Fatal("runQualificationBundle() accepted adversarial bundle")
			}
			if networkCalls.Load() != 0 || installCalls.Load() != 0 {
				t.Fatalf("network=%d installs=%d after bundle refusal", networkCalls.Load(), installCalls.Load())
			}
			assertEmptyDirectory(t, tempBase)
		})
	}
}

func TestQualificationBundleRejectsSymlinkedAndNoncanonicalPaths(t *testing.T) {
	fixture := newQualificationFixture(t)
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(filepath.Dir(fixture.bundle), linkedParent); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"relative/bundle",
		filepath.Join(linkedParent, filepath.Base(fixture.bundle)),
		fixture.bundle + "/../" + filepath.Base(fixture.bundle),
	}
	for _, path := range paths {
		if bundle, err := openQualificationBundle(path, os.Geteuid()); err == nil {
			_ = bundle.Close()
			t.Errorf("openQualificationBundle(%q) accepted unsafe path", path)
		}
	}
}

func TestQualificationFileRevalidationRejectsPathReplacement(t *testing.T) {
	fixture := newQualificationFixture(t)
	bundle, err := openQualificationBundle(fixture.bundle, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	file, identity, err := openQualificationBundleFile(bundle, updateManifestAssetName, maxManifestBytes, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	originalPath := filepath.Join(fixture.bundle, updateManifestAssetName)
	if err := os.Rename(originalPath, filepath.Join(fixture.bundle, "moved-manifest")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originalPath, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := revalidateQualificationBundleFile(bundle, file, updateManifestAssetName, identity, os.Geteuid()); err == nil {
		t.Fatal("revalidation accepted a replaced qualification path")
	}
}

func TestInstalledVersionAttestationRejectsPackageAndBinaryDisagreement(t *testing.T) {
	binaryDirectory := filepath.Join(t.TempDir(), "opt", "syswarden", "bin")
	if err := os.MkdirAll(binaryDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(binaryDirectory, "syswarden-cli")
	if err := os.WriteFile(binaryPath, []byte("attested installed CLI"), 0750); err != nil { // #nosec G306 -- the test CLI fixture must be owner-executable
		t.Fatal(err)
	}
	query := func(_ context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "/usr/bin/rpm" && strings.HasPrefix(joined, "--query syswarden"):
			return []byte("syswarden\t4.04.2\tx86_64\n"), nil
		case name == "/usr/bin/rpm" && strings.HasPrefix(joined, "--query --file"):
			return []byte("syswarden\t4.03.3\tx86_64\n"), nil
		default:
			return nil, nil
		}
	}
	_, err := attestInstalledQualificationVersionWith(
		t.Context(),
		packageTarget{format: packageFormatRPM, installer: "/usr/bin/dnf"},
		os.Geteuid(),
		binaryPath,
		query,
	)
	if err == nil || !strings.Contains(err.Error(), "ownership versions disagree") {
		t.Fatalf("installed version attestation error = %v", err)
	}
}

func TestInstalledBinaryAttestationRejectsModeLinksOwnerAndSymlink(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(t *testing.T, path string)
		ownerUID func() int
	}{
		{
			name: "wrong mode",
			mutate: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0755); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates an over-permissive executable
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, path string) {
				if err := os.Link(path, filepath.Join(t.TempDir(), "second-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "wrong owner expectation",
			mutate: func(*testing.T, string) {},
			ownerUID: func() int {
				return os.Geteuid() + 1
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, path string) {
				victim := filepath.Join(t.TempDir(), "victim")
				if err := os.WriteFile(victim, []byte("victim"), 0750); err != nil { // #nosec G306 -- the symlink target fixture must be owner-executable
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "opt", "syswarden", "bin")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "syswarden-cli")
			if err := os.WriteFile(path, []byte("installed cli"), 0750); err != nil { // #nosec G306 -- the test CLI fixture must be owner-executable
				t.Fatal(err)
			}
			test.mutate(t, path)
			expectedUID := os.Geteuid()
			if test.ownerUID != nil {
				expectedUID = test.ownerUID()
			}
			root, file, _, err := openInstalledQualificationBinary(path, expectedUID)
			if err == nil {
				_ = file.Close()
				_ = root.Close()
				t.Fatal("installed CLI attestation accepted adversarial identity")
			}
		})
	}
}

func TestInstalledBinaryAttestationRejectsWritableParentComponent(t *testing.T) {
	anchor := t.TempDir()
	directory := filepath.Join(anchor, "opt", "syswarden", "bin")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(anchor, "opt", "syswarden"), 0770); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates a group-writable parent
		t.Fatal(err)
	}
	path := filepath.Join(directory, "syswarden-cli")
	if err := os.WriteFile(path, []byte("installed cli"), 0750); err != nil { // #nosec G306 -- the test CLI fixture must be owner-executable
		t.Fatal(err)
	}
	root, file, _, err := openInstalledQualificationBinary(path, os.Geteuid())
	if err == nil {
		_ = file.Close()
		_ = root.Close()
		t.Fatal("installed CLI attestation accepted a group-writable parent")
	}
	if !strings.Contains(err.Error(), "unsafe ownership or mode") {
		t.Fatalf("writable parent error = %v", err)
	}
}

func TestInstalledBinaryAttestationRejectsConcurrentContentMutation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "opt", "syswarden", "bin")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(directory, "syswarden-cli")
	original := []byte("attested-installed-cli")
	if err := os.WriteFile(binaryPath, original, 0750); err != nil { // #nosec G306 -- the test CLI fixture must be owner-executable
		t.Fatal(err)
	}
	mutated := false
	query := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if !mutated {
			mutated = true
			replacement := bytes.Repeat([]byte{'X'}, len(original))
			if err := os.WriteFile(binaryPath, replacement, 0750); err != nil { // #nosec G306 -- the replacement must retain execute permission for this race test
				t.Fatal(err)
			}
		}
		switch {
		case name == "/usr/bin/dpkg-query" && args[0] == "--show":
			return []byte("ii \t4.04.2\n"), nil
		case name == "/usr/bin/dpkg-query" && args[0] == "--search":
			return []byte("syswarden: " + binaryPath + "\n"), nil
		default:
			return nil, nil
		}
	}
	_, err := attestInstalledQualificationVersionWith(
		t.Context(), packageTarget{format: packageFormatDEB}, os.Geteuid(), binaryPath, query,
	)
	if err == nil || !strings.Contains(err.Error(), "changed during package attestation") {
		t.Fatalf("concurrent installed CLI mutation error = %v", err)
	}
}

func TestInstalledVersionParsersRequireExactPackageAndBinaryIdentity(t *testing.T) {
	binaryPath := "/opt/syswarden/bin/syswarden-cli"
	tests := []struct {
		name   string
		target packageTarget
		query  qualificationCommandOutput
		want   string
	}{
		{
			name:   "deb",
			target: packageTarget{format: packageFormatDEB},
			query: func(_ context.Context, name string, args ...string) ([]byte, error) {
				switch {
				case name == "/usr/bin/dpkg-query" && args[0] == "--show":
					return []byte("ii \t4.04.2\n"), nil
				case name == "/usr/bin/dpkg-query" && args[0] == "--search":
					return []byte("syswarden: " + binaryPath + "\n"), nil
				default:
					return nil, nil
				}
			},
			want: "v4.04.2",
		},
		{
			name:   "rpm",
			target: packageTarget{format: packageFormatRPM},
			query: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "--verify" {
					return []byte("S.5....T.  c /etc/syswarden/config/modules/99-user.toml\n"),
						&qualificationCommandExitError{code: 1}
				}
				return []byte("syswarden\t4.04.2\tx86_64\n"), nil
			},
			want: "v4.04.2",
		},
		{
			name:   "apk",
			target: packageTarget{format: packageFormatAPK, installer: "/sbin/apk"},
			query: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[1] == "--verbose" {
					return []byte("syswarden-4.04.2-r0\n"), nil
				}
				return []byte(binaryPath + " is owned by syswarden-4.04.2-r0\n"), nil
			},
			want: "v4.04.2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got string
			var err error
			switch test.target.format {
			case packageFormatDEB:
				got, err = attestInstalledDEBVersion(t.Context(), binaryPath, test.query)
			case packageFormatRPM:
				got, err = attestInstalledRPMVersion(t.Context(), binaryPath, test.query)
			case packageFormatAPK:
				got, err = attestInstalledAPKVersion(t.Context(), test.target.installer, binaryPath, test.query)
			}
			if err != nil || got != test.want {
				t.Fatalf("installed %s version = %q, %v", test.name, got, err)
			}
		})
	}
}

func TestQualificationAPKPayloadBindsExpectedCLIDigestBeforeInstall(t *testing.T) {
	payload := []byte("authenticated candidate cli bytes")
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "opt/syswarden/bin/syswarden-cli",
		Mode: 0750,
		Uid:  0,
		Gid:  0,
		Size: int64(len(payload)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "candidate.apk")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	packageFile, err := os.Open(path) // #nosec G304 -- path is a package fixture created beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	defer packageFile.Close()
	got, err := qualificationAPKPayloadCLISHA256(packageFile)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if got != fmt.Sprintf("%x", want) {
		t.Fatalf("APK CLI SHA-256 = %s, want %x", got, want)
	}
}

type qualificationTarFixtureEntry struct {
	name     string
	payload  []byte
	mode     int64
	uid      int
	gid      int
	typeflag byte
	linkname string
}

func qualificationTarGzipFixture(t *testing.T, entries []qualificationTarFixtureEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := int64(len(entry.payload))
		if !qualificationTarHeaderIsRegular(typeflag) {
			size = 0
		}
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: entry.name, Mode: entry.mode, Uid: entry.uid, Gid: entry.gid,
			Size: size, Typeflag: typeflag, Linkname: entry.linkname,
		}); err != nil {
			t.Fatal(err)
		}
		if size != 0 {
			if _, err := tarWriter.Write(entry.payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func appendQualificationARMember(t *testing.T, archive *bytes.Buffer, name string, payload []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0644, len(payload))
	if len(header) != 60 {
		t.Fatalf("ar header size = %d, want 60", len(header))
	}
	archive.WriteString(header)
	archive.Write(payload)
	if len(payload)%2 != 0 {
		archive.WriteByte('\n')
	}
}

func qualificationDEBFixture(t *testing.T, dataMemberName string, data []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	appendQualificationARMember(t, &archive, "debian-binary", []byte("2.0\n"))
	appendQualificationARMember(t, &archive, "control.tar.gz", qualificationTarGzipFixture(t, nil))
	appendQualificationARMember(t, &archive, dataMemberName, data)
	return archive.Bytes()
}

type qualificationCPIOFixtureEntry struct {
	name    string
	payload []byte
	mode    uint64
	uid     uint64
	gid     uint64
	nlink   uint64
}

func appendQualificationCPIOEntry(t *testing.T, archive *bytes.Buffer, entry qualificationCPIOFixtureEntry) {
	t.Helper()
	name := append([]byte(entry.name), 0)
	fields := []uint64{
		1, entry.mode, entry.uid, entry.gid, entry.nlink, 0, uint64(len(entry.payload)),
		0, 0, 0, 0, uint64(len(name)), 0,
	}
	archive.WriteString("070701")
	for _, field := range fields {
		archive.WriteString(fmt.Sprintf("%08x", field))
	}
	archive.Write(name)
	for archive.Len()%4 != 0 {
		archive.WriteByte(0)
	}
	archive.Write(entry.payload)
	for archive.Len()%4 != 0 {
		archive.WriteByte(0)
	}
}

func qualificationCPIOFixture(t *testing.T, entries []qualificationCPIOFixtureEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	for _, entry := range entries {
		appendQualificationCPIOEntry(t, &archive, entry)
	}
	appendQualificationCPIOEntry(t, &archive, qualificationCPIOFixtureEntry{
		name: "TRAILER!!!", mode: 0, nlink: 1,
	})
	return archive.Bytes()
}

func openQualificationPayloadFixture(t *testing.T, name string, payload []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path) // #nosec G304 -- path is a package fixture created beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestQualificationPackagePayloadBindsExpectedCLIDigestForEveryFormat(t *testing.T) {
	payload := []byte("authenticated candidate CLI payload")
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	tarPayload := qualificationTarGzipFixture(t, []qualificationTarFixtureEntry{{
		name: qualificationPackageCLIPath, payload: payload, mode: 0750, uid: 0, gid: 0,
	}})
	rpmPackage := []byte("authenticated RPM descriptor bytes")
	rpmPayload := qualificationCPIOFixture(t, []qualificationCPIOFixtureEntry{{
		name: qualificationPackageCLIPath, payload: payload, mode: 0100750, uid: 0, gid: 0, nlink: 1,
	}})
	tests := []struct {
		name      string
		target    packageTarget
		packageIn []byte
		converter qualificationRPMPayloadConverter
	}{
		{name: "deb", target: packageTarget{format: packageFormatDEB}, packageIn: qualificationDEBFixture(t, "data.tar.gz", tarPayload)},
		{name: "rpm", target: packageTarget{format: packageFormatRPM}, packageIn: rpmPackage, converter: func(ctx context.Context, packageFile *os.File, output io.Writer) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			got, err := io.ReadAll(io.NewSectionReader(packageFile, 0, int64(len(rpmPackage))))
			if err != nil {
				return err
			}
			if !bytes.Equal(got, rpmPackage) {
				return errors.New("RPM converter did not receive authenticated descriptor")
			}
			_, err = output.Write(rpmPayload)
			return err
		}},
		{name: "apk", target: packageTarget{format: packageFormatAPK}, packageIn: tarPayload},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := openQualificationPayloadFixture(t, "candidate."+test.name, test.packageIn)
			got, err := attestQualificationPackageCLIWith(t.Context(), test.target, file, test.converter)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("%s CLI SHA-256 = %s, want %s", test.name, got, want)
			}
		})
	}
}

func TestQualificationPackagePayloadRejectsUnsafeCLIInventoryForEveryFormat(t *testing.T) {
	payload := []byte("candidate CLI")
	tests := []struct {
		name       string
		tarEntries []qualificationTarFixtureEntry
		cpio       []qualificationCPIOFixtureEntry
	}{
		{
			name:       "missing",
			tarEntries: []qualificationTarFixtureEntry{{name: "opt/syswarden/bin/not-the-cli", payload: payload, mode: 0750}},
			cpio:       []qualificationCPIOFixtureEntry{{name: "opt/syswarden/bin/not-the-cli", payload: payload, mode: 0100750, nlink: 1}},
		},
		{
			name: "duplicate",
			tarEntries: []qualificationTarFixtureEntry{
				{name: qualificationPackageCLIPath, payload: payload, mode: 0750},
				{name: "./" + qualificationPackageCLIPath, payload: payload, mode: 0750},
			},
			cpio: []qualificationCPIOFixtureEntry{
				{name: qualificationPackageCLIPath, payload: payload, mode: 0100750, nlink: 1},
				{name: "./" + qualificationPackageCLIPath, payload: payload, mode: 0100750, nlink: 1},
			},
		},
		{
			name:       "unsafe mode",
			tarEntries: []qualificationTarFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0777}},
			cpio:       []qualificationCPIOFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0100777, nlink: 1}},
		},
		{
			name:       "non-root owner",
			tarEntries: []qualificationTarFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0750, uid: 1000}},
			cpio:       []qualificationCPIOFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0100750, uid: 1000, nlink: 1}},
		},
		{
			name:       "non-root group",
			tarEntries: []qualificationTarFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0750, gid: 1000}},
			cpio:       []qualificationCPIOFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0100750, gid: 1000, nlink: 1}},
		},
		{
			name:       "linked payload",
			tarEntries: []qualificationTarFixtureEntry{{name: qualificationPackageCLIPath, mode: 0750, typeflag: tar.TypeLink, linkname: "opt/syswarden/bin/other"}},
			cpio:       []qualificationCPIOFixtureEntry{{name: qualificationPackageCLIPath, payload: payload, mode: 0100750, nlink: 2}},
		},
		{
			name:       "empty payload",
			tarEntries: []qualificationTarFixtureEntry{{name: qualificationPackageCLIPath, mode: 0750}},
			cpio:       []qualificationCPIOFixtureEntry{{name: qualificationPackageCLIPath, mode: 0100750, nlink: 1}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tarPayload := qualificationTarGzipFixture(t, test.tarEntries)
			cpioPayload := qualificationCPIOFixture(t, test.cpio)
			formats := []struct {
				name      string
				target    packageTarget
				packageIn []byte
				converter qualificationRPMPayloadConverter
			}{
				{name: "deb", target: packageTarget{format: packageFormatDEB}, packageIn: qualificationDEBFixture(t, "data.tar.gz", tarPayload)},
				{name: "rpm", target: packageTarget{format: packageFormatRPM}, packageIn: []byte("rpm"), converter: func(context.Context, *os.File, io.Writer) error { return nil }},
				{name: "apk", target: packageTarget{format: packageFormatAPK}, packageIn: tarPayload},
			}
			formats[1].converter = func(_ context.Context, _ *os.File, output io.Writer) error {
				_, err := output.Write(cpioPayload)
				return err
			}
			for _, format := range formats {
				t.Run(format.name, func(t *testing.T) {
					file := openQualificationPayloadFixture(t, "candidate."+format.name, format.packageIn)
					if digest, err := attestQualificationPackageCLIWith(t.Context(), format.target, file, format.converter); err == nil {
						t.Fatalf("unsafe %s payload accepted with digest %s", format.name, digest)
					}
				})
			}
		})
	}
}

func TestQualificationDEBPayloadCompressionIsFailClosed(t *testing.T) {
	payload := qualificationTarGzipFixture(t, []qualificationTarFixtureEntry{{
		name: qualificationPackageCLIPath, payload: []byte("cli"), mode: 0750,
	}})
	file := openQualificationPayloadFixture(t, "candidate.deb", qualificationDEBFixture(t, "data.tar.xz", payload))
	_, err := attestQualificationPackageCLIWith(t.Context(), packageTarget{format: packageFormatDEB}, file, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported DEB data member error = %v", err)
	}
}

func TestQualificationPayloadAttestationHonorsCanceledContextForEveryFormat(t *testing.T) {
	payload := qualificationTarGzipFixture(t, []qualificationTarFixtureEntry{{
		name: qualificationPackageCLIPath, payload: []byte("cli"), mode: 0750,
	}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name      string
		target    packageTarget
		packageIn []byte
		converter qualificationRPMPayloadConverter
	}{
		{name: "deb", target: packageTarget{format: packageFormatDEB}, packageIn: qualificationDEBFixture(t, "data.tar.gz", payload)},
		{name: "rpm", target: packageTarget{format: packageFormatRPM}, packageIn: []byte("rpm"), converter: func(ctx context.Context, _ *os.File, _ io.Writer) error { return ctx.Err() }},
		{name: "apk", target: packageTarget{format: packageFormatAPK}, packageIn: payload},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := openQualificationPayloadFixture(t, "candidate."+test.name, test.packageIn)
			_, err := attestQualificationPackageCLIWith(ctx, test.target, file, test.converter)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled %s attestation error = %v", test.name, err)
			}
		})
	}
}

func TestQualificationRejectsInstalledCLIDifferentFromAuthenticatedPackagePayload(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestCandidateCLI = func(context.Context, packageTarget, *os.File) (string, error) {
		return strings.Repeat("b", sha256.Size*2), nil
	}
	activationCalls := 0
	u.activateCandidate = func(context.Context, installedQualificationEvidence) error {
		activationCalls++
		return nil
	}
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "does not match authenticated package payload") {
		t.Fatalf("authenticated APK payload mismatch error = %v", err)
	}
	if installCalls.Load() != 1 || activationCalls != 0 || networkCalls.Load() != 0 {
		t.Fatalf("install=%d activation=%d network=%d", installCalls.Load(), activationCalls, networkCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationRejectsMissingAuthenticatedPackageCLIDigestBeforeInstall(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestCandidateCLI = func(context.Context, packageTarget, *os.File) (string, error) {
		return "", nil
	}
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "lacks a valid SHA-256 digest") {
		t.Fatalf("missing authenticated package CLI digest error = %v", err)
	}
	if installCalls.Load() != 0 || networkCalls.Load() != 0 {
		t.Fatalf("install=%d network=%d", installCalls.Load(), networkCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationPackageVerificationAllowsOnlyDeclaredConffileDrift(t *testing.T) {
	for _, valid := range [][]byte{
		nil,
		[]byte("??5?????? c /etc/syswarden/config/config.toml\n"),
		[]byte("S.5....T.  c /etc/syswarden/config/modules/99-user.toml\n"),
	} {
		if err := validateQualificationPackageVerification(valid); err != nil {
			t.Errorf("declared conffile drift rejected: %q: %v", valid, err)
		}
	}
	for _, invalid := range [][]byte{
		[]byte("S.5....T.    /opt/syswarden/bin/syswarden-cli\n"),
		[]byte("S.5....T.  d /opt/syswarden/bin/syswarden-cli\n"),
		[]byte("S.5....T.  c relative/path\n"),
		[]byte("S.5....T.  c /etc/syswarden/config\r\n"),
		[]byte("S.5....T.  c /etc/syswarden/config\nS.5....T.  c /etc/syswarden/config\n"),
	} {
		if err := validateQualificationPackageVerification(invalid); err == nil {
			t.Errorf("unsafe package drift accepted: %q", invalid)
		}
	}
}

func TestQualificationPackageVerificationHandlesRPMAndDPKGDriftExitSeparately(t *testing.T) {
	conffile := []byte("S.5....T.  c /etc/syswarden/config/modules/99-user.toml\n")
	for _, manager := range []string{"rpm", "dpkg"} {
		t.Run(manager+" conffile exit one", func(t *testing.T) {
			err := validateQualificationPackageVerificationResult(
				conffile,
				&qualificationCommandExitError{code: 1},
			)
			if err != nil {
				t.Fatalf("%s conffile drift with exit one rejected: %v", manager, err)
			}
		})
	}
	for _, failure := range []error{
		&qualificationCommandExitError{code: 2},
		&qualificationCommandExitError{code: 1, stderr: []byte("warning\n")},
		&qualificationCommandExitError{code: 1},
	} {
		output := conffile
		if exit, ok := failure.(*qualificationCommandExitError); ok && exit.code == 1 && len(exit.stderr) == 0 {
			output = nil
		}
		if err := validateQualificationPackageVerificationResult(output, failure); err == nil {
			t.Fatalf("ambiguous package verification failure accepted: %#v", failure)
		}
	}
}

func TestAllowedQualificationQueriesAreClosed(t *testing.T) {
	if !allowedQualificationQuery(
		"/usr/bin/dpkg-query",
		[]string{"--show", "--showformat=${db:Status-Abbrev}\t${Version}\n", "syswarden"},
	) {
		t.Fatal("exact installed-version query was rejected")
	}
	for _, query := range []struct {
		name string
		args []string
	}{
		{name: "/tmp/dpkg-query", args: []string{"--show", "syswarden"}},
		{name: "/usr/bin/dpkg-query", args: []string{"--show", "operator-package"}},
		{name: "/usr/bin/rpm", args: []string{"--erase", "syswarden"}},
		{name: "/sbin/apk", args: []string{"add", "syswarden"}},
	} {
		if allowedQualificationQuery(query.name, query.args) {
			t.Fatalf("unsafe query accepted: %s %#v", query.name, query.args)
		}
	}
}

func TestQualificationCopyBindsExactPackageDigest(t *testing.T) {
	fixture := newQualificationFixture(t)
	bundle, err := openQualificationBundle(fixture.bundle, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	workspace, err := createSecureWorkspace(t.TempDir(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := removeSecureWorkspace(workspace); err != nil {
			t.Errorf("remove secure workspace: %v", err)
		}
	}()
	destination, _, err := createSecureExclusiveFile(workspace, "syswarden_4.10.0_amd64.deb", os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	artifact := fixture.manifest.Artifacts[0]
	artifact.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("different")))
	if err := copyVerifiedQualificationPackage(bundle, artifact, destination, os.Geteuid()); err == nil {
		t.Fatal("qualification copy accepted a mismatched package digest")
	}
}

func TestQualificationAttestationHasBoundedDeadline(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestTimeout = 20 * time.Millisecond
	u.attestInstalled = func(ctx context.Context, _ packageTarget, _ int) (installedQualificationEvidence, error) {
		<-ctx.Done()
		return installedQualificationEvidence{}, ctx.Err()
	}
	started := time.Now()
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("bounded attestation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded attestation took %s", elapsed)
	}
	if networkCalls.Load() != 0 || installCalls.Load() != 0 {
		t.Fatalf("network=%d installs=%d after attestation timeout", networkCalls.Load(), installCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationBundleRejectsFalseInstallSuccessBeforeActivation(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
		return installedQualificationEvidence{
			version: "v4.04.2", cliSHA256: strings.Repeat("a", sha256.Size*2),
		}, nil
	}
	serviceCalls := atomic.Int32{}
	originalRunner := u.runCommand
	u.runCommand = func(ctx context.Context, name string, args ...string) error {
		if name == "/usr/bin/dpkg" {
			return originalRunner(ctx, name, args...)
		}
		serviceCalls.Add(1)
		return nil
	}

	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "installed version v4.04.2, want exact candidate v4.10.0") {
		t.Fatalf("false installation success error = %v", err)
	}
	if installCalls.Load() != 1 || serviceCalls.Load() != 0 {
		t.Fatalf("install calls=%d service calls=%d, want 1 and 0", installCalls.Load(), serviceCalls.Load())
	}
	if networkCalls.Load() != 0 {
		t.Fatalf("offline qualification made %d network calls", networkCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationActivationStartsOnlyAfterExactCandidateAttestation(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	var attestationCalls atomic.Int32
	var activationCalls atomic.Int32
	u.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
		call := attestationCalls.Add(1)
		version := "v4.04.2"
		if call >= 2 {
			version = testQualificationCandidate
		}
		return installedQualificationEvidence{
			version: version, cliSHA256: strings.Repeat("a", sha256.Size*2),
		}, nil
	}
	u.activateCandidate = func(_ context.Context, evidence installedQualificationEvidence) error {
		if attestationCalls.Load() != 3 {
			t.Fatalf("activation began after %d attestations, want 3", attestationCalls.Load())
		}
		if evidence.version != testQualificationCandidate || evidence.cliSHA256 != strings.Repeat("a", sha256.Size*2) {
			t.Fatalf("activation evidence = %#v", evidence)
		}
		activationCalls.Add(1)
		return nil
	}

	if err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate); err != nil {
		t.Fatalf("runQualificationBundle() error = %v", err)
	}
	if installCalls.Load() != 1 || activationCalls.Load() != 1 || networkCalls.Load() != 0 {
		t.Fatalf(
			"install=%d activation=%d network=%d, want 1, 1, 0",
			installCalls.Load(), activationCalls.Load(), networkCalls.Load(),
		)
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationRefusesCandidateDriftImmediatelyBeforeActivation(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	var attestationCalls atomic.Int32
	u.attestInstalled = func(context.Context, packageTarget, int) (installedQualificationEvidence, error) {
		call := attestationCalls.Add(1)
		evidence := installedQualificationEvidence{
			version: "v4.04.2", cliSHA256: strings.Repeat("a", sha256.Size*2),
		}
		if call >= 2 {
			evidence.version = testQualificationCandidate
		}
		if call == 3 {
			evidence.cliSHA256 = strings.Repeat("b", sha256.Size*2)
		}
		return evidence, nil
	}
	activationCalls := 0
	u.activateCandidate = func(context.Context, installedQualificationEvidence) error {
		activationCalls++
		return nil
	}
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "identity changed before activation") {
		t.Fatalf("pre-activation candidate drift error = %v", err)
	}
	if attestationCalls.Load() != 3 || activationCalls != 0 || installCalls.Load() != 1 || networkCalls.Load() != 0 {
		t.Fatalf(
			"attest=%d activation=%d install=%d network=%d",
			attestationCalls.Load(), activationCalls, installCalls.Load(), networkCalls.Load(),
		)
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationActivationExecutesAttestedDescriptorAfterPathReplacement(t *testing.T) {
	anchor := t.TempDir()
	directory := filepath.Join(anchor, "opt", "syswarden", "bin")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(anchor, "attested-ran")
	binaryPath := filepath.Join(directory, "syswarden-cli")
	original := []byte("#!/bin/sh\n[ \"$1\" = install ] || exit 91\nprintf '%s\\n' attested > " + strconv.Quote(marker) + "\n")
	if err := os.WriteFile(binaryPath, original, 0750); err != nil { // #nosec G306 -- the test activation fixture must be owner-executable
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	expected := installedQualificationEvidence{
		version: testQualificationCandidate, cliSHA256: fmt.Sprintf("%x", digest),
	}
	err := runQualificationActivationCommandAt(t.Context(), expected, binaryPath, func() error {
		if err := os.Rename(binaryPath, binaryPath+".attested"); err != nil {
			return err
		}
		return os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 92\n"), 0750) // #nosec G306 -- the adversarial replacement must remain executable
	})
	if err != nil {
		t.Fatalf("descriptor-bound activation failed: %v", err)
	}
	content, err := os.ReadFile(marker) // #nosec G304 -- marker is a fixed filename beneath the test-owned activation directory
	if err != nil || string(content) != "attested\n" {
		t.Fatalf("descriptor-bound activation marker = %q, %v", content, err)
	}
}

func TestQualificationDependencyPreflightFailsBeforePackageTransaction(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	var activationCalls atomic.Int32
	u.attestDependencies = func(context.Context, packageTarget) error {
		return errors.New("required dependency is missing")
	}
	u.activateCandidate = func(context.Context, installedQualificationEvidence) error {
		activationCalls.Add(1)
		return nil
	}

	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "attest locally installed dependencies") {
		t.Fatalf("dependency preflight error = %v", err)
	}
	if installCalls.Load() != 0 || activationCalls.Load() != 0 || networkCalls.Load() != 0 {
		t.Fatalf(
			"install=%d activation=%d network=%d after dependency failure, want zero",
			installCalls.Load(), activationCalls.Load(), networkCalls.Load(),
		)
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationDependencyPreflightAttestsEveryDeclaredPackage(t *testing.T) {
	for _, target := range []packageTarget{
		{format: packageFormatDEB, installer: "/usr/bin/apt-get"},
		{format: packageFormatRPM, installer: "/usr/bin/dnf"},
		{format: packageFormatAPK, installer: "/sbin/apk"},
	} {
		t.Run(target.format, func(t *testing.T) {
			calls := 0
			output := func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls++
				if !allowedQualificationQuery(name, args) {
					t.Fatalf("dependency query was not allowlisted: %s %#v", name, args)
				}
				if target.format == packageFormatDEB {
					return []byte("ii \n"), nil
				}
				return nil, nil
			}
			if err := attestOfflineQualificationPackageDependenciesWith(t.Context(), target, output); err != nil {
				t.Fatalf("dependency attestation failed: %v", err)
			}
			if calls != len(qualificationRequiredPackages(target.format)) {
				t.Fatalf("dependency queries = %d, want %d", calls, len(qualificationRequiredPackages(target.format)))
			}
		})
	}
}

func TestQualificationDependencyPreflightRejectsMissingPackage(t *testing.T) {
	target := packageTarget{format: packageFormatRPM, installer: "/usr/bin/dnf"}
	err := attestOfflineQualificationPackageDependenciesWith(
		t.Context(),
		target,
		func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "jq" {
				return nil, &qualificationCommandExitError{code: 1}
			}
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), `required package dependency "jq" is unavailable`) {
		t.Fatalf("missing dependency error = %v", err)
	}
}

func TestQualificationDependencyPreflightHasBoundedDeadline(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestTimeout = 20 * time.Millisecond
	u.attestDependencies = func(ctx context.Context, _ packageTarget) error {
		<-ctx.Done()
		return ctx.Err()
	}
	started := time.Now()
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("bounded dependency attestation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded dependency attestation took %s", elapsed)
	}
	if installCalls.Load() != 0 || networkCalls.Load() != 0 {
		t.Fatalf("install=%d network=%d after dependency timeout", installCalls.Load(), networkCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationPostInstallAttestationHasBoundedDeadline(t *testing.T) {
	fixture := newQualificationFixture(t)
	var networkCalls atomic.Int32
	var installCalls atomic.Int32
	u, _, tempBase := qualificationTestUpdater(t, fixture, "v4.04.2", &networkCalls, &installCalls)
	u.attestTimeout = 20 * time.Millisecond
	var attestationCalls atomic.Int32
	u.attestInstalled = func(ctx context.Context, _ packageTarget, _ int) (installedQualificationEvidence, error) {
		if attestationCalls.Add(1) == 1 {
			return installedQualificationEvidence{
				version: "v4.04.2", cliSHA256: strings.Repeat("a", sha256.Size*2),
			}, nil
		}
		<-ctx.Done()
		return installedQualificationEvidence{}, ctx.Err()
	}
	started := time.Now()
	err := u.runQualificationBundle(t.Context(), fixture.bundle, testQualificationCandidate)
	if err == nil || !strings.Contains(err.Error(), "candidate attestation failed") ||
		!strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("bounded post-install attestation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded post-install attestation took %s", elapsed)
	}
	if networkCalls.Load() != 0 || installCalls.Load() != 1 {
		t.Fatalf("network=%d installs=%d after post-install timeout", networkCalls.Load(), installCalls.Load())
	}
	assertEmptyDirectory(t, tempBase)
}

func TestQualificationInstallCommandsCannotResolveRepositoryDependencies(t *testing.T) {
	packagePath := "/var/tmp/syswarden-update-safe/package"
	tests := []struct {
		name      string
		target    packageTarget
		installer string
		want      []string
	}{
		{
			name: "deb", target: packageTarget{format: packageFormatDEB, installer: "/usr/bin/apt-get"}, installer: "/usr/bin/dpkg",
			want: []string{"--install", packagePath},
		},
		{
			name: "rpm dnf", target: packageTarget{format: packageFormatRPM, installer: "/usr/bin/dnf"}, installer: "/usr/bin/dnf",
			want: []string{"--noplugins", "--cacheonly", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "install", "-y", packagePath},
		},
		{
			name: "rpm yum", target: packageTarget{format: packageFormatRPM, installer: "/usr/bin/yum"}, installer: "/usr/bin/yum",
			want: []string{"--noplugins", "--cacheonly", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "install", "-y", packagePath},
		},
		{
			name: "apk", target: packageTarget{format: packageFormatAPK, installer: "/sbin/apk"}, installer: "/sbin/apk",
			want: []string{"--no-network", "--no-cache", "--repositories-file", "/dev/null", "add", packagePath},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installer, got := test.target.qualificationInstallCommand(packagePath)
			if installer != test.installer {
				t.Fatalf("qualification installer = %q, want %q", installer, test.installer)
			}
			if strings.Join(got, "\x00") != strings.Join(test.want, "\x00") {
				t.Fatalf("qualification arguments = %#v, want %#v", got, test.want)
			}
			if err := validateQualificationExternalCommand(test.installer, got); err != nil {
				t.Fatalf("offline qualification command rejected: %v", err)
			}
			if err := validateExternalCommand(test.installer, got); err == nil {
				t.Fatal("production command contract accepted qualification-only arguments")
			}
			if err := validateQualificationExternalCommand(
				test.installer,
				test.target.installArguments(packagePath),
			); err == nil {
				t.Fatal("qualification command contract accepted network-capable production arguments")
			}
			if test.target.format == packageFormatAPK {
				if err := validateQualificationExternalCommand(
					test.installer,
					[]string{"--no-network", "--no-cache", "--repositories-file", "/dev/null", "add", "--allow-untrusted", packagePath},
				); err == nil {
					t.Fatal("qualification command contract accepted an APK signature bypass")
				}
				if err := validateQualificationExternalCommand(
					test.installer,
					[]string{"--no-network", "--no-cache", "add", packagePath},
				); err == nil {
					t.Fatal("qualification command accepted APK repository metadata")
				}
			}
			if test.target.format == packageFormatDEB {
				if err := validateQualificationExternalCommand(
					"/usr/bin/apt-get",
					[]string{"-o", aptDPkgLockTimeoutOption, "--no-download", "install", "-y", packagePath},
				); err == nil {
					t.Fatal("qualification command accepted APT cached-dependency resolution")
				}
			}
			if test.target.format == packageFormatRPM {
				for _, unsafe := range [][]string{
					{"--cacheonly", "--disablerepo=*", "install", "-y", packagePath},
					{"--noplugins", "--cacheonly", "--setopt=localpkg_gpgcheck=1", "install", "-y", packagePath},
					{"--noplugins", "--cacheonly", "--disablerepo=*", "--setopt=localpkg_gpgcheck=0", "install", "-y", packagePath},
				} {
					if err := validateQualificationExternalCommand(test.installer, unsafe); err == nil {
						t.Fatalf("qualification command accepted RPM native-signature bypass: %#v", unsafe)
					}
				}
			}
		})
	}
}

func TestQualificationPackageEnvironmentIsExactAndPrivate(t *testing.T) {
	t.Setenv(offlineQualificationEnvironment, "hostile")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	t.Setenv("LD_PRELOAD", "/tmp/hostile.so")
	t.Setenv("PYTHONPATH", "/tmp/hostile-python")
	t.Setenv("HTTPS_PROXY", "https://proxy.invalid")
	t.Setenv("DNF_VAR_hostile", "override")
	environment := qualificationExternalCommandEnvironment()
	wantEnvironment := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		offlineQualificationEnvironment + "=1",
	}
	if strings.Join(environment, "\x00") != strings.Join(wantEnvironment, "\x00") {
		t.Fatalf("qualification environment = %#v, want %#v", environment, wantEnvironment)
	}
	for _, forbidden := range []string{"LD_PRELOAD=", "PYTHONPATH=", "HTTPS_PROXY=", "DNF_VAR_"} {
		for _, entry := range environment {
			if strings.HasPrefix(entry, forbidden) {
				t.Fatalf("qualification inherited hostile environment %q", entry)
			}
		}
	}
	t.Setenv(offlineQualificationEnvironment, "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	if !OfflineQualificationPackageInstall() {
		t.Fatal("paired package qualification markers were not recognized")
	}
	os.Unsetenv("SYSWARDEN_PKG_INSTALL")
	if OfflineQualificationPackageInstall() {
		t.Fatal("qualification marker alone changed package-install behavior")
	}
}

func TestQualificationActivationEnvironmentIsExactAndDistinct(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/hostile.so")
	t.Setenv("HTTPS_PROXY", "https://proxy.invalid")
	want := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		offlineQualificationEnvironment + "=" + offlineQualificationActivationValue,
		"SYSWARDEN_PKG_INSTALL=1",
	}
	if got := qualificationActivationEnvironment(); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("qualification activation environment = %#v, want %#v", got, want)
	}
	t.Setenv(offlineQualificationEnvironment, offlineQualificationActivationValue)
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	if OfflineQualificationPackageInstall() || !OfflineQualificationActivation() || !OfflineQualificationOperation() {
		t.Fatal("qualification activation marker was not distinct from package staging")
	}
}

func TestProductionPackageEnvironmentCannotInheritQualificationMarker(t *testing.T) {
	t.Setenv(offlineQualificationEnvironment, "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	t.Setenv("SYSWARDEN_ENVIRONMENT_SENTINEL", "preserved")
	environment := productionExternalCommandEnvironment()
	markerPrefix := offlineQualificationEnvironment + "="
	sentinelFound := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, markerPrefix) {
			t.Fatalf("production environment retained private qualification marker %q", entry)
		}
		if strings.HasPrefix(entry, "SYSWARDEN_PKG_INSTALL=") {
			t.Fatalf("production environment retained private package-install marker %q", entry)
		}
		if entry == "SYSWARDEN_ENVIRONMENT_SENTINEL=preserved" {
			sentinelFound = true
		}
	}
	if !sentinelFound {
		t.Fatal("production environment filtering dropped an unrelated setting")
	}
}

func TestQualificationCommandCaptureIsBounded(t *testing.T) {
	buffer := qualificationBoundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("123456")); err != nil || written != 6 {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if got := string(buffer.Bytes()); got != "1234" || !buffer.overflow {
		t.Fatalf("bounded buffer = %q overflow=%t", got, buffer.overflow)
	}
}

func TestQualificationCommandHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := runQualificationCommandOutput(
		ctx,
		"/usr/bin/rpm",
		"--query",
		"syswarden",
		"--queryformat",
		"%{NAME}\t%{VERSION}\t%{ARCH}\n",
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled qualification query error = %v", err)
	}
}

func TestQualificationProcessCancellationTerminatesDescendantGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	output := new(bytes.Buffer)
	command := exec.Command("/bin/sh", "-c", "sleep 60 & child=$!; echo $child; wait")
	command.Stdout = output
	command.Stderr = output
	started := time.Now()
	err := runQualificationProcessGroup(ctx, command)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("qualification process cancellation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("qualification process group cancellation took %s", elapsed)
	}
	childPID, parseErr := strconv.Atoi(strings.TrimSpace(output.String()))
	if parseErr != nil || childPID <= 0 {
		t.Fatalf("qualification child PID output = %q, error = %v", output.String(), parseErr)
	}
	deadline := time.Now().Add(time.Second)
	for {
		killErr := syscall.Kill(childPID, 0)
		if errors.Is(killErr, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("qualification descendant %d survived process-group cancellation: %v", childPID, killErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQualificationProcessRejectsLingeringDescendantAfterParentSuccess(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "child.pid")
	command := exec.Command("/bin/sh", "-c", "sleep 60 & echo $! > \"$1\"", "qualification-helper", pidPath) // #nosec G204 -- fixed shell script receives only a path beneath t.TempDir
	err := runQualificationProcessGroup(t.Context(), command)
	if err == nil || !strings.Contains(err.Error(), "left a live descendant process") {
		t.Fatalf("lingering qualification descendant error = %v", err)
	}
}
