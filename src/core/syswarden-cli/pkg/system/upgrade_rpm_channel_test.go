package system

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInstalledRPMIdentityCommandUsesFixedBoundedContract(t *testing.T) {
	t.Parallel()

	command := installedRPMIdentityCommand(t.Context())
	if command.Path != installedRPMExecutablePath {
		t.Fatalf("RPM query executable = %q, want %q", command.Path, installedRPMExecutablePath)
	}
	wantArguments := []string{
		installedRPMExecutablePath,
		"--noplugins",
		"--query",
		"--queryformat",
		installedRPMQueryFormat,
		installedRPMPackageName,
	}
	if !reflect.DeepEqual(command.Args, wantArguments) {
		t.Fatalf("RPM query arguments = %#v, want %#v", command.Args, wantArguments)
	}
	wantEnvironment := []string{
		"HOME=/nonexistent",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
		"XDG_CONFIG_HOME=/nonexistent",
	}
	if !reflect.DeepEqual(command.Env, wantEnvironment) {
		t.Fatalf("RPM query environment = %#v, want %#v", command.Env, wantEnvironment)
	}
	if command.Dir != "/" {
		t.Fatalf("RPM query directory = %q, want /", command.Dir)
	}
	if command.WaitDelay != installedRPMCommandWaitDelay {
		t.Fatalf("RPM query wait delay = %s, want %s", command.WaitDelay, installedRPMCommandWaitDelay)
	}

	buffer := &rpmQueryBoundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("12345")); err != nil || written != 5 {
		t.Fatalf("bounded buffer write = (%d, %v), want (5, nil)", written, err)
	}
	if string(buffer.Bytes()) != "1234" || !buffer.overflow {
		t.Fatalf("bounded buffer = %q overflow=%t", buffer.Bytes(), buffer.overflow)
	}
}

func TestValidateInstalledStandardRPMReleaseFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		output         string
		currentVersion string
		wantError      string
	}{
		{
			name:           "exact standard identity",
			output:         "syswarden\t0\t4.10.0\t1\tx86_64\n",
			currentVersion: "v4.10.0",
		},
		{
			name:           "exact RHEL package-owned identity",
			output:         "syswarden\t0\t4.10.0\t1.rhelpo\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      rhelPackageOwnedRPMFilename,
		},
		{
			name:           "unexpected package-owned version",
			output:         "syswarden\t0\t4.10.1\t1.rhelpo\tx86_64\n",
			currentVersion: "v4.10.1",
			wantError:      "unrecognized RHEL package-owned RPM version",
		},
		{
			name:           "wrong name",
			output:         "other\t0\t4.10.0\t1\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      "name",
		},
		{
			name:           "nonzero epoch",
			output:         "syswarden\t1\t4.10.0\t1\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      "epoch",
		},
		{
			name:           "running and installed version mismatch",
			output:         "syswarden\t0\t4.04.3\t1\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      "does not match running",
		},
		{
			name:           "unknown release",
			output:         "syswarden\t0\t4.10.0\t2\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      "not the standard release",
		},
		{
			name:           "wrong architecture",
			output:         "syswarden\t0\t4.10.0\t1\taarch64\n",
			currentVersion: "v4.10.0",
			wantError:      "architecture",
		},
		{
			name:           "multiple installed identities",
			output:         "syswarden\t0\t4.10.0\t1\tx86_64\nsyswarden\t0\t4.10.0\t1.rhelpo\tx86_64\n",
			currentVersion: "v4.10.0",
			wantError:      "not canonical",
		},
		{
			name:           "missing final newline",
			output:         "syswarden\t0\t4.10.0\t1\tx86_64",
			currentVersion: "v4.10.0",
			wantError:      "not canonical",
		},
		{
			name:           "oversized identity",
			output:         strings.Repeat("x", maximumInstalledRPMIdentityBytes+1),
			currentVersion: "v4.10.0",
			wantError:      "outside the accepted range",
		},
		{
			name:           "invalid running version",
			output:         "syswarden\t0\t4.10.0\t1\tx86_64\n",
			currentVersion: "4.10.0",
			wantError:      "validate running SysWarden version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateInstalledStandardRPMRelease([]byte(test.output), test.currentVersion)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateInstalledStandardRPMRelease() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateInstalledStandardRPMRelease() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestRHELPackageOwnedRPMIsRefusedBeforeReleaseAssetDownload(t *testing.T) {
	t.Parallel()

	var releaseAssetRequests atomic.Int32
	client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/latest" {
			return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"v4.10.1"}`)), nil
		}
		releaseAssetRequests.Add(1)
		return testHTTPResponse(http.StatusInternalServerError, []byte("unexpected release asset request")), nil
	})
	u := testUpdater(client, t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
		t.Fatal("installer or activation command ran for the package-owned RPM")
		return nil
	})
	u.currentVersion = "v4.10.0"
	u.lookPath = func(name string) (string, error) {
		if name == "dnf" {
			return "/usr/bin/dnf", nil
		}
		return "", os.ErrNotExist
	}
	u.attestRPM = func(ctx context.Context, currentVersion string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("RPM release attestation has no deadline")
		}
		return validateInstalledStandardRPMRelease(
			[]byte("syswarden\t0\t4.10.0\t1.rhelpo\tx86_64\n"),
			currentVersion,
		)
	}

	err := u.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), rhelPackageOwnedRPMFilename) {
		t.Fatalf("updater.run() error = %v, want package-owned RPM refusal", err)
	}
	if releaseAssetRequests.Load() != 0 {
		t.Fatalf("release asset requests = %d, want 0", releaseAssetRequests.Load())
	}
}

func TestStandardRPMReleaseIsReattestedImmediatelyBeforeInstallation(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	packagePayload := []byte("verified standard rpm package")
	manifestBytes := testMarshalManifest(t, testUpdateManifest(t, testUpdateVersion, packagePayload))
	signature := testSignManifest(privateKey, manifestBytes)
	packageName := "syswarden-4.02.9-1.x86_64.rpm"
	var packageDownloaded atomic.Bool
	client := staticHTTPClient(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/latest":
			return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestAssetName:
			return testHTTPResponse(http.StatusOK, manifestBytes), nil
		case "/download/" + testUpdateVersion + "/" + updateManifestSignatureAssetName:
			return testHTTPResponse(http.StatusOK, signature), nil
		case "/download/" + testUpdateVersion + "/" + packageName:
			packageDownloaded.Store(true)
			return testHTTPResponse(http.StatusOK, packagePayload), nil
		default:
			return testHTTPResponse(http.StatusNotFound, []byte("not found")), nil
		}
	})
	var attestations atomic.Int32
	var installations atomic.Int32
	u := testUpdater(
		client,
		t.TempDir(),
		"amd64",
		map[string]ed25519.PublicKey{testReleaseKeyID: publicKey},
		func(_ context.Context, name string, _ ...string) error {
			if name == "/usr/bin/dnf" {
				installations.Add(1)
			}
			return nil
		},
	)
	u.lookPath = func(name string) (string, error) {
		switch name {
		case "dnf":
			return "/usr/bin/dnf", nil
		case "systemctl":
			return "/usr/bin/systemctl", nil
		default:
			return "", os.ErrNotExist
		}
	}
	u.attestRPM = func(ctx context.Context, currentVersion string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("RPM release attestation has no deadline")
		}
		call := attestations.Add(1)
		if call == 2 {
			return errors.New("installed RPM release changed during download")
		}
		return validateInstalledStandardRPMRelease(
			[]byte("syswarden\t0\t4.02.8\t1\tx86_64\n"),
			currentVersion,
		)
	}

	err = u.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "immediately before package installation") {
		t.Fatalf("updater.run() error = %v, want final RPM attestation failure", err)
	}
	if !packageDownloaded.Load() {
		t.Fatal("test did not reach the post-download RPM attestation")
	}
	if attestations.Load() != 2 {
		t.Fatalf("RPM release attestations = %d, want 2", attestations.Load())
	}
	if installations.Load() != 0 {
		t.Fatalf("RPM installations = %d, want 0", installations.Load())
	}
}

func TestNonRPMUpdaterDoesNotInvokeRPMReleaseAttestation(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	u := &updater{attestRPM: func(context.Context, string) error {
		calls.Add(1)
		return errors.New("must not run")
	}}
	for _, format := range []string{packageFormatDEB, packageFormatAPK} {
		if err := u.attestStandardRPMChannel(t.Context(), packageTarget{format: format}, "test"); err != nil {
			t.Fatalf("attestStandardRPMChannel(%s) error = %v", format, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("RPM release attestation calls for DEB/APK = %d, want 0", calls.Load())
	}
	if err := (&updater{}).attestStandardRPMChannel(
		t.Context(),
		packageTarget{format: packageFormatRPM},
		"test",
	); err == nil || !strings.Contains(err.Error(), "attestation is unavailable") {
		t.Fatalf("missing RPM release attestor error = %v", err)
	}
}
