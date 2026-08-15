//go:build freebsd

package system

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	freeBSDUpdaterE2EEnabledEnv   = "SYSWARDEN_FREEBSD_UPDATER_E2E"
	freeBSDUpdaterE2EManifestEnv  = "SYSWARDEN_FREEBSD_UPDATER_MANIFEST"
	freeBSDUpdaterE2ESignatureEnv = "SYSWARDEN_FREEBSD_UPDATER_SIGNATURE"
	freeBSDUpdaterE2EPackageEnv   = "SYSWARDEN_FREEBSD_UPDATER_PACKAGE"
	freeBSDUpdaterE2EReleaseEnv   = "SYSWARDEN_FREEBSD_UPDATER_RELEASE"
	freeBSDUpdaterE2EPreviousEnv  = "SYSWARDEN_FREEBSD_UPDATER_PREVIOUS"
	freeBSDUpdaterE2ESourceSHAEnv = "SYSWARDEN_FREEBSD_UPDATER_SOURCE_SHA"
)

// freeBSDUpdaterQualificationSourceSHA is populated only by the qualification
// workflow through -ldflags -X. A normal test binary deliberately remains
// unlinked and cannot run the real package transition.
var freeBSDUpdaterQualificationSourceSHA = "unlinked"

func TestFreeBSDSignedUpdaterRealPackageTransition_SW_UPD_002(t *testing.T) {
	if os.Getenv(freeBSDUpdaterE2EEnabledEnv) != "1" {
		t.Skip("real FreeBSD signed-updater transition is qualification-only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real FreeBSD signed-updater transition requires root")
	}
	requireFreeBSDUpdaterSourceSHA(t)

	release := requireFreeBSDUpdaterVersionEnv(t, freeBSDUpdaterE2EReleaseEnv)
	previous := requireFreeBSDUpdaterVersionEnv(t, freeBSDUpdaterE2EPreviousEnv)
	comparison, err := compareReleaseVersions(previous, release)
	if err != nil || comparison >= 0 {
		t.Fatalf("invalid FreeBSD updater transition %q -> %q: %v", previous, release, err)
	}
	wantPreviousPackageVersion := strings.TrimPrefix(previous, "v")
	requireFreeBSDQualificationOutput(t, "package-version", wantPreviousPackageVersion)
	manifestBytes := readFreeBSDUpdaterFixture(t, freeBSDUpdaterE2EManifestEnv, maxManifestBytes)
	signatureBytes := readFreeBSDUpdaterFixture(t, freeBSDUpdaterE2ESignatureEnv, maxSignatureAssetBytes)
	packageBytes := readFreeBSDUpdaterFixture(t, freeBSDUpdaterE2EPackageEnv, maxPackageBytes)
	packageName, err := packageFilename(release, packageFormatTXZ, "amd64")
	if err != nil {
		t.Fatalf("derive FreeBSD package name: %v", err)
	}
	tamperedSignature := bytes.Clone(signatureBytes)
	if len(tamperedSignature) == 0 {
		t.Fatal("production signature fixture is empty")
	}
	tamperedSignature[0] ^= 1
	server := newFreeBSDUpdaterTLSServer(t, release, packageName, manifestBytes, signatureBytes, tamperedSignature, packageBytes)

	var rejectedCommands atomic.Int32
	rejected := freeBSDQualificationUpdater(
		t, server.Client(), server.URL+"/latest", server.URL+"/invalid", previous,
		func(context.Context, string, ...string) error {
			rejectedCommands.Add(1)
			return errors.New("command execution must remain unreachable for rejected metadata")
		},
	)
	if err := rejected.run(t.Context()); err == nil {
		t.Fatal("FreeBSD updater accepted a tampered production signature")
	}
	if rejectedCommands.Load() != 0 {
		t.Fatalf("FreeBSD updater executed %d commands after rejecting metadata", rejectedCommands.Load())
	}
	requireFreeBSDQualificationOutput(t, "package-version", wantPreviousPackageVersion)

	qualified := freeBSDQualificationUpdater(
		t, server.Client(), server.URL+"/latest", server.URL+"/qualified", previous, runExternalCommand,
	)
	if err := qualified.run(t.Context()); err != nil {
		t.Fatalf("real FreeBSD signed updater transition failed: %v", err)
	}

	wantPackageVersion := strings.TrimPrefix(release, "v")
	requireFreeBSDQualificationOutput(t, "package-version", wantPackageVersion)
	requireFreeBSDQualificationOutput(t, "core-enabled", "YES")
	requireFreeBSDQualificationOutput(t, "webtui-enabled", "YES")
	requireFreeBSDQualificationSuccess(t, "core-running")
	requireFreeBSDQualificationSuccess(t, "webtui-running")
}

func requireFreeBSDUpdaterSourceSHA(t *testing.T) {
	t.Helper()
	want := os.Getenv(freeBSDUpdaterE2ESourceSHAEnv)
	if len(want) != 40 {
		t.Fatalf("%s is not a canonical commit SHA", freeBSDUpdaterE2ESourceSHAEnv)
	}
	for _, character := range want {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			t.Fatalf("%s is not a canonical commit SHA", freeBSDUpdaterE2ESourceSHAEnv)
		}
	}
	if freeBSDUpdaterQualificationSourceSHA != want {
		t.Fatalf(
			"qualification binary source SHA = %q, want %q",
			freeBSDUpdaterQualificationSourceSHA,
			want,
		)
	}
}

func freeBSDQualificationUpdater(
	t *testing.T,
	client *http.Client,
	latestURL, downloadBaseURL, previous string,
	runner commandRunner,
) *updater {
	t.Helper()
	candidate, err := newProductionUpdater()
	if err != nil {
		t.Fatalf("construct production updater: %v", err)
	}
	if candidate.goos != "freebsd" || candidate.goarch != "amd64" || candidate.tempBase != productionTempBase ||
		candidate.effectiveUID != 0 || !candidate.requireRoot {
		t.Fatalf("qualification binary is not the exact FreeBSD amd64 root updater: %#v", candidate)
	}
	candidate.client = client
	candidate.latestURL = latestURL
	candidate.downloadBaseURL = downloadBaseURL
	candidate.currentVersion = previous
	candidate.runCommand = runner
	candidate.stdout = io.Discard
	return candidate
}

func newFreeBSDUpdaterTLSServer(
	t *testing.T,
	release, packageName string,
	manifestBytes, signatureBytes, tamperedSignature, packageBytes []byte,
) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body []byte
		switch request.URL.Path {
		case "/latest":
			body = []byte(fmt.Sprintf(`{"tag_name":%q}`, release))
		case "/qualified/" + release + "/" + updateManifestAssetName,
			"/invalid/" + release + "/" + updateManifestAssetName:
			body = manifestBytes
		case "/qualified/" + release + "/" + updateManifestSignatureAssetName:
			body = signatureBytes
		case "/invalid/" + release + "/" + updateManifestSignatureAssetName:
			body = tamperedSignature
		case "/qualified/" + release + "/" + packageName,
			"/invalid/" + release + "/" + packageName:
			body = packageBytes
		default:
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write(body); err != nil {
			t.Errorf("serve FreeBSD updater fixture: %v", err)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func requireFreeBSDUpdaterVersionEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if _, err := parseReleaseVersion(value); err != nil {
		t.Fatalf("%s is not a canonical SysWarden version: %v", name, err)
	}
	return value
}

func readFreeBSDUpdaterFixture(t *testing.T, environment string, limit int64) []byte {
	t.Helper()
	path := os.Getenv(environment)
	if path == "" || !filepath.IsAbs(path) || limit <= 0 {
		t.Fatalf("%s does not identify a bounded absolute fixture", environment)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open %s fixture directory: %v", environment, err)
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		t.Fatalf("%s fixture is not a bounded regular file", environment)
	}
	file, err := root.Open(name)
	if err != nil {
		t.Fatalf("open %s fixture: %v", environment, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		t.Fatalf("%s fixture identity changed while opening", environment)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != info.Size() || int64(len(data)) > limit {
		t.Fatalf("read bounded %s fixture: %v", environment, err)
	}
	return data
}

func freeBSDQualificationCommand(name string) *exec.Cmd {
	switch name {
	case "package-version":
		return exec.Command("/usr/sbin/pkg", "query", "%v", "syswarden")
	case "core-enabled":
		return exec.Command("/usr/sbin/sysrc", "-n", "syswarden_enable")
	case "webtui-enabled":
		return exec.Command("/usr/sbin/sysrc", "-n", "syswardenwebtui_enable")
	case "core-running":
		return exec.Command("/usr/sbin/service", "syswarden", "onestatus")
	case "webtui-running":
		return exec.Command("/usr/sbin/service", "syswardenwebtui", "onestatus")
	default:
		return nil
	}
}

func requireFreeBSDQualificationOutput(t *testing.T, commandName, expected string) {
	t.Helper()
	command := freeBSDQualificationCommand(commandName)
	if command == nil {
		t.Fatalf("unknown FreeBSD qualification command %q", commandName)
	}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("FreeBSD qualification command %q failed: %v", commandName, err)
	}
	if strings.TrimSpace(string(output)) != expected {
		t.Fatalf("FreeBSD qualification command %q output = %q, want %q", commandName, output, expected)
	}
}

func requireFreeBSDQualificationSuccess(t *testing.T, commandName string) {
	t.Helper()
	command := freeBSDQualificationCommand(commandName)
	if command == nil {
		t.Fatalf("unknown FreeBSD qualification command %q", commandName)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FreeBSD qualification command %q failed: %v: %s", commandName, err, output)
	}
}
