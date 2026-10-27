package system

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syswarden-cli/config"
	"time"
)

var Version = "v4.10.4"

const (
	latestReleaseAPI           = "https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
	releaseDownloadBase        = "https://github.com/duggytuxy/syswarden/releases/download"
	firstSignedUpdaterMajor    = 4
	firstSignedUpdaterMinor    = 2
	firstSignedUpdaterPatch    = 9
	metadataDownloadTimeout    = 30 * time.Second
	packageDownloadTimeout     = 10 * time.Minute
	packageInstallationTimeout = 30 * time.Minute
	qualificationAttestTimeout = 2 * time.Minute
	productionTempBase         = "/var/tmp"
)

// The public baseline predates this manifest contract. Its one-time transition
// must therefore use the separately documented, manually verified package
// procedure. The signed updater deliberately has no unsigned fallback.

func firstSignedUpdaterVersion() string {
	return fmt.Sprintf("v%d.%02d.%d", firstSignedUpdaterMajor, firstSignedUpdaterMinor, firstSignedUpdaterPatch)
}

type commandRunner func(context.Context, string, ...string) error
type installedRPMReleaseAttestor func(context.Context, string, string) error
type installedVersionAttestor func(context.Context, packageTarget, int) (installedQualificationEvidence, error)
type qualificationActivator func(context.Context, installedQualificationEvidence) error
type qualificationDependencyAttestor func(context.Context, packageTarget) error
type qualificationCandidateCLIAttestor func(context.Context, packageTarget, *os.File) (string, error)

type updater struct {
	client                  *http.Client
	latestURL               string
	downloadBaseURL         string
	currentVersion          string
	goos                    string
	goarch                  string
	tempBase                string
	trustedKeys             map[string]ed25519.PublicKey
	lookPath                func(string) (string, error)
	installPackage          nativePackageInstaller
	prepareAPKTransition    apkTransitionPreparer
	effectiveUID            int
	requireRoot             bool
	stdout                  io.Writer
	metadataTimeout         time.Duration
	packageTimeout          time.Duration
	installTimeout          time.Duration
	attestTimeout           time.Duration
	retireWebTUI            func() error
	attestRPM               installedRPMReleaseAttestor
	preflightNativeIdentity func(context.Context) (nativeUpdateIdentity, error)
	attestInstalled         installedVersionAttestor
	attestDependencies      qualificationDependencyAttestor
	attestCandidateCLI      qualificationCandidateCLIAttestor
	attestPackageIdentity   nativePackageHeaderAttestor
	activateCandidate       qualificationActivator
}

func productionHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many HTTP redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("release download redirect is not HTTPS")
			}
			return nil
		},
		Timeout: packageDownloadTimeout + time.Minute,
	}
}

func productionCommandEnvironment(name string) []string {
	if productionPackageManager(name) {
		return productionNativeCommandEnvironment()
	}
	return productionExternalCommandEnvironment()
}

// The package execution boundary is independent of the manager-specific
// retention backend. APK retains requirements within its add transaction.
func productionPackageManager(name string) bool {
	switch name {
	case "/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk":
		return true
	default:
		return false
	}
}

func productionExternalCommandEnvironment() []string {
	environment := os.Environ()
	filtered := make([]string, 0, len(environment))
	privatePrefixes := []string{
		offlineQualificationEnvironment + "=",
		"SYSWARDEN_PKG_INSTALL=",
		nativeInstallPhaseEnvironment + "=",
	}
	for _, entry := range environment {
		private := false
		for _, prefix := range privatePrefixes {
			if strings.HasPrefix(entry, prefix) {
				private = true
				break
			}
		}
		if private {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func executeExternalCommand(ctx context.Context, name string, environment []string, args ...string) error {
	cmd, err := productionExternalCommand(ctx, name, environment, args...)
	if err != nil {
		return err
	}
	return cmd.Run()
}

// Construct without executing so callers can inspect the actual fixed-path
// command boundary without invoking a package manager or changing its database.
func productionExternalCommand(ctx context.Context, name string, environment []string, args ...string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch name {
	case "/usr/bin/apt-get":
		cmd = exec.CommandContext(ctx, "/usr/bin/apt-get")
	case "/usr/bin/dnf":
		cmd = exec.CommandContext(ctx, "/usr/bin/dnf")
	case "/usr/bin/yum":
		cmd = exec.CommandContext(ctx, "/usr/bin/yum")
	case "/sbin/apk":
		cmd = exec.CommandContext(ctx, "/sbin/apk")
	case "/usr/sbin/apk":
		cmd = exec.CommandContext(ctx, "/usr/sbin/apk")
	case "/opt/syswarden/bin/syswarden-cli":
		cmd = exec.CommandContext(ctx, "/opt/syswarden/bin/syswarden-cli")
	case "/sbin/rc-service":
		cmd = exec.CommandContext(ctx, "/sbin/rc-service")
	case "/usr/sbin/rc-service":
		cmd = exec.CommandContext(ctx, "/usr/sbin/rc-service")
	case "/bin/systemctl":
		cmd = exec.CommandContext(ctx, "/bin/systemctl")
	case "/usr/bin/systemctl":
		cmd = exec.CommandContext(ctx, "/usr/bin/systemctl")
	default:
		return nil, fmt.Errorf("refusing untrusted executable path %q", name)
	}
	if productionPackageManager(name) {
		cmd.Dir = "/"
	}
	cmd.Args = append([]string{cmd.Path}, args...)
	if environment != nil {
		cmd.Env = environment
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func validateExternalCommand(name string, args []string) error {
	switch name {
	case "/usr/bin/apt-get":
		if len(args) != 7 {
			break
		}
		if args[0] == "-o" && args[1] == aptDPkgLockTimeoutOption && args[2] == "--no-install-recommends" &&
			args[3] == "--no-remove" && args[4] == "install" && args[5] == "-y" && validSecurePackageArgument(args[6]) {
			return nil
		}
	case "/usr/bin/dnf", "/usr/bin/yum":
		if len(args) != 7 {
			break
		}
		if args[0] == "--setopt=localpkg_gpgcheck=1" && args[1] == "--setopt=install_weak_deps=False" &&
			args[2] == "--setopt=clean_requirements_on_remove=False" && args[3] == "--setopt=obsoletes=False" &&
			args[4] == "install" && args[5] == "-y" && validSecurePackageArgument(args[6]) {
			return nil
		}
	case "/sbin/apk", "/usr/sbin/apk":
		if len(args) != 2 {
			break
		}
		if args[0] == "add" && validSecurePackageArgument(args[1]) {
			return nil
		}
	case "/sbin/rc-service", "/usr/sbin/rc-service":
		if len(args) != 2 {
			break
		}
		if args[0] == "syswarden-core" && args[1] == "restart" {
			return nil
		}
	case "/bin/systemctl", "/usr/bin/systemctl":
		switch len(args) {
		case 1:
			if args[0] == "daemon-reload" {
				return nil
			}
		case 2:
			if args[0] == "restart" && args[1] == "syswarden-core" {
				return nil
			}
		}
	}
	return fmt.Errorf("refusing unexpected arguments for %q", name)
}

func validSecurePackageArgument(path string) bool {
	if !strings.HasPrefix(path, productionTempBase+"/syswarden-update-") {
		return false
	}
	name := strings.TrimPrefix(path, productionTempBase+"/syswarden-update-")
	separator := strings.IndexByte(name, '/')
	return separator > 0 && safeAssetName(name[separator+1:])
}

func newProductionUpdater() (*updater, error) {
	trustedKeys, err := embeddedTrustedReleaseKeys()
	if err != nil {
		return nil, err
	}

	return &updater{
		client:                  productionHTTPClient(),
		latestURL:               latestReleaseAPI,
		downloadBaseURL:         releaseDownloadBase,
		currentVersion:          Version,
		goos:                    runtime.GOOS,
		goarch:                  runtime.GOARCH,
		tempBase:                productionTempBase,
		trustedKeys:             trustedKeys,
		lookPath:                exec.LookPath,
		installPackage:          runAuthenticatedNativeInstall,
		prepareAPKTransition:    prepareProductionAPKTransition,
		effectiveUID:            os.Geteuid(),
		requireRoot:             true,
		stdout:                  os.Stdout,
		metadataTimeout:         metadataDownloadTimeout,
		packageTimeout:          packageDownloadTimeout,
		installTimeout:          packageInstallationTimeout,
		attestTimeout:           qualificationAttestTimeout,
		attestRPM:               attestInstalledStandardRPMRelease,
		preflightNativeIdentity: preflightStandardNativeUpdate,
		attestInstalled:         attestInstalledQualificationVersion,
		attestCandidateCLI:      attestQualificationPackageCLI,
		attestPackageIdentity:   attestNativePackageHeader,
		retireWebTUI: func() error {
			return config.RemoveRetiredWebTUIConfiguration("/etc/syswarden/config")
		},
	}, nil
}

// UpgradeSystem checks for a newer release and installs only a package bound to
// an authenticated release manifest.
func UpgradeSystem() error {
	u, err := newProductionUpdater()
	if err != nil {
		return err
	}
	return u.run(context.Background())
}

func (u *updater) run(ctx context.Context) (returnErr error) {
	if err := u.validateConfiguration(); err != nil {
		return err
	}

	identity, err := u.preflightStandardNativeIdentity(ctx, u.metadataTimeout)
	if err != nil {
		return err
	}

	fmt.Fprintln(u.stdout, "[INFO] Checking for SYSWARDEN updates via GitHub API...")
	latestVersion, err := u.fetchLatestVersion(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintf(u.stdout, "Current Version : %s\n", u.currentVersion)
	fmt.Fprintf(u.stdout, "Latest Version  : %s\n", latestVersion)

	comparison, err := compareReleaseVersions(u.currentVersion, latestVersion)
	if err != nil {
		return fmt.Errorf("compare release versions: %w", err)
	}
	if comparison == 0 {
		if u.attestInstalled == nil {
			return errors.New("current release cannot be confirmed without installed-package attestation")
		}
		target, err := detectPackageTarget(u.goos, u.goarch, latestVersion, identity, u.lookPath)
		if err != nil {
			return err
		}
		attestationCtx, cancel := context.WithTimeout(ctx, u.metadataTimeout)
		defer cancel()
		if err := attestationCtx.Err(); err != nil {
			return fmt.Errorf("attest current installed package: %w", err)
		}
		evidence, err := u.attestInstalled(attestationCtx, target, u.effectiveUID)
		err = errors.Join(err, attestationCtx.Err())
		if err != nil {
			return fmt.Errorf("release version is current, but installed package state or integrity is not verified; inspect the native package manager and resolve any incomplete configuration: %w", err)
		}
		if evidence.version != u.currentVersion {
			return fmt.Errorf("installed package version %s does not match running CLI %s", evidence.version, u.currentVersion)
		}
		fmt.Fprintln(u.stdout, "[SUCCESS] Release version is current and installed package state and integrity are verified.")
		fmt.Fprintln(u.stdout, "[INFO] This update check does not verify service, firewall or WireGuard runtime health.")
		return nil
	}
	if comparison > 0 {
		return fmt.Errorf("refusing release downgrade from %s to %s", u.currentVersion, latestVersion)
	}
	minimumComparison, err := compareReleaseVersions(latestVersion, firstSignedUpdaterVersion())
	if err != nil {
		return fmt.Errorf("compare first signed release: %w", err)
	}
	if minimumComparison < 0 {
		return fmt.Errorf("release %s predates the signed updater contract", latestVersion)
	}

	target, err := detectPackageTarget(u.goos, u.goarch, latestVersion, identity, u.lookPath)
	if err != nil {
		return err
	}
	if err := u.attestStandardRPMChannel(ctx, target, "before release asset download"); err != nil {
		return err
	}

	fmt.Fprintln(u.stdout, "[+] A new Enterprise version is available!")
	fmt.Fprintf(u.stdout, "[INFO] Selected %s package %s for %s/%s.\n", target.format, target.filename, u.goos, u.goarch)

	manifest, manifestBytes, signatureBytes, err := u.fetchAndVerifyManifestProof(ctx, latestVersion)
	if err != nil {
		return err
	}
	artifact, err := manifest.artifactFor(target)
	if err != nil {
		return err
	}

	workspace, err := createSecureWorkspace(u.tempBase, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("create secure update workspace: %w", err)
	}
	defer func() {
		if retainAPKTransitionWorkspace(returnErr, workspace) {
			return
		}
		if cleanupErr := removeSecureWorkspace(workspace); cleanupErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean update workspace: %w", cleanupErr))
		}
	}()

	packageFile, packagePath, err := createSecureExclusiveFile(workspace, artifact.Filename, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("create secure package file: %w", err)
	}
	defer func() {
		if closeErr := packageFile.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close package file: %w", closeErr))
		}
	}()

	packageURL, err := releaseAssetURL(u.downloadBaseURL, latestVersion, artifact.Filename)
	if err != nil {
		return err
	}
	fmt.Fprintf(u.stdout, "[INFO] Downloading authenticated package %s...\n", packageURL)
	packageCtx, cancelPackage := context.WithTimeout(ctx, u.packageTimeout)
	err = downloadVerifiedPackage(packageCtx, u.client, packageURL, packageFile, artifact, u.effectiveUID)
	cancelPackage()
	if err != nil {
		return fmt.Errorf("download package: %w", err)
	}
	if err := validateSecureWorkspace(workspace, u.effectiveUID); err != nil {
		return fmt.Errorf("validate update workspace before installation: %w", err)
	}
	if err := verifySecurePackageForInstallation(packageFile, packagePath, artifact, u.effectiveUID); err != nil {
		return fmt.Errorf("verify package immediately before installation: %w", err)
	}
	if err := u.attestAuthenticatedPackageIdentity(ctx, target, latestVersion, packageFile, u.metadataTimeout); err != nil {
		return fmt.Errorf("attest authenticated native package identity before installation: %w", err)
	}
	if err := verifySecurePackageForInstallation(packageFile, packagePath, artifact, u.effectiveUID); err != nil {
		return fmt.Errorf("reverify package after native header attestation: %w", err)
	}
	payloadAttestationCtx, cancelPayloadAttestation := context.WithTimeout(ctx, u.attestTimeout)
	if err := payloadAttestationCtx.Err(); err != nil {
		cancelPayloadAttestation()
		return fmt.Errorf("attest candidate CLI from authenticated package: %w", err)
	}
	expectedCandidateCLISHA256, err := u.attestCandidateCLI(payloadAttestationCtx, target, packageFile)
	err = errors.Join(err, payloadAttestationCtx.Err())
	cancelPayloadAttestation()
	if err != nil {
		return fmt.Errorf("attest candidate CLI from authenticated package: %w", err)
	}
	if !validSHA256(expectedCandidateCLISHA256) {
		return errors.New("authenticated package CLI attestation lacks a valid SHA-256 digest")
	}
	if err := verifySecurePackageForInstallation(packageFile, packagePath, artifact, u.effectiveUID); err != nil {
		return fmt.Errorf("reverify package after candidate CLI attestation: %w", err)
	}
	if err := u.attestStandardRPMChannel(ctx, target, "immediately before package installation"); err != nil {
		return err
	}

	if err := u.recheckStandardNativeIdentity(ctx, u.metadataTimeout, identity); err != nil {
		return fmt.Errorf("native package identity changed before installation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifySecurePackageForInstallation(packageFile, packagePath, artifact, u.effectiveUID); err != nil {
		return fmt.Errorf("reverify package after native installation preflight: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := u.preflightAPKTransition(ctx, target, latestVersion, artifact, packageFile, packagePath, manifestBytes, signatureBytes, expectedCandidateCLISHA256, false); err != nil {
		return err
	}

	fmt.Fprintf(u.stdout, "[INFO] Installing authenticated %s package...\n", target.format)
	installCtx, cancelInstall := context.WithTimeout(ctx, u.installTimeout)
	err = u.installPackage(installCtx, target, packagePath, func(ctx context.Context) error {
		return verifyPackageAtNativeExecution(ctx, packageFile, packagePath, artifact, u.effectiveUID)
	})
	err = errors.Join(err, installCtx.Err())
	cancelInstall()
	if err != nil {
		return fmt.Errorf("install %s package: %w", target.format, err)
	}

	if err := u.recheckStandardNativeIdentity(ctx, u.attestTimeout, identity); err != nil {
		return fmt.Errorf("package transaction completed but native package identity changed: %w", err)
	}
	installedCandidate, err := u.attestQualificationInstallation(ctx, target, "post-install")
	if err != nil {
		return fmt.Errorf("package transaction completed but candidate attestation failed: %w", err)
	}
	if installedCandidate.version != latestVersion {
		return fmt.Errorf("package transaction installed version %s, want exact candidate %s", installedCandidate.version, latestVersion)
	}
	if installedCandidate.cliSHA256 != expectedCandidateCLISHA256 {
		return fmt.Errorf("installed candidate CLI SHA-256 %s does not match authenticated package payload %s", installedCandidate.cliSHA256, expectedCandidateCLISHA256)
	}

	if err := u.finishUpgrade(ctx, target); err != nil {
		return fmt.Errorf("package installed but post-install finalization failed: %w", err)
	}
	return nil
}

func (u *updater) validateConfiguration() error {
	if u.client == nil || u.lookPath == nil || u.installPackage == nil || u.stdout == nil || u.preflightNativeIdentity == nil || u.attestPackageIdentity == nil || u.attestInstalled == nil || u.attestCandidateCLI == nil {
		return errors.New("updater dependencies are incomplete")
	}
	if u.metadataTimeout <= 0 || u.packageTimeout <= 0 || u.installTimeout <= 0 || u.attestTimeout <= 0 {
		return errors.New("updater timeouts must be positive")
	}
	for label, rawURL := range map[string]string{"release API": u.latestURL, "release download base": u.downloadBaseURL} {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("%s must be an absolute HTTPS URL", label)
		}
	}
	if u.effectiveUID < 0 {
		return errors.New("effective user ID is invalid")
	}
	if u.requireRoot && u.effectiveUID != 0 {
		return errors.New("signed package updates require root privileges")
	}
	return nil
}

func (u *updater) fetchLatestVersion(ctx context.Context) (string, error) {
	metadataCtx, cancel := context.WithTimeout(ctx, u.metadataTimeout)
	defer cancel()

	body, err := downloadBoundedBytes(metadataCtx, u.client, u.latestURL, maxReleaseAPIBytes)
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.statusCode == http.StatusForbidden {
			return "", errors.New("GitHub API rate limit exceeded; try again later or authenticate")
		}
		return "", fmt.Errorf("query latest GitHub release: %w", err)
	}
	latestVersion, err := parseLatestRelease(body)
	if err != nil {
		return "", fmt.Errorf("parse latest GitHub release: %w", err)
	}
	return latestVersion, nil
}

func (u *updater) fetchAndVerifyManifestProof(ctx context.Context, version string) (*updateManifest, []byte, []byte, error) {
	if len(u.trustedKeys) == 0 {
		return nil, nil, nil, errors.New("no trusted Ed25519 release keys are embedded; refusing update")
	}
	manifestURL, err := releaseAssetURL(u.downloadBaseURL, version, updateManifestAssetName)
	if err != nil {
		return nil, nil, nil, err
	}
	signatureURL, err := releaseAssetURL(u.downloadBaseURL, version, updateManifestSignatureAssetName)
	if err != nil {
		return nil, nil, nil, err
	}

	metadataCtx, cancel := context.WithTimeout(ctx, u.metadataTimeout)
	manifestBytes, err := downloadBoundedBytes(metadataCtx, u.client, manifestURL, maxManifestBytes)
	cancel()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("download update manifest: %w", err)
	}
	metadataCtx, cancel = context.WithTimeout(ctx, u.metadataTimeout)
	signatureBytes, err := downloadBoundedBytes(metadataCtx, u.client, signatureURL, maxSignatureAssetBytes)
	cancel()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("download update manifest signature: %w", err)
	}

	manifest, err := verifySignedManifest(manifestBytes, signatureBytes, version, u.trustedKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verify update manifest: %w", err)
	}
	return manifest, manifestBytes, signatureBytes, nil
}

func releaseAssetURL(baseURL, version, assetName string) (string, error) {
	if _, err := parseReleaseVersion(version); err != nil {
		return "", fmt.Errorf("invalid release tag: %w", err)
	}
	if !safeAssetName(assetName) {
		return "", fmt.Errorf("invalid release asset name %q", assetName)
	}
	joined, err := url.JoinPath(baseURL, version, assetName)
	if err != nil {
		return "", fmt.Errorf("build release asset URL: %w", err)
	}
	parsed, err := url.Parse(joined)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", errors.New("release asset URL must be absolute HTTPS")
	}
	return parsed.String(), nil
}

func (u *updater) finishUpgrade(ctx context.Context, target packageTarget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if target.os != "linux" {
		return errors.New("package target operating system is not supported")
	}
	// Native hooks own activation and may deliberately stage a package while
	// preserving stopped, disabled or masked services. Never override that
	// disposition with a second restart here.
	errorsFound := make([]error, 0, 1)
	if u.retireWebTUI != nil {
		if err := u.retireWebTUI(); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("retire Web-TUI configuration: %w", err))
		}
	}
	errorsFound = append(errorsFound, ctx.Err())
	if err := errors.Join(errorsFound...); err != nil {
		return err
	}
	fmt.Fprintln(u.stdout, "\n[+] Native package transaction completed successfully!")
	fmt.Fprintln(u.stdout, "[INFO] Native hooks control activation; package success does not establish service or firewall health.")
	return nil
}

func safeAssetName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\\`) && len(name) <= 255
}
