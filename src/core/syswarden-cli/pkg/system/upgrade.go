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
	"time"
)

var Version = "v4.02.13"

const (
	latestReleaseAPI             = "https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
	releaseDownloadBase          = "https://github.com/duggytuxy/syswarden/releases/download"
	firstSignedUpdaterMajor      = 4
	firstSignedUpdaterMinor      = 2
	firstSignedUpdaterPatch      = 9
	metadataDownloadTimeout      = 30 * time.Second
	packageDownloadTimeout       = 10 * time.Minute
	packageInstallationTimeout   = 30 * time.Minute
	postInstallationCommandLimit = 2 * time.Minute
	productionTempBase           = "/var/tmp"
)

// The public baseline predates this manifest contract. Its one-time transition
// must therefore use the separately documented, manually verified package
// procedure. The signed updater deliberately has no unsigned fallback.

func firstSignedUpdaterVersion() string {
	return fmt.Sprintf("v%d.%02d.%d", firstSignedUpdaterMajor, firstSignedUpdaterMinor, firstSignedUpdaterPatch)
}

type commandRunner func(context.Context, string, ...string) error

type updater struct {
	client          *http.Client
	latestURL       string
	downloadBaseURL string
	currentVersion  string
	goos            string
	goarch          string
	tempBase        string
	trustedKeys     map[string]ed25519.PublicKey
	lookPath        func(string) (string, error)
	runCommand      commandRunner
	effectiveUID    int
	requireRoot     bool
	stdout          io.Writer
	metadataTimeout time.Duration
	packageTimeout  time.Duration
	installTimeout  time.Duration
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

func runExternalCommand(ctx context.Context, name string, args ...string) error {
	if err := validateExternalCommand(name, args); err != nil {
		return err
	}
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
	case "/usr/sbin/pkg":
		cmd = exec.CommandContext(ctx, "/usr/sbin/pkg")
	case "/usr/local/sbin/pkg":
		cmd = exec.CommandContext(ctx, "/usr/local/sbin/pkg")
	case "/opt/syswarden/bin/syswarden-cli":
		cmd = exec.CommandContext(ctx, "/opt/syswarden/bin/syswarden-cli")
	case "/usr/local/syswarden/bin/syswarden-cli":
		cmd = exec.CommandContext(ctx, "/usr/local/syswarden/bin/syswarden-cli")
	case "/sbin/rc-service":
		cmd = exec.CommandContext(ctx, "/sbin/rc-service")
	case "/usr/sbin/rc-service":
		cmd = exec.CommandContext(ctx, "/usr/sbin/rc-service")
	case "/bin/systemctl":
		cmd = exec.CommandContext(ctx, "/bin/systemctl")
	case "/usr/bin/systemctl":
		cmd = exec.CommandContext(ctx, "/usr/bin/systemctl")
	case "/usr/sbin/service":
		cmd = exec.CommandContext(ctx, "/usr/sbin/service")
	default:
		return fmt.Errorf("refusing untrusted executable path %q", name)
	}
	cmd.Args = append([]string{cmd.Path}, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func validateExternalCommand(name string, args []string) error {
	switch name {
	case "/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum":
		if len(args) == 3 && args[0] == "install" && args[1] == "-y" && validSecurePackageArgument(args[2]) {
			return nil
		}
	case "/sbin/apk", "/usr/sbin/apk":
		if len(args) == 3 && args[0] == "add" && args[1] == "--allow-untrusted" && validSecurePackageArgument(args[2]) {
			return nil
		}
	case "/usr/sbin/pkg", "/usr/local/sbin/pkg":
		if len(args) == 3 && args[0] == "add" && args[1] == "-f" && validSecurePackageArgument(args[2]) {
			return nil
		}
	case "/opt/syswarden/bin/syswarden-cli", "/usr/local/syswarden/bin/syswarden-cli":
		if len(args) == 1 && args[0] == "web-token" {
			return nil
		}
	case "/sbin/rc-service", "/usr/sbin/rc-service":
		if len(args) == 2 && args[1] == "restart" && (args[0] == "syswarden-core" || args[0] == "syswarden-webtui") {
			return nil
		}
	case "/bin/systemctl", "/usr/bin/systemctl":
		if len(args) == 1 && args[0] == "daemon-reload" {
			return nil
		}
		if len(args) == 2 && args[0] == "restart" && (args[1] == "syswarden-core" || args[1] == "syswarden-webtui") {
			return nil
		}
	case "/usr/sbin/service":
		if len(args) == 2 && (args[1] == "restart" || args[1] == "onestatus") &&
			(args[0] == "syswarden" || args[0] == "syswardenwebtui") {
			return nil
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
		client:          productionHTTPClient(),
		latestURL:       latestReleaseAPI,
		downloadBaseURL: releaseDownloadBase,
		currentVersion:  Version,
		goos:            runtime.GOOS,
		goarch:          runtime.GOARCH,
		tempBase:        productionTempBase,
		trustedKeys:     trustedKeys,
		lookPath:        exec.LookPath,
		runCommand:      runExternalCommand,
		effectiveUID:    os.Geteuid(),
		requireRoot:     true,
		stdout:          os.Stdout,
		metadataTimeout: metadataDownloadTimeout,
		packageTimeout:  packageDownloadTimeout,
		installTimeout:  packageInstallationTimeout,
	}, nil
}

// UpgradeSystem checks for a newer release and installs only a package bound to
// an authenticated v1 update manifest.
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
		fmt.Fprintln(u.stdout, "[SUCCESS] You are already using the latest version of SYSWARDEN!")
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

	target, err := detectPackageTarget(u.goos, u.goarch, latestVersion, u.lookPath)
	if err != nil {
		return err
	}

	fmt.Fprintln(u.stdout, "[+] A new Enterprise version is available!")
	fmt.Fprintf(u.stdout, "[INFO] Selected %s package %s for %s/%s.\n", target.format, target.filename, u.goos, u.goarch)

	manifest, err := u.fetchAndVerifyManifest(ctx, latestVersion)
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

	fmt.Fprintf(u.stdout, "[INFO] Installing authenticated %s package...\n", target.format)
	installCtx, cancelInstall := context.WithTimeout(ctx, u.installTimeout)
	err = u.runCommand(installCtx, target.installer, target.installArguments(packagePath)...)
	cancelInstall()
	if err != nil {
		return fmt.Errorf("install %s package: %w", target.format, err)
	}

	if err := u.finishUpgrade(ctx, target); err != nil {
		return fmt.Errorf("package installed but post-install activation failed: %w", err)
	}
	return nil
}

func (u *updater) validateConfiguration() error {
	if u.client == nil || u.lookPath == nil || u.runCommand == nil || u.stdout == nil {
		return errors.New("updater dependencies are incomplete")
	}
	if u.metadataTimeout <= 0 || u.packageTimeout <= 0 || u.installTimeout <= 0 {
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

func (u *updater) fetchAndVerifyManifest(ctx context.Context, version string) (*updateManifest, error) {
	if len(u.trustedKeys) == 0 {
		return nil, errors.New("no trusted Ed25519 release keys are embedded; refusing update")
	}
	manifestURL, err := releaseAssetURL(u.downloadBaseURL, version, updateManifestAssetName)
	if err != nil {
		return nil, err
	}
	signatureURL, err := releaseAssetURL(u.downloadBaseURL, version, updateManifestSignatureAssetName)
	if err != nil {
		return nil, err
	}

	metadataCtx, cancel := context.WithTimeout(ctx, u.metadataTimeout)
	manifestBytes, err := downloadBoundedBytes(metadataCtx, u.client, manifestURL, maxManifestBytes)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("download update manifest: %w", err)
	}
	metadataCtx, cancel = context.WithTimeout(ctx, u.metadataTimeout)
	signatureBytes, err := downloadBoundedBytes(metadataCtx, u.client, signatureURL, maxSignatureAssetBytes)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("download update manifest signature: %w", err)
	}

	manifest, err := verifySignedManifest(manifestBytes, signatureBytes, version, u.trustedKeys)
	if err != nil {
		return nil, fmt.Errorf("verify update manifest: %w", err)
	}
	return manifest, nil
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
	if (target.os == "freebsd") != (target.format == packageFormatTXZ) {
		return errors.New("package target operating system and format are inconsistent")
	}
	fmt.Fprintln(u.stdout, "\n[INFO] Upgrading SysWarden: Initializing Web-TUI...")
	activationCLI := "/opt/syswarden/bin/syswarden-cli"
	if target.os == "freebsd" {
		activationCLI = "/usr/local/syswarden/bin/syswarden-cli"
	}
	commandCtx, cancel := context.WithTimeout(ctx, postInstallationCommandLimit)
	webTokenErr := u.runCommand(commandCtx, activationCLI, "web-token")
	cancel()

	fmt.Fprintln(u.stdout, "[INFO] Restarting services to apply the new version...")
	errorsFound := make([]error, 0, 6)
	if webTokenErr != nil {
		errorsFound = append(errorsFound, fmt.Errorf("initialize Web-TUI token: %w", webTokenErr))
	}
	if target.os == "freebsd" {
		if err := u.runResolvedCommand(ctx, "service", "syswarden", "restart"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswarden: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "service", "syswarden", "onestatus"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("verify syswarden status: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "service", "syswardenwebtui", "restart"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswardenwebtui: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "service", "syswardenwebtui", "onestatus"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("verify syswardenwebtui status: %w", err))
		}
	} else if target.format == packageFormatAPK {
		if err := u.runResolvedCommand(ctx, "rc-service", "syswarden-core", "restart"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswarden-core: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "rc-service", "syswarden-webtui", "restart"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswarden-webtui: %w", err))
		}
	} else {
		if err := u.runResolvedCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("reload systemd manager configuration: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "systemctl", "restart", "syswarden-core"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswarden-core: %w", err))
		}
		if err := u.runResolvedCommand(ctx, "systemctl", "restart", "syswarden-webtui"); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("restart syswarden-webtui: %w", err))
		}
	}
	if err := errors.Join(errorsFound...); err != nil {
		return err
	}
	fmt.Fprintln(u.stdout, "\n[+] In-place upgrade completed successfully!")
	fmt.Fprintln(u.stdout, "[INFO] Please restart your terminal session to use the new version.")
	return nil
}

func (u *updater) runResolvedCommand(ctx context.Context, name string, args ...string) error {
	resolved, err := u.lookPath(name)
	if err != nil {
		return fmt.Errorf("locate %s: %w", name, err)
	}
	commandCtx, cancel := context.WithTimeout(ctx, postInstallationCommandLimit)
	err = u.runCommand(commandCtx, resolved, args...)
	cancel()
	return err
}

func safeAssetName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\\`) && len(name) <= 255
}
