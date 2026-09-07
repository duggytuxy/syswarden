package system

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"time"

	"golang.org/x/sys/unix"
)

const qualificationChannelDisclosure = "This pre-publication path attests the candidate CLI; it does not attest execution of the installed production updater."

const installedSyswardenCLIPath = "/opt/syswarden/bin/syswarden-cli"

const offlineQualificationEnvironment = "SYSWARDEN_OFFLINE_QUALIFICATION"

const offlineQualificationActivationValue = "activate"

const qualificationCommandTerminationGrace = 2 * time.Second

const maximumQualificationPackageExpandedBytes = 2 * maxPackageBytes

const maximumQualificationDecoderDiagnostics = 4 * 1024

func qualificationTarHeaderIsRegular(typeflag byte) bool {
	return typeflag == tar.TypeReg || typeflag == 0
}

type qualificationCommandOutput func(context.Context, string, ...string) ([]byte, error)

type qualificationCommandExitError struct {
	code   int
	stderr []byte
}

func (failure *qualificationCommandExitError) Error() string {
	return fmt.Sprintf("qualification query exited with status %d", failure.code)
}

type qualificationBoundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *qualificationBoundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > len(data) {
		remaining = len(data)
	}
	if remaining > 0 {
		_, _ = buffer.buffer.Write(data[:remaining])
	}
	if remaining != len(data) {
		buffer.overflow = true
	}
	return written, nil
}

func (buffer *qualificationBoundedBuffer) Bytes() []byte {
	return bytes.Clone(buffer.buffer.Bytes())
}

type installedQualificationEvidence struct {
	version   string
	cliSHA256 string
}

type qualificationFileIdentity struct {
	device      uint64
	inode       uint64
	size        int64
	mode        uint32
	uid         uint32
	gid         uint32
	links       uint64
	modifiedSec int64
	modifiedNS  int64
	changedSec  int64
	changedNS   int64
	digest      [sha256.Size]byte
}

func identityFromQualificationStat(status unix.Stat_t) qualificationFileIdentity {
	return qualificationFileIdentity{
		device:      uint64(status.Dev),
		inode:       status.Ino,
		size:        status.Size,
		mode:        status.Mode,
		uid:         status.Uid,
		gid:         status.Gid,
		links:       uint64(status.Nlink),
		modifiedSec: status.Mtim.Sec,
		modifiedNS:  status.Mtim.Nsec,
		changedSec:  status.Ctim.Sec,
		changedNS:   status.Ctim.Nsec,
	}
}

// UpgradeSystemFromQualificationBundle installs one explicitly selected,
// unpublished candidate from a protected local bundle. This path deliberately
// has no HTTP client, release URL, discovery step, or network fallback.
func UpgradeSystemFromQualificationBundle(bundlePath, candidateVersion string) error {
	u, err := newQualificationUpdater()
	if err != nil {
		return err
	}
	return u.runQualificationBundle(context.Background(), bundlePath, candidateVersion)
}

func newQualificationUpdater() (*updater, error) {
	trustedKeys, err := embeddedTrustedReleaseKeys()
	if err != nil {
		return nil, err
	}
	return &updater{
		goos:               runtime.GOOS,
		goarch:             runtime.GOARCH,
		tempBase:           productionTempBase,
		trustedKeys:        trustedKeys,
		lookPath:           exec.LookPath,
		runCommand:         runQualificationExternalCommand,
		effectiveUID:       os.Geteuid(),
		requireRoot:        true,
		stdout:             os.Stdout,
		installTimeout:     packageInstallationTimeout,
		attestTimeout:      qualificationAttestTimeout,
		attestInstalled:    attestInstalledQualificationVersion,
		attestDependencies: attestOfflineQualificationPackageDependencies,
		attestCandidateCLI: attestQualificationPackageCLI,
		activateCandidate:  runQualificationActivationCommand,
		retireWebTUI: func() error {
			return config.RemoveRetiredWebTUIConfiguration("/etc/syswarden/config")
		},
	}, nil
}

func (u *updater) validateQualificationConfiguration() error {
	if u.lookPath == nil || u.runCommand == nil || u.stdout == nil || u.attestInstalled == nil ||
		u.attestDependencies == nil || u.attestCandidateCLI == nil || u.activateCandidate == nil {
		return errors.New("offline qualification updater dependencies are incomplete")
	}
	if u.installTimeout <= 0 {
		return errors.New("offline qualification installer timeout must be positive")
	}
	if u.attestTimeout <= 0 {
		return errors.New("offline qualification attestation timeout must be positive")
	}
	if len(u.trustedKeys) == 0 {
		return errors.New("no trusted Ed25519 release keys are embedded; refusing qualification update")
	}
	if u.effectiveUID < 0 {
		return errors.New("effective user ID is invalid")
	}
	if u.requireRoot && u.effectiveUID != 0 {
		return errors.New("signed package qualification updates require root privileges")
	}
	return nil
}

func validateQualificationCandidateVersion(candidateVersion string) error {
	if _, err := parseReleaseVersion(candidateVersion); err != nil {
		return fmt.Errorf("invalid candidate version: %w", err)
	}
	minimumComparison, err := compareReleaseVersions(candidateVersion, firstSignedUpdaterVersion())
	if err != nil {
		return fmt.Errorf("compare first signed release: %w", err)
	}
	if minimumComparison < 0 {
		return fmt.Errorf("qualification candidate %s predates the signed updater contract", candidateVersion)
	}
	return nil
}

func validateQualificationUpgrade(installedVersion, candidateVersion string) error {
	if _, err := parseReleaseVersion(installedVersion); err != nil {
		return fmt.Errorf("invalid attested installed version: %w", err)
	}
	comparison, err := compareReleaseVersions(installedVersion, candidateVersion)
	if err != nil {
		return fmt.Errorf("compare attested installed version with candidate: %w", err)
	}
	if comparison >= 0 {
		return fmt.Errorf("qualification candidate %s must be strictly newer than attested installed version %s", candidateVersion, installedVersion)
	}
	return nil
}

func (u *updater) attestQualificationInstallation(
	ctx context.Context,
	target packageTarget,
	label string,
) (installedQualificationEvidence, error) {
	attestationCtx, cancelAttestation := context.WithTimeout(ctx, u.attestTimeout)
	defer cancelAttestation()
	evidence, err := u.attestInstalled(attestationCtx, target, u.effectiveUID)
	if err != nil {
		return installedQualificationEvidence{}, fmt.Errorf("attest %s SysWarden version: %w", label, err)
	}
	if !validSHA256(evidence.cliSHA256) {
		return installedQualificationEvidence{}, fmt.Errorf("%s SysWarden CLI attestation lacks a valid SHA-256 digest", label)
	}
	return evidence, nil
}

func (u *updater) runQualificationBundle(ctx context.Context, bundlePath, candidateVersion string) (returnErr error) {
	if err := u.validateQualificationConfiguration(); err != nil {
		return err
	}
	if err := validateQualificationCandidateVersion(candidateVersion); err != nil {
		return err
	}
	bundle, err := openQualificationBundle(bundlePath, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("open offline qualification bundle: %w", err)
	}
	defer func() {
		if closeErr := bundle.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close offline qualification bundle: %w", closeErr))
		}
	}()

	fmt.Fprintln(u.stdout, "[INFO] Offline qualification bundle selected; network discovery and fallback are disabled.")
	fmt.Fprintf(u.stdout, "[NOTICE] %s\n", qualificationChannelDisclosure)
	fmt.Fprintf(u.stdout, "Candidate Version : %s\n", candidateVersion)

	manifestBytes, err := readQualificationBundleFile(bundle, updateManifestAssetName, maxManifestBytes, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("read qualification manifest: %w", err)
	}
	signatureBytes, err := readQualificationBundleFile(bundle, updateManifestSignatureAssetName, maxSignatureAssetBytes, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("read qualification manifest signature: %w", err)
	}
	manifest, err := verifySignedManifest(manifestBytes, signatureBytes, candidateVersion, u.trustedKeys)
	if err != nil {
		return fmt.Errorf("verify qualification update manifest: %w", err)
	}
	target, err := detectPackageTarget(u.goos, u.goarch, candidateVersion, u.lookPath)
	if err != nil {
		return err
	}
	artifact, err := manifest.artifactFor(target)
	if err != nil {
		return err
	}
	if err := validateQualificationBundleInventory(bundle, artifact.Filename); err != nil {
		return err
	}
	installedEvidence, err := u.attestQualificationInstallation(ctx, target, "installed")
	if err != nil {
		return err
	}
	if err := validateQualificationUpgrade(installedEvidence.version, candidateVersion); err != nil {
		return err
	}
	dependencyCtx, cancelDependencies := context.WithTimeout(ctx, u.attestTimeout)
	err = u.attestDependencies(dependencyCtx, target)
	cancelDependencies()
	if err != nil {
		return fmt.Errorf("attest locally installed dependencies before candidate transaction: %w", err)
	}
	fmt.Fprintf(u.stdout, "Installed Version    : %s\n", installedEvidence.version)
	fmt.Fprintf(u.stdout, "Installed CLI SHA-256: %s\n", installedEvidence.cliSHA256)
	fmt.Fprintf(u.stdout, "[INFO] Verified signed manifest for %s with embedded key %s.\n", candidateVersion, manifest.KeyID)
	fmt.Fprintf(u.stdout, "[INFO] Selected %s package %s for %s/%s.\n", target.format, artifact.Filename, u.goos, u.goarch)

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

	if err := copyVerifiedQualificationPackage(bundle, artifact, packageFile, u.effectiveUID); err != nil {
		return fmt.Errorf("copy authenticated qualification package: %w", err)
	}
	if err := validateQualificationBundle(bundle, u.effectiveUID); err != nil {
		return fmt.Errorf("revalidate qualification bundle before installation: %w", err)
	}
	if err := validateQualificationBundleInventory(bundle, artifact.Filename); err != nil {
		return fmt.Errorf("revalidate qualification bundle inventory before installation: %w", err)
	}
	manifestRecheck, err := readQualificationBundleFile(bundle, updateManifestAssetName, maxManifestBytes, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("reread qualification manifest before installation: %w", err)
	}
	signatureRecheck, err := readQualificationBundleFile(bundle, updateManifestSignatureAssetName, maxSignatureAssetBytes, u.effectiveUID)
	if err != nil {
		return fmt.Errorf("reread qualification manifest signature before installation: %w", err)
	}
	if !bytes.Equal(manifestBytes, manifestRecheck) || !bytes.Equal(signatureBytes, signatureRecheck) {
		return errors.New("qualification manifest or signature changed before installation")
	}
	if err := validateSecureWorkspace(workspace, u.effectiveUID); err != nil {
		return fmt.Errorf("validate update workspace before installation: %w", err)
	}
	if err := verifySecurePackageForInstallation(packageFile, packagePath, artifact, u.effectiveUID); err != nil {
		return fmt.Errorf("verify package immediately before installation: %w", err)
	}
	payloadAttestationCtx, cancelPayloadAttestation := context.WithTimeout(ctx, u.attestTimeout)
	expectedCandidateCLISHA256, err := u.attestCandidateCLI(payloadAttestationCtx, target, packageFile)
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
	fmt.Fprintf(u.stdout, "[INFO] Verified package SHA-256 %s.\n", artifact.SHA256)

	fmt.Fprintf(u.stdout, "[INFO] Installing authenticated %s qualification package without repository access...\n", target.format)
	installCtx, cancelInstall := context.WithTimeout(ctx, u.installTimeout)
	qualificationInstaller, qualificationArguments := target.qualificationInstallCommand(packagePath)
	err = u.runCommand(installCtx, qualificationInstaller, qualificationArguments...)
	cancelInstall()
	if err != nil {
		return fmt.Errorf("install %s qualification package: %w", target.format, err)
	}
	installedCandidate, err := u.attestQualificationInstallation(ctx, target, "post-install")
	if err != nil {
		return fmt.Errorf("qualification package transaction completed but candidate attestation failed: %w", err)
	}
	if installedCandidate.version != candidateVersion {
		return fmt.Errorf(
			"qualification package transaction installed version %s, want exact candidate %s",
			installedCandidate.version,
			candidateVersion,
		)
	}
	if installedCandidate.cliSHA256 != expectedCandidateCLISHA256 {
		return fmt.Errorf(
			"installed candidate CLI SHA-256 %s does not match authenticated package payload %s",
			installedCandidate.cliSHA256,
			expectedCandidateCLISHA256,
		)
	}
	preActivationCandidate, err := u.attestQualificationInstallation(ctx, target, "pre-activation")
	if err != nil {
		return fmt.Errorf("qualification candidate changed before activation: %w", err)
	}
	if preActivationCandidate != installedCandidate || preActivationCandidate.version != candidateVersion {
		return errors.New("qualification candidate package or CLI identity changed before activation")
	}
	fmt.Fprintf(u.stdout, "Installed Candidate Version    : %s\n", installedCandidate.version)
	fmt.Fprintf(u.stdout, "Installed Candidate CLI SHA-256: %s\n", installedCandidate.cliSHA256)
	fmt.Fprintln(u.stdout, "[INFO] Activating the exactly attested candidate through the offline qualification install path...")
	activationCtx, cancelActivation := context.WithTimeout(ctx, u.installTimeout)
	err = u.activateCandidate(activationCtx, preActivationCandidate)
	cancelActivation()
	if err != nil {
		return fmt.Errorf("qualification candidate attested but activation failed: %w", err)
	}
	fmt.Fprintln(u.stdout, "\n[+] Offline qualification upgrade completed successfully!")
	return nil
}

func openQualificationBundle(path string, expectedUID int) (*os.Root, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("qualification bundle path must be canonical, absolute, and non-root: %q", path)
	}
	current, err := openCanonicalQualificationDirectory(path, "qualification bundle")
	if err != nil {
		return nil, err
	}
	if err := validateQualificationBundle(current, expectedUID); err != nil {
		_ = current.Close()
		return nil, err
	}
	return current, nil
}

func openCanonicalQualificationDirectory(path, label string) (*os.Root, error) {
	if label == "" || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("%s path must be canonical, absolute, and non-root: %q", label, path)
	}
	current, err := os.OpenRoot("/")
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = current.Close()
			return nil, fmt.Errorf("%s has an invalid path component", label)
		}
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect %s component %q: %w", label, component, err)
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, fmt.Errorf("%s component %q is not a real directory", label, component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open %s component %q: %w", label, component, err)
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("%s component %q changed while opening", label, component)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func validateQualificationBundleInventory(bundle *os.Root, packageName string) error {
	if bundle == nil || !safeAssetName(packageName) {
		return errors.New("invalid qualification bundle inventory request")
	}
	directory, err := bundle.Open(".")
	if err != nil {
		return fmt.Errorf("open qualification bundle inventory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read qualification bundle inventory: %w", err)
	}
	expected := map[string]struct{}{
		updateManifestAssetName:          {},
		updateManifestSignatureAssetName: {},
		packageName:                      {},
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("qualification bundle contains %d entries, want exactly %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("qualification bundle contains unexpected entry %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("qualification bundle entry %q is not a regular non-symlink file", entry.Name())
		}
	}
	return nil
}

func validateQualificationBundle(bundle *os.Root, expectedUID int) error {
	if bundle == nil {
		return errors.New("qualification bundle handle is unavailable")
	}
	info, err := bundle.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect qualification bundle directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("qualification bundle is not a real directory")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("qualification bundle ownership metadata is unavailable")
	}
	if int(status.Uid) != expectedUID {
		return fmt.Errorf("qualification bundle owner is UID %d, want %d", status.Uid, expectedUID)
	}
	if status.Mode&07777 != 0700 {
		return fmt.Errorf("qualification bundle mode is %#o, want 0700", status.Mode&07777)
	}
	return nil
}

func openQualificationBundleFile(bundle *os.Root, name string, maximum int64, expectedUID int) (*os.File, qualificationFileIdentity, error) {
	if bundle == nil || !safeAssetName(name) || maximum <= 0 {
		return nil, qualificationFileIdentity{}, errors.New("invalid qualification bundle file request")
	}
	if err := validateQualificationBundle(bundle, expectedUID); err != nil {
		return nil, qualificationFileIdentity{}, err
	}
	pathInfo, err := bundle.Lstat(name)
	if err != nil {
		return nil, qualificationFileIdentity{}, fmt.Errorf("inspect qualification bundle file %q: %w", name, err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q is not a regular non-symlink file", name)
	}
	file, err := bundle.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, qualificationFileIdentity{}, fmt.Errorf("open qualification bundle file %q: %w", name, err)
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q changed while opening", name)
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &status); err != nil {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("inspect qualification bundle file %q descriptor: %w", name, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Nlink != 1 {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q must be regular with link count 1", name)
	}
	if int(status.Uid) != expectedUID {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q owner is UID %d, want %d", name, status.Uid, expectedUID)
	}
	if status.Mode&07777 != 0600 {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q mode is %#o, want 0600", name, status.Mode&07777)
	}
	if status.Size <= 0 || status.Size > maximum {
		_ = file.Close()
		return nil, qualificationFileIdentity{}, fmt.Errorf("qualification bundle file %q size %d is outside the accepted range", name, status.Size)
	}
	return file, identityFromQualificationStat(status), nil
}

func revalidateQualificationBundleFile(bundle *os.Root, file *os.File, name string, expected qualificationFileIdentity, expectedUID int) error {
	if err := validateQualificationBundle(bundle, expectedUID); err != nil {
		return err
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &status); err != nil {
		return fmt.Errorf("reinspect qualification bundle file %q descriptor: %w", name, err)
	}
	if identityFromQualificationStat(status) != expected {
		return fmt.Errorf("qualification bundle file %q changed while being consumed", name)
	}
	pathInfo, err := bundle.Lstat(name)
	if err != nil {
		return fmt.Errorf("reinspect qualification bundle file %q path: %w", name, err)
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		return fmt.Errorf("qualification bundle file %q path no longer names the open descriptor", name)
	}
	return nil
}

func readQualificationBundleFile(bundle *os.Root, name string, maximum int64, expectedUID int) (data []byte, returnErr error) {
	file, identity, err := openQualificationBundleFile(bundle, name, maximum, expectedUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close qualification bundle file %q: %w", name, closeErr))
		}
	}()
	data, err = io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read qualification bundle file %q: %w", name, err)
	}
	if int64(len(data)) != identity.size {
		return nil, fmt.Errorf("qualification bundle file %q read size is %d, want %d", name, len(data), identity.size)
	}
	if err := revalidateQualificationBundleFile(bundle, file, name, identity, expectedUID); err != nil {
		return nil, err
	}
	return data, nil
}

func attestInstalledQualificationVersion(ctx context.Context, target packageTarget, expectedUID int) (installedQualificationEvidence, error) {
	return attestInstalledQualificationVersionWith(
		ctx,
		target,
		expectedUID,
		installedSyswardenCLIPath,
		runQualificationCommandOutput,
	)
}

func attestInstalledQualificationVersionWith(
	ctx context.Context,
	target packageTarget,
	expectedUID int,
	binaryPath string,
	output qualificationCommandOutput,
) (evidence installedQualificationEvidence, returnErr error) {
	if output == nil || binaryPath == "" || !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		return installedQualificationEvidence{}, errors.New("invalid installed-version attestation configuration")
	}
	binaryRoot, binary, identity, err := openInstalledQualificationBinary(binaryPath, expectedUID)
	if err != nil {
		return installedQualificationEvidence{}, err
	}
	defer func() {
		if closeErr := binary.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close installed SysWarden CLI: %w", closeErr))
		}
		if closeErr := binaryRoot.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close installed SysWarden CLI directory: %w", closeErr))
		}
	}()

	var version string
	switch target.format {
	case packageFormatDEB:
		version, err = attestInstalledDEBVersion(ctx, binaryPath, output)
	case packageFormatRPM:
		version, err = attestInstalledRPMVersion(ctx, binaryPath, output)
	case packageFormatAPK:
		version, err = attestInstalledAPKVersion(ctx, target.installer, binaryPath, output)
	default:
		err = fmt.Errorf("unsupported qualification package format %q", target.format)
	}
	if err != nil {
		return installedQualificationEvidence{}, err
	}
	if err := revalidateInstalledQualificationBinary(binaryRoot, binary, filepath.Base(binaryPath), identity, expectedUID); err != nil {
		return installedQualificationEvidence{}, err
	}
	return installedQualificationEvidence{
		version: version, cliSHA256: hex.EncodeToString(identity.digest[:]),
	}, nil
}

func openInstalledQualificationBinary(path string, expectedUID int) (*os.Root, *os.File, qualificationFileIdentity, error) {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	if !safeAssetName(name) {
		return nil, nil, qualificationFileIdentity{}, errors.New("installed SysWarden CLI name is unsafe")
	}
	root, err := openOwnedInstalledQualificationDirectory(directory, expectedUID)
	if err != nil {
		return nil, nil, qualificationFileIdentity{}, err
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("inspect installed SysWarden CLI: %w", err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, errors.New("installed SysWarden CLI is not a regular non-symlink file")
	}
	binary, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("open installed SysWarden CLI: %w", err)
	}
	openedInfo, err := binary.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, errors.New("installed SysWarden CLI changed while opening")
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(binary.Fd()), &status); err != nil {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("inspect installed SysWarden CLI descriptor: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Nlink != 1 || status.Size <= 0 {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, errors.New("installed SysWarden CLI must be a nonempty regular file with link count 1")
	}
	if int(status.Uid) != expectedUID {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("installed SysWarden CLI owner is UID %d, want %d", status.Uid, expectedUID)
	}
	if status.Mode&07777 != 0750 {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("installed SysWarden CLI mode is %#o, want 0750", status.Mode&07777)
	}
	identity := identityFromQualificationStat(status)
	digest, err := qualificationFileSHA256(binary, status.Size)
	if err != nil {
		_ = binary.Close()
		_ = root.Close()
		return nil, nil, qualificationFileIdentity{}, fmt.Errorf("hash installed SysWarden CLI: %w", err)
	}
	identity.digest = digest
	return root, binary, identity, nil
}

func openOwnedInstalledQualificationDirectory(directory string, expectedUID int) (*os.Root, error) {
	const installedSuffix = "/opt/syswarden/bin"
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!strings.HasSuffix(directory, installedSuffix) {
		return nil, fmt.Errorf("installed SysWarden CLI directory is outside the fixed package path")
	}
	anchor := strings.TrimSuffix(directory, installedSuffix)
	if anchor == "" {
		anchor = "/"
	}
	current, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, fmt.Errorf("open installed SysWarden CLI path anchor: %w", err)
	}
	validate := func(info os.FileInfo, label string) error {
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int(status.Uid) != expectedUID ||
			info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("installed SysWarden CLI directory component %s has unsafe ownership or mode", label)
		}
		return nil
	}
	anchorInfo, err := current.Stat(".")
	if err != nil || validate(anchorInfo, anchor) != nil {
		_ = current.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect installed SysWarden CLI path anchor: %w", err)
		}
		return nil, validate(anchorInfo, anchor)
	}
	for _, component := range []string{"opt", "syswarden", "bin"} {
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect installed SysWarden CLI directory component %s: %w", component, err)
		}
		if err := validate(before, component); err != nil {
			_ = current.Close()
			return nil, err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open installed SysWarden CLI directory component %s: %w", component, err)
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) || validate(after, component) != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("installed SysWarden CLI directory component %s changed while opening", component)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func revalidateInstalledQualificationBinary(
	root *os.Root,
	binary *os.File,
	name string,
	expected qualificationFileIdentity,
	expectedUID int,
) error {
	var status unix.Stat_t
	if err := unix.Fstat(int(binary.Fd()), &status); err != nil {
		return fmt.Errorf("reinspect installed SysWarden CLI descriptor: %w", err)
	}
	actual := identityFromQualificationStat(status)
	digest, err := qualificationFileSHA256(binary, status.Size)
	if err != nil {
		return fmt.Errorf("rehash installed SysWarden CLI: %w", err)
	}
	actual.digest = digest
	if actual != expected || int(status.Uid) != expectedUID {
		return errors.New("installed SysWarden CLI changed during package attestation")
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("reinspect installed SysWarden CLI path: %w", err)
	}
	openedInfo, err := binary.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("installed SysWarden CLI path no longer names the attested descriptor")
	}
	return nil
}

func qualificationFileSHA256(file *os.File, size int64) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if file == nil || size <= 0 || size > maxPackageBytes {
		return digest, errors.New("invalid installed CLI hash request")
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.NewSectionReader(file, 0, size+1))
	if err != nil {
		return digest, err
	}
	if read != size {
		return digest, fmt.Errorf("read %d bytes, want %d", read, size)
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

type qualificationExpandedReader struct {
	reader io.Reader
	total  *int64
	ctx    context.Context
}

func (reader qualificationExpandedReader) Read(buffer []byte) (int, error) {
	if reader.ctx != nil {
		select {
		case <-reader.ctx.Done():
			return 0, reader.ctx.Err()
		default:
		}
	}
	if reader.total == nil || *reader.total >= maximumQualificationPackageExpandedBytes {
		return 0, errors.New("qualification package expanded size exceeds the accepted limit")
	}
	remaining := maximumQualificationPackageExpandedBytes - *reader.total
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	read, err := reader.reader.Read(buffer)
	*reader.total += int64(read)
	if *reader.total > maximumQualificationPackageExpandedBytes {
		return read, errors.New("qualification package expanded size exceeds the accepted limit")
	}
	return read, err
}

const qualificationPackageCLIPath = "opt/syswarden/bin/syswarden-cli"

type qualificationRPMPayloadConverter func(context.Context, *os.File, io.Writer) error

// attestQualificationPackageCLI derives the expected installed CLI digest
// from the already-open Ed25519-authenticated package descriptor before the
// native transaction. Every supported format must bind exactly one payload.
func attestQualificationPackageCLI(ctx context.Context, target packageTarget, packageFile *os.File) (string, error) {
	return attestQualificationPackageCLIWith(ctx, target, packageFile, runQualificationRPM2CPIO)
}

func attestQualificationPackageCLIWith(
	ctx context.Context,
	target packageTarget,
	packageFile *os.File,
	rpmConverter qualificationRPMPayloadConverter,
) (string, error) {
	if ctx == nil {
		return "", errors.New("qualification package payload context is unavailable")
	}
	if packageFile == nil {
		return "", errors.New("qualification package descriptor is unavailable")
	}
	switch target.format {
	case packageFormatDEB:
		return qualificationDEBPayloadCLISHA256(ctx, packageFile)
	case packageFormatRPM:
		return qualificationRPMPayloadCLISHA256With(ctx, packageFile, rpmConverter)
	case packageFormatAPK:
		return qualificationAPKPayloadCLISHA256WithContext(ctx, packageFile)
	default:
		return "", fmt.Errorf("unsupported qualification package format %q", target.format)
	}
}

func qualificationPackageDescriptorSize(packageFile *os.File, format string) (int64, error) {
	if packageFile == nil {
		return 0, errors.New("qualification package descriptor is unavailable")
	}
	info, err := packageFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("inspect authenticated %s descriptor: %w", format, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPackageBytes {
		return 0, fmt.Errorf("authenticated %s descriptor has an invalid identity", format)
	}
	return info.Size(), nil
}

func qualificationTarPayloadCLISHA256(ctx context.Context, reader io.Reader, format string, expandedBytes *int64) (string, error) {
	if reader == nil || expandedBytes == nil {
		return "", fmt.Errorf("authenticated %s payload reader is unavailable", format)
	}
	typedReader := tar.NewReader(qualificationExpandedReader{reader: reader, total: expandedBytes, ctx: ctx})
	cliDigest := ""
	for {
		header, err := typedReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read authenticated %s payload: %w", format, err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name != qualificationPackageCLIPath {
			continue
		}
		if cliDigest != "" {
			return "", fmt.Errorf("authenticated %s contains duplicate SysWarden CLI payloads", format)
		}
		if !qualificationTarHeaderIsRegular(header.Typeflag) {
			return "", fmt.Errorf("authenticated %s SysWarden CLI payload is not a regular file", format)
		}
		if header.Linkname != "" || header.Mode&07777 != 0750 || header.Uid != 0 || header.Gid != 0 ||
			header.Size <= 0 || header.Size > maxPackageBytes {
			return "", fmt.Errorf("authenticated %s SysWarden CLI payload metadata is invalid", format)
		}
		hash := sha256.New()
		read, err := io.Copy(hash, io.LimitReader(typedReader, header.Size+1))
		if err != nil {
			return "", fmt.Errorf("hash authenticated %s SysWarden CLI payload: %w", format, err)
		}
		if read != header.Size {
			return "", fmt.Errorf("hash authenticated %s SysWarden CLI payload: read %d bytes, want %d", format, read, header.Size)
		}
		cliDigest = hex.EncodeToString(hash.Sum(nil))
	}
	if cliDigest == "" {
		return "", fmt.Errorf("authenticated %s lacks one exact SysWarden CLI payload", format)
	}
	return cliDigest, nil
}

func parseQualificationARMemberSize(field []byte) (int64, error) {
	raw := strings.TrimSpace(string(field))
	if raw == "" {
		return 0, errors.New("empty ar member size")
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, errors.New("non-decimal ar member size")
		}
	}
	size, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || size < 0 || size > maxPackageBytes {
		return 0, errors.New("ar member size is outside accepted bounds")
	}
	return size, nil
}

func qualificationDEBDataMember(ctx context.Context, packageFile *os.File) (*io.SectionReader, error) {
	if ctx == nil {
		return nil, errors.New("authenticated DEB payload context is unavailable")
	}
	size, err := qualificationPackageDescriptorSize(packageFile, "DEB")
	if err != nil {
		return nil, err
	}
	const (
		arMagic      = "!<arch>\n"
		arHeaderSize = int64(60)
		maxARMembers = 64
	)
	magic := make([]byte, len(arMagic))
	if _, err := packageFile.ReadAt(magic, 0); err != nil || string(magic) != arMagic {
		return nil, errors.New("authenticated DEB has an invalid ar signature")
	}
	var (
		offset     = int64(len(arMagic))
		dataOffset int64
		dataSize   int64
		dataCount  int
		members    int
	)
	for offset < size {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		members++
		if members > maxARMembers || offset > size-arHeaderSize {
			return nil, errors.New("authenticated DEB ar inventory is malformed or excessive")
		}
		header := make([]byte, arHeaderSize)
		if _, err := packageFile.ReadAt(header, offset); err != nil {
			return nil, fmt.Errorf("read authenticated DEB ar header: %w", err)
		}
		if string(header[58:60]) != "`\n" {
			return nil, errors.New("authenticated DEB ar header trailer is invalid")
		}
		memberSize, err := parseQualificationARMemberSize(header[48:58])
		if err != nil {
			return nil, fmt.Errorf("parse authenticated DEB ar member: %w", err)
		}
		memberOffset := offset + arHeaderSize
		if memberOffset > size-memberSize {
			return nil, errors.New("authenticated DEB ar member exceeds its descriptor")
		}
		name := strings.TrimSpace(string(header[:16]))
		name = strings.TrimSuffix(name, "/")
		if strings.HasPrefix(name, "data.tar.") {
			if name != "data.tar.gz" {
				return nil, fmt.Errorf("authenticated DEB data member compression %q is unsupported", name)
			}
			dataCount++
			dataOffset = memberOffset
			dataSize = memberSize
		}
		offset = memberOffset + memberSize
		if memberSize%2 != 0 {
			padding := []byte{0}
			if _, err := packageFile.ReadAt(padding, offset); err != nil || padding[0] != '\n' {
				return nil, errors.New("authenticated DEB ar padding is invalid")
			}
			offset++
		}
		if offset > size {
			return nil, errors.New("authenticated DEB ar padding exceeds its descriptor")
		}
	}
	if offset != size || dataCount != 1 || dataSize <= 0 {
		return nil, errors.New("authenticated DEB must contain exactly one nonempty data.tar.gz member")
	}
	return io.NewSectionReader(packageFile, dataOffset, dataSize), nil
}

func qualificationDEBPayloadCLISHA256(ctx context.Context, packageFile *os.File) (string, error) {
	if ctx == nil {
		return "", errors.New("authenticated DEB payload context is unavailable")
	}
	member, err := qualificationDEBDataMember(ctx, packageFile)
	if err != nil {
		return "", err
	}
	compressedBytes := int64(0)
	compressed := bufio.NewReader(qualificationExpandedReader{reader: member, total: &compressedBytes, ctx: ctx})
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return "", fmt.Errorf("open authenticated DEB data member: %w", err)
	}
	gzipReader.Multistream(false)
	expandedBytes := int64(0)
	digest, payloadErr := qualificationTarPayloadCLISHA256(ctx, gzipReader, "DEB", &expandedBytes)
	if payloadErr == nil {
		_, payloadErr = io.Copy(io.Discard, qualificationExpandedReader{reader: gzipReader, total: &expandedBytes, ctx: ctx})
	}
	closeErr := gzipReader.Close()
	if payloadErr != nil {
		return "", payloadErr
	}
	if closeErr != nil {
		return "", fmt.Errorf("close authenticated DEB data member: %w", closeErr)
	}
	if _, err := compressed.Peek(1); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("authenticated DEB data member contains trailing compressed data")
		}
		return "", fmt.Errorf("inspect authenticated DEB data member trailer: %w", err)
	}
	return digest, nil
}

func runQualificationRPM2CPIO(ctx context.Context, packageFile *os.File, output io.Writer) error {
	size, err := qualificationPackageDescriptorSize(packageFile, "RPM")
	if err != nil {
		return err
	}
	if output == nil {
		return errors.New("authenticated RPM payload output is unavailable")
	}
	command := exec.Command("/usr/bin/rpm2cpio") // #nosec G204 -- fixed local decoder, authenticated descriptor is stdin
	command.Stdin = io.NewSectionReader(packageFile, 0, size)
	command.Stdout = output
	stderr := &qualificationBoundedBuffer{limit: maximumQualificationDecoderDiagnostics}
	command.Stderr = stderr
	command.Env = qualificationExternalCommandEnvironment()
	if err := runQualificationProcessGroup(ctx, command); err != nil {
		if stderr.overflow || len(stderr.Bytes()) != 0 {
			return fmt.Errorf("decode authenticated RPM payload failed with bounded diagnostics")
		}
		return fmt.Errorf("decode authenticated RPM payload: %w", err)
	}
	if stderr.overflow || len(stderr.Bytes()) != 0 {
		return errors.New("authenticated RPM payload decoder emitted unexpected diagnostics")
	}
	return nil
}

func parseQualificationCPIOHex(field []byte) (uint64, error) {
	if len(field) != 8 {
		return 0, errors.New("invalid cpio field width")
	}
	for _, character := range field {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return 0, errors.New("invalid cpio hexadecimal field")
		}
	}
	return strconv.ParseUint(string(field), 16, 32)
}

func readQualificationCPIOPadding(reader io.Reader, size uint64) error {
	padding := (4 - (size % 4)) % 4
	if padding == 0 {
		return nil
	}
	buffer := make([]byte, padding)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return err
	}
	for _, value := range buffer {
		if value != 0 {
			return errors.New("authenticated RPM cpio padding is nonzero")
		}
	}
	return nil
}

func qualificationCPIOPayloadCLISHA256(ctx context.Context, reader io.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("authenticated RPM cpio reader is unavailable")
	}
	expandedBytes := int64(0)
	bounded := qualificationExpandedReader{reader: reader, total: &expandedBytes, ctx: ctx}
	cliDigest := ""
	const (
		cpioHeaderSize = 110
		maxCPIOEntries = 200000
	)
	for entries := 0; entries < maxCPIOEntries; entries++ {
		header := make([]byte, cpioHeaderSize)
		if _, err := io.ReadFull(bounded, header); err != nil {
			return "", fmt.Errorf("read authenticated RPM cpio header: %w", err)
		}
		if string(header[:6]) != "070701" {
			return "", errors.New("authenticated RPM payload is not canonical newc cpio")
		}
		fields := make([]uint64, 13)
		for index := range fields {
			value, err := parseQualificationCPIOHex(header[6+index*8 : 14+index*8])
			if err != nil {
				return "", fmt.Errorf("parse authenticated RPM cpio header: %w", err)
			}
			fields[index] = value
		}
		mode, uid, gid, links := fields[1], fields[2], fields[3], fields[4]
		fileSize, nameSize := fields[6], fields[11]
		if nameSize < 2 || nameSize > 4096 || fileSize > uint64(maximumQualificationPackageExpandedBytes) {
			return "", errors.New("authenticated RPM cpio entry size is outside accepted bounds")
		}
		nameBytes := make([]byte, nameSize)
		if _, err := io.ReadFull(bounded, nameBytes); err != nil {
			return "", fmt.Errorf("read authenticated RPM cpio name: %w", err)
		}
		if nameBytes[len(nameBytes)-1] != 0 || bytes.IndexByte(nameBytes[:len(nameBytes)-1], 0) >= 0 {
			return "", errors.New("authenticated RPM cpio name is malformed")
		}
		if err := readQualificationCPIOPadding(bounded, uint64(cpioHeaderSize)+nameSize); err != nil {
			return "", fmt.Errorf("read authenticated RPM cpio name padding: %w", err)
		}
		name := string(nameBytes[:len(nameBytes)-1])
		if name == "TRAILER!!!" {
			if fileSize != 0 {
				return "", errors.New("authenticated RPM cpio trailer has content")
			}
			trailing, err := io.ReadAll(io.LimitReader(bounded, 4097))
			if err != nil {
				return "", fmt.Errorf("read authenticated RPM cpio trailer padding: %w", err)
			}
			if len(trailing) > 4096 {
				return "", errors.New("authenticated RPM cpio trailer padding exceeds accepted bounds")
			}
			for _, value := range trailing {
				if value != 0 {
					return "", errors.New("authenticated RPM cpio trailer contains nonzero data")
				}
			}
			if cliDigest == "" {
				return "", errors.New("authenticated RPM lacks one exact SysWarden CLI payload")
			}
			return cliDigest, nil
		}
		normalizedName := strings.TrimPrefix(name, "./")
		isCLI := normalizedName == qualificationPackageCLIPath
		if isCLI {
			if cliDigest != "" {
				return "", errors.New("authenticated RPM contains duplicate SysWarden CLI payloads")
			}
			if mode&0170000 != 0100000 || mode&07777 != 0750 || uid != 0 || gid != 0 || links != 1 ||
				fileSize == 0 || fileSize > uint64(maxPackageBytes) {
				return "", errors.New("authenticated RPM SysWarden CLI payload metadata is invalid")
			}
			hash := sha256.New()
			read, err := io.CopyN(hash, bounded, int64(fileSize))
			if err != nil || read != int64(fileSize) {
				return "", fmt.Errorf("hash authenticated RPM SysWarden CLI payload: read %d bytes, want %d: %w", read, fileSize, err)
			}
			cliDigest = hex.EncodeToString(hash.Sum(nil))
		} else if _, err := io.CopyN(io.Discard, bounded, int64(fileSize)); err != nil {
			return "", fmt.Errorf("skip authenticated RPM cpio payload: %w", err)
		}
		if err := readQualificationCPIOPadding(bounded, fileSize); err != nil {
			return "", fmt.Errorf("read authenticated RPM cpio content padding: %w", err)
		}
	}
	return "", errors.New("authenticated RPM cpio inventory exceeds accepted bounds")
}

func qualificationRPMPayloadCLISHA256With(
	ctx context.Context,
	packageFile *os.File,
	convert qualificationRPMPayloadConverter,
) (string, error) {
	if convert == nil {
		return "", errors.New("authenticated RPM payload decoder is unavailable")
	}
	if _, err := qualificationPackageDescriptorSize(packageFile, "RPM"); err != nil {
		return "", err
	}
	reader, writer := io.Pipe()
	converted := make(chan error, 1)
	go func() {
		err := convert(ctx, packageFile, writer)
		_ = writer.CloseWithError(err)
		converted <- err
	}()
	digest, parseErr := qualificationCPIOPayloadCLISHA256(ctx, reader)
	if parseErr != nil {
		_ = reader.CloseWithError(parseErr)
	} else {
		_ = reader.Close()
	}
	convertErr := <-converted
	if parseErr != nil || convertErr != nil {
		return "", errors.Join(parseErr, convertErr)
	}
	return digest, nil
}

func qualificationAPKPayloadCLISHA256(packageFile *os.File) (string, error) {
	return qualificationAPKPayloadCLISHA256WithContext(context.Background(), packageFile)
}

func qualificationAPKPayloadCLISHA256WithContext(ctx context.Context, packageFile *os.File) (string, error) {
	if ctx == nil {
		return "", errors.New("authenticated APK payload context is unavailable")
	}
	size, err := qualificationPackageDescriptorSize(packageFile, "APK")
	if err != nil {
		return "", err
	}
	compressedBytes := int64(0)
	compressed := bufio.NewReader(qualificationExpandedReader{
		reader: io.NewSectionReader(packageFile, 0, size),
		total:  &compressedBytes,
		ctx:    ctx,
	})
	var (
		expandedBytes int64
		cliDigest     string
		members       int
	)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if _, err := compressed.Peek(1); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", fmt.Errorf("inspect authenticated APK member: %w", err)
		}
		members++
		if members > 16 {
			return "", errors.New("authenticated APK contains too many gzip members")
		}
		gzipReader, err := gzip.NewReader(compressed)
		if err != nil {
			return "", fmt.Errorf("open authenticated APK gzip member: %w", err)
		}
		gzipReader.Multistream(false)
		expanded := qualificationExpandedReader{reader: gzipReader, total: &expandedBytes, ctx: ctx}
		tarReader := tar.NewReader(expanded)
		for {
			header, err := tarReader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = gzipReader.Close()
				return "", fmt.Errorf("read authenticated APK payload: %w", err)
			}
			name := strings.TrimPrefix(header.Name, "./")
			if name != qualificationPackageCLIPath {
				continue
			}
			if cliDigest != "" {
				_ = gzipReader.Close()
				return "", errors.New("authenticated APK contains duplicate SysWarden CLI payloads")
			}
			if !qualificationTarHeaderIsRegular(header.Typeflag) {
				_ = gzipReader.Close()
				return "", errors.New("authenticated APK SysWarden CLI payload is not a regular file")
			}
			if header.Linkname != "" || header.Mode&07777 != 0750 || header.Uid != 0 || header.Gid != 0 ||
				header.Size <= 0 || header.Size > maxPackageBytes {
				_ = gzipReader.Close()
				return "", errors.New("authenticated APK SysWarden CLI payload metadata is invalid")
			}
			hash := sha256.New()
			read, err := io.Copy(hash, io.LimitReader(tarReader, header.Size+1))
			if err != nil {
				_ = gzipReader.Close()
				return "", fmt.Errorf("hash authenticated APK SysWarden CLI payload: %w", err)
			}
			if read != header.Size {
				_ = gzipReader.Close()
				return "", fmt.Errorf("hash authenticated APK SysWarden CLI payload: read %d bytes, want %d", read, header.Size)
			}
			cliDigest = hex.EncodeToString(hash.Sum(nil))
		}
		if _, err := io.Copy(io.Discard, expanded); err != nil {
			_ = gzipReader.Close()
			return "", fmt.Errorf("finish authenticated APK gzip member: %w", err)
		}
		if err := gzipReader.Close(); err != nil {
			return "", fmt.Errorf("close authenticated APK gzip member: %w", err)
		}
	}
	if members == 0 || cliDigest == "" {
		return "", errors.New("authenticated APK lacks one exact SysWarden CLI payload")
	}
	return cliDigest, nil
}

func attestInstalledDEBVersion(ctx context.Context, binaryPath string, output qualificationCommandOutput) (string, error) {
	versionOutput, err := output(
		ctx,
		"/usr/bin/dpkg-query",
		"--show",
		"--showformat=${db:Status-Abbrev}\t${Version}\n",
		"syswarden",
	)
	if err != nil {
		return "", fmt.Errorf("query installed DEB version: %w", err)
	}
	const prefix = "ii \t"
	if !bytes.HasPrefix(versionOutput, []byte(prefix)) || bytes.Count(versionOutput, []byte{'\n'}) != 1 || versionOutput[len(versionOutput)-1] != '\n' {
		return "", errors.New("installed DEB status and version are ambiguous")
	}
	rawVersion := strings.TrimSuffix(strings.TrimPrefix(string(versionOutput), prefix), "\n")
	version, err := canonicalInstalledSyswardenVersion(rawVersion, packageFormatDEB)
	if err != nil {
		return "", err
	}
	ownerOutput, err := output(ctx, "/usr/bin/dpkg-query", "--search", binaryPath)
	if err != nil {
		return "", fmt.Errorf("query installed CLI DEB ownership: %w", err)
	}
	if string(ownerOutput) != "syswarden: "+binaryPath+"\n" {
		return "", errors.New("installed CLI DEB ownership does not match the syswarden package")
	}
	verification, err := output(ctx, "/usr/bin/dpkg", "--verify", "--verify-format=rpm", "syswarden")
	if err := validateQualificationPackageVerificationResult(verification, err); err != nil {
		return "", fmt.Errorf("installed DEB package integrity verification: %w", err)
	}
	return version, nil
}

func attestInstalledRPMVersion(ctx context.Context, binaryPath string, output qualificationCommandOutput) (string, error) {
	const queryFormat = "%{NAME}\t%{VERSION}\t%{ARCH}\n"
	packageOutput, err := output(ctx, "/usr/bin/rpm", "--query", "syswarden", "--queryformat", queryFormat)
	if err != nil {
		return "", fmt.Errorf("query installed RPM version: %w", err)
	}
	ownerOutput, err := output(ctx, "/usr/bin/rpm", "--query", "--file", binaryPath, "--queryformat", queryFormat)
	if err != nil {
		return "", fmt.Errorf("query installed CLI RPM ownership: %w", err)
	}
	if !bytes.Equal(packageOutput, ownerOutput) {
		return "", errors.New("installed RPM package and CLI ownership versions disagree")
	}
	fields := strings.Split(strings.TrimSuffix(string(packageOutput), "\n"), "\t")
	if len(fields) != 3 || fields[0] != "syswarden" || fields[2] != "x86_64" || bytes.Count(packageOutput, []byte{'\n'}) != 1 {
		return "", errors.New("installed RPM identity is ambiguous")
	}
	version, err := canonicalInstalledSyswardenVersion(fields[1], packageFormatRPM)
	if err != nil {
		return "", err
	}
	verification, err := output(ctx, "/usr/bin/rpm", "--verify", "syswarden", "--noscripts")
	if err := validateQualificationPackageVerificationResult(verification, err); err != nil {
		return "", fmt.Errorf("installed RPM package integrity verification: %w", err)
	}
	return version, nil
}

// Package-wide verification may report legitimate operator changes to declared
// conffiles. Only records explicitly classified by the package manager as
// conffiles are tolerated. Any non-conffile drift, including the fixed CLI,
// fails closed.
func validateQualificationPackageVerification(output []byte) error {
	if len(output) == 0 {
		return nil
	}
	if strings.ContainsAny(string(output), "\x00\r") || output[len(output)-1] != '\n' {
		return errors.New("verification output is malformed")
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || len(fields[0]) != 9 || fields[1] != "c" ||
			!filepath.IsAbs(fields[2]) || filepath.Clean(fields[2]) != fields[2] {
			return fmt.Errorf("non-conffile or malformed package drift record %q", line)
		}
		for _, character := range fields[0] {
			if !strings.ContainsRune(".?SM5DLUGTP", character) {
				return fmt.Errorf("invalid package verification status in %q", line)
			}
		}
		if _, duplicate := seen[fields[2]]; duplicate {
			return fmt.Errorf("duplicate package drift record for %s", fields[2])
		}
		seen[fields[2]] = struct{}{}
	}
	return nil
}

func validateQualificationPackageVerificationResult(output []byte, commandErr error) error {
	if commandErr == nil {
		return validateQualificationPackageVerification(output)
	}
	var exitFailure *qualificationCommandExitError
	if !errors.As(commandErr, &exitFailure) || exitFailure.code != 1 || len(exitFailure.stderr) != 0 || len(output) == 0 {
		return fmt.Errorf("package verification command failed: %w", commandErr)
	}
	return validateQualificationPackageVerification(output)
}

func attestInstalledAPKVersion(ctx context.Context, apkPath, binaryPath string, output qualificationCommandOutput) (string, error) {
	if apkPath != "/sbin/apk" && apkPath != "/usr/sbin/apk" {
		return "", fmt.Errorf("untrusted APK package manager path %q", apkPath)
	}
	packageOutput, err := output(ctx, apkPath, "info", "--verbose", "syswarden")
	if err != nil {
		return "", fmt.Errorf("query installed APK version: %w", err)
	}
	const packagePrefix = "syswarden-"
	if !bytes.HasPrefix(packageOutput, []byte(packagePrefix)) || bytes.Count(packageOutput, []byte{'\n'}) != 1 || packageOutput[len(packageOutput)-1] != '\n' {
		return "", errors.New("installed APK version is ambiguous")
	}
	rawVersion := strings.TrimSuffix(strings.TrimPrefix(string(packageOutput), packagePrefix), "\n")
	version, err := canonicalInstalledSyswardenVersion(rawVersion, packageFormatAPK)
	if err != nil {
		return "", err
	}
	ownerOutput, err := output(ctx, apkPath, "info", "--who-owns", binaryPath)
	if err != nil {
		return "", fmt.Errorf("query installed CLI APK ownership: %w", err)
	}
	if string(ownerOutput) != binaryPath+" is owned by syswarden-"+rawVersion+"\n" {
		return "", errors.New("installed APK package and CLI ownership versions disagree")
	}
	return version, nil
}

func qualificationRequiredPackages(format string) []string {
	switch format {
	case packageFormatDEB:
		return []string{
			"apt-listchanges", "bash-completion", "cron", "curl", "e2fsprogs", "ipset", "jq",
			"nftables", "procps", "qrencode", "rsyslog", "unattended-upgrades", "wget", "wireguard-tools",
		}
	case packageFormatRPM:
		return []string{
			"bash-completion", "checkpolicy", "cronie", "curl", "dnf-automatic", "e2fsprogs", "ipset", "jq",
			"nftables", "policycoreutils-python-utils", "procps-ng", "rsyslog", "systemd", "wget", "wireguard-tools",
		}
	case packageFormatAPK:
		return []string{
			"bash-completion", "cronie", "cronie-openrc", "curl", "e2fsprogs-extra", "jq", "libqrencode-tools",
			"nftables", "openrc", "procps-ng", "rsyslog", "rsyslog-uxsock", "shadow", "wget", "wireguard-tools",
		}
	default:
		return nil
	}
}

func qualificationRequiredPackage(format, name string) bool {
	for _, required := range qualificationRequiredPackages(format) {
		if name == required {
			return true
		}
	}
	return false
}

func attestOfflineQualificationPackageDependencies(ctx context.Context, target packageTarget) error {
	return attestOfflineQualificationPackageDependenciesWith(ctx, target, runQualificationCommandOutput)
}

func attestOfflineQualificationPackageDependenciesWith(
	ctx context.Context,
	target packageTarget,
	output qualificationCommandOutput,
) error {
	if output == nil {
		return errors.New("offline package dependency attestation is unavailable")
	}
	required := qualificationRequiredPackages(target.format)
	if len(required) == 0 {
		return fmt.Errorf("unsupported package format %q for dependency attestation", target.format)
	}
	for _, dependency := range required {
		var (
			name string
			args []string
			want []byte
		)
		switch target.format {
		case packageFormatDEB:
			name = "/usr/bin/dpkg-query"
			args = []string{"--show", "--showformat=${db:Status-Abbrev}\n", dependency}
			want = []byte("ii \n")
		case packageFormatRPM:
			name = "/usr/bin/rpm"
			args = []string{"--query", "--quiet", dependency}
		case packageFormatAPK:
			name = target.installer
			args = []string{"info", "--exists", dependency}
		default:
			return fmt.Errorf("unsupported package format %q for dependency attestation", target.format)
		}
		result, err := output(ctx, name, args...)
		if err != nil {
			return fmt.Errorf("required package dependency %q is unavailable: %w", dependency, err)
		}
		if !bytes.Equal(result, want) {
			return fmt.Errorf("required package dependency %q returned ambiguous status", dependency)
		}
	}
	return nil
}

func canonicalInstalledSyswardenVersion(rawVersion, format string) (string, error) {
	if format == packageFormatAPK {
		revision := strings.LastIndex(rawVersion, "-r")
		if revision <= 0 || revision+2 >= len(rawVersion) {
			return "", fmt.Errorf("installed APK version %q lacks a canonical revision", rawVersion)
		}
		for _, character := range rawVersion[revision+2:] {
			if character < '0' || character > '9' {
				return "", fmt.Errorf("installed APK version %q has an invalid revision", rawVersion)
			}
		}
		rawVersion = rawVersion[:revision]
	}
	version := "v" + rawVersion
	if _, err := parseReleaseVersion(version); err != nil {
		return "", fmt.Errorf("installed %s package version is invalid: %w", format, err)
	}
	return version, nil
}

// OfflineQualificationPackageInstall reports whether a package maintainer
// script inherited the private qualification marker. Both values are required
// so setting the qualification marker on an ordinary interactive install does
// not change its feed-refresh behavior.
func OfflineQualificationPackageInstall() bool {
	return os.Getenv(offlineQualificationEnvironment) == "1" && os.Getenv("SYSWARDEN_PKG_INSTALL") == "1"
}

// OfflineQualificationActivation reports the second phase of an authenticated
// candidate update. The updater invokes it only after exact post-install
// package and CLI attestation succeeds.
func OfflineQualificationActivation() bool {
	return os.Getenv(offlineQualificationEnvironment) == offlineQualificationActivationValue &&
		os.Getenv("SYSWARDEN_PKG_INSTALL") == "1"
}

// OfflineQualificationOperation covers both the package-script staging phase
// and the explicitly attested activation phase.
func OfflineQualificationOperation() bool {
	return OfflineQualificationPackageInstall() || OfflineQualificationActivation()
}

func (target packageTarget) qualificationInstallCommand(packagePath string) (string, []string) {
	switch target.format {
	case packageFormatDEB:
		// dpkg changes exactly the already verified candidate package. It cannot
		// resolve cached or repository dependencies and therefore cannot run
		// unrelated maintainer scripts before post-install attestation.
		return "/usr/bin/dpkg", []string{"--install", packagePath}
	case packageFormatRPM:
		return target.installer, []string{
			"--noplugins",
			"--cacheonly",
			"--disablerepo=*",
			"--setopt=localpkg_gpgcheck=1",
			"install",
			"-y",
			packagePath,
		}
	case packageFormatAPK:
		return target.installer, []string{
			"--no-network",
			"--no-cache",
			"--repositories-file", "/dev/null",
			"add",
			packagePath,
		}
	default:
		return "", nil
	}
}

func validateQualificationExternalCommand(name string, args []string) error {
	switch name {
	case "/usr/bin/dpkg":
		if len(args) != 2 {
			break
		}
		if args[0] == "--install" && validSecurePackageArgument(args[1]) {
			return nil
		}
	case "/usr/bin/dnf", "/usr/bin/yum":
		if len(args) != 7 {
			break
		}
		if args[0] == "--noplugins" && args[1] == "--cacheonly" && args[2] == "--disablerepo=*" &&
			args[3] == "--setopt=localpkg_gpgcheck=1" && args[4] == "install" && args[5] == "-y" &&
			validSecurePackageArgument(args[6]) {
			return nil
		}
	case "/sbin/apk", "/usr/sbin/apk":
		if len(args) != 6 {
			break
		}
		if args[0] == "--no-network" && args[1] == "--no-cache" &&
			args[2] == "--repositories-file" && args[3] == "/dev/null" && args[4] == "add" &&
			validSecurePackageArgument(args[5]) {
			return nil
		}
	default:
		return validateExternalCommand(name, args)
	}
	return fmt.Errorf("refusing non-offline qualification arguments for %q", name)
}

func qualificationExternalCommandEnvironment() []string {
	return []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		offlineQualificationEnvironment + "=1",
	}
}

func qualificationActivationEnvironment() []string {
	return []string{
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		offlineQualificationEnvironment + "=" + offlineQualificationActivationValue,
		"SYSWARDEN_PKG_INSTALL=1",
	}
}

func runQualificationExternalCommand(ctx context.Context, name string, args ...string) error {
	if err := validateQualificationExternalCommand(name, args); err != nil {
		return err
	}
	command := exec.Command(name, args...) // #nosec G204 -- executable and arguments passed the exact allowlist above
	command.Env = qualificationExternalCommandEnvironment()
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return runQualificationProcessGroup(ctx, command)
}

func runQualificationActivationCommand(ctx context.Context, expected installedQualificationEvidence) error {
	return runQualificationActivationCommandAt(ctx, expected, installedSyswardenCLIPath, nil)
}

func runQualificationActivationCommandAt(
	ctx context.Context,
	expected installedQualificationEvidence,
	binaryPath string,
	beforeExec func() error,
) error {
	if expected.version == "" || !validSHA256(expected.cliSHA256) {
		return errors.New("qualification activation evidence is incomplete")
	}
	root, binary, identity, err := openInstalledQualificationBinary(binaryPath, os.Geteuid())
	if err != nil {
		return fmt.Errorf("reopen exactly attested candidate CLI for activation: %w", err)
	}
	defer func() {
		_ = binary.Close()
		_ = root.Close()
	}()
	actualDigest := hex.EncodeToString(identity.digest[:])
	if actualDigest != expected.cliSHA256 {
		return fmt.Errorf("candidate CLI changed before descriptor-bound activation")
	}
	if beforeExec != nil {
		if err := beforeExec(); err != nil {
			return fmt.Errorf("qualification activation boundary hook: %w", err)
		}
	}
	// ExtraFiles maps the already attested descriptor to fd 3 in the child.
	// Executing /proc/self/fd/3 avoids reopening a replaceable pathname after
	// the final package and byte attestation.
	command := exec.Command("/proc/self/fd/3", "install") // #nosec G204 -- fd 3 is the fixed attested candidate descriptor
	command.ExtraFiles = []*os.File{binary}
	command.Env = qualificationActivationEnvironment()
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return runQualificationProcessGroup(ctx, command)
}

func runQualificationProcessGroup(ctx context.Context, command *exec.Cmd) error {
	if command == nil {
		return errors.New("qualification command is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	processGroupID := command.Process.Pid
	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()

	select {
	case err := <-waited:
		if qualificationProcessGroupAlive(processGroupID) {
			terminationErr := terminateQualificationProcessGroup(processGroupID)
			return errors.Join(err, errors.New("qualification command left a live descendant process"), terminationErr)
		}
		return err
	case <-ctx.Done():
	}

	terminationErr := signalQualificationProcessGroup(processGroupID, syscall.SIGTERM)
	timer := time.NewTimer(qualificationCommandTerminationGrace)
	defer timer.Stop()
	select {
	case <-waited:
	case <-timer.C:
		terminationErr = errors.Join(terminationErr, signalQualificationProcessGroup(processGroupID, syscall.SIGKILL))
		<-waited
	}
	if qualificationProcessGroupAlive(processGroupID) {
		terminationErr = errors.Join(terminationErr, terminateQualificationProcessGroup(processGroupID))
	}
	return errors.Join(ctx.Err(), terminationErr)
}

func qualificationProcessGroupAlive(processGroupID int) bool {
	if processGroupID <= 0 {
		return false
	}
	err := syscall.Kill(-processGroupID, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func signalQualificationProcessGroup(processGroupID int, signal syscall.Signal) error {
	if processGroupID <= 0 {
		return errors.New("qualification process group identity is invalid")
	}
	if err := syscall.Kill(-processGroupID, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal qualification process group %d: %w", processGroupID, err)
	}
	return nil
}

func terminateQualificationProcessGroup(processGroupID int) error {
	if !qualificationProcessGroupAlive(processGroupID) {
		return nil
	}
	if err := signalQualificationProcessGroup(processGroupID, syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(qualificationCommandTerminationGrace)
	for qualificationProcessGroupAlive(processGroupID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if qualificationProcessGroupAlive(processGroupID) {
		return signalQualificationProcessGroup(processGroupID, syscall.SIGKILL)
	}
	return nil
}

func runQualificationCommandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowedQualificationQuery(name, args) {
		return nil, fmt.Errorf("refusing unapproved installed-version query for %q", name)
	}
	command := exec.Command(name, args...) // #nosec G204 -- executable and arguments passed allowedQualificationQuery
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	stdout := qualificationBoundedBuffer{limit: 64 << 10}
	stderr := qualificationBoundedBuffer{limit: 4 << 10}
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := runQualificationProcessGroup(ctx, command)
	output := stdout.Bytes()
	if stdout.overflow {
		return nil, errors.New("installed-version query output exceeds 65536 bytes")
	}
	if stderr.overflow {
		return nil, errors.New("installed-version query stderr exceeds 4096 bytes")
	}
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	if err != nil {
		var exitFailure *exec.ExitError
		if !errors.As(err, &exitFailure) {
			return output, err
		}
		return output, &qualificationCommandExitError{code: exitFailure.ExitCode(), stderr: stderr.Bytes()}
	}
	if len(stderr.Bytes()) != 0 {
		return nil, errors.New("installed-version query emitted unexpected stderr")
	}
	return output, nil
}

func allowedQualificationQuery(name string, args []string) bool {
	same := func(want ...string) bool {
		if len(args) != len(want) {
			return false
		}
		for index := range want {
			if args[index] != want[index] {
				return false
			}
		}
		return true
	}
	switch name {
	case "/usr/bin/dpkg-query":
		return same("--show", "--showformat=${db:Status-Abbrev}\t${Version}\n", "syswarden") ||
			same("--search", installedSyswardenCLIPath) ||
			(len(args) == 3 && args[0] == "--show" && args[1] == "--showformat=${db:Status-Abbrev}\n" &&
				qualificationRequiredPackage(packageFormatDEB, args[2]))
	case "/usr/bin/dpkg":
		return same("--verify", "--verify-format=rpm", "syswarden")
	case "/usr/bin/rpm":
		return same("--query", "syswarden", "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\n") ||
			same("--query", "--file", installedSyswardenCLIPath, "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\n") ||
			same("--verify", "syswarden", "--noscripts") ||
			(len(args) == 3 && args[0] == "--query" && args[1] == "--quiet" &&
				qualificationRequiredPackage(packageFormatRPM, args[2]))
	case "/sbin/apk", "/usr/sbin/apk":
		return same("info", "--verbose", "syswarden") || same("info", "--who-owns", installedSyswardenCLIPath) ||
			(len(args) == 3 && args[0] == "info" && args[1] == "--exists" &&
				qualificationRequiredPackage(packageFormatAPK, args[2]))
	default:
		return false
	}
}

func copyVerifiedQualificationPackage(bundle *os.Root, artifact updateArtifact, destination *os.File, expectedUID int) (returnErr error) {
	if artifact.Size <= 0 || artifact.Size > maxPackageBytes || !validSHA256(artifact.SHA256) {
		return errors.New("package manifest metadata is invalid")
	}
	source, identity, err := openQualificationBundleFile(bundle, artifact.Filename, maxPackageBytes, expectedUID)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close qualification package source: %w", closeErr))
		}
	}()
	if identity.size != artifact.Size {
		return fmt.Errorf("qualification package size is %d, manifest requires %d", identity.size, artifact.Size)
	}
	if err := validateSecureOpenFile(destination, destination.Name(), expectedUID); err != nil {
		return fmt.Errorf("validate qualification package destination: %w", err)
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(source, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("copy qualification package: %w", err)
	}
	if written != artifact.Size {
		return fmt.Errorf("copied qualification package size is %d, manifest requires %d", written, artifact.Size)
	}
	actualDigest := hex.EncodeToString(digest.Sum(nil))
	if actualDigest != artifact.SHA256 {
		return fmt.Errorf("qualification package SHA-256 is %s, manifest requires %s", actualDigest, artifact.SHA256)
	}
	if err := revalidateQualificationBundleFile(bundle, source, artifact.Filename, identity, expectedUID); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync qualification package destination: %w", err)
	}
	if err := validateSecureOpenFile(destination, destination.Name(), expectedUID); err != nil {
		return fmt.Errorf("revalidate qualification package destination: %w", err)
	}
	return nil
}
