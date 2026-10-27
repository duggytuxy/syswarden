//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"time"

	"golang.org/x/sys/unix"
)

const apkTransitionRoot = "/var/backups/syswarden-apk-transitions-v1"
const apkTransitionSchema = "syswarden-apk-transition-preparation/v1"
const maximumAPKTransitionSnapshotBytes = 32 << 20

// Approval is an explicit review of an existing immutable plan. It is not a
// native transaction, migration acceptance or permission inferred from a path.
type APKTransitionApprovalRequiredError struct{ PlanSHA256, Directory string }

func (failure *APKTransitionApprovalRequiredError) Error() string {
	return fmt.Sprintf("APK transition preparation retained at %s; review exact plan SHA-256 %s; no package transaction performed", failure.Directory, failure.PlanSHA256)
}

// A custody failure must not cause either updater to delete the complete
// authenticated staging file. Pending evidence may contain only a partial copy.
// CandidateVerified describes a fresh postfailure check, not just download state.
type APKTransitionRetainedMaterialError struct {
	Workspace, PackagePath    string
	CandidateVerified         bool
	OriginalStageSynchronized bool
	Cause                     error
}

func (failure *APKTransitionRetainedMaterialError) Error() string {
	return fmt.Sprintf("APK preparation refused; original private stage retained at %s (candidate bytes verified: %t, stage synchronized: %t); pending custody may be incomplete: %v", failure.Workspace, failure.CandidateVerified, failure.OriginalStageSynchronized, failure.Cause)
}

func (failure *APKTransitionRetainedMaterialError) Unwrap() error { return failure.Cause }

func retainAPKTransitionWorkspace(err error, workspace string) bool {
	var retained *APKTransitionRetainedMaterialError
	return errors.As(err, &retained) && retained.Workspace == workspace && filepath.Dir(retained.PackagePath) == workspace
}

func synchronizeAPKTransitionStage(file *os.File, path string, uid int) error {
	if err := validateSecureOpenFile(file, path, uid); err != nil {
		return err
	}
	workspace, base := filepath.Dir(path), filepath.Dir(filepath.Dir(path))
	if err := validateSecureWorkspace(workspace, uid); err != nil {
		return err
	}
	if err := validateSecureTempBase(base, uid); err != nil {
		return err
	}
	var opened []*os.File
	defer func() {
		for _, directory := range opened {
			_ = directory.Close()
		}
	}()
	for _, name := range []string{workspace, base} {
		before, err := os.Lstat(name)
		if err != nil {
			return err
		}
		fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(fd), name)
		if directory == nil {
			_ = unix.Close(fd)
			return errors.New("APK original stage could not be pinned for synchronization")
		}
		opened = append(opened, directory)
		current, err := directory.Stat()
		if err != nil || !os.SameFile(before, current) {
			return errors.New("APK original stage ancestry changed before synchronization")
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	for _, directory := range opened {
		if err := directory.Sync(); err != nil {
			return err
		}
		named, err := os.Lstat(directory.Name())
		current, statErr := directory.Stat()
		if err != nil || statErr != nil || !os.SameFile(named, current) {
			return errors.New("APK original stage ancestry changed during synchronization")
		}
	}
	return errors.Join(validateSecureOpenFile(file, path, uid), validateSecureWorkspace(workspace, uid), validateSecureTempBase(base, uid))
}

var errAPKTransitionExecutionUnavailable = errors.New("APK transition preparation is verified, but native execution remains unavailable pending coordinated hooks, removal and failure qualification; no package transaction performed")

type authenticatedAPKCandidate struct {
	target              packageTarget
	version             string
	artifact            updateArtifact
	file                *os.File
	path                string
	manifest, signature []byte
	cliSHA256           string
	offline             bool
	uid                 int
	keys                map[string]ed25519.PublicKey
	attestInstalled     installedVersionAttestor
}

type apkTransitionPreparer func(context.Context, authenticatedAPKCandidate) error

type apkTransitionIdentity struct {
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Mode        uint32 `json:"mode"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Links       uint64 `json:"links"`
	Size        int64  `json:"size"`
	ModifiedSec int64  `json:"modified_sec"`
	ModifiedNS  int64  `json:"modified_ns"`
	ChangedSec  int64  `json:"changed_sec"`
	ChangedNS   int64  `json:"changed_ns"`
}

func apkTransitionStat(status *syscall.Stat_t) apkTransitionIdentity {
	return apkTransitionIdentity{status.Dev, status.Ino, status.Mode, status.Uid, status.Gid, status.Nlink, status.Size,
		status.Mtim.Sec, status.Mtim.Nsec, status.Ctim.Sec, status.Ctim.Nsec}
}

type apkTransitionHostEntry struct {
	Path       string                `json:"path"`
	Identity   apkTransitionIdentity `json:"identity"`
	Absent     bool                  `json:"absent,omitempty"`
	LinkTarget string                `json:"link_target,omitempty"`
	Content    []byte                `json:"content,omitempty"`
}

type apkTransitionPolicyBinding struct {
	ApprovalSHA256 string `json:"approval_sha256"`
	PolicySHA256   string `json:"policy_sha256"`
	HostSHA256     string `json:"host_sha256"`
}

type apkTransitionPlan struct {
	Schema                    string                     `json:"schema"`
	PackageName               string                     `json:"package_name"`
	Installer                 string                     `json:"installer"`
	CandidateVersion          string                     `json:"candidate_version"`
	Artifact                  updateArtifact             `json:"artifact"`
	CandidateAPKChecksum      string                     `json:"candidate_apk_checksum"`
	CandidateCapabilitySHA256 string                     `json:"candidate_capability_sha256"`
	EffectPlanSHA256          string                     `json:"effect_plan_sha256"`
	CandidateCLISHA256        string                     `json:"candidate_cli_sha256"`
	ManifestSHA256            string                     `json:"manifest_sha256"`
	SignatureSHA256           string                     `json:"signature_sha256"`
	InstalledVersion          string                     `json:"installed_version"`
	InstalledCLISHA256        string                     `json:"installed_cli_sha256"`
	Inventory                 []apkTransitionMember      `json:"inventory"`
	HostSnapshotSHA256        string                     `json:"host_snapshot_sha256"`
	Policy                    apkTransitionPolicyBinding `json:"runtime_policy"`
	RetainedDependencyNames   []string                   `json:"retained_dependency_names"`
	Offline                   bool                       `json:"offline"`
	NativeExecutionAuthorized bool                       `json:"native_execution_authorized"`
	ProductAccepted           bool                       `json:"product_accepted"`
}

type apkTransitionActivation interface {
	DurableEffects() ([]byte, error)
	OriginalRuntime() nativeActivationRuntimeSnapshot
	EffectPlanSHA256() string
	Revalidate(context.Context) error
	VerifyInstalledCandidate(context.Context) error
}

type apkTransitionServices struct {
	activation    func(context.Context, authenticatedAPKCandidate) (apkTransitionActivation, error)
	root          string
	hostRoot      string
	verifyNative  func(context.Context, authenticatedAPKCandidate) error
	policy        func(context.Context) (apkTransitionPolicyBinding, error)
	copyCandidate func(context.Context, *pinnedServiceDirectory, authenticatedAPKCandidate) error
	publish       func(*pinnedServiceDirectory, string, string) error
}

func productionAPKTransitionServices() apkTransitionServices {
	return apkTransitionServices{root: apkTransitionRoot, hostRoot: "/", verifyNative: verifyAPKTransitionNativeSignature,
		policy: captureAPKTransitionPolicy,
		activation: func(ctx context.Context, candidate authenticatedAPKCandidate) (apkTransitionActivation, error) {
			return captureNativeActivationBinding(ctx, candidate)
		}}
}

func captureAPKTransitionPolicy(ctx context.Context) (apkTransitionPolicyBinding, error) {
	policy, err := config.CaptureActivationPolicy(ctx, "/etc/syswarden/config")
	if err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	approval, err := policy.VerifyApproved(ctx)
	if err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	if approval == nil || approval.Review().Operation != "install" {
		return apkTransitionPolicyBinding{}, errors.New("APK transition requires an existing exact runtime install approval")
	}
	review := approval.Review()
	if err := policy.Revalidate(ctx); err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	if err := approval.Revalidate(ctx); err != nil {
		return apkTransitionPolicyBinding{}, err
	}
	return apkTransitionPolicyBinding{review.SHA256, review.PolicySHA256, review.HostSHA256}, nil
}

func verifyAPKTransitionNativeSignature(ctx context.Context, candidate authenticatedAPKCandidate) error {
	if candidate.target.installer != "/sbin/apk" && candidate.target.installer != "/usr/sbin/apk" {
		return errors.New("APK signature verification requires the fixed native manager")
	}
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid); err != nil {
		return err
	}
	// This read-only command uses the existing system trust roots. No custom
	// keys, untrusted override, scripts, repositories or caller arguments enter.
	command := exec.Command(candidate.target.installer, "verify", candidate.path) // #nosec G204 -- fixed manager and authenticated protected package
	command.Dir = "/"
	command.Env = nativeRetentionEnvironment()
	output := qualificationBoundedBuffer{limit: maximumQualificationQueryOutputBytes}
	command.Stdout, command.Stderr = &output, &output
	if err := runQualificationProcessGroup(ctx, command); err != nil {
		return fmt.Errorf("native APK signature verification failed: %w", err)
	}
	if output.overflow {
		return errors.New("native APK signature verification exceeded its diagnostic bound")
	}
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid); err != nil {
		return err
	}
	return ctx.Err()
}

func prepareProductionAPKTransition(ctx context.Context, candidate authenticatedAPKCandidate) error {
	return prepareAPKTransition(ctx, candidate, productionAPKTransitionServices())
}

func prepareAPKTransition(ctx context.Context, candidate authenticatedAPKCandidate, services apkTransitionServices) (returnErr error) {
	if ctx == nil || services.verifyNative == nil || services.policy == nil || services.activation == nil || candidate.attestInstalled == nil {
		return errors.New("APK transition preparation dependencies are unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if candidate.target.packageName != compatibilityNativePackageName || candidate.target.format != packageFormatAPK ||
		candidate.target.os != "linux" || candidate.target.architecture != "amd64" || candidate.uid != os.Geteuid() {
		return errors.New("APK transition requires the existing Linux AMD64 compatibility identity")
	}
	manifest, err := verifySignedManifest(candidate.manifest, candidate.signature, candidate.version, candidate.keys)
	if err != nil {
		return err
	}
	artifact, err := manifest.artifactFor(candidate.target)
	if err != nil || artifact != candidate.artifact {
		return errors.New("APK transition candidate differs from its signed manifest")
	}
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, artifact, candidate.uid); err != nil {
		return err
	}
	parent, err := openAPKTransitionRoot(services.root, true)
	if err != nil {
		return err
	}
	defer parent.close()
	if err := syscall.Flock(parent.fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another APK preparation owns private custody: %w", err)
	}
	defer func() { _ = syscall.Flock(parent.fd, syscall.LOCK_UN) }()
	path, err := os.MkdirTemp(services.root, ".pending-")
	if err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return err
	}
	defer directory.close()
	// Pending material is deliberately never removed, even after cancellation
	// or a failed copy. An incomplete directory never grants approval.
	defer func() {
		if returnErr != nil {
			var review *APKTransitionApprovalRequiredError
			if !errors.As(returnErr, &review) {
				data, _ := json.Marshal(map[string]string{"schema": apkTransitionSchema, "state": "preparation-failed", "error": returnErr.Error()})
				_ = writeAPKTransitionBytes(directory, "failure.json", append(data, '\n'))
				returnErr = fmt.Errorf("APK preparation refused; incomplete custody retained at %s: %w", path, returnErr)
			}
		}
	}()
	if err := parent.sync(); err != nil {
		return err
	}
	for name, data := range map[string][]byte{updateManifestAssetName: candidate.manifest, updateManifestSignatureAssetName: candidate.signature} {
		if err := writeAPKTransitionBytes(directory, name, data); err != nil {
			return err
		}
	}
	copyCandidate := services.copyCandidate
	if copyCandidate == nil {
		copyCandidate = copyAPKTransitionCandidate
	}
	if err := copyCandidate(ctx, directory, candidate); err != nil {
		return err
	}
	if err := services.verifyNative(ctx, candidate); err != nil {
		return err
	}
	inventory, header, err := readAPKTransitionInventory(ctx, candidate.file)
	if err != nil {
		return err
	}
	if err := attestNativePackageHeaderWith(ctx, candidate.target, candidate.version, candidate.file,
		func(context.Context, *os.File) (nativePackageHeaderIdentity, error) { return header, nil }); err != nil {
		return err
	}
	candidateChecksum, err := readAuthenticatedAPKRegistrationChecksum(ctx, candidate.file)
	if err != nil {
		return err
	}
	cliDigest := ""
	for _, member := range inventory {
		if member.Path == "opt/syswarden/bin/syswarden-cli" {
			cliDigest = member.SHA256
		}
	}
	if !validSHA256(candidate.cliSHA256) || cliDigest != candidate.cliSHA256 {
		return errors.New("APK full inventory CLI digest differs from authenticated CLI attestation")
	}
	installed, err := candidate.attestInstalled(ctx, candidate.target, candidate.uid)
	if err != nil || !validSHA256(installed.cliSHA256) {
		return errors.Join(errors.New("APK original installed identity is unavailable"), err)
	}
	if comparison, err := compareReleaseVersions(installed.version, candidate.version); err != nil || comparison >= 0 {
		return errors.New("APK transition refuses equal-version replacement or downgrade")
	}
	snapshot, err := captureAPKTransitionHost(ctx, services.hostRoot)
	if err != nil {
		return err
	}
	var world, database []byte
	for _, entry := range snapshot {
		switch entry.Path {
		case "etc/apk/world":
			world = entry.Content
		case "lib/apk/db/installed":
			database = entry.Content
		}
	}
	dependencies, err := apkDependencyRetentionNamesForName(candidate.target.packageName, world, database)
	if err != nil {
		return err
	}
	hostBytes, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	hostBytes = append(hostBytes, '\n')
	if err := writeAPKTransitionBytes(directory, "host-snapshot.json", hostBytes); err != nil {
		return err
	}
	policy, err := services.policy(ctx)
	if err != nil {
		return fmt.Errorf("APK replacement requires prior exact runtime approval: %w", err)
	}
	if !validSHA256(policy.ApprovalSHA256) || !validSHA256(policy.PolicySHA256) || !validSHA256(policy.HostSHA256) {
		return errors.New("APK runtime approval binding is incomplete")
	}
	capability, err := attestNativeActivationCandidate(ctx, candidate.target, candidate.file)
	if err != nil {
		return err
	}
	activation, err := services.activation(ctx, candidate)
	if err != nil {
		return err
	}
	if activation == nil || !validSHA256(activation.EffectPlanSHA256()) {
		return errors.New("APK candidate effect evidence is incomplete")
	}
	if err := activation.Revalidate(ctx); err != nil {
		return err
	}
	effects, err := activation.DurableEffects()
	if err != nil || len(effects) == 0 || len(effects) > 1<<20 || apkTransitionDigest(effects) != activation.EffectPlanSHA256() {
		return errors.Join(errors.New("APK durable effects differ from original approval evidence"), err)
	}
	if err := writeAPKTransitionBytes(directory, "native-effects.json", effects); err != nil {
		return err
	}
	plan := apkTransitionPlan{CandidateAPKChecksum: candidateChecksum, CandidateCapabilitySHA256: capability.SHA256(), EffectPlanSHA256: activation.EffectPlanSHA256(), Schema: apkTransitionSchema, PackageName: candidate.target.packageName, Installer: candidate.target.installer, CandidateVersion: candidate.version,
		Artifact: artifact, CandidateCLISHA256: cliDigest, ManifestSHA256: apkTransitionDigest(candidate.manifest), SignatureSHA256: apkTransitionDigest(candidate.signature),
		InstalledVersion: installed.version, InstalledCLISHA256: installed.cliSHA256, Inventory: inventory, HostSnapshotSHA256: apkTransitionDigest(hostBytes), Policy: policy,
		RetainedDependencyNames: dependencies, Offline: candidate.offline}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	planBytes = append(planBytes, '\n')
	digest := apkTransitionDigest(planBytes)
	if err := writeAPKTransitionBytes(directory, "plan.json", planBytes); err != nil {
		return err
	}
	if err := writeAPKTransitionBytes(directory, "prepared.json", []byte("{\"schema\":\""+apkTransitionSchema+"\",\"state\":\"prepared-only\",\"plan_sha256\":\""+digest+"\"}\n")); err != nil {
		return err
	}
	current, err := captureAPKTransitionHost(ctx, services.hostRoot)
	if err != nil || !reflect.DeepEqual(snapshot, current) {
		return errors.Join(errors.New("APK host evidence changed during preparation"), err)
	}
	currentPolicy, err := services.policy(ctx)
	if err != nil || currentPolicy != policy {
		return errors.Join(errors.New("APK runtime approval changed during preparation"), err)
	}
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, artifact, candidate.uid); err != nil {
		return err
	}
	if err := errors.Join(ctx.Err(), attestRetainedDirectoryParent(services.root, parent, false), attestRetainedDirectoryParent(path, directory, false)); err != nil {
		return err
	}
	publish := services.publish
	if publish == nil {
		publish = func(parent *pinnedServiceDirectory, pending, digest string) error {
			return unix.Renameat2(parent.fd, pending, parent.fd, digest, unix.RENAME_NOREPLACE)
		}
	}
	if err := publish(parent, filepath.Base(path), digest); err != nil {
		return fmt.Errorf("APK plan publication refused without overwriting existing evidence: %w", err)
	}
	path = filepath.Join(services.root, digest)
	if err := parent.sync(); err != nil {
		return err
	}
	if err := attestRetainedDirectoryParent(path, directory, false); err != nil {
		return err
	}
	return &APKTransitionApprovalRequiredError{PlanSHA256: digest, Directory: path}
}

func apkTransitionDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func openAPKTransitionRoot(path string, create bool) (*pinnedServiceDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != filepath.Base(apkTransitionRoot) {
		return nil, errors.New("unsupported APK transition custody path")
	}
	parent, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.close()
	if create {
		if err := parent.root.Mkdir(filepath.Base(path), 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := parent.sync(); err != nil {
			return nil, err
		}
	}
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		directory.close()
		return nil, errors.New("APK transition custody must be a private real directory")
	}
	if err := attestRetainedDirectoryParent(filepath.Dir(path), parent, false); err != nil {
		directory.close()
		return nil, err
	}
	return directory, nil
}

func writeAPKTransitionBytes(directory *pinnedServiceDirectory, name string, content []byte) error {
	file, err := directory.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	return errors.Join(writeErr, file.Sync(), file.Close(), directory.sync())
}

func copyAPKTransitionCandidate(ctx context.Context, directory *pinnedServiceDirectory, candidate authenticatedAPKCandidate) error {
	file, err := directory.root.OpenFile(candidate.artifact.Filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	digest := sha256.New()
	total := int64(0)
	reader := &nativeHeaderReader{reader: io.NewSectionReader(candidate.file, 0, candidate.artifact.Size), ctx: ctx, limit: candidate.artifact.Size, total: &total}
	n, copyErr := io.Copy(io.MultiWriter(file, digest), reader)
	err = errors.Join(copyErr, file.Sync(), file.Close(), directory.sync())
	if err != nil {
		return err
	}
	if n != candidate.artifact.Size || hex.EncodeToString(digest.Sum(nil)) != candidate.artifact.SHA256 {
		return errors.New("APK retained candidate does not match authenticated bytes")
	}
	return verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid)
}

func captureAPKTransitionHost(ctx context.Context, anchor string) ([]apkTransitionHostEntry, error) {
	if ctx == nil || !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor {
		return nil, errors.New("APK host snapshot root is invalid")
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	var entries []apkTransitionHostEntry
	total := 0
	var capture func(string, bool, bool) error
	capture = func(path string, recursive, optional bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(entries) >= 2048 {
			return errors.New("APK host evidence has too many paths")
		}
		before, err := root.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && optional {
			entries = append(entries, apkTransitionHostEntry{Path: path, Absent: true})
			return nil
		}
		if err != nil {
			return err
		}
		status, ok := before.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("APK host evidence metadata is unavailable")
		}
		entry := apkTransitionHostEntry{Path: path, Identity: apkTransitionStat(status)}
		switch {
		case before.IsDir():
			if int(status.Uid) != os.Geteuid() || int(status.Gid) != os.Getegid() || before.Mode().Perm()&0022 != 0 {
				return errors.New("APK evidence directory is not administrator-controlled")
			}
			if recursive {
				dir, err := root.Open(path)
				if err != nil {
					return err
				}
				opened, statErr := dir.Stat()
				names, readErr := dir.Readdirnames(2049)
				closeErr := dir.Close()
				if statErr != nil || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) >= 2049 || !os.SameFile(before, opened) {
					return errors.New("APK configuration inventory changed or exceeds its bound")
				}
				sort.Strings(names)
				for _, name := range names {
					if err := capture(filepath.Join(path, name), true, false); err != nil {
						return err
					}
				}
			}
		case before.Mode().IsRegular():
			if status.Nlink != 1 || status.Size < 0 || status.Size > maximumAPKInstalledDatabaseSize || total+int(status.Size) > maximumAPKTransitionSnapshotBytes {
				return errors.New("APK original file is linked or exceeds its evidence bound")
			}
			file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			opened, statErr := file.Stat()
			content, readErr := io.ReadAll(io.LimitReader(file, status.Size+1))
			finished, finishErr := file.Stat()
			closeErr := file.Close()
			if statErr != nil || finishErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, finished) || int64(len(content)) != status.Size {
				return errors.New("APK original file changed during capture")
			}
			if apkTransitionStat(finished.Sys().(*syscall.Stat_t)) != entry.Identity {
				return errors.New("APK original file metadata changed during capture")
			}
			if len(content) != 0 {
				entry.Content = content
			}
			total += len(content)
		case before.Mode()&os.ModeSymlink != 0:
			if recursive || status.Nlink != 1 {
				return errors.New("APK configuration links require separate bounded recovery")
			}
			entry.LinkTarget, err = root.Readlink(path)
			if err != nil || len(entry.LinkTarget) > 4096 {
				return errors.New("APK alias link target is unavailable or excessive")
			}
		default:
			return errors.New("APK original evidence contains an unsupported file kind")
		}
		after, err := root.Lstat(path)
		if err != nil || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != entry.Identity {
			return errors.New("APK original evidence changed during capture")
		}
		entries = append(entries, entry)
		return nil
	}
	for _, path := range []string{".", "usr", "usr/local", "usr/local/bin", "etc", "etc/apk", "lib", "lib/apk", "lib/apk/db"} {
		info, err := root.Lstat(path)
		if err != nil || !info.IsDir() {
			return nil, errors.New("APK evidence ancestry is not a real directory")
		}
		if err := capture(path, false, false); err != nil {
			return nil, err
		}
	}
	for _, path := range []string{"etc/apk/world", "lib/apk/db/installed"} {
		if err := capture(path, false, false); err != nil {
			return nil, err
		}
	}
	for _, path := range []string{"usr/local/bin/syswarden", "usr/local/bin/syswarden-tui"} {
		if err := capture(path, false, true); err != nil {
			return nil, err
		}
	}
	if err := capture("etc/syswarden", true, false); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, ctx.Err()
}

// UpgradeSystemWithAPKTransitionApproval reviews only an already retained plan.
// It never discovers a newer release, adopts current aliases, invokes APK or
// restarts a service. The native execution boundary remains explicitly closed.
func UpgradeSystemWithAPKTransitionApproval(planSHA256 string) error {
	if os.Geteuid() != 0 {
		return errors.New("APK transition review requires root")
	}
	keys, err := embeddedTrustedReleaseKeys()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	identity, err := preflightStandardNativeUpdate(ctx)
	if err != nil {
		return err
	}
	if identity.manager != "apk" || identity.name != compatibilityNativePackageName {
		return errors.New("APK review requires the installed compatibility identity")
	}
	return approvePreparedAPKTransition(ctx, planSHA256, keys, attestInstalledQualificationVersion, productionAPKTransitionServices())
}

// A verified preparation retains the exact candidate and both custody directory
// descriptors under the preparation lock. That lock is not an APK database lease.
type verifiedPreparedAPKTransition struct {
	digest, path      string
	services          apkTransitionServices
	parent, directory *pinnedServiceDirectory
	plan              apkTransitionPlan
	candidate         authenticatedAPKCandidate
	snapshot          []apkTransitionHostEntry
	activation        apkTransitionActivation
	capability        NativeActivationCandidate
	locked, closed    bool
}

func (prepared *verifiedPreparedAPKTransition) Close() error {
	if prepared == nil || prepared.closed {
		return nil
	}
	prepared.closed = true
	var err error
	if prepared.candidate.file != nil {
		err = errors.Join(err, prepared.candidate.file.Close())
	}
	if prepared.directory != nil {
		err = errors.Join(err, prepared.directory.file.Close(), prepared.directory.root.Close())
	}
	if prepared.parent != nil {
		if prepared.locked {
			err = errors.Join(err, syscall.Flock(prepared.parent.fd, syscall.LOCK_UN))
		}
		err = errors.Join(err, prepared.parent.file.Close(), prepared.parent.root.Close())
	}
	return err
}

func (prepared *verifiedPreparedAPKTransition) Revalidate(ctx context.Context) error {
	if prepared == nil || prepared.closed || prepared.activation == nil || ctx == nil {
		return errors.New("verified APK preparation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := prepared.candidate
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid); err != nil {
		return err
	}
	installed, err := candidate.attestInstalled(ctx, candidate.target, candidate.uid)
	if err != nil || installed.version != prepared.plan.InstalledVersion || installed.cliSHA256 != prepared.plan.InstalledCLISHA256 {
		return errors.Join(errors.New("APK original native identity changed before execution"), err)
	}
	current, err := captureAPKTransitionHost(ctx, prepared.services.hostRoot)
	if err != nil || !reflect.DeepEqual(current, prepared.snapshot) {
		return errors.Join(errors.New("APK original host evidence changed before execution"), err)
	}
	policy, err := prepared.services.policy(ctx)
	if err != nil || policy != prepared.plan.Policy {
		return errors.Join(errors.New("APK original runtime approval changed before execution"), err)
	}
	return errors.Join(ctx.Err(), prepared.activation.Revalidate(ctx), attestRetainedDirectoryParent(prepared.services.root, prepared.parent, false), attestRetainedDirectoryParent(prepared.path, prepared.directory, false))
}

func openVerifiedPreparedAPKTransition(ctx context.Context, digest string, keys map[string]ed25519.PublicKey,
	attest installedVersionAttestor, services apkTransitionServices) (*verifiedPreparedAPKTransition, error) {
	return openRetainedAPKTransition(ctx, digest, keys, attest, services, true)
}

// Poststate inspection authenticates original retained evidence without
// recapturing the replaced host as its original before-transaction authority.
func openRetainedAPKTransition(ctx context.Context, digest string, keys map[string]ed25519.PublicKey,
	attest installedVersionAttestor, services apkTransitionServices, original bool) (verified *verifiedPreparedAPKTransition, returnErr error) {
	if ctx == nil || !validSHA256(digest) || services.policy == nil || services.verifyNative == nil || original && services.activation == nil || attest == nil {
		return nil, errors.New("APK review requires an exact stored plan digest and complete verification dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := openAPKTransitionRoot(services.root, false)
	if err != nil {
		return nil, err
	}
	opened := &verifiedPreparedAPKTransition{digest: digest, services: services, parent: parent}
	defer func() {
		if verified == nil {
			returnErr = errors.Join(returnErr, opened.Close())
		}
	}()
	if err := syscall.Flock(parent.fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	opened.locked = true
	path := filepath.Join(services.root, digest)
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	opened.directory, opened.path = directory, path
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return nil, errors.New("APK stored plan directory is not private")
	}
	planBytes, err := readAPKTransitionBytes(directory, "plan.json", 1<<20)
	if err != nil || apkTransitionDigest(planBytes) != digest {
		return nil, errors.New("APK approval does not match immutable stored plan bytes")
	}
	var plan apkTransitionPlan
	if err := decodeAPKTransitionJSON(planBytes, &plan); err != nil {
		return nil, err
	}
	if plan.Schema != apkTransitionSchema || plan.PackageName != compatibilityNativePackageName || plan.NativeExecutionAuthorized || plan.ProductAccepted || !validAPKRetentionChecksum(plan.CandidateAPKChecksum) || !validSHA256(plan.CandidateCapabilitySHA256) || !validSHA256(plan.EffectPlanSHA256) {
		return nil, errors.New("APK stored plan claims unsupported identity, execution or acceptance")
	}
	prepared, err := readAPKTransitionBytes(directory, "prepared.json", 1024)
	wantPrepared := "{\"schema\":\"" + apkTransitionSchema + "\",\"state\":\"prepared-only\",\"plan_sha256\":\"" + digest + "\"}\n"
	if err != nil || string(prepared) != wantPrepared {
		return nil, errors.New("APK plan preparation is incomplete")
	}
	if err := inspectAPKTransitionCustodyInventory(directory, plan.Artifact.Filename); err != nil {
		return nil, err
	}
	manifestBytes, err := readAPKTransitionBytes(directory, updateManifestAssetName, maxManifestBytes)
	if err != nil || apkTransitionDigest(manifestBytes) != plan.ManifestSHA256 {
		return nil, errors.New("APK stored manifest changed")
	}
	signatureBytes, err := readAPKTransitionBytes(directory, updateManifestSignatureAssetName, maxSignatureAssetBytes)
	if err != nil || apkTransitionDigest(signatureBytes) != plan.SignatureSHA256 {
		return nil, errors.New("APK stored manifest signature changed")
	}
	manifest, err := verifySignedManifest(manifestBytes, signatureBytes, plan.CandidateVersion, keys)
	if err != nil {
		return nil, err
	}
	if plan.Installer != "/sbin/apk" && plan.Installer != "/usr/sbin/apk" {
		return nil, errors.New("APK stored native manager is unsupported")
	}
	target := packageTarget{packageName: plan.PackageName, os: "linux", architecture: "amd64", format: packageFormatAPK, filename: plan.Artifact.Filename, installer: plan.Installer}
	artifact, err := manifest.artifactFor(target)
	if err != nil || artifact != plan.Artifact {
		return nil, errors.New("APK stored candidate selection changed")
	}
	packagePath := filepath.Join(path, artifact.Filename)
	file, err := directory.root.OpenFile(artifact.Filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened.candidate.file = file
	candidate := authenticatedAPKCandidate{target: target, version: plan.CandidateVersion, artifact: artifact, file: file, path: packagePath,
		manifest: manifestBytes, signature: signatureBytes, cliSHA256: plan.CandidateCLISHA256, uid: os.Geteuid(), keys: keys, attestInstalled: attest, offline: plan.Offline}
	if err := verifySecurePackageForInstallation(file, packagePath, artifact, candidate.uid); err != nil {
		return nil, err
	}
	if err := services.verifyNative(ctx, candidate); err != nil {
		return nil, err
	}
	inventory, header, err := readAPKTransitionInventory(ctx, file)
	if err != nil || !reflect.DeepEqual(inventory, plan.Inventory) {
		return nil, errors.Join(errors.New("APK stored candidate full inventory changed"), err)
	}
	if err := attestNativePackageHeaderWith(ctx, target, plan.CandidateVersion, file,
		func(context.Context, *os.File) (nativePackageHeaderIdentity, error) { return header, nil }); err != nil {
		return nil, err
	}
	candidateChecksum, err := readAuthenticatedAPKRegistrationChecksum(ctx, file)
	if err != nil || candidateChecksum != plan.CandidateAPKChecksum {
		return nil, errors.Join(errors.New("APK stored native registration identity differs from authenticated control bytes"), err)
	}

	if original {
		installed, err := attest(ctx, target, candidate.uid)
		if err != nil || installed.version != plan.InstalledVersion || installed.cliSHA256 != plan.InstalledCLISHA256 {
			return nil, errors.Join(errors.New("APK original installed candidate changed since preparation"), err)
		}
	}
	effects, err := readAPKTransitionBytes(directory, "native-effects.json", 1<<20)
	if err != nil || apkTransitionDigest(effects) != plan.EffectPlanSHA256 {
		return nil, errors.Join(errors.New("APK retained original effects changed"), err)
	}
	snapshotBytes, err := readAPKTransitionBytes(directory, "host-snapshot.json", 2*maximumAPKTransitionSnapshotBytes)
	if err != nil || apkTransitionDigest(snapshotBytes) != plan.HostSnapshotSHA256 {
		return nil, errors.New("APK original host evidence changed")
	}
	var snapshot []apkTransitionHostEntry
	if err := decodeAPKTransitionJSON(snapshotBytes, &snapshot); err != nil {
		return nil, err
	}
	if original {
		current, err := captureAPKTransitionHost(ctx, services.hostRoot)
		if err != nil || !reflect.DeepEqual(snapshot, current) {
			return nil, errors.Join(errors.New("APK current host differs from the explicitly reviewed plan"), err)
		}
	}
	policy, err := services.policy(ctx)
	if err != nil || policy != plan.Policy {
		return nil, errors.Join(errors.New("APK current runtime approval differs from the stored plan"), err)
	}
	if err := errors.Join(ctx.Err(), attestRetainedDirectoryParent(services.root, parent, false), attestRetainedDirectoryParent(path, directory, false)); err != nil {
		return nil, err
	}
	capability, err := attestNativeActivationCandidate(ctx, candidate.target, candidate.file)
	if err != nil || capability.SHA256() != plan.CandidateCapabilitySHA256 {
		return nil, errors.Join(errors.New("APK stored runtime capability changed"), err)
	}
	if original {
		activation, err := services.activation(ctx, candidate)
		if err != nil {
			return nil, err
		}
		if activation == nil || activation.EffectPlanSHA256() != plan.EffectPlanSHA256 {
			return nil, errors.New("APK stored candidate effect evidence changed")
		}
		if err := activation.Revalidate(ctx); err != nil {
			return nil, err
		}
		opened.activation = activation
	}
	opened.capability = capability
	opened.plan, opened.candidate, opened.snapshot = plan, candidate, snapshot
	return opened, nil
}

func approvePreparedAPKTransition(ctx context.Context, digest string, keys map[string]ed25519.PublicKey,
	attest installedVersionAttestor, services apkTransitionServices) (returnErr error) {
	prepared, err := openVerifiedPreparedAPKTransition(ctx, digest, keys, attest, services)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, prepared.Close()) }()
	directory := prepared.directory
	approval := []byte("{\"schema\":\"" + apkTransitionSchema + "\",\"state\":\"reviewed-preparation-only\",\"plan_sha256\":\"" + digest + "\",\"native_execution_authorized\":false}\n")
	if err := writeAPKTransitionBytes(directory, "approval.json", approval); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := readAPKTransitionBytes(directory, "approval.json", 1024)
		if readErr != nil || !bytes.Equal(existing, approval) {
			return errors.New("APK stored review differs; existing evidence was preserved")
		}
	}
	return errAPKTransitionExecutionUnavailable
}

func readAPKTransitionBytes(directory *pinnedServiceDirectory, name string, limit int64) ([]byte, error) {
	if !safeAssetName(name) {
		return nil, errors.New("APK evidence filename is invalid")
	}
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("APK evidence file kind, mode or bound is invalid")
	}
	status, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(status.Uid) != os.Geteuid() || int(status.Gid) != os.Getegid() || status.Nlink != 1 {
		return nil, errors.New("APK evidence ownership is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) != before.Size() {
		return nil, errors.New("APK evidence read is incomplete")
	}
	after, err := directory.root.Lstat(name)
	if err != nil || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != apkTransitionStat(status) {
		return nil, errors.New("APK evidence changed while reading")
	}
	return content, nil
}

func decodeAPKTransitionJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(append(canonical, '\n'), data) {
		return errors.New("APK evidence JSON is not canonical")
	}
	return nil
}

func inspectAPKTransitionCustodyInventory(directory *pinnedServiceDirectory, filename string) error {
	if !safeAssetName(filename) || !strings.HasSuffix(filename, ".apk") {
		return errors.New("APK custody candidate filename is invalid")
	}
	file, err := directory.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := file.Readdirnames(10)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > 8 {
		return errors.New("APK custody inventory is incomplete or excessive")
	}
	expected := map[string]bool{filename: true, updateManifestAssetName: true, updateManifestSignatureAssetName: true, "host-snapshot.json": true, "native-effects.json": true, "plan.json": true, "prepared.json": true}
	for _, name := range names {
		if name == "approval.json" {
			continue
		}
		if !expected[name] {
			return fmt.Errorf("APK custody contains unexpected evidence %q", name)
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		return errors.New("APK custody lacks required immutable evidence")
	}
	return nil
}

func (u *updater) preflightAPKTransition(ctx context.Context, target packageTarget, version string, artifact updateArtifact,
	file *os.File, path string, manifest, signature []byte, cliSHA256 string, offline bool) error {
	if target.format != packageFormatAPK {
		return nil
	}
	retain := func(err error) error {
		verified := verifySecurePackageForInstallation(file, path, artifact, u.effectiveUID)
		synchronized := synchronizeAPKTransitionStage(file, path, u.effectiveUID)
		return &APKTransitionRetainedMaterialError{Workspace: filepath.Dir(path), PackagePath: path, CandidateVerified: verified == nil,
			OriginalStageSynchronized: synchronized == nil, Cause: errors.Join(err, verified, synchronized)}
	}
	if err := synchronizeAPKTransitionStage(file, path, u.effectiveUID); err != nil {
		return retain(err)
	}
	if u.prepareAPKTransition == nil {
		return retain(errors.New("APK candidate capability is unclassified; authenticated transition preparation is required before package execution"))
	}
	bounded, cancel := context.WithTimeout(ctx, u.attestTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return retain(err)
	}
	err := u.prepareAPKTransition(bounded, authenticatedAPKCandidate{target: target, version: version, artifact: artifact, file: file, path: path,
		manifest: bytes.Clone(manifest), signature: bytes.Clone(signature), cliSHA256: cliSHA256, offline: offline,
		uid: u.effectiveUID, keys: u.trustedKeys, attestInstalled: u.attestInstalled})
	err = errors.Join(err, bounded.Err())
	if err == nil {
		return nil
	}
	var prepared *APKTransitionApprovalRequiredError
	if errors.As(err, &prepared) && bounded.Err() == nil {
		return err
	}
	return retain(err)
}
