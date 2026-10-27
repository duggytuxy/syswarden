//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The release builders compile these exact companion digests into the CLI
// after building the core and TUI. Missing bindings never authorize removal.
var standaloneCoreSHA256 string
var standaloneTUISHA256 string
var standaloneSignaturesSHA256 string

const maximumStandalonePayloadBytes = 128 << 20

func standalonePayloadDigests() (map[string]string, error) {
	// /proc/self/exe identifies the executing image, including after its original
	// directory has moved into a recovery backup. It is not an operator path.
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer func() { _ = self.Close() }()
	_, digest, err := hashStandalonePayload(self, 0750)
	if err != nil {
		return nil, err
	}
	expected := map[string]string{
		"bin/syswarden-cli":  digest,
		"bin/syswarden-core": standaloneCoreSHA256,
		"bin/syswarden-tui":  standaloneTUISHA256,
		"signatures.json":    standaloneSignaturesSHA256,
	}
	for name, value := range expected {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
			return nil, fmt.Errorf("standalone payload lacks a compiled exact companion binding for %s; preserve the CLI and payload for verified recovery", name)
		}
	}
	return expected, nil
}

func hashStandalonePayload(file *os.File, mode os.FileMode) (removalArtifactIdentity, string, error) {
	before, err := file.Stat()
	identity, identityErr := exactRemovalArtifactIdentity(before)
	if err != nil || identityErr != nil || !before.Mode().IsRegular() || before.Mode() != mode ||
		!serviceFileOwnedByCurrentUser(before) || identity.nlink != 1 || identity.size < 1 || identity.size > maximumStandalonePayloadBytes {
		return identity, "", fmt.Errorf("standalone payload must be an exclusive owner-controlled file with exact package permissions")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maximumStandalonePayloadBytes+1))
	if err != nil || size != identity.size {
		return identity, "", fmt.Errorf("standalone payload changed during bounded hashing")
	}
	after, err := file.Stat()
	actual, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != identity {
		return identity, "", fmt.Errorf("standalone payload identity changed during hashing")
	}
	return identity, fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func inspectStandalonePayload(directory *pinnedServiceDirectory, expected map[string]string) (retainedDirectorySnapshot, error) {
	return inspectBoundPayload(directory, expected, false)
}

// Source-only copies may coexist with administrator files. They never copy or
// grant retirement authority to anything outside the four compiled bindings.
func inspectBoundPayload(directory *pinnedServiceDirectory, expected map[string]string, additionalSourceEntries bool) (retainedDirectorySnapshot, error) {
	result := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	if len(expected) != 4 {
		return result, fmt.Errorf("standalone payload bindings are incomplete")
	}
	info, err := directory.root.Stat(".")
	if err != nil {
		return result, err
	}
	result.directory, err = exactRemovalArtifactIdentity(info)
	// Native archives create these directories as 0755; historical hardened
	// installations may retain 0750. Exact file bindings remain mandatory.
	if err != nil || !slices.Contains([]os.FileMode{os.ModeDir | 0750, os.ModeDir | 0755}, info.Mode()) || !serviceFileOwnedByCurrentUser(info) {
		return result, fmt.Errorf("standalone payload directory has unexpected metadata")
	}
	checkNames := func(root *os.Root, want []string) error {
		entries, err := readBoundedSharedRemovalEntries(root)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		slices.Sort(names)
		if additionalSourceEntries {
			for _, name := range want {
				if !slices.Contains(names, name) {
					return fmt.Errorf("compiled payload is incomplete")
				}
			}
		} else if !slices.Equal(names, want) {
			return fmt.Errorf("standalone payload contains missing or unrelated entries; preserve the original tree")
		}
		return nil
	}
	// Older payloads have no descriptor. A present descriptor is product-owned
	// only when its exact canonical bytes derive from already bound runtimes.
	descriptorName := filepath.Base(nativeActivationDescriptorPath)
	rootNames := []string{"bin", "signatures.json"}
	descriptorPresent := false
	if _, err := directory.root.Lstat(descriptorName); err == nil {
		descriptorPresent = true
		rootNames = append([]string{descriptorName}, rootNames...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if err := checkNames(directory.root, rootNames); err != nil {
		return result, err
	}
	binInfo, err := directory.root.Lstat("bin")
	binIdentity, identityErr := exactRemovalArtifactIdentity(binInfo)
	if err != nil || identityErr != nil || !slices.Contains([]os.FileMode{os.ModeDir | 0750, os.ModeDir | 0755}, binInfo.Mode()) || !serviceFileOwnedByCurrentUser(binInfo) {
		return result, fmt.Errorf("standalone binary directory has unexpected metadata")
	}
	bin, err := directory.root.OpenRoot("bin")
	if err != nil {
		return result, err
	}
	defer func() { _ = bin.Close() }()
	opened, err := bin.Stat(".")
	actual, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || actual != binIdentity {
		return result, fmt.Errorf("standalone binary directory changed while opening")
	}
	if err := checkNames(bin, []string{"syswarden-cli", "syswarden-core", "syswarden-tui"}); err != nil {
		return result, err
	}
	result.files["bin"] = binIdentity
	digest := sha256.New()
	for _, name := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"} {
		root, relative, mode := directory.root, name, os.FileMode(0640)
		if name != "signatures.json" {
			root, relative, mode = bin, name[len("bin/"):], 0750
		}
		before, err := root.Lstat(relative)
		if err != nil || !before.Mode().IsRegular() {
			return result, fmt.Errorf("standalone payload entry is not a regular file: %s", name)
		}
		beforeIdentity, err := exactRemovalArtifactIdentity(before)
		if err != nil {
			return result, err
		}
		file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return result, err
		}
		identity, actual, readErr := hashStandalonePayload(file, mode)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || identity != beforeIdentity || actual != expected[name] {
			return result, fmt.Errorf("standalone payload does not match its compiled exact binding: %s", name)
		}
		after, err := root.Lstat(relative)
		afterIdentity, identityErr := exactRemovalArtifactIdentity(after)
		if err != nil || identityErr != nil || afterIdentity != identity {
			return result, fmt.Errorf("standalone payload entry changed: %s", name)
		}
		result.files[name], result.content[name] = identity, []byte(actual)
		_, _ = digest.Write([]byte(name + "\x00" + actual + "\n"))
	}
	if descriptorPresent {
		raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(expected["bin/syswarden-cli"], expected["bin/syswarden-core"]))
		if err != nil {
			return result, err
		}
		before, err := directory.root.Lstat(descriptorName)
		if err != nil || !before.Mode().IsRegular() || before.Size() != int64(len(raw)) {
			return result, errors.New("native activation removal descriptor is ambiguous")
		}
		beforeIdentity, err := exactRemovalArtifactIdentity(before)
		if err != nil {
			return result, err
		}
		file, err := directory.root.OpenFile(descriptorName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return result, err
		}
		identity, actual, readErr := hashStandalonePayload(file, 0644)
		closeErr := file.Close()
		want := fmt.Sprintf("%x", sha256.Sum256(raw))
		if readErr != nil || closeErr != nil || identity != beforeIdentity || actual != want {
			return result, errors.New("native activation removal descriptor does not match bound runtimes")
		}
		after, err := directory.root.Lstat(descriptorName)
		if err != nil {
			return result, err
		}
		afterIdentity, err := exactRemovalArtifactIdentity(after)
		if err != nil || afterIdentity != identity {
			return result, errors.New("native activation removal descriptor changed")
		}
		result.files[descriptorName], result.content[descriptorName] = identity, []byte(actual)
		_, _ = digest.Write([]byte(descriptorName + "\x00" + actual + "\n"))
	}
	if err := checkNames(directory.root, rootNames); err != nil {
		return result, err
	}
	if err := checkNames(bin, []string{"syswarden-cli", "syswarden-core", "syswarden-tui"}); err != nil {
		return result, err
	}
	for name, expectedIdentity := range map[string]removalArtifactIdentity{".": result.directory, "bin": binIdentity} {
		current, err := directory.root.Lstat(name)
		identity, identityErr := exactRemovalArtifactIdentity(current)
		if err != nil || identityErr != nil || identity != expectedIdentity {
			return result, fmt.Errorf("standalone payload directory changed during inspection")
		}
	}
	if err := attestBoundPayloadLeaves(directory.root, result); err != nil {
		return result, err
	}
	result.digest = fmt.Sprintf("%x", digest.Sum(nil))
	return result, nil
}

// Recheck the complete captured set after the final read. A directory identity
// alone cannot witness an in-place change to an earlier file during hashing.
func attestBoundPayloadLeaves(root *os.Root, snapshot retainedDirectorySnapshot) error {
	for name, expected := range snapshot.files {
		info, err := root.Lstat(name)
		actual, identityErr := exactRemovalArtifactIdentity(info)
		if err != nil || identityErr != nil || actual != expected {
			return fmt.Errorf("standalone payload changed before the complete snapshot was witnessed: %s", name)
		}
	}
	return nil
}

func retireStandalonePayloadForRemoval() error {
	guard := func() error {
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		if err := preflightHostRemovalMountBoundaries(); err != nil {
			return err
		}
		root, err := os.OpenRoot("/")
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		for _, path := range []string{"/opt/syswarden/bin/syswarden-cli", "/var/backups/syswarden-retired-v1/standalone-payload"} {
			if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
				return err
			}
		}
		if err := PreflightStandaloneUninstall(); err != nil {
			return err
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	if err := guard(); err != nil {
		return err
	}
	if _, err := os.Lstat("/opt/syswarden"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	expected, err := standalonePayloadDigests()
	if err != nil {
		return err
	}
	inspect := func(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
		return inspectStandalonePayload(directory, expected)
	}
	backup, err := retireAttestedDirectory("/opt", "syswarden", "/var/backups", "standalone-payload", guard, inspect, unix.Renameat2)
	if err == nil && backup != "" {
		fmt.Printf("[INFO] Retained exact standalone payload in private recovery backup: %s\n", backup)
	}
	return err
}

// A finalization retry may execute the original CLI from its exact private
// retained tree. Verify that complete tree before using its inodes to inspect
// processes. Original installed paths remain aliases for deleted processes.
func retainedStandaloneProcessScanner() (firewallRemovalProcessScanner, error) {
	scanner := productionFirewallRemovalProcessScanner()
	if _, err := os.Lstat(scanner.cliPath); !errors.Is(err, os.ErrNotExist) {
		return scanner, err
	}
	if err := RequireRemovalTombstone(); err != nil {
		return scanner, err
	}
	executing, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return scanner, err
	}
	const parent = "/var/backups/syswarden-retired-v1"
	if filepath.Clean(executing) != executing || filepath.Base(executing) != "syswarden-cli" || filepath.Base(filepath.Dir(executing)) != "bin" {
		return scanner, fmt.Errorf("absent installed CLI has no exact retained executable for finalization")
	}
	treePath := filepath.Dir(filepath.Dir(executing))
	isAPKCopy := strings.HasPrefix(filepath.Base(treePath), "apk-payload-")
	if filepath.Dir(treePath) != parent || (!strings.HasPrefix(filepath.Base(treePath), "standalone-payload-") && !isAPKCopy) {
		return scanner, fmt.Errorf("finalization executable is outside the private retained payload root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return scanner, err
	}
	_, err = historicalRemovalCandidatePresent(root, executing, 0, 0, func() {})
	_ = root.Close()
	if err != nil {
		return scanner, err
	}
	private, err := os.Lstat(parent)
	if err != nil || !private.IsDir() || private.Mode() != os.ModeDir|0700 || !serviceFileOwnedByCurrentUser(private) {
		return scanner, fmt.Errorf("retained payload parent is not private and owner controlled")
	}
	expected, err := standalonePayloadDigests()
	if err != nil {
		return scanner, err
	}
	directory, err := openExistingPinnedServiceDirectory(treePath)
	if err != nil {
		return scanner, err
	}
	snapshot, err := inspectStandalonePayload(directory, expected)
	directory.close()
	expectedName := retainedDirectoryBackupName("standalone-payload", snapshot)
	if isAPKCopy {
		expectedName = "apk-payload-" + snapshot.digest
	}
	if err != nil || expectedName != filepath.Base(treePath) {
		return scanner, fmt.Errorf("executing retained payload does not match its exact backup identity")
	}
	return bindRetainedStandaloneProcessScanner(scanner, treePath), nil
}

func bindRetainedStandaloneProcessScanner(scanner firewallRemovalProcessScanner, directory string) firewallRemovalProcessScanner {
	paths := map[string]string{
		scanner.cliPath:  filepath.Join(directory, "bin/syswarden-cli"),
		scanner.corePath: filepath.Join(directory, "bin/syswarden-core"),
		scanner.tuiPath:  filepath.Join(directory, "bin/syswarden-tui"),
	}
	resolve := func(path string) string {
		if actual, found := paths[path]; found {
			return actual
		}
		return path
	}
	lstat, stat, validate := scanner.lstat, scanner.stat, scanner.validateCLI
	scanner.lstat = func(path string) (os.FileInfo, error) { return lstat(resolve(path)) }
	scanner.stat = func(path string) (os.FileInfo, error) { return stat(resolve(path)) }
	scanner.validateCLI = func(path string) error { return validate(resolve(path)) }
	return scanner
}
