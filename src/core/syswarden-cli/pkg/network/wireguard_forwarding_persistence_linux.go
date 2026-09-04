//go:build linux

package network

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"

	"golang.org/x/sys/unix"
)

const (
	wireGuardForwardingTransitionSchema = "syswarden-wireguard-forwarding-transition-v1"
	wireGuardForwardingTransitionPath   = "/etc/wireguard/.syswarden-forwarding-transition-v1.json"
	wireGuardForwardingHeaderPrefix     = "# SYSWARDEN net.ipv4.ip_forward baseline v1 token="
	wireGuardForwardingSetting          = "net.ipv4.ip_forward = 1\n"
	maximumForwardingArtifactBytes      = 4096
	maximumForwardingTransitionBytes    = 64 << 10
)

var wireGuardForwardingTransitionFault = func(string) error { return nil }
var wireGuardForwardingRuntimeReconciler = reconcileWireGuardForwardingRuntime
var wireGuardExactFileDirectorySync = func(directory *os.File, _ string) error { return directory.Sync() }

type wireGuardForwardingPersistenceState struct {
	BootEnabled   bool
	BaselineKnown bool
	Baseline      string
	Legacy        bool
	Content       []byte
}

type wireGuardExactFile struct {
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	NLink  uint64 `json:"nlink"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
}

type wireGuardForwardingTransitionJournal struct {
	Schema              string             `json:"schema"`
	OwnershipToken      string             `json:"ownership_token"`
	TargetContent       string             `json:"target_content"`
	ForwardingStageName string             `json:"forwarding_stage_name"`
	ManifestStageName   string             `json:"manifest_stage_name"`
	OldForwarding       wireGuardExactFile `json:"old_forwarding"`
	OldManifest         wireGuardExactFile `json:"old_manifest"`
	OldManifestContent  string             `json:"old_manifest_content"`
}

func canonicalWireGuardForwardingContent(
	identity wireguardstate.ServerConfigurationIdentity,
	bootEnabled bool,
	baselineKnown bool,
	baseline string,
) ([]byte, error) {
	if !wireGuardOwnershipTokenName.MatchString(identity.OwnershipToken) {
		return nil, fmt.Errorf("invalid WireGuard ownership token for forwarding persistence")
	}
	value := "unknown"
	if baselineKnown {
		if baseline != "0" && baseline != "1" {
			return nil, fmt.Errorf("invalid attested net.ipv4.ip_forward baseline %q", baseline)
		}
		value = baseline
	}
	content := wireGuardForwardingHeaderPrefix + identity.OwnershipToken + " value=" + value + "\n"
	if bootEnabled {
		content += wireGuardForwardingSetting
	}
	return []byte(content), nil
}

func parseWireGuardForwardingPersistence(
	content []byte,
	identity wireguardstate.ServerConfigurationIdentity,
) (wireGuardForwardingPersistenceState, error) {
	if bytes.Equal(content, []byte(wireGuardForwardingSetting)) {
		return wireGuardForwardingPersistenceState{
			BootEnabled: true,
			Legacy:      true,
			Content:     append([]byte(nil), content...),
		}, nil
	}
	if !wireGuardOwnershipTokenName.MatchString(identity.OwnershipToken) {
		return wireGuardForwardingPersistenceState{}, fmt.Errorf("invalid WireGuard ownership token for forwarding persistence")
	}
	prefix := wireGuardForwardingHeaderPrefix + identity.OwnershipToken + " value="
	if !bytes.HasPrefix(content, []byte(prefix)) {
		return wireGuardForwardingPersistenceState{}, fmt.Errorf("WireGuard forwarding artifact has no exact ownership-bound baseline marker")
	}
	remainder := string(content[len(prefix):])
	line, tail, found := strings.Cut(remainder, "\n")
	if !found || (tail != "" && tail != wireGuardForwardingSetting) {
		return wireGuardForwardingPersistenceState{}, fmt.Errorf("WireGuard forwarding artifact has a noncanonical payload")
	}
	state := wireGuardForwardingPersistenceState{
		BootEnabled: tail == wireGuardForwardingSetting,
		Content:     append([]byte(nil), content...),
	}
	switch line {
	case "unknown":
	case "0", "1":
		state.BaselineKnown = true
		state.Baseline = line
	default:
		return wireGuardForwardingPersistenceState{}, fmt.Errorf("WireGuard forwarding artifact has an invalid baseline %q", line)
	}
	canonical, err := canonicalWireGuardForwardingContent(
		identity, state.BootEnabled, state.BaselineKnown, state.Baseline,
	)
	if err != nil || !bytes.Equal(canonical, content) {
		return wireGuardForwardingPersistenceState{}, fmt.Errorf("WireGuard forwarding artifact bytes are not canonical")
	}
	return state, nil
}

func wireGuardExactFileFromInfo(info os.FileInfo, content []byte) (wireGuardExactFile, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		stat.Uid != wireGuardExpectedOwnerUID || stat.Gid != wireGuardExpectedOwnerGID || stat.Nlink != 1 {
		return wireGuardExactFile{}, fmt.Errorf("file is not an exact owner-bound 0600 regular file")
	}
	digest := sha256.Sum256(content)
	return wireGuardExactFile{
		SHA256: hex.EncodeToString(digest[:]), Mode: uint32(info.Mode().Perm()),
		UID: stat.Uid, GID: stat.Gid, NLink: stat.Nlink,
		Device: uint64(stat.Dev), Inode: stat.Ino, Size: info.Size(),
	}, nil
}

func validWireGuardExactFile(identity wireGuardExactFile, maximum int64) bool {
	digest, err := hex.DecodeString(identity.SHA256)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == identity.SHA256 &&
		identity.Mode == 0600 && identity.UID == wireGuardExpectedOwnerUID &&
		identity.GID == wireGuardExpectedOwnerGID && identity.NLink == 1 &&
		identity.Inode != 0 && identity.Size >= 0 && identity.Size <= maximum
}

func sameWireGuardExactFile(left, right wireGuardExactFile) bool {
	return left == right
}

func wireGuardExactFileMatchesArtifact(identity wireGuardExactFile, artifact wireguardstate.Artifact) bool {
	return identity.SHA256 == artifact.SHA256 && identity.Mode == artifact.Mode &&
		identity.UID == artifact.UID && identity.GID == artifact.GID &&
		identity.NLink == artifact.NLink && identity.Device == artifact.Device &&
		identity.Inode == artifact.Inode
}

func wireGuardArtifactFromExactFile(path string, identity wireGuardExactFile) wireguardstate.Artifact {
	return wireguardstate.Artifact{
		Path: path, SHA256: identity.SHA256, Mode: identity.Mode,
		UID: identity.UID, GID: identity.GID, NLink: identity.NLink,
		Device: identity.Device, Inode: identity.Inode,
	}
}

func openAttestedWireGuardDirectory(relative string, exactMode os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(relative) || relative == "." {
		return nil, fmt.Errorf("invalid WireGuard directory %q", relative)
	}
	current, err := os.OpenRoot(wireGuardFilesystemRoot)
	if err != nil {
		return nil, fmt.Errorf("open WireGuard filesystem root: %w", err)
	}
	for index, component := range strings.Split(relative, "/") {
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect WireGuard directory %s: %w", relative, err)
		}
		if err := attestWireGuardDirectory(info, filepath.Join("/", strings.Join(strings.Split(relative, "/")[:index+1], "/"))); err != nil {
			_ = current.Close()
			return nil, err
		}
		if index == len(strings.Split(relative, "/"))-1 && exactMode != 0 && info.Mode().Perm() != exactMode.Perm() {
			_ = current.Close()
			return nil, fmt.Errorf("WireGuard directory /%s must have mode %#o", relative, exactMode.Perm())
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("pin WireGuard directory %s: %w", relative, err)
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("WireGuard directory /%s changed while opening", relative)
		}
		_ = current.Close()
		current = next
	}
	directory, err := current.Open(".")
	closeErr := current.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = directory.Close()
		return nil, closeErr
	}
	return directory, nil
}

func readWireGuardExactFileAt(directory *os.File, name string, maximum int64) (wireGuardExactFile, []byte, bool, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return wireGuardExactFile{}, nil, false, nil
	}
	if err != nil {
		return wireGuardExactFile{}, nil, false, fmt.Errorf("open exact WireGuard file %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return wireGuardExactFile{}, nil, false, fmt.Errorf("adopt exact WireGuard file %s", name)
	}
	info, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil {
		return wireGuardExactFile{}, nil, false, errors.Join(statErr, readErr, closeErr)
	}
	if int64(len(content)) > maximum {
		return wireGuardExactFile{}, nil, false, fmt.Errorf("WireGuard file %s exceeds %d bytes", name, maximum)
	}
	identity, err := wireGuardExactFileFromInfo(info, content)
	if err != nil {
		return wireGuardExactFile{}, nil, false, fmt.Errorf("attest exact WireGuard file %s: %w", name, err)
	}
	return identity, content, true, nil
}

func createWireGuardExactFileAt(directory *os.File, name string, content []byte) (wireGuardExactFile, error) {
	fd, err := unix.Openat(
		int(directory.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return wireGuardExactFile{}, fmt.Errorf("create private WireGuard stage %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return wireGuardExactFile{}, fmt.Errorf("adopt private WireGuard stage %s", name)
	}
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return wireGuardExactFile{}, err
	}
	identity, actual, present, err := readWireGuardExactFileAt(directory, name, int64(len(content)))
	if err != nil || !present || !bytes.Equal(actual, content) {
		if err == nil {
			err = fmt.Errorf("private WireGuard stage content mismatch")
		}
		return wireGuardExactFile{}, err
	}
	if err := wireGuardExactFileDirectorySync(directory, name); err != nil {
		return identity, fmt.Errorf("persist private WireGuard stage %s directory entry: %w", name, err)
	}
	return identity, nil
}

func randomWireGuardTransitionName(prefix string) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(cryptorand.Reader, value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func validWireGuardTransitionName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	suffix := name[len(prefix):]
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == suffix
}

func canonicalWireGuardForwardingJournal(journal wireGuardForwardingTransitionJournal) ([]byte, error) {
	if journal.Schema != wireGuardForwardingTransitionSchema ||
		!wireGuardOwnershipTokenName.MatchString(journal.OwnershipToken) ||
		!validWireGuardTransitionName(journal.ForwardingStageName, ".99-syswarden-wireguard.conf.stage-") ||
		!validWireGuardTransitionName(journal.ManifestStageName, ".syswarden-ownership-v1.json.stage-") ||
		!validWireGuardExactFile(journal.OldForwarding, maximumForwardingArtifactBytes) ||
		!validWireGuardExactFile(journal.OldManifest, 32<<10) ||
		int64(len(journal.OldManifestContent)) != journal.OldManifest.Size {
		return nil, fmt.Errorf("invalid WireGuard forwarding transition journal")
	}
	oldDigest := sha256.Sum256([]byte(journal.OldManifestContent))
	if hex.EncodeToString(oldDigest[:]) != journal.OldManifest.SHA256 {
		return nil, fmt.Errorf("WireGuard forwarding transition journal has an invalid prior manifest")
	}
	identity := wireguardstate.ServerConfigurationIdentity{OwnershipToken: journal.OwnershipToken}
	if _, err := parseWireGuardForwardingPersistence([]byte(journal.TargetContent), identity); err != nil {
		return nil, fmt.Errorf("WireGuard forwarding transition journal has an invalid target: %w", err)
	}
	wire, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func decodeWireGuardForwardingJournal(wire []byte) (wireGuardForwardingTransitionJournal, error) {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var journal wireGuardForwardingTransitionJournal
	if err := decoder.Decode(&journal); err != nil {
		return journal, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return journal, fmt.Errorf("WireGuard forwarding transition journal has trailing data")
	}
	canonical, err := canonicalWireGuardForwardingJournal(journal)
	if err != nil {
		return journal, err
	}
	if !bytes.Equal(canonical, wire) {
		return journal, fmt.Errorf("WireGuard forwarding transition journal bytes are not canonical")
	}
	return journal, nil
}

func wireGuardManifestArtifact(manifest wireguardstate.Manifest, path string) (wireguardstate.Artifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == path {
			return artifact, nil
		}
	}
	return wireguardstate.Artifact{}, fmt.Errorf("WireGuard ownership manifest is missing %s", path)
}

func canonicalWireGuardManifestBytes(manifest wireguardstate.Manifest) ([]byte, error) {
	wire, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(wire, '\n'), nil
}

func manifestWithWireGuardForwarding(
	manifest wireguardstate.Manifest,
	forwarding wireGuardExactFile,
) (wireguardstate.Manifest, []byte, error) {
	found := false
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].Path == wireguardstate.ForwardingConfigurationPath {
			manifest.Artifacts[index] = wireGuardArtifactFromExactFile(
				wireguardstate.ForwardingConfigurationPath, forwarding,
			)
			found = true
		}
	}
	if !found {
		return wireguardstate.Manifest{}, nil, fmt.Errorf("WireGuard ownership manifest is missing forwarding persistence")
	}
	wire, err := canonicalWireGuardManifestBytes(manifest)
	return manifest, wire, err
}

func readWireGuardForwardingTransitionJournal() (
	wireGuardForwardingTransitionJournal,
	wireGuardExactFile,
	bool,
	error,
) {
	directory, err := openAttestedWireGuardDirectory("etc/wireguard", 0700)
	if errors.Is(err, os.ErrNotExist) {
		return wireGuardForwardingTransitionJournal{}, wireGuardExactFile{}, false, nil
	}
	if err != nil {
		return wireGuardForwardingTransitionJournal{}, wireGuardExactFile{}, false, err
	}
	defer func() { _ = directory.Close() }()
	identity, wire, present, err := readWireGuardExactFileAt(
		directory, filepath.Base(wireGuardForwardingTransitionPath), maximumForwardingTransitionBytes,
	)
	if err != nil || !present {
		return wireGuardForwardingTransitionJournal{}, wireGuardExactFile{}, present, err
	}
	journal, err := decodeWireGuardForwardingJournal(wire)
	return journal, identity, true, err
}

func wireGuardForwardingTransitionPathPresent() (bool, error) {
	root, err := os.OpenRoot(wireGuardFilesystemRoot)
	if err != nil {
		return false, err
	}
	_, statErr := root.Lstat(strings.TrimPrefix(wireGuardForwardingTransitionPath, "/"))
	closeErr := root.Close()
	if errors.Is(statErr, os.ErrNotExist) {
		return false, closeErr
	}
	if statErr != nil {
		return false, errors.Join(statErr, closeErr)
	}
	if closeErr != nil {
		return false, closeErr
	}
	return true, nil
}

func wireGuardForwardingTransitionPending() (bool, error) {
	present, err := wireGuardForwardingTransitionPathPresent()
	if err != nil || !present {
		return present, err
	}
	_, _, present, err = readWireGuardForwardingTransitionJournal()
	return present, err
}

func verifyWireGuardStaticManifestArtifacts(manifest wireguardstate.Manifest) error {
	for _, path := range []string{
		wireguardstate.ServerConfigurationPath,
		wireguardstate.ClientConfigurationPath,
	} {
		if _, err := wireguardstate.ReadVerifiedArtifact(
			wireGuardFilesystemRoot, manifest, path,
			wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		); err != nil {
			return err
		}
	}
	if manifest.OpenRCServiceLink != nil {
		actual, present, err := wireguardstate.InspectOpenRCServiceLink(
			wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil || !present || actual != *manifest.OpenRCServiceLink {
			if err == nil {
				err = fmt.Errorf("owned OpenRC WireGuard service link identity mismatch")
			}
			return err
		}
	}
	return nil
}

func inspectWireGuardForwardingPersistence(
	manifest wireguardstate.Manifest,
	identity wireguardstate.ServerConfigurationIdentity,
) (wireGuardForwardingPersistenceState, error) {
	content, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, manifest, wireguardstate.ForwardingConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireGuardForwardingPersistenceState{}, err
	}
	return parseWireGuardForwardingPersistence(content, identity)
}

func reconcileWireGuardForwardingRuntime(value string) error {
	if value != "0" && value != "1" {
		return fmt.Errorf("refusing invalid attested net.ipv4.ip_forward baseline %q", value)
	}
	if wireGuardFilesystemRoot != "/" {
		return fmt.Errorf("runtime forwarding reconciliation requires the live filesystem root")
	}
	transaction, err := openPinnedWireGuardForwardingTransaction("/proc/sys/net/ipv4/ip_forward", 0)
	if err != nil {
		return err
	}
	if transaction.original == value {
		return transaction.Close()
	}
	writeErr := transaction.write(value)
	closeErr := transaction.Close()
	return errors.Join(writeErr, closeErr)
}

func exchangeWireGuardFiles(directory *os.File, left, right string) error {
	if err := unix.Renameat2(
		int(directory.Fd()), left, int(directory.Fd()), right, unix.RENAME_EXCHANGE,
	); err != nil {
		return err
	}
	return directory.Sync()
}

func removeExactWireGuardFileAt(
	directory *os.File,
	name string,
	expected wireGuardExactFile,
	maximum int64,
) error {
	actual, _, present, err := readWireGuardExactFileAt(directory, name, maximum)
	if err != nil || !present || !sameWireGuardExactFile(actual, expected) {
		if err == nil {
			err = fmt.Errorf("exact file identity mismatch")
		}
		return fmt.Errorf("refuse removal of changed WireGuard file %s: %w", name, err)
	}
	if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil {
		return err
	}
	return directory.Sync()
}

func decodeWireGuardManifestBytes(wire []byte) (wireguardstate.Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var manifest wireguardstate.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return manifest, fmt.Errorf("WireGuard ownership manifest has trailing data")
	}
	canonical, err := canonicalWireGuardManifestBytes(manifest)
	if err != nil || !bytes.Equal(canonical, wire) {
		return manifest, fmt.Errorf("WireGuard ownership manifest bytes are not canonical")
	}
	return manifest, nil
}

func recoverWireGuardForwardingTransition() (bool, error) {
	journal, journalIdentity, present, err := readWireGuardForwardingTransitionJournal()
	if err != nil || !present {
		return present, err
	}
	oldManifest, err := decodeWireGuardManifestBytes([]byte(journal.OldManifestContent))
	if err != nil {
		return true, fmt.Errorf("decode prior WireGuard ownership manifest from forwarding transition: %w", err)
	}
	oldForwardingArtifact, err := wireGuardManifestArtifact(oldManifest, wireguardstate.ForwardingConfigurationPath)
	if err != nil || !wireGuardExactFileMatchesArtifact(journal.OldForwarding, oldForwardingArtifact) {
		return true, fmt.Errorf("forwarding transition journal does not match its prior ownership manifest")
	}
	if err := verifyWireGuardStaticManifestArtifacts(oldManifest); err != nil {
		return true, fmt.Errorf("reattest static WireGuard artifacts before forwarding transition recovery: %w", err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, oldManifest, wireguardstate.ServerConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return true, err
	}
	serverIdentity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil || serverIdentity.OwnershipToken != journal.OwnershipToken {
		return true, fmt.Errorf("forwarding transition ownership token no longer matches the server configuration")
	}

	forwardingDirectory, err := openAttestedWireGuardDirectory("etc/sysctl.d", 0)
	if err != nil {
		return true, err
	}
	defer func() { _ = forwardingDirectory.Close() }()
	manifestDirectory, err := openAttestedWireGuardDirectory("etc/wireguard", 0700)
	if err != nil {
		return true, err
	}
	defer func() { _ = manifestDirectory.Close() }()

	activeForwarding, activeForwardingWire, activeForwardingPresent, err := readWireGuardExactFileAt(
		forwardingDirectory, filepath.Base(wireguardstate.ForwardingConfigurationPath), maximumForwardingArtifactBytes,
	)
	if err != nil || !activeForwardingPresent {
		return true, errors.Join(fmt.Errorf("active WireGuard forwarding artifact is absent during recovery"), err)
	}
	stageForwarding, stageForwardingWire, stageForwardingPresent, err := readWireGuardExactFileAt(
		forwardingDirectory, journal.ForwardingStageName, maximumForwardingArtifactBytes,
	)
	if err != nil {
		return true, err
	}
	activeManifest, activeManifestWire, activeManifestPresent, err := readWireGuardExactFileAt(
		manifestDirectory, filepath.Base(wireguardstate.ManifestPath), 32<<10,
	)
	if err != nil || !activeManifestPresent {
		return true, errors.Join(fmt.Errorf("active WireGuard ownership manifest is absent during recovery"), err)
	}
	stageManifest, stageManifestWire, stageManifestPresent, err := readWireGuardExactFileAt(
		manifestDirectory, journal.ManifestStageName, 32<<10,
	)
	if err != nil {
		return true, err
	}

	activeForwardingOld := sameWireGuardExactFile(activeForwarding, journal.OldForwarding)
	stageForwardingOld := stageForwardingPresent && sameWireGuardExactFile(stageForwarding, journal.OldForwarding)
	activeManifestOld := sameWireGuardExactFile(activeManifest, journal.OldManifest) &&
		bytes.Equal(activeManifestWire, []byte(journal.OldManifestContent))
	stageManifestOld := stageManifestPresent && sameWireGuardExactFile(stageManifest, journal.OldManifest) &&
		bytes.Equal(stageManifestWire, []byte(journal.OldManifestContent))

	var newForwarding wireGuardExactFile
	var newForwardingPresent bool
	if activeForwardingPresent && bytes.Equal(activeForwardingWire, []byte(journal.TargetContent)) && !activeForwardingOld {
		newForwarding = activeForwarding
		newForwardingPresent = true
	}
	if stageForwardingPresent && bytes.Equal(stageForwardingWire, []byte(journal.TargetContent)) && !stageForwardingOld {
		if newForwardingPresent && !sameWireGuardExactFile(newForwarding, stageForwarding) {
			return true, fmt.Errorf("forwarding transition has duplicate target artifacts")
		}
		newForwarding = stageForwarding
		newForwardingPresent = true
	}
	if !newForwardingPresent {
		if activeForwardingOld && !stageForwardingPresent && activeManifestOld && !stageManifestPresent {
			return true, removeExactWireGuardFileAt(
				manifestDirectory, filepath.Base(wireGuardForwardingTransitionPath), journalIdentity,
				maximumForwardingTransitionBytes,
			)
		}
		return true, fmt.Errorf("forwarding transition target artifact is missing or changed")
	}
	_, expectedNewManifestWire, err := manifestWithWireGuardForwarding(oldManifest, newForwarding)
	if err != nil {
		return true, err
	}
	activeManifestNew := bytes.Equal(activeManifestWire, expectedNewManifestWire) && !activeManifestOld
	stageManifestNew := stageManifestPresent && bytes.Equal(stageManifestWire, expectedNewManifestWire) && !stageManifestOld

	switch {
	case activeForwardingOld && activeManifestOld:
		if stageForwardingPresent {
			if !bytes.Equal(stageForwardingWire, []byte(journal.TargetContent)) {
				return true, fmt.Errorf("forwarding transition stage changed before rollback")
			}
			if err := removeExactWireGuardFileAt(
				forwardingDirectory, journal.ForwardingStageName, stageForwarding, maximumForwardingArtifactBytes,
			); err != nil {
				return true, err
			}
		}
		if stageManifestPresent {
			if !stageManifestNew {
				return true, fmt.Errorf("manifest transition stage changed before rollback")
			}
			if err := removeExactWireGuardFileAt(
				manifestDirectory, journal.ManifestStageName, stageManifest, 32<<10,
			); err != nil {
				return true, err
			}
		}
	case !activeForwardingOld && stageForwardingOld && activeManifestOld && stageManifestNew:
		if err := exchangeWireGuardFiles(
			forwardingDirectory, filepath.Base(wireguardstate.ForwardingConfigurationPath), journal.ForwardingStageName,
		); err != nil {
			return true, fmt.Errorf("rollback interrupted WireGuard forwarding exchange: %w", err)
		}
		rolledBack, _, ok, err := readWireGuardExactFileAt(
			forwardingDirectory, filepath.Base(wireguardstate.ForwardingConfigurationPath), maximumForwardingArtifactBytes,
		)
		if err != nil || !ok || !sameWireGuardExactFile(rolledBack, journal.OldForwarding) {
			return true, errors.Join(fmt.Errorf("reattest rolled-back WireGuard forwarding artifact"), err)
		}
		newStage, _, ok, err := readWireGuardExactFileAt(
			forwardingDirectory, journal.ForwardingStageName, maximumForwardingArtifactBytes,
		)
		if err != nil || !ok {
			return true, errors.Join(fmt.Errorf("reattest rolled-back WireGuard forwarding stage"), err)
		}
		if err := removeExactWireGuardFileAt(
			forwardingDirectory, journal.ForwardingStageName, newStage, maximumForwardingArtifactBytes,
		); err != nil {
			return true, err
		}
		if err := removeExactWireGuardFileAt(
			manifestDirectory, journal.ManifestStageName, stageManifest, 32<<10,
		); err != nil {
			return true, err
		}
	case activeManifestNew && !activeForwardingOld:
		if stageForwardingPresent {
			if !stageForwardingOld {
				return true, fmt.Errorf("committed forwarding transition lost its prior artifact")
			}
			if err := removeExactWireGuardFileAt(
				forwardingDirectory, journal.ForwardingStageName, stageForwarding, maximumForwardingArtifactBytes,
			); err != nil {
				return true, err
			}
		}
		if stageManifestPresent {
			if !stageManifestOld {
				return true, fmt.Errorf("committed forwarding transition lost its prior manifest")
			}
			if err := removeExactWireGuardFileAt(
				manifestDirectory, journal.ManifestStageName, stageManifest, 32<<10,
			); err != nil {
				return true, err
			}
		}
	default:
		return true, fmt.Errorf("WireGuard forwarding transition is in an unrecognized mixed state")
	}

	if err := removeExactWireGuardFileAt(
		manifestDirectory, filepath.Base(wireGuardForwardingTransitionPath), journalIdentity,
		maximumForwardingTransitionBytes,
	); err != nil {
		return true, err
	}
	return true, nil
}

func transitionWireGuardForwardingPersistence(
	identity wireguardstate.ServerConfigurationIdentity,
	target []byte,
) (resultErr error) {
	if _, err := parseWireGuardForwardingPersistence(target, identity); err != nil {
		return err
	}
	if _, err := recoverWireGuardForwardingTransition(); err != nil {
		return fmt.Errorf("recover prior WireGuard forwarding transition: %w", err)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return fmt.Errorf("verify WireGuard ownership before forwarding transition: %w", err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return err
	}
	actualIdentity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil || actualIdentity != identity {
		return fmt.Errorf("WireGuard ownership identity changed before forwarding transition")
	}
	current, err := inspectWireGuardForwardingPersistence(manifest, identity)
	if err != nil {
		return err
	}
	if bytes.Equal(current.Content, target) {
		return nil
	}

	forwardingDirectory, err := openAttestedWireGuardDirectory("etc/sysctl.d", 0)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, forwardingDirectory.Close()) }()
	manifestDirectory, err := openAttestedWireGuardDirectory("etc/wireguard", 0700)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manifestDirectory.Close()) }()

	oldForwarding, oldForwardingWire, present, err := readWireGuardExactFileAt(
		forwardingDirectory, filepath.Base(wireguardstate.ForwardingConfigurationPath), maximumForwardingArtifactBytes,
	)
	if err != nil || !present || !bytes.Equal(oldForwardingWire, current.Content) {
		return errors.Join(fmt.Errorf("reattest WireGuard forwarding artifact before transition"), err)
	}
	forwardingArtifact, err := wireGuardManifestArtifact(manifest, wireguardstate.ForwardingConfigurationPath)
	if err != nil || !wireGuardExactFileMatchesArtifact(oldForwarding, forwardingArtifact) {
		return fmt.Errorf("WireGuard forwarding artifact identity changed before transition")
	}
	oldManifest, oldManifestWire, present, err := readWireGuardExactFileAt(
		manifestDirectory, filepath.Base(wireguardstate.ManifestPath), 32<<10,
	)
	if err != nil || !present {
		return errors.Join(fmt.Errorf("reattest WireGuard ownership manifest before transition"), err)
	}
	canonicalOldManifest, err := canonicalWireGuardManifestBytes(manifest)
	if err != nil || !bytes.Equal(canonicalOldManifest, oldManifestWire) {
		return fmt.Errorf("WireGuard ownership manifest changed before forwarding transition")
	}
	forwardingStageName, err := randomWireGuardTransitionName(".99-syswarden-wireguard.conf.stage-")
	if err != nil {
		return err
	}
	manifestStageName, err := randomWireGuardTransitionName(".syswarden-ownership-v1.json.stage-")
	if err != nil {
		return err
	}
	journal := wireGuardForwardingTransitionJournal{
		Schema:              wireGuardForwardingTransitionSchema,
		OwnershipToken:      identity.OwnershipToken,
		TargetContent:       string(target),
		ForwardingStageName: forwardingStageName,
		ManifestStageName:   manifestStageName,
		OldForwarding:       oldForwarding,
		OldManifest:         oldManifest,
		OldManifestContent:  string(oldManifestWire),
	}
	journalWire, err := canonicalWireGuardForwardingJournal(journal)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		_, recoveryErr := recoverWireGuardForwardingTransition()
		return errors.Join(cause, recoveryErr)
	}
	_, err = createWireGuardExactFileAt(
		manifestDirectory, filepath.Base(wireGuardForwardingTransitionPath), journalWire,
	)
	if err != nil {
		return fail(err)
	}
	if err := wireGuardForwardingTransitionFault("journal-published"); err != nil {
		return fail(err)
	}
	newForwarding, err := createWireGuardExactFileAt(forwardingDirectory, forwardingStageName, target)
	if err != nil {
		return fail(err)
	}
	if err := wireGuardForwardingTransitionFault("forwarding-staged"); err != nil {
		return fail(err)
	}
	_, newManifestWire, err := manifestWithWireGuardForwarding(manifest, newForwarding)
	if err != nil {
		return fail(err)
	}
	if _, err := createWireGuardExactFileAt(manifestDirectory, manifestStageName, newManifestWire); err != nil {
		return fail(err)
	}
	if err := wireGuardForwardingTransitionFault("manifest-staged"); err != nil {
		return fail(err)
	}
	if err := exchangeWireGuardFiles(
		forwardingDirectory, filepath.Base(wireguardstate.ForwardingConfigurationPath), forwardingStageName,
	); err != nil {
		return fail(fmt.Errorf("exchange WireGuard forwarding artifact: %w", err))
	}
	if err := wireGuardForwardingTransitionFault("forwarding-exchanged"); err != nil {
		return fail(err)
	}
	if err := exchangeWireGuardFiles(
		manifestDirectory, filepath.Base(wireguardstate.ManifestPath), manifestStageName,
	); err != nil {
		return fail(fmt.Errorf("exchange WireGuard ownership manifest: %w", err))
	}
	if err := wireGuardForwardingTransitionFault("manifest-exchanged"); err != nil {
		return fail(err)
	}
	if _, err := recoverWireGuardForwardingTransition(); err != nil {
		return fmt.Errorf("finalize WireGuard forwarding transition: %w", err)
	}
	finalManifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return err
	}
	finalState, err := inspectWireGuardForwardingPersistence(finalManifest, identity)
	if err != nil || !bytes.Equal(finalState.Content, target) {
		return errors.Join(fmt.Errorf("WireGuard forwarding persistence did not converge"), err)
	}
	return nil
}

func transitionWireGuardForwardingPersistenceGuarded(
	identity wireguardstate.ServerConfigurationIdentity,
	target []byte,
) (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard forwarding transition guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard forwarding transition guard: %w", err))
		}
	}()
	return transitionWireGuardForwardingPersistence(identity, target)
}

func recoverWireGuardForwardingTransitionGuarded() (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard forwarding recovery guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard forwarding recovery guard: %w", err))
		}
	}()
	return recoverPendingWireGuardForwardingStateLocked()
}

func recoverPendingWireGuardForwardingStateLocked() error {
	pending, err := wireGuardForwardingTransitionPathPresent()
	if err != nil {
		return fmt.Errorf("inspect pending WireGuard forwarding persistence: %w", err)
	}
	if pending {
		if _, err := recoverWireGuardForwardingTransition(); err != nil {
			return fmt.Errorf("recover attested WireGuard forwarding persistence: %w", err)
		}
	}
	pending, err = wireGuardForwardingTransitionPending()
	if err != nil {
		return fmt.Errorf("reattest WireGuard forwarding persistence after recovery: %w", err)
	}
	if pending {
		return fmt.Errorf("WireGuard forwarding persistence transaction remains after recovery")
	}
	return nil
}

// RecoverPendingWireGuardForwardingState recovers only the bounded,
// ownership-attested forwarding persistence transaction. A corrupt or
// unrecognized journal is preserved and reported without mutation.
func RecoverPendingWireGuardForwardingState() error {
	return recoverWireGuardForwardingTransitionGuarded()
}
