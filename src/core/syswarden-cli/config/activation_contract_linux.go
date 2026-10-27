//go:build linux

package config

// This contract is intentionally byte-identical in the CLI and core packages.
// Neither consumer imports the other executable. Cross-consumer tests enforce
// the wire contract and each consumer independently verifies the opened inputs.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const activationApprovalSchema = "syswarden-activation-approval-v1"
const activationAppliedSchema = "syswarden-activation-applied-v1"
const activationSourceContract = "syswarden-toml-source-v1"
const activationEnvironmentContract = "toml-only-reject-modular-environment-v1"
const activationStateDirectory = "/var/lib/syswarden/activation"
const activationApprovedName = "approved.json"
const activationAppliedName = "applied.json"
const activationLockName = ".approval.lock"
const activationRetirementName = ".activation-retirement.json"
const maximumActivationRecordBytes = 512 * 1024
const maximumActivationInputBytes = 256 * 1024
const maximumActivationInputs = 256
const maximumActivationDirectoryEntries = 1024

var activationNamespaces = []string{"SSH", "SCHEMA_VERSION", "CORE", "NETWORK", "SECURITY", "WAAP", "INTEGRATIONS", "OPERATOR_POLICY", "USER"}

type activationDirectoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type activationFileIdentity struct {
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Mode         uint32 `json:"mode"`
	Links        uint64 `json:"links"`
	Size         int64  `json:"size"`
	ModifiedSec  int64  `json:"modified_sec"`
	ModifiedNsec int64  `json:"modified_nsec"`
	ChangedSec   int64  `json:"changed_sec"`
	ChangedNsec  int64  `json:"changed_nsec"`
	SHA256       string `json:"sha256"`
}

type activationInput struct {
	Path string                 `json:"path"`
	File activationFileIdentity `json:"file"`
}

type activationApprovalRecord struct {
	Schema                 string                      `json:"schema"`
	SourceContract         string                      `json:"source_contract"`
	Environment            string                      `json:"environment"`
	Root                   string                      `json:"root"`
	RootIdentity           activationDirectoryIdentity `json:"root_identity"`
	ModulesIdentity        activationDirectoryIdentity `json:"modules_identity"`
	Inputs                 []activationInput           `json:"inputs"`
	PolicySHA256           string                      `json:"policy_sha256"`
	HostSHA256             string                      `json:"host_sha256"`
	PlanSHA256             string                      `json:"plan_sha256"`
	PreviousApprovalSHA256 string                      `json:"previous_approval_sha256"`
	RetainedAppliedSHA256  string                      `json:"retained_applied_sha256"`
	Operation              string                      `json:"operation"`
}

type activationAppliedRecord struct {
	Schema         string `json:"schema"`
	ApprovalSHA256 string `json:"approval_sha256"`
}

func activationHex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, digit := range value {
		if !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')) {
			return false
		}
	}
	return true
}

func activationDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func activationCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func decodeActivationCanonical(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumActivationRecordBytes {
		return errors.New("activation record exceeds its bounded wire contract")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode activation record: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("activation record has trailing data")
	}
	canonical, err := activationCanonical(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("activation record is not exact canonical JSON")
	}
	return nil
}

func activationDirectoryFrom(info os.FileInfo, uid uint32) (activationDirectoryIdentity, error) {
	if info == nil || !info.IsDir() || info.Mode() & ^(os.ModeDir|0777) != 0 || info.Mode().Perm()&0022 != 0 {
		return activationDirectoryIdentity{}, errors.New("activation directory metadata is unsafe")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Ino == 0 || status.Uid != uid {
		return activationDirectoryIdentity{}, errors.New("activation directory ownership is unavailable or foreign")
	}
	return activationDirectoryIdentity{uint64(status.Dev), status.Ino, status.Uid, status.Gid, uint32(info.Mode().Perm())}, nil
}

func activationFileFrom(info os.FileInfo, raw []byte, uid uint32, maximum int64) (activationFileIdentity, error) {
	if info == nil || !info.Mode().IsRegular() || (info.Mode() != 0600 && info.Mode() != 0640) {
		return activationFileIdentity{}, errors.New("activation file metadata is unsafe")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Ino == 0 || status.Uid != uid || status.Nlink != 1 || info.Size() < 0 || info.Size() > maximum {
		return activationFileIdentity{}, errors.New("activation file ownership, links or size is unsafe")
	}
	return activationFileIdentity{
		Device: uint64(status.Dev), Inode: status.Ino, UID: status.Uid, GID: status.Gid, Mode: uint32(info.Mode().Perm()),
		Links: uint64(status.Nlink), Size: info.Size(), ModifiedSec: status.Mtim.Sec, ModifiedNsec: status.Mtim.Nsec,
		ChangedSec: status.Ctim.Sec, ChangedNsec: status.Ctim.Nsec, SHA256: activationDigest(raw),
	}, nil
}

func validateActivationDirectory(identity activationDirectoryIdentity, uid uint32) error {
	if identity.Inode == 0 || identity.UID != uid || identity.Mode & ^uint32(0777) != 0 || identity.Mode&0022 != 0 {
		return errors.New("activation directory witness is invalid")
	}
	return nil
}

func validateActivationFile(identity activationFileIdentity, uid uint32) error {
	if identity.Inode == 0 || identity.UID != uid || (identity.Mode != 0600 && identity.Mode != 0640) || identity.Links != 1 ||
		identity.Size < 0 || identity.Size > maximumActivationInputBytes || identity.ModifiedNsec < 0 || identity.ModifiedNsec >= 1e9 ||
		identity.ChangedNsec < 0 || identity.ChangedNsec >= 1e9 || !activationHex(identity.SHA256) {
		return errors.New("activation input witness is invalid")
	}
	return nil
}

// HostSHA256 identifies only the approved local source scope. It is not a
// globally unique machine identity and grants no authority by itself.
func activationHostDigest(root string, configRoot, modules activationDirectoryIdentity) (string, error) {
	raw, err := activationCanonical(struct {
		Domain          string                      `json:"domain"`
		Root            string                      `json:"root"`
		RootIdentity    activationDirectoryIdentity `json:"root_identity"`
		ModulesIdentity activationDirectoryIdentity `json:"modules_identity"`
	}{"syswarden-activation-local-source-scope-v1", root, configRoot, modules})
	if err != nil {
		return "", err
	}
	return activationDigest(raw), nil
}

func validateActivationRecord(record *activationApprovalRecord, uid uint32) error {
	if record == nil || record.Schema != activationApprovalSchema || record.SourceContract != activationSourceContract ||
		record.Environment != activationEnvironmentContract || !filepath.IsAbs(record.Root) || filepath.Clean(record.Root) != record.Root ||
		!activationHex(record.PolicySHA256) || !activationHex(record.HostSHA256) || !activationHex(record.PlanSHA256) ||
		(record.PreviousApprovalSHA256 != "" && !activationHex(record.PreviousApprovalSHA256)) ||
		(record.RetainedAppliedSHA256 != "" && !activationHex(record.RetainedAppliedSHA256)) ||
		(record.Operation != "install" && record.Operation != "reload") {
		return errors.New("activation approval contract is invalid or unsupported")
	}
	if err := validateActivationDirectory(record.RootIdentity, uid); err != nil {
		return err
	}
	if err := validateActivationDirectory(record.ModulesIdentity, uid); err != nil {
		return err
	}
	host, err := activationHostDigest(record.Root, record.RootIdentity, record.ModulesIdentity)
	if err != nil || host != record.HostSHA256 {
		return errors.New("activation local source scope differs")
	}
	if len(record.Inputs) < 7 || len(record.Inputs) > maximumActivationInputs {
		return errors.New("activation input inventory is incomplete or oversized")
	}
	required := map[string]bool{
		"config.toml": false, "modules/00-core.toml": false, "modules/10-network.toml": false,
		"modules/20-security.toml": false, "modules/30-waap.toml": false, "modules/40-integrations.toml": false, "modules/99-user.toml": false,
	}
	previous := ""
	for _, input := range record.Inputs {
		if input.Path <= previous {
			return errors.New("activation input inventory is not unique and ordered")
		}
		previous = input.Path
		if input.Path != "config.toml" {
			name := strings.TrimPrefix(input.Path, "modules/")
			if input.Path == name || name == "" || filepath.Base(name) != name || filepath.Ext(name) != ".toml" {
				return errors.New("activation input path is outside its exact inventory")
			}
		}
		if err := validateActivationFile(input.File, uid); err != nil {
			return err
		}
		if _, found := required[input.Path]; found {
			required[input.Path] = true
		}
	}
	for _, present := range required {
		if !present {
			return errors.New("activation required input is absent")
		}
	}
	return nil
}

func decodeActivationApproval(raw []byte, uid uint32) (*activationApprovalRecord, error) {
	var record activationApprovalRecord
	if err := decodeActivationCanonical(raw, &record); err != nil {
		return nil, err
	}
	if err := validateActivationRecord(&record, uid); err != nil {
		return nil, err
	}
	return &record, nil
}

func decodeActivationApplied(raw []byte) (*activationAppliedRecord, error) {
	var record activationAppliedRecord
	if err := decodeActivationCanonical(raw, &record); err != nil {
		return nil, err
	}
	if record.Schema != activationAppliedSchema || !activationHex(record.ApprovalSHA256) {
		return nil, errors.New("activation application record is invalid")
	}
	return &record, nil
}

func activationOwnerUID(value int64) (uint32, error) {
	if value < 0 || value > 1<<32-1 {
		return 0, errors.New("activation owner UID is outside the supported range")
	}
	return uint32(value), nil
}

func rejectActivationContractEnvironment() error {
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		for _, section := range activationNamespaces {
			prefix := "SYSWARDEN_" + section
			if name == prefix || strings.HasPrefix(name, prefix+"_") {
				return errors.New("approved activation requires TOML-only configuration without modular environment overrides")
			}
		}
	}
	return nil
}

// Resolve each directory component without following a symlink. Root-owned
// sticky ancestors permit private rootless test directories, but final source
// and state directories always require their exact protected owner and mode.
func openActivationDirectory(path string, uid uint32) (*os.Root, activationDirectoryIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, activationDirectoryIdentity{}, errors.New("activation path must be canonical and absolute")
	}
	current, err := os.OpenRoot("/")
	if err != nil {
		return nil, activationDirectoryIdentity{}, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, activationDirectoryIdentity{}, err
		}
		status, ok := before.Sys().(*syscall.Stat_t)
		if !ok || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || (status.Uid != uid && status.Uid != 0) ||
			(before.Mode().Perm()&0022 != 0 && !(status.Uid == 0 && before.Mode()&os.ModeSticky != 0)) {
			_ = current.Close()
			return nil, activationDirectoryIdentity{}, errors.New("activation ancestor is not protected")
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, activationDirectoryIdentity{}, err
		}
		opened, openErr := next.Stat(".")
		after, afterErr := current.Lstat(component)
		if openErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || before.Mode() != after.Mode() {
			_ = next.Close()
			_ = current.Close()
			return nil, activationDirectoryIdentity{}, errors.New("activation ancestor changed while opening")
		}
		_ = current.Close()
		current = next
	}
	info, err := current.Stat(".")
	if err != nil {
		_ = current.Close()
		return nil, activationDirectoryIdentity{}, err
	}
	identity, err := activationDirectoryFrom(info, uid)
	if err != nil {
		_ = current.Close()
		return nil, activationDirectoryIdentity{}, err
	}
	return current, identity, nil
}

func readActivationFile(root *os.Root, name string, uid uint32, maximum int64) ([]byte, activationFileIdentity, error) {
	return readActivationFileUsing(root, name, uid, maximum, nil)
}

func readActivationFileUsing(root *os.Root, name string, uid uint32, maximum int64, beforeOpen func() error) ([]byte, activationFileIdentity, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, activationFileIdentity{}, errors.New("invalid activation filename")
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	expected, err := activationFileFrom(before, nil, uid, maximum)
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	if beforeOpen != nil {
		if err := beforeOpen(); err != nil {
			return nil, activationFileIdentity{}, err
		}
	}
	// A replaced FIFO must not block before fstat can reject its kind. Never
	// follow a replacement symlink even when the rooted API would contain it.
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	openedIdentity, err := activationFileFrom(opened, nil, uid, maximum)
	if err != nil || expected != openedIdentity {
		return nil, activationFileIdentity{}, errors.New("activation file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, activationFileIdentity{}, errors.New("activation file read exceeded its bound or failed")
	}
	afterOpened, err := file.Stat()
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	after, err := root.Lstat(name)
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	afterIdentity, err := activationFileFrom(after, nil, uid, maximum)
	if err != nil {
		return nil, activationFileIdentity{}, err
	}
	afterOpenedIdentity, err := activationFileFrom(afterOpened, nil, uid, maximum)
	if err != nil || afterIdentity != expected || afterOpenedIdentity != expected || int64(len(raw)) != expected.Size {
		return nil, activationFileIdentity{}, errors.New("activation file changed while reading")
	}
	expected.SHA256 = activationDigest(raw)
	return raw, expected, nil
}

func activationReadBarrier(root *os.Root) error {
	for _, name := range []string{".config-edit-intent.json", ".migration-in-progress"} {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("activation requires resolved configuration publication and migration")
		}
	}
	return nil
}

func activationModuleNames(root *os.Root) ([]string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	entries, err := directory.ReadDir(maximumActivationDirectoryEntries + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maximumActivationDirectoryEntries {
		return nil, errors.New("activation directory inventory exceeds its bound")
	}
	names := []string{}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".toml" {
			names = append(names, "modules/"+entry.Name())
		}
	}
	sort.Strings(names)
	return append([]string{"config.toml"}, names...), nil
}

func readActivationInputs(record *activationApprovalRecord, uid uint32) (map[string][]byte, error) {
	if err := rejectActivationContractEnvironment(); err != nil {
		return nil, err
	}
	if err := validateActivationRecord(record, uid); err != nil {
		return nil, err
	}
	root, rootIdentity, err := openActivationDirectory(record.Root, uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	modules, modulesIdentity, err := openActivationDirectory(filepath.Join(record.Root, "modules"), uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = modules.Close() }()
	if rootIdentity != record.RootIdentity || modulesIdentity != record.ModulesIdentity {
		return nil, errors.New("approved activation source directories changed")
	}
	if err := activationReadBarrier(root); err != nil {
		return nil, err
	}
	names, err := activationModuleNames(modules)
	if err != nil || len(names) != len(record.Inputs) {
		return nil, errors.New("approved activation input inventory changed")
	}
	inputs := make(map[string][]byte, len(names))
	for index, name := range names {
		if name != record.Inputs[index].Path {
			return nil, errors.New("approved activation input inventory changed")
		}
		directory := modules
		if name == "config.toml" {
			directory = root
		}
		raw, actual, err := readActivationFile(directory, filepath.Base(name), uid, maximumActivationInputBytes)
		if err != nil {
			return nil, err
		}
		if actual != record.Inputs[index].File {
			return nil, errors.New("approved activation input bytes or metadata changed")
		}
		inputs[name] = raw
	}
	afterNames, err := activationModuleNames(modules)
	if err != nil || !equalActivationNames(names, afterNames) {
		return nil, errors.New("activation input inventory changed during verification")
	}
	if err := activationReadBarrier(root); err != nil {
		return nil, err
	}
	for _, expected := range []struct {
		path     string
		identity activationDirectoryIdentity
	}{
		{record.Root, record.RootIdentity}, {filepath.Join(record.Root, "modules"), record.ModulesIdentity},
	} {
		reopened, identity, err := openActivationDirectory(expected.path, uid)
		if err != nil {
			return nil, err
		}
		_ = reopened.Close()
		if identity != expected.identity {
			return nil, errors.New("activation source directory changed during verification")
		}
	}
	if err := rejectActivationContractEnvironment(); err != nil {
		return nil, err
	}
	return inputs, nil
}

func equalActivationNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func refuseActivationRetirement(statePath string, uid uint32) error {
	parent, _, err := openActivationDirectory(filepath.Dir(statePath), uid)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if _, err := parent.Lstat(activationRetirementName); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("activation state retirement is incomplete; preserve its intent and finish authorized removal")
	}
	return nil
}
