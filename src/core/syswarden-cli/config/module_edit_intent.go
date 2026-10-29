package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const moduleEditIntentName = ".config-edit-intent.json"
const maximumModuleEditIntentSize int64 = 512 * 1024
const maximumModuleEditInputs = 256

// These witnesses contain metadata and digests, never TOML or secret values.
// Directory timestamps are excluded because creating the intent changes them.
type moduleEditDirectory struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type moduleEditFile struct {
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Mode        uint32 `json:"mode"`
	Size        int64  `json:"size"`
	Modified    string `json:"modified"`
	ChangedSec  int64  `json:"changed_sec"`
	ChangedNsec int64  `json:"changed_nsec"`
	Links       uint64 `json:"links"`
	SHA256      string `json:"sha256"`
}

type moduleEditInput struct {
	Path string         `json:"path"`
	File moduleEditFile `json:"file"`
}

// The immutable body binds one approval, physical tree and atomic name pair.
// Only State may advance during publication; records are not activation proof.
type moduleEditIntent struct {
	Schema          int                 `json:"schema"`
	State           string              `json:"state"`
	Root            string              `json:"root"`
	Target          string              `json:"target"`
	ApprovalID      string              `json:"approval_id"`
	Stage           string              `json:"stage"`
	RootIdentity    moduleEditDirectory `json:"root_identity"`
	ModulesIdentity moduleEditDirectory `json:"modules_identity"`
	Original        *moduleEditFile     `json:"original"`
	Candidate       moduleEditFile      `json:"candidate"`
	Inputs          []moduleEditInput   `json:"inputs"`
}

func moduleEditDirectoryFrom(info os.FileInfo) (moduleEditDirectory, error) {
	if info == nil || !info.IsDir() || info.Mode() & ^(os.ModeDir|0777) != 0 || info.Mode().Perm()&0022 != 0 {
		return moduleEditDirectory{}, errors.New("configuration edit directory metadata is unsafe")
	}
	dev, ino, ok := fileDeviceInode(info)
	uid, gid, ownerOK := fileOwnerUIDGID(info)
	if !ok || !ownerOK || ino == 0 || int64(uid) != int64(os.Geteuid()) {
		return moduleEditDirectory{}, errors.New("configuration edit directory ownership is unavailable or foreign")
	}
	return moduleEditDirectory{Device: dev, Inode: ino, UID: uid, GID: gid, Mode: uint32(info.Mode().Perm())}, nil
}

func moduleEditFileFrom(identity *secureFileIdentity) (moduleEditFile, error) {
	if identity == nil || identity.info == nil {
		return moduleEditFile{}, errors.New("configuration edit file identity is missing")
	}
	info := identity.info
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return moduleEditFile{}, errors.New("configuration edit file metadata is unavailable")
	}
	changedSec, changedNsec, changeOK := secureFileChangeTime(info)
	if !changeOK {
		return moduleEditFile{}, errors.New("configuration file change time is unavailable")
	}
	result := moduleEditFile{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: stat.Uid, GID: stat.Gid,
		Mode: uint32(info.Mode()), Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339Nano),
		ChangedSec: changedSec, ChangedNsec: changedNsec, Links: uint64(stat.Nlink), SHA256: hex.EncodeToString(identity.digest[:])}
	if err := result.validate(); err != nil {
		return moduleEditFile{}, err
	}
	return result, nil
}

func (file moduleEditFile) validate() error {
	modified, err := time.Parse(time.RFC3339Nano, file.Modified)
	if file.Inode == 0 || int64(file.UID) != int64(os.Geteuid()) || file.Mode & ^uint32(0640) != 0 ||
		file.Mode&0600 != 0600 || file.Size < 0 || file.Size > maximumUserModuleSize || file.Links != 1 || file.ChangedNsec < 0 || file.ChangedNsec >= 1000000000 ||
		!isLowerHex(file.SHA256, sha256.Size*2) || err != nil || modified.UTC().Format(time.RFC3339Nano) != file.Modified {
		return errors.New("configuration edit file witness is unsafe or malformed")
	}
	return nil
}

func isLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func moduleEditInputPath(relative string) bool {
	if relative == "config.toml" {
		return true
	}
	if !strings.HasPrefix(relative, "modules/") {
		return false
	}
	name := strings.TrimPrefix(relative, "modules/")
	return name != "" && filepath.Base(name) == name && filepath.Ext(name) == ".toml" &&
		!strings.ContainsAny(name, "\\\x00\r\n") && len(name) <= 255
}

func (intent *moduleEditIntent) validate() error {
	if intent == nil || intent.Schema != 1 ||
		(intent.State != "prepared" && intent.State != "committed" && intent.State != "rolled_back") ||
		!filepath.IsAbs(intent.Root) || filepath.Clean(intent.Root) != intent.Root || !isLowerHex(intent.ApprovalID, 64) {
		return errors.New("configuration edit intent header is invalid")
	}
	target, err := ordinaryTOMLTarget(intent.Target)
	if err != nil {
		return err
	}
	prefix := "." + target.name + ".tmp-"
	if !strings.HasPrefix(intent.Stage, prefix) || !isLowerHex(strings.TrimPrefix(intent.Stage, prefix), 32) {
		return errors.New("configuration edit stage is outside its fixed target boundary")
	}
	for _, directory := range []moduleEditDirectory{intent.RootIdentity, intent.ModulesIdentity} {
		if directory.Inode == 0 || int64(directory.UID) != int64(os.Geteuid()) ||
			directory.Mode & ^uint32(0777) != 0 || directory.Mode&0022 != 0 || directory.Mode&0700 != 0700 {
			return errors.New("configuration edit directory witness is invalid")
		}
	}
	if err := intent.Candidate.validate(); err != nil {
		return err
	}
	destination := intent.ModulesIdentity
	if target.master {
		destination = intent.RootIdentity
	}
	if intent.Candidate.Device != destination.Device {
		return errors.New("configuration candidate belongs to a different filesystem")
	}
	if len(intent.Inputs) == 0 || len(intent.Inputs) > maximumModuleEditInputs {
		return errors.New("configuration edit input inventory is unavailable or exceeds its limit")
	}
	var original *moduleEditFile
	previous := ""
	for _, input := range intent.Inputs {
		if !moduleEditInputPath(input.Path) || input.Path <= previous {
			return errors.New("configuration edit inventory paths are invalid or duplicated")
		}
		if err := input.File.validate(); err != nil {
			return err
		}
		directory := intent.ModulesIdentity
		if input.Path == "config.toml" {
			directory = intent.RootIdentity
		}
		if input.File.Device != directory.Device {
			return errors.New("configuration input belongs to a different filesystem")
		}
		if input.File.Device == intent.Candidate.Device && input.File.Inode == intent.Candidate.Inode {
			return errors.New("configuration candidate aliases an original input")
		}
		if input.Path == intent.Target {
			value := input.File
			original = &value
		}
		previous = input.Path
	}
	if (original == nil) != (intent.Original == nil) || (original != nil && *original != *intent.Original) {
		return errors.New("configuration edit original does not match its captured inventory")
	}
	if intent.Original != nil && (intent.Candidate.UID != intent.Original.UID || intent.Candidate.GID != intent.Original.GID || intent.Candidate.Mode != intent.Original.Mode) {
		return errors.New("configuration edit must preserve the original owner, group and mode")
	}
	return nil
}

func encodeModuleEditIntent(intent *moduleEditIntent) ([]byte, error) {
	if err := intent.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximumModuleEditIntentSize {
		return nil, errors.New("configuration edit intent exceeds its size limit")
	}
	return raw, nil
}

func decodeModuleEditIntent(raw []byte) (*moduleEditIntent, error) {
	if int64(len(raw)) > maximumModuleEditIntentSize {
		return nil, errors.New("configuration edit intent exceeds its size limit")
	}
	var intent moduleEditIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return nil, errors.New("configuration edit intent JSON is invalid; preserve it for inspection")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration edit intent has trailing data")
	}
	canonical, err := encodeModuleEditIntent(&intent)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, errors.New("configuration edit intent is not canonical; preserve it for inspection")
	}
	return &intent, nil
}

func newModuleEditIntent(state *moduleProposalState, stage string, candidate *secureFileIdentity) (*moduleEditIntent, error) {
	if state == nil || state.snapshot == nil {
		return nil, errors.New("configuration proposal snapshot is unavailable")
	}
	if err := state.snapshot.requireEditOwnership(os.Geteuid()); err != nil {
		return nil, err
	}
	intent := &moduleEditIntent{Schema: 1, State: "prepared", Root: state.root, Target: state.target.relative,
		ApprovalID: state.review.ApprovalID, Stage: stage, Inputs: make([]moduleEditInput, 0, len(state.snapshot.modules)+2)}
	var err error
	intent.RootIdentity, err = moduleEditDirectoryFrom(state.snapshot.configRootInfo)
	if err != nil {
		return nil, err
	}
	intent.ModulesIdentity, err = moduleEditDirectoryFrom(state.snapshot.modulesRootInfo)
	if err != nil {
		return nil, err
	}
	intent.Candidate, err = moduleEditFileFrom(candidate)
	if err != nil {
		return nil, err
	}
	add := func(relative string, identity *secureFileIdentity) error {
		if identity == nil {
			return nil
		}
		file, err := moduleEditFileFrom(identity)
		if err != nil {
			return err
		}
		intent.Inputs = append(intent.Inputs, moduleEditInput{Path: relative, File: file})
		if relative == state.target.relative {
			intent.Original = &file
		}
		return nil
	}
	if err := add("config.toml", state.snapshot.master); err != nil {
		return nil, err
	}
	if err := add("modules/"+userModuleName, state.snapshot.user); err != nil {
		return nil, err
	}
	for name, identity := range state.snapshot.modules {
		if err := add("modules/"+name, identity); err != nil {
			return nil, err
		}
	}
	sort.Slice(intent.Inputs, func(i, j int) bool { return intent.Inputs[i].Path < intent.Inputs[j].Path })
	if err := intent.validate(); err != nil {
		return nil, err
	}
	return intent, nil
}
