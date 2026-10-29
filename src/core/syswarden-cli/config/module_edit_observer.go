package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// ModuleEditObservation is a read-only, point-in-time diagnosis. Neither its
// state nor its digest is permission to mutate files or activate host policy.
type ModuleEditObservation struct {
	State         string
	Target        string
	ApprovalID    string
	RecordSHA256  string
	InputsChanged bool
}

type observedModuleEdit struct {
	observation ModuleEditObservation
	intent      *moduleEditIntent
	identity    *secureFileIdentity
}

// ObserveModuleEdit never removes, repairs, creates or rewrites an artifact.
// An invalid or ambiguous record remains in place and cannot establish success.
func ObserveModuleEdit(ctx context.Context, configDir string) (ModuleEditObservation, error) {
	observed, err := observeModuleEdit(ctx, configDir)
	if err != nil {
		return ModuleEditObservation{}, err
	}
	return observed.observation, nil
}

func observeModuleEdit(ctx context.Context, configDir string) (*observedModuleEdit, error) {
	if ctx == nil {
		return nil, errors.New("configuration edit observation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(configDir) || filepath.Clean(configDir) != configDir {
		return nil, errors.New("configuration edit root must be absolute and canonical")
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Lstat(moduleEditIntentName); errors.Is(err, fs.ErrNotExist) {
		return &observedModuleEdit{observation: ModuleEditObservation{State: "none"}}, nil
	} else if err != nil {
		return nil, err
	}
	raw, info, err := readSecureRegularFileSnapshotBounded(root, moduleEditIntentName, moduleEditIntentName, maximumModuleEditIntentSize)
	if err != nil {
		return nil, err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK || int64(stat.Uid) != int64(os.Geteuid()) || info.Mode() != 0600 || stat.Nlink != 1 {
		return nil, errors.New("configuration edit intent requires private effective-user ownership and one link")
	}
	intent, err := decodeModuleEditIntent(raw)
	if err != nil {
		return nil, err
	}
	if intent.Root != configDir {
		return nil, errors.New("configuration edit intent belongs to a different root")
	}
	modules, err := openConfigDirectory(filepath.Join(configDir, "modules"), false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = modules.Close() }()
	bind := func(opened *os.Root, expected moduleEditDirectory) error {
		info, err := rootDirectoryInfo(opened)
		if err != nil {
			return err
		}
		actual, err := moduleEditDirectoryFrom(info)
		if err != nil {
			return err
		}
		if actual != expected {
			return errors.New("configuration edit directory identity changed; artifacts retained")
		}
		return nil
	}
	if err := bind(root, intent.RootIdentity); err != nil {
		return nil, err
	}
	if err := bind(modules, intent.ModulesIdentity); err != nil {
		return nil, err
	}
	target, err := ordinaryTOMLTarget(intent.Target)
	if err != nil {
		return nil, err
	}
	destination := modules
	if target.master {
		destination = root
	}
	live, err := readModuleEditWitness(destination, target.name)
	if err != nil {
		return nil, err
	}
	staged, err := readModuleEditWitness(destination, intent.Stage)
	if err != nil {
		return nil, err
	}
	changed, err := moduleEditOtherInputsChanged(root, modules, intent)
	if err != nil {
		return nil, err
	}
	identity := newSecureFileIdentity(raw, info)
	latest, latestInfo, err := readSecureRegularFileSnapshotBounded(root, moduleEditIntentName, moduleEditIntentName, maximumModuleEditIntentSize)
	if err != nil {
		return nil, err
	}
	if !identity.matches(latest, latestInfo) || !sameSecureFileMetadata(info, latestInfo) {
		return nil, errors.New("configuration edit record changed during observation")
	}
	if err := bind(root, intent.RootIdentity); err != nil {
		return nil, err
	}
	if err := bind(modules, intent.ModulesIdentity); err != nil {
		return nil, err
	}
	// Resolve the named directories again; an old open descriptor must not
	// authorize a root or modules path replaced while observation was running.
	if err := recheckModuleEditDirectoryPath(configDir, intent.RootIdentity); err != nil {
		return nil, err
	}
	if err := recheckModuleEditDirectoryPath(filepath.Join(configDir, "modules"), intent.ModulesIdentity); err != nil {
		return nil, err
	}
	latestLive, err := readModuleEditWitness(destination, target.name)
	if err != nil {
		return nil, err
	}
	latestStage, err := readModuleEditWitness(destination, intent.Stage)
	if err != nil {
		return nil, err
	}
	if !sameModuleEditFile(live, latestLive) || !sameModuleEditFile(staged, latestStage) {
		return nil, errors.New("configuration edit file pair changed during observation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return &observedModuleEdit{intent: intent, identity: identity, observation: ModuleEditObservation{
		State: classifyModuleEditPair(intent, live, staged), Target: intent.Target, ApprovalID: intent.ApprovalID,
		RecordSHA256: hex.EncodeToString(digest[:]), InputsChanged: changed,
	}}, nil
}

func recheckModuleEditDirectoryPath(path string, expected moduleEditDirectory) error {
	opened, err := openConfigDirectory(path, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = opened.Close() }()
	info, err := rootDirectoryInfo(opened)
	if err != nil {
		return err
	}
	actual, err := moduleEditDirectoryFrom(info)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("configuration edit directory path was replaced")
	}
	return nil
}

func readModuleEditWitness(root *os.Root, name string) (*moduleEditFile, error) {
	if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	raw, info, err := readSecureRegularFileSnapshotBounded(root, name, name, maximumUserModuleSize)
	if err != nil {
		return nil, err
	}
	witness, err := moduleEditFileFrom(newSecureFileIdentity(raw, info))
	if err != nil {
		return nil, err
	}
	return &witness, nil
}

func sameModuleEditFile(left, right *moduleEditFile) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	a, b := *left, *right
	// renameat2 changes ctime for the selected pair. Unmoved inputs are
	// compared in full, including ctime, by the inventory observer below.
	a.ChangedSec, a.ChangedNsec, b.ChangedSec, b.ChangedNsec = 0, 0, 0, 0
	return a == b
}

func classifyModuleEditPair(intent *moduleEditIntent, live, stage *moduleEditFile) string {
	originalLive := sameModuleEditFile(live, intent.Original)
	candidateLive := sameModuleEditFile(live, &intent.Candidate)
	candidateStaged := sameModuleEditFile(stage, &intent.Candidate)
	originalStaged := sameModuleEditFile(stage, intent.Original)
	switch intent.State {
	case "prepared":
		if originalLive && candidateStaged {
			return "prepared"
		}
		if candidateLive && originalStaged {
			return "published_pending"
		}
	case "committed":
		if candidateLive && (originalStaged || stage == nil) {
			return "committed_cleanup"
		}
	case "rolled_back":
		if originalLive && (candidateStaged || stage == nil) {
			return "rolled_back_cleanup"
		}
	}
	return "ambiguous"
}

func moduleEditOtherInputsChanged(root, modules *os.Root, intent *moduleEditIntent) (bool, error) {
	expectedPaths := make([]string, 0, len(intent.Inputs))
	changed := false
	for _, input := range intent.Inputs {
		if input.Path == intent.Target {
			continue
		}
		expectedPaths = append(expectedPaths, input.Path)
		parent, name := modules, filepath.Base(input.Path)
		if input.Path == "config.toml" {
			parent = root
		}
		actual, err := readModuleEditWitness(parent, name)
		if err != nil {
			return false, err
		}
		if actual == nil || *actual != input.File {
			changed = true
		}
	}
	actualPaths := make([]string, 0, len(expectedPaths))
	if _, err := root.Lstat("config.toml"); err == nil {
		if intent.Target != "config.toml" {
			actualPaths = append(actualPaths, "config.toml")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	directory, err := modules.Open(".")
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	// Bound entries as well as TOML inputs; never scan an unbounded directory
	// to derive recovery authority from a bounded intent.
	entries, err := directory.ReadDir(maximumModuleEditInputs + 16)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if len(entries) == maximumModuleEditInputs+16 {
		return false, errors.New("configuration edit directory exceeds the observation limit")
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		relative := "modules/" + entry.Name()
		if relative != intent.Target {
			actualPaths = append(actualPaths, relative)
		}
	}
	sort.Strings(actualPaths)
	if len(actualPaths) != len(expectedPaths) {
		changed = true
	}
	for i, path := range actualPaths {
		if i >= len(expectedPaths) || path != expectedPaths[i] {
			changed = true
		}
	}
	if _, err := root.Lstat(migrationMarkerName); err == nil {
		return false, errors.New("configuration migration must be resolved before edit recovery")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("inspect migration marker: %w", err)
	}
	return changed, nil
}
