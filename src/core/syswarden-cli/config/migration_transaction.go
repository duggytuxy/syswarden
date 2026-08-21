package config

import (
	"crypto/rand"
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

const (
	migrationMarkerName    = ".migration-in-progress"
	migrationMarkerVersion = 1
	migrationPublishing    = "publishing"
	migrationPublished     = "published"
	migrationWipeStaged    = "wipe_staged"
)

type legacySourceSnapshot struct {
	path       string
	parent     string
	name       string
	root       *os.Root
	parentInfo os.FileInfo
	info       os.FileInfo
	content    []byte
	digest     string
}

type migrationMarker struct {
	Version        int               `json:"version"`
	State          string            `json:"state"`
	SourcePath     string            `json:"source_path"`
	SourceSHA256   string            `json:"source_sha256"`
	SourceDevice   uint64            `json:"source_device"`
	SourceInode    uint64            `json:"source_inode"`
	SourceMode     uint32            `json:"source_mode"`
	SourceOwner    uint32            `json:"source_owner"`
	ParentDevice   uint64            `json:"parent_device"`
	ParentInode    uint64            `json:"parent_inode"`
	ParentMode     uint32            `json:"parent_mode"`
	ParentOwner    uint32            `json:"parent_owner"`
	SecureWipe     bool              `json:"secure_wipe"`
	WipeStaging    string            `json:"wipe_staging,omitempty"`
	PreserveUser   bool              `json:"preserve_user"`
	ArtifactSHA256 map[string]string `json:"artifact_sha256"`
}

type migrationArtifact struct {
	relative  string
	content   []byte
	preserve  bool
	noReplace bool
}

type migrationArtifactPublisher func(directory, name string, content []byte, noReplace bool) error

var (
	publishMigrationFile migrationArtifactPublisher = func(directory, name string, content []byte, noReplace bool) error {
		if noReplace {
			return writeMissingSecureFile(directory, name, content)
		}
		return writeSecureFileAtomically(directory, name, content)
	}
	renameLegacyFile     = secureRenameLegacySource
	shredLegacyFile      = secureWipeLegacySource
	sourceFinalizeHook   = func() error { return nil }
	migrationCommitHook  = func() error { return nil }
	secureWipeCheckpoint = func(int) error { return nil }
)

func openLegacySourceSnapshot(path string) (*legacySourceSnapshot, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve migration source: %w", err)
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	root, err := openDirectoryNoSymlinks(parent, false, 0)
	if err != nil {
		return nil, fmt.Errorf("open migration source parent: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = root.Close()
		}
	}()

	parentInfo, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, fmt.Errorf("inspect migration source parent: %w", err)
	}
	if parentInfo.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("migration source parent %s has unsafe mode %#o", parent, parentInfo.Mode().Perm())
	}
	if owner, ok := fileOwnerUID(parentInfo); !ok || int64(owner) != int64(os.Geteuid()) {
		return nil, fmt.Errorf("migration source parent %s is not owned by effective uid %d", parent, os.Geteuid())
	}

	name := filepath.Base(absolute)
	content, info, err := readSecureRegularFileSnapshot(root, name, absolute)
	if err != nil {
		return nil, err
	}
	if owner, ok := fileOwnerUID(info); !ok || int64(owner) != int64(os.Geteuid()) {
		return nil, fmt.Errorf("migration source %s is not owned by effective uid %d", absolute, os.Geteuid())
	}
	sum := sha256.Sum256(content)
	closeOnError = false
	return &legacySourceSnapshot{
		path:       absolute,
		parent:     parent,
		name:       name,
		root:       root,
		parentInfo: parentInfo,
		info:       info,
		content:    content,
		digest:     hex.EncodeToString(sum[:]),
	}, nil
}

func (snapshot *legacySourceSnapshot) Close() error {
	if snapshot == nil || snapshot.root == nil {
		return nil
	}
	err := snapshot.root.Close()
	snapshot.root = nil
	return err
}

func (snapshot *legacySourceSnapshot) revalidate() error {
	if snapshot == nil || snapshot.root == nil {
		return fmt.Errorf("migration source snapshot is closed")
	}
	if err := snapshot.revalidateParent(); err != nil {
		return err
	}
	content, info, err := readSecureRegularFileSnapshot(snapshot.root, snapshot.name, snapshot.path)
	if err != nil {
		return err
	}
	if !os.SameFile(snapshot.info, info) || snapshot.info.Mode() != info.Mode() {
		return fmt.Errorf("migration source %s was substituted after validation", snapshot.path)
	}
	if owner, ok := fileOwnerUID(info); !ok || int64(owner) != int64(os.Geteuid()) {
		return fmt.Errorf("migration source %s owner changed after validation", snapshot.path)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != snapshot.digest {
		return fmt.Errorf("migration source %s content changed after validation", snapshot.path)
	}
	return nil
}

func (snapshot *legacySourceSnapshot) revalidateParent() error {
	if snapshot == nil || snapshot.root == nil || snapshot.parentInfo == nil {
		return fmt.Errorf("migration source parent snapshot is unavailable")
	}
	openedInfo, err := rootDirectoryInfo(snapshot.root)
	if err != nil || !sameFileAndMode(snapshot.parentInfo, openedInfo) {
		return fmt.Errorf("migration source parent changed after validation")
	}
	if openedInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("migration source parent %s became writable by group or others", snapshot.parent)
	}
	if owner, ok := fileOwnerUID(openedInfo); !ok || int64(owner) != int64(os.Geteuid()) {
		return fmt.Errorf("migration source parent %s owner changed after validation", snapshot.parent)
	}
	pathRoot, err := openDirectoryNoSymlinks(snapshot.parent, false, 0)
	if err != nil {
		return fmt.Errorf("reopen migration source parent: %w", err)
	}
	defer func() { _ = pathRoot.Close() }()
	pathInfo, err := rootDirectoryInfo(pathRoot)
	if err != nil || !sameFileAndMode(snapshot.parentInfo, pathInfo) {
		return fmt.Errorf("migration source parent path was substituted after validation")
	}
	return nil
}

func (snapshot *legacySourceSnapshot) matchesIdentity(info os.FileInfo) bool {
	if snapshot == nil || snapshot.info == nil || info == nil || !sameFileAndMode(snapshot.info, info) {
		return false
	}
	expectedOwner, expectedOK := fileOwnerUID(snapshot.info)
	currentOwner, currentOK := fileOwnerUID(info)
	return expectedOK && currentOK && expectedOwner == currentOwner
}

func (snapshot *legacySourceSnapshot) matchesContentAndIdentity(content []byte, info os.FileInfo) bool {
	return snapshot.matchesIdentity(info) && digestBytes(content) == snapshot.digest
}

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func fileOwnerUIDGID(info os.FileInfo) (uint32, uint32, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

func fileDeviceInode(info os.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

func (marker *migrationMarker) matchesSourceIdentity(snapshot *legacySourceSnapshot) bool {
	if marker == nil || snapshot == nil || snapshot.info == nil || snapshot.parentInfo == nil {
		return false
	}
	device, inode, ok := fileDeviceInode(snapshot.info)
	owner, ownerOK := fileOwnerUID(snapshot.info)
	parentDevice, parentInode, parentOK := fileDeviceInode(snapshot.parentInfo)
	parentOwner, parentOwnerOK := fileOwnerUID(snapshot.parentInfo)
	return ok && ownerOK && marker.SourceDevice == device && marker.SourceInode == inode &&
		marker.SourceMode == uint32(snapshot.info.Mode()) && marker.SourceOwner == owner &&
		parentOK && parentOwnerOK && marker.ParentDevice == parentDevice && marker.ParentInode == parentInode &&
		marker.ParentMode == uint32(snapshot.parentInfo.Mode()) && marker.ParentOwner == parentOwner
}

func secureRenameLegacySource(snapshot *legacySourceSnapshot) error {
	if err := snapshot.revalidate(); err != nil {
		return err
	}
	target := snapshot.name + ".migrated"
	if _, err := snapshot.root.Lstat(target); err == nil {
		return fmt.Errorf("migration retention target %s already exists", snapshot.path+".migrated")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect migration retention target: %w", err)
	}
	if err := sourceFinalizeHook(); err != nil {
		return fmt.Errorf("migration source finalization hook: %w", err)
	}
	if err := snapshot.revalidate(); err != nil {
		return err
	}
	staging, err := randomFinalizationName(snapshot.name)
	if err != nil {
		return err
	}
	if err := snapshot.root.Rename(snapshot.name, staging); err != nil {
		return fmt.Errorf("stage migration source for identity verification: %w", err)
	}
	restore := func(name string) error {
		if _, err := snapshot.root.Lstat(snapshot.name); err == nil {
			return fmt.Errorf("cannot restore staged source because %s reappeared; retained staged inode as %s", snapshot.path, filepath.Join(snapshot.parent, name))
		} else if !os.IsNotExist(err) {
			return err
		}
		return snapshot.root.Rename(name, snapshot.name)
	}
	stagedContent, stagedInfo, err := readSecureRegularFileSnapshot(snapshot.root, staging, filepath.Join(snapshot.parent, staging))
	if err != nil || !snapshot.matchesContentAndIdentity(stagedContent, stagedInfo) {
		restoreErr := restore(staging)
		return fmt.Errorf("migration source was substituted before retention; replacement restored: %v", restoreErr)
	}
	if err := snapshot.revalidateParent(); err != nil {
		restoreErr := restore(staging)
		return fmt.Errorf("migration parent changed before retention: %w (restore: %v)", err, restoreErr)
	}
	if _, err := snapshot.root.Lstat(target); err == nil {
		restoreErr := restore(staging)
		return fmt.Errorf("migration retention target %s appeared concurrently (restore: %v)", snapshot.path+".migrated", restoreErr)
	} else if !os.IsNotExist(err) {
		restoreErr := restore(staging)
		return fmt.Errorf("reinspect migration retention target: %w (restore: %v)", err, restoreErr)
	}
	if err := snapshot.root.Rename(staging, target); err != nil {
		restoreErr := restore(staging)
		return fmt.Errorf("retain verified migration source: %w (restore: %v)", err, restoreErr)
	}
	retainedContent, retainedInfo, err := readSecureRegularFileSnapshot(snapshot.root, target, snapshot.path+".migrated")
	if err != nil || !snapshot.matchesContentAndIdentity(retainedContent, retainedInfo) {
		restoreErr := restore(target)
		return fmt.Errorf("retained migration source failed post-rename identity verification (restore: %v)", restoreErr)
	}
	if err := snapshot.revalidateParent(); err != nil {
		return err
	}
	return syncRootDirectory(snapshot.root)
}

func randomFinalizationName(sourceName string) (string, error) {
	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return "", err
	}
	return "." + sourceName + ".finalize-" + hex.EncodeToString(randomSuffix), nil
}

func secureWipeLegacySource(snapshot *legacySourceSnapshot, beforeRemove func(string) error) error {
	if err := snapshot.revalidate(); err != nil {
		return err
	}
	if err := sourceFinalizeHook(); err != nil {
		return fmt.Errorf("migration source finalization hook: %w", err)
	}
	if err := snapshot.revalidate(); err != nil {
		return err
	}
	staging := wipeStagingName(snapshot.name)
	if _, err := snapshot.root.Lstat(staging); err == nil {
		return fmt.Errorf("secure-wipe staging path %s already exists", filepath.Join(snapshot.parent, staging))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect secure-wipe staging path: %w", err)
	}
	file, err := snapshot.root.OpenFile(snapshot.name, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open migration source for secure wipe: %w", err)
	}
	defer func() { _ = file.Close() }()
	openedBefore, err := file.Stat()
	if err != nil || !snapshot.matchesIdentity(openedBefore) {
		return fmt.Errorf("migration source changed before secure wipe")
	}
	currentContent, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("revalidate migration source content before secure wipe: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(openedBefore, opened) || !snapshot.matchesContentAndIdentity(currentContent, opened) {
		return fmt.Errorf("migration source content changed before secure wipe")
	}

	buffer := make([]byte, 64*1024)
	for pass := 0; pass < 4; pass++ {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek migration source for wipe pass %d: %w", pass+1, err)
		}
		remaining := snapshot.info.Size()
		for remaining > 0 {
			chunk := int64(len(buffer))
			if remaining < chunk {
				chunk = remaining
			}
			if pass < 3 {
				if _, err := io.ReadFull(rand.Reader, buffer[:chunk]); err != nil {
					return fmt.Errorf("generate secure wipe data: %w", err)
				}
			} else {
				clear(buffer[:chunk])
			}
			if _, err := file.Write(buffer[:chunk]); err != nil {
				return fmt.Errorf("write secure wipe pass %d: %w", pass+1, err)
			}
			remaining -= chunk
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync secure wipe pass %d: %w", pass+1, err)
		}
		if err := secureWipeCheckpoint(pass + 1); err != nil {
			return fmt.Errorf("secure wipe interrupted after pass %d: %w", pass+1, err)
		}
	}
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate securely wiped source: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync truncated migration source: %w", err)
	}
	if err := secureWipeCheckpoint(5); err != nil {
		return fmt.Errorf("secure wipe interrupted after truncate: %w", err)
	}
	if err := snapshot.revalidateParent(); err != nil {
		return err
	}
	current, err := snapshot.root.Lstat(snapshot.name)
	if err != nil || !os.SameFile(opened, current) {
		return fmt.Errorf("migration source path changed before secure wipe removal")
	}
	if err := snapshot.root.Rename(snapshot.name, staging); err != nil {
		return fmt.Errorf("stage securely wiped migration source: %w", err)
	}
	stagedContent, stagedInfo, err := readSecureRegularFileSnapshot(snapshot.root, staging, filepath.Join(snapshot.parent, staging))
	if err != nil || !os.SameFile(opened, stagedInfo) || !snapshot.matchesIdentity(stagedInfo) || len(stagedContent) != 0 {
		restoreErr := restoreStagedSource(snapshot.root, snapshot.name, staging)
		return fmt.Errorf("secure-wipe staging inode failed identity verification (restore: %v)", restoreErr)
	}
	if err := syncRootDirectory(snapshot.root); err != nil {
		return err
	}
	if err := secureWipeCheckpoint(6); err != nil {
		return fmt.Errorf("secure wipe interrupted after durable staging: %w", err)
	}
	if beforeRemove == nil {
		return fmt.Errorf("secure-wipe durable staging callback is missing")
	}
	if err := beforeRemove(staging); err != nil {
		return fmt.Errorf("persist secure-wipe staging state: %w", err)
	}
	if err := removeVerifiedWipeStaging(snapshot.root, staging, opened); err != nil {
		return err
	}
	if err := syncRootDirectory(snapshot.root); err != nil {
		return err
	}
	if err := secureWipeCheckpoint(7); err != nil {
		return fmt.Errorf("secure wipe interrupted after removal: %w", err)
	}
	return snapshot.revalidateParent()
}

func wipeStagingName(sourceName string) string {
	return "." + sourceName + ".syswarden-wipe-in-progress"
}

func restoreStagedSource(root *os.Root, sourceName, stagingName string) error {
	if _, err := root.Lstat(sourceName); err == nil {
		return fmt.Errorf("source path reappeared while restoring staged inode")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return root.Rename(stagingName, sourceName)
}

func removeVerifiedWipeStaging(root *os.Root, stagingName string, expected os.FileInfo) error {
	current, err := root.Lstat(stagingName)
	if err != nil || expected == nil || !os.SameFile(expected, current) {
		return fmt.Errorf("secure-wipe staging inode changed before removal")
	}
	if err := root.Remove(stagingName); err != nil {
		return fmt.Errorf("remove securely wiped migration source: %w", err)
	}
	return nil
}

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func markerPath(outputDir string) string {
	return filepath.Join(outputDir, migrationMarkerName)
}

func rejectMigrationInProgress(outputDir string) error {
	root, err := openConfigDirectory(outputDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(migrationMarkerName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect migration transaction marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
		return fmt.Errorf("migration transaction marker is unsafe")
	}
	return fmt.Errorf("configuration migration is incomplete; rerun syswarden migrate-config before loading or filling defaults")
}

func readMigrationMarker(outputDir string) (*migrationMarker, error) {
	content, err := readSecureFileByPath(markerPath(outputDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var marker migrationMarker
	if err := json.Unmarshal(content, &marker); err != nil {
		return nil, fmt.Errorf("decode migration marker: %w", err)
	}
	if marker.Version != migrationMarkerVersion ||
		(marker.State != migrationPublishing && marker.State != migrationPublished && marker.State != migrationWipeStaged) ||
		marker.SourcePath == "" || marker.SourceSHA256 == "" || marker.SourceInode == 0 ||
		marker.SourceMode == 0 || marker.ParentInode == 0 || marker.ParentMode == 0 || len(marker.ArtifactSHA256) == 0 {
		return nil, fmt.Errorf("migration marker is invalid")
	}
	expectedStaging := wipeStagingName(filepath.Base(marker.SourcePath))
	if marker.State == migrationWipeStaged {
		if !marker.SecureWipe || marker.WipeStaging != expectedStaging {
			return nil, fmt.Errorf("migration secure-wipe marker is invalid")
		}
	} else if marker.WipeStaging != "" {
		return nil, fmt.Errorf("migration marker has an unexpected secure-wipe staging path")
	}
	return &marker, nil
}

func (m *Migrator) migrationArtifacts(master string, modules []renderedModule, marker *migrationMarker) ([]migrationArtifact, bool, error) {
	artifacts := make([]migrationArtifact, 0, len(modules)+1)
	preserveUser := marker != nil && marker.PreserveUser
	modulesDir := filepath.Join(m.OutputDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = modulesRoot.Close() }()

	for _, module := range modules {
		artifact := migrationArtifact{
			relative: filepath.ToSlash(filepath.Join("modules", module.name)),
			content:  []byte(module.content),
		}
		if module.name == "99-user.toml" {
			info, statErr := modulesRoot.Lstat(module.name)
			switch {
			case statErr == nil:
				content, readErr := readSecureRegularFile(modulesRoot, module.name, filepath.Join(modulesDir, module.name))
				if readErr != nil {
					return nil, false, readErr
				}
				if marker == nil || marker.PreserveUser || marker.State == migrationPublishing {
					artifact.content = content
					artifact.preserve = true
					preserveUser = true
				} else if digestBytes(content) != marker.ArtifactSHA256[artifact.relative] {
					return nil, false, fmt.Errorf("operator user module changed after migration publication")
				}
				_ = info
			case errors.Is(statErr, fs.ErrNotExist):
				if marker != nil && marker.PreserveUser {
					return nil, false, fmt.Errorf("preserved operator user module disappeared during migration transaction")
				}
			default:
				return nil, false, fmt.Errorf("inspect operator user module: %w", statErr)
			}
			// The generated operator module is published only when the name is
			// still absent. A concurrent validated writer always wins this race.
			artifact.noReplace = !artifact.preserve
		}
		artifacts = append(artifacts, artifact)
	}
	artifacts = append(artifacts, migrationArtifact{relative: "config.toml", content: []byte(master)})
	return artifacts, preserveUser, nil
}

func (m *Migrator) validateEffectiveMigrationArtifacts(master string, artifacts []migrationArtifact) error {
	modules := make([]renderedModule, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.relative == "config.toml" {
			continue
		}
		if filepath.Dir(filepath.FromSlash(artifact.relative)) != "modules" {
			return fmt.Errorf("unexpected migration artifact %s", artifact.relative)
		}
		modules = append(modules, renderedModule{
			name:    filepath.Base(filepath.FromSlash(artifact.relative)),
			content: string(artifact.content),
		})
	}
	return m.validateRenderedMigration(master, modules)
}

func (m *Migrator) publishMigrationArtifacts(artifacts []migrationArtifact) error {
	for _, artifact := range artifacts {
		outputPath := filepath.Join(m.OutputDir, filepath.FromSlash(artifact.relative))
		if artifact.preserve {
			fmt.Printf("Preserved: %s\n", outputPath)
			continue
		}
		if err := publishMigrationFile(filepath.Dir(outputPath), filepath.Base(outputPath), artifact.content, artifact.noReplace); err != nil {
			return fmt.Errorf("publish migration artifact %s: %w", artifact.relative, err)
		}
		fmt.Printf("Created: %s\n", outputPath)
	}
	return nil
}

func (m *Migrator) recoverPublishedMigration(marker *migrationMarker, sourceErr error) error {
	absolute, err := filepath.Abs(m.SourcePath)
	if err != nil || filepath.Clean(absolute) != marker.SourcePath {
		return fmt.Errorf("migration source path does not match the published transaction")
	}
	if !errors.Is(sourceErr, fs.ErrNotExist) {
		return fmt.Errorf("migration source cannot be safely recovered: %w", sourceErr)
	}
	if err := verifyMigrationArtifacts(m.OutputDir, marker.ArtifactSHA256); err != nil {
		return err
	}
	if marker.SecureWipe {
		return m.recoverSecureWipeMigration(marker)
	}
	retained, err := readSecureFileByPath(marker.SourcePath + ".migrated")
	if err != nil {
		return fmt.Errorf("verify retained migration source: %w", err)
	}
	if digestBytes(retained) != marker.SourceSHA256 {
		return fmt.Errorf("retained migration source does not match the transaction")
	}
	if err := removeMigrationMarker(m.OutputDir); err != nil {
		return fmt.Errorf("finalize recovered migration transaction: %w", err)
	}
	return nil
}

func (m *Migrator) recoverSecureWipeMigration(marker *migrationMarker) error {
	if marker == nil || !marker.SecureWipe ||
		(marker.State != migrationPublished && marker.State != migrationWipeStaged) {
		return fmt.Errorf("secure-wipe recovery marker is invalid")
	}
	stagingName := wipeStagingName(filepath.Base(marker.SourcePath))
	stagingPath := filepath.Join(filepath.Dir(marker.SourcePath), stagingName)
	staged, err := openLegacySourceSnapshot(stagingPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect secure-wipe staging inode: %w", err)
		}
		if marker.State != migrationWipeStaged || marker.WipeStaging != stagingName {
			return fmt.Errorf("migration source disappeared before a durable secure-wipe staging state")
		}
		if err := removeMigrationMarker(m.OutputDir); err != nil {
			return fmt.Errorf("finalize recovered secure-wipe transaction: %w", err)
		}
		return nil
	}
	defer func() { _ = staged.Close() }()
	if !marker.matchesSourceIdentity(staged) || staged.info.Size() != 0 || len(staged.content) != 0 {
		return fmt.Errorf("secure-wipe staging inode does not match the published transaction")
	}
	if marker.State == migrationPublished {
		marker.State = migrationWipeStaged
		marker.WipeStaging = stagingName
		if err := writeMigrationMarker(m.OutputDir, marker, true); err != nil {
			return fmt.Errorf("commit recovered secure-wipe staging state: %w", err)
		}
	} else if marker.WipeStaging != stagingName {
		return fmt.Errorf("secure-wipe staging path does not match the transaction")
	}
	if err := staged.revalidateParent(); err != nil {
		return err
	}
	if err := removeVerifiedWipeStaging(staged.root, staged.name, staged.info); err != nil {
		return err
	}
	if err := syncRootDirectory(staged.root); err != nil {
		return err
	}
	if err := secureWipeCheckpoint(7); err != nil {
		return fmt.Errorf("secure wipe interrupted after recovered removal: %w", err)
	}
	if err := removeMigrationMarker(m.OutputDir); err != nil {
		return fmt.Errorf("finalize recovered secure-wipe transaction: %w", err)
	}
	return nil
}

func writeMigrationMarker(outputDir string, marker *migrationMarker, replace bool) error {
	content, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if replace {
		return writeSecureFileAtomically(outputDir, migrationMarkerName, content)
	}
	return writeMissingSecureFile(outputDir, migrationMarkerName, content)
}

func removeMigrationMarker(outputDir string) error {
	root, err := openConfigDirectory(outputDir, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(migrationMarkerName)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
		return fmt.Errorf("migration marker is unsafe")
	}
	if err := root.Remove(migrationMarkerName); err != nil {
		return err
	}
	return syncRootDirectory(root)
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func verifyMigrationArtifacts(outputDir string, expected map[string]string) error {
	expectedModules := make(map[string]struct{})
	for relative := range expected {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
		if clean != relative {
			return fmt.Errorf("migration artifact path %s is not canonical", relative)
		}
		if relative == "config.toml" {
			continue
		}
		if !strings.HasPrefix(relative, "modules/") {
			return fmt.Errorf("migration artifact path %s is outside the module inventory", relative)
		}
		name := strings.TrimPrefix(relative, "modules/")
		if name == "" || filepath.Base(name) != name || filepath.Ext(name) != ".toml" {
			return fmt.Errorf("migration artifact path %s is not a canonical TOML module", relative)
		}
		expectedModules[name] = struct{}{}
	}

	modulesDir := filepath.Join(outputDir, "modules")
	modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return fmt.Errorf("verify migration module inventory: %w", err)
	}
	directory, err := modulesRoot.Open(".")
	if err != nil {
		_ = modulesRoot.Close()
		return fmt.Errorf("verify migration module inventory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	_ = modulesRoot.Close()
	if err != nil {
		return fmt.Errorf("verify migration module inventory: %w", err)
	}
	var actualModules []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".toml" {
			actualModules = append(actualModules, entry.Name())
		}
	}
	sort.Strings(actualModules)
	if len(actualModules) != len(expectedModules) {
		return fmt.Errorf("migration TOML module inventory changed: got %v", actualModules)
	}
	for _, name := range actualModules {
		if _, ok := expectedModules[name]; !ok {
			return fmt.Errorf("migration TOML module inventory contains unexpected module %s", name)
		}
	}

	for relative, digest := range expected {
		content, err := readSecureFileByPath(filepath.Join(outputDir, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("verify migration artifact %s: %w", relative, err)
		}
		if digestBytes(content) != digest {
			return fmt.Errorf("migration artifact %s does not match the transaction", relative)
		}
	}
	return nil
}
