package security

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type securityFileTarget struct {
	directory string
	name      string
}

func securityFileTargetForPath(path string) (securityFileTarget, error) {
	switch path {
	case "/boot/loader.conf.local":
		return securityFileTarget{directory: "/boot", name: "loader.conf.local"}, nil
	case "/etc/ssh/sshd_config":
		return securityFileTarget{directory: "/etc/ssh", name: "sshd_config"}, nil
	case "/etc/newsyslog.conf":
		return securityFileTarget{directory: "/etc", name: "newsyslog.conf"}, nil
	default:
		return securityFileTarget{}, fmt.Errorf("security file path is not approved: %q", path)
	}
}

func openSecurityDirectory(target securityFileTarget) (*os.Root, error) {
	if !filepath.IsAbs(target.directory) || filepath.Clean(target.directory) != target.directory {
		return nil, fmt.Errorf("security directory must be canonical and absolute: %q", target.directory)
	}
	if target.name == "" || target.name == "." || target.name == ".." ||
		filepath.Base(target.name) != target.name || strings.ContainsAny(target.name, `/\`) {
		return nil, fmt.Errorf("security filename must be a safe basename: %q", target.name)
	}

	currentRoot, err := os.OpenRoot("/")
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(target.directory, "/"), "/") {
		if component == "" {
			continue
		}
		info, err := currentRoot.Lstat(component)
		if err != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("inspect security directory component %s: %w", component, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("security directory component is not a real directory: %s", component)
		}
		nextRoot, err := currentRoot.OpenRoot(component)
		if err != nil {
			_ = currentRoot.Close()
			return nil, fmt.Errorf("open security directory component %s: %w", component, err)
		}
		openedInfo, err := nextRoot.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = nextRoot.Close()
			_ = currentRoot.Close()
			return nil, fmt.Errorf("security directory component changed while opening: %s", component)
		}
		_ = currentRoot.Close()
		currentRoot = nextRoot
	}
	return currentRoot, nil
}

func rewriteSecurityFile(path string, content []byte) (resultErr error) {
	target, err := securityFileTargetForPath(path)
	if err != nil {
		return err
	}
	return rewriteSecurityTarget(target, content)
}

func rewriteSecurityFileFromSnapshot(path string, content, snapshot []byte) error {
	target, err := securityFileTargetForPath(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(snapshot)
	return rewriteSecurityTargetExpected(target, content, &digest, nil)
}

type securityFileIdentity struct {
	info       fs.FileInfo
	digest     [sha256.Size]byte
	uid        int
	gid        int
	ownerKnown bool
}

func snapshotSecurityFile(file *os.File) (fs.FileInfo, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	before, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, digest, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, digest, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, digest, fmt.Errorf("security file changed while snapshotting")
	}
	copy(digest[:], hash.Sum(nil))
	return after, digest, nil
}

func sameSecurityFileState(expected securityFileIdentity, actualInfo fs.FileInfo, actualDigest [sha256.Size]byte) bool {
	if !os.SameFile(expected.info, actualInfo) || expected.info.Size() != actualInfo.Size() ||
		!expected.info.ModTime().Equal(actualInfo.ModTime()) || expected.info.Mode() != actualInfo.Mode() ||
		expected.digest != actualDigest {
		return false
	}
	if expected.ownerKnown {
		stat, ok := actualInfo.Sys().(*syscall.Stat_t)
		return ok && int(stat.Uid) == expected.uid && int(stat.Gid) == expected.gid
	}
	return true
}

func inspectSecurityDestination(root *os.Root, target securityFileTarget) (securityFileIdentity, bool, error) {
	pathInfo, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return securityFileIdentity{}, false, nil
	}
	if err != nil {
		return securityFileIdentity{}, false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return securityFileIdentity{}, false, fmt.Errorf("security file is not regular: %s", target.name)
	}
	file, err := root.OpenFile(target.name, os.O_RDONLY, 0)
	if err != nil {
		return securityFileIdentity{}, false, err
	}
	openedInfo, digest, statErr := snapshotSecurityFile(file)
	closeErr := file.Close()
	if statErr != nil {
		return securityFileIdentity{}, false, statErr
	}
	if closeErr != nil {
		return securityFileIdentity{}, false, closeErr
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return securityFileIdentity{}, false, fmt.Errorf("security file changed while opening: %s", target.name)
	}
	identity := securityFileIdentity{info: openedInfo, digest: digest}
	if stat, ok := openedInfo.Sys().(*syscall.Stat_t); ok {
		identity.uid = int(stat.Uid)
		identity.gid = int(stat.Gid)
		identity.ownerKnown = true
	}
	return identity, true, nil
}

func createSecurityStagingFile(root *os.Root, target securityFileTarget) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate security staging name: %w", err)
		}
		name := "." + target.name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create security staging file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("create security staging file: too many name collisions")
}

func verifySecurityDestination(root *os.Root, target securityFileTarget, identity securityFileIdentity, existed bool) error {
	current, err := root.Lstat(target.name)
	if !existed {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("security file appeared before publication: %s", target.name)
	}
	if err != nil {
		return fmt.Errorf("reinspect security file %s: %w", target.name, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(identity.info, current) {
		return fmt.Errorf("security file changed before publication: %s", target.name)
	}
	file, err := root.OpenFile(target.name, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("reopen security file %s before publication: %w", target.name, err)
	}
	actualInfo, actualDigest, snapshotErr := snapshotSecurityFile(file)
	closeErr := file.Close()
	if snapshotErr != nil {
		return fmt.Errorf("resnapshot security file %s: %w", target.name, snapshotErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close security file %s after resnapshot: %w", target.name, closeErr)
	}
	if !sameSecurityFileState(identity, actualInfo, actualDigest) {
		return fmt.Errorf("security file content or metadata changed before publication: %s", target.name)
	}
	return nil
}

func syncSecurityDirectory(root *os.Root) error {
	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open security directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync security directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close security directory: %w", err)
	}
	return nil
}

func rewriteSecurityTarget(target securityFileTarget, content []byte) error {
	return rewriteSecurityTargetBeforeRename(target, content, nil)
}

func rewriteSecurityTargetBeforeRename(target securityFileTarget, content []byte, beforeRename func() error) error {
	return rewriteSecurityTargetExpected(target, content, nil, beforeRename)
}

func rewriteSecurityTargetExpected(target securityFileTarget, content []byte, expectedDigest *[sha256.Size]byte, beforeRename func() error) error {
	root, err := openSecurityDirectory(target)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	identity, existed, err := inspectSecurityDestination(root, target)
	if err != nil {
		return fmt.Errorf("inspect security file %s: %w", target.name, err)
	}
	if expectedDigest != nil && (!existed || identity.digest != *expectedDigest) {
		return fmt.Errorf("security file changed after it was read: %s", target.name)
	}
	file, stagingName, err := createSecurityStagingFile(root, target)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = root.Remove(stagingName)
		}
	}()
	if identity.ownerKnown {
		if err := file.Chown(identity.uid, identity.gid); err != nil {
			return fmt.Errorf("preserve security file owner %s: %w", target.name, err)
		}
	}
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict security staging file for %s: %w", target.name, err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write security staging file for %s: %w", target.name, err)
	} else if written != len(content) {
		return fmt.Errorf("write security staging file for %s: %w", target.name, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync security staging file for %s: %w", target.name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close security staging file for %s: %w", target.name, err)
	}
	file = nil
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := verifySecurityDestination(root, target, identity, existed); err != nil {
		return err
	}
	if err := root.Rename(stagingName, target.name); err != nil {
		return fmt.Errorf("publish security file %s: %w", target.name, err)
	}
	stagingName = ""
	return syncSecurityDirectory(root)
}
