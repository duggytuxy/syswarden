//go:build linux

package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type configReplacementOps struct {
	rename func(*os.Root, string, string, bool) error
	sync   func(*os.Root) error
	remove func(*os.Root, string) error
}

func defaultConfigReplacementOps() configReplacementOps {
	return configReplacementOps{
		rename: renameConfigFileAt,
		sync:   syncRootDirectory,
		remove: func(root *os.Root, name string) error { return root.Remove(name) },
	}
}

// renameConfigFileAt never removes the live name before replacing it. Unsupported
// renameat2 operations are errors; there is no rename-away fallback.
func renameConfigFileAt(root *os.Root, from, to string, exchange bool) error {
	if from == "" || to == "" || filepath.Base(from) != from || filepath.Base(to) != to || from == to {
		return fmt.Errorf("invalid configuration publication names")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	flags := uint(unix.RENAME_NOREPLACE)
	if exchange {
		flags = unix.RENAME_EXCHANGE
	}
	return unix.Renameat2(int(directory.Fd()), from, int(directory.Fd()), to, flags)
}

func replaceSecureConfigFile(directory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error) error {
	return replaceSecureConfigFileUsing(directory, name, content, expected, preCommit, prePublish, postCommit, defaultConfigReplacementOps())
}

// This is atomic name replacement with in-process rollback, not a durable
// transaction journal. After interruption, retained private files require
// explicit inspection. Concurrent root modification cannot be serialized by
// pathname checks; observed ambiguous identities are retained without cleanup.
func replaceSecureConfigFileUsing(directory, name string, content []byte, expected *secureFileIdentity, preCommit, prePublish, postCommit func() error, ops configReplacementOps) (resultErr error) {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return fmt.Errorf("invalid configuration filename")
	}
	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return err
	}
	stage := "." + name + ".tmp-" + hex.EncodeToString(randomSuffix)
	file, err := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	fileOpen := true
	stagedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect new configuration stage; private stage retained: %w", err)
	}
	candidate := newSecureFileIdentity(nil, stagedInfo)
	cleanupStage := true
	defer func() {
		if fileOpen {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if cleanupStage {
			if err := removeConfigReplacementFile(root, stage, candidate, ops); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("cleanup private configuration stage: %w", err))
			} else if err := ops.sync(root); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("sync configuration stage cleanup: %w", err))
			}
		}
	}()
	if expected != nil {
		uid, gid, ok := fileOwnerUIDGID(expected.info)
		if !ok {
			return fmt.Errorf("capture existing secure file ownership")
		}
		if err := applySecureFileOwnership(file, int(uid), int(gid)); err != nil {
			return fmt.Errorf("preserve existing secure file ownership: %w", err)
		}
		if err := file.Chmod(expected.info.Mode().Perm()); err != nil {
			return err
		}
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	stagedInfo, err = file.Stat()
	if err != nil {
		return err
	}
	candidate = newSecureFileIdentity(content, stagedInfo)
	if err := file.Sync(); err != nil {
		return err
	}
	fileOpen = false
	if err := file.Close(); err != nil {
		return err
	}

	checkDestination := func() error {
		if expected == nil {
			if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
				return nil
			} else if err != nil {
				return err
			}
			return fmt.Errorf("secure file appeared before publish")
		}
		if err := verifyConfigReplacementFile(root, name, expected); err != nil {
			return fmt.Errorf("secure file changed before publish: %w", err)
		}
		return nil
	}
	if err := checkDestination(); err != nil {
		return err
	}
	if preCommit != nil {
		if err := preCommit(); err != nil {
			return fmt.Errorf("pre-commit configuration CAS: %w", err)
		}
	}
	if prePublish != nil {
		if err := prePublish(); err != nil {
			return fmt.Errorf("pre-publication configuration CAS: %w", err)
		}
	}
	// A callback can run another writer. Repeat the complete input snapshot,
	// including all read modules, after the last pre-publication callback.
	if preCommit != nil {
		if err := preCommit(); err != nil {
			return fmt.Errorf("final pre-publication configuration CAS: %w", err)
		}
	}
	if err := checkDestination(); err != nil {
		return err
	}
	if err := verifyConfigReplacementFile(root, stage, candidate); err != nil {
		return fmt.Errorf("configuration stage changed before publish: %w", err)
	}
	if err := ops.rename(root, stage, name, expected != nil); err != nil {
		return fmt.Errorf("publish configuration with atomic exchange or no-replace operation: %w", err)
	}
	// After exchange, the staging name holds the original, never disposable
	// candidate bytes. No deferred cleanup may remove it on an ambiguous error.
	cleanupStage = false
	checkPair := func() error {
		if err := verifyConfigReplacementFile(root, name, candidate); err != nil {
			return fmt.Errorf("published configuration identity changed: %w", err)
		}
		if expected != nil {
			if err := verifyConfigReplacementFile(root, stage, expected); err != nil {
				return fmt.Errorf("retained original configuration identity changed: %w", err)
			}
		} else if _, err := root.Lstat(stage); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("configuration stage reappeared after publication")
		}
		return nil
	}
	rollback := func() error {
		if err := checkPair(); err != nil {
			return fmt.Errorf("ambiguous configuration pair retained without rollback: %w", err)
		}
		if err := ops.rename(root, name, stage, expected != nil); err != nil {
			return fmt.Errorf("atomic configuration rollback: %w", err)
		}
		if expected != nil {
			if err := verifyConfigReplacementFile(root, name, expected); err != nil {
				return fmt.Errorf("restored configuration identity changed; pair retained: %w", err)
			}
		}
		if err := verifyConfigReplacementFile(root, stage, candidate); err != nil {
			return fmt.Errorf("rollback candidate identity changed; pair retained: %w", err)
		}
		if err := ops.sync(root); err != nil {
			return fmt.Errorf("sync configuration rollback; stage retained: %w", err)
		}
		if err := removeConfigReplacementFile(root, stage, candidate, ops); err != nil {
			return fmt.Errorf("cleanup rolled-back configuration: %w", err)
		}
		return ops.sync(root)
	}
	failAfterPublish := func(cause error) error { return errors.Join(cause, rollback()) }
	if err := checkPair(); err != nil {
		return fmt.Errorf("post-publication inode CAS; ambiguous configuration pair retained: %w", err)
	}
	if err := ops.sync(root); err != nil {
		return failAfterPublish(fmt.Errorf("sync configuration publication: %w", err))
	}
	if postCommit != nil {
		if err := postCommit(); err != nil {
			return failAfterPublish(fmt.Errorf("post-commit configuration CAS: %w", err))
		}
	}
	if err := checkPair(); err != nil {
		return failAfterPublish(fmt.Errorf("post-commit inode CAS: %w", err))
	}
	if expected != nil {
		if err := removeConfigReplacementFile(root, stage, expected, ops); err != nil {
			return failAfterPublish(fmt.Errorf("remove original configuration stage: %w", err))
		}
		if err := ops.sync(root); err != nil {
			return fmt.Errorf("configuration published but cleanup durability is unconfirmed: %w", err)
		}
	}
	return nil
}

func verifyConfigReplacementFile(root *os.Root, name string, expected *secureFileIdentity) error {
	if expected == nil || expected.info == nil || expected.info.Size() < 0 || expected.info.Size() == 1<<63-1 {
		return fmt.Errorf("configuration identity is unavailable")
	}
	content, info, err := readSecureRegularFileSnapshotBounded(root, name, name, expected.info.Size()+1)
	if err != nil {
		return err
	}
	actualStat, actualOK := info.Sys().(*syscall.Stat_t)
	expectedStat, expectedOK := expected.info.Sys().(*syscall.Stat_t)
	// Rename can change ctime. Bytes, inode, owner, group, mode, size, mtime and
	// link count must still agree with the captured file on either side.
	if !expected.matches(content, info) || !info.ModTime().Equal(expected.info.ModTime()) ||
		!actualOK || !expectedOK || actualStat.Nlink != expectedStat.Nlink {
		return fmt.Errorf("configuration file identity does not match")
	}
	return nil
}

func removeConfigReplacementFile(root *os.Root, name string, expected *secureFileIdentity, ops configReplacementOps) error {
	if err := verifyConfigReplacementFile(root, name, expected); err != nil {
		return fmt.Errorf("refuse cleanup of changed configuration file: %w", err)
	}
	return ops.remove(root, name)
}
