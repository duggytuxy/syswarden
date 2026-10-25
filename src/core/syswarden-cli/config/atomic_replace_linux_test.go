//go:build linux

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const atomicReplacementName = "operator.toml"

func atomicReplacementFixture(t *testing.T, present bool) (string, *secureFileIdentity) {
	t.Helper()
	directory := t.TempDir()
	if !present {
		return directory, nil
	}
	if err := os.WriteFile(filepath.Join(directory, atomicReplacementName), []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, identity, err := readSecureRegularFileIdentity(root, atomicReplacementName, atomicReplacementName)
	if err != nil {
		t.Fatal(err)
	}
	return directory, identity
}

func assertAtomicReplacementOriginal(t *testing.T, directory string, expected *secureFileIdentity) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if expected == nil {
		if _, err := root.Lstat(atomicReplacementName); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("originally absent target exists: %v", err)
		}
	} else if err := verifyConfigReplacementFile(root, atomicReplacementName, expected); err != nil {
		t.Fatalf("original inode, content or metadata changed: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != atomicReplacementName {
			t.Fatalf("unexpected retained stage %q", entry.Name())
		}
	}
}

func TestConfigAtomicExchangeNeverRemovesLiveName(t *testing.T) {
	directory, expected := atomicReplacementFixture(t, true)
	path := filepath.Join(directory, atomicReplacementName)
	done := make(chan struct{})
	failures := make(chan error, 1)
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			content, err := os.ReadFile(path) // #nosec G304 -- fixed filename inside the private test directory
			if err != nil || (string(content) != "original\n" && string(content) != "candidate\n") {
				select {
				case failures <- fmt.Errorf("reader observed missing or partial configuration: %q: %v", content, err):
				default:
				}
				return
			}
		}
	}()
	defer func() { close(done); reader.Wait() }()
	for index := 0; index < 24; index++ {
		content := []byte("candidate\n")
		if index%2 != 0 {
			content = []byte("original\n")
		}
		prePublish := func() error {
			root, err := os.OpenRoot(directory)
			if err != nil {
				return err
			}
			defer func() { _ = root.Close() }()
			return verifyConfigReplacementFile(root, atomicReplacementName, expected)
		}
		if err := replaceSecureConfigFile(directory, atomicReplacementName, content, expected, nil, prePublish, nil); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		_, expected, err = readSecureRegularFileIdentity(root, atomicReplacementName, atomicReplacementName)
		_ = root.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
}

func TestConfigAtomicExchangeCallbackOrderAndRollback(t *testing.T) {
	for _, present := range []bool{true, false} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			directory, expected := atomicReplacementFixture(t, present)
			failure := errors.New("post-publication refusal")
			var order []string
			err := replaceSecureConfigFile(directory, atomicReplacementName, []byte("candidate\n"), expected,
				func() error { order = append(order, "snapshot"); return nil },
				func() error { order = append(order, "before"); return nil },
				func() error { order = append(order, "after"); return failure })
			if !errors.Is(err, failure) {
				t.Fatalf("rollback lost callback failure: %v", err)
			}
			if !reflect.DeepEqual(order, []string{"snapshot", "before", "snapshot", "after"}) {
				t.Fatalf("callback order = %v", order)
			}
			assertAtomicReplacementOriginal(t, directory, expected)
		})
	}
}

func TestConfigAtomicExchangeSyncAndCleanupFailures(t *testing.T) {
	for _, scenario := range []string{"publication-sync", "cleanup-remove", "cleanup-sync", "rollback-sync", "prepublication-cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			directory, expected := atomicReplacementFixture(t, true)
			failure := errors.New("injected filesystem failure")
			refusal := errors.New("injected callback refusal")
			ops := defaultConfigReplacementOps()
			syncs, removes := 0, 0
			ops.sync = func(root *os.Root) error {
				syncs++
				if (scenario == "publication-sync" && syncs == 1) ||
					(scenario == "cleanup-sync" && syncs == 2) ||
					(scenario == "rollback-sync" && syncs == 2) {
					return failure
				}
				return syncRootDirectory(root)
			}
			ops.remove = func(root *os.Root, name string) error {
				removes++
				if (scenario == "cleanup-remove" || scenario == "prepublication-cleanup") && removes == 1 {
					return failure
				}
				return root.Remove(name)
			}
			var before, after func() error
			if scenario == "rollback-sync" {
				after = func() error { return refusal }
			}
			if scenario == "prepublication-cleanup" {
				before = func() error { return refusal }
			}
			err := replaceSecureConfigFileUsing(directory, atomicReplacementName, []byte("candidate\n"), expected, before, nil, after, ops)
			if !errors.Is(err, failure) {
				t.Fatalf("filesystem failure was hidden: %v", err)
			}
			if (before != nil || after != nil) && !errors.Is(err, refusal) {
				t.Fatalf("callback failure was hidden: %v", err)
			}
			if scenario == "publication-sync" || scenario == "cleanup-remove" {
				assertAtomicReplacementOriginal(t, directory, expected)
				return
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if scenario == "cleanup-sync" {
				content, err := root.ReadFile(atomicReplacementName)
				if err != nil || string(content) != "candidate\n" {
					t.Fatal("committed candidate lost after cleanup sync failure", err)
				}
			} else if err := verifyConfigReplacementFile(root, atomicReplacementName, expected); err != nil {
				t.Fatal("failed cleanup displaced original", err)
			}
		})
	}
}

func TestConfigAtomicExchangeRefusesUnsupportedOperations(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			directory, expected := atomicReplacementFixture(t, present)
			ops := defaultConfigReplacementOps()
			ops.rename = func(_ *os.Root, _, _ string, exchange bool) error {
				if exchange != present {
					t.Fatal("wrong rename operation selected")
				}
				return unix.EOPNOTSUPP
			}
			if err := replaceSecureConfigFileUsing(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, nil, nil, ops); !errors.Is(err, unix.EOPNOTSUPP) {
				t.Fatalf("unsupported operation did not refuse: %v", err)
			}
			assertAtomicReplacementOriginal(t, directory, expected)
		})
	}
}

func TestConfigAtomicExchangePreservesLateNoReplaceConflict(t *testing.T) {
	directory, expected := atomicReplacementFixture(t, false)
	ops := defaultConfigReplacementOps()
	var winner os.FileInfo
	ops.rename = func(root *os.Root, from, to string, exchange bool) error {
		if exchange {
			t.Fatal("absent target used exchange")
		}
		if err := root.WriteFile(to, []byte("administrator\n"), 0600); err != nil {
			return err
		}
		var err error
		winner, err = root.Lstat(to)
		if err != nil {
			return err
		}
		return renameConfigFileAt(root, from, to, exchange)
	}
	if err := replaceSecureConfigFileUsing(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, nil, nil, ops); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("late target did not refuse: %v", err)
	}
	after, err := os.Lstat(filepath.Join(directory, atomicReplacementName))
	if err != nil || winner == nil || !os.SameFile(winner, after) {
		t.Fatal("concurrent destination was displaced", err)
	}
}

func TestConfigAtomicExchangePreservesAmbiguousPostPublicationFiles(t *testing.T) {
	for _, mutation := range []string{"source-bytes", "source-inode", "source-mode", "source-mtime", "candidate-bytes", "candidate-inode", "candidate-symlink"} {
		t.Run(mutation, func(t *testing.T) {
			directory, expected := atomicReplacementFixture(t, true)
			var changed os.FileInfo
			var changedName string
			after := func() error {
				entries, err := os.ReadDir(directory)
				if err != nil {
					return err
				}
				changedName = atomicReplacementName
				if strings.HasPrefix(mutation, "source-") {
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), "."+atomicReplacementName+".tmp-") {
							changedName = entry.Name()
						}
					}
				}
				path := filepath.Join(directory, changedName)
				switch mutation {
				case "source-mode":
					err = os.Chmod(path, 0640) // #nosec G302 -- deliberate safe-mode drift fixture
				case "source-mtime":
					err = os.Chtimes(path, time.Unix(10, 0), time.Unix(10, 0))
				case "source-inode", "candidate-inode", "candidate-symlink":
					if err = os.Rename(path, path+".retained"); err == nil {
						if mutation == "candidate-symlink" {
							err = os.Symlink(path+".retained", path)
						} else {
							content := []byte("candidate\n")
							if mutation == "source-inode" {
								content = []byte("original\n")
							}
							err = os.WriteFile(path, content, 0600)
						}
					}
				default:
					err = os.WriteFile(path, []byte("concurrent edit\n"), 0600)
				}
				if err != nil {
					return err
				}
				changed, err = os.Lstat(path)
				return err
			}
			if err := replaceSecureConfigFile(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, nil, after); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("ambiguous pair did not refuse: %v", err)
			}
			observed, err := os.Lstat(filepath.Join(directory, changedName))
			if err != nil || changed == nil || !os.SameFile(observed, changed) {
				t.Fatal("concurrent inode was deleted or overwritten", err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) < 2 {
				t.Fatal("ambiguous original/candidate pair was cleaned", err)
			}
		})
	}
}

func TestConfigAtomicExchangePreservesSymlinkConflictBeforePublication(t *testing.T) {
	directory, expected := atomicReplacementFixture(t, true)
	path := filepath.Join(directory, atomicReplacementName)
	victim := filepath.Join(directory, "administrator.toml")
	if err := os.WriteFile(victim, []byte("administrator\n"), 0600); err != nil {
		t.Fatal(err)
	}
	victimInfo, err := os.Lstat(victim)
	if err != nil {
		t.Fatal(err)
	}
	before := func() error {
		if err := os.Rename(path, path+".retained"); err != nil {
			return err
		}
		return os.Symlink(victim, path)
	}
	if err := replaceSecureConfigFile(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, before, nil); err == nil {
		t.Fatal("symlink publication conflict was accepted")
	}
	link, err := os.Readlink(path)
	if err != nil || link != victim {
		t.Fatal("concurrent symlink changed", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := verifyConfigReplacementFile(root, atomicReplacementName+".retained", expected); err != nil {
		t.Fatal("concurrent retained original changed", err)
	}
	content, err := root.ReadFile("administrator.toml")
	after, statErr := root.Lstat("administrator.toml")
	if err != nil || statErr != nil || !os.SameFile(victimInfo, after) || string(content) != "administrator\n" {
		t.Fatal("symlink victim changed", err, statErr)
	}
}

func TestConfigAtomicExchangePreservesUnexpectedDisplacedInode(t *testing.T) {
	for _, boundary := range []string{"before-exchange", "after-exchange"} {
		t.Run(boundary, func(t *testing.T) {
			directory, expected := atomicReplacementFixture(t, true)
			ops := defaultConfigReplacementOps()
			var stage string
			var unexpected os.FileInfo
			ops.rename = func(root *os.Root, from, to string, exchange bool) error {
				if !exchange {
					t.Fatal("existing target did not use exchange")
				}
				stage = from
				replace := func(name string) error {
					if err := root.Rename(name, "retained-original"); err != nil {
						return err
					}
					if err := root.WriteFile(name, []byte("original\n"), 0600); err != nil {
						return err
					}
					var err error
					unexpected, err = root.Lstat(name)
					return err
				}
				if boundary == "before-exchange" {
					if err := replace(to); err != nil {
						return err
					}
				}
				if err := renameConfigFileAt(root, from, to, exchange); err != nil {
					return err
				}
				if boundary == "after-exchange" {
					return replace(from)
				}
				return nil
			}
			if err := replaceSecureConfigFileUsing(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, nil, nil, ops); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("unexpected original inode did not refuse: %v", err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if err := verifyConfigReplacementFile(root, "retained-original", expected); err != nil {
				t.Fatal("original source inode lost", err)
			}
			observed, err := root.Lstat(stage)
			if err != nil || unexpected == nil || !os.SameFile(unexpected, observed) {
				t.Fatal("unexpected displaced inode was cleaned or overwritten", err)
			}
			content, err := root.ReadFile(atomicReplacementName)
			if err != nil || string(content) != "candidate\n" {
				t.Fatal("ambiguous candidate was overwritten", err)
			}
		})
	}
}

func TestConfigAtomicExchangeRetainsPairWhenRollbackFails(t *testing.T) {
	directory, expected := atomicReplacementFixture(t, true)
	failure := errors.New("rollback operation failed")
	refusal := errors.New("publication callback refused")
	ops := defaultConfigReplacementOps()
	var stage string
	renames := 0
	ops.rename = func(root *os.Root, from, to string, exchange bool) error {
		renames++
		if renames == 2 {
			return failure
		}
		stage = from
		return renameConfigFileAt(root, from, to, exchange)
	}
	err := replaceSecureConfigFileUsing(directory, atomicReplacementName, []byte("candidate\n"), expected, nil, nil, func() error { return refusal }, ops)
	if !errors.Is(err, failure) || !errors.Is(err, refusal) {
		t.Fatalf("rollback or callback error was hidden: %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := verifyConfigReplacementFile(root, stage, expected); err != nil {
		t.Fatal("original recovery inode lost", err)
	}
	content, err := root.ReadFile(atomicReplacementName)
	if err != nil || string(content) != "candidate\n" {
		t.Fatal("candidate recovery bytes lost", err)
	}
}
