//go:build linux

package logger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"syswarden-core/fileorigin"
)

func coreLogTestRead(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Base(path))
}

func coreLogTestWrite(path string, content []byte, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFile(filepath.Base(path), content, mode)
}

func coreLogTestOpen(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(filepath.Base(path))
}

func coreLogTestChmod(directory string, mode os.FileMode) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Chmod(".", mode)
}

func privateCoreLogTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := coreLogTestChmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func newTestCoreLog(t *testing.T, limit int64) (*CoreProcessLog, string) {
	t.Helper()
	path := filepath.Join(privateCoreLogTestDirectory(t), "core.log")
	writer, err := openCoreProcessLogWithLimit(path, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	return writer, path
}

func writeTestCoreLog(t *testing.T, w *CoreProcessLog, record string) {
	t.Helper()
	if n, err := w.Write([]byte(record)); err != nil || n != len(record) {
		t.Fatalf("write=%d error=%v", n, err)
	}
}

func inspectTestCoreLog(t *testing.T, path, want string) {
	t.Helper()
	data, err := coreLogTestRead(path)
	if err != nil || string(data) != want {
		t.Fatalf("content=%q error=%v want=%q", data, err, want)
	}
	file, err := coreLogTestOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if owned, err := fileorigin.HasLogOrigin(file, fileorigin.CoreLog); err != nil || !owned {
		t.Fatal("missing origin", owned, err)
	}
}

func TestCoreProcessLogBoundedRotationAndRestart(t *testing.T) {
	w, path := newTestCoreLog(t, 8)
	writeTestCoreLog(t, w, "one\ntwo\n")
	if _, err := os.Lstat(path + ".1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rotated before reaching limit", err)
	}
	writeTestCoreLog(t, w, "new\n")
	inspectTestCoreLog(t, path, "new\n")
	inspectTestCoreLog(t, path+".1", "one\ntwo\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err := openCoreProcessLogWithLimit(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	writeTestCoreLog(t, w, "end\n")
	writeTestCoreLog(t, w, "last\n")
	inspectTestCoreLog(t, path, "last\n")
	inspectTestCoreLog(t, path+".1", "new\nend\n")
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("unbounded inventory: %v", entries)
	}
}

func TestCoreProcessLogConcurrentWritesStayBounded(t *testing.T) {
	w, path := newTestCoreLog(t, 128)
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 50; j++ {
				if _, err := w.Write([]byte("record\n")); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	group.Wait()
	for _, name := range []string{path, path + ".1"} {
		data, err := coreLogTestRead(name)
		if err != nil || len(data) > 128 || !bytes.Equal(data, bytes.Repeat([]byte("record\n"), len(data)/7)) {
			t.Fatal("incomplete or oversized output", len(data), err)
		}
	}
}

func TestCoreProcessLogCompactsOwnedOversizedFiles(t *testing.T) {
	for _, suffix := range []string{"", ".1"} {
		t.Run("generation"+suffix, func(t *testing.T) {
			path := filepath.Join(privateCoreLogTestDirectory(t), "core.log")
			f, err := openAppendProductLog(path+suffix, fileorigin.CoreLog)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write([]byte("discarded prefix\nretained\nend\npartial"))
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			w, err := openCoreProcessLogWithLimit(path, 24)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			inspectTestCoreLog(t, path+suffix, "retained\nend\n")
			if _, err := os.Lstat(filepath.Join(filepath.Dir(path), ".core.log.tail")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("staging residue", err)
			}
		})
	}
}

func TestCoreProcessLogBoundsSparseMultiGigabyteUpgrade(t *testing.T) {
	path := filepath.Join(privateCoreLogTestDirectory(t), "core.log")
	file, err := openAppendProductLog(path, fileorigin.CoreLog)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse allocation exercises the real upgrade size without consuming
	// gigabytes of local storage. The writer reads only one bounded tail.
	if err := file.Truncate(7 << 30); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("\nlast complete record\n")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	w, err := OpenCoreProcessLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	inspectTestCoreLog(t, path, "last complete record\n")
}

func TestCoreProcessLogPreservesUnmarkedFiles(t *testing.T) {
	for _, test := range []struct{ name, content string }{
		{"core.log", "legacy oversized record\n"}, {"core.log.1", "old\n"}, {".core.log.tail", "staged\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateCoreLogTestDirectory(t)
			path := filepath.Join(dir, test.name)
			if err := coreLogTestWrite(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			if w, err := openCoreProcessLogWithLimit(filepath.Join(dir, "core.log"), 8); err == nil {
				_ = w.Close()
				t.Fatal("accepted unmarked retention input")
			}
			after, _ := os.Lstat(path)
			data, _ := coreLogTestRead(path)
			if !os.SameFile(before, after) || string(data) != test.content {
				t.Fatal("changed unmarked input")
			}
		})
	}
	path := filepath.Join(privateCoreLogTestDirectory(t), "core.log")
	if err := coreLogTestWrite(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := openCoreProcessLogWithLimit(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	writeTestCoreLog(t, w, "new\n")
	if _, err := w.Write([]byte("next\n")); err == nil {
		t.Fatal("rotated an unmarked inode")
	}
	if owned, err := fileorigin.HasLogOrigin(w.file, fileorigin.CoreLog); owned || err != nil {
		t.Fatal("adopted old inode", err)
	}
	data, _ := coreLogTestRead(path)
	if string(data) != "old\nnew\n" {
		t.Fatal("unbounded legacy append", string(data))
	}
}

func TestCoreProcessLogRejectsUnsafeLeaves(t *testing.T) {
	for _, name := range []string{"core.log", "core.log.1", ".core.log.tail"} {
		for _, attack := range []string{"symlink", "hardlink", "writable", "fifo", "copied-marker"} {
			t.Run(name+"/"+attack, func(t *testing.T) {
				dir := privateCoreLogTestDirectory(t)
				path := filepath.Join(dir, name)
				sentinel := filepath.Join(privateCoreLogTestDirectory(t), "sentinel")
				if err := coreLogTestWrite(sentinel, []byte("preserve\n"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch attack {
				case "symlink":
					err = os.Symlink(sentinel, path)
				case "hardlink":
					err = os.Link(sentinel, path)
				case "writable":
					err = coreLogTestWrite(path, []byte("unsafe\n"), 0666)
				case "fifo":
					err = unix.Mkfifo(path, 0600)
				case "copied-marker":
					err = coreLogTestWrite(path, []byte("unsafe\n"), 0600)
					if err == nil {
						err = unix.Setxattr(path, fileorigin.LogAttribute, []byte("SYSWARDEN_LOG_ORIGIN_V1\nkind=core\ninode=1\nbirth_sec=0\nbirth_nsec=0\n"), 0)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if w, err := openCoreProcessLogWithLimit(filepath.Join(dir, "core.log"), 32); err == nil {
					_ = w.Close()
					t.Fatal("accepted unsafe file")
				}
				data, _ := coreLogTestRead(sentinel)
				if string(data) != "preserve\n" {
					t.Fatal("modified unrelated file")
				}
			})
		}
	}
}

func TestCoreProcessLogRefusesReplacementAndSecondWriter(t *testing.T) {
	w, path := newTestCoreLog(t, 8)
	if other, err := openCoreProcessLogWithLimit(path, 8); err == nil {
		_ = other.Close()
		t.Fatal("accepted second writer")
	}
	writeTestCoreLog(t, w, "old\n")
	if err := os.Rename(path, path+".admin"); err != nil {
		t.Fatal(err)
	}
	if err := coreLogTestWrite(path, []byte("private\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("new\n")); err == nil {
		t.Fatal("wrote after path replacement")
	}
	data, _ := coreLogTestRead(path)
	if string(data) != "private\n" {
		t.Fatal("modified replacement")
	}
	old, _ := coreLogTestRead(path + ".admin")
	if string(old) != "old\n" {
		t.Fatal("continued writing the renamed inode")
	}
}

func TestCoreProcessLogRefusesLateUnprovenRotationTarget(t *testing.T) {
	w, path := newTestCoreLog(t, 8)
	writeTestCoreLog(t, w, "old\nend\n")
	if err := coreLogTestWrite(path+".1", []byte("keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("new\n")); err == nil {
		t.Fatal("overwrote an unproven retained file")
	}
	inspectTestCoreLog(t, path, "old\nend\n")
	data, err := coreLogTestRead(path + ".1")
	if err != nil || string(data) != "keep\n" {
		t.Fatal("changed administrator data", err)
	}
}

func TestCoreProcessLogWriteFailureStopsTheSink(t *testing.T) {
	w, path := newTestCoreLog(t, 32)
	writeTestCoreLog(t, w, "old\n")
	if err := w.file.Close(); err != nil {
		t.Fatal(err)
	}
	// A read-only descriptor keeps the same inode and passes attestation, but
	// causes a real kernel write failure after the preflight has completed.
	var err error
	w.file, err = coreLogTestOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write([]byte("new\n")); n != 0 || err == nil {
		t.Fatal("write failure was hidden", n, err)
	}
	if w.failure == nil {
		t.Fatal("uncertain sink was not disabled")
	}
	if _, err := w.Write([]byte("next\n")); err != w.failure {
		t.Fatal("sink retried after failure", err)
	}
	inspectTestCoreLog(t, path, "old\n")
}

func TestCoreProcessLogRestartRecoversBoundedProductStage(t *testing.T) {
	w, path := newTestCoreLog(t, 8)
	writeTestCoreLog(t, w, "keep\n")
	stage, err := w.open(w.stagingName(), true)
	if err != nil {
		t.Fatal(err)
	}
	input, err := w.tailInput(w.file, w.name)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Fsetxattr(int(stage.Fd()), coreTailInputAttribute, input, unix.XATTR_CREATE); err != nil {
		t.Fatal(err)
	}
	_, _ = stage.Write([]byte("part"))
	_ = stage.Close()
	_ = w.Close()
	w, err = openCoreProcessLogWithLimit(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	inspectTestCoreLog(t, path, "keep\n")
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), ".core.log.tail")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("proven redundant staging inode retained", err)
	}
}

func TestCoreProcessLogPreservesUnboundOrChangedTailSource(t *testing.T) {
	for _, change := range []string{"unbound", "missing", "changed"} {
		t.Run(change, func(t *testing.T) {
			w, path := newTestCoreLog(t, 32)
			writeTestCoreLog(t, w, "keep\n")
			stage, err := w.open(w.stagingName(), true)
			if err != nil {
				t.Fatal(err)
			}
			input, err := w.tailInput(w.file, w.name)
			if err != nil {
				t.Fatal(err)
			}
			if change != "unbound" {
				if err := unix.Fsetxattr(int(stage.Fd()), coreTailInputAttribute, input, unix.XATTR_CREATE); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stage.Write([]byte("tail\n")); err != nil {
				t.Fatal(err)
			}
			_ = stage.Close()
			if change == "changed" {
				writeTestCoreLog(t, w, "later\n")
			}
			_ = w.Close()
			if change == "missing" {
				if err := os.Rename(path, path+".private"); err != nil {
					t.Fatal(err)
				}
			}
			if next, err := openCoreProcessLogWithLimit(path, 32); err == nil {
				_ = next.Close()
				t.Fatal("retired an unproven tail")
			}
			inspectTestCoreLog(t, filepath.Join(filepath.Dir(path), ".core.log.tail"), "tail\n")
		})
	}
}

func TestCoreProcessLogRestartAfterActiveRename(t *testing.T) {
	w, path := newTestCoreLog(t, 8)
	writeTestCoreLog(t, w, "keep\n")
	_ = w.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	w, err := openCoreProcessLogWithLimit(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	writeTestCoreLog(t, w, "new\n")
	inspectTestCoreLog(t, path, "new\n")
	inspectTestCoreLog(t, path+".1", "keep\n")
}

func TestCoreProcessOutputRetainsJournalAndReportsFailureOnce(t *testing.T) {
	w, path := newTestCoreLog(t, 4)
	var journal, diagnostics bytes.Buffer
	output := CoreProcessOutput(&journal, w, &diagnostics)
	for _, line := range []string{"too long\n", "next\n"} {
		if n, err := output.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatal(n, err)
		}
	}
	if journal.String() != "too long\nnext\n" || strings.Count(diagnostics.String(), "File logging unavailable") != 1 {
		t.Fatal(journal.String(), diagnostics.String())
	}
	data, _ := coreLogTestRead(path)
	if len(data) != 0 {
		t.Fatal("oversized record reached disk")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(nil); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestCoreProcessLogRejectsUnsafeParent(t *testing.T) {
	for _, attack := range []string{"symlink", "mode", "changed"} {
		t.Run(attack, func(t *testing.T) {
			base := privateCoreLogTestDirectory(t)
			dir := filepath.Join(base, "logs")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "core.log")
			if attack == "symlink" {
				if err := os.Symlink(dir, filepath.Join(base, "linked")); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(base, "linked", "core.log")
			} else if attack == "mode" {
				if err := coreLogTestChmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			w, err := openCoreProcessLogWithLimit(path, 8)
			if attack != "changed" {
				if err == nil {
					_ = w.Close()
					t.Fatal("accepted unsafe parent")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if err := os.Rename(dir, dir+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("no\n")); err == nil {
				t.Fatal("wrote through replaced parent")
			}
		})
	}
}

func TestCoreProcessLogInputBounds(t *testing.T) {
	for _, limit := range []int64{0, -1, coreProcessLogLimit + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			if w, err := openCoreProcessLogWithLimit(filepath.Join(privateCoreLogTestDirectory(t), "core.log"), limit); err == nil {
				_ = w.Close()
				t.Fatal("accepted invalid bound")
			}
		})
	}
	for _, path := range []string{"", "relative", "/var/log/../core.log", "/var/log/bad\nname"} {
		if w, err := OpenCoreProcessLog(path); err == nil {
			_ = w.Close()
			t.Fatal("accepted invalid path")
		}
	}
}

var _ io.WriteCloser = (*CoreProcessLog)(nil)
