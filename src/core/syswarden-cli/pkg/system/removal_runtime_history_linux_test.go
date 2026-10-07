//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"syswarden-cli/pkg/runtimehistory"
	"testing"

	"golang.org/x/sys/unix"
)

func runtimeGenesisProducerFixture(t *testing.T) map[string][]byte {
	t.Helper()
	wire, err := os.ReadFile("testdata/runtime_genesis_producer.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Files map[string][]byte `json:"files"`
	}
	if err := json.Unmarshal(wire, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Files
}

func TestRuntimeHistoryRetirementKeepsPopulatedHistory(t *testing.T) {
	for _, state := range []string{"active", "deleted"} {
		t.Run(state, func(t *testing.T) {
			parent, backups, root, files := prepareRuntimeGenesisFixture(t)
			var model runtimehistory.Model
			var anchor runtimehistory.Anchor
			if err := json.Unmarshal(files["state.json"], &model); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files["anchor.json"], &anchor); err != nil {
				t.Fatal(err)
			}
			model.Sequence = 2
			cause := "verified-ban"
			if state == "deleted" {
				cause = "verified-deletion"
			}
			model.Records = []runtimehistory.Claim{{Entry: "192.0.2.9", Generation: 1, State: state, Cause: cause, CreatedAt: model.UpdatedAt, TransitionAt: model.UpdatedAt}}
			request := runtimehistory.Intent{Entry: "192.0.2.9", Present: state == "active", Permanent: state == "active", PreparedAt: model.UpdatedAt}
			frame := struct {
				Version int                   `json:"version"`
				Anchor  runtimehistory.Anchor `json:"anchor"`
				Intent  runtimehistory.Intent `json:"intent"`
			}{1, anchor, request}
			payload, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			size := len(payload)
			if size < 1 || size > 4096-44 {
				t.Fatal("synthetic frame exceeds its fixed payload bound")
				return
			}
			slot := make([]byte, 4096)
			copy(slot, "SWINT001")
			binary.BigEndian.PutUint32(slot[8:12], uint32(size))
			copy(slot[44:], payload)
			checksum := sha256.Sum256(slot)
			copy(slot[12:44], checksum[:])
			model.RetiredIntent = fmt.Sprintf("%x", sha256.Sum256(slot))
			wire, err := json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			files["state.json"] = append(wire, '\n')
			anchor.Sequence, anchor.Digest = model.Sequence, fmt.Sprintf("%x", sha256.Sum256(files["state.json"]))
			wire, err = json.Marshal(anchor)
			if err != nil {
				t.Fatal(err)
			}
			files["anchor.json"], files["intent.slot"] = append(wire, '\n'), slot
			identities := map[string]os.FileInfo{}
			for name, wire := range files {
				if err := root.WriteFile("state/runtime-lifecycle/"+name, wire, 0600); err != nil {
					t.Fatal(err)
				}
				identities[name], err = root.Lstat("state/runtime-lifecycle/" + name)
				if err != nil {
					t.Fatal(err)
				}
			}
			backup, err := retireRuntimeHistory(parent, backups, func() error { return nil }, unix.Renameat2)
			if err != nil {
				t.Fatal(err)
			}
			relative, err := filepath.Rel(filepath.Dir(parent), backup)
			if err != nil {
				t.Fatal(err)
			}
			for name, wire := range files {
				path := filepath.Join(relative, name)
				saved, err := root.ReadFile(path)
				if err != nil || !bytes.Equal(saved, wire) {
					t.Fatal("populated history bytes changed", name, err)
				}
				info, err := root.Lstat(path)
				if err != nil || !os.SameFile(identities[name], info) {
					t.Fatal("populated history inode changed", name, err)
				}
			}
		})
	}
}

func prepareRuntimeGenesisFixture(t *testing.T) (string, string, *os.Root, map[string][]byte) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, n := range []string{"state", "state/runtime-lifecycle", "backups"} {
		if err := root.Mkdir(n, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := runtimeGenesisProducerFixture(t)
	for name, content := range files {
		if err := root.WriteFile("state/runtime-lifecycle/"+name, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(base, "state"), filepath.Join(base, "backups"), root, files
}

func TestRuntimeHistoryRetirementKeepsExactProducerBytes(t *testing.T) {
	parent, backups, root, files := prepareRuntimeGenesisFixture(t)
	original, err := root.Lstat("state/runtime-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := retireRuntimeHistory(parent, backups, func() error { return nil }, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("state/runtime-lifecycle"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("active runtime history remains", err)
	}
	relative, err := filepath.Rel(filepath.Dir(parent), backup)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := root.Lstat(relative)
	if err != nil || !os.SameFile(original, saved) || saved.Mode().Perm() != 0700 {
		t.Fatal("original private directory inode was not retained", err)
	}
	for name, content := range files {
		actual, err := root.ReadFile(filepath.Join(relative, name))
		if err != nil || !bytes.Equal(actual, content) {
			t.Fatal("original producer bytes changed", name, err)
		}
	}
	if _, err := retireRuntimeHistory(parent, backups, func() error { return nil }, unix.Renameat2); err != nil {
		t.Fatal("absent runtime history was recreated or refused", err)
	}
}

func TestRuntimeHistoryRetirementPreservesUnprovenHistory(t *testing.T) {
	for _, kind := range []string{"populated", "sequence", "unknown-field", "duplicate-key", "anchor", "intent", "padding", "extra", "missing", "symlink", "hardlink", "fifo", "mode", "lease", "destination-collision", "guard-change"} {
		t.Run(kind, func(t *testing.T) {
			parent, backups, root, files := prepareRuntimeGenesisFixture(t)
			write := func(name string, b []byte) {
				t.Helper()
				if err := root.WriteFile("state/runtime-lifecycle/"+name, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "populated":
				write("state.json", bytes.Replace(files["state.json"], []byte(`"records":[]`), []byte(`"records":[{}]`), 1))
			case "sequence":
				write("state.json", bytes.Replace(files["state.json"], []byte(`"sequence":1`), []byte(`"sequence":2`), 1))
			case "unknown-field":
				write("state.json", append([]byte(`{"custom":true,`), files["state.json"][1:]...))
			case "duplicate-key":
				write("state.json", append([]byte(`{"sequence":1,`), files["state.json"][1:]...))
			case "anchor":
				write("anchor.json", bytes.Replace(files["anchor.json"], []byte(`"sequence":1`), []byte(`"sequence":2`), 1))
			case "intent", "padding":
				changed := bytes.Clone(files["intent.slot"])
				if kind == "intent" {
					changed[80] ^= 1
				} else {
					changed[len(changed)-1] = 1
				}
				write("intent.slot", changed)
			case "extra":
				write("operator-notes.txt", []byte("Operator data must remain.\n"))
			case "missing":
				if err := root.Remove("state/runtime-lifecycle/anchor.json"); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink", "fifo":
				if err := root.WriteFile("operator-state", files["state.json"], 0600); err != nil {
					t.Fatal(err)
				}
				if err := root.Remove("state/runtime-lifecycle/state.json"); err != nil {
					t.Fatal(err)
				}
				var err error
				path := filepath.Join(parent, runtimeHistoryName, "state.json")
				if kind == "symlink" {
					err = root.Symlink("../../operator-state", "state/runtime-lifecycle/state.json")
				} else if kind == "hardlink" {
					err = root.Link("operator-state", "state/runtime-lifecycle/state.json")
				} else {
					err = syscall.Mkfifo(path, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := root.Chmod("state/runtime-lifecycle/anchor.json", 0644); err != nil {
					t.Fatal(err)
				}
			case "lease":
				file, err := root.Open("state/runtime-lifecycle")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "destination-collision":
				directory, err := openExistingPinnedServiceDirectory(filepath.Join(parent, runtimeHistoryName))
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := inspectRuntimeHistory(directory)
				directory.close()
				if err != nil {
					t.Fatal(err)
				}
				if err := root.Mkdir("backups/syswarden-retired-v1", 0700); err != nil {
					t.Fatal(err)
				}
				name := runtimeHistoryBackupName(snapshot)
				if err := root.Mkdir("backups/syswarden-retired-v1/"+name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			guard := func() error {
				calls++
				if kind == "guard-change" && calls == 2 {
					write("operator-notes.txt", []byte("Concurrent administrator data.\n"))
				}
				return nil
			}
			if _, err := retireRuntimeHistory(parent, backups, guard, unix.Renameat2); err == nil {
				t.Fatal("unproven history was retired")
			}
			if _, err := root.Lstat("state/runtime-lifecycle"); err != nil {
				t.Fatal("active history was lost", err)
			}
		})
	}
}

func TestRuntimeHistoryRetirementRestoresChangedDirectoryAfterRename(t *testing.T) {
	parent, backups, root, files := prepareRuntimeGenesisFixture(t)
	calls := 0
	rename := func(oldfd int, old string, newfd int, new string, flags uint) error {
		if err := unix.Renameat2(oldfd, old, newfd, new, flags); err != nil {
			return err
		}
		calls++
		if calls == 1 {
			return root.WriteFile("backups/syswarden-retired-v1/"+new+"/operator-notes.txt", []byte("Concurrent administrator data.\n"), 0600)
		}
		return nil
	}
	if _, err := retireRuntimeHistory(parent, backups, func() error { return nil }, rename); err == nil {
		t.Fatal("changed inventory was accepted")
	}
	for name, expected := range files {
		actual, err := root.ReadFile("state/runtime-lifecycle/" + name)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("original evidence was lost", name, err)
		}
	}
	if _, err := root.Lstat("state/runtime-lifecycle/operator-notes.txt"); err != nil {
		t.Fatal("concurrent administrator data was lost", err)
	}
}
