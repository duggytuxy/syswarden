package config

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func moduleIntentFixture(t *testing.T, missing bool) (string, *moduleEditIntent) {
	t.Helper()
	root, _ := initializedUserModule(t)
	if missing {
		root = historicalOrdinaryEditRoot(t)
		user := filepath.Join(root, "modules", userModuleName)
		if err := os.Remove(user); err != nil {
			t.Fatal(err)
		}
	}
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	proposal := prepareProfileProposal(t, edit)
	stage := "." + userModuleName + ".tmp-" + strings.Repeat("a", 32)
	destination, err := openConfigDirectory(filepath.Join(root, "modules"), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = destination.Close() }()
	file, err := destination.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	content := proposal.state.content
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	intent, err := newModuleEditIntent(proposal.state, stage, newSecureFileIdentity(content, info))
	if err != nil {
		t.Fatal(err)
	}
	return root, intent
}

func writeIntentFixture(t *testing.T, root string, intent *moduleEditIntent) []byte {
	t.Helper()
	raw, err := encodeModuleEditIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeModuleFixture(filepath.Join(root, moduleEditIntentName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func exchangeIntentFixture(t *testing.T, root string, intent *moduleEditIntent, undo bool) {
	t.Helper()
	target, err := ordinaryTOMLTarget(intent.Target)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openConfigDirectory(target.directory(root), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	from, to := intent.Stage, target.name
	if undo {
		from, to = to, from
	}
	if err := renameConfigFileAt(directory, from, to, intent.Original != nil); err != nil {
		t.Fatal(err)
	}
}

func TestModuleEditIntentClassifiesRealRenameAndCleanupBoundaries(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "replace"
		if missing {
			name = "create"
		}
		for _, boundary := range []string{"prepared", "published_pending", "committed_cleanup", "committed_clean", "rolled_back_cleanup", "rolled_back_clean", "missing_stage", "altered_live", "altered_stage"} {
			t.Run(name+"/"+boundary, func(t *testing.T) {
				root, intent := moduleIntentFixture(t, missing)
				stage := filepath.Join(root, "modules", intent.Stage)
				live := filepath.Join(root, "modules", userModuleName)
				expected := boundary
				switch boundary {
				case "published_pending":
					exchangeIntentFixture(t, root, intent, false)
				case "committed_cleanup", "committed_clean":
					exchangeIntentFixture(t, root, intent, false)
					intent.State = "committed"
					if boundary == "committed_clean" && !missing {
						if err := os.Remove(stage); err != nil {
							t.Fatal(err)
						}
					}
					expected = "committed_cleanup"
				case "rolled_back_cleanup", "rolled_back_clean":
					exchangeIntentFixture(t, root, intent, false)
					exchangeIntentFixture(t, root, intent, true)
					intent.State = "rolled_back"
					if boundary == "rolled_back_clean" {
						if err := os.Remove(stage); err != nil {
							t.Fatal(err)
						}
					}
					expected = "rolled_back_cleanup"
				case "missing_stage":
					if err := os.Remove(stage); err != nil {
						t.Fatal(err)
					}
					expected = "ambiguous"
				case "altered_live":
					if err := writeModuleFixture(live, []byte("[user]\nprofile_name=\"Administrator\"\n"), 0600); err != nil {
						t.Fatal(err)
					}
					expected = "ambiguous"
				case "altered_stage":
					if err := writeModuleFixture(stage, []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
					expected = "ambiguous"
				}
				raw := writeIntentFixture(t, root, intent)
				before := intentFixtureFiles(t, root)
				observed, err := ObserveModuleEdit(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				if observed.State != expected || observed.InputsChanged || observed.Target != intent.Target || observed.ApprovalID != intent.ApprovalID || len(observed.RecordSHA256) != 64 {
					t.Fatalf("unexpected observation: %+v", observed)
				}
				after := intentFixtureFiles(t, root)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("read-only observation changed files")
				}
				actual, err := readModuleFixture(filepath.Join(root, moduleEditIntentName))
				if err != nil || !bytes.Equal(raw, actual) {
					t.Fatal("observer changed intent bytes")
				}
			})
		}
	}
}

func readModuleFixture(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}

func writeModuleFixture(path string, content []byte, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.WriteFile(filepath.Base(path), content, mode)
}

func intentFixtureFiles(t *testing.T, path string) map[string]string {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	result := make(map[string]string)
	err = fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := root.ReadFile(relative)
		if err != nil {
			return err
		}
		result[filepath.Join(path, relative)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestModuleEditIntentRejectsNoncanonicalAndInconsistentRecords(t *testing.T) {
	_, original := moduleIntentFixture(t, false)
	raw, err := encodeModuleEditIntent(original)
	if err != nil {
		t.Fatal(err)
	}
	invalidJSON := map[string][]byte{
		"newline":   append(bytes.Clone(raw), '\n'),
		"duplicate": bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"unknown":   bytes.Replace(raw, []byte(`"schema":1`), []byte(`"extra":true,"schema":1`), 1),
		"trailing":  append(bytes.Clone(raw), []byte(`{}`)...),
		"omitted":   bytes.Replace(raw, []byte(`"schema":1,`), nil, 1),
		"oversized": bytes.Repeat([]byte{' '}, int(maximumModuleEditIntentSize)+1),
	}
	for name, invalid := range invalidJSON {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeModuleEditIntent(invalid); err == nil {
				t.Fatal("accepted noncanonical record")
			}
		})
	}
	mutations := map[string]func(*moduleEditIntent){
		"state":              func(i *moduleEditIntent) { i.State = "complete" },
		"schema":             func(i *moduleEditIntent) { i.Schema = 2 },
		"root":               func(i *moduleEditIntent) { i.Root = "relative" },
		"target_ssh":         func(i *moduleEditIntent) { i.Target = "modules/05-ssh.toml" },
		"stage_traversal":    func(i *moduleEditIntent) { i.Stage = "../private" },
		"stage_wrong_target": func(i *moduleEditIntent) { i.Stage = ".config.toml.tmp-" + strings.Repeat("a", 32) },
		"approval":           func(i *moduleEditIntent) { i.ApprovalID = "yes" },
		"unsafe_dir":         func(i *moduleEditIntent) { i.RootIdentity.Mode = 0777 },
		"foreign_dir":        func(i *moduleEditIntent) { i.RootIdentity.UID ^= 1 },
		"candidate_owner":    func(i *moduleEditIntent) { i.Candidate.UID ^= 1 },
		"candidate_mode":     func(i *moduleEditIntent) { i.Candidate.Mode = 0700 },
		"candidate_link":     func(i *moduleEditIntent) { i.Candidate.Links = 2 },
		"candidate_size":     func(i *moduleEditIntent) { i.Candidate.Size = maximumUserModuleSize + 1 },
		"candidate_time":     func(i *moduleEditIntent) { i.Candidate.Modified = "now" },
		"candidate_digest":   func(i *moduleEditIntent) { i.Candidate.SHA256 = strings.Repeat("G", 64) },
		"candidate_device":   func(i *moduleEditIntent) { i.Candidate.Device ^= 1 },
		"candidate_alias":    func(i *moduleEditIntent) { i.Candidate = *i.Original },
		"missing_original":   func(i *moduleEditIntent) { i.Original = nil },
		"wrong_original":     func(i *moduleEditIntent) { i.Original.Inode++ },
		"empty_inputs":       func(i *moduleEditIntent) { i.Inputs = nil },
		"excess_inputs":      func(i *moduleEditIntent) { i.Inputs = make([]moduleEditInput, maximumModuleEditInputs+1) },
		"duplicate_input":    func(i *moduleEditIntent) { i.Inputs = append(i.Inputs, i.Inputs[0]) },
		"input_traversal":    func(i *moduleEditIntent) { i.Inputs[0].Path = "modules/../private.toml" },
		"input_device":       func(i *moduleEditIntent) { i.Inputs[0].File.Device ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed moduleEditIntent
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			invalid, err := json.Marshal(&changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeModuleEditIntent(invalid); err == nil {
				t.Fatal("accepted inconsistent record")
			}
		})
	}
}

func TestModuleEditObservationRetainsConcurrentAdministratorChanges(t *testing.T) {
	for _, change := range []string{"edit", "add", "remove", "restore_bytes_and_mtime"} {
		t.Run(change, func(t *testing.T) {
			root, intent := moduleIntentFixture(t, false)
			exchangeIntentFixture(t, root, intent, false)
			writeIntentFixture(t, root, intent)
			switch change {
			case "restore_bytes_and_mtime":
				path := filepath.Join(root, "modules", "40-integrations.toml")
				raw, err := readModuleFixture(path)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeModuleFixture(path, append(bytes.Clone(raw), '#'), 0600); err != nil {
					t.Fatal(err)
				}
				if err := writeModuleFixture(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "edit":
				if err := writeModuleFixture(filepath.Join(root, "modules", "40-integrations.toml"), []byte("# administrator changed this\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "add":
				if err := writeModuleFixture(filepath.Join(root, "modules", "zz-admin.toml"), []byte("# administrator added this\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "remove":
				if err := os.Remove(filepath.Join(root, "modules", "40-integrations.toml")); err != nil {
					t.Fatal(err)
				}
			}
			before := intentFixtureFiles(t, root)
			observed, err := ObserveModuleEdit(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if !observed.InputsChanged || observed.State != "published_pending" {
				t.Fatalf("concurrent inputs were not identified: %+v", observed)
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) {
				t.Fatal("observer rewrote administrator state")
			}
		})
	}
}

func TestModuleEditObservationRejectsUnsafeRecordAndDirectorySubstitution(t *testing.T) {
	for _, fault := range []string{"record_symlink", "record_hardlink", "record_mode", "root_replaced", "modules_replaced", "migration", "stage_symlink", "different_root"} {
		t.Run(fault, func(t *testing.T) {
			root, intent := moduleIntentFixture(t, false)
			record := filepath.Join(root, moduleEditIntentName)
			writeIntentFixture(t, root, intent)
			switch fault {
			case "record_symlink":
				if err := os.Rename(record, record+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(record+".saved", record); err != nil {
					t.Fatal(err)
				}
			case "record_hardlink":
				if err := os.Link(record, record+".link"); err != nil {
					t.Fatal(err)
				}
			case "record_mode":
				if err := os.Chmod(record, 0640); err != nil { // #nosec G302 -- Deliberately weaken only an isolated test record to verify that the private-record reader refuses group-readable evidence.
					t.Fatal(err)
				}
			case "root_replaced":
				saved := root + ".saved"
				if err := os.Rename(root, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				raw, err := readModuleFixture(filepath.Join(saved, moduleEditIntentName))
				if err != nil {
					t.Fatal(err)
				}
				if err := writeModuleFixture(record, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(saved, "modules"), filepath.Join(root, "modules")); err != nil {
					t.Fatal(err)
				}
			case "modules_replaced":
				if err := os.Rename(filepath.Join(root, "modules"), filepath.Join(root, "modules.saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "modules"), 0700); err != nil {
					t.Fatal(err)
				}
			case "migration":
				if err := writeModuleFixture(filepath.Join(root, migrationMarkerName), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "stage_symlink":
				stage := filepath.Join(root, "modules", intent.Stage)
				if err := os.Remove(stage); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(userModuleName, stage); err != nil {
					t.Fatal(err)
				}
			case "different_root":
				intent.Root = root + "-other"
				writeIntentFixture(t, root, intent)
			}
			if _, err := ObserveModuleEdit(context.Background(), root); err == nil {
				t.Fatal("accepted unsafe or substituted recovery evidence")
			}
			if _, err := os.Lstat(record); err != nil {
				t.Fatal("observer removed invalid record")
			}
		})
	}
}

func TestModuleEditObservationRequiresContextAndDoesNotCreateAbsentRecord(t *testing.T) {
	root, _ := initializedUserModule(t)
	before := intentFixtureFiles(t, root)
	observed, err := ObserveModuleEdit(context.Background(), root)
	if err != nil || observed.State != "none" {
		t.Fatalf("unexpected absent state: %+v %v", observed, err)
	}
	if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) {
		t.Fatal("absent observation wrote configuration")
	}
	var missingContext context.Context
	if _, err := ObserveModuleEdit(missingContext, root); err == nil {
		t.Fatal("missing context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveModuleEdit(ctx, root); err == nil {
		t.Fatal("canceled observation accepted")
	}
}
