//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func preparationFixture(t *testing.T) (*inventoryFixture, migrationPlan, sshFileImage, *sshAnonymousStage, *sshAnonymousStage) {
	t.Helper()
	return preparationFixtureWithMain(t, includeDropIns+"PasswordAuthentication no\n")
}

func preparationFixtureWithMain(t *testing.T, content string) (*inventoryFixture, migrationPlan, sshFileImage, *sshAnonymousStage, *sshAnonymousStage) {
	t.Helper()
	f := planFixture(t, content)
	if err := os.MkdirAll(f.path(sshStateParent), 0700); err != nil {
		t.Fatal(err)
	}
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	plan := f.plan()
	before := fixtureMainImage(t, f)
	main, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh"), plan.main,
		before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = main.Close() })
	drop, err := newSSHAnonymousStage(fixtureDirectory(t, f, "/etc/ssh/sshd_config.d"), plan.candidate.Bytes(),
		before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = drop.Close() })
	return f, plan, before, main, drop
}

func fixturePreparation(t *testing.T, plan migrationPlan, before sshFileImage, main, drop *sshAnonymousStage) sshPreparation {
	t.Helper()
	record, err := prepareSSHRecord(plan, plan.summary.PlanSHA256, strings.Repeat("a", 64), before, main, drop, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func fixtureJournal(t *testing.T, f *inventoryFixture) *sshJournal {
	t.Helper()
	journal, err := openSSHJournal(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func TestSSHPreparationSurvivesReopenWithoutChangingActiveFiles(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := main.Close(); err != nil {
		t.Fatal(err)
	}
	if err := drop.Close(); err != nil {
		t.Fatal(err)
	}
	// Anonymous candidates disappear on close or process death. Their exact
	// private bytes/metadata remain in the journal for reviewed recovery, not
	// as proof that either candidate was ever published or activated.
	reopened := fixtureJournal(t, f)
	got, err := reopened.read()
	if err != nil || !reflect.DeepEqual(record, got) {
		t.Fatal("lost durable record", err)
	}
	if err := reopened.write(record); !errors.Is(err, unix.EEXIST) {
		t.Fatal("replaced immutable record", err)
	}
	current, err := collectPlanInventory(f.root, os.Geteuid())
	if err != nil || !reflect.DeepEqual(current, plan.inventory) {
		t.Fatal("preparation modified live inputs", err)
	}
	if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published policy prematurely")
	}
	st, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPreparedRecord))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("record is not private", err)
	}
}

func TestSSHJournalRefusesConcurrentAndReplacedDirectory(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if other, err := openSSHJournal(f.root, os.Geteuid()); err == nil {
		_ = other.Close()
		t.Fatal("allowed overlapping transaction")
	}
	if err := os.Rename(f.path(sshJournalDirectory), f.path(sshJournalDirectory+"-retained")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path(sshJournalDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	if err := journal.write(record); err == nil {
		t.Fatal("wrote through detached directory")
	}
	for _, path := range []string{sshJournalDirectory, sshJournalDirectory + "-retained"} {
		entries, err := os.ReadDir(f.path(path))
		want := 0
		if strings.HasSuffix(path, "-retained") {
			want = 1
		}
		if err != nil || len(entries) != want {
			t.Fatal("changed replaced directory", err)
		}
	}
}

func TestSSHJournalSyncFailureRetainsEvidenceAndPoisonsHandle(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	journal.syncDirectory = func(*os.File) error { return unix.EIO }
	if err := journal.write(record); err == nil {
		t.Fatal("claimed durability after sync failure")
	}
	if _, err := journal.read(); err == nil {
		t.Fatal("reused uncertain handle")
	}
	data, err := os.ReadFile(f.path(sshJournalDirectory + "/" + sshPreparedRecord))
	expected, marshalErr := json.Marshal(record)
	if err != nil || marshalErr != nil || !bytes.Equal(data, expected) {
		t.Fatal("discarded uncertain evidence", err, marshalErr)
	}
	if !reflect.DeepEqual(fixtureMainImage(t, f), before) {
		t.Fatal("altered active SSH input")
	}
}

func TestSSHJournalRejectsSameContentReplacementDuringSync(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	journal.syncDirectory = func(directory *os.File) error {
		root, err := os.OpenRoot(f.base)
		if err != nil {
			return err
		}
		defer root.Close()
		name := strings.TrimPrefix(sshJournalDirectory, "/") + "/" + sshPreparedRecord
		content, err := root.ReadFile(name)
		if err != nil {
			return err
		}
		if err := root.Rename(name, name+".retained"); err != nil {
			return err
		}
		if err := root.WriteFile(name, content, 0600); err != nil {
			return err
		}
		return directory.Sync()
	}
	if err := journal.write(record); err == nil {
		t.Fatal("adopted a replacement with matching bytes")
	}
	for _, suffix := range []string{"", ".retained"} {
		if _, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPreparedRecord + suffix)); err != nil {
			t.Fatal("removed unrecognized or retained evidence", err)
		}
	}
}

func TestSSHPreparationDecoderRejectsInvalidIdentityAndMetadata(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	_ = f
	for _, change := range []string{"uid", "links", "inode", "same inode", "mode", "group", "null data", "null attributes", "timestamp", "capability", "attributes"} {
		t.Run(change, func(t *testing.T) {
			record := fixturePreparation(t, plan, before, main, drop)
			switch change {
			case "uid":
				record.MainBefore.UID++
			case "links":
				record.MainAfter.Links = 1
			case "inode":
				record.MainAfter.Inode = 0
			case "same inode":
				record.MainAfter.Inode = record.MainBefore.Inode
			case "mode":
				record.MainAfter.Mode |= 0020
			case "group":
				record.MainAfter.GID++
			case "null data":
				record.MainBefore.Data = nil
			case "null attributes":
				record.MainAfter.Attributes = nil
			case "timestamp":
				record.MainAfter.Changed.Nsec = 1e9
			case "capability":
				record.DropIn.Attributes["security.capability"] = []byte{1}
			case "attributes":
				record.MainAfter.Attributes["user.unreviewed"] = []byte("extra")
			}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeSSHPreparation(data, os.Geteuid())
			if err == nil || !reflect.DeepEqual(got, sshPreparation{}) {
				t.Fatal("returned invalid or partial record")
			}
		})
	}
}

func FuzzSSHPreparationDecoder(f *testing.F) {
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte(`{"schema":1,"schema":1}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSSHJournalBytes {
			return
		}
		record, err := decodeSSHPreparation(data, os.Geteuid())
		if err != nil {
			if !reflect.DeepEqual(record, sshPreparation{}) {
				t.Fatal("error exposed partial record")
			}
			return
		}
		canonical, err := json.Marshal(record)
		if err != nil || !bytes.Equal(canonical, data) || record.validate(os.Geteuid()) != nil {
			t.Fatal("accepted noncanonical or invalid recovery data")
		}
	})
}

func TestSSHJournalRejectsUnsafeRecordAndStorageWithoutRepair(t *testing.T) {
	for _, kind := range []string{"malformed", "unknown key", "duplicate key", "alias", "whitespace", "truncated", "unsafe mode", "symlink", "hardlink", "fifo", "directory", "oversized", "unsafe parent", "missing parent"} {
		t.Run(kind, func(t *testing.T) {
			f, plan, before, main, drop := preparationFixture(t)
			record := fixturePreparation(t, plan, before, main, drop)
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			p := sshJournalDirectory + "/" + sshPreparedRecord
			f.write(p, string(encoded))
			switch kind {
			case "malformed":
				f.write(p, "not JSON")
			case "unknown key":
				f.write(p, strings.Replace(string(encoded), "{", `{"unexpected":true,`, 1))
			case "duplicate key":
				f.write(p, strings.Replace(string(encoded), "{", `{"schema":1,`, 1))
			case "alias":
				f.write(p, strings.Replace(string(encoded), `"schema"`, `"Schema"`, 1))
			case "whitespace":
				f.write(p, string(encoded)+"\n")
			case "truncated":
				f.write(p, string(encoded[:len(encoded)-1]))
			case "unsafe mode":
				if err := f.chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(p), f.path(sshJournalDirectory+"/alias")); err != nil {
					t.Fatal(err)
				}
			case "symlink", "fifo", "directory":
				if err := os.Remove(f.path(p)); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					err = os.Symlink(f.path(MainPath), f.path(p))
				case "fifo":
					err = unix.Mkfifo(f.path(p), 0600)
				case "directory":
					err = os.Mkdir(f.path(p), 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "oversized":
				f.write(p, strings.Repeat("x", maxSSHJournalBytes+1))
			case "unsafe parent":
				if err := f.chmod(sshJournalDirectory, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing parent":
				if err := os.Rename(f.path(sshJournalDirectory), f.path(sshJournalDirectory+"-saved")); err != nil {
					t.Fatal(err)
				}
			}
			journal, openErr := openSSHJournal(f.root, os.Geteuid())
			if kind == "unsafe parent" || kind == "missing parent" {
				if openErr == nil {
					_ = journal.Close()
					t.Fatal("adopted or repaired unsafe storage")
				}
				return
			}
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer journal.Close()
			if _, err := journal.read(); err == nil {
				t.Fatal("accepted unsafe record")
			}
			if err := journal.write(record); err == nil {
				t.Fatal("replaced existing evidence")
			}
			if !reflect.DeepEqual(fixtureMainImage(t, f), before) {
				t.Fatal("damaged unrelated input")
			}
		})
	}
}

func TestSSHPreparationRejectsStaleApprovalAndChangedStages(t *testing.T) {
	for _, change := range []string{"approval", "before", "main stage", "drop stage", "parser", "external", "stage closed"} {
		t.Run(change, func(t *testing.T) {
			_, plan, before, main, drop := preparationFixture(t)
			approved, parser := plan.summary.PlanSHA256, strings.Repeat("a", 64)
			switch change {
			case "approval":
				approved = strings.Repeat("b", 64)
			case "before":
				before.data = []byte("unreviewed source")
			case "main stage":
				if _, err := main.file.WriteAt([]byte("X"), 0); err != nil {
					t.Fatal(err)
				}
			case "drop stage":
				if _, err := drop.file.WriteAt([]byte("X"), 0); err != nil {
					t.Fatal(err)
				}
			case "parser":
				parser = "untrusted"
			case "external":
				plan.intent.Owner = "external"
			case "stage closed":
				if err := main.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := prepareSSHRecord(plan, approved, parser, before, main, drop, os.Geteuid()); err == nil {
				t.Fatal("authorized stale or invalid preparation")
			}
		})
	}
}

func TestSSHPreparationRecordOwnsItsPrivateBuffers(t *testing.T) {
	_, plan, before, main, drop := preparationFixture(t)
	a := fixturePreparation(t, plan, before, main, drop)
	b := fixturePreparation(t, plan, before, main, drop)
	if a.Transaction == b.Transaction {
		t.Fatal("reused transaction identity")
	}
	a.MainBefore.Data[0] ^= 1
	a.MainBefore.Attributes["user.extra"] = []byte("private")
	if !bytes.Equal(b.MainBefore.Data, before.data) || reflect.DeepEqual(a.MainBefore.Attributes, before.attrs) {
		t.Fatal("aliased retained data")
	}
}
