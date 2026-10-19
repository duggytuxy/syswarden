//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func stateFixture(t *testing.T) *inventoryFixture {
	t.Helper()
	f := newInventoryFixture(t, includeDropIns+"Port 2222\n")
	if err := os.MkdirAll(f.path(sshStateParent), 0700); err != nil {
		t.Fatal(err)
	}
	return f
}

func fixtureOwner(t *testing.T, f *inventoryFixture) sshStateOwner {
	t.Helper()
	parent, err := openSSHStateParent(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	owner, _, err := readSSHOwner(parent, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestSSHStateProvisioningIsDurablePrivateAndIdempotent(t *testing.T) {
	f := stateFixture(t)
	before := fixtureMainImage(t, f)
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	first, err := verifySSHStateOwner(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
			t.Fatal(err)
		}
		after, err := verifySSHStateOwner(f.root, os.Geteuid())
		if err != nil || !reflect.DeepEqual(first, after) {
			t.Fatal("changed immutable receipt", err)
		}
		journal := fixtureJournal(t, f)
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
		t.Fatal("changed SSH configuration")
	}
	entries, err := os.ReadDir(f.path(sshStateParent))
	if err != nil || len(entries) != 2 {
		t.Fatal("left extra state", err)
	}
	owner := fixtureOwner(t, f)
	if owner.Directory.Mode&07777 != 0700 || owner.Marker.Mode&07777 != 0600 || first.state.mode&07777 != 0600 {
		t.Fatal("nonprivate state")
	}
	other := stateFixture(t)
	if err := provisionSSHState(other.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	if fixtureOwner(t, other).Instance == owner.Instance {
		t.Fatal("reused instance identity")
	}
}

func TestSSHStateInterruptedCreationRequiresIndependentReceipt(t *testing.T) {
	for failure := 1; failure <= 5; failure++ {
		t.Run(fmt.Sprintf("sync-%d", failure), func(t *testing.T) {
			f := stateFixture(t)
			before := fixtureMainImage(t, f)
			calls := 0
			ops := sshProvisionDefaults()
			ops.sync = func(file *os.File) error {
				calls++
				if calls == failure {
					return unix.EIO
				}
				return file.Sync()
			}
			if err := provisionSSHState(f.root, os.Geteuid(), ops); !errors.Is(err, unix.EIO) {
				t.Fatal("ignored sync failure", err)
			}
			entries, err := os.ReadDir(f.path(sshStateParent))
			if err != nil || len(entries) == 0 {
				t.Fatal("lost recovery evidence", err)
			}
			err = provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults())
			if failure < 3 {
				if err == nil {
					t.Fatal("adopted pre-receipt crash debris")
				}
				after, readErr := os.ReadDir(f.path(sshStateParent))
				if readErr != nil || len(after) != len(entries) {
					t.Fatal("changed unclaimed debris", readErr)
				}
				if journal, openErr := openSSHJournal(f.root, os.Geteuid()); openErr == nil {
					_ = journal.Close()
					t.Fatal("opened unowned state")
				}
			} else {
				if err != nil {
					t.Fatal("could not complete receipted creation", err)
				}
				if _, err := verifySSHStateOwner(f.root, os.Geteuid()); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("changed SSH input during recovery")
			}
		})
	}
}

func interruptedState(t *testing.T) (*inventoryFixture, sshStateOwner) {
	t.Helper()
	f := stateFixture(t)
	ops := sshProvisionDefaults()
	ops.rename = func(int, string, int, string, uint) error { return unix.EIO }
	if err := provisionSSHState(f.root, os.Geteuid(), ops); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	return f, fixtureOwner(t, f)
}

func TestSSHStateRecoveryNeverAdoptsReplacementsOrExtraStagingFiles(t *testing.T) {
	for _, change := range []string{"directory", "marker copy", "marker edit", "extra file", "target exists", "missing stage"} {
		t.Run(change, func(t *testing.T) {
			f, owner := interruptedState(t)
			stage := sshStateParent + "/" + sshStateStagePrefix + owner.Instance
			switch change {
			case "directory":
				if err := os.Rename(f.path(stage), f.path(stage+".saved")); err != nil {
					t.Fatal(err)
				}
				f.write(stage+"/"+sshMarkerName, string(owner.Marker.Data))
			case "marker copy":
				if err := os.Rename(f.path(stage+"/"+sshMarkerName), f.path(stage+"/saved-marker")); err != nil {
					t.Fatal(err)
				}
				f.write(stage+"/"+sshMarkerName, string(owner.Marker.Data))
			case "marker edit":
				f.write(stage+"/"+sshMarkerName, "modified")
			case "extra file":
				f.write(stage+"/operator.conf", "keep this")
			case "target exists":
				f.write(sshJournalDirectory+"/operator.conf", "keep this")
			case "missing stage":
				if err := os.Rename(f.path(stage), f.path(stage+".saved")); err != nil {
					t.Fatal(err)
				}
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("adopted changed state")
			}
			if got := fixtureOwner(t, f); !reflect.DeepEqual(got, owner) {
				t.Fatal("rewrote receipt")
			}
		})
	}
}

func TestSSHStateProvisionRefusesUnattributedAndUnsafeStorage(t *testing.T) {
	for _, kind := range []string{"existing directory", "existing file", "orphan", "receipt", "receipt symlink", "parent symlink", "parent writable", "parent missing"} {
		t.Run(kind, func(t *testing.T) {
			f := stateFixture(t)
			switch kind {
			case "existing directory":
				f.write(sshJournalDirectory+"/admin.conf", "preserve")
			case "existing file":
				f.write(sshJournalDirectory, "preserve")
			case "orphan":
				f.write(sshStateParent+"/"+sshStateStagePrefix+strings.Repeat("a", 64)+"/admin.conf", "preserve")
			case "receipt":
				f.write(sshStateParent+"/"+sshOwnerName, "unrelated")
			case "receipt symlink":
				if err := os.Symlink(f.path(MainPath), f.path(sshStateParent+"/"+sshOwnerName)); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				if err := os.Rename(f.path(sshStateParent), f.path(sshStateParent+".saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("syswarden.saved", f.path(sshStateParent)); err != nil {
					t.Fatal(err)
				}
			case "parent writable":
				if err := f.chmod(sshStateParent, 0777); err != nil {
					t.Fatal(err)
				}
			case "parent missing":
				if err := os.Remove(f.path(sshStateParent)); err != nil {
					t.Fatal(err)
				}
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("adopted unsafe state")
			}
			if journal, err := openSSHJournal(f.root, os.Geteuid()); err == nil {
				_ = journal.Close()
				t.Fatal("opened unreceipted journal")
			}
		})
	}
}

func TestSSHStateParentLockAndReplacement(t *testing.T) {
	f := stateFixture(t)
	parent, err := openSSHStateParent(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("ignored competing provisioner", err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	ops := sshProvisionDefaults()
	detached := false
	ops.sync = func(file *os.File) error {
		if !detached {
			detached = true
			if err := os.Rename(f.path(sshStateParent), f.path(sshStateParent+".saved")); err != nil {
				return err
			}
			if err := os.Mkdir(f.path(sshStateParent), 0700); err != nil {
				return err
			}
		}
		return file.Sync()
	}
	if err := provisionSSHState(f.root, os.Geteuid(), ops); err == nil {
		t.Fatal("published through a detached parent")
	}
	entries, err := os.ReadDir(f.path(sshStateParent))
	if err != nil || len(entries) != 0 {
		t.Fatal("changed replacement parent", err)
	}
}

func TestSSHStateJournalDetectsReceiptAndMarkerChanges(t *testing.T) {
	for _, kind := range []string{"receipt copy", "receipt edit", "marker copy", "marker edit", "directory mode", "directory attribute"} {
		t.Run(kind, func(t *testing.T) {
			f, _, _, _, _ := preparationFixture(t)
			journal := fixtureJournal(t, f)
			owner := fixtureOwner(t, f)
			switch kind {
			case "receipt copy":
				name := sshStateParent + "/" + sshOwnerName
				if err := os.Rename(f.path(name), f.path(name+".saved")); err != nil {
					t.Fatal(err)
				}
				f.write(name, string(journal.owner.data))
			case "receipt edit":
				f.write(sshStateParent+"/"+sshOwnerName, "changed")
			case "marker copy":
				name := sshJournalDirectory + "/" + sshMarkerName
				if err := os.Rename(f.path(name), f.path(name+".saved")); err != nil {
					t.Fatal(err)
				}
				f.write(name, string(owner.Marker.Data))
			case "marker edit":
				f.write(sshJournalDirectory+"/"+sshMarkerName, "changed")
			case "directory mode":
				if err := f.chmod(sshJournalDirectory, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory attribute":
				if err := unix.Setxattr(f.path(sshJournalDirectory), "user.changed", []byte("yes"), 0); err != nil {
					t.Fatal(err)
				}
			}
			if err := journal.recheck(); err == nil {
				t.Fatal("accepted changed ownership")
			}
			if err := journal.recheck(); err == nil {
				t.Fatal("reused poisoned ownership handle")
			}
		})
	}
}

func TestSSHOwnerRejectsNoncanonicalAndInvalidReceipts(t *testing.T) {
	f, owner := interruptedState(t)
	_ = f
	data, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, []byte("null"), append(bytes.Clone(data), '\n'), []byte(strings.Replace(string(data), "{", `{"schema":1,`, 1)), []byte(strings.Replace(string(data), `"schema"`, `"Schema"`, 1)), []byte(strings.Replace(string(data), "{", `{"extra":0,`, 1))} {
		if got, err := decodeSSHOwner(invalid, os.Geteuid()); err == nil || !reflect.DeepEqual(got, sshStateOwner{}) {
			t.Fatal("accepted malformed receipt")
		}
	}
	for _, kind := range []string{"instance", "parent", "directory", "marker", "links", "uid", "mode", "attributes", "device"} {
		t.Run(kind, func(t *testing.T) {
			copy, err := decodeSSHOwner(data, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "instance":
				copy.Instance = "../untrusted"
			case "parent":
				copy.Parent.Inode = 0
			case "directory":
				copy.Directory.Inode = copy.Parent.Inode
			case "marker":
				copy.Marker.Data = []byte("unrelated")
			case "links":
				copy.Marker.Links = 2
			case "uid":
				copy.Directory.UID++
			case "mode":
				copy.Directory.Mode |= 0040
			case "attributes":
				copy.Directory.Attributes = nil
			case "device":
				copy.Marker.Device++
			}
			encoded, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSSHOwner(encoded, os.Geteuid()); err == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}

func FuzzSSHStateOwner(f *testing.F) {
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSSHOwnerBytes {
			return
		}
		owner, err := decodeSSHOwner(data, os.Geteuid())
		if err != nil {
			if !reflect.DeepEqual(owner, sshStateOwner{}) {
				t.Fatal("partial invalid owner")
			}
			return
		}
		encoded, err := json.Marshal(owner)
		if err != nil || !bytes.Equal(encoded, data) || owner.validate(os.Geteuid()) != nil {
			t.Fatal("noncanonical owner")
		}
	})
}

func TestSSHStateStripsInheritedACLsWithoutChangingParent(t *testing.T) {
	f := stateFixture(t)
	parent := fixtureDirectory(t, f, sshStateParent)
	if err := unix.Fsetxattr(int(parent.Fd()), "system.posix_acl_default", fixtureACL(t), 0); err != nil {
		t.Fatal(err)
	}
	before, err := sshDirectoryImage(parent, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	after, err := sshDirectoryImage(parent, os.Geteuid())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("modified shared parent", err)
	}
	owner := fixtureOwner(t, f)
	image, err := verifySSHStateOwner(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	for _, attrs := range []map[string][]byte{owner.Directory.Attributes, owner.Marker.Attributes, image.attrs} {
		for name := range attrs {
			if name != "security.selinux" {
				t.Fatal("retained inherited discretionary attribute")
			}
		}
	}
}

func TestSSHStatePublicationDoesNotReplaceRacingDestination(t *testing.T) {
	f := stateFixture(t)
	ops := sshProvisionDefaults()
	ops.rename = func(oldFD int, old string, newFD int, name string, flags uint) error {
		if flags != unix.RENAME_NOREPLACE {
			t.Fatal("unsafe publication flags")
		}
		f.write(sshJournalDirectory+"/admin.conf", "preserve this")
		return unix.Renameat2(oldFD, old, newFD, name, flags)
	}
	if err := provisionSSHState(f.root, os.Geteuid(), ops); !errors.Is(err, unix.EEXIST) {
		t.Fatal("replaced racing destination", err)
	}
	root, err := os.OpenRoot(f.base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := root.ReadFile(strings.TrimPrefix(sshJournalDirectory, "/") + "/admin.conf")
	if err != nil || string(data) != "preserve this" {
		t.Fatal("lost administrator file", err)
	}
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
		t.Fatal("adopted racing destination on retry")
	}
}

func TestSSHStateOwnerFileRefusesUnsafeMetadata(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "oversized", "mode"} {
		t.Run(kind, func(t *testing.T) {
			f := stateFixture(t)
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			name := sshStateParent + "/" + sshOwnerName
			switch kind {
			case "symlink", "fifo", "directory":
				if err := os.Rename(f.path(name), f.path(name+".saved")); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(sshOwnerName+".saved", f.path(name))
				case "fifo":
					err = unix.Mkfifo(f.path(name), 0600)
				case "directory":
					err = os.Mkdir(f.path(name), 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(name), f.path(name+".alias")); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				f.write(name, strings.Repeat("x", maxSSHOwnerBytes+1))
			case "mode":
				if err := f.chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("accepted unsafe receipt")
			}
			if _, err := verifySSHStateOwner(f.root, os.Geteuid()); err == nil {
				t.Fatal("verified unsafe receipt")
			}
		})
	}
}
