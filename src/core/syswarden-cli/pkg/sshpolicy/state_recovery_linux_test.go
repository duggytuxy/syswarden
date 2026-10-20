//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func orphanFixture(t *testing.T, marker bool) (*inventoryFixture, string) {
	t.Helper()
	f := stateFixture(t)
	instance := strings.Repeat("a", 64)
	name := sshStateParent + "/" + sshStateStagePrefix + instance
	if err := os.Mkdir(f.path(name), 0700); err != nil {
		t.Fatal(err)
	}
	if marker {
		f.write(name+"/"+sshMarkerName, string(sshMarkerBytes(instance)))
	}
	return f, instance
}

func orphanPlan(t *testing.T, f *inventoryFixture, instance string) sshRetirementInspection {
	t.Helper()
	inspection, err := inspectSSHStateRetirement(f.root, os.Geteuid(), instance)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func TestSSHOrphanRetirementRetainsExactPrivateFilesWithoutAdoption(t *testing.T) {
	for _, marker := range []bool{false, true} {
		t.Run(fmt.Sprintf("marker-%t", marker), func(t *testing.T) {
			f, instance := orphanFixture(t, marker)
			main := fixtureMainImage(t, f)
			f.write(sshStateParent+"/administrator.conf", "preserve unrelated settings")
			inspection := orphanPlan(t, f, instance)
			if inspection.receipt != nil || inspection.retired {
				t.Fatal("inspection created state")
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("automatically adopted orphan")
			}
			if err := retireSSHState(f.root, os.Geteuid(), instance, "", sshProvisionDefaults()); err == nil {
				t.Fatal("retired without approval")
			}
			for range 2 {
				if err := retireSSHState(f.root, os.Geteuid(), instance, inspection.record.digest(), sshProvisionDefaults()); err != nil {
					t.Fatal(err)
				}
				current := orphanPlan(t, f, instance)
				if !current.retired || current.receipt == nil || !reflect.DeepEqual(inspection.record, current.record) {
					t.Fatal("retirement changed original evidence")
				}
			}
			if _, err := verifySSHStateOwner(f.root, os.Geteuid()); err == nil {
				t.Fatal("retirement granted active ownership")
			}
			if !reflect.DeepEqual(main, fixtureMainImage(t, f)) {
				t.Fatal("modified SSH configuration")
			}
			if data, err := os.ReadFile(f.path(sshStateParent + "/administrator.conf")); err != nil || string(data) != "preserve unrelated settings" {
				t.Fatal("modified administrator state", err)
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
				t.Fatal("could not provision new independent state", err)
			}
			owner := fixtureOwner(t, f)
			if owner.Directory.Inode == inspection.record.Directory.Inode || owner.Instance == instance {
				t.Fatal("reused orphan as active state")
			}
			parent := fixtureDirectory(t, f, sshStateParent)
			if err := attestSSHOrphan(parent, inspection.record, os.Geteuid(), true); err != nil {
				t.Fatal("lost private retained directory", err)
			}
		})
	}
}

func TestSSHOrphanRetirementRecoversActualPreReceiptFailures(t *testing.T) {
	for failure := 1; failure <= 2; failure++ {
		t.Run(fmt.Sprintf("provision-sync-%d", failure), func(t *testing.T) {
			f := stateFixture(t)
			ops := sshProvisionDefaults()
			calls := 0
			ops.sync = func(file *os.File) error {
				calls++
				if calls == failure {
					return unix.EIO
				}
				return file.Sync()
			}
			if err := provisionSSHState(f.root, os.Geteuid(), ops); !errors.Is(err, unix.EIO) {
				t.Fatal("missing injected creation failure", err)
			}
			entries, err := os.ReadDir(f.path(sshStateParent))
			if err != nil || len(entries) != 1 {
				t.Fatal("unexpected crash residue", err)
			}
			instance := strings.TrimPrefix(entries[0].Name(), sshStateStagePrefix)
			plan := orphanPlan(t, f, instance)
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHOrphanRetirementPreservesAndResumesUncertainBoundaries(t *testing.T) {
	for _, failure := range []string{"receipt-sync", "receipt-resync", "rename", "retirement-sync"} {
		t.Run(failure, func(t *testing.T) {
			f, instance := orphanFixture(t, true)
			plan := orphanPlan(t, f, instance)
			ops := sshProvisionDefaults()
			calls := 0
			ops.sync = func(file *os.File) error {
				calls++
				if (failure == "receipt-sync" && calls == 1) ||
					(failure == "receipt-resync" && calls == 2) || (failure == "retirement-sync" && calls == 3) {
					return unix.EIO
				}
				return file.Sync()
			}
			if failure == "rename" {
				ops.rename = func(int, string, int, string, uint) error { return unix.EIO }
			}
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), ops); !errors.Is(err, unix.EIO) {
				t.Fatal("claimed success after uncertain operation", err)
			}
			resume := orphanPlan(t, f, instance)
			if resume.receipt == nil || !reflect.DeepEqual(plan.record, resume.record) {
				t.Fatal("lost durable operation evidence")
			}
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err != nil {
				t.Fatal("failed bounded recovery", err)
			}
			if !orphanPlan(t, f, instance).retired {
				t.Fatal("did not finish retirement")
			}
		})
	}
}

func TestSSHOrphanRetirementRefusesChangedAndUnrelatedEvidence(t *testing.T) {
	for _, kind := range []string{"directory", "directory-mode", "directory-attribute", "marker", "marker-copy",
		"extra-child", "new-marker", "other-orphan", "fixed-state", "owner", "destination", "parent", "configuration", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			f, instance := orphanFixture(t, kind != "new-marker")
			plan := orphanPlan(t, f, instance)
			stage := sshStateParent + "/" + sshStateStagePrefix + instance
			marker := stage + "/" + sshMarkerName
			switch kind {
			case "directory":
				if err := os.Rename(f.path(stage), f.path(stage+".kept")); err != nil {
					t.Fatal(err)
				}
				f.write(marker, string(sshMarkerBytes(instance)))
			case "directory-mode":
				if err := f.chmod(stage, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-attribute":
				dir := fixtureDirectory(t, f, stage)
				if err := unix.Fsetxattr(int(dir.Fd()), "user.operator", []byte("preserve"), 0); err != nil {
					t.Fatal(err)
				}
			case "marker":
				f.write(marker, "changed marker")
			case "marker-copy":
				if err := os.Rename(f.path(marker), f.path(sshStateParent+"/kept-marker")); err != nil {
					t.Fatal(err)
				}
				f.write(marker, string(sshMarkerBytes(instance)))
			case "extra-child":
				f.write(stage+"/administrator.conf", "preserve")
			case "new-marker":
				f.write(marker, string(sshMarkerBytes(instance)))
			case "other-orphan":
				f.write(sshStateParent+"/"+sshStateStagePrefix+strings.Repeat("b", 64)+"/admin", "preserve")
			case "fixed-state":
				f.write(sshJournalDirectory+"/admin", "preserve")
			case "owner":
				f.write(sshStateParent+"/"+sshOwnerName, "preserve")
			case "destination":
				f.write(sshStateParent+"/"+sshRetiredPrefix+instance+"/admin", "preserve")
			case "parent":
				if err := os.Rename(f.path(sshStateParent), f.path(sshStateParent+".kept")); err != nil {
					t.Fatal(err)
				}
				f.write(marker, string(sshMarkerBytes(instance)))
			case "configuration":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "receipt":
				f.write(sshStateParent+"/"+plan.record.receiptName(), "preserve")
			}
			called := false
			ops := sshProvisionDefaults()
			ops.rename = func(int, string, int, string, uint) error { called = true; return nil }
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), ops); err == nil || called {
				t.Fatal("renamed stale or unrelated state", err)
			}
			if _, err := os.Lstat(f.path(stage)); err != nil {
				t.Fatal("removed changed evidence", err)
			}
		})
	}
}

func TestSSHRetirementRefusesUnsafeMarkerObjects(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "readable", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f, instance := orphanFixture(t, false)
			marker := sshStateParent + "/" + sshStateStagePrefix + instance + "/" + sshMarkerName
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(f.path(MainPath), f.path(marker))
			case "hardlink":
				f.write(sshStateParent+"/marker-copy", string(sshMarkerBytes(instance)))
				err = os.Link(f.path(sshStateParent+"/marker-copy"), f.path(marker))
			case "fifo":
				err = unix.Mkfifo(f.path(marker), 0600)
			case "directory":
				err = os.Mkdir(f.path(marker), 0700)
			case "readable":
				f.write(marker, string(sshMarkerBytes(instance)))
				err = f.chmod(marker, 0644)
			case "oversized":
				f.write(marker, strings.Repeat("x", maxSSHOwnerBytes+1))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectSSHStateRetirement(f.root, os.Geteuid(), instance); err == nil {
				t.Fatal("accepted unsafe marker")
			}
		})
	}
}

func TestSSHRetirementRefusesRacingDestinationAndReceiptReplacement(t *testing.T) {
	for _, kind := range []string{"destination", "source", "receipt", "configuration"} {
		t.Run(kind, func(t *testing.T) {
			f, instance := orphanFixture(t, true)
			plan := orphanPlan(t, f, instance)
			ops := sshProvisionDefaults()
			renamed := false
			if kind == "destination" || kind == "source" {
				ops.rename = func(oldFD int, old string, newFD int, target string, flags uint) error {
					if flags != unix.RENAME_NOREPLACE {
						t.Fatal("unsafe rename")
					}
					if kind == "destination" {
						f.write(sshStateParent+"/"+target+"/administrator.conf", "preserve")
					} else {
						if err := os.Rename(f.path(sshStateParent+"/"+old), f.path(sshStateParent+"/kept-original")); err != nil {
							t.Fatal(err)
						}
						f.write(sshStateParent+"/"+old+"/administrator.conf", "preserve")
					}
					renamed = true
					return unix.Renameat2(oldFD, old, newFD, target, flags)
				}
			} else {
				calls := 0
				ops.sync = func(file *os.File) error {
					calls++
					if calls == 2 {
						if kind == "configuration" {
							f.write(MainPath, includeDropIns+"Port 2223\n")
						} else {
							name := sshStateParent + "/" + plan.record.receiptName()
							data, err := os.ReadFile(f.path(name))
							if err != nil {
								t.Fatal(err)
							}
							if err := os.Rename(f.path(name), f.path(sshStateParent+"/kept-receipt")); err != nil {
								t.Fatal(err)
							}
							f.write(name, string(data))
						}
					}
					return file.Sync()
				}
			}
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), ops); err == nil {
				t.Fatal("claimed success after a race")
			}
			if (kind == "destination" || kind == "source") && !renamed {
				t.Fatal("rename injection was not reached")
			}
			if kind == "destination" || kind == "source" {
				name := sshStateParent + "/" + sshRetiredPrefix + instance + "/administrator.conf"
				if data, err := os.ReadFile(f.path(name)); err != nil || string(data) != "preserve" {
					t.Fatal("lost raced administrator content", err)
				}
			}
		})
	}
}

func TestSSHRetirementReceiptRejectsMalformedOrInvalidRecords(t *testing.T) {
	f, instance := orphanFixture(t, true)
	record := orphanPlan(t, f, instance).record
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, []byte("null"), append(bytes.Clone(data), '\n'),
		[]byte(strings.Replace(string(data), "{", `{"extra":0,`, 1)),
		[]byte(strings.Replace(string(data), "{", `{"schema":1,`, 1)),
		[]byte(strings.Replace(string(data), `"schema"`, `"Schema"`, 1))} {
		if got, err := decodeSSHStateRetirement(invalid, os.Geteuid()); err == nil || !reflect.DeepEqual(got, sshStateRetirement{}) {
			t.Fatal("accepted noncanonical receipt")
		}
	}
	for _, kind := range []string{"schema", "instance", "digest", "directory", "parent", "marker", "time", "mode"} {
		t.Run(kind, func(t *testing.T) {
			copy, err := decodeSSHStateRetirement(data, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "schema":
				copy.Schema++
			case "instance":
				copy.Instance = "../elsewhere"
			case "digest":
				copy.InventorySHA256 = ""
			case "directory":
				copy.Directory.Inode = copy.Parent.Inode
			case "parent":
				copy.Parent.Mode |= 0002
			case "marker":
				copy.Marker.Data = []byte("unrelated")
			case "time":
				copy.Changed.Nsec = 1e9
			case "mode":
				copy.Directory.Mode |= 0040
			}
			encoded, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSSHStateRetirement(encoded, os.Geteuid()); err == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}

func TestSSHRetirementRequiresExactApprovalAndExclusiveParent(t *testing.T) {
	f, instance := orphanFixture(t, true)
	plan := orphanPlan(t, f, instance)
	for _, approval := range []string{"", "not-a-digest", strings.Repeat("0", 64), strings.ToUpper(plan.record.digest())} {
		if err := retireSSHState(f.root, os.Geteuid(), instance, approval, sshProvisionDefaults()); err == nil {
			t.Fatal("accepted missing or wrong approval")
		}
	}
	for _, name := range []string{"", "../escape", strings.Repeat("b", 64)} {
		if _, err := inspectSSHStateRetirement(f.root, os.Geteuid(), name); err == nil {
			t.Fatal("accepted invalid or unrelated instance")
		}
	}
	parent, err := openSSHRetirementParent(f.root, os.Geteuid(), instance)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err == nil {
		t.Fatal("ignored concurrent operation lock")
	}
	if _, err := os.Lstat(f.path(sshStateParent + "/" + plan.record.receiptName())); !os.IsNotExist(err) {
		t.Fatal("wrote a receipt without exclusive exact approval", err)
	}
}

func TestSSHRetirementRefusesUnsafeReceiptObjects(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "readable", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f, instance := orphanFixture(t, true)
			plan := orphanPlan(t, f, instance)
			receipt := sshStateParent + "/" + plan.record.receiptName()
			data, err := json.Marshal(plan.record)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				err = os.Symlink(f.path(MainPath), f.path(receipt))
			case "hardlink":
				f.write(sshStateParent+"/receipt-copy", string(data))
				err = os.Link(f.path(sshStateParent+"/receipt-copy"), f.path(receipt))
			case "fifo":
				err = unix.Mkfifo(f.path(receipt), 0600)
			case "directory":
				err = os.Mkdir(f.path(receipt), 0700)
			case "readable":
				f.write(receipt, string(data))
				err = f.chmod(receipt, 0644)
			case "oversized":
				f.write(receipt, strings.Repeat("x", maxSSHOwnerBytes+1))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err == nil {
				t.Fatal("accepted unsafe receipt")
			}
			if _, err := os.Lstat(f.path(sshStateParent + "/" + sshStateStagePrefix + instance)); err != nil {
				t.Fatal("moved state without a valid receipt", err)
			}
		})
	}
}

func TestSSHRetirementPreservesChangedBackupAfterUncertainSync(t *testing.T) {
	f, instance := orphanFixture(t, true)
	plan := orphanPlan(t, f, instance)
	ops := sshProvisionDefaults()
	calls := 0
	ops.sync = func(file *os.File) error {
		calls++
		if calls == 3 {
			return unix.EIO
		}
		return file.Sync()
	}
	if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), ops); !errors.Is(err, unix.EIO) {
		t.Fatal("missing final sync interruption", err)
	}
	name := sshStateParent + "/" + sshRetiredPrefix + instance + "/administrator.conf"
	f.write(name, "preserve recovery annotation")
	if err := retireSSHState(f.root, os.Geteuid(), instance, plan.record.digest(), sshProvisionDefaults()); err == nil {
		t.Fatal("claimed completed recovery of changed backup")
	}
	if data, err := os.ReadFile(f.path(name)); err != nil || string(data) != "preserve recovery annotation" {
		t.Fatal("lost changed recovery evidence", err)
	}
}

func FuzzSSHStateRetirement(f *testing.F) {
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte("null"))
	currentUID := os.Geteuid()
	if currentUID < 0 || currentUID > math.MaxUint32 {
		f.Fatal("unsupported fixture UID")
		return
	}
	uid := uint32(currentUID)
	seed := sshStateRetirement{
		Schema: 1, Instance: strings.Repeat("a", 64), InventorySHA256: strings.Repeat("b", 64),
		Parent:    sshDirectoryIdentity{1, 2, unix.S_IFDIR | 0755, uid, uid, map[string][]byte{}},
		Directory: sshDirectoryIdentity{1, 3, unix.S_IFDIR | 0700, uid, uid, map[string][]byte{}},
	}
	encodedSeed, err := json.Marshal(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encodedSeed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSSHOwnerBytes {
			return
		}
		record, err := decodeSSHStateRetirement(data, os.Geteuid())
		if err != nil {
			if !reflect.DeepEqual(record, sshStateRetirement{}) {
				t.Fatal("partial invalid record")
			}
			return
		}
		encoded, err := json.Marshal(record)
		if err != nil || !bytes.Equal(encoded, data) || record.validate(os.Geteuid()) != nil {
			t.Fatal("invalid canonical record")
		}
	})
}
