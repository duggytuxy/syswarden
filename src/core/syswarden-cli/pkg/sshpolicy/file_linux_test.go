//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureDirectory(t *testing.T, fixture *inventoryFixture, name string) *os.File {
	t.Helper()
	reader := inventoryReader{root: fixture.root, uid: os.Geteuid(), state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	dir, err := reader.openDirectory(name)
	if err != nil || dir == nil {
		t.Fatal("cannot open fixture directory", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func fixtureMainImage(t *testing.T, fixture *inventoryFixture) sshFileImage {
	t.Helper()
	file, err := os.Open(fixture.path(MainPath))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	image, err := readSSHImage(file, os.Geteuid(), 1, MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

// Linux POSIX ACL xattr encoding: owner rw, named UID read, group read,
// mask read, other none. Only disposable fixture inodes receive these bytes.
func fixtureACL(t *testing.T) []byte {
	t.Helper()
	uid := os.Geteuid()
	if uid < 0 || uid > math.MaxUint32 {
		t.Fatal("fixture UID is outside Linux bounds")
		return nil
	}
	data := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(data, 2)
	entries := []struct {
		tag, permissions uint16
		id               uint32
	}{
		{1, 6, ^uint32(0)}, {2, 4, uint32(uid)}, {4, 4, ^uint32(0)},
		{16, 4, ^uint32(0)}, {32, 0, ^uint32(0)},
	}
	for i, entry := range entries {
		p := data[4+i*8:]
		binary.LittleEndian.PutUint16(p, entry.tag)
		binary.LittleEndian.PutUint16(p[2:], entry.permissions)
		binary.LittleEndian.PutUint32(p[4:], entry.id)
	}
	return data
}

func TestAnonymousSSHStagePreservesExactMetadataWithoutNamedFiles(t *testing.T) {
	fixture := planFixture(t, includeDropIns)
	const attr = "user.ssh-policy-test"
	if err := unix.Setxattr(fixture.path(MainPath), attr, []byte("private metadata"), 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(fixture.path(MainPath), "system.posix_acl_access", fixtureACL(t), 0); err != nil {
		t.Fatal(err)
	}
	before := fixtureMainImage(t, fixture)
	dir := fixtureDirectory(t, fixture, "/etc/ssh")
	entries, err := os.ReadDir(fixture.path("/etc/ssh"))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := newSSHAnonymousStage(dir, []byte("reviewed candidate\n"), before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if stage.image.state.links != 0 || !reflect.DeepEqual(stage.image.attrs, before.attrs) || stage.image.state.mode != before.state.mode {
		t.Fatal("stage lost exact permissions or attributes")
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(fixture.path("/etc/ssh"))
	if err != nil || len(entries) != len(after) || !reflect.DeepEqual(fixtureMainImage(t, fixture), before) {
		t.Fatal("anonymous staging changed active configuration", err)
	}
}

func TestAnonymousSSHStageRemovesInheritedACLAbsentFromSource(t *testing.T) {
	fixture := planFixture(t, includeDropIns)
	dir := fixtureDirectory(t, fixture, "/etc/ssh")
	before := fixtureMainImage(t, fixture)
	if _, exists := before.attrs["system.posix_acl_access"]; exists {
		t.Fatal("unexpected source ACL")
	}
	if err := unix.Fsetxattr(int(dir.Fd()), "system.posix_acl_default", fixtureACL(t), 0); err != nil {
		t.Fatal(err)
	}
	stage, err := newSSHAnonymousStage(dir, before.data, before.state.mode&0777, before.state.gid, before.attrs, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if !reflect.DeepEqual(stage.image.attrs, before.attrs) {
		t.Fatal("retained an inherited attribute")
	}
}

func TestSSHImageAndStagingRejectUnsafeInputs(t *testing.T) {
	fixture := planFixture(t, includeDropIns)
	dir := fixtureDirectory(t, fixture, "/etc/ssh")
	gid := fixtureMainImage(t, fixture).state.gid
	for _, name := range []string{"security.ima", "security.evm", "security.capability", "system.posix_acl_default", "bad\x00name", "user.invalid\xff", ""} {
		t.Run(name, func(t *testing.T) {
			if stage, err := newSSHAnonymousStage(dir, nil, 0600, gid, map[string][]byte{name: {1}}, os.Geteuid()); err == nil {
				_ = stage.Close()
				t.Fatal("accepted unsafe replacement attributes")
			}
		})
	}
	for _, mode := range []uint32{0666, 0620, 0602, 0700, 04600, 02600, 01000, 0000, 0200} {
		if stage, err := newSSHAnonymousStage(dir, nil, mode, gid, map[string][]byte{}, os.Geteuid()); err == nil {
			_ = stage.Close()
			t.Fatal("accepted unsafe mode", mode)
		}
	}
	if stage, err := newSSHAnonymousStage(dir, nil, 0600, gid, map[string][]byte{"user.bound": make([]byte, maxSSHAttributes)}, os.Geteuid()); err == nil {
		_ = stage.Close()
		t.Fatal("accepted excessive metadata")
	}
	file, err := os.Open(fixture.path(MainPath))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := readSSHImage(file, os.Geteuid(), 0, MaxBytes); err == nil {
		t.Fatal("treated named input as unnamed")
	}
	if _, err := readSSHImage(file, os.Geteuid(), 1, 1); err == nil {
		t.Fatal("read exceeded bound")
	}
	if err := os.Link(fixture.path(MainPath), fixture.path("/etc/ssh/alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSHImage(file, os.Geteuid(), 1, MaxBytes); err == nil {
		t.Fatal("accepted shared inode")
	}
}

func TestSSHPlanBindsFileAndDirectoryAttributeBytes(t *testing.T) {
	for _, name := range []string{MainPath, IntentPath, "/etc/ssh", "/etc/ssh/sshd_config.d"} {
		t.Run(name, func(t *testing.T) {
			fixture := planFixture(t, includeDropIns)
			if err := unix.Setxattr(fixture.path(name), "user.inventory", []byte("before"), 0); err != nil {
				t.Fatal(err)
			}
			plan := fixture.plan()
			if string(plan.inventory.attributes[name]["user.inventory"]) != "before" {
				t.Fatal("attribute not captured")
			}
			old := plan.summary.PlanSHA256
			plan.inventory.attributes[name]["user.inventory"] = []byte("after")
			if old == planDigest(plan) {
				t.Fatal("digest ignored attribute bytes")
			}
			inventory := fixture.open()
			if err := unix.Setxattr(fixture.path(name), "user.inventory", []byte("after"), 0); err != nil {
				t.Fatal(err)
			}
			if name != IntentPath && inventory.Recheck() == nil {
				t.Fatal("recheck ignored metadata edit")
			}
			if fixture.plan().summary.PlanSHA256 == old {
				t.Fatal("plan reinspection ignored metadata edit")
			}
		})
	}
}

func TestReadSSHAttributesIncludesEmptyValuesAndRefusesExcess(t *testing.T) {
	fixture := planFixture(t, includeDropIns)
	file, err := os.Open(fixture.path(MainPath))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Fsetxattr(int(file.Fd()), "user.empty", []byte{}, 0); err != nil {
		t.Fatal(err)
	}
	attrs, err := readSSHAttributes(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := attrs["user.empty"]; !exists || len(value) != 0 {
		t.Fatal("lost empty attribute")
	}
	// Repeated small values also exceed the aggregate budget on filesystems
	// where one large attribute is unavailable.
	large := map[string][]byte{"user.large": bytes.Repeat([]byte("x"), maxSSHAttributes)}
	if validateSSHAttributes(large, false) == nil {
		t.Fatal("ignored aggregate bound")
	}
	if validateSSHAttributes(map[string][]byte{strings.Repeat("x", 256): {}}, false) == nil {
		t.Fatal("ignored name bound")
	}
}
