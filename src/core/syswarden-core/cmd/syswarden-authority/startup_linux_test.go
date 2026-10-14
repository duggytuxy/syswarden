package main

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStartupIdentityRejectsRetainedPrivileges(t *testing.T) {
	baseline := startupIdentity{uids: [3]int{101, 101, 101}, gids: [3]int{102, 102, 102}, groups: []int{103}, noNewPrivileges: 1}
	if !validStartupIdentity(baseline, 101, 102, 103) {
		t.Fatal("minimal identity rejected")
	}
	for _, sameGroup := range [][]int{nil, {102}} {
		id := baseline
		id.groups = sameGroup
		if !validStartupIdentity(id, 101, 102, 102) {
			t.Fatal("shared endpoint group rejected")
		}
	}
	for _, groups := range [][]int{nil, {0}, {102}, {104}, {103, 103}, {103, 104}} {
		id := baseline
		id.groups = groups
		if validStartupIdentity(id, 101, 102, 103) {
			t.Fatal("unexpected groups admitted", groups)
		}
	}
	for i := 0; i < 3; i++ {
		for _, value := range []int{0, -1, 104} {
			id := baseline
			id.uids[i] = value
			if validStartupIdentity(id, 101, 102, 103) {
				t.Fatal("unexpected UID admitted", i, value)
			}
			id = baseline
			id.gids[i] = value
			if validStartupIdentity(id, 101, 102, 103) {
				t.Fatal("unexpected GID admitted", i, value)
			}
		}
	}
	for _, value := range []int{0, -1, 2} {
		id := baseline
		id.noNewPrivileges = value
		if validStartupIdentity(id, 101, 102, 103) {
			t.Fatal("missing no_new_privs admitted")
		}
	}
	for word := 0; word < 2; word++ {
		for _, caps := range []unix.CapUserData{{Effective: 1}, {Permitted: 1}, {Inheritable: 1}} {
			id := baseline
			id.caps[word] = caps
			if validStartupIdentity(id, 101, 102, 103) {
				t.Fatal("retained capability admitted", word, caps)
			}
		}
	}
	for _, bad := range []uint32{0, 1 << 31, ^uint32(0)} {
		if validStartupIdentity(baseline, bad, 102, 103) || validStartupIdentity(baseline, 101, bad, 103) || validStartupIdentity(baseline, 101, 102, bad) {
			t.Fatal("invalid configured identity admitted")
		}
	}
}

func TestSealStartupDescriptor(t *testing.T) {
	if sealStartupDescriptor(nil) == nil {
		t.Fatal("nil descriptor admitted")
	}
	f, err := os.CreateTemp(t.TempDir(), "descriptor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	raw, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var operation error
	if err := raw.Control(func(fd uintptr) { _, operation = unix.FcntlInt(fd, unix.F_SETFD, 0) }); err != nil || operation != nil {
		t.Fatal(err, operation)
	}
	for i := 0; i < 2; i++ {
		if err := sealStartupDescriptor(f); err != nil {
			t.Fatal(err)
		}
		var flags int
		if err := raw.Control(func(fd uintptr) { flags, operation = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil || operation != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("descriptor remains inheritable", err, operation)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if sealStartupDescriptor(f) == nil {
		t.Fatal("closed descriptor admitted")
	}
}
