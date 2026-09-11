package network

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUDSProducerIdentityAuthorizesOnlyRootAndSyslogUID(t *testing.T) {
	lookupUser := func(string) (*user.User, error) { return &user.User{Username: "syslog", Uid: "100", Gid: "101"}, nil }
	lookupGroup := func(string) (*user.Group, error) { return &user.Group{Name: "syslog", Gid: "101"}, nil }
	identity, err := resolveUDSProducerIdentity(0, 0, lookupUser, lookupGroup)
	if err != nil || identity.group != 101 || len(identity.uids) != 2 {
		t.Fatalf("configured logging producer cannot access its socket: %+v %v", identity, err)
	}
	for _, uid := range []uint32{0, 100, 1000} {
		control := unix.UnixCredentials(&unix.Ucred{Pid: 123, Uid: uid, Gid: 101})
		if authorizedUDSCredentials(control, 0, identity.uids) != (uid == 0 || uid == 100) {
			t.Fatalf("sender UID %d was authorized by group membership instead of identity", uid)
		}
		if authorizedUDSCredentials(control, unix.MSG_CTRUNC, identity.uids) {
			t.Fatal("truncated sender credentials were accepted")
		}
	}
	if authorizedUDSCredentials(nil, 0, identity.uids) || authorizedUDSCredentials([]byte("invalid"), 0, identity.uids) {
		t.Fatal("missing or invalid sender credentials were accepted")
	}
	if _, err := resolveUDSProducerIdentity(0, 0, lookupUser, func(string) (*user.Group, error) {
		return &user.Group{Name: "syslog", Gid: "102"}, nil
	}); err == nil {
		t.Fatal("unrelated producer group was accepted")
	}
	root, err := resolveUDSProducerIdentity(0, 0, func(string) (*user.User, error) {
		return nil, user.UnknownUserError("syslog")
	}, lookupGroup)
	if err != nil || root.group != 0 || len(root.uids) != 1 || root.uids[0] != 0 {
		t.Fatalf("root-only native logging changed: %+v %v", root, err)
	}
}

func TestUDSKernelCredentialsCarryTheActualNativeSender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.sock")
	server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	identity, err := configureUDSProducerAccess(server, path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("native credential witness")); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data, control := make([]byte, 128), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := server.ReadMsgUnix(data, control)
	if err != nil || string(data[:n]) != "native credential witness" || !authorizedUDSCredentials(control[:oobn], flags, identity.uids) {
		t.Fatalf("actual kernel credentials were not accepted: %v", err)
	}
	if authorizedUDSCredentials(control[:oobn], flags, []uint32{uint32(os.Geteuid()) + 1}) { // #nosec G115 -- test uses the kernel's current UID and a deliberately different identity
		t.Fatal("actual sender was accepted as another UID")
	}
}
