package system

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRuntimeSocketRemovalResolvesCanonicalPrivateGroup(t *testing.T) {
	account := &user.User{Username: "syslog", Uid: "100", Gid: "101"}
	group := &user.Group{Name: "syslog", Gid: "101"}
	lookupUser := func(name string) (*user.User, error) {
		if name != "syslog" {
			t.Fatalf("unexpected account %q", name)
		}
		return account, nil
	}
	lookupGroup := func(name string) (*user.Group, error) {
		if name != "syslog" {
			t.Fatalf("unexpected group %q", name)
		}
		return group, nil
	}
	if gid, err := resolveRemovalSyslogGroup(lookupUser, lookupGroup); err != nil || gid != 101 {
		t.Fatalf("canonical native producer group refused: %d %v", gid, err)
	}
	for _, invalid := range []string{"", "0", "-1", "+100", "0100", "4294967295", "4294967296", "invalid"} {
		account.Uid = invalid
		if _, err := resolveRemovalSyslogGroup(lookupUser, lookupGroup); err == nil {
			t.Fatalf("unsafe UID accepted: %q", invalid)
		}
		account.Uid = "100"
		account.Gid, group.Gid = invalid, invalid
		if _, err := resolveRemovalSyslogGroup(lookupUser, lookupGroup); err == nil {
			t.Fatalf("unsafe GID accepted: %q", invalid)
		}
		account.Gid, group.Gid = "101", "101"
	}
	for _, mutate := range []func(){
		func() { account.Username = "operator" },
		func() { group.Name = "operator" },
		func() { account.Gid = "102" },
		func() { account = nil },
		func() { group = nil },
	} {
		mutate()
		if _, err := resolveRemovalSyslogGroup(lookupUser, lookupGroup); err == nil {
			t.Fatal("mismatched or missing producer identity accepted")
		}
		account = &user.User{Username: "syslog", Uid: "100", Gid: "101"}
		group = &user.Group{Name: "syslog", Gid: "101"}
	}
	for _, failure := range []error{user.UnknownUserError("syslog"), errors.New("NSS unavailable")} {
		if _, err := resolveRemovalSyslogGroup(func(string) (*user.User, error) { return nil, failure }, lookupGroup); !errors.Is(err, failure) {
			t.Fatalf("account lookup failure lost: %v", err)
		}
		if _, err := resolveRemovalSyslogGroup(lookupUser, func(string) (*user.Group, error) { return nil, failure }); !errors.Is(err, failure) {
			t.Fatalf("group lookup failure lost: %v", err)
		}
	}
}

type runtimeSocketMetadataFixture struct {
	os.FileInfo
	metadata syscall.Stat_t
	mode     os.FileMode
}

func (info runtimeSocketMetadataFixture) Sys() any          { return &info.metadata }
func (info runtimeSocketMetadataFixture) Mode() os.FileMode { return info.mode }

func TestRuntimeSocketRemovalPrivateGroupBoundaries(t *testing.T) {
	baseline := runtimeSocketMetadataFixture{metadata: syscall.Stat_t{Uid: 0, Gid: 101, Nlink: 1, Mode: syscall.S_IFSOCK | 0660}, mode: os.ModeSocket | 0660}
	resolve := func() (uint32, error) { return 101, nil }
	if _, err := attestRuntimeSocketIdentity(baseline, 0, 0, resolve); err != nil {
		t.Fatalf("native root:syslog socket refused: %v", err)
	}
	for _, mutate := range []func(*runtimeSocketMetadataFixture){
		func(info *runtimeSocketMetadataFixture) { info.metadata.Uid = 100 },
		func(info *runtimeSocketMetadataFixture) { info.metadata.Gid = 102 },
		func(info *runtimeSocketMetadataFixture) { info.metadata.Nlink = 2 },
		func(info *runtimeSocketMetadataFixture) { info.mode = 0660 },
		func(info *runtimeSocketMetadataFixture) { info.mode = os.ModeSymlink | 0660 },
		func(info *runtimeSocketMetadataFixture) { info.mode = os.ModeNamedPipe | 0660 },
		func(info *runtimeSocketMetadataFixture) { info.mode = os.ModeSocket | 0666 },
		func(info *runtimeSocketMetadataFixture) { info.mode = os.ModeSocket | 0600 },
		func(info *runtimeSocketMetadataFixture) { info.mode |= os.ModeSticky },
	} {
		info := baseline
		mutate(&info)
		if _, err := attestRuntimeSocketIdentity(info, 0, 0, resolve); err == nil {
			t.Fatalf("non-attributable socket accepted: %+v", info)
		}
	}
	for _, resolver := range []func() (uint32, error){nil, func() (uint32, error) { return 0, nil }, func() (uint32, error) { return 101, errors.New("NSS failure") }} {
		if _, err := attestRuntimeSocketIdentity(baseline, 0, 0, resolver); err == nil {
			t.Fatal("socket accepted without a verified private group")
		}
	}
	baseline.metadata.Gid = 0
	if _, err := attestRuntimeSocketIdentity(baseline, 0, 0, func() (uint32, error) {
		t.Fatal("legacy root socket unexpectedly required syslog")
		return 0, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSocketNativePrivateGroupRemoval(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root to create the native root:syslog socket fixture")
	}
	for _, scenario := range []string{"remove", "group-writable-parent", "changed-owner", "changed-group", "changed-mode", "replaced-inode"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "syswarden.sock")
			conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := os.Chown(path, 0, 101); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0660); err != nil {
				t.Fatal(err)
			} // #nosec G302 -- private root-owned test socket reproduces the exact native producer mode
			if err := removeExactRuntimeSocketAt(path, 0, 0); err == nil {
				t.Fatal("strict root socket policy accepted the private group")
			}
			if scenario == "group-writable-parent" {
				if err := os.Chmod(parent, 0770); err != nil {
					t.Fatal(err)
				} // #nosec G302 -- deliberately unsafe private fixture must be refused
			}
			resolve := func() (uint32, error) {
				switch scenario {
				case "changed-owner":
					if err := os.Chown(path, 100, 101); err != nil {
						t.Fatal(err)
					}
				case "changed-group":
					if err := os.Chown(path, 0, 102); err != nil {
						t.Fatal(err)
					}
				case "changed-mode":
					if err := os.Chmod(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "replaced-inode":
					if err := os.Rename(path, path+".retained"); err != nil {
						t.Fatal(err)
					}
					replacement, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = replacement.Close() })
					if err := os.Chown(path, 0, 101); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0660); err != nil {
						t.Fatal(err)
					} // #nosec G302 -- private replacement fixture matches the native mode to test inode attestation
				}
				return 101, nil
			}
			err = removeExactRuntimeSocketWithPrivateGroupAt(path, 0, 0, resolve)
			_, statErr := os.Lstat(path)
			if scenario == "remove" {
				if err != nil || !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("private socket removal failed: %v %v", err, statErr)
				}
				if err := removeExactRuntimeSocketWithPrivateGroupAt(path, 0, 0, func() (uint32, error) {
					t.Fatal("absent socket required an account lookup")
					return 0, nil
				}); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || statErr != nil {
				t.Fatalf("unsafe socket or parent was removed: %v %v", err, statErr)
			} else if scenario != "group-writable-parent" && !strings.Contains(err.Error(), "changed during attestation") {
				t.Fatalf("identity change was not detected: %v", err)
			}
		})
	}
}
