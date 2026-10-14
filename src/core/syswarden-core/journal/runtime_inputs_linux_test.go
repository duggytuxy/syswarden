package journal

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthorityRuntimeDirectoryResolution(t *testing.T) {
	for _, denial := range []error{nil, unix.ENOSYS, unix.EINVAL, unix.EPERM, unix.EXDEV, unix.ELOOP, unix.EAGAIN} {
		calls := 0
		fd, err := openAuthorityRuntimeDirectoryFD(42, "state", func(parent int, name string, how *unix.OpenHow) (int, error) {
			calls++
			if parent != 42 || name != "state" || how.Mode != 0 || how.Flags != unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY || how.Resolve != unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV {
				t.Fatal("weakened runtime resolution")
			}
			if denial != nil {
				return -1, denial
			}
			return 43, nil
		})
		if calls != 1 || !errors.Is(err, denial) || (denial == nil && fd != 43) || (denial != nil && fd != -1) {
			t.Fatal("unexpected retry or fallback", fd, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../state", "/endpoint", "sub/state", "launch.json"} {
		if _, err := openAuthorityRuntimeDirectoryFD(42, name, func(int, string, *unix.OpenHow) (int, error) { t.Fatal("unapproved name opened"); return -1, nil }); err == nil {
			t.Fatal("unapproved name accepted")
		}
	}
	if _, err := openAuthorityRuntimeDirectoryFD(42, "state", nil); err == nil {
		t.Fatal("nil opener accepted")
	}
	if _, err := openAuthorityRuntimeDirectoryFD(-1, "state", unix.Openat2); err == nil {
		t.Fatal("invalid parent accepted")
	}
}

// Directory mutation is confined to the opt-in disposable root fixture.
func testAuthorityRuntimeInputs(t *testing.T, launchBytes []byte) {
	c, err := DecodeAuthorityLaunch(launchBytes)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"valid-held", "entry-replacement", "nil-state-parent", "nil-endpoint-parent", "closed-state-parent", "closed-endpoint-parent", "path-state-parent", "path-endpoint-parent", "swapped-parents", "same-parents", "nil-launch", "closed-launch", "wrong-launch-digest"}
	for _, target := range []string{"state-parent", "endpoint-parent", "state", "endpoint"} {
		for _, mutation := range []string{"owner", "group", "mode", "acl", "default-acl"} {
			cases = append(cases, target+"-"+mutation)
		}
	}
	for _, target := range []string{"state", "endpoint"} {
		for _, mutation := range []string{"symlink", "fifo", "file", "missing"} {
			cases = append(cases, target+"-"+mutation)
		}
	}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			for _, dir := range []struct {
				name     string
				uid, gid int
				mode     os.FileMode
			}{
				{"private", 0, 0, 0700}, {"public", 0, 0, 0755}, {"private/state", int(c.ServiceUID), int(c.ServiceGID), 0700}, {"public/endpoint", int(c.ServiceUID), int(c.EndpointGID), 0750},
			} {
				if err := root.Mkdir(dir.name, 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Chown(dir.name, dir.uid, dir.gid); err != nil {
					t.Fatal(err)
				}
				if err := root.Chmod(dir.name, dir.mode); err != nil {
					t.Fatal(err)
				}
			}
			if err := root.WriteFile("launch", launchBytes, 0400); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				target, name string
				mode         os.FileMode
			}{
				{"state-parent", "private", 0700}, {"endpoint-parent", "public", 0755}, {"state", "private/state", 0700}, {"endpoint", "public/endpoint", 0750},
			} {
				if !strings.HasPrefix(kind, item.target+"-") {
					continue
				}
				mutation := strings.TrimPrefix(kind, item.target+"-")
				path := filepath.Join(base, item.name)
				switch mutation {
				case "owner":
					err = root.Chown(item.name, 1, -1)
				case "group":
					err = root.Chown(item.name, -1, 1)
				case "mode":
					err = root.Chmod(item.name, 0777)
				case "acl":
					authorityTestACL(t, path, "system.posix_acl_access")
					err = root.Chmod(item.name, item.mode)
				case "default-acl":
					authorityTestACL(t, path, "system.posix_acl_default")
				case "symlink", "fifo", "file", "missing":
					if err = root.Rename(item.name, item.name+".retired"); err != nil {
						t.Fatal(err)
					}
					switch mutation {
					case "symlink":
						err = root.Symlink(filepath.Base(item.name)+".retired", item.name)
					case "fifo":
						err = unix.Mkfifo(path, uint32(item.mode))
					case "file":
						err = root.WriteFile(item.name, []byte("unrelated"), 0600)
					}
				}
				if err != nil {
					t.Fatal("fixture mutation", err)
				}
			}
			sf, ef := os.O_RDONLY, os.O_RDONLY
			if kind == "path-state-parent" {
				sf = unix.O_PATH
			}
			if kind == "path-endpoint-parent" {
				ef = unix.O_PATH
			}
			sp, err := root.OpenFile("private", sf, 0)
			if err != nil {
				t.Fatal(err)
			}
			ep, err := root.OpenFile("public", ef, 0)
			if err != nil {
				_ = sp.Close()
				t.Fatal(err)
			}
			launch, err := root.Open("launch")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sp.Close(); _ = ep.Close(); _ = launch.Close() }()
			a, b, record := sp, ep, launch
			digest := recoveryDigest(launchBytes)
			switch kind {
			case "nil-state-parent":
				a = nil
			case "nil-endpoint-parent":
				b = nil
			case "closed-state-parent":
				_ = sp.Close()
			case "closed-endpoint-parent":
				_ = ep.Close()
			case "swapped-parents":
				a, b = ep, sp
			case "same-parents":
				b = sp
			case "nil-launch":
				record = nil
			case "closed-launch":
				_ = launch.Close()
			case "wrong-launch-digest":
				digest = strings.Repeat("0", 64)
			}
			paths := []string{filepath.Join(base, "private"), filepath.Join(base, "public"), filepath.Join(base, "private/state"), filepath.Join(base, "public/endpoint"), filepath.Join(base, "launch")}
			before := endpointRecoverySnapshot(t, paths)
			state, endpoint, err := OpenAuthorityRuntimeDirectories(a, b, record, digest)
			requireEndpointRecoverySnapshot(t, before, paths)
			if kind != "valid-held" && kind != "entry-replacement" {
				if state != nil {
					_ = state.Close()
					t.Fatal("failed acquisition returned state")
				}
				if endpoint != nil {
					_ = endpoint.Close()
					t.Fatal("failed acquisition returned endpoint")
				}
				if !errors.Is(err, ErrAuthorityRuntimeInputs) {
					t.Fatal("unsafe runtime admitted", err)
				}
				requireNoAuthorityInputHandles(t, filepath.Join(base, "private"), sp.Fd())
				requireNoAuthorityInputHandles(t, filepath.Join(base, "public"), ep.Fd())
				return
			}
			if err != nil || state == nil || endpoint == nil {
				t.Fatal("valid runtime refused", err)
			}
			defer func() { _ = state.Close(); _ = endpoint.Close() }()
			for _, f := range []*os.File{state, endpoint} {
				flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("inheritable runtime", err)
				}
				flags, err = unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
					t.Fatal("invalid runtime access", err)
				}
			}
			var stamp unix.Stat_t
			if err := unix.Fstat(int(state.Fd()), &stamp); err != nil {
				t.Fatal(err)
			}
			if !authorityInputStillBound(int(sp.Fd()), "state", state, stamp) {
				t.Fatal("fresh state unbound")
			}
			if kind == "entry-replacement" {
				if err := root.Rename("private/state", "private/retired"); err != nil {
					t.Fatal(err)
				}
				if err := root.Mkdir("private/state", 0700); err != nil {
					t.Fatal(err)
				}
				if authorityInputStillBound(int(sp.Fd()), "state", state, stamp) {
					t.Fatal("replaced state binding accepted")
				}
			}
			if err := errors.Join(sp.Close(), ep.Close()); err != nil {
				t.Fatal(err)
			}
			held, err := attestAuthorityRuntimeDirectory(int(state.Fd()), c.ServiceUID, c.ServiceGID, 0700)
			if err != nil || !sameAuthorityRuntimeObject(stamp, held) {
				t.Fatal("caller close invalidated held runtime", err)
			}
			if _, err := attestAuthorityRuntimeDirectory(int(endpoint.Fd()), c.ServiceUID, c.EndpointGID, 0750); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func prepareActualAuthorityRuntimeInputs(t, owner *testing.T, binary *executableImages, c *processFixtureConfig) {
	t.Helper()
	private, public := owner.TempDir(), owner.TempDir()
	if err := chmodFixture(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := chmodFixture(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := chmodFixture(filepath.Dir(public), 0755); err != nil {
		t.Fatal(err)
	}
	state, endpoint := filepath.Join(private, "state"), filepath.Join(public, "endpoint")
	old := c.StateDirectory
	if err := os.Rename(old, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(c.Endpoint, endpoint); err != nil {
		t.Fatal(err)
	}
	c.StateDirectory, c.Endpoint = state, endpoint
	c.PrivateStateParent = true
	for i, name := range authorityLayoutNames() {
		if i < len(c.Paths) {
			c.Paths[i] = filepath.Join(state, name)
		} else {
			c.PinDirectory = filepath.Join(state, name)
		}
	}
	a, err := os.OpenRoot(private)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := os.OpenRoot(public)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	sp, err := a.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ep, err := b.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	before := adversarialSnapshot(t, c.Paths)
	stateFile, endpointFile, err := OpenAuthorityRuntimeDirectories(sp, ep, binary.launch, c.LaunchDigest)
	if err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() { _ = stateFile.Close(); _ = endpointFile.Close() })
	binary.state, binary.endpoint = stateFile, endpointFile
	if !reflect.DeepEqual(before, adversarialSnapshot(t, c.Paths)) {
		t.Fatal("acquisition modified private runtime")
	}
	// All caller parent handles close before the actual process starts. State and
	// endpoint stay separate so clients can traverse only their group-facing path.
}
