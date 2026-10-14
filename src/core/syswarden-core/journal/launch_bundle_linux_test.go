package journal

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthorityLaunchBundleClose(t *testing.T) {
	if err := (*AuthorityLaunchBundle)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	for _, alreadyClosed := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "continues-after-error"}[alreadyClosed], func(t *testing.T) {
			var files [4]*os.File
			for i := range files {
				f, err := os.CreateTemp(t.TempDir(), "owned")
				if err != nil {
					t.Fatal(err)
				}
				files[i] = f
				t.Cleanup(func() { _ = f.Close() })
			}
			b := &AuthorityLaunchBundle{Launch: files[0], Image: files[1], State: files[2], Endpoint: files[3]}
			if alreadyClosed {
				_ = files[0].Close()
			}
			err := b.Close()
			if (err != nil) != alreadyClosed {
				t.Fatal("incorrect close result", err)
			}
			if b.Launch != nil || b.Image != nil || b.State != nil || b.Endpoint != nil {
				t.Fatal("bundle not consumed")
			}
			for _, f := range files {
				if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("owned handle retained", err)
				}
			}
			if err := b.Close(); err != nil {
				t.Fatal("repeated close", err)
			}
		})
	}
}

// Bundle composition runs in the mandatory disposable root fixture. Individual
// resource attacks remain covered by their independent mandatory acquisition cases.
func testAuthorityLaunchBundle(t *testing.T, launchBytes []byte) {
	c, err := DecodeAuthorityLaunch(launchBytes)
	if err != nil {
		t.Fatal(err)
	}
	imageBytes := testAuthorityELF(runtime.GOARCH, false)
	cases := []string{"valid-held", "nil-inputs", "nil-state", "nil-endpoint", "closed-inputs", "closed-state", "closed-endpoint", "wrong-launch-digest", "wrong-image-digest", "invalid-image", "state-owner", "endpoint-owner", "state-missing", "endpoint-missing", "swapped-parents", "repeated-runtime-refusal"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			for _, item := range []struct {
				name     string
				uid, gid int
				mode     os.FileMode
			}{
				{"inputs", 0, 0, 0700}, {"private", 0, 0, 0700}, {"public", 0, 0, 0755},
				{"private/state", int(c.ServiceUID), int(c.ServiceGID), 0700},
				{"public/endpoint", int(c.ServiceUID), int(c.EndpointGID), 0750},
			} {
				if err := root.Mkdir(item.name, 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Chown(item.name, item.uid, item.gid); err != nil {
					t.Fatal(err)
				}
				if err := root.Chmod(item.name, item.mode); err != nil {
					t.Fatal(err)
				}
			}
			data := imageBytes
			if kind == "invalid-image" {
				data = []byte("#!/bin/sh\nexit 0\n")
			}
			if err := root.WriteFile("inputs/launch.json", launchBytes, 0400); err != nil {
				t.Fatal(err)
			}
			if err := root.WriteFile("inputs/syswarden-authority", data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := root.Chmod("inputs/syswarden-authority", 0555); err != nil {
				t.Fatal(err)
			}
			var parents [3]*os.File
			for i, name := range []string{"inputs", "private", "public"} {
				f, err := root.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				parents[i] = f
				defer func() { _ = f.Close() }()
			}
			a, b, e := parents[0], parents[1], parents[2]
			ld, id := recoveryDigest(launchBytes), recoveryDigest(data)
			attempts := 1
			switch kind {
			case "nil-inputs":
				a = nil
			case "nil-state":
				b = nil
			case "nil-endpoint":
				e = nil
			case "closed-inputs":
				_ = a.Close()
			case "closed-state":
				_ = b.Close()
			case "closed-endpoint":
				_ = e.Close()
			case "wrong-launch-digest":
				ld = strings.Repeat("0", 64)
			case "wrong-image-digest":
				id = strings.Repeat("0", 64)
			case "state-owner":
				err = root.Chown("private/state", 1, -1)
			case "endpoint-owner", "repeated-runtime-refusal":
				err = root.Chown("public/endpoint", 1, -1)
				if kind == "repeated-runtime-refusal" {
					attempts = 12
				}
			case "state-missing":
				err = root.Remove("private/state")
			case "endpoint-missing":
				err = root.Remove("public/endpoint")
			case "swapped-parents":
				b, e = e, b
			}
			if err != nil {
				t.Fatal(err)
			}
			paths := []string{base}
			for _, name := range []string{"inputs", "private", "public", "private/state", "public/endpoint", "inputs/launch.json", "inputs/syswarden-authority"} {
				paths = append(paths, filepath.Join(base, name))
			}
			before := endpointRecoverySnapshot(t, paths)
			handles := authorityBundleHandles(t, base)
			for attempt := 0; attempt < attempts; attempt++ {
				bundle, err := OpenAuthorityLaunchBundle(a, b, e, ld, id)
				requireEndpointRecoverySnapshot(t, before, paths)
				if kind != "valid-held" {
					if bundle != nil {
						_ = bundle.Close()
						t.Fatal("partial bundle escaped")
					}
					if !errors.Is(err, ErrAuthorityLaunchBundle) {
						t.Fatal("unsafe bundle admitted", err)
					}
					if got := authorityBundleHandles(t, base); !reflect.DeepEqual(got, handles) {
						t.Fatal("acquisition changed descriptor ownership", handles, got)
					}
					continue
				}
				if err != nil || bundle == nil {
					t.Fatal("valid bundle refused", err)
				}
				defer func() { _ = bundle.Close() }()
				for _, f := range []*os.File{bundle.Launch, bundle.Image, bundle.State, bundle.Endpoint} {
					if f == nil {
						t.Fatal("incomplete bundle")
					}
					flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
					if err != nil || flags&unix.FD_CLOEXEC == 0 {
						t.Fatal("inheritable bundle", err)
					}
				}
				for _, f := range parents {
					if err := f.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := root.Remove("inputs/launch.json"); err != nil {
					t.Fatal(err)
				}
				if err := root.Remove("inputs/syswarden-authority"); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadAuthorityLaunch(bundle.Launch, ld); err != nil {
					t.Fatal(err)
				}
				if _, err := InspectAuthorityExecutableImage(bundle.Image, id); err != nil {
					t.Fatal(err)
				}
				if _, err := attestAuthorityRuntimeDirectory(int(bundle.State.Fd()), c.ServiceUID, c.ServiceGID, 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := attestAuthorityRuntimeDirectory(int(bundle.Endpoint.Fd()), c.ServiceUID, c.EndpointGID, 0750); err != nil {
					t.Fatal(err)
				}
				owned := [4]*os.File{bundle.Launch, bundle.Image, bundle.State, bundle.Endpoint}
				if err := bundle.Close(); err != nil {
					t.Fatal(err)
				}
				for _, f := range owned {
					if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("bundle close leaked", err)
					}
				}
			}
		})
	}
}

func authorityBundleHandles(t *testing.T, base string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]string)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if target == base || strings.HasPrefix(target, base+"/") || strings.HasPrefix(target, "/memfd:syswarden-") {
			found[entry.Name()] = target
		}
	}
	return found
}

func prepareActualAuthorityBundle(t, owner *testing.T, binary *executableImages, c processFixtureConfig) {
	t.Helper()
	directory := owner.TempDir()
	if err := chmodFixture(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("launch.json", readFile(t, c.LaunchPath), 0400); err != nil {
		t.Fatal(err)
	}
	st, err := binary.authority.Stat()
	if err != nil || st.Size() <= 0 || st.Size() > MaxAuthorityExecutableBytes {
		t.Fatal("invalid verified image size", err)
	}
	data := make([]byte, int(st.Size()))
	if _, err := binary.authority.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("syswarden-authority", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("syswarden-authority", 0555); err != nil {
		t.Fatal(err)
	}
	inputs, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inputs.Close() }()
	sp, err := os.Open(filepath.Dir(c.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ep, err := os.Open(filepath.Dir(c.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	before := adversarialSnapshot(t, c.Paths)
	bundle, err := OpenAuthorityLaunchBundle(inputs, sp, ep, c.LaunchDigest, binary.digest)
	if err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() { _ = bundle.Close() })
	for _, f := range []*os.File{binary.launch, binary.authority, binary.state, binary.endpoint} {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	binary.launch, binary.authority, binary.state, binary.endpoint = bundle.Launch, bundle.Image, bundle.State, bundle.Endpoint
	for _, name := range []string{"launch.json", "syswarden-authority"} {
		if err := root.Remove(name); err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(name, []byte("unapproved replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	requireAdversarialSnapshot(t, before, c.Paths)
	// Caller parents and old acquisition handles close before actual startup.
	// Only this complete bundle supplies the four resources to both real paths.
}
