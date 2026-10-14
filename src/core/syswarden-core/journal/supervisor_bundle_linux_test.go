package journal

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAuthoritySupervisorBundleClose(t *testing.T) {
	if err := (*AuthoritySupervisorBundle)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"complete", "partial", "bundle-error", "launcher-error"} {
		t.Run(kind, func(t *testing.T) {
			var files [5]*os.File
			for i := range files {
				f, err := os.CreateTemp(t.TempDir(), "owned")
				if err != nil {
					t.Fatal(err)
				}
				files[i] = f
				t.Cleanup(func() { _ = f.Close() })
			}
			b := &AuthoritySupervisorBundle{Bundle: &AuthorityLaunchBundle{Launch: files[0], Image: files[1], State: files[2], Endpoint: files[3]}, Launcher: files[4]}
			switch kind {
			case "partial":
				if err := b.Bundle.Close(); err != nil {
					t.Fatal(err)
				}
				b.Bundle = nil
			case "bundle-error":
				_ = files[0].Close()
			case "launcher-error":
				_ = files[4].Close()
			}
			err := b.Close()
			if (err != nil) != strings.HasSuffix(kind, "error") {
				t.Fatal("incorrect close result", err)
			}
			if b.Bundle != nil || b.Launcher != nil {
				t.Fatal("supervisor bundle not consumed")
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
	if b, err := openAuthoritySupervisorBundle(-1, strings.Repeat("0", 64), nil); b != nil || !errors.Is(err, ErrAuthoritySupervisorBundle) {
		t.Fatal("nil acquisition accepted", err)
	}
}

// These composition cases run only in the mandatory disposable root fixture.
func testAuthoritySupervisorBundle(t *testing.T, launchBytes []byte) {
	c, err := DecodeAuthorityLaunch(launchBytes)
	if err != nil {
		t.Fatal(err)
	}
	imageBytes := testAuthorityELF(runtime.GOARCH, false)
	cases := []string{"valid-held", "nil-inputs", "nil-state", "nil-endpoint", "closed-inputs", "wrong-launch-digest", "wrong-image-digest", "wrong-launcher-digest", "malformed-launcher-digest", "parent-mode", "launcher-missing", "launcher-symlink", "launcher-hardlink", "launcher-fifo", "launcher-owner", "launcher-group", "launcher-mode", "launcher-acl", "launcher-file-capability", "launcher-invalid-elf", "repeated-runtime-refusal", "replacement-during-acquisition", "modification-during-acquisition", "parent-change-during-acquisition", "partial-acquisition-failure"}
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
			launcherBytes := imageBytes
			if kind == "launcher-invalid-elf" {
				launcherBytes = []byte("#!/bin/sh\nexit 0\n")
			}
			if err := root.WriteFile("inputs/launch.json", launchBytes, 0400); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string][]byte{"inputs/syswarden-authority": imageBytes, "inputs/" + authorityLauncherInputName: launcherBytes} {
				if err := root.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := root.Chmod(name, 0555); err != nil {
					t.Fatal(err)
				}
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
			a, s, e := parents[0], parents[1], parents[2]
			ld, id, xd := recoveryDigest(launchBytes), recoveryDigest(imageBytes), recoveryDigest(launcherBytes)
			name := "inputs/" + authorityLauncherInputName
			attempts := 1
			switch kind {
			case "nil-inputs":
				a = nil
			case "nil-state":
				s = nil
			case "nil-endpoint":
				e = nil
			case "closed-inputs":
				_ = a.Close()
			case "wrong-launch-digest":
				ld = strings.Repeat("0", 64)
			case "wrong-image-digest":
				id = strings.Repeat("0", 64)
			case "wrong-launcher-digest":
				xd = strings.Repeat("0", 64)
			case "malformed-launcher-digest":
				xd = "bad"
			case "parent-mode":
				err = root.Chmod("inputs", 0755)
			case "launcher-missing":
				err = root.Remove(name)
			case "launcher-symlink":
				if err = root.Rename(name, name+".original"); err == nil {
					err = root.Symlink(authorityLauncherInputName+".original", name)
				}
			case "launcher-hardlink":
				err = root.Link(name, "inputs/alias")
			case "launcher-fifo":
				if err = root.Remove(name); err == nil {
					err = unix.Mkfifo(filepath.Join(base, name), 0400)
				}
			case "launcher-owner":
				err = root.Chown(name, 1, 0)
			case "launcher-group":
				err = root.Chown(name, 0, 1)
			case "launcher-mode":
				err = root.Chmod(name, 0755)
			case "launcher-acl":
				authorityTestACL(t, filepath.Join(base, name), "system.posix_acl_access")
				err = root.Chmod(name, 0555)
			case "launcher-file-capability":
				capability := make([]byte, 20)
				binary.LittleEndian.PutUint32(capability, 0x02000001)
				binary.LittleEndian.PutUint32(capability[4:], 1<<unix.CAP_NET_BIND_SERVICE)
				err = unix.Setxattr(filepath.Join(base, name), "security.capability", capability, 0)
			case "repeated-runtime-refusal":
				err = root.Chown("public/endpoint", 1, -1)
				attempts = 12
			}
			if err != nil {
				t.Fatal("fixture prerequisite", err)
			}
			paths := []string{base}
			for _, path := range []string{"inputs", "private", "public", "private/state", "public/endpoint", "inputs/launch.json", "inputs/syswarden-authority", name, name + ".original", "inputs/alias"} {
				paths = append(paths, filepath.Join(base, path))
			}
			before := endpointRecoverySnapshot(t, paths)
			handles := authorityBundleHandles(t, base)
			for attempt := 0; attempt < attempts; attempt++ {
				var bundle *AuthoritySupervisorBundle
				var err error
				if strings.HasSuffix(kind, "during-acquisition") || kind == "partial-acquisition-failure" {
					bundle, err = openAuthoritySupervisorBundle(int(a.Fd()), xd, func() (*AuthorityLaunchBundle, error) {
						acquired, err := OpenAuthorityLaunchBundle(a, s, e, ld, id)
						if err != nil {
							return acquired, err
						}
						switch kind {
						case "replacement-during-acquisition":
							if err = root.Rename(name, name+".original"); err == nil {
								err = root.WriteFile(name, []byte("unapproved replacement"), 0600)
							}
						case "modification-during-acquisition":
							err = root.WriteFile(name, []byte("unapproved replacement"), 0600)
						case "parent-change-during-acquisition":
							err = root.Chmod("inputs", 0755)
						case "partial-acquisition-failure":
							return acquired, os.ErrPermission
						}
						if err != nil {
							_ = acquired.Close()
							t.Fatal("fixture mutation failed", err)
						}
						before = endpointRecoverySnapshot(t, paths)
						return acquired, nil
					})
				} else {
					bundle, err = OpenAuthoritySupervisorBundle(a, s, e, ld, id, xd)
				}
				requireEndpointRecoverySnapshot(t, before, paths)
				if kind != "valid-held" {
					if bundle != nil {
						_ = bundle.Close()
						t.Fatal("partial supervisor bundle escaped")
					}
					if !errors.Is(err, ErrAuthoritySupervisorBundle) {
						t.Fatal("unsafe supervisor bundle admitted", err)
					}
					if got := authorityBundleHandles(t, base); !reflect.DeepEqual(got, handles) {
						t.Fatal("acquisition changed descriptor ownership", handles, got)
					}
					continue
				}
				if err != nil || bundle == nil || bundle.Bundle == nil {
					t.Fatal("valid supervisor bundle refused", err)
				}
				defer func() { _ = bundle.Close() }()
				owned := []*os.File{bundle.Bundle.Launch, bundle.Bundle.Image, bundle.Bundle.State, bundle.Bundle.Endpoint, bundle.Launcher}
				for _, f := range owned {
					if f == nil {
						t.Fatal("incomplete supervisor bundle")
					}
					flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
					if err != nil || flags&unix.FD_CLOEXEC == 0 {
						t.Fatal("inheritable supervisor input", err)
					}
				}
				for _, f := range parents {
					if err := f.Close(); err != nil {
						t.Fatal("borrowed parent unexpectedly consumed", err)
					}
				}
				for _, path := range []string{"inputs/launch.json", "inputs/syswarden-authority", name} {
					if err := root.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := root.WriteFile(path, []byte("unapproved replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := LoadAuthorityLaunch(bundle.Bundle.Launch, ld); err != nil {
					t.Fatal(err)
				}
				if _, err := InspectAuthorityExecutableImage(bundle.Bundle.Image, id); err != nil {
					t.Fatal(err)
				}
				if _, err := InspectAuthorityExecutableImage(bundle.Launcher, xd); err != nil {
					t.Fatal(err)
				}
				if _, err := attestAuthorityRuntimeDirectory(int(bundle.Bundle.State.Fd()), c.ServiceUID, c.ServiceGID, 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := attestAuthorityRuntimeDirectory(int(bundle.Bundle.Endpoint.Fd()), c.ServiceUID, c.EndpointGID, 0750); err != nil {
					t.Fatal(err)
				}
				var fresh [3]*os.File
				for i, path := range []string{"inputs", "private", "public"} {
					f, err := root.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					fresh[i] = f
					defer func() { _ = f.Close() }()
				}
				again, err := OpenAuthoritySupervisorBundle(fresh[0], fresh[1], fresh[2], ld, id, xd)
				if again != nil || err == nil {
					_ = again.Close()
					t.Fatal("unapproved replacement reacquired")
				}
				if err := bundle.Close(); err != nil {
					t.Fatal(err)
				}
				for _, f := range owned {
					if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("supervisor close leaked", err)
					}
				}
			}
		})
	}
}

func prepareActualAuthoritySupervisorBundle(t, owner *testing.T, images *executableImages, c processFixtureConfig) {
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
	for name, source := range map[string]*os.File{"syswarden-authority": images.authority, authorityLauncherInputName: images.launcher} {
		st, err := source.Stat()
		if err != nil || st.Size() <= 0 || st.Size() > MaxAuthorityExecutableBytes {
			t.Fatal("invalid verified image size", err)
		}
		data := make([]byte, int(st.Size()))
		if _, err := source.ReadAt(data, 0); err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := root.Chmod(name, 0555); err != nil {
			t.Fatal(err)
		}
	}
	inputs, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inputs.Close() }()
	sp, err := openFixtureDirectory(filepath.Dir(c.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ep, err := openFixtureDirectory(filepath.Dir(c.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	before := adversarialSnapshot(t, c.Paths)
	bundle, err := OpenAuthoritySupervisorBundle(inputs, sp, ep, c.LaunchDigest, images.digest, os.Getenv("SYSWARDEN_AUTHORITY_LAUNCHER_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() { _ = bundle.Close() })
	for _, f := range []*os.File{images.launch, images.authority, images.state, images.endpoint, images.launcher} {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	images.launch, images.authority, images.state, images.endpoint, images.launcher = bundle.Bundle.Launch, bundle.Bundle.Image, bundle.Bundle.State, bundle.Bundle.Endpoint, bundle.Launcher
	for _, name := range []string{"launch.json", "syswarden-authority", authorityLauncherInputName} {
		if err := root.Remove(name); err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(name, []byte("unapproved replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	requireAdversarialSnapshot(t, before, c.Paths)
	// All caller parents close before actual process creation and lifecycle tests.
}
