package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityChildStartupInvalid(t *testing.T) {
	if child, err := StartAuthorityChildFromInputs(AuthorityChildInputs{}); child != nil || !errors.Is(err, ErrAuthorityChildStartup) {
		t.Fatal("empty inputs admitted", err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	good := AuthorityChildInputs{Inputs: null, StateParent: null, EndpointParent: null, Null: null, LaunchSHA256: strings.Repeat("a", 64), ImageSHA256: strings.Repeat("b", 64), LauncherSHA256: strings.Repeat("c", 64)}
	for _, kind := range []string{"nil-inputs", "nil-state", "nil-endpoint", "nil-null", "bad-launch", "bad-image", "bad-launcher", "non-root-or-invalid-parent"} {
		t.Run(kind, func(t *testing.T) {
			c := good
			switch kind {
			case "nil-inputs":
				c.Inputs = nil
			case "nil-state":
				c.StateParent = nil
			case "nil-endpoint":
				c.EndpointParent = nil
			case "nil-null":
				c.Null = nil
			case "bad-launch":
				c.LaunchSHA256 = "bad"
			case "bad-image":
				c.ImageSHA256 = "bad"
			case "bad-launcher":
				c.LauncherSHA256 = "bad"
			}
			if child, err := StartAuthorityChildFromInputs(c); child != nil || !errors.Is(err, ErrAuthorityChildStartup) {
				t.Fatal("invalid startup admitted", err)
			}
		})
	}
}

func TestAuthorityChildStartupMissingFactory(t *testing.T) {
	acquire := func() (*AuthoritySupervisorBundle, error) {
		t.Fatal("missing factory reached acquisition")
		return nil, nil
	}
	start := func(AuthorityChildConfig) (*AuthorityChild, error) {
		t.Fatal("missing factory reached start")
		return nil, nil
	}
	if child, err := startAuthorityChildFromInputs(AuthorityChildInputs{}, nil, start); child != nil || err == nil {
		t.Fatal("nil acquisition accepted", err)
	}
	if child, err := startAuthorityChildFromInputs(AuthorityChildInputs{}, acquire, nil); child != nil || err == nil {
		t.Fatal("nil creation accepted", err)
	}
	if child, err := startAuthorityChildFromInputs(AuthorityChildInputs{}, func() (*AuthoritySupervisorBundle, error) { return nil, nil }, start); child != nil || err == nil {
		t.Fatal("missing acquisition result accepted", err)
	}
}

func testAuthorityChildStartup(t *testing.T, images executableImages, c processFixtureConfig) {
	for _, kind := range []string{"lifecycle", "independent-handoff", "wrong-launch-digest", "wrong-image-digest", "wrong-launcher-digest", "closed-inputs", "nil-null", "read-only-null", "closed-null", "regular-null", "runtime-refusal", "creation-refusal", "partial-acquisition-failure", "nil-start-result", "post-start-close-failure", "post-start-error", "startup-failure"} {
		t.Run(kind, func(t *testing.T) {
			input, root := authorityChildInputFixture(t, images, c)
			original := input
			parentConfig := AuthorityChildConfig{Bundle: &AuthorityLaunchBundle{Launch: images.launch, Image: images.authority, State: images.state, Endpoint: images.endpoint}, Launcher: images.launcher, Null: original.Null}
			parent := authorityChildParentSnapshot(t, parentConfig)
			switch kind {
			case "wrong-launch-digest":
				input.LaunchSHA256 = strings.Repeat("0", 64)
			case "wrong-image-digest":
				input.ImageSHA256 = strings.Repeat("0", 64)
			case "wrong-launcher-digest":
				input.LauncherSHA256 = strings.Repeat("0", 64)
			case "closed-inputs":
				_ = input.Inputs.Close()
			case "nil-null":
				input.Null = nil
			case "closed-null":
				input.Null = duplicateReadinessWriter(t, original.Null)
				_ = input.Null.Close()
			case "read-only-null":
				var err error
				input.Null, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = input.Null.Close() }()
			case "regular-null":
				var err error
				input.Null, err = os.CreateTemp(t.TempDir(), "not-null")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = input.Null.Close() }()
			case "runtime-refusal":
				input.EndpointParent = input.StateParent
			case "startup-failure":
				if err := root.Mkdir("empty-runtime", 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Mkdir("empty-runtime/state", 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Chown("empty-runtime/state", int(processServiceID), int(processServiceID)); err != nil {
					t.Fatal(err)
				}
				var err error
				input.StateParent, err = root.Open("empty-runtime")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = input.StateParent.Close() }()
			}
			before := adversarialSnapshot(t, c.Paths)
			paths := []string{root.Name(), filepath.Join(root.Name(), "launch.json"), filepath.Join(root.Name(), "syswarden-authority"), filepath.Join(root.Name(), authorityLauncherInputName)}
			sources := endpointRecoverySnapshot(t, paths)
			handles := authorityChildHandleInventory(t)
			acquire := func() (*AuthoritySupervisorBundle, error) {
				return OpenAuthoritySupervisorBundle(input.Inputs, input.StateParent, input.EndpointParent, input.LaunchSHA256, input.ImageSHA256, input.LauncherSHA256)
			}
			var child *AuthorityChild
			var err error
			attempts := 1
			if kind == "creation-refusal" {
				attempts = 12
			}
			for range attempts {
				switch kind {
				case "partial-acquisition-failure":
					child, err = startAuthorityChildFromInputs(input, func() (*AuthoritySupervisorBundle, error) {
						b, e := acquire()
						return b, errors.Join(e, os.ErrPermission)
					}, func(AuthorityChildConfig) (*AuthorityChild, error) {
						t.Fatal("partial acquisition reached process creation")
						return nil, nil
					})
				case "nil-start-result":
					child, err = startAuthorityChildFromInputs(input, acquire, func(AuthorityChildConfig) (*AuthorityChild, error) { return nil, nil })
				case "creation-refusal":
					calls := 0
					child, err = startAuthorityChildFromInputs(input, acquire, func(conf AuthorityChildConfig) (*AuthorityChild, error) {
						return startAuthorityChild(conf, func(string, []string, *os.ProcAttr) (*os.Process, error) { calls++; return nil, unix.EAGAIN })
					})
					if calls != 1 || !errors.Is(err, unix.EAGAIN) {
						t.Fatal("creation retried or error lost", calls, err)
					}
				case "post-start-close-failure", "post-start-error":
					child, err = startAuthorityChildFromInputs(input, acquire, func(conf AuthorityChildConfig) (*AuthorityChild, error) {
						started, e := StartAuthorityChild(conf)
						if e != nil || started == nil {
							return started, e
						}
						if kind == "post-start-close-failure" {
							if closeErr := conf.Launcher.Close(); closeErr != nil {
								t.Error(closeErr)
							}
							return started, nil
						}
						return started, unix.EIO
					})
				default:
					child, err = StartAuthorityChildFromInputs(input)
				}
				if child != nil {
					cleanupAuthorityTestChild(t, child)
				}
				uncertain := kind == "post-start-close-failure" || kind == "post-start-error"
				successful := kind == "lifecycle" || kind == "independent-handoff" || kind == "startup-failure"
				if !successful && !uncertain {
					if child != nil || !errors.Is(err, ErrAuthorityChildStartup) {
						t.Fatal("invalid startup created child", err)
					}
					requireAdversarialSnapshot(t, before, c.Paths)
					requireEndpointRecoverySnapshot(t, sources, paths)
					requireExecutableCleanup(t, c)
					if !reflect.DeepEqual(handles, authorityChildHandleInventory(t)) {
						t.Fatal("refused startup leaked handles")
					}
					continue
				}
				if child == nil || child.PID() <= 0 || (!uncertain && err != nil) {
					t.Fatal("startup lost child", err)
				}
				wanted := error(os.ErrClosed)
				if kind == "post-start-error" {
					wanted = unix.EIO
				}
				if uncertain && (!errors.Is(err, ErrAuthorityChildStartup) || !errors.Is(err, wanted)) {
					t.Fatal("post-start uncertainty lost", err)
				}
				if !reflect.DeepEqual(parent, authorityChildParentSnapshot(t, parentConfig)) {
					t.Fatal("parent credentials, limits or borrowed flags changed")
				}
				// Closing all borrowed inputs and replacing source names must not affect
				// the child. Remove those deliberately closed descriptors from the inventory.
				if kind == "independent-handoff" {
					for _, f := range []*os.File{input.Inputs, input.StateParent, input.EndpointParent, input.Null} {
						delete(handles, strconv.FormatUint(uint64(f.Fd()), 10))
						if err := f.Close(); err != nil {
							t.Fatal(err)
						}
					}
					for _, name := range []string{"launch.json", "syswarden-authority", authorityLauncherInputName} {
						if err := root.Remove(name); err != nil {
							t.Fatal(err)
						}
						if err := root.WriteFile(name, []byte("unapproved replacement"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					sources = endpointRecoverySnapshot(t, paths)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if kind == "startup-failure" {
					if err := child.AwaitReady(ctx); err == nil {
						t.Fatal("missing private state reported ready")
					}
					state, e := child.Wait(ctx)
					if state == nil || state.ExitCode() != 1 || !errors.Is(e, ErrAuthorityChildExit) {
						t.Fatal("failed startup lost verdict", state, e)
					}
				} else {
					if uncertain {
						if !errors.Is(child.AwaitReady(ctx), ErrAuthorityChild) {
							t.Fatal("uncertain startup reported ready")
						}
						// Test-only observation permits graceful cleanup without discarding the
						// sticky public failure verdict or bypassing production admission.
						if e := child.readiness.Wait(ctx); e != nil {
							t.Fatal(e)
						}
					} else if e := child.AwaitReady(ctx); e != nil {
						t.Fatal(e)
					}
					requireExecutableIdentity(t, child.PID())
					client := c
					client.ServicePID = child.PID()
					runProcessClient(t, "resume", client, processClientID)
					if !errors.Is(child.Close(), ErrAuthorityChildRunning) {
						t.Fatal("live ownership discarded")
					}
					if e := child.RequestStop(); e != nil {
						t.Fatal(e)
					}
					state, e := child.Wait(ctx)
					if state == nil || !state.Success() || (!uncertain && e != nil) || (uncertain && !errors.Is(e, wanted)) {
						t.Fatal("incorrect exit verdict", state, e)
					}
					again, e := child.Wait(ctx)
					if again != state || (!uncertain && e != nil) || (uncertain && !errors.Is(e, wanted)) {
						t.Fatal("cached wait lost verdict", e)
					}
				}
				closeErr := child.Close()
				if (!uncertain && closeErr != nil) || (uncertain && !errors.Is(closeErr, wanted)) {
					t.Fatal("close lost outcome", closeErr)
				}
				requireAdversarialSnapshot(t, before, c.Paths)
				requireEndpointRecoverySnapshot(t, sources, paths)
				requireExecutableCleanup(t, c)
				if !reflect.DeepEqual(handles, authorityChildHandleInventory(t)) {
					t.Fatal("completed startup leaked handles")
				}
			}
		})
	}
}

func authorityChildInputFixture(t *testing.T, images executableImages, c processFixtureConfig) (AuthorityChildInputs, *os.Root) {
	t.Helper()
	directory := t.TempDir()
	if err := chmodFixture(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
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
	input := AuthorityChildInputs{LaunchSHA256: c.LaunchDigest, ImageSHA256: images.digest, LauncherSHA256: os.Getenv("SYSWARDEN_AUTHORITY_LAUNCHER_SHA256")}
	input.Inputs, err = root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Inputs.Close() })
	input.StateParent, err = openFixtureDirectory(filepath.Dir(c.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.StateParent.Close() })
	input.EndpointParent, err = openFixtureDirectory(filepath.Dir(c.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.EndpointParent.Close() })
	input.Null, err = os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Null.Close() })
	return input, root
}
