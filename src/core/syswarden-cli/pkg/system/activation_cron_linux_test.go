//go:build linux

package system

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func activationCronTestProvider(name string) CronDProviderEvidence {
	switch name {
	case "debian":
		return CronDProviderEvidence{Mode: CronDProviderRuntime, Manager: "systemd", Unit: "cron.service", Daemon: "/usr/sbin/cron", Fragment: "/usr/lib/systemd/system/cron.service", Packages: []string{"cron"}}
	case "alpine":
		return CronDProviderEvidence{Mode: CronDProviderRuntime, Manager: "openrc", Unit: "cronie", Daemon: "/usr/sbin/crond", Fragment: "/etc/init.d/cronie", Packages: []string{"cronie", "cronie-openrc"}, DefaultRunlevel: true}
	default:
		return CronDProviderEvidence{Mode: CronDProviderRuntime, Manager: "systemd", Unit: "crond.service", Daemon: "/usr/sbin/crond", Fragment: "/usr/lib/systemd/system/crond.service", Packages: []string{"cronie"}}
	}
}

func activationCronTestRoot(t *testing.T, provider CronDProviderEvidence) (string, string) {
	t.Helper()
	root := t.TempDir()
	spool, err := activationCronSpoolForProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{spool, "/etc/cron.d"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, spool, "root")
}

func activationCronTree(t *testing.T, root string) map[string]removalArtifactIdentity {
	t.Helper()
	result := map[string]removalArtifactIdentity{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity, err := exactRemovalArtifactIdentity(info)
		if err != nil {
			return err
		}
		result[path] = identity
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func activationCronTestOwner(t *testing.T, root string) *syscall.Stat_t {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership unavailable")
	}
	return owner
}

func runActivationCronTest(t *testing.T, root string, provider CronDProviderEvidence, verify func() error) (string, error) {
	t.Helper()
	owner := activationCronTestOwner(t, root)
	_, digest, err := preflightActivationCronAt(context.Background(), provider, false, verify, root, owner.Uid, owner.Gid)
	return digest, err
}

func TestActivationCronProvidersExactBytesAbsenceAndNoWrites(t *testing.T) {
	for _, name := range []string{"debian", "alpine", "rpm"} {
		t.Run(name, func(t *testing.T) {
			provider := activationCronTestProvider(name)
			root, file := activationCronTestRoot(t, provider)
			if name == "debian" {
				if err := os.Chmod(filepath.Dir(file), os.ModeSticky|0730); err != nil {
					t.Fatal(err)
				}
			}
			var previous string
			for _, content := range []string{"absent", "", "# administrator comment\n  # exact whitespace without final newline"} {
				if content != "absent" {
					if err := os.WriteFile(file, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before := activationCronTree(t, root)
				digest, err := runActivationCronTest(t, root, provider, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				if len(digest) != 64 || digest == previous {
					t.Fatal("absence or exact content not bound to digest")
				}
				again, err := runActivationCronTest(t, root, provider, func() error { return nil })
				if err != nil || again != digest {
					t.Fatalf("unchanged evidence unstable: %v", err)
				}
				if !reflect.DeepEqual(before, activationCronTree(t, root)) {
					t.Fatal("preflight changed filesystem metadata or inventory")
				}
				if content != "absent" {
					reader, err := os.OpenRoot(root)
					if err != nil {
						t.Fatal(err)
					}
					relative, err := filepath.Rel(root, file)
					if err != nil {
						t.Fatal(errors.Join(err, reader.Close()))
					}
					actual, err := reader.ReadFile(relative)
					err = errors.Join(err, reader.Close())
					if err != nil || string(actual) != content {
						t.Fatal("preflight rewrote root crontab")
					}
				}
				previous = digest
			}
		})
	}
}

func TestActivationCronRejectsUnsafeSpoolAndFileWithoutWrites(t *testing.T) {
	for _, kind := range []string{"missing-spool", "ancestor-symlink", "ancestor-writable", "spool-world-writable", "spool-group-writable", "symlink", "fifo", "hardlink", "mode", "oversized", "nul"} {
		t.Run(kind, func(t *testing.T) {
			provider := activationCronTestProvider("rpm")
			root, file := activationCronTestRoot(t, provider)
			var err error
			switch kind {
			case "missing-spool":
				err = os.Remove(filepath.Dir(file))
			case "ancestor-symlink":
				path := filepath.Join(root, "var")
				if err = os.Rename(path, path+"-old"); err == nil {
					err = os.Symlink("var-old", path)
				}
			case "ancestor-writable":
				err = os.Chmod(filepath.Join(root, "var"), 0777) // #nosec G302 -- deliberately unsafe fixture verifies ancestor mode refusal.
			case "spool-world-writable":
				err = os.Chmod(filepath.Dir(file), 0777) // #nosec G302 -- deliberately unsafe fixture verifies world-writable spool refusal.
			case "spool-group-writable":
				err = os.Chmod(filepath.Dir(file), 0770) // #nosec G302 -- deliberately unsafe fixture verifies group-writable spool refusal.
			case "symlink":
				err = os.Symlink("missing", file)
			case "fifo":
				err = syscall.Mkfifo(file, 0600)
			case "hardlink":
				if err = os.WriteFile(file, []byte("# private\n"), 0600); err == nil {
					err = os.Link(file, file+"-other")
				}
			case "mode":
				err = os.WriteFile(file, []byte("# private\n"), 0644) // #nosec G306 -- deliberately unsafe fixture verifies root crontab mode refusal.
			case "oversized":
				err = os.WriteFile(file, []byte(strings.Repeat("#", (1<<20)+1)), 0600)
			case "nul":
				err = os.WriteFile(file, []byte("# invalid\x00"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := activationCronTree(t, root)
			if digest, err := runActivationCronTest(t, root, provider, func() error { return nil }); err == nil || digest != "" {
				t.Fatal("unsafe evidence accepted")
			}
			if !reflect.DeepEqual(before, activationCronTree(t, root)) {
				t.Fatal("refusal changed filesystem evidence")
			}
		})
	}
}

func TestActivationCronRejectsProviderAndMetadataDrift(t *testing.T) {
	for _, kind := range []string{"metadata", "content", "appearance", "disappearance", "provider"} {
		t.Run(kind, func(t *testing.T) {
			provider := activationCronTestProvider("debian")
			root, file := activationCronTestRoot(t, provider)
			if kind != "appearance" {
				if err := os.WriteFile(file, []byte("# exact\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			verify := func() error {
				calls++
				if calls != 2 {
					return nil
				}
				switch kind {
				case "metadata":
					return os.Chtimes(file, time.Unix(1234, 0), time.Unix(1234, 0))
				case "content", "appearance":
					return os.WriteFile(file, []byte("# replaced\n"), 0600)
				case "disappearance":
					return os.Remove(file)
				default:
					return errors.New("provider changed")
				}
			}
			if digest, err := runActivationCronTest(t, root, provider, verify); err == nil || digest != "" {
				t.Fatal("live evidence drift accepted")
			}
		})
	}
}

func TestActivationCronMetadataOnlyChangesDigest(t *testing.T) {
	provider := activationCronTestProvider("alpine")
	root, file := activationCronTestRoot(t, provider)
	if err := os.WriteFile(file, []byte("# same bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := runActivationCronTest(t, root, provider, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, time.Unix(1234, 0), time.Unix(1234, 0)); err != nil {
		t.Fatal(err)
	}
	second, err := runActivationCronTest(t, root, provider, func() error { return nil })
	if err != nil || second == first {
		t.Fatalf("metadata not bound to digest: %v", err)
	}
}

func TestActivationCronRejectsUnknownProviderAndCancelledContext(t *testing.T) {
	provider := activationCronTestProvider("rpm")
	root, _ := activationCronTestRoot(t, provider)
	for _, mutate := range []func(*CronDProviderEvidence){
		func(p *CronDProviderEvidence) { p.Mode = CronDProviderOffline },
		func(p *CronDProviderEvidence) { p.Fragment = "/custom/crond.service" },
		func(p *CronDProviderEvidence) { p.Packages = []string{"unknown"} },
	} {
		changed := provider
		mutate(&changed)
		if _, err := runActivationCronTest(t, root, changed, func() error { return nil }); err == nil {
			t.Fatal("unverified provider accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	owner := activationCronTestOwner(t, root)
	_, _, err := preflightActivationCronAt(ctx, provider, false, func() error { called = true; return nil }, root, owner.Uid, owner.Gid)
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled preflight read provider")
	}
}
