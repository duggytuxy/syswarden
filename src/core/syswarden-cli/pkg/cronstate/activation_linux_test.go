//go:build linux

package cronstate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestActivationPreflightRefusesBusyDirectoryImmediately(t *testing.T) {
	options, path := testCronOptions(t, &testLegacyReader{})
	// #nosec G304 -- path is the cron directory created by testCronOptions inside this test's private root.
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			t.Errorf("unlock fixture cron directory: %v", err)
		}
	}()
	finished := make(chan error, 1)
	go func() { _, _, err := PreflightForActivation(options, false); finished <- err }()
	select {
	case err := <-finished:
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("expected immediate busy refusal, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation preflight blocked on a directory lock")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("lock inspection created artifacts: %v %v", entries, err)
	}
}

func TestActivationPreflightEvidenceAndNoWrites(t *testing.T) {
	reader := &testLegacyReader{content: "# administrator record without newline", present: true}
	options, path := testCronOptions(t, reader)
	content := ownedCronHeader + ownedFeedLine(options.CLIPath, 17) + "\n"
	file := filepath.Join(path, options.FileName)
	// #nosec G306 -- fixture intentionally uses the supported public 0644 cron.d schedule mode.
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	inspection, digest, err := PreflightForActivation(options, false)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.OwnedFeed || inspection.FeedMinute != 17 || len(digest) != 64 {
		t.Fatalf("unexpected result: %+v %s", inspection, digest)
	}
	_, again, err := PreflightForActivation(options, false)
	if err != nil || again != digest {
		t.Fatalf("unstable unchanged evidence: %s %s %v", digest, again, err)
	}
	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, _ := unixStat(before)
	afterStat, _ := unixStat(after)
	if beforeStat.Ino != afterStat.Ino || beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim {
		t.Fatal("preflight modified owned cron metadata")
	}
	// #nosec G304 -- read only the owned schedule created in this test's private cron directory.
	actual, err := os.ReadFile(file)
	if err != nil || string(actual) != content {
		t.Fatal("preflight changed cron bytes")
	}
	reader.set("# changed administrator record without newline", true)
	_, changed, err := PreflightForActivation(options, false)
	if err != nil || changed == digest {
		t.Fatalf("legacy bytes did not bind digest: %v", err)
	}
	// #nosec G306 -- the replacement fixture retains the deployed 0644 cron.d mode while changing its inode.
	if err := os.WriteFile(file+"-replacement", []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file+"-replacement", file); err != nil {
		t.Fatal(err)
	}
	_, replaced, err := PreflightForActivation(options, false)
	if err != nil || replaced == changed {
		t.Fatalf("owned inode did not bind digest: %v", err)
	}
}

func TestActivationPreflightRejectsUnresolvedAndUnsafeState(t *testing.T) {
	for _, name := range []string{pendingFileName, retiredFileName, transactionFileName, transactionRetired, commitFileName, commitRetired, "fifo", "symlink", "ha"} {
		t.Run(name, func(t *testing.T) {
			options, path := testCronOptions(t, &testLegacyReader{})
			file := filepath.Join(path, name)
			switch name {
			case "fifo":
				file = filepath.Join(path, options.FileName)
				if err := syscall.Mkfifo(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				file = filepath.Join(path, options.FileName)
				if err := os.Symlink("missing", file); err != nil {
					t.Fatal(err)
				}
			case "ha":
				file = filepath.Join(path, options.FileName)
				// #nosec G306 -- this 0644 fixture verifies an existing HA schedule is refused when HA is disabled.
				if err := os.WriteFile(file, []byte(ownedCronHeader+ownedHALine(options.CLIPath)+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(file, []byte("unresolved"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := PreflightForActivation(options, false)
			if err == nil || digest != "" {
				t.Fatal("unsafe or unresolved state accepted")
			}
			after, err := os.Lstat(file)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("refusal modified evidence")
			}
		})
	}
}

func TestActivationPreflightRejectsSourceAndProviderDrift(t *testing.T) {
	for _, kind := range []string{"legacy", "directory", "provider"} {
		t.Run(kind, func(t *testing.T) {
			reader := &testLegacyReader{content: "# unchanged\n", present: true}
			options, path := testCronOptions(t, reader)
			calls := 0
			options.AttestCronDProvider = func() error {
				calls++
				if calls == 2 {
					switch kind {
					case "legacy":
						reader.set("# changed\n", true)
					case "directory":
						if err := os.Rename(path, path+"-old"); err != nil {
							return err
						}
						// #nosec G301 -- replace the private fixture's cron directory with its normal 0755 mode to test inode drift.
						return os.Mkdir(path, 0755)
					case "provider":
						return errors.New("provider changed")
					}
				}
				return nil
			}
			if _, _, err := PreflightForActivation(options, false); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}
