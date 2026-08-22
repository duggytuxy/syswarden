//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"syswarden-cli/pkg/cronstate"
)

func TestReadOnlyRootCrontabGrammarAndFixedArguments_SW2_FWBACKEND_001(t *testing.T) {
	for _, testCase := range []struct {
		path string
		want []string
	}{
		{path: "/usr/bin/crontab", want: []string{"-l"}},
		{path: "/bin/busybox", want: []string{"crontab", "-l"}},
		{path: "/bin/busybox.nosuid", want: []string{"crontab", "-l"}},
	} {
		if got := readOnlyRootCrontabArguments(testCase.path); !reflect.DeepEqual(got, testCase.want) {
			t.Fatalf("arguments for %s = %#v, want %#v", testCase.path, got, testCase.want)
		}
	}

	operator := []byte("19 4 * * * /usr/local/bin/operator --exact  value\n")
	content, present, err := parseReadOnlyRootCrontabResult(operator, nil, nil)
	if err != nil || !present || content != string(operator) {
		t.Fatalf("operator bytes = %q present=%t error=%v", content, present, err)
	}
	for _, diagnostic := range []string{
		"no crontab for root\n",
		"crontab: no crontab for root\n",
		"crontab: can't open 'root': No such file or directory\n",
	} {
		content, present, err = parseReadOnlyRootCrontabResult(
			nil, []byte(diagnostic), fakeFirewallRemovalExitError(1),
		)
		if err != nil || present || content != "" {
			t.Fatalf("absence %q = %q present=%t error=%v", diagnostic, content, present, err)
		}
	}
	if _, _, err := parseReadOnlyRootCrontabResult(
		[]byte("partial"), []byte("no crontab for root\n"), fakeFirewallRemovalExitError(1),
	); err == nil {
		t.Fatal("partial output was accepted as absence")
	}
}

func TestReadOnlyRootCrontabCommandIsOutputBoundedAndTimed_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}

	writeProbe := func(name string, content string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for the isolated crontab probes
			t.Fatal(err)
		}
		return path
	}

	overflow := writeProbe(
		"crontab-overflow",
		"#!/bin/sh\n/usr/bin/head -c 70000 /dev/zero\n",
	)
	stdout, _, err := runReadOnlyRootCrontabCommandWithTimeout(
		overflow, cache, time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("overflow result = %v", err)
	}
	if len(stdout) != maximumFirewallPreflightOutput {
		t.Fatalf("bounded stdout length = %d, want %d", len(stdout), maximumFirewallPreflightOutput)
	}

	slow := writeProbe("crontab-slow", "#!/bin/sh\nexec /bin/sleep 2\n")
	started := time.Now()
	_, _, err = runReadOnlyRootCrontabCommandWithTimeout(
		slow, cache, 25*time.Millisecond,
	)
	if err == nil || !strings.Contains(err.Error(), "command exceeded") {
		t.Fatalf("timeout result = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded crontab command returned after %s", elapsed)
	}
}

func testRemovalCronOptions(t *testing.T, reader cronstate.RootCrontabReader) (cronstate.Options, string) {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil { // #nosec G302 -- owner-only mode secures this private cron fixture root
		t.Fatal(err)
	}
	cronPath := filepath.Join(rootPath, "etc", "cron.d")
	if err := os.MkdirAll(cronPath, 0755); err != nil { // #nosec G301 -- fixture models the root-owned system cron directory mode
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test filesystem lacks Unix identity")
	}
	options := cronstate.DefaultOptions(reader)
	options.RootPath = rootPath
	options.DirectoryOwnerUID = int(identity.Uid)
	options.DirectoryOwnerGID = int(identity.Gid)
	options.FileOwnerUID = int(identity.Uid)
	options.FileOwnerGID = int(identity.Gid)
	options.AttestCronDProvider = func() error { return nil }
	return options, cronPath
}

func TestRemovalCronCallerPreservesRootBytesAndRefusesLookalikes_SW2_FWBACKEND_001(t *testing.T) {
	operator := "19 4 * * * /usr/local/bin/operator --exact  value\n"
	reader := func() (string, bool, error) { return operator, true, nil }
	options, cronPath := testRemovalCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 17, nil }
	if _, err := cronstate.ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(cronPath, cronstate.DefaultFileName)
	if err := removeOwnedCronStateForRemovalWithOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ownedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned cron.d state remains: %v", err)
	}
	content, present, err := reader()
	if err != nil || !present || content != operator {
		t.Fatalf("root bytes changed: %q present=%t error=%v", content, present, err)
	}

	if err := os.WriteFile(ownedPath, []byte("operator lookalike\n"), 0644); err != nil { // #nosec G306 -- fixture deliberately models a non-owned system cron lookalike
		t.Fatal(err)
	}
	if err := removeOwnedCronStateForRemovalWithOptions(options); err == nil {
		t.Fatal("operator cron.d lookalike was removed")
	}
	lookalike, err := os.ReadFile(ownedPath) // #nosec G304 -- ownedPath is confined to the private cron fixture root
	if err != nil || string(lookalike) != "operator lookalike\n" {
		t.Fatalf("operator lookalike changed: %q error=%v", lookalike, err)
	}
}

func TestRemovalCronProductionPathContainsNoRootWriter_SW2_FWBACKEND_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "removal_cron_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	for _, forbidden := range []string{
		`"-r"`,
		"writeRoot" + "Crontab",
		"filterManaged" + "RootCrontab",
		`command.Stdin`,
		`exec.Command("crontab"`,
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("removal cron path contains writer or ambient command %q", forbidden)
		}
	}
}
