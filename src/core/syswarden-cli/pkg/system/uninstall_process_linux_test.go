//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFirewallRemovalProcessFixture(
	t *testing.T,
	procRoot string,
	pid string,
	executable string,
	arguments []string,
	terminated bool,
) {
	t.Helper()
	processRoot := filepath.Join(procRoot, pid)
	if err := os.Mkdir(processRoot, 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Join(arguments, "\x00"))
	if terminated {
		content = append(content, 0)
	}
	if err := os.WriteFile(filepath.Join(processRoot, "cmdline"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(processRoot, "exe")); err != nil {
		t.Fatal(err)
	}
}

func newFirewallRemovalProcessScannerForTest(
	t *testing.T,
	procRoot string,
	cliPath string,
	selfPID int,
	nonRootPID string,
) firewallRemovalProcessScanner {
	t.Helper()
	return firewallRemovalProcessScanner{
		procRoot:    procRoot,
		cliPath:     cliPath,
		tuiPath:     filepath.Join(filepath.Dir(cliPath), "syswarden-tui"),
		corePath:    filepath.Join(filepath.Dir(cliPath), "syswarden-core"),
		selfPID:     selfPID,
		readDir:     os.ReadDir,
		openRoot:    os.OpenRoot,
		lstat:       os.Lstat,
		stat:        os.Stat,
		readlink:    os.Readlink,
		validateCLI: func(string) error { return nil },
		ownerUID: func(info os.FileInfo) (uint32, bool) {
			if info.Name() == nonRootPID {
				return 1000, true
			}
			return 0, true
		},
	}
}

func TestFirewallRemovalProcessScanRejectsExactMutatorsAndSkipsSelf_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(root, "syswarden-cli")
	if err := os.WriteFile(cliPath, []byte("binary"), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for this isolated process fixture
		t.Fatal(err)
	}
	writeFirewallRemovalProcessFixture(
		t, procRoot, "101", cliPath,
		[]string{cliPath, "--config", "/etc/syswarden/config.toml", "update-feeds"}, true,
	)
	scanner := newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "")
	err := scanner.scan()
	if err == nil || !strings.Contains(err.Error(), "update-feeds") || !strings.Contains(err.Error(), "process 101") {
		t.Fatalf("exact mutator scan result = %v", err)
	}

	scanner.selfPID = 101
	if err := scanner.scan(); err != nil {
		t.Fatalf("current removal process was not excluded: %v", err)
	}
}

func TestFirewallRemovalProcessScanPreservesLookalikesAndNonRootProcesses_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(root, "syswarden-cli")
	helperPath := filepath.Join(root, "syswarden-cli-helper")
	tuiHelperPath := filepath.Join(root, "syswarden-tui-helper")
	for _, path := range []string{cliPath, helperPath, tuiHelperPath} {
		if err := os.WriteFile(path, []byte(path), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for isolated process fixtures
			t.Fatal(err)
		}
	}
	writeFirewallRemovalProcessFixture(
		t, procRoot, "201", helperPath, []string{helperPath, "update-feeds"}, true,
	)
	writeFirewallRemovalProcessFixture(
		t, procRoot, "202", cliPath, []string{cliPath, "update-feeds-lookalike"}, true,
	)
	writeFirewallRemovalProcessFixture(
		t, procRoot, "203", cliPath, []string{cliPath, "reload"}, true,
	)
	writeFirewallRemovalProcessFixture(
		t, procRoot, "204", tuiHelperPath, []string{tuiHelperPath}, true,
	)
	scanner := newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "203")
	if err := scanner.scan(); err != nil {
		t.Fatalf("lookalike or non-root process blocked removal: %v", err)
	}
}

func TestFirewallRemovalProcessScanRejectsExactDirectTUI_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(root, "syswarden-cli")
	tuiPath := filepath.Join(root, "syswarden-tui")
	for _, path := range []string{cliPath, tuiPath} {
		if err := os.WriteFile(path, []byte(path), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for isolated process fixtures
			t.Fatal(err)
		}
	}
	writeFirewallRemovalProcessFixture(
		t, procRoot, "401", tuiPath, []string{tuiPath}, false,
	)
	scanner := newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "")
	err := scanner.scan()
	if err == nil || !strings.Contains(err.Error(), "SysWarden TUI") || !strings.Contains(err.Error(), "process 401") {
		t.Fatalf("exact TUI scan result = %v", err)
	}

	scanner = newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "401")
	if err := scanner.scan(); err != nil {
		t.Fatalf("non-root exact TUI process blocked removal: %v", err)
	}

	sentinel := errors.New("synthetic TUI process reattestation failure")
	scanner = newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "")
	processPath := filepath.Join(procRoot, "401")
	lstatCalls := 0
	scanner.lstat = func(path string) (os.FileInfo, error) {
		if path == processPath {
			lstatCalls++
			if lstatCalls == 2 {
				return nil, sentinel
			}
		}
		return os.Lstat(path)
	}
	if err := scanner.scan(); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("TUI reattestation error = %v", err)
	}

	cliInfo, err := os.Stat(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exactRemovalProcessExecutable(cliInfo, nil, tuiPath+" (deleted)", tuiPath) {
		t.Fatal("exact deleted TUI executable path was not classified")
	}
	if exactRemovalProcessExecutable(cliInfo, nil, tuiPath+"-helper (deleted)", tuiPath) {
		t.Fatal("deleted TUI lookalike path was classified")
	}
}

func TestFirewallRemovalProcessScanRejectsExactDirectCore_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(root, "syswarden-cli")
	corePath := filepath.Join(root, "syswarden-core")
	for _, path := range []string{cliPath, corePath} {
		if err := os.WriteFile(path, []byte(path), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for isolated process fixtures
			t.Fatal(err)
		}
	}
	writeFirewallRemovalProcessFixture(
		t, procRoot, "501", corePath, []string{corePath}, false,
	)
	scanner := newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "")
	if err := scanner.scan(); err != nil {
		t.Fatalf("pre-stop process scan rejected the service-managed core before it could be stopped: %v", err)
	}
	scanner.rejectCore = true
	err := scanner.scan()
	if err == nil || !strings.Contains(err.Error(), "SysWarden core") || !strings.Contains(err.Error(), "process 501") {
		t.Fatalf("exact core scan result = %v", err)
	}

	scanner = newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "501")
	scanner.rejectCore = true
	if err := scanner.scan(); err != nil {
		t.Fatalf("non-root exact core process blocked removal: %v", err)
	}

	cliInfo, err := os.Stat(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exactRemovalProcessExecutable(cliInfo, nil, corePath+" (deleted)", corePath) {
		t.Fatal("exact deleted core executable path was not classified")
	}
	if exactRemovalProcessExecutable(cliInfo, nil, corePath+"-helper (deleted)", corePath) {
		t.Fatal("deleted core lookalike path was classified")
	}
}

func TestFirewallRemovalProcessScanFailsClosedOnMalformedExactCLICommandLine_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(root, "syswarden-cli")
	if err := os.WriteFile(cliPath, []byte("binary"), 0700); err != nil { // #nosec G306 -- owner-only executable mode is required for this isolated process fixture
		t.Fatal(err)
	}
	writeFirewallRemovalProcessFixture(
		t, procRoot, "301", cliPath, []string{cliPath, "reload"}, false,
	)
	scanner := newFirewallRemovalProcessScannerForTest(t, procRoot, cliPath, 999, "")
	err := scanner.scan()
	if err == nil || !strings.Contains(err.Error(), "not NUL terminated") {
		t.Fatalf("malformed exact CLI command line result = %v", err)
	}
}

func TestFirewallRemovalProcessClassificationCoversEveryMutatorFamily_SW2_FWBACKEND_001(t *testing.T) {
	cli := "/opt/syswarden/bin/syswarden-cli"
	for _, testCase := range []struct {
		name      string
		arguments []string
		want      string
		mutating  bool
	}{
		{name: "config", arguments: []string{cli, "config"}, want: "config", mutating: true},
		{name: "migration", arguments: []string{cli, "migrate-config"}, want: "migrate-config", mutating: true},
		{name: "tui", arguments: []string{cli, "tui"}, want: "tui", mutating: true},
		{name: "ha engage", arguments: []string{cli, "ha-fence", "engage", "--force"}, want: "ha-fence engage", mutating: true},
		{
			name: "ha manifest create with fixed global flag",
			arguments: []string{
				cli, "ha-fence", "--config=/etc/syswarden/config.toml", "manifest", "create",
			},
			want: "ha-fence manifest create", mutating: true,
		},
		{name: "read-only list", arguments: []string{cli, "list"}},
		{name: "read-only HA status", arguments: []string{cli, "ha-fence", "status"}},
		{name: "read-only HA manifest", arguments: []string{cli, "ha-fence", "manifest", "verify"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, mutating := exactFirewallMutatingCLISubcommand(testCase.arguments)
			if got != testCase.want || mutating != testCase.mutating {
				t.Fatalf("classification = %q/%t, want %q/%t", got, mutating, testCase.want, testCase.mutating)
			}
		})
	}
}
