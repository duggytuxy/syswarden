//go:build linux

package firewall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"
)

func TestLinuxFirewallWrappersAreIdempotentAcrossFamilies_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	statePath := filepath.Join(directory, "rules")
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
operation="$1"
shift
if [ "$operation" = "-C" ]; then
    target="$*"
    if [ -f "$state" ]; then
        while IFS= read -r line; do
            [ "$line" = "$target" ] && exit 0
        done < "$state"
    fi
    exit 1
fi
if [ "$operation" = "-I" ]; then
    chain="$1"
    shift
    [ "$1" = "1" ] && shift
    printf '%s\n' "$chain $*" >> "$state"
    exit 0
fi
if [ "$operation" = "-D" ]; then
    target="$*"
    found=0
    : > "$state.next"
    if [ -f "$state" ]; then
        while IFS= read -r line; do
            if [ "$line" = "$target" ]; then
                found=1
            else
                printf '%s\n' "$line" >> "$state.next"
            fi
        done < "$state"
    fi
    /bin/mv "$state.next" "$state"
    [ "$found" = "1" ] && exit 0
    exit 1
fi
exit 2
`
	for _, name := range []string{"iptables", "ip6tables"} {
		writeRootedExecutableTestFile(t, filepath.Join(directory, name), []byte(script))
	}
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", statePath)
	for range 2 {
		if err := applyLinuxFirewallWrappers(
			[]string{"192.0.2.0/24", "2001:db8::/64"},
			[]string{"62027"},
		); err != nil {
			t.Fatalf("wrapper reconciliation: %v", err)
		}
	}
	content := readRootedTestFile(t, statePath)
	lines := strings.FieldsFunc(strings.TrimSpace(string(content)), func(character rune) bool { return character == '\n' })
	if len(lines) != 3 {
		t.Fatalf("wrapper rules = %d, want one port plus one v4 and one v6 source:\n%s", len(lines), content)
	}
}

func TestLinuxFirewallWrappersRemoveOnlyOwnedStaleRules_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	statePath := filepath.Join(directory, "rules")
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
operation="$1"
shift
target="$*"
if [ "$operation" = "-C" ]; then
    if [ -f "$state" ]; then
        while IFS= read -r line; do
            [ "$line" = "$target" ] && exit 0
        done < "$state"
    fi
    exit 1
fi
if [ "$operation" = "-I" ]; then
    chain="$1"
    shift
    [ "$1" = "1" ] && shift
    printf '%s\n' "$chain $*" >> "$state"
    exit 0
fi
if [ "$operation" = "-D" ]; then
    found=0
    : > "$state.next"
    if [ -f "$state" ]; then
        while IFS= read -r line; do
            if [ "$line" = "$target" ]; then
                found=1
            else
                printf '%s\n' "$line" >> "$state.next"
            fi
        done < "$state"
    fi
    /bin/mv "$state.next" "$state"
    [ "$found" = "1" ] && exit 0
    exit 1
fi
exit 2
`
	for _, name := range []string{"iptables", "ip6tables"} {
		writeRootedExecutableTestFile(t, filepath.Join(directory, name), []byte(script))
	}
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", statePath)
	if err := applyLinuxFirewallWrappers(
		[]string{"192.0.2.0/24", "2001:db8::/64"},
		[]string{"62026", "62027"},
	); err != nil {
		t.Fatalf("initial wrapper reconciliation: %v", err)
	}
	if err := applyLinuxFirewallWrappers(
		[]string{"192.0.2.0/24"},
		[]string{"62027"},
	); err != nil {
		t.Fatalf("stale wrapper reconciliation: %v", err)
	}
	content := readRootedTestFile(t, statePath)
	text := string(content)
	for _, stale := range []string{"62026", "2001:db8::/64"} {
		if strings.Contains(text, stale) {
			t.Fatalf("stale owned wrapper rule %s remains:\n%s", stale, text)
		}
	}
	for _, retained := range []string{"62027", "192.0.2.0/24"} {
		if !strings.Contains(text, retained) {
			t.Fatalf("desired wrapper rule %s was removed:\n%s", retained, text)
		}
	}
}

func TestLinuxFirewallWrappersPreservePreexistingUnownedRules_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	statePath := filepath.Join(directory, "rules")
	preexisting := "INPUT -p tcp --dport 62027 -j ACCEPT\n"
	if err := os.WriteFile(statePath, []byte(preexisting), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
operation="$1"
shift
target="$*"
if [ "$operation" = "-C" ]; then
    while IFS= read -r line; do
        [ "$line" = "$target" ] && exit 0
    done < "$state"
    exit 1
fi
if [ "$operation" = "-I" ]; then
    chain="$1"
    shift
    [ "$1" = "1" ] && shift
    printf '%s\n' "$chain $*" >> "$state"
    exit 0
fi
if [ "$operation" = "-D" ]; then
    exit 99
fi
exit 2
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "iptables"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", statePath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62027"}); err != nil {
		t.Fatalf("adopt-free wrapper verification: %v", err)
	}
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatalf("unowned wrapper preservation: %v", err)
	}
	content := readRootedTestFile(t, statePath)
	if string(content) != preexisting {
		t.Fatalf("pre-existing unowned rule changed:\n%s", content)
	}
}

func TestWrapperFailureReportsCommittedAuthoritativeNftState_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	for _, name := range []string{"iptables", "ip6tables"} {
		writeRootedExecutableTestFile(t, filepath.Join(directory, name), []byte("#!/bin/sh\nexit 2\n"))
	}
	t.Setenv("PATH", directory)
	wrapperErr := applyLinuxFirewallWrappers([]string{"192.0.2.0/24"}, []string{"62027"})
	if wrapperErr == nil {
		t.Fatal("failing compatibility wrapper reported success")
	}
	err := committedWrapperReconciliationError("0123456789abcdef", wrapperErr)
	for _, fragment := range []string{"0123456789abcdef", "committed", "remains authoritative", "incomplete"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("wrapper failure %q omitted final-state marker %q", err, fragment)
		}
	}
}

func writeRootedExecutableTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0700); err != nil {
		t.Fatal(err)
	}
}

func readRootedTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestWrapperFailureAfterNftCommitDoesNotReportSuccessOrRollback_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan)
	wrapperFailure := errors.New("synthetic wrapper failure")
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		stateDirectory,
		minimalNftRules(),
		nil,
		plan,
		func() error { return wrapperFailure },
	)
	if transactionID == "" {
		t.Fatal("committed transaction omitted its identifier")
	}
	if err == nil || !errors.Is(err, wrapperFailure) {
		t.Fatalf("wrapper failure = %v, want wrapped synthetic failure", err)
	}
	for _, fragment := range []string{transactionID, "committed", "remains authoritative", "incomplete"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("wrapper failure %q omitted final-state marker %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("kernel apply/rollback calls = %d/%d, want 1/0", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, statErr := os.Stat(filepath.Join(stateDirectory, "syswarden.nft")); statErr != nil {
		t.Fatalf("verified authoritative policy was not persisted: %v", statErr)
	}
}

func useLinuxWrapperStateFile(t *testing.T, path string) {
	t.Helper()
	previous := linuxWrapperStateFile
	linuxWrapperStateFile = path
	t.Cleanup(func() { linuxWrapperStateFile = previous })
}

func TestApplyPoliciesRejectsInjectedValuesBeforeTransaction_SW_FW_001(t *testing.T) {
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	tests := []struct {
		name      string
		configure func(*config.Config)
		wantError string
	}{
		{
			name: "interface statement",
			configure: func(value *config.Config) {
				value.Interfaces = "eth0; flush ruleset"
			},
			wantError: "network interface",
		},
		{
			name: "LAN subnet statement",
			configure: func(value *config.Config) {
				value.LANSubnets = "10.0.0.0/8 } add table inet injected"
			},
			wantError: "LAN subnet",
		},
		{
			name: "HA port statement",
			configure: func(value *config.Config) {
				value.HAEnabled = true
				value.HAPeerPort = "62026; flush ruleset"
			},
			wantError: "HA peer port",
		},
		{
			name: "SSH port statement",
			configure: func(value *config.Config) {
				value.SSHPort = "22; flush ruleset"
			},
			wantError: "SSH port",
		},
		{
			name: "WireGuard subnet statement",
			configure: func(value *config.Config) {
				value.EnableWG = true
				value.WGSubnet = "10.20.0.0/24; flush ruleset"
			},
			wantError: "WireGuard subnet",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := &config.Config{Interfaces: "eth0", SSHPort: "22"}
			test.configure(value)
			config.GlobalConfig = value
			err := ApplyPolicies()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ApplyPolicies() error = %v, want validation error containing %q", err, test.wantError)
			}
		})
	}
}
