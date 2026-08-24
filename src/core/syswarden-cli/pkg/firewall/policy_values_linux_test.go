//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"syswarden-cli/config"
)

const statefulFirewalldWrapperTestScript = `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
runtime="$state.runtime"
if [ -n "$SYSWARDEN_WRAPPER_LOG" ]; then
    printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
fi
if [ "$1" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
if [ "$1" = "--get-active-zones" ]; then
    active_zones="${SYSWARDEN_ACTIVE_ZONES_OUTPUT:-public
  interfaces: eth0}"
    if [ -n "$SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE" ]; then
        probe=0
        if [ -f "$SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE" ]; then
            read -r probe < "$SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE"
        fi
        probe=$((probe + 1))
        printf '%s\n' "$probe" > "$SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE"
        if [ -n "$SYSWARDEN_ACTIVE_ZONES_OUTPUT_AFTER" ] && [ "$probe" -ge "${SYSWARDEN_ACTIVE_ZONES_SWITCH_AT:-2}" ]; then
            active_zones="$SYSWARDEN_ACTIVE_ZONES_OUTPUT_AFTER"
        fi
    fi
    printf '%s\n' "$active_zones"
    exit 0
fi
if [ "$1" = "--get-zones" ]; then
    printf 'public trusted work\n'
    exit 0
fi
if [ "$1" = "--reload" ]; then
    : > "$runtime"
    if [ -f "$state" ]; then
        while IFS= read -r line; do
            printf '%s\n' "$line" >> "$runtime"
        done < "$state"
    fi
    exit 0
fi
permanent=0
if [ "$1" = "--permanent" ]; then
    permanent=1
    shift
fi
zone=""
case "$1" in
    --zone=*) zone="${1#--zone=}"; shift ;;
esac
[ -n "$zone" ] || exit 96
argument="$1"
case "$argument" in
    --query-*)
        selector="$zone|${argument#--query-}"
        if [ -n "$SYSWARDEN_QUERY_SEQUENCE_FILE" ] && [ -n "$SYSWARDEN_OPERATOR_APPEAR_QUERY" ]; then
            query_probe=0
            if [ -f "$SYSWARDEN_QUERY_SEQUENCE_FILE" ]; then
                read -r query_probe < "$SYSWARDEN_QUERY_SEQUENCE_FILE"
            fi
            query_probe=$((query_probe + 1))
            printf '%s\n' "$query_probe" > "$SYSWARDEN_QUERY_SEQUENCE_FILE"
            if [ "$query_probe" -ge "$SYSWARDEN_OPERATOR_APPEAR_QUERY" ]; then
                for target in "$state" "$runtime"; do
                    found=0
                    if [ -f "$target" ]; then
                        while IFS= read -r line; do
                            [ "$line" = "$selector" ] && found=1
                        done < "$target"
                    fi
                    [ "$found" = "1" ] || printf '%s\n' "$selector" >> "$target"
                done
            fi
        fi
        source="$runtime"
        [ "$permanent" = "1" ] && source="$state"
        if [ -f "$source" ]; then
            while IFS= read -r line; do
                [ "$line" = "$selector" ] && exit 0
            done < "$source"
        fi
        exit 1
        ;;
    --add-*)
        selector="$zone|${argument#--add-}"
        target="$runtime"
        [ "$permanent" = "1" ] && target="$state"
        printf '%s\n' "$selector" >> "$target"
        exit 0
        ;;
    --remove-*)
        [ "$SYSWARDEN_REMOVE_FAIL" = "1" ] && exit 7
        selector="$zone|${argument#--remove-}"
        target="$runtime"
        [ "$permanent" = "1" ] && target="$state"
        found=0
        : > "$target.next"
        if [ -f "$target" ]; then
            while IFS= read -r line; do
                if [ "$line" = "$selector" ]; then
                    found=1
                else
                    printf '%s\n' "$line" >> "$target.next"
                fi
            done < "$target"
        fi
        /bin/mv "$target.next" "$target"
        [ "$found" = "1" ] && exit 0
        exit 1
        ;;
esac
exit 2
`

func TestLinuxFirewallWrappersAreIdempotentAcrossFamilies_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	statePath := filepath.Join(directory, "rules")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", statePath)
	for range 2 {
		if err := applyLinuxFirewallWrappers(
			[]string{"192.0.2.0/24", "2001:db8::/64"},
			[]string{"62028"},
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
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", statePath)
	if err := applyLinuxFirewallWrappers(
		[]string{"192.0.2.0/24", "2001:db8::/64"},
		[]string{"62026", "62028"},
	); err != nil {
		t.Fatalf("initial wrapper reconciliation: %v", err)
	}
	if err := applyLinuxFirewallWrappers(
		[]string{"192.0.2.0/24"},
		[]string{"62028"},
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
	for _, retained := range []string{"62028", "192.0.2.0/24"} {
		if !strings.Contains(text, retained) {
			t.Fatalf("desired wrapper rule %s was removed:\n%s", retained, text)
		}
	}
}

func TestLinuxFirewallWrappersPreservePreexistingUnownedRules_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	statePath := filepath.Join(directory, "rules")
	preexisting := "62027/tcp ALLOW Anywhere\n"
	if err := os.WriteFile(statePath, []byte(preexisting), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
if [ "$*" = "status" ]; then
    printf 'Status: active\n'
    while IFS= read -r line; do
        printf '%s\n' "$line"
    done < "$state"
    exit 0
fi
if [ "$1" = "allow" ]; then
    value="$2"
    [ "$2" = "from" ] && value="$3"
    printf '%s ALLOW Anywhere # SYSWARDEN_CORE\n' "$value" >> "$state"
    exit 0
fi
if [ "$1" = "--force" ] && [ "$2" = "delete" ]; then
    exit 99
fi
exit 2
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
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

func TestUFWStatusMatchingRequiresInboundRuleSemantics_SW_FW_001(t *testing.T) {
	portRule := linuxWrapperRule{backend: "ufw", kind: "port", value: "62028"}
	sourceRule := linuxWrapperRule{backend: "ufw", kind: "source", value: "192.0.2.0/24"}
	tests := []struct {
		name string
		line string
		rule linuxWrapperRule
		want bool
	}{
		{name: "implicit inbound port", line: "62028/tcp ALLOW Anywhere", rule: portRule, want: true},
		{name: "explicit inbound port", line: "62028/tcp ALLOW IN Anywhere", rule: portRule, want: true},
		{name: "IPv6 inbound port", line: "62028/tcp (v6) ALLOW Anywhere (v6)", rule: portRule, want: true},
		{name: "outbound port", line: "62028/tcp ALLOW OUT Anywhere", rule: portRule},
		{name: "routed port", line: "62028/tcp ALLOW FWD Anywhere", rule: portRule},
		{name: "port in source column", line: "Anywhere ALLOW 62028/tcp", rule: portRule},
		{name: "source restricted port", line: "62028/tcp ALLOW 192.0.2.0/24", rule: portRule},
		{name: "interface restricted port", line: "62028/tcp on eth0 ALLOW Anywhere", rule: portRule},
		{name: "implicit inbound source", line: "Anywhere ALLOW 192.0.2.0/24", rule: sourceRule, want: true},
		{name: "explicit inbound source", line: "Anywhere ALLOW IN 192.0.2.0/24", rule: sourceRule, want: true},
		{name: "outbound source", line: "Anywhere ALLOW OUT 192.0.2.0/24", rule: sourceRule},
		{name: "source in destination column", line: "192.0.2.0/24 ALLOW Anywhere", rule: sourceRule},
		{name: "source restricted to port", line: "22/tcp ALLOW 192.0.2.0/24", rule: sourceRule},
		{name: "source restricted to interface", line: "Anywhere on eth0 ALLOW 192.0.2.0/24", rule: sourceRule},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ufwStatusLineMatchesRule(test.line, test.rule); got != test.want {
				t.Fatalf("ufw status match = %v, want %v for %q", got, test.want, test.line)
			}
		})
	}
}

func TestUFWOwnershipMarkerRequiresExactTerminalComment_SW_FW_001(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{line: "62028/tcp ALLOW Anywhere # SYSWARDEN_CORE", want: true},
		{line: "62028/tcp ALLOW Anywhere # SYSWARDEN_CORE_OPERATOR"},
		{line: "62028/tcp ALLOW Anywhere # SYSWARDEN_CORE backup"},
		{line: "62028/tcp ALLOW Anywhere # operator SYSWARDEN_CORE"},
		{line: "62028/tcp ALLOW Anywhere"},
	}
	for _, test := range tests {
		if got := ufwStatusLineHasExactOwnershipMarker(test.line); got != test.want {
			t.Fatalf("ufw ownership marker match = %v, want %v for %q", got, test.want, test.line)
		}
	}
}

func TestUFWCleanupNeverClaimsOwnershipMarkerLookalikes_SW_FW_001(t *testing.T) {
	previousEffectiveUserID := firewallCleanupEffectiveUserID
	firewallCleanupEffectiveUserID = func() int { return 0 }
	t.Cleanup(func() { firewallCleanupEffectiveUserID = previousEffectiveUserID })
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	logPath := filepath.Join(directory, "commands.log")
	operatorRules := "62028/tcp ALLOW Anywhere # SYSWARDEN_CORE_OPERATOR\n" +
		"62028/tcp ALLOW Anywhere # SYSWARDEN_CORE backup\n"
	if err := os.WriteFile(rulesPath, []byte(operatorRules), 0600); err != nil {
		t.Fatal(err)
	}
	ownership := linuxWrapperStateVersion + "\nufw\tport\t62028\t-\towned\n"
	if err := os.WriteFile(ownershipPath, []byte(ownership), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: active\n\nTo Action From\n-- ------ ----\n'
    while IFS= read -r line; do
        printf '%s\n' "$line"
    done < "$SYSWARDEN_WRAPPER_STATE"
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	if err := CleanupOwnedCompatibilityRulesForUninstall(); err != nil {
		t.Fatalf("cleanup ownership lookalikes: %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != operatorRules {
		t.Fatalf("cleanup changed operator marker lookalikes:\n%s", content)
	}
	if calls := string(readRootedTestFile(t, logPath)); strings.Contains(calls, "delete") {
		t.Fatalf("cleanup issued an operator-rule delete:\n%s", calls)
	}
	if content := string(readRootedTestFile(t, ownershipPath)); content != linuxWrapperStateVersion+"\n" {
		t.Fatalf("cleanup retained stale ownership after proving no exact marker:\n%s", content)
	}
}

func TestUninstallCleanupRetainsInactiveWrapperOwnershipDebt_SW_FW_001(t *testing.T) {
	previousEffectiveUserID := firewallCleanupEffectiveUserID
	firewallCleanupEffectiveUserID = func() int { return 0 }
	t.Cleanup(func() { firewallCleanupEffectiveUserID = previousEffectiveUserID })

	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	initial := linuxWrapperStateVersion + "\nufw\tport\t62028\t-\towned\n"
	if err := os.WriteFile(ownershipPath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: inactive\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	err := CleanupOwnedCompatibilityRulesForUninstall()
	if err == nil || !strings.Contains(err.Error(), "inactive ufw retains stale owned permission") {
		t.Fatalf("inactive uninstall cleanup error = %v", err)
	}
	if content := string(readRootedTestFile(t, ownershipPath)); content != initial {
		t.Fatalf("inactive uninstall cleanup changed ownership debt:\n%s", content)
	}
	if calls := string(readRootedTestFile(t, logPath)); calls != "status\n" {
		t.Fatalf("inactive uninstall cleanup issued unexpected operations:\n%s", calls)
	}
}

func TestUninstallCleanupRemovesOnlyExactFirewalldOwnership_SW_FW_001(t *testing.T) {
	previousEffectiveUserID := firewallCleanupEffectiveUserID
	firewallCleanupEffectiveUserID = func() int { return 0 }
	t.Cleanup(func() { firewallCleanupEffectiveUserID = previousEffectiveUserID })

	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("prepare owned firewalld rule: %v", err)
	}
	operatorRule := "work|port=63000/tcp\n"
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- path is one of two fixed private transaction fixtures
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(operatorRule); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := CleanupOwnedCompatibilityRulesForUninstall(); err != nil {
		t.Fatalf("verified firewalld uninstall cleanup: %v", err)
	}
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if content := string(readRootedTestFile(t, path)); content != operatorRule {
			t.Fatalf("firewalld uninstall cleanup changed operator state in %s:\n%s", path, content)
		}
	}
	if content := string(readRootedTestFile(t, ownershipPath)); content != linuxWrapperStateVersion+"\n" {
		t.Fatalf("firewalld uninstall cleanup retained ownership:\n%s", content)
	}
}

func TestUninstallCleanupRemovesOnlyExactUFWOwnership_SW_FW_001(t *testing.T) {
	previousEffectiveUserID := firewallCleanupEffectiveUserID
	firewallCleanupEffectiveUserID = func() int { return 0 }
	t.Cleanup(func() { firewallCleanupEffectiveUserID = previousEffectiveUserID })

	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	operatorRule := "63000/tcp ALLOW Anywhere # operator\n"
	if err := os.WriteFile(rulesPath, []byte(operatorRule), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
if [ "$*" = "status" ]; then
    printf 'Status: active\n\nTo Action From\n-- ------ ----\n'
    while IFS= read -r line; do
        printf '%s\n' "$line"
    done < "$state"
    exit 0
fi
if [ "$1" = "allow" ]; then
    printf '%s ALLOW Anywhere # SYSWARDEN_CORE\n' "$2" >> "$state"
    exit 0
fi
if [ "$1" = "--force" ] && [ "$2" = "delete" ] && [ "$3" = "allow" ]; then
    target="$4 ALLOW Anywhere # SYSWARDEN_CORE"
    found=0
    : > "$state.next"
    while IFS= read -r line; do
        if [ "$line" = "$target" ]; then
            found=1
        else
            printf '%s\n' "$line" >> "$state.next"
        fi
    done < "$state"
    /bin/mv "$state.next" "$state"
    [ "$found" = "1" ] && exit 0
    exit 1
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("prepare owned ufw rule: %v", err)
	}
	if err := CleanupOwnedCompatibilityRulesForUninstall(); err != nil {
		t.Fatalf("verified ufw uninstall cleanup: %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != operatorRule {
		t.Fatalf("ufw uninstall cleanup changed operator state:\n%s", content)
	}
	if content := string(readRootedTestFile(t, ownershipPath)); content != linuxWrapperStateVersion+"\n" {
		t.Fatalf("ufw uninstall cleanup retained ownership:\n%s", content)
	}
}

func TestUFWOutboundOperatorRuleDoesNotSuppressOwnedInboundRule_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	operatorRule := "62028/tcp ALLOW OUT Anywhere\n"
	if err := os.WriteFile(rulesPath, []byte(operatorRule), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
state="$SYSWARDEN_WRAPPER_STATE"
if [ "$*" = "status" ]; then
    printf 'Status: active\n\nTo Action From\n-- ------ ----\n'
    while IFS= read -r line; do
        printf '%s\n' "$line"
    done < "$state"
    exit 0
fi
if [ "$1" = "allow" ]; then
    printf '%s ALLOW Anywhere # SYSWARDEN_CORE\n' "$2" >> "$state"
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("reconcile inbound ufw rule beside outbound operator rule: %v", err)
	}
	wantRules := operatorRule + "62028/tcp ALLOW Anywhere # SYSWARDEN_CORE\n"
	if content := string(readRootedTestFile(t, rulesPath)); content != wantRules {
		t.Fatalf("ufw inbound reconciliation changed operator semantics:\n%s", content)
	}
	wantOwnership := linuxWrapperStateVersion + "\nufw\tport\t62028\t-\towned\n"
	if content := string(readRootedTestFile(t, ownershipPath)); content != wantOwnership {
		t.Fatalf("ufw inbound ownership state:\n%s", content)
	}
}

func TestManagedLinuxWrapperDiscoveryRequiresAnActiveBackend_SW_FW_001(t *testing.T) {
	tests := []struct {
		name        string
		executable  string
		backend     string
		script      string
		wantActive  bool
		wantDormant bool
		wantCleanup bool
		wantError   string
	}{
		{
			name:       "active ufw",
			executable: "ufw",
			backend:    "ufw",
			script:     "#!/bin/sh\nprintf 'Status: active\\n'\n",
			wantActive: true,
		},
		{
			name:        "inactive ufw",
			executable:  "ufw",
			backend:     "ufw",
			script:      "#!/bin/sh\nprintf 'Status: inactive\\n'\n",
			wantDormant: true,
		},
		{
			name:       "ufw command error",
			executable: "ufw",
			backend:    "ufw",
			script:     "#!/bin/sh\nprintf 'permission denied\\n'\nexit 7\n",
			wantError:  "query ufw service state",
		},
		{
			name:       "ufw ambiguous state",
			executable: "ufw",
			backend:    "ufw",
			script:     "#!/bin/sh\nprintf 'Status: unknown\\n'\n",
			wantError:  "unexpected state",
		},
		{
			name:       "active firewalld",
			executable: "firewall-cmd",
			backend:    "firewalld",
			script:     "#!/bin/sh\nprintf 'running\\n'\n",
			wantActive: true,
		},
		{
			name:        "inactive firewalld",
			executable:  "firewall-cmd",
			backend:     "firewalld",
			script:      "#!/bin/sh\nprintf 'not running\\n'\nexit 252\n",
			wantDormant: true,
		},
		{
			name:       "firewalld command error",
			executable: "firewall-cmd",
			backend:    "firewalld",
			script:     "#!/bin/sh\nprintf 'dbus unavailable\\n'\nexit 7\n",
			wantError:  "query firewalld service state",
		},
		{
			name:       "firewalld ambiguous state",
			executable: "firewall-cmd",
			backend:    "firewalld",
			script:     "#!/bin/sh\nprintf 'degraded\\n'\n",
			wantError:  "unexpected value",
		},
		{
			name:        "bare iptables is cleanup only",
			executable:  "iptables",
			backend:     "iptables",
			script:      "#!/bin/sh\nexit 97\n",
			wantCleanup: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, test.executable)
			writeRootedExecutableTestFile(t, path, []byte(test.script))
			t.Setenv("PATH", directory)
			active, dormant, cleanup, err := discoverLinuxWrapperPaths()
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("discovery error = %v, want error containing %q", err, test.wantError)
				}
				if active != nil || dormant != nil || cleanup != nil {
					t.Fatalf("failed discovery returned active=%v dormant=%v cleanup=%v", active, dormant, cleanup)
				}
				return
			}
			if err != nil {
				t.Fatalf("wrapper discovery: %v", err)
			}
			_, isActive := active[test.backend]
			_, isDormant := dormant[test.backend]
			_, isCleanup := cleanup[test.backend]
			if isActive != test.wantActive || isDormant != test.wantDormant || isCleanup != test.wantCleanup {
				t.Fatalf(
					"backend state active=%v dormant=%v cleanup=%v, want active=%v dormant=%v cleanup=%v",
					isActive,
					isDormant,
					isCleanup,
					test.wantActive,
					test.wantDormant,
					test.wantCleanup,
				)
			}
		})
	}
}

func TestExplicitNftablesBackendRejectsActiveCompatibilityFrontend_SW2_FWBACKEND_001(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		script     string
		want       string
	}{
		{
			name:       "ufw",
			executable: "ufw",
			script:     "#!/bin/sh\nprintf 'ufw %s\\n' \"$*\" >> \"$SYSWARDEN_WRAPPER_LOG\"\nprintf 'Status: active\\n'\n",
			want:       "ufw",
		},
		{
			name:       "firewalld",
			executable: "firewall-cmd",
			script:     statefulFirewalldWrapperTestScript,
			want:       "firewalld",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			statePath := filepath.Join(directory, "ownership.state")
			logPath := filepath.Join(directory, "commands.log")
			useLinuxWrapperStateFile(t, statePath)
			writeRootedExecutableTestFile(t, filepath.Join(directory, test.executable), []byte(test.script))
			t.Setenv("PATH", directory)
			t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
			t.Setenv("SYSWARDEN_WRAPPER_STATE", filepath.Join(directory, "rules"))

			_, err := prepareLinuxFirewallWrapperReconciliationForBackend("nftables", nil, []string{"62028"})
			if err == nil || !strings.Contains(err.Error(), "explicit nftables backend forbids active compatibility frontends") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("strict nftables wrapper error = %v", err)
			}
			if _, statErr := os.Stat(statePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("strict nftables preflight created ownership state: %v", statErr)
			}
			calls := string(readRootedTestFile(t, logPath))
			for _, forbidden := range []string{"--query-", "--add-", "--remove-", "--reload"} {
				if strings.Contains(calls, forbidden) {
					t.Fatalf("strict nftables preflight issued wrapper operation %q:\n%s", forbidden, calls)
				}
			}
		})
	}
}

func TestFirewallMutationEntryPointsPreflightBeforePersistentState_SW2_FWBACKEND_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousPreflight := firewallBackendPreflight
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		firewallBackendPreflight = previousPreflight
	})

	mutationCalls := []struct {
		name string
		call func() error
	}{
		{name: "add-whitelist", call: func() error { return AddToWhitelist("8.8.8.8", "") }},
		{name: "remove-whitelist", call: func() error { return RemoveFromWhitelist("8.8.8.8") }},
		{name: "add-blocklist", call: func() error { return AddToBlocklist("8.8.8.8") }},
		{name: "remove-blocklist", call: func() error { return RemoveFromBlocklist("8.8.8.8") }},
		{name: "allow-ssh", call: func() error { return AllowSSH("8.8.8.8", "22") }},
		{name: "revoke-ssh", call: func() error { return RevokeSSH("8.8.8.8") }},
		{name: "whitelist-infra", call: WhitelistInfra},
		{name: "auto-whitelist-admin-and-infra", call: AutoWhitelistAdminAndInfra},
		{name: "apply-policies", call: ApplyPolicies},
	}

	t.Run("iptables", func(t *testing.T) {
		config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
		firewallBackendPreflight = func(string) error {
			t.Fatal("iptables must be rejected before host backend inspection")
			return nil
		}
		for _, mutation := range mutationCalls {
			t.Run(mutation.name, func(t *testing.T) {
				err := mutation.call()
				if err == nil || !strings.Contains(err.Error(), "accepted for configuration compatibility but refused") {
					t.Fatalf("iptables mutation error = %v", err)
				}
			})
		}
	})

	t.Run("nftables-service-preflight", func(t *testing.T) {
		config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
		sentinel := errors.New("synthetic inactive nftables service")
		firewallBackendPreflight = func(backend string) error {
			if backend != "nftables" {
				t.Fatalf("preflight backend = %q", backend)
			}
			return sentinel
		}
		for _, mutation := range mutationCalls {
			t.Run(mutation.name, func(t *testing.T) {
				err := mutation.call()
				if err == nil || !errors.Is(err, sentinel) {
					t.Fatalf("nftables service preflight error = %v", err)
				}
			})
		}
	})
}

func TestNftablesPrecommitBackendReattestationRunsBeforeKernelApply_SW2_FWBACKEND_001(t *testing.T) {
	directory := t.TempDir()
	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	sentinel := errors.New("synthetic backend state change")
	reconcileCalled := false
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		nil,
		func() error { return sentinel },
		func() error {
			reconcileCalled = true
			return nil
		},
	)
	if transactionID == "" {
		t.Fatal("precommit backend failure omitted transaction identifier")
	}
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "preserved the previous ruleset") || !strings.Contains(err.Error(), "precommit firewall backend reattestation") {
		t.Fatalf("precommit backend error = %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("precommit backend failure applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if reconcileCalled {
		t.Fatal("wrapper reconciliation ran after precommit backend failure")
	}
}

func TestNftablesPostApplyBackendDriftRollsBackBeforePersistence_SW2_FWBACKEND_001(t *testing.T) {
	directory := t.TempDir()
	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	sentinel := errors.New("synthetic backend activation after apply")
	attestations := 0
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		nil,
		func() error {
			attestations++
			if attestations == 2 {
				return sentinel
			}
			return nil
		},
		nil,
	)
	if transactionID == "" {
		t.Fatal("post-apply backend failure omitted transaction identifier")
	}
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "rolled back before persistence") {
		t.Fatalf("post-apply backend error = %v", err)
	}
	if attestations != 2 {
		t.Fatalf("backend attestations = %d, want 2", attestations)
	}
	if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 1 {
		t.Fatalf("post-apply drift apply/rollback calls = %d/%d, want 1/1", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, filepath.Base(nftStateFile))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("post-apply drift persisted authoritative state: %v", statErr)
	}
}

func TestWrapperExecutableResolutionPinsTrustedAbsoluteTarget_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ufw-real")
	writeRootedExecutableTestFile(t, target, []byte("#!/bin/sh\nexit 0\n"))
	link := filepath.Join(directory, "ufw")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveLinuxWrapperExecutable(link)
	if err != nil {
		t.Fatalf("resolve trusted wrapper executable: %v", err)
	}
	if resolved != target {
		t.Fatalf("resolved wrapper path = %q, want %q", resolved, target)
	}
	if err := os.Chmod(target, 0777); err != nil { // #nosec G302 -- fixture deliberately proves writable executables are rejected
		t.Fatal(err)
	}
	if err := validateResolvedLinuxWrapperExecutable(target); err == nil || !strings.Contains(err.Error(), "non-writable regular executable") {
		t.Fatalf("writable production wrapper validation error = %v", err)
	}
	if err := os.Chmod(target, 0700); err != nil { // #nosec G302 -- owner-only executable mode is restored before parent validation
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 01777); err != nil { // #nosec G302 -- adversarial fixture models a sticky world-writable executable parent
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0700) }) // #nosec G302 -- cleanup restores the private test directory to owner-only mode
	if err := validateResolvedLinuxWrapperExecutable(target); err == nil ||
		!strings.Contains(err.Error(), "directory") || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("sticky writable parent validation error = %v", err)
	}
	if _, err := resolveLinuxWrapperExecutable("ufw"); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("relative wrapper resolution error = %v", err)
	}
}

func TestWrapperCommandsEnforceOutputAndTimeBounds_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	t.Run("output", func(t *testing.T) {
		payloadPath := filepath.Join(directory, "payload")
		if err := os.WriteFile(payloadPath, bytes.Repeat([]byte("x"), maximumFirewallCommandOutput+1), 0600); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\n/bin/cat \"$SYSWARDEN_OUTPUT_PAYLOAD\"\n"
		path := filepath.Join(directory, "ufw-output")
		writeRootedExecutableTestFile(t, path, []byte(script))
		t.Setenv("SYSWARDEN_OUTPUT_PAYLOAD", payloadPath)
		output, err := runLinuxFirewallCommand(path)
		if err == nil || !strings.Contains(err.Error(), "output exceeds") {
			t.Fatalf("oversized wrapper output error = %v", err)
		}
		if len(output) != maximumFirewallCommandOutput {
			t.Fatalf("captured oversized wrapper output = %d bytes, want %d", len(output), maximumFirewallCommandOutput)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		path := filepath.Join(directory, "ufw-timeout")
		writeRootedExecutableTestFile(t, path, []byte("#!/bin/sh\nwhile :; do :; done\n"))
		started := time.Now()
		_, err := runLinuxFirewallCommandWithTimeout(path, 25*time.Millisecond)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wrapper timeout error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("wrapper timeout took %s", elapsed)
		}
	})
}

func TestWrapperCommandsUseFixedMinimalEnvironment_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "firewall-cmd-environment")
	script := `#!/bin/sh
[ -z "${LD_PRELOAD+x}" ] || exit 31
[ -z "${LD_LIBRARY_PATH+x}" ] || exit 32
[ -z "${PYTHONPATH+x}" ] || exit 33
[ -z "${DBUS_SYSTEM_BUS_ADDRESS+x}" ] || exit 34
[ "$LC_ALL" = "C" ] || exit 35
[ "$LANG" = "C" ] || exit 36
[ "$PATH" = "/usr/sbin:/usr/bin:/sbin:/bin" ] || exit 37
printf 'minimal-environment\n'
`
	writeRootedExecutableTestFile(t, path, []byte(script))
	t.Setenv("LD_PRELOAD", "/untrusted/syswarden-test-preload.so")
	t.Setenv("LD_LIBRARY_PATH", "/untrusted/syswarden-test-library")
	t.Setenv("PYTHONPATH", "/untrusted/syswarden-test-python")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/untrusted/syswarden-test-bus")
	output, err := runLinuxFirewallCommand(path)
	if err != nil {
		t.Fatalf("fixed wrapper environment: %v: %s", err, output)
	}
	if string(output) != "minimal-environment\n" {
		t.Fatalf("fixed wrapper environment output: %q", output)
	}
}

func TestSimultaneouslyActiveManagedWrappersFailBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	logPath := filepath.Join(directory, "commands.log")
	ufwScript := `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: active\n'
    exit 0
fi
exit 97
`
	firewalldScript := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(ufwScript))
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(firewalldScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)

	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, nil)
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if transactionID == "" {
		t.Fatal("frontend conflict omitted the transaction identifier")
	}
	if err == nil || !strings.Contains(err.Error(), "ufw and firewalld are both active") || !strings.Contains(err.Error(), "preserved the previous ruleset") {
		t.Fatalf("frontend conflict error = %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("frontend conflict applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, statErr := os.Stat(statePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("frontend conflict created ownership state: %v", statErr)
	}
	wantCalls := "ufw status\nfirewall-cmd --state\n"
	if calls := readRootedTestFile(t, logPath); string(calls) != wantCalls {
		t.Fatalf("frontend conflict issued unexpected commands:\n%s", calls)
	}
}

func TestBareIptablesBinariesAreNeverInvokedWithoutOwnedCleanup_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf '%s %s\n' "$0" "$*" >> "$SYSWARDEN_WRAPPER_LOG"
exit 97
`
	for _, name := range []string{"iptables", "ip6tables"} {
		writeRootedExecutableTestFile(t, filepath.Join(directory, name), []byte(script))
	}
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	if err := applyLinuxFirewallWrappers(
		[]string{"192.0.2.0/24", "2001:db8::/64"},
		[]string{"62028"},
	); err != nil {
		t.Fatalf("ignore bare iptables binaries: %v", err)
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bare iptables binary was invoked: %v", err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bare iptables binary created ownership state: %v", err)
	}
}

func TestLegacyOwnedIptablesCleanupPreservesOperatorRule_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	ownedRule := "INPUT -p tcp --dport 62028 -m comment --comment SYSWARDEN_CORE -j ACCEPT"
	operatorRule := "INPUT -p tcp --dport 62027 -j ACCEPT"
	rulesPath := filepath.Join(directory, "rules")
	if err := os.WriteFile(rulesPath, []byte(ownedRule+"\n"+operatorRule+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ownership := zonedLinuxWrapperStateVersion + "\niptables\tport\t62028\t-\n"
	if err := os.WriteFile(statePath, []byte(ownership), 0600); err != nil {
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
if [ "$operation" = "-D" ]; then
    found=0
    : > "$state.next"
    while IFS= read -r line; do
        if [ "$line" = "$target" ]; then
            found=1
        else
            printf '%s\n' "$line" >> "$state.next"
        fi
    done < "$state"
    /bin/mv "$state.next" "$state"
    [ "$found" = "1" ] && exit 0
    exit 1
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "iptables"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatalf("legacy owned iptables cleanup: %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != operatorRule+"\n" {
		t.Fatalf("legacy cleanup changed the operator rule or retained the owned rule:\n%s", content)
	}
	if content := string(readRootedTestFile(t, statePath)); content != linuxWrapperStateVersion+"\n" {
		t.Fatalf("legacy cleanup retained ownership debt:\n%s", content)
	}
}

func TestLegacyFirewalldPortWithoutZoneFailsBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	initial := legacyLinuxWrapperStateVersion + "\nfirewalld\tport\t62028\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)

	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, nil)
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if transactionID == "" {
		t.Fatal("ambiguous legacy ownership omitted the transaction identifier")
	}
	for _, fragment := range []string{
		"preserved the previous ruleset",
		"legacy firewalld port ownership",
		"has no explicit zone",
		"verified cleanup or migration is required",
	} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("legacy zone error = %v, want fragment %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("ambiguous legacy ownership applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || string(readRootedTestFile(t, statePath)) != initial {
		t.Fatal("ambiguous legacy ownership was mutated")
	}
	if calls := string(readRootedTestFile(t, logPath)); calls != "firewall-cmd --state\n" {
		t.Fatalf("ambiguous legacy ownership issued rule commands:\n%s", calls)
	}
}

func TestLegacyFirewalldSourceWithoutZoneFailsBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	legacy := legacyLinuxWrapperStateVersion + "\nfirewalld\tsource\t192.0.2.0/24\n"
	if err := os.WriteFile(statePath, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)

	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	_, err = applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation([]string{"192.0.2.0/24"}, nil)
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	for _, fragment := range []string{
		"preserved the previous ruleset",
		"legacy firewalld source ownership",
		"has no explicit zone",
		"verified cleanup or migration is required",
	} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("legacy source zone error = %v, want %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("ambiguous legacy source applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || string(readRootedTestFile(t, statePath)) != legacy {
		t.Fatal("ambiguous legacy source ownership was mutated")
	}
	if calls := string(readRootedTestFile(t, logPath)); calls != "firewall-cmd --state\n" {
		t.Fatalf("ambiguous legacy source issued rule commands:\n%s", calls)
	}
}

func TestFirewalldPortZoneIsPinnedAcrossDefaultZoneChanges_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	rulesPath := filepath.Join(directory, "rules")
	if err := os.WriteFile(rulesPath, []byte("public|port=62028/tcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initial := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_DEFAULT_ZONE", "work")
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("reconcile pinned firewalld zone: %v", err)
	}
	calls := string(readRootedTestFile(t, logPath))
	if strings.Contains(calls, "default-zone") || strings.Contains(calls, "--zone=work") {
		t.Fatalf("firewalld reconciliation depended on the mutable default zone:\n%s", calls)
	}
	for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
		if strings.Contains(line, "port=62028/tcp") && !strings.Contains(line, "--zone=public") {
			t.Fatalf("firewalld port command omitted the recorded public zone: %q", line)
		}
	}
	if content := string(readRootedTestFile(t, statePath)); content != initial {
		t.Fatalf("pinned zone ownership changed:\n%s", content)
	}
}

func TestFirewalldPortMigratesToTheUniqueActiveZone_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	rulesPath := filepath.Join(directory, "rules")
	if err := os.WriteFile(rulesPath, []byte("public|port=62028/tcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initial := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "work\n  interfaces: eth0")
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("migrate firewalld port to active zone: %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != "work|port=62028/tcp\n" {
		t.Fatalf("firewalld rule did not migrate to the active zone:\n%s", content)
	}
	wantOwnership := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\twork\towned\n"
	if content := string(readRootedTestFile(t, statePath)); content != wantOwnership {
		t.Fatalf("firewalld ownership did not record the active zone:\n%s", content)
	}
	calls := string(readRootedTestFile(t, logPath))
	for _, required := range []string{
		"--permanent --zone=public --remove-port=62028/tcp",
		"--permanent --zone=work --add-port=62028/tcp",
	} {
		if !strings.Contains(calls, required) {
			t.Fatalf("firewalld zone migration omitted %q:\n%s", required, calls)
		}
	}
}

func TestFirewalldPortRefusesZeroOrMultipleActiveZonesBeforeNftCommit_SW_FW_001(t *testing.T) {
	tests := []struct {
		name         string
		activeZones  string
		wantFragment string
	}{
		{name: "no active zone", activeZones: " ", wantFragment: "has no active interface-bound zone"},
		{name: "multiple active zones", activeZones: "public\n  interfaces: eth0\nwork\n  interfaces: eth1", wantFragment: "has multiple active interface-bound zones"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
			writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
			t.Setenv("PATH", directory)
			t.Setenv("SYSWARDEN_WRAPPER_STATE", filepath.Join(directory, "rules"))
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", test.activeZones)
			verification := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(verification)
			var prepared *linuxWrapperReconciliationPlan
			_, err := applyNftablesPolicyWithWrappers(
				context.Background(),
				runner,
				directory,
				minimalNftRules(),
				nil,
				verification,
				func() error {
					var prepareErr error
					prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, []string{"62028"})
					return prepareErr
				},
				nil,
				func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
			)
			if err == nil || !strings.Contains(err.Error(), test.wantFragment) || !strings.Contains(err.Error(), "preserved the previous ruleset") {
				t.Fatalf("active zone error = %v, want %q", err, test.wantFragment)
			}
			if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("ambiguous active zone applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
			}
		})
	}
}

func TestSourceOnlyFirewalldZoneDoesNotMakePortZoneAmbiguous_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", filepath.Join(directory, "rules"))
	t.Setenv(
		"SYSWARDEN_ACTIVE_ZONES_OUTPUT",
		"public\n  interfaces: eth0\ntrusted\n  sources: 192.0.2.0/24",
	)
	if err := applyLinuxFirewallWrappers([]string{"192.0.2.0/24"}, []string{"62028"}); err != nil {
		t.Fatalf("resolve interface-bound zone beside source-only trusted zone: %v", err)
	}
	content := string(readRootedTestFile(t, statePath))
	for _, rule := range []string{
		"firewalld\tport\t62028\tpublic",
		"firewalld\tsource\t192.0.2.0/24\ttrusted",
	} {
		if !strings.Contains(content, rule) {
			t.Fatalf("zoned ownership omitted %q:\n%s", rule, content)
		}
	}
}

func TestFirewalldActiveZoneChangeAfterNftCommitPreventsWrapperMutation_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	zoneProbePath := filepath.Join(directory, "zone-probed")
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
if [ "$*" = "--get-active-zones" ]; then
    if [ -f "$SYSWARDEN_ZONE_PROBE_STATE" ]; then
        printf 'work\n  interfaces: eth0\n'
    else
        : > "$SYSWARDEN_ZONE_PROBE_STATE"
        printf 'public\n  interfaces: eth0\n'
    fi
    exit 0
fi
if [ "$*" = "--get-zones" ]; then
    printf 'public trusted work\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_ZONE_PROBE_STATE", zoneProbePath)
	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, []string{"62028"})
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if transactionID == "" {
		t.Fatal("active zone race omitted transaction identifier")
	}
	for _, fragment := range []string{
		"committed and remains authoritative",
		`active firewalld port zone changed from "public" to "work"`,
	} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("active zone race error = %v, want %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("active zone race nft apply/rollback = %d/%d, want 1/0", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active zone race created ownership state: %v", err)
	}
	calls := string(readRootedTestFile(t, logPath))
	for _, forbidden := range []string{"--query-", "--add-", "--remove-", "--reload"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("active zone race issued wrapper mutation or rule query %q:\n%s", forbidden, calls)
		}
	}
}

func TestManagedWrapperActivationRaceIsDetectedBeforeSuccess_SW_FW_001(t *testing.T) {
	tests := []struct {
		name         string
		activateAt   string
		wantMutation bool
	}{
		{name: "before wrapper mutation", activateAt: "2"},
		{name: "immediately before wrapper mutation", activateAt: "3"},
		{name: "before final verification", activateAt: "4", wantMutation: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			ownershipPath := filepath.Join(directory, "ownership.state")
			useLinuxWrapperStateFile(t, ownershipPath)
			rulesPath := filepath.Join(directory, "rules")
			logPath := filepath.Join(directory, "commands.log")
			probePath := filepath.Join(directory, "ufw-probes")
			ufwScript := `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    probe=0
    if [ -f "$SYSWARDEN_UFW_PROBE_STATE" ]; then
        read -r probe < "$SYSWARDEN_UFW_PROBE_STATE"
    fi
    probe=$((probe + 1))
    printf '%s\n' "$probe" > "$SYSWARDEN_UFW_PROBE_STATE"
    if [ "$probe" -ge "$SYSWARDEN_UFW_ACTIVATE_AT" ]; then
        printf 'Status: active\n'
    else
        printf 'Status: inactive\n'
    fi
    exit 0
fi
exit 97
`
			writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(ufwScript))
			writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
			t.Setenv("PATH", directory)
			t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
			t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
			t.Setenv("SYSWARDEN_UFW_PROBE_STATE", probePath)
			t.Setenv("SYSWARDEN_UFW_ACTIVATE_AT", test.activateAt)

			verification := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(verification)
			var prepared *linuxWrapperReconciliationPlan
			transactionID, err := applyNftablesPolicyWithWrappers(
				context.Background(),
				runner,
				directory,
				minimalNftRules(),
				nil,
				verification,
				func() error {
					var prepareErr error
					prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, []string{"62028"})
					return prepareErr
				},
				nil,
				func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
			)
			if transactionID == "" {
				t.Fatal("wrapper activation race omitted transaction identifier")
			}
			for _, fragment := range []string{"committed and remains authoritative", "ufw and firewalld are both active"} {
				if err == nil || !strings.Contains(err.Error(), fragment) {
					t.Fatalf("wrapper activation race error = %v, want %q", err, fragment)
				}
			}
			if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("wrapper activation race nft apply/rollback = %d/%d, want 1/0", runner.mainApplyCalls, runner.rollbackApplyCalls)
			}
			calls := string(readRootedTestFile(t, logPath))
			mutated := strings.Contains(calls, "--add-port=62028/tcp")
			if mutated != test.wantMutation {
				t.Fatalf("wrapper mutation = %v, want %v:\n%s", mutated, test.wantMutation, calls)
			}
			if strings.Contains(calls, "--reload") {
				t.Fatalf("wrapper activation race globally reloaded firewalld:\n%s", calls)
			}
			if test.wantMutation {
				if content := string(readRootedTestFile(t, ownershipPath)); !strings.Contains(content, "firewalld\tport\t62028\tpublic") {
					t.Fatalf("postcommit mutation debt was not retained:\n%s", content)
				}
			} else if _, statErr := os.Stat(ownershipPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("pre-mutation race created ownership state: %v", statErr)
			}
		})
	}
}

func TestFirewalldFinalZoneReinspectionPreventsFalseSuccess_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	logPath := filepath.Join(directory, "commands.log")
	zoneProbePath := filepath.Join(directory, "zone-probes")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE", zoneProbePath)
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_SWITCH_AT", "4")
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT_AFTER", "work\n  interfaces: eth0")

	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, []string{"62028"})
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if transactionID == "" {
		t.Fatal("final zone race omitted transaction identifier")
	}
	for _, fragment := range []string{
		"committed and remains authoritative",
		`active firewalld port zone changed from "public" to "work" after preflight`,
	} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("final zone race error = %v, want %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("final zone race nft apply/rollback = %d/%d, want 1/0", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if content := string(readRootedTestFile(t, path)); content != "public|port=62028/tcp\n" {
			t.Fatalf("final zone race exact rule state in %s:\n%s", path, content)
		}
	}
	if content := string(readRootedTestFile(t, ownershipPath)); !strings.Contains(content, "firewalld\tport\t62028\tpublic") {
		t.Fatalf("final zone race discarded ownership debt:\n%s", content)
	}
	if calls := string(readRootedTestFile(t, logPath)); strings.Contains(calls, "--reload") {
		t.Fatalf("final zone race globally reloaded firewalld:\n%s", calls)
	}
}

func TestMissingExplicitFirewalldSourceZoneFailsBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	script := `#!/bin/sh
if [ "$*" = "--state" ]; then
    printf 'running\n'
    exit 0
fi
if [ "$*" = "--get-active-zones" ]; then
    printf 'public\n  interfaces: eth0\n'
    exit 0
fi
if [ "$*" = "--get-zones" ]; then
	printf 'public work\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(script))
	t.Setenv("PATH", directory)
	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	_, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation([]string{"192.0.2.0/24"}, nil)
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if err == nil || !strings.Contains(err.Error(), `required explicit firewalld zone "trusted" is unavailable`) || !strings.Contains(err.Error(), "preserved the previous ruleset") {
		t.Fatalf("missing explicit firewalld zone error = %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("missing explicit zone applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
}

func TestPreexistingFirewalldOperatorRuleIsNeverClaimedOrRemoved_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	rulesPath := filepath.Join(directory, "rules")
	operatorRule := "public|port=62028/tcp\n"
	runtimeOnlyOperatorRule := "work|port=63000/tcp\n"
	if err := os.WriteFile(rulesPath, []byte(operatorRule), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath+".runtime", []byte(operatorRule+runtimeOnlyOperatorRule), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("verify pre-existing firewalld rule: %v", err)
	}
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatalf("preserve pre-existing firewalld rule: %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != operatorRule {
		t.Fatalf("operator firewalld rule changed:\n%s", content)
	}
	if content := string(readRootedTestFile(t, rulesPath+".runtime")); content != operatorRule+runtimeOnlyOperatorRule {
		t.Fatalf("operator firewalld runtime rules changed:\n%s", content)
	}
	if content := string(readRootedTestFile(t, statePath)); content != linuxWrapperStateVersion+"\n" {
		t.Fatalf("operator firewalld rule was claimed:\n%s", content)
	}
	calls := string(readRootedTestFile(t, logPath))
	for _, forbidden := range []string{"--add-", "--remove-", "--reload"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("operator firewalld preservation invoked %q:\n%s", forbidden, calls)
		}
	}
}

func TestRuntimeOnlyFirewalldOperatorRuleIsNotClaimed_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	runtimeRules := "public|port=62028/tcp\nwork|port=63000/tcp\n"
	if err := os.WriteFile(rulesPath+".runtime", []byte(runtimeRules), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	err := applyLinuxFirewallWrappers(nil, []string{"62028"})
	if err == nil || !strings.Contains(err.Error(), "inconsistent permanent and runtime state") {
		t.Fatalf("runtime-only operator rule error = %v", err)
	}
	if content := string(readRootedTestFile(t, rulesPath+".runtime")); content != runtimeRules {
		t.Fatalf("runtime-only operator rules changed:\n%s", content)
	}
	if _, statErr := os.Stat(rulesPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runtime-only operator rule was copied to permanent state: %v", statErr)
	}
	if _, statErr := os.Stat(ownershipPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runtime-only operator rule was claimed: %v", statErr)
	}
	calls := string(readRootedTestFile(t, logPath))
	for _, forbidden := range []string{"--add-", "--remove-", "--reload"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("runtime-only operator rule invoked %q:\n%s", forbidden, calls)
		}
	}
}

func TestFirewalldOperatorAppearanceAfterProbeRetainsPendingDebt_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	logPath := filepath.Join(directory, "commands.log")
	queryProbePath := filepath.Join(directory, "query-probes")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_QUERY_SEQUENCE_FILE", queryProbePath)
	t.Setenv("SYSWARDEN_OPERATOR_APPEAR_QUERY", "3")

	err := applyLinuxFirewallWrappers(nil, []string{"62028"})
	if err == nil || !strings.Contains(err.Error(), "appeared after the ownership preflight") {
		t.Fatalf("operator interleaving error = %v", err)
	}
	wantRule := "public|port=62028/tcp\n"
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if content := string(readRootedTestFile(t, path)); content != wantRule {
			t.Fatalf("operator interleaving rule state in %s:\n%s", path, content)
		}
	}
	wantPending := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\tpending\n"
	if content := string(readRootedTestFile(t, ownershipPath)); content != wantPending {
		t.Fatalf("operator interleaving ownership state:\n%s", content)
	}

	err = applyLinuxFirewallWrappers(nil, []string{"62028"})
	if err == nil || !strings.Contains(err.Error(), "cannot be attributed safely") {
		t.Fatalf("pending retry attribution error = %v", err)
	}
	if content := string(readRootedTestFile(t, ownershipPath)); content != wantPending {
		t.Fatalf("pending retry changed ownership debt:\n%s", content)
	}
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if content := string(readRootedTestFile(t, path)); content != wantRule {
			t.Fatalf("pending retry changed operator rule in %s:\n%s", path, content)
		}
	}
	calls := string(readRootedTestFile(t, logPath))
	for _, forbidden := range []string{"--add-", "--remove-", "--reload"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("operator interleaving invoked %q:\n%s", forbidden, calls)
		}
	}
}

func TestAbsentPendingFirewalldRuleConvergesToOwned_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	ownershipPath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, ownershipPath)
	rulesPath := filepath.Join(directory, "rules")
	pending := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\tpending\n"
	if err := os.WriteFile(ownershipPath, []byte(pending), 0600); err != nil {
		t.Fatal(err)
	}
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	if err := applyLinuxFirewallWrappers(nil, []string{"62028"}); err != nil {
		t.Fatalf("converge absent pending firewalld rule: %v", err)
	}
	wantRule := "public|port=62028/tcp\n"
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if content := string(readRootedTestFile(t, path)); content != wantRule {
			t.Fatalf("pending convergence rule state in %s:\n%s", path, content)
		}
	}
	wantOwned := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\towned\n"
	if content := string(readRootedTestFile(t, ownershipPath)); content != wantOwned {
		t.Fatalf("pending convergence ownership state:\n%s", content)
	}
}

func TestFailedZonedFirewalldCleanupRetainsOwnershipDebtWithoutReload_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	rulesPath := filepath.Join(directory, "rules")
	if err := os.WriteFile(rulesPath, []byte("public|port=62028/tcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initial := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_REMOVE_FAIL", "1")
	err = applyLinuxFirewallWrappers(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "remove wrapper rule") {
		t.Fatalf("failed zoned cleanup error = %v", err)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || string(readRootedTestFile(t, statePath)) != initial {
		t.Fatal("failed cleanup discarded the zoned ownership debt")
	}
	if content := string(readRootedTestFile(t, rulesPath)); content != "public|port=62028/tcp\n" {
		t.Fatalf("failed cleanup changed the firewalld rule:\n%s", content)
	}
	calls := string(readRootedTestFile(t, logPath))
	if strings.Contains(calls, "--reload") {
		t.Fatalf("failed cleanup reloaded firewalld:\n%s", calls)
	}
	for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
		if strings.Contains(line, "port=62028/tcp") && !strings.Contains(line, "--zone=public") {
			t.Fatalf("cleanup command omitted recorded zone: %q", line)
		}
	}
}

func TestInactiveManagedWrappersPreserveStillDesiredOwnershipWithoutMutation_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	initial := linuxWrapperStateVersion + "\n" +
		"firewalld\tport\t62028\tpublic\towned\n" +
		"ufw\tsource\t192.0.2.0/24\t-\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	ufwScript := `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: inactive\n'
    exit 0
fi
exit 97
`
	firewalldScript := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'not running\n'
    exit 252
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(ufwScript))
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(firewalldScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	if err := applyLinuxFirewallWrappers([]string{"192.0.2.0/24"}, []string{"62028"}); err != nil {
		t.Fatalf("defer inactive wrapper ownership: %v", err)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("inactive wrapper reconciliation replaced the ownership state")
	}
	if content := readRootedTestFile(t, statePath); string(content) != initial {
		t.Fatalf("inactive wrapper ownership changed:\n%s", content)
	}
	wantCalls := strings.Repeat("ufw status\nfirewall-cmd --state\n", 4)
	if calls := readRootedTestFile(t, logPath); string(calls) != wantCalls {
		t.Fatalf("inactive wrappers received unexpected commands:\n%s", calls)
	}
}

func TestInactiveStaleOwnedPermissionsFailBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	initial := linuxWrapperStateVersion + "\n" +
		"firewalld\tport\t62028\tpublic\towned\n" +
		"ufw\tsource\t192.0.2.0/24\t-\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	ufwScript := `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: inactive\n'
    exit 0
fi
exit 97
`
	firewalldScript := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "--state" ]; then
    printf 'not running\n'
    exit 252
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(ufwScript))
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(firewalldScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)

	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var prepared *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		context.Background(),
		runner,
		directory,
		minimalNftRules(),
		nil,
		verification,
		func() error {
			var prepareErr error
			prepared, prepareErr = prepareLinuxFirewallWrapperReconciliation(nil, nil)
			return prepareErr
		},
		nil,
		func() error { return reconcileLinuxFirewallWrapperPlan(prepared) },
	)
	if transactionID == "" {
		t.Fatal("wrapper preflight failure omitted the transaction identifier")
	}
	for _, fragment := range []string{
		"preserved the previous ruleset",
		"inactive firewalld retains stale owned permission",
		"inactive ufw retains stale owned permission",
		"verified cleanup is required before the nftables commit",
	} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("wrapper preflight error = %v, want fragment %q", err, fragment)
		}
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("preflight failure applied or rolled back nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, statErr := os.Stat(filepath.Join(directory, "syswarden.nft")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("preflight failure persisted an nftables policy: %v", statErr)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("stale inactive wrapper preflight replaced the ownership state")
	}
	if content := readRootedTestFile(t, statePath); string(content) != initial {
		t.Fatalf("stale inactive wrapper preflight changed ownership:\n%s", content)
	}
	wantCalls := "ufw status\nfirewall-cmd --state\n"
	if calls := readRootedTestFile(t, logPath); string(calls) != wantCalls {
		t.Fatalf("stale inactive wrapper preflight issued mutation commands:\n%s", calls)
	}
}

func TestManagedWrapperStateErrorPreventsOwnershipAndWrapperMutation_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	initial := linuxWrapperStateVersion + "\nfirewalld\tport\t62028\tpublic\towned\n"
	if err := os.WriteFile(statePath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "commands.log")
	script := `#!/bin/sh
printf 'firewall-cmd %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
printf 'dbus unavailable\n'
exit 7
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(script))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	err = applyLinuxFirewallWrappers(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "inspect installed firewalld compatibility wrapper") {
		t.Fatalf("wrapper state error = %v, want fail-closed discovery error", err)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("failed wrapper discovery replaced the ownership state")
	}
	if content := readRootedTestFile(t, statePath); string(content) != initial {
		t.Fatalf("failed wrapper discovery changed ownership:\n%s", content)
	}
	if calls := readRootedTestFile(t, logPath); string(calls) != "firewall-cmd --state\n" {
		t.Fatalf("failed wrapper discovery issued a mutation command:\n%s", calls)
	}
}

func TestActiveManagedWrappersWithoutRulesAreNotMutated_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	logPath := filepath.Join(directory, "commands.log")
	ufwScript := `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$SYSWARDEN_WRAPPER_LOG"
if [ "$*" = "status" ]; then
    printf 'Status: active\n'
    exit 0
fi
exit 97
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(ufwScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatalf("empty active wrapper reconciliation: %v", err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty reconciliation created ownership state: %v", err)
	}
	wantCalls := strings.Repeat("ufw status\n", 2)
	if calls := readRootedTestFile(t, logPath); string(calls) != wantCalls {
		t.Fatalf("active wrappers without rules received mutation commands:\n%s", calls)
	}
}

func TestWrapperFailureReportsCommittedAuthoritativeNftState_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	script := `#!/bin/sh
if [ "$*" = "status" ]; then
    printf 'Status: active\n'
    exit 0
fi
exit 2
`
	writeRootedExecutableTestFile(t, filepath.Join(directory, "ufw"), []byte(script))
	t.Setenv("PATH", directory)
	wrapperErr := applyLinuxFirewallWrappers([]string{"192.0.2.0/24"}, []string{"62028"})
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
		nil,
		nil,
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
	previousPreflight := firewallBackendPreflight
	firewallBackendPreflight = func(string) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previous
		firewallBackendPreflight = previousPreflight
	})
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
			name: "HA port collides with cloaked SSH",
			configure: func(value *config.Config) {
				value.EnableWG = true
				value.HAEnabled = true
				value.HAPeerPort = "022"
			},
			wantError: "HA peer port must differ from the effective SSH port while WireGuard cloaking is enabled",
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
