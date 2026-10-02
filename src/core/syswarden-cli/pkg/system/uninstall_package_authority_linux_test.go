//go:build linux

package system

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type packageAuthorityTestExit int

func (status packageAuthorityTestExit) Error() string { return fmt.Sprintf("query exit %d", status) }
func (status packageAuthorityTestExit) ExitCode() int { return int(status) }

func TestStandaloneUninstallRejectsNativePackageRegistration(t *testing.T) {
	cases := []struct{ manager, output, guidance string }{
		{"dpkg-query", "syswarden\tinstalled\n", "apt-get purge"},
		{"dpkg-query", "syswarden\thalf-configured\n", "apt-get purge"},
		{"dpkg-query", "syswarden\tconfig-files\n", "apt-get purge"},
		{"dpkg-query", "syswarden\tunpacked\n", "apt-get purge"},
		{"rpm", "syswarden\n", "dnf remove"},
		{"apk", "", "apk del"},
	}
	for _, tc := range cases {
		t.Run(tc.manager+strings.TrimSpace(tc.output), func(t *testing.T) {
			calls := 0
			executor := testFirewallRemovalPackageExecutor(t, []string{tc.manager}, func(path string, args ...string) ([]byte, error) {
				calls++
				if filepath.Base(path) != tc.manager {
					t.Fatal("unexpected manager")
				}
				if !reflect.DeepEqual(args[len(args)-1:], []string{"syswarden"}) {
					t.Fatal("query not limited to SysWarden")
				}
				return []byte(tc.output), nil
			})
			err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil })
			if err == nil || !strings.Contains(err.Error(), tc.guidance) || calls != 1 {
				t.Fatalf("registration not protected: %v calls=%d", err, calls)
			}
		})
	}
}

func TestStandaloneUninstallAllowsOnlyProvenAbsentPackages(t *testing.T) {
	for _, tc := range []struct {
		manager, output string
		err             error
	}{
		{"dpkg-query", "dpkg-query: no packages found matching syswarden\n", packageAuthorityTestExit(1)},
		{"dpkg-query", "syswarden\tnot-installed\n", nil},
		{"rpm", "package syswarden is not installed\n", packageAuthorityTestExit(1)},
		{"apk", "", packageAuthorityTestExit(1)},
	} {
		executor := testFirewallRemovalPackageExecutor(t, []string{tc.manager}, func(string, ...string) ([]byte, error) { return []byte(tc.output), tc.err })
		if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("%s absence rejected: %v", tc.manager, err)
		}
	}
}

func TestStandaloneUninstallRejectsAmbiguousOrUnavailableAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, manager, output string
		err                   error
		database              bool
	}{
		{name: "broken database", manager: "dpkg-query", output: "database unreadable\n", err: packageAuthorityTestExit(1)},
		{name: "untyped failure", manager: "dpkg-query", output: "dpkg-query: no packages found matching syswarden\n", err: errors.New("untyped")},
		{name: "wrong exit", manager: "dpkg-query", output: "dpkg-query: no packages found matching syswarden\n", err: packageAuthorityTestExit(2)},
		{name: "duplicate record", manager: "dpkg-query", output: "syswarden\tinstalled\nsyswarden\tinstalled\n"},
		{name: "foreign record", manager: "dpkg-query", output: "other\tinstalled\n"},
		{name: "unknown state", manager: "dpkg-query", output: "syswarden\tunknown\n"},
		{name: "RPM duplicate", manager: "rpm", output: "syswarden\nsyswarden\n"},
		{name: "APK error", manager: "apk", output: "ERROR: database\n", err: packageAuthorityTestExit(1)},
		{name: "missing tool with database", database: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{}
			if tc.manager != "" {
				names = append(names, tc.manager)
			}
			executor := testFirewallRemovalPackageExecutor(t, names, func(string, ...string) ([]byte, error) { return []byte(tc.output), tc.err })
			if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return tc.database, nil }); err == nil {
				t.Fatal("ambiguous package ownership permitted direct removal")
			}
		})
	}
}

func TestStandaloneUninstallRejectsConflictingNativeManagers(t *testing.T) {
	executor := testFirewallRemovalPackageExecutor(t, []string{"rpm", "apk"}, func(path string, args ...string) ([]byte, error) {
		if filepath.Base(path) == "rpm" {
			return []byte("syswarden\n"), nil
		}
		return nil, nil
	})
	if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil }); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("conflicting claims: %v", err)
	}
}
