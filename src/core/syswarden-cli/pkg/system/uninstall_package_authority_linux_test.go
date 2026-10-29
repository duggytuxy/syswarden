//go:build linux

package system

import (
	"errors"
	"fmt"
	"path/filepath"
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
		for _, packageName := range nativeProductPackageNames {
			t.Run(tc.manager+packageName+strings.TrimSpace(tc.output), func(t *testing.T) {
				calls := 0
				executor := testFirewallRemovalPackageExecutor(t, []string{tc.manager}, func(path string, args ...string) ([]byte, error) {
					calls++
					if filepath.Base(path) != tc.manager {
						t.Fatal("unexpected manager")
					}
					name, matched := nativeRegistrationTestQuery(tc.manager, args)
					if !matched {
						t.Fatal("query not limited to the two native identities")
					}
					if name != packageName {
						return nativeRegistrationTestOutput(tc.manager, name, "")
					}
					return []byte(strings.ReplaceAll(tc.output, "syswarden", packageName)), nil
				})
				err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil })
				if err == nil || !strings.Contains(err.Error(), tc.guidance+" "+packageName) || calls != 2 {
					t.Fatalf("registration not protected: %v calls=%d", err, calls)
				}
			})
		}
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
		executor := testFirewallRemovalPackageExecutor(t, []string{tc.manager}, func(_ string, args ...string) ([]byte, error) {
			name, matched := nativeRegistrationTestQuery(tc.manager, args)
			if !matched {
				t.Fatal("unexpected native registration query")
			}
			return []byte(strings.ReplaceAll(tc.output, "syswarden", name)), tc.err
		})
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
		manager := filepath.Base(path)
		name, matched := nativeRegistrationTestQuery(manager, args)
		if !matched {
			t.Fatal("unexpected native registration query")
		}
		state := "installed"
		if name == baseNativePackageName {
			state = ""
		}
		return nativeRegistrationTestOutput(manager, name, state)
	})
	if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil }); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("conflicting claims: %v", err)
	}
}

func TestUninstallAllowsOnlyExactlyAttestedSingleRPMProfile(t *testing.T) {
	sentinel := errors.New("modified RPM profile")
	for _, test := range []struct {
		name       string
		managers   []string
		present    bool
		profileErr error
		queryErr   error
		wantCall   bool
		wantError  bool
	}{
		{name: "exact optional profile", managers: []string{"rpm"}, present: true, wantCall: true},
		{name: "ordinary RPM", managers: []string{"rpm"}, wantCall: true, wantError: true},
		{name: "modified profile", managers: []string{"rpm"}, present: true, profileErr: sentinel, wantCall: true, wantError: true},
		{name: "multiple managers", managers: []string{"rpm", "apk"}, present: true, wantError: true},
		{name: "DEB cannot use RPM authority", managers: []string{"dpkg-query"}, present: true, wantError: true},
		{name: "failed package query", managers: []string{"rpm"}, present: true, queryErr: sentinel, wantError: true},
		{name: "standalone", managers: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			executor := testFirewallRemovalPackageExecutor(t, test.managers, func(path string, args ...string) ([]byte, error) {
				if test.queryErr != nil {
					return nil, test.queryErr
				}
				manager := filepath.Base(path)
				name, matched := nativeRegistrationTestQuery(manager, args)
				if !matched {
					t.Fatal("unexpected native registration query")
				}
				state := "installed"
				if name == baseNativePackageName {
					state = ""
				}
				return nativeRegistrationTestOutput(manager, name, state)
			})
			err := preflightUninstallWithProfile(executor, func(string) (bool, error) { return false, nil }, func() (bool, error) { called = true; return test.present, test.profileErr })
			if called != test.wantCall || (err != nil) != test.wantError {
				t.Fatalf("profile inspection=%v error=%v", called, err)
			}
			if test.profileErr != nil && !errors.Is(err, sentinel) {
				t.Fatal("profile failure lost its cause")
			}
		})
	}
}

func TestUninstallCompletionPreservesRPMOwnedPayload(t *testing.T) {
	sentinel := errors.New("ownership changed")
	for _, test := range []struct {
		name          string
		present       bool
		profileErr    error
		standaloneErr error
		wantDelete    bool
		wantError     bool
	}{
		{name: "RPM payload", present: true},
		{name: "standalone", wantDelete: true},
		{name: "profile ambiguity", profileErr: sentinel, wantError: true},
		{name: "package appeared before deletion", standaloneErr: sentinel, wantDelete: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := removeUninstallCompletionPayloadWith("exact completion", func() (bool, error) { return test.present, test.profileErr }, func(content string) error {
				called = true
				if content != "exact completion" {
					t.Fatal("completion changed")
				}
				return test.standaloneErr
			})
			if called != test.wantDelete || (err != nil) != test.wantError {
				t.Fatalf("standalone removal=%v error=%v", called, err)
			}
		})
	}
}
