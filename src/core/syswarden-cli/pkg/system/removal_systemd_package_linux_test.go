//go:build linux

package system

import (
	"errors"
	"testing"
)

func TestHistoricalRemovalPackageOwnerRequiresExactStateAndBarrier(t *testing.T) {
	for _, test := range []struct {
		name       string
		owner      string
		state      string
		barrierErr int
		queryErr   bool
		pass       bool
	}{
		{"exact", "4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.2\n", 0, false, true},
		{"absent barrier", "4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.2\n", 1, false, false},
		{"barrier drift", "4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.2\n", 2, false, false},
		{"query failure", "4.10.2\tamd64\n", "", 0, true, false},
		{"installed", "4.10.2\tamd64\n", "install ok installed\tamd64\t4.10.2\n", 0, false, false},
		{"unpacked", "4.10.2\tamd64\n", "install ok unpacked\tamd64\t4.10.2\n", 0, false, false},
		{"wrong state version", "4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.1\n", 0, false, false},
		{"wrong architecture", "4.10.2\tarm64\n", "install ok half-configured\tarm64\t4.10.2\n", 0, false, false},
		{"unknown old release", "4.10.1\tamd64\n", "install ok half-configured\tamd64\t4.10.1\n", 0, false, false},
		{"epoch", "1:4.10.2\tamd64\n", "install ok half-configured\tamd64\t1:4.10.2\n", 0, false, false},
		{"duplicate owner", "4.10.2\tamd64\n4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.2\n", 0, false, false},
		{"duplicate status", "4.10.2\tamd64\n", "install ok half-configured\tamd64\t4.10.2\ninstall ok half-configured\tamd64\t4.10.2\n", 0, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			barrierCalls, queryCalls := 0, 0
			claim, err := parseSystemdRemovalDPKGOwnerWith([]byte(test.owner), func() error {
				barrierCalls++
				if barrierCalls == test.barrierErr {
					return errors.New("unproven barrier fixture")
				}
				return nil
			}, func() ([]byte, error) {
				queryCalls++
				if test.queryErr {
					return nil, errors.New("package query fixture failure")
				}
				return []byte(test.state), nil
			})
			if (err == nil) != test.pass {
				t.Fatalf("claim=%q error=%v expected success=%t", claim, err, test.pass)
			}
			if test.pass && (barrierCalls != 2 || queryCalls != 1 || claim != "syswarden@4.10.2#amd64#dpkg#half-configured-removal") {
				t.Fatal("historical package claim did not retain its exact state and barrier proof")
			}
		})
	}
}

func TestHistoricalRemovalPackageExceptionDoesNotChangeNormalOwnership(t *testing.T) {
	if _, err := parseSysWardenDPKGDropInOwner([]byte("4.10.2\tamd64\n")); err == nil {
		t.Fatal("normal operation admitted a different release")
	}
	current, err := currentSysWardenPackageVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSystemdRemovalDPKGOwnerWith([]byte(current+"\tamd64\n"), nil, nil); err != nil {
		t.Fatalf("current release removal changed: %v", err)
	}
	if _, err := parseSystemdRemovalDPKGOwnerWith([]byte("4.10.2\tamd64\n"), nil, nil); err == nil {
		t.Fatal("historical release admitted without barrier and state dependencies")
	}
}

func TestHistoricalRemovalDropInReattestsPackageStateWithoutChangingFile(t *testing.T) {
	for _, drift := range []bool{false, true} {
		root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
		executor := testSysWardenOrderingPackageExecutor(t, path, true, false, func(string) string { return "4.10.2" })
		original := mustReadTestFile(t, path)
		if _, err := attestExactSystemdFirewallOrderingDropInAt(executor, path, path, root, uid, gid); err == nil {
			t.Fatal("normal drop-in attestation admitted a historical package")
		}
		queries := 0
		_, err := attestExactSystemdPackageDropInWithDPKGOwner(
			executor, path, path, root, uid, gid, systemdFirewallWireGuardOrderingDropIn, "ordering",
			func(owner []byte) (string, error) {
				return parseSystemdRemovalDPKGOwnerWith(owner, func() error { return nil }, func() ([]byte, error) {
					queries++
					if drift && queries == 2 {
						return []byte("install ok unpacked\tamd64\t4.10.2\n"), nil
					}
					return []byte("install ok half-configured\tamd64\t4.10.2\n"), nil
				})
			},
		)
		if (err != nil) != drift || queries != 2 {
			t.Fatalf("drift=%t queries=%d error=%v", drift, queries, err)
		}
		if string(mustReadTestFile(t, path)) != string(original) {
			t.Fatal("drop-in was changed during read-only package attestation")
		}
	}
}
