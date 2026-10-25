//go:build linux

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const apkRetentionFixtureChecksum = "Q1AAECAwQFBgcICQoLDA0ODxAREhM="

func apkRetentionFixtureDatabase() string {
	return "P:syswarden\nV:4.10.4-r0\nA:x86_64\nC:" + apkRetentionFixtureChecksum + "\nD:nftables wireguard-tools rsyslog\nf:S\nF:opt/syswarden\nR:fixture\n\n" +
		"P:wireguard-tools\nV:1.0-r0\n\nP:rsyslog\nV:8.0-r0\n\n" +
		"P:unrelated\nV:1.0-r0\nf:s\n\n"
}

func TestAPKRetentionChecksumEncodingIsBoundedAndCanonical(t *testing.T) {
	if !validAPKRetentionChecksum(apkRetentionFixtureChecksum) {
		t.Fatal("canonical observed checksum encoding rejected")
	}
	for _, checksum := range []string{
		"", "Q1", strings.Replace(apkRetentionFixtureChecksum, "Q1", "Q2", 1),
		strings.TrimSuffix(apkRetentionFixtureChecksum, "="),
		apkRetentionFixtureChecksum + "\n", " " + apkRetentionFixtureChecksum,
		strings.Replace(apkRetentionFixtureChecksum, "EhM=", "EhN=", 1),
		strings.Replace(apkRetentionFixtureChecksum, "AAEC", "____", 1),
		"Q1" + strings.Repeat("0", 40),
	} {
		if validAPKRetentionChecksum(checksum) {
			t.Fatalf("unsupported checksum encoding accepted: %q", checksum)
		}
	}
}

func TestAPKRetentionSelectedProductChecksumRoot(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		database := strings.Replace(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+packageName+"\n", 1)
		checksumLine := "C:" + apkRetentionFixtureChecksum + "\n"
		boundRoot := packageName + "><" + apkRetentionFixtureChecksum + "\n"
		for _, test := range []struct {
			name, world, database string
			valid                 bool
		}{
			{"exact native checksum root", boundRoot, database, true},
			{"bare root with canonical identity", packageName + "\n", database, true},
			{"missing bound checksum", boundRoot, strings.Replace(database, checksumLine, "", 1), false},
			{"missing bare checksum", packageName + "\n", strings.Replace(database, checksumLine, "", 1), false},
			{"mismatched installed checksum", boundRoot, strings.Replace(database, checksumLine, "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", 1), false},
			{"malformed installed checksum", boundRoot, strings.Replace(database, checksumLine, "C:Q1invalid\n", 1), false},
			{"unsupported installed checksum", boundRoot, strings.Replace(database, checksumLine, "C:Q2AAECAwQFBgcICQoLDA0ODxAREhM=\n", 1), false},
			{"duplicate installed checksum", boundRoot, strings.Replace(database, checksumLine, checksumLine+checksumLine, 1), false},
			{"duplicate checksum roots", boundRoot + boundRoot, database, false},
			{"bare and checksum roots", packageName + "\n" + boundRoot, database, false},
			{"tagged checksum root", packageName + "@local><" + apkRetentionFixtureChecksum + "\n", database, false},
			{"version comparator with checksum", packageName + "=" + apkRetentionFixtureChecksum + "\n", database, false},
			{"unbound checksum form", packageName + "><Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", database, false},
		} {
			t.Run(packageName+"/"+test.name, func(t *testing.T) {
				world, installed := []byte(test.world), []byte(test.database)
				beforeWorld, beforeInstalled := bytes.Clone(world), bytes.Clone(installed)
				got, err := apkDependencyRetentionNamesForName(packageName, world, installed)
				if test.valid {
					if err != nil || !reflect.DeepEqual(got, []string{"rsyslog", "wireguard-tools"}) {
						t.Fatalf("exact checksum root: %q %v", got, err)
					}
				} else if err == nil || len(got) != 0 {
					t.Fatalf("ambiguous checksum root accepted: %q %v", got, err)
				}
				if !bytes.Equal(world, beforeWorld) || !bytes.Equal(installed, beforeInstalled) {
					t.Fatal("checksum inspection changed native inventory")
				}
			})
		}
	}
}

func TestAPKRetentionPreservesExistingChoices(t *testing.T) {
	database := apkRetentionFixtureDatabase()
	for _, test := range []struct {
		name, world, database string
		want                  []string
	}{
		{"historical optional dependencies", "syswarden\n", database, []string{"rsyslog", "wireguard-tools"}},
		{"pinned administrator dependency", "syswarden\nrsyslog=8.0-r0\n", database, []string{"wireguard-tools"}},
		{"tagged administrator dependency", "syswarden\nrsyslog@local~8\n", database, []string{"wireguard-tools"}},
		{"independent administrator dependency", "syswarden\nrsyslog\nwireguard-tools\n", database, nil},
		{"modern minimal metadata", "syswarden\n", strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:nftables", 1), nil},
		{"unrelated packages do not become roots", "syswarden\n", strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:unrelated", 1), nil},
		{"no dependency field", "syswarden\n", strings.Replace(database, "D:nftables wireguard-tools rsyslog\n", "", 1), nil},
		{"unselected optional package repair is independent", "syswarden\n", strings.Replace(strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:nftables", 1), "P:rsyslog\n", "P:rsyslog\nf:s\n", 1), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			worldBefore, databaseBefore := []byte(test.world), []byte(test.database)
			got, err := apkDependencyRetentionNames(worldBefore, databaseBefore)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("names %q, error %v, want %q", got, err, test.want)
			}
			if string(worldBefore) != test.world || string(databaseBefore) != test.database {
				t.Fatal("inventory was modified")
			}
		})
	}
}

func TestAPKRetentionSelectedProductPreservesDependencyScope(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, minimal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/minimal=%t", packageName, minimal), func(t *testing.T) {
				database := strings.Replace(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+packageName+"\n", 1)
				want := []string{"wireguard-tools"}
				if minimal {
					database = strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:bash-completion cronie cronie-openrc curl jq nftables openrc procps-ng shadow wget", 1)
					want = nil
				}
				world := []byte(packageName + "\nrsyslog@local=8.0-r0\n")
				installed := []byte(database)
				beforeWorld, beforeInstalled := bytes.Clone(world), bytes.Clone(installed)
				got, err := apkDependencyRetentionNamesForName(packageName, world, installed)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("selected dependencies: %q %v, want %q", got, err, want)
				}
				if !bytes.Equal(world, beforeWorld) || !bytes.Equal(installed, beforeInstalled) {
					t.Fatal("retention modified native inventory")
				}
			})
		}
	}
}

func TestAPKRetentionSelectedProductRefusesAmbiguityAndConstraints(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		other := compatibilityNativePackageName
		if packageName == other {
			other = baseNativePackageName
		}
		database := strings.Replace(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+packageName+"\n", 1)
		for _, test := range []struct{ name, world, database string }{
			{"missing selected owner", packageName + "\n", strings.Replace(database, "P:"+packageName+"\n", "P:"+other+"\n", 1)},
			{"coexisting identities", packageName + "\n", database + "P:" + other + "\nV:5.00.0-r0\nA:x86_64\n\n"},
			{"missing product architecture", packageName + "\n", strings.Replace(database, "A:x86_64\n", "", 1)},
			{"architecture independent product", packageName + "\n", strings.Replace(database, "A:x86_64\n", "A:noarch\n", 1)},
			{"foreign product architecture", packageName + "\n", strings.Replace(database, "A:x86_64\n", "A:x86\n", 1)},
			{"duplicate product architecture", packageName + "\n", strings.Replace(database, "A:x86_64\n", "A:x86_64\nA:x86_64\n", 1)},
			{"ambiguous product version", packageName + "\n", strings.Replace(database, "V:4.10.4-r0\n", "V:4.10.4-r0 other\n", 1)},
			{"unrooted product", "alpine-base\n", database},
			{"duplicate product root", packageName + "\n" + packageName + "\n", database},
			{"other product root", packageName + "\n" + other + "\n", database},
			{"other product conflict", packageName + "\n!" + other + "\n", database},
			{"pinned product", packageName + "=4.10.4-r0\n", database},
			{"tagged product", packageName + "@local\n", database},
			{"tagged pinned product", packageName + "@local=4.10.4-r0\n", database},
			{"minimum product", packageName + ">=4.10.4-r0\n", database},
			{"maximum product", packageName + "<5.00.0-r0\n", database},
			{"fuzzy product", packageName + "~4\n", database},
			{"conflicting product", "!" + packageName + "\n", database},
		} {
			t.Run(packageName+"/"+test.name, func(t *testing.T) {
				world, installed := []byte(test.world), []byte(test.database)
				beforeWorld, beforeInstalled := bytes.Clone(world), bytes.Clone(installed)
				if got, err := apkDependencyRetentionNamesForName(packageName, world, installed); err == nil || len(got) != 0 {
					t.Fatalf("unsafe selected product accepted: %q %v", got, err)
				}
				if !bytes.Equal(world, beforeWorld) || !bytes.Equal(installed, beforeInstalled) {
					t.Fatal("refusal modified native inventory")
				}
			})
		}
	}
}

func TestAPKRetentionSelectedProductRejectsUnknownNamesBeforeInventory(t *testing.T) {
	for _, name := range []string{"", "other", "syswarden-base=1", "syswarden*", "--root=/tmp"} {
		if got, err := apkDependencyRetentionNamesForName(name, []byte("syswarden\n"), []byte(apkRetentionFixtureDatabase())); err == nil || len(got) != 0 {
			t.Fatalf("unknown owner accepted: %q %v", got, err)
		}
		got, err := apkPreservedInstallArgumentsForName(name, "/sbin/apk", []string{"add", "/var/tmp/syswarden-update-safe/package.apk"}, openRCWireGuardDefinitionPaths{root: "/not-an-inventory"})
		if err == nil || len(got) != 0 || strings.Contains(err.Error(), "read protected") {
			t.Fatalf("unknown owner reached native inventory: %q %v", got, err)
		}
	}
}

func TestAPKRetentionRejectsAmbiguousOrBrokenState(t *testing.T) {
	database := apkRetentionFixtureDatabase()
	for _, test := range []struct{ name, world, database string }{
		{"no installed product", "alpine-base\n", "P:rsyslog\nV:8.0-r0\n\n"},
		{"missing dependency", "syswarden\n", strings.Replace(database, "P:rsyslog\nV:8.0-r0\n\n", "", 1)},
		{"constrained historical metadata", "syswarden\n", strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:rsyslog=8.0-r0", 1)},
		{"duplicate historical metadata", "syswarden\n", strings.Replace(database, "D:nftables wireguard-tools rsyslog", "D:rsyslog rsyslog", 1)},
		{"broken product", "syswarden\n", strings.Replace(database, "f:S", "f:Ss", 1)},
		{"broken dependency", "syswarden\n", strings.Replace(database, "P:rsyslog\n", "P:rsyslog\nf:f\n", 1)},
		{"unknown dependency flag", "syswarden\n", strings.Replace(database, "P:rsyslog\n", "P:rsyslog\nf:z\n", 1)},
		{"duplicate package", "syswarden\n", database + "P:rsyslog\nV:8.1-r0\n\n"},
		{"duplicate field", "syswarden\n", strings.Replace(database, "P:syswarden\n", "P:syswarden\nP:rsyslog\n", 1)},
		{"missing identity", "syswarden\n", database + "P:extra\n\n"},
		{"malformed record", "syswarden\n", database + "malformed\n\n"},
		{"conflicting world", "syswarden\n!rsyslog\n", database},
		{"duplicate world", "syswarden\nrsyslog=8.0-r0\nrsyslog\n", database},
		{"ambiguous whitespace", "syswarden\n rsyslog\n", database},
		{"ambiguous whitespace token", "syswarden\nrsyslog wireguard-tools\n", database},
		{"empty world", "", database},
		{"empty database", "syswarden\n", ""},
		{"world NUL", "syswarden\x00\n", database},
		{"database NUL", "syswarden\n", database + "\x00"},
		{"database carriage return", "syswarden\n", database + "\r"},
		{"world tab", "syswarden\t\n", database},
		{"oversized world", strings.Repeat("a", (1<<20)+1), database},
		{"oversized record line", "syswarden\n", database + "P:" + strings.Repeat("a", 64<<10) + "\nV:1\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if names, err := apkDependencyRetentionNames([]byte(test.world), []byte(test.database)); err == nil || len(names) != 0 {
				t.Fatalf("unsafe inventory accepted: %q %v", names, err)
			}
		})
	}
}

func apkRetentionProtectedFixture(t *testing.T) (openRCWireGuardDefinitionPaths, string, string) {
	t.Helper()
	paths := openRCWireGuardDefinitionPaths{root: t.TempDir(), expectedUID: systemTestUID(t), expectedGID: systemTestGID(t)}
	world := filepath.Join(paths.root, "etc/apk/world")
	database := filepath.Join(paths.root, "lib/apk/db/installed")
	for path, content := range map[string]string{world: "syswarden\nrsyslog=8.0-r0\n", database: apkRetentionFixtureDatabase()} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return paths, world, database
}

func TestAPKRetentionProtectedArguments(t *testing.T) {
	paths, world, database := apkRetentionProtectedFixture(t)
	for _, executable := range []string{"/sbin/apk", "/usr/sbin/apk"} {
		target := packageTarget{format: packageFormatAPK, installer: executable}
		packagePath := "/var/tmp/syswarden-update-safe/package.apk"
		_, offline := target.qualificationInstallCommand(packagePath)
		for _, args := range [][]string{target.installArguments(packagePath), offline} {
			original := append([]string(nil), args...)
			got, err := apkPreservedInstallArguments(executable, args, paths)
			want := append(append([]string(nil), args...), "wireguard-tools")
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("args %q, error %v, want %q", got, err, want)
			}
			if !reflect.DeepEqual(args, original) {
				t.Fatal("caller arguments changed")
			}
		}
	}
	for path, want := range map[string]string{world: "syswarden\nrsyslog=8.0-r0\n", database: apkRetentionFixtureDatabase()} {
		got, err := os.ReadFile(path) // #nosec G304 -- exact private fixture paths created by this test
		if err != nil || string(got) != want {
			t.Fatalf("inventory mutated: %v", err)
		}
	}
}

func TestAPKRetentionSelectedProductProtectedArguments(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, minimal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/minimal=%t", packageName, minimal), func(t *testing.T) {
				paths, world, database := apkRetentionProtectedFixture(t)
				worldContent := packageName + "><" + apkRetentionFixtureChecksum + "\nrsyslog@local=8.0-r0\n"
				databaseContent := strings.Replace(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+packageName+"\n", 1)
				if minimal {
					databaseContent = strings.Replace(databaseContent, "D:nftables wireguard-tools rsyslog", "D:bash-completion cronie cronie-openrc curl jq nftables openrc procps-ng shadow wget", 1)
				}
				for path, content := range map[string]string{world: worldContent, database: databaseContent} {
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, executable := range []string{"/sbin/apk", "/usr/sbin/apk"} {
					target := packageTarget{packageName: packageName, format: packageFormatAPK, installer: executable}
					packagePath := "/var/tmp/syswarden-update-safe/" + packageName + ".apk"
					_, offline := target.qualificationInstallCommand(packagePath)
					for _, args := range [][]string{target.installArguments(packagePath), offline} {
						original := append([]string(nil), args...)
						want := append([]string(nil), args...)
						if !minimal {
							want = append(want, "wireguard-tools")
						}
						got, err := apkPreservedInstallArgumentsForName(packageName, executable, args, paths)
						if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, original) {
							t.Fatalf("selected argument plan: %q %v, want %q", got, err, want)
						}
					}
				}
				for path, want := range map[string]string{world: worldContent, database: databaseContent} {
					got, err := os.ReadFile(path) // #nosec G304 -- exact protected private fixture created above
					if err != nil || string(got) != want {
						t.Fatalf("native inventory changed: %v", err)
					}
				}
			})
		}
	}
}

func TestAPKRetentionSelectedProductConstraintRefusalPreservesInventory(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, root := range []string{packageName + "=4.10.4-r0", packageName + "@local", "alpine-base"} {
			t.Run(root, func(t *testing.T) {
				paths, world, database := apkRetentionProtectedFixture(t)
				worldContent := root + "\nrsyslog=8.0-r0\n"
				databaseContent := strings.Replace(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+packageName+"\n", 1)
				for path, content := range map[string]string{world: worldContent, database: databaseContent} {
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				target := packageTarget{packageName: packageName, format: packageFormatAPK, installer: "/sbin/apk"}
				packagePath := "/var/tmp/syswarden-update-safe/" + packageName + ".apk"
				_, offline := target.qualificationInstallCommand(packagePath)
				for _, args := range [][]string{target.installArguments(packagePath), offline} {
					original := append([]string(nil), args...)
					got, err := apkPreservedInstallArgumentsForName(packageName, target.installer, args, paths)
					if err == nil || len(got) != 0 || !strings.Contains(err.Error(), "product root") || !reflect.DeepEqual(args, original) {
						t.Fatalf("constrained product returned a plan: %q %v", got, err)
					}
				}
				for path, want := range map[string]string{world: worldContent, database: databaseContent} {
					got, err := os.ReadFile(path) // #nosec G304 -- exact protected private fixture created above
					if err != nil || string(got) != want {
						t.Fatalf("refusal changed native inventory: %v", err)
					}
				}
			})
		}
	}
}

func TestAPKRetentionRejectsUnsafeInventoryPaths(t *testing.T) {
	for _, kind := range []string{"world writable", "database writable", "world symlink", "database hardlink", "parent writable", "missing database", "wrong owner"} {
		t.Run(kind, func(t *testing.T) {
			paths, world, database := apkRetentionProtectedFixture(t)
			var err error
			switch kind {
			case "world writable":
				err = os.Chmod(world, 0620) // #nosec G302 -- adversarial private fixture proves writable inventory is refused
			case "database writable":
				err = os.Chmod(database, 0620) // #nosec G302 -- adversarial private fixture proves writable inventory is refused
			case "world symlink":
				if err = os.Rename(world, world+".original"); err == nil {
					err = os.Symlink(world+".original", world)
				}
			case "database hardlink":
				err = os.Link(database, database+".other")
			case "parent writable":
				err = os.Chmod(filepath.Dir(world), 0720) // #nosec G302 -- adversarial private fixture proves writable parents are refused
			case "missing database":
				err = os.Remove(database)
			case "wrong owner":
				paths.expectedUID++
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := apkPreservedInstallArguments("/sbin/apk", []string{"add", "/var/tmp/syswarden-update-safe/package.apk"}, paths); err == nil || len(got) != 0 {
				t.Fatalf("unsafe inventory accepted: %q %v", got, err)
			}
		})
	}
}

func TestAPKRetentionCannotAcceptInjectedCommands(t *testing.T) {
	paths := openRCWireGuardDefinitionPaths{root: "/not-an-inventory"}
	for _, executable := range []string{"apk", "/tmp/apk", "/usr/bin/apt-get", "/sbin/apk", "/usr/sbin/apk"} {
		for _, args := range [][]string{{"add", "syswarden"}, {"del", "syswarden"}, {"add", "/var/tmp/syswarden-update-safe/package.apk", "rsyslog"}, {"add", "--allow-untrusted", "/var/tmp/syswarden-update-safe/package.apk"}} {
			if got, err := apkPreservedInstallArguments(executable, args, paths); err == nil || len(got) != 0 || strings.Contains(err.Error(), "read protected") {
				t.Fatalf("unsafe command reached inventory: %q %v", got, err)
			}
		}
	}
}

func FuzzAPKRetentionInventory(f *testing.F) {
	f.Add([]byte("syswarden\n"), []byte(apkRetentionFixtureDatabase()))
	f.Add([]byte("syswarden\nrsyslog@local=8.0-r0\n"), []byte(apkRetentionFixtureDatabase()))
	f.Fuzz(func(t *testing.T, world, database []byte) {
		if len(world) > 1<<20 || len(database) > 1<<20 {
			t.Skip()
		}
		beforeWorld, beforeDatabase := bytes.Clone(world), bytes.Clone(database)
		names, err := apkDependencyRetentionNames(world, database)
		if !bytes.Equal(world, beforeWorld) || !bytes.Equal(database, beforeDatabase) {
			t.Fatal("parser modified inventory")
		}
		if err != nil && len(names) > 0 {
			t.Fatal("failure returned an executable plan")
		}
		seen := make(map[string]bool)
		for _, name := range names {
			if validNativeProductPackageName(name) || !apkRetentionRelevant(name) || seen[name] {
				t.Fatalf("unexpected retention argument %q", name)
			}
			seen[name] = true
		}
	})
}

// This opt-in test runs inside the rootless synthetic APK laboratory. It only
// reads protected APK inventory and checks the same argument planner used by
// production updates. The harness performs the separate synthetic transaction.
func TestAPKRetentionNativePlanner(t *testing.T) {
	if os.Getenv("SYSWARDEN_APK_RETENTION_NATIVE") != "1" {
		t.Skip("requires the isolated APK dependency transition oracle")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native oracle must be namespace-root inside its disposable container")
	}
	if _, err := os.Stat("/tmp/sw-apk-lab/cases.sh"); err != nil {
		t.Fatal("synthetic APK laboratory marker is missing")
	}
	expected := os.Getenv("SYSWARDEN_APK_RETENTION_EXPECT")
	if expected != "" && expected != "rsyslog" {
		t.Fatal("unsupported synthetic expectation")
	}
	paths := productionOpenRCWireGuardDefinitionPaths()
	for _, executable := range []string{"/sbin/apk", "/usr/sbin/apk"} {
		target := packageTarget{os: "linux", architecture: "amd64", packageName: "syswarden", format: packageFormatAPK, installer: executable}
		path := "/var/tmp/syswarden-update-oracle/package.apk"
		_, offline := target.qualificationInstallCommand(path)
		for _, args := range [][]string{target.installArguments(path), offline} {
			got, err := apkPreservedInstallArguments(executable, args, paths)
			want := append([]string(nil), args...)
			if expected != "" {
				want = append(want, expected)
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("native argument planner: %q, %v; want %q", got, err, want)
			}
		}
	}
	fmt.Println("APK_RETENTION_NATIVE_PASS=" + expected)
}

// This oracle executes only synthetic, unsigned APK files in a separately
// verified rootless fixture. No production installer or base-update gate is
// bypassed, changed or exposed by the test-only unsigned trust override.
func TestAPKSelectedRetentionNativeTransaction(t *testing.T) {
	if os.Getenv("SYSWARDEN_APK_SELECTED_RETENTION_NATIVE") != "1" {
		t.Skip("requires the isolated selected APK transaction laboratory")
	}
	requireAPKSelectedNativeFixture(t)
	var packageName string
	switch os.Getenv("SYSWARDEN_APK_SELECTED_PACKAGE") {
	case "syswarden":
		packageName = "syswarden"
	case "syswarden-base":
		packageName = "syswarden-base"
	default:
		t.Fatal("exact selected fixture package identity required")
	}
	var scenario string
	switch os.Getenv("SYSWARDEN_APK_SELECTED_CASE") {
	case "native-selected-upgrade":
		scenario = "native-selected-upgrade"
	case "native-selected-pinned-refusal":
		scenario = "native-selected-pinned-refusal"
	case "native-selected-tagged-refusal":
		scenario = "native-selected-tagged-refusal"
	default:
		t.Fatal("exact selected fixture case required")
	}
	const candidate = "/var/tmp/syswarden-update-oracle/package.apk"
	candidateBytes := readAPKOracleProtectedFile(t, candidate, 16<<20, true)
	if len(candidateBytes) == 0 {
		t.Fatal("empty fixture candidate")
	}
	if string(readAPKOracleProtectedFile(t, "/opt/sw-apk-lab/model", 128, false)) != "model-1.0.0\n" {
		t.Fatal("installed fixture payload differs from the inert old generation")
	}
	world := readAPKOracleProtectedFile(t, "/etc/apk/world", 1<<20, false)
	database := readAPKOracleProtectedFile(t, "/lib/apk/db/installed", maximumAPKInstalledDatabaseSize, false)
	paths := productionOpenRCWireGuardDefinitionPaths()
	target := packageTarget{os: "linux", architecture: "amd64", packageName: packageName, format: packageFormatAPK, installer: "/sbin/apk"}
	_, offline := target.qualificationInstallCommand(candidate)
	var planned []string
	for _, arguments := range [][]string{target.installArguments(candidate), offline} {
		got, err := apkPreservedInstallArgumentsForName(packageName, "/sbin/apk", arguments, paths)
		if scenario != "native-selected-upgrade" {
			if err == nil || !strings.Contains(err.Error(), "product root") || got != nil {
				t.Fatalf("constrained selected product root did not refuse for its world constraint: %q, %v", got, err)
			}
			continue
		}
		want := append([]string(nil), arguments...)
		if packageName == "syswarden" {
			want = append(want, "rsyslog")
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("selected native planner: %q, %v; want %q", got, err, want)
		}
		planned = got
	}
	if !bytes.Equal(world, readAPKOracleProtectedFile(t, "/etc/apk/world", 1<<20, false)) ||
		!bytes.Equal(database, readAPKOracleProtectedFile(t, "/lib/apk/db/installed", maximumAPKInstalledDatabaseSize, false)) {
		t.Fatal("read-only selected planner changed native inventory")
	}
	if scenario == "native-selected-upgrade" {
		// The actual offline planner vector reaches native execution. Only the
		// inert laboratory permits unsigned fixtures, with no additional roots.
		want := []string{"--no-network", "--no-cache", "--repositories-file", "/dev/null", "add", candidate}
		if packageName == "syswarden" {
			want = append(want, "rsyslog")
		}
		if !reflect.DeepEqual(planned, want) {
			t.Fatal("offline planner changed the exact native execution contract")
		}
		if !bytes.Equal(candidateBytes, readAPKOracleProtectedFile(t, candidate, 16<<20, true)) {
			t.Fatal("fixture candidate changed before execution")
		}
		readAPKOracleProtectedFile(t, "/sbin/apk", 16<<20, false)
		wire, err := json.Marshal(planned)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("APK_SELECTED_RETENTION_ARGUMENTS=" + string(wire))
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		arguments := append([]string{"--allow-untrusted"}, planned...)
		command := exec.CommandContext(ctx, "/sbin/apk", arguments...) // #nosec G204 -- fixed binary and exact offline argument vector checked above, restricted to the remapped disposable fixture
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root"}
		output, err := command.CombinedOutput()
		if err != nil || ctx.Err() != nil {
			t.Fatalf("inert native transaction failed: %v, %v, %s", err, ctx.Err(), output)
		}
		fmt.Print(string(output))
	}
	fmt.Println("APK_SELECTED_RETENTION_NATIVE_PASS=" + packageName + ":" + scenario)
}

func requireAPKSelectedNativeFixture(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("selected native oracle requires Linux AMD64 namespace root")
	}
	for _, name := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		file, err := os.Open(name) // #nosec G304 -- closed pair of kernel namespace-map paths, never caller input
		if err != nil {
			t.Fatal(err)
		}
		mapping, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || !apkOracleRemappedRoot(mapping) {
			t.Fatal("initial or ambiguous namespace mapping is prohibited", name, readErr, closeErr)
		}
	}
	// Podman can publish an empty engine marker without --privileged. Its
	// optional text is not rootless authority. Require protected file presence;
	// the independent kernel UID and GID remaps above exclude initial host
	// namespaces. The runner separately requires Podman Rootless=true, and the
	// exact private fixture marker below binds this test to its disposable lab.
	_ = readAPKOracleProtectedFile(t, "/run/.containerenv", 64<<10, false)
	for _, directory := range []string{"/tmp/sw-apk-lab", "/var/tmp/syswarden-update-oracle"} {
		var state unix.Stat_t
		if err := unix.Lstat(directory, &state); err != nil || state.Mode&unix.S_IFMT != unix.S_IFDIR || state.Mode&07777 != 0700 || state.Uid != 0 || state.Gid != 0 {
			t.Fatal("private native fixture directory is unsafe", directory, err)
		}
	}
	marker := readAPKOracleProtectedFile(t, "/tmp/sw-apk-lab/.selected-retention-oracle-v1", 128, true)
	if string(marker) != "SYSWARDEN-ISOLATED-APK-RETENTION-V1\n" {
		t.Fatal("selected native fixture marker missing")
	}
}

func apkOracleRemappedRoot(mapping []byte) bool {
	if len(mapping) == 0 || len(mapping) > 4096 {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(mapping), "\n"), "\n")
	if len(lines) == 0 || len(lines) > 5 {
		return false
	}
	var next uint64
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return false
		}
		var values [3]uint64
		for i, field := range fields {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || strconv.FormatUint(value, 10) != field {
				return false
			}
			values[i] = value
		}
		inside, outside, length := values[0], values[1], values[2]
		if (index == 0 && inside != 0) || inside < next || outside == 0 || inside == outside || length == 0 || inside+length > 1<<32 || outside+length > 1<<32 {
			return false
		}
		next = inside + length
	}
	return true
}

func readAPKOracleProtectedFile(t *testing.T, name string, maximum int64, private bool) []byte {
	t.Helper()
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("cannot open protected native fixture input", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !apkOracleProtectedFileMetadata(before, maximum, private) {
		t.Fatal("unsafe native fixture input", name, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		t.Fatal("unbounded native fixture input", name, err)
	}
	if err := unix.Fstat(fd, &after); err != nil {
		t.Fatal(err)
	}
	before.Atim, after.Atim = unix.Timespec{}, unix.Timespec{}
	if before != after {
		t.Fatal("native fixture input changed while reading", name)
	}
	return data
}

func apkOracleProtectedFileMetadata(state unix.Stat_t, maximum int64, private bool) bool {
	return maximum >= 0 && state.Mode&unix.S_IFMT == unix.S_IFREG && state.Nlink == 1 && state.Uid == 0 && state.Gid == 0 &&
		state.Mode&0022 == 0 && (!private || state.Mode&07777 == 0600) && state.Size >= 0 && state.Size <= maximum
}

func TestAPKSelectedOracleContainerMarkerMetadata(t *testing.T) {
	const maximum = 64 << 10
	// An empty engine marker is native Podman behavior without --privileged.
	// Contents do not grant authority, but the held descriptor must retain all
	// existing protected-file checks independently of both namespace maps.
	valid := unix.Stat_t{Mode: unix.S_IFREG | 0644, Nlink: 1}
	for _, size := range []int64{0, 1, maximum} {
		state := valid
		state.Size = size
		if !apkOracleProtectedFileMetadata(state, maximum, false) {
			t.Fatalf("protected marker size %d refused", size)
		}
	}
	for name, mutate := range map[string]func(*unix.Stat_t){
		"symlink":        func(state *unix.Stat_t) { state.Mode = unix.S_IFLNK | 0644 },
		"directory":      func(state *unix.Stat_t) { state.Mode = unix.S_IFDIR | 0644 },
		"fifo":           func(state *unix.Stat_t) { state.Mode = unix.S_IFIFO | 0644 },
		"socket":         func(state *unix.Stat_t) { state.Mode = unix.S_IFSOCK | 0644 },
		"foreign-owner":  func(state *unix.Stat_t) { state.Uid = 1 },
		"foreign-group":  func(state *unix.Stat_t) { state.Gid = 1 },
		"group-writable": func(state *unix.Stat_t) { state.Mode |= 0020 },
		"other-writable": func(state *unix.Stat_t) { state.Mode |= 0002 },
		"multiple-links": func(state *unix.Stat_t) { state.Nlink = 2 },
		"negative-size":  func(state *unix.Stat_t) { state.Size = -1 },
		"oversized":      func(state *unix.Stat_t) { state.Size = maximum + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			state := valid
			mutate(&state)
			if apkOracleProtectedFileMetadata(state, maximum, false) {
				t.Fatal("unsafe engine marker accepted")
			}
		})
	}
	if apkOracleProtectedFileMetadata(valid, -1, false) || apkOracleProtectedFileMetadata(valid, maximum, true) {
		t.Fatal("invalid bound or nonprivate fixture marker accepted")
	}
	valid.Mode = unix.S_IFREG | 0600
	if !apkOracleProtectedFileMetadata(valid, maximum, true) {
		t.Fatal("protected private fixture marker refused")
	}
}

func TestAPKSelectedOracleRequiresRemappedRoot(t *testing.T) {
	for _, mapping := range []string{"0 1000 1\n1 100000 65536\n", "         0       1000          1\n"} {
		if !apkOracleRemappedRoot([]byte(mapping)) {
			t.Fatalf("valid isolated mapping rejected: %q", mapping)
		}
	}
	for _, mapping := range []string{"", "0 0 4294967295\n", "0 0 1\n", "0 1000\n", "1 1000 1\n", "0 1000 0\n", "0 1000 1\n0 2000 1\n", "0 1000 1\n1 1 65536\n", "0 1000 4294967295\n", "0 01000 1\n", "0 -1 1\n"} {
		if apkOracleRemappedRoot([]byte(mapping)) {
			t.Fatalf("unsafe mapping accepted: %q", mapping)
		}
	}
}
