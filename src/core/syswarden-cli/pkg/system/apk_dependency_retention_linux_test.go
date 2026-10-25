//go:build linux

package system

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
		target := packageTarget{format: packageFormatAPK, installer: executable}
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
