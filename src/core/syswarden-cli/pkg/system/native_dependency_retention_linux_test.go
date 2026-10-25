//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNativeRetentionCommandScope(t *testing.T) {
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dnf", "/usr/bin/yum"} {
		for _, op := range []string{"identity", "reasons", "retain"} {
			for _, names := range [][]string{nil, {"--nogpgcheck"}, {"rsyslog", "rsyslog"}, {"unrelated"}, {"rsyslog=1"}, {"rsyslog;id"}, {"/tmp/package"}, {"syswarden", "rsyslog"}} {
				if _, _, err := nativeRetentionCommand(manager, op, names); err == nil {
					t.Fatalf("unsafe scope accepted: %q %q %q", manager, op, names)
				}
			}
			name, args, err := nativeRetentionCommand(manager, op, []string{"rsyslog"})
			if err != nil || name == "" || !slices.Contains(args, "rsyslog") {
				t.Fatalf("fixed command rejected: %q %q %v", name, args, err)
			}
			for _, forbidden := range []string{"--nogpgcheck", "--allow-unauthenticated", "--allowerasing", "autoremove", "remove"} {
				if slices.Contains(args, forbidden) {
					t.Fatalf("unsafe command operation: %q", args)
				}
			}
		}
	}
	for _, manager := range []string{"/tmp/apt-get", "apt-get", "/sbin/apk", "/usr/bin/../bin/dnf"} {
		if _, _, err := nativeRetentionCommand(manager, "retain", []string{"rsyslog"}); err == nil {
			t.Fatalf("untrusted manager accepted: %q", manager)
		}
	}
}

func TestNativeRetentionSelectedProductCommands(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dnf", "/usr/bin/yum"} {
			for _, generation := range []int{4, 5} {
				path, args, err := nativeRetentionCommandVariant(manager, "identity", []string{packageName}, generation)
				wantPath, wantArgs := "/usr/bin/rpm", []string{"--query", "--queryformat", rpmRetentionQuery, packageName}
				deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
				if deb {
					wantPath, wantArgs = "/usr/bin/dpkg-query", []string{"--show", debRetentionQuery, packageName}
				}
				if err != nil || path != wantPath || !slices.Equal(args, wantArgs) {
					t.Fatalf("selected identity command: %s %q %v", path, args, err)
				}
				path, args, err = nativeRetentionCommandVariant(manager, "product-requires", []string{packageName}, generation)
				if deb {
					if err == nil {
						t.Fatal("RPM requires query accepted for DEB")
					}
				} else if err != nil || path != "/usr/bin/rpm" || !slices.Equal(args, []string{"--query", "--requires", packageName}) {
					t.Fatalf("selected requires command: %s %q %v", path, args, err)
				}
				for _, operation := range []string{"reasons", "retain"} {
					if _, _, err := nativeRetentionCommandVariant(manager, operation, []string{packageName}, generation); err == nil {
						t.Fatalf("product entered dependency mutation scope: %s %s", packageName, operation)
					}
				}
			}
		}
	}
	for _, names := range [][]string{nil, {"other"}, {"rsyslog"}, {"syswarden", "syswarden-base"}, {"syswarden-base=1"}, {"--root=/tmp"}} {
		if _, _, err := nativeRetentionCommandVariant("/usr/bin/dnf", "product-requires", names, 4); err == nil {
			t.Fatalf("ambiguous product query accepted: %q", names)
		}
	}
}

func TestNativeRetentionSelectedProductIdentityIsExact(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dnf", "/usr/bin/yum"} {
			deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
			valid := packageName + "\t0:5.00.0-1\tx86_64\n"
			if deb {
				valid = packageName + "\thi \t5.00.0\tamd64\tnftables\n"
			}
			if _, _, err := retentionRecord(manager, packageName, []byte(valid)); err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{
				strings.Replace(valid, packageName, "foreign", 1),
				strings.ReplaceAll(strings.ReplaceAll(valid, "amd64", "all"), "x86_64", "noarch"),
				strings.ReplaceAll(strings.ReplaceAll(valid, "amd64", "386"), "x86_64", "i686"),
				valid + valid,
			} {
				if _, _, err := retentionRecord(manager, packageName, []byte(bad)); err == nil {
					t.Fatalf("non-exact selected identity accepted: %q", bad)
				}
			}
		}
	}
}

func TestNativeRetentionSelectedProductRefusesBeforeQueries(t *testing.T) {
	called := false
	run := func(context.Context, string, string, []string) ([]byte, error) {
		called = true
		return nil, errors.New("unexpected query")
	}
	for _, packageName := range []string{"", "foreign", "syswarden-base=1", "syswarden*", "--root=/tmp"} {
		if err := preserveNativeDependencyReasonsForName(t.Context(), "/usr/bin/apt-get", packageName); err == nil {
			t.Fatalf("production helper accepted unknown product %q", packageName)
		}
		if err := preserveNativeDependencyReasonsForNameWith(t.Context(), "/usr/bin/apt-get", packageName, run); err == nil {
			t.Fatalf("injected helper accepted unknown product %q", packageName)
		}
		if _, err := inspectNativeRetentionForName(t.Context(), "/usr/bin/apt-get", packageName, run); err == nil {
			t.Fatalf("inspection accepted unknown product %q", packageName)
		}
	}
	var missingContext context.Context
	if err := preserveNativeDependencyReasonsForNameWith(missingContext, "/usr/bin/apt-get", baseNativePackageName, run); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := preserveNativeDependencyReasonsForNameWith(t.Context(), "/usr/bin/apt-get", baseNativePackageName, nil); err == nil {
		t.Fatal("nil runner accepted")
	}
	if err := preserveNativeDependencyReasonsForNameWith(t.Context(), "/tmp/apt-get", baseNativePackageName, run); err == nil {
		t.Fatal("foreign manager accepted")
	}
	if called {
		t.Fatal("invalid selection reached native queries")
	}
}

func TestNativeRetentionCompatibilityInspectionWrapper(t *testing.T) {
	run := func(_ context.Context, manager, operation string, names []string) ([]byte, error) {
		if manager != "/usr/bin/apt-get" || operation != "identity" || !slices.Equal(names, []string{compatibilityNativePackageName}) {
			t.Fatalf("compatibility wrapper changed authority: %s %s %q", manager, operation, names)
		}
		return []byte("syswarden\tii \t5.00.0\tamd64\tnftables\n"), nil
	}
	got, err := inspectNativeRetention(t.Context(), "/usr/bin/apt-get", run)
	if err != nil || got.owner != "syswarden\tii \t5.00.0\tamd64" || len(got.identities) != 0 || len(got.reasons) != 0 {
		t.Fatalf("compatibility snapshot: %+v %v", got, err)
	}
}

func TestNativeRetentionRejectsAmbiguousDeclarationsAndReasons(t *testing.T) {
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf"} {
		for _, declaration := range []string{"rsyslog >= 1", "rsyslog:any", "rsyslog (>= 1)", "nftables | rsyslog", "(rsyslog if nftables)", "rsyslog\x00", "rsyslog\r", "rsyslog\t", strings.Repeat("a", 65537)} {
			if _, err := retentionDeclared(manager, declaration); err == nil {
				t.Fatalf("ambiguous declaration accepted: %q", declaration)
			}
		}
		for _, reasons := range []string{"rsyslog", "rsyslog\nrsyslog\n", "other\n", " rsyslog\n", "rsyslog\n\n", "rsyslog:amd64\n", "rsyslog\x00\n"} {
			if _, err := retentionReasons(manager, []string{"rsyslog"}, []byte(reasons)); err == nil {
				t.Fatalf("ambiguous reasons accepted: %q", reasons)
			}
		}
	}
	for _, test := range []struct{ manager, declaration string }{
		{"/usr/bin/apt-get", "nftables, rsyslog, wireguard-tools"},
		{"/usr/bin/dnf", "rpmlib(PayloadIsXz) <= 5.2-1\nrsyslog\nwireguard-tools\n"},
	} {
		got, err := retentionDeclared(test.manager, test.declaration)
		if err != nil || !reflect.DeepEqual(got, []string{"rsyslog", "wireguard-tools"}) {
			t.Fatalf("declaration: %q %v", got, err)
		}
	}
}

func TestNativeRetentionIdentityRefusesIncompleteAndForeignPackages(t *testing.T) {
	for _, test := range []struct{ manager, valid string }{
		{"/usr/bin/apt-get", "syswarden\tii \t4.10.4\tamd64\trsyslog\n"},
		{"/usr/bin/dnf", "syswarden\t0:4.10.4-1\tx86_64\n"},
	} {
		if _, _, err := retentionRecord(test.manager, "syswarden", []byte(test.valid)); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"", test.valid + test.valid, strings.ReplaceAll(test.valid, "syswarden", "other"),
			strings.ReplaceAll(strings.ReplaceAll(test.valid, "amd64", "all"), "x86_64", "noarch"),
			strings.TrimSuffix(test.valid, "\n"), strings.ReplaceAll(test.valid, "4.10.4", "4\x00.10"),
			strings.ReplaceAll(test.valid, "4.10.4", "bad version")} {
			if _, _, err := retentionRecord(test.manager, "syswarden", []byte(bad)); err == nil {
				t.Fatalf("unsafe package identity accepted: %q", bad)
			}
		}
	}
	if _, _, err := retentionRecord("/usr/bin/apt-get", "rsyslog", []byte("rsyslog\thi \t1.0\tamd64\tlibc6\n")); err != nil {
		t.Fatal("held configured dependency must remain held", err)
	}
	for _, state := range []string{"iU ", "rc ", "iF ", "iiR", "ri "} {
		if _, _, err := retentionRecord("/usr/bin/apt-get", "rsyslog", []byte("rsyslog\t"+state+"\t1\tamd64\t\n")); err == nil {
			t.Fatalf("unconfigured/scheduled-removal dependency accepted: %q", state)
		}
	}
}

func TestNativeRetentionPreparesOnlyHistoricalAutomaticDependencies(t *testing.T) {
	for _, packageName := range nativeProductPackageNames {
		for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dnf", "/usr/bin/yum"} {
			for _, scenario := range []string{"automatic", "already protected", "minimal", "query failure", "wrong owner", "owner drift", "before drift", "after drift", "reason failure", "reason unconfirmed", "cancel before", "cancel after"} {
				t.Run(packageName+"/"+manager+"/"+scenario, func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if scenario == "cancel before" {
						cancel()
					}
					deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
					protected := scenario == "already protected"
					reads, writes := 0, 0
					run := func(_ context.Context, gotManager, operation string, names []string) ([]byte, error) {
						if gotManager != manager {
							t.Fatal("manager changed")
						}
						switch operation {
						case "identity":
							if names[0] == packageName {
								reads++
							}
							identityName := names[0]
							if names[0] == packageName && (scenario == "wrong owner" || scenario == "owner drift" && reads == 2) {
								identityName = compatibilityNativePackageName
								if identityName == packageName {
									identityName = baseNativePackageName
								}
							}
							if scenario == "query failure" {
								return nil, errors.New("fixture unavailable")
							}
							version := "1.0"
							if (scenario == "before drift" && reads == 2) || (scenario == "after drift" && reads == 3) {
								version = "1.1"
							}
							if deb {
								dependencies := ""
								if names[0] == packageName && scenario != "minimal" {
									dependencies = "nftables, rsyslog, wireguard-tools"
								}
								return []byte(identityName + "\thi \t" + version + "\tamd64\t" + dependencies + "\n"), nil
							}
							return []byte(identityName + "\t0:" + version + "-1\tx86_64\n"), nil
						case "product-requires":
							if !slices.Equal(names, []string{packageName}) {
								t.Fatalf("requires query changed product: %q", names)
							}
							if scenario == "minimal" {
								return []byte("nftables\n"), nil
							}
							return []byte("nftables\nrsyslog\nwireguard-tools\n"), nil
						case "reasons":
							if scenario == "minimal" {
								t.Fatal("minimal package queried unrelated dependency reasons")
							}
							// wireguard-tools represents an administrator/group choice and
							// must never be included in the reason mutation.
							if deb {
								if protected {
									return nil, nil
								}
								return []byte("rsyslog\n"), nil
							}
							if protected {
								return []byte("rsyslog\tuser\nwireguard-tools\tgroup\n"), nil
							}
							return []byte("rsyslog\tdependency\nwireguard-tools\tgroup\n"), nil
						case "retain":
							writes++
							if !reflect.DeepEqual(names, []string{"rsyslog"}) {
								t.Fatalf("changed unrelated/protected scope: %q", names)
							}
							if scenario == "reason failure" {
								return nil, errors.New("partial native failure")
							}
							if scenario != "reason unconfirmed" {
								protected = true
							}
							if scenario == "cancel after" {
								cancel()
							}
							return nil, nil
						}
						t.Fatalf("unexpected operation: %q", operation)
						return nil, nil
					}
					err := preserveNativeDependencyReasonsForNameWith(ctx, manager, packageName, run)
					wantError := scenario != "automatic" && scenario != "already protected" && scenario != "minimal"
					if (err != nil) != wantError {
						t.Fatalf("error %v, want failure=%v", err, wantError)
					}
					wantWrites := 0
					if slices.Contains([]string{"automatic", "after drift", "reason failure", "reason unconfirmed", "cancel after"}, scenario) {
						wantWrites = 1
					}
					if writes != wantWrites {
						t.Fatalf("writes=%d want %d", writes, wantWrites)
					}
					if !wantError {
						if err := preserveNativeDependencyReasonsForNameWith(ctx, manager, packageName, run); err != nil || writes != wantWrites {
							t.Fatalf("retry changed retained choices: %v, writes=%d", err, writes)
						}
					}
				})
			}
		}
	}
}

// Explicitly enabled only in the synthetic rootless container laboratory. No
// host installation or real SysWarden payload is used by this native oracle.
func TestNativeDependencyRetentionOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_NATIVE_RETENTION_TEST") != "1" {
		t.Skip("requires the isolated native dependency laboratory")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires namespace root")
	}
	for _, path := range []string{"/run/.containerenv", "/tmp/sw-native-lab/cases.sh"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("isolated laboratory marker missing", err)
		}
	}
	var manager string
	switch os.Getenv("SYSWARDEN_NATIVE_RETENTION_MANAGER") {
	case "/usr/bin/apt-get":
		manager = "/usr/bin/apt-get"
	case "/usr/bin/dnf":
		manager = "/usr/bin/dnf"
	default:
		t.Fatal("unsupported laboratory manager")
	}
	var packageName string
	switch os.Getenv("SYSWARDEN_NATIVE_RETENTION_PACKAGE") {
	case "", compatibilityNativePackageName:
		packageName = compatibilityNativePackageName
	case baseNativePackageName:
		packageName = baseNativePackageName
	default:
		t.Fatal("unsupported laboratory product package")
	}
	bound, err := bindNativeRetentionRunner(t.Context(), manager, runNativeRetentionCommandVariant)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	run := func(ctx context.Context, manager, operation string, names []string) ([]byte, error) {
		if operation == "retain" {
			writes++
		}
		return bound(ctx, manager, operation, names)
	}
	expected := os.Getenv("SYSWARDEN_NATIVE_RETENTION_WRITES")
	if expected != "0" && expected != "1" {
		t.Fatal("exact expected retention write count required")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := preserveNativeDependencyReasonsForNameWith(t.Context(), manager, packageName, run); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(writes) != expected {
			t.Fatalf("retention writes=%d, expected %s", writes, expected)
		}
	}

	fmt.Println("NATIVE_RETENTION_PASS=" + manager)
	fmt.Println("NATIVE_RETENTION_PACKAGE=" + packageName)
}

func TestNativeRetentionPreservesExactRPMReasons(t *testing.T) {
	for _, reason := range []string{"user", "group", "dependency", "weak-dependency"} {
		got, err := retentionReasons("/usr/bin/dnf", []string{"rsyslog"}, []byte("rsyslog\t"+reason+"\n"))
		if err != nil || got["rsyslog"] != reason {
			t.Fatalf("lost reason %q: %v %v", reason, got, err)
		}
	}
	for _, data := range []string{"", "rsyslog\tunknown\n", "rsyslog\tgroup\nrsyslog\tuser\n", "rsyslog\tuser\tgroup\n"} {
		if _, err := retentionReasons("/usr/bin/dnf", []string{"rsyslog"}, []byte(data)); err == nil {
			t.Fatalf("ambiguous reasons accepted: %q", data)
		}
	}
}

func TestNativeRetentionBoundaryStopsReplacementOnUncertainty(t *testing.T) {
	for _, offline := range []bool{false, true} {
		for _, target := range []packageTarget{
			{format: packageFormatDEB, installer: "/usr/bin/apt-get"},
			{format: packageFormatRPM, installer: "/usr/bin/dnf"},
			{format: packageFormatRPM, installer: "/usr/bin/yum"},
		} {
			for _, scenario := range []string{"success", "bad command", "preparation failure", "cancel during preparation", "execution failure"} {
				t.Run(fmt.Sprintf("%s/%t/%s", target.installer, offline, scenario), func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					name, args := target.installer, target.installArguments("/var/tmp/syswarden-update-test/package")
					if offline {
						name, args = target.qualificationInstallCommand("/var/tmp/syswarden-update-test/package")
					}
					if scenario == "bad command" {
						args = append(args, "--allowerasing")
					}
					var events []string
					prepare := func(_ context.Context, manager string) error {
						if manager != name {
							t.Fatal("changed manager")
						}
						events = append(events, "prepare")
						if scenario == "preparation failure" {
							return errors.New("native reason not verified")
						}
						if scenario == "cancel during preparation" {
							cancel()
						}
						return nil
					}
					execute := func(_ context.Context, got string, gotArgs ...string) error {
						if got != name || !reflect.DeepEqual(gotArgs, args) {
							t.Fatal("changed verified install command")
						}
						events = append(events, "execute")
						if scenario == "execution failure" {
							return errors.New("native install failed")
						}
						return nil
					}
					err := runWithNativeDependencyRetention(ctx, name, args, offline, prepare, execute)
					want := []string{"prepare", "execute"}
					if scenario == "bad command" {
						want = nil
					}
					if scenario == "preparation failure" || scenario == "cancel during preparation" {
						want = []string{"prepare"}
					}
					if !reflect.DeepEqual(events, want) || (err != nil) != (scenario != "success") {
						t.Fatalf("events=%q error=%v", events, err)
					}
				})
			}
		}
	}
	if err := runWithNativeDependencyRetention(t.Context(), "/usr/bin/systemctl", []string{"daemon-reload"}, false,
		func(context.Context, string) error { t.Fatal("service operation attempted retention"); return nil },
		func(context.Context, string, ...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRetentionEnvironmentUsesTheSystemDatabase(t *testing.T) {
	for _, key := range []string{"APT_CONFIG", "DPKG_ROOT", "DPKG_ADMINDIR", "RPM_CONFIGDIR", "RPMRC", "HOME", "XDG_CONFIG_HOME", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "PATH", "SYSWARDEN_OFFLINE_QUALIFICATION", "SYSWARDEN_PKG_INSTALL"} {
		t.Setenv(key, "/tmp/unrelated-native-root")
	}
	t.Setenv("https_proxy", "http://proxy.example.invalid:3128")
	for _, environment := range [][]string{nativeRetentionEnvironment(), productionNativeCommandEnvironment()} {
		if !slices.Contains(environment, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
			t.Fatal("trusted path missing")
		}
		for _, entry := range environment {
			if strings.Contains(entry, "/tmp/unrelated-native-root") {
				t.Fatalf("inherited native database override: %q", entry)
			}
		}
	}
	if !slices.Contains(productionNativeCommandEnvironment(), "https_proxy=http://proxy.example.invalid:3128") {
		t.Fatal("administrator proxy was not retained")
	}
}
