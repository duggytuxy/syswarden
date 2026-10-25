//go:build linux

package system

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// APK 2.14 and APK 3 share -e. The newer --exists spelling is not
// accepted by APK 2.14; quiet is necessary for the expected empty output.
func TestAPKQualificationQueriesUsePortableQuietInstalledOption(t *testing.T) {
	target := packageTarget{packageName: compatibilityNativePackageName, format: packageFormatAPK, installer: "/sbin/apk"}
	calls := 0
	err := attestOfflineQualificationPackageDependenciesWith(t.Context(), target, func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls++
		if path != "/sbin/apk" || len(args) != 4 || !reflect.DeepEqual(args[:3], []string{"info", "--quiet", "-e"}) || !allowedQualificationQuery(path, args) {
			t.Fatalf("nonportable APK query: %s %v", path, args)
		}
		return nil, nil
	})
	if err != nil || calls == 0 {
		t.Fatal(err, calls)
	}
	for _, args := range [][]string{{"info", "--exists", "nftables"}, {"info", "-e", "nftables"}, {"info", "--quiet", "-e", "unrelated-package"}, {"info", "--quiet", "-e", "nftables", "curl"}} {
		if allowedQualificationQuery("/sbin/apk", args) {
			t.Fatalf("unexpected query authorized: %v", args)
		}
	}
}

// APK 2.14 and APK 3 print package architecture in the normal installed-list
// output. Origin and license are display fields, not selected-package authority.
func TestAPKInstalledIdentityUsesPortableOfflineList(t *testing.T) {
	for _, apkPath := range []string{"/sbin/apk", "/usr/sbin/apk"} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			t.Run(apkPath+"/"+name, func(t *testing.T) {
				calls := 0
				query := func(_ context.Context, path string, args ...string) ([]byte, error) {
					calls++
					if path != apkPath || !allowedQualificationQuery(path, args) {
						t.Fatalf("unapproved APK identity query: %s %v", path, args)
					}
					switch calls {
					case 1:
						want := []string{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", name}
						if !reflect.DeepEqual(args, want) {
							t.Fatalf("APK identity query = %v, want %v", args, want)
						}
						return []byte(name + "-5.00.0-r0 x86_64 {source-package} ((AGPL-3.0-only OR MIT) AND BSD-2-Clause) [installed]\n"), nil
					case 2:
						if !reflect.DeepEqual(args, []string{"info", "--who-owns", installedSyswardenCLIPath}) {
							t.Fatalf("APK ownership query = %v", args)
						}
						return []byte(installedSyswardenCLIPath + " is owned by " + name + "-5.00.0-r0\n"), nil
					default:
						t.Fatalf("unexpected APK query: %v", args)
						return nil, nil
					}
				}
				version, err := attestInstalledAPKVersionForName(t.Context(), name, apkPath, installedSyswardenCLIPath, query)
				if err != nil || version != "v5.00.0" || calls != 2 {
					t.Fatalf("APK identity = %q, calls=%d, error=%v", version, calls, err)
				}
			})
		}
	}

	for _, args := range [][]string{
		{"list", "--installed", "syswarden"},
		{"--no-network", "list", "--installed", "syswarden"},
		{"--repositories-file", "/dev/null", "list", "--installed", "syswarden"},
		{"--no-network", "--repositories-file", "/etc/apk/repositories", "list", "--installed", "syswarden"},
		{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", "syswarden*"},
		{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", "syswarden", "syswarden-base"},
		{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", "--quiet", "syswarden"},
		{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", "--verbose", "syswarden"},
		{"info", "--verbose", "syswarden"},
	} {
		if allowedQualificationQuery("/sbin/apk", args) {
			t.Fatalf("unbounded or architecture-free APK identity query authorized: %v", args)
		}
	}
}

func TestAPKStandaloneRemovalUsesPortableQuietInstalledOption(t *testing.T) {
	for _, installed := range []string{"syswarden", "syswarden-base"} {
		calls := 0
		executor := testFirewallRemovalPackageExecutor(t, []string{"apk"}, func(_ string, args ...string) ([]byte, error) {
			calls++
			if len(args) != 4 || !reflect.DeepEqual(args[:3], []string{"info", "--quiet", "-e"}) ||
				(args[3] != "syswarden" && args[3] != "syswarden-base") {
				t.Fatalf("nonportable APK ownership query: %v", args)
			}
			if args[3] != installed {
				return nil, packageAuthorityTestExit(1)
			}
			return nil, nil
		})
		if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil }); err == nil || !strings.Contains(err.Error(), "apk del "+installed) || calls != 2 {
			t.Fatalf("installed APK ownership was not preserved: %v calls=%d", err, calls)
		}
	}
}
