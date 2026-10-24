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
	target := packageTarget{format: packageFormatAPK, installer: "/sbin/apk"}
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

func TestAPKStandaloneRemovalUsesPortableQuietInstalledOption(t *testing.T) {
	executor := testFirewallRemovalPackageExecutor(t, []string{"apk"}, func(_ string, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(args, []string{"info", "--quiet", "-e", "syswarden"}) {
			t.Fatalf("nonportable APK ownership query: %v", args)
		}
		return nil, nil
	})
	if err := preflightStandaloneUninstallWith(executor, func(string) (bool, error) { return false, nil }); err == nil || !strings.Contains(err.Error(), "apk del") {
		t.Fatalf("installed APK ownership was not preserved: %v", err)
	}
}
