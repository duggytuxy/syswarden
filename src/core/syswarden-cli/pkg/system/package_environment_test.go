package system

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestProductionPackageEnvironmentKeepsSystemDatabaseBoundary(t *testing.T) {
	for _, key := range []string{"APK_CONFIG", "APK_CACHE_DIR", "APK_CONFIG_DIR", "APT_CONFIG", "DNF_VAR_releasever", "PYTHONPATH", "BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "SYSWARDEN_PKG_INSTALL", offlineQualificationEnvironment} {
		t.Setenv(key, "untrusted-fixture-value")
	}
	t.Setenv("PATH", "/tmp/fixture-bin")
	t.Setenv("https_proxy", "http://proxy.example.invalid:3128")
	for _, manager := range []string{"/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/yum", "/sbin/apk", "/usr/sbin/apk"} {
		t.Run(manager, func(t *testing.T) {
			environment := productionCommandEnvironment(manager)
			command, err := productionExternalCommand(context.Background(), manager, environment, "fixture-argument")
			if err != nil {
				t.Fatal(err)
			}
			if command.Dir != "/" || command.Path != manager || !slices.Equal(command.Args, []string{manager, "fixture-argument"}) {
				t.Fatal("native installer command escaped the fixed system boundary")
			}
			if !slices.Equal(command.Env, environment) {
				t.Fatal("native installer lost the selected environment")
			}
			for _, item := range environment {
				key, value, ok := strings.Cut(item, "=")
				if !ok || key == "" || strings.Contains(value, "untrusted-fixture-value") || value == "/tmp/fixture-bin" {
					t.Errorf("native installer inherited an ambient override: %q", key)
				}
				if !slices.Contains([]string{"DEBIAN_FRONTEND", "LANG", "LC_ALL", "PATH", "http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}, key) {
					t.Errorf("native installer inherited unexpected environment key: %q", key)
				}
			}
			if !slices.Contains(environment, "https_proxy=http://proxy.example.invalid:3128") || !slices.Contains(environment, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
				t.Fatal("fixed native tools or explicit transport proxy were lost")
			}
		})
	}
}

func TestProductionCommandRejectsAlternatePackageManager(t *testing.T) {
	for _, manager := range []string{"apk", "apt-get", "/tmp/apk", "/usr/local/bin/dnf", "/usr/bin/../sbin/apk"} {
		if command, err := productionExternalCommand(context.Background(), manager, nil); err == nil || command != nil {
			t.Fatalf("accepted alternate package executable %q", manager)
		}
	}
}
