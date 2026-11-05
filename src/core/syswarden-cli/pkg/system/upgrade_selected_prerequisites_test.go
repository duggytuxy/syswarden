package system

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSelectedQualificationPrerequisitesAreExactAndBounded(t *testing.T) {
	profiles := []struct {
		format, packageName, installer string
		dependencies                   []string
	}{
		{packageFormatDEB, baseNativePackageName, "/usr/bin/apt-get", []string{"bash-completion", "cron", "curl", "jq", "nftables", "procps", "wget"}},
		{packageFormatRPM, baseNativePackageName, "/usr/bin/dnf", []string{"bash-completion", "cronie", "curl", "jq", "nftables", "procps-ng", "systemd", "wget"}},
		{packageFormatAPK, baseNativePackageName, "/sbin/apk", []string{"bash-completion", "cronie", "cronie-openrc", "curl", "jq", "nftables", "openrc", "procps-ng", "shadow", "wget"}},
		{packageFormatDEB, compatibilityNativePackageName, "/usr/bin/apt-get", []string{"apt-listchanges", "bash-completion", "cron", "curl", "e2fsprogs", "ipset", "jq", "nftables", "procps", "qrencode", "rsyslog", "unattended-upgrades", "wget", "wireguard-tools"}},
		{packageFormatRPM, compatibilityNativePackageName, "/usr/bin/yum", []string{"bash-completion", "checkpolicy", "cronie", "curl", "dnf-automatic", "e2fsprogs", "ipset", "jq", "nftables", "policycoreutils-python-utils", "procps-ng", "rsyslog", "systemd", "wget", "wireguard-tools"}},
		{packageFormatAPK, compatibilityNativePackageName, "/usr/sbin/apk", []string{"bash-completion", "cronie", "cronie-openrc", "curl", "e2fsprogs-extra", "jq", "libqrencode-tools", "nftables", "openrc", "procps-ng", "rsyslog", "rsyslog-uxsock", "shadow", "wget", "wireguard-tools"}},
	}
	for _, profile := range profiles {
		t.Run(profile.packageName+"/"+profile.format, func(t *testing.T) {
			got := qualificationRequiredPackagesForName(profile.format, profile.packageName)
			if !reflect.DeepEqual(got, profile.dependencies) {
				t.Fatalf("prerequisites = %q, want %q", got, profile.dependencies)
			}
			for _, failure := range []string{"none", "missing", "ambiguous", "cancel", "held"} {
				t.Run(failure, func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					calls := 0
					target := packageTarget{format: profile.format, packageName: profile.packageName, installer: profile.installer}
					query := func(queryCtx context.Context, executable string, args ...string) ([]byte, error) {
						if queryCtx != ctx || calls >= len(profile.dependencies) {
							t.Fatal("unexpected query/context")
						}
						dependency := profile.dependencies[calls]
						calls++
						wantExe := "/usr/bin/rpm"
						wantArgs := []string{"--query", "--quiet", dependency}
						if profile.format == packageFormatDEB {
							wantExe = "/usr/bin/dpkg-query"
							wantArgs = []string{"--show", "--showformat=${db:Status-Abbrev}\n", dependency}
						}
						if profile.format == packageFormatAPK {
							wantExe = profile.installer
							wantArgs = []string{"info", "--quiet", "-e", dependency}
						}
						if executable != wantExe || !reflect.DeepEqual(args, wantArgs) || !allowedQualificationQuery(executable, args) {
							t.Fatalf("wrong prerequisite authority: %s %q", executable, args)
						}
						if failure == "missing" {
							return nil, errors.New("fixture unavailable")
						}
						if failure == "ambiguous" {
							return []byte("unexpected\n"), nil
						}
						if failure == "cancel" {
							cancel()
						}
						if failure == "held" {
							return []byte("hi \n"), nil
						}
						if profile.format == packageFormatDEB {
							return []byte("ii \n"), nil
						}
						return nil, nil
					}
					err := attestOfflineQualificationPackageDependenciesWith(ctx, target, query)
					if failure == "none" {
						if err != nil || calls != len(profile.dependencies) {
							t.Fatalf("query count=%d: %v", calls, err)
						}
					} else if err == nil || calls != 1 {
						t.Fatalf("unsafe prerequisite result accepted, count=%d: %v", calls, err)
					}
				})
			}
		})
	}
}

func TestSelectedPrerequisitesRejectMissingAuthorityBeforeQueries(t *testing.T) {
	for _, target := range []packageTarget{
		{format: packageFormatDEB},
		{format: packageFormatRPM, packageName: "foreign"},
		{format: "foreign", packageName: baseNativePackageName},
		{format: packageFormatAPK, packageName: baseNativePackageName, installer: "/tmp/apk"},
	} {
		err := attestOfflineQualificationPackageDependenciesWith(t.Context(), target, func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("query ran without exact authority")
			return nil, nil
		})
		if err == nil {
			t.Fatal("missing authority accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := attestOfflineQualificationPackageDependenciesWith(ctx, packageTarget{format: packageFormatDEB, packageName: baseNativePackageName}, func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("cancelled query ran")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled attestation: %v", err)
	}
}

func TestInstalledAPKHistoricalNormalizationIsOwnerBound(t *testing.T) {
	for _, tc := range []struct{ raw, name, want string }{
		{"4.3.2-r0", compatibilityNativePackageName, "v4.03.2"},
		{"4.0.1-r1", compatibilityNativePackageName, "v4.00.1"},
		{"4.03.2-r0", compatibilityNativePackageName, "v4.03.2"},
		{"4.10.4-r0", compatibilityNativePackageName, "v4.10.4"},
		{"5.00.0-r0", baseNativePackageName, "v5.00.0"},
		{"5.00.0-r1", baseNativePackageName, ""},
		{"5.00.0-r1", compatibilityNativePackageName, ""},
		{"5.0.0-r0", compatibilityNativePackageName, ""},
		{"4.3.2-r0", baseNativePackageName, ""},
		{"4.03.2-r0", baseNativePackageName, ""},
		{"4.10.4-r0", baseNativePackageName, ""},
		{"4.10.4-r1", baseNativePackageName, ""},
		{"3.00.0-r0", baseNativePackageName, ""},
		{"4.3.2-r0", "foreign", ""},
		{"4.3.02-r0", compatibilityNativePackageName, ""},
		{"04.3.2-r0", compatibilityNativePackageName, ""},
		{"4.3.2-r00", compatibilityNativePackageName, ""},
		{"4.03.2-r00", compatibilityNativePackageName, ""},
		{"4.3.2-r-1", compatibilityNativePackageName, ""},
		{"4.3.2-r0-r1", compatibilityNativePackageName, ""},
		{"4.3.2", compatibilityNativePackageName, "v4.03.2"},
		{"4.10.4", compatibilityNativePackageName, "v4.10.4"},
		{"4.03.2", compatibilityNativePackageName, "v4.03.2"},
		{"4.3.2", baseNativePackageName, ""},
		{"4.10.4", baseNativePackageName, ""},
		{"5.00.0", compatibilityNativePackageName, ""},
		{"4.3.2-r", compatibilityNativePackageName, ""},
		{"4.3.2-r0\n", compatibilityNativePackageName, ""},
		{"4.3.2-r+0", compatibilityNativePackageName, ""},
	} {
		t.Run(tc.name+"/"+tc.raw, func(t *testing.T) {
			got, err := canonicalInstalledAPKVersionForName(tc.raw, tc.name)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("unsafe historical version accepted: %s", got)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("version=%q: %v", got, err)
			}
		})
	}
	for _, ownerVersion := range []string{"4.3.2-r0", "4.03.2-r0", "4.3.2-r1"} {
		t.Run("raw-owner/"+ownerVersion, func(t *testing.T) {
			calls := 0
			version, err := attestInstalledAPKVersionForName(t.Context(), compatibilityNativePackageName, "/sbin/apk", installedSyswardenCLIPath,
				func(_ context.Context, executable string, args ...string) ([]byte, error) {
					calls++
					if !allowedQualificationQuery(executable, args) {
						t.Fatal("unapproved query")
					}
					if calls == 1 {
						return []byte("syswarden-4.3.2-r0 x86_64 {syswarden} (AGPL-3.0) [installed]\n"), nil
					}
					return []byte(installedSyswardenCLIPath + " is owned by syswarden-" + ownerVersion + "\n"), nil
				})
			if ownerVersion == "4.3.2-r0" {
				if err != nil || version != "v4.03.2" {
					t.Fatalf("normalized installed version=%q: %v", version, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "ownership versions disagree") {
				t.Fatalf("raw ownership mismatch accepted: %v", err)
			}
		})
	}
	// A downloaded candidate cannot use the installed-only normalization.
	if _, err := canonicalInstalledSyswardenVersion("4.3.2-r0", packageFormatAPK); err == nil {
		t.Fatal("candidate version parser was broadened")
	}
}

func TestInstalledAPKRevisionCannotSatisfyCandidateIdentity(t *testing.T) {
	for _, name := range []string{compatibilityNativePackageName, baseNativePackageName} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := attestInstalledAPKVersionForName(t.Context(), name, "/sbin/apk", installedSyswardenCLIPath,
				func(_ context.Context, executable string, args ...string) ([]byte, error) {
					calls++
					if calls != 1 || !allowedQualificationQuery(executable, args) {
						t.Fatal("invalid installed revision reached ownership query")
					}
					return []byte(name + "-5.00.0-r1 x86_64 {syswarden} (AGPL-3.0) [installed]\n"), nil
				})
			if err == nil || calls != 1 {
				t.Fatalf("foreign installed revision accepted: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestInstalledHistoricalBareAPKOwnershipRemainsExact(t *testing.T) {
	for _, installed := range []string{"4.10.4", "4.3.2", "4.03.2"} {
		for _, ownership := range []string{installed, installed + "-r0", "4.03.2-r0", "4.3.2"} {
			t.Run(installed+"/owner-"+ownership, func(t *testing.T) {
				calls := 0
				got, err := attestInstalledAPKVersionForName(t.Context(), compatibilityNativePackageName, "/sbin/apk", installedSyswardenCLIPath,
					func(_ context.Context, executable string, args ...string) ([]byte, error) {
						calls++
						if !allowedQualificationQuery(executable, args) || calls > 2 {
							t.Fatal("unexpected historical query")
						}
						if calls == 1 {
							return []byte("syswarden-" + installed + " x86_64 {syswarden} (GPL-3.0-or-later) [installed]\n"), nil
						}
						return []byte(installedSyswardenCLIPath + " is owned by syswarden-" + ownership + "\n"), nil
					})
				if installed != ownership {
					if err == nil {
						t.Fatal("different raw ownership spelling accepted")
					}
					return
				}
				want := "v4.03.2"
				if installed == "4.10.4" {
					want = "v4.10.4"
				}
				if err != nil || calls != 2 || got != want {
					t.Fatalf("historical identity=%q calls=%d: %v", got, calls, err)
				}
			})
		}
	}
}
