//go:build linux

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureNFTOpenRCLoader(t *testing.T) (nftPersistenceFilesystem, []map[string]string) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	files := map[string]string{
		"/etc/alpine-release": "3.24.0\n", "/etc/rc.conf": "rc_tty_number=12\n",
		"/etc/conf.d/nftables": "save_objects=\"counters limits quotas\"\n",
		"/usr/sbin/nft":        "#!/bin/sh\nexit 91\n", "/proc/1/comm": "openrc-init\n",
		"/run/openrc/softlevel": "default\n",
	}
	profile := make(map[string]string)
	for path := range nftOpenRCProfiles()[0] {
		// These definitions are never executed. Production uses only the fixed
		// distribution profiles; this explicit argument is a private test seam.
		files[path] = "#!/bin/sh\nexit 92\n# " + path + "\n"
		profile[path] = nftSHA256Hex([]byte(files[path]))
	}
	for path, content := range files {
		writeNFTOpenRCFixture(t, host, path, content)
	}
	for _, path := range []string{"/sbin/openrc-run", "/etc/init.d/nftables", "/usr/sbin/nft"} {
		if err := host.root.Chmod(strings.TrimPrefix(path, "/"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"run/openrc/started", "run/openrc/starting", "run/openrc/scheduled", "etc/runlevels/default", "etc/runlevels/boot"} {
		if err := host.root.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return host, []map[string]string{profile}
}

func writeNFTOpenRCFixture(t *testing.T, host nftPersistenceFilesystem, path, content string) {
	t.Helper()
	path = strings.TrimPrefix(path, "/")
	if err := host.root.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNFTOpenRCReadsLoaderWithoutExecutingShellOrNFT(t *testing.T) {
	host, profiles := fixtureNFTOpenRCLoader(t)
	writeNFTOpenRCFixture(t, host, "/etc/rc.conf.d/custom.conf", "rules_file='/etc/global.nft'\n")
	writeNFTOpenRCFixture(t, host, "/etc/conf.d/nftables", "rules_file='/etc/operator.nft'\n")
	loader, err := inspectNFTOpenRCLoader(context.Background(), host, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if loader.status.entries[0] != "/etc/operator.nft" || loader.resolvedBinary != "/usr/sbin/nft" {
		t.Fatal("wrong literal configuration precedence")
	}
	if !validLegacyRetirementDigest(loader.digest) || loader.openrc.runtime.started {
		t.Fatal("invalid loader evidence")
	}
	if _, err := nftRemovalLoaderDigest(loader, loader.status.entries, nil); err != nil {
		t.Fatal(err)
	}
	writeNFTOpenRCFixture(t, host, "/etc/rc.conf.d/new.conf", "rc_parallel=no\n")
	if err := loader.verify(context.Background()); err == nil {
		t.Fatal("new global source was not detected")
	}
}

func TestNFTOpenRCRejectsUnsafeDefinitionsAndState(t *testing.T) {
	cases := map[string]func(*testing.T, nftPersistenceFilesystem){
		"manager": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/sbin/openrc-run", "changed\n")
		},
		"script": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/init.d/nftables", "changed\n")
		},
		"shell syntax": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/conf.d/nftables", "rules_file=$(touch /tmp/unsafe)\n")
		},
		"profile environment": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/profile.env", "rules_file=/etc/other.nft\n")
		},
		"legacy global": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/conf.d/rc", "rc_env_allow=rules_file\n")
		},
		"hidden config": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/rc.conf.d/.conf", "rc_env_allow=rules_file\n")
		},
		"runlevel config": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/conf.d/nftables.default", "rules_file=/etc/other.nft\n")
		},
		"path shadow": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/bin/nft", "#!/bin/sh\nexit 0\n")
		},
		"plugin": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/usr/libexec/rc/plugins/.custom.so", "plugin")
		},
		"runlevel transition": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/run/openrc/rc.starting", "")
		},
		"pid1": func(t *testing.T, h nftPersistenceFilesystem) { writeNFTOpenRCFixture(t, h, "/proc/1/comm", "sh\n") },
		"softlevel": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/run/openrc/softlevel", "shutdown\n")
		},
		"busy": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/run/openrc/starting/nftables", "busy")
		},
		"scheduled": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/run/openrc/scheduled/networking/nftables", "pending")
		},
		"unknown release": func(t *testing.T, h nftPersistenceFilesystem) {
			writeNFTOpenRCFixture(t, h, "/etc/alpine-release", "9.0.0\n")
		},
		"dangling override": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Symlink("/missing", "etc/profile.env"); err != nil {
				t.Fatal(err)
			}
		},
		"unsafe runtime": func(t *testing.T, h nftPersistenceFilesystem) {
			if err := h.root.Chmod("run/openrc", os.ModePerm); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			host, profiles := fixtureNFTOpenRCLoader(t)
			loader, err := inspectNFTOpenRCLoader(context.Background(), host, profiles)
			if err != nil {
				t.Fatal(err)
			}
			change(t, host)
			if err := loader.verify(context.Background()); err == nil {
				t.Fatal("changed input accepted")
			}
			if _, err := inspectNFTOpenRCLoader(context.Background(), host, profiles); err == nil {
				t.Fatal("unsafe initial state accepted")
			}
		})
	}
}

func TestNFTOpenRCBootProofRequiresStartedAndEnabled(t *testing.T) {
	for _, started := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			host, profiles := fixtureNFTOpenRCLoader(t)
			if started {
				if err := host.root.Symlink("/etc/init.d/nftables", "run/openrc/started/nftables"); err != nil {
					t.Fatal(err)
				}
			}
			if enabled {
				if err := host.root.Symlink("../../init.d/nftables", "etc/runlevels/boot/nftables"); err != nil {
					t.Fatal(err)
				}
			}
			loader, err := inspectNFTOpenRCLoader(context.Background(), host, profiles)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := nftRemovalLoaderDigest(loader, loader.status.entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			boot := nftOperatorBootLoader{loader, digest}
			if err := boot.verify(context.Background()); (err == nil) != (started && enabled) {
				t.Fatalf("wrong boot proof: %v", err)
			}
			if started {
				if err := host.root.Remove("run/openrc/started/nftables"); err != nil {
					t.Fatal(err)
				}
				if err := loader.verify(context.Background()); err == nil {
					t.Fatal("runtime transition ignored")
				}
			}
		}
	}
}

func TestNFTOpenRCConfigurationHasLiteralShellMeaning(t *testing.T) {
	for _, input := range []string{
		"save_objects=counters limits quotas\n", "rules_file=/etc/other.nft\u00a0\n", "\u00a0rules_file=/etc/other.nft\n",
		"rules_file=/etc/a;true\n", "rules_file=\"${OTHER}\"\n", "rules_file=/etc/a\\\n",
		"rules_file=/etc/a\nrules_file=/etc/b\n", "rc_env_allow=rules_file\n", "enable_forwarding=yes\n",
		"netns=other\n", "save_on_stop=yes\n", "rules_file=/etc/a\r\n", "rules_file =/etc/a\n",
	} {
		if err := parseNFTOpenRCConfig([]byte(input), make(map[string]string)); err == nil {
			t.Fatalf("unsupported shell form accepted: %q", input)
		}
	}
	values := make(map[string]string)
	if err := parseNFTOpenRCConfig([]byte("\t# comment\nNFTABLES_SAVE='/etc/legacy.nft'\nsave_objects=\"counters limits quotas\"\nsave_on_stop=no\n"), values); err != nil {
		t.Fatal(err)
	}
	if nftOpenRCRulesFile(values) != "/etc/legacy.nft" {
		t.Fatal("legacy literal alias lost")
	}
}
