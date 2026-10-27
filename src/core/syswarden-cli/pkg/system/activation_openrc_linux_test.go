//go:build linux

package system

import (
	"context"
	"crypto/sha1" // #nosec G505 -- inert native checksum fixture
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const activationCronieFixtureDefinition = "#!/sbin/openrc-run\n\nname=\"$RC_SVCNAME\"\ncommand=\"/usr/sbin/crond\"\ncommand_args=\"$CRON_OPTS -n\"\ncommand_background=true\npidfile=\"/run/$RC_SVCNAME.pid\"\n\ndepend() {\n\tprovide cron\n}\n"

func activationOpenRCReadFixture(t *testing.T, host nativeOpenRCObserver, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(host.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	raw, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func activationOpenRCFixture(t *testing.T) (nativeOpenRCObserver, nativeOpenRCCoreObserver, nativeOpenRCCoreObserver) {
	t.Helper()
	host, core := nativeOpenRCFixture(t)
	nativeOpenRCWrite(t, host, "etc/init.d/cronie", activationCronieFixtureDefinition, 0755)
	nativeOpenRCWrite(t, host, "etc/conf.d/cronie", "CRON_OPTS=\"\"\n", 0644)
	nativeOpenRCWrite(t, host, "usr/sbin/crond", "inert package daemon bytes", 0755)
	nativeOpenRCWrite(t, host, "usr/sbin/nft", "inert package nft bytes", 0755)
	nativeOpenRCWrite(t, host, "run/cronie.pid", "42\n", 0644)
	nativeOpenRCLink(t, host, "run/openrc/started/cronie", "/etc/init.d/cronie")
	nativeOpenRCLink(t, host, "etc/runlevels/default/cronie", "../../init.d/cronie")
	var database strings.Builder
	for _, item := range []struct{ owner, name string }{{"cronie", "usr/sbin/crond"}, {"cronie-openrc", "etc/init.d/cronie"}, {"nftables", "usr/sbin/nft"}} {
		raw := activationOpenRCReadFixture(t, host, item.name)
		sum := sha1.Sum(raw) // #nosec G401 -- fixture for installed native metadata
		database.WriteString("P:" + item.owner + "\nV:1.0-r0\nF:" + filepath.ToSlash(filepath.Dir(item.name)) + "\nR:" + filepath.Base(item.name) + "\nZ:Q1" + base64.StdEncoding.EncodeToString(sum[:]) + "\n\n")
	}
	nativeOpenRCWrite(t, host, "lib/apk/db/installed", database.String(), 0644)
	return host, core, func(*nativeOpenRCRead) (string, error) { return "42:100:/usr/sbin/crond:-n", nil }
}

func TestActivationOpenRCObservationUsesOnlyProtectedEvidence(t *testing.T) {
	host, core, cronie := activationOpenRCFixture(t)
	t.Setenv("PATH", t.TempDir())
	result, err := observeActivationOpenRCWith(t.Context(), "keep", host, core, cronie)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProofSHA256 == "" || result.Scheduler.Unit != "cronie" || !result.Scheduler.DefaultRunlevel || len(result.Services) != 3 {
		t.Fatalf("incomplete result: %#v", result)
	}
	again, err := observeActivationOpenRCWith(t.Context(), "keep", host, core, cronie)
	if err != nil || result.ProofSHA256 != again.ProofSHA256 {
		t.Fatal("unchanged protected evidence did not remain stable", err)
	}
	nativeOpenRCWrite(t, host, "etc/init.d/cronie", "#!/bin/sh\nprintf mutated > sentinel\n", 0755)
	if _, err := observeActivationOpenRCWith(t.Context(), "keep", host, core, cronie); err == nil {
		t.Fatal("administrator provider script accepted")
	}
	if _, err := os.Lstat(filepath.Join(host.root, "sentinel")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("provider script executed", err)
	}
}

func TestActivationOpenRCObservationRejectsIncompleteAndAmbiguousPrerequisites(t *testing.T) {
	for _, kind := range []string{"checksum", "owner", "duplicate", "version", "mode", "symlink", "cron-option", "cron-variant", "cron-custom-runlevel", "cron-stopped", "compatibility", "nft-inactive", "nft-definition", "daemon-record", "pid-observer", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			host, core, cronie := activationOpenRCFixture(t)
			backend := "keep"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			raw := activationOpenRCReadFixture(t, host, "lib/apk/db/installed")
			switch kind {
			case "checksum":
				nativeOpenRCWrite(t, host, "usr/sbin/crond", "changed package daemon bytes", 0755)
			case "owner":
				nativeOpenRCWrite(t, host, "lib/apk/db/installed", strings.Replace(string(raw), "P:cronie\n", "P:other\n", 1), 0644)
			case "duplicate":
				nativeOpenRCWrite(t, host, "lib/apk/db/installed", string(raw)+string(raw), 0644)
			case "version":
				nativeOpenRCWrite(t, host, "lib/apk/db/installed", strings.Replace(string(raw), "V:1.0-r0", "V:2.0-r0", 1), 0644)
			case "mode":
				if err := os.Chmod(filepath.Join(host.root, "usr/sbin/crond"), 0777); err != nil { // #nosec G302 -- deliberately unsafe fixture verifies daemon mode refusal.
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(filepath.Join(host.root, "usr/sbin/crond")); err != nil {
					t.Fatal(err)
				}
				nativeOpenRCLink(t, host, "usr/sbin/crond", "/bin/sh")
			case "cron-option":
				nativeOpenRCWrite(t, host, "etc/conf.d/cronie", "CRON_OPTS=\"-c /tmp/alternate\"\n", 0644)
			case "cron-variant":
				nativeOpenRCWrite(t, host, "etc/conf.d/cronie.default", "# custom\n", 0644)
			case "cron-custom-runlevel":
				nativeOpenRCLink(t, host, "etc/runlevels/custom/cronie", "/etc/init.d/cronie")
			case "cron-stopped":
				nativeOpenRCLink(t, host, "run/openrc/stopped/cronie", "/etc/init.d/cronie")
			case "compatibility":
				nativeOpenRCWrite(t, host, "etc/init.d/iptables", "#!/bin/sh\nexit 0\n", 0755)
			case "nft-inactive":
				backend = "nftables"
			case "nft-definition":
				nativeOpenRCWrite(t, host, "etc/init.d/nftables", "#!/bin/sh\nexit 0\n", 0755)
			case "daemon-record":
				nativeOpenRCWrite(t, host, "run/openrc/daemons/cronie/001", "exec=/usr/sbin/other\n", 0644)
			case "pid-observer":
				cronie = func(*nativeOpenRCRead) (string, error) { return "", errors.New("dead PID") }
			case "canceled":
				cancel()
			}
			if _, err := observeActivationOpenRCWith(ctx, backend, host, core, cronie); err == nil {
				t.Fatal("unsupported or changed prerequisites accepted")
			}
		})
	}
}

func TestActivationOpenRCObservationRejectsEvidenceChangedBetweenCaptures(t *testing.T) {
	host, core, _ := activationOpenRCFixture(t)
	calls := 0
	cronie := func(*nativeOpenRCRead) (string, error) {
		calls++
		if calls == 1 {
			nativeOpenRCWrite(t, host, "etc/conf.d/cronie", "# independent change\nCRON_OPTS=\"\"\n", 0644)
		}
		return "42:100:/usr/sbin/crond:-n", nil
	}
	if _, err := observeActivationOpenRCWith(t.Context(), "keep", host, core, cronie); err == nil {
		t.Fatal("cross-capture source replacement accepted")
	}
}

func TestActivationOpenRCCronieRequiresExactProcessAndInstalledInode(t *testing.T) {
	for _, kind := range []string{"valid", "argv", "executable", "generation", "deleted", "pid"} {
		t.Run(kind, func(t *testing.T) {
			host, _, _ := activationOpenRCFixture(t)
			root, err := os.OpenRoot(host.root)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			r := &nativeOpenRCRead{host: host, root: root, proofs: make(map[string]nativeOpenRCProof)}
			if _, err := r.file("usr/sbin/crond", 4096); err != nil {
				t.Fatal(err)
			}
			procPath := t.TempDir()
			processPath := filepath.Join(procPath, "42")
			if err := os.Mkdir(processPath, 0700); err != nil {
				t.Fatal(err)
			}
			expectedPath := filepath.Join(host.root, "usr/sbin/crond")
			exePath := expectedPath
			if kind == "executable" {
				exePath = filepath.Join(host.root, "usr/sbin/nft")
			}
			if kind == "deleted" {
				exePath += " (deleted)"
			}
			if err := os.Symlink(exePath, filepath.Join(processPath, "exe")); err != nil {
				t.Fatal(err)
			}
			stat := nativeOpenRCProcStat("42", "S", "100")
			if kind == "generation" {
				stat = nativeOpenRCProcStat("42", "Z", "100")
			}
			if err := os.WriteFile(filepath.Join(processPath, "stat"), []byte(stat), 0600); err != nil {
				t.Fatal(err)
			}
			uid := strconv.FormatUint(uint64(host.uid), 10)
			if err := os.WriteFile(filepath.Join(processPath, "status"), []byte("Uid:\t"+strings.Join([]string{uid, uid, uid, uid}, "\t")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := expectedPath + "\x00-n\x00"
			if kind == "argv" {
				args = expectedPath + "\x00-c\x00/other\x00"
			}
			if err := os.WriteFile(filepath.Join(processPath, "cmdline"), []byte(args), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "pid" {
				nativeOpenRCWrite(t, host, "run/cronie.pid", "0042\n", 0644)
			}
			proc, err := os.OpenRoot(procPath)
			if err != nil {
				t.Fatal(err)
			}
			defer proc.Close()
			proof, err := observeActivationCronieAt(r, proc, expectedPath)
			if kind == "valid" {
				if err != nil || proof == "" {
					t.Fatal("coherent process rejected", err)
				}
			} else if err == nil {
				t.Fatal("unsupported process accepted")
			}
		})
	}
}

// Exact upstream Alpine 3.23 definition; retained verbatim as external test data.
const activationNFTFixtureDefinition = "#!/sbin/openrc-run\n\nextra_commands=\"checkconfig panic save\"\nextra_started_commands=\"reload reset\"\n\ndescription=\"Manage nftable based firewall.\"\ndescription_checkconfig=\"Check validity of rulesets on disk without applying changes.\"\ndescription_panic=\"Immediately drop all packets on all interfaces.\"\ndescription_reload=\"Clear current rulesets and load rulesets from the ruleset files.\"\ndescription_save=\"Save nftables state or ruleset to disk.\"\ndescription_reset=\"Reset stateful objects (counters and quotas).\"\n\n# Uppercase variables are there for backward compatibility (Alpine <3.8).\n: ${rules_file:=${NFTABLES_SAVE:-\"/etc/nftables.nft\"}}\n: ${save_objects:=\"ruleset\"}  # \"ruleset\" is for backward compatibility (Alpine <3.17)\n: ${save_options:=${SAVE_OPTIONS:-}}\n: ${save_on_stop:=${SAVE_ON_STOP:-\"no\"}}\n: ${enable_forwarding:=\"no\"}\n\nif [ \"$save_objects\" = 'ruleset' ]; then\n\t: ${save_file:=\"$rules_file\"}\nelse\n\t: ${save_file:=\"/var/lib/nftables/state.nft\"}\nfi\n\nnft=nft\n\n# Add ip netns if configured to run in a netns namespace\nif [ -n \"$netns\" ]; then\n\ttest -e /run/netns/$netns || ip netns add $netns\n\tnft=\"ip netns exec $netns $nft\"\nfi\n\n# Add ip vrf if configured to run in a VRF\nif [ -n \"$vrf\" ]; then\n\tnft=\"ip vrf exec $vrf $nft\"\nfi\n\ndepend() {\n\tneed localmount\n\tafter sysctl\n\tbefore net\n\tprovide firewall\n}\n\nstart_pre() {\n\tcheckkernel && checkconfig\n}\n\nstart() {\n\tebegin \"Loading nftables rules and starting firewall\"\n\n\t$nft -f \"$rules_file\"\n\teend $? || return 1\n\n\tif yesno \"$enable_forwarding\"; then\n\t\tebegin \"Enabling forwarding\"\n\t\tforwarding 1\n\t\teend $? || return 1\n\tfi\n}\n\nstop() {\n\tif yesno \"$save_on_stop\"; then\n\t\tsave || return 1\n\tfi\n\n\tif yesno \"$enable_forwarding\"; then\n\t\tebegin \"Disabling forwarding\"\n\t\tforwarding 0\n\t\teend $?\n\tfi\n\n\tebegin \"Stopping firewall\"\n\t$nft flush ruleset\n\teend $?\n}\n\nreload() {\n\t# This condition is mainly for backward compatibility (Alpine <3.17).\n\tif yesno \"$save_on_stop\" && [ \"$save_objects\" != 'ruleset' ]; then\n\t\tsave || return 1\n\tfi\n\tstart\n}\n\npanic() {\n\tcheckkernel || return 1\n\n\tif service_started \"$RC_SVCNAME\"; then\n\t\trc-service \"$RC_SVCNAME\" stop\n\tfi\n\n\tebegin \"Dropping all packets\"\n\t$nft -f /dev/stdin <<-EOF\n\t\tflush ruleset\n\t\ttable inet filter {\n\t\t    chain input { type filter hook input priority 0; policy drop; }\n\t\t    chain forward { type filter hook forward priority 0; policy drop; }\n\t\t    chain output { type filter hook output priority 0; policy drop; }\n\t\t}\n\tEOF\n\teend $?\n}\n\nsave() {\n\t[ \"$RC_CMD\" = 'save' ] && ebegin \"Saving nftables state\"\n\n\tcheckpath -q -d \"${save_file%/*}\"\n\tcheckpath -q -m 0600 -F -f \"$save_file.tmp\"\n\n\tlocal rc=0\n\tlocal type; for type in $save_objects; do\n\t\t[ \"$type\" = 'ruleset' ] && echo 'flush ruleset' >> \"$save_file.tmp\"\n\t\t$nft $save_options list $type >> \"$save_file.tmp\" || rc=$?\n\tdone\n\n\t[ $rc -eq 0 ] && mv \"$save_file.tmp\" \"$save_file\"\n\n\t[ \"$RC_CMD\" = 'save' ] && eend $rc\n\n\treturn $rc\n}\n\nreset() {\n\tebegin \"Resetting stateful objects\"\n\n\tlocal rc=0 type\n\tfor type in counters quotas; do\n\t\t$nft reset $type >/dev/null || rc=$?\n\tdone\n\n\teend $rc\n}\n\ncheckconfig() {\n\tif [ ! -f \"$rules_file\" ]; then\n\t\teerror \"Rules files $rules_file does not exist!\"\n\t\treturn 1\n\tfi\n\t$nft -c -f \"$rules_file\"\n}\n\ncheckkernel() {\n\tif ! $nft list tables >/dev/null 2>&1; then\n\t\teerror \"Your kernel lacks nftables support, please load\"\n\t\teerror \"appropriate modules and try again.\"\n\t\treturn 1\n\tfi\n\treturn 0\n}\n\nforwarding() {\n\t/sbin/sysctl -qw net.ipv4.ip_forward=$1 || return 1\n\n\tif /sbin/sysctl -eq net.ipv6.conf.all.forwarding >/dev/null; then\n\t\t/sbin/sysctl -qw \\\n\t\t\tnet.ipv6.conf.default.forwarding=$1 \\\n\t\t\tnet.ipv6.conf.all.forwarding=$1 || return 1\n\tfi\n\treturn 0\n}\n"

func TestActivationOpenRCObservedNFTBackend(t *testing.T) {
	host, core, cronie := activationOpenRCFixture(t)
	nativeOpenRCWrite(t, host, "etc/init.d/nftables", activationNFTFixtureDefinition, 0755)
	nativeOpenRCWrite(t, host, "etc/conf.d/nftables", "save_objects=\"counters limits quotas\"\n", 0644)
	nativeOpenRCLink(t, host, "run/openrc/started/nftables", "/etc/init.d/nftables")
	nativeOpenRCLink(t, host, "etc/runlevels/default/nftables", "../../init.d/nftables")
	raw := activationOpenRCReadFixture(t, host, "lib/apk/db/installed")
	sum := sha1.Sum([]byte(activationNFTFixtureDefinition)) // #nosec G401 -- native checksum fixture
	raw = append(raw, []byte("P:nftables-openrc\nV:1.0-r0\nF:etc/init.d\nR:nftables\nZ:Q1"+base64.StdEncoding.EncodeToString(sum[:])+"\n\n")...)
	nativeOpenRCWrite(t, host, "lib/apk/db/installed", string(raw), 0644)
	observation, err := observeActivationOpenRCWith(t.Context(), "nftables", host, core, cronie)
	if err != nil || observation.ProofSHA256 == "" {
		t.Fatal("qualified nftables prerequisites rejected", err)
	}
	nativeOpenRCWrite(t, host, "etc/conf.d/nftables", "netns=\"foreign\"\n", 0644)
	if _, err := observeActivationOpenRCWith(t.Context(), "nftables", host, core, cronie); err == nil {
		t.Fatal("network namespace override accepted")
	}
}
