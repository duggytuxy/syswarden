//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeInactiveOpenRCFixture(t *testing.T) nativeOpenRCObserver {
	t.Helper()
	host, _ := nativeOpenRCFixture(t)
	for _, name := range []string{"etc/init.d/syswarden-core", "etc/init.d/syswarden-firewall", "run/openrc/started/syswarden-core", "run/openrc/started/syswarden-firewall", "etc/runlevels/custom/syswarden-core", "etc/runlevels/custom/syswarden-firewall", "etc/runlevels/default/syswarden-core"} {
		if err := os.Remove(filepath.Join(host.root, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"run/openrc/daemons/syswarden-core", "run/openrc/options/syswarden-core"} {
		if err := os.RemoveAll(filepath.Join(host.root, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"etc/syswarden/config", "etc/cron.d", "etc/periodic/daily", "var/spool/cron/crontabs"} {
		if err := os.MkdirAll(filepath.Join(host.root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	nativeOpenRCWrite(t, host, "etc/cron.d/administrator", "5 * * * * root /usr/local/sbin/administrator-job\n", 0600)
	nativeOpenRCWrite(t, host, "var/spool/cron/crontabs/root", "0 * * * * /usr/bin/run-parts /etc/periodic/hourly\n", 0600)
	return host
}

func TestNativeInactiveOpenRCIsReadOnlyWithoutActiveProviders(t *testing.T) {
	host := nativeInactiveOpenRCFixture(t)
	first, err := observeNativeInactiveOpenRCWith(t.Context(), host)
	if err != nil {
		t.Fatal(err)
	}
	second, err := observeNativeInactiveOpenRCWith(t.Context(), host)
	if err != nil || first != second {
		t.Fatal("unchanged inactive host changed", err)
	}
	for _, name := range []string{"etc/init.d/cronie", "etc/init.d/nftables", "run/openrc/started/cronie", "run/openrc/started/nftables", "var/lib/syswarden", "var/log/syswarden"} {
		if _, err := os.Lstat(filepath.Join(host.root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("observer created prerequisites or product state", name, err)
		}
	}
	nativeOpenRCWrite(t, host, "etc/cron.d/administrator", "6 * * * * root /usr/local/sbin/administrator-job\n", 0600)
	changed, err := observeNativeInactiveOpenRCWith(t.Context(), host)
	if err != nil || changed == first {
		t.Fatal("changed administrator schedule was not bound", err)
	}
}

func TestNativeInactiveOpenRCRefusesRetainedHistoryAndSchedules(t *testing.T) {
	for _, name := range []string{"stopped-service", "active-service", "runlevel", "pending", "cron", "hidden-cron", "root-cron", "periodic", "state", "persistent", "hidden-state", "ssh", "symlink", "oversized", "depth"} {
		t.Run(name, func(t *testing.T) {
			host := nativeInactiveOpenRCFixture(t)
			switch name {
			case "stopped-service":
				nativeOpenRCWrite(t, host, "etc/init.d/syswarden-core", openRCCoreService, 0755)
			case "active-service":
				nativeOpenRCLink(t, host, "run/openrc/started/syswarden-core", "/etc/init.d/syswarden-core")
			case "runlevel":
				nativeOpenRCLink(t, host, "etc/runlevels/custom/syswarden-core", "../../init.d/syswarden-core")
			case "pending":
				nativeOpenRCWrite(t, host, "run/openrc/starting/syswarden-core", "pending", 0600)
			case "cron":
				nativeOpenRCWrite(t, host, "etc/cron.d/administrator", "* * * * * root /opt/syswarden/bin/syswarden-cli reload\n", 0600)
			case "hidden-cron":
				nativeOpenRCWrite(t, host, "etc/cron.d/.syswarden-intent", "old", 0600)
			case "root-cron":
				nativeOpenRCWrite(t, host, "var/spool/cron/crontabs/root", "* * * * * syswarden reload\n", 0600)
			case "periodic":
				nativeOpenRCWrite(t, host, "etc/periodic/daily/update", "#!/bin/sh\n/opt/syswarden/bin/syswarden-cli update-feeds\n", 0700)
			case "state":
				nativeOpenRCWrite(t, host, "var/lib/syswarden/state", "old", 0600)
			case "persistent":
				nativeOpenRCWrite(t, host, "etc/syswarden/syswarden.nft", "old", 0600)
			case "hidden-state":
				nativeOpenRCWrite(t, host, "etc/syswarden/.intent", "old", 0600)
			case "ssh":
				nativeOpenRCWrite(t, host, "etc/ssh/sshd_config.d/00-syswarden-hardening.conf", "old", 0600)
			case "symlink":
				nativeOpenRCLink(t, host, "etc/cron.d/alias", "administrator")
			case "oversized":
				nativeOpenRCWrite(t, host, "etc/cron.d/large", strings.Repeat("x", (1<<20)+1), 0600)
			case "depth":
				nativeOpenRCWrite(t, host, "etc/periodic/"+strings.Repeat("nested/", 10)+"job", "true", 0600)
			}
			if _, err := observeNativeInactiveOpenRCWith(t.Context(), host); err == nil {
				t.Fatal("incomplete inactive admission accepted")
			}
		})
	}
}

func TestNativeInactiveOpenRCSchedulingMembershipAndIdentityAreBound(t *testing.T) {
	for _, name := range []string{"addition", "same-bytes-replacement", "missing-spool"} {
		t.Run(name, func(t *testing.T) {
			host := nativeInactiveOpenRCFixture(t)
			first, err := observeNativeInactiveOpenRCWith(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "addition":
				nativeOpenRCWrite(t, host, "etc/cron.d/another", "true", 0600)
			case "same-bytes-replacement":
				old := filepath.Join(host.root, "etc/cron.d/administrator")
				fixtureRoot, err := os.OpenRoot(host.root)
				if err != nil {
					t.Fatal(err)
				}
				defer fixtureRoot.Close()
				pinned, err := fixtureRoot.Open("etc/cron.d/administrator")
				if err != nil {
					t.Fatal(err)
				}
				defer pinned.Close()
				if err := os.Remove(old); err != nil {
					t.Fatal(err)
				}
				nativeOpenRCWrite(t, host, "etc/cron.d/administrator", "5 * * * * root /usr/local/sbin/administrator-job\n", 0600)
			case "missing-spool":
				if err := os.RemoveAll(filepath.Join(host.root, "var/spool/cron")); err != nil {
					t.Fatal(err)
				}
			}
			second, err := observeNativeInactiveOpenRCWith(t.Context(), host)
			if err != nil || first == second {
				t.Fatal("schedule identity/membership change was lost", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := observeNativeInactiveOpenRCWith(ctx, nativeInactiveOpenRCFixture(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}

func TestNativeInactivePolicyNeverAdoptsCurrentStateAsOriginalAuthority(t *testing.T) {
	for _, name := range []string{"valid", "policy", "absence", "host", "mixed", "host-error", "during-host", "cancel"} {
		t.Run(name, func(t *testing.T) {
			original := inactivePolicyFixture()
			current := original
			hostSHA := strings.Repeat("a", 64)
			changed := false
			policy := func(ctx context.Context) (apkTransitionPolicyBinding, error) { return current, ctx.Err() }
			host := func(ctx context.Context) (string, error) {
				if changed && name == "host-error" {
					return "", errors.New("unavailable")
				}
				if changed && name == "during-host" {
					current.AbsenceSHA256 = strings.Repeat("b", 64)
				}
				return hostSHA, ctx.Err()
			}
			observed, err := captureNativeInactivePolicyWith(t.Context(), policy, host)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			changed = true
			switch name {
			case "policy":
				current.PolicySHA256 = strings.Repeat("f", 64)
			case "absence":
				current.AbsenceSHA256 = strings.Repeat("f", 64)
			case "host":
				hostSHA = strings.Repeat("f", 64)
			case "mixed":
				current.ApprovalSHA256 = strings.Repeat("f", 64)
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if err := observed.revalidate(ctx); (err == nil) != (name == "valid") {
				t.Fatal("changed admission state accepted", err)
			}
			if observed.binding != original {
				t.Fatal("original policy was rebased")
			}
		})
	}
	services := productionInactiveNativeBindingServices(nil)
	if services.policy == nil || services.publication == nil || services.classify == nil || services.installedRuntime == nil {
		t.Fatal("incomplete explicit read-only factory")
	}
}

func TestNativeInactiveOpenRCBindsExactAlpineCronAlias(t *testing.T) {
	for _, kind := range []string{"valid", "changed-target-content", "wrong-target", "dangling", "nested-alias"} {
		t.Run(kind, func(t *testing.T) {
			host := nativeInactiveOpenRCFixture(t)
			if err := os.RemoveAll(filepath.Join(host.root, "var/spool/cron/crontabs")); err != nil {
				t.Fatal(err)
			}
			nativeOpenRCWrite(t, host, "etc/crontabs/root", "5 * * * * /usr/local/sbin/admin-job\n", 0600)
			nativeOpenRCLink(t, host, "var/spool/cron/crontabs", "../../../etc/crontabs")
			first, err := observeNativeInactiveOpenRCWith(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "changed-target-content":
				nativeOpenRCWrite(t, host, "etc/crontabs/root", "6 * * * * /usr/local/sbin/admin-job\n", 0600)
			case "wrong-target":
				if err := os.Remove(filepath.Join(host.root, "var/spool/cron/crontabs")); err != nil {
					t.Fatal(err)
				}
				nativeOpenRCLink(t, host, "var/spool/cron/crontabs", "../../../etc/cron.d")
			case "dangling":
				if err := os.RemoveAll(filepath.Join(host.root, "etc/crontabs")); err != nil {
					t.Fatal(err)
				}
			case "nested-alias":
				nativeOpenRCLink(t, host, "etc/crontabs/alias", "root")
			}
			second, err := observeNativeInactiveOpenRCWith(t.Context(), host)
			if kind == "valid" {
				if err != nil || first != second {
					t.Fatal("unchanged native alias rejected", err)
				}
			} else if kind == "changed-target-content" {
				if err != nil || first == second {
					t.Fatal("target content not bound", err)
				}
			} else if err == nil {
				t.Fatal("unsafe alias accepted")
			}
		})
	}
}

func TestNativeInactiveProcessScanIncludesNonRootProductProcesses(t *testing.T) {
	for _, kind := range []string{"core", "tui", "mutator", "readonly", "lookalike"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			proc := filepath.Join(root, "proc")
			if err := os.Mkdir(proc, 0700); err != nil {
				t.Fatal(err)
			}
			cli := filepath.Join(root, "syswarden-cli")
			for _, name := range []string{"syswarden-cli", "syswarden-core", "syswarden-tui", "administrator-helper"} {
				// These are inert scanner fixtures; no executable permission is needed.
				if err := os.WriteFile(filepath.Join(root, name), []byte("inert"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			executable := cli
			args := []string{cli, "reload"}
			switch kind {
			case "core":
				executable = filepath.Join(root, "syswarden-core")
				args = []string{executable}
			case "tui":
				executable = filepath.Join(root, "syswarden-tui")
				args = []string{executable}
			case "readonly":
				args = []string{cli, "status"}
			case "lookalike":
				executable = filepath.Join(root, "administrator-helper")
				args = []string{executable, "reload"}
			}
			writeFirewallRemovalProcessFixture(t, proc, "103", executable, args, true)
			scanner := newFirewallRemovalProcessScannerForTest(t, proc, cli, 999, "103")
			scanner.rejectCore = true
			if err := scanner.scan(); err != nil {
				t.Fatal("existing root-only contract changed", err)
			}
			scanner.inspectAllUsers = true
			err := scanner.scan()
			if kind == "readonly" || kind == "lookalike" {
				if err != nil {
					t.Fatal("unrelated read-only process refused", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "non-root") {
				t.Fatal("non-root product process accepted", err)
			}
		})
	}
}
