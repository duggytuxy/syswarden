//go:build linux

package firewall

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureLegacyFail2banServiceStatus() []byte {
	values := map[string]string{
		"Id": "fail2ban.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Type": "simple",
		"MainPID": "123", "ControlPID": "0", "ControlGroup": "/system.slice/fail2ban.service", "InvocationID": strings.Repeat("a", 32),
		"DynamicUser": "no", "NeedDaemonReload": "no", "PIDFile": "/run/fail2ban/fail2ban.pid",
		"FragmentPath": "/usr/lib/systemd/system/fail2ban.service", "DropInPaths": "/etc/systemd/system/fail2ban.service.d/hardening.conf",
		"Environment": "PYTHONNOUSERSITE=yes",
		"ExecStart":   "{ path=/usr/bin/fail2ban-server ; argv[]=/usr/bin/fail2ban-server -xf start ; ignore_errors=no ; start_time=[Sun 2026-10-04 10:00:00 UTC] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }",
	}
	var output strings.Builder
	for _, key := range strings.Split(legacyFail2banServiceProperties, ",") {
		output.WriteString(key + "=" + values[key] + "\n")
	}
	return []byte(output.String())
}

func TestLegacyFail2banServiceRejectsAmbiguousLaunches(t *testing.T) {
	valid := fixtureLegacyFail2banServiceStatus()
	status, err := decodeLegacyFail2banServiceStatus(valid)
	if err != nil || status.peer.Pid != 123 || status.peer.Uid != 0 || len(status.fragments) != 2 {
		t.Fatal("packaged launch rejected", err)
	}
	for _, change := range [][2]string{
		{"Id=fail2ban.service", "Id=another.service"}, {"MainPID=123", "MainPID=00123"},
		{"MainPID=123", "MainPID=2147483648"}, {"ControlPID=0", "ControlPID=456"},
		{"DynamicUser=no", "DynamicUser=yes"}, {"Type=simple", "Type=forking"},
		{"ActiveState=active", "ActiveState=activating"}, {"NeedDaemonReload=no", "NeedDaemonReload=yes"},
		{"User=\n", "User=operator\n"}, {"RootDirectory=\n", "RootDirectory=/isolated\n"},
		{"WorkingDirectory=\n", "WorkingDirectory=/tmp\n"}, {"EnvironmentFiles=\n", "EnvironmentFiles=/etc/custom\n"},
		{"PassEnvironment=\n", "PassEnvironment=PYTHONPATH\n"}, {"UnsetEnvironment=\n", "UnsetEnvironment=PYTHONNOUSERSITE\n"},
		{" -xf start ;", " -xf -c /other/config start ;"}, {" -xf start ;", " --async start ;"},
		{"ignore_errors=no", "ignore_errors=yes"}, {" ; pid=123 ;", " ; pid=456 ;"},
		{"status=0/0 }", "status=0/0 } { path=/bin/sh }"}, {"ControlGroup=/system.slice/fail2ban.service", "ControlGroup=/system.slice/../other"},
		{"InvocationID=" + strings.Repeat("a", 32), "InvocationID=" + strings.Repeat("0", 32)},
		{"InvocationID=" + strings.Repeat("a", 32), "InvocationID=" + strings.Repeat("g", 32)},
		{"DropInPaths=/etc/systemd/system/fail2ban.service.d/hardening.conf", "DropInPaths=/etc/a\\x20b.conf"},
		{"PIDFile=/run/fail2ban/fail2ban.pid", "PIDFile=relative.pid"},
	} {
		t.Run(change[1], func(t *testing.T) {
			input := bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(valid, input) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := decodeLegacyFail2banServiceStatus(input); err == nil {
				t.Fatal("unsupported service launch accepted")
			}
		})
	}
	for _, input := range [][]byte{nil, valid[:len(valid)-1], append(bytes.Clone(valid), []byte("Id=fail2ban.service\n")...), append(bytes.Clone(valid), []byte("Unexpected=value\n")...), bytes.Repeat([]byte("x"), 65537)} {
		if _, err := decodeLegacyFail2banServiceStatus(input); err == nil {
			t.Fatal("incomplete or duplicate property response accepted")
		}
	}
}

func TestLegacyFail2banServiceAllowsOnlyOmittedEmptyEnvironmentFiles(t *testing.T) {
	valid := fixtureLegacyFail2banServiceStatus()
	omitted := bytes.Replace(valid, []byte("EnvironmentFiles=\n"), nil, 1)
	status, err := decodeLegacyFail2banServiceStatus(omitted)
	if err != nil || status.values["EnvironmentFiles"] != "" {
		t.Fatal("empty systemd environment file array rejected", err)
	}
	for _, key := range strings.Split(legacyFail2banServiceProperties, ",") {
		if key == "EnvironmentFiles" {
			continue
		}
		t.Run(key, func(t *testing.T) {
			var incomplete []byte
			for _, line := range bytes.SplitAfter(omitted, []byte("\n")) {
				if !bytes.HasPrefix(line, []byte(key+"=")) {
					incomplete = append(incomplete, line...)
				}
			}
			if _, err := decodeLegacyFail2banServiceStatus(incomplete); err == nil {
				t.Fatal("missing required property accepted")
			}
		})
	}
	for _, suffix := range []string{
		"EnvironmentFiles=/etc/default/custom (ignore_errors=yes)\n",
		"EnvironmentFiles=/etc/one (ignore_errors=no)\nEnvironmentFiles=/etc/two (ignore_errors=no)\n",
		"EnvironmentFiles=\nEnvironmentFiles=\n",
	} {
		if _, err := decodeLegacyFail2banServiceStatus(append(bytes.Clone(omitted), []byte(suffix)...)); err == nil {
			t.Fatal("unsupported environment file array accepted")
		}
	}
}

// The private fixture is an opt-in read-only service-manager capture. Keep its
// bytes and operational details outside the repository and test output.
func TestLegacyFail2banServicePrivatePropertyCapture(t *testing.T) {
	path := os.Getenv("SYSWARDEN_TEST_FAIL2BAN_SERVICE_CAPTURE")
	if path == "" {
		t.Skip("private service capture not supplied")
	}
	content, err := os.ReadFile(path) // #nosec G304 G703 -- Explicit opt-in private test fixture, never part of production command handling.
	if err != nil {
		t.Fatal("cannot read private service capture")
	}
	if _, err := decodeLegacyFail2banServiceStatus(content); err != nil {
		t.Fatal("private service capture is unsupported")
	}
}

func TestLegacyFail2banRuntimePathResolvesOnlyTrustedAlias(t *testing.T) {
	for _, target := range []string{"/run", "../run", "/tmp", "../elsewhere"} {
		t.Run(target, func(t *testing.T) {
			_, host := fixtureNFTPersistenceFilesystem(t)
			if err := host.root.Mkdir("var", 0700); err != nil {
				t.Fatal(err)
			}
			if err := host.root.Symlink(target, "var/run"); err != nil {
				t.Fatal(err)
			}
			path, err := resolveLegacyFail2banRuntimePath(host, "/var/run/fail2ban/fail2ban.sock")
			if target == "/run" || target == "../run" {
				if err != nil || path != "/run/fail2ban/fail2ban.sock" {
					t.Fatal("trusted standard alias rejected", err)
				}
			} else if err == nil {
				t.Fatal("unexpected runtime alias accepted")
			}
		})
	}
	_, host := fixtureNFTPersistenceFilesystem(t)
	for _, path := range []string{"/tmp/control.sock", "/run/../tmp/control.sock", "control.sock", "/run"} {
		if _, err := resolveLegacyFail2banRuntimePath(host, path); err == nil {
			t.Fatal("unsupported endpoint accepted")
		}
	}
}

func TestLegacyFail2banServiceEnvironmentRejectsImportOverrides(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	valid := []byte("PATH=/usr/bin:/bin\x00PYTHONNOUSERSITE=1\x00INVOCATION_ID=" + invocation + "\x00")
	if err := verifyLegacyFail2banServiceEnvironment(valid, invocation); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		nil, valid[:len(valid)-1], bytes.Replace(valid, []byte("PYTHONNOUSERSITE=1"), []byte("PYTHONNOUSERSITE="), 1),
		bytes.Replace(valid, []byte(invocation), []byte(strings.Repeat("b", 32)), 1),
		append(bytes.Clone(valid), []byte("PYTHONPATH=/custom\x00")...),
		append(bytes.Clone(valid), []byte("PYTHONHOME=/custom\x00")...),
		append(bytes.Clone(valid), []byte("LD_PRELOAD=/custom.so\x00")...),
		append(bytes.Clone(valid), []byte("PATH=/different\x00")...),
	} {
		if err := verifyLegacyFail2banServiceEnvironment(input, invocation); err == nil {
			t.Fatal("unsupported import or invocation environment accepted")
		}
	}
}

func TestLegacyFail2banServiceQueryIsBoundedAndUsesFixedArguments(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0700); err != nil {
		t.Fatal(err)
	}
	arguments := "--system --no-pager --all show --property=" + legacyFail2banServiceProperties + " -- fail2ban.service"
	script := "#!/bin/sh\nset -eu\ntest \"$*\" = '" + arguments + "'\nprintf '%s' '" + string(fixtureLegacyFail2banServiceStatus()) + "'\n"
	if err := host.root.WriteFile("usr/bin/systemctl", []byte(script), 0700); err != nil { // #nosec G306 -- Private fixture executable prints synthetic properties and checks fixed read-only arguments.
		t.Fatal(err)
	}
	expected, err := host.snapshot("/usr/bin/systemctl")
	if err != nil {
		t.Fatal(err)
	}
	status, err := queryLegacyFail2banService(context.Background(), host, expected)
	if err != nil || status.peer.Pid != 123 {
		t.Fatal("fixed query failed", err)
	}
	if err := host.root.WriteFile("usr/bin/systemctl", []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0700); err != nil { // #nosec G306 -- Bounded disposable fixture deliberately stalls to test cancellation.
		t.Fatal(err)
	}
	if _, err := queryLegacyFail2banService(context.Background(), host, expected); err == nil {
		t.Fatal("changed service manager accepted")
	}
	expected, err = host.snapshot("/usr/bin/systemctl")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := queryLegacyFail2banService(ctx, host, expected); err == nil || ctx.Err() == nil {
		t.Fatal("unbounded service manager query accepted")
	}
}

func TestLegacyFail2banProbePreservesEarlyEndpoints(t *testing.T) {
	root, host := fixtureLegacyFail2banInstalledParser(t)
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/fail2ban.local", "[Definition]\nsocket = /run/custom/control.sock\npidfile = /run/custom/server.pid\n")
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	view, err := probe(inventory, nil)
	if err != nil || view.socket != "/run/custom/control.sock" || view.pidfile != "/run/custom/server.pid" {
		t.Fatal("installed parser did not resolve early local overrides", err)
	}
	after := cloneLegacyFail2banView(view)
	if err := verifyLegacyFail2banConfigurationViews(view, after, nil); err != nil {
		t.Fatal(err)
	}
	after.socket = "/run/changed/control.sock"
	if err := verifyLegacyFail2banConfigurationViews(view, after, nil); err == nil {
		t.Fatal("changed shared endpoint accepted")
	}
}

// Native validation is opt-in and read-only. It creates no configuration,
// invokes no action hook and never emits the private runtime snapshot.
func TestLegacyFail2banNativeServiceReadOnly(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_FAIL2BAN_NATIVE_READ_ONLY") != "1" {
		t.Skip("native read-only inspection not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native inspection requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	host := nftPersistenceFilesystem{root: root}
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		t.Fatal("capture installed parser:", err)
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal("capture configuration inventory:", err)
	}
	view, err := legacyFail2banConfigurationProbeUsingParser(host, parser)(inventory, nil)
	if err != nil {
		t.Fatal("evaluate immutable configuration:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	inspection, err := inspectLegacyFail2banService(ctx, host, parser, inventory, view)
	if err != nil {
		t.Fatal("bind live service:", err)
	}
	defer func() { _ = inspection.Close() }()
	if _, err := inspection.runtime(ctx); err != nil {
		t.Fatal("inspect runtime without action execution:", err)
	}
	t.Log("Installed parser, immutable configuration and live service inspection passed without mutation")
}

func TestLegacyFail2banServiceAcceptsOnlyCompleteReloadAccountingReset(t *testing.T) {
	original := fixtureLegacyFail2banServiceStatus()
	reset := bytes.Replace(original, []byte("start_time=[Sun 2026-10-04 10:00:00 UTC]"), []byte("start_time=[n/a]"), 1)
	reset = bytes.Replace(reset, []byte(" ; pid=123 ;"), []byte(" ; pid=0 ;"), 1)
	status, err := decodeLegacyFail2banServiceStatus(reset)
	if err != nil || status.peer.Pid != 123 {
		t.Fatal("reload accounting lost the real foreground process", err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(original, []byte(" ; pid=123 ;"), []byte(" ; pid=0 ;"), 1),
		bytes.Replace(reset, []byte("stop_time=[n/a]"), []byte("stop_time=[Mon 2026-10-05 09:00:00 UTC]"), 1),
		bytes.Replace(reset, []byte("MainPID=123"), []byte("MainPID=0"), 1),
		bytes.Replace(reset, []byte(" ; pid=0 ;"), []byte(" ; pid=456 ;"), 1),
	} {
		if _, err := decodeLegacyFail2banServiceStatus(invalid); err == nil {
			t.Fatal("partial or conflicting reload accounting was accepted")
		}
	}
}

func TestLegacyFail2banServiceIdentitySurvivesOnlyAccountingReset(t *testing.T) {
	original := fixtureLegacyFail2banServiceStatus()
	reset := bytes.Replace(original, []byte("start_time=[Sun 2026-10-04 10:00:00 UTC] ; stop_time=[n/a] ; pid=123"), []byte("start_time=[n/a] ; stop_time=[n/a] ; pid=0"), 1)
	before, err := decodeLegacyFail2banServiceStatus(original)
	if err != nil {
		t.Fatal(err)
	}
	after, err := decodeLegacyFail2banServiceStatus(reset)
	if err != nil || !sameLegacyFail2banServiceIdentity(before, after) {
		t.Fatal("same foreground service rejected after accounting reset", err)
	}
	if before.values["ExecStart"] == after.values["ExecStart"] {
		t.Fatal("identity comparison rewrote raw accounting evidence")
	}
	differentTime, err := decodeLegacyFail2banServiceStatus(bytes.Replace(original, []byte("10:00:00"), []byte("11:00:00"), 1))
	if err != nil || sameLegacyFail2banServiceIdentity(before, differentTime) {
		t.Fatal("ordinary changed execution accounting was accepted as a reload reset", err)
	}
	for _, replacement := range [][2]string{
		{"MainPID=123", "MainPID=456"},
		{"InvocationID=" + strings.Repeat("a", 32), "InvocationID=" + strings.Repeat("b", 32)},
		{"Environment=PYTHONNOUSERSITE=yes", "Environment=PYTHONNOUSERSITE=1"},
		{"ControlGroup=/system.slice/fail2ban.service", "ControlGroup=/system.slice/other.service"},
	} {
		changed, err := decodeLegacyFail2banServiceStatus(bytes.Replace(reset, []byte(replacement[0]), []byte(replacement[1]), 1))
		if err != nil {
			t.Fatal("changed fixture did not reach identity comparison", err)
		}
		if sameLegacyFail2banServiceIdentity(before, changed) {
			t.Fatal("accounting exception accepted a changed service identity", replacement[0])
		}
	}
}
