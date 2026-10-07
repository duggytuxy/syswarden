//go:build linux

package firewall

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixtureNFTPersistenceLoaderStatus() []byte {
	values := map[string]string{
		"Id": "nftables.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "exited", "Type": "oneshot",
		"MainPID": "0", "ControlPID": "0", "RemainAfterExit": "yes", "DynamicUser": "no", "NeedDaemonReload": "no", "PrivateNetwork": "no", "PrivateUsers": "no",
		"FragmentPath": "/usr/lib/systemd/system/nftables.service", "DropInPaths": "/etc/systemd/system/nftables.service.d/administrator.conf",
		"ExecStart":  "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf ; ignore_errors=no ; start_time=[Sun 2026-10-04 10:00:00 UTC] ; stop_time=[Sun 2026-10-04 10:00:00 UTC] ; pid=123 ; code=exited ; status=0 }",
		"ExecReload": "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
	}
	var output strings.Builder
	for _, key := range strings.Split(nftPersistenceLoaderProperties, ",") {
		output.WriteString(key + "=" + values[key] + "\n")
	}
	return []byte(output.String())
}

func TestNFTPersistenceLoaderRejectsAmbiguousCommandsAndNamespaces(t *testing.T) {
	valid := fixtureNFTPersistenceLoaderStatus()
	status, err := decodeNFTPersistenceLoaderStatus(valid)
	if err != nil || !reflect.DeepEqual(status.entries, []string{"/etc/nftables.conf"}) || len(status.fragments) != 2 {
		t.Fatal("supported idle loader rejected", err)
	}
	for _, change := range [][2]string{
		{"Id=nftables.service", "Id=another.service"}, {"MainPID=0", "MainPID=123"}, {"ControlPID=0", "ControlPID=123"},
		{"ActiveState=active", "ActiveState=activating"}, {"SubState=exited", "SubState=running"}, {"LoadState=loaded", "LoadState=masked"},
		{"Type=oneshot", "Type=simple"}, {"RemainAfterExit=yes", "RemainAfterExit=no"}, {"DynamicUser=no", "DynamicUser=yes"},
		{"NeedDaemonReload=no", "NeedDaemonReload=yes"}, {"User=\n", "User=operator\n"}, {"Group=\n", "Group=operator\n"},
		{"RootDirectory=\n", "RootDirectory=/other\n"}, {"RootImage=\n", "RootImage=/other.raw\n"}, {"WorkingDirectory=\n", "WorkingDirectory=/etc\n"},
		{"Environment=\n", "Environment=LD_PRELOAD=/custom.so\n"}, {"EnvironmentFiles=\n", "EnvironmentFiles=/etc/override\n"},
		{"PassEnvironment=\n", "PassEnvironment=PATH\n"}, {"UnsetEnvironment=\n", "UnsetEnvironment=PATH\n"},
		{"BindPaths=\n", "BindPaths=/other:/etc\n"}, {"BindReadOnlyPaths=\n", "BindReadOnlyPaths=/other:/etc\n"},
		{"TemporaryFileSystem=\n", "TemporaryFileSystem=/etc\n"}, {"MountImages=\n", "MountImages=/other.raw\n"},
		{"ExtensionImages=\n", "ExtensionImages=/other.raw\n"}, {"ExtensionDirectories=\n", "ExtensionDirectories=/other\n"},
		{"PrivateNetwork=no", "PrivateNetwork=yes"}, {"NetworkNamespacePath=\n", "NetworkNamespacePath=/run/netns/other\n"},
		{"JoinsNamespaceOf=\n", "JoinsNamespaceOf=other.service\n"}, {"PrivateUsers=no", "PrivateUsers=yes"},
		{" -f /etc/nftables.conf ;", " -f relative.nft ;"}, {" -f /etc/nftables.conf ;", " -I /other /etc/nftables.conf ;"},
		{" -f /etc/nftables.conf ;", " -f /etc/*.nft ;"}, {"path=/usr/sbin/nft ;", "path=/bin/sh ;"},
		{"ignore_errors=no", "ignore_errors=yes"}, {" ; status=0 }", " ; status=1 }"}, {" ; pid=123 ;", " ; pid=00123 ;"},
		{"ExecStartPre=\n", "ExecStartPre={ path=/bin/sh }\n"}, {"ExecStartPost=\n", "ExecStartPost={ path=/bin/sh }\n"},
		{"ExecStopPost=\n", "ExecStopPost={ path=/bin/sh }\n"}, {"ExecCondition=\n", "ExecCondition={ path=/bin/sh }\n"},
		{"DropInPaths=/etc/systemd/system/nftables.service.d/administrator.conf", "DropInPaths=/etc/unit\\x20name.conf"},
	} {
		t.Run(change[1], func(t *testing.T) {
			input := bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(input, valid) {
				t.Fatal("fixture change did not apply")
			}
			if _, err := decodeNFTPersistenceLoaderStatus(input); err == nil {
				t.Fatal("unsupported loader configuration accepted")
			}
		})
	}
	for _, input := range [][]byte{nil, valid[:len(valid)-1], append(bytes.Clone(valid), []byte("Id=nftables.service\n")...), append(bytes.Clone(valid), []byte("Unknown=value\n")...), bytes.Repeat([]byte("x"), 65537)} {
		if _, err := decodeNFTPersistenceLoaderStatus(input); err == nil {
			t.Fatal("unbounded or incomplete loader properties accepted")
		}
	}
}

func TestNFTPersistenceLoaderAllowsOnlyKnownEmptyArrayOmissions(t *testing.T) {
	valid := fixtureNFTPersistenceLoaderStatus()
	optional := []string{"EnvironmentFiles", "ExecReload", "ExecStop", "ExecStartPre", "ExecStartPost", "ExecStopPost", "ExecCondition", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "MountImages", "ExtensionImages", "ExtensionDirectories"}
	for _, key := range strings.Split(nftPersistenceLoaderProperties, ",") {
		t.Run(key, func(t *testing.T) {
			var input []byte
			for _, line := range bytes.SplitAfter(valid, []byte("\n")) {
				if !bytes.HasPrefix(line, []byte(key+"=")) {
					input = append(input, line...)
				}
			}
			allowed := false
			for _, candidate := range optional {
				allowed = allowed || key == candidate
			}
			_, err := decodeNFTPersistenceLoaderStatus(input)
			if (err == nil) != allowed {
				t.Fatal("incorrect property omission policy", key, err)
			}
		})
	}
	stop := "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft flush ruleset ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	if _, err := decodeNFTPersistenceLoaderStatus(bytes.Replace(valid, []byte("ExecStop=\n"), []byte("ExecStop="+stop+"\n"), 1)); err != nil {
		t.Fatal("read-only observation rejected the packaged stop command", err)
	}
}

func fixtureNFTPersistenceLoaderInspection(t *testing.T) (nftPersistenceFilesystem, *nftPersistenceLoaderInspection) {
	t.Helper()
	_, host := fixtureNFTPersistenceFilesystem(t)
	return host, installNFTPersistenceLoaderFixture(t, host)
}

func installNFTPersistenceLoaderFixture(t *testing.T, host nftPersistenceFilesystem) *nftPersistenceLoaderInspection {
	t.Helper()
	for _, path := range []string{"usr/bin", "usr/sbin", "usr/lib/systemd/system", "etc/systemd/system/nftables.service.d"} {
		if err := host.root.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	arguments := "--system --no-pager --all show --property=" + nftPersistenceLoaderProperties + " -- nftables.service"
	script := "#!/bin/sh\nset -eu\ntest \"$*\" = '" + arguments + "'\nprintf '%s' '" + string(fixtureNFTPersistenceLoaderStatus()) + "'\n"
	if err := host.root.WriteFile("usr/bin/systemctl", []byte(script), 0700); err != nil { // #nosec G306 -- Private fixed-argument read-only fixture executable.
		t.Fatal(err)
	}
	if err := host.root.WriteFile("usr/sbin/nft", []byte("#!/bin/sh\nexit 91\n"), 0700); err != nil { // #nosec G306 -- Private sentinel fails if loader inspection attempts to execute nftables.
		t.Fatal(err)
	}
	for _, path := range []string{"usr/lib/systemd/system/nftables.service", "etc/systemd/system/nftables.service.d/administrator.conf"} {
		if err := host.root.WriteFile(path, []byte("# synthetic service observation fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	inspection, err := inspectNFTPersistenceLoader(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func TestNFTPersistenceLoaderBindsCommandsAndEveryUnitFile(t *testing.T) {
	for _, change := range []string{"manager", "binary", "unit", "drop-in", "permissions", "none"} {
		t.Run(change, func(t *testing.T) {
			host, inspection := fixtureNFTPersistenceLoaderInspection(t)
			if !validLegacyRetirementDigest(inspection.digest) || len(inspection.files) != 4 {
				t.Fatal("incomplete loader binding")
			}
			paths := map[string]string{"manager": "usr/bin/systemctl", "binary": "usr/sbin/nft", "unit": "usr/lib/systemd/system/nftables.service", "drop-in": "etc/systemd/system/nftables.service.d/administrator.conf"}
			if path, exists := paths[change]; exists {
				if err := host.root.WriteFile(path, []byte("changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if change == "permissions" {
				if err := host.root.Chmod(paths["drop-in"], 0640); err != nil {
					t.Fatal(err)
				}
			}
			if err := inspection.verify(context.Background()); (err == nil) != (change == "none") {
				t.Fatal("changed loader evidence was not rejected", err)
			}
		})
	}
}

func TestNFTPersistenceLoaderPrivatePropertyCapture(t *testing.T) {
	path := os.Getenv("SYSWARDEN_TEST_NFT_LOADER_CAPTURE")
	if path == "" {
		t.Skip("private read-only service capture not supplied")
	}
	content, err := os.ReadFile(path) // #nosec G304 G703 -- Explicit opt-in private fixture; no production path or public output.
	if err != nil {
		t.Fatal("private capture unavailable")
	}
	if _, err := decodeNFTPersistenceLoaderStatus(content); err != nil {
		t.Fatal("private loader capture is unsupported")
	}
}

func TestNFTPersistenceLoaderNativeReadOnly(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_LOADER_NATIVE") != "1" {
		t.Skip("explicit read-only native inspection not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("read-only native inspection requires root metadata access")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inspection, err := inspectNFTPersistenceLoader(ctx, nftPersistenceFilesystem{root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := inspection.verify(ctx); err != nil {
		t.Fatal(err)
	}
}
