//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyFail2banProbeRequestBindsOmissions(t *testing.T) {
	_, host := fixtureLegacyFail2banInventory(t)
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	source := inventory.sources[0]
	targets := []nftPersistenceRetiredSource{{source.path, source.sha256}}
	encoded, err := makeLegacyFail2banProbeRequest(inventory, targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	var request legacyFail2banProbeRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	if _, found := request.Files[source.path]; found || len(request.Files) != len(inventory.sources)-1 {
		t.Fatal("staged omission changed the wrong inventory")
	}
	for _, other := range inventory.sources {
		if other.path != source.path && !bytes.Equal(request.Files[other.path], other.snapshot.content) {
			t.Fatal("retained source bytes changed")
		}
	}
	for _, invalid := range [][]nftPersistenceRetiredSource{
		{targets[0], targets[0]},
		{{source.path, sha256.Sum256([]byte("changed"))}},
		{{"/etc/fail2ban/missing.conf", source.sha256}},
	} {
		if _, err := makeLegacyFail2banProbeRequest(inventory, invalid, nil); err == nil {
			t.Fatal("invalid omission accepted")
		}
	}
}

func TestLegacyFail2banProbeResponseRejectsPartialOrUnexpectedStreams(t *testing.T) {
	command := "['set', 'loglevel', 'INFO']\n"
	valid, _ := json.Marshal(map[string]string{"enabled": command, "all": command, "version": "1.1.0", "socket": "/run/fail2ban/control.sock", "pidfile": "/run/fail2ban/server.pid", "actionsEnabled": "[]", "actionsAll": "[]"})
	if _, err := decodeLegacyFail2banProbe(valid); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		nil, []byte("{}"), append(bytes.Clone(valid), []byte("{}")...),
		bytes.Replace(valid, []byte("1.1.0"), []byte("2.0.0"), 1),
		bytes.Replace(valid, []byte("enabled"), []byte("unknown"), 1),
		bytes.ReplaceAll(valid, []byte("'set'"), []byte("'config-error'")),
		bytes.ReplaceAll(valid, []byte("\\n"), nil),
		append([]byte("{\"version\":\"1.1.0\","), valid[1:]...),
		bytes.Replace(valid, []byte("/run/fail2ban/control.sock"), []byte("../control.sock"), 1),
		bytes.Replace(valid, []byte("/run/fail2ban/server.pid"), []byte("/run/fail2ban/control.sock"), 1),
	} {
		if _, err := decodeLegacyFail2banProbe(data); err == nil {
			t.Fatal("invalid parser response accepted")
		}
	}
}

func TestLegacyFail2banPlanBindsParserIdentity(t *testing.T) {
	_, host := fixtureLegacyFail2banInventory(t)
	base := fixtureLegacyFail2banPlanProbe(t)
	for _, kind := range []string{"absent", "changed"} {
		calls := 0
		probe := func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
			view, err := base(inventory, retiring)
			calls++
			if kind == "absent" {
				view.parserSHA256 = [sha256.Size]byte{}
			} else if calls == 2 {
				view.parserSHA256[0] ^= 1
			}
			return view, err
		}
		plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, probe)
		assertEmptyLegacyFail2banPlan(t, plan, err)
	}
	plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, base)
	if err != nil || plan.binding.ParserSHA256 != fixtureLegacyFail2banParserSHA256 {
		t.Fatal("plan did not bind parser identity", err)
	}
	plan.binding.ParserSHA256 = [sha256.Size]byte{}
	if _, _, err := encodeLegacyFail2banPlan(plan.binding, host.expectedUID, host.expectedGID); err == nil {
		t.Fatal("journal accepted absent parser identity")
	}
}

// This opt-in integration test uses the real packaged parser, not a replacement
// INI implementation. The caller supplies an extracted or installed Fail2ban
// 1.1.0 source directory. No host service or host configuration is changed.
func fixtureLegacyFail2banInstalledParser(t *testing.T) (string, nftPersistenceFilesystem) {
	t.Helper()
	library := os.Getenv("SYSWARDEN_TEST_FAIL2BAN_PARSER_ROOT")
	if library == "" {
		t.Skip("set SYSWARDEN_TEST_FAIL2BAN_PARSER_ROOT to the verified packaged Fail2ban 1.1.0 source directory")
	}
	root, host := fixtureNFTPersistenceFilesystem(t)
	libraryRoot, err := os.OpenRoot(library)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = libraryRoot.Close() }()
	for _, part := range []string{"", "client", "server"} {
		if err := os.MkdirAll(filepath.Join(root, legacyFail2banLibrary, part), 0700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(library, part)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".py") {
				continue
			}
			content, err := libraryRoot.ReadFile(filepath.Join(part, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			writeNFTPersistenceFixture(t, root, filepath.Join(legacyFail2banLibrary, part, entry.Name()), string(content))
		}
	}
	binary, err := os.ReadFile("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "usr/bin/python3-fixture")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, binary, 0700); err != nil { // #nosec G306 G703 -- Private fixture copy of the installed interpreter requires owner execute permission.
		t.Fatal(err)
	}
	if err := os.Symlink("python3-fixture", filepath.Join(root, "usr/bin/python3")); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "synthetic.log")
	for _, dir := range []string{"action.d", "filter.d", "jail.d"} {
		if err := os.MkdirAll(filepath.Join(root, "etc/fail2ban", dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/fail2ban.conf", "[Definition]\nloglevel = INFO\nlogtarget = STDERR\nsocket = /run/fail2ban-fixture.sock\npidfile = /run/fail2ban-fixture.pid\ndbfile = None\nallowipv6 = no\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.conf", "[DEFAULT]\nenabled = false\nbackend = polling\nfilter = synthetic\nlogpath = "+log+"\naction = noop\nbantime = 60\nfindtime = 60\nmaxretry = 1\nusedns = no\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/filter.d/synthetic.conf", "[Definition]\nfailregex = ^<HOST> failed$\nignoreregex =\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/noop.conf", "[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = echo <configuration_path>\nactionunban =\n[Init]\nconfiguration_path = unset\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin.conf", "[administrator-active]\nenabled = true\naction = noop[configuration_path=%(fail2ban_confpath)s]\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/syswarden-nft.conf", string(readLegacyFail2banFixture(t, "syswarden-nft.conf")))
	return root, host
}

func TestLegacyFail2banInstalledSnapshotProbe(t *testing.T) {
	for _, profile := range []string{
		"unused", "absolute_include", "relative_include", "implicit_local", "enabled_consumer",
		"disabled_consumer", "inherited_disabled_consumer", "python_action", "external_filter",
		"changed_parser", "changed_interpreter", "hostile_environment", "retained_interpolation",
	} {
		t.Run(profile, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInstalledParser(t)
			target := "/etc/fail2ban/action.d/syswarden-nft.conf"
			switch profile {
			case "absolute_include", "relative_include", "implicit_local":
				include := "/etc/fail2ban/common.fixture"
				reference := include
				if profile == "relative_include" {
					reference = "../common.fixture"
				}
				content := "[administrator-active]\nenabled = true\nbantime = 123\n"
				if profile == "implicit_local" {
					writeNFTPersistenceFixture(t, root, "/etc/fail2ban/common.local", content)
				} else {
					writeNFTPersistenceFixture(t, root, include, content)
				}
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin.conf", "[INCLUDES]\nbefore = "+reference+"\n")
			case "enabled_consumer", "disabled_consumer", "inherited_disabled_consumer":
				content := "[administrator-extra]\nenabled = false\naction = syswarden-nft\n"
				if profile == "enabled_consumer" {
					content = strings.Replace(content, "false", "true", 1)
				}
				if profile == "inherited_disabled_consumer" {
					content = "[DEFAULT]\ncustom_action = syswarden-nft\n[administrator-extra]\nenabled = false\naction = %(custom_action)s\n"
				}
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/extra.local", content)
			case "python_action":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/synthetic.py", "raise RuntimeError('configuration plugin must never run')\n")
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/extra.local", "[administrator-extra]\nenabled = false\naction = synthetic.py\n")
			case "external_filter":
				outside := filepath.Join(root, "external.conf")
				if err := os.WriteFile(outside, []byte("[Definition]\nfailregex = ^<HOST> failed$\n"), 0600); err != nil {
					t.Fatal(err)
				}
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/extra.local", "[administrator-extra]\nenabled = false\nfilter = "+strings.TrimSuffix(outside, ".conf")+"\n")
			case "hostile_environment":
				t.Setenv("PYTHONPATH", root)
				t.Setenv("PYTHONHOME", root)
				t.Setenv("PYTHONINSPECT", "1")
				if err := os.WriteFile(filepath.Join(root, "sitecustomize.py"), []byte("raise RuntimeError('site customization must never run')\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "retained_interpolation":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/noop.local", "[Definition]\nactionban = cat <configuration_path>/action.d/syswarden-nft.conf\n")
			}
			probe, err := newLegacyFail2banConfigurationProbe(host)
			if err != nil {
				t.Fatal("capture parser", err)
			}
			switch profile {
			case "changed_parser":
				writeNFTPersistenceFixture(t, root, legacyFail2banLibrary+"/version.py", "version = '1.1.0'\n")
			case "changed_interpreter":
				if err := os.WriteFile(filepath.Join(root, "usr/bin/python3-fixture"), []byte("replaced"), 0700); err != nil { // #nosec G306 -- Private fixture copy of the installed interpreter requires owner execute permission.
					t.Fatal(err)
				}
			}
			plan, err := prepareLegacyFail2banRetirement(host, []string{target}, probe)
			refused := strings.Contains(profile, "consumer") || profile == "python_action" || profile == "external_filter" || profile == "retained_interpolation" || strings.HasPrefix(profile, "changed_")
			if refused {
				assertEmptyLegacyFail2banPlan(t, plan, err)
			} else if err != nil || len(plan.records) != 1 || plan.binding.ParserSHA256 == ([sha256.Size]byte{}) {
				t.Fatal("immutable installed parser failed", err)
			}
			if _, err := host.snapshot(target); err != nil {
				t.Fatal("probe changed active target", err)
			}
			if _, err := os.Stat(filepath.Join(root, "var/backups")); !os.IsNotExist(err) {
				t.Fatal("probe created recovery state")
			}
		})
	}
}

func TestLegacyFail2banSnapshotProbeCannotReadActiveFiles(t *testing.T) {
	root, host := fixtureLegacyFail2banInstalledParser(t)
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	input, err := makeLegacyFail2banProbeRequest(inventory, nil, parser.modules)
	if err != nil {
		t.Fatal(err)
	}
	// Changes after capture must not affect evaluation of the immutable bytes.
	// The production closure separately refuses such changes before approval.
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin.conf", "[broken configuration")
	binary, err := os.Open(filepath.Join(root, parser.executable)) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = binary.Close() }()
	view, err := runLegacyFail2banProbe(binary, input, 20*time.Second)
	if err != nil || !bytes.Contains(view.enabled, []byte("administrator-active")) {
		t.Fatal("parser read active files instead of captured bytes", err)
	}
	if !bytes.Contains(view.enabled, []byte("/etc/fail2ban")) || bytes.Contains(view.enabled, []byte(filepath.Join(root, "etc/fail2ban"))) {
		t.Fatal("logical configuration paths were rewritten")
	}
	if err := reattestLegacyFail2banPlanInventory(host, inventory); err == nil {
		t.Fatal("live edit was not refused by the caller")
	}
}

func TestLegacyFail2banSnapshotProbeRedactsErrorsAndBoundsExecution(t *testing.T) {
	root, host := fixtureLegacyFail2banInstalledParser(t)
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(filepath.Join(root, parser.executable)) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = binary.Close() }()
	secret := []byte("private-diagnostic-marker")
	if _, err := runLegacyFail2banProbe(binary, secret, time.Second); err == nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatal("probe accepted input or exposed it", err)
	}
	if _, err := runLegacyFail2banProbe(binary, secret, time.Nanosecond); err == nil {
		t.Fatal("deadline not enforced")
	}
}

func TestLegacyFail2banSnapshotProbeWithPackagedConfiguration(t *testing.T) {
	source := os.Getenv("SYSWARDEN_TEST_FAIL2BAN_CONFIG_ROOT")
	if source == "" {
		t.Skip("set SYSWARDEN_TEST_FAIL2BAN_CONFIG_ROOT to the verified packaged configuration directory")
	}
	root, host := fixtureLegacyFail2banInstalledParser(t)
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourceRoot.Close() }()
	targetRoot, err := os.OpenRoot(filepath.Join(root, legacyFail2banDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = targetRoot.Close() }()
	err = fs.WalkDir(sourceRoot.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return targetRoot.MkdirAll(path, 0700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("packaged configuration fixture contains a non-regular file")
		}
		content, err := sourceRoot.ReadFile(path)
		if err != nil {
			return err
		}
		return targetRoot.WriteFile(path, content, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Use a synthetic enabled jail without relying on a host log path. The
	// packaged dormant jails, filters and actions are still resolved in full.
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.local", "[sshd]\nenabled = false\n")
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/admin.conf", "[administrator-active]\nenabled = true\nbackend = polling\nfilter = synthetic\naction = noop\nlogpath = "+filepath.Join(root, "synthetic.log")+"\n")
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyFail2banRetirement(host, []string{"/etc/fail2ban/action.d/syswarden-nft.conf"}, probe)
	if err != nil || len(plan.binding.Sources) < 150 {
		t.Fatal("packaged enabled and dormant configuration evaluation failed", err)
	}
}
