//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readLegacyFail2banFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "legacy_fail2ban", name)) // #nosec G304 -- The table-driven fixture name selects only inert files under testdata/legacy_fail2ban.
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestLegacyFail2banTemplateMatchesCompleteOfficialOutputs(t *testing.T) {
	for _, fixture := range []struct{ name, path, kind, action string }{
		{"syswarden-nft.conf", "action.d/syswarden-nft.conf", "action", ""},
		{"syswarden-webhook.conf", "action.d/syswarden-webhook.conf", "action", ""},
		{"syswarden-persistence.conf", "action.d/syswarden-persistence.conf", "action", ""},
		{"syswarden-portscan-filter.conf", "filter.d/syswarden-portscan.conf", "filter", ""},
		{"portscan-v1013.conf", "jail.d/syswarden-portscan.conf", "jail", "nftables-allports"},
		{"portscan-v1013-aligned.conf", "jail.d/syswarden-portscan.conf", "jail", "nftables-allports"},
		{"portscan-pre_v2.conf", "jail.d/syswarden-portscan.conf", "jail", "syswarden-nft"},
		{"portscan-pre_v2-aligned.conf", "jail.d/syswarden-portscan.conf", "jail", "syswarden-nft"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			content := readLegacyFail2banFixture(t, fixture.name)
			before := bytes.Clone(content)
			path := "/etc/fail2ban/" + fixture.path
			match, ok := matchLegacyFail2banTemplate(path, content)
			if !ok || match.path != path || match.sha256 != sha256.Sum256(content) || match.kind != fixture.kind || match.banaction != fixture.action || match.templateSource == "" || match.templateRevision == "" {
				t.Fatalf("official complete fixture was not identified: %+v", match)
			}
			if !bytes.Equal(content, before) {
				t.Fatal("template inspection modified its input")
			}
			if _, ok := matchLegacyFail2banTemplate(path+".local", content); ok {
				t.Fatal("recognized an unowned override path")
			}
			if _, ok := matchLegacyFail2banTemplate(path, append(bytes.Clone(content), []byte("# administrator customization\n")...)); ok {
				t.Fatal("recognized a modified complete file")
			}
		})
	}
}

func TestLegacyFail2banTemplateRejectsModifiedActionsByteForByte(t *testing.T) {
	for _, name := range []string{"syswarden-nft.conf", "syswarden-webhook.conf", "syswarden-persistence.conf"} {
		t.Run(name, func(t *testing.T) {
			content := readLegacyFail2banFixture(t, name)
			for index := range content {
				changed := bytes.Clone(content)
				changed[index] ^= 1
				if _, ok := matchLegacyFail2banTemplate("/etc/fail2ban/action.d/"+name, changed); ok {
					t.Fatalf("action modification at byte %d was accepted", index)
				}
			}
		})
	}
}

func TestLegacyFail2banTemplateRejectsJailOverridesAndLookalikes(t *testing.T) {
	content := string(readLegacyFail2banFixture(t, "portscan-pre_v2.conf"))
	for _, replacement := range [][2]string{
		{"[syswarden-portscan]", "[administrator-portscan]"},
		{"enabled   = true", "enabled   = false"},
		{"port      = 0:65535", "port      = 22"},
		{"filter    = syswarden-portscan", "filter    = custom"},
		{"/var/log/kern.log", "/var/log/custom.log"},
		{"/var/log/kern.log", "/var/log/*.log"},
		{"backend   = systemd", "backend   = polling"},
		{"banaction = syswarden-nft", "banaction = nftables-allports[name=administrator]"},
		{"maxretry  = 10", "maxretry  = 11"},
		{"findtime  = 10m", "findtime  = 11m"},
		{"bantime   = 24h", "bantime   = 25h"},
	} {
		changed := strings.Replace(content, replacement[0], replacement[1], 1)
		if changed == content {
			t.Fatal("ineffective fixture modification")
		}
		if _, ok := matchLegacyFail2banTemplate("/etc/fail2ban/jail.d/syswarden-portscan.conf", []byte(changed)); ok {
			t.Fatalf("accepted customized jail: %q", replacement[1])
		}
	}
	for _, changed := range []string{content + "action = custom\n", strings.TrimSuffix(content, "\n"), "# local\n" + content, strings.ReplaceAll(content, "\n", "\r\n")} {
		if _, ok := matchLegacyFail2banTemplate("/etc/fail2ban/jail.d/syswarden-portscan.conf", []byte(changed)); ok {
			t.Fatal("accepted unrecognized jail representation")
		}
	}
}

func TestLegacyFail2banFilterRequiresCompleteSafeAppend(t *testing.T) {
	content := readLegacyFail2banFixture(t, "syswarden-portscan-filter.conf")
	prefix := strings.TrimSuffix(string(content), "ignoreregex =\n")
	path := "/etc/fail2ban/filter.d/syswarden-portscan.conf"
	for _, line := range []string{
		"ignoreregex =\n",
		"ignoreregex = SRC=(192\\.0\\.2\\.9|198\\.51\\.100\\.0/24|2001:db8::1) \n",
	} {
		if _, ok := matchLegacyFail2banTemplate(path, []byte(prefix+line)); !ok {
			t.Fatal("complete filter with literal addresses was rejected")
		}
	}
	for _, line := range []string{
		"", "ignoreregex =", "ignoreregex =\nextra = value\n",
		"ignoreregex = SRC=() \n", "ignoreregex = SRC=(.*) \n",
		"ignoreregex = SRC=(192.0.2.9) \n",
		"ignoreregex = SRC=(192\\.0\\.2\\.9||198\\.51\\.100\\.1) \n",
		"ignoreregex = SRC=(custom.example) \n",
		"ignoreregex = SRC=(fe80::1%eth0) \n",
		"ignoreregex = SRC=(192\\.0\\.2\\.1/33) \n",
	} {
		if _, ok := matchLegacyFail2banTemplate(path, []byte(prefix+line)); ok {
			t.Fatalf("accepted incomplete or ambiguous filter suffix %q", line)
		}
	}
}

func TestLegacyFail2banTemplateInspectionIsBounded(t *testing.T) {
	for _, content := range [][]byte{nil, bytes.Repeat([]byte("x"), maximumLegacyFail2banTemplateBytes+1)} {
		if _, ok := matchLegacyFail2banTemplate("/etc/fail2ban/jail.d/syswarden-portscan.conf", content); ok {
			t.Fatal("accepted unbounded or empty input")
		}
	}
}
