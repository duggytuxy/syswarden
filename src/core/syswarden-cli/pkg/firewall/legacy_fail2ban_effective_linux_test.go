//go:build linux

package firewall

import (
	"bytes"
	"strings"
	"testing"
)

func fixtureLegacyFail2banEffective(t *testing.T, profile string) ([]byte, []byte, []legacyFail2banTemplateMatch) {
	t.Helper()
	name := "portscan-pre_v2.conf"
	if profile == "upstream" {
		name = "portscan-v1013.conf"
	}
	match, ok := matchLegacyFail2banTemplate("/etc/fail2ban/jail.d/syswarden-portscan.conf", readLegacyFail2banFixture(t, name))
	if !ok {
		t.Fatal("fixture has no template match")
	}
	return readLegacyFail2banFixture(t, "effective-"+profile+"-before.txt"), readLegacyFail2banFixture(t, "effective-"+profile+"-after.txt"), []legacyFail2banTemplateMatch{match}
}

func TestLegacyFail2banEffectiveRetirementPreservesActualUnrelatedCommands(t *testing.T) {
	for _, profile := range []string{"upstream", "historical"} {
		t.Run(profile, func(t *testing.T) {
			before, after, templates := fixtureLegacyFail2banEffective(t, profile)
			originalBefore, originalAfter := bytes.Clone(before), bytes.Clone(after)
			if err := verifyLegacyFail2banEffectiveRetirement(before, after, templates); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, originalBefore) || !bytes.Equal(after, originalAfter) {
				t.Fatal("comparison modified its source evidence")
			}
		})
	}
}

func TestLegacyFail2banEffectiveRetirementRejectsChangesToAdministratorProtection(t *testing.T) {
	for _, profile := range []string{"upstream", "historical"} {
		before, after, templates := fixtureLegacyFail2banEffective(t, profile)
		for _, replacement := range [][2]string{
			{"'administrator-web', 'bantime', '3600'", "'administrator-web', 'bantime', '1'"},
			{"'administrator-web', 'maxretry', 1", "'administrator-web', 'maxretry', 99"},
			{"'loglevel', 'INFO'", "'loglevel', 'ERROR'"},
			{"'allowipv6', 'no'", "'allowipv6', 'yes'"},
			{"['start', 'administrator-web']\n", ""},
			{"'administrator-web'", "'administrator-web-copy'"},
			{"/run/fail2ban-fixture/state.sqlite3", "/run/fail2ban-fixture/replaced.sqlite3"},
		} {
			changed := strings.Replace(string(after), replacement[0], replacement[1], 1)
			if changed == string(after) {
				t.Fatalf("ineffective change %q", replacement[0])
			}
			if err := verifyLegacyFail2banEffectiveRetirement(before, []byte(changed), templates); err == nil {
				t.Fatalf("accepted changed protection in %s: %q", profile, replacement[0])
			}
		}
	}
}

func TestLegacyFail2banEffectiveRetirementRejectsPartialAndAmbiguousStreams(t *testing.T) {
	before, after, templates := fixtureLegacyFail2banEffective(t, "historical")
	for _, replacement := range [][2]string{
		{"['add', 'syswarden-portscan', 'polling']\n", ""},
		{"['add', 'syswarden-portscan', 'polling']\n", "['add', 'syswarden-portscan', 'polling']\n['add', 'syswarden-portscan', 'polling']\n"},
		{"['start', 'syswarden-portscan']\n", ""},
		{"['start', 'syswarden-portscan']\n", "['start', 'syswarden-portscan']\n['set', 'syswarden-portscan', 'maxretry', 2]\n"},
		{"['start', 'syswarden-portscan']\n", "['start', 'syswarden-portscan', 'other']\n"},
		{"['start', 'syswarden-portscan']\n", "['start', 'syswarden-portscan-copy']\n"},
	} {
		changed := strings.Replace(string(before), replacement[0], replacement[1], 1)
		if changed == string(before) {
			t.Fatal("ineffective change")
		}
		if err := verifyLegacyFail2banEffectiveRetirement([]byte(changed), after, templates); err == nil {
			t.Fatal("accepted an ambiguous target jail stream")
		}
	}
	for _, extra := range []string{
		"['config-error', 'configuration is invalid']\n",
		"diagnostic text\n", "\n", "['unknown', 'syswarden-portscan']\n",
		"['set', 'syswarden-portscan',\n 'maxretry', 2]\n",
	} {
		if err := verifyLegacyFail2banEffectiveRetirement(append(bytes.Clone(before), []byte(extra)...), after, templates); err == nil {
			t.Fatal("ignored an invalid dump record")
		}
	}
	if err := verifyLegacyFail2banEffectiveRetirement(before, before, templates); err == nil {
		t.Fatal("accepted a target that was not retired")
	}
	if err := verifyLegacyFail2banEffectiveRetirement(after, after, templates); err == nil {
		t.Fatal("accepted a target absent from the initial evidence")
	}
}

func TestLegacyFail2banEffectiveRetirementRequiresBoundTemplatesAndBoundedInput(t *testing.T) {
	before, after, templates := fixtureLegacyFail2banEffective(t, "upstream")
	for _, change := range []string{"absent", "digest", "kind", "path", "name", "source", "duplicate"} {
		matches := append([]legacyFail2banTemplateMatch(nil), templates...)
		switch change {
		case "absent":
			matches = nil
		case "digest":
			clear(matches[0].sha256[:])
		case "kind":
			matches[0].kind = "filter"
		case "path":
			matches[0].path += ".local"
		case "name":
			matches[0].jail = "syswarden-portscan'"
		case "source":
			matches[0].templateSource = ""
		case "duplicate":
			matches = append(matches, matches[0])
		}
		if err := verifyLegacyFail2banEffectiveRetirement(before, after, matches); err == nil {
			t.Fatalf("accepted unbound template: %s", change)
		}
	}
	for _, input := range [][]byte{
		nil, before[:len(before)-1], append(bytes.Clone(before), 0),
		bytes.Repeat([]byte("x"), maximumLegacyFail2banDumpBytes+1),
		bytes.Repeat([]byte("['set', 'loglevel', 'INFO']\n"), maximumLegacyFail2banDumpLines+1),
	} {
		if err := verifyLegacyFail2banEffectiveRetirement(input, after, templates); err == nil {
			t.Fatal("accepted empty, truncated or oversized dump")
		}
	}
}
