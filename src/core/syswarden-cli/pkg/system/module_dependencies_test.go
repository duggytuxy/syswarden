package system

import (
	"errors"
	"syswarden-cli/config"
	"testing"
)

func TestSelectedModulePrerequisitesPreserveMinimalAndExistingFeatures(t *testing.T) {
	for _, test := range []struct {
		name string
		c    config.Config
		want []string
	}{{name: "minimal"}, {name: "log bridge", c: config.Config{LogBridgeEnabled: true}, want: []string{"rsyslogd"}}, {name: "SIEM", c: config.Config{SiemEnabled: true}, want: []string{"rsyslogd"}}, {name: "WireGuard", c: config.Config{EnableWG: true}, want: []string{"wg", "wg-quick"}}} {
		t.Run(test.name, func(t *testing.T) {
			var seen []string
			err := preflightSelectedModuleDependencies(&test.c, func(name string) (string, error) { seen = append(seen, name); return "/usr/bin/" + name, nil }, func(string) error { return nil })
			if err != nil || len(seen) != len(test.want) {
				t.Fatal(seen, err)
			}
			for i, name := range seen {
				if name != test.want[i] {
					t.Fatal(seen)
				}
			}
			if len(test.want) > 0 {
				if err := preflightSelectedModuleDependencies(&test.c, func(string) (string, error) { return "", errors.New("absent") }, func(string) error { return nil }); err == nil {
					t.Fatal("missing selected prerequisite accepted")
				}
			}
		})
	}
}

func TestSelectedPrerequisitesFailClosedWithoutChangingConfiguration(t *testing.T) {
	for _, profile := range []string{"", "standard-v1"} {
		c := &config.Config{InstallProfile: profile, EnableWG: true, LogBridgeEnabled: true, SiemEnabled: true}
		before := *c
		denied := errors.New("untrusted executable")
		err := preflightSelectedModuleDependencies(c, func(name string) (string, error) { return "/tmp/" + name, nil }, func(string) error { return denied })
		if !errors.Is(err, denied) {
			t.Fatalf("untrusted selected prerequisite accepted: %v", err)
		}
		if c.InstallProfile != before.InstallProfile || c.EnableWG != before.EnableWG || c.LogBridgeEnabled != before.LogBridgeEnabled || c.SiemEnabled != before.SiemEnabled {
			t.Fatal("preflight changed installed selection")
		}
	}
}
